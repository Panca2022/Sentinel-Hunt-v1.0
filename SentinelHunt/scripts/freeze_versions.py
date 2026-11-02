#!/usr/bin/env python3
"""
Freeze the exact state the demo and report run on -> versions_and_hashes.json (checklist gate A).
Records: sha256 of every code/config file (ours + the kit's), model + digest + settings, Elasticsearch / Docker / Python
versions, registered Agent 1 templates (pipeline hashes), index counts + the v3 data fingerprint, and the result folders.
Read-only. No passwords or env values are written.

Usage (WSL):
  cd ~/se6014 && export SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable
  .venv/bin/python scripts/freeze_versions.py            -> versions_and_hashes.json
"""
import hashlib
import json
import os
import platform
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
sys.path.insert(0, str(KIT / "scripts"))
from manage import es  # noqa: E402  (kit admin account, read-only calls only)

OURS = ["agent1/*.py", "agent1/vocabulary.json", "agent1/example_library.json", "agent2/*.py", "mcp_server/*.py",
        "mcp_server/requirements.txt", "demo/app.py", "demo/requirements.txt", "experiments/*.py", "scripts/*.py"]
KITS = ["compose.yaml", "scripts/*.py", "config/pipeline/*.conf", "config/*.json", "config/*.yml"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(base, patterns):
    out = {}
    for pat in patterns:
        for p in sorted(base.glob(pat)):
            if p.is_file() and "__pycache__" not in p.parts:
                out[str(p.relative_to(base))] = sha(p)
    return out


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:
        return f"unavailable ({e.__class__.__name__})"


def main():
    sys.path.insert(0, str(ROOT / "agent2"))
    sys.path.insert(0, str(ROOT / "agent1"))
    import hunt_agent
    import schema_agent
    out = {"frozen_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    out["code"] = {"project": files(ROOT, OURS), "kit": files(KIT, KITS)}

    tags = {}
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as r:
            tags = {m["name"]: m for m in json.load(r).get("models", [])}
    except Exception:
        pass
    m = tags.get(hunt_agent.MODEL, {})
    out["model"] = {"name": hunt_agent.MODEL, "digest": m.get("digest"), "size_bytes": m.get("size"),
                    "parameter_size": (m.get("details") or {}).get("parameter_size"),
                    "quantization": (m.get("details") or {}).get("quantization_level"),
                    "ollama_version": run(["ollama", "--version"]),
                    "agent2_settings": {"temperature": os.environ.get("HUNT_TEMPERATURE", "0"),
                                        "seed": os.environ.get("HUNT_SEED", str(hunt_agent.SEED)),
                                        "num_ctx": 8192, "think": False},
                    "agent1_settings": {"model": schema_agent.MODEL, "seed": schema_agent.SEED,
                                        "temperatures": "0 for the first candidate, 0.7 for the others",
                                        "parse_threshold": schema_agent.PARSE_THRESHOLD}}

    info = es("GET", "/")
    out["platform"] = {"elasticsearch": info.get("version", {}).get("number"),
                       "elasticsearch_build": info.get("version", {}).get("build_hash"),
                       "docker_images": run(["docker", "ps", "--format", "{{.Image}}"]).splitlines(),
                       "python": platform.python_version(), "os": platform.platform(),
                       "packages": [l for l in run([sys.executable, "-m", "pip", "freeze"]).splitlines()
                                    if l.split("==")[0].lower() in ("mcp", "streamlit", "anyio", "pydantic")]}

    pipes = es("GET", "/_ingest/pipeline")
    reg = es("POST", "/sentinelhunt-schema-v1/_search", {"size": 100, "_source": ["feed_name", "updated"]})
    out["agent1_templates"] = {
        h["_id"]: {"feed_name": h["_source"].get("feed_name"), "updated": h["_source"].get("updated"),
                   "pipeline_sha256": hashlib.sha256(json.dumps(pipes.get(h["_id"], {}).get("processors"),
                                                                sort_keys=True).encode()).hexdigest()
                   if h["_id"] in pipes else None}
        for h in reg["hits"]["hits"]}
    out["feed_routers"] = {k: v.get("_meta", {}).get("layouts") for k, v in pipes.items() if k.startswith("feed-")}

    idx = {}
    for ix in ("sentinelhunt-raw-v1", "sentinelhunt-hunt-v1"):
        aggs = es("POST", f"/{ix}/_search", {"size": 0, "aggs": {"f": {"terms": {"field": "feed_name", "size": 50}}}})
        idx[ix] = {"total": aggs["hits"]["total"]["value"],
                   "per_feed": {b["key"]: b["doc_count"] for b in aggs["aggregations"]["f"]["buckets"]}}
    r = es("POST", "/sentinelhunt-hunt-v1/_search", {"size": 10000, "sort": [{"_doc": "asc"}],
                                                      "query": {"term": {"feed_name": "v3-mixed-pilot"}}})
    hits = sorted(r["hits"]["hits"], key=lambda h: h["_id"])
    idx["v3_fingerprint"] = {
        "records": len(hits),
        "ids_sha256": hashlib.sha256("\n".join(h["_id"] for h in hits).encode()).hexdigest(),
        "content_sha256": hashlib.sha256("\n".join(h["_id"] + " " + json.dumps(h["_source"], sort_keys=True)
                                                   for h in hits).encode()).hexdigest()}
    out["indices"] = idx

    res = ROOT / "experiments" / "results"
    out["result_folders"] = {p.name: {"comparison_sha256": sha(p / "comparison.json")} if (p / "comparison.json").exists()
                             else {} for p in sorted(res.glob("*")) if p.is_dir()} if res.exists() else {}

    path = ROOT / "versions_and_hashes.json"
    path.write_text(json.dumps(out, indent=2))
    v3 = idx["v3_fingerprint"]
    print(f"wrote {path}")
    print(f"code files: {len(out['code']['project'])} ours, {len(out['code']['kit'])} kit")
    print(f"model: {out['model']['name']} digest {str(out['model']['digest'])[:12]}… | ES {out['platform']['elasticsearch']}")
    print(f"templates: {list(out['agent1_templates'])}")
    print(f"hunt index: {idx['sentinelhunt-hunt-v1']['per_feed']}")
    print(f"v3 data: {v3['records']} records, content {v3['content_sha256'][:12]}… "
          f"({'same as the experiment' if v3['content_sha256'].startswith('6fd3ef8e') else 'DIFFERENT from the experiment'})")


if __name__ == "__main__":
    main()
