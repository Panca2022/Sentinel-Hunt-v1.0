#!/usr/bin/env python3
"""
Export every Agent 1 template from Elasticsearch into a folder (read-only), so a rebuild can restore them exactly
instead of asking the model again:
  <out>/<template>.json   {"registry": registry doc, "pipeline": ingest pipeline, "pipeline_sha256": ...}
  <out>/routers.json      the feed-<feed> router pipelines
  <out>/local_cache.json  agent1/registry.json (Agent 1's local copy of the registry)
pipeline_sha256 is computed exactly as freeze_versions.py does, so it can be compared with the version manifest.

Usage (WSL, from ~/se6014):  .venv/bin/python scripts/export_templates.py templates/
"""
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
sys.path.insert(0, str(KIT / "scripts"))
from manage import es  # noqa: E402  (kit admin account; GET/search only here)


def psha(p):
    return hashlib.sha256(json.dumps(p.get("processors"), sort_keys=True).encode()).hexdigest()


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    pipes = es("GET", "/_ingest/pipeline")
    reg = es("POST", "/sentinelhunt-schema-v1/_search", {"size": 500})["hits"]["hits"]
    for h in reg:
        name = h["_id"]
        p = pipes.get(name)
        (out / f"{name}.json").write_text(json.dumps(
            {"name": name, "registry": h["_source"], "pipeline": p, "pipeline_sha256": psha(p) if p else None}, indent=2))
        print(f"{name}: pipeline {'sha ' + psha(p)[:12] if p else 'MISSING'}")
    routers = {k: v for k, v in pipes.items() if k.startswith("feed-")}
    (out / "routers.json").write_text(json.dumps(routers, indent=2))
    cache = ROOT / "agent1" / "registry.json"
    names = {h["_id"] for h in reg}
    local = [e for e in json.loads(cache.read_text())] if cache.exists() else []
    (out / "local_cache.json").write_text(json.dumps([e for e in local if e.get("name") in names], indent=2))
    print(f"routers: {list(routers)} | local cache entries: {sum(e.get('name') in names for e in local)} -> {out}")


if __name__ == "__main__":
    main()
