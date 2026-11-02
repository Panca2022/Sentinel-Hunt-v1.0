#!/usr/bin/env python3
"""
Compare this checkout with the version manifest of the recorded, verified run (docs/VERSION_MANIFEST.json):
  code     sha256 of every project file and every kit file listed in the manifest
  model    Ollama model digest (needs Ollama running)
  stack    Elasticsearch version, registered templates (pipeline sha256), v3 data fingerprint (needs the kit running)
Read-only. Prints PASS/FAIL per item; exit 1 on any FAIL. Use --code-only without Ollama/Elasticsearch.

Usage (WSL, from the repo):  python3 scripts/verify_manifest.py [--code-only]
"""
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
M = json.loads((ROOT / "docs" / "VERSION_MANIFEST.json").read_text())
fails = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        fails.append(name)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    for base, key in ((ROOT, "project"), (KIT, "kit")):
        bad = [f for f, h in M["code"][key].items() if not (base / f).exists() or sha(base / f) != h]
        check(f"{key} code: {len(M['code'][key])} files match the manifest", not bad, f"differ/missing: {bad}" if bad else "")
    if "--code-only" in sys.argv:
        return
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as r:
            tags = {m["name"]: m for m in json.load(r).get("models", [])}
        d = tags.get(M["model"]["name"], {}).get("digest")
        check(f"model {M['model']['name']} digest", d == M["model"]["digest"], f"{str(d)[:12]}…")
    except Exception as e:
        check("model (Ollama reachable)", False, e.__class__.__name__)
    sys.path.insert(0, str(KIT / "scripts"))
    from manage import es  # kit admin account, read-only calls
    v = es("GET", "/").get("version", {}).get("number")
    check("Elasticsearch version", v == M["platform"]["elasticsearch"], v)
    pipes = es("GET", "/_ingest/pipeline")
    for name, t in M["agent1_templates"].items():
        p = pipes.get(name)
        got = hashlib.sha256(json.dumps(p.get("processors"), sort_keys=True).encode()).hexdigest() if p else None
        if t.get("feed_name") == "v3-mixed-pilot":
            check(f"template {name}", got == t["pipeline_sha256"], "missing" if not p else f"{got[:12]}…")
        else:   # demo template: built live by the AI during the demo (may differ in detail); verify_demo_run.py
            print(f"INFO  template {name} (demo): " + ("not built yet" if not p else      # checks its output values
                  "same as the recorded run" if got == t["pipeline_sha256"] else
                  "built anew, differs from the recorded run (expected unless restored from templates/)"))
    hits = sorted(es("POST", "/sentinelhunt-hunt-v1/_search", {"size": 10000, "query": {"term": {"feed_name": "v3-mixed-pilot"}}})
                  ["hits"]["hits"], key=lambda h: h["_id"])
    c = hashlib.sha256("\n".join(h["_id"] + " " + json.dumps(h["_source"], sort_keys=True) for h in hits).encode()).hexdigest()
    check("v3 data fingerprint (545 records, content sha256)", c == M["indices"]["v3_fingerprint"]["content_sha256"],
          f"{len(hits)} records, {c[:12]}…")


if __name__ == "__main__":
    main()
    print(f"\n{'ALL MATCH' if not fails else str(len(fails)) + ' item(s) differ'}")
    sys.exit(1 if fails else 0)
