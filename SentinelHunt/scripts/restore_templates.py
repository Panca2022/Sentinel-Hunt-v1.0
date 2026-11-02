#!/usr/bin/env python3
"""
Restore Agent 1 templates exported by export_templates.py: ingest pipelines, feed routers, registry entries and
Agent 1's local cache. After this, Agent 1 REUSES the templates (no model call) and parses exactly as frozen.
Each pipeline's sha256 is checked against the export before anything is written. Dry run unless --yes.

Usage (WSL, from the repo):
  .venv/bin/python scripts/restore_templates.py templates/ [--only v3-mixed-pilot] [--yes]
"""
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
sys.path.insert(0, str(KIT / "scripts"))
from manage import es  # noqa: E402  (kit admin account: pipelines and the registry are kit maintenance)


def psha(p):
    return hashlib.sha256(json.dumps(p.get("processors"), sort_keys=True).encode()).hexdigest()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    src, go = Path(args[0]), "--yes" in sys.argv
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
    items = [json.loads(p.read_text()) for p in sorted(src.glob("logs-*.json"))]
    if only:
        items = [t for t in items if t["name"].startswith(f"logs-{only}-layout")]
    routers = json.loads((src / "routers.json").read_text())
    if only:
        routers = {k: v for k, v in routers.items() if k == f"feed-{only}"}
    for t in items:
        ok = t["pipeline"] and psha(t["pipeline"]) == t["pipeline_sha256"]
        print(f"{t['name']}: pipeline sha {t['pipeline_sha256'][:12]} {'ok' if ok else 'MISMATCH'}")
        if not ok:
            sys.exit("refusing: exported pipeline does not match its recorded sha256")
    print(f"routers: {list(routers)}")
    if not go:
        print("\ndry run: nothing written (add --yes)")
        return
    for t in items:
        print(f"  PUT pipeline {t['name']}: {es('PUT', '/_ingest/pipeline/' + t['name'], t['pipeline'])}")
        print(f"  registry {t['name']}: "
              f"{es('PUT', '/sentinelhunt-schema-v1/_doc/' + t['name'] + '?refresh=true', t['registry']).get('result')}")
    for k, v in routers.items():
        print(f"  PUT router {k}: {es('PUT', '/_ingest/pipeline/' + k, v)}")
    cache_path = ROOT / "agent1" / "registry.json"
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else []
    names = {t["name"] for t in items}
    new = [e for e in json.loads((src / "local_cache.json").read_text()) if e.get("name") in names]
    cache = [e for e in cache if e.get("name") not in names] + new
    cache_path.write_text(json.dumps(cache, indent=2))
    print(f"  local cache: {len(new)} entries restored")


if __name__ == "__main__":
    main()
