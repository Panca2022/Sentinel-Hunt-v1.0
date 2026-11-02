#!/usr/bin/env python3
"""
Take templates off Agent 1's registry so they can't be matched/reused any more.
  - registry entries in sentinelhunt-schema-v1 AND the local cache entries are backed up to a JSON file, then deleted
  - the same names are removed from the local agent1/registry.json cache
  - the ingest pipelines themselves are KEPT (history; nothing that was indexed changes)
Optional: --relabel NAME=FEED fixes the feed_name label of an entry that stays.
Uses the kit's admin account via the kit's manage.py. Dry run unless --yes.

Usage (WSL, from ~/se6014):
  .venv/bin/python scripts/retire_templates.py logs-v3-layout1 logs-v3-layout2 logs-v3-layout3 logs-demo-ssh-1-layout1
  .venv/bin/python scripts/retire_templates.py ... --yes
"""
import json
import os
import sys
import urllib.error
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
sys.path.insert(0, str(KIT / "scripts"))
from manage import es  # noqa: E402

REG = "sentinelhunt-schema-v1"
KEEP_ROUTED = True     # refuse to retire a template that a feed router still uses


def call(method, path, body=None):
    try:
        return es(method, path, body)
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}


def main():
    names = [a for a in sys.argv[1:] if not a.startswith("--")]
    go = "--yes" in sys.argv
    if not names:
        sys.exit(__doc__)
    routed = set()
    for k, v in call("GET", "/_ingest/pipeline").items():
        if k.startswith("feed-"):
            routed |= set(v.get("_meta", {}).get("layouts", []))
    if KEEP_ROUTED and routed & set(names):
        sys.exit(f"refusing: {sorted(routed & set(names))} still used by a feed router")
    found = {}
    for n in names:
        d = call("GET", f"/{REG}/_doc/{n}")
        print(f"{n}: registry entry {'found' if d.get('found') else 'not found'}"
              + (f" (feed_name {d['_source'].get('feed_name')}, updated {d['_source'].get('updated')})" if d.get("found") else ""))
        if d.get("found"):
            found[n] = d["_source"]
    local = ROOT / "agent1" / "registry.json"
    cache = json.loads(local.read_text()) if local.exists() else []
    in_cache = [e["name"] for e in cache if e.get("name") in names]
    print(f"local cache entries: {in_cache}")
    if not go:
        print("\ndry run: nothing changed (add --yes)")
        return
    backup = ROOT / "agent1" / f"registry_retired_{datetime.now():%Y%m%d-%H%M%S}.json"
    backup.write_text(json.dumps({"registry_index": found,
                                  "local_cache": [e for e in cache if e.get("name") in names]}, indent=2))
    print(f"backup of registry entries: {backup}")
    for n in found:
        print(f"  delete registry {n}: {call('DELETE', f'/{REG}/_doc/{n}?refresh=true').get('result')}")
    if in_cache:
        local.write_text(json.dumps([e for e in cache if e.get("name") not in names], indent=2))
        print(f"  local cache: removed {in_cache}")
    left = call("POST", f"/{REG}/_search", {"size": 100, "_source": ["feed_name"]})
    print("\nregistry now: " + ", ".join(f"{h['_id']} ({h['_source'].get('feed_name')})"
                                          for h in left.get("hits", {}).get("hits", [])))


if __name__ == "__main__":
    main()
