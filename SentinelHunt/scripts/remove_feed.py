#!/usr/bin/env python3
"""
Remove a test/demo feed completely so the indices hold only the real data again:
  - its records in the parsed hunt index and in raw staging
  - the templates Agent 1 built for it (ingest pipelines logs-<feed>-layoutN, router feed-<feed>,
    registry entries in sentinelhunt-schema-v1 and in the local agent1/registry.json cache)
Uses the kit's admin account through the kit's own manage.py (index maintenance is not an agent permission).
Dry run by default: shows what would be removed. Add --yes to remove.

Usage (WSL):
  export SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable
  .venv/bin/python scripts/remove_feed.py demo-ssh-1            # dry run
  .venv/bin/python scripts/remove_feed.py demo-ssh-1 --yes      # remove
"""
import json
import os
import re
import sys
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
sys.path.insert(0, str(KIT / "scripts"))
from manage import es  # noqa: E402  (kit admin account, kit CA)

HUNT, RAW, REG = "sentinelhunt-hunt-v1", "sentinelhunt-raw-v1", "sentinelhunt-schema-v1"


def call(method, path, body=None):
    try:
        return es(method, path, body)
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}


def main():
    feeds = [a for a in sys.argv[1:] if not a.startswith("--")]
    go = "--yes" in sys.argv
    if not feeds:
        sys.exit(__doc__)
    if "v3-mixed-pilot" in feeds:
        sys.exit("refusing to remove v3-mixed-pilot (the frozen experiment data)")
    for feed in feeds:
        slug = re.sub(r"[^a-z0-9_-]", "-", feed.lower())
        q = {"query": {"term": {"feed_name": feed}}}
        n_hunt = call("POST", f"/{HUNT}/_count", q).get("count")
        n_raw = call("POST", f"/{RAW}/_count", q).get("count")
        pipes = [p for p in call("GET", "/_ingest/pipeline") if p == f"feed-{slug}" or p.startswith(f"logs-{slug}-layout")]
        # match registry entries by NAME (feed_name is a text field, so a term query on it misses)
        regs = [h["_id"] for h in call("POST", f"/{REG}/_search", {"size": 500, "_source": False})
                .get("hits", {}).get("hits", []) if h["_id"].startswith(f"logs-{slug}-layout")]
        local = ROOT / "agent1" / "registry.json"
        cache = json.loads(local.read_text()) if local.exists() else []
        cached = [e["name"] for e in cache if e.get("name", "").startswith(f"logs-{slug}-layout")]
        print(f"feed {feed}: hunt index {n_hunt} records | raw staging {n_raw} records | pipelines {pipes} | "
              f"registry {regs} | local cache {cached}")
        if not go:
            continue
        for ix in (HUNT, RAW):
            r = call("POST", f"/{ix}/_delete_by_query?refresh=true&conflicts=proceed", q)
            print(f"  {ix}: deleted {r.get('deleted', r)}")
        for p in pipes:
            print(f"  pipeline {p}: {call('DELETE', f'/_ingest/pipeline/{p}')}")
        for d in regs:
            print(f"  registry {d}: {call('DELETE', f'/{REG}/_doc/{d}?refresh=true').get('result')}")
        if cached:
            local.write_text(json.dumps([e for e in cache if e.get("name") not in cached], indent=2))
            print(f"  local cache: removed {cached}")
    total = call("POST", f"/{HUNT}/_count", {"query": {"match_all": {}}}).get("count")
    print(f"\nhunt index now holds {total} records" + ("" if go else " (dry run: nothing removed; add --yes)"))


if __name__ == "__main__":
    main()
