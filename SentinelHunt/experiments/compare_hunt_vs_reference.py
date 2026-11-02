#!/usr/bin/env python3
"""
Agreement of the PARSED hunt index (what Agent 1 actually wrote on the kit) with the teammate's parsing reference,
record by record (join on record_id). Read-only: uses the MCP backend's hunt account.

Reported as AGREEMENT WITH THE REFERENCE (rule-derived, not human-audited), not detection accuracy.
  value agreement : the field exists with the same value (numbers/strings normalised, timestamps to the second)
  extra fields    : fields Agent 1 set that the reference leaves empty (not necessarily wrong)

Usage (from ~/se6014, kit mode):
  .venv/bin/python experiments/compare_hunt_vs_reference.py /path/to/sentinelhunt-multisource-v3
"""
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mcp_server"))
import server as S  # noqa: E402

SKIP = {"message", "event.original"}
DERIVED = {"event.action", "event.outcome", "log.category"}


def flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flat(v, prefix + k + "."))
        else:
            out[prefix + k] = v
    return out


def same(field, a, b):
    if field == "@timestamp":
        try:
            fa = datetime.fromisoformat(str(a).replace("Z", "+00:00"))
            fb = datetime.fromisoformat(str(b).replace("Z", "+00:00"))
            return abs((fa - fb).total_seconds()) < 1
        except ValueError:
            return False
    return str(a).strip().lower() == str(b).strip().lower()


def main():
    ref_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "/mnt/c/Users/ckung/Downloads/sentinelhunt-multisource-v3")
    ref = {r["record_id"]: r for r in (json.loads(l) for l in open(ref_dir / "parsing-reference.ndjson") if l.strip())}
    S.configure("hunt")
    status, resp = S.es("POST", f"/{S.HUNT_INDEX or 'sentinelhunt-hunt-v1'}/_search",
                        {"size": 10000, "query": {"match_all": {}}})
    if status != 200:
        sys.exit(f"cannot read hunt index: {resp}")
    docs = {h["_id"]: flat(h["_source"]) for h in resp["hits"]["hits"]}
    per = defaultdict(Counter)
    extra = defaultdict(Counter)
    missing = set(ref) - set(docs)
    for rid, r in ref.items():
        if rid not in docs:
            continue
        d, st = docs[rid], r.get("source_type") or r["log_type"]
        refp = {k: v for k, v in r["parsed"].items() if v is not None and k not in SKIP}
        for k, v in refp.items():
            per[(st, k)]["total"] += 1
            per[(st, k)]["agree"] += k in d and same(k, d[k], v)
        for k in d:
            if k not in refp and k not in SKIP and k not in ("record_id", "capture_id", "feed_name", "raw_line"):
                extra[(st, k)][str(d[k])[:30]] += 1
    lit = [(k, c) for k, c in per.items() if k[1] not in DERIVED]
    der = [(k, c) for k, c in per.items() if k[1] in DERIVED]
    pct = lambda xs: round(100 * sum(c["agree"] for _, c in xs) / max(1, sum(c["total"] for _, c in xs)), 1)
    print(f"hunt index records: {len(docs)} | reference records: {len(ref)} | missing in hunt index: {len(missing)}")
    print(f"agreement with reference: literal fields {pct(lit)}% | derived fields {pct(der)}%\n")
    print("field-level (below 100%):")
    for (st, k), c in sorted(per.items()):
        if c["agree"] < c["total"]:
            print(f"  {st:11} {k:28} {c['agree']}/{c['total']}")
    print("\nextra fields set by Agent 1 where the reference is empty (type: field -> example values):")
    for (st, k), c in sorted(extra.items()):
        print(f"  {st:11} {k:28} {sum(c.values()):4} × {dict(c.most_common(3))}")


if __name__ == "__main__":
    main()
