#!/usr/bin/env python3
"""
Verify two details of run_twice_20261024-161924 / converged / TC1 on the frozen v3 data (read-only hunt account):
  1. the real time range of the 15 failed-password records (run 2 claimed 17:07:00 -> 17:08:00)
  2. destination.port vs source.port on those records (run 2's follow-up "terms destination.port" said 15 events)
and recompute the data checksum of the v3 records to show they are unchanged since the experiment.
Only feed v3-mixed-pilot is used (demo feeds added later are excluded).

Usage (from ~/se6014, kit mode):
  .venv/bin/python experiments/verify_tc1.py [experiments/results/run_twice_20261024-161924]
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mcp_server"))
import server as S  # noqa: E402

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "experiments" / "results" / "run_twice_20261024-161924"
FEED = 'feed_name:"v3-mixed-pilot"'
Q = "process.name:sshd AND event.outcome:failure AND event.action:ssh_authentication"
HID = "verify-tc1"


def main():
    S.configure("hunt")
    ix = "sentinelhunt-hunt-v1"
    L = [f"# Verification of {RUN.name} · converged · TC1", "",
         f"Read-only hunt account via the MCP backend. Records restricted to `{FEED}` (the frozen v3 data).", ""]

    # 0. data checksum of the v3 records, same formula as run_twice.fingerprint()
    _, resp = S.es("POST", f"/{ix}/_search", {"size": 10000, "track_total_hits": True, "sort": [{"_doc": "asc"}],
                                              "query": {"query_string": {"query": FEED}}})
    hits = sorted(resp["hits"]["hits"], key=lambda h: h["_id"])
    ids_sha = hashlib.sha256("\n".join(h["_id"] for h in hits).encode()).hexdigest()
    content_sha = hashlib.sha256("\n".join(h["_id"] + " " + json.dumps(h["_source"], sort_keys=True)
                                           for h in hits).encode()).hexdigest()
    fp = json.loads((RUN / "fingerprint_before.json").read_text())[ix]
    same = ids_sha == fp["ids_sha256"] and content_sha == fp["content_sha256"]
    L += ["## 0. Frozen data checksum", "",
          "| | at the experiment (fingerprint_before/after.json) | now (v3 records only) |", "|---|---|---|",
          f"| records | {fp['docs']} | {len(hits)} |", f"| sha256 of ids | `{fp['ids_sha256']}` | `{ids_sha}` |",
          f"| sha256 of ids + contents | `{fp['content_sha256']}` | `{content_sha}` |", "",
          f"**Identical: {'yes' if same else 'NO'}**. During the experiment the index held only these {fp['docs']} "
          "records (before = after). Demo feeds were added later and are excluded here.", ""]

    # 1. real time range
    s = S.search(HID, ix, f"{Q} AND {FEED}", size=50, fields=["@timestamp", "source.ip", "user.name"])
    ts = [h["@timestamp"] for h in s["hits"]]
    h = S.aggregate(HID, ix, "date_histogram", "@timestamp", f"{Q} AND {FEED}", interval="1m")
    L += ["## 1. Time range of the failed-password records", "",
          f"Query: `{Q}` → {s['total']} records.", "",
          f"- first: **{min(ts)}**", f"- last: **{max(ts)}**",
          "- per minute (bucket key = START of the minute): "
          + ", ".join(f"{b['key']} = {b['count']}" for b in h["buckets"]), "",
          "Run 2 claim: \"between 2026-10-22T17:07:00.000Z and 2026-10-22T17:08:00.000Z\". **Not supported**: "
          "the model used the two bucket keys as start and end; 11 of the 15 records are after 17:08:00. "
          "The claim checker at the time compared counts and entities only, so it passed. Fixed after review "
          "(see README.md).", ""]

    # 2. destination.port vs source.port
    rows = []
    for field in ("destination.port", "source.port"):
        a = S.aggregate(HID, ix, "terms", field, f"{Q} AND {FEED}", size=20)
        rows.append(f"| {field} | {a['matching_events']} | {len(a['buckets'])} | {a.get('events_without_field', '?')} | "
                    + (", ".join(f"{b['key']}={b['count']}" for b in a["buckets"][:5]) or "(none)") + " |")
    L += ["## 2. destination.port vs source.port on the same records", "",
          "| field | matching records | distinct values | records WITHOUT the field | first values |",
          "|---|---|---|---|---|"] + rows + [
          "", "\"15 events\" in run 2's follow-up `terms destination.port` was the number of records matching the "
          "query, not records with a destination port: the aggregation returned no buckets (SSH auth lines carry the "
          "client's source port only). No claim cited that query. The aggregate tool now reports "
          "`events_without_field` and its summary says e.g. \"15 events; 15 without destination.port\".", ""]
    out = RUN / "VERIFY_TC1.md"
    out.write_text("\n".join(L))
    print("\n".join(L))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
