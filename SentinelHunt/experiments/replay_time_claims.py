#!/usr/bin/env python3
"""
Replay every AI claim that mentions a time, from every saved run of a run-twice folder, through the CURRENT checker.
Each claim's cited queries are re-run with their exact saved arguments (patched MCP tools, read-only account, frozen
data), so the checker sees the real first/last event times. The saved runs are not changed.

Usage (from ~/se6014, kit mode):
  .venv/bin/python experiments/replay_time_claims.py [experiments/results/run_twice_20261024-161924]
  -> experiments/results/replay_time_claims_<stamp>/REPLAY.md (+ replay.json, ledger.jsonl)
"""
import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mcp_server"))
sys.path.insert(0, str(ROOT / "agent2"))
import server as S  # noqa: E402
import hunt_agent as H  # noqa: E402

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "experiments" / "results" / "run_twice_20261024-161924"


def main():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = ROOT / "experiments" / "results" / f"replay_time_claims_{stamp}"
    out.mkdir(parents=True)
    hid = f"replay-time-{stamp}"
    S.configure("hunt")
    rows = []
    for rp in sorted(RUN.glob("*/TC*/run*/report.json")):
        rep = json.loads(rp.read_text())
        byid = {q["query_id"]: q for q in rep["queries"]}
        for c in rep["claims"]:
            if not H.claim_times(c["text"], "2000-01-01"):
                continue
            facts = {}
            for qid in c.get("query_ids") or []:
                q = byid.get(qid)
                if not q or q["tool"] not in ("search", "aggregate"):
                    continue
                fn = S.search if q["tool"] == "search" else S.aggregate
                r = fn(hid, **q["args"])
                facts[qid] = {"result": {k: v for k, v in r.items() if k != "query_id"}}
            kept, rejected = H.verify([{k: c[k] for k in ("text", "query_ids", "doc_ids", "count", "entity") if k in c}],
                                      facts, {d for d in c.get("doc_ids", [])})
            where = "/".join(rp.parent.parts[-3:])
            origin = "rewritten by the AI (kept)" if c.get("rewritten_from") else "kept"
            rows.append({"run": where, "claim": c["text"], "at_the_time": origin,
                         "now": "kept" if kept else "rejected", "why": rejected[0]["problems"] if rejected else []})
    L = [f"# Replay of time claims through the current checker ({stamp})", "",
         f"Source: `{RUN.name}` (unchanged). Every kept claim that mentions a time; its cited queries re-run with the "
         "saved arguments on the frozen data (read-only account), then checked by the current checker.", "",
         f"**{sum(r['now'] == 'rejected' for r in rows)} of {len(rows)} time claims are now rejected.**", "",
         "| run | claim | at the time | now | why |", "|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['run']} | {r['claim']} | {r['at_the_time']} | **{r['now']}** | {'; '.join(r['why'])} |")
    (out / "REPLAY.md").write_text("\n".join(L) + "\n")
    (out / "replay.json").write_text(json.dumps(rows, indent=2))
    shutil.copy(S.LEDGER_DIR / f"{hid}.jsonl", out / "ledger.jsonl")
    print("\n".join(L))
    print(f"\nSaved in {out.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
