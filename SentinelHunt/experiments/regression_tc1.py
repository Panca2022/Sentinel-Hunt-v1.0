#!/usr/bin/env python3
"""
Post-fix regression for the two gaps the review found in run_twice_20261024-161924 / converged / TC1 run 2:
  A. missing aggregation fields: rerun run 2's `terms destination.port` follow-up with the patched MCP tool
  B. wrong time range: rerun the per-minute playbook query (patched tool: real first/last event) and put run 2's
     ORIGINAL claim through the patched checker (must be rejected; a correct control claim must be kept);
     then the normal self-correction step: the rejected claim goes to the live model once with the reason,
     and the rewrite is verified again by code
  C. one normal post-fix hunt (17:07-17:09 window, so demo feeds added later are outside it)
A and B use only feed v3-mixed-pilot (the frozen data). Writes experiments/results/regression_tc1_<stamp>/.

Usage (from ~/se6014, kit mode):  .venv/bin/python experiments/regression_tc1.py [--no-live]
"""
import asyncio
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mcp_server"))
sys.path.insert(0, str(ROOT / "agent2"))
import server as S  # noqa: E402
import hunt_agent as H  # noqa: E402

RUN = ROOT / "experiments" / "results" / "run_twice_20261024-161924" / "converged" / "TC1" / "run2" / "report.json"
FEED = 'feed_name:"v3-mixed-pilot"'
Q = "process.name:sshd AND event.outcome:failure AND event.action:ssh_authentication"
LIVE_HYP = "Someone brute-forced SSH between 17:07 and 17:09 on 22 Oct 2026"


def main():
    live = "--no-live" not in sys.argv
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = ROOT / "experiments" / "results" / f"regression_tc1_{stamp}"
    out.mkdir(parents=True)
    hid = f"regression-tc1-{stamp}"
    S.configure("hunt")
    ix = "sentinelhunt-hunt-v1"
    L = [f"# Post-fix regression for the TC1 review findings ({stamp})", "",
         f"Model {H.MODEL}, temperature 0, seed 42. Parts A and B use only `{FEED}` (the frozen v3 records). "
         f"Query log: `ledger.jsonl` (hunt id `{hid}`).", ""]
    res = {}

    # ---- A. missing aggregation fields
    L += ["## A. Missing aggregation fields are reported", "",
          "Run 2's follow-up `terms destination.port` returned the summary \"15 events\" (no buckets). Same query "
          "with the patched MCP tool:", "", "| field | summary | buckets | events_without_field |", "|---|---|---|---|"]
    for field in ("destination.port", "source.port"):
        a = S.aggregate(hid, ix, "terms", field, f"{Q} AND {FEED}", size=10)
        res[f"A_{field}"] = a
        summary = next(json.loads(l)["summary"] for l in open(S.LEDGER_DIR / f"{hid}.jsonl")
                       if json.loads(l)["query_id"] == a["query_id"])
        L.append(f"| {field} | \"{summary}\" | {len(a['buckets'])} | {a.get('events_without_field')} |")
    ok_a = res["A_destination.port"].get("events_without_field") == 15
    L += ["", f"**{'PASS' if ok_a else 'FAIL'}**: the empty field is now visible in the summary and the result.", ""]

    # ---- B. wrong time range
    h = S.aggregate(hid, ix, "date_histogram", "@timestamp", f"{Q} AND {FEED}", interval="1m")
    res["B_histogram"] = h
    qid = h["query_id"]
    facts = {qid: {"tool": "aggregate", "args": {}, "result": {k: v for k, v in h.items() if k != "query_id"}}}
    original = json.loads(RUN.read_text())
    orig_claim = next(c for c in original["claims"] if "17:07:00" in c["text"])
    claims = [{"text": orig_claim["text"], "query_ids": [qid], "doc_ids": []},
              {"text": f"The failed password attempts occurred between {h['first_event'][:19]} and "
                       f"{h['last_event'][:19]}.", "query_ids": [qid], "doc_ids": []}]
    kept, rejected = H.verify(claims, facts, set())
    L += ["## B. Wrong time range is rejected", "",
          "Patched per-minute query result: " + ", ".join(f"{b['key']} = {b['count']}" for b in h["buckets"])
          + f"; first_event {h.get('first_event')}; last_event {h.get('last_event')}; "
            f"bucket_note \"{h.get('bucket_note')}\".", "",
          "| claim | origin | patched checker |", "|---|---|---|",
          f"| {orig_claim['text']} | run 2, original (passed the old checker) | "
          + ("**rejected**: " + "; ".join(rejected[0]["problems"]) if rejected and rejected[0]["text"] == orig_claim["text"]
             else "kept") + " |",
          f"| {claims[1]['text']} | control, correct range | "
          + ("kept" if any(c["text"] == claims[1]["text"] for c in kept) else "**rejected**") + " |", ""]
    ok_b = (len(rejected) == 1 and rejected[0]["text"] == orig_claim["text"]
            and any(c["text"] == claims[1]["text"] for c in kept))

    # self-correction, exactly as in a hunt: one rewrite by the model, verified again by code
    todo = [{"number": 0, "claim": rejected[0]["text"], "query_ids": [qid], "rejected_because": rejected[0]["problems"]}] \
        if ok_b else []
    rewrite_line = "not run"
    if todo:
        try:
            fix, _ = H.llm(H.REPAIR_PROMPT, f"Rejected claims:\n{json.dumps(todo)}\n"
                           f"Query results:\n{json.dumps({qid: {'result': H.compact(facts[qid]['result'])}}, default=str)}",
                           H.REPAIR_SCHEMA, 900)
        except H.LLMOutputError as e:
            fix = {"claims": []}
            rewrite_line = f"model output error: {e}"
        cand = next((c for c in (fix or {}).get("claims", []) if c.get("replaces") == 0), None)
        if cand:
            ok2, bad2 = H.verify([{k: v for k, v in cand.items() if k != "replaces"}], facts, set())
            rewrite_line = (f"\"{cand['text']}\" → **{'kept (passes the checker)' if ok2 else 'removed'}**"
                            + ("" if ok2 else f": {'; '.join(bad2[0]['problems'])}"))
            res["B_rewrite"] = {"text": cand["text"], "kept": bool(ok2)}
        elif rewrite_line == "not run":
            rewrite_line = "the model left the claim out (allowed by the repair rules) → removed"
    L += [f"Self-correction (live model, one round): {rewrite_line}", "",
          f"**{'PASS' if ok_b else 'FAIL'}**: the original wrong claim is rejected with the reason, the correct "
          "control is kept. Either outcome of the rewrite is safe: it is kept only if it passes the checker.", ""]

    # ---- C. one normal post-fix hunt
    if live:
        rep = asyncio.run(H.hunt(LIVE_HYP, hunt_id=f"regression-hunt-{stamp}", quiet=True))
        for ext in ("md", "json"):
            src = H.REPORTS / f"{rep['hunt_id']}.{ext}"
            if src.exists():
                shutil.copy(src, out / f"hunt_report.{ext}")
        with open(out / "hunt_queries.jsonl", "w") as f:
            for q in rep["queries"]:
                f.write(json.dumps(q, default=str) + "\n")
        times = [c["text"] for c in rep["claims"] if "T17:" in c["text"] or "17:0" in c["text"]]
        missing = [f"{q['args'].get('field')}: {q['summary']}" for q in rep["queries"] if "without" in (q.get("summary") or "")]
        removed = [(c["text"], c.get("problems")) for c in rep.get("removed_claims", [])]
        L += ["## C. One normal hunt after the fix", "",
              f"Hypothesis: \"{LIVE_HYP}\" (window 17:07-17:09 on 22 Oct, so demo feeds added on 24 Oct are outside it).",
              "", f"- verdict: **{rep['verdict']}** ({rep['verdict_rule'][:160]}…)",
              f"- claims kept: {len(rep['claims'])}, rewritten after checker feedback: "
              f"{rep['verification'].get('rewritten_after_feedback', 0)}, removed: {rep['verification'].get('removed', 0)}",
              "- claims with a time: " + ("; ".join(f"\"{t}\"" for t in times) or "none"),
              "- aggregations that reported missing fields: " + ("; ".join(missing) or "none in this hunt"),
              "- claims rejected on the first check (rewritten or removed, see the report): " + ("; ".join(f"\"{t}\" ({'; '.join(p or [])})" for t, p in removed) or "none"),
              "", "Full report: `hunt_report.md` / `hunt_report.json`; queries: `hunt_queries.jsonl`.", ""]
        res["C_hunt"] = {"hunt_id": rep["hunt_id"], "verdict": rep["verdict"], "time_claims": times,
                         "missing_field_summaries": missing, "removed": removed}

    shutil.copy(S.LEDGER_DIR / f"{hid}.jsonl", out / "ledger.jsonl")
    (out / "regression_results.json").write_text(json.dumps(res, indent=2, default=str))
    (out / "REGRESSION_TC1.md").write_text("\n".join(L))
    print("\n".join(L))
    print(f"\nSaved in {out.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
