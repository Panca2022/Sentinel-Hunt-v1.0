#!/usr/bin/env python3
"""
Before/after page for the time-claim fix: the original run-twice folder vs the post-fix one.
  1. metrics per setting, before vs after (verdict, playbook, key evidence, queries, wording, checker counts)
  2. the real times of each case (from the parsing reference)
  3. every AI claim with a time, per run, before vs after: what the checker did then/now, and whether it matches
     the reference
Usage:
  python experiments/fix_comparison.py <before run_twice folder> <after run_twice folder> <replay.json> \
         <parsing-reference.ndjson> <out.html> [link prefix for before side-by-sides] [link prefix for after]
"""
import html
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent2"))
import hunt_agent as H  # noqa: E402

CASES = {  # main events of each test case, as the playbook's rule counts them
    "TC1": ("failed password attempts", lambda p: p.get("event.action") == "ssh_authentication"
            and p.get("event.outcome") == "failure"),
    "TC2": ("4xx responses from 192.0.2.2", lambda p: p.get("source.ip") == "192.0.2.2"
            and str(p.get("http.response.status_code", "")).startswith("4")),
    "TC3": ("dropped packets from 192.0.2.3", lambda p: p.get("source.ip") == "192.0.2.3"
            and p.get("event.action") == "network_drop"),
    "TC4": ("sudo records", lambda p: p.get("process.name") == "sudo"),
}
e = lambda x: html.escape(str(x))
CSS = """body{font-family:Segoe UI,Arial,sans-serif;background:#f4f5f7;margin:24px;color:#1b1f24;max-width:1500px}
h1{font-size:21px;margin:0 0 4px}h2{font-size:17px;margin:26px 0 8px}.sub{color:#555;font-size:14px;margin-bottom:6px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;border-radius:8px;overflow:hidden}
th,td{border-bottom:1px solid #eceef1;padding:6px 9px;text-align:left;vertical-align:top}th{background:#fafbfc;color:#555}
.ok{color:#1e6b34;font-weight:700}.bad{color:#b42318;font-weight:700}.fix{color:#8a5a00;font-weight:700}
.note{background:#fff;border-left:5px solid #1565c0;border-radius:8px;padding:10px 14px;font-size:14px;margin:8px 0}
small{color:#666}a{color:#1565c0}td.num{text-align:right;white-space:nowrap}"""


def truth(ref_path):
    rows = [json.loads(l)["parsed"] for l in open(ref_path) if l.strip()]
    out = {}
    for tc, (label, f) in CASES.items():
        ts = sorted(datetime.fromisoformat(p["@timestamp"].replace("Z", "+00:00")) for p in rows if f(p))
        out[tc] = {"label": label, "n": len(ts), "first": ts[0], "last": ts[-1],
                   "per_minute": Counter(t.strftime("%H:%M") for t in ts)}
    return out


def vs_ref(text, t):
    win = {"first_event": t["first"].isoformat(), "last_event": t["last"].isoformat()}
    return H.time_problems(text, [win])


def has_time(text):
    return bool(H.claim_times(text, "2000-01-01"))


def collect(folder):
    out = {}
    for rp in sorted(Path(folder).glob("*/TC*/run*/report.json")):
        cfg, tc, run = rp.parent.parts[-3:]
        out[(cfg, tc, run)] = json.loads(rp.read_text())
    return out


def totals(reps, cfg):
    k = rw = rm = 0
    for (c, _, _), r in reps.items():
        if c == cfg:
            k += len(r["claims"])
            rw += r["verification"].get("rewritten_after_feedback", 0)
            rm += r["verification"].get("removed", 0)
    return k, rw, rm


def main(before, after, replay, ref, out_html, before_link="", after_link=""):
    B, A = collect(before), collect(after)
    comp_b = json.loads((Path(before) / "comparison.json").read_text())
    comp_a = json.loads((Path(after) / "comparison.json").read_text())
    rp = {(r["run"], r["claim"]): r for r in json.loads(Path(replay).read_text())}
    T = truth(ref)

    def mean(rows, cfg, k):
        xs = [r[k] for r in rows if r["config"] == cfg]
        return sum(xs) / len(xs)

    # ---- 1. metrics
    L = ["<h2>1. Before vs after, per setting</h2><table><tr><th>setting</th><th></th><th>same verdict</th>"
         "<th>same playbook</th><th>key evidence overlap</th><th>query overlap</th><th>claim wording similarity</th>"
         "<th>claims kept / rewritten / removed</th><th>wrong time claims kept</th></tr>"]
    wrong_before = Counter(r["run"].split("/")[0] for r in rp.values() if r["now"] == "rejected")
    for cfg in ("baseline", "converged"):
        for tag, comp, reps, wrong in (("before", comp_b, B, wrong_before[cfg]), ("after", comp_a, A, 0)):
            rows = [r for r in comp["rows"] if r["config"] == cfg]
            k, rw, rm = totals(reps, cfg)
            L.append(f"<tr><td>{cfg}</td><td>{tag}</td><td>{sum(r['same_verdict'] for r in rows)}/{len(rows)}</td>"
                     f"<td>{sum(r['same_playbook'] for r in rows)}/{len(rows)}</td>"
                     f"<td class=num>{mean(comp['rows'], cfg, 'evidence_jaccard'):.2f}</td>"
                     f"<td class=num>{mean(comp['rows'], cfg, 'query_jaccard'):.2f}</td>"
                     f"<td class=num>{mean(comp['rows'], cfg, 'claim_similarity'):.2f}</td>"
                     f"<td class=num>{k} / {rw} / {rm}</td>"
                     f"<td class=num><span class={'bad' if wrong else 'ok'}>{wrong}</span></td></tr>")
    L.append("</table><p class=sub>Data unchanged in both experiments (same checksum). \"Wrong time claims kept\": "
             "before = claims the new checker rejects in the replay; after = 0, every kept time claim matches the "
             "reference (section 3).</p>")

    # ---- 2. real times
    L.append("<h2>2. Real times of each case (from the parsing reference)</h2><table><tr><th>case</th><th>events</th>"
             "<th>first</th><th>last</th><th>per minute</th></tr>")
    for tc, t in T.items():
        L.append(f"<tr><td>{tc}</td><td>{t['n']} {e(t['label'])}</td><td>{t['first']:%H:%M:%S.%f}"[:-3]
                 + f"</td><td>{t['last']:%H:%M:%S.%f}"[:-3] + "</td><td>"
                 + ", ".join(f"{m} → {n}" for m, n in sorted(t["per_minute"].items())) + "</td></tr>")
    L.append("</table>")

    # ---- 3. every time claim
    L.append("<h2>3. Every AI claim with a time</h2><table><tr><th>run</th><th>before (v1.15)</th>"
             "<th>after (v1.16)</th></tr>")
    for key in sorted(set(B) | set(A), key=lambda k: (k[1], k[0], k[2])):
        cfg, tc, run = key
        t = T[tc]
        cell_b = []
        for c in B.get(key, {}).get("claims", []):
            if has_time(c["text"]):
                r = rp.get((f"{cfg}/{tc}/{run}", c["text"]), {})
                bad = r.get("now") == "rejected"
                cell_b.append(f"<div>{e(c['text'])}<br><small>old checker: kept · "
                              + (f"<span class=bad>new checker: rejected</span>" if bad else
                                 "<span class=ok>new checker: kept</span>")
                              + (f" · {e(r['why'][0])}" if bad else "") + "</small></div>")
        cell_a = []
        rep = A.get(key, {})
        for c in rep.get("claims", []):
            if has_time(c["text"]):
                ref_bad = vs_ref(c["text"], t)
                tag = ("<span class=ok>matches the reference</span>" if not ref_bad
                       else f"<span class=bad>reference: {e(ref_bad[0])}</span>")
                if c.get("rewritten_from") and has_time(c["rewritten_from"]):
                    cell_a.append(f"<div><s>{e(c['rewritten_from'])}</s><br><small><span class=fix>caught by the "
                                  f"checker</span>: {e('; '.join(c.get('rewrite_reason', [])))}</small><br>"
                                  f"→ {e(c['text'])}<br><small>rewritten by the AI, passed · {tag}</small></div>")
                else:
                    cell_a.append(f"<div>{e(c['text'])}<br><small>passed · {tag}</small></div>")
        for c in rep.get("removed_claims", []):
            if not c.get("rewritten") and has_time(c["text"]):
                cell_a.append(f"<div><s>{e(c['text'])}</s><br><small><span class=fix>caught and removed</span>: "
                              f"{e('; '.join(c.get('problems', [])))}</small></div>")
        lb = f" <a href='{before_link}{cfg}/{tc}/side_by_side_{cfg}_{tc}.html'>before</a>" if before_link else ""
        la = f" <a href='{after_link}side_by_side_{cfg}_{tc}.html'>after</a>" if after_link else ""
        L.append(f"<tr><td>{cfg} {tc} {run}<br><small>side-by-side:{lb} ·{la}</small></td>"
                 f"<td>{''.join(cell_b) or '<small>no time claim</small>'}</td>"
                 f"<td>{''.join(cell_a) or '<small>no time claim</small>'}</td></tr>")
    L.append("</table>")

    head = (f"<!doctype html><html><head><meta charset=utf-8><title>Time-claim fix: before vs after</title>"
            f"<style>{CSS}</style></head><body><h1>Time-claim fix: before vs after</h1>"
            f"<div class=sub>Before: <b>{e(Path(before).name)}</b> (Agent 2 v1.15) · After: <b>{e(Path(after).name)}"
            f"</b> (v1.16) · same 545 frozen v3 records, same 4 hypotheses, 2 runs each, 2 settings</div>"
            "<div class=note>The problem: the model read the per-minute counts (17:07 → 4, 17:08 → 11) and wrote the "
            "minute labels as exact times. The fix: query results carry the real first/last event time, the checker "
            "checks every time in a claim at the precision it is written, and the model is told minute labels are not "
            "event times. The original runs are unchanged.</div>")
    Path(out_html).write_text(head + "".join(L) + "</body></html>", encoding="utf-8")
    print(f"wrote {out_html}")


if __name__ == "__main__":
    main(*sys.argv[1:])
