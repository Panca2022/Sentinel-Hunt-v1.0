#!/usr/bin/env python3
"""
One case of a run-twice folder, run 1 vs run 2, everything on one page:
  1. match overview: each part identical (✓) or different (≠)
  2. the HUNT RESULT of both runs (same lines as the terminal box, hunt_agent.result_lines); words that differ
     between the two AI summaries are highlighted
  3. all AI claims (kept / rewritten after checker feedback / removed)
  4. every query of both runs in one aligned table (who proposed it, result in run 1 and run 2)
  5. key evidence record ids
Writes HTML, plus PNG if Playwright exists.

Usage:  python experiments/side_by_side_image.py experiments/run_twice_<stamp> converged TC1
"""
import difflib
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent2"))
import hunt_agent  # noqa: E402

CSS = """body{font-family:Segoe UI,Arial,sans-serif;background:#f4f5f7;margin:24px;color:#1b1f24;width:1500px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:17px;margin:22px 0 8px}.sub{color:#555;margin-bottom:12px;font-size:14px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.col h3{margin:0 0 8px}
.box{background:#fff;border-radius:8px;padding:10px 14px;margin-bottom:10px;border-left:5px solid #999;font-size:13.5px;position:relative;padding-right:110px}
.code{border-left-color:#2e7d32}.ai{border-left-color:#1565c0}.you{border-left-color:#9e9e9e}
.row{display:grid;grid-template-columns:96px 1fr;gap:10px;margin:3px 0}.k{font-weight:600;color:#444}
.v{font-weight:700;font-size:16px}.same,.diff{position:absolute;right:10px;top:8px;font-size:11px;font-weight:700;
padding:1px 7px;border-radius:9px}.same{background:#e7f6ec;color:#1e6b34}.diff{background:#fff1d6;color:#8a5a00}
mark{background:#ffe08a;padding:0 1px;border-radius:2px}
.legend span{display:inline-block;padding:2px 8px;border-radius:4px;margin-right:8px;color:#fff;font-size:12px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:12.5px;border-radius:8px;overflow:hidden}
th,td{border-bottom:1px solid #eceef1;padding:5px 8px;text-align:left;vertical-align:top;white-space:nowrap}
td.q{white-space:normal}th{background:#fafbfc;color:#555}
td.q{font-family:Consolas,monospace;font-size:12px;word-break:break-word}.only{background:#fff8e6}
ul{margin:4px 0 0 18px;padding:0}li{margin-bottom:5px}small{color:#666}.rw{background:#eef4ff;border-radius:3px;padding:0 2px}
.ov td{font-size:13.5px}.ok{color:#1e6b34;font-weight:700}.no{color:#8a5a00;font-weight:700}"""

CARDS = [("you", ["Question"]), ("ai", ["AI picked", "Focus"]), ("code", ["Searched"]),
         ("code", ["Verdict", "Decided by", "Why", "Also found"]), ("ai", ["AI summary"]),
         ("code", ["Checked", "Queries", "Report", "Note"])]
VERDICT_COLOR = {"DETECTION CRITERIA MATCHED": "#b42318", "NOT FOUND": "#2e7d32"}
# lines that legitimately differ per run (ids, runtime, counts of checks) are not compared
NOT_COMPARED = {"Report", "Checked", "Queries", "Note"}
e = lambda x: html.escape(str(x))


def word_diff(a, b):
    """Return (a_html, b_html) with the words that differ highlighted."""
    wa, wb = a.split(), b.split()
    oa, ob = [], []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, wa, wb).get_opcodes():
        x, y = e(" ".join(wa[i1:i2])), e(" ".join(wb[j1:j2]))
        if op == "equal":
            oa.append(x), ob.append(y)
        else:
            if x:
                oa.append(f"<mark>{x}</mark>")
            if y:
                ob.append(f"<mark>{y}</mark>")
    return " ".join(oa), " ".join(ob)


def qsig(q):
    a = q["args"]
    return json.dumps({"tool": q["tool"], "agg": a.get("agg_type"), "field": a.get("field"), "query": a.get("query"),
                       "size": a.get("size")}, sort_keys=True)


def qlabel(q):
    a = q["args"]
    if q["tool"] == "aggregate":
        return f"{a.get('agg_type')} {a.get('field')}"
    return q["tool"]


def origin(rep):
    fu = {f.get("query_id") for f in rep.get("followups", []) if f.get("query_id")}
    out = {}
    for q in rep["queries"]:
        a = q["args"]
        if q["query_id"] in fu:
            out[q["query_id"]] = "AI follow-up"
        elif a.get("query") == "*" and a.get("agg_type") == "terms" and a.get("size") == 50:
            out[q["query_id"]] = "value list (code)"
        else:
            out[q["query_id"]] = "playbook (code)"
    return out


def cards(rep, other, side):
    lines, olines = dict(hunt_agent.result_lines(rep)), dict(hunt_agent.result_lines(other))
    out = []
    for cls, labels in CARDS:
        rows, same = [], True
        for k in labels:
            if k not in lines:
                continue
            val = str(lines[k])
            if k not in NOT_COMPARED and val != str(olines.get(k, "")):
                same = False
            if k == "AI summary":
                a, b = word_diff(val, str(olines.get(k, "")))
                txt = a
            else:
                txt = e(val)
            if k == "Verdict":
                txt = f"<span class=v style='color:{VERDICT_COLOR.get(val, '#8a5a00')}'>{txt}</span>"
            rows.append(f"<div class=row><div class=k>{k}</div><div>{txt}</div></div>")
        if rows:
            compared = any(k not in NOT_COMPARED and k in lines for k in labels)
            badge = (f"<span class={'same' if same else 'diff'}>{'✓ identical' if same else '≠ differs'}</span>"
                     if compared else "")
            out.append(f"<div class='box {cls}'>{badge}{''.join(rows)}</div>")
    return "".join(out)


def claims_html(rep):
    items = []
    for c in rep["claims"]:
        if c.get("rewritten_from"):
            items.append(f"<li><span class=rw>{e(c['text'])}</span><br><small>rewritten by the AI after checker "
                         f"feedback; first version: <s>{e(c['rewritten_from'])}</s></small></li>")
        else:
            items.append(f"<li>{e(c['text'])}</li>")
    for c in rep.get("removed_claims", []):
        if not c.get("rewritten"):
            items.append(f"<li><s>{e(c['text'])}</s><br><small>removed by the checker: "
                         f"{e('; '.join(c.get('problems', [])))}</small></li>")
    return "<ul>" + "".join(items) + "</ul>" if items else "(none)"


def queries_table(r1, r2):
    o1, o2 = origin(r1), origin(r2)
    m1 = {qsig(q): q for q in r1["queries"]}
    m2 = {qsig(q): q for q in r2["queries"]}
    order = list(m1) + [s for s in m2 if s not in m1]
    rows = []
    for i, s in enumerate(order, 1):
        q1, q2 = m1.get(s), m2.get(s)
        q = q1 or q2
        who = (o1.get(q1["query_id"]) if q1 else o2.get(q2["query_id"]))
        res1 = e(q1.get("summary", q1.get("status"))) if q1 else "<i>not run</i>"
        res2 = e(q2.get("summary", q2.get("status"))) if q2 else "<i>not run</i>"
        mark = "✓" if q1 and q2 else "only run 1" if q1 else "only run 2"
        rows.append(f"<tr class='{'' if q1 and q2 else 'only'}'><td>{i}</td><td>{e(who)}</td><td>{e(qlabel(q))}</td>"
                    f"<td class=q>{e(q['args'].get('query'))}</td><td>{res1}</td><td>{res2}</td><td>{mark}</td></tr>")
    # AI follow-ups that never ran (rejected / skipped) - listed so nothing is hidden
    for n, rep in (("run 1", r1), ("run 2", r2)):
        for f in rep.get("followups", []):
            if f.get("status") != "ok":
                rows.append(f"<tr class=only><td>-</td><td>AI follow-up</td><td>{e(f.get('tool'))}</td>"
                            f"<td class=q>{e(f.get('query'))}</td><td colspan=3 style='white-space:normal'>{n}: <b>{e(f.get('status'))}</b> "
                            f"({e(f.get('note', ''))[:140]})</td></tr>")
    both = sum(1 for s in order if s in m1 and s in m2)
    head = ("<table><tr><th>#</th><th>proposed by</th><th>type</th><th>query (Lucene)</th><th>result run 1</th>"
            "<th>result run 2</th><th>in both?</th></tr>")
    return both, len(order), head + "".join(rows) + "</table>"


def main(folder, cfg, case):
    folder = Path(folder)
    r1 = json.loads((folder / cfg / case / "run1" / "report.json").read_text())
    r2 = json.loads((folder / cfg / case / "run2" / "report.json").read_text())
    comp = folder / "comparison.json"
    unchanged = json.loads(comp.read_text()).get("data_unchanged") if comp.exists() else None
    setting = "temperature 0, seed 42" if cfg == "converged" else "temperature 0.7, no fixed seed"
    both, total, qtable = queries_table(r1, r2)
    ev1 = [x["_id"] for x in r1.get("key_evidence") or []]
    ev2 = [x["_id"] for x in r2.get("key_evidence") or []]
    t1, t2 = sorted(c["text"] for c in r1["claims"]), sorted(c["text"] for c in r2["claims"])
    sim = round(difflib.SequenceMatcher(None, " ".join(t1), " ".join(t2)).ratio(), 2)
    ov = [("Verdict (code)", r1["verdict"] == r2["verdict"], r1["verdict"]),
          ("Playbook (AI pick, fixed list)", r1["playbook"] == r2["playbook"], r1["playbook_title"]),
          ("Why / rule text (code)", r1["verdict_rule"] == r2["verdict_rule"], "word for word"),
          ("Key evidence ids (code)", ev1 == ev2, f"{len(ev1)} records"),
          ("Queries", both == total, f"{both} of {total} identical in both runs"),
          ("AI summary", r1["summary"] == r2["summary"],
           "exact match" if r1["summary"] == r2["summary"] else
           f"same facts, wording differs (similarity {difflib.SequenceMatcher(None, r1['summary'], r2['summary']).ratio():.2f})"),
          ("AI claims", t1 == t2, "exact match" if t1 == t2 else f"wording differs (similarity {sim})")]
    ovrows = "".join(f"<tr><td>{k}</td><td class={'ok' if s else 'no'}>{'✓ identical' if s else '≠ differs'}</td>"
                     f"<td>{e(d)}</td></tr>" for k, s, d in ov)
    page = (f"<!doctype html><html><head><meta charset=utf-8><title>Run twice: full comparison</title>"
            f"<style>{CSS}</style></head><body><h1>Same hypothesis run twice: full comparison</h1>"
            f"<div class=sub>{e(r1['model'])} ({setting}) · data unchanged between runs: "
            f"<b>{'yes' if unchanged else 'NO' if unchanged is False else '?'}</b> (sha256 of all record ids and "
            f"contents identical) · {e(folder.name)} · {e(cfg)} · {e(case)}</div>"
            f"<div class=legend><span style='background:#9e9e9e'>your input</span>"
            f"<span style='background:#1565c0'>written by the AI</span>"
            f"<span style='background:#2e7d32'>decided / checked by code</span>"
            f"<mark style='color:#1b1f24'>highlighted = words that differ</mark></div>"
            f"<h2>1. What matched</h2><table class=ov><tr><th>part</th><th>run 1 vs run 2</th><th>detail</th></tr>"
            f"{ovrows}</table>"
            f"<h2>2. Hunt result</h2><div class=grid><div class=col><h3>Run 1</h3>{cards(r1, r2, 1)}</div>"
            f"<div class=col><h3>Run 2</h3>{cards(r2, r1, 2)}</div></div>"
            f"<h2>3. AI claims (each checked by code against the query results)</h2><div class=grid>"
            f"<div class='box ai'>{claims_html(r1)}</div><div class='box ai'>{claims_html(r2)}</div></div>"
            f"<h2>4. Every query ({both} of {total} identical in both runs)</h2>{qtable}"
            f"<h2>5. Key evidence (chosen by code)</h2><div class=grid>"
            f"<div class='box code'>{'<br>'.join(e(x) for x in ev1) or '(none)'}</div>"
            f"<div class='box code'>{'<br>'.join(e(x) for x in ev2) or '(none)'}</div></div></body></html>")
    out = folder / f"side_by_side_{cfg}_{case}.html"
    out.write_text(page, encoding="utf-8")
    print(f"wrote {out}")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1550, "height": 900}, device_scale_factor=2)
            pg.goto(out.resolve().as_uri())
            pg.screenshot(path=str(out.with_suffix(".png")), full_page=True)
            b.close()
        print(f"wrote {out.with_suffix('.png')}")
    except Exception as ex:
        print(f"(no PNG: {ex.__class__.__name__}; open the HTML in a browser instead)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "converged", sys.argv[3] if len(sys.argv) > 3 else "TC1")
