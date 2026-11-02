#!/usr/bin/env python3
"""
Simple side-by-side view of a run-twice folder: for every case, run 1 and run 2 next to each other
(verdict, why, AI summary, AI claims, AI follow-up queries, key evidence ids). Lines that differ are marked ≠.

Usage:  python experiments/side_by_side.py experiments/run_twice_<stamp>     -> writes <folder>/side_by_side.md
"""
import json
import sys
from pathlib import Path


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def lines(rep):
    fu = [f"[{f.get('status')}] {f.get('query')}" for f in rep.get("followups", [])]
    return {
        "Verdict": [rep["verdict"]],
        "Why (code rule)": [rep["verdict_rule"]],
        "AI summary": [rep["summary"]],
        "AI claims (kept)": [c["text"] + ("  (rewritten by the AI after checker feedback)" if c.get("rewritten_from") else "")
                             for c in rep["claims"]] or ["(none)"],
        "AI claims rejected by checker": [f"{c['text']}  → {'; '.join(c.get('problems', []))}"
                                          + ("  → rewritten" if c.get("rewritten") else "  → removed")
                                          for c in rep.get("removed_claims", [])] or ["(none)"],
        "AI follow-up queries": fu or ["(none)"],
        "Key evidence ids": [", ".join(e["_id"] for e in rep.get("key_evidence") or []) or "(none)"],
        "Queries run": [str(len(rep["queries"]))],
    }


def main(folder):
    folder = Path(folder)
    out = [f"# Run 1 vs run 2, side by side ({folder.name})", "",
           "≠ = the two runs differ in this section. Verdict, rule and key evidence are decided by code; "
           "summary, claims and follow-up queries are written by the AI.", ""]
    for cfg_dir in sorted(p for p in folder.iterdir() if p.is_dir() and not p.name.startswith("_")):
        for case_dir in sorted(p for p in cfg_dir.iterdir() if p.is_dir()):
            r1 = json.loads((case_dir / "run1" / "report.json").read_text())
            r2 = json.loads((case_dir / "run2" / "report.json").read_text())
            a, b = lines(r1), lines(r2)
            out += [f"## {cfg_dir.name} · {case_dir.name}", "", f"**Hypothesis:** {r1['hypothesis']}", "",
                    "| | | Run 1 | Run 2 |", "|---|---|---|---|"]
            for sec in a:
                same = a[sec] == b[sec]
                n = max(len(a[sec]), len(b[sec]))
                for i in range(n):
                    x = a[sec][i] if i < len(a[sec]) else ""
                    y = b[sec][i] if i < len(b[sec]) else ""
                    out.append(f"| {('**' + sec + '**') if i == 0 else ''} | {('' if same else '≠') if i == 0 else ''} "
                               f"| {cell(x)} | {cell(y)} |")
            out.append("")
    path = folder / "side_by_side.md"
    path.write_text("\n".join(out))
    print(f"wrote {path}")


if __name__ == "__main__":
    main(sys.argv[1])
