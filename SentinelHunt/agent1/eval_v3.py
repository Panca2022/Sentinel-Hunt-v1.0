#!/usr/bin/env python3
"""
Agent 1 (v3.3 core + v4 stages C/D/E) on the teammate's v3 raw lines, scored against parsing-reference.ndjson.

  1. Read inputs.ndjson (record_id, raw_line). Labels / source types are NOT used for parsing.
  2. Split the mixed file into layouts by line SHAPE only (code, no labels): the first two tokens
     with letters -> a, digits -> 9. (Agent 1 parses one layout at a time.)
  3. Run Agent 1 (schema_agent.process) on each layout: reuse a registered template or create,
     validate and register a new ES ingest pipeline.
  4. Run EVERY line of that layout through the registered pipeline (ES _simulate) and compare
     with the reference, field by field:
       value found  = the reference value appears in some field Agent 1 extracted (parsing accuracy)
       name match   = ... under the same ECS field name (naming accuracy)
     Derived fields that are not literally in the line (event.action, event.outcome, log.category,
     event.original, message) are reported separately: Agent 1 only extracts text, it does not
     interpret it.
  5. Write experiments/agent1_v3_eval_<ts>.md + .json

Usage (from ~/se6014):
  .venv/bin/python agent1/eval_v3.py /mnt/c/Users/ckung/Downloads/sentinelhunt-multisource-v3 [--fresh]
Env: ES_URL, OLLAMA_URL, MODEL (same as schema_agent.py). Standard library only.
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import schema_agent as sa  # noqa: E402
import stages_v4 as v4  # noqa: E402

ROOT = HERE.parent
DERIVED = {"event.action", "event.outcome", "log.category"}     # interpretations: scored, vocabulary from reference
SKIP = {"message", "event.original"}                             # message differs by convention; original checked separately
FEED = "v3-mixed-pilot"


def token_shape(tok):
    return re.sub(r"9+", "9", re.sub(r"a+", "a", re.sub(r"\d", "9", re.sub(r"[A-Za-z]", "a", tok))))


def layout_of(line):
    toks = line.split()
    return " ".join(token_shape(t) for t in toks[:2])


def flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flat(v, prefix + k + "."))
        else:
            out[prefix + k] = v
    return out


def norm(v):
    return str(v).strip().lower()


def same_time(a, b):
    try:
        fa = datetime.fromisoformat(str(a).replace("Z", "+00:00"))
        fb = datetime.fromisoformat(str(b).replace("Z", "+00:00"))
        return abs((fa - fb).total_seconds()) < 1.0
    except Exception:
        return False


def run_pipeline(name, recs):
    """Simulate the registered pipeline on staging-shaped records (as the teammate's raw index holds them)."""
    docs = []
    for i in range(0, len(recs), 500):
        chunk = recs[i:i + 500]
        status, resp = sa.http("POST", f"{sa.ES_URL}/_ingest/pipeline/{name}/_simulate",
                               {"docs": [{"_source": {"record_id": r["record_id"], "capture_id": r["capture_id"],
                                                      "raw_line": r["raw_line"], "feed_name": FEED,
                                                      "ingestion_channel": "pull"}} for r in chunk]})
        if status != 200:
            raise RuntimeError(f"simulate failed: {sa.es_error(resp)}")
        for d in resp.get("docs", []):
            docs.append(None if ("error" in d or "doc" not in d) else flat(d["doc"]["_source"]))
    return docs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("v3_dir")
    ap.add_argument("--fresh", action="store_true", help="ignore registered templates (force generation)")
    a = ap.parse_args()
    if not sa.check_es():
        sys.exit(f"Elasticsearch not reachable at {sa.ES_URL}")
    d = Path(a.v3_dir)
    inputs = [json.loads(l) for l in open(d / "inputs.ndjson", encoding="utf-8") if l.strip()]
    ref = {r["record_id"]: r for r in (json.loads(l) for l in open(d / "parsing-reference.ndjson", encoding="utf-8")
                                         if l.strip())}

    # 1-2. split by layout (shape only)
    groups = defaultdict(list)
    for rec in inputs:
        groups[layout_of(rec["raw_line"])].append(rec)
    work = ROOT / "samples" / "v3"
    work.mkdir(parents=True, exist_ok=True)
    print(f"{len(inputs)} raw lines -> {len(groups)} layouts (split by line shape, no labels used)")

    rows, per_field = [], defaultdict(lambda: Counter())
    for n, (shape_key, recs) in enumerate(sorted(groups.items(), key=lambda x: -len(x[1])), 1):
        source = f"v3-layout{n}"
        truth_mix = Counter(ref[r["record_id"]].get("source_type") or ref[r["record_id"]]["log_type"] for r in recs)
        print(f"\n=== {source}: {len(recs)} lines, shape '{shape_key}'  (reference types, for reporting only: "
              f"{dict(truth_mix)})")
        path = work / f"{source}.log"
        path.write_text("\n".join(r["raw_line"] for r in recs) + "\n", encoding="utf-8")

        # 3. Agent 1: v3.3 core (select or create header grok + timestamp) ...
        t0 = datetime.now()
        run = sa.process(str(path), source, fresh=a.fresh, do_register=True)
        row = {"layout": source, "shape": shape_key, "lines": len(recs), "reference_types": dict(truth_mix),
               "outcome": run["outcome"], "template": run.get("template"), "grok_pattern": run.get("grok_pattern")}
        if not run.get("template"):
            rows.append(row)
            continue
        # ... then v4 stages C/D/E, unless the matched template already is a full v4 template (reuse)
        entry = next((e for e in sa.load_json(sa.REGISTRY, []) if e["name"] == run["template"]), {})
        if run["outcome"] == "matched" and entry.get("version") == "4":
            print(f"  ✓ reused v4 template {run['template']} (no LLM calls)")
            row["v4"] = "reused"
        else:
            ts = run.get("timestamp") or ({"formats": entry.get("timestamp_formats"), "ts_pattern": entry.get("ts_pattern")}
                                          if entry.get("timestamp_formats") else None)
            res = v4.run_v4(run.get("grok_pattern") or entry["grok_pattern"], ts, [r["raw_line"] for r in recs])
            v4.register_v4(source, res, ts)
            row["v4"] = {k: res[k] for k in ("header_pattern", "message_patterns", "rename", "drop", "log_category",
                                             "rules", "stage_c", "stage_d", "stage_e", "output_problems")}
            print(f"  registered v4 pipeline {run['template']}")
        row["agent_seconds"] = round((datetime.now() - t0).total_seconds(), 1)

        # 4. every line through the registered pipeline, compare with reference
        docs = run_pipeline(run["template"], recs)
        parsed = sum(x is not None for x in docs)
        found = Counter()
        example = None
        for rec, doc in zip(recs, docs):
            refp = {k: v for k, v in ref[rec["record_id"]]["parsed"].items() if v is not None}
            if doc is None:
                for k in refp:
                    per_field[(source, k)]["total"] += 1
                continue
            if example is None:
                example = {"raw_line": rec["raw_line"], "agent1": {k: v for k, v in doc.items() if k != "message"},
                           "reference": refp}
            values = {norm(v) for k, v in doc.items() if k not in ("message", "raw_line", "event.original")}
            kept = (doc.get("record_id") == rec["record_id"] and doc.get("capture_id") == rec["capture_id"]
                    and doc.get("raw_line") == rec["raw_line"] and doc.get("event.original") == rec["raw_line"]
                    and doc.get("feed_name") == FEED)
            per_field[(source, "(ids + raw line kept)")]["total"] += 1
            per_field[(source, "(ids + raw line kept)")]["value_found"] += kept
            per_field[(source, "(ids + raw line kept)")]["name_match"] += kept
            extra = [k for k in doc if k not in v4.HUNT_FIELDS]
            per_field[(source, "(only hunt-index fields)")]["total"] += 1
            per_field[(source, "(only hunt-index fields)")]["value_found"] += not extra
            per_field[(source, "(only hunt-index fields)")]["name_match"] += not extra
            for k, v in refp.items():
                if k in SKIP:
                    continue
                c = per_field[(source, k)]
                c["total"] += 1
                if k == "@timestamp":
                    ok = same_time(doc.get("@timestamp"), v)
                    c["value_found"] += ok
                    c["name_match"] += ok
                    continue
                c["value_found"] += norm(v) in values
                c["name_match"] += k in doc and norm(doc[k]) == norm(v)
        row.update(parse_rate=round(parsed / len(recs), 3), agent_fields=sorted(
            {k for x in docs if x for k in x if k != "message"}), example=example)
        rows.append(row)

    # summary
    def pct(a_, b_):
        return round(100 * a_ / b_, 1) if b_ else None
    field_rows = []
    for (src, k), c in sorted(per_field.items()):
        field_rows.append({"layout": src, "field": k, "derived": k in DERIVED, "total": c["total"],
                           "value_found_pct": pct(c["value_found"], c["total"]),
                           "name_match_pct": pct(c["name_match"], c["total"])})
    lit = [f for f in field_rows if not f["derived"] and not f["field"].startswith("(")]
    der = [f for f in field_rows if f["derived"]]
    tot = sum(f["total"] for f in lit)
    vf = sum(per_field[(f["layout"], f["field"])]["value_found"] for f in lit)
    nm = sum(per_field[(f["layout"], f["field"])]["name_match"] for f in lit)
    dtot = sum(f["total"] for f in der)
    dnm = sum(per_field[(f["layout"], f["field"])]["name_match"] for f in der)
    summary = {"derived_fields_match_pct": pct(dnm, dtot),
               "lines": len(inputs), "layouts": len(groups),
               "layouts_schematised": sum(r["outcome"] in ("generated", "matched") for r in rows),
               "literal_field_values_found_pct": pct(vf, tot), "literal_field_names_match_pct": pct(nm, tot)}

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = ROOT / "experiments"
    out.mkdir(exist_ok=True)
    (out / f"agent1_v3_eval_{stamp}.json").write_text(json.dumps(
        {"summary": summary, "layouts": rows, "fields": field_rows, "model": sa.MODEL,
         "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")}, indent=2, default=str))
    L = [f"# Agent 1 on teammate v3 raw lines ({stamp})", "",
         f"Model {sa.MODEL}. {summary['lines']} lines → {summary['layouts']} layouts (split by line shape only). "
         f"Schematised automatically: {summary['layouts_schematised']}/{summary['layouts']}.", "",
         f"**Literal fields** (values that appear in the raw line): value found {summary['literal_field_values_found_pct']}%, "
         f"same ECS name {summary['literal_field_names_match_pct']}%. **Derived fields** (event.action / event.outcome / "
         f"log.category; fixed vocabulary taken from the reference): {summary['derived_fields_match_pct']}% match.", "",
         "| layout | lines | reference types | outcome | template | parse rate | agent time (s) |",
         "|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['layout']} | {r['lines']} | {r['reference_types']} | {r['outcome']} | {r.get('template') or '-'} | "
                 f"{r.get('parse_rate', '-')} | {r.get('agent_seconds')} |")
    L += ["", "## Field accuracy vs parsing-reference", "",
          "value found = the reference value was extracted (under any name); name match = under the same ECS name. "
          "Derived fields are interpretations (stage E rules + fixed vocabulary). Rows in brackets are format checks: "
          "IDs/raw line preserved and no field outside the strict hunt mapping.", "",
          "| layout | field | derived | records | value found % | name match % |", "|---|---|---|---|---|---|"]
    for f in field_rows:
        L.append(f"| {f['layout']} | {f['field']} | {'yes' if f['derived'] else ''} | {f['total']} | "
                 f"{f['value_found_pct']} | {f['name_match_pct']} |")
    L += ["", "## Grok patterns and one example per layout", ""]
    for r in rows:
        L += [f"### {r['layout']} ({r['outcome']}, v4: {'reused' if r.get('v4') == 'reused' else 'built'})", "",
              f"Header: `{r.get('grok_pattern')}`", ""]
        if isinstance(r.get("v4"), dict):
            x = r["v4"]
            L += [f"Message patterns (stage C): " + (", ".join(f"`{p}`" for p in x["message_patterns"]) or "none"), "",
                  f"Renames (stage D): {x['rename']} · dropped: {x['drop']}", "",
                  f"Stage E: log.category={x['log_category']}; rules: " +
                  "; ".join(f"{q['field']} {q['op']} '{q['value']}' → {q['action']}/{q['outcome']}" for q in x["rules"]), "",
                  f"Output problems: {x['output_problems'] or 'none'}", ""]
        if r.get("example"):
            L += ["```json", json.dumps(r["example"], indent=2, default=str), "```", ""]
    (out / f"agent1_v3_eval_{stamp}.md").write_text("\n".join(L))

    print("\n=== SUMMARY")
    for r in rows:
        print(f"  {r['layout']:12} {r['lines']:4} lines  {r['outcome']:12} parse {r.get('parse_rate', '-')}  "
              f"types {r['reference_types']}")
    print(f"  literal field values found: {summary['literal_field_values_found_pct']}%  |  "
          f"same ECS name: {summary['literal_field_names_match_pct']}%  |  derived fields match: "
          f"{summary['derived_fields_match_pct']}%")
    for f in field_rows:
        if f["field"].startswith("("):
            print(f"    {f['layout']:12} {f['field']:28} {f['value_found_pct']}%")
    worst = sorted((f for f in lit + der if f["name_match_pct"] is not None), key=lambda f: f["name_match_pct"])[:10]
    for f in worst:
        print(f"    {f['layout']:12} {f['field']:28} value {f['value_found_pct']}%  name {f['name_match_pct']}%")
    print(f"\nSaved experiments/agent1_v3_eval_{stamp}.md (+ .json)")


if __name__ == "__main__":
    main()
