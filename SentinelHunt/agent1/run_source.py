#!/usr/bin/env python3
"""
Agent 1 end to end for ONE feed: "point at a source, agents do the rest" (R2 + R3).

  raw staging (teammate kit: sentinelhunt-raw-v1, raw_line + feed_name)
    -> split the feed into layouts by line shape (code; a feed may mix formats)
    -> per layout: reuse a registered template, or create + validate + register one (v3.3 core + v4 stages C/D/E)
    -> router pipeline  feed-<feed>  tries the layout pipelines in turn
    -> reindex raw records of the feed through the router into the parsed hunt index (_id = record_id)
    -> templates mirrored into the schema-registry index for reuse

Called by the MCP server's `process_source` tool (Agent 1's ES access = the agent1 account of the kit, inside
the MCP backend; credentials never reach the model). Also runnable directly for testing:
  .venv/bin/python agent1/run_source.py --feed v3-mixed-pilot [--fresh]      (uses env ES_URL etc.)
"""
import argparse
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import schema_agent as sa  # noqa: E402
import stages_v4 as v4  # noqa: E402

CFG = {"raw_index": "sentinelhunt-raw-v1", "raw_field": "raw_line", "feed_field": "feed_name",
       "hunt_index": "sentinelhunt-hunt-v1", "registry_index": "sentinelhunt-schema-v1"}
WORK = HERE.parent / "samples" / "feeds"
MAX_RECORDS = 10000


def token_shape(tok):
    return re.sub(r"9+", "9", re.sub(r"a+", "a", re.sub(r"\d", "9", re.sub(r"[A-Za-z]", "a", tok))))


def layout_of(line):
    return " ".join(token_shape(t) for t in line.split()[:2])


def slug(text):
    return re.sub(r"[^a-z0-9_-]", "-", text.lower())


def es(method, path, body=None, timeout=600):
    return sa.http(method, f"{sa.ES_URL}{path}", body, timeout=timeout)


def fetch_feed(feed):
    body = {"size": MAX_RECORDS, "query": {"term": {CFG["feed_field"]: feed}},
            "_source": [CFG["raw_field"], "record_id"], "sort": [{"_doc": "asc"}]}
    status, resp = es("POST", f"/{CFG['raw_index']}/_search", body)
    if status != 200:
        raise RuntimeError(f"cannot read raw staging: {sa.es_error(resp)}")
    return [h["_source"].get(CFG["raw_field"], "") for h in resp["hits"]["hits"]], resp["hits"]["total"]["value"]


def list_feeds():
    body = {"size": 0, "aggs": {"f": {"terms": {"field": CFG["feed_field"], "size": 100}}}}
    status, resp = es("POST", f"/{CFG['raw_index']}/_search", body)
    if status != 200:
        return {"error": sa.es_error(resp)}
    return [{"feed": b["key"], "raw_records": b["doc_count"]} for b in resp["aggregations"]["f"]["buckets"]]


def sync_registry_from_es():
    """Remote registry index -> local cache file (so registry matching works on any machine)."""
    status, resp = es("POST", f"/{CFG['registry_index']}/_search", {"size": 500})
    if status != 200:
        return 0
    remote = [json.loads(h["_source"]["template_json"]) for h in resp["hits"]["hits"]
              if h["_source"].get("template_json") not in (None, "null")]
    local = {e["name"]: e for e in sa.load_json(sa.REGISTRY, [])}
    for e in remote:
        local[e["name"]] = e
    sa.REGISTRY.write_text(json.dumps(list(local.values()), indent=2))
    return len(remote)


def push_registry_entry(name, feed, layout_shape, processors):
    entry = next((e for e in sa.load_json(sa.REGISTRY, []) if e["name"] == name), None)
    doc = {"name": name, "feed_name": feed, "layout_shape": layout_shape, "version": (entry or {}).get("version"),
           "model": sa.MODEL, "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "processors_json": json.dumps(processors), "template_json": json.dumps(entry)}   # strings: no mapping drift
    st, resp = es("PUT", f"/{CFG['registry_index']}/_doc/{name}", doc)
    if st not in (200, 201):
        raise RuntimeError(f"registry write failed: {sa.es_error(resp)}")


def router(feed, pipelines):
    """feed-<feed>: try each layout pipeline; if its header grok fails, the next one runs (on_failure chain)."""
    chain = None
    for name in reversed(pipelines):
        proc = {"pipeline": {"name": name}}
        if chain:
            proc["pipeline"]["on_failure"] = [chain]
        chain = proc
    name = f"feed-{slug(feed)}"
    status, resp = es("PUT", f"/_ingest/pipeline/{name}",
                      {"description": f"Agent 1 router for feed {feed}", "processors": [chain],
                       "_meta": {"created_by": "schema_agent_v4", "layouts": pipelines}})
    if status != 200:
        raise RuntimeError(f"router registration failed: {sa.es_error(resp)}")
    return name


def process_feed(feed, fresh=False, log=print):
    t0 = time.perf_counter()
    synced = sync_registry_from_es()
    lines, total = fetch_feed(feed)
    if not lines:
        return {"feed": feed, "error": f"no raw records with {CFG['feed_field']}={feed} in {CFG['raw_index']}"}
    groups = defaultdict(list)
    for l in lines:
        groups[layout_of(l)].append(l)
    log(f"[{feed}] {len(lines)} raw records ({total} in staging) -> {len(groups)} layouts; "
        f"{synced} templates in the registry index")
    WORK.mkdir(parents=True, exist_ok=True)
    layouts, pipelines = [], []
    for n, (shape, ls) in enumerate(sorted(groups.items(), key=lambda x: -len(x[1])), 1):
        source = f"{slug(feed)}-layout{n}"
        path = WORK / f"{source}.log"
        path.write_text("\n".join(ls) + "\n", encoding="utf-8")
        run = sa.process(str(path), source, fresh=fresh, do_register=True, verbose=True)
        row = {"layout": source, "shape": shape, "lines": len(ls), "outcome": run["outcome"],
               "template": run.get("template")}
        if not run.get("template"):
            row["note"] = "no template: needs a human"
            layouts.append(row)
            continue
        entry = next((e for e in sa.load_json(sa.REGISTRY, []) if e["name"] == run["template"]), {})
        procs, extending = [], False
        if run["outcome"] == "matched" and entry.get("version") == "4":
            status, resp = es("GET", f"/_ingest/pipeline/{run['template']}")
            procs = resp.get(run["template"], {}).get("processors", []) if status == 200 else []
            if procs:
                log(f"  ✓ reused v4 template {run['template']} (no LLM calls)")
                row["v4"] = "reused"
            elif entry.get("v4", {}).get("processors"):      # template known, pipeline not on this ES -> restore
                procs = entry["v4"]["processors"]
                st, r2 = es("PUT", f"/_ingest/pipeline/{run['template']}",
                            {"description": "Schema Agent v4 template (restored from registry)", "processors": procs})
                if st != 200:
                    procs = []
                else:
                    log(f"  ✓ reused v4 template {run['template']}: pipeline restored from the registry (no LLM calls)")
                    row["v4"] = "reused (restored)"
            if not procs:
                log(f"  template {run['template']} matched but its v4 pipeline is unavailable here -> rebuilding stages C/D/E")
            elif entry.get("v4"):
                ts0 = run.get("timestamp") or ({"formats": entry.get("timestamp_formats"),
                                                "ts_pattern": entry.get("ts_pattern")} if entry.get("timestamp_formats") else None)
                new = v4.unseen_message_types(entry["v4"], ts0, ls)
                if new:
                    log(f"  {sum(n for _, n in new)} line(s) of message types this template has not seen "
                        f"({', '.join(repr(k) for k, _ in new)}) -> extending it: header reused, message stages "
                        f"C/D/E rebuilt on all lines")
                    procs, extending = [], True
        if procs:
            pass
        else:
            ts = run.get("timestamp") or ({"formats": entry.get("timestamp_formats"),
                                           "ts_pattern": entry.get("ts_pattern")} if entry.get("timestamp_formats") else None)
            res = v4.run_v4(run.get("grok_pattern") or entry["grok_pattern"], ts, ls, log)
            if res["output_problems"] or res["parse_rate"] < sa.PARSE_THRESHOLD:
                row.update(note=f"v4 output check failed: {res['output_problems'] or res['parse_rate']}")
                layouts.append(row)
                continue
            v4.register_v4(source if run["outcome"] != "matched" else run["template"].replace("logs-", "", 1), res, ts)
            row["v4"] = "extended (new message types)" if extending else "built"
            procs = res["processors"]
        push_registry_entry(run["template"], feed, shape, procs)
        pipelines.append(run["template"])
        layouts.append(row)
    if not pipelines:
        return {"feed": feed, "layouts": layouts, "error": "no layout could be schematised"}
    rname = router(feed, pipelines)
    body = {"source": {"index": CFG["raw_index"], "query": {"term": {CFG["feed_field"]: feed}}},
            "dest": {"index": CFG["hunt_index"], "pipeline": rname, "op_type": "index"}}
    # no refresh=true: the agent1 account may write but not run index maintenance (least privilege);
    # ES makes the documents searchable within its 1 s refresh interval anyway
    status, resp = es("POST", "/_reindex?wait_for_completion=true", body, timeout=900)
    time.sleep(2)
    if status != 200:
        fails = resp.get("failures", []) if isinstance(resp, dict) else []
        return {"feed": feed, "layouts": layouts, "router": rname,
                "error": f"reindex failed: HTTP {status}: {sa.es_error(resp) if resp.get('error') else ''}",
                "created": resp.get("created"), "updated": resp.get("updated"), "failed": len(fails),
                "failure_examples": [json.dumps(f.get("cause", f))[:400] for f in fails[:3]],
                "response_head": json.dumps(resp)[:600]}
    fails = resp.get("failures", [])
    out = {"feed": feed, "layouts": layouts, "router": rname, "hunt_index": CFG["hunt_index"],
           "indexed": resp.get("created", 0) + resp.get("updated", 0), "created": resp.get("created", 0),
           "updated": resp.get("updated", 0), "failed": len(fails),
           "failure_examples": [str(f.get("cause", {}).get("reason", f))[:200] for f in fails[:3]],
           "seconds": round(time.perf_counter() - t0, 1)}
    log(f"[{feed}] indexed {out['indexed']} parsed records into {CFG['hunt_index']} via {rname}; "
        f"failed {out['failed']} ({out['seconds']}s)")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", help="feed_name in raw staging (omit to list feeds)")
    ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()
    if not sa.check_es():
        sys.exit(f"Elasticsearch not reachable at {sa.ES_URL}")
    if not a.feed:
        print(json.dumps(list_feeds(), indent=2))
    else:
        print(json.dumps(process_feed(a.feed, a.fresh), indent=2, default=str))
