#!/usr/bin/env python3
"""
SentinelHunt MCP server v2: exposes Elasticsearch to the agents as MCP tools.

Tool sets, enforced by the server (not by prompts):
  --role hunt    -> Agent 2 (Hunt agent), READ-ONLY: search, aggregate, get_document, get_query_log
                    (+ list_indices, get_field_mappings)
  --role schema  -> Agent 1 (Schema agent): list_feeds, sample_unparsed, list_templates, simulate_pipeline,
                    register_template, reprocess_unparsed, process_source (+ shared)
  --role ingest  -> "point at a source": list_feeds, process_source (what the ingestion side / user triggers)
  --role all     -> everything (development only)

Guardrails: field validation (unknown fields rejected), query ledger with query IDs + exact ES request +
result hash, result caps, and in kit mode separate least-privilege ES accounts per role (agent2 = read-only on the
hunt index; agent1 = read raw staging, write hunt + registry, manage ingest pipelines). Credentials are loaded by
this backend only and never returned to the model.

Modes
  dev (default): ES_URL http://localhost:9200, no auth, staging logs-unparsed (message, event.dataset)
  kit: set SENTINELHUNT_KIT=/path/to/SentinelHunt_ELK_Portable  -> https://localhost:19200 with the kit CA,
       credentials from runtime/agent1.env (schema/ingest/all) or runtime/agent2.env (hunt),
       staging sentinelhunt-raw-v1 (raw_line, feed_name), parsed sentinelhunt-hunt-v1, registry sentinelhunt-schema-v1
Run (stdio, spawned by an agent):   python3 server.py --role hunt
Run (HTTP):                         python3 server.py --role hunt --http --port 8765
Env overrides: ES_URL, ES_USER/ES_PASS, ES_CA_CERT, ES_VERIFY_TLS, LEDGER_DIR, UNPARSED_INDEX,
               UNPARSED_SOURCE_FIELD, RAW_LINE_FIELD, HUNT_INDEX, REGISTRY_INDEX, INDEX_PATTERN
"""
import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

KIT = os.environ.get("SENTINELHUNT_KIT")
KIT = Path(KIT).expanduser() if KIT else None
ES_URL = os.environ.get("ES_URL", "https://localhost:19200" if KIT else "http://localhost:9200").rstrip("/")
ES_USER, ES_PASS = os.environ.get("ES_USER"), os.environ.get("ES_PASS")
ES_CA_CERT = os.environ.get("ES_CA_CERT", str(KIT / "runtime" / "ca.crt") if KIT else "")
VERIFY_TLS = os.environ.get("ES_VERIFY_TLS", "true").lower() != "false"
LEDGER_DIR = Path(os.environ.get("LEDGER_DIR", Path(__file__).resolve().parent / "ledger"))
UNPARSED_INDEX = os.environ.get("UNPARSED_INDEX", "sentinelhunt-raw-v1" if KIT else "logs-unparsed")
UNPARSED_SOURCE_FIELD = os.environ.get("UNPARSED_SOURCE_FIELD", "feed_name" if KIT else "event.dataset")
RAW_LINE_FIELD = os.environ.get("RAW_LINE_FIELD", "raw_line" if KIT else "message")
HUNT_INDEX = os.environ.get("HUNT_INDEX", "sentinelhunt-hunt-v1" if KIT else "")
REGISTRY_INDEX = os.environ.get("REGISTRY_INDEX", "sentinelhunt-schema-v1" if KIT else "schema-registry")
# Which indices the hunt agent may see (comma-separated, wildcards ok).
INDEX_PATTERN = os.environ.get("INDEX_PATTERN", "sentinelhunt-hunt-v1" if KIT else "logs-*,sentinelhunt-*,-logs-unparsed")
SSL_CTX = None


def configure(role):
    """Load the role's least-privilege credentials (kit mode) and the TLS context. Called once at start."""
    global ES_USER, ES_PASS, SSL_CTX
    if KIT and not ES_USER:
        env_file = KIT / "runtime" / ("agent2.env" if role == "hunt" else "agent1.env")
        vals = dict(l.split("=", 1) for l in env_file.read_text().splitlines() if l and not l.startswith("#"))
        ES_USER, ES_PASS = vals["ES_USERNAME"], vals["ES_PASSWORD"]
    if ES_CA_CERT:
        SSL_CTX = ssl.create_default_context(cafile=ES_CA_CERT)
    elif not VERIFY_TLS:
        SSL_CTX = ssl._create_unverified_context()


MAX_HITS, MAX_BUCKETS, MAX_MSG = 50, 50, 400


# --------------------------------------------------------------------------- Elasticsearch HTTP
def es(method, path, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if ES_USER:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    req = urllib.request.Request(ES_URL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw.decode(errors="replace")[:500]}
    except (urllib.error.URLError, OSError) as e:      # ES down / unreachable -> readable error, no crash
        return 0, {"error": f"cannot reach Elasticsearch at {ES_URL}: {getattr(e, 'reason', e)}"}


def es_reason(resp):
    err = resp.get("error")
    if isinstance(err, dict):
        rc = err.get("root_cause") or [{}]
        return rc[0].get("reason") or err.get("reason") or json.dumps(err)[:300]
    return str(err)[:300]


# --------------------------------------------------------------------------- Mappings / validation
def _flatten_props(props, prefix=""):
    out = {}
    for name, spec in props.items():
        full = prefix + name
        if "properties" in spec:
            out.update(_flatten_props(spec["properties"], full + "."))
        else:
            out[full] = spec.get("type", "object")
            for sub, subspec in spec.get("fields", {}).items():
                out[f"{full}.{sub}"] = subspec.get("type")
    return out


def field_map(index):
    status, resp = es("GET", f"/{index}/_mapping")
    if status != 200:
        return None
    fields = {}
    for idx in resp.values():
        fields.update(_flatten_props(idx.get("mappings", {}).get("properties", {})))
    return fields


QUERY_FIELD_RE = re.compile(r'(?<![\w.@])([A-Za-z_@][\w.@]*)\s*:(?!//)')


def fields_in_query(q):
    stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', q)          # ignore quoted values
    exists = set(re.findall(r'_exists_\s*:\s*([A-Za-z0-9_.@]+)', stripped))   # _exists_:field -> check that field
    return {f for f in QUERY_FIELD_RE.findall(stripped) if f != "_exists_"} | exists


def unknown_fields(index, names):
    fm = field_map(index)
    if fm is None:
        return None, [f"index '{index}' not found"]
    bad = [n for n in names if n not in fm and not any(k.startswith(n + ".") for k in fm)]
    return fm, bad


def agg_field(fm, field):
    """Use the keyword sub-field for text fields (terms/cardinality need keyword)."""
    if fm.get(field) == "text" and f"{field}.keyword" in fm:
        return f"{field}.keyword"
    return field


def time_filter(time_from, time_to):
    if not (time_from or time_to):
        return []
    rng = {}
    if time_from:
        rng["gte"] = time_from
    if time_to:
        rng["lte"] = time_to
    return [{"range": {"@timestamp": rng}}]


# --------------------------------------------------------------------------- Query ledger
def ledger(hunt_id, tool, args, request, status, summary, result):
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", hunt_id or "adhoc")
    path = LEDGER_DIR / f"{safe}.jsonl"
    n = sum(1 for _ in open(path)) + 1 if path.exists() else 1
    qid = f"{safe}-q{n:03d}"
    entry = {"query_id": qid, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "tool": tool, "args": args, "es_request": request, "status": status, "summary": summary,
             "result_sha256": hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()}
    with open(path, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    return qid


def trim(src):
    out = {}
    for k, v in src.items():
        if isinstance(v, str) and len(v) > MAX_MSG:
            v = v[:MAX_MSG] + "…"
        out[k] = v
    return out


# =========================================================================== Shared tools
def list_indices() -> list:
    """List log indices with document counts and time range. Start every task here."""
    status, resp = es("GET", f"/_cat/indices/{INDEX_PATTERN}?format=json&h=index,docs.count&expand_wildcards=open")
    if status != 200:      # least-privilege account (no index monitor): resolve names, count with a search
        st2, res = es("GET", f"/_resolve/index/{INDEX_PATTERN}")
        if st2 != 200:
            return [{"error": es_reason(resp)}]
        resp = []
        for ix in res.get("indices", []):
            _, c = es("POST", f"/{ix['name']}/_search", {"size": 0, "track_total_hits": True})
            resp.append({"index": ix["name"], "docs.count": c.get("hits", {}).get("total", {}).get("value", 0)})
    out = []
    for row in sorted(resp, key=lambda r: r["index"]):
        _, rng = es("POST", f"/{row['index']}/_search", {"size": 0, "aggs": {
            "min": {"min": {"field": "@timestamp"}}, "max": {"max": {"field": "@timestamp"}}}})
        aggs = rng.get("aggregations", {}) if isinstance(rng, dict) else {}
        out.append({"index": row["index"], "docs": int(row.get("docs.count") or 0),
                    "first_event": aggs.get("min", {}).get("value_as_string"),
                    "last_event": aggs.get("max", {}).get("value_as_string")})
    return out


def get_field_mappings(index: str) -> dict:
    """Return every field name and type in an index. Only use field names returned here."""
    fm = field_map(index)
    if fm is None:
        return {"error": f"index '{index}' not found"}
    return {"index": index, "fields": fm}


# =========================================================================== Hunt tools (read-only)
def search(hunt_id: str, index: str, query: str = "*", time_from: Optional[str] = None,
           time_to: Optional[str] = None, size: int = 20, fields: Optional[list[str]] = None) -> dict:
    """Search events. `query` uses Lucene query_string syntax, e.g.
    'event.outcome:failure AND source.ip:"198.51.100.20"'. Times are ISO8601 (e.g. 2026-10-22T00:00:00Z).
    Returns total hit count, up to `size` (max 50) events with their document ids, and a query_id to cite."""
    args = {"index": index, "query": query, "time_from": time_from, "time_to": time_to, "size": size,
            "fields": fields}
    fm, bad = unknown_fields(index, fields_in_query(query) | set(fields or []))
    if bad:
        res = {"error": f"unknown field(s) {bad}", "available_fields": sorted(fm)[:200] if fm else []}
        res["query_id"] = ledger(hunt_id, "search", args, None, "rejected", res["error"], res)
        return res
    body = {"size": max(0, min(size, MAX_HITS)), "track_total_hits": True, "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"must": [{"query_string": {"query": query or "*"}}],
                               "filter": time_filter(time_from, time_to)}}}
    if fields:
        body["_source"] = list(set(fields) | {"@timestamp"})
    body["aggs"] = {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}
    status, resp = es("POST", f"/{index}/_search", body)
    if status != 200:
        res = {"error": es_reason(resp)}
        res["query_id"] = ledger(hunt_id, "search", args, body, "error", res["error"], res)
        return res
    hits = [{"_id": h["_id"], "_index": h["_index"], **trim(h["_source"])} for h in resp["hits"]["hits"]]
    total = resp["hits"]["total"]["value"]
    res = {"total": total, "returned": len(hits), "hits": hits}
    for k in ("first", "last"):                       # real time range of ALL matches, not just returned hits
        v = resp.get("aggregations", {}).get(k, {})
        if v.get("value") is not None:
            res[f"{k}_event"] = v.get("value_as_string", v["value"])
    res["query_id"] = ledger(hunt_id, "search", args, body, "ok", f"{total} hits", res)
    return res


def aggregate(hunt_id: str, index: str, agg_type: Literal["terms", "date_histogram", "cardinality", "stats"],
              field: str, query: str = "*", time_from: Optional[str] = None, time_to: Optional[str] = None,
              interval: str = "1h", size: int = 10) -> dict:
    """Aggregate events. terms = top values of `field` with counts; date_histogram = counts over time
    (field usually @timestamp, interval like 1m/1h/1d); cardinality = number of distinct values;
    stats = min/max/avg/sum of a numeric field. `query` filters events first (Lucene syntax)."""
    args = {"index": index, "agg_type": agg_type, "field": field, "query": query, "time_from": time_from,
            "time_to": time_to, "interval": interval, "size": size}
    fm, bad = unknown_fields(index, fields_in_query(query) | {field})
    if bad:
        res = {"error": f"unknown field(s) {bad}", "available_fields": sorted(fm)[:200] if fm else []}
        res["query_id"] = ledger(hunt_id, "aggregate", args, None, "rejected", res["error"], res)
        return res
    f = agg_field(fm, field)
    if agg_type == "terms":
        agg = {"terms": {"field": f, "size": max(1, min(size, MAX_BUCKETS))}}
    elif agg_type == "date_histogram":
        agg = {"date_histogram": {"field": f, "fixed_interval": interval, "min_doc_count": 1}}
    elif agg_type == "cardinality":
        agg = {"cardinality": {"field": f}}
    else:
        agg = {"stats": {"field": f}}
    aggs = {"a": agg,
            "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}  # real time range
    if agg_type != "date_histogram":
        aggs["no_field"] = {"missing": {"field": f}}      # matching events that do not have `field` at all
    body = {"size": 0, "track_total_hits": True, "aggs": aggs,
            "query": {"bool": {"must": [{"query_string": {"query": query or "*"}}],
                               "filter": time_filter(time_from, time_to)}}}
    status, resp = es("POST", f"/{index}/_search", body)
    if status != 200:
        res = {"error": es_reason(resp)}
        res["query_id"] = ledger(hunt_id, "aggregate", args, body, "error", res["error"], res)
        return res
    a = resp["aggregations"]["a"]
    extra = {}
    for k in ("first", "last"):
        v = resp["aggregations"][k]
        if v.get("value") is not None:
            extra[f"{k}_event"] = v.get("value_as_string", v["value"])
    if "no_field" in resp["aggregations"]:
        extra["events_without_field"] = resp["aggregations"]["no_field"]["doc_count"]
    total = resp["hits"]["total"]["value"]
    if agg_type in ("terms", "date_histogram"):
        buckets = [{"key": b.get("key_as_string", b["key"]), "count": b["doc_count"]} for b in a["buckets"]][:MAX_BUCKETS]
        res = {"matching_events": total, "buckets": buckets}
        if agg_type == "terms":
            res["other_count"] = a.get("sum_other_doc_count", 0)
    elif agg_type == "cardinality":
        res = {"matching_events": total, "distinct_values": a["value"]}
    else:
        res = {"matching_events": total, "stats": a}
    res.update(extra)
    if agg_type == "date_histogram":
        res["bucket_note"] = f"each bucket key is the START of a {interval} interval"
    summary = f"{total} events" + (f"; {extra['events_without_field']} without {field}"
                                    if extra.get("events_without_field") else "")
    res["query_id"] = ledger(hunt_id, "aggregate", args, body, "ok", summary, res)
    return res


def get_document(hunt_id: str, index: str, id: str) -> dict:
    """Fetch one event by index and document id (to quote exact evidence)."""
    args = {"index": index, "id": id}
    status, resp = es("GET", f"/{index}/_doc/{id}")
    if status != 200 or not resp.get("found"):
        res = {"error": f"document {id} not found in {index}"}
        res["query_id"] = ledger(hunt_id, "get_document", args, None, "not_found", res["error"], res)
        return res
    res = {"_id": resp["_id"], "_index": resp["_index"], **trim(resp["_source"])}
    res["query_id"] = ledger(hunt_id, "get_document", args, {"GET": f"/{index}/_doc/{id}"}, "ok", "found", res)
    return res


def get_query_log(hunt_id: str) -> list:
    """Return every query run in a hunt (for the report's query appendix)."""
    path = LEDGER_DIR / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', hunt_id)}.jsonl"
    return [json.loads(l) for l in open(path)] if path.exists() else []


# =========================================================================== Schema tools (Agent 1)
def sample_unparsed(source: str, n: int = 50) -> dict:
    """Return up to n raw lines from raw staging for one source/feed (feed_name in kit mode)."""
    body = {"size": max(1, min(n, 500)), "query": {"term": {UNPARSED_SOURCE_FIELD: source}}}
    status, resp = es("POST", f"/{UNPARSED_INDEX}/_search", body)
    if status != 200:
        return {"error": es_reason(resp)}
    lines = [h["_source"].get(RAW_LINE_FIELD, "") for h in resp["hits"]["hits"]]
    return {"source": source, "total_unparsed": resp["hits"]["total"]["value"], "lines": lines}


def list_templates() -> list:
    """List registered parsing templates (schema registry)."""
    status, resp = es("POST", f"/{REGISTRY_INDEX}/_search", {"size": 200})
    if status != 200:
        return []
    return [h["_source"] for h in resp["hits"]["hits"]]


def _processors(grok_pattern, ts_pattern=None, timestamp_formats=None):
    procs = [{"grok": {"field": "message", "patterns": [grok_pattern]}}]
    if ts_pattern:
        procs.append({"grok": {"field": "message", "patterns": [ts_pattern]}})
    if timestamp_formats:
        procs.append({"date": {"field": "timestamp", "target_field": "@timestamp", "formats": timestamp_formats}})
    return procs


def simulate_pipeline(grok_pattern: str, samples: list[str], ts_pattern: Optional[str] = None,
                      timestamp_formats: Optional[list[str]] = None) -> dict:
    """Test a grok pattern (optionally + timestamp grok/date formats) against sample lines with ES _simulate.
    Returns parse rate, average extracted fields, failed lines and an example parsed document."""
    body = {"pipeline": {"processors": _processors(grok_pattern, ts_pattern, timestamp_formats)},
            "docs": [{"_source": {"message": l}} for l in samples]}
    status, resp = es("POST", "/_ingest/pipeline/_simulate", body)
    if status != 200:
        return {"valid": False, "error": es_reason(resp)}
    ok, nfields, failed, example, years = 0, 0, [], None, []
    for line, d in zip(samples, resp.get("docs", [])):
        if "doc" not in d:
            failed.append(line)
            continue
        src = d["doc"]["_source"]
        ok += 1
        nfields += len([k for k in src if k not in ("message", "@timestamp")])
        ts = src.get("@timestamp")
        if isinstance(ts, str) and ts[:4].isdigit():
            years.append(int(ts[:4]))
        example = example or {k: v for k, v in src.items() if k != "message"}
    n = len(samples) or 1
    return {"valid": True, "parse_rate": ok / n, "avg_fields": nfields / ok if ok else 0,
            "failed_lines": failed[:5], "example": example, "years": sorted(set(years))}


def register_template(name: str, source: str, grok_pattern: str, event_type: str,
                      ts_pattern: Optional[str] = None, timestamp_formats: Optional[list[str]] = None,
                      parse_rate: Optional[float] = None) -> dict:
    """Register a VALIDATED template: creates ES ingest pipeline `name` and records it in the schema registry."""
    pipeline = {"description": f"Schema Agent template for {source}",
                "processors": _processors(grok_pattern, ts_pattern, timestamp_formats)
                + [{"set": {"field": "event.dataset", "value": source}}],
                "_meta": {"created_by": "schema_agent", "event_type": event_type}}
    status, resp = es("PUT", f"/_ingest/pipeline/{name}", pipeline)
    if status != 200:
        return {"ok": False, "error": es_reason(resp)}
    entry = {"name": name, "source": source, "grok_pattern": grok_pattern, "ts_pattern": ts_pattern,
             "timestamp_formats": timestamp_formats, "event_type": event_type, "parse_rate": parse_rate,
             "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    es("PUT", f"/{REGISTRY_INDEX}/_doc/{name}", entry)
    return {"ok": True, "pipeline": name}


def reprocess_unparsed(source: str, template_name: str, target_index: Optional[str] = None) -> dict:
    """Re-index all unparsed events of `source` through pipeline `template_name` into `target_index`
    (default logs-<source>). Makes them searchable for the Hunt agent."""
    target = target_index or HUNT_INDEX or f"logs-{source}"
    body = {"source": {"index": UNPARSED_INDEX, "query": {"term": {UNPARSED_SOURCE_FIELD: source}}},
            "dest": {"index": target, "pipeline": template_name}}
    status, resp = es("POST", "/_reindex?wait_for_completion=true", body, timeout=600)
    if status != 200:
        return {"ok": False, "error": es_reason(resp)}
    return {"ok": not resp.get("failures"), "target_index": target, "created": resp.get("created", 0),
            "failures": len(resp.get("failures", []))}


def _agent1():
    """Import Agent 1 and point its ES client at this backend's (role) connection."""
    import sys as _sys
    root = Path(__file__).resolve().parent.parent / "agent1"
    if str(root) not in _sys.path:
        _sys.path.insert(0, str(root))
    import schema_agent as sa
    import run_source as rs
    sa.ES_URL = ES_URL
    sa.ES_SSL = SSL_CTX
    sa.ES_HEADERS = ({"Authorization": "Basic " + base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()}
                     if ES_USER else {})
    rs.CFG.update(raw_index=UNPARSED_INDEX, raw_field=RAW_LINE_FIELD, feed_field=UNPARSED_SOURCE_FIELD,
                  hunt_index=HUNT_INDEX or "logs-parsed", registry_index=REGISTRY_INDEX)
    return sa, rs


def list_feeds() -> list:
    """List the feeds (sources) waiting in raw staging, with record counts. A feed is where logs came in
    (folder, push endpoint, stream), not a parsed type."""
    _, rs = _agent1()
    return rs.list_feeds()


def process_source(feed_name: str, fresh: bool = False) -> dict:
    """Point at a source: Agent 1 inspects the raw records of `feed_name`, splits them into layouts, reuses a
    registered template or creates + validates + registers one per layout, then indexes every record of the feed
    into the parsed hunt index (record_id kept as document id). Returns per-layout outcomes and counts.
    fresh=True ignores registered templates (forces new ones)."""
    import contextlib
    import io
    sa, rs = _agent1()
    if not sa.check_es():
        return {"error": f"Elasticsearch not reachable at {ES_URL}"}
    buf, lines = io.StringIO(), []
    with contextlib.redirect_stdout(buf):          # stdio transport: nothing may print to stdout
        try:
            res = rs.process_feed(feed_name, fresh=fresh, log=lambda *a: lines.append(" ".join(map(str, a))))
        except Exception as e:                      # never crash the MCP server
            res = {"feed": feed_name, "error": f"{type(e).__name__}: {e}"}
    res["log_tail"] = (buf.getvalue().splitlines() + lines)[-400:]
    return res


# =========================================================================== Server
SHARED = [list_indices, get_field_mappings]
ROLES = {
    "hunt": SHARED + [search, aggregate, get_document, get_query_log],
    "schema": SHARED + [list_feeds, sample_unparsed, list_templates, simulate_pipeline, register_template,
                        reprocess_unparsed, process_source],
    "ingest": [list_feeds, process_source],
}
ROLES["all"] = SHARED + list(dict.fromkeys(t for r in ("hunt", "schema") for t in ROLES[r] if t not in SHARED))


def build(role):
    mcp = FastMCP(f"sentinelhunt-{role}", log_level="WARNING")
    for fn in ROLES[role]:
        mcp.tool()(fn)
    return mcp


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=list(ROLES), default="hunt")
    ap.add_argument("--http", action="store_true", help="serve streamable HTTP instead of stdio")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    configure(a.role)
    server = build(a.role)
    if a.http:
        server.settings.host, server.settings.port = "0.0.0.0", a.port
        server.run(transport="streamable-http")
    else:
        server.run()
