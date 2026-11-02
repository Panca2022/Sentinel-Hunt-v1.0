#!/usr/bin/env python3
"""
End-to-end check of the MCP server against the dev Elasticsearch, using real Loghub OpenSSH logs
(which contain real SSH brute-force traffic).

  Step 0  (simulates teammate's ingestion) raw OpenSSH lines -> index logs-unparsed (event.dataset=openssh)
  Step 1  SCHEMA role: tool list, sample_unparsed, register Agent 1's openssh template, reprocess_unparsed
  Step 2  HUNT role:   tool list (must NOT contain write tools), list_indices, get_field_mappings,
                       search failures, top source IPs, a hallucinated field (must be rejected), query log

Usage (from ~/se6014):  .venv/bin/python mcp_server/demo_flow.py
"""
import asyncio
import json
import os
import sys
import urllib.request
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
SERVER = Path(__file__).resolve().parent / "server.py"
ES_URL = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")
RAW = ROOT / "samples" / "OpenSSH_2k.log"
REGISTRY = ROOT / "agent1" / "registry.json"
WRITE_TOOLS = {"register_template", "reprocess_unparsed", "simulate_pipeline", "sample_unparsed"}


def es(method, path, body=None, ndjson=None):
    data = ndjson.encode() if ndjson else (json.dumps(body).encode() if body is not None else None)
    ctype = "application/x-ndjson" if ndjson else "application/json"
    req = urllib.request.Request(ES_URL + path, data=data, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def load_unparsed():
    es("DELETE", "/logs-unparsed")
    es("DELETE", "/logs-openssh")
    lines = [l.rstrip("\n") for l in open(RAW, encoding="utf-8", errors="replace") if l.strip()]
    nd = "".join(json.dumps({"index": {"_index": "logs-unparsed"}}) + "\n" +
                 json.dumps({"message": l, "event": {"dataset": "openssh"}}) + "\n" for l in lines)
    r = es("POST", "/_bulk?refresh=true", ndjson=nd)
    print(f"step 0: loaded {len(lines)} raw OpenSSH lines into logs-unparsed (errors: {r.get('errors')})")


def payload(res):
    if getattr(res, "structuredContent", None):
        sc = res.structuredContent
        return sc["result"] if set(sc) == {"result"} else sc
    texts = [c.text for c in res.content if getattr(c, "text", None)]
    try:
        return json.loads(texts[0]) if len(texts) == 1 else [json.loads(t) for t in texts]
    except Exception:
        return texts


async def session(role):
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER), "--role", role], env=dict(os.environ))
    return stdio_client(params)


async def schema_step():
    async with await session("schema") as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            print(f"\nstep 1: SCHEMA role tools: {tools}")
            smp = payload(await s.call_tool("sample_unparsed", {"source": "openssh", "n": 3}))
            print(f"  sample_unparsed: {smp['total_unparsed']} unparsed; first: {smp['lines'][0][:90]}")
            reg = json.loads(REGISTRY.read_text())
            t = next(x for x in reg if x["source"] == "openssh")
            r1 = payload(await s.call_tool("register_template", {
                "name": t["name"], "source": "openssh", "grok_pattern": t["grok_pattern"],
                "event_type": t.get("event_type", "authentication"), "ts_pattern": t.get("ts_pattern"),
                "timestamp_formats": t.get("timestamp_formats"), "parse_rate": t.get("parse_rate")}))
            print(f"  register_template (Agent 1's openssh pattern): {r1}")
            r2 = payload(await s.call_tool("reprocess_unparsed", {"source": "openssh", "template_name": t["name"]}))
            print(f"  reprocess_unparsed: {r2}")


async def hunt_step():
    async with await session("hunt") as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            leaked = WRITE_TOOLS & set(tools)
            print(f"\nstep 2: HUNT role tools: {tools}")
            print(f"  allowlist check: {'✓ no write/schema tools exposed' if not leaked else '✗ LEAKED ' + str(leaked)}")
            print(f"  list_indices: {payload(await s.call_tool('list_indices', {}))}")
            fm = payload(await s.call_tool("get_field_mappings", {"index": "logs-openssh"}))["fields"]
            print(f"  fields in logs-openssh: {sorted(k for k in fm if not k.endswith('.keyword'))}")
            hid = "demo-openssh"
            ip_field = next((k for k in fm if k.endswith("ip") and not k.endswith(".keyword")), None)
            q = 'log_message:"Failed password" OR message:"Failed password"'
            q = q if "log_message" in fm else 'message:"Failed password"'
            res = payload(await s.call_tool("search", {"hunt_id": hid, "index": "logs-openssh", "query": q, "size": 2}))
            print(f"  search failed passwords: total={res.get('total')} query_id={res.get('query_id')} "
                  f"first_doc={res.get('hits', [{}])[0].get('_id') if res.get('hits') else None}")
            if ip_field:
                agg = payload(await s.call_tool("aggregate", {"hunt_id": hid, "index": "logs-openssh", "agg_type": "terms",
                                                              "field": ip_field, "query": q, "size": 5}))
                print(f"  top {ip_field} among failures: {agg.get('buckets')} query_id={agg.get('query_id')}")
            bad = payload(await s.call_tool("search", {"hunt_id": hid, "index": "logs-openssh",
                                                       "query": "attacker.country:RU"}))
            print(f"  hallucinated field test: {'✓ rejected: ' + bad['error'] if 'error' in bad else '✗ NOT rejected'}")
            log = payload(await s.call_tool("get_query_log", {"hunt_id": hid}))
            print(f"  query ledger: {[ (e['query_id'], e['tool'], e['status']) for e in log]}")


async def main():
    load_unparsed()
    await schema_step()
    await hunt_step()


if __name__ == "__main__":
    asyncio.run(main())
