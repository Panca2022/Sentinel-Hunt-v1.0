#!/usr/bin/env python3
"""
"Point at a source" over MCP: spawns the MCP server with the ingest role and calls its tools.

  .venv/bin/python mcp_server/ingest_client.py                 -> list feeds waiting in raw staging
  .venv/bin/python mcp_server/ingest_client.py --feed NAME     -> Agent 1 processes that feed into the hunt index
Kit mode: export SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable first.
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = Path(__file__).resolve().parent / "server.py"


def payload(res):
    if getattr(res, "structuredContent", None):
        sc = res.structuredContent
        return sc["result"] if set(sc) == {"result"} else sc
    texts = [c.text for c in res.content if getattr(c, "text", None)]
    try:
        return json.loads(texts[0]) if len(texts) == 1 else [json.loads(t) for t in texts]
    except Exception:
        return texts


async def main(feed, fresh):
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER), "--role", "ingest"], env=dict(os.environ))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            print(f"MCP ingest role tools: {tools}")
            feeds = payload(await s.call_tool("list_feeds", {}))
            print("feeds in raw staging:", json.dumps(feeds))
            if not feed:
                return
            print(f"\nprocess_source({feed!r}) ... (Agent 1 runs inside the MCP backend; may take a few minutes)")
            res = payload(await s.call_tool("process_source", {"feed_name": feed, "fresh": fresh}))
            for line in res.pop("log_tail", []):
                print("  |", line)
            print(json.dumps(res, indent=2, default=str))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed")
    ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()
    asyncio.run(main(a.feed, a.fresh))
