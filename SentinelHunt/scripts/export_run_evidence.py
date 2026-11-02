#!/usr/bin/env python3
"""
Export the ingest + Agent 1 evidence of one feed into a folder (read-only).
  ingest_by_channel.json  raw staging records per ingestion_channel (pull/stream/push, set by Logstash itself),
                          first/last received_at, record ids, plus the inbox/upload files with sha256
  agent1_template.json    registry entry(s) + ingest pipeline(s) + feed router built for the feed
  agent1_runs/            Agent 1 run files (agent1/runs/*.json) written since --since
  parsed_summary.json     hunt-index records of the feed per event.action / outcome, first/last @timestamp
Uses the kit's admin account via manage.py, GET/search only. No passwords are written.

Usage (WSL, from ~/se6014):
  .venv/bin/python scripts/export_run_evidence.py bastion-02-auth OUT_DIR [--since 2026-10-25T10:50:00]
"""
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
sys.path.insert(0, str(KIT / "scripts"))
from manage import es  # noqa: E402


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        sys.exit(__doc__)
    feed, out = args[0], Path(args[1])
    since = None
    if "--since" in sys.argv:
        since = datetime.fromisoformat(sys.argv[sys.argv.index("--since") + 1]).replace(tzinfo=timezone.utc)
    out.mkdir(parents=True, exist_ok=True)
    slug = feed.lower()

    # ---- ingest, as Logstash recorded it
    r = es("POST", "/sentinelhunt-raw-v1/_search", {"size": 10000, "query": {"term": {"feed_name": feed}},
                                                     "sort": [{"received_at": "asc"}],
                                                     "_source": ["record_id", "ingestion_channel", "received_at",
                                                                 "source_name", "raw_line"]})
    ch = {}
    for h in r["hits"]["hits"]:
        s = h["_source"]
        c = ch.setdefault(s.get("ingestion_channel"), {"records": 0, "first_received_at": s.get("received_at"),
                                                        "record_ids": [], "first_line": s.get("raw_line")})
        c["records"] += 1
        c["last_received_at"] = s.get("received_at")
        c["record_ids"].append(s.get("record_id"))
    files = {}
    for sub in ("inbox", "demo_uploads"):
        for p in sorted((KIT / "runtime" / sub).glob("*")):
            if p.is_file() and (sub == "demo_uploads" and p.name.startswith(slug) or sub == "inbox"
                                and feed in p.read_text(errors="replace")[:2000]):
                files[f"runtime/{sub}/{p.name}"] = {"sha256": sha(p), "lines": sum(1 for _ in p.open()),
                                                     "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat()}
    (out / "ingest_by_channel.json").write_text(json.dumps(
        {"feed": feed, "total_raw_records": r["hits"]["total"]["value"], "by_channel": ch, "files": files,
         "note": "ingestion_channel and received_at are set by the kit's Logstash pipeline (raw.conf), not by our code"},
        indent=2))

    # ---- Agent 1 template
    pipes = es("GET", "/_ingest/pipeline")
    mine = {k: v for k, v in pipes.items() if k == f"feed-{slug}" or k.startswith(f"logs-{slug}-layout")}
    reg = es("POST", "/sentinelhunt-schema-v1/_search", {"size": 100})
    entries = {h["_id"]: h["_source"] for h in reg["hits"]["hits"] if h["_id"].startswith(f"logs-{slug}-layout")}
    (out / "agent1_template.json").write_text(json.dumps({"registry": entries, "pipelines": mine}, indent=2))

    copied = []
    runs = ROOT / "agent1" / "runs"
    if runs.exists():
        (out / "agent1_runs").mkdir(exist_ok=True)
        for p in sorted(runs.glob("*.json")):
            t = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
            if since is None or t >= since:
                shutil.copy2(p, out / "agent1_runs" / p.name)
                copied.append(p.name)

    # ---- parsed result
    a = es("POST", "/sentinelhunt-hunt-v1/_search", {"size": 0, "query": {"term": {"feed_name": feed}}, "aggs": {
        "action": {"terms": {"field": "event.action", "size": 50}},
        "outcome": {"terms": {"field": "event.outcome", "size": 10}},
        "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}})
    ag = a["aggregations"]
    (out / "parsed_summary.json").write_text(json.dumps(
        {"feed": feed, "records": a["hits"]["total"]["value"],
         "event.action": {b["key"]: b["doc_count"] for b in ag["action"]["buckets"]},
         "event.outcome": {b["key"]: b["doc_count"] for b in ag["outcome"]["buckets"]},
         "first_event": ag["first"].get("value_as_string"), "last_event": ag["last"].get("value_as_string")}, indent=2))

    print(f"raw records {r['hits']['total']['value']}: " + ", ".join(f"{k} {v['records']}" for k, v in ch.items()))
    print(f"files: {list(files)}")
    print(f"templates: {list(entries)} | pipelines: {list(mine)} | agent1 runs copied: {copied}")
    print(f"parsed: {a['hits']['total']['value']} records -> {out}")


if __name__ == "__main__":
    main()
