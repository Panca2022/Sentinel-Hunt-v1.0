# SentinelHunt agents: agentic threat hunting on ELK

SE6014 group project. Two local-LLM agents work on top of the team's ELK kit (SentinelHunt_ELK_Portable):

- **Agent 1 (schema agent)** reads raw log lines it has never seen. It builds an Elasticsearch ingest pipeline for them, validates it, registers it, and parses every record into the hunt index. When the same format comes back it reuses the pipeline; when the format brings new message types it extends it.
- **Agent 2 (hunt agent)** takes a threat hypothesis in plain English (e.g. "Someone brute-forced SSH on bastion-02 on 24 Oct 2026 between 09:15 and 09:25"). It picks a playbook, queries the hunt index read-only, decides the verdict by a code rule, and writes a report in which every claim is checked against the query results.

The design rule throughout: **the LLM proposes, code verifies, repairs and decides.** The model (qwen3:14b, run locally by Ollama) never sees Elasticsearch credentials. All Elasticsearch access goes through an MCP server, with a separate least-privilege account per agent.

```
log source ──pull / push / stream──▶ Logstash (kit) ──▶ raw staging index
                                                         │
             MCP server (ingest role, agent1 account) ◀──┤ Agent 1: layout → pattern → message types → fields → event rules
                                                         ▼            (LLM proposes, code validates on held-out lines)
                                              ingest pipeline + router + registry
                                                         ▼
                                                  hunt index (ECS-style fields)
                                                         ▲
             MCP server (hunt role, read-only agent2 account) ◀── Agent 2: playbook → queries → verdict rule (code)
                                                                   → claims checked by code → report + query ledger
```

## Repository

| Path | What |
|---|---|
| `agent1/` | Schema agent: `schema_agent.py` (line pattern, timestamp, validation, repairs, registry), `stages_v4.py` (message types, field mapping, event rules, extend), `run_source.py` (one feed end to end), `vocabulary.json` (allowed event.action / outcome / category) |
| `agent2/hunt_agent.py` | Hunt agent: 4 playbooks (SSH brute force, web probing, port probing, destructive sudo), planner, host scope, verdict rule, follow-up queries with guards, claim checker incl. times, report |
| `mcp_server/server.py` | MCP server with three roles: **ingest** (`list_feeds`, `process_source`), **schema** (adds `sample_unparsed`, `list_templates`, `simulate_pipeline`, `register_template`, `reprocess_unparsed`) and **hunt**, read-only (`list_indices`, `get_field_mappings`, `search`, `aggregate`, `get_document`, `get_query_log`); every query is written to a ledger per hunt |
| `demo/app.py` | Streamlit demo app: 1 ingest, 2 Agent 1, 3 Agent 2, 4 run twice. `demo/sample_logs/` holds the 3 demo log files |
| `experiments/` | Repeatability experiment (run twice, baseline vs converged settings), time-claim replay and comparison pages |
| `scripts/` | Run checks and kit maintenance: `verify_demo_run.py`, `finish_run.sh`, `freeze_versions.py`, `verify_manifest.py`, `export_templates.py` / `restore_templates.py`, `export_run_evidence.py`, `remove_feed.py`, `retire_templates.py` |
| `templates/` | Agent 1's registered templates as frozen (v3 dataset + demo source), restorable exactly |
| `docs/REBUILD.md` | **How to rebuild the frozen version step by step** |
| `docs/VERSION_MANIFEST.json` | The freeze of the recorded, verified run: file hashes, model digest, Elasticsearch version, template hashes, data fingerprint |
| `docs/SYSLOG_TIMESTAMPS.md` | How year and timezone are assigned to syslog timestamps (and the limits) |
| `docs/DEVELOPMENT_LOG.md` | Every finding and fix, in order |

## Recorded run (verified)

Recorded demo, 25 Oct 2026, hunt `hunt-20261025-200312-688`. 25/25 strict checks passed (`scripts/verify_demo_run.py`: every field value of all 36 records against an answer key built from the sample files, every number in the hunt).

- Ingest: pull 23, stream 10, push 3 lines, as Logstash recorded them.
- Agent 1: **generated** a template for the unseen syslog format (44.5 s; the model's line pattern was repaired by code), **extended** it when the stream batch brought a new message type (55.2 s), and **reused** it for the push batch (2.1 s, no model call).
- Agent 2: DETECTION CRITERIA MATCHED. 203.0.113.45 made 14 failed password attempts against `deploy` between 09:15:48 and 09:22:39, followed by 1 successful login at 09:22:44. The checker rewrote one claim, rejected two AI follow-up queries (one incomplete, one with an invented value) and skipped one repeated query.

Evidence for the run is in the team's results package (`SE6014_checklist_results/VERIFIED_RUN`), not in this repo.

## Quick start

See `docs/REBUILD.md`. In short: start the kit, `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`, `export SENTINELHUNT_KIT=…`, `python3 scripts/verify_manifest.py --code-only`, then `.venv/bin/streamlit run demo/app.py`.

## Not in this repo

- The ELK kit itself (`SentinelHunt_ELK_Portable`, the team's setup kit). The manifest pins its file hashes.
- The v3 test dataset (`sentinelhunt-multisource-v3.zip`, team dataset), staged into the kit with `manage.py stage`.
- Credentials. The kit generates them under its `runtime/` folder. Never commit that folder or any `*.env` file.
- Run outputs (`reports/`, `mcp_server/ledger/`, `agent1/runs/`, `agent1/registry.json`, `experiments/results/`).
