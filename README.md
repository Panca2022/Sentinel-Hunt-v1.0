<div align="center">

# 🛡️ SentinelHunt

### Agentic Threat Hunting on ELK, where the LLM proposes and code verifies

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Elastic Stack](https://img.shields.io/badge/Elastic_Stack-8.19.23-005571?logo=elastic&logoColor=white)
![Model](https://img.shields.io/badge/LLM-qwen3:14b_(local)-black)
![MCP](https://img.shields.io/badge/Protocol-MCP-6E56CF)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)

</div>

---

## Overview

**SentinelHunt** is a local, privacy-preserving, multi-agent threat-hunting system built on the Elastic Stack. Two LLM agents, running entirely on-premises through Ollama, automate two of the most time-consuming SOC tasks: **onboarding unfamiliar log formats** and **testing threat hypotheses against the data**.

The central design rule is simple:

> **The LLM proposes. Code verifies, repairs and decides.**

The model never holds Elasticsearch credentials, never decides a verdict, and never has an unchecked claim reach a report.

## Key Features

| Capability | Description |
|---|---|
| **Self-building parsers** | Agent 1 reads raw log lines it has never seen, builds an Elasticsearch ingest pipeline, validates it on held-out lines, registers it, and parses every record into the hunt index. |
| **Template reuse & extension** | Known formats are reused with no model call; formats that bring new message types extend the existing template. |
| **Plain-English hunting** | Agent 2 takes a hypothesis such as *"Someone brute-forced SSH on bastion-02 between 09:15 and 09:25"* and selects a playbook automatically. |
| **Code-decided verdicts** | Rule thresholds, not the model, return `DETECTION CRITERIA MATCHED`, `NOT FOUND` or `INCONCLUSIVE`. |
| **Verified reporting** | Every claim is checked against query results. Unknown IDs, wrong counts and invented entities are removed. |
| **Full auditability** | Every query is written to a per-hunt ledger with the exact Elasticsearch request, hit count and result hash. |
| **Least privilege** | A dedicated MCP server exposes separate ingest, schema and read-only hunt roles. |

## Architecture

```
log source ──pull / push / stream──▶ Logstash ──▶ raw staging index
                                                       │
         MCP server (schema role, agent1 account) ◀───┤  Agent 1: layout → pattern → message types
                                                       ▼            → fields → event rules
                                            ingest pipeline + router + registry
                                                       ▼
                                            hunt index (ECS-style fields)
                                                       ▲
         MCP server (hunt role, read-only agent2) ◀────┘  Agent 2: playbook → queries → verdict (code)
                                                                   → claim check → report + ledger
```

## Repository Structure

```
.
├── SentinelHunt/                 # Agents, MCP server, demo UI, tooling
│   ├── agent1/                   # Schema agent (pattern, timestamp, repair, registry)
│   ├── agent2/                   # Hunt agent (playbooks, verdict rule, claim checker)
│   ├── mcp_server/               # Role-based MCP gateway to Elasticsearch
│   ├── demo/                     # Streamlit app + sample logs
│   ├── experiments/              # Repeatability and comparison experiments
│   ├── scripts/                  # Verification, freeze, export/restore utilities
│   ├── templates/                # Frozen, restorable Agent 1 templates
│   └── docs/                     # REBUILD, HANDOVER, DEVELOPMENT_LOG, manifest
├── SentinelHunt_ELK_Portable/    # Isolated ELK lab (Docker Compose) for ingestion
├── PACKAGE_SHA256.json           # Package file hashes
├── START_HERE.md
└── README.md
```

## Components

### Agent 1: Schema Agent
Generates three Grok candidates, simulates them against 100 unseen lines, auto-repairs common failures, detects timestamp layouts in code, and registers the pipeline only if it passes the quality gates (≥ 95 % parse rate, ≥ 3 fields, no catch-all pattern). Failures after three attempts are flagged `needs_human`, and nothing is registered.

### Agent 2: Hunt Agent
Ships four playbooks mapped to MITRE ATT&CK:

| Playbook | Technique |
|---|---|
| `ssh_bruteforce` | T1110 |
| `web_probing` | T1595.003 |
| `port_probing` | T1046 |
| `destructive_sudo` | T1548.003 / T1485 (negative control) |

### MCP Server
| Role | Tools | Write access |
|---|---|---|
| `schema` | list/inspect indices, sample, simulate, register, reprocess | Pipelines and reindex only |
| `hunt` | list, mappings, search, aggregate, get document, query log | **None (read-only)** |

Safeguards include field validation against real mappings, a result cap of 50 per call, and a per-hunt query ledger.

### ELK Portable Kit
Elasticsearch, Logstash and Kibana **8.19.23** in an isolated Compose project, with pull (watched folder), push (authenticated HTTP) and stream (TCP) adapters. All ports bind to `127.0.0.1`.

## Quick Start

**Prerequisites:** Windows + WSL2 Ubuntu 24.04 (or Ubuntu), Docker Engine, Docker Compose v2, Python 3.12, [Ollama](https://ollama.com), roughly 5 GiB free RAM plus the model.

```bash
# 1. Model
ollama pull qwen3:14b

# 2. ELK kit
cd SentinelHunt_ELK_Portable
sudo sysctl -w vm.max_map_count=1048576
python3 scripts/manage.py init
python3 scripts/manage.py check
python3 scripts/manage.py start

# 3. Agents and demo
cd ../SentinelHunt
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export SENTINELHUNT_KIT=$(realpath ../SentinelHunt_ELK_Portable)
python3 scripts/verify_manifest.py --code-only
.venv/bin/streamlit run demo/app.py
```

Open **http://localhost:8501**. Full step-by-step instructions are in [`SentinelHunt/docs/REBUILD.md`](SentinelHunt/docs/REBUILD.md).

### Run a hunt from the CLI

```bash
.venv/bin/python agent2/hunt_agent.py --list
.venv/bin/python agent2/hunt_agent.py "A compromised workstation is brute-forcing SSH on host_001"
```

## Recorded Verification Run

| Item | Result |
|---|---|
| Strict checks | **25 / 25 passed** (all field values of 36 records, every number in the hunt) |
| Agent 1 | Generated a template for an unseen syslog format, extended it for a new message type, reused it with no model call |
| Agent 2 | `DETECTION CRITERIA MATCHED`: 14 failed SSH attempts, then 1 successful login |
| Claim checker | Rewrote 1 claim, rejected 2 AI follow-up queries, skipped 1 repeated query |

## Security & Data Handling

- **No credentials in this repository.** The kit generates them locally under `runtime/`.
- Never commit `runtime/`, `*.env`, `*.crt` or `*.key` (already covered by `.gitignore`).
- The v3 545-record dataset and run outputs are intentionally **not included**.
- Push and stream endpoints are local lab transports and must not be exposed to a LAN.
- Do not publish `docker compose config` output, because it can expose secrets.

## Limitations

- Results depend on a 14B local model, so run-to-run variance exists. Code-side verification is the safeguard.
- Four playbooks are supported. Unsupported hypotheses are reported as `unsupported`.
- Syslog year and timezone assignment has documented limits (`docs/SYSLOG_TIMESTAMPS.md`).
- Built and verified on WSL2 Ubuntu, and other platforms are untested.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/REBUILD.md`](SentinelHunt/docs/REBUILD.md) | Rebuild the frozen version step by step |
| [`docs/HANDOVER.md`](SentinelHunt/docs/HANDOVER.md) | Handover notes |
| [`docs/DEVELOPMENT_LOG.md`](SentinelHunt/docs/DEVELOPMENT_LOG.md) | Every finding and fix, in order |
| [`docs/VERSION_MANIFEST.json`](SentinelHunt/docs/VERSION_MANIFEST.json) | Hashes, model digest and versions |

## Contributing

Issues and pull requests are welcome. Please do not include credentials, private logs or personal data in any contribution.
