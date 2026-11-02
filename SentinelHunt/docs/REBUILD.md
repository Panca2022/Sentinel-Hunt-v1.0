# Rebuild the frozen version

This rebuilds the exact version of the recorded, verified demo run (25 Oct 2026, hunt `hunt-20261025-200312-688`).
`docs/VERSION_MANIFEST.json` is that run's freeze. Every step below ends with a check against it.

## 0. What has to match the manifest

| Item | Frozen value | How it is checked |
|---|---|---|
| Our code | sha256 of the 26 files in `code.project` | `scripts/verify_manifest.py --code-only` |
| ELK kit | sha256 of the 7 kit files in `code.kit` (compose.yaml, Logstash pipeline, mappings, manage.py, ship.py) | same script |
| Elastic stack | Elasticsearch / Logstash / Kibana **8.19.23** (images pinned by the kit's compose.yaml) | `verify_manifest.py` |
| Model | `qwen3:14b`, digest `bdbd181c33f2…`, 14.8B, Q4_K_M, via **Ollama 0.40.6** | `verify_manifest.py` |
| Model settings | Agent 2: temperature 0, seed 42, num_ctx 8192, thinking off. Agent 1: seed 42, temperature 0 for the first candidate and 0.7 for the others, parse threshold 0.95 | in the code (hashed) |
| Python | 3.12.3, `mcp==1.30.0`, `streamlit==1.40.2`, `anyio==4.15.1`, `pydantic==2.14.1` | `requirements.txt` |
| Platform used | Windows + WSL2 Ubuntu (kernel 6.18 WSL2, glibc 2.39), Docker inside WSL | recorded only |
| Templates | 3 v3 templates + `logs-bastion-02-auth-layout1`, pipeline sha256 each | `templates/` + `verify_manifest.py` |
| v3 data | 545 records in the hunt index, content sha256 `6fd3ef8ebcae…` | `verify_manifest.py` |

The scripts added for packaging after the freeze (`export_templates.py`, `restore_templates.py`, `verify_manifest.py`)
and `finish_run.sh` are not in the manifest. They do not run as part of the agents.

## 1. Prerequisites (once)

```bash
# WSL2 Ubuntu with Docker running; Elasticsearch needs this after every reboot:
sudo sysctl -w vm.max_map_count=1048576
# Ollama 0.40.6, then the model:
ollama pull qwen3:14b
ollama list            # ID must start with bdbd181c33f2
```

## 2. ELK kit

Unpack the team's `SentinelHunt_ELK_Portable` (not in this repo; the manifest pins its files), then:

```bash
cd ~/se6014-portable/SentinelHunt_ELK_Portable
python3 scripts/manage.py check
python3 scripts/manage.py start        # ends with PASS lines; credentials are created under runtime/ (never commit)
```

Ports (localhost only): Elasticsearch https://localhost:19200, Kibana http://localhost:15601, push http://127.0.0.1:18088,
stream 127.0.0.1:15514, pull = the `runtime/inbox` folder.

## 3. This repository

```bash
git clone <repo url> ~/se6014 && cd ~/se6014
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
export SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable
python3 scripts/verify_manifest.py --code-only        # expect: project 26 files and kit 7 files match
```

## 4. The v3 dataset and its templates (exact)

```bash
# stage the team's dataset into raw staging (545 records)
cd $SENTINELHUNT_KIT && python3 scripts/manage.py stage /path/to/sentinelhunt-multisource-v3.zip && cd ~/se6014
# restore the frozen v3 templates (dry run first, then --yes)
.venv/bin/python scripts/restore_templates.py templates/ --only v3-mixed-pilot
.venv/bin/python scripts/restore_templates.py templates/ --only v3-mixed-pilot --yes
# Agent 1 over MCP: reuses the restored templates (no model call) and parses the 545 records
.venv/bin/python mcp_server/ingest_client.py --feed v3-mixed-pilot
python3 scripts/verify_manifest.py
```

Expected: every line PASS, including `v3 data fingerprint (545 records, content sha256) … 6fd3ef8ebcae…`. The demo
template shows `INFO … not built yet`.

Without the restore step, Agent 1 builds the v3 templates with the model again. The records are then parsed, but the
pipelines can differ in detail, and so can the fingerprint. The restore is what makes the rebuild exact.

## 5. The demo run (as recorded)

```bash
.venv/bin/streamlit run demo/app.py           # http://localhost:8501
```

In the app, set feed `bastion-02-auth` and source `bastion-02` before every Send:

| # | Page | Action | Expected |
|---|---|---|---|
| 1 | 1 Ingest | `demo/sample_logs/log_pull.log`, **Pull** | 23 raw records |
| 2 | 2 Agent 1 | Process, **"Build a new template" ticked** | generated |
| 3 | 1 Ingest | `log_stream.log`, **Stream** | 33 |
| 4 | 2 Agent 1 | Process | extended (new message types) |
| 5 | 1 Ingest | `log_push.log`, **Push** | 36 |
| 6 | 2 Agent 1 | Process | reused, no model call |
| 7 | 3 Agent 2 | `Someone brute-forced SSH on bastion-02 on 24 Oct 2026 between 09:15 and 09:25` | DETECTION CRITERIA MATCHED |

Then check it:

```bash
RESULTS_ROOT=~/results bash scripts/finish_run.sh MY_RUN
```

Expected: `25/25 checks passed`. The script freezes and saves the evidence only when every check passes.

Step 2 asks the model to build the demo template, so the pipeline text can differ from the frozen one. That is
expected. The check that matters is `verify_demo_run.py`, which compares every output value with an answer key built
from the sample files. To replay with the exact frozen demo template, skip step 2's tick and restore it first:
`.venv/bin/python scripts/restore_templates.py templates/ --only bastion-02-auth --yes`. Agent 1 then reuses it for
all three batches.

To start over: `.venv/bin/python scripts/remove_feed.py bastion-02-auth --yes` (removes only the demo feed; it refuses
to touch v3).

## 6. Year and timezone of syslog timestamps (short version)

The demo logs use classic syslog timestamps such as `Oct 24 09:15:45`, which carry **no year and no timezone**.
Agent 1 detects the format `MMM d HH:mm:ss` and registers an Elasticsearch `date` processor with that format and no
timezone. Elasticsearch then assigns:

- **the year in which the record is processed** (2026 in the recorded run), and
- **UTC**, the date processor's default timezone.

So `Oct 24 09:15:45` becomes `2026-10-24T09:15:45.000Z`, and the hunt window "09:15 to 09:25" is in UTC. Limits:

- logs written in another timezone would be shifted by their UTC offset
- December logs processed in January would get the wrong year
- syslog has whole seconds only

A real deployment should set the source's timezone per feed. The v3 dataset is not affected: its timestamps are
ISO 8601 with year and offset. Details are in `docs/SYSLOG_TIMESTAMPS.md`.
