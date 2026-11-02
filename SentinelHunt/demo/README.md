# Demo app (Streamlit)

One page per demo scene, on the teammate's ELK kit. Every Elasticsearch access goes through the MCP server
(agent1 account for ingest/schema, read-only agent2 account for hunting); the app holds no ES credentials.

## Start (WSL, from ~/se6014)

    .venv/bin/pip install -r demo/requirements.txt          # once
    export SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable
    .venv/bin/streamlit run demo/app.py

Open http://localhost:8501 in Windows. The sidebar shows Elasticsearch / Kibana / Ollama / kit status (all green before recording).

## Pages = recording scenes

| Page | Scene | What to click |
|---|---|---|
| 1 · Ingest | logs come in | upload a log file, pick Pull / Push / Stream, feed name, **Send**; counter waits until the records are in raw staging; link to Kibana |
| 2 · Agent 1 | build a template (new format) / reuse it (same format again) | pick the feed, **Process source**; layouts + reused/built + indexed/failed; raw line next to its parsed record |
| 3 · Agent 2 | detect + negative case | pick an example or type a hypothesis, **Run hunt**; live steps, result cards, claims, every query, key evidence, report download |
| 4 · Run twice | A2 | pick a result folder, setting, case: full side-by-side (or start a new run) |

## Before recording
- Kit running (`python3 scripts/manage.py start` in the kit folder), Ollama warmed up with one quick hunt.
- Use a new feed name per scene (e.g. demo-auth-1, demo-auth-2) so counts start from zero.
- Scene "Agent 1 builds" needs a log format Agent 1 has not registered yet; scene "reuses" needs the same format again.
- Pages run the real agents; waits (Agent 1 build, hunts) are cut in editing.
