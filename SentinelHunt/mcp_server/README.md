# MCP server (ours): the agents' only door into Elasticsearch

```
Agent 1 (Schema) ──stdio/HTTP──► server.py --role schema ─┐
Agent 2 (Hunt)   ──stdio/HTTP──► server.py --role hunt   ─┴──► Elasticsearch (teammate's ELK)
```

| Role | Tools | Can write? |
|---|---|---|
| `schema` (Agent 1) | list_indices, get_field_mappings, sample_unparsed, list_templates, simulate_pipeline, register_template, reprocess_unparsed | Yes: pipelines + reindex only |
| `hunt` (Agent 2) | list_indices, get_field_mappings, search, aggregate, get_document, get_query_log | **No (read-only)** |

## Guardrails (report material: hallucination prevention)
- **Allowlist enforced by the server:** the hunt process does not even contain write tools.
- **Field validation:** a query naming a field that is not in the index is rejected with the real field list.
- **Query ledger:** every hunt call gets `<hunt_id>-qNNN`, logged to `ledger/<hunt_id>.jsonl` with the exact ES request, hit count and result hash. Reports cite these IDs.
- **Caps:** ≤ 50 hits / buckets per call, long messages truncated (protects the 8k context).

## Setup (once, in Ubuntu)
```bash
sudo apt-get install -y python3-venv
cd ~/se6014 && python3 -m venv .venv && .venv/bin/pip install -r mcp_server/requirements.txt
```

## End-to-end check (dev ES must be running)
```bash
cd ~/se6014 && .venv/bin/python mcp_server/demo_flow.py
```
Raw OpenSSH lines → `logs-unparsed` → Agent 1's template registered **through MCP** → `reprocess_unparsed` → `logs-openssh` → hunt tools search/aggregate the brute force.

## Connect to the teammate's ELK later
`ES_URL=https://<host>:9200 ES_USER=... ES_PASS=... ES_VERIFY_TLS=false` (self-signed certs). For containers: `server.py --role hunt --http --port 8765`.
