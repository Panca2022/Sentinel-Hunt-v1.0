# Validation record

Prepared for Ubuntu 24.04 / WSL2, with Elasticsearch/Logstash/Kibana 8.19.23.

Completed locally:
- All Python sources compile.
- Compose and Logstash settings parse as JSON-formatted YAML.
- Twelve automated checks passed: credential preservation, duplicate-line identities,
  label-field exclusion, raw-only ZIP import, corrupt-input rejection, pinned images
  and loopback ports, role boundaries, and stable endpoint identities.
- The distribution ZIP is checked for integrity, checksums, and excluded runtime credentials.

Re-run local checks with: python3 -m unittest discover -s tests -v

Docker is unavailable in the author's Codex workspace. Container startup, Compose
validation, and Logstash plugin/runtime validation have NOT been executed here.
The design reuses the earlier Ubuntu lab, but this distribution requires its own acceptance run.

Target Ubuntu acceptance sequence:
1. python3 scripts/manage.py check
2. python3 scripts/manage.py start
3. python3 scripts/manage.py smoke

Start checks in-image Logstash configuration, Elasticsearch TLS/authentication,
Kibana readiness and actual backend-account privileges.
Smoke verifies indexed records for folder pickup, HTTP push, and continuous TCP stream.
Preserve the project logs and state if a check fails; diagnose the failure first.

Still outstanding: MCP source registration, Agent 1 integration and schema-creation tests,
Agent 2 integration using the parsed hunt index, and two complete frozen-data hunt runs.
Passing ingestion checks does not establish a complete Q1 implementation.

Feed update checks additionally cover explicit feed preservation, invalid-feed rejection, and feed-aware endpoint identity. Docker pipeline execution remains pending.

Teammate handoff regression check: Kibana token requests omit the body and ingest-pipeline management is assigned to Agent 1 only. Twelve local checks pass; live target acceptance remains separate.
