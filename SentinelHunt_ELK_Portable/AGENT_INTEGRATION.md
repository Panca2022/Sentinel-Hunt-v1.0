# Agent integration contract (proposed; confirm with teammate)

This kit supplies ingestion and indices, not an LLM or MCP implementation.
Do not replace the teammate's existing Elasticsearch or change its MCP URL automatically.

## Connections

- From WSL/Linux host: https://localhost:19200; CA: runtime/ca.crt.
- From a container explicitly joined to this project's network: https://elasticsearch:9200.
- runtime/agent1.env: ES_USERNAME and ES_PASSWORD for Agent 1's MCP backend.
- runtime/agent2.env: read-only hunt credentials for Agent 2's MCP backend.
- Host Kibana: http://localhost:15601, user elastic, locally generated password.

Agent credentials are for the MCP/tool backend, never model prompts.
Load env files in the backend without printing them. Use verified TLS; do not disable certificate verification.

## Flow and ownership

User selects source -> an agent/MCP source-registration operation starts or selects an ingestion adapter ->
Logstash raw staging -> Agent 1 inspects samples, selects or creates a schema, validates and registers it ->
Agent 1 indexes parsed events -> Agent 2 plans and queries via MCP -> evidence-linked report.

The source-selection/adapter-registration MCP workflow is NOT implemented by this kit.
The CLI adapters let the team build and test that integration independently.

### Raw staging: sentinelhunt-raw-v1

Documents have record_id (also Elasticsearch _id), capture_id (optional), raw_line,
source_name (optional), ingestion_channel, received_at, and @timestamp.
The timestamp here is RECEIPT time, not the original event time.
Folder/push envelopes preserve supplied record_id and capture_id. If no record_id is
supplied a UUID is generated. Streaming lines receive UUIDs and do not invent capture IDs.
Malformed envelopes/JSON are routed to sentinelhunt-rejected-v1 without copying the invalid payload.
Stable IDs allow intentional updates on replay; use fresh IDs for genuinely distinct repeated events.

### Parsed hunt: sentinelhunt-hunt-v1

Agent 1 must preserve record_id/capture_id and the exact raw_line, set event.original,
and extract the event timestamp into @timestamp. Suggested fields and types are in
config/hunt-mapping.json and the live index mapping. Nested JSON and dotted field paths
refer to the same Elasticsearch fields, e.g. source.ip and event.action.

Use the original record_id as parsed _id. Do not infer missing usernames/IPs or import labels.
Mappings are strict; unexpected new fields must be reviewed/mapped by an authorized maintainer
rather than silently getting incorrect dynamic types. Existing types cannot be changed in place.

### Schema registry: sentinelhunt-schema-v1

This is an Elasticsearch DOCUMENT index for versioned parser definitions, not an
Elasticsearch index-template API. Its document format is deliberately left to the teammate.
Agent 1 has read/write access here plus manage_ingest_pipelines for creating and simulating ingest pipelines. It has no index-template or mapping administration.
The teammate uses Elasticsearch ingest pipelines, not index templates. Pipeline-management permission is cluster-wide on this isolated lab cluster; the MCP backend should constrain pipeline names and allowed operations. If index-template APIs are needed later, agree an explicit tool and security policy first. Do not give the LLM the elastic superuser credential.

### Agent 2

Read/search/aggregate sentinelhunt-hunt-v1 only, via MCP. This kit tests its backend
account permissions; it does not implement or test the teammate's MCP server.

## Minimum acceptance test

1. Stage inputs.ndjson only from v3 (never parsing-reference or labels).
2. Agent 1 parses real raw lines; compare extracted fields against the reference afterward.
3. Exercise a known schema AND a previously unregistered format: create/validate/register/reuse.
4. Agent 2's MCP search/aggregate tools target the parsed hunt index, not the old reference-loaded test index.
5. Run an identical hypothesis twice on frozen data; retain reports, exact queries, record IDs,
   source/time coverage, validation failures, and explain any differences.
6. Count SSH failed-password attempts, not all related PAM/invalid-user records.
7. Report DETECTION CRITERIA MATCHED / NOT MATCHED / INCONCLUSIVE with evidence limits.

The smoke command tests three ingestion channels only. It does not establish completion of Q1.

## Feed identity (updated integration contract)

Every raw document has a `feed_name` keyword. Agent 1 must preserve it in parsed output.
Use a stable source/feed identity, such as `host-a-auth`, `nginx-access`, or `firewall-lab`.
It is not a threat label, predicted schema, or individual session identifier.
`capture_id` remains the session/window identity; `record_id` remains the event identity.
Feed names accept 1-128 letters, digits, dots, underscores, colons, or hyphens.

Folder/push envelopes can include `feed_name` explicitly. If absent, fallback names are
`folder-inbox`, `endpoint-push`, and `local-syslog` for plain TCP/syslog.
For distinct real feeds, supply explicit names rather than relying on these shared defaults.
The bundled stream forwarder sends an explicit versioned transport envelope, which Logstash
unwraps without changing the original log line. Plain syslog senders remain supported.
The raw envelope keys are record_id, capture_id, raw_line, source_name, feed_name.

Examples:

```bash
python3 scripts/manage.py stage /path/to/sentinelhunt-multisource-v3.zip --feed v3-mixed-pilot
python3 scripts/ship.py push /path/to/auth.log --source host-a --feed host-a-auth --follow
python3 scripts/ship.py stream /path/to/firewall.log --source firewall-lab --feed firewall-lab --follow
```

Staging the combined v3 ZIP as `v3-mixed-pilot` does not imply one parser fits every line:
that collection contains multiple original sources. A real feed should identify the actual
source/configured collection. Agent 1 must still inspect formats; do not infer a schema or
threat label from the feed name. For an already wrapped file, --envelopes preserves supplied
IDs/feed names; an explicit --feed overrides the feed for this import/forwarding session.

Bootstrap adds feed_name to existing kit-created raw/hunt/rejected mappings without altering
the teammate's old Elasticsearch container. Previously indexed documents are not backfilled.
The existing pending Docker smoke test now checks feed values as well as ingestion channels.

## Teammate handoff reviewed (24 October 2026)

The supplied README_UPDATE.md reports 545 records parsed/indexed and template reuse on a second pass. These are teammate-reported runtime results, not independently reproduced here. Its START_HERE.md still lists Agent 2 hunting on the final index and frozen-data report comparisons as pending.

Kit corrections applied: Agent 1 gets manage_ingest_pipelines; the service-token POST sends no body. Agent 2 remains read-only. Use SENTINELHUNT_KIT mode and runtime/ca.crt for the supplied MCP backend. The older mcp_server/README.md contains development-era paths and TLS-disabling instructions; follow README_UPDATE.md instead and keep TLS verification enabled.

Known parsing gaps in the supplied report: sudo USER=root is missing on command records; authentication action/outcome reference agreement is 89.7%. The headline 99.6% is a field-level reference comparison, not threat-detection accuracy. Preserve both parsing errors and improvements in the report.
