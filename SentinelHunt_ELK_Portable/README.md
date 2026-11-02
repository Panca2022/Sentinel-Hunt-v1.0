# SentinelHunt portable ELK lab

Elasticsearch, Logstash, Kibana pinned to **8.19.23**. For Ubuntu 24.04 / WSL2 with Docker Engine inside WSL.
The Compose and Logstash settings files are JSON-formatted YAML (valid YAML).

## What this contains

- Separate Compose project: `se6014-sentinelhunt-portable`.
- Fresh local Elasticsearch password, Kibana service token, encryption keys, and restricted backend accounts.
- Verified HTTPS to Elasticsearch, including Logstash/Kibana connections.
- Named volumes for data, certificates, Kibana state, Logstash progress/persistent queue.
- Three raw-staging adapters: watched folder (pull), authenticated local HTTP (push), TCP line stream.
- Bootstrap, permission/readiness verification, ingestion smoke test, v3 raw-only staging, endpoint/file forwarder.

No LLM, Agent 1, Agent 2, or MCP server is included. Agentic parsing and source-registration must be integrated.
No datasets, credentials, certificate private keys, existing Docker volumes, or AppSec resources are bundled.

## 1. Extract in Ubuntu's Linux filesystem

Use Ubuntu terminal in WSL, not PowerShell. Recommended location:

```bash
mkdir -p ~/se6014-portable
cd ~/se6014-portable
unzip /path/to/SentinelHunt_ELK_Portable.zip
cd SentinelHunt_ELK_Portable
```

If unzip is missing: `sudo apt-get install unzip`.
Keep the working directory under `~`, not `/mnt/c`, for normal Linux permissions and file-watching performance.
Requires Python 3, working `docker info`, Docker Compose v2 (tested configuration targets 2.33+),
8 GiB free disk minimum (15 GiB recommended), and roughly 5 GiB RAM available to the lab.
The combined steady container memory limits are approximately 4.75 GiB, plus Docker/OS overhead.
The teammate's existing ES and local LLM consume additional memory.

## 2. Initialize and check without starting services

```bash
python3 scripts/manage.py init
python3 scripts/manage.py check
```

If the kernel limit check fails, inspect it and raise it only if required:

```bash
sysctl vm.max_map_count
sudo sysctl -w vm.max_map_count=1048576
python3 scripts/manage.py check
```

This is a host-wide runtime kernel setting and may reset after reboot. It does not alter firewall rules.
With Docker inside WSL, run it inside the WSL distro hosting Docker. The kit does not modify .wslconfig.
No global Docker prune/reset/down commands are used. Existing containers and volumes are preserved.

## 3. Bootstrap

```bash
python3 scripts/manage.py start
```

This pulls images, creates certificates, starts ES, provisions indices/accounts, copies the public CA,
validates Logstash configuration inside its image, and starts Kibana/Logstash. Initial startup can take minutes.
Success ends with PASS for authentication, Kibana readiness, and backend access boundaries.
Re-running preserves credentials, certificates, data, and existing index contents.
Do not delete runtime/ or the named volumes; their credentials and data belong together.

| Host endpoint | Purpose |
|---|---|
| https://localhost:19200 | New secure Elasticsearch; existing 9200 stays untouched |
| http://localhost:15601 | Kibana; existing 5601 stays untouched |
| http://127.0.0.1:18088 | Authenticated push receiver |
| 127.0.0.1:15514 TCP | Continuous newline-delimited raw/syslog stream |

All published ports bind to 127.0.0.1. Kibana/browser HTTP and push/stream are local lab transports,
not encrypted remote endpoints. TCP stream has no authentication. Do not expose them to a LAN.
For a real external endpoint, add an SSH tunnel or approved TLS/authenticated transport before using it.
WSL host-browser localhost access depends on the machine's forwarding configuration; first try inside WSL.

For Kibana log in as `elastic`; display its password only in your own terminal:

```bash
python3 scripts/manage.py password elastic
```

Do not paste passwords or runtime/*.env into chat. The password command intentionally prints a secret.

## 4. Verify raw ingestion channels

```bash
python3 scripts/manage.py verify
python3 scripts/manage.py smoke
```

Expected: `folder pickup=1, authenticated push=1, continuous stream=2 in raw staging`.
Evidence is saved under runtime/smoke-*.json. These four test documents remain in raw staging.
No reference answers are imported and the test never populates the parsed hunt index.
HTTP acceptance is not proof of durable indexing: smoke polls Elasticsearch for the actual documents.

## 5. Stage the team's v3 dataset

Keep the dataset ZIP separate from this setup kit:

```bash
python3 scripts/manage.py stage /path/to/sentinelhunt-multisource-v3.zip
```

This verifies the inputs.ndjson checksum and atomically deposits only raw input envelopes in runtime/inbox.
It imports neither labels nor parsing references. Expect 545 dataset records in sentinelhunt-raw-v1
in addition to previous smoke documents. This does not yet run Agent 1.

Optional local endpoint push with the existing input envelopes:

```bash
python3 scripts/ship.py push /path/to/inputs.ndjson --envelopes
```

A local raw log endpoint/file, optionally followed continuously:

```bash
python3 scripts/ship.py push /path/to/demo.log --source demo-endpoint --follow
python3 scripts/ship.py stream /path/to/demo-syslog.log --follow
```

The stream command consumes a continuously appended file over a persistent TCP connection.
It does not interpret JSON envelopes or parse syslog; Agent 1 must inspect raw lines.
The forwarder reads from the beginning, requires newline-terminated records, stops on errors,
and has no rotation/reconnection checkpointing. Replayed push records get stable IDs from file offsets.
It is a small lab adapter, not a replacement for a production shipper. Ctrl+C stops a following session.

## 6. Connect agents

Read AGENT_INTEGRATION.md before changing MCP URLs. The existing teammate test index is not migrated.
Do not point Agent 2 at raw staging: Agent 1 writes the parsed hunt index first.
Use separate runtime/agent1.env and runtime/agent2.env credentials in the MCP backend.
The proposed registry/parsed-index interface still needs agreement with the teammate.

For display, create Kibana data views for `sentinelhunt-raw-v1` (receipt @timestamp) and
`sentinelhunt-hunt-v1` (parsed event @timestamp). Use a time range covering the events' dates.
Kibana views are not automatically created by this kit.

## Operations

```bash
python3 scripts/manage.py status
python3 scripts/manage.py stop
```

Stop preserves named volumes. Services do not automatically restart after a VM shutdown; run start again.
To inspect logs, scope explicitly to this project:

```bash
docker compose -p se6014-sentinelhunt-portable -f compose.yaml logs --tail 80 elasticsearch kibana logstash
```

Do not publish effective Compose configuration: env_file secrets can appear in `docker compose config`.
Use `config --quiet` for validation. Do not share runtime/ or re-zip a used deployment.
For a new machine use the original clean distribution ZIP so it generates its own credentials/certificates.

## Validation status

See VALIDATION.md for checks actually performed before delivery. Docker is not available in the author's
Codex workspace, so container startup, Logstash plugin validation, TLS/RBAC, and ingestion smoke tests
must run in the target Ubuntu environment. The scripts perform these checks and stop on failures.
This kit is prepared for testing; it is not a claim of a completed agentic end-to-end demonstration.

## Official sources

- https://www.elastic.co/guide/en/elasticsearch/reference/8.19/docker.html
- https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/service-accounts
- https://www.elastic.co/guide/en/logstash/8.19/docker-config.html
- https://www.elastic.co/guide/en/logstash/8.19/plugins-inputs-http.html
- https://www.elastic.co/guide/en/logstash/8.19/plugins-inputs-tcp.html

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
