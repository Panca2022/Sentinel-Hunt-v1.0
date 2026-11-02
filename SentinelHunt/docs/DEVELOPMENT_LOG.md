# SE6014 Final Project — Agentic Threat Hunting on ELK (Question 1)

> Working plan. Build owner: **Cigmy** (with Claude). Team owns report, presentation and pitch.
> Deadline: **≈ 31 Oct 2026 (to confirm)**. Demo: brief says **live in-class** (5 min demo + 5 min pitch + Q&A); we planned a recorded video → **confirm with prof**, keep video as backup.
>
> **Rule: requirements first.** Nothing in Tier 2 (wow features) until every ❌/⚠️ in §0 is ✅.

---

## 0. Requirement status & priorities (read this first; updated 23 Oct)

Checked against the brief (SE6014 Q1). ✅ done · ⚠️ partly · ❌ missing.

### 0.1 Build requirements

| # | Requirement (brief wording) | Owner | Status | What is left |
|---|---|---|---|---|
| ELK | Set up the ELK stack (Elasticsearch, Logstash, Kibana) | Teammate | ⚠️ | Stack runs (8.19.23). Our hunts so far ran on the dev ES copy, not his stack |
| R1 | Ingest via **pull, push and stream** | Teammate | ⚠️ | Pull ✅. **Push and stream missing** |
| R2 | Agentic ingestion: "user points the system at a log source and agents handle the rest" | Us | ❌ | **Agent 1 v4 one-command flow**: raw file → logs-unparsed → template → register → reprocess → searchable |
| R3 | Agent inspects log, **selects** matching template, else **creates** one, **validates** on samples, **registers** for reuse | Us | ⚠️ | Create/validate/register ✅ (v3.3, Loghub 5/5). Missing: select-existing-template step; run on teammate v3 raw data (3 formats, field accuracy vs parsing-reference) |
| R4 | At least 3 distinct log types | Both | ✅ | auth (SSH + sudo), web access, firewall (+ Loghub as unknown formats) |
| R5 | Search, aggregation and every capability the hunt needs as **MCP tools** | Us | ✅ | Hunt + schema roles, server-enforced allowlist, field validation, query ledger |
| R6 | Hypothesis → agents via MCP **plan, query the ingested logs, test, report** (verdict, evidence, every query) | Us | ✅ / ⚠️ | Works (Agent 2 v1.9). Gap: must hunt **pipeline-ingested** logs (teammate ELK index or Agent 1 output), not our side-loaded parsing-reference |

### 0.2 Analysis & experiment

| # | Requirement | Status | What is left |
|---|---|---|---|
| A1 | Completeness & accuracy: coverage of data sources, time windows, techniques; every claim tied to retrievable evidence; hallucination prevented/detected | ⚠️ | Mechanisms ✅ (coverage check, code time parser, claim checker, ledger). Write-up needs a **technique coverage table** (4 ATT&CK techniques testable; others → INCONCLUSIVE + missing data) and the known limit: checker verifies numbers, not their meaning (45 records reported as 45 attempts) |
| A2 | Run the **same** hunt twice, compare, explain, what was changed to converge | ✅ (24 Oct, on kit) | Done on v1.1 (9/9 verdicts). **Rerun on final Agent 2** (AI follow-ups now vary between runs) |

### 0.3 Deliverables

| Item | Status | What is left |
|---|---|---|
| Report (60%): cover, TOC, exec summary (non-technical), architecture, setup docs + challenges + **code repo URL**, workflow design + guardrails, experiment results, conclusion/limitations, timesheet appendix | ❌ | Material in PROJECT.md, SETUP_DESKTOP.md, agent READMEs. **Create GitHub repo** |
| Demo + Shark Tank pitch (40%) | ❌ | Live vs recorded (confirm); demo script; pitch slides |
| Naming: `Group<x>_SE6014ProjectReport.pdf`, `Group<x>_Pitch.pdf`, no spaces | ❌ | Need group number |

### 0.4 Priority order (do in this order)

1. **Agent 1 v4 + one-command ingest flow** on teammate v3 raw data (closes R2, R3, and the R6 gap)
2. **Push + stream ingestion** (R1, teammate) — confirm his timeline
3. **Agent 2 against teammate's ELK index** (set `ES_URL` / `INDEX_PATTERN`; rerun the test suite there)
4. **Rerun run-twice experiment** on final Agent 2 (A2)
5. **GitHub repo** + ask prof: live vs recorded demo, AI-use policy
6. Report write-up incl. technique coverage table (A1) and limitations found in testing
7. Only then Tier 2: Streamlit page + PDF export, select-existing-template polish, extra playbooks

### 0.5 Integration contract: teammate's portable ELK kit (`SentinelHunt_ELK_Portable`, 24 Oct)

| Item | Teammate's kit | Impact on our side |
|---|---|---|
| Stack | Separate secure ES/Logstash/Kibana 8.19.23 (TLS + passwords): ES `https://localhost:19200` (CA `runtime/ca.crt`), Kibana `:15601`, push `:18088`, stream `:15514`. Our test ES on 9200 untouched | MCP server needs CA-file TLS + per-role credentials (`runtime/agent1.env` schema role, `runtime/agent2.env` hunt role) |
| Ingest | Pull (folder `runtime/inbox/*.ndjson`), push (HTTP, auth), stream (TCP lines) → **`sentinelhunt-raw-v1`**: `record_id` (= _id), `capture_id`, `raw_line`, `source_name`, `feed_name`, `ingestion_channel`, `received_at`, `@timestamp` (= receipt time) | R1 covered by his kit once it passes `manage.py smoke` on our machine (not yet run in Docker). Agent 1 reads `raw_line`, groups by **`feed_name`** (replaces `event.dataset`) |
| Parsed | **`sentinelhunt-hunt-v1`**, **strict mapping, 32 fixed ECS fields**; keep record_id (= _id), capture_id, feed_name, raw_line, event.original; event time → @timestamp | Agent 1 must map its fields onto the 32 names; anything else is rejected. event.action / event.outcome are interpretations Agent 1 does not produce yet → **normalisation step needed** (Agent 2 playbooks depend on them) |
| Registry | `sentinelhunt-schema-v1` document index, format up to us | Move registry.json into this index |
| Permissions | agent1: read raw, read/write hunt + registry, **no ingest-pipeline privileges**. agent2: read hunt only | Ask for `manage_ingest_pipelines` on agent1 (validate with _simulate + register pipelines), or parse in Python |
| Agent 2 | Reads only `sentinelhunt-hunt-v1` | `INDEX_PATTERN=sentinelhunt-hunt-v1` |
| Memory | Lab ≈ 4.75 GiB | + dev ES 3 GiB + Ollama within WSL 18 GiB: stop dev ES if tight |

Open asks to teammate: (1) `manage_ingest_pipelines` for agent1 role; (2) a field for extra extracted values not in the 32 (or agree to drop them); (3) we derive event.action/outcome in Agent 1.

### 0.6 Changes we made to the teammate's kit (keep this list; tell him)

| Date | File | Change | Why |
|---|---|---|---|
| 24 Oct | `scripts/manage.py` line 156 | agent1 role cluster privileges `['monitor']` → `['monitor', 'manage_ingest_pipelines']` | Agent 1 validates rules with ES `_simulate` and registers them as ingest pipelines. Narrow: pipelines only, no users/indices/templates. His test `assertNotIn('manage_index_templates', ...)` still holds. Note: `DISTRIBUTION_SHA256.json` hash for manage.py no longer matches (not checked at runtime) |
| 24 Oct | `scripts/manage.py` line 173 | Kibana service-token request sent an empty JSON body `{}` → ES 8.19 rejects it (`does not support having a body`, HTTP 400) and `start` stopped in provision. Now sent without a body | **Bug in the kit** found on its first Docker run; everything before it (indices, roles incl. our privilege, users) had succeeded |

### 0.65 Agent 1 v3 test on teammate's v3 raw lines (24 Oct, `experiments/agent1_v3_eval_20261024-004010.md`)

3/3 layouts schematised automatically, 100% of 545 lines parse. Literal field values found 93.6%, same ECS name 74.8%.
- Firewall + web: every literal value extracted; only naming issues (network.packet.length→network.bytes, http.response.bytes→http.response.body.bytes, host.hostname→host.name, PREFIX captured as event.action instead of rule.name, UDP vs udp) + leftover temp fields (timestamp, log_message, log.logger, event.dataset) that the strict hunt mapping would reject
- SSH/sudo (one syslog layout): header only; source.ip/port, user.name, user.target.name, sudo command/cwd/terminal stay inside log_message (0%)
- Derived fields (event.action/outcome, log.category) not produced
→ v4 stages: **C** message-body parsing per message type · **D** map fields onto the 32 hunt fields (code-validated names + types) · **E** normalisation with a **fixed vocabulary** (option A, `agent1/vocabulary.json`)
- Honesty note: example library contains apache-combined and iptables-style examples, so web/firewall were not fully "unseen"

**Agent 1 v4 runs (24 Oct)** — values found / his field names / derived fields:
93.6 / 74.8 / – (v3.3) → 92.5 / 92.5 / 73.1 (v4 first) → 98.3 / 93.0 / 85.0 (diagnosis + outcome guidance) → **99.6 / 99.6 / 99.1** (template-based stage C, code name matching, per-action outcomes). Format checks 100% (only the 32 hunt fields; record_id/capture_id/feed_name/raw_line/event.original kept). Reuse run: all 3 templates reused, no LLM calls.
- Lesson (again): the 14B model could not write whole message patterns AND name fields (`%{WORD:rule.name} %{WORD:rule.name}` for "Failed password"); **code builds the template (Drain-style token alignment), LLM only names slots** → all 13 SSH/sudo message types parsed
- Caveats for the report: event.action vocabulary and per-action outcomes come from the teammate's reference (contract, option A) → derived-field score is partly by construction; web/firewall formats resemble library examples; 545 lines from one lab; user.target.name 66.7% (sudo USER= slot left unnamed)
- v4.1 (pending run): literal digits in templates generalised (`(uid=\d+)`), stage E rejects rules tied to one user/host/IP, coverage round for events no rule covers ("Connection closed by" fell to other)

**First end-to-end run on the teammate's kit (24 Oct):** kit started (after fixing its Kibana-token bug), smoke PASS (pull + push + stream → raw staging = **R1 shown**), v3 staged by pull as feed `v3-mixed-pilot` (545 raw lines, no labels/reference). Then **`process_source('v3-mixed-pilot')` over MCP (ingest role)**: 3 layouts, templates created + validated + registered (pipelines + `sentinelhunt-schema-v1` docs), router `feed-v3-mixed-pilot`, **545/545 records indexed into `sentinelhunt-hunt-v1`, 0 failed**, 143 s with fresh generation; reuse run: 3/3 templates reused, no LLM calls (= **R2 + R3 shown**).
Integration bugs found on the way: (1) `_reindex?refresh=true` needs index maintenance privilege the agent1 account (correctly) lacks → removed; (2) a rename (network.packet.length → network.bytes) left an EMPTY `network.packet` object → strict hunt mapping rejected 200 firewall records; pipeline now removes emptied parent objects and the output check flags empty objects (my simulate-based check had only looked at fields with values).

**Agent 2 on the kit's parsed hunt index (24 Oct, read-only agent2 account via MCP):** 4/4 verdicts as expected (SSH 17:07–17:09 criteria matched, 15 failed-password attempts from 192.0.2.1, 0 later logins; slowdown INCONCLUSIVE + web probing related; fake IP NOT FOUND + related; ransomware INCONCLUSIVE), 18/18 claims verified; 3 malformed AI follow-ups rejected. Full chain: raw → Logstash → staging → Agent 1 (MCP) → hunt index → Agent 2 (MCP) = **R6 on ingested logs**. Bug fixed on the way: MCP returns a one-item list as the item (only one index visible to agent2).
**A2 run-twice on the kit (`experiments/run_twice_20261024-134108/`)**, data proven unchanged (doc count, time range, sha256 of all ids before = after): baseline (T 0.7) verdict 1/1, playbook 1/1, query Jaccard 0.70, key-evidence Jaccard 1.00, claim similarity 0.52; converged (T 0, seed 42) 1/1, 1/1, 0.89, 1.00, 0.72. Verdict + evidence decided by code → identical; AI follow-up queries and wording vary, less with the converged setting.
Wording (agreed with teammate): parsing percentages = **agreement with the parsing reference**, not detection accuracy.

**Hunt index vs parsing reference, record by record on the kit (`experiments/compare_hunt_vs_reference.py`, 24 Oct):** 545/545 records, **100.0% agreement** on all reference fields (literal and derived) after the sudo USER= fix (slot context + second naming pass). Extra fields beyond the reference: correct ones (Connection-closed lines: user.name/source.ip/source.port; tty=ssh → terminal) and two wrong ones — PAM `uid=0` named user.name/user.target.name, `ssh2` named network.transport → type checks tightened (usernames may not be numeric; transport must be an IANA transport name, ECS). Lesson: agreement with a reference does not catch extra wrong fields; check extras too.

**Fresh-generation variance (Agent 1's version of A2):** the next `--fresh` run removed the wrong extras (uid as username, ssh2 as transport) but sudo USER= fell back to 30/45 (LLM left the slot unnamed). Fix: focused key=value naming question retries once (T 0.7). Report point: building a parser from scratch varies run to run; a validated, registered parser reused later gives identical output → final data should come from a reused template, not a fresh one. Also: run-twice fingerprint now hashes full document contents (ids alone would not notice a re-parse).

**Sudo USER= fixed — final parsers (24 Oct):** the notes showed the 14B model insisting USER=root is `user.name` (rejected each time as a duplicate → field left empty, i.e. fail-safe: empty rather than wrong). Asking it to *name* the slot again failed 3×; asking a **two-way role question** for the conflicting related pair ("which of S1/S4 is the target user?") answered correctly (S4) → **100.0% agreement with the reference on literal and derived fields, 545/545, no wrong extra fields.** Same rule covers source/destination IP and port. Lesson: turn an open naming task into a constrained choice. **Parsers frozen from here: reuse only, no --fresh.**

**A2 final (frozen parsers, kit, 24 Oct):** data unchanged (ids + full contents hashed before = after).
- `run_twice_20261024-144113` (SSH window hypothesis): verdict/playbook/key evidence identical in both configs; query J 0.70 (baseline) vs 0.89 (converged); claim similarity 0.25 vs 0.26.
- `run_twice_20261024-144428` (TC1–TC4 × 2 configs × 2 runs = 16 hunts): **verdict 4/4 and 4/4, playbook 4/4 and 4/4, key-evidence Jaccard 1.00 and 1.00**; query Jaccard 0.70 → 0.78; claim-text similarity 0.32 → 0.52.
- Reading: decisions converge **by design** (playbooks, rule verdict, code-chosen evidence); AI follow-up queries and wording vary; T=0 + seed reduces but does not remove variation (also not fully repeatable on GPU: SSH-window claim similarity 0.72 in one session, 0.26 in another). Wording similarity is a noisy metric at n=1.

**Agent 2 v1.13 (after reading the run-twice summaries):** 4/16 reports had a misleading claim ("all 15 failed password attempts were categorized as pam_authentication, pam_unknown_user, ssh_authentication and ssh_invalid_user" — those are 4 log records per attempt). It passed the claim checker (numbers and names exist in the results). Fix: writer rule (per-type counts are log records) + **code check rejects claims that describe attempts as several record types**; summary always starts with the code verdict; `@timestamp:>X` time filters stripped too (one slipped into a follow-up). → rerun run-twice for the final saved reports. Rerun (`run_twice_20261024-151948`): 4/4 misleading claims caught and removed by the checker, 0 kept (49 kept claims); summaries all start with the verdict. One new failure seen at T 0.7: literal placeholder text ("each appearing `count` times") → code check rejects placeholder tokens (`count`, {ip}, <port> …).

**A2 FINAL = `run_twice_20261024-153103` (Agent 2 v1.13, frozen parsers):** data unchanged (ids + contents); baseline verdict 4/4, playbook 4/4, key evidence 1.00, query J 0.70, claim similarity 0.28; converged 4/4, 4/4, 1.00, 0.70, 0.54. 47 claims kept, 0 misleading, 0 placeholders; **6 removed by the code checker** (4 attempts-as-record-types, 2 `count` placeholders) — shown in the reports. Sent to teammate as SE6014_request_agent2.zip (older runs only under _older_versions_not_final).

**Agent 2 v1.14 — self-correction:** the writer rule alone did not stop the attempts-as-record-types claim (4 before, 4 after). Now a claim rejected by the code checker goes back to the AI **once, with the checker's reason**; the rewrite is verified again by code (kept only if it passes, otherwise removed). Reports show "rewritten by the AI after checker feedback" + the original. Same build → test → explain → retry loop as Agent 1; code keeps the final word.

**Run 155852 (v1.14) + checker fix (v1.14.1):** 54 claims kept, 0 misleading, 0 placeholders; 4 rejected → 2 rewritten and passed, 2 removed. One removal was a **checker false positive**: the AI's corrected claim "the failed password attempts generated log records with event.action values …" is true but was still rejected. Fix: the attempts check now accepts *attempts generated / produced / wrote / created / resulted in / left … records* and still rejects *attempts were / included / were categorized as <record types>* (offline test: correct form kept, 4 wrong forms rejected). Needs one more `run_twice --suite --quick` for the final evidence.

**Run 160908 (v1.14.1) review → v1.15:** data unchanged; verdict 4/4, playbook 4/4, key evidence 1.00 in both configs; query Jaccard 0.69 baseline / 0.87 converged; claim similarity 0.37 / 0.41. The checker fix worked (rewritten claims kept; ambiguous "attempts included/were logged with … types" removed). Found:
- **Wrong count passed the checker:** baseline TC3 run 1 said "9 distinct ports" and then "8 distinct ports". Cause: `compact()` showed the AI only the first 8 buckets without saying so; the checker only checked the claim's main number. Fix: compact adds "showing 8 of 9 buckets"; checker compares every "N distinct/different/unique" with the full cited result (distinct_values, or bucket count when the list is complete).
- **Repeated follow-up queries** (the same query 2–3×): now skipped as repeats (status `skipped`), not run again.
- **Converged is not fully deterministic:** converged TC2 ran identical queries in both runs but the claim wording still differed (Ollama output at temperature 0 + seed 42 still varies a little). Claim similarity is therefore noisy (0.83 in run 155852, 0.41 in 160908); report it as a range. Verdict, playbook, rule and key evidence are decided by code and were identical in every run.

**FINAL A2 evidence: run_twice_20261024-161924 (v1.15).** Data unchanged. baseline: verdict 4/4, playbook 4/4, key evidence 1.00, query J 0.80, claim sim 0.50; converged: 4/4, 4/4, 1.00, 0.86, 0.52. 52 claims kept (manual review: none wrong), 4 rewritten after checker feedback and passed, 3 removed. Follow-ups: 32 ran, 4 skipped as repeats, 11 rejected. Picture: side_by_side_converged_TC1.png (made by experiments/side_by_side_image.py). Teammate package SE6014_request_agent2(.zip) updated to this run. Known minor wording issue: some TC4 claims say "15 sudo events" where 15 = sudo command records (45 sudo log records in total).

**Side-by-side picture (final format):** experiments/side_by_side_image.py → one page per case: what matched (✓/≠), the HUNT RESULT of both runs in cards (same lines as the terminal box via `hunt_agent.result_lines`), word diff of the AI summaries, all claims (rewritten/removed), every query aligned (13 of 19 identical in TC1: all code queries; the 6 different ones are AI follow-ups), key evidence.

**Demo app (Streamlit) v1:** demo/app.py + demo/README.md. Pages: 1 Ingest (pull/push/stream via the kit's own publish()/ship.py, counter from MCP list_feeds), 2 Agent 1 (process_source over MCP, layouts, raw vs parsed from the hunt index via the read-only account), 3 Agent 2 (live hunt via `hunt(..., log=callback)`, cards, claims, queries, evidence, report download), 4 Run twice (comparison table + side-by-side, optional new run). No ES credentials in the app. Smoke-tested offline (all pages load, MCP errors shown, no crashes); live test on WSL pending. `hunt()` got an optional `log=` callback (terminal output unchanged). Pending: demo log batch (a new format for "Agent 1 builds", same format again for "reuses", plus fresh attack lines).

**Agent 1 fix (relax over-strict types):** demo feed demo-ssh-1 with fresh=True → needs_human, 0% in all 3 rounds: the 14B model kept `%{HOSTNAME:host.hostname}`, which rejects `host_001` (underscore); the diagnosis said so but the model repeated it. New code repair after whitespace/anchors: find the piece that fails on a real failed line (`failing_piece`, split out of `diagnose`), swap its strict grok types (HOSTNAME, IPORHOST, WORD, USERNAME, INT…) for NOTSPACE, re-validate on the held-out lines; up to 4 steps, logged as `relax-types-N`. Same rule as before: the AI proposes, code repairs, code validates. Demo sample: demo/sample_logs/demo-ssh-auth.log (64 lab lines, 198.51.100.77 → user_009, 24 Oct 09:15).
Result with the fix: built in 47 s, 64/64 indexed, 0 failed (relax step 1 → 100%). **But stage E misclassified**: ssh_invalid_user=24, i.e. the 12 "Failed password for invalid user" lines were labelled ssh_invalid_user (a broad `contains "invalid user"` rule matched first) → Agent 2's SSH playbook would see 0 failed passwords. Fixes: (1) code orders E rules most specific first (equals > startswith > contains, longer value first, always last); first match wins in the pipeline too; (2) vocabulary: ssh_invalid_user says it is NOT the "Failed password for invalid user" line, ssh_authentication says it includes it. Frozen v3 templates unaffected (already built).

**Teammate review of TC1 (converged, run_twice_20261024-161924):** (1) run 2 claim "between 17:07:00 and 17:08:00" is wrong: real range 17:07:40.247–17:08:56.119 (4 + 11); the model used per-minute bucket keys as start/end and the checker only checked counts/entities. (2) run 2 follow-up `terms destination.port` "15 events" = matching records; no buckets (SSH auth lines have source.port only); not cited. Fixes (future runs; saved runs unchanged): aggregate tool returns `first_event`/`last_event`, `events_without_field` (+ summary "15 events; 15 without destination.port"), `bucket_note`; checker rejects "between A and B" claims when cited events fall outside A–B (offline test: wrong range rejected, two correct ranges kept). experiments/verify_tc1.py recomputes both on feed v3-mixed-pilot + the checksum → VERIFY_TC1.md. Package: Documents/SE6014_repeatability_TC1 (both reports, query ledgers, fingerprints, comparison, side-by-side, README with answers + convergence explanation).
Teammate accepted the evidence, keeps the original mistake in the report. Post-fix: postfix/guardrail_fix.patch (applies cleanly on SE6014_request_agent2) + regression_tc1_20261024-185158: A destination.port → "15 events; 15 without destination.port" PASS; B run 2 original claim rejected with reason, control kept PASS, live rewrite "17:07:00.000Z–17:08:56.119Z" kept (true, loose start); C normal hunt 17:07–17:09: CRITERIA MATCHED, 3 kept / 1 rewritten / 0 removed, missing fields reported. Package now covers all 4 cases × 2 settings (86+ files).

### 0.7 Implementation plan on top of the kit (our side)

1. **Agent 1 v3 test on dev ES** (`agent1/eval_v3.py`): parsing quality on v3 raw lines vs parsing-reference, independent of the kit
2. **Start the kit in WSL**: copy to `~/se6014-portable`, `manage.py check` → `start` → `smoke` → `stage <v3 zip> --feed v3-mixed-pilot` (first Docker run of the kit)
3. **MCP server v2**: TLS with CA file, per-role credentials from `runtime/agent1.env` / `agent2.env`, hunt role → `sentinelhunt-hunt-v1` only, schema tools read `raw_line` + `feed_name` from `sentinelhunt-raw-v1`, registry documents in `sentinelhunt-schema-v1`, new tool **`process_source(feed_name)`** (R2)
4. **Agent 1 v4** through MCP: layout split per feed, select/create/validate/register, map fields onto the 32 hunt fields (rename/drop), **normalisation step for event.action / event.outcome**, keep record_id (= _id), capture_id, feed_name, raw_line, event.original, event time → @timestamp; write parsed records to the hunt index
5. **Agent 2 on the hunt index**: rerun the test suite, then run-twice (A2) on frozen data

### 0.8 Teammate's asks (owed to him / must match his kit) — tick when done

- [x] **Agent 1 v3 test results** vs parsing-reference (eval_v3) — v4: 99.6 / 99.6 / 99.1
- [x] **One example of Agent 1's parsed output** (sent in SE6014_request_agent1)
- [ ] **Parsed record format**: keep `record_id` (also ES `_id`), `capture_id`, `feed_name`, exact `raw_line`, set `event.original`, event time → `@timestamp` (staging @timestamp is receipt time); only the 32 hunt fields (strict mapping); never invent usernames/IPs, never import labels
- [ ] **Separate indices**: read `sentinelhunt-raw-v1`, write `sentinelhunt-hunt-v1`; Agent 2 queries the hunt index only
- [x] **MCP operation to select/register a source and trigger processing**: built + run on kit 24 Oct (545/545) (`list_feeds`, `process_source(feed_name)` in roles ingest/schema; `agent1/run_source.py`; client `mcp_server/ingest_client.py`) — to test on the kit
- [~] **Registry document format** for `sentinelhunt-schema-v1`: one doc per template, _id = pipeline name: `name, feed_name, layout_shape, version, model, updated, processors_json, template_json` (JSON strings → no mapping drift) — to test on the kit
- [~] **Security** (built: SENTINELHUNT_KIT mode loads runtime/agent1.env or agent2.env per role, CA-verified TLS; to test): credentials only in the MCP backend (runtime/agent1.env, agent2.env), never in prompts; verified TLS with the kit's CA; never the elastic superuser
- [ ] **Send Agent 1 + MCP code** when ready
- [ ] **Keep our test ES (9200) intact**
- [ ] **Fixed vocabulary for event.action / event.outcome / log.category** (option A, `agent1/vocabulary.json`): send to him, ask him to add it to AGENT_INTEGRATION.md as part of the contract
- [ ] His acceptance list (AGENT_INTEGRATION.md): stage inputs.ndjson only; known AND unregistered format (create / validate / register / **reuse**); Agent 2 on the hunt index; identical hypothesis twice on frozen data keeping reports, exact queries, record IDs, source/time coverage, validation failures; SSH attempts not records ✅; verdict wording **DETECTION CRITERIA MATCHED / NOT MATCHED / INCONCLUSIVE** (we still say NOT FOUND → align)

**Current component status:** desktop setup ✅ · models + GPU ✅ · Agent 1 v3.3 frozen (Loghub 4/5, 5/5) · teammate ELK + pull ✅ · MCP server ✅ · Agent 2 v1.11 ✅ (9/9 suite, 7/7 curveballs, 9/9 time/false-positive tests, run-twice 9/9 verdicts; SSH now counts attempts not records; verdict = "detection criteria matched")

---

## 1. Goal

A user gives the system a log source or a plain-language threat hypothesis. Agents then:

1. **Ingest:** pull logs in, recognise their format (or create a new schema), and index them in Elasticsearch.
2. **Hunt:** plan the hunt, query through MCP tools, test the hypothesis, and return a report with a **verdict, the evidence, and every query that produced it**.

Everything runs locally on one PC. No live log sources; public datasets are replayed through the pull, push and stream ingestion modes.

---

## 2. Requirement traceability

| # | Requirement (from the brief) | How we meet it | Tier |
|---|---|---|---|
| R1 | Ingest via **pull, push and stream** | One Logstash pipeline with 3 inputs (file folder, HTTP, syslog). **Any log type can come through any mode** | Must |
| R2 | Easy agentic ingestion: "point at a source, agents do the rest" | `ingest_source` MCP tool + Agent 1. The user gives a path or mode; the agent handles detection, schema and indexing | Must |
| R3 | Assign the right parsing schema; if none exists, create one, validate it on samples and save it for reuse | Agent 1 + schema registry + Elasticsearch `_ingest/pipeline/_simulate` validation | Must |
| R4 | At least 3 distinct log types | Teammate v3 dataset: auth (SSH + sudo), web access, firewall (+ Loghub samples as unknown formats). Original plan was Windows/Sysmon; replaced by teammate's lab data | Must |
| R5 | Search, aggregation and all hunt capabilities exposed as MCP tools | Python MCP server (see §5) | Must |
| R6 | Hypothesis → plan → query → test → report (verdict, evidence, all queries) | Agent 2 (playbook-guided hunt agent) via MCP; Markdown/JSON report (Streamlit + PDF later) | Must |
| A1 | Explain completeness and accuracy: data-source coverage, time windows, techniques, claim↔evidence links, hallucination prevention | Coverage matrix + query ledger + code-based verifier (see §7) | Must |
| A2 | Run the **same** hunt twice, compare, explain, make the runs agree | Experiment harness (see §8) | Must |
| D1 | Report (60%) | Team, from the build artefacts (see §10) | Must |
| D2 | 5-min demo + 5-min pitch (40%) | Brief says live in-class; recorded video as backup (confirm) + team pitch | Must |

---

## 3. Decisions made

| Topic | Decision |
|---|---|
| Question | Q1: Agentic Threat Hunting on ELK |
| Log sources | Public datasets only, replayed (no live sources) |
| Log types | Windows Security, Sysmon, firewall/network, web server (Apache/nginx), unstructured (Loghub) |
| Ingest modes | Pull = watched folder; Push = HTTP POST to Logstash; Stream = **syslog replay** (UDP/TCP) |
| Hypotheses | ① Brute force / password spray (T1110) ② Web attack / scanning (T1190) ③ C2 beaconing / lateral movement (T1071 / T1021) |
| Hardware | Demo machine = desktop (RTX 4070 Super 12 GB, 32 GB DDR5). Teammate's laptop = development copy + backup |
| Deployment | **Everything inside WSL2 Ubuntu on F:**: Docker Engine (no Docker Desktop) running ELK, MCP server and agents, plus Ollama using the GPU through the Windows driver. Default NAT networking (mirrored mode broke downloads). See `setup/SETUP_DESKTOP.md` |
| LLM | **One pretrained model shared by two logical agents.** Each agent has its own system prompt, context and **MCP tool allowlist enforced by the server**. Model chosen by benchmark (`bench/`) from qwen3:14b (favourite), qwen2.5:14b, llama3.1:8b (gpt-oss:20b dropped: doesn't fit fully in GPU memory) |
| Agent 1 approach | **No fine-tuning initially.** Pre-labelled example library (few-shot retrieval) + generate → simulate → retry loop. If results are inconsistent: improve prompts and validation first; QLoRA only as a last-resort stretch goal (§6.3) |
| Hunt UI | Streamlit chat + report view |
| Scope strategy | **Every requirement first (Tier 1), then wow features (Tier 2) in priority order** |

---

## 4. Architecture

```
 datasets/ ─┬─ drop into ./ingest/drop/  ──► [Logstash file input]   (PULL)
            ├─ push_client.py  ──HTTP──►     [Logstash http :8080]   (PUSH)
            └─ stream_replay.py ─syslog──►   [Logstash syslog :5514] (STREAM)
                                               │ adds: ingest.mode, source.name, raw message
                                               ▼
                                Elasticsearch ingest "router" pipeline
                          ┌───────── known fingerprint? ─────────┐
                        yes                                      no
                          ▼                                       ▼
              per-type parse pipeline                     index: logs-unparsed
              → logs-<type>-*                                    │ triggers
                                                                 ▼
                                                    AGENT 1 (Schema agent)
                                       sample → match registry → else generate Grok
                                       → _simulate on samples → retry ≤3 → register
                                       → reprocess unparsed docs into logs-<type>-*

 ┌──────────────────────── MCP SERVER (Python) ────────────────────────┐
 │ ingest tools │ schema tools │ hunt tools (search/aggregate/…)       │
 │ Query ledger: every call logged with query_id, DSL, hit count, hash │
 └─────────────────────────────────────────────────────────────────────┘
                 ▲                                   ▲
           AGENT 1                            AGENT 2 (Hunt agent)
                                  hypothesis → plan → coverage check → execute
                                  → evidence → rule-based verdict → write → VERIFY
                                                   ▲
                                        Streamlit chat (human)
                                                   │
                                  Hunt report (Markdown/PDF + JSON) with
                                  query IDs + clickable Kibana evidence links
```

**Stack:** WSL2 Ubuntu 24.04 (on F:), Docker Engine, Elasticsearch + Logstash + Kibana **8.19.23** (teammate's version; dev sandbox switched to match), Python 3.12, official MCP Python SDK (FastMCP), Ollama (inside WSL, GPU), Streamlit.

**Resource caps:** `.wslconfig` memory=18GB (Windows keeps ~14 GB); ES heap 2–3 GB; Logstash heap 1 GB; LLM in GPU memory (~10 GB of 12 GB).

---

## 5. MCP tools

| Group | Tool | Purpose |
|---|---|---|
| Ingest | `ingest_source(path, mode)` | Start pull, push or stream replay for a dataset |
| | `ingest_status()` | Doc counts per index and mode; size of the unparsed backlog |
| Schema | `sample_unparsed(n)` | Return raw unparsed lines |
| | `list_templates()` / `get_template(id)` | Schema registry |
| | `simulate_pipeline(grok, samples)` | Validate with ES `_simulate`; returns success rate + failed lines |
| | `register_template(...)` | Save the ingest pipeline + index template + fingerprint |
| | `reprocess_unparsed(template_id)` | Re-index matching unparsed docs |
| Hunt | `list_indices()` / `get_field_mappings(index)` | Ground the model in real fields |
| | `search(index, query, time_range, size)` | Validated query → hits (+ doc IDs) |
| | `aggregate(index, agg_type, field, …)` | terms / date_histogram / cardinality / stats |
| | `get_document(index, id)` | Fetch exact evidence |
| | `timeline(entity, time_range)` | Events for a host, user or IP in time order *(Tier 2)* |
| | `rare_values(index, field)` | Anomaly pivot *(Tier 2)* |
| Ledger | `get_query_log(hunt_id)` | Every query run in a hunt, for the report |

Every hunt tool **validates fields and indices against real mappings before running**, so the model cannot query fields that don't exist.

---

## 6. Agent 1: Schema / ingestion agent

### 6.1 Flow

1. Take **20 diverse lines** (one per layout first) for generation, plus **100 different lines held out** for validation.
2. **Match:** test each registered template on the samples. If one parses ≥ 95% of lines, use it.
3. **Retrieve:** pull the 3 most similar examples from the labelled example library.
4. **Generate:** write a Grok pattern, field names (mapped to ECS where possible) and the event type.
5. **Validate** on the held-out lines with ES `_simulate`. Pass = ≥ 95% parse **and** ≥ 3 fields per line **and** no catch-all pattern. Otherwise feed back the failed lines + reason and retry (max 3 attempts).
6. **Register** the template and reprocess the unparsed docs. If it still fails after 3 attempts, mark the source "needs human" (a guardrail).

### 6.2 "Training" with pre-determined data (Tier 1)

- **v1 has 6 formats** (Apache access, nginx error, iptables, Java log4j, generic syslog, FortiGate key=value); grow it to ~12–15 if the evaluation shows gaps.
- Build an **example library** of ~15–20 known formats. Each entry has sample lines, a verified Grok pattern, a field map and an event type.
- Sources: Loghub (which publishes ground-truth event templates), sshd, nginx/Apache, iptables, pfSense, and others.
- **Evaluation:** 5 Loghub systems the library doesn't contain (OpenSSH, HDFS, Apache error, Linux, Zookeeper), run with `--eval --fresh`, then measure the share of lines parsed and the number of attempts needed. These numbers go in the report.

### 6.3 Stretch (Tier 2): QLoRA fine-tune

- Fine-tune a 7–8B model with QLoRA using Unsloth on the 4070 Super, on (log sample → Grok + field map) pairs.
- **Go/no-go at end of Day 8.** If it's a go, compare base vs. fine-tuned on the held-out set (a good wow-factor chart).

---

## 7. Agent 2: Hunt agent + hallucination prevention

### 7.1 Hunt flow

1. **Parse the hypothesis** into a structured form: ATT&CK technique, entities, expected observable behaviour.
2. **Plan** using a fixed JSON plan template: data sources × fields × time window × queries × "what result would confirm or refute the hypothesis".
3. **Coverage check (code):** every relevant index in the plan must exist and contain data in the time window. Gaps are logged and reported.
4. **Execute** each planned query through MCP. Allow at most N follow-up pivots, each of which must be justified.
5. **Collect evidence:** document IDs, aggregation results, query IDs.
6. **Verdict (rule-based):** each hypothesis has explicit thresholds (e.g. ≥ X failed logons from one source followed by a success). Possible verdicts are `CONFIRMED`, `NOT FOUND` or `INCONCLUSIVE`. The LLM explains the verdict but does not decide it.
7. **Write the report**, then pass it through the **verifier** (§7.2).

### 7.2 Hallucination prevention layers

| Layer | Mechanism | Catches |
|---|---|---|
| Grounding | Agent sees only tool outputs; system prompt forbids outside facts | Invented events |
| Schema validation | Queries checked against real mappings before execution | Invented fields or indices |
| Query ledger | Every query gets an ID; the report must reference query IDs | Unsupported or untraceable claims |
| Citation rule | Every factual sentence carries `[q:ID]` and/or `[doc:ID]` tags | Uncited statements |
| **Code verifier** (not LLM) | Re-fetches each cited doc and checks that the stated values (IP, user, count, time) match; re-runs counts | Wrong numbers, wrong entities, fabricated IDs |
| Deterministic verdict | Verdict computed from evidence thresholds | LLM over-confidence |
| Repair loop | Failed claims go back to the writer once; anything still failing is removed and listed as "unverified" | Residual hallucination |
| Metric | Report shows **% of claims verified** and a count of removed claims | Gives a measurable number for the report |

**Wow:** every claim in the report links to the exact event in Kibana.

---

## 8. Experiment: run the same hunt twice

- **Run A (baseline):** default settings (temperature 0.7, free-form planning).
- **Run B (repeat):** same hypothesis, same settings → compare with Run A.
- **Fix:** temperature 0, fixed seed, fixed plan template, rule-based verdict, sorted query results.
- **Runs C & D:** with the fixes → compare again.
- **Compare:** verdict match, overlap between the two runs' query sets and evidence sets (Jaccard score), claim count, % of claims verified, run time.
- Done for all 3 hypotheses → a table and chart for the report.

---

## 9. Tiers and 2-week schedule

### Tier 1: Requirements (must finish)

- ELK + 5 log types via all 3 modes
- Agent 1 with example library + simulate loop, plus the held-out evaluation
- MCP server with core tools + query ledger
- Agent 2 with fixed plan, rule-based verdict, citations + code verifier
- Streamlit chat + report export
- Two-run experiment for all 3 hypotheses

### Tier 2: Wow factor (in priority order)

1. Clickable Kibana evidence links in reports
2. % verified claims + "unverified" panel shown live in the UI
3. Auto-generated Kibana dashboard for each hunt
4. ATT&CK technique mapping + coverage heatmap
5. `timeline` / `rare_values` pivot tools and adaptive follow-up questions in chat
6. QLoRA fine-tuned Agent 1 vs. base comparison

### Build split

| Owner | Scope |
|---|---|
| **Teammate** (VM/laptop) | **Log sources → ELK**: ELK in Docker Compose (Elastic 8.15.3), Logstash pull/push/stream, **all test-case datasets** (TC1 SSH from lab VM, TC2 web, TC3 firewall/C2) as raw logs + separate labels file, Kibana dashboards |
| **Cigmy** (desktop) | **Everything AI**: Ollama/qwen, **MCP server** (tools, per-agent allowlists, query ledger, field validation), Schema agent, Hunt agent, claim checker, Streamlit UI, experiments, demo |
| **Shared** | Data spec (index names, ECS field names, labels format). Final system runs on the desktop: teammate's Compose (ELK + Logstash) + our containers (MCP, agents, UI). `.env` for endpoints |

### Desktop setup checklist (Cigmy, Days 1–3)

- [x] Specs: Ryzen 7 7800X3D, Win 11 25H2, RTX 4070 Super, 32 GB; F: SSD 114 GB free
- [x] WSL2 Ubuntu 24.04 on F: + `.wslconfig` (memory=18GB, NAT networking, max_map_count)
- [x] Docker Engine inside Ubuntu; `hello-world` OK
- [x] Ollama inside Ubuntu, 100% GPU, llama3.1:8b = 83.7 tok/s
- [x] Container → Ollama test (`host.docker.internal` via host-gateway)
- [x] Pull qwen3:14b (9.7 GB, 100% GPU) + qwen2.5:14b
- [ ] Dev Elasticsearch sandbox up (`dev/docker-compose.dev.yml`) — temporary, until teammate's stack is ready
- [ ] Run benchmark → pick a model (22 Oct)
- [ ] Run teammate's Compose stack; Kibana opens at http://localhost:5601

### 2-DAY SPRINT (decided 23 Oct) — core scope only

**In scope:** R1–R6, A1 guardrails, A2 run-twice, demo. **Cut:** model benchmark, Kibana auto-dashboards, ATT&CK heatmap, extra pivot tools, polished UI.
**Hunts (v3 data):** ① SSH brute force (T1110) ② web path probing (T1595.003) ③ **firewall port probing (T1046)** ④ negative control: destructive sudo → expect NOT FOUND. Independent scenarios (teammate: not one linked timeline).
**Scenario:** each log category is an independent controlled lab scenario; shared NAT IPs within a category mean hunts rely on *behaviour*, not IP reputation (state honestly in report).

| Sprint day | Step | Status |
|---|---|---|
| Day 1 | 1. ES 8.19.23 + `data/load_v2.py` (teammate v3 → `sentinelhunt-events-v3`, labels kept out) | ✅ |
| Day 1 | 2. Agent 1 on teammate raw lines: split formats + field-level accuracy vs `parsing-reference.ndjson` | ⬜ |
| Day 1 | 3. **Agent 2** (`agent2/hunt_agent.py`): plan → coverage → MCP queries → rule verdict → claims → **code claim checker** → **report** (md + json) | ✅ v1.1, 9/9 |
| Day 2 | 4. Run-twice experiment harness + table | ✅ 9/9 verdict agreement both configs |
| Day 2 | 5. R2 flow: file → logs-unparsed → Agent 1 → reprocess → searchable | ⬜ |
| Day 2 | 6. 3rd log type: ✅ firewall arrived in v3; playbook written; Agent 1 must split 3 formats | ◐ |
| Day 2 | 7. Streamlit page: hypothesis → report + **PDF download** | ⬜ |
| Day 2 | 8. Record demo | ⬜ |

Team in parallel: report draft from PROJECT.md material; timesheet; confirm with prof whether SSH + sudo count as 2 log types.

### Progress log

| Date | Done | Notes for report ("challenges") |
|---|---|---|
| 20 Oct | WSL2 Ubuntu on F:, Docker Engine in WSL, Ollama in WSL | Two reboots needed; Ollama installer needed `zstd` |
| 21 Oct | Models pulled; GPU verified (llama3.1:8b 83.7 tok/s; qwen3:14b 100% GPU, 9.7 GB); container→Ollama OK; Agent 1 v1 + dev ES + Loghub fetch script written | `networkingMode=mirrored` stalled large downloads → switched to NAT; qwen3 "thinking" made answers 10× slower → disabled via API (`think:false`) |
| 22 Oct | **Agent 1 v1 eval (qwen3:14b, Loghub, unseen formats): 3/5 automatic** — Apache 3 attempts, HDFS 1, Linux 2 (all 100% full-file parse, 3–10 s each); OpenSSH + Zookeeper → needs_human. Agent 1 v2 written | (1) HDFS parsed 100% but month/year swapped → *parsing ≠ correct meaning*; added timestamp semantic check (date parse + plausible range/span). (2) Zookeeper failed on a double space ("INFO  [") and the model repeated the same pattern 3× at temp 0 → added piece-by-piece diagnosis + repeat guard. (3) OpenSSH pattern was fine but rejected by an over-strict GREEDYDATA rule → made it a warning |
| 22 Oct | **Agent 1 v2 eval: 2/5** (OpenSSH, Linux ✓; Apache, HDFS, Zookeeper ✗). Agent 1 v3 written | Asking the 14B model to write grok **and** date formats made it worse; it also ignored a precise diagnosis and returned the identical pattern 3× even at temp 0.6. → v3 splits jobs: LLM = best-of-3 grok only; code = whitespace auto-repair + deterministic timestamp detection (narrowest-span rule fixes HDFS yyMMdd) |
| 22 Oct | **Agent 1 v3 eval: 4/5** (Apache, Linux, OpenSSH, Zookeeper ✓, 100% full-file parse, correct dates; 9–19 s each). HDFS ✗ (22%). v3.1 written | Best-of-3 mattered (Zookeeper candidates 100%/99%/1%); diagnosis+retry fixed Apache and Linux in round 2. HDFS: model can't split the compact date → v3.1 gives the code-detected timestamp to the LLM as a fixed prefix |
| 22 Oct | v3.1 3/5, v3.2 3/5, **v3.3 4/5 (frozen)**: HDFS/Linux/OpenSSH/Zookeeper ✓ with correct dates; Apache near-miss (99% parse, 2.5 fields/line) | Each strategy helped some logs and hurt others → ensemble. One run hung on a runaway LLM generation → added 1024-token cap + 90 s timeout. Run-to-run variance (3/5 vs 4/5) → report mean of 3 runs |
| 22 Oct | **Agent 1 v3.3 run B: 5/5** (all 100% full-file parse, correct dates, 7–21 s per source; HDFS via *stripped*, rest via *full*) → mean 4.5/5 over 2 runs | Ensemble justified: each strategy uniquely solved a source. A stuck round can take up to 4×90 s before timing out |
| 23 Oct | Teammate: ELK + Kibana + pull ingestion working on his VM (6-event synthetic smoke test); sent auth-pilot-v1 (20 normalized SSH events, labels separate). Ownership clarified: **MCP server is ours** (AI side). Pilot classifier script written | Smoke data has `label`/`scenario` inside the index (would let the hunt agent read the answer) and non-ECS names → data spec needed. Pilot strips users/IPs/raw text → integration test only |
| 23 Oct | **MCP server v1 written** (`mcp_server/`): roles schema/hunt with server-enforced allowlists, field validation, query ledger, result caps; `demo_flow.py` runs raw OpenSSH → logs-unparsed → Agent 1 template registered via MCP → reprocess → hunt search/aggregate. Passed against mock ES; real run pending | Covers R5 (tools) and the R2 hand-off (Agent 1 → register → reprocess). Lucene query_string chosen over KQL (KQL is Kibana-only) |
| 23 Oct | **Auth pilot integration test passed** (qwen3:14b): capture-001 benign ✓, capture-002 suspicious ✓, 3/3 consistent each, 0 invented event IDs, 3–10 s per capture. Requested from teammate: raw unstructured logs, bigger set, 2 more log types, ELK version + index/field names | 2 captures = integration only, not accuracy. Citation check is a first instance of the hallucination guardrail |
| 23 Oct | Teammate reply: ELK **8.19.23**; next package = larger dataset, **raw + structured + separate labels**, consistent pseudonyms; log types SSH auth, sudo, web access; schema/index details to follow. We asked for a **firewall (UFW) log** as 3rd distinct type (SSH + sudo share auth.log) and an ETA. MCP `INDEX_PATTERN` now includes `sentinelhunt-*` | Risk: sudo + SSH may count as one log type and leave hypothesis ③ (C2) without network data |
| 23 Oct | Teammate **v2 dataset**: 345 raw lines / 35 sessions (SSH 100, sudo 45, web 200), ECS parsing reference, separate labels (20 benign / 15 suspicious). Wrote `data/load_v2.py` and **Agent 2 v1** (playbooks, rule verdict, claim checker, md/json report). Claim checker unit test: 5/5 fabricated claim types caught | All traffic from one Docker NAT IP per log type → scenario = compromised internal workstation, hunt on behaviour. Raw file mixes 2 formats → Agent 1 needs a split-by-layout step |
| 23 Oct | Teammate **v3 dataset verified** (all sha256 OK, 545 raw = 545 reference, no label words in raw): authentication 145 (SSH 100 + sudo 45), web 200, **firewall 200 (NFLOG, UDP)**; 55 sessions (30 benign / 25 suspicious). Loader → `sentinelhunt-events-v3`; Agent 2 gets `port_probing` playbook (T1046). R4 now 3 categories / 3 raw formats | Firewall: benign sessions also have drops (to one port) → rule uses *distinct* dropped ports (probing = 9 ports, benign = 1). IPs differ per category (192.0.2.1 auth, .2 web, .3 firewall loopback) and scenarios are independent → **report 4 independent hunts, not one compromised-machine timeline** |
| 23 Oct | **Agent 2 v1 real run (qwen3:14b, v3 data): 4/4 correct** — SSH brute force CONFIRMED (45 failures from 192.0.2.1), web probing CONFIRMED (110 4xx, 11 paths), port probing CONFIRMED (9 distinct dropped ports), destructive sudo NOT FOUND; **100% claims verified** each, 7–20 s per hunt | First end-to-end hunts through MCP; every claim cites ledger query ids |
| 23 Oct | **Curveball tests (v1): only 1/5 handled well** — ransomware → picked sudo playbook → misleading NOT FOUND; fake IP 10.66.66.66 → CONFIRMED (answered a different question); "user_001 brute-forced SSH" → CONFIRMED (innocent user blamed); prompt injection → INCONCLUSIVE ✓; vague → checked only web. **Agent 2 v1.1:** planner states *fit* (exact/partial/none) + missing data → partial fit = INCONCLUSIVE with related findings; named IP/user must exist and narrows the hunt, absent → NOT FOUND + related finding; vague → sweep all playbooks; SSH success check now only for the *targeted* user after the first failure | Key lesson: the claim checker stops invented *facts*, but the verdict must answer *this hypothesis*, not "is there any attack of this type". Claim checker verifies facts, not interpretation (e.g. normal user_001 logins via same NAT IP) |
| 23 Oct | **Agent 2 v1.1 suite: 9/9 correct** (4 test cases + 5 curveballs), 100% claims verified on all; ransomware → INCONCLUSIVE with missing-data list; fake IP → NOT FOUND + related finding; innocent user_001 → NOT FOUND; injection → INCONCLUSIVE; vague → sweep (3 CONFIRMED, sudo NOT FOUND, 18 queries, 32 s). Run-twice harness `experiments/run_twice.py` written (baseline T=0.7 random seed vs converged T=0 seed 42) | Curveballs 1/5 → 5/5 after v1.1. PDF export of reports planned with Streamlit (Day 2) |
| 23 Oct | **A2 run-twice experiment** (9 hypotheses × 2 runs × 2 configs = 36 hunts): verdict agreement **9/9 in both** baseline (T=0.7, random seed) and converged (T=0, seed 42); playbook 9/9 and query Jaccard 1.00 in both; evidence Jaccard 0.81 → 0.89; claim-text similarity **0.42 → 0.83** (`experiments/run_twice_20261023-210034.md`) | Decisions converge by **design** (fixed playbooks, rule verdict, deterministic queries), not by temperature. T=0 + seed halves wording variation but is **not deterministic** (converged TC1 evidence J=0.0, CB5 text 0.29; GPU numerics). Next convergence step: code selects cited evidence docs |
| 23 Oct | **Time curveballs (v1.1) failed both**: 'slower than normal around 17:05 22 Oct' → sweep CONFIRMED; 'around 03:00 21 Oct' (no data exists that day) → CONFIRMED from another day. **Agent 2 v1.2:** planner extracts time window (ISO, validated by code, ±15 min around a point), applied to every query; empty window → INCONCLUSIVE 'no log data'; non-security symptoms (slowness) → sweep with partial fit → INCONCLUSIVE + related security findings in that window; key evidence events now chosen by code (deterministic). Experiment suite extended to 11 hypotheses | Time scoping was missing entirely; the agent answered 'is there any attack' instead of 'what happened then' |
| 23 Oct | **v1.2 time curveballs: 2/2** — 'slow ~17:05 22 Oct' → INCONCLUSIVE (needs CPU/memory/IO/latency) + related in-window findings: SSH brute force + web probing CONFIRMED, port probing NOT FOUND (firewall data is 23 Oct → window applied); 'slow ~03:00 21 Oct' → INCONCLUSIVE, no log data in window. Fixed: single-entry query log dropped from report ('0 queries') | Curveballs overall 7/7 after fixes |
| 23 Oct | **Agent 2 v1.3 = option A: AI follow-up investigation.** After the playbook, qwen proposes ≤3 follow-up queries of its own (sees field list + results); code caps/validates, MCP rejects unknown fields and runs them read-only within the time window; results are logged with query_ids and citable; **verdict unchanged** | Answers the 'does the agent really plan/query?' critique while keeping the rule-based verdict. Expect run-twice query Jaccard < 1.0 in baseline now (AI queries vary) |
| 23 Oct | **False-positive time tests (v1.3): 3/4** — SSH 17:06:00–17:07:00 NOT FOUND ✓ (25 sshd events, 0 failures); SSH ~11:39 23 Oct NOT FOUND ✓; port scan ~17:05 22 Oct NOT FOUND ✓; **web probing 'between 17:06 and 17:10' → CONFIRMED ✗ false positive**: qwen read the range as ~17:05 ±15 min (16:50–17:20), which included the real probing at 17:01–17:02. **v1.4:** time windows parsed by code (regex for 'between X and Y', 'from X to Y', 'X-Y', 'around/at X', 3 date styles); LLM window only as fallback; disagreements recorded in the report | Same lesson as Agent 1 timestamps: precise parsing belongs in code, not the LLM. Rule was right; the input to the rule was wrong |
| 23 Oct | **v1.4 time tests: 9/9 verdicts correct** (8 NOT FOUND incl. former false positive 'web 17:06–17:10'; positive control CONFIRMED). 2 runs crashed AFTER the verdict: qwen's follow-up JSON was cut off at 600 tokens. qwen also wrote SQL-style time filters (`@timestamp >= '...'`) → rejected by ES (guardrail held). **v1.5:** invalid/truncated JSON → one retry with 2× tokens, then fail-safe (planner → unsupported/INCONCLUSIVE; follow-ups skipped + noted; writer → summary-unavailable); investigator told the window is automatic; entity message says 'within the selected time window' | Robustness: an optional AI step must never crash a hunt. Rejected AI queries are evidence the MCP validation works |
| 23 Oct | **v1.5 time tests: 9/9 verdicts correct, 0 crashes**, 100% claims verified on all 9 (8 NOT FOUND incl. 'wrong thing, right time' cases: port scan / destructive sudo / user_001 at 17:07–17:11 → NOT FOUND, user_001 with related SSH brute force CONFIRMED; positive control SSH 17:07–17:09 CONFIRMED). Fail-safe fired twice: follow-up JSON failed twice → step skipped, hunt still finished (~100 s instead of ~40 s). One follow-up still rejected for an `@timestamp:[..]` clause. **v1.6:** code strips LLM time clauses from follow-up queries (window is applied by code anyway; original kept in report JSON); skip reason now printed | Prompt rules are suggestions; code enforces. Same pattern as v1.4 time parsing |
| 23 Oct | **Teammate review → v1.7–v1.9.** v1.7: follow-up schema maxLength/maxItems (runaway query strings truncated JSON) → follow-ups run again, hunts 25–37 s instead of ~100 s; plain-English result box. v1.8: summary must mention CONFIRMED related findings (code appends them if the LLM omits them). v1.9: **SSH counted log records, not attempts**: each password attempt writes 4 failure records (invalid user, PAM unknown user, PAM auth failure, Failed password) → report said 45, real = **15 attempts**; playbook now counts `event.action:ssh_authentication` (fallback: message "Failed password") and lists the other record types as context; login-success check states its exact search window; verdict meaning shown as 'detection criteria matched' (controlled lab data, not proof of a real attack); rules worded as 'criteria: …'. Web probing verified in raw data: 110 4xx from 192.0.2.2 17:01:34–17:02:05, 100 on 10 sensitive paths (suspicious captures) + 10 benign /missing-page 404s | Unit of counting matters: records ≠ events ≠ attempts. Shared NAT IP means benign 404s are counted with the probe (110 vs 100) |
| 23 Oct | **v1.10–v1.11.** Verdict label CONFIRMED → **DETECTION CRITERIA MATCHED** (lab data; not proof of a real attack); summary told not to call matches proven attacks; focus line shows absent entities; bare-word AI queries rejected; MCP accepts `_exists_:field` (validates the named field). **Invented field values:** AI queried values that do not exist (`event.action:authentication`, `event.action:file.*`) → 0 hits → summary claimed 'no encryption events detected'. v1.11: code fetches the real values of categorical fields in scope via MCP (terms aggs, logged), gives them to the AI, and **rejects follow-ups using values not present** | Field-name validation is not enough: values can be hallucinated too. A query on a non-existent value returns 0 and looks like evidence of absence |

---

## 10. Deliverables checklist

**Report: `Group<x>_SE6014ProjectReport.pdf`**

- [ ] Cover (Q1, names, matriculation numbers) · ToC
- [ ] Executive summary (non-technical: what it does, what it proved, what it can't do yet)
- [ ] System architecture (components, data flow, agent tools, decision logic)
- [ ] Setup documentation + challenges faced + repository URL
- [ ] Agentic workflow design (completeness, accuracy, guardrails)
- [ ] Experiment results (two-run comparison, differences, what made the runs agree)
- [ ] Conclusion (next steps, limitations)
- [ ] Appendix: timesheet + work breakdown per member
- [ ] Appendix: MCP tool list, prompts, example hunt report, references (MCP SDK, datasets, models)

**Pitch: `Group<x>_Pitch.pdf`** (no spaces in file names; PDF slides must still make sense without animations)

- [ ] 5-min recorded demo (label sped-up parts; keep the raw recording)
- [ ] 5-min shark-tank pitch (local/private AI angle: "your logs never leave your network")

**Demo script (~5 min):** Kibana showing the 5 log types and 3 ingest modes → Agent 1 schemas an unknown log live → Agent 2 runs a hypothesis in chat → report with verdict, % verified claims, click-through to raw evidence.

---

## 11. Open items (need input / confirmation)

| # | Item | Owner | Due |
|---|---|---|---|
| O1 | Group number + member names and matriculation numbers | Team | Day 3 |
| O2 | Exact submission and demo date | Cigmy | **ASAP** |
| O3 | Course policy on AI-assisted coding and how to disclose it | Cigmy | Day 1 |
| O4 | **Dataset check:** confirm public datasets actually contain (a) brute-force/spray, (b) web scanning/SQLi, (c) C2 beaconing or lateral movement. If one is missing, inject documented synthetic attack events into benign data with a generator script (stated openly in the report) | Teammate | 22 Oct |
| O5 | QLoRA stretch goal: go/no-go | Cigmy | Day 8 |
| O6 | Who on the team owns which report sections and pitch roles (for the timesheet) | Team | Day 2 |
| O7 | Repository hosting (GitHub public/private?) | Cigmy | Day 2 |
| O8 | ~~Desktop specs~~ ✅ done | Cigmy | Day 1 |
| O9 | Model choice from benchmark | Cigmy | 22 Oct |
| O10 | ~~ELK version~~ ✅ teammate on **8.19.23**; our dev ES switched to match | — | 23 Oct |


**Time claims, full fix (v1.16).** Scan of all 16 runs: the model reads per-minute bucket keys as event times (TC1 run 2 in BOTH settings "17:07:00–17:08:00"; baseline TC1 run 1 "4 at 17:07:00, 11 at 17:08:00"; converged TC3 "at 11:39:00" vs 11:39:22–11:39:55; TC2 minute-level ranges OK). v1.15 only caught full-timestamp "between A and B". Now:
- `time_problems()` in the checker: every time in a claim (ISO, HH:MM:SS, HH:MM) at its written precision; a range must equal first/last of a cited result (minute precision: same minute; second precision: same second); a single time must lie inside first..last; a time citing no result with event times is rejected (cannot be checked). 12/12 offline cases OK.
- search tool also returns first_event/last_event (of ALL matches).
- writer + repair prompts: copy first_event/last_event for "when"; bucket keys are interval labels ("in the 17:07 minute"), never event times.
- experiments/replay_time_claims.py: re-runs each saved time claim's cited queries (saved args, frozen data) and puts it through the current checker. Then a fresh run_twice --suite --quick in a new folder (originals untouched).
Known: summaries are still not checked (only claims).Results: replay_time_claims_20261024-192313: 5 of 9 original time claims rejected (exactly the 5 wrong ones), 4 TC2 minute-level kept. run_twice_20261024-192357 (v1.16, data unchanged): every kept time claim correct (checked against the reference: TC1 4/11 per minute, TC2 17:01:34–17:02:05, TC3 11:39:22–11:39:55, TC4 sudo 17:10:16–17:10:26); summaries' times also correct (not code-checked); new mistake "17:39:22–17:39:56" (wrong hour, baseline TC3 r1) rejected and rewritten correctly. 50 kept / 4 rewritten / 2 removed. Verdict 4/4, evidence J 1.00 both; query J 0.68 / 0.87; claim similarity 0.28 / 0.69. Package SE6014_repeatability.zip updated (postfix/: patch, replay, new run, regression; 169 files).

**Demo rehearsal, new format (bastion-02, classic syslog `Oct 24 09:15:46 bastion-02 sshd[7200]: …`):** batch 1 (23 lines) → 23 indexed, 0 failed, 41 s, but (1) outcome "matched logs-linux" = an old dev-era header template in the local registry cache, so only stages C/D/E were new; (2) process.name = "sshd[7200]" (pid not split) → SSH playbook (process.name:sshd) would find nothing. Fix (code): process.name type "program" (no [pid]/colon, output check rejects), split_program() normalises the simulated docs before stage E, and SPLIT_PROG grok+convert in every built pipeline → process.name + process.pid. Next: remove feed + retire logs-linux, then rerun so Agent 1 creates the template from scratch.
Rehearsal 2 (after cleanup, registry = 3 v3 templates only): outcome **generated** (logs-bastion-02-auth-layout1), process.name sshd + pid split OK, but every record event.action=other: the AI's line pattern (3 rounds) split whole lines into module/action/sub_action/logname with NO message part, so stage C never ran and stage E had no message text (0 rules kept). Fix (code): `header_cut()` — if the line pattern has no trailing GREEDYDATA, keep the leading pieces that only capture header fields (time, host, program, pid, level) and make the rest `message_body`; accepted only if every line still parses with a non-empty body; then C/D/E run as usual.
Rehearsal 3: stage A failed all 3 rounds (33/67/67%) → needs_human (round 3 success last time was luck). Root cause: the 14B model must describe the WHOLE line in one pattern. Fix: `header_cut()` moved to schema_agent as a stage A auto-repair, tried on every candidate after whitespace/relax: keep the leading header pieces (time, host, program, pid, level…), rest = `%{GREEDYDATA:message_body}`, validated on the held-out lines like any pattern; messages are then parsed by stage C per message type. stages_v4 reuses sa.header_cut.
Rehearsal 4 (create + reuse + hunt): create OK (logs-bastion-02-auth-layout1, event counts exact), reuse OK (33/33, 2.1 s, no LLM), hunt: CRITERIA MATCHED 203.0.113.45, 14 failed passwords on deploy, BUT successful login = 0 although batch 2 has "Accepted password for deploy from 203.0.113.45": the template learned "Accepted publickey" (batch 1) only, so the reused pipeline parsed the new message type's header but not its message. Fixes: (1) Agent 1 records the message types it learned (`message_groups`); on reuse `unseen_message_types()` compares the new lines; if new types appear it logs it and rebuilds C/D/E on all lines (header reused), parser column "extended (new message types)"; templates without recorded types are left as they are (v3 frozen). (2) Checker: a claimed range equal to a cited query's search window (time_from/time_to) is allowed ("nothing found between A and B" is about where it looked); the TC1 wrong range is still rejected.
Rehearsal 5 (final, clean): create 42.5 s exact counts → batch 2 stream: reused + 'Accepted password for' detected as new → extended, counts exact (14/14, 2 successes) → third pass pure reuse 2.1 s → hunt: CRITERIA MATCHED, 203.0.113.45, 14 failed passwords, successful login of deploy: 1, 3/3 claims verified. Evidence in Downloads/SE6014_Demo_Readiness/results/. One AI follow-up mixed AND/OR without brackets (searched something else, 0 events, uncited). Fix (code): `bracket_or_runs()` groups each run of OR-joined terms in brackets before an AI follow-up runs ('A AND B AND x OR y' → 'A AND B AND (x OR y)'); quotes, (), [a TO b] respected; original kept as original_query.

**Teammate review before recording (25 Oct):** (1) hunt queries must filter by the named host → Agent 2 host scope: code finds a host name from the data (terms host.name) in the hypothesis text (exact token), planner `focus_host` validated as fallback; `Tools.scope` ANDs `host.name:"…"` into every search/aggregate (like the window; whole-dataset value lists unscoped); shown as "[scope]" log line, Focus and Searched. Offline tests OK. (2) query grouping fix already in frozen code; final run saves report + ledger. (3) pull live: new batch 3 (3 lines, normal login 09:41, same message types) → final run = batch 1 PULL (create), batch 2 STREAM (extend), batch 3 PUSH (pure reuse). (4) ASSUMPTIONS_syslog_timestamps.md: no year/timezone in syslog → year of processing + UTC (date processor default). (5) wording: preservation checker ≠ parsing accuracy; field agreement (compare_hunt_vs_reference.py) reported separately, as agreement with the reference labels.

**Demo app ingest log (25 Oct):** page 1 now shows what really runs (Pull: manage.publish() writes one .ndjson into runtime/inbox, watched by Logstash file input `folder_pull`; Push/Stream: the exact kit `ship.py` command), the full transport output, and the newest inbox files. Batch 1 also saved as demo/sample_logs/demo-bastion-batch1.ndjson (same record ids) for a manual drop.

## TODO after the demo (26 Oct)
- [ ] ONE markdown file that answers every report question: what we built and how (architecture, Agent 1 stages, Agent 2 playbooks/checker, MCP server, ingest channels, guardrails), the experiment (run twice, baseline vs converged), the reviewer's time-claim finding and fix, rehearsal findings and fixes, limits, versions/hashes. Source: this PROJECT.md + results folders. Check against the assignment's report questions.
- [ ] After recording: freeze_versions.py again, copy recording hunt report + ledger into results, rebuild zip.
- [ ] GitHub repo (no secrets, README, .gitignore) Tue–Wed; report + pitch PDFs due 6 Nov.

**Recording take 1 (25 Oct 18:55) → user.name bug found in the export:** session_opened lines `session opened for user user_003(uid=1003) by (uid=0)` gave user.name `user_003(uid=1003` on 3 records. Cause (code, not the AI): the template builder (split_value) handled `name(uid=N)` only when the value was the same on every line; with different users the common suffix was just ")", so the slot swallowed "(uid=1003". The type check for user fields only rejected empty/numeric values, so nothing caught it (the checker checks preservation, not values). Fix: (1) split_value also splits varying `name(uid=N)` into slot + literal (digits generalised); (2) type_ok for user fields rejects brackets, '=' and spaces, so any pattern that captures them is refused and retried. Offline test: user_003 / deploy. Take 1 kept as evidence; re-record after the fix.
Practice run after the fix (hunt-20261025-193923-876), checked with scripts/verify_demo_run.py (answer key built from the sample files by fixed regexes): 24/25 PASS. user.name now correct on all 36. New FAIL: log.category 'other' on all 36 (take 1 had 'authentication'). Cause: log.category was the AI's single answer in stage E; an answer outside the vocabulary fell back to 'other' for the whole feed. Fix: code decides log.category from the event types the rules give (ACTION_CATEGORY: ssh/pam/session/sudo -> authentication, http_request -> web_access, network_* -> firewall); the AI's answer is only the fallback, a disagreement is logged as 'corrected'. Not frozen; rerun.
Confirmed from the step snapshots (reports/agent1_steps): generation (pull batch) stage E log.category=authentication; the EXTEND step re-runs stage E on all 33 lines and its answer became 'other' ("6 rules kept, 1 rejected"). So the category was correct at generation and overwritten by the extend. Event rules were correct in both. The code-decided category fixes both steps.
Practice run 2 (hunt-20261025-194814-073): Agent 1 fully clean (every value of all 36 records = answer key). Agent 2: 1 of 18 ledger queries ended in an Elasticsearch parse error. Cause: the follow-up JSON schema capped the AI's query at maxLength 250 (set earlier to stop runaway strings); the model wrote a time clause anyway (it is told not to; code strips it), ran past 250 and was cut at '... @timestamp <= "2026-10-24T09:25:00.'; strip_time_clauses then removed the broken time terms and left a dangling 'AND ('. Fixes: (1) maxLength 500; (2) syntax_problem(): code checks brackets, quotes and dangling operators BEFORE an AI query is sent -> 'rejected: incomplete query; nothing run'; (3) the silent [:300] cut of AI queries removed (over 600 chars -> rejected openly). Verdict/claims were not affected.
Verified run hunt-20261025-200312-688 (25/25, frozen) is the recorded demo video. Results: SE6014_checklist_results/VERIFIED_RUN/.
