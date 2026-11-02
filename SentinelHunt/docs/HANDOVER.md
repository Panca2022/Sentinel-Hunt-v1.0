# Handover: AI side of SentinelHunt (Agent 1, Agent 2, MCP server, demo app)

From: Cigmy (Chonnawee Udompongpipat). Date: 26 Oct 2026.
The run this handover describes is the recorded and verified demo run: hunt `hunt-20261025-200312-688`, 25/25 checks,
frozen in `docs/VERSION_MANIFEST.json`. Sections 1–9 follow the handover request; section 10 explains the design decisions.
Where something is already documented, this file points to it.

---

## 1. Source code / repository

- **Folder:** `SE6014_repo` (zip: `SE6014_repo.zip`). Push it to the team's GitHub as is; `.gitignore` is included.
- **Matches the manifest:** `python3 scripts/verify_manifest.py --code-only` reports 26/26 project files and 7/7 kit
  files identical to the freeze of the recorded run.
- **No secrets.** The code reads credentials only from the kit's `runtime/*.env` at run time (inside the MCP server),
  and `.gitignore` excludes `runtime/`, `*.env`, `*.crt` and `*.key`. A search of the repo found no passwords, tokens or keys.
  Some hashed files contain local example paths (`/mnt/c/Users/ckung/...`). They can't be edited without breaking the
  manifest hashes; they are paths, not secrets.
- **Not in the repo:** the ELK kit, the v3 dataset, run outputs. Evidence lives in the results package
  `SE6014_checklist_results` (the recorded run is in `VERIFIED_RUN/`).
- Repo overview: `README.md`.

## 2. Rebuild / start / stop

All in **`docs/REBUILD.md`**: the version table (what must match), prerequisites, venv + `requirements.txt`, model
setup (`ollama pull qwen3:14b`, digest check), kit start, dataset staging, template restore, the checks, and how to
launch the demo app. Additions not in that file:

- **Configuration:** one environment variable, `SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable`. The
  MCP server reads the Elasticsearch URL, CA certificate and the agent1/agent2 credentials from the kit's
  `runtime/` folder. Nothing else needs configuring.
- **Start after a reboot (demo machine):**
  1. `sudo sysctl -w vm.max_map_count=1048576`
  2. In the kit folder: `python3 scripts/manage.py start` (wait for the PASS lines)
  3. `ollama list` (shows qwen3:14b `bdbd181c33f2`)
  4. In the repo: `export SENTINELHUNT_KIT=...` then `.venv/bin/streamlit run demo/app.py`, and open http://localhost:8501
- **Checks:**
  - `python3 scripts/verify_manifest.py` (versions, templates, v3 fingerprint)
  - after a demo run, `bash scripts/finish_run.sh <name>` (25 strict checks; freezes only if all pass)
- **Shutdown:**
  1. Ctrl+C in the app terminal (or `pkill -f "streamlit run"`; check with `pgrep -fa streamlit`)
  2. In the kit folder: `python3 scripts/manage.py stop` (keeps data and credentials)
  3. Ollama can keep running, or stop it with `pkill ollama`

## 3. Architecture (short)

| Component | Job |
|---|---|
| **Logstash** (kit) | Receives raw log lines three ways: **pull** (watches `runtime/inbox/*.ndjson`), **push** (authenticated HTTP :18088), **stream** (TCP :15514). It stamps each record with `ingestion_channel`, `received_at`, `feed_name` and `record_id`, and writes it to the raw staging index `sentinelhunt-raw-v1`. No parsing. |
| **Elasticsearch** (kit) | Stores raw staging, the parsed **hunt index** `sentinelhunt-hunt-v1` (strict mapping), and the template **registry** `sentinelhunt-schema-v1`. Runs the ingest pipelines Agent 1 registers. |
| **Kibana** (kit) | For people only: browse raw and parsed records (Discover). The agents don't use it. |
| **MCP server** (`mcp_server/server.py`) | The only way the agents reach Elasticsearch. One server process per role, each role with its own tool allowlist and its own kit account: Agent 1 uses the agent1 account (read raw, write hunt/registry); Agent 2 uses the read-only agent2 account. Credentials never reach the model. Validates fields and logs every query to a ledger. |
| **Agent 1** (`agent1/`) | Turns a feed of unknown raw lines into parsed records: builds or reuses an ingest pipeline (template), registers it, reindexes the feed into the hunt index. |
| **Agent 2** (`agent2/hunt_agent.py`) | Takes a hypothesis, runs a playbook of queries via MCP, decides the verdict by code rule, and writes a report whose claims are checked by code. |
| **Ollama + qwen3:14b** | The local LLM both agents call (no cloud). |
| **Streamlit app** (`demo/app.py`) | Demo UI: page 1 ingest, 2 Agent 1, 3 Agent 2, 4 run twice. It holds no Elasticsearch credentials. |

**Data flow:**

1. Log file → (pull / push / stream) → Logstash → raw staging.
2. Agent 1 (via MCP `process_source`) reads raw staging and builds or reuses a template → registers the ingest
   pipeline + router `feed-<feed>` + registry entry → reindexes the feed through the router into the hunt index
   (`_id` = `record_id`).
3. Agent 2 (via MCP `search` / `aggregate`, read-only) queries the hunt index → report (.md / .json) + query ledger.

The diagram is in `README.md`.

## 4. Agent details

### 4.1 MCP tools (`mcp_server/server.py`, `ROLES`)

| Role (account) | Tool | Purpose |
|---|---|---|
| ingest (agent1) | `list_feeds` | Feeds waiting in raw staging, with counts |
| | `process_source(feed_name, fresh)` | Runs Agent 1 end to end on one feed |
| schema (agent1) | `sample_unparsed` | Raw lines not parsed yet |
| | `list_templates` | Registered templates |
| | `simulate_pipeline` | Tests a pattern with Elasticsearch `_simulate` on sample lines |
| | `register_template` | Stores an ingest pipeline + registry entry |
| | `reprocess_unparsed` | Re-indexes lines through a template |
| hunt (agent2, read-only) | `list_indices`, `get_field_mappings` | What exists (grounds the model in real fields) |
| | `search` | Validated query → hits + doc ids + first/last event time |
| | `aggregate` | terms / date_histogram / cardinality / stats; reports events without the field and truncated buckets |
| | `get_document` | One record by id |
| | `get_query_log` | The ledger: every query of a hunt with its id, exact request and result summary |

Every hunt query is checked against the real field mappings first; unknown fields are rejected. The demo app uses the
ingest and hunt roles.

### 4.2 Agent 1: create, validate, extend, reuse

| Step | AI decides | Code decides / checks |
|---|---|---|
| Split the feed into layouts | – | groups lines by token shape |
| **Reuse?** | – | tries every registered template on the lines; ≥ 95% parse → **reuse** (no model call) |
| Timestamp | – | detects the format deterministically (narrowest plausible date span) |
| **Create**, stage A: line pattern | proposes grok patterns (best of 3–4 candidates, temperature 0 then 0.7) | validates on **held-out lines** with ES `_simulate` (≥ 95% parse, enough fields, no catch-all). Repairs: whitespace, stray anchors, over-strict types → NOTSPACE, **header cut** (keep the header, rest = message). Up to 3 rounds with a diagnosis of the failing piece; otherwise "needs human" |
| Stage C: message types | names the value slots of each message type (user.name, source.ip, …) | builds the template per message type by token alignment; rejects names not in the allowed list and values of the wrong type (IP, int, user name without brackets/`=`, program name) |
| Stage D: field names | maps leftover fields to allowed names | type check; obvious renames by name tokens |
| Stage E: event meaning | writes rules (field, op, value → event.action / outcome) from a fixed vocabulary | rejects actions/outcomes outside `vocabulary.json`, rules tied to one user/IP, rules matching nothing; orders rules most specific first; **log.category from the event types** |
| Register | – | pipeline `logs-<feed>-layoutN`, router `feed-<feed>`, registry entry incl. the message types it learned |
| **Extend** | stages C/D/E again on all lines | on reuse, code compares message types with those learned; a new type (e.g. "Accepted password for") → header reused, C/D/E rebuilt |
| Output check | – | 100% of lines processed, only hunt-index fields, types ok; `record_id` kept |

Details: `agent1/README.md`, `docs/DEVELOPMENT_LOG.md` (sections 6 and the 22–25 Oct entries).

### 4.3 Agent 2: playbook, follow-ups, verdict

| Step | AI decides | Code decides / checks |
|---|---|---|
| Plan | picks a playbook (ssh_bruteforce, web_probing, port_probing, destructive_sudo, sweep_all, unsupported) and how well it fits (exact / partial / none), plus the data that is missing | an unknown playbook → unsupported; fit "partial" → INCONCLUSIVE + related findings |
| Time window | fallback only | parsed by code from the hypothesis ("between 09:15 and 09:25", dates); applied to every query |
| Entities / host | suggests a focus IP / user / host | must exist in the data (else NOT FOUND + related finding); host name matched in the text by code and **ANDed into every evidence query once** |
| Playbook queries | – | fixed per playbook (code) |
| **Verdict** | – | **code rule** with thresholds, e.g. SSH: one source.ip with ≥ 5 failed password attempts (attempts counted on `ssh_authentication` records, not all failure records) + successful login of the targeted user after the first failure. Labels: DETECTION CRITERIA MATCHED / NOT FOUND / INCONCLUSIVE |
| Key evidence | – | chosen by code (first events by time) |
| Follow-ups | proposes ≤ 3 extra queries | rejected if incomplete (brackets/quotes/operators), bare words, `*` search, invented field values, or a repeat; time clauses stripped; OR-runs bracketed; run read-only; **verdict never changes** |
| Report text | writes summary + claims citing query ids | **claim checker**: numbers, IPs, users, times (at their precision) must match the cited results; "attempts" ≠ record types; no placeholders; a failed claim goes back once with the reason; still failing → removed and listed |

Details: `agent2/README.md`, `docs/DEVELOPMENT_LOG.md` (section 7 and the v1.1–v1.16 entries).

## 5. Demo instructions

Exact steps, files, feed, hypothesis and expected results: **`docs/REBUILD.md` §5**. In short:

- Files: `demo/sample_logs/log_pull.log` (23 lines), `log_stream.log` (10), `log_push.log` (3).
- Feed `bastion-02-auth`, source `bastion-02`. Check both before every Send; the app's default is `demo-feed`.
- Buttons:
  1. Page 1 Pull → Send (23)
  2. Page 2 tick "Build a new template" → Process source (generated)
  3. Page 1 Stream → Send (33)
  4. Page 2 Process source (extended)
  5. Page 1 Push → Send (36)
  6. Page 2 Process source (reused, ~2 s)
  7. Page 3 `Someone brute-forced SSH on bastion-02 on 24 Oct 2026 between 09:15 and 09:25` → Run hunt
- Expected: DETECTION CRITERIA MATCHED. 203.0.113.45 made 14 failed password attempts (09:15:48–09:22:39), then logged
  in successfully as `deploy` at 09:22:44.
- **Safe reset:** `.venv/bin/python scripts/remove_feed.py bastion-02-auth --yes`. It removes only that feed's raw +
  parsed records, its pipelines and its registry entry, and **refuses to touch `v3-mixed-pilot`** (the experiment
  data). Afterwards `verify_manifest.py` still shows the v3 fingerprint `6fd3ef8e…`. Also move old step snapshots
  aside: `mv reports/agent1_steps/* reports/_old_steps/`.
- After the run: `bash scripts/finish_run.sh <name>` → 25/25 and the evidence folder.
- Recording: 25 Oct, starts 19:59:54. Steps between 20:00:13 (pull) and 20:04:01 (hunt done) are mapped in
  `SE6014_checklist_results/VERIFIED_RUN/SUMMARY.md`.

## 6. Guardrails and limitations

**Guardrails (all code):**

- **MCP access:** least-privilege accounts per agent, read-only for hunting; unknown fields rejected; every query in the ledger.
- **Claim checker:** every number, IP, user and time in a claim must match a cited query result. Times are checked at
  the precision written: a range must equal the first/last event, a single time must fall inside. Counts of "attempts"
  can't be record types. Placeholders are rejected. One rewrite with the reason, then removal (listed in the report).
  Recorded run: 1 claim rewritten.
- **Rejected queries:** incomplete syntax (never sent to ES), invented values (checked against the real values),
  bare words, unfiltered search, repeats. Recorded run: 2 rejected, 1 skipped.
- **Verdict and evidence by code:** the AI can't change the verdict.
- **Agent 1:** held-out validation, type checks, fixed vocabulary, code-ordered rules, code-decided category, output
  check, "needs human" when it fails.

**Timestamp assumption:** syslog has no year or timezone, so Elasticsearch uses the year of processing and UTC
(`docs/SYSLOG_TIMESTAMPS.md`, `docs/REBUILD.md` §6).

**Known gaps:**

- The AI **summary** is not checked by code (only claims). In the recorded run its times were right (checked by
  `verify_demo_run.py`).
- The `verify_demo_run.py` answer key covers the demo source only. For v3, field agreement was measured separately
  (545/545 against the team's parsing reference).
- Some AI follow-up queries are still cut at the 500-character limit; they are rejected, not run.
- The AI wording varies between runs even at temperature 0 + seed (GPU numerics).
- Four playbooks only; anything else → INCONCLUSIVE / unsupported.
- Timezone not configurable per feed yet. Syslog has whole seconds only.
- Lab data: one controlled scenario per log category; shared NAT IPs.

**What the system cannot claim:**

- that an attack really happened ("detection criteria matched" ≠ proof)
- that NOT FOUND means safe (only: these criteria not met in these logs and this window)
- full parsing accuracy: the teammate's checker tests preservation; agreement with the reference labels is measured
  separately and is not "100% accuracy"
- determinism of the AI text

## 7. Repeatability

- **Setup:** the same hypothesis run twice per setting, 4 test cases (TC1 SSH brute force, TC2 web probing, TC3 port
  probing, TC4 destructive sudo = negative) × 2 settings × 2 runs = 16 hunts, on the frozen v3 data (fingerprint
  checked before and after: unchanged).
- **Settings changed between the two configurations:**
  - **baseline** = temperature 0.7, random seed
  - **converged** = temperature 0, seed 42

  Everything else is identical: code, playbooks, data, model.
- **Consistent in every run:** verdict 4/4, playbook 4/4, key evidence Jaccard 1.00 (all decided by code).
- **Varied:**
  - AI follow-up queries (query Jaccard 0.80 baseline / 0.86 converged in the final pre-fix run)
  - claim wording (similarity ~0.5; noisy, give a range)
  - converged is closer, but still not identical
- **Files to cite** (`SE6014_repeatability` package):
  - top level (`baseline/`, `converged/`, `comparison.json` / `comparison.md`, fingerprints): the final run of the original
    experiment, `run_twice_20261024-161924` (Agent 2 v1.15), with side-by-side pages per case
  - `postfix/run_twice_20261024-192357/`: the rerun after the time-claim fix (v1.16): verdict 4/4, evidence J 1.00
    both; query J 0.68 / 0.87; claim similarity 0.28 / 0.69; every kept time claim correct
  - `postfix/fix_comparison.html`: before/after of every time claim
  - `README.md` and `VERIFY_TC1.md`: the reviewer's TC1 finding and the hash proof
- **Note for the report:** the experiment ran on Agent 2 v1.15/v1.16. The demo version adds host scope, the
  follow-up syntax check and the 500-character limit; the run-twice experiment was not repeated on it. The recorded
  demo run itself is verified separately (25/25).

## 8. Presenter Q&A

| Question | Short answer |
|---|---|
| Why a local model? | Logs can be sensitive; nothing leaves the machine. qwen3:14b fits a 12 GB GPU. |
| What stops hallucination? | The AI never decides: code picks the evidence and verdict and checks every claim against the query results; failed claims are rewritten once or removed, visibly. |
| Can the AI query anything it wants? | Only through MCP, read-only, real fields only, invented values rejected, every query logged with an id. |
| What does Agent 1 do that a regex can't? | It writes the parser for a format it has never seen; code validates it on held-out lines. A known format is reused with no AI call. |
| What if Agent 1 fails? | Code repairs first; after 3 rounds the source is marked "needs human". Nothing unvalidated is registered. |
| How do you know parsing is right? | Held-out validation while building; for the demo, every field of all 36 records against an answer key (`verify_demo_run.py`); for v3, 545/545 agreement with the team's reference labels. |
| Is it deterministic? | The decisions are (verdict, playbook, evidence identical in all 16 runs). The wording isn't, even at temperature 0. |
| Why "detection criteria matched", not "confirmed"? | It's lab data and a rule threshold; it is evidence for analysts, not proof. |
| Where do the times come from? | Event times copied from query results; the checker rejects bucket labels or ranges that don't match. |
| Year/timezone of syslog? | The year of processing and UTC (Elasticsearch default). A known limit. |
| Why a recording? | The system runs on a desktop GPU machine; the recorded run is verified (25/25) and frozen, with all logs and the query ledger saved. |
| Main limitation? | 4 playbooks, lab data, summary text not code-checked, one timezone. |

**Main challenges and fixes:**

1. **The 14B model wouldn't write whole-line patterns reliably** → code repairs (relax types, header cut) + per-message-type stage C.
2. **Misclassified events** ("Failed password for invalid user" as invalid_user) → rules ordered by specificity in code + vocabulary wording.
3. **Counting units** (4 log records per SSH attempt) → attempts counted on one record type; checker blocks "attempts = record types".
4. **Time claims from bucket labels** (reviewer's TC1 finding) → first/last event in results + a time checker.
5. **Invented field values / truncated or broken AI queries** → value catalog check, syntax check before sending.
6. **New message types on a known format** → template extend.
7. **Found only by the strict demo check:** user name swallowing "(uid=…)", log.category overwritten on extend,
   follow-up cut at 250 characters → all fixed before the recorded run.

Full list: `docs/DEVELOPMENT_LOG.md`.

## 9. Contributions and time (work-breakdown appendix)

Cigmy owned the AI side; the teammate owned the ELK kit, the datasets and the setup docs. Development was done with an AI
coding assistant (Claude); state that in the appendix if the course requires disclosing AI use.

| Dates | Work | Time (approx.) |
|---|---|---|
| 20–21 Oct | Desktop setup: WSL2, Docker, Ollama on the GPU; model selection; dev Elasticsearch | ~5 h |
| 22 Oct | Agent 1 v1 → v3.3: schema generation, held-out validation, repairs, timestamp detection; Loghub evaluation (4.5/5 mean) | ~5 h |
| 23 Oct | MCP server (roles, validation, ledger); Agent 2 v1 → v1.11 (playbooks, rule verdict, claim checker, time windows, curveball and false-positive tests); first run-twice experiment | ~7 h |
| 24 Oct | Integration with the team kit; Agent 1 v4 (message types, mapping, rules); run-twice on the kit (final evidence); reviewer TC1 fix + replay; Streamlit demo app; demo source and extend | ~10 h |
| 25 Oct | Host scope, query grouping; strict verification, three fixes, recorded and verified run, freeze | ~6 h |
| 26 Oct | Repository, rebuild guide, handover | ~2 h |

**Total: about 35 hours** (own estimate, 30–40 h) over 20–26 Oct. The split per day follows the workload in the development log: the heaviest day was 24 Oct (kit integration, repeatability experiment, demo app).

## 10. Design: how we designed it and why

The decisions below are the ones to explain in the report's design section. Background and alternatives are in
`docs/DEVELOPMENT_LOG.md` §3 (decisions), §4 (architecture) and the progress log.

### 10.1 Guiding principle: the LLM proposes, code verifies, repairs and decides
Every step where a wrong answer would be harmful has a code check after the model: Agent 1's patterns (held-out
validation), field names and types, event rules, Agent 2's verdict, evidence, follow-up queries and claims. The
model is used where language understanding helps: writing a parser for an unseen format, naming values, reading a
hypothesis, proposing extra queries, writing the summary. We arrived at this by testing. Every time a decision was
left to the model alone, a test found a failure; moving it into code fixed it for good. Examples: time windows (v1.4),
counting attempts (v1.9), invented values (v1.11), time claims (v1.16), log.category (25 Oct).

### 10.2 Why these components
| Decision | Chosen | Why / alternative rejected |
|---|---|---|
| Model location | Local, Ollama, qwen3:14b | Logs are sensitive, so no cloud. qwen3:14b fits a 12 GB GPU fully. Benchmarked against qwen2.5:14b and llama3.1:8b; gpt-oss:20b did not fit in GPU memory. Thinking mode off (10× faster). |
| One model, two agents | Same model, separate prompts, tools and accounts | Two models would not fit the GPU; separation comes from the MCP role allowlists and separate kit accounts, not from the model. |
| Tool access | MCP server, role allowlists, field validation, query ledger | The model never holds credentials and can't call anything outside its role; every query is traceable by id for the report. |
| Agent 1 approach | Generate → validate → repair → retry, plus an example library; **no fine-tuning** | Fine-tuning would need labelled data and time we didn't have; validation on held-out lines gives a measurable pass/fail instead. Fine-tuning was kept as a stretch goal and not needed. |
| Agent 1 structure | Staged: line pattern (A) → message types (C) → field names (D) → event rules (E) | One big pattern for the whole line was unreliable with a 14B model (v1 3/5, v2 2/5). Splitting the job and letting code do the deterministic parts (timestamps, alignment, ordering) raised it to 4.5/5 on unseen Loghub formats and made the demo format work. |
| Reuse / extend | Reuse a registered template when it parses ≥ 95%; extend only the message stages when new message types appear | Reuse costs no model call (2 s instead of 45–60 s) and keeps results stable; extending instead of rebuilding keeps the validated header. |
| Agent 2 decisions | Fixed playbooks + code verdict rules with thresholds | Repeatable and explainable verdicts; the run-twice experiment shows verdict, playbook and evidence identical in every run. The AI's freedom is limited to follow-ups and wording, which never change the verdict. |
| Verdict wording | "Detection criteria matched", not "confirmed" | Lab data and a rule threshold are evidence for an analyst, not proof of an attack. |
| Hallucination control | Claim checker in code + one rewrite + removal, all shown in the report | A prompt rule alone did not stop wrong claims (measured: 4 before, 4 after); a code check did. |
| Ingest | Use the team kit's three channels unchanged (pull, push, stream) | Agent 1 works on raw staging, independent of how lines arrived; the channel is recorded by Logstash for evidence. |
| UI | Streamlit, one page per demo scene | Fast to build, shows each agent's log live; holds no credentials. |
| Verification of the demo | Answer key from the sample files + 25 strict checks before freezing | Counts alone hid real bugs (user.name, log.category); value-level checks found them. |

### 10.3 Design process
Build → test on data the agent hadn't seen → read the failures → move the failing decision into code or add a
guardrail → test again. Each round is in the development log, with numbers (e.g. Agent 1 Loghub 3/5 → 2/5 → 4/5 →
4.5/5 mean; Agent 2 curveballs 1/5 → 5/5; false-positive time tests 3/4 → 9/9). External review was part of the loop: the
teammate's TC1 review led to the time-claim checker, and the demo checklist review led to host scope and query
grouping.

---

**Prof's reply:** will be forwarded when it arrives (email sent 26 Oct asking whether a recorded demo may be used).
