# Agent 1: Schema Agent (v3.3, frozen 22 Oct)

Turns an unrecognised log file into a validated, reusable Elasticsearch ingest pipeline.

Design: **the LLM proposes, code verifies and repairs.**

```
sample lines ─► match registry? ─yes─► reuse template
                     │ no
                     ▼
 STAGE A (fields)  LLM writes 3 Grok candidates (temp 0 + 2×0.7) ─► ES _simulate on 100 UNSEEN lines
                     │ best fails                                        │ best passes (≥95%, ≥3 fields)
                     ▼                                                   │
                code auto-repair (spaces → \s+) ── passes ──────────────┤
                     │ fails                                             │
                     ▼                                                   │
                pinpoint diagnosis ("matches up to X, breaks at Y")      │
                → LLM retry, 2 candidates (max 3 rounds → needs_human)   │
                                                                         ▼
 STAGE B (time)   code tries ~10 known timestamp layouts; keeps the one parsing ≥95%
                  with the narrowest date span (e.g. HDFS yyMMdd beats MMddyy)
                                                                         ▼
 REGISTER         ES ingest pipeline logs-<source> (grok + timestamp grok + date) + registry.json
```

### Version history (report material)

| Version | Change | Loghub result (qwen3:14b) |
|---|---|---|
| v1 | 1 LLM attempt + retry with failed lines | 3/5; HDFS parsed but month/year swapped |
| v2 | LLM also writes date formats; diagnosis; repeat guard | 2/5: one model doing two jobs got worse; it ignored the diagnosis and repeated itself |
| v3 | Best-of-3 + code repair + code timestamp detection | **4/5**, all with correct dates (Apache 2005, Zookeeper 2015). HDFS failed: model kept splitting the compact `081109 203615` date (22%) |
| v3.1 | Timestamp detected first, LLM told to copy it as prefix | 3/5: HDFS ✓ but Apache ✗ (model mangled the regex it was asked to copy) |
| v3.2 | Code strips timestamp; LLM writes the rest; code glues them | 3/5: HDFS ✓, Apache/Zookeeper ✗ (model dropped leading "- ") |
| **v3.3** | **Strategy ensemble** (whole-line vs stripped, best wins) + stray-`$` repair + output cap (1024 tok) / 90 s timeout | Run A **4/5** (Apache near-miss: 99% parsed, 2.5 fields/line). Run B **5/5**: HDFS solved by *stripped*, other 4 by *full*; Apache fixed in round 2 after diagnosis. All dates correct. **Mean so far 4.5/5** |

**Observations for the report**
- *Parsing ≠ meaning*: v1 parsed HDFS 100% with month/year swapped; only a semantic check (date span) catches this.
- A 14B model ignores precise diagnostic feedback and repeats itself; **sampling several candidates** works better than arguing.
- Deterministic code (timestamp library, whitespace/anchor repair) beats asking the LLM to do the same.
- Run-to-run variance is real (same version: 3/5 vs 4/5) → final numbers = mean of 3 runs.
- One run hung on a runaway generation → output-token cap + timeout are mandatory guardrails.

## Guardrails

- Validation uses **held-out lines the LLM never saw**, so the pattern must generalise beyond the sample.
- Quality gates: ≥ 95% parse rate, ≥ 3 fields per line, no catch-all `GREEDYDATA` pattern.
- At most 3 attempts; still failing → flagged `needs_human`, nothing registered.
- Every run is logged to `runs/<source>-<time>.json` (attempts, patterns, parse rates, tokens, time). This is evidence for the report.

## Files

| File | Purpose |
|---|---|
| `schema_agent.py` | The agent (standard-library Python, nothing to install) |
| `example_library.json` | Pre-labelled known formats (retrieval examples). **Not** the test formats |
| `registry.json` | Created on first success; registered templates |
| `runs/` | One JSON log per run |

## Commands

Run these from the project root (`~/se6014`):

```bash
python3 agent1/schema_agent.py --check-library                       # verify library patterns in ES
python3 agent1/schema_agent.py --file samples/OpenSSH_2k.log --source openssh
python3 agent1/schema_agent.py --eval samples/*.log --fresh          # evaluation table for the report
MODEL=qwen2.5:14b python3 agent1/schema_agent.py --eval samples/*.log --fresh --no-register   # compare models
```

## Later (integration)

The ES calls (`simulate`, `register`) become MCP tools (`simulate_pipeline`, `register_template`) once the teammate's MCP server is ready. The agent logic stays the same.
