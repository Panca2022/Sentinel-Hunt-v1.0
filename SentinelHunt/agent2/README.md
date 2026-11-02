# Agent 2: Hunt agent

Hypothesis in → evidenced hunt report out (`reports/<hunt_id>.md` + `.json`).

| Step | Who | What |
|---|---|---|
| 1 Plan | LLM | Picks a playbook (or `unsupported`) and optional focus IP/user |
| 2 Coverage | code | Finds indices containing every required field; gaps are reported |
| 3 Execute | code | Playbook queries through MCP (`--role hunt`, read-only), each gets a ledger query_id |
| 4 Verdict | code | Rule thresholds → DETECTION CRITERIA MATCHED / NOT FOUND / INCONCLUSIVE. **The LLM never decides the verdict** |
| 5 Write | LLM | Summary + claims, each citing query_ids, doc_ids, count, entity |
| 6 Verify | code | Claims checked against the cited results; unknown query/doc ids, wrong counts, unseen entities → removed |
| 7 Report | code | Verdict, rule, coverage, verified findings, removed claims, % verified, every query + exact ES request |

Playbooks: `ssh_bruteforce` (T1110, authentication), `web_probing` (T1595.003, web), `port_probing` (T1046, firewall: many distinct blocked ports, since drops alone are normal), `destructive_sudo` (T1548.003/T1485, negative control: lab has only harmless sudo).

```bash
.venv/bin/python agent2/hunt_agent.py --list
.venv/bin/python agent2/hunt_agent.py "A compromised internal workstation is brute-forcing SSH on host_001"
```
