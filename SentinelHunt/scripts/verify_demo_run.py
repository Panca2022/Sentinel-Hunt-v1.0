#!/usr/bin/env python3
"""
Strict end-to-end check of one demo run on the bastion-02 sample logs (read-only).

An answer key is built straight from the 3 sample files with fixed regexes (independent of Agent 1), then:
  INGEST   every line arrived once, through the channel planned for its file (pull / stream / push),
           as recorded by the kit's Logstash (ingestion_channel)
  AGENT 1  every one of the 36 parsed records: every field VALUE equals the answer key
           (@timestamp, host.name, process.name/pid, user.name, source.ip/port, terminal, event.action/outcome,
           log.category), no extra fields, record_id kept, original text kept
  AGENT 2  (with --report) verdict and its numbers, every time/IP/user/count in the kept claims and the summary
           against the answer key, host filter on every evidence query, every cited query id in the ledger
Prints PASS/FAIL per check and exits 1 on any FAIL.

Usage (WSL, from ~/se6014):
  .venv/bin/python scripts/verify_demo_run.py                         # ingest + Agent 1
  .venv/bin/python scripts/verify_demo_run.py --report reports/<hunt id>.json --ledger mcp_server/ledger/<hunt id>.jsonl
  .venv/bin/python scripts/verify_demo_run.py --selftest              # answer key only, no Elasticsearch
"""
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "demo" / "sample_logs"
FILES = {"log_pull.log": "pull", "log_stream.log": "stream", "log_push.log": "push"}
FEED, HOST, ATTACKER, TARGET = "bastion-02-auth", "bastion-02", "203.0.113.45", "deploy"
BOOKKEEPING = {"@timestamp", "record_id", "capture_id", "feed_name", "raw_line", "message", "event.original",
               "event.action", "event.outcome", "log.category"}

HEAD = re.compile(r"^(?P<mon>\w{3}) +(?P<day>\d+) (?P<time>\d\d:\d\d:\d\d) (?P<host>\S+) (?P<prog>[^\[\s]+)\[(?P<pid>\d+)\]: (?P<body>.*)$")
BODY = [  # (regex, event.action, event.outcome)
    (r"^Accepted (?:publickey|password) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ", "ssh_authentication", "success"),
    (r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ", "ssh_authentication", "failure"),
    (r"^pam_unix\(sshd:auth\): authentication failure;.* tty=(?P<tty>\S+) .*rhost=(?P<ip>\S+) +user=(?P<user>\S+)$",
     "pam_authentication", "failure"),
    (r"^pam_unix\(sshd:session\): session opened for user (?P<user>[^(\s]+)\(uid=\d+\)", "session_opened", "success"),
    (r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)$", "session_closed", "success"),
]
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
YEAR = 2026        # syslog has no year: the date processor uses the year of processing (ASSUMPTIONS file)

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  -> {detail}" if detail and not ok else (f"  ({detail})" if detail else "")))


def answer_key():
    key = []
    for fname, channel in FILES.items():
        for line in (SAMPLES / fname).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            h = HEAD.match(line)
            assert h, f"header not understood: {line}"
            exp = {"@timestamp": f"{YEAR}-{MONTHS[h['mon']]:02d}-{int(h['day']):02d}T{h['time']}.000Z",
                   "host.name": h["host"], "process.name": h["prog"], "process.pid": int(h["pid"]),
                   "log.category": "authentication"}
            for rx, action, outcome in BODY:
                m = re.match(rx, h["body"])
                if m:
                    g = m.groupdict()
                    exp.update({"event.action": action, "event.outcome": outcome, "user.name": g["user"]})
                    if g.get("ip"):
                        exp["source.ip"] = g["ip"]
                    if g.get("port"):
                        exp["source.port"] = int(g["port"])
                    if g.get("tty"):
                        exp["terminal"] = g["tty"]
                    break
            else:
                raise AssertionError(f"message type not in the answer key: {line}")
            key.append({"line": line, "file": fname, "channel": channel, "expected": exp})
    return key


def flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict) and v:
            out.update(flat(v, prefix + k + "."))
        else:
            out[prefix + k] = v
    return out


def facts(key):
    fail = sorted((k["expected"]["@timestamp"], k) for k in key if k["expected"]["event.action"] == "ssh_authentication"
                  and k["expected"]["event.outcome"] == "failure" and k["expected"].get("source.ip") == ATTACKER)
    succ = [k for k in key if k["expected"]["event.action"] == "ssh_authentication" and k["expected"]["event.outcome"]
            == "success" and k["expected"].get("source.ip") == ATTACKER and k["expected"]["user.name"] == TARGET]
    in_window = [k for k in key if "09:15:00" <= k["expected"]["@timestamp"][11:19] < "09:25:00"]
    return {"failed": len(fail), "first_failed": fail[0][0][11:19], "last_failed": fail[-1][0][11:19],
            "success": len(succ), "success_times": [k["expected"]["@timestamp"][11:19] for k in succ],
            "pam": sum(k["expected"]["event.action"] == "pam_authentication" for k in key),
            "window_records": len(in_window),
            "all_times": {k["expected"]["@timestamp"][11:19] for k in key},
            "ips": {k["expected"].get("source.ip") for k in key} - {None},
            "users": {k["expected"]["user.name"] for k in key}}


def main():
    key = answer_key()
    F = facts(key)
    print(f"answer key: {len(key)} lines " + str(dict(Counter(k['channel'] for k in key))) + " | "
          + str(dict(Counter(k['expected']['event.action'] + '/' + k['expected']['event.outcome'] for k in key))))
    print(f"            attacker {ATTACKER}: {F['failed']} failed passwords {F['first_failed']}–{F['last_failed']}, "
          f"{F['success']} success at {F['success_times']}; users {sorted(F['users'])}")
    if "--selftest" in sys.argv:
        return

    kit = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", "~/se6014-portable/SentinelHunt_ELK_Portable")))
    sys.path.insert(0, str(kit / "scripts"))
    from manage import es  # kit admin account, search only

    # ---------------- ingest
    print("\n== INGEST")
    raw = es("POST", "/sentinelhunt-raw-v1/_search", {"size": 10000, "query": {"term": {"feed_name": FEED}}})["hits"]["hits"]
    by_line = {}
    for h in raw:
        by_line.setdefault(h["_source"].get("raw_line"), []).append(h["_source"])
    check("raw staging holds exactly the 36 sample lines", len(raw) == len(key) and set(by_line) == {k["line"] for k in key},
          f"{len(raw)} raw records")
    dup = [l for l, v in by_line.items() if len(v) > 1]
    check("no line arrived twice", not dup, f"{len(dup)} duplicated, e.g. {dup[:1]}")
    wrong = [(k["file"], k["channel"], by_line[k["line"]][0].get("ingestion_channel")) for k in key
             if k["line"] in by_line and by_line[k["line"]][0].get("ingestion_channel") != k["channel"]]
    check("each file came through its channel (pull / stream / push, as Logstash recorded it)", not wrong,
          f"{len(wrong)} wrong, e.g. {wrong[:2]}")
    raw_id = {l: v[0].get("record_id") for l, v in by_line.items()}

    # ---------------- agent 1
    print("\n== AGENT 1 (every field of every record)")
    docs = es("POST", "/sentinelhunt-hunt-v1/_search", {"size": 10000, "query": {"term": {"feed_name": FEED}}})["hits"]["hits"]
    check("36 parsed records", len(docs) == len(key), f"{len(docs)}")
    parsed = {}
    for d in docs:
        s = flat(d["_source"])
        parsed.setdefault(s.get("event.original") or s.get("message") or s.get("raw_line"), []).append((d["_id"], s))
    bad_vals, extra, missing, ids = [], Counter(), [], []
    for k in key:
        got = parsed.get(k["line"])
        if not got:
            missing.append(k["line"])
            continue
        _id, s = got[0]
        if s.get("record_id") != raw_id.get(k["line"]) or _id != raw_id.get(k["line"]):
            ids.append(k["line"])
        for f, v in k["expected"].items():
            g = s.get(f)
            same = (str(g) == str(v)) if not isinstance(v, int) else (str(g).isdigit() and int(g) == v)
            if not same:
                bad_vals.append(f"{f}: expected {v!r} got {g!r} | {k['line'][:70]}")
        for f in s:
            if f not in k["expected"] and f not in BOOKKEEPING:
                extra[f] += 1
    check("every sample line has a parsed record", not missing, f"{len(missing)} missing, e.g. {missing[:1]}")
    check("record_id kept from raw staging (document id = record_id)", not ids, f"{len(ids)} differ")
    check("every field value equals the answer key", not bad_vals,
          f"{len(bad_vals)} wrong values:\n        " + "\n        ".join(bad_vals[:12]))
    check("no extra fields", not extra, f"{dict(extra)}")
    for action in sorted({k["expected"]["event.action"] for k in key}):
        n_exp = sum(k["expected"]["event.action"] == action for k in key)
        n_got = sum(flat(d["_source"]).get("event.action") == action for d in docs)
        check(f"  count {action}", n_exp == n_got, f"expected {n_exp}, got {n_got}")

    # ---------------- agent 2
    if "--report" not in sys.argv:
        print("\n(no --report given: Agent 2 not checked)")
    else:
        print("\n== AGENT 2")
        rep = json.loads(Path(sys.argv[sys.argv.index("--report") + 1]).read_text())
        led = []
        if "--ledger" in sys.argv:
            led = [json.loads(l) for l in Path(sys.argv[sys.argv.index("--ledger") + 1]).read_text().splitlines() if l.strip()]
        rule = rep.get("verdict_rule", "")
        check("verdict DETECTION CRITERIA MATCHED", rep.get("verdict") == "DETECTION CRITERIA MATCHED", rep.get("verdict"))
        check(f"verdict: top source {ATTACKER} with {F['failed']} failed password attempts",
              f"{ATTACKER} with {F['failed']} failed password attempts" in rule, rule[:200])
        check(f"verdict: pam_authentication={F['pam']}", f"pam_authentication={F['pam']}" in rule)
        check(f"verdict: successful login of {TARGET} from {ATTACKER}: {F['success']}",
              re.search(rf"successful login of targeted user {TARGET} from {re.escape(ATTACKER)}: {F['success']}\b", rule) is not None)
        check("plan focus host = bastion-02", (rep.get("plan") or {}).get("focus", {}).get("host") == HOST)

        def text_problems(t):
            p = []
            for tm in re.findall(r"\b\d\d:\d\d(?::\d\d)?\b", t):
                if len(tm) == 8 and tm not in F["all_times"] and tm not in ("09:15:00", "09:25:00"):
                    p.append(f"time {tm} is not an event time")
                if len(tm) == 5 and not any(x.startswith(tm) for x in F["all_times"]) and tm not in ("09:15", "09:25"):
                    p.append(f"minute {tm} has no event")
            for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", t):
                if ip not in F["ips"]:
                    p.append(f"IP {ip} not in the logs")
            rng = re.search(r"(\d\d:\d\d:\d\d)\D{1,12}(\d\d:\d\d:\d\d)", t)
            if rng and "fail" in t.lower() and (rng.group(1), rng.group(2)) != (F["first_failed"], F["last_failed"]):
                p.append(f"failed-attempt range {rng.groups()} should be {F['first_failed']}–{F['last_failed']}")
            for n in re.findall(r"\b(\d+) failed", t):
                if int(n) != F["failed"]:
                    p.append(f"'{n} failed' should be {F['failed']}")
            return p

        for c in rep.get("claims", []):
            pr = text_problems(c["text"])
            check(f"claim: {c['text'][:90]}", not pr, "; ".join(pr))
        pr = text_problems(rep.get("summary", ""))
        check("summary: times / IPs / counts", not pr, "; ".join(pr))
        ev = rep.get("evidence_query_ids", {})
        ev_ids = [q for v in ev.values() for q in (v if isinstance(v, list) else [v])]
        led_by = {q.get("query_id"): q for q in led}
        if led:
            noscope = [q for q in ev_ids if f'host.name:"{HOST}"' not in str((led_by.get(q) or {}).get("args", {}).get("query"))]
            check("host filter on every playbook evidence query", not noscope, f"missing on {noscope}")
            twice = [q for q, x in led_by.items() if str(x.get("args", {}).get("query", "")).count(f'host.name:"{HOST}"') > 1]
            check("host filter added at most once per query", not twice, f"{twice}")
            cited = {q for c in rep.get("claims", []) for q in c.get("query_ids", [])}
            check("every query a claim cites is in the ledger", cited <= set(led_by), f"{sorted(cited - set(led_by))}")
            check("every ledger query ran ok or was rejected with a reason",
                  all(q.get("status") in ("ok", "rejected") for q in led), str(Counter(q.get("status") for q in led)))
        else:
            print("(no --ledger given: query checks skipped)")

    print(f"\n{sum(results)}/{len(results)} checks passed" + ("" if all(results) else "  <-- NOT CLEAN"))
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
