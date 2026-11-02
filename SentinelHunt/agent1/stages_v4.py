#!/usr/bin/env python3
"""
Agent 1 v4 stages, run AFTER the v3.3 core (schema_agent.process) has found a header grok + timestamp.
Same principle: the LLM proposes, code validates (ES _simulate) and decides.

  Header fix (code)  a lazy %{DATA:x} right before the trailing %{GREEDYDATA:body} swallows the first word of the
                     message -> merged into the body.
  Stage C (message)  messages in the free-text body are grouped by shape (code); the LLM writes one small grok per
                     message type, extracting ONLY into the hunt index's field names; each is validated on its group.
  Stage D (names)    every extracted field that is not a hunt-index field is mapped by the LLM onto one of them or
                     dropped; code checks the name is allowed and every sample value fits the type (ip / integer).
  Stage E (meaning)  event.action / event.outcome / log.category from ordered rules the LLM writes over the
                     extracted fields; values must come from the fixed vocabulary (vocabulary.json); every rule
                     must match at least one sample.
  Assemble           one ES ingest pipeline: staging fields in -> exactly the hunt-index fields out
                     (strict mapping: record_id, capture_id, feed_name, raw_line, event.original kept).
"""
import ipaddress
import json
import re
import time
from collections import Counter, OrderedDict
from pathlib import Path

import schema_agent as sa

HERE = Path(__file__).resolve().parent
VOCAB = json.loads((HERE / "vocabulary.json").read_text())

# hunt-index fields Agent 1 may EXTRACT (teammate's strict mapping, minus bookkeeping/derived fields)
TARGETS = OrderedDict([
    ("source.ip", ("ip", "address the connection/request came from (from X, rhost=X, SRC=)")),
    ("source.port", ("int", "port on the source side (port N, SPT=)")),
    ("destination.ip", ("ip", "address the traffic went to (DST=)")),
    ("destination.port", ("int", "port on the destination side (DPT=)")),
    ("user.name", ("user", "account NAME acting or logging in (sudo: the invoking user, 'by X'); not a numeric uid")),
    ("user.target.name", ("user", "account NAME being switched to (sudo USER=X, 'session opened for user X' under sudo); not a numeric uid")),
    ("host.name", ("kw", "host that wrote the log")),
    ("process.name", ("program", "program name, e.g. sshd, sudo (without the [pid])")),
    ("process.pid", ("int", "process id")),
    ("process.command_line", ("kw", "command that was run (COMMAND=)")),
    ("process.working_directory", ("kw", "working directory (PWD=)")),
    ("terminal", ("kw", "terminal / tty (TTY=)")),
    ("network.transport", ("transport", "transport protocol: tcp, udp, icmp (not an application protocol like ssh2)")),
    ("network.bytes", ("int", "packet / connection length in bytes (LEN=)")),
    ("rule.name", ("kw", "firewall rule or log prefix name (PREFIX=, rule=)")),
    ("http.version", ("kw", "HTTP version, e.g. 1.1")),
    ("http.request.method", ("kw", "HTTP method")),
    ("http.request.referrer", ("kw", "HTTP referrer")),
    ("http.response.status_code", ("int", "HTTP status code")),
    ("http.response.body.bytes", ("int", "HTTP response body size in bytes")),
    ("url.original", ("kw", "requested URL / path")),
    ("user_agent.original", ("kw", "HTTP user agent")),
])
BOOKKEEPING = {"@timestamp", "record_id", "capture_id", "feed_name", "raw_line", "message", "event.original",
               "event.action", "event.outcome", "log.category"}
HUNT_FIELDS = set(TARGETS) | BOOKKEEPING
STAGING_ONLY = ["received_at", "ingestion_channel", "source_name"]
ACTION_CATEGORY = {"ssh_authentication": "authentication", "ssh_invalid_user": "authentication",
                   "ssh_connection_closed": "authentication", "pam_authentication": "authentication",
                   "pam_unknown_user": "authentication", "session_opened": "authentication",
                   "session_closed": "authentication", "sudo_command_recorded": "authentication",
                   "http_request": "web_access", "network_allow": "firewall", "network_drop": "firewall"}
LOWERCASE = {"network.transport"}
TRANSPORTS = {"tcp", "udp", "icmp", "ipv6-icmp", "sctp", "gre", "esp", "ah", "igmp"}            # ECS convention: lowercase protocol names
MAX_GROUPS = 14
GROK_RE = re.compile(r"%\{(\w+)(?::([\w.@]+))?(?::\w+)?\}|\(\?<([\w]+)>")


# --------------------------------------------------------------------------- helpers
def llm_json(system, user, schema, temperature=0.0, seed=sa.SEED, max_tokens=900):
    body = {"model": sa.MODEL, "stream": False, "format": schema,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": temperature, "seed": seed, "num_ctx": 8192, "num_predict": max_tokens}}
    if sa.MODEL.startswith("qwen3"):
        body["think"] = False
    t0 = time.perf_counter()
    try:
        status, resp = sa.http("POST", f"{sa.OLLAMA_URL}/api/chat", body, timeout=sa.LLM_TIMEOUT_S)
        out = json.loads(resp.get("message", {}).get("content", "")) if status == 200 else None
    except Exception:
        out, resp = None, {}
    return out, {"seconds": round(time.perf_counter() - t0, 1),
                 "tokens": resp.get("prompt_eval_count", 0) + resp.get("eval_count", 0)}


def flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict) and v:
            out.update(flat(v, prefix + k + "."))
        else:
            out[prefix + k] = v          # an EMPTY object is reported too: strict mappings reject it
    return out


def simulate_docs(processors, sources):
    """Run an inline pipeline over source dicts. Returns (docs or None per input, first error)."""
    docs, err = [], None
    for i in range(0, len(sources), 500):
        chunk = sources[i:i + 500]
        status, resp = sa.http("POST", f"{sa.ES_URL}/_ingest/pipeline/_simulate",
                               {"pipeline": {"processors": processors}, "docs": [{"_source": s} for s in chunk]})
        if status != 200:
            return [None] * len(sources), sa.es_error(resp)
        for d in resp.get("docs", []):
            if "error" in d or "doc" not in d:
                err = err or (d.get("error", {}).get("reason") or "error")
                docs.append(None)
            else:
                docs.append(flat(d["doc"]["_source"]))
    return docs, err


def names_in(pattern):
    return [m.group(2) or m.group(3) for m in GROK_RE.finditer(pattern or "") if (m.group(2) or m.group(3))]


def type_ok(field, value):
    kind = TARGETS.get(field, ("kw",))[0]
    s = str(value).strip()
    if kind == "ip":
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False
    if kind == "int":
        return bool(re.fullmatch(r"-?\d+", s))
    if kind == "user":           # a username, not a numeric uid (uid=0 is not the user "0")
        # no brackets, '=' or spaces: 'user_003(uid=1003' is not a user name
        return s != "" and not re.fullmatch(r"\d+", s) and not re.search(r"[()\[\]=\s]", s)
    if kind == "transport":      # ECS: IANA transport names, lowercase
        return s.lower() in TRANSPORTS
    if kind == "program":        # a program name, never 'sshd[7200]' or 'sshd:'
        return bool(re.fullmatch(r"[A-Za-z0-9_.@/+-]+", s))
    return s != ""


def painless_path(field):
    parts = field.split(".")
    return "ctx." + parts[0] + "".join(f"?.{p}" for p in parts[1:])


def painless_str(v):
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


def mask(text):
    t = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP", text)
    return re.sub(r"\d+", "0", t)


# --------------------------------------------------------------------------- header fix
def fix_header(pattern):
    """'%{DATA:x} %{GREEDYDATA:body}' at the end -> '%{GREEDYDATA:body}' (lazy DATA eats the first word)."""
    m = re.search(r"%\{GREEDYDATA:([\w.]+)\}\s*$", pattern or "")
    if not m:
        return pattern, None, None
    body = m.group(1)
    fixed = re.sub(r"(?:%\{DATA:[\w.]+\}[:\s]*)+(?=%\{GREEDYDATA:[\w.]+\}\s*$)", "", pattern)
    return fixed, body, (fixed != pattern)


header_cut = sa.header_cut       # shared with stage A (schema_agent)


# --------------------------------------------------------------------------- stage C
C_SYSTEM = """You write ONE Elasticsearch grok pattern for a group of log MESSAGES that share one message type.
Extract only values that literally appear, using ONLY these field names:
{fields}
Rules: keep literal words as literal text; built-in patterns: IP, IPORHOST, INT, POSINT, WORD, USERNAME, USER,
NOTSPACE, DATA, GREEDYDATA, UNIXPATH, PATH, QUOTEDSTRING. Escape regex characters \\[ \\] \\( \\) \\. \\? \\* \\| \\$.
Name a value ONLY if it clearly is that thing (a protocol word like "ssh2" is not network.transport; a word like
"password" is not rule.name). A value with no matching field name is matched WITHOUT a name (e.g. %{{NOTSPACE}}).
The pattern must match the WHOLE message from its first character to its end. If the messages contain none of the
listed values, return "".
Return JSON only: {{"grok_pattern": "..."}}"""
C_SCHEMA = {"type": "object", "properties": {"grok_pattern": {"type": "string"}}, "required": ["grok_pattern"]}


def group_messages(msgs):
    groups = OrderedDict()
    for m in msgs:
        key = " ".join(mask(m).split()[:3])
        groups.setdefault(key, []).append(m)
    return sorted(groups.items(), key=lambda kv: -len(kv[1]))


def explain_miss(pattern, msg):
    """Pinpoint where a message pattern stops matching (reuses the v3 diagnosis)."""
    core = pattern.lstrip("^").rstrip("$")
    hint = sa.diagnose(core, msg)
    if hint:
        return hint
    docs, _ = simulate_docs([{"grok": {"field": "m", "patterns": ["^" + core + "(?<diag_rest>.*)$"]}}], [{"m": msg}])
    rest = (docs[0] or {}).get("diag_rest", "")
    return f"On this message:\n{msg[:300]}\nthe pattern stops before the end; this text is left unmatched: {rest[:120]!r}"


def check_message_pattern(pattern, msgs, exclude=()):
    procs = [{"grok": {"field": "m", "patterns": ["^" + pattern.lstrip("^").rstrip("$") + "$"]}}]
    docs, err = simulate_docs(procs, [{"m": m} for m in msgs])
    if err and all(d is None for d in docs) and "do not match" not in str(err):
        return 0.0, [f"Elasticsearch rejected the pattern: {err}"], docs
    ok = [d for d in docs if d is not None]
    issues = []
    rate = len(ok) / len(msgs)
    if rate < 0.9:
        bad = next(m for m, d in zip(msgs, docs) if d is None)
        issues.append(f"only {rate:.0%} of the messages matched. DIAGNOSIS: {explain_miss(pattern, bad)}")
    bad_names = [n for n in names_in(pattern) if n not in TARGETS or n in exclude]
    if bad_names:
        issues.append(f"field names not allowed here: {bad_names} (use only the listed names, or no name)")
    for d in ok:
        for k, v in d.items():
            if k in TARGETS and not type_ok(k, v):
                issues.append(f"{k} captured '{v}', which is not a valid {TARGETS[k][0]}")
                break
    return rate, issues, docs


STOP = {"user", "invalid", "authenticating", "from", "port", "for", "by", "to", "on", "of", "the", "session",
        "opened", "closed", "password", "failed", "accepted", "connection", "disconnected", "received", "disconnect",
        "unknown", "failure", "success"}
SEP_OPEN, SEP_CLOSE = "=:([", ")]:;,"


def grok_escape(text):
    return re.sub(r"([\\.\[\]\(\)\*\+\?\{\}\|\^\$])", r"\\\1", text)


def is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def slot_type(vals):
    if all(is_ip(v) for v in vals):
        return "IP"
    if all(re.fullmatch(r"\d+", v) for v in vals):
        return "INT"
    return "NOTSPACE"


def split_value(vals, prev):
    """Column of one token position -> list of ('lit', text) / ('slot', values) parts, or None if pure literal."""
    if len(set(vals)) == 1:
        v = vals[0]
        if v.lower().strip(";,:") in STOP or not (re.search(r"[\d/=@_]", v) or prev.lower() in {"user", "for", "by", "from", "port"}):
            return None
        if re.fullmatch(r"[\w.-]+\(.*\):", v):          # logger tag like pam_unix(sshd:auth): -> literal
            return None
        m = re.fullmatch(r"([^=()\s]+)(\(.*\)[;,:]*)", v)   # name(uid=0) -> slot 'name' + literal '(uid=0)'
        if m:
            pre, core, suf = "", m.group(1), m.group(2)
        else:
            pre = v[:v.index("=") + 1] if "=" in v else ""
            core = v[len(pre):]
            suf = ""
            m = re.search(r"(\(.*\)|[;,:]+)$", core)
            if m and m.start() > 0:
                core, suf = core[:m.start()], core[m.start():]
        if not core:
            return None
        return [("lit", pre)] * bool(pre) + [("slot", [core] * len(vals))] + [("lit", suf)] * bool(suf)
    # varying name(uid=N): slot 'name' + literal '(uid=N)' (digits are generalised when the pattern is built)
    ms = [re.fullmatch(r"([^=()\s]+)(\(.*\)[;,:]*)", v) for v in vals]
    if all(ms) and len({re.sub(r"\d+", "0", m.group(2)) for m in ms}) == 1:
        return [("slot", [m.group(1) for m in ms]), ("lit", ms[0].group(2))]
    pre = vals[0]
    for v in vals[1:]:
        while not v.startswith(pre):
            pre = pre[:-1]
    cut = max((pre.rfind(c) for c in SEP_OPEN), default=-1)
    pre = pre[:cut + 1] if cut >= 0 else ""
    suf = vals[0]
    for v in vals[1:]:
        while not v.endswith(suf):
            suf = suf[1:]
    idx = [suf.find(c) for c in SEP_CLOSE if suf.find(c) >= 0]
    suf = suf[min(idx):] if idx else ""
    cores = [v[len(pre):len(v) - len(suf) if suf else None] for v in vals]
    if any(c == "" for c in cores):
        pre, suf, cores = "", "", list(vals)
    return [("lit", pre)] * bool(pre) + [("slot", cores)] + [("lit", suf)] * bool(suf)


def build_template(group):
    """Align messages token by token (Drain-style). Returns parts list or None."""
    toks = [m.split() for m in group]
    n = min(len(t) for t in toks)
    if n == 0:
        return None
    ragged = any(len(t) != n for t in toks)
    parts = []
    for i in range(n):
        last_greedy = ragged and i == n - 1
        col = [" ".join(t[i:]) if last_greedy else t[i] for t in toks]
        if i:
            parts.append(("sep", None))
        if last_greedy:
            if len(set(col)) == 1:
                parts.append(("lit", col[0]))
                continue
            pre = col[0]
            for v in col[1:]:
                while not v.startswith(pre):
                    pre = pre[:-1]
            cut = max((pre.rfind(c) for c in SEP_OPEN), default=-1)
            pre = pre[:cut + 1] if cut >= 0 else ""
            if pre:
                parts.append(("lit", pre))
            parts.append(("slot", [c[len(pre):] for c in col], "GREEDYDATA"))
            continue
        sv = split_value(col, toks[0][i - 1] if i else "")
        if sv is None:
            parts.append(("lit", col[0]))
        else:
            parts += [p if p[0] == "lit" else ("slot", p[1], slot_type(p[1])) for p in sv]
    return parts


SLOT_SYSTEM = """A log message type was turned into a template: literal text plus value slots <S1>, <S2>, ...
For each slot choose ONE field name from this list, or "none" if the slot is not one of these things:
{fields}
Each field name at most once. Return JSON only: {{"slots": [{{"slot": "S1", "field": "..."}}]}}"""
# related field pairs: when two slots claim the same field, the model picks the role instead of naming again
PAIRS = {"user.name": ("user.target.name", "the acting user: who logged in or who ran the command",
                       "the target user: the account being switched to or acted upon"),
         "source.ip": ("destination.ip", "where the traffic came FROM", "where the traffic went TO"),
         "source.port": ("destination.port", "the port on the side the traffic came FROM",
                         "the port on the side the traffic went TO")}
for _a, (_b, _ra, _rb) in list(PAIRS.items()):
    PAIRS[_b] = (_a, _rb, _ra)
ROLE_SCHEMA = {"type": "object", "properties": {"slot": {"type": "string"}}, "required": ["slot"]}


SLOT_SCHEMA = {"type": "object", "properties": {"slots": {"type": "array", "items": {"type": "object", "properties": {
    "slot": {"type": "string"}, "field": {"type": "string"}}, "required": ["slot", "field"]}}}, "required": ["slots"]}


def name_slots(parts, exclude, temp=0.0, seed=sa.SEED):
    slots = [p for p in parts if p[0] == "slot"]
    if not slots:
        return None, []
    shown, k = [], 0
    for p in parts:
        if p[0] == "sep":
            shown.append(" ")
        elif p[0] == "lit":
            shown.append(p[1])
        else:
            k += 1
            shown.append(f"<S{k}>")
    # text right before each slot (e.g. "USER=") helps the model name it
    before, prev = [], ""
    for p in parts:
        if p[0] == "slot":
            before.append(prev.split("<v>")[-1].strip()[-14:])     # literal text since the previous slot
        prev = prev + (" " if p[0] == "sep" else p[1] if p[0] == "lit" else "<v>")
    examples = "\n".join(f"S{i + 1} (after '{before[i]}'): {list(dict.fromkeys(p[1]))[:4]}" for i, p in enumerate(slots))
    fields = "\n".join(f"- {f}: {d}" for f, (t, d) in TARGETS.items() if f not in exclude)
    system = SLOT_SYSTEM.format(fields=fields)
    out, _ = llm_json(system, f"Template: {''.join(shown)}\nSlot values seen:\n{examples}", SLOT_SCHEMA, temp, seed, 400)
    def slot_key(label):                       # "S4", "4", "S4: key USER=" -> "S4"
        m = re.search(r"(\d+)", str(label or ""))
        return f"S{m.group(1)}" if m else None

    chosen = {slot_key(d.get("slot")): (d.get("field") or "").strip() for d in (out or {}).get("slots", [])}
    retry_log = []

    def validate(ch):
        nm, used, why = [], set(), {}
        for i, p in enumerate(slots):
            f = ch.get(f"S{i + 1}", "none")
            if f in (None, "", "none"):
                nm.append(None)
            elif f not in TARGETS or f in exclude:
                nm.append(None)
                why[i] = f"'{f}' is not an allowed field"
            elif f in used:
                nm.append(None)
                why[i] = f"'{f}' is already used by another slot"
            elif not all(type_ok(f, v) for v in p[1]):
                nm.append(None)
                why[i] = f"values do not fit '{f}'"
            else:
                nm.append(f)
                used.add(f)
        return nm, used, why

    names, used, why = validate(chosen)
    # conflict between a related pair (two slots claim user.name): ask a two-way ROLE question, not a naming question
    for i in [i for i in range(len(slots)) if names[i] is None and "already used" in why.get(i, "")]:
        f = chosen.get(f"S{i + 1}")
        if f not in PAIRS or PAIRS[f][0] in used:
            continue
        j = next(k for k in range(len(slots)) if names[k] == f)
        other, role_f, role_other = PAIRS[f]
        q = (f"Template: {''.join(shown)}\nTwo slots are both '{f.split('.')[0]}' values:\n"
             f"S{j + 1} (after '{before[j]}'): {list(dict.fromkeys(slots[j][1]))[:3]}\n"
             f"S{i + 1} (after '{before[i]}'): {list(dict.fromkeys(slots[i][1]))[:3]}\n"
             f"One is {role_f}; the other is {role_other}. Which slot is {role_other}? Answer with the slot (S{j + 1} or S{i + 1}).")
        ans, _ = llm_json("You read log templates and answer precisely. Return JSON only: {\"slot\": \"S..\"}",
                          q, ROLE_SCHEMA, temp, seed, 50)
        pick = slot_key((ans or {}).get("slot"))
        retry_log.append(f"role question S{j + 1}/S{i + 1}: {role_other.split(':')[0]} -> {pick}")
        if pick == f"S{i + 1}":
            chosen[f"S{i + 1}"] = other
        elif pick == f"S{j + 1}":
            chosen[f"S{j + 1}"], chosen[f"S{i + 1}"] = other, f
        names, used, why = validate(chosen)
    # second pass: key=value slots that are unnamed OR whose name was rejected (e.g. sudo USER=root named user.name
    # twice) get a focused question with the reason; one retry at a different temperature
    for t2, s2 in ((temp, seed), (0.7, seed + 1)):
        todo = [i for i in range(len(slots)) if names[i] is None and before[i].endswith("=")]
        if not todo:
            break
        ask = "\n".join(f"S{i + 1}: key '{before[i]}' values {list(dict.fromkeys(slots[i][1]))[:4]}"
                        + (f" (your earlier answer was rejected: {why[i]})" if i in why else "") for i in todo)
        out2, _ = llm_json(system, f"Template: {''.join(shown)}\nThese key=value slots still need a name. Name each one "
                           f"if a listed field fits and is not already used ({sorted(used)}), else none:\n{ask}",
                           SLOT_SCHEMA, t2, s2, 300)
        answers = {slot_key(d.get("slot")): (d.get("field") or "").strip() for d in (out2 or {}).get("slots", [])}
        retry_log.append(f"retry(T={t2}): {answers or 'no usable answer'}")
        for k2, f2 in answers.items():
            if k2 in {f"S{i + 1}" for i in todo}:
                chosen[k2] = f2
        names, used, why = validate(chosen)
    notes = [f"S{i + 1}: {w}" for i, w in sorted(why.items())] + retry_log
    pat, k = "^", 0
    for p in parts:
        if p[0] == "sep":
            pat += r"\s+"
        elif p[0] == "lit":
            pat += re.sub(r"\d+", r"\\d+", grok_escape(p[1]))     # other uids / codes must still match
        else:
            pat += "%{" + p[2] + (":" + names[k] if names[k] else "") + "}"
            k += 1
    return pat + "$", notes


def stage_c(msgs, log, exclude=()):
    """exclude: fields the header already extracts (process.name, host.name, ...) - not allowed again."""
    fields = "\n".join(f"- {k}: {d}" for k, (t, d) in TARGETS.items() if k not in exclude)
    system = C_SYSTEM.format(fields=fields)
    patterns, report = [], []
    for key, group in group_messages(msgs)[:MAX_GROUPS]:
        examples = list(dict.fromkeys(group))[:6]
        user = "Messages (same type):\n" + "\n".join(examples)
        chosen, notes, pat_prev, how = None, [], "", "template"
        parts = build_template(group)
        if parts is not None and not any(p[0] == "slot" for p in parts):
            report.append({"group": key, "messages": len(group), "pattern": None, "fields": [], "issues": [],
                           "how": "template: fixed text, no values"})
            log(f"    C  {len(group):4} × '{key[:40]}' -> nothing to extract (fixed text)")
            continue
        if parts is not None:
            tpat, tnotes = name_slots(parts, exclude)
            if tpat is not None:
                rate, issues, _ = check_message_pattern(tpat, group, exclude)
                if not issues:
                    chosen = tpat if names_in(tpat) else None
                    notes = tnotes if chosen else []
                    if not chosen:
                        report.append({"group": key, "messages": len(group), "pattern": None, "fields": [],
                                       "issues": [], "how": "template: no named values"})
                        log(f"    C  {len(group):4} × '{key[:40]}' -> nothing to extract (template)")
                        continue
        how = "template" if chosen else "llm-pattern"
        for attempt, (temp, seed) in enumerate([(0.0, sa.SEED), (0.7, sa.SEED + 1), (0.7, sa.SEED + 2)] if not chosen else [], 1):
            out, _ = llm_json(system, user + (f"\n\nYour previous pattern:\n{pat_prev}\nfailed: " + "; ".join(notes)
                                              if notes and pat_prev else ""), C_SCHEMA, temp, seed, 400)
            pat = ((out or {}).get("grok_pattern") or "").strip()
            if not pat:
                notes = ["no pattern returned"] if out is None else []
                if out is not None:
                    break                                  # model says: nothing to extract
                continue
            pat_prev = pat
            rate, issues, _ = check_message_pattern(pat, group, exclude)
            if not issues:
                chosen = "^" + pat.lstrip("^").rstrip("$") + "$"
                break
            notes = issues[:2]
        report.append({"group": key, "messages": len(group), "pattern": chosen, "how": how,
                       "fields": names_in(chosen) if chosen else [], "issues": notes})
        log(f"    C  {len(group):4} × '{key[:40]}' -> " + (f"{names_in(chosen)} ({how})"
                                                       + (f" | notes: {'; '.join(notes)[:300]}" if notes else "") if chosen else
                                                         ("nothing to extract" if not notes else f"✗ {notes[0][:90]}")))
        if chosen:
            patterns.append(chosen)
    return patterns, report


# --------------------------------------------------------------------------- stage D
D_SYSTEM = """Map each extracted log field onto ONE of the allowed hunt-index field names, or "drop" if none fits.
Allowed names:
{fields}
Use each allowed name at most once. Return JSON only: {{"mapping": [{{"field": "...", "target": "..."}}]}}"""
D_SCHEMA = {"type": "object", "properties": {"mapping": {"type": "array", "items": {"type": "object", "properties": {
    "field": {"type": "string"}, "target": {"type": "string"}}, "required": ["field", "target"]}}},
    "required": ["mapping"]}


def stage_d(docs, skip, log, pattern=""):
    """docs: sample outputs after header+C. Returns (rename dict, drop list, report)."""
    values = {}
    for d in docs:
        if d is None:
            continue
        for k, v in d.items():
            if k not in skip:
                values.setdefault(k, Counter())[str(v)] += 1
    taken = {k for k in values if k in TARGETS}
    todo = {k: [v for v, _ in c.most_common(4)] for k, c in values.items() if k not in TARGETS}
    rename, drop, report = {}, [], []
    # fields already named correctly: type check only
    for k in sorted(taken):
        bad = [v for v in values[k] if not type_ok(k, v)]
        if bad:
            drop.append(k)
            taken.discard(k)
            report.append({"field": k, "target": "drop", "why": f"values not {TARGETS[k][0]}: {bad[:2]}"})
    for k in list(todo):     # code first: obvious renames by name tokens (http.response.bytes -> http.response.body.bytes)
        kt = set(re.split(r"[._]", k.lower()))
        cands = [t for t in TARGETS if t not in taken and kt <= set(re.split(r"[._]", t)) and
                 all(type_ok(t, v) for v in values[k])]
        if len(cands) == 1:
            rename[k] = cands[0]
            taken.add(cands[0])
            report.append({"field": k, "examples": todo[k][:2], "target": cands[0], "why": "code: name tokens match"})
            log(f"    D  {k:28} -> {cands[0]:26} (code: name tokens match)")
            del todo[k]
    if todo:
        fields = "\n".join(f"- {k}: {d}" for k, (t, d) in TARGETS.items())
        user = (f"The fields come from this grok pattern (shows the text around each value):\n{pattern}\n\n"
                "Extracted fields with example values:\n" + "\n".join(f"- {k}: {v}" for k, v in todo.items()))
        out, _ = llm_json(D_SYSTEM.format(fields=fields), user, D_SCHEMA, 0.0, sa.SEED, 600)
        proposed = {m.get("field"): m.get("target") for m in (out or {}).get("mapping", [])}
        for k, examples in todo.items():
            t = proposed.get(k, "drop")
            why = "LLM: no fitting field"
            if t != "drop":
                if t not in TARGETS:
                    why, t = f"LLM proposed '{t}' (not an allowed name)", "drop"
                elif t in taken:
                    why, t = f"'{t}' already used", "drop"
                elif not all(type_ok(t, v) for v in values[k]):
                    why, t = f"values do not fit {t} ({TARGETS[t][0]})", "drop"
                else:
                    why = "LLM mapping, type-checked"
            if t == "drop":
                drop.append(k)
            else:
                rename[k] = t
                taken.add(t)
            report.append({"field": k, "examples": examples[:2], "target": t, "why": why})
            log(f"    D  {k:28} -> {t:26} ({why})")
    return rename, drop, report


# --------------------------------------------------------------------------- stage E
E_SYSTEM = """Classify log events with ordered rules. For each kind of event in the samples, write a rule that
recognises it from ONE field and gives event.action and event.outcome. The first matching rule wins.
Allowed event.action values (meaning):
{actions}
Allowed event.outcome values: {outcomes}. Allowed log.category values: {categories}.
event.outcome: "success" or "failure" ONLY when the event itself states it (e.g. Accepted / Failed password /
authentication failure / session opened); otherwise "unknown" (e.g. a request was logged, a packet was allowed or
dropped by a rule, a connection closed, a command was recorded).
If events of one kind differ in a field value (e.g. allowed vs dropped), write one rule per value.
Operators: "contains", "equals", "startswith", "always" (always = matches everything; use only for the last rule).
Use only fields shown in the samples. Return JSON only:
{{"log_category": "...", "rules": [{{"field": "...", "op": "...", "value": "...", "action": "...", "outcome": "..."}}]}}"""
E_SCHEMA = {"type": "object", "properties": {
    "log_category": {"type": "string"},
    "rules": {"type": "array", "items": {"type": "object", "properties": {
        "field": {"type": "string"}, "op": {"type": "string", "enum": ["contains", "equals", "startswith", "always"]},
        "value": {"type": "string"}, "action": {"type": "string"}, "outcome": {"type": "string"}},
        "required": ["field", "op", "value", "action", "outcome"]}}},
    "required": ["log_category", "rules"]}


def rule_matches(rule, doc):
    if rule["op"] == "always":
        return True
    v = doc.get(rule["field"])
    if v is None:
        return False
    v = str(v)
    return {"contains": rule["value"] in v, "equals": v == rule["value"],
            "startswith": v.startswith(rule["value"])}.get(rule["op"], False)


def stage_e(docs, body, log):
    sample_docs = [d for d in docs if d]
    # one representative per distinct (body shape or field-value signature)
    reps, seen = [], set()
    for d in sample_docs:
        sig = mask(str(d.get(body, ""))[:60]) + "|" + "|".join(
            mask(str(d.get(k, ""))) for k in ("rule.name", "process.name", "http.response.status_code"))
        if sig not in seen:
            seen.add(sig)
            reps.append({k: v for k, v in d.items() if k in TARGETS or k == body})
    reps = reps[:24]
    actions = "\n".join(f"- {k}: {v['description']} (outcome: {'/'.join(v['outcomes'])})"
                        for k, v in VOCAB["event.action"].items())
    system = E_SYSTEM.format(actions=actions, outcomes=VOCAB["event.outcome"], categories=VOCAB["log.category"])
    user = "Sample events (field: value):\n" + "\n".join(json.dumps(r) for r in reps)
    out, _ = llm_json(system, user, E_SCHEMA, 0.0, sa.SEED, 1200)
    rules, report = [], []
    specific = {str(d.get(f)) for d in sample_docs for f in ("user.name", "user.target.name", "host.name",
                                                             "source.ip", "destination.ip") if d.get(f)}
    cat = (out or {}).get("log_category")
    if cat not in VOCAB["log.category"]:
        report.append({"rule": "log_category", "status": "rejected", "why": f"'{cat}' not in vocabulary"})
        cat = "other"
    allowed_fields = set(TARGETS) | ({body} if body else set())
    proposed = list((out or {}).get("rules", []))
    # coverage round: events that only the catch-all would classify get one more, focused request
    def uncovered(rs):
        return [x for x in reps if not any(rule_matches(q, x) for q in rs if q.get("op") != "always"
                                           and q.get("action") in VOCAB["event.action"])]
    left = uncovered(proposed)
    if left:
        out2, _ = llm_json(system, "These events are NOT covered by any rule yet. Write rules for them only:\n"
                           + "\n".join(json.dumps(x) for x in left[:12]), E_SCHEMA, 0.0, sa.SEED, 800)
        extra = [q for q in (out2 or {}).get("rules", []) if q.get("op") != "always"]
        catch_all = [q for q in proposed if q.get("op") == "always"]
        proposed = [q for q in proposed if q.get("op") != "always"] + extra + catch_all
        log(f"    E  coverage round: {len(left)} event kinds had no rule -> {len(extra)} rules proposed")
    for r in proposed:
        why = None
        if r.get("action") not in VOCAB["event.action"]:
            why = f"action '{r.get('action')}' not in vocabulary"
        elif r.get("outcome") not in VOCAB["event.action"][r["action"]]["outcomes"]:
            allowed_o = VOCAB["event.action"][r["action"]]["outcomes"]
            if len(allowed_o) == 1:      # contract fixes the outcome for this action -> code sets it
                report.append({**r, "status": "corrected", "why": f"outcome '{r.get('outcome')}' -> '{allowed_o[0]}' "
                               f"(fixed for {r['action']})"})
                r = {**r, "outcome": allowed_o[0]}
            else:
                why = f"outcome '{r.get('outcome')}' not allowed for {r['action']}"
        if not why and r["op"] != "always" and any(v and v in r.get("value", "") for v in specific):
            why = "rule depends on one specific user/host/IP (not general)"
        if not why and r["op"] != "always" and r.get("field") not in allowed_fields:
            why = f"field '{r.get('field')}' not available"
        elif not why and not any(rule_matches(r, d) for d in sample_docs):
            why = "matches no sample event"
        report.append({**r, "status": "rejected" if why else "ok", "why": why})
        if not why:
            rules.append(r)
    # first match wins, so code orders rules most specific first (equals > startswith > contains, longer text
    # first, catch-all last): a broad 'contains "invalid user"' must not swallow 'Failed password for invalid user'
    rank = {"equals": 0, "startswith": 1, "contains": 2, "always": 3}
    rules.sort(key=lambda r: (rank.get(r["op"], 2), -len(str(r.get("value", "")))))
    covered = Counter()
    for d in sample_docs:
        hit = next((r for r in rules if rule_matches(r, d)), None)
        covered[(hit["action"], hit["outcome"]) if hit else ("other", "unknown")] += 1
    # log.category is decided by code from the event types the rules give (the AI's answer is only a fallback):
    # the model once answered something outside the vocabulary and the whole feed became 'other'
    by_type = Counter(ACTION_CATEGORY[a] for (a, _), n in covered.items() for _ in range(n) if a in ACTION_CATEGORY)
    if by_type:
        code_cat = by_type.most_common(1)[0][0]
        if code_cat != cat:
            report.append({"rule": "log_category", "status": "corrected",
                           "why": f"AI said '{(out or {}).get('log_category')}', event types say '{code_cat}'"})
        cat = code_cat
    log(f"    E  log.category={cat}; {len(rules)} rules kept, {sum(x['status'] == 'rejected' for x in report)} "
        f"rejected; result: " + ", ".join(f"{a}/{o}={n}" for (a, o), n in covered.most_common(8)))
    return cat, rules, report


# --------------------------------------------------------------------------- assemble
PROG_PID = re.compile(r"^([^\[\s]+)\[(\d+)\]:?$")
SPLIT_PROG = [{"grok": {"field": "process.name", "patterns": [r"^(?<process.name>[^\[\s]+)\[(?<process.pid>\d+)\]:?$"],
                        "ignore_missing": True, "ignore_failure": True}},
              {"convert": {"field": "process.pid", "type": "long", "ignore_missing": True}}]


def split_program(doc):
    """Code normalisation: 'sshd[7200]' captured as process.name -> process.name 'sshd' + process.pid 7200."""
    if doc and isinstance(doc.get("process.name"), str):
        m = PROG_PID.match(doc["process.name"])
        if m:
            doc["process.name"] = m.group(1)
            doc.setdefault("process.pid", m.group(2))
    return doc


def build_processors(header_procs, body, c_patterns, rename, drop, category, rules, captured):
    p = [{"set": {"field": "message", "copy_from": "raw_line", "if": "ctx.message == null && ctx.raw_line != null"}},
         {"set": {"field": "event.original", "copy_from": "message", "if": "ctx.event?.original == null"}}]
    p += header_procs
    if body and c_patterns:
        p.append({"grok": {"field": body, "patterns": c_patterns, "ignore_failure": True}})
    for src, dst in rename.items():
        p.append({"rename": {"field": src, "target_field": dst, "ignore_missing": True}})
    if drop:   # before stage E: a dropped field may sit on a derived name (e.g. raw text captured as event.action)
        p.append({"remove": {"field": sorted(drop), "ignore_missing": True}})
    if "process.name" in set(rename.values()) | set(captured):
        p += SPLIT_PROG
    for f in sorted(set(rename.values()) | (set(captured) - set(drop))):
        if f in TARGETS and TARGETS[f][0] == "int":
            p.append({"convert": {"field": f, "type": "long", "ignore_missing": True}})
        if f in LOWERCASE:
            p.append({"lowercase": {"field": f, "ignore_missing": True}})
    for r in rules:
        cond = "true" if r["op"] == "always" else {
            "contains": "{x} != null && {x}.toString().contains({v})",
            "equals": "{x} != null && {x}.toString() == {v}",
            "startswith": "{x} != null && {x}.toString().startsWith({v})"}[r["op"]].format(
                x=painless_path(r["field"]), v=painless_str(r["value"]))
        guard = f"ctx.event?.action == null && ({cond})"
        p.append({"set": {"field": "event.outcome", "value": r["outcome"], "if": guard}})
        p.append({"set": {"field": "event.action", "value": r["action"], "if": guard}})
    p += [{"set": {"field": "event.outcome", "value": "unknown", "if": "ctx.event?.outcome == null"}},
          {"set": {"field": "event.action", "value": "other", "if": "ctx.event?.action == null"}},
          {"set": {"field": "log.category", "value": category}}]
    temp = sorted((set(captured) | set(drop) | {"timestamp", body or "", *STAGING_ONLY, "event.dataset"})
                  - HUNT_FIELDS - set(rename.values()) - {""})
    if temp:
        p.append({"remove": {"field": temp, "ignore_missing": True}})
    moved = set(rename) | set(drop) | set(temp)
    parents = sorted({".".join(f.split(".")[:i]) for f in moved for i in range(1, f.count(".") + 1)},
                     key=lambda x: -x.count("."))
    for par in parents:          # e.g. network.packet.length -> network.bytes leaves an empty network.packet
        path = painless_path(par)
        p.append({"remove": {"field": par, "ignore_missing": True,
                             "if": f"{path} instanceof Map && {path}.isEmpty()"}})
    return p


def check_output(docs):
    """Every output field must exist in the strict hunt mapping and fit its type."""
    problems = Counter()
    for d in docs:
        if d is None:
            continue
        for k, v in d.items():
            if k not in HUNT_FIELDS:
                problems[f"field not in hunt mapping: {k}"] += 1
            elif k in TARGETS and not type_ok(k, v):
                problems[f"{k} has invalid value"] += 1
    return problems


def run_v4(header_pattern, ts, lines, log=print):
    """Stages C/D/E on top of the v3.3 header grok. Returns dict with processors and stage reports."""
    pattern, body, changed = fix_header(header_pattern)
    if changed:
        log(f"    header fix: lazy DATA before the message body merged into '{body}'")
    if not body:
        cand = header_cut(header_pattern)
        if cand:
            procs_try = sa.processors(cand, ts["formats"] if ts else None, ts["ts_pattern"] if ts else None)
            docs_try, _ = simulate_docs(procs_try, [{"message": l} for l in lines])
            if all(d and str(d.get("message_body", "")).strip() for d in docs_try):
                log(f"    header fix: the AI pattern had no message part; code kept the header "
                    f"({', '.join(n for n in names_in(cand) if n != 'message_body')}) and made the rest the message")
                pattern, body = cand, "message_body"
            else:
                log("    header fix: tried to split header/message, but not every line fits; kept the AI pattern")
    header_procs = sa.processors(pattern, ts["formats"] if ts else None, ts["ts_pattern"] if ts else None)
    base, err = simulate_docs(header_procs, [{"message": l} for l in lines])
    c_patterns, c_report = [], []
    groups = []
    if body:
        msgs = [d[body] for d in base if d and body in d]
        header_fields = {f for f in names_in(pattern) if f in TARGETS}
        c_patterns, c_report = stage_c(msgs, log, header_fields)
    groups = [k for k, _ in group_messages(msgs)] if body else []
    procs_c = header_procs + ([{"grok": {"field": body, "patterns": c_patterns, "ignore_failure": True}}]
                              if body and c_patterns else [])
    after_c, _ = simulate_docs(procs_c, [{"message": l} for l in lines])
    skip = {"message", "@timestamp", "timestamp", "event.dataset", body}
    rename, drop, d_report = stage_d(after_c, skip, log, pattern)
    renamed = [None if d is None else split_program({rename.get(k, k): v for k, v in d.items() if k not in drop})
               for d in after_c]
    category, rules, e_report = stage_e(renamed, body, log)
    captured = set(names_in(pattern)) | {n for p in c_patterns for n in names_in(p)}
    procs = build_processors(header_procs, body, c_patterns, rename, drop, category, rules, captured)
    final, err = simulate_docs(procs, [{"raw_line": l, "record_id": "r", "feed_name": "f"} for l in lines])
    problems = check_output(final)
    rate = sum(d is not None for d in final) / len(lines)
    log(f"    v4 pipeline: {rate:.0%} of lines processed; output check: " +
        ("✓ only hunt-index fields, types ok" if not problems else "; ".join(f"{k} ×{n}" for k, n in problems.most_common(3))))
    return {"header_pattern": pattern, "body_field": body, "message_patterns": c_patterns, "stage_c": c_report,
            "rename": rename, "drop": drop, "stage_d": d_report, "log_category": category, "rules": rules,
            "stage_e": e_report, "processors": procs, "parse_rate": rate,
            "output_problems": dict(problems), "error": err, "message_groups": groups}


def unseen_message_types(v4entry, ts, lines):
    """Message types in `lines` that a reused template never learned (it parses their header but not the message).
    Templates built before message types were recorded return [] (nothing to compare)."""
    known = set((v4entry or {}).get("message_groups") or [])
    body = (v4entry or {}).get("body_field")
    if not known or not body:
        return []
    procs = sa.processors(v4entry["header_pattern"], ts["formats"] if ts else None, ts["ts_pattern"] if ts else None)
    base, _ = simulate_docs(procs, [{"message": l} for l in lines])
    msgs = [d[body] for d in base if d and body in d]
    return [(k, len(v)) for k, v in group_messages(msgs) if k not in known]


def register_v4(source, v4, ts):
    name = f"logs-{re.sub(r'[^a-z0-9_-]', '-', source.lower())}"
    pipe = {"description": f"Schema Agent v4 template for {source}", "processors": v4["processors"],
            "_meta": {"created_by": "schema_agent_v4", "model": sa.MODEL}}
    status, resp = sa.http("PUT", f"{sa.ES_URL}/_ingest/pipeline/{name}", pipe)
    if status != 200:
        raise RuntimeError(f"pipeline registration failed: {sa.es_error(resp)}")
    reg = sa.load_json(sa.REGISTRY, [])
    for e in reg:
        if e["name"] == name:
            e.update(version="4", v4={k: v4[k] for k in ("header_pattern", "body_field", "message_patterns",
                                                           "rename", "drop", "log_category", "rules", "processors",
                                                           "message_groups") if k in v4})
    sa.REGISTRY.write_text(json.dumps(reg, indent=2))
    return name
