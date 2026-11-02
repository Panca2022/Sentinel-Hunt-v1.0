#!/usr/bin/env python3
"""
Schema Agent v3.3: turns an unrecognised log source into a validated, reusable
Elasticsearch ingest pipeline (Grok + timestamp).

Design: "the LLM proposes, code verifies and repairs".
  v3.1: Stage B runs FIRST. v3.2: code REMOVES the leading timestamp from the lines the LLM sees,
        the LLM writes the rest, code glues timestamp-grok + LLM-grok together.
  v3.3: strategy ENSEMBLE (whole-line vs timestamp-stripped, best wins) + stray-anchor repair.
  Stage A  (fields)    LLM writes best-of-3 Grok candidates -> ES _simulate on HELD-OUT lines
                       -> code auto-repair (whitespace, over-strict types) -> LLM retry with pinpoint diagnosis (<=3 rounds)
  Stage B  (timestamp) code tries a library of known date layouts; keeps the one that parses
                       >=95% with the narrowest date span (disambiguates yyMMdd vs MMddyy)
  Register             ES ingest pipeline logs-<source> + registry.json

History: v1 = single LLM attempt + retry (3/5 on Loghub). v2 = also asked LLM for date formats
-> worse (2/5): small model can't do both, and ignores feedback. v3 splits the jobs.

Usage:
  python3 schema_agent.py --check-library
  python3 schema_agent.py --file samples/HDFS_2k.log --source hdfs --fresh
  python3 schema_agent.py --eval samples/*.log --fresh

Env: ES_URL (http://localhost:9200), OLLAMA_URL (http://localhost:11434), MODEL (qwen3:14b)
Standard library only.
"""
import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

ES_URL = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("MODEL", "qwen3:14b")

HERE = Path(__file__).resolve().parent
LIBRARY = HERE / "example_library.json"
REGISTRY = HERE / "registry.json"
RUNS = HERE / "runs"

PARSE_THRESHOLD = 0.95    # share of held-out lines that must parse (grok + date)
MIN_FIELDS = 3            # avg extracted fields per line (excluding message/@timestamp)
MAX_ATTEMPTS = 3
GEN_N = 20                # lines shown to the LLM
VAL_N = 100               # held-out lines used for validation
SEED = 42
MAX_OUT_TOKENS = 1024     # a grok answer needs ~200; stops runaway generations
LLM_TIMEOUT_S = 90
YEAR_MIN, YEAR_MAX = 1990, 2035
MAX_SPAN_YEARS = 3        # a single log sample spanning more than this => likely wrong field order

# Known timestamp layouts: (name, grok that captures `timestamp`, Java formats). Stage B tries all.
TS_CANDIDATES = [
    ("syslog", r"^%{SYSLOGTIMESTAMP:timestamp}", ["MMM d HH:mm:ss", "MMM  d HH:mm:ss"]),
    ("iso8601", r"^%{TIMESTAMP_ISO8601:timestamp}",
     ["yyyy-MM-dd HH:mm:ss,SSS", "yyyy-MM-dd HH:mm:ss.SSS", "yyyy-MM-dd HH:mm:ss", "ISO8601"]),
    ("bracket-ctime", r"^\[(?<timestamp>%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR})\]",
     ["EEE MMM dd HH:mm:ss yyyy", "EEE MMM d HH:mm:ss yyyy"]),
    ("httpdate", r"\[%{HTTPDATE:timestamp}\]", ["dd/MMM/yyyy:HH:mm:ss Z"]),
    ("slash-date", r"^(?<timestamp>%{YEAR}/%{MONTHNUM}/%{MONTHDAY} %{TIME})", ["yyyy/MM/dd HH:mm:ss"]),
    ("compact-yyMMdd", r"^(?<timestamp>\d{6} \d{6})", ["yyMMdd HHmmss"]),
    ("compact-MMddyy", r"^(?<timestamp>\d{6} \d{6})", ["MMddyy HHmmss"]),
    ("compact-ddMMyy", r"^(?<timestamp>\d{6} \d{6})", ["ddMMyy HHmmss"]),
    ("compact-yyyyMMdd", r"^(?<timestamp>\d{8}[-T ]?\d{2}:?\d{2}:?\d{2})",
     ["yyyyMMdd-HH:mm:ss", "yyyyMMdd-HHmmss", "yyyyMMddHHmmss", "yyyyMMdd HH:mm:ss"]),
    ("epoch", r"^(?<timestamp>\d{10})(?:\.\d+)?\b", ["UNIX"]),
]

SYSTEM = """You are the Schema Agent in a security log ingestion pipeline.
Given sample lines from ONE log source, write ONE Elasticsearch grok pattern that parses EVERY line.

Rules:
- Elasticsearch grok processor syntax. Useful built-in patterns: SYSLOGTIMESTAMP, TIMESTAMP_ISO8601, HTTPDATE,
  YEAR, MONTHNUM, MONTHDAY, MONTH, DAY, TIME, HOUR, MINUTE, SECOND, IP, IPORHOST, HOSTNAME, INT, POSINT,
  NUMBER, WORD, NOTSPACE, LOGLEVEL, JAVACLASS, PATH, USER, DATA, GREEDYDATA, QUOTEDSTRING.
- The pattern must match each line from its first character. Escape literal regex characters:
  \\[ \\] \\( \\) \\. \\* \\? \\| \\{ \\} \\$
- Look carefully at whitespace: where columns are padded or spacing varies (e.g. "INFO  [" vs "WARN  ["),
  use \\s+ instead of a single space.
- If lines have different layouts, use optional groups (?: ... )? or alternation (?:A|B).
- Prefer specific patterns (INT, IP, WORD, LOGLEVEL) for structured parts. Prefer a single trailing
  GREEDYDATA named log_message for free text.
- Name a field only for what it clearly is. If unsure, use a neutral name (e.g. thread_id, code, value_1)
  instead of guessing. Never name a field "message" or "@timestamp". Use ECS names where obvious:
  host.hostname, process.name, process.pid, log.level, log.logger, source.ip, source.port, destination.ip,
  destination.port, user.name, event.action, url.original, http.response.status_code.
- Custom named groups (?<snake_case_name>regex) must not contain dots in the name.
- Extract at least 3 fields besides log_message.
Return JSON only: {"grok_pattern": "...",
"event_type": "authentication|web|network|application|system|other", "fields": ["field names"]}"""

OUT_SCHEMA = {
    "type": "object",
    "properties": {
        "grok_pattern": {"type": "string"},
        "event_type": {"type": "string"},
        "fields": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["grok_pattern", "event_type", "fields"],
}


# --------------------------------------------------------------------------- HTTP
# Set by the MCP backend for the secure kit ES (Basic auth + CA). Never shown to the model.
ES_HEADERS = {}
ES_SSL = None


def http(method, url, body=None, timeout=600):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    ctx = None
    if url.startswith(ES_URL):
        headers.update(ES_HEADERS)
        ctx = ES_SSL
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw.decode(errors="replace")[:500]}


def es_error(resp):
    err = resp.get("error")
    if isinstance(err, dict):
        rc = err.get("root_cause") or [{}]
        return rc[0].get("reason") or err.get("reason") or json.dumps(err)[:300]
    return str(err)[:300]


# --------------------------------------------------------------------------- Validation (ES)
def leaves(d, prefix=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from leaves(v, prefix + k + ".")
        else:
            yield prefix + k


def processors(pattern, formats=None, ts_pattern=None):
    procs = []
    if pattern:
        procs.append({"grok": {"field": "message", "patterns": [pattern]}})
    if ts_pattern:
        procs.append({"grok": {"field": "message", "patterns": [ts_pattern]}})
    if formats:
        procs.append({"date": {"field": "timestamp", "target_field": "@timestamp", "formats": formats}})
    return procs


def simulate(pattern, lines, formats=None, batch=500, ts_pattern=None):
    """Run grok (+ date) through ES _simulate. Returns parse statistics."""
    ok, fields_total, failed, example = 0, 0, [], None
    reasons, years = Counter(), []
    for i in range(0, len(lines), batch):
        chunk = lines[i:i + batch]
        body = {"pipeline": {"processors": processors(pattern, formats, ts_pattern)},
                "docs": [{"_source": {"message": l}} for l in chunk]}
        status, resp = http("POST", f"{ES_URL}/_ingest/pipeline/_simulate", body)
        if status != 200:
            return {"valid": False, "error": es_error(resp), "parse_rate": 0.0, "avg_fields": 0.0,
                    "failed_lines": [], "example": None, "reasons": [], "years": []}
        for line, d in zip(chunk, resp.get("docs", [])):
            if "error" in d or "doc" not in d:
                failed.append(line)
                err = d.get("error", {})
                reason = err.get("reason") or err.get("type") or "no match"
                if reason.startswith("Provided Grok expressions do not match"):
                    reason = "grok did not match"
                reasons[reason[:160]] += 1
                continue
            src = d["doc"]["_source"]
            ts = src.get("@timestamp")
            if isinstance(ts, str) and ts[:4].isdigit():
                years.append(int(ts[:4]))
            ok += 1
            fields_total += len([k for k in leaves(src) if k not in ("message", "@timestamp")])
            if example is None:
                example = {k: v for k, v in src.items() if k != "message"}
    n = len(lines)
    return {"valid": True, "error": None, "parse_rate": ok / n if n else 0.0,
            "avg_fields": fields_total / ok if ok else 0.0, "failed_lines": failed, "example": example,
            "reasons": reasons.most_common(3), "years": years}


def quality(pattern, stats):
    """Stage A gate. Returns (issues that fail validation, warnings that are only logged)."""
    issues, warnings = [], []
    if not stats["valid"]:
        return [f"Elasticsearch rejected the pattern: {stats['error']}"], warnings
    if stats["parse_rate"] < PARSE_THRESHOLD:
        issues.append(f"only {stats['parse_rate']:.0%} of unseen lines parsed (need {PARSE_THRESHOLD:.0%})")
    if stats["avg_fields"] < MIN_FIELDS:
        issues.append(f"only {stats['avg_fields']:.1f} fields extracted per line (need >= {MIN_FIELDS})")
    if re.fullmatch(r"\s*%\{GREEDYDATA(:[\w.]+)?\}\s*", pattern):
        issues.append("pattern is a catch-all")
    if pattern.count("GREEDYDATA") > 1:
        warnings.append("GREEDYDATA used more than once")
    return issues, warnings


def score(stats, issues):
    return (not issues, stats["parse_rate"], stats["avg_fields"])


def auto_repairs(pattern):
    """Deterministic repairs tried before asking the LLM again."""
    out = []
    anchors = re.sub(r"(?<!\\)\$(?!$)", "", pattern)         # stray $ in the middle (qwen quirk)
    anchors = re.sub(r"(?<!^)(?<!\\)(?<!\[)\^", "", anchors)  # stray ^ not at start / not in [^..]
    if anchors != pattern:
        out.append(("stray-anchors", anchors))
    for base_name, base in [("", pattern)] + ([("stray-anchors+", anchors)] if anchors != pattern else []):
        ws = re.sub(r"(?<!\\) +", r"\\s+", base)           # single/multiple spaces -> \s+
        if ws != base:
            out.append((base_name + "whitespace", ws))
    return out


def detect_timestamp(lines):
    """Stage B: pick the known timestamp layout that parses >=95% with the narrowest date span."""
    results = []
    for name, ts_pat, formats in TS_CANDIDATES:
        st = simulate(None, lines, formats, ts_pattern=ts_pat)
        ys = st["years"]
        if not st["valid"] or st["parse_rate"] < PARSE_THRESHOLD or not ys:
            continue
        if any(not YEAR_MIN <= y <= YEAR_MAX for y in ys):
            continue
        span = max(ys) - min(ys)
        if span > MAX_SPAN_YEARS:
            continue
        results.append({"name": name, "ts_pattern": ts_pat, "formats": formats,
                        "parse_rate": st["parse_rate"], "span": span, "years": [min(ys), max(ys)]})
    results.sort(key=lambda r: (-r["parse_rate"], r["span"]))
    return results[0] if results else None


def ts_prefix(ts):
    """Anchored timestamp grok (without ^) + optional whitespace, or None."""
    if ts and ts["ts_pattern"].startswith("^"):
        return ts["ts_pattern"][1:] + r"\s*"
    return None


def after_timestamp(lines, ts):
    """Text of each line after its leading timestamp (code strips it before the LLM sees the line)."""
    pre = ts_prefix(ts)
    if not pre:
        return list(lines)
    body = {"pipeline": {"processors": [{"grok": {"field": "message",
                                                  "patterns": ["^" + pre + "(?<schema_rest>.*)"]}}]},
            "docs": [{"_source": {"message": l}} for l in lines]}
    status, resp = http("POST", f"{ES_URL}/_ingest/pipeline/_simulate", body)
    if status != 200:
        return list(lines)
    out = []
    for l, d in zip(lines, resp.get("docs", [])):
        out.append(d["doc"]["_source"].get("schema_rest", l) if "doc" in d else l)
    return out


def combine(ts, rest_pattern):
    pre = ts_prefix(ts)
    rest_pattern = rest_pattern.lstrip("^")
    return pre + rest_pattern if pre else rest_pattern


# --------------------------------------------------------------------------- Diagnosis
def split_top_level(pattern):
    """Split a grok pattern into pieces at top-level spaces (outside (), {}, [] and escapes)."""
    pieces, cur, depth, i = [], "", 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            cur += pattern[i:i + 2]
            i += 2
            continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth = max(0, depth - 1)
        cur += c
        if c == " " and depth == 0:
            pieces.append(cur)
            cur = ""
        i += 1
    if cur:
        pieces.append(cur)
    return pieces


def failing_piece(pattern, line):
    """(pieces, index of the first piece that fails on `line`, text left at that point); index None = all match."""
    pieces = split_top_level(pattern)
    best_k, best_rest = 0, line
    for k in range(1, len(pieces) + 1):
        prefix = "^" + "".join(pieces[:k]) + "(?<diag_rest>.*)"
        body = {"pipeline": {"processors": [{"grok": {"field": "message", "patterns": [prefix]}}]},
                "docs": [{"_source": {"message": line}}]}
        status, resp = http("POST", f"{ES_URL}/_ingest/pipeline/_simulate", body)
        if status != 200:
            break
        d = resp.get("docs", [{}])[0]
        if "doc" not in d:
            break
        best_k, best_rest = k, d["doc"]["_source"].get("diag_rest", "")
    return pieces, (None if best_k == len(pieces) else best_k), best_rest


STRICT_TYPES = r"HOSTNAME|IPORHOST|SYSLOGHOST|HOST|IPV4|IPV6|IP|WORD|USERNAME|USER|PROG|POSINT|NONNEGINT|INT|NUMBER"


def relax_repairs(pattern, failed_line, max_steps=4):
    """Code repair: the piece that fails on a real line has a too-strict grok type (e.g. HOSTNAME rejects
    'host_001') -> swap that piece's strict types for NOTSPACE and test the next failure. Yields each step."""
    out, cur = [], pattern
    for _ in range(max_steps):
        pieces, k, _rest = failing_piece(cur, failed_line)
        if k is None:
            break
        relaxed = re.sub(r"%\{(?:" + STRICT_TYPES + r")(:[^}]*)?\}", r"%{NOTSPACE\1}", pieces[k])
        if relaxed == pieces[k]:
            break                                   # nothing strict to relax: leave it to the LLM retry
        cur = "".join(pieces[:k]) + relaxed + "".join(pieces[k + 1:])
        out.append(cur)
    return out


HEADER_NAMES = {"timestamp", "host.hostname", "host.name", "hostname", "host", "logsource", "process.name", "program",
                "process.pid", "pid", "syslog_hostname", "syslog_program", "syslog_pid", "log.level", "level",
                "loglevel", "severity", "service", "app", "application", "process", "proc", "daemon", "facility",
                "priority", "syslog_facility", "syslog_severity", "source_host"}
_CAPTURE = re.compile(r"%\{\w+(?::([\w.@]+))?(?::\w+)?\}|\(\?<([\w.]+)>")


def header_cut(pattern):
    """Code repair: keep only the leading pieces of a line pattern that capture header fields (time, host, program,
    pid, level) and make the rest of the line the message (%{GREEDYDATA:message_body}). The header is the same on
    every line of a source, so this passes even when the AI's description of the message part does not; the message
    is parsed later (stage C, one message type at a time). Returns the candidate or None."""
    pieces = split_top_level(pattern or "")
    k = 0
    for piece in pieces:
        names = [a or b for a, b in _CAPTURE.findall(piece) if a or b]
        if not names or not set(names) <= HEADER_NAMES:
            break
        k += 1
    if k < 2 or k == len(pieces):
        return None
    head = "".join(pieces[:k])
    if not head.endswith((" ", "\\s+", "\\s*")):
        head += "\\s*"
    return head + "%{GREEDYDATA:message_body}"


def diagnose(pattern, line):
    """Find how far the pattern matches `line`; return a human-readable hint for the model."""
    pieces, best_k, best_rest = failing_piece(pattern, line)
    if best_k is None:
        return None
    matched = "".join(pieces[:best_k]).strip() or "(nothing)"
    nxt = pieces[best_k].strip()
    return (f"On this line:\n{line[:300]}\n"
            f"your pattern matches up to and including: {matched}\n"
            f"then the next part `{nxt}` fails. The remaining text at that point is: {best_rest[:120]!r}")


# --------------------------------------------------------------------------- Sampling & retrieval
def shape(line, n=80):
    s = re.sub(r"[A-Za-z]+", "a", line[:n])
    return re.sub(r"\d+", "0", s)


def trigrams(s):
    return {s[i:i + 3] for i in range(max(1, len(s) - 2))}


def similarity(lines_a, lines_b):
    a = set().union(*(trigrams(shape(l)) for l in lines_a))
    b = set().union(*(trigrams(shape(l)) for l in lines_b))
    return len(a & b) / len(a | b) if a | b else 0.0


def split_samples(lines):
    """Diverse generation lines (one per layout first), then a disjoint held-out validation set."""
    rng = random.Random(SEED)
    by_layout = {}
    for l in lines:
        by_layout.setdefault(shape(l, 40), []).append(l)
    gen = [rng.choice(v) for v in by_layout.values()]
    rng.shuffle(gen)
    gen = gen[:GEN_N]
    used = set(gen)
    rest = [l for l in lines if l not in used]
    if len(gen) < GEN_N:
        gen += rng.sample(rest, min(GEN_N - len(gen), len(rest)))
        used = set(gen)
        rest = [l for l in rest if l not in used]
    val = rng.sample(rest, min(VAL_N, len(rest)))
    return gen, val


# --------------------------------------------------------------------------- LLM
def llm(messages, temperature=0.0, seed=SEED):
    body = {"model": MODEL, "messages": messages, "stream": False, "format": OUT_SCHEMA,
            "options": {"temperature": temperature, "seed": seed, "num_ctx": 8192,
                        "num_predict": MAX_OUT_TOKENS}}
    if MODEL.startswith("qwen3"):
        body["think"] = False
    t0 = time.perf_counter()
    try:
        status, resp = http("POST", f"{OLLAMA_URL}/api/chat", body, timeout=LLM_TIMEOUT_S)
    except Exception as e:                      # timeout / runaway generation -> failed candidate
        return "", {"in_tokens": 0, "out_tokens": 0, "seconds": round(time.perf_counter() - t0, 2),
                    "temperature": temperature, "seed": seed, "error": f"LLM call failed: {e}"}
    wall = time.perf_counter() - t0
    if status != 200:
        raise RuntimeError(f"Ollama error {status}: {resp}")
    content = resp.get("message", {}).get("content", "")
    usage = {"in_tokens": resp.get("prompt_eval_count", 0), "out_tokens": resp.get("eval_count", 0),
             "seconds": round(wall, 2), "temperature": temperature, "seed": seed}
    return content, usage


def build_prompt(source, gen_lines, examples, ts=None, stripped=False):
    ex = "\n\n".join(
        f"Example {i + 1} ({e['name']}, event_type={e['event_type']}):\n" + "\n".join(e["example_lines"])
        + f"\nGrok: {e['grok_pattern']}"
        for i, e in enumerate(examples))
    samples = "\n".join(l[:400] for l in gen_lines)
    hint = ""
    if stripped:
        hint = ("\n\nNOTE: each line's leading TIMESTAMP has already been removed above (code handles it). "
                "Write the pattern for these remaining lines only, starting at their first character.")
    return (f"Reference examples of known formats (for style only, the new source differs):\n\n{ex}\n\n"
            f"New unrecognised source: '{source}'. Sample lines:\n{samples}{hint}\n\n"
            "Write the grok pattern for the new source.")


# --------------------------------------------------------------------------- Registry
def load_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return default


def register(source, result, gen_lines):
    reg = load_json(REGISTRY, [])
    name = f"logs-{re.sub(r'[^a-z0-9_-]', '-', source.lower())}"
    pipeline = {
        "description": f"Schema Agent template for {source}",
        "processors": processors(result["grok_pattern"], result.get("timestamp_formats"),
                                 result.get("ts_pattern"))
        + [{"set": {"field": "event.dataset", "value": source}}],
        "_meta": {"created_by": "schema_agent", "model": MODEL, "event_type": result["event_type"]},
    }
    status, resp = http("PUT", f"{ES_URL}/_ingest/pipeline/{name}", pipeline)
    if status != 200:
        raise RuntimeError(f"pipeline registration failed: {es_error(resp)}")
    entry = {"name": name, "source": source, "grok_pattern": result["grok_pattern"],
             "ts_pattern": result.get("ts_pattern"), "timestamp_formats": result.get("timestamp_formats"),
             "event_type": result["event_type"],
             "fields": result["fields"], "parse_rate": result["parse_rate"], "avg_fields": result["avg_fields"],
             "example_lines": gen_lines[:3], "model": MODEL,
             "created": datetime.now().isoformat(timespec="seconds")}
    reg = [r for r in reg if r["name"] != name] + [entry]
    REGISTRY.write_text(json.dumps(reg, indent=2))
    return name


# --------------------------------------------------------------------------- Agent
def process(path, source, fresh=False, do_register=True, verbose=True):
    log = (lambda *a: print(*a, flush=True)) if verbose else (lambda *a: None)
    lines = [l.rstrip("\n") for l in open(path, encoding="utf-8", errors="replace") if l.strip()]
    gen, val = split_samples(lines)
    t_start = time.perf_counter()
    run = {"source": source, "file": str(path), "model": MODEL, "version": "3.3", "lines_total": len(lines),
           "gen_lines": len(gen), "val_lines": len(val), "attempts": [], "outcome": None}
    log(f"\n[{source}] {len(lines)} lines | {len(gen)} for generation, {len(val)} held out for validation")

    # 1. Match registry (reuse)
    if not fresh:
        for t in load_json(REGISTRY, []):
            st = simulate(t["grok_pattern"], val)
            issues, _ = quality(t["grok_pattern"], st)
            if not issues:
                full = simulate(t["grok_pattern"], lines, t.get("timestamp_formats"), ts_pattern=t.get("ts_pattern"))
                log(f"  ✓ matched existing template {t['name']} ({st['parse_rate']:.0%})")
                run.update(outcome="matched", template=t["name"], grok_pattern=t["grok_pattern"],
                           parse_rate=st["parse_rate"], full_file_parse_rate=round(full["parse_rate"], 3),
                           avg_fields=round(st["avg_fields"], 1), example_parsed=full["example"])
                return finish(run, t_start)

    # 2. Retrieve similar examples
    lib = load_json(LIBRARY, [])
    ranked = sorted(lib, key=lambda e: similarity(gen, e["example_lines"]), reverse=True)[:3]
    log("  examples: " + ", ".join(e["name"] for e in ranked))
    # 3. Stage B first (code): solve the timestamp, then hand it to the LLM as a fixed prefix
    ts = detect_timestamp(val)
    if ts:
        log(f"  timestamp: {ts['name']} {ts['formats'][0]!r} -> dates {ts['years'][0]}-{ts['years'][1]}")
    else:
        log("  timestamp: no known layout matched (will register without @timestamp; warning)")
    # 4. Stage A: strategy ensemble -> best-of-N -> auto-repair -> diagnosed retry
    #    "full"     : LLM sees whole lines and writes the whole pattern
    #    "stripped" : code removes the leading timestamp; LLM writes the rest; code glues them together
    strategies = {"full": {"ts": None, "messages": [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": build_prompt(source, gen, ranked)}]}}
    if ts_prefix(ts):
        strategies["stripped"] = {"ts": ts, "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": build_prompt(source, after_timestamp(gen, ts), ranked, ts, stripped=True)}]}

    def run_candidates(rnd, name, n):
        strat, cands = strategies[name], []
        for i in range(n):
            temp, seed = (0.0, SEED) if i == 0 else (0.7, SEED + 100 * rnd + i)
            content, usage = llm(strat["messages"], temp, seed)
            rec = {"round": rnd, "strategy": name, "candidate": i + 1, **usage}
            try:
                out = json.loads(content)
                llm_pattern = out["grok_pattern"]
            except Exception:
                rec["error"] = usage.get("error") or "invalid JSON / truncated output from model"
                run["attempts"].append(rec)
                continue
            pattern = combine(strat["ts"], llm_pattern)
            st = simulate(pattern, val)
            issues, warnings = quality(pattern, st)
            rec.update(grok_pattern=pattern, parse_rate=round(st["parse_rate"], 3),
                       avg_fields=round(st["avg_fields"], 1), issues=issues, warnings=warnings)
            run["attempts"].append(rec)
            cands.append({"score": score(st, issues), "content": content, "out": out, "pattern": pattern,
                          "llm_pattern": llm_pattern, "st": st, "issues": issues, "strategy": name})
        return cands

    winner, current = None, None
    for rnd in range(1, MAX_ATTEMPTS + 1):
        if rnd == 1:
            names = list(strategies)
            n = 3 if len(names) == 1 else 2
        else:
            names, n = [current], 2
        cands = [c for name in names for c in run_candidates(rnd, name, n)]
        if not cands:
            log(f"  round {rnd}: no usable output from the model")
            continue
        cands.sort(key=lambda c: c["score"], reverse=True)
        best = cands[0]
        current = best["strategy"]
        st, issues = best["st"], best["issues"]
        rates = ", ".join(f"{c['strategy'][0]}:{c['st']['parse_rate']:.0%}" for c in cands)
        log(f"  round {rnd}: {len(cands)} candidates [{rates}] -> best ({current}) {st['parse_rate']:.0%}, "
            f"{st['avg_fields']:.1f} fields/line" + (" ✓" if not issues else f" | {'; '.join(issues)}"))
        if not issues:
            winner = (best["out"], best["pattern"], st, f"llm:{current}")
            break
        # auto-repair (code) on the best candidate
        strat_ts = strategies[current]["ts"]
        for how, fixed_rest in auto_repairs(best["llm_pattern"]):
            fixed = combine(strat_ts, fixed_rest)
            st2 = simulate(fixed, val)
            issues2, _ = quality(fixed, st2)
            run["attempts"].append({"round": rnd, "strategy": current, "repair": how, "grok_pattern": fixed,
                                    "parse_rate": round(st2["parse_rate"], 3), "issues": issues2})
            log(f"    auto-repair ({how}): {st2['parse_rate']:.0%}" + (" ✓" if not issues2 else ""))
            if not issues2:
                winner = (best["out"], fixed, st2, f"llm:{current}+repair:{how}")
                break
        if not winner and st["valid"] and st["failed_lines"]:
            # relax over-strict types on the piece that fails (code repair, re-validated like everything else)
            line0 = (after_timestamp(st["failed_lines"][:1], strat_ts) if strat_ts else st["failed_lines"][:1])[0]
            for step, fixed_rest in enumerate(relax_repairs(best["llm_pattern"], line0), 1):
                fixed = combine(strat_ts, fixed_rest)
                st2 = simulate(fixed, val)
                issues2, _ = quality(fixed, st2)
                run["attempts"].append({"round": rnd, "strategy": current, "repair": f"relax-types-{step}",
                                        "grok_pattern": fixed, "parse_rate": round(st2["parse_rate"], 3),
                                        "issues": issues2})
                log(f"    auto-repair (relax over-strict type, step {step}): {st2['parse_rate']:.0%}"
                    + (" ✓" if not issues2 else ""))
                if not issues2:
                    winner = (best["out"], fixed, st2, f"llm:{current}+repair:relax-types")
                    break
        if not winner:
            # header + message: keep the header the AI got right, leave the message to stage C (code repair)
            for c in cands:
                cut = header_cut(c["llm_pattern"])
                if not cut:
                    continue
                fixed = combine(strategies[c["strategy"]]["ts"], cut)
                st2 = simulate(fixed, val)
                issues2, _ = quality(fixed, st2)
                run["attempts"].append({"round": rnd, "strategy": c["strategy"], "repair": "header-cut",
                                        "grok_pattern": fixed, "parse_rate": round(st2["parse_rate"], 3),
                                        "issues": issues2})
                log(f"    auto-repair (keep header, rest = message for stage C): {st2['parse_rate']:.0%}"
                    + (" ✓" if not issues2 else ""))
                if not issues2:
                    winner = (c["out"], fixed, st2, f"llm:{c['strategy']}+repair:header-cut")
                    break
        if winner:
            break
        # diagnosed feedback for the winning strategy's conversation
        fb = [f"Validation on {len(val)} unseen lines from the same source failed: " + "; ".join(issues) + "."]
        if st["valid"] and st["failed_lines"]:
            shown = after_timestamp(st["failed_lines"][:4], strat_ts) if strat_ts else st["failed_lines"][:4]
            hint = diagnose(best["llm_pattern"], shown[0])
            if hint:
                fb.append("DIAGNOSIS: " + hint)
                log("    diagnosis: " + hint.splitlines()[-1][:110])
            fb.append("Other lines that did NOT match:\n" + "\n".join(l[:300] for l in shown[1:4]))
        fb.append("Write a corrected pattern that fixes exactly this problem. Return the full JSON.")
        strategies[current]["messages"] += [{"role": "assistant", "content": best["content"]},
                                            {"role": "user", "content": "\n\n".join(fb)}]

    if not winner:
        log("  ✗ no passing pattern after 3 rounds -> flagged 'needs human'")
        run.update(outcome="needs_human")
        return finish(run, t_start)

    out, pattern, st, how = winner

    full = simulate(pattern, lines, ts["formats"] if ts else None, ts_pattern=ts["ts_pattern"] if ts else None)
    result = {**out, "grok_pattern": pattern, "parse_rate": st["parse_rate"], "avg_fields": st["avg_fields"],
              "ts_pattern": ts["ts_pattern"] if ts else None, "timestamp_formats": ts["formats"] if ts else None}
    run.update(outcome="generated", solved_by=how, grok_pattern=pattern, event_type=out.get("event_type"),
               timestamp=ts, parse_rate=st["parse_rate"], full_file_parse_rate=round(full["parse_rate"], 3),
               avg_fields=round(st["avg_fields"], 1), date_range=ts["years"] if ts else None,
               example_parsed=full["example"])
    log(f"  full file: {full['parse_rate']:.1%} of {len(lines)} lines parse (fields + timestamp)")
    if do_register:
        run["template"] = register(source, result, gen)
        log(f"  registered ES ingest pipeline: {run['template']}")
    return finish(run, t_start)


def finish(run, t_start):
    run["seconds_total"] = round(time.perf_counter() - t_start, 1)
    run["tokens_total"] = sum(a.get("in_tokens", 0) + a.get("out_tokens", 0) for a in run["attempts"])
    RUNS.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    (RUNS / f"{run['source']}-{stamp}.json").write_text(json.dumps(run, indent=2, default=str))
    return run


# --------------------------------------------------------------------------- CLI
def check_es():
    try:
        status, _ = http("GET", ES_URL, timeout=10)
        return status == 200
    except Exception:
        return False


def check_library():
    ok_all = True
    for e in load_json(LIBRARY, []):
        st = simulate(e["grok_pattern"], e["example_lines"], e.get("timestamp_formats"))  # library grok has `timestamp`
        ok = st["valid"] and st["parse_rate"] == 1.0
        ok_all &= ok
        detail = (f"{st['parse_rate']:.0%} parsed, {st['avg_fields']:.1f} fields, years {sorted(set(st['years']))}"
                  if st["valid"] else st["error"])
        if st["valid"] and st["reasons"]:
            detail += f" | {st['reasons'][0][0]}"
        print(f"  {'✓' if ok else '✗'} {e['name']}: {detail}")
    return ok_all


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file")
    ap.add_argument("--source")
    ap.add_argument("--eval", nargs="+", metavar="FILE")
    ap.add_argument("--fresh", action="store_true", help="ignore registry (force generation)")
    ap.add_argument("--no-register", action="store_true")
    ap.add_argument("--check-library", action="store_true")
    a = ap.parse_args()

    if not check_es():
        sys.exit(f"Elasticsearch not reachable at {ES_URL}. Start it: docker compose -f dev/docker-compose.dev.yml up -d")

    if a.check_library:
        sys.exit(0 if check_library() else 1)

    if a.eval:
        rows = []
        for f in a.eval:
            src = Path(f).stem.replace("_2k", "").lower()
            rows.append(process(f, src, fresh=a.fresh, do_register=not a.no_register))
        print(f"\n=== EVALUATION ({MODEL}, agent v3.3) ===")
        print("source | outcome | solved by | LLM calls | val parse | full-file parse | fields/line | timestamp | dates | seconds | tokens")
        for r in rows:
            dr = r.get("date_range")
            calls = sum(1 for x in r["attempts"] if "candidate" in x)
            tsn = (r.get("timestamp") or {}).get("name", "-")
            print(f"{r['source']} | {r['outcome']} | {r.get('solved_by', '-')} | {calls} | {r.get('parse_rate', 0):.0%} | "
                  f"{r.get('full_file_parse_rate', 0):.0%} | {r.get('avg_fields', '-')} | {tsn} | "
                  f"{f'{dr[0]}-{dr[1]}' if dr else '-'} | {r['seconds_total']} | {r['tokens_total']}")
        ok = sum(r["outcome"] in ("generated", "matched") for r in rows)
        print(f"\n{ok}/{len(rows)} sources schematised automatically. Run logs: {RUNS}/")
        return

    if not a.file:
        ap.error("use --file, --eval or --check-library")
    r = process(a.file, a.source or Path(a.file).stem.lower(), fresh=a.fresh, do_register=not a.no_register)
    print(f"\nOutcome: {r['outcome']} in {r['seconds_total']}s, {len(r['attempts'])} attempt(s), "
          f"{r['tokens_total']} tokens")
    if r.get("grok_pattern"):
        print(f"Grok: {r['grok_pattern']}")
        print(f"timestamp: {(r.get('timestamp') or {}).get('name')} {(r.get('timestamp') or {}).get('formats')}")
        print(f"Example parsed fields: {json.dumps(r.get('example_parsed'), default=str)[:500]}")


if __name__ == "__main__":
    main()
