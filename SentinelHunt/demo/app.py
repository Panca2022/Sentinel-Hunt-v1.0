#!/usr/bin/env python3
"""
SentinelHunt demo app (Streamlit): the whole pipeline on the teammate's ELK kit, one page per demo scene.

  1. Ingest       pull (inbox folder) / push (HTTP) / stream (TCP) raw lines into raw staging
  2. Agent 1      "point at a source": process_source over MCP -> templates built or reused -> parsed hunt index
  3. Agent 2      hypothesis hunt over MCP (read-only account) -> verdict by code, claims checked by code
  4. Run twice    A2: the same hunt twice on unchanged data, full side-by-side

Every Elasticsearch access goes through the MCP server with the role's least-privilege account; the app never
holds ES credentials. Run from ~/se6014 in WSL:
  export SENTINELHUNT_KIT=~/se6014-portable/SentinelHunt_ELK_Portable
  .venv/bin/streamlit run demo/app.py
"""
import asyncio
import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent
for sub in ("agent2", "mcp_server", "experiments"):
    sys.path.insert(0, str(ROOT / sub))
import hunt_agent  # noqa: E402
from ingest_client import payload  # noqa: E402
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

KIT = Path(os.path.expanduser(os.environ.get("SENTINELHUNT_KIT", ""))) if os.environ.get("SENTINELHUNT_KIT") else None
SERVER = ROOT / "mcp_server" / "server.py"
HUNT_INDEX = "sentinelhunt-hunt-v1"
KIBANA = "http://localhost:15601"
EXAMPLES = ["Someone is brute-forcing SSH logins on our server",
            "Someone is probing our web server for admin and hidden pages",
            "A host is scanning ports and being blocked by the firewall",
            "A user ran destructive commands with sudo"]

st.set_page_config(page_title="SentinelHunt", layout="wide")
st.markdown("""<style>
.box{background:#fff;border:1px solid #e6e9ef;border-radius:8px;padding:10px 14px;margin-bottom:10px;
border-left:5px solid #999;font-size:14px;color:#1b1f24}.box *{color:inherit}.box small{color:#555}.code{border-left-color:#2e7d32}.ai{border-left-color:#1565c0}
.you{border-left-color:#9e9e9e}.row{display:grid;grid-template-columns:110px 1fr;gap:10px;margin:3px 0}
.box .k{font-weight:600;color:#444}.v{font-weight:700;font-size:18px}
.chip{display:inline-block;padding:2px 9px;border-radius:5px;margin-right:6px;color:#fff;font-size:12px}
.rw{background:#eef4ff;border-radius:3px;padding:0 2px}
</style>""", unsafe_allow_html=True)


# --------------------------------------------------------------------------- helpers
async def _mcp(role, calls):
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER), "--role", role], env=dict(os.environ))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return [payload(await s.call_tool(tool, args)) for tool, args in calls]


def mcp(role, tool, **args):
    """One MCP tool call with the role's account (spawns the MCP server over stdio)."""
    return asyncio.run(_mcp(role, [(tool, args)]))[0]


def as_list(x):
    return x if isinstance(x, list) else [x] if isinstance(x, dict) and x else []


def up(url, ok=(200,), ctx=None):
    try:
        with urllib.request.urlopen(url, timeout=3, context=ctx) as r:
            return r.status in ok
    except urllib.error.HTTPError as e:
        return e.code in ok
    except Exception:
        return False


def feeds():
    try:
        res = mcp("ingest", "list_feeds")
        if isinstance(res, dict) and res.get("error"):
            st.error(f"list_feeds: {res['error']}")
            return {}
        if not isinstance(res, (list, dict)):
            st.error(f"list_feeds: {str(res)[:300]}")
            return {}
        return {f["feed"]: f["raw_records"] for f in as_list(res) if isinstance(f, dict) and "feed" in f}
    except Exception as e:
        st.error(f"cannot list feeds over MCP: {e}")
        return {}


def flat(d, pre=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flat(v, pre + k + "."))
        else:
            out[pre + k] = v
    return out


def esc(x):
    import html
    return html.escape(str(x))


# --------------------------------------------------------------------------- sidebar
st.sidebar.markdown("### SentinelHunt\nAgentic threat hunting on ELK")
page = st.sidebar.radio("Demo", ["1 · Ingest", "2 · Agent 1 · schema", "3 · Agent 2 · hunt", "4 · Run twice (A2)"],
                        label_visibility="collapsed")
ollama_ok = up("http://localhost:11434/api/tags")
es_ok = up("https://localhost:19200", ok=(200, 401), ctx=ssl._create_unverified_context())  # 401 = up, auth required
st.sidebar.markdown("**Status**")
for name, ok in (("Elasticsearch (kit, TLS)", es_ok), ("Kibana", up(KIBANA + "/api/status")),
                 (f"Ollama {hunt_agent.MODEL}", ollama_ok), ("Kit folder (SENTINELHUNT_KIT)", bool(KIT and KIT.exists()))):
    st.sidebar.markdown(f"{'🟢' if ok else '🔴'} {name}")
st.sidebar.caption("All Elasticsearch access goes through the MCP server: agent1 account for ingest/schema, "
                   "read-only agent2 account for hunting.")


# --------------------------------------------------------------------------- 1. ingest
def page_ingest():
    st.title("1 · Ingest raw logs")
    st.caption("Three ways in, all land in raw staging (sentinelhunt-raw-v1) as raw lines with a feed name. "
               "Nothing is parsed here.")
    if not KIT:
        st.error("Set SENTINELHUNT_KIT to the kit folder before starting the app.")
        return
    c1, c2 = st.columns([2, 1])
    with c1:
        up_file = st.file_uploader("Log file (one raw line per record)", type=None)
    with c2:
        channel = st.radio("Channel", ["Pull (inbox folder)", "Push (HTTP :18088)", "Stream (TCP :15514)"])
        feed = st.text_input("Feed name", value="demo-feed")
        source = st.text_input("Source name", value="demo-host")
    if up_file:
        text = up_file.getvalue().decode("utf-8", "replace")
        lines = [l for l in text.splitlines() if l.strip()]
        st.code("\n".join(lines[:8]) + (f"\n… {len(lines)} lines" if len(lines) > 8 else ""), language=None)
    before = feeds()
    if st.button("Send", type="primary", disabled=not up_file):
        work = KIT / "runtime" / "demo_uploads"
        work.mkdir(parents=True, exist_ok=True)
        path = work / f"{feed}-{datetime.now():%H%M%S}.log"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with st.status(f"sending {len(lines)} lines via {channel.split()[0].lower()} …", expanded=True) as s:
            if channel.startswith("Pull"):
                rows = [{"record_id": "demo-" + hashlib.sha256(f"{feed}\n{source}\n{i}\n{l}".encode()).hexdigest()[:24],
                         "source_name": source, "feed_name": feed, "raw_line": l} for i, l in enumerate(lines)]
                code = ("import json,sys;sys.path.insert(0,'scripts');from manage import publish;"
                        "print('deposited', publish([json.loads(l) for l in sys.stdin]))")
                cmd = [sys.executable, "-c", code]
                inp = "\n".join(json.dumps(r) for r in rows)
            else:
                mode = "push" if channel.startswith("Push") else "stream"
                cmd, inp = [sys.executable, "scripts/ship.py", mode, str(path), "--source", source, "--feed", feed], None
            if channel.startswith("Pull"):
                st.markdown("**What runs:** the kit's `manage.publish()` writes the batch as one `.ndjson` file into "
                            "`runtime/inbox/`. Logstash's file input `folder_pull` watches `/inbox/*.ndjson` and "
                            "picks it up by itself. Nothing is sent to Elasticsearch directly.")
            else:
                st.markdown("**What runs:** the kit's own shipper, "
                            + ("one HTTP POST per line to :18088 with the push login" if mode == "push"
                               else "one TCP connection to :15514, one line per record") + ":")
                st.code(f"cd {KIT}\npython3 scripts/ship.py {mode} {path} --source {source} --feed {feed}",
                        language="bash")
            p = subprocess.run(cmd, cwd=KIT, input=inp, capture_output=True, text=True, timeout=600)
            out = (p.stdout.strip().splitlines() or [""])[-1]
            st.markdown("**Transport output:**")
            st.code((p.stdout.strip() + ("\n" + p.stderr.strip() if p.stderr.strip() else "")) or "(no output)",
                    language=None)
            if channel.startswith("Pull") and out.startswith("deposited"):
                st.write("Newest files in the watched inbox:",
                         [x.name for x in sorted((KIT / "runtime" / "inbox").glob("*.ndjson"),
                                                 key=lambda x: x.stat().st_mtime)[-3:]])
            if p.returncode:
                s.update(label="transport failed", state="error")
                return
            target = before.get(feed, 0) + len(lines)
            bar = st.progress(0.0, text="waiting for the records in raw staging …")
            for _ in range(40):
                now = feeds().get(feed, 0)
                bar.progress(min(1.0, (now - before.get(feed, 0)) / max(1, len(lines))),
                             text=f"raw staging: {now} records in feed {feed} (expecting {target})")
                if now >= target:
                    break
                time.sleep(1.5)
            s.update(label=f"done: feed {feed} has {now} raw records", state="complete")
    st.subheader("Raw staging per feed")
    st.dataframe([{"feed": k, "raw records": v} for k, v in sorted(feeds().items())], hide_index=True,
                 use_container_width=True)
    st.markdown(f"[Open raw staging in Kibana Discover]({KIBANA}/app/discover)")


# --------------------------------------------------------------------------- 2. agent 1
def page_agent1():
    st.title("2 · Agent 1 · point at a source")
    st.caption("Agent 1 splits the feed into layouts, reuses a registered template or builds + validates + registers "
               "one (LLM proposes, code checks), then writes every record into the hunt index (record_id kept).")
    fs = feeds()
    if not fs:
        st.info("No feeds in raw staging yet (page 1).")
        return
    feed = st.selectbox("Feed in raw staging", sorted(fs), format_func=lambda f: f"{f}  ({fs[f]} raw records)")
    fresh = st.checkbox("Build a new template with the AI (ignore registered templates)",
                        help="Agent 1 normally reuses a registered template when the format is known (no AI calls). "
                             "Ticked: the AI proposes a new template, code validates it, then it is registered. "
                             "Existing templates are not deleted.")
    if st.button("Process source", type="primary"):
        label = "building a new template with the AI (a few minutes)" if fresh else "reusing or building templates"
        with st.status(f"process_source({feed}) over MCP … {label}", expanded=True) as s:
            t0 = time.perf_counter()
            res = mcp("ingest", "process_source", feed_name=feed, fresh=fresh)
            s.update(label=f"finished in {time.perf_counter() - t0:.0f}s",
                     state="error" if res.get("error") else "complete")
        st.session_state["a1"] = res
        # evidence: Agent 1 log + a snapshot of the template as it is right after this step
        outcome = "-".join(sorted({str(l.get("v4") or l.get("outcome")).split(" ")[0] for l in res.get("layouts", [])})) or "error"
        snap = ROOT / "reports" / "agent1_steps" / f"{datetime.now():%Y%m%d-%H%M%S}-{feed}-{outcome}"
        snap.mkdir(parents=True, exist_ok=True)
        (snap / "agent1_result.json").write_text(json.dumps(res, indent=2, default=str))
        (snap / "agent1_log.txt").write_text("\n".join(res.get("log_tail", [])) + "\n")
        if KIT:
            subprocess.run([sys.executable, str(ROOT / "scripts" / "export_run_evidence.py"), feed, str(snap), "--since",
                            (datetime.utcnow() - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")],
                           capture_output=True, text=True, timeout=120, env={**os.environ, "SENTINELHUNT_KIT": str(KIT)})
        st.caption(f"saved: reports/agent1_steps/{snap.name}/ (log, result, template snapshot)")
    res = st.session_state.get("a1")
    if res:
        failed = bool(res.get("error")) or any(l.get("note") for l in res.get("layouts", []))
        if res.get("error"):
            st.error(res["error"])
        for l in res.get("layouts", []):
            if l.get("note"):
                st.error(f"{l['layout']}: {l['note']}")
        m = st.columns(4)
        m[0].metric("Indexed into hunt index", res.get("indexed", 0))
        m[1].metric("Failed", res.get("failed", 0))
        m[2].metric("Layouts", len(res.get("layouts", [])))
        m[3].metric("Seconds", res.get("seconds", "-"))
        st.dataframe([{"layout": l["layout"], "lines": l["lines"], "outcome": l["outcome"], "template": l.get("template"),
                       "parser": l.get("v4", l.get("note", ""))} for l in res.get("layouts", [])],
                     hide_index=True, use_container_width=True)
        with st.expander("Agent 1 log", expanded=failed):
            st.code("\n".join(res.get("log_tail", [])), language=None)
    st.subheader("Raw line → parsed record (read back from the hunt index, read-only account)")
    r = mcp("hunt", "search", hunt_id="demo-view", index=HUNT_INDEX, query=f'feed_name:"{feed}"', size=50)
    if r.get("error"):
        st.warning(r["error"])
        return
    # one example per kind of event (failures first), so the interesting records are on screen
    picked, kinds = [], set()
    for h in sorted(r.get("hits", []), key=lambda h: flat(h).get("event.outcome") != "failure"):
        kind = flat(h).get("event.action")
        if kind not in kinds:
            kinds.add(kind)
            picked.append(h)
    st.caption(f"{r.get('total', 0)} parsed records of feed {feed} in {HUNT_INDEX} · "
               f"one example per event.action ({len(picked)} kinds)")
    for h in picked[:4]:
        d = flat({k: v for k, v in h.items() if k not in ("_index",)})
        raw = d.pop("event.original", None) or d.get("message", "")
        rows = [{"field": k, "value": str(v)} for k, v in sorted(d.items()) if k not in ("message", "_id")]
        a, b = st.columns([1, 1])
        a.markdown(f"**{esc(d.get('event.action', ''))}** · {esc(d.get('event.outcome', ''))}")
        a.code(raw, language=None, wrap_lines=True)
        a.caption(f"_id {h.get('_id')}")
        b.dataframe(rows, hide_index=True, use_container_width=True, height=36 * (len(rows) + 1) + 4)
    st.markdown(f"[Open the hunt index in Kibana Discover]({KIBANA}/app/discover)")


# --------------------------------------------------------------------------- 3. agent 2
def result_cards(rep):
    lines = hunt_agent.result_lines(rep)
    groups = [("you", ["Question"]), ("ai", ["AI picked", "Focus"]), ("code", ["Searched"]),
              ("code", ["Verdict", "Decided by", "Why", "Also found"]), ("ai", ["AI summary"]),
              ("code", ["Checked", "Queries", "Report", "Note"])]
    color = {"DETECTION CRITERIA MATCHED": "#b42318", "NOT FOUND": "#2e7d32"}
    html = ""
    for cls, labels in groups:
        rows = ""
        for k, v in lines:
            if k in labels:
                txt = esc(v)
                if k == "Verdict":
                    txt = f"<span class=v style='color:{color.get(v, '#8a5a00')}'>{txt}</span>"
                rows += f"<div class=row><div class=k>{k}</div><div>{txt}</div></div>"
        if rows:
            html += f"<div class='box {cls}'>{rows}</div>"
    st.markdown(html, unsafe_allow_html=True)


def page_agent2():
    st.title("3 · Agent 2 · hypothesis hunt")
    st.markdown("<span class=chip style='background:#9e9e9e'>your input</span>"
                "<span class=chip style='background:#1565c0'>written by the AI</span>"
                "<span class=chip style='background:#2e7d32'>decided / checked by code</span>", unsafe_allow_html=True)
    ex = st.selectbox("Examples", ["(type your own)"] + EXAMPLES)
    hyp = st.text_input("Hypothesis", value="" if ex.startswith("(") else ex)
    if st.button("Run hunt", type="primary", disabled=not hyp.strip()):
        with st.status("hunting … (plan → playbook queries → verdict by code → AI follow-ups → claims checked)",
                       expanded=True) as s:
            box = st.empty()
            seen = []

            def log(*a):
                seen.append(" ".join(map(str, a)))
                box.code("\n".join(seen[-30:]), language=None)

            rep = asyncio.run(hunt_agent.hunt(hyp.strip(), log=log))
            s.update(label=f"{rep['verdict']} · {len(rep['queries'])} queries · {rep['runtime_s']}s", state="complete")
        st.session_state["a2"] = rep
    rep = st.session_state.get("a2")
    if not rep:
        return
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Hunt result")
        result_cards(rep)
    with right:
        st.subheader("AI claims (checked by code)")
        items = ""
        for c in rep["claims"]:
            items += (f"<li><span class=rw>{esc(c['text'])}</span><br><small>rewritten by the AI after checker feedback;"
                      f" first version: <s>{esc(c['rewritten_from'])}</s></small></li>" if c.get("rewritten_from")
                      else f"<li>✓ {esc(c['text'])}</li>")
        for c in rep.get("removed_claims", []):
            if not c.get("rewritten"):
                items += (f"<li><s>{esc(c['text'])}</s><br><small>removed by the checker: "
                          f"{esc('; '.join(c.get('problems', [])))}</small></li>")
        st.markdown(f"<div class='box ai'><ul>{items or '(none)'}</ul></div>", unsafe_allow_html=True)
        st.subheader("Key evidence (chosen by code)")
        st.dataframe([{"_id": e["_id"], "@timestamp": e.get("@timestamp"), "raw": e.get("message")}
                      for e in rep.get("key_evidence") or []], hide_index=True, use_container_width=True)
    st.subheader(f"Every query ({len(rep['queries'])}, all through MCP, logged with ids)")
    fu = {f.get("query_id") for f in rep.get("followups", [])}
    st.dataframe([{"id": q["query_id"].split("-")[-1], "by": "AI follow-up" if q["query_id"] in fu else "code",
                   "tool": q["tool"] + (f" {q['args'].get('agg_type')} {q['args'].get('field')}"
                                        if q["tool"] == "aggregate" else ""),
                   "query": q["args"].get("query"), "result": q.get("summary")} for q in rep["queries"]],
                 hide_index=True, use_container_width=True)
    bad = [f for f in rep.get("followups", []) if f.get("status") != "ok"]
    if bad:
        with st.expander(f"AI follow-up queries not run ({len(bad)})"):
            st.dataframe([{"status": f["status"], "query": f.get("query"), "why": f.get("note")} for f in bad],
                         hide_index=True, use_container_width=True)
    md = hunt_agent.REPORTS / f"{rep['hunt_id']}.md"
    if md.exists():
        st.download_button("Download report (.md)", md.read_text(), file_name=md.name)


# --------------------------------------------------------------------------- 4. run twice
def page_run_twice():
    st.title("4 · Run twice on unchanged data (A2)")
    folders = sorted([p for d in (ROOT / "experiments", ROOT / "experiments" / "results") if d.exists()
                      for p in d.glob("run_twice_*") if (p / "comparison.json").exists()], key=lambda p: p.name)
    with st.expander("Run the experiment now (4 hypotheses × 2 runs × 2 settings, takes a while)"):
        if st.button("Start run_twice --suite --quick"):
            out = st.empty()
            p = subprocess.Popen([sys.executable, str(ROOT / "experiments" / "run_twice.py"), "--suite", "--quick"],
                                 cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            buf = []
            for line in p.stdout:
                buf.append(line.rstrip())
                out.code("\n".join(buf[-25:]), language=None)
            p.wait()
            st.rerun()
    if not folders:
        st.info("No run_twice results yet.")
        return
    folder = st.selectbox("Result folder", folders[::-1], format_func=lambda p: p.name)
    comp = json.loads((folder / "comparison.json").read_text())
    st.markdown(f"**Data unchanged between runs: {'yes' if comp.get('data_unchanged') else 'NO'}** "
                "(doc count, time range, sha256 of every record id and content, before vs after)")
    st.dataframe([{"setting": r["config"], "case": r["case"], "same verdict": "✓" if r["same_verdict"] else "✗",
                   "verdicts": r["verdicts"], "same playbook": "✓" if r["same_playbook"] else "✗",
                   "key evidence J": r["evidence_jaccard"], "query J": r["query_jaccard"],
                   "claim similarity": r["claim_similarity"]} for r in comp["rows"]],
                 hide_index=True, use_container_width=True)
    c1, c2 = st.columns(2)
    cfg = c1.selectbox("Setting", sorted({r["config"] for r in comp["rows"]})[::-1])
    case = c2.selectbox("Case", sorted({r["case"].split()[0] for r in comp["rows"]}))
    html_path = folder / f"side_by_side_{cfg}_{case}.html"
    if not html_path.exists():
        import side_by_side_image
        side_by_side_image.main(folder, cfg, case)
    components.html(html_path.read_text(encoding="utf-8"), height=2300, scrolling=True)


{"1": page_ingest, "2": page_agent1, "3": page_agent2, "4": page_run_twice}[page[0]]()
