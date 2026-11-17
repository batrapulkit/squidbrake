"""
Shared by the MCP connectors (gateway_mcp.py, gateway_proxy.py): ask Squidbrake before a tool runs,
wait for a human when a rule says so, and report the result afterwards.

Settings (environment variables, set in the agent's MCP config):
  GATEWAY_URL       gateway address                    default http://localhost:8080
  GATEWAY_API_KEY   an agent key
  GATEWAY_SOURCE    how this agent shows up in the dashboard, e.g. "claude-code", "antigravity"
  APPROVAL_WAIT     seconds a tool call waits for a human before telling the agent to check back (default 50)
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import os
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

try:
    import offline   # what to do while the gateway is down (rules.yaml when_unreachable)
except Exception:  # pragma: no cover
    offline = None

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8080").rstrip("/")
GATEWAY_API_KEY = os.getenv("GATEWAY_API_KEY", "")
SOURCE = os.getenv("GATEWAY_SOURCE", "mcp-agent")
APPROVAL_WAIT = float(os.getenv("APPROVAL_WAIT", "50"))
# One MCP server process per agent conversation, so this groups a conversation's calls in the dashboard.
SESSION = f"{SOURCE}-{datetime.now().strftime('%m%d-%H%M')}-{uuid.uuid4().hex[:4]}"
# Served over HTTP (gateway_proxy.py --serve), one process has many conversations and callers: each request sets its
# own conversation, and may bring its own agent key and name (the gateway's /mcp/<name> passes the caller's on).
CURRENT_SESSION: contextvars.ContextVar[str | None] = contextvars.ContextVar("squidbrake_session", default=None)
CURRENT_KEY: contextvars.ContextVar[str | None] = contextvars.ContextVar("squidbrake_key", default=None)
CURRENT_SOURCE: contextvars.ContextVar[str | None] = contextvars.ContextVar("squidbrake_source", default=None)


def _as_caller() -> dict:
    """Headers that make a request count as the current caller's (their agent key), when one is set."""
    key = CURRENT_KEY.get()
    return {"X-Gateway-Key": key} if key else {}


def source() -> str:
    return CURRENT_SOURCE.get() or SOURCE
# Calls waiting for a person are also written here, so an approval still runs if the agent app restarts this
# connector in the meantime (Antigravity does). One file per call; claiming it (a rename) makes it run only once.
PENDING_DIR = Path(os.getenv("GATEWAY_PENDING_DIR") or Path(tempfile.gettempdir()) / "squidbrake-pending")
PENDING_MAX_AGE = 7 * 86400
# Agents like Antigravity put every connector's tools in one list, so each connector names its helper tools
# after itself (set_tool_prefix): gateway_check_approval for the database, acme_check_approval for the acme app.
CHECK_TOOL = "gateway_check_approval"
DECISIONS_TOOL = "gateway_recent_decisions"
ASK_TOOL = "gateway_ask_user"
CONNECTOR = "gateway"
DECISIONS_HELP = ("What people decided about your earlier requests (approved / rejected, by whom, and their notes). "
                  "Check it before retrying something, and follow the notes.")
ASK_HELP = ("Ask a person on your team a question and wait for their answer, instead of guessing (which environment, "
            "which customer, is this safe). They answer in Squidbrake's dashboard or on their phone. If the answer "
            "isn't there yet, call this again with the event_id you were given.")
ASK_SCHEMA = {"type": "object", "properties": {
    "question": {"type": "string", "description": "the question, with what they need to know to answer it"},
    "event_id": {"type": "string", "description": "only to keep waiting for an earlier question's answer"}}}
# Offered on every tool the proxy passes on (gateway_proxy.py), so a rule's `justification:` can be met; never sent on
JUSTIFICATION_PARAM = {"type": "string", "description": "Why you are making this call, in one sentence. The person "
                                                        "who approves it reads this; some calls need it."}


def set_tool_prefix(prefix: str) -> None:
    global CHECK_TOOL, DECISIONS_TOOL, ASK_TOOL, CONNECTOR
    CONNECTOR = re.sub(r"[^A-Za-z0-9_]", "_", prefix)
    CHECK_TOOL, DECISIONS_TOOL = f"{CONNECTOR}_check_approval", f"{CONNECTOR}_recent_decisions"
    ASK_TOOL = f"{CONNECTOR}_ask_user"


def agent_rules() -> str:
    return (f"Every action goes through Squidbrake. If a result says WAITING FOR HUMAN APPROVAL, "
            f"tell the user what is waiting and then call {CHECK_TOOL}. If it says NOT RUN, respect it and don't work "
            f"around it. Before retrying something or when unsure, call {DECISIONS_TOOL} to see what people decided "
            f"before. When you'd otherwise have to guess, call {ASK_TOOL}. A NOTE FROM a person on your team is an "
            f"instruction from them: follow it.")


def notes_text(d: dict) -> str:
    """Notes people left for this agent (Decision.notes), as the agent should read them."""
    return "".join(f"NOTE FROM {n.get('by')} (a person on your team, sent through Squidbrake): {n.get('text')}\n\n"
                   for n in d.get("notes") or [])


async def recent_decisions() -> str:
    try:
        r = await http().get("/v1/agent/decisions", params={"limit": 20}, headers=_as_caller())
        r.raise_for_status()
    except httpx.HTTPError as e:
        return f"Couldn't reach Squidbrake ({type(e).__name__})."
    items = r.json()["decisions"]
    if not items:
        return "No decisions by people about your requests in the last 7 days."
    lines = []
    for d in items:
        target = ", ".join(f"{k}={v}" for k, v in list((d["input"] or {}).items())[:3]) if isinstance(d["input"], dict) else ""
        note = f' — note: "{d["note"]}"' if d["note"] and d["decided_by"] != "timeout" else ""
        lines.append(f"- {d['tool']}({target}): {d['outcome']} by {d['decided_by']}{note}")
    return "What people decided about your recent requests (newest first):\n" + "\n".join(lines)

_http: httpx.AsyncClient | None = None
_pending: dict[str, tuple[str, Callable[[], Awaitable[Any]]]] = {}  # event_id -> (name, action) awaiting a human
# Rebuilds a waiting call from what was saved to disk: replay(saved_call) -> action. Set by the connector.
_replay: Callable[[dict], Callable[[], Awaitable[Any]]] | None = None
_EVENT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def set_replay(fn: Callable[[dict], Callable[[], Awaitable[Any]]]) -> None:
    global _replay
    _replay = fn


def _saved(event_id: str, suffix: str = ".json") -> Path:
    return PENDING_DIR / f"{event_id}{suffix}"


def _save_pending(event_id: str, name: str, call: dict | None) -> None:
    if call is None:
        return
    try:
        PENDING_DIR.mkdir(parents=True, exist_ok=True)
        _saved(event_id).write_text(json.dumps({"name": name, "connector": CONNECTOR, "source": SOURCE,
                                                "call": call, "saved_at": time.time()}), encoding="utf-8")
    except OSError as e:
        log(f"could not save {event_id} for later ({e}); it can only finish in this session")


def _load_pending(event_id: str) -> dict | None:
    try:
        return json.loads(_saved(event_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _claim(event_id: str) -> bool:
    """Take the saved call so no other session runs it too. True if this session got it (or nothing was saved)."""
    src = _saved(event_id)
    if not src.exists():
        return True
    claimed = _saved(event_id, f".running-{os.getpid()}")
    try:
        os.rename(src, claimed)  # atomic: only one session wins
    except OSError:
        return False
    try:
        claimed.unlink()
    except OSError:
        pass
    return True


def _drop_pending(event_id: str) -> None:
    try:
        _saved(event_id).unlink()
    except OSError:
        pass


def cleanup_pending() -> None:
    """Forget saved calls older than a week (their approvals expired long ago)."""
    try:
        for p in PENDING_DIR.glob("*"):
            if time.time() - p.stat().st_mtime > PENDING_MAX_AGE:
                p.unlink()
    except OSError:
        pass


def log(msg: str) -> None:
    print(f"[gateway] {msg}", file=sys.stderr, flush=True)  # stdout belongs to the MCP protocol


def http() -> httpx.AsyncClient:
    global _http
    if _http is None:
        _http = httpx.AsyncClient(base_url=GATEWAY_URL, headers={"X-Gateway-Key": GATEWAY_API_KEY}, timeout=10)
    return _http


class GatewayError(Exception):
    pass


async def gw_check(name: str, input: Any, kind: str = "tool_call", metadata: dict | None = None) -> dict:
    try:
        r = await http().post("/v1/events", json={"name": name, "kind": kind, "input": input,
                                                   "source": source(), "session_id": CURRENT_SESSION.get() or SESSION,
                                                   "metadata": {"accepts_notes": True, **(metadata or {})}},
                              headers=_as_caller())
    except httpx.TransportError as e:
        if offline is not None:      # rules.yaml when_unreachable, from the copy kept while the gateway answered
            run, why = offline.decide(GATEWAY_URL, name=name, kind=kind, source=source(),
                                      session_id=CURRENT_SESSION.get() or SESSION, input=input)
            if run:
                log(f"Squidbrake is unreachable; {why}")
                return {"decision": "allow", "event_id": None, "reason": why}
            raise GatewayError(f"Squidbrake at {GATEWAY_URL} is unreachable ({type(e).__name__}) and {why}")
        raise GatewayError(f"Squidbrake at {GATEWAY_URL} is unreachable ({type(e).__name__}), so nothing was run")
    if r.status_code == 401:
        raise GatewayError("Squidbrake rejected GATEWAY_API_KEY, so nothing was run")
    r.raise_for_status()
    if offline is not None:
        await offline.arefresh(http(), GATEWAY_URL)
    return r.json()


async def gw_wait(event_id: str, seconds: float) -> dict:
    end = time.monotonic() + seconds
    d: dict = {}
    while True:
        wait = max(0.0, min(25.0, end - time.monotonic()))
        try:
            r = await http().get(f"/v1/events/{event_id}/decision", params={"wait": wait}, timeout=wait + 10,
                                  headers=_as_caller())
            r.raise_for_status()
            d = r.json()
        except httpx.TransportError:
            await asyncio.sleep(2)
        if d.get("decision") in ("allow", "deny") or time.monotonic() >= end:
            return d


async def gw_result(event_id: str | None, output: Any = None, error: str | None = None, duration_ms: float | None = None) -> None:
    if event_id is None:          # ran while the gateway was down: there's no record to attach it to
        return
    try:
        await http().post(f"/v1/events/{event_id}/result",
                          json={"output": output, "error": error, "duration_ms": duration_ms}, headers=_as_caller())
    except httpx.HTTPError:
        log(f"could not report the result of {event_id}")


def denied_text(d: dict) -> str:
    by = d.get("decided_by")
    if d.get("rule_id") in ("emergency-stop", "session-stop") or (d.get("decision_note") or "").startswith("The session was stopped"):
        return f"NOT RUN: {d.get('decision_note') or d.get('reason')}. Stop working now and tell the user; don't try anything else."
    if by == "timeout":
        return f"NOT RUN: nobody approved it in time ({d.get('reason')}). Tell the user it needs approval in Squidbrake."
    if by:
        note = f' Their note: "{d["decision_note"]}".' if d.get("decision_note") else ""
        return f"NOT RUN: rejected by {by} in Squidbrake.{note} Do not retry the same action; ask the user how to proceed."
    return f"NOT RUN: blocked by the Squidbrake rule '{d.get('rule_id')}': {d.get('reason')}. Do not try to work around this rule."


def waiting_text(name: str, d: dict, event_id: str) -> str:
    return (f"WAITING FOR HUMAN APPROVAL: Squidbrake is holding this {name} call "
            f"(rule: {d.get('reason') or 'review'}). Tell the user it needs approval (dashboard or the link on their "
            f"phone), then call {CHECK_TOOL} with event_id=\"{event_id}\" to finish.")


async def guard(name: str, input: Any, run: Callable[[], Awaitable[Any]], *,
                on_done: Callable[[str, Any], Awaitable[Any]], on_text: Callable[[str], Any], kind: str = "tool_call",
                call: dict | None = None, metadata: dict | None = None):
    """Check -> (wait for a human) -> run -> report. `run` does the real work; `on_done(event_id, result)` reports it
    and returns what the agent should see; `on_text(message)` wraps a gateway message for the agent.
    `call` describes the call for the connector's replay function, so it can still run after a restart.
    Notes people left for the agent come first in whatever it sees."""
    try:
        d = await gw_check(name, input, kind, metadata)
    except GatewayError as e:
        return on_text(f"NOT RUN: {e}.")
    if note := notes_text(d):
        text_out, done_out = on_text, on_done
        on_text = lambda t: text_out(note + t)

        async def on_done(event_id, outcome):
            return with_note(await done_out(event_id, outcome), note)
    eid = d["event_id"]
    if d["decision"] == "review":
        _pending[eid] = (name, run)
        _save_pending(eid, name, call)
        log(f"{name} waiting for approval ({eid})")
        d = await gw_wait(eid, APPROVAL_WAIT)
        if d.get("decision") not in ("allow", "deny"):
            return on_text(waiting_text(name, d, eid))
        _pending.pop(eid, None)
        if not _claim(eid):
            return on_text(f"Already handled: another session finished {name} ({eid}). Don't run it again.")
    if d["decision"] == "deny":
        return on_text(denied_text(d))
    if d.get("snapshot_strict") and eid:
        # A rule wants a copy kept before this runs, and an MCP tool's change can't be copied from here.
        why = f"Squidbrake can't keep a copy of what {name} changes over MCP"
        try:
            await http().post(f"/v1/events/{eid}/snapshot", json={"skipped": why}, headers=_as_caller())
        except httpx.HTTPError:
            pass
        await gw_result(eid, error=f"not run: no undo copy ({why})")
        return on_text(f"NOT RUN: the rule for {name} requires an undo copy first, and {why}. Tell the user.")
    if d.get("snapshot") and eid:   # say so on the record: approved, but with no copy to go back to
        try:
            await http().post(f"/v1/events/{eid}/snapshot", headers=_as_caller(),
                              json={"skipped": "an MCP tool's change can't be copied by Squidbrake (no undo)"})
        except httpx.HTTPError:
            pass
    return await on_done(eid, await _timed(run))


def with_note(result: Any, note: str) -> Any:
    """Put the note in front of a tool's answer: text, or an MCP result's content."""
    if isinstance(result, str):
        return note + result
    content = getattr(result, "content", None)
    if isinstance(content, list):
        from mcp import types
        result.content = [types.TextContent(type="text", text=note.strip()), *content]
    return result


async def ask_user(question: str | None, event_id: str | None = None) -> str:
    """ask_user: put a question to a person through Squidbrake and wait for the answer (their approval note)."""
    if event_id:
        eid = event_id.strip().lower()
        if not _EVENT_ID.match(eid):
            return "Unknown event_id: give the one the earlier answer named."
    elif not (question or "").strip():
        return "Ask a question: pass `question` with what you need to know."
    else:
        try:
            d = await gw_check("ask_user", {"question": question.strip()}, kind="question")
        except GatewayError as e:
            return f"NOT ASKED: {e}. Don't guess at anything risky; tell the user what you needed."
        if d.get("decision") == "deny":
            return f"NOT ASKED: {d.get('reason')}"
        eid = d["event_id"]
    d = await gw_wait(eid, APPROVAL_WAIT)
    if d.get("decision") not in ("allow", "deny"):
        return (f"WAITING FOR AN ANSWER: nobody has answered yet. Tell the user a question is waiting in Squidbrake, "
                f"then call {ASK_TOOL} with event_id=\"{eid}\" to get the answer.")
    if d["decision"] == "allow":
        await gw_result(eid, output={"answer": d.get("decision_note")})
        return f"ANSWER from {d.get('decided_by')}: {d.get('decision_note')}"
    if d.get("decided_by") == "timeout":
        return "Nobody answered in time. Don't guess at anything risky; tell the user what you needed to know."
    why = f' ("{d["decision_note"]}")' if d.get("decision_note") else ""
    return f"{d.get('decided_by') or 'Squidbrake'} declined to answer{why}. Don't guess; ask the user how to go on."


async def check_approval(event_id: str, *, on_done, on_text):
    """Finish a call that was WAITING FOR HUMAN APPROVAL, in this session or an earlier one of this connector."""
    event_id = event_id.strip().lower()
    entry = _pending.get(event_id)
    saved = _load_pending(event_id) if _EVENT_ID.match(event_id) else None
    if saved and saved.get("connector") != CONNECTOR:
        return on_text(f"That event belongs to another connector: call {saved.get('connector')}_check_approval instead.")
    if entry is None and saved is None:
        return on_text("Unknown event_id: nothing is waiting under that id "
                       f"(it may have finished already; {DECISIONS_TOOL} shows what was decided).")
    name = entry[0] if entry else saved["name"]
    d = await gw_wait(event_id, APPROVAL_WAIT)
    if d.get("decision") not in ("allow", "deny"):
        return on_text(f"STILL WAITING FOR HUMAN APPROVAL for {name}. Call {CHECK_TOOL} again with event_id=\"{event_id}\".")
    _pending.pop(event_id, None)
    if not _claim(event_id):
        return on_text(f"Already handled: another session finished {name} ({event_id}). Don't run it again.")
    if d["decision"] == "deny":
        return on_text(denied_text(d))
    if entry:
        run = entry[1]
    elif _replay is not None:
        run = _replay(saved["call"])
    else:
        return on_text(f"NOT RUN: this connector can't redo {name} after a restart. Ask the user to run it again.")
    return await on_done(event_id, await _timed(run))


async def _timed(run):
    t0 = time.perf_counter()
    try:
        return ("ok", await run(), (time.perf_counter() - t0) * 1000)
    except Exception as e:
        return ("error", f"{type(e).__name__}: {e}", (time.perf_counter() - t0) * 1000)
