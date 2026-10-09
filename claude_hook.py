"""
Claude Code hook: sends EVERY Claude Code tool call (Bash, Edit, Write, Read, WebFetch, MCP tools...)
through Squidbrake before it runs, and reports the result afterwards.

  allowed by the rules    -> Claude Code carries on as normal (its own permission prompts still apply)
  blocked by a rule       -> the call is denied and Claude is told why
  held for approval       -> Claude Code waits (up to ~9 minutes) until someone approves / rejects it
                             in the dashboard

It also records what you ask (UserPromptSubmit), so the gateway can tell addresses you gave from ones a web page gave.

Install it with:  python connect.py claude-code   (or the Claude Code plugin: see plugin/README.md)
Settings (env vars, set by connect.py in the hook command):
  GATEWAY_URL, GATEWAY_API_KEY, GATEWAY_SOURCE (default "claude-code"),
  GATEWAY_FAIL_OPEN=1 to let calls run when the gateway is unreachable (default: block them)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

import httpx

try:  # what a command will change, and an undo for what it destroys (both best effort, never fatal)
    import commands
    import effects
    import runs
    import undo
except Exception:  # pragma: no cover
    commands = effects = runs = undo = None
try:
    import hooklog   # which agent ran the hook and when, for `squidbrake doctor`
except Exception:  # pragma: no cover
    hooklog = None

def _arg(flag: str, env: str, default: str) -> str:
    # Claude Code hook config has no env field, so connect.py passes settings as arguments.
    # Installed as a Claude Code plugin, they come from the plugin's settings instead.
    if flag in sys.argv[1:-1]:
        return sys.argv[sys.argv.index(flag) + 1]
    plugin_option = {"GATEWAY_URL": "CLAUDE_PLUGIN_OPTION_GATEWAY_URL", "GATEWAY_API_KEY": "CLAUDE_PLUGIN_OPTION_API_KEY"}.get(env)
    return os.getenv(env) or (plugin_option and os.getenv(plugin_option)) or default


GATEWAY_URL = _arg("--url", "GATEWAY_URL", "http://localhost:8080").rstrip("/")
GATEWAY_API_KEY = _arg("--key", "GATEWAY_API_KEY", "")
SOURCE = _arg("--source", "GATEWAY_SOURCE", "claude-code")
FAIL_OPEN = os.getenv("GATEWAY_FAIL_OPEN", "").lower() in ("1", "true", "yes")
MAX_WAIT = float(os.getenv("GATEWAY_MAX_WAIT", "540"))  # stay under Claude Code's 600 s hook timeout
# Tools that already report to the gateway themselves (gateway_mcp.py) - don't record them twice.
SKIP_PREFIXES = ("mcp__gateway-db__", "mcp__gw-")
STATE_DIR = Path(tempfile.gettempdir()) / "squidbrake-hook"


def deny(reason: str, stop: bool = False) -> None:
    """Refuse this tool call. stop=True also ends Claude's turn (the agent or its session was stopped)."""
    out: dict = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
    if stop:
        out.update({"continue": False, "stopReason": reason})
    print(json.dumps(out))
    sys.exit(0)


def gateway_client(url: str, key: str, timeout: float) -> httpx.Client:
    """The gateway on this computer is reached directly: 127.0.0.1, not localhost (Windows tries IPv6 ::1 first, and
    waits about 2 s for each call to fail over), and never through a proxy (on Windows the system proxy setting is
    read without its "bypass for local addresses" list, so a company proxy would get every hook call)."""
    host = httpx.URL(url).host
    if host == "localhost":
        url = url.replace("//localhost", "//127.0.0.1", 1)
    return httpx.Client(base_url=url, headers={"X-Gateway-Key": key}, timeout=timeout,
                        trust_env=host not in ("localhost", "127.0.0.1", "::1"))


def unreachable(url: str, e: httpx.HTTPError, what: str = "action") -> str:
    """Why everything is blocked, in words a person can act on (the agent passes it on). Same text in agent_hook.py."""
    status = getattr(getattr(e, "response", None), "status_code", None)
    if isinstance(e, (ValueError, KeyError, TypeError)):
        why = f"Something at {url} answered, but not like Squidbrake does (a proxy or another app on that port?)"
    elif "rejected" in str(e):
        why = f"Squidbrake's dashboard at {url} rejected this computer's key (it may have been removed)"
    elif status in (502, 503, 504) or isinstance(e, (httpx.ConnectError, httpx.TimeoutException)):
        why = f"Squidbrake's dashboard at {url} isn't answering: it may be switched off, restarting, or deleted"
    else:
        why = f"Squidbrake at {url} is unreachable or misconfigured ({e})"
    return (f"{why}. Every {what} must go through it, so this was blocked. Tell the user: start it again (or ask "
            f"whoever runs it). If it was removed on purpose, take Squidbrake out of this computer's agents with: "
            f"squidbrake connect all --remove")


def shell_command(ev: dict) -> str | None:
    if commands is None or ev.get("tool_name") not in ("Bash", "PowerShell"):
        return None
    return commands.command_of(ev.get("tool_input"))


def pre(ev: dict, http: httpx.Client) -> None:
    line = shell_command(ev)
    body = {
        "name": ev.get("tool_name", "unknown"), "kind": "claude_code", "input": ev.get("tool_input"),
        "source": SOURCE, "session_id": ev.get("session_id"),
        "metadata": {"cwd": ev.get("cwd"), "permission_mode": ev.get("permission_mode"),
                     "tool_use_id": ev.get("tool_use_id")},
    }
    if line:
        try:
            if found := effects.predict(line, ev.get("cwd")):
                body["metadata"]["effects"] = found
        except Exception:
            pass
        try:  # what `make clean` / `npm run x` / `bash x.sh` runs underneath, so the gateway checks that too
            if found := runs.expand(line, ev.get("cwd")):
                body["metadata"]["runs"] = found
        except Exception:
            pass
    try:
        r = http.post("/v1/events", json=body)
        if r.status_code == 401:
            raise httpx.HTTPError("the gateway rejected GATEWAY_API_KEY")
        r.raise_for_status()
        d = r.json()
        if d["decision"] == "review":
            undo = " It can't be undone once it runs." if d.get("cannot_undo") else ""
            print(f"Squidbrake: '{body['name']}' is waiting for approval at {GATEWAY_URL}/dashboard.{undo}",
                  file=sys.stderr, flush=True)
            end = time.monotonic() + MAX_WAIT
            while d["decision"] == "review" and time.monotonic() < end:
                wait = min(25.0, end - time.monotonic())
                r = http.get(f"/v1/events/{d['event_id']}/decision", params={"wait": wait}, timeout=wait + 10)
                r.raise_for_status()
                d = r.json()
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:   # not JSON / not our answer: blocked too
        if FAIL_OPEN:
            return
        deny(unreachable(GATEWAY_URL, e, "tool call"))

    if d["decision"] == "review":
        deny("Squidbrake: nobody approved this in time. Ask the user to approve it in the dashboard, then try again.")
    if d["decision"] == "deny":
        by = d.get("decided_by")
        if d.get("rule_id") in ("emergency-stop", "session-stop") or                 (d.get("decision_note") or "").startswith("The session was stopped"):
            deny(f"Squidbrake: {d.get('decision_note') or d.get('reason')}. Stop working and tell the user.", stop=True)
        if by == "timeout":
            deny("Squidbrake: nobody approved this in time, so it didn't run. Ask the user to approve it in the "
                 f"dashboard ({GATEWAY_URL}/dashboard) when you try again.")
        if by:
            note = f' Note: "{d["decision_note"]}".' if d.get("decision_note") else ""
            deny(f"Squidbrake: rejected by {by}.{note} Don't retry it; ask the user how to proceed.")
        deny(f"Squidbrake blocked this (rule '{d.get('rule_id')}'): {(d.get('reason') or '').rstrip('.')}. Don't try to work around it.")

    # Allowed: remember the event so PostToolUse can attach the result, then let Claude Code continue normally.
    if ev.get("tool_use_id"):
        STATE_DIR.mkdir(exist_ok=True)
        (STATE_DIR / f"{ev['tool_use_id']}.json").write_text(json.dumps({"event_id": d["event_id"], "t0": time.time()}))
    if line and (kept := undo.snapshot(line, ev.get("cwd"))):
        print(json.dumps({"systemMessage": undo.describe(kept)}))


def post(ev: dict, http: httpx.Client, failed: bool = False) -> None:
    """PostToolUse: attach the result. PostToolUseFailure (the tool errored, e.g. a command exited non-zero): the error."""
    f = STATE_DIR / f"{ev.get('tool_use_id')}.json"
    if not f.exists():
        return
    state = json.loads(f.read_text())
    f.unlink(missing_ok=True)
    result = {"duration_ms": (time.time() - state["t0"]) * 1000}
    if failed:
        result["error"] = str(ev.get("error") or "the tool failed")[:2000]
    else:
        result["output"] = ev.get("tool_response")
    try:
        http.post(f"/v1/events/{state['event_id']}/result", json=result)
    except httpx.HTTPError:
        pass  # the tool already ran; never fail Claude Code because reporting failed


def prompt(ev: dict, http: httpx.Client) -> None:
    """Record what the user asked. Never blocks the prompt: if the gateway is down, Claude Code carries on."""
    text = ev.get("prompt")
    if not text:
        return
    try:
        http.post("/v1/events", json={"name": "user.prompt", "kind": "prompt", "input": {"prompt": text},
                                      "output": {"recorded": True}, "source": SOURCE, "session_id": ev.get("session_id")})
    except httpx.HTTPError:
        pass


def _cursor_has_own_hook() -> bool:
    try:
        return "agent_hook.py" in (Path.home() / ".cursor" / "hooks.json").read_text(encoding="utf-8")
    except OSError:
        return False


def main() -> None:
    # UTF-8 whatever the console's code page, with or without a byte-order mark (Windows shells add one)
    text = sys.stdin.buffer.read().decode("utf-8-sig", errors="replace").strip()
    if not text:
        sys.exit(0)                                 # nothing to check
    try:
        ev = json.loads(text)
        if not isinstance(ev, dict):
            raise ValueError("not a JSON object")
    except ValueError:
        if FAIL_OPEN:
            sys.exit(0)
        deny("Squidbrake couldn't read what Claude Code sent to its hook, so this was blocked to be safe. "
             "Tell the user to run: squidbrake doctor")
    if hooklog is not None:
        hooklog.record("cursor-via-claude-code" if ev.get("cursor_version") else "claude-code", str(ev.get("hook_event_name") or ""))
    if str(ev.get("tool_name", "")).startswith(SKIP_PREFIXES):
        sys.exit(0)
    if ev.get("cursor_version") and _cursor_has_own_hook():
        sys.exit(0)   # Cursor runs Claude Code's hooks too; its own Squidbrake hook (agent_hook.py) covers it already
    with gateway_client(GATEWAY_URL, GATEWAY_API_KEY, 10) as http:
        if ev.get("hook_event_name") == "PreToolUse":
            pre(ev, http)
        elif ev.get("hook_event_name") == "PostToolUse":
            post(ev, http)
        elif ev.get("hook_event_name") == "PostToolUseFailure":
            post(ev, http, failed=True)
        elif ev.get("hook_event_name") == "UserPromptSubmit":
            prompt(ev, http)
    sys.exit(0)


if __name__ == "__main__":
    main()
