"""
One pre-execution hook for the coding agents that have hooks, besides Claude Code (claude_hook.py):

  python agent_hook.py cursor       Cursor        beforeShellExecution, beforeReadFile, beforeMCPExecution,
                                                  preToolUse for Write|Delete            (~/.cursor/hooks.json)
  python agent_hook.py gemini-cli   Gemini CLI    BeforeTool                             (~/.gemini/settings.json)
  python agent_hook.py codex        Codex CLI     PreToolUse                             (~/.codex/hooks.json)
  python agent_hook.py vscode       VS Code       PreToolUse (Copilot agent mode)        (~/.copilot/hooks/)
  python agent_hook.py antigravity  Antigravity   PreToolUse                             (~/.gemini/config/hooks.json)

Each reads the agent's JSON on stdin, sends the action to Squidbrake, waits while a person decides if it's held, and
answers in that agent's format. Shell commands are sent as "Bash", reads as "Read", writes and edits as "Write" / "Edit",
so the same rules apply whichever agent ran them. MCP tools: Cursor's and Codex's are checked here as <server>.<tool>
(unless the server is already Squidbrake's proxy); the other agents' go through `connect guard`, which routes their MCP
servers through Squidbrake, so no call is recorded twice.

Installed by `squidbrake connect agents`. Settings come as arguments: --url, --key (like claude_hook.py).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import time

import httpx

try:  # what a command will change, and an undo for what it destroys (both best effort, never fatal)
    import effects
    import runs
    import undo
except Exception:  # pragma: no cover
    effects = runs = undo = None
try:
    import hooklog   # which agent ran the hook and when, for `squidbrake doctor`
except Exception:  # pragma: no cover
    hooklog = None

AGENTS = ("cursor", "gemini-cli", "codex", "vscode", "antigravity")


def _arg(flag: str, env: str, default: str = "") -> str:
    if flag in sys.argv[1:-1]:
        return sys.argv[sys.argv.index(flag) + 1]
    return os.getenv(env, default)


URL = _arg("--url", "GATEWAY_URL", "http://localhost:8080").rstrip("/")
KEY = _arg("--key", "GATEWAY_API_KEY")
FAIL_OPEN = os.getenv("GATEWAY_FAIL_OPEN", "").lower() in ("1", "true", "yes")
MAX_WAIT = float(os.getenv("GATEWAY_MAX_WAIT", "540"))   # under the 600 s timeout `connect agents` sets


# --------------------------------------------------------------------------- what the agent wants to do

def normalize(name: str, args) -> tuple[str, dict] | None:
    """(name, input) the way Squidbrake's rules see it, or None for actions left to other paths (MCP tools)."""
    args = args if isinstance(args, dict) else {"value": args}
    low = name.lower()
    if low.startswith("mcp"):
        return None
    lower = {k.lower(): v for k, v in args.items()}
    cmd = next((lower[k] for k in ("command", "commandline", "command_line", "cmd") if k in lower), None)
    if cmd is not None:
        if isinstance(cmd, list):         # e.g. Codex: ["bash", "-lc", "rm -rf ..."]; keep the quoting
            cmd = shlex.join(str(c) for c in cmd)
        out = {"command": str(cmd)}
        cwd = next((lower[k] for k in ("cwd", "workdir", "directory") if k in lower), None)
        if cwd:
            out["cwd"] = cwd
        return "Bash", out
    path = next((v for k, v in lower.items() if k in ("file_path", "filepath", "path", "absolute_path", "absolutepath",
                                                        "targetfile", "target_file", "file")), None)
    if any(w in low for w in ("read", "view", "open")) and path:
        return "Read", {"file_path": path}
    if any(w in low for w in ("edit", "replace", "patch", "str_replace", "multi_edit")):
        return "Edit", {**args, **({"file_path": path} if path else {})}
    if any(w in low for w in ("write", "create")):
        return "Write", {**args, **({"file_path": path} if path else {})}
    return name, args


OURS = ("gateway_proxy", "squidbrake proxy", "gateway_mcp")


def mcp_call(server, tool, args, launched_by) -> tuple[str, dict] | None:
    """An MCP tool call as `<server>.<tool>`, the way the proxy names them, so the same rules apply. None when the
    server is already Squidbrake's proxy (`connect guard` / `wrap`): it checks the call itself, once."""
    server, tool = str(server or "mcp"), str(tool or "unknown")
    if any(o in str(launched_by or "") for o in OURS) or server.startswith(("gw-", "gw_")) or server == "gateway-db":
        return None
    if isinstance(args, str):           # Cursor sends the arguments as a JSON string
        try:
            args = json.loads(args) if args.strip() else {}
        except ValueError:
            args = {"value": args}
    app = re.sub(r"[^A-Za-z0-9_-]+", "-", server).strip("-").lower() or "mcp"
    return f"{app}.{tool}", args if isinstance(args, dict) else {"value": args}


def cursor_tool(name: str, args, cwd) -> tuple[str, dict] | None:
    """Cursor's preToolUse, installed for Write (every file edit) and Delete. Shell and reads have their own hooks."""
    args = args if isinstance(args, dict) else {}
    path = next((args[k] for k in ("file_path", "path", "target_file", "filePath", "file") if args.get(k)), None)
    if name == "Delete" and isinstance(path, str):
        # deleting a file is the same as `rm` it: the command checks know which deletes are everyday work (a log, a
        # temp file), and those only count inside the project, so a path in it is made relative
        # compared as text: os.path.isabs disagrees across OSes and Python versions on paths like /w/x (Windows, 3.13)
        root = str(cwd or "").replace("\\", "/").rstrip("/") + "/"
        posix = path.replace("\\", "/")
        if cwd and posix.lower().startswith(root.lower()):
            path = posix[len(root):] or path
        return "Bash", {"command": f"rm -- {shlex.quote(path)}", **({"cwd": cwd} if cwd else {})}
    if name in ("Shell", "Read", "Grep") or name.startswith("MCP:"):
        return None                     # covered by beforeShellExecution / beforeReadFile / beforeMCPExecution
    return normalize(name, {**args, **({"file_path": path} if path else {})})


def parse(agent: str, ev: dict) -> tuple[tuple[str, dict] | None, str | None]:
    """-> ((name, input) or None, session id)"""
    if agent == "cursor":
        session = ev.get("conversation_id")
        if ev.get("hook_event_name") == "beforeShellExecution":
            # cwd can come empty: then the open project, so `rm -rf build` is measured where it would run, not in the hook's folder
            cwd = ev.get("cwd") or next(iter(ev.get("workspace_roots") or []), None)
            if isinstance(cwd, str) and re.match(r"^/[A-Za-z]:[/\\]", cwd):   # Windows roots come as /e:/project
                cwd = cwd[1:]
            return ("Bash", {k: v for k, v in (("command", ev.get("command")), ("cwd", cwd)) if v}), session
        if ev.get("hook_event_name") == "beforeReadFile":
            return ("Read", {"file_path": ev.get("file_path")}), session
        if ev.get("hook_event_name") == "beforeMCPExecution":
            return mcp_call(ev.get("mcp_server_name"), ev.get("tool_name"), ev.get("tool_input"),
                            ev.get("command") or ev.get("url") or ev.get("mcp_server_url")), session
        if ev.get("hook_event_name") == "preToolUse":   # Cursor's own tools: here for edits and deletes
            return cursor_tool(str(ev.get("tool_name") or ""), ev.get("tool_input"), ev.get("cwd")), session
        return normalize(str(ev.get("tool_name", "unknown")), ev.get("tool_input")), session
    if agent == "codex" and str(ev.get("tool_name", "")).startswith("mcp__"):
        # Codex's MCP servers live in config.toml, which `connect guard` doesn't rewrite: the hook checks them
        _, server, tool = (str(ev["tool_name"]).split("__", 2) + ["", ""])[:3]
        return mcp_call(server, tool, ev.get("tool_input"), None), ev.get("session_id")
    if agent == "antigravity":
        call = ev.get("toolCall") or {}
        return normalize(str(call.get("name", "unknown")), call.get("args")), ev.get("conversationId")
    return normalize(str(ev.get("tool_name", "unknown")), ev.get("tool_input")), ev.get("session_id")


# --------------------------------------------------------------------------- answers, in each agent's format

def answer(agent: str, allow: bool, message: str = "", stop: bool = False) -> None:
    if agent == "cursor":
        out = {"permission": "allow"} if allow else {"permission": "deny", "user_message": message, "agent_message": message}
    elif agent in ("gemini-cli", "antigravity"):
        out = {"decision": "allow"} if allow else {"decision": "deny", "reason": message}
        if stop and agent == "gemini-cli":
            out.update({"continue": False, "stopReason": message})
    elif agent == "codex":
        if allow:                     # Codex: no output means "carry on"
            sys.exit(0)
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": message}}
    else:                             # vscode
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" if allow else "deny",
                                      **({} if allow else {"permissionDecisionReason": message})}}
        if stop:
            out.update({"continue": False, "stopReason": message})
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
    """Why everything is blocked, in words a person can act on (the agent passes it on). Same text in claude_hook.py."""
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


def check(agent: str, name: str, inp: dict, session: str | None) -> None:
    body = {"name": name, "kind": "agent_hook", "input": inp, "source": agent, "session_id": session}
    line = inp.get("command") if name == "Bash" and effects is not None else None
    cwd = inp.get("cwd") or os.getcwd()
    if line:
        try:
            if found := effects.predict(line, cwd):
                body.setdefault("metadata", {})["effects"] = found
        except Exception:
            pass
        try:  # what `make clean` / `npm run x` / `bash x.sh` runs underneath, so the gateway checks that too
            if found := runs.expand(line, cwd):
                body.setdefault("metadata", {})["runs"] = found
        except Exception:
            pass
    try:
        with gateway_client(URL, KEY, 15) as http:
            r = http.post("/v1/events", json=body)
            if r.status_code == 401:
                raise httpx.HTTPError("the gateway rejected the key")
            r.raise_for_status()
            d = r.json()
            end = time.monotonic() + MAX_WAIT
            while d["decision"] == "review" and time.monotonic() < end:
                wait = min(25.0, end - time.monotonic())
                r = http.get(f"/v1/events/{d['event_id']}/decision", params={"wait": wait}, timeout=wait + 10)
                r.raise_for_status()
                d = r.json()
            if d["decision"] == "allow":
                # these agents don't report results back: mark the call done so it isn't left "pending"
                http.post(f"/v1/events/{d['event_id']}/result", json={"output": {"result": f"not reported by {agent}"}})
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:   # not JSON / not our answer: blocked too
        if FAIL_OPEN:
            answer(agent, True)
        answer(agent, False, unreachable(URL, e))
    if d["decision"] == "allow":
        if line and (kept := undo.snapshot(line, cwd)):
            print(undo.describe(kept), file=sys.stderr)
        answer(agent, True)
    if d["decision"] == "review":
        answer(agent, False, "Squidbrake: nobody approved this in time. Ask the user to approve it in the dashboard, then try again.")
    by, note = d.get("decided_by"), d.get("decision_note")
    if d.get("rule_id") in ("emergency-stop", "session-stop") or (note or "").startswith("The session was stopped"):
        answer(agent, False, f"Squidbrake: {note or d.get('reason')}. Stop working and tell the user.", stop=True)
    if by == "timeout":
        answer(agent, False, "Squidbrake: nobody approved this in time, so it didn't run. Ask the user to approve it in "
                             f"the dashboard ({URL}/dashboard) when you try again.")
    if by:
        answer(agent, False, f"Squidbrake: rejected by {by}." + (f' Note: "{note}".' if note else "")
               + " Don't retry it; ask the user how to proceed.")
    answer(agent, False, f"Squidbrake blocked this (rule '{d.get('rule_id')}'): {(d.get('reason') or '').rstrip('.')}. "
                         "Don't try to work around it.")


def read_event() -> dict | None:
    """The event on stdin as UTF-8 whatever the console's code page, with or without a byte-order mark (Cursor on
    Windows sends one). None if nothing came; ValueError if what came isn't a JSON object."""
    text = sys.stdin.buffer.read().decode("utf-8-sig", errors="replace").strip()
    if not text:
        return None
    ev = json.loads(text)
    if not isinstance(ev, dict):
        raise ValueError("not a JSON object")
    return ev


def main() -> None:
    agent = sys.argv[1] if len(sys.argv) > 1 else ""
    if agent not in AGENTS:
        sys.exit(f"usage: agent_hook.py {{{'|'.join(AGENTS)}}} --url URL --key KEY")
    try:
        ev = read_event()
    except ValueError:
        # Something arrived but it isn't an event we can read: never let that through unchecked
        answer(agent, FAIL_OPEN, f"Squidbrake couldn't read what {agent} sent to its hook, so this was blocked to be "
                                 "safe. Tell the user to run: squidbrake doctor")
    if ev is None:
        answer(agent, True)                       # nothing to check
    if hooklog is not None:
        hooklog.record(agent, str(ev.get("hook_event_name") or (ev.get("toolCall") or {}).get("name") or ev.get("tool_name") or ""))
    action, session = parse(agent, ev)
    if action is None:
        answer(agent, True)
    check(agent, action[0], action[1], session)


if __name__ == "__main__":
    main()
