"""
The `squidbrake` command (installed with pip):

  squidbrake                         start the gateway; the first time it asks once whether to keep it running in
                                     the background and at every login (Enter means no; see service.py)
  squidbrake setup                   everything at once: runs in the background, connects every agent here, checks
                                     them, and opens the dashboard signed in (the installers run this at the end)
  squidbrake start --background      install the background service and start it, without asking
  squidbrake service status | stop   is the background service running / stop it and take it out
  squidbrake run                     run the gateway in this window (same as: python server.py)
  squidbrake connect all             connect every AI agent on this computer (same as: python connect.py ...)
  squidbrake connect claude-code     connect one agent
  squidbrake connect status          which agents are covered (and whether Codex has trusted the hook)
  squidbrake doctor                  check everything end to end, and say what to fix
  squidbrake hook                    the Claude Code hook, used by the Claude Code plugin (plugin/)
  squidbrake agent-hook AGENT        the hook for cursor, codex, gemini-cli, vscode, antigravity
  squidbrake lockdown --url URL      policy files IT pushes to every machine so agents can't skip the gateway
  squidbrake evidence --days 90      a printable evidence pack for your auditor
  squidbrake shell-guard install --shell bash|zsh|powershell   guard the lines you type or paste into your terminal
  squidbrake shell-guard check "LINE"  exit code 0 run, 1 block, 2 ask (used by the snippet above)
  squidbrake undo [ID]               list, or put back, what an agent deleted or overwrote
  squidbrake proxy --app NAME -- CMD an MCP server that checks every call to the app's MCP server CMD first
                                     (same as: python gateway_proxy.py ...); add --serve HOST:PORT --token T to
                                     serve it by URL, for ChatGPT / claude.ai connectors, Devin, n8n, cloud agents
  squidbrake pilot join CODE --server URL   share usage counts with a pilot (asks first; see pilot.py)
  squidbrake telemetry [status|on|off]      anonymous usage stats (asked once; see telemetry.py)
  squidbrake register EMAIL          tell the Squidbrake team who you are (optional, asks first)
  squidbrake add-key NAME | keys | verify FILE | ...   see: squidbrake --help

Data, keys and rules.yaml live in ~/.squidbrake (set SQUIDBRAKE_HOME to move them).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path


def _safe_output() -> None:
    """Printing a name the console's code page can't show (C:/Users/राहुल on Windows, where output to a pipe or a
    log file is cp1252) would stop the command with UnicodeEncodeError: show it escaped instead."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream and (stream.encoding or "").lower().replace("-", "") not in ("utf8", "utf8sig"):
                stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


UPDATE_COMMANDS = {"start", "setup", "run", "doctor", "connect", "status"}


def _upgrade_command() -> str:
    exe = sys.executable.replace("\\", "/").lower()
    if "/uv/tools/" in exe:
        return "uv tool upgrade squidbrake"
    if "/pipx/" in exe:
        return "pipx upgrade squidbrake"
    return f'"{sys.executable}" -m pip install -U squidbrake   (or run the install line again)'


def update_notice(argv: list[str], version: str) -> str | None:
    """Once a day, the newest version number on PyPI (one request, nothing about this computer in it beyond the
    request itself); said the next time you run a command in a terminal. Off: SQUIDBRAKE_NO_UPDATE_CHECK=1 or
    DO_NOT_TRACK=1. Never in hooks, scripts or CI."""
    import json
    import threading
    import time
    command = argv[0] if argv and not argv[0].startswith("-") else "start"
    if command not in UPDATE_COMMANDS or os.getenv("CI") or \
            os.getenv("SQUIDBRAKE_NO_UPDATE_CHECK", "").lower() in ("1", "true", "yes") or \
            os.getenv("DO_NOT_TRACK", "").lower() in ("1", "true", "yes"):
        return None
    try:
        if not sys.stdout.isatty():
            return None
    except (AttributeError, ValueError):
        return None
    path = Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake") / "update-check.json"
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cached = {}

    def check():
        try:
            import httpx
            latest = httpx.get("https://pypi.org/pypi/squidbrake/json", timeout=5).json()["info"]["version"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"checked": time.time(), "latest": latest}), encoding="utf-8")
        except Exception:
            pass
    if time.time() - cached.get("checked", 0) > 86400:
        threading.Thread(target=check, daemon=True).start()     # for next time: never slows this command down
    latest = str(cached.get("latest") or "")
    as_tuple = lambda v: tuple(int(n) for n in re.findall(r"\d+", v)[:3])
    if latest and as_tuple(latest) > as_tuple(version):
        return f"New version {latest} available (you have {version}). Upgrade: {_upgrade_command()}"
    return None


def main() -> int:
    _safe_output()
    here = Path(__file__).resolve().parent
    # The gateway's modules sit next to this file in the package (in a checkout, one folder up)
    # and import each other by their plain names.
    sys.path.insert(0, str(here if (here / "server.py").exists() else here.parent))
    os.environ.setdefault("SQUIDBRAKE_CLI", "squidbrake")
    argv = sys.argv[1:]
    if argv[:1] in (["-V"], ["--version"]):
        from squidbrake import __version__
        print(f"squidbrake {__version__}")
        return 0
    from squidbrake import __version__
    if argv[:1] == ["telemetry"]:
        import telemetry
        return telemetry.main(argv[1:], __version__)
    if argv[:1] == ["register"]:
        import telemetry
        return telemetry.register(argv[1:], __version__)
    try:   # asks once in a terminal; never in the hooks, scripts or CI (see telemetry.py)
        import telemetry
        telemetry.maybe(argv, __version__)
    except Exception:
        pass
    try:
        if note := update_notice(argv, __version__):
            print(note + "\n", file=sys.stderr)
    except Exception:
        pass
    if argv[:1] == ["doctor"]:     # everything a person would check by hand, with what to fix
        import connect
        connect.main(["doctor", *argv[1:]])
        return 0
    if argv[:1] == ["connect"]:
        import connect
        connect.main(argv[1:])
        return 0
    if argv[:1] == ["hook"]:   # the Claude Code plugin's hook (reads the event on stdin)
        sys.argv = ["claude_hook.py", *argv[1:]]
        import claude_hook
        claude_hook.main()
        return 0
    if argv[:1] == ["agent-hook"]:  # the hook for Cursor, Codex, Gemini CLI, VS Code, Antigravity (see lockdown.py)
        sys.argv = ["agent_hook.py", *argv[1:]]
        import agent_hook
        agent_hook.main()
        return 0
    if argv[:1] == ["shell-guard"]:  # check a line typed into your own terminal (see shell_guard.py)
        try:
            import shell_guard
        except Exception:  # a broken install must never block a command: exit 1 means "block"
            return 0 if argv[1:2] == ["check"] else 1
        return shell_guard.main(argv[1:])
    if argv[:1] == ["undo"]:  # list or restore what an agent deleted or overwrote (see undo.py)
        import undo
        return undo.main(argv[1:])
    if argv[:1] == ["proxy"]:  # an MCP server: put Squidbrake in front of any app's MCP server
        sys.argv = ["squidbrake proxy", *argv[1:]]
        import gateway_proxy
        gateway_proxy.main()
        return 0
    if argv[:1] == ["setup"]:      # everything at once: background, every agent connected, dashboard (onboard.py)
        import onboard
        return onboard.main(argv[1:])
    if argv[:1] == ["service"]:
        import service
        return service.main(argv[1:])
    if argv[:1] == ["start"]:
        import service
        return service.main(argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        import service   # `squidbrake` or `squidbrake --port 9000`: asks once before installing anything
        return service.main(["start", *argv])
    import server
    return server.main(argv)


if __name__ == "__main__":
    sys.exit(main())
