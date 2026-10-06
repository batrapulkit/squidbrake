"""
The `squidbrake` command (installed with pip):

  squidbrake                         start the gateway in the background, and again at every login (see service.py)
  squidbrake service status | stop   is the background service running / stop it and take it out
  squidbrake run                     run the gateway in this window instead (same as: python server.py)
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
                                     (same as: python gateway_proxy.py ...)
  squidbrake pilot join CODE --server URL   share usage counts with a pilot (asks first; see pilot.py)
  squidbrake telemetry [status|on|off]      anonymous usage stats (asked once; see telemetry.py)
  squidbrake register EMAIL          tell the Squidbrake team who you are (optional, asks first)
  squidbrake add-key NAME | keys | verify FILE | ...   see: squidbrake --help

Data, keys and rules.yaml live in ~/.squidbrake (set SQUIDBRAKE_HOME to move them).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
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
    if argv[:1] == ["service"]:
        import service
        return service.main(argv[1:])
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        import service   # `squidbrake` or `squidbrake --port 9000`: install the background service and start it
        return service.main(["start", *argv])
    import server
    return server.main(argv)


if __name__ == "__main__":
    sys.exit(main())
