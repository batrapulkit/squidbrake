"""
Connect an AI agent to Squidbrake in one command.
(Installed with pip? Type `squidbrake connect ...` wherever this says `python connect.py ...`.)

  python connect.py all                    every agent on this computer at once: Claude Code, Cursor, Codex,
                                           Gemini CLI, VS Code, Antigravity, and the MCP servers they use (--remove undoes it)
  python connect.py status                 which agents go through Squidbrake, and whether each will run the hook
  python connect.py doctor                 check everything end to end and say what to fix (squidbrake doctor)
                                           (Codex runs a new hook only after you trust it in /hooks)
  python connect.py claude-code            Claude Code: every tool call goes through the gateway (hook)
                                           + database tools (MCP)
  python connect.py claude-code --remove   undo it
  python connect.py mcp --name antigravity Antigravity, Claude Desktop, Cursor, ...: prints the MCP config to paste
                                           (--install writes it into Antigravity's config for you)

Guard every MCP server your agents already use (Cursor, Windsurf, VS Code, Gemini CLI, Antigravity, Claude Desktop):
  python connect.py guard --agent all          (--remove puts the originals back)

Guard any app (Stripe, GitHub, Gmail, Slack, ... anything with an MCP server) for an agent:
  python connect.py wrap --agent claude-code --app stripe --env STRIPE_SECRET_KEY=sk_... -- npx -y @stripe/mcp --tools=all
  python connect.py wrap --agent antigravity --install --sandbox      (the built-in Acme sandbox company)

Options:
  --url URL      gateway address (default http://localhost:8080)
  --key KEY      use an existing agent key (default: create a new key named after the agent;
                 only works on the machine where the gateway runs)
  --project DIR  Claude Code: install for one project folder instead of for all your projects
  --yes          don't ask before changing Claude Code settings
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from urllib.parse import urlparse
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PYTHON = sys.executable
HOOK = BASE_DIR / "claude_hook.py"
MCP_SERVER = BASE_DIR / "gateway_mcp.py"
MCP_NAME = "gateway-db"  # claude_hook.py skips mcp__gateway-db__* so these calls aren't recorded twice


LOCAL_URLS = ("http://localhost", "http://127.0.0.1", "http://[::1]")


def new_key(name: str, url: str = "http://localhost:8080") -> str:
    if not url.startswith(LOCAL_URLS):
        sys.exit(f"This gateway ({url}) runs on another machine, so its keys are made there.\n"
                 f"Ask its admin to add '{name}' as an AI agent in the dashboard's Team tab, then run this again with --key gw_...")
    import server  # the gateway's key store (data/keys.json next to it)
    if server.keystore.from_env:
        sys.exit("Keys come from GATEWAY_API_KEYS on this gateway. Add one there and pass it with --key.")
    # connecting before the gateway's first start: make its first keys now, or the admin key would never be shown
    if created := server.keystore.ensure_initialized():
        server.print_banner(None, created)
    existing = {k["name"] for k in server.keystore.listing()}
    final, n = name, 2
    while final in existing:
        final, n = f"{name}-{n}", n + 1
    key = server.keystore.add(final)
    with server.audited_tx() as conn:
        server.audit(conn, "command-line", "team.added", final, kind="agent", approver=False, roles=[], via="connect.py")
    print(f"Created gateway key '{final}' for this agent.")
    return key


def mcp_entry(url: str, key: str, source: str) -> dict:
    return {"command": PYTHON, "args": [str(MCP_SERVER)],
            "env": {"GATEWAY_URL": url, "GATEWAY_API_KEY": key, "GATEWAY_SOURCE": source}}


# --------------------------------------------------------------------------- claude code

def settings_path(project: str | None) -> Path:
    return (Path(project).resolve() / ".claude" / "settings.json") if project else Path.home() / ".claude" / "settings.json"


def strip_ours(settings: dict) -> dict:
    """Remove hook entries this script added earlier (so re-running doesn't duplicate them)."""
    hooks = settings.get("hooks", {})
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit"):
        groups = []
        for g in hooks.get(event, []):
            g["hooks"] = [h for h in g.get("hooks", []) if "claude_hook.py" not in json.dumps(h)]
            if g["hooks"]:
                groups.append(g)
        if groups:
            hooks[event] = groups
        else:
            hooks.pop(event, None)
    if not hooks:
        settings.pop("hooks", None)
    return settings


def previous_key(settings: dict, url: str) -> str | None:
    """Re-running connect.py reuses the key it installed last time instead of piling up new ones."""
    for g in settings.get("hooks", {}).get("PreToolUse", []):
        for h in g.get("hooks", []):
            a = h.get("args", [])
            if any("claude_hook.py" in x for x in a) and "--key" in a and "--url" in a and a[a.index("--url") + 1] == url:
                return a[a.index("--key") + 1]
    return None


def confirm(question: str, yes: bool) -> bool:
    if yes:
        return True
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def claude_code(args) -> None:
    path = settings_path(args.project)
    try:
        settings = _read_json(path)
    except ValueError as e:     # never overwrite a file we couldn't read: say which one, and stop
        raise SystemExit(f"{path} isn't valid JSON ({e}). Fix it (or move it away), then run this again.")
    claude = shutil.which("claude")
    scope = ["--scope", "project"] if args.project else ["--scope", "user"]

    if args.remove:
        if not confirm(f"Remove Squidbrake hooks from {path}?", args.yes):
            return
        path.write_text(json.dumps(strip_ours(settings), indent=2), encoding="utf-8")
        if claude:
            subprocess.run([claude, "mcp", "remove", MCP_NAME, *scope], cwd=args.project or None)
        print("Removed. Restart Claude Code to apply.")
        return

    where = f"the project {Path(args.project).resolve()}" if args.project else "ALL your Claude Code projects"
    tools = "" if args.hook_only else ",\nand adds database tools"
    print(f"This routes every Claude Code tool call in {where} through the gateway at {args.url}{tools}.\n"
          f"It changes {path} (a backup is kept).")
    if not confirm("Continue?", args.yes):
        return
    key = args.key or previous_key(settings, args.url) or new_key("claude-code", args.url)

    hook_cmd = {"type": "command", "command": PYTHON,
                "args": [str(HOOK), "--url", args.url, "--key", key, "--source", "claude-code"]}
    settings = strip_ours(settings)
    hooks = settings.setdefault("hooks", {})
    hooks.setdefault("PreToolUse", []).append({"matcher": "*", "hooks": [{**hook_cmd, "timeout": 600}]})
    hooks.setdefault("PostToolUse", []).append({"matcher": "*", "hooks": [{**hook_cmd, "timeout": 30}]})
    # a tool that errored (e.g. a command that exited non-zero) reports here instead of PostToolUse
    hooks.setdefault("PostToolUseFailure", []).append({"matcher": "*", "hooks": [{**hook_cmd, "timeout": 30}]})
    # what you ask, so the gateway can tell what came from you and what came from a web page or an email
    hooks.setdefault("UserPromptSubmit", []).append({"hooks": [{**hook_cmd, "timeout": 15}]})
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(f"settings.json.bak-{time.strftime('%Y%m%d-%H%M%S')}"))
    path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    print(f"Added the hook to {path}")
    if args.hook_only:
        print(f"\nDone. Restart Claude Code; every tool call now goes through {args.url}/dashboard")
        return

    entry = mcp_entry(args.url, key, "claude-code")
    cmd = [claude or "claude", "mcp", "add", "--transport", "stdio", MCP_NAME, *scope,
           *[x for k, v in entry["env"].items() for x in ("--env", f"{k}={v}")], "--", entry["command"], *entry["args"]]
    if claude:
        subprocess.run([claude, "mcp", "remove", MCP_NAME, *scope], cwd=args.project or None,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok = subprocess.run(cmd, cwd=args.project or None).returncode == 0
        print("Added the database tools (MCP server 'gateway-db')." if ok else "Adding the MCP server failed; see above.")
    else:
        print("The `claude` command wasn't found, so add the database tools yourself with:\n  " + subprocess.list2cmdline(cmd))
    print("\nDone. Restart Claude Code, then try asking it:\n"
          '  "Using the gateway-db tools, show me the top 5 customers by revenue"\n'
          '  "Give every customer on the team plan a 15% discount"   <- waits for your approval\n'
          '  "Drop the orders table"                                <- blocked\n'
          f"Watch it all at {args.url}/dashboard")


# --------------------------------------------------------------------------- other MCP clients

WHERE = {
    "antigravity": "Antigravity: in the Agent panel open the '...' menu > MCP Servers > Manage MCP Servers > "
                   "View raw config, and merge this into mcp_config.json",
    "claude-desktop": "Claude Desktop: Settings > Developer > Edit Config, and merge this into claude_desktop_config.json",
    "cursor": "Cursor: merge this into ~/.cursor/mcp.json (or Settings > MCP > Add new server)",
}


def mcp(args) -> None:
    name = args.name
    key = args.key or existing_mcp_key(name, args.url) or new_key(name, args.url)
    deliver(name, MCP_NAME, mcp_entry(args.url, key, name), args,
            f"The agent then has list_tables / describe_table / query / execute tools; watch at {args.url}/dashboard")


# --------------------------------------------------------------------------- guard any app

def antigravity_config() -> Path:          # looked up each time, so tests (and a changed HOME) see the right one
    return Path.home() / ".gemini" / "antigravity" / "mcp_config.json"
PROXY = BASE_DIR / "gateway_proxy.py"
SANDBOX = BASE_DIR / "demo_apps_mcp.py"


def agent_configs() -> dict[str, Path]:
    """Where each agent keeps its MCP servers (only read here, to find a key we gave it before)."""
    appdata = Path(os.getenv("APPDATA") or Path.home() / "AppData" / "Roaming")
    desktop = (appdata / "Claude" if sys.platform == "win32" else
               Path.home() / "Library" / "Application Support" / "Claude" if sys.platform == "darwin" else
               Path.home() / ".config" / "Claude")
    return {"antigravity": antigravity_config(), "cursor": Path.home() / ".cursor" / "mcp.json",
            "claude-desktop": desktop / "claude_desktop_config.json"}


def existing_mcp_key(agent: str, url: str) -> str | None:
    """Reuse the key this agent already has (from its MCP config) instead of making a new one."""
    path = agent_configs().get(agent)
    if path and path.exists():
        try:
            servers = json.loads(path.read_text(encoding="utf-8") or "{}").get("mcpServers", {})
        except ValueError:
            return None
        for s in servers.values():
            env = s.get("env", {})
            if env.get("GATEWAY_URL") == url and env.get("GATEWAY_API_KEY"):
                return env["GATEWAY_API_KEY"]
    return None


def install_json(path: Path, server_name: str, entry: dict) -> None:
    text = path.read_text(encoding="utf-8").strip() if path.exists() else ""
    data = json.loads(text) if text else {}
    if path.exists():
        shutil.copy2(path, path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}"))
    data.setdefault("mcpServers", {})[server_name] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def deliver(agent: str, server_name: str, entry: dict, args, done: str) -> None:
    """Install the MCP server for the agent, or print the config to paste."""
    if agent == "claude-code":
        claude = shutil.which("claude")
        scope = ["--scope", "project"] if args.project else ["--scope", "user"]
        cmd = [claude or "claude", "mcp", "add", "--transport", "stdio", server_name, *scope,
               *[x for k, v in entry["env"].items() for x in ("--env", f"{k}={v}")], "--", entry["command"], *entry["args"]]
        if not claude:
            print("The `claude` command wasn't found; add it yourself with:\n  " + subprocess.list2cmdline(cmd))
            return
        subprocess.run([claude, "mcp", "remove", server_name, *scope], cwd=args.project or None,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if subprocess.run(cmd, cwd=args.project or None).returncode == 0:
            print(f"Added MCP server '{server_name}' to Claude Code. Restart Claude Code. {done}")
        return
    if agent == "antigravity" and getattr(args, "install", False):
        install_json(antigravity_config(), server_name, entry)
        print(f"Added '{server_name}' to {antigravity_config()} (backup kept). Restart Antigravity. {done}")
        return
    print("\n" + WHERE.get(agent, "Add this to your agent's MCP configuration") + ", then restart the agent:\n")
    print(json.dumps({"mcpServers": {server_name: entry}}, indent=2))
    print("\n" + done)


def wrap(args) -> None:
    if args.sandbox:
        app, command = args.app or "acme", [PYTHON, str(SANDBOX)]
    else:
        command = [c for c in args.command if c != "--"]
        app = args.app
        if not app or not (command or args.app_url):
            sys.exit("give --app NAME and the app's MCP command after --  (or --app-url URL), or use --sandbox")
    key = args.key
    if not key and args.agent == "claude-code":
        path = settings_path(args.project)
        key = previous_key(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}, args.url)
    key = key or existing_mcp_key(args.agent, args.url) or new_key(args.agent, args.url)
    env = {"GATEWAY_URL": args.url, "GATEWAY_API_KEY": key, "GATEWAY_SOURCE": args.agent}
    for kv in args.env or []:  # the app's own credentials, e.g. STRIPE_SECRET_KEY=sk_live_...
        k, _, v = kv.partition("=")
        env[k] = v
    target = ["--url", args.app_url] if args.app_url else ["--", *command]
    entry = {"command": PYTHON, "args": [str(PROXY), "--app", app, *target], "env": env}
    # Claude Code's hook skips mcp__gw-* tools: the proxy already records them.
    deliver(args.agent, f"gw-{app}", entry, args,
            f"Its {app} tools now go through the gateway (shown as {app}.<tool>); watch at {args.url}/dashboard")


# --------------------------------------------------------------------------- guard an agent's own MCP servers

def _user_dir() -> Path:
    appdata = Path(os.getenv("APPDATA") or Path.home() / "AppData" / "Roaming")
    return (appdata if sys.platform == "win32" else
            Path.home() / "Library" / "Application Support" if sys.platform == "darwin" else Path.home() / ".config")


def mcp_configs() -> dict[str, list[tuple[Path, str]]]:
    """agent -> its user-level MCP config files, each with the key its servers live under."""
    home = Path.home()
    devin = (Path(os.getenv("APPDATA") or home) / "devin" if sys.platform == "win32" else
             Path(os.getenv("XDG_CONFIG_HOME") or home / ".config") / "devin")
    return {
        "cursor": [(home / ".cursor" / "mcp.json", "mcpServers")],
        "windsurf": [(devin / "mcp_config.json", "mcpServers"), (home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers")],
        "vscode": [(_user_dir() / "Code" / "User" / "mcp.json", "servers"), (home / ".copilot" / "mcp-config.json", "mcpServers")],
        "gemini-cli": [(home / ".gemini" / "settings.json", "mcpServers")],
        "antigravity": [(home / ".gemini" / "config" / "mcp_config.json", "mcpServers"), (antigravity_config(), "mcpServers")],
        "kiro": [(home / ".kiro" / "settings" / "mcp.json", "mcpServers")],
        "claude-desktop": [(agent_configs()["claude-desktop"], "mcpServers")],
    }


def _originals_path(agent: str, path: Path) -> Path:
    tag = hashlib.sha1(str(path).encode()).hexdigest()[:8]
    return Path.home() / ".squidbrake" / "guarded" / f"{agent}-{tag}.json"


def _ours(entry: dict) -> bool:
    text = json.dumps(entry)
    return "gateway_proxy.py" in text or "gateway_mcp.py" in text or "demo_apps_mcp.py" in text


def guard(args) -> None:
    """Route every MCP server an agent already uses through Squidbrake (or put them back with --remove)."""
    configs = mcp_configs()
    if args.agent != "all" and args.agent not in configs:
        sys.exit(f"don't know where {args.agent} keeps its MCP servers; known: {', '.join(configs)}")
    targets = [(a, path, key_name) for a, files in configs.items() if args.agent in ("all", a)
               for path, key_name in files if path.exists()]
    if not targets:
        print("No MCP configs found for: " + ", ".join(configs if args.agent == "all" else [args.agent]))
        return
    keys: dict[str, str] = {}
    for agent, path, key_name in targets:
        text = path.read_text(encoding="utf-8").strip() if path.exists() else ""
        try:
            data = json.loads(text) if text else {}
        except ValueError:
            print(f"{agent}: {path} isn't plain JSON (comments?); skipped. Use `connect wrap` for single servers.")
            continue
        servers = data.get(key_name) or {}
        saved_path = _originals_path(agent, path)
        saved = json.loads(saved_path.read_text(encoding="utf-8")) if saved_path.exists() else {}
        if args.remove:
            for name, original in saved.items():
                if name in servers:
                    servers[name] = original
            changed, note = list(saved), "restored"
        else:
            if any(not _ours(e) for e in servers.values() if isinstance(e, dict) and not e.get("disabled")):
                keys[agent] = keys.get(agent) or args.key or existing_mcp_key(agent, args.url) or new_key(agent, args.url)
            key = keys.get(agent, "")
            changed, skipped = [], []
            for name, entry in servers.items():
                if not isinstance(entry, dict) or _ours(entry) or entry.get("disabled"):
                    continue
                remote = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
                headers = entry.get("headers") if isinstance(entry.get("headers"), dict) else {}
                # a remote server's own headers (its auth) go along to it through the proxy
                target = (["--url", remote, *[a for k, v in headers.items() for a in ("--header", f"{k}: {v}")]]
                          if remote else ["--", entry.get("command", ""), *entry.get("args", [])])
                if not remote and not entry.get("command"):
                    skipped.append(name)
                    continue
                app = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-") or "app"
                env = {**(entry.get("env") or {}), "GATEWAY_URL": args.url, "GATEWAY_API_KEY": key, "GATEWAY_SOURCE": agent}
                saved[name] = entry
                servers[name] = {**({"type": "stdio"} if key_name == "servers" else {}),
                                 "command": PYTHON, "args": [str(PROXY), "--app", app, *target], "env": env}
                changed.append(name)
            note = "now go through Squidbrake" + (f" (skipped: {', '.join(skipped)})" if skipped else "")
        if not changed:
            print(f"{agent}: nothing to {'restore' if args.remove else 'guard'} in {path}")
            continue
        if not args.yes and not confirm(f"{agent}: change {len(changed)} MCP server(s) in {path} (a backup is kept)?", False):
            continue
        shutil.copy2(path, path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}"))
        data[key_name] = servers
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        saved_path.parent.mkdir(parents=True, exist_ok=True)
        if args.remove:
            saved_path.unlink(missing_ok=True)
        else:
            saved_path.write_text(json.dumps(saved, indent=2), encoding="utf-8")
        print(f"{agent}: {', '.join(changed)} {note}. Restart {agent} to apply.")


# --------------------------------------------------------------------------- hooks for the other coding agents

AGENT_HOOK = BASE_DIR / "agent_hook.py"


def _q(s: str) -> str:
    return f'"{s}"' if " " in s else s


def _short_path(path: str) -> str:
    """Windows' short (8.3) name for a path, which has no spaces: C:/Users/Rahul Kumar -> C:/Users/RAHULK~1."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetShortPathNameW(path, buf, len(buf))
        return buf.value if 0 < n < len(buf) else path
    except (AttributeError, OSError):
        return path


def _word(path: str) -> str:
    """A path as one word that cmd, PowerShell and bash all read the same way. Agents run hook commands through
    different shells (Cursor on Windows: PowerShell, or bash when started from Git Bash): to PowerShell a quoted first
    word is a string, not a program to run, and bash drops backslashes. So on Windows: forward slashes, and the short
    name when the path has a space. Only if the drive has no short names does it stay quoted."""
    if os.name == "nt":
        if " " in path:
            path = _short_path(path)
        path = path.replace("\\", "/")
    return _q(path)


def _get(base: str, url: str, **kw):
    """GET from the gateway. One on this computer is reached directly: a system proxy (common on company Windows
    laptops) often doesn't bypass 127.0.0.1, and would make a running gateway look down."""
    import httpx
    host = urlparse(base).hostname or ""
    return httpx.get(url, trust_env=host not in ("localhost", "127.0.0.1", "::1"), **kw)


def _read_json(path: Path) -> dict:
    # utf-8-sig: Notepad and PowerShell 5.1 save JSON with a byte-order mark; an empty file is an empty config
    text = path.read_text(encoding="utf-8-sig").strip() if path.exists() else ""
    return json.loads(text) if text else {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}"))
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _without_ours(entries: list) -> list:
    return [e for e in entries or [] if "agent_hook.py" not in json.dumps(e)]


def hook_agents() -> dict[str, dict]:
    """agent -> how to tell it's installed, and how to add / remove Squidbrake's hook in its config."""
    home = Path.home()

    def cursor(data, cmd):
        data.setdefault("version", 1)
        hooks = data.setdefault("hooks", {})
        # shell, reads and MCP calls have their own hooks; preToolUse (newer Cursor) adds file edits and deletes
        for ev, matcher in (("beforeShellExecution", None), ("beforeReadFile", None), ("beforeMCPExecution", None),
                            ("preToolUse", "Write|Delete")):
            ours = {"command": cmd, "timeout": 600, "failClosed": True, **({"matcher": matcher} if matcher else {})}
            hooks[ev] = _without_ours(hooks.get(ev)) + ([ours] if cmd else [])
            if not hooks[ev]:
                hooks.pop(ev)

    def grouped(event, matcher, timeout):
        def edit(data, cmd):
            hooks = data.setdefault("hooks", {})
            hooks[event] = _without_ours(hooks.get(event)) + (
                [{"matcher": matcher, "hooks": [{"name": "squidbrake", "type": "command", "command": cmd, "timeout": timeout}]}]
                if cmd else [])
            if not hooks[event]:
                hooks.pop(event)
            if not hooks:
                data.pop("hooks")
        return edit

    def vscode(data, cmd):
        data.clear()
        if cmd:
            data["hooks"] = {"PreToolUse": [{"type": "command", "command": cmd, "timeout": 600}]}

    def antigravity(data, cmd):
        data.pop("squidbrake", None)
        if cmd:
            data["squidbrake"] = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 600}]}]}

    return {
        "cursor": {"present": (home / ".cursor").exists(), "file": home / ".cursor" / "hooks.json", "edit": cursor,
                   "covers": "terminal commands, file reads, edits and deletes, and MCP tools"},
        "gemini-cli": {"present": bool(shutil.which("gemini")) or (home / ".gemini" / "settings.json").exists(),
                       "file": home / ".gemini" / "settings.json",
                       "edit": grouped("BeforeTool", "run_shell_command|write_file|replace|read_file|read_many_files", 600000),
                       "covers": "shell commands, file reads, writes and edits"},
        "codex": {"present": bool(shutil.which("codex")) or (home / ".codex").exists(), "file": home / ".codex" / "hooks.json",
                  "edit": grouped("PreToolUse", "Bash|shell|apply_patch|Edit|Write|mcp__.*", 600),
                  "covers": "shell commands, edits and MCP tools"},
        "vscode": {"present": (_user_dir() / "Code" / "User").exists() or (home / ".copilot").exists(),
                   "file": home / ".copilot" / "hooks" / "squidbrake.json", "edit": vscode,
                   "covers": "Copilot agent mode: terminal commands, reads and edits"},
        "antigravity": {"present": (home / ".gemini" / "antigravity").exists() or (home / ".gemini" / "config").exists(),
                        "file": home / ".gemini" / "config" / "hooks.json", "edit": antigravity,
                        "covers": "terminal commands, file reads and writes"},
    }


def agents(args) -> None:
    """Add (or with --remove, take out) Squidbrake's pre-execution hook in every coding agent installed here."""
    table = hook_agents()
    chosen = [a for a in table if args.agent in ("all", a)]
    if args.agent != "all" and not chosen:
        sys.exit(f"no hook support for {args.agent} yet; supported: {', '.join(table)}")
    key = None
    for name in chosen:
        t = table[name]
        if not (t["present"] or args.agent == name or args.remove):
            continue
        try:
            data = _read_json(t["file"])
        except ValueError:
            print(f"{name}: {t['file']} isn't plain JSON (comments?); skipped")
            continue
        if args.remove:
            before = json.dumps(data)
            t["edit"](data, None)
            if json.dumps(data) != before:
                if data:
                    _write_json(t["file"], data)
                else:
                    t["file"].unlink(missing_ok=True)
                print(f"{name}: hook removed")
            continue
        key = key or args.key or new_key("agents", args.url)
        cmd = " ".join([_word(PYTHON), _word(str(AGENT_HOOK)), name, "--url", args.url, "--key", key])
        t["edit"](data, cmd)
        _write_json(t["file"], data)
        print(f"{name}: hook added ({t['covers']}). Restart {name} to apply.")
        if name == "codex" and codex_hook_trust() != "trusted":
            print(CODEX_UNTRUSTED)


CODEX_UNTRUSTED = ("  !! Codex won't run it yet: it skips a new hook until you approve it. Until then NOTHING Codex does is\n"
                   "     checked, in any mode. Open Codex, type /hooks and trust the Squidbrake hook. Check with:\n"
                   "     squidbrake connect status")


def codex_hook_trust(timeout: float = 20) -> str | None:
    """Ask Codex itself whether it will run Squidbrake's hook: "trusted", "untrusted" or "modified" (what /hooks
    shows, from its app-server's hooks/list). None if Codex isn't installed, has no Squidbrake hook, or didn't answer."""
    codex = shutil.which("codex")
    if not codex:
        return None
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"clientInfo": {"name": "squidbrake", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "hooks/list", "params": {"cwds": [str(Path.home())]}}]
    try:
        proc = subprocess.Popen([codex, "app-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
    except OSError:
        return None
    answer: list[dict] = []

    def read() -> None:
        for line in proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("id") == 2:
                answer.append(msg)
                return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        proc.stdin.write("".join(json.dumps(r) + "\n" for r in requests))
        proc.stdin.flush()
    except OSError:
        pass
    reader.join(timeout)
    proc.kill()
    if not answer:
        return None
    statuses = [h.get("trustStatus") for d in (answer[0].get("result") or {}).get("data", [])
                for h in d.get("hooks", []) if "agent_hook.py" in (h.get("command") or "")]
    if not statuses:
        return None
    return next((s for s in statuses if s not in ("trusted", "managed")), "trusted")


def _hooked_gateway() -> tuple[str, str] | None:
    """(url, key) the installed hooks point at, so status checks a hosted dashboard, not localhost."""
    files = [settings_path(None)] + [t["file"] for t in hook_agents().values()]
    for f in files:
        try:
            cmds = _hook_commands(json.loads(f.read_text(encoding="utf-8", errors="replace"))) if f.exists() else []
        except (OSError, ValueError):
            continue
        for c in cmds:
            if m := re.search(r"--url\s+\"?(\S+?)\"?\s+--key\s+\"?(gw_[A-Za-z0-9_\-]+)", c):
                return m.group(1), m.group(2)
    return None


AGENT_LABELS = {"claude-code": "Claude Code", "cursor": "Cursor", "codex": "Codex", "gemini-cli": "Gemini CLI",
                "vscode": "VS Code Copilot", "antigravity": "Antigravity"}


def local_agents() -> list[dict]:
    """Every agent this computer has, and whether Squidbrake's hook is in it (the dashboard's toggles)."""
    on = set(connected_agents())
    found = [{"name": "claude-code", "present": bool(shutil.which("claude")) or (Path.home() / ".claude").exists()}]
    found += [{"name": n, "present": t["present"]} for n, t in hook_agents().items()]
    return [{**a, "label": AGENT_LABELS.get(a["name"], a["name"]), "connected": a["name"] in on} for a in found]


def set_agent(name: str, on: bool, url: str) -> None:
    """Connect (or take out) one agent, the way `connect all --agent NAME` does, with the key the other hooks use."""
    if name not in AGENT_LABELS:
        raise ValueError(f"unknown agent {name}")
    hooked = _hooked_gateway()
    key = hooked[1] if hooked else None
    args = argparse.Namespace(url=url, key=key, remove=not on, yes=True, agent=name, project=None, hook_only=True)
    if name == "claude-code":
        claude_code(args)
    else:
        agents(args)
        if name in ("cursor", "vscode", "gemini-cli", "antigravity"):
            guard(args)


def connected_agents() -> list[str]:
    """The agents on this computer whose config has Squidbrake's hook in it (no network, nothing run)."""
    found = []
    claude = settings_path(None)
    try:
        text = claude.read_text(encoding="utf-8", errors="replace") if claude.exists() else ""
        if "claude_hook.py" in text or ("squidbrake" in text and re.search(r"\bhook\b", text)):   # or the plugin's
            found.append("claude-code")
    except OSError:
        pass
    for name, t in hook_agents().items():
        try:
            text = t["file"].read_text(encoding="utf-8", errors="replace") if t["file"].exists() else ""
        except OSError:
            continue
        if "agent_hook.py" in text or "agent-hook" in text:
            found.append(name)
    return found


def status(args) -> int:
    """Which agents here go through Squidbrake, and whether each one will really run the hook."""
    hooked = _hooked_gateway()
    url = args.url or (hooked[0] if hooked else "http://localhost:8080")
    key = args.key or (hooked[1] if hooked and url == hooked[0] else None)
    hosted = not url.startswith(("http://localhost", "http://127.0.0.1"))
    try:
        import httpx
        up = _get(url, f"{url}/health", timeout=8).status_code == 200
        accepted = None if not key else _get(url, f"{url}/v1/me", headers={"X-Gateway-Key": key}, timeout=8).status_code == 200
    except Exception:
        up, accepted = False, None
    print(f"gateway       {url}: {'running' if up else 'NOT REACHABLE' + ('' if hosted else ' (start it: squidbrake)')}")
    if accepted is False:
        print("              the key in your agents' hooks is REJECTED: run the install command from your start page "
              "again with your current agent key")
    problems = 0 if up and accepted is not False else 1
    claude = settings_path(None)
    if (Path.home() / ".claude").exists() or shutil.which("claude"):
        hooked = claude.exists() and "claude_hook.py" in claude.read_text(encoding="utf-8", errors="replace")
        print(f"{'claude-code':13} {'connected' if hooked else 'no hook in settings.json (fine if you use the plugin)'}")
    for name, t in hook_agents().items():
        if not t["present"]:
            continue
        text = t["file"].read_text(encoding="utf-8", errors="replace") if t["file"].exists() else ""
        if "agent_hook.py" not in text:
            print(f"{name:13} not connected (squidbrake connect agents --agent {name})")
            problems += 1
            continue
        if name == "codex":
            trust = codex_hook_trust()
            if trust == "trusted":
                print(f"{name:13} connected (hook trusted in Codex)")
            else:
                print(f"{name:13} hook added, but {('NOT TRUSTED' if trust else 'trust unknown (Codex did not answer)')}")
                print(CODEX_UNTRUSTED)
                problems += 1
            continue
        print(f"{name:13} connected")
    return 1 if problems else 0


# --------------------------------------------------------------------------- doctor: is it all really working?

DOCTOR_COMMAND = "echo squidbrake doctor check"     # read-only: allowed without anyone approving
DOCTOR_EVENTS = {
    "claude-code": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": DOCTOR_COMMAND},
                    "session_id": "squidbrake-doctor"},
    "cursor": {"hook_event_name": "beforeShellExecution", "command": DOCTOR_COMMAND, "conversation_id": "squidbrake-doctor"},
    "antigravity": {"toolCall": {"name": "run_command", "args": {"CommandLine": DOCTOR_COMMAND}},
                    "conversationId": "squidbrake-doctor"},
}
RESTART = {"cursor": "Quit Cursor completely (Cmd+Q on a Mac, File > Exit on Windows) and open it again",
           "claude-code": "Close every Claude Code window and start it again",
           "codex": "Quit Codex and start it again", "gemini-cli": "Quit Gemini CLI and start it again",
           "vscode": "Quit VS Code completely and open it again", "antigravity": "Quit Antigravity and open it again"}


def _join(parts: list[str]) -> str:
    return subprocess.list2cmdline(parts) if os.name == "nt" else " ".join(shlex.quote(p) for p in parts)


def _hook_commands(data) -> list[str]:
    """Every Squidbrake hook command in an agent's config, wherever that agent nests it, as one command line
    (Claude Code keeps the program in "command" and its arguments in "args")."""
    found = []
    if isinstance(data, dict):
        cmd, args = data.get("command"), data.get("args")
        if isinstance(cmd, str):
            full = _join([cmd, *map(str, args)]) if isinstance(args, list) and args else cmd
            if re.search(r"agent_hook\.py|claude_hook\.py|squidbrake\S* (agent-)?hook", full):
                found.append(full)
        for k, v in data.items():
            if k not in ("command", "args"):
                found += _hook_commands(v)
    elif isinstance(data, list):
        for v in data:
            found += _hook_commands(v)
    return list(dict.fromkeys(found))


def _run_hook(cmd: str, event: dict, powershell: bool = True) -> tuple[bool, str]:
    """Run the hook exactly as the agent would, with a harmless command. -> (allowed, what it said)
    On Windows also through PowerShell, which is what Cursor runs hooks with: a line cmd runs can fail there.
    Not for Claude Code: it runs "command" with "args" directly, no shell (a quoted path is fine there)."""
    if powershell and os.name == "nt" and (ps := shutil.which("powershell") or shutil.which("pwsh")):
        ok, said = _run_hook_in(cmd, event, True)
        if not ok:
            return ok, said
        ok, said = _run_hook_in([ps, "-NoProfile", "-NonInteractive", "-Command", cmd], event, False)
        return ok, (f"in PowerShell (how Cursor runs it): {said}" if not ok else said)
    return _run_hook_in(cmd, event, True)


def _run_hook_in(cmd, event: dict, shell: bool) -> tuple[bool, str]:
    env = {**os.environ, "SQUIDBRAKE_DOCTOR": "1"}
    try:
        p = subprocess.run(cmd, shell=shell, input=json.dumps({**event, "cwd": str(Path.home())}), capture_output=True,
                           text=True, timeout=45, env=env, cwd=str(Path.home()))
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    out = (p.stdout or "") + (p.stderr or "")
    denied = re.search(r'"(permission|decision|permissionDecision)"\s*:\s*"deny"', p.stdout or "")
    if p.returncode != 0 or denied:
        m = re.search(r'"(?:user_message|reason|permissionDecisionReason)"\s*:\s*"([^"]+)"', out)
        return False, (m.group(1) if m else out.strip()[-300:] or f"exit code {p.returncode}")
    return True, ""


def _cursor_version() -> str | None:
    import plistlib
    for app in (Path("/Applications/Cursor.app"), Path.home() / "Applications" / "Cursor.app"):
        try:
            return plistlib.loads((app / "Contents" / "Info.plist").read_bytes()).get("CFBundleShortVersionString")
        except (OSError, ValueError):
            pass
    pkg = Path(os.getenv("LOCALAPPDATA", "")) / "Programs" / "cursor" / "resources" / "app" / "package.json"
    try:
        return json.loads(pkg.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError):
        return None


def _cursor_hooks_log() -> dict:
    """What Cursor's own hooks log (on disk) says: did it load Squidbrake's hook, has it run it, real errors.
    -> {"loaded": "beforeShellExecution, beforeReadFile" | "" | None, "ran": bool, "errors": [...]}"""
    roots = [Path.home() / "Library" / "Application Support" / "Cursor" / "logs",
             Path(os.getenv("APPDATA", "")) / "Cursor" / "logs", Path.home() / ".config" / "Cursor" / "logs"]
    for root in roots:
        try:
            sessions = sorted((d for d in root.iterdir() if d.is_dir()), key=lambda d: d.stat().st_mtime)[-2:]
        except OSError:
            continue
        logs = sorted((f for s in sessions for f in s.rglob("*.log") if "hook" in f.name.lower()),
                      key=lambda f: f.stat().st_mtime, reverse=True)
        if not logs:
            continue
        lines = logs[0].read_text(encoding="utf-8", errors="replace").splitlines()
        loaded = None
        for l in lines:
            if m := re.search(r"Loaded (\d+) user hook\(s\) for steps:\s*(.*)$", l):
                loaded = m.group(2).strip() if int(m.group(1)) else ""
        ran = any(re.search(r"Hook step requested: (beforeShellExecution|beforeReadFile)", l) for l in lines)
        # not real problems: a project without its own hooks file, and Claude Code events Cursor doesn't know
        noise = re.compile(r"Failed to parse project hooks configuration|No project hooks|\[Claude\] Unknown", re.I)
        errors = [l.strip()[:200] for l in lines if re.search(r"error|fail|invalid", l, re.I) and not noise.search(l)]
        return {"loaded": loaded, "ran": ran, "errors": errors[-3:]}
    return {"loaded": None, "ran": False, "errors": []}


def doctor(args) -> int:
    """Everything a person would otherwise check by hand, in one go, with what to do about each problem."""
    from datetime import timedelta

    import httpx
    import hooklog
    bad = warn = used = 0
    unused: list[tuple[str, str, str, list[str]]] = []

    def say(mark, text, fix=None):
        nonlocal bad, warn
        bad += mark == "X"
        warn += mark == "!"
        print(f"  [{mark if mark != 'OK' else 'OK'}] {text}")
        if fix:
            print(f"       -> {fix}")

    print("\nSquidbrake doctor\n")
    try:
        from squidbrake import __version__ as mine
    except Exception:
        try:
            from importlib.metadata import version as _v
            mine = _v("squidbrake")
        except Exception:
            mine = "?"
    latest = None
    no_check = os.getenv("SQUIDBRAKE_NO_UPDATE_CHECK") or os.getenv("DO_NOT_TRACK", "").lower() in ("1", "true", "yes")
    try:     # the same switches as the daily update check turn this off (README)
        latest = None if no_check else httpx.get("https://pypi.org/pypi/squidbrake/json", timeout=6).json()["info"]["version"]
    except Exception:
        latest = None
    if latest and mine != "?" and tuple(int(x) for x in re.findall(r"\d+", mine)[:3]) < tuple(int(x) for x in re.findall(r"\d+", latest)[:3]):
        say("!", f"Squidbrake {mine} (latest is {latest})", "run the install command from your start page again to update")
    else:
        say("OK", f"Squidbrake {mine}")

    hooked = _hooked_gateway()
    url = args.url or (hooked[0] if hooked else "http://localhost:8080")
    key = args.key or (hooked[1] if hooked and url == hooked[0] else None)
    local = url.startswith(("http://localhost", "http://127.0.0.1"))
    try:
        up = _get(url, f"{url}/health", timeout=8).status_code == 200
    except Exception:
        up = False
    if up:
        say("OK", f"Dashboard answers: {url}")
    else:
        say("X", f"Dashboard doesn't answer: {url}",
            "start it with: squidbrake" if local else "it may have been deleted; ask whoever sent you the link for a new one")
    if up and key:
        try:
            ok = _get(url, f"{url}/v1/me", headers={"X-Gateway-Key": key}, timeout=8).status_code == 200
        except Exception:
            ok = None
        if ok is False:
            say("X", "The agents' key is rejected by the dashboard",
                "run the install command from your start page again, with your current AGENT key")
        elif ok:
            say("OK", "The agents' key works")

    agents = {}
    claude = settings_path(None)
    if claude.exists() or (Path.home() / ".claude").exists() or shutil.which("claude"):
        agents["claude-code"] = claude
    for name, t in hook_agents().items():
        if t["present"]:
            agents[name] = t["file"]
    if not agents:
        say("X", "No coding agent found on this computer (Claude Code, Cursor, Codex, Gemini CLI, VS Code, Antigravity)")
    for name, f in agents.items():
        try:
            cmds = _hook_commands(json.loads(f.read_text(encoding="utf-8-sig"))) if f.exists() else []
        except (OSError, ValueError):
            cmds = []
        if not cmds:
            say("X", f"{name}: not connected", "run the install command from your start page again (or: squidbrake connect all)")
            continue
        exe = cmds[0].strip()
        try:     # the program, quoted or not, with spaces in its path (C:\Users\Rahul Kumar\..., /Users/a b/...)
            exe = shlex.split(exe, posix=os.name != "nt")[0].strip('"')
        except ValueError:
            exe = exe.split()[0]
        if not Path(exe).exists() and not shutil.which(exe):
            say("X", f"{name}: its hook points to a Squidbrake that isn't installed any more ({exe})",
                "run the install command from your start page again")
            continue
        allowed, said = _run_hook(cmds[0], DOCTOR_EVENTS.get(name, {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                                                      "tool_input": {"command": DOCTOR_COMMAND},
                                                                      "session_id": "squidbrake-doctor"}),
                                  powershell=name != "claude-code")
        if not allowed:
            say("X", f"{name}: the hook runs but answered: {said[:240]}",
                "fix the dashboard or key line above, then run: squidbrake doctor")
            continue
        if name == "codex" and codex_hook_trust() != "trusted":
            say("X", "codex: hook works, but Codex hasn't trusted it yet, so Codex skips it",
                "open Codex, type /hooks, and trust the Squidbrake hook")
            continue
        last = hooklog.last_call(name) or (hooklog.last_call("cursor-via-claude-code") if name == "cursor" else None)
        since = datetime_from_mtime(f)
        if last and last >= since - timedelta(seconds=2):   # timestamps and file times differ slightly
            say("OK", f"{name}: connected, and it used the hook {ago(last)}")
            used += 1
        elif args.quick:
            say("OK", f"{name}: connected; the hook works", RESTART.get(name, f"restart {name}") + ", then use it as usual")
        elif name == "cursor" and (log := _cursor_hooks_log())["loaded"]:
            # Cursor says it loaded the hook: it just hasn't had a terminal command or file read to check yet
            unused.append((name, f"cursor: connected, and Cursor has loaded the hook ({log['loaded']}), but its agent "
                                 "hasn't run a terminal command since",
                           "in Cursor's Agent chat (Ctrl+I / Cmd+I), type: Run git status in the terminal. Commands you "
                           "type into the terminal yourself aren't sent to the hook. Then run: squidbrake doctor", []))
        else:
            extra, log = "", (_cursor_hooks_log() if name == "cursor" else None)
            if name == "cursor":
                v = _cursor_version()
                extra = f" (Cursor {v})" if v else ""
                if log["loaded"] == "":
                    extra += "; Cursor's log says it loaded no user hooks"
            unused.append((name, f"{name}: connected and the hook works, but {name} hasn't run it since it was connected{extra}",
                           RESTART.get(name, f"restart {name}") + ", then ask its agent (in its chat, not by typing in "
                           "the terminal yourself) to run a terminal command, like: Run git status in the terminal. "
                           "Then run: squidbrake doctor", (log or {}).get("errors", [])))
    for name, text, fix, errors in unused:
        if used:   # another agent already works through it: one you don't open isn't a problem
            print(f"  [-] {name}: connected, not used yet (fine if you don't use {name})")
            continue
        say("!", text, fix)
        for line in errors:
            print(f"       Cursor's hooks log: {line}")
    print()
    if bad:
        print("Fix the [X] lines above, then run: squidbrake doctor\n")
    elif warn:
        print("Almost there: do what the [!] lines say, then run: squidbrake doctor\n")
    else:
        print("Everything works.\n")
    return 1 if bad else 0


def datetime_from_mtime(f: Path):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(f.stat().st_mtime, timezone.utc)


def ago(t) -> str:
    from datetime import datetime, timezone
    s = int((datetime.now(timezone.utc) - t).total_seconds())
    return "just now" if s < 60 else f"{s // 60} min ago" if s < 3600 else f"{s // 3600} h ago" if s < 86400 else f"{s // 86400} days ago"


# --------------------------------------------------------------------------- everything at once

def connect_all(args) -> None:
    """Claude Code, the other coding agents' hooks, and the MCP servers they already use, in one go."""
    only = [a.strip().lower() for x in (getattr(args, "only", None) or []) for a in x.split(",") if a.strip()]
    known = {"claude-code", *hook_agents()}
    if bad := [a for a in only if a not in known]:
        sys.exit(f"unknown agent {', '.join(bad)}; pick from: {', '.join(sorted(known))}")
    claude = (bool(shutil.which("claude")) or (Path.home() / ".claude").exists()) and (not only or "claude-code" in only)
    others = [a for a in only if a != "claude-code"]
    if only and not args.remove:
        print(f"Only: {', '.join(only)} (the other agents here are left as they are)")
    if not args.remove:
        print(f"This sends what every AI agent on this computer does through the gateway at {args.url}:\n"
              f"  - Claude Code: {'every tool call' if claude else 'not found, skipped'}\n"
              "  - Cursor, Codex, Gemini CLI, VS Code Copilot, Antigravity (the ones installed): commands, reads and edits\n"
              "  - the MCP servers those agents already use\n"
              "Every config is backed up first; `connect all --remove` undoes it all.")
        if not confirm("Continue?", args.yes):
            return
    each = argparse.Namespace(url=args.url, key=args.key, remove=args.remove, yes=True, agent="all",
                              project=None, hook_only=True)
    if claude:
        print("\nClaude Code")
        claude_code(each)
    if not only:
        print("\nOther coding agents")
        agents(each)
        print("\nMCP servers")
        guard(each)
    for name in others:
        print(f"\n{name}")
        agents(argparse.Namespace(**{**vars(each), "agent": name}))
        if name in ("cursor", "vscode", "gemini-cli", "antigravity"):         # its MCP servers too
            guard(argparse.Namespace(**{**vars(each), "agent": name}))
    if args.remove:
        return
    print(f"\nUsing Squidbrake with a team? Tell us about it and we'll help you set it up: {TEAM_FORM}?from=cli"
          f"\n(or 15 minutes with the founder: {FOUNDER_CALL})")
    if not args.yes and sys.stdin.isatty():
        offer_counts()


# Only printed, never opened or sent: the team can't see who installs, so this is how people can find us
FOUNDER_CALL = "https://calendly.com/pulkitbatra2024/new-meeting-1"
TEAM_FORM = "https://pilots.squidbrake.com/team"

# Counts from installs that aren't pilots: asked once, default no, never in scripts (--yes) or without a terminal
COMMUNITY_SERVER, COMMUNITY_CODE = "https://pilots.squidbrake.com", "community-opt-in-ins-a42929"


def offer_counts() -> None:
    import pilot
    import server
    asked = server.PILOT_DIR / "community-asked"
    if pilot.load(server.PILOT_DIR) or asked.exists():       # already sharing (e.g. a pilot), or asked before
        return
    print("\nOne optional thing: the Squidbrake team can't see installs like this one, only pilots.")
    pilot.join(server.PILOT_DIR, COMMUNITY_CODE, COMMUNITY_SERVER, False, server.VERSION)
    asked.parent.mkdir(parents=True, exist_ok=True)
    asked.write_text("asked once; to share later: squidbrake pilot join " + COMMUNITY_CODE +
                     " --server " + COMMUNITY_SERVER + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="squidbrake connect" if os.getenv("SQUIDBRAKE_CLI") else None,
                                description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("all", "status", "doctor", "claude-code", "mcp", "wrap", "guard", "agents"):
        s = sub.add_parser(name)
        found = name in ("status", "doctor")   # these find the gateway the hooks use
        s.add_argument("--url", default=None if found else "http://localhost:8080",
                       help="the gateway's address" + (" (default: the one your agents' hooks use)" if found else ""))
        s.add_argument("--key")
        if name == "status":
            pass
        elif name == "doctor":
            s.add_argument("--quick", action="store_true", help="right after installing: don't expect the agents "
                                                                 "to have used the hook yet")
        elif name == "all":
            s.add_argument("--remove", action="store_true", help="undo it for every agent")
            s.add_argument("--yes", action="store_true")
            s.add_argument("--agent", dest="only", action="append", metavar="AGENT",
                           help="only this one (repeat, or comma-separated): claude-code, cursor, codex, gemini-cli, "
                                "vscode, antigravity")
        elif name == "agents":
            s.add_argument("--agent", default="all", help="cursor, gemini-cli, codex, vscode, antigravity, or all (every one installed)")
            s.add_argument("--remove", action="store_true", help="take Squidbrake's hook out again")
            s.add_argument("--yes", action="store_true")
        elif name == "guard":
            s.add_argument("--agent", default="all", help="cursor, windsurf, vscode, gemini-cli, antigravity, "
                                                           "claude-desktop, or all (every one installed)")
            s.add_argument("--remove", action="store_true", help="put the original MCP servers back")
            s.add_argument("--yes", action="store_true")
        elif name == "claude-code":
            s.add_argument("--project")
            s.add_argument("--remove", action="store_true")
            s.add_argument("--yes", action="store_true")
            s.add_argument("--hook-only", action="store_true", help="just the hook, without the demo database tools")
        elif name == "mcp":
            s.add_argument("--name", default="mcp-agent", help="antigravity, claude-desktop, cursor, or any label")
            s.add_argument("--install", action="store_true", help="antigravity: write it into its config")
            s.add_argument("--project")
        else:
            s.add_argument("--agent", required=True, help="claude-code, antigravity, claude-desktop, cursor, or any label")
            s.add_argument("--app", help="short name for the app, e.g. stripe, github, gmail")
            s.add_argument("--app-url", help="the app's remote MCP server URL (instead of a command)")
            s.add_argument("--sandbox", action="store_true", help="use the built-in Acme sandbox company")
            s.add_argument("--env", action="append", help="KEY=VALUE for the app's own credentials (repeatable)")
            s.add_argument("--project", help="claude-code: only for this project folder")
            s.add_argument("--install", action="store_true", help="antigravity: write it into its config")
            s.add_argument("command", nargs=argparse.REMAINDER, help="-- then the app's MCP server command")
    args = p.parse_args(argv)
    args.url = args.url.rstrip("/") if args.url else None
    if args.cmd == "mcp":
        args.agent = args.name
    if args.cmd == "status":
        sys.exit(status(args))
    if args.cmd == "doctor":
        sys.exit(doctor(args))
    {"all": connect_all, "claude-code": claude_code, "mcp": mcp, "wrap": wrap, "guard": guard, "agents": agents}[args.cmd](args)


if __name__ == "__main__":
    main()
