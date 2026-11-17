"""
Company-wide lockdown: the policy files IT pushes to every developer machine (MDM, Intune, Jamf, Ansible...)
so each coding agent runs Squidbrake's hook and a developer can't switch it off.

  squidbrake lockdown --url https://gateway.yourcompany.com --out squidbrake-lockdown

writes one folder per agent, each in that vendor's own managed-settings format, plus a README saying where each
file goes on macOS, Linux and Windows. One policy (rules.yaml on the gateway) then decides for every agent:
the hooks only ask the gateway. What each vendor file adds on top:

  claude-code   managed-settings.json: Squidbrake's hooks, only managed hooks run, no --dangerously-skip-permissions,
                and a short native deny list as a backstop
  codex         requirements.toml: Squidbrake's managed hook, only managed hooks run, hooks forced on, no
                danger-full-access sandbox (no --yolo)
  gemini-cli    settings.json (system): Squidbrake's BeforeTool hook, YOLO mode off; policies/squidbrake.toml: the
                same backstop as an admin-tier policy
  cursor        hooks.json (enterprise): Squidbrake's hooks with failClosed

Every machine also needs Squidbrake installed (`pipx install squidbrake`) and its own agent key in the
GATEWAY_API_KEY environment variable (made in the dashboard's Team tab with "Works for" set to that person).
Keys are never written into these files: one file goes to every machine, and a key in it would be everyone's.

Formats follow each vendor's managed-settings documentation as of October 2026; check `squidbrake lockdown`'s README
against your agent versions before a fleet-wide rollout.
"""
from __future__ import annotations

import json
from pathlib import Path

AGENTS = ("claude-code", "codex", "gemini-cli", "cursor")

# Catastrophic commands blocked by the agent itself as well, so they stay blocked even if the hook process
# can't start (Claude Code and Codex let a call through when a command hook crashes or times out).
# Kept short and exact on purpose: in Claude Code's rules `*` is a wildcard and Gemini's commandPrefix matches
# prefixes, so `rm -rf /*` or a prefix `rm -rf /` there would also block `rm -rf /tmp/build`.
# Everything else is judged by the gateway, with your rules and history.
CLAUDE_DENY = ["rm -rf /", "rm -rf ~", "rm -rf ~/", "rm -rf $HOME", "sudo rm -rf /"]
GEMINI_DENY_REGEX = [r"^\s*(sudo\s+)?rm\s+-(rf|fr)\s+(/|/\*|~|~/|~/\*|\$HOME)\s*$",
                     r"^\s*(sudo\s+)?mkfs(\.\w+)?\s",
                     r"^\s*(sudo\s+)?dd\s.*\bof=/dev/(sd|nvme|disk|hd)"]

WHERE = {
    "claude-code": {"macOS": "/Library/Application Support/ClaudeCode/managed-settings.json",
                    "Linux / WSL": "/etc/claude-code/managed-settings.json",
                    "Windows": r"C:\Program Files\ClaudeCode\managed-settings.json",
                    "MDM instead": "macOS: plist domain com.anthropic.claudecode; Windows: REG_SZ value 'Settings' under "
                                   r"HKLM\SOFTWARE\Policies\ClaudeCode (the JSON as its value)"},
    "codex": {"macOS / Linux": "/etc/codex/requirements.toml",
              "Windows": r"%ProgramData%\OpenAI\Codex\requirements.toml",
              "also": "create the hooks folder it names (/etc/squidbrake/codex-hooks, or "
                      r"C:\ProgramData\squidbrake\codex-hooks); Codex checks that it exists"},
    "gemini-cli": {"macOS": "/Library/Application Support/GeminiCli/settings.json and .../GeminiCli/policies/squidbrake.toml",
                   "Linux": "/etc/gemini-cli/settings.json and /etc/gemini-cli/policies/squidbrake.toml",
                   "Windows": r"C:\ProgramData\gemini-cli\settings.json and C:\ProgramData\gemini-cli\policies\squidbrake.toml",
                   "also": "the policies folder must be owned by root (Windows: not writable by standard users)"},
    "cursor": {"macOS": "/Library/Application Support/Cursor/hooks.json", "Linux / WSL": "/etc/cursor/hooks.json",
               "Windows": r"C:\ProgramData\Cursor\hooks.json"},
}


def _hook_args(url: str, *extra: str) -> list[str]:
    return [*extra, "--url", url]


def _cmd(url: str, *extra: str) -> str:
    return " ".join(["squidbrake", *_hook_args(url, *extra)])


def claude_code(url: str) -> dict:
    hook = {"type": "command", "command": "squidbrake", "args": _hook_args(url, "hook", "--source", "claude-code")}
    return {
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [{**hook, "timeout": 600}]}],
            "PostToolUse": [{"matcher": "*", "hooks": [{**hook, "timeout": 30}]}],
            "PostToolUseFailure": [{"matcher": "*", "hooks": [{**hook, "timeout": 30}]}],
            "UserPromptSubmit": [{"hooks": [{**hook, "timeout": 15}]}],
        },
        "allowManagedHooksOnly": True,
        "permissions": {
            "disableBypassPermissionsMode": "disable",
            "deny": [f"Bash({c})" for c in CLAUDE_DENY],
        },
    }


def codex(url: str) -> str:
    cmd = _cmd(url, "agent-hook", "codex")
    return f'''# Squidbrake lockdown for Codex: install as requirements.toml (see README.md)
allowed_sandbox_modes = ["read-only", "workspace-write"]   # no danger-full-access, so no --yolo
allow_managed_hooks_only = true

[features]
hooks = true   # managed hooks run even if a user turns hooks off

[hooks]
managed_dir = "/etc/squidbrake/codex-hooks"
windows_managed_dir = 'C:\\ProgramData\\squidbrake\\codex-hooks'

[[hooks.PreToolUse]]
matcher = "Bash|shell|apply_patch|Edit|Write"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "{cmd}"
command_windows = "{cmd}"
timeout = 600
statusMessage = "Squidbrake: checking"
'''


def gemini_settings(url: str) -> dict:
    return {
        "hooks": {"BeforeTool": [{"matcher": "run_shell_command|write_file|replace|read_file|read_many_files",
                                  "hooks": [{"name": "squidbrake", "type": "command",
                                             "command": _cmd(url, "agent-hook", "gemini-cli"), "timeout": 600000}]}]},
        "security": {"disableYoloMode": True},
    }


def gemini_policy() -> str:
    rules = "\n".join(f'''[[rule]]
toolName = "run_shell_command"
commandRegex = {json.dumps(c)}
decision = "deny"
priority = 900
denyMessage = "Blocked by company policy (Squidbrake backstop)"
''' for c in GEMINI_DENY_REGEX)
    return "# Squidbrake backstop, admin tier: these stay blocked even if the hook can't run\n\n" + rules


def cursor(url: str) -> dict:
    cmd = _cmd(url, "agent-hook", "cursor")
    entry = {"command": cmd, "type": "command", "timeout": 600, "matcher": "", "failClosed": True}
    return {"version": 1, "hooks": {"beforeShellExecution": [entry], "beforeReadFile": [entry]}}


def readme(url: str, agents: list[str]) -> str:
    lines = [
        "# Squidbrake lockdown", "",
        f"These files make every developer machine send its coding agents' actions to {url} and stop a",
        "developer from switching that off. Push them with your device management (Jamf, Intune, Kandji, Ansible...).", "",
        "On every machine:", "",
        "1. Install Squidbrake: `pipx install squidbrake` (the `squidbrake` command must be on PATH for the agent).",
        "2. Set `GATEWAY_API_KEY` to that person's own agent key (dashboard -> Team -> Add -> AI agent, \"Works for\" = them).",
        "   One key per person means the dashboard shows whose agent did what, and second-person approval works.",
        "3. Copy each file below to its place. Restart the agents.", "",
        "Check a machine with `squidbrake connect status`.", "",
    ]
    for a in agents:
        lines += [f"## {a}", ""] + [f"- **{k}:** `{v}`" if k not in ("also", "MDM instead") else f"- {k}: {v}"
                                    for k, v in WHERE[a].items()] + [""]
    lines += [
        "## What to know", "",
        "- The hook asks the gateway; if the gateway can't be reached, the hook blocks the action (fail closed).",
        "- If the hook itself can't start (Squidbrake not installed, PATH wrong), Claude Code and Codex let the call",
        "  through. The short native deny list in these files still blocks the catastrophic commands in that case.",
        "  Cursor's hooks use failClosed, so they block.",
        "- Codex runs a new hook only after it's trusted; managed hooks from requirements.toml are trusted by policy.",
        "- Vendors change these formats. Test on one machine per agent before a fleet-wide rollout.", "",
    ]
    return "\n".join(lines)


def write(url: str, out: Path, agents: list[str] | None = None) -> list[Path]:
    """Write the lockdown files under out/. Returns the files written."""
    url = url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ValueError("the gateway URL must start with http:// or https://")
    agents = [a for a in (agents or AGENTS)]
    unknown = [a for a in agents if a not in AGENTS]
    if unknown:
        raise ValueError(f"no lockdown for {', '.join(unknown)}; supported: {', '.join(AGENTS)}")
    files: dict[str, str] = {}
    if "claude-code" in agents:
        files["claude-code/managed-settings.json"] = json.dumps(claude_code(url), indent=2) + "\n"
    if "codex" in agents:
        files["codex/requirements.toml"] = codex(url)
    if "gemini-cli" in agents:
        files["gemini-cli/settings.json"] = json.dumps(gemini_settings(url), indent=2) + "\n"
        files["gemini-cli/policies/squidbrake.toml"] = gemini_policy()
    if "cursor" in agents:
        files["cursor/hooks.json"] = json.dumps(cursor(url), indent=2) + "\n"
    files["README.md"] = readme(url, agents)
    written = []
    for rel, body in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        written.append(p)
    return written
