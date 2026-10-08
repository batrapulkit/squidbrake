# Squidbrake for Claude Code (plugin)

Change control for Claude Code. Every tool call (Bash, PowerShell, Edit, Write, Read, WebFetch, MCP tools) goes
through [Squidbrake](https://github.com/batrapulkit/squidbrake) before it runs, and onto its record:

- everything: recorded in a tamper-evident record (which agent, what it changed, who approved it, what led to it)
- `git push --force`, `terraform destroy`, destructive SQL, cloud deletes: **wait for a person to sign off**
  (dashboard, phone or Slack), and destructive ones keep an undo
- `ls`, `git status`, reading files: run as normal
- `rm -rf ~/`, `rmdir /s /q d:\`, wiping a disk: never run, and Claude is told why

## Install

1. Start a gateway (once):

   ```bash
   pipx install squidbrake      # or: pip install squidbrake
   squidbrake                   # prints an admin key and an agent key, opens the dashboard
   ```

2. In Claude Code:

   ```
   /plugin marketplace add batrapulkit/squidbrake
   /plugin install squidbrake@squidbrake
   ```

   It asks for the gateway URL (default `http://localhost:8080`) and an agent key: paste the **agent** key the
   gateway printed (or make one with `squidbrake add-key claude-code`). The key is kept in your system's credential
   store. Restart Claude Code.

The `squidbrake` command must be on your PATH (pipx does this). If you already connected Claude Code with
`squidbrake connect claude-code` (or `python connect.py claude-code`), use one or the other, not both, or every call
is recorded twice. To undo the other: `squidbrake connect claude-code --remove`.

**Fails closed:** if the gateway is down, tool calls are refused (set `GATEWAY_FAIL_OPEN=1` to let them run).
Edit what's blocked or held in `~/.squidbrake/rules.yaml`; changes apply at once.
