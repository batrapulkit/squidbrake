# Install and connect

Every way to install Squidbrake, connect agents, and share it.

## See it live, nothing to install

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/batrapulkit/squidbrake?quickstart=1)

Click the button and the live demo starts in your browser (free with a GitHub account): a sandbox company's AI
support agent works its inbox while you watch. A scam wire is blocked, refunds wait for a person, and a demo
manager approves or rejects them. If the editor asks whether to allow tasks that run automatically, click
**Allow**: that's the demo starting. On your own machine: `pip install -r requirements.txt` then `python demo/live_demo.py`.

## Try it in 30 seconds

One line installs it, runs it in the background, connects every AI agent on this computer and opens the dashboard:

```bash
curl -fsSL https://pilots.squidbrake.com/install.sh | SQUIDBRAKE_REF=github sh        # macOS / Linux
```

```powershell
$env:SQUIDBRAKE_REF="github"; irm https://pilots.squidbrake.com/install.ps1 | iex       # Windows
```

With pip instead (`SQUIDBRAKE_REF` only tells the usage stats, if you say yes to them, that you came from here):

```bash
pip install squidbrake            # or: pipx install squidbrake
squidbrake setup                  # the same as the line above: background, every agent connected, dashboard
```

`setup` connects the agents you have (Claude Code, Cursor, Codex, Gemini CLI, VS Code Copilot, Antigravity) and
the MCP servers they already use, and routes them all through Squidbrake. It prints your dashboard key the first
time, backs up every config it changes, and `squidbrake connect all --remove` undoes it. Restart the agents, then
ask one to run `rm -rf ~/` and watch it get blocked. `squidbrake connect status` shows which agents are covered, and
catches the one step people miss (Codex runs a new hook only after you approve it in `/hooks`).

Your rules, keys and data live in `~/.squidbrake`; edit `~/.squidbrake/rules.yaml` and changes apply at once.
If the first run does not look right, see the [first-10-minutes troubleshooting guide](troubleshooting.md).

Only Claude Code? It's also a plugin, installed from inside Claude Code (see [plugin/](../plugin/)):
`/plugin marketplace add batrapulkit/squidbrake`, then `/plugin install squidbrake@squidbrake`.

From a clone instead: `git clone https://github.com/batrapulkit/squidbrake && cd squidbrake`, then `./start.sh`
(Windows: `start.bat`) and `./connect.sh claude-code` (Windows: `connect.bat claude-code`).

Or with Docker: `docker run -d -p 8080:8080 -v squidbrake-data:/app/data --name squidbrake ghcr.io/batrapulkit/squidbrake`
(keys: `docker logs squidbrake`).

## 1. Start it

| Where | Command |
|---|---|
| Windows | double-click `start.bat` |
| macOS / Linux | `./start.sh` |
| A Linux server, 24/7 | `./install.sh` (or `./install.sh gateway.yourdomain.com` for HTTPS) |

The first start installs everything, prints an **admin** key (for the dashboard) and an **agent** key
(shown once, so save them), and opens `http://localhost:8080/dashboard`. No configuration needed; every
setting in `.env.example` is optional.

The first start in a terminal also asks once whether to keep Squidbrake running in the background, so your agents
(which fail closed) are never locked out because it's down. Enter means yes (type n to keep it in the window);
scripts or CI are never asked and get no service. It adds a login item: a LaunchAgent on macOS, a systemd user service on
Linux, a `Run` registry value on Windows (some endpoint security tools flag these, so check with IT first).
`squidbrake start --background` installs it without asking (or set `SQUIDBRAKE_BACKGROUND=1` for unattended
installs), `squidbrake service status` checks it, `squidbrake service stop` takes it out, and `squidbrake run`
(or `./start.sh --foreground`) always runs in the window. Docker restarts by itself already.

Keys: `python server.py add-key NAME [--approver]`, `python server.py remove-key NAME`, `python server.py keys`.
Changes apply immediately, no restart needed. (Inside Docker, prefix with `docker compose exec gateway`.)

## 2. Connect real agents

With the gateway running, one command per agent (installed with pip, type `squidbrake connect ...` instead;
from a clone, use the `.venv` Python that `start.bat` / `start.sh` created):

```bash
.venv/Scripts/python connect.py all                  # every agent at once (Windows; macOS/Linux: .venv/bin/python)
.venv/Scripts/python connect.py claude-code          # or one at a time
.venv/Scripts/python connect.py mcp --name antigravity   # also: claude-desktop, cursor
```

| Agent | What's checked | One at a time |
|---|---|---|
| Claude Code | every tool call (Bash, PowerShell, edits, reads, web, MCP) | `connect claude-code` |
| Cursor | terminal commands, file reads, file edits and deletes (Cursor's `preToolUse`, in recent versions), and MCP tools | `connect agents --agent cursor`, `connect guard --agent cursor` |
| Codex | shell commands, edits and MCP tools. **Approve the hook once in Codex with `/hooks`**: until then Codex skips it | `connect agents --agent codex` |
| Gemini CLI | shell commands, reads, writes and edits, plus its MCP servers | `connect agents --agent gemini-cli` |
| VS Code Copilot | agent-mode commands, reads and edits, plus its MCP servers | `connect agents --agent vscode` |
| Antigravity | terminal commands, reads and writes, plus its MCP servers | `connect agents --agent antigravity` |
| Windsurf, Kiro, Claude Desktop | their MCP servers | `connect guard --agent windsurf` |

- **Claude Code**: a hook sends *every* tool call (Bash, PowerShell, Edit, Write, Read, WebFetch, MCP tools)
  through the gateway before it runs. Blocked calls are refused with the reason, and calls held for
  approval wait until you decide in the dashboard. It also adds the database tools below.
  Add `--project DIR` to limit it to one project; `--remove` undoes it. If the gateway is down, Claude Code's
  tool calls are blocked (fail closed) and it says why.
- **Antigravity, Claude Desktop, Cursor, any MCP client**: prints the config block to paste in. The agent
  gets `list_tables`, `describe_table`, `query` and `execute` tools on a SQLite database
  (`data/shop.db`, created with sample customers / products / orders; set `DB_PATH` to use your own).
  Reads run immediately, `UPDATE`/`DELETE`/`INSERT`/`ALTER` wait for your approval, and `DROP`/`TRUNCATE` are blocked.

Wrapping a GitHub, Stripe, Slack, Gmail or Postgres / Supabase MCP server? Start with the commented example policies in
[`examples/rules/`](../examples/rules/) and adjust their tool-name patterns to the server's tool list.
Running an agent with nobody watching (a nightly loop, a cron job, a Routine)? Start from
[`unattended-agent.yaml`](../examples/rules/unattended-agent.yaml): a step cap, an allowlist, no redoing work,
and no deletes or money movement, enforced from outside the agent instead of promised in its prompt.

Things to ask the agent, then watch the dashboard:

- "Show me the top 5 customers by revenue" (runs)
- "Give every customer on the team plan a 15% discount" (waits for you to approve)
- "Delete all failed orders" (approve or reject it; a rejection note is passed back to the agent)
- "Drop the orders table" (blocked)
- In Claude Code: "commit and push this" (the `git push` waits for approval)

## 3. Show it to someone

- **Right now, from your PC:** `cloudflared tunnel --url http://localhost:8080` prints a public
  `https://….trycloudflare.com` link. Give viewers their own key: `python server.py add-key guest`.
  Afterwards, press Ctrl+C and run `python server.py remove-key guest`.
- **Permanently:** `./install.sh gateway.yourdomain.com` on a small cloud server.

## 4. Other computers (a friend, a teammate, a server)

Make a clean copy (no keys, no history): `python pack.py` -> `dist/squidbrake.zip`.

- **Their own gateway:** unzip, double-click `start.bat` (Windows) or run `./start.sh`. It makes its own keys.
- **Their agents on YOUR gateway:** in your dashboard's **Team** tab add them (a person, to watch/approve) and add
  their agent (type *AI agent*); send them that agent key. They unzip and run, for example:
  `connect.bat wrap --sandbox --agent claude-code --url https://your-gateway --key gw_...`
  (or `connect.bat claude-code --url ... --key ...` to route every Claude Code action through your gateway).
- **A cloud server, 24/7:** unzip there and run `bash install.sh` (HTTPS included, no domain needed).
