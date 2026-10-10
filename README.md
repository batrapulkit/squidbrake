# Squidbrake

<!-- mcp-name: io.github.batrapulkit/squidbrake -->

[![tests](https://github.com/batrapulkit/squidbrake/actions/workflows/tests.yml/badge.svg)](https://github.com/batrapulkit/squidbrake/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/squidbrake.svg)](https://pypi.org/project/squidbrake/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![MCP](https://img.shields.io/badge/MCP-compatible-8A2BE2.svg)](#2-connect-real-agents)
[![Real incidents replayed: 12 of 13 stopped](https://img.shields.io/badge/real%20incidents%20replayed-12%20of%2013%20stopped-yellow.svg)](incidents/)
[![Good first issues](https://img.shields.io/github/issues/batrapulkit/squidbrake/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/batrapulkit/squidbrake/labels/good%20first%20issue)

![Demo: every agent action goes on the record; a refund waits for a person and is approved from a phone; the record shows who asked, who approved and what led to it](https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/demo.gif)

**Change control for AI agents.** Your agents run commands, edit code, send emails, issue refunds and change
databases. Squidbrake keeps the record of every one of those changes: which agent, what it changed, who approved
it, and what led to it. Risky changes wait for someone other than the requester to sign off; routine ones run on
their own and are still recorded. The record is tamper-evident, readable by people who don't write code (a weekly
summary, an evidence pack for your auditor), and destructive changes keep an undo. **One policy for every agent your
company runs** (Claude Code, Cursor, Codex, Gemini CLI, VS Code Copilot, Antigravity and your MCP tools), and **a
record that sits outside them**: the agents can't quietly change it, or switch Squidbrake off, without a person.

Free and open source (Apache 2.0). Runs on your laptop or your own server. What your agents do (commands, files,
prompts, the audit trail) never leaves it; usage counts go out only if you say yes when it asks (Enter means yes).

- **A second person signs off:** risky changes wait in the dashboard, on your phone (one-tap links, push via ntfy) or in Slack.
  The approver sees *what led to it*, e.g. the email the agent just read.
- **Shows what it will change, and keeps an undo:** before a risky command, the approver sees it measured on the
  developer's machine ("removes 3 commits from origin/main: fix login, ...", "deletes 1,204 files (56 MB) in data",
  "deletes 4,312 rows of 10,240 in orders", "destroys 12 resources in workspace prod, including 1 that holds data:
  aws_db_instance.main", "deletes the bucket and all 8,200 objects (14.0 GB)"). Database rows are counted with the
  same WHERE in a read-only session with a timeout (psql, mysql, sqlite3); terraform is read from its state or a plan
  without refresh or lock; AWS and Kubernetes use list and describe calls with the command's own credentials.
  Right before an approved delete, `git reset --hard` or `git clean` runs, Squidbrake keeps a copy;
  `squidbrake undo` lists them and `squidbrake undo ID` puts one back.
- **A record someone else can read:** every Monday a short summary of what the
  agents did and who approved what goes to Slack (when Slack is connected). `squidbrake evidence` (or Reports → Evidence pack) writes one printable page: the
  controls in place, what was blocked, held and approved and by whom, whether the audit trail is intact, and which
  SOC 2, ISO/IEC 42001, EU AI Act, CERT-In and RBI requirements those records speak to.
- **For teams:** one gateway for everyone's laptops (`connect all --url https://gateway.yourcompany.com --key gw_...`, one
  agent key per person, made in Team with "Works for" set), roles (only `finance` approves wires), **second-person approval** (nobody approves what their
  own agent asked for), an emergency stop (all agents, one agent, or one conversation, which also ends Claude Code's
  turn), reports, CSV export, and evidence anyone can verify offline (`python verify.py`).
- **Works with real agents:** `squidbrake connect all` connects Claude Code, Cursor, Codex, Gemini CLI, VS Code
  Copilot and Antigravity (their commands, reads and edits, via hooks) and the MCP servers they already use; any MCP
  app (Stripe, GitHub, Slack, databases, internal tools) can be wrapped too.
- **Agents can't switch it off:** an agent removing, stopping or uninstalling Squidbrake waits for a person. For a
  company, `squidbrake lockdown --url https://gateway.yourcompany.com` writes the managed-settings files IT pushes to
  every machine (Claude Code, Codex, Gemini CLI, Cursor), so each agent must run Squidbrake's hook and
  `--dangerously-skip-permissions` / `--yolo` are turned off; only someone with admin rights on the machine can undo
  that. One policy, every agent.
- **Rules, not vibes:** `rules.yaml` says what runs by itself, what's blocked, and what waits for a person.
  No LLM in the decision path.
- **Reads what a command really does:** `ls && rm -rf ~/`, `bash -c "..."`, `rmdir /s /q d:\` or `curl ... | sh` are
  split and read before they run. Wiping a disk or home folder is blocked; `git push --force`, `terraform destroy`,
  `kubectl delete` or cloud deletes wait for a person; commands that only look (`ls`, `git status`) run without asking.
- **Catches prompt injection without a model:** if an agent sends data to an address that only a web page, email or
  issue mentioned (not you, not your own systems), it's held and the approver is told where the address came from.
- **Judges by history:** blocks a retry of something a person rejected, catches look-alike domains
  (`acrne-corp.com` pretending to be `acme.com`), flags duplicate refunds, and lets you write sequence rules
  ("deleting a database right after its backups were turned off") that say which earlier step caused them.
- **Fails closed:** if Squidbrake is down, guarded tools don't run.

See [SHOWCASE.md](SHOWCASE.md) for a 5-minute demo with a sandbox company, and [incidents/](incidents/) for **10 real
AI-agent incidents replayed against the shipped rules** (Replit, the Railway volume deletion, GitHub MCP, Supabase
MCP, Postmark MCP, Claude Code and Antigravity deletes...): 12 of 13 harmful actions stopped, checked in CI. The same steps through two other guards (destructive_command_guard, Microsoft's Agent Governance Toolkit), plus everyday coding work: [bench/compare/](bench/compare/).

![Squidbrake dashboard: a git push and a refund wait for approval, while a scam wire transfer was blocked](https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/dashboard.png)

<table><tr>
<td width="62%"><img src="https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/blocked-scam.png" alt="A $24,800 wire blocked because it follows an email from a look-alike domain"><br>
<sub>An agent read an "urgent CEO" email from <code>acrne-corp.com</code> and tried to wire $24,800. Blocked, with the story of what led to it.</sub></td>
<td width="38%"><img src="https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/phone-approval.png" alt="One-tap approval on a phone"><br>
<sub>Approve or reject from your phone with one tap.</sub></td>
</tr></table>

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

Only Claude Code? It's also a plugin, installed from inside Claude Code (see [plugin/](plugin/)):
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
(which fail closed) are never locked out because it's down. Enter means no; nothing is installed without a yes,
and scripts or CI are never asked. A yes adds a login item: a LaunchAgent on macOS, a systemd user service on
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

Wrapping a GitHub, Stripe, Slack or Postgres / Supabase MCP server? Start with the commented example policies in
[`examples/rules/`](examples/rules/) and adjust their tool-name patterns to the server's tool list.
Running an agent with nobody watching (a nightly loop, a cron job, a Routine)? Start from
[`unattended-agent.yaml`](examples/rules/unattended-agent.yaml): a step cap, an allowlist, no redoing work,
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

## Other ways to send calls through it

**Any MCP server** - put Squidbrake in front of it, in any MCP client. The agent sees the app's normal tools, and
each call is checked first (with `GATEWAY_URL` and `GATEWAY_API_KEY` set in the client's MCP config):

```bash
squidbrake proxy --app linear --url https://mcp.linear.app/mcp          # a remote MCP server
squidbrake proxy --app github --url https://api.githubcopilot.com/mcp/ --header 'Authorization: Bearer ${GITHUB_TOKEN}'
squidbrake proxy --app stripe -- npx -y @stripe/mcp --tools=all          # one started by a command
```

`squidbrake connect guard` does this for the servers your agents already use, including remote ones with their own
auth headers.

**Agents that connect to MCP by URL** (ChatGPT and claude.ai connectors, Devin, n8n, cloud agents) - easiest: in the
dashboard, **Settings → Agents that connect by URL**, add the app's MCP server (its URL, and the header its auth
needs). The agent then uses `https://<your gateway>/mcp/<name>` and signs in with one of its agent keys
(`Authorization: Bearer gw_...`, or `?key=gw_...` for apps that take only a URL). Every call is checked and recorded as
that agent; the app's own token stays on the gateway and is never shown again. Hosted dashboards take servers by URL;
servers started by a command need a self-hosted gateway with `SQUIDBRAKE_MCP_COMMANDS=1`.

Apps whose MCP server signs in only through a browser (OAuth: Slack, HubSpot, Notion, Asana, ClickUp, Grafana Cloud):
choose **Sign in to the app (OAuth)**, add it, click **Connect** and sign in once. The gateway keeps the session and
refreshes it before it runs out. Apps that only let in OAuth apps registered with them (Slack, HubSpot) need your own
OAuth app's client ID and secret, with the redirect URL the dashboard shows.

Or run the proxy yourself and serve it over HTTP. The agent adds `https://your-host:9000/mcp` as its MCP server and sends the token
(`Authorization: Bearer`, `X-Squidbrake-Token`, or `?token=` for clients that take only a URL):

```bash
squidbrake proxy --app github --serve 0.0.0.0:9000 --token "$PROXY_TOKEN" -- npx -y @modelcontextprotocol/server-github
```

Each connected conversation is checked on its own, so one agent's chain never mixes with another's. A caller can
name its conversation with an `X-Squidbrake-Session` header. Put HTTPS in front of it (Caddy, a tunnel) before
exposing it.

**Python agent frameworks** - OpenAI Agents SDK, LangChain / LangGraph, CrewAI, PydanticAI, smolagents, Google ADK:
put all of an agent's tools behind it in one line. A call Squidbrake stops doesn't run, and the model gets a
"NOT RUN: ..." message as the tool's result:

```python
from squidbrake.client import Gateway          # pip install squidbrake (or drop client.py into your project)
gw = Gateway("https://gateway.example.com", api_key="...", source="support-agent", session_id=run_id)

agent = Agent(name="support", tools=gw.guard_tools([lookup_order, refund, send_email]))   # OpenAI Agents SDK
graph = create_react_agent(llm, gw.guard_tools(tools))                                      # LangGraph
```

Or one function at a time (raises `Denied` when it's stopped):

```python
@gw.guard(name="shell.exec")
def shell_exec(command: str): ...
```

**Any language** - two HTTP calls (header `X-Gateway-Key: <secret>`):

```
POST /v1/events               {"name": "shell.exec", "input": {...}, "source": "...", "session_id": "..."}
  -> {"event_id": "...", "decision": "allow" | "deny", "reason": "...", "rule_id": ...}
POST /v1/events/{id}/result   {"output": ..., "error": null, "duration_ms": 12}
```

Record an action that already happened in one call by including `output`/`error` in the first POST.

**HTTP proxy** - no code changes: define `upstreams` in `rules.yaml`, then point the client at
`http://gateway:8080/proxy/<upstream>/...`. Optional headers: `X-Gateway-Source`, `X-Gateway-Session`.
Denied requests get `403`; every response carries `X-Gateway-Event-Id`.

## Try it on real work first: shadow mode

Set `mode: shadow` in `rules.yaml` (or `shadow_agents: ["new-bot*"]` for some agents) and Squidbrake blocks and holds
nothing: it records what it *would* have done. Reports then shows **would block** and **would hold** counts, and each
event is tagged, so a team can see a week of real decisions before switching `mode: enforce` on. Stops and
catastrophic commands (`rm -rf /`, wiping a drive) are enforced even in shadow mode.

## Command checks

Shell tools (Claude Code's `Bash` and `PowerShell`, or any tool matching `command_checks.tools`) are read by
[`commands.py`](commands.py) before the rules decide: the line is split on `&&`, `;`, `|` (outside quotes), and
`sudo`, `xargs`, `bash -c`, `powershell -Command` and `$(...)` are looked inside. Nothing is ever run or expanded.

| Kind | Examples | Default |
|---|---|---|
| catastrophic | `rm -rf /`, `rm -rf ~`, `rmdir /s /q d:\`, `mkfs`, `dd of=/dev/sda`, `chmod -R 777 /` | block |
| irreversible | `rm -r`, `git push --force`, `git reset --hard`, `terraform destroy`, `kubectl delete`, `aws ... delete-*`, `DROP TABLE` | review |
| hidden | `eval`, `curl ... \| sh`, `base64 -d \| bash`, `powershell -EncodedCommand` | review |
| read_only | `ls`, `cat`, `grep`, `git status` / `log` / `diff` | `allow` in the shipped `rules.yaml` |

Command checks apply even when a rule allows the tool, and `read_only: allow` only relaxes the `default` (never a
rule or a warning). Configure them under `command_checks:` in `rules.yaml`.

## Terminal guard

Commands people paste from ChatGPT, a forum or a README never pass an agent hook. This puts the same command reader
([`commands.py`](commands.py)) in front of your own shell: catastrophic lines are blocked, irreversible or unreadable
ones (`git push --force`, `curl ... | sh`) ask `Run it anyway? [y/N]`, everything else runs without a word. It works
offline, nothing is sent anywhere, and if the guard itself fails your command still runs.

```bash
squidbrake shell-guard install --shell bash >> ~/.bashrc        # then open a new terminal
squidbrake shell-guard install --shell zsh  >> ~/.zshrc
```

```powershell
if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Force $PROFILE }
squidbrake shell-guard install --shell powershell | Add-Content $PROFILE
```

`install` only prints the snippet; it never edits a file, so read it first. Scripts and CI (non-interactive shells) are
never blocked or prompted. Each Enter starts Python, which adds about 150 ms. If bash already has a `DEBUG` trap (VS Code's shell integration, bash-preexec), the snippet leaves it alone and prints a warning. Check one line by hand: `squidbrake shell-guard check "rm -rf ~/"` (exit code 0 run, 1 block, 2 ask).

## Prompt injection, caught without a model

The attacks that actually happened to agents (a GitHub issue, a support ticket or a web page telling the agent to send
data somewhere) share one shape: the destination comes from content someone else wrote. Squidbrake records what you
ask (Claude Code prompts, via the hook) and which tools bring in outside content (`WebFetch`, inboxes, issues,
tickets...). When an action sends something to an email address, URL, bank account or repo that appears in that
outside content but not in what you asked or in your own systems' results, it's held with the reason:

> This sends to keys@evil.io (to), which appears in WebFetch (2 minutes ago) but not in anything you asked or in your
> own systems. Content from outside can carry hidden instructions (prompt injection).

Uploads from the shell count too (`curl -d @.env https://...`, `scp`, `git push`). Anything sent out after outside
content was read gets a warning for the approver. Configure it under `taint_checks:` in `rules.yaml`.

## Customer names and personal data in public places

Agents copy what they read: a ticket's customer ends up in a pull request description or a public issue. When an
agent puts text where other people read it (a PR, an issue or comment, a gist, a chat post, a page, and
`gh pr|issue|gist ... create|comment|edit`), it waits for a person if the text:

- names a customer on your list (dashboard → **Settings → Customers**), or
- carries personal data: a card number, a social security number, an IBAN, or a list of 3+ emails or phone numbers.

Looking things up (`list_issues`, `search_issues`) doesn't count, and email has its own rule. The approver sees which
customer it named, or which kind of data; the data itself isn't repeated. Configure it under `data_checks:` in
`rules.yaml` (`block`, `review`, `warn`, `off`).

## Sequence rules

Some actions are only dangerous because of what came before them. `sequences:` in `rules.yaml` judges an action by
the steps before it and names the step that caused the decision:

```yaml
sequences:
  - id: destroy-after-recovery-removed      # turn off backups, then delete the database
    action: review
    reason: Destroying data right after its backups or deletion protection were turned off
    match: { input_regex: 'delete[-_ ]?db[-_ ]?instance|terraform\s+destroy|drop\s+(table|database)' }
    after:
      match: { input_regex: 'backup[-_ ]?retention[-_ ]?period\W{0,4}0|deletion[-_ ]?protection\W{0,4}false' }
      within_hours: 24
  - id: runaway-refunds                     # an agent stuck in a loop
    action: deny
    reason: Too many refunds in a short time
    match: { name: ["*refund*"] }
    count: { more_than: 10, within_hours: 1, scope: agent }
```

The approver then sees, for example: *Destroying data right after its backups were turned off. Because earlier:
Bash `aws rds modify-db-instance --backup-retention-period 0` (12 minutes ago).* `after:` looks at steps in the same
conversation that went ahead (`same_target: true` = on the same charge, file or account); `count:` counts earlier
matching actions per `session`, `agent` or `all`. Actions: `deny`, `review` or `warn`.

## Human approval

Rules with `action: review` hold the call until a person approves or rejects it:

```yaml
- id: approve-payments
  action: review
  reason: Money movement needs a human
  timeout_seconds: 600     # default APPROVAL_TIMEOUT (300)
  on_timeout: deny         # or allow
  approvers: [alice, bob]  # optional; default = any approver key
  match: { name: "payments.*" }
```

- The first `POST /v1/events` returns `"decision": "review"`. **The Python client handles this for
  you**: `check()` and `@gw.guard` block until the call is decided, then run the tool or raise `Denied`.
  Other clients long-poll `GET /v1/events/{id}/decision?wait=25` until `decision` is `allow` or `deny`.
- To decide, use the **Needs approval** queue at the top of the dashboard, or call
  `POST /v1/events/{id}/approve` / `.../reject` with an optional `{"note": "..."}`.
- Only approver keys (`python server.py add-key NAME --approver`, and the rule's `approvers` if set) can decide,
  and **a key can never approve its own request**. So give people their own keys, separate from the agents' keys.
- If nobody decides before the deadline, `on_timeout` applies and `decided_by` is recorded as `timeout`.
- Every decision is stored on the event with who decided, when, and their note.
- Set `APPROVAL_WEBHOOK_URL` (plus `PUBLIC_URL`) to get a Slack- or Discord-formatted message with a link to the event
  whenever something needs approval.
- **Microsoft Teams and email:** in Settings, paste a Teams Workflows webhook ("Post to a channel when a webhook
  request is received"), or an SMTP server and the addresses to send to. Each approval links to the one-tap review
  page; an email never decides anything by being opened, since mail scanners open links.
- **Every Monday, what it caught:** Slack, Discord, Teams and email get the week's summary: what was blocked, rejected,
  or (in shadow mode) would have been, why, and what it would have changed. *Reports → What it caught* shows it any
  time, with *Copy weekly report*.
- **Stop asking about what you always approve:** *Settings → Rules* suggests an `allow` rule for anything people
  approved 5+ times in 30 days and never rejected (never for money, an agent's own setup, or what the command,
  data or chain checks held). *Allow it* adds the rule right before the one that held it, with a backup.
- **Starter packs** for a support, finance or ops agent add a block of rules after the read rule, so blocks above
  still win.
- **To your SIEM:** *Settings → Send to your SIEM* streams every decision to Splunk (HEC), Datadog (logs) or any HTTP
  endpoint, in batches in the background. Or set `SIEM_URL`, `SIEM_TOKEN`, `SIEM_FORMAT`.
- **Approve and Reject right in Slack:** in Settings, open *Approve and Reject right in Slack*, create the Slack app
  from the manifest shown there, install it to your approvals channel, and paste its webhook URL and signing secret.
  Each click is checked against the signing secret and carries that one event's signed token; the message then says
  who decided.
- Through the HTTP proxy, a held request stays open until it's decided, so the caller's HTTP
  timeout must be longer than the rule's `timeout_seconds`.

## Dashboard

Open `http://<host>:8080/dashboard` and paste your admin key (or any key made with `add-key`). It is stored
only in that browser. The page shows:

- totals per status (click a tile to filter), a calls-per-hour/day chart (hover for counts,
  click a bar to list just that hour, "View as table" for exact numbers), and the top tools
- the event list, updated every 5 s while "Live" is on. Filter by time range, search, status,
  kind, source or session. Click a source or session to filter by it. "Load older" pages back.
- the full record for any event: input, output, error, metadata, the rule that blocked it, timings
- filters are kept in the URL, so a view like `/dashboard?status=denied&range=7d` can be bookmarked or shared

## FAQ

### How is Squidbrake different from Claude Code's built-in allow/ask permissions?

Claude Code's built-in permissions control actions for an individual agent. Squidbrake provides **centralized rules for a whole team**, with approvals from your **phone or Slack**, history checks, an **audit trail**, and support across multiple agents.

### What happens if Squidbrake is down?

Squidbrake **fails closed**. Guarded tool calls are blocked if the gateway is unreachable, rather than being allowed through.

### Does my data leave my machine?

What your agents do doesn't: commands, files, prompts, tool inputs and outputs, and the audit trail stay on your
laptop or your server. What can leave is usage counts, and only after a yes: the first run asks once (Enter means
yes) to send the command name, version, OS, how many actions were allowed, held and blocked, and for each held or
blocked one the program (like `rm`) and the rule. See [Usage sharing](#usage-sharing-asked-first).

### Does Squidbrake use an LLM to make decisions?

No. Squidbrake uses **deterministic rules and checks**. There is no LLM in the decision path.

### Can an agent get around Squidbrake?

Squidbrake is built for the common case: a **cooperative agent that makes a mistake** or follows instructions it found
in an email, a web page or an issue. It is not a sandbox against an agent that is deliberately trying to escape.
Here's what that means in practice:

- **Caught:** what the agent does through a connected tool. That includes shell commands read before they run
  (`ls && rm -rf ~/`, `bash -c "..."`, `curl ... | sh`), MCP calls, edits to its own settings, hooks and MCP servers
  or to Squidbrake's rules (held for a person), and chains of steps such as backups switched off and then a delete.
  Through the hooks, what a command runs underneath is read too: a Makefile target's recipe (`make clean`), a
  `package.json` script (`npm run release`) and a shell script (`bash cleanup.sh`).
- **Held because it can't be read:** a program written inline (`python -c`, `node -e`, `perl -e`), a program named
  only when it runs (`$(...)`, `eval`), and a script the agent created in this conversation and then runs
  (`python cleanup.py` right after writing `cleanup.py`). A person reads it first.
- **Held: the agent turning Squidbrake off.** `squidbrake connect --remove`, `service stop`, uninstalling it, killing
  its process, or editing the agents' hook settings all wait for a person.
- **Not caught:**
  - A script that was already in the project, edited and then run: `python scripts/seed.py` runs, and what it does
    inside isn't seen (running the project's own scripts after a change is everyday work). Cursor reports new files
    and edits the same way, so there a new script counts as written too.
  - Programs that aren't common developer tools are recorded, not held (`command_checks.unknown: warn`; set it to
    `review` to hold them).
  - Tools that aren't connected (`squidbrake connect status` shows which are).
  - Damage done inside an MCP server after the call it checks: see the postmark-mcp row in [`incidents/`](incidents/).
  - A person, or a program running outside the agents, can still remove Squidbrake from their own laptop. For a
    company, `squidbrake lockdown` writes policy files IT pushes to every machine, so agents can't run without it
    (only an admin on the machine can undo that).
- **For a hostile agent,** add a sandbox (a container or a VM, with no credentials it doesn't need) underneath.
  Squidbrake then decides what is allowed, and the sandbox makes sure nothing goes around it.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Querying

| Endpoint | |
|---|---|
| `GET /v1/events?q=&session_id=&source=&client=&kind=&name=&status=&since=&before=&limit=` | newest first, page with `before=<next_before>` |
| `GET /v1/events/{id}` | one event |
| `GET /v1/events/{id}/decision?wait=25` | current decision; long-polls while awaiting approval |
| `POST /v1/events/{id}/approve` · `/reject` | human decision, body `{"note": "..."}` (approver keys only) |
| `GET /v1/me` | which key you are and whether it can approve |
| `GET /v1/stats?hours=24&bucket=hour` | counts by status, top tool names, timeline (same filters as events) |
| `POST /v1/policy/check` | dry-run a call against the rules (not recorded) |
| `GET /docs` | interactive OpenAPI docs |

## Evidence anyone can check

Every decision is written to a hash-chained audit trail together with the fingerprint of the `rules.yaml` version
that made it, and each version's text is kept. **Reports > Tamper check > Download evidence** (or
`GET /v1/audit/export.json`) gives one file that anyone can check on their own machine, without trusting the server:

```bash
python verify.py squidbrake-evidence-20261001-0930.json
```

It confirms the chain is unbroken, that every recorded action still matches the fingerprint taken when it happened
(so rows edited in the database are caught, not just edits to the log), and that every decision's rules version is
in the file. `verify.py` needs only the Python standard library. The dashboard's tamper check runs the same checks live.
Add `--json` for one machine-readable object (`ok`, the number of records checked, and a list of problems with the
record each one was found in) for CI; the exit code stays 0/1 either way.

## Behaviour notes

- **Fail closed**: the Python client refuses to run a tool if the gateway is unreachable
  (`fail_open=True` to change that).
- **Rules hot-reload** on file save; a broken edit is logged and the last good rules stay active.
- **Audit records are write-once**: a result can be posted once, never for a denied call, and never
  while the call is still awaiting approval. Each approval can be decided only once. If two approvers
  click at the same moment, only the first decision counts.
- **Upgrades**: new columns are added to an existing database automatically at startup.
- **Redaction**: keys like `password`, `token`, `api_key`, `authorization`, `cookie` and values like
  `Bearer ...`, `sk-...`, `ghp_...`, AWS, Slack, Stripe, Google and npm keys, JWTs, private keys and the password in a
  URL (`postgres://user:...@host`) are stored as `[REDACTED]`. Rules still see the raw input.
- Payloads over `MAX_PAYLOAD_CHARS` are truncated in storage. Proxy responses are buffered (no streaming/SSE).
- SQLite (WAL) is fine for one machine. For several gateway replicas, set `DATABASE_URL` to Postgres.

## Tests

```bash
pip install pytest && pytest -q
python tests/e2e_business_scenario.py
```

## Usage sharing (asked first)

Squidbrake shares nothing about you or your agents without asking first. The one request it makes on its own is
the daily update check below, which only asks for the newest version number.

**Anonymous usage stats.** The first time you run `squidbrake` in a terminal, it asks once whether to send
anonymous stats (Enter means yes): the command name (e.g. `doctor`, never its arguments), version, OS, Python
version and country, plus the gateway's usage counts described below (what it allowed, held and blocked). After a
yes it asks where you heard about Squidbrake (pick from a list, or Enter to skip); if you installed from a named
link, that name (`SQUIDBRAKE_REF`, e.g. `linkedin`) answers it instead. Never
commands an agent ran, files, prompts, rules, keys or the audit trail. The agent hooks never send anything, and
scripts, CI and `--yes` are never asked. `squidbrake telemetry off` (or
`SQUIDBRAKE_TELEMETRY=0`, or `DO_NOT_TRACK=1`) stops it; `squidbrake telemetry status` shows exactly what is sent.
**Update check.** Once a day, running `squidbrake` in a terminal asks pypi.org for the newest version number, and
the next time says if there's a newer one. That request carries nothing about you beyond the request itself; never
in hooks, scripts or CI; off with `SQUIDBRAKE_NO_UPDATE_CHECK=1` or `DO_NOT_TRACK=1`.

If you'd like the team to know who you are, `squidbrake register you@company.com` (asks first). Details:
[`telemetry.py`](telemetry.py).

**Usage counts.** There are two ways to share counts of what Squidbrake did, and both show exactly what will be
sent and ask first (the default answer is no):

- `squidbrake connect all`, run in a terminal, asks once at the end whether to share counts with the Squidbrake
  team. It never asks again after a no, and never asks with `--yes` or in scripts.
- A pilot joins with the code they were given: `squidbrake pilot join CODE --server URL`.

What is shared is usage **counts**: actions allowed, held, approved and blocked per day, and which agents and
rules. Never commands, code, prompts or keys. `squidbrake pilot leave` stops it. Details: [`pilot.py`](pilot.py)
and [`insights/`](insights/).

## Roadmap

- **Reach checks for AWS** ([#18](https://github.com/batrapulkit/squidbrake/issues/18), [design](docs/design/aws-reach-checks.md)):
  before an IAM change runs, work out what the agent will be able to reach afterwards, and hold it if that crosses a line
  (admin roles, production, secrets). Stops an agent from giving itself admin in steps that each look harmless.
- **An optional risk model that can only escalate** ([#16](https://github.com/batrapulkit/squidbrake/issues/16)): a second
  opinion that can hold an action, never allow one.
- **More agents connected in one command**: Cursor install ([#2](https://github.com/batrapulkit/squidbrake/issues/2)),
  more rule packs like the [GitHub, Stripe, Slack and Postgres ones](examples/rules/).

Tell us what you need most: 👍 or comment on the issues.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md): a 10-minute setup, and
  [good first issues](https://github.com/batrapulkit/squidbrake/labels/good%20first%20issue) that name the file and
  function to change. Comment on one to claim it. Hacktoberfest pull requests are welcome.
- [SECURITY.md](SECURITY.md): report vulnerabilities privately
- Licensed under the [Apache License 2.0](LICENSE)
