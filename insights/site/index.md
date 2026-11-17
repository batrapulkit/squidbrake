# Squidbrake: agents propose, people approve

Change control for AI agents. Everyday work runs on its own. When Claude Code, Cursor, Codex or Gemini CLI wants to do something it can't take back, a teammate sees what it will change ("deletes 4,312 rows of 10,240 in orders", "destroys 12 resources, including the prod database") and says yes or no.

- Install: `pipx install squidbrake`
- Backed by Entrepreneur First
- Design-partner pilots with engineering teams in the US, Canada and India
- Book a 30-minute demo: https://calendly.com/pulkitbatra2024/new-meeting-1 · pulkit@squidbrake.com

## The problem: every step looks fine, the chain doesn't

AI agents can now touch cloud, production and payments. Each action looks fine on its own, but a chain of fine actions can add up to something nobody authorized, like deleting a production database right after its backups were turned off. Squidbrake checks each tool call against your rules and against what the agent already did, and stops the step that makes the combination dangerous.

## Why now: agents got write access, controls did not catch up

Ten publicly reported AI-agent incidents, replayed against the rules Squidbrake ships with, with nothing written for the occasion:

| Incident | When | Squidbrake |
|---|---|---|
| Claude Code deletes a user's home folder | Dec 2025 | Blocked |
| Google Antigravity wipes a whole D: drive | Dec 2025 | Blocked |
| Replit's agent deletes a production database during a code freeze | Jul 2025 | Held for a person |
| A coding agent deletes a production volume and its backups | Apr 2026 | Held for a person |
| A wiper prompt ships inside the Amazon Q VS Code extension | Jul 2025 | 2 held, 1 blocked |
| A GitHub issue makes an agent leak private repos | May 2025 | Held for a person |
| A support ticket makes an agent post secret tokens (Supabase MCP) | Jul 2025 | 2 held |
| OpenAI's Operator buys eggs without asking | Feb 2025 | Held for a person |
| An AI coding agent deletes and recreates a live environment, 13-hour AWS outage (Amazon disputes the account) | Dec 2025 | Held for a person |
| A malicious Postmark MCP server secretly BCCs every email | Sep 2025 | Not stopped: the BCC is added inside the server, after approval |

12 of 13 harmful actions stopped across 10 incidents: 3 blocked, 9 held for a person, 1 not stopped. Sources and scenarios: https://github.com/batrapulkit/squidbrake/tree/main/incidents. Reproduce with `python incidents/replay.py`.

## How it works

Policy is one YAML file in your repo. Every decision names the rule that made it.

```yaml
default: review

command_checks:
  catastrophic: block     # rm -rf ~, wiping a drive
  irreversible: review    # git push --force, cloud deletes
  read_only: allow        # ls, cat, git status

rules:
  - id: allow-reads
    action: allow
    match: { name: ["Read", "Grep", "Glob"] }

  - id: refunds-to-finance
    action: review
    approvers: ["role:finance"]
    match: { name: ["mcp__stripe__*refund*"] }

sequences:
  - id: delete-after-backups-off
    action: review
    reason: Deleting a database right after its backups were turned off
    match: { name: ["mcp__aws__rds_delete_*"] }
    after:
      match: { input_regex: '"backup_retention_days":\s*0' }
      within_hours: 24
```

1. Declare what each agent is for: which tools run freely, which wait for a person, which never run.
2. Each agent gets its own key, so every call is tied to one agent and can be cut off on its own.
3. Every call is checked against the rules and the agent's recent actions. A step that looks fine alone is held when it completes something dangerous.
4. Held calls go to Slack, the dashboard or a one-tap phone link. Blocked calls never reach the tool. Access can be revoked in one call.

## Not only coding agents

Support, finance and ops agents make the changes that cost money. They go through the same rules, the same chain checks and the same person.

- **Support agent:** a ticket asks for a $900 refund to a different card than the one that was charged. Held: refunds wait for a person, who sees the ticket that asked for it.
- **Finance agent:** an email from ceo.office@acrne.com asks for an urgent $24,800 wire. Blocked: money moving right after a message from a look-alike of your domain.
- **Data agent:** a ticket from a "data partner" asks for the full customer export, by email. Held: an email to an outside address waits for a person.
- **Ops agent:** pins a customer to an older version, changes their plan, flips a feature flag, through your own tools. Held by default: a change through a tool Squidbrake doesn't know waits for a person; reads run.

The first three are sessions from the benchmark (https://github.com/batrapulkit/squidbrake/tree/main/bench/chains), replayed against the shipped rules.

## Compared with what you already have

| | Squidbrake | IAM | Policy engine (OPA, Cedar) | API gateway | In-agent guardrail |
|---|---|---|---|---|---|
| Remembers what the agent did before | Yes, across sessions and agents | No | No, stateless | No | Only in the prompt |
| Reads the actual command | Yes, parsed | Sees the API action | If you write it | Method and path | Yes |
| Out of the model's reach | Yes | Yes | Yes | Yes | No, can be injected |
| Holds one step for a person | Slack, phone, dashboard | No | No | No | Asks in the chat |
| Approved by someone other than the person running the agent | Yes | No | No | No | No, the same person |
| Shows what it will change before approval | Rows, resources, commits, files | No | No | No | The raw command |

## Latency

The check takes 3.3 ms at the median and 9 ms at p95: 1,000 mixed calls against the shipped rules, measured 3 Oct 2026 on a laptop with server and caller on the same machine and SQLite. A network hop adds its own round trip.

## Available today

- Runs in your cloud: Docker image, Compose file or systemd unit; SQLite or Postgres.
- Second-person approval through Slack, Discord, the dashboard or a phone link. Nobody approves their own agent's request.
- Shows what it will change, measured before approval: rows a DELETE would remove, resources a terraform destroy would take (and which hold data), commits a force push would erase, objects in a bucket.
- Undo: right before an approved delete, git reset or git clean, Squidbrake keeps a copy; one command puts it back.
- One policy on every laptop: lockdown uses the agents' own managed settings (Claude Code, Cursor, Codex, Gemini CLI).
- Evidence for your auditor: hash-chained decisions verified offline, CSV or JSONL export, and a one-page evidence pack that supports SOC 2 change-management evidence.
- Kill switch: stop every agent, one agent or one session in a single call.
- Shadow mode: log what would have been blocked, without blocking anything.

On the roadmap: SSO and SCIM, streaming to your SIEM, managed cloud.

## What it connects to

- **Coding agents, with `squidbrake connect all`:** Claude Code, Cursor, Codex CLI, Gemini CLI, VS Code Copilot, Antigravity. Windsurf, Kiro and Claude Desktop through their MCP tools.
- **Agents that connect by URL, with one URL from the dashboard:** ChatGPT connectors, claude.ai connectors, Devin, n8n, any MCP client.
- **Agents you build, with `gw.guard_tools([...])` or one HTTP call:** OpenAI Agents SDK, LangChain, LangGraph, CrewAI, PydanticAI, smolagents, Google ADK, any language over HTTP.
- **Apps, any MCP server:**
  - Picked in the dashboard, with only the token to paste: GitHub, Stripe, Linear, Jira and Confluence, Sentry, Supabase, Neon, Cloudflare, Intercom, Airtable, Zapier, Make, monday.com, PagerDuty, Context7, Exa, Firecrawl.
  - Run on a laptop or your own gateway: Notion, Square, PayPal, MongoDB, Grafana, Postgres, Filesystem, Playwright, Brave Search, Twilio, and any other MCP server.
  - Not yet: hosted servers that sign in only through a browser (OAuth), such as Slack, HubSpot, Asana, Vercel, Figma, ClickUp, Google Workspace and hosted Salesforce.
- **Approvals reach people in:** Slack, Discord, a one-tap phone link, phone notifications (ntfy), the dashboard.

Checked against the real apps: Claude Code, Cursor, Codex CLI, Gemini CLI, the OpenAI Agents SDK and LangChain. The others are covered by tests of their documented hook or MCP formats.

```bash
pipx install squidbrake
squidbrake connect all
squidbrake
```

Quickstart: https://squidbrake.com/docs

## FAQ

**Does any of our data leave our network?** No. Squidbrake runs where you run it. Tool calls, results and the audit log stay in your database.

**Does it use an LLM to decide?** No. Decisions come from your rules, a command parser and the agent's recent history. The same call gets the same answer every time.

**What happens if Squidbrake is down?** You choose. By default a call that can't be checked doesn't run. Set `GATEWAY_FAIL_OPEN` to keep agents moving instead.

**Can the agent get around it?** It's built for the common case: a cooperative agent that makes a mistake, or follows instructions it read in an email, a web page or an issue. Everything that goes through a connected tool is checked outside the model, including the agent trying to change its own settings or Squidbrake's rules. It doesn't see inside a script the agent writes and then runs, or tools you haven't connected. For an agent you don't trust at all, run it in a sandbox too.

**Doesn't auto mode already handle this?** Keep auto mode for everyday work: it should decide the 99% of steps that are easy to undo. Squidbrake is for the 1% you can't take back, and there the person running the agent shouldn't be the only one saying yes. A teammate approves, with the effect in front of them, and a wrong yes can often be undone.

**How does this help with SOC 2?** SOC 2's change-management control asks that changes be authorized and approved. Once agents change production, your auditor will ask who approved what they changed. Squidbrake records a second person's approval for every risky step in a tamper-evident log, and the evidence pack puts it on one page. It supports your evidence; your auditor decides what it satisfies.

**How do we start without breaking anything?** Turn on shadow mode. Nothing is blocked for the first week; you see what would have been, then decide what to enforce.
