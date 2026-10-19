# Squidbrake

<!-- mcp-name: io.github.batrapulkit/squidbrake -->

**Change control for AI agents. Agents propose. People approve.**

5,000+ PyPI downloads.

[![tests](https://github.com/batrapulkit/squidbrake/actions/workflows/tests.yml/badge.svg)](https://github.com/batrapulkit/squidbrake/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/squidbrake.svg)](https://pypi.org/project/squidbrake/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/batrapulkit/squidbrake/badge)](https://scorecard.dev/viewer/?uri=github.com/batrapulkit/squidbrake)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![MCP](https://img.shields.io/badge/MCP-compatible-8A2BE2.svg)](docs/install.md#2-connect-real-agents)
[![Real incidents replayed: 13 of 14 stopped](https://img.shields.io/badge/real%20incidents%20replayed-13%20of%2014%20stopped-yellow.svg)](incidents/)
[![Good first issues](https://img.shields.io/github/issues/batrapulkit/squidbrake/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/batrapulkit/squidbrake/labels/good%20first%20issue)

<a href="https://www.producthunt.com/products/squidbrake?embed=true&utm_source=badge-featured&utm_medium=badge&utm_campaign=badge-squidbrake" target="_blank" rel="noopener noreferrer"><img alt="Squidbrake - Change control for AI agents: sign-off, undo and a record | Product Hunt" width="250" height="54" src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1275992&theme=light&t=1791704247916"></a>

Your AI agents run commands, edit code, call MCP tools, send emails, issue refunds and change databases. Squidbrake
sits between the agents and those actions:

- routine work runs on its own, and is recorded
- risky changes wait for a person who isn't the one who asked
- catastrophic ones are blocked

Every decision goes into a tamper-evident record that someone outside engineering can read.

One policy covers every agent your company runs: Claude Code, Cursor, Codex, Gemini CLI, VS Code Copilot,
Antigravity, and any MCP tool. Open source (Apache 2.0) and free for one person; more than one person, phone approvals, Slack/Teams/email and the audit export are part of the Team plan (`squidbrake license`). Runs on your laptop or your own server.

![Demo: every agent action goes on the record; a refund waits for a person and is approved from a phone; the record shows who asked, who approved and what led to it](https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/demo.gif)

## Why

Agents are good at each step and blind to the whole. Often every step is allowed, and the combination isn't:

- An agent turns off a database's backups. Later, in another conversation or from another agent, it deletes the
  database.
- An agent reads a web page, an issue or a support ticket that names an address. It then sends your data there.
- A person rejects a force push, and the agent retries it with a different spelling.

Built-in agent permissions judge one tool call at a time, inside one agent. Squidbrake judges each action against
what came before it, across conversations and agents. A person signs off on what matters, with the reason and the
steps that led to it.

## How it works

```
 agent (Claude Code, Cursor, Codex, MCP client, your own code)
   │  every action, before it runs (hook, MCP proxy or HTTP)
   ▼
 Squidbrake gateway ── rules.yaml + what came before ──► allow · hold for a person · block
   │                                                          │
   └──────────── tamper-evident record ◄──────────────────────┘
                     dashboard · phone · Slack · Teams · email · SIEM
```

- **Deterministic.** No LLM decides anything. Rules and checks are in `rules.yaml`, hot-reloaded on save.
- **Reads what a command really does** before it runs:
  - `ls && rm -rf ~/`, `bash -c "..."`, `curl ... | sh`
  - Makefile targets and `package.json` scripts
  - commands sent over `ssh`, `docker exec` and `kubectl exec`
- **Shows the approver the blast radius**, measured on the developer's machine:
  - "removes 3 commits from origin/main"
  - "deletes 4,312 rows of 10,240 in orders"
  - "destroys 12 resources, including aws_db_instance.main"

![Squidbrake dashboard: a git push and a refund wait for approval, while a scam wire transfer was blocked](https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/dashboard.png)

<table><tr>
<td width="62%"><img src="https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/blocked-scam.png" alt="A $24,800 wire blocked because it follows an email from a look-alike domain"><br>
<sub>An agent read an "urgent CEO" email from <code>acrne-corp.com</code> and tried to wire $24,800. Blocked, with the story of what led to it.</sub></td>
<td width="38%"><img src="https://raw.githubusercontent.com/batrapulkit/squidbrake/main/docs/phone-approval.png" alt="One-tap approval on a phone"><br>
<sub>Approve or reject from your phone with one tap.</sub></td>
</tr></table>

## Quick start

**1. Install.** One line installs it, runs it in the background, connects every agent on this computer, and opens
the dashboard:

```bash
curl -fsSL https://pilots.squidbrake.com/install.sh | SQUIDBRAKE_REF=github sh        # macOS / Linux
```

```powershell
$env:SQUIDBRAKE_REF="github"; irm https://pilots.squidbrake.com/install.ps1 | iex       # Windows
```

Or with pip: `pip install squidbrake && squidbrake setup`.

**2. Start in observe mode.** Nothing is blocked or held; Squidbrake records what it *would* have done:

```bash
squidbrake connect all --mode observe
squidbrake doctor                       # every agent connected, and what each one's hook does and doesn't check
```

**3. Review after a week:**

```bash
squidbrake report --week                # held, blocked, would-have, false-positive rate, decision time, chains caught
```

Mark any hold that shouldn't have happened with "This was legit" in the dashboard, or
`squidbrake feedback EVENT_ID legit`. The report counts the false-positive rate per rule.

**4. Enforce.** Set `mode: enforce` in `~/.squidbrake/rules.yaml`. You can also enforce rule by rule (`mode:` on a
single rule) and observe the rest.

Even in observe mode, three things are always enforced:

- catastrophic commands (`rm -rf ~/`, wiping a drive)
- an emergency stop
- an agent reaching for Squidbrake's own approval path

No install? Open the live demo in your browser: a sandbox company's support agent works its inbox while you watch.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/batrapulkit/squidbrake?quickstart=1)

More ways to install: [docs/install.md](docs/install.md).
First run not right? [docs/troubleshooting.md](docs/troubleshooting.md).

## What it controls

| Control | What it does | Details |
|---|---|---|
| **Sign-off by a second person** | Risky changes wait in the dashboard, on a phone (one tap, optional Face ID / fingerprint), or in Slack, Teams or email. A key can't approve its own request, and per rule (`second_person: true`) or for the team, nobody approves what their own agent asked for. Roles: only `finance` approves wires. Two people for the big ones (`required_approvals: 2`, one rejection stops it), and escalation when nobody decides in time | [rules](docs/rules.md#human-approval) |
| **Steer a running agent** | Send a note an agent gets with its next action. The agent can ask a person instead of guessing (`ask_user`), and must say why before a call a rule names (`justification: required`). `action: notify` lets it run and tells the team | [rules](docs/rules.md#tell-ask-why-ask-a-person-steer) |
| **Command checks** | Catastrophic commands are blocked. Irreversible ones (`git push --force`, `terraform destroy`, `kubectl delete`, cloud deletes, `DROP TABLE`) and code that can't be read (`python -c`, `curl \| sh`, a script the agent just wrote) wait for a person. Commands that only look run | [rules](docs/rules.md#command-checks) |
| **Chains** | An action is judged by what came before it: backups off and then a delete, a retry after a no, a refund loop. This works across conversations and agents, until the earlier step expires (`squidbrake capabilities`) | [rules](docs/rules.md#sequence-rules) |
| **Prompt injection, without a model** | Sending to an address that only outside content mentioned (a web page, an email, an issue), even in an earlier conversation, waits for a person. The approver is told where the address came from | [rules](docs/rules.md#prompt-injection-caught-without-a-model) |
| **Data in public places** | A customer's name or personal data in a PR, issue, comment or chat post waits for a person | [rules](docs/rules.md#customer-names-and-personal-data-in-public-places) |
| **Undo** | Before an approved delete, `git reset --hard` or `git clean`, a copy is kept. `squidbrake undo` puts it back | [rules](docs/rules.md#undo-copies-spend-limits-proof-of-work-and-signed-approvals) |
| **Self-protection** | An agent can't approve its own action, read Squidbrake's keys, or switch Squidbrake off without a person. Every minute it checks that its hooks, rules and installed files are unchanged | [threat model](THREAT_MODEL.md) |
| **Evidence** | A hash-chained record with signed checkpoints that anyone can verify offline (`python verify.py`, `squidbrake audit verify`). A Monday summary, and an evidence pack for auditors (`squidbrake evidence`). Every rules version that decided something is kept, with a diff and *Put back* | [operations](docs/operations.md#evidence-anyone-can-check) |
| **Spend limits and kill switch** | Pause an agent after N tokens or dollars a day. Stop one agent, one conversation, or all of them, from the dashboard or a phone. While stopped, its waiting approvals don't time out | [rules](docs/rules.md#undo-copies-spend-limits-proof-of-work-and-signed-approvals) |

An example from the shipped `rules.yaml`:

```yaml
rules:
  - id: approve-money-out
    action: review                       # allow | review (a person decides) | deny
    reason: Bank transfers, wires and payouts need finance sign-off
    timeout_seconds: 900
    approvers: ["role:finance", "role:admin"]
    match:
      name: ["*transfer*", "*wire*", "*payout*"]

sequences:
  - id: runaway-refunds
    action: deny
    reason: Too many refunds in a short time; the agent may be stuck in a loop
    match: { name: ["*refund*"] }
    count: { more_than: 10, within_hours: 1, scope: identity }   # across all of one person's agents
```

## Proof

The incidents and the session benchmark run in CI, so they can't quietly stop being true.

- **Real incidents:** [incidents/](incidents/) replays 11 public AI-agent incidents against the shipped rules.
  - Examples: Replit's production database, the Railway volume deletion, GitHub MCP, Supabase MCP, CurXecute.
  - **13 of 14 harmful actions are stopped.**
- **Reported bypasses:** every way around Squidbrake that someone sent us is a test that must stay stopped on
  every release ([tests/test_reported_bypasses.py](tests/test_reported_bypasses.py)): **20 of 20 stopped**, and
  the everyday variants of each still run.
  - The one not stopped is listed and explained: a malicious MCP server adds a BCC inside itself, after the check.
- **Whole sessions:** in [bench/chains/](bench/chains/), Squidbrake stops 64 of 65 harmful steps and holds 3 of 41
  routine ones. An allowlist stops 53 and holds 10.
- **Other tools:** [bench/compare/](bench/compare/) runs the same steps through two other tools (dcg and Microsoft's
  Agent Governance Toolkit), plus everyday coding work. This one is run by hand, not in CI.
- **Claims audit:** [AUDIT.md](AUDIT.md) checks every claim on this page against the code. Gaps still open are tests
  that fail on purpose.

## Supported agents

| Agent | What's checked |
|---|---|
| Claude Code | every tool call: commands, edits, reads, web, MCP (hook, or the Claude Code plugin) |
| Cursor | terminal commands, file reads, edits and deletes, MCP tools |
| Codex | shell commands, edits, MCP tools. Approve the hook once in Codex with `/hooks` |
| Gemini CLI | shell commands, reads, writes and edits, and its MCP servers |
| VS Code Copilot | agent-mode commands, reads and edits, and its MCP servers |
| Antigravity | terminal commands, reads and writes, and its MCP servers |
| Windsurf, Kiro, Claude Desktop | their MCP servers |
| Any MCP client, ChatGPT / claude.ai connectors, Devin, n8n | through the MCP proxy, by command or by URL |
| Your own agents (OpenAI Agents SDK, LangGraph, CrewAI, ...) | `gw.guard_tools(tools)` in Python, or two HTTP calls from any language |

`squidbrake doctor` lists, for each agent on a computer, what its hook doesn't see.
Details: [docs/install.md](docs/install.md#2-connect-real-agents) and [docs/integrations.md](docs/integrations.md).

## Deployment

- **One laptop:** the quick start above. Data, keys and rules stay in `~/.squidbrake`.
- **A team:**
  - Run one gateway on a server: `./install.sh gateway.yourcompany.com` from a clone sets it up with HTTPS. Or use
    Docker: `docker run -d -p 8080:8080 -v squidbrake-data:/app/data ghcr.io/batrapulkit/squidbrake`.
  - Connect each laptop with `squidbrake connect all --url https://gateway.yourcompany.com --key gw_...`. Each agent
    key works for one person.
  - For several replicas, use Postgres (`DATABASE_URL`).
  - *Settings → Agents across the team* lists the agents on each computer that don't go through Squidbrake yet
    (`squidbrake doctor` reports names only; `SQUIDBRAKE_NO_INVENTORY=1` turns it off).
- **Company-wide:** `squidbrake lockdown --url https://gateway.yourcompany.com` writes the managed-settings files IT
  pushes to every machine. Each agent must then run Squidbrake's hook, and `--dangerously-skip-permissions` / `--yolo`
  are turned off.
- **Integrations:** Slack (approve and reject in the channel), Microsoft Teams, email, phone push (ntfy), and SIEM
  export (Splunk HEC, Datadog, an OpenTelemetry collector, any HTTP endpoint).
- **Signed builds:** every PyPI file and Docker image carries Sigstore-signed build provenance
  ([how to check](SECURITY.md#checking-a-release-is-ours)).

## Security model and limits

Squidbrake is a policy and approval layer for agents that make mistakes or follow instructions they shouldn't. It
is not a sandbox against an agent deliberately trying to escape.

- **It doesn't see** code running inside an allowed program or an MCP server, a background process started earlier,
  a tool that isn't connected, or someone with admin rights on the machine.
- **When the agent and Squidbrake run as the same OS user,** a program the agent was allowed to run can read
  whatever that user can. Squidbrake finds its keys by real path (symlinks, globs and `cd` followed). It alerts within
  seconds if a key file changes, and approvals come only from the dashboard, a phone or Slack. To close the gap
  fully, run the gateway as another user or on a server, so the agent's computer only ever holds a key that can ask
  and never approve. Details: [THREAT_MODEL.md](THREAT_MODEL.md#when-the-agent-and-squidbrake-run-as-the-same-user).
- **It doesn't make an over-privileged agent safe.** Use it with least-privilege credentials, and a container or VM
  for untrusted work.
- **While the gateway is down** (`when_unreachable: block_risky`, the default):
  - what the rules already allow (reads, everyday coding work) still runs, unrecorded
  - anything that would wait for a person, and any command that can't be undone or can't be read, is blocked
- **AWS IAM reach isn't checked yet.** An agent giving itself admin in small steps isn't caught. This is on the
  roadmap and is an open test in [AUDIT.md](AUDIT.md).
- **The evidence pack shows which controls exist** for SOC 2, ISO/IEC 42001, the EU AI Act, CERT-In and RBI. It
  doesn't make you compliant.

The full list, per agent and with the test behind each claim, is in [THREAT_MODEL.md](THREAT_MODEL.md). To report
a vulnerability, see [SECURITY.md](SECURITY.md).

## Privacy

What your agents do never leaves your machine or server: commands, files, prompts, tool inputs and outputs, and the
audit trail.

Anonymous usage **counts** are sent to the Squidbrake team:

- the command name and version
- how many actions were allowed, held and blocked
- the decision time
- for each hold or block, only the program (like `rm`) and the rule

The first run in a terminal says so, and asks, optionally, for your work email and name (Enter skips it; only if you
give an email are it, your name and the names of the coding agents installed here sent). `squidbrake telemetry status` shows exactly what is sent, and `DO_NOT_TRACK=1`
turns it off. Details: [docs/operations.md](docs/operations.md#usage-sharing).

## Documentation

| | |
|---|---|
| [Install and connect](docs/install.md) | install options, connecting each agent, sharing with a team |
| [Rules and checks](docs/rules.md) | observe mode, command checks, prompt injection, sequences, approvals, undo, spend limits |
| [Integrations](docs/integrations.md) | MCP proxy, agents by URL, OAuth apps, Python frameworks, HTTP API |
| [Operations](docs/operations.md) | dashboard, API, evidence and offline verification, behaviour notes, usage counts |
| [FAQ](docs/faq.md) | how it differs from built-in permissions, what if it's down, can an agent get around it |
| [Threat model](THREAT_MODEL.md) · [Claims audit](AUDIT.md) | what it stops, what it doesn't, and the test behind each claim |
| [Troubleshooting](docs/troubleshooting.md) · [Showcase](SHOWCASE.md) | the first ten minutes; a five-minute demo with a sandbox company |

## Status and roadmap

Squidbrake is early and moves fast: releases are frequent, and the rules format can still change between minor
versions. Start in observe mode, and read the release notes before upgrading.

Next:

- **Reach checks for AWS** ([#18](https://github.com/batrapulkit/squidbrake/issues/18),
  [design](docs/design/aws-reach-checks.md)). Before an IAM change runs, work out what the agent can reach afterwards.
- **Rule packs for chains.**
  - Business email compromise: a vendor's bank details change, then a payment goes to that vendor.
  - Refunds larger than the order, or sent to a destination changed just before.
- **An optional risk model that can only escalate**
  ([#16](https://github.com/batrapulkit/squidbrake/issues/16)): a second opinion that can hold an action, never allow
  one.

Tell us what you need most with a 👍 or a comment on the issue.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md) covers a 10-minute setup and
  [good first issues](https://github.com/batrapulkit/squidbrake/labels/good%20first%20issue) that name the file and
  function to change. Hacktoberfest pull requests are welcome. Replaying a real agent incident is a good first one.
- [SECURITY.md](SECURITY.md) explains how to report vulnerabilities privately.
- Licensed under the [Apache License 2.0](LICENSE).
