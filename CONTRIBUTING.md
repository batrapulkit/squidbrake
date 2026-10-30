# Contributing

Thanks for helping! Squidbrake is small on purpose: plain Python files, no build step, and a first pull request
fits in an evening.

## Set up (about 10 minutes)

```bash
git clone https://github.com/<you>/squidbrake && cd squidbrake     # your fork
./start.sh            # Windows: start.bat  (creates .venv, installs everything, opens the dashboard)
```

Stop it with Ctrl+C, then check that the tests pass on your machine before you change anything:

```bash
.venv/bin/python -m pip install pytest      # Windows: .venv\Scripts\python
.venv/bin/python -m pytest -q               # unit tests, a few seconds
.venv/bin/python tests/e2e_business_scenario.py   # full scenario: an agent works a sandbox company's inbox
```

## Pick something

- [`good first issue`](https://github.com/batrapulkit/squidbrake/labels/good%20first%20issue): small, with the file
  and function to change and a clear "done when".
- [`help wanted`](https://github.com/batrapulkit/squidbrake/labels/help%20wanted): bigger, with more room for your
  own design.
- **Comment on the issue to claim it** before you start, so two people don't do the same work. You'll usually get a
  reply within a day. One open claim per person; a claim with no pull request after 5 days goes back in the pool.
- An idea that isn't an issue yet? Open one first (or a [Discussion](https://github.com/batrapulkit/squidbrake/discussions))
  so we can agree on the shape before you write code.

## Where things live

| File | What it does |
|---|---|
| `server.py` | The gateway: rules, history checks, approvals, audit trail, API |
| `commands.py` | Reads what a shell command does (never runs it). Tests: `tests/test_commands.py` |
| `taint.py` | Finds where an action sends things, and whether that came from outside content |
| `rules.yaml` | The shipped policy. `examples/rules/` has policies for specific MCP servers |
| `connect.py`, `claude_hook.py` | Connect Claude Code and MCP clients to the gateway |
| `agent_hook.py` | The same hook for Cursor, Codex CLI, Gemini CLI, VS Code and Antigravity |
| `gateway_proxy.py`, `gateway_mcp.py` | Wrap another MCP server; the demo database tools |
| `dashboard.html`, `approve.html` | The dashboard and the phone approval page (single files, no build step) |
| `incidents/` | Real AI-agent incidents replayed against the shipped rules, run in CI |
| `client.py`, `verify.py` | Python client; offline check of an evidence file |

## Three contributions that are always welcome

**Teach the command reader a command.** See what it makes of a line today:

```bash
.venv/bin/python -c "import commands; r = commands.read('dropdb production'); print(r.kind, '|', r.summary())"
```

If a command that destroys or publishes something comes back as `other`, add it in `classify()` in `commands.py`
with a plain-English `why` (the approver reads it), add the line to the matching list in `tests/test_commands.py`,
and add a harmless look-alike to a "not" list so it doesn't cause false alarms.

**Add a policy for an MCP server.** Copy [`examples/rules/github.yaml`](examples/rules/github.yaml) or [`examples/rules/gmail.yaml`](examples/rules/gmail.yaml), list the server's
real tool names, and sort them: reads run, changes wait for a person, destructive ones are blocked.

**Add an incident.** A public report of an agent doing damage goes in [`incidents/scenarios.py`](incidents/scenarios.py)
with its source and the steps the agent took; `python incidents/replay.py` shows what Squidbrake does with it. The ones
it *doesn't* stop yet are the most useful.

## Guidelines

- Add a test for any behaviour you change, and keep both suites passing.
- Keep it simple to run: no new required services or settings. Everything in `.env.example` stays optional.
- Security first: the gateway must stay fail-closed, and a rule that blocks or holds an action must not be bypassable.
- Rules and checks are deterministic. No LLM calls in the decision path.
- Never commit keys, `.env` files or `data/`. `.gitignore` covers them; `MY_*` files are private by convention.
- Found a way around a block or an approval, or a secret stored unredacted? Don't open an issue: report it privately
  (see [SECURITY.md](SECURITY.md)).

## Hacktoberfest

This repository takes part in Hacktoberfest. Pull requests that fix an issue and pass the tests get the
`hacktoberfest-accepted` label. Typo-only or generated pull requests that don't fix anything are closed.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
