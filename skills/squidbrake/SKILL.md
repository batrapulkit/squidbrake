---
name: squidbrake
description: Set up Squidbrake, which checks every command and tool call an AI agent makes against rules (risky ones wait for a person, rm -rf ~/ never runs), and respond correctly when Squidbrake blocks or holds an action. Use when the user wants guardrails, approvals or an audit trail for their coding agents, or when a tool call comes back blocked or waiting for approval from Squidbrake.
---

# Squidbrake

Squidbrake is a gateway between AI agents and the machine. Every command, file edit, read and MCP tool call is
checked against `rules.yaml` before it runs: safe ones run, dangerous ones are blocked, and risky ones wait until
a person approves them in the dashboard, on their phone or in Slack. Everything is recorded in a tamper-evident
audit trail. Source: https://github.com/batrapulkit/squidbrake

## Setting it up for the user

Ask before running these: `connect all` changes the user's agent configs (each one is backed up first).

1. Install: `pipx install squidbrake` (or `pip install squidbrake`).
2. Connect every agent on this computer: `squidbrake connect all`. It finds Claude Code, Cursor, Codex, Gemini CLI,
   VS Code Copilot and Antigravity, plus the MCP servers they use. The first time, it prints the dashboard's admin
   key. Tell the user to save it, and don't repeat the key back in chat.
3. Start the gateway: `squidbrake` (opens `http://localhost:8080/dashboard`). For it to keep protecting them it must
   stay running. A 24/7 server option is in the README.
4. Tell the user to restart their agents. Codex also needs the hook approved once with `/hooks`.
5. Check: an agent asked to run `rm -rf ~/` should be refused with the reason.

Undo: `squidbrake connect all --remove`. Rules live in `~/.squidbrake/rules.yaml` and changes apply at once.
To guard one app's MCP server: `squidbrake proxy --app NAME --url URL` (or `-- COMMAND`).

## When Squidbrake blocks or holds one of your actions

- **Blocked:** the reason says why. Don't retry the same action, and don't reach the same result another way
  (a different command, a script, another tool, encoding it). Tell the user what was blocked and why, and ask how
  they want to proceed. Only the user can change the rules.
- **Waiting for approval:** a person is deciding. Wait for the decision; don't start a workaround meanwhile.
- **Rejected with a note:** the note is from the person. Follow it.
- **"Squidbrake can't be reached":** it fails closed on purpose. Ask the user to start it (`squidbrake`). Don't
  remove the hook to get around it.
