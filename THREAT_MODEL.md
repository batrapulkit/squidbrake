# Threat model

Squidbrake sits between an AI agent and what the agent changes. Each agent's hook (or the MCP proxy) sends every
action to the gateway before it runs. The gateway decides: let it run, block it, or hold it for a person. Then it
records what happened in a hash-chained log.

This page says what that does and doesn't protect against. Each claim marked **(test)** is checked in CI; the test
named next to it is in `tests/`.

## What it assumes

- **The agent can be wrong or manipulated.** It can follow a prompt injection, retry after a no, or try to switch
  Squidbrake off. The agent is treated as untrusted.
- **The person at the keyboard isn't the adversary.** Someone with admin rights on their own laptop can remove
  Squidbrake. For a company, `squidbrake lockdown` writes the managed settings IT pushes, so that only an admin can
  take the hook out.
- **The gateway's machine and its data folder** (`~/.squidbrake/data`: keys, link secret, ledger key, database)
  aren't writable by anything the agent runs, except through the agent's own tools, which go through the hook.

## When the agent and Squidbrake run as the same user

On a laptop, the agent and Squidbrake usually run as the same OS user. Then the agent's process has the same file
permissions as Squidbrake's, and **no check on what a command says can fully close that**. A program the agent was
allowed to run can read any file that user can read.

What Squidbrake does about it:

- **Keys are found by their real path.** Before a call is judged, `cd`, variables, `~`, globs and symlinks are
  followed. A call that reaches Squidbrake's data folder or home folder by any of them is blocked. A call that reads
  or copies a whole folder that holds the keys (`find ~`, `cp -r`, `tar`, a search across the home folder) waits for
  a person. **(test)** `test_protected_paths.py`
- **Tamper detection.** Every 15 seconds Squidbrake checks `keys.json`, `secret.key` and `ledger.key`. Its own
  changes are noted as they happen (a key added in Team or with `add-key`). Any other change is an immediate alert,
  an `integrity.changed` entry in the audit trail and, with `integrity: fail_closed`, a stop on risky actions.
  **(test)** `test_threat_model.py`
- **Approvals come from another channel.** A person approves in the dashboard, on a phone or in Slack. The agent's
  key can't approve, and the agent can't reach the approval API.
- **Owner-only files.** On macOS and Linux the data folder is 700 and the key files are 600. That stops other users
  on the machine, but not the same user.

**What closes it fully: run Squidbrake as a different user, or on another machine.** With a team gateway on a
server (`install.sh`, Docker), the agent's computer holds only its own agent key. That key can ask, but it can
never approve. The approvers' keys, the link secret and the record live where the agent's user has no access at
all. For a single laptop, running the gateway under a separate OS user gives the same separation. Without that,
treat the same-user protections above as making tampering visible and slow, not impossible.

## What it stops

- **An agent approving its own action.** These are blocked in code, before the rules and in observe mode too
  (`selfguard.py`, **test** `test_approval_integrity.py`):
  - reading or writing Squidbrake's keys, link secret and database
  - `squidbrake add-key / remove-key / resume / feedback / integrity`
  - calling the approval API from its own tools
  - reading browser storage, where the dashboard keeps a person's key

  Each attempt is recorded as `security.self_approval_attempt` and sent where approvals go. Approval links are
  bound to one action, work once, and expire with it.
- **An agent loosening Squidbrake.** These wait for a person (**test** `test_audit.py`):
  - editing its own hooks, settings, MCP config or `rules.yaml`
  - uninstalling, stopping or killing Squidbrake
  - editing or reinstalling the installed package
  - setting a lasting `GATEWAY_*` or `SQUIDBRAKE_*` variable
  - starting a gateway with sign-in off
- **Changes made around it.** Every minute the gateway checks its own hook lines in each agent, `rules.yaml` and the
  installed files (`integrity.py`). A change is recorded and alerted. With `integrity: fail_closed`, risky actions
  are blocked until a person runs `squidbrake integrity accept`. **(test)** `test_threat_model.py`
- **A tampered record.** `squidbrake audit verify` checks the hash chain end to end, names the first broken link, and
  checks that each recorded action still matches its fingerprint. **(test)** `test_threat_model.py`
- **Single steps that can't be undone**, read from what the command really does: `a && b`, `bash -c`, `sudo`,
  `$(...)`, Makefile targets and package.json scripts, and commands sent over `ssh`, `docker exec` or `kubectl exec`.
  **(test)** `test_commands.py`, `test_threat_model.py`
- **Chains**: a step judged by what came before it. Examples:
  - backups switched off and then a delete, by any agent in any conversation
  - a destination that only outside content mentioned, even in an earlier conversation
  - a retry after a person said no
  - a script the agent wrote and then runs
  - a refund loop split across agents

  What earlier steps give an agent is kept per identity (all your agents on your own computer; on a team gateway,
  the agents whose key works for one person), until it expires, across restarts. **(test)** `test_capabilities.py`,
  `test_audit.py`, `test_risk.py`

## While Squidbrake is down

`when_unreachable: block_risky` is the shipped default. What the rules already let run on its own still runs. That
covers reads and everyday coding work, and it runs **unrecorded**. Anything that would wait for a person or be
blocked is blocked, and so is any command that can't be undone or can't be read. Squidbrake's own keys stay out of
reach.

- **The tradeoff:** an agent that can make the gateway unreachable gets unrecorded everyday work, never a risky
  action.
- **`block`** stops everything. It's the safest setting, but agents stop working until Squidbrake is back.
- **`allow`** runs everything.

**(test)** `test_threat_model.py`

## What Squidbrake does not stop

These are known and not fixed. Some can't be fixed at this layer.

1. **Code that isn't read before it runs.**
   - Shell and PowerShell scripts are read line by line before they run, however they're run: `bash x.sh`, `./x.sh`,
     a full path, `source x.sh`, `. x.sh`, `exec ./x.sh`, `sudo bash x.sh`, `pwsh -File x.ps1`.
   - A Python, Node or other-language script isn't read. One that was already on disk before the conversation runs
     like any other program: this is the limit.
   - If the agent wrote it in the same conversation, with its edit tools or a shell command (`cat > x.py <<EOF`,
     `echo ... > x.js`, `tee`), it's held before it runs (`python x.py`, `node x.js`, `uv run x.py`).
   - If the agent changed it, it's flagged but runs (`edited_then_run: warn`), because fixing a script and running it
     is everyday work. Set `edited_then_run: review` to hold those too. **(test)** `test_threat_model.py`
   - Inline code (`python -c`) is held as hidden.
   - `npx -y pkg` and `pip install pkg` run code nobody has read, and so do a new dependency's own install scripts
     (they can't be read before it's downloaded). They're recorded (`unknown: warn`), not held: holding every
     install would hold everyday work. Use `npm install --ignore-scripts` where you can.
   - A file downloaded and then run, sourced or made runnable in the same conversation is held
     (`curl -o x.sh URL` or `curl URL > x.sh`, then `sh x.sh`). The same file run in a later conversation isn't connected to its
     download.
2. **What runs inside an approved or allowed program.** One allowed `terraform apply` or deploy script can do
   anything its credentials allow. Squidbrake sees the command, not what the program does afterwards.
3. **Code inside an upstream MCP server.** A compromised server can add a hidden BCC after the call Squidbrake
   checked. That's the Postmark case: [incidents/](incidents/).
4. **Anything outside the agent's tools.**
   - A background process the agent started earlier.
   - A cron job or CI pipeline.
   - Credentials used from another machine.
   - A person's own terminal (`squidbrake shell-guard` covers lines typed there, as an opt-in).
5. **Agent paths the hook doesn't see.** `squidbrake doctor` lists them for each agent on the machine:

   | Agent | Not checked |
   |---|---|
   | Codex | everything until its hook is trusted in `/hooks`; Codex cloud tasks |
   | Gemini CLI | MCP tools (unless `connect` wrapped the server), `web_fetch` |
   | Cursor | edits on versions without `preToolUse`; cloud background agents |
   | VS Code | the Copilot coding agent on GitHub |
6. **Cloud reach.** There is no IAM reach check yet. An agent can give itself admin in steps that each run on their
   own: `test_audit.py::test_iam_escalation_chain_is_held` is an open gap. Changes made outside the agent (no
   CloudTrail sync) aren't seen either.
7. **Chains across people.**
   - On a team gateway, one person's agents and another's are separate identities, so a chain split between two
     people isn't connected. The exception is rules with `scope: all`, like the shipped
     backups-off-then-delete rule.
   - Chains only remember what their rules name. A first step that no rule names is in the record, but it
     isn't a capability.
8. **Someone with admin rights on the machine, or the agent's own user outside its tools.** They can edit the data
   folder, the package or the agents' configs directly. Integrity checks alert on the hooks, rules, package and key
   files within seconds, but they can't prevent the change. See *When the agent and Squidbrake run as the same user*. Lockdown and
   `audit verify` (an exported, signed log) are the answers for a company.
9. **A person approving something they shouldn't.** Squidbrake makes sure a person sees the action, with the reason
   and what led to it. It doesn't make the decision for them.
