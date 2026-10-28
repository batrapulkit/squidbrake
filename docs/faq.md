# FAQ


## How is Squidbrake different from Claude Code's built-in allow/ask permissions?

Claude Code's built-in permissions control actions for an individual agent. Squidbrake provides **centralized rules for a whole team**, with approvals from your **phone or Slack**, history checks, an **audit trail**, and support across multiple agents.

## What happens if Squidbrake is down?

It **fails closed for what matters** (`when_unreachable: block_risky`, the default). Anything that would wait for a
person or be blocked doesn't run, and neither does a command that can't be undone or can't be read, or one that
reaches for Squidbrake's own keys. What your rules already let run on its own (reads, everyday coding work) carries
on. `when_unreachable: block` stops everything instead, and each rule can say `when_unreachable: allow | block`. The
hooks, MCP connectors and `client.py` keep a copy of these answers while the gateway answers, so they follow them
while it's down. What runs then isn't recorded. `GATEWAY_FAIL_OPEN=1` on a machine still lets everything through
there.

## Does my data leave my machine?

What your agents do doesn't: commands, files, prompts, tool inputs and outputs, and the audit trail stay on your
laptop or your server. What leaves is anonymous usage counts: the command name, version, OS, how many actions were
allowed, held and blocked, and for each held or blocked one the program (like `rm`) and the rule. The first run in a
terminal says so; `DO_NOT_TRACK=1` turns it off. See [Usage sharing](operations.md#usage-sharing).

## Does Squidbrake use an LLM to make decisions?

No. Squidbrake uses **deterministic rules and checks**. There is no LLM in the decision path. The optional AI brief
(Settings → AI approval briefs, your own Anthropic key, `pip install "squidbrake[ai]"`) writes a short risk note for
the person deciding on a held action; nothing reads it to decide.

## Can an agent get around Squidbrake?

Squidbrake is built for the common case: a **cooperative agent that makes a mistake** or follows instructions it found
in an email, a web page or an issue. It is not a sandbox against an agent that is deliberately trying to escape.
Here's what that means in practice:

- **Caught:** what the agent does through a connected tool. That includes shell commands read before they run
  (`ls && rm -rf ~/`, `bash -c "..."`, `curl ... | sh`), MCP calls, edits to its own settings, hooks and MCP servers
  or to Squidbrake's rules (held for a person), and chains of steps such as backups switched off and then a delete.
  Through the hooks, what a command runs underneath is read too: a Makefile target's recipe (`make clean`), a
  `package.json` script (`npm run release`) and a shell script (`bash cleanup.sh`).
- **Held because it can't be read:** inline code that does more than look (`python -c` or `node -e` that runs a
  shell, uses the network, changes files or builds code at run time; any `perl -e`, `ruby -e`), the same code fed to
  an interpreter on its input (`python3 - <<EOF`), a program named only when it runs (`$(...)`, `eval`), and a script the agent created in this conversation and then runs
  (`python cleanup.py` right after writing `cleanup.py`). A person reads it first.
- **Held: the agent turning Squidbrake off.** `squidbrake connect --remove`, `service stop`, uninstalling it, killing
  its process, editing the agents' hook settings or Squidbrake's installed files, or setting a lasting variable that
  loosens it all wait for a person.
- **Blocked: the agent approving itself.** Reading or writing Squidbrake's keys, link secret or database,
  `squidbrake add-key`, or calling the approval API from its own tools.
- **Not caught:**
  - A script that was already in the project, edited and then run: `python scripts/seed.py` runs and is flagged for
    the approver (`edited_then_run: warn`, because running the project's own scripts after a change is everyday work);
    `edited_then_run: review` holds it. What it does inside isn't seen.
  - Programs that aren't common developer tools are recorded, not held (`command_checks.unknown: warn`; set it to
    `review` to hold them).
  - Tools that aren't connected (`squidbrake connect status` shows which are).
  - Damage done inside an MCP server after the call it checks: see the postmark-mcp row in [`incidents/`](../incidents/).
  - A person, or a program running outside the agents, can still remove Squidbrake from their own laptop. For a
    company, `squidbrake lockdown` writes policy files IT pushes to every machine, so agents can't run without it
    (only an admin on the machine can undo that).
- **For a hostile agent,** add a sandbox (a container or a VM, with no credentials it doesn't need) underneath.
  Squidbrake then decides what is allowed, and the sandbox makes sure nothing goes around it.

The full list, per agent and with the test behind each line, is in [THREAT_MODEL.md](../THREAT_MODEL.md);
`squidbrake doctor` shows what each agent's hook on your computer does and doesn't check.

To report a vulnerability, see [`SECURITY.md`](../SECURITY.md).
