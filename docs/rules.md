# Rules and checks

What Squidbrake checks, how to configure it in `rules.yaml`, and how approvals work.

## Try it on real work first: observe mode

```bash
squidbrake connect all --mode observe     # or mode: observe in rules.yaml (shadow_agents: [...] for some agents)
squidbrake report --week                  # a week later: Markdown, or --json
```

In observe mode (also called shadow) Squidbrake blocks and holds nothing: it records what it *would* have done.
Stops, catastrophic commands (`rm -rf /`, wiping a drive) and an agent reaching for Squidbrake's own approval path are
enforced anyway. A rule or sequence can set its own `mode: enforce | observe`, so a team can enforce the catastrophic
ones first and observe the rest.

The weekly report (also `GET /v1/reports/week` and the Reports tab) has:

- actions seen, held and blocked, and what would have been held or blocked
- the **false-positive rate**, per rule and per week, from people marking a hold or block "This was legit" in the
  dashboard or with `squidbrake feedback EVENT_ID legit` (an agent can't mark its own)
- **decision time**, p50 / p95 / p99, recorded for every action
- the top 3 **chains** it caught, in plain words

## Command checks

A script, a Makefile target or a `package.json` script (including the `preinstall`, `install`, `postinstall` and `prepare` scripts `npm install` runs) is read line by line through the same checks, and the same `rules.yaml` rules, as a command typed directly. `npm install --ignore-scripts` runs none of them.

Shell tools (Claude Code's `Bash` and `PowerShell`, or any tool matching `command_checks.tools`) are read by
[`commands.py`](../commands.py) before the rules decide: the line is split on `&&`, `;`, `|` (outside quotes), and
`sudo`, `xargs`, `bash -c`, `powershell -Command`, `$(...)` and commands sent over `ssh`, `docker exec` or
`kubectl exec` are looked inside. Nothing is ever run or expanded.

| Kind | Examples | Default |
|---|---|---|
| catastrophic | `rm -rf /`, `rm -rf ~`, `rmdir /s /q d:\`, `mkfs`, `dd of=/dev/sda`, `chmod -R 777 /` | block |
| irreversible | every delete (`rm`, even `rm -rf node_modules`; `git rm`, `git branch -d`, `docker rm`, `DELETE FROM`, `redis-cli DEL`, `Remove-*`), `git push --force`, `git reset --hard`, `terraform destroy`, `kubectl delete`, `aws ... delete-*`, `DROP TABLE` | review |
| hidden | `eval`, `curl ... \| sh`, `bash <(curl ...)`, `source <(...)`, `cat setup.sh \| bash`, `base64 -d \| bash`, `powershell -EncodedCommand`, `python -c` | review |
| rename | `mv`, `git mv`, `Rename-Item`, `git branch -m`, `gh repo rename`, `aws s3 mv`, `ALTER TABLE ... RENAME`: the old name stops working | review |
| secret | `cat key.pem`, `cat ~/.kube/config`, `grep KEY .env.local`, `gh auth token`, `gcloud auth print-access-token`, `security find-generic-password -w`, `kubectl get secret -o yaml`: shows a secret to the agent, and so to its transcript and model provider. Templates (`.env.example`) and code about secrets (`secrets.py`) aren't | review |
| secrets out | `curl -d "$(env)"`, `curl -F k=@~/.ssh/id_rsa`, `scp ~/.aws/credentials`, `nc ... < .env`: a send whose data is environment variables, SSH or cloud keys, `.env` or key files | review (irreversible) |
| downloaded_then_run | a file downloaded in this conversation, then run, sourced or made runnable (`curl -o x.sh URL`, then `sh x.sh`) | review |
| written_then_run | a script the agent wrote in this conversation, then runs (`python cleanup.py`) | review |
| edited_then_run | a script the agent changed in this conversation, then runs | warn (`review` holds it) |
| read_only | `ls`, `cat`, `grep`, `git status` / `log` / `diff` | `allow` in the shipped `rules.yaml` |

Command checks apply even when a rule allows the tool, and `read_only: allow` only relaxes the `default` (never a
rule or a warning). Configure them under `command_checks:` in `rules.yaml`.

## Terminal guard

Commands people paste from ChatGPT, a forum or a README never pass an agent hook. This puts the same command reader
([`commands.py`](../commands.py)) in front of your own shell: catastrophic lines are blocked, irreversible or unreadable
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

Uploads from the shell count too (`curl -d @.env https://...`, `scp`, `git push`). Outside content read in one
conversation still counts in the next one, by any of the same person's agents (`taint_checks.scope: identity`; set
`session` to keep it to one conversation). Anything sent out after outside content was read in the same conversation
gets a warning for the approver. Configure it under `taint_checks:` in `rules.yaml`.

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
    count: { more_than: 10, within_hours: 1, scope: identity }
```

The approver then sees, for example: *Destroying data right after its backups were turned off. Because earlier:
Bash `aws rds modify-db-instance --backup-retention-period 0` (12 minutes ago).* Actions: `deny`, `review` or `warn`.

- `after:` looks at earlier steps that went ahead (`same_target: true` = on the same charge, file or account).
- `count:` counts earlier matching actions.
- `scope:` sets where both look: `session` (one conversation), `agent`, `identity` (every conversation of every agent
  working for the same person: on your own computer all of them, on a team gateway the agents whose key works for
  that person) or `all`.

What earlier steps give an agent is kept until `within_hours` runs out, across restarts: `squidbrake capabilities`
lists the chains in progress.

## Human approval

Rules with `action: review` hold the call until a person approves or rejects it:

```yaml
- id: approve-payments
  action: review
  reason: Money movement needs a human
  timeout_seconds: 600     # default APPROVAL_TIMEOUT (300)
  on_timeout: deny         # or allow
  approvers: [alice, bob]  # optional; default = any approver key
  required_approvals: 2    # optional: two different people approve (maker-checker); one rejection stops it
  escalate_after_seconds: 300   # optional: nobody decided in 5 minutes? then
  escalate_to: [carol]          #   carol may decide too, and everyone is told again
  match: { name: "payments.*" }
```

- **Two-person approval (`required_approvals:`).** The call runs once that many *different* people approved it; the
  same person can't count twice, a key never approves its own request, and one rejection stops it. The queue shows
  "1 of 2 approvals"; the audit trail has each approval (`event.approval_added`), signed by a passkey if one was used,
  and `verify.py` checks those signatures too. One-tap links approve as the Settings "notify as" person, so the
  second approval comes from someone else's dashboard or phone.
- **Escalation (`escalate_after_seconds:` + `escalate_to:`).** If nobody decided by then, the people in `escalate_to`
  may decide too (added to `approvers:`; with no `approvers:` anyone already could), and the notification goes out
  again marked *Escalated*. It must be shorter than `timeout_seconds`. Frozen, like the deadline, while the agent is
  stopped.

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
- **Starter packs** for a support, finance, ops or back-office (CRM, orders, campaigns, warehouse) agent add a block of rules after the read rule, so blocks above
  still win.
- **To your SIEM:** *Settings → Send to your SIEM* streams every decision to Splunk (HEC), Datadog (logs) or any HTTP
  endpoint, in batches in the background; or an OpenTelemetry collector (format `otlp`, its `/v1/logs` URL),
  as OTLP log records. Or set `SIEM_URL`, `SIEM_TOKEN`, `SIEM_FORMAT`.
- **Approve and Reject right in Slack:** in Settings, open *Approve and Reject right in Slack*, create the Slack app
  from the manifest shown there, install it to your approvals channel, and paste its webhook URL and signing secret.
  Each click is checked against the signing secret and carries that one event's signed token; the message then says
  who decided.
- Through the HTTP proxy, a held request stays open until it's decided, so the caller's HTTP
  timeout must be longer than the rule's `timeout_seconds`.

## Tell, ask why, ask a person, steer

**`action: notify`** runs the action and tells the team (Slack, Teams, phone, email), at most once an hour per rule and
agent. A gentle first step for pilots: nothing is held, and people still see what happens.

```yaml
- id: tell-on-exports
  action: notify
  reason: Customer data leaves the system
  match: { name: "*export*" }
```

A sequence can notify too, which makes it an alert for unusual behaviour. The shipped `unusual-burst` tells the team
when one agent takes more than 300 actions in 15 minutes:

```yaml
sequences:
  - id: unusual-burst
    action: notify
    reason: Far more actions than usual from one agent
    match: {}
    count: { more_than: 300, within_hours: 0.25, scope: agent }
```

**`justification: required | optional`** on a rule: the agent must say why before the call runs (`required`), and
the approver reads it as *Why, says the agent*. Without one the call is blocked with a message asking for it, so the
agent calls again with a reason. Where the reason comes from: a `justification` argument (the MCP proxy offers it on
every tool, and never passes it to the app), `metadata.justification` from your own client, or the `description` of
Claude Code's Bash tool. Use `required` only on tools that can carry it (MCP tools, Bash, your own client): Claude
Code's Write or Edit can't.

**Questions from the agent (`ask_user`).** The MCP connectors give the agent an `<app>_ask_user` tool. A question
waits in the approval queue (and on Slack, Teams, phone, email) with an answer box: *Send answer* gives the agent your
words; *Decline* tells it not to guess. From Python: `answer = gw.ask("Staging or prod?")` (or
`await gw.aask(...)`); it raises `Denied` if they decline or nobody answers in time. Any other client can ask with
`POST /v1/events` and `{"kind": "question", "input": {"question": "..."}}`; the answer is the decision's
`decision_note`.

**Notes to a running agent.** *Note* next to an agent in Reports, or *send a note* next to a conversation, or
`POST /v1/notes {"agent": "..."}` / `{"session": "..."}`. The agent gets it with its next action: Claude Code as
context for its next step, MCP tools at the top of the next result, your own Python agent through
`Gateway(on_note=...)`. Cursor, Codex, Gemini CLI, VS Code and Antigravity surely read only a refusal's message, so
there the next action is refused once with the note in it, and runs when the agent tries again. A note steers; it can't approve or lift anything.
It's kept in the audit trail, with who sent it and when it was delivered. A note can be taken back until it's delivered
(`DELETE /v1/notes/{id}`).

**Stops freeze approval deadlines.** While an agent is stopped, its waiting approvals don't time out and can't be
approved (only rejected). When it's resumed they get back the time they spent frozen; a stop with a time limit gives
its whole length up front.

**Rules history.** Every version of rules.yaml that decided something is kept (with its fingerprint, which each
decision records). *Settings → Rules → History* shows what changed since any of them, and an admin can **Put back** an
earlier version (`POST /v1/policy/versions/{fingerprint}/restore`): only if it still loads, with a backup of today's
file, and in the audit trail.

**Agents across the team.** Each computer's `squidbrake doctor` tells the gateway which agents it has and which go
through Squidbrake (names only; off with `SQUIDBRAKE_NO_INVENTORY=1`). *Settings → Agents across the team* lists the
ones that don't yet.

## Undo copies, spend limits, proof of work and signed approvals

- **Undo copies (`snapshots:` in rules.yaml, default `required`).** Before an action that waits for a person, or a
  command that can't be undone, runs, Squidbrake keeps a copy of what it changes: files and git changes on the agent's
  computer (`squidbrake undo`; Claude Code's Write and Edit too), the record behind an API call through `/proxy` (read
  with a GET first), or what your `client.py` snapshot function returns
  (`@gw.guard(snapshot=lambda args: db.get_order(args["order_id"]))`). If a copy is required and can't be made, the
  action doesn't run. A rule can set `snapshot: required | best_effort | off`; `required` on a rule also blocks paths
  that can't make a copy (MCP tools). The dashboard shows each copy and how to restore it.
- **Kill switch.** *Stop agents* in the dashboard or on the phone page stops one agent, one conversation or all of them.
  Phone notifications also carry a **Stop agent** button, and the one-tap approval page a *Stop* button.
- **Spend limits (`budgets:`).** Pause an agent once it has used N model tokens (or `usd:`) in a day or month, each on
  its own or several together. Claude Code's hook reports its tokens from the transcript; other agents send them to
  `POST /v1/usage` (`gw.usage(...)`). Reports shows each limit and what's used.
- **Proof of work (`proof_checks:`).** When an agent says an action is done, Squidbrake looks in the real system (Stripe,
  GitHub, a SQL database, or any HTTP API) with read-only credentials from the gateway's environment, and records
  *confirmed* or *not actually done*; a mismatch notifies a person.
- **Approvals signed by Face ID or fingerprint.** Register a phone or laptop as a passkey (Settings, or the phone page).
  Each approval made with it is signed by the device over exactly that decision and kept in the audit trail. Settings
  can require it for every approval (rejecting never needs it).
- **Access levels.** Owner, admin, approver and viewer. Viewers see everything and change nothing; only owners make
  admins and owners, and a team always keeps one owner. Teams such as `finance` still work for `approvers: [role:finance]`.
- **AI approval briefs.** Off until an admin adds the team's own Anthropic key: a short, plain-English risk note on each
  held action, written from what the dashboard shows (redacted). Advice only.
