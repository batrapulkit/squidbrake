# Operations

The dashboard, the API, evidence for auditors, behaviour details and what usage counts are sent.

## Dashboard

Open `http://<host>:8080/dashboard` and paste your admin key (or any key made with `add-key`). It is stored
only in that browser. The page shows:

- totals per status (click a tile to filter), a calls-per-hour/day chart (hover for counts,
  click a bar to list just that hour, "View as table" for exact numbers), and the top tools
- the event list, updated every 5 s while "Live" is on. Filter by time range, search, status,
  kind, source or session. Click a source or session to filter by it. "Load older" pages back.
- the full record for any event: input, output, error, metadata, the rule that blocked it, timings
- filters are kept in the URL, so a view like `/dashboard?status=denied&range=7d` can be bookmarked or shared

### Sign in with SSO (Scale plan)

People can sign in with your identity provider (Okta, Entra ID, Google Workspace, Auth0, Keycloak or any other
OpenID Connect provider) instead of pasting a key:

1. Register an app (a web app with a client secret) with the redirect URI `<PUBLIC_URL>/sso/callback`.
2. Start the gateway with `SQUIDBRAKE_OIDC_ISSUER` (e.g. `https://acme.okta.com`), `SQUIDBRAKE_OIDC_CLIENT_ID`
   and `SQUIDBRAKE_OIDC_CLIENT_SECRET`, and `PUBLIC_URL` set.
3. Give each person a key named with their email: `python server.py add-key alice@acme.com --approver`.

The key dialog then shows *Sign in with SSO*. SSO only says who someone is. What they may do still comes from their
key, and a verified email with no person key gets nothing. A sign-in lasts 12 hours, and removing the key ends it
at once. Each sign-in is on the record (`sso.login`).

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

`squidbrake audit verify` checks the record on this gateway end to end and names the first broken link, if any.

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

**Signed checkpoints.** Every 50 entries the gateway signs the chain's fingerprint with its ledger key (Ed25519, kept in
`data/ledger.key` or `SQUIDBRAKE_LEDGER_KEY`). The public half is published, without a key, at `GET /v1/audit/public-key`.
Publish it somewhere you control (your site, your auditor's ticket); then

```bash
python verify.py squidbrake-evidence-20261001-0930.json --key <the published public key>
```

also proves the file wasn't re-chained by someone with access to the database. Approvals made with a passkey carry the
device's signature, and `verify.py` checks those too (keep `signing.py` next to `verify.py`).

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
  URL (`postgres://user:...@host`) are stored as `[REDACTED]`. Email addresses are stored as `p.redacted-3f2a9c@domain`
  (first letter, a fingerprint, the domain) and card numbers as `[card ending 4242]`
  (`SQUIDBRAKE_REDACT_PERSONAL=0` turns those two off). Rules still see the raw input. Lists, the phone page,
  notifications and AI briefs show at most `MAX_PREVIEW_CHARS` (2 KB) of any value.
- Payloads over `MAX_PAYLOAD_CHARS` are truncated in storage. Proxy responses are buffered (no streaming/SSE).
- SQLite (WAL) is fine for one machine. For several gateway replicas, set `DATABASE_URL` to Postgres.

## Tests

```bash
pip install pytest && pytest -q
python tests/e2e_business_scenario.py
```

## Usage sharing

Squidbrake sends anonymous usage **counts** to its team, and says so the first time you run `squidbrake` in a
terminal. Nothing in them is about you or your agents' work: never commands an agent ran, files, prompts, rules,
keys or the audit trail.

**Anonymous usage stats.** The command name (e.g. `doctor`, never its arguments), version, OS, Python version and
country, plus the gateway's usage counts described below (what it allowed, held and blocked). The first run also
asks, optionally, where you heard about Squidbrake (pick from a list, or Enter to skip); if you installed from a
named link, that name (`SQUIDBRAKE_REF`, e.g. `linkedin`) answers it instead. The agent hooks never send anything,
and scripts, CI and `--yes` send nothing until that first run in a terminal has happened. A gateway that starts
without one (Docker, a background service) writes the same notice to its log, then shares its counts; turn it off
before starting it with `SQUIDBRAKE_TELEMETRY=0` or `DO_NOT_TRACK=1`. `squidbrake telemetry
status` shows exactly what is sent.
**Update check.** Once a day, running `squidbrake` in a terminal asks pypi.org for the newest version number, and
the next time says if there's a newer one. That request carries nothing about you beyond the request itself; never
in hooks, scripts or CI; off with `SQUIDBRAKE_NO_UPDATE_CHECK=1` or `DO_NOT_TRACK=1`.

**Registration.** A pip install that isn't part of a named pilot asks for your name and work email the first time
you run a `squidbrake` command in a terminal, and runs the command once you've given them. They go to the
Squidbrake team once, with the names of the coding agents installed here (not with every command), so the team
knows who uses it. The agent hooks, `pilot join` and CI are never stopped. Where nobody can answer (a script, a
gateway in Docker, a service), set `SQUIDBRAKE_NAME` and `SQUIDBRAKE_EMAIL`, or register ahead with
`squidbrake register you@company.com --name "Your Name"`. Details: [`telemetry.py`](../telemetry.py).

**Usage counts.** The gateway's counts reach the team one of two ways:

- Every install, through the anonymous usage stats above.
- A pilot joins with the code they were given: `squidbrake pilot join CODE --server URL` (asks first, default no).

What is shared is usage **counts**: actions allowed, held, approved and blocked per day, how many a person marked
"this was legit", the gateway's decision time (p50 / p95 / p99 milliseconds), and which agents and rules; for each
action held or blocked, the program only (e.g. `rm`), the rule and sizes as numbers. Never commands, code, prompts or
keys. Details: [`pilot.py`](../pilot.py) and [`insights/`](../insights/).
