# Squidbrake usage analytics implementation cycle

Status: proposed implementation plan; this PR changes documentation only.
Baseline: upstream `302c882`, version 0.14.17, inspected on 2026-11-02.

## Outcome and scope

Give the Squidbrake team a reliable view of adoption, agent and tool usage,
activation, retention, approvals, feature adoption, reliability, and paid conversion.
Cover every supported product interaction through an explicit event catalogue.
Each cycle below is a separate, reviewable PR with acceptance criteria.

"Every data" means comprehensive product usage metadata from reporting installs.
Customer commands, prompts, source code, paths, destinations, credentials, tool
arguments/results, and audit records stay in the customer's gateway. Optional
support diagnostics use a separate, customer-authorized workflow. Hosting a gateway
does not automatically authorize copying its records into product analytics.

Offline users, disabled telemetry, modified builds, disconnected tools, and older
versions create coverage gaps. Show these limits; never claim universal visibility.
The reported 8,000 users is an unverified business input until its source is known.
Historical events that were never collected cannot be reconstructed.

## Architecture and tooling

```text
CLI / agent hooks / MCP / HTTP / dashboard
  -> customer gateway's existing operational records
  -> local allowlisted summaries + product lifecycle outbox
  -> versioned Insights ingestion API
  -> PostgreSQL: durable usage summaries, identity links, lifecycle events
  -> asynchronous PostHog exporter: selected lifecycle events
  -> Insights admin: authoritative usage and account metrics

Separately enabled, filtered diagnostics -> Sentry
```

- Keep PostHog Cloud for funnels, cohorts, retention, and feature adoption.
- Extend Insights rather than replacing its pilot/admin system. Use its existing
  PostgreSQL support for production; retain SQLite for local development.
- Keep detailed numerical tool/action rollups in PostgreSQL. PostHog receives
  lifecycle events and deduplicated active-day markers, not every snapshot upload.
- Add Sentry for reliability after payload filtering and customer controls exist.
- Defer Metabase until Insights cannot answer an identified reporting question.
- Keep analytics outside the permission decision path. Analytics outages must not
  change allow/review/deny behavior, block tools, or weaken policy enforcement.

## Current implementation and gaps

| Area | Current implementation | Change needed |
| --- | --- | --- |
| CLI usage | `telemetry.py` sends `cli_command` and optional identification directly to PostHog | Stable catalogue, successful lifecycle transitions, consistent identity and controls |
| Gateway summaries | `pilot.py` reports seven-day counts, agents, rule hits, latency and limited catches | All-decision tool/category rollups, event-time dimensions, delivery guarantees |
| Delivery cadence | v0.14.17 checks every 120 seconds; sends changes, a six-hour idle heartbeat, and a best-effort shutdown flush | Preserve useful freshness; add jitter, backoff, bounded persistence and measurement |
| Ingestion | `insights/app.py` accepts join/ping; daily snapshots replace prior daily counts | Versioned schemas, authenticated installs, ordered revisions, outbox and deduplication |
| Storage | Insights supports SQLite and PostgreSQL through `insights/pg.py` | Compatible migrations, indexes, retention, exports and restore checks |
| Identity | CLI `telemetry.json` ID and pilot `pilot.json` install ID are separate | Explicit canonical mapping without inferring a person's identity |
| Tool details | `catches` contains at most 60 recent held/blocked examples | Count all tools across allowed, held and blocked actions; label examples as samples |
| Admin reporting | `insights/admin.html` already shows pilots, community usage and health | Comparable definitions, longer cohorts, coverage and integration rankings |
| Controls | CLI/startup telemetry has environment checks; pilot delivery uses membership | One tested policy at every outbound path, including already-enrolled pilots |

## Metric contract

Use UTC event time for product metrics and ingestion time for delivery health.
Display reporting coverage, schema/version coverage, last successful upload, and
the metric definition alongside dashboards. Never silently mix the units below.

| Metric | Definition |
| --- | --- |
| Downloads | Package fetches; acquisition signal, not people or installs |
| Reporting installations | Distinct canonical installation IDs that successfully enrolled/reported |
| Active installation | At least one real action checked in the UTC day/week/month; heartbeats, CLI help and synthetic checks excluded |
| Active person | Distinct authenticated account with qualifying activity; unavailable for unidentified installations |
| Active organization | Verified organization with a linked active installation; never inferred from an email domain alone |
| Activated installation | Successful setup, confirmed connection, and first real checked action; count imported/pre-enrollment activity separately |
| Time to first action | First qualifying action time minus setup completion time; unknown if either timestamp is unavailable |
| Week-one retention | Activated cohort with qualifying activity on days 7-13 after activation / cohort members old enough to reach day 13 |
| Week-four retention | Same calculation for days 28-34; exclude immature cohorts from denominator |
| Connected vs used | Hook/config presence versus observed qualifying action; report both |
| Integration popularity | Active-install reach and total checked-action volume, shown separately |
| Review rate | Unique actions whose initial enforced policy decision was review / unique enforced actions checked |
| Human approval rate | Human approvals / (human approvals + human rejections); exclude pending and timeouts |
| Timeout rate | Timed-out reviews / completed review requests; show pending reviews separately |
| Reported false-positive rate | Actions marked legit / held-or-blocked actions in the stated cohort; also show feedback participation |
| Paying organization | Organization with verified billing state; manually recorded pilot MRR remains a separately labelled source |

An action can be held, approved, executed, and failed. These are stages, not mutually
exclusive totals. Persist initial policy decision, observe-mode would-decision,
human outcome, and execution outcome separately. Capture mode at action time;
today's gateway mode must not relabel yesterday's activity.

## Proposed data contract

Use versioned, typed payloads and a documented field allowlist. Suggested envelope:

```json
{
  "schema_version": 1,
  "batch_id": "random-uuid",
  "installation_id": "random-installation-id",
  "dataset_epoch": "random-id-for-this-gateway-dataset",
  "sent_at": "2026-11-02T12:05:00Z",
  "product_version": "0.14.17",
  "events": [],
  "rollups": []
}
```

Lifecycle events carry `event_id`, `event_name`, `occurred_at`, `recorded_at`,
catalogue version, emitter version and typed, bounded properties. No arbitrary
`metadata`, free text, nested customer input, or exception body field is accepted.

Daily action rollup key:
`installation_id + dataset_epoch + utc_day + agent_family + integration_family +
tool_category + mode + initial_decision`. A separately bounded registered tool code
may be added for known integrations; unknown/custom names map to `custom`/`other`.
Each row has an absolute count and monotonically increasing revision. Approval and
execution outcomes have distinct rollup types and explicit time bases, so later
outcomes do not overwrite the initial decision. Never sum repeated snapshots.

Keep one authorized writer per dataset epoch. A fresh gateway database gets a new
epoch; restarts preserve it. Define safe epoch rotation on cloned/restored data so
independent writers cannot overwrite or double-report one dataset. Do not hash
customer-defined names as a substitute for an allowlist: hashes can remain identifying.

Lifecycle catalogue to implement incrementally:

| Family | Event names / measurement | Safe properties |
| --- | --- | --- |
| Setup | `setup_started`, `setup_completed`, `setup_failed` | Installer/channel enum, OS family, error code |
| Connections | `agent_connected`, `agent_connection_failed`, `agent_disconnected` | Known agent family, hook/MCP/HTTP method, verified result |
| Activation | `first_action_checked`, `installation_active_day` | Action time, known agent family, mode |
| Approval features | First use / explicit dashboard interaction with approval, rejection, escalation | Channel enum and outcome; operational totals remain in rollups |
| Other features | `feature_used` for undo, sequences, stop/resume, steering, evidence/report, rule editing, budgets | Registered feature code and success/failure enum |
| Adoption changes | `mode_changed`, `product_version_changed` | Previous/new known mode or validated version |
| Reliability | Setup, hook, proxy and API failure counts | Known component and error code, duration buckets |
| Commercial | Account/organization linked, trial started, subscription changed | Opaque verified account/org ID and plan enum |

Record successful state changes where they actually complete, not merely when a
command starts. Derive operational action counts once from gateway records so
hooks, clients and proxy wrappers cannot count the same action twice. Token/spend
metrics are supported-source-only, labelled as reported/estimated, with an explicit
coverage denominator; do not imply every agent exposes model usage.

## Ordered implementation PRs

Track each cycle as not started, in progress, in review, or merged. This initial
documentation PR completes cycle 0 only; none of the runtime work below is done.

### Cycle 0 — Plan and baseline (this PR)

- [x] Inspect the actual collection, ingestion, storage and reporting paths.
- [x] Define scope, metrics, PR boundaries, acceptance checks and rollout sequence.
- [ ] Review and merge this plan before implementing the runtime cycles.

Deliverable: `cycle.md`. Validation: Markdown/link checks and `git diff --check`;
runtime tests are not required for this documentation-only change.

### Cycle 1 — Reporting controls and identity

Depends on: cycle 0. Files: `telemetry.py`, `pilot.py`, `squidbrake/cli.py`,
`server.py`, existing telemetry/pilot tests, `docs/operations.md`, `README.md`.

1. Define one reporting policy used by CLI, gateway startup, scheduled sends,
   retries, shutdown flush, PostHog export and diagnostics. Both `DO_NOT_TRACK=1`
   and `SQUIDBRAKE_TELEMETRY=0` override existing enrollments; CI remains excluded.
2. Expose clear on/off/status behavior for usage reporting. Keep prior refusals
   and pilot leave durable; disable purges pending outbound usage locally.
3. Separate anonymous product usage, optional account identification, and optional
   diagnostics settings. Document shipped defaults and any migration change.
4. Introduce canonical installation identity with a migration mapping for both
   existing IDs. Preserve existing pilot associations. Handle concurrency safely.
5. Introduce dataset epochs. Link verified account/org IDs only through explicit
   authenticated operations; unlinking preserves tenant boundaries.

Acceptance: opted-out, previously enrolled, CI, offline, restart, multi-process,
upgrade, leave/rejoin and late registration fixtures have deterministic results.
No network send occurs after disable takes effect, except any separately requested
account deletion operation. Offline disable must succeed without contacting a server.

Rollback: disable new producers and retain the ID mapping; never restore an older
sender that ignores the newly recorded opt-out.

### Cycle 2 — Typed ingestion and durable storage

Depends on: cycle 1. Files: `insights/app.py`, `insights/pg.py`,
`insights/export_to_supabase.py`, `insights/Dockerfile`, new analytics schema module
and focused tests. Include new packaged modules in `pyproject.toml` where needed.

1. Add a versioned endpoint alongside `/v1/ping`; keep old clients working.
2. Add tables for identity mappings, installation credentials, immutable lifecycle
   events, revisioned daily rollups, and transactional export outbox. Store the
   original occurrence time and server receipt time separately.
3. Use per-installation scoped reporting credentials; a public enrollment code or
   PostHog capture key is not proof of identity. Rate-limit enrollment and ingest;
   treat community counts as self-reported, not cryptographically verified users.
4. Reject unknown schema versions/fields, invalid dimensions, excessive rows,
   negative counts, oversized bodies and unreasonable timestamps. Bound request
   streams before fully buffering oversized input. Return explicit retry guidance.
5. Commit accepted records and outbox atomically. Uniqueness on lifecycle event ID;
   accept only higher rollup revisions; reject conflicting equal revisions.
6. Extend PostgreSQL SQL translation/upsert keys, schema permissions and migration
   paths, rather than assuming new SQLite statements work on PostgreSQL.

Acceptance: replay, timeout-after-commit, out-of-order revisions, forged tenant
IDs, mixed-validity batches, concurrent writers and old clients are tested on both
databases. Migrations preserve existing pilots and daily counts. Ingest acknowledges
only durable commits and does not wait for PostHog.

Rollback: turn off the new endpoint/exporter; retain additive tables and legacy
ingestion. Do not drop collected data or bypass reporting controls.

### Cycle 3 — Complete agent and tool usage summaries

Depends on: cycle 2. Files: `pilot.py`, `server.py`, `commands.py`, `taint.py`
where normalization needs existing classifications, new aggregation module/tests.

1. Define a versioned registry for known agents, integrations, tool codes and
   categories: shell, read, edit, database, deploy, payment, communication, other.
2. Aggregate all checked actions, including ordinary allowed activity. Keep raw
   customer tool/source/rule names local; map custom values to bounded categories.
3. Use action-time mode and initial decision; keep review and execution outcomes
   separate. Observe-mode would-block/would-review gets its own measurements.
4. Track confirmed connection coverage independently from actual integration use.
   Exclude demo, CI, health, onboarding probes and internal reporting activity.
5. Introduce indexed incremental aggregation or durable cursors so reporting does
   not rescan an indefinitely growing gateway database every two minutes. Reconcile
   mutations such as late approvals and feedback without duplicating initial actions.
6. Treat existing `catches` as examples, never complete incident counts. Validate
   every outbound string; do not forward custom rule reasons or error messages.

Acceptance: a labelled synthetic day with allow/review/deny, late approval,
execution failure, observe mode and multiple integrations matches expected totals.
Changed mode, repeated uploads and restart preserve historical counts. Seeded
secrets in names, reasons, paths, inputs and outputs never reach the collector.

Rollback: stop new summary production; old summary ingestion remains available.

### Cycle 4 — Reliable local delivery and lifecycle events

Depends on: cycles 2-3. Files: `telemetry.py`, `pilot.py`, `connect.py`,
`service.py`, `server.py`, hooks/proxy/client only where needed, new outbox module.

1. Persist allowlisted lifecycle records and summary revisions in a local outbox.
   Persist at observation time, before operational retention can remove source data.
2. Retry with exponential backoff and jitter; preserve IDs across retry/restart.
   Use server acknowledgments, bounded queues, bounded request sizes and timeouts.
3. Keep the existing change-aware cadence initially; jitter clients and measure
   fleet load. Never use the current two-minute upload cadence as activity events.
4. Put finite limits on disk and retries (initial proposal: 10 MB/7 days), document
   expiry behavior, and expose counts of dropped/expired records without content.
5. Emit successful setup/connect/first-action events and other registered features
   at their completion points. Link setup-attempt IDs to report failure/retry funnels.
6. Emit at most one active-day marker per installation/UTC date with a real action;
   mark historical/imported activity separately. Heartbeats measure reachability.
7. Route new CLI analytics through the collector; prevent direct legacy PostHog
   sends from double-emitting during migration. Document that old-version CLI
   events remain separate until identity mappings are available.

Acceptance: offline/reconnect, queue-full, cancellation, crash-after-send,
shutdown, network timeout, 429/5xx, invalid payload and disable-during-retry tests.
Analytics failure leaves permission outcomes unchanged. Establish a fixed workload
baseline; target <5 ms added p95 local bookkeeping and zero analytics HTTP calls in
the tool-check path. If unmet, move bookkeeping off-path before rollout.

Rollback: disable new emitters/delivery without discarding approved durable data;
disabled telemetry clears pending data and cannot be restarted by rollback.

### Cycle 5 — PostHog funnels, retention and adoption

Depends on: cycle 4. Files: Insights exporter module, configuration/docs,
packaging/container files, integration tests. Exporter is asynchronous and resumable.

1. Send selected lifecycle events and active-day markers with stable PostHog
   deduplication identifiers, original timestamps and canonical installation IDs.
2. Keep anonymous installations separate from identified people. Add explicit
   organization groups for verified teams; confirm group analytics pricing first.
3. Create setup-to-first-action funnel, time-to-value, mature-cohort retention,
   feature-adoption and agent-adoption dashboards. Version the definitions.
4. Use PostgreSQL for numerical action totals and late rollup corrections; do not
   append every replacement snapshot into PostHog and sum it as new usage.
5. Reconcile exporter counts against accepted lifecycle IDs. Handle vendor outages,
   permanent rejections and billing limits; expose missing-export coverage.

Acceptance: duplicates do not inflate supported PostHog metrics within its
documented deduplication guarantees; replay/reconciliation detects residual issues.
Late corrections remain accurate in PostgreSQL. No claim of exactly-once delivery
across the external vendor boundary. Reporting opt-out stops future export too.

Rollback: pause exporter; retain accepted source events and outbox state.

### Cycle 6 — Founder and customer-account dashboards

Depends on: cycle 5. Files: `insights/admin.html`, `insights/app.py`, reporting
queries/tests. Customer-facing account views require separate tenant-scoped APIs.

1. Add scorecards for reporting installs, active installs, activated cohorts,
   observe/enforce adoption, active verified organizations and verified paying teams.
2. Rank agents/integrations/tools by both installation reach and action volume;
   filter by date, version, mode, OS family and hosted/self-hosted deployment.
3. Show approval outcomes, wait-time distribution, reported false positives,
   recovery/sequence adoption and setup/integration failure trends.
4. Show last-upload time, missing periods, unsupported versions, taxonomy coverage,
   sample limits and reporting-only denominators. Missing telemetry is unknown,
   not proof of uninstall, churn, disablement or zero actions.
5. Make optional account journeys and organization aggregation inspectable without
   exposing another tenant. Keep private client activity out of public scoreboards.
6. For fleet latency, retain mergeable bounded histograms or label per-install
   statistics; averaging installation p95s is not a fleet p95.

Acceptance: synthetic cohorts give exact expected funnel/retention results;
reach and volume rankings differ correctly; immature cohorts are excluded;
tenant access checks, filters and labelled screenshot review pass.

Rollback: hide new panels while retaining existing pilot/community dashboards.

### Cycle 7 — Reliability diagnostics

Depends on: cycles 1 and 4. Files: optional Sentry integration/config, CLI,
gateway/hooks/Insights as appropriate, diagnostics docs and tests.

1. Add separately controlled Sentry reporting with strict event filtering and
   release/component tags. Disable automatic local variables, request bodies,
   breadcrumbs containing commands, user identity and customer paths.
2. Prefer registered failure codes/counts; scrub and test any optional stack traces.
   Keep customer audit pages out of session replay and browser autocapture.
3. Add a customer-invoked, inspect-before-send support bundle with explicit scope,
   destination, expiry and access restrictions. Do not silently attach audit data.

Acceptance: seeded-secret tests inspect actual SDK outbound envelopes, including
breadcrumbs and SDK defaults; opt-out and collector/vendor failure tests pass.

Rollback: disable/remove optional diagnostic sender; product usage keeps working.

### Cycle 8 — Retention, access and operations

Depends on: cycles 2 and 5. Files: Insights admin/auth, retention jobs, operations
docs, deletion/export tooling, backup/restore tests and deployment configuration.

1. Restrict founder analytics and identified accounts to authorized roles; audit
   administrative access, exports, identity links, credential rotation and deletion.
2. Proposed starting retention: local outbound queue 7 days/10 MB, central lifecycle
   records and installation-level rollups 13 months, temporary diagnostic bundles
   7 days. Apply expiry to every copy, including PostHog/Sentry where supported;
   validate purchased vendor retention/settings before promising these limits.
3. Add authenticated account/installation data export and deletion. Cascade identity
   maps, rollups, outboxes and vendor records; revoke reporting credentials and use
   a minimal deletion marker to prevent old queued events resurrecting deleted data.
4. Document backup expiry and restore-time reapplication of deletion markers.
   Keep deletion administration independent of ordinary analytics opt-out.
5. Monitor ingestion lag, queue depth, exporter lag, rejects, retry/drop rates,
   duplicates, storage growth and vendor spend. Set alerts and runbooks.

Acceptance: cross-tenant attempts fail; deletion survives pending retries and
restore; queue/database retention works; operators can rotate credentials, recover
from backup, and pause collection/export without changing customer policy decisions.

Rollback: pause collection/export and admin write features; preserve access and
deletion controls. Do not undo completed deletion or resurrect expired records.

### Cycle 9 — Staging, canary and production rollout

Depends on: cycles 1-8. Files: rollout docs/config, `.github/workflows/tests.yml`,
synthetic integration fixtures and targeted performance tests.

1. Run a separate staging collector and PostHog project using synthetic data.
2. Add explicit Insights PostgreSQL tests to CI; the current PostgreSQL job mainly
   exercises gateway tests and does not prove the new Insights schema works.
3. Replay setup success/failure, multiple agents, all decision types, delayed human
   decisions, feedback, undo, observe/enforce transitions and an offline restart.
4. Load-test 8,000 simulated reporters with realistic sparse/high-use cases. A
   synchronized 120-second cadence means about 67 uploads/second on average if all
   reporters change continuously, before spikes/retries. Measure actual payload
   sizes, query cost, idle behavior and PostHog event volume; use jitter.
5. Start with team-owned installs, then an explicitly recruited reporting cohort;
   compare local reference counts, collector totals and PostHog lifecycle counts.
6. Proposed gates: zero seeded-content leaks; exact synthetic source/rollup totals;
   >99% accepted batches within 10 minutes while online; no statistically material
   permission-path regression against the cycle-4 baseline. Record the workload,
   sample sizes, vendor lag and any dropped data. These are targets, not claims.
7. Expand gradually using server-side cohort controls. Do not remotely enable
   reporting on opted-out installations. Publish updated data documentation with
   the release; stop rollout if counts diverge or enforcement changes.

Acceptance: staging evidence, migration/restore results, latency/load measurements,
dashboard screenshots and a rehearsed rollback accompany the release PR.

Rollback: independently pause new producers, ingestion and exporter; preserve
legacy compatibility, opt-out, existing operational records and enforcement.

## Review and merge routine for every implementation PR

1. Branch from current upstream `main`; keep each cycle's scope explicit. Split
   a cycle further if migrations, producers and UI cannot be reviewed clearly.
2. Include the event/schema delta, migration compatibility, dashboard implication,
   acceptance evidence and rollback in the PR description.
3. Run focused tests for changed behavior, then the repository-required checks:
   `python -m pytest -q` and `python tests/e2e_business_scenario.py`. Add PostgreSQL,
   wheel installation and Insights container checks when their paths change.
4. Tests use throwaway databases and intercepted network transports. Never send
   test events to the shipped PostHog project or live pilot endpoint. Respect CI
   suppression; test explicit enabled/disabled states with fake collectors.
5. Review the actual serialized outbound payload, not only the internal dictionary.
   Use planted secrets and custom names to catch accidental data leakage.
6. Keep behavior and data migrations additive until old-client compatibility is
   demonstrated. Do not combine these changes with unrelated gateway refactors.
7. Push a review PR, wait for checks and reviewer feedback, update this checklist
   when merged, and proceed to the next dependent cycle. Deployment and merging
   remain separate from creating a PR.

## Definition of complete

- [ ] Usage metadata covers every supported interaction in the catalogue.
- [ ] All-action agent/tool rankings reconcile with synthetic source records.
- [ ] Acquisition, installs, active installs, people and organizations are distinct.
- [ ] Identity migration preserves existing pilots without fabricating people.
- [ ] Funnels, mature retention cohorts and feature adoption are inspectable.
- [ ] Both analytics paths honor disablement, deletion and tenant access controls.
- [ ] Offline delivery, duplicate/out-of-order reporting and vendor failures are tested.
- [ ] Customer work content remains outside product analytics and diagnostics defaults.
- [ ] PostgreSQL, SQLite, package/container, performance and rollout evidence is reviewed.
- [ ] Operators have a working kill switch, cost alerts, restore and rollback runbook.

## Vendor references to recheck during implementation

- [PostHog product analytics](https://posthog.com/docs/product-analytics/start-here)
- [PostHog group analytics and separate billing](https://posthog.com/docs/product-analytics/group-analytics)
- [PostHog pricing and billing limits](https://posthog.com/pricing)

The current published analytics allowance is 1 million events/month; confirm it
again when configuring production. As a planning example, 8,000 installations
each emitting one active-day marker daily produce 240,000 events in 30 days, before
lifecycle events. Ten emitted events per install/day would produce 2.4 million.
These are event-budget scenarios, not a claim that every installation is active.
