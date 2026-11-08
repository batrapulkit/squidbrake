# Versioned usage reporting: collector contract

Cycle 2 adds collector-side ingestion and storage to Squidbrake Insights. Existing
agents still use `/v1/pilot/join` and `/v1/ping`; this change does not switch clients
or enable additional collection. New client producers and delivery arrive in later
cycles. The reporting controls in cycle 1 must remain effective when that happens.

## Enablement and rollback

Set `INSIGHTS_REPORTING_V2=1` on the **Insights service** to enable the new protocol.
It is disabled by default. Disabling it rejects new enrollments, uploads, invitations
and credential rotations with 503 and `Retry-After: 300`. Requests already being
processed may complete. Administrator credential revocation remains available.
Legacy endpoints continue working; their existing 64 KB body limit is now checked
while reading the stream.

Startup creates additive `reporting_*` tables even when ingestion is disabled.
Rollback by disabling the protocol and keeping these tables. Do not drop collected
records or restore a customer sender that ignores saved reporting preferences.
The pending export outbox has no worker in this release: nothing is sent to PostHog.

## Enrollment and ownership

`POST /v2/reporting/enroll` accepts one of these JSON objects:

```json
{
  "schema_version": 2,
  "installation_id": "0123456789abcdef0123456789abcdef",
  "community_code": "the-community-code-from-this-insights-service"
}
```

```json
{
  "schema_version": 2,
  "installation_id": "0123456789abcdef0123456789abcdef",
  "invitation_token": "sbi_<one-time-invitation>"
}
```

The response contains `installation_id`, `reporting_token` and `provenance`.
Tokens have the form `sbr_` plus 43 URL-safe characters, are returned once, and are
stored only as SHA-256 hashes. Secret-bearing responses use `Cache-Control: no-store`.
The client must store the credential privately before using it. A repeated enrollment
cannot retrieve or replace an existing credential: it returns 409, including after
a committed enrollment whose response was lost. Administrator recovery is required.

A community code creates an unverified, **self-reported** installation. It does not
verify a person, organization, installed software, or the truth of reported counts.
It cannot link legacy IDs or enroll directly into a named pilot. An existing legacy
installation with the same ID is not automatically linked or granted access.

For a named pilot or legacy migration, an administrator calls:

`POST /v1/admin/reporting/invitations` with `X-Admin-Key` (the existing Insights
administrator key or session token), using:

```json
{
  "installation_id": "0123456789abcdef0123456789abcdef",
  "pilot_code": "private-pilot-code",
  "aliases": [
    {"kind": "pilot", "alias": "abcdef0123456789abcdef0123456789"},
    {"kind": "cli", "alias": "12345678-1234-4234-8234-123456789abc"}
  ]
}
```

The invitation is bound to that installation and pilot, expires after 24 hours,
and can be consumed once. Pilot aliases must already belong to the specified
legacy pilot. CLI aliases are an administrator's explicit migration assertion:
verify them before creating the invitation. Aliases have a global uniqueness
constraint per kind, cannot be reassigned by a client, and do not change legacy
pilot membership or historical records. `invited` provenance means administrative
enrollment, not verified person or organization membership.

For a lost or compromised credential, an administrator can rotate it with
`POST /v1/admin/reporting/installations/{installation_id}/credential`, or revoke
it with `DELETE` on the same path. Rotation returns the new token once and stops
the previous token; revocation stops all uploads with that token. Ingest checks
the credential again inside the commit transaction, so a request authenticated
before revocation cannot subsequently commit using the revoked token.
Removing the linked pilot also stops authentication; stored reporting data remains
for the separately planned retention/deletion workflow.

## Batch protocol

`POST /v2/reporting/batches` requires `Authorization: Bearer sbr_...` and this envelope:

```json
{
  "schema_version": 2,
  "batch_id": "11111111111141118111111111111111",
  "installation_id": "0123456789abcdef0123456789abcdef",
  "dataset_epoch": "22222222222242228222222222222222",
  "sent_at": "2026-11-08T12:00:00Z",
  "product_version": "0.14.17",
  "events": [{
    "event_id": "33333333333343338333333333333333",
    "event_name": "setup_completed",
    "occurred_at": "2026-11-08T11:59:00Z",
    "recorded_at": "2026-11-08T11:59:00Z",
    "catalogue_version": 1,
    "emitter_version": "0.14.17",
    "properties": {"installer": "pip", "os_family": "linux"}
  }],
  "rollups": [{
    "day": "2026-11-08",
    "agent_family": "codex",
    "integration_family": "builtin",
    "tool_category": "shell",
    "mode": "enforce",
    "kind": "initial_decision",
    "outcome": "allow",
    "would_decision": "none",
    "revision": 1,
    "count": 10
  }]
}
```

The example timestamps must be changed to the actual observation times. IDs are
32 lowercase hexadecimal characters. Event times require timezone information
and are normalized to UTC; occurrence, recording and receipt times remain distinct.
The sender retains original batch IDs, event IDs, timestamps and content across
retries, including upgrades. Never regenerate IDs just because an HTTP response
was lost.

The complete allowlist is [reporting_schema.py](../insights/reporting_schema.py).
It includes setup, connection, activation, feature use, mode and version transitions.
Properties are typed per event; unknown fields, arbitrary custom names, free text,
commands, paths, prompts, tool arguments/results and contact/account fields are
rejected. Unregistered agent/integration/category values must be normalized to
`custom` or `other` by the future producer. Commercial/account events require a
separate authoritative integration and are not accepted from this protocol.

Initial decisions, human-review outcomes and execution outcomes are different
rollup kinds with distinct valid outcomes. Observe-mode would-decisions are only
valid on observed initial decisions. Counts must be integers from 0 to 10^12;
revisions are positive signed 64-bit integers. Boolean/floating counters and
versions are rejected. A higher revision can reduce a count to correct a summary.

Each dataset epoch has one enrolled installation as its reporting writer. Another
installation cannot claim it. Replicas must coordinate their reporting identity;
independently operated cloned/restored datasets require a new epoch and an explicit
historical-data policy in the future producer.

## Acknowledgment and retry rules

A successful response is returned only after the database transaction commits.
It includes `batch_id`, `accepted_at`, `replayed`, `accepted_events`,
`duplicate_events`, `updated_rollups`, `duplicate_rollups` and `stale_rollups`.

- Same installation and batch ID, same normalized content: return the saved
  acknowledgment with `replayed: true`; do not insert more records.
- Same batch ID with changed content: 409; repair the producer rather than retrying unchanged.
- Same installation and event ID: identical content is a duplicate; changed content,
  including a changed epoch, is a 409 conflict. Event records are immutable.
- Rollup key: installation, epoch, UTC day, agent, integration, category, mode,
  kind, outcome and would-decision. Higher revision replaces the absolute count;
  lower revision is ignored. Equal revision with different content is 409.
- All records in a batch, its receipt and new lifecycle export entries commit
  together. Validation or conflict rejects the whole batch; valid rows before
  a conflict do not survive. There is no per-row partial acknowledgment.
- 401/403: fix credentials or ownership; 409: resolve identity/content conflicts;
  400/413/415/422: correct the payload. Do not blindly retry these responses.
- 429/503: retain IDs and content, respect `Retry-After`, and retry with backoff
  and jitter. After a network timeout, retry the original batch unchanged.

A previously committed batch can be retried after the normal acceptance window;
it returns its stored receipt. A new batch must have `sent_at` and event times
within 35 days and no more than five minutes in the future. Recording cannot
precede occurrence or be more than five minutes after sending. Rollup dates must
fall between 35 days ago and today in UTC. Expired never-accepted data requires
an explicit future import path; changing timestamps would falsify the metric.

## Limits, storage and operations

Bodies are bounded at 128,000 bytes while streaming, including when Content-Length
is absent or dishonest. Compression is unsupported. Batches contain at most 100
events and 200 rollups. Errors use fixed messages without echoing rejected input.

Database-backed fixed-window limits apply across workers: 20 enrollment attempts
per IP/hour, 600 ingest requests per IP/minute, and 60 per valid installation/minute.
IP bucket keys are hashed, not saved as raw addresses; expired buckets are pruned
on subsequent requests after a day. These limits do not authenticate anonymous
community activity, and shared networks may need operator tuning after measurement.
Only trust forwarded client addresses from your actual reverse proxy.

Ten additive tables hold installations, credential hashes, invitation hashes,
legacy aliases, dataset writer bindings, batch receipts, immutable lifecycle events,
latest rollups, pending exports and rate-limit buckets. The outbox contains only
accepted lifecycle metadata; rollup corrections stay in the authoritative database.
Admin controls, data retention/deletion and the PostHog worker are later cycles.
Do not point test collectors at production vendors or copy customer audit content
into these tables.

SQLite serializes ingestion through its write transaction; PostgreSQL serializes
per installation through a credential-row lock. Constraints arbitrate conflicts
between different installations, including alias and epoch ownership. Schema startup
is serialized on PostgreSQL, and already-private tables avoid unnecessary schema locks.
RLS and public-role restrictions apply to all Insights tables, including after export.

`insights/export_to_supabase.py` exports the new tables and indexes automatically.
Stop writes before exporting; protect the export as a private database backup.
Tested restore preserves credential hashes, receipts, counts and pending exports
and can be run twice without duplicating records. Configure PostgreSQL using
`INSIGHTS_DATABASE_URL` and `INSIGHTS_PG_SCHEMA` as in [Insights setup](../insights/README.md).

Tests: `pytest -q tests/test_reporting_ingest.py tests/test_reporting_export.py`.
Set `TEST_INSIGHTS_DATABASE_URL` to a disposable PostgreSQL database to run the
same collector cases on both backends and exercise SQLite-to-Postgres export.
The dedicated CI job also creates Supabase-style public roles to verify revocation.
