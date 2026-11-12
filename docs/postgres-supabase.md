# Postgres and Supabase

SQLite is the default and needs nothing. Use Postgres when the gateway runs on a server that may be replaced, or as
several replicas. Everything below works with any Postgres 13+; the Supabase steps are marked.

## Setup

1. **Install the driver** (pip doesn't by default): `pip install "squidbrake[postgres]"`. The Docker image
   (`ghcr.io/batrapulkit/squidbrake`, 0.14.5 and later) has it.
2. **Supabase: create a project for the gateway alone.** It will hold what your agents did (see
   [What is stored](../README.md#what-is-stored)); keep it apart from anything else, such as an analytics project.
3. **Supabase: run [`deploy/supabase_setup.sql`](../deploy/supabase_setup.sql)** in the SQL editor, after replacing
   `<A-LONG-RANDOM-PASSWORD>`. It makes the `squidbrake` schema, a `squidbrake_gateway` login that isn't the
   superuser, keeps the REST API's roles (`anon`, `authenticated`) out, and turns on row level security.
4. **Copy the connection string.** Supabase: Connect > **Session pooler** (port **5432**). The user is
   `squidbrake_gateway.<project-ref>` and the password is the one from step 3. `postgres://` and `postgresql://` are
   accepted as they are.
5. **Set the environment** (or `~/.squidbrake/.env`):

   ```
   DATABASE_URL=postgresql://squidbrake_gateway.<project-ref>:<password>@<pooler-host>:5432/postgres?sslmode=require
   DB_SCHEMA=squidbrake
   DB_POOL_SIZE=5            # Supabase's small plans allow few connections
   DB_MAX_OVERFLOW=5
   ```

6. **Keep the key files** (next section): put the data folder on a persistent volume, or set the secrets as
   environment variables, before the first start.
7. **First start:** `squidbrake run` (or the Docker image). It creates every table in the schema and prints an
   **admin** and an **agent** key once. Save both now.
8. **Supabase: run `deploy/supabase_setup.sql` again.** The tables exist now; it checks them too. Its last query
   should show `rowsecurity = true` on every row.
9. **Verify** that the public API can't read anything (`<anon-key>` is under Settings > API):

   ```bash
   curl -s "https://<project-ref>.supabase.co/rest/v1/events?select=id&limit=1" \
     -H "apikey: <anon-key>" -H "Authorization: Bearer <anon-key>"
   curl -s "https://<project-ref>.supabase.co/rest/v1/events?select=id&limit=1" -H "Accept-Profile: squidbrake" \
     -H "apikey: <anon-key>" -H "Authorization: Bearer <anon-key>"
   ```

   The first answers that there's no such table in `public`; the second that `squidbrake` isn't an exposed schema.
   Any rows in either answer mean something is wrong: stop and check step 3.

## Settings

| Variable | Default | What it does |
|---|---|---|
| `DATABASE_URL` | SQLite in `~/.squidbrake/data` | Where the record lives. |
| `DB_SCHEMA` | (public) | Postgres: every table in this schema, made if missing (set as each connection's `search_path`, so it needs a direct connection or a session pooler, not port 6543). Lowercase letters, digits, `_`. |
| `DB_POOL_SIZE` | 10 | Connections kept open per gateway process. |
| `DB_MAX_OVERFLOW` | 20 | Extra connections under load. |
| `DB_POOL_RECYCLE` | 1800 | Seconds before a connection is replaced (poolers close idle ones). |
| `DB_DISABLE_PREPARED` | off | `1` for a transaction pooler (Supabase port 6543, PgBouncer). |

## What the database doesn't hold: back these up too

The database has the record. These live in the gateway's data folder (`~/.squidbrake/data`, or next to `KEYS_PATH`),
or come from the environment. On a server that can be replaced, keep them on a persistent volume or set them as
secrets, **before** the first start:

| File | What it is | Lost, then | Or set |
|---|---|---|---|
| `keys.json` | every key's fingerprint (agents and people) | no agent or person can sign in; a new start makes new keys | `GATEWAY_API_KEYS`, `GATEWAY_APPROVERS` |
| `ledger.key` | signs the audit checkpoints | old checkpoints can't be checked against the new public key | `SQUIDBRAKE_LEDGER_KEY` (64 hex) |
| `secret.key` | signs approval links, masks emails | links already sent stop working | `GATEWAY_SECRET` |
| `license.key` | your paid plan | that plan's features stop | `SQUIDBRAKE_LICENSE` |
| `rules.yaml` | the policy | the shipped rules apply | `RULES_PATH` |

`integrity.json` and `pilot.json` are made again on their own. Keys from `GATEWAY_API_KEYS` can't be managed from the
dashboard's Team page; a persistent `keys.json` can.

Back up the database (Supabase does daily backups on paid plans; otherwise `pg_dump`) **and** these files, together.

## Moving a gateway that ran on SQLite

The record moves with its audit chain: `squidbrake import-sqlite` copies every table as stored, so the chain and each
action's fingerprints verify as before. Keep the data folder (keys, `ledger.key`, `secret.key`): the old checkpoints
are signed with that ledger key.

1. Stop the gateway (its agents wait, fail closed, for the minute this takes).
2. Copy `gateway.db` aside as a backup.
3. Set `DATABASE_URL` (and `DB_SCHEMA`) as above, then:
   `squidbrake import-sqlite /path/to/gateway.db`. It prints the rows per table and checks the chain; it refuses a
   database that already has a record.
4. Start the gateway with the new settings and run `squidbrake audit verify`.

## A fresh database

A gateway started on an empty database starts a new audit chain from its first entry. Records from an earlier
database can't be verified together with it: export and keep the old chain (`/v1/audit/export.json`) if you have it.
New keys are made only when there's no `keys.json` and no `GATEWAY_API_KEYS`.

## Troubleshooting

- **`prepared statement "_pg3_0" already exists`** (or does not exist): you're on a transaction pooler (port 6543).
  Use the session pooler (5432), or set `DB_DISABLE_PREPARED=1`.
- **`remaining connection slots are reserved` / `too many clients`**: lower `DB_POOL_SIZE` and `DB_MAX_OVERFLOW`; each
  gateway process opens up to their sum.
- **SSL errors**: add `?sslmode=require` to the URL. Supabase needs SSL.
- **`relation "events" does not exist` with `DB_SCHEMA` set**: a transaction pooler (port 6543) doesn't keep
  each connection's schema. Use the session pooler (5432) or a direct connection.
- **`permission denied for schema squidbrake`**: run step 3 again; the gateway's login needs `usage, create` on it.
- **`DB_SCHEMA: lowercase letters, digits and _ only`**: the name is used in SQL, so it's checked.
