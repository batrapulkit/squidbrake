# Squidbrake Insights (squidbrake.com)

The one website: the pages people read (`/`, `/pricing`, `/docs`, `/security`, `/changelog`, from [`site/`](site)),
sign-up, the setup guides, the demo form and your admin. A visitor signs up (`/signup`, email link through Supabase
Auth), picks **on my computer** or **on our server (hosted)**, and lands on a setup guide with a checklist for that
choice.

It is also a small service for running pilots: you send a founder a link, they install Squidbrake from it, and you see whether
and how they use it, **as counts only**.

- **`/start/<code>`**: the page you send. Their install command, with their pilot code filled in. No GitHub needed.
- **`/install.ps1`, `/install.sh`**: one-line installers (pipx + `squidbrake`), which also offer to join the pilot.
- **`/admin`**: your dashboard. Create a pilot (you get a link and a message to send), then see each pilot's stage
  (link sent → opened → installed → active / gone quiet), actions per day, what was held, approved, rejected or
  blocked, which agents are connected and which rules fired.

## Hosted pilots

Tick **Hosted** when creating a pilot and the founder gets their own gateway at `https://<name>.<HOSTED_DOMAIN>`:
nothing to keep running on their laptop, approvals from their phone. Their start page shows their keys once and a
one-line command that connects Claude Code to it.

- `provision.py` runs on the server (systemd: `squidbrake-provision.service`) and is the only part that touches Docker:
  it asks Insights what to start or remove, runs one container per pilot (`sbp-<name>`, its own volume, capped memory),
  reports the keys back, and joins the gateway to its pilot so its counts show up here.
- Caddy serves `*.HOSTED_DOMAIN` with on-demand certificates, and asks `/v1/caddy/ask` first, so it only gets
  certificates for hosted pilots that exist.
- Be clear with founders: on a hosted gateway their agents' actions (commands, tool inputs and results) are stored on
  your server. The start page says so, and points to the self-hosted setup in the docs instead.

### Self-serve sign-up

Nobody approves a sign-up by hand. A hosted dashboard starts at once while one of the `HOSTED_MAX` slots is free;
otherwise the sign-up waits in line (first in, first out: `queued_at`) and starts on its own on provision.py's next
round after a slot frees up. The start page shows the place in line. You get a message either way.

So junk or abandoned sign-ups can't hold the slots, a free sign-up's dashboard that nobody uses is freed again (and you
get a message): keys not taken within `INSIGHTS_RECLAIM_KEYS_MINUTES` (30) of its start, or no agent action within
`INSIGHTS_RECLAIM_IDLE_HOURS` (24). Never one made from the admin or one that paid; `0` turns either off.

With Supabase sign-in (`SUPABASE_URL`, `SUPABASE_ANON_KEY`; see "One address", and give Supabase your own SMTP, since
its built-in sender won't reach real users) the email is proven before the dashboard starts. Without it the dashboard
starts straight away, and one address gets `INSIGHTS_HOSTED_PER_IP_DAY` (2) hosted sign-ups a day.

The start page has two steps: get your keys, then the install line with the agent key filled in; it turns green on its
own when the first agent action arrives (hosted gateways send their counts every 20 s when they change).

`/signup` offers only the hosted setup; `INSIGHTS_SIGNUP_LOCAL=1` brings back the "On my computer" choice and the
line on what we see of a local install. Keys are shown once on the start page. Someone who lost theirs signs in again
(`/signup?new_keys=1`) for new ones, at most 3 times an hour (`INSIGHTS_NEW_KEYS_PER_HOUR`); the start page link
alone is never enough. Without Supabase, make them from the admin. provision.py then makes the new keys.

### Monthly usage (for plan limits)

Admin, then **Monthly usage** (`GET /v1/admin/usage/monthly?months=6`): real actions per pilot and calendar month
(UTC). Real means something an agent did or tried: not a person's prompt, an agent's question, or the installer's
own hook check (`pilot.is_real`), from the daily counts each install sends (a hosted gateway is one). A month from a
gateway older than this count shows all its actions and is marked estimated.

## The database: your Supabase project

Set `INSIGHTS_DATABASE_URL` to the **Session pooler** connection string (Supabase > Connect; port 5432, IPv4). The
tables live in their own schema (`squidbrake`), which Supabase's public API doesn't serve, with row level security on.
Without it, everything is kept in a SQLite file (`INSIGHTS_DB`).

Moving the SQLite data over, once (stop writes first, so nothing arrives between the copy and the switch):

```bash
sudo docker compose stop insights
sudo docker compose run --rm --no-deps insights python export_to_supabase.py /data/insights.db > supabase_import.sql
# Supabase > SQL Editor > paste supabase_import.sql > Run   (or: psql "<connection string>" -f supabase_import.sql)
# add INSIGHTS_DATABASE_URL=... to .env, then:
sudo docker compose --profile https up -d --build insights
```

The file is safe to run twice (rows already there are skipped). Keep `/data/insights.db` as the backup.

## One address

`INSIGHTS_PUBLIC_URL=https://squidbrake.com` and `INSIGHTS_REDIRECT_HOSTS=pilots.squidbrake.com`: people opening a
page on the old address are sent to the same page on squidbrake.com, while installs, posted `/go/...` links and the
API keep answering there. In Supabase > Authentication > URL configuration, set the Site URL to
`https://squidbrake.com` and add `https://squidbrake.com/signup` to the redirect URLs.

## What a pilot install sends

Only after `squidbrake pilot join CODE --server URL`, which shows the list below and asks first
(see [`pilot.py`](../pilot.py)):

- Squidbrake version, OS, enforce/shadow mode, number of rules
- agent labels (e.g. `claude-code`) and how many actions each made
- per day, for the last 7 days: actions allowed, held, approved, rejected, blocked, timed out, failed, and how many
  were agents' actions (not prompts, questions or the install check)
- the ids of the rules that blocked or held things

**Never:** commands, code, files, prompts, tool inputs or outputs, keys, people's names. `squidbrake pilot leave` stops it.

## Run it

```bash
docker build -t squidbrake-insights insights/
docker run -d -p 8090:8090 -v insights-data:/data \
  -e INSIGHTS_ADMIN_KEY=$(openssl rand -hex 24) \
  -e INSIGHTS_PUBLIC_URL=https://insights.example.com \
  -e INSIGHTS_CONTACT="you@example.com" \
  squidbrake-insights
```

Put it behind HTTPS (pilot installs only send to `https://` servers).

## Pipeline (admin → Pipeline)

Every person you talk to about Squidbrake, in one place: what they said, an honest read, the next step, LOIs and money,
and their pilot's usage when they have one. See [`pipeline.py`](pipeline.py).

- **Sync:** a daily Claude task writes `contacts.json` (format: [`contacts.example.json`](contacts.example.json)) to a
  **private** repo; this service pulls it every 15 minutes and on "Sync now". Keep that file out of this public repo.
- **By hand:** "Add person" or "Edit" on any card. A field you edit by hand is kept: the sync won't overwrite it.
- **Paste a conversation:** a transcript or DM thread is read by OpenAI into a suggested update you check before saving.
  The pasted text isn't stored.

```bash
-e PIPELINE_REPO=you/your-private-pipeline-repo \
-e PIPELINE_TOKEN=github_pat_...      # fine-grained, that repo only, Contents: read-only
-e OPENAI_API_KEY=sk-...              # optional, for "Paste a conversation"
```
