# Hosted dashboards: what the server and accounts need

For whoever deploys squidbrake.com (insights) and the hosted gateways. The code ships with each merge; these are the
pieces that live outside the code. Check each after a deploy that touches `insights/`.

## 1. provision.py restarted on new code
`provision.py` runs as the systemd unit `squidbrake-provision` and only picks up changes when restarted:
```
systemctl restart squidbrake-provision
systemctl status squidbrake-provision --no-pager | head -3     # active (running) since <after the deploy>
```
Needed for: sleeping instead of deleting (#232), per-computer app keys (#233), the admin's Container column (#235).
**Check:** the admin's pilot list shows a Container column with values within a minute. If it warns "Container info
is from N minutes ago", provision.py isn't running.

## 2. Caddy: waking a sleeping dashboard from its address
Add `deploy/caddy/hosted-wake.caddy` inside the `*.app.squidbrake.com` site block, then `caddy reload` (or reload
the Caddy container). Without it, the start link and the Squidbrake app still wake a sleeping dashboard, but opening
its address shows Caddy's 502.
**Check:** a pilot that shows "asleep" in the admin: open its dashboard address. You land on "Waking your dashboard"
and then on the dashboard.

## 3. Supabase email templates (Authentication > Emails > Templates)
`deploy/supabase/confirm-signup.html` (subject "Confirm your email for Squidbrake") and
`deploy/supabase/magic-link.html` (subject "Sign in to Squidbrake"). Both must show `{{ .Token }}`: the Squidbrake
app signs in with that 6-digit code (Email OTP Length: 6). The sign-up form stores the name as `.Data.name`.
Confirm signup goes to an address never confirmed before (new sign-ups, pilots from before Supabase or made in the
admin); Magic Link to every later sign-in.

## 4. The start page's App tab (the Squidbrake app's downloads)
Nothing to do: it shows on its own once the newest GitHub release has `squidbrake-macos-arm64.pkg` and
`squidbrake-windows-x64.msi` and is v0.14.22 or later (insights `app_downloads`, checked every 10 minutes). The
installers are attached by `native.yml` some minutes after a release is published.
`INSIGHTS_APP_DOWNLOADS=off` in the insights `.env` hides it; any other value is used as the download address.

## Environment (insights `.env`)
| Name | What |
|---|---|
| `SUPABASE_URL`, `SUPABASE_ANON_KEY` | email sign-in (sign-up, lost keys, the app). The anon key, never service_role |
| `INSIGHTS_RECLAIM_KEYS_MINUTES` (30), `INSIGHTS_RECLAIM_IDLE_HOURS` (24) | when an unused hosted dashboard goes to sleep |
| `INSIGHTS_APP_DOWNLOADS` | optional, see 4 |
