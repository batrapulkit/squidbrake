# Squidbrake: the control room for your company's AI agents

Every action an AI agent takes (sending an email, issuing a refund, wiring money, changing a database,
running a command) goes through Squidbrake first. It is **checked** against company rules, **held for a
person** when it's risky, **recorded** in a tamper-evident audit trail, and can be **stopped** instantly.

## Run it

- **Just watch:** `python demo/live_demo.py` runs this whole scenario by itself (a demo manager approves and
  rejects), resetting every hour. Or click *Open in Codespaces* in the README: the demo starts by itself and
  opens in a new tab (or open port 8090 from the Ports tab; it runs in the "Squidbrake live demo" terminal).
- **Try it on your PC:** `start.bat` (Windows) or `./start.sh`. It prints your keys and opens the dashboard.
- **24/7 on a server:** copy the folder to any Linux server (a free Oracle Cloud VM works) and run `bash install.sh`.
  You get `https://<your-server-ip>.sslip.io/dashboard` with HTTPS, no domain needed.
- Connect agents with `connect.bat` / `./connect.sh` (see the README).

## The dashboard

| Tab | What you do there |
|---|---|
| **Activity** | watch every agent action live; approve or reject held ones; open any action's full record |
| **Team** | add people (view / approve / admin, plus roles like `finance`) and agents; each gets its own key |
| **Reports** | per-agent activity, approvals, what was blocked, the tamper check, audit trail; CSV export and print-to-PDF |
| **Settings** | phone and Slack notifications, public address, test what a rule would do |
| **⏹ Stop agents** | blocks every agent immediately (or one agent from Reports, or one conversation from any event's details) until an admin resumes |
| **📱 Phone** | scan once; approve from your phone from then on |

## The demo scenario: an AI support agent at "Acme Inc"

Connect an agent to Acme's sandbox apps (`connect.bat wrap --sandbox --agent claude-code`, or `--agent antigravity`): a support inbox with 4 real-looking emails, CRM, email and payments.

**The policy:** agents may *look* at anything (read, list, search) on their own. Anything that *changes*
something (a refund of any size, an email, a CRM note, a database update, a shell command) waits for a person.
Before deciding, the approver sees **what led to it**: the steps the agent took just before, e.g. the email it read.

Ask the agent: **"Go through the support inbox and handle each email."** Then watch:

1. It reads the inbox and each email on its own (recorded, no approval needed)
2. Maya was charged twice → it asks to refund **$49** → **waits for you**; open *What led to this* to see Maya's email → approve
3. Liam wants **$199** back → waits for you → approve
4. Priya wants an invoice → it asks to email her → waits for you → reject with a note like "attach the PDF first";
   the agent reads your note
5. A fake "CEO" email (from `acrne-corp.com`, not `acme.com`) asks for an urgent **$24,800 wire** →
   **the gateway blocks it by itself**: *"Possible scam: this follows a message from ceo.office@acrne-corp.com,
   which imitates acme.com"*. No one even had to look.
6. If the agent tries again something you rejected → **blocked automatically**, with your note.
   A second refund on the same charge is flagged *"requested before"* for the approver.

The agent can also ask *"what did people decide before?"* (its `acme_recent_decisions` / `gateway_recent_decisions` tools) and follows the notes.

Then open **Reports** to show the audit trail, the tamper check, and download the CSV.
To replay: delete `data\sandbox\acme.json` (the sandbox resets itself).

Also try the shop database: "top 5 customers by revenue" (runs), "give team-plan customers 15% off" (waits),
"drop the orders table" (blocked).

The rules live in `rules.yaml` (see the `history_checks:` section for the "judge by what came before" checks).

## Phone approvals

- **Quick:** 📱 Phone → scan the QR code → your phone shows everything waiting, with big Approve / Reject buttons.
- **Push notifications:** Settings → Generate private topic → Save → install the free **ntfy** app → subscribe to that
  topic. Each held action pops up on your phone with Approve / Reject buttons right in the notification.
- **Slack:** Settings → paste a Slack incoming-webhook URL. Messages carry a one-tap link; Mondays get a weekly summary.

## Guard your real apps

Anything with an MCP connector (Stripe, GitHub, Gmail, Slack, Linear, Notion, databases, internal tools):

    .venv\Scripts\python connect.py wrap --agent claude-code --app stripe --env STRIPE_SECRET_KEY=sk_... -- npx -y @stripe/mcp --tools=all

Calls show up as `stripe.<tool>`, and rules in `rules.yaml` can target them (e.g. every `stripe.create_refund` → a person).

## Undo

- Claude Code: `.venv\Scripts\python connect.py claude-code --remove` (add `--project DIR` if you connected one project),
  and `claude mcp remove <name>` for MCP servers it added (e.g. `gw-acme`, `gateway-db`)
- Antigravity: remove the servers it added from `~/.gemini/antigravity/mcp_config.json` (a backup is kept next to it)
- A key: Team tab → Remove, or `.venv\Scripts\python server.py remove-key NAME`
