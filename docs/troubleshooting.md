# Troubleshooting the first 10 minutes

This page covers the problems most people hit immediately after installing
Squidbrake. If a command still behaves unexpectedly, run `squidbrake doctor`
and keep its output when asking for help.

## `squidbrake` is not found after installation

**Symptom:** The installer finishes, but a new terminal says that
`squidbrake` is not recognized (Windows) or cannot be found (macOS/Linux).

**Why it happens:** The installer or `pipx` added the executable to a Scripts
or bin directory that the current terminal has not reloaded yet.

**Fix:** Close and reopen the terminal. On Windows, make sure the Python
Scripts directory is on `PATH`, then try again. If the command is still not
found, start a fresh PowerShell and run:

```powershell
python -m pip show squidbrake
```

For a pipx installation, run `pipx ensurepath`, reopen the terminal, and
retry `squidbrake setup`.

## Port 8080 is already in use

**Symptom:** Setup reports that port 8080 is already in use.

**Why it happens:** Another application, or an existing Squidbrake process,
is listening on the default gateway port.

**Fix:** Check which process owns the port. On Windows PowerShell:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen
```

On macOS/Linux:

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN
```

Stop the unrelated process, or choose another port for the gateway:

```bash
squidbrake setup --port 8090
```

Use the same port when checking the service or connecting agents. Setup also
prints the gateway URL it configured.

## Actions are blocked: “Squidbrake at ... is unreachable”

**Symptom:** An agent refuses an action with a message such as
“Squidbrake at http://127.0.0.1:8080 is unreachable or misconfigured (...)”.

**Why it happens:** Hooks fail closed when the local gateway is unavailable;
the agent action is blocked instead of bypassing the policy. Since 0.9, a rule
can set `when_unreachable: allow` for its actions, so those actions may still
run while the gateway is down; everything else remains blocked.

**Fix:** Check the gateway first:

```bash
squidbrake service status
```

If it is stopped, start it in the background:

```bash
squidbrake start --background
```

For a foreground run while diagnosing startup output, use
`squidbrake run`. Keep that terminal open, then retry the agent action.

## Codex does not use the hook

**Symptom:** `squidbrake connect status` lists Codex, but its actions do not
appear in the dashboard.

**Why it happens:** Codex requires one explicit approval before it runs a new
hook from its `/hooks` settings.

**Fix:** Check the installed connections:

```bash
squidbrake connect status
```

In Codex, open `/hooks` and approve the Squidbrake hook. Restart Codex after
approving it, then run `squidbrake connect status` again. A fresh action
should then appear in the dashboard.

## A company proxy blocks setup on Windows

**Symptom:** Package installation or a connection to a hosted gateway times
out on a company network.

**Why it happens:** The network requires outbound HTTP(S) traffic to use the
company proxy. Local gateway traffic is intentionally sent directly to
`localhost`, so the proxy must not be used for that address.

**Fix:** Ask IT for the proxy URL and set it in the current PowerShell session
before installing or checking a hosted gateway:

```powershell
$env:HTTP_PROXY="http://proxy.example:8080"
$env:HTTPS_PROXY=$env:HTTP_PROXY
$env:NO_PROXY="localhost,127.0.0.1"
```

Then retry the failed command. Do not commit proxy credentials or put them in
the repository. For a local gateway, `localhost` remains a direct connection.

## The agent is connected, but nothing appears in the dashboard

**Symptom:** `connect status` reports a connection, but new actions do not
show up in the dashboard.

**Why it happens:** Agents load hook configuration when they start. A hook
added after the agent was already open is not used until that agent is
restarted. A stale key or gateway URL can cause the same symptom.

**Fix:** Restart the affected agent first, then run the end-to-end diagnostic:

```bash
squidbrake doctor
```

Follow the suggested fix for any failed hook or gateway check and try one
small, safe action again.

## Turn off one agent or remove every connection

To stop routing one hook-based agent through Squidbrake, remove its hook:

```bash
squidbrake connect agents --agent codex --remove
```

Replace `codex` with `cursor`, `gemini-cli`, `vscode`, or `antigravity` as
needed. For Claude Code, use `squidbrake connect claude-code --remove`.

When the gateway is running on that computer, an administrator can also turn
off an individual agent from its switch in the dashboard's **Settings**.

To remove all connections installed by Squidbrake:

```bash
squidbrake connect all --remove
```

This removes Squidbrake's entries and leaves unrelated agent configuration
untouched. Restart the agents after the change.
