# OpenAI Agents SDK

This example guards OpenAI Agents SDK `@function_tool` tools with `client.Gateway` ([`client.py`](../../client.py))
using the async calls (`acheck` and `aresult`).

Before a tool runs, `await gw.acheck(name, args)` posts the call to the local Squidbrake gateway:

- If the rule says **allow**, the tool runs immediately and `await gw.aresult(...)` records the output and duration.
- If the rule says **review**, `acheck` waits while a person approves or rejects the call in the dashboard (or on a
  phone / Slack). If approved, the tool runs; if rejected, `Denied` is caught and returned as a `"NOT RUN: ..."` tool
  message so the agent sees the rejection reason instead of crashing the run.
- If the rule says **deny**, `acheck` raises `Denied` right away and the tool function is never called.

You can also guard a list of OpenAI Agents SDK `FunctionTool` objects in one line with `gw.guard_tools(tools)`.

## Run against a local gateway

1. Start Squidbrake with `start.bat` (Windows) or `./start.sh` (macOS/Linux). The dashboard is at
   `http://localhost:8080/dashboard`.
2. Set `GATEWAY_API_KEY` (or `SQUIDBRAKE_KEY`) to the agent key printed on first start. The URL defaults to
   `http://localhost:8080`.
3. Install the example requirements in a virtual environment (optional if you only run the direct tool demo):

   ```bash
   pip install -r examples/openai-agents/requirements.txt
   ```

4. Run the demo to fire all three tool calls against the shipped `rules.yaml`:

   ```powershell
   # PowerShell
   $env:GATEWAY_API_KEY = "<agent-key>"
   python examples/openai-agents/demo.py
   ```

   ```bash
   # macOS/Linux
   GATEWAY_API_KEY="<agent-key>" python examples/openai-agents/demo.py
   ```

The three calls trigger all three outcomes in the dashboard:

- `notes.read` matches `allow-reads` and runs immediately.
- `invoice.refund` matches `approve-refunds` and waits in the dashboard for a person to approve or reject it. Approve
  it to let the refund run, or reject it with a note to see the refusal message returned to the agent.
- `shell.exec` with `rm -rf /` is blocked immediately (`block-destructive-shell`), so the function never runs.

## Run with the full OpenAI Agent loop

With `OPENAI_API_KEY` set and `openai-agents` installed, pass `--agent` to run the guarded tools inside `Runner.run`:

```bash
GATEWAY_API_KEY="<agent-key>" OPENAI_API_KEY="sk-..." python examples/openai-agents/demo.py --agent
```
