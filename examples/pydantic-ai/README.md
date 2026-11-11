# Pydantic AI

This example guards a [Pydantic AI](https://ai.pydantic.dev) agent's tools with `client.Gateway`
([`client.py`](../../client.py)). Pydantic AI tools are plain functions, so each function is
guarded with `gw.guard(...)` **before** it is registered on the agent:

```python
agent = Agent(model, tools=[
    Tool(guard_tool(gw, "notes.read", read_notes), name="notes.read"),
    ...
])
```

Before a tool runs, the guard posts the call to the local Squidbrake gateway:

- If the rule says **allow**, the tool runs immediately and the guard records the output and duration.
- If the rule says **review**, the call waits while a person approves or rejects it in the dashboard
  (or on a phone / Slack). If approved, the tool runs; if rejected, the tool never runs.
- If the rule says **deny**, the tool function is never called.

A stopped call does not end the run on an exception. `Denied` carries the gateway's reason, and the
guard returns the `refusal(...)` text as the tool's result — `NOT RUN: Squidbrake stopped
shell.exec: ...` — so the model reads *why* it was stopped and can tell the user, instead of the
agent crashing or silently carrying on.

## Run against a local gateway

1. Start Squidbrake with `start.bat` (Windows) or `./start.sh` (macOS/Linux). The dashboard is at
   `http://localhost:8080/dashboard`.
2. Set `GATEWAY_API_KEY` (or `SQUIDBRAKE_KEY`) to the agent key printed on first start. The URL defaults to
   `http://localhost:8080`.
3. Install the example requirements (Pydantic AI stays out of the gateway's own `requirements.txt`):

   ```bash
   pip install -r examples/pydantic-ai/requirements.txt
   ```

4. Run the demo. The default run drives the agent with a scripted model, so **no LLM API key is
   needed** — it issues the same three calls as the OpenAI Agents example, in order:

   ```powershell
   # PowerShell
   $env:GATEWAY_API_KEY="gw_..."; python examples/pydantic-ai/demo.py
   ```

   ```bash
   # macOS/Linux
   GATEWAY_API_KEY=gw_... python examples/pydantic-ai/demo.py
   ```

The three calls trigger all three outcomes in the dashboard:

- `notes.read` matches `allow-reads` and runs immediately.
- `invoice.refund` matches `approve-refunds` and waits in the dashboard for a person to approve or reject it. Approve
  it to let the refund run, or reject it with a note to see the refusal text returned to the model as the tool result.
- `shell.exec` with `rm -rf /` is blocked immediately (`block-destructive-shell`), so the function never runs.

## Run with a real model

Pass `--agent` to run the same guarded tools with a real model. Set the provider's API key
(e.g. `OPENAI_API_KEY`) and, optionally, `PYDANTIC_AI_MODEL` (default `openai:gpt-5`):

```bash
GATEWAY_API_KEY=gw_... OPENAI_API_KEY=sk-... python examples/pydantic-ai/demo.py --agent
```
