# Vercel AI SDK

A small [Vercel AI SDK](https://ai-sdk.dev) agent with three tools. Each tool's `execute` calls the
[`guard`](../typescript/guard.ts) helper from the TypeScript example, so the local gateway decides whether it runs:

| Tool | Gateway name | Rule | What happens |
|---|---|---|---|
| `readNotes` | `notes.read` | `allow-reads` | Runs immediately |
| `refundInvoice` | `invoice.refund` | `approve-refunds` | Waits for approval in the dashboard |
| `runShell` (`rm -rf /`) | `shell.exec` | `block-destructive-shell` | Blocked, never runs |

## Run against a local gateway

1. Start Squidbrake with `start.bat` (Windows) or `./start.sh` (macOS/Linux). The dashboard is at
   `http://localhost:8080/dashboard`.
2. Install the example's dependencies (Node.js 22.6 or later). It was written against `ai` 7.0.169 and `zod` 4.6.
   They stay in this folder:

   ```bash
   cd examples/vercel-ai-sdk
   npm install
   ```

3. Run it with the agent key printed on first start. `SQUIDBRAKE_URL` defaults to `http://localhost:8080`.

   ```powershell
   # PowerShell
   $env:SQUIDBRAKE_KEY = "<agent-key>"
   npm start
   ```

   ```bash
   # macOS/Linux
   SQUIDBRAKE_KEY="<agent-key>" npm start
   ```

4. The run waits at `refundInvoice`. Approve it in the dashboard, or reject it with a note, then run it again to see
   the other outcome.

No API key is needed. Without `OPENAI_API_KEY`, a scripted model from `ai/test` calls the three tools in order.

## How a rejection reaches the model

When the gateway denies a call, `guard()` throws with the approver's note (or the rule's reason). The tool catches it
and returns it as the tool result, so the model can tell the user why instead of the run failing:

```
refundInvoice: NOT RUN: Squidbrake denied invoice.refund: Over the limit for this customer, check with finance
runShell: NOT RUN: Squidbrake denied shell.exec: Destructive shell command
```

If the gateway can't be reached, the tool doesn't run either.

## Use a real model

Set `OPENAI_API_KEY` to use OpenAI through `@ai-sdk/openai` (`gpt-4.1-mini` by default, or set `OPENAI_MODEL`). For
another provider, change `chooseModel()` in `agent.ts`.
