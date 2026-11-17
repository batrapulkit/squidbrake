# TypeScript

`guard()` checks each function call with the local Squidbrake gateway before it runs. It uses only the built-in
`fetch` API. If the gateway request fails, the function is not called. A review decision is long-polled until an
approver allows or denies it, and the function's output or error is then reported to the gateway.

## Run against a local gateway

1. Start Squidbrake with `start.bat` (Windows) or `./start.sh` (macOS/Linux). The dashboard is at
   `http://localhost:8080/dashboard`.
2. Set `SQUIDBRAKE_KEY` to the agent key printed on first start. The URL defaults to `http://localhost:8080`.
3. With Node.js 22.6 or later, run this example:

   ```bash
   # PowerShell
   $env:SQUIDBRAKE_KEY = "<agent-key>"
   node --experimental-strip-types examples/typescript/demo.ts
   ```

   ```bash
   # macOS/Linux
   SQUIDBRAKE_KEY="<agent-key>" node --experimental-strip-types examples/typescript/demo.ts
   ```

The three calls use the shipped local policy:

- `notes.read` is allowed and runs immediately.
- `invoice.refund` waits for approval. Approve it in the dashboard; reject it to see the wrapper throw with the
  gateway's reason. The refund function only runs after approval.
- `shell.exec` with `rm -rf /` is blocked, so its function never runs.

Use `guard()` in your own code by passing the gateway URL and agent key, then the tool name and function to protect:

```ts
import { guard } from "./guard.ts";

const sendEmail = guard("email.send", {
  url: "http://localhost:8080",
  key: process.env.SQUIDBRAKE_KEY!,
}, async (to: string, subject: string) => {
  // Send the email here.
  return { to, subject };
});
```
