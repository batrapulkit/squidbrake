import { generateText, isStepCount, tool, type LanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import { guard } from "../typescript/guard.ts";

const gateway = {
  url: process.env.SQUIDBRAKE_URL ?? "http://localhost:8080",
  key: process.env.SQUIDBRAKE_KEY ?? "",
  source: "vercel-ai-sdk-example",
  sessionId: "vercel-ai-sdk-demo",
};

// Each guarded function only runs after the gateway allows the call.
const readNotes = guard("notes.read", gateway, async (input: { topic: string }) => {
  return `Release notes for ${input.topic}: all checks green.`;
});

const refundInvoice = guard("invoice.refund", gateway, async (input: { invoiceId: string; amount: number }) => {
  return `Refunded $${input.amount.toFixed(2)} on ${input.invoiceId}.`;
});

const runShell = guard("shell.exec", gateway, async (input: { command: string }) => {
  return `Ran ${input.command}`;
});

// A denial or an unreachable gateway comes back as a tool result, so the model
// sees why the action didn't happen and the run keeps going.
async function orRefusal(call: () => Promise<string>): Promise<string> {
  try {
    return await call();
  } catch (error) {
    return `NOT RUN: ${error instanceof Error ? error.message : String(error)}`;
  }
}

const tools = {
  readNotes: tool({
    description: "Read the internal release notes for a topic.",
    inputSchema: z.object({ topic: z.string() }),
    execute: (input) => orRefusal(() => readNotes(input)),
  }),
  refundInvoice: tool({
    description: "Refund an amount on a customer invoice.",
    inputSchema: z.object({ invoiceId: z.string(), amount: z.number() }),
    execute: (input) => orRefusal(() => refundInvoice(input)),
  }),
  runShell: tool({
    description: "Run a shell command on the server.",
    inputSchema: z.object({ command: z.string() }),
    execute: (input) => orRefusal(() => runShell(input)),
  }),
};

const plannedCalls = [
  { toolName: "readNotes", input: { topic: "v0.15 rollout" } },
  { toolName: "refundInvoice", input: { invoiceId: "inv_demo_123", amount: 42 } },
  { toolName: "runShell", input: { command: "rm -rf /" } },
];

const usage = {
  inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 0, text: 0, reasoning: 0 },
};

// Without an API key, a scripted model asks for the three tools one by one,
// then repeats the tool results back as its answer.
function scriptedModel(): LanguageModel {
  return new MockLanguageModelV4({
    doGenerate: async ({ prompt }) => {
      const results = prompt
        .filter((message) => message.role === "tool")
        .flatMap((message) => message.content)
        .filter((part) => part.type === "tool-result");

      const next = plannedCalls[results.length];
      if (next) {
        return {
          content: [
            {
              type: "tool-call",
              toolCallId: `call_${results.length + 1}`,
              toolName: next.toolName,
              input: JSON.stringify(next.input),
            },
          ],
          finishReason: { unified: "tool-calls", raw: undefined },
          usage,
          warnings: [],
        };
      }

      const summary = results
        .map((part) => {
          const output = part.output as { value?: unknown };
          return `- ${part.toolName}: ${typeof output.value === "string" ? output.value : JSON.stringify(output.value)}`;
        })
        .join("\n");
      return {
        content: [{ type: "text", text: `Here is what happened:\n${summary}` }],
        finishReason: { unified: "stop", raw: undefined },
        usage,
        warnings: [],
      };
    },
  });
}

async function chooseModel(): Promise<LanguageModel> {
  if (!process.env.OPENAI_API_KEY) return scriptedModel();
  const { openai } = await import("@ai-sdk/openai");
  return openai(process.env.OPENAI_MODEL ?? "gpt-4.1-mini");
}

const result = await generateText({
  model: await chooseModel(),
  tools,
  stopWhen: isStepCount(5),
  system:
    "You are a support agent. Use one tool per step, in this order: read the notes for 'v0.15 rollout', " +
    "refund $42 on invoice 'inv_demo_123', then run 'rm -rf /' with runShell. " +
    "Then report what happened with each tool, including any reason it did not run.",
  prompt: "Run the three demo actions now.",
});

for (const step of result.steps) {
  for (const toolResult of step.toolResults) {
    console.log(`${toolResult.toolName}:`, toolResult.output);
  }
}
console.log(`\nAgent: ${result.text}`);
