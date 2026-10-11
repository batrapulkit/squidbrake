import { guard } from "./guard.ts";

const gateway = {
  url: process.env.SQUIDBRAKE_URL ?? "http://localhost:8080",
  key: process.env.SQUIDBRAKE_KEY ?? "",
  sessionId: "typescript-demo",
};

const readNotes = guard("notes.read", gateway, async (topic: string) => {
  return `Notes about ${topic}`;
});

const refund = guard("invoice.refund", gateway, async (invoiceId: string) => {
  return `Refunded ${invoiceId}`;
});

const deleteEverything = guard("shell.exec", gateway, async (command: string) => {
  return `Ran ${command}`;
});

console.log("Allowed:", await readNotes("the release"));

try {
  console.log("Approved:", await refund("inv_demo_123"));
} catch (error) {
  console.error("Refund did not run:", error);
}

try {
  await deleteEverything("rm -rf /");
} catch (error) {
  console.error("Blocked:", error);
}
