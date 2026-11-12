// Checks the website's "What would Squidbrake do?" preview (insights/site/assets/try.js) against the real engine.
// tests/site_try_expected.jsonl holds the engine's answers (one {"cmd","decision","rule"} per line). To refresh it, run a
// gateway with the shipped rules.yaml and send each cmd as {"name": "Bash", "input": {"command": cmd}} to /v1/events.
// Run: node tests/site_try_parity.mjs
import { readFileSync } from "node:fs";
import vm from "node:vm";

const root = new URL("..", import.meta.url);
const noop = () => {};
const ctx = { window: {}, location: { pathname: "/" }, localStorage: null,
  document: { readyState: "loading", addEventListener: noop, head: { appendChild: noop }, createElement: () => ({}) } };
vm.runInNewContext(readFileSync(new URL("insights/site/assets/try.js", root), "utf8"), ctx);
const check = ctx.window.squidbrakeTryCheck;
const verdict = { run: "allow", ask: "review", stop: "deny" };

let bad = 0;
const lines = readFileSync(new URL("tests/site_try_expected.jsonl", root), "utf8").split("\n").filter(Boolean);
for (const line of lines) {
  const want = JSON.parse(line), got = check(want.cmd);
  // The preview only needs the same outcome and the same rule; command checks share one rule id per kind.
  if (verdict[got[0]] !== want.decision || got[1] !== want.rule) {
    bad++;
    console.log(`MISMATCH  ${want.cmd}\n  engine:  ${want.decision} ${want.rule}\n  preview: ${verdict[got[0]]} ${got[1]}`);
  }
}
console.log(`${lines.length - bad}/${lines.length} match`);
process.exit(bad ? 1 : 0);
