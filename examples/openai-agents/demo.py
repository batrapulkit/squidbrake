"""
OpenAI Agents SDK example: three function tools guarded by Squidbrake's async Gateway API (acheck / aresult).

Run the three tool calls directly against a local gateway (no OPENAI_API_KEY needed):
    python examples/openai-agents/demo.py

Or run the full OpenAI Agent loop with Runner.run (requires OPENAI_API_KEY and `pip install -r examples/openai-agents/requirements.txt`):
    python examples/openai-agents/demo.py --agent
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from client import Denied, Gateway, GatewayUnavailable, refusal  # noqa: E402

try:
    from agents import Agent, Runner, function_tool
except ImportError:
    Agent = None  # type: ignore[assignment]
    Runner = None  # type: ignore[assignment]

    def function_tool(fn: Callable | None = None, *, name_override: str | None = None):
        """Minimal FunctionTool shim when openai-agents is not installed yet."""
        def wrap(f: Callable):
            tool_name = name_override or f.__name__

            async def on_invoke_tool(_ctx: Any, raw: str) -> Any:
                kwargs = json.loads(raw) if raw else {}
                res = f(**kwargs)
                return await res if asyncio.iscoroutine(res) else res

            f.name = tool_name  # type: ignore[attr-defined]
            f.on_invoke_tool = on_invoke_tool  # type: ignore[attr-defined]
            return f

        return wrap(fn) if fn is not None else wrap


def guard_function_tool(gw: Gateway, tool: Any, *, name: str | None = None) -> Any:
    """Guard an OpenAI Agents SDK FunctionTool using Gateway.acheck and Gateway.aresult."""
    tool_name = name or getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    original = getattr(tool, "_raw_on_invoke_tool", tool.on_invoke_tool)
    tool._raw_on_invoke_tool = original

    async def invoke(ctx: Any, raw: str) -> Any:
        try:
            args = json.loads(raw) if raw else {}
        except ValueError:
            args = {"input": raw}
        try:
            event_id = await gw.acheck(tool_name, args)
        except (Denied, GatewayUnavailable) as exc:
            return refusal(exc)
        started = time.perf_counter()
        try:
            output = await original(ctx, raw)
        except Exception as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            await gw.aresult(event_id, error=f"{type(exc).__name__}: {exc}", duration_ms=duration_ms)
            raise
        duration_ms = (time.perf_counter() - started) * 1000
        await gw.aresult(event_id, output=output, duration_ms=duration_ms)
        return output

    tool.on_invoke_tool = invoke
    return tool


@function_tool(name_override="notes.read")
async def read_notes(topic: str) -> str:
    """Look up internal release notes for a topic."""
    return f"Release notes for {topic}: all checks green."


@function_tool(name_override="invoice.refund")
async def refund_invoice(invoice_id: str, amount: float) -> str:
    """Issue a refund for an invoice."""
    return f"Refunded ${amount:.2f} on {invoice_id}."


@function_tool(name_override="shell.exec")
async def run_shell(command: str) -> str:
    """Execute a shell command."""
    return f"Executed: {command}"


def build_tools(gw: Gateway) -> list[Any]:
    return [
        guard_function_tool(gw, read_notes, name="notes.read"),
        guard_function_tool(gw, refund_invoice, name="invoice.refund"),
        guard_function_tool(gw, run_shell, name="shell.exec"),
    ]


async def run_direct(gw: Gateway) -> None:
    tools = {t.name: t for t in build_tools(gw)}

    allowed = await tools["notes.read"].on_invoke_tool(None, json.dumps({"topic": "v0.15 rollout"}))
    print("Allowed:", allowed)

    approved_or_refused = await tools["invoice.refund"].on_invoke_tool(
        None, json.dumps({"invoice_id": "inv_demo_123", "amount": 42.0})
    )
    print("Review outcome:", approved_or_refused)

    blocked = await tools["shell.exec"].on_invoke_tool(None, json.dumps({"command": "rm -rf /"}))
    print("Blocked:", blocked)


async def run_agent(gw: Gateway) -> None:
    if Agent is None or Runner is None:
        raise RuntimeError("Install openai-agents first: pip install -r examples/openai-agents/requirements.txt")
    agent = Agent(
        name="SupportAgent",
        instructions=(
            "You are a support agent. First read the notes for 'v0.15 rollout', "
            "then refund $42 on invoice 'inv_demo_123', and finally run 'rm -rf /' with shell.exec. "
            "Report what happened for each tool call."
        ),
        tools=build_tools(gw),
    )
    result = await Runner.run(
        agent,
        "Run the three demo actions now and summarize what succeeded or was stopped.",
    )
    print(result.final_output)


async def main() -> None:
    url = os.getenv("GATEWAY_URL") or os.getenv("SQUIDBRAKE_URL") or "http://localhost:8080"
    api_key = os.getenv("GATEWAY_API_KEY") or os.getenv("SQUIDBRAKE_KEY") or ""
    gw = Gateway(url, api_key=api_key, source="openai-agents-example", session_id="openai-agents-demo")
    if "--agent" in sys.argv[1:]:
        await run_agent(gw)
    else:
        await run_direct(gw)


if __name__ == "__main__":
    asyncio.run(main())
