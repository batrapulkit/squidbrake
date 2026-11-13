"""
Pydantic AI example: three plain-function tools checked by Squidbrake's Gateway (client.py).

Pydantic AI tools are plain functions, so each one is wrapped with `gw.guard(...)` *before*
it is registered on the agent, and a call the gateway stops comes back as the tool's result
(the `refusal(...)` text, built from the reason `Denied` carries) instead of ending the run
on an exception - so the model reads why it was stopped.

Run the three tool calls through a real agent loop with a scripted model (no LLM API key
needed; `pip install -r examples/pydantic-ai/requirements.txt` first):
    python examples/pydantic-ai/demo.py

Or run it with a real model (requires the provider's API key, e.g. OPENAI_API_KEY):
    python examples/pydantic-ai/demo.py --agent
"""
from __future__ import annotations

import functools
import os
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from client import Denied, Gateway, GatewayUnavailable, refusal  # noqa: E402

try:
    from pydantic_ai import Agent, Tool
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
    from pydantic_ai.models.function import FunctionModel
except ImportError:  # pragma: no cover - the example's own requirements install pydantic-ai
    Agent = None  # type: ignore[assignment]


def read_notes(topic: str) -> str:
    """Look up internal release notes for a topic."""
    return f"Release notes for {topic}: all checks green."


def refund_invoice(invoice_id: str, amount: float) -> str:
    """Issue a refund for an invoice."""
    return f"Refunded ${amount:.2f} on {invoice_id}."


def run_shell(command: str) -> str:
    """Execute a shell command."""
    return f"Executed: {command}"


def guard_tool(gw: Gateway, name: str, fn: Callable) -> Callable:
    """Check a plain function with the Gateway under `name`, before it is registered as a tool.

    `gw.guard` raises `Denied` when the gateway stops a call; here that becomes the tool's
    result (the `refusal` text), so the model reads the reason and the run continues.
    """
    checked = gw.guard(name)(fn)

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return checked(*args, **kwargs)
        except (Denied, GatewayUnavailable) as exc:
            return refusal(exc)

    return wrapper


def build_agent(gw: Gateway, model: Any) -> Any:
    """The agent: the same three tools as the OpenAI Agents example, checked the same way.

    Tool names are the ones the shipped rules.yaml keys on: `notes.read` runs
    (allow-reads), `invoice.refund` waits for approval (approve-refunds), and
    `shell.exec` with a destructive command is blocked (block-destructive-shell).
    """
    return Agent(
        model,
        tools=[
            Tool(guard_tool(gw, "notes.read", read_notes), name="notes.read"),
            Tool(guard_tool(gw, "invoice.refund", refund_invoice), name="invoice.refund"),
            Tool(guard_tool(gw, "shell.exec", run_shell), name="shell.exec"),
        ],
        instructions=(
            "You are a support agent. First read the notes for 'v0.15 rollout', "
            "then refund $42 on invoice 'inv_demo_123', and finally run 'rm -rf /' with shell.exec. "
            "Report what happened for each tool call."
        ),
    )


# The demo actions, in order: (tool name, arguments). A scripted model issues exactly
# these calls, so the no-key run below exercises the same three outcomes every time.
DEMO_CALLS = [
    ("notes.read", {"topic": "v0.15 rollout"}),
    ("invoice.refund", {"invoice_id": "inv_demo_123", "amount": 42.0}),
    ("shell.exec", {"command": "rm -rf /"}),
]

_LABELS = {"notes.read": "Allowed", "invoice.refund": "Review outcome", "shell.exec": "Blocked"}


def _tool_returns(messages: list) -> list:
    return [part for message in messages for part in message.parts if isinstance(part, ToolReturnPart)]


def scripted_model() -> Any:
    """A FunctionModel that issues DEMO_CALLS in order, then summarises what the tools
    returned - including the refusal text for the call the gateway stopped."""

    def respond(messages: list, _info: Any) -> ModelResponse:
        done = _tool_returns(messages)
        if len(done) < len(DEMO_CALLS):
            name, args = DEMO_CALLS[len(done)]
            return ModelResponse(parts=[ToolCallPart(name, args)])
        lines = [f"{ret.tool_name}: {ret.content}" for ret in done]
        return ModelResponse(parts=[TextPart("Here is what happened:\n" + "\n".join(lines))])

    return FunctionModel(respond)


def run_direct(gw: Gateway) -> None:
    """Run the agent with the scripted model: no LLM key, all three gateway outcomes."""
    agent = build_agent(gw, scripted_model())
    result = agent.run_sync("Run the three demo actions now and summarize what succeeded or was stopped.")
    for ret in _tool_returns(result.all_messages()):
        print(f"{_LABELS.get(ret.tool_name, ret.tool_name)}: {ret.content}")
    print("\nAgent summary:\n" + str(result.output))


def run_agent(gw: Gateway) -> None:
    if Agent is None:
        raise RuntimeError("Install pydantic-ai first: pip install -r examples/pydantic-ai/requirements.txt")
    model = os.getenv("PYDANTIC_AI_MODEL", "openai:gpt-5")
    agent = build_agent(gw, model)
    result = agent.run_sync("Run the three demo actions now and summarize what succeeded or was stopped.")
    print(result.output)


def main() -> None:
    url = os.getenv("GATEWAY_URL") or os.getenv("SQUIDBRAKE_URL") or "http://localhost:8080"
    api_key = os.getenv("GATEWAY_API_KEY") or os.getenv("SQUIDBRAKE_KEY") or ""
    gw = Gateway(url, api_key, source="pydantic-ai-example", session_id="pydantic-ai-demo")
    if "--agent" in sys.argv[1:]:
        run_agent(gw)
    else:
        run_direct(gw)


if __name__ == "__main__":
    main()
