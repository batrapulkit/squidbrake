"""client.py against a real gateway: the decorator, and guard_tools for agent frameworks (shaped like LangChain tools
and OpenAI Agents SDK FunctionTools; bench-tested against the real libraries too)."""
import asyncio
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from client import Denied, Gateway  # noqa: E402


@pytest.fixture(scope="module")
def gateway():
    tmp = Path(tempfile.mkdtemp())
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "KEYS_PATH": str(tmp / "keys.json"), "DATABASE_URL": f"sqlite:///{(tmp / 'gw.db').as_posix()}",
           "RULES_PATH": str(ROOT / "rules.yaml"), "DO_NOT_TRACK": "1"}
    env.pop("GATEWAY_AUTH", None)
    env.pop("GATEWAY_API_KEYS", None)
    p = subprocess.Popen([sys.executable, "server.py", "run", "--port", str(port), "--no-browser"], cwd=ROOT, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    threading.Thread(target=lambda: [out.append(line) for line in p.stdout], daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(url + "/health")
            break
        except httpx.HTTPError:
            time.sleep(0.3)
    agent = re.search(r"agent\s+(gw_\S+)", "".join(out)).group(1)
    yield Gateway(url, agent, source="client-test", session_id="run-1")
    p.terminate()
    p.wait(10)


def test_decorator_runs_everyday_work_and_raises_on_a_block(gateway):
    ran = []

    @gateway.guard()
    def shell_exec(command: str) -> str:
        ran.append(command)
        return "ok"

    assert shell_exec("ls -la") == "ok"
    with pytest.raises(Denied) as e:
        shell_exec("rm -rf ~/")
    assert "rm -rf ~/" not in ran and e.value.event_id


class LangChainLike:                     # StructuredTool: name, func, coroutine
    def __init__(self, name, func=None, coroutine=None):
        self.name, self.func, self.coroutine = name, func, coroutine


class AgentsSdkLike:                     # FunctionTool: name, on_invoke_tool(ctx, json_string)
    def __init__(self, name, impl):
        self.name = name

        async def on_invoke_tool(ctx, raw):
            import json
            return impl(**json.loads(raw))
        self.on_invoke_tool = on_invoke_tool


def test_guard_tools_for_agent_frameworks(gateway):
    ran = []

    def shell_exec(command: str) -> str:
        """Run a command."""
        ran.append(command)
        return f"ran {command}"

    async def ashell(command: str) -> str:
        ran.append("a:" + command)
        return f"ran {command}"

    plain, lc, sdk = gateway.guard_tools([shell_exec, LangChainLike("shell_exec", shell_exec, ashell),
                                          AgentsSdkLike("shell_exec", shell_exec)], prefix="t.")
    assert plain.__name__ == "shell_exec" and plain.__doc__ == "Run a command."       # schemas come from these
    assert plain("ls") == "ran ls"
    assert plain("rm -rf ~/").startswith("NOT RUN")                                   # the model is told; no crash
    assert lc.func("ls") == "ran ls" and lc.func("rm -rf ~/").startswith("NOT RUN")
    assert asyncio.run(lc.coroutine("rm -rf ~/")).startswith("NOT RUN")
    assert asyncio.run(sdk.on_invoke_tool(None, '{"command": "git status"}')) == "ran git status"
    assert asyncio.run(sdk.on_invoke_tool(None, '{"command": "rm -rf ~/"}')).startswith("NOT RUN")  # another loop: fine
    assert not [r for r in ran if "rm -rf" in r]
    with pytest.raises(TypeError):
        gateway.guard_tools([object()])
