"""gateway_proxy.py --serve: an MCP endpoint by URL, for agents that don't start commands (ChatGPT and claude.ai
connectors, Devin, n8n, cloud agents). Same checks as stdio; a token keeps strangers out; each connection is its
own conversation."""
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
PY = sys.executable


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_up(url: str, ok=lambda r: True, secs: float = 30) -> bool:
    end = time.time() + secs
    while time.time() < end:
        try:
            if ok(httpx.get(url, timeout=2)):
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    return False


@pytest.fixture(scope="module")
def stack():
    tmp = Path(tempfile.mkdtemp())
    gport, pport = free_port(), free_port()
    env = {**os.environ, "KEYS_PATH": str(tmp / "keys.json"), "DATABASE_URL": f"sqlite:///{(tmp / 'gw.db').as_posix()}",
           "RULES_PATH": str(ROOT / "rules.yaml"), "DO_NOT_TRACK": "1"}
    env.pop("GATEWAY_AUTH", None)
    env.pop("GATEWAY_API_KEYS", None)
    gw = subprocess.Popen([PY, "server.py", "run", "--port", str(gport), "--no-browser"], cwd=ROOT, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    threading.Thread(target=lambda: [out.append(line) for line in gw.stdout], daemon=True).start()
    assert wait_up(f"http://127.0.0.1:{gport}/health")
    banner = "".join(out)
    admin = re.search(r"admin\s+(gw_\S+)", banner).group(1)
    agent = re.search(r"agent\s+(gw_\S+)", banner).group(1)
    penv = {**os.environ, "GATEWAY_URL": f"http://127.0.0.1:{gport}", "GATEWAY_API_KEY": agent,
            "GATEWAY_SOURCE": "chatgpt", "APPROVAL_WAIT": "2", "ACME_STATE": str(tmp / "acme.json"),
            "GATEWAY_PENDING_DIR": str(tmp / "pending"), "DB_PATH": str(tmp / "shop.db")}
    proxy = subprocess.Popen([PY, "gateway_proxy.py", "--app", "acme", "--serve", f"127.0.0.1:{pport}",
                              "--token", "s3cret", "--", PY, str(ROOT / "demo_apps_mcp.py")], cwd=ROOT, env=penv,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{pport}/mcp"
    assert wait_up(url, ok=lambda r: r.status_code == 401)       # up, and refusing callers without the token
    yield {"url": url, "gateway": f"http://127.0.0.1:{gport}", "admin": {"X-Gateway-Key": admin}}
    for p in (proxy, gw):
        p.terminate()
        p.wait(10)


def test_no_token_no_entry(stack):
    assert httpx.post(stack["url"], json={}).status_code == 401
    assert httpx.post(stack["url"], json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_any_url_agent_goes_through_the_same_checks(stack):
    from mcp import Client
    text = lambda r: "\n".join(c.text for c in r.content)

    async def flow():
        async with Client(f"{stack['url']}?token=s3cret") as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert {"inbox_list", "crm_add_note", "acme_check_approval"} <= names
            assert not (await c.call_tool("inbox_list", {})).is_error                    # reads run by themselves
            r = await c.call_tool("crm_add_note", {"email": "maya.chen@example.com", "note": "hi"})
            assert "WAITING FOR HUMAN APPROVAL" in text(r)                              # a change waits for a person
            eid = re.search(r'event_id="([^"]+)"', text(r)).group(1)
            httpx.post(f"{stack['gateway']}/v1/events/{eid}/approve", headers=stack["admin"], json={"note": "ok"})
            r = await c.call_tool("acme_check_approval", {"event_id": eid})
            assert not r.is_error, text(r)

    async def stranger():
        async with Client(stack["url"]) as other:   # no token: turned away before reaching the app
            await other.list_tools()

    asyncio.run(flow())
    with pytest.raises(Exception):
        asyncio.run(stranger())
    # the first connection's calls were all recorded, under the agent's name, in one conversation of their own
    events = httpx.get(f"{stack['gateway']}/v1/events", headers=stack["admin"], params={"limit": 50}).json()["events"]
    ours = [e for e in events if e["source"] == "chatgpt"]
    assert {e["name"] for e in ours} >= {"acme.inbox_list", "acme.crm_add_note"}
    assert len({e["session_id"] for e in ours}) == 1 and ours[0]["session_id"].startswith("chatgpt-")


def test_calls_by_url_get_a_conversation_of_their_own(stack):
    events = httpx.get(f"{stack['gateway']}/v1/events", headers=stack["admin"],
                       params={"name": "acme.inbox_list", "limit": 10}).json()["events"]
    # not the process-wide fallback (chatgpt-MMDD-HHMM-xxxx): the served path picked the conversation
    assert events and all(re.fullmatch(r"chatgpt-[0-9a-f]{12}", e["session_id"]) for e in events)


class _Req:
    def __init__(self, headers, host="10.0.0.5"):
        self.headers = headers
        self.client = type("C", (), {"host": host})()


def _ctx(headers=None, session_id=None, client="chatgpt", host="10.0.0.5"):
    params = type("P", (), {"client_info": type("I", (), {"name": client})()})()
    conn = type("Conn", (), {"session_id": session_id, "client_params": params})()
    return type("Ctx", (), {"request": _Req(headers or {}, host), "session": type("S", (), {"_connection": conn})()})()


def test_which_conversation_a_call_belongs_to(monkeypatch):
    sys.path.insert(0, str(ROOT))
    import gateway_proxy as gp
    monkeypatch.setattr(gp.gw, "SOURCE", "agent")
    gp._recent.clear()
    assert gp._conversation(type("Ctx", (), {"request": None})()) is None                      # stdio
    assert gp._conversation(_ctx({"x-squidbrake-session": "run 42!"})) == "agent-run42"          # caller says
    assert gp._conversation(_ctx(session_id="abc123")) == "agent-abc123"                         # MCP session
    a, b = gp._conversation(_ctx()), gp._conversation(_ctx())
    assert a == b                                                   # same client, back to back: one conversation
    assert gp._conversation(_ctx(client="n8n")) != a                # another client: its own
    assert gp._conversation(_ctx(host="10.0.0.9")) != a             # another machine: its own
    monkeypatch.setattr(gp.time, "monotonic", lambda: 10**9)        # quiet for long enough: a new one
    assert gp._conversation(_ctx()) != a


def test_public_address_needs_a_token():
    r = subprocess.run([PY, "gateway_proxy.py", "--app", "x", "--serve", "0.0.0.0:1", "--", PY, "-c", "pass"], cwd=ROOT,
                       capture_output=True, text=True, timeout=30,
                       env={k: v for k, v in os.environ.items() if k != "SQUIDBRAKE_PROXY_TOKEN"})
    assert r.returncode != 0 and "needs a token" in r.stderr


def test_a_remote_server_that_needs_its_own_auth(stack):
    """--url with --header: the guarded server needs `Authorization: Bearer ...`. Here that server is the served proxy
    above, which turns away anyone without its token. ${VARS} come from the environment."""
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    env = {**os.environ, "GATEWAY_URL": stack["gateway"], "GATEWAY_SOURCE": "outer", "UPSTREAM_TOKEN": "s3cret",
           "DO_NOT_TRACK": "1"}
    params = StdioServerParameters(command=PY, args=[str(ROOT / "gateway_proxy.py"), "--app", "outer", "--url",
                                                     stack["url"], "--header", "Authorization: Bearer ${UPSTREAM_TOKEN}"],
                                   env=env)

    async def flow():
        async with Client(params) as c:
            return {t.name for t in (await c.list_tools()).tools}

    assert "inbox_list" in asyncio.run(flow())
