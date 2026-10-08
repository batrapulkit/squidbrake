"""MCP servers by URL on the gateway itself (mcp_hub.py): an admin adds one, any agent with a key connects to
https://<gateway>/mcp/<name>, and every call is checked and recorded as that agent."""
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


@pytest.fixture(scope="module")
def gw():
    tmp = Path(tempfile.mkdtemp())
    port, plain = free_port(), free_port()
    upstream = subprocess.Popen([PY, str(ROOT / "tests" / "plain_mcp_http.py"), str(plain), "up-secret"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = {**os.environ, "KEYS_PATH": str(tmp / "keys.json"), "DATABASE_URL": f"sqlite:///{(tmp / 'gw.db').as_posix()}",
           "RULES_PATH": str(ROOT / "rules.yaml"), "DO_NOT_TRACK": "1", "SQUIDBRAKE_MCP_COMMANDS": "1",
           "ACME_STATE": str(tmp / "acme.json"), "DB_PATH": str(tmp / "shop.db"), "APPROVAL_WAIT": "2"}
    env.pop("GATEWAY_AUTH", None)
    env.pop("GATEWAY_API_KEYS", None)
    p = subprocess.Popen([PY, "server.py", "run", "--port", str(port), "--no-browser"], cwd=ROOT, env=env,
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
    banner = "".join(out)
    admin = {"X-Gateway-Key": re.search(r"admin\s+(gw_\S+)", banner).group(1)}
    agent = re.search(r"agent\s+(gw_\S+)", banner).group(1)
    yield {"url": url, "admin": admin, "agent": agent, "plain": f"http://127.0.0.1:{plain}/mcp"}
    for proc in (p, upstream):
        proc.terminate()
        proc.wait(10)


def test_admins_add_servers_agents_cannot(gw):
    body = {"command": PY, "args": [str(ROOT / "demo_apps_mcp.py")]}
    assert httpx.put(f"{gw['url']}/v1/mcp-servers/acme", json=body,
                     headers={"X-Gateway-Key": gw["agent"]}).status_code == 403
    r = httpx.put(f"{gw['url']}/v1/mcp-servers/acme", json=body, headers=gw["admin"]).json()
    assert r["endpoint"].endswith("/mcp/acme")
    assert httpx.put(f"{gw['url']}/v1/mcp-servers/Bad Name", json=body, headers=gw["admin"]).status_code in (400, 404)


def test_any_agent_with_a_key_connects_by_url_and_is_checked_as_itself(gw):
    from mcp import Client
    text = lambda r: "\n".join(c.text for c in r.content)
    assert httpx.post(f"{gw['url']}/mcp/acme", json={}).status_code == 401              # no key, no entry

    async def flow():
        async with Client(f"{gw['url']}/mcp/acme?key={gw['agent']}") as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert {"inbox_list", "crm_add_note"} <= names
            assert not (await c.call_tool("inbox_list", {})).is_error
            r = await c.call_tool("crm_add_note", {"email": "maya.chen@example.com", "note": "hi"})
            assert "WAITING FOR HUMAN APPROVAL" in text(r)
            eid = re.search(r'event_id="([^"]+)"', text(r)).group(1)
            httpx.post(f"{gw['url']}/v1/events/{eid}/approve", headers=gw["admin"], json={"note": "ok"})
            assert not (await c.call_tool("acme_check_approval", {"event_id": eid})).is_error

    asyncio.run(flow())
    events = httpx.get(f"{gw['url']}/v1/events", headers=gw["admin"], params={"limit": 20}).json()["events"]
    mine = [e for e in events if e["name"].startswith("acme.")]
    assert {e["name"] for e in mine} >= {"acme.inbox_list", "acme.crm_add_note"}
    assert all(e["client"] == "agent" and e["source"] == "agent" for e in mine)        # recorded as the caller


def test_a_remote_server_with_its_own_auth(gw):
    from mcp import Client
    r = httpx.put(f"{gw['url']}/v1/mcp-servers/notes", headers=gw["admin"],
                  json={"url": gw["plain"], "headers": {"Authorization": "Bearer up-secret"}})
    assert r.status_code == 200 and r.json()["headers"] == ["Authorization"]
    listing = httpx.get(f"{gw['url']}/v1/mcp-servers", headers=gw["admin"]).text
    assert "up-secret" not in listing                                                   # never shown back

    async def flow():
        async with Client(f"{gw['url']}/mcp/notes?key={gw['agent']}") as c:
            assert (await c.call_tool("list_notes", {})).content[0].text == "list_notes done"
            held = await c.call_tool("delete_notes", {})                               # a change waits for a person
            return "WAITING FOR HUMAN APPROVAL" in held.content[0].text

    assert asyncio.run(flow())
    assert httpx.delete(f"{gw['url']}/v1/mcp-servers/notes", headers=gw["admin"]).json() == {"ok": True}
    assert httpx.post(f"{gw['url']}/mcp/notes?key={gw['agent']}", json={}).status_code == 404


def test_hosted_gateways_take_urls_not_commands(monkeypatch):
    sys.path.insert(0, str(ROOT))
    import mcp_hub
    monkeypatch.setattr(mcp_hub, "COMMANDS_ALLOWED", False)
    with pytest.raises(ValueError, match="self-hosted"):
        mcp_hub.check("x", {"command": "rm", "args": ["-rf", "/"]})
    assert mcp_hub.check("github", {"url": "https://api.example.com/mcp", "headers": {"Authorization": "Bearer t"}})
    for bad in ({"url": "file:///etc/passwd"}, {"url": "https://x", "headers": {"Bad Header": "v"}}, {}):
        with pytest.raises(ValueError):
            mcp_hub.check("x", bad)


def test_a_proxy_knows_whether_its_gateway_is_alive():
    sys.path.insert(0, str(ROOT))
    import gateway_proxy
    assert gateway_proxy._alive(os.getpid())
    done = subprocess.Popen([PY, "-c", "pass"])
    done.wait()
    assert not gateway_proxy._alive(done.pid)


def test_catalog_entries_are_valid_servers(gw):
    sys.path.insert(0, str(ROOT))
    import mcp_catalog
    import mcp_hub
    for app_id, a in mcp_catalog.CATALOG.items():
        assert "<TOKEN>" in a["value"] and a["source"].startswith("https://"), app_id
        mcp_hub.check(app_id, {"url": a["url"], "headers": {a["header"]: a["value"].replace("<TOKEN>", "t")}})
    r = httpx.get(f"{gw['url']}/v1/mcp-catalog", headers=gw["admin"]).json()
    assert {a["id"] for a in r["apps"]} >= {"github", "stripe", "linear", "zapier", "slack", "notion"}
    assert next(a for a in r["apps"] if a["id"] == "slack")["auth"] == "oauth" and "Vercel" in r["approved_clients_only"]
    for app_id, a in mcp_catalog.OAUTH.items():
        mcp_hub.check(app_id, {"url": a["url"], "auth": "oauth"})
    assert httpx.get(f"{gw['url']}/v1/mcp-catalog", headers={"X-Gateway-Key": gw["agent"]}).status_code == 403
