"""Apps whose MCP server signs in only with OAuth (Slack, HubSpot, Notion's hosted one...): an admin clicks Connect,
signs in to the app, and agents then reach it at /mcp/<name> with every call checked; the tokens are refreshed in time."""
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


def until(check, secs=20):
    end = time.time() + secs
    while time.time() < end:
        if check():
            return True
        time.sleep(0.25)
    return False


@pytest.fixture(scope="module")
def env():
    tmp = Path(tempfile.mkdtemp())
    port, app_port = free_port(), free_port()
    fake = subprocess.Popen([PY, str(ROOT / "tests" / "fake_oauth_mcp.py"), str(app_port), "35"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    genv = {**os.environ, "KEYS_PATH": str(tmp / "keys.json"), "DATABASE_URL": f"sqlite:///{(tmp / 'gw.db').as_posix()}",
            "RULES_PATH": str(ROOT / "rules.yaml"), "DO_NOT_TRACK": "1", "APPROVAL_WAIT": "2"}   # held calls answer fast
    genv.pop("GATEWAY_AUTH", None)
    genv.pop("GATEWAY_API_KEYS", None)
    gw = subprocess.Popen([PY, "server.py", "run", "--port", str(port), "--no-browser"], cwd=ROOT, env=genv,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    threading.Thread(target=lambda: [out.append(line) for line in gw.stdout], daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    assert until(lambda: _up(url + "/health")) and until(lambda: _up(f"http://127.0.0.1:{app_port}/stats"))
    banner = "".join(out)
    admin = {"X-Gateway-Key": re.search(r"admin\s+(gw_\S+)", banner).group(1)}
    agent = re.search(r"agent\s+(gw_\S+)", banner).group(1)
    httpx.put(f"{url}/v1/settings", headers=admin, json={"public_url": url})
    yield {"url": url, "admin": admin, "agent": agent, "app": f"http://127.0.0.1:{app_port}"}
    for p in (gw, fake):
        p.terminate()
        p.wait(10)


def _up(u):
    try:
        return httpx.get(u, timeout=2).status_code < 500
    except httpx.HTTPError:
        return False


def sign_in(env, name):
    r = httpx.post(f"{env['url']}/v1/mcp-servers/{name}/connect", headers=env["admin"], timeout=40)
    assert r.status_code == 200, r.text
    page = r.json()["authorize_url"]
    assert page and page.startswith(env["app"] + "/authorize")
    back = httpx.get(page).headers["location"]                     # the app approves and sends the browser back
    assert back.startswith(env["url"] + "/v1/mcp-oauth/callback")
    assert "Signed in" in httpx.get(back).text
    servers = lambda: {s["name"]: s for s in httpx.get(f"{env['url']}/v1/mcp-servers", headers=env["admin"]).json()["servers"]}
    assert until(lambda: servers()[name]["connected"] and str(servers()[name]["sign_in"]).startswith("connected"))


def test_sign_in_then_every_call_is_checked_and_tokens_refresh(env):
    from mcp import Client
    r = httpx.put(f"{env['url']}/v1/mcp-servers/chat", headers=env["admin"], json={"url": env["app"] + "/mcp", "auth": "oauth"})
    assert r.status_code == 200 and r.json()["auth"] == "oauth" and r.json()["connected"] is False
    assert httpx.post(f"{env['url']}/v1/mcp-servers/chat/connect",
                      headers={"X-Gateway-Key": env["agent"]}).status_code == 403   # admins sign in, not agents
    sign_in(env, "chat")
    stats = lambda: httpx.get(env["app"] + "/stats").json()
    assert stats()["registered"] == 1 and stats()["code_grants"] == 1

    async def calls(post=True):
        async with Client(f"{env['url']}/mcp/chat?key={env['agent']}") as c:
            read = (await c.call_tool("list_channels", {})).content[0].text
            held = (await c.call_tool("post_message", {"text": "hi"})).content[0].text if post else None
            return read, held

    read, held = asyncio.run(calls())
    assert read == "list_channels done" and "WAITING FOR HUMAN APPROVAL" in held    # reads run, a post waits
    time.sleep(6)                                    # the token now has under 30 s left: the proxy refreshes it first
    read, _ = asyncio.run(calls(post=False))
    assert read == "list_channels done" and stats()["refresh_grants"] >= 1 and stats()["code_grants"] == 1


def test_an_admins_own_oauth_app_skips_registration(env):
    before = httpx.get(env["app"] + "/stats").json()["registered"]
    r = httpx.put(f"{env['url']}/v1/mcp-servers/crm", headers=env["admin"],
                  json={"url": env["app"] + "/mcp", "auth": "oauth", "client_id": "my-own-app", "client_secret": "s3"})
    assert r.status_code == 200 and r.json()["own_app"] is True and "s3" not in r.text
    sign_in(env, "crm")
    assert httpx.get(env["app"] + "/stats").json()["registered"] == before          # no registration needed
    assert "s3" not in httpx.get(f"{env['url']}/v1/mcp-servers", headers=env["admin"]).text


def test_a_stray_callback_does_nothing(env):
    r = httpx.get(f"{env['url']}/v1/mcp-oauth/callback", params={"code": "x", "state": "made-up"})
    assert r.status_code == 400 and "no longer valid" in r.text
