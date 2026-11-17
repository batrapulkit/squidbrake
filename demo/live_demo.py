"""
A live demo: a Squidbrake gateway with a sandbox company's AI support agent at work, reset every hour.

    python demo/live_demo.py        -> opens http://localhost:8090/dashboard with a view-only key

What visitors see: the agent reads the support inbox, a scam wire is blocked, refunds wait for a person,
and a demo "manager" approves or rejects them a minute or two later, with notes the agent reads.
Visitors get a read-only key: they can look at everything but can't change anything.

Settings (environment variables, all optional):
  DEMO_PORT            port to serve on                                   default 8090
  DEMO_VIEW_KEY        the public, read-only key visitors use             default demo
  DEMO_PUBLIC_URL      how visitors reach it, used in links               default http://localhost:DEMO_PORT
  DEMO_RESET_MINUTES   start over from a clean slate this often           default 60
  DEMO_TICK_MINUTES    a new short story this often in between            default 8
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp import Client
from mcp.client.stdio import StdioServerParameters

HERE = Path(__file__).resolve().parent.parent
PY = sys.executable
PORT = int(os.getenv("DEMO_PORT", "8090"))
VIEW_KEY = os.getenv("DEMO_VIEW_KEY", "demo")
URL = f"http://127.0.0.1:{PORT}"
if os.getenv("CODESPACES") == "true":  # GitHub Codespaces: links should use the forwarded address
    _cs = f"https://{os.getenv('CODESPACE_NAME')}-{PORT}.{os.getenv('GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN', 'app.github.dev')}"
else:
    _cs = f"http://localhost:{PORT}"
PUBLIC_URL = os.getenv("DEMO_PUBLIC_URL", _cs).rstrip("/")
RESET = float(os.getenv("DEMO_RESET_MINUTES", "60")) * 60
TICK = float(os.getenv("DEMO_TICK_MINUTES", "8")) * 60


def say(msg: str) -> None:
    print(f"[demo {datetime.now():%H:%M:%S}] {msg}", flush=True)


def write_keys(path: Path) -> tuple[str, str]:
    """Keys for this round: the public read-only visitor key, plus private admin and agent keys."""
    admin, agent = "gw_" + secrets.token_urlsafe(24), "gw_" + secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc).isoformat()
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()
    path.write_text(json.dumps({"keys": {
        "manager": {"sha256": h(admin), "kind": "person", "approver": True, "roles": ["admin", "finance"], "created_at": now},
        "support-agent": {"sha256": h(agent), "kind": "agent", "approver": False, "roles": [], "created_at": now},
        "visitor": {"sha256": h(VIEW_KEY), "kind": "person", "approver": False, "roles": [], "created_at": now},
    }}))
    return admin, agent


class Round:
    """One clean demo: its own database, keys and sandbox company, thrown away at the end."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="squidbrake-demo-"))
        self.admin, self.agent = write_keys(self.tmp / "keys.json")
        self.env = {**os.environ, "KEYS_PATH": str(self.tmp / "keys.json"),
                    "DATABASE_URL": f"sqlite:///{(self.tmp / 'gw.db').as_posix()}",
                    "PUBLIC_URL": PUBLIC_URL, "READ_ONLY_KEYS": "visitor", "HOST": os.getenv("HOST", "127.0.0.1"),
                    "ROOT_REDIRECT": f"/dashboard#key={VIEW_KEY}"}
        self.A = {"X-Gateway-Key": self.admin}
        self.G = {"X-Gateway-Key": self.agent}
        self.server = None

    def start(self) -> None:
        self.server = subprocess.Popen([PY, str(HERE / "server.py"), "run", "--port", str(PORT), "--no-browser"],
                                       cwd=HERE, env=self.env)
        for _ in range(100):
            try:
                if httpx.get(URL + "/health", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        raise RuntimeError("the demo gateway didn't start")

    def stop(self) -> None:
        if self.server:
            self.server.terminate()
            try:
                self.server.wait(10)
            except subprocess.TimeoutExpired:
                self.server.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def agent_params(self, session: str) -> StdioServerParameters:
        return StdioServerParameters(
            command=PY, args=[str(HERE / "gateway_proxy.py"), "--app", "acme", "--", PY, str(HERE / "demo_apps_mcp.py")],
            env={**os.environ, "GATEWAY_URL": URL, "GATEWAY_API_KEY": self.agent, "GATEWAY_SOURCE": session,
                 "APPROVAL_WAIT": "1", "ACME_STATE": str(self.tmp / "acme.json"),
                 "GATEWAY_PENDING_DIR": str(self.tmp / "pending")})

    def event(self, name: str, input: dict, source: str, session: str, output=None) -> dict:
        """A tool call recorded straight over HTTP (how a Claude Code session shows up)."""
        d = httpx.post(URL + "/v1/events", headers=self.G, json={"name": name, "input": input, "source": source,
                                                                  "session_id": session}).json()
        if d["decision"] == "allow" and output is not None:
            httpx.post(f"{URL}/v1/events/{d['event_id']}/result", headers=self.G, json={"output": output, "duration_ms": 35})
        return d

    def decide(self, event_id: str, outcome: str, note: str) -> None:
        httpx.post(f"{URL}/v1/events/{event_id}/{outcome}", headers=self.A, json={"note": note})


def text(r) -> str:
    return "\n".join(getattr(c, "text", "") for c in r.content)


def held(r) -> str | None:
    m = re.search(r'event_id="([^"]+)"', text(r))
    return m.group(1) if m else None


async def finish(c, rnd: Round, eid: str, outcome: str, note: str, after: float) -> None:
    """The manager decides a little later; the agent then finishes (or drops) the call."""
    await asyncio.sleep(after)
    rnd.decide(eid, outcome, note)
    await c.call_tool("acme_check_approval", {"event_id": eid})


async def opening(rnd: Round) -> None:
    """The full story, right after a reset."""
    dev = "claude-code-" + secrets.token_hex(2)
    rnd.event("Read", {"file_path": "src/billing/refunds.py"}, "claude-code", dev, output={"lines": 184})
    rnd.event("Grep", {"pattern": "def issue_refund", "path": "src"}, "claude-code", dev, output={"matches": 2})
    rnd.event("Bash", {"command": "rm -rf / --no-preserve-root"}, "claude-code", dev)
    rnd.event("Bash", {"command": "git push --force origin main"}, "claude-code", dev)   # waits, then times out

    async with Client(rnd.agent_params("support-agent")) as c:
        await c.call_tool("inbox_list", {})
        await c.call_tool("inbox_read", {"message_id": "msg_2"})
        await c.call_tool("crm_find_customer", {"query": "liam.garcia@example.com"})
        r = await c.call_tool("payments_refund", {"charge_id": "ch_1003", "amount": 199.0, "reason": "cancelled within 7 days"})
        if eid := held(r):
            await finish(c, rnd, eid, "approve", "within the refund window", after=2)
        await c.call_tool("inbox_read", {"message_id": "msg_4"})
        await c.call_tool("payments_transfer", {"to_account": "DE44 5001 0517 5407 3249 31", "amount": 24800,
                                                "memo": "INV-7781"})                  # blocked: look-alike domain
        await c.call_tool("inbox_read", {"message_id": "msg_1"})
        await c.call_tool("payments_list_charges", {"customer_email": "maya.chen@example.com"})
        r = await c.call_tool("payments_refund", {"charge_id": "ch_1002", "amount": 49.0, "reason": "duplicate charge"})
        pending = []
        if eid := held(r):
            pending.append(finish(c, rnd, eid, "approve", "verified: charged twice", after=90))
        await c.call_tool("inbox_read", {"message_id": "msg_3"})
        r = await c.call_tool("email_send", {"to": "priya.patel@example.com", "subject": "Your invoice",
                                             "body": "Hi Priya, here is your invoice for September."})
        if eid := held(r):
            pending.append(finish(c, rnd, eid, "reject", "attach the PDF invoice first", after=180))
        await asyncio.gather(*pending)
        await c.call_tool("acme_recent_decisions", {})


async def tick(rnd: Round, n: int) -> None:
    """A short new story, so there's always something happening."""
    async with Client(rnd.agent_params("support-agent")) as c:
        await c.call_tool("inbox_list", {})
        await c.call_tool("inbox_read", {"message_id": "msg_1"})
        await c.call_tool("crm_find_customer", {"query": "maya.chen@example.com"})
        r = await c.call_tool("crm_add_note", {"email": "maya.chen@example.com",
                                               "note": f"Followed up on the duplicate charge (check-in #{n})"})
        if eid := held(r):
            await finish(c, rnd, eid, "approve", "fine", after=60)
        # asks for the same refund again: flagged "requested before", and the manager says no
        r = await c.call_tool("payments_refund", {"charge_id": "ch_1002", "amount": 49.0, "reason": "duplicate charge"})
        if eid := held(r):
            await finish(c, rnd, eid, "reject", "already refunded, don't refund twice", after=75)


async def run_round(rnd: Round) -> None:
    end = time.monotonic() + RESET
    await opening(rnd)
    n = 1
    while time.monotonic() + TICK < end:
        await asyncio.sleep(TICK)
        await tick(rnd, n)
        n += 1
    await asyncio.sleep(max(0.0, end - time.monotonic()))


def main() -> None:
    # The Codespaces editor task passes --codespaces-only, so opening the repo in VS Code elsewhere doesn't start it
    if "--codespaces-only" in sys.argv and os.getenv("CODESPACES") != "true":
        print("Squidbrake live demo: runs by itself only in GitHub Codespaces. Start it with: python demo/live_demo.py")
        return
    first = True
    while True:
        rnd = Round()
        try:
            rnd.start()
            say(f"ready: {PUBLIC_URL}/dashboard#key={VIEW_KEY}  (read-only; resets every {RESET / 60:.0f} min)")
            if first and not (os.getenv("IN_DOCKER") or os.getenv("CODESPACES")):  # Codespaces opens it itself
                webbrowser.open(f"{URL}/dashboard#key={VIEW_KEY}")
            first = False
            asyncio.run(run_round(rnd))
        except KeyboardInterrupt:
            break
        except Exception as e:  # keep the demo up; start over
            say(f"round failed ({type(e).__name__}: {e}); starting over")
            time.sleep(5)
        finally:
            rnd.stop()


if __name__ == "__main__":
    main()
