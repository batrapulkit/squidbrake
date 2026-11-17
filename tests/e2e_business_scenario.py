"""
End-to-end business scenario: an AI support agent works Acme's inbox through the gateway proxy.
Run:  .venv\\Scripts\\python tests\\e2e_business_scenario.py   (starts its own gateway on port 8096, own temp data)
"""
import asyncio, json, os, re, subprocess, sys, tempfile, threading, time
from pathlib import Path
import httpx

HERE = Path(__file__).resolve().parent.parent  # the project folder
T = Path(tempfile.mkdtemp())
PY = sys.executable
URL = "http://127.0.0.1:8096"
env = {**os.environ, "KEYS_PATH": str(T / "keys.json"), "DATABASE_URL": f"sqlite:///{(T / 'gw.db').as_posix()}"}
srv = subprocess.Popen([PY, "server.py", "run", "--port", "8096", "--no-browser"], cwd=HERE, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
out = []
threading.Thread(target=lambda: [out.append(l) for l in srv.stdout], daemon=True).start()
ok = lambda cond, label: print(("PASS " if cond else "FAIL ") + label, flush=True) or cond
results = []
try:
    for _ in range(60):
        try: httpx.get(URL + "/health"); break
        except Exception: time.sleep(0.3)
    banner = "".join(out)
    admin = re.search(r"admin\s+(gw_\S+)", banner).group(1); agent = re.search(r"agent\s+(gw_\S+)", banner).group(1)
    A = {"X-Gateway-Key": admin}

    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    penv = {**os.environ, "GATEWAY_URL": URL, "GATEWAY_API_KEY": agent, "GATEWAY_SOURCE": "support-agent",
            "APPROVAL_WAIT": "2", "ACME_STATE": str(T / "acme.json"), "GATEWAY_PENDING_DIR": str(T / "pending"),
            "DB_PATH": str(T / "shop.db")}
    params = StdioServerParameters(command=PY, args=[str(HERE / "gateway_proxy.py"), "--app", "acme", "--", PY, str(HERE / "demo_apps_mcp.py")], env=penv)
    text = lambda r: "\n".join(c.text for c in r.content)
    eid_of = lambda r: re.search(r'event_id="([^"]+)"', text(r)).group(1)

    async def flow():
        async with Client(params) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            results.append(ok({"acme_check_approval", "acme_recent_decisions", "payments_transfer"} <= names, "proxy lists app tools + gateway tools"))
            async with Client(StdioServerParameters(command=PY, args=[str(HERE / "gateway_mcp.py")], env=penv)) as db:
                db_names = {t.name for t in (await db.list_tools()).tools}
            results.append(ok("gateway_check_approval" in db_names and not (names & db_names),
                              "no tool name clashes between connectors (Antigravity keeps one list)"))
            results.append(ok(not (await c.call_tool("inbox_list", {})).is_error, "reading the inbox runs by itself"))
            await c.call_tool("inbox_read", {"message_id": "msg_4"})
            r = await c.call_tool("payments_transfer", {"to_account": "DE44 5001 0517 5407 3249 31", "amount": 24800, "memo": "INV-7781"})
            results.append(ok(r.is_error and "history:impersonation" in text(r) and "acrne-corp.com" in text(r),
                              "scam wire after the look-alike CEO email is blocked by the gateway itself"))
            wire = httpx.get(f"{URL}/v1/events", headers=A, params={"name": "acme.payments_transfer"}).json()["events"][0]
            steps = httpx.get(f"{URL}/v1/events/{wire['id']}/context", headers=A).json()["steps"]
            results.append(ok(any("@acrne-corp.com" in (s["output"] or "") and "ceo.office@" not in (s["output"] or "") for s in steps), "the story shows the email that asked for it (sender masked, domain kept)"))

            await c.call_tool("inbox_read", {"message_id": "msg_1"})
            r = await c.call_tool("payments_refund", {"charge_id": "ch_1002", "amount": 49.0, "reason": "duplicate charge"})
            results.append(ok("WAITING FOR HUMAN APPROVAL" in text(r), "even a $49 refund waits for a person"))
            eid = eid_of(r)
            httpx.post(f"{URL}/v1/events/{eid}/approve", headers=A, json={"note": "ok, verified duplicate"})
            r = await c.call_tool("acme_check_approval", {"event_id": eid})
            results.append(ok(not r.is_error and "re_" in text(r), "approved refund is carried out"))

            r = await c.call_tool("payments_refund", {"charge_id": "ch_1002", "amount": 49.0, "reason": "duplicate charge"})
            eid2 = eid_of(r)
            ev = httpx.get(f"{URL}/v1/events/{eid2}", headers=A).json()
            results.append(ok(ev["signals"] and ev["signals"][0]["check"] == "duplicate_change", "a second refund on the same charge is flagged for the approver"))
            httpx.post(f"{URL}/v1/events/{eid2}/reject", headers=A, json={"note": "already refunded, do not refund twice"})
            r = await c.call_tool("acme_check_approval", {"event_id": eid2})
            results.append(ok(r.is_error and "do not refund twice" in text(r), "the rejection and its note reach the agent"))
            r = await c.call_tool("payments_refund", {"charge_id": "ch_1002", "amount": 49.0, "reason": "trying again"})
            ev3 = httpx.get(f"{URL}/v1/events/{eid_of(r)}", headers=A).json()
            again = next((s for s in ev3.get("signals") or [] if s["check"] == "repeat_of_rejected"), None)
            results.append(ok("WAITING FOR HUMAN APPROVAL" in text(r) and again and "do not refund twice" in again["message"],
                              "retrying a rejected action goes back to a person, with their earlier no and note"))
            httpx.post(f"{URL}/v1/events/{eid_of(r)}/reject", headers=A, json={"note": "still no"})
            r = await c.call_tool("acme_recent_decisions", {})
            results.append(ok("do not refund twice" in text(r) and "approved" in text(r), "the agent can look up past decisions and notes"))

            r = await c.call_tool("crm_add_note", {"email": "maya.chen@example.com", "note": "refunded duplicate"})
            results.append(ok("WAITING FOR HUMAN APPROVAL" in text(r), "any other change (a CRM note) waits for a person"))
            token = subprocess.run([PY, "-c", f"import server; print(server.make_link_token('{eid_of(r)}', 'admin'))"],
                                   cwd=HERE, env=env, capture_output=True, text=True).stdout.strip().splitlines()[-1]
            info = httpx.get(f"{URL}/v1/a/{token}").json()
            results.append(ok(info["context"] and info["context"][-1]["name"] == "acme.payments_refund", "the phone link shows what led to it"))

        # The agent app restarts the connector while a call waits (Antigravity does): the approval must still run, once.
        async with Client(params) as c:
            r = await c.call_tool("crm_update_plan", {"email": "liam.garcia@example.com", "plan": "pro"})
            eid3 = eid_of(r)
        httpx.post(f"{URL}/v1/events/{eid3}/approve", headers=A, json={"note": "ok"})
        async with Client(params) as c:
            r = await c.call_tool("acme_check_approval", {"event_id": eid3})
            results.append(ok(not r.is_error and httpx.get(f"{URL}/v1/events/{eid3}", headers=A).json()["status"] == "completed",
                              "an approval still runs after the connector restarted"))
            r = await c.call_tool("acme_check_approval", {"event_id": eid3})
            results.append(ok(r.is_error and "Unknown event_id" in text(r), "and it runs only once"))
    asyncio.run(flow())
    state = json.loads((T / "acme.json").read_text())
    results.append(ok(len(state["refunds"]) == 1 and not state["transfers"], "only the approved refund actually happened"))
    liam = next(c for c in state["customers"] if c["email"] == "liam.garcia@example.com")
    results.append(ok(liam["plan"] == "pro", "the change approved across the restart really happened"))
    results.append(ok(httpx.get(f"{URL}/v1/audit/verify", headers=A).json()["ok"], "audit trail intact"))
finally:
    srv.terminate(); srv.wait(10)
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
