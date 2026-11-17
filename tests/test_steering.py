"""Steering a running agent and seeing the whole team: notify-only rules, a reason the agent must give, questions an
agent asks a person, notes a person sends an agent, approval deadlines frozen while an agent is stopped, and the
computers whose agents don't go through Squidbrake yet."""
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import siem  # noqa: E402
from test_server import BOSS, H, c, server  # noqa: E402,F401

RULES = """
default: allow
history_checks: { repeat_of_rejected: off, impersonation: off, payment_request_in_message: off, duplicate_change: off }
rules:
  - id: tell-on-exports
    action: notify
    reason: customer data leaves
    match: { name: "crm.export*" }
  - id: refunds-say-why
    action: review
    justification: required
    reason: money out
    match: { name: "pay.refund*" }
  - id: deploys
    action: review
    reason: production
    match: { name: "deploy.*" }
"""


@pytest.fixture()
def rules(monkeypatch, tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(RULES, encoding="utf-8")
    monkeypatch.setattr(server, "policy", server.Policy(path))
    server.policy._maybe_reload()
    return path


def agent():
    return f"steer-{uuid.uuid4().hex[:12]}"


def post(c, name, inp=None, **kw):
    r = c.post("/v1/events", headers=H, json={"name": name, "input": inp or {}, **kw})
    assert r.status_code == 200, r.text
    return r.json()


# ---- notify: it runs, and the team hears about it (once an hour per rule and agent)

def test_notify_rule_runs_and_tells_the_team_once(c, rules, monkeypatch):
    sent = []
    monkeypatch.setattr(server, "notify_text", lambda title, text: sent.append((title, text)))
    monkeypatch.setattr(server.threading, "Thread", lambda target, args=(), daemon=None, **kw:
                        type("T", (), {"start": lambda self: target(*args)})())
    who = agent()
    d = post(c, "crm.export_contacts", {"list": "all"}, source=who)
    assert d["decision"] == "allow" and d["rule_id"] == "tell-on-exports"
    post(c, "crm.export_contacts", {"list": "vip"}, source=who)
    mine = [m for m in sent if who in m[0]]      # other tests' background threads may notify too
    assert len(mine) == 1 and "only tells you" in mine[0][1]


def test_notify_sequence_alerts_on_a_burst_and_holds_nothing(c, rules, monkeypatch):
    rules.write_text(RULES + """
sequences:
  - id: burst
    action: notify
    reason: unusual burst
    match: { name: "crm.lookup*" }
    count: { more_than: 3, within_hours: 1, scope: agent }
""", encoding="utf-8")
    server.policy._maybe_reload()
    sent = []
    monkeypatch.setattr(server, "notify_text", lambda title, text: sent.append((title, text)))
    monkeypatch.setattr(server.threading, "Thread", lambda target, args=(), daemon=None, **kw:
                        type("T", (), {"start": lambda self: target(*args)})())
    who = agent()
    for _ in range(3):
        post(c, "crm.lookup", source=who)
    assert not [m for m in sent if who in m[0]]
    d = post(c, "crm.lookup", source=who)
    assert d["decision"] == "allow"
    mine = [m for m in sent if who in m[0]]
    assert len(mine) == 1 and "unusual burst" in mine[0][1] and "sequence:burst" in mine[0][1]


def test_notify_is_a_valid_action_but_not_a_default(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("default: notify\nrules: []\n", encoding="utf-8")
    pol = server.Policy(p)
    pol._maybe_reload()
    assert pol.default == "allow"          # the broken file is refused and the safe default kept


# ---- justification: required means no reason, no run; the approver reads it

def test_required_justification_blocks_until_the_agent_says_why(c, rules):
    d = post(c, "pay.refund", {"amount": 40}, source=agent())
    assert d["decision"] == "deny" and d["rule_id"] == "justification:refunds-say-why"
    assert "justification" in d["reason"]
    d = post(c, "pay.refund", {"amount": 40, "justification": "customer was double charged, ticket 4411"},
             source=agent())
    assert d["decision"] == "review"
    e = c.get(f"/v1/events/{d['event_id']}", headers=BOSS).json()
    assert e["justification"] == "customer was double charged, ticket 4411"
    title, body = server.approval_message(e)
    assert "Why, says the agent: customer was double charged" in body


def test_justification_from_metadata_and_bash_description(c, rules):
    d = post(c, "pay.refund", {"amount": 5}, source=agent(), metadata={"justification": "duplicate order"})
    assert d["decision"] == "review"
    d = post(c, "Bash", {"command": "ls", "description": "List the files"}, source=agent())
    assert c.get(f"/v1/events/{d['event_id']}", headers=BOSS).json()["justification"] == "List the files"


def test_justification_is_redacted(c, rules):
    d = post(c, "pay.refund", {"amount": 5, "justification": "api_key=sk_live_abcdefghijklmnop1234 told me to"},
             source=agent())
    assert "sk_live_abcdefghijklmnop1234" not in c.get(f"/v1/events/{d['event_id']}", headers=BOSS).json()["justification"]


# ---- ask_user: a question waits for a person; the answer is the note

def test_question_waits_and_the_answer_comes_back(c, rules):
    d = post(c, "ask_user", {"question": "Staging or prod database?"}, kind="question", source=agent())
    assert d["decision"] == "review" and d["rule_id"] == "ask-user" and d["snapshot"] is None
    eid = d["event_id"]
    assert c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={}).status_code == 400   # an answer needs words
    r = c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={"note": "staging"})
    assert r.status_code == 200 and r.json()["decision_note"] == "staging"
    title, body = server.approval_message(c.get(f"/v1/events/{eid}", headers=BOSS).json())
    assert title.startswith("Question from") and "Staging or prod database?" in body


def test_question_needs_a_question(c, rules):
    r = c.post("/v1/events", headers=H, json={"name": "ask_user", "kind": "question", "input": {}})
    assert r.status_code == 422


def test_question_is_never_waved_through_by_shadow_mode(c, rules):
    rules.write_text("mode: observe\n" + RULES, encoding="utf-8")
    server.policy._maybe_reload()
    d = post(c, "ask_user", {"question": "ok?"}, kind="question", source=agent())
    assert d["decision"] == "review"


# ---- notes: delivered once, with the next action of a client that can carry them

def test_note_is_delivered_once_to_the_right_agent(c, rules):
    who, other = agent(), agent()
    r = c.post("/v1/notes", headers=BOSS, json={"agent": who, "text": "use the staging cluster, eu-west-1"})
    assert r.status_code == 200
    assert post(c, "Read", {"file_path": "a"}, source=other, metadata={"accepts_notes": True}).get("notes") is None
    # a client that can't pass it on doesn't take it
    assert post(c, "Read", {"file_path": "a"}, source=who).get("notes") is None
    d = post(c, "Read", {"file_path": "a"}, source=who, metadata={"accepts_notes": True})
    assert [n["text"] for n in d["notes"]] == ["use the staging cluster, eu-west-1"] and d["notes"][0]["by"] == "boss"
    assert post(c, "Read", {"file_path": "b"}, source=who, metadata={"accepts_notes": True}).get("notes") is None
    assert any(e["action"] == "note.delivered" for e in c.get("/v1/audit/log", headers=BOSS).json()["entries"])


def test_note_waits_while_the_action_is_held(c, rules):
    who = agent()
    c.post("/v1/notes", headers=BOSS, json={"agent": who, "text": "hold off on prod"})
    held = post(c, "deploy.prod", {}, source=who, metadata={"accepts_notes": True})
    assert held["decision"] == "review" and held.get("notes") is None
    assert post(c, "Read", {}, source=who, metadata={"accepts_notes": True})["notes"][0]["text"] == "hold off on prod"


def test_note_to_a_session_and_taking_one_back(c, rules):
    sid = f"s-{uuid.uuid4().hex[:12]}"
    n = c.post("/v1/notes", headers=BOSS, json={"session": sid, "text": "wrap up"}).json()
    assert c.post("/v1/notes", headers=BOSS, json={"text": "nobody"}).status_code == 400
    assert c.post("/v1/notes", headers=H, json={"session": sid, "text": "x"}).status_code == 403   # not an approver
    assert c.delete(f"/v1/notes/{n['id']}", headers=BOSS).status_code == 200
    assert post(c, "Read", {}, session_id=sid, metadata={"accepts_notes": True}).get("notes") is None


# ---- a stop freezes approval deadlines; resuming gives the time back

def _deadline(c, eid):
    return datetime.fromisoformat(c.get(f"/v1/events/{eid}", headers=BOSS).json()["approval_deadline"].replace("Z", "+00:00"))


def test_stopped_agent_approvals_dont_expire_and_get_time_back(c, rules):
    who = agent()
    eid = post(c, "deploy.prod", {}, source=who)["event_id"]
    before = _deadline(c, eid)
    c.post("/v1/controls/stop", headers=BOSS, json={"agent": who, "reason": "test"})
    with server.engine.begin() as conn:   # backdate the stop by 10 minutes and make the deadline overdue
        s = json.loads(conn.execute(server.select(server.gateway_state.c.value)
                                    .where(server.gateway_state.c.key == "stop")).scalar())
        s["agents"][who]["at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        server.state_set(conn, "stop", s)
        conn.execute(server.update(server.events).where(server.events.c.id == eid).values(
            approval_deadline=(datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")))
    server.expire_overdue()
    assert c.get(f"/v1/events/{eid}", headers=BOSS).json()["status"] == "awaiting_approval"   # frozen, not expired
    r = c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={})
    assert r.status_code == 409 and "stopped" in r.json()["detail"]
    c.post("/v1/controls/resume", headers=BOSS, json={"agent": who})
    after = _deadline(c, eid)
    assert after > datetime.now(timezone.utc) + timedelta(minutes=9)       # about 10 minutes given back
    assert before is not None
    server.expire_overdue()
    assert c.get(f"/v1/events/{eid}", headers=BOSS).json()["status"] == "awaiting_approval"
    assert c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={}).status_code == 200


def test_a_timed_stop_gives_its_length_up_front_and_takes_back_what_is_left(c, rules):
    who = agent()
    eid = post(c, "deploy.prod", {}, source=who)["event_id"]
    before = _deadline(c, eid)
    c.post("/v1/controls/stop", headers=BOSS, json={"agent": who, "minutes": 60})
    assert abs((_deadline(c, eid) - before).total_seconds() - 3600) < 2
    c.post("/v1/controls/resume", headers=BOSS, json={"agent": who})
    assert abs((_deadline(c, eid) - before).total_seconds()) < 5     # resumed at once: nearly nothing frozen


# ---- the agents across the team that don't go through Squidbrake yet

def test_inventory_lists_agents_not_connected(c):
    m = f"laptop-{uuid.uuid4().hex[:12]}"
    r = c.post("/v1/agents/inventory", headers=H, json={"machine": m, "agents": [
        {"name": "claude-code", "label": "Claude Code", "present": True, "connected": True},
        {"name": "cursor", "label": "Cursor", "present": True, "connected": False},
        {"name": "codex", "label": "Codex", "present": False, "connected": False}]})
    assert r.json()["not_connected"] == ["Cursor"]
    inv = c.get("/v1/agents/inventory", headers=BOSS).json()
    assert {"machine": m, "agent": "cursor"}.items() <= next(x for x in inv["not_connected"] if x["machine"] == m).items()
    mine = next(x for x in inv["machines"] if x["machine"] == m)
    assert [a["name"] for a in mine["agents"]] == ["claude-code", "cursor"] and mine["key"] == "tester"


def test_inventory_keeps_mcp_server_names_only(c, tmp_path, monkeypatch):
    import connect
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "server-github"], "env": {"GITHUB_TOKEN": "ghp_secret"}},
        "linear": {"command": "python", "args": ["gateway_proxy.py", "--app", "linear"]}}}), encoding="utf-8")
    monkeypatch.setattr(connect, "mcp_configs", lambda: {"cursor": [(cfg, "mcpServers")]})
    found = connect.mcp_servers()
    assert found == [{"agent": "cursor", "name": "github", "guarded": False},
                     {"agent": "cursor", "name": "linear", "guarded": True}]
    m = f"laptop-{uuid.uuid4().hex[:12]}"
    c.post("/v1/agents/inventory", headers=H, json={"machine": m, "agents": [], "mcp": found})
    mine = next(x for x in c.get("/v1/agents/inventory", headers=BOSS).json()["machines"] if x["machine"] == m)
    assert mine["mcp"] == found and "ghp_secret" not in json.dumps(mine)


# ---- OTLP: every decision as an OpenTelemetry log record

def test_otlp_body_is_opentelemetry_logs():
    body, headers = siem.body_and_headers("otlp", "tok", [{"epoch": 1.5, "type": "decision", "agent": "a", "tool": "Bash",
                                                            "decision": "deny", "rule_id": "no-rm", "risk": 80}])
    doc = json.loads(body)
    rec = doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert rec["timeUnixNano"] == "1500000000" and rec["severityText"] == "WARN"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["squidbrake.decision"] == {"stringValue": "deny"} and attrs["squidbrake.risk"] == {"intValue": "80"}
    assert headers["Authorization"] == "Bearer tok"


def test_doctor_reports_this_computers_agents(monkeypatch):
    import connect
    import httpx
    sent = {}
    monkeypatch.delenv("SQUIDBRAKE_NO_INVENTORY", raising=False)
    monkeypatch.setattr(connect, "_hooked_gateway", lambda: ("https://gw.example.com", "gw_k"))
    monkeypatch.setattr(connect, "local_agents", lambda: [{"name": "cursor", "present": True, "connected": False}])

    def fake_post(url, **kw):
        sent.update(url=url, **kw)
        return httpx.Response(200, json={"not_connected": ["Cursor"]}, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", fake_post)
    assert connect.report_inventory() == ["Cursor"]
    assert sent["url"] == "https://gw.example.com/v1/agents/inventory" and sent["headers"] == {"X-Gateway-Key": "gw_k"}
    monkeypatch.setenv("SQUIDBRAKE_NO_INVENTORY", "1")
    assert connect.report_inventory() is None


# ---- the MCP proxy: the extra argument, notes in what the agent sees, and ask_user

def test_proxy_offers_justification_and_never_sends_it_to_the_app():
    import gateway_proxy
    from mcp import types
    t = types.Tool(name="refund", input_schema={"type": "object", "properties": {"amount": {"type": "number"}}})
    own = types.Tool(name="explain", input_schema={"type": "object", "properties": {"justification": {"type": "string"}}})
    assert "justification" in gateway_proxy.with_justification(t).input_schema["properties"]
    assert gateway_proxy.with_justification(own) is own and "explain" not in gateway_proxy._justified
    assert "refund" in gateway_proxy._justified


def test_notes_come_first_in_what_the_agent_sees():
    import gw_async
    from mcp import types
    note = gw_async.notes_text({"notes": [{"by": "pat", "text": "use staging"}]})
    assert note.startswith("NOTE FROM pat") and gw_async.with_note("result", note).startswith("NOTE FROM pat")
    r = gw_async.with_note(types.CallToolResult(content=[types.TextContent(type="text", text="ok")]), note)
    assert [c.text for c in r.content] == [note.strip(), "ok"]


def test_ask_user_returns_the_answer(monkeypatch):
    import asyncio
    import gw_async
    eid = "12345678-1234-1234-1234-123456789abc"
    sent = []

    async def check(name, input, kind="tool_call", metadata=None):
        sent.append((name, input, kind))
        return {"decision": "review", "event_id": eid}

    async def wait(event_id, seconds):
        return {"decision": "allow", "decided_by": "pat", "decision_note": "staging"}

    async def result(*a, **k):
        return None
    monkeypatch.setattr(gw_async, "gw_check", check)
    monkeypatch.setattr(gw_async, "gw_wait", wait)
    monkeypatch.setattr(gw_async, "gw_result", result)
    assert asyncio.run(gw_async.ask_user("which db?")) == "ANSWER from pat: staging"
    assert sent == [("ask_user", {"question": "which db?"}, "question")]
    assert "Ask a question" in asyncio.run(gw_async.ask_user(""))

    async def nobody(event_id, seconds):
        return {"decision": "review"}
    monkeypatch.setattr(gw_async, "gw_wait", nobody)
    assert f'event_id="{eid}"' in asyncio.run(gw_async.ask_user(None, eid))


def test_back_office_pack_loads_and_does_what_it_says(c, rules):
    assert c.post("/v1/policy/packs/back-office/apply", headers=BOSS).json()["ok"]
    server.policy._maybe_reload()
    assert {"back-office-exports", "back-office-order-changes"} <= {r["id"] for r in server.policy.rules}
    who = agent()
    assert post(c, "crm.delete_contact", {"id": 7}, source=who)["decision"] == "deny"
    assert post(c, "shop.cancel_order", {"id": 9}, source=who)["rule_id"] == "justification:back-office-order-changes"
    assert post(c, "shop.cancel_order", {"id": 9, "justification": "customer asked, ticket 12"},
                source=who)["decision"] == "review"
    assert post(c, "hubspot.export_contacts", {}, source=who)["decision"] == "allow"
    assert post(c, "snowflake.query", {"sql": "select 1"}, source=who)["decision"] == "allow"
    assert post(c, "snowflake.query", {"sql": "delete from orders"}, source=who)["decision"] == "review"


# ---- two-person approval and escalation

BOSS2 = {"X-Gateway-Key": "k3"}
QUORUM = RULES + """
  - id: big-payouts
    action: review
    required_approvals: 2
    reason: big money out
    match: { name: "pay.payout*" }
  - id: urgent
    action: review
    approvers: [boss]
    escalate_after_seconds: 60
    escalate_to: [boss2]
    reason: production change
    match: { name: "prod.*" }
"""


@pytest.fixture()
def quorum(rules):
    rules.write_text(QUORUM, encoding="utf-8")
    server.policy._maybe_reload()
    return rules


def test_two_people_must_approve_and_one_rejection_stops_it(c, quorum):
    eid = post(c, "pay.payout", {"amount": 9000}, source=agent())["event_id"]
    r = c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={"note": "checked invoice"})
    assert r.status_code == 200 and r.json()["decision"] == "review"           # one of two
    assert c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={}).status_code == 409   # not twice
    e = c.get(f"/v1/events/{eid}", headers=BOSS).json()
    assert [a["by"] for a in e["approvals"]] == ["boss"] and e["required_approvals"] == 2
    r = c.post(f"/v1/events/{eid}/approve", headers=BOSS2, json={})
    assert r.json()["decision"] == "allow" and r.json()["decided_by"] == "boss + boss2"
    assert "boss: checked invoice" in r.json()["decision_note"]

    eid = post(c, "pay.payout", {"amount": 9000}, source=agent())["event_id"]
    c.post(f"/v1/events/{eid}/approve", headers=BOSS, json={})
    r = c.post(f"/v1/events/{eid}/reject", headers=BOSS2, json={"note": "not this week"})
    assert r.json()["decision"] == "deny"
    acts = [x["action"] for x in c.get("/v1/audit/log", headers=BOSS, params={"limit": 50}).json()["entries"]
            if x["target"] == eid]
    assert "event.approval_added" in acts and "event.rejected" in acts


def test_quorum_settings_are_checked(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("rules:\n  - id: x\n    action: review\n    escalate_after_seconds: 30\n    match: {name: a}\n",
                 encoding="utf-8")
    pol = server.Policy(p)
    pol._maybe_reload()
    assert pol.rules == []                       # escalate without escalate_to: refused, the last good rules kept


def test_escalation_lets_more_people_decide_and_tells_them(c, quorum, monkeypatch):
    sent = []
    monkeypatch.setattr(server, "notify_approval_needed", lambda row, escalated_to=None: sent.append(escalated_to))
    eid = post(c, "prod.restart", {}, source=agent())["event_id"]
    assert c.post(f"/v1/events/{eid}/approve", headers=BOSS2, json={}).status_code == 403   # not yet theirs
    with server.engine.begin() as conn:
        conn.execute(server.update(server.events).where(server.events.c.id == eid).values(
            escalate_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")))
    assert server.escalate_due() == 1 and server.escalate_due() == 0          # once
    assert sent[-1] == ["boss2"]
    assert c.post(f"/v1/events/{eid}/approve", headers=BOSS2, json={}).json()["decision"] == "allow"


# ---- rules history: diff against today's, and putting a version back

def test_rules_history_diff_and_restore(c, rules):
    post(c, "Read", {}, source=agent())                       # a decision records this version
    old_fp = server.policy.fingerprint
    rules.write_text(RULES.replace("action: notify", "action: deny"), encoding="utf-8")
    server.policy._maybe_reload()
    post(c, "Read", {}, source=agent())
    v = c.get("/v1/policy/versions", headers=BOSS).json()
    assert v["current"] == server.policy.fingerprint and old_fp in [x["fingerprint"] for x in v["versions"]]
    d = c.get(f"/v1/policy/versions/{old_fp}", headers=BOSS).json()
    assert "-    action: notify" in d["diff_to_current"] and "+    action: deny" in d["diff_to_current"]
    assert c.post(f"/v1/policy/versions/{old_fp}/restore", headers=H).status_code == 403    # admins only
    r = c.post(f"/v1/policy/versions/{old_fp}/restore", headers=BOSS)
    assert r.status_code == 200 and r.json()["ok"] and server.policy.fingerprint == old_fp
    assert (rules.parent / r.json()["backup"]).read_text(encoding="utf-8").count("action: deny") >= 1
    assert c.get("/v1/policy/versions/nope", headers=BOSS).status_code == 404
