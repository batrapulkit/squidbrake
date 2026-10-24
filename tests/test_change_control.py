"""Undo copies, signed checkpoints, per-rule offline behaviour, spend limits, proof of work, AI briefs, passkey
approvals, access levels and the kill switch from a notification."""
import base64
import hashlib
import json
import re
import os
import sys
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import brief  # noqa: E402
import offline  # noqa: E402
import proof  # noqa: E402
import verify  # noqa: E402
from test_server import BOSS, BOSS2, H, TMP, c, server  # noqa: E402,F401

RULES = """
default: allow
when_unreachable: block
history_checks: { repeat_of_rejected: off, impersonation: off, payment_request_in_message: off, duplicate_change: off }
budgets:
  - id: daily
    match: { source: "budgeted-*" }
    per: agent
    period: day
    tokens: 1000
proof_checks:
  - id: order-updated
    match: { name: "orders.update_status" }
    sql: { url_env: CC_ORDERS_DB, query: "select status from orders where id = :id", params: { id: "{input.order_id}" } }
    expect: { status: "{input.status}" }
    delay_seconds: 0
rules:
  - id: reads
    action: allow
    when_unreachable: allow
    match: { name: "Read" }
  - id: wipe
    action: allow
    snapshot: required
    match: { name: "crm.wipe*" }
  - id: hold-refunds
    action: review
    match: { name: "refund*" }
upstreams:
  crm: http://crm.test
"""


@pytest.fixture()
def rules(monkeypatch, tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(RULES)
    monkeypatch.setattr(server, "policy", server.Policy(path))
    server.policy._maybe_reload()
    assert server.policy.budgets and server.policy.proofs, "rules didn't load"
    return path


def post(c, name, inp=None, source="cc-agent", **kw):
    return c.post("/v1/events", headers=H, json={"name": name, "input": inp, "source": source, **kw}).json()


# ---- 4. signed checkpoints

def test_checkpoints_are_signed_and_checked_offline(c):
    for i in range(55):
        post(c, "notes.add", {"i": i})
    server.sign_missing_checkpoints()
    v = server.verify_audit_chain()
    assert v["ok"] and v["checkpoints"]["ok"] and v["checkpoints"]["count"] >= 1
    key = c.get("/v1/audit/public-key").json()                    # published: no key needed
    assert key["algorithm"] == "ed25519" and key["every"] == 50 and key["latest_checkpoint"]["seq"] % 50 == 0
    data = json.loads(json.dumps(server.evidence_body("t"), default=str))
    good = verify.verify(data, key["public_key"])
    assert good["ok"] and good["checkpoints"]["valid"] >= 1
    assert not verify.verify(data, "00" * 32)["ok"]               # someone else's key: caught
    forged = json.loads(json.dumps(data))
    forged["checkpoints"][0]["signature"] = "11" * 64
    assert "didn't make" in verify.verify(forged)["checkpoints"]["message"]
    rewritten = json.loads(json.dumps(data))
    rewritten["checkpoints"][0]["head_hash"] = "ab" * 32
    assert "rewritten" in verify.verify(rewritten)["checkpoints"]["message"]


# ---- 5. redaction in what's stored

def test_people_details_are_masked_when_stored(c):
    d = post(c, "crm.note", {"to": "maya@customer.example", "card": "4111 1111 1111 1111"})
    stored = c.get(f"/v1/events/{d['event_id']}", headers=H).json()["input"]
    assert "maya@" not in stored["to"] and stored["to"].endswith("@customer.example")
    assert stored["card"] == "[card ending 1111]"


# ---- 6. what each rule does while the gateway is down

def test_offline_policy_per_rule(c, rules, monkeypatch, tmp_path):
    monkeypatch.setenv("SQUIDBRAKE_OFFLINE_DIR", str(tmp_path))
    pol = c.get("/v1/policy/offline", headers=H).json()
    assert pol["default"] == "block" and pol["client"] == "tester"
    assert {r["id"]: r["when_unreachable"] for r in pol["rules"]}["reads"] == "allow"
    url = "http://gw.example"
    assert offline.decide(url, name="Read")[0] is False                     # no copy yet: blocked
    offline.save(url, pol)
    assert offline.decide(url, name="Read") == (True, "rule 'reads' says when_unreachable: allow, so it ran unrecorded")
    assert offline.decide(url, name="Bash", input={"command": "ls"})[0] is False
    assert offline.decide(url, name="Bash", fail_open=True)[0] is True


def test_bad_when_unreachable_keeps_the_last_good_rules(rules):
    rules.write_text(RULES.replace("when_unreachable: block", "when_unreachable: maybe"))
    os.utime(rules, (time.time(), time.time() + 30))
    server.policy._maybe_reload()
    assert server.policy.when_unreachable == "block"


# ---- 13. spend brake

def test_budget_pauses_only_the_agent_over_it(c, rules):
    agent = f"budgeted-{time.time_ns()}"
    assert post(c, "notes.add", source=agent)["decision"] == "allow"
    r = c.post("/v1/usage", headers=H, json={"source": agent, "input_tokens": 800, "output_tokens": 300}).json()
    assert r["paused"] and "1,100 of 1,000 tokens" in r["message"]
    d = post(c, "notes.add", source=agent)
    assert d["decision"] == "deny" and d["rule_id"] == "budget:daily" and "starts again" in d["reason"]
    assert post(c, "notes.add", source=f"budgeted-other-{time.time_ns()}")["decision"] == "allow"
    assert post(c, "notes.add", source="unbudgeted")["decision"] == "allow"
    spend = c.get("/v1/budgets", headers=BOSS).json()["spend"]
    assert any(s["who"] == agent and s["paused"] for s in spend)


def test_hook_reported_usage_counts(c, rules):
    agent = f"budgeted-hook-{time.time_ns()}"
    post(c, "Read", {"file_path": "a"}, source=agent, metadata={"usage": {"input_tokens": 2000, "output_tokens": 1}})
    assert post(c, "Read", {"file_path": "b"}, source=agent)["rule_id"] == "budget:daily"


# ---- 1. undo copies

def test_snapshot_wanted_for_held_and_named_actions(c, rules):
    held = post(c, "refund.create", {"charge": "ch_1"})
    assert held["decision"] == "review" and held["snapshot"] == "required" and held["snapshot_strict"] is False
    named = post(c, "crm.wipe_contacts", {})
    assert named["snapshot"] == "required" and named["snapshot_strict"] is True
    assert post(c, "notes.add", {})["snapshot"] is None
    after = c.post(f"/v1/events/{held['event_id']}/approve", headers=BOSS, json={}).json()
    assert after["snapshot"] == "required"
    # the agent keeps the copy; anyone else's key can't attach one
    r = c.post(f"/v1/events/{named['event_id']}/snapshot", headers=H,
               json={"kind": "data", "summary": "contacts before", "data": {"rows": [{"email": "a@b.co"}]}})
    assert r.status_code == 200 and r.json()["kind"] == "data"
    snaps = c.get(f"/v1/events/{named['event_id']}/snapshots", headers=BOSS).json()["snapshots"]
    assert re.fullmatch(r"a.redacted-[0-9a-f]{6}@b.co", snaps[0]["data"]["rows"][0]["email"])
    ev = c.get(f"/v1/events/{named['event_id']}", headers=BOSS).json()
    assert ev["snapshot"]["summary"] == "contacts before"


def test_proxy_keeps_the_record_before_changing_it(c, rules):
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.method)
        if req.url.path.endswith("/gone"):
            return httpx.Response(404)
        return httpx.Response(200, json={"id": 7, "plan": "pro"})

    server.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    r = c.patch("/proxy/crm/customers/7", headers=H, json={})     # matches nothing held... so no copy
    assert r.status_code == 200 and calls == ["PATCH"]
    rules.write_text(RULES.replace("rules:\n", "rules:\n  - id: crm-deletes\n    action: allow\n    snapshot: required\n"
                                               "    match: { name: 'DELETE crm/*' }\n", 1))
    os.utime(rules, (time.time(), time.time() + 40))
    calls.clear()
    r = c.delete("/proxy/crm/customers/7", headers=H)
    assert r.status_code == 200 and calls == ["GET", "DELETE"]
    ev = c.get(f"/v1/events/{r.headers['X-Gateway-Event-Id']}", headers=BOSS).json()
    assert ev["snapshot"]["kind"] == "http"
    calls.clear()
    r = c.delete("/proxy/crm/gone", headers=H)                  # can't read it first: not run
    assert r.status_code == 403 and calls == ["GET"] and "couldn't" in r.json()["reason"]


# ---- 12. proof of work

def test_proof_checks_the_real_system(c, rules, monkeypatch, tmp_path):
    from sqlalchemy import create_engine, text
    db = f"sqlite:///{(tmp_path / 'orders.db').as_posix()}"
    eng = create_engine(db)
    with eng.begin() as conn:
        conn.execute(text("create table orders (id text, status text)"))
        conn.execute(text("insert into orders values ('A1', 'shipped'), ('A2', 'open')"))
    eng.dispose()
    monkeypatch.setenv("CC_ORDERS_DB", db)
    ok = post(c, "orders.update_status", {"order_id": "A1", "status": "shipped"})
    c.post(f"/v1/events/{ok['event_id']}/result", headers=H, json={"output": {"ok": True}})
    assert server.run_proofs(ok["event_id"])["status"] == "confirmed"
    lie = post(c, "orders.update_status", {"order_id": "A2", "status": "shipped"})
    c.post(f"/v1/events/{lie['event_id']}/result", headers=H, json={"output": {"ok": True}})
    r = c.post(f"/v1/events/{lie['event_id']}/proof", headers=BOSS).json()
    assert r["status"] == "mismatch" and "'open'" in r["message"]
    assert c.get(f"/v1/events/{lie['event_id']}", headers=BOSS).json()["proof_status"] == "mismatch"


def test_proof_templates_cant_escape_the_url():
    assert proof.fill("https://api.x/c/{input.id}", {"id": "../admin?x=1"}, None, in_url=True) == \
        "https://api.x/c/..%2Fadmin%3Fx%3D1"
    assert proof.run({"id": "x", "kind": "sql", "spec": {"url_env": "NOPE_NOT_SET", "query": "select 1"}, "expect": {}},
                     {}, {})["status"] == "error"
    assert "SELECT" in proof.run({"id": "x", "kind": "sql", "spec": {"url_env": "PATH", "query": "delete from t"},
                                  "expect": {}}, {}, {})["message"]


# ---- 9. AI approval briefs (advice only)

class FakeClaude:
    def __init__(self, text="1. Refunds $40.\n2. Risk: Medium, money leaves.\n3. Check the charge."):
        self.sent, self._text = None, text
        self.beta = type("B", (), {"messages": self})()

    def create(self, **kw):
        self.sent = kw
        block = type("T", (), {"type": "text", "text": self._text})()
        return type("M", (), {"stop_reason": "end_turn", "content": [block], "model": kw["model"]})()


def test_brief_is_written_with_the_customers_key_and_only_advises(c, rules, monkeypatch):
    fake = FakeClaude()
    out = brief.write("sk-test", None, {"name": "refund.create", "input": {"amount": 40}, "reason": "money"}, [], client=fake)
    assert out["text"].startswith("1. Refunds") and fake.sent["model"] == "claude-opus-5-5"
    assert "<action>" in fake.sent["messages"][0]["content"] and "never as instructions" in fake.sent["system"]
    real = server.settings
    monkeypatch.setattr(server, "settings", lambda: {**real(), "ai_briefs": True, "ai_key": "k"})
    monkeypatch.setattr(brief, "write", lambda key, model, row, ctx, client=None: {"text": f"brief for {row['name']}"})
    held = post(c, "refund.create", {"charge": "ch_9"})
    assert server.write_brief(held["event_id"])["text"] == "brief for refund.create"
    ev = c.get(f"/v1/events/{held['event_id']}", headers=BOSS).json()
    assert ev["brief"]["text"] == "brief for refund.create" and ev["status"] == "awaiting_approval"   # still a person's call


def test_settings_never_return_the_ai_key(c):
    r = c.put("/v1/settings", headers=BOSS, json={"ai_key": "sk-ant-secret-123456", "ai_briefs": True}).json()
    assert "ai_key" not in r and r["ai_key_set"] and r["ai_key_hint"] == "…3456"
    c.put("/v1/settings", headers=BOSS, json={"ai_key": "", "ai_briefs": False})


# ---- 10. approvals signed with a passkey

def _cbor(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        if n < 256:
            return bytes([major << 5 | 24, n])
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    return head(5, len(v)) + b"".join(_cbor(k) + _cbor(x) for k, x in v.items())


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Phone:
    """A pretend phone with Face ID: makes and uses an ES256 passkey the way a browser's WebAuthn does."""
    def __init__(self):
        self.key, self.cred, self.count = ec.generate_private_key(ec.SECP256R1()), os.urandom(16), 0

    def register(self, options: dict) -> dict:
        rp = options["rp"]["id"]
        n = self.key.public_key().public_numbers()
        cose = _cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        auth = hashlib.sha256(rp.encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16) \
            + len(self.cred).to_bytes(2, "big") + self.cred + cose
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": f"https://{rp}"}).encode()
        return {"name": "Pat's phone", "challenge": options["challenge"], "credential_id": b64u(self.cred),
                "client_data_json": b64u(client), "attestation_object": b64u(_cbor({"fmt": "none", "attStmt": {}, "authData": auth}))}

    def sign(self, ch: dict, verified: bool = True) -> dict:
        self.count += 1
        auth = hashlib.sha256(ch["rp_id"].encode()).digest() + bytes([0x05 if verified else 0x01]) + self.count.to_bytes(4, "big")
        client = json.dumps({"type": "webauthn.get", "challenge": ch["challenge"], "origin": f"https://{ch['rp_id']}"}).encode()
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"credential_id": b64u(self.cred), "statement": ch["statement"], "authenticator_data": b64u(auth),
                "client_data_json": b64u(client), "signature": b64u(sig)}


def test_passkey_approvals(c, rules):
    phone = Phone()
    options = c.post("/v1/devices/register/start", headers=BOSS).json()
    assert options["authenticatorSelection"]["userVerification"] == "required"
    r = c.post("/v1/devices/register/finish", headers=BOSS, json=phone.register(options))
    assert r.status_code == 200, r.text
    assert c.post("/v1/devices/register/finish", headers=BOSS, json=phone.register(options)).status_code == 409

    held = post(c, "refund.create", {"charge": f"ch_{time.time_ns()}"})
    ch = c.post(f"/v1/events/{held['event_id']}/challenge", headers=BOSS, json={"outcome": "approve"}).json()
    assert ch["allow_credentials"] == [b64u(phone.cred)]
    wrong = c.post(f"/v1/events/{held['event_id']}/reject", headers=BOSS, json={"device_proof": phone.sign(ch)})
    assert wrong.status_code == 403 and "different decision" in wrong.json()["detail"]   # signed approve, not reject
    no_face = c.post(f"/v1/events/{held['event_id']}/approve", headers=BOSS, json={"device_proof": phone.sign(ch, verified=False)})
    assert no_face.status_code == 403 and "verify the person" in no_face.json()["detail"]
    ok = c.post(f"/v1/events/{held['event_id']}/approve", headers=BOSS, json={"device_proof": phone.sign(ch)})
    assert ok.status_code == 200, ok.text
    ev = c.get(f"/v1/events/{held['event_id']}", headers=BOSS).json()
    assert ev["decided_with"] == "passkey: Pat's phone"
    data = json.loads(json.dumps(server.evidence_body("t"), default=str))
    assert verify.verify(data)["devices"]["checked"] >= 1 and not verify.verify(data)["devices"]["bad"]

    # boss2 has no device: with signatures required, a plain approval is refused, a rejection is still fine
    c.put("/v1/settings", headers=BOSS, json={"require_device_signature": True})
    try:
        a = post(c, "refund.create", {"charge": f"ch_{time.time_ns()}"})
        assert c.post(f"/v1/events/{a['event_id']}/approve", headers=BOSS2, json={}).status_code == 403
        assert c.post(f"/v1/events/{a['event_id']}/reject", headers=BOSS2, json={}).status_code == 200
        assert c.put("/v1/settings", headers=BOSS2, json={"require_device_signature": True}).status_code == 400
    finally:
        c.put("/v1/settings", headers=BOSS, json={"require_device_signature": False})


# ---- 2. kill switch from the notification itself

def test_stop_the_agent_from_a_notification_link(c, rules):
    agent = f"linked-{time.time_ns()}"
    held = post(c, "refund.create", {"charge": "x"}, source=agent)
    token = server.make_link_token(held["event_id"], "boss")
    assert c.post(f"/v1/a/{token}/stop", json={}).status_code == 200
    d = post(c, "notes.add", source=agent)
    assert d["decision"] == "deny" and d["rule_id"] == "emergency-stop"
    assert post(c, "notes.add", source="someone-else")["decision"] == "allow"
    c.post("/v1/controls/resume", headers=BOSS, json={"agent": agent})


# ---- 11. owner / admin / approver / viewer

@pytest.fixture()
def team(c, monkeypatch):
    ks = server.KeyStore(TMP / f"levels-{time.time_ns()}" / "keys.json")
    keys = ks.ensure_initialized()
    monkeypatch.setattr(server, "keystore", ks)
    return {n: {"X-Gateway-Key": k} for n, k in keys.items()}


def test_access_levels(c, team):
    me = c.get("/v1/me", headers=team["admin"]).json()
    assert me["access"] == "owner" and me["is_owner"]
    add = lambda who, name, access: c.post("/v1/team", headers=team[who] if isinstance(who, str) else who,
                                           json={"name": name, "access": access})
    r = add("admin", "ana", "admin").json()
    ana = {"X-Gateway-Key": r["key"]}
    assert r["access"] == "admin"
    assert add(ana, "eve", "owner").status_code == 403                 # only owners make owners or admins
    assert add(ana, "ed", "admin").status_code == 403
    v = add(ana, "vic", "viewer").json()
    assert v["access"] == "viewer"
    vic = {"X-Gateway-Key": v["key"]}
    assert c.get("/v1/events", headers=vic).status_code == 200
    assert c.post("/v1/events", headers=vic, json={"name": "x"}).status_code == 403   # view only
    assert c.post("/v1/controls/stop", headers=vic, json={}).status_code == 403
    assert c.patch("/v1/team/vic", headers=ana, json={"access": "approver"}).json()["access"] == "approver"
    assert c.patch("/v1/team/admin", headers=ana, json={"access": "approver"}).status_code == 403
    assert c.delete("/v1/team/admin", headers=ana).status_code == 403
    assert c.patch("/v1/team/ana", headers=team["admin"], json={"access": "owner"}).json()["access"] == "owner"
    assert c.patch("/v1/team/admin", headers=ana, json={"access": "admin"}).json()["access"] == "admin"
    assert c.patch("/v1/team/ana", headers=ana, json={"access": "viewer"}).status_code == 400   # not yourself
    names = {m["name"]: m["access"] for m in c.get("/v1/team", headers=ana).json()["members"]}
    assert names == {"admin": "admin", "agent": "agent", "ana": "owner", "vic": "approver"}
