"""Phase 2: an agent can never approve its own action. Each test is an agent trying a way in; every one fails closed
(blocked, or waiting for a person), and the attempt is on the record."""
import base64
import json
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import selfguard  # noqa: E402
from test_server import BOSS, BOSS2, H, TMP, c, server  # noqa: E402,F401

HOME = str(Path.home()).replace("\\", "/")


@pytest.fixture()
def shipped(monkeypatch):
    monkeypatch.setattr(server, "policy", server.Policy(ROOT / "rules.yaml"))
    server.policy._maybe_reload()


def act(c, name, inp, **kw):
    return c.post("/v1/events", headers=H, json={"kind": "tool_call", "name": name, "input": inp, "source": "claude-code",
                                                 "session_id": str(uuid.uuid4()), **kw}).json()


ATTEMPTS = [
    ("run the approve CLI", "Bash", {"command": "squidbrake add-key helper --approver"}),
    ("run it through python", "Bash", {"command": "python -m squidbrake add-key helper --approver"}),
    ("lift a stop", "Bash", {"command": "squidbrake resume"}),
    ("read the token store", "Read", {"file_path": f"{HOME}/.squidbrake/data/secret.key"}),
    ("read the keys", "Grep", {"pattern": "sha256", "path": f"{HOME}/.squidbrake/data"}),
    ("write the token store", "Write", {"file_path": f"{HOME}/.squidbrake/data/keys.json", "content": "{}"}),
    ("edit the record", "Bash", {"command": "sqlite3 ~/.squidbrake/data/gateway.db 'update events set status=1'"}),
    ("call the approval API", "Bash", {"command": "curl -X POST http://127.0.0.1:8080/v1/events/abc/approve"}),
    ("approve through a link", "Bash", {"command": "curl -X POST http://127.0.0.1:8080/v1/a/x.y/approve"}),
    ("fetch it from a script", "Bash", {"command": "node -e \"fetch('http://localhost:8080/v1/events/1/approve',{method:'POST'})\""}),
    ("steal the dashboard key", "Bash",
     {"command": "grep -r gw_ \"$LOCALAPPDATA/Google/Chrome/User Data/Default/Local Storage/leveldb\""}),
]
TAMPER = [
    ("edit the policy file", "Write", {"file_path": f"{HOME}/.squidbrake/rules.yaml", "content": "default: allow"}),
    ("edit the hook config", "Edit", {"file_path": f"{HOME}/.claude/settings.json", "old_string": "a", "new_string": "b"}),
    ("disable it with a variable", "Bash", {"command": "setx GATEWAY_FAIL_OPEN 1"}),
    ("disable it in PowerShell", "PowerShell",
     {"command": "[Environment]::SetEnvironmentVariable('SQUIDBRAKE_TELEMETRY','0','User')"}),
    ("run a gateway with sign-in off", "Bash", {"command": "GATEWAY_AUTH=off squidbrake run --port 8080"}),
    ("downgrade it", "Bash", {"command": "pip install squidbrake==0.1.0"}),
    ("edit the installed hook", "Edit",
     {"file_path": "/home/u/.local/lib/python3.12/site-packages/claude_hook.py", "old_string": "a", "new_string": "b"}),
]


@pytest.mark.parametrize("what,name,inp", ATTEMPTS, ids=[a[0] for a in ATTEMPTS])
def test_agent_reaching_for_the_approval_path_is_blocked(c, shipped, what, name, inp):
    d = act(c, name, inp)
    assert d["decision"] == "deny" and d["rule_id"] == "self-protection:approval", d


@pytest.mark.parametrize("what,name,inp", TAMPER, ids=[a[0] for a in TAMPER])
def test_agent_loosening_squidbrake_waits_for_a_person(c, shipped, what, name, inp):
    assert act(c, name, inp)["decision"] in ("deny", "review")


def test_shadow_mode_does_not_switch_it_off(c, monkeypatch, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("default: allow\nmode: shadow\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    server.policy._maybe_reload()
    assert server.policy.mode == "shadow"
    assert act(c, "Bash", {"command": "squidbrake add-key helper --approver"})["decision"] == "deny"
    d = act(c, "Bash", {"command": "setx GATEWAY_FAIL_OPEN 1"})
    assert d["decision"] == "review" and d["rule_id"] == "self-protection:tamper"


def test_attempt_is_recorded_as_high_severity(c, shipped):
    d = act(c, "Bash", {"command": "squidbrake add-key helper --approver"})
    log = c.get("/v1/audit/log", params={"limit": 50}, headers=BOSS).json()
    entries = log["entries"] if isinstance(log, dict) else log
    assert any(e["action"] == "security.self_approval_attempt" and e["target"] == d["event_id"] for e in entries)


@pytest.mark.parametrize("name,inp,cwd", [
    ("Bash", {"command": "squidbrake explain \"git init\""}, None),
    ("Bash", {"command": "squidbrake doctor"}, None),
    ("Read", {"file_path": "/repo/config/keys.json"}, "/repo"),
    ("Bash", {"command": "cat data/keys.json"}, "/repo"),
    ("Bash", {"command": "curl -s http://localhost:3000/v1/settings"}, None),
    ("Edit", {"file_path": "/repo/server.py", "old_string": "a", "new_string": "b"}, "/repo"),
    ("Bash", {"command": "pip install requests"}, None),
    # writing docs and tests about Squidbrake: only the path is read, not the text
    ("Edit", {"file_path": "/repo/README.md", "old_string": "a", "new_string": "run squidbrake add-key NAME --approver"}, None),
    ("Write", {"file_path": "/repo/tests/t.py", "content": "c.post('/v1/events/1/approve')  # GATEWAY_AUTH=off"}, None),
])
def test_everyday_work_is_not_mistaken_for_it(name, inp, cwd):
    assert selfguard.check("tool_call", name, inp, {"cwd": cwd}, Path(HOME) / ".squidbrake" / "data") is None


# ---- the tokens a person approves with ----------------------------------------------------------------------------

def _link(event_id, approver="boss"):
    return server.make_link_token(event_id, approver)


def _held(c, name="payments.send"):
    d = c.post("/v1/events", headers=H, json={"name": name, "input": {"amount": time.time_ns()}}).json()
    assert d["decision"] == "review"
    return d["event_id"]


def test_link_works_once(c):
    eid = _held(c)
    token = _link(eid)
    assert c.post(f"/v1/a/{token}/approve").status_code == 200
    assert c.post(f"/v1/a/{token}/approve").status_code == 409        # replay
    assert c.post(f"/v1/a/{token}/reject").status_code == 409


def test_link_is_bound_to_one_action(c):
    a, b = _held(c), _held(c)
    payload, sig = _link(a).split(".")
    other = base64.urlsafe_b64encode(json.dumps([b, "boss"]).encode()).decode().rstrip("=")
    assert c.post(f"/v1/a/{other}.{sig}/approve").status_code == 404     # the signature covers the action
    assert c.get(f"/v1/events/{b}", headers=BOSS).json()["status"] == "awaiting_approval"


def test_link_expires_with_the_action(c):
    d = c.post("/v1/events", headers=H, json={"name": "slow.thing", "input": {}}).json()   # 1 s timeout, then deny
    time.sleep(1.2)
    assert c.post(f"/v1/a/{_link(d['event_id'])}/approve").status_code == 409


def test_the_requesting_key_cannot_approve(c):
    eid = _held(c)
    assert c.post(f"/v1/events/{eid}/approve", headers=H).status_code == 403
    assert c.post(f"/v1/a/{_link(eid, 'tester')}/approve").status_code == 403    # not an approver


def test_maker_checker_per_rule(c, monkeypatch, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("default: allow\nrules:\n  - id: wires\n    action: review\n    second_person: true\n"
                     "    match: { name: 'bank.*' }\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    server.policy._maybe_reload()
    ks = server.KeyStore(TMP / f"mc-{time.time_ns()}" / "keys.json")
    ks.ensure_initialized()
    monkeypatch.setattr(server, "keystore", ks)
    priya = ks.add("priya", approver=True, kind="person")
    bot = ks.add("priya-bot", kind="agent", owner="priya")
    other = ks.add("omar", approver=True, kind="person")
    assert not server.settings().get("second_person")      # off in Settings: only the rule asks for it
    eid = c.post("/v1/events", headers={"X-Gateway-Key": bot}, json={"name": "bank.wire", "input": {"amount": 9}}).json()["event_id"]
    r = c.post(f"/v1/events/{eid}/approve", headers={"X-Gateway-Key": priya})
    assert r.status_code == 403 and "someone else" in r.json()["detail"]
    assert c.post(f"/v1/events/{eid}/approve", headers={"X-Gateway-Key": other}).json()["status"] == "pending"
