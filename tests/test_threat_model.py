"""Phase 3: what THREAT_MODEL.md says Squidbrake stops, checked: integrity, fail mode, audit verify, remote commands,
and the doctor's list of what each agent's hook does and doesn't check."""
import json
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import commands  # noqa: E402
import integrity  # noqa: E402
import offline  # noqa: E402
from test_server import BOSS, H, c, server  # noqa: E402,F401

HOME = str(Path.home()).replace("\\", "/")


@pytest.fixture()
def machine(tmp_path, monkeypatch):
    """A computer with one agent's hook, a rules file and an installed package, and the gateway's data folder."""
    hook, rules, pkg, data = tmp_path / "settings.json", tmp_path / "rules.yaml", tmp_path / "pkg", tmp_path / "data"
    hook.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "python /x/claude_hook.py --url http://localhost:8080 --key k"}]}]},
        "permissions": {"allow": []}}))
    rules.write_text("default: allow\n")
    pkg.mkdir()
    (pkg / "server.py").write_text("print('hi')\n")
    monkeypatch.setattr(server, "_integrity_inputs", lambda: (rules, pkg, {"claude-code": hook}))
    monkeypatch.setattr(server, "KEYS_PATH", data / "keys.json")
    monkeypatch.setattr(server, "notify_text", lambda *a: None)
    with server.audited_tx() as conn:
        server.state_set(conn, "integrity", {"changes": [], "at": None})
    return {"hook": hook, "rules": rules, "pkg": pkg, "data": data}


def test_integrity_sees_our_hook_removed_but_not_other_settings(machine, monkeypatch):
    assert server.check_integrity() == []                         # first look: kept as the normal
    data = json.loads(machine["hook"].read_text())
    data["permissions"]["allow"].append("Bash(ls)")               # the person's own settings: not our business
    machine["hook"].write_text(json.dumps(data))
    assert server.check_integrity() == []
    data["hooks"] = {}                                            # Squidbrake's hook taken out
    machine["hook"].write_text(json.dumps(data))
    (machine["pkg"] / "server.py").write_text("print('patched')\n")
    changes = server.check_integrity()
    assert {(c["kind"], c["change"]) for c in changes} == {("hooks", "removed"), ("package", "changed")}
    assert server.state_get("integrity")["changes"] == changes
    server.accept_integrity("tester")
    assert server.check_integrity() == []
    machine["rules"].write_text("default: review\n")            # a person's own edit: recorded, not an alert
    data["hooks"] = {"PreToolUse": [{"hooks": [{"type": "command", "command": "python /x/agent_hook.py cursor"}]}]}
    machine["hook"].write_text(json.dumps(data))                # an agent connected again: fine
    assert server.check_integrity() == []
    monkeypatch.setattr(server, "VERSION", "99.0.0")             # an upgrade replaces the package's files
    (machine["pkg"] / "server.py").write_text("print('new release')\n")
    assert server.check_integrity() == []


def test_doctor_sees_the_same_as_the_gateway(machine):
    """doctor once compared without the key files and version: keys.json always looked removed."""
    machine["data"].mkdir()
    (machine["data"] / "keys.json").write_text('{"keys": {}}')
    assert server.check_integrity() == []
    assert integrity.compare(server.KEYS_PATH.parent, server.integrity_now()) == []


def test_fail_closed_blocks_risky_actions_until_accepted(c, machine, monkeypatch, tmp_path):
    rules = tmp_path / "gw-rules.yaml"
    rules.write_text("default: allow\nintegrity: fail_closed\nrules:\n  - { id: pay, action: review, match: { name: 'pay.*' } }\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    server.policy._maybe_reload()
    server.check_integrity()
    machine["hook"].write_text("{}")
    server.check_integrity()
    d = c.post("/v1/events", headers=H, json={"name": "pay.send", "input": {"amount": 1}}).json()
    assert (d["decision"], d["rule_id"]) == ("deny", "integrity:fail-closed")
    assert c.post("/v1/events", headers=H, json={"name": "notes.read", "input": {}}).json()["decision"] == "allow"
    assert c.post("/v1/integrity/accept", headers=BOSS).status_code == 200
    assert c.post("/v1/events", headers=H, json={"name": "pay.send", "input": {"amount": 2}}).json()["decision"] == "review"


def test_alert_only_by_default(c, machine, monkeypatch, tmp_path):
    rules = tmp_path / "gw-rules.yaml"
    rules.write_text("default: allow\nrules:\n  - { id: pay, action: review, match: { name: 'pay.*' } }\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    server.policy._maybe_reload()
    server.check_integrity()
    machine["hook"].write_text("{}")
    assert server.check_integrity()
    assert c.post("/v1/events", headers=H, json={"name": "pay.send", "input": {"amount": 3}}).json()["decision"] == "review"
    assert c.get("/v1/integrity", headers=BOSS).json()["changes"]


def test_audit_verify_names_the_first_broken_link(c, capsys):
    c.post("/v1/events", headers=H, json={"name": "notes.read", "input": {}})
    assert server.main(["audit", "verify"]) == 0
    assert "Intact" in capsys.readouterr().out
    with server.engine.begin() as conn:
        row = conn.execute(server.select(server.audit_trail).order_by(server.audit_trail.c.seq.desc())).first()
        conn.execute(server.audit_trail.update().where(server.audit_trail.c.seq == row.seq).values(detail='{"x": 1}'))
    try:
        assert server.main(["audit", "verify"]) == 1
        assert f"entry #{row.seq}" in capsys.readouterr().out
    finally:
        with server.engine.begin() as conn:
            conn.execute(server.audit_trail.update().where(server.audit_trail.c.seq == row.seq).values(detail=row.detail))


def test_block_risky_while_unreachable(c, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "policy", server.Policy(ROOT / "rules.yaml"))
    server.policy._maybe_reload()
    monkeypatch.setenv("SQUIDBRAKE_OFFLINE_DIR", str(tmp_path))
    pol = c.get("/v1/policy/offline", headers=H).json()
    assert pol["default"] == "block_risky"
    url = f"http://gw-{uuid.uuid4().hex[:6]}.example"
    offline.save(url, pol)
    run = lambda name, inp: offline.decide(url, name=name, input=inp)[0]
    assert run("Read", {"file_path": "/repo/a.py"}) is True                          # reads carry on
    assert run("Edit", {"file_path": "/repo/a.py", "old_string": "a", "new_string": "b"}) is True
    assert run("Bash", {"command": "npm test"}) is True                              # everyday coding work
    assert run("Bash", {"command": "git push --force origin main"}) is False         # can't be undone
    assert run("Bash", {"command": "python -c 'import os; os.system(x)'"}) is False  # inline code that does things
    assert run("Bash", {"command": "python -c 'import json; print(1)'"}) is True      # inline code that only looks
    assert run("stripe.refund", {"amount": 5}) is False                              # would wait for a person
    assert run("Read", {"file_path": f"{HOME}/.squidbrake/data/secret.key"}) is False  # its own keys
    assert offline.decide(url, name="stripe.refund", input={}, fail_open=True)[0] is True


@pytest.mark.parametrize("line,where", [
    ("ssh prod-db 'psql -c \"DELETE FROM users\"'", "prod-db"),
    ("ssh -i key.pem -p 2222 deploy@box rm -rf /srv/app", "deploy@box"),
    ("docker exec -it -u root db psql -c 'DROP TABLE orders'", "container db"),
    ("kubectl exec -n prod api-0 -- rm -rf /data", "pod api-0"),
])
def test_commands_sent_elsewhere_are_read(line, where):
    r = commands.read(line)
    assert r.kind in ("irreversible", "catastrophic") and f"on {where}" in r.summary()


def test_edited_then_run_can_be_held(c, monkeypatch, tmp_path):
    rules = tmp_path / "r.yaml"
    rules.write_text("default: allow\ncommand_checks: { edited_then_run: review }\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    server.policy._maybe_reload()
    s = str(uuid.uuid4())
    post = lambda name, inp, **kw: c.post("/v1/events", headers=H, json={"name": name, "input": inp, "session_id": s,
                                                                        "source": "cc", **kw}).json()
    post("Edit", {"file_path": "/repo/deploy.py", "old_string": "a", "new_string": "b"}, output="ok")
    d = post("Bash", {"command": "python deploy.py"}, metadata={"cwd": "/repo"})
    assert (d["decision"], d["rule_id"]) == ("review", "command:edited_then_run_command")


def test_doctor_lists_what_each_agent_does_not_check():
    import connect
    agents = {a["name"]: a for a in connect.local_agents()}
    assert agents["codex"]["not_checked"].startswith("everything until the hook is trusted")
    assert all(a["checks"] and a["not_checked"] for a in agents.values())


def test_threat_model_names_every_open_gap():
    text = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    for gap in ("test_iam_escalation_chain_is_held", "What Squidbrake does not stop", "block_risky"):
        assert gap in text


def test_keys_changed_behind_squidbrakes_back_are_an_alert(machine):
    data = machine["data"]
    data.mkdir(parents=True, exist_ok=True)
    (data / "keys.json").write_text('{"keys": {}}')
    assert server.check_integrity() == []                         # first look: kept as the normal
    ks = server.KeyStore(data / "keys.json")
    ks.add("priya", approver=True, kind="person")                 # Squidbrake's own change: noted, not an alert
    assert server.check_integrity() == []
    (data / "keys.json").write_text('{"keys": {"me": {"sha256": "x", "approver": true}}}')   # edited by hand
    changes = server.check_integrity()
    assert {"kind": "keys", "what": "keys.json", "change": "changed"} in changes
    log = server.verify_audit_chain()                              # the alert is on the record too
    with server.engine.connect() as conn:
        assert conn.execute(server.select(server.audit_trail.c.action).where(
            server.audit_trail.c.action == "integrity.changed")).first()
    server.accept_integrity("tester")
