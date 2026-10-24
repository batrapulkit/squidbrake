"""Phase 4: what an agent's earlier steps give it is kept per identity, until it expires, and chains are judged from
it: split across conversations, across agents, and across a restart."""
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_server import BOSS, H, c, server  # noqa: E402,F401

RULES = """
default: allow
command_checks: { irreversible: off }   # chains on their own: db.wipe would otherwise wait as a delete
sequences:
  - id: wipe-after-backups-off
    action: review
    reason: Wiping a database right after its backups were turned off
    match: { name: "db.wipe" }
    after: { match: { name: "db.backups_off" }, scope: identity, within_hours: WITHIN, same_target: true }
"""


@pytest.fixture()
def rules(monkeypatch, tmp_path):
    def load(within=24):
        path = tmp_path / f"rules-{time.time_ns()}.yaml"
        path.write_text(RULES.replace("WITHIN", str(within)))
        monkeypatch.setattr(server, "policy", server.Policy(path))
        server.policy._maybe_reload()
        assert server.policy.sequences
    load()
    return load


def act(c, name, db, session, source="claude-code", **kw):
    return c.post("/v1/events", headers=H, json={"name": name, "input": {"id": db}, "session_id": session,
                                                 "source": source, **kw}).json()


def test_chain_split_across_two_conversations(c, rules):
    db = f"db-{uuid.uuid4().hex[:6]}"
    act(c, "db.backups_off", db, "monday", output="ok")
    d = act(c, "db.wipe", db, "tuesday")
    assert d["rule_id"] == "sequence:wipe-after-backups-off" and "in another conversation" in d["reason"]
    assert act(c, "db.wipe", "some-other-db", "tuesday")["decision"] == "allow"     # same_target: only that database


def test_chain_split_across_two_agents(c, rules):
    db = f"db-{uuid.uuid4().hex[:6]}"
    act(c, "db.backups_off", db, "a", source="cursor", output="ok")
    d = act(c, "db.wipe", db, "b", source="claude-code")
    assert d["rule_id"] == "sequence:wipe-after-backups-off" and "by cursor" in d["reason"]


def test_expired_capability_stops_counting(c, rules):
    rules(within=0.0003)            # about a second
    db = f"db-{uuid.uuid4().hex[:6]}"
    act(c, "db.backups_off", db, "a", output="ok")
    assert act(c, "db.wipe", db, "a")["decision"] == "review"
    time.sleep(1.3)
    assert act(c, "db.wipe", db, "a")["decision"] == "allow"


def test_only_steps_that_went_ahead_count(c, rules):
    db = f"db-{uuid.uuid4().hex[:6]}"
    failed = act(c, "db.backups_off", db, "a")                                      # allowed, result not in yet
    assert c.post(f"/v1/events/{failed['event_id']}/result", headers=H, json={"error": "permission denied"}).status_code == 200
    assert act(c, "db.wipe", db, "a")["decision"] == "allow"                        # it failed: it gave nothing
    act(c, "db.backups_off", db, "a")
    assert act(c, "db.wipe", db, "a")["decision"] == "review"                       # allowed and pending: it counts
    listed = c.get("/v1/capabilities", headers=BOSS).json()["capabilities"]
    mine = [x for x in listed if x["target"] == db]
    assert mine and mine[0]["chain"].startswith("Wiping a database") and mine[0]["identity"] == "this-computer"


def test_identity_on_a_team_gateway_is_the_person(monkeypatch, tmp_path):
    ks = server.KeyStore(tmp_path / "keys.json")
    ks.ensure_initialized()
    ks.add("priya", approver=True, kind="person")
    ks.add("priya-claude", kind="agent", owner="priya")
    ks.add("priya-cursor", kind="agent", owner="priya")
    ks.add("omar-claude", kind="agent")
    monkeypatch.setattr(server, "keystore", ks)
    monkeypatch.setattr(server, "PUBLIC_URL", "https://gw.example.com")
    assert server.identity_of("priya-claude") == server.identity_of("priya-cursor") == "person:priya"
    assert server.identity_of("omar-claude") == "key:omar-claude"
    monkeypatch.setattr(server, "PUBLIC_URL", "")
    assert server.identity_of("omar-claude") == "this-computer"


STEP = """
import os, sys
sys.path.insert(0, sys.argv[1])
from fastapi.testclient import TestClient
import server
with TestClient(server.app) as c:
    d = c.post("/v1/events", headers={"X-Gateway-Key": "k1"}, json={"name": sys.argv[2], "input": {"id": "prod"},
               "session_id": sys.argv[3], **({"output": "ok"} if sys.argv[2] == "db.backups_off" else {})}).json()
    print(d["decision"], d["rule_id"])
"""


def test_state_survives_a_restart(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(RULES.replace("WITHIN", "24"))
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{(tmp_path / 'gw.db').as_posix()}", "RULES_PATH": str(rules),
           "GATEWAY_API_KEYS": "tester:k1", "GATEWAY_APPROVERS": "", "LOG_LEVEL": "ERROR"}
    run = lambda name, session: subprocess.run([sys.executable, "-c", STEP, str(ROOT), name, session], env=env,
                                               capture_output=True, text=True, timeout=120).stdout.split()
    assert run("db.backups_off", "first") == ["allow", "None"]
    assert run("db.wipe", "second") == ["review", "sequence:wipe-after-backups-off"]      # a new process
