"""What pilots ran into (October 2026): a stop nobody could see, stopped counts that were really a stop, installs with
no agent connected, old versions, and rules everyone approves."""
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_server import BOSS, H, c, server  # noqa: E402,F401


@pytest.fixture()
def clean_stop():
    def reset():
        with server.audited_tx() as conn:                 # exactly as a fresh gateway has it (other tests compare)
            server.state_set(conn, "stop", {"all": None, "agents": {}})
    reset()
    yield
    reset()


def post(c, name="notes.add", **kw):
    return c.post("/v1/events", headers=H, json={"name": name, "input": {}, "source": "fb-agent",
                                                 "session_id": f"fb-{time.time_ns()}", **kw}).json()


# ---- 1. the agent is told it's a stop, and how to end it

def test_a_stopped_agent_is_told_how_to_turn_it_off(c, clean_stop):
    c.post("/v1/controls/stop", headers=BOSS, json={"reason": "incident"})
    d = post(c)
    assert d["decision"] == "deny" and d["rule_id"] == "emergency-stop"
    assert "emergency stop is ON" in d["reason"] and "since" in d["reason"] and "(incident)" in d["reason"]
    assert f"{server.CLI} resume" in d["reason"] and "/dashboard" in d["reason"]


def test_squidbrake_resume_turns_it_off(c, clean_stop, capsys):
    c.post("/v1/controls/stop", headers=BOSS, json={})
    assert server.main(["resume"]) == 0 and "Resumed all agents" in capsys.readouterr().out
    assert post(c)["decision"] == "allow"
    assert server.main(["resume"]) == 0 and "Nothing to resume" in capsys.readouterr().out


def test_a_conversation_stop_says_which_resume(c, clean_stop):
    sid = f"conv-{time.time_ns()}"
    c.post("/v1/controls/stop", headers=BOSS, json={"session": sid})
    d = c.post("/v1/events", headers=H, json={"name": "notes.add", "input": {}, "session_id": sid}).json()
    assert d["rule_id"] == "session-stop" and f"resume --session {sid}" in d["reason"]
    server.resume_stop(None, sid, "test")


# ---- 2. it ends by itself, and asks once if it's been on a while

def test_a_stop_for_an_hour_ends_by_itself(c, clean_stop):
    c.post("/v1/controls/stop", headers=BOSS, json={"minutes": 60})
    d = post(c)
    assert d["decision"] == "deny" and "until" in d["reason"]
    with server.audited_tx() as conn:
        s = server.state_get("stop", {})
        s["all"]["until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        server.state_set(conn, "stop", s)
    assert post(c)["decision"] == "allow"


def test_a_long_stop_asks_once_whether_it_was_meant(c, clean_stop, monkeypatch):
    sent = []
    monkeypatch.setattr(server, "notify_text", lambda title, text: sent.append((title, text)))
    monkeypatch.setattr(server.threading, "Thread", lambda target, args, daemon: type(
        "T", (), {"start": lambda self: target(*args)})())
    c.post("/v1/controls/stop", headers=BOSS, json={})
    post(c)
    assert sent == []                                                  # just switched on: nothing yet
    with server.audited_tx() as conn:
        s = server.state_get("stop", {})
        s["all"]["at"] = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat().replace("+00:00", "Z")
        server.state_set(conn, "stop", s)
    post(c, name="deploy.run")
    post(c, name="deploy.run")
    assert len(sent) == 1 and "did you mean to leave this on?" in sent[0][1] and "deploy.run" in sent[0][1]


def test_resume_waits_for_a_person_when_an_agent_runs_it():
    import commands
    assert commands.read("squidbrake resume").kind == "irreversible"


# ---- 3. a stop's blocks aren't "stopped" (pilot counts and the pilots dashboard)

def test_pilot_counts_keep_a_stop_apart_from_what_rules_blocked(c, clean_stop):
    import pilot
    c.post("/v1/controls/stop", headers=BOSS, json={})
    for _ in range(3):
        post(c)
    server.resume_stop(None, None, "test")
    post(c, name="Bash", input={"command": "rm -rf ~/"})                   # blocked by a rule
    u = pilot.usage(server.engine, server.events, "enforce", 1, "1.0", connected=["cursor"])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert u["days"][today]["paused"] >= 3 and u["connected"] == ["cursor"]
    with server.engine.connect() as conn:
        from sqlalchemy import func, select
        rule_blocks = conn.execute(select(func.count()).where(
            server.events.c.status == "denied", server.events.c.decided_by.is_(None),
            server.events.c.created_at >= today, server.events.c.rule_id.notin_(pilot.PAUSE_RULES))).scalar()
    assert u["days"][today]["blocked"] == rule_blocks


from test_pilot import insights  # noqa: E402,F401  (the pilots server, with its throwaway database)

ADMIN = {"X-Admin-Key": "admin-test-key"}


def _install(insights, company, version="0.6.9"):
    code = insights.post("/v1/admin/pilots", headers=ADMIN, json={"company": company}).json()["code"]
    iid = f"{time.time_ns():032x}"[-32:]
    assert insights.post("/v1/pilot/join", json={"code": code, "install_id": iid, "version": version}).status_code == 200
    return code, iid


def _ping(insights, code, iid, **usage):
    r = insights.post("/v1/ping", json={"code": code, "install_id": iid, "usage": {"version": "0.6.9", **usage}})
    assert r.status_code == 200, r.text


def _row(insights, code):
    return next(p for p in insights.get("/v1/admin/overview", headers=ADMIN).json()["pilots"] if p["code"] == code)


def test_the_pilots_dashboard_counts_a_stop_apart(insights):
    code, iid = _install(insights, "Brandon Co")
    now = datetime.now(timezone.utc)
    t = now.strftime("%Y-%m-%dT%H:%M")
    catches = [{"t": t, "rule": "emergency-stop", "outcome": "blocked"} for _ in range(13)] +               [{"t": t, "rule": "command:catastrophic_command", "outcome": "blocked", "program": "rm"}]
    # a gateway from before 0.8: its "blocked" includes the stop's 13
    _ping(insights, code, iid, days={now.strftime("%Y-%m-%d"): {"events": 20, "blocked": 14}}, catches=catches,
          total_events=20)
    row = _row(insights, code)
    assert row["stopped"] == 1 and row["paused"] == 13 and row["week"]["blocked"] == 1
    assert insights.get("/v1/admin/overview", headers=ADMIN).json()["week"]["paused"] >= 13
    tr = insights.get("/v1/admin/traction", headers=ADMIN).json()
    assert tr["paused_this_week"] >= 13


def test_installed_but_no_agent_connected_is_its_own_stage(insights):
    code, iid = _install(insights, "AJ Co")
    _ping(insights, code, iid, connected=[], total_events=0)
    assert _row(insights, code)["stage"] == "installed · agent not connected"
    _ping(insights, code, iid, connected=["cursor"], total_events=0)
    row = _row(insights, code)
    assert row["stage"] == "agent connected" and row["connected"] == ["cursor"]
    steps = [s["step"] for s in insights.get("/v1/admin/traction", headers=ADMIN).json()["funnel"]]
    assert steps.index("Set up (keys or install)") < steps.index("Agent connected") < steps.index("First action")


def test_an_old_version_is_tagged(insights, monkeypatch):
    import app as insights_app
    monkeypatch.setattr(insights_app, "oss_numbers", lambda: {"latest_version": "0.8.0"})
    code, iid = _install(insights, "Kaustubh Co")
    _ping(insights, code, iid)
    assert _row(insights, code)["outdated"] is True
    monkeypatch.setattr(insights_app, "oss_numbers", lambda: {"latest_version": "0.6.9"})
    assert _row(insights, code)["outdated"] is False


def test_a_rule_everyone_approves_is_pointed_out(insights):
    code, iid = _install(insights, "Shield Co")
    t = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    catches = [{"t": t, "rule": "approve-git-push", "outcome": "approved", "decide_s": 9} for _ in range(9)] +               [{"t": t, "rule": "approve-refunds", "outcome": "approved"}, {"t": t, "rule": "approve-refunds", "outcome": "rejected"}]
    _ping(insights, code, iid, catches=catches)
    by = {r["rule"]: r for r in _row(insights, code)["rule_approvals"]}
    assert by["approve-git-push"]["approve_pct"] == 100 and by["approve-git-push"]["always_allowed"]
    assert by["approve-refunds"]["approve_pct"] == 50 and not by["approve-refunds"]["always_allowed"]


# ---- 5. an old version says so

def test_an_old_version_says_how_to_upgrade(monkeypatch, tmp_path):
    from squidbrake import cli
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    for k in ("CI", "DO_NOT_TRACK", "SQUIDBRAKE_NO_UPDATE_CHECK"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    (tmp_path / "update-check.json").write_text(json.dumps({"checked": time.time(), "latest": "0.8.0"}))
    note = cli.update_notice(["doctor"], "0.6.9")
    assert note and "New version 0.8.0 available (you have 0.6.9)" in note and "squidbrake" in note
    assert cli.update_notice(["doctor"], "0.8.0") is None                 # up to date
    assert cli.update_notice(["agent-hook", "cursor"], "0.6.9") is None   # never in a hook
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    assert cli.update_notice(["doctor"], "0.6.9") is None


def test_agents_with_the_hook_are_found(monkeypatch, tmp_path):
    import connect
    monkeypatch.setattr(connect.Path, "home", classmethod(lambda cls: tmp_path))
    (tmp_path / ".cursor").mkdir()
    assert connect.connected_agents() == []
    (tmp_path / ".cursor" / "hooks.json").write_text('{"hooks": {"beforeShellExecution": [{"command": "py agent_hook.py cursor"}]}}')
    assert connect.connected_agents() == ["cursor"]
