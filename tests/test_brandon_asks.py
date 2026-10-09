"""What a pilot asked for (October 2026): connect just one agent, a warning before approving what can't be undone,
the logo back to Activity, the version and the latest release, and the audit trail kept in S3."""
import json
import sys
import time
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_server import BOSS, H, c, server  # noqa: E402,F401

import connect  # noqa: E402


# ---- connect just one agent

def test_connect_all_can_take_just_one_agent(monkeypatch):
    done = []
    monkeypatch.setattr(connect, "claude_code", lambda a: done.append("claude-code"))
    monkeypatch.setattr(connect, "agents", lambda a: done.append(f"hook:{a.agent}"))
    monkeypatch.setattr(connect, "guard", lambda a: done.append(f"mcp:{a.agent}"))
    monkeypatch.setattr(connect, "offer_counts", lambda: None)
    connect.connect_all(Namespace(url="http://localhost:8080", key="gw_x", remove=False, yes=True, only=["cursor"]))
    assert done == ["hook:cursor", "mcp:cursor"]
    done.clear()
    connect.connect_all(Namespace(url="http://localhost:8080", key="gw_x", remove=False, yes=True, only=None))
    assert "hook:all" in done and "mcp:all" in done
    with pytest.raises(SystemExit):
        connect.connect_all(Namespace(url="u", key="k", remove=False, yes=True, only=["notepad"]))


# ---- a warning before approving what can't be undone

def test_what_cant_be_undone_is_flagged_everywhere_it_is_approved(c):
    sid = f"undo-{time.time_ns()}"
    held = c.post("/v1/events", headers=H, json={"name": "Bash", "input": {"command": "git push --force origin main"},
                                                 "session_id": sid}).json()
    assert held["decision"] == "review"
    ev = c.get(f"/v1/events/{held['event_id']}", headers=BOSS).json()
    assert ev["cannot_undo"] is True
    routine = c.post("/v1/events", headers=H, json={"name": "deploy.staging", "input": {}, "session_id": sid}).json()
    assert c.get(f"/v1/events/{routine['event_id']}", headers=BOSS).json()["cannot_undo"] is False
    blocks = server.slack_blocks("t", "b", "tok", "https://x/a/tok", "soon", undo_warning=True)
    approve = next(e for b in blocks for e in b.get("elements", []) if e.get("action_id") == "approve")
    assert approve["confirm"]["title"]["text"] == "This can't be undone"
    for page in ("dashboard.html", "approve.html"):
        assert "e.cannot_undo" in (ROOT / page).read_text(encoding="utf-8") and "Approve anyway?" in (ROOT / page).read_text(encoding="utf-8")


# ---- the logo, the version, the latest release

def test_the_dashboard_shows_the_version_and_a_newer_one(c, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "HOME_DIR", tmp_path)
    assert c.get("/v1/me", headers=BOSS).json()["version"] == server.VERSION
    (tmp_path / "update-check.json").write_text(json.dumps({"latest": "99.0.0"}))
    assert c.get("/v1/me", headers=BOSS).json()["latest"] == "99.0.0"
    (tmp_path / "update-check.json").write_text(json.dumps({"latest": "0.0.1"}))
    assert c.get("/v1/me", headers=BOSS).json()["latest"] is None
    page = (ROOT / "dashboard.html").read_text(encoding="utf-8")
    assert 'id="home"' in page and 'showView("activity")' in page and "releases/tag/v" in page


# ---- the audit trail in S3

def test_the_audit_trail_goes_to_s3_once_a_day(c, monkeypatch):
    put = []

    class S3:
        def put_object(self, **kw):
            put.append(kw)
    fake = type(sys)("boto3")
    fake.client = lambda name, region_name=None: S3()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    with server.audited_tx() as conn:
        server.state_set(conn, "s3_archived", "")
    assert server.s3_archive({"s3_bucket": ""}) is None                   # not set up: nothing
    key = server.s3_archive({"s3_bucket": "acme-audit", "s3_prefix": "gw/"})
    assert key.startswith("gw/squidbrake-evidence-") and put[0]["Bucket"] == "acme-audit"
    body = json.loads(put[0]["Body"])
    assert body["format"] == "squidbrake-evidence/1" and body["entries"] and put[0]["ServerSideEncryption"] == "AES256"
    assert server.s3_archive({"s3_bucket": "acme-audit"}) is None and len(put) == 1   # once a day
    import verify                                                        # the copy in S3 checks out offline
    assert verify.verify(json.loads(json.dumps(body, default=str)))["chain"]["ok"]


# ---- every release page says how to install exactly that version

def test_release_notes_get_an_install_block_once():
    sys.path.insert(0, str(ROOT / ".github" / "scripts"))
    import install_notes
    once = install_notes.notes("v0.8.0", "What changed.")
    assert 'SQUIDBRAKE_VERSION="0.8.0"' in once and "SQUIDBRAKE_VERSION=0.8.0 sh" in once
    assert "pip install squidbrake==0.8.0" in once and "ghcr.io/batrapulkit/squidbrake:0.8.0" in once
    assert install_notes.notes("v0.8.0", once) is None                  # never twice
    wf = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "install_notes.py" in wf and "contents: write" in wf


# ---- a switch per agent, in the dashboard

def test_one_agent_can_be_switched_on_and_off_from_the_dashboard(c, monkeypatch, tmp_path):
    monkeypatch.setattr(connect.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(connect.shutil, "which", lambda name: None)
    monkeypatch.setattr(connect, "new_key", lambda name, url="": "gw_test_agents")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".codex").mkdir()
    agents = {a["name"]: a for a in c.get("/v1/agents/local", headers=BOSS).json()["agents"]}
    assert agents["cursor"]["present"] and not agents["cursor"]["connected"] and not agents["gemini-cli"]["present"]
    assert c.post("/v1/agents/local/cursor", headers=H, json={"on": True}).status_code == 403   # an agent's key: no
    r = c.post("/v1/agents/local/cursor", headers=BOSS, json={"on": True}).json()
    on = {a["name"]: a["connected"] for a in r["agents"]}
    assert on["cursor"] is True and on["codex"] is False                  # only the one switched on
    assert "agent_hook.py" in (tmp_path / ".cursor" / "hooks.json").read_text()
    r = c.post("/v1/agents/local/cursor", headers=BOSS, json={"on": False}).json()
    assert {a["name"]: a["connected"] for a in r["agents"]}["cursor"] is False
    assert c.post("/v1/agents/local/notepad", headers=BOSS, json={"on": True}).status_code == 404
    monkeypatch.setattr(server, "PUBLIC_URL", "https://gw.example.com")    # a gateway on a server: no switches
    assert c.get("/v1/agents/local", headers=BOSS).status_code == 404
    assert 'id="agentsHere"' in (ROOT / "dashboard.html").read_text(encoding="utf-8")


# ---- a person is told first that it can't be undone: their agent, their phone, their own terminal

def test_the_person_is_told_first_that_it_cant_be_undone(c, monkeypatch):
    d = c.post("/v1/events", headers=H, json={"name": "Bash", "input": {"command": "git push --force origin main"},
                                              "session_id": f"undo-first-{time.time_ns()}"}).json()
    assert d["decision"] == "review" and d["cannot_undo"] is True        # the hook says so in the agent's window
    assert "It can't be undone once it runs." in (ROOT / "claude_hook.py").read_text(encoding="utf-8")
    sent = []
    real = server.settings()
    monkeypatch.setattr(server, "settings", lambda: {**real,
                        "slack_webhook": "https://hooks.slack.com/x", "ntfy_topic": "", "public_url": "", "notify_as": "boss",
                        "ntfy_server": "https://ntfy.sh", "teams_webhook": "", "email_to": ""})
    monkeypatch.setattr(server, "email_ready", lambda cfg: False)
    monkeypatch.setattr(server.httpx, "post", lambda url, timeout=None, json=None, **k: sent.append(json) or
                        type("R", (), {"raise_for_status": lambda s: None})())
    monkeypatch.setattr(server.threading, "Thread", lambda target, daemon=None, **k: type(
        "T", (), {"start": lambda s: target()})())
    row = {"id": d["event_id"], "name": "Bash", "kind": "tool_call", "source": "x", "session_id": "s", "client": "tester",
           "rule_id": "command:irreversible_command", "reason": "rewrites history", "approval_deadline": "soon",
           "input": json.dumps({"command": "git push --force origin main"}), "signals": None}
    server.notify_approval_needed(row)
    assert sent and sent[0]["text"].startswith(":raised_hand: *Can't be undone:")


def test_the_terminal_guard_goes_in_and_out_of_the_startup_file(tmp_path):
    import shell_guard
    rc = tmp_path / ".bashrc"
    rc.write_text("export A=1\n")
    assert "Added" in shell_guard.write("bash", rc)
    assert "already" in shell_guard.write("bash", rc)                    # never twice
    text = rc.read_text()
    assert text.count(shell_guard.BEGIN) == 1 and "export A=1" in text and "shell-guard check" in text
    assert list(tmp_path.glob(".bashrc.bak-*"))                          # the old one kept
    assert "Took" in shell_guard.remove("bash", rc)
    assert rc.read_text() == "export A=1\n"
