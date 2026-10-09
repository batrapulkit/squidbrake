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
    assert 'id="home"' in page and 'showView("activity")' in page and "releases/latest" in page


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
