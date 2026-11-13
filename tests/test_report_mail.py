"""The report email free sign-ups get: who is due, what it says, sent once per period, and the link that stops it."""
import json
import os
import sys
import tempfile
import threading
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "insights"))
os.environ.setdefault("INSIGHTS_DB", str(Path(tempfile.mkdtemp()) / "insights.db"))
os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")
os.environ.setdefault("HOSTED_DOMAIN", "app.example.com")     # read when app is imported: the same as the other
os.environ.setdefault("HOSTED_MAX", "2")                      # insights test files, whichever runs first

from fastapi.testclient import TestClient  # noqa: E402

import app as insights_app  # noqa: E402
import report_mail  # noqa: E402

TODAY, BASE, SECRET = date(2026, 11, 13), "https://example.test", "s3cret"
CODES = ("rm-active", "rm-quiet", "rm-stuck", "rm-paying", "rm-local")


def _seed():
    with insights_app.db() as c:
        for code in CODES:
            insights_app._forget(c, code)
            c.execute("DELETE FROM settings WHERE key LIKE ?", (f"report_%:{code}",))
        row = "INSERT INTO pilots (code, company, created_at, email, hosted, mrr) VALUES (?,?,?,?,?,?)"
        c.execute(row, ("rm-active", "A", "2026-11-01T00:00:00Z", "a@example.test", 1, 0))
        c.execute(row, ("rm-quiet", "Q", "2026-11-01T00:00:00Z", "q@example.test", 1, 0))     # used it, not lately
        c.execute(row, ("rm-stuck", "S", "2026-11-01T00:00:00Z", "s@example.test", 1, 0))     # never an action
        c.execute(row, ("rm-paying", "P", "2026-11-01T00:00:00Z", "p@example.test", 1, 19))
        c.execute(row, ("rm-local", "L", "2026-11-01T00:00:00Z", "l@example.test", 0, 0))     # local: silence is normal
        for code, day, counts in (("rm-active", "2026-11-12", {"events": 40, "would_hold": 3, "would_block": 1}),
                                  ("rm-active", "2026-11-01", {"events": 500, "would_hold": 9}),   # outside the period
                                  ("rm-quiet", "2026-11-02", {"events": 7}),
                                  ("rm-paying", "2026-11-12", {"events": 9, "would_hold": 2})):
            c.execute("INSERT OR IGNORE INTO installs (install_id, code, joined_at) VALUES (?,?,?)", (f"i-{code}", code, "2026-11-01"))
            c.execute("INSERT INTO days (install_id, day, counts) VALUES (?,?,?)", (f"i-{code}", day, json.dumps(counts)))
        c.execute("INSERT INTO catches (install_id, t, data) VALUES (?,?,?)", ("i-rm-active", "2026-11-12T10:05", json.dumps(
            {"t": "2026-11-12T10:05", "agent": "claude-code", "program": "rm", "why": "deletes many files", "outcome": "would_hold"})))


def _mine(c):
    return {m["code"]: m for m in report_mail.due(c, TODAY, BASE, SECRET) if m["code"] in CODES}


def test_who_is_due_and_what_it_says():
    _seed()
    with insights_app.db() as c:
        due = _mine(c)
    assert set(due) == {"rm-active", "rm-stuck"}           # not the paying one, the quiet one or the local one
    a = due["rm-active"]
    assert a["kind"] == "report" and "40 actions" in a["text"] and "500" not in a["text"]
    assert "3 of them would have waited" in a["text"] and "1 would have been blocked" in a["text"]
    assert "claude-code rm: deletes many files (would hold)" in a["text"]
    assert f"{BASE}/pricing" in a["text"] and a["off"] in a["text"]
    assert due["rm-stuck"]["kind"] == "nudge" and f"{BASE}/start/rm-stuck" in due["rm-stuck"]["text"]


def test_sent_once_per_period_and_the_nudge_only_once():
    _seed()
    sent = []
    mail = lambda m: m["code"] not in CODES or bool(sent.append(m["code"])) or True
    lock = threading.Lock()
    report_mail.run(insights_app.db, lock, BASE, SECRET, mail, TODAY)
    report_mail.run(insights_app.db, lock, BASE, SECRET, mail, TODAY)
    assert sorted(sent) == ["rm-active", "rm-stuck"]
    with insights_app.db() as c:                            # three days on with no new actions: nobody is due
        assert not {m["code"] for m in report_mail.due(c, date(2026, 11, 17), BASE, SECRET)} & set(CODES)


def test_the_stop_link_needs_its_token_and_a_click():
    _seed()
    old = insights_app.ADMIN_KEY
    with TestClient(insights_app.app) as web:
        t = report_mail.off_token(old, "rm-active")
        assert web.get("/v1/report/off", params={"code": "rm-active", "t": "wrong"}).status_code == 404
        assert web.get("/v1/report/off", params={"code": "rm-active", "t": t}).status_code == 200
        with insights_app.db() as c:                        # opening the link (a mail scanner) stops nothing
            assert "rm-active" in _mine(c)
        assert web.post("/v1/report/off", params={"code": "rm-active", "t": t}).status_code == 200
        with insights_app.db() as c:
            assert "rm-active" not in _mine(c)
        prev = web.get("/v1/admin/reports/preview", headers={"X-Admin-Key": old}).json()
        assert prev["sending"] is False and web.get("/v1/admin/reports/preview").status_code in (401, 403)
    with insights_app.db() as c:
        for code in CODES:
            insights_app._forget(c, code)
