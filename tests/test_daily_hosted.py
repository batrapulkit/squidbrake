"""The dashboards we host get the end-of-day email from squidbrake.com (insights), made from the counts their gateway
already shares: no commands, every day (a nudge on a quiet day), once, and never after "stop these emails"."""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "insights"))
os.environ.setdefault("INSIGHTS_DB", str(Path(tempfile.mkdtemp()) / "insights.db"))
os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")
os.environ.setdefault("HOSTED_DOMAIN", "app.example.com")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

EVENING = datetime(2026, 10, 13, 19, 0, tzinfo=timezone.utc)
CODES = ("daily-busy", "daily-quiet", "daily-new", "daily-off-co")


@pytest.fixture()
def hosted():
    import app as ia
    with ia.db() as c:
        for code in CODES:
            ia._forget(c, code)
        for code, sub in zip(CODES, ("busy", "quiet", "newbie", "offco")):
            c.execute("INSERT INTO pilots (code, company, created_at, hosted, subdomain, state, email) "
                      "VALUES (?,?,?,1,?,'running',?)", (code, code, ia.now(), sub, f"founder@{sub}.example"))
        for code, total in (("daily-busy", 40), ("daily-quiet", 9)):     # quiet: used before, nothing today
            c.execute("INSERT INTO installs (install_id, code, joined_at, total_events) VALUES (?,?,?,?)",
                      (f"i-{code}", code, ia.now(), total))
        c.execute("INSERT INTO days (install_id, day, counts) VALUES (?,?,?)", ("i-daily-busy", "2026-10-13", json.dumps(
            {"events": 30, "real": 25, "held": 2, "approved": 1, "rejected": 1, "blocked": 1})))
        c.execute("INSERT INTO catches (install_id, t, data) VALUES (?,?,?)", ("i-daily-busy", "2026-10-13T11:42", json.dumps(
            {"t": "2026-10-13T11:42", "agent": "claude-code", "tool": "Bash", "program": "rm", "rule":
             "command:catastrophic_command", "why": "Deletes a home folder", "outcome": "blocked",
             "saved": {"files": 48213}})))
    with TestClient(ia.app) as client:
        yield ia, client
    with ia.db() as c:
        for code in CODES:
            ia._forget(c, code)


def test_every_hosted_owner_gets_one_email_a_day(hosted):
    ia, _ = hosted
    mails = {}
    send = lambda to, subject, text, html, off: mails.setdefault(to, (subject, text, html, off)) and True
    assert ia.maybe_send_daily(EVENING.replace(hour=9), send) == 0          # not before the evening
    ia.maybe_send_daily(EVENING, send)
    ia.maybe_send_daily(EVENING, send)                                       # the loop runs every 10 minutes
    ours = {k: v for k, v in mails.items() if k.split("@")[1].split(".")[0] in ("busy", "quiet", "newbie", "offco")}
    assert len(ours) == 4

    subject, text, html, off = ours["founder@busy.example"]
    assert "close call" in subject or "saved your day" in subject or "risky" in subject
    assert "$ rm …" in html and "Touches 48,213 files" in html and "docker.com/blog" in html   # program and size only
    assert "https://busy.app.example.com/dashboard" in html
    assert off.startswith("https://") and "/daily-off/daily-busy?t=" in off and off in html

    assert ours["founder@quiet.example"][0] in ia.daily.SUBJECTS["miss"]
    assert "Meanwhile, somewhere without a brake" in ours["founder@quiet.example"][2]
    new = ours["founder@newbie.example"]
    assert new[0] in ia.daily.SUBJECTS["new"] and "/start/daily-new" in new[2] and "Connect my first agent" in new[2]


def test_stop_these_emails_link(hosted):
    ia, client = hosted
    assert client.get("/daily-off/daily-off-co?t=wrong").status_code == 404
    r = client.get(f"/daily-off/daily-off-co?t={ia.daily_off_token('daily-off-co')}")
    assert r.status_code == 200 and "No more daily emails" in r.text
    mails = []
    ia.maybe_send_daily(EVENING, lambda to, *a: mails.append(to) or True)
    assert "founder@offco.example" not in mails and "founder@busy.example" in mails


def test_without_smtp_nothing_is_sent(hosted, monkeypatch):
    ia, _ = hosted
    monkeypatch.setitem(ia.SMTP, "host", "")
    assert ia.maybe_send_daily(EVENING) == 0
