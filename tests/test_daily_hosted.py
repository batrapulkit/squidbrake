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
            for table in ("days", "catches", "installs"):     # a deleted pilot's counts are kept: clear this test's own
                c.execute(f"DELETE FROM {table} WHERE install_id=?", (f"i-{code}",))
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
            for table in ("days", "catches", "installs"):     # a deleted pilot's counts are kept: clear this test's own
                c.execute(f"DELETE FROM {table} WHERE install_id=?", (f"i-{code}",))


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


def test_a_quiet_dashboard_gets_the_email_for_three_days_then_weekly(hosted):
    # nothing to report (never connected, or no actions today): a daily nag would teach the inbox it's spam
    ia, _ = hosted
    from datetime import timedelta
    for age, expect in ((1, True), (4, False), (7, True), (9, False), (14, True)):
        with ia.db() as c:
            c.execute("DELETE FROM daily_sent WHERE code IN ('daily-quiet', 'daily-new', 'daily-busy')")
            for code in ("daily-quiet", "daily-new", "daily-busy"):
                c.execute("UPDATE pilots SET created_at=? WHERE code=?", ((EVENING - timedelta(days=age)).isoformat(), code))
        got = []
        ia.maybe_send_daily(EVENING, lambda to, s, t, h, off: got.append(to) or True)
        assert ("founder@quiet.example" in got) is expect and ("founder@newbie.example" in got) is expect, age
        assert "founder@busy.example" in got, age                     # a day with actions always gets its email


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


def test_the_start_page_gives_the_time_zone(hosted):
    ia, client = hosted
    tz = lambda: ia.db().execute("SELECT tz FROM pilots WHERE code='daily-busy'").fetchone()[0]
    assert client.post("/v1/pilot/daily-busy/seen", json={"tz": "Asia/Kolkata"}).json()["ok"]
    assert tz() == "Asia/Kolkata"
    client.post("/v1/pilot/daily-busy/seen", json={"tz": "Not/A_Zone"})           # unknown: kept as it was
    client.post("/v1/pilot/daily-busy/seen", json={"tz": "../../etc/passwd"})
    client.post("/v1/pilot/daily-busy/seen")                                      # an older start page: no body
    assert tz() == "Asia/Kolkata"


def test_sent_at_7pm_in_each_owners_own_time(hosted):
    ia, _ = hosted
    with ia.db() as c:
        c.execute("UPDATE pilots SET tz='Asia/Kolkata' WHERE code='daily-busy'")
        c.execute("UPDATE pilots SET tz='America/New_York' WHERE code='daily-quiet'")
    got = []
    send = lambda to, subject, text, html, off: got.append((to, html)) or True
    at = lambda h, m: datetime(2026, 10, 13, h, m, tzinfo=timezone.utc)
    ia.maybe_send_daily(at(13, 0), send)                  # 18:30 in Kolkata, 09:00 in New York
    assert not [to for to, _ in got if to in ("founder@busy.example", "founder@quiet.example")]
    ia.maybe_send_daily(at(13, 40), send)                 # 19:10 in Kolkata
    busy = [h for to, h in got if to == "founder@busy.example"]
    assert len(busy) == 1 and "17:12 IST" in busy[0]      # the catch at 11:42 UTC, in their time
    assert "founder@quiet.example" not in [to for to, _ in got]
    ia.maybe_send_daily(at(23, 10), send)                 # 19:10 in New York
    ia.maybe_send_daily(at(23, 50), send)
    assert [to for to, _ in got].count("founder@quiet.example") == 1
    assert [to for to, _ in got].count("founder@busy.example") == 1   # 04:40 the next day in Kolkata: not yet again
