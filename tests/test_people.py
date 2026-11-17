"""The admin's People list: everyone known by email, one row each, from every way in (pip registration, website
sign-up, demo request), with where they came from. The website's first touch is kept as short text only: a referrer
without its query string, a landing path, known keys."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "insights"))
os.environ.setdefault("INSIGHTS_DB", str(Path(tempfile.mkdtemp()) / "insights.db"))
os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN = {"X-Admin-Key": os.environ["INSIGHTS_ADMIN_KEY"]}
REG_ID = "ab" * 16


@pytest.fixture(scope="module")
def insights():
    import app as insights_app
    insights_app._requests.clear()       # the per-address limit sign-ups share with the team request form
    with TestClient(insights_app.app) as c:
        yield c
    with insights_app.db() as db:
        for (code,) in db.execute("SELECT code FROM pilots WHERE email IN ('cy@beta.dev')").fetchall():
            insights_app._forget(db, code)
        db.execute("DELETE FROM registrations WHERE id=?", (REG_ID,))
        db.execute("DELETE FROM team_requests WHERE email IN ('bo@acme.dev')")
    insights_app._requests.clear()


def test_attribution_keeps_known_keys_as_short_text():
    import app as insights_app
    import json
    a = json.loads(insights_app._attribution({
        "utm_source": "Newsletter", "utm_campaign": "x" * 500, "referrer": "https://news.ycombinator.com/item?id=1#c",
        "landing": "/blog/post?utm_source=a", "first_seen": 5, "evil": "x", "from": " "}))
    assert a == {"utm_source": "Newsletter", "utm_campaign": "x" * 150, "referrer": "https://news.ycombinator.com/item",
                 "landing": "/blog/post"}
    assert insights_app._attribution({"referrer": "javascript:alert(1)"}) is None
    assert insights_app._attribution(None) is None


def test_people_joins_every_way_in_by_email(insights):
    assert insights.post("/v1/register", json={"id": REG_ID, "email": "Bo@Acme.dev", "name": "Bo", "company": "Acme",
                                               "ref": "linkedin", "agents": ["claude-code"], "install": "pip"}).status_code == 200
    assert insights.post("/v1/team-request", json={"name": "Bo", "email": "bo@acme.dev", "company": "Acme",
                                                   "team_size": "6-20", "note": "audit in March"}).json() == {"ok": True}
    r = insights.post("/v1/signup", json={"name": "Cy", "email": "cy@beta.dev", "company": "Beta", "agents": ["cursor"],
                                          "setup": "local", "attribution": {"utm_source": "Newsletter",
                                          "referrer": "https://www.google.com/search?q=secret", "landing": "/pricing"}})
    assert r.status_code == 200, r.text

    assert insights.get("/v1/admin/people").status_code == 401
    ppl = {p["email"]: p for p in insights.get("/v1/admin/people", headers=ADMIN).json()["people"]}
    bo, cy = ppl["bo@acme.dev"], ppl["cy@beta.dev"]
    assert bo["name"] == "Bo" and bo["company"] == "Acme" and bo["source"] == "linkedin"
    assert set(bo["ways"]) == {"pip", "demo request"} and "team of 6-20" in bo["notes"] and bo["agents"] == ["claude-code"]
    assert cy["ways"] == ["signup"] and cy["company"] == "Beta" and cy["agents"] == ["cursor"]
    assert cy["attribution"] == {"utm_source": "Newsletter", "referrer": "https://www.google.com/search", "landing": "/pricing"}

    rows = {r["channel"]: r for r in insights.get("/v1/admin/sources", headers=ADMIN).json()["rows"]}
    assert rows["newsletter"]["signups"] == 1


def test_every_public_page_counts_visits_and_keeps_first_touch():
    site = ROOT / "insights" / "site"
    pages = [p for p in [*site.glob("*.html"), *(site / "blog").glob("*.html")] if p.name != "card.html"]
    pages += [ROOT / "insights" / n for n in ("signup.html", "team.html", "get.html")]
    for p in pages:
        t = p.read_text()
        assert "plausible.io/js/" in t and "/assets/touch.js" in t, p.name
    assert "plausible" not in (ROOT / "insights" / "start.html").read_text()   # its address holds the setup code
