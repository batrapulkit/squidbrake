"""Pilot usage sharing: nothing without joining, only counts when joined, and the insights service guards its doors."""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "insights"))
if "server" not in sys.modules:   # run on its own: a throwaway database (test_server.py sets the same keys)
    _tmp = Path(tempfile.mkdtemp())
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(_tmp / 'gw.db').as_posix()}")
    os.environ.setdefault("RULES_PATH", str(_tmp / "rules.yaml"))
    os.environ.setdefault("GATEWAY_API_KEYS", "tester:k1,boss:k2,boss2:k3")
    os.environ.setdefault("GATEWAY_APPROVERS", "boss,boss2")
os.environ["INSIGHTS_DB"] = str(Path(tempfile.mkdtemp()) / "insights.db")
os.environ["INSIGHTS_ADMIN_KEY"] = "admin-test-key"
os.environ["HOSTED_DOMAIN"] = "app.example.com"
os.environ["HOSTED_MAX"] = "2"

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import pilot  # noqa: E402

SECRET = "PLANTED-MARKER-not-a-real-secret"   # must never show up in what a pilot install sends


@pytest.fixture(scope="module")
def insights():
    import app as insights_app
    with TestClient(insights_app.app) as c:
        yield c


@pytest.fixture()
def gateway():
    import server
    with TestClient(server.app) as c:
        yield server, c


def test_usage_is_counts_only(gateway):
    server, c = gateway
    c.post("/v1/events", headers={"X-Gateway-Key": "k1"}, json={
        "name": "Bash", "source": "pilot-test", "input": {"command": f"echo {SECRET} > .env"}})
    u = pilot.usage(server.engine, server.events, "enforce", 3, "9.9.9")
    text = json.dumps(u)
    assert SECRET not in text and "echo" not in text and ".env" not in text   # no content, ever
    assert u["agents"].get("pilot-test", 0) >= 1 and u["version"] == "9.9.9"
    assert all(set(day) >= {"events", "held", "blocked", "approved"} for day in u["days"].values())


def test_nothing_is_sent_without_joining(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(a))
    assert pilot.send(tmp_path, {"days": {}}) is False and calls == []


def test_link_previews_are_not_views(insights):
    """LinkedIn, Slack and mail scanners fetch a pasted link for its preview; only the page running in a browser counts."""
    admin = {"X-Admin-Key": "admin-test-key"}
    code = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Previewed"}).json()["code"]
    views = lambda: next(p for p in insights.get("/v1/admin/overview", headers=admin).json()["pilots"]
                         if p["code"] == code)["page_views"]
    insights.get(f"/start/{code}", headers={"User-Agent": "LinkedInBot/1.0 (compatible; Mozilla/5.0)"})
    insights.post(f"/v1/pilot/{code}/seen", headers={"User-Agent": "Slackbot-LinkExpanding 1.0"})
    assert views() == 0
    insights.post(f"/v1/pilot/{code}/seen", headers={"User-Agent": "Mozilla/5.0 (Macintosh) Chrome/129.0 Safari/537.36"})
    assert views() == 1


def test_join_ping_leave(insights, tmp_path, monkeypatch):
    admin = {"X-Admin-Key": "admin-test-key"}
    assert insights.post("/v1/admin/pilots", json={"company": "Acme"}).status_code == 401
    code = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Acme"}).json()["code"]
    assert insights.get(f"/start/{code}").status_code == 200 and "Acme" in insights.get(f"/start/{code}").text
    assert insights.get("/start/no-such-code").status_code == 404

    # the gateway side talks to the in-process insights service
    path_of = lambda url: "/" + url.split("://", 1)[1].split("/", 1)[1]          # http://localhost/v1/x -> /v1/x
    monkeypatch.setattr(pilot.httpx, "post", lambda url, json, timeout: insights.post(path_of(url), json=json))
    assert pilot.join(tmp_path, "nope-000000", "http://localhost", True, "1.0") == 1          # unknown code
    assert pilot.join(tmp_path, code, "http://localhost", True, "1.0") == 0
    cfg = pilot.load(tmp_path)
    from datetime import datetime, timedelta, timezone
    long_ago = (datetime.now(timezone.utc) - timedelta(days=40)).strftime("%Y-%m-%d")   # outside every window below
    usage = {"version": "1.0", "agents": {"claude-code": 5}, "rules_hit": {"command:catastrophic_command": 1},
             "days": {long_ago: {"events": 5, "held": 2, "blocked": 1}, "../../etc": {"events": 9}}, "total_events": 5}
    assert pilot.send(tmp_path, usage) is True
    p = next(p for p in insights.get("/v1/admin/overview", headers=admin).json()["pilots"] if p["code"] == code)
    assert p["installs"] == 1 and p["agents"] == {"claude-code": 5} and p["total_events"] == 5

    # the weekly scorecard: active today, this week and last week (retention), and how many holds were approved
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)  # pilots and insights both count days in UTC
    today, last_week = now.strftime("%Y-%m-%d"), (now - timedelta(days=9)).strftime("%Y-%m-%d")
    assert pilot.send(tmp_path, {**usage, "days": {today: {"events": 7, "held": 4, "approved": 3, "rejected": 1, "blocked": 1},
                                                   last_week: {"events": 2}}}) is True
    d = insights.get("/v1/admin/overview", headers=admin).json()
    s, p = d["scorecard"], next(p for p in d["pilots"] if p["code"] == code)
    assert p["active_today"] and p["days_last_week"] == 1
    assert s["active_today"] >= 1 and s["retained"] >= 1 and s["active_last_week"] >= 1 and s["approve_rate"] is not None

    # pings from an install that never joined (or left) are refused
    stranger = {"code": code, "install_id": "f" * 32, "usage": usage}
    assert insights.post("/v1/ping", json=stranger).status_code == 403
    assert pilot.leave(tmp_path) == 0 and pilot.load(tmp_path) is None
    again = {"code": code, "install_id": cfg["install_id"], "usage": usage}
    assert insights.post("/v1/ping", json=again).status_code == 403


def test_hosted_pilot_lifecycle(insights):
    admin = {"X-Admin-Key": "admin-test-key"}
    r = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Hosted Co", "hosted": True}).json()
    code, dash = r["code"], r["dashboard"]
    assert dash == "https://hosted-co.app.example.com"
    # Caddy may only get certificates for hosted pilots that exist
    assert insights.get("/v1/caddy/ask", params={"domain": "hosted-co.app.example.com"}).status_code == 200
    assert insights.get("/v1/caddy/ask", params={"domain": "evil.app.example.com"}).status_code == 404
    assert insights.get("/v1/caddy/ask", params={"domain": "hosted-co.app.example.com.attacker.io"}).status_code == 404
    # the provisioner sees it, starts it and reports the keys; the keys are never in the admin overview
    q = insights.get("/v1/admin/provision", headers=admin).json()["pilots"]
    assert any(p["code"] == code and p["state"] == "requested" and p["keys_ready"] is False for p in q)
    assert insights.get("/v1/admin/provision").status_code == 401
    assert insights.post("/v1/admin/provisioned", json={"code": code, "state": "running"}).status_code == 401
    insights.post("/v1/admin/provisioned", headers=admin, json={"code": code, "state": "running",
                                                                "admin_key": "gw_admin_xyz", "agent_key": "gw_agent_xyz"})
    overview = insights.get("/v1/admin/overview", headers=admin).text
    assert "gw_admin_xyz" not in overview and "gw_agent_xyz" not in overview
    # the provisioner learns the keys arrived (a gateway whose keys never did gets recreated), never the keys
    q = insights.get("/v1/admin/provision", headers=admin).json()["pilots"]
    assert any(p["code"] == code and p["keys_ready"] is True for p in q) and "gw_admin_xyz" not in str(q)
    # once shown and forgotten here, the keys still count as delivered: the gateway must not be recreated
    k = insights.post(f"/v1/pilot/{code}/keys").json()                                 # the founder's page shows them once
    assert k["admin_key"] == "gw_admin_xyz" and k["agent_key"] == "gw_agent_xyz" and k["dashboard"] == dash
    q = insights.get("/v1/admin/provision", headers=admin).json()["pilots"]
    assert any(p["code"] == code and p["keys_ready"] is True for p in q)
    assert insights.post(f"/v1/pilot/{code}/keys").status_code == 409                   # shown once
    # a recreated gateway's new keys can be shown again
    insights.post("/v1/admin/provisioned", headers=admin, json={"code": code, "state": "running",
                                                                "admin_key": "gw_admin_new", "agent_key": "gw_agent_new"})
    assert insights.post(f"/v1/pilot/{code}/keys").json()["agent_key"] == "gw_agent_new"
    insights.post("/v1/admin/provisioned", headers=admin, json={"code": code, "state": "running"})   # a plain tick
    assert insights.post(f"/v1/pilot/{code}/keys").status_code == 409
    # slots are limited (HOSTED_MAX=2 here)
    insights.post("/v1/admin/pilots", headers=admin, json={"company": "Second", "hosted": True})
    assert insights.post("/v1/admin/pilots", headers=admin, json={"company": "Third", "hosted": True}).status_code == 409
    # deleting waits for the provisioner to remove the gateway
    assert insights.delete(f"/v1/admin/pilots/{code}", headers=admin).json() == {"deleting": code}
    assert insights.get("/v1/caddy/ask", params={"domain": "hosted-co.app.example.com"}).status_code == 404
    insights.post("/v1/admin/provisioned", headers=admin, json={"code": code, "state": "deleted"})
    assert all(p["code"] != code for p in insights.get("/v1/admin/overview", headers=admin).json()["pilots"])


def test_connect_all_offers_counts_once_default_no(tmp_path, monkeypatch, capsys):
    """Installs that aren't pilots can share counts, but only if they say yes when connect all asks: once,
    default no, never in scripts, and never again after a no."""
    import connect
    import server
    monkeypatch.setattr(server, "PILOT_DIR", tmp_path)
    joined = []
    monkeypatch.setattr(pilot, "_post", lambda srv, path, body: joined.append((srv, body["code"])) or {"company": "Community"})

    monkeypatch.setattr("builtins.input", lambda prompt="": "")                 # just Enter: no
    connect.offer_counts()
    assert joined == [] and pilot.load(tmp_path) is None and (tmp_path / "community-asked").exists()
    assert "Never sent" in capsys.readouterr().out                             # it says what would be sent first

    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("asked twice"))
    connect.offer_counts()                                                     # a no is remembered

    (tmp_path / "community-asked").unlink()
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    connect.offer_counts()
    assert joined == [(connect.COMMUNITY_SERVER, connect.COMMUNITY_CODE)] and pilot.load(tmp_path)["code"] == connect.COMMUNITY_CODE


def test_pilot_server_must_be_https_or_internal(tmp_path):
    for bad in ("http://pilots.example.com", "ftp://x", ""):
        assert pilot.join(tmp_path, "c", bad, True, "1") == 2

def test_admin_password_and_sessions(insights):
    key = {"X-Admin-Key": "admin-test-key"}
    assert insights.post("/v1/admin/login", json={"password": "nope"}).status_code == 401
    # the server key signs in the first time; then a password is set with it
    token = insights.post("/v1/admin/login", json={"password": "admin-test-key"}).json()["token"]
    s = {"X-Admin-Key": token}
    assert insights.get("/v1/admin/me", headers=s).json() == {"has_password": False}
    assert insights.post("/v1/admin/password", headers=s, json={"current": "wrong", "new": "a-long-password-1"}).status_code == 403
    assert insights.post("/v1/admin/password", headers=s, json={"current": "admin-test-key", "new": "short"}).status_code == 422
    assert insights.post("/v1/admin/password", headers=s, json={"current": "admin-test-key", "new": "a-long-password-1"}).status_code == 200
    assert insights.get("/v1/admin/overview", headers=s).status_code == 401          # changing it signs everyone out
    s = {"X-Admin-Key": insights.post("/v1/admin/login", json={"password": "a-long-password-1"}).json()["token"]}
    assert insights.get("/v1/admin/me", headers=s).json() == {"has_password": True}
    import app as insights_app
    with insights_app.db() as c:                                                          # stored hashed, never as text
        stored = c.execute("SELECT value FROM settings WHERE key='admin_password'").fetchone()[0]
    assert "a-long-password-1" not in stored and stored.startswith("pbkdf2_sha256$")
    insights.post("/v1/admin/logout", headers=s)
    assert insights.get("/v1/admin/overview", headers=s).status_code == 401
    assert insights.get("/v1/admin/overview", headers=key).status_code == 200            # the server key still works (provisioner)
    insights_app._failures.clear()
    for _ in range(8):
        insights.post("/v1/admin/login", json={"password": "guess"})
    assert insights.post("/v1/admin/login", json={"password": "a-long-password-1"}).status_code == 429   # slowed down
    insights_app._failures.clear()

def test_team_request_form(insights):
    """Teams that installed on their own can ask for help; only what they typed is kept, and only the admin sees it."""
    admin = {"X-Admin-Key": os.environ["INSIGHTS_ADMIN_KEY"]}
    page = insights.get("/team")
    assert page.status_code == 200 and "__CONTACT__" not in page.text
    ask = {"name": "Asha", "email": "asha@example.com", "company": "Pilot B", "team_size": "6-20",
           "agents": "Claude Code", "note": "audit in March", "source": "cli"}
    assert insights.post("/v1/team-request", json=ask).json() == {"ok": True}
    assert insights.post("/v1/team-request", json={**ask, "email": "not-an-email"}).status_code == 422
    assert insights.post("/v1/team-request", json={**ask, "name": "Bot", "website": "http://spam"}).json() == {"ok": True}
    assert insights.post("/v1/team-request", json={**ask, "name": "Odd", "source": "elsewhere"}).status_code == 200

    assert insights.get("/v1/admin/team-requests").status_code == 401
    rows = insights.get("/v1/admin/team-requests", headers=admin).json()
    names = [r["name"] for r in rows]
    assert "Asha" in names and "Bot" not in names                     # the hidden field caught the bot
    asha = next(r for r in rows if r["name"] == "Asha")
    assert asha["source"] == "cli" and asha["done"] == 0
    assert next(r for r in rows if r["name"] == "Odd")["source"] == ""   # only known link names are kept
    assert set(asha) == {"id", "created_at", "name", "email", "company", "team_size", "agents", "note", "source", "done"}

    assert insights.post(f"/v1/admin/team-requests/{asha['id']}", json={"done": True}).status_code == 401
    assert insights.post(f"/v1/admin/team-requests/{asha['id']}", headers=admin, json={"done": True}).status_code == 200
    assert next(r for r in insights.get("/v1/admin/team-requests", headers=admin).json() if r["id"] == asha["id"])["done"] == 1
    assert insights.post("/v1/admin/team-requests/999999", headers=admin, json={"done": True}).status_code == 404

    for _ in range(5):                                                  # 5 an hour from one address
        insights.post("/v1/team-request", json=ask)
    assert insights.post("/v1/team-request", json=ask).status_code == 429


def test_catches_say_what_and_why_never_the_details(gateway):
    """Held and blocked actions are shared as program + rule + outcome + sizes; never arguments, paths or content."""
    server, c = gateway
    h = {"X-Gateway-Key": "k1"}
    held = c.post("/v1/events", headers=h, json={
        "name": "Bash", "source": "catch-test", "input": {"command": f"rm -rf {SECRET}-folder"},
        "metadata": {"effects": [f"Deletes 3 files (1.2 KB) in {SECRET}-folder"]}}).json()
    assert held["decision"] == "review"
    c.post(f"/v1/events/{held['event_id']}/reject", headers={"X-Gateway-Key": "k2"}, json={"note": f"no {SECRET}"})
    c.post("/v1/events", headers=h, json={"name": "Bash", "source": "catch-test", "input": {"command": "rm -rf ~/"}})
    u = pilot.usage(server.engine, server.events, "enforce", 3, "9.9.9",
                    reasons={r["id"]: r.get("reason", "") for r in server.policy.rules})
    mine = [x for x in u["catches"] if x["agent"] == "catch-test"]
    assert SECRET not in json.dumps(u)       # the folder name, the command and the note are all marked with it
    rejected = next(x for x in mine if x["outcome"] == "rejected")
    assert rejected["program"] == "rm" and rejected["category"] == "irreversible" and rejected["saved"] == {"files": 3}
    assert rejected["why"] and isinstance(rejected["decide_s"], int)
    blocked = next(x for x in mine if x["outcome"] == "blocked")
    assert blocked["program"] == "rm" and blocked["category"] == "catastrophic" and "home folder" in blocked["why"]


def test_insights_keeps_only_known_catch_fields_and_shows_churn(insights, tmp_path, monkeypatch):
    admin = {"X-Admin-Key": "admin-test-key"}
    code = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Catchy"}).json()["code"]
    path_of = lambda url: "/" + url.split("://", 1)[1].split("/", 1)[1]
    monkeypatch.setattr(pilot.httpx, "post", lambda url, json, timeout: insights.post(path_of(url), json=json))
    assert pilot.join(tmp_path, code, "http://localhost", True, "1.0") == 0
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    catch = {"t": today + "T10:00", "agent": "cursor", "tool": "Bash", "program": "git", "category": "irreversible",
             "rule": "approve-git-push", "why": "Pushing code to a remote", "outcome": "rejected", "decide_s": 42,
             "saved": {"commits": 3}, "input": {"command": "git push --force " + SECRET}, "command": SECRET}
    assert pilot.send(tmp_path, {"version": "1.0", "agents": {"cursor": 1}, "days": {today: {"events": 4, "held": 1}},
                                 "rules_hit": {}, "total_events": 4, "catches": [catch, {"t": "garbage"}]}) is True
    d = insights.get("/v1/admin/overview", headers=admin).json()
    p = next(p for p in d["pilots"] if p["code"] == code)
    assert SECRET not in json.dumps(d)                                           # unknown fields are dropped
    [x] = p["catches"]
    assert x["program"] == "git" and x["outcome"] == "rejected" and x["saved"] == {"commits": 3}
    assert p["stopped"] == 1 and p["saved"] == {"commits": 3} and p["decide_median_s"] == 42
    assert p["health"] == "active" and p["idle_days"] == 0
    assert d["scorecard"]["stopped"] >= 1 and d["scorecard"]["saved"].get("commits", 0) >= 3


def test_traction_metrics(insights, tmp_path, monkeypatch):
    import app as insights_app
    admin = {"X-Admin-Key": "admin-test-key"}

    class H(dict):
        def get(self, k, d=None): return '<https://x?page=12>; rel="last"' if k == "Link" else d
    monkeypatch.setattr(insights_app, "_fetch_json", lambda url: (
        {"stargazers_count": 42, "forks_count": 7} if url.endswith("/squidbrake") else
        {"data": {"last_week": 1355}} if "pypistats" in url else [], H()))
    with insights_app.db() as c:
        c.execute("DELETE FROM settings WHERE key='oss_cache'")
    code = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Investable"}).json()["code"]
    insights.get(f"/start/{code}")
    path_of = lambda url: "/" + url.split("://", 1)[1].split("/", 1)[1]
    monkeypatch.setattr(pilot.httpx, "post", lambda url, json, timeout: insights.post(path_of(url), json=json))
    assert pilot.join(tmp_path, code, "http://localhost", True, "1.0") == 0
    from datetime import datetime, timedelta, timezone
    d = lambda n: (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d")
    assert pilot.send(tmp_path, {"version": "1.0", "agents": {"cursor": 3, "codex": 1}, "rules_hit": {}, "total_events": 9,
                                 "days": {d(0): {"events": 4}, d(1): {"events": 2}, d(2): {"events": 1}, d(8): {"events": 2}},
                                 "catches": [{"t": d(0) + "T09:00", "agent": "cursor", "program": "rm", "rule": "r",
                                              "outcome": "rejected", "decide_s": 30, "saved": {"files": 12}}]}) is True
    assert insights.post(f"/v1/admin/pilots/{code}/revenue", json={"mrr": 99}).status_code == 401
    assert insights.post(f"/v1/admin/pilots/{code}/revenue", headers=admin, json={"mrr": 99}).json() == {"ok": True}
    v = insights.get("/v1/admin/traction", headers=admin).json()
    steps = {f["step"]: f["count"] for f in v["funnel"]}
    assert steps["Pilots created"] >= 1 and steps["First action"] >= 1 and steps["Active 3+ days this week"] >= 1
    assert steps["Paying"] >= 1 and v["mrr"] >= 99 and v["arr"] == v["mrr"] * 12
    assert any(p["company"] == "Investable" and p["mrr"] == 99 and p["since"] for p in v["paying"])
    assert len(v["weeks"]) == 8 and v["weeks"][-1]["active_pilots"] >= 1 and v["retention_w1"] is not None
    assert v["stopped_this_week"] >= 1 and v["saved_this_week"].get("files", 0) >= 12
    assert v["oss"]["stars"] == 42 and v["oss"]["forks"] == 7 and v["oss"]["contributors"] == 12
    assert v["oss"]["downloads_last_week"] == 1355
    insights.post(f"/v1/admin/pilots/{code}/revenue", headers=admin, json={"mrr": 0})
    assert not any(p["company"] == "Investable" for p in insights.get("/v1/admin/traction", headers=admin).json()["paying"])


def test_the_website_form_may_post_here_other_sites_may_not(insights):
    """squidbrake.com is a static site; its demo form posts to /v1/team-request from the browser."""
    ask = lambda origin: insights.options("/v1/team-request", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    for ok in ("https://squidbrake.com", "https://www.squidbrake.com", "https://squidbrake-site.onrender.com"):
        assert ask(ok).headers.get("access-control-allow-origin") == ok, ok
    for bad in ("https://evil.example", "https://squidbrake.com.evil.example", "http://squidbrake.com"):
        assert "access-control-allow-origin" not in ask(bad).headers, bad


def test_where_installs_come_from(insights):
    """A named link counts clicks (no IP, no cookie) and lands on install commands that carry its name; installs
    that share stats report it, and the admin sees clicks -> installs -> used -> stopped per channel."""
    import app as insights_app
    admin = {"X-Admin-Key": os.environ["INSIGHTS_ADMIN_KEY"]}
    r = insights.get("/go/LinkedIn", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/get?ref=linkedin"
    insights.get("/go/linkedin", follow_redirects=False)
    assert insights.get("/go/bad%20name", follow_redirects=False).status_code == 404
    page = insights.get("/get?ref=linkedin").text
    assert '"ref": "linkedin"' in page and "SQUIDBRAKE_REF=" in page and "__DATA__" not in page
    assert '"ref": ""' in insights.get("/get?ref=</script><script>alert(1)").text   # not a word: dropped
    from datetime import datetime, timezone

    code = insights_app.COMMUNITY_CODE
    with insights_app.db() as c:
        c.execute("INSERT OR IGNORE INTO pilots (code, company, created_at) VALUES (?, 'Community', ?)", (code, "2026-01-01"))
    a, b = "a" * 32, "b" * 32
    assert insights.post("/v1/pilot/join", json={"code": code, "install_id": a, "ref": "linkedin"}).status_code == 200
    assert insights.post("/v1/pilot/join", json={"code": code, "install_id": b}).status_code == 200
    assert insights.post("/v1/pilot/join", json={"code": code, "install_id": "c" * 32, "ref": "Not A Word!"}).status_code == 422
    insights.post("/v1/pilot/join", json={"code": code, "install_id": a})       # joining again keeps where it came from
    today = datetime.now(timezone.utc).date().isoformat()
    insights.post("/v1/ping", json={"code": code, "install_id": a, "usage": {
        "days": {today: {"events": 4, "blocked": 1}},
        "catches": [{"t": today + "T10:00", "program": "rm", "rule": "command:catastrophic_command", "outcome": "blocked"}]}})

    assert insights.get("/v1/admin/sources").status_code == 401
    rows = {r["channel"]: r for r in insights.get("/v1/admin/sources", headers=admin).json()["rows"]}
    assert rows["linkedin"]["clicks"] >= 2 and rows["linkedin"]["installs"] == 1
    assert rows["linkedin"]["used_this_week"] == 1 and rows["linkedin"]["stopped"] == 1
    assert rows["not said"]["installs"] >= 1 and rows["not said"]["stopped"] == 0
