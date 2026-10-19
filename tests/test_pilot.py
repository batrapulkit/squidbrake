"""Pilot usage sharing: nothing without joining, only counts when joined, and the insights service guards its doors."""
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

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


def test_individual_installs_are_rolled_up_apart_from_the_pilots(insights, monkeypatch):
    """pip installs (the community code) get their own block in the overview: how many, how many used it, and who
    they are as counts. The pilot numbers (pilots_week, scorecard) no longer include them."""
    import app as insights_app
    from datetime import datetime, timezone
    monkeypatch.setattr(insights_app, "oss_numbers", lambda: {"latest_version": "0.9.0"})
    admin = {"X-Admin-Key": os.environ["INSIGHTS_ADMIN_KEY"]}
    code, today = insights_app.COMMUNITY_CODE, datetime.now(timezone.utc).date().isoformat()
    pilot_code = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Named Co"}).json()["code"]
    pid, mac, win = "e" * 32, "f" * 32, "a" * 31 + "b"
    insights.post("/v1/pilot/join", json={"code": pilot_code, "install_id": pid, "version": "0.9.0", "os": "Linux 6.1"})
    insights.post("/v1/ping", json={"code": pilot_code, "install_id": pid, "usage": {"days": {today: {"events": 1000, "held": 10}}}})
    insights.post("/v1/pilot/join", json={"code": code, "install_id": mac, "version": "0.9.0", "os": "Darwin 22.6.0", "ref": "friend"})
    insights.post("/v1/pilot/join", json={"code": code, "install_id": win, "version": "0.8.0", "os": "Windows 11"})
    insights.post("/v1/ping", json={"code": code, "install_id": mac, "usage": {
        "version": "0.9.0", "os": "Darwin 22.6.0", "connected": ["claude-code", "cursor"],
        "days": {today: {"events": 30, "held": 3, "approved": 2, "rejected": 1, "blocked": 1}},
        "catches": [{"t": today + "T09:00", "program": "git", "rule": "command:irreversible", "outcome": "rejected", "decide_s": 20}]}})

    d = insights.get("/v1/admin/overview", headers=admin).json()
    c = d["community"]
    assert c["installs"] >= 2 and c["used_this_week"] >= 1 and c["new_this_week"] >= 2
    assert dict((k, n) for k, n, *_ in c["versions"])["0.8.0"] >= 1 and c["outdated"] is True
    assert any(v[0] == "0.8.0" and v[2] for v in c["versions"]) and not any(v[0] == "0.9.0" and v[2] for v in c["versions"])
    assert dict(c["os"])["macOS"] >= 1 and dict(c["os"])["Windows"] >= 1
    assert dict(c["refs"])["friend"] >= 1 and dict(c["refs"]).get("not said", 0) >= 1
    assert dict(c["connected"]) == {"claude-code": 1, "cursor": 1}
    assert c["week"]["events"] >= 30 and c["stopped"] >= 1 and c["catches"][0]["program"] == "git"
    assert c["median_actions"] >= 1 and "install_id" not in json.dumps(c)
    # the pilots' side doesn't include them, and the totals still do
    named = [p for p in d["pilots"] if not p["community"]]
    assert d["pilots_week"]["events"] == sum(p["week"]["events"] for p in named) >= 1000
    assert d["week"]["events"] == d["pilots_week"]["events"] + c["week"]["events"]
    assert d["scorecard"]["actions"] == d["pilots_week"]["events"]
    assert d["active_pilots"] == sum(1 for p in named if p["stage"] == "active")
    assert "Individual installs" in insights.get("/admin").text


def test_connect_all_never_asks_about_counts(tmp_path, monkeypatch):
    """Counts aren't a question any more (telemetry.py says once what is sent): connect all, with or without
    --yes, never prompts for them and never joins a pilot by itself."""
    from argparse import Namespace
    import connect
    import server
    monkeypatch.setattr(server, "PILOT_DIR", tmp_path)
    monkeypatch.setattr(pilot, "_post", lambda srv, path, body: pytest.fail("joined a pilot from connect all"))
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("asked about counts"))
    for f in ("claude_code", "agents", "guard", "_next_step"):
        monkeypatch.setattr(connect, f, lambda *a, **k: None)
    monkeypatch.setattr(connect, "_first_keys", lambda url: None)
    connect.connect_all(Namespace(url="http://localhost:8080", key="gw_x", remove=False, yes=True, only=None))
    assert pilot.load(tmp_path) is None


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


def test_all_time_usage_counts_every_day_ever_received(insights, tmp_path, monkeypatch):
    """The overview shows the last 14 days; All time usage adds up every day the server has kept."""
    import json as _json
    from datetime import datetime, timedelta, timezone
    import app as insights_app
    admin = {"X-Admin-Key": "admin-test-key"}
    code = insights.post("/v1/admin/pilots", headers=admin, json={"company": "Forever Co"}).json()["code"]
    path_of = lambda url: "/" + url.split("://", 1)[1].split("/", 1)[1]
    monkeypatch.setattr(pilot.httpx, "post", lambda url, json, timeout: insights.post(path_of(url), json=json))
    assert pilot.join(tmp_path, code, "http://localhost", True, "1.0") == 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert pilot.send(tmp_path, {"version": "1.0", "days": {today: {"events": 7, "held": 2, "blocked": 1, "legit": 1}}})
    old = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d")   # kept from a ping 60 days ago
    with insights_app.db() as c:
        c.execute("INSERT INTO days (install_id, day, counts) VALUES (?,?,?)",
                  (pilot.load(tmp_path)["install_id"], old, _json.dumps({"events": 30, "held": 5})))
    assert insights.get("/v1/admin/all-time").status_code == 401                     # admins only
    a = insights.get("/v1/admin/all-time", headers=admin).json()
    me = next(p for p in a["pilots"] if p["code"] == code)
    assert (me["events"], me["held"], me["blocked"], me["legit"]) == (37, 7, 1, 1)
    assert (me["active_days"], me["first_day"], me["last_day"]) == (2, old, today)
    assert a["pilots_total"]["events"] >= 37 and a["since"] <= old
    week = next(p for p in insights.get("/v1/admin/overview", headers=admin).json()["pilots"] if p["code"] == code)
    assert week["week"]["events"] == 7                                             # the overview is unchanged


def test_signup_needs_a_work_email_and_gives_the_local_setup_page(insights):
    import app as insights_app
    admin = {"X-Admin-Key": "admin-test-key"}
    insights_app._requests.clear()
    sign = lambda email, **kw: insights.post("/v1/signup", json={"name": "Asha", "email": email, "company": "Acme",
                                                                 "agents": ["claude-code", "cursor"], **kw})
    assert "/start/" in sign("asha@gmail.com").json()["link"]                # any email, Gmail too
    assert sign("not-an-email").status_code == 422
    assert "link" not in sign("bot@acme.com", website="spam").json()      # a bot: thanked, nothing kept
    r = sign("asha@acme.com").json()
    assert "/start/" in r["link"]
    assert sign("ASHA@acme.com").status_code == 409                        # one sign-up per email
    code = r["link"].rsplit("/", 1)[1]
    page = insights.get(f"/start/{code}").text
    assert '"hosted": false' in page                                       # the local install line, not a hosted one
    p = next(p for p in insights.get("/v1/admin/overview", headers=admin).json()["pilots"] if p["code"] == code)
    assert p["email"] == "asha@acme.com" and json.loads(p["uses_agents"]) == ["claude-code", "cursor"]
    assert "Asha" in p["contact"] and not p["hosted"]
    assert "bot@acme.com" not in json.dumps(insights.get("/v1/admin/overview", headers=admin).json())


def test_with_supabase_only_a_verified_sign_in_signs_up_and_signing_in_again_gives_the_same_page(insights, monkeypatch):
    import app as insights_app
    insights_app._requests.clear()
    monkeypatch.setattr(insights_app, "SUPABASE_URL", "https://x.supabase.co")
    users = {"good": {"email": "Ravi@Beta.io", "email_confirmed_at": "2026-10-19T10:00:00Z"},
             "unconfirmed": {"email": "ravi@beta.io", "email_confirmed_at": None},
             "gmail": {"email": "ravi@gmail.com", "email_confirmed_at": "2026-10-19T10:00:00Z"}}
    monkeypatch.setattr(insights_app, "supabase_user", lambda token: users.get(token))
    body = {"name": "Ravi", "company": "Beta", "email": "someone-else@acme.com", "agents": ["codex"]}
    post = lambda token=None, b=body: insights.post("/v1/signup", json=b,
                                                    headers={"Authorization": f"Bearer {token}"} if token else {})
    assert post().status_code == 401                                         # not signed in
    assert post("forged").status_code == 401
    assert post("unconfirmed").status_code == 401
    assert "/start/" in post("gmail").json()["link"]                         # Gmail is fine
    first = post("good").json()["link"]
    insights_app._requests.clear()                                          # 5 an hour from one address
    assert post("good", {}).json()["link"] == first                          # back again: same page, no form needed
    p = next(p for p in insights.get("/v1/admin/overview", headers={"X-Admin-Key": "admin-test-key"}).json()["pilots"]
             if p.get("email") == "ravi@beta.io")                            # the verified email, not the typed one
    assert "someone-else" not in p["contact"]
    page = insights.get("/signup").text
    assert '"supabase_url": "https://x.supabase.co"' in page and "__CONFIG__" not in page


def test_signup_picks_hosted_or_local_and_hosted_waits_for_a_free_slot(insights, monkeypatch):
    import app as insights_app
    insights_app._requests.clear()
    with insights_app.db() as c:
        live = c.execute(f"SELECT COUNT(*) FROM pilots WHERE {insights_app.LIVE}").fetchone()[0]
    monkeypatch.setattr(insights_app, "HOSTED_MAX", live + 1)
    sign = lambda email, setup: insights.post("/v1/signup", json={"name": "Mei", "email": email, "company": "Gamma",
                                                                  "agents": ["codex"], "setup": setup})
    r = sign("mei@gamma.io", "hosted").json()
    page = insights.get(urlparse(r["link"]).path).text
    assert '"hosted": true' in page and "gamma.app.example.com" in page and "Your checklist" in page
    q = insights.get("/v1/admin/provision", headers={"X-Admin-Key": "admin-test-key"}).json()["pilots"]
    assert any(p["code"] == r["link"].rsplit("/", 1)[1] and p["state"] == "requested" for p in q)   # provision.py starts it
    full = sign("li@gamma.io", "hosted")                                    # no slot left: told, offered local
    assert full.status_code == 409 and "On my computer" in full.json()["detail"]
    assert '"hosted": false' in insights.get(urlparse(sign("li@gamma.io", "local").json()["link"]).path).text
    assert sign("x@gamma.io", "cloud").status_code == 422


def test_one_website_serves_the_pages_and_the_old_address_sends_people_there(insights, monkeypatch):
    import app as insights_app
    for path, text in (("/", "Agents propose."), ("/pricing", "Start with Team"), ("/docs.html", "<html"),
                       ("/security", "<html"), ("/llms.txt", "Squidbrake"), ("/assets/og.png", "")):
        r = insights.get(path)
        assert r.status_code == 200 and text in r.text, path
    assert 'href="/signup"' in insights.get("/").text and "pilots.squidbrake.com" not in insights.get("/").text
    assert insights.get("/nope").status_code == 404 and insights.get("/app.py").status_code == 404
    monkeypatch.setattr(insights_app, "PUBLIC_URL", "https://squidbrake.com")
    monkeypatch.setattr(insights_app, "OLD_HOSTS", {"pilots.squidbrake.com"})
    old = {"Host": "pilots.squidbrake.com"}
    r = insights.get("/signup?from=x", headers=old, follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "https://squidbrake.com/signup?from=x"
    assert insights.get("/health", headers=old).status_code == 200                      # installs keep working there
    assert insights.get("/install.sh", headers=old, follow_redirects=False).status_code == 200
