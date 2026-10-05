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
    usage = {"version": "1.0", "agents": {"claude-code": 5}, "rules_hit": {"command:catastrophic_command": 1},
             "days": {"2026-10-01": {"events": 5, "held": 2, "blocked": 1}, "../../etc": {"events": 9}}, "total_events": 5}
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
