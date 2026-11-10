"""Real actions are counted per pilot and month (for plan limits), and a hosted sign-up gets its dashboard and keys
on its own, new keys included."""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
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
os.environ.setdefault("INSIGHTS_DB", str(Path(tempfile.mkdtemp()) / "insights.db"))
os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")
os.environ.setdefault("HOSTED_DOMAIN", "app.example.com")
os.environ.setdefault("HOSTED_MAX", "2")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import pilot  # noqa: E402

ADMIN = {"X-Admin-Key": os.environ["INSIGHTS_ADMIN_KEY"]}


@pytest.fixture(scope="module")
def insights():
    import app as insights_app
    with TestClient(insights_app.app) as c:
        yield c
    with insights_app.db() as db:        # the rows made here would take the hosted slots other test files count on
        for code in ("mon-local", "lost-co", "rekey-co"):
            insights_app._forget(db, code)
    insights_app._requests.clear()       # the per-address limit sign-ups share with the team request form


def test_real_actions_leave_out_prompts_questions_and_the_install_check():
    import server
    with TestClient(server.app) as c:
        k = {"X-Gateway-Key": "k1"}
        before = pilot.usage(server.engine, server.events, "enforce", 1, "t")["days"]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        was = before.get(today, {"events": 0, "real": 0})
        c.post("/v1/events", headers=k, json={"name": "Bash", "source": "rt", "input": {"command": "ls"}})
        c.post("/v1/events", headers=k, json={"name": "Bash", "source": "rt",
                                              "input": {"command": "echo squidbrake doctor check"}})
        c.post("/v1/events", headers=k, json={"name": "user.prompt", "kind": "prompt", "source": "rt",
                                              "input": {"prompt": "hi"}})
        now = pilot.usage(server.engine, server.events, "enforce", 1, "t")["days"][today]
    assert now["events"] - was["events"] == 3 and now["real"] - was["real"] == 1
    assert pilot.is_real("tool_call", '{"command": "ls"}') and not pilot.is_real("prompt", None)


def test_monthly_usage_counts_real_actions_per_pilot(insights):
    import app as insights_app
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    day = f"{month}-01"
    with insights_app.db() as c:
        c.execute("INSERT INTO pilots (code, company, created_at) VALUES ('mon-local', 'Local Co', ?)", (insights_app.now(),))
        c.execute("INSERT INTO installs (install_id, code, joined_at) VALUES (?, 'mon-local', ?)", ("1" * 32, insights_app.now()))
        c.execute("INSERT INTO installs (install_id, code, joined_at) VALUES (?, 'mon-local', ?)", ("2" * 32, insights_app.now()))
        c.execute("INSERT INTO days (install_id, day, counts) VALUES (?, ?, ?)", ("1" * 32, day, json.dumps({"events": 9, "real": 7})))
        c.execute("INSERT INTO days (install_id, day, counts) VALUES (?, ?, ?)", ("2" * 32, day, json.dumps({"events": 4})))  # older gateway
    m = insights.get("/v1/admin/usage/monthly", headers=ADMIN).json()
    by = {p["code"]: p["months"][month] for p in m["pilots"] if month in p["months"]}
    assert m["this_month"] == month
    assert by["mon-local"] == {"real": 11, "events": 13, "held": 0, "blocked": 0, "estimated": True}   # 7 + an older gateway's 4
    assert insights.get("/v1/admin/usage/monthly").status_code == 401


def test_lost_keys_signing_in_again_makes_new_ones(insights, monkeypatch):
    import app as insights_app
    insights_app._requests.clear()
    monkeypatch.setattr(insights_app, "SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setattr(insights_app, "supabase_user", lambda token: {"email": "lost@keys.dev",
                                                                      "email_confirmed_at": "2026-11-01T00:00:00Z"})
    monkeypatch.setattr(insights_app, "notify", lambda text: None)
    with insights_app.db() as c:
        c.execute("INSERT INTO pilots (code, company, created_at, email, hosted, subdomain, state, keys_revealed_at) "
                  "VALUES ('lost-co', 'Lost', ?, 'lost@keys.dev', 1, 'lost', 'running', ?)",
                  (insights_app.now(), insights_app.now()))
    post = lambda **kw: insights.post("/v1/signup", json=kw, headers={"Authorization": "Bearer t"})
    assert post().json()["link"].endswith("/start/lost-co")
    assert insights.get("/v1/pilot/lost-co/status").json()["rekey"] is False        # just signing in: nothing changes
    post(new_keys=True)
    assert insights.get("/v1/pilot/lost-co/status").json()["rekey"] is True
    assert any(p["code"] == "lost-co" and p["rekey"] for p in insights.get("/v1/admin/provision", headers=ADMIN).json()["pilots"])
    page = insights.get("/start/lost-co").text
    assert '"self_serve_keys": true' in page and '"rekey": true' in page


def test_the_start_page_link_alone_never_makes_new_keys(insights, monkeypatch):
    # a forwarded start link must not be enough to take over a dashboard: new keys need signing in again
    import app as insights_app
    monkeypatch.setattr(insights_app, "SUPABASE_URL", "")
    with insights_app.db() as c:
        c.execute("INSERT INTO pilots (code, company, created_at, hosted, subdomain, state, keys_revealed_at) "
                  "VALUES ('rekey-co', 'Rekey', ?, 1, 'rekey', 'running', ?)", (insights_app.now(), insights_app.now()))
    assert insights.post("/v1/pilot/rekey-co/new-keys").status_code in (404, 405)
    assert insights.get("/v1/pilot/rekey-co/status").json()["rekey"] is False
    page = insights.get("/start/rekey-co").text
    assert '"self_serve_keys": false' in page and "/new-keys" not in page
    with insights_app.db() as c:
        insights_app._forget(c, "rekey-co")


def test_signing_in_again_makes_new_keys_three_times_an_hour(insights, monkeypatch):
    import app as insights_app
    insights_app._requests.clear()
    insights_app._rekeys.clear()
    monkeypatch.setattr(insights_app, "SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setattr(insights_app, "supabase_user", lambda token: {"email": "re@key.dev",
                                                                      "email_confirmed_at": "2026-11-01T00:00:00Z"})
    with insights_app.db() as c:
        c.execute("INSERT INTO pilots (code, company, created_at, email, hosted, subdomain, state, keys_revealed_at) "
                  "VALUES ('rekey2-co', 'Rekey', ?, 're@key.dev', 1, 'rekey2', 'running', ?)",
                  (insights_app.now(), insights_app.now()))
    def ask():
        insights_app._requests.clear()
        return insights.post("/v1/signup", json={"new_keys": True}, headers={"Authorization": "Bearer t"})
    for i in range(3):
        assert ask().status_code == 200
        assert insights.get("/v1/pilot/rekey2-co/status").json()["rekey"] is True
        insights.post("/v1/admin/provisioned", headers=ADMIN, json={"code": "rekey2-co", "state": "running",
                                                                    "admin_key": "gw_a", "agent_key": "gw_b"})
        if i == 0:
            assert ask().status_code == 200                      # new keys waiting on the page: just the page back
        assert insights.post("/v1/pilot/rekey2-co/keys").json()["admin_key"] == "gw_a"   # shown once
    assert ask().status_code == 429                              # the fourth in an hour
    with insights_app.db() as c:
        insights_app._forget(c, "rekey2-co")


def test_the_signup_page_offers_only_the_hosted_setup_unless_the_flag_is_on(insights, monkeypatch):
    import app as insights_app
    monkeypatch.setattr(insights_app, "SUPABASE_URL", "https://x.supabase.co")
    page = insights.get("/signup").text
    assert '"hosted": true' in page and '"offer_local": false' in page
    monkeypatch.setattr(insights_app, "SIGNUP_LOCAL", True)                # INSIGHTS_SIGNUP_LOCAL=1
    page = insights.get("/signup").text
    assert '"offer_local": true' in page and 'data-setup="local"' in page and "Never your commands, files or prompts" in page
    monkeypatch.setattr(insights_app, "SUPABASE_URL", "")                  # no email sign-in: no hosted
    assert '"hosted": false' in insights.get("/signup").text
