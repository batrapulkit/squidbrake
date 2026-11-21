"""The pricing page's plans reach the product: the gateway and squidbrake.com agree on them, each plan's people limit
is enforced, the new Crew plans start a trial, payment links keep the live ones, and monthly usage shows the allowance."""
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "insights"))
os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")
import license  # noqa: E402
from test_license import SECRET, after_grace  # noqa: E402,F401
from test_server import c, org, server  # noqa: E402,F401


@pytest.fixture()
def app():
    import app as insights_app
    return insights_app


def test_the_gateway_and_squidbrake_com_agree_on_the_plans(app):
    assert set(app.PAID_PLANS) == set(license.ORDER) == set(license.PEOPLE) == set(app.PLAN_PRICES)
    assert all(app.PLAN_NAMES[p] == license.NAMES[p] for p in app.PAID_PLANS)
    assert [app.PLAN_PRICES[p] for p in license.ORDER] == sorted(app.PLAN_PRICES.values())   # ORDER is cheapest first
    for p in ("crew", "crewplus", "crewmax"):
        assert p in app.TRIAL_PLANS and "people" in license.PLANS[p]


def test_a_plan_caps_the_people(c, org, after_grace, monkeypatch):             # org: 3 people already
    monkeypatch.setenv("SQUIDBRAKE_LICENSE", license.issue(SECRET, "Acme", "2099-01-01", plan="crew"))
    assert license.people_limit(server.KEYS_PATH.parent) == 3
    me = c.get("/v1/me", headers=org["admin"]).json()["license"]
    assert me["plan_name"] == "Crew" and me["people"] == 3
    r = c.post("/v1/team", headers=org["admin"], json={"name": "ravi", "kind": "person"})
    assert r.status_code == 402 and "up to 3 people" in r.json()["detail"]
    assert c.post("/v1/team", headers=org["admin"], json={"name": "bot-9", "kind": "agent"}).status_code == 200  # agents: free
    monkeypatch.setenv("SQUIDBRAKE_LICENSE", license.issue(SECRET, "Acme", "2099-01-01", plan="crewplus"))
    assert c.post("/v1/team", headers=org["admin"], json={"name": "ravi", "kind": "person"}).status_code == 200
    monkeypatch.setenv("SQUIDBRAKE_LICENSE", license.issue(SECRET, "Acme", "2099-01-01", plan="enterprise"))
    assert license.people_limit(server.KEYS_PATH.parent) is None


def test_the_live_payment_links_stay_and_new_ones_add_to_them(app, monkeypatch):
    src = (ROOT / "insights" / "app.py").read_text(encoding="utf-8")
    assert "28EfZh1Lq7Zy0S05zr3Ru0f" in src and "3cI6oHahW1Ba6ck7Hz3Ru0g" in src        # Brake $9, Brake Pro $19
    import importlib
    monkeypatch.setenv("INSIGHTS_CHECKOUT_URLS", "crew=https://buy.stripe.com/crew")
    fresh = importlib.reload(app)
    try:
        assert fresh.checkout_url("crew") == "https://buy.stripe.com/crew"
        assert fresh.checkout_url("starter") == "https://buy.stripe.com/28EfZh1Lq7Zy0S05zr3Ru0f"
    finally:
        monkeypatch.delenv("INSIGHTS_CHECKOUT_URLS")
        importlib.reload(app)


def test_stripe_setup_only_makes_the_plans_without_a_link():
    sys.path.insert(0, str(ROOT / "insights"))
    import stripe_setup
    todo = stripe_setup.plans()
    assert todo == {"crew": ("Crew", 49), "crewplus": ("Crew Plus", 99), "crewmax": ("Crew Max", 199)}
    said = []
    assert stripe_setup.setup("", False, todo, out=said.append) == {} and len(said) == 3      # dry run: nothing sent


def test_monthly_usage_shows_the_allowance_and_whats_over_it(app):
    code = f"usage-{time.time_ns()}"
    month = time.strftime("%Y-%m", time.gmtime())
    with app.db() as db:
        db.execute("INSERT INTO pilots (code, company, created_at, plan) VALUES (?,?,?,?)", (code, "Overco", app.now(), "crew"))
        db.execute("INSERT INTO installs (install_id, code, joined_at, last_seen) VALUES (?,?,?,?)",
                   (code + "-i", code, app.now(), app.now()))
        db.execute("INSERT INTO days (install_id, day, counts) VALUES (?,?,?)",
                   (code + "-i", month + "-01", json.dumps({"real": 30_000, "events": 30_000})))
    try:
        with app.db() as db:
            row = next(p for p in app.monthly_usage(db, 1) if p["code"] == code)
        assert row["allowance"] == 25_000 and row["months"][month]["over"] == 5_000
    finally:
        with app.db() as db:
            db.execute("DELETE FROM days WHERE install_id=?", (code + "-i",))
            db.execute("DELETE FROM installs WHERE install_id=?", (code + "-i",))
            app._forget(db, code)
