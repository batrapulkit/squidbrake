"""The pricing page's plans reach the product: a sign-up names its plan, its license carries that plan's people limit
(which the gateway enforces), payment links and Stripe payments follow the plan, and monthly usage shows the allowance."""
import hashlib
import hmac
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
import signing  # noqa: E402
from test_license import SECRET, after_grace  # noqa: E402,F401
from test_server import c, org, server  # noqa: E402,F401

import plans  # noqa: E402


def test_the_gateway_and_squidbrake_com_agree_on_the_plans():
    assert set(license.PLANS) == set(plans.TIERS)
    for tier, (name, people, actions) in license.PLANS.items():
        assert plans.TIERS[tier][0] == name and plans.TIERS[tier][2:] == (people, actions)


def test_a_plans_license_caps_the_people(c, org, after_grace, monkeypatch):     # org: 3 people already
    monkeypatch.setenv("SQUIDBRAKE_LICENSE", license.issue(SECRET, "Acme", "2099-01-01", tier="crew"))
    assert license.people_limit(server.KEYS_PATH.parent) == 3
    assert c.get("/v1/me", headers=org["admin"]).json()["license"]["tier"] == "crew"
    r = c.post("/v1/team", headers=org["admin"], json={"name": "ravi", "kind": "person"})
    assert r.status_code == 402 and "up to 3 people" in r.json()["detail"]
    assert c.post("/v1/team", headers=org["admin"], json={"name": "bot-9", "kind": "agent"}).status_code == 200  # agents: free
    monkeypatch.setenv("SQUIDBRAKE_LICENSE", license.issue(SECRET, "Acme", "2099-01-01", tier="crewplus"))
    assert c.post("/v1/team", headers=org["admin"], json={"name": "ravi", "kind": "person"}).status_code == 200
    monkeypatch.setenv("SQUIDBRAKE_LICENSE", license.issue(SECRET, "Acme", "2099-01-01"))       # Enterprise: no tier
    assert license.people_limit(server.KEYS_PATH.parent) is None


@pytest.fixture()
def insights(monkeypatch):
    import app as insights_app
    from fastapi.testclient import TestClient
    monkeypatch.setattr(insights_app, "LICENSE_SECRET", SECRET.hex())
    monkeypatch.setattr(license, "PUBLIC_KEY_HEX", signing.ed25519_public_key(SECRET).hex())
    monkeypatch.setattr(insights_app, "HOSTED_PER_IP_DAY", 100)       # several sign-ups from the test client's address
    with TestClient(insights_app.app) as cl:
        yield insights_app, cl
    insights_app._requests.clear()
    insights_app._hosted_ips.clear()


def _signup(cl, **kw):
    r = cl.post("/v1/signup", json={"name": "Asha", "email": f"asha-{time.time_ns()}@acme.test", "company": "Tierco",
                                    "plan": "team", **kw})
    assert r.status_code == 200, r.text
    return r.json()["link"].rsplit("/", 1)[1]


def test_a_signup_keeps_its_plan_and_its_license_carries_the_limit(insights, monkeypatch):
    app, cl = insights
    monkeypatch.setattr(app, "CHECKOUT_URLS", {"crewmax": "https://buy.stripe.com/max"})
    monkeypatch.setattr(app, "CHECKOUT_URL", "https://buy.stripe.com/any")
    code = _signup(cl, tier="crewmax")
    try:
        with app.db() as db:
            p = db.execute("SELECT * FROM pilots WHERE code=?", (code,)).fetchone()
            assert p["tier"] == "crewmax" and p["trial_ends"]
            assert license.check(app._license_for(p))["people"] == 25
        page = cl.get(f"/start/{code}").text
        assert "https://buy.stripe.com/max?client_reference_id=" in page and "Crew Max" in page
        other = _signup(cl)                                            # no tier: Crew, and the general link
        with app.db() as db:
            assert db.execute("SELECT tier FROM pilots WHERE code=?", (other,)).fetchone()["tier"] == "crew"
        assert "https://buy.stripe.com/any?client_reference_id=" in cl.get(f"/start/{other}").text
        assert cl.post("/v1/signup", json={"name": "A", "email": "a@b.test", "company": "C", "plan": "team",
                                           "tier": "gold"}).status_code == 422
    finally:
        with app.db() as db:
            for k in (code, locals().get("other")):
                if k:
                    app._forget(db, k)


def test_a_stripe_payment_sets_the_plan_it_paid_for(insights, monkeypatch):
    app, cl = insights
    monkeypatch.setattr(app, "STRIPE_SECRET", "whsec_test")
    monkeypatch.setattr(app, "notify", lambda *a, **k: None)
    assert app.tier_for_amount(199) == "crewmax" and app.tier_for_amount(4990) == "fleetmax"
    assert app.tier_for_amount(150) is None
    code = _signup(cl, tier="crew")
    try:
        ev = json.dumps({"type": "checkout.session.completed", "data": {"object": {
            "client_reference_id": code, "mode": "subscription", "amount_total": 9900, "customer": "cus_1"}}}).encode()
        t = int(time.time())
        sig = hmac.new(b"whsec_test", f"{t}.".encode() + ev, hashlib.sha256).hexdigest()
        assert cl.post("/v1/stripe/webhook", content=ev, headers={"stripe-signature": f"t={t},v1={sig}"}).status_code == 200
        with app.db() as db:
            p = db.execute("SELECT tier, mrr FROM pilots WHERE code=?", (code,)).fetchone()
        assert (p["tier"], p["mrr"]) == ("crewplus", 99)                # an upgrade: the plan follows the payment
    finally:
        with app.db() as db:
            app._forget(db, code)


def test_monthly_usage_shows_the_allowance_and_whats_over_it(insights):
    app, _ = insights
    code = f"usage-{time.time_ns()}"
    with app.db() as db:
        db.execute("INSERT INTO pilots (code, company, created_at, plan, tier) VALUES (?,?,?,?,?)",
                   (code, "Overco", app.now(), "team", "crew"))
        db.execute("INSERT INTO installs (install_id, code, joined_at, last_seen) VALUES (?,?,?,?)",
                   (code + "-i", code, app.now(), app.now()))
        month = time.strftime("%Y-%m", time.gmtime())
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
