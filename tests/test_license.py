"""The Team plan: what blocks and holds is free; more than one person, phone approvals, Slack/Teams/email and the
audit export need a license once the grace period is over. A license is checked offline against our public key."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import license  # noqa: E402
import signing  # noqa: E402
from test_server import BOSS, H, c, org, server  # noqa: E402,F401

SECRET = signing.new_secret()


@pytest.fixture()
def after_grace(monkeypatch, tmp_path):
    monkeypatch.setattr(license, "PUBLIC_KEY_HEX", signing.ed25519_public_key(SECRET).hex())
    monkeypatch.setattr(license, "GRACE_UNTIL", "2020-01-01")
    monkeypatch.delenv("SQUIDBRAKE_LICENSE", raising=False)
    monkeypatch.setattr(server, "KEYS_PATH", tmp_path / "keys.json")
    with server.audited_tx() as conn:
        server.state_set(conn, "settings", {"slack_webhook": "https://hooks.example/x", "ntfy_topic": "mine"})
    yield
    with server.audited_tx() as conn:
        server.state_set(conn, "settings", {})


def test_a_license_is_ours_and_unexpired():
    lic = license.issue(SECRET, "Acme", "2099-01-01")
    pub = signing.ed25519_public_key(SECRET).hex()
    orig = license.PUBLIC_KEY_HEX
    try:
        license.PUBLIC_KEY_HEX = pub
        assert license.check(lic) == {"org": "Acme", "plan": "team", "expires": "2099-01-01"}
        assert license.check(license.issue(SECRET, "Acme", "2020-01-01")) is None              # expired
        assert license.check(license.issue(signing.new_secret(), "Acme", "2099-01-01")) is None  # not our key
        sig = lic.split(".")[1]
        assert license.check(license.issue(SECRET, "Evil", "2099-01-01").split(".")[0] + "." + sig) is None  # edited
        assert license.check("not a license") is None and license.check("") is None
    finally:
        license.PUBLIC_KEY_HEX = orig


def test_without_a_license_the_team_features_ask_for_the_plan(c, org, after_grace):
    me = c.get("/v1/me", headers=org["admin"]).json()["license"]
    assert me["licensed"] is False and me["team_features"] is False and me["upgrade_url"]
    assert c.post("/v1/team", headers=org["admin"], json={"name": "ravi", "kind": "person"}).status_code == 402
    assert c.post("/v1/team", headers=org["admin"], json={"name": "bot-2", "kind": "agent"}).status_code == 200  # agents: free
    r = c.put("/v1/settings", headers=org["admin"], json={"slack_webhook": "https://hooks.example/y"})
    assert r.status_code == 402 and "Team plan" in r.json()["detail"]
    assert c.put("/v1/settings", headers=org["admin"], json={"ntfy_topic": "other"}).status_code == 402
    assert c.get("/v1/audit/export.csv", headers=org["admin"]).status_code == 402
    assert c.get("/v1/audit/evidence-pack", headers=org["admin"]).status_code == 402
    assert c.post("/v1/devices/register/start", headers=org["admin"]).status_code == 402
    cfg = server.settings()                                    # saved, but nothing is sent there
    assert cfg["slack_webhook"] == "" and cfg["ntfy_topic"] == ""
    # what blocks and holds is free
    d = c.post("/v1/events", headers=org["agent"], json={"name": "Bash", "input": {"command": "rm -rf ~/"}}).json()
    assert d["decision"] == "deny"


def test_a_license_turns_them_on(c, org, after_grace, monkeypatch, capsys):
    lic = license.issue(SECRET, "Acme", "2099-01-01")
    assert server.main(["license", "set", "garbage"]) == 1
    assert server.main(["license", "set", lic]) == 0 and "Acme" in capsys.readouterr().out
    assert (server.KEYS_PATH.parent / license.FILE).read_text().strip() == lic
    assert c.get("/v1/me", headers=org["admin"]).json()["license"]["licensed"] is True
    assert c.post("/v1/team", headers=org["admin"], json={"name": "ravi", "kind": "person"}).status_code == 200
    assert c.get("/v1/audit/export.csv", headers=org["admin"]).status_code == 200
    assert server.settings()["slack_webhook"] == "https://hooks.example/x"


def test_squidbrake_com_issues_licenses_the_gateway_accepts(monkeypatch):
    sys.path.insert(0, str(ROOT / "insights"))
    import os
    os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")
    import app as insights_app
    monkeypatch.setattr(insights_app, "LICENSE_SECRET", SECRET.hex())
    monkeypatch.setattr(license, "PUBLIC_KEY_HEX", signing.ed25519_public_key(SECRET).hex())
    token = insights_app.issue_license("Acme", "2099-01-01")
    assert license.check(token) == {"org": "Acme", "plan": "team", "expires": "2099-01-01"}
    monkeypatch.setattr(insights_app, "LICENSE_SECRET", "")
    assert insights_app.issue_license("Acme", "2099-01-01") is None                  # no secret: no licenses
