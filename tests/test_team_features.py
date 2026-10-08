"""What a team running agents asks for after week one: the weekly "what it caught" report, rules suggested from what
people keep approving, starter packs per kind of agent, approvals by Teams and email, and every decision to a SIEM."""
import json
import shutil
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import policy_edit  # noqa: E402
import siem  # noqa: E402
from test_server import BOSS, BOSS2, H, c, server  # noqa: E402,F401


AGENT = f"team-features-{time.time_ns()}"     # its own agent name: other tests' refunds don't count toward its limits


def post(c, name, inp, **kw):
    return c.post("/v1/events", headers=H, json={"name": name, "input": inp, "session_id": f"tf-{time.time_ns()}",
                                                 "source": AGENT, **kw}).json()


@pytest.fixture()
def shipped(monkeypatch, tmp_path):
    """The shipped rules, in a copy the test may edit."""
    path = tmp_path / "rules.yaml"
    shutil.copy(ROOT / "rules.yaml", path)
    monkeypatch.setattr(server, "policy", server.Policy(path))
    server.policy._maybe_reload()
    return path


# ---- the weekly report says what it caught

def test_weekly_report_names_what_was_caught(c, shipped):
    post(c, "Bash", {"command": "rm -rf ~/"})                                       # blocked
    held = post(c, "Bash", {"command": "git push --force origin main"})
    c.post(f"/v1/events/{held['event_id']}/reject", headers=BOSS, json={"note": "not on main"})
    post(c, "Bash", {"command": "npm test"})                                        # routine: not in the list
    caught = [x for x in server.caught(7, limit=1000) if x["agent"] == AGENT]   # other tests' catches share this database
    outcomes = [(x["outcome"], x["what"]) for x in caught]
    assert ("blocked", "rm -rf ~/") in outcomes and ("rejected", "git push --force origin main") in outcomes
    assert outcomes.index(("blocked", "rm -rf ~/")) < outcomes.index(("rejected", "git push --force origin main"))
    text = server.digest_text(server.build_report(7), caught)
    assert "What it caught" in text and "`rm -rf ~/`" in text and 'by boss ("not on main")' in text
    assert all(x["what"] != "npm test" for x in caught)


def test_the_report_goes_to_discord_teams_and_email(c, monkeypatch):
    sent = []
    monkeypatch.setattr(server.httpx, "post", lambda url, json=None, timeout=None, **k: sent.append((url, json))
                        or type("R", (), {"raise_for_status": lambda self: None})())
    mails = []
    monkeypatch.setattr(server, "send_email", lambda cfg, subject, text: mails.append((subject, text)) or True)
    monkeypatch.setattr(server, "settings", lambda: {**_base(), "weekly_digest": True,
                        "slack_webhook": "https://discord.com/api/webhooks/1/x", "teams_webhook": "https://t.example/wf",
                        "email_to": "ops@acme.com", "smtp_host": "smtp.acme.com"})
    monkeypatch.setattr(server, "datetime", _Monday)
    with server.audited_tx() as conn:
        server.state_set(conn, "digest_week", "")
    server.maybe_send_digest()
    discord = next(b for u, b in sent if "discord" in u)
    assert "content" in discord and "text" not in discord                          # Discord's format, not Slack's
    teams = next(b for u, b in sent if u == "https://t.example/wf")
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert mails and mails[0][0] == "What your AI agents did this week" and "*" not in mails[0][1]


_real_settings = server.settings


def _base():
    return _real_settings()


class _Monday(server.datetime):
    @classmethod
    def now(cls, tz=None):
        return server.datetime(2026, 10, 12, 10, 0, tzinfo=tz)


# ---- rules suggested from what people keep approving

def test_suggestions_and_adding_one(c, shipped):
    for _ in range(5):
        d = post(c, "deploy.staging", {"service": "api"})                           # held by the default
        assert d["decision"] == "review"
        c.post(f"/v1/events/{d['event_id']}/approve", headers=BOSS, json={})
    for _ in range(6):                                                               # money: never suggested
        d = post(c, "payments.refund", {"charge": "ch_1", "amount": 9})
        c.post(f"/v1/events/{d['event_id']}/approve", headers=BOSS, json={})
    d = post(c, "deploy.prod", {"env": "x"})                                         # once rejected: never suggested
    for _ in range(5):
        d = post(c, "deploy.prod", {"env": "x"})
        c.post(f"/v1/events/{d['event_id']}/approve", headers=BOSS, json={})
    c.post(f"/v1/events/{post(c, 'deploy.prod', {'env': 'x'})['event_id']}/reject", headers=BOSS, json={})
    assert c.get("/v1/policy/suggestions", headers=H).status_code == 403
    s = c.get("/v1/policy/suggestions", headers=BOSS).json()["suggestions"]
    assert [x["tool"] for x in s] == ["deploy.staging"] and s[0]["approved"] >= 5
    r = c.post(f"/v1/policy/suggestions/{s[0]['id']}/apply", headers=BOSS).json()
    assert r["ok"] and (shipped.parent / r["backup"]).exists()
    assert post(c, "deploy.staging", {"service": "api"})["decision"] == "allow"      # stops asking
    assert post(c, "Bash", {"command": "rm -rf ~/"})["decision"] == "deny"          # blocks still win
    assert c.get("/v1/policy/suggestions", headers=BOSS).json()["suggestions"] == []


def test_shell_suggestions_group_by_program_and_subcommand():
    rows = [type("R", (), {"name": "Bash", "input": json.dumps({"command": f"npm run deploy:staging -- --tag {i}"}),
                           "rule_id": None, "decision": "allow"})() for i in range(5)]
    rows += [type("R", (), {"name": "Bash", "input": json.dumps({"command": "git push --force origin main"}),
                            "rule_id": "command:irreversible_command", "decision": "allow"})() for _ in range(9)]
    s = policy_edit.suggestions(rows, ["Bash"])
    assert [x["what"] for x in s] == ["npm run deploy:staging"]                      # command checks never opened
    import re
    import yaml
    rule = yaml.safe_load("rules:\n" + s[0]["yaml"])["rules"][0]
    assert re.search(rule["match"]["input_regex"], json.dumps({"command": "npm run deploy:staging"}))
    assert not re.search(rule["match"]["input_regex"], json.dumps({"command": "npm run deploy:staging-db"}))


# ---- starter packs per kind of agent

def test_packs_go_after_reads_and_before_the_holds(c, shipped):
    r = c.post("/v1/policy/packs/support/apply", headers=BOSS).json()
    assert r["ok"]
    ids = [x["id"] for x in server.policy.rules]
    assert ids.index("allow-reads") < ids.index("support-small-refunds") < ids.index("approve-refunds")
    assert ids.index("block-destructive-shell") < ids.index("support-never-delete-customers")
    assert post(c, "payments.refund", {"charge": "ch_1", "amount": 20})["decision"] == "allow"
    assert post(c, "payments.refund", {"charge": "ch_1", "amount": 500})["decision"] == "review"
    assert post(c, "crm.delete_customer", {"id": 7})["decision"] == "deny"
    assert post(c, "crm.list_customers", {})["decision"] == "allow"                  # reads still run
    assert c.post("/v1/policy/packs/support/apply", headers=BOSS).status_code == 400  # already added
    packs = {p["id"]: p for p in c.get("/v1/policy/packs", headers=BOSS).json()["packs"]}
    assert packs["support"]["added"] and not packs["finance"]["added"]
    assert c.post("/v1/policy/packs/ops/apply", headers=BOSS).json()["ok"]
    assert post(c, "ops.get_version", {"customer": 1})["decision"] == "allow"         # looking runs
    assert post(c, "ops.pin_version", {"customer": 1, "v": "2.3"})["decision"] == "review"


def test_a_broken_insert_puts_the_file_back(tmp_path):
    path = tmp_path / "rules.yaml"
    shutil.copy(ROOT / "rules.yaml", path)
    before = path.read_text(encoding="utf-8")

    def refuses(_):
        raise ValueError("didn't load")
    with pytest.raises(ValueError):
        policy_edit.insert(path, policy_edit.PACKS["finance"]["yaml"], None, refuses)
    assert path.read_text(encoding="utf-8") == before


# ---- every decision to a SIEM

@pytest.mark.parametrize("fmt,header,starts", [("splunk", "Authorization", "Splunk tok"), ("datadog", "DD-API-KEY", "tok"),
                                               ("json", "Authorization", "Bearer tok")])
def test_siem_formats(fmt, header, starts):
    body, headers = siem.body_and_headers(fmt, "tok", [{"id": "e1", "tool": "Bash", "decision": "deny", "epoch": 1.0}])
    assert headers[header] == starts
    if fmt == "splunk":
        assert json.loads(body.decode().splitlines()[0])["event"]["tool"] == "Bash"
    else:
        assert json.loads(body)[0]["id"] == "e1"


def test_decisions_reach_the_siem(c, shipped, monkeypatch):
    got = []
    f = siem.Forwarder(lambda: {"siem_url": "https://siem.example/in", "siem_token": "t", "siem_format": "json"})
    monkeypatch.setattr(siem.httpx, "post", lambda url, content=None, headers=None, timeout=None:
                        got.extend(json.loads(content)) or type("R", (), {"raise_for_status": lambda s: None})())
    monkeypatch.setattr(server, "forwarder", f)
    d = post(c, "Bash", {"command": "rm -rf ~/"})
    held = post(c, "payments.refund", {"charge": "ch_2", "amount": 70})
    c.post(f"/v1/events/{held['event_id']}/approve", headers=BOSS, json={"note": "ok"})
    for _ in range(40):
        if len(got) >= 3:
            break
        time.sleep(0.1)
    kinds = {(g["type"], g["id"]) for g in got}
    assert ("decision", d["event_id"]) in kinds and ("approved", held["event_id"]) in kinds
    assert next(g for g in got if g["id"] == d["event_id"])["decision"] == "deny"
