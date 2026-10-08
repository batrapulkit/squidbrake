"""Data checks: text an agent puts where others read it (a PR, an issue, a comment, a post) that names a customer on the
team's list, or carries personal data, waits for a person."""
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import outbound  # noqa: E402
from test_server import BOSS, H, c, server  # noqa: E402,F401  (the throwaway gateway and its keys)


@pytest.mark.parametrize("text,names,expected", [
    ("Fixes the export bug Acme Corp hit", ["Acme Corp", "Globex"], ["Acme Corp"]),
    ("acme corp and GLOBEX both", ["Acme Corp", "Globex"], ["Acme Corp", "Globex"]),
    ("Acme Corporation, acmecorp.com, notacme corp", ["Acme Corp"], []),       # whole names only
    ("anything", ["Al", ""], []),                                                 # too short to match safely
])
def test_customer_names(text, names, expected):
    assert outbound.customers_named(text, names) == expected


@pytest.mark.parametrize("text,expected", [
    ("card 4242 4242 4242 4242", ["a card number"]),
    ("order 4242 4242 4242 4241", []),                                    # fails the card checksum
    ("ssn 123-45-6789", ["a social security number"]),
    ("GB82 WEST 1234 5698 7654 32", ["a bank account number (IBAN)"]),
    ("a@x.com, b@y.com, c@z.com", ["3 email addresses"]),
    ("a@x.com, b@y.com and the team at ops@acme.com", []),               # two outside addresses: not a list of people
    ("+1 415 555 0100, +44 20 7946 0958, (212) 555-0199", ["3 phone numbers"]),
    ("v2.3.1 built 20261007120000, PR #4182", []),
])
def test_personal_data(text, expected):
    assert outbound.personal_data(text, ["acme.com"]) == expected


@pytest.mark.parametrize("name,command,shared", [
    ("github.create_pull_request", None, True), ("github.add_issue_comment", None, True),
    ("slack.post_message", None, True), ("github.list_issues", None, False), ("github.search_issues", None, False),
    ("github.pull_request_read", None, False), ("email.send", None, False),
    ("Bash", 'gh pr create --title fix --body "for Acme Corp"', True), ("Bash", "gh pr view 12", False),
])
def test_where_others_read_it(name, command, shared):
    assert outbound.is_shared_place(name, command, outbound.DEFAULT_WHERE) is shared


def test_the_gateway_holds_them(c, monkeypatch, tmp_path):
    rules = tmp_path / "data.yaml"
    rules.write_text("default: allow\n")              # data_checks default to review
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    assert c.put("/v1/settings", headers=H, json={"customers": ["Acme Corp"]}).status_code == 403   # admins only
    r = c.put("/v1/settings", headers=BOSS, json={"customers": [" Acme Corp ", "Globex", "Acme Corp", ""]})
    assert r.status_code == 200 and r.json()["customers"] == ["Acme Corp", "Globex"]
    post = lambda name, inp: c.post("/v1/events", headers=H, json={"name": name, "input": inp,
                                                                     "session_id": f"data-{time.time_ns()}"}).json()

    d = post("github.create_pull_request", {"title": "Fix export", "body": "Acme Corp reported the export bug"})
    assert d["decision"] == "review" and d["rule_id"] == "data:customer_names" and "Acme Corp" in d["reason"]
    d = post("Bash", {"command": 'gh issue comment 7 --body "Globex hit this too"'})
    assert d["decision"] == "review" and d["rule_id"] == "data:customer_names"
    d = post("slack.post_message", {"channel": "#general", "text": "refund for card 4242 4242 4242 4242"})
    assert d["decision"] == "review" and d["rule_id"] == "data:personal_data" and "4242" not in d["reason"]
    assert post("github.create_pull_request", {"title": "Fix export", "body": "Fixes the CSV export"})["decision"] == "allow"
    assert post("github.search_issues", {"query": "Acme Corp"})["decision"] == "allow"          # looking it up is fine
    assert post("email.send", {"to": "ops@acme-corp.example", "text": "Hi Acme Corp"})["decision"] == "allow"

    rules.write_text("default: allow\ndata_checks: { customer_names: off }\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    assert post("github.create_pull_request", {"body": "Acme Corp"})["decision"] == "allow"
    bad = tmp_path / "bad.yaml"
    bad.write_text("default: allow\ndata_checks: { personal_data: maybe }\n")
    p = server.Policy(bad)
    p._maybe_reload()
    assert p.data["personal_data"] == "review"          # a bad value is refused; the safe default stays
    c.put("/v1/settings", headers=BOSS, json={"customers": []})
