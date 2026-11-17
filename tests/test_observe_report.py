"""Phase 1: observe mode (all, or per rule), decision latency, "this was legit" feedback and the weekly report."""
import json
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pilot  # noqa: E402
import selfguard  # noqa: E402
import weekly  # noqa: E402
from test_server import BOSS, H, c, server  # noqa: E402,F401


def use_rules(monkeypatch, tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text)
    monkeypatch.setattr(server, "policy", server.Policy(path))
    server.policy._maybe_reload()
    return path


def act(c, name, inp, **kw):
    return c.post("/v1/events", headers=H, json={"name": name, "input": inp, "source": "obs-agent",
                                                 "session_id": kw.pop("session", str(uuid.uuid4())), **kw}).json()


def test_observe_records_what_would_have_happened(c, monkeypatch, tmp_path):
    use_rules(monkeypatch, tmp_path, "default: allow\nmode: observe\nrules:\n"
              "  - { id: hold-pay, action: review, match: { name: 'pay.*' } }\n"
              "  - { id: no-wipe, action: deny, match: { name: 'wipe.*' } }\n")
    assert server.policy.mode == "shadow"
    held, blocked = act(c, "pay.send", {"amount": 1}), act(c, "wipe.all", {})
    assert (held["decision"], held["would"]) == ("allow", "review")
    assert (blocked["decision"], blocked["would"]) == ("allow", "deny")


def test_mode_per_rule(c, monkeypatch, tmp_path):
    use_rules(monkeypatch, tmp_path, "default: allow\nmode: observe\nrules:\n"
              "  - { id: wipe, action: deny, mode: enforce, match: { name: 'wipe.*' } }\n"
              "  - { id: pay, action: review, match: { name: 'pay.*' } }\n")
    assert act(c, "wipe.all", {})["decision"] == "deny"           # the catastrophic one is enforced
    assert act(c, "pay.send", {"amount": 2})["would"] == "review"   # the rest is observed
    use_rules(monkeypatch, tmp_path, "default: allow\nrules:\n"
              "  - { id: pay, action: review, mode: observe, match: { name: 'pay.*' } }\n")
    d = act(c, "pay.send", {"amount": 3})
    assert (d["decision"], d["would"]) == ("allow", "review")


def test_bad_mode_keeps_the_last_good_rules(c, monkeypatch, tmp_path):
    use_rules(monkeypatch, tmp_path, "default: allow\nrules:\n  - { id: x, action: deny, mode: loud, match: { name: x } }\n")
    assert not any(r["id"] == "x" for r in server.policy.rules)


def test_latency_feedback_and_weekly_report(c, monkeypatch, tmp_path):
    use_rules(monkeypatch, tmp_path, "default: allow\nrules:\n"
              "  - { id: fp-hold, action: review, timeout_seconds: 600, match: { name: 'fp.*' } }\n"
              "sequences:\n  - id: fp-chain\n    action: deny\n    reason: Exporting right after reading the customer list\n"
              "    match: { name: 'fpx.export' }\n    after: { match: { name: 'fpx.read' }, scope: session }\n")
    s = str(uuid.uuid4())
    act(c, "fpx.read", {}, session=s, output="rows")
    chain = act(c, "fpx.export", {"to": "x"}, session=s)
    assert chain["decision"] == "deny"
    held = [act(c, "fp.thing", {"n": i})["event_id"] for i in range(4)]
    assert c.get(f"/v1/events/{held[0]}", headers=BOSS).json()["decision_ms"] > 0

    assert selfguard.check("tool_call", "Bash", {"command": f"squidbrake feedback {held[0]} legit"}, {},
                           tmp_path)["effect"] == "block"            # an agent can't clear its own record
    assert c.post(f"/v1/events/{held[0]}/feedback", headers=BOSS, json={"verdict": "legit"}).json()["feedback"] == "legit"
    allowed = act(c, "other.thing", {})["event_id"]
    assert c.post(f"/v1/events/{allowed}/feedback", headers=BOSS, json={"verdict": "legit"}).status_code == 409

    r = weekly.build(server.engine, server.events, 7)
    assert r["false_positives"]["by_rule"]["fp-hold"]["legit"] == 1
    assert r["false_positives"]["by_rule"]["fp-hold"]["stopped"] >= 4
    assert r["latency_ms"]["p50"] is not None and r["latency_ms"]["p99"] >= r["latency_ms"]["p50"]
    assert any(t["rule"] == "sequence:fp-chain" and "customer list" in t["story"] for t in r["top_chains"])
    md = c.get("/v1/reports/week", headers=BOSS, params={"format": "md"}).text
    assert "False positives" in md and "Decision time" in md and "Chains caught" in md
    assert c.get("/v1/reports/summary", headers=BOSS).json()["week"]["actions"]["seen"] >= 6


def test_report_says_what_it_did_not_measure():
    """A pilot's review: no feedback is not 0% false positives, non-tool records and warned-but-allowed actions show."""
    r = {"days": 30, "actions": {"seen": 50, "held": 3, "blocked": 2, "would_hold": 0, "would_block": 0,
                                 "approved": 0, "rejected": 0, "warned": 4},
         "other_kinds": {"local_test_summary": 40},
         "false_positives": {"legit": 0, "stopped": 5, "rated": 0, "rate": None, "by_rule": {}, "by_week": {}},
         "latency_ms": {"n": 50, "p50": 1.0, "p95": 2.0, "p99": 3.0}, "top_chains": []}
    md = weekly.markdown(r)
    assert "not measured" in md and "0.0%" not in md
    assert "40 `local_test_summary`" in md and "Let through with a warning:** 4" in md
    r["false_positives"].update(rated=5, rate=0.0)
    assert "0 of 5 stopped actions were marked legit (0.0%)" in weekly.markdown(r)


def test_warned_counts_risks_let_through_not_info_notes(c):
    """An allowed action with only an "info" note (how much it would change) wasn't warned about."""
    before = weekly.build(server.engine, server.events, 7)["actions"]["warned"]
    with server.audited_tx() as conn:
        for effect in ("info", "warn"):
            conn.execute(server.events.insert().values(
                id=str(uuid.uuid4()), created_at=server.utcnow(), kind="tool_call", name="Bash", status="completed",
                decision="allow", signals=json.dumps([{"check": "effect" if effect == "info" else "rename_command",
                                                       "effect": effect, "message": "x"}])))
    assert weekly.build(server.engine, server.events, 7)["actions"]["warned"] == before + 1


def test_cli_report_and_feedback(c, capsys, tmp_path):
    held = c.post("/v1/events", headers=H, json={"name": "payments.send", "input": {"amount": 7}}).json()["event_id"]
    assert server.main(["feedback", held, "right"]) == 0
    assert c.get(f"/v1/events/{held}", headers=BOSS).json()["feedback"] == "right"
    assert server.main(["report", "--week", "--json"]) == 0
    assert json.loads(capsys.readouterr().out.split("\n", 1)[1])["days"] == 7
    out = tmp_path / "week.md"
    assert server.main(["report", "--days", "3", "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# Squidbrake: the last 3 days")


def test_pilot_counts_include_latency_and_legit_only_as_numbers(c):
    u = pilot.usage(server.engine, server.events, "enforce", 1, "9.9.9")
    assert set(u["latency_ms"]) == {"n", "p50", "p95", "p99"}
    assert all("legit" in day for day in u["days"].values())


def test_connect_mode_observe_sets_the_rules(tmp_path, monkeypatch):
    import connect
    rules = tmp_path / "rules.yaml"
    rules.write_text("default: review\nmode: enforce\nrules: []\n", encoding="utf-8")
    monkeypatch.setattr(server, "RULES_PATH", rules)
    connect.set_mode("http://localhost:8080", "observe")
    assert "mode: shadow" in rules.read_text(encoding="utf-8")
    connect.set_mode("http://localhost:8080", "enforce")
    assert "mode: enforce" in rules.read_text(encoding="utf-8") and "shadow" not in rules.read_text(encoding="utf-8")
