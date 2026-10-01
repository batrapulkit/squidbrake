"""
Replay real AI-agent incidents against Squidbrake's shipped rules.yaml and show what it would have done.

    python incidents/replay.py

Runs on a throwaway database; nothing touches your gateway. See scenarios.py for the incidents and their sources.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from scenarios import SCENARIOS  # noqa: E402

VERB = {"deny": "BLOCKED", "review": "HELD for a person", "allow": "ALLOWED"}


def replay(client, headers: dict, approver: dict, scenario: dict) -> list[dict]:
    """Post a scenario's steps; return one result per expected (harmful) step."""
    session = f"incident-{scenario['id']}-{time.time_ns()}"
    source = f"incident:{scenario['id']}"
    results = []
    for step in scenario["steps"]:
        if "prompt" in step:
            body = {"name": "user.prompt", "kind": "prompt", "input": {"prompt": step["prompt"]},
                    "output": {"recorded": True}}
        else:
            body = {"name": step["tool"], "input": step.get("input")}
            if "output" in step:
                body["output"] = step["output"]
        d = client.post("/v1/events", headers=headers, json={**body, "session_id": session, "source": source}).json()
        if "expect" not in step:
            continue
        e = step["expect"]
        checks = [d["decision"] == e["decision"]]
        if e.get("rule"):
            checks.append((d.get("rule_id") or "").startswith(e["rule"]))
        if e.get("reason_has"):
            checks.append(e["reason_has"] in (d.get("reason") or ""))
        if e.get("signal"):
            checks.append(any(s["check"] == e["signal"] for s in d.get("signals") or []))
        outcome = "not_stopped" if d["decision"] == "allow" else "stopped"
        if d["decision"] == "review":
            if step.get("after_approval"):
                # Model a person approving the legitimate-looking call. The described side effect is data only:
                # it happens beyond the gateway in the real incident and is never executed by this replay.
                approved = client.post(f"/v1/events/{d['event_id']}/approve", headers=approver,
                                       json={"note": "synthetic incident replay"}).json()
                outcome = "not_stopped" if approved.get("decision") == "allow" else "stopped"
            else:   # tidy up: nothing should stay waiting
                client.post(f"/v1/events/{d['event_id']}/reject", headers=approver, json={"note": "incident replay"})
        results.append({"tool": step["tool"], "input": step["input"], "decision": d["decision"],
                        "rule_id": d.get("rule_id"), "reason": d.get("reason"), "signals": d.get("signals") or [],
                        "after_approval": step.get("after_approval"), "outcome": outcome,
                        "expected": e, "ok": all(checks)})
    return results


def outcome(results: list[dict]) -> str:
    """Return the scenario outcome: one unstopped harmful action makes the incident not stopped."""
    return "not_stopped" if any(r["outcome"] == "not_stopped" for r in results) else "stopped"


def run_all(client, headers: dict, approver: dict) -> list[tuple[dict, list[dict]]]:
    """Every scenario against the shipped rules.yaml (swapped in for the replay, then put back)."""
    import server
    shipped = server.Policy(ROOT / "rules.yaml")
    shipped._maybe_reload()
    previous, server.policy = server.policy, shipped
    try:
        return [(s, replay(client, headers, approver, s)) for s in SCENARIOS]
    finally:
        server.policy = previous


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    os.environ.update(DATABASE_URL=f"sqlite:///{(tmp / 'replay.db').as_posix()}", KEYS_PATH=str(tmp / "keys.json"),
                      RULES_PATH=str(ROOT / "rules.yaml"), GATEWAY_AUTH="off", LOG_LEVEL="WARNING")
    from fastapi.testclient import TestClient
    import server
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    with TestClient(server.app) as client:
        outcomes = run_all(client, {}, {})
    failed_checks = 0
    failed_outcomes = 0
    stopped = 0
    not_stopped = 0
    for s, results in outcomes:
        print(f"\n{s['title']} ({s['when']})\n  {s['source']}")
        for r in results:
            mark = "✓" if r["ok"] else "✗"
            failed_checks += not r["ok"]
            what = r["input"].get("command") or r["input"].get("query") or f"{r['tool']} {r['input']}"
            print(f"  {mark} {VERB[r['decision']]}: {str(what)[:90]}\n      {r['reason'][:160]}")
            if r["outcome"] == "not_stopped":
                detail = r["after_approval"] or "the gateway allowed the harmful action"
                print(f"      NOT STOPPED: {detail}")
        actual = outcome(results)
        expected = s.get("expected_outcome", "stopped")
        failed_outcomes += actual != expected
        stopped += sum(r["outcome"] == "stopped" for r in results)
        not_stopped += sum(r["outcome"] == "not_stopped" for r in results)
    total = stopped + not_stopped
    matched = total - failed_checks
    outcome_matches = len(outcomes) - failed_outcomes
    print(f"\n{stopped} of {total} harmful actions stopped across {len(outcomes)} incidents; "
          f"{not_stopped} not stopped. {matched} action checks and {outcome_matches} expected outcomes matched.")
    return 1 if failed_checks or failed_outcomes else 0


if __name__ == "__main__":
    sys.exit(main())
