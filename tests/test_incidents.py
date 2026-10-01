"""Every incident must match the stopped/not-stopped outcome documented for the shipped rules.yaml."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "incidents"))
if "server" not in sys.modules:   # run on its own: a throwaway database (test_server.py sets the same keys)
    _tmp = Path(tempfile.mkdtemp())
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(_tmp / 'gw.db').as_posix()}")
    os.environ.setdefault("RULES_PATH", str(_tmp / "rules.yaml"))
    os.environ.setdefault("GATEWAY_API_KEYS", "tester:k1,boss:k2,boss2:k3")
    os.environ.setdefault("GATEWAY_APPROVERS", "boss,boss2")

import pytest  # noqa: E402

from scenarios import SCENARIOS  # noqa: E402


@pytest.fixture(scope="module")
def outcomes():
    from fastapi.testclient import TestClient
    import replay
    import server
    with TestClient(server.app) as client:
        return dict((s["id"], r) for s, r in replay.run_all(client, {"X-Gateway-Key": "k1"}, {"X-Gateway-Key": "k2"}))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_incident_matches_expected_outcome(outcomes, scenario):
    import replay
    results = outcomes[scenario["id"]]
    assert results, "every scenario needs at least one expected step"
    for r in results:
        assert r["ok"], (r["tool"], r["input"], r["decision"], r["rule_id"], r["reason"], r["expected"])
    expected = scenario.get("expected_outcome", "stopped")
    assert expected in ("stopped", "not_stopped")
    assert replay.outcome(results) == expected
    if expected == "not_stopped":
        assert scenario.get("not_stopped_because"), "document why the gateway cannot stop this incident"
        assert any(r["outcome"] == "not_stopped" for r in results)
    else:
        assert all(r["decision"] in ("deny", "review") for r in results), "an expected stop was allowed"
