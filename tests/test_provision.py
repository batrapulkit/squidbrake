"""provision.py: a hosted gateway whose keys never reached the start page is recreated, not left half-running."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "insights"))

import provision  # noqa: E402


def fake(monkeypatch, running):
    calls, reports = [], []
    keys = "admin  gw_admin_AAAA\nagent  gw_agent_BBBB\n"

    def docker(*args, check=True):
        calls.append(args)
        if args[0] == "inspect":
            return running.pop(0) if running else "true"
        return keys if args[0] == "logs" else ""
    monkeypatch.setattr(provision, "docker", docker)
    monkeypatch.setattr(provision, "api", lambda path, body=None: reports.append((path, body)) or {})
    return calls, reports


def test_a_gateway_without_keys_is_recreated(monkeypatch):
    calls, reports = fake(monkeypatch, ["true"])          # the container exists (crash-looping), keys never captured
    provision.start({"code": "co-1", "subdomain": "co", "dashboard": "https://co.app.test", "keys_ready": False})
    names = [c[0] for c in calls]
    assert ("rm", "-f", "sbp-co") in calls and ("volume", "rm", "sbp-co") in calls
    assert names.index("rm") < names.index("run")         # removed before it starts fresh
    body = reports[-1][1]
    assert body["state"] == "running" and body["admin_key"] == "gw_admin_AAAA" and body["agent_key"] == "gw_agent_BBBB"


def test_a_working_gateway_is_left_alone(monkeypatch):
    calls, reports = fake(monkeypatch, ["true"])
    provision.start({"code": "co-1", "subdomain": "co", "dashboard": "https://co.app.test", "keys_ready": True})
    assert [c[0] for c in calls] == ["inspect"]           # nothing removed, nothing recreated
    assert reports == [("/v1/admin/provisioned", {"code": "co-1", "state": "running"})]
