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


def test_a_free_signup_gets_its_plan_and_end_date(monkeypatch):
    calls, _ = fake(monkeypatch, [""])
    provision.start({"code": "co-1", "subdomain": "co", "dashboard": "https://co.app.test", "keys_ready": False,
                     "plan": "free", "trial_ends": "2026-11-02T10:00:00+00:00"})
    run = next(c for c in calls if c[0] == "run")
    assert "SQUIDBRAKE_PLAN=free" in run and "SQUIDBRAKE_TRIAL_ENDS=2026-11-02T10:00:00+00:00" in run


def test_a_team_trial_gets_a_license_not_the_free_plan_and_a_running_one_gets_it_once(monkeypatch):
    calls, _ = fake(monkeypatch, [""])
    provision._licensed.clear()
    provision.start({"code": "co-2", "subdomain": "co2", "dashboard": "https://co2.app.test", "keys_ready": False,
                     "plan": "team", "trial_ends": "2026-11-03", "license": "LIC1"})
    run = next(c for c in calls if c[0] == "run")
    assert not any("SQUIDBRAKE_PLAN" in a for a in run)    # after the trial it keeps blocking; only Team features stop
    assert ("exec", "sbp-co2", "python", "server.py", "license", "set", "LIC1") in calls
    calls2, _ = fake(monkeypatch, ["true", "true"])
    running = {"code": "co-2", "subdomain": "co2", "dashboard": "https://co2.app.test", "keys_ready": True, "license": "LIC1"}
    provision.start(running)
    provision.start(running | {"license": "LIC2"})          # renewed: written again
    sets = [c for c in calls2 if c[:1] == ("exec",)]
    assert sets == [("exec", "sbp-co2", "python", "server.py", "license", "set", "LIC2")]


def test_a_license_that_did_not_take_is_tried_again(monkeypatch):
    calls, _ = fake(monkeypatch, ["true", "true"])
    provision._licensed.clear()
    real = provision.docker

    def old_gateway(*args, check=True):
        if args[:1] == ("exec",):
            calls.append(args)
            raise RuntimeError("invalid choice: 'license'")
        return real(*args, check=check)
    monkeypatch.setattr(provision, "docker", old_gateway)
    p = {"code": "co-3", "subdomain": "co3", "dashboard": "https://co3.app.test", "keys_ready": True, "license": "L"}
    provision.start(p)
    provision.start(p)
    assert sum(1 for c in calls if c[:1] == ("exec",)) == 2
