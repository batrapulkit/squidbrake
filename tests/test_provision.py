"""provision.py: a hosted gateway whose keys never reached the start page is recreated, not left half-running."""
import sys
from pathlib import Path

import pytest

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
    assert "SQUIDBRAKE_PLAN=team" in run    # blocks with the trial's license; after the trial, unpaid, it only watches
    assert ("exec", "sbp-co2", "python", "-c", provision.LICENSE_SET, "LIC1") in calls
    calls2, _ = fake(monkeypatch, ["true", "true"])
    running = {"code": "co-2", "subdomain": "co2", "dashboard": "https://co2.app.test", "keys_ready": True, "license": "LIC1"}
    provision.start(running)
    provision.start(running | {"license": "LIC2"})          # renewed: written again
    sets = [c for c in calls2 if c[:1] == ("exec",)]
    assert sets == [("exec", "sbp-co2", "python", "-c", provision.LICENSE_SET, "LIC2")]


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


def test_a_healthy_running_gateway_gets_its_license_from_the_loop(monkeypatch):
    calls, _ = fake(monkeypatch, [])
    provision._licensed.clear()
    pilot = {"code": "co-4", "subdomain": "co4", "state": "running", "keys_ready": True, "license": "L4",
             "dashboard": "https://co4.app.test"}
    monkeypatch.setattr(provision, "api", lambda path, body=None: {"pilots": [pilot]} if path == "/v1/admin/provision" else {})
    provision.tick()
    provision.tick()
    assert [c for c in calls if c[:1] == ("exec",)] == [("exec", "sbp-co4", "python", "-c", provision.LICENSE_SET, "L4")]
    assert not any(c[0] == "run" for c in calls)              # not restarted


def test_keys_that_dont_open_the_gateway_are_never_handed_out(monkeypatch):
    """The founder sees the keys once: if the ones in the log don't open this gateway, nothing is reported as ready,
    so the next tick recreates it instead of showing dead keys on the start page."""
    calls, reports = fake(monkeypatch, [None])
    real = provision.docker

    def docker(*args, check=True):
        if args[:1] == ("exec",) and provision.KEY_CHECK in args:
            raise RuntimeError("docker exec (exit 3): 401")
        return real(*args, check=check)
    monkeypatch.setattr(provision, "docker", docker)
    try:
        provision.start({"code": "co-1", "subdomain": "co", "dashboard": "https://co.app.test", "keys_ready": False})
        raise AssertionError("should have raised")
    except RuntimeError as e:
        assert "doesn't open it" in str(e)
    assert not any(b and b.get("admin_key") for _, b in reports)


def test_a_failing_join_doesnt_stop_the_dashboard(monkeypatch):
    """Joining only shares usage counts: three failed tries are logged, and the gateway is still reported ready."""
    calls, reports = fake(monkeypatch, [None])
    real = provision.docker
    monkeypatch.setattr(provision.time, "sleep", lambda s: None)

    def docker(*args, check=True):
        if args[:1] == ("exec",) and provision.JOIN in args:
            raise RuntimeError("docker exec (exit 137): killed")
        return real(*args, check=check)
    monkeypatch.setattr(provision, "docker", docker)
    provision.start({"code": "co-1", "subdomain": "co", "dashboard": "https://co.app.test", "keys_ready": False})
    body = reports[-1][1]
    assert body["state"] == "running" and body["admin_key"] == "gw_admin_AAAA"


def test_the_snippets_run_on_python_38():
    """They run inside the gateway, but the provisioner itself runs on the server's Python 3.8."""
    import ast
    for src in (provision.KEY_CHECK, provision.JOIN):
        ast.parse(src, feature_version=(3, 8))
    ast.parse((Path(__file__).resolve().parents[1] / "insights" / "provision.py").read_text(encoding="utf-8"),
              feature_version=(3, 8))


def test_lost_keys_get_new_ones_and_connected_agents_keep_working(tmp_path, monkeypatch):
    """The real snippets, on a real keys.json: new admin and agent keys open the gateway, the old admin key stops."""
    import subprocess
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    import server
    store = server.KeyStore(tmp_path / "keys.json")
    first = store.ensure_initialized()
    alice = store.add("alice", approver=True)
    reports = []

    def docker(*args, check=True):
        assert args[:4] == ("exec", "sbp-co", "python", "-c")
        code = args[4].replace("/app/data", str(tmp_path).replace("\\", "/"))
        out = subprocess.run([sys.executable, "-c", code, *args[5:]], capture_output=True, text=True, cwd=root)
        assert out.returncode == 0, out.stderr
        return out.stdout.strip()
    monkeypatch.setattr(provision, "docker", docker)
    monkeypatch.setattr(provision, "key_works", lambda name, key: store.identify(key) is not None)
    monkeypatch.setattr(provision, "api", lambda path, body=None: reports.append(body) or {})
    provision.new_keys({"code": "co-1", "subdomain": "co"})
    got = reports[-1]
    assert got["state"] == "running" and store.is_owner(store.identify(got["admin_key"]))
    assert not store.is_person(store.identify(got["agent_key"]))
    assert store.identify(first["admin"]) is None                     # the lost admin key stops working
    assert store.identify(first["agent"]) == "agent" and store.identify(alice) == "alice"   # the rest keep working


def test_new_keys_never_end_up_in_an_error_or_with_a_founder_unless_they_work(monkeypatch):
    reports = []
    monkeypatch.setattr(provision, "api", lambda path, body=None: reports.append(body) or {})

    def killed(*a, check=True):
        raise RuntimeError('docker exec (exit 137): ...{"old": [], "admin": "gw_SECRET"')
    monkeypatch.setattr(provision, "docker", killed)
    with pytest.raises(RuntimeError) as e:
        provision.new_keys({"code": "co-1", "subdomain": "co"})
    assert "gw_" not in str(e.value)
    monkeypatch.setattr(provision, "docker", lambda *a, check=True: '{"old": ["admin"], "admin": "gw_a", "agent": "gw_b"}')
    monkeypatch.setattr(provision, "key_works", lambda name, key: False)
    with pytest.raises(RuntimeError):
        provision.new_keys({"code": "co-1", "subdomain": "co"})
    assert reports == []


def test_the_license_is_written_without_loading_the_gateway(tmp_path, monkeypatch):
    """`server.py license set` loaded a second gateway in a 192 MB container: OOM, a restart, and a retry every tick."""
    import subprocess
    import license
    root = Path(__file__).resolve().parents[1]
    code = provision.LICENSE_SET.replace("Path('/app/data')", f"Path({str(tmp_path)!r})")
    monkeypatch.setattr(license, "check", lambda t: {"org": "Co"} if t == "GOOD" else None)
    monkeypatch.setattr(sys, "argv", ["-c", "GOOD"])
    exec(code, {})
    f = tmp_path / license.FILE
    assert f.read_text(encoding="utf-8") == "GOOD\n"
    before = f.stat().st_mtime_ns
    exec(code, {})                                   # the same license again: nothing written
    assert f.stat().st_mtime_ns == before
    monkeypatch.setattr(sys, "argv", ["-c", "FORGED"])
    with pytest.raises(SystemExit):
        exec(code, {})
    probe = "import sys\ntry:\n    exec(sys.argv[1])\nexcept SystemExit:\n    pass\nprint('server' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", probe, code, "not-a-license"], cwd=root, capture_output=True, text=True,
                         env={**__import__("os").environ, "PYTHONPATH": str(root)})
    assert out.stdout.strip() == "False", out.stderr     # the gateway (server.py) is never imported


def test_a_sleeping_gateway_is_stopped_never_removed_and_wakes_as_it_was(monkeypatch):
    calls, reports = fake(monkeypatch, ["true", "false"])
    pilot = {"code": "co-z", "subdomain": "coz", "state": "sleeping", "keys_ready": True, "dashboard": "https://coz.app.test"}
    monkeypatch.setattr(provision, "api", lambda path, body=None: {"pilots": [pilot]} if path == "/v1/admin/provision"
                        else reports.append((path, body)) or {})
    provision.tick()                                          # running: stopped
    provision.tick()                                          # already stopped: left as it is
    assert [c for c in calls if c[0] != "inspect"] == [("stop", "-t", "20", "sbp-coz")]
    assert not any(c[0] in ("rm", "volume", "run") for c in calls) and reports == []
    calls_, reports_ = fake(monkeypatch, ["false"])          # woken (state requested): the same container starts again
    provision.start({**pilot, "state": "requested"})
    assert ("start", "sbp-coz") in calls_ and not any(c[0] in ("rm", "run") for c in calls_)
    assert reports_[-1] == ("/v1/admin/provisioned", {"code": "co-z", "state": "running"})


def test_a_failing_setup_is_reported_and_tried_again_later(monkeypatch):
    reports = []
    pilot = {"code": "co-f", "subdomain": "cof", "state": "requested", "keys_ready": False, "dashboard": "https://cof.app.test"}
    monkeypatch.setattr(provision, "api", lambda path, body=None: {"pilots": [pilot]} if path == "/v1/admin/provision"
                        else reports.append(body) or {})

    def broken(p):
        raise RuntimeError("docker is down")
    monkeypatch.setattr(provision, "start", broken)
    provision.last_failure.clear()
    provision.tick()
    assert reports == [{"code": "co-f", "state": "failed", "error": "docker is down"}]
