"""`squidbrake` (and start.sh / start.bat) always run the gateway as a background service that starts at every
login and again when it stops, takes over from an older install's service, and keeps itself up to date."""
import json
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import service  # noqa: E402


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("SQUIDBRAKE_FOREGROUND", raising=False)
    monkeypatch.delenv("IN_DOCKER", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    calls = []
    monkeypatch.setattr(service, "_run", lambda *cmd: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""))
    return tmp_path, calls


def test_launchd_agent_runs_the_server_at_login_and_keeps_it_alive(fake_home, monkeypatch):
    home, calls = fake_home
    monkeypatch.setattr(service.os, "getuid", lambda: 501, raising=False)
    service._launchd_install(["--port", "9000"])
    plist = plistlib.loads((home / "Library/LaunchAgents/com.squidbrake.gateway.plist").read_bytes())
    assert plist["RunAtLoad"] is True and plist["KeepAlive"] is True
    assert plist["ProgramArguments"][1:] == [str(service.SERVER), "run", "--no-browser", "--port", "9000"]
    assert plist["WorkingDirectory"] == str(service.HERE)
    assert plist["EnvironmentVariables"]["SQUIDBRAKE_SERVICE"] == "1"     # the gateway knows a service restarts it
    assert ("launchctl", "bootstrap", "gui/501", str(home / "Library/LaunchAgents/com.squidbrake.gateway.plist")) in calls
    assert service._launchd_remove() and not service._launchd_installed()


def test_systemd_user_unit_restarts_and_starts_at_boot(fake_home):
    home, calls = fake_home
    service._systemd_install([])
    unit = (home / ".config/systemd/user/squidbrake.service").read_text()
    assert "Restart=always" in unit and "WantedBy=default.target" in unit
    assert f'{service._sd_quote(str(service.SERVER))} "run" "--no-browser"' in unit   # quoted, so \ doubles on Windows
    assert ("systemctl", "--user", "enable", "squidbrake.service") in calls
    assert any(c[:2] == ("loginctl", "enable-linger") for c in calls)
    assert service._systemd_remove() and not service._systemd_installed()


def test_foreground_when_asked_or_in_docker(monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_FOREGROUND", "1")
    assert service.backend() is None
    monkeypatch.delenv("SQUIDBRAKE_FOREGROUND")
    monkeypatch.setenv("IN_DOCKER", "1")
    assert service.backend() is None


def test_port_comes_from_the_run_options(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    assert service._port([]) == 8080
    assert service._port(["--port", "9000"]) == 9000
    assert service._port(["--port=9100"]) == 9100


def test_bare_squidbrake_command_goes_through_the_service(monkeypatch):
    seen = []
    monkeypatch.setattr(service, "main", lambda argv: seen.append(argv) or 0)
    monkeypatch.setenv("SQUIDBRAKE_TELEMETRY", "0")
    from squidbrake import cli
    for argv in (["squidbrake"], ["squidbrake", "--port", "9000"], ["squidbrake", "start", "--background"],
                 ["squidbrake", "service", "status"]):
        monkeypatch.setattr(sys, "argv", argv)
        assert cli.main() == 0
    assert seen == [["start"], ["start", "--port", "9000"], ["start", "--background"], ["status"]]


@pytest.fixture
def mac(tmp_path, monkeypatch):
    """A Mac with nothing installed yet; records what start() does instead of doing it."""
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    for var in ("SQUIDBRAKE_BACKGROUND", "SQUIDBRAKE_FOREGROUND", "IN_DOCKER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SQUIDBRAKE_NO_BROWSER", "1")
    did = {"installed": False, "foreground": 0, "asked": 0}
    monkeypatch.setattr(service, "backend", lambda: "launchd")
    monkeypatch.setattr(service, "_launchd_installed", lambda: did["installed"])
    monkeypatch.setattr(service, "_launchd_install", lambda run_args: did.update(installed=True) or "log")
    monkeypatch.setattr(service, "_foreground", lambda run_args: did.update(foreground=did["foreground"] + 1) or 0)
    monkeypatch.setattr(service, "_answering", lambda port: True)
    monkeypatch.setattr(service.subprocess, "call", lambda *a, **k: 0)
    monkeypatch.setattr(service.time, "sleep", lambda s: None)
    monkeypatch.setattr(service, "_interactive", lambda: True)

    def answer(text):
        def fake_input(prompt):
            did["asked"] += 1
            return text
        monkeypatch.setattr("builtins.input", fake_input)
    return did, answer


def test_start_installs_the_service_without_asking(mac):
    did, answer = mac
    answer("n")                                     # nothing is asked, so an answer changes nothing
    service.start([])
    assert did == {"installed": True, "foreground": 0, "asked": 0} and service._saved_choice() is True


def test_no_terminal_still_runs_in_the_background(mac, monkeypatch):
    did, _ = mac
    monkeypatch.setattr(service, "_interactive", lambda: False)
    service.start([])
    assert did == {"installed": True, "foreground": 0, "asked": 0}


def test_background_flag_still_works_for_scripts_that_pass_it(mac):
    did, _ = mac
    service.start(["--background"])
    assert did == {"installed": True, "foreground": 0, "asked": 0}


def test_env_or_flag_keeps_it_in_the_window(mac, monkeypatch):
    did, _ = mac
    monkeypatch.setenv("SQUIDBRAKE_BACKGROUND", "0")
    service.start([])
    monkeypatch.delenv("SQUIDBRAKE_BACKGROUND")
    service.start(["--foreground"])
    assert did == {"installed": False, "foreground": 2, "asked": 0}


def test_an_old_no_or_a_stop_doesnt_keep_it_out(mac, monkeypatch):
    did, _ = mac
    monkeypatch.setattr(service, "_launchd_remove", lambda: True)
    service._save_choice(False)                     # said no to the question older versions asked
    service.start([])
    assert did["installed"] and did["foreground"] == 0
    did["installed"] = False
    service.stop()                                  # stopped by hand: back at the next start
    service.start([])
    assert did["installed"] and did["foreground"] == 0


def test_setup_can_tell_an_older_install_or_version_is_running(mac):
    did, _ = mac
    assert service.stale("launchd", "1.0.0")                        # no service installed: set it up
    did["installed"] = True
    assert service.stale("launchd", "1.0.0")                        # an older gateway doesn't say what it is
    service.record_running("1.0.0")
    assert not service.stale("launchd", "1.0.0")                    # this install, this version
    assert service.stale("launchd", "1.0.1")                        # upgraded in place, old code still running
    r = service._running_path()
    data = json.loads(r.read_text())
    r.write_text(json.dumps({**data, "server": "/elsewhere/server.py"}))
    assert service.stale("launchd", "1.0.0")                        # another install's service


@pytest.fixture
def updatable(tmp_path, monkeypatch):
    """An installer-made install with PyPI, pip and the new version's check all recorded instead of done."""
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    for var in ("SQUIDBRAKE_NO_AUTO_UPDATE", "SQUIDBRAKE_NO_UPDATE_CHECK", "DO_NOT_TRACK", "IN_DOCKER"):
        monkeypatch.delenv(var, raising=False)
    w = {"latest": "2.0.0", "age_h": 48, "pypi": 0, "ran": [], "installed": "1.0.0", "pip_ok": True, "works": True}
    monkeypatch.setattr(service, "install_kind", lambda: "venv")

    def pypi():
        w["pypi"] += 1
        return w["latest"], service.time.time() - w["age_h"] * 3600
    monkeypatch.setattr(service, "_pypi", pypi)

    def run(cmd, **k):
        w["ran"].append(cmd)
        pin = next((a for a in cmd if a.startswith("squidbrake==")), None)
        if pin and (w["pip_ok"] or pin.endswith(w["current"])):
            w["installed"] = pin.split("==")[1]
        return subprocess.CompletedProcess(cmd, 0 if w["pip_ok"] else 1, "", "" if w["pip_ok"] else "no network")
    monkeypatch.setattr(service.subprocess, "run", run)
    monkeypatch.setattr(service, "_installed_version", lambda: w["installed"])
    monkeypatch.setattr(service, "_works", lambda: w["works"])
    w["current"] = "1.0.0"
    return w


def test_a_newer_version_is_installed_and_the_gateway_restarts_on_it(updatable):
    w = updatable
    assert service.self_update("1.0.0") is True
    assert w["ran"][0][-1] == "squidbrake==2.0.0" and w["installed"] == "2.0.0"


def test_nothing_happens_when_up_to_date_or_the_release_is_too_new(updatable):
    w = updatable
    w["latest"] = "1.0.0"
    assert service.self_update("1.0.0") is False and w["ran"] == []
    w["latest"], w["age_h"] = "2.0.0", 2                       # out for 2 hours: wait for a day
    (service.state_dir() / "update-check.json").unlink()
    assert service.self_update("1.0.0") is False and w["ran"] == []
    assert service.self_update("1.0.0") is False and w["pypi"] == 2     # the day's answer is reused, not asked again


def test_a_version_that_doesnt_start_is_put_back_and_not_tried_again_today(updatable):
    w = updatable
    w["works"] = False
    assert service.self_update("1.0.0") is False
    assert w["ran"][-1][-1] == "squidbrake==1.0.0" and w["installed"] == "1.0.0"      # the one that works, back
    w["ran"].clear()
    assert service.self_update("1.0.0") is False and w["ran"] == []


def test_a_failed_download_keeps_this_version(updatable):
    w = updatable
    w["pip_ok"] = False
    assert service.self_update("1.0.0") is False and w["installed"] == "1.0.0"


def test_auto_update_can_be_turned_off_and_skips_installs_it_doesnt_own(updatable, monkeypatch):
    w = updatable
    monkeypatch.setenv("SQUIDBRAKE_NO_AUTO_UPDATE", "1")
    assert service.self_update("1.0.0") is False and w["pypi"] == 0
    monkeypatch.delenv("SQUIDBRAKE_NO_AUTO_UPDATE")
    monkeypatch.setattr(service, "install_kind", lambda: None)          # a system Python, a checkout
    assert service.self_update("1.0.0") is False and w["pypi"] == 0


def test_only_installs_squidbrake_made_are_updated(monkeypatch, tmp_path):
    monkeypatch.setattr(service, "HERE", tmp_path)                       # a checkout: no __init__.py
    assert service.install_kind() is None
    (tmp_path / "__init__.py").write_text("")
    monkeypatch.setattr(service.sys, "prefix", "/usr")
    monkeypatch.setattr(service.sys, "base_prefix", "/usr")
    monkeypatch.setattr(service.sys, "executable", "/usr/bin/python3")
    assert service.install_kind() is None                                 # a system Python: shared, not ours
    monkeypatch.setattr(service.sys, "prefix", str(tmp_path / ".squidbrake/app"))
    assert service.install_kind() == "venv"                               # the installer's own folder


def test_start_scripts_go_through_the_service():
    assert 'service.py start "$@"' in (ROOT / "start.sh").read_text(encoding="utf-8")
    assert "service.py start %*" in (ROOT / "start.bat").read_text(encoding="utf-8")


def test_service_help_is_the_service_help(capsys):
    assert service.main(["--help"]) == 0 and service.main(["-h"]) == 0
    assert "start --foreground" in capsys.readouterr().out
