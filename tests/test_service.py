"""`squidbrake` (and start.sh / start.bat) can install a background service that starts at every login,
but only after a yes."""
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
    assert ("launchctl", "bootstrap", "gui/501", str(home / "Library/LaunchAgents/com.squidbrake.gateway.plist")) in calls
    assert service._launchd_remove() and not service._launchd_installed()


def test_systemd_user_unit_restarts_and_starts_at_boot(fake_home):
    home, calls = fake_home
    service._systemd_install([])
    unit = (home / ".config/systemd/user/squidbrake.service").read_text()
    assert "Restart=always" in unit and "WantedBy=default.target" in unit
    assert f'"{service.SERVER}" "run" "--no-browser"' in unit
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


def test_no_terminal_never_installs_or_remembers(mac, monkeypatch):
    did, _ = mac
    monkeypatch.setattr(service, "_interactive", lambda: False)
    service.start([])
    assert did == {"installed": False, "foreground": 1, "asked": 0}
    assert service._saved_choice() is None


def test_enter_means_no_and_is_asked_only_once(mac):
    did, answer = mac
    answer("")
    service.start([])
    service.start([])
    assert did == {"installed": False, "foreground": 2, "asked": 1}
    assert service._saved_choice() is False


def test_yes_installs_the_service(mac):
    did, answer = mac
    answer("y")
    service.start([])
    assert did["installed"] and did["foreground"] == 0 and service._saved_choice() is True


def test_background_flag_installs_without_asking(mac):
    did, answer = mac
    answer("n")
    service.start(["--background"])
    assert did == {"installed": True, "foreground": 0, "asked": 0}


def test_env_answers_for_unattended_installs(mac, monkeypatch):
    did, answer = mac
    answer("y")
    monkeypatch.setenv("SQUIDBRAKE_BACKGROUND", "0")
    service.start([])
    assert did == {"installed": False, "foreground": 1, "asked": 0}


def test_taken_out_by_hand_is_not_put_back(mac):
    did, answer = mac
    service._save_choice(True)
    answer("y")
    service.start([])
    assert did == {"installed": False, "foreground": 1, "asked": 0}


def test_stop_remembers_no(mac, monkeypatch):
    monkeypatch.setattr(service, "_launchd_remove", lambda: True)
    service._save_choice(True)
    service.stop()
    assert service._saved_choice() is False


def test_start_scripts_go_through_the_service():
    assert 'service.py start "$@"' in (ROOT / "start.sh").read_text(encoding="utf-8")
    assert "service.py start %*" in (ROOT / "start.bat").read_text(encoding="utf-8")
