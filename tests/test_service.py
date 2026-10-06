"""`squidbrake` (and start.sh / start.bat) installs a background service that starts at every login."""
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


def test_bare_squidbrake_command_starts_the_service(monkeypatch):
    seen = []
    monkeypatch.setattr(service, "main", lambda argv: seen.append(argv) or 0)
    from squidbrake import cli
    monkeypatch.setattr(sys, "argv", ["squidbrake"])
    assert cli.main() == 0
    monkeypatch.setattr(sys, "argv", ["squidbrake", "--port", "9000"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["squidbrake", "service", "status"])
    cli.main()
    assert seen == [["start"], ["start", "--port", "9000"], ["status"]]


def test_start_scripts_go_through_the_service():
    assert 'service.py start "$@"' in (ROOT / "start.sh").read_text(encoding="utf-8")
    assert "service.py start %*" in (ROOT / "start.bat").read_text(encoding="utf-8")
