"""Install once, covered everywhere: an agent installed after setup gets the hook from the gateway on its own, an agent a
person took out stays out, and the first `squidbrake` after pip install does the whole setup."""
import sys
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connect  # noqa: E402


@pytest.fixture()
def machine(monkeypatch, tmp_path):
    """Claude Code connected to the gateway; Cursor installed later; Codex installed and taken out by hand."""
    monkeypatch.setenv("SQUIDBRAKE_AGENTS_OFF", str(tmp_path / "agents-off.json"))
    connected = {"claude-code"}
    monkeypatch.setattr(connect, "_hooked_gateway", lambda: ("http://localhost:8080", "gw_agents"))
    monkeypatch.setattr(connect, "local_agents", lambda: [
        {"name": n, "present": True, "connected": n in connected} for n in ("claude-code", "cursor", "codex")])
    done = []
    hook = lambda name, a: done.append((name, a.remove)) or (connected.discard if a.remove else connected.add)(name)
    monkeypatch.setattr(connect, "claude_code", lambda a: hook("claude-code", a))
    monkeypatch.setattr(connect, "agents", lambda a: hook(a.agent, a))
    monkeypatch.setattr(connect, "guard", lambda a: None)
    return done


def test_an_agent_installed_later_is_connected_one_taken_out_stays_out(machine):
    connect.set_agent("codex", False, "http://localhost:8080")          # a person took Codex out (dashboard toggle)
    machine.clear()
    assert connect.auto_connect() == ["cursor"]
    assert machine == [("cursor", False)]
    connect.set_agent("codex", True, "http://localhost:8080")           # and put it back: auto-connect may again
    assert "codex" not in connect.agents_off()


def test_connect_all_remove_keeps_every_agent_out(machine, monkeypatch):
    monkeypatch.setattr(connect, "connected_agents", lambda: [])
    connect.connect_all(Namespace(url="http://localhost:8080", key=None, remove=True, yes=True, only=None))
    assert {"claude-code", "cursor", "codex"} <= connect.agents_off()
    machine.clear()
    assert connect.auto_connect() == []


def test_nothing_happens_where_squidbrake_was_never_set_up(machine, monkeypatch):
    monkeypatch.setattr(connect, "_hooked_gateway", lambda: None)
    assert connect.auto_connect() == [] and machine == []


def test_the_first_squidbrake_after_pip_install_is_the_whole_setup(monkeypatch):
    import onboard
    import service
    from squidbrake import cli
    ran = []
    monkeypatch.setattr(onboard, "main", lambda argv: ran.append(("setup", argv)) or 0)
    monkeypatch.setattr(service, "main", lambda argv: ran.append(("start", argv)) or 0)
    monkeypatch.setattr(sys, "argv", ["squidbrake"])
    monkeypatch.setattr(service, "is_first_start", lambda argv: True)
    assert cli.main() == 0 and ran[-1] == ("setup", [])
    monkeypatch.setattr(service, "is_first_start", lambda argv: False)   # every later `squidbrake`: just a start
    cli.main()
    assert ran[-1] == ("start", ["start"])


# ---- the dashboard: one command and one icon, local or hosted; it opens after auto-connect saying who joined

def test_the_dashboard_link_follows_the_hooks(monkeypatch):
    import onboard
    monkeypatch.setattr(connect, "_hooked_gateway", lambda: ("https://acme.app.squidbrake.com", "gw_x"))
    assert onboard.dashboard_url() == "https://acme.app.squidbrake.com/dashboard"     # a pilot: the hosted one
    monkeypatch.setattr(connect, "_hooked_gateway", lambda: ("http://127.0.0.1:9000", "gw_x"))
    assert onboard.dashboard_url() == "http://localhost:9000/dashboard"
    monkeypatch.setattr(connect, "_hooked_gateway", lambda: None)
    assert onboard.dashboard_url() == "http://localhost:8080/dashboard"


def test_the_icon_is_a_plain_link_and_only_where_a_desktop_is(monkeypatch, tmp_path):
    import onboard
    monkeypatch.delenv("SQUIDBRAKE_NO_SHORTCUT")
    monkeypatch.setattr(onboard, "_desktop", lambda: tmp_path / "Desktop")
    monkeypatch.setenv("APPDATA", str(tmp_path / "nope"))
    monkeypatch.setattr(onboard.Path, "home", lambda: tmp_path)
    assert onboard.make_shortcuts("https://acme.app.squidbrake.com/dashboard") == [] or sys.platform.startswith("linux")
    (tmp_path / "Desktop").mkdir()
    (tmp_path / ".local" / "share" / "applications").mkdir(parents=True)
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path / "sb"))
    made = onboard.make_shortcuts("https://acme.app.squidbrake.com/dashboard")
    assert made and all("https://acme.app.squidbrake.com/dashboard" in p.read_text(encoding="utf-8") for p in made)
    assert not (tmp_path / "nope").exists()                              # never makes a folder that isn't there
    if sys.platform != "darwin":                                         # the logo, kept with Squidbrake's own files
        logo = next((tmp_path / "sb").glob("squidbrake.*"))
        assert str(logo) in made[0].read_text(encoding="utf-8") and logo.stat().st_size > 1000


def test_auto_opens_the_dashboard_saying_who_joined(machine, monkeypatch):
    import onboard
    opened = []
    monkeypatch.setattr(onboard, "open_dashboard", lambda url=None: opened.append(url))
    monkeypatch.setattr(onboard, "dashboard_url", lambda: "https://acme.app.squidbrake.com/dashboard")
    connect.auto()
    assert opened == ["https://acme.app.squidbrake.com/dashboard#connected=cursor,codex"]
    opened.clear()
    connect.auto()                                       # nothing new: nothing pops up
    assert opened == []


def test_a_hosted_hook_starts_the_check_once_a_day_never_a_local_one(monkeypatch, tmp_path):
    import hooklog
    started = []
    monkeypatch.setattr("subprocess.Popen", lambda cmd, **k: started.append(cmd))
    monkeypatch.delenv("SQUIDBRAKE_HOOKLOG")
    monkeypatch.delenv("SQUIDBRAKE_DOCTOR", raising=False)
    monkeypatch.setattr(hooklog, "path", lambda: tmp_path / "hooks.log")
    hooklog.daily("http://localhost:8080")                # a gateway here does it itself
    assert started == []
    hooklog.daily("https://acme.app.squidbrake.com")
    hooklog.daily("https://acme.app.squidbrake.com")      # the same day: once
    assert len(started) == 1 and started[0][-2:] == [str(Path(hooklog.__file__).resolve().parent / "connect.py"), "auto"]
