"""The Squidbrake app (desktop.py): sign-in page, what it keeps, the agents it connects, start at login, status."""
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import desktop  # noqa: E402


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path / ".squidbrake"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setattr(desktop, "device_name", lambda: "Test Mac")
    return tmp_path


def _fake_server(monkeypatch, answers):
    """squidbrake.com: each (method, path) gets the next answer in line (a dict, or an ApiError to raise)."""
    calls = []

    def api(method, path, body=None, server=None):
        calls.append((method, path, body))
        key = path.split("/")[3] if path.startswith("/v1/app/") else path
        a = answers[key].pop(0)
        if isinstance(a, Exception):
            raise a
        return a
    monkeypatch.setattr(desktop, "api", api)
    return calls


def _post(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body or {}).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_the_sign_in_page_only_answers_at_its_secret_address_and_never_shows_the_key(home, monkeypatch):
    connected = {"state": "connected", "dashboard": "https://co.app.test", "agent_key": "gw_SECRET_AGENT",
                 "device_token": "tok_" + "x" * 30, "company": "Co"}
    calls = _fake_server(monkeypatch, {"code": [{"ok": True}], "connect": [{"link": "L1", "state": "starting"}],
                                       "link": [{"state": "waiting", "ahead": 2}, connected]})
    wired = []
    monkeypatch.setattr(desktop, "wire_agents", lambda url, key: wired.append((url, key)) or ["Claude Code: connected"])
    done = []
    page = desktop.SignIn(on_done=lambda: done.append(1))
    try:
        base = page.url
        port = base.split(":")[2].split("/")[0]
        with pytest.raises(urllib.error.HTTPError):                         # another page can't find or drive it
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        assert _post(f"http://127.0.0.1:{port}/wrong/code", {"email": "a@b.co"})[0] == 404
        html = urllib.request.urlopen(base, timeout=5).read().decode()
        assert "Connect this computer" in html and '"Test Mac"' in html
        assert _post(base + "code", {"email": "a@b.co"}) == (200, {"ok": True})
        code, s = _post(base + "connect", {"code": "123456"})
        assert code == 200 and s["state"] == "starting" and "link" not in s
        code, s = _post(base + "poll")
        assert s["state"] == "waiting" and "2 ahead" in s["say"]
        code, s = _post(base + "poll")
        assert s == {"state": "done", "dashboard": "https://co.app.test", "agents": ["Claude Code: connected"], "company": "Co"}
        assert "gw_SECRET_AGENT" not in json.dumps(s)                       # the browser never gets the key
        assert _post(base + "poll")[1]["state"] == "done"                   # asked again: still done, no second fetch
    finally:
        page.close()
    assert calls[1] == ("POST", "/v1/app/connect", {"email": "a@b.co", "code": "123456", "device": "Test Mac"})
    assert wired == [("https://co.app.test", "gw_SECRET_AGENT")] and done == [1]
    cfg = desktop.load()
    assert cfg["agent_key"] == "gw_SECRET_AGENT" and cfg["device_token"].startswith("tok_") and cfg["email"] == "a@b.co"
    if os.name != "nt":
        assert stat.S_IMODE(desktop.config_path().stat().st_mode) == 0o600    # only this person can read it


def test_a_key_that_was_ready_at_once_is_used_and_not_asked_for_again(home, monkeypatch):
    connected = {"link": "L2", "state": "connected", "dashboard": "https://co.app.test", "agent_key": "gw_A",
                 "device_token": "t" * 30}
    _fake_server(monkeypatch, {"code": [{"ok": True}], "connect": [connected], "link": []})   # no poll to the server
    monkeypatch.setattr(desktop, "wire_agents", lambda url, key: [])
    page = desktop.SignIn()
    try:
        _post(page.url + "code", {"email": "a@b.co"})
        assert _post(page.url + "connect", {"code": "123456"})[1]["state"] == "connected"
        assert _post(page.url + "poll")[1]["state"] == "done"
    finally:
        page.close()
    assert desktop.load()["agent_key"] == "gw_A"


def test_a_wrong_code_says_so(home, monkeypatch):
    _fake_server(monkeypatch, {"code": [{"ok": True}], "connect": [desktop.ApiError(401, "that code isn't right")]})
    page = desktop.SignIn()
    try:
        _post(page.url + "code", {"email": "a@b.co"})
        assert _post(page.url + "connect", {"code": "000000"}) == (401, {"detail": "that code isn't right"})
    finally:
        page.close()
    assert desktop.load() == {}


def test_it_connects_the_agents_the_way_the_install_command_does(home, monkeypatch):
    ran = []
    monkeypatch.setattr(desktop, "_quiet_run", lambda cmd: ran.append(cmd[2:]) or (True, "  [OK] cursor: connected"))
    monkeypatch.setattr(desktop.shutil, "which", lambda name: "/usr/bin/claude" if name == "claude" else None)
    said = desktop.wire_agents("https://co.app.test", "gw_K")
    common = ["--url", "https://co.app.test", "--key", "gw_K", "--yes"]
    assert ran == [["claude-code", *common, "--hook-only"], ["agents", "--agent", "all", *common],
                   ["guard", "--agent", "all", *common]]
    assert said[0] == "Claude Code: connected" and "[OK] cursor: connected" in said


def test_start_at_login_on_and_off(home, monkeypatch):
    monkeypatch.setattr(desktop.sys, "platform", "linux")
    assert desktop.login_item() is False
    assert desktop.login_item(True) is True
    entry = (home / ".config" / "autostart" / "squidbrake-app.desktop").read_text()
    assert "desktop.py" in entry and "run" in entry
    assert desktop.login_item(False) is False
    monkeypatch.setattr(desktop.sys, "platform", "darwin")
    monkeypatch.setattr(desktop.Path, "home", classmethod(lambda cls: home))
    assert desktop.login_item(True) is True
    import plistlib
    plist = plistlib.loads((home / "Library" / "LaunchAgents" / "com.squidbrake.app.plist").read_bytes())
    assert plist["RunAtLoad"] is True and plist["ProgramArguments"][-1] == "run" and "KeepAlive" not in plist   # Quit stays quit
    assert desktop.login_item(False) is False


def test_status_colours(home, monkeypatch):
    cfg = {"dashboard": "https://co.app.test", "agent_key": "gw_K", "device_token": "t" * 30}
    up = {"v": True}
    monkeypatch.setattr(desktop, "gateway_answers", lambda c: up["v"])
    beats = []
    monkeypatch.setattr(desktop, "heartbeat", lambda c: beats.append(1) or {"state": "sleeping"})
    assert desktop.check(cfg, beat=False) == ("green", "Protecting your agents") and beats == []
    assert desktop.check(cfg, beat=True)[0] == "green" and beats == [1]          # checks in every 10 minutes
    up["v"] = False
    assert desktop.check(cfg, beat=False) == ("amber", "Waking your dashboard…")  # down: asks (and that wakes it)

    def gone(c):
        raise desktop.ApiError(401, "signed out")
    monkeypatch.setattr(desktop, "heartbeat", gone)
    assert desktop.check(cfg, beat=True)[0] == "red"
    monkeypatch.setattr(desktop, "heartbeat", lambda c: (_ for _ in ()).throw(desktop.ApiError(0, "offline")))
    assert desktop.check(cfg, beat=True) == ("grey", "Can't reach your dashboard")


def test_the_cli_runs_it(home, capsys):
    sys.path.insert(0, str(ROOT))
    from squidbrake import cli
    old = sys.argv
    try:
        sys.argv = ["squidbrake", "app", "--status"]
        assert cli.main() == 1
    finally:
        sys.argv = old
    assert "Not signed in" in capsys.readouterr().out


def test_the_page_is_packaged():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"app_signin.html" = "squidbrake/app_signin.html"' in text and '"desktop.py" = "squidbrake/desktop.py"' in text


def test_the_windows_app_connects_agents_with_its_console_twin(tmp_path, monkeypatch):
    # squidbrake-app.exe always runs the app (entry.py adds "app"): connecting agents with it did nothing
    app_exe, cli_exe = tmp_path / "squidbrake-app.exe", tmp_path / "squidbrake.exe"
    app_exe.write_text(""); cli_exe.write_text("")
    monkeypatch.setattr(desktop.sys, "executable", str(app_exe))
    cmd = desktop._script("connect.py", "claude-code")
    assert cmd[0] == str(cli_exe) and cmd[1].endswith("connect.py") and cmd[2] == "claude-code"


def test_green_means_an_agent_really_goes_through_the_dashboard(monkeypatch):
    # the dashboard answering while no agent here has the hook is not "protecting": that hid a Windows app that
    # never connected anything
    monkeypatch.setattr(desktop, "gateway_answers", lambda cfg: True)
    monkeypatch.setattr(desktop, "heartbeat", lambda cfg: {"state": "running"})
    monkeypatch.setattr(desktop, "agents_here", lambda: [])
    assert desktop.check({}, beat=False) == ("amber", "No agent connected: choose Reconnect agents")
    monkeypatch.setattr(desktop, "agents_here", lambda: ["claude-code"])
    assert desktop.check({}, beat=False) == ("green", "Protecting your agents")
