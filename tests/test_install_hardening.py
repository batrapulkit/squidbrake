"""What can go wrong when a pilot founder installs Squidbrake: the pilots server's doors (community code, guessing
codes), the hooks an install writes, the first run, and the installers' text, each checked here so it stays fixed.
(install.sh runs for real in test_install_sh.py.)"""
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_pilot import insights  # noqa: E402,F401  (same throwaway insights database and admin key)

import agent_hook  # noqa: E402
import claude_hook  # noqa: E402
import connect  # noqa: E402
import service  # noqa: E402
import telemetry  # noqa: E402


@pytest.fixture()
def server():
    """Imported when used, not at collection: test_server.py sets up the gateway's settings before it's first imported."""
    import server
    return server

ADMIN = {"X-Admin-Key": "admin-test-key"}


# ---- the pilots server

def test_the_community_code_is_always_there_and_cant_be_deleted(insights):
    import app as insights_app
    code = insights_app.COMMUNITY_CODE
    assert insights.post("/v1/pilot/join", json={"code": code, "install_id": "c" * 32}).status_code == 200
    assert insights.delete(f"/v1/admin/pilots/{code}", headers=ADMIN).status_code == 400
    with insights_app.db() as c:                       # gone from the database anyway (by hand): the next start puts it back
        c.execute("DELETE FROM pilots WHERE code=?", (code,))
    insights_app.seed_community()                      # what every start of the server runs
    with insights_app.db() as c:
        assert c.execute("SELECT 1 FROM pilots WHERE code=?", (code,)).fetchone()


def test_guessing_pilot_codes_is_slowed_down(insights):
    import app as insights_app
    insights_app._misses.clear()
    real = insights.post("/v1/admin/pilots", headers=ADMIN, json={"company": "Guessable Co"}).json()["code"]
    assert len(real.rsplit("-", 1)[1]) == 12                         # 48 random bits after the company's name
    try:
        for i in range(30):
            assert insights.get(f"/start/guessable-co-{i:06x}").status_code == 404
        assert insights.get(f"/start/{real}").status_code == 429         # even the right one, from that address, waits
        assert insights.post(f"/v1/pilot/{real}/keys").status_code == 429
        assert insights.post("/v1/pilot/join", json={"code": real, "install_id": "d" * 32}).status_code == 429
    finally:
        insights_app._misses.clear()
    assert insights.get(f"/start/{real}").status_code == 200


def test_misses_from_many_addresses_dont_grow_without_end():
    import time

    import app as insights_app
    insights_app._misses.clear()
    insights_app._misses.update({f"10.0.{i // 256}.{i % 256}": [time.time() - 3600] for i in range(10_001)})
    insights_app._guessing(None)
    assert len(insights_app._misses) < 10
    insights_app._misses.clear()


# ---- the hooks an install writes into the agents, and how they reach the gateway

def test_hook_command_is_one_word_per_path_in_every_shell(monkeypatch, tmp_path):
    """Cursor runs hooks through PowerShell on Windows (bash from Git Bash): a quoted first word or backslashes
    there and every action in Cursor is blocked. A profile like C:/Users/Rahul Kumar is common."""
    home = tmp_path / "Rahul Kumar"
    (home / ".cursor").mkdir(parents=True)
    monkeypatch.setattr(connect.Path, "home", classmethod(lambda cls: home))
    py = home / ".squidbrake" / "app" / "Scripts" / "python.exe"
    py.parent.mkdir(parents=True)
    py.write_text("")
    monkeypatch.setattr(connect, "PYTHON", str(py))
    connect.agents(SimpleNamespace(agent="cursor", remove=False, key="gw_test", url="http://localhost:8080"))
    cmd = json.loads((home / ".cursor" / "hooks.json").read_text())["hooks"]["beforeShellExecution"][0]["command"]
    if os.name == "nt":
        words = cmd.split(" ")
        assert '"' not in cmd and "\\" not in cmd, cmd
        assert words[0].endswith("python.exe") and words[1].endswith("agent_hook.py") and words[2] == "cursor", cmd
    else:
        assert cmd.startswith('"')                                      # sh / bash: a quoted path is fine


@pytest.mark.skipif(os.name != "nt", reason="Windows shells")
def test_the_hook_runs_the_same_in_cmd_powershell_and_bash(tmp_path):
    folder = tmp_path / "Rahul Kumar"
    folder.mkdir()
    script = folder / "hook.py"
    script.write_text('import sys, json; sys.stdin.read(); print(json.dumps({"permission": "allow"}))')
    cmd = f"{connect._word(sys.executable)} {connect._word(str(script))}"
    shells = [["cmd", "/c", cmd], ["powershell", "-NoProfile", "-Command", cmd]]
    if (bash := shutil.which("bash")) and "Git" in bash:
        shells.append([bash, "-c", cmd])
    for sh in shells:
        p = subprocess.run(sh, input="{}", capture_output=True, text=True, timeout=60)
        assert '"allow"' in p.stdout, (sh[0], p.stdout, p.stderr)


@pytest.mark.parametrize("hook", [claude_hook, agent_hook])
def test_the_local_gateway_is_reached_directly(hook, monkeypatch):
    """127.0.0.1, not localhost (Windows waits ~2 s on IPv6 first), and never through the system's proxy."""
    monkeypatch.setenv("HTTP_PROXY", "http://corp-proxy.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://corp-proxy.example:3128")
    with hook.gateway_client("http://localhost:8080", "k", 5) as c:
        assert c.base_url.host == "127.0.0.1" and c.trust_env is False
    with hook.gateway_client("https://acme.app.squidbrake.com", "k", 5) as c:     # a hosted one: the proxy may be needed
        assert c.trust_env is True


def _html_200(request):
    return httpx.Response(200, text="<html>Sign in to the company proxy</html>")


def test_a_page_that_isnt_the_gateway_blocks_the_claude_code_call(monkeypatch, capsys):
    monkeypatch.setattr(claude_hook, "FAIL_OPEN", False)
    http = httpx.Client(base_url="http://127.0.0.1:8080", transport=httpx.MockTransport(_html_200))
    with pytest.raises(SystemExit):
        claude_hook.pre({"tool_name": "Bash", "tool_input": {"command": "ls"}, "hook_event_name": "PreToolUse"}, http)
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "not like Squidbrake" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_a_page_that_isnt_the_gateway_blocks_the_cursor_call(monkeypatch, capsys):
    monkeypatch.setattr(agent_hook, "FAIL_OPEN", False)
    monkeypatch.setattr(agent_hook, "gateway_client", lambda url, key, t: httpx.Client(
        base_url="http://127.0.0.1:8080", transport=httpx.MockTransport(_html_200)))
    with pytest.raises(SystemExit):
        agent_hook.check("cursor", "Bash", {"command": "ls"}, None)
    out = json.loads(capsys.readouterr().out)
    assert out["permission"] == "deny" and "not like Squidbrake" in out["user_message"]


# ---- the first run

def test_a_taken_port_is_said_before_any_key_is_printed_or_browser_opened(server, monkeypatch, capsys):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    made, opened = [], []
    monkeypatch.setattr(server.keystore, "ensure_initialized", lambda: made.append(1))
    monkeypatch.setattr(server.webbrowser, "open", lambda *a: opened.append(a))
    try:
        assert server.port_in_use("127.0.0.1", port)
        code = server._cli_run(SimpleNamespace(host="127.0.0.1", port=port, workers=1, no_browser=False))
    finally:
        s.close()
    err = capsys.readouterr().err
    assert code == 1 and f"Port {port} is already in use" in err and f"--port {port + 10}" in err
    assert not made and not opened
    assert server.port_in_use("127.0.0.1", port) is None                 # free again


def test_no_browser_over_ssh_or_on_a_linux_box_without_a_desktop(server, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 51000")
    assert not server.can_open_browser()
    monkeypatch.delenv("SSH_CONNECTION")
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert not server.can_open_browser()
    monkeypatch.setenv("DISPLAY", ":0")
    assert server.can_open_browser()


def test_a_gateway_that_cant_start_isnt_restarted_every_two_seconds_forever():
    assert service.restart_delay(0) == 2 and service.restart_delay(1) == 2
    assert service.restart_delay(4) == 16 and service.restart_delay(50) == 300


@pytest.mark.skipif(os.name != "nt", reason="Windows processes")
def test_stopping_the_service_only_kills_a_python():
    assert service._is_python(os.getpid())
    p = subprocess.Popen(["cmd", "/c", "ping -n 5 127.0.0.1 >nul"])
    try:
        assert not service._is_python(p.pid)                           # a saved pid now used by something else
    finally:
        p.kill()
    assert not service._is_python(4_000_000)


def test_saying_no_to_the_background_says_the_agents_wait_for_it(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert service._ask("windows") is False
    assert "your agents' actions are blocked" in capsys.readouterr().out


def test_pilot_join_never_asks_the_usage_question(monkeypatch, tmp_path):
    """Enter on both (that one says Yes, the pilot's says No) used to put a founder in the community pilot."""
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    monkeypatch.delenv("SQUIDBRAKE_TELEMETRY", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(telemetry, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("asked during pilot join"))
    telemetry.maybe(["pilot", "join", "acme-abc", "--server", "https://p.example"], "1.0")
    assert "enabled" not in telemetry.load()


def test_names_the_console_cant_show_dont_stop_the_command():
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    env["PYTHONUTF8"] = "0"
    code = ("import io, sys; sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='cp1252'); "
            "from squidbrake import cli; cli._safe_output(); print('C:/Users/\\u0930\\u093e\\u0939\\u0941\\u0932'); "
            "sys.stdout.flush(); sys.__stdout__.write(sys.stdout.buffer.getvalue().decode('cp1252'))")
    p = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert "\\u0930" in p.stdout


# ---- what gets installed, and the installers' text

def test_windows_on_arm_doesnt_need_a_package_without_a_wheel():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "uvicorn[standard]>=0.29; platform_machine != 'ARM64'" in text
    assert "uvicorn>=0.29; platform_machine == 'ARM64'" in text


PS1 = (ROOT / "insights" / "install.ps1").read_text(encoding="utf-8")


def test_install_ps1_upgrades_in_place_and_keeps_a_working_install():
    assert "venv --clear" not in PS1                                    # it used to wipe the hooks' Python first
    assert PS1.index("service stop") < PS1.index("-m venv") and "start --background" in PS1
    assert "you still have" in PS1 and "Upgrading Squidbrake in" in PS1


def test_rerunning_the_installer_right_after_a_release_gets_it():
    """pip and uv keep PyPI's list of versions for minutes: "the fix is out, run it again" got the old version."""
    sh = (ROOT / "insights" / "install.sh").read_text(encoding="utf-8")
    for text in (PS1, sh):
        assert "--no-cache-dir" in text and "--refresh-package squidbrake" in text
        assert "https://pypi.org/pypi/squidbrake/json" in text and "squidbrake==" in text   # the newest, by name


def test_install_ps1_sets_everything_up_after_installing():
    assert '& $sb setup' in PS1 and '$env:SQUIDBRAKE_SETUP -ne "0"' in PS1
    assert PS1.index("pilot join") < PS1.index("& $sb setup")              # the pilot first, so its counts start with it
    page = (ROOT / "insights" / "start.html").read_text(encoding="utf-8")
    assert "That one line does it all" in page and "squidbrake connect claude-code</div>" not in page


def test_install_ps1_path_survives_no_user_path_and_keeps_variables():
    assert "DoNotExpandEnvironmentNames" in PS1 and "ExpandString" in PS1
    assert "[string]$envKey.GetValue" in PS1
    assert '$env:Path = "$env:Path;$bin"' in PS1                         # this window finds it too


def test_install_ps1_says_why_things_failed():
    assert PS1.count("ShowLog $log") >= 4 and "UV_NATIVE_TLS" in PS1 and "truststore" in PS1
    assert "LanguageMode" in PS1                                        # AppLocker / constrained language: say so
    assert '"3.14"' in PS1
    assert 'irm https://astral.sh/uv/install.ps1 | iex" *> $log' in PS1  # uv's own window, its output kept
    assert not any(ord(ch) > 127 for ch in PS1)                         # PowerShell 5.1 reads it in the ANSI code page


def test_start_page_says_powershell_and_the_real_way_to_undo():
    page = (ROOT / "insights" / "start.html").read_text(encoding="utf-8")
    assert "pipx uninstall" not in page and "not Command Prompt" in page and "connect all --remove" in page
    assert "Keep this window open while you work" not in page


# ---- installs that failed: sent only after a yes, with nothing private in them

def test_a_failed_install_report_is_kept_without_keys_names_or_emails(insights):
    import app as insights_app
    insights_app._reports.clear()
    code = insights.post("/v1/admin/pilots", headers=ADMIN, json={"company": "Broke Install Co"}).json()["code"]
    log = ("Collecting squidbrake\nERROR: certificate verify failed for C:\\Users\\Rahul Kumar\\AppData\\x\n"
           "token=abc123 key gw_agent_secret_1234 me@acme.com /home/rahul/.cache\n")
    r = insights.post(f"/v1/install-report?installer=ps1&code={code}&os=Windows+10&step=Installing+with+uv+failed",
                      content=log.encode(), headers={"Content-Type": "text/plain"})
    assert r.status_code == 200
    assert insights.get("/v1/admin/install-reports").status_code == 401
    got = next(x for x in insights.get("/v1/admin/install-reports", headers=ADMIN).json() if x["code"] == code)
    assert got["company"] == "Broke Install Co" and got["installer"] == "ps1" and "certificate verify failed" in got["log"]
    for private in ("Rahul", "rahul", "abc123", "gw_agent_secret_1234", "me@acme.com"):
        assert private not in got["log"], private
    stranger = insights.post("/v1/install-report?code=made-up-code", content=b"boom").json()
    assert stranger == {"ok": True}                                    # kept, but not tied to a pilot
    assert insights.post("/v1/install-report", content=b"   ").status_code == 422
    assert insights.post(f"/v1/admin/install-reports/{got['id']}", headers=ADMIN, json={"done": True}).json()["ok"]


def test_failed_install_reports_are_limited_per_address(insights):
    import app as insights_app
    insights_app._reports.clear()
    try:
        for _ in range(5):
            assert insights.post("/v1/install-report", content=b"x" * 50_000).status_code == 200   # capped, not refused
        assert insights.post("/v1/install-report", content=b"again").status_code == 429
    finally:
        insights_app._reports.clear()
    import app
    with app.db() as c:
        assert max(len(r[0]) for r in c.execute("SELECT log FROM install_reports")) <= 6000


def test_install_ps1_asks_before_sending_a_failed_install():
    assert "OfferReport $msg" in PS1 and "[y/N]" in PS1 and "IsInputRedirected" in PS1
    assert "[regex]::Escape($env:USERPROFILE)" in PS1 and "-Tail 15" in PS1
    assert PS1.index("function OfferReport") < PS1.index("try {")
