"""The three-command setup (pip install, connect all, squidbrake) keeps its thread: each step says which step it is,
the keys come after the agents, and the last thing printed is the next command."""
import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connect  # noqa: E402
import flow  # noqa: E402
import service  # noqa: E402

URL = "http://localhost:8080"


@pytest.fixture(autouse=True)
def fresh_process():
    flow._shown.clear()          # the header prints once per process; every test is a new "process"


@pytest.fixture()
def agents(monkeypatch, tmp_path):
    """connect all with the agents recorded instead of written, the gateway down, and the first keys to show."""
    monkeypatch.setenv("SQUIDBRAKE_CLI", "squidbrake")
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail(f"asked: {prompt}"))
    seen = []
    monkeypatch.setattr(connect, "claude_code", lambda a: seen.append("claude-code") or print("claude-code: hook added"))
    monkeypatch.setattr(connect, "agents", lambda a: seen.append("agents") or print("cursor: hook added"))
    monkeypatch.setattr(connect, "guard", lambda a: seen.append("guard"))
    monkeypatch.setattr(connect, "_first_keys", lambda url: {"admin": "gw_admin_once", "agent": "gw_agent_once"})
    monkeypatch.setattr(connect, "gateway_up", lambda url: False)
    import server
    monkeypatch.setattr(server, "print_banner", lambda url, created: print(f"KEYS {created['admin']}"))
    monkeypatch.setattr(connect.shutil, "which", lambda name: "/usr/bin/claude" if name == "claude" else None)
    return seen


def test_connect_all_says_which_step_it_is_and_ends_with_the_next_command(agents, capsys):
    connect.connect_all(Namespace(url=URL, key=None, remove=False, yes=True, only=None))
    out = capsys.readouterr().out
    assert "step 2 of 3: connect your agents" in out and "2 connect (now)" in out and "3 start (next)" in out
    assert agents == ["claude-code", "agents", "guard"]
    # the keys come after the agents' lines, not in the middle of them
    assert out.index("cursor: hook added") < out.index("KEYS gw_admin_once")
    # the gateway isn't running: the last thing said is the command that starts it
    tail = out[out.index("KEYS"):]
    assert "isn't running yet" in tail and "step 3 of 3" in tail and tail.rstrip().endswith(flow.BAR)
    assert "squidbrake" in tail.split("step 3 of 3")[1].splitlines()[0]
    assert "Continue?" not in out                                          # --yes: no question, and no counts question


def test_connect_all_with_the_gateway_already_running_points_at_doctor(agents, monkeypatch, capsys):
    monkeypatch.setattr(connect, "gateway_up", lambda url: True)
    connect.connect_all(Namespace(url=URL, key=None, remove=False, yes=True, only=None))
    out = capsys.readouterr().out
    assert "the gateway is running at " + URL in out and "squidbrake doctor" in out
    assert "step 3 of 3" not in out.split("KEYS")[1]


def test_setup_runs_connect_all_without_the_step_header(agents, capsys):
    connect.connect_all(Namespace(url=URL, key=None, remove=False, yes=True, only=None, steps=False))
    out = capsys.readouterr().out
    assert "step 2 of 3" not in out and "step 3 of 3" not in out and "KEYS gw_admin_once" in out


def test_the_keys_are_shown_even_when_an_agent_stops_it(agents, monkeypatch, capsys):
    monkeypatch.setattr(connect, "agents", lambda a: (_ for _ in ()).throw(SystemExit("cursor's hooks.json is broken")))
    with pytest.raises(SystemExit):
        connect.connect_all(Namespace(url=URL, key=None, remove=False, yes=True, only=None))
    assert "KEYS gw_admin_once" in capsys.readouterr().out


def test_remove_has_no_header_and_no_next_step(agents, capsys):
    connect.connect_all(Namespace(url=URL, key=None, remove=True, yes=True, only=None))
    out = capsys.readouterr().out
    assert "step 2 of 3" not in out and "KEYS" not in out and connect.FOUNDER_CALL not in out


@pytest.fixture
def mac(tmp_path, monkeypatch):
    """A Mac with nothing installed yet; records what start() does instead of doing it (as test_service does)."""
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    monkeypatch.setenv("SQUIDBRAKE_CLI", "squidbrake")
    for var in ("SQUIDBRAKE_BACKGROUND", "SQUIDBRAKE_FOREGROUND", "IN_DOCKER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SQUIDBRAKE_NO_BROWSER", "1")
    did = {"installed": False, "foreground": 0, "init": []}
    monkeypatch.setattr(service, "backend", lambda: "launchd")
    monkeypatch.setattr(service, "_launchd_installed", lambda: did["installed"])
    monkeypatch.setattr(service, "_launchd_install", lambda run_args: did.update(installed=True) or "log")
    monkeypatch.setattr(service, "_foreground", lambda run_args: did.update(foreground=did["foreground"] + 1) or 0)
    monkeypatch.setattr(service, "_answering", lambda port: True)
    monkeypatch.setattr(service.subprocess, "call", lambda cmd, **k: did["init"].append(cmd[-2:]) or 0)
    monkeypatch.setattr(service.time, "sleep", lambda s: None)
    monkeypatch.setattr(service, "_interactive", lambda: True)
    return did


def test_first_start_is_step_3_and_ends_with_setup_complete(mac, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert service.start([]) == 0
    out = capsys.readouterr().out
    assert "step 3 of 3: start the gateway" in out and "1 install (done)" in out and "2 connect (done)" in out
    assert mac["init"] == [["init", "--quiet"]]                                  # no "Already set up" noise
    assert out.index("runs in the background now") < out.index("Setup complete")
    assert "squidbrake doctor" in out.split("Setup complete")[1]

    service.start([])                                                            # every later start: just a start
    assert "step 3 of 3" not in capsys.readouterr().out


def test_first_start_asks_nothing_and_runs_in_the_background(mac, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked"))
    service.start([])
    out = capsys.readouterr().out
    assert mac["installed"] and mac["foreground"] == 0 and "step 3 of 3" in out
    assert "quit and reopen your agents" in out


def test_a_script_sees_no_header(mac, monkeypatch, capsys):
    monkeypatch.setattr(service, "_interactive", lambda: False)
    service.start([])
    assert "step 3 of 3" not in capsys.readouterr().out


def test_the_header_names_the_commands_people_type(monkeypatch):
    import io
    import contextlib
    monkeypatch.setenv("SQUIDBRAKE_CLI", "squidbrake")
    for step in (1, 2, 3):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            flow.header(step)
        assert f"step {step} of 3: {flow.STEPS[step - 1]}" in buf.getvalue()
    assert flow.start_command() == "squidbrake" and flow.doctor_command() == "squidbrake doctor"
