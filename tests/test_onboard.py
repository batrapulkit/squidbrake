"""squidbrake setup: one command that leaves this computer working (background, every agent, checked, dashboard)."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import onboard  # noqa: E402
import service  # noqa: E402

KEYS = {"admin": "gw_admin_secret", "agent": "gw_agent_secret"}


@pytest.fixture()
def world(monkeypatch):
    """The gateway, the service manager, the agents and the browser, all recorded instead of done."""
    import connect
    import server
    w = {"up": False, "started": [], "connected": [], "checked": 0, "opened": [], "keys": dict(KEYS)}
    monkeypatch.setattr(service, "_answering", lambda port: w["up"])
    monkeypatch.setattr(service, "backend", lambda: "windows")
    monkeypatch.setattr(service, "_save_choice", lambda yes: w.setdefault("choice", yes))
    monkeypatch.setattr(service, "stale", lambda kind, version: w.get("stale", False))

    def start(args):
        w["started"].append(args)
        w["up"] = True
        return 0
    monkeypatch.setattr(service, "start", start)
    monkeypatch.setattr(server, "port_in_use", lambda host, port: None)
    monkeypatch.setattr(server.keystore, "ensure_initialized", lambda: w["keys"])
    monkeypatch.setattr(server, "can_open_browser", lambda: True)
    monkeypatch.setattr(server, "print_banner", lambda url, created: print("KEYS:", created))
    monkeypatch.setattr(connect, "connect_all", lambda a: w["connected"].append((a.url, a.yes)))
    monkeypatch.setattr(connect, "doctor", lambda a: w.__setitem__("checked", w["checked"] + 1) or 0)
    monkeypatch.setattr(connect, "connected_agents", lambda: w.get("agents_here", ["cursor"]))
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda url: w["opened"].append(url))
    return w


def test_first_setup_does_everything_and_opens_the_dashboard_signed_in(world, capsys):
    assert onboard.main([]) == 0
    assert world["started"] == [["--background", "--port", "8080"]] and world["choice"] is True
    assert world["connected"] == [("http://localhost:8080", True)] and world["checked"] == 1
    assert world["opened"] == ["http://localhost:8080/dashboard#key=gw_admin_secret"]
    out = capsys.readouterr().out
    assert "gw_admin_secret" in out and "runs in the background" in out


def test_setup_again_doesnt_restart_it_or_show_keys(world, capsys):
    world["up"], world["keys"] = True, None
    assert onboard.main([]) == 0
    assert world["started"] == [] and world["connected"] and world["opened"] == ["http://localhost:8080/dashboard"]
    assert "already running" in capsys.readouterr().out


def test_setup_over_an_older_install_switches_the_service_to_this_one(world, capsys):
    world["up"], world["keys"], world["stale"] = True, None, True
    assert onboard.main([]) == 0
    assert world["started"] == [["--background", "--port", "8080"]]
    assert "switching to this one" in capsys.readouterr().out


def test_a_taken_port_stops_before_any_key_is_made(world, monkeypatch, capsys):
    import server
    monkeypatch.setattr(server, "port_in_use", lambda host, port: "another program is using it")
    made = []
    monkeypatch.setattr(server.keystore, "ensure_initialized", lambda: made.append(1))
    assert onboard.main(["--port", "9000"]) == 1
    assert not made and not world["connected"] and "setup --port 9010" in capsys.readouterr().out


def test_no_background_service_here_says_so_and_still_connects(world, monkeypatch, capsys):
    monkeypatch.setattr(service, "backend", lambda: None)
    assert onboard.main(["--no-browser"]) == 0
    assert not world["started"] and world["connected"] and not world["opened"]
    assert "can't run it in the background" in capsys.readouterr().out


def test_a_service_that_wont_start_is_said(world, monkeypatch, capsys):
    monkeypatch.setattr(service, "start", lambda args: 0)            # installed, but never answers
    monkeypatch.setattr(onboard.time, "sleep", lambda s: None)
    assert onboard.main([]) == 1
    assert not world["connected"] and "didn't start" in capsys.readouterr().out


def test_no_agent_on_this_computer_is_said(world, capsys):
    world["agents_here"] = []
    assert onboard.main(["--no-browser"]) == 0
    assert "Installed, but no agent connected yet" in capsys.readouterr().out


def test_setup_adds_the_rule_packs_asked_for(world, monkeypatch, tmp_path, capsys):
    import server
    added = []
    monkeypatch.setattr(server, "_rule_ids", lambda path: ["allow-reads"])
    monkeypatch.setattr(server, "_add_rules", lambda block, before, who, what: added.append((what, before, who)))
    assert onboard.main(["--packs", "finance,crypto,nope"]) == 0
    assert added == [("pack:finance", None, "setup"), ("pack:crypto", "allow-reads", "setup")]
    assert "Added the Finance agent rules" in capsys.readouterr().out


def test_setup_asks_which_packs_in_a_terminal(world, monkeypatch, capsys):
    import policy_edit
    import server
    added = []
    have = list(policy_edit._ids(policy_edit.PACKS["support"]["yaml"]))     # already added: not offered again
    monkeypatch.setattr(server, "_rule_ids", lambda path: have)
    monkeypatch.setattr(server, "_add_rules", lambda block, before, who, what: added.append(what))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    answers = iter(["n", "1, 9"])          # the terminal guard: no; then pack 1 (finance, since support is there)
    monkeypatch.setattr("builtins.input", lambda q="": next(answers))
    onboard.offer_terminal_guard(False)
    onboard.offer_packs(None)
    assert added == ["pack:finance"] and "Support agent" not in capsys.readouterr().out
