"""Usage stats: always on, said once in a terminal, never from the hooks or scripts, never more than the command name.
Registration: a pip install gives its name and work email once before it runs."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pilot  # noqa: E402
import telemetry  # noqa: E402


@pytest.fixture()
def sent(tmp_path, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    monkeypatch.delenv("KEYS_PATH", raising=False)
    monkeypatch.delenv("SQUIDBRAKE_REF", raising=False)
    for var in ("SQUIDBRAKE_TELEMETRY", "DO_NOT_TRACK", "CI"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(telemetry, "POSTHOG_KEY", "phc_test")
    bodies = []
    monkeypatch.setattr(telemetry, "_post", bodies.append)
    monkeypatch.setattr(telemetry, "_interactive", lambda: True)
    monkeypatch.setattr(telemetry.threading, "Thread", RunNow)
    monkeypatch.setattr(pilot, "_post", lambda server, path, body: joins.append((path, body["code"])) or {})
    monkeypatch.setattr(telemetry, "_send_registration", lambda cfg, version, company=None: registered.append(
        {**cfg, "company": company}) or online[0])
    for var in ("SQUIDBRAKE_EMAIL", "SQUIDBRAKE_NAME"):
        monkeypatch.delenv(var, raising=False)
    joins.clear(); registered.clear(); online[0] = True
    return bodies


registered = []   # what /v1/register was sent
online = [True]
joins = []   # what the community pilot was told: ("/v1/pilot/join" or "/v1/pilot/leave", code)


class RunNow:   # sends straight away, so a test can look at what went out
    def __init__(self, target, args, daemon):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)

    def join(self, _timeout=None):
        pass


def answers(monkeypatch, *replies):
    it = iter(replies)
    monkeypatch.setattr("builtins.input", lambda _q: next(it, ""))   # past the replies: Enter


def test_first_run_says_what_is_sent_once_and_only_the_command_name_goes(sent, monkeypatch, capsys):
    answers(monkeypatch, "")   # the one optional question (where from): skipped
    telemetry.maybe(["undo", "SECRET-FILE-ID", "--path", "/home/me/secret.txt"], "9.9.9")
    out = capsys.readouterr().out
    assert "Never your commands, files, prompts, rules or keys" in out and "?" not in out.split("where did you hear")[0]
    assert len(sent) == 1
    body = json.dumps(sent[0])
    assert sent[0]["event"] == "cli_command" and sent[0]["properties"]["command"] == "undo"
    assert "SECRET" not in body and "secret.txt" not in body
    assert telemetry.load()["enabled"] is True
    assert joins == [("/v1/pilot/join", telemetry.COMMUNITY_CODE)]        # the gateway's counts too

    answers(monkeypatch)                                                  # a second question would raise
    telemetry.maybe(["doctor"], "1")
    assert "Never your commands" not in capsys.readouterr().out            # said once
    assert len(sent) == 2


def test_there_is_no_yes_no_question_and_no_off_switch(sent, monkeypatch, capsys):
    answers(monkeypatch, "n")                                             # "n" to the where-from question: skipped
    telemetry.maybe(["doctor"], "1")
    assert telemetry.load()["enabled"] is True and len(sent) == 1
    assert telemetry.main(["off"], "1") == 2 and telemetry.load()["enabled"] is True
    assert "usage: squidbrake telemetry status" in capsys.readouterr().out
    assert telemetry.main(["status"], "1") == 0
    assert "Anonymous usage stats: on" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["hook"], ["agent-hook", "cursor"], ["shell-guard", "check", "rm -rf /"], ["proxy"]])
def test_hooks_never_say_or_send(sent, monkeypatch, argv):
    answers(monkeypatch)
    telemetry.maybe(argv, "1")
    assert sent == [] and telemetry.load() == {}


def test_scripts_ci_and_do_not_track_never_say_or_send(sent, monkeypatch):
    answers(monkeypatch)
    monkeypatch.setattr(telemetry, "_interactive", lambda: False)
    telemetry.maybe(["doctor"], "1")
    monkeypatch.setattr(telemetry, "_interactive", lambda: True)
    telemetry.maybe(["connect", "all", "--yes"], "1")
    for var, val in (("CI", "true"), ("DO_NOT_TRACK", "1"), ("SQUIDBRAKE_TELEMETRY", "0")):
        monkeypatch.setenv(var, val)
        telemetry.maybe(["doctor"], "1")
        monkeypatch.delenv(var)
    assert sent == [] and telemetry.load() == {}


def test_without_a_posthog_key_only_counts_are_shared(sent, monkeypatch):
    monkeypatch.setattr(telemetry, "POSTHOG_KEY", "")
    answers(monkeypatch, "")
    telemetry.maybe(["doctor"], "1")
    assert sent == []
    assert joins == [("/v1/pilot/join", telemetry.COMMUNITY_CODE)]
    assert (telemetry._pilot_dir() / "community-asked").exists()          # connect all has nothing left to ask


def test_a_real_pilot_is_never_moved_to_the_community_code(sent, monkeypatch, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "pilot.json").write_text(json.dumps({"code": "acme-123abc", "server": "https://x",
                                                              "install_id": "a" * 32}), encoding="utf-8")
    answers(monkeypatch, "")
    telemetry.maybe(["doctor"], "1")
    assert joins == [] and pilot.load(tmp_path / "data")["code"] == "acme-123abc"


def test_register_asks_first_and_sends_the_email(sent, monkeypatch):
    answers(monkeypatch, "n")
    telemetry.register(["me@acme.com", "--name", "Asha"], "1")
    assert sent == [] and registered == []
    assert telemetry.register(["me@acme.com"], "1") == 2                  # a name is needed too
    answers(monkeypatch, "")
    telemetry.register(["me@acme.com", "--company", "Acme", "--name", "Asha"], "1")
    assert registered[0]["email"] == "me@acme.com" and registered[0]["company"] == "Acme"
    assert sent[0]["event"] == "$identify"
    assert sent[0]["properties"]["$set"]["email"] == "me@acme.com"
    assert sent[0]["properties"]["$set"]["company"] == "Acme"
    assert isinstance(sent[0]["properties"]["$set"]["agents"], list)
    answers(monkeypatch, "")
    telemetry.register(["me@acme.com", "--name", "Asha"], "1")
    assert sent[1]["properties"]["$set"]["name"] == "Asha"


def test_where_they_heard_about_it_is_one_word_from_a_list(sent, monkeypatch):
    joined = []
    monkeypatch.setattr(pilot, "_post", lambda server, path, body: joined.append(body) or {})
    answers(monkeypatch, "1")                                             # LinkedIn
    telemetry.maybe(["doctor"], "1")
    assert telemetry.load()["ref"] == "linkedin"
    assert sent[-1]["properties"]["ref"] == "linkedin" and sent[-1]["properties"]["$set_once"] == {"ref": "linkedin"}
    assert joined[0]["ref"] == "linkedin"                                # the counts carry it too


def test_a_named_link_answers_it_and_free_text_is_never_kept(sent, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_REF", "whatsapp")
    answers(monkeypatch)                                                  # no where-from question at all
    telemetry.maybe(["setup"], "1")
    assert telemetry.load()["ref"] == "whatsapp"
    assert telemetry.ref_from_env() == "whatsapp"
    monkeypatch.setenv("SQUIDBRAKE_REF", "My Name; rm -rf ~/")
    assert telemetry.ref_from_env() is None                             # only a short lowercase word
    answers(monkeypatch, "maybe 3")
    assert telemetry._ask_source() is None                               # not a number from the list: nothing


def test_a_pip_install_gives_name_and_email_before_it_runs(sent, monkeypatch, capsys):
    monkeypatch.setattr(telemetry, "installed_agents", lambda: ["claude-code", "cursor"])
    answers(monkeypatch, "Asha", "me@acme.com", "")                     # name, email, then where-from: skipped
    assert telemetry.require_registration(["doctor"], "1") is None        # given: the command runs
    assert "Before Squidbrake runs" in capsys.readouterr().out
    assert registered[0]["email"] == "me@acme.com" and registered[0]["name"] == "Asha"
    ident = next(b for b in sent if b["event"] == "$identify")
    assert ident["properties"]["$set"] == {"email": "me@acme.com", "name": "Asha",
                                           "agents": ["claude-code", "cursor"], "version": "1"}
    telemetry.maybe(["doctor"], "1")                                      # the first-run notice: no second ask
    assert telemetry.load()["email"] == "me@acme.com" and telemetry.load()["enabled"] is True
    answers(monkeypatch)                                                  # registered: never asked again
    assert telemetry.require_registration(["connect", "all"], "1") is None and len(registered) == 1


def test_a_blank_name_or_a_bad_email_is_asked_again(sent, monkeypatch):
    answers(monkeypatch, "", "  ", "Asha", "not an email", "", "me@acme.com")
    assert telemetry.require_registration(["doctor"], "1") is None
    assert telemetry.load()["name"] == "Asha" and telemetry.load()["email"] == "me@acme.com"


def test_no_answer_means_the_command_does_not_run(sent, monkeypatch, capsys):
    def ctrl_d(_q):
        raise EOFError
    monkeypatch.setattr("builtins.input", ctrl_d)
    assert telemetry.require_registration(["doctor"], "1") == 1
    assert "needs your name and work email" in capsys.readouterr().out
    assert registered == [] and "email" not in telemetry.load()


@pytest.mark.parametrize("argv", [["hook"], ["agent-hook", "cursor"], ["shell-guard", "check", "ls"], ["proxy"],
                                  ["pilot", "join", "acme-1"], ["telemetry"], ["register"], ["doctor", "--help"]])
def test_hooks_pilot_join_and_help_are_never_stopped(sent, monkeypatch, argv):
    answers(monkeypatch)                                                  # a question would raise
    assert telemetry.require_registration(argv, "1") is None and registered == []


def test_ci_and_a_named_pilot_are_never_asked(sent, monkeypatch, tmp_path):
    answers(monkeypatch)
    monkeypatch.setenv("CI", "true")
    assert telemetry.require_registration(["doctor"], "1") is None
    monkeypatch.delenv("CI")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "pilot.json").write_text(json.dumps({"code": "acme-123abc", "server": "https://x",
                                                              "install_id": "a" * 32}), encoding="utf-8")
    assert telemetry.require_registration(["doctor"], "1") is None and registered == []


def test_the_community_counts_alone_do_not_count_as_a_named_pilot(sent, monkeypatch):
    telemetry.gateway_start("1", lambda s: None)                          # joined the community code, no email
    answers(monkeypatch, "Ana", "ana@acme.dev")
    assert telemetry.require_registration(["doctor"], "1") is None and registered[0]["email"] == "ana@acme.dev"


def test_scripts_and_services_register_from_the_environment_or_go_on(sent, monkeypatch):
    answers(monkeypatch)
    monkeypatch.setattr(telemetry, "_interactive", lambda: False)
    assert telemetry.require_registration(["start"], "1") is None and registered == []   # asked next time in a terminal
    monkeypatch.setenv("SQUIDBRAKE_EMAIL", "ops@acme.dev")
    monkeypatch.setenv("SQUIDBRAKE_NAME", "Acme Ops")
    assert telemetry.require_registration(["start"], "1") is None
    assert registered[0]["email"] == "ops@acme.dev" and telemetry.load()["name"] == "Acme Ops"


def test_a_registration_made_offline_is_sent_later(sent, monkeypatch):
    online[0] = False
    answers(monkeypatch, "Asha", "me@acme.com")
    assert telemetry.require_registration(["doctor"], "1") is None        # not stopped for being offline
    assert telemetry.load()["register_pending"] is True
    online[0] = True
    telemetry.require_registration(["doctor"], "1")
    assert telemetry.load()["register_pending"] is False and len(registered) == 2
    telemetry.require_registration(["doctor"], "1")
    assert len(registered) == 2                                           # sent once it worked


def test_a_join_that_failed_is_retried_once_a_day_and_never_after_leaving(sent, monkeypatch, tmp_path):
    calls = []

    def flaky(server, path, body):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("offline")
        return {}
    monkeypatch.setattr(pilot, "_post", flaky)
    answers(monkeypatch, "")                                              # skip where-from
    telemetry.maybe(["doctor"], "1")
    assert telemetry.load()["counts_joined"] is False                    # the join failed (offline)
    telemetry.maybe(["doctor"], "1")                                     # the same day: not tried again
    assert calls == ["/v1/pilot/join"]
    monkeypatch.setattr(telemetry, "_today", lambda: "2099-01-01")
    telemetry.maybe(["doctor"], "1")                                     # the next day: tried again, and it works
    assert telemetry.load()["counts_joined"] is True and pilot.load(tmp_path / "data")
    pilot.leave(tmp_path / "data")                                       # they leave: never joined again
    n = len(calls)
    telemetry.maybe(["doctor"], "1")
    assert pilot.load(tmp_path / "data") is None and "/v1/pilot/join" not in calls[n:]


def test_status_tells_an_earlier_no_apart(sent, monkeypatch, capsys):
    """Someone who said no to an older version keeps sending nothing, and status says so instead of "on"."""
    telemetry._save({"id": "x", "enabled": False, "asked": "2026-10-01"})
    telemetry.maybe(["doctor"], "1")
    assert sent == []
    telemetry.main(["status"], "1")
    assert "off (you said no" in capsys.readouterr().out


def test_a_gateway_with_no_terminal_first_run_says_so_in_its_log_and_shares_counts(sent, tmp_path):
    """Docker or a background service: the notice goes to the gateway's log, then counts are shared, once."""
    said = []
    assert telemetry.gateway_start("1", said.append) is True
    assert joins == [("/v1/pilot/join", telemetry.COMMUNITY_CODE)] and "SQUIDBRAKE_TELEMETRY=0" in said[0]
    assert not (tmp_path / "telemetry.json").exists()     # a later terminal first run still asks its questions
    assert telemetry.gateway_start("1", said.append) is False and len(joins) == 1 and len(said) == 1   # once


def test_a_gateway_start_respects_off_switches_and_a_leave(sent, monkeypatch, tmp_path):
    for var, val in (("SQUIDBRAKE_TELEMETRY", "0"), ("DO_NOT_TRACK", "1"), ("CI", "true")):
        monkeypatch.setenv(var, val)
        assert telemetry.gateway_start("1", print) is False and joins == []
        monkeypatch.delenv(var)
    telemetry.gateway_start("1", lambda s: None)
    pilot.leave(tmp_path / "data")                         # they left: a restart never joins them again
    joins.clear()
    assert telemetry.gateway_start("1", lambda s: None) is False and joins == []


def test_a_gateway_that_was_offline_tries_again_on_its_next_start(sent, monkeypatch, tmp_path):
    def offline(server, path, body):
        raise RuntimeError("offline")
    monkeypatch.setattr(pilot, "_post", offline)
    assert telemetry.gateway_start("1", lambda s: None) is False
    monkeypatch.setattr(pilot, "_post", lambda server, path, body: joins.append((path, body["code"])) or {})
    assert telemetry.gateway_start("1", lambda s: None) is True and pilot.load(tmp_path / "data")


def test_an_email_given_after_the_gateway_joined_moves_its_counts_to_that_person(sent, monkeypatch, tmp_path):
    told = []
    monkeypatch.setattr(pilot, "_post", lambda server, path, body: told.append(body) or {})
    telemetry.gateway_start("1", lambda s: None)
    answers(monkeypatch, "Ana", "ana@acme.dev", "")                      # terminal first run: name, email, where-from
    telemetry.require_registration(["doctor"], "1")
    telemetry.maybe(["doctor"], "1")
    assert told[-1]["email"] == "ana@acme.dev" and told[-1]["install_id"] == told[0]["install_id"]


def test_the_off_switches_stop_the_counts_of_an_install_that_already_joined(sent, monkeypatch, tmp_path):
    """Joined the community counts, then DO_NOT_TRACK or SQUIDBRAKE_TELEMETRY=0 is set: nothing more is sent."""
    telemetry.gateway_start("1", lambda s: None)
    pings = []
    monkeypatch.setattr(pilot, "_post", lambda server, path, body, timeout=15: pings.append(path) or {})
    assert pilot.send(tmp_path / "data", {"days": {}}) is True and pings == ["/v1/ping"]
    for var, val in (("DO_NOT_TRACK", "1"), ("SQUIDBRAKE_TELEMETRY", "0")):
        monkeypatch.setenv(var, val)
        assert pilot.send(tmp_path / "data", {"days": {}}) is False and pings == ["/v1/ping"]
        monkeypatch.delenv(var)


def test_a_named_pilot_keeps_its_own_consent(sent, monkeypatch, tmp_path):
    """A pilot joined with its own code (it asked "Share these counts?") is left with `squidbrake pilot leave`."""
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "pilot.json").write_text(json.dumps({"code": "acme-123abc", "server": "https://x",
                                                              "install_id": "a" * 32}), encoding="utf-8")
    pings = []
    monkeypatch.setattr(pilot, "_post", lambda server, path, body, timeout=15: pings.append(path) or {})
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    assert pilot.send(tmp_path / "data", {"days": {}}) is True and pings == ["/v1/ping"]
