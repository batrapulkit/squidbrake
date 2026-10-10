"""Usage stats: nothing without a yes, never from the hooks or scripts, and never more than the command name."""
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
    for var in ("SQUIDBRAKE_TELEMETRY", "DO_NOT_TRACK", "CI"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(telemetry, "POSTHOG_KEY", "phc_test")
    bodies = []
    monkeypatch.setattr(telemetry, "_post", bodies.append)
    monkeypatch.setattr(telemetry, "_interactive", lambda: True)
    monkeypatch.setattr(telemetry.threading, "Thread", RunNow)
    monkeypatch.setattr(pilot, "_post", lambda server, path, body: joins.append((path, body["code"])) or {})
    joins.clear()
    return bodies


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
    monkeypatch.setattr("builtins.input", lambda _q: next(it))


def test_enter_means_yes_and_only_the_command_name_is_sent(sent, monkeypatch):
    answers(monkeypatch, "", "", "")   # yes, where from: skipped, email: skipped
    telemetry.maybe(["undo", "SECRET-FILE-ID", "--path", "/home/me/secret.txt"], "9.9.9")
    assert len(sent) == 1
    body = json.dumps(sent[0])
    assert sent[0]["event"] == "cli_command" and sent[0]["properties"]["command"] == "undo"
    assert "SECRET" not in body and "secret.txt" not in body
    assert telemetry.load()["enabled"] is True


def test_no_sends_nothing_and_never_asks_again(sent, monkeypatch):
    answers(monkeypatch, "n")
    telemetry.maybe(["doctor"], "1")
    answers(monkeypatch)          # a second question would raise StopIteration
    telemetry.maybe(["doctor"], "1")
    assert sent == [] and telemetry.load()["enabled"] is False


@pytest.mark.parametrize("argv", [["hook"], ["agent-hook", "cursor"], ["shell-guard", "check", "rm -rf /"], ["proxy"]])
def test_hooks_never_ask_or_send(sent, monkeypatch, argv):
    answers(monkeypatch)
    telemetry.maybe(argv, "1")
    assert sent == [] and telemetry.load() == {}


def test_scripts_ci_and_opt_out_never_ask_or_send(sent, monkeypatch):
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


def test_without_a_posthog_key_it_still_asks_but_only_counts_are_shared(sent, monkeypatch):
    monkeypatch.setattr(telemetry, "POSTHOG_KEY", "")
    answers(monkeypatch, "", "", "me@acme.com")
    telemetry.maybe(["doctor"], "1")
    assert sent == []
    assert joins == [("/v1/pilot/join", telemetry.COMMUNITY_CODE)]


def test_yes_shares_counts_no_does_not_and_off_stops_them(sent, monkeypatch, tmp_path):
    answers(monkeypatch, "n")
    telemetry.maybe(["doctor"], "1")
    assert joins == [] and (tmp_path / "data" / "community-asked").exists()   # connect all won't ask again
    telemetry.main(["on"], "1")
    assert joins == [("/v1/pilot/join", telemetry.COMMUNITY_CODE)] and pilot.load(tmp_path / "data")
    telemetry.main(["off"], "1")
    assert joins[-1] == ("/v1/pilot/leave", telemetry.COMMUNITY_CODE) and not pilot.load(tmp_path / "data")


def test_a_real_pilot_is_never_moved_to_the_community_code(sent, monkeypatch, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "pilot.json").write_text(json.dumps({"code": "acme-123abc", "server": "https://x",
                                                              "install_id": "a" * 32}), encoding="utf-8")
    answers(monkeypatch, "", "", "")
    telemetry.maybe(["doctor"], "1")
    telemetry.main(["off"], "1")
    assert joins == [] and pilot.load(tmp_path / "data")["code"] == "acme-123abc"


def test_off_stops_sending(sent, monkeypatch):
    answers(monkeypatch, "", "", "")
    telemetry.maybe(["doctor"], "1")
    telemetry.main(["off"], "1")
    sent.clear()
    telemetry.maybe(["doctor"], "1")
    assert sent == []


def test_register_asks_first_and_sends_the_email(sent, monkeypatch):
    answers(monkeypatch, "n")
    telemetry.register(["me@acme.com"], "1")
    assert sent == []
    answers(monkeypatch, "")
    telemetry.register(["me@acme.com", "--company", "Acme"], "1")
    assert sent[0]["event"] == "$identify"
    assert sent[0]["properties"]["$set"]["email"] == "me@acme.com"
    assert sent[0]["properties"]["$set"]["company"] == "Acme"


def test_where_they_heard_about_it_is_one_word_from_a_list(sent, monkeypatch):
    joined = []
    monkeypatch.setattr(pilot, "_post", lambda server, path, body: joined.append(body) or {})
    monkeypatch.delenv("SQUIDBRAKE_REF", raising=False)
    answers(monkeypatch, "", "1", "")                                   # yes, LinkedIn, no email
    telemetry.maybe(["doctor"], "1")
    assert telemetry.load()["ref"] == "linkedin"
    assert sent[-1]["properties"]["ref"] == "linkedin" and sent[-1]["properties"]["$set_once"] == {"ref": "linkedin"}
    assert joined[0]["ref"] == "linkedin"                                # the counts carry it too


def test_a_named_link_answers_it_and_free_text_is_never_kept(sent, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_REF", "whatsapp")
    answers(monkeypatch, "", "")                                        # yes, no email: no where-from question
    telemetry.maybe(["setup"], "1")
    assert telemetry.load()["ref"] == "whatsapp"
    assert telemetry.ref_from_env() == "whatsapp"
    monkeypatch.setenv("SQUIDBRAKE_REF", "My Name; rm -rf ~/")
    assert telemetry.ref_from_env() is None                             # only a short lowercase word
    answers(monkeypatch, "maybe 3")
    assert telemetry._ask_source() is None                               # not a number from the list: nothing


def test_no_never_asks_where_from(sent, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_REF", "linkedin")
    answers(monkeypatch, "n")                                           # a where-from question would raise
    telemetry.maybe(["doctor"], "1")
    assert "ref" not in telemetry.load() and sent == []


def test_a_yes_whose_join_failed_is_retried_once_a_day_and_never_after_leaving(sent, monkeypatch, tmp_path):
    calls = []

    def flaky(server, path, body):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("offline")
        return {}
    monkeypatch.setattr(pilot, "_post", flaky)
    monkeypatch.delenv("SQUIDBRAKE_REF", raising=False)
    answers(monkeypatch, "", "", "")                                    # yes, skip where-from, skip email
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
