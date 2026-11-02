"""Shared reporting controls: real send boundaries, migration and cross-process identity."""
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, create_engine

import pilot
import reporting
import telemetry

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path))
    for key in ("CI", "DO_NOT_TRACK", "SQUIDBRAKE_TELEMETRY", "KEYS_PATH"):
        monkeypatch.delenv(key, raising=False)
    # Block the actual HTTP boundary; individual tests install their own fake.
    monkeypatch.setattr(pilot.httpx, "post", lambda *a, **k: pytest.fail("unexpected HTTP request"))


def enrolled(home):
    pilot._save(home, {"code": "community-test", "server": "https://collector.example",
                       "install_id": "a" * 32})


@pytest.mark.parametrize("key,value", [("DO_NOT_TRACK", "1"), ("SQUIDBRAKE_TELEMETRY", "0"), ("CI", "true")])
def test_overrides_stop_existing_membership_and_every_retry(tmp_path, monkeypatch, key, value):
    home = reporting.data_dir()
    enrolled(home)
    monkeypatch.setenv(key, value)
    requests = []
    monkeypatch.setattr(pilot.httpx, "post", lambda *a, **k: requests.append(a))
    telemetry._post({"event": "cli_command"})
    assert not pilot.send(home, {"days": {}})
    assert pilot.send_if_changed(home, lambda: pytest.fail("collected while off")) is None
    pilot.flush(home, lambda: pytest.fail("collected at shutdown while off"))
    assert pilot.join(home, "community-test", "https://collector.example", True, "1") == 1
    assert telemetry.register(["a@example.com", "--yes"], "1") == 1
    assert requests == []


def test_persisted_off_survives_restart_and_cancels_queued_posthog(tmp_path, monkeypatch):
    enrolled(reporting.data_dir())
    telemetry._save({"enabled": True, "id": "old-cli-id"})
    assert telemetry.main(["off"]) == 0
    telemetry._post({"event": "cli_command"})       # a thread created before off
    assert not pilot.send(reporting.data_dir(), {"days": {}})
    env = dict(os.environ)
    result = subprocess.run([sys.executable, "-c", "import reporting; print(reporting.enabled())"],
                            cwd=ROOT, env=env, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "False"
    assert reporting.read_json(telemetry._path())["enabled"] is False


def test_a_stale_cli_settings_write_cannot_undo_off(tmp_path):
    telemetry._save({"enabled": True, "id": "old-cli-id"})
    stale = telemetry.load()
    telemetry.main(["off"])
    stale["ref"] = "github"
    telemetry._save(stale)
    assert telemetry.load()["enabled"] is False
    assert not reporting.enabled()


def test_policy_and_existing_identity_reads_do_not_wait_for_network_sends(tmp_path):
    ident = reporting.identity()
    ident = reporting.identity(cli_id=ident["installation_id"])
    with reporting.permit() as ok:
        assert ok
        assert reporting.enabled()
        assert reporting.identity(cli_id=ident["installation_id"]) == ident


def test_off_serializes_with_a_send_in_another_process(tmp_path):
    # The child announces that it started before attempting the settings lock.
    code = "import telemetry; print('started', flush=True); telemetry.main(['off'])"
    with reporting.permit() as ok:
        assert ok
        child = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=dict(os.environ),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert child.stdout.readline().strip() == "started"
        assert child.poll() is None
    out, err = child.communicate(timeout=10)
    assert child.returncode == 0, err
    assert not reporting.enabled()


def test_off_waits_for_inflight_send_then_no_more_requests(tmp_path, monkeypatch):
    entered, release, disabled = threading.Event(), threading.Event(), threading.Event()
    requests = []

    def fake_post(*a, **k):
        requests.append(a)
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr(pilot.httpx, "post", fake_post)
    with ThreadPoolExecutor(max_workers=2) as pool:
        send = pool.submit(telemetry._post, {"event": "cli_command"})
        assert entered.wait(5)

        def off():
            telemetry.main(["off"])
            disabled.set()

        stop = pool.submit(off)
        try:
            assert not disabled.wait(0.1)
        finally:
            release.set()
        send.result(timeout=5)
        stop.result(timeout=5)
    telemetry._post({"event": "cli_command"})
    assert len(requests) == 1


def test_offline_leave_keeps_identity_and_blocks_automatic_rejoin(tmp_path, monkeypatch):
    home = reporting.data_dir()
    enrolled(home)
    before = reporting.identity(home)
    assert pilot.leave(home) == 0
    assert not reporting.automatic_join_allowed(home)
    assert telemetry.gateway_start("1") is False
    assert not pilot.send(home, {"days": {}})
    telemetry.main(["on"])
    assert not reporting.automatic_join_allowed(home)
    sent = []
    monkeypatch.setattr(pilot, "_post", lambda *a, **k: sent.append(a[2]) or {})
    assert pilot.join(home, "new-pilot", "https://collector.example", True, "1") == 0
    assert sent[0]["install_id"] == before["legacy_pilot_id"]
    assert reporting.identity(home)["installation_id"] == before["installation_id"]


def test_leaving_before_migration_keeps_the_original_installation_id(tmp_path):
    home = reporting.data_dir()
    enrolled(home)
    pilot.leave(home)
    assert reporting.identity(home)["installation_id"] == "a" * 32


def test_automatic_join_never_overwrites_a_named_pilot(tmp_path):
    home = reporting.data_dir()
    enrolled(home)
    assert pilot.join(home, "community-other", "https://collector.example", True, "1", automatic=True) == 1
    assert pilot.load(home)["code"] == "community-test"


def test_override_changed_during_retry_stops_followup_requests(tmp_path, monkeypatch):
    home = reporting.data_dir()
    enrolled(home)
    calls = []

    def refused(*args, **kwargs):
        calls.append(args[1])
        monkeypatch.setenv("DO_NOT_TRACK", "1")
        raise RuntimeError("403: missing membership")

    monkeypatch.setattr(pilot, "_post", refused)
    assert not pilot.send(home, {"days": {}})
    assert calls == ["/v1/ping"]


def test_enable_after_fresh_off_enrolls_on_the_next_normal_command(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry, "_post", lambda *a, **k: None)
    monkeypatch.setattr(telemetry.threading, "Thread", ImmediateThread)
    calls = []
    monkeypatch.setattr(pilot, "_post", lambda *a, **k: calls.append(a[1]) or {})
    telemetry.main(["off"])
    telemetry.main(["on"])
    assert calls == []
    telemetry.maybe(["doctor"], "1")
    assert calls == ["/v1/pilot/join"]
    assert telemetry.load()["id"] == reporting.identity()["installation_id"]


def test_migrate_both_ids_without_moving_the_pilot(tmp_path):
    cli_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    telemetry._save({"id": cli_id, "enabled": True})
    home = reporting.data_dir()
    enrolled(home)
    mine = reporting.identity(home)
    assert mine == {"installation_id": "a" * 32, "legacy_cli_id": cli_id, "legacy_pilot_id": "a" * 32}
    assert telemetry.load()["id"] == cli_id
    assert pilot.load(home)["code"] == "community-test"
    assert reporting.identity(home) == mine


def test_simultaneous_processes_get_one_canonical_identity(tmp_path):
    code = "import reporting; print(reporting.identity()['installation_id'])"
    children = [subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=dict(os.environ),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(6)]
    ids = []
    for child in children:
        out, err = child.communicate(timeout=20)
        assert child.returncode == 0, err
        ids.append(out.strip())
    assert len(set(ids)) == 1 and len(ids[0]) == 32


def test_prior_refusal_and_corrupt_settings_fail_closed(tmp_path):
    enrolled(reporting.data_dir())
    telemetry._save({"enabled": False, "id": "old-id"})
    assert not pilot.send(reporting.data_dir(), {})
    telemetry._path().write_text("{broken", encoding="utf-8")
    assert not reporting.enabled()
    assert not pilot.send(reporting.data_dir(), {})


@pytest.mark.parametrize("bad", [[], {"usage": "false"}, {"identity": []}])
def test_invalid_local_reporting_state_never_enables_a_send(tmp_path, bad):
    import sqlite3
    home = reporting.data_dir()
    enrolled(home)
    assert reporting.enabled(home)
    with reporting.transaction(home):
        pass
    with sqlite3.connect(home / "reporting.db") as conn:
        conn.execute("UPDATE reporting_state SET value=?", (json.dumps(bad),))
    assert not reporting.enabled(home)
    assert not pilot.send(home, {})


def test_registration_is_optional_and_never_verifies_an_organization(tmp_path, monkeypatch):
    bodies = []
    monkeypatch.setattr(telemetry, "_post", bodies.append)
    monkeypatch.setattr(telemetry.threading, "Thread", ImmediateThread)
    assert not reporting.enabled(channel="contact")
    assert telemetry.register(["a@example.com", "--company", "Claimed company", "--yes"], "1") == 0
    assert reporting.enabled(channel="contact")
    assert "$groups" not in json.dumps(bodies)
    telemetry.main(["contact-off"])
    telemetry._send("$identify", "a", {"email": "a@example.com"}, wait=True)
    assert len(bodies) == 1
    assert reporting.enabled()             # anonymous usage remains independently enabled
    telemetry.main(["off"])
    telemetry.main(["on"])
    assert not reporting.enabled(channel="contact")


class ImmediateThread:
    def __init__(self, target, args, daemon):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)

    def join(self, timeout=None):
        pass


def test_dataset_epoch_is_database_scoped_and_can_be_rotated(tmp_path):
    def database(path):
        eng = create_engine(f"sqlite:///{path}")
        md = MetaData()
        Table("gateway_state", md, Column("key", String, primary_key=True), Column("value", Text))
        md.create_all(eng)
        return eng

    eng = database(tmp_path / "gateway.db")
    first = reporting.dataset_epoch(eng)
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert set(pool.map(lambda _: reporting.dataset_epoch(eng), range(6))) == {first}
    eng.dispose()
    eng = database(tmp_path / "gateway.db")
    assert reporting.dataset_epoch(eng) == first
    rotated = reporting.dataset_epoch(eng, rotate=True)
    assert rotated != first and reporting.dataset_epoch(eng) == rotated
    eng.dispose()
    (tmp_path / "gateway.db").unlink()
    eng = database(tmp_path / "gateway.db")
    assert reporting.dataset_epoch(eng) not in {first, rotated}
    eng.dispose()
