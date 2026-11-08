"""Versioned Insights ingestion: protocol, isolation and atomicity on both databases."""
import asyncio
import copy
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "insights"))
import reporting_ingest as ingest  # noqa: E402
from reporting_schema import Batch  # noqa: E402

BACKENDS = ["sqlite"] + (["postgres"] if os.getenv("TEST_INSIGHTS_DATABASE_URL") else [])
COMMUNITY = "community-test"
ADMIN = {"X-Admin-Key": "test-admin"}


def uid():
    return uuid.uuid4().hex


@pytest.fixture(params=BACKENDS)
def service(request, tmp_path, monkeypatch):
    monkeypatch.setenv("INSIGHTS_REPORTING_V2", "1")
    pool, schema = None, None
    path = tmp_path / "insights.db"
    if request.param == "postgres":
        import pg
        schema = "reporting_test_" + uid()[:12]
        pool = pg.pool(os.environ["TEST_INSIGHTS_DATABASE_URL"], schema)
        db = lambda: pg.Conn(pool)
    else:
        @contextmanager
        def db():
            c = sqlite3.connect(path, timeout=20)
            c.row_factory = sqlite3.Row
            try:
                with c:
                    yield c
            finally:
                c.close()
    with db() as c:
        c.executescript("""CREATE TABLE pilots (code TEXT PRIMARY KEY, company TEXT NOT NULL);
            CREATE TABLE installs (install_id TEXT PRIMARY KEY, code TEXT NOT NULL);
            CREATE TABLE days (install_id TEXT NOT NULL, day TEXT NOT NULL, counts TEXT NOT NULL,
                PRIMARY KEY (install_id, day));""")
        c.execute("INSERT INTO pilots VALUES (?,?)", (COMMUNITY, "Community"))
        c.execute("INSERT INTO pilots VALUES (?,?)", ("private-pilot", "Private"))
        c.execute("INSERT INTO installs VALUES (?,?)", ("e" * 32, "private-pilot"))
        c.execute("INSERT INTO days VALUES (?,?,?)", ("e" * 32, "2026-10-01", '{"events": 5}'))
    app = FastAPI()

    def admin(x_admin_key: str = Header(default="")):
        if x_admin_key != ADMIN["X-Admin-Key"]:
            raise HTTPException(401, "admin required")

    ingest.mount(app, db, admin, COMMUNITY)
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, db=db, collector=app.state.reporting_collector,
                              path=path, schema=schema, backend=request.param, tmp=tmp_path)
    if pool:
        pool.close()
        import psycopg
        from psycopg import sql
        with psycopg.connect(os.environ["TEST_INSIGHTS_DATABASE_URL"], autocommit=True) as c:
            c.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def enroll(s, iid=None):
    iid = iid or uid()
    r = s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": iid,
                                                     "community_code": COMMUNITY})
    assert r.status_code == 200, r.text
    assert r.headers["Cache-Control"] == "no-store"
    return iid, r.json()["reporting_token"]


def payload(iid):
    at = datetime.now(timezone.utc)
    return {"schema_version": 2, "installation_id": iid, "dataset_epoch": uid(), "batch_id": uid(),
            "sent_at": at.isoformat(), "product_version": "0.14.17", "events": [{
                "event_id": uid(), "event_name": "setup_completed", "occurred_at": at.isoformat(),
                "recorded_at": at.isoformat(), "emitter_version": "0.14.17",
                "properties": {"installer": "pip", "os_family": "linux"}}], "rollups": [{
                "day": at.date().isoformat(), "agent_family": "codex", "integration_family": "builtin",
                "tool_category": "shell", "mode": "enforce", "kind": "initial_decision", "outcome": "allow",
                "count": 10, "revision": 1}]}


def send(s, token, body):
    return s.client.post("/v2/reporting/batches", headers={"Authorization": "Bearer " + token}, json=body)


def count(s, table):
    with s.db() as c:
        return c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_credentials_are_scoped_hashed_and_not_retrievable(service):
    s = service
    iid, token = enroll(s)
    with s.db() as c:
        row = c.execute("SELECT * FROM reporting_credentials").fetchone()
        assert token not in json.dumps(dict(row)) and ingest.digest(token) in row
    assert s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": iid,
                                                      "community_code": COMMUNITY}).status_code == 409
    body = payload(uid())
    assert send(s, token, body).status_code == 403
    for wrong in (COMMUNITY, "phc_public_capture_key", "sbr_" + "x" * 43):
        assert send(s, wrong, body).status_code == 401
    assert count(s, "reporting_events") == 0


def test_named_pilots_and_aliases_need_one_time_admin_invitations(service):
    s, iid = service, uid()
    request = {"installation_id": iid, "pilot_code": "private-pilot", "aliases": [
        {"kind": "pilot", "alias": "e" * 32}, {"kind": "cli", "alias": str(uuid.uuid4())}]}
    assert s.client.post("/v1/admin/reporting/invitations", json=request).status_code == 401
    r = s.client.post("/v1/admin/reporting/invitations", headers=ADMIN, json=request)
    assert r.status_code == 200, r.text
    invitation = r.json()["invitation_token"]
    body = {"schema_version": 2, "installation_id": iid, "invitation_token": invitation}
    assert s.client.post("/v2/reporting/enroll", json=body).status_code == 200
    assert s.client.post("/v2/reporting/enroll", json=body).status_code == 403
    with s.db() as c:
        row = c.execute("SELECT pilot_code, provenance FROM reporting_installations").fetchone()
        assert tuple(row) == ("private-pilot", "invited")
        assert c.execute("SELECT code FROM installs WHERE install_id=?", ("e" * 32,)).fetchone()[0] == "private-pilot"
        assert c.execute("SELECT counts FROM days").fetchone()[0] == '{"events": 5}'
    assert count(s, "reporting_aliases") == 2
    with s.db() as c:
        stored = c.execute("SELECT token_hash FROM reporting_invitations").fetchone()[0]
        assert stored == ingest.digest(invitation) and stored != invitation


def test_community_enrollment_cannot_attach_legacy_data(service):
    s = service
    r = s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": uid(),
        "community_code": COMMUNITY, "aliases": [{"kind": "pilot", "alias": "e" * 32}]})
    assert r.status_code == 422
    bad = {"installation_id": uid(), "pilot_code": COMMUNITY,
           "aliases": [{"kind": "pilot", "alias": "e" * 32}]}
    assert s.client.post("/v1/admin/reporting/invitations", headers=ADMIN, json=bad).status_code == 409
    assert count(s, "reporting_aliases") == 0


def test_expired_invitation_and_conflicting_alias_roll_back_enrollment(service):
    s = service
    alias = {"kind": "cli", "alias": uid()}
    first = {"installation_id": uid(), "pilot_code": "private-pilot", "aliases": [alias]}
    invite = s.client.post("/v1/admin/reporting/invitations", headers=ADMIN, json=first).json()["invitation_token"]
    with s.db() as c:
        c.execute("UPDATE reporting_invitations SET expires_at=?", ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),))
    assert s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": first["installation_id"],
                                                     "invitation_token": invite}).status_code == 403
    for index in range(2):
        first["installation_id"] = uid()
        invite = s.client.post("/v1/admin/reporting/invitations", headers=ADMIN, json=first).json()["invitation_token"]
        r = s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": first["installation_id"],
                                                       "invitation_token": invite})
        assert r.status_code == (200 if index == 0 else 409)
    assert count(s, "reporting_installations") == count(s, "reporting_credentials") == 1


def test_admin_rotation_and_revocation_stop_old_tokens(service):
    s = service
    iid, old = enroll(s)
    url = f"/v1/admin/reporting/installations/{iid}/credential"
    assert s.client.post(url).status_code == 401
    new = s.client.post(url, headers=ADMIN).json()["reporting_token"]
    body = payload(iid)
    assert send(s, old, body).status_code == 401
    assert send(s, new, body).status_code == 200
    assert s.client.delete(url, headers=ADMIN).status_code == 200
    assert send(s, new, body).status_code == 401


def test_revocation_during_a_request_prevents_commit_and_works_while_disabled(service, monkeypatch):
    s = service
    iid, token = enroll(s)
    principal = s.collector.authenticate("Bearer " + token)
    body = Batch.model_validate_json(json.dumps(payload(iid)))
    monkeypatch.setenv("INSIGHTS_REPORTING_V2", "0")
    assert s.client.delete(f"/v1/admin/reporting/installations/{iid}/credential", headers=ADMIN).status_code == 200
    with pytest.raises(HTTPException) as error:
        s.collector.ingest(principal, body)
    assert error.value.status_code == 401 and count(s, "reporting_events") == 0


def test_removed_pilot_cannot_continue_reporting(service):
    s, iid = service, uid()
    invitation = s.client.post("/v1/admin/reporting/invitations", headers=ADMIN,
        json={"installation_id": iid, "pilot_code": "private-pilot"}).json()["invitation_token"]
    token = s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": iid,
        "invitation_token": invitation}).json()["reporting_token"]
    principal = s.collector.authenticate("Bearer " + token)
    with s.db() as c:
        c.execute("DELETE FROM pilots WHERE code=?", ("private-pilot",))
    assert send(s, token, payload(iid)).status_code == 401
    with pytest.raises(HTTPException) as error:
        s.collector.ingest(principal, Batch.model_validate_json(json.dumps(payload(iid))))
    assert error.value.status_code == 401 and count(s, "reporting_events") == 0


def test_replay_and_new_batch_event_duplicates_create_one_outbox_record(service, monkeypatch):
    s = service
    iid, token = enroll(s)
    body = payload(iid)
    first = send(s, token, body)
    assert first.status_code == 200, first.text
    assert first.json()["accepted_events"] == first.json()["updated_rollups"] == 1
    replay = send(s, token, body).json()
    assert replay == {**first.json(), "replayed": True}
    body["batch_id"] = uid()
    again = send(s, token, body).json()
    assert again["duplicate_events"] == again["duplicate_rollups"] == 1
    assert count(s, "reporting_events") == count(s, "reporting_outbox") == count(s, "reporting_rollups") == 1
    body["rollups"][0]["count"] = 100
    assert send(s, token, body).status_code == 409
    body["rollups"][0]["count"] = 10
    old_clock = ingest.utcnow()
    monkeypatch.setattr(ingest, "utcnow", lambda: old_clock + timedelta(days=42))
    assert send(s, token, body).json()["replayed"] is True    # receipt retry after the acceptance window


def test_rollups_replace_and_ignore_stale_revisions(service):
    s = service
    iid, token = enroll(s)
    body = payload(iid)
    assert send(s, token, body).status_code == 200
    for revision, amount, field in ((3, 7, "updated_rollups"), (2, 900, "stale_rollups"), (3, 7, "duplicate_rollups")):
        body["batch_id"] = uid()
        body["rollups"][0].update(revision=revision, count=amount)
        response = send(s, token, body)
        assert response.status_code == 200 and response.json()[field] == 1, response.text
    with s.db() as c:
        assert tuple(c.execute("SELECT revision, count FROM reporting_rollups").fetchone()) == (3, 7)


@pytest.mark.parametrize("conflict", ["event", "rollup"])
def test_conflicts_rollback_other_events_and_outbox(service, conflict):
    s = service
    iid, token = enroll(s)
    body = payload(iid)
    assert send(s, token, body).status_code == 200
    body["batch_id"] = uid()
    new = copy.deepcopy(body["events"][0])
    new["event_id"] = uid()
    body["events"].insert(0, new)
    if conflict == "event":
        body["events"][1]["properties"]["installer"] = "docker"
    else:
        body["rollups"][0]["count"] = 999
    assert send(s, token, body).status_code == 409
    assert count(s, "reporting_batches") == count(s, "reporting_events") == count(s, "reporting_outbox") == 1


def test_dataset_epoch_has_one_writer(service):
    s = service
    iid, token = enroll(s)
    body = payload(iid)
    assert send(s, token, body).status_code == 200
    other, secret = enroll(s)
    body.update(installation_id=other, batch_id=uid())
    assert send(s, secret, body).status_code == 409
    assert count(s, "reporting_events") == 1


@pytest.mark.parametrize("bad", ["extra", "properties", "dimension", "negative", "bool", "float", "schema",
                                 "future", "old", "naive", "kind", "rows", "catalogue_bool", "schema_float"])
def test_invalid_batches_are_atomic_and_do_not_echo_customer_input(service, bad):
    s = service
    iid, token = enroll(s)
    body = payload(iid)
    marker = "PLANTED-CUSTOMER-COMMAND-SECRET"
    if bad == "extra": body["command"] = marker
    if bad == "properties": body["events"][0]["properties"]["prompt"] = marker
    if bad == "dimension": body["rollups"][0]["agent_family"] = marker
    if bad == "negative": body["rollups"][0]["count"] = -1
    if bad == "bool": body["rollups"][0]["count"] = True
    if bad == "float": body["rollups"][0]["revision"] = 1.5
    if bad == "schema": body["schema_version"] = 99
    if bad == "schema_float": body["schema_version"] = 2.0
    if bad == "catalogue_bool": body["events"][0]["catalogue_version"] = True
    if bad == "future": body["sent_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    if bad == "old": body["rollups"][0]["day"] = "2020-01-01"
    if bad == "naive": body["sent_at"] = "2026-11-02T00:00:00"
    if bad == "kind": body["rollups"][0]["outcome"] = "failed"
    if bad == "rows": body["events"] *= 101
    r = send(s, token, body)
    assert r.status_code == 422 and marker not in r.text, r.text
    assert count(s, "reporting_events") == count(s, "reporting_outbox") == count(s, "reporting_datasets") == 0


def test_commit_failure_never_acknowledges_or_leaves_partial_records(service, monkeypatch):
    s = service
    iid, token = enroll(s)
    body, db = payload(iid), s.db

    @contextmanager
    def failure():
        with db() as c:
            yield c
            if c.execute("SELECT count(*) FROM reporting_batches").fetchone()[0]:
                raise sqlite3.OperationalError("injected commit failure")

    monkeypatch.setattr(s.collector, "db", failure)
    r = send(s, token, body)
    assert r.status_code == 503 and "Retry-After" in r.headers
    assert count(s, "reporting_batches") == count(s, "reporting_outbox") == count(s, "reporting_events") == 0
    monkeypatch.setattr(s.collector, "db", db)
    assert send(s, token, body).status_code == 200


def test_concurrent_requests_do_not_duplicate_records(service):
    s = service
    iid, token = enroll(s)
    body = payload(iid)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: send(s, token, body), range(8)))
    assert all(r.status_code == 200 for r in responses), [r.text for r in responses]
    assert sum(not r.json()["replayed"] for r in responses) == 1
    assert count(s, "reporting_batches") == count(s, "reporting_events") == count(s, "reporting_outbox") == 1


def test_separate_processes_serialize_ingestion(service):
    s = service
    iid, token = enroll(s)
    file = s.tmp / "batch.json"
    file.write_text(json.dumps({"who": [iid, ingest.digest(token)], "body": payload(iid)}))
    script = """import json, os, sqlite3, sys
from reporting_ingest import Collector
from reporting_schema import Batch
pool = None
if os.environ.get('REPORTING_TEST_SCHEMA'):
    import pg
    pool = pg.pool(os.environ['TEST_INSIGHTS_DATABASE_URL'], os.environ['REPORTING_TEST_SCHEMA'])
    db = lambda: pg.Conn(pool)
else:
    def db():
        c = sqlite3.connect(sys.argv[2], timeout=20)
        c.row_factory = sqlite3.Row
        return c
data = json.load(open(sys.argv[1]))
c = Collector(db, 'community-test')
print(json.dumps(c.ingest(tuple(data['who']), Batch.model_validate_json(json.dumps(data['body'])))))
if pool: pool.close()
"""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "insights")}
    if s.schema: env["REPORTING_TEST_SCHEMA"] = s.schema
    workers = [subprocess.Popen([sys.executable, "-c", script, str(file), str(s.path)], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    results = []
    for worker in workers:
        out, err = worker.communicate(timeout=30)
        assert worker.returncode == 0, err
        results.append(json.loads(out))
    assert sum(not r["replayed"] for r in results) == 1
    assert count(s, "reporting_events") == count(s, "reporting_outbox") == 1


def test_disable_and_durable_rate_limits(service, monkeypatch):
    s = service
    monkeypatch.setenv("INSIGHTS_REPORTING_V2", "0")
    assert s.client.post("/v2/reporting/enroll", json={}).status_code == 503
    monkeypatch.setenv("INSIGHTS_REPORTING_V2", "1")
    monkeypatch.setattr(ingest, "ENROLL_LIMIT", 1)
    iid, token = enroll(s)
    r = s.client.post("/v2/reporting/enroll", json={"schema_version": 2, "installation_id": uid(), "community_code": COMMUNITY})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    monkeypatch.setattr(ingest, "INGEST_INSTALL_LIMIT", 1)
    assert send(s, token, payload(iid)).status_code == 200
    assert send(s, token, payload(iid)).status_code == 429
    s.collector.limit("shared-worker-bucket", 1, 3600)
    another = ingest.Collector(s.db, COMMUNITY)
    with pytest.raises(HTTPException) as error:
        another.limit("shared-worker-bucket", 1, 3600)
    assert error.value.status_code == 429


def test_body_limits_stop_reading_chunked_requests():
    calls = []

    async def receive():
        calls.append(1)
        assert len(calls) <= 2, "read beyond the limit"
        return {"type": "http.request", "body": b"x" * 10, "more_body": True}

    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []}, receive)
    with pytest.raises(HTTPException) as error:
        asyncio.run(ingest.read_body(request, 16))
    assert error.value.status_code == 413 and len(calls) == 2


def test_declared_oversize_and_compression_are_rejected(service):
    iid, token = enroll(service)
    headers = {"Authorization": "Bearer " + token, "Content-Length": str(ingest.MAX_BODY + 1)}
    assert service.client.post("/v2/reporting/batches", content=b"{}", headers=headers).status_code == 413
    headers.pop("Content-Length")
    headers["Content-Encoding"] = "gzip"
    assert service.client.post("/v2/reporting/batches", content=b"{}", headers=headers).status_code == 415


def test_migrations_are_repeatable_and_postgres_tables_are_private(service):
    s = service
    enroll(s)
    ingest.Collector(s.db, COMMUNITY)
    assert count(s, "reporting_installations") == 1
    with s.db() as c:
        assert c.execute("SELECT count(*) FROM days").fetchone()[0] == 1
        if s.backend == "postgres":
            rows = c.execute("SELECT rowsecurity FROM pg_tables WHERE schemaname=current_schema() AND tablename LIKE 'reporting_%'").fetchall()
            assert len(rows) == 10 and all(row[0] for row in rows)


def test_migration_revokes_public_grants_even_when_rls_is_already_enabled(service):
    s = service
    if s.backend != "postgres":
        pytest.skip("PostgreSQL role permissions")
    with s.db() as c:
        if c.execute("SELECT count(*) FROM pg_roles WHERE rolname IN ('anon', 'authenticated')").fetchone()[0] != 2:
            pytest.skip("disposable database has no Supabase roles")
        c.execute("GRANT SELECT ON reporting_events TO anon, authenticated")
    ingest.Collector(s.db, COMMUNITY)
    with s.db() as c:
        assert not c.execute("""SELECT 1 FROM information_schema.table_privileges
            WHERE table_schema=current_schema() AND table_name='reporting_events'
            AND grantee IN ('anon', 'authenticated')""").fetchall()


def test_real_app_preserves_legacy_join_and_ping_alongside_v2(service):
    s = service
    schema = "reporting_app_" + uid()[:12]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("INSIGHTS_", "PIPELINE_"))}
    env.update(PYTHONPATH=str(ROOT / "insights"), INSIGHTS_DB=str(s.tmp / "real-app.db"),
               INSIGHTS_REPORTING_V2="1", INSIGHTS_ADMIN_KEY="test-admin-key")
    if s.backend == "postgres":
        env.update(INSIGHTS_DATABASE_URL=os.environ["TEST_INSIGHTS_DATABASE_URL"], INSIGHTS_PG_SCHEMA=schema)
    code = """import uuid
from fastapi.testclient import TestClient
import app
with TestClient(app.app) as c:
    old = {'code': app.COMMUNITY_CODE, 'install_id': uuid.uuid4().hex, 'version': '0.14.17'}
    assert c.post('/v1/pilot/join', json=old).status_code == 200
    assert c.post('/v1/ping', json={**old, 'usage': {'days': {}, 'total_events': 5}}).status_code == 200
    new = c.post('/v2/reporting/enroll', json={'schema_version': 2,
        'installation_id': uuid.uuid4().hex, 'community_code': app.COMMUNITY_CODE})
    assert new.status_code == 200, new.text
    with app.db() as db:
        assert db.execute('SELECT total_events FROM installs WHERE install_id=?', (old['install_id'],)).fetchone()[0] == 5
print('legacy and v2 coexist')
if app.DATABASE_URL: app._pg.close()
"""
    try:
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT / "insights", env=env,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "legacy and v2 coexist" in result.stdout
    finally:
        if s.backend == "postgres":
            import psycopg
            from psycopg import sql
            with psycopg.connect(os.environ["TEST_INSIGHTS_DATABASE_URL"], autocommit=True) as c:
                c.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
