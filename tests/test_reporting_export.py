"""The actual Insights export preserves v2 receipts, hashes, rollups and pending exports."""
import io
import os

import pytest

from test_reporting_ingest import COMMUNITY, enroll, payload, send, service, uid  # noqa: F401


@pytest.mark.skipif(not os.getenv("TEST_INSIGHTS_DATABASE_URL"), reason="requires disposable Insights Postgres")
def test_sqlite_reporting_export_roundtrips_and_remains_idempotent(service, monkeypatch):
    if service.backend != "sqlite":
        pytest.skip("this exercises SQLite to Postgres export")
    import psycopg
    from psycopg import sql
    import export_to_supabase
    import pg
    from reporting_ingest import Collector, digest

    s = service
    iid, token = enroll(s)
    body = payload(iid)
    assert send(s, token, body).status_code == 200
    schema = "reporting_export_" + uid()[:12]
    monkeypatch.setattr(export_to_supabase, "SCHEMA", schema)
    stream = io.StringIO()
    export_to_supabase.export(str(s.path), stream)
    assert token not in stream.getvalue()
    url, pool = os.environ["TEST_INSIGHTS_DATABASE_URL"], None
    try:
        with psycopg.connect(url, autocommit=True) as c:
            c.execute(stream.getvalue())
            c.execute(stream.getvalue())
            assert c.execute("SELECT count(*) FROM reporting_events").fetchone()[0] == 1
            assert c.execute("SELECT count(*) FROM reporting_outbox WHERE sent_at IS NULL").fetchone()[0] == 1
            assert c.execute("SELECT revision, count FROM reporting_rollups").fetchone() == (1, 10)
            assert c.execute("SELECT counts FROM days").fetchone()[0] == '{"events": 5}'
            assert c.execute("SELECT bool_and(rowsecurity) FROM pg_tables WHERE schemaname=current_schema()").fetchone()[0]
        pool = pg.pool(url, schema)
        migrated = Collector(lambda: pg.Conn(pool), COMMUNITY)
        assert migrated.authenticate("Bearer " + token) == (iid, digest(token))
        from reporting_schema import Batch
        import json
        assert migrated.ingest((iid, digest(token)), Batch.model_validate_json(json.dumps(body)))["replayed"]
    finally:
        if pool:
            pool.close()
        with psycopg.connect(url, autocommit=True) as c:
            c.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
