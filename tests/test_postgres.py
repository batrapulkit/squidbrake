"""Postgres as the gateway's database (TEST_DATABASE_URL, the CI job "postgres"): the tables in DB_SCHEMA when it's set,
values longer than the old column sizes, and two gateway processes writing at once keeping one linear audit chain.
The rest of the gateway's behaviour runs here too: test_server.py and the modules that import it use the same database."""
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

if not os.getenv("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to a Postgres database to run these", allow_module_level=True)

from test_server import c, server  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[1]
TABLES = {"events", "notes", "gateway_state", "audit_log", "audit_checkpoints", "snapshots", "usage", "devices",
          "capabilities", "policy_versions"}


def test_the_url_from_supabase_works_as_given():
    assert server.engine.dialect.name == "postgresql" and server.DATABASE_URL.startswith("postgresql+psycopg://")


def test_every_table_is_in_the_schema(c):
    from sqlalchemy import inspect
    schema = os.getenv("DB_SCHEMA") or None
    with server.engine.connect() as conn:          # plain SQL lands there too (search_path, set per connection)
        assert conn.execute(server.text("SELECT current_schema()")).scalar() == (schema or "public")
        assert conn.execute(server.text("SELECT count(*) FROM events")).scalar() >= 0
    assert TABLES <= set(inspect(server.engine).get_table_names(schema=schema))
    if schema:
        assert "events" not in inspect(server.engine).get_table_names(schema="public")


def test_a_long_path_fits_where_sqlite_kept_it(c):
    """The old String(n) sizes were never enforced by SQLite; Postgres would have refused these rows."""
    long = "/very/deep/" + "folder/" * 300 + "file.txt"
    with server.audited_tx() as conn:
        conn.execute(server.capabilities.insert().values(
            identity="pg-test", capability="after:pg-test", target=long, source_event=str(uuid.uuid4()),
            created_at=server.utcnow(), expires_at="2999-01-01T00:00:00.000Z"))   # not purged mid-test as expired
        server.audit(conn, "pg-test", "test.long", long)
    with server.engine.connect() as conn:
        got = conn.execute(server.select(server.capabilities.c.target)
                           .where(server.capabilities.c.identity == "pg-test")).scalar()
    assert got == long


def test_two_gateway_processes_keep_one_chain(c):
    """Writes from two processes at once: the advisory lock keeps the hash chain linear, and it verifies."""
    with server.engine.connect() as conn:
        before = conn.execute(server.select(server.func.count()).select_from(server.audit_trail)).scalar()
    write = ("import server\n"
             "for i in range(40):\n"
             "    with server.audited_tx() as conn:\n"
             "        server.audit(conn, 'writer', 'test.concurrent', str(i))\n")
    procs = [subprocess.Popen([sys.executable, "-c", write], cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
             for _ in range(2)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0]
    with server.engine.connect() as conn:
        after = conn.execute(server.select(server.func.count()).select_from(server.audit_trail)).scalar()
    assert after - before == 80
    result = server.verify_audit_chain()
    assert result["ok"], result
