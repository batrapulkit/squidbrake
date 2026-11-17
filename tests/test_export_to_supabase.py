"""The pilots database moves to Supabase whole: every table and row, the id counters, and row level security on.
Needs a real Postgres (pip install pgserver), so it's skipped without one."""
import io
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "insights"))
pgserver = pytest.importorskip("pgserver")
psycopg = pytest.importorskip("psycopg")


def test_export_loads_into_postgres(tmp_path):
    import export_to_supabase
    src = tmp_path / "insights.db"
    with sqlite3.connect(src) as c:
        c.executescript("""
        CREATE TABLE pilots (code TEXT PRIMARY KEY, company TEXT NOT NULL, created_at TEXT NOT NULL,
            page_views INTEGER NOT NULL DEFAULT 0, mrr INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE team_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, name TEXT NOT NULL,
            note TEXT);
        CREATE INDEX team_requests_t ON team_requests (created_at);
        CREATE TABLE catches (install_id TEXT NOT NULL, t TEXT NOT NULL, data TEXT NOT NULL);
        """)
        c.execute("INSERT INTO pilots VALUES ('acme-1', 'O''Neil & Co', '2026-10-01', 3, 99)")
        c.execute("INSERT INTO team_requests (created_at, name, note) VALUES ('2026-10-02', 'Asha', '100% sure; ?')")
        c.execute("INSERT INTO catches VALUES ('i1', '2026-10-02', '{}')")
    sql = io.StringIO()
    export_to_supabase.export(str(src), sql)
    srv = pgserver.get_server(str(tmp_path / "pg"), cleanup_mode="stop")
    with psycopg.connect(srv.get_uri(), autocommit=True) as pgc:
        pgc.execute("CREATE ROLE anon; CREATE ROLE authenticated")
        pgc.execute(sql.getvalue())
        pgc.execute(sql.getvalue())                                   # twice: rows already there are skipped
        pgc.execute("SET search_path TO squidbrake")
        assert pgc.execute("SELECT company, page_views FROM pilots").fetchall() == [("O'Neil & Co", 3)]
        assert pgc.execute("SELECT note FROM team_requests").fetchall() == [("100% sure; ?",)]
        assert pgc.execute("SELECT count(*) FROM catches").fetchone()[0] == 1     # no key, run twice: not doubled
        pgc.execute("INSERT INTO team_requests (created_at, name) VALUES ('2026-10-03', 'Ben')")   # counter moved on
        assert pgc.execute("SELECT max(id) FROM team_requests").fetchone()[0] == 2
        assert pgc.execute("SELECT bool_and(rowsecurity) FROM pg_tables WHERE schemaname='squidbrake'").fetchone()[0]
