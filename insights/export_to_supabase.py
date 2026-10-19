"""
Everything in the insights SQLite database, as one SQL file for your Supabase project: the tables (in their own
schema, row level security on), every row, and the id counters moved past the copied rows. Safe to run twice: rows
already there are skipped.

  python export_to_supabase.py [path/to/insights.db] > supabase_import.sql
  then: Supabase > SQL Editor > paste > Run   (or: psql "$INSIGHTS_DATABASE_URL" -f supabase_import.sql)
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys

from pg import translate

SCHEMA = os.getenv("INSIGHTS_PG_SCHEMA", "squidbrake")


def literal(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, bytes):
        v = v.decode("utf-8", errors="replace")
    return "'" + str(v).replace("\x00", "").replace("'", "''") + "'"


def export(path: str, out=sys.stdout) -> None:
    src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    w = lambda s: out.write(s + "\n")
    w(f"BEGIN;\nCREATE SCHEMA IF NOT EXISTS {SCHEMA};\nSET search_path TO {SCHEMA};")
    tables = src.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                         "ORDER BY name").fetchall()
    for name, ddl in tables:
        w(translate(re.sub(r"(?i)^CREATE TABLE (IF NOT EXISTS )?", "CREATE TABLE IF NOT EXISTS ", ddl), False) + ";")
    for (ddl,) in src.execute("SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"):
        w(re.sub(r"(?i)^CREATE INDEX (IF NOT EXISTS )?", "CREATE INDEX IF NOT EXISTS ", ddl) + ";")
    for name, ddl in tables:
        cur = src.execute(f'SELECT * FROM "{name}"')
        cols = ", ".join(d[0] for d in cur.description)
        while rows := cur.fetchmany(500):
            w(f"INSERT INTO {name} ({cols}) VALUES\n" + ",\n".join(
                "(" + ", ".join(literal(v) for v in r) + ")" for r in rows) + "\nON CONFLICT DO NOTHING;")
        if re.search(r"(?i)\bid INTEGER PRIMARY KEY AUTOINCREMENT", ddl):
            w(f"SELECT setval(pg_get_serial_sequence('{SCHEMA}.{name}', 'id'), COALESCE((SELECT MAX(id) FROM {name}), 0) + 1, false);")
    w("""DO $$ DECLARE t text; BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = current_schema() LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON %I FROM anon, authenticated', t);
  END LOOP; END $$;
COMMIT;""")


if __name__ == "__main__":
    export(sys.argv[1] if len(sys.argv) > 1 else os.getenv("INSIGHTS_DB", "data/insights.db"))
