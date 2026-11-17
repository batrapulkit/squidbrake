"""squidbrake import-sqlite: an old gateway.db copied into an empty database (Postgres in the CI job, else another
SQLite file) keeps every row and an audit chain that verifies, refuses a second copy, and new entries carry on after it."""
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRITE = ("import server, json\n"
         "with server.audited_tx() as conn:\n"
         "    conn.execute(server.events.insert().values(id='ev-1', created_at=server.utcnow(), name='Bash', status='denied',\n"
         "                 input=json.dumps({'command': 'rm -rf ~/'})))\n"
         "    for i in range(30):\n"
         "        server.audit(conn, 'old-gateway', 'test.entry', str(i))\n")
NEXT = ("import server\n"
        "with server.audited_tx() as conn:\n"
        "    server.audit(conn, 'new-gateway', 'test.after-import', None)\n")


def run(env: dict, *args: str) -> subprocess.CompletedProcess:
    base = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "DB_SCHEMA", "TEST_DATABASE_URL")}
    return subprocess.run([sys.executable, *args], cwd=ROOT, env={**base, **env, "PYTHONPATH": str(ROOT)},
                          capture_output=True, text=True, timeout=180)


def test_an_old_gateway_db_moves_with_its_chain():
    tmp = Path(tempfile.mkdtemp())
    old = {"DATABASE_URL": f"sqlite:///{(tmp / 'old.db').as_posix()}"}
    assert run(old, "-c", WRITE).returncode == 0
    if os.getenv("TEST_DATABASE_URL"):        # a schema of its own in the Postgres the CI job gives
        new = {"DATABASE_URL": os.environ["TEST_DATABASE_URL"], "DB_SCHEMA": f"import_{uuid.uuid4().hex[:8]}"}
    else:
        new = {"DATABASE_URL": f"sqlite:///{(tmp / 'new.db').as_posix()}"}
    first = run(new, "server.py", "import-sqlite", str(tmp / "old.db"))
    assert first.returncode == 0, first.stdout + first.stderr
    assert "audit_log" in first.stdout and "30 rows" in first.stdout and "intact, 30 entries" in first.stdout
    again = run(new, "server.py", "import-sqlite", str(tmp / "old.db"))
    assert again.returncode != 0 and "already has a record" in again.stdout + again.stderr
    assert run(new, "-c", NEXT).returncode == 0                       # numbering carries on after the copied entries
    check = run(new, "server.py", "audit", "verify")
    assert check.returncode == 0 and "Intact: 31 entries" in check.stdout, check.stdout + check.stderr
