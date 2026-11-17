"""
Database tools for AI agents (Claude Code, Claude Desktop, Antigravity, Cursor, ...) over MCP,
where every tool call goes through Squidbrake first.

  - reads run and are recorded
  - writes (UPDATE / DELETE / INSERT / ALTER) wait for a human to approve them in the dashboard
  - DROP / TRUNCATE are blocked
  (exactly which is decided by rules.yaml on the gateway)

Settings (environment variables, set in the agent's MCP config): GATEWAY_URL, GATEWAY_API_KEY,
GATEWAY_SOURCE, APPROVAL_WAIT (see gw_async.py), plus
  DB_PATH           SQLite file to work on             default data/shop.db (created with sample data)

Run by hand to check it starts:  python gateway_mcp.py   (it then waits for an MCP client on stdin)
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer

import gw_async as gw
from gw_async import log

BASE_DIR = Path(__file__).resolve().parent
HOME_DIR = Path(os.getenv("SQUIDBRAKE_HOME") or  # same place as server.py: ~/.squidbrake when installed with pip
                (Path.home() / ".squidbrake" if (BASE_DIR / "__init__.py").exists() else BASE_DIR))
DB_PATH = Path(os.getenv("DB_PATH", HOME_DIR / "data" / "shop.db"))
MAX_ROWS = 200


# --------------------------------------------------------------------------- sample database

def seed_sample_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(42)
    first = ["Aarav", "Maya", "Liam", "Sofia", "Noah", "Zara", "Ethan", "Priya", "Lucas", "Amara", "Kenji", "Elena",
             "Omar", "Chloe", "Rohan", "Isla", "Mateo", "Hana", "Leo", "Nia"]
    last = ["Sharma", "Chen", "Garcia", "Muller", "Okafor", "Kim", "Rossi", "Patel", "Silva", "Novak"]
    countries = ["IN", "US", "DE", "BR", "GB", "JP", "NG", "FR"]
    products = [("Starter plan", 19), ("Pro plan", 49), ("Team plan", 199), ("API credits 10k", 25),
                ("API credits 100k", 200), ("Priority support", 99), ("Onboarding session", 150),
                ("Extra seat", 12), ("Data export add-on", 30), ("SSO add-on", 80)]
    now = datetime.now(timezone.utc)
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
                                country TEXT, plan TEXT, discount_pct INTEGER DEFAULT 0, created_at TEXT);
        CREATE TABLE products  (id INTEGER PRIMARY KEY, name TEXT NOT NULL, price REAL NOT NULL, active INTEGER DEFAULT 1);
        CREATE TABLE orders    (id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers(id),
                                product_id INTEGER REFERENCES products(id), quantity INTEGER, total REAL,
                                status TEXT, created_at TEXT);
    """)
    con.executemany("INSERT INTO products (name, price) VALUES (?, ?)", products)
    for i in range(1, 51):
        name = f"{rnd.choice(first)} {rnd.choice(last)}"
        con.execute("INSERT INTO customers (name, email, country, plan, created_at) VALUES (?, ?, ?, ?, ?)",
                    (name, f"{name.lower().replace(' ', '.')}{i}@example.com", rnd.choice(countries),
                     rnd.choice(["free", "starter", "pro", "team"]),
                     (now - timedelta(days=rnd.randint(30, 700))).date().isoformat()))
    for _ in range(400):
        pid = rnd.randint(1, len(products))
        qty = rnd.choice([1, 1, 1, 2, 3, 5])
        con.execute("INSERT INTO orders (customer_id, product_id, quantity, total, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (rnd.randint(1, 50), pid, qty, products[pid - 1][1] * qty,
                     rnd.choices(["paid", "refunded", "pending", "failed"], [80, 6, 10, 4])[0],
                     (now - timedelta(days=rnd.randint(0, 365), minutes=rnd.randint(0, 1440))).isoformat(timespec="seconds")))
    con.commit()
    con.close()
    log(f"created sample database {path} (customers, products, orders)")


def read_conn() -> sqlite3.Connection:
    # Read-only at the SQLite level: `query` can never change data, whatever SQL it is given.
    return sqlite3.connect(f"{DB_PATH.resolve().as_uri()}?mode=ro", uri=True)


def rows_result(cur: sqlite3.Cursor) -> dict:
    cols = [d[0] for d in cur.description or []]
    rows = cur.fetchmany(MAX_ROWS + 1)
    return {"columns": cols, "rows": [list(r) for r in rows[:MAX_ROWS]], "truncated": len(rows) > MAX_ROWS}


# --------------------------------------------------------------------------- tools

async def _report(event_id: str, outcome) -> str:
    status, value, ms = outcome
    if status == "error":
        await gw.gw_result(event_id, error=value, duration_ms=ms)
        return f"ERROR: {value}"
    await gw.gw_result(event_id, output=value, duration_ms=ms)
    return json.dumps(value, default=str)


def _list_tables(_: dict):
    with read_conn() as con:
        names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {n: con.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in names}


def _describe_table(a: dict):
    table = a["table"]
    with read_conn() as con:
        cols = [{"name": c[1], "type": c[2], "not_null": bool(c[3]), "primary_key": bool(c[5])}
                for c in con.execute("SELECT * FROM pragma_table_info(?)", (table,))]
        if not cols:
            raise ValueError(f"no table named '{table}'")
        sample = rows_result(con.execute(f'SELECT * FROM "{table.replace(chr(34), "")}" LIMIT 5'))
        return {"table": table, "columns": cols, "sample": sample}


def _query(a: dict):
    with read_conn() as con:
        return rows_result(con.execute(a["sql"]))


def _execute(a: dict):
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.execute(a["sql"])
        con.commit()
        return {"rows_affected": cur.rowcount if cur.rowcount >= 0 else None}
    finally:
        con.close()


# What each tool does, by the name the gateway sees; also used to finish a call approved after a restart.
ACTIONS = {"db.list_tables": _list_tables, "db.describe_table": _describe_table,
           "db.query": _query, "db.execute": _execute}


def replay(call: dict):
    fn, args = ACTIONS[call["tool"]], call.get("args") or {}

    async def run():
        return await asyncio.to_thread(fn, args)
    return run


async def guarded(name: str, input: dict) -> str:
    call = {"tool": name, "args": input}
    return await gw.guard(name, input, replay(call), on_done=_report, on_text=lambda t: t, call=call)


gw.set_replay(replay)
server = MCPServer(
    "squidbrake-db",
    instructions="SQLite database tools. Reads run immediately; data changes need a person to approve them. " + gw.agent_rules(),
)


@server.tool()
async def list_tables() -> str:
    """List the tables in the database with their row counts."""
    return await guarded("db.list_tables", {})


@server.tool()
async def describe_table(table: str) -> str:
    """Show a table's columns and 5 example rows."""
    return await guarded("db.describe_table", {"table": table})


@server.tool()
async def query(sql: str) -> str:
    """Run a read-only SQL query (SELECT / WITH). Returns up to 200 rows as JSON. Use execute to change data."""
    return await guarded("db.query", {"sql": sql})


@server.tool()
async def execute(sql: str) -> str:
    """Run ONE SQL statement that changes data or schema (INSERT, UPDATE, DELETE, CREATE, ALTER, ...).
    Squidbrake may hold it for human approval or block it."""
    return await guarded("db.execute", {"sql": sql})


@server.tool(name=gw.DECISIONS_TOOL, description=gw.DECISIONS_HELP)
async def gateway_recent_decisions() -> str:
    return await gw.recent_decisions()


@server.tool(name=gw.ASK_TOOL, description=gw.ASK_HELP)
async def gateway_ask_user(question: str = "", event_id: str = "") -> str:
    return await gw.ask_user(question, event_id or None)


@server.tool(name=gw.CHECK_TOOL)
async def gateway_check_approval(event_id: str) -> str:
    """Finish a call that was WAITING FOR HUMAN APPROVAL: runs it if approved, reports if rejected,
    or keeps waiting a little longer."""
    return await gw.check_approval(event_id, on_done=_report, on_text=lambda t: t)


def main() -> None:
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per gateway call is just noise
    gw.cleanup_pending()
    if not DB_PATH.exists():
        seed_sample_db(DB_PATH)
    if not gw.GATEWAY_API_KEY:
        log("warning: GATEWAY_API_KEY is not set; the gateway will reject calls unless auth is off")
    log(f"database {DB_PATH} -> gateway {gw.GATEWAY_URL} as '{gw.SOURCE}' (session {gw.SESSION})")
    server.run("stdio")


if __name__ == "__main__":
    main()
