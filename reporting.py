"""Local reporting policy and identity shared by the CLI and gateway.

SQLite serializes sends and settings changes across threads/processes. An `off`
command waits for an in-flight send, then prevents subsequent sends. No customer
operational data or account credentials belong in this database.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path


def data_dir() -> Path:
    if os.getenv("KEYS_PATH"):
        return Path(os.environ["KEYS_PATH"]).resolve().parent
    here = Path(__file__).resolve().parent
    home = Path(os.getenv("SQUIDBRAKE_HOME") or
                (Path.home() / ".squidbrake" if (here / "__init__.py").exists() else here))
    return home / "data"


def cli_path() -> Path:
    # Preserve the existing CLI settings location, including source checkouts.
    return Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake") / "telemetry.json"


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("expected a settings object")
        return value
    except FileNotFoundError:
        return {}


def environment_off() -> bool:
    return (os.getenv("SQUIDBRAKE_TELEMETRY", "").strip().lower() in {"0", "false", "off", "no"}
            or os.getenv("DO_NOT_TRACK", "").strip().lower() in {"1", "true", "yes"}
            or bool(os.getenv("CI")))


def _validate(state):
    if not isinstance(state, dict) or any(
            key in state and not isinstance(state[key], bool)
            for key in ("usage", "contact", "diagnostics", "pilot_left")):
        raise ValueError("invalid reporting preferences")
    if "identity" in state and not isinstance(state["identity"], dict):
        raise ValueError("invalid reporting identity")
    return state


def _snapshot(home: Path | None = None) -> dict:
    path = (home if home is not None else data_dir()) / "reporting.db"
    if not path.exists():
        return {}
    # Read committed preferences without waiting for a network send's write lock.
    # The actual transport still takes permit() and checks again under that lock.
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0)
    try:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE name='reporting_state'").fetchone()
        row = conn.execute("SELECT value FROM reporting_state WHERE id=1").fetchone() if tables else None
        return _validate(json.loads(row[0]) if row else {})
    finally:
        conn.close()


@contextmanager
def transaction(home: Path | None = None):
    home = home if home is not None else data_dir()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "reporting.db"
    # Permission applies on initial creation too; never truncate another writer.
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    conn = sqlite3.connect(path, timeout=30)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS reporting_state (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        row = conn.execute("SELECT value FROM reporting_state WHERE id=1").fetchone()
        state = _validate(json.loads(row[0]) if row else {})
        yield state
        conn.execute("INSERT OR REPLACE INTO reporting_state VALUES (1, ?)", (json.dumps(state),))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def allowed(state: dict, channel: str = "usage") -> bool:
    # Read legacy refusal on every send, so an upgrade never reverses an old no.
    legacy = read_json(cli_path())
    return (not environment_off() and state.get("usage", True)
            and legacy.get("enabled") is not False
            and (channel == "usage" or state.get(channel, False)))


@contextmanager
def permit(home: Path | None = None, channel: str = "usage"):
    if environment_off():
        yield False
        return
    with transaction(home) as state:
        yield allowed(state, channel)


def enabled(home: Path | None = None, channel: str = "usage") -> bool:
    try:
        return not environment_off() and allowed(_snapshot(home), channel)
    except (OSError, ValueError, sqlite3.Error):
        return False                     # reporting failures never enable a send


def identity(home: Path | None = None, cli_id: str | None = None, pilot_id: str | None = None) -> dict:
    home = home if home is not None else data_dir()
    try:
        mine = _snapshot(home).get("identity", {})
    except sqlite3.OperationalError as e:
        if "locked" not in str(e):
            raise
        mine = {}                          # concurrent initialization: use the serialized path
    cli_id = cli_id or read_json(cli_path()).get("id") or mine.get("legacy_cli_id")
    pilot_id = pilot_id or read_json(home / "pilot.json").get("install_id") or mine.get("legacy_pilot_id")
    if (mine.get("installation_id") and (not cli_id or mine.get("legacy_cli_id"))
            and (not pilot_id or mine.get("legacy_pilot_id"))):
        return dict(mine)
    with transaction(home) as state:
        mine = state.setdefault("identity", {})
        cli_id = cli_id or read_json(cli_path()).get("id") or mine.get("legacy_cli_id")
        pilot_id = pilot_id or read_json(home / "pilot.json").get("install_id") or mine.get("legacy_pilot_id")
        if "installation_id" not in mine:
            for candidate in (pilot_id, cli_id):
                try:
                    mine["installation_id"] = uuid.UUID(str(candidate)).hex
                    break
                except (ValueError, AttributeError):
                    pass
            else:
                mine["installation_id"] = uuid.uuid4().hex
        # Legacy IDs stay unchanged at their existing destinations; retain aliases
        # locally until the versioned collector can accept an explicit mapping.
        if cli_id:
            mine.setdefault("legacy_cli_id", cli_id)
        if pilot_id:
            mine.setdefault("legacy_pilot_id", pilot_id)
        return dict(mine)


def automatic_join_allowed(home: Path | None = None) -> bool:
    try:
        state = _snapshot(home)
        return allowed(state) and not state.get("pilot_left", False)
    except (OSError, ValueError, sqlite3.Error):
        return False


def dataset_epoch(engine, rotate: bool = False) -> str:
    """An epoch belongs to the operational DB, not a process or reporting install.

    A new database gets a new epoch. Independent restored/cloned gateways must
    explicitly rotate before reporting; replicas sharing a DB keep the same epoch.
    """
    from sqlalchemy import Column, MetaData, String, Table, Text, select
    from sqlalchemy.dialects import postgresql, sqlite
    table = Table("gateway_state", MetaData(), Column("key", String, primary_key=True), Column("value", Text))
    key, fresh = "reporting_dataset_epoch", uuid.uuid4().hex
    dialect = postgresql if engine.dialect.name == "postgresql" else sqlite
    insert = dialect.insert(table).values(key=key, value=json.dumps(fresh))
    statement = (insert.on_conflict_do_update(index_elements=["key"], set_={"value": insert.excluded.value})
                 if rotate else insert.on_conflict_do_nothing(index_elements=["key"]))
    with engine.begin() as conn:
        conn.execute(statement)
        return json.loads(conn.execute(select(table.c.value).where(table.c.key == key)).scalar_one())
