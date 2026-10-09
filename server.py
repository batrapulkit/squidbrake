"""
Squidbrake - a 24/7 server that every tool call / action goes through.

Every request is checked against the rules in rules.yaml (allow / deny / review),
recorded to the database, and logged as a JSON line to stdout. `review` holds the call
until a human approves or rejects it (or its timeout passes).

Two ways for clients to route through it:

  1. Event API (any language, any tool):
       POST /v1/events               -> "may I run tool X with input Y?"  => allow/deny + event_id
       POST /v1/events/{id}/result   -> report the output / error afterwards

  2. HTTP proxy (zero client code changes, just swap the base URL):
       ANY  /proxy/{upstream}/{path} -> checked, recorded, forwarded to the upstream in rules.yaml

Browse the history at /dashboard.

Run:        python server.py                (or start.bat / ./start.sh, which also install dependencies)
Keys:       python server.py add-key NAME [--approver] | remove-key NAME | keys
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("Squidbrake needs Python 3.10 or newer: https://www.python.org/downloads/")

import argparse
import base64
import asyncio
import fnmatch
import hashlib
import hmac
import json
import logging
import operator
import os
import re
import secrets
import threading
import time
import uuid
import webbrowser
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, Float, Integer, MetaData, String, Table, Text, case, create_engine, delete, event as sa_event,
    and_, func, inspect as sa_inspect, or_, select, text, true, update,
)

import commands
import evidence
import lockdown
import mcp_catalog
import mcp_hub
import mcp_oauth
import outbound
import pilot
import policy_edit
import risk
import siem
import taint
import verify

# --------------------------------------------------------------------------- config

# Defaults live next to this file, so it doesn't matter which folder you start it from.
# Installed with pip (the package has an __init__.py), they live in ~/.squidbrake instead.
BASE_DIR = Path(__file__).resolve().parent
HOME_DIR = Path(os.getenv("SQUIDBRAKE_HOME") or
                (Path.home() / ".squidbrake" if (BASE_DIR / "__init__.py").exists() else BASE_DIR))

# Every setting is optional. A .env file there is picked up automatically.
try:
    from dotenv import load_dotenv
    load_dotenv(HOME_DIR / ".env")
except ImportError:
    pass


def _default_rules() -> Path:
    """rules.yaml in HOME_DIR; a pip install starts from a copy of the shipped one, which you then edit."""
    path = HOME_DIR / "rules.yaml"
    if (BASE_DIR / "rules.yaml").exists() and HOME_DIR != BASE_DIR:
        if not path.exists():
            HOME_DIR.mkdir(parents=True, exist_ok=True)
            path.write_bytes((BASE_DIR / "rules.yaml").read_bytes())
        else:
            update_unedited_rules(path, BASE_DIR / "rules.yaml", BASE_DIR / "rules.shipped")
    return path


def update_unedited_rules(path: Path, shipped: Path, known: Path) -> bool:
    """A rules.yaml copied from an older release and never edited gets this release's rules (the old file is kept
    as a backup). An edited one is left alone. `known` lists the sha256 of every rules.yaml ever shipped."""
    import hashlib
    digest = lambda b: hashlib.sha256(b.replace(b"\r\n", b"\n")).hexdigest()
    mine, current = path.read_bytes(), shipped.read_bytes()
    if digest(mine) == digest(current) or not known.exists() or digest(mine) not in known.read_text(encoding="utf-8"):
        return False
    backup = path.with_name(f"rules.yaml.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    backup.write_bytes(mine)
    path.write_bytes(current)
    print(f"Squidbrake: updated {path} to this version's rules (you hadn't edited it). The old one is {backup.name}.",
          file=sys.stderr)
    return True


DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(HOME_DIR / 'data' / 'gateway.db').as_posix()}")
KEYS_PATH = Path(os.getenv("KEYS_PATH", HOME_DIR / "data" / "keys.json"))
PILOT_DIR = KEYS_PATH.parent          # pilot.json (squidbrake pilot join) lives with the keys: writable, also in Docker
AUTH_DISABLED = os.getenv("GATEWAY_AUTH", "on").strip().lower() in ("off", "disabled", "false", "0", "no")
IN_DOCKER = bool(os.getenv("IN_DOCKER"))
RULES_PATH = Path(os.getenv("RULES_PATH") or _default_rules())
MAX_PAYLOAD_CHARS = int(os.getenv("MAX_PAYLOAD_CHARS", "65536"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0"))  # 0 = keep forever
PROXY_TIMEOUT = float(os.getenv("PROXY_TIMEOUT", "60"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("squidbrake")
    except Exception:
        m = re.search(r'__version__ = "([^"]+)"', (BASE_DIR / "squidbrake" / "__init__.py").read_text()
                      if (BASE_DIR / "squidbrake" / "__init__.py").exists() else "")
        return m.group(1) if m else "dev"


VERSION = _version()


def _parse_api_keys(raw: str) -> dict[str, str]:
    """GATEWAY_API_KEYS="agent-a:secret1,ci-bot:secret2" -> {secret: name}"""
    keys: dict[str, str] = {}
    for item in filter(None, (p.strip() for p in raw.split(","))):
        name, _, secret = item.partition(":")
        if not secret:
            name, secret = "default", name
        keys[secret] = name
    return keys


APPROVAL_TIMEOUT = int(os.getenv("APPROVAL_TIMEOUT", "300"))  # default seconds a call waits for a human
APPROVAL_WEBHOOK_URL = os.getenv("APPROVAL_WEBHOOK_URL", "")   # e.g. a Slack incoming webhook
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")           # used for links in webhook messages
# Key names that can look at everything they're allowed to see but never change anything, e.g. an auditor
# or a public demo key: READ_ONLY_KEYS="auditor,visitor"
READ_ONLY_KEYS = {k.strip() for k in os.getenv("READ_ONLY_KEYS", "").split(",") if k.strip()}

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("gateway")
audit_log = logging.getLogger("gateway.audit")

# --------------------------------------------------------------------------- keys

KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _file_sig(path: Path) -> tuple[int, int, int] | None:
    """What a hot-reloaded file's reload is keyed on; None if it's missing. mtime alone misses a second write
    in the same clock tick (common on Windows), so size and inode (new on every os.replace) count too."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    return st.st_mtime_ns, st.st_size, st.st_ino


class KeyStore:
    """Who may call the gateway, and who may approve.

    Keys come from GATEWAY_API_KEYS / GATEWAY_APPROVERS if those are set, otherwise from
    data/keys.json, which is created on first start and managed with `python server.py add-key`.
    keys.json holds only SHA-256 hashes; a secret is shown once, when it is created.
    It is re-read when it changes, so adding or removing a key needs no restart."""

    # A key is either a *person* (can open the dashboard; may approve; may have roles such as
    # "admin" or "finance") or an *agent* (can only ask for permission and report results).

    def __init__(self, path: Path, env_keys: str = "", env_approvers: str = "", disabled: bool = False):
        self.path, self.disabled = path, disabled
        self.from_env = bool(env_keys.strip())
        self._lock = threading.Lock()
        self._sig: tuple | None = ()  # never equal to a real signature or None
        self._by_hash: dict[str, str] = {}
        self._info: dict[str, dict] = {}
        self.approvers: set[str] = set()
        if self.from_env:
            self._by_hash = {_hash(s): n for s, n in _parse_api_keys(env_keys).items()}
            self.approvers = {n.strip() for n in env_approvers.split(",") if n.strip()}
            # Env-configured keys predate teams: everyone may view, approvers are admins.
            self._info = {n: {"kind": "person", "approver": n in self.approvers,
                              "roles": ["admin"] if n in self.approvers else []} for n in self._by_hash.values()}

    @staticmethod
    def _normalize(name: str, k: dict) -> dict:
        approver = bool(k.get("approver"))
        roles = k.get("roles")
        if roles is None:  # keys.json from before teams existed
            roles = ["admin"] if name == "admin" and approver else []
        return {"kind": k.get("kind") or ("person" if approver else "agent"), "approver": approver,
                "roles": list(roles), "owner": k.get("owner"), "created_at": k.get("created_at")}

    @property
    def enabled(self) -> bool:
        return not self.disabled

    def _maybe_reload(self) -> None:
        if self.from_env or self.disabled:
            return
        sig = _file_sig(self.path)
        if sig == self._sig:
            return
        with self._lock:
            try:
                keys = self._read()["keys"]
                self._by_hash = {k["sha256"]: name for name, k in keys.items()}
                self._info = {name: self._normalize(name, k) for name, k in keys.items()}
                self.approvers = {name for name, i in self._info.items() if i["approver"]}
            except Exception:
                log.exception("failed to read %s, keeping previous keys", self.path)
            self._sig = sig

    def identify(self, secret: str) -> str | None:
        if self.disabled:
            return "anonymous"
        self._maybe_reload()
        return self._by_hash.get(_hash(secret)) if secret else None

    def can_approve(self, name: str) -> bool:
        if self.disabled:
            return True
        self._maybe_reload()
        return name in self.approvers

    def names(self) -> set[str]:
        self._maybe_reload()
        return set(self._by_hash.values())

    def info(self, name: str) -> dict:
        if self.disabled:
            return {"kind": "person", "approver": True, "roles": ["admin"], "created_at": None}
        self._maybe_reload()
        return self._info.get(name) or {"kind": "agent", "approver": False, "roles": [], "created_at": None}

    def is_person(self, name: str) -> bool:
        return self.info(name)["kind"] == "person"

    def is_admin(self, name: str) -> bool:
        return "admin" in self.info(name)["roles"]

    def matches(self, name: str, allowed: list[str]) -> bool:
        """Rule `approvers:` entries are key names or `role:NAME`."""
        roles = set(self.info(name)["roles"])
        return any(a == name or (a.startswith("role:") and a[5:] in roles) for a in allowed)

    # ---- keys.json management (used by the CLI)
    def _read(self) -> dict:
        if not self.path.exists():
            return {"keys": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def _guard_env(self) -> None:
        if self.from_env:
            raise ValueError("keys come from the GATEWAY_API_KEYS setting; edit that instead")

    @staticmethod
    def _clean_roles(roles: list[str] | None) -> list[str]:
        out = []
        for r in roles or []:
            r = r.strip().lower()
            if r and not re.fullmatch(r"[a-z0-9_-]{1,32}", r):
                raise ValueError(f"role '{r}': use lowercase letters, digits, '-' or '_'")
            if r and r not in out:
                out.append(r)
        return out

    def add(self, name: str, approver: bool = False, kind: str | None = None, roles: list[str] | None = None,
            owner: str | None = None) -> str:
        self._guard_env()
        if not KEY_NAME_RE.match(name):
            raise ValueError("use letters, digits, '.', '_', '-' or '@' (max 64), e.g. 'alice' or 'billing-agent'")
        kind = kind or ("person" if approver else "agent")
        if kind not in ("person", "agent"):
            raise ValueError("kind must be 'person' or 'agent'")
        if kind == "agent" and (approver or roles):
            raise ValueError("agents can't approve or have roles; make it a person instead")
        data = self._read()
        if name in data["keys"]:
            raise ValueError(f"a key named '{name}' already exists (remove it first to replace it)")
        owner = self._check_owner(data, kind, owner)
        secret = "gw_" + secrets.token_urlsafe(24)
        data["keys"][name] = {"sha256": _hash(secret), "kind": kind, "approver": approver,
                              "roles": self._clean_roles(roles), "created_at": utcnow()}
        if owner:
            data["keys"][name]["owner"] = owner
        self._write(data)
        return secret

    def _check_owner(self, data: dict, kind: str, owner: str | None) -> str | None:
        """An agent's owner is the person it works for (it runs on their laptop). With second-person
        approval on, the owner can't approve what their own agent asks for."""
        if not owner:
            return None
        if kind != "agent":
            raise ValueError("only an agent has an owner")
        k = data["keys"].get(owner)
        if k is None or self._normalize(owner, k)["kind"] != "person":
            raise ValueError(f"owner '{owner}' must be an existing person key")
        return owner

    def update(self, name: str, approver: bool | None = None, roles: list[str] | None = None,
               owner: str | None = None) -> dict:
        self._guard_env()
        data = self._read()
        if name not in data["keys"]:
            raise ValueError(f"no key named '{name}'")
        k = data["keys"][name]
        current = self._normalize(name, k)
        if current["kind"] == "agent" and (approver or roles):
            raise ValueError("agents can't approve or have roles")
        k.update(kind=current["kind"], approver=current["approver"] if approver is None else approver,
                 roles=current["roles"] if roles is None else self._clean_roles(roles))
        if owner == "":
            k.pop("owner", None)
        elif owner is not None:
            k["owner"] = self._check_owner(data, current["kind"], owner)
        self._write(data)
        return self._normalize(name, k)

    def remove(self, name: str) -> None:
        self._guard_env()
        data = self._read()
        if name not in data["keys"]:
            raise ValueError(f"no key named '{name}'")
        del data["keys"][name]
        self._write(data)

    def listing(self) -> list[dict]:
        if self.from_env:
            return [{"name": n, **self._info[n]} for n in sorted(self._info)]
        return [{"name": n, **self._normalize(n, k)} for n, k in sorted(self._read()["keys"].items())]

    def ensure_initialized(self) -> dict[str, str] | None:
        """First start: create an 'admin' key (can approve) and an 'agent' key. Returns the new
        secrets, or None if keys already exist. Safe if several workers start at once."""
        if self.from_env or self.disabled or self.path.exists():
            return None
        created = {"admin": "gw_" + secrets.token_urlsafe(24), "agent": "gw_" + secrets.token_urlsafe(24)}
        now = utcnow()
        data = {"keys": {
            "admin": {"sha256": _hash(created["admin"]), "kind": "person", "approver": True,
                      "roles": ["admin"], "created_at": now},
            "agent": {"sha256": _hash(created["agent"]), "kind": "agent", "approver": False,
                      "roles": [], "created_at": now},
        }}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # first process wins
        except FileExistsError:
            return None
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return created


keystore = KeyStore(KEYS_PATH, os.getenv("GATEWAY_API_KEYS", ""), os.getenv("GATEWAY_APPROVERS", ""), AUTH_DISABLED)

# --------------------------------------------------------------------------- storage

if DATABASE_URL.startswith("sqlite:///"):
    Path(DATABASE_URL.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 30})

    @sa_event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")  # concurrent readers + one writer, safe across workers
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)

metadata = MetaData()
events = Table(
    "events", metadata,
    Column("id", String(36), primary_key=True),
    Column("created_at", String(32), nullable=False, index=True),  # ISO-8601 UTC, sorts lexically
    Column("completed_at", String(32)),
    Column("client", String(200), index=True),      # API-key name that sent it
    Column("client_ip", String(64)),
    Column("source", String(200), index=True),      # agent / service / machine name
    Column("session_id", String(200), index=True),
    Column("kind", String(100), index=True),        # tool_call | action | http_request | ...
    Column("name", String(500), index=True),        # tool name, e.g. "shell.exec"
    Column("status", String(20), index=True),       # awaiting_approval | pending | completed | failed | denied
    Column("decision", String(10)),                 # allow | deny | review (while awaiting a human)
    Column("rule_id", String(200)),
    Column("reason", Text),
    Column("input", Text),
    Column("output", Text),
    Column("error", Text),
    Column("metadata", Text),
    Column("duration_ms", Float),
    # human approval (only set for calls held by a `review` rule)
    Column("approval_deadline", String(32)),
    Column("approval_on_timeout", String(10)),      # allow | deny
    Column("approvers", Text),                      # JSON list of key names, null = any approver
    Column("decided_by", String(200)),              # approver key name, or "timeout"
    Column("decided_at", String(32)),
    Column("decision_note", Text),
    Column("signals", Text),                        # JSON list of history-check findings (see history_signals)
    Column("would", String(10)),                    # shadow mode: what would have happened (deny | review), then allowed
    Column("risk", Integer),                        # risk.py's 0..100 score: recorded, never used to decide
    Column("risk_why", Text),                       # JSON list of what made the score
)

# Small key/value store for state all workers share: the emergency stop and notification settings.
gateway_state = Table(
    "gateway_state", metadata,
    Column("key", String(100), primary_key=True),
    Column("value", Text),
)

# Append-only, hash-chained record of everything that happened. Each entry's hash covers the previous
# entry's hash, so editing or deleting any past entry breaks every hash after it (see /v1/audit/verify).
audit_trail = Table(
    "audit_log", metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("at", String(32), nullable=False),
    Column("actor", String(200)),
    Column("action", String(50), nullable=False),
    Column("target", String(200)),
    Column("detail", Text),
    Column("prev_hash", String(64), nullable=False, unique=True),  # a fork can't be written silently
    Column("hash", String(64), nullable=False),
)
GENESIS = verify.GENESIS

# Every version of rules.yaml that made a decision, so any decision can be traced to the exact rules behind it.
policy_versions = Table(
    "policy_versions", metadata,
    Column("fingerprint", String(16), primary_key=True),
    Column("first_seen", String(32), nullable=False),
    Column("content", Text, nullable=False),
)


def migrate(eng) -> None:
    """Create the table, and add any columns missing from a database made by an older version."""
    metadata.create_all(eng)
    existing = {c["name"] for c in sa_inspect(eng).get_columns("events")}
    with eng.begin() as conn:
        for col in events.columns:
            if col.name not in existing:
                conn.execute(text(f"ALTER TABLE events ADD COLUMN {col.name} {col.type.compile(eng.dialect)}"))
                log.info("migrated: added column events.%s", col.name)


migrate(engine)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- audit trail + shared state

_write_lock = threading.RLock()


@contextmanager
def audited_tx():
    """A write transaction that may append to the audit trail. Writes are serialized so the hash
    chain stays linear: in-process with a lock, across processes with a Postgres advisory lock.
    (With SQLite, run a single worker process - the default.)"""
    with _write_lock, engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(7355608)"))
        yield conn


def _sha(obj: Any) -> str | None:
    return None if obj is None else hashlib.sha256(str(obj).encode()).hexdigest()


_entry_hash = verify.entry_hash   # one definition, shared with the offline checker


def audit(conn, actor: str | None, action: str, target: str | None, **detail) -> None:
    """Append to the hash chain inside the caller's audited_tx()."""
    prev = conn.execute(select(audit_trail.c.hash).order_by(audit_trail.c.seq.desc()).limit(1)).scalar() or GENESIS
    at, d = utcnow(), json.dumps(detail, sort_keys=True, default=str, ensure_ascii=False)
    conn.execute(audit_trail.insert().values(at=at, actor=actor, action=action, target=target, detail=d,
                                             prev_hash=prev, hash=_entry_hash(prev, at, actor, action, target, d)))


def verify_audit_chain() -> dict:
    """The hash chain, plus: do the recorded actions still match the fingerprints taken when they happened?"""
    with engine.connect() as conn:
        entries = [dict(r._mapping) for r in conn.execute(select(audit_trail).order_by(audit_trail.c.seq)).all()]
        rows = {r.id: {"id": r.id, "input": r.input, "output": r.output}
                for r in conn.execute(select(events.c.id, events.c.input, events.c.output)).all()}
    result = verify.check_chain(entries)
    changed = verify.check_events(entries, rows)["changed"] if result["ok"] else []
    if changed:
        result.update(ok=False, head_hash=result["head_hash"], events_changed=changed,
                      message=f"the chain is intact, but {len(changed)} recorded action(s) were edited in the database "
                              f"afterwards (first: {changed[0]['event']}, {changed[0]['field']})")
    return result


def state_get(key: str, default: Any = None) -> Any:
    with engine.connect() as conn:
        v = conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == key)).scalar()
    return default if v is None else json.loads(v)


def state_set(conn, key: str, value: Any) -> None:
    v = json.dumps(value)
    if conn.execute(update(gateway_state).where(gateway_state.c.key == key).values(value=v)).rowcount == 0:
        conn.execute(gateway_state.insert().values(key=key, value=v))


# --------------------------------------------------------------------------- redaction

SECRET_KEY_RE = re.compile(
    r"pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|x-gateway-key",
    re.I,
)
SECRET_VALUE_RE = re.compile(
    r"(Bearer\s+)[A-Za-z0-9._~+/=-]+"
    r"|\bsk-[A-Za-z0-9_-]{16,}"                                          # OpenAI, Anthropic
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"      # GitHub
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"                                    # AWS access key id
    r"|\b(?:xox[abeprs]|xapp)-[A-Za-z0-9-]{10,}"                         # Slack
    r"|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"                           # Stripe
    r"|\bAIza[0-9A-Za-z_-]{35}"                                          # Google API key
    r"|\bnpm_[A-Za-z0-9]{36}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"     # JWT
    r"|(://[^\s:/@]+:)[^\s/@]+(?=@)"                                     # password in a URL (postgres://user:pass@host)
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: "[REDACTED]" if SECRET_KEY_RE.search(str(k)) else redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return SECRET_VALUE_RE.sub(lambda m: (m.group(1) or m.group(2) or "") + "[REDACTED]", obj)
    return obj


def to_stored_json(obj: Any) -> str | None:
    if obj is None:
        return None
    s = json.dumps(redact(obj), default=str, ensure_ascii=False)
    if len(s) > MAX_PAYLOAD_CHARS:
        s = json.dumps({"_truncated": True, "_original_chars": len(s), "preview": s[:MAX_PAYLOAD_CHARS]})
    return s


# --------------------------------------------------------------------------- policy


# History checks (rules.yaml `history_checks:`) look at what happened before an action, not just the action.
# Each check's effect: block (stop it), review (make a person decide), warn (just flag it), off.
HISTORY_EFFECT_KEYS = ("repeat_of_rejected", "impersonation", "payment_request_in_message", "duplicate_change")
HISTORY_DEFAULTS = {
    "company_domains": [],
    "lookback_hours": 24,
    "money_tools": ["*refund*", "*transfer*", "*wire*", "*payout*", "*send_money*", "*payment_create*"],
    "repeat_of_rejected": "review",         # the same action (same tool + same target) a person already rejected
    "impersonation": "block",               # moving money right after reading a message from a look-alike domain
    "payment_request_in_message": "review", # moving money right after reading a message that asks for a payment
    "duplicate_change": "review",           # the same change on the same target again (e.g. a 2nd refund)
}

# Taint checks (rules.yaml `taint_checks:`): where is this action sending things, and did that come from content
# someone else wrote (a web page, an email, an issue) rather than from the user or the company's own systems?
TAINT_EFFECT_KEYS = ("untrusted_destination", "after_untrusted")
TAINT_DEFAULTS = {
    "untrusted": ["WebFetch", "WebSearch", "*fetch*", "*browse*", "*scrape*", "*crawl*", "*web_search*", "*search_web*",
                  "*inbox*", "*read_email*", "*email_read*", "*get_email*", "*mail*read*", "*read*mail*", "*get_message*",
                  "*read_message*", "*message_read*", "*issue*", "*ticket*", "*comment*", "*pull_request*",
                  "*channel*history*", "*conversations*history*", "*download*", "*http_get*"],
    "sinks": ["*send*", "*reply*", "*forward*", "*_post*", "*post_*", "*.post*", "*publish*", "*add_comment*",
              "*create_comment*", "*comment_create*", "*create_issue*", "*issue_create*", "*create_pull*",
              "*pull_request_create*", "*pr_create*", "*transfer*", "*wire*", "*payout*", "*refund*", "*payment*create*",
              "*webhook*", "*upload*", "*share*", "*invite*", "*http_request*"],
    "lookback_hours": 24,
    "untrusted_destination": "review",  # sends to an address/URL/account found only in untrusted content
    "after_untrusted": "warn",          # sends anything out after untrusted content was read in this conversation
}

# Data checks (rules.yaml `data_checks:`): text an action puts where others read it (a PR, an issue, a comment, a chat
# post) that names a customer on the team's list, or carries personal data. See outbound.py.
DATA_EFFECT_KEYS = ("customer_names", "personal_data")
DATA_DEFAULTS = {"customer_names": "review", "personal_data": "review", "where": outbound.DEFAULT_WHERE}

# Command checks (rules.yaml `command_checks:`) read what a shell command actually does (see commands.py).
COMMAND_EFFECT_KEYS = ("catastrophic", "irreversible", "hidden")
COMMAND_DEFAULTS = {
    "tools": ["Bash", "PowerShell", "*shell*", "*run_command*", "*execute_command*", "*terminal*", "*exec_command*"],
    "catastrophic": "block",   # wipes a disk, the filesystem or a home folder: rm -rf /, rm -rf ~, mkfs, dd onto a disk
    "irreversible": "review",  # rm -r, git push --force, git reset --hard, terraform destroy, kubectl delete, DROP TABLE
    "hidden": "review",        # code that can't be read first: eval, curl | sh, base64 -d | bash, -EncodedCommand,
                               # inline programs (python -c, node -e, ...), a program named only when it runs
    "written_then_run": "review",  # runs a script the agent itself created in this conversation (read it first)
    "unknown": "warn",         # a program that isn't a common developer tool: recorded (shadow); "review" holds it
    "read_only": "off",        # "allow": commands that only look (ls, cat, grep, git status) run without asking
}


class Policy:
    """rules.yaml, hot-reloaded whenever the file changes. First matching rule wins."""

    MATCH_FIELDS = ("kind", "name", "source", "client", "session_id")
    INPUT_OPS = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le,
                 "eq": operator.eq, "ne": operator.ne}

    @classmethod
    def _input_conds(cls, spec: Any) -> list[tuple[str, Any, float]]:
        """match.input {field: {op: number}} -> [(field, op_fn, number)]. Dotted fields reach into nested objects."""
        if not spec:
            return []
        if not isinstance(spec, dict) or not all(isinstance(c, dict) and c for c in spec.values()):
            raise ValueError("match.input must look like {field: {gt: 100}}")
        conds = []
        for field, ops in spec.items():
            for op, value in ops.items():
                if op not in cls.INPUT_OPS or isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"match.input.{field}: use {'/'.join(cls.INPUT_OPS)} with a number")
                conds.append((str(field), cls.INPUT_OPS[op], value))
        return conds

    @staticmethod
    def _input_number(input: Any, field: str) -> float | None:
        """The number at `field` in the call's input, or None if missing / not a number."""
        if isinstance(input, str):
            try:
                input = json.loads(input)
            except ValueError:
                return None
        for part in field.split("."):
            if not isinstance(input, dict) or part not in input:
                return None
            input = input[part]
        if isinstance(input, bool):
            return None
        try:
            n = float(input)  # numeric strings like "120.50" count too
        except (TypeError, ValueError):
            return None
        return n if n == n else None  # NaN never matches

    @classmethod
    def _compile_match(cls, m: dict) -> dict:
        return {
            "globs": {f: ([m[f]] if isinstance(m[f], str) else list(m[f])) for f in cls.MATCH_FIELDS if f in m},
            "input_regex": re.compile(m["input_regex"], re.I | re.S) if m.get("input_regex") else None,
            "input_conds": cls._input_conds(m.get("input")),
        }

    @classmethod
    def matches(cls, compiled: dict, values: dict, input: Any, input_text: str | None = None) -> bool:
        if not all(any(fnmatch.fnmatchcase((values.get(f) or "").lower(), p.lower()) for p in pats)
                   for f, pats in compiled["globs"].items()):
            return False
        if compiled["input_regex"] is not None:
            if input_text is None:
                input_text = input if isinstance(input, str) else json.dumps(input, default=str, ensure_ascii=False)
            if not compiled["input_regex"].search(input_text):
                return False
        # A missing or non-numeric field never matches, so the call falls through to later rules.
        return all((n := cls._input_number(input, f)) is not None and op(n, v) for f, op, v in compiled["input_conds"])

    @classmethod
    def _compile_sequences(cls, items: list) -> list[dict]:
        out = []
        for i, r in enumerate(items or []):
            rid = r.get("id") or f"sequence-{i}"
            action = r.get("action", "review")
            if action not in ("deny", "review", "warn"):
                raise ValueError(f"sequences.{rid}: action must be deny, review or warn")
            after, count = r.get("after"), r.get("count")
            if not after and not count:
                raise ValueError(f"sequences.{rid}: needs `after:` or `count:`")
            seq = {"id": rid, "action": action, "reason": r.get("reason") or rid,
                   "match": cls._compile_match(r.get("match") or {}), "after": None, "count": None}
            if after:
                scope = after.get("scope", "session")
                if scope not in ("session", "agent", "all"):
                    raise ValueError(f"sequences.{rid}: after.scope must be session | agent | all")
                seq["after"] = {"match": cls._compile_match(after.get("match") or {}),
                                "within_hours": float(after.get("within_hours", 24)),
                                "same_target": bool(after.get("same_target", False)), "scope": scope}
            if count:
                scope = count.get("scope", "agent")
                if scope not in ("session", "agent", "all") or "more_than" not in count:
                    raise ValueError(f"sequences.{rid}: count needs more_than, and scope session | agent | all")
                field = count.get("sum")
                if field is not None and not (isinstance(field, str) and field.strip()):
                    raise ValueError(f"sequences.{rid}: count.sum must be an input field name")
                if "same_target" in count and not isinstance(count["same_target"], bool):
                    raise ValueError(f"sequences.{rid}: count.same_target must be true or false")
                seq["count"] = {"more_than": float(count["more_than"]) if field else int(count["more_than"]),
                                "within_hours": float(count.get("within_hours", 1)), "scope": scope,
                                "sum": field.strip() if field else None,
                                "same_target": bool(count.get("same_target", False))}
            out.append(seq)
        return out

    def __init__(self, path: Path):
        self.path = path
        self._sig: tuple | None = ()  # never equal to a real signature or None
        self._lock = threading.Lock()
        self.default = "allow"
        self.default_reason = "default allow"
        self.rules: list[dict] = []
        self.history: dict = dict(HISTORY_DEFAULTS)
        self.commands: dict = dict(COMMAND_DEFAULTS)
        self.taint: dict = dict(TAINT_DEFAULTS)
        self.data: dict = dict(DATA_DEFAULTS)
        self.sequences: list[dict] = []
        self.source, self.fingerprint = "", verify.rules_fingerprint("")
        self.mode, self.shadow_agents = "enforce", []
        self.upstreams: dict[str, str] = {}

    def _maybe_reload(self) -> None:
        sig = _file_sig(self.path)
        if sig == self._sig:
            return
        with self._lock:
            if sig == self._sig:
                return
            try:
                source = self.path.read_text(encoding="utf-8") if sig else ""
                data = yaml.safe_load(source) or {}
                rules = []
                for i, r in enumerate(data.get("rules") or []):
                    m = r.get("match") or {}
                    approvers = r.get("approvers")
                    rules.append({
                        "id": r.get("id") or f"rule-{i}",
                        "action": r.get("action", "deny"),
                        "reason": r.get("reason", ""),
                        **self._compile_match(m),
                        # review-only options
                        "timeout_seconds": int(r.get("timeout_seconds", APPROVAL_TIMEOUT)),
                        "on_timeout": r.get("on_timeout", "deny"),
                        "approvers": [approvers] if isinstance(approvers, str) else approvers,
                    })
                default = data.get("default", "allow")
                if default not in ("allow", "deny", "review") or any(r["action"] not in ("allow", "deny", "review") for r in rules):
                    raise ValueError("actions must be 'allow', 'deny' or 'review'")
                if any(r["on_timeout"] not in ("allow", "deny") or r["timeout_seconds"] < 1 for r in rules):
                    raise ValueError("on_timeout must be 'allow' or 'deny' and timeout_seconds >= 1")
                hc = {**HISTORY_DEFAULTS, **(data.get("history_checks") or {})}
                for k in HISTORY_EFFECT_KEYS:
                    # YAML reads a bare `off` / `no` as false and `on` / `yes` as true.
                    hc[k] = "off" if hc[k] is False else HISTORY_DEFAULTS[k] if hc[k] is True else str(hc[k]).lower()
                    if hc[k] not in ("block", "review", "warn", "off"):
                        raise ValueError(f"history_checks.{k} must be block, review, warn or off")
                hc["company_domains"] = [d.lower().strip() for d in hc["company_domains"] or []]
                cc = {**COMMAND_DEFAULTS, **(data.get("command_checks") or {})}
                for k in (*COMMAND_EFFECT_KEYS, "written_then_run", "unknown"):
                    cc[k] = "off" if cc[k] is False else COMMAND_DEFAULTS[k] if cc[k] is True else str(cc[k]).lower()
                    if cc[k] not in ("block", "review", "warn", "off"):
                        raise ValueError(f"command_checks.{k} must be block, review, warn or off")
                cc["read_only"] = "off" if cc["read_only"] is False else "allow" if cc["read_only"] is True \
                    else str(cc["read_only"]).lower()
                if cc["read_only"] not in ("allow", "off"):
                    raise ValueError("command_checks.read_only must be allow or off")
                cc["tools"] = [cc["tools"]] if isinstance(cc["tools"], str) else list(cc["tools"] or [])
                sequences = self._compile_sequences(data.get("sequences"))
                tc = {**TAINT_DEFAULTS, **(data.get("taint_checks") or {})}
                for k in TAINT_EFFECT_KEYS:
                    tc[k] = "off" if tc[k] is False else TAINT_DEFAULTS[k] if tc[k] is True else str(tc[k]).lower()
                    if tc[k] not in ("block", "review", "warn", "off"):
                        raise ValueError(f"taint_checks.{k} must be block, review, warn or off")
                for k in ("untrusted", "sinks"):
                    tc[k] = [tc[k]] if isinstance(tc[k], str) else list(tc[k] or [])
                dc = {**DATA_DEFAULTS, **(data.get("data_checks") or {})}
                for k in DATA_EFFECT_KEYS:
                    dc[k] = "off" if dc[k] is False else DATA_DEFAULTS[k] if dc[k] is True else str(dc[k]).lower()
                    if dc[k] not in ("block", "review", "warn", "off"):
                        raise ValueError(f"data_checks.{k} must be block, review, warn or off")
                dc["where"] = [dc["where"]] if isinstance(dc["where"], str) else list(dc["where"] or [])
                mode = str(data.get("mode", "enforce")).lower()
                if mode not in ("enforce", "shadow"):
                    raise ValueError("mode must be enforce or shadow")
                shadow_agents = data.get("shadow_agents") or []
                shadow_agents = [shadow_agents] if isinstance(shadow_agents, str) else list(shadow_agents)
                self.default, self.rules, self.history, self.commands = default, rules, hc, cc
                self.sequences, self.taint, self.data = sequences, tc, dc
                self.source, self.fingerprint = source, verify.rules_fingerprint(source)
                self.mode, self.shadow_agents = mode, shadow_agents
                self.default_reason = data.get("default_reason") or f"default {default}"
                self.upstreams = {k: str(v).rstrip("/") for k, v in (data.get("upstreams") or {}).items()}
                log.info("loaded %d rules from %s (default=%s)", len(rules), self.path, default)
            except Exception:
                # A broken edit must never take the gateway down: keep serving the last good rules.
                log.exception("failed to load %s, keeping previous rules", self.path)
            self._sig = sig

    DEFAULT_RULE = {"timeout_seconds": APPROVAL_TIMEOUT, "on_timeout": "deny", "approvers": None}

    def shadow_for(self, source: str | None, client: str) -> bool:
        """Shadow mode: record what would happen, but let it through (everything, or the agents listed)."""
        self._maybe_reload()
        if self.mode == "shadow":
            return True
        return any(fnmatch.fnmatchcase((k or "").lower(), g.lower()) for g in self.shadow_agents for k in (source, client))

    def evaluate(self, *, kind: str, name: str, source: str | None, client: str,
                 session_id: str | None, input: Any) -> tuple[str, str, str | None, dict]:
        """-> (action, reason, rule_id, rule). `rule` carries the review options."""
        self._maybe_reload()
        values = {"kind": kind, "name": name, "source": source, "client": client, "session_id": session_id}
        input_text = input if isinstance(input, str) else json.dumps(input, default=str, ensure_ascii=False)
        for rule in self.rules:
            if self.matches(rule, values, input, input_text):
                return rule["action"], rule["reason"] or f"matched rule {rule['id']}", rule["id"], rule
        return self.default, self.default_reason, None, self.DEFAULT_RULE


policy = Policy(RULES_PATH)

# --------------------------------------------------------------------------- models


class EventIn(BaseModel):
    name: str = Field(..., max_length=500, description="Tool / action name, e.g. 'shell.exec'")
    kind: str = Field("tool_call", max_length=100)
    input: Any = None
    source: str | None = Field(None, max_length=200, description="Agent / service / host name")
    session_id: str | None = Field(None, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Optional: send these to record an already-finished action in a single call.
    output: Any = None
    error: str | None = None
    duration_ms: float | None = None


class ResultIn(BaseModel):
    output: Any = None
    error: str | None = None
    duration_ms: float | None = None


class Decision(BaseModel):
    event_id: str
    decision: Literal["allow", "deny", "review"]  # review = held for a human; poll /v1/events/{id}/decision
    reason: str
    rule_id: str | None = None
    status: str | None = None
    approval_deadline: str | None = None
    decided_by: str | None = None
    decision_note: str | None = None
    signals: list[dict] | None = None  # history-check findings, e.g. possible impersonation
    would: str | None = None           # shadow mode: deny | review that was let through
    risk: int | None = None            # risk.py's score, 0..100: measured only, never part of the decision


class ApprovalIn(BaseModel):
    note: str | None = Field(None, max_length=2000)


# --------------------------------------------------------------------------- core


def _live(entry: dict | None) -> bool:
    """A stop with a time limit ("for 1 hour") ends by itself when the time is up."""
    return bool(entry) and not (entry.get("until") and entry["until"] <= utcnow())


def stopped_for(source: str | None, client: str, session_id: str | None = None) -> dict | None:
    """The stop that applies to this caller, if any: everything, one agent (by source or key), or one session."""
    s = state_get("stop", {"all": None, "agents": {}, "sessions": {}})
    if _live(s.get("all")):
        return {**s["all"], "scope": "all"}
    for k in (source, client):
        if k and _live(s.get("agents", {}).get(k)):
            return {**s["agents"][k], "scope": "agent", "agent": k}
    if session_id and _live(s.get("sessions", {}).get(session_id)):
        return {**s["sessions"][session_id], "session": session_id, "scope": "session"}
    return None


def _hhmm(iso: str | None) -> str:
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).strftime("%H:%M UTC")
    except ValueError:
        return str(iso or "")


def stop_message(stop: dict) -> str:
    """What the agent is told, so the person reading its reply knows it's a stop, not a rule, and how to end it."""
    by = f" by {stop.get('by')}" if stop.get("by") else ""
    why = f" ({stop['reason']})" if stop.get("reason") else ""
    until = f", until {_hhmm(stop['until'])}" if stop.get("until") else ""
    dash = f"{(settings().get('public_url') or PUBLIC_URL or 'http://localhost:8080').rstrip('/')}/dashboard"
    if stop.get("scope") == "session":
        what = "This conversation is stopped"
        cli = f"{CLI} resume --session {stop['session']}"
    elif stop.get("scope") == "agent":
        what = f"Squidbrake's emergency stop is ON for {stop['agent']}"
        cli = f"{CLI} resume --agent {stop['agent']}"
    else:
        what = "Squidbrake's emergency stop is ON. All agents' actions are paused"
        cli = f"{CLI} resume"
    return (f"{what} (since {_hhmm(stop.get('at'))}{by}{why}{until}). Nothing runs until a person turns it off: "
            f"in the dashboard ({dash}, Resume), or on the computer running Squidbrake: {cli}")


STOP_REMINDER_MINUTES = int(os.getenv("SQUIDBRAKE_STOP_REMINDER_MINUTES", "30"))


def remind_if_still_stopped(stop: dict, tried: str) -> None:
    """A stop that's been on for 30 minutes while agents keep trying: ask once whether it was meant to stay on."""
    try:
        at = datetime.fromisoformat(str(stop.get("at")).replace("Z", "+00:00"))
    except ValueError:
        return
    if stop.get("reminded") or datetime.now(timezone.utc) - at < timedelta(minutes=STOP_REMINDER_MINUTES):
        return
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar() or "{}")
        entry = s.get("all") if stop.get("scope") == "all" else \
            s.get("agents", {}).get(stop.get("agent")) if stop.get("scope") == "agent" else \
            s.get("sessions", {}).get(stop.get("session"))
        if not entry or entry.get("reminded"):
            return
        entry["reminded"] = utcnow()
        state_set(conn, "stop", s)
    minutes = int((datetime.now(timezone.utc) - at).total_seconds() // 60)
    text = (f"Still stopped: did you mean to leave this on? Squidbrake's emergency stop has been on for {minutes} "
            f"minutes{' (' + stop['reason'] + ')' if stop.get('reason') else ''}, and agents keep trying (just now: "
            f"{tried}). Turn it off in the dashboard, or run: {CLI} resume")
    threading.Thread(target=notify_text, args=("Squidbrake is still stopped", text), daemon=True).start()


def notify_text(title: str, text: str) -> None:
    """A plain message to wherever approvals go: Slack or Discord, Teams, a phone (ntfy) and email."""
    cfg = settings()
    if cfg["slack_webhook"]:
        discord = any(h in cfg["slack_webhook"] for h in ("discord.com/api/webhooks/", "discordapp.com/api/webhooks/"))
        try:
            body = {"content": _truncate_discord(f"**{title}**\n{text}", 1999), "allowed_mentions": {"parse": []}} \
                if discord else {"text": f"*{slack_escape(title)}*\n{slack_escape(text)}"}
            httpx.post(cfg["slack_webhook"], json=body, timeout=10).raise_for_status()
        except Exception:
            log.exception("notification failed: %s", title)
    if cfg.get("teams_webhook"):
        send_teams(cfg["teams_webhook"], title, text)
    if cfg["ntfy_topic"]:
        try:
            httpx.post(cfg["ntfy_server"].rstrip("/"), timeout=10,
                       json={"topic": cfg["ntfy_topic"], "title": title, "message": text, "priority": 4}).raise_for_status()
        except Exception:
            log.exception("phone notification failed: %s", title)
    send_email(cfg, title, text)


# --------------------------------------------------------------------------- history checks

TARGET_KEYS = ("charge_id", "order_id", "invoice_id", "payment_id", "to_account", "account", "iban", "account_number",
               "customer_email", "email", "to", "recipient", "message_id", "id", "file_path", "path", "sql", "command")
EMAIL_FROM_RE = re.compile(r'\\?"from\\?"\s*:\s*\\?"([^"\\@\s]+@([^"\\\s]+))', re.I)
PAYMENT_WORDS_RE = re.compile(r"\b(wire|bank account|iban|swift|routing number|gift ?cards?|urgent(ly)?|confidential|"
                              r"asap|do not call|new vendor|payment details)\b", re.I)
HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("|", "l"))


def _target(input: Any) -> tuple[str, str] | None:
    """What an action is about: the charge, account, recipient, file... (first of TARGET_KEYS present)."""
    if isinstance(input, dict):
        for k in TARGET_KEYS:
            v = input.get(k)
            if isinstance(v, (str, int, float)) and str(v).strip():
                return k, str(v).strip()
    return None


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str, company_domains: list[str]) -> str | None:
    """'acrne-corp.com' looks like 'acme.com' (rn -> m); 'acmee.com' too. The real domain never matches."""
    d = domain.lower().strip(".")
    for c in company_domains:
        if d == c or d.endswith("." + c):
            continue
        company, label = c.split(".")[0], d.split(".")[-2] if d.count(".") else d
        norm = label
        for a, b in HOMOGLYPHS:
            norm = norm.replace(a, b)
        if company in re.split(r"[-_.]", norm) or c in d or (len(company) >= 4 and 0 < _edit_distance(label, company) <= 2):
            return c
    return None


def _ago(iso: str) -> str:
    s = (datetime.now(timezone.utc) - datetime.fromisoformat(iso.replace("Z", "+00:00"))).total_seconds()
    return f"{int(s)}s ago" if s < 60 else f"{int(s // 60)} min ago" if s < 3600 else f"{s / 3600:.0f} h ago"


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\n", " ").replace("\\\\", "\\")


def _needles(input: Any) -> list[re.Pattern]:
    """The action's specifics to look for in what the agent read: account numbers, ids, emails, amounts."""
    out: list[re.Pattern] = []
    for v in (input.values() if isinstance(input, dict) else []):
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)) and v >= 10:
            # Only an amount written as money counts ("$24,800", "USD 900"): a bare "10" also matches
            # times, dates and ids in whatever the agent read.
            n = float(v)
            forms = {f"{n:,.2f}", f"{n:.2f}"} | ({f"{n:,.0f}", f"{n:.0f}"} if n == int(n) else set())
            money = r"(?:[$€£₹¥]\s?|\b(?:USD|EUR|GBP|INR|Rs\.?)\s?)"
            out += [re.compile(rf"{money}{re.escape(f)}(?![\d])", re.I) for f in forms]
        elif isinstance(v, str) and len(v.strip()) >= 5 and len(v) <= 120:
            out.append(re.compile(re.escape(v.strip()), re.I))
    return out


def _message_behind(prior: list, input: Any) -> tuple[str, str] | None:
    """Where did this request come from? Find the message the agent read that mentions this action's specifics
    (the account number, charge, customer or amount) and return its sender and text. No match, no guess:
    an unrelated refund made after reading a scam email must not be blamed on that email."""
    needles = _needles(input)
    for r in prior:  # newest first
        text = r.output or ""
        for pat in needles:
            m = pat.search(text)
            if m:
                froms = EMAIL_FROM_RE.findall(text[max(0, m.start() - 2000): m.start()])
                if froms:
                    return froms[-1][0], _unescape(text[max(0, m.start() - 400): m.start() + 150])
    return None


def history_signals(conn, name: str, input: Any, stored_input: str | None, source: str | None,
                    session_id: str | None, is_change: bool, client: str | None = None,
                    only_reads: bool = False) -> list[dict]:
    """Look at what happened before this action (see HISTORY_DEFAULTS)."""
    hc = policy.history
    if all(hc[k] == "off" for k in HISTORY_EFFECT_KEYS):
        return []
    since = (datetime.now(timezone.utc) - timedelta(hours=float(hc["lookback_hours"]))).isoformat().replace("+00:00", "Z")
    target = _target(input)
    out: list[dict] = []
    add = lambda check, message, ref=None: hc[check] != "off" and out.append(
        {"check": check, "effect": hc[check], "message": message, "ref": ref})

    # 1. A person already said no to this - to this agent. (Looking again, e.g. `git status`, is not a retry.)
    if hc["repeat_of_rejected"] != "off" and not only_reads:
        same_agent = and_(events.c.source == source if source else events.c.source.is_(None),
                          events.c.client == client if client else true())
        rejected = conn.execute(select(events).where(
            events.c.name == name, events.c.decision == "deny", events.c.decided_by.isnot(None),
            events.c.decided_by != "timeout", events.c.created_at >= since, same_agent,
        ).order_by(events.c.created_at.desc()).limit(50)).all()
        for r in rejected:
            prev_target = _target(json.loads(r.input)) if r.input else None
            if r.input == stored_input or (target and prev_target and prev_target[1].lower() == target[1].lower()):
                note = f': "{r.decision_note}"' if r.decision_note else ""
                then = f"{r.decided_by} already rejected this {_ago(r.decided_at or r.created_at)}{note}"
                add("repeat_of_rejected", then + (". Don't retry it; ask the person what to do instead."
                                                  if hc["repeat_of_rejected"] == "block" else
                                                  ". Asking again, in case they've changed their mind."), r.id)
                break

    # 2 + 3. Money moving right after reading a message: who asked for it?
    is_money = any(fnmatch.fnmatchcase(name.lower(), g.lower()) for g in hc["money_tools"])
    if is_money and (hc["impersonation"] != "off" or hc["payment_request_in_message"] != "off"):
        scope = events.c.session_id == session_id if session_id else and_(
            events.c.source == source, events.c.created_at >= (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        prior = conn.execute(select(events.c.id, events.c.output).where(scope, events.c.output.isnot(None))
                             .order_by(events.c.created_at.desc()).limit(30)).all()
        found = _message_behind(prior, input)
        if found:
            sender, text = found
            fake = lookalike_of(sender.split("@")[1], hc["company_domains"])
            if fake:
                add("impersonation", f"Possible scam: this follows a message from {sender}, which imitates {fake} "
                                     f"but is NOT your domain.")
            elif PAYMENT_WORDS_RE.search(text):
                words = sorted({m.group(0).lower() for m in PAYMENT_WORDS_RE.finditer(text)})[:4]
                add("payment_request_in_message", f"This follows a message from {sender} asking for a payment "
                                                  f"({', '.join(words)}). Check the request is genuine.")

    # 4. The same change on the same thing again.
    if is_change and target and hc["duplicate_change"] != "off":
        # .all(): never `break` out of a live SQLite cursor - the pooled connection would keep a stale snapshot.
        for r in conn.execute(select(events).where(
                events.c.name == name, events.c.created_at >= since,
                events.c.status.in_(("completed", "pending", "awaiting_approval"))).order_by(events.c.created_at.desc()).limit(50)).all():
            prev = _target(json.loads(r.input)) if r.input else None
            if prev and prev[1].lower() == target[1].lower():
                state = {"completed": "and it was carried out",
                         "pending": "and it was allowed (no result reported yet)",
                         "awaiting_approval": "and it's still waiting for approval"}[r.status]
                add("duplicate_change", f"The same {name} on {target[0]} {target[1]} was requested {_ago(r.created_at)}, "
                                        f"{state}.", r.id)
                break
    return out


def reported_runs(metadata: dict | None) -> list[tuple[str, str]]:
    """What the hook read underneath the command on the developer's machine (runs.py): a Makefile target's recipe,
    a package.json script, a shell script. -> [(via, line)]. Checked like the command; it can only add a stop."""
    found = (metadata or {}).get("runs")
    out: list[tuple[str, str]] = []
    for item in found[:20] if isinstance(found, list) else []:
        if isinstance(item, dict) and isinstance(item.get("lines"), list):
            via = str(item.get("via") or "what it runs")[:200]
            out += [(via, l[:1000]) for l in item["lines"][:60] if isinstance(l, str) and l.strip()]
    return out[:60]


def command_signals(name: str, input: Any, metadata: dict | None = None) -> tuple[list[dict], bool]:
    """What a shell tool's command actually does (commands.py), including what it runs underneath when the hook
    read that (a Makefile target, a package.json script). -> (signals, only_reads)."""
    cc = policy.commands
    if not any(fnmatch.fnmatchcase(name.lower(), t.lower()) for t in cc["tools"]):
        return [], False
    line = commands.command_of(input)
    if not line:
        return [], False
    reading = commands.read(line)
    kind, message = reading.kind, f"This command {reading.summary()}."
    for via, inner in reported_runs(metadata):
        r = commands.read(inner)
        if r.kind in COMMAND_EFFECT_KEYS and commands.SEVERITY.index(r.kind) > commands.SEVERITY.index(kind):
            kind = r.kind
            message = f"This command runs {via}, which {r.summary()}."
    if kind in COMMAND_EFFECT_KEYS:
        if cc[kind] == "off":
            return [], False
        return [{"check": f"{kind}_command", "effect": cc[kind], "message": message}], False
    if reading.unknown and cc["unknown"] != "off":
        return [{"check": "unknown_command", "effect": cc["unknown"],
                 "message": f"This command runs a program Squidbrake doesn't know ({', '.join(reading.unknown[:3])}), so "
                            f"what it does is up to that program."}], False
    return [], kind == "read_only"


WRITES_A_FILE = ("Write", "write_file", "create_file", "write_to_file", "Create", "fs_write")


def written_then_run(conn, ev: "EventIn", client: str) -> list[dict]:
    """A script the agent created in this conversation, now run: `python x.py` is as unreadable to a shell reading
    as `python -c`, so a person reads it first (command_checks.written_then_run). Edits to existing files aren't
    counted: running the project's own tests and scripts after changing them is everyday work."""
    cc = policy.commands
    if cc["written_then_run"] == "off" or not ev.session_id             or not any(fnmatch.fnmatchcase(ev.name.lower(), t.lower()) for t in cc["tools"]):
        return []
    line = commands.command_of(ev.input)
    scripts = commands.read(line).scripts if line else []
    if not scripts:
        return []
    cwd = str((ev.metadata or {}).get("cwd") or "")
    norm = lambda p: os.path.normcase(os.path.normpath(p.replace("\\", "/"))) if p else ""
    wanted = {norm(os.path.join(cwd, sp) if cwd and not os.path.isabs(sp) and not sp.startswith("~") else sp): sp
              for sp in scripts}
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    rows = conn.execute(select(events.c.name, events.c.input).where(
        events.c.session_id == ev.session_id, events.c.created_at >= since, events.c.status.in_(("completed", "pending")),
        events.c.name.in_(WRITES_A_FILE)).order_by(events.c.created_at.desc()).limit(200)).all()
    for r in rows:
        try:
            inp = json.loads(r.input) if r.input else {}
        except ValueError:
            continue
        path = str(inp.get("file_path") or inp.get("path") or "") if isinstance(inp, dict) else ""
        hit = wanted.get(norm(path)) or next((sp for sp in scripts if not cwd and path and
                                              os.path.basename(path.replace("\\", "/")) == os.path.basename(sp)), None)
        if hit:
            return [{"check": "written_then_run_command", "effect": cc["written_then_run"],
                     "message": f"This command runs {hit}, a script the agent wrote in this conversation. Read it "
                                f"before it runs: {path}"}]
    return []


SEQUENCE_EFFECT = {"deny": "block", "review": "review", "warn": "warn"}
_recorded_policies: set[str] = set()


def record_policy_version(conn) -> None:
    """Keep the text of each rules.yaml version that decides something (inside audited_tx, so no two race)."""
    fp = policy.fingerprint
    if fp in _recorded_policies:
        return
    if conn.execute(select(policy_versions.c.fingerprint).where(policy_versions.c.fingerprint == fp)).first() is None:
        conn.execute(policy_versions.insert().values(fingerprint=fp, first_seen=utcnow(), content=policy.source))
        audit(conn, "gateway", "policy.version", fp, sha256=hashlib.sha256(policy.source.encode()).hexdigest(),
              rules=len(policy.rules), sequences=len(policy.sequences))
    _recorded_policies.add(fp)


def _step_phrase(row) -> str:
    """How an earlier step reads in a reason: Bash `aws rds modify-db-instance ...` (12 minutes ago)."""
    stored = json.loads(row.input) if row.input else None
    line = commands.command_of(stored) if stored is not None else None
    target = _target(stored) if stored is not None else None
    detail = f" `{line[:90]}`" if line else f" on {target[1]}" if target else ""
    return f"{row.name}{detail} ({_ago(row.created_at)})"


def sequence_signals(conn, ev: "EventIn", client: str) -> list[dict]:
    """rules.yaml `sequences:` - this action, judged by what came before it (see rules.yaml)."""
    seqs = policy.sequences
    if not seqs:
        return []
    values = {"kind": ev.kind, "name": ev.name, "source": ev.source, "client": client, "session_id": ev.session_id}
    input_text = ev.input if isinstance(ev.input, str) else json.dumps(ev.input, default=str, ensure_ascii=False)
    out: list[dict] = []
    now = datetime.now(timezone.utc)
    for seq in seqs:
        if not Policy.matches(seq["match"], values, ev.input, input_text):
            continue
        earlier = lambda hours, scope: conn.execute(select(events).where(
            scope, events.c.created_at >= (now - timedelta(hours=hours)).isoformat().replace("+00:00", "Z"))
            .order_by(events.c.created_at.desc()).limit(500)).all()
        row_values = lambda r: {"kind": r.kind, "name": r.name, "source": r.source, "client": r.client,
                                "session_id": r.session_id}
        stored = lambda r: json.loads(r.input) if r.input else None
        message = None
        if seq["after"]:
            a = seq["after"]
            same_agent = and_(events.c.source == ev.source, events.c.client == client)
            scope = {"session": events.c.session_id == ev.session_id if ev.session_id else same_agent,
                     "agent": same_agent, "all": events.c.id.isnot(None)}[a["scope"]]
            target = _target(ev.input)
            for r in earlier(a["within_hours"], scope):
                if r.status not in ("completed", "pending"):      # only steps that actually went ahead
                    continue
                if not Policy.matches(a["match"], row_values(r), stored(r), r.input or ""):
                    continue
                prev = _target(stored(r))
                if a["same_target"] and not (target and prev and prev[1].lower() == target[1].lower()):
                    continue
                where = "" if r.session_id and r.session_id == ev.session_id else \
                    " (in another conversation)" if r.source == ev.source else f" (by {r.source or 'another agent'})"
                message, ref = f"{seq['reason']}. Because earlier{where}: {_step_phrase(r)}.", r.id
                break
        if seq["count"] and message is None:
            c = seq["count"]
            scope = {"session": events.c.session_id == ev.session_id if ev.session_id else events.c.source == ev.source,
                     "agent": and_(events.c.source == ev.source, events.c.client == client),
                     "all": events.c.id.isnot(None)}[c["scope"]]
            target = _target(ev.input)
            hits = []
            for r in earlier(c["within_hours"], scope):
                if c["sum"] and r.status not in ("completed", "pending"):  # only completed or allowed actions contribute amounts
                    continue
                if not c["sum"] and r.status == "denied":
                    continue
                if not Policy.matches(seq["match"], row_values(r), stored(r), r.input or ""):
                    continue
                if c["same_target"]:
                    prev = _target(stored(r))
                    if not (target and prev and prev[1].lower() == target[1].lower()):
                        continue
                hits.append(r)
            span = f"{c['within_hours']:g} hour{'s' if c['within_hours'] != 1 else ''}"
            if c["sum"]:
                amt = lambda inp: Policy._input_number(inp, c["sum"]) or 0.0
                earlier_total = sum(amt(stored(r)) for r in hits)
                total = earlier_total + amt(ev.input)
                if total > c["more_than"]:
                    who = f" to {target[1]}" if target else ""
                    message = (f"{seq['reason']}. Because earlier: {len(hits)} totalling {earlier_total:g}"
                               f"{who} in the last {span}.")
                    ref = hits[0].id if hits else None
            elif len(hits) >= c["more_than"]:
                who = {"session": "in this conversation", "agent": "by this agent", "all": "across all agents"}[c["scope"]]
                message = (f"{seq['reason']}. Because {len(hits)} like it ran {who} in the last {span} "
                           f"(limit {c['more_than']}); the latest: {_step_phrase(hits[0])}.")
                ref = hits[0].id
        if message:
            out.append({"check": "sequence", "rule": seq["id"], "effect": SEQUENCE_EFFECT[seq["action"]],
                        "message": message, "ref": ref})
    return out


def _globbed(name: str | None, globs: list[str]) -> bool:
    return any(fnmatch.fnmatchcase((name or "").lower(), g.lower()) for g in globs)


def data_signals(ev: "EventIn") -> list[dict]:
    """Text this action puts where others read it (a PR, an issue, a comment, a chat post): does it name a customer on
    the team's list, or carry personal data? (see outbound.py)"""
    dc = policy.data
    if dc["customer_names"] == "off" and dc["personal_data"] == "off":
        return []
    shell = _globbed(ev.name, policy.commands["tools"])
    line = commands.command_of(ev.input) if shell else None
    if (shell and not line) or not outbound.is_shared_place(ev.name, line if shell else None, dc["where"]):
        return []
    text = line if shell else outbound.text_of(ev.input)
    out: list[dict] = []
    if dc["customer_names"] != "off" and (names := outbound.customers_named(text, settings().get("customers") or [])):
        who = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        out.append({"check": "customer_names", "effect": dc["customer_names"],
                    "message": f"This puts text where others can read it, and it names {who}, on your customer list. "
                               "Check it should be there."})
    if dc["personal_data"] != "off" and (found := outbound.personal_data(text, policy.history["company_domains"])):
        out.append({"check": "personal_data", "effect": dc["personal_data"],
                    "message": f"This puts text where others can read it, and it contains {', '.join(found)}."})
    return out


def taint_signals(conn, ev: "EventIn", client: str) -> list[dict]:
    """Does this action send something to a destination that only untrusted content mentioned? (see taint.py)"""
    tc = policy.taint
    if tc["untrusted_destination"] == "off" and tc["after_untrusted"] == "off":
        return []
    shell = _globbed(ev.name, policy.commands["tools"])
    line = commands.command_of(ev.input) if shell else None
    if shell:
        if not taint.sends_out(line):
            return []
    elif not _globbed(ev.name, tc["sinks"]):     # e.g. github.create_pull_request: a sink, even though "*pull_request*" reads
        return []
    since = (datetime.now(timezone.utc) - timedelta(hours=float(tc["lookback_hours"]))).isoformat().replace("+00:00", "Z")
    scope = events.c.session_id == ev.session_id if ev.session_id else and_(events.c.source == ev.source,
                                                                            events.c.client == client)
    rows = conn.execute(select(events.c.id, events.c.name, events.c.kind, events.c.input, events.c.output,
                               events.c.created_at).where(scope, events.c.created_at >= since)
                        .order_by(events.c.created_at.desc()).limit(300)).all()

    def untrusted(r) -> bool:
        if r.kind == "prompt":
            return False
        if _globbed(r.name, policy.commands["tools"]):        # a shell command that fetched something from outside
            cmd = commands.command_of(json.loads(r.input)) if r.input else None
            return bool(cmd and taint.UPLOAD_RE.search(cmd) and not taint.sends_out(cmd))
        return _globbed(r.name, tc["untrusted"])

    outside = [r for r in rows if r.output and untrusted(r)]
    if not outside:
        return []
    trusted = [r.input for r in rows if r.kind == "prompt" and r.input] + \
              [r.output for r in rows if r.output and r.kind != "prompt" and not untrusted(r)]
    out: list[dict] = []
    if tc["untrusted_destination"] != "off":
        for dest in taint.destinations(ev.input, line):
            if taint.own_domain(dest, policy.history["company_domains"]):
                continue
            hit = next((r for r in outside if taint.appears_in(dest, r.output)), None)
            if hit and not any(taint.appears_in(dest, t) for t in trusted):
                out.append({"check": "untrusted_destination", "effect": tc["untrusted_destination"], "ref": hit.id,
                            "message": f"This sends to {dest['value']} ({dest['field']}), which appears in {hit.name} "
                                       f"({_ago(hit.created_at)}) but not in anything you asked or in your own systems. "
                                       "Content from outside can carry hidden instructions (prompt injection)."})
                break
    if not out and tc["after_untrusted"] != "off":
        names = list(dict.fromkeys(r.name for r in outside))
        out.append({"check": "after_untrusted", "effect": tc["after_untrusted"], "ref": outside[0].id,
                    "message": f"Earlier in this conversation the agent read content from outside "
                               f"({', '.join(names[:3])}{'...' if len(names) > 3 else ''}), and this sends something out. "
                               "Check it's what you asked for."})
    return out


def reported_effects(metadata: dict | None) -> str | None:
    """What the hook measured on the developer's machine (effects.py): "Removes 3 commits from origin/main ...".
    Shown to the approver as reported by that machine; it never changes the decision."""
    found = (metadata or {}).get("effects")
    lines = [str(x)[:400] for x in found if isinstance(x, str) and x.strip()][:5] if isinstance(found, list) else []
    return "; ".join(lines) or None


def record_event(ev: EventIn, client: str, client_ip: str | None) -> Decision:
    signals: list[dict] = []
    if stop := stopped_for(ev.source, client, ev.session_id):
        decision, rule = "deny", policy.DEFAULT_RULE
        rule_id = "session-stop" if stop.get("session") else "emergency-stop"
        reason = stop_message(stop)
        remind_if_still_stopped(stop, ev.name)
    else:
        # Policy sees the raw input; storage only ever sees the redacted copy.
        decision, reason, rule_id, rule = policy.evaluate(
            kind=ev.kind, name=ev.name, source=ev.source, client=client, session_id=ev.session_id, input=ev.input
        )
        if decision != "deny":
            command_found, only_reads = command_signals(ev.name, ev.input, ev.metadata)
            with engine.connect() as conn:
                # Most telling first: a sequence names the step that caused it; history checks are specific to
                # the business (who asked for this payment); taint and command checks are more general.
                signals = sequence_signals(conn, ev, client)
                # A command that only looks isn't a change: running `git status` twice is not a duplicate.
                signals += history_signals(conn, ev.name, ev.input, to_stored_json(ev.input), ev.source,
                                           ev.session_id, is_change=decision == "review" and not only_reads,
                                           client=client, only_reads=only_reads)
                signals += data_signals(ev) + taint_signals(conn, ev, client) + command_found                     + written_then_run(conn, ev, client)
            blocking = next((s for s in signals if s["effect"] == "block"), None)
            needs_person = next((s for s in signals if s["effect"] == "review"), None)
            signal_id = lambda s: f"sequence:{s['rule']}" if s["check"] == "sequence" else \
                f"command:{s['check']}" if s["check"].endswith("_command") else \
                f"data:{s['check']}" if s["check"] in DATA_EFFECT_KEYS else \
                f"taint:{s['check']}" if s["check"] in TAINT_EFFECT_KEYS else f"history:{s['check']}"
            if blocking and ev.output is None and ev.error is None:
                decision, reason, rule_id = "deny", blocking["message"], signal_id(blocking)
            elif needs_person and decision == "allow":
                decision, reason, rule_id, rule = "review", needs_person["message"], signal_id(needs_person), policy.DEFAULT_RULE
            elif needs_person and decision == "review" and rule_id is None:
                # held by the default anyway: give the approver the specific reason
                reason, rule_id = needs_person["message"], signal_id(needs_person)
            elif (only_reads and decision == "review" and rule_id is None and policy.commands["read_only"] == "allow"
                  and not any(s["effect"] in ("block", "review") for s in signals)):
                # Nothing matched but the default, and the command only looks: don't make a person approve `ls`.
                decision, reason, rule_id = "allow", "Only reads (like ls, cat, grep, git status), so it runs without asking", \
                    "command:read_only"
    if effect := reported_effects(ev.metadata):
        signals.append({"check": "effect", "effect": "info", "message": effect})
    try:   # shadow risk score: measured next to the decision, never changes it
        shell = any(fnmatch.fnmatchcase(ev.name.lower(), t.lower()) for t in policy.commands["tools"])
        risk_score, risk_why = risk.score(ev.name, ev.input, signals, ev.metadata, shell=shell)
    except Exception:
        log.exception("risk score failed")
        risk_score, risk_why = None, []
    would = None
    # Shadow mode lets it through but records what would have happened. Stops and catastrophic commands still apply.
    if decision in ("deny", "review") and rule_id not in ("emergency-stop", "session-stop", "command:catastrophic_command")             and policy.shadow_for(ev.source, client):
        would = decision
        reason = f"Shadow mode, allowed. Would have {'been blocked' if decision == 'deny' else 'waited for approval'}: {reason}"
        decision = "allow"
    already_ran = ev.error is not None or ev.output is not None
    if decision == "review" and already_ran:
        # A record-only event has already happened; there is nothing left to approve.
        decision, reason = "allow", f"{reason} (already executed, approval not applicable)"

    now = utcnow()
    deadline = None
    if decision == "deny":
        status = "denied"
    elif decision == "review":
        status = "awaiting_approval"
        deadline = (datetime.now(timezone.utc) + timedelta(seconds=rule["timeout_seconds"])) \
            .isoformat(timespec="milliseconds").replace("+00:00", "Z")
    elif ev.error:
        status = "failed"
    elif ev.output is not None:
        status = "completed"
    else:
        status = "pending"

    row = {
        "id": str(uuid.uuid4()), "created_at": now,
        "completed_at": now if status in ("completed", "failed") else None,
        "client": client, "client_ip": client_ip, "source": ev.source, "session_id": ev.session_id,
        "kind": ev.kind, "name": ev.name, "status": status, "decision": decision, "rule_id": rule_id,
        "reason": reason, "input": to_stored_json(ev.input), "output": to_stored_json(ev.output),
        "error": ev.error, "metadata": to_stored_json(ev.metadata), "duration_ms": ev.duration_ms,
        "approval_deadline": deadline,
        "approval_on_timeout": rule["on_timeout"] if deadline else None,
        "approvers": json.dumps(rule["approvers"]) if deadline and rule["approvers"] else None,
        "signals": json.dumps(signals) if signals else None,
        "would": would,
        "risk": risk_score, "risk_why": json.dumps(risk_why) if risk_why else None,
    }
    with audited_tx() as conn:
        record_policy_version(conn)
        conn.execute(events.insert().values(**row))
        audit(conn, client, "event.created", row["id"], rules=policy.fingerprint, name=ev.name, kind=ev.kind, source=ev.source,
              session_id=ev.session_id, status=status, decision=decision, rule_id=rule_id, reason=reason,
              input_sha256=_sha(row["input"]), output_sha256=_sha(row["output"]),
              signals=[f"{x['check']}:{x['effect']}" for x in signals] or None, would=would)
    audit_log.info(json.dumps({k: row[k] for k in ("id", "created_at", "client", "source", "session_id",
                                                    "kind", "name", "status", "rule_id")}))
    forwarder.emit(siem_record("decision", row))
    if status == "awaiting_approval":
        notify_approval_needed(row)
    return Decision(event_id=row["id"], decision=decision, reason=reason, rule_id=rule_id,
                    status=status, approval_deadline=deadline, signals=signals or None, would=would, risk=risk_score)


# --------------------------------------------------------------------------- notifications + approval links

def settings() -> dict:
    """Notification settings: env vars are the defaults, the dashboard's Settings page overrides them."""
    defaults = {"public_url": PUBLIC_URL, "slack_webhook": APPROVAL_WEBHOOK_URL,
                "ntfy_topic": os.getenv("NTFY_TOPIC", ""), "ntfy_server": os.getenv("NTFY_SERVER", "https://ntfy.sh"),
                "notify_as": os.getenv("NOTIFY_APPROVER", "admin"), "weekly_digest": True,
                "second_person": os.getenv("SECOND_PERSON_APPROVAL", "").lower() in ("1", "true", "yes"),
                "customers": [], "slack_signing_secret": os.getenv("SLACK_SIGNING_SECRET", ""),
                "teams_webhook": os.getenv("TEAMS_WEBHOOK_URL", ""), "email_to": os.getenv("APPROVAL_EMAIL_TO", ""),
                "smtp_host": os.getenv("SMTP_HOST", ""), "smtp_port": int(os.getenv("SMTP_PORT", "587") or 587),
                "smtp_user": os.getenv("SMTP_USER", ""), "smtp_password": os.getenv("SMTP_PASSWORD", ""),
                "smtp_from": os.getenv("SMTP_FROM", ""), "siem_url": os.getenv("SIEM_URL", ""),
                "siem_token": os.getenv("SIEM_TOKEN", ""), "siem_format": os.getenv("SIEM_FORMAT", "json")}
    return {**defaults, **state_get("settings", {})}


_secret_cache: bytes | None = None


def _link_secret() -> bytes:
    """Signs approval links. From GATEWAY_SECRET, else data/secret.key (created once)."""
    global _secret_cache
    if _secret_cache is None:
        if env := os.getenv("GATEWAY_SECRET"):
            _secret_cache = env.encode()
        else:
            path = KEYS_PATH.parent / "secret.key"
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(secrets.token_hex(32))
            except FileExistsError:
                pass
            _secret_cache = path.read_text().strip().encode()
    return _secret_cache


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_link_token(event_id: str, approver: str) -> str:
    """A link that lets `approver` decide this one event, and nothing else. It stops working once
    the event is decided or expires."""
    payload = _b64(json.dumps([event_id, approver]).encode())
    sig = _b64(hmac.new(_link_secret(), payload.encode(), hashlib.sha256).digest()[:18])
    return f"{payload}.{sig}"


def read_link_token(token: str) -> tuple[str, str]:
    try:
        payload, sig = token.split(".")
        good = _b64(hmac.new(_link_secret(), payload.encode(), hashlib.sha256).digest()[:18])
        if not hmac.compare_digest(sig, good):
            raise ValueError
        event_id, approver = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return event_id, approver
    except Exception:
        raise HTTPException(404, "this approval link is not valid")


def _preview(stored_json: str | None, limit: int = 280) -> str:
    s = stored_json or ""
    return s if len(s) <= limit else s[:limit] + "…"


def approval_message(row: dict) -> tuple[str, str]:
    who = row["source"] or row["client"]
    title = f"Approve {row['name']}?"
    body = f"{who} wants to run {row['name']} ({row['reason']}).\n{_preview(row['input'])}"
    for s in json.loads(row.get("signals") or "[]"):
        if s.get("check") == "effect":
            body += f"\nWhat it changes: {s['message']}"
    return title, body


DISCORD_MARKDOWN = re.compile(r"([\\`*_~|>\[\]()#-])")


def discord_escape(s: str) -> str:
    return DISCORD_MARKDOWN.sub(r"\\\1", s)


def slack_escape(s: str) -> str:
    """Slack's own escaping, so text from the agent can't become a link (<url|Approve>) or a mention (<!channel>)."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_blocks(title: str, body: str, token: str, link: str, expires: str) -> list[dict]:
    """The approval as a Slack message with Approve / Reject buttons (Squidbrake's Slack app sends the click to
    /v1/slack/actions). Each button carries the same signed, one-event token as the one-tap link."""
    text = f"*{slack_escape(title)}*\n{slack_escape(body)}"
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}},
        {"type": "actions", "block_id": "squidbrake", "elements": [
            {"type": "button", "action_id": "approve", "style": "primary", "value": token,
             "text": {"type": "plain_text", "text": "Approve"}},
            {"type": "button", "action_id": "reject", "style": "danger", "value": token,
             "text": {"type": "plain_text", "text": "Reject"}},
            {"type": "button", "action_id": "open", "url": link, "text": {"type": "plain_text", "text": "Details"}},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Expires {slack_escape(expires or '')}"}]},
    ]


def email_ready(cfg: dict) -> bool:
    return bool(cfg.get("smtp_host") and cfg.get("email_to"))


def send_email(cfg: dict, subject: str, text: str) -> bool:
    """Email `text` to the addresses in Settings, through the SMTP server set there. Never raises."""
    if not email_ready(cfg):
        return False
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = cfg.get("smtp_from") or cfg.get("smtp_user") or "squidbrake@localhost"
    msg["To"] = ", ".join(a.strip() for a in str(cfg["email_to"]).split(",") if a.strip())
    msg.set_content(text)
    port = int(cfg.get("smtp_port") or 587)
    try:
        smtp = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=15) if port == 465 else smtplib.SMTP(cfg["smtp_host"], port, timeout=15)
        with smtp:
            if port != 465:
                smtp.ehlo()
                if smtp.has_extn("starttls"):
                    smtp.starttls()
            if cfg.get("smtp_user"):
                smtp.login(cfg["smtp_user"], cfg.get("smtp_password") or "")
            smtp.send_message(msg)
        return True
    except Exception:
        log.exception("email to %s failed", msg["To"])
        return False


def send_teams(webhook: str, title: str, body: str, link: str | None = None) -> bool:
    """A Microsoft Teams message (a Workflows webhook: "Post to a channel when a webhook request is received"), as an
    Adaptive Card. Its button opens the one-tap approval page; Teams can't decide in the card itself without an app."""
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": title[:300], "weight": "Bolder", "size": "Medium", "wrap": True},
                     {"type": "TextBlock", "text": body[:3500], "wrap": True}]}
    if link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Review and approve or reject", "url": link}]
    try:
        httpx.post(webhook, timeout=10, json={"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}).raise_for_status()
        return True
    except Exception:
        log.exception("Teams message failed")
        return False


def _truncate_discord(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    if limit <= 0:
        return ""
    truncated = s[:limit - 1]
    trailing_backslashes = len(truncated) - len(truncated.rstrip("\\"))
    if trailing_backslashes % 2:
        truncated = truncated[:-1]
    return truncated + "…"


def notify_approval_needed(row: dict) -> None:
    """Tell a human, wherever they are: Slack (or any incoming webhook) and/or a phone push via ntfy.
    Both carry a signed link that opens a one-tap Approve / Reject page."""
    cfg = settings()
    if not (cfg["slack_webhook"] or cfg["ntfy_topic"] or cfg.get("teams_webhook") or email_ready(cfg)):
        return
    base = (cfg["public_url"] or "http://localhost:8080").rstrip("/")
    token = make_link_token(row["id"], cfg["notify_as"])
    link = f"{base}/a/{token}"
    title, body = approval_message(row)
    expires = row["approval_deadline"]

    def send():
        if cfg["slack_webhook"]:
            try:
                if any(host in cfg["slack_webhook"] for host in (
                        "discord.com/api/webhooks/", "discordapp.com/api/webhooks/")):
                    link_message = f"[Review and approve or reject]({link}) (expires {expires})"
                    content_limit = 1999
                    prefix = f"**{discord_escape(title)}**\n"
                    suffix = f"\n{link_message}"
                    prefix = _truncate_discord(prefix, max(0, content_limit - len(suffix)))
                    body_limit = max(0, content_limit - len(prefix) - len(suffix))
                    discord_body = _truncate_discord(discord_escape(body), body_limit)
                    payload = {
                        "content": f"{prefix}{discord_body}{suffix}",
                        "allowed_mentions": {"parse": []},
                    }
                else:
                    payload = {
                        "text": f":raised_hand: *{slack_escape(title)}*\n{slack_escape(body)}\n"
                                f"<{link}|Review and approve or reject> (expires {expires})",
                        "event": {k: row[k] for k in ("id", "name", "kind", "source", "session_id", "client",
                                                      "rule_id", "reason", "approval_deadline")},
                    }
                    if cfg.get("slack_signing_secret"):
                        # Squidbrake's Slack app (Settings): decide right in the message, no page to open
                        payload["blocks"] = slack_blocks(title, body, token, link, expires)
                httpx.post(cfg["slack_webhook"], timeout=10, json=payload).raise_for_status()
            except Exception:
                log.exception("Slack/webhook notification failed for event %s", row["id"])
        if cfg["ntfy_topic"]:
            try:
                httpx.post(cfg["ntfy_server"].rstrip("/"), timeout=10, json={
                    "topic": cfg["ntfy_topic"], "title": title, "message": body, "priority": 4,
                    "tags": ["raised_hand"], "click": link,
                    "actions": [
                        {"action": "http", "label": "Approve", "url": f"{base}/v1/a/{token}/approve", "method": "POST", "clear": True},
                        {"action": "http", "label": "Reject", "url": f"{base}/v1/a/{token}/reject", "method": "POST", "clear": True},
                    ],
                }).raise_for_status()
            except Exception:
                log.exception("phone notification failed for event %s", row["id"])
        if cfg.get("teams_webhook"):
            send_teams(cfg["teams_webhook"], title, f"{body}\n\nExpires {expires}", link)
        # Only the review page's link: mail scanners open links, so nothing in an email decides by being opened.
        send_email(cfg, title, f"{body}\n\nReview and approve or reject: {link}\n(expires {expires})")

    threading.Thread(target=send, daemon=True).start()


forwarder = siem.Forwarder(lambda: settings())


def siem_record(kind: str, r) -> dict:
    """What a SIEM gets for an event: who, which tool, the decision and why, and the stored (redacted) input."""
    g = r.get if isinstance(r, dict) else (lambda k, d=None: getattr(r, k, d))
    return {"type": kind, "id": g("id"), "time": g("decided_at") or g("created_at"), "agent": g("source") or g("client"),
            "key": g("client"), "session": g("session_id"), "tool": g("name"), "kind": g("kind"),
            "decision": g("decision"), "status": g("status"), "rule_id": g("rule_id"), "reason": g("reason"),
            "decided_by": g("decided_by"), "note": g("decision_note"), "risk": g("risk"), "would": g("would"),
            "input": (g("input") or "")[:500] or None}


def expire_overdue() -> int:
    """Apply each overdue approval's on_timeout outcome. Idempotent, safe from any worker."""
    now = utcnow()
    with engine.connect() as conn:  # cheap check first; this runs every couple of seconds
        if conn.execute(select(events.c.id).where(events.c.status == "awaiting_approval",
                                                  events.c.approval_deadline < now).limit(1)).first() is None:
            return 0
    n = 0
    with audited_tx() as conn:
        overdue = conn.execute(select(events.c.id, events.c.approval_on_timeout).where(
            events.c.status == "awaiting_approval", events.c.approval_deadline < now)).all()
        for eid, outcome in overdue:
            outcome = outcome or "deny"
            if conn.execute(update(events).where(events.c.id == eid, events.c.status == "awaiting_approval").values(
                    status="denied" if outcome == "deny" else "pending", decision=outcome, decided_by="timeout",
                    decided_at=now, decision_note=f"no human decision before the deadline; on_timeout={outcome}")).rowcount:
                audit(conn, "timeout", "event.expired", eid, outcome=outcome)
                forwarder.emit(siem_record("timed_out", conn.execute(select(events).where(events.c.id == eid)).first()))
                n += 1
    if n:
        log.info("approvals: %d expired", n)
    return n


def can_approve(who: str) -> bool:
    return keystore.can_approve(who)


def decide(event_id: str, outcome: Literal["allow", "deny"], who: str, note: str | None,
           via: str = "dashboard") -> Decision:
    expire_overdue()
    with audited_tx() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
        if row is None:
            raise HTTPException(404, "event not found")
        if row.status != "awaiting_approval":
            raise HTTPException(409, f"event is not awaiting approval (status '{row.status}'"
                                     f"{', decided by ' + row.decided_by if row.decided_by else ''})")
        if not can_approve(who):
            raise HTTPException(403, f"'{who}' can't approve. Ask an admin to give them approval rights in Team.")
        allowed = json.loads(row.approvers) if row.approvers else None
        if keystore.enabled and allowed and not keystore.matches(who, allowed):
            raise HTTPException(403, f"rule '{row.rule_id}' only accepts approval from: {', '.join(allowed)}")
        if keystore.enabled and who == row.client:
            raise HTTPException(403, "a key cannot approve its own request")
        owner = keystore.info(row.client).get("owner") if keystore.enabled else None
        if owner and owner == who and settings().get("second_person"):
            raise HTTPException(403, f"'{row.client}' is {who}'s own agent and second-person approval is on, "
                                     "so someone else has to decide")
        # Conditional update: if two approvers click at once, exactly one wins.
        won = conn.execute(update(events).where(
            events.c.id == event_id, events.c.status == "awaiting_approval",
        ).values(status="pending" if outcome == "allow" else "denied", decision=outcome,
                 decided_by=who, decided_at=utcnow(), decision_note=note)).rowcount
        if not won:
            raise HTTPException(409, "event was decided by someone else a moment ago")
        audit(conn, who, "event.approved" if outcome == "allow" else "event.rejected", event_id, note=note, via=via)
        forwarder.emit(siem_record("approved" if outcome == "allow" else "rejected",
                                   conn.execute(select(events).where(events.c.id == event_id)).first()))
    audit_log.info(json.dumps({"id": event_id, "approval": outcome, "decided_by": who, "via": via}))
    return current_decision(event_id)


def current_decision(event_id: str) -> Decision:
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    return Decision(event_id=row.id, decision=row.decision, reason=row.reason or "", rule_id=row.rule_id,
                    status=row.status, approval_deadline=row.approval_deadline,
                    decided_by=row.decided_by, decision_note=row.decision_note)


async def wait_for_decision(event_id: str, wait: float) -> Decision:
    """Long-poll the DB (shared by all workers) until a human or the timeout decides, or `wait` runs out."""
    end = time.monotonic() + wait
    while True:
        d = await run_in_threadpool(current_decision, event_id)
        if d.decision == "review" and d.approval_deadline and d.approval_deadline < utcnow():
            await run_in_threadpool(expire_overdue)  # don't wait for the sweeper
            d = await run_in_threadpool(current_decision, event_id)
        if d.decision != "review" or time.monotonic() >= end:
            return d
        await asyncio.sleep(min(0.5, max(end - time.monotonic(), 0)))


def complete_event(event_id: str, res: ResultIn) -> dict:
    with audited_tx() as conn:
        current = conn.execute(select(events.c.status).where(events.c.id == event_id)).scalar_one_or_none()
        if current is None:
            raise HTTPException(404, "event not found")
        if current != "pending":
            raise HTTPException(409, f"event is already '{current}'")  # audit records are write-once
        status = "failed" if res.error else "completed"
        output = to_stored_json(res.output)
        conn.execute(update(events).where(events.c.id == event_id).values(
            status=status, completed_at=utcnow(), output=output, error=res.error, duration_ms=res.duration_ms,
        ))
        audit(conn, None, f"event.{status}", event_id, output_sha256=_sha(output), error=res.error,
              duration_ms=res.duration_ms)
    audit_log.info(json.dumps({"id": event_id, "status": status, "duration_ms": res.duration_ms}))
    return {"event_id": event_id, "status": status}


def row_to_dict(row) -> dict:
    d = dict(row._mapping)
    for f in ("input", "output", "metadata", "approvers", "signals"):
        if d.get(f) is not None:
            d[f] = json.loads(d[f])
    return d


# --------------------------------------------------------------------------- app


async def _retention_loop():
    while True:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat().replace("+00:00", "Z")

        def purge():
            with engine.begin() as conn:
                return conn.execute(delete(events).where(events.c.created_at < cutoff)).rowcount

        try:
            n = await run_in_threadpool(purge)
            if n:
                log.info("retention: purged %d events older than %s", n, cutoff)
        except Exception:
            log.exception("retention purge failed")
        await asyncio.sleep(3600)


async def _expiry_loop():
    while True:
        try:
            await run_in_threadpool(expire_overdue)
        except Exception:
            log.exception("approval expiry failed")
        await asyncio.sleep(2)


CAUGHT_ORDER = {"blocked": 0, "rejected": 1, "would have been blocked": 2, "would have waited for a person": 3}


def caught(days: int = 7, limit: int = 8) -> list[dict]:
    """What Squidbrake stopped (or, in shadow mode, would have), newest of each kind first: the call, why, what it
    would have changed (when the hook measured it), and who decided. Inputs are the stored, redacted copies."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    blocked = (events.c.status == "denied") & events.c.decided_by.is_(None)
    rejected = (events.c.decision == "deny") & events.c.decided_by.isnot(None) & (events.c.decided_by != "timeout")
    with engine.connect() as conn:
        rows = conn.execute(select(events).where(
            events.c.created_at >= since, blocked | rejected | events.c.would.isnot(None))
            .order_by(events.c.created_at.desc()).limit(500)).all()
    out = []
    for r in rows:
        if r.would:
            outcome = "would have been blocked" if r.would == "deny" else "would have waited for a person"
        elif r.decided_by:
            outcome = "rejected"
        else:
            outcome = "blocked"
        try:
            inp = json.loads(r.input or "null")
        except ValueError:
            inp = r.input
        what = (inp.get("command") if isinstance(inp, dict) else None) or r.name
        effect = next((s["message"] for s in json.loads(r.signals or "[]") if s.get("check") == "effect"), None)
        reason = (r.reason or "").removeprefix("Shadow mode, allowed. ")
        out.append({"at": r.created_at, "agent": r.source or r.client, "tool": r.name, "what": str(what)[:120],
                    "why": reason[:200], "outcome": outcome, "by": r.decided_by if outcome == "rejected" else None,
                    "note": r.decision_note if outcome == "rejected" else None, "effect": effect})
    out.sort(key=lambda x: x["at"], reverse=True)               # newest first...
    out.sort(key=lambda x: CAUGHT_ORDER[x["outcome"]])         # ...within blocked, rejected, would-block, would-hold
    seen, picked = set(), []
    for x in out:                                    # the same thing caught ten times is one line
        key = (x["outcome"], x["what"])
        if key not in seen:
            seen.add(key)
            picked.append(x)
    return picked[:limit]


def digest_text(r: dict, catches: list[dict] | None = None) -> str:
    a, s = r["approvals"], r["by_status"]
    sh = r.get("shadow") or {}
    lines = [f":bar_chart: *What your AI agents did this week* ({r['days']} days)"]
    if sh.get("would_block") or sh.get("would_hold"):
        lines.append(f"Shadow mode: nothing was stopped, but Squidbrake would have blocked {sh['would_block']} and held "
                     f"{sh['would_hold']} for a person.")
    if catches:
        lines.append("*What it caught:*")
        for c in catches:
            who = f" by {c['by']}" + (f' ("{c["note"]}")' if c.get("note") else "") if c["by"] else ""
            lines.append(f"• {c['outcome'].capitalize()}{who}: `{c['what']}` ({c['agent']}). {c['why']}"
                         + (f" It would have: {c['effect']}" if c.get("effect") else ""))
    lines += [
             f"Signed off by a person: {a['held']} held, {a['approved']} approved, {a['rejected']} rejected, "
             f"Signed off by a person: {a['held']} held, {a['approved']} approved, {a['rejected']} rejected, "
             f"{a['timed_out']} timed out"
             + (f", median decision time {int(a['median_seconds_to_decide'])}s." if a['median_seconds_to_decide'] is not None else "."),
             f"{r['total']} agent actions on the record: {s.get('completed', 0)} completed, {s.get('denied', 0)} refused, "
             f"{s.get('failed', 0)} failed."]
    if r["agents"]:
        lines.append("Most active: " + ", ".join(f"{g['agent']} ({g['total']})" for g in r["agents"][:5]))
    au = r["audit"]
    lines.append(f"Record: {'intact' if au['ok'] else 'BROKEN at entry ' + str(au['first_bad_seq'])}, "
                 f"{au['entries']} entries, fingerprint {str(au['head_hash'])[:16]}")
    if r["blocked_by_rule"]:
        lines.append("Most refused by: " + ", ".join(f"{b['rule_id']} ({b['count']})" for b in r["blocked_by_rule"][:3]))
    return "\n".join(lines)


def maybe_send_digest() -> None:
    """Every Monday from 09:00 (server local time), once per week, post last week's summary to Slack."""
    cfg, now = settings(), datetime.now()
    if not ((cfg["slack_webhook"] or cfg.get("teams_webhook") or email_ready(cfg)) and cfg.get("weekly_digest")) \
            or now.weekday() != 0 or now.hour < 9:
        return
    week = now.strftime("%G-W%V")
    with audited_tx() as conn:
        if conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "digest_week")).scalar() == json.dumps(week):
            return
        state_set(conn, "digest_week", week)
    text = digest_text(build_report(7), caught(7))
    plain = text.replace(":bar_chart: ", "").replace("*", "").replace("`", "")
    if cfg["slack_webhook"]:
        discord = any(h in cfg["slack_webhook"] for h in ("discord.com/api/webhooks/", "discordapp.com/api/webhooks/"))
        try:
            body = {"content": _truncate_discord(text.replace(":bar_chart: ", "").replace("*", "**"), 1999),
                    "allowed_mentions": {"parse": []}} if discord else {"text": text}
            httpx.post(cfg["slack_webhook"], json=body, timeout=15).raise_for_status()
        except Exception:
            log.exception("weekly digest failed")
    if cfg.get("teams_webhook"):
        send_teams(cfg["teams_webhook"], "What your AI agents did this week", plain)
    send_email(cfg, "What your AI agents did this week", plain)


async def _digest_loop():
    while True:
        try:
            await run_in_threadpool(maybe_send_digest)
        except Exception:
            log.exception("weekly digest check failed")
        await asyncio.sleep(600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if keystore.disabled:
        log.warning("GATEWAY_AUTH=off: authentication is DISABLED. Do not expose this publicly.")
    else:
        # Normally done by `python server.py`; this covers starting uvicorn directly.
        if created := keystore.ensure_initialized():
            print_banner(None, created)
        if not keystore.names():
            log.warning("no API keys exist; add one with: python server.py add-key NAME --approver")
        elif not keystore.approvers:
            log.warning("no key can approve: calls held by 'review' rules can only time out "
                        "(add one with: python server.py add-key NAME --approver)")
        elif keystore.from_env and (unknown := keystore.approvers - keystore.names()):
            log.warning("GATEWAY_APPROVERS names keys that don't exist: %s", ", ".join(sorted(unknown)))
    policy._maybe_reload()
    app.state.http = httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=False)
    # MCP by URL: no read timeout, a held call or an event stream can stay open a long time
    app.state.mcp_http = httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None), follow_redirects=False)
    if servers := mcp_servers():
        await run_in_threadpool(hub.sync, servers)
    tasks = [asyncio.create_task(_expiry_loop()), asyncio.create_task(_digest_loop())]
    if RETENTION_DAYS > 0:
        tasks.append(asyncio.create_task(_retention_loop()))
    # usage counts for the pilot programme: does nothing unless this install joined one (squidbrake pilot join)
    tasks.append(asyncio.create_task(pilot.loop(PILOT_DIR, lambda: pilot.usage(
        engine, events, policy.mode, len(policy.rules), VERSION,
        reasons={r["id"]: r.get("reason", "") for r in policy.rules + policy.sequences},
        connected=_agents_connected_here()))))
    yield
    for t in tasks:
        t.cancel()
    await app.state.http.aclose()
    await app.state.mcp_http.aclose()
    hub.stop_all()


app = FastAPI(title="Squidbrake", version="1.0.0", lifespan=lifespan)


def auth(request: Request, x_gateway_key: str | None = Header(None)) -> str:
    name = keystore.identify(x_gateway_key or "")
    if name is None:
        raise HTTPException(401, "missing or invalid X-Gateway-Key")
    if name in READ_ONLY_KEYS and (request.method not in ("GET", "HEAD") or request.url.path.startswith("/proxy/")):
        raise HTTPException(403, f"'{name}' is a read-only key: it can look, but not change anything")
    return name


def person(who: str = Depends(auth)) -> str:
    """History, reports and settings are for people. Agent keys can only ask and report."""
    if not keystore.is_person(who):
        raise HTTPException(403, f"'{who}' is an agent key; open the dashboard with a person's key")
    return who


def admin(who: str = Depends(auth)) -> str:
    if not keystore.is_admin(who):
        raise HTTPException(403, f"'{who}' is not an admin")
    return who


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok", "rules": len(policy.rules), "time": utcnow()}


@app.post("/v1/events", response_model=Decision)
def create_event(ev: EventIn, request: Request, client: str = Depends(auth)):
    return record_event(ev, client, _ip(request))


@app.post("/v1/events/{event_id}/result")
def post_result(event_id: str, res: ResultIn, _: str = Depends(auth)):
    return complete_event(event_id, res)


@app.get("/v1/events/{event_id}/decision", response_model=Decision)
async def get_decision(event_id: str, wait: float = Query(0, ge=0, le=60,
                       description="Long-poll: hold the request up to this many seconds while awaiting approval"),
                       _: str = Depends(auth)):
    return await wait_for_decision(event_id, wait)


@app.post("/v1/events/{event_id}/approve", response_model=Decision)
def approve(event_id: str, body: ApprovalIn | None = None, who: str = Depends(auth)):
    return decide(event_id, "allow", who, body.note if body else None)


@app.post("/v1/events/{event_id}/reject", response_model=Decision)
def reject(event_id: str, body: ApprovalIn | None = None, who: str = Depends(auth)):
    return decide(event_id, "deny", who, body.note if body else None)


@app.get("/v1/me")
def me(who: str = Depends(auth)):
    i = keystore.info(who)
    return {"client": who, "kind": i["kind"], "roles": i["roles"], "is_admin": keystore.is_admin(who),
            "can_approve": can_approve(who), "auth_enabled": keystore.enabled,
            "mode": policy.mode, "shadow_agents": policy.shadow_agents}


@app.get("/v1/me/phone-link")
def phone_link(request: Request, who: str = Depends(person), x_gateway_key: str = Header("")):
    """QR code that opens the phone approvals page signed in as you. The key rides in the #fragment,
    which browsers never send to a server, and the page moves it into the phone's local storage."""
    import segno
    public = settings()["public_url"]
    base = (public or str(request.base_url)).rstrip("/")
    url = f"{base}/m#key={x_gateway_key}"
    with audited_tx() as conn:
        audit(conn, who, "phone.link_shown", None, base=base)
    return {"as": who, "url": url, "public": bool(public),
            "qr": segno.make(url, error="m").svg_data_uri(scale=5, border=2, dark="#111", light="#fff")}


# ---- team (admins)

class MemberIn(BaseModel):
    name: str = Field(..., max_length=64)
    kind: Literal["person", "agent"] = "person"
    approver: bool = False
    roles: list[str] = Field(default_factory=list)
    owner: str | None = Field(None, max_length=64, description="for an agent: the person it works for")


class MemberPatch(BaseModel):
    approver: bool | None = None
    roles: list[str] | None = None
    owner: str | None = Field(None, max_length=64, description="for an agent: the person it works for ('' clears it)")


def _team_call(fn):
    try:
        return fn()
    except ValueError as e:
        raise HTTPException(409 if keystore.from_env else 400, str(e))


@app.get("/v1/team")
def team_list(_: str = Depends(person)):
    return {"members": keystore.listing(), "managed_by_env": keystore.from_env}


@app.post("/v1/team")
def team_add(m: MemberIn, who: str = Depends(admin)):
    secret = _team_call(lambda: keystore.add(m.name, approver=m.approver, kind=m.kind, roles=m.roles, owner=m.owner))
    with audited_tx() as conn:
        audit(conn, who, "team.added", m.name, kind=m.kind, approver=m.approver, roles=m.roles, owner=m.owner)
    return {"name": m.name, "key": secret, "note": "shown once; the gateway keeps only a hash"}


@app.patch("/v1/team/{name}")
def team_update(name: str, p: MemberPatch, who: str = Depends(admin)):
    if name == who and p.roles is not None and "admin" not in p.roles:
        raise HTTPException(400, "you can't remove your own admin role")
    info = _team_call(lambda: keystore.update(name, approver=p.approver, roles=p.roles, owner=p.owner))
    with audited_tx() as conn:
        audit(conn, who, "team.updated", name, approver=info["approver"], roles=info["roles"], owner=info["owner"])
    return {"name": name, **info}


@app.delete("/v1/team/{name}")
def team_remove(name: str, who: str = Depends(admin)):
    if name == who:
        raise HTTPException(400, "you can't remove your own key")
    _team_call(lambda: keystore.remove(name))
    with audited_tx() as conn:
        audit(conn, who, "team.removed", name)
    return {"removed": name}


# ---- emergency stop

class StopIn(BaseModel):
    agent: str | None = Field(None, description="an agent's source or key name; omit to stop everything")
    session: str | None = Field(None, max_length=200, description="stop just this session (one conversation)")
    reason: str | None = Field(None, max_length=500)
    minutes: int | None = Field(None, ge=1, le=7 * 24 * 60, description="end the stop by itself after this long")


@app.get("/v1/controls")
def controls(_: str = Depends(auth)):
    return state_get("stop", {"all": None, "agents": {}})


@app.post("/v1/controls/stop")
def controls_stop(body: StopIn, who: str = Depends(person)):
    """Anyone who can approve (or any admin) can pull the brake; only admins can release it."""
    if not (can_approve(who) or keystore.is_admin(who)):
        raise HTTPException(403, "only approvers and admins can stop agents")
    entry = {"by": who, "at": utcnow(), "reason": body.reason}
    if body.minutes:
        entry["until"] = (datetime.now(timezone.utc) + timedelta(minutes=body.minutes)).isoformat().replace("+00:00", "Z")
    target = f"session:{body.session}" if body.session else body.agent or "*"
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar()
                       or '{"all": null, "agents": {}}')
        if body.session:
            s.setdefault("sessions", {})[body.session] = entry
            # Anything still waiting in that session is rejected: nobody should approve half of a stopped run.
            waiting = conn.execute(select(events.c.id).where(events.c.session_id == body.session,
                                                             events.c.status == "awaiting_approval")).all()
            note = "The session was stopped" + (f": {body.reason}" if body.reason else "")
            for (eid,) in waiting:
                if conn.execute(update(events).where(events.c.id == eid, events.c.status == "awaiting_approval").values(
                        status="denied", decision="deny", decided_by=who, decided_at=utcnow(), decision_note=note)).rowcount:
                    audit(conn, who, "event.rejected", eid, note=note, via="session-stop")
        elif body.agent:
            s.setdefault("agents", {})[body.agent] = entry
        else:
            s["all"] = entry
        state_set(conn, "stop", s)
        audit(conn, who, "controls.stopped", target, reason=body.reason)
    log.warning("STOP (%s) by %s: %s", target if target != "*" else "all agents", who, body.reason)
    return s


@app.post("/v1/controls/resume")
def controls_resume(body: StopIn, who: str = Depends(admin)):
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar()
                       or '{"all": null, "agents": {}}')
        if body.session:
            s.setdefault("sessions", {}).pop(body.session, None)
        elif body.agent:
            s.setdefault("agents", {}).pop(body.agent, None)
        else:
            s["all"] = None
        state_set(conn, "stop", s)
        audit(conn, who, "controls.resumed", f"session:{body.session}" if body.session else body.agent or "*")
    return s


def resume_stop(agent: str | None, session: str | None, who: str) -> bool:
    """`squidbrake resume` on the gateway's own computer: the same as Resume in the dashboard. -> was one on?"""
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar()
                       or '{"all": null, "agents": {}}')
        was = s.get("sessions", {}).pop(session, None) if session else \
            s.get("agents", {}).pop(agent, None) if agent else s.get("all")
        if not agent and not session:
            s["all"] = None
        state_set(conn, "stop", s)
        if was:
            audit(conn, who, "controls.resumed", f"session:{session}" if session else agent or "*", via="command line")
    return bool(was)


def _cli_resume(args) -> int:
    if resume_stop(args.agent, args.session, "command-line"):
        what = f"session {args.session}" if args.session else args.agent or "all agents"
        print(f"Resumed {what}: their actions are checked as usual again.")
        return 0
    print("Nothing to resume: no emergency stop is on" + (f" for {args.session or args.agent}." if args.session or args.agent else "."))
    return 0


# ---- notification settings (admins)

class SettingsIn(BaseModel):
    public_url: str | None = Field(None, max_length=300)
    slack_webhook: str | None = Field(None, max_length=500)
    ntfy_topic: str | None = Field(None, max_length=100)
    ntfy_server: str | None = Field(None, max_length=300)
    notify_as: str | None = Field(None, max_length=64)
    weekly_digest: bool | None = None
    second_person: bool | None = None
    customers: list[str] | None = Field(None, max_length=5000)   # names to keep out of PRs, issues, posts (data_checks)
    slack_signing_secret: str | None = Field(None, max_length=200)  # Squidbrake's Slack app: Approve / Reject buttons
    teams_webhook: str | None = Field(None, max_length=1000)     # a Teams Workflows webhook: approvals and the weekly report
    email_to: str | None = Field(None, max_length=1000)          # comma-separated: approvals and the weekly report by email
    smtp_host: str | None = Field(None, max_length=200)
    smtp_port: int | None = Field(None, ge=1, le=65535)
    smtp_user: str | None = Field(None, max_length=200)
    smtp_password: str | None = Field(None, max_length=500)
    smtp_from: str | None = Field(None, max_length=200)
    siem_url: str | None = Field(None, max_length=1000)          # every decision, as it happens, to Splunk / Datadog / any HTTP
    siem_token: str | None = Field(None, max_length=500)
    siem_format: Literal["json", "splunk", "datadog"] | None = None


@app.get("/v1/settings")
def get_settings(_: str = Depends(admin)):
    return settings()


@app.put("/v1/settings")
def put_settings(body: SettingsIn, who: str = Depends(admin)):
    changes = body.model_dump(exclude_none=True)
    for k in ("public_url", "slack_webhook", "ntfy_server", "teams_webhook", "siem_url"):
        v = changes.get(k)
        if v and not re.match(r"^https?://", v):
            raise HTTPException(400, f"{k} must start with http:// or https://")
    if changes.get("email_to") and not all(re.fullmatch(r"[^@\s,]+@[^@\s,]+\.[^@\s,]+", a.strip())
                                           for a in changes["email_to"].split(",") if a.strip()):
        raise HTTPException(400, "email_to: email addresses, separated by commas")
    if changes.get("ntfy_topic") and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", changes["ntfy_topic"]):
        raise HTTPException(400, "ntfy_topic: letters, digits, '-' and '_' only")
    if changes.get("notify_as") and not can_approve(changes["notify_as"]):
        raise HTTPException(400, f"'{changes['notify_as']}' can't approve, so links sent as them wouldn't work")
    if "customers" in changes:
        names = list(dict.fromkeys(n.strip() for n in changes["customers"] if n.strip()))
        if any(len(n) > 200 for n in names):
            raise HTTPException(400, "customers: one name per line, up to 200 characters each")
        changes["customers"] = names
    with audited_tx() as conn:
        current = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "settings")).scalar() or "{}")
        current.update(changes)
        state_set(conn, "settings", current)
        # Record which settings changed, never the webhook secrets themselves.
        audit(conn, who, "settings.updated", None, changed=sorted(changes))
    return settings()


@app.post("/v1/settings/siem-test")
def siem_test(who: str = Depends(admin)):
    """Send one record to the SIEM now and say whether it took it."""
    cfg = settings()
    if not cfg.get("siem_url"):
        raise HTTPException(400, "set the SIEM's URL first")
    ok = forwarder.flush([{"type": "test", "id": "test", "time": utcnow(), "agent": "squidbrake", "tool": "test",
                           "decision": "allow", "reason": f"Test from {who}", "epoch": time.time()}])
    return {"ok": ok, "error": None if ok else "the SIEM didn't accept it (see the gateway log for why)"}


@app.post("/v1/settings/test")
def test_notification(who: str = Depends(admin)):
    cfg = settings()
    if not (cfg["slack_webhook"] or cfg["ntfy_topic"] or cfg.get("teams_webhook") or email_ready(cfg)):
        raise HTTPException(400, "set Slack, Teams, email or a phone topic first")
    sent, errors = [], []
    if cfg.get("teams_webhook"):
        (sent.append("Teams") if send_teams(cfg["teams_webhook"], "Squidbrake", f"Test from {who}: notifications work.")
         else errors.append("Teams: the webhook didn't accept it (see the gateway log)"))
    if email_ready(cfg):
        (sent.append("email") if send_email(cfg, "Squidbrake test", f"Test from {who}: approval requests will come here.")
         else errors.append("Email: the SMTP server didn't accept it (see the gateway log)"))
    if cfg["slack_webhook"]:
        try:
            httpx.post(cfg["slack_webhook"], json={"text": f":white_check_mark: Squidbrake test from {who}: notifications work."},
                       timeout=10).raise_for_status()
            sent.append("slack")
        except Exception as e:
            errors.append(f"Slack: {e}")
    if cfg["ntfy_topic"]:
        try:
            httpx.post(cfg["ntfy_server"].rstrip("/"), json={"topic": cfg["ntfy_topic"], "title": "Squidbrake",
                       "message": f"Test from {who}: approval requests will show up here.", "tags": ["white_check_mark"]},
                       timeout=10).raise_for_status()
            sent.append("phone")
        except Exception as e:
            errors.append(f"Phone: {e}")
    return {"sent": sent, "errors": errors}


# ---- one-tap approval links (from Slack / phone notifications; the link itself is the credential)

@app.get("/v1/a/{token}")
def link_event(token: str):
    event_id, approver = read_link_token(token)
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    d = row_to_dict(row)
    return {"approver": approver, "context": event_context(row), **{k: d[k] for k in (
        "id", "name", "kind", "source", "client", "session_id", "created_at", "status", "decision", "rule_id",
        "reason", "input", "approval_deadline", "approval_on_timeout", "decided_by", "decided_at", "decision_note",
        "signals")}}


# ---- the story behind an action, and what people decided before

def _output_preview(stored: str | None, limit: int = 700) -> str | None:
    if stored is None:
        return None
    text = _unescape(stored)
    return text if len(text) <= limit else text[:limit] + "…"


def event_context(row, limit: int = 15) -> list[dict]:
    """What the same agent did just before this, in the same conversation (oldest first)."""
    if row.session_id:
        scope = events.c.session_id == row.session_id
    else:
        start = (datetime.fromisoformat(row.created_at.replace("Z", "+00:00")) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        scope = and_(events.c.source == row.source, events.c.created_at >= start)
    with engine.connect() as conn:
        # <= : created_at is millisecond-precise, so a step taken in the same millisecond still counts as "before".
        rows = conn.execute(select(events).where(scope, events.c.created_at <= row.created_at, events.c.id != row.id)
                            .order_by(events.c.created_at.desc()).limit(limit)).all()
    return [{"id": r.id, "created_at": r.created_at, "name": r.name, "status": r.status, "decision": r.decision,
             "input": json.loads(r.input) if r.input else None, "output": _output_preview(r.output),
             "decided_by": r.decided_by, "decision_note": r.decision_note, "error": r.error} for r in reversed(rows)]


@app.get("/v1/events/{event_id}/context")
def get_event_context(event_id: str, _: str = Depends(person)):
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    return {"event_id": event_id, "steps": event_context(row)}


@app.get("/v1/agent/decisions")
def agent_decisions(days: int = Query(7, ge=1, le=90), limit: int = Query(20, ge=1, le=100), who: str = Depends(auth)):
    """For agents: what people decided about YOUR earlier requests (never anyone else's)."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    with engine.connect() as conn:
        rows = conn.execute(select(events).where(events.c.client == who, events.c.decided_by.isnot(None),
                                                 events.c.created_at >= since)
                            .order_by(events.c.decided_at.desc()).limit(limit)).all()
    return {"decisions": [{
        "tool": r.name, "input": json.loads(r.input) if r.input else None,
        "outcome": ("approved" if r.decision == "allow" else "rejected") if r.decided_by != "timeout" else f"timed out ({r.decision})",
        "decided_by": r.decided_by, "note": r.decision_note, "when": r.decided_at, "rule": r.reason,
    } for r in rows]}


@app.post("/v1/slack/actions")
async def slack_actions(request: Request):
    """Approve / Reject clicked in a Slack message (Squidbrake's Slack app, Settings). Slack signs each request with
    the app's signing secret; the button carries the event's signed token, so a click decides that one event only."""
    secret = settings().get("slack_signing_secret") or ""
    if not secret:
        raise HTTPException(404, "Slack buttons aren't set up on this gateway")
    raw = await request.body()
    ts, sig = request.headers.get("x-slack-request-timestamp", ""), request.headers.get("x-slack-signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
        raise HTTPException(401, "stale or missing Slack timestamp")
    good = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good):
        raise HTTPException(401, "bad Slack signature")
    from urllib.parse import parse_qs
    try:
        payload = json.loads(parse_qs(raw.decode())["payload"][0])
        action = payload["actions"][0]
    except (KeyError, IndexError, ValueError):
        raise HTTPException(400, "not a Slack button click")
    if action.get("action_id") not in ("approve", "reject"):
        return Response(status_code=200)                    # "Details" just opens the page
    event_id, approver = read_link_token(str(action.get("value", "")))
    user = payload.get("user") or {}
    clicker = re.sub(r"[^\w.@-]", "", str(user.get("username") or user.get("name") or user.get("id") or "someone"))[:60]
    outcome = "allow" if action["action_id"] == "approve" else "deny"
    try:
        d = await run_in_threadpool(decide, event_id, outcome, approver, f"in Slack by @{clicker}", "slack")
        done = f"{':white_check_mark: Approved' if d.decision == 'allow' else ':no_entry: Rejected'} by @{clicker} in Slack"
    except HTTPException as e:
        done = f":information_source: {e.detail}"
    url = str(payload.get("response_url") or "")
    if url.startswith("https://hooks.slack.com/"):          # replace the buttons with what happened
        original = (payload.get("message") or {}).get("blocks") or []
        blocks = [b for b in original if b.get("type") == "section"][:1] + [
            {"type": "context", "elements": [{"type": "mrkdwn", "text": done}]}]

        async def tell():
            try:
                await request.app.state.http.post(url, json={"replace_original": True, "text": done, "blocks": blocks},
                                                   timeout=10)
            except httpx.HTTPError:
                log.warning("couldn't update the Slack message for %s", event_id)
        asyncio.create_task(tell())
    return Response(status_code=200)


def slack_manifest(public_url: str) -> dict:
    """A Slack app that posts approvals with buttons: create it from this manifest, install it to a channel."""
    return {"display_information": {"name": "Squidbrake", "description": "Approve or reject what your AI agents want to do"},
            "features": {"bot_user": {"display_name": "Squidbrake", "always_online": False}},
            "oauth_config": {"scopes": {"bot": ["incoming-webhook"]}},
            "settings": {"interactivity": {"is_enabled": True, "request_url": f"{public_url.rstrip('/')}/v1/slack/actions"},
                         "org_deploy_enabled": False, "socket_mode_enabled": False, "token_rotation_enabled": False}}


@app.get("/v1/slack/manifest")
def get_slack_manifest(request: Request, _: str = Depends(admin)):
    base = settings().get("public_url") or str(request.base_url)
    return {"manifest": slack_manifest(base), "public": bool(settings().get("public_url"))}


@app.post("/v1/a/{token}/{outcome}", response_model=Decision)
def link_decide(token: str, outcome: Literal["approve", "reject"], body: ApprovalIn | None = None):
    event_id, approver = read_link_token(token)
    return decide(event_id, "allow" if outcome == "approve" else "deny", approver,
                  body.note if body else None, via="link")


# ---- reports + audit

def build_report(days: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    agent = func.coalesce(events.c.source, events.c.client).label("agent")
    in_period = events.c.created_at >= since
    human = events.c.decided_by.isnot(None) & (events.c.decided_by != "timeout")
    count_if = lambda cond: func.sum(case((cond, 1), else_=0))
    with engine.connect() as conn:
        by_status = dict(conn.execute(select(events.c.status, func.count()).where(in_period).group_by(events.c.status)).all())
        agents = [dict(r._mapping) for r in conn.execute(select(
            agent, func.count().label("total"),
            count_if(events.c.status == "denied").label("denied"),
            count_if(events.c.approval_deadline.isnot(None)).label("held"),
            count_if(human & (events.c.decision == "allow")).label("approved"),
            count_if(human & (events.c.decision == "deny")).label("rejected"),
            count_if(events.c.status == "failed").label("failed"),
            count_if(events.c.would == "deny").label("would_block"),
            count_if(events.c.would == "review").label("would_hold"),
            func.max(events.c.created_at).label("last_seen"),
        ).where(in_period).group_by(agent).order_by(text("total DESC")))]
        blocked = [dict(r._mapping) for r in conn.execute(select(
            events.c.rule_id, events.c.reason, func.count().label("count"),
        ).where(in_period, events.c.status == "denied", events.c.decided_by.is_(None))
            .group_by(events.c.rule_id, events.c.reason).order_by(text("count DESC")).limit(15))]
        top_tools = [dict(r._mapping) for r in conn.execute(select(
            events.c.name, func.count().label("count")).where(in_period)
            .group_by(events.c.name).order_by(text("count DESC")).limit(10))]
        decided = conn.execute(select(events.c.created_at, events.c.decided_at, events.c.decided_by, events.c.decision)
                               .where(in_period, events.c.decided_by.isnot(None)).limit(20000)).all()
    parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    waits = sorted((parse(d) - parse(c)).total_seconds() for c, d, by, _ in decided if by != "timeout" and d)
    by_approver: dict[str, dict] = {}
    for _, _, by, dec in decided:
        if by != "timeout":
            a = by_approver.setdefault(by, {"approver": by, "approved": 0, "rejected": 0})
            a["approved" if dec == "allow" else "rejected"] += 1
    approvals = {
        "held": sum(a["held"] or 0 for a in agents),
        "approved": sum(1 for *_, by, dec in decided if by != "timeout" and dec == "allow"),
        "rejected": sum(1 for *_, by, dec in decided if by != "timeout" and dec == "deny"),
        "timed_out": sum(1 for *_, by, _d in decided if by == "timeout"),
        "waiting_now": by_status.get("awaiting_approval", 0),
        "median_seconds_to_decide": waits[len(waits) // 2] if waits else None,
        "by_approver": sorted(by_approver.values(), key=lambda a: -(a["approved"] + a["rejected"])),
    }
    return {"generated_at": utcnow(), "days": days, "since": since, "total": sum(by_status.values()),
            "by_status": by_status, "agents": agents, "approvals": approvals, "blocked_by_rule": blocked,
            "top_tools": top_tools, "controls": state_get("stop", {"all": None, "agents": {}}),
            "shadow": {"mode": policy.mode, "agents": policy.shadow_agents,
                       "would_block": sum(a["would_block"] or 0 for a in agents),
                       "would_hold": sum(a["would_hold"] or 0 for a in agents)},
            "audit": verify_audit_chain()}


CONTROL_CHANGES = ("team.", "settings.", "controls.", "policy.version")


def build_evidence(days: int, who: str) -> dict:
    """The numbers behind the evidence pack (evidence.py renders them)."""
    policy._maybe_reload()  # from the command line nothing has evaluated an action yet, so load rules.yaml now
    rep = build_report(days)
    since = rep["since"]
    with engine.connect() as conn:
        changes = [dict(r._mapping) for r in conn.execute(
            select(audit_trail.c.at, audit_trail.c.actor, audit_trail.c.action, audit_trail.c.target)
            .where(audit_trail.c.at >= since, or_(*[audit_trail.c.action.startswith(c) for c in CONTROL_CHANGES]))
            .order_by(audit_trail.c.seq).limit(500))]
        versions = conn.execute(select(func.count()).select_from(policy_versions)
                                .where(policy_versions.c.first_seen >= since)).scalar() or 0
        decided = conn.execute(select(events.c.client, events.c.decided_by).where(
            events.c.created_at >= since, events.c.decided_by.isnot(None), events.c.decided_by != "timeout")).all()
    members = keystore.listing() if keystore.enabled else []
    owners = {m["name"]: m.get("owner") for m in members if m["kind"] == "agent"}
    sp = {"enforced": bool(settings().get("second_person")), "decided": len(decided),
          "by_someone_else": 0, "by_owner": 0, "owner_unknown": 0}
    for client, by in decided:
        owner = owners.get(client)
        sp["owner_unknown" if not owner else "by_owner" if owner == by else "by_someone_else"] += 1
    by_action: dict[str, int] = {}
    for r in policy.rules:
        by_action[r.get("action", "allow")] = by_action.get(r.get("action", "allow"), 0) + 1
    people = [m for m in members if m["kind"] == "person"]
    return {**rep, "version": VERSION, "generated_by": who, "retention_days": RETENTION_DAYS,
            "second_person": sp,
            "policy": {"rules": len(policy.rules), "by_action": by_action, "sequences": len(policy.sequences),
                       "default": policy.default, "mode": policy.mode, "shadow_agents": policy.shadow_agents,
                       "fingerprint": policy.fingerprint, "versions_in_period": max(versions, 1)},
            "team": {"people": len(people), "approvers": sum(1 for m in people if m["approver"]),
                     "admins": sum(1 for m in people if "admin" in m["roles"]), "agents": len(owners),
                     "agents_with_owner": sum(1 for o in owners.values() if o)},
            "changes": {"entries": changes, "stops": sum(1 for c in changes if c["action"] == "controls.stopped")}}


@app.get("/v1/audit/evidence-pack")
def evidence_pack(days: int = Query(90, ge=1, le=3650), who: str = Depends(person)):
    """A printable page for an auditor: controls in place, what happened, and the requirements it speaks to."""
    with audited_tx() as conn:
        audit(conn, who, "audit.exported", None, format="evidence-pack", days=days)
    return Response(evidence.render_html(build_evidence(days, who)), media_type="text/html", headers={
        "Content-Disposition": f'inline; filename="squidbrake-evidence-pack-{datetime.now():%Y%m%d}.html"'})


@app.get("/v1/reports/summary")
def report_summary(days: int = Query(7, ge=1, le=3650), _: str = Depends(person)):
    return build_report(days)


@app.get("/v1/audit/verify")
def audit_verify(_: str = Depends(person)):
    return verify_audit_chain()


@app.get("/v1/audit/export.json")
def audit_evidence(who: str = Depends(person)):
    """Everything needed to check the history offline: python verify.py <file> (see verify.py)."""
    with audited_tx() as conn:
        audit(conn, who, "audit.exported", None, format="evidence")
    with engine.connect() as conn:
        entries = [dict(r._mapping) for r in conn.execute(select(audit_trail).order_by(audit_trail.c.seq)).all()]
        evs = [dict(r._mapping) for r in conn.execute(select(*[events.c[c] for c in EXPORT_COLUMNS])
                                                      .order_by(events.c.created_at)).all()]
        policies = {r.fingerprint: r.content for r in conn.execute(select(policy_versions)).all()}
    body = {"format": verify.FORMAT, "generated_at": utcnow(), "generated_by": who,
            "head_hash": entries[-1]["hash"] if entries else GENESIS, "entries": entries, "events": evs,
            "policies": policies,
            "how_to_check": "python verify.py this-file.json   (verify.py is in the Squidbrake repository)"}
    return Response(json.dumps(body, ensure_ascii=False, indent=1), media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="squidbrake-evidence-{datetime.now():%Y%m%d-%H%M}.json"'})


@app.get("/v1/audit/log")
def audit_entries(limit: int = Query(100, ge=1, le=1000), _: str = Depends(person)):
    with engine.connect() as conn:
        rows = conn.execute(select(audit_trail).order_by(audit_trail.c.seq.desc()).limit(limit)).all()
    return {"entries": [{**dict(r._mapping), "detail": json.loads(r.detail or "{}")} for r in rows]}


EXPORT_COLUMNS = ["created_at", "id", "source", "client", "session_id", "kind", "name", "status", "decision",
                  "rule_id", "reason", "decided_by", "decided_at", "decision_note", "completed_at", "duration_ms",
                  "error", "input", "output", "would"]


@app.get("/v1/audit/export.csv")
def audit_export(days: int = Query(30, ge=1, le=3650), who: str = Depends(person)):
    import csv, io
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    buf = io.StringIO()
    w = csv.writer(buf)
    head = verify_audit_chain()
    w.writerow([f"# Squidbrake audit export, last {days} days, generated {utcnow()} by {who}; "
                f"audit chain {'VERIFIED' if head['ok'] else 'BROKEN'} ({head['entries']} entries, head {head['head_hash']})"])
    w.writerow(EXPORT_COLUMNS)
    with engine.connect() as conn:
        for r in conn.execute(select(*[events.c[c] for c in EXPORT_COLUMNS]).where(events.c.created_at >= since)
                              .order_by(events.c.created_at)):
            w.writerow(["" if v is None else v for v in r])
    with audited_tx() as conn:
        audit(conn, who, "audit.exported", None, days=days)
    return Response(buf.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="squidbrake-audit-{datetime.now():%Y%m%d}.csv"'})


@app.get("/v1/audit/export.jsonl")
def audit_export_jsonl(days: int = Query(30, ge=1, le=3650), who: str = Depends(person)):
    import io
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    buf = io.StringIO()
    head = verify_audit_chain()

    def serialize(v):
        if isinstance(v, datetime):
            return v.isoformat().replace("+00:00", "Z")
        return v

    with engine.connect() as conn:
        for r in conn.execute(select(*[events.c[c] for c in EXPORT_COLUMNS]).where(events.c.created_at >= since)
                              .order_by(events.c.created_at)):
            row_dict = {c: serialize(v) for c, v in zip(EXPORT_COLUMNS, r)}
            for col in ("input", "output"):
                if row_dict.get(col):
                    try:
                        row_dict[col] = json.loads(row_dict[col])
                    except ValueError:
                        pass
            buf.write(json.dumps(row_dict, default=str) + "\n")
    with audited_tx() as conn:
        audit(conn, who, "audit.exported", None, days=days, format="jsonl")
    # A broken chain has no head hash: say so instead of failing, since that's exactly when someone needs this export.
    return Response(buf.getvalue(), media_type="application/jsonl", headers={
        "Content-Disposition": f'attachment; filename="squidbrake-audit-{datetime.now():%Y%m%d}.jsonl"',
        "X-Audit-Chain": "verified" if head["ok"] else "broken",
        "X-Audit-Chain-Head": head.get("head_hash") or "none",
    })


@app.post("/v1/policy/check")
def policy_check(ev: EventIn, client: str = Depends(auth)):
    """Dry run: what would the rules decide? Nothing is recorded."""
    decision, reason, rule_id, rule = policy.evaluate(
        kind=ev.kind, name=ev.name, source=ev.source, client=client, session_id=ev.session_id, input=ev.input
    )
    out = {"decision": decision, "reason": reason, "rule_id": rule_id}
    if decision == "review":
        out.update(timeout_seconds=rule["timeout_seconds"], on_timeout=rule["on_timeout"], approvers=rule["approvers"])
    return out


def event_filters(
    session_id: str | None = None, source: str | None = None, client: str | None = None,
    kind: str | None = None, name: str | None = None, status: str | None = None,
    q: str | None = Query(None, description="Substring search over name, source and session_id"),
) -> list:
    conds = [events.c[col] == val for col, val in (
        ("session_id", session_id), ("source", source), ("client", client),
        ("kind", kind), ("name", name), ("status", status)) if val]
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conds.append(or_(*(events.c[f].ilike(like, escape="\\") for f in ("name", "source", "session_id"))))
    return conds


@app.get("/v1/events")
def list_events(
    since: str | None = Query(None, description="ISO timestamp, inclusive"),
    before: str | None = Query(None, description="ISO timestamp, exclusive (use for paging)"),
    limit: int = Query(100, ge=1, le=1000),
    conds: list = Depends(event_filters),
    _: str = Depends(person),
):
    stmt = select(events).where(*conds).order_by(events.c.created_at.desc()).limit(limit)
    if since:
        stmt = stmt.where(events.c.created_at >= since)
    if before:
        stmt = stmt.where(events.c.created_at < before)
    with engine.connect() as conn:
        rows = [row_to_dict(r) for r in conn.execute(stmt)]
    return {"events": rows, "next_before": rows[-1]["created_at"] if len(rows) == limit else None}


@app.get("/v1/events/{event_id}")
def get_event(event_id: str, _: str = Depends(person)):
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    return row_to_dict(row)


@app.get("/v1/stats")
def stats(
    hours: int = Query(24, ge=1, le=24 * 365),
    bucket: Literal["hour", "day"] = "hour",
    conds: list = Depends(event_filters),
    _: str = Depends(person),
):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    where = [events.c.created_at >= since, *conds]
    # created_at is ISO text, so its prefix is the UTC bucket: "2026-09-28T14" (hour) / "2026-09-28" (day)
    key = func.substr(events.c.created_at, 1, 13 if bucket == "hour" else 10).label("bucket")
    denied = func.sum(case((events.c.status == "denied", 1), else_=0))
    failed = func.sum(case((events.c.status == "failed", 1), else_=0))
    with engine.connect() as conn:
        by_status = dict(conn.execute(
            select(events.c.status, func.count()).where(*where).group_by(events.c.status)
        ).all())
        top = conn.execute(
            select(events.c.name, func.count().label("n")).where(*where)
            .group_by(events.c.name).order_by(text("n DESC")).limit(20)
        ).all()
        timeline = conn.execute(
            select(key, func.count(), denied, failed).where(*where).group_by(key).order_by(key)
        ).all()
    return {
        "since": since, "bucket": bucket, "by_status": by_status,
        "top_names": [{"name": n, "count": c} for n, c in top],
        "timeline": [{"bucket": b, "count": c, "denied": int(d or 0), "failed": int(f or 0)} for b, c, d, f in timeline],
    }


DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")


APPROVE_HTML = Path(__file__).with_name("approve.html")
PAGE_HEADERS = {"Cache-Control": "no-cache", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                           "script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"}


@app.get("/a/{token}", include_in_schema=False)
def approve_link_page(token: str):
    """Opened from a Slack message or phone notification: one event, big Approve / Reject buttons."""
    return FileResponse(APPROVE_HTML, media_type="text/html", headers=PAGE_HEADERS)


@app.get("/m", include_in_schema=False)
def mobile_page():
    """Phone view of everything waiting for you (uses your key, like the dashboard)."""
    return FileResponse(APPROVE_HTML, media_type="text/html", headers=PAGE_HEADERS)


@app.get("/", include_in_schema=False)
def root():
    # ROOT_REDIRECT lets a demo send visitors straight in, e.g. /dashboard#key=demo (see demo/live_demo.py)
    return RedirectResponse(os.getenv("ROOT_REDIRECT", "/dashboard"))


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    # The page itself is static; every data call it makes still needs X-Gateway-Key.
    return FileResponse(DASHBOARD_HTML, media_type="text/html", headers=PAGE_HEADERS)


# --------------------------------------------------------------------------- HTTP proxy

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length", "content-encoding"}
GATEWAY_HEADERS = {"x-gateway-key", "x-gateway-source", "x-gateway-session"}


def _body_preview(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw[:MAX_PAYLOAD_CHARS].decode("utf-8", errors="replace")


@app.api_route("/proxy/{upstream}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(upstream: str, path: str, request: Request, client: str = Depends(auth)):
    policy._maybe_reload()
    base = policy.upstreams.get(upstream)
    if not base:
        raise HTTPException(404, f"unknown upstream '{upstream}' (define it under 'upstreams' in rules.yaml)")

    body = await request.body()
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP | GATEWAY_HEADERS}
    ev = EventIn(
        kind="http_request",
        name=f"{request.method} {upstream}/{path}",
        source=request.headers.get("x-gateway-source") or client,
        session_id=request.headers.get("x-gateway-session"),
        input={"method": request.method, "path": path, "query": request.url.query or None,
               "headers": fwd_headers, "body": _body_preview(body)},
    )
    decision = await run_in_threadpool(record_event, ev, client, _ip(request))
    if decision.decision == "review":
        # Hold the HTTP request open until a human (or the timeout) decides. The caller's own
        # HTTP timeout must be longer than the rule's timeout_seconds.
        left = (datetime.fromisoformat(decision.approval_deadline.replace("Z", "+00:00"))
                - datetime.now(timezone.utc)).total_seconds()
        decision = await wait_for_decision(decision.event_id, max(left, 0) + 3)
        if decision.decision == "review":  # sweeper lagging; treat as not approved
            decision.decision = "deny"
    if decision.decision == "deny":
        return JSONResponse(status_code=403, content=decision.model_dump(),
                            headers={"X-Gateway-Event-Id": decision.event_id})

    url = f"{base}/{path}" + (f"?{request.url.query}" if request.url.query else "")
    t0 = time.perf_counter()
    try:
        resp = await request.app.state.http.request(request.method, url, headers=fwd_headers, content=body)
    except httpx.HTTPError as e:
        await run_in_threadpool(complete_event, decision.event_id,
                                ResultIn(error=f"{type(e).__name__}: {e}", duration_ms=(time.perf_counter() - t0) * 1000))
        return JSONResponse(status_code=502, content={"error": "upstream unreachable", "event_id": decision.event_id})

    await run_in_threadpool(complete_event, decision.event_id, ResultIn(
        output={"status_code": resp.status_code, "headers": dict(resp.headers), "body": _body_preview(resp.content)},
        error=f"upstream returned {resp.status_code}" if resp.status_code >= 500 else None,
        duration_ms=(time.perf_counter() - t0) * 1000,
    ))
    headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP}
    headers["X-Gateway-Event-Id"] = decision.event_id
    return Response(content=resp.content, status_code=resp.status_code, headers=headers)


# --------------------------------------------------------------------------- adding rules from the dashboard

def _rule_ids(path: Path) -> list[str]:
    p = Policy(path)
    p._maybe_reload()
    return [r["id"] for r in p.rules]


def _add_rules(block: str, before: str | None, who: str, what: str) -> dict:
    try:
        backup = policy_edit.insert(policy.path, block, before, _rule_ids)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except OSError as e:
        raise HTTPException(500, f"couldn't write the rules file: {e}")
    policy._maybe_reload()
    with audited_tx() as conn:
        audit(conn, who, "policy.edited", what, backup=backup.name)
    return {"ok": True, "backup": backup.name, "rules": len(policy.rules)}


def _held_and_decided(days: int = 30):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with engine.connect() as conn:
        return conn.execute(select(events.c.name, events.c.input, events.c.rule_id, events.c.decision).where(
            events.c.created_at >= since, events.c.approval_deadline.isnot(None), events.c.decided_by.isnot(None),
            events.c.decided_by != "timeout")).all()


@app.get("/v1/report/weekly")
def weekly_report(days: int = Query(7, ge=1, le=90), _: str = Depends(person)):
    """The weekly summary (what Squidbrake caught, and the counts), ready to paste or forward."""
    catches = caught(days)
    text = digest_text(build_report(days), catches)
    return {"text": text.replace(":bar_chart: ", "").replace("*", "").replace("`", ""), "caught": catches}


@app.get("/v1/policy/suggestions")
def rule_suggestions(_: str = Depends(admin)):
    """Rules to stop asking about what people keep approving (5+ times in 30 days, never rejected)."""
    policy._maybe_reload()
    existing = {r["id"] for r in policy.rules}
    return {"suggestions": [s for s in policy_edit.suggestions(_held_and_decided(), policy.commands["tools"])
                            if s["id"] not in existing]}


@app.post("/v1/policy/suggestions/{sid}/apply")
def apply_suggestion(sid: str, who: str = Depends(admin)):
    s = next((x for x in policy_edit.suggestions(_held_and_decided(), policy.commands["tools"]) if x["id"] == sid), None)
    if s is None:
        raise HTTPException(404, "that suggestion isn't there any more")
    return _add_rules(s["yaml"], s["held_by"], who, f"suggestion:{sid}")


@app.get("/v1/policy/packs")
def rule_packs(_: str = Depends(admin)):
    policy._maybe_reload()
    have = {r["id"] for r in policy.rules}
    return {"packs": [{"id": k, "title": p["title"], "about": p["about"], "yaml": p["yaml"],
                       "added": policy_edit._ids(p["yaml"]) <= have} for k, p in policy_edit.PACKS.items()]}


@app.post("/v1/policy/packs/{pack}/apply")
def apply_pack(pack: str, who: str = Depends(admin)):
    p = policy_edit.PACKS.get(pack)
    if p is None:
        raise HTTPException(404, "no such pack")
    return _add_rules(p["yaml"], None, who, f"pack:{pack}")


# --------------------------------------------------------------------------- MCP servers by URL (mcp_hub.py)
# For agents that connect to MCP by URL: ChatGPT and claude.ai connectors, Devin, n8n, cloud agents.

hub = mcp_hub.Hub(lambda: f"http://127.0.0.1:{os.getenv('SQUIDBRAKE_LISTEN_PORT') or os.getenv('PORT') or 8080}",
                  KEYS_PATH.parent)
MCP_FORWARD = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id", "x-squidbrake-session")


def mcp_servers() -> dict[str, dict]:
    return state_get("mcp_servers", {}) or {}


class McpServerIn(BaseModel):
    url: str | None = Field(None, max_length=2000)
    headers: dict[str, str] | None = None
    auth: Literal["header", "oauth"] | None = None
    client_id: str | None = Field(None, max_length=300)
    client_secret: str | None = Field(None, max_length=500)
    scope: str | None = Field(None, max_length=1000)
    command: str | None = Field(None, max_length=500)
    args: list[str] | None = None
    env: dict[str, str] | None = None


def _mcp_public(name: str, cfg: dict, request: Request) -> dict:
    base = (settings().get("public_url") or str(request.base_url)).rstrip("/")
    oauth = cfg.get("auth") == "oauth"
    return {"name": name, "endpoint": f"{base}/mcp/{name}", "running": hub.running(name),
            "url": cfg.get("url"), "command": " ".join([cfg["command"], *cfg.get("args", [])]) if cfg.get("command") else None,
            "headers": sorted(cfg.get("headers") or {}),            # names only: the values are secrets
            "auth": "oauth" if oauth else "header", "own_app": bool(cfg.get("client_id")),
            "connected": mcp_oauth.FileTokenStorage(hub.oauth_path(name)).connected() if oauth else None,
            "sign_in": _oauth_status.get(name)}


@app.get("/v1/mcp-servers")
def list_mcp_servers(request: Request, _: str = Depends(admin)):
    return {"servers": [_mcp_public(n, c, request) for n, c in sorted(mcp_servers().items())],
            "commands_allowed": mcp_hub.COMMANDS_ALLOWED}


@app.get("/v1/mcp-catalog")
def mcp_catalog_list(_: str = Depends(person)):
    """Apps the dashboard can fill in: their official remote MCP URL and the header their token goes in."""
    return {"apps": mcp_catalog.public(), "local": mcp_catalog.LOCAL,
            "approved_clients_only": mcp_catalog.APPROVED_CLIENTS_ONLY,
            "redirect_uri": f"{(settings().get('public_url') or '').rstrip('/') or '<this gateway>'}/v1/mcp-oauth/callback"}


@app.put("/v1/mcp-servers/{name}")
def put_mcp_server(name: str, body: McpServerIn, request: Request, who: str = Depends(admin)):
    try:
        cfg = mcp_hub.check(name, body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(400, str(e))
    servers = {**mcp_servers(), name: cfg}
    with audited_tx() as conn:
        state_set(conn, "mcp_servers", servers)
        audit(conn, who, "mcp_server.saved", name, url=cfg.get("url"), headers=sorted(cfg.get("headers") or {}))
    hub.sync(servers)
    return _mcp_public(name, cfg, request)


_oauth_flows: dict[str, asyncio.Future] = {}   # sign-in state -> where the app's redirect delivers the code
_oauth_status: dict[str, str] = {}             # name -> what the last sign-in did, for the dashboard


def _oauth_redirect(request: Request) -> str:
    base = (settings().get("public_url") or str(request.base_url)).rstrip("/")
    return f"{base}/v1/mcp-oauth/callback"


@app.post("/v1/mcp-servers/{name}/connect")
async def connect_mcp_server(name: str, request: Request, who: str = Depends(admin)):
    """Start signing in to an app's MCP server (OAuth). Returns the app's sign-in page to open; the app sends the
    browser back to /v1/mcp-oauth/callback, and the proxy then uses (and refreshes) the tokens."""
    servers = mcp_servers()
    cfg = servers.get(name)
    if not cfg or cfg.get("auth") != "oauth":
        raise HTTPException(404, f"'{name}' isn't an MCP server that signs in with OAuth")
    from mcp import Client
    from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
    from mcp.shared.auth import AuthorizationCodeResult
    from urllib.parse import parse_qs, urlsplit
    storage = mcp_oauth.FileTokenStorage(hub.oauth_path(name))
    storage.forget()                                     # a fresh sign-in, with nothing left over
    redirect = _oauth_redirect(request)
    if cfg.get("client_id"):
        await mcp_oauth.use_own_app(storage, redirect, cfg["client_id"], cfg.get("client_secret"), cfg.get("scope"))
    loop = asyncio.get_running_loop()
    sign_in_page: asyncio.Future = loop.create_future()
    code: asyncio.Future = loop.create_future()

    async def open_page(url: str) -> None:
        state = (parse_qs(urlsplit(url).query).get("state") or [""])[0]
        _oauth_flows[state] = code
        if not sign_in_page.done():
            sign_in_page.set_result(url)

    async def wait_for_code() -> AuthorizationCodeResult:
        return await asyncio.wait_for(code, 900)

    auth = mcp_oauth.provider(cfg["url"], storage, redirect, cfg.get("scope"), bool(cfg.get("client_secret")),
                              redirect_handler=open_page, callback_handler=wait_for_code)

    async def sign_in() -> None:
        try:
            async with Client(streamable_http_client(cfg["url"], http_client=create_mcp_http_client(auth=auth))) as c:
                tools = (await c.list_tools()).tools
            _oauth_status[name] = f"connected, {len(tools)} tools"
            await run_in_threadpool(hub.restart, name, mcp_servers())
            with audited_tx() as conn:
                audit(conn, who, "mcp_server.connected", name)
        except BaseException as e:   # noqa: BLE001  (the flow's errors are the person's to read)
            _oauth_status[name] = f"sign-in failed: {type(e).__name__}: {str(e)[:200]}"
            if not sign_in_page.done():
                sign_in_page.set_exception(RuntimeError(_oauth_status[name]))
        if not sign_in_page.done():
            sign_in_page.set_result("")                  # already signed in, no page needed

    _oauth_status[name] = "waiting for sign-in"
    asyncio.create_task(sign_in())
    try:
        url = await asyncio.wait_for(asyncio.shield(sign_in_page), 30)
    except Exception as e:
        raise HTTPException(502, f"couldn't start signing in to {cfg['url']}: {e}")
    return {"authorize_url": url or None, "status": _oauth_status.get(name), "redirect_uri": redirect}


@app.get("/v1/mcp-oauth/callback")
async def mcp_oauth_callback(request: Request):
    """Where an app sends the browser back after sign-in. The state ties it to one sign-in started by an admin."""
    from fastapi.responses import HTMLResponse
    from mcp.shared.auth import AuthorizationCodeResult
    q = request.query_params
    fut = _oauth_flows.pop(q.get("state", ""), None)
    if fut is None or fut.done():
        return HTMLResponse("<p>This sign-in link is no longer valid. Start again from Squidbrake's Settings.</p>", 400)
    if q.get("error"):
        fut.set_exception(RuntimeError(f"the app said: {q.get('error')} {q.get('error_description', '')}".strip()))
        return HTMLResponse(f"<p>Sign-in didn't go through ({html_escape(q.get('error'))}). You can close this tab.</p>", 400)
    fut.set_result(AuthorizationCodeResult(code=q.get("code", ""), state=q.get("state"), iss=q.get("iss")))
    return HTMLResponse("<!doctype html><meta charset=utf-8><title>Connected</title><body style='font-family:system-ui;"
                        "padding:40px'><h2>Signed in.</h2><p>Squidbrake is connecting to the app now. You can close this "
                        "tab and go back to Settings.</p>")


@app.delete("/v1/mcp-servers/{name}")
def delete_mcp_server(name: str, who: str = Depends(admin)):
    servers = mcp_servers()
    if servers.pop(name, None) is None:
        raise HTTPException(404, f"no MCP server named '{name}'")
    mcp_oauth.FileTokenStorage(hub.oauth_path(name)).forget()
    with audited_tx() as conn:
        state_set(conn, "mcp_servers", servers)
        audit(conn, who, "mcp_server.removed", name)
    hub.sync(servers)
    return {"ok": True}


def _mcp_caller(request: Request) -> tuple[str, str]:
    """(key name, secret) of whoever calls /mcp/<name>: an agent key as Bearer, X-Gateway-Key, or ?key= (for agents
    that take only a URL)."""
    h = request.headers
    secret = h.get("x-gateway-key") or ""
    if h.get("authorization", "").lower().startswith("bearer "):
        secret = h["authorization"][7:].strip()
    secret = secret or request.query_params.get("key", "")
    who = keystore.identify(secret)
    if who is None:
        raise HTTPException(401, "send an agent key: Authorization: Bearer gw_..., or add ?key=gw_... to the URL",
                            headers={"WWW-Authenticate": "Bearer"})
    if who in READ_ONLY_KEYS:
        raise HTTPException(403, f"'{who}' is a read-only key")
    return who, secret


@app.api_route("/mcp/{name}", methods=["GET", "POST", "DELETE"])
async def mcp_endpoint(name: str, request: Request):
    from fastapi.responses import StreamingResponse
    who, secret = _mcp_caller(request)
    servers = mcp_servers()
    if name not in servers:
        raise HTTPException(404, f"no MCP server named '{name}' on this gateway (an admin adds it in Settings)")
    port = await run_in_threadpool(hub.port, name, servers)
    if not port:
        raise HTTPException(502, f"the proxy for '{name}' isn't running; see data/mcp-{name}.log")
    headers = {k: v for k, v in request.headers.items() if k.lower() in MCP_FORWARD}
    headers.update({"X-Squidbrake-Token": hub.token, "X-Squidbrake-Source": who})
    if not keystore.disabled:
        headers["X-Gateway-Key"] = secret                 # the proxy asks the gateway as this caller
    client = request.app.state.mcp_http
    upstream = client.build_request(request.method, f"http://127.0.0.1:{port}/mcp", headers=headers,
                                    content=await request.body())
    for attempt in range(20):                              # a proxy just (re)started takes a moment to listen
        try:
            resp = await client.send(upstream, stream=True)
            break
        except httpx.ConnectError:
            if attempt == 19:
                raise HTTPException(502, f"the proxy for '{name}' isn't answering; see data/mcp-{name}.log")
            await asyncio.sleep(0.25)
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP | {"content-length"}}

    async def body():
        try:
            async for chunk in resp.aiter_raw():
                yield chunk
        finally:
            await resp.aclose()
    return StreamingResponse(body(), status_code=resp.status_code, headers=out_headers)


# --------------------------------------------------------------------------- command line

CLI = os.getenv("SQUIDBRAKE_CLI") or ("docker compose exec gateway python server.py" if IN_DOCKER else "python server.py")


def print_banner(url: str | None, created: dict[str, str] | None) -> None:
    bar = "=" * 72
    lines = ["", bar, "  Squidbrake is running" if url else "  Squidbrake"]
    if url:
        lines += [f"  Dashboard:  {url}/dashboard", f"  Rules:      {RULES_PATH}   (edit it; changes apply at once)"]
    if created:
        lines += [
            "",
            "  First start: created these keys. They are shown ONLY ONCE - save them now.",
            "",
            f"    admin   {created['admin']}   <- paste into the dashboard (can approve)",
            f"    agent   {created['agent']}   <- give to your agents",
            "",
            f"  More keys:  {CLI} add-key NAME            (for an agent)",
            f"              {CLI} add-key NAME --approver (for a person)",
        ]
    if url and (p := pilot.load(PILOT_DIR)):
        lines += ["", f"  Pilot:      sharing usage counts (never commands or content) with {p['server']}",
                  f"              stop anytime: {CLI} pilot leave"]
    lines += [bar, ""]
    print("\n".join(lines), flush=True)


def _cli_add_key(args) -> int:
    kind = "person" if (args.person or args.approver or args.role) else "agent"
    try:
        secret = keystore.add(args.name, approver=args.approver, kind=kind, roles=args.role, owner=args.owner)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    with audited_tx() as conn:
        audit(conn, "command-line", "team.added", args.name, kind=kind, approver=args.approver, roles=args.role or [],
              owner=args.owner)
    what = ("person, can approve" if args.approver else "person, can view") if kind == "person" else "agent"
    if args.role:
        what += ", roles: " + ", ".join(args.role)
    print(f"\n  Key for '{args.name}' ({what}):\n\n    {secret}\n\n  Shown only once - save it now. "
          f"It works immediately, no restart needed.\n")
    return 0


def _cli_remove_key(args) -> int:
    try:
        keystore.remove(args.name)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    with audited_tx() as conn:
        audit(conn, "command-line", "team.removed", args.name)
    print(f"Removed '{args.name}'. It stops working immediately.")
    return 0


def _cli_keys(_) -> int:
    rows = keystore.listing()
    if not rows:
        print(f"No keys yet. Start the server once, or: {CLI} add-key NAME --approver")
        return 0
    source = "GATEWAY_API_KEYS setting" if keystore.from_env else str(keystore.path)
    print(f"Keys (from {source}):")
    for r in rows:
        what = ("can approve" if r["approver"] else "can view") if r["kind"] == "person" else "agent"
        print(f"  {r['name']:<22} {r['kind']:<7} {what:<12} {','.join(r['roles']) or '-':<16} {r['created_at'] or ''}")
    return 0


def _cli_init(_) -> int:
    created = keystore.ensure_initialized()
    if created:
        print_banner(None, created)
    elif keystore.from_env or keystore.disabled:
        print("Keys come from your settings (GATEWAY_API_KEYS / GATEWAY_AUTH); nothing to create.")
    else:
        print(f"Already set up ({keystore.path} exists). List keys with: {CLI} keys")
    return 0


def port_in_use(host: str, port: int) -> str | None:
    """Why the gateway can't listen on host:port (another app, or Squidbrake already running), or None if it can."""
    import socket
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        if os.name != "nt":   # like uvicorn: a socket closed a moment ago (TIME_WAIT) doesn't count. On Windows this
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # option would let two programs share a port
        s.bind((host or "127.0.0.1", port))
        return None
    except OSError as e:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=2, trust_env=False)
            if r.status_code == 200 and r.json().get("status") == "ok" and "rules" in r.json():
                return "Squidbrake is already running there (in the background, or in another window)"
        except Exception:
            pass
        return f"another program is using it ({e.strerror or e})"
    finally:
        s.close()


def can_open_browser() -> bool:
    """No browser on a server over SSH or a Linux box without a desktop (webbrowser would start a text browser
    in this terminal instead)."""
    if os.getenv("SSH_CONNECTION") or os.getenv("SSH_TTY"):
        return False
    if sys.platform.startswith("linux") and not (os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")):
        return False
    return True


def _agents_connected_here() -> list[str] | None:
    """Which agents on this computer have Squidbrake's hook; None when the gateway can't tell (Docker, a server)."""
    if IN_DOCKER or PUBLIC_URL:
        return None
    try:
        import connect
        return connect.connected_agents()
    except Exception:
        return None


def _cli_run(args) -> int:
    import uvicorn

    shown_host = "localhost" if args.host in ("0.0.0.0", "127.0.0.1", "::", "") else args.host
    if taken := port_in_use(args.host, args.port):
        # before the keys and the browser: the browser would open whatever app has the port, and the keys go there
        print(f"Port {args.port} is already in use: {taken}.\n"
              f"Stop that, or run Squidbrake on another port:  {CLI} --port {args.port + 10}\n"
              f"(then connect your agents to it: {CLI} connect all --url http://127.0.0.1:{args.port + 10})", file=sys.stderr)
        return 1
    created = None if keystore.disabled else keystore.ensure_initialized()
    url = PUBLIC_URL or f"http://{shown_host}:{args.port}"
    print_banner(url, created)
    if created and not IN_DOCKER and not args.no_browser and can_open_browser():
        threading.Timer(2.0, webbrowser.open, [f"{url}/dashboard"]).start()
    os.environ["SQUIDBRAKE_LISTEN_PORT"] = str(args.port)    # where the MCP proxies (mcp_hub.py) reach this gateway
    uvicorn.run("server:app", host=args.host, port=args.port, workers=args.workers,
                proxy_headers=True, forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
                log_level=LOG_LEVEL.lower())
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="squidbrake" if CLI == "squidbrake" else "server.py", description="Squidbrake. With no command, starts the server.")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    r = sub.add_parser("run", help="start the server (default)")
    r.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"),
                   help="use 0.0.0.0 to accept connections from other machines (default: this machine only)")
    r.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))
    r.add_argument("--workers", type=int, default=int(os.getenv("WORKERS", "1")))
    r.add_argument("--no-browser", action="store_true", help="don't open the dashboard on first start")
    sub.add_parser("init", help="create the first keys (happens automatically on first start)")
    rs = sub.add_parser("resume", help="turn an emergency stop off (all agents, one agent, or one conversation)")
    rs.add_argument("--agent")
    rs.add_argument("--session")
    a = sub.add_parser("add-key", help="create a key for an agent or a person")
    a.add_argument("name")
    a.add_argument("--approver", action="store_true", help="a person who may approve/reject held calls")
    a.add_argument("--person", action="store_true", help="a person who can open the dashboard (default: an agent)")
    a.add_argument("--role", action="append", help="a role such as admin or finance (repeatable); implies --person")
    a.add_argument("--owner", help="for an agent: the person it works for (with second-person approval on, "
                                   "they can't approve its requests)")
    rm = sub.add_parser("remove-key", help="revoke a key")
    rm.add_argument("name")
    sub.add_parser("keys", help="list keys")
    v = sub.add_parser("verify", help="check an evidence file offline (same as: python verify.py FILE)")
    v.add_argument("file")
    ex = sub.add_parser("explain", help="show how a shell command would be read without running anything")
    ex.add_argument("command")
    lk = sub.add_parser("lockdown", help="write the policy files IT pushes to every developer machine so each coding "
                                         "agent must go through this gateway")
    lk.add_argument("--url", required=True, help="the gateway's address as developer machines reach it")
    lk.add_argument("--out", default="squidbrake-lockdown", help="folder to write (default squidbrake-lockdown)")
    lk.add_argument("--agent", action="append", choices=lockdown.AGENTS, help="only these agents (repeatable; default all)")
    e = sub.add_parser("evidence", help="write the evidence pack (a printable page for an auditor)")
    e.add_argument("--days", type=int, default=90, help="period to cover (default 90)")
    e.add_argument("--out", default=None, help="file to write (default squidbrake-evidence-pack-DATE.html)")
    pl = sub.add_parser("pilot", help="join or leave a pilot: share usage counts (never content) with the Squidbrake team")
    pl.add_argument("action", choices=["join", "leave", "status"])
    pl.add_argument("code", nargs="?", help="the pilot code you were given (join)")
    pl.add_argument("--server", help="the pilot server you were given (join)")
    pl.add_argument("--yes", action="store_true", help="don't ask before joining")
    argv = sys.argv[1:] if argv is None else argv
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv = ["run", *argv]  # `python server.py --port 9000` means run
    args = p.parse_args(argv)
    return {"run": _cli_run, "init": _cli_init, "resume": _cli_resume, "add-key": _cli_add_key, "remove-key": _cli_remove_key,
            "keys": _cli_keys, "verify": lambda a: verify.main([a.file]), "pilot": _cli_pilot,
            "evidence": _cli_evidence, "lockdown": _cli_lockdown, "explain": _cli_explain}[args.cmd](args)


def _cli_lockdown(args) -> int:
    try:
        files = lockdown.write(args.url, Path(args.out), args.agent)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"Wrote {len(files)} files to {Path(args.out).resolve()}:")
    for f in files:
        print(f"  {f}")
    print("Read its README.md: where each file goes, and the GATEWAY_API_KEY every machine needs.")
    return 0


def _cli_evidence(args) -> int:
    migrate(engine)
    out = Path(args.out or f"squidbrake-evidence-pack-{datetime.now():%Y%m%d}.html")
    with audited_tx() as conn:
        audit(conn, "command-line", "audit.exported", None, format="evidence-pack", days=args.days)
    out.write_text(evidence.render_html(build_evidence(args.days, "command-line")), encoding="utf-8")
    print(f"Evidence pack for the last {args.days} days written to {out.resolve()}\n"
          f"Open it in a browser; print it to PDF for your auditor.")
    return 0


def _cli_explain(args) -> int:
    policy._maybe_reload()
    reading = commands.read(args.command)
    print(reading.kind + (f": {reading.summary()}" if reading.summary() else ""))
    for c in reading.commands:
        print("  " + c.raw.ljust(14) + " " + c.kind)
    effect = policy.commands.get(reading.kind)
    if effect:
        print(f"  rule: command_checks.{reading.kind} = {effect}")
    # What the gateway would do with it as a Bash call: the rules (first match wins), then the command checks on top,
    # the way record_event combines them (without history: no earlier steps here)
    inp = {"command": args.command}
    decision, _reason, rule_id, _rule = policy.evaluate(kind="tool_call", name="Bash", source=None, client="cli",
                                                        session_id=None, input=inp)
    if decision != "deny":
        found, only_reads = command_signals("Bash", inp)
        if hit := next((s for s in found if s["effect"] == "block"), None):
            decision, rule_id = "deny", f"command:{hit['check']}"
        elif (hit := next((s for s in found if s["effect"] == "review"), None)) and decision == "allow":
            decision, rule_id = "review", f"command:{hit['check']}"
        elif only_reads and decision == "review" and rule_id is None and policy.commands["read_only"] == "allow":
            decision, rule_id = "allow", "command:read_only"
    verb = {"deny": "blocked", "review": "waits for a person", "allow": "runs"}[decision]
    print(f"  gateway: {verb} ({rule_id or 'default: ' + policy.default})")
    return 0 if reading.kind in ("read_only", "other") else 1


def _cli_pilot(args) -> int:
    if args.action == "join":
        if not args.code:
            print("usage: pilot join CODE --server URL", file=sys.stderr)
            return 2
        return pilot.join(PILOT_DIR, args.code, args.server, args.yes, VERSION)
    return pilot.leave(PILOT_DIR) if args.action == "leave" else pilot.status(PILOT_DIR)


if __name__ == "__main__":
    sys.exit(main())
