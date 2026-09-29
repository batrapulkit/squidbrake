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
    and_, func, inspect as sa_inspect, or_, select, text, update,
)

# --------------------------------------------------------------------------- config

# Every setting is optional. A .env file next to this one is picked up automatically.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).with_name(".env"))
except ImportError:
    pass

# Defaults live next to this file, so it doesn't matter which folder you start it from.
BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(BASE_DIR / 'data' / 'gateway.db').as_posix()}")
KEYS_PATH = Path(os.getenv("KEYS_PATH", BASE_DIR / "data" / "keys.json"))
AUTH_DISABLED = os.getenv("GATEWAY_AUTH", "on").strip().lower() in ("off", "disabled", "false", "0", "no")
IN_DOCKER = bool(os.getenv("IN_DOCKER"))
RULES_PATH = Path(os.getenv("RULES_PATH", BASE_DIR / "rules.yaml"))
MAX_PAYLOAD_CHARS = int(os.getenv("MAX_PAYLOAD_CHARS", "65536"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0"))  # 0 = keep forever
PROXY_TIMEOUT = float(os.getenv("PROXY_TIMEOUT", "60"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


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
        self._mtime: float | None = -1.0
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
                "roles": list(roles), "created_at": k.get("created_at")}

    @property
    def enabled(self) -> bool:
        return not self.disabled

    def _maybe_reload(self) -> None:
        if self.from_env or self.disabled:
            return
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            mtime = None
        if mtime == self._mtime:
            return
        with self._lock:
            try:
                keys = self._read()["keys"]
                self._by_hash = {k["sha256"]: name for name, k in keys.items()}
                self._info = {name: self._normalize(name, k) for name, k in keys.items()}
                self.approvers = {name for name, i in self._info.items() if i["approver"]}
            except Exception:
                log.exception("failed to read %s, keeping previous keys", self.path)
            self._mtime = mtime

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

    def add(self, name: str, approver: bool = False, kind: str | None = None, roles: list[str] | None = None) -> str:
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
        secret = "gw_" + secrets.token_urlsafe(24)
        data["keys"][name] = {"sha256": _hash(secret), "kind": kind, "approver": approver,
                              "roles": self._clean_roles(roles), "created_at": utcnow()}
        self._write(data)
        return secret

    def update(self, name: str, approver: bool | None = None, roles: list[str] | None = None) -> dict:
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
GENESIS = "0" * 64


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


def _entry_hash(prev: str, at: str, actor: str | None, action: str, target: str | None, detail: str) -> str:
    body = json.dumps([prev, at, actor, action, target, detail], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()


def audit(conn, actor: str | None, action: str, target: str | None, **detail) -> None:
    """Append to the hash chain inside the caller's audited_tx()."""
    prev = conn.execute(select(audit_trail.c.hash).order_by(audit_trail.c.seq.desc()).limit(1)).scalar() or GENESIS
    at, d = utcnow(), json.dumps(detail, sort_keys=True, default=str, ensure_ascii=False)
    conn.execute(audit_trail.insert().values(at=at, actor=actor, action=action, target=target, detail=d,
                                             prev_hash=prev, hash=_entry_hash(prev, at, actor, action, target, d)))


def verify_audit_chain() -> dict:
    prev, n = GENESIS, 0
    with engine.connect() as conn:
        for r in conn.execute(select(audit_trail).order_by(audit_trail.c.seq)).all():
            n += 1
            if r.prev_hash != prev or r.hash != _entry_hash(prev, r.at, r.actor, r.action, r.target, r.detail):
                return {"ok": False, "entries": n, "first_bad_seq": r.seq, "head_hash": None,
                        "message": f"entry #{r.seq} was changed, removed or inserted after the fact"}
            prev = r.hash
    return {"ok": True, "entries": n, "first_bad_seq": None, "head_hash": prev,
            "message": "every entry is intact and in its original order"}


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
SECRET_VALUE_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+|\bsk-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}")


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: "[REDACTED]" if SECRET_KEY_RE.search(str(k)) else redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return SECRET_VALUE_RE.sub(lambda m: (m.group(1) or "") + "[REDACTED]", obj)
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
    "repeat_of_rejected": "block",          # the same action (same tool + same target) a person already rejected
    "impersonation": "block",               # moving money right after reading a message from a look-alike domain
    "payment_request_in_message": "review", # moving money right after reading a message that asks for a payment
    "duplicate_change": "review",           # the same change on the same target again (e.g. a 2nd refund)
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

    def __init__(self, path: Path):
        self.path = path
        self._mtime: float | None = -1.0
        self._lock = threading.Lock()
        self.default = "allow"
        self.default_reason = "default allow"
        self.rules: list[dict] = []
        self.history: dict = dict(HISTORY_DEFAULTS)
        self.upstreams: dict[str, str] = {}

    def _maybe_reload(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            mtime = None
        if mtime == self._mtime:
            return
        with self._lock:
            if mtime == self._mtime:
                return
            try:
                data = (yaml.safe_load(self.path.read_text(encoding="utf-8")) if mtime else None) or {}
                rules = []
                for i, r in enumerate(data.get("rules") or []):
                    m = r.get("match") or {}
                    approvers = r.get("approvers")
                    rules.append({
                        "id": r.get("id") or f"rule-{i}",
                        "action": r.get("action", "deny"),
                        "reason": r.get("reason", ""),
                        "globs": {f: ([m[f]] if isinstance(m[f], str) else list(m[f])) for f in self.MATCH_FIELDS if f in m},
                        "input_regex": re.compile(m["input_regex"], re.I | re.S) if m.get("input_regex") else None,
                        "input_conds": self._input_conds(m.get("input")),
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
                self.default, self.rules, self.history = default, rules, hc
                self.default_reason = data.get("default_reason") or f"default {default}"
                self.upstreams = {k: str(v).rstrip("/") for k, v in (data.get("upstreams") or {}).items()}
                log.info("loaded %d rules from %s (default=%s)", len(rules), self.path, default)
            except Exception:
                # A broken edit must never take the gateway down: keep serving the last good rules.
                log.exception("failed to load %s, keeping previous rules", self.path)
            self._mtime = mtime

    DEFAULT_RULE = {"timeout_seconds": APPROVAL_TIMEOUT, "on_timeout": "deny", "approvers": None}

    def evaluate(self, *, kind: str, name: str, source: str | None, client: str,
                 session_id: str | None, input: Any) -> tuple[str, str, str | None, dict]:
        """-> (action, reason, rule_id, rule). `rule` carries the review options."""
        self._maybe_reload()
        values = {"kind": kind, "name": name, "source": source, "client": client, "session_id": session_id}
        input_text: str | None = None
        for rule in self.rules:
            if not all(
                any(fnmatch.fnmatchcase((values[f] or "").lower(), p.lower()) for p in pats)
                for f, pats in rule["globs"].items()
            ):
                continue
            if rule["input_regex"] is not None:
                if input_text is None:
                    input_text = input if isinstance(input, str) else json.dumps(input, default=str, ensure_ascii=False)
                if not rule["input_regex"].search(input_text):
                    continue
            # A missing or non-numeric field never matches, so the call falls through to later rules.
            if not all((n := self._input_number(input, f)) is not None and op(n, v) for f, op, v in rule["input_conds"]):
                continue
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


class ApprovalIn(BaseModel):
    note: str | None = Field(None, max_length=2000)


# --------------------------------------------------------------------------- core


def stopped_for(source: str | None, client: str) -> dict | None:
    """The emergency stop that applies to this caller, if any: everything, or one agent (by source or key)."""
    s = state_get("stop", {"all": None, "agents": {}})
    if s.get("all"):
        return s["all"]
    for k in (source, client):
        if k and k in s.get("agents", {}):
            return s["agents"][k]
    return None


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
                    session_id: str | None, is_change: bool) -> list[dict]:
    """Look at what happened before this action (see HISTORY_DEFAULTS)."""
    hc = policy.history
    if all(hc[k] == "off" for k in HISTORY_EFFECT_KEYS):
        return []
    since = (datetime.now(timezone.utc) - timedelta(hours=float(hc["lookback_hours"]))).isoformat().replace("+00:00", "Z")
    target = _target(input)
    out: list[dict] = []
    add = lambda check, message, ref=None: hc[check] != "off" and out.append(
        {"check": check, "effect": hc[check], "message": message, "ref": ref})

    # 1. A person already said no to this.
    if hc["repeat_of_rejected"] != "off":
        rejected = conn.execute(select(events).where(
            events.c.name == name, events.c.decision == "deny", events.c.decided_by.isnot(None),
            events.c.decided_by != "timeout", events.c.created_at >= since,
        ).order_by(events.c.created_at.desc()).limit(50)).all()
        for r in rejected:
            prev_target = _target(json.loads(r.input)) if r.input else None
            if r.input == stored_input or (target and prev_target and prev_target[1].lower() == target[1].lower()):
                note = f': "{r.decision_note}"' if r.decision_note else ""
                add("repeat_of_rejected", f"{r.decided_by} already rejected this {_ago(r.decided_at or r.created_at)}{note}. "
                                          "Don't retry it; ask the person what to do instead.", r.id)
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


def record_event(ev: EventIn, client: str, client_ip: str | None) -> Decision:
    signals: list[dict] = []
    if stop := stopped_for(ev.source, client):
        decision, rule_id, rule = "deny", "emergency-stop", policy.DEFAULT_RULE
        reason = f"Emergency stop by {stop['by']}" + (f": {stop['reason']}" if stop.get("reason") else "")
    else:
        # Policy sees the raw input; storage only ever sees the redacted copy.
        decision, reason, rule_id, rule = policy.evaluate(
            kind=ev.kind, name=ev.name, source=ev.source, client=client, session_id=ev.session_id, input=ev.input
        )
        if decision != "deny":
            with engine.connect() as conn:
                signals = history_signals(conn, ev.name, ev.input, to_stored_json(ev.input), ev.source,
                                          ev.session_id, is_change=decision == "review")
            blocking = next((s for s in signals if s["effect"] == "block"), None)
            needs_person = next((s for s in signals if s["effect"] == "review"), None)
            if blocking and ev.output is None and ev.error is None:
                decision, reason, rule_id = "deny", blocking["message"], f"history:{blocking['check']}"
            elif needs_person and decision == "allow":
                decision, reason, rule_id, rule = "review", needs_person["message"], f"history:{needs_person['check']}", policy.DEFAULT_RULE
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
    }
    with audited_tx() as conn:
        conn.execute(events.insert().values(**row))
        audit(conn, client, "event.created", row["id"], name=ev.name, kind=ev.kind, source=ev.source,
              session_id=ev.session_id, status=status, decision=decision, rule_id=rule_id, reason=reason,
              input_sha256=_sha(row["input"]), output_sha256=_sha(row["output"]),
              signals=[f"{x['check']}:{x['effect']}" for x in signals] or None)
    audit_log.info(json.dumps({k: row[k] for k in ("id", "created_at", "client", "source", "session_id",
                                                    "kind", "name", "status", "rule_id")}))
    if status == "awaiting_approval":
        notify_approval_needed(row)
    return Decision(event_id=row["id"], decision=decision, reason=reason, rule_id=rule_id,
                    status=status, approval_deadline=deadline, signals=signals or None)


# --------------------------------------------------------------------------- notifications + approval links

def settings() -> dict:
    """Notification settings: env vars are the defaults, the dashboard's Settings page overrides them."""
    defaults = {"public_url": PUBLIC_URL, "slack_webhook": APPROVAL_WEBHOOK_URL,
                "ntfy_topic": os.getenv("NTFY_TOPIC", ""), "ntfy_server": os.getenv("NTFY_SERVER", "https://ntfy.sh"),
                "notify_as": os.getenv("NOTIFY_APPROVER", "admin"), "weekly_digest": True}
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
    return title, body


def notify_approval_needed(row: dict) -> None:
    """Tell a human, wherever they are: Slack (or any incoming webhook) and/or a phone push via ntfy.
    Both carry a signed link that opens a one-tap Approve / Reject page."""
    cfg = settings()
    if not (cfg["slack_webhook"] or cfg["ntfy_topic"]):
        return
    base = (cfg["public_url"] or "http://localhost:8080").rstrip("/")
    token = make_link_token(row["id"], cfg["notify_as"])
    link = f"{base}/a/{token}"
    title, body = approval_message(row)
    expires = row["approval_deadline"]

    def send():
        if cfg["slack_webhook"]:
            try:
                httpx.post(cfg["slack_webhook"], timeout=10, json={
                    "text": f":raised_hand: *{title}*\n{body}\n<{link}|Review and approve or reject> (expires {expires})",
                    "event": {k: row[k] for k in ("id", "name", "kind", "source", "session_id", "client",
                                                  "rule_id", "reason", "approval_deadline")},
                }).raise_for_status()
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

    threading.Thread(target=send, daemon=True).start()


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
        # Conditional update: if two approvers click at once, exactly one wins.
        won = conn.execute(update(events).where(
            events.c.id == event_id, events.c.status == "awaiting_approval",
        ).values(status="pending" if outcome == "allow" else "denied", decision=outcome,
                 decided_by=who, decided_at=utcnow(), decision_note=note)).rowcount
        if not won:
            raise HTTPException(409, "event was decided by someone else a moment ago")
        audit(conn, who, "event.approved" if outcome == "allow" else "event.rejected", event_id, note=note, via=via)
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


def digest_text(r: dict) -> str:
    a, s = r["approvals"], r["by_status"]
    lines = [f":bar_chart: *Squidbrake weekly summary* ({r['days']} days)",
             f"{r['total']} agent actions: {s.get('completed', 0)} completed, {s.get('denied', 0)} blocked, "
             f"{s.get('failed', 0)} failed.",
             f"Approvals: {a['held']} held, {a['approved']} approved, {a['rejected']} rejected, {a['timed_out']} timed out"
             + (f", median decision time {int(a['median_seconds_to_decide'])}s." if a['median_seconds_to_decide'] is not None else ".")]
    if r["agents"]:
        lines.append("Most active: " + ", ".join(f"{g['agent']} ({g['total']})" for g in r["agents"][:5]))
    if r["blocked_by_rule"]:
        lines.append("Top blocks: " + ", ".join(f"{b['rule_id']} ({b['count']})" for b in r["blocked_by_rule"][:3]))
    au = r["audit"]
    lines.append(f"Audit trail: {'intact' if au['ok'] else 'BROKEN at entry ' + str(au['first_bad_seq'])}, "
                 f"{au['entries']} entries, fingerprint {str(au['head_hash'])[:16]}")
    return "\n".join(lines)


def maybe_send_digest() -> None:
    """Every Monday from 09:00 (server local time), once per week, post last week's summary to Slack."""
    cfg, now = settings(), datetime.now()
    if not (cfg["slack_webhook"] and cfg.get("weekly_digest")) or now.weekday() != 0 or now.hour < 9:
        return
    week = now.strftime("%G-W%V")
    with audited_tx() as conn:
        if conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "digest_week")).scalar() == json.dumps(week):
            return
        state_set(conn, "digest_week", week)
    try:
        httpx.post(cfg["slack_webhook"], json={"text": digest_text(build_report(7))}, timeout=15).raise_for_status()
    except Exception:
        log.exception("weekly digest failed")


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
    tasks = [asyncio.create_task(_expiry_loop()), asyncio.create_task(_digest_loop())]
    if RETENTION_DAYS > 0:
        tasks.append(asyncio.create_task(_retention_loop()))
    yield
    for t in tasks:
        t.cancel()
    await app.state.http.aclose()


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
            "can_approve": can_approve(who), "auth_enabled": keystore.enabled}


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


class MemberPatch(BaseModel):
    approver: bool | None = None
    roles: list[str] | None = None


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
    secret = _team_call(lambda: keystore.add(m.name, approver=m.approver, kind=m.kind, roles=m.roles))
    with audited_tx() as conn:
        audit(conn, who, "team.added", m.name, kind=m.kind, approver=m.approver, roles=m.roles)
    return {"name": m.name, "key": secret, "note": "shown once; the gateway keeps only a hash"}


@app.patch("/v1/team/{name}")
def team_update(name: str, p: MemberPatch, who: str = Depends(admin)):
    if name == who and p.roles is not None and "admin" not in p.roles:
        raise HTTPException(400, "you can't remove your own admin role")
    info = _team_call(lambda: keystore.update(name, approver=p.approver, roles=p.roles))
    with audited_tx() as conn:
        audit(conn, who, "team.updated", name, approver=info["approver"], roles=info["roles"])
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
    reason: str | None = Field(None, max_length=500)


@app.get("/v1/controls")
def controls(_: str = Depends(auth)):
    return state_get("stop", {"all": None, "agents": {}})


@app.post("/v1/controls/stop")
def controls_stop(body: StopIn, who: str = Depends(person)):
    """Anyone who can approve (or any admin) can pull the brake; only admins can release it."""
    if not (can_approve(who) or keystore.is_admin(who)):
        raise HTTPException(403, "only approvers and admins can stop agents")
    entry = {"by": who, "at": utcnow(), "reason": body.reason}
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar()
                       or '{"all": null, "agents": {}}')
        if body.agent:
            s.setdefault("agents", {})[body.agent] = entry
        else:
            s["all"] = entry
        state_set(conn, "stop", s)
        audit(conn, who, "controls.stopped", body.agent or "*", reason=body.reason)
    log.warning("EMERGENCY STOP (%s) by %s: %s", body.agent or "all agents", who, body.reason)
    return s


@app.post("/v1/controls/resume")
def controls_resume(body: StopIn, who: str = Depends(admin)):
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar()
                       or '{"all": null, "agents": {}}')
        if body.agent:
            s.setdefault("agents", {}).pop(body.agent, None)
        else:
            s["all"] = None
        state_set(conn, "stop", s)
        audit(conn, who, "controls.resumed", body.agent or "*")
    return s


# ---- notification settings (admins)

class SettingsIn(BaseModel):
    public_url: str | None = Field(None, max_length=300)
    slack_webhook: str | None = Field(None, max_length=500)
    ntfy_topic: str | None = Field(None, max_length=100)
    ntfy_server: str | None = Field(None, max_length=300)
    notify_as: str | None = Field(None, max_length=64)
    weekly_digest: bool | None = None


@app.get("/v1/settings")
def get_settings(_: str = Depends(admin)):
    return settings()


@app.put("/v1/settings")
def put_settings(body: SettingsIn, who: str = Depends(admin)):
    changes = body.model_dump(exclude_none=True)
    for k in ("public_url", "slack_webhook", "ntfy_server"):
        v = changes.get(k)
        if v and not re.match(r"^https?://", v):
            raise HTTPException(400, f"{k} must start with http:// or https://")
    if changes.get("ntfy_topic") and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", changes["ntfy_topic"]):
        raise HTTPException(400, "ntfy_topic: letters, digits, '-' and '_' only")
    if changes.get("notify_as") and not can_approve(changes["notify_as"]):
        raise HTTPException(400, f"'{changes['notify_as']}' can't approve, so links sent as them wouldn't work")
    with audited_tx() as conn:
        current = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "settings")).scalar() or "{}")
        current.update(changes)
        state_set(conn, "settings", current)
        # Record which settings changed, never the webhook secrets themselves.
        audit(conn, who, "settings.updated", None, changed=sorted(changes))
    return settings()


@app.post("/v1/settings/test")
def test_notification(who: str = Depends(admin)):
    cfg = settings()
    if not (cfg["slack_webhook"] or cfg["ntfy_topic"]):
        raise HTTPException(400, "set a Slack webhook or a phone topic first")
    sent, errors = [], []
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
            "audit": verify_audit_chain()}


@app.get("/v1/reports/summary")
def report_summary(days: int = Query(7, ge=1, le=3650), _: str = Depends(person)):
    return build_report(days)


@app.get("/v1/audit/verify")
def audit_verify(_: str = Depends(person)):
    return verify_audit_chain()


@app.get("/v1/audit/log")
def audit_entries(limit: int = Query(100, ge=1, le=1000), _: str = Depends(person)):
    with engine.connect() as conn:
        rows = conn.execute(select(audit_trail).order_by(audit_trail.c.seq.desc()).limit(limit)).all()
    return {"entries": [{**dict(r._mapping), "detail": json.loads(r.detail or "{}")} for r in rows]}


EXPORT_COLUMNS = ["created_at", "id", "source", "client", "session_id", "kind", "name", "status", "decision",
                  "rule_id", "reason", "decided_by", "decided_at", "decision_note", "completed_at", "duration_ms",
                  "error", "input", "output"]


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


# --------------------------------------------------------------------------- command line

CLI = "docker compose exec gateway python server.py" if IN_DOCKER else "python server.py"


def print_banner(url: str | None, created: dict[str, str] | None) -> None:
    bar = "=" * 72
    lines = ["", bar, "  Squidbrake is running" if url else "  Squidbrake"]
    if url:
        lines += [f"  Dashboard:  {url}/dashboard"]
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
    lines += [bar, ""]
    print("\n".join(lines), flush=True)


def _cli_add_key(args) -> int:
    kind = "person" if (args.person or args.approver or args.role) else "agent"
    try:
        secret = keystore.add(args.name, approver=args.approver, kind=kind, roles=args.role)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    with audited_tx() as conn:
        audit(conn, "command-line", "team.added", args.name, kind=kind, approver=args.approver, roles=args.role or [])
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


def _cli_run(args) -> int:
    import uvicorn

    created = None if keystore.disabled else keystore.ensure_initialized()
    shown_host = "localhost" if args.host in ("0.0.0.0", "127.0.0.1", "::", "") else args.host
    url = PUBLIC_URL or f"http://{shown_host}:{args.port}"
    print_banner(url, created)
    if created and not IN_DOCKER and not args.no_browser:
        threading.Timer(2.0, webbrowser.open, [f"{url}/dashboard"]).start()
    uvicorn.run("server:app", host=args.host, port=args.port, workers=args.workers,
                proxy_headers=True, forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
                log_level=LOG_LEVEL.lower())
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="server.py", description="Squidbrake. With no command, starts the server.")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    r = sub.add_parser("run", help="start the server (default)")
    r.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"),
                   help="use 0.0.0.0 to accept connections from other machines (default: this machine only)")
    r.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))
    r.add_argument("--workers", type=int, default=int(os.getenv("WORKERS", "1")))
    r.add_argument("--no-browser", action="store_true", help="don't open the dashboard on first start")
    sub.add_parser("init", help="create the first keys (happens automatically on first start)")
    a = sub.add_parser("add-key", help="create a key for an agent or a person")
    a.add_argument("name")
    a.add_argument("--approver", action="store_true", help="a person who may approve/reject held calls")
    a.add_argument("--person", action="store_true", help="a person who can open the dashboard (default: an agent)")
    a.add_argument("--role", action="append", help="a role such as admin or finance (repeatable); implies --person")
    rm = sub.add_parser("remove-key", help="revoke a key")
    rm.add_argument("name")
    sub.add_parser("keys", help="list keys")
    argv = sys.argv[1:] if argv is None else argv
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv = ["run", *argv]  # `python server.py --port 9000` means run
    args = p.parse_args(argv)
    return {"run": _cli_run, "init": _cli_init, "add-key": _cli_add_key,
            "remove-key": _cli_remove_key, "keys": _cli_keys}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
