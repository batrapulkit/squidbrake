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
from urllib.parse import urlsplit

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
import integrity
import selfguard
import weekly
import license
import siem
import signing
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
# A free hosted dashboard (signed up on pilots.squidbrake.com/signup; provision.py sets these): one person only, and
# after TRIAL_ENDS everything is still recorded but nothing is blocked or held (shadow mode for every agent).
PLAN = os.getenv("SQUIDBRAKE_PLAN", "").lower()
TRIAL_ENDS = os.getenv("SQUIDBRAKE_TRIAL_ENDS", "")           # ISO time, e.g. 2026-11-02T10:00:00+00:00
UPGRADE_URL = os.getenv("SQUIDBRAKE_UPGRADE_URL", "https://pilots.squidbrake.com/team")


def trial_over() -> bool:
    try:
        return bool(TRIAL_ENDS) and datetime.now(timezone.utc) >= datetime.fromisoformat(TRIAL_ENDS)
    except (ValueError, TypeError):    # not a date, or no timezone: never cut someone off over a typo
        return False

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
            self._info = {n: self._normalize(n, {"kind": "person", "approver": n in self.approvers,
                                                 "roles": ["admin"] if n in self.approvers else []})
                          for n in self._by_hash.values()}

    @staticmethod
    def _normalize(name: str, k: dict) -> dict:
        approver = bool(k.get("approver"))
        roles = k.get("roles")
        if roles is None:  # keys.json from before teams existed
            roles = ["admin"] if name == "admin" and approver else []
        roles = list(roles)
        kind = k.get("kind") or ("person" if approver else "agent")
        access = "agent" if kind == "agent" else "owner" if "owner" in roles else "admin" if "admin" in roles             else "approver" if approver else "viewer"
        return {"kind": kind, "approver": approver,
                "roles": roles, "owner": k.get("owner"), "created_at": k.get("created_at"), "access": access}

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
            return {"kind": "person", "approver": True, "roles": ["admin"], "created_at": None, "access": "owner"}
        self._maybe_reload()
        return self._info.get(name) or {"kind": "agent", "approver": False, "roles": [], "created_at": None,
                                        "access": "agent"}

    def is_person(self, name: str) -> bool:
        return self.info(name)["kind"] == "person"

    def is_admin(self, name: str) -> bool:
        roles = self.info(name)["roles"]
        return "admin" in roles or "owner" in roles

    def is_owner(self, name: str) -> bool:
        """Owners manage who is an admin or owner. A team that never named one (keys from before roles had levels)
        treats its admins as owners."""
        if "owner" in self.info(name)["roles"]:
            return True
        return self.is_admin(name) and not any("owner" in i["roles"] for i in self._all_info().values())

    def _all_info(self) -> dict[str, dict]:
        self._maybe_reload()
        return self._info

    def access(self, name: str) -> str:
        """owner > admin > approver > viewer for people; agents only ask and report."""
        return self.info(name)["access"]

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
        integrity.note_keys(self.path.parent)        # our own change to the keys, not tampering

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
                      "roles": ["owner", "admin"], "created_at": now},
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
    Column("snapshot", Text),                       # JSON: the copy kept before it ran ({kind, ref, summary}), or why not
    Column("proof_status", String(20)),             # did the change really happen? confirmed | mismatch | error
    Column("proof", Text),                          # JSON: what was checked, where, and what it found (proof.py)
    Column("brief", Text),                          # JSON: the AI approval brief {text, model, at} (advice only)
    Column("decided_with", String(200)),
    Column("decision_ms", Float),                   # how long the gateway took to decide (what the agent waited)
    Column("feedback", String(10)),                 # a person's verdict on a hold or block: legit | right
    Column("feedback_by", String(200)),
    Column("feedback_at", String(32)),
    Column("identity", String(200), index=True),    # who the agent acts for (identity_of): chains follow it            # how the person decided, e.g. "passkey: Pat's iPhone"
    Column("justification", Text),                  # why the agent says it's doing this (rule `justification:`), redacted
    # two-person approval (rule `required_approvals:`): who approved so far, JSON [{by, at, note, with}]
    Column("required_approvals", Integer),
    Column("approvals", Text),
    # rule `escalate_after_seconds:` / `escalate_to:`: when nobody decided by then, more people may, and are told
    Column("escalate_at", String(32), index=True),
    Column("escalate_to", Text),
)

# A person's note to a running agent ("use the staging database, not prod"): delivered with the agent's next action
# that can carry it (Decision.notes), then marked delivered. A steer only: it never approves or lifts anything.
notes = Table(
    "notes", metadata,
    Column("id", String(36), primary_key=True),
    Column("created_at", String(32), nullable=False),
    Column("by", String(200), nullable=False),
    Column("agent", String(200), index=True),       # an agent's source or key name, or
    Column("session_id", String(200), index=True),  # one conversation
    Column("text", Text, nullable=False),
    Column("delivered_at", String(32), index=True),
    Column("delivered_event", String(36)),
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

# Every CHECKPOINT_EVERY entries the chain's fingerprint is signed with the ledger key (signing.py), whose public half
# is published at /v1/audit/public-key: an export can then be proven unedited by anyone, without trusting this server.
audit_checkpoints = Table(
    "audit_checkpoints", metadata,
    Column("seq", Integer, primary_key=True),       # the audit entry the checkpoint covers (inclusive)
    Column("at", String(32), nullable=False),
    Column("head_hash", String(64), nullable=False),
    Column("key_id", String(16), nullable=False),
    Column("signature", String(128), nullable=False),  # Ed25519, hex
)

# A copy of what an approved action was about to change, taken right before it ran (see /v1/events/{id}/snapshot):
# a file backup on the agent's computer (squidbrake undo ID), or the record itself (an API resource, a row).
snapshots = Table(
    "snapshots", metadata,
    Column("id", String(36), primary_key=True),
    Column("event_id", String(36), nullable=False, index=True),
    Column("created_at", String(32), nullable=False),
    Column("kind", String(30), nullable=False),     # local | http | data
    Column("ref", String(300)),                     # local: the backup id on that computer; http: the URL read
    Column("summary", Text),
    Column("data", Text),                           # the saved copy (redacted like everything stored)
    Column("sha256", String(64)),
)

# Model tokens and money spent, reported by agents (see /v1/usage and rules.yaml `budgets:`).
usage = Table(
    "usage", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("at", String(32), nullable=False, index=True),
    Column("client", String(200), index=True),
    Column("source", String(200), index=True),
    Column("session_id", String(200)),
    Column("model", String(100)),
    Column("input_tokens", Integer),
    Column("output_tokens", Integer),
    Column("cost_usd", Float),
)

# Phones and laptops that sign approvals with a passkey (Face ID, fingerprint): WebAuthn credentials.
devices = Table(
    "devices", metadata,
    Column("credential_id", String(400), primary_key=True),   # base64url
    Column("person", String(200), nullable=False, index=True),
    Column("name", String(100)),
    Column("created_at", String(32), nullable=False),
    Column("public_key", Text, nullable=False),               # JSON {"x": hex, "y": hex} (P-256)
    Column("sign_count", Integer),
    Column("last_used_at", String(32)),
)

# What an agent's earlier actions gave it, until it expires: the first step of each `after:` chain in rules.yaml
# (backups switched off, ...), per identity. Chains are judged from here, across restarts, conversations and agents.
capabilities = Table(
    "capabilities", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("identity", String(200), index=True, nullable=False),
    Column("capability", String(200), index=True, nullable=False),   # after:<sequence id>
    Column("target", String(500)),                                   # what it was on (lowercase), if it says
    Column("source_event", String(36), index=True, nullable=False),
    Column("summary", Text),                                         # the step, in words
    Column("agent", String(200)),
    Column("client", String(200)),
    Column("session_id", String(200)),
    Column("created_at", String(32), nullable=False),
    Column("expires_at", String(32), index=True, nullable=False),
)

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

# Keys, the record, the link and ledger secrets and the rules: readable by this user only (POSIX; 600 / folder 700)
import offline  # noqa: E402
for _p in [KEYS_PATH.parent, *KEYS_PATH.parent.glob("*.db*"), *KEYS_PATH.parent.glob("*.key"),
           *KEYS_PATH.parent.glob("*.json"), *([RULES_PATH] if HOME_DIR != BASE_DIR else [])]:
    if _p.exists():
        offline._private(_p)


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
    h = _entry_hash(prev, at, actor, action, target, d)
    seq = conn.execute(audit_trail.insert().values(at=at, actor=actor, action=action, target=target, detail=d,
                                                   prev_hash=prev, hash=h)).inserted_primary_key[0]
    if seq and seq % signing.CHECKPOINT_EVERY == 0:
        _sign_checkpoint(conn, seq, h)


# --------------------------------------------------------------------------- signed checkpoints (the ledger key)

_ledger_cache: bytes | None = None


def ledger_secret() -> bytes:
    """The Ed25519 key that signs checkpoints: SQUIDBRAKE_LEDGER_KEY (64 hex characters), else data/ledger.key, made
    once. Keep a copy somewhere safe: a new key can't sign the old checkpoints, so publish each public key you use."""
    global _ledger_cache
    if _ledger_cache is None:
        if env := os.getenv("SQUIDBRAKE_LEDGER_KEY", "").strip():
            _ledger_cache = bytes.fromhex(env)
        else:
            path = KEYS_PATH.parent / "ledger.key"
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(signing.new_secret().hex())
            except FileExistsError:
                pass
            _ledger_cache = bytes.fromhex(path.read_text().strip())
        if len(_ledger_cache) != 32:
            raise ValueError("the ledger key must be 32 bytes (64 hex characters)")
    return _ledger_cache


def ledger_public() -> dict:
    pub = signing.ed25519_public_key(ledger_secret())
    return {"algorithm": "ed25519", "public_key": pub.hex(), "key_id": hashlib.sha256(pub).hexdigest()[:16],
            "every": signing.CHECKPOINT_EVERY, "format": signing.CHECKPOINT_FORMAT,
            "message": f"{signing.CHECKPOINT_FORMAT}|<seq>|<hash of entry seq>"}


def _sign_checkpoint(conn, seq: int, head_hash: str) -> None:
    key = ledger_public()
    sig = signing.ed25519_sign(ledger_secret(), signing.checkpoint_message(seq, head_hash)).hex()
    conn.execute(audit_checkpoints.insert().values(seq=seq, at=utcnow(), head_hash=head_hash, key_id=key["key_id"],
                                                   signature=sig))


def sign_missing_checkpoints() -> int:
    """At start: a chain from before checkpoints existed gets them now (they attest the history as of today)."""
    every = signing.CHECKPOINT_EVERY
    with audited_tx() as conn:
        have = {r[0] for r in conn.execute(select(audit_checkpoints.c.seq)).all()}
        due = conn.execute(select(audit_trail.c.seq, audit_trail.c.hash).where(
            text(f"seq % {every} = 0")).order_by(audit_trail.c.seq)).all()
        missing = [(s, h) for s, h in due if s not in have]
        for s, h in missing:
            _sign_checkpoint(conn, s, h)
    return len(missing)


def checkpoint_rows(conn) -> list[dict]:
    return [dict(r._mapping) for r in conn.execute(select(audit_checkpoints).order_by(audit_checkpoints.c.seq)).all()]


def verify_audit_chain() -> dict:
    """The hash chain, plus: do the recorded actions still match the fingerprints taken when they happened? And is
    every signed checkpoint still a valid signature over the chain as it is now?"""
    with engine.connect() as conn:
        entries = [dict(r._mapping) for r in conn.execute(select(audit_trail).order_by(audit_trail.c.seq)).all()]
        rows = {r.id: {"id": r.id, "input": r.input, "output": r.output}
                for r in conn.execute(select(events.c.id, events.c.input, events.c.output)).all()}
        cps = checkpoint_rows(conn)
    result = verify.check_chain(entries)
    changed = verify.check_events(entries, rows)["changed"] if result["ok"] else []
    if changed:
        result.update(ok=False, head_hash=result["head_hash"], events_changed=changed,
                      message=f"the chain is intact, but {len(changed)} recorded action(s) were edited in the database "
                              f"afterwards (first: {changed[0]['event']}, {changed[0]['field']})")
    signed = verify.check_checkpoints(entries, cps, ledger_public()["public_key"])
    result["checkpoints"] = signed
    if not signed["ok"] and result["ok"]:
        result.update(ok=False, message=signed["message"])
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


# People's details in stored actions: an email keeps its first letter and its domain (the domain is what look-alike and
# untrusted-destination checks need) plus a short fingerprint, so the same address always masks the same way and
# "the same customer again" is still seen. A card number keeps its last four digits. SQUIDBRAKE_REDACT_PERSONAL=0: off.
REDACT_PERSONAL = os.getenv("SQUIDBRAKE_REDACT_PERSONAL", "1").lower() not in ("0", "false", "no", "off")
EMAIL_VALUE_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
CARD_VALUE_RE = re.compile(r"(?<![\d-])[2-6](?:[ -]?\d){12,18}(?![\d-])")
MAX_PREVIEW_CHARS = int(os.getenv("MAX_PREVIEW_CHARS", "2048"))   # what lists, phones, notifications and briefs show


def _mask_email(m: re.Match) -> str:
    local, domain = m.group(1), m.group(2)
    if ".redacted-" in local:                       # already masked (a stored copy redacted again)
        return m.group(0)
    tag = hmac.new(_link_secret(), m.group(0).lower().encode(), hashlib.sha256).hexdigest()[:6]
    return f"{local[0].lower()}.redacted-{tag}@{domain}"


def _mask_card(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return f"[card ending {digits[-4:]}]" if 13 <= len(digits) <= 19 and outbound._luhn(digits) else m.group(0)


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: "[REDACTED]" if SECRET_KEY_RE.search(str(k)) else redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        obj = SECRET_VALUE_RE.sub(lambda m: (m.group(1) or m.group(2) or "") + "[REDACTED]", obj)
        if REDACT_PERSONAL:
            obj = CARD_VALUE_RE.sub(_mask_card, EMAIL_VALUE_RE.sub(_mask_email, obj))
        return obj
    return obj


def preview_of(value: Any, limit: int | None = None) -> Any:
    """A stored (already redacted) value, cut to MAX_PREVIEW_CHARS when it's long: what lists, the phone page and
    briefs show. The full redacted copy stays in the database for the drawer, exports and checks."""
    limit = limit or MAX_PREVIEW_CHARS
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    if text is None or len(text) <= limit:
        return value
    return {"_preview": text[:limit], "_truncated": True, "_original_chars": len(text)}


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
TAINT_EFFECT_KEYS = ("untrusted_destination", "after_untrusted", "after_untrusted_setup_edit")
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
    "scope": "identity",                # where outside content is remembered: identity (every conversation) | session
    "untrusted_destination": "review",  # sends to an address/URL/account found only in untrusted content
    "after_untrusted": "warn",          # sends anything out after untrusted content was read in this conversation
    "after_untrusted_setup_edit": "warn",  # changes the agent's own setup (held by the guard-rail rule) after
                                           # untrusted content was read in the same conversation; warn only, it never
                                           # changes the decision (#74)
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
    "edited_then_run": "warn",     # runs a script the agent changed in this conversation: flagged; review holds it
    "unknown": "warn",         # a program that isn't a common developer tool: recorded (shadow); "review" holds it
    "read_only": "off",        # "allow": commands that only look (ls, cat, grep, git status) run without asking
}


def _rule_mode(r: dict, rid: str) -> str | None:
    """A rule's own `mode: enforce | observe` (None = the top-level mode)."""
    m = r.get("mode")
    if m is None:
        return None
    m = str(m).lower().replace("observe", "shadow")
    if m not in ("enforce", "shadow"):
        raise ValueError(f"{rid}: mode must be enforce or observe")
    return m


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
            seq = {"id": rid, "action": action, "reason": r.get("reason") or rid, "mode": _rule_mode(r, rid),
                   "match": cls._compile_match(r.get("match") or {}), "after": None, "count": None}
            if after:
                scope = after.get("scope", "session")
                if scope not in ("session", "agent", "identity", "all"):
                    raise ValueError(f"sequences.{rid}: after.scope must be session | agent | identity | all")
                seq["after"] = {"match": cls._compile_match(after.get("match") or {}),
                                "within_hours": float(after.get("within_hours", 24)),
                                "same_target": bool(after.get("same_target", False)), "scope": scope}
            if count:
                scope = count.get("scope", "agent")
                if scope not in ("session", "agent", "identity", "all") or "more_than" not in count:
                    raise ValueError(f"sequences.{rid}: count needs more_than, and scope session | agent | identity | all")
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

    @classmethod
    def _compile_budgets(cls, items: list | None) -> list[dict]:
        """rules.yaml `budgets:` - model tokens / money an agent may spend per day or month before it's paused."""
        out = []
        for i, b in enumerate(items or []):
            bid = b.get("id") or f"budget-{i}"
            per, period = b.get("per", "agent"), b.get("period", "day")
            if per not in ("agent", "together") or period not in ("day", "month"):
                raise ValueError(f"budgets.{bid}: per must be agent or together, period day or month")
            tokens, usd = b.get("tokens"), b.get("usd")
            if tokens is None and usd is None:
                raise ValueError(f"budgets.{bid}: needs tokens: or usd:")
            if any(isinstance(v, bool) or (v is not None and (not isinstance(v, (int, float)) or v <= 0))
                   for v in (tokens, usd)):
                raise ValueError(f"budgets.{bid}: tokens and usd must be positive numbers")
            out.append({"id": bid, "per": per, "period": period, "tokens": int(tokens) if tokens else None,
                        "usd": float(usd) if usd else None, "reason": b.get("reason") or "",
                        "match": cls._compile_match({k: v for k, v in (b.get("match") or {}).items()
                                                     if k in ("source", "client")})})
        return out

    @classmethod
    def _compile_proofs(cls, items: list | None) -> list[dict]:
        """rules.yaml `proof_checks:` - after an action reports it's done, look in the real system (proof.py)."""
        import proof
        out = []
        for i, p in enumerate(items or []):
            pid = p.get("id") or f"proof-{i}"
            kinds = [k for k in proof.KINDS if k in p]
            if len(kinds) != 1:
                raise ValueError(f"proof_checks.{pid}: needs exactly one of {', '.join(proof.KINDS)}")
            if p.get("expect") is not None and not isinstance(p["expect"], dict):
                raise ValueError(f"proof_checks.{pid}: expect must map fields to values")
            out.append({"id": pid, "kind": kinds[0], "spec": p[kinds[0]] or {}, "expect": p.get("expect") or {},
                        "delay_seconds": float(p.get("delay_seconds", 2)), **cls._compile_match(p.get("match") or {})})
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
        self.when_unreachable, self.snapshots, self.integrity = "block", "required", "alert"
        self.budgets: list[dict] = []
        self.proofs: list[dict] = []

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
                    unreachable = r.get("when_unreachable")
                    rules.append({
                        "id": r.get("id") or f"rule-{i}",
                        "action": r.get("action", "deny"),
                        "reason": r.get("reason", ""),
                        "match_spec": m,
                        # while the gateway is down: block or allow (offline.py); None = the top-level setting
                        "when_unreachable": None if unreachable is None else
                            "allow" if unreachable is True or str(unreachable).lower() == "allow" else "block",
                        # undo: a copy of what it changes, before it runs (see Decision.snapshot)
                        "snapshot": str(r["snapshot"]).lower() if r.get("snapshot") not in (None, False) else
                            ("off" if r.get("snapshot") is False else None),
                        **self._compile_match(m),
                        # review-only options
                        "timeout_seconds": int(r.get("timeout_seconds", APPROVAL_TIMEOUT)),
                        "on_timeout": r.get("on_timeout", "deny"),
                        "approvers": [approvers] if isinstance(approvers, str) else approvers,
                        # maker-checker: the person whose agent asked can't approve it, whatever Settings say
                        "second_person": bool(r.get("second_person")),
                        "mode": _rule_mode(r, r.get("id") or f"rule-{i}"),
                        # the agent must (required) or may (optional) say why; the approver sees it
                        "justification": str(r["justification"]).lower() if r.get("justification") else None,
                        # this many different people approve before it runs (one rejection is enough to stop it)
                        "required_approvals": r.get("required_approvals", 1),
                        "escalate_after_seconds": r.get("escalate_after_seconds"),
                        "escalate_to": [r["escalate_to"]] if isinstance(r.get("escalate_to"), str) else r.get("escalate_to"),
                    })
                default = data.get("default", "allow")
                if default not in ("allow", "deny", "review") or \
                        any(r["action"] not in ("allow", "deny", "review", "notify") for r in rules):
                    raise ValueError("actions must be 'allow', 'deny', 'review' or 'notify' (the default: allow, deny "
                                     "or review)")
                if any(r["justification"] not in (None, "required", "optional") for r in rules):
                    raise ValueError("justification must be required or optional")
                for r in rules:
                    n, esc = r["required_approvals"], r["escalate_after_seconds"]
                    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 10:
                        raise ValueError(f"{r['id']}: required_approvals must be a number from 1 to 10")
                    if esc is not None and (isinstance(esc, bool) or not isinstance(esc, int)
                                            or not 1 <= esc < r["timeout_seconds"] or not r["escalate_to"]):
                        raise ValueError(f"{r['id']}: escalate_after_seconds needs escalate_to, and must be shorter "
                                         "than timeout_seconds")
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
                for k in (*COMMAND_EFFECT_KEYS, "written_then_run", "edited_then_run", "unknown"):
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
                if tc["scope"] not in ("identity", "session"):
                    raise ValueError("taint_checks.scope must be identity or session")
                dc = {**DATA_DEFAULTS, **(data.get("data_checks") or {})}
                for k in DATA_EFFECT_KEYS:
                    dc[k] = "off" if dc[k] is False else DATA_DEFAULTS[k] if dc[k] is True else str(dc[k]).lower()
                    if dc[k] not in ("block", "review", "warn", "off"):
                        raise ValueError(f"data_checks.{k} must be block, review, warn or off")
                dc["where"] = [dc["where"]] if isinstance(dc["where"], str) else list(dc["where"] or [])
                mode = str(data.get("mode", "enforce")).lower().replace("observe", "shadow")
                if mode not in ("enforce", "shadow"):
                    raise ValueError("mode must be enforce or observe (shadow)")
                wu = data.get("when_unreachable", "block")
                wu = "allow" if wu is True or str(wu).lower() == "allow" else \
                    "block" if wu is False or str(wu).lower() in ("block", "deny") else \
                    "block_risky" if str(wu).lower() == "block_risky" else \
                    "warn" if str(wu).lower() == "warn" else None
                if wu is None or any(str(r.get("when_unreachable", "block")).lower() not in ("allow", "block", "deny", "true", "false")
                                     for r in data.get("rules") or []):
                    raise ValueError("when_unreachable must be block, block_risky, warn or allow (a rule: block or allow)")
                integ = str(data.get("integrity", "alert")).lower()
                if integ not in ("alert", "fail_closed"):
                    raise ValueError("integrity must be alert or fail_closed")
                snaps = str(data.get("snapshots", "required")).lower() if data.get("snapshots") is not False else "off"
                if snaps not in ("required", "best_effort", "off") or \
                        any(r["snapshot"] not in (None, "required", "best_effort", "off") for r in rules):
                    raise ValueError("snapshots / snapshot must be required, best_effort or off")
                budgets = self._compile_budgets(data.get("budgets"))
                proofs = self._compile_proofs(data.get("proof_checks"))
                shadow_agents = data.get("shadow_agents") or []
                shadow_agents = [shadow_agents] if isinstance(shadow_agents, str) else list(shadow_agents)
                self.default, self.rules, self.history, self.commands = default, rules, hc, cc
                self.sequences, self.taint, self.data = sequences, tc, dc
                self.source, self.fingerprint = source, verify.rules_fingerprint(source)
                self.mode, self.shadow_agents = mode, shadow_agents
                self.when_unreachable, self.snapshots, self.integrity = wu, snaps, integ
                self.budgets, self.proofs = budgets, proofs
                self.default_reason = data.get("default_reason") or f"default {default}"
                self.upstreams = {k: str(v).rstrip("/") for k, v in (data.get("upstreams") or {}).items()}
                log.info("loaded %d rules from %s (default=%s)", len(rules), self.path, default)
            except Exception:
                # A broken edit must never take the gateway down: keep serving the last good rules.
                log.exception("failed to load %s, keeping previous rules", self.path)
            self._sig = sig

    DEFAULT_RULE = {"timeout_seconds": APPROVAL_TIMEOUT, "on_timeout": "deny", "approvers": None, "justification": None,
                    "required_approvals": 1, "escalate_after_seconds": None, "escalate_to": None}

    def shadow_for(self, source: str | None, client: str, rule_id: str | None = None) -> bool:
        """Shadow mode: record what would happen, but let it through (everything, or the agents listed). A rule or
        sequence with its own `mode:` wins, so a team can enforce the catastrophic ones first and observe the rest."""
        self._maybe_reload()
        if trial_over():
            return True
        rid = str(rule_id or "")
        own = next((r["mode"] for r in self.rules if r["id"] == rid), None) or             next((q["mode"] for q in self.sequences if f"sequence:{q['id']}" == rid), None)
        if own:
            return own == "shadow"
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
    cannot_undo: bool = False          # once it runs it can't be taken back: the agent's person is told first
    risk: int | None = None            # risk.py's score, 0..100: measured only, never part of the decision
    # Undo: keep a copy of what this changes before it runs. "required": if a copy can't be made, don't run it;
    # "best_effort": try, and run anyway. snapshot_strict: a rule asked for it by name, so a path with no way to
    # make a copy (an MCP tool, a client without a snapshot function) must not run it either.
    snapshot: str | None = None
    snapshot_strict: bool = False
    # Notes people left for this agent ({by, text, at}), handed over with this answer (callers that send
    # metadata.accepts_notes: true pass them to the agent). A steer, never a permission.
    notes: list[dict] | None = None


class ChallengeIn(BaseModel):
    outcome: Literal["approve", "reject"] = "approve"


class SnapshotIn(BaseModel):
    kind: Literal["local", "http", "data"] = "data"
    ref: str | None = Field(None, max_length=300, description="local: the backup id (squidbrake undo ID)")
    summary: str | None = Field(None, max_length=1000)
    data: Any = None                   # the saved copy itself (kept redacted, like every stored value)
    skipped: str | None = Field(None, max_length=500, description="why no copy could be made (the action was blocked)")


class UsageIn(BaseModel):
    source: str | None = Field(None, max_length=200)
    session_id: str | None = Field(None, max_length=200)
    model: str | None = Field(None, max_length=100)
    input_tokens: int = Field(0, ge=0, le=10**10)
    output_tokens: int = Field(0, ge=0, le=10**10)
    cost_usd: float | None = Field(None, ge=0, le=10**7)


class ApprovalIn(BaseModel):
    note: str | None = Field(None, max_length=2000)
    # A passkey's signature over this decision (passkeys.py): {credential_id, statement, challenge,
    # authenticator_data, client_data_json, signature}
    device_proof: dict | None = None


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


# --------------------------------------------------------------------------- spend brake (rules.yaml `budgets:`)

def _period_start(period: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return day.replace(day=1) if period == "month" else day


def _period_end(period: str, now: datetime | None = None) -> datetime:
    start = _period_start(period, now)
    if period == "day":
        return start + timedelta(days=1)
    return start.replace(year=start.year + (start.month == 12), month=start.month % 12 + 1)


def _iso(d: datetime) -> str:
    return d.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def record_usage(client: str, u: UsageIn) -> None:
    if not (u.input_tokens or u.output_tokens or u.cost_usd):
        return
    with engine.begin() as conn:
        conn.execute(usage.insert().values(at=utcnow(), client=client, source=u.source, session_id=u.session_id,
                                           model=u.model, input_tokens=u.input_tokens, output_tokens=u.output_tokens,
                                           cost_usd=u.cost_usd))


def _spend_by_agent(since: str) -> list:
    tokens = func.coalesce(func.sum(usage.c.input_tokens), 0) + func.coalesce(func.sum(usage.c.output_tokens), 0)
    with engine.connect() as conn:
        return conn.execute(select(usage.c.source, usage.c.client, tokens.label("tokens"),
                                   func.coalesce(func.sum(usage.c.cost_usd), 0).label("usd"))
                            .where(usage.c.at >= since).group_by(usage.c.source, usage.c.client)).all()


def budget_status(source: str | None = None, client: str | None = None) -> list[dict]:
    """Each budget's spend this period: per agent (per: agent) or for all its agents together (per: together).
    With source/client: only the budgets that cover that agent, and only its own line."""
    out = []
    for b in policy.budgets:
        rows = [r for r in _spend_by_agent(_iso(_period_start(b["period"])))
                if Policy.matches(b["match"], {"source": r.source, "client": r.client}, None)]
        if source is not None or client is not None:
            if not Policy.matches(b["match"], {"source": source, "client": client}, None):
                continue
            if b["per"] == "agent":
                rows = [r for r in rows if (r.source or r.client) == (source or client)]
        groups: dict[str, list] = {}
        for r in rows:
            groups.setdefault(r.source or r.client if b["per"] == "agent" else "together", []).append(r)
        if source is not None or client is not None:
            groups.setdefault(source or client if b["per"] == "agent" else "together", [])
        for who, rs in groups.items():
            tokens, usd = sum(int(r.tokens or 0) for r in rs), sum(float(r.usd or 0) for r in rs)
            over = (b["tokens"] is not None and tokens >= b["tokens"]) or (b["usd"] is not None and usd >= b["usd"])
            out.append({"budget": b["id"], "who": who, "period": b["period"], "tokens": tokens, "usd": round(usd, 4),
                        "token_limit": b["tokens"], "usd_limit": b["usd"], "paused": over,
                        "resets_at": _iso(_period_end(b["period"]))})
    return out


def budget_hit(source: str | None, client: str) -> dict | None:
    """The budget this agent has used up, if any: its actions are paused until the period ends."""
    if not policy.budgets:
        return None
    for s in budget_status(source, client):
        if s["paused"]:
            used = (f"{s['tokens']:,} of {s['token_limit']:,} tokens" if s["token_limit"] is not None
                    and s["tokens"] >= s["token_limit"] else f"${s['usd']:,.2f} of ${s['usd_limit']:,.2f}")
            whose = "by this agent" if s["who"] != "together" else "by the agents it covers, together"
            return {**s, "message": f"Paused by the spend limit '{s['budget']}': {used} used this {s['period']} {whose}. "
                                    f"It starts again {s['resets_at'][:16].replace('T', ' ')} UTC, or when an admin raises "
                                    f"the limit in rules.yaml."}
    return None


def usage_from_metadata(metadata: dict | None) -> UsageIn | None:
    u = (metadata or {}).get("usage")
    if not isinstance(u, dict):
        return None
    try:
        return UsageIn(**{k: u[k] for k in ("model", "input_tokens", "output_tokens", "cost_usd") if k in u})
    except Exception:
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


def run_rule_signals(ev: "EventIn", client: str) -> list[dict]:
    """What a script, Makefile target or package.json script runs, judged by the same rules and self-protection as a
    command typed directly (command_signals reads its commands; this applies rules.yaml and selfguard to each line)."""
    out: list[dict] = []
    for via, line in reported_runs(ev.metadata):
        inp = {"command": line}
        if hit := selfguard.check("tool_call", ev.name, inp, ev.metadata, KEYS_PATH.parent):
            return [{**hit, "message": f"This command runs {via}, which: {hit['message']}"}]
        d, why, rid, _ = policy.evaluate(kind=ev.kind, name=ev.name, source=ev.source, client=client,
                                         session_id=ev.session_id, input=inp)
        if rid and d in ("deny", "review") and not any(o["rule"] == rid for o in out):
            out.append({"check": "script_rule_command", "rule": rid, "effect": "block" if d == "deny" else "review",
                        "message": f"This command runs {via}, which a rule holds: {why} ({line[:120]})"})
    return out


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
EDITS_A_FILE = ("Edit", "MultiEdit", "replace", "edit_file", "str_replace_editor", "str_replace_based_edit_tool")


def written_then_run(conn, ev: "EventIn", client: str) -> list[dict]:
    """A script the agent created or changed in this conversation, now run directly (`python x.py`, `./x.sh`): as
    unreadable to a shell reading as `python -c`, so a person reads it first (command_checks.written_then_run).
    Running tests (`pytest`, `npm test`) after editing the code isn't a script run, so it isn't counted."""
    cc = policy.commands
    if (cc["written_then_run"] == "off" and cc["edited_then_run"] == "off") or not ev.session_id             or not any(fnmatch.fnmatchcase(ev.name.lower(), t.lower()) for t in cc["tools"]):
        return []
    line = commands.command_of(ev.input)
    scripts = commands.executes(line) if line else []
    if not scripts:
        return []
    cwd = str((ev.metadata or {}).get("cwd") or "")
    norm = lambda p: os.path.normcase(os.path.normpath(p.replace("\\", "/"))) if p else ""
    wanted = {norm(os.path.join(cwd, sp) if cwd and not os.path.isabs(sp) and not sp.startswith("~") else sp): sp
              for sp in scripts}
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    names = (WRITES_A_FILE + tuple(cc["tools"]) if cc["written_then_run"] != "off" else ()) + (EDITS_A_FILE if cc["edited_then_run"] != "off" else ())
    rows = conn.execute(select(events.c.name, events.c.input).where(
        events.c.session_id == ev.session_id, events.c.created_at >= since, events.c.status.in_(("completed", "pending")),
        events.c.name.in_(names)).order_by(events.c.created_at.desc()).limit(200)).all()
    for r in rows:
        try:
            inp = json.loads(r.input) if r.input else {}
        except ValueError:
            continue
        if r.name not in WRITES_A_FILE + EDITS_A_FILE:      # a shell command: what it downloaded or wrote
            line_was = commands.command_of(inp) or ""
            same = lambda d, sp: norm(os.path.join(cwd, d) if cwd else d) == \
                norm(os.path.join(cwd, sp) if cwd and not os.path.isabs(sp) else sp)
            got = commands.downloads(line_was)
            if hit := next((sp for sp in scripts for d in got if same(d, sp)), None):
                return [{"check": "downloaded_then_run_command", "effect": "review",
                         "message": f"This runs, sources or makes runnable {hit}, a file downloaded in this "
                                    f"conversation ({line_was[:100]}). Read it first."}]
            if cc["written_then_run"] != "off" and \
                    (hit := next((sp for sp in scripts for d in commands.writes(line_was) if same(d, sp)), None)):
                return [{"check": "written_then_run_command", "effect": cc["written_then_run"],
                         "message": f"This command runs {hit}, a script the agent wrote with a shell command in this "
                                    f"conversation ({line_was[:100]}). Read it before it runs."}]
            continue
        path = str(inp.get("file_path") or inp.get("path") or "") if isinstance(inp, dict) else ""
        hit = wanted.get(norm(path)) or next((sp for sp in scripts if not cwd and path and
                                              os.path.basename(path.replace("\\", "/")) == os.path.basename(sp)), None)
        if hit:
            edited = r.name in EDITS_A_FILE
            return [{"check": "edited_then_run_command" if edited else "written_then_run_command",
                     "effect": cc["edited_then_run" if edited else "written_then_run"],
                     "message": f"This command runs {hit}, a script the agent "
                                f"{'changed' if edited else 'wrote'} in this conversation. Read it "
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
    backfill_capabilities(conn)
    _recorded_policies.add(fp)


def _step_text(name: str, stored: Any) -> str:
    """How a step reads: Bash `aws rds modify-db-instance ...`, or stripe.refund on ch_1."""
    line = commands.command_of(stored) if stored is not None else None
    target = _target(stored) if stored is not None else None
    detail = f" `{line[:90]}`" if line else f" on {target[1]}" if target else ""
    return f"{name}{detail}"


def _step_phrase(row) -> str:
    """How an earlier step reads in a reason: Bash `aws rds modify-db-instance ...` (12 minutes ago)."""
    return f"{_step_text(row.name, json.loads(row.input) if row.input else None)} ({_ago(row.created_at)})"


def identity_of(client: str | None) -> str:
    """Who an agent acts for, so a chain split across its conversations and agents is still one chain. On a person's
    own computer every agent is that person; on a shared gateway, the person a key belongs to (Team: "works for")."""
    if not (IN_DOCKER or PUBLIC_URL):
        return "this-computer"
    if keystore.enabled and not keystore.from_env and client:
        info = keystore.info(client)
        if info.get("owner"):
            return f"person:{info['owner']}"
        if info.get("kind") == "person":
            return f"person:{client}"
    return f"key:{client}"


def grant_capabilities(conn, r: dict) -> None:
    """What this action, now going ahead, gives the agent: the first step of every `after:` chain it matches."""
    if r.get("status") not in ("completed", "pending") or r.get("kind") == "prompt":
        return
    stored = json.loads(r["input"]) if r.get("input") else None
    values = {"kind": r["kind"], "name": r["name"], "source": r["source"], "client": r["client"],
              "session_id": r["session_id"]}
    target = _target(stored) if stored is not None else None
    created = r["created_at"]
    for seq in policy.sequences:
        a = seq["after"]
        if not a or not Policy.matches(a["match"], values, stored, r.get("input") or ""):
            continue
        cap = f"after:{seq['id']}"
        if conn.execute(select(capabilities.c.id).where(capabilities.c.source_event == r["id"],
                                                        capabilities.c.capability == cap)).first():
            continue
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")) + timedelta(hours=a["within_hours"])) \
            .isoformat(timespec="milliseconds").replace("+00:00", "Z")
        conn.execute(capabilities.insert().values(
            identity=r.get("identity") or identity_of(r["client"]), capability=cap,
            target=target[1].lower() if target else None, source_event=r["id"], summary=_step_text(r["name"], stored),
            agent=r["source"], client=r["client"], session_id=r["session_id"], created_at=created, expires_at=expires))


def revoke_capabilities(conn, event_id: str) -> None:
    """The step didn't happen after all (it failed): it gives nothing."""
    conn.execute(delete(capabilities).where(capabilities.c.source_event == event_id))


def backfill_capabilities(conn) -> None:
    """New rules, or a database from before the table: work out what earlier steps still give."""
    longest = max((q["after"]["within_hours"] for q in policy.sequences if q["after"]), default=0)
    if not longest:
        return
    since = (datetime.now(timezone.utc) - timedelta(hours=longest)).isoformat().replace("+00:00", "Z")
    for row in conn.execute(select(events).where(events.c.created_at >= since,
                                                 events.c.status.in_(("completed", "pending")))
                            .order_by(events.c.created_at.desc()).limit(5000)).all():
        grant_capabilities(conn, dict(row._mapping))


def active_capabilities(identity: str | None = None, limit: int = 200) -> list[dict]:
    q = select(capabilities).where(capabilities.c.expires_at > utcnow())
    if identity:
        q = q.where(capabilities.c.identity == identity)
    with engine.connect() as conn:
        rows = conn.execute(q.order_by(capabilities.c.created_at.desc()).limit(limit)).all()
    reasons = {f"after:{q['id']}": q["reason"] for q in policy.sequences}
    return [{**dict(r._mapping), "chain": reasons.get(r.capability)} for r in rows]


def sequence_signals(conn, ev: "EventIn", client: str) -> list[dict]:
    """rules.yaml `sequences:` - this action, judged by what came before it (see rules.yaml)."""
    seqs = policy.sequences
    if not seqs:
        return []
    values = {"kind": ev.kind, "name": ev.name, "source": ev.source, "client": client, "session_id": ev.session_id}
    input_text = ev.input if isinstance(ev.input, str) else json.dumps(ev.input, default=str, ensure_ascii=False)
    out: list[dict] = []
    now = datetime.now(timezone.utc)
    ident = identity_of(client)
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
            caps = capabilities.c
            same_agent = and_(caps.agent == ev.source, caps.client == client)
            scope = {"session": caps.session_id == ev.session_id if ev.session_id else same_agent,
                     "agent": same_agent, "identity": caps.identity == ident, "all": true()}[a["scope"]]
            target = _target(redact(ev.input))    # compared with stored (redacted) copies
            q = select(capabilities).where(caps.capability == f"after:{seq['id']}", caps.expires_at > utcnow(), scope)
            if a["same_target"]:      # only the same thing: an action without a target can't be on it
                q = q.where(caps.target == target[1].lower()) if target else None
            if q is not None and (r := conn.execute(q.order_by(caps.created_at.desc()).limit(1)).first()):
                where = "" if r.session_id and r.session_id == ev.session_id else \
                    " (in another conversation)" if r.agent == ev.source else f" (by {r.agent or 'another agent'})"
                message, ref = f"{seq['reason']}. Because earlier{where}: {r.summary} ({_ago(r.created_at)}).", \
                    r.source_event
        if seq["count"] and message is None:
            c = seq["count"]
            scope = {"session": events.c.session_id == ev.session_id if ev.session_id else events.c.source == ev.source,
                     "agent": and_(events.c.source == ev.source, events.c.client == client),
                     "identity": events.c.identity == ident, "all": events.c.id.isnot(None)}[c["scope"]]
            target = _target(redact(ev.input))
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
                who = {"session": "in this conversation", "agent": "by this agent",
                       "identity": "by your agents, in any conversation", "all": "across all agents"}[c["scope"]]
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


def _edited_target(ev: "EventIn", line: str | None) -> str | None:
    """What this action changes, for the approver: a file path from the input, or the shell command."""
    inp = ev.input if isinstance(ev.input, dict) else {}
    for key in ("file_path", "path", "file", "target", "filename"):
        v = inp.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:200]
    if line:
        return line[:200]
    if isinstance(ev.input, str) and ev.input.strip():
        return ev.input.strip()[:200]
    return None


def taint_signals(conn, ev: "EventIn", client: str, held_setup_change: bool = False) -> list[dict]:
    """Taint checks (see taint.py): where is this action sending things, or is it changing the agent's own setup
    after reading content someone else wrote? held_setup_change = this action is already held by the guard-rail rule
    for agent-setup changes; then a prior untrusted read adds information, never a decision."""
    tc = policy.taint
    if not any(tc[k] != "off" for k in TAINT_EFFECT_KEYS):
        return []
    shell = _globbed(ev.name, policy.commands["tools"])
    line = commands.command_of(ev.input) if shell else None
    sends = taint.sends_out(line) if shell else _globbed(ev.name, tc["sinks"])
    # e.g. github.create_pull_request: a sink, even though "*pull_request*" reads
    if not sends and tc["after_untrusted_setup_edit"] == "off":
        return []
    since = (datetime.now(timezone.utc) - timedelta(hours=float(tc["lookback_hours"]))).isoformat().replace("+00:00", "Z")
    this_session = events.c.session_id == ev.session_id if ev.session_id else and_(events.c.source == ev.source,
                                                                                   events.c.client == client)
    scope = or_(this_session, events.c.identity == identity_of(client)) if tc["scope"] == "identity" else this_session
    rows = conn.execute(select(events.c.id, events.c.name, events.c.kind, events.c.input, events.c.output,
                               events.c.created_at, events.c.session_id, events.c.source, events.c.client)
                        .where(scope, events.c.created_at >= since)
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
    if sends and tc["untrusted_destination"] != "off":
        # compared with what was stored, so with the same masking (an address keeps its domain and fingerprint)
        for dest in taint.destinations(redact(ev.input), redact(line) if line else line):
            if taint.own_domain(dest, policy.history["company_domains"]):
                continue
            hit = next((r for r in outside if taint.appears_in(dest, r.output)), None)
            if hit and not any(taint.appears_in(dest, t) for t in trusted):
                elsewhere = "" if (hit.session_id == ev.session_id if ev.session_id else True) else ", in another conversation"
                out.append({"check": "untrusted_destination", "effect": tc["untrusted_destination"], "ref": hit.id,
                            "message": f"This sends to {dest['value']} ({dest['field']}), which appears in {hit.name} "
                                       f"({_ago(hit.created_at)}{elsewhere}) but not in anything you asked or in your own systems. "
                                       "Content from outside can carry hidden instructions (prompt injection)."})
                break
    here = (lambda r: r.session_id == ev.session_id) if ev.session_id else         (lambda r: r.source == ev.source and r.client == client)
    outside = [r for r in outside if here(r)]
    if sends and not out and outside and tc["after_untrusted"] != "off":      # a plain flag: this conversation only
        names = list(dict.fromkeys(r.name for r in outside))
        out.append({"check": "after_untrusted", "effect": tc["after_untrusted"], "ref": outside[0].id,
                    "message": f"Earlier in this conversation the agent read content from outside "
                               f"({', '.join(names[:3])}{'...' if len(names) > 3 else ''}), and this sends something out. "
                               "Check it's what you asked for."})
    if held_setup_change and outside and tc["after_untrusted_setup_edit"] != "off":   # #74: only adds information
        names = list(dict.fromkeys(r.name for r in outside))
        target = _edited_target(ev, line)
        out.append({"check": "after_untrusted_setup_edit", "effect": tc["after_untrusted_setup_edit"], "ref": outside[0].id,
                    "message": f"Earlier in this conversation the agent read content from outside "
                               f"({', '.join(names[:3])}{'...' if len(names) > 3 else ''}, {_ago(outside[0].created_at)}), "
                               f"and this changes the agent's own setup{f' ({target})' if target else ''}. "
                               "Content from outside can carry hidden instructions (prompt injection); "
                               "check this change is what you asked for."})
    return out


def reported_effects(metadata: dict | None) -> str | None:
    """What the hook measured on the developer's machine (effects.py): "Removes 3 commits from origin/main ...".
    Shown to the approver as reported by that machine; it never changes the decision."""
    found = (metadata or {}).get("effects")
    lines = [str(x)[:400] for x in found if isinstance(x, str) and x.strip()][:5] if isinstance(found, list) else []
    return "; ".join(lines) or None


def justification_of(ev: EventIn) -> str | None:
    """Why the agent says it's doing this: `justification` in its metadata or in the call (the MCP proxy offers that
    argument on every tool), or a shell tool's own `description` (Claude Code's Bash has one). Redacted, 1000 chars."""
    inp = ev.input if isinstance(ev.input, dict) else {}
    shell = inp.get("description") if ev.name in ("Bash", "PowerShell") else None
    for v in ((ev.metadata or {}).get("justification"), inp.get("justification"), shell):
        if isinstance(v, str) and v.strip():
            return redact(v.strip())[:1000]
    return None


NOTIFY_EVERY = float(os.getenv("SQUIDBRAKE_NOTIFY_EVERY_SECONDS", "3600"))
_notified: dict[tuple, float] = {}


def notify_rule_hit(rule: dict, row: dict) -> None:
    """A `notify` rule matched: the action ran, and the team hears about it, at most once an hour per rule and agent.
    shortcut: the hourly limit is per gateway process; with several workers each may send one, fine until it isn't."""
    who = row["source"] or row["client"]
    now = time.monotonic()
    if now - _notified.get((rule["id"], who), -NOTIFY_EVERY) < NOTIFY_EVERY:
        return
    _notified[(rule["id"], who)] = now
    dash = f"{(settings().get('public_url') or PUBLIC_URL or 'http://localhost:8080').rstrip('/')}/dashboard"
    text = (f"{who} ran {row['name']} ({rule['reason'] or rule['id']}). Nothing was held: rule '{rule['id']}' only "
            f"tells you. {_preview(row['input'], 200)}\nSee it: {dash}")
    threading.Thread(target=notify_text, args=(f"Squidbrake: {who} ran {row['name']}", text), daemon=True).start()


def take_notes(conn, ev: EventIn, client: str, event_id: str) -> list[dict]:
    """Notes people left for this agent or conversation, handed over with this action and marked delivered."""
    conds = [notes.c.agent.in_([k for k in (ev.source, client) if k])]
    if ev.session_id:
        conds.append(notes.c.session_id == ev.session_id)
    out = []
    for n in conn.execute(select(notes).where(notes.c.delivered_at.is_(None), or_(*conds))
                          .order_by(notes.c.created_at)).all():
        if conn.execute(update(notes).where(notes.c.id == n.id, notes.c.delivered_at.is_(None))
                        .values(delivered_at=utcnow(), delivered_event=event_id)).rowcount:
            audit(conn, client, "note.delivered", n.id, event=event_id, by=n.by)
            out.append({"by": n.by, "text": n.text, "at": n.created_at})
    return out


def record_event(ev: EventIn, client: str, client_ip: str | None) -> Decision:
    started = time.perf_counter()
    signals: list[dict] = []
    why = None if ev.kind == "prompt" else justification_of(ev)
    notify_rule = None
    if spent := usage_from_metadata(ev.metadata):      # the hook reports model tokens with each action
        spent.source, spent.session_id = ev.source, ev.session_id
        record_usage(client, spent)
    already_done = ev.error is not None or ev.output is not None
    # Squidbrake protecting itself (selfguard.py): checked in code, so no rules.yaml edit or shadow mode loosens it
    guard = None if already_done else selfguard.check(ev.kind, ev.name, ev.input, ev.metadata, KEYS_PATH.parent)
    if stop := stopped_for(ev.source, client, ev.session_id):
        decision, rule = "deny", policy.DEFAULT_RULE
        rule_id = "session-stop" if stop.get("session") else "emergency-stop"
        reason = stop_message(stop)
        remind_if_still_stopped(stop, ev.name)
    elif guard and guard["effect"] == "block":
        decision, rule, rule_id, reason, signals = "deny", policy.DEFAULT_RULE, "self-protection:approval", \
            guard["message"], [guard]
    elif ev.kind == "question" and not already_done:
        # ask_user: the agent asks a person instead of guessing. Always waits for one; the answer is the note.
        q = ev.input.get("question") if isinstance(ev.input, dict) else None
        if not isinstance(q, str) or not q.strip():
            raise HTTPException(422, "a question needs input {\"question\": \"...\"}")
        decision, rule, rule_id = "review", policy.DEFAULT_RULE, "ask-user"
        reason = f"{ev.source or client} asks: {redact(q.strip())[:300]}"
    elif not already_done and ev.kind != "prompt" and (over := budget_hit(ev.source, client)):
        decision, rule, rule_id, reason = "deny", policy.DEFAULT_RULE, f"budget:{over['budget']}", over["message"]
    else:
        # Policy sees the raw input; storage only ever sees the redacted copy.
        decision, reason, rule_id, rule = policy.evaluate(
            kind=ev.kind, name=ev.name, source=ev.source, client=client, session_id=ev.session_id, input=ev.input
        )
        if decision == "notify":       # runs; the team is told (below), unless a check below holds it after all
            decision, notify_rule = "allow", rule
        if rule.get("justification") == "required" and not why and not already_done and decision != "deny":
            reason = (f"Say why first: rule '{rule_id}' ({reason}) needs a reason before {ev.name} runs. Call it again "
                      "with a `justification` argument: one sentence on why this, and why now. The person who approves "
                      "it reads that.")
            decision, rule_id = "deny", f"justification:{rule_id}"
        if decision != "deny":
            command_found, only_reads = command_signals(ev.name, ev.input, ev.metadata)
            with engine.connect() as conn:
                # Most telling first: a sequence names the step that caused it; history checks are specific to
                # the business (who asked for this payment); taint and command checks are more general.
                signals = ([guard] if guard else []) + sequence_signals(conn, ev, client)
                # A command that only looks isn't a change: running `git status` twice is not a duplicate.
                signals += history_signals(conn, ev.name, redact(ev.input), to_stored_json(ev.input), ev.source,
                                           ev.session_id, is_change=decision == "review" and not only_reads,
                                           client=client, only_reads=only_reads)
                # #74: a change to the agent's own setup already held by the setup rule gets an extra signal
                # naming the outside content read before it; it only adds information, never a decision.
                held_setup_change = decision == "review" and rule_id == "approve-agent-setup-changes"
                signals += data_signals(ev) + taint_signals(conn, ev, client, held_setup_change=held_setup_change)                     + command_found + run_rule_signals(ev, client) + written_then_run(conn, ev, client)
            blocking = next((s for s in signals if s["effect"] == "block"), None)
            needs_person = next((s for s in signals if s["effect"] == "review"), None)
            signal_id = lambda s: f"sequence:{s['rule']}" if s["check"] == "sequence" else \
                f"self-protection:{s['check']}" if s["check"] in ("approval", "tamper") else \
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
    if decision in ("deny", "review") and rule_id not in ("emergency-stop", "session-stop", "command:catastrophic_command",
                                                          "ask-user") \
            and not str(rule_id).startswith(("budget:", "self-protection:")) and policy.shadow_for(ev.source, client, rule_id):
        would = decision
        reason = f"Shadow mode, allowed. Would have {'been blocked' if decision == 'deny' else 'waited for approval'}: {reason}"
        decision = "allow"
    broken = state_get("integrity", {}).get("changes") if policy.integrity == "fail_closed" else None
    if broken and not already_done and ev.kind not in ("prompt", "question") and any(c["kind"] != "rules" for c in broken) and (
            decision in ("deny", "review") or would or cannot_undo({"rule_id": rule_id, "signals": signals, "reason": reason})):
        decision, would, rule_id = "deny", None, "integrity:fail-closed"
        reason = (f"Squidbrake's own files changed ({integrity.describe(broken)}), so actions that wait for a person or "
                  f"can't be undone are blocked until a person checks and runs: {CLI} integrity accept")
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

    # Undo: should a copy of what this changes be kept before it runs? A rule can ask by name (snapshot: required);
    # otherwise everything held for a person or flagged as irreversible gets rules.yaml `snapshots:` (default required).
    snap_want, snap_strict = None, False
    if decision != "deny" and not already_ran and ev.kind != "question":
        named = rule.get("snapshot")
        risky = decision == "review" or any(s.get("check") in ("irreversible_command", "catastrophic_command")
                                            for s in signals)
        snap_want = named if named else policy.snapshots if risky else None
        snap_want = None if snap_want == "off" else snap_want
        snap_strict = named == "required"

    row = {
        "id": str(uuid.uuid4()), "created_at": now,
        "snapshot": json.dumps({"want": snap_want, "strict": snap_strict}) if snap_want else None,
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
        "decision_ms": round((time.perf_counter() - started) * 1000, 2),
        "identity": identity_of(client),
        "justification": why,
        "required_approvals": rule.get("required_approvals") if deadline and (rule.get("required_approvals") or 1) > 1
        else None,
        "escalate_at": _iso_plus(now, rule["escalate_after_seconds"]) if deadline and rule.get("escalate_after_seconds")
        else None,
        "escalate_to": json.dumps(rule["escalate_to"]) if deadline and rule.get("escalate_after_seconds") else None,
    }
    delivered: list[dict] = []
    with audited_tx() as conn:
        record_policy_version(conn)
        conn.execute(events.insert().values(**row))
        grant_capabilities(conn, row)
        audit(conn, client, "event.created", row["id"], rules=policy.fingerprint, name=ev.name, kind=ev.kind, source=ev.source,
              session_id=ev.session_id, status=status, decision=decision, rule_id=rule_id, reason=reason,
              input_sha256=_sha(row["input"]), output_sha256=_sha(row["output"]),
              signals=[f"{x['check']}:{x['effect']}" for x in signals] or None, would=would)
        # Notes ride on an answer the agent reads now; a held action's answer comes later, so they wait for the next.
        if (ev.metadata or {}).get("accepts_notes") and not already_done and decision != "review":
            delivered = take_notes(conn, ev, client, row["id"])
        if (ev.metadata or {}).get("while_unreachable"):   # warn-only mode: it ran while nothing checked it
            audit(conn, client, "protection.was_off", row["id"], name=ev.name, source=ev.source,
                  at=(ev.metadata or {}).get("ran_at"))
        if rule_id == "self-protection:approval":    # high severity: an agent reaching for the approval path
            audit(conn, client, "security.self_approval_attempt", row["id"], name=ev.name, source=ev.source,
                  session_id=ev.session_id, reason=reason)
    audit_log.info(json.dumps({k: row[k] for k in ("id", "created_at", "client", "source", "session_id",
                                                    "kind", "name", "status", "rule_id")}))
    forwarder.emit(siem_record("decision", row))
    if rule_id == "self-protection:approval":
        forwarder.emit(siem_record("self_approval_attempt", row))
        threading.Thread(target=notify_text, daemon=True, args=(
            f"Squidbrake: {ev.source or client} tried to reach the approval path",
            f"Blocked {ev.name}: {reason} Look at what this agent is doing.")).start()
    if decision != "deny" and any(Policy.matches(p, {"kind": ev.kind, "name": ev.name, "source": ev.source,
                                                     "client": client, "session_id": ev.session_id}, ev.input)
                                  for p in policy.proofs):
        _raw_inputs[row["id"]] = ev.input              # proof checks fill {input.x} from the real values
        while len(_raw_inputs) > 2000:
            _raw_inputs.pop(next(iter(_raw_inputs)))
        if already_ran and status == "completed":
            start_proof(row["id"], ev.output)
    if status == "awaiting_approval":
        notify_approval_needed(row)
        if ev.kind != "question":
            start_brief(row["id"])
    if notify_rule and decision == "allow" and not already_done:
        notify_rule_hit(notify_rule, row)
    return Decision(event_id=row["id"], decision=decision, reason=reason, rule_id=rule_id,
                    status=status, approval_deadline=deadline, signals=signals or None, would=would, risk=risk_score,
                    cannot_undo=cannot_undo({"rule_id": rule_id, "signals": signals, "reason": reason}),
                    snapshot=snap_want, snapshot_strict=snap_strict, notes=delivered or None)


_raw_inputs: dict[str, Any] = {}


# --------------------------------------------------------------------------- proof of work (proof.py)

def run_proofs(event_id: str, output: Any = None) -> dict | None:
    """Look in the real system for what this action says it did. Records the first matching check's answer."""
    import proof
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None or row.status not in ("completed", "pending"):
        return None
    stored_in = json.loads(row.input) if row.input else None
    raw_in = _raw_inputs.get(event_id, stored_in)
    out = output if output is not None else (json.loads(row.output) if row.output else None)
    values = {"kind": row.kind, "name": row.name, "source": row.source, "client": row.client, "session_id": row.session_id}
    check = next((p for p in policy.proofs if Policy.matches(p, values, raw_in)), None)
    if check is None:
        return None
    result = proof.run(check, raw_in, out)
    result["at"] = utcnow()
    with audited_tx() as conn:
        conn.execute(update(events).where(events.c.id == event_id).values(
            proof_status=result["status"], proof=to_stored_json(result)))
        audit(conn, "proof", "event.proof", event_id, status=result["status"], check=check["id"],
              message=result["message"][:500])
    forwarder.emit({**siem_record("proof", row), "proof": result["status"], "reason": result["message"]})
    if result["status"] == "mismatch":
        notify_text(f"Not actually done: {row.name}", f"{row.source or row.client}: {result['message']}")
    return result


def start_proof(event_id: str, output: Any = None) -> None:
    check_delay = max([p["delay_seconds"] for p in policy.proofs] or [0])

    def go():
        time.sleep(min(check_delay, 30))       # give the other system a moment to show the change
        try:
            run_proofs(event_id, output)
        except Exception:
            log.exception("proof check failed for %s", event_id)
    threading.Thread(target=go, daemon=True).start()


# --------------------------------------------------------------------------- AI approval briefs (brief.py)

def write_brief(event_id: str) -> dict | None:
    import brief
    cfg = settings()
    if not (cfg.get("ai_briefs") and cfg.get("ai_key")):
        return None
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None:
        return None
    d = row_to_dict(row)
    d["input"] = preview_of(d["input"])
    context = [{**s, "input": preview_of(s.get("input"), 300)} for s in event_context(row, limit=8)]
    out = brief.write(cfg["ai_key"], cfg.get("ai_model") or None, d, context)
    out["at"] = utcnow()
    with engine.begin() as conn:
        conn.execute(update(events).where(events.c.id == event_id).values(brief=json.dumps(out)))
    return out


def start_brief(event_id: str) -> None:
    cfg = settings()
    if not (cfg.get("ai_briefs") and cfg.get("ai_key")):
        return

    def go():
        try:
            write_brief(event_id)
        except Exception:
            log.exception("AI brief failed for %s", event_id)
    threading.Thread(target=go, daemon=True).start()


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
    cfg = {**defaults, **state_get("settings", {})}
    if not license.paid(KEYS_PATH.parent):       # Team plan: Slack, Teams, email and phone push
        cfg.update(slack_webhook="", teams_webhook="", email_to="", ntfy_topic="")
    return cfg


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
    if row.get("kind") == "question":
        inp = row["input"] or "{}"
        q = str(((json.loads(inp) if isinstance(inp, str) else inp) or {}).get("question", ""))
        return f"Question from {who}", f"{who} asks: {q[:1500]}\nAnswer it (or decline) on the page; the agent waits."
    title = f"Approve {row['name']}?"
    body = f"{who} wants to run {row['name']} ({row['reason']}).\n{_preview(row['input'])}"
    if row.get("justification"):
        body += f"\nWhy, says the agent: {row['justification'][:500]}"
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


def slack_blocks(title: str, body: str, token: str, link: str, expires: str, undo_warning: bool = False) -> list[dict]:
    """The approval as a Slack message with Approve / Reject buttons (Squidbrake's Slack app sends the click to
    /v1/slack/actions). Each button carries the same signed, one-event token as the one-tap link."""
    text = f"*{slack_escape(title)}*\n{slack_escape(body)}"
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}},
        {"type": "actions", "block_id": "squidbrake", "elements": [
            {"type": "button", "action_id": "approve", "style": "primary", "value": token,
             **({"confirm": {"title": {"type": "plain_text", "text": "This can't be undone"},
                             "text": {"type": "mrkdwn", "text": "Once it runs it can't be taken back. Approve anyway?"},
                             "confirm": {"type": "plain_text", "text": "Approve"},
                             "deny": {"type": "plain_text", "text": "Go back"}, "style": "danger"}}
                if undo_warning else {}),
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


def is_teams_webhook(webhook: str) -> bool:
    try:
        host = (urlsplit(webhook).hostname or "").lower()
    except ValueError:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in (
        "webhook.office.com", "logic.azure.com", "api.powerplatform.com"))


def teams_payload(title: str, body: str, link: str | None = None) -> dict:
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": title[:300], "weight": "Bolder", "size": "Medium", "wrap": True},
                     {"type": "TextBlock", "text": body[:3500], "wrap": True}]}
    if link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Review and approve or reject", "url": link}]
    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def send_teams(webhook: str, title: str, body: str, link: str | None = None) -> bool:
    """Send a Teams Adaptive Card; its button opens the existing approval page."""
    try:
        httpx.post(webhook, timeout=10, json=teams_payload(title, body, link)).raise_for_status()
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


def notify_approval_needed(row: dict, escalated_to: list[str] | None = None) -> None:
    """Tell a human, wherever they are: Slack (or any incoming webhook) and/or a phone push via ntfy.
    Both carry a signed link that opens a one-tap Approve / Reject page."""
    cfg = settings()
    if not (cfg["slack_webhook"] or cfg["ntfy_topic"] or cfg.get("teams_webhook") or email_ready(cfg)):
        return
    base = (cfg["public_url"] or "http://localhost:8080").rstrip("/")
    token = make_link_token(row["id"], cfg["notify_as"])
    link = f"{base}/a/{token}"
    title, body = approval_message(row)
    if cannot_undo(row):                       # said first, before anything else about it
        title = f"Can't be undone: {title}"
    if escalated_to:
        title = f"Escalated to {', '.join(escalated_to)}: {title}"
        body += "\nNobody decided in time, so it's escalated: they can decide it now too."
    if (row.get("required_approvals") or 1) > 1:
        body += f"\nNeeds {row['required_approvals']} different people to approve; one rejection stops it."
    expires = row["approval_deadline"]

    def send():
        if cfg["slack_webhook"]:
            try:
                if is_teams_webhook(cfg["slack_webhook"]):
                    payload = teams_payload(title, f"{body}\n\nExpires {expires}", link)
                elif any(host in cfg["slack_webhook"] for host in (
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
                    if cfg.get("slack_signing_secret") and row.get("kind") != "question":   # an answer needs typing
                        # Squidbrake's Slack app (Settings): decide right in the message, no page to open
                        payload["blocks"] = slack_blocks(title, body, token, link, expires, undo_warning=cannot_undo(row))
                httpx.post(cfg["slack_webhook"], timeout=10, json=payload).raise_for_status()
            except Exception:
                log.exception("Slack/webhook notification failed for event %s", row["id"])
        if cfg["ntfy_topic"]:
            try:
                httpx.post(cfg["ntfy_server"].rstrip("/"), timeout=10, json={
                    "topic": cfg["ntfy_topic"], "title": title, "message": body, "priority": 4,
                    "tags": ["raised_hand"], "click": link,
                    # can't be undone, or approvals need Face ID: approve on the page, which asks first
                    "actions": ([] if cannot_undo(row) or cfg.get("require_device_signature")
                                or row.get("kind") == "question" else [
                        {"action": "http", "label": "Approve", "url": f"{base}/v1/a/{token}/approve", "method": "POST", "clear": True},
                    ]) + [
                        {"action": "http", "label": "Reject", "url": f"{base}/v1/a/{token}/reject", "method": "POST", "clear": True},
                        # the kill switch, one tap from the lock screen: stops this agent until an admin resumes it
                        {"action": "http", "label": "Stop agent", "url": f"{base}/v1/a/{token}/stop", "method": "POST",
                         "clear": True},
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
            "justification": g("justification"), "input": (g("input") or "")[:500] or None}


def expire_overdue() -> int:
    """Apply each overdue approval's on_timeout outcome. Idempotent, safe from any worker."""
    now = utcnow()
    with engine.connect() as conn:  # cheap check first; this runs every couple of seconds
        if conn.execute(select(events.c.id).where(events.c.status == "awaiting_approval",
                                                  events.c.approval_deadline < now).limit(1)).first() is None:
            return 0
    n = 0
    with audited_tx() as conn:
        overdue = conn.execute(select(events.c.id, events.c.approval_on_timeout, events.c.source, events.c.client,
                                      events.c.session_id).where(
            events.c.status == "awaiting_approval", events.c.approval_deadline < now)).all()
        for eid, outcome, source, client, session_id in overdue:
            if stopped_for(source, client, session_id):
                continue        # frozen while its agent is stopped: resuming gives the time back (shift_waiting)
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


def escalate_due() -> int:
    """Approvals nobody decided by the rule's escalate_after_seconds: the escalate_to people may decide now too, and
    everyone is told again. Once per event; idempotent, safe from any worker."""
    now = utcnow()
    with engine.connect() as conn:
        if conn.execute(select(events.c.id).where(events.c.status == "awaiting_approval",
                                                  events.c.escalate_at < now).limit(1)).first() is None:
            return 0
    done = []
    with audited_tx() as conn:
        for row in conn.execute(select(events).where(events.c.status == "awaiting_approval",
                                                     events.c.escalate_at < now)).all():
            if stopped_for(row.source, row.client, row.session_id):
                continue                          # frozen like its deadline
            to = json.loads(row.escalate_to or "[]")
            before = json.loads(row.approvers) if row.approvers else None
            wider = None if before is None else list(dict.fromkeys(before + to))   # None stays "any approver"
            if conn.execute(update(events).where(events.c.id == row.id, events.c.escalate_at.is_not(None)).values(
                    escalate_at=None, approvers=json.dumps(wider) if wider else None)).rowcount:
                audit(conn, "timeout", "event.escalated", row.id, to=to)
                done.append((dict(row._mapping), to))
    for r, to in done:
        notify_approval_needed(r, escalated_to=to)
    return len(done)


def can_approve(who: str) -> bool:
    return keystore.can_approve(who)


def _device_check(event_id: str, outcome: str, who: str, proof: dict | None, rp_id: str | None) -> tuple[str | None, dict | None]:
    """A passkey's signature on this decision, checked. -> (device name, the proof to keep in the audit trail).
    With Settings > "Approvals need Face ID or fingerprint" on, an approval without one is refused (rejecting never
    needs one: saying no is always safe)."""
    import passkeys
    required = bool(settings().get("require_device_signature")) and outcome == "allow"
    if not proof:
        if required:
            raise HTTPException(403, "approvals need Face ID or fingerprint here: open the approval page on your "
                                     "registered phone or laptop and approve there")
        return None, None
    with engine.connect() as conn:
        dev = conn.execute(select(devices).where(devices.c.credential_id == str(proof.get("credential_id") or "")
                                                 .rstrip("="))).first()
    if dev is None or dev.person != who:
        raise HTTPException(403, f"that passkey isn't registered to {who}")
    try:
        count = passkeys.verify_assertion(proof=proof, public_key=json.loads(dev.public_key), rp_id=rp_id or "",
                                          event_id=event_id, outcome="approve" if outcome == "allow" else "reject")
    except passkeys.PasskeyError as e:
        raise HTTPException(403, f"the device signature didn't check: {e}")
    if dev.sign_count and count and count <= dev.sign_count:
        raise HTTPException(403, "that passkey signature was used before (a copied passkey?)")
    with engine.begin() as conn:
        conn.execute(update(devices).where(devices.c.credential_id == dev.credential_id)
                     .values(sign_count=count, last_used_at=utcnow()))
    kept = {k: proof.get(k) for k in ("statement", "authenticator_data", "client_data_json", "signature")}
    kept.update(credential_id=dev.credential_id, challenge=passkeys.challenge_of(str(proof.get("statement"))))
    return f"passkey: {dev.name or 'device'}", kept


def decide(event_id: str, outcome: Literal["allow", "deny"], who: str, note: str | None,
           via: str = "dashboard", device_proof: dict | None = None, rp_id: str | None = None) -> Decision:
    expire_overdue()
    decided_with, kept_proof = _device_check(event_id, outcome, who, device_proof, rp_id)
    with audited_tx() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
        if row is None:
            raise HTTPException(404, "event not found")
        if row.status != "awaiting_approval":
            raise HTTPException(409, f"event is not awaiting approval (status '{row.status}'"
                                     f"{', decided by ' + row.decided_by if row.decided_by else ''})")
        if not can_approve(who):
            raise HTTPException(403, f"'{who}' can't approve. Ask an admin to give them approval rights in Team.")
        if row.kind == "question" and outcome == "allow" and not (note or "").strip():
            raise HTTPException(400, "type the answer in the note: that's what the agent gets")
        if outcome == "allow" and row.kind != "question" and stopped_for(row.source, row.client, row.session_id):
            raise HTTPException(409, f"{row.source or row.client} is stopped: resume it first, or reject this")
        allowed = json.loads(row.approvers) if row.approvers else None
        if keystore.enabled and allowed and not keystore.matches(who, allowed):
            raise HTTPException(403, f"rule '{row.rule_id}' only accepts approval from: {', '.join(allowed)}")
        if keystore.enabled and who == row.client:
            raise HTTPException(403, "a key cannot approve its own request")
        owner = keystore.info(row.client).get("owner") if keystore.enabled else None
        per_rule = any(r["id"] == row.rule_id and r.get("second_person") for r in policy.rules)
        if owner and owner == who and (settings().get("second_person") or per_rule):
            raise HTTPException(403, f"'{row.client}' is {who}'s own agent and second-person approval is on, "
                                     "so someone else has to decide")
        # Two-person approval: each approval is kept; it runs once enough different people approved. A rejection
        # by any one of them stops it at once.
        need, so_far = row.required_approvals or 1, json.loads(row.approvals or "[]")
        partial = False
        if outcome == "allow" and need > 1:
            if any(a["by"] == who for a in so_far):
                raise HTTPException(409, f"you approved this already; it needs {need - len(so_far)} more "
                                         "approval(s) from someone else")
            now_list = so_far + [{"by": who, "at": utcnow(), "note": note, "with": decided_with}]
            if len(now_list) < need:
                same = events.c.approvals.is_(None) if row.approvals is None else events.c.approvals == row.approvals
                if not conn.execute(update(events).where(events.c.id == event_id, events.c.status == "awaiting_approval",
                                                         same).values(approvals=json.dumps(now_list))).rowcount:
                    raise HTTPException(409, "someone else decided a moment ago: look again")
                audit(conn, who, "event.approval_added", event_id, note=note, via=via, count=len(now_list), needed=need,
                      **({"device_proof": kept_proof, "decided_with": decided_with} if kept_proof else {}))
                partial = True    # still waiting: the next approver decides it
            who_all = " + ".join(a["by"] for a in now_list)
            notes_all = "; ".join(f"{a['by']}: {a['note']}" for a in now_list if a.get("note")) or None
        else:
            now_list, who_all, notes_all = None, who, note
        # Conditional update: if two approvers click at once, exactly one wins.
        won = partial or conn.execute(update(events).where(
            events.c.id == event_id, events.c.status == "awaiting_approval",
        ).values(status="pending" if outcome == "allow" else "denied", decision=outcome,
                 decided_by=who_all[:200], decided_at=utcnow(), decision_note=notes_all, decided_with=decided_with,
                 **({"approvals": json.dumps(now_list)} if now_list else {}))).rowcount
        if not won:
            raise HTTPException(409, "event was decided by someone else a moment ago")
        if not partial:
            if outcome == "allow":
                grant_capabilities(conn, dict(conn.execute(select(events).where(events.c.id == event_id)).first()._mapping))
            audit(conn, who, "event.approved" if outcome == "allow" else "event.rejected", event_id, note=note, via=via,
                  **({"device_proof": kept_proof, "decided_with": decided_with} if kept_proof else {}))
            forwarder.emit(siem_record("approved" if outcome == "allow" else "rejected",
                                       conn.execute(select(events).where(events.c.id == event_id)).first()))
    audit_log.info(json.dumps({"id": event_id, "approval": "added" if partial else outcome, "decided_by": who, "via": via}))
    return current_decision(event_id)


def current_decision(event_id: str) -> Decision:
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    snap = json.loads(row.snapshot) if row.snapshot else {}
    return Decision(event_id=row.id, decision=row.decision, reason=row.reason or "", rule_id=row.rule_id,
                    status=row.status, approval_deadline=row.approval_deadline,
                    decided_by=row.decided_by, decision_note=row.decision_note,
                    snapshot=snap.get("want"), snapshot_strict=bool(snap.get("strict")))


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
        if status == "failed":
            revoke_capabilities(conn, event_id)
    audit_log.info(json.dumps({"id": event_id, "status": status, "duration_ms": res.duration_ms}))
    if status == "completed" and policy.proofs:
        start_proof(event_id, res.output)          # the agent says it's done: look in the real system
    return {"event_id": event_id, "status": status}


CANNOT_UNDO_RULES = {"command:irreversible_command", "command:catastrophic_command", "block-sql-drop", "mass-deletes",
                     "destroy-after-recovery-removed", "approve-money-out", "approve-refunds", "approve-outbound-email"}


def cannot_undo(d: dict) -> bool:
    """Once this runs it can't be taken back (a delete, a force push, money or an email sent): approving warns first."""
    signals = d.get("signals")
    if isinstance(signals, str):
        try:
            signals = json.loads(signals)
        except ValueError:
            signals = []
    checks = {s.get("check") for s in signals or [] if isinstance(s, dict)}
    return (d.get("rule_id") in CANNOT_UNDO_RULES or bool(checks & {"irreversible_command", "catastrophic_command"})
            or "can't be undone" in str(d.get("reason") or ""))


def row_to_dict(row) -> dict:
    d = dict(row._mapping)
    for f in ("input", "output", "metadata", "approvers", "signals", "snapshot", "proof", "brief", "approvals",
              "escalate_to"):
        if d.get(f) is not None:
            d[f] = json.loads(d[f])
    d["cannot_undo"] = cannot_undo(d)
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
            await run_in_threadpool(escalate_due)
        except Exception:
            log.exception("approval expiry failed")
        await asyncio.sleep(2)


def _integrity_inputs() -> tuple[Path, Path | None, dict[str, Path]]:
    """rules.yaml, the installed package (not a checkout), and the agents' hook configs when they're on this computer."""
    package = BASE_DIR if (BASE_DIR / "__init__.py").exists() else None
    hooks: dict[str, Path] = {}
    if not (IN_DOCKER or PUBLIC_URL):
        import connect
        hooks = {"claude-code": connect.settings_path(None),
                 **{n: t["file"] for n, t in connect.hook_agents().items() if t["present"]}}
    return RULES_PATH, package, hooks


_integrity_lock = threading.Lock()   # the minute check and `integrity accept` never interleave


def check_integrity() -> list[dict]:
    """Compare with the copy kept the first time; a new change is recorded once and sent where approvals go."""
    with _integrity_lock:
        now = {**integrity.current(*_integrity_inputs()), "version": VERSION, "keys": integrity.keys_state(KEYS_PATH.parent)}
        changes = integrity.compare(KEYS_PATH.parent, now)
        # a person's rules edit, a newly connected agent, a secret made the first time: the new normal
        if changes and all(c["kind"] == "rules" or (c["kind"] in ("hooks", "keys") and c["change"] == "added")
                           for c in changes):
            integrity.accept(KEYS_PATH.parent, now)      # a person's edits, a newly connected agent: the new normal
            with audited_tx() as conn:
                audit(conn, "gateway", "integrity.noted", None, changes=changes)
            changes = []
        seen = state_get("integrity", {}).get("changes") or []
        new = [c for c in changes if c not in seen]
        if changes != seen:
            with audited_tx() as conn:
                state_set(conn, "integrity", {"changes": changes, "at": utcnow()})
                if changes:
                    audit(conn, "gateway", "integrity.changed", None, changes=changes)
    if new:
        notify_text("Squidbrake: its own files changed", f"{integrity.describe(new)}. If you did this, run: "
                    f"{CLI} integrity accept. If not, look at what your agents did just before.")
        forwarder.emit({"type": "integrity_changed", "time": utcnow(), "changes": new})
    return changes


def accept_integrity(who: str) -> None:
    with _integrity_lock:
        integrity.accept(KEYS_PATH.parent, {**integrity.current(*_integrity_inputs()), "version": VERSION,
                                            "keys": integrity.keys_state(KEYS_PATH.parent)})
        with audited_tx() as conn:
            state_set(conn, "integrity", {"changes": [], "at": utcnow()})
            audit(conn, who, "integrity.accepted", None)


def purge_expired_capabilities() -> None:
    with engine.begin() as conn:
        conn.execute(delete(capabilities).where(capabilities.c.expires_at <= utcnow()))


async def _integrity_loop():
    while True:
        try:
            await run_in_threadpool(purge_expired_capabilities)
            await run_in_threadpool(check_integrity)
        except Exception:
            log.exception("integrity check failed")
        await asyncio.sleep(15)          # keys.json changed behind Squidbrake's back: said within seconds


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
    try:
        if n := await run_in_threadpool(sign_missing_checkpoints):
            log.info("signed %d audit checkpoint(s) for history recorded before checkpoints existed", n)
    except Exception:
        log.exception("couldn't sign audit checkpoints (the chain itself is unaffected)")
    app.state.http = httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=False)
    # MCP by URL: no read timeout, a held call or an event stream can stay open a long time
    app.state.mcp_http = httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None), follow_redirects=False)
    if servers := mcp_servers():
        await run_in_threadpool(hub.sync, servers)
    tasks = [asyncio.create_task(_expiry_loop()), asyncio.create_task(_digest_loop()), asyncio.create_task(_s3_loop()),
             asyncio.create_task(_integrity_loop())]
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
    # People with view-only access can look at everything they may see and change nothing (env keys predate levels)
    if request.method not in ("GET", "HEAD") and keystore.enabled and not keystore.from_env \
            and keystore.access(name) == "viewer":
        raise HTTPException(403, f"'{name}' can view only: ask an owner or admin for approver access to act")
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


def _rp_id(request: Request) -> str:
    import passkeys
    return passkeys.rp_id_for(settings().get("public_url"), request.headers.get("host") or "localhost")


@app.post("/v1/events/{event_id}/approve", response_model=Decision)
def approve(event_id: str, request: Request, body: ApprovalIn | None = None, who: str = Depends(auth)):
    return decide(event_id, "allow", who, body.note if body else None,
                  device_proof=body.device_proof if body else None, rp_id=_rp_id(request))


@app.post("/v1/events/{event_id}/reject", response_model=Decision)
def reject(event_id: str, request: Request, body: ApprovalIn | None = None, who: str = Depends(auth)):
    return decide(event_id, "deny", who, body.note if body else None,
                  device_proof=body.device_proof if body else None, rp_id=_rp_id(request))


@app.get("/v1/me")
def me(who: str = Depends(auth)):
    i = keystore.info(who)
    return {"client": who, "kind": i["kind"], "roles": i["roles"], "is_admin": keystore.is_admin(who),
            "is_owner": keystore.is_owner(who), "access": keystore.access(who),
            "can_approve": can_approve(who), "auth_enabled": keystore.enabled,
            "mode": policy.mode, "shadow_agents": policy.shadow_agents, "version": VERSION, "latest": latest_known(),
            "plan": PLAN or None, "trial_ends": TRIAL_ENDS or None, "trial_over": trial_over(), "upgrade_url": UPGRADE_URL,
            "license": license.status(KEYS_PATH.parent)}


def _local_only(request: Request) -> None:
    """The toggles change files on the computer the gateway runs on: only when that's the person's own computer."""
    if IN_DOCKER or PUBLIC_URL or (request.client and request.client.host not in ("127.0.0.1", "::1", "localhost", "testclient")):
        raise HTTPException(404, "the agents on this computer can only be switched from the computer itself")


@app.get("/v1/agents/local")
def agents_here(request: Request, _: str = Depends(admin)):
    _local_only(request)
    import connect
    return {"agents": connect.local_agents()}


class AgentToggleIn(BaseModel):
    on: bool


@app.post("/v1/agents/local/{name}")
def agent_toggle(name: str, body: AgentToggleIn, request: Request, who: str = Depends(admin)):
    """Connect one agent to Squidbrake, or take it out: Settings → Agents on this computer."""
    _local_only(request)
    import connect
    if name not in connect.AGENT_LABELS:
        raise HTTPException(404, "unknown agent")
    port = os.getenv("SQUIDBRAKE_LISTEN_PORT") or os.getenv("PORT") or "8080"
    try:
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            connect.set_agent(name, body.on, f"http://localhost:{port}")
    except SystemExit as e:
        raise HTTPException(400, str(e))
    with audited_tx() as conn:
        audit(conn, who, "agent.connected" if body.on else "agent.disconnected", name, via="dashboard")
    return {"agents": connect.local_agents()}


class InventoryIn(BaseModel):
    machine: str = Field(..., min_length=1, max_length=100)
    agents: list[dict] = Field(default_factory=list, max_length=50)   # connect.local_agents(): name, label, present, connected


INVENTORY_STALE_DAYS = 14


@app.post("/v1/agents/inventory")
def report_inventory(body: InventoryIn, who: str = Depends(auth)):
    """A computer says which agents it has and which go through Squidbrake (`squidbrake doctor` sends it), so the team
    sees the ones that don't yet. Kept per computer; the latest report replaces the one before."""
    clean = [{"name": str(a.get("name"))[:40], "label": str(a.get("label") or a.get("name"))[:60],
              "connected": bool(a.get("connected"))} for a in body.agents if a.get("present") and a.get("name")]
    with audited_tx() as conn:
        inv = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "inventory")).scalar()
                         or "{}")
        if body.machine not in inv and len(inv) >= 2000:
            raise HTTPException(429, "2000 computers reported already; remove old ones first")
        before = inv.get(body.machine, {}).get("agents")
        inv[body.machine] = {"at": utcnow(), "key": who, "agents": clean}
        state_set(conn, "inventory", inv)
        if before != clean:
            audit(conn, who, "agents.inventory", body.machine, agents={a["name"]: a["connected"] for a in clean})
    return {"recorded": body.machine, "not_connected": [a["label"] for a in clean if not a["connected"]]}


@app.get("/v1/agents/inventory")
def team_inventory(_: str = Depends(person)):
    """Every computer that reported, newest first, and the agents on them that don't go through Squidbrake yet."""
    inv = state_get("inventory", {}) or {}
    stale = (datetime.now(timezone.utc) - timedelta(days=INVENTORY_STALE_DAYS)).isoformat().replace("+00:00", "Z")
    machines = sorted(({"machine": m, **v, "stale": v["at"] < stale} for m, v in inv.items()),
                      key=lambda m: m["at"], reverse=True)
    missing = [{"machine": m["machine"], "agent": a["name"], "label": a["label"], "at": m["at"]}
               for m in machines if not m["stale"] for a in m["agents"] if not a["connected"]]
    return {"machines": machines, "not_connected": missing}


def latest_known() -> str | None:
    """The newest version the CLI's daily update check saw (squidbrake/cli.py); this gateway never asks on its own."""
    try:
        latest = json.loads((HOME_DIR / "update-check.json").read_text(encoding="utf-8")).get("latest")
    except (OSError, ValueError):
        return None
    num = lambda v: tuple(int(n) for n in re.findall(r"\d+", str(v))[:3])
    return latest if latest and num(latest) > num(VERSION) else None


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

Access = Literal["owner", "admin", "approver", "viewer"]
LEVEL_ROLES = ("owner", "admin")


class MemberIn(BaseModel):
    name: str = Field(..., max_length=64)
    kind: Literal["person", "agent"] = "person"
    approver: bool = False
    roles: list[str] = Field(default_factory=list)
    owner: str | None = Field(None, max_length=64, description="for an agent: the person it works for")
    access: Access | None = Field(None, description="for a person: owner, admin, approver or viewer (sets approver "
                                                    "and the owner/admin roles)")


class MemberPatch(BaseModel):
    approver: bool | None = None
    roles: list[str] | None = None
    owner: str | None = Field(None, max_length=64, description="for an agent: the person it works for ('' clears it)")
    access: Access | None = None


def _with_access(access: str | None, approver: bool | None, roles: list[str] | None,
                 current_roles: list[str]) -> tuple[bool | None, list[str] | None]:
    """An access level is approver + the owner/admin roles; other roles (finance, ops...) are kept as they are."""
    if access is None:
        return approver, roles
    others = [r for r in (roles if roles is not None else current_roles) if r not in LEVEL_ROLES]
    level = {"owner": ["owner", "admin"], "admin": ["admin"]}.get(access, [])
    return access != "viewer", level + others


def _check_level_change(who: str, name: str, before: list[str], after: list[str]) -> None:
    """Only an owner makes or unmakes admins and owners, and a team always keeps at least one owner."""
    changed = {r for r in LEVEL_ROLES if (r in before) != (r in after)}
    if changed and not keystore.is_owner(who):
        raise HTTPException(403, f"only an owner can change who is {' or '.join(sorted(changed))}")
    if "owner" in before and "owner" not in after:
        owners = [m["name"] for m in keystore.listing() if "owner" in m["roles"]]
        if owners == [name]:
            raise HTTPException(400, "a team needs at least one owner: make someone else an owner first")


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
    approver, roles = m.approver, m.roles
    if PLAN == "free" and m.kind == "person":
        raise HTTPException(402, f"The free plan is for one person. To add your team: {UPGRADE_URL}")
    if m.kind == "person" and any(x["kind"] == "person" for x in keystore.listing()):
        license.need(KEYS_PATH.parent, "people")
    if m.kind == "person":
        approver, roles = _with_access(m.access, m.approver, m.roles, [])
        _check_level_change(who, m.name, [], [r.strip().lower() for r in roles])
    secret = _team_call(lambda: keystore.add(m.name, approver=approver, kind=m.kind, roles=roles, owner=m.owner))
    with audited_tx() as conn:
        audit(conn, who, "team.added", m.name, kind=m.kind, approver=approver, roles=roles, owner=m.owner,
              access=keystore.access(m.name))
    return {"name": m.name, "key": secret, "access": keystore.access(m.name),
            "note": "shown once; the gateway keeps only a hash"}


@app.patch("/v1/team/{name}")
def team_update(name: str, p: MemberPatch, who: str = Depends(admin)):
    before = keystore.info(name)["roles"] if name in keystore.names() else []
    approver, roles = _with_access(p.access, p.approver, p.roles, before)
    if roles is not None:
        roles = [r.strip().lower() for r in roles]
        if name == who and not set(roles) & set(LEVEL_ROLES):
            raise HTTPException(400, "you can't remove your own admin role")
        _check_level_change(who, name, before, roles)
    info = _team_call(lambda: keystore.update(name, approver=approver, roles=roles, owner=p.owner))
    with audited_tx() as conn:
        audit(conn, who, "team.updated", name, approver=info["approver"], roles=info["roles"], owner=info["owner"],
              access=info["access"])
    return {"name": name, **info}


@app.delete("/v1/team/{name}")
def team_remove(name: str, who: str = Depends(admin)):
    if name == who:
        raise HTTPException(400, "you can't remove your own key")
    if name in keystore.names():
        _check_level_change(who, name, keystore.info(name)["roles"], [])
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
    return stop_agents(body, who)


def stop_agents(body: StopIn, who: str, via: str = "dashboard") -> dict:
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
        audit(conn, who, "controls.stopped", target, reason=body.reason, via=via)
        if body.minutes and not body.session:   # it ends by itself: its waiting approvals get that time now
            shift_waiting(conn, body.agent, body.minutes * 60, who)
    log.warning("STOP (%s) by %s: %s", target if target != "*" else "all agents", who, body.reason)
    return s


def _iso_plus(iso: str, seconds: float) -> str:
    d = datetime.fromisoformat(iso.replace("Z", "+00:00")) + timedelta(seconds=seconds)
    return d.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def shift_waiting(conn, agent: str | None, seconds: float, who: str) -> int:
    """Move the deadlines of approvals waiting on `agent` (None: every agent) by `seconds`: a stop freezes them, so
    nothing times out while nobody may act on it. shortcut: an agent under two stops at once (its own and "all")
    gets both; fine while stops are rare and short."""
    if abs(seconds) < 1:
        return 0
    q = select(events.c.id, events.c.approval_deadline).where(events.c.status == "awaiting_approval",
                                                              events.c.approval_deadline.is_not(None))
    if agent:
        q = q.where(or_(events.c.source == agent, events.c.client == agent))
    rows = conn.execute(q).all()
    for eid, deadline in rows:
        conn.execute(update(events).where(events.c.id == eid).values(approval_deadline=_iso_plus(deadline, seconds)))
    if rows:
        audit(conn, who, "approvals.deadlines_moved", agent or "*", seconds=round(seconds), count=len(rows))
    return len(rows)


def _give_time_back(conn, agent: str | None, entry: dict | None, who: str) -> None:
    """A stop ended early: the waiting approvals get back exactly the time they spent frozen."""
    if not _live(entry):
        return
    now = datetime.now(timezone.utc)
    if entry.get("until"):    # it was given its full length at the start: take back what's left
        shift_waiting(conn, agent, -(datetime.fromisoformat(entry["until"].replace("Z", "+00:00")) - now)
                      .total_seconds(), who)
    else:
        shift_waiting(conn, agent, (now - datetime.fromisoformat(entry["at"].replace("Z", "+00:00")))
                      .total_seconds(), who)


@app.post("/v1/controls/resume")
def controls_resume(body: StopIn, who: str = Depends(admin)):
    with audited_tx() as conn:
        s = json.loads(conn.execute(select(gateway_state.c.value).where(gateway_state.c.key == "stop")).scalar()
                       or '{"all": null, "agents": {}}')
        if body.session:
            s.setdefault("sessions", {}).pop(body.session, None)
        elif body.agent:
            _give_time_back(conn, body.agent, s.setdefault("agents", {}).pop(body.agent, None), who)
        else:
            _give_time_back(conn, None, s.get("all"), who)
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
        if not session:
            _give_time_back(conn, agent, was, who)
        if not agent and not session:
            s["all"] = None
        state_set(conn, "stop", s)
        if was:
            audit(conn, who, "controls.resumed", f"session:{session}" if session else agent or "*", via="command line")
    return bool(was)


# ---- notes to a running agent

class NoteIn(BaseModel):
    agent: str | None = Field(None, max_length=200, description="an agent's source or key name")
    session: str | None = Field(None, max_length=200, description="or one conversation")
    text: str = Field(..., min_length=1, max_length=2000)


@app.post("/v1/notes")
def send_note(body: NoteIn, who: str = Depends(person)):
    """Tell a running agent something ("the staging cluster is eu-west-1"): it gets it with its next action. Anyone who
    may stop an agent may steer one; a note grants nothing."""
    if not (can_approve(who) or keystore.is_admin(who)):
        raise HTTPException(403, "only approvers and admins can send notes to agents")
    if not (body.agent or body.session) or (body.agent and body.session):
        raise HTTPException(400, "send it to one agent or one session")
    row = {"id": str(uuid.uuid4()), "created_at": utcnow(), "by": who, "agent": body.agent,
           "session_id": body.session, "text": redact(body.text.strip())}
    with audited_tx() as conn:
        conn.execute(notes.insert().values(**row))
        audit(conn, who, "note.sent", row["id"], agent=body.agent, session=body.session, text_sha256=_sha(row["text"]))
    return {**row, "delivered_at": None}


@app.get("/v1/notes")
def list_notes(limit: int = Query(50, ge=1, le=500), _: str = Depends(person)):
    with engine.connect() as conn:
        rows = conn.execute(select(notes).order_by(notes.c.created_at.desc()).limit(limit)).all()
    return {"notes": [dict(r._mapping) for r in rows]}


@app.delete("/v1/notes/{note_id}")
def cancel_note(note_id: str, who: str = Depends(person)):
    with audited_tx() as conn:
        n = conn.execute(select(notes).where(notes.c.id == note_id)).first()
        if n is None:
            raise HTTPException(404, "no such note")
        if n.by != who and not keystore.is_admin(who):
            raise HTTPException(403, "only whoever sent it, or an admin, can take a note back")
        if not conn.execute(notes.delete().where(notes.c.id == note_id, notes.c.delivered_at.is_(None))).rowcount:
            raise HTTPException(409, "already delivered: the agent has it")
        audit(conn, who, "note.cancelled", note_id)
    return {"cancelled": note_id}


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
    s3_bucket: str | None = Field(None, max_length=200)          # the audit trail archived there every day (s3_archive)
    s3_prefix: str | None = Field(None, max_length=200)
    s3_region: str | None = Field(None, max_length=40)
    smtp_host: str | None = Field(None, max_length=200)
    smtp_port: int | None = Field(None, ge=1, le=65535)
    smtp_user: str | None = Field(None, max_length=200)
    smtp_password: str | None = Field(None, max_length=500)
    smtp_from: str | None = Field(None, max_length=200)
    siem_url: str | None = Field(None, max_length=1000)          # every decision, as it happens, to Splunk / Datadog / any HTTP
    siem_token: str | None = Field(None, max_length=500)
    siem_format: Literal["json", "splunk", "datadog", "otlp"] | None = None
    ai_briefs: bool | None = None                                # a plain-English risk note on each held action
    ai_key: str | None = Field(None, max_length=300)             # the customer's own Anthropic API key ("" removes it)
    ai_model: str | None = Field(None, max_length=100)
    require_device_signature: bool | None = None                 # approvals need Face ID / fingerprint (a passkey)


def public_settings() -> dict:
    """Settings as the dashboard sees them: the AI key is never sent back, only whether one is set."""
    s = settings()
    key = s.pop("ai_key", "") or ""
    return {**s, "ai_key_set": bool(key), "ai_key_hint": f"…{key[-4:]}" if len(key) > 8 else "",
            "license": license.status(KEYS_PATH.parent)}


@app.get("/v1/settings")
def get_settings(_: str = Depends(admin)):
    return public_settings()


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
    if changes.get("ai_model") and not re.fullmatch(r"[a-z0-9][a-z0-9.\-]{2,99}", changes["ai_model"]):
        raise HTTPException(400, "ai_model: a model id such as claude-opus-5-5")
    if changes.get("require_device_signature"):
        with engine.connect() as conn:
            if conn.execute(select(devices.c.credential_id).where(devices.c.person == who).limit(1)).first() is None:
                raise HTTPException(400, "register your own phone or laptop first (📱 Phone → Set up Face ID), so "
                                         "you can still approve once this is on")
    if changes.get("ntfy_topic") and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", changes["ntfy_topic"]):
        raise HTTPException(400, "ntfy_topic: letters, digits, '-' and '_' only")
    if any(changes.get(k) for k in ("slack_webhook", "teams_webhook", "email_to")):
        license.need(KEYS_PATH.parent, "channels")
    if changes.get("ntfy_topic"):
        license.need(KEYS_PATH.parent, "phone")
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
    return public_settings()


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
            teams = is_teams_webhook(cfg["slack_webhook"])
            payload = teams_payload("Squidbrake", f"Test from {who}: notifications work.") if teams else {
                "text": f":white_check_mark: Squidbrake test from {who}: notifications work."}
            httpx.post(cfg["slack_webhook"], json=payload,
                       timeout=10).raise_for_status()
            sent.append("Teams" if teams else "slack")
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
    d["input"] = preview_of(d["input"])
    return {"approver": approver, "context": event_context(row),
            "device_required": bool(settings().get("require_device_signature")), **{k: d[k] for k in (
        "id", "name", "kind", "source", "client", "session_id", "created_at", "status", "decision", "rule_id",
        "reason", "input", "approval_deadline", "approval_on_timeout", "decided_by", "decided_at", "decision_note",
        "signals", "cannot_undo", "brief", "snapshot", "decided_with")}}


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


# Before /v1/a/{token}/{outcome}, which would otherwise take these paths.
@app.post("/v1/a/{token}/challenge")
def link_challenge(token: str, body: ChallengeIn, request: Request):
    event_id, approver = read_link_token(token)
    return _challenge(event_id, body.outcome, approver, request)


@app.post("/v1/a/{token}/stop")
def link_stop(token: str, body: StopIn | None = None):
    """Kill switch from a notification: stop the agent that asked, in one tap (an admin resumes it)."""
    event_id, approver = read_link_token(token)
    with engine.connect() as conn:
        row = conn.execute(select(events.c.source, events.c.client).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    agent = row.source or row.client
    reason = (body.reason if body and body.reason else None) or "stopped from a notification"
    return stop_agents(StopIn(agent=agent, reason=reason, minutes=body.minutes if body else None), approver, via="link")


@app.post("/v1/a/{token}/{outcome}", response_model=Decision)
def link_decide(token: str, outcome: Literal["approve", "reject"], request: Request, body: ApprovalIn | None = None):
    event_id, approver = read_link_token(token)
    return decide(event_id, "allow" if outcome == "approve" else "deny", approver,
                  body.note if body else None, via="link", device_proof=body.device_proof if body else None,
                  rp_id=_rp_id(request))


# ---- while the gateway is down (offline.py)

@app.get("/v1/policy/offline")
def policy_offline(who: str = Depends(auth)):
    """What each rule says to do while this gateway can't be reached, for the agents' computers to keep a copy of.
    First matching rule wins, as on the gateway; `default` covers everything else."""
    policy._maybe_reload()
    return {"client": who, "default": policy.when_unreachable, "fingerprint": policy.fingerprint,
            "default_action": policy.default, "shell_tools": policy.commands["tools"],
            "rules": [{"id": r["id"], "match": r["match_spec"], "action": r["action"],
                       "when_unreachable": r["when_unreachable"] or policy.when_unreachable} for r in policy.rules]}


# ---- spend brake

@app.post("/v1/usage")
def post_usage(u: UsageIn, who: str = Depends(auth)):
    """Model tokens (and money, if known) an agent just spent. rules.yaml `budgets:` pause it when it's over."""
    record_usage(who, u)
    over = budget_hit(u.source, who)
    return {"recorded": True, "paused": bool(over), "message": over["message"] if over else None}


@app.get("/v1/budgets")
def get_budgets(_: str = Depends(person)):
    return {"budgets": [{k: b[k] for k in ("id", "per", "period", "tokens", "usd", "reason")} for b in policy.budgets],
            "spend": budget_status()}


# ---- undo snapshots

SNAPSHOT_MAX_CHARS = int(os.getenv("SNAPSHOT_MAX_CHARS", str(2_000_000)))


def save_snapshot(event_id: str, snap: SnapshotIn, who: str) -> dict:
    with engine.connect() as conn:
        row = conn.execute(select(events.c.id, events.c.client, events.c.snapshot).where(events.c.id == event_id)).first()
    if row is None:
        raise HTTPException(404, "event not found")
    if keystore.enabled and who != row.client and not keystore.is_admin(who):
        raise HTTPException(403, "only the agent that asked (or an admin) can attach its snapshot")
    current = json.loads(row.snapshot) if row.snapshot else {}
    if snap.skipped:
        current.update(skipped=snap.skipped[:500], at=utcnow())
        sid = None
    else:
        data = json.dumps(redact(snap.data), default=str, ensure_ascii=False) if snap.data is not None else None
        if data and len(data) > SNAPSHOT_MAX_CHARS:
            raise HTTPException(413, f"the copy is {len(data):,} characters; the limit is {SNAPSHOT_MAX_CHARS:,}")
        sid = str(uuid.uuid4())
        current.update(id=sid, kind=snap.kind, ref=snap.ref, summary=(snap.summary or "")[:1000], at=utcnow())
        current.pop("skipped", None)
    with audited_tx() as conn:
        if sid:
            conn.execute(snapshots.insert().values(id=sid, event_id=event_id, created_at=utcnow(), kind=snap.kind,
                                                   ref=snap.ref, summary=snap.summary, data=data, sha256=_sha(data)))
        conn.execute(update(events).where(events.c.id == event_id).values(snapshot=json.dumps(current)))
        audit(conn, who, "event.snapshot", event_id, kind=snap.kind, ref=snap.ref, skipped=snap.skipped,
              data_sha256=_sha(data) if sid else None)
    return current


@app.post("/v1/events/{event_id}/snapshot")
def post_snapshot(event_id: str, snap: SnapshotIn, who: str = Depends(auth)):
    """The copy kept right before the action ran (or why none could be made, in which case it didn't run)."""
    return save_snapshot(event_id, snap, who)


@app.get("/v1/events/{event_id}/snapshots")
def get_snapshots(event_id: str, _: str = Depends(person)):
    with engine.connect() as conn:
        rows = conn.execute(select(snapshots).where(snapshots.c.event_id == event_id)
                            .order_by(snapshots.c.created_at)).all()
    return {"snapshots": [{**dict(r._mapping), "data": json.loads(r.data) if r.data else None} for r in rows]}


# ---- proof of work, AI briefs

@app.post("/v1/events/{event_id}/proof")
def recheck_proof(event_id: str, _: str = Depends(person)):
    """Look in the real system again (e.g. after it was slow to show the change)."""
    result = run_proofs(event_id)
    if result is None:
        raise HTTPException(404, "no proof check in rules.yaml matches this action (proof_checks:), or it hasn't run")
    return result


@app.post("/v1/events/{event_id}/brief")
def regenerate_brief(event_id: str, _: str = Depends(person)):
    if not (settings().get("ai_briefs") and settings().get("ai_key")):
        raise HTTPException(400, "AI briefs are off: an admin turns them on in Settings with the team's Anthropic key")
    return write_brief(event_id) or {"error": "event not found"}


# ---- passkeys: approvals signed by Face ID / fingerprint (passkeys.py)

class DeviceFinishIn(BaseModel):
    name: str = Field("My device", max_length=100)
    challenge: str = Field(..., max_length=200)
    credential_id: str = Field(..., max_length=400)
    client_data_json: str = Field(..., max_length=20000)
    attestation_object: str = Field(..., max_length=20000)


def _approver(who: str) -> str:
    if not can_approve(who):
        raise HTTPException(403, f"'{who}' can't approve, so there's nothing to sign")
    return who


@app.post("/v1/devices/register/start")
def device_register_start(request: Request, who: str = Depends(person)):
    import passkeys
    license.need(KEYS_PATH.parent, "phone")
    _approver(who)
    rp = _rp_id(request)
    with engine.connect() as conn:
        have = [r[0] for r in conn.execute(select(devices.c.credential_id).where(devices.c.person == who)).all()]
    return {"rp": {"id": rp, "name": "Squidbrake"},
            "user": {"id": passkeys.b64u(hashlib.sha256(who.encode()).digest()[:16]), "name": who, "displayName": who},
            "challenge": passkeys.registration_challenge(_link_secret(), who),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"userVerification": "required", "residentKey": "preferred"},
            "excludeCredentials": [{"type": "public-key", "id": c} for c in have],
            "attestation": "none", "timeout": 120000}


@app.post("/v1/devices/register/finish")
def device_register_finish(body: DeviceFinishIn, request: Request, who: str = Depends(person)):
    import passkeys
    _approver(who)
    try:
        passkeys.check_registration_challenge(_link_secret(), who, body.challenge)
        dev = passkeys.register(credential_id=body.credential_id, client_data_json=body.client_data_json,
                                attestation_object=body.attestation_object, challenge=body.challenge, rp_id=_rp_id(request))
    except passkeys.PasskeyError as e:
        raise HTTPException(400, f"couldn't add this device: {e}")
    with audited_tx() as conn:
        if conn.execute(select(devices.c.credential_id).where(devices.c.credential_id == dev["credential_id"])).first():
            raise HTTPException(409, "this device is already registered")
        conn.execute(devices.insert().values(credential_id=dev["credential_id"], person=who, name=body.name.strip()[:100],
                                             created_at=utcnow(), public_key=json.dumps(dev["public_key"]),
                                             sign_count=dev["sign_count"]))
        audit(conn, who, "device.added", body.name.strip()[:100], credential_id=dev["credential_id"],
              public_key=dev["public_key"])
    return {"added": body.name, "credential_id": dev["credential_id"]}


@app.get("/v1/devices")
def device_list(who: str = Depends(person)):
    with engine.connect() as conn:
        q = select(devices).order_by(devices.c.created_at)
        rows = conn.execute(q if keystore.is_admin(who) else q.where(devices.c.person == who)).all()
    return {"devices": [{k: getattr(r, k) for k in ("credential_id", "person", "name", "created_at", "last_used_at")}
                        for r in rows], "required": bool(settings().get("require_device_signature"))}


@app.delete("/v1/devices/{credential_id}")
def device_remove(credential_id: str, who: str = Depends(person)):
    with audited_tx() as conn:
        row = conn.execute(select(devices).where(devices.c.credential_id == credential_id)).first()
        if row is None:
            raise HTTPException(404, "no such device")
        if row.person != who and not keystore.is_admin(who):
            raise HTTPException(403, "only its owner or an admin can remove a device")
        conn.execute(delete(devices).where(devices.c.credential_id == credential_id))
        audit(conn, who, "device.removed", row.name, credential_id=credential_id, person=row.person)
    return {"removed": credential_id}


def _challenge(event_id: str, outcome: str, approver: str, request: Request) -> dict:
    import passkeys
    with engine.connect() as conn:
        creds = [r[0] for r in conn.execute(select(devices.c.credential_id).where(devices.c.person == approver)).all()]
    text_ = passkeys.statement(event_id, outcome)
    return {"statement": text_, "challenge": passkeys.challenge_of(text_), "rp_id": _rp_id(request),
            "allow_credentials": creds, "required": bool(settings().get("require_device_signature"))}


@app.post("/v1/events/{event_id}/challenge")
def event_challenge(event_id: str, body: ChallengeIn, request: Request, who: str = Depends(person)):
    """What to sign with a passkey to approve or reject this event: the page asks the device, then sends the result
    with the decision (device_proof)."""
    return _challenge(event_id, body.outcome, _approver(who), request)


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
            "audit": verify_audit_chain(), "week": weekly.build(engine, events, days),
            "integrity": {"mode": policy.integrity, **state_get("integrity", {"changes": [], "at": None})}}


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
        signed = conn.execute(select(func.count()).where(events.c.created_at >= since,
                                                         events.c.decided_with.isnot(None))).scalar() or 0
        snaps = conn.execute(select(events.c.snapshot).where(events.c.created_at >= since,
                                                             events.c.snapshot.isnot(None))).all()
        proofs = dict(conn.execute(select(events.c.proof_status, func.count()).where(
            events.c.created_at >= since, events.c.proof_status.isnot(None)).group_by(events.c.proof_status)).all())
        n_checkpoints = conn.execute(select(func.count()).select_from(audit_checkpoints)).scalar() or 0
        n_devices = conn.execute(select(func.count()).select_from(devices)).scalar() or 0
    kept = sum(1 for (x,) in snaps if '"id"' in x)
    skipped = sum(1 for (x,) in snaps if '"skipped"' in x)
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
            "changes": {"entries": changes, "stops": sum(1 for c in changes if c["action"] == "controls.stopped")},
            "controls": {"snapshots": policy.snapshots, "snapshots_kept": kept, "snapshots_skipped": skipped,
                         "when_unreachable": policy.when_unreachable,
                         "allow_while_unreachable": sum(1 for r in policy.rules if r["when_unreachable"] == "allow"),
                         "checkpoints": n_checkpoints, "ledger_key": ledger_public()["public_key"],
                         "devices": n_devices, "device_signed": signed,
                         "device_required": bool(settings().get("require_device_signature")),
                         "budgets": len(policy.budgets), "proof_checks": len(policy.proofs),
                         "proofs": {"confirmed": proofs.get("confirmed", 0), "mismatch": proofs.get("mismatch", 0),
                                    "error": proofs.get("error", 0)},
                         "redaction": "secrets, emails and card numbers masked before storage" if REDACT_PERSONAL
                                      else "secrets masked before storage"}}


@app.get("/v1/audit/evidence-pack")
def evidence_pack(days: int = Query(90, ge=1, le=3650), who: str = Depends(person)):
    """A printable page for an auditor: controls in place, what happened, and the requirements it speaks to."""
    license.need(KEYS_PATH.parent, "audit")
    with audited_tx() as conn:
        audit(conn, who, "audit.exported", None, format="evidence-pack", days=days)
    return Response(evidence.render_html(build_evidence(days, who)), media_type="text/html", headers={
        "Content-Disposition": f'inline; filename="squidbrake-evidence-pack-{datetime.now():%Y%m%d}.html"'})


class FeedbackIn(BaseModel):
    verdict: Literal["legit", "right"]                 # legit: it should have run (a false positive)


def give_feedback(event_id: str, verdict: str, who: str) -> dict:
    """A person says whether a hold or block was right. Counted per rule and per week (weekly.py)."""
    with audited_tx() as conn:
        row = conn.execute(select(events).where(events.c.id == event_id)).first()
        if row is None:
            raise HTTPException(404, "event not found")
        if not (row.approval_deadline or row.would or (row.status == "denied" and not row.decided_by)):
            raise HTTPException(409, "only actions Squidbrake held or blocked (or would have) can be marked")
        conn.execute(update(events).where(events.c.id == event_id)
                     .values(feedback=verdict, feedback_by=who, feedback_at=utcnow()))
        audit(conn, who, "event.feedback", event_id, verdict=verdict, rule_id=row.rule_id)
    return {"id": event_id, "feedback": verdict, "rule_id": row.rule_id}


@app.post("/v1/events/{event_id}/feedback")
def post_feedback(event_id: str, body: FeedbackIn, who: str = Depends(person)):
    return give_feedback(event_id, body.verdict, who)


@app.get("/v1/capabilities")
def get_capabilities(identity: str | None = None, _: str = Depends(person)):
    """What the agents' earlier steps give them right now, per identity, until each expires."""
    return {"capabilities": active_capabilities(identity)}


@app.get("/v1/integrity")
def get_integrity(_: str = Depends(person)):
    return {"mode": policy.integrity, **state_get("integrity", {"changes": [], "at": None})}


@app.post("/v1/integrity/accept")
def post_integrity_accept(who: str = Depends(admin)):
    accept_integrity(who)
    return {"changes": []}


@app.get("/v1/reports/week")
def report_week(days: int = Query(7, ge=1, le=366), format: Literal["json", "md"] = "json",
                _: str = Depends(person)):
    r = weekly.build(engine, events, days)
    return Response(weekly.markdown(r), media_type="text/markdown") if format == "md" else r


@app.get("/v1/reports/summary")
def report_summary(days: int = Query(7, ge=1, le=3650), _: str = Depends(person)):
    return build_report(days)


@app.get("/v1/audit/verify")
def audit_verify(_: str = Depends(person)):
    return verify_audit_chain()


@app.get("/v1/audit/export.json")
def audit_evidence(who: str = Depends(person)):
    license.need(KEYS_PATH.parent, "audit")
    """Everything needed to check the history offline: python verify.py <file> (see verify.py)."""
    with audited_tx() as conn:
        audit(conn, who, "audit.exported", None, format="evidence")
    return Response(json.dumps(evidence_body(who), ensure_ascii=False, indent=1), media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="squidbrake-evidence-{datetime.now():%Y%m%d-%H%M}.json"'})


def evidence_body(who: str) -> dict:
    with engine.connect() as conn:
        entries = [dict(r._mapping) for r in conn.execute(select(audit_trail).order_by(audit_trail.c.seq)).all()]
        evs = [dict(r._mapping) for r in conn.execute(select(*[events.c[c] for c in EXPORT_COLUMNS])
                                                      .order_by(events.c.created_at)).all()]
        policies = {r.fingerprint: r.content for r in conn.execute(select(policy_versions)).all()}
        cps = checkpoint_rows(conn)
        devs = [{"credential_id": r.credential_id, "person": r.person, "name": r.name, "public_key": r.public_key}
                for r in conn.execute(select(devices)).all()]
    key = ledger_public()
    return {"format": verify.FORMAT, "generated_at": utcnow(), "generated_by": who,
            "head_hash": entries[-1]["hash"] if entries else GENESIS, "entries": entries, "events": evs,
            "policies": policies, "checkpoints": cps, "ledger_key": key, "devices": devs,
            "how_to_check": f"python verify.py this-file.json --key {key['public_key']}   (verify.py and signing.py are "
                            "in the Squidbrake repository; check the key against the one this gateway publishes at "
                            "/v1/audit/public-key)"}


def s3_archive(cfg: dict | None = None, force: bool = False) -> str | None:
    """Once a day: the whole evidence file (audit chain, actions, rule versions) to s3://bucket/prefix/, a copy
    outside this machine that `python verify.py` checks. Credentials come from AWS's usual places (on EC2, the
    instance role), never from Squidbrake. -> the object's key, or None if it isn't set up or ran already today."""
    cfg = cfg or settings()
    bucket = (cfg.get("s3_bucket") or "").strip()
    if not bucket:
        return None
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not force and state_get("s3_archived", "") == day:
        return None
    import boto3                                  # optional: pip install "squidbrake[s3]"
    key = f"{(cfg.get('s3_prefix') or 'squidbrake').strip('/')}/squidbrake-evidence-{day}.json"
    body = json.dumps(evidence_body("s3-archive"), ensure_ascii=False).encode()
    boto3.client("s3", region_name=(cfg.get("s3_region") or None)).put_object(
        Bucket=bucket, Key=key, Body=body, ContentType="application/json", ServerSideEncryption="AES256")
    with audited_tx() as conn:
        state_set(conn, "s3_archived", day)
        audit(conn, "s3-archive", "audit.archived", f"s3://{bucket}/{key}", bytes=len(body))
    return key


async def _s3_loop():
    while True:
        try:
            await run_in_threadpool(s3_archive)
        except Exception:
            log.exception("S3 archive failed (the evidence file wasn't uploaded; it tries again in an hour)")
        await asyncio.sleep(3600)


@app.get("/v1/audit/public-key")
@app.get("/.well-known/squidbrake-ledger-key.json", include_in_schema=False)
def audit_public_key():
    """The public half of the key that signs audit checkpoints. Public on purpose: publish it (your site, your security
    page, a ticket with your auditor) so anyone can check an export with `verify.py --key`."""
    with engine.connect() as conn:
        last = conn.execute(select(audit_checkpoints).order_by(audit_checkpoints.c.seq.desc()).limit(1)).first()
    return {**ledger_public(), "latest_checkpoint": dict(last._mapping) if last else None}


@app.get("/v1/audit/checkpoints")
def audit_checkpoint_list(limit: int = Query(50, ge=1, le=1000), _: str = Depends(person)):
    with engine.connect() as conn:
        rows = conn.execute(select(audit_checkpoints).order_by(audit_checkpoints.c.seq.desc()).limit(limit)).all()
    return {"key": ledger_public(), "checkpoints": [dict(r._mapping) for r in rows]}


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
    license.need(KEYS_PATH.parent, "audit")
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
    license.need(KEYS_PATH.parent, "audit")
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
    for d in rows:      # lists show previews; one event (GET /v1/events/{id}) has the whole stored copy
        d["input"], d["output"] = preview_of(d["input"]), preview_of(d["output"])
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
    if decision.snapshot and request.method in ("PUT", "PATCH", "DELETE"):
        # Undo for an API: read the record as it is now (the same URL, the same credentials), keep it, then change it.
        why = None
        try:
            before = await request.app.state.http.get(url, headers={k: v for k, v in fwd_headers.items()
                                                                     if k.lower() not in ("content-type",)})
            if 200 <= before.status_code < 300:
                await run_in_threadpool(save_snapshot, decision.event_id, SnapshotIn(
                    kind="http", ref=f"GET {upstream}/{path}", summary=f"{upstream}/{path} as it was before the "
                    f"{request.method}", data=_body_preview(before.content)), client)
            else:
                why = f"reading {upstream}/{path} first returned {before.status_code}"
        except (httpx.HTTPError, HTTPException) as e:
            why = f"couldn't read {upstream}/{path} first ({getattr(e, 'detail', None) or type(e).__name__})"
        if why:
            await run_in_threadpool(save_snapshot, decision.event_id, SnapshotIn(skipped=why), client)
            if decision.snapshot == "required":
                await run_in_threadpool(complete_event, decision.event_id,
                                        ResultIn(error=f"not run: no undo copy could be made ({why})"))
                return JSONResponse(status_code=403, headers={"X-Gateway-Event-Id": decision.event_id}, content={
                    "event_id": decision.event_id, "decision": "deny",
                    "reason": f"Squidbrake keeps a copy before this kind of change and couldn't ({why}), so it "
                              "didn't run. Set snapshot: best_effort on the rule to allow it without one."})
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


# ---- rules history: every version that decided something, a diff against today's, and putting one back

@app.get("/v1/policy/versions")
def policy_version_list(_: str = Depends(person)):
    policy._maybe_reload()
    with engine.connect() as conn:
        rows = conn.execute(select(policy_versions.c.fingerprint, policy_versions.c.first_seen)
                            .order_by(policy_versions.c.first_seen.desc()).limit(200)).all()
    return {"current": policy.fingerprint,
            "versions": [{"fingerprint": r.fingerprint, "first_seen": r.first_seen,
                          "current": r.fingerprint == policy.fingerprint} for r in rows]}


def _version_text(fp: str) -> str:
    with engine.connect() as conn:
        text_ = conn.execute(select(policy_versions.c.content).where(policy_versions.c.fingerprint == fp)).scalar()
    if text_ is None:
        raise HTTPException(404, "no such rules version")
    return text_


@app.get("/v1/policy/versions/{fp}")
def policy_version_get(fp: str, _: str = Depends(person)):
    """That version's text, and what changed from it to today's rules (a unified diff)."""
    import difflib
    old = _version_text(fp)
    policy._maybe_reload()
    diff = "".join(difflib.unified_diff(old.splitlines(keepends=True), policy.source.splitlines(keepends=True),
                                        f"rules {fp}", f"rules now ({policy.fingerprint})"))
    return {"fingerprint": fp, "content": old, "diff_to_current": diff, "current": fp == policy.fingerprint}


@app.post("/v1/policy/versions/{fp}/restore")
def policy_version_restore(fp: str, who: str = Depends(admin)):
    """Put an earlier rules.yaml back (a backup of today's is kept). Only if it still loads as it did."""
    old = _version_text(fp)
    if verify.rules_fingerprint(old) != fp:
        raise HTTPException(409, "that stored version doesn't match its fingerprint; not restoring it")
    import tempfile
    with tempfile.TemporaryDirectory() as d:          # it must load with this version of Squidbrake first
        trial = Policy(Path(d) / "rules.yaml")
        trial.path.write_text(old, encoding="utf-8")
        trial._maybe_reload()
    if trial.fingerprint != fp:
        raise HTTPException(400, "that version doesn't load with this version of Squidbrake (see the gateway log)")
    try:
        backup = policy_edit.replace_all(policy.path, old)
    except OSError as e:
        raise HTTPException(500, f"couldn't write the rules file: {e}")
    policy._maybe_reload()
    with audited_tx() as conn:
        audit(conn, who, "policy.restored", fp, backup=backup.name)
    return {"ok": policy.fingerprint == fp, "fingerprint": policy.fingerprint, "backup": backup.name}


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


def _cli_init(args) -> int:
    created = keystore.ensure_initialized()
    if created:
        print_banner(None, created)
    elif getattr(args, "quiet", False):      # `squidbrake` runs this before installing the service: nothing to say
        pass
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
    sub.add_parser("init", help="create the first keys (happens automatically on first start)").add_argument(
        "--quiet", action="store_true", help="say nothing if they exist already")
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
    li = sub.add_parser("license", help="the Team plan's license: status, or set the one you were sent")
    li.add_argument("action", nargs="?", choices=["status", "set"], default="status")
    li.add_argument("token", nargs="?", help="with set: the license line from squidbrake.com")
    rp = sub.add_parser("report", help="the weekly report: actions, holds, blocks, false positives, latency, chains")
    rp.add_argument("--week", action="store_true", help="the last 7 days (the default)")
    rp.add_argument("--days", type=int, default=7)
    rp.add_argument("--json", action="store_true", help="JSON instead of Markdown")
    rp.add_argument("--out", help="write it to this file")
    ig = sub.add_parser("integrity", help="has anything changed Squidbrake's hooks, rules or installed files?")
    ig.add_argument("action", nargs="?", choices=["status", "accept"], default="status",
                    help="accept: the changes are yours, take them as the new normal")
    cp = sub.add_parser("capabilities", help="what the agents' earlier steps give them now (the chains in progress)")
    cp.add_argument("--json", action="store_true")
    au = sub.add_parser("audit", help="audit verify: check the tamper-evident record end to end")
    au.add_argument("action", choices=["verify"])
    fb = sub.add_parser("feedback", help="say whether a hold or block was right: feedback EVENT_ID legit|right")
    fb.add_argument("event_id")
    fb.add_argument("verdict", choices=["legit", "right"])
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
            "evidence": _cli_evidence, "lockdown": _cli_lockdown, "explain": _cli_explain,
            "report": _cli_report, "feedback": _cli_feedback, "integrity": _cli_integrity,
            "audit": _cli_audit, "capabilities": _cli_capabilities, "license": _cli_license}[args.cmd](args)


def _cli_capabilities(args) -> int:
    migrate(engine)
    caps = active_capabilities()
    if args.json:
        print(json.dumps(caps, indent=2))
        return 0
    if not caps:
        print("No chain in progress: no earlier step gives an agent anything right now.")
    for c in caps:
        print(f"{c['identity']}: {c['summary']} by {c['agent'] or c['client']} ({_ago(c['created_at'])}, until "
              f"{c['expires_at'][:16]}). Starts: {c['chain'] or c['capability']}")
    return 0


def _cli_integrity(args) -> int:
    migrate(engine)
    if args.action == "accept":
        accept_integrity("command-line")
        print("Accepted: the hooks, rules and installed files as they are now are the new normal.")
        return 0
    changes = check_integrity()
    if not changes:
        print("Intact: hooks, rules and installed files are as they were.")
        return 0
    print(f"Changed: {integrity.describe(changes)}.\nIf you did this, run: {CLI} integrity accept")
    return 1


def _cli_audit(args) -> int:
    migrate(engine)
    r = verify_audit_chain()
    if r.get("ok"):
        print(f"Intact: {r.get('entries')} entries, every link checks.")
        return 0
    where = f" The first broken link is entry #{r['first_bad_seq']}." if r.get("first_bad_seq") else ""
    print(f"BROKEN: {r.get('message', 'the record was changed')}.{where}")
    return 1


def _cli_report(args) -> int:
    migrate(engine)
    r = weekly.build(engine, events, 7 if args.week else args.days)
    text = json.dumps(r, indent=2) if args.json else weekly.markdown(r)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Written to {Path(args.out).resolve()}")
    else:
        print(text)
    return 0


def _cli_feedback(args) -> int:
    migrate(engine)
    try:
        r = give_feedback(args.event_id, args.verdict, "command-line")
    except HTTPException as e:
        print(e.detail, file=sys.stderr)
        return 1
    print(f"Marked {r['id']} as {r['feedback']} (rule {r['rule_id'] or 'default'}).")
    return 0


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


def _cli_license(args) -> int:
    data = KEYS_PATH.parent
    if args.action == "set":
        terms = license.check(args.token or "")
        if not terms:
            print("That license isn't valid (or has expired). Copy the whole line you were sent.")
            return 1
        data.mkdir(parents=True, exist_ok=True)
        (data / license.FILE).write_text(args.token.strip() + "\n", encoding="utf-8")
        print(f"Team plan on for {terms['org']} until {terms['expires']}. Restart the gateway: squidbrake service restart")
        return 0
    st = license.status(data)
    if st["licensed"]:
        print(f"Team plan: {st['org']}, until {st['expires']}.")
    elif st["in_grace"]:
        print(f"No license. Team features ({', '.join(st['features'])}) stay on until {st['grace_until']}; "
              f"after that they need the Team plan: {st['upgrade_url']}")
    else:
        print(f"Free plan. Team features ({', '.join(st['features'])}) need the Team plan: {st['upgrade_url']}")
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
