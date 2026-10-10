"""
Squidbrake Insights: see how pilot users use Squidbrake, without ever seeing what their agents did.

  /start/<code>        the page you send a founder: their install commands, with their pilot code filled in
  /install.ps1 | .sh   one-line installers (pipx + squidbrake)
  /admin               your dashboard (sign in with your password, or INSIGHTS_ADMIN_KEY): pilots, activity, blocks
  /team                a form for teams that want help setting Squidbrake up (linked from `connect all` and the
                       dashboard): the only way to hear from installs that aren't pilots, since nothing is tracked
  POST /v1/pilot/join  an install joins with a code (squidbrake pilot join)
  POST /v1/ping        an install's usage counts (every 6 hours)

Run:  INSIGHTS_ADMIN_KEY=... uvicorn app:app --port 8090      (data in INSIGHTS_DB, default ./data/insights.db)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

HERE = Path(__file__).resolve().parent
DB = Path(os.getenv("INSIGHTS_DB", HERE / "data" / "insights.db"))
ADMIN_KEY = os.getenv("INSIGHTS_ADMIN_KEY", "")
PUBLIC_URL = os.getenv("INSIGHTS_PUBLIC_URL", "").rstrip("/")
CONTACT = os.getenv("INSIGHTS_CONTACT", "")           # shown on start pages, e.g. "WhatsApp +91..., you@x.com"
CODE_RE = re.compile(r"^[a-z0-9-]{3,40}$")

app = FastAPI(title="Squidbrake Insights", docs_url=None, redoc_url=None)
# squidbrake.com is a static site: its "Book a demo" form posts here (/v1/team-request), from the browser
app.add_middleware(CORSMiddleware, allow_origin_regex=r"https://([a-z0-9-]+\.)?(squidbrake\.com|onrender\.com)",
                   allow_methods=["POST"], allow_headers=["Content-Type"])
_lock = threading.Lock()


def db() -> sqlite3.Connection:
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c


with db() as _c:
    _c.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS pilots (code TEXT PRIMARY KEY, company TEXT NOT NULL, contact TEXT, note TEXT,
        created_at TEXT NOT NULL, page_views INTEGER NOT NULL DEFAULT 0, first_view TEXT, last_view TEXT);
    CREATE TABLE IF NOT EXISTS installs (install_id TEXT PRIMARY KEY, code TEXT NOT NULL, joined_at TEXT NOT NULL,
        left_at TEXT, last_seen TEXT, version TEXT, os TEXT, mode TEXT, rules INTEGER, agents TEXT,
        rules_hit TEXT, total_events INTEGER, first_event TEXT);
    CREATE TABLE IF NOT EXISTS days (install_id TEXT NOT NULL, day TEXT NOT NULL, counts TEXT NOT NULL,
        PRIMARY KEY (install_id, day));
    CREATE TABLE IF NOT EXISTS catches (install_id TEXT NOT NULL, t TEXT NOT NULL, data TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS catches_install ON catches (install_id);
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS install_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
        code TEXT, os TEXT, step TEXT, installer TEXT, log TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS team_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
        name TEXT NOT NULL, email TEXT NOT NULL, company TEXT, team_size TEXT, agents TEXT, note TEXT, source TEXT,
        done INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS link_clicks (channel TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (channel, day));
    """)
    if "ref" not in {r[1] for r in _c.execute("PRAGMA table_info(installs)")}:
        _c.execute("ALTER TABLE installs ADD COLUMN ref TEXT")           # where they heard about it (telemetry.py)
    # hosted pilots: their own gateway at <subdomain>.<HOSTED_DOMAIN>, started by provision.py on the server
    if "connected" not in {r[1] for r in _c.execute("PRAGMA table_info(installs)")}:
        _c.execute("ALTER TABLE installs ADD COLUMN connected TEXT")     # agents with Squidbrake's hook, as JSON
    _have = {r[1] for r in _c.execute("PRAGMA table_info(pilots)")}
    for _col, _type in (("hosted", "INTEGER NOT NULL DEFAULT 0"), ("subdomain", "TEXT"), ("state", "TEXT"),
                        ("admin_key", "TEXT"), ("agent_key", "TEXT"), ("keys_revealed_at", "TEXT"), ("error", "TEXT"),
                        ("mrr", "INTEGER NOT NULL DEFAULT 0"), ("paying_since", "TEXT")):
        if _col not in _have:
            _c.execute(f"ALTER TABLE pilots ADD COLUMN {_col} {_type}")

# Every install that says yes to the first-run question (telemetry.py) joins this code. It has gone missing from the
# database twice (deleted with the other test links), and then every one of those joins was refused with a 404 that
# nobody sees: so it is put back on every start, and it can't be deleted.
COMMUNITY_CODE = os.getenv("INSIGHTS_COMMUNITY_CODE", "community-opt-in-ins-a42929")


def seed_community() -> None:
    with db() as c:
        c.execute("INSERT OR IGNORE INTO pilots (code, company, note, created_at) VALUES (?, ?, ?, ?)",
                  (COMMUNITY_CODE, "Community (opted in)", "everyone who said yes on first run; can't be deleted",
                   datetime.now(timezone.utc).isoformat(timespec="seconds")))


seed_community()

HOSTED_DOMAIN = os.getenv("HOSTED_DOMAIN", "")        # e.g. app.squidbrake.com (with a *.app wildcard DNS record)
HOSTED_MAX = int(os.getenv("HOSTED_MAX", "6"))         # each hosted gateway uses ~50-100 MB of memory


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- admin sign-in
# The dashboard signs in with a password you set (hashed here) and gets a 30-day session token; the password itself is
# never stored in the browser. INSIGHTS_ADMIN_KEY (from the server's .env) also works: provision.py uses it, and it's
# how you sign in the first time and set the password.

SESSION_DAYS = 30
_failures: dict[str, list[float]] = {}        # ip -> recent failed sign-ins


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000)
    return f"pbkdf2_sha256$300000${salt.hex()}${digest.hex()}"


def _password_ok(password: str) -> bool:
    with db() as c:
        row = c.execute("SELECT value FROM settings WHERE key='admin_password'").fetchone()
    if not row or not password:
        return False
    _, rounds, salt, digest = row[0].split("$")
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
    return hmac.compare_digest(got, digest)


def _key_ok(key: str) -> bool:
    return bool(ADMIN_KEY) and bool(key) and hmac.compare_digest(key, ADMIN_KEY)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _session_ok(token: str) -> bool:
    if not token:
        return False
    with db() as c:
        return bool(c.execute("SELECT 1 FROM sessions WHERE token_hash=? AND expires_at > ?", (_token_hash(token), now())).fetchone())


def _throttle(ip: str) -> None:
    recent = [t for t in _failures.get(ip, []) if time.time() - t < 900]
    _failures[ip] = recent
    if len(recent) >= 8:
        raise HTTPException(429, "too many failed sign-ins: try again in 15 minutes")


def _failed(ip: str) -> None:
    _failures.setdefault(ip, []).append(time.time())


def admin(request: Request, x_admin_key: str = Header(default="")) -> None:
    if _key_ok(x_admin_key) or _session_ok(x_admin_key):
        return
    raise HTTPException(401, "sign in required")


class LoginIn(BaseModel):
    password: str = Field(max_length=200)


@app.post("/v1/admin/login")
def login(body: LoginIn, request: Request):
    ip = request.client.host if request.client else "?"
    _throttle(ip)
    if not (_password_ok(body.password) or _key_ok(body.password)):
        _failed(ip)
        raise HTTPException(401, "wrong password")
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
    with _lock, db() as c:
        c.execute("DELETE FROM sessions WHERE expires_at <= ?", (now(),))
        c.execute("INSERT INTO sessions (token_hash, created_at, expires_at) VALUES (?,?,?)", (_token_hash(token), now(), expires))
        has_password = bool(c.execute("SELECT 1 FROM settings WHERE key='admin_password'").fetchone())
    return {"token": token, "expires": expires, "has_password": has_password}


@app.post("/v1/admin/logout")
def logout(x_admin_key: str = Header(default="")):
    with _lock, db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(x_admin_key),))
    return {"ok": True}


class PasswordIn(BaseModel):
    current: str = Field(max_length=200)
    new: str = Field(min_length=10, max_length=200)


@app.post("/v1/admin/password", dependencies=[Depends(admin)])
def set_password(body: PasswordIn, request: Request):
    """Set or change the admin password. Needs the current password (or the server key the first time)."""
    ip = request.client.host if request.client else "?"
    _throttle(ip)
    if not (_password_ok(body.current) or _key_ok(body.current)):
        _failed(ip)
        raise HTTPException(403, "the current password (or server key) is wrong")
    with _lock, db() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)", (_hash_password(body.new),))
        c.execute("DELETE FROM sessions")                     # every browser signs in again with the new password
    return {"ok": True}


@app.get("/v1/admin/me", dependencies=[Depends(admin)])
def admin_me():
    with db() as c:
        has_password = bool(c.execute("SELECT 1 FROM settings WHERE key='admin_password'").fetchone())
    return {"has_password": has_password}


def public_url(request: Request) -> str:
    return PUBLIC_URL or str(request.base_url).rstrip("/")


# --------------------------------------------------------------------------- installs report in

class JoinIn(BaseModel):
    code: str = Field(max_length=40)
    install_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    version: str = Field(default="", max_length=40)
    os: str = Field(default="", max_length=80)
    ref: str = Field(default="", pattern=r"^([a-z0-9][a-z0-9-]{0,29})?$")


class PingIn(BaseModel):
    code: str = Field(max_length=40)
    install_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    usage: dict


# A pilot code is the only secret on a start page (and, for a hosted pilot, the way to its keys once), so guessing
# codes is slowed down: an address that asks for 30 codes that don't exist in 10 minutes waits.
_misses: dict[str, list[float]] = {}


def _ip(request: Request | None) -> str:
    return (request.client.host if request and request.client else "") or "?"


def _guessing(request: Request | None) -> None:
    ip = _ip(request)
    recent = [t for t in _misses.get(ip, []) if time.time() - t < 600]
    if len(_misses) > 10_000:                          # many addresses: keep only the ones still counting
        for k in [k for k, v in _misses.items() if not v or time.time() - v[-1] > 600]:
            _misses.pop(k, None)
    _misses[ip] = recent
    if len(recent) >= 30:
        raise HTTPException(429, "too many unknown pilot codes from here: try again in 10 minutes")


def _missed(request: Request | None) -> None:
    _misses.setdefault(_ip(request), []).append(time.time())


def _pilot(c, code: str, request: Request | None = None):
    _guessing(request)
    row = c.execute("SELECT * FROM pilots WHERE code=?", (code.lower(),)).fetchone()
    if not row:
        _missed(request)
        raise HTTPException(404, "unknown pilot code: check the link you were sent")
    return row


@app.post("/v1/pilot/join")
def join(j: JoinIn, request: Request):
    with _lock, db() as c:
        p = _pilot(c, j.code, request)
        c.execute("""INSERT INTO installs (install_id, code, joined_at, version, os, ref) VALUES (?,?,?,?,?,?)
                     ON CONFLICT(install_id) DO UPDATE SET code=excluded.code, left_at=NULL, version=excluded.version,
                     os=excluded.os, ref=COALESCE(excluded.ref, installs.ref)""",
                  (j.install_id, p["code"], now(), j.version, j.os, j.ref or None))
    return {"company": p["company"]}


@app.post("/v1/pilot/leave")
def leave(j: PingIn | JoinIn):
    with _lock, db() as c:
        c.execute("UPDATE installs SET left_at=? WHERE install_id=?", (now(), j.install_id))
    return {"ok": True}


def _int(v) -> int:
    try:
        return max(0, min(int(v), 10 ** 9))
    except (TypeError, ValueError):
        return 0


@app.post("/v1/ping")
async def ping(request: Request):
    raw = await request.body()
    if len(raw) > 64_000:
        raise HTTPException(413, "too large")
    p = PingIn.model_validate_json(raw)
    u = p.usage
    days = {d: {k: _int(v) for k, v in (cnt or {}).items()} for d, cnt in (u.get("days") or {}).items()
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(d))}
    clip = lambda m, n=30: json.dumps({str(k)[:60]: _int(v) for k, v in list((m or {}).items())[:n]})
    with _lock, db() as c:
        _pilot(c, p.code, request)
        if not c.execute("SELECT 1 FROM installs WHERE install_id=? AND left_at IS NULL", (p.install_id,)).fetchone():
            raise HTTPException(403, "this install hasn't joined (or has left) the pilot")
        connected = u.get("connected")
        connected = json.dumps([str(a)[:40] for a in connected[:20]]) if isinstance(connected, list) else None
        c.execute("""UPDATE installs SET last_seen=?, version=?, os=?, mode=?, rules=?, agents=?, rules_hit=?,
                     total_events=?, first_event=?, connected=? WHERE install_id=?""",
                  (now(), str(u.get("version", ""))[:40], str(u.get("os", ""))[:80], str(u.get("mode", ""))[:20],
                   _int(u.get("rules")), clip(u.get("agents")), clip(u.get("rules_hit")), _int(u.get("total_events")),
                   str(u.get("first_event", ""))[:10], connected, p.install_id))
        for d, cnt in days.items():
            c.execute("INSERT OR REPLACE INTO days (install_id, day, counts) VALUES (?,?,?)", (p.install_id, d, json.dumps(cnt)))
        if isinstance(u.get("catches"), list):
            c.execute("DELETE FROM catches WHERE install_id=?", (p.install_id,))
            c.executemany("INSERT INTO catches (install_id, t, data) VALUES (?,?,?)",
                          [(p.install_id, x["t"], json.dumps(x)) for x in map(_catch, u["catches"][:60]) if x])
    return {"ok": True}


CATCH_TEXT = {"agent": 40, "tool": 60, "program": 30, "category": 20, "rule": 80, "why": 100, "outcome": 20}


def _catch(x) -> dict | None:
    """Only the fields a gateway is meant to send (pilot.py), each short: nothing else is stored."""
    if not isinstance(x, dict) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", str(x.get("t", ""))):
        return None
    out = {"t": x["t"]} | {k: str(x[k])[:n] for k, n in CATCH_TEXT.items() if x.get(k) not in (None, "")}
    if isinstance(x.get("decide_s"), int) and 0 <= x["decide_s"] < 10**7:
        out["decide_s"] = x["decide_s"]
    saved = x.get("saved") if isinstance(x.get("saved"), dict) else {}
    out["saved"] = {str(k)[:20]: _int(v) for k, v in list(saved.items())[:5] if re.fullmatch(r"[a-z ]{1,20}", str(k))}
    return out


# --------------------------------------------------------------------------- admin

class PilotIn(BaseModel):
    company: str = Field(min_length=1, max_length=80)
    contact: str = Field(default="", max_length=120)
    note: str = Field(default="", max_length=500)
    hosted: bool = False


def dashboard_url(subdomain: str | None) -> str | None:
    return f"https://{subdomain}.{HOSTED_DOMAIN}" if subdomain and HOSTED_DOMAIN else None


@app.post("/v1/admin/pilots", dependencies=[Depends(admin)])
def create_pilot(p: PilotIn, request: Request):
    slug = re.sub(r"[^a-z0-9]+", "-", p.company.lower()).strip("-")[:20].strip("-") or "pilot"
    code = f"{slug}-{secrets.token_hex(6)}"         # 48 random bits: the company's name is easy to guess, this isn't
    with _lock, db() as c:
        sub = None
        if p.hosted:
            if not HOSTED_DOMAIN:
                raise HTTPException(400, "hosted pilots need HOSTED_DOMAIN set on the insights server")
            live = c.execute("SELECT COUNT(*) FROM pilots WHERE hosted=1 AND state != 'deleting'").fetchone()[0]
            if live >= HOSTED_MAX:
                raise HTTPException(409, f"all {HOSTED_MAX} hosted slots are in use: delete one, or raise HOSTED_MAX "
                                         "if the server has the memory")
            taken = {r[0] for r in c.execute("SELECT subdomain FROM pilots WHERE subdomain IS NOT NULL")}
            sub = slug if slug not in taken and slug not in ("www", "admin", "pilots", "app") else f"{slug}-{secrets.token_hex(2)}"
        c.execute("INSERT INTO pilots (code, company, contact, note, created_at, hosted, subdomain, state) VALUES (?,?,?,?,?,?,?,?)",
                  (code, p.company, p.contact, p.note, now(), int(p.hosted), sub, "requested" if p.hosted else None))
    return {"code": code, "link": f"{public_url(request)}/start/{code}", "dashboard": dashboard_url(sub)}


def _forget(c, code: str) -> None:
    ids = [r[0] for r in c.execute("SELECT install_id FROM installs WHERE code=?", (code,))]
    c.executemany("DELETE FROM days WHERE install_id=?", [(i,) for i in ids])
    c.executemany("DELETE FROM catches WHERE install_id=?", [(i,) for i in ids])
    c.execute("DELETE FROM installs WHERE code=?", (code,))
    c.execute("DELETE FROM pilots WHERE code=?", (code,))


@app.delete("/v1/admin/pilots/{code}", dependencies=[Depends(admin)])
def delete_pilot(code: str):
    if code == COMMUNITY_CODE:
        raise HTTPException(400, "that's the code every opted-in install joins; it can't be deleted")
    with _lock, db() as c:
        p = c.execute("SELECT hosted FROM pilots WHERE code=?", (code,)).fetchone()
        if p and p["hosted"]:   # provision.py removes its gateway first, then the row goes
            c.execute("UPDATE pilots SET state='deleting', admin_key=NULL, agent_key=NULL WHERE code=?", (code,))
            return {"deleting": code}
        _forget(c, code)
    return {"deleted": code}


# ---- hosted gateways: provision.py (on the server, with Docker) asks what to do and reports back

@app.get("/v1/admin/provision", dependencies=[Depends(admin)])
def provision_queue():
    with db() as c:
        # keys_ready: the keys arrived here (and may since have been shown to the founder and forgotten)
        rows = c.execute("SELECT code, subdomain, state, (admin_key IS NOT NULL OR keys_revealed_at IS NOT NULL) AS keys_ready "
                         "FROM pilots WHERE hosted=1").fetchall()
    return {"domain": HOSTED_DOMAIN, "pilots": [dict(r) | {"keys_ready": bool(r["keys_ready"]),
                                                          "dashboard": dashboard_url(r["subdomain"])} for r in rows]}


class ProvisionedIn(BaseModel):
    code: str
    state: str = Field(pattern="^(running|failed|deleted)$")
    admin_key: str | None = Field(default=None, max_length=120)
    agent_key: str | None = Field(default=None, max_length=120)
    error: str | None = Field(default=None, max_length=1000)


@app.post("/v1/admin/provisioned", dependencies=[Depends(admin)])
def provisioned(p: ProvisionedIn):
    with _lock, db() as c:
        if p.state == "deleted":
            _forget(c, p.code)
        elif p.state == "running":
            # New keys (a recreated gateway) replace the old ones, so the start page shows them again
            c.execute("UPDATE pilots SET state='running', error=NULL, admin_key=COALESCE(?, admin_key), "
                      "agent_key=COALESCE(?, agent_key), keys_revealed_at=CASE WHEN ? IS NULL THEN keys_revealed_at END "
                      "WHERE code=? AND state != 'deleting'", (p.admin_key, p.agent_key, p.admin_key, p.code))
        else:
            c.execute("UPDATE pilots SET state='failed', error=? WHERE code=?", (p.error, p.code))
    return {"ok": True}


@app.get("/v1/caddy/ask")
def caddy_ask(domain: str = ""):
    """Caddy asks before getting a certificate for <sub>.HOSTED_DOMAIN: only for hosted pilots that exist."""
    sub = domain.removesuffix("." + HOSTED_DOMAIN) if HOSTED_DOMAIN and domain.endswith("." + HOSTED_DOMAIN) else None
    with db() as c:
        ok = bool(sub) and c.execute("SELECT 1 FROM pilots WHERE subdomain=? AND state IN ('requested','running')",
                                     (sub,)).fetchone()
    if not ok:
        raise HTTPException(404)
    return {"ok": True}


@app.get("/v1/pilot/{code}/status")
def pilot_status(code: str, request: Request):
    """Polled by the start page while a hosted dashboard is being set up."""
    _guessing(request)
    with db() as c:
        p = c.execute("SELECT state, admin_key, keys_revealed_at FROM pilots WHERE code=? AND hosted=1", (code,)).fetchone()
    if not p:
        _missed(request)
        raise HTTPException(404)
    return {"state": p["state"], "keys_ready": bool(p["admin_key"]), "keys_shown": bool(p["keys_revealed_at"])}


PREVIEW_BOTS = re.compile(r"bot|crawl|spider|preview|facebookexternalhit|slack|whatsapp|telegram|discord|skype|"
                          r"linkedin|embedly|headless|lighthouse|python-|curl|wget|go-http|okhttp", re.I)


@app.post("/v1/pilot/{code}/seen")
def pilot_seen(code: str, request: Request):
    """The start page, open in a browser: one view. Link previews and scanners don't run the page, or say what they are."""
    if not CODE_RE.match(code) or PREVIEW_BOTS.search(request.headers.get("user-agent", "")):
        return {"ok": False}
    with _lock, db() as c:
        c.execute("UPDATE pilots SET page_views=page_views+1, first_view=COALESCE(first_view, ?), last_view=? WHERE code=?",
                  (now(), now(), code))
    return {"ok": True}


@app.post("/v1/pilot/{code}/keys")
def reveal_keys(code: str, request: Request):
    """The founder's keys for their hosted gateway, shown once on their start page and then forgotten here."""
    _guessing(request)
    with _lock, db() as c:
        p = c.execute("SELECT * FROM pilots WHERE code=? AND hosted=1", (code,)).fetchone()
        if not p:
            _missed(request)
            raise HTTPException(404)
        if not p["admin_key"]:
            raise HTTPException(409, "already shown" if p["keys_revealed_at"] else "your dashboard is still being set up")
        c.execute("UPDATE pilots SET admin_key=NULL, agent_key=NULL, keys_revealed_at=? WHERE code=?", (now(), code))
    return {"dashboard": dashboard_url(p["subdomain"]), "admin_key": p["admin_key"], "agent_key": p["agent_key"]}


SUMS = ("events", "allowed", "held", "approved", "rejected", "blocked", "timed_out", "failed", "would_block", "would_hold",
        "paused")
# Blocks from an emergency stop a person switched on: not something a rule caught, so never counted as "stopped"
PAUSE_RULES = ("emergency-stop", "session-stop")


def _paused(x: dict) -> bool:
    return x.get("rule") in PAUSE_RULES


def _version(v: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", v or "")[:3]) or (0,)


def rule_approvals(caught: list[dict]) -> list[dict]:
    """Per rule: how many holds a person decided, and how many they approved. A rule whose 5+ holds were all
    approved is holding routine work: suggest letting it run."""
    by: dict[str, dict] = {}
    for x in caught:
        if x.get("outcome") in ("approved", "rejected") and x.get("rule") and not _paused(x):
            r = by.setdefault(x["rule"], {"rule": x["rule"], "decided": 0, "approved": 0})
            r["decided"] += 1
            r["approved"] += x["outcome"] == "approved"
    out = []
    for r in sorted(by.values(), key=lambda r: -r["decided"]):
        r["approve_pct"] = round(100 * r["approved"] / r["decided"])
        r["always_allowed"] = r["decided"] >= 5 and r["approved"] == r["decided"]
        out.append(r)
    return out


@app.get("/v1/admin/overview", dependencies=[Depends(admin)])
def overview(request: Request):
    today = datetime.now(timezone.utc).date()
    span = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    with db() as c:
        pilots = [dict(r) for r in c.execute("SELECT * FROM pilots ORDER BY created_at DESC")]
        installs = [dict(r) for r in c.execute("SELECT * FROM installs")]
        days = c.execute("SELECT install_id, day, counts FROM days WHERE day >= ?", (span[0],)).fetchall()
        caught: dict[str, list] = {}
        for iid, data in c.execute("SELECT install_id, data FROM catches"):
            caught.setdefault(iid, []).append(json.loads(data))
    by_install: dict[str, dict] = {}
    for iid, day, counts in days:
        by_install.setdefault(iid, {})[day] = json.loads(counts)
    latest = oss_numbers().get("latest_version") or ""
    t = datetime.now(timezone.utc)
    seen_within = lambda s, h: bool(s) and t - datetime.fromisoformat(s) < timedelta(hours=h)
    out, totals = [], {k: 0 for k in SUMS}
    for p in pilots:
        mine = [i for i in installs if i["code"] == p["code"]]
        daily = {d: {k: 0 for k in SUMS} for d in span}
        agents, hits = {}, {}
        for i in mine:
            for d, cnt in by_install.get(i["install_id"], {}).items():
                if d in daily:
                    for k in SUMS: daily[d][k] += cnt.get(k, 0)
            for k, v in json.loads(i["agents"] or "{}").items(): agents[k] = agents.get(k, 0) + v
            for k, v in json.loads(i["rules_hit"] or "{}").items(): hits[k] = hits.get(k, 0) + v
        week = {k: sum(daily[d][k] for d in span[-7:]) for k in SUMS}
        for k in SUMS: totals[k] += week[k]
        active = [i for i in mine if not i["left_at"]]
        known = [json.loads(i["connected"]) for i in active if i.get("connected")]
        connected = sorted({a for k in known for a in k}) if known else None
        active_days = [d for d in span if daily[d]["events"]]
        days_this_week = sum(1 for d in active_days if d in span[-7:])
        days_last_week = len(active_days) - days_this_week
        last = max((i["last_seen"] or "" for i in active), default="")
        ever_acted = sum(i["total_events"] or 0 for i in mine) > 0
        stage = ("left" if mine and not active else "active" if seen_within(last, 48) and week["events"] else
                 "quiet" if last and ever_acted else
                 "installed · agent not connected" if active and connected == [] else
                 "agent connected" if active and connected else
                 "installed" if active else "opened link" if p["page_views"] else "link sent")
        keys_waiting = bool(p.pop("admin_key", None)); p.pop("agent_key", None)   # never sent to the browser
        if p["hosted"]:
            # a hosted gateway reports on its own from the start, so the founder's progress is: opened the link ->
            # took their keys -> their agent's actions arrive
            ever = sum(i["total_events"] or 0 for i in mine)
            if p["state"] != "running":
                stage = {"requested": "setting up", "failed": "setup failed", "deleting": "deleting"}.get(p["state"], stage)
            elif not p["keys_revealed_at"]:
                stage = "opened link" if p["page_views"] else "link sent"
            elif not ever:
                stage = "keys taken"
        mine_caught = sorted((x for i in mine for x in caught.get(i["install_id"], [])), key=lambda x: x["t"], reverse=True)
        stopped = [x for x in mine_caught if x.get("outcome") in ("rejected", "blocked") and not _paused(x)]
        paused = sum(1 for x in mine_caught if _paused(x) and x.get("t", "") >= span[-7])
        if not any("paused" in by_install.get(i["install_id"], {}).get(d, {}) for i in mine for d in span[-7:]):
            # a gateway from before 0.8 counts emergency-stop blocks as "blocked": take them out here
            week["blocked"] = max(0, week["blocked"] - paused)
            totals["blocked"] -= min(paused, totals["blocked"])
        week["paused"] = max(week["paused"], paused)
        saved: dict[str, int] = {}
        for x in stopped:
            for k, v in (x.get("saved") or {}).items():
                saved[k] = saved.get(k, 0) + v
        waits = sorted(x["decide_s"] for x in mine_caught if isinstance(x.get("decide_s"), int))
        last_day = max((d for d in span if daily[d]["events"]), default=None)
        idle = (today - datetime.fromisoformat(last_day).date()).days if last_day else None
        prev = sum(daily[d]["events"] for d in span[:7])
        health = ("not started" if last_day is None else "active" if idle <= 2 else "at risk" if idle <= 6 else "churned")
        if stage == "active" and health in ("at risk", "churned"):
            stage = "quiet"           # reporting in, but its agents haven't done anything for 3+ days
        out.append({**p, "dashboard": dashboard_url(p["subdomain"]), "keys_waiting": keys_waiting,
                    "catches": mine_caught[:25], "stopped": len(stopped), "paused": week["paused"], "saved": saved,
                    "connected": connected, "rule_approvals": rule_approvals(mine_caught),
                    "outdated": bool(latest) and any(_version(v) < _version(latest) for v in
                                                     {i["version"] for i in active if i["version"]}),
                    "decide_median_s": waits[len(waits) // 2] if waits else None, "health": health,
                    "idle_days": idle, "trend": (None if not prev else round(100 * (week["events"] - prev) / prev)),
                    "link": f"{public_url(request)}/start/{p['code']}", "stage": stage, "installs": len(active),
                    "last_seen": last or None, "versions": sorted({i["version"] for i in active if i["version"]}),
                    "modes": sorted({i["mode"] for i in active if i["mode"]}), "agents": agents,
                    "rules_hit": dict(sorted(hits.items(), key=lambda kv: -kv[1])[:6]), "week": week,
                    "daily": [daily[d]["events"] for d in span], "total_events": sum(i["total_events"] or 0 for i in mine),
                    "active_today": bool(daily[span[-1]]["events"]), "days_this_week": days_this_week,
                    "days_last_week": days_last_week})
    totals["paused"] = sum(p["paused"] for p in out)     # per pilot, incl. ones read from older gateways' catches
    return {"span": span, "pilots": out, "week": totals, "latest_version": latest or None,
            "active_pilots": sum(1 for p in out if p["stage"] == "active"),
            "installs": sum(p["installs"] for p in out), "scorecard": scorecard(out, totals)}


def scorecard(pilots: list[dict], week: dict) -> dict:
    """The numbers that say whether pilots use it, week over week, week over week."""
    last_week = [p for p in pilots if p["days_last_week"]]
    decided = week["approved"] + week["rejected"]
    return {
        "active_today": sum(1 for p in pilots if p["active_today"]),
        "active_this_week": sum(1 for p in pilots if p["days_this_week"]),
        "active_3_plus_days": sum(1 for p in pilots if p["days_this_week"] >= 3),
        "retained": sum(1 for p in last_week if p["days_this_week"]), "active_last_week": len(last_week),
        "actions": week["events"], "held": week["held"], "blocked": week["blocked"],
        "approved": week["approved"], "rejected": week["rejected"],
        # most holds approved means the rules hold things people are fine with: noise that gets Squidbrake switched off
        "approve_rate": round(100 * week["approved"] / decided) if decided else None,
        "at_risk": sum(1 for p in pilots if p.get("health") == "at risk"),
        "churned": sum(1 for p in pilots if p.get("health") == "churned"),
        "stopped": sum(p.get("stopped", 0) for p in pilots),
        "paused": sum(p.get("paused", 0) for p in pilots),
        "saved": {k: sum((p.get("saved") or {}).get(k, 0) for p in pilots)
                  for k in sorted({k for p in pilots for k in (p.get("saved") or {})})},
    }


# --------------------------------------------------------------------------- traction
# Does anyone activate, come back, get value and pay; and is the open source growing.

class RevenueIn(BaseModel):
    mrr: int = Field(ge=0, le=1_000_000)       # dollars a month; 0 = not paying


@app.post("/v1/admin/pilots/{code}/revenue", dependencies=[Depends(admin)])
def set_revenue(code: str, r: RevenueIn):
    with _lock, db() as c:
        if not c.execute("SELECT 1 FROM pilots WHERE code=?", (code,)).fetchone():
            raise HTTPException(404)
        c.execute("UPDATE pilots SET mrr=?, paying_since=CASE WHEN ?>0 THEN COALESCE(paying_since, ?) END WHERE code=?",
                  (r.mrr, r.mrr, now(), code))
    return {"ok": True}


OSS_REPO = os.getenv("OSS_REPO", "batrapulkit/squidbrake")
OSS_PACKAGE = os.getenv("OSS_PACKAGE", "squidbrake")


def _fetch_json(url: str):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "squidbrake-insights"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read() or b"null"), r.headers


def oss_numbers() -> dict:
    """GitHub stars, forks and contributors, PyPI downloads last week: cached for an hour, kept if a fetch fails."""
    with db() as c:
        row = c.execute("SELECT value FROM settings WHERE key='oss_cache'").fetchone()
    cached = json.loads(row[0]) if row else {}
    if cached and time.time() - cached.get("at", 0) < 3600:
        return cached
    fresh = dict(cached)
    try:
        repo, _ = _fetch_json(f"https://api.github.com/repos/{OSS_REPO}")
        fresh.update(stars=repo.get("stargazers_count"), forks=repo.get("forks_count"))
        _, h = _fetch_json(f"https://api.github.com/repos/{OSS_REPO}/contributors?per_page=1&anon=1")
        m = re.search(r'page=(\d+)>; rel="last"', h.get("Link") or "")
        fresh["contributors"] = int(m.group(1)) if m else 1
    except Exception:
        pass
    try:
        pkg, _ = _fetch_json(f"https://pypi.org/pypi/{OSS_PACKAGE}/json")
        fresh["latest_version"] = (pkg.get("info") or {}).get("version")
    except Exception:
        pass
    try:
        dl, _ = _fetch_json(f"https://pypistats.org/api/packages/{OSS_PACKAGE}/recent")
        fresh["downloads_last_week"] = (dl.get("data") or {}).get("last_week")
    except Exception:
        pass
    fresh["at"] = time.time()
    with _lock, db() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('oss_cache', ?)", (json.dumps(fresh),))
    return fresh


def _median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


def _pct(a, b):
    return None if not b else round(100 * (a - b) / b)


@app.get("/v1/admin/traction", dependencies=[Depends(admin)])
def traction():
    today = datetime.now(timezone.utc).date()
    with db() as c:
        pilots = [dict(r) for r in c.execute(
            "SELECT code, company, created_at, page_views, keys_revealed_at, mrr, paying_since FROM pilots "
            "WHERE COALESCE(state, '') != 'deleting'")]
        installs = [dict(r) for r in c.execute("SELECT install_id, code, left_at, agents, connected, total_events "
                                               "FROM installs")]
        days = c.execute("SELECT install_id, day, counts FROM days").fetchall()
        caught = [json.loads(r[0]) for r in c.execute("SELECT data FROM catches")]
        asks = [r[0] for r in c.execute("SELECT created_at FROM team_requests")]
    code_of = {i["install_id"]: i["code"] for i in installs}
    events_by: dict[str, dict] = {}                 # pilot code -> {day: actions}
    for iid, day, counts in days:
        n = json.loads(counts).get("events", 0)
        if n and iid in code_of:
            d = events_by.setdefault(code_of[iid], {})
            d[day] = d.get(day, 0) + n
    window = lambda w: {(today - timedelta(days=7 * w + i)).isoformat() for i in range(7)}   # w=0: the last 7 days
    active_in = lambda code, w: any(d in window(w) for d in events_by.get(code, {}))
    weeks = [{"week_ending": (today - timedelta(days=7 * w)).isoformat(),
              "active_pilots": sum(1 for p in pilots if active_in(p["code"], w)),
              "actions": sum(n for p in pilots for d, n in events_by.get(p["code"], {}).items() if d in window(w))}
             for w in range(7, -1, -1)]
    this, last = weeks[-1], weeks[-2]
    # first action after the pilot was created (a gateway can also report days from before it joined)
    first_action = {}
    for p in pilots:
        after = [d for d in events_by.get(p["code"], {}) if d >= p["created_at"][:10]]
        if after:
            first_action[p["code"]] = min(after)
    set_up = {i["code"] for i in installs} | {p["code"] for p in pilots if p["keys_revealed_at"]}
    # an agent is connected when the gateway says a hook is in place, or once any action has arrived
    connected_codes = {i["code"] for i in installs if json.loads(i["connected"] or "[]") or (i["total_events"] or 0)} \
        | set(first_action)
    days_this_week = {p["code"]: sum(1 for d in events_by.get(p["code"], {}) if d in window(0)) for p in pilots}
    funnel = [("Pilots created", len(pilots)),
              ("Opened the link", sum(1 for p in pilots if p["page_views"])),
              ("Set up (keys or install)", sum(1 for p in pilots if p["code"] in set_up)),
              ("Agent connected", sum(1 for p in pilots if p["code"] in connected_codes)),
              ("First action", len(first_action)),
              ("Active 3+ days this week", sum(1 for v in days_this_week.values() if v >= 3)),
              ("Paying", sum(1 for p in pilots if (p["mrr"] or 0) > 0))]
    ttfa = [(datetime.fromisoformat(first_action[p["code"]]).date() - datetime.fromisoformat(p["created_at"]).date()).days
            for p in pilots if p["code"] in first_action]
    then4 = [p for p in pilots if active_in(p["code"], 4)]
    cut = (today - timedelta(days=7)).isoformat()
    week_caught = [x for x in caught if x.get("t", "") >= cut]
    stopped = [x for x in week_caught if x.get("outcome") in ("rejected", "blocked") and not _paused(x)]
    paused = sum(1 for x in week_caught if _paused(x))
    decided = [x for x in week_caught if x.get("outcome") in ("approved", "rejected") and not _paused(x)]
    saved: dict[str, int] = {}
    for x in stopped:
        for k, v in (x.get("saved") or {}).items():
            saved[k] = saved.get(k, 0) + _int(v)
    active_codes = {p["code"] for p in pilots if active_in(p["code"], 0)}
    agents_per = [len(json.loads(i["agents"] or "{}")) for i in installs if i["code"] in active_codes and not i["left_at"]]
    mrr = sum(p["mrr"] or 0 for p in pilots)
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    return {
        "funnel": [{"step": s, "count": n} for s, n in funnel],
        "median_days_to_first_action": _median(ttfa),
        "weeks": weeks,
        "active_pilots_wow": _pct(this["active_pilots"], last["active_pilots"]),
        "actions_wow": _pct(this["actions"], last["actions"]),
        "retention_w1": None if not last["active_pilots"] else round(
            100 * sum(1 for p in pilots if active_in(p["code"], 1) and active_in(p["code"], 0)) / last["active_pilots"]),
        "retention_w4": None if not then4 else round(100 * sum(1 for p in then4 if active_in(p["code"], 0)) / len(then4)),
        "actions_per_active_pilot": round(this["actions"] / this["active_pilots"]) if this["active_pilots"] else 0,
        "agents_per_active_install": round(sum(agents_per) / len(agents_per), 1) if agents_per else 0,
        "stopped_this_week": len(stopped), "paused_this_week": paused, "saved_this_week": saved,
        "approve_rate": round(100 * sum(1 for x in decided if x["outcome"] == "approved") / len(decided)) if decided else None,
        "median_seconds_to_decide": _median([x["decide_s"] for x in week_caught if isinstance(x.get("decide_s"), int)]),
        "mrr": mrr, "arr": mrr * 12,
        "paying": [{"code": p["code"], "company": p["company"], "mrr": p["mrr"], "since": p["paying_since"]}
                   for p in pilots if (p["mrr"] or 0) > 0],
        "inbound_total": len(asks), "inbound_this_week": sum(1 for a in asks if a >= week_ago),
        "oss": oss_numbers(),
    }


# --------------------------------------------------------------------------- teams asking for help
# Someone who installed Squidbrake on their own fills this in to get help rolling it out to a team. It stores only
# what they typed (no IP address); `source` says which link they followed (cli, dashboard), not who they are.

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
SOURCES = ("cli", "dashboard", "github", "site")
_requests: dict[str, list[float]] = {}


class TeamRequestIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(max_length=200)
    company: str = Field(default="", max_length=120)
    team_size: str = Field(default="", max_length=20)
    agents: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=1000)
    source: str = Field(default="", max_length=20)
    website: str = Field(default="", max_length=200)   # a field people don't see: bots fill it in


@app.post("/v1/team-request")
def team_request(t: TeamRequestIn, request: Request):
    ip = request.client.host if request.client else ""
    recent = [x for x in _requests.get(ip, []) if time.time() - x < 3600]
    if len(recent) >= 5:
        raise HTTPException(429, "too many requests from here: try again in an hour")
    _requests[ip] = recent + [time.time()]
    if not EMAIL_RE.match(t.email.strip()):
        raise HTTPException(422, "that email address doesn't look right")
    if t.website:                                       # a bot: say thanks, keep nothing
        return {"ok": True}
    with _lock, db() as c:
        c.execute("INSERT INTO team_requests (created_at, name, email, company, team_size, agents, note, source) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (now(), t.name.strip(), t.email.strip(), t.company.strip(), t.team_size.strip(), t.agents.strip(),
                   t.note.strip(), t.source if t.source in SOURCES else ""))
    return {"ok": True}


@app.get("/v1/admin/team-requests", dependencies=[Depends(admin)])
def team_requests():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM team_requests ORDER BY id DESC LIMIT 200")]


class DoneIn(BaseModel):
    done: bool


@app.post("/v1/admin/team-requests/{rid}", dependencies=[Depends(admin)])
def team_request_done(rid: int, d: DoneIn):
    with _lock, db() as c:
        if not c.execute("UPDATE team_requests SET done=? WHERE id=?", (int(d.done), rid)).rowcount:
            raise HTTPException(404)
    return {"ok": True}


# ---- installs that failed: the installer asks first ([y/N]), shows what it sends, and sends the last lines of what
# pip / uv / Python printed (home folder already replaced with ~ on the computer). Keys, tokens and email addresses
# are taken out again here, in case a line had one.

SCRUB = [(re.compile(r"gw_[A-Za-z0-9_-]{6,}"), "gw_..."),
         (re.compile(r"(?i)(bearer|token|key|password|secret)([=: ]+)\S+"), r"\1\2..."),
         (re.compile(r"[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}"), "...@..."),
         (re.compile(r"(?i)([a-z]:[\\/]users[\\/])[^\\/\r\n]+"), r"\1..."),       # Windows names can have spaces
         (re.compile(r"(?i)(/users/|/home/)[^/\s]+"), r"\1...")]
_reports: dict[str, list[float]] = {}


def scrub(text: str) -> str:
    for rx, to in SCRUB:
        text = rx.sub(to, text)
    return text


@app.post("/v1/install-report")
async def install_report(request: Request, code: str = "", os_name: str = Query("", alias="os"), step: str = "",
                         installer: str = ""):
    ip = _ip(request)
    recent = [x for x in _reports.get(ip, []) if time.time() - x < 3600]
    if len(recent) >= 5:
        raise HTTPException(429, "too many reports from here: try again in an hour")
    _reports[ip] = recent + [time.time()]
    if len(_reports) > 10_000:
        _reports.clear()
    raw = (await request.body())[:16_000].decode("utf-8", errors="replace")
    log = scrub("\n".join(raw.splitlines()[-40:]))[:6000]
    if not log.strip():
        raise HTTPException(422, "nothing to report")
    with _lock, db() as c:
        known = code and c.execute("SELECT 1 FROM pilots WHERE code=?", (code.lower(),)).fetchone()
        c.execute("INSERT INTO install_reports (created_at, code, os, step, installer, log) VALUES (?, ?, ?, ?, ?, ?)",
                  (now(), code.lower() if known else None, scrub(os_name)[:80], scrub(step)[:200],
                   installer if installer in ("ps1", "sh") else "", log))
    return {"ok": True}


@app.get("/v1/admin/install-reports", dependencies=[Depends(admin)])
def install_reports():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT r.*, p.company FROM install_reports r LEFT JOIN pilots p ON p.code = r.code "
                                           "ORDER BY r.id DESC LIMIT 100")]


@app.post("/v1/admin/install-reports/{rid}", dependencies=[Depends(admin)])
def install_report_done(rid: int, d: DoneIn):
    with _lock, db() as c:
        if not c.execute("UPDATE install_reports SET done=? WHERE id=?", (int(d.done), rid)).rowcount:
            raise HTTPException(404)
    return {"ok": True}


# --------------------------------------------------------------------------- pages

PAGE = lambda name: (HERE / name).read_text(encoding="utf-8")


@app.get("/start/{code}", response_class=HTMLResponse)
def start_page(code: str, request: Request):
    if not CODE_RE.match(code):
        raise HTTPException(404)
    _guessing(request)
    with _lock, db() as c:
        p = c.execute("SELECT * FROM pilots WHERE code=?", (code,)).fetchone()
        if not p:
            _missed(request)
            return HTMLResponse(PAGE("start.html").replace("__DATA__", json.dumps({"missing": True})), status_code=404)
    # Not counted here: LinkedIn, Slack, WhatsApp and mail scanners fetch a link the moment it's pasted, to draw a
    # preview. The page counts a view itself (/seen) once it runs in a browser.
    data = {"company": p["company"], "code": code, "server": public_url(request), "contact": CONTACT,
            "hosted": bool(p["hosted"]), "dashboard": dashboard_url(p["subdomain"]), "state": p["state"],
            "keys_ready": bool(p["admin_key"]), "keys_shown": bool(p["keys_revealed_at"])}
    return HTMLResponse(PAGE("start.html").replace("__DATA__", json.dumps(data).replace("</", "<\\/")))


# --------------------------------------------------------------------------- where people come from
# A link you post somewhere names its channel: https://pilots.squidbrake.com/go/linkedin. A click is counted per
# channel and day (no IP address, no cookie) and lands on /get, whose install commands carry SQUIDBRAKE_REF=linkedin;
# installs that say yes to stats report that word (telemetry.py). Others pick where they heard about it from a list.

CHANNEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")


@app.get("/go/{channel}")
def go(channel: str):
    channel = channel.lower()
    if not CHANNEL_RE.match(channel):
        raise HTTPException(404)
    with _lock, db() as c:
        c.execute("INSERT INTO link_clicks (channel, day, n) VALUES (?, ?, 1) ON CONFLICT(channel, day) DO UPDATE SET n=n+1",
                  (channel, datetime.now(timezone.utc).date().isoformat()))
    return RedirectResponse(f"/get?ref={channel}", status_code=302)


@app.get("/get", response_class=HTMLResponse)
def get_page(request: Request, ref: str = ""):
    ref = ref.lower() if CHANNEL_RE.match(ref.lower()) else ""
    data = {"ref": ref, "server": public_url(request)}
    return HTMLResponse(PAGE("get.html").replace("__DATA__", json.dumps(data).replace("</", "<\\/")))


@app.get("/v1/admin/sources", dependencies=[Depends(admin)])
def sources(days: int = 30):
    """Per channel: link clicks -> installs that share stats -> used this week -> stopped something."""
    days = max(1, min(days, 365))
    since = (datetime.now(timezone.utc).date() - timedelta(days=days - 1)).isoformat()
    week = (datetime.now(timezone.utc).date() - timedelta(days=6)).isoformat()
    with db() as c:
        clicks = dict(c.execute("SELECT channel, SUM(n) FROM link_clicks WHERE day >= ? GROUP BY channel", (since,)).fetchall())
        installs = c.execute("SELECT install_id, code, ref, joined_at FROM installs WHERE left_at IS NULL").fetchall()
        used = {iid for iid, counts in c.execute("SELECT install_id, counts FROM days WHERE day >= ?", (week,))
                if _int(json.loads(counts).get("events"))}
        stopped: dict[str, int] = {}
        for iid, data in c.execute("SELECT install_id, data FROM catches"):
            if json.loads(data).get("outcome") in ("rejected", "blocked"):
                stopped[iid] = stopped.get(iid, 0) + 1
    rows: dict[str, dict] = {}
    for iid, code, ref, joined in installs:
        ch = ref or ("pilot" if code != COMMUNITY_CODE else "not said")
        r = rows.setdefault(ch, {"channel": ch, "clicks": 0, "installs": 0, "new": 0, "used_this_week": 0, "stopped": 0})
        r["installs"] += 1
        r["new"] += (joined or "") >= since
        r["used_this_week"] += iid in used
        r["stopped"] += stopped.get(iid, 0)
    for ch, n in clicks.items():
        rows.setdefault(ch, {"channel": ch, "clicks": 0, "installs": 0, "new": 0, "used_this_week": 0, "stopped": 0})["clicks"] = n
    return {"days": days, "rows": sorted(rows.values(), key=lambda r: (-r["installs"], -r["clicks"], r["channel"]))}


@app.get("/team", response_class=HTMLResponse)
def team_page():
    return HTMLResponse(PAGE("team.html").replace("__CONTACT__", json.dumps(CONTACT).replace("</", "<\\/")))


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return HTMLResponse(PAGE("admin.html"))


@app.get("/install.ps1", response_class=PlainTextResponse)
def install_ps1():
    return PlainTextResponse(PAGE("install.ps1"), media_type="text/plain; charset=utf-8")


@app.get("/install.sh", response_class=PlainTextResponse)
def install_sh():
    return PlainTextResponse(PAGE("install.sh"), media_type="text/plain; charset=utf-8")


@app.get("/health")
def health():
    return {"ok": True}
