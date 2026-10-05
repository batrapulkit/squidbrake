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

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

HERE = Path(__file__).resolve().parent
DB = Path(os.getenv("INSIGHTS_DB", HERE / "data" / "insights.db"))
ADMIN_KEY = os.getenv("INSIGHTS_ADMIN_KEY", "")
PUBLIC_URL = os.getenv("INSIGHTS_PUBLIC_URL", "").rstrip("/")
CONTACT = os.getenv("INSIGHTS_CONTACT", "")           # shown on start pages, e.g. "WhatsApp +91..., you@x.com"
CODE_RE = re.compile(r"^[a-z0-9-]{3,40}$")

app = FastAPI(title="Squidbrake Insights", docs_url=None, redoc_url=None)
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
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS team_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
        name TEXT NOT NULL, email TEXT NOT NULL, company TEXT, team_size TEXT, agents TEXT, note TEXT, source TEXT,
        done INTEGER NOT NULL DEFAULT 0);
    """)
    # hosted pilots: their own gateway at <subdomain>.<HOSTED_DOMAIN>, started by provision.py on the server
    _have = {r[1] for r in _c.execute("PRAGMA table_info(pilots)")}
    for _col, _type in (("hosted", "INTEGER NOT NULL DEFAULT 0"), ("subdomain", "TEXT"), ("state", "TEXT"),
                        ("admin_key", "TEXT"), ("agent_key", "TEXT"), ("keys_revealed_at", "TEXT"), ("error", "TEXT")):
        if _col not in _have:
            _c.execute(f"ALTER TABLE pilots ADD COLUMN {_col} {_type}")

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


class PingIn(BaseModel):
    code: str = Field(max_length=40)
    install_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    usage: dict


def _pilot(c, code: str):
    row = c.execute("SELECT * FROM pilots WHERE code=?", (code.lower(),)).fetchone()
    if not row:
        raise HTTPException(404, "unknown pilot code: check the link you were sent")
    return row


@app.post("/v1/pilot/join")
def join(j: JoinIn):
    with _lock, db() as c:
        p = _pilot(c, j.code)
        c.execute("""INSERT INTO installs (install_id, code, joined_at, version, os) VALUES (?,?,?,?,?)
                     ON CONFLICT(install_id) DO UPDATE SET code=excluded.code, left_at=NULL, version=excluded.version,
                     os=excluded.os""", (j.install_id, p["code"], now(), j.version, j.os))
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
        _pilot(c, p.code)
        if not c.execute("SELECT 1 FROM installs WHERE install_id=? AND left_at IS NULL", (p.install_id,)).fetchone():
            raise HTTPException(403, "this install hasn't joined (or has left) the pilot")
        c.execute("""UPDATE installs SET last_seen=?, version=?, os=?, mode=?, rules=?, agents=?, rules_hit=?,
                     total_events=?, first_event=? WHERE install_id=?""",
                  (now(), str(u.get("version", ""))[:40], str(u.get("os", ""))[:80], str(u.get("mode", ""))[:20],
                   _int(u.get("rules")), clip(u.get("agents")), clip(u.get("rules_hit")), _int(u.get("total_events")),
                   str(u.get("first_event", ""))[:10], p.install_id))
        for d, cnt in days.items():
            c.execute("INSERT OR REPLACE INTO days (install_id, day, counts) VALUES (?,?,?)", (p.install_id, d, json.dumps(cnt)))
    return {"ok": True}


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
    code = f"{slug}-{secrets.token_hex(3)}"
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
    c.execute("DELETE FROM installs WHERE code=?", (code,))
    c.execute("DELETE FROM pilots WHERE code=?", (code,))


@app.delete("/v1/admin/pilots/{code}", dependencies=[Depends(admin)])
def delete_pilot(code: str):
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
def pilot_status(code: str):
    """Polled by the start page while a hosted dashboard is being set up."""
    with db() as c:
        p = c.execute("SELECT state, admin_key, keys_revealed_at FROM pilots WHERE code=? AND hosted=1", (code,)).fetchone()
    if not p:
        raise HTTPException(404)
    return {"state": p["state"], "keys_ready": bool(p["admin_key"]), "keys_shown": bool(p["keys_revealed_at"])}


@app.post("/v1/pilot/{code}/keys")
def reveal_keys(code: str):
    """The founder's keys for their hosted gateway, shown once on their start page and then forgotten here."""
    with _lock, db() as c:
        p = c.execute("SELECT * FROM pilots WHERE code=? AND hosted=1", (code,)).fetchone()
        if not p:
            raise HTTPException(404)
        if not p["admin_key"]:
            raise HTTPException(409, "already shown" if p["keys_revealed_at"] else "your dashboard is still being set up")
        c.execute("UPDATE pilots SET admin_key=NULL, agent_key=NULL, keys_revealed_at=? WHERE code=?", (now(), code))
    return {"dashboard": dashboard_url(p["subdomain"]), "admin_key": p["admin_key"], "agent_key": p["agent_key"]}


SUMS = ("events", "allowed", "held", "approved", "rejected", "blocked", "timed_out", "failed", "would_block", "would_hold")


@app.get("/v1/admin/overview", dependencies=[Depends(admin)])
def overview(request: Request):
    today = datetime.now(timezone.utc).date()
    span = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    with db() as c:
        pilots = [dict(r) for r in c.execute("SELECT * FROM pilots ORDER BY created_at DESC")]
        installs = [dict(r) for r in c.execute("SELECT * FROM installs")]
        days = c.execute("SELECT install_id, day, counts FROM days WHERE day >= ?", (span[0],)).fetchall()
    by_install: dict[str, dict] = {}
    for iid, day, counts in days:
        by_install.setdefault(iid, {})[day] = json.loads(counts)
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
        active_days = [d for d in span if daily[d]["events"]]
        days_this_week = sum(1 for d in active_days if d in span[-7:])
        days_last_week = len(active_days) - days_this_week
        active = [i for i in mine if not i["left_at"]]
        last = max((i["last_seen"] or "" for i in active), default="")
        stage = ("left" if mine and not active else "active" if seen_within(last, 48) and week["events"] else
                 "quiet" if last else "installed" if active else "opened link" if p["page_views"] else "link sent")
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
        out.append({**p, "dashboard": dashboard_url(p["subdomain"]), "keys_waiting": keys_waiting,
                    "link": f"{public_url(request)}/start/{p['code']}", "stage": stage, "installs": len(active),
                    "last_seen": last or None, "versions": sorted({i["version"] for i in active if i["version"]}),
                    "modes": sorted({i["mode"] for i in active if i["mode"]}), "agents": agents,
                    "rules_hit": dict(sorted(hits.items(), key=lambda kv: -kv[1])[:6]), "week": week,
                    "daily": [daily[d]["events"] for d in span], "total_events": sum(i["total_events"] or 0 for i in mine),
                    "active_today": bool(daily[span[-1]]["events"]), "days_this_week": days_this_week,
                    "days_last_week": days_last_week})
    return {"span": span, "pilots": out, "week": totals,
            "active_pilots": sum(1 for p in out if p["stage"] == "active"),
            "installs": sum(p["installs"] for p in out), "scorecard": scorecard(out, totals)}


def scorecard(pilots: list[dict], week: dict) -> dict:
    """The numbers that say whether pilots use it, week over week: what an investor (or a kill criterion) asks for."""
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


# --------------------------------------------------------------------------- pages

PAGE = lambda name: (HERE / name).read_text(encoding="utf-8")


@app.get("/start/{code}", response_class=HTMLResponse)
def start_page(code: str, request: Request):
    if not CODE_RE.match(code):
        raise HTTPException(404)
    with _lock, db() as c:
        p = c.execute("SELECT * FROM pilots WHERE code=?", (code,)).fetchone()
        if not p:
            return HTMLResponse(PAGE("start.html").replace("__DATA__", json.dumps({"missing": True})), status_code=404)
        c.execute("UPDATE pilots SET page_views=page_views+1, first_view=COALESCE(first_view, ?), last_view=? WHERE code=?",
                  (now(), now(), code))
    data = {"company": p["company"], "code": code, "server": public_url(request), "contact": CONTACT,
            "hosted": bool(p["hosted"]), "dashboard": dashboard_url(p["subdomain"]), "state": p["state"],
            "keys_ready": bool(p["admin_key"]), "keys_shown": bool(p["keys_revealed_at"])}
    return HTMLResponse(PAGE("start.html").replace("__DATA__", json.dumps(data).replace("</", "<\\/")))


@app.get("/team", response_class=HTMLResponse)
def team_page():
    return HTMLResponse(PAGE("team.html").replace("__CONTACT__", json.dumps(CONTACT).replace("</", "<\/")))


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
