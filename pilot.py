"""
Pilot programme: share usage COUNTS with the Squidbrake team, only after you join: with a code you were given, by
saying yes to anonymous usage stats the first time you run `squidbrake` (telemetry.py), or by saying yes when
`squidbrake connect all` asks (once, default no).

    squidbrake pilot join CODE --server URL    start sharing (shows exactly what is sent, and asks first)
    squidbrake pilot status                    what is shared, where, and when it was last sent
    squidbrake pilot leave                     stop sharing

Nothing is sent unless you join. What is sent, at start and every 6 hours (a hosted dashboard: every 2 minutes):
  - the Squidbrake version, operating system, enforce/shadow mode and number of rules
  - the agents connected, by their labels (e.g. "claude-code", "antigravity"), and which agents on this computer
    have Squidbrake's hook in their settings (so a pilot that installed but never connected an agent can be helped)
  - per day, for the last 7 days: how many actions were allowed, held, approved, rejected, blocked, timed out or failed,
    and how many were paused by an emergency stop (counted apart from what rules blocked)
  - which rules blocked or held things (rule ids such as "command:catastrophic_command")
  - for each action held or blocked in the last 7 days: when, which agent, the program only (e.g. "rm", "git"),
    the rule and its reason, what happened (approved, rejected, blocked, timed out), how long a person took,
    and the size of what it would have changed, as numbers only (e.g. 3 commits, 1,204 files, 4,312 rows)
When you join through the first-run question (telemetry.py), also: where you heard about Squidbrake, if you answered.
Never sent: commands or their arguments, file or folder names, file contents, prompts, tool inputs or outputs,
keys, names of people.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from sqlalchemy import case, func, select

log = logging.getLogger("gateway")
INTERVAL = int(os.getenv("SQUIDBRAKE_PILOT_INTERVAL", str(6 * 3600)))   # hosted pilots use a shorter one
WHAT_IS_SENT = __doc__.split("Nothing is sent unless you join.")[1].strip()


def _path(home: Path) -> Path:
    return home / "pilot.json"       # `home` is the gateway's data folder (next to keys.json): writable everywhere


def load(home: Path) -> dict | None:
    try:
        return json.loads(_path(home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save(home: Path, cfg: dict) -> None:
    home.mkdir(parents=True, exist_ok=True)
    _path(home).write_text(json.dumps(cfg, indent=2), encoding="utf-8")


SIZE = re.compile(r"(\d[\d,]*)\+?\s+(Kubernetes objects?|files?|rows?|commits?|resources?|objects?)\b", re.I)
WHY = {"catastrophic": "could wipe a home folder, a drive or the system", "irreversible": "can't be undone",
       "hidden": "runs code that can't be read first"}
HISTORY_WHY = {"repeat_of_rejected": "asked again after a person said no", "impersonation": "money after a look-alike sender",
               "payment_request_in_message": "money a message asked for", "duplicate_change": "the same change again",
               "untrusted_destination": "sends to an address found only in outside content"}


def _program(name: str, raw_input: str | None) -> tuple[str | None, str | None]:
    """(program, category) of a shell command, e.g. ("rm", "irreversible"): never its arguments."""
    try:
        import commands
        cmd = commands.command_of(json.loads(raw_input)) if raw_input else None
        if not cmd:
            return None, None
        reading = commands.read(cmd)
        worst = reading.worst()
        prog = re.sub(r"[^a-z0-9._+-]", "", (worst.program if worst else "").lower())[:30] or None
        return prog, reading.kind
    except Exception:
        return None, None


def catches(conn, events, since: str, reasons: dict) -> list[dict]:
    """What was held or blocked, without what it was about: program, rule, outcome, and sizes as numbers."""
    rows = conn.execute(select(
        events.c.created_at, events.c.decided_at, events.c.source, events.c.client, events.c.name, events.c.input,
        events.c.rule_id, events.c.decision, events.c.decided_by, events.c.approval_deadline, events.c.metadata,
    ).where(events.c.created_at >= since, events.c.approval_deadline.isnot(None) |
            ((events.c.status == "denied") & events.c.decided_by.is_(None))
            ).order_by(events.c.created_at.desc()).limit(60)).all()
    out = []
    for r in rows:
        prog, kind = _program(r.name or "", r.input)
        rule = (r.rule_id or "")[:80]
        why = reasons.get(rule) or (HISTORY_WHY.get(rule.split(":", 1)[1]) if rule.startswith(("history:", "taint:")) else None) \
            or WHY.get(kind or "") or ""
        if r.approval_deadline is None:
            outcome = "blocked"
        else:
            outcome = {None: "waiting", "timeout": "timed out"}.get(r.decided_by) or ("approved" if r.decision == "allow" else "rejected")
        saved: dict[str, int] = {}
        try:
            for line in (json.loads(r.metadata or "{}").get("effects") or []):
                for n, unit in SIZE.findall(str(line)):
                    u = unit.lower().replace("kubernetes ", "")
                    u = u if u.endswith("s") else u + "s"
                    saved[u] = saved.get(u, 0) + int(n.replace(",", ""))
        except (ValueError, AttributeError):
            pass
        decide_s = None
        if r.decided_at and r.decided_by not in (None, "timeout"):
            try:
                decide_s = int((datetime.fromisoformat(r.decided_at.replace("Z", "+00:00"))
                                - datetime.fromisoformat(r.created_at.replace("Z", "+00:00"))).total_seconds())
            except ValueError:
                pass
        tool = re.sub(r"[^A-Za-z0-9_.:-]", "", r.name or "")[:60]
        out.append({"t": (r.created_at or "")[:16], "agent": str(r.source or r.client or "")[:40], "tool": tool,
                    "program": prog, "category": kind if prog else None, "rule": rule, "why": str(why)[:100],
                    "outcome": outcome, "decide_s": decide_s, "saved": saved})
    return out


PAUSE_RULES = ("emergency-stop", "session-stop")


def usage(engine, events, mode: str, rules: int, version: str, reasons: dict | None = None,
          connected: list[str] | None = None) -> dict:
    """Counts, and what was held or blocked as program + rule + outcome + sizes (see the top of this file).
    No inputs, outputs, arguments, file names, names of people."""
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    day = func.substr(events.c.created_at, 1, 10)
    human = events.c.decided_by.isnot(None) & (events.c.decided_by != "timeout")
    n = lambda cond: func.sum(case((cond, 1), else_=0))
    in_week = events.c.created_at >= since
    paused = func.coalesce(events.c.rule_id.in_(PAUSE_RULES), False)
    with engine.connect() as conn:
        days = {d: {"events": int(t or 0), "allowed": int(a or 0), "held": int(h or 0), "approved": int(ap or 0),
                    "rejected": int(rj or 0), "blocked": int(b or 0), "timed_out": int(to or 0), "failed": int(f or 0),
                    "would_block": int(wb or 0), "would_hold": int(wh or 0), "paused": int(ps or 0)}
                for d, t, a, h, ap, rj, b, to, f, wb, wh, ps in conn.execute(select(
                    day, func.count(),
                    n((events.c.decision == "allow") & events.c.decided_by.is_(None)),
                    n(events.c.approval_deadline.isnot(None)),
                    n(human & (events.c.decision == "allow")),
                    n(human & (events.c.decision == "deny")),
                    n((events.c.status == "denied") & events.c.decided_by.is_(None) & paused.is_(False)),
                    n(events.c.decided_by == "timeout"),
                    n(events.c.status == "failed"),
                    n(events.c.would == "deny"),
                    n(events.c.would == "review"),
                    n((events.c.status == "denied") & events.c.decided_by.is_(None) & paused.is_(True)),
                ).where(in_week).group_by(day)).all()}
        agent = func.coalesce(events.c.source, events.c.client)
        agents = dict(conn.execute(select(agent, func.count()).where(in_week).group_by(agent)).all())
        rules_hit = dict(conn.execute(select(events.c.rule_id, func.count()).where(
            in_week, events.c.rule_id.isnot(None),
            (events.c.status == "denied") | events.c.approval_deadline.isnot(None),
        ).group_by(events.c.rule_id).order_by(func.count().desc()).limit(15)).all())
        total, first = conn.execute(select(func.count(), func.min(events.c.created_at)).select_from(events)).one()
        held = catches(conn, events, since, reasons or {})
    return {"version": version, "os": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
            "mode": mode, "rules": rules, "agents": {str(k): v for k, v in agents.items() if k},
            "days": days, "rules_hit": rules_hit, "total_events": total, "first_event": (first or "")[:10],
            "catches": held, "connected": connected}


def _post(server: str, path: str, body: dict) -> dict:
    r = httpx.post(server.rstrip("/") + path, json=body, timeout=15)
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = r.text[:200]
        raise RuntimeError(f"{r.status_code}: {detail}")
    return r.json()


def send(home: Path, payload: dict) -> bool:
    cfg = load(home)
    if not cfg:
        return False
    body = {"code": cfg["code"], "install_id": cfg["install_id"], "usage": payload}
    try:
        try:
            _post(cfg["server"], "/v1/ping", body)
        except RuntimeError as e:
            # 403: the server doesn't know this install any more (e.g. its record was removed): join again, same id
            if not str(e).startswith("403") or not str(cfg["code"]).startswith("community-"):
                raise
            _post(cfg["server"], "/v1/pilot/join", {"code": cfg["code"], "install_id": cfg["install_id"],
                                                    "version": str(payload.get("version", ""))[:40],
                                                    "os": f"{platform.system()} {platform.release()}"[:80]})
            _post(cfg["server"], "/v1/ping", body)
    except (httpx.HTTPError, RuntimeError) as e:
        log.info("pilot: usage not sent (%s); will try again later", e)
        return False
    cfg["last_sent"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _save(home, cfg)
    return True


async def loop(home: Path, make_payload) -> None:
    """Runs inside the gateway. Does nothing at all unless this install joined a pilot."""
    await asyncio.sleep(20)
    while True:
        if load(home):
            try:
                await asyncio.to_thread(lambda: send(home, make_payload()))
            except Exception as e:  # never let reporting affect the gateway
                log.info("pilot: %s", e)
        await asyncio.sleep(INTERVAL)


# --------------------------------------------------------------------------- command line

def join(home: Path, code: str, server: str | None, yes: bool, version: str, ref: str | None = None) -> int:
    server = (server or os.getenv("SQUIDBRAKE_PILOT_SERVER") or "").rstrip("/")
    host = urlparse(server).hostname or ""
    # https, or plain http only to this machine or an internal name without dots (a hosted gateway's Docker network)
    if not (server.startswith("https://") or (server.startswith("http://") and (host in ("localhost", "127.0.0.1") or "." not in host))):
        print("Give the pilot server you were sent, e.g. --server https://...  (https only)", file=sys.stderr)
        return 2
    print(f"\nJoining the Squidbrake pilot with code {code}.\nThis sends usage counts to {server}:\n")
    print("  " + WHAT_IS_SENT.replace("\n", "\n  ") + "\n")
    if not yes:
        try:
            answer = input("Share these counts? [y/N] ")
        except EOFError:                                # no keyboard here (piped, CI): don't guess
            print(f"\nNot joined: nothing to answer with here. To join, run:  squidbrake pilot join {code} --server {server}")
            return 1
        if answer.strip().lower() not in ("y", "yes"):
            print("Not joined. Nothing is shared.")
            return 1
    cfg = load(home) or {}
    install_id = cfg.get("install_id") or uuid.uuid4().hex
    try:
        r = _post(server, "/v1/pilot/join", {"code": code, "install_id": install_id, "version": version,
                                             "os": f"{platform.system()} {platform.release()}",
                                             **({"ref": ref} if ref else {})})
    except (httpx.HTTPError, RuntimeError) as e:
        print(f"Couldn't join: {e}", file=sys.stderr)
        return 1
    _save(home, {"code": code, "server": server, "install_id": install_id, "company": r.get("company"),
                 "joined": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    print(f"Joined{(' as ' + r['company']) if r.get('company') else ''}. Thank you!"
          f"\nCounts are sent while the gateway runs (restart it if it's running). Stop anytime: squidbrake pilot leave")
    return 0


def leave(home: Path) -> int:
    cfg = load(home)
    if not cfg:
        print("Not in a pilot; nothing is shared.")
        return 0
    try:
        _post(cfg["server"], "/v1/pilot/leave", {"code": cfg["code"], "install_id": cfg["install_id"]})
    except (httpx.HTTPError, RuntimeError):
        pass
    _path(home).unlink(missing_ok=True)
    print("Left the pilot. Nothing more is shared.")
    return 0


def status(home: Path) -> int:
    cfg = load(home)
    if not cfg:
        print("Not in a pilot; nothing is shared.")
        return 0
    print(f"In the pilot {cfg.get('company') or cfg['code']} (code {cfg['code']}), sharing usage counts with {cfg['server']}.")
    print(f"Last sent: {cfg.get('last_sent') or 'not yet (sent while the gateway runs)'}.  Stop: squidbrake pilot leave")
    return 0
