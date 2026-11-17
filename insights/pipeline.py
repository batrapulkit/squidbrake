"""
Pipeline: every person you talk to about Squidbrake (prospects, pilots, intros, investors, advisors), in the admin.

Three ways a contact changes, all landing in the same two tables:
  - a sync file (contacts.json) in a PRIVATE GitHub repo, written by a daily Claude task from your conversation notes
    and calendar; pulled every PIPELINE_PULL_MINUTES and on "Sync now"
  - the admin page: add or edit a card by hand (fields you edit by hand are kept: the sync won't overwrite them)
  - "Paste a conversation": a transcript or DM thread is read by OpenAI (OPENAI_API_KEY) into a suggested update you
    check before saving; the pasted text itself is never stored

Env:
  PIPELINE_REPO           owner/name of the private repo with the sync file, e.g. batrapulkit/squidbrake-pipeline
  PIPELINE_TOKEN          a fine-grained GitHub token with read access to that repo only (Contents: read)
  PIPELINE_PATH           path of the file in that repo (default contacts.json)
  PIPELINE_PULL_MINUTES   how often to pull (default 15; 0 turns the background pull off)
  OPENAI_API_KEY          for "Paste a conversation" (optional)
  INSIGHTS_OPENAI_MODEL   model for it (default gpt-4o-mini)

Contact data never leaves this server except the pasted text you choose to send to OpenAI.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

REPO = os.getenv("PIPELINE_REPO", "").strip()
TOKEN = os.getenv("PIPELINE_TOKEN", "").strip()
PATH = os.getenv("PIPELINE_PATH", "contacts.json").strip().lstrip("/")
PULL_MINUTES = float(os.getenv("PIPELINE_PULL_MINUTES", "15") or 0)
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("INSIGHTS_OPENAI_MODEL", "gpt-4o-mini").strip()

SIGNALS = ("using", "for", "against", "neutral", "pending")
TEXT = ("name", "org", "lane", "stage", "signal", "said", "read", "next", "pilot_code", "last_contact")
NUMS = ("loi", "paid_once", "monthly", "conditional", "talked", "needs_outcome")
FIELDS = TEXT + NUMS
LIMITS = {"name": 120, "org": 160, "lane": 60, "stage": 80, "signal": 10, "said": 1500, "read": 1000, "next": 500,
          "pilot_code": 40, "last_contact": 10}
SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (id TEXT PRIMARY KEY, name TEXT NOT NULL, org TEXT, lane TEXT NOT NULL DEFAULT 'Other',
    stage TEXT, signal TEXT NOT NULL DEFAULT 'pending', said TEXT, read TEXT, next TEXT, pilot_code TEXT,
    loi INTEGER NOT NULL DEFAULT 0, paid_once INTEGER NOT NULL DEFAULT 0, monthly INTEGER NOT NULL DEFAULT 0,
    conditional INTEGER NOT NULL DEFAULT 0, talked INTEGER NOT NULL DEFAULT 1, needs_outcome INTEGER NOT NULL DEFAULT 0,
    last_contact TEXT, locked TEXT NOT NULL DEFAULT '[]', source TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS contact_log (id INTEGER PRIMARY KEY AUTOINCREMENT, contact_id TEXT NOT NULL, t TEXT NOT NULL,
    source TEXT NOT NULL, text TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS contact_log_id ON contact_log (contact_id);
"""
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:60] or "contact"


def clean(d: dict) -> dict:
    """Only known fields, trimmed to their limits, numbers as ints, signal from the fixed set."""
    out: dict = {}
    for k in TEXT:
        if k in d and d[k] is not None:
            v = str(d[k]).strip()[: LIMITS[k]]
            if k == "last_contact" and v and not DATE_RE.match(v):
                continue
            out[k] = v
    for k in NUMS:
        if k in d and d[k] is not None:
            try:
                out[k] = max(0, int(float(d[k])))
            except (TypeError, ValueError):
                continue
    if "signal" in out and out["signal"] not in SIGNALS:
        out["signal"] = "pending"
    for k in ("talked", "needs_outcome"):
        if k in out:
            out[k] = 1 if out[k] else 0
    return out


def upsert(c, cid: str | None, d: dict, source: str, now: str, manual: bool = False, update: str = "") -> str:
    """Create or change one contact. A field edited by hand is locked: later syncs leave it alone.
    Returns 'new', 'changed' or 'same'."""
    d = clean(d)
    cid = slug(cid or d.get("name") or "")
    row = c.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
    if row is None:
        if not d.get("name"):
            raise ValueError("a new contact needs a name")
        locked = sorted(d) if manual else []
        cols = ["id", "locked", "source", "created_at", "updated_at"] + list(d)
        vals = [cid, json.dumps(locked), source, now, now] + list(d.values())
        c.execute(f"INSERT INTO contacts ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals)
        c.execute("INSERT INTO contact_log (contact_id, t, source, text) VALUES (?, ?, ?, ?)",
                  (cid, now, source, update or f"Added: {d.get('stage') or 'new contact'}"))
        return "new"
    locked = set(json.loads(row["locked"] or "[]"))
    changes = {k: v for k, v in d.items() if (manual or k not in locked) and (row[k] if row[k] is not None else "") != v}
    said = []
    if changes:
        if manual:
            locked |= set(changes)
        sets = ", ".join(f"{k}=?" for k in changes)
        c.execute(f"UPDATE contacts SET {sets}, locked=?, source=?, updated_at=? WHERE id=?",
                  [*changes.values(), json.dumps(sorted(locked)), source, now, cid])
        if "stage" in changes:
            said.append(f"stage: {row['stage'] or '-'} → {changes['stage']}")
        if "next" in changes and changes["next"]:
            said.append(f"next: {changes['next']}")
        rest = [k for k in changes if k not in ("stage", "next")]
        if rest:
            said.append("updated " + ", ".join(rest))
    if update and not c.execute("SELECT 1 FROM contact_log WHERE contact_id=? AND text=?", (cid, update)).fetchone():
        c.execute("INSERT INTO contact_log (contact_id, t, source, text) VALUES (?, ?, ?, ?)", (cid, now, source, update))
    elif said:
        c.execute("INSERT INTO contact_log (contact_id, t, source, text) VALUES (?, ?, ?, ?)",
                  (cid, now, source, "; ".join(said)[:600]))
    return "changed" if changes else "same"


def import_file(c, data: dict, source: str, now: str) -> dict:
    """The sync file: {"contacts": [{"id"?, "name", ..., "update"?: "one line about what just happened"}]}"""
    items = data.get("contacts") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("the sync file needs a \"contacts\" list")
    counts = {"new": 0, "changed": 0, "same": 0, "skipped": 0}
    for it in items[:2000]:
        if not isinstance(it, dict):
            counts["skipped"] += 1
            continue
        try:
            counts[upsert(c, it.get("id"), it, source, now, update=str(it.get("update") or "")[:600])] += 1
        except ValueError:
            counts["skipped"] += 1
    return counts


def fetch_sync_file() -> tuple[str, dict]:
    if not (REPO and TOKEN):
        raise RuntimeError("sync isn't set up: PIPELINE_REPO and PIPELINE_TOKEN are missing on the server")
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/contents/{PATH}",
                                 headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github.raw",
                                          "User-Agent": "squidbrake-insights"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read(5_000_000)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub answered {e.code} for {REPO}/{PATH}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"couldn't reach GitHub: {e.reason}") from None
    return hashlib.sha256(body).hexdigest(), json.loads(body)


PROMPT = """You turn a founder's conversation (a call transcript, notes, or a DM thread) into a CRM update for ONE person.
The founder sells Squidbrake, a control layer that stops risky chains of AI-agent actions. Return JSON only, with keys:
name, org, stage (2-5 words, e.g. "Live call, Oct 20" or "Agreed 2-week pilot"), signal (one of using, for, against,
neutral, pending), said (what they actually said or did, 1-3 plain sentences, only facts from the text),
read (one honest sentence on what it means for the founder; no flattery, say if it is politeness and not commitment),
next (the single next step), loi (1 only if they signed a letter of intent, else 0),
monthly (USD per month they committed to pay, 0 if none), conditional (USD per month offered only if a condition is met),
last_contact (YYYY-MM-DD if a date is clear, else empty). Never invent facts that are not in the text.
Use simple words and no em dashes."""


def read_with_openai(text: str, hint: str) -> dict:
    if not OPENAI_KEY:
        raise RuntimeError("set OPENAI_API_KEY on the server to read pasted conversations")
    body = json.dumps({"model": OPENAI_MODEL, "response_format": {"type": "json_object"}, "temperature": 0.2,
                       "messages": [{"role": "system", "content": PROMPT},
                                    {"role": "user", "content": (f"Known contact: {hint}\n\n" if hint else "") + text}]})
    req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=body.encode(),
                                 headers={"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OpenAI answered {e.code}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"couldn't reach OpenAI: {e.reason}") from None
    try:
        return clean(json.loads(out["choices"][0]["message"]["content"]))
    except (KeyError, IndexError, ValueError):
        raise RuntimeError("OpenAI's answer wasn't the expected JSON; try again") from None


class ContactIn(BaseModel):
    id: str | None = Field(default=None, max_length=60)
    name: str | None = Field(default=None, max_length=120)
    org: str | None = Field(default=None, max_length=160)
    lane: str | None = Field(default=None, max_length=60)
    stage: str | None = Field(default=None, max_length=80)
    signal: str | None = Field(default=None, max_length=10)
    said: str | None = Field(default=None, max_length=1500)
    read: str | None = Field(default=None, max_length=1000)
    next: str | None = Field(default=None, max_length=500)
    pilot_code: str | None = Field(default=None, max_length=40)
    last_contact: str | None = Field(default=None, max_length=10)
    loi: int | None = None
    paid_once: int | None = None
    monthly: int | None = None
    conditional: int | None = None
    talked: int | None = None
    needs_outcome: int | None = None
    update: str | None = Field(default=None, max_length=600)


class PasteIn(BaseModel):
    text: str = Field(min_length=20, max_length=60_000)
    contact_id: str | None = Field(default=None, max_length=60)


def setup(app: FastAPI, db: Callable, admin: Callable, now: Callable[[], str]) -> None:
    with db() as c:
        c.executescript(SCHEMA)
    state = {"last_pull": None, "last_error": None, "last_counts": None}

    def pull(force: bool = False) -> dict:
        digest, data = fetch_sync_file()
        with db() as c:
            seen = c.execute("SELECT value FROM settings WHERE key='pipeline_sync_hash'").fetchone()
            if seen and seen[0] == digest and not force:
                counts = {"new": 0, "changed": 0, "same": len(data.get("contacts") or []), "skipped": 0, "unchanged": True}
            else:
                counts = import_file(c, data, "sync", now())
                c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('pipeline_sync_hash', ?)", (digest,))
        state.update(last_pull=now(), last_error=None, last_counts=counts)
        return counts

    def loop() -> None:
        while True:
            try:
                pull()
            except Exception as e:                       # noqa: BLE001  (shown on the page, then tried again)
                state.update(last_pull=now(), last_error=str(e)[:300])
            time.sleep(max(60.0, PULL_MINUTES * 60))

    @app.on_event("startup")
    def _start_pull() -> None:
        if REPO and TOKEN and PULL_MINUTES > 0:
            threading.Thread(target=loop, name="pipeline-pull", daemon=True).start()

    @app.get("/v1/admin/contacts", dependencies=[Depends(admin)])
    def contacts():
        with db() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM contacts ORDER BY updated_at DESC")]
            logs: dict[str, list] = {}
            for r in c.execute("SELECT contact_id, t, source, text FROM contact_log ORDER BY id DESC"):
                if len(logs.setdefault(r[0], [])) < 6:
                    logs[r[0]].append({"t": r[1], "source": r[2], "text": r[3]})
            pilots = {r[0]: {"company": r[1], "actions": r[2] or 0, "last_seen": r[3], "mrr": r[4] or 0}
                      for r in c.execute("SELECT p.code, p.company, SUM(i.total_events), MAX(i.last_seen), p.mrr "
                                         "FROM pilots p LEFT JOIN installs i ON i.code = p.code GROUP BY p.code")}
        for r in rows:
            r["locked"] = json.loads(r["locked"] or "[]")
            r["log"] = logs.get(r["id"], [])
            r["pilot"] = pilots.get(r["pilot_code"] or "")
        totals = {"contacts": len(rows), "talked": sum(1 for r in rows if r["talked"]),
                  "intros": sum(1 for r in rows if not r["talked"]), "loi": sum(r["loi"] for r in rows),
                  "paid_once": sum(r["paid_once"] for r in rows), "monthly": sum(r["monthly"] for r in rows),
                  "conditional": sum(r["conditional"] for r in rows),
                  "needs_outcome": sum(1 for r in rows if r["needs_outcome"]),
                  "using": sum(1 for r in rows if r["signal"] == "using")}
        return {"contacts": rows, "totals": totals, "sync": {"configured": bool(REPO and TOKEN), "repo": REPO, **state},
                "reader": bool(OPENAI_KEY)}

    @app.post("/v1/admin/contacts", dependencies=[Depends(admin)])
    def save_contact(body: ContactIn):
        d = body.model_dump(exclude_none=True)
        update = d.pop("update", "")
        cid = d.pop("id", None)
        with db() as c:
            try:
                result = upsert(c, cid or d.get("name"), d, "manual", now(), manual=True, update=update)
            except ValueError as e:
                raise HTTPException(400, str(e)) from None
        return {"ok": True, "result": result}

    @app.delete("/v1/admin/contacts/{cid}", dependencies=[Depends(admin)])
    def delete_contact(cid: str):
        with db() as c:
            if not c.execute("DELETE FROM contacts WHERE id=?", (cid,)).rowcount:
                raise HTTPException(404, "no such contact")
            c.execute("DELETE FROM contact_log WHERE contact_id=?", (cid,))
        return {"ok": True}

    @app.post("/v1/admin/contacts/import", dependencies=[Depends(admin)])
    def import_contacts(data: dict):
        """The same file the sync reads, posted directly (for scripts that can reach this server)."""
        with db() as c:
            try:
                return import_file(c, data, "import", now())
            except ValueError as e:
                raise HTTPException(400, str(e)) from None

    @app.post("/v1/admin/contacts/pull", dependencies=[Depends(admin)])
    def pull_now():
        try:
            return pull(force=True)
        except Exception as e:                           # noqa: BLE001
            state.update(last_pull=now(), last_error=str(e)[:300])
            raise HTTPException(502, str(e)) from None

    @app.post("/v1/admin/contacts/read", dependencies=[Depends(admin)])
    def read_paste(body: PasteIn):
        hint = ""
        if body.contact_id:
            with db() as c:
                row = c.execute("SELECT name, org, stage FROM contacts WHERE id=?", (body.contact_id,)).fetchone()
            if row:
                hint = f"{row[0]} ({row[1] or ''}), currently: {row[2] or ''}"
        try:
            return {"suggestion": read_with_openai(body.text, hint)}
        except RuntimeError as e:
            raise HTTPException(502, str(e)) from None
