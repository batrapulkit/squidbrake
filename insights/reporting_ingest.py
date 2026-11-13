"""Additive, opt-in collector. No exporter or customer-side producer runs here."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from reporting_schema import Batch, Enrollment, Invitation

DB_ERRORS = (sqlite3.Error,)
try:
    from psycopg import Error as PostgresError
    DB_ERRORS += (PostgresError,)
except ImportError:
    pass

MAX_BODY = 128_000
ENROLL_LIMIT = 20                 # per IP/hour
INGEST_IP_LIMIT = 600             # per IP/minute (shared office networks)
INGEST_INSTALL_LIMIT = 60         # per credential/minute

SCHEMA = """
CREATE TABLE IF NOT EXISTS reporting_installations (
    installation_id TEXT PRIMARY KEY, pilot_code TEXT NOT NULL, provenance TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reporting_credentials (
    installation_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS reporting_invitations (
    token_hash TEXT PRIMARY KEY, installation_id TEXT NOT NULL, pilot_code TEXT NOT NULL,
    aliases TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE IF NOT EXISTS reporting_aliases (
    kind TEXT NOT NULL, alias TEXT NOT NULL, installation_id TEXT NOT NULL, PRIMARY KEY (kind, alias));
CREATE TABLE IF NOT EXISTS reporting_datasets (
    dataset_epoch TEXT PRIMARY KEY, installation_id TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reporting_batches (
    installation_id TEXT NOT NULL, batch_id TEXT NOT NULL, digest TEXT NOT NULL, ack TEXT NOT NULL,
    received_at TEXT NOT NULL, PRIMARY KEY (installation_id, batch_id));
CREATE TABLE IF NOT EXISTS reporting_events (
    installation_id TEXT NOT NULL, event_id TEXT NOT NULL, dataset_epoch TEXT NOT NULL,
    event_name TEXT NOT NULL, occurred_at TEXT NOT NULL, recorded_at TEXT NOT NULL,
    received_at TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (installation_id, event_id));
CREATE INDEX IF NOT EXISTS reporting_events_time ON reporting_events (installation_id, occurred_at);
CREATE TABLE IF NOT EXISTS reporting_rollups (
    installation_id TEXT NOT NULL, dataset_epoch TEXT NOT NULL, rollup_key TEXT NOT NULL,
    day TEXT NOT NULL, kind TEXT NOT NULL, revision INTEGER NOT NULL, count INTEGER NOT NULL,
    received_at TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (installation_id, dataset_epoch, rollup_key));
CREATE INDEX IF NOT EXISTS reporting_rollups_day ON reporting_rollups (day, installation_id);
CREATE TABLE IF NOT EXISTS reporting_outbox (
    installation_id TEXT NOT NULL, event_id TEXT NOT NULL, destination TEXT NOT NULL,
    payload TEXT NOT NULL, created_at TEXT NOT NULL, sent_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (installation_id, event_id, destination));
CREATE INDEX IF NOT EXISTS reporting_outbox_pending ON reporting_outbox (sent_at, created_at);
CREATE TABLE IF NOT EXISTS reporting_limits (
    bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, n INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS reporting_limits_expiry ON reporting_limits (window_start);
"""


def utcnow():
    return datetime.now(timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def parse(model, raw):
    try:
        return model.model_validate_json(raw)
    except ValidationError:
        # Pydantic's default error includes rejected input; keep customer content out of responses/logs.
        raise HTTPException(422, "invalid reporting payload") from None


def active():
    if os.getenv("INSIGHTS_REPORTING_V2", "0").lower() not in {"1", "true", "yes"}:
        raise HTTPException(503, "versioned reporting is disabled", headers={"Retry-After": "300"})


async def read_body(request: Request, maximum: int):
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(415, "compressed reporting bodies are unsupported")
    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) < 0:
                raise ValueError
            if int(length) > maximum:
                raise HTTPException(413, "reporting body too large")
        except ValueError:
            raise HTTPException(400, "invalid content length") from None
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise HTTPException(413, "reporting body too large")
        body.extend(chunk)
    return bytes(body)


async def bounded_body(request: Request):
    return await read_body(request, MAX_BODY)


@contextmanager
def available():
    try:
        yield
    except DB_ERRORS:
        raise HTTPException(503, "reporting storage unavailable", headers={"Retry-After": "30"}) from None


class Collector:
    def __init__(self, db, community_code):
        self.db, self.community_code = db, community_code
        with db() as c:
            c.executescript(SCHEMA)       # pg.Conn also enables RLS and restricts public roles

    def limit(self, key, limit, seconds):
        epoch = int(time.time())
        window = epoch // seconds * seconds
        with available(), self.db() as c:
            c.execute("DELETE FROM reporting_limits WHERE window_start < ?", (epoch - 86400,))
        with available(), self.db() as c:
            c.execute("""INSERT INTO reporting_limits (bucket, window_start, n) VALUES (?,?,1)
                ON CONFLICT (bucket) DO UPDATE SET n=CASE
                  WHEN reporting_limits.window_start=excluded.window_start THEN reporting_limits.n+1 ELSE 1 END,
                  window_start=excluded.window_start""", (key, window))
            count = c.execute("SELECT n FROM reporting_limits WHERE bucket=?", (key,)).fetchone()[0]
        if count > limit:
            raise HTTPException(429, "reporting rate limit exceeded",
                                headers={"Retry-After": str(window + seconds - epoch)})

    def ip_limit(self, request, purpose, limit, seconds):
        active()
        ip = request.client.host if request.client else "unknown"
        self.limit(purpose + ":" + digest(ip), limit, seconds)

    def invitation(self, body):
        token, at = "sbi_" + secrets.token_urlsafe(32), utcnow()
        with available(), self.db() as c:
            if not c.execute("SELECT 1 FROM pilots WHERE code=?", (body.pilot_code,)).fetchone():
                raise HTTPException(404, "pilot not found")
            for alias in body.aliases:
                if alias.kind == "pilot" and not c.execute(
                        "SELECT 1 FROM installs WHERE install_id=? AND code=?", (alias.alias, body.pilot_code)).fetchone():
                    raise HTTPException(409, "legacy installation does not belong to this pilot")
            c.execute("""INSERT INTO reporting_invitations
                (token_hash, installation_id, pilot_code, aliases, expires_at) VALUES (?,?,?,?,?)""",
                (digest(token), body.installation_id, body.pilot_code,
                 canonical([a.model_dump() for a in body.aliases]), (at + timedelta(hours=24)).isoformat()))
        return {"invitation_token": token, "expires_at": (at + timedelta(hours=24)).isoformat()}

    def enroll(self, body):
        token, at = "sbr_" + secrets.token_urlsafe(32), utcnow().isoformat()
        with available(), self.db() as c:
            aliases = []
            if body.invitation_token:
                key = digest(body.invitation_token)
                changed = c.execute("""UPDATE reporting_invitations SET used_at=?
                    WHERE token_hash=? AND installation_id=? AND used_at IS NULL AND expires_at>?""",
                    (at, key, body.installation_id, at)).rowcount
                if changed != 1:
                    raise HTTPException(403, "invalid or expired enrollment invitation")
                row = c.execute("SELECT pilot_code, aliases FROM reporting_invitations WHERE token_hash=?", (key,)).fetchone()
                code, aliases, provenance = row[0], json.loads(row[1]), "invited"
            else:
                if not secrets.compare_digest(body.community_code.encode(), self.community_code.encode()):
                    raise HTTPException(403, "invalid community code")
                code, provenance = self.community_code, "self_reported"
            if not c.execute("SELECT 1 FROM pilots WHERE code=?", (code,)).fetchone():
                raise HTTPException(403, "enrollment pilot unavailable")
            # No overwrite or credential retrieval via a public code, even after a lost response.
            changed = c.execute("""INSERT INTO reporting_installations
                (installation_id, pilot_code, provenance, created_at) VALUES (?,?,?,?)
                ON CONFLICT (installation_id) DO NOTHING""", (body.installation_id, code, provenance, at)).rowcount
            if changed != 1:
                raise HTTPException(409, "installation already enrolled; administrator recovery is required")
            c.execute("INSERT INTO reporting_credentials (installation_id, token_hash, created_at) VALUES (?,?,?)",
                      (body.installation_id, digest(token), at))
            for alias in aliases:
                c.execute("""INSERT INTO reporting_aliases (kind, alias, installation_id) VALUES (?,?,?)
                    ON CONFLICT (kind, alias) DO NOTHING""", (alias["kind"], alias["alias"], body.installation_id))
                owner = c.execute("SELECT installation_id FROM reporting_aliases WHERE kind=? AND alias=?",
                                  (alias["kind"], alias["alias"])).fetchone()[0]
                if owner != body.installation_id:
                    raise HTTPException(409, "legacy alias already linked")
        return {"schema_version": 2, "installation_id": body.installation_id, "reporting_token": token,
                "provenance": provenance}

    def authenticate(self, authorization):
        if not re.fullmatch(r"Bearer sbr_[A-Za-z0-9_-]{43}", authorization):
            raise HTTPException(401, "reporting credential required")
        key = digest(authorization[7:])
        with available(), self.db() as c:
            row = c.execute("""SELECT r.installation_id FROM reporting_credentials r
                JOIN reporting_installations i ON i.installation_id=r.installation_id
                JOIN pilots p ON p.code=i.pilot_code WHERE r.token_hash=? AND r.revoked_at IS NULL""", (key,)).fetchone()
        if not row:
            raise HTTPException(401, "invalid reporting credential")
        self.limit("install:" + row[0], INGEST_INSTALL_LIMIT, 60)
        return row[0], key

    def credential(self, installation_id, revoke=False):
        token, at = "sbr_" + secrets.token_urlsafe(32), utcnow().isoformat()
        with available(), self.db() as c:
            changed = c.execute("""UPDATE reporting_credentials SET token_hash=?, created_at=?, revoked_at=?
                WHERE installation_id=?""", (digest(token), at, at if revoke else None, installation_id)).rowcount
            if not changed:
                raise HTTPException(404, "reporting installation not found")
        return {"revoked": True} if revoke else {"installation_id": installation_id, "reporting_token": token}

    def ingest(self, who, body):
        iid, key = who
        if iid != body.installation_id:
            raise HTTPException(403, "credential belongs to another installation")
        encoded, at = canonical(body.model_dump(mode="json")), utcnow()
        with available(), self.db() as c:
            # First write serializes this installation across workers/processes on both databases.
            changed = c.execute("""UPDATE reporting_credentials SET installation_id=installation_id
                WHERE installation_id=? AND token_hash=? AND revoked_at IS NULL AND EXISTS (
                    SELECT 1 FROM reporting_installations i JOIN pilots p ON p.code=i.pilot_code
                    WHERE i.installation_id=reporting_credentials.installation_id)""", (iid, key)).rowcount
            if not changed:
                raise HTTPException(401, "reporting credential was revoked")
            previous = c.execute("SELECT digest, ack FROM reporting_batches WHERE installation_id=? AND batch_id=?",
                                 (iid, body.batch_id)).fetchone()
            if previous:
                if previous[0] != digest(encoded):
                    raise HTTPException(409, "batch ID reused with different content")
                return {**json.loads(previous[1]), "replayed": True}
            self.check_times(body, at)
            c.execute("""INSERT INTO reporting_datasets (dataset_epoch, installation_id, created_at) VALUES (?,?,?)
                ON CONFLICT (dataset_epoch) DO NOTHING""", (body.dataset_epoch, iid, at.isoformat()))
            owner = c.execute("SELECT installation_id FROM reporting_datasets WHERE dataset_epoch=?", (body.dataset_epoch,)).fetchone()[0]
            if owner != iid:
                raise HTTPException(409, "dataset epoch already has another reporting writer")
            ack = {"batch_id": body.batch_id, "accepted_at": at.isoformat(), "replayed": False,
                   "accepted_events": 0, "duplicate_events": 0, "updated_rollups": 0,
                   "stale_rollups": 0, "duplicate_rollups": 0}
            for event in body.events:
                payload = canonical({"dataset_epoch": body.dataset_epoch, **event.model_dump(mode="json")})
                old = c.execute("SELECT payload FROM reporting_events WHERE installation_id=? AND event_id=?",
                                (iid, event.event_id)).fetchone()
                if old:
                    if old[0] != payload:
                        raise HTTPException(409, "event ID reused with different content")
                    ack["duplicate_events"] += 1
                    continue
                c.execute("""INSERT INTO reporting_events (installation_id, event_id, dataset_epoch, event_name,
                    occurred_at, recorded_at, received_at, payload) VALUES (?,?,?,?,?,?,?,?)""",
                    (iid, event.event_id, body.dataset_epoch, event.event_name, event.occurred_at.isoformat(),
                     event.recorded_at.isoformat(), at.isoformat(), payload))
                c.execute("""INSERT INTO reporting_outbox (installation_id, event_id, destination, payload, created_at)
                    VALUES (?,?,?,?,?)""", (iid, event.event_id, "posthog", canonical({"installation_id": iid,
                                                                                   **json.loads(payload)}), at.isoformat()))
                ack["accepted_events"] += 1
            for rollup in body.rollups:
                payload = canonical(rollup.model_dump(mode="json"))
                rkey = digest(canonical(rollup.model_dump(mode="json", exclude={"revision", "count"})))
                args = (iid, body.dataset_epoch, rkey)
                old = c.execute("""SELECT revision, payload FROM reporting_rollups
                    WHERE installation_id=? AND dataset_epoch=? AND rollup_key=?""", args).fetchone()
                if old and old[0] >= rollup.revision:
                    if old[0] == rollup.revision and old[1] != payload:
                        raise HTTPException(409, "equal rollup revisions have different content")
                    ack["duplicate_rollups" if old[0] == rollup.revision else "stale_rollups"] += 1
                    continue
                c.execute("""INSERT INTO reporting_rollups (installation_id, dataset_epoch, rollup_key, day, kind,
                    revision, count, received_at, payload) VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT (installation_id, dataset_epoch, rollup_key) DO UPDATE SET
                    revision=excluded.revision, count=excluded.count, received_at=excluded.received_at, payload=excluded.payload""",
                    (*args, rollup.day.isoformat(), rollup.kind, rollup.revision, rollup.count, at.isoformat(), payload))
                ack["updated_rollups"] += 1
            c.execute("INSERT INTO reporting_batches (installation_id, batch_id, digest, ack, received_at) VALUES (?,?,?,?,?)",
                      (iid, body.batch_id, digest(encoded), canonical(ack), at.isoformat()))
        return ack                           # response only after commit; no vendor/network call

    @staticmethod
    def check_times(body, at):
        earliest, latest = at - timedelta(days=35), at + timedelta(minutes=5)
        valid = earliest <= body.sent_at <= latest
        for event in body.events:
            valid &= earliest <= event.occurred_at <= event.recorded_at <= latest
            valid &= event.recorded_at <= body.sent_at + timedelta(minutes=5)
        for rollup in body.rollups:
            valid &= earliest.date() <= rollup.day <= at.date()
        if not valid:
            raise HTTPException(422, "reporting timestamps outside the accepted window")


def mount(app, db, admin, community_code):
    collector = Collector(db, community_code)
    app.state.reporting_collector = collector

    def enrollment_limit(request: Request):
        collector.ip_limit(request, "enroll", ENROLL_LIMIT, 3600)

    def auth(request: Request, authorization: str = Header(default="")):
        collector.ip_limit(request, "ingest", INGEST_IP_LIMIT, 60)
        return collector.authenticate(authorization)

    @app.post("/v2/reporting/enroll", dependencies=[Depends(enrollment_limit)])
    def enroll(raw: bytes = Depends(bounded_body)):
        return JSONResponse(collector.enroll(parse(Enrollment, raw)), headers={"Cache-Control": "no-store"})

    @app.post("/v2/reporting/batches")
    def ingest(who=Depends(auth), raw: bytes = Depends(bounded_body)):
        return collector.ingest(who, parse(Batch, raw))

    @app.post("/v1/admin/reporting/invitations", dependencies=[Depends(admin), Depends(active)])
    def invitation(raw: bytes = Depends(bounded_body)):
        return JSONResponse(collector.invitation(parse(Invitation, raw)), headers={"Cache-Control": "no-store"})

    @app.post("/v1/admin/reporting/installations/{installation_id}/credential", dependencies=[Depends(admin), Depends(active)])
    def rotate(installation_id: str):
        return JSONResponse(collector.credential(installation_id), headers={"Cache-Control": "no-store"})

    @app.delete("/v1/admin/reporting/installations/{installation_id}/credential", dependencies=[Depends(admin)])
    def revoke(installation_id: str):
        return collector.credential(installation_id, revoke=True)
