"""
The Team plan, unlocked by a license. What blocks and holds is free and stays free; a license adds what a team needs:

  people     more than one person on the gateway (approvers, viewers, admins)
  phone      approvals on a phone: push notifications (ntfy) and Face ID / fingerprint (passkeys)
  channels   approvals and the weekly report in Slack, Teams and email
  audit      the audit export (JSON, CSV, JSONL) and the evidence pack for an auditor

A license is one line from squidbrake.com: base64url(JSON) "." base64url(Ed25519 signature), checked offline against
PUBLIC_KEY. It goes in SQUIDBRAKE_LICENSE or data/license.key (`squidbrake license set LICENSE`). Until GRACE_UNTIL
everyone keeps these features, so nobody who uses them today is cut off without notice.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import date, datetime, timezone
from pathlib import Path

import signing

PUBLIC_KEY_HEX = "__PUBLIC_KEY__"   # its secret half is only on squidbrake.com's server
GRACE_UNTIL = "2026-11-20"
FILE = "license.key"
FEATURES = {"people": "more than one person", "phone": "approvals on a phone",
            "channels": "Slack, Teams and email", "audit": "audit export and the evidence pack"}
UPGRADE_URL = "https://squidbrake.com/signup?plan=team&from=license"


def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(secret: bytes, org: str, expires: str, plan: str = "team") -> str:
    """A license for `org` until `expires` (YYYY-MM-DD). Only squidbrake.com holds the secret."""
    body = json.dumps({"org": org, "plan": plan, "expires": expires}, separators=(",", ":")).encode()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    return enc(body) + "." + enc(signing.ed25519_sign(secret, body))


def check(token: str) -> dict | None:
    """The license's terms if its signature is ours and it hasn't expired, else None."""
    try:
        body, sig = token.strip().split(".")
        raw = _b64(body)
        if not signing.ed25519_verify(bytes.fromhex(PUBLIC_KEY_HEX), raw, _b64(sig)):
            return None
        terms = json.loads(raw)
        if date.fromisoformat(terms["expires"]) < datetime.now(timezone.utc).date():
            return None
        return terms
    except Exception:          # malformed: no license, never a crash
        return None


def current(data_dir: Path) -> dict | None:
    token = os.getenv("SQUIDBRAKE_LICENSE", "")
    if not token:
        try:
            token = (Path(data_dir) / FILE).read_text(encoding="utf-8")
        except OSError:
            return None
    return check(token)


def in_grace() -> bool:
    return datetime.now(timezone.utc).date() < date.fromisoformat(GRACE_UNTIL)


def paid(data_dir: Path) -> bool:
    return in_grace() or current(data_dir) is not None


def status(data_dir: Path) -> dict:
    lic = current(data_dir)
    return {"licensed": lic is not None, "org": lic and lic.get("org"), "expires": lic and lic.get("expires"),
            "grace_until": GRACE_UNTIL, "in_grace": in_grace(), "team_features": paid(data_dir),
            "features": list(FEATURES.values()), "upgrade_url": UPGRADE_URL}


def need(data_dir: Path, feature: str) -> None:
    """Raise 402 with what to do, when a Team feature is used without a license (after the grace period)."""
    if not paid(data_dir):
        from fastapi import HTTPException
        raise HTTPException(402, f"{FEATURES[feature][0].upper()}{FEATURES[feature][1:]} is part of the Team plan. "
                                 f"Start a 14-day trial or get a license: {UPGRADE_URL}")
