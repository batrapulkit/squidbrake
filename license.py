"""
Paid plans, unlocked by a license. On a self-hosted gateway what blocks and holds is free and stays free; a license
adds, by plan (PLANS):

  phone      approvals on a phone: push notifications (ntfy) and Face ID / fingerprint (passkeys)   Starter and up
  channels   approvals and the weekly report in Slack, Teams and email                              Starter and up
  audit      the audit export (JSON, CSV, JSONL)                                                     Pro and up
  people     more than one person on the gateway (approvers, viewers, admins)                       Team and up
  compliance the evidence pack for an auditor (SOC 2, ISO/IEC 42001, EU AI Act)                      Scale
  sso        sign-in with your company's SSO                                                         Scale

A gateway we host for someone (SQUIDBRAKE_PLAN, set by provision.py) also needs a license to block and hold: without
one it only watches (server.py hosted_watch_only).

A license is one line from squidbrake.com: base64url(JSON) "." base64url(Ed25519 signature), checked offline against
PUBLIC_KEY. It goes in SQUIDBRAKE_LICENSE or data/license.key (`squidbrake license set LICENSE`). Until GRACE_UNTIL
everyone keeps these features, so nobody who uses them today is cut off without notice.
"""
from __future__ import annotations

import base64
import functools
import json
import os
from datetime import date, datetime, timezone
from pathlib import Path

import signing

PUBLIC_KEY_HEX = "57316a1391b1d078f922eeea02ffa5a5f26098f36b48e2048f3e526b6157fe12"   # its secret half is only on squidbrake.com's server
GRACE_UNTIL = "2026-11-20"
FILE = "license.key"
FEATURES = {"people": "more than one person", "phone": "approvals on a phone",
            "channels": "Slack, Teams and email", "audit": "the audit export",
            "compliance": "compliance reports (the evidence pack)", "sso": "sign-in with your company's SSO"}
UPGRADE_URL = "https://squidbrake.com/pricing"
# What each paid plan unlocks (squidbrake.com/pricing). A license names its plan; one without a known plan is a Team
# license (every license issued before plans existed says "team").
PLANS = {"starter": {"phone", "channels"}, "pro": {"phone", "channels", "audit"},
         "team": {"phone", "channels", "audit", "people"}, "scale": set(FEATURES), "enterprise": set(FEATURES)}
ORDER = ["starter", "pro", "team", "scale"]


def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(secret: bytes, org: str, expires: str, plan: str = "team") -> str:
    """A license for `org` until `expires` (YYYY-MM-DD). Only squidbrake.com holds the secret."""
    body = json.dumps({"org": org, "plan": plan, "expires": expires}, separators=(",", ":")).encode()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    return enc(body) + "." + enc(signing.ed25519_sign(secret, body))


def check(token: str) -> dict | None:
    """The license's terms if its signature is ours and it hasn't expired, else None."""
    if not isinstance(token, str):
        return None
    terms = _check(token.strip(), PUBLIC_KEY_HEX, datetime.now(timezone.utc).date().isoformat())
    return dict(terms) if terms else None


@functools.lru_cache(maxsize=32)      # checked on every decision once hosted plans depend on it: verify once a day
def _check(token: str, public_key_hex: str, today: str) -> dict | None:
    try:
        body, sig = token.split(".")
        raw = _b64(body)
        if not signing.ed25519_verify(bytes.fromhex(public_key_hex), raw, _b64(sig)):
            return None
        terms = json.loads(raw)
        if date.fromisoformat(terms["expires"]) < date.fromisoformat(today):
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


def plan_of(lic: dict | None) -> str | None:
    return None if lic is None else (lic.get("plan") if lic.get("plan") in PLANS else "team")


def has(data_dir: Path, feature: str) -> bool:
    """Whether this gateway's plan includes `feature` (everything during the grace period)."""
    return in_grace() or feature in PLANS.get(plan_of(current(data_dir)) or "", set())


def cheapest(feature: str) -> str:
    return next(p for p in ORDER if feature in PLANS[p])


def status(data_dir: Path) -> dict:
    lic = current(data_dir)
    plan = plan_of(lic)
    return {"licensed": lic is not None, "org": lic and lic.get("org"), "expires": lic and lic.get("expires"),
            "plan": plan, "grace_until": GRACE_UNTIL, "in_grace": in_grace(), "team_features": paid(data_dir),
            "features": [FEATURES[f] for f in FEATURES if in_grace() or f in PLANS.get(plan or "", set())],
            "upgrade_url": UPGRADE_URL}


def need(data_dir: Path, feature: str) -> None:
    """Raise 402 with what to do, when a feature isn't in this gateway's plan (after the grace period)."""
    if not has(data_dir, feature):
        from fastapi import HTTPException
        plan = cheapest(feature)
        raise HTTPException(402, f"{FEATURES[feature][0].upper()}{FEATURES[feature][1:]} is part of the "
                                 f"{plan.capitalize()} plan. See the plans: {UPGRADE_URL}")
