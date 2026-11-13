"""
The report email a free sign-up gets every few days: what their agents did, what would have been held, and where to
turn the hold on. The pricing page promises it ("A weekly email of what would have been held"); a gateway's own
weekly digest (server.py) is a Team feature that needs the customer's mail server, so a free user never got one.

Sent from here because this service already has each sign-up's email and what their gateway reports (days, catches).
A hosted sign-up whose agents never did anything gets one "where did it stop?" email instead, once.

Off until INSIGHTS_SMTP_HOST (and INSIGHTS_SMTP_FROM) are set. Every email carries a link that stops them.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import smtplib
import threading
import time
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Callable
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse

log = logging.getLogger("insights.report_mail")

SMTP_HOST = os.getenv("INSIGHTS_SMTP_HOST", "")
SMTP_PORT = int(os.getenv("INSIGHTS_SMTP_PORT", "587") or 587)
SMTP_USER = os.getenv("INSIGHTS_SMTP_USER", "")
SMTP_PASSWORD = os.getenv("INSIGHTS_SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("INSIGHTS_SMTP_FROM", "")           # e.g. "Pulkit from Squidbrake <pulkit@squidbrake.com>"
EVERY_DAYS = int(os.getenv("INSIGHTS_REPORT_DAYS", "3") or 3)
NUDGE_AFTER_DAYS = 2


def _n(v) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def off_token(secret: str, code: str) -> str:
    return hmac.new(secret.encode(), f"report-off:{code}".encode(), hashlib.sha256).hexdigest()[:32]


def report_text(days: int, tot: dict, catches: list[dict]) -> tuple[str, str]:
    would, stopped = tot["would_hold"] + tot["would_block"], tot["held"] + tot["blocked"]
    risky = would + stopped
    lines = [f"In the last {days} days Squidbrake saw your agents take {tot['events']} actions.", ""]
    if would:
        lines.append(f"It only watched, so nothing was stopped. {tot['would_hold']} of them would have waited for your "
                     f"yes, and {tot['would_block']} would have been blocked.")
    if stopped:
        lines.append(f"{tot['held']} waited for a person and {tot['blocked']} were blocked.")
    if not risky:
        lines.append("Nothing risky this time.")
    if catches:
        lines += ["", "Worth a look:"]
        for x in catches:
            what = " ".join(str(x[k]) for k in ("agent", "program", "tool") if x.get(k))
            lines.append(f"- {x['t'].replace('T', ' ')}  {what or 'an action'}: {x.get('why') or x.get('rule') or ''} "
                         f"({str(x.get('outcome', '')).replace('_', ' ').replace('-', ' ')})".replace(" ()", ""))
    subject = f"Your AI agents: {tot['events']} actions, {risky} worth a look" if risky \
        else f"Your AI agents: {tot['events']} actions, nothing risky"
    return subject, "\n".join(lines)


def due(c, today: date, base: str, secret: str) -> list[dict]:
    """Who gets an email today: {code, email, kind, subject, text, off}. Reads only; `mark` records the send."""
    since = (today - timedelta(days=EVERY_DAYS)).isoformat()
    state = {k: v for k, v in c.execute("SELECT key, value FROM settings WHERE key LIKE 'report_%'")}
    out = []
    for p in c.execute("SELECT code, email, hosted, subdomain, created_at FROM pilots WHERE email IS NOT NULL AND email != '' "
                       "AND COALESCE(mrr, 0) = 0 AND COALESCE(plan, '') = ''").fetchall():
        code = p["code"]
        if state.get(f"report_off:{code}") or state.get(f"report_sent:{code}", "") > since:
            continue
        ids = [r[0] for r in c.execute("SELECT install_id FROM installs WHERE code=?", (code,)).fetchall()]
        tot = dict.fromkeys(("events", "held", "blocked", "would_hold", "would_block"), 0)
        ever, catches = 0, []
        for iid in ids:
            for day, counts in c.execute("SELECT day, counts FROM days WHERE install_id=?", (iid,)).fetchall():
                cnt = json.loads(counts)
                ever += _n(cnt.get("events"))
                if day >= since:
                    for k in tot:
                        tot[k] += _n(cnt.get(k))
            catches += [json.loads(d) for (d,) in c.execute(
                "SELECT data FROM catches WHERE install_id=? AND t >= ?", (iid, since)).fetchall()]
        off = f"{base}/v1/report/off?code={quote(code)}&t={off_token(secret, code)}"
        foot = f"\n\nReply to this email and it reaches Pulkit.\n\nStop these emails: {off}"
        if tot["events"]:
            subject, text = report_text(EVERY_DAYS, tot, sorted(catches, key=lambda x: x["t"], reverse=True)[:3])
            if tot["would_hold"] + tot["would_block"]:
                text += f"\n\nOn Starter those wait for your yes before they run, and any agent has a stop button: {base}/pricing"
            out.append({"code": code, "email": p["email"], "kind": "report", "subject": subject,
                        "text": "Hi,\n\n" + text + foot, "off": off})
        elif not ever and p["hosted"] and not state.get(f"report_nudged:{code}") \
                and p["created_at"][:10] <= (today - timedelta(days=NUDGE_AFTER_DAYS)).isoformat():
            # only hosted: its gateway reports on its own, so no actions here really means none (a local install
            # with stats off also shows none)
            out.append({"code": code, "email": p["email"], "kind": "nudge", "subject": "Stuck setting up Squidbrake?",
                        "text": "Hi,\n\nYou signed up for Squidbrake and no agent action has reached it yet. Where did it "
                                f"stop? One line back is enough.\n\nYour setup page: {base}/start/{quote(code)}" + foot,
                        "off": off})
    return out


def mark(c, m: dict, today: date) -> None:
    key = "report_nudged" if m["kind"] == "nudge" else "report_sent"
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"{key}:{m['code']}", today.isoformat()))


def send(m: dict) -> bool:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = m["subject"], SMTP_FROM or SMTP_USER, m["email"]
    msg["List-Unsubscribe"], msg["List-Unsubscribe-Post"] = f"<{m['off']}>", "List-Unsubscribe=One-Click"
    msg.set_content(m["text"])
    try:
        smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) if SMTP_PORT == 465 else smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
        with smtp:
            if SMTP_PORT != 465:
                smtp.starttls()
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception:                                        # noqa: BLE001  (one bad address must not stop the rest)
        log.exception("report email to %s failed", m["email"])
        return False


def run(db: Callable, lock, base: str, secret: str, mail: Callable[[dict], bool] = send, today: date | None = None) -> int:
    today = today or datetime.now(timezone.utc).date()
    with lock, db() as c:
        todo = due(c, today, base, secret)
        for m in todo:          # recorded before sending: a crash mid-way skips an email, never sends one twice
            mark(c, m, today)
    return sum(1 for m in todo if mail(m))


PAGE = ('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Squidbrake report emails</title><body style="font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">')


def setup(app: FastAPI, db: Callable, lock, admin: Callable, base: str, secret: str) -> None:
    ready = bool(SMTP_HOST and (SMTP_FROM or SMTP_USER) and base and secret)

    def loop() -> None:
        while True:
            try:
                run(db, lock, base, secret)
            except Exception:                                # noqa: BLE001  (tried again in an hour)
                log.exception("report emails failed")
            time.sleep(3600)

    @app.on_event("startup")
    def _start_reports() -> None:
        if ready:
            threading.Thread(target=loop, name="report-mail", daemon=True).start()

    @app.get("/v1/admin/reports/preview", dependencies=[Depends(admin)])
    def preview():
        """What the next run would send, without sending or recording anything."""
        with db() as c:
            return {"sending": ready, "emails": due(c, datetime.now(timezone.utc).date(), base, secret or "preview")}

    def _check(code: str, t: str) -> None:
        if not secret or not hmac.compare_digest(t, off_token(secret, code)):
            raise HTTPException(404)

    # Opening the link only shows a button: mail scanners open links, so nothing is decided by a GET.
    @app.get("/v1/report/off", response_class=HTMLResponse, include_in_schema=False)
    def off_page(code: str = "", t: str = ""):
        _check(code, t)
        return PAGE + '<h1>Stop the report emails?</h1><form method="post"><button style="font:inherit;padding:.6rem 1rem">Yes, stop them</button></form>'

    @app.post("/v1/report/off", response_class=HTMLResponse, include_in_schema=False)
    def off(code: str = "", t: str = ""):
        _check(code, t)
        with lock, db() as c:
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, '1')", (f"report_off:{code}",))
        return PAGE + "<h1>Done</h1><p>No more report emails. Your dashboard keeps working.</p>"
