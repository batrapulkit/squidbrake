"""
The end-of-day email: what the AI agents did today and where Squidbrake stepped in, written for a person to read in
a minute. HTML (email-safe: tables and inline styles, no scripts, no images to load) with a plain-text twin. It goes
out every day: a day with no agent actions gets a short, friendly nudge and a real incident instead of the numbers.

Each catch gets a little snapshot: the command as the agent sent it, what Squidbrake did, and what would have happened
without it. That last part is only ever one of two things: what the action would really have changed, when the hook
measured it (the "effect" signal), or a real, publicly reported incident of the same kind, with its source. Nothing
is made up for the email. STORIES is checked against incidents/scenarios.py by tests/test_daily.py, so each story is
one Squidbrake's own replay stops.

Two senders, one layout:
  - a gateway with email set up (server.maybe_send_daily), from build_report(1) and caught(1): the stored, redacted
    copies the dashboard shows;
  - squidbrake.com for the dashboards we host (insights/app.py maybe_send_daily), from the counts the gateway already
    shares (pilot.py): programs and sizes only, never commands or their arguments.
insights/daily.py is a copy of this file (the insights image is built from insights/ alone); a test keeps them equal.
Standard library only.
"""
from __future__ import annotations

import re
from datetime import datetime
from html import escape

# What has happened when this kind of action ran unchecked: (rule ids, a pattern the command must match or None,
# incident id in incidents/scenarios.py, title, when, source, what happened in one line). First match wins.
STORIES = [
    (("command:irreversible_command",), r"\b(ping|nslookup|dig|host)\b", "claude-code-dns-exfiltration",
     "Claude Code leaked secrets through DNS lookups (CVE-2025-55284)", "Aug 2025",
     "https://advisories.gitlab.com/npm/@anthropic-ai/claude-code/CVE-2025-55284/",
     "Hidden instructions got the agent to read secrets like .env and leak them inside ping and nslookup lookups."),
    (("block-sql-drop", "approve-writes-to-db", "command:irreversible_command"),
     r"(?i)\b(drop|truncate|delete\s+from|db:reset|migrate:fresh)\b", "replit-production-database",
     "Replit's agent deleted a production database during a code freeze", "Jul 2025",
     "https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/",
     "During an explicit code freeze, the agent ran destructive commands on the production database and wiped "
     "records on about 1,200 executives."),
    (("command:catastrophic_command", "block-destructive-shell"), None, "claude-code-home-folder",
     "Claude Code deleted a user's home folder", "Dec 2025",
     "https://www.docker.com/blog/coding-agent-horror-stories-the-rm-rf-incident/",
     "Asked to clean up, the agent ran a recursive delete whose last argument was the home folder: rm -rf ... ~/"),
    (("approve-agent-setup-changes",), None, "copilot-vscode-autoapprove",
     "GitHub Copilot turned on its own auto-approve (CVE-2025-53773)", "Aug 2025",
     "https://www.wiz.io/vulnerability-database/cve/cve-2025-53773",
     "Instructions hidden in a file it read made it switch on auto-approve, so its next shell commands ran without "
     "asking anyone."),
    (("approve-money-out", "approve-refunds", "runaway-refunds"), None, "operator-buys-eggs",
     "OpenAI's Operator bought groceries without asking", "Feb 2025",
     "https://www.washingtonpost.com/technology/2025/02/07/openai-operator-ai-agent-chatgpt/",
     "Asked to find cheap eggs, the agent went ahead and completed a $31 grocery order without checking first."),
]

OUTCOME = {   # catch outcome -> (emoji, what Squidbrake did, colour)
    "blocked": ("🛑", "Blocked it", "#C2410C"),
    "rejected": ("🙅", "Held it, and a person said no", "#A5560C"),
    "would have been blocked": ("👀", "Would have blocked it (shadow mode: it ran)", "#6B7280"),
    "would have waited for a person": ("👀", "Would have held it for a person (shadow mode: it ran)", "#6B7280"),
}

INK, MUTED, LINE, BG, CARD, ACCENT, GOOD = "#1E2A23", "#5B6660", "#E6E2DA", "#F7F4EE", "#FFFFFF", "#F2622E", "#237447"


def _story(s: tuple) -> dict:
    return dict(zip(("id", "title", "when", "url", "what"), s[2:]))


def story(catch: dict) -> dict | None:
    rule, what = (catch.get("share") or {}).get("rule") or "", catch.get("what") or ""
    for s in STORIES:
        if rule in s[0] and (s[1] is None or re.search(s[1], what)):
            return _story(s)
    return None


def story_of_the_day(day_number: int) -> dict:
    """A quiet day's incident: a different one each day, in turn."""
    return _story(STORIES[day_number % len(STORIES)])


def without(catch: dict) -> str:
    """What would have happened without Squidbrake, in one or two plain sentences, from facts only."""
    shadow = catch["outcome"].startswith("would")
    if catch.get("effect"):      # measured before it ran, e.g. "Deletes 1,204 files (3.1 GB) in ~/"
        lead = "It ran. Squidbrake had measured what it does" if shadow else \
            "It would have run straight away. Squidbrake measured what it does"
        return f"{lead}: {catch['effect'].rstrip('.')}."
    if shadow:
        return "It ran, with nobody asked. Turn on enforcement and next time it waits for you."
    if catch["outcome"] == "rejected":
        return "It would have run straight away, with nobody asked. A person looked and said no."
    return "It would have run straight away, with nobody asked and no way to stop it halfway."


def headline(r: dict, catches: list[dict], ever_used: bool) -> tuple[str, str]:
    n, stepped = r["total"], len(catches)
    if not n and not ever_used:
        return ("🦗 Crickets. Your dashboard waited all day.",
                "It's up, it's yours, and no agent has knocked yet. Connecting one takes about two minutes, "
                "and then this email gets a lot more interesting.")
    if not n:
        return ("Your agents took the day off 🏖️",
                "Nothing to check, nothing to stop. Squidbrake is still on guard for when they're back. "
                "Here's why that matters.")
    if not stepped:
        return (f"A calm day 🌤️ {n} actions, all routine.",
                "Your agents kept to the everyday stuff. Nothing needed stopping, which is exactly the goal.")
    times = "once" if stepped == 1 else "twice" if stepped == 2 else f"{stepped} times"
    return (f"Your agents did {n} things today. Squidbrake stepped in {times}. 🦑",
            "Here's what they tried, what happened instead, and what could have gone wrong.")


def clock(at: str, zone=None) -> str:
    """"2026-10-13T11:42:07Z" as the reader's time ("17:12 IST"), or the server's local time without a zone."""
    try:
        t = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        return at[11:16]
    t = t.astimezone(zone) if zone else t.astimezone()
    return f"{t:%H:%M} {t.tzname() or ''}".strip()


def build(r: dict, catches: list[dict], day: str, dashboard: str = "", *, day_number: int = 0,
          ever_used: bool = True, connect_url: str = "", unsubscribe: str = "", zone=None) -> dict:
    """Everything the email says, as data (the tests read this; html() and text() only lay it out).

    r: the day's report in server.build_report's shape (insights builds the same keys from shared counts; its
    "audit" is None there, since only the gateway can check its own record)."""
    a, s = r["approvals"], r["by_status"]
    title, sub = headline(r, catches, ever_used)
    stats = [("🔍", r["total"], "actions checked"),
             ("🛑", sum(b["count"] for b in r["blocked_by_rule"]), "blocked"),
             ("✋", a["held"], "held for a person"),
             ("✅", a["approved"], "approved by a person")] if r["total"] else []
    facts = []
    if r["agents"]:
        top = r["agents"][0]
        facts.append(f"🏆 Busiest agent: {top['agent']} ({top['total']} actions)")
    if r.get("top_tools"):
        facts.append(f"🧰 Favourite tool: {r['top_tools'][0]['name']} ({r['top_tools'][0]['count']} times)")
    if a["median_seconds_to_decide"] is not None:
        secs = int(a["median_seconds_to_decide"])
        facts.append(f"⏱️ Typical time to approve: {secs // 60} min {secs % 60} s" if secs >= 60 else
                     f"⏱️ Typical time to approve: {secs} seconds")
    if a["rejected"]:
        facts.append("🙅 A person said no " + ("once" if a["rejected"] == 1 else f"{a['rejected']} times"))
    if a["waiting_now"]:
        facts.append(f"⏳ {a['waiting_now']} still waiting for you")
    if s.get("failed"):
        facts.append(f"💥 {s['failed']} actions failed on their own (not Squidbrake)")
    au = r.get("audit")
    if au:
        facts.append("🔒 Your record is intact (tamper-evident, checked just now)" if au["ok"] else
                     f"⚠️ Your record doesn't check out from entry {au['first_bad_seq']}: look at it in the dashboard")
    nudge = None
    if not r["total"]:
        nudge = {"story": story_of_the_day(day_number),
                 "cta": ("Connect my first agent →", connect_url or (dashboard.rstrip("/") + "/dashboard"))
                 if not ever_used else ("Open my dashboard →", dashboard.rstrip("/") + "/dashboard"),
                 "tips": ["⚡ 60-second test: ask your agent to delete a throwaway folder and see what Squidbrake makes of it.",
                          "🔌 Using more than one agent? Connect each one: they all show up on the same dashboard.",
                          "🧾 Every decision is kept on a tamper-evident record you can hand an auditor."]}
    shadow = r.get("shadow") or {}
    return {"day": day, "title": title, "sub": sub, "stats": stats, "facts": facts, "dashboard": dashboard.rstrip("/"),
            "shadow": bool(shadow.get("would_block") or shadow.get("would_hold")), "nudge": nudge,
            "unsubscribe": unsubscribe, "day_number": day_number, "total": r["total"],
            "catches": [{**c, "did": OUTCOME[c["outcome"]], "without": without(c), "story": story(c), "clock": clock(c["at"], zone)}
                        for c in catches]}


SUBJECTS = {   # a few of each, in turn by day. Plain and specific: emoji and teasers read as promotions to spam filters
    "new": ["Connect your first agent to Squidbrake (2 minutes)",
            "Your Squidbrake dashboard is ready for its first agent",
            "Squidbrake: one step left to check your AI agents"],
    "miss": ["Squidbrake daily: no agent actions today",
             "Squidbrake daily: a quiet day, and a real incident to read",
             "Squidbrake daily: what happened to a team without approvals"],
    "calm": ["Squidbrake daily: {n} agent actions, nothing needed stopping",
             "Squidbrake daily: {n} actions, all routine",
             "Squidbrake daily: a calm day, {n} actions"],
    "saves": ["Squidbrake daily: {k} risky action{s} stopped",
              "Squidbrake daily: {k} action{s} held or blocked today",
              "Squidbrake daily: your agents tried {k} risky thing{s}"],
}


def kind(d: dict) -> str:
    if d["catches"]:
        return "saves"
    if d["nudge"]:
        return "new" if d["nudge"]["cta"][0].startswith("Connect") else "miss"
    return "calm"


def subject(d: dict) -> str:
    k = len(d["catches"])
    options = SUBJECTS[kind(d)]
    return options[d.get("day_number", 0) % len(options)].format(n=d["total"], k=k, s="" if k == 1 else "s")


# ---------------------------------------------------------------------------- layout

def _button(label: str, url: str) -> str:
    return (f'<p style="margin:24px 0 0;text-align:center"><a href="{escape(url)}" '
            f'style="display:inline-block;background:{ACCENT};color:#fff;text-decoration:none;font:bold 14px Arial,sans-serif;'
            f'padding:12px 22px;border-radius:999px">{escape(label)}</a></p>')


def _snapshot(c: dict) -> str:
    emoji, did, colour = c["did"]
    who = f" by {escape(c['by'])}" if c.get("by") else ""
    note = f' &ldquo;{escape(c["note"])}&rdquo;' if c.get("note") else ""
    st = c["story"]
    story_html = (f'<tr><td style="padding:10px 16px 14px;font:13px/1.5 Arial,sans-serif;color:{MUTED}">'
                  f'📰 <b style="color:{INK}">This has happened for real:</b> {escape(st["title"])} ({escape(st["when"])}). '
                  f'<a href="{escape(st["url"])}" style="color:{ACCENT}">Read the story</a></td></tr>') if st else ""
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{CARD};border:1px solid {LINE};border-radius:12px;margin:0 0 16px;border-collapse:separate">
  <tr><td style="padding:12px 16px 6px;font:12px/1.4 Arial,sans-serif;color:{MUTED}">{escape(c['clock'])} · {escape(c['agent'] or 'an agent')} · {escape(c['tool'])}</td></tr>
  <tr><td style="padding:0 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#16201B;border-radius:8px">
      <tr><td style="padding:8px 12px 0;font:10px Arial,sans-serif;color:#6B7A72">● ● ●&nbsp;&nbsp;what the agent tried</td></tr>
      <tr><td style="padding:6px 12px 12px;font:13px/1.5 Menlo,Consolas,monospace;color:#E8F0EA;word-break:break-all">$ {escape(c['what'])}</td></tr>
    </table>
  </td></tr>
  <tr><td style="padding:10px 16px 0">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top" width="50%" style="padding:10px 12px;background:#EEF6F0;border-radius:8px 0 0 8px;font:13px/1.5 Arial,sans-serif;color:{INK}">
        <div style="font-weight:bold;color:{GOOD};margin-bottom:4px">With Squidbrake</div>
        {emoji} <b style="color:{colour}">{escape(did)}</b>{who}{note}.<br><span style="color:{MUTED}">{escape(c['why'])}</span></td>
      <td valign="top" width="50%" style="padding:10px 12px;background:#FCEDE6;border-radius:0 8px 8px 0;font:13px/1.5 Arial,sans-serif;color:{INK}">
        <div style="font-weight:bold;color:#C2410C;margin-bottom:4px">Without Squidbrake</div>
        💥 {escape(c['without'])}</td>
    </tr></table>
  </td></tr>
  {story_html or '<tr><td style="height:14px"></td></tr>'}
</table>"""


def _nudge(n: dict) -> str:
    st = n["story"]
    tips = "".join(f'<li style="margin:0 0 6px">{escape(t)}</li>' for t in n["tips"])
    return f"""
<tr><td style="font:bold 17px Arial,sans-serif;color:{INK};padding:0 0 10px">Meanwhile, somewhere without a brake 📰</td></tr>
<tr><td>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{CARD};border:1px solid {LINE};border-radius:12px;border-collapse:separate">
  <tr><td style="padding:14px 16px 4px;font:12px Arial,sans-serif;color:{MUTED}">{escape(st['when'])} · a real, reported incident</td></tr>
  <tr><td style="padding:0 16px 6px;font:bold 16px/1.35 Arial,sans-serif;color:{INK}">{escape(st['title'])}</td></tr>
  <tr><td style="padding:0 16px 10px;font:14px/1.5 Arial,sans-serif;color:{INK}">{escape(st['what'])}</td></tr>
  <tr><td style="padding:0 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top" width="50%" style="padding:10px 12px;background:#FCEDE6;border-radius:8px 0 0 8px;font:13px/1.5 Arial,sans-serif;color:{INK}">
        <div style="font-weight:bold;color:#C2410C;margin-bottom:4px">Without Squidbrake</div>💥 It just ran. Nobody was asked.</td>
      <td valign="top" width="50%" style="padding:10px 12px;background:#EEF6F0;border-radius:0 8px 8px 0;font:13px/1.5 Arial,sans-serif;color:{INK}">
        <div style="font-weight:bold;color:{GOOD};margin-bottom:4px">With Squidbrake</div>🛑 Squidbrake stops our replay of this incident before the harmful step runs.</td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:10px 16px 14px;font:13px Arial,sans-serif"><a href="{escape(st['url'])}" style="color:{ACCENT}">Read the story</a></td></tr>
</table></td></tr>
<tr><td style="font:bold 17px Arial,sans-serif;color:{INK};padding:22px 0 8px">Try this tomorrow</td></tr>
<tr><td><ul style="margin:0;padding:0 0 0 2px;list-style:none;font:14px/1.5 Arial,sans-serif;color:{INK}">{tips}</ul>
{_button(*n['cta'])}</td></tr>"""


def html(d: dict) -> str:
    stats = "".join(
        f'<td align="center" width="25%" style="padding:12px 4px;background:{CARD};border:1px solid {LINE};border-radius:10px">'
        f'<div style="font-size:20px">{e}</div><div style="font:bold 22px Arial,sans-serif;color:{INK}">{n}</div>'
        f'<div style="font:12px Arial,sans-serif;color:{MUTED}">{escape(lbl)}</div></td>'
        + ('<td width="8"></td>' if i < 3 else "") for i, (e, n, lbl) in enumerate(d["stats"]))
    stats = (f'<tr><td style="padding:0 0 20px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
             f'<tr>{stats}</tr></table></td></tr>') if stats else ""
    facts = "".join(f'<li style="margin:0 0 6px">{escape(f)}</li>' for f in d["facts"])
    shadow = (f'<tr><td><p style="margin:0 0 16px;padding:10px 12px;background:#FFF7E0;border-radius:8px;font:13px/1.5 Arial,sans-serif;color:{INK}">'
              "👀 <b>Shadow mode is on</b>, so Squidbrake only watched today: the actions below marked shadow mode really ran.</p></td></tr>"
              ) if d["shadow"] else ""
    if d["nudge"]:
        body = _nudge(d["nudge"])
    else:
        saves = ("".join(_snapshot(c) for c in d["catches"]) if d["catches"] else
                 f'<p style="font:14px/1.5 Arial,sans-serif;color:{MUTED}">No saves today. 🧘 Nothing your agents did needed a second look.</p>')
        body = (f'<tr><td style="font:bold 17px Arial,sans-serif;color:{INK};padding:0 0 10px">The saves of the day</td></tr>'
                f'<tr><td>{saves}</td></tr>')
        if facts or d["dashboard"]:
            body += (f'<tr><td style="font:bold 17px Arial,sans-serif;color:{INK};padding:12px 0 8px">Fun facts</td></tr>'
                     f'<tr><td><ul style="margin:0;padding:0 0 0 2px;list-style:none;font:14px/1.5 Arial,sans-serif;color:{INK}">{facts}</ul>'
                     + (_button("Open my dashboard →", d["dashboard"] + "/dashboard") if d["dashboard"] else "") + '</td></tr>')
    stop = (f'<a href="{escape(d["unsubscribe"])}" style="color:{MUTED}">Stop these daily emails</a>.' if d["unsubscribe"]
            else 'Don\'t want these? Untick "Email a report at the end of each day" in Settings.')
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{escape(subject(d))}</title></head>
<body style="margin:0;padding:0;background:{BG}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{BG}"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px">
  <tr><td style="font:bold 13px Arial,sans-serif;color:{ACCENT};letter-spacing:.5px;padding:0 0 6px">🦑 SQUIDBRAKE · YOUR DAY IN AI · {escape(d['day']).upper()}</td></tr>
  <tr><td style="font:bold 24px/1.25 Arial,sans-serif;color:{INK};padding:0 0 6px">{escape(d['title'])}</td></tr>
  <tr><td style="font:15px/1.5 Arial,sans-serif;color:{MUTED};padding:0 0 18px">{escape(d['sub'])}</td></tr>
  {stats}{shadow}{body}
  <tr><td style="font:12px/1.5 Arial,sans-serif;color:{MUTED};padding:28px 0 0">
    "Without Squidbrake" is what the action would have changed when Squidbrake could measure it, or a real reported
    incident of the same kind. Commands are shown as stored, with secrets taken out. {stop}</td></tr>
</table></td></tr></table></body></html>"""


def text(d: dict) -> str:
    lines = [f"SQUIDBRAKE: YOUR DAY IN AI ({d['day']})", "", d["title"], d["sub"], ""]
    if d["stats"]:
        lines += ["  ".join(f"{n} {lbl}" for _, n, lbl in d["stats"]), ""]
    if d["shadow"]:
        lines += ["Shadow mode is on: Squidbrake only watched today, so the shadow-mode actions below really ran.", ""]
    if d["nudge"]:
        st, label, url = d["nudge"]["story"], *d["nudge"]["cta"]
        lines += ["MEANWHILE, SOMEWHERE WITHOUT A BRAKE", f"{st['title']} ({st['when']})", st["what"],
                  "Without Squidbrake: it just ran. With Squidbrake: Squidbrake stops our replay of this incident "
                  "before the harmful step runs.", st["url"], "", "TRY THIS TOMORROW"] + [f"- {t}" for t in d["nudge"]["tips"]]
        lines += ["", f"{label.rstrip(' →')}: {url}"]
    else:
        lines.append("THE SAVES OF THE DAY")
        if not d["catches"]:
            lines.append("No saves today. Nothing your agents did needed a second look.")
        for i, c in enumerate(d["catches"], 1):
            who = f" by {c['by']}" + (f' ("{c["note"]}")' if c.get("note") else "") if c.get("by") else ""
            lines += [f"{i}. {c['agent'] or 'an agent'} tried: {c['what']}",
                      f"   With Squidbrake: {c['did'][1]}{who}. {c['why']}",
                      f"   Without Squidbrake: {c['without']}"]
            if c["story"]:
                lines.append(f"   This has happened for real: {c['story']['title']} ({c['story']['when']}). {c['story']['url']}")
        if d["facts"]:
            lines += ["", "FUN FACTS"] + [f"- {f}" for f in d["facts"]]
        if d["dashboard"]:
            lines += ["", f"Open your dashboard: {d['dashboard']}/dashboard"]
    if d["unsubscribe"]:
        lines += ["", f"Stop these daily emails: {d['unsubscribe']}"]
    return "\n".join(lines) + "\n"
