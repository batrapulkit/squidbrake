"""
The weekly report a pilot hands back (`squidbrake report --week`, GET /v1/reports/week): actions seen, held, blocked,
would-have-blocked (observe mode), the false-positive rate from people's "this was legit" feedback, how long the
gateway took to decide, and the top chains it caught, in plain language. Markdown or JSON.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

# Findings that come from what happened before the action, not the action alone: these are the chains.
CHAIN_CHECKS = ("sequence", "untrusted_destination", "impersonation", "payment_request_in_message",
                "repeat_of_rejected", "written_then_run_command", "edited_then_run_command",
                "duplicate_change")


def percentiles(values: list[float]) -> dict:
    xs = sorted(v for v in values if v is not None)
    if not xs:
        return {"n": 0, "p50": None, "p95": None, "p99": None}
    q = lambda p: round(xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))], 1)
    return {"n": len(xs), "p50": q(50), "p95": q(95), "p99": q(99)}


def _outcome(r) -> str | None:
    if r.would:
        return "would_block" if r.would == "deny" else "would_hold"
    if r.status == "denied" and not r.decided_by:
        return "blocked"
    if r.approval_deadline:
        return "held"
    return None


def _week(iso: str) -> str:
    y, w, _ = datetime.fromisoformat(iso.replace("Z", "+00:00")).isocalendar()
    return f"{y}-W{w:02d}"


def build(engine, events, days: int = 7) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with engine.connect() as conn:
        rows = conn.execute(select(
            events.c.id, events.c.created_at, events.c.kind, events.c.name, events.c.source, events.c.client,
            events.c.status, events.c.decided_by, events.c.decision, events.c.approval_deadline, events.c.would,
            events.c.rule_id, events.c.reason, events.c.signals, events.c.decision_ms, events.c.feedback,
        ).where(events.c.created_at >= since, events.c.kind != "prompt").limit(200000)).all()
    counts = defaultdict(int)
    other_kinds: dict[str, int] = defaultdict(int)
    by_rule: dict[str, dict] = {}
    by_week: dict[str, dict] = {}
    chains: list[dict] = []
    for r in rows:
        counts["seen"] += 1
        if r.kind not in ("tool_call", "question"):
            other_kinds[r.kind] += 1
        out = _outcome(r)
        if not out:
            # a risk it noted and let through; not an "info" note such as how much the action would change
            counts["warned"] += any(s.get("effect") == "warn" for s in json.loads(r.signals or "[]"))
            continue
        counts[out] += 1
        if r.approval_deadline and r.decided_by and r.decided_by != "timeout":
            counts["approved" if r.decision == "allow" else "rejected"] += 1
        legit = r.feedback == "legit"
        for bucket in (by_rule.setdefault(r.rule_id or "default", {"stopped": 0, "legit": 0, "rated": 0}),
                       by_week.setdefault(_week(r.created_at), {"stopped": 0, "legit": 0, "rated": 0})):
            bucket["stopped"] += 1
            bucket["legit"] += legit
            bucket["rated"] += r.feedback is not None
        found = next((s for s in json.loads(r.signals or "[]") if s.get("check") in CHAIN_CHECKS), None)
        if found and not legit:
            chains.append({"at": r.created_at, "agent": r.source or r.client, "tool": r.name, "outcome": out,
                           "rule": r.rule_id, "story": found.get("message", "")[:400]})
    # no feedback at all is an unmeasured rate, not a zero one
    rate = lambda b: round(b["legit"] / b["stopped"], 3) if b["rated"] else None
    stopped = sum(counts[k] for k in ("blocked", "held", "would_block", "would_hold"))
    legit = sum(b["legit"] for b in by_rule.values())
    rated = sum(b["rated"] for b in by_rule.values())
    order = {"blocked": 0, "held": 1, "would_block": 2, "would_hold": 3}
    seen, top = set(), []
    for c in sorted(chains, key=lambda c: (order[c["outcome"]], c["at"])):
        if c["rule"] not in seen:            # three different chains, not one chain three times
            seen.add(c["rule"])
            top.append(c)
    return {
        "days": days, "since": since,
        "actions": {"seen": counts["seen"], "held": counts["held"], "blocked": counts["blocked"],
                    "would_block": counts["would_block"], "would_hold": counts["would_hold"],
                    "approved": counts["approved"], "rejected": counts["rejected"], "warned": counts["warned"]},
        "other_kinds": dict(sorted(other_kinds.items())),
        "false_positives": {"legit": legit, "stopped": stopped, "rated": rated,
                            "rate": round(legit / stopped, 3) if rated else None,
                            "by_rule": {k: {**v, "rate": rate(v)} for k, v in sorted(by_rule.items())},
                            "by_week": {k: {**v, "rate": rate(v)} for k, v in sorted(by_week.items())}},
        "latency_ms": percentiles([r.decision_ms for r in rows]),
        "top_chains": top[:3],
    }


def markdown(r: dict) -> str:
    a, fp, lat = r["actions"], r["false_positives"], r["latency_ms"]
    pct = lambda x: "n/a" if x is None else f"{x * 100:.1f}%"
    ms = lambda x: "n/a" if x is None else f"{x:g} ms"
    lines = [f"# Squidbrake: the last {r['days']} days", "",
             "| Actions seen | Held for a person | Blocked | Would have held (observe) | Would have blocked (observe) |",
             "|---|---|---|---|---|",
             f"| {a['seen']} | {a['held']} | {a['blocked']} | {a['would_hold']} | {a['would_block']} |", ""]
    if r["other_kinds"]:
        lines += ["Actions seen includes records that are not agent tool calls: "
                  + ", ".join(f"{n} `{k}`" for k, n in r["other_kinds"].items()) + ".", ""]
    if a["warned"]:
        lines += [f"**Let through with a warning:** {a['warned']} actions ran while Squidbrake noted a risk. "
                  "Check them in the dashboard.", ""]
    if fp["stopped"] and not fp["rated"]:
        lines += [f"**False positives:** not measured. Nobody has marked any of the {fp['stopped']} stopped actions "
                  "yet. Mark one with `squidbrake feedback EVENT_ID legit` (or `right`).", ""]
    else:
        lines += [f"**False positives:** {fp['legit']} of {fp['stopped']} stopped actions were marked legit "
                  f"({pct(fp['rate'])}). Mark one with `squidbrake feedback EVENT_ID legit`.", ""]
    lines += [
             f"**Decision time:** p50 {ms(lat['p50'])}, p95 {ms(lat['p95'])}, p99 {ms(lat['p99'])} "
             f"over {lat['n']} actions (the gateway's decision; a hook adds its own start-up).", ""]
    if fp["by_rule"]:
        lines += ["| Rule | Stopped | Marked legit | Rate |", "|---|---|---|---|"]
        lines += [f"| `{k}` | {v['stopped']} | {v['legit']} | {pct(v['rate'])} |" for k, v in fp["by_rule"].items()]
        lines.append("")
    lines.append("## Chains caught")
    if not r["top_chains"]:
        lines.append("None this period: nothing was stopped because of what came before it.")
    for i, c in enumerate(r["top_chains"], 1):
        lines.append(f"{i}. **{c['outcome'].replace('_', ' ')}**: {c['tool']} by {c['agent']} ({c['at'][:16]}). "
                     f"{c['story']}")
    return "\n".join(lines) + "\n"
