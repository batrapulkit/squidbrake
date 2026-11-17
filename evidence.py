"""
Evidence pack: one printable page an auditor can read, built from the gateway's own records.

  squidbrake evidence --days 90 --out evidence.html     (or the dashboard's Reports tab)

It says what controls were in place (rules, who may approve, second-person approval, emergency stop),
what happened (actions checked, blocked, held, approved and by whom), whether the audit trail is intact,
and which common audit requirements each of those speaks to. The mapping is a starting point for the
conversation with an auditor, not a certification: the auditor decides what satisfies a control.

server.py gathers the numbers (build_evidence); this file only turns them into the page.
"""
from __future__ import annotations

from html import escape


def _n(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _pct(part: int, whole: int) -> str:
    return f"{round(100 * part / whole)}%" if whole else "n/a"


def mapping(ev: dict) -> list[dict]:
    """Which requirement each recorded control speaks to, with this period's numbers filled in."""
    a, sp, p, t = ev["approvals"], ev["second_person"], ev["policy"], ev["team"]
    stops = ev["changes"]["stops"]
    chain = "intact" if ev["audit"]["ok"] else "BROKEN"
    keys = (f"{_n(t['people'], 'person') if t['people'] == 1 else str(t['people']) + ' people'} ({t['approvers']} can approve, "
            f"{_n(t['admins'], 'admin')}) and {_n(t['agents'], 'agent key')}, "
            f"{t['agents_with_owner']} of them tied to the person they work for")
    oversight = (f"{a['held']} actions held for a person; {a['approved']} approved, {a['rejected']} rejected, "
                 f"{a['timed_out']} timed out. {_pct(sp['by_someone_else'], sp['by_someone_else'] + sp['by_owner'])} of decisions on agents "
                 f"with a known owner were made by someone other than that owner (second-person approval is {'on' if sp['enforced'] else 'off'}).")
    logging = (f"{ev['total']} agent actions recorded in a hash-chained trail ({ev['audit']['entries']} entries, "
               f"chain {chain}); each decision carries the fingerprint of the rules that made it.")
    rules = (f"{p['rules']} rules ({p['by_action'].get('deny', 0)} block, {p['by_action'].get('review', 0)} hold for a person, "
             f"{p['by_action'].get('allow', 0)} allow), {p['sequences']} sequence rules, default '{p['default']}', "
             f"mode '{p['mode']}'. {p['versions_in_period']} rules versions were in force during the period.")
    stop = f"Emergency stop available for all agents, one agent or one conversation; used {stops} times in the period."
    retention = (f"Records kept {'forever' if not ev['retention_days'] else str(ev['retention_days']) + ' days'}.")
    k = ev.get("controls") or {}
    signed = (f" {k.get('checkpoints', 0)} signed checkpoints (Ed25519, one per 50 entries) let anyone verify an export "
              f"against the published ledger key." if k else "")
    devices = (f" {k.get('device_signed', 0)} decisions were signed by a registered device (passkey: Face ID or "
               f"fingerprint){'; device signatures are required for approvals' if k.get('device_required') else ''}."
               if k else "")
    undo = (f" Before held or irreversible actions run, a copy of what they change is kept ({k.get('snapshots_kept', 0)} "
            f"kept, {k.get('snapshots_skipped', 0)} could not be made"
            f"{', and those actions were blocked' if k.get('snapshots') == 'required' else ''})." if k else "")
    proof = (f" Completed actions were checked in the real system: {k['proofs']['confirmed']} confirmed, "
             f"{k['proofs']['mismatch']} not actually done." if k.get("proof_checks") else "")
    rows = [
        {"framework": "SOC 2 (2017 TSC)", "ref": "CC6.1, CC6.3", "requirement": "Logical access; access granted by role",
         "evidence": keys + ". Rules can name who may approve (a person or a role)."},
        {"framework": "SOC 2 (2017 TSC)", "ref": "CC7.2", "requirement": "Monitor system components for anomalies",
         "evidence": logging + f" {ev['by_status'].get('denied', 0)} actions were blocked."},
        {"framework": "SOC 2 (2017 TSC)", "ref": "CC8.1", "requirement": "Changes are authorized before they are made",
         "evidence": oversight},
        {"framework": "ISO/IEC 42001", "ref": "Annex A, AI system operation and monitoring; event logs",
         "requirement": "Monitor AI system operation and keep event logs", "evidence": logging + " " + retention},
        {"framework": "EU AI Act", "ref": "Art. 12", "requirement": "Automatic recording of events (logs)",
         "evidence": logging + " " + retention},
        {"framework": "EU AI Act", "ref": "Art. 14", "requirement": "Human oversight, including the ability to intervene and stop",
         "evidence": oversight + " " + stop},
        {"framework": "EU AI Act", "ref": "Art. 26(6)", "requirement": "Deployers keep logs for at least six months",
         "evidence": retention},
        {"framework": "CERT-In AI security blueprint (2026)", "ref": "Agentic AI controls",
         "requirement": "Operational boundaries, continuous monitoring, audit logging, emergency shutdown",
         "evidence": rules + " " + logging + " " + stop},
        {"framework": "RBI FREE-AI (2025, guidance)", "ref": "Audit and oversight recommendations",
         "requirement": "Audit trails and human oversight of AI decisions", "evidence": logging + " " + oversight},
    ]
    if k:
        rows += [
            {"framework": "SOC 2 (2017 TSC)", "ref": "CC7.4, CC7.5", "requirement": "Respond to and recover from incidents",
             "evidence": (stop + undo + proof).strip()},
            {"framework": "SOC 2 (2017 TSC)", "ref": "CC6.7, C1.1", "requirement": "Protect confidential information",
             "evidence": f"Stored action details: {k.get('redaction')}; long values are cut to a preview where shown."},
            {"framework": "ISO/IEC 42001", "ref": "Annex A, AI system records and responsible use",
             "requirement": "Records are protected from tampering and decisions are attributable",
             "evidence": (logging + signed + devices).strip()},
            {"framework": "EU AI Act", "ref": "Art. 14(4)", "requirement": "Overseers can decide not to use, override or "
             "reverse the output, and interrupt the system", "evidence": (oversight + " " + stop + undo).strip()},
            {"framework": "EU AI Act", "ref": "Art. 15", "requirement": "Accuracy, robustness, resilience to faults",
             "evidence": f"When Squidbrake is unreachable, actions are {'blocked' if k.get('when_unreachable') == 'block' else 'allowed'} "
                         f"by default; {k.get('allow_while_unreachable', 0)} rule(s) explicitly allow their actions while it's "
                         f"down.{proof}"},
        ]
    return rows


def _table(head: list[str], rows: list[list], empty: str = "None in this period.") -> str:
    if not rows:
        return f"<p class='muted'>{escape(empty)}</p>"
    th = "".join(f"<th>{escape(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def render_html(ev: dict) -> str:
    a, sp, p, t, ch = ev["approvals"], ev["second_person"], ev["policy"], ev["team"], ev["changes"]
    ok = ev["audit"]["ok"]
    tiles = [("Actions recorded", ev["total"]), ("Blocked or rejected", ev["by_status"].get("denied", 0)),
             ("Held for a person", a["held"]), ("Approved / rejected", f"{a['approved']} / {a['rejected']}"),
             ("Decided by someone else", _pct(sp["by_someone_else"], sp["by_someone_else"] + sp["by_owner"])),
             ("Audit trail", "intact" if ok else "BROKEN")]
    tiles_html = "".join(f"<div class='tile'><div class='lbl'>{escape(k)}</div><div class='val'>{escape(str(v))}</div></div>"
                         for k, v in tiles)
    m = mapping(ev)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Squidbrake evidence pack</title>
<style>
:root {{ --ink:#1d1d1f; --muted:#666; --line:#ddd; --bad:#b42318; --good:#067647; }}
body {{ font: 14px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; color: var(--ink); background: #fff;
       max-width: 960px; margin: 32px auto; padding: 0 16px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }} h2 {{ font-size: 16px; margin: 28px 0 8px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }}
.muted {{ color: var(--muted); }} .bad {{ color: var(--bad); font-weight: 600; }} .good {{ color: var(--good); font-weight: 600; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; margin: 16px 0; }}
.tile {{ border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; }} .lbl {{ font-size: 12px; color: var(--muted); }}
.val {{ font-size: 18px; font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }} th, td {{ text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); }}
th {{ background: #f6f6f7; }} code {{ font-size: 12px; word-break: break-all; }}
@media print {{ body {{ margin: 0; }} h2 {{ break-after: avoid; }} tr {{ break-inside: avoid; }} }}
</style></head><body>
<h1>AI agent evidence pack</h1>
<div class="muted">Squidbrake {escape(ev['version'])} · period {escape(ev['since'][:10])} to {escape(ev['generated_at'][:10])} ({ev['days']} day{'s' if ev['days'] != 1 else ''})
 · generated {escape(ev['generated_at'])} by {escape(ev['generated_by'])}</div>
<div class="tiles">{tiles_html}</div>

<h2>1. Integrity of these records</h2>
<p>The audit trail is <span class="{'good' if ok else 'bad'}">{'intact' if ok else 'BROKEN'}</span>:
{ev['audit']['entries']} entries, each hash covering the one before, so an edited or deleted entry breaks every hash after it.
Head hash <code>{escape(str(ev['audit']['head_hash']))}</code>.</p>
<p class="muted">To check independently: download the full evidence file (dashboard → Reports → Evidence, or
<code>GET /v1/audit/export.json</code>) and run <code>python verify.py FILE</code> from the open-source Squidbrake repository.
It needs no access to this system.</p>

<h2>2. Controls in place</h2>
{_table(["Control", "Setting"], [
    ["Rules", f"{p['rules']} rules: {p['by_action'].get('deny', 0)} block, {p['by_action'].get('review', 0)} hold for a person, {p['by_action'].get('allow', 0)} allow; {p['sequences']} sequence rules"],
    ["Default for unmatched actions", p["default"]],
    ["Mode", p["mode"] + (f" (shadow for: {', '.join(p['shadow_agents'])})" if p["shadow_agents"] else "")],
    ["Rules fingerprint now", p["fingerprint"]],
    ["Second-person approval", "on: nobody approves their own agent's request" if sp["enforced"] else "off"],
    ["People and agents", f"{t['people']} people ({_n(t['approvers'], 'approver')}, {_n(t['admins'], 'admin')}); {_n(t['agents'], 'agent')}, {t['agents_with_owner']} with an owner"],
    ["When Squidbrake is unreachable", (f"each rule decides; default {ev['controls']['when_unreachable']}, "
                                        f"{ev['controls']['allow_while_unreachable']} rule(s) allow while it's down"
                                        if ev.get("controls") else "agent hooks block the action (fail closed)")
                                       + " (GATEWAY_FAIL_OPEN on a machine overrides it there)"],
    *([["Undo copies before risky actions", f"{ev['controls']['snapshots']}: {ev['controls']['snapshots_kept']} kept, "
                                             f"{ev['controls']['snapshots_skipped']} not possible"],
       ["Signed checkpoints", f"{ev['controls']['checkpoints']}; ledger key {ev['controls']['ledger_key'][:16]}…"],
       ["Approvals signed by a device", f"{ev['controls']['device_signed']} in the period, {ev['controls']['devices']} devices "
                                        f"registered{', required' if ev['controls']['device_required'] else ''}"],
       ["Spend limits", f"{ev['controls']['budgets']} budget(s)"],
       ["Proof of work", f"{ev['controls']['proof_checks']} check(s): {ev['controls']['proofs']['confirmed']} confirmed, "
                         f"{ev['controls']['proofs']['mismatch']} mismatched"],
       ["Stored data", ev["controls"]["redaction"]]] if ev.get("controls") else []),
    ["Record retention", "forever" if not ev["retention_days"] else f"{ev['retention_days']} days"],
])}

<h2>3. Human oversight</h2>
<p>{a['held']} actions were held for a person. {a['approved']} approved, {a['rejected']} rejected, {a['timed_out']} timed out
(timeouts follow each rule's setting). Of {sp['decided']} decisions by a person, {sp['by_someone_else']} were made by someone
other than the agent's owner, {sp['by_owner']} by the owner, and {sp['owner_unknown']} for agents with no owner set.</p>
{_table(["Approver", "Approved", "Rejected"], [[x["approver"], x["approved"], x["rejected"]] for x in a["by_approver"]])}

<h2>4. What was blocked</h2>
{_table(["Rule", "Reason", "Count"], [[b["rule_id"] or "", b["reason"] or "", b["count"]] for b in ev["blocked_by_rule"]])}

<h2>5. Changes to the controls during the period</h2>
{_table(["When", "Who", "What", "Target"], [[c["at"][:19].replace("T", " "), c["actor"] or "", c["action"], c["target"] or ""] for c in ch["entries"]],
        "No changes to rules, people, settings or emergency stops in this period.")}

<h2>6. Requirements these records speak to</h2>
<p class="muted">A starting point for your auditor, not a certification. Control references are given as commonly cited;
your auditor decides what satisfies each one.</p>
{_table(["Framework", "Reference", "Requirement", "Evidence from this period"], [[r["framework"], r["ref"], r["requirement"], r["evidence"]] for r in m])}
</body></html>
"""
