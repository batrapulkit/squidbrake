"""
Check a Squidbrake evidence file on any machine, without trusting the server that produced it.

    python verify.py squidbrake-evidence-20261001.json [--json]

Download the file from the dashboard (Reports > Tamper check > Download evidence) or GET /v1/audit/export.json.
Only the Python standard library is needed. It checks that:

  1. the audit trail is one unbroken hash chain from the first entry (nothing edited, removed or inserted);
  2. every recorded action's input and result still match the fingerprints taken when they happened;
  3. every decision names the version of the rules that made it, and that version's text is in the file.

Exit code 0 if everything checks out, 1 if anything doesn't.
"""
from __future__ import annotations

import hashlib
import json
import sys

GENESIS = "0" * 64
FORMAT = "squidbrake-evidence/1"


def entry_hash(prev: str, at: str, actor: str | None, action: str, target: str | None, detail: str) -> str:
    """The fingerprint of one audit entry, chained to the one before. The server uses this same function."""
    body = json.dumps([prev, at, actor, action, target, detail], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()


def sha(value: object) -> str | None:
    return None if value is None else hashlib.sha256(str(value).encode()).hexdigest()


def rules_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def check_chain(entries: list[dict]) -> dict:
    prev = GENESIS
    for n, e in enumerate(entries, 1):
        if e["prev_hash"] != prev or e["hash"] != entry_hash(prev, e["at"], e["actor"], e["action"], e["target"], e["detail"]):
            return {"ok": False, "entries": n, "first_bad_seq": e.get("seq"), "head_hash": None,
                    "message": f"entry #{e.get('seq')} was changed, removed or inserted after the fact"}
        prev = e["hash"]
    return {"ok": True, "entries": len(entries), "first_bad_seq": None, "head_hash": prev,
            "message": "every entry is intact and in its original order"}


def check_events(entries: list[dict], events: dict[str, dict]) -> dict:
    """Do the actions still hold what was fingerprinted when they happened? (Deleted by retention = skipped.)"""
    changed, checked = [], 0
    for e in entries:
        ev = events.get(e["target"] or "")
        if ev is None or not e["action"].startswith("event."):
            continue
        d = json.loads(e["detail"] or "{}")
        if e["action"] == "event.created":
            checked += 1
            if d.get("input_sha256") != sha(ev.get("input")):
                changed.append({"event": ev["id"], "field": "input"})
        if "output_sha256" in d and d["output_sha256"] is not None and d["output_sha256"] != sha(ev.get("output")):
            changed.append({"event": ev["id"], "field": "output"})
    return {"checked": checked, "changed": changed}


def check_rules(entries: list[dict], policies: dict[str, str]) -> dict:
    missing, wrong, used = set(), [], set()
    for fp, text in policies.items():
        if rules_fingerprint(text) != fp:
            wrong.append(fp)
    for e in entries:
        if e["action"] == "event.created":
            fp = json.loads(e["detail"] or "{}").get("rules")
            if fp:
                used.add(fp)
                if fp not in policies:
                    missing.add(fp)
    return {"versions": sorted(used), "missing": sorted(missing), "mismatched": wrong}


def verify(data: dict) -> dict:
    if data.get("format") != FORMAT:
        return {"ok": False, "message": f"not a Squidbrake evidence file (format {data.get('format')!r})"}
    entries = data.get("entries") or []
    chain = check_chain(entries)
    events = {e["id"]: e for e in data.get("events") or []}
    evs = check_events(entries, events)
    rules = check_rules(entries, data.get("policies") or {})
    ok = chain["ok"] and not evs["changed"] and not rules["missing"] and not rules["mismatched"]
    if data.get("head_hash") and chain["ok"] and data["head_hash"] != chain["head_hash"]:
        ok, chain["message"] = False, "the chain doesn't end at the fingerprint the file says it does"
    return {"ok": ok, "chain": chain, "events": evs, "rules": rules}


def report(result: dict) -> str:
    if "chain" not in result:
        return "✗ " + result["message"]
    c, e, r = result["chain"], result["events"], result["rules"]
    lines = [("✓ " if c["ok"] else "✗ ") + f"Audit trail: {c['entries']} entries, {c['message']}."]
    if c["ok"]:
        lines.append(f"  Fingerprint: {c['head_hash']}")
    lines.append(("✓ " if not e["changed"] else "✗ ") + f"Actions: {e['checked']} checked against their fingerprints"
                 + ("." if not e["changed"] else f", {len(e['changed'])} changed after the fact: "
                    + ", ".join(f"{x['event']} ({x['field']})" for x in e["changed"][:10])))
    lines.append(("✓ " if not r["missing"] and not r["mismatched"] else "✗ ")
                 + f"Rules: decisions were made by {len(r['versions'])} version(s) of rules.yaml"
                 + (f"; missing from the file: {', '.join(r['missing'])}" if r["missing"] else "")
                 + (f"; text doesn't match its fingerprint: {', '.join(r['mismatched'])}" if r["mismatched"] else "") + ".")
    lines.append("RESULT: " + ("everything checks out." if result["ok"] else "this evidence has been tampered with."))
    return "\n".join(lines)


def json_report(result: dict) -> dict:
    """The same verdict as report(), as one object a script can read (records = audit entries checked)."""
    if "chain" not in result:
        return {"ok": False, "records": 0, "problems": [{"record": None, "problem": result["message"]}]}
    c, e, r = result["chain"], result["events"], result["rules"]
    problems = []
    if not c["ok"]:
        problems.append({"record": c["first_bad_seq"], "problem": c["message"]})
    for x in e["changed"]:
        problems.append({"record": x["event"], "problem": f"its {x['field']} was changed after the fact"})
    for fp in r["missing"]:
        problems.append({"record": fp, "problem": "the rules version that made a decision is missing from the file"})
    for fp in r["mismatched"]:
        problems.append({"record": fp, "problem": "the rules text doesn't match its fingerprint"})
    return {"ok": result["ok"], "records": c["entries"], "problems": problems}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # the check marks, on Windows consoles too
    except (AttributeError, ValueError):
        pass
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 1:
        print(__doc__.strip())
        return 2
    try:
        with open(argv[0], encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        message = f"can't read {argv[0]}: {e}"
        if as_json:
            print(json.dumps({"ok": False, "records": 0, "problems": [{"record": None, "problem": message}]}))
        else:
            print("✗ " + message)
        return 2
    result = verify(data)
    print(json.dumps(json_report(result)) if as_json else report(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
