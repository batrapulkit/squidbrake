"""
Check a Squidbrake evidence file on any machine, without trusting the server that produced it.

    python verify.py squidbrake-evidence-20261001.json [--json] [--key PUBLIC_KEY_HEX]

Download the file from the dashboard (Reports > Tamper check > Download evidence) or GET /v1/audit/export.json.
Only the Python standard library is needed (keep signing.py from the repository next to this file). It checks that:

  1. the audit trail is one unbroken hash chain from the first entry (nothing edited, removed or inserted);
  2. every recorded action's input and result still match the fingerprints taken when they happened;
  3. every decision names the version of the rules that made it, and that version's text is in the file;
  4. every signed checkpoint (one per 50 entries) is a valid signature, by the gateway's ledger key, over the chain
     exactly as it is in the file. Pass the key the gateway published (GET /v1/audit/public-key) with --key, so a
     file re-signed with some other key is caught too;
  5. every approval made with a passkey (Face ID, fingerprint) carries that device's valid signature.

Exit code 0 if everything checks out, 1 if anything doesn't.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import signing
except ImportError:  # pragma: no cover - verify.py copied on its own
    signing = None

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


def check_checkpoints(entries: list[dict], checkpoints: list[dict], public_key: str | None,
                      pinned: str | None = None) -> dict:
    """Each checkpoint: the entry it names has the fingerprint it signed, and the signature is the ledger key's."""
    out = {"ok": True, "count": len(checkpoints), "valid": 0, "last_seq": None, "key": public_key, "pinned": bool(pinned),
           "message": "no signed checkpoints yet" if not checkpoints else ""}
    if pinned and public_key and pinned.lower() != public_key.lower():
        out.update(ok=False, message="the file was signed with a different key than the one you gave with --key")
        return out
    key = pinned or public_key
    if checkpoints and (signing is None or not key):
        out.update(ok=False, message="can't check the signatures: " + (
            "signing.py isn't next to verify.py" if signing is None else "the file has no public key; pass --key"))
        return out
    hashes = {e.get("seq"): e["hash"] for e in entries}
    try:
        pub = bytes.fromhex(key) if key else b""
    except ValueError:
        out.update(ok=False, message="the public key isn't hex")
        return out
    for cp in checkpoints:
        seq = cp["seq"]
        if hashes.get(seq) != cp["head_hash"]:
            out.update(ok=False, message=f"checkpoint at entry #{seq} doesn't match the chain: the history was rewritten "
                                         "after it was signed")
            return out
        try:
            good = signing.ed25519_verify(pub, signing.checkpoint_message(seq, cp["head_hash"]),
                                          bytes.fromhex(cp["signature"]))
        except ValueError:
            good = False
        if not good:
            out.update(ok=False, message=f"checkpoint at entry #{seq} has a signature the ledger key didn't make")
            return out
        out["valid"] += 1
        out["last_seq"] = seq
    if checkpoints:
        out["message"] = f"{out['valid']} signed checkpoint(s) valid, the latest at entry #{out['last_seq']}"
    return out


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def check_device_approvals(entries: list[dict], devices: dict[str, dict]) -> dict:
    """Approvals made with a passkey: the device's signature over the approval challenge (WebAuthn assertion)."""
    checked, bad = 0, []
    for e in entries:
        if e["action"] not in ("event.approved", "event.approval_added", "event.rejected"):
            continue
        proof = json.loads(e["detail"] or "{}").get("device_proof")
        if not proof:
            continue
        checked += 1
        dev = devices.get(proof.get("credential_id"))
        ok = False
        if dev and signing is not None:
            try:
                auth = _b64d(proof["authenticator_data"])
                client = _b64d(proof["client_data_json"])
                cd = json.loads(client)
                key = json.loads(dev["public_key"]) if isinstance(dev["public_key"], str) else dev["public_key"]
                parts = str(proof.get("statement") or "").split("|")
                wanted = "reject" if e["action"] == "event.rejected" else "approve"
                bound = (len(parts) == 4 and parts[1] == e["target"] and parts[2] == wanted and proof.get("challenge")
                         == base64.urlsafe_b64encode(hashlib.sha256(proof["statement"].encode()).digest()).decode().rstrip("="))
                ok = (bound and cd.get("type") == "webauthn.get" and cd.get("challenge") == proof.get("challenge")
                      and signing.p256_verify(int(key["x"], 16), int(key["y"], 16),
                                              auth + hashlib.sha256(client).digest(), _b64d(proof["signature"])))
            except (KeyError, ValueError, TypeError):
                ok = False
        if not ok:
            bad.append(e.get("seq"))
    return {"checked": checked, "bad": bad}


def verify(data: dict, pinned_key: str | None = None) -> dict:
    if data.get("format") != FORMAT:
        return {"ok": False, "message": f"not a Squidbrake evidence file (format {data.get('format')!r})"}
    entries = data.get("entries") or []
    chain = check_chain(entries)
    events = {e["id"]: e for e in data.get("events") or []}
    evs = check_events(entries, events)
    rules = check_rules(entries, data.get("policies") or {})
    cps = check_checkpoints(entries, data.get("checkpoints") or [], (data.get("ledger_key") or {}).get("public_key"),
                            pinned_key)
    devs = check_device_approvals(entries, {d["credential_id"]: d for d in data.get("devices") or []})
    ok = chain["ok"] and not evs["changed"] and not rules["missing"] and not rules["mismatched"] and cps["ok"] \
        and not devs["bad"]
    if data.get("head_hash") and chain["ok"] and data["head_hash"] != chain["head_hash"]:
        ok, chain["message"] = False, "the chain doesn't end at the fingerprint the file says it does"
    return {"ok": ok, "chain": chain, "events": evs, "rules": rules, "checkpoints": cps, "devices": devs}


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
    cp = result.get("checkpoints") or {"ok": True, "count": 0, "message": "no signed checkpoints yet"}
    pin_note = ""
    if cp["ok"] and cp["count"]:
        pin_note = (" (key checked against the one you gave)" if cp.get("pinned") else
                    " (pass --key with the gateway's published key to rule out a re-signed file)")
    lines.append(("✓ " if cp["ok"] else "✗ ") + f"Signatures: {cp['message']}{pin_note}.")
    dv = result.get("devices") or {"checked": 0, "bad": []}
    if dv["checked"]:
        lines.append(("✓ " if not dv["bad"] else "✗ ") + f"Passkey approvals: {dv['checked']} checked"
                     + (f", {len(dv['bad'])} without a valid device signature (entries "
                        f"{', '.join(map(str, dv['bad'][:10]))})" if dv["bad"] else ", each signed by its device") + ".")
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
    cp = result.get("checkpoints") or {"ok": True}
    if not cp["ok"]:
        problems.append({"record": None, "problem": cp["message"]})
    for seq in (result.get("devices") or {}).get("bad", []):
        problems.append({"record": seq, "problem": "an approval says it was made with a passkey, but its signature "
                                                   "doesn't check"})
    return {"ok": result["ok"], "records": c["entries"], "problems": problems}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # the check marks, on Windows consoles too
    except (AttributeError, ValueError):
        pass
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    pinned = None
    if "--key" in argv:
        i = argv.index("--key")
        pinned = argv[i + 1] if i + 1 < len(argv) else ""
        argv = argv[:i] + argv[i + 2:]
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
    result = verify(data, pinned)
    print(json.dumps(json_report(result)) if as_json else report(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
