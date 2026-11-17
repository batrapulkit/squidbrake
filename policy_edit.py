"""
Adding rules from the dashboard, safely: suggestions from what people keep approving, and starter packs per kind of
agent (support, finance, ops, back-office, crypto).

  suggestions()   calls held for a person, approved (or marked "legit") 5+ times in 30 days and never rejected, grouped by what they are
                  (a tool, or a shell command's program and subcommand): each comes with an `allow` rule to add.
                  Never suggested: money, an agent changing its own setup, or anything the command, history,
                  data or chain checks held (a rule can't and shouldn't open those).
  PACKS           rule blocks per kind of agent. A pack with "before" goes right before that rule, not after allow-reads.
  insert()        puts a block into rules.yaml right before the rule that held the call (so block rules above it
                  still win), keeps a backup, and puts the file back if the result doesn't load.
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

import yaml

import commands
import risk

NEVER = {"approve-agent-setup-changes", "approve-guard-rail-changes", "approve-money-out", "approve-refunds", "approve-outbound-email"}
CHECK_PREFIXES = ("command:", "taint:", "history:", "sequence:", "data:", "session-stop", "emergency-stop")
WORD = re.compile(r"^[a-z][\w:.@/-]*$")


def shape(tool: str, input: dict | None, shell_tools: list[str]) -> tuple[str, list[str]] | None:
    """What a call is, for grouping: ("tool", [name]) or ("shell", [program, subcommand...])."""
    import fnmatch
    if any(fnmatch.fnmatchcase(tool.lower(), g.lower()) for g in shell_tools):
        line = commands.command_of(input or {})
        reading = commands.read(line) if line else None
        if not reading or len(reading.commands) != 1 or reading.hidden:
            return None                          # pipelines and hidden code stay with a person
        words = []
        for w in reading.commands[0].words:
            if len(words) == 3 or not WORD.match(w.lower()):
                break
            words.append(w)
        return ("shell", words) if words else None
    return "tool", [tool]


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:48] or "rule"


def rule_for(kind: str, words: list[str], tool: str, count: int) -> tuple[str, str]:
    """(id, YAML block) for an allow rule matching this group."""
    rid = "allow-" + _slug(" ".join(words) if kind == "shell" else tool)
    reason = f"People approved this (or marked it legit) {count} times in 30 days; added from Squidbrake's suggestions"
    if kind == "shell":
        rx = '"command":\\s*"' + re.escape(" ".join(words)).replace("'", "''") + '(\\s|")'
        match = f"      name: [\"{tool}\"]\n      input_regex: '{rx}'"
    else:
        match = f"      name: [\"{tool}\"]"
    return rid, f"  - id: {rid}\n    action: allow\n    reason: {reason}\n    match:\n{match}\n"


def vote(r) -> str | None:
    """What people said about one held call: a "legit" / "right" verdict (feedback) wins over how it was decided,
    so a hold that timed out or was rejected by mistake still teaches. -> "approved", "rejected" or None."""
    fb = getattr(r, "feedback", None)
    if fb in ("legit", "right"):
        return "approved" if fb == "legit" else "rejected"
    who = getattr(r, "decided_by", "a person")
    if not who or who == "timeout":
        return None
    return "approved" if r.decision == "allow" else "rejected"


def suggestions(rows, shell_tools: list[str], min_count: int = 5) -> list[dict]:
    """rows: held calls (name, input, rule_id, decision, decided_by, feedback). -> suggested rules, most approved
    first. One rejection, or one "right" verdict, and that kind of call is never suggested."""
    import json
    groups: dict[tuple, dict] = {}
    for r in rows:
        v = vote(r)
        if v is None:
            continue
        try:
            inp = json.loads(r.input) if isinstance(r.input, str) else r.input
        except ValueError:
            inp = None
        s = shape(r.name, inp if isinstance(inp, dict) else None, shell_tools)
        if s is None:
            continue
        g = groups.setdefault((r.name, s[0], tuple(s[1])), {"approved": 0, "rejected": 0, "rules": {}})
        g[v] += 1
        g["rules"][r.rule_id or ""] = g["rules"].get(r.rule_id or "", 0) + 1
    out = []
    for (tool, kind, words), g in groups.items():
        rules = set(g["rules"])
        if g["rejected"] or g["approved"] < min_count or rules & NEVER or risk.MONEY.search(tool) \
                or any(r.startswith(CHECK_PREFIXES) for r in rules if r):
            continue
        held_by = max(g["rules"], key=g["rules"].get) or None
        rid, block = rule_for(kind, list(words), tool, g["approved"])
        out.append({"id": rid, "what": " ".join(words) if kind == "shell" else tool, "tool": tool, "kind": kind,
                    "approved": g["approved"], "held_by": held_by, "yaml": block})
    return sorted(out, key=lambda x: -x["approved"])


PACKS: dict[str, dict] = {
    "support": {"title": "Support agent", "about": "Refunds, customer records and exports through your helpdesk, CRM "
                "and payment tools. Small refunds run; account deletions never do.", "yaml": """\
  - id: support-never-delete-customers
    action: deny
    reason: Deleting a customer or their account is not something a support agent does
    match:
      name: ["*delete_customer*", "*delete_user*", "*delete_account*", "*customer*delete*"]

  - id: support-small-refunds
    action: allow
    reason: A small refund (50 or less, in your payment API's units; Stripe counts cents) runs on its own
    match:
      name: ["*refund*"]
      input: { amount: { gte: 0, lte: 50 } }

  - id: support-plan-and-billing-changes
    action: review
    reason: Changes what a customer pays or can use
    match:
      name: ["*plan*", "*subscription*", "*billing*", "*credit*", "*discount*", "*coupon*"]

  - id: support-customer-exports
    action: review
    reason: Takes customer data out in bulk
    match:
      name: ["*export*", "*bulk*", "*download*"]
"""},
    "finance": {"title": "Finance agent", "about": "Payments, payouts and invoices. Money out needs finance, and very "
                "large transfers are refused.", "yaml": """\
  - id: finance-very-large-transfers
    action: deny
    reason: Over 10,000 (in your payment API's units) is never sent by an agent
    match:
      name: ["*transfer*", "*wire*", "*payout*", "*send_payment*"]
      input: { amount: { gt: 10000 } }

  - id: finance-invoices-and-ledgers
    action: review
    reason: Changes an invoice, a ledger or the books
    approvers: ["role:finance", "role:admin"]
    match:
      name: ["*invoice*", "*ledger*", "*journal*", "*credit_note*", "*write_off*", "*void*"]

  - id: finance-payee-changes
    action: review
    reason: Adds or changes where money goes (a payee or bank account)
    approvers: ["role:finance", "role:admin"]
    match:
      name: ["*payee*", "*beneficiary*", "*bank_account*", "*recipient*", "*vendor*"]
"""},
    "ops": {"title": "Ops agent", "about": "Deploys, feature flags, customer versions and plans in production, through "
            "your own tools. Each change waits for a person; looking runs.", "yaml": """\
  - id: ops-feature-flags
    action: review
    reason: Turns a feature on or off for real customers
    match:
      name: ["*flag*", "*toggle*", "*rollout*", "*experiment*"]

  - id: ops-customer-versions
    action: review
    reason: Moves a customer to another version
    match:
      name: ["*pin_version*", "*pin_customer*", "*set_version*", "*rollback*", "*upgrade*", "*downgrade*"]

  - id: ops-scale-and-restart
    action: review
    reason: Scales, restarts or stops a running service
    match:
      name: ["*scale*", "*restart*", "*stop*", "*drain*", "*failover*"]
"""},
    "back-office": {"title": "Back-office agent", "about": "CRM, orders, marketing and data-warehouse tools. Records are "
                    "never deleted; order and bulk changes wait for a person and say why; exports and campaigns run, "
                    "and the team is told.", "yaml": """\
  - id: back-office-never-delete-records
    action: deny
    reason: Deleting contacts, accounts, deals or orders is never an agent's call
    match:
      name: ["*delete_contact*", "*delete_account*", "*delete_deal*", "*delete_company*", "*delete_order*", "*purge*"]

  - id: back-office-order-changes
    action: review
    justification: required
    reason: Changes, cancels or re-prices a customer's order
    match:
      name: ["*cancel_order*", "*update_order*", "*order*price*", "*reship*", "*return*", "*chargeback*"]

  - id: back-office-bulk-changes
    action: review
    justification: required
    reason: Changes many records at once
    match:
      name: ["*bulk*", "*batch*", "*mass_update*", "*merge_contacts*", "*import*"]

  - id: back-office-campaigns
    action: review
    reason: Sends to customers (an email, SMS or push campaign)
    match:
      name: ["*send_campaign*", "*schedule_campaign*", "*send_sms*", "*broadcast*", "*send_newsletter*"]

  - id: back-office-exports
    action: notify
    reason: Customer data leaves the system (an export or a report download)
    match:
      name: ["*export*", "*download*", "*extract*", "*unload*"]

  - id: back-office-warehouse-writes
    action: review
    reason: Writes to the data warehouse (tables other teams read)
    match:
      name: ["*warehouse*", "*bigquery*", "*snowflake*", "*redshift*", "*dbt*"]
      input_regex: '\\b(insert|update|delete|merge|create|drop|alter|truncate)\\b'
"""},
    "crypto": {"title": "Crypto and wallets", "about": "Wallet keys and on-chain payments, for agents working where "
               "wallet keys live. Reading a key, signing or sending a transaction waits for a person.",
               "before": "allow-reads",   # reading a wallet key is a read, so this has to come before allow-reads
               "yaml": """\
  - id: crypto-wallet-keys
    action: review
    reason: Reads a wallet's private key, keystore or seed phrase
    match:
      name: ["read*", "file*", "cat*", "grep*", "bash*", "shell*", "powershell*", "run_command*"]
      input_regex: '(?i)keystore[\\\\/]|\\.keystore\\b|UTC--\\d|wallet\\.(dat|json)\\b|mnemonic\\.(txt|json)\\b|seed[-_ ]?phrase|solana[\\\\/]+id\\.json\\b'

  - id: crypto-sign-and-send
    action: review
    reason: Signs or sends a crypto transaction from the terminal
    timeout_seconds: 900
    match:
      name: ["bash*", "shell*", "powershell*", "run_command*"]
      input_regex: '\\bcast\\s+(send|publish|mktx|wallet\\s+sign)\\b|\\bbitcoin-cli\\b[^"&;|]*\\s(send\\w*|sign\\w*|walletpassphrase|dumpprivkey|dumpwallet)\\b|\\bsolana\\s+(transfer|pay|withdraw-stake|delegate-stake)\\b|\\bspl-token\\s+(transfer|burn|close)\\b|\\bsui\\s+client\\s+(pay\\w*|transfer\\w*)\\b|\\baptos\\s+account\\s+transfer\\b|\\bnear\\s+(send|tokens)\\b|\\bforge\\s+script\\b[^"&;|]*\\s--broadcast\\b|\\bhardhat\\s+run\\b[^"&;|]*\\s--network\\s+mainnet\\b'

  - id: crypto-agent-tools
    action: review
    reason: Moves crypto through an agent tool (a signed transaction, swap, trade, withdrawal, bridge or stake)
    timeout_seconds: 900
    match:
      name: ["*send_transaction*", "*sign_transaction*", "*sign_message*", "*swap*", "*trade*", "*withdraw*",
             "*bridge*", "*stake*", "*deploy_token*"]
"""},
}


def _ids(text: str) -> set[str]:
    return set(re.findall(r"^\s*-\s*id:\s*([\w.-]+)\s*$", text, re.M))


def replace_all(rules_path: Path, text: str) -> Path:
    """Write `text` as the whole rules file (an earlier version put back), keeping a backup. Returns the backup."""
    rules_path = Path(rules_path)
    backup = rules_path.with_name(f"{rules_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(rules_path, backup)
    rules_path.write_bytes(text.encode("utf-8"))       # bytes: the text is exactly what was fingerprinted
    return backup


def set_mode(rules_path: Path, mode: str) -> Path:
    """Switch the top-level `mode:` (enforce | shadow) in the rules file, keeping its comment and a backup."""
    rules_path = Path(rules_path)
    text = rules_path.read_text(encoding="utf-8")
    new, n = re.subn(r"^mode:[ \t]*[\w\"']*", f"mode: {mode}", text, count=1, flags=re.M)
    if not n:     # no top-level mode yet: put it right before `rules:`
        new, n = re.subn(r"^rules:[ \t]*$", f"mode: {mode}\n\nrules:", text, count=1, flags=re.M)
    if not n:
        raise ValueError("couldn't find `mode:` or `rules:` in the rules file")
    backup = rules_path.with_name(f"{rules_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(rules_path, backup)
    rules_path.write_text(new, encoding="utf-8")
    return backup


def insert(rules_path: Path, block: str, before_id: str | None, loads) -> Path:
    """Add `block` (rule items, indented for `rules:`) to the rules file: right before rule `before_id` if given, else
    right after allow-reads (so reads still run, and block rules above stay first), else at the top of `rules:`.
    Returns the backup. `loads(path)` must return the loaded rule ids, or raise."""
    rules_path = Path(rules_path)
    text = rules_path.read_text(encoding="utf-8")
    yaml.safe_load(block if block.lstrip().startswith("rules:") else "rules:\n" + block)   # the block parses alone
    clash = _ids(block) & _ids(text)
    if clash:
        raise ValueError(f"already in your rules: {', '.join(sorted(clash))}")
    lines = text.splitlines(keepends=True)
    rule_at = lambda rid: next((i for i, l in enumerate(lines) if re.match(rf"^\s*-\s*id:\s*{re.escape(rid)}\s*$", l)), None)
    at = rule_at(before_id) if before_id else None
    if at is None and (reads := rule_at("allow-reads")) is not None:
        # the line where the rule after allow-reads starts (or where the rules list ends)
        at = next((i for i in range(reads + 1, len(lines))
                   if re.match(r"^\s*-\s*id:", lines[i]) or re.match(r"^\S", lines[i])), len(lines))
        while at > reads + 1 and lines[at - 1].lstrip().startswith("#"):    # keep a rule's comment with it
            at -= 1
    if at is None:
        top = next((i for i, l in enumerate(lines) if re.match(r"^rules:\s*$", l)), None)
        if top is None:
            raise ValueError("couldn't find `rules:` in the rules file")
        at = top + 1
    backup = rules_path.with_name(f"{rules_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(rules_path, backup)
    rules_path.write_text("".join(lines[:at]) + block.rstrip("\n") + "\n\n" + "".join(lines[at:]), encoding="utf-8")
    try:
        if not _ids(block) <= set(loads(rules_path)):
            raise ValueError("the rules didn't load with the new block")
    except Exception:
        shutil.copy2(backup, rules_path)            # put it back as it was
        raise
    return backup
