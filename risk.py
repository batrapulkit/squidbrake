"""
A risk score for each action, 0 to 100, recorded next to the decision and never used to make it (shadow).

The rules decide; this only measures. Each action gets a score from what it is (a shell command's kind, money,
sending out, secrets, production), what came before it (the gateway's chain signals) and how big it is (what the hook
measured). Recorded on the event, so we can see, on real traffic, whether a score would hold the right things before
letting it decide anything. bench/chains/ reports how well it separates harmful steps from everyday work.
"""
from __future__ import annotations

import json
import re
from typing import Any

import commands

KIND = {"catastrophic": 80, "irreversible": 45, "hidden": 35}
# chain signals from the gateway (server.py): what came before this step
SIGNAL = {"untrusted_destination": 40, "after_untrusted": 25, "sequence": 30, "repeat_of_rejected": 25,
          "impersonation": 45, "payment_request_in_message": 35, "duplicate_change": 15,
          "customer_names": 35, "personal_data": 35}
MONEY = re.compile(r"(pay|transfer|refund|checkout|charge|invoice|purchase|payout|wire)", re.I)
SENDS = re.compile(r"(send|email|mail|post_message|create_pull_request|create_issue|comment|publish|upload|webhook|tweet)", re.I)
WRITES = re.compile(r"(write|edit|create|update|delete|remove|drop|insert|execute|exec|run|apply|deploy|merge|push)", re.I)
SECRETS = re.compile(r"(\.env\b|secret|token|credential|password|passwd|id_rsa|\.pem\b|\.aws/|api[_-]?key|private[_-]?key)", re.I)
PROD = re.compile(r"\b(prod|production|live|master|main)\b", re.I)
DESTRUCTIVE_SQL = re.compile(r"\b(drop|truncate|delete\s+from|alter\s+table)\b", re.I)
UNSCOPED_SQL = re.compile(r"\b(update\s+\S+\s+set|delete\s+from\s+\S+)\b(?![^;]*\bwhere\b)", re.I)
# an agent's own settings, hooks and MCP servers, and files that run code at login: the agent's own setup
GUARD_RAILS = re.compile(r"\.(claude|cursor|codex|gemini|copilot|kiro|windsurf|squidbrake)[\\/]|mcp(_config)?\.json|"
                         r"\.git[\\/]+hooks[\\/]|\.(bashrc|zshrc|bash_profile|zprofile|profile)\b", re.I)
SIZE = re.compile(r"(\d[\d,]*)\+?\s+(files?|rows?|commits?|resources?|objects?|Kubernetes objects?)\b", re.I)


def _text(value: Any) -> str:
    try:
        return value if isinstance(value, str) else json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def score(name: str, input: Any, signals: list[dict] | None = None, metadata: dict | None = None,
          shell: bool = False) -> tuple[int, list[str]]:
    """-> (0..100, the factors behind it, most telling first)."""
    found: list[tuple[int, str]] = []
    text = _text(input)
    line = commands.command_of(input) if shell else None
    reading = commands.read(line) if line else None
    if reading is not None:
        kind = reading.kind
        runs = (metadata or {}).get("runs")
        for item in runs[:20] if isinstance(runs, list) else []:   # what `make clean` / `npm run x` runs underneath
            for inner in (item.get("lines") or [])[:60] if isinstance(item, dict) else []:
                r = commands.read(str(inner))
                if commands.SEVERITY.index(r.kind) > commands.SEVERITY.index(kind):
                    kind = r.kind
        if kind in KIND:
            found.append((KIND[kind], f"{kind} command"))
        if kind == "read_only":
            found.append((-30, "only reads"))
    elif WRITES.search(name) and not MONEY.search(name):
        found.append((10, "changes something"))
    if MONEY.search(name):
        found.append((40, "moves money"))
    if SENDS.search(name) or (line and re.search(r"\b(curl|wget|scp|rsync|nc)\b.*(-d|--data|-T|-F|@|\s\S+:)", line)):
        found.append((15, "sends something out"))
    if DESTRUCTIVE_SQL.search(text) and reading is None:
        found.append((40, "destructive SQL"))
    elif UNSCOPED_SQL.search(text):
        found.append((40, "changes every row (no WHERE)"))
    if GUARD_RAILS.search(text) and (WRITES.search(name) or reading is not None):
        found.append((40, "changes an agent's own setup (settings, hooks, MCP servers)"))
    if SECRETS.search(text):
        found.append((20, "touches secrets"))
    if PROD.search(text) and any(p > 0 for p, _ in found):
        found.append((15, "production"))
    for s in signals or []:
        check = s.get("check", "")
        if check in SIGNAL:
            found.append((SIGNAL[check], check.replace("_", " ")))
    big = 0
    for line_ in ((metadata or {}).get("effects") or []):
        for n, _unit in SIZE.findall(str(line_)):
            big = max(big, int(n.replace(",", "")))
    if big >= 1000:
        found.append((15, f"large ({big:,})"))
    elif big >= 50:
        found.append((5, f"sized ({big:,})"))
    total = max(0, min(100, sum(p for p, _ in found)))
    return total, [w for p, w in sorted(found, key=lambda x: -x[0]) if p > 0]
