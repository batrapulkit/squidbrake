"""
What an action puts where other people can read it: a pull request, an issue or comment, a gist, a chat post, a page.

Two checks (rules.yaml `data_checks:`), both only on those places:
  customer_names  the text names a customer on the team's list (dashboard, Settings → Customers). Agents copy what
                  they read: a ticket's customer ends up in a PR description or a public issue.
  personal_data   the text carries a card number, a US social security number, an IBAN, or a list of people
                  (3 or more email addresses or phone numbers).

It reads text only. It never stores or repeats what it found beyond the customer's name (people on the team already
know their customers); personal data is reported by kind, not value.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

# tools whose text others read; shell commands are checked by what they run (gh / glab below)
DEFAULT_WHERE = ["*pull_request*", "*create_pull*", "*update_pull*", "*pr_create*", "*issue*", "*comment*", "*gist*",
                 "*discussion*", "*review*", "*post_message*", "*chat*post*", "*send_message*", "*publish*",
                 "*create_page*", "*update_page*", "*wiki*", "*tweet*", "*release*", "*push_files*",
                 "*create_or_update_file*"]
SHELL_WHERE = re.compile(r"\b(gh|glab)\s+(pr|issue|gist|release|discussion)\s+(create|comment|edit|review|new)\b"
                         r"|\bgh\s+api\b.*\b(-f|--field|-F|--raw-field|--input)\b", re.I)

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<![\w+])\+?\d[\d ().-]{8,}\d(?!\w)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d) * (2 if alt else 1)
        total += n - 9 if n > 9 else n
        alt = not alt
    return total % 10 == 0


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    n = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(n) % 97 == 1


def text_of(input: Any) -> str:
    """Every string in the call's input, as one text."""
    out: list[str] = []

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            out.append(v)
    walk(input if not isinstance(input, str) else [input])
    return "\n".join(out)


@lru_cache(maxsize=8)
def _names_re(names: tuple[str, ...]) -> re.Pattern | None:
    terms = sorted({n.strip() for n in names if len(n.strip()) >= 3}, key=len, reverse=True)
    if not terms:
        return None
    return re.compile(r"(?<![\w@.-])(" + "|".join(re.escape(t) for t in terms) + r")(?![\w-])", re.I)


def customers_named(text: str, names: list[str]) -> list[str]:
    """Customers on the list that the text names (as written on the list), in order of first mention."""
    rx = _names_re(tuple(names))
    if rx is None:
        return []
    by_lower = {n.strip().lower(): n.strip() for n in names}
    seen: list[str] = []
    for m in rx.finditer(text):
        name = by_lower.get(m.group(1).lower(), m.group(1))
        if name not in seen:
            seen.append(name)
    return seen


def personal_data(text: str, own_domains: list[str] | None = None) -> list[str]:
    """What kinds of personal data the text carries, e.g. ["a card number", "4 email addresses"]."""
    found = []
    if any(_luhn(re.sub(r"\D", "", m.group(0))) for m in CARD.finditer(text) if 13 <= len(re.sub(r"\D", "", m.group(0))) <= 19):
        found.append("a card number")
    if SSN.search(text):
        found.append("a social security number")
    if any(_iban_ok(m.group(0)) for m in IBAN.finditer(text)):
        found.append("a bank account number (IBAN)")
    own = tuple(d.lower().lstrip("@") for d in own_domains or [])
    emails = {e.lower() for e in EMAIL.findall(text) if not e.lower().split("@")[1].endswith(own or ("\0",))}
    if len(emails) >= 3:
        found.append(f"{len(emails)} email addresses")
    phones = {re.sub(r"\D", "", p) for p in PHONE.findall(text) if 10 <= len(re.sub(r"\D", "", p)) <= 15}
    if len(phones) >= 3:
        found.append(f"{len(phones)} phone numbers")
    return found


READS = re.compile(r"(?:^|[._-])(get|list|search|read|fetch|view|find|describe|show|lookup|count)(?:[._-]|$)")


def is_shared_place(name: str, command: str | None, where: list[str]) -> bool:
    """Does this action put text where other people read it? (Looking things up, like list_issues, doesn't.)"""
    import fnmatch
    if command is not None:
        return bool(SHELL_WHERE.search(command))
    tool = (name or "").lower().rsplit(".", 1)[-1]
    if READS.search(tool):
        return False
    return any(fnmatch.fnmatchcase((name or "").lower(), g.lower()) for g in where)
