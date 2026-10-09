"""
Where is this action sending things, and where did that address come from?

Prompt-injection attacks that actually happened (GitHub MCP, Supabase MCP, EchoLeak, tool poisoning) share one shape:
the agent reads content someone else wrote (a web page, an email, an issue, a ticket), that content says "send X to
<attacker>", and the agent does. No model is needed to catch the core of it: if an action sends data to a destination
(an email address, a URL, a bank account, a repo) that appears in untrusted content, and NOT in what the user asked or
in the company's own systems, the destination came from the untrusted content.

This module is pure (no database): it finds destinations in an action's input and checks where a value appears.
server.py decides what counts as untrusted, loads the texts, and applies the effects from rules.yaml.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

# Keys whose values say WHERE something goes.
DEST_KEYS = {
    "to", "cc", "bcc", "recipient", "recipients", "email", "emails", "address", "reply_to", "forward_to",
    "url", "uri", "endpoint", "webhook", "webhook_url", "callback", "callback_url", "host", "domain", "target_url",
    "to_account", "account", "account_number", "iban", "destination", "payee", "beneficiary",
    "channel", "repo", "repository", "owner", "remote",
}
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.I)
SCP_RE = re.compile(r"\b[\w.-]+@([\w.-]+\.[A-Za-z]{2,}):([\w./~-]*)")    # scp / rsync / git over ssh: user@host:path
# Images load by themselves when text is rendered (an email, a PR, a chat message), so a URL in one sends whatever is in
# its query string, with nobody clicking (EchoLeak). Markdown ![](url), reference-style ![x][r] + [r]: url, and <img src>.
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^\s)>]+)|<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\s\"'>]+)", re.I)
IMAGE_REF_RE = re.compile(r"^\s*\[[^\]]+\]:\s*<?(https?://[^\s>]+)", re.M)
# Hosts everyone uses: github.com alone says nothing about who gets the data, github.com/attacker/leaks does.
# Value = how many path segments name the owner (github.com/<owner>/<repo>, docs.google.com/document/d/<id>).
SHARED_HOSTS = {"github.com": 2, "gist.github.com": 2, "gitlab.com": 2, "bitbucket.org": 2, "huggingface.co": 2,
                "docs.google.com": 3, "drive.google.com": 3}
# Shell commands that send data somewhere.
UPLOAD_RE = re.compile(r"\b(curl|wget|http|https|xh|nc|ncat|netcat|scp|rsync|sftp|ftp|invoke-webrequest|iwr|"
                       r"invoke-restmethod|irm|git\s+push|gh\s+(gist|issue|pr|api|release))\b", re.I)
CURL_SEND_RE = re.compile(r"(^|\s)(-d|--data\S*|-F|--form|-T|--upload-file|-X\s*(POST|PUT|PATCH)|--json|"
                          r"--post-data|--post-file|--body-file|-Method\s+(Post|Put))(\s|=|$)", re.I)
# The same from inside a one-line script: python -c "requests.post(...)", node -e "fetch(u, {method: 'POST'})".
SCRIPT_SEND_RE = re.compile(r"\b(requests|httpx|axios|session|client)\.(post|put|patch)\s*\(|"
                            r"\bfetch\s*\([^;]*?\bmethod\s*:\s*[\"'](post|put|patch)[\"']|"
                            r"\burllib\.request\b[^;]*\bdata\s*=", re.I)
# gh subcommands that put something on GitHub (gh gist create .env makes a secret public); gh issue view, gh pr list read.
GH_SEND_RE = re.compile(r"\bgh\s+(gist\s+(create|new|edit)|(issue|pr)\s+(create|new|comment|edit|review)|"
                        r"release\s+(create|upload|edit)|"
                        r"api\b[^|;&]*\s(-f|-F|--field|--raw-field|--input|-X\s*(POST|PUT|PATCH)|--method\s+(POST|PUT|PATCH))\b)",
                        re.I)


def _host_value(host: str, path: str = "") -> str | None:
    """What identifies the receiver: the host, or for a shared host the owner part of the path (None if there's none)."""
    host = host.lower().removeprefix("www.")
    if host not in SHARED_HOSTS:
        return host
    parts = [p for p in re.split(r"[/:]", path.lower()) if p][:SHARED_HOSTS[host]]
    if len(parts) < SHARED_HOSTS[host]:
        return None
    parts[-1] = parts[-1].removesuffix(".git")
    return "/".join([host] + parts)


def _url_value(url: str) -> str | None:
    try:
        u = urlsplit(url)
        return _host_value(u.hostname, u.path) if u.hostname else None
    except ValueError:
        return None


def _walk(value: Any, key: str = "") -> list[tuple[str, str]]:
    out = []
    if isinstance(value, dict):
        for k, v in value.items():
            out += _walk(v, str(k).lower())
    elif isinstance(value, list):
        for v in value:
            out += _walk(v, key)
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        out.append((key, str(value)))
    return out


def destinations(input: Any, command: str | None = None) -> list[dict]:
    """[{field, value, kind}] for where this action sends things. kind: email | host | account | name."""
    found: list[dict] = []
    seen = set()

    def add(field: str, value: str, kind: str) -> None:
        v = value.strip().strip(".,;").lower() if kind in ("email", "host") else re.sub(r"\s+", "", value.strip())
        if len(v) >= 3 and (kind, v) not in seen:
            seen.add((kind, v))
            found.append({"field": field, "value": v, "kind": kind})

    for key, text in _walk(input):
        if not text.strip():
            continue
        # Any field, not only the ones above: an image in a body or message is fetched when it's shown.
        images = [a or b for a, b in IMAGE_RE.findall(text)] + (IMAGE_REF_RE.findall(text) if "![" in text else [])
        for u in images:
            if v := _url_value(u):
                add(key, v, "host")
        if key not in DEST_KEYS:
            continue
        emails, urls = EMAIL_RE.findall(text), URL_RE.findall(text)
        for e in emails:
            add(key, e, "email")
        for u in urls:
            if v := _url_value(u):
                add(key, v, "host")
        if not emails and not urls:
            if key in ("to_account", "account", "account_number", "iban", "payee", "beneficiary", "destination"):
                add(key, text, "account")
            elif key in ("host", "domain"):
                if v := _host_value(text.strip()):
                    add(key, v, "host")
            elif key in ("repo", "repository", "channel", "owner", "remote") and len(text) <= 100:
                add(key, text, "name")
    if sends_out(command):
        for u in URL_RE.findall(command):
            if v := _url_value(u):
                add("command", v, "host")
        for host, path in SCP_RE.findall(command):
            if v := _host_value(host, path):
                add("command", v, "host")
        for e in EMAIL_RE.findall(command):
            if not SCP_RE.search(command):
                add("command", e, "email")
    return found


def sends_out(command: str | None) -> bool:
    """Does this shell command send data somewhere (not just download)?"""
    return bool(command and ((UPLOAD_RE.search(command) and (CURL_SEND_RE.search(command) or re.search(
        r"\b(scp|rsync|sftp|nc|ncat|netcat|git\s+push)\b", command, re.I)))
                             or SCRIPT_SEND_RE.search(command) or GH_SEND_RE.search(command)))


def appears_in(dest: dict, text: str) -> bool:
    """Does this destination appear in a piece of text? Hosts also match as part of URLs and email domains."""
    if not text:
        return False
    low = text.lower()
    v = dest["value"]
    if dest["kind"] == "account":
        return v.lower() in re.sub(r"\s+", "", low)
    if dest["kind"] == "host":       # github.com/owner/repo also matches git@github.com:owner/repo
        pat = re.escape(v).replace("/", "[/:]", 1) if "/" in v else re.escape(v)
        return re.search(rf"(?<![\w.-]){pat}(?![\w-])", low) is not None
    return v in low


def own_domain(dest: dict, company_domains: list[str]) -> bool:
    host = dest["value"].split("@")[-1] if dest["kind"] in ("email", "host") else ""
    return bool(host) and any(host == d or host.endswith("." + d) for d in company_domains)
