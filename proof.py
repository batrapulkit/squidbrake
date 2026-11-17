"""
Proof of work: when an agent says an action is done, look in the real system and check it actually happened.

  rules.yaml
    proof_checks:
      - id: refund-really-made
        match: { name: "*refund*" }
        stripe: { object: refunds, id: "{output.id}" }           # GET https://api.stripe.com/v1/refunds/<id>
        expect: { status: succeeded, amount: "{input.amount}" }
      - id: pr-really-open
        match: { name: "*create_pull_request*" }
        github: { path: "repos/{input.owner}/{input.repo}/pulls/{output.number}" }
        expect: { state: open }
      - id: order-really-updated
        match: { name: "orders.update_status" }
        sql: { url_env: ORDERS_DB_URL, query: "select status from orders where id = :id", params: { id: "{input.order_id}" } }
        expect: { status: "{input.status}" }
      - id: anything-with-an-api
        match: { name: "crm.update_plan" }
        http: { url: "https://crm.example.com/api/customers/{input.customer_id}", headers: { Authorization: "Bearer ${CRM_TOKEN}" } }
        expect: { plan: "{input.plan}" }

{input.x} and {output.y} take values from the action (dotted paths reach into nested objects). Credentials only ever
come from environment variables on the gateway (STRIPE_SECRET_KEY, GITHUB_TOKEN, ${NAME} in http headers, url_env for
SQL), never from rules.yaml. Every check is a read: a GET, or a SQL query that must start with SELECT.

The answer is recorded on the action: confirmed (found, and every expected field matches), mismatch (missing, or a field
differs: the agent's "done" isn't true), or error (the check itself couldn't run). It never changes the decision; a
mismatch tells a person.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from urllib.parse import quote

import httpx

KINDS = ("stripe", "github", "sql", "http")
TEMPLATE_RE = re.compile(r"\{(input|output)((?:\.[\w-]+)*)\}")
ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
TIMEOUT = 15


def _dig(value: Any, path: str) -> Any:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None if path else value
    for part in [p for p in path.split(".") if p]:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def fill(template: Any, input: Any, output: Any, in_url: bool = False) -> Any:
    """{input.x} / {output.y} filled in. A string that is only one placeholder keeps the value's type. In a URL each
    value is percent-encoded, so what the agent sent can't change the host or climb the path (../)."""
    if isinstance(template, dict):
        return {k: fill(v, input, output) for k, v in template.items()}
    if isinstance(template, list):
        return [fill(v, input, output) for v in template]
    if not isinstance(template, str):
        return template
    src = {"input": input, "output": output}
    whole = TEMPLATE_RE.fullmatch(template)
    if whole and not in_url:
        return _dig(src[whole.group(1)], whole.group(2))

    def one(m: re.Match) -> str:
        v = _dig(src[m.group(1)], m.group(2))
        if v is None:
            raise LookupError(f"{m.group(0)} isn't in the action")
        return quote(str(v), safe="") if in_url else str(v)
    return TEMPLATE_RE.sub(one, template)


def _env(text: str) -> str:
    def one(m: re.Match) -> str:
        if m.group(1) not in os.environ:
            raise LookupError(f"environment variable {m.group(1)} isn't set on the gateway")
        return os.environ[m.group(1)]
    return ENV_RE.sub(one, text)


def _get_json(url: str, headers: dict[str, str]) -> tuple[int, Any]:
    r = httpx.get(url, headers=headers, timeout=TIMEOUT, follow_redirects=False)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:2000]


def _required(spec: dict, key: str, input: Any, output: Any, in_url: bool = False) -> str:
    v = fill(spec.get(key), input, output, in_url)
    if v in (None, ""):
        raise LookupError(f"{key} ({spec.get(key)}) has no value in this action")
    return str(v)


def look(kind: str, spec: dict, input: Any, output: Any) -> tuple[str, Any, str]:
    """-> (where it looked, what it found or None if it isn't there, description)."""
    if kind == "stripe":
        obj = re.sub(r"[^a-z_]", "", str(spec.get("object") or "charges"))
        oid = re.sub(r"[^A-Za-z0-9_]", "", _required(spec, "id", input, output))
        key = os.getenv(str(spec.get("key_env") or "STRIPE_SECRET_KEY"), "")
        if not key:
            raise LookupError(f"{spec.get('key_env') or 'STRIPE_SECRET_KEY'} isn't set on the gateway")
        url = f"https://api.stripe.com/v1/{obj}/{oid}"
        status, body = _get_json(url, {"Authorization": f"Bearer {key}"})
        return url, body if status == 200 else None, f"Stripe {obj} {oid}"
    if kind == "github":
        path = _required(spec, "path", input, output, in_url=True).lstrip("/")
        base = str(spec.get("api") or "https://api.github.com").rstrip("/")
        token = os.getenv(str(spec.get("token_env") or "GITHUB_TOKEN"), "")
        headers = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
        url = f"{base}/{path}"
        status, body = _get_json(url, headers)
        return url, body if status == 200 else None, f"GitHub {path}"
    if kind == "http":
        url = _required(spec, "url", input, output, in_url=True)
        if not re.match(r"^https?://", url):
            raise LookupError("http.url must start with http:// or https://")
        headers = {str(k): _env(str(fill(v, input, output))) for k, v in (spec.get("headers") or {}).items()}
        status, body = _get_json(url, headers)
        return url, body if 200 <= status < 300 else None, f"GET {url}"
    if kind == "sql":
        from sqlalchemy import create_engine, text
        env = str(spec.get("url_env") or "")
        if not env or env not in os.environ:
            raise LookupError(f"sql.url_env ({env or 'not set'}) isn't an environment variable on the gateway")
        query = str(spec.get("query") or "")
        if not re.match(r"^\s*select\b", query, re.I) or ";" in query.strip().rstrip(";"):
            raise LookupError("sql.query must be a single SELECT")
        params = fill(spec.get("params") or {}, input, output)
        eng = create_engine(os.environ[env])
        try:
            with eng.connect() as conn:
                row = conn.execute(text(query), params).mappings().first()
        finally:
            eng.dispose()
        return f"{env}: {query[:120]}", dict(row) if row is not None else None, "the database"
    raise LookupError(f"unknown check {kind}")


def _same(found: Any, want: Any) -> bool:
    if isinstance(found, bool) or isinstance(want, bool):
        return str(found).lower() == str(want).lower()
    try:
        return float(found) == float(want)
    except (TypeError, ValueError):
        return str(found).strip().lower() == str(want).strip().lower()


def run(check: dict, input: Any, output: Any) -> dict:
    """One proof check for one action. Never raises."""
    try:
        where, found, what = look(check["kind"], check["spec"], input, output)
    except Exception as e:
        return {"status": "error", "check": check["id"], "message": f"Couldn't check: {e}"}
    if found is None:
        return {"status": "mismatch", "check": check["id"], "where": where,
                "message": f"The agent reported this done, but {what} wasn't found."}
    diffs, seen = [], {}
    for field, want in (check.get("expect") or {}).items():
        try:
            want = fill(want, input, output)
        except LookupError as e:
            return {"status": "error", "check": check["id"], "where": where, "message": f"Couldn't check: {e}"}
        got = _dig(found, str(field))
        seen[field] = got
        if not _same(got, want):
            diffs.append(f"{field} is {got!r}, expected {want!r}")
    if diffs:
        return {"status": "mismatch", "check": check["id"], "where": where, "found": seen,
                "message": f"The agent reported this done, but in {what}: {'; '.join(diffs)}."}
    return {"status": "confirmed", "check": check["id"], "where": where, "found": seen,
            "message": f"Confirmed in {what}" + (f": {', '.join(f'{k} = {v}' for k, v in seen.items())}." if seen else ".")}
