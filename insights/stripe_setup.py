"""
Stripe products, monthly prices and Payment Links for the paid plans that don't have a link yet (app.py CHECKOUT_URLS:
Brake, Brake Pro, Fleet and Fleet Max already do). Today that's Crew, Crew Plus and Crew Max.

  python insights/stripe_setup.py            # what it would create; nothing is sent
  STRIPE_SECRET_KEY=sk_live_... python insights/stripe_setup.py --create

It prints INSIGHTS_CHECKOUT_URLS for the insights server (it adds to the built-in links, it doesn't replace them).
Run it again any time: a plan whose price (lookup key squidbrake_<plan>_monthly) or Payment Link (metadata plan=<plan>)
already exists is reused, not made twice. The webhook (/v1/stripe/webhook) learns who paid for which plan from
client_reference_id, which the start page adds to the link.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.stripe.com/v1/"


def plans() -> dict:
    """plan -> (name, $ a month) for the paid plans without a Payment Link, read from app.py without starting it."""
    import ast
    src = (Path(__file__).resolve().parent / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    val = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    names, prices = ast.literal_eval(val["PLAN_NAMES"]), ast.literal_eval(val["PLAN_PRICES"])
    linked = {part.partition("=")[0] for part in "".join(
        c.value for c in ast.walk(val["CHECKOUT_URLS"]) if isinstance(c, ast.Constant) and isinstance(c.value, str)
        and "buy.stripe.com" in c.value).split(",") if part}
    return {p: (names[p], prices[p]) for p in prices if p not in linked}


def call(key: str, method: str, path: str, data: dict | None = None) -> dict:
    body = urllib.parse.urlencode(data or {}).encode() if method == "POST" else None
    req = urllib.request.Request(API + path, data=body, method=method, headers={"Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def setup(key: str, create: bool, todo: dict, out=print) -> dict:
    links: dict[str, str] = {}
    have = {}
    if create:
        for pl in call(key, "GET", "payment_links?active=true&limit=100")["data"]:
            if pl.get("metadata", {}).get("plan") in todo:
                have[pl["metadata"]["plan"]] = pl["url"]
    for plan, (name, dollars) in todo.items():
        lookup = f"squidbrake_{plan}_monthly"
        if not create:
            out(f"would create: Squidbrake {name}, ${dollars}/month ({lookup}), and its Payment Link")
            continue
        if plan in have:
            links[plan] = have[plan]
            out(f"{name}: already has a Payment Link")
            continue
        found = call(key, "GET", "prices?" + urllib.parse.urlencode({"lookup_keys[]": lookup, "active": "true"}))["data"]
        if found:
            price = found[0]["id"]
        else:
            product = call(key, "POST", "products", {"name": f"Squidbrake {name}", "metadata[plan]": plan})["id"]
            price = call(key, "POST", "prices", {"product": product, "unit_amount": dollars * 100, "currency": "usd",
                                                 "recurring[interval]": "month", "lookup_key": lookup,
                                                 "metadata[plan]": plan})["id"]
        links[plan] = call(key, "POST", "payment_links", {"line_items[0][price]": price, "line_items[0][quantity]": 1,
                                                           "metadata[plan]": plan})["url"]
        out(f"{name}: {links[plan]}")
    return links


def main(argv: list[str]) -> int:
    create = "--create" in argv
    key = os.getenv("STRIPE_SECRET_KEY", "")
    todo = plans()
    if not todo:
        print("Every paid plan already has a Payment Link.")
        return 0
    if create and not key.startswith(("sk_", "rk_")):
        print("set STRIPE_SECRET_KEY (sk_live_... or sk_test_...) to create them", file=sys.stderr)
        return 1
    links = setup(key, create, todo)
    if create:
        print("\nOn the insights server, set:\nINSIGHTS_CHECKOUT_URLS=" + ",".join(f"{k}={v}" for k, v in links.items()))
    else:
        print("\nNothing was sent. Add --create (with STRIPE_SECRET_KEY set) to make them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
