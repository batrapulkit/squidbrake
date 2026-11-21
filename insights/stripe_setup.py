"""
Stripe products, monthly prices and Payment Links for the paid plans (plans.py), once.

  python insights/stripe_setup.py            # what it would create; nothing is sent
  STRIPE_SECRET_KEY=sk_live_... python insights/stripe_setup.py --create

It prints INSIGHTS_CHECKOUT_URLS for the insights server. Run it again any time: a plan that already has its price
(lookup key squidbrake_<tier>_monthly) and Payment Link (metadata tier=<tier>) is reused, not made twice.
After paying, the webhook (/v1/stripe/webhook) finds the pilot from client_reference_id, which the start page adds.
Yearly prices (2 months free) aren't made here: add them in the Stripe dashboard if you want them.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plans import TIERS  # noqa: E402

API = "https://api.stripe.com/v1/"


def call(key: str, method: str, path: str, data: dict | None = None) -> dict:
    body = urllib.parse.urlencode(data or {}).encode() if method == "POST" else None
    req = urllib.request.Request(API + path, data=body, method=method, headers={"Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def setup(key: str | None, create: bool, out=print) -> dict:
    links: dict[str, str] = {}
    have = {}
    if create:
        for pl in call(key, "GET", "payment_links?active=true&limit=100")["data"]:
            if pl.get("metadata", {}).get("tier") in TIERS:
                have[pl["metadata"]["tier"]] = pl["url"]
    for tier, (name, dollars, people, actions) in TIERS.items():
        lookup = f"squidbrake_{tier}_monthly"
        if not create:
            out(f"would create: Squidbrake {name}, ${dollars}/month ({lookup}), and its Payment Link")
            continue
        if tier in have:
            links[tier] = have[tier]
            out(f"{name}: already has a Payment Link")
            continue
        found = call(key, "GET", "prices?" + urllib.parse.urlencode({"lookup_keys[]": lookup, "active": "true"}))["data"]
        if found:
            price = found[0]["id"]
        else:
            product = call(key, "POST", "products", {"name": f"Squidbrake {name}", "metadata[tier]": tier,
                                                     "description": f"Up to {people} {'person' if people == 1 else 'people'}, "
                                                                    f"{actions:,} actions a month"})["id"]
            price = call(key, "POST", "prices", {"product": product, "unit_amount": dollars * 100, "currency": "usd",
                                                 "recurring[interval]": "month", "lookup_key": lookup,
                                                 "metadata[tier]": tier})["id"]
        links[tier] = call(key, "POST", "payment_links", {"line_items[0][price]": price, "line_items[0][quantity]": 1,
                                                           "metadata[tier]": tier})["url"]
        out(f"{name}: {links[tier]}")
    return links


def main(argv: list[str]) -> int:
    create = "--create" in argv
    key = os.getenv("STRIPE_SECRET_KEY", "")
    if create and not key.startswith(("sk_", "rk_")):
        print("set STRIPE_SECRET_KEY (sk_live_... or sk_test_...) to create them", file=sys.stderr)
        return 1
    links = setup(key, create)
    if create:
        print("\nOn the insights server, set:\nINSIGHTS_CHECKOUT_URLS=" + json.dumps(links, separators=(",", ":")))
    else:
        print("\nNothing was sent. Add --create (with STRIPE_SECRET_KEY set) to make them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
