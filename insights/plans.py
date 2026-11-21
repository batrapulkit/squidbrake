"""The paid plans on squidbrake.com/pricing: tier -> (name, $ a month, people, actions a month). Enterprise has no tier.

Used by app.py (sign-up, licenses, the Stripe webhook, monthly usage) and stripe_setup.py. The gateway's license.py
PLANS has the same people and actions (tests/test_plan_tiers.py checks they match).
"""
TIERS = {"brake": ("Brake", 9, 1, 5_000), "brakepro": ("Brake Pro", 19, 1, 10_000),
         "crew": ("Crew", 49, 3, 25_000), "crewplus": ("Crew Plus", 99, 10, 100_000),
         "crewmax": ("Crew Max", 199, 25, 250_000),
         "fleet": ("Fleet", 299, 25, 250_000), "fleetmax": ("Fleet Max", 499, 50, 500_000)}
