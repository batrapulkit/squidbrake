"""
Sign in to the dashboard with your company's identity provider (OpenID Connect: Okta, Entra ID, Google Workspace,
Auth0, Keycloak, ...).

SSO only says who someone is. What they may do still comes from their person key, the one named with their email
(`python server.py add-key alice@acme.com --approver`): nobody gets in by SSO alone, and removing the key locks them
out. Set SQUIDBRAKE_OIDC_ISSUER, SQUIDBRAKE_OIDC_CLIENT_ID and SQUIDBRAKE_OIDC_CLIENT_SECRET, and register
<PUBLIC_URL>/sso/callback as the redirect URI with the identity provider.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
import urllib.parse

import httpx


def config() -> dict | None:
    issuer = os.getenv("SQUIDBRAKE_OIDC_ISSUER", "").strip().rstrip("/")
    cid, secret = os.getenv("SQUIDBRAKE_OIDC_CLIENT_ID", "").strip(), os.getenv("SQUIDBRAKE_OIDC_CLIENT_SECRET", "")
    if not (issuer and cid and secret):
        return None
    if not issuer.startswith("https://"):
        raise ValueError("SQUIDBRAKE_OIDC_ISSUER must be an https:// URL")
    return {"issuer": issuer, "client_id": cid, "client_secret": secret}


_discovered: dict[str, dict] = {}


def discover(issuer: str) -> dict:
    if issuer not in _discovered:
        r = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
        r.raise_for_status()
        _discovered[issuer] = r.json()
    return _discovered[issuer]


# shortcut: sign-ins in progress live in this process; with several replicas use sticky sessions or move them to the DB
_pending: dict[str, tuple[str, float]] = {}       # state -> (nonce, expires)


def start(cfg: dict, redirect_uri: str) -> str:
    """-> the identity provider's sign-in URL to send the browser to."""
    now = time.time()
    for s in [s for s, (_, exp) in _pending.items() if exp < now]:
        _pending.pop(s, None)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    _pending[state] = (nonce, now + 600)
    q = urllib.parse.urlencode({"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": redirect_uri,
                                "scope": "openid email", "state": state, "nonce": nonce})
    return f"{discover(cfg['issuer'])['authorization_endpoint']}?{q}"


def finish(cfg: dict, redirect_uri: str, code: str, state: str) -> str:
    """The browser came back from the identity provider. -> the verified email of whoever signed in.
    ValueError with what went wrong otherwise."""
    nonce, exp = _pending.pop(state, (None, 0.0))
    if not nonce or exp < time.time():
        raise ValueError("this sign-in expired or was already used; start again")
    r = httpx.post(discover(cfg["issuer"])["token_endpoint"], timeout=15, auth=(cfg["client_id"], cfg["client_secret"]),
                   data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri})
    if r.status_code != 200:
        raise ValueError(f"the identity provider refused the sign-in ({r.status_code})")
    # The ID token came straight from the token endpoint over TLS, so its signature needn't be checked as well
    # (OpenID Connect Core 3.1.3.7); its claims still must.
    return check_claims(id_token_claims(r.json().get("id_token") or ""), cfg, nonce)


def id_token_claims(token: str) -> dict:
    try:
        body = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (IndexError, ValueError):
        raise ValueError("the identity provider sent no readable ID token")


def check_claims(claims: dict, cfg: dict, nonce: str) -> str:
    aud = claims.get("aud")
    if str(claims.get("iss", "")).rstrip("/") != cfg["issuer"]:
        raise ValueError("the ID token is from another issuer")
    if cfg["client_id"] not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("the ID token is for another app")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < time.time():
        raise ValueError("the ID token has expired")
    if claims.get("nonce") != nonce:
        raise ValueError("the ID token doesn't belong to this sign-in")
    email = str(claims.get("email") or "").strip().lower()
    if not email or claims.get("email_verified") is False:
        raise ValueError("the identity provider didn't give a verified email (ask for the 'email' scope)")
    return email
