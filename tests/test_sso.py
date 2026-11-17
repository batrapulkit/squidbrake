"""Sign in to the dashboard with OpenID Connect: SSO says who you are, your person key says what you may do."""
import base64
import json
import sys
import time
import urllib.parse
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sso  # noqa: E402
from test_server import TMP, c, server  # noqa: E402,F401

ISSUER = "https://idp.example.com"
IDP = {}   # what the fake identity provider says: the email, and the nonce of the sign-in in progress


def id_token(**claims) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


@pytest.fixture()
def idp(c, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("SQUIDBRAKE_OIDC_CLIENT_ID", "sb-client")
    monkeypatch.setenv("SQUIDBRAKE_OIDC_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(sso, "_discovered", {ISSUER: {"authorization_endpoint": f"{ISSUER}/authorize",
                                                      "token_endpoint": f"{ISSUER}/token"}})
    ks = server.KeyStore(TMP / f"sso-{time.time_ns()}" / "keys.json")
    ks.ensure_initialized()
    ks.add("alice@acme.com", approver=True, kind="person")
    ks.add("bot@acme.com", kind="agent")
    monkeypatch.setattr(server, "keystore", ks)
    IDP.clear()
    IDP["who"] = {"email": "alice@acme.com"}

    def token(url, data, auth, **kw):
        assert auth == ("sb-client", "s3cret") and data["code"] == "good-code"
        return httpx.Response(200, json={"id_token": id_token(iss=ISSUER, aud="sb-client", exp=time.time() + 300,
                                                              nonce=IDP["nonce"], email_verified=True, **IDP["who"])},
                              request=httpx.Request("POST", url))
    monkeypatch.setattr(sso.httpx, "post", token)
    return ks


def sign_in(c):
    r = c.get("/sso/login", follow_redirects=False)
    assert r.status_code in (302, 307), r.text
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
    assert q["redirect_uri"].endswith("/sso/callback") and q["scope"] == "openid email"
    IDP["nonce"] = q["nonce"]
    return c.get("/sso/callback", params={"code": "good-code", "state": q["state"]}, follow_redirects=False), q


def test_sso_signs_a_person_into_the_dashboard_with_their_keys_rights(c, idp):
    assert c.get("/sso/status").json() == {"enabled": True}
    r, q = sign_in(c)
    assert r.status_code in (302, 307), r.text
    secret = r.headers["location"].split("#key=")[1]
    assert secret.startswith("sso_")
    assert c.get("/v1/events", headers={"X-Gateway-Key": secret}).status_code == 200
    # the same state can't be used twice
    assert c.get("/sso/callback", params={"code": "good-code", "state": q["state"]}).status_code == 403
    idp.remove("alice@acme.com")                                     # key removed: the session stops working
    assert c.get("/v1/events", headers={"X-Gateway-Key": secret}).status_code == 401


def test_sso_without_a_person_key_gets_nothing(c, idp):
    IDP["who"].update(email="mallory@acme.com")
    r, _ = sign_in(c)
    assert r.status_code == 403 and "add-key mallory@acme.com" in r.text
    IDP["who"].update(email="bot@acme.com")                             # an agent key's name isn't a way in either
    assert sign_in(c)[0].status_code == 403


def test_claims_are_checked():
    cfg = {"issuer": ISSUER, "client_id": "sb-client"}
    good = dict(iss=ISSUER, aud=["sb-client"], exp=time.time() + 60, nonce="n", email="A@acme.com")
    assert sso.check_claims(good, cfg, "n") == "a@acme.com"
    for bad in ({"iss": "https://evil.example"}, {"aud": "other"}, {"exp": time.time() - 1}, {"nonce": "x"},
                {"email_verified": False}, {"email": ""}):
        with pytest.raises(ValueError):
            sso.check_claims({**good, **bad}, cfg, "n")


def test_sso_off_by_default(c, monkeypatch):
    monkeypatch.delenv("SQUIDBRAKE_OIDC_ISSUER", raising=False)
    assert c.get("/sso/status").json() == {"enabled": False}
    assert c.get("/sso/login", follow_redirects=False).status_code == 404
    assert c.get("/v1/events", headers={"X-Gateway-Key": "sso_made-up"}).status_code == 401
