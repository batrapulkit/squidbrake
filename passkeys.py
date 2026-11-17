"""
Approvals signed by a device: a person registers their phone or laptop as a passkey (Face ID, Touch ID, fingerprint,
Windows Hello), and each approval they make with it carries the device's signature over exactly what they approved.

The statement signed is   squidbrake-approval/1|<event id>|<approve or reject>|<unix time>
and the WebAuthn challenge is its SHA-256, so the signature in the audit trail proves which device approved which
action, and verify.py can check it offline with the device's public key (in the evidence export).

WebAuthn (https://www.w3.org/TR/webauthn-3/), ES256 (P-256) keys only, attestation "none": the device is trusted
because a signed-in person registered it, not because of who made it. Standard library + signing.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time
from urllib.parse import urlparse

import signing

STATEMENT_FORMAT = "squidbrake-approval/1"
CHALLENGE_SECONDS = 300
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


class PasskeyError(ValueError):
    pass


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (ValueError, TypeError):
        raise PasskeyError("not base64url")


# --------------------------------------------------------------------------- CBOR (just enough for WebAuthn)

def _cbor(data: bytes, i: int = 0):
    ib = data[i]
    major, info = ib >> 5, ib & 31
    i += 1
    if info < 24:
        val = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        val = int.from_bytes(data[i:i + n], "big")
        i += n
    else:
        raise PasskeyError("unsupported CBOR")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major in (2, 3):
        chunk = data[i:i + val]
        return (chunk if major == 2 else chunk.decode()), i + val
    if major == 4:
        out = []
        for _ in range(val):
            item, i = _cbor(data, i)
            out.append(item)
        return out, i
    if major == 5:
        out = {}
        for _ in range(val):
            k, i = _cbor(data, i)
            v, i = _cbor(data, i)
            out[k] = v
        return out, i
    if major == 7 and info in (20, 21):
        return info == 21, i
    raise PasskeyError("unsupported CBOR")


def cbor_decode(data: bytes):
    return _cbor(data)[0]


# --------------------------------------------------------------------------- challenges

def statement(event_id: str, outcome: str, at: int | None = None) -> str:
    return f"{STATEMENT_FORMAT}|{event_id}|{outcome}|{int(at or time.time())}"


def challenge_of(text: str) -> str:
    return b64u(hashlib.sha256(text.encode()).digest())


def registration_challenge(secret: bytes, person: str) -> str:
    ts = struct.pack(">Q", int(time.time()))
    mac = hmac.new(secret, b"register|" + person.encode() + b"|" + ts, hashlib.sha256).digest()[:24]
    return b64u(ts + mac)


def check_registration_challenge(secret: bytes, person: str, challenge: str) -> None:
    raw = unb64u(challenge)
    if len(raw) != 32:
        raise PasskeyError("bad challenge")
    ts, mac = raw[:8], raw[8:]
    good = hmac.new(secret, b"register|" + person.encode() + b"|" + ts, hashlib.sha256).digest()[:24]
    if not hmac.compare_digest(mac, good):
        raise PasskeyError("this registration wasn't started here, or by someone else")
    if time.time() - struct.unpack(">Q", ts)[0] > CHALLENGE_SECONDS:
        raise PasskeyError("the registration took too long; start again")


def rp_id_for(public_url: str | None, request_host: str) -> str:
    """The passkey's site: the public address's host if set, else the host the page was opened on."""
    host = urlparse(public_url).hostname if public_url else None
    return (host or request_host.split(":")[0]).lower()


def _check_client_data(raw: bytes, kind: str, challenge: str, rp_id: str) -> dict:
    try:
        cd = json.loads(raw)
    except ValueError:
        raise PasskeyError("client data isn't JSON")
    if cd.get("type") != kind:
        raise PasskeyError(f"expected {kind}")
    if cd.get("challenge") != challenge:
        raise PasskeyError("the signature is for a different request")
    origin = urlparse(str(cd.get("origin") or ""))
    if (origin.hostname or "").lower() != rp_id or (origin.scheme != "https" and origin.hostname not in ("localhost", "127.0.0.1")):
        raise PasskeyError(f"signed on {cd.get('origin')}, not on this gateway ({rp_id})")
    return cd


def _check_auth_data(auth: bytes, rp_id: str) -> tuple[int, int]:
    if len(auth) < 37:
        raise PasskeyError("authenticator data is too short")
    if not hmac.compare_digest(auth[:32], hashlib.sha256(rp_id.encode()).digest()):
        raise PasskeyError("the passkey belongs to another site")
    flags = auth[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise PasskeyError("the device didn't verify the person (Face ID, fingerprint or PIN)")
    return flags, struct.unpack(">I", auth[33:37])[0]


# --------------------------------------------------------------------------- register a device

def register(*, credential_id: str, client_data_json: str, attestation_object: str, challenge: str, rp_id: str) -> dict:
    """-> {"credential_id", "public_key": {"x", "y"}, "sign_count"} for a new ES256 passkey."""
    _check_client_data(unb64u(client_data_json), "webauthn.create", challenge, rp_id)
    att = cbor_decode(unb64u(attestation_object))
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise PasskeyError("not a WebAuthn attestation")
    auth = att["authData"]
    flags, count = _check_auth_data(auth, rp_id)
    if not flags & FLAG_AT:
        raise PasskeyError("no credential in the attestation")
    n = struct.unpack(">H", auth[53:55])[0]
    cred_id = auth[55:55 + n]
    if b64u(cred_id) != credential_id.rstrip("="):
        raise PasskeyError("credential id doesn't match")
    key = cbor_decode(auth[55 + n:])
    if not isinstance(key, dict) or key.get(1) != 2 or key.get(3) != -7 or key.get(-1) != 1:
        raise PasskeyError("only P-256 (ES256) passkeys are supported")
    x, y = int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big")
    if not signing._on_curve(x, y):
        raise PasskeyError("the public key isn't on the curve")
    return {"credential_id": b64u(cred_id), "public_key": {"x": f"{x:064x}", "y": f"{y:064x}"}, "sign_count": count}


# --------------------------------------------------------------------------- check an approval

def verify_assertion(*, proof: dict, public_key: dict, rp_id: str, event_id: str, outcome: str,
                     max_age: int = CHALLENGE_SECONDS) -> int:
    """The device's signature over this approval. -> the authenticator's sign count. Raises PasskeyError."""
    text = str(proof.get("statement") or "")
    parts = text.split("|")
    if len(parts) != 4 or parts[0] != STATEMENT_FORMAT or parts[1] != event_id or parts[2] != outcome:
        raise PasskeyError("the signature is for a different decision")
    if not parts[3].isdigit() or abs(time.time() - int(parts[3])) > max_age:
        raise PasskeyError("the signature is too old; try again")
    challenge = challenge_of(text)
    if proof.get("challenge") not in (None, challenge):
        raise PasskeyError("challenge doesn't match the statement")
    client = unb64u(str(proof.get("client_data_json") or ""))
    auth = unb64u(str(proof.get("authenticator_data") or ""))
    _check_client_data(client, "webauthn.get", challenge, rp_id)
    _, count = _check_auth_data(auth, rp_id)
    if not signing.p256_verify(int(public_key["x"], 16), int(public_key["y"], 16),
                               auth + hashlib.sha256(client).digest(), unb64u(str(proof.get("signature") or ""))):
        raise PasskeyError("the device signature doesn't check")
    return count
