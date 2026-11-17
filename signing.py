"""
Signatures Squidbrake makes and checks, in plain Python (standard library only, so verify.py runs anywhere).

  Ed25519 (RFC 8032)   signs audit checkpoints: every CHECKPOINT_EVERY entries the gateway signs the chain's
                       fingerprint at that point with its ledger key, whose public half it publishes. Anyone holding an
                       export can then prove nobody edited the history, without trusting the server or its database.
  ECDSA P-256          checks the signature a phone's passkey (Face ID, fingerprint) puts on an approval (WebAuthn).

The maths follows the RFC 8032 reference code and SEC 1; it's slow next to a C library (a few milliseconds a
signature), which is fine for one checkpoint per 50 entries and one approval at a time. When the `cryptography`
package is installed (it comes with the `mcp` dependency) the gateway uses it instead for speed; both give the same
bytes.
"""
from __future__ import annotations

import hashlib
import os

CHECKPOINT_EVERY = 50
CHECKPOINT_FORMAT = "squidbrake-checkpoint/1"


def checkpoint_message(seq: int, head_hash: str) -> bytes:
    """What a checkpoint signature covers: the chain's fingerprint as of entry `seq`."""
    return f"{CHECKPOINT_FORMAT}|{seq}|{head_hash}".encode()


# --------------------------------------------------------------------------- Ed25519 (RFC 8032, section 6)

_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _sha512_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % _p, (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C, D = 2 * P[3] * Q[3] * _d % _p, 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return E * F % _p, G * H % _p, F * G % _p, E * H % _p


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _p:
        return None
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _I % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * pow(5, _p - 2, _p) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P) -> bytes:
    zinv = pow(P[2], _p - 2, _p)
    x, y = P[0] * zinv % _p, P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _expand(secret: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _pure_public_key(secret: bytes) -> bytes:
    return _compress(_mul(_expand(secret)[0], _G))


def _pure_sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = _sha512_int(prefix, msg) % _L
    R = _compress(_mul(r, _G))
    h = _sha512_int(R, A, msg) % _L
    return R + int.to_bytes((r + h * a) % _L, 32, "little")


def _pure_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(public), _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = _sha512_int(sig[:32], public, msg) % _L
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


try:  # the same signatures, faster
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization as _ser

    def ed25519_public_key(secret: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
            _ser.Encoding.Raw, _ser.PublicFormat.Raw)

    def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(secret).sign(msg)

    def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
except Exception:  # pragma: no cover - standard library only
    ed25519_public_key, ed25519_sign, ed25519_verify = _pure_public_key, _pure_sign, _pure_verify


def new_secret() -> bytes:
    return os.urandom(32)


# --------------------------------------------------------------------------- ECDSA P-256 (verify only), for passkeys

_P256_p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_a = _P256_p - 3
_P256_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _ec_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % _P256_p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + _P256_a) * pow(2 * P[1], -1, _P256_p) % _P256_p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, _P256_p) % _P256_p
    x = (lam * lam - P[0] - Q[0]) % _P256_p
    return x, (lam * (P[0] - x) - P[1]) % _P256_p


def _ec_mul(k: int, P):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P)
        P = _ec_add(P, P)
        k >>= 1
    return R


def _on_curve(x: int, y: int) -> bool:
    return 0 <= x < _P256_p and 0 <= y < _P256_p and (y * y - x * x * x - _P256_a * x - _P256_b) % _P256_p == 0


def der_signature(sig: bytes) -> tuple[int, int] | None:
    """r and s from an ASN.1 DER ECDSA signature (what WebAuthn authenticators return)."""
    try:
        if sig[0] != 0x30:
            return None
        i = 2
        out = []
        for _ in range(2):
            if sig[i] != 0x02:
                return None
            n = sig[i + 1]
            out.append(int.from_bytes(sig[i + 2:i + 2 + n], "big"))
            i += 2 + n
        return out[0], out[1]
    except IndexError:
        return None


def p256_verify(x: int, y: int, msg: bytes, der_sig: bytes) -> bool:
    """ECDSA with SHA-256 over `msg`, public key (x, y), signature in DER."""
    rs = der_signature(der_sig)
    if rs is None or not _on_curve(x, y):
        return False
    r, s = rs
    if not (1 <= r < _P256_n and 1 <= s < _P256_n):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _P256_n)
    point = _ec_add(_ec_mul(e * w % _P256_n, _P256_G), _ec_mul(r * w % _P256_n, (x, y)))
    return point is not None and point[0] % _P256_n == r
