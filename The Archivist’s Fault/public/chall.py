#!/usr/bin/env python3
"""
Public handout for The Archivist's Fault.

Reference implementation of the slip protocol used by the live web
desk and TCP seal plate:

  - canonical-JSON encoding rule
  - EMSA-PKCS1-v1.5 SHA-256 representative under the published RSA
    modulus
  - KDF shapes for sealed records the player may encounter
  - shape of the maintenance-plate proof-of-work

Server-side material (private factors, cabinet secret, AES keys,
flag plaintexts) is intentionally absent. This file is for offline
inspection only; it does not connect to the challenge services.

Run `python3 public/chall.py` for a structured JSON dump of the
public reference constants.
"""

import base64
import hashlib
import json
from typing import Any


TITLE = "The Archivist's Fault"
ISSUED = 20260501

E = 65537
N = 898851249861783110574813152783081759704290488108934886121290121710982541281069451770406572933010871888283998756858870495988216640052320123162958111455116235674110259478735269188689042708328336363640854000710337523816553093522572077
K = 96

SLIP_DOMAIN = b"CBJS:archive-slip-v2\x00"
DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

RESTRICTED_SLIP = {
    "cabinet": -1,
    "issued": ISSUED,
    "nonce": "black-ledger",
    "scope": ["reading-room", "inner-vault", "seal-reissue"],
    "sub": "archivist:root",
    "typ": "archive-slip-v2",
}

VISITOR_EXAMPLE = {
    "cabinet": 0,
    "issued": ISSUED,
    "nonce": "server-issued",
    "scope": ["reading-room"],
    "sub": "visitor:guest",
    "typ": "archive-slip-v2",
}

CABINET_SIZE = 64
MAX_SEALS_PER_SESSION = 4
MAX_CABINET_TOUCHES = 28
POW_BITS_DEFAULT = 20

RELIC_AAD = b"relic-v2|catalogue:umbra|drawers:bar-48..bar-33"
BLACK_LEDGER_AAD = b"black-ledger-v1|margin:sable|sample-set:12x160"
BLACK_LEDGER_SHIFT = 160
BLACK_LEDGER_SAMPLES = 12

SEAL_PLATE_MENU = [
    "public folio",
    "stamp visitor slip",
    "mark cabinet drawer",
    "read cabinet drawer / maintenance plate",
    "quit",
]


def int_to_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def slip_signing_bytes(payload: bytes) -> bytes:
    return SLIP_DOMAIN + payload


def emsa_pkcs1_v15_sha256(message: bytes) -> int:
    digest = hashlib.sha256(message).digest()
    trailer = DIGESTINFO_SHA256 + digest
    padding = b"\xff" * (K - len(trailer) - 3)
    return int.from_bytes(b"\x00\x01" + padding + b"\x00" + trailer, "big")


def verify_token(token: str) -> bool:
    payload, sig = decode_token(token)
    return 0 < sig < N and pow(sig, E, N) == emsa_pkcs1_v15_sha256(slip_signing_bytes(payload))


def decode_token(token: str) -> tuple[bytes, int]:
    left, right = token.split(".", 1)
    sig_raw = b64u_decode(right)
    if len(sig_raw) != K:
        raise ValueError("bad seal length")
    return b64u_decode(left), int.from_bytes(sig_raw, "big")


def parse_slip_payload(payload: bytes) -> dict[str, Any]:
    obj = json.loads(payload.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("slip must be an object")
    if canonical_json_bytes(obj) != payload:
        raise ValueError("not canonical")
    return obj


def relic_v2_key_shape(p: int, q: int, cabinet_bytes: bytes, aad: bytes) -> bytes:
    lo, hi = sorted((p, q))
    return hashlib.sha256(b"relic-v2|" + int_to_bytes(lo) + int_to_bytes(hi) + cabinet_bytes + aad).digest()


def black_ledger_key_shape(x: int, p: int, q: int, aad: bytes) -> bytes:
    lo, hi = sorted((p, q))
    x_bytes = x.to_bytes(16, "big")
    return hashlib.sha256(b"black-ledger-v1|" + x_bytes + int_to_bytes(lo) + int_to_bytes(hi) + aad).digest()


def black_ledger_sample_shape(a: int, b: int, x: int, ledger_prime: int) -> int:
    return ((a * x + b) % ledger_prime) >> BLACK_LEDGER_SHIFT


def proof_ok(prefix: str, nonce: str, bits: int = POW_BITS_DEFAULT) -> bool:
    digest = hashlib.sha256(prefix.encode("ascii") + nonce.encode("utf-8")).digest()
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count >= bits


if __name__ == "__main__":
    print(
        json.dumps(
            {
                "title": TITLE,
                "public_key": {"n": str(N), "e": E, "bytes": K},
                "domain_hex": SLIP_DOMAIN.hex(),
                "restricted_slip": RESTRICTED_SLIP,
                "visitor_example": VISITOR_EXAMPLE,
                "seal_plate_menu": SEAL_PLATE_MENU,
                "relic_aad": RELIC_AAD.hex(),
                "black_ledger_aad": BLACK_LEDGER_AAD.hex(),
                "black_ledger_shift": BLACK_LEDGER_SHIFT,
            },
            indent=2,
        )
    )
