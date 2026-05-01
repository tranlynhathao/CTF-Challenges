from __future__ import annotations

import base64
import json
import os
import time
from hashlib import sha256

from ecdsa import BadSignatureError, SECP256k1, VerifyingKey, util
from flask import Flask, jsonify, render_template, request

import data


app = Flask(__name__)


def _public_tcp_port() -> str:
    """Public-facing TCP port for the vault gateway, used only in the UI templates."""
    return os.getenv("PUBLIC_TCP_PORT", "41337")


FLAG_DEFAULTS = {
    "web": "LOCAL_DEV_FLAG_CBJS_WEB",
    "pwn": "LOCAL_DEV_FLAG_CBJS_PWN",
    "airdrop": "LOCAL_DEV_FLAG_EGG_AIRDROP",
    "cuso": "LOCAL_DEV_FLAG_EGG_CUSO",
    "bd": "LOCAL_DEV_FLAG_EGG_BD",
}

FLAG_ENV = {
    "web": "FLAG_CBJS_WEB",
    "pwn": "FLAG_CBJS_PWN",
    "airdrop": "FLAG_EGG_AIRDROP",
    "cuso": "FLAG_EGG_CUSO",
    "bd": "FLAG_EGG_BD",
}


def load_flags() -> dict[str, str]:
    return {k: os.getenv(env_name, FLAG_DEFAULTS[k]) for k, env_name in FLAG_ENV.items()}


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def canonical_json(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def validator_vk() -> VerifyingKey:
    pub = data.VALIDATOR_PUBLIC
    raw = bytes.fromhex(pub["x"] + pub["y"])
    return VerifyingKey.from_string(raw, curve=SECP256k1)


def verify_admin_token(token: str) -> tuple[bool, str]:
    if not token or "." not in token:
        return False, "missing token"
    try:
        payload_part, sig_part = token.split(".", 1)
        payload_bytes = b64url_decode(payload_part)
        signature = b64url_decode(sig_part)
        payload = json.loads(payload_bytes.decode())
    except Exception:
        return False, "malformed token"

    if len(signature) != 64:
        return False, "bad signature shape"
    if payload.get("role") != "admin":
        return False, "role denied"
    if payload.get("scope") != "orchard:admin":
        return False, "scope denied"
    if int(payload.get("exp", 0)) < int(time.time()):
        return False, "token expired"

    digest = sha256(payload_bytes).digest()
    try:
        validator_vk().verify_digest(signature, digest, sigdecode=util.sigdecode_string)
    except BadSignatureError:
        return False, "signature denied"
    except Exception:
        return False, "signature error"
    return True, "ok"


def normalize_bits(raw: object) -> list[int] | None:
    if isinstance(raw, str):
        if any(ch not in "01" for ch in raw):
            return None
        return [int(ch) for ch in raw]
    if not isinstance(raw, list):
        return None
    bits: list[int] = []
    for item in raw:
        if item is True:
            bits.append(1)
        elif item is False:
            bits.append(0)
        elif isinstance(item, int) and item in (0, 1):
            bits.append(item)
        else:
            return None
    return bits


@app.get("/")
def index():
    return render_template("index.html", tcp_port=_public_tcp_port())


@app.get("/explorer")
def explorer():
    return render_template(
        "explorer.html",
        blocks=data.public_blocks(),
        tcp_port=_public_tcp_port(),
    )


@app.get("/api/health")
def health():
    return jsonify({"ok": True})


@app.get("/api/blocks")
def blocks():
    return jsonify({"ok": True, "blocks": data.public_blocks()})


@app.get("/api/oracle")
def oracle():
    flags = load_flags()
    seed = os.getenv("CHALLENGE_SEED", data.DEFAULT_SEED)
    return jsonify({"ok": True, "oracle": data.public_oracle(flags, seed)})


@app.post("/api/admin")
def admin():
    body = request.get_json(silent=True) or {}
    token = body.get("token") or request.form.get("token", "")
    ok, reason = verify_admin_token(token)
    if not ok:
        return json_error(reason, 403)
    return jsonify({"ok": True, "flag": load_flags()["web"], "console": "sequencer admin access granted"})


@app.post("/api/claim")
def claim():
    body = request.get_json(silent=True) or {}
    bits = normalize_bits(body.get("bits", body.get("proof")))
    if bits is None:
        return json_error("proof must be a bits array or bit string")
    if len(bits) != len(data.ORCHARD_WEIGHTS):
        return json_error("proof length mismatch")

    total = sum(weight * bit for weight, bit in zip(data.ORCHARD_WEIGHTS, bits))
    if total != data.ORCHARD_TARGET:
        return json_error("basket weight mismatch", 403)

    digest = sha256("".join(str(b) for b in bits).encode()).hexdigest()
    if digest != data.ORCHARD_CHECKSUM:
        return json_error("basket root mismatch", 403)
    return jsonify({"ok": True, "flag": load_flags()["airdrop"], "claim": "quiet basket accepted"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
