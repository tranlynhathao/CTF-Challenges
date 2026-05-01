#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import socketserver
import string
import sys
from pathlib import Path
from typing import Any, Optional

from Crypto.Cipher import AES
from flask import Flask, jsonify, make_response, render_template, request

BASE_DIR = Path(__file__).resolve().parent


TITLE = "The Archivist's Fault"
ISSUED = 20260501

E = 65537
P = 35759029932597598307021242262109047100090220102663598800791241147854613955355487157965158934601193187449548994675869
Q = 25136343227320008788695399294212446977266527303569943284240424996022586338055544264086772005379395032862608677063633
N = P * Q
PHI = (P - 1) * (Q - 1)
D = pow(E, -1, PHI)
DP = D % (P - 1)
DQ = D % (Q - 1)
QINV = pow(Q, -1, P)
K = (N.bit_length() + 7) // 8

MAIN_FLAG = os.environ.get("MAIN_FLAG", "CBJS{black_ledger_residues_open_the_inner_vault}")
EGG1_FLAG = os.environ.get("EGG1_FLAG", "EGG{relic_paths_bind_primes_to_drawers}")
EGG2_FLAG = os.environ.get("EGG2_FLAG", "EGG{lll_reads_the_black_ledger_margin}")

SLIP_DOMAIN = b"CBJS:archive-slip-v2\x00"
DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

VISITOR_SCOPE = ["reading-room"]
RESTRICTED_SLIP = {
    "cabinet": -1,
    "issued": ISSUED,
    "nonce": "black-ledger",
    "scope": ["reading-room", "inner-vault", "seal-reissue"],
    "sub": "archivist:root",
    "typ": "archive-slip-v2",
}

CABINET_SIZE = 64
CABINET_SECRET = bytes.fromhex("68b1f16cf0d4270a8b3609ca5740e7d2")
CABINET_SECRET_START = -48
PLATE_RUBBING = [(-9, 0x31), (-14, 0xC2), (-4, 0x7D)]
MAX_SEALS_PER_SESSION = int(os.environ.get("MAX_SEALS", "4"))
MAX_CABINET_TOUCHES = int(os.environ.get("MAX_CABINET_TOUCHES", "28"))
POW_BITS = int(os.environ.get("POW_BITS", "20"))

RELIC_AAD = b"relic-v2|catalogue:umbra|drawers:bar-48..bar-33"
RELIC_NONCE = bytes.fromhex("6f4d8c3a1c52bb7090e544e1")

BLACK_LEDGER_AAD = b"black-ledger-v1|margin:sable|sample-set:12x160"
BLACK_LEDGER_NONCE = bytes.fromhex("12c05ab7f49a31d0e3cd20a8")
BLACK_LEDGER_SHIFT = 160
BLACK_LEDGER_SAMPLES = 12
BLACK_LEDGER_X = 78857696374426010966184570707436443210

DECOY_SEAL = hashlib.sha256(b"black-ledger:retired:seal").hexdigest()


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
    if K < len(trailer) + 11:
        raise ValueError("RSA modulus too small")
    padding = b"\xff" * (K - len(trailer) - 3)
    return int.from_bytes(b"\x00\x01" + padding + b"\x00" + trailer, "big")


def rsa_residue_sign(m: int, bad_impression: bool = False) -> int:
    sp = pow(m, DP, P)
    sq = pow(m, DQ, Q)
    if bad_impression:
        # Private organizer note: corrupt only one prime-side residue before
        # recombination so gcd(s^e - m, n) exposes the other prime.
        sq ^= 1 << 23
        sq %= Q
    h = (QINV * (sp - sq)) % P
    return (sq + h * Q) % N


def sign_slip_payload(payload: bytes, bad_impression: bool = False) -> int:
    return rsa_residue_sign(emsa_pkcs1_v15_sha256(slip_signing_bytes(payload)), bad_impression)


def verify_slip_signature(payload: bytes, sig: int) -> bool:
    if sig <= 0 or sig >= N:
        return False
    return pow(sig, E, N) == emsa_pkcs1_v15_sha256(slip_signing_bytes(payload))


def encode_token(payload: bytes, sig: int) -> str:
    return f"{b64u(payload)}.{b64u(sig.to_bytes(K, 'big'))}"


def decode_token(token: str) -> tuple[bytes, int]:
    left, right = token.split(".", 1)
    payload = b64u_decode(left)
    sig_raw = b64u_decode(right)
    if len(sig_raw) != K:
        raise ValueError("bad signature length")
    return payload, int.from_bytes(sig_raw, "big")


def parse_slip(payload: bytes) -> dict[str, Any]:
    obj = json.loads(payload.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("slip must be a JSON object")
    if canonical_json_bytes(obj) != payload:
        raise ValueError("slip is not canonical")
    return obj


def clean_name(raw: str) -> str:
    raw = (raw or "guest").strip() or "guest"
    allowed = set(string.ascii_letters + string.digits + "._-")
    if len(raw) > 28 or any(ch not in allowed for ch in raw):
        raise ValueError("name must use 1..28 chars from A-Za-z0-9._-")
    return raw


def nonce_for(origin: str, name: str, counter: int) -> str:
    seed = f"v2|{origin}|{name}|{counter}|{ISSUED}".encode("ascii")
    return hashlib.sha256(seed).hexdigest()[:14]


def make_visitor_slip(name: str, origin: str, counter: int) -> dict[str, Any]:
    safe = clean_name(name)
    return {
        "cabinet": 0,
        "issued": ISSUED,
        "nonce": nonce_for(origin, safe, counter),
        "scope": VISITOR_SCOPE,
        "sub": f"visitor:{safe}",
        "typ": "archive-slip-v2",
    }


def token_from_request() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.values.get("token") or request.cookies.get("token")


def wants_json() -> bool:
    return "application/json" in request.headers.get("Accept", "")


def relic_envelope() -> dict[str, str]:
    lo, hi = sorted((P, Q))
    key = hashlib.sha256(b"relic-v2|" + int_to_bytes(lo) + int_to_bytes(hi) + CABINET_SECRET + RELIC_AAD).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=RELIC_NONCE)
    cipher.update(RELIC_AAD)
    ciphertext, tag = cipher.encrypt_and_digest(EGG1_FLAG.encode("ascii"))
    return {"aad": RELIC_AAD.hex(), "ciphertext": ciphertext.hex(), "nonce": RELIC_NONCE.hex(), "tag": tag.hex()}


def ledger_samples() -> list[dict[str, str]]:
    modulus = min(P, Q)
    rows = []
    for i in range(BLACK_LEDGER_SAMPLES):
        a_seed = hashlib.sha256(b"black-ledger:a:" + i.to_bytes(2, "big")).digest()
        b_seed = hashlib.sha256(b"black-ledger:b:" + i.to_bytes(2, "big")).digest()
        a = int.from_bytes(a_seed + hashlib.sha256(a_seed + b"a").digest(), "big") % (modulus - 1) + 1
        b = int.from_bytes(b_seed + hashlib.sha256(b_seed + b"b").digest(), "big") % modulus
        z = (a * BLACK_LEDGER_X + b) % modulus
        rows.append({"a": str(a), "b": str(b), "top": str(z >> BLACK_LEDGER_SHIFT)})
    return rows


def black_ledger_envelope() -> dict[str, Any]:
    lo, hi = sorted((P, Q))
    x_bytes = BLACK_LEDGER_X.to_bytes(16, "big")
    key = hashlib.sha256(
        b"black-ledger-v1|" + x_bytes + int_to_bytes(lo) + int_to_bytes(hi) + BLACK_LEDGER_AAD
    ).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=BLACK_LEDGER_NONCE)
    cipher.update(BLACK_LEDGER_AAD)
    ciphertext, tag = cipher.encrypt_and_digest(EGG2_FLAG.encode("ascii"))
    return {
        "ciphertext": ciphertext.hex(),
        "ledger_prime": "smaller recovered prime",
        "nonce": BLACK_LEDGER_NONCE.hex(),
        "aad": BLACK_LEDGER_AAD.hex(),
        "samples": ledger_samples(),
        "shift": BLACK_LEDGER_SHIFT,
        "tag": tag.hex(),
    }


def build_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
        static_url_path="/static",
    )

    def view(template: str, active: str, subtitle: str, **ctx):
        return render_template(template, title=TITLE, subtitle=subtitle, active=active, **ctx)

    @app.get("/")
    def index():
        return view("index.html", active="home", subtitle="Rules")

    @app.get("/ledger")
    def ledger():
        data = {
            "public_key": {"n": str(N), "e": E, "bytes": K},
            "domain_hex": SLIP_DOMAIN.hex(),
            "token_format": "base64url(canonical JSON) + '.' + base64url(seal bytes)",
            "canonical_json": "UTF-8, sorted keys, compact separators",
        }
        if wants_json():
            return jsonify(data)
        return view("ledger.html", active="ledger", subtitle="Ledger", n=str(N), e=E, k=K, domain_hex=SLIP_DOMAIN.hex())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        name = request.values.get("name", "guest")
        error = None
        token = None
        payload_text = None
        try:
            slip = make_visitor_slip(name, "web", 0)
            payload = canonical_json_bytes(slip)
            token = encode_token(payload, sign_slip_payload(payload))
            payload_text = payload.decode("utf-8")
        except ValueError as exc:
            error = str(exc)

        if wants_json():
            if error:
                return jsonify({"error": error}), 400
            return jsonify({"payload": payload_text, "token": token})

        response = make_response(
            view(
                "login.html",
                active="login",
                subtitle="Visitor Slip",
                name=name,
                error=error,
                token=token,
                payload_text=payload_text,
            )
        )
        if token:
            response.set_cookie("token", token, httponly=True, samesite="Strict")
        return response

    @app.route("/vault", methods=["GET", "POST"])
    def vault():
        token = token_from_request()

        if wants_json():
            if not token:
                return jsonify({"error": "missing slip"}), 401
            try:
                payload, sig = decode_token(token)
                slip = parse_slip(payload)
            except Exception as exc:
                return jsonify({"error": f"unreadable slip: {exc}"}), 400
            if not verify_slip_signature(payload, sig):
                return jsonify({"error": "seal rejected"}), 403
            if slip != RESTRICTED_SLIP:
                return jsonify({"error": "inner gate refuses this scope"}), 403
            return jsonify({"flag": MAIN_FLAG})

        state: Optional[str] = None
        status_code = 200
        exc_message: Optional[str] = None
        if request.method == "POST" or token:
            if not token:
                state, status_code = "missing", 401
            else:
                try:
                    payload, sig = decode_token(token)
                    slip = parse_slip(payload)
                except Exception as exc:
                    state, status_code = "unreadable", 400
                    exc_message = str(exc)
                else:
                    if not verify_slip_signature(payload, sig):
                        state, status_code = "bad_sig", 403
                    elif slip != RESTRICTED_SLIP:
                        state, status_code = "wrong_scope", 403
                    else:
                        state, status_code = "granted", 200

        return view(
            "vault.html",
            active="vault",
            subtitle="Vault",
            state=state,
            status_code=status_code,
            exc_message=exc_message,
            main_flag=MAIN_FLAG if state == "granted" else None,
        )

    @app.get("/relic")
    def relic():
        data = relic_envelope()
        if wants_json():
            return jsonify(data)
        return view("relic.html", active="relic", subtitle="Relic", env=data)

    @app.get("/black-ledger")
    def black_ledger():
        data = black_ledger_envelope()
        if wants_json():
            return jsonify(data)
        return view(
            "black_ledger.html",
            active="black",
            subtitle="Black Ledger",
            env=data,
            samples=data["samples"],
            ledger_prime=data["ledger_prime"],
            shift=data["shift"],
        )

    @app.get("/healthz")
    def healthz():
        return "ok\n"

    return app


def leading_zero_bits(data: bytes) -> int:
    count = 0
    for byte in data:
        if byte == 0:
            count += 8
            continue
        return count + (8 - byte.bit_length())
    return count


class CabinetWindow:
    def __init__(self):
        self.cells: dict[int, int] = {i: 0 for i in range(CABINET_SIZE)}
        self.stage = 0
        self.bad_ready = False

    def write(self, drawer: int, value: int) -> None:
        value &= 0xFF
        self.cells[drawer] = value
        expected = PLATE_RUBBING[self.stage]
        if (drawer, value) == expected:
            self.stage += 1
            if self.stage == len(PLATE_RUBBING):
                self.bad_ready = True
                self.stage = 0
        elif drawer < 0:
            self.stage = 0

    def read(self, drawer: int) -> int:
        if CABINET_SECRET_START <= drawer < CABINET_SECRET_START + len(CABINET_SECRET):
            return CABINET_SECRET[drawer - CABINET_SECRET_START]
        return self.cells.get(drawer, 0)

    def consume_bad(self) -> bool:
        ready = self.bad_ready
        self.bad_ready = False
        return ready

    def state_name(self) -> str:
        if self.bad_ready:
            return "ready"
        if self.stage:
            return f"mark {self.stage} of {len(PLATE_RUBBING)}"
        return "quiet"


def parse_byte(text: str) -> int:
    text = text.strip()
    if text.lower().startswith("0x"):
        value = int(text, 16)
    else:
        value = int(text, 16)
    if not 0 <= value <= 255:
        raise ValueError("byte must be between 00 and ff")
    return value


class SealPlateHandler(socketserver.StreamRequestHandler):
    def setup(self):
        super().setup()
        self.request.settimeout(90)
        self.cabinet = CabinetWindow()
        self.seals_left = MAX_SEALS_PER_SESSION
        self.touches_left = MAX_CABINET_TOUCHES
        self.counter = 0

    def out(self, text: str) -> None:
        self.wfile.write(text.encode("utf-8"))
        self.wfile.flush()

    def read_line(self) -> str:
        line = self.rfile.readline(4096)
        if not line:
            raise EOFError
        return line.decode("utf-8", "replace").strip()

    def proof_gate(self) -> bool:
        bits = max(0, POW_BITS)
        prefix = os.urandom(8).hex()
        self.out(
            "Seal plate proof required.\n"
            f"Find nonce text with sha256(prefix || nonce) showing {bits} leading zero bits.\n"
            f"prefix: {prefix}\n"
            f"bits: {bits}\n"
            "nonce> "
        )
        nonce = self.read_line()
        digest = hashlib.sha256(prefix.encode("ascii") + nonce.encode("utf-8")).digest()
        if leading_zero_bits(digest) < bits:
            self.out("proof rejected\n")
            return False
        self.out("proof accepted\n")
        return True

    def menu(self):
        self.out(
            "\n"
            f"stamps left: {self.seals_left} | cabinet touches left: {self.touches_left}\n"
            "1) public folio\n"
            "2) stamp visitor slip\n"
            "3) mark cabinet drawer\n"
            "4) read cabinet drawer / maintenance plate\n"
            "5) quit\n"
            "choice> "
        )

    def handle(self):
        self.out(
            "Archivist seal plate v2\n"
            "Visitor slips only. Restricted folios are recorded elsewhere.\n"
            "Drawer labels on the maintenance plate do not all begin at zero.\n"
        )
        try:
            if not self.proof_gate():
                return
            while True:
                self.menu()
                choice = self.read_line()
                if choice == "1":
                    self.cmd_public_folio()
                elif choice == "2":
                    self.cmd_stamp()
                elif choice == "3":
                    self.cmd_mark()
                elif choice == "4":
                    self.cmd_read()
                elif choice == "5":
                    self.out("archive closed\n")
                    return
                else:
                    self.out("unknown shelf mark\n")
        except (EOFError, TimeoutError, BrokenPipeError, ConnectionError):
            return
        except Exception as exc:
            self.out(f"plate error: {exc}\n")

    def cmd_public_folio(self):
        self.out(json.dumps({"n": str(N), "e": E, "bytes": K, "domain": SLIP_DOMAIN.hex()}) + "\n")

    def cmd_stamp(self):
        if self.seals_left <= 0:
            self.out("stamp quota exhausted\n")
            return
        self.out("name: ")
        name = self.read_line()
        try:
            slip = make_visitor_slip(name, "plate", self.counter)
            payload = canonical_json_bytes(slip)
        except ValueError as exc:
            self.out(f"rejected: {exc}\n")
            return
        bad = self.cabinet.consume_bad()
        sig = sign_slip_payload(payload, bad_impression=bad)
        token = encode_token(payload, sig)
        self.seals_left -= 1
        self.counter += 1
        self.out(f"slip: {payload.decode('utf-8')}\n")
        self.out(f"token: {token}\n")
        self.out(f"impression: {'bad' if bad else 'clean'}\n")

    def cmd_mark(self):
        if self.touches_left <= 0:
            self.out("cabinet touch quota exhausted\n")
            return
        self.out("drawer: ")
        try:
            drawer = int(self.read_line(), 0)
            self.out("ink byte: ")
            value = parse_byte(self.read_line())
        except Exception as exc:
            self.out(f"rejected: {exc}\n")
            return
        self.touches_left -= 1
        if drawer < CABINET_SIZE:
            self.cabinet.write(drawer, value)
            self.out("mark accepted\n")
        else:
            self.out("drawer outside cabinet\n")

    def cmd_read(self):
        if self.touches_left <= 0:
            self.out("cabinet touch quota exhausted\n")
            return
        self.out("drawer (or plate): ")
        raw = self.read_line()
        self.touches_left -= 1
        if raw.lower() == "plate":
            self.out(f"maintenance plate: {self.cabinet.state_name()}\n")
            self.out("rubbing: bar-09:31 bar-14:c2 bar-04:7d\n")
            self.out("relic path: bar-48..bar-33\n")
            self.out(f"retired seal: {DECOY_SEAL[:24]}\n")
            return
        try:
            drawer = int(raw, 0)
        except ValueError:
            self.out("unreadable drawer label\n")
            return
        if drawer < CABINET_SIZE:
            self.out(f"cell: {self.cabinet.read(drawer):02x}\n")
        else:
            self.out("drawer outside cabinet\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_web(host: str, port: int) -> None:
    build_app().run(host=host, port=port, threaded=True)


def run_plate(host: str, port: int) -> None:
    with ThreadedTCPServer((host, port), SealPlateHandler) as server:
        print(f"Seal plate listening on {host}:{port}", flush=True)
        server.serve_forever()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=TITLE)
    sub = parser.add_subparsers(dest="mode", required=True)

    web = sub.add_parser("web")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8080)

    plate = sub.add_parser("plate", aliases=["hsm"])
    plate.add_argument("--host", default="127.0.0.1")
    plate.add_argument("--port", type=int, default=31337)

    args = parser.parse_args(argv)
    if args.mode == "web":
        run_web(args.host, args.port)
    elif args.mode in ("plate", "hsm"):
        run_plate(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
