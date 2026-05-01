#!/usr/bin/env python3
"""Starter helpers for EggRoll Silent Orchard.

Use this file as a thin client for the live challenge. The interesting data is
served by the rollup oracle and the vault gateway.
"""

from __future__ import annotations

import socket
from typing import Any

import requests


BASE_URL = "http://HOST:28080"
TCP_HOST = "HOST"
TCP_PORT = 41337


def fetch_oracle(base_url: str = BASE_URL) -> dict[str, Any]:
    r = requests.get(f"{base_url}/api/oracle", timeout=10)
    r.raise_for_status()
    return r.json()["oracle"]


def fetch_blocks(base_url: str = BASE_URL) -> list[dict[str, Any]]:
    r = requests.get(f"{base_url}/api/blocks", timeout=10)
    r.raise_for_status()
    return r.json()["blocks"]


def submit_admin_token(token: str, base_url: str = BASE_URL) -> dict[str, Any]:
    r = requests.post(f"{base_url}/api/admin", json={"token": token}, timeout=10)
    return r.json()


def submit_orchard_claim(bits: list[int] | str, base_url: str = BASE_URL) -> dict[str, Any]:
    r = requests.post(f"{base_url}/api/claim", json={"bits": bits}, timeout=10)
    return r.json()


def tcp_exchange(payload: bytes, host: str = TCP_HOST, port: int = TCP_PORT) -> bytes:
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


if __name__ == "__main__":
    print(fetch_oracle().keys())
