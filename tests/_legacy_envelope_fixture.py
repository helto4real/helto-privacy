"""Synthetic outputs from the removed plaintext-key envelope writer."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from helto_privacy._atomic_file import atomic_write_private_bytes


def write_legacy_state_fixture(
    directory: Path,
    schema: str,
    state: dict[str, object],
    *,
    key: bytes | None = None,
) -> tuple[dict[str, object], bytes, str]:
    """Write one test-only legacy key source and return its old envelope."""

    key = key or secrets.token_bytes(32)
    key_id = _b64url(hashlib.sha256(key).digest()[:12])
    nonce = secrets.token_bytes(12)
    algorithm = "AES-256-GCM"
    plaintext = json.dumps(
        state,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    aad = f"{schema}|1|{algorithm}|{key_id}".encode("utf-8")
    envelope = {
        "version": 1,
        "schema": schema,
        "encrypted": True,
        "algorithm": algorithm,
        "keyId": key_id,
        "nonce": _b64url(nonce),
        "ciphertext": _b64url(AESGCM(key).encrypt(nonce, plaintext, aad)),
    }
    atomic_write_private_bytes(
        directory / "privacy_key.json",
        json.dumps(
            {
                "version": 1,
                "algorithm": algorithm,
                "keyId": key_id,
                "key": _b64url(key),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8"),
    )
    return envelope, key, key_id


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
