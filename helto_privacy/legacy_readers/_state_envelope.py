"""Exact AES-GCM mechanics shared by schema-specific historical units."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_ALGORITHM = "AES-256-GCM"
_VERSION = 1
_FIELDS = {
    "version",
    "schema",
    "encrypted",
    "algorithm",
    "keyId",
    "nonce",
    "ciphertext",
}


class ExactStateEnvelopeReader:
    """Read one authenticated historical schema and nothing else."""

    def __init__(self, schema: str, key_import_id: str) -> None:
        self._schema = schema
        self._key_import_id = key_import_id

    def probe(self, source: object, _context: object) -> bool:
        payload = self._payload(source)
        if payload is None or set(payload) != _FIELDS:
            return False
        if (
            payload.get("version") != _VERSION
            or payload.get("schema") != self._schema
            or payload.get("encrypted") is not True
            or payload.get("algorithm") != _ALGORITHM
        ):
            return False
        try:
            if any(
                not isinstance(payload.get(field), str)
                for field in ("keyId", "nonce", "ciphertext")
            ):
                return False
            key_id_bytes = self._b64decode(payload.get("keyId"))
            nonce = self._b64decode(payload.get("nonce"))
            ciphertext = self._b64decode(payload.get("ciphertext"))
        except Exception:
            return False
        return (
            len(key_id_bytes) == 12
            and len(nonce) == 12
            and len(ciphertext) >= 16
            and self._b64encode(key_id_bytes) == payload.get("keyId")
            and self._b64encode(nonce) == payload.get("nonce")
            and self._b64encode(ciphertext) == payload.get("ciphertext")
        )

    def read(self, source: object, context: object) -> dict[str, object]:
        payload = self._payload(source)
        if payload is None or not self.probe(payload, context):
            raise ValueError("Historical state envelope is not an exact supported format.")
        key_for = getattr(context, "key_for", None)
        if not callable(key_for):
            raise ValueError("Historical key import is unavailable.")
        key = key_for(self._key_import_id)
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Historical key import is invalid.")
        key_id = self._b64encode(hashlib.sha256(key).digest()[:12])
        if not hmac.compare_digest(key_id, str(payload.get("keyId") or "")):
            raise ValueError("Historical state envelope key does not match its import.")
        plaintext = AESGCM(key).decrypt(
            self._b64decode(payload["nonce"]),
            self._b64decode(payload["ciphertext"]),
            f"{self._schema}|{_VERSION}|{_ALGORITHM}|{key_id}".encode("utf-8"),
        )
        loaded = json.loads(plaintext.decode("utf-8"))
        if not isinstance(loaded, Mapping):
            raise ValueError("Historical state envelope did not contain an object.")
        return dict(loaded)

    @staticmethod
    def _payload(source: object) -> dict[str, object] | None:
        if isinstance(source, str):
            try:
                source = json.loads(source)
            except (TypeError, ValueError):
                return None
        return dict(source) if isinstance(source, Mapping) else None

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _b64decode(value: object) -> bytes:
        text = str(value or "")
        return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
