"""Low-level immutable encrypted JSON journal publication.

This module deliberately knows nothing about migrations, mode transitions, or
external operations.  Callers own their state machines and public indexes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._atomic_file import atomic_write_private_bytes
from .keystore import primary_session_key, session_key_for


class EncryptedJournalError(RuntimeError):
    """Product-data-free low-level journal failure."""


def publish_encrypted_json(
    *,
    path_for_digest: Callable[[str], Path],
    schema: str,
    version: int,
    aad: bytes,
    payload: Mapping[str, object],
    maximum_plaintext_bytes: int,
) -> str:
    """Encrypt one immutable revision, reopen it, and verify exact plaintext."""

    try:
        plaintext = _canonical_json(dict(payload))
        if not plaintext or len(plaintext) > maximum_plaintext_bytes:
            raise ValueError
        key, key_id = primary_session_key()
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        envelope = {
            "schema": schema,
            "version": version,
            "keyId": key_id,
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        }
        encoded = _canonical_json(envelope)
        digest = hashlib.sha256(encoded).hexdigest()
        path = path_for_digest(digest)
        atomic_write_private_bytes(path, encoded)
        reopened, reopened_digest = load_encrypted_json(
            path=path,
            schema=schema,
            version=version,
            aad=aad,
            expected_digest=digest,
            maximum_plaintext_bytes=maximum_plaintext_bytes,
        )
        if reopened_digest != digest or _canonical_json(reopened) != plaintext:
            raise ValueError
        return digest
    except EncryptedJournalError:
        raise
    except Exception:
        raise EncryptedJournalError() from None


def load_encrypted_json(
    *,
    path: Path,
    schema: str,
    version: int,
    aad: bytes,
    expected_digest: str,
    maximum_plaintext_bytes: int,
) -> tuple[dict[str, object], str]:
    """Authenticate and decode one exact immutable journal revision."""

    try:
        raw = path.read_bytes()
        if len(raw) > maximum_plaintext_bytes * 2 + 4096:
            raise ValueError
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected_digest:
            raise ValueError
        envelope = json.loads(raw)
        if (
            type(envelope) is not dict
            or set(envelope) != {"schema", "version", "keyId", "nonce", "ciphertext"}
            or envelope["schema"] != schema
            or type(envelope["version"]) is not int
            or envelope["version"] != version
            or not isinstance(envelope["keyId"], str)
        ):
            raise ValueError
        key = session_key_for(envelope["keyId"])
        if key is None:
            raise ValueError
        plaintext = AESGCM(key).decrypt(
            _unb64(envelope["nonce"]),
            _unb64(envelope["ciphertext"]),
            aad,
        )
        if not plaintext or len(plaintext) > maximum_plaintext_bytes:
            raise ValueError
        payload = json.loads(plaintext)
        if type(payload) is not dict:
            raise ValueError
        return payload, digest
    except Exception:
        raise EncryptedJournalError() from None


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError
    return base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )


__all__ = [
    "EncryptedJournalError",
    "load_encrypted_json",
    "publish_encrypted_json",
]
