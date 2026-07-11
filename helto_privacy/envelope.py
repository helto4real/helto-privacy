"""Schema-parameterized privacy envelopes for Helto node packs."""

from __future__ import annotations

import base64
import json
import math
import os
import secrets
from pathlib import Path
from typing import Any, Mapping

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    CRYPTO_AVAILABLE = True
    CRYPTO_IMPORT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - dependency may be absent in ComfyUI installs.
    AESGCM = None  # type: ignore[assignment]
    CRYPTO_AVAILABLE = False
    CRYPTO_IMPORT_ERROR = str(exc)

from . import keystore as default_keystore
from .keystore import PrivacyKeystoreError
from ._legacy_key_source import (
    JSON_FORMAT,
    LegacyKeySourceError,
    read_legacy_key_source,
    unlink_unchanged_legacy_key_source,
)
from .suite_runtime import require_active_process_suite


ENVELOPE_VERSION = 1
ALGORITHM = "AES-256-GCM"
KEY_FILE_NAME = "privacy_key.json"
BYTE_CHUNK_SIZE = 64 * 1024 * 1024


class PrivacyError(RuntimeError):
    """Raised when privacy encryption cannot complete safely."""


def config_dir() -> Path:
    return Path.cwd() / "config"


def key_path(base_dir: str | os.PathLike[str] | None = None) -> Path:
    return Path(base_dir) / KEY_FILE_NAME if base_dir is not None else config_dir() / KEY_FILE_NAME


def initialize_keystore_with_legacy_migration(
    password: str,
    legacy_dir: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    """Initialize or extend the shared keystore with a legacy plaintext key."""
    require_active_process_suite()
    path = key_path(legacy_dir)
    source = None
    if path.exists():
        try:
            source = read_legacy_key_source(path, JSON_FORMAT)
        except LegacyKeySourceError as exc:
            raise PrivacyError(f"Cannot migrate existing privacy key file '{path}': {exc}") from exc

    try:
        if default_keystore.keystore_exists():
            result = default_keystore.unlock_keystore(password)
        else:
            result = default_keystore.initialize_keystore(password)
        if source is not None:
            result = default_keystore.import_decrypt_only_key_verified(
                password,
                source.key_id,
                source.key,
            )
    except PrivacyKeystoreError as exc:
        raise PrivacyError(str(exc)) from exc

    if source is not None:
        try:
            unlink_unchanged_legacy_key_source(source)
        except LegacyKeySourceError as exc:
            raise PrivacyError("Cannot unlink imported historical privacy key source.") from exc
    return result


class PrivacyEnvelopeCodec:
    """Encrypt and decrypt state/byte envelopes for a specific pack schema."""

    def __init__(self, schema: str, *, key_provider=None):
        schema = str(schema or "").strip()
        if not schema:
            raise ValueError("Privacy envelope schema must be non-empty.")
        self.schema = schema
        self.byte_schema = f"{schema}.bytes"
        self.chunked_byte_schema = f"{schema}.bytes.chunked"
        self.key_provider = key_provider or default_keystore

    def crypto_status(self, base_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        status = self.key_provider.keystore_status()
        return {
            "available": CRYPTO_AVAILABLE,
            "algorithm": ALGORITHM,
            "keyExists": bool(status.get("keystoreInitialized", False)),
            "keyPath": str(status.get("keystorePath") or ""),
            "error": "" if CRYPTO_AVAILABLE else f"Python package 'cryptography' is required: {CRYPTO_IMPORT_ERROR}",
            **status,
        }

    def is_encrypted_payload(self, value: Any) -> bool:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception:
                return False
        return (
            isinstance(value, Mapping)
            and value.get("encrypted") is True
            and value.get("schema") == self.schema
            and value.get("algorithm") == ALGORITHM
        )

    def encrypt_state(self, state: Mapping[str, Any], base_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        require_active_process_suite()
        key, key_id = self._current_key(base_dir)
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, self._aad(key_id))  # type: ignore[operator]
        return {
            "version": ENVELOPE_VERSION,
            "schema": self.schema,
            "encrypted": True,
            "algorithm": ALGORITHM,
            "keyId": key_id,
            "nonce": _b64url_encode(nonce),
            "ciphertext": _b64url_encode(ciphertext),
        }

    def decrypt_state(self, payload: Any, base_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        require_active_process_suite()
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception as exc:
                raise PrivacyError(f"Encrypted state payload is not valid JSON: {exc}") from exc
        if not self.is_encrypted_payload(payload):
            raise PrivacyError("Data is not an encrypted privacy payload.")
        key_id = str(payload.get("keyId", ""))
        key = self._key_for_payload(
            key_id,
            base_dir,
            "Encrypted state payload was created with a different local privacy key.",
        )
        try:
            nonce = _b64url_decode(str(payload.get("nonce", "")))
            ciphertext = _b64url_decode(str(payload.get("ciphertext", "")))
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, self._aad(key_id))  # type: ignore[operator]
            loaded = json.loads(plaintext.decode("utf-8"))
        except PrivacyError:
            raise
        except Exception as exc:  # noqa: BLE001 - auth/tag/key failures should be user-readable.
            raise PrivacyError(f"Could not decrypt state payload: {exc}") from exc
        if not isinstance(loaded, Mapping):
            raise PrivacyError("Encrypted state payload did not contain an object.")
        return dict(loaded)

    def encrypt_bytes(
        self,
        data: bytes,
        purpose: str,
        base_dir: str | os.PathLike[str] | None = None,
        *,
        chunk_size: int | None = None,
    ) -> dict[str, Any]:
        require_active_process_suite()
        key, key_id = self._current_key(base_dir)
        if chunk_size is None:
            chunk_size = self._byte_chunk_size()
        elif (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or chunk_size < 1
        ):
            raise PrivacyError("Encrypted byte chunk size is invalid.")
        if len(data) > chunk_size:
            return self._encrypt_bytes_chunked(data, purpose, key, key_id, chunk_size)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, data, self._bytes_aad(key_id, purpose))  # type: ignore[operator]
        return {
            "version": ENVELOPE_VERSION,
            "schema": self.byte_schema,
            "encrypted": True,
            "algorithm": ALGORITHM,
            "purpose": purpose,
            "keyId": key_id,
            "nonce": _b64url_encode(nonce),
            "ciphertext": _b64url_encode(ciphertext),
        }

    def decrypt_bytes(
        self,
        payload: Any,
        purpose: str,
        base_dir: str | os.PathLike[str] | None = None,
    ) -> bytes:
        return b"".join(self.iter_decrypt_bytes(payload, purpose, base_dir))

    def iter_decrypt_bytes(
        self,
        payload: Any,
        purpose: str,
        base_dir: str | os.PathLike[str] | None = None,
    ):
        """Yield authenticated plaintext chunks without named plaintext staging."""

        require_active_process_suite()
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception as exc:
                raise PrivacyError(f"Encrypted byte payload is not valid JSON: {exc}") from exc
        if not (
            isinstance(payload, Mapping)
            and payload.get("encrypted") is True
            and payload.get("algorithm") == ALGORITHM
        ):
            raise PrivacyError("Data is not an encrypted byte payload.")
        schema = payload.get("schema")
        if str(payload.get("purpose", "")) != purpose:
            raise PrivacyError("Encrypted byte payload was created for a different purpose.")
        key_id = str(payload.get("keyId", ""))
        key = self._key_for_payload(
            key_id,
            base_dir,
            "Encrypted byte payload was created with a different local privacy key.",
        )
        if schema == self.chunked_byte_schema:
            yield from self._iter_decrypt_bytes_chunked(payload, purpose, key, key_id)
            return
        if schema != self.byte_schema:
            raise PrivacyError("Data is not an encrypted byte payload.")
        try:
            nonce = _b64url_decode(str(payload.get("nonce", "")))
            ciphertext = _b64url_decode(str(payload.get("ciphertext", "")))
            yield AESGCM(key).decrypt(nonce, ciphertext, self._bytes_aad(key_id, purpose))  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - auth/tag/key failures should be user-readable.
            raise PrivacyError(f"Could not decrypt byte payload: {exc}") from exc

    def iter_decrypt_chunked_bytes(
        self,
        payload: Any,
        purpose: str,
        chunks,
        total_chunks: int,
        base_dir: str | os.PathLike[str] | None = None,
    ):
        """Yield chunked plaintext from a bounded external ciphertext iterator."""

        require_active_process_suite()
        if not (
            isinstance(payload, Mapping)
            and payload.get("encrypted") is True
            and payload.get("algorithm") == ALGORITHM
            and payload.get("schema") == self.chunked_byte_schema
            and str(payload.get("purpose", "")) == purpose
            and isinstance(total_chunks, int)
            and not isinstance(total_chunks, bool)
            and total_chunks > 0
        ):
            raise PrivacyError("Data is not an encrypted chunked byte payload.")
        key_id = str(payload.get("keyId", ""))
        key = self._key_for_payload(
            key_id,
            base_dir,
            "Encrypted byte payload was created with a different local privacy key.",
        )
        yield from self._iter_decrypt_bytes_chunked(
            payload,
            purpose,
            key,
            key_id,
            chunks=chunks,
            total_chunks=total_chunks,
        )

    def _current_key(
        self,
        base_dir: str | os.PathLike[str] | None = None,
    ) -> tuple[bytes, str]:
        if not CRYPTO_AVAILABLE:
            raise PrivacyError(f"Python package 'cryptography' is required for privacy mode: {CRYPTO_IMPORT_ERROR}")
        if base_dir is not None:
            raise PrivacyError(
                "Current privacy envelopes do not read or write legacy key directories."
            )
        try:
            return self.key_provider.primary_session_key()
        except PrivacyKeystoreError as exc:
            raise PrivacyError(str(exc)) from exc

    def _key_for_payload(
        self,
        payload_key_id: str,
        base_dir: str | os.PathLike[str] | None,
        mismatch_error: str,
    ) -> bytes:
        key, key_id = self._current_key(base_dir)
        if payload_key_id == key_id:
            return key
        alt = self.key_provider.session_key_for(payload_key_id)
        if alt is not None:
            return alt
        raise PrivacyError(mismatch_error)

    def _aad(self, key_id: str) -> bytes:
        return f"{self.schema}|{ENVELOPE_VERSION}|{ALGORITHM}|{key_id}".encode("utf-8")

    def _bytes_aad(self, key_id: str, purpose: str) -> bytes:
        return f"{self.byte_schema}|{ENVELOPE_VERSION}|{ALGORITHM}|{key_id}|{purpose}".encode("utf-8")

    def _chunk_bytes_aad(self, key_id: str, purpose: str, index: int, total_chunks: int, plaintext_size: int) -> bytes:
        return (
            f"{self.chunked_byte_schema}|{ENVELOPE_VERSION}|{ALGORITHM}|{key_id}|{purpose}|"
            f"{int(index)}|{int(total_chunks)}|{int(plaintext_size)}"
        ).encode("utf-8")

    def _byte_chunk_size(self) -> int:
        try:
            return max(1, int(BYTE_CHUNK_SIZE))
        except (TypeError, ValueError):
            return 64 * 1024 * 1024

    def _encrypt_bytes_chunked(self, data: bytes, purpose: str, key: bytes, key_id: str, chunk_size: int) -> dict[str, Any]:
        plaintext_size = len(data)
        total_chunks = max(1, int(math.ceil(plaintext_size / chunk_size)))
        chunks = []
        for index, offset in enumerate(range(0, plaintext_size, chunk_size)):
            nonce = secrets.token_bytes(12)
            chunk = data[offset: offset + chunk_size]
            ciphertext = AESGCM(key).encrypt(
                nonce,
                chunk,
                self._chunk_bytes_aad(key_id, purpose, index, total_chunks, plaintext_size),  # type: ignore[operator]
            )
            chunks.append({
                "index": index,
                "nonce": _b64url_encode(nonce),
                "ciphertext": _b64url_encode(ciphertext),
            })
        return {
            "version": ENVELOPE_VERSION,
            "schema": self.chunked_byte_schema,
            "encrypted": True,
            "algorithm": ALGORITHM,
            "purpose": purpose,
            "keyId": key_id,
            "chunkSize": int(chunk_size),
            "plaintextSize": plaintext_size,
            "chunks": chunks,
        }

    def _decrypt_bytes_chunked(self, payload: Mapping[str, Any], purpose: str, key: bytes, key_id: str) -> bytes:
        return b"".join(self._iter_decrypt_bytes_chunked(payload, purpose, key, key_id))

    def _iter_decrypt_bytes_chunked(
        self,
        payload: Mapping[str, Any],
        purpose: str,
        key: bytes,
        key_id: str,
        *,
        chunks=None,
        total_chunks: int | None = None,
    ):
        try:
            plaintext_size = int(payload.get("plaintextSize"))
            chunk_size = int(payload.get("chunkSize"))
        except (TypeError, ValueError) as exc:
            raise PrivacyError("Encrypted byte payload has invalid chunk metadata.") from exc
        if plaintext_size < 0 or chunk_size <= 0:
            raise PrivacyError("Encrypted byte payload has invalid chunk metadata.")
        if chunks is None:
            chunks = payload.get("chunks")
            if not isinstance(chunks, list) or not chunks:
                raise PrivacyError("Encrypted byte payload does not contain chunks.")
            total_chunks = len(chunks)
        if total_chunks is None or total_chunks <= 0:
            raise PrivacyError("Encrypted byte payload has invalid chunk metadata.")
        expected_indexes = set(range(total_chunks))
        seen_indexes = set()
        plaintext_total = 0
        try:
            for entry in chunks:
                if not isinstance(entry, Mapping):
                    raise PrivacyError("Encrypted byte payload contains an invalid chunk.")
                index = int(entry.get("index"))
                if (
                    index not in expected_indexes
                    or index in seen_indexes
                    or index != len(seen_indexes)
                ):
                    raise PrivacyError("Encrypted byte payload contains invalid chunk indexes.")
                nonce = _b64url_decode(str(entry.get("nonce", "")))
                ciphertext = _b64url_decode(str(entry.get("ciphertext", "")))
                plaintext = AESGCM(key).decrypt(  # type: ignore[operator]
                    nonce,
                    ciphertext,
                    self._chunk_bytes_aad(key_id, purpose, index, total_chunks, plaintext_size),
                )
                seen_indexes.add(index)
                plaintext_total += len(plaintext)
                yield plaintext
        except PrivacyError:
            raise
        except Exception as exc:  # noqa: BLE001 - auth/tag/key failures should be user-readable.
            raise PrivacyError(f"Could not decrypt chunked byte payload: {exc}") from exc
        if seen_indexes != expected_indexes:
            raise PrivacyError("Encrypted byte payload is missing chunks.")
        if plaintext_total != plaintext_size:
            raise PrivacyError("Encrypted byte payload decrypted to an unexpected size.")

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
