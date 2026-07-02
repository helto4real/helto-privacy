"""Schema-parameterized privacy envelopes for Helto node packs."""

from __future__ import annotations

import base64
import hashlib
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
    codec = PrivacyEnvelopeCodec("helto.legacy-migration")
    path = key_path(legacy_dir)
    legacy_keys: list[tuple[str, bytes]] = []
    if path.exists():
        try:
            legacy_key, legacy_key_id = codec._load_or_create_key(legacy_dir, create=False)
            legacy_keys.append((legacy_key_id, legacy_key))
        except PrivacyError as exc:
            raise PrivacyError(f"Cannot migrate existing privacy key file '{path}': {exc}") from exc

    try:
        if default_keystore.keystore_exists():
            result = (
                default_keystore.add_keys_to_keystore(password, legacy_keys)
                if legacy_keys
                else default_keystore.unlock_keystore(password)
            )
        else:
            result = default_keystore.initialize_keystore(password, legacy_keys=legacy_keys)
    except PrivacyKeystoreError as exc:
        raise PrivacyError(str(exc)) from exc

    if legacy_keys:
        migrated = path.with_name(path.name + ".migrated")
        try:
            path.replace(migrated)
            os.chmod(migrated, 0o600)
        except OSError:
            pass
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
        path = key_path(base_dir)
        return {
            "available": CRYPTO_AVAILABLE,
            "algorithm": ALGORITHM,
            "keyExists": path.exists(),
            "keyPath": str(path),
            "error": "" if CRYPTO_AVAILABLE else f"Python package 'cryptography' is required: {CRYPTO_IMPORT_ERROR}",
            **self.key_provider.keystore_status(),
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
        key, key_id = self._load_or_create_key(base_dir, create=True)
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
    ) -> dict[str, Any]:
        key, key_id = self._load_or_create_key(base_dir, create=True)
        chunk_size = self._byte_chunk_size()
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
            return self._decrypt_bytes_chunked(payload, purpose, key, key_id)
        if schema != self.byte_schema:
            raise PrivacyError("Data is not an encrypted byte payload.")
        try:
            nonce = _b64url_decode(str(payload.get("nonce", "")))
            ciphertext = _b64url_decode(str(payload.get("ciphertext", "")))
            return AESGCM(key).decrypt(nonce, ciphertext, self._bytes_aad(key_id, purpose))  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - auth/tag/key failures should be user-readable.
            raise PrivacyError(f"Could not decrypt byte payload: {exc}") from exc

    def _load_or_create_key(
        self,
        base_dir: str | os.PathLike[str] | None = None,
        create: bool = True,
    ) -> tuple[bytes, str]:
        if not CRYPTO_AVAILABLE:
            raise PrivacyError(f"Python package 'cryptography' is required for privacy mode: {CRYPTO_IMPORT_ERROR}")

        if base_dir is None and self.key_provider.keystore_exists():
            try:
                return self.key_provider.primary_session_key()
            except PrivacyKeystoreError as exc:
                raise PrivacyError(str(exc)) from exc

        path = key_path(base_dir)
        if path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                key = _b64url_decode(str(payload.get("key", "")))
                key_id = str(payload.get("keyId", "")).strip()
            except Exception as exc:  # noqa: BLE001 - bad local key should become a readable privacy error.
                raise PrivacyError(f"Could not read privacy key file '{path}': {exc}") from exc
            if len(key) != 32 or not key_id:
                raise PrivacyError(f"Privacy key file '{path}' is malformed.")
            return key, key_id

        if not create:
            raise PrivacyError(f"Privacy key file is missing: {path}")

        key = secrets.token_bytes(32)
        key_id = _b64url_encode(hashlib.sha256(key).digest()[:12])
        _write_private_json(
            path,
            {
                "version": 1,
                "algorithm": ALGORITHM,
                "keyId": key_id,
                "key": _b64url_encode(key),
            },
        )
        return key, key_id

    def _key_for_payload(
        self,
        payload_key_id: str,
        base_dir: str | os.PathLike[str] | None,
        mismatch_error: str,
    ) -> bytes:
        key, key_id = self._load_or_create_key(base_dir, create=False)
        if payload_key_id == key_id:
            return key
        if base_dir is None and self.key_provider.keystore_exists():
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
        try:
            plaintext_size = int(payload.get("plaintextSize"))
            chunk_size = int(payload.get("chunkSize"))
        except (TypeError, ValueError) as exc:
            raise PrivacyError("Encrypted byte payload has invalid chunk metadata.") from exc
        if plaintext_size < 0 or chunk_size <= 0:
            raise PrivacyError("Encrypted byte payload has invalid chunk metadata.")
        chunks = payload.get("chunks")
        if not isinstance(chunks, list) or not chunks:
            raise PrivacyError("Encrypted byte payload does not contain chunks.")
        total_chunks = len(chunks)
        expected_indexes = set(range(total_chunks))
        seen_indexes = set()
        plaintext_parts: list[bytes] = [b""] * total_chunks
        try:
            for entry in chunks:
                if not isinstance(entry, Mapping):
                    raise PrivacyError("Encrypted byte payload contains an invalid chunk.")
                index = int(entry.get("index"))
                if index not in expected_indexes or index in seen_indexes:
                    raise PrivacyError("Encrypted byte payload contains invalid chunk indexes.")
                nonce = _b64url_decode(str(entry.get("nonce", "")))
                ciphertext = _b64url_decode(str(entry.get("ciphertext", "")))
                plaintext_parts[index] = AESGCM(key).decrypt(  # type: ignore[operator]
                    nonce,
                    ciphertext,
                    self._chunk_bytes_aad(key_id, purpose, index, total_chunks, plaintext_size),
                )
                seen_indexes.add(index)
        except PrivacyError:
            raise
        except Exception as exc:  # noqa: BLE001 - auth/tag/key failures should be user-readable.
            raise PrivacyError(f"Could not decrypt chunked byte payload: {exc}") from exc
        if seen_indexes != expected_indexes:
            raise PrivacyError("Encrypted byte payload is missing chunks.")
        plaintext = b"".join(plaintext_parts)
        if len(plaintext) != plaintext_size:
            raise PrivacyError("Encrypted byte payload decrypted to an unexpected size.")
        return plaintext


def _write_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(text, encoding="utf-8")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    tmp_path.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
