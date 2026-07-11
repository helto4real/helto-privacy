"""Password-protected privacy keystore shared by Helto node packs.

At rest, data keys (DEKs) live wrapped in a single keystore file
(default ``~/.config/helto/privacy_keystore.json``): a key-encryption key is
derived from the user's password with scrypt and wraps each DEK with
AES-256-GCM. Nothing in that file is usable without the password.

After an unlock, the plain DEKs are cached in a session file under
``$XDG_RUNTIME_DIR/helto`` — per-user tmpfs that the OS wipes on
reboot/logout — together with a random bearer token for the HTTP routes.
That gives the intended lifetime: unlock survives browser refreshes and
ComfyUI restarts, and expires with the machine session.

The cryptographic mechanics remain independent of ComfyUI. Public mutation and
secret/session reads consult the exact-suite activation gate so verification
mode cannot use this module as a bypass.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from .suite_runtime import require_active_process_suite

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    KEYSTORE_CRYPTO_AVAILABLE = True
    KEYSTORE_CRYPTO_IMPORT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - dependency may be absent in ComfyUI installs.
    AESGCM = None  # type: ignore[assignment]
    Scrypt = None  # type: ignore[assignment]
    KEYSTORE_CRYPTO_AVAILABLE = False
    KEYSTORE_CRYPTO_IMPORT_ERROR = str(exc)


KEYSTORE_SCHEMA = "helto.privacy-keystore"
KEYSTORE_VERSION = 1
KEYSTORE_ENV = "HELTO_PRIVACY_KEYSTORE"
SESSION_DIR_ENV = "HELTO_PRIVACY_SESSION_DIR"
KEYSTORE_FILE_NAME = "privacy_keystore.json"
SESSION_FILE_NAME = "privacy_session.json"

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
KEY_BYTES = 32
MIN_PASSWORD_LENGTH = 8

ERROR_LOCKED = "PRIVACY_LOCKED"
ERROR_UNINITIALIZED = "PRIVACY_KEYSTORE_UNINITIALIZED"
ERROR_ALREADY_INITIALIZED = "PRIVACY_KEYSTORE_EXISTS"
ERROR_PASSWORD_INVALID = "PRIVACY_PASSWORD_INVALID"
ERROR_PASSWORD_TOO_SHORT = "PRIVACY_PASSWORD_TOO_SHORT"
ERROR_KEYSTORE_INVALID = "PRIVACY_KEYSTORE_INVALID"


class PrivacyKeystoreError(RuntimeError):
    """Raised when the privacy keystore cannot complete an operation."""


def keystore_path() -> Path:
    configured = str(os.environ.get(KEYSTORE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    config_home = str(os.environ.get("XDG_CONFIG_HOME") or "").strip()
    root = Path(config_home).expanduser() if config_home else Path.home() / ".config"
    return root / "helto" / KEYSTORE_FILE_NAME


def session_path() -> Path:
    configured = str(os.environ.get(SESSION_DIR_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser() / SESSION_FILE_NAME
    runtime_dir = str(os.environ.get("XDG_RUNTIME_DIR") or "").strip()
    if runtime_dir:
        return Path(runtime_dir) / "helto" / SESSION_FILE_NAME
    # Fallback for systems without a runtime dir; usually tmpfs, and the
    # per-uid suffix keeps it private even on shared /tmp.
    return Path(tempfile.gettempdir()) / f"helto-privacy-{os.getuid()}" / SESSION_FILE_NAME


def keystore_exists() -> bool:
    return keystore_path().is_file()


def keystore_status() -> dict[str, Any]:
    initialized = keystore_exists()
    session = _read_session() if initialized else None
    return {
        "keystoreAvailable": KEYSTORE_CRYPTO_AVAILABLE,
        "keystoreInitialized": initialized,
        "keystoreLocked": initialized and session is None,
        "keystorePath": str(keystore_path()),
        "sessionPath": str(session_path()),
    }


def initialize_keystore(
    password: str,
    *,
    legacy_keys: list[tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    """Create the keystore with a fresh primary DEK and unlock it.

    ``legacy_keys`` are (key_id, key) pairs imported as decrypt-only entries
    so envelopes written by the old plaintext key files stay readable.
    """
    require_active_process_suite()
    _require_crypto()
    password = _valid_password(password)
    path = keystore_path()
    if path.is_file():
        raise PrivacyKeystoreError(
            f"{ERROR_ALREADY_INITIALIZED}: Privacy keystore already exists: {path}"
        )

    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    kek = _derive_kek(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    primary_key = secrets.token_bytes(KEY_BYTES)
    primary_key_id = _key_id_for(primary_key)
    entries = [_wrap_entry(kek, primary_key_id, primary_key, primary=True)]
    unlocked: dict[str, bytes] = {primary_key_id: primary_key}

    for key_id, key in legacy_keys or []:
        key_id = str(key_id or "").strip()
        if not key_id or len(key) != KEY_BYTES or key_id in unlocked:
            continue
        entries.append(_wrap_entry(kek, key_id, key, primary=False))
        unlocked[key_id] = key

    payload = {
        "schema": KEYSTORE_SCHEMA,
        "version": KEYSTORE_VERSION,
        "kdf": {
            "name": "scrypt",
            "salt": _b64url_encode(salt),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "keys": entries,
    }
    _write_private_json(path, payload)
    token = _write_session(primary_key_id, unlocked)
    return {"token": token, **keystore_status()}


def unlock_keystore(password: str) -> dict[str, Any]:
    require_active_process_suite()
    _require_crypto()
    payload = _load_keystore()
    kdf = payload.get("kdf") or {}
    try:
        salt = _b64url_decode(str(kdf.get("salt", "")))
        kek = _derive_kek(
            str(password or ""),
            salt,
            int(kdf.get("n") or SCRYPT_N),
            int(kdf.get("r") or SCRYPT_R),
            int(kdf.get("p") or SCRYPT_P),
        )
    except PrivacyKeystoreError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed KDF params should be readable.
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore KDF metadata is invalid: {exc}") from exc

    unlocked: dict[str, bytes] = {}
    primary_key_id = ""
    for entry in payload.get("keys") or []:
        if not isinstance(entry, dict):
            continue
        key_id = str(entry.get("keyId") or "").strip()
        try:
            nonce = _b64url_decode(str(entry.get("nonce", "")))
            wrapped = _b64url_decode(str(entry.get("wrapped_key", "")))
            key = AESGCM(kek).decrypt(nonce, wrapped, _wrap_aad(key_id))  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - GCM auth failure means wrong password.
            raise PrivacyKeystoreError(
                f"{ERROR_PASSWORD_INVALID}: Privacy password is incorrect."
            ) from exc
        if len(key) != KEY_BYTES or not key_id:
            raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore entry '{key_id}' is malformed.")
        unlocked[key_id] = key
        if entry.get("primary"):
            primary_key_id = key_id
    if not unlocked or not primary_key_id:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore has no usable primary key.")

    token = _write_session(primary_key_id, unlocked)
    return {"token": token, **keystore_status()}


def lock_keystore() -> dict[str, Any]:
    path = session_path()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    _invalidate_private_runtimes("lock")
    return keystore_status()


def change_keystore_password(current_password: str, new_password: str) -> dict[str, Any]:
    require_active_process_suite()
    _require_crypto()
    new_password = _valid_password(new_password)
    # Re-verify the current password against the file rather than trusting
    # the session cache.
    unlock_keystore(current_password)
    session = _read_session()
    if session is None:
        raise PrivacyKeystoreError(f"{ERROR_LOCKED}: Privacy keystore is locked.")

    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    kek = _derive_kek(new_password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    entries = [
        _wrap_entry(kek, key_id, key, primary=(key_id == session["primary_key_id"]))
        for key_id, key in session["keys"].items()
    ]
    payload = {
        "schema": KEYSTORE_SCHEMA,
        "version": KEYSTORE_VERSION,
        "kdf": {
            "name": "scrypt",
            "salt": _b64url_encode(salt),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "keys": entries,
    }
    _write_private_json(keystore_path(), payload)
    token = _write_session(session["primary_key_id"], session["keys"])
    return {"token": token, **keystore_status()}


def add_keys_to_keystore(password: str, keys: list[tuple[str, bytes]]) -> dict[str, Any]:
    """Import additional decrypt-only keys into an existing keystore.

    The password is verified against the on-disk keystore, duplicate key IDs
    are ignored, and the refreshed session contains every decryptable key.
    """
    require_active_process_suite()
    _require_crypto()
    unlock_keystore(password)
    payload = _load_keystore()
    session = _read_session()
    if session is None:
        raise PrivacyKeystoreError(f"{ERROR_LOCKED}: Privacy keystore is locked.")

    kek = _kek_from_payload(password, payload)
    entries = list(payload.get("keys") or [])
    existing_ids = {
        str(entry.get("keyId") or "").strip()
        for entry in entries
        if isinstance(entry, dict)
    }
    unlocked = dict(session["keys"])

    for key_id, key in keys or []:
        key_id = str(key_id or "").strip()
        if not key_id or not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
            continue
        key_bytes = bytes(key)
        if key_id in existing_ids or key_id in unlocked:
            continue
        entries.append(_wrap_entry(kek, key_id, key_bytes, primary=False))
        existing_ids.add(key_id)
        unlocked[key_id] = key_bytes

    payload["keys"] = entries
    _write_private_json(keystore_path(), payload)
    token = _write_session(session["primary_key_id"], unlocked)
    return {"token": token, **keystore_status()}


def rotate_primary_key(password: str) -> dict[str, Any]:
    """Generate a fresh primary key and keep older keys for decryption."""
    require_active_process_suite()
    _require_crypto()
    unlock_keystore(password)
    payload = _load_keystore()
    session = _read_session()
    if session is None:
        raise PrivacyKeystoreError(f"{ERROR_LOCKED}: Privacy keystore is locked.")

    kek = _kek_from_payload(password, payload)
    unlocked = dict(session["keys"])
    new_key = secrets.token_bytes(KEY_BYTES)
    new_key_id = _key_id_for(new_key)
    while new_key_id in unlocked:
        new_key = secrets.token_bytes(KEY_BYTES)
        new_key_id = _key_id_for(new_key)

    entries = [_wrap_entry(kek, new_key_id, new_key, primary=True)]
    for key_id, key in unlocked.items():
        entries.append(_wrap_entry(kek, key_id, key, primary=False))
    unlocked[new_key_id] = new_key
    payload["keys"] = entries
    _write_private_json(keystore_path(), payload)
    token = _write_session(new_key_id, unlocked)
    return {"token": token, **keystore_status()}


def primary_session_key() -> tuple[bytes, str]:
    """Return (key, key_id) for encryption, or raise a locked/uninitialized error."""
    require_active_process_suite()
    session = _require_session()
    key_id = session["primary_key_id"]
    return session["keys"][key_id], key_id


def session_key_for(key_id: str) -> bytes | None:
    require_active_process_suite()
    session = _read_session()
    if session is None:
        return None
    return session["keys"].get(str(key_id or "").strip())


def session_token() -> str | None:
    require_active_process_suite()
    session = _read_session()
    return session["token"] if session else None


def _require_crypto() -> None:
    if not KEYSTORE_CRYPTO_AVAILABLE:
        raise PrivacyKeystoreError(
            f"Python package 'cryptography' is required for the privacy keystore: {KEYSTORE_CRYPTO_IMPORT_ERROR}"
        )


def _valid_password(password: str) -> str:
    password = str(password or "")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PrivacyKeystoreError(
            f"{ERROR_PASSWORD_TOO_SHORT}: Privacy password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    return password


def _derive_kek(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=n, r=r, p=p)  # type: ignore[operator]
    return kdf.derive(password.encode("utf-8"))


def _kek_from_payload(password: str, payload: dict[str, Any]) -> bytes:
    kdf = payload.get("kdf") or {}
    try:
        salt = _b64url_decode(str(kdf.get("salt", "")))
        return _derive_kek(
            str(password or ""),
            salt,
            int(kdf.get("n") or SCRYPT_N),
            int(kdf.get("r") or SCRYPT_R),
            int(kdf.get("p") or SCRYPT_P),
        )
    except PrivacyKeystoreError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed KDF params should be readable.
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore KDF metadata is invalid: {exc}") from exc


def _wrap_aad(key_id: str) -> bytes:
    return f"{KEYSTORE_SCHEMA}|{KEYSTORE_VERSION}|{key_id}".encode("utf-8")


def _wrap_entry(kek: bytes, key_id: str, key: bytes, *, primary: bool) -> dict[str, Any]:
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(kek).encrypt(nonce, key, _wrap_aad(key_id))  # type: ignore[operator]
    entry = {
        "keyId": key_id,
        "nonce": _b64url_encode(nonce),
        "wrapped_key": _b64url_encode(wrapped),
    }
    if primary:
        entry["primary"] = True
    return entry


def _key_id_for(key: bytes) -> str:
    import hashlib

    return _b64url_encode(hashlib.sha256(key).digest()[:12])


def _load_keystore() -> dict[str, Any]:
    path = keystore_path()
    if not path.is_file():
        raise PrivacyKeystoreError(
            f"{ERROR_UNINITIALIZED}: Privacy keystore has not been created yet: {path}"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - unreadable keystore should be a readable error.
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Could not read keystore '{path}': {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != KEYSTORE_SCHEMA:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: File is not a Helto privacy keystore: {path}")
    return payload


def _require_session() -> dict[str, Any]:
    if not keystore_exists():
        raise PrivacyKeystoreError(
            f"{ERROR_UNINITIALIZED}: Privacy keystore has not been created yet."
        )
    session = _read_session()
    if session is None:
        raise PrivacyKeystoreError(
            f"{ERROR_LOCKED}: Privacy keystore is locked. Unlock it with your privacy password."
        )
    return session


def _read_session() -> dict[str, Any] | None:
    path = session_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    keys: dict[str, bytes] = {}
    for entry in payload.get("keys") or []:
        try:
            key = _b64url_decode(str(entry.get("key", "")))
            key_id = str(entry.get("keyId") or "").strip()
        except Exception:  # noqa: BLE001 - a corrupt session cache is treated as locked.
            return None
        if key_id and len(key) == KEY_BYTES:
            keys[key_id] = key
    primary_key_id = str(payload.get("primaryKeyId") or "").strip()
    token = str(payload.get("token") or "").strip()
    if not keys or primary_key_id not in keys or not token:
        return None
    return {"keys": keys, "primary_key_id": primary_key_id, "token": token}


def _write_session(primary_key_id: str, keys: dict[str, bytes]) -> str:
    token = secrets.token_urlsafe(32)
    payload = {
        "version": KEYSTORE_VERSION,
        "token": token,
        "primaryKeyId": primary_key_id,
        "keys": [
            {"keyId": key_id, "key": _b64url_encode(key)}
            for key_id, key in keys.items()
        ],
    }
    _write_private_json(session_path(), payload)
    _invalidate_private_runtimes("session-replaced")
    return token


def _invalidate_private_runtimes(reason: str) -> None:
    from .artifacts import invalidate_artifact_session
    from .execution import invalidate_execution_session

    invalidate_artifact_session(reason)
    invalidate_execution_session(reason)


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
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
