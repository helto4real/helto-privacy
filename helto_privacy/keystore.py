"""Password- or YubiKey-protected privacy keystore shared by Helto node packs.

At rest, data keys (DEKs) live wrapped in a single keystore file
(default ``~/.config/helto/privacy_keystore.json``): a key-encryption key is
derived from the user's password or from a YubiKey FIDO2 hmac-secret credential,
then wraps each DEK with AES-256-GCM.

After an unlock, the plain DEKs are cached in a session file under
``$XDG_RUNTIME_DIR/helto`` — per-user tmpfs that the OS wipes on
reboot/logout — together with a random bearer token for the HTTP routes.
That gives the intended lifetime: unlock survives browser refreshes and
ComfyUI restarts, and expires with the machine session.

The optional hardware-key dependency is imported lazily so password-only
installations remain lightweight.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

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
KEYSTORE_VERSION = 2
LEGACY_KEYSTORE_VERSION = 1
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
MAX_PASSWORD_BYTES = 4096
MAX_KEYSTORE_BYTES = 1024 * 1024
MAX_SESSION_BYTES = 1024 * 1024
MAX_KEY_ENTRIES = 128
MIN_SCRYPT_N = 2**10
MAX_SCRYPT_N = 2**18
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4
MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024
MAX_SCRYPT_WORK = 2**22

ERROR_LOCKED = "PRIVACY_LOCKED"
ERROR_UNINITIALIZED = "PRIVACY_KEYSTORE_UNINITIALIZED"
ERROR_ALREADY_INITIALIZED = "PRIVACY_KEYSTORE_EXISTS"
ERROR_PASSWORD_INVALID = "PRIVACY_PASSWORD_INVALID"
ERROR_PASSWORD_TOO_SHORT = "PRIVACY_PASSWORD_TOO_SHORT"
ERROR_KEYSTORE_INVALID = "PRIVACY_KEYSTORE_INVALID"
ERROR_AUTH_METHOD_INVALID = "PRIVACY_AUTH_METHOD_INVALID"

AUTH_PASSWORD = "password"
AUTH_YUBIKEY_FIDO2 = "yubikey-fido2"
YUBIKEY_SECRET_ALGORITHM = "FIDO2-HMAC-SECRET-SHA256"


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
    unlock_method = None
    touch_required = False
    if initialized:
        try:
            unlock_method = _unlock_method(_load_keystore())
            touch_required = unlock_method == AUTH_YUBIKEY_FIDO2
        except PrivacyKeystoreError:
            unlock_method = "unknown"
    try:
        from .fido2_provider import runtime_available

        yubikey_available = runtime_available()
    except Exception:
        yubikey_available = False
    return {
        "keystoreAvailable": KEYSTORE_CRYPTO_AVAILABLE,
        "keystoreInitialized": initialized,
        "keystoreLocked": initialized and session is None,
        "unlockMethod": unlock_method,
        "yubikeyAvailable": yubikey_available,
        "touchRequired": touch_required,
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
    _require_crypto()
    password = _valid_password(password)
    path = keystore_path()
    if path.is_file():
        raise PrivacyKeystoreError(
            f"{ERROR_ALREADY_INITIALIZED}: Privacy keystore already exists."
        )

    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    kek = _derive_kek(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    primary_key = secrets.token_bytes(KEY_BYTES)
    primary_key_id = _key_id_for(primary_key)
    entries = [
        _wrap_entry(
            kek,
            primary_key_id,
            primary_key,
            primary=True,
            version=KEYSTORE_VERSION,
        )
    ]
    unlocked: dict[str, bytes] = {primary_key_id: primary_key}

    for key_id, key in legacy_keys or []:
        key_id = str(key_id or "").strip()
        if not key_id or len(key) != KEY_BYTES or key_id in unlocked:
            continue
        entries.append(
            _wrap_entry(kek, key_id, key, primary=False, version=KEYSTORE_VERSION)
        )
        unlocked[key_id] = key

    payload = {
        "schema": KEYSTORE_SCHEMA,
        "version": KEYSTORE_VERSION,
        "unlock": {"method": AUTH_PASSWORD},
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


def unlock_keystore(
    credential: str,
    *,
    legacy_keys: list[tuple[str, bytes]] | None = None,
    fido_provider: Any = None,
) -> dict[str, Any]:
    """Unlock with the store's password or YubiKey PIN and refresh the session."""
    _require_crypto()
    payload, kek, unlocked, primary_key_id = _unlock_material(
        credential, fido_provider=fido_provider
    )
    changed = _merge_keys(payload, kek, unlocked, legacy_keys or [])
    if changed:
        _write_private_json(keystore_path(), payload)
    token = _write_session(primary_key_id, unlocked)
    return {"token": token, **keystore_status()}


def lock_keystore() -> dict[str, Any]:
    path = session_path()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return keystore_status()


def change_keystore_password(current_password: str, new_password: str) -> dict[str, Any]:
    _require_crypto()
    new_password = _valid_password(new_password)
    if _unlock_method(_load_keystore()) != AUTH_PASSWORD:
        raise PrivacyKeystoreError(
            f"{ERROR_AUTH_METHOD_INVALID}: A YubiKey-only keystore has no privacy password."
        )
    payload, _old_kek, unlocked, primary_key_id = _unlock_material(current_password)

    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    kek = _derive_kek(new_password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    entries = [
        _wrap_entry(
            kek,
            key_id,
            key,
            primary=(key_id == primary_key_id),
            version=KEYSTORE_VERSION,
        )
        for key_id, key in unlocked.items()
    ]
    payload = {
        "schema": KEYSTORE_SCHEMA,
        "version": KEYSTORE_VERSION,
        "unlock": {"method": AUTH_PASSWORD},
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
    token = _write_session(primary_key_id, unlocked)
    return {"token": token, **keystore_status()}


def add_keys_to_keystore(
    credential: str,
    keys: list[tuple[str, bytes]],
    *,
    fido_provider: Any = None,
) -> dict[str, Any]:
    """Import additional decrypt-only keys into an existing keystore.

    The credential is verified against the on-disk keystore, duplicate key IDs
    are ignored, and the refreshed session contains every decryptable key.
    """
    return unlock_keystore(
        credential, legacy_keys=keys, fido_provider=fido_provider
    )


def rotate_primary_key(credential: str, *, fido_provider: Any = None) -> dict[str, Any]:
    """Generate a fresh primary key and keep older keys for decryption."""
    _require_crypto()
    payload, kek, unlocked, _old_primary_key_id = _unlock_material(
        credential, fido_provider=fido_provider
    )
    new_key = secrets.token_bytes(KEY_BYTES)
    new_key_id = _key_id_for(new_key)
    while new_key_id in unlocked:
        new_key = secrets.token_bytes(KEY_BYTES)
        new_key_id = _key_id_for(new_key)

    version = int(payload["version"])
    entries = [
        _wrap_entry(kek, new_key_id, new_key, primary=True, version=version)
    ]
    for key_id, key in unlocked.items():
        entries.append(
            _wrap_entry(kek, key_id, key, primary=False, version=version)
        )
    unlocked[new_key_id] = new_key
    payload["keys"] = entries
    _write_private_json(keystore_path(), payload)
    token = _write_session(new_key_id, unlocked)
    return {"token": token, **keystore_status()}


def enroll_yubikey_keystore(
    *,
    pin: str,
    current_password: str | None = None,
    device_path: str | None = None,
    fido_provider: Any = None,
) -> dict[str, Any]:
    """Create or convert a keystore using a protected FIDO2 credential."""
    _require_crypto()
    if keystore_exists():
        payload = _load_keystore()
        if _unlock_method(payload) != AUTH_PASSWORD:
            raise PrivacyKeystoreError(
                f"{ERROR_AUTH_METHOD_INVALID}: Privacy keystore already uses a YubiKey."
            )
        if current_password is None:
            raise PrivacyKeystoreError(
                f"{ERROR_PASSWORD_INVALID}: Current privacy password is required for conversion."
            )
        _payload, _old_kek, unlocked, primary_key_id = _unlock_material(
            current_password
        )
    else:
        primary_key = secrets.token_bytes(KEY_BYTES)
        primary_key_id = _key_id_for(primary_key)
        unlocked = {primary_key_id: primary_key}

    provider = fido_provider or _default_fido_provider()
    try:
        enrollment = provider.enroll(
            pin=pin,
            device_path=device_path,
        )
        identity = enrollment.identity
        kek = enrollment.secret
        if len(kek) != KEY_BYTES:
            raise PrivacyKeystoreError(
                "PRIVACY_YUBIKEY_ENROLLMENT_FAILED: FIDO2 hmac-secret verification failed."
            )
        entries = [
            _wrap_entry(
                kek,
                key_id,
                key,
                primary=(key_id == primary_key_id),
                version=KEYSTORE_VERSION,
            )
            for key_id, key in unlocked.items()
        ]
        payload = {
            "schema": KEYSTORE_SCHEMA,
            "version": KEYSTORE_VERSION,
            "unlock": {
                "method": AUTH_YUBIKEY_FIDO2,
                "rpId": "helto-privacy.local",
                "credentialId": _b64url_encode(identity.credential_id),
                "aaguid": _b64url_encode(identity.aaguid),
                "credentialPublicKey": _b64url_encode(identity.public_key_cbor),
                "publicKeySha256": identity.public_key_sha256,
                "salt": _b64url_encode(identity.salt),
                "secretAlgorithm": YUBIKEY_SECRET_ALGORITHM,
                "credentialProtection": "userVerificationRequired",
                "userVerification": "required",
                "userPresence": "required",
                "residentKey": False,
            },
            "keys": entries,
        }
        _validate_keystore_payload(payload)
        try:
            session_path().unlink(missing_ok=True)
        except OSError as exc:
            raise PrivacyKeystoreError(
                f"{ERROR_LOCKED}: Could not clear the existing privacy session before conversion: {exc}"
            ) from exc
        _write_private_json(keystore_path(), payload)
    except PrivacyKeystoreError:
        raise
    except Exception as exc:
        message = str(exc)
        if not message.startswith("PRIVACY_"):
            message = f"PRIVACY_YUBIKEY_ENROLLMENT_FAILED: {message}"
        raise PrivacyKeystoreError(message) from exc

    token = _write_session(primary_key_id, unlocked)
    return {
        "token": token,
        **keystore_status(),
    }


def primary_session_key() -> tuple[bytes, str]:
    """Return (key, key_id) for encryption, or raise a locked/uninitialized error."""
    session = _require_session()
    key_id = session["primary_key_id"]
    return session["keys"][key_id], key_id


def session_key_for(key_id: str) -> bytes | None:
    session = _read_session()
    if session is None:
        return None
    return session["keys"].get(str(key_id or "").strip())


def session_token() -> str | None:
    session = _read_session()
    return session["token"] if session else None


def keystore_unlock_method() -> str | None:
    """Return the configured unlock method without disclosing device metadata."""
    if not keystore_exists():
        return None
    return _unlock_method(_load_keystore())


def _unlock_method(payload: dict[str, Any]) -> str:
    if int(payload.get("version") or 0) == LEGACY_KEYSTORE_VERSION:
        return AUTH_PASSWORD
    unlock = payload.get("unlock") or {}
    return str(unlock.get("method") or "")


def _unlock_material(
    credential: str,
    *,
    fido_provider: Any = None,
) -> tuple[dict[str, Any], bytes, dict[str, bytes], str]:
    credential = _bounded_password(credential)
    payload = _load_keystore()
    method = _unlock_method(payload)
    if method == AUTH_PASSWORD:
        kek = _kek_from_payload(credential, payload)
        invalid_message = f"{ERROR_PASSWORD_INVALID}: Privacy password is incorrect."
    elif method == AUTH_YUBIKEY_FIDO2:
        unlock = payload["unlock"]
        from .fido2_provider import Fido2Identity, Fido2ProviderError

        identity = Fido2Identity(
            credential_id=_b64url_decode(str(unlock["credentialId"])),
            aaguid=_b64url_decode(str(unlock["aaguid"])),
            public_key_cbor=_b64url_decode(str(unlock["credentialPublicKey"])),
            public_key_sha256=str(unlock["publicKeySha256"]),
            salt=_b64url_decode(str(unlock["salt"])),
        )
        try:
            kek = (fido_provider or _default_fido_provider()).derive(
                identity, str(credential or "")
            )
        except Fido2ProviderError as exc:
            raise PrivacyKeystoreError(str(exc)) from exc
        except Exception as exc:
            raise PrivacyKeystoreError(
                f"PRIVACY_YUBIKEY_UNAVAILABLE: FIDO2 YubiKey unlock failed: {exc}"
            ) from exc
        if len(kek) != KEY_BYTES:
            raise PrivacyKeystoreError(
                f"{ERROR_KEYSTORE_INVALID}: YubiKey returned an invalid keystore key."
            )
        invalid_message = f"{ERROR_KEYSTORE_INVALID}: YubiKey keystore authentication failed."
    else:
        raise PrivacyKeystoreError(
            f"{ERROR_AUTH_METHOD_INVALID}: Keystore unlock method is unsupported."
        )

    unlocked: dict[str, bytes] = {}
    primary_key_id = ""
    version = int(payload["version"])
    for entry in payload.get("keys") or []:
        key_id = str(entry.get("keyId") or "").strip()
        try:
            nonce = _b64url_decode(str(entry.get("nonce", "")))
            wrapped = _b64url_decode(str(entry.get("wrapped_key", "")))
            key = AESGCM(kek).decrypt(  # type: ignore[operator]
                nonce, wrapped, _wrap_aad(key_id, version=version)
            )
        except Exception as exc:
            raise PrivacyKeystoreError(invalid_message) from exc
        if len(key) != KEY_BYTES or not key_id:
            raise PrivacyKeystoreError(
                f"{ERROR_KEYSTORE_INVALID}: Keystore entry '{key_id}' is malformed."
            )
        unlocked[key_id] = key
        if entry.get("primary"):
            primary_key_id = key_id
    if not unlocked or not primary_key_id:
        raise PrivacyKeystoreError(
            f"{ERROR_KEYSTORE_INVALID}: Keystore has no usable primary key."
        )
    return payload, kek, unlocked, primary_key_id


def _merge_keys(
    payload: dict[str, Any],
    kek: bytes,
    unlocked: dict[str, bytes],
    keys: list[tuple[str, bytes]],
) -> bool:
    entries = list(payload.get("keys") or [])
    existing_ids = {str(entry.get("keyId") or "").strip() for entry in entries}
    changed = False
    for key_id, key in keys:
        key_id = str(key_id or "").strip()
        if not key_id or not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
            continue
        if key_id in existing_ids or key_id in unlocked:
            continue
        key_bytes = bytes(key)
        entries.append(
            _wrap_entry(
                kek,
                key_id,
                key_bytes,
                primary=False,
                version=int(payload["version"]),
            )
        )
        existing_ids.add(key_id)
        unlocked[key_id] = key_bytes
        changed = True
    if changed:
        payload["keys"] = entries
    return changed


def _default_fido_provider():
    from .fido2_provider import YubiKeyFido2Provider

    return YubiKeyFido2Provider()


def _require_crypto() -> None:
    if not KEYSTORE_CRYPTO_AVAILABLE:
        raise PrivacyKeystoreError(
            f"Python package 'cryptography' is required for the privacy keystore: {KEYSTORE_CRYPTO_IMPORT_ERROR}"
        )


def _valid_password(password: str) -> str:
    password = _bounded_password(password)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PrivacyKeystoreError(
            f"{ERROR_PASSWORD_TOO_SHORT}: Privacy password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    return password


def _bounded_password(password: str) -> str:
    password = str(password or "")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PrivacyKeystoreError(
            f"{ERROR_PASSWORD_INVALID}: Privacy password is too long."
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


def _wrap_aad(key_id: str, *, version: int) -> bytes:
    return f"{KEYSTORE_SCHEMA}|{version}|{key_id}".encode("utf-8")


def _wrap_entry(
    kek: bytes,
    key_id: str,
    key: bytes,
    *,
    primary: bool,
    version: int,
) -> dict[str, Any]:
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(kek).encrypt(  # type: ignore[operator]
        nonce, key, _wrap_aad(key_id, version=version)
    )
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
            f"{ERROR_UNINITIALIZED}: Privacy keystore has not been created yet."
        )
    try:
        if path.stat().st_size > MAX_KEYSTORE_BYTES:
            raise PrivacyKeystoreError(
                f"{ERROR_KEYSTORE_INVALID}: Keystore file is too large."
            )
        payload = json.loads(path.read_text(encoding="utf-8"))
    except PrivacyKeystoreError:
        raise
    except Exception as exc:  # noqa: BLE001 - unreadable keystore should be a readable error.
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Could not read privacy keystore: {exc}") from exc
    return _validate_keystore_payload(payload)


def _validate_keystore_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != KEYSTORE_SCHEMA:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: File is not a Helto privacy keystore.")
    version = payload.get("version")
    if version not in (LEGACY_KEYSTORE_VERSION, KEYSTORE_VERSION):
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore version is unsupported.")

    method = _unlock_method(payload)
    if method == AUTH_PASSWORD:
        _validate_password_kdf(payload)
    elif method == AUTH_YUBIKEY_FIDO2 and version == KEYSTORE_VERSION:
        _validate_yubikey_unlock(payload.get("unlock"))
    else:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore unlock method is unsupported.")

    entries = payload.get("keys")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_KEY_ENTRIES:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore key list is invalid.")
    seen_ids: set[str] = set()
    primary_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore key entry is invalid.")
        key_id = str(entry.get("keyId") or "").strip()
        if not key_id or len(key_id) > 128 or key_id in seen_ids:
            raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore key identifier is invalid.")
        seen_ids.add(key_id)
        try:
            nonce = _b64url_decode(str(entry.get("nonce") or ""))
            wrapped = _b64url_decode(str(entry.get("wrapped_key") or ""))
        except Exception as exc:
            raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore key encoding is invalid.") from exc
        if len(nonce) != 12 or len(wrapped) != KEY_BYTES + 16:
            raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore key entry is malformed.")
        if entry.get("primary") is True:
            primary_count += 1
    if primary_count != 1:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore must contain one primary key.")
    return payload


def _validate_password_kdf(payload: dict[str, Any]) -> None:
    kdf = payload.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore KDF is unsupported.")
    try:
        salt = _b64url_decode(str(kdf.get("salt") or ""))
        n = _strict_int(kdf.get("n"))
        r = _strict_int(kdf.get("r"))
        p = _strict_int(kdf.get("p"))
    except Exception as exc:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore KDF metadata is invalid.") from exc
    if not 16 <= len(salt) <= 64:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore KDF salt is invalid.")
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore scrypt n is outside supported bounds.")
    if not 1 <= r <= MAX_SCRYPT_R or not 1 <= p <= MAX_SCRYPT_P:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore scrypt parameters are outside supported bounds.")
    if 128 * n * r > MAX_SCRYPT_MEMORY_BYTES or n * r * p > MAX_SCRYPT_WORK:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: Keystore scrypt cost is outside supported bounds.")


def _validate_yubikey_unlock(value: Any) -> None:
    if not isinstance(value, dict):
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: YubiKey metadata is missing.")
    try:
        credential_id = _b64url_decode(str(value.get("credentialId") or ""))
        aaguid = _b64url_decode(str(value.get("aaguid") or ""))
        public_key = _b64url_decode(str(value.get("credentialPublicKey") or ""))
        fingerprint = _b64url_decode(str(value.get("publicKeySha256") or ""))
        salt = _b64url_decode(str(value.get("salt") or ""))
    except Exception as exc:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: YubiKey metadata is malformed.") from exc
    if not credential_id or len(credential_id) > 1024 or len(aaguid) != 16:
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: YubiKey identity is invalid.")
    expected = {
        "method": AUTH_YUBIKEY_FIDO2,
        "rpId": "helto-privacy.local",
        "secretAlgorithm": YUBIKEY_SECRET_ALGORITHM,
        "credentialProtection": "userVerificationRequired",
        "userVerification": "required",
        "userPresence": "required",
        "residentKey": False,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise PrivacyKeystoreError(f"{ERROR_KEYSTORE_INVALID}: YubiKey policies are invalid.")
    if (
        not 32 <= len(public_key) <= 1024
        or len(fingerprint) != 32
        or len(salt) != KEY_BYTES
        or not secrets.compare_digest(fingerprint, hashlib.sha256(public_key).digest())
    ):
        raise PrivacyKeystoreError(
            f"{ERROR_KEYSTORE_INVALID}: YubiKey credential metadata is malformed."
        )


def _strict_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("parameter is not an integer")
    return value


def _require_session() -> dict[str, Any]:
    if not keystore_exists():
        raise PrivacyKeystoreError(
            f"{ERROR_UNINITIALIZED}: Privacy keystore has not been created yet."
        )
    session = _read_session()
    if session is None:
        raise PrivacyKeystoreError(
            f"{ERROR_LOCKED}: Privacy keystore is locked. Authenticate to unlock it."
        )
    return session


def _read_session() -> dict[str, Any] | None:
    path = session_path()
    try:
        if path.stat().st_size > MAX_SESSION_BYTES:
            return None
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
    return token


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
    return base64.b64decode((value + padding).encode("ascii"), altchars=b"-_", validate=True)
