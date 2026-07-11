import json
from concurrent.futures import ThreadPoolExecutor

import pytest

import helto_privacy.envelope as envelope_module
import helto_privacy.keystore as keystore
from helto_privacy.envelope import (
    PrivacyEnvelopeCodec,
    PrivacyError,
    initialize_keystore_with_legacy_migration,
)
from helto_privacy.guard import check_privacy_token
from helto_privacy.keystore import (
    KEYSTORE_CRYPTO_AVAILABLE,
    PrivacyKeystoreError,
)
from helto_privacy.suite_runtime import SuiteBlockedError
from _legacy_envelope_fixture import write_legacy_state_fixture

pytestmark = pytest.mark.skipif(
    not KEYSTORE_CRYPTO_AVAILABLE,
    reason="cryptography package is required for privacy keystore tests",
)

PASSWORD = "correct horse battery"
DIRECTOR_SCHEMA = "helto.timeline-director"


def test_initialize_unlock_lock_lifecycle():
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    status = codec.crypto_status()
    assert status["keystoreInitialized"] is False

    result = initialize_keystore_with_legacy_migration(PASSWORD, envelope_module.config_dir())
    assert result["token"]
    assert result["keystoreInitialized"] is True
    assert result["keystoreLocked"] is False
    assert keystore.session_token() == result["token"]

    envelope = codec.encrypt_state({"secret": "prompt"})
    assert codec.decrypt_state(envelope) == {"secret": "prompt"}

    keystore.lock_keystore()
    assert codec.crypto_status()["keystoreLocked"] is True
    assert keystore.session_token() is None
    with pytest.raises(PrivacyError, match="PRIVACY_LOCKED"):
        codec.decrypt_state(envelope)
    with pytest.raises(PrivacyError, match="PRIVACY_LOCKED"):
        codec.encrypt_state({"secret": "prompt"})

    unlocked = keystore.unlock_keystore(PASSWORD)
    assert unlocked["token"]
    assert unlocked["token"] != result["token"]
    assert codec.decrypt_state(envelope) == {"secret": "prompt"}


def test_direct_keystore_writers_and_secret_reads_require_active_suite(
    monkeypatch,
    isolated_privacy_paths,
):
    monkeypatch.setattr(
        keystore,
        "require_active_process_suite",
        isolated_privacy_paths[2],
    )

    blocked_operations = (
        lambda: keystore.initialize_keystore(PASSWORD),
        lambda: keystore.unlock_keystore(PASSWORD),
        lambda: keystore.change_keystore_password(PASSWORD, "new password"),
        lambda: keystore.add_keys_to_keystore(PASSWORD, []),
        lambda: keystore.import_decrypt_only_key_verified(
            PASSWORD,
            "synthetic-key",
            bytes(range(32)),
        ),
        lambda: keystore.rotate_primary_key(PASSWORD),
        keystore.primary_session_key,
        lambda: keystore.session_key_for("opaque-key"),
        keystore.session_token,
    )
    for operation in blocked_operations:
        with pytest.raises(SuiteBlockedError) as blocked:
            operation()
        assert blocked.value.code == "suite_incomplete"

    assert keystore.lock_keystore()["keystoreInitialized"] is False


def test_route_guard_blocks_before_keystore_initialization_when_suite_inactive(
    monkeypatch,
    isolated_privacy_paths,
):
    import helto_privacy.guard as guard

    monkeypatch.setattr(
        guard,
        "require_active_process_suite",
        isolated_privacy_paths[3],
    )

    assert check_privacy_token(_FakeRequest()) == {
        "status": 409,
        "error": "PRIVACY_SUITE_BLOCKED",
    }


def test_unlock_rejects_wrong_password():
    keystore.initialize_keystore(PASSWORD)
    keystore.lock_keystore()
    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_PASSWORD_INVALID"):
        keystore.unlock_keystore("not the password")
    assert keystore.keystore_status()["keystoreLocked"] is True


def test_unlock_reads_kdf_params_from_file(monkeypatch):
    keystore.initialize_keystore(PASSWORD)
    keystore.lock_keystore()
    monkeypatch.setattr(keystore, "SCRYPT_N", 2**13)

    assert keystore.unlock_keystore(PASSWORD)["token"]


def test_initialize_requires_minimum_password_length():
    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_PASSWORD_TOO_SHORT"):
        keystore.initialize_keystore("short")
    assert keystore.keystore_status()["keystoreInitialized"] is False


def test_initialize_twice_is_rejected():
    keystore.initialize_keystore(PASSWORD)
    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_KEYSTORE_EXISTS"):
        keystore.initialize_keystore(PASSWORD)


def test_legacy_key_is_imported_and_retired():
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    legacy_path = envelope_module.config_dir() / "privacy_key.json"
    legacy_envelope, _legacy_key, _legacy_key_id = write_legacy_state_fixture(
        envelope_module.config_dir(),
        DIRECTOR_SCHEMA,
        {"old": "workflow"},
    )
    assert legacy_path.exists()

    initialize_keystore_with_legacy_migration(PASSWORD, envelope_module.config_dir())

    assert not legacy_path.exists()
    assert not legacy_path.with_name(legacy_path.name + ".migrated").exists()
    assert codec.decrypt_state(legacy_envelope) == {"old": "workflow"}
    new_envelope = codec.encrypt_state({"new": "workflow"})
    assert new_envelope["keyId"] != legacy_envelope["keyId"]
    assert codec.decrypt_state(new_envelope) == {"new": "workflow"}


def test_add_keys_to_existing_keystore_imports_decrypt_only_key(tmp_path):
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    keystore.initialize_keystore(PASSWORD)
    second_dir = tmp_path / "second_pack"
    legacy_envelope, legacy_key, legacy_key_id = write_legacy_state_fixture(
        second_dir,
        DIRECTOR_SCHEMA,
        {"old": "other pack"},
    )

    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_PASSWORD_INVALID"):
        keystore.add_keys_to_keystore("wrong password", [(legacy_key_id, legacy_key)])

    result = keystore.add_keys_to_keystore(
        PASSWORD,
        [(legacy_key_id, legacy_key), (legacy_key_id, legacy_key)],
    )

    assert result["token"]
    raw = json.loads(keystore.keystore_path().read_text(encoding="utf-8"))
    assert [entry["keyId"] for entry in raw["keys"]].count(legacy_key_id) == 1
    assert codec.decrypt_state(legacy_envelope) == {"old": "other pack"}


def test_concurrent_verified_imports_preserve_every_wrapped_key():
    keystore.initialize_keystore(PASSWORD)
    keys = (
        ("synthetic-key-a", bytes(range(32))),
        ("synthetic-key-b", bytes(reversed(range(32)))),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(
                lambda item: keystore.import_decrypt_only_key_verified(
                    PASSWORD,
                    item[0],
                    item[1],
                ),
                keys,
            )
        )

    assert all(result["token"] for result in results)
    assert keystore.session_key_for("synthetic-key-a") == keys[0][1]
    assert keystore.session_key_for("synthetic-key-b") == keys[1][1]


def test_rotate_primary_key_keeps_old_envelopes_decryptable():
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    keystore.initialize_keystore(PASSWORD)
    old_envelope = codec.encrypt_state({"secret": "old"})

    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_PASSWORD_INVALID"):
        keystore.rotate_primary_key("wrong password")

    result = keystore.rotate_primary_key(PASSWORD)
    assert result["token"]
    new_envelope = codec.encrypt_state({"secret": "new"})

    assert new_envelope["keyId"] != old_envelope["keyId"]
    assert codec.decrypt_state(old_envelope) == {"secret": "old"}
    assert codec.decrypt_state(new_envelope) == {"secret": "new"}


def test_change_password_rewraps_keys():
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    keystore.initialize_keystore(PASSWORD)
    envelope = codec.encrypt_state({"secret": "prompt"})

    keystore.change_keystore_password(PASSWORD, "new password 123")
    keystore.lock_keystore()
    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_PASSWORD_INVALID"):
        keystore.unlock_keystore(PASSWORD)
    keystore.unlock_keystore("new password 123")
    assert codec.decrypt_state(envelope) == {"secret": "prompt"}


def test_keystore_file_contains_no_usable_key_material():
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    keystore.initialize_keystore(PASSWORD)
    envelope = codec.encrypt_state({"secret": "prompt"})
    session = keystore._read_session()
    raw = json.loads(keystore.keystore_path().read_text(encoding="utf-8"))

    assert raw["schema"] == keystore.KEYSTORE_SCHEMA
    assert raw["kdf"]["name"] == "scrypt"
    keystore_text = json.dumps(raw)
    for key in session["keys"].values():
        assert keystore._b64url_encode(key) not in keystore_text
    assert envelope["keyId"] in {entry["keyId"] for entry in raw["keys"]}


def test_session_cache_survives_module_state_reset():
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    result = keystore.initialize_keystore(PASSWORD)
    envelope = codec.encrypt_state({"secret": "prompt"})

    session = keystore._read_session()
    assert session is not None
    assert session["token"] == result["token"]
    assert codec.decrypt_state(envelope) == {"secret": "prompt"}


def test_explicit_base_dir_cannot_bypass_locked_keystore(tmp_path):
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    keystore.initialize_keystore(PASSWORD)
    keystore.lock_keystore()

    with pytest.raises(PrivacyError, match="legacy key directories"):
        codec.encrypt_state(
            {"secret": "prompt"},
            base_dir=tmp_path / "standalone",
        )
    assert not (tmp_path / "standalone" / "privacy_key.json").exists()


class _FakeRequest:
    def __init__(self, header_token=None, cookie_token=None):
        self.headers = {}
        self.cookies = {}
        if header_token is not None:
            self.headers["X-Helto-Privacy-Token"] = header_token
        if cookie_token is not None:
            self.cookies["helto_privacy_token"] = cookie_token


def test_check_privacy_token_gates_by_keystore_state():
    assert check_privacy_token(_FakeRequest()) == {
        "status": 409,
        "error": "PRIVACY_KEYSTORE_UNINITIALIZED",
    }

    result = keystore.initialize_keystore(PASSWORD)
    token = result["token"]

    assert check_privacy_token(_FakeRequest(header_token=token)) is None
    assert check_privacy_token(_FakeRequest(cookie_token=token)) is None

    missing = check_privacy_token(_FakeRequest())
    assert missing == {
        "status": 401,
        "error": "PRIVACY_TOKEN_REQUIRED",
    }
    wrong = check_privacy_token(_FakeRequest(header_token="not-the-token"))
    assert wrong is not None and wrong["status"] == 401

    keystore.lock_keystore()
    locked = check_privacy_token(_FakeRequest(header_token=token))
    assert locked is not None
    assert locked["status"] == 401
    assert locked["error"] == "PRIVACY_LOCKED"
