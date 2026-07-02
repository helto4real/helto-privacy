import base64
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import helto_privacy.envelope as envelope_module
from helto_privacy.envelope import (
    ALGORITHM,
    ENVELOPE_VERSION,
    PrivacyEnvelopeCodec,
    PrivacyError,
)
from helto_privacy.keystore import KEYSTORE_CRYPTO_AVAILABLE

pytestmark = pytest.mark.skipif(
    not KEYSTORE_CRYPTO_AVAILABLE,
    reason="cryptography package is required for privacy envelope tests",
)

DIRECTOR_SCHEMA = "helto.timeline-director"


def test_state_envelope_round_trip_and_structure(tmp_path):
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    payload = codec.encrypt_state({"secret": "prompt", "count": 2}, base_dir=tmp_path)

    assert payload["version"] == ENVELOPE_VERSION
    assert payload["schema"] == DIRECTOR_SCHEMA
    assert payload["encrypted"] is True
    assert payload["algorithm"] == ALGORITHM
    assert set(payload) == {
        "version",
        "schema",
        "encrypted",
        "algorithm",
        "keyId",
        "nonce",
        "ciphertext",
    }
    assert codec.is_encrypted_payload(payload) is True
    assert codec.is_encrypted_payload(json.dumps(payload)) is True
    assert codec.decrypt_state(payload, base_dir=tmp_path) == {"secret": "prompt", "count": 2}


def test_director_schema_is_aes_gcm_aad_compatible_with_pre_extraction_code(tmp_path):
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    state = {"secret": "prompt", "nested": {"a": 1}}
    payload = codec.encrypt_state(state, base_dir=tmp_path)
    key, key_id = codec._load_or_create_key(tmp_path, create=False)
    aad = f"{DIRECTOR_SCHEMA}|1|AES-256-GCM|{key_id}".encode("utf-8")

    plaintext = AESGCM(key).decrypt(
        _b64url_decode(payload["nonce"]),
        _b64url_decode(payload["ciphertext"]),
        aad,
    )
    assert json.loads(plaintext.decode("utf-8")) == state

    nonce = b"123456789012"
    legacy_plaintext = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    legacy_payload = {
        "version": 1,
        "schema": DIRECTOR_SCHEMA,
        "encrypted": True,
        "algorithm": "AES-256-GCM",
        "keyId": key_id,
        "nonce": _b64url_encode(nonce),
        "ciphertext": _b64url_encode(AESGCM(key).encrypt(nonce, legacy_plaintext, aad)),
    }
    assert codec.decrypt_state(legacy_payload, base_dir=tmp_path) == state


def test_state_envelope_rejects_different_schema(tmp_path):
    director = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    other = PrivacyEnvelopeCodec("helto.other-pack")
    payload = director.encrypt_state({"secret": "prompt"}, base_dir=tmp_path)

    with pytest.raises(PrivacyError, match="not an encrypted privacy payload"):
        other.decrypt_state(payload, base_dir=tmp_path)


def test_byte_envelope_round_trip_and_purpose_binding(tmp_path):
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    payload = codec.encrypt_bytes(b"private preview bytes", "thumbnail", base_dir=tmp_path)

    assert payload["schema"] == f"{DIRECTOR_SCHEMA}.bytes"
    assert payload["purpose"] == "thumbnail"
    assert codec.decrypt_bytes(payload, "thumbnail", base_dir=tmp_path) == b"private preview bytes"
    with pytest.raises(PrivacyError, match="different purpose"):
        codec.decrypt_bytes(payload, "waveform", base_dir=tmp_path)


def test_chunked_byte_envelope_round_trip_and_tamper_detection(tmp_path, monkeypatch):
    monkeypatch.setattr(envelope_module, "BYTE_CHUNK_SIZE", 4)
    codec = PrivacyEnvelopeCodec(DIRECTOR_SCHEMA)
    payload = codec.encrypt_bytes(b"abcdefghijk", "spill", base_dir=tmp_path)

    assert payload["schema"] == f"{DIRECTOR_SCHEMA}.bytes.chunked"
    assert payload["chunkSize"] == 4
    assert payload["plaintextSize"] == 11
    assert [entry["index"] for entry in payload["chunks"]] == [0, 1, 2]
    assert codec.decrypt_bytes(payload, "spill", base_dir=tmp_path) == b"abcdefghijk"

    tampered = json.loads(json.dumps(payload))
    tampered["chunks"][0]["ciphertext"] = "A" + tampered["chunks"][0]["ciphertext"][1:]
    with pytest.raises(PrivacyError, match="Could not decrypt chunked byte payload"):
        codec.decrypt_bytes(tampered, "spill", base_dir=tmp_path)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
