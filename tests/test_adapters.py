import json

import pytest

import helto_privacy.keystore as shared_keystore
from helto_privacy import ExternalJsonValueTransitionAdapter, PrivateByDefaultModeAdapter
from helto_privacy import PrivacyEnvelopeCodec


def test_private_by_default_mode_adapter_accepts_only_declared_modes():
    adapter = PrivateByDefaultModeAdapter()

    assert adapter.read_declared_mode("scope") == "private"
    adapter.write_declared_mode("scope", "public")
    assert adapter.read_declared_mode("scope") == "public"

    with pytest.raises(ValueError):
        adapter.write_declared_mode("scope", "automatic")


def test_private_by_default_mode_adapter_uses_revisioned_compare_and_set():
    adapter = PrivateByDefaultModeAdapter()
    prior = adapter.read_mode_source("scope")

    target = adapter.compare_and_set_mode_source(
        "scope",
        prior["revision"],
        prior["declared"],
        "public",
    )

    assert target == {"revision": 1, "declared": "public"}
    assert adapter.classify_mode_source("scope", prior, target) == "target"
    restored = adapter.rollback_mode_source("scope", target, prior)
    assert restored == {"revision": 2, "declared": "private"}
    assert adapter.rollback_mode_source("scope", target, prior) == restored

    with pytest.raises(RuntimeError):
        adapter.compare_and_set_mode_source("scope", 0, "private", "public")


class ValueAdapter(ExternalJsonValueTransitionAdapter):
    def normalize(self, value, _context):
        if not isinstance(value, dict) or set(value) != {"value"}:
            raise ValueError("invalid")
        return {"value": str(value["value"])}


def test_external_json_value_transition_adapter_is_exact_and_canonical():
    adapter = ValueAdapter("helto.synthetic")
    public = b'{"value":"hello"}'

    assert adapter.classify_mode_transition_representation(public, None) == "public"
    assert adapter.decode_mode_transition_representation(public, None) == {
        "value": "hello"
    }
    assert adapter.encode_public_mode_transition({"value": "hello"}, None) == public
    assert adapter.encode_public_mode_transition([], None) == b'{"value":[]}'
    assert adapter.encode_public_mode_transition("raw prompt", None) == (
        b'{"value":"raw prompt"}'
    )

    for invalid in (
        '{"value":"hello"}',
        b'',
        b'{"value":1,"value":2}',
        b'{"value":NaN}',
        b'{"schema":"helto.synthetic","value":"hello"}',
    ):
        with pytest.raises(ValueError):
            adapter.classify_mode_transition_representation(invalid, None)


def test_external_json_value_transition_adapter_rejects_malformed_envelopes():
    adapter = ValueAdapter("helto.synthetic")
    malformed = json.dumps(
        {
            "algorithm": "AES-256-GCM",
            "ciphertext": "not-base64url",
            "encrypted": True,
            "keyId": "key",
            "nonce": "not-base64url",
            "schema": "helto.synthetic",
            "version": 1,
        }
    ).encode()

    with pytest.raises(ValueError):
        adapter.classify_mode_transition_representation(malformed, None)


def test_external_json_value_transition_adapter_decodes_only_value_envelopes():
    shared_keystore.initialize_keystore("synthetic adapter password")
    adapter = ValueAdapter("helto.synthetic")
    codec = PrivacyEnvelopeCodec("helto.synthetic")
    protected = json.dumps(
        codec.encrypt_state({"value": "secret"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    assert adapter.classify_mode_transition_representation(protected, None) == "private"
    assert adapter.decode_mode_transition_representation(protected, None) == {
        "value": "secret"
    }

    malformed_plaintext = json.dumps(
        codec.encrypt_state({"unexpected": "secret"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(ValueError):
        adapter.decode_mode_transition_representation(malformed_plaintext, None)
