import os

import pytest

import helto_privacy.operator_activation as operator_activation
from helto_privacy.operator_activation import OperatorActivationError


def test_operator_key_generation_is_private_and_refuses_overwrite(tmp_path):
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"

    result = operator_activation.generate_operator_key(private_key, public_key)

    assert result == {
        "ok": True,
        "privateKeyCreated": True,
        "publicKeyCreated": True,
    }
    assert os.stat(private_key).st_mode & 0o777 == 0o600
    assert os.stat(public_key).st_mode & 0o777 == 0o644
    with pytest.raises(OperatorActivationError) as duplicate:
        operator_activation.generate_operator_key(private_key, public_key)
    assert duplicate.value.code == "activation_key_path_exists"


def test_operator_activation_signs_exact_process_request(tmp_path, monkeypatch):
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"
    operator_activation.generate_operator_key(private_key, public_key)
    calls = []

    def request_json(method, url, payload=None):
        calls.append((method, url, payload))
        if method == "GET":
            return {
                "ok": True,
                "manifestDigest": "a" * 64,
                "inventoryDigest": "b" * 64,
                "processNonce": "c" * 64,
                "previousSuiteId": "helto-suite-previous",
                "rollback": "data-snapshot-required-after-activation",
            }
        return {
            "ok": True,
            "suiteStatus": "active",
            "suiteManifestDigest": "a" * 64,
            "suiteIssueCodes": [],
        }

    monkeypatch.setattr(operator_activation, "_request_json", request_json)

    result = operator_activation.activate_operator_suite(
        server="http://127.0.0.1:8188",
        private_key_path=private_key,
        signer_key_id="user-activation-2026",
        pre_activation_snapshot_digest="d" * 64,
    )

    assert result == {
        "ok": True,
        "suiteStatus": "active",
        "suiteManifestDigest": "a" * 64,
        "suiteIssueCodes": [],
    }
    assert calls[0][:2] == (
        "GET",
        "http://127.0.0.1:8188/helto_privacy/suite/activation-request",
    )
    submitted = calls[1][2]
    assert submitted["manifestDigest"] == "a" * 64
    assert submitted["inventoryDigest"] == "b" * 64
    assert submitted["processNonce"] == "c" * 64
    assert submitted["preActivationSnapshotDigest"] == "d" * 64
    assert submitted["signerKeyId"] == "user-activation-2026"
    assert isinstance(submitted["signature"], str) and submitted["signature"]


def test_operator_activation_rejects_non_loopback_server(tmp_path):
    with pytest.raises(OperatorActivationError) as invalid:
        operator_activation.activate_operator_suite(
            server="https://example.invalid",
            private_key_path=tmp_path / "missing.pem",
            signer_key_id="user-activation-2026",
            pre_activation_snapshot_digest="d" * 64,
        )
    assert invalid.value.code == "activation_server_invalid"


def test_operator_activation_rejects_readable_or_symlinked_private_key(
    tmp_path,
):
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"
    operator_activation.generate_operator_key(private_key, public_key)
    os.chmod(private_key, 0o644)

    with pytest.raises(OperatorActivationError) as readable:
        operator_activation._load_private_key(private_key)
    assert readable.value.code == "activation_private_key_permissions_invalid"

    os.chmod(private_key, 0o600)
    symlink = tmp_path / "operator-link.pem"
    symlink.symlink_to(private_key)
    if getattr(os, "O_NOFOLLOW", 0):
        with pytest.raises(OperatorActivationError) as linked:
            operator_activation._load_private_key(symlink)
        assert linked.value.code == "activation_private_key_invalid"
