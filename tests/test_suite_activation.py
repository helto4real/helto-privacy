from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helto_privacy.suite_activation import (
    FileActivationRecordStore,
    SuiteActivationError,
    sign_activation_authorization,
)
from helto_privacy.suite_runtime import (
    SuiteInstallation,
    SuiteStatus,
    process_suite_status_payload,
    register_process_suite,
    require_active_process_suite,
)
from test_suite_runtime import _inventory, _release


def test_explicit_digest_bound_activation_persists_rollback_boundary(
    tmp_path,
    monkeypatch,
):
    import helto_privacy.suite_runtime as suite_runtime

    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_INSTALLATION", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_CONFLICT", False)
    release = _release(ready=True)
    activation_key = Ed25519PrivateKey.generate()
    store = FileActivationRecordStore(tmp_path / "activation.json")
    installation = SuiteInstallation(
        release,
        activation_store=store,
        trusted_activation_keys={"user-activation-2026": activation_key.public_key()},
    )
    inventory = _inventory(release.manifest)
    assert installation._verify_inventory(inventory).status is SuiteStatus.ACTIVATION_REQUIRED
    request = installation.activation_request()
    authorization = sign_activation_authorization(
        request,
        pre_activation_snapshot_digest="d" * 64,
        authorization_id="activation-2026-07-10.1",
        authorized_at="2026-07-10T21:00:00Z",
        signer_key_id="user-activation-2026",
        private_key=activation_key,
    )

    with pytest.raises(SuiteActivationError) as mismatch:
        installation.activate(replace(authorization, manifest_digest="e" * 64))
    assert mismatch.value.code == "activation_manifest_mismatch"
    assert installation.status is SuiteStatus.ACTIVATION_REQUIRED

    record = installation.activate(authorization)

    assert installation.status is SuiteStatus.ACTIVE
    installation.require_active()
    register_process_suite(installation)
    assert require_active_process_suite() is installation
    assert process_suite_status_payload()["suiteStatus"] == "active"
    assert record.manifest_digest == release.manifest.digest
    assert record.inventory_digest == request.inventory_digest
    assert record.previous_suite_id == release.manifest.previous_suite_id
    assert record.pre_activation_snapshot_digest == "d" * 64
    assert record.rollback == release.manifest.rollback
    stored = (tmp_path / "activation.json").read_text(encoding="utf-8")
    assert "plaintext" not in stored
    assert "decrypt" not in stored

    restarted = SuiteInstallation(
        release,
        activation_store=store,
        trusted_activation_keys={"user-activation-2026": activation_key.public_key()},
    )
    assert restarted._verify_inventory(inventory).status is SuiteStatus.ACTIVE

    mismatched = replace(inventory, browser_manifest_digest="e" * 64)
    assert restarted._verify_inventory(mismatched).status is SuiteStatus.MISMATCH
    blocked_repair = restarted._verify_inventory(inventory)
    assert blocked_repair.issue_codes == ("process_restart_required",)
    assert store.load().reactivation_required is True

    repaired_process = SuiteInstallation(
        release,
        activation_store=store,
        trusted_activation_keys={"user-activation-2026": activation_key.public_key()},
    )
    reactivation = repaired_process._verify_inventory(inventory)
    assert reactivation.status is SuiteStatus.ACTIVATION_REQUIRED
    assert reactivation.issue_codes == ("explicit_reactivation_required",)
