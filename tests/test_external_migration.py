from __future__ import annotations

import json

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.migration as migration
from helto_privacy.guard import PrivacyAuthorizationError, authorize_privacy_request
from helto_privacy.profile import (
    AdapterSlot,
    LegacyLocationKind,
    LegacyReaderBinding,
    PrivacyProfile,
    ProfileResource,
    ProtectedOperation,
    ResourceKind,
)


PASSWORD = "synthetic external migration password"
OPERATION_ID = "imports.apply"
BINDING_ID = "legacy-export-binding"


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ExportReader:
    def probe(self, source, _context):
        return isinstance(source, bytes) and source.startswith(b"SYNTHETIC_RAW_EXPORT")

    def read(self, _source, _context):
        return {"entries": [{"value": "SYNTHETIC_NORMALIZED"}]}


def _profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.external-test",
        distribution="comfyui-external-test",
        resources=(
            ProfileResource("imports", ResourceKind.OPERATION, ("imports-adapter",)),
        ),
        server_adapters=(
            AdapterSlot("imports-adapter", ResourceKind.OPERATION, "imports"),
        ),
        protected_operations=(
            ProtectedOperation(
                OPERATION_ID,
                "imports",
                "imports-adapter",
                "/imports/apply",
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                BINDING_ID,
                "legacy-export-v1",
                "imports",
                LegacyLocationKind.EXPORT,
                OPERATION_ID,
            ),
        ),
    )


@pytest.fixture
def external_migration(tmp_path, monkeypatch):
    monkeypatch.setenv(
        migration.MIGRATION_STATE_ENV,
        str(tmp_path / "migration" / "state.json"),
    )
    migration.reset_migration_runtime_for_tests()
    migration.register_legacy_reader_units(
        (migration.LegacyReaderUnit("legacy-export-v1", "Legacy export", ExportReader()),)
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    profile = _profile()
    handle = migration.MigrationHandle(profile)
    authorization = authorize_privacy_request(
        Request(token),
        OPERATION_ID,
        pack_id=profile.id,
    )
    return profile, handle, authorization, tmp_path


def _discover(profile, authorization, suffix=b"one"):
    result = migration.discover_bound_legacy(
        profile,
        BINDING_ID,
        b"SYNTHETIC_RAW_EXPORT_" + suffix,
        authorization,
        operation_id=OPERATION_ID,
    )
    assert result is not None
    return result


def _context(mode=migration.ExternalMigrationMode.REPLACE):
    return migration.ExternalMigrationContext(mode, "2026-07-13T12:34:56Z")


def _verification(expected, context=None):
    return migration.ExternalMigrationVerification(
        normalized=expected,
        current_exact=b"SYNTHETIC_CURRENT_EXACT_BYTES",
        reexported_exact=b"SYNTHETIC_REEXPORTED_EXACT_BYTES",
        context=context or _context(),
        current_format=True,
        durable_artifacts_current=True,
    )


def _nested_normalized(depth):
    value = "leaf"
    for _ in range(depth):
        value = {"child": value}
    return value


def test_external_finalize_is_restart_safe_and_response_loss_idempotent(
    external_migration,
):
    profile, handle, authorization, tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    prepared = external.prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_DESTINATION_ORIGINAL_EXACT",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )

    assert prepared.status.disposition == "prepared"
    assert prepared.status.expires_in_seconds == 300
    assert prepared.resume_token.startswith("hp-resume-")
    encrypted = (tmp_path / "migration" / "state.json").read_text(encoding="utf-8")
    assert "SYNTHETIC" not in encrypted
    assert "owner-12" not in encrypted

    restarted = migration.MigrationHandle(profile).external(BINDING_ID, OPERATION_ID)
    retry = restarted.prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_DESTINATION_ORIGINAL_EXACT",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    assert retry == prepared
    assert retry.resume_token == prepared.resume_token
    assert restarted.status(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    ).disposition == "prepared"
    resumed = restarted.resume(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    )
    assert resumed.original_exact == b"SYNTHETIC_DESTINATION_ORIGINAL_EXACT"
    assert resumed.expected_normalized == discovered.value
    assert resumed.context == _context()
    assert "SYNTHETIC" not in repr(resumed)
    assert not hasattr(resumed, "to_payload")

    proof = _verification(discovered.value)
    receipt = restarted.finalize(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        proof,
        authorization,
    )
    repeated = restarted.finalize(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        proof,
        authorization,
    )
    assert repeated == receipt
    assert handle.obligation(discovered.obligation.id).disposition == "migrated"

    state = migration._load_state()
    assert "SYNTHETIC_RAW_EXPORT" not in json.dumps(state)
    assert state["externalTransactions"] == {}
    tombstone = state["externalTombstones"][prepared.status.id]
    assert tombstone["disposition"] == "migrated"
    assert set(tombstone).isdisjoint(
        {"original", "expected", "exportedAt", "mode", "preparedAtNs", "expiresAtNs"}
    )
    assert "SYNTHETIC" not in json.dumps(tombstone)


def test_external_sections_are_optional_in_existing_v1_state(external_migration):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    historical_v1 = migration._load_state()
    historical_v1.pop("externalTransactions")
    historical_v1.pop("externalTombstones")
    migration._save_state(historical_v1)

    prepared = handle.external(BINDING_ID, OPERATION_ID).prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    assert prepared.status.disposition == "prepared"
    state = migration._load_state()
    assert prepared.status.id in state["externalTransactions"]
    assert state.get("externalTombstones", {}) == {}


def test_external_prepare_enforces_idempotency_and_one_owner_transaction(
    external_migration,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    prepared = external.prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    assert external.prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    ) == prepared

    with pytest.raises(migration.MigrationError) as conflict:
        external.prepare(
            discovered.obligation.id,
            {"entries": []},
            b"SYNTHETIC_ORIGINAL",
            _context(),
            "owner-12",
            "request-abc",
            authorization,
        )
    assert conflict.value.code == "migration_idempotency_conflict"

    second = _discover(profile, authorization, b"two")
    with pytest.raises(migration.MigrationError) as owner_conflict:
        external.prepare(
            second.obligation.id,
            second.value,
            b"SYNTHETIC_ORIGINAL_TWO",
            _context(migration.ExternalMigrationMode.MERGE),
            "owner-12",
            "request-def",
            authorization,
        )
    assert owner_conflict.value.code == "external_migration_owner_in_progress"


def test_external_cancel_requires_exact_rollback_ack_and_is_idempotent(
    external_migration,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    original = b"SYNTHETIC_DESTINATION_ORIGINAL_EXACT"
    prepared = external.prepare(
        discovered.obligation.id,
        discovered.value,
        original,
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    cancelled = external.cancel(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    )
    assert cancelled.disposition == "rollback-required"

    with pytest.raises(migration.MigrationError) as unverified:
        external.confirm_rollback(
            prepared.status.id,
            "owner-12",
            prepared.resume_token,
            authorization,
            verification=migration.ExternalRollbackVerification(b"SYNTHETIC_WRONG"),
        )
    assert unverified.value.code == "external_migration_rollback_unverified"
    rolled_back = external.confirm_rollback(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
        verification=migration.ExternalRollbackVerification(original),
    )
    assert rolled_back.disposition == "rolled-back"
    assert external.confirm_rollback(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
        verification=migration.ExternalRollbackVerification(original),
    ) == rolled_back
    with pytest.raises(migration.MigrationError) as changed_retry:
        external.confirm_rollback(
            prepared.status.id,
            "owner-12",
            prepared.resume_token,
            authorization,
            verification=migration.ExternalRollbackVerification(b"SYNTHETIC_WRONG"),
        )
    assert changed_retry.value.code == "migration_idempotency_conflict"
    assert handle.obligation(discovered.obligation.id).disposition == "unresolved"
    tombstone = migration._load_state()["externalTombstones"][prepared.status.id]
    assert "original" not in tombstone
    assert "SYNTHETIC" not in json.dumps(tombstone)


def test_external_expiry_only_moves_to_rollback_required(
    external_migration,
    monkeypatch,
):
    profile, handle, authorization, _tmp_path = external_migration
    base_ns = 2_000_000_000_000
    monkeypatch.setattr(migration.time, "time_ns", lambda: base_ns)
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    original = b"SYNTHETIC_DESTINATION_ORIGINAL_EXACT"
    prepared = external.prepare(
        discovered.obligation.id,
        discovered.value,
        original,
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    monkeypatch.setattr(
        migration.time,
        "time_ns",
        lambda: base_ns + 301 * 1_000_000_000,
    )
    status = external.status(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    )
    assert status.disposition == "rollback-required"
    assert prepared.status.id in migration._load_state()["externalTransactions"]
    with pytest.raises(migration.MigrationError) as blocked:
        external.finalize(
            prepared.status.id,
            "owner-12",
            prepared.resume_token,
            _verification(discovered.value),
            authorization,
        )
    assert blocked.value.code == "external_migration_rollback_required"
    resumed = external.resume(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    )
    assert resumed.status.disposition == "rollback-required"
    assert resumed.original_exact == original

    monkeypatch.setattr(migration, "EXTERNAL_MIGRATION_MAX_GLOBAL", 1)
    second = _discover(profile, authorization, b"two")
    with pytest.raises(migration.MigrationError) as still_counted:
        external.prepare(
            second.obligation.id,
            second.value,
            b"SYNTHETIC_ORIGINAL_TWO",
            _context(),
            "owner-13",
            "request-def",
            authorization,
        )
    assert still_counted.value.code == "external_migration_capacity_exceeded"


def test_external_authority_binding_capability_and_capacity_are_fail_closed(
    external_migration,
    monkeypatch,
):
    profile, handle, authorization, _tmp_path = external_migration
    with pytest.raises(migration.MigrationError) as wrong_operation:
        handle.external(BINDING_ID, "imports.other")
    assert wrong_operation.value.code == "typed_migration_operation_required"

    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    prepared = external.prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    with pytest.raises(migration.MigrationError) as owner_mismatch:
        external.status(
            prepared.status.id,
            "owner-13",
            prepared.resume_token,
            authorization,
        )
    assert owner_mismatch.value.code == "external_migration_unknown"
    with pytest.raises(migration.MigrationError) as token_mismatch:
        external.status(
            prepared.status.id,
            "owner-12",
            "hp-resume-" + "A" * 43,
            authorization,
        )
    assert token_mismatch.value.code == "external_migration_unknown"

    wrong_authorization = authorize_privacy_request(
        Request(keystore.session_token()),
        "migration.complete",
        pack_id=profile.id,
    )
    with pytest.raises(PrivacyAuthorizationError):
        external.status(
            prepared.status.id,
            "owner-12",
            prepared.resume_token,
            wrong_authorization,
        )

    monkeypatch.setattr(migration, "EXTERNAL_MIGRATION_MAX_GLOBAL", 1)
    second = _discover(profile, authorization, b"two")
    with pytest.raises(migration.MigrationError) as capacity:
        external.prepare(
            second.obligation.id,
            second.value,
            b"SYNTHETIC_ORIGINAL_TWO",
            _context(),
            "owner-13",
            "request-def",
            authorization,
        )
    assert capacity.value.code == "external_migration_capacity_exceeded"

    monkeypatch.setattr(migration, "EXTERNAL_MIGRATION_MAX_GLOBAL", 256)
    monkeypatch.setattr(migration, "EXTERNAL_MIGRATION_MAX_PER_PACK", 1)
    with pytest.raises(migration.MigrationError) as pack_capacity:
        external.prepare(
            second.obligation.id,
            second.value,
            b"SYNTHETIC_ORIGINAL_TWO",
            _context(),
            "owner-13",
            "request-ghi",
            authorization,
        )
    assert pack_capacity.value.code == "external_migration_capacity_exceeded"


def test_external_verification_failure_requires_rollback(external_migration):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    prepared = external.prepare(
        discovered.obligation.id,
        discovered.value,
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    with pytest.raises(migration.MigrationError) as failed:
        external.finalize(
            prepared.status.id,
            "owner-12",
            prepared.resume_token,
            _verification({"entries": []}),
            authorization,
        )
    assert failed.value.code == "external_migration_verification_failed"
    assert external.status(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    ).disposition == "rollback-required"
    assert handle.obligation(discovered.obligation.id).disposition == "unresolved"


@pytest.mark.parametrize(
    "invalid_value",
    (
        lambda: {"value": "x" * (migration._EXTERNAL_MIGRATION_MAX_STRING_BYTES + 1)},
        lambda: _nested_normalized(migration._EXTERNAL_MIGRATION_MAX_DEPTH + 1),
        lambda: list(range(migration._EXTERNAL_MIGRATION_MAX_CONTAINER_ITEMS + 1)),
        lambda: {
            "groups": [
                list(range(migration._EXTERNAL_MIGRATION_MAX_CONTAINER_ITEMS))
                for _ in range(5)
            ]
        },
        lambda: {1: "numeric-key"},
        lambda: {"value": float("nan")},
        lambda: {"value": float("inf")},
    ),
)
def test_external_prepare_rejects_unbounded_normalized_values_before_state_mutation(
    external_migration,
    monkeypatch,
    invalid_value,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    monkeypatch.setattr(migration, "EXTERNAL_MIGRATION_MAX_GLOBAL", 1)
    monkeypatch.setattr(migration, "EXTERNAL_MIGRATION_MAX_PER_PACK", 1)

    with pytest.raises(migration.MigrationError) as rejected:
        external.prepare(
            discovered.obligation.id,
            invalid_value(),
            b"SYNTHETIC_ORIGINAL",
            _context(),
            "owner-12",
            "request-invalid",
            authorization,
        )
    assert rejected.value.code == "external_migration_normalized_invalid"
    state = migration._load_state()
    assert state.get("externalTransactions", {}) == {}
    assert state.get("externalTombstones", {}) == {}

    accepted = external.prepare(
        discovered.obligation.id,
        {"flag": True, "count": 1, "ratio": 1.0},
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-valid",
        authorization,
    )
    assert accepted.status.disposition == "prepared"


def test_external_prepare_enforces_final_canonical_byte_limit(
    external_migration,
    monkeypatch,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    monkeypatch.setattr(
        migration,
        "_EXTERNAL_MIGRATION_MAX_STRING_BYTES",
        16 * 1024 * 1024,
    )
    oversized = "x" * (migration._EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES + 1)
    with pytest.raises(migration.MigrationError) as rejected:
        external.prepare(
            discovered.obligation.id,
            {"value": oversized},
            b"SYNTHETIC_ORIGINAL",
            _context(),
            "owner-12",
            "request-invalid",
            authorization,
        )
    assert rejected.value.code == "external_migration_normalized_invalid"
    assert migration._load_state().get("externalTransactions", {}) == {}


def test_external_finalize_bounds_verification_without_mutating_prepared_state(
    external_migration,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    prepared = external.prepare(
        discovered.obligation.id,
        {"flag": True, "count": 1, "ratio": 1.0},
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    invalid_proof = migration.ExternalMigrationVerification(
        normalized=_nested_normalized(migration._EXTERNAL_MIGRATION_MAX_DEPTH + 1),
        current_exact=b"SYNTHETIC_CURRENT",
        reexported_exact=b"SYNTHETIC_REEXPORT",
        context=_context(),
        current_format=True,
        durable_artifacts_current=True,
    )
    with pytest.raises(migration.MigrationError) as rejected:
        external.finalize(
            prepared.status.id,
            "owner-12",
            prepared.resume_token,
            invalid_proof,
            authorization,
        )
    assert rejected.value.code == "external_migration_normalized_invalid"
    assert external.status(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    ).disposition == "prepared"

    exact_proof = migration.ExternalMigrationVerification(
        normalized={"flag": True, "count": 1, "ratio": 1.0},
        current_exact=b"SYNTHETIC_CURRENT",
        reexported_exact=b"SYNTHETIC_REEXPORT",
        context=_context(),
        current_format=True,
        durable_artifacts_current=True,
    )
    receipt = external.finalize(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        exact_proof,
        authorization,
    )
    assert receipt.disposition == "migrated"


def test_external_normalized_canonicalization_preserves_exact_json_scalar_types():
    assert migration._external_canonical_normalized(True) != (
        migration._external_canonical_normalized(1)
    )
    assert migration._external_canonical_normalized(1) != (
        migration._external_canonical_normalized(1.0)
    )

    class IntAlias(int):
        pass

    with pytest.raises(migration.MigrationError) as alias:
        migration._external_canonical_normalized(IntAlias(1))
    assert alias.value.code == "external_migration_normalized_invalid"


def test_external_cumulative_prepass_rejects_before_canonicalization_or_state_access(
    external_migration,
    monkeypatch,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    calls = {"canonical": 0, "state": 0}

    def canonical_called(_value):
        calls["canonical"] += 1
        raise AssertionError("canonicalization must not run")

    def state_called():
        calls["state"] += 1
        raise AssertionError("migration state must not be read")

    many_sub_limit_strings = ["x" * 40 for _ in range(20)]
    with monkeypatch.context() as scoped:
        scoped.setattr(migration, "_EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES", 512)
        scoped.setattr(migration, "_canonical_value", canonical_called)
        scoped.setattr(migration, "_load_state", state_called)
        with pytest.raises(migration.MigrationError) as rejected:
            external.prepare(
                discovered.obligation.id,
                many_sub_limit_strings,
                b"SYNTHETIC_ORIGINAL",
                _context(),
                "owner-12",
                "request-invalid",
                authorization,
            )
    assert rejected.value.code == "external_migration_normalized_invalid"
    assert calls == {"canonical": 0, "state": 0}
    assert migration._load_state().get("externalTransactions", {}) == {}


def test_external_cumulative_prepass_counts_nested_structural_overhead(
    monkeypatch,
):
    calls = 0

    def canonical_called(_value):
        nonlocal calls
        calls += 1
        raise AssertionError("canonicalization must not run")

    nested = []
    for _ in range(20):
        nested = [nested]
    monkeypatch.setattr(migration, "_EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES", 32)
    monkeypatch.setattr(migration, "_canonical_value", canonical_called)
    with pytest.raises(migration.MigrationError) as rejected:
        migration._external_canonical_normalized(nested)
    assert rejected.value.code == "external_migration_normalized_invalid"
    assert calls == 0


def test_external_finalize_cumulative_prepass_does_not_read_state(
    external_migration,
    monkeypatch,
):
    profile, handle, authorization, _tmp_path = external_migration
    discovered = _discover(profile, authorization)
    external = handle.external(BINDING_ID, OPERATION_ID)
    prepared = external.prepare(
        discovered.obligation.id,
        {"value": "valid"},
        b"SYNTHETIC_ORIGINAL",
        _context(),
        "owner-12",
        "request-abc",
        authorization,
    )
    proof = migration.ExternalMigrationVerification(
        normalized=["x" * 40 for _ in range(20)],
        current_exact=b"SYNTHETIC_CURRENT",
        reexported_exact=b"SYNTHETIC_REEXPORT",
        context=_context(),
        current_format=True,
        durable_artifacts_current=True,
    )
    calls = {"canonical": 0, "state": 0}

    def canonical_called(_value):
        calls["canonical"] += 1
        raise AssertionError("canonicalization must not run")

    def state_called():
        calls["state"] += 1
        raise AssertionError("migration state must not be read")

    with monkeypatch.context() as scoped:
        scoped.setattr(migration, "_EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES", 512)
        scoped.setattr(migration, "_canonical_value", canonical_called)
        scoped.setattr(migration, "_load_state", state_called)
        with pytest.raises(migration.MigrationError) as rejected:
            external.finalize(
                prepared.status.id,
                "owner-12",
                prepared.resume_token,
                proof,
                authorization,
            )
    assert rejected.value.code == "external_migration_normalized_invalid"
    assert calls == {"canonical": 0, "state": 0}
    assert external.status(
        prepared.status.id,
        "owner-12",
        prepared.resume_token,
        authorization,
    ).disposition == "prepared"
