from __future__ import annotations

import copy
import json

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.migration as migration
import helto_privacy.runtime as runtime
import helto_privacy.singletons as singletons
from helto_privacy import (
    AdapterSlot,
    LegacyLocationKind,
    LegacyReaderBinding,
    LegacyReaderUnit,
    MigrationVerification,
    PrivacyEnvelopeCodec,
    PrivacyAuthorizationError,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
    SingletonDeclaration,
    SingletonError,
    SingletonHandle,
    SingletonPayloadKind,
    SingletonSnapshot,
    install,
    lock_keystore,
    register_legacy_reader_units,
)
from helto_privacy.guard import authorize_privacy_request


PASSWORD = "synthetic singleton password"


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeAdapter:
    def read_declared_mode(self, *_args):
        return "private"

    def write_declared_mode(self, *_args):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class StoreTransaction:
    def __init__(self, store, singleton_id, expected_revision, replacement) -> None:
        self.store = store
        self.singleton_id = singleton_id
        self.expected_revision = expected_revision
        self.replacement = replacement
        self.original = copy.deepcopy(store.snapshots[singleton_id])
        self.mismatched = False

    def commit(self):
        if self.store.snapshots[self.singleton_id].revision != self.expected_revision:
            return False
        if self.store.concurrent_snapshot is not None:
            self.store.snapshots[self.singleton_id] = self.store.concurrent_snapshot
            return False
        self.store.snapshots[self.singleton_id] = self.replacement
        if self.store.fail_commit:
            raise RuntimeError("synthetic commit failure")
        return True

    def read_back(self):
        current = self.store.snapshots[self.singleton_id]
        if self.store.mismatch_readback and not self.mismatched:
            self.mismatched = True
            return SingletonSnapshot(
                current.revision,
                {"malformed": "SYNTHETIC_MISMATCH"},
            )
        return current

    def rollback(self):
        if self.store.fail_rollback:
            raise RuntimeError("synthetic rollback failure")
        self.store.snapshots[self.singleton_id] = self.original


class SingletonStore:
    def __init__(self) -> None:
        self.snapshots = {
            "provider-settings": SingletonSnapshot(0),
            "queue-state": SingletonSnapshot(0),
        }
        self.fail_commit = False
        self.fail_rollback = False
        self.mismatch_readback = False
        self.concurrent_snapshot = None
        self.begin_calls = []

    def read_singleton(self, singleton_id):
        return self.snapshots[singleton_id]

    def begin_singleton_replace(
        self,
        singleton_id,
        expected_revision,
        replacement,
    ):
        self.begin_calls.append((singleton_id, expected_revision))
        return StoreTransaction(
            self,
            singleton_id,
            expected_revision,
            replacement,
        )

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


def _profile(*, legacy_reader_id: str | None = None) -> PrivacyProfile:
    field_readers = (legacy_reader_id,) if legacy_reader_id else ()
    bindings = (
        (
            LegacyReaderBinding(
                "provider-plaintext-v1",
                legacy_reader_id,
                "pack-state",
                LegacyLocationKind.PACK_STATE,
                "provider-settings",
            ),
        )
        if legacy_reader_id
        else ()
    )
    return PrivacyProfile(
        id="helto.singleton-test",
        distribution="comfyui-singleton-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource(
                "pack-state",
                ResourceKind.SINGLETON,
                ("singleton-store",),
            ),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot(
                "singleton-store",
                ResourceKind.SINGLETON,
                "pack-state",
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        singletons=(
            SingletonDeclaration(
                "provider-settings",
                "pack-state",
                "main",
                "helto.singleton.provider-settings",
                "provider-settings",
                "singleton-store",
                SingletonPayloadKind.FIELD,
                legacy_reader_ids=field_readers,
            ),
            SingletonDeclaration(
                "queue-state",
                "pack-state",
                "main",
                "helto.singleton.queue-state",
                "queue-state",
                "singleton-store",
                SingletonPayloadKind.BLOB,
            ),
        ),
        legacy_bindings=bindings,
    )


@pytest.fixture
def singleton_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    singletons.reset_singleton_runtime_for_tests()
    store = SingletonStore()
    pack = install(
        _profile(),
        {"mode": ModeAdapter(), "singleton-store": store},
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    return pack, store, token


def _authorization(pack, token: str, operation: str):
    return authorize_privacy_request(
        Request(token),
        operation,
        pack_id=pack.profile.id,
    )


def _assert_snapshot_equal(left: SingletonSnapshot, right: SingletonSnapshot) -> None:
    assert left.revision == right.revision
    assert left.protected == right.protected


def test_singleton_snapshot_never_reveals_its_protected_value_in_repr():
    snapshot = SingletonSnapshot(
        revision=1,
        protected={"ciphertext": "SYNTHETIC_SINGLETON_CIPHERTEXT_CANARY"},
    )

    assert snapshot.revision == 1
    assert "SYNTHETIC" not in repr(snapshot)


def test_profile_compiles_typed_singleton_contract_and_handle(singleton_pack):
    pack, _store, _token = singleton_pack

    assert isinstance(pack.singletons("pack-state"), SingletonHandle)
    assert pack.profile.server_adapter_contracts["singleton-store"] == (
        "begin_singleton_replace",
        "commit_mode_transition",
        "prepare_mode_transition",
        "read_singleton",
        "rollback_mode_transition",
    )
    assert pack.profile._canonical_value()["singletons"] == [
        {
            "id": "provider-settings",
            "resourceId": "pack-state",
            "scopeId": "main",
            "currentSchema": "helto.singleton.provider-settings",
            "purpose": "provider-settings",
            "storeAdapter": "singleton-store",
            "payloadKind": "field",
            "legacyReaderIds": [],
        },
        {
            "id": "queue-state",
            "resourceId": "pack-state",
            "scopeId": "main",
            "currentSchema": "helto.singleton.queue-state",
            "purpose": "queue-state",
            "storeAdapter": "singleton-store",
            "payloadKind": "blob",
            "legacyReaderIds": [],
        },
    ]


def test_field_singleton_replace_reveal_and_generic_status(singleton_pack):
    pack, store, token = singleton_pack
    handle = pack.singletons("pack-state")
    value = {
        "provider": "synthetic-provider",
        "token": "SYNTHETIC_PROVIDER_SECRET_CANARY",
    }

    receipt = handle.replace_field(
        "provider-settings",
        value,
        0,
        _authorization(pack, token, "singleton.replace"),
    )

    assert receipt.revision == 1
    assert receipt.operation == "replace"
    assert "SYNTHETIC" not in repr(receipt)
    stored = store.snapshots["provider-settings"]
    assert stored.revision == 1
    assert "SYNTHETIC_PROVIDER_SECRET_CANARY" not in json.dumps(stored.protected)
    status = handle.status("provider-settings")
    assert status.to_payload() == {
        "exists": True,
        "revision": 1,
        "private": True,
        "currentFormat": True,
    }
    assert set(status.to_payload()) == {
        "exists",
        "revision",
        "private",
        "currentFormat",
    }
    revealed = handle.reveal_field(
        "provider-settings",
        _authorization(pack, token, "singleton.reveal"),
    )
    assert revealed.revision == 1
    assert revealed.value == value
    assert "SYNTHETIC" not in repr(revealed)


def test_blob_singleton_round_trips_only_through_blob_methods(singleton_pack):
    pack, store, token = singleton_pack
    handle = pack.singletons("pack-state")
    value = b"SYNTHETIC_QUEUE_STATE_BLOB_CANARY"

    receipt = handle.replace_blob(
        "queue-state",
        value,
        0,
        _authorization(pack, token, "singleton.replace"),
    )

    assert receipt.revision == 1
    assert store.snapshots["queue-state"].protected["schema"] == (
        "helto.singleton.queue-state.bytes"
    )
    assert handle.reveal_blob(
        "queue-state",
        _authorization(pack, token, "singleton.reveal"),
    ).value == value
    with pytest.raises(SingletonError) as wrong_kind:
        handle.reveal_field(
            "queue-state",
            _authorization(pack, token, "singleton.reveal"),
        )
    assert wrong_kind.value.code == "PRIVACY_SINGLETON_OPERATION_INVALID"


def test_stale_revision_never_overwrites_current_singleton(singleton_pack):
    pack, store, token = singleton_pack
    handle = pack.singletons("pack-state")
    authorization = _authorization(pack, token, "singleton.replace")
    handle.replace_field("provider-settings", {"version": 1}, 0, authorization)
    original = copy.deepcopy(store.snapshots["provider-settings"])

    with pytest.raises(SingletonError) as stale:
        handle.replace_field(
            "provider-settings",
            {"version": 2},
            0,
            _authorization(pack, token, "singleton.replace"),
        )

    assert stale.value.code == "PRIVACY_SINGLETON_REVISION_CONFLICT"
    _assert_snapshot_equal(store.snapshots["provider-settings"], original)
    assert store.begin_calls == [("provider-settings", 0)]


def test_atomic_cas_conflict_never_rolls_back_concurrent_writer(singleton_pack):
    pack, store, token = singleton_pack
    concurrent_value = PrivacyEnvelopeCodec(
        "helto.singleton.provider-settings"
    ).encrypt_state({"token": "SYNTHETIC_CONCURRENT_WINNER"})
    concurrent = SingletonSnapshot(1, concurrent_value)
    store.concurrent_snapshot = concurrent

    with pytest.raises(SingletonError) as conflict:
        pack.singletons("pack-state").replace_field(
            "provider-settings",
            {"token": "SYNTHETIC_CONFLICTING_WRITER"},
            0,
            _authorization(pack, token, "singleton.replace"),
        )

    assert conflict.value.code == "PRIVACY_SINGLETON_REVISION_CONFLICT"
    _assert_snapshot_equal(store.snapshots["provider-settings"], concurrent)


def test_verified_readback_failure_rolls_back_exact_snapshot(singleton_pack):
    pack, store, token = singleton_pack
    store.mismatch_readback = True
    original = copy.deepcopy(store.snapshots["provider-settings"])

    with pytest.raises(SingletonError) as failure:
        pack.singletons("pack-state").replace_field(
            "provider-settings",
            {"token": "SYNTHETIC_FAILED_REPLACEMENT"},
            0,
            _authorization(pack, token, "singleton.replace"),
        )

    assert failure.value.code == "PRIVACY_SINGLETON_VERIFICATION_FAILED"
    _assert_snapshot_equal(store.snapshots["provider-settings"], original)


def test_partial_commit_failure_rolls_back_exact_snapshot(singleton_pack):
    pack, store, token = singleton_pack
    store.fail_commit = True
    original = copy.deepcopy(store.snapshots["provider-settings"])

    with pytest.raises(SingletonError) as failure:
        pack.singletons("pack-state").replace_field(
            "provider-settings",
            {"token": "SYNTHETIC_PARTIAL_COMMIT"},
            0,
            _authorization(pack, token, "singleton.replace"),
        )

    assert failure.value.code == "PRIVACY_SINGLETON_REPLACE_FAILED"
    _assert_snapshot_equal(store.snapshots["provider-settings"], original)


def test_malformed_and_locked_state_never_defaults_or_resets(singleton_pack):
    pack, store, token = singleton_pack
    handle = pack.singletons("pack-state")
    handle.replace_field(
        "provider-settings",
        {"token": "SYNTHETIC_LOCKED_SECRET"},
        0,
        _authorization(pack, token, "singleton.replace"),
    )
    original = copy.deepcopy(store.snapshots["provider-settings"])
    lock_keystore()

    assert handle.status("provider-settings").revision == 1
    with pytest.raises(PrivacyAuthorizationError) as locked_read:
        handle.reveal_field(
            "provider-settings",
            _authorization(pack, token, "singleton.reveal"),
        )
    assert locked_read.value.code == "PRIVACY_LOCKED"
    _assert_snapshot_equal(store.snapshots["provider-settings"], original)

    store.snapshots["provider-settings"] = SingletonSnapshot(
        1,
        {"schema": "unknown"},
    )
    malformed = copy.deepcopy(store.snapshots["provider-settings"])
    with pytest.raises(SingletonError) as malformed_status:
        handle.status("provider-settings")
    assert malformed_status.value.code == "PRIVACY_SINGLETON_STORED_VALUE_INVALID"
    _assert_snapshot_equal(store.snapshots["provider-settings"], malformed)


def test_malformed_existing_value_blocks_replace_and_delete(singleton_pack):
    pack, store, token = singleton_pack
    malformed = SingletonSnapshot(4, {"schema": "unknown"})
    store.snapshots["provider-settings"] = malformed
    handle = pack.singletons("pack-state")

    with pytest.raises(SingletonError) as replace_failure:
        handle.replace_field(
            "provider-settings",
            {"token": "SYNTHETIC_WOULD_RESET_MALFORMED"},
            4,
            _authorization(pack, token, "singleton.replace"),
        )
    assert replace_failure.value.code == "PRIVACY_SINGLETON_STORED_VALUE_INVALID"

    with pytest.raises(SingletonError) as delete_failure:
        handle.delete(
            "provider-settings",
            4,
            _authorization(pack, token, "singleton.delete"),
        )
    assert delete_failure.value.code == "PRIVACY_SINGLETON_STORED_VALUE_INVALID"
    _assert_snapshot_equal(store.snapshots["provider-settings"], malformed)


def test_rollback_failure_blocks_with_sanitized_error(singleton_pack):
    pack, store, token = singleton_pack
    store.fail_commit = True
    store.fail_rollback = True

    with pytest.raises(SingletonError) as failure:
        pack.singletons("pack-state").replace_field(
            "provider-settings",
            {"token": "SYNTHETIC_ROLLBACK_FAILURE"},
            0,
            _authorization(pack, token, "singleton.replace"),
        )

    assert failure.value.code == "PRIVACY_SINGLETON_ROLLBACK_FAILED"
    assert "SYNTHETIC" not in str(failure.value)
    assert "SYNTHETIC" not in repr(failure.value)


def test_delete_persists_revisioned_tombstone_and_blocks_aba(singleton_pack):
    pack, _store, token = singleton_pack
    handle = pack.singletons("pack-state")
    handle.replace_field(
        "provider-settings",
        {"token": "SYNTHETIC_DELETE_SECRET"},
        0,
        _authorization(pack, token, "singleton.replace"),
    )

    receipt = handle.delete(
        "provider-settings",
        1,
        _authorization(pack, token, "singleton.delete"),
    )

    assert receipt.revision == 2
    assert receipt.operation == "delete"
    assert handle.status("provider-settings").to_payload() == {
        "exists": False,
        "revision": 2,
        "private": True,
        "currentFormat": True,
    }
    with pytest.raises(SingletonError) as stale_create:
        handle.replace_field(
            "provider-settings",
            {"token": "SYNTHETIC_STALE_CREATE"},
            0,
            _authorization(pack, token, "singleton.replace"),
        )
    assert stale_create.value.code == "PRIVACY_SINGLETON_REVISION_CONFLICT"


class PlaintextLegacyReader:
    def probe(self, source, _context):
        return (
            isinstance(source, dict)
            and set(source) == {"schema", "version", "value"}
            and source.get("schema") == "synthetic-provider-plaintext"
            and source.get("version") == 1
            and isinstance(source.get("value"), dict)
        )

    def read(self, source, _context):
        if not self.probe(source, _context):
            raise ValueError("invalid synthetic plaintext fixture")
        return copy.deepcopy(source["value"])


class SingletonLegacyMigrationTransaction:
    def __init__(self, store, source_path, *, valid_readback=True) -> None:
        self.store = store
        self.source_path = source_path
        self.valid_readback = valid_readback
        self.original = copy.deepcopy(store.snapshots["provider-settings"])
        self.transaction = None

    def capture_original(self):
        return {
            "revision": self.original.revision,
            "protected": self.original.protected,
        }

    def stage_current(self, normalized):
        protected = PrivacyEnvelopeCodec(
            "helto.singleton.provider-settings"
        ).encrypt_state(normalized)
        replacement = SingletonSnapshot(self.original.revision + 1, protected)
        self.transaction = self.store.begin_singleton_replace(
            "provider-settings",
            self.original.revision,
            replacement,
        )

    def stage_durable_adjuncts(self, _normalized):
        return None

    def commit(self):
        if self.transaction.commit() is not True:
            raise ValueError("revision conflict")

    def read_back(self):
        snapshot = self.transaction.read_back()
        return MigrationVerification(
            normalized=PrivacyEnvelopeCodec(
                "helto.singleton.provider-settings"
            ).decrypt_state(snapshot.protected),
            current_format=True,
            durable_artifacts_current=self.valid_readback,
        )

    def rollback(self, _original):
        self.transaction.rollback()

    def finalize(self, _original):
        self.source_path.unlink()


def test_plaintext_singleton_source_retires_only_after_verified_current_readback(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        migration.MIGRATION_STATE_ENV,
        str(tmp_path / "migration" / "state.json"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    migration.reset_migration_runtime_for_tests()
    register_legacy_reader_units(
        (
            LegacyReaderUnit(
                "provider-plaintext-v1",
                "Provider plaintext v1",
                PlaintextLegacyReader(),
            ),
        )
    )
    store = SingletonStore()
    pack = install(
        _profile(legacy_reader_id="provider-plaintext-v1"),
        {"mode": ModeAdapter(), "singleton-store": store},
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    source_path = tmp_path / "provider-settings.json"
    source_path.write_text("SYNTHETIC_PLAINTEXT_SOURCE", encoding="utf-8")
    source = {
        "schema": "synthetic-provider-plaintext",
        "version": 1,
        "value": {"token": "SYNTHETIC_MIGRATED_PROVIDER_SECRET"},
    }
    discovered = pack.migration.discover_and_read(
        "provider-plaintext-v1",
        source,
        _authorization(pack, token, "migration.read"),
    )
    transaction = SingletonLegacyMigrationTransaction(store, source_path)

    receipt = pack.migration.complete(
        discovered.obligation.id,
        discovered.value,
        transaction,
        _authorization(pack, token, "migration.complete"),
    )

    assert receipt.disposition == "migrated"
    assert not source_path.exists()
    assert PrivacyEnvelopeCodec(
        "helto.singleton.provider-settings"
    ).decrypt_state(store.snapshots["provider-settings"].protected) == source["value"]


def test_failed_plaintext_singleton_migration_preserves_source_and_prior_snapshot(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        migration.MIGRATION_STATE_ENV,
        str(tmp_path / "migration" / "state.json"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    migration.reset_migration_runtime_for_tests()
    register_legacy_reader_units(
        (
            LegacyReaderUnit(
                "provider-plaintext-v1",
                "Provider plaintext v1",
                PlaintextLegacyReader(),
            ),
        )
    )
    store = SingletonStore()
    original = copy.deepcopy(store.snapshots["provider-settings"])
    pack = install(
        _profile(legacy_reader_id="provider-plaintext-v1"),
        {"mode": ModeAdapter(), "singleton-store": store},
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    source_path = tmp_path / "provider-settings.json"
    source_path.write_text("SYNTHETIC_PLAINTEXT_SOURCE", encoding="utf-8")
    source = {
        "schema": "synthetic-provider-plaintext",
        "version": 1,
        "value": {"token": "SYNTHETIC_FAILED_PROVIDER_MIGRATION"},
    }
    discovered = pack.migration.discover_and_read(
        "provider-plaintext-v1",
        source,
        _authorization(pack, token, "migration.read"),
    )
    transaction = SingletonLegacyMigrationTransaction(
        store,
        source_path,
        valid_readback=False,
    )

    with pytest.raises(migration.MigrationError) as failure:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            _authorization(pack, token, "migration.complete"),
        )

    assert failure.value.code == "migration_verification_failed"
    assert source_path.exists()
    _assert_snapshot_equal(store.snapshots["provider-settings"], original)
    assert pack.migration.obligation(
        discovered.obligation.id
    ).disposition == "unresolved"
