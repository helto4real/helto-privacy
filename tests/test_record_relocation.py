from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import threading

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.keystore as keystore
import helto_privacy.migration as legacy_migration
import helto_privacy.record_relocation as relocation
import helto_privacy.runtime as runtime
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.profile import (
    AdapterSlot,
    LegacyLocationKind,
    LegacyReaderBinding,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    RecordDeclaration,
    RecordReferenceMigration,
    ResourceKind,
)
from helto_privacy.record_relocation import (
    LegacyRecordSource,
    RecordReferenceError,
    RecordRelocationCommit,
    RecordRelocationReadback,
)
from helto_privacy.records import RecordSnapshot


class ModeAdapter(ModeSourceProtocolFixture):
    def read_declared_mode(self, _scope_id):
        return "private"

    def write_declared_mode(self, _scope_id, _mode):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class RelocationStore:
    def __init__(self):
        self.legacy = {
            "old-private-id": (7, {"secret": "SYNTHETIC_PRIVATE_RECORD"}),
            "old-public-id": (2, {"name": "SYNTHETIC_PUBLIC_RECORD"}),
        }
        self.records = {}
        self.mappings = {}
        self.commits = {}
        self.finalized = {}
        self.commit_calls = 0
        self.raise_after_commit_once = False
        self.corrupt_readback = False
        self.finalize_diverged = False
        self.rollback_raise_after_side_effect_once = False
        self.non_json_readback = False

    def list_ids(self):
        return tuple(self.records)

    def read_record(self, record_id):
        revision, protected = self.records.get(record_id, (0, None))
        return RecordSnapshot(revision, protected)

    def compare_and_swap_record(self, record_id, expected, replacement):
        if self.read_record(record_id) != expected:
            return False
        if replacement.protected is None:
            self.records.pop(record_id, None)
        else:
            self.records[record_id] = (
                replacement.revision,
                copy.deepcopy(replacement.protected),
            )
        return True

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None

    def read_legacy_record(self, migration_id, legacy_reference):
        assert migration_id == "library-v1-relocation"
        revision, value = self.legacy[legacy_reference]
        return LegacyRecordSource(revision, copy.deepcopy(value))

    def commit_record_relocation(self, write):
        self.commit_calls += 1
        existing = self.commits.get(write.transaction_id)
        if existing is not None:
            return existing
        current = self.legacy.get(write.legacy_reference)
        if current is None or current[0] != write.source_revision:
            raise RuntimeError("source conflict")
        if write.record_id in self.records or write.mapping_id in self.mappings:
            raise RuntimeError("target conflict")
        self.records[write.record_id] = (1, copy.deepcopy(write.protected_record))
        self.mappings[write.mapping_id] = (
            write.migration_id,
            1,
            copy.deepcopy(write.protected_mapping),
        )
        commit = RecordRelocationCommit(
            "store-commit-1",
            1,
            1,
        )
        self.commits[write.transaction_id] = commit
        if self.raise_after_commit_once:
            self.raise_after_commit_once = False
            raise RuntimeError("synthetic crash after atomic commit")
        return commit

    def read_record_relocation(self, commit):
        assert commit.commit_id == "store-commit-1"
        record_id = next(reversed(self.records))
        mapping_id = next(reversed(self.mappings))
        protected_mapping = copy.deepcopy(self.mappings[mapping_id][2])
        if self.corrupt_readback:
            protected_mapping["ciphertext"] = "corrupt"
        if self.non_json_readback:
            protected_mapping = {"non_json": b"synthetic-bytes"}
        return RecordRelocationReadback(
            self.records[record_id][0],
            self.mappings[mapping_id][1],
            copy.deepcopy(self.records[record_id][1]),
            protected_mapping,
        )

    def rollback_record_relocation(self, rollback):
        record = self.records.get(rollback.record_id)
        mapping = self.mappings.get(rollback.mapping_id)
        if record is None and mapping is None:
            return "already-original"
        if (
            record is None
            or mapping is None
            or record[0] != rollback.expected_record_revision
            or mapping[1] != rollback.expected_mapping_revision
        ):
            return "diverged"
        del self.records[rollback.record_id]
        del self.mappings[rollback.mapping_id]
        if self.rollback_raise_after_side_effect_once:
            self.rollback_raise_after_side_effect_once = False
            raise RuntimeError("synthetic crash after rollback side effect")
        return "rolled-back"

    def finalize_legacy_record(self, finalize):
        if self.finalize_diverged:
            return "diverged"
        previous = self.finalized.get(finalize.transaction_id)
        if previous == finalize.committed_record_id:
            return "already-finalized"
        current = self.legacy.get(finalize.legacy_reference)
        if current is None or current[0] != finalize.expected_source_revision:
            return "diverged"
        del self.legacy[finalize.legacy_reference]
        self.finalized[finalize.transaction_id] = finalize.committed_record_id
        return "finalized"

    def list_record_reference_mapping_ids(self, migration_id):
        return tuple(
            mapping_id
            for mapping_id, (candidate, _revision, _protected) in self.mappings.items()
            if candidate == migration_id
        )

    def read_record_reference_mapping(self, mapping_id):
        return self.mappings[mapping_id][2]


def profile(*, relocation_enabled=True, pack_id="helto.record-relocation-test"):
    return PrivacyProfile(
        id=pack_id,
        distribution=f"comfyui-{pack_id}",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("library", ResourceKind.RECORD, ("records",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("records", ResourceKind.RECORD, "library"),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        records=(
            RecordDeclaration(
                "prompt-record",
                "library",
                "main",
                "helto.record-relocation-test.v1",
                "records",
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "library-v1-binding",
                "library-v1-reader",
                "library",
                LegacyLocationKind.RECORD,
                "prompt-record",
            ),
        ) if relocation_enabled else (),
        record_reference_migrations=(
            RecordReferenceMigration(
                "library-v1-relocation",
                "library",
                "prompt-record",
                "library-v1-binding",
            ),
        ) if relocation_enabled else (),
    )


class Request:
    def __init__(self, token):
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class Reader:
    def probe(self, _source, _context):
        return False

    def read(self, _source, _context):
        raise RuntimeError


@pytest.fixture
def relocation_pack(tmp_path, monkeypatch):
    monkeypatch.setenv(
        relocation.RECORD_RELOCATION_STATE_ENV,
        str(tmp_path / "relocations" / "state.json"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    legacy_migration.reset_migration_runtime_for_tests()
    legacy_migration.register_legacy_reader_units(
        (
            legacy_migration.LegacyReaderUnit(
                "library-v1-reader",
                "Synthetic relocation reader",
                Reader(),
            ),
        )
    )
    store = RelocationStore()
    pack = runtime.install(profile(), {"mode": ModeAdapter(), "records": store})
    token = keystore.initialize_keystore("synthetic relocation password")["token"]
    return pack, store, Request(token)


def authorization(pack, request, operation):
    return pack.authorization.authorize_request(request, operation)


def test_empty_declaration_preserves_old_fingerprint_and_adapter_contract():
    without = profile(relocation_enabled=False)
    assert "recordReferenceMigrations" not in without._canonical_value()
    assert "read_legacy_record" not in without.server_adapter_contracts["records"]


def test_declaration_changes_fingerprint_and_requires_atomic_adapter_contract():
    enabled = profile()
    disabled = profile(relocation_enabled=False)
    assert enabled.fingerprint != disabled.fingerprint
    assert set(enabled.server_adapter_contracts["records"]) >= {
        "read_legacy_record",
        "commit_record_relocation",
        "read_record_relocation",
        "rollback_record_relocation",
        "finalize_legacy_record",
        "list_record_reference_mapping_ids",
        "read_record_reference_mapping",
    }


@pytest.mark.parametrize("legacy_reference", ["old-private-id", "old-public-id"])
def test_migration_encrypts_complete_record_and_mapping_then_resolves(
    relocation_pack,
    legacy_reference,
):
    pack, store, request = relocation_pack
    receipt = pack.records("library").migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        legacy_reference,
        authorization(pack, request, "record.reference.migrate"),
    )
    assert receipt.record_id.startswith("hp-rec-")
    assert legacy_reference not in store.legacy
    protected = store.records[receipt.record_id][1]
    plaintext = PrivacyEnvelopeCodec("helto.record-relocation-test.v1").decrypt_state(protected)
    assert plaintext in (
        {"secret": "SYNTHETIC_PRIVATE_RECORD"},
        {"name": "SYNTHETIC_PUBLIC_RECORD"},
    )
    mapping_text = repr(store.mappings)
    assert legacy_reference not in mapping_text
    resolution = pack.records("library").resolve_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        legacy_reference,
        authorization(pack, request, "record.reference.resolve"),
    )
    assert resolution.record_id == receipt.record_id


def test_retry_is_idempotent_and_does_not_expose_reference(relocation_pack):
    pack, store, request = relocation_pack
    handle = pack.records("library")
    first = handle.migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.migrate"),
    )
    second = handle.migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.migrate"),
    )
    assert second.record_id == first.record_id
    assert len(store.records) == len(store.mappings) == 1
    assert "old-private-id" not in repr(first)


def test_resolver_rejects_missing_duplicate_corrupt_and_missing_target(relocation_pack):
    pack, store, request = relocation_pack
    resolve = lambda: pack.records("library").resolve_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.resolve"),
    )
    with pytest.raises(RecordReferenceError) as missing:
        resolve()
    assert missing.value.code == "PRIVACY_RECORD_REFERENCE_UNAVAILABLE"
    receipt = pack.records("library").migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.migrate"),
    )
    mapping_id = next(iter(store.mappings))
    original = store.mappings[mapping_id]
    store.mappings[mapping_id] = (original[0], original[1], {"schema": "corrupt"})
    with pytest.raises(RecordReferenceError):
        resolve()
    store.mappings[mapping_id] = original
    del store.records[receipt.record_id]
    with pytest.raises(RecordReferenceError):
        resolve()


def test_wrong_authorization_operation_fails_before_adapter_read(relocation_pack):
    pack, store, request = relocation_pack
    with pytest.raises(Exception):
        pack.records("library").migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.resolve"),
        )
    assert store.commit_calls == 0


def test_retry_recovers_crash_after_atomic_commit_with_same_ids(relocation_pack):
    pack, store, request = relocation_pack
    store.raise_after_commit_once = True
    handle = pack.records("library")
    with pytest.raises(RecordReferenceError) as crashed:
        handle.migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert crashed.value.code == "PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED"
    committed_record_id = next(iter(store.records))
    receipt = handle.migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.migrate"),
    )
    assert receipt.record_id == committed_record_id
    assert store.commit_calls == 2
    assert len(store.records) == len(store.mappings) == 1


def test_failed_verification_rolls_back_record_and_mapping_atomically(relocation_pack):
    pack, store, request = relocation_pack
    store.corrupt_readback = True
    with pytest.raises(RecordReferenceError) as failed:
        pack.records("library").migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert failed.value.code == "PRIVACY_RECORD_RELOCATION_VERIFICATION_FAILED"
    assert store.records == {}
    assert store.mappings == {}
    assert "old-private-id" in store.legacy


def test_finalize_divergence_persists_blocked_state(relocation_pack):
    pack, store, request = relocation_pack
    store.finalize_diverged = True
    handle = pack.records("library")
    with pytest.raises(RecordReferenceError) as first:
        handle.migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert first.value.code == "PRIVACY_RECORD_RELOCATION_BLOCKED"
    store.finalize_diverged = False
    with pytest.raises(RecordReferenceError) as retry:
        handle.migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert retry.value.code == "PRIVACY_RECORD_RELOCATION_BLOCKED"


def test_journal_and_safe_objects_never_render_reference_or_plaintext(relocation_pack):
    pack, _store, request = relocation_pack
    receipt = pack.records("library").migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.migrate"),
    )
    stored = relocation.record_relocation_state_path().read_text(encoding="utf-8")
    assert "old-private-id" not in stored
    assert "SYNTHETIC_PRIVATE_RECORD" not in stored
    assert "old-private-id" not in repr(receipt)


def test_browser_transport_keeps_reference_out_of_route_and_response_source():
    root = Path(__file__).resolve().parents[1]
    client = (root / "helto_privacy" / "web" / "privacy_client.js").read_text()
    route = "`${base(item)}/reference-migrations/${encodeURIComponent(migration.id)}/${operation}`"
    assert route in client
    assert "{ body: { reference } }" in client
    assert "reference-migrations/${encodeURIComponent(reference)" not in client
    route_source = (root / "helto_privacy" / "comfy_ui.py").read_text()
    assert 'set(payload) != {"reference"}' in route_source
    assert '"recordId": result.record_id' in route_source
    assert '"reference": result' not in route_source


def test_concurrent_same_reference_converges_on_one_record(relocation_pack):
    pack, store, request = relocation_pack
    barrier = threading.Barrier(4)
    results = []
    failures = []

    def migrate():
        try:
            barrier.wait()
            result = pack.records("library").migrate_legacy_reference(
                "prompt-record",
                "library-v1-relocation",
                "old-private-id",
                authorization(pack, request, "record.reference.migrate"),
            )
            results.append(result.record_id)
        except Exception as exc:  # pragma: no cover - asserted through failures.
            failures.append(exc)

    threads = [threading.Thread(target=migrate) for _index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert len(set(results)) == 1
    assert len(store.records) == len(store.mappings) == 1


def test_cross_profile_mapping_cannot_be_resolved_through_shared_adapter(
    relocation_pack,
):
    first, store, request = relocation_pack
    first_receipt = first.records("library").migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(first, request, "record.reference.migrate"),
    )
    second_profile = profile(pack_id="helto.record-relocation-adversary")
    second = runtime.install(
        second_profile,
        {"mode": ModeAdapter(), "records": store},
    )
    token = keystore.session_token()
    second_request = Request(token)
    with pytest.raises(RecordReferenceError) as unavailable:
        second.records("library").resolve_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(second, second_request, "record.reference.resolve"),
        )
    assert unavailable.value.code == "PRIVACY_RECORD_REFERENCE_UNAVAILABLE"
    mapping = PrivacyEnvelopeCodec(relocation.RECORD_REFERENCE_MAP_SCHEMA).decrypt_state(
        store.read_record_reference_mapping(next(iter(store.mappings)))
    )
    assert mapping["pack"] == first.profile.id
    assert mapping["fingerprint"] == first.profile.fingerprint
    assert mapping["target"] == first_receipt.record_id


def test_primary_key_rotation_resumes_prepared_transaction_without_duplicate(
    relocation_pack,
):
    pack, store, request = relocation_pack
    store.raise_after_commit_once = True
    with pytest.raises(RecordReferenceError):
        pack.records("library").migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    committed_record_id = next(iter(store.records))
    rotated = keystore.rotate_primary_key("synthetic relocation password")
    rotated_request = Request(rotated["token"])
    receipt = pack.records("library").migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, rotated_request, "record.reference.migrate"),
    )
    assert receipt.record_id == committed_record_id
    assert len(store.records) == len(store.mappings) == 1


def test_rollback_pending_recovers_crash_after_adapter_side_effect(relocation_pack):
    pack, store, request = relocation_pack
    store.corrupt_readback = True
    store.rollback_raise_after_side_effect_once = True
    handle = pack.records("library")
    with pytest.raises(RecordReferenceError) as crashed:
        handle.migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert crashed.value.code == "PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED"
    assert store.records == store.mappings == {}
    with pytest.raises(RecordReferenceError) as recovered:
        handle.migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert recovered.value.code == "PRIVACY_RECORD_RELOCATION_VERIFICATION_FAILED"
    store.corrupt_readback = False
    receipt = handle.migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, request, "record.reference.migrate"),
    )
    assert receipt.record_id in store.records


def test_non_json_readback_twice_never_escapes_raw_canonicalization_error(
    relocation_pack,
):
    pack, store, request = relocation_pack
    store.non_json_readback = True
    for _attempt in range(2):
        with pytest.raises(RecordReferenceError) as failed:
            pack.records("library").migrate_legacy_reference(
                "prompt-record",
                "library-v1-relocation",
                "old-private-id",
                authorization(pack, request, "record.reference.migrate"),
            )
        assert failed.value.code == "PRIVACY_RECORD_RELOCATION_VERIFICATION_FAILED"
        assert "bytes" not in str(failed.value)
    assert store.records == store.mappings == {}


def test_locked_session_blocks_before_legacy_or_mapping_access(relocation_pack):
    pack, store, request = relocation_pack
    granted = authorization(pack, request, "record.reference.migrate")
    keystore.lock_keystore()
    with pytest.raises(Exception):
        pack.records("library").migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            granted,
        )
    assert store.commit_calls == 0
    assert store.records == store.mappings == {}


def test_unstable_scope_blocks_before_legacy_or_mapping_access(
    relocation_pack,
    monkeypatch,
):
    pack, store, request = relocation_pack
    monkeypatch.setattr(
        "helto_privacy.mode_runtime.require_stable_bound_scope",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic unstable scope")),
    )
    with pytest.raises(RecordReferenceError) as blocked:
        pack.records("library").migrate_legacy_reference(
            "prompt-record",
            "library-v1-relocation",
            "old-private-id",
            authorization(pack, request, "record.reference.migrate"),
        )
    assert blocked.value.code == "PRIVACY_RECORD_REFERENCE_UNAVAILABLE"
    assert store.commit_calls == 0
    assert store.records == store.mappings == {}


def test_identity_lookup_is_serialized_with_rotation_and_new_key_migration(
    relocation_pack,
    monkeypatch,
):
    pack, store, old_request = relocation_pack
    original_exclusive_state = relocation._exclusive_state
    first_waiting = threading.Event()
    release_first = threading.Event()
    first_gate_used = False
    current_request = {"value": old_request}

    @contextmanager
    def gated_exclusive_state():
        nonlocal first_gate_used
        if threading.current_thread().name == "old-key-request" and not first_gate_used:
            first_gate_used = True
            first_waiting.set()
            assert release_first.wait(timeout=5)
        with original_exclusive_state():
            yield

    monkeypatch.setattr(relocation, "_exclusive_state", gated_exclusive_state)
    results = []
    failures = []

    def old_key_request():
        try:
            try:
                result = pack.records("library").migrate_legacy_reference(
                    "prompt-record",
                    "library-v1-relocation",
                    "old-private-id",
                    authorization(
                        pack,
                        old_request,
                        "record.reference.migrate",
                    ),
                )
            except Exception:
                retry_request = current_request["value"]
                result = pack.records("library").migrate_legacy_reference(
                    "prompt-record",
                    "library-v1-relocation",
                    "old-private-id",
                    authorization(
                        pack,
                        retry_request,
                        "record.reference.migrate",
                    ),
                )
            results.append(result.record_id)
        except Exception as exc:  # pragma: no cover - asserted through failures.
            failures.append(exc)

    first = threading.Thread(target=old_key_request, name="old-key-request")
    first.start()
    assert first_waiting.wait(timeout=5)

    rotated = keystore.rotate_primary_key("synthetic relocation password")
    new_request = Request(rotated["token"])
    current_request["value"] = new_request
    second_record_id = pack.records("library").migrate_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, new_request, "record.reference.migrate"),
    ).record_id
    release_first.set()
    first.join(timeout=5)

    assert not first.is_alive()
    assert failures == []
    assert results == [second_record_id]
    assert len(store.records) == len(store.mappings) == 1
    resolved = pack.records("library").resolve_legacy_reference(
        "prompt-record",
        "library-v1-relocation",
        "old-private-id",
        authorization(pack, new_request, "record.reference.resolve"),
    )
    assert resolved.record_id == second_record_id


def test_unlocked_session_key_ids_require_active_suite_and_unlock(monkeypatch):
    with pytest.raises(keystore.PrivacyKeystoreError):
        keystore.unlocked_session_key_ids()
    monkeypatch.setattr(
        keystore,
        "require_active_process_suite",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic inactive suite")),
    )
    with pytest.raises(RuntimeError, match="inactive suite"):
        keystore.unlocked_session_key_ids()
