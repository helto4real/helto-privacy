from __future__ import annotations

import copy
import threading

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.keystore as keystore
import helto_privacy.migration as migration
import helto_privacy.records as records
import helto_privacy.runtime as runtime
from helto_privacy import (
    LockedRecordShell,
    ProtectedRecordValue,
    RecordError,
    RecordMutationReceipt,
    RecordProjectionResult,
    RecordSnapshot,
    RevealedRecord,
    confirm_record_mutation,
    generate_private_record_id,
    private_record_response_headers,
    safe_record_diagnostic,
)
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.guard import PrivacyAuthorizationError, authorize_privacy_request
from helto_privacy.profile import (
    AdapterSlot,
    LegacyLocationKind,
    LegacyReaderBinding,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    RecordDeclaration,
    RecordRevealProjection,
    ResourceKind,
)


RECORD_ID = "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
SECOND_RECORD_ID = "hp-rec-Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6"


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


class RecordStore:
    def __init__(self) -> None:
        self.ids = (
            RECORD_ID,
            SECOND_RECORD_ID,
        )
        self.read_calls = 0
        self.project_calls = 0
        self.records = {}
        self.revisions = {}
        self.retained_plaintext = None
        self.extra_projection = {}
        self.deleted = []
        self.written = []
        self.failure = None
        self.mutation_calls = []
        self.project_replacement = None
        self.corrupt_next_write = False

    def list_ids(self):
        return tuple(dict.fromkeys((*self.ids, *self.records)))

    def read_record(self, record_id):
        self.read_calls += 1
        return RecordSnapshot(
            self.revisions.get(record_id, 1 if record_id in self.records else 0),
            self.records.get(record_id),
        )

    def compare_and_swap_record(self, record_id, expected, replacement):
        if self.failure:
            raise RuntimeError(self.failure)
        current = self.read_record(record_id)
        if current != expected:
            return False
        value = replacement.protected
        self.written.append((record_id, value))
        if self.corrupt_next_write:
            self.corrupt_next_write = False
            value = copy.deepcopy(value)
            value["ciphertext"] = (
                ("A" if value["ciphertext"][0] != "A" else "B")
                + value["ciphertext"][1:]
            )
        self.revisions[record_id] = replacement.revision
        if value is None:
            self.deleted.append(record_id)
            self.records.pop(record_id, None)
            self.ids = tuple(item for item in self.ids if item != record_id)
        else:
            self.records[record_id] = value
        return True

    def project(self, value, operation):
        self.project_calls += 1
        self.retained_plaintext = value
        projection = (
            {"prompt": value["prompt"], **self.extra_projection}
            if operation == "use"
            else {"summary": value["summary"], **self.extra_projection}
        )
        if self.project_replacement is not None:
            return RecordProjectionResult(projection, self.project_replacement)
        return projection

    def mutate(self, current, operation, value):
        self.mutation_calls.append((current, operation, value))
        result = dict(current or {})
        result.update(value["record"])
        return result

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class LegacyRecordReader:
    def __init__(self) -> None:
        self.probe_calls = 0
        self.read_calls = 0

    def probe(self, source, _context):
        self.probe_calls += 1
        return isinstance(source, dict) and source.get("schema") == "legacy.record.v1"

    def read(self, source, _context):
        self.read_calls += 1
        return copy.deepcopy(source["record"])


def _profile(
    *,
    reveal: bool = False,
    mutations: bool = False,
    legacy: bool = False,
) -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.record-test",
        distribution="comfyui-record-test",
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
                "helto.record-test.v1",
                "records",
                projections=(
                    RecordRevealProjection("details", ("summary",)),
                    RecordRevealProjection("use", ("prompt",)),
                ) if reveal else (),
                mutation_operations=(
                    "create",
                    "replace",
                    "patch",
                    "duplicate",
                ) if mutations else (),
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "prompt-record-v1-binding",
                "prompt-record-v1",
                "library",
                LegacyLocationKind.RECORD,
                "prompt-record",
            ),
        ) if legacy else (),
    )


@pytest.fixture
def record_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    store = RecordStore()
    keystore.initialize_keystore("synthetic record listing password")
    for record_id in store.ids:
        store.records[record_id] = PrivacyEnvelopeCodec(
            "helto.record-test.v1"
        ).encrypt_state({"prompt": "private", "summary": "private"})
    keystore.lock_keystore()
    pack = runtime.install(_profile(), {"mode": ModeAdapter(), "records": store})
    return pack, store


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


@pytest.fixture
def reveal_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    store = RecordStore()
    pack = runtime.install(_profile(reveal=True), {"mode": ModeAdapter(), "records": store})
    token = keystore.initialize_keystore("synthetic record password")["token"]
    record_id = store.ids[0]
    store.records[record_id] = PrivacyEnvelopeCodec(
        "helto.record-test.v1"
    ).encrypt_state(
        {
            "prompt": "SYNTHETIC_PRIVATE_PROMPT",
            "summary": "SYNTHETIC_PRIVATE_SUMMARY",
            "path": "/SYNTHETIC/PRIVATE/PATH",
        }
    )
    return pack, store, record_id, Request(token)


@pytest.fixture
def mutation_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    store = RecordStore()
    store.ids = ()
    pack = runtime.install(
        _profile(reveal=True, mutations=True),
        {"mode": ModeAdapter(), "records": store},
    )
    token = keystore.initialize_keystore("synthetic record mutation password")["token"]
    return pack, store, Request(token)


@pytest.fixture
def legacy_record_pack(tmp_path, monkeypatch):
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
    reader = LegacyRecordReader()
    migration.register_legacy_reader_units(
        (
            migration.LegacyReaderUnit(
                "prompt-record-v1",
                "Legacy prompt record",
                reader,
            ),
        )
    )
    store = RecordStore()
    store.ids = (RECORD_ID,)
    store.records[RECORD_ID] = {
        "schema": "legacy.record.v1",
        "record": {
            "prompt": "SYNTHETIC_LEGACY_PROMPT",
            "summary": "SYNTHETIC_LEGACY_SUMMARY",
        },
    }
    pack = runtime.install(
        _profile(reveal=True, mutations=True, legacy=True),
        {"mode": ModeAdapter(), "records": store},
    )
    token = keystore.initialize_keystore("synthetic legacy record password")["token"]
    return pack, store, reader, Request(token), tmp_path


def test_locked_listing_returns_only_minimal_shells_without_decrypting_records(
    record_pack,
):
    pack, store = record_pack

    shells = pack.records("library").list_shells("prompt-record")

    assert shells == (
        LockedRecordShell(
            id=RECORD_ID,
            kind="prompt-record",
        ),
        LockedRecordShell(
            id=SECOND_RECORD_ID,
            kind="prompt-record",
        ),
    )
    assert [shell.to_payload() for shell in shells] == [
        {
            "id": RECORD_ID,
            "kind": "prompt-record",
            "private": True,
            "label": "Private record",
        },
        {
            "id": SECOND_RECORD_ID,
            "kind": "prompt-record",
            "private": True,
            "label": "Private record",
        },
    ]
    assert store.read_calls == 2
    assert "A1b2C3d4" not in repr(shells[0])


def test_legacy_listing_blocks_unclassified_storage_without_probing(
    legacy_record_pack,
):
    pack, store, reader, _request, tmp_path = legacy_record_pack

    with pytest.raises(RecordError) as blocked:
        pack.records("library").list_shells("prompt-record")

    assert blocked.value.code == "PRIVACY_RECORD_MODE_BLOCKED"
    assert store.read_calls == 1
    assert reader.probe_calls == 0
    assert reader.read_calls == 0
    assert not (tmp_path / "migration" / "state.json").exists()


def test_generic_migration_handle_cannot_reveal_record_plaintext(
    legacy_record_pack,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack
    authorization = authorize_privacy_request(
        request,
        "migration.read",
        pack_id=pack.profile.id,
    )

    with pytest.raises(migration.MigrationError) as blocked:
        pack.migration.discover_and_read(
            "prompt-record-v1-binding",
            store.records[RECORD_ID],
            authorization,
        )

    assert blocked.value.code == "typed_migration_operation_required"
    with pytest.raises(migration.MigrationError) as bound_blocked:
        migration.discover_bound_legacy(
            pack.profile,
            "prompt-record-v1-binding",
            store.records[RECORD_ID],
            authorization,
            operation_id="migration.read",
        )
    assert bound_blocked.value.code == "typed_migration_operation_required"
    assert reader.probe_calls == 0
    assert reader.read_calls == 0


@pytest.mark.parametrize("operation_id", ["record.audit", "record.use"])
def test_record_authorization_cannot_invoke_raw_migration_bridge(
    legacy_record_pack,
    operation_id,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack

    with pytest.raises(migration.MigrationError) as blocked:
        migration.discover_bound_legacy(
            pack.profile,
            "prompt-record-v1-binding",
            store.records[RECORD_ID],
            authorize_privacy_request(
                request,
                operation_id,
                pack_id=pack.profile.id,
            ),
            operation_id=operation_id,
        )

    assert blocked.value.code == "typed_migration_operation_required"
    assert reader.probe_calls == 0
    assert reader.read_calls == 0


def test_generic_migration_handle_cannot_complete_record_obligation(
    legacy_record_pack,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack
    original = copy.deepcopy(store.records[RECORD_ID])
    store.extra_projection = {"path": "/SYNTHETIC/PRIVATE/PATH"}

    with pytest.raises(RecordError):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )
    obligation_id = next(iter(migration._load_state()["obligations"]))
    transaction = records._RecordMigrationTransaction(
        store,
        RECORD_ID,
        "helto.record-test.v1",
        original=store.read_record(RECORD_ID),
    )

    authorization = authorize_privacy_request(
        request,
        "migration.complete",
        pack_id=pack.profile.id,
    )
    with pytest.raises(migration.MigrationError) as blocked:
        pack.migration.complete(
            obligation_id,
            {"prompt": "SYNTHETIC_BYPASS"},
            transaction,
            authorization,
        )

    assert blocked.value.code == "typed_migration_operation_required"
    with pytest.raises(migration.MigrationError) as bound_blocked:
        migration.complete_bound_legacy(
            pack.profile,
            "prompt-record-v1-binding",
            obligation_id,
            {"prompt": "SYNTHETIC_BYPASS"},
            transaction,
            authorization,
            operation_id="migration.complete",
            recovery_locator=RECORD_ID,
        )
    assert bound_blocked.value.code == "typed_migration_operation_required"
    with pytest.raises(migration.MigrationError) as record_blocked:
        migration.complete_bound_legacy(
            pack.profile,
            "prompt-record-v1-binding",
            obligation_id,
            {"prompt": "SYNTHETIC_BYPASS"},
            transaction,
            authorize_privacy_request(
                request,
                "record.audit",
                pack_id=pack.profile.id,
            ),
            operation_id="record.audit",
            recovery_locator=RECORD_ID,
        )
    assert record_blocked.value.code == "typed_migration_operation_required"
    assert store.records[RECORD_ID] == original
    assert pack.migration.status()[0].unresolved == 1


def test_generic_migration_handle_cannot_recover_record_transaction(
    legacy_record_pack,
    monkeypatch,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack
    original_commit = records._RecordMigrationTransaction.commit

    class SyntheticProcessStop(BaseException):
        pass

    def stop_after_write(transaction):
        original_commit(transaction)
        raise SyntheticProcessStop()

    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "commit",
        stop_after_write,
    )
    with pytest.raises(SyntheticProcessStop):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )
    obligation_id = next(iter(migration._load_state()["obligations"]))
    transaction = records._RecordMigrationTransaction(
        store,
        RECORD_ID,
        "helto.record-test.v1",
    )

    authorization = authorize_privacy_request(
        request,
        "migration.recover",
        pack_id=pack.profile.id,
    )
    with pytest.raises(migration.MigrationError) as blocked:
        pack.migration.recover_pending(
            obligation_id,
            transaction,
            authorization,
        )

    assert blocked.value.code == "typed_migration_operation_required"
    with pytest.raises(migration.MigrationError) as bound_blocked:
        migration.recover_bound_legacy(
            pack.profile,
            ("prompt-record-v1-binding",),
            RECORD_ID,
            transaction,
            authorization,
            operation_id="migration.recover",
        )
    state = migration._load_state()
    assert bound_blocked.value.code == "typed_migration_operation_required"
    with pytest.raises(migration.MigrationError) as record_blocked:
        migration.recover_bound_legacy(
            pack.profile,
            ("prompt-record-v1-binding",),
            RECORD_ID,
            transaction,
            authorize_privacy_request(
                request,
                "record.audit",
                pack_id=pack.profile.id,
            ),
            operation_id="record.audit",
        )
    assert record_blocked.value.code == "typed_migration_operation_required"
    assert len(state["transactions"]) == 1
    assert PrivacyEnvelopeCodec("helto.record-test.v1").is_encrypted_payload(
        store.records[RECORD_ID]
    )
    assert reader.read_calls == 1


def test_typed_record_audit_checks_scope_without_returning_plaintext(
    legacy_record_pack,
):
    pack, _store, reader, request, _tmp_path = legacy_record_pack
    pack.migration.declare_audit_scope(
        "legacy-records",
        "prompt-record-v1",
        (migration.AuditItem("record-a", migration.AuditItemKind.LIBRARY),),
        authorize_privacy_request(
            request,
            "migration.audit.declare",
            pack_id=pack.profile.id,
        ),
    )

    matched = pack.records("library").audit_legacy(
        "prompt-record",
        RECORD_ID,
        "legacy-records",
        "record-a",
        "prompt-record-v1-binding",
        authorize_privacy_request(
            request,
            "record.audit",
            pack_id=pack.profile.id,
        ),
    )

    assert matched is True
    assert reader.read_calls == 1
    with pytest.raises(migration.MigrationError) as unresolved:
        pack.migration.confirm_retirement_seal(
            "legacy-records",
            "prompt-record-v1",
            authorize_privacy_request(
                request,
                "migration.audit.seal",
                pack_id=pack.profile.id,
            ),
        )
    assert unresolved.value.code == "audit_scope_has_unresolved_migrations"

    pack.records("library").reveal(
        "prompt-record",
        RECORD_ID,
        "use",
        authorize_privacy_request(
            request,
            "record.use",
            pack_id=pack.profile.id,
        ),
    )
    seal = pack.migration.confirm_retirement_seal(
        "legacy-records",
        "prompt-record-v1",
        authorize_privacy_request(
            request,
            "migration.audit.seal",
            pack_id=pack.profile.id,
        ),
    )
    assert seal.valid is True


def test_locked_listing_rejects_nonopaque_consumer_ids(record_pack):
    pack, store = record_pack
    store.ids = ("user-authored-project-name",)

    with pytest.raises(RecordError) as invalid:
        pack.records("library").list_shells("prompt-record")

    assert invalid.value.code == "PRIVACY_RECORD_ID_INVALID"
    assert store.read_calls == 0
    assert "user-authored" not in str(invalid.value)
    assert "user-authored" not in repr(invalid.value)


def test_record_ids_are_shared_minted_and_bare_hashes_are_rejected(
    record_pack,
    monkeypatch,
):
    pack, store = record_pack
    monkeypatch.setattr(
        "helto_privacy.records.secrets.token_urlsafe",
        lambda _size: "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
    )

    assert generate_private_record_id() == RECORD_ID

    store.ids = ("0123456789abcdef0123456789abcdef",)
    with pytest.raises(RecordError) as bare_hash:
        pack.records("library").list_shells("prompt-record")
    assert bare_hash.value.code == "PRIVACY_RECORD_ID_INVALID"


def test_authorized_reveal_returns_only_allowlisted_product_projection(reveal_pack):
    pack, store, record_id, request = reveal_pack
    authorization = authorize_privacy_request(
        request,
        "record.use",
        pack_id=pack.profile.id,
    )

    revealed = pack.records("library").reveal(
        "prompt-record",
        record_id,
        "use",
        authorization,
    )

    assert isinstance(revealed, RevealedRecord)
    assert revealed.value == {"prompt": "SYNTHETIC_PRIVATE_PROMPT"}
    assert revealed.correlation_id.startswith("hp-record-")
    assert "SYNTHETIC_PRIVATE_PROMPT" not in repr(revealed)
    assert store.read_calls == 1
    assert store.project_calls == 1
    assert store.retained_plaintext == {}


def test_authorized_legacy_reveal_rewrites_verifies_and_receipts(
    legacy_record_pack,
):
    pack, store, reader, request, tmp_path = legacy_record_pack

    revealed = pack.records("library").reveal(
        "prompt-record",
        RECORD_ID,
        "use",
        authorize_privacy_request(request, "record.use", pack_id=pack.profile.id),
    )

    assert revealed.value == {"prompt": "SYNTHETIC_LEGACY_PROMPT"}
    assert PrivacyEnvelopeCodec("helto.record-test.v1").decrypt_state(
        store.records[RECORD_ID]
    ) == {
        "prompt": "SYNTHETIC_LEGACY_PROMPT",
        "summary": "SYNTHETIC_LEGACY_SUMMARY",
    }
    assert reader.probe_calls == 2
    assert reader.read_calls == 1
    status = pack.migration.status()
    assert status[0].discovered == 1
    assert status[0].resolved == 1
    assert status[0].unresolved == 0
    assert "SYNTHETIC" not in repr(revealed)
    assert "SYNTHETIC" not in (tmp_path / "migration" / "state.json").read_text()


def test_legacy_reveal_replacement_becomes_the_verified_current_state(
    legacy_record_pack,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack
    store.project_replacement = {
        "prompt": "SYNTHETIC_LEGACY_PROMPT",
        "summary": "SYNTHETIC_LEGACY_SUMMARY",
        "last_used_at": "2030-01-01T00:00:00Z",
    }

    revealed = pack.records("library").reveal(
        "prompt-record",
        RECORD_ID,
        "use",
        authorize_privacy_request(request, "record.use", pack_id=pack.profile.id),
    )

    assert revealed.value == {"prompt": "SYNTHETIC_LEGACY_PROMPT"}
    assert PrivacyEnvelopeCodec("helto.record-test.v1").decrypt_state(
        store.records[RECORD_ID]
    )["last_used_at"] == "2030-01-01T00:00:00Z"
    assert pack.migration.status()[0].resolved == 1


def test_unauthorized_legacy_reveal_never_invokes_the_reader(legacy_record_pack):
    pack, store, reader, _request, _tmp_path = legacy_record_pack

    with pytest.raises(PrivacyAuthorizationError):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            object(),
        )

    assert store.read_calls == 0
    assert reader.probe_calls == 0
    assert reader.read_calls == 0


def test_unauthorized_legacy_mutation_never_invokes_the_reader(legacy_record_pack):
    pack, store, reader, _request, _tmp_path = legacy_record_pack

    with pytest.raises(PrivacyAuthorizationError):
        pack.records("library").mutate(
            "prompt-record",
            "patch",
            {"record": {"summary": "SYNTHETIC_UNAUTHORIZED"}},
            object(),
            record_id=RECORD_ID,
        )

    assert store.read_calls == 0
    assert reader.probe_calls == 0
    assert reader.read_calls == 0


def test_corrupt_current_record_never_falls_back_to_a_legacy_reader(
    legacy_record_pack,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack
    store.records[RECORD_ID] = {
        "schema": "helto.record-test.v1",
        "encrypted": True,
        "algorithm": "AES-256-GCM",
        "ciphertext": "corrupt-current-envelope",
    }

    with pytest.raises(RecordError) as failed:
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )

    assert failed.value.code == "PRIVACY_RECORD_DECRYPT_FAILED"
    assert reader.probe_calls == 0
    assert reader.read_calls == 0


def test_record_declaration_exposes_strict_shell_and_mutation_contract():
    declaration = _profile(reveal=True, mutations=True).records[0]

    assert declaration.fixed_private_label == "Private record"
    assert declaration.safe_projection == ()
    assert declaration.mutation_operations == (
        "create",
        "duplicate",
        "patch",
        "replace",
    )


def test_authorized_create_patch_and_duplicate_are_shared_protected_mutations(
    mutation_pack,
    monkeypatch,
):
    pack, store, request = mutation_pack
    generated = iter(
        (
            "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "hp-rec-Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6",
        )
    )
    monkeypatch.setattr("helto_privacy.records.generate_private_record_id", lambda: next(generated))
    handle = pack.records("library")

    created = handle.mutate(
        "prompt-record",
        "create",
        {"record": {"prompt": "SYNTHETIC_CREATED", "summary": "created"}},
        authorize_privacy_request(request, "record.create", pack_id=pack.profile.id),
    )
    patched = handle.mutate(
        "prompt-record",
        "patch",
        {"record": {"summary": "patched"}},
        authorize_privacy_request(request, "record.patch", pack_id=pack.profile.id),
        record_id=created.record_id,
    )
    duplicated = handle.mutate(
        "prompt-record",
        "duplicate",
        {"record": {"prompt": "SYNTHETIC_DUPLICATED"}},
        authorize_privacy_request(request, "record.duplicate", pack_id=pack.profile.id),
        record_id=created.record_id,
    )

    codec = PrivacyEnvelopeCodec("helto.record-test.v1")
    assert created.operation == "create"
    assert patched.record_id == created.record_id
    assert duplicated.record_id != created.record_id
    assert codec.decrypt_state(store.records[created.record_id]) == {
        "prompt": "SYNTHETIC_CREATED",
        "summary": "patched",
    }
    assert codec.decrypt_state(store.records[duplicated.record_id]) == {
        "prompt": "SYNTHETIC_DUPLICATED",
        "summary": "patched",
    }
    assert all(
        envelope["schema"] == "helto.record-test.v1"
        for envelope in store.records.values()
    )


def test_record_protect_supports_verified_consumer_migration_without_commit(
    mutation_pack,
):
    pack, store, request = mutation_pack
    protected = pack.records("library").protect(
        "prompt-record",
        {"prompt": "SYNTHETIC_MIGRATED", "summary": "migration"},
        authorize_privacy_request(request, "record.protect", pack_id=pack.profile.id),
    )

    assert isinstance(protected, ProtectedRecordValue)
    assert protected.envelope["schema"] == "helto.record-test.v1"
    assert store.written == []


def test_failed_mutation_readback_restores_the_original_envelope(mutation_pack):
    pack, store, request = mutation_pack
    handle = pack.records("library")
    created = handle.mutate(
        "prompt-record",
        "create",
        {"record": {"prompt": "SYNTHETIC_ORIGINAL", "summary": "original"}},
        authorize_privacy_request(request, "record.create", pack_id=pack.profile.id),
    )
    original = copy.deepcopy(store.records[created.record_id])
    store.corrupt_next_write = True

    with pytest.raises(RecordError) as failed:
        handle.mutate(
            "prompt-record",
            "patch",
            {"record": {"summary": "SYNTHETIC_FAILED_PATCH"}},
            authorize_privacy_request(request, "record.patch", pack_id=pack.profile.id),
            record_id=created.record_id,
        )

    assert failed.value.code == "PRIVACY_RECORD_VERIFICATION_FAILED"
    assert store.records[created.record_id] == original
    assert "SYNTHETIC" not in repr(failed.value)


def test_legacy_projection_failure_keeps_original_and_obligation_unresolved(
    legacy_record_pack,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack
    original = copy.deepcopy(store.records[RECORD_ID])
    store.extra_projection = {"path": "/SYNTHETIC/PRIVATE/PATH"}

    with pytest.raises(RecordError) as failed:
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )

    assert failed.value.code == "PRIVACY_RECORD_PROJECTION_INVALID"
    assert store.records[RECORD_ID] == original
    status = pack.migration.status()[0]
    assert status.discovered == 1
    assert status.resolved == 0
    assert status.unresolved == 1
    assert "SYNTHETIC" not in repr(failed.value)


def test_legacy_readback_failure_restores_exact_original_and_stays_unresolved(
    legacy_record_pack,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack
    original = copy.deepcopy(store.records[RECORD_ID])
    store.corrupt_next_write = True

    with pytest.raises(RecordError) as failed:
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )

    assert failed.value.code == "PRIVACY_RECORD_VERIFICATION_FAILED"
    assert store.records[RECORD_ID] == original
    status = pack.migration.status()[0]
    assert status.resolved == 0
    assert status.unresolved == 1


@pytest.mark.parametrize("operation", ["patch", "replace"])
def test_legacy_in_place_mutations_commit_current_and_resolve(
    legacy_record_pack,
    operation,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack

    receipt = pack.records("library").mutate(
        "prompt-record",
        operation,
        {"record": {"summary": f"SYNTHETIC_{operation.upper()}"}},
        authorize_privacy_request(
            request,
            f"record.{operation}",
            pack_id=pack.profile.id,
        ),
        record_id=RECORD_ID,
    )

    assert receipt.record_id == RECORD_ID
    assert PrivacyEnvelopeCodec("helto.record-test.v1").decrypt_state(
        store.records[RECORD_ID]
    ) == {
        "prompt": "SYNTHETIC_LEGACY_PROMPT",
        "summary": f"SYNTHETIC_{operation.upper()}",
    }
    status = pack.migration.status()[0]
    assert status.resolved == 1
    assert status.unresolved == 0


def test_legacy_duplicate_migrates_source_before_creating_current_target(
    legacy_record_pack,
    monkeypatch,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack
    monkeypatch.setattr(
        records,
        "generate_private_record_id",
        lambda: SECOND_RECORD_ID,
    )

    receipt = pack.records("library").mutate(
        "prompt-record",
        "duplicate",
        {"record": {"summary": "SYNTHETIC_DUPLICATE"}},
        authorize_privacy_request(
            request,
            "record.duplicate",
            pack_id=pack.profile.id,
        ),
        record_id=RECORD_ID,
    )

    codec = PrivacyEnvelopeCodec("helto.record-test.v1")
    assert receipt.record_id == SECOND_RECORD_ID
    assert codec.decrypt_state(store.records[RECORD_ID]) == {
        "prompt": "SYNTHETIC_LEGACY_PROMPT",
        "summary": "SYNTHETIC_LEGACY_SUMMARY",
    }
    assert codec.decrypt_state(store.records[SECOND_RECORD_ID]) == {
        "prompt": "SYNTHETIC_LEGACY_PROMPT",
        "summary": "SYNTHETIC_DUPLICATE",
    }
    assert pack.migration.status()[0].resolved == 1


def test_legacy_duplicate_target_failure_keeps_truthful_source_receipt(
    legacy_record_pack,
    monkeypatch,
):
    pack, store, _reader, request, _tmp_path = legacy_record_pack
    monkeypatch.setattr(records, "generate_private_record_id", lambda: SECOND_RECORD_ID)
    original_compare_and_swap = store.compare_and_swap_record

    def fail_target(record_id, expected, replacement):
        if record_id == SECOND_RECORD_ID:
            raise OSError("synthetic target failure")
        return original_compare_and_swap(record_id, expected, replacement)

    monkeypatch.setattr(store, "compare_and_swap_record", fail_target)

    with pytest.raises(RecordError):
        pack.records("library").mutate(
            "prompt-record",
            "duplicate",
            {"record": {"summary": "SYNTHETIC_DUPLICATE"}},
            authorize_privacy_request(
                request,
                "record.duplicate",
                pack_id=pack.profile.id,
            ),
            record_id=RECORD_ID,
        )

    assert PrivacyEnvelopeCodec("helto.record-test.v1").is_encrypted_payload(
        store.records[RECORD_ID]
    )
    assert SECOND_RECORD_ID not in store.records
    status = pack.migration.status()[0]
    assert status.resolved == 1
    assert status.unresolved == 0


def test_next_authorized_reveal_recovers_prepared_record_transaction(
    legacy_record_pack,
    monkeypatch,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack
    original_commit = records._RecordMigrationTransaction.commit

    class SyntheticProcessStop(BaseException):
        pass

    def stop_after_write(transaction):
        original_commit(transaction)
        raise SyntheticProcessStop()

    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "commit",
        stop_after_write,
    )
    with pytest.raises(SyntheticProcessStop):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )
    assert PrivacyEnvelopeCodec("helto.record-test.v1").is_encrypted_payload(
        store.records[RECORD_ID]
    )

    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "commit",
        original_commit,
    )
    revealed = pack.records("library").reveal(
        "prompt-record",
        RECORD_ID,
        "use",
        authorize_privacy_request(request, "record.use", pack_id=pack.profile.id),
    )

    assert revealed.value == {"prompt": "SYNTHETIC_LEGACY_PROMPT"}
    assert reader.read_calls == 1
    assert pack.migration.status()[0].resolved == 1


def test_next_authorized_reveal_finishes_finalize_pending_receipt(
    legacy_record_pack,
    monkeypatch,
):
    pack, _store, reader, request, _tmp_path = legacy_record_pack
    original_finalize = records._RecordMigrationTransaction.finalize

    def fail_finalize(_transaction, _original):
        raise OSError("synthetic process interruption")

    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "finalize",
        fail_finalize,
    )
    with pytest.raises(RecordError) as pending:
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )
    assert pending.value.code == "PRIVACY_RECORD_VERIFICATION_FAILED"
    assert pack.migration.status()[0].resolved == 1

    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "finalize",
        original_finalize,
    )
    revealed = pack.records("library").reveal(
        "prompt-record",
        RECORD_ID,
        "use",
        authorize_privacy_request(request, "record.use", pack_id=pack.profile.id),
    )

    assert revealed.value == {"prompt": "SYNTHETIC_LEGACY_PROMPT"}
    assert reader.read_calls == 1
    assert pack.migration.status()[0].resolved == 1


@pytest.mark.parametrize("phase", ["prepared", "finalize-pending"])
@pytest.mark.parametrize("destructive_operation", ["delete", "replace"])
def test_pending_migration_never_undoes_locked_destructive_record_change(
    legacy_record_pack,
    monkeypatch,
    phase,
    destructive_operation,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack
    original_commit = records._RecordMigrationTransaction.commit
    original_finalize = records._RecordMigrationTransaction.finalize

    class SyntheticProcessStop(BaseException):
        pass

    if phase == "prepared":
        def stop_after_write(transaction):
            original_commit(transaction)
            raise SyntheticProcessStop()

        monkeypatch.setattr(
            records._RecordMigrationTransaction,
            "commit",
            stop_after_write,
        )
        expected_failure = SyntheticProcessStop
    else:
        def stop_before_finalize(_transaction, _original):
            raise OSError("synthetic finalize interruption")

        monkeypatch.setattr(
            records._RecordMigrationTransaction,
            "finalize",
            stop_before_finalize,
        )
        expected_failure = RecordError

    with pytest.raises(expected_failure):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )
    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "commit",
        original_commit,
    )
    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "finalize",
        original_finalize,
    )

    replacement = PrivacyEnvelopeCodec("helto.record-test.v1").encrypt_state(
        {
            "prompt": "SYNTHETIC_CONFIRMED_REPLACEMENT",
            "summary": "SYNTHETIC_REPLACEMENT_SUMMARY",
        }
    )
    keystore.lock_keystore()
    confirmation = confirm_record_mutation(
        pack_id=pack.profile.id,
        resource_id="library",
        record_kind="prompt-record",
        record_id=RECORD_ID,
        operation=destructive_operation,
        confirmed=True,
    )
    if destructive_operation == "delete":
        pack.records("library").delete(
            "prompt-record",
            RECORD_ID,
            confirmation,
        )
    else:
        pack.records("library").replace(
            "prompt-record",
            RECORD_ID,
            replacement,
            confirmation,
        )

    next_token = keystore.unlock_keystore(
        "synthetic legacy record password"
    )["token"]
    next_authorization = authorize_privacy_request(
        Request(next_token),
        "record.use",
        pack_id=pack.profile.id,
    )
    if destructive_operation == "delete":
        with pytest.raises(RecordError) as missing:
            pack.records("library").reveal(
                "prompt-record",
                RECORD_ID,
                "use",
                next_authorization,
            )
            assert missing.value.code == "PRIVACY_RECORD_READ_FAILED"
        assert RECORD_ID not in store.records
    else:
        revealed = pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            next_authorization,
        )
        assert revealed.value == {"prompt": "SYNTHETIC_CONFIRMED_REPLACEMENT"}
        assert PrivacyEnvelopeCodec("helto.record-test.v1").decrypt_state(
            store.records[RECORD_ID]
        )["prompt"] == "SYNTHETIC_CONFIRMED_REPLACEMENT"

    state = migration._load_state()
    obligation = next(iter(state["obligations"].values()))
    assert state["transactions"] == {}
    status = pack.migration.status()[0]
    if phase == "prepared":
        assert obligation["disposition"] == "unresolved"
        assert state["receipts"] == {}
        assert status.resolved == 0
        assert status.unresolved == 1
    else:
        assert obligation["disposition"] == "migrated"
        assert len(state["receipts"]) == 1
        assert status.resolved == 1
        assert status.unresolved == 0
    assert reader.read_calls == 1


@pytest.mark.parametrize("phase", ["prepared", "finalize-pending"])
@pytest.mark.parametrize(
    "divergent_value",
    (
        None,
        {
            "schema": "helto.record-test.v1",
            "encrypted": True,
            "algorithm": "AES-256-GCM",
            "ciphertext": "unrecognized-current-value",
        },
    ),
)
def test_recovery_preserves_unexplained_record_divergence(
    legacy_record_pack,
    monkeypatch,
    phase,
    divergent_value,
):
    pack, store, reader, request, _tmp_path = legacy_record_pack
    original_commit = records._RecordMigrationTransaction.commit
    original_finalize = records._RecordMigrationTransaction.finalize

    class SyntheticProcessStop(BaseException):
        pass

    if phase == "prepared":
        def stop_after_write(transaction):
            original_commit(transaction)
            raise SyntheticProcessStop()

        monkeypatch.setattr(
            records._RecordMigrationTransaction,
            "commit",
            stop_after_write,
        )
        expected_failure = SyntheticProcessStop
    else:
        def stop_before_finalize(_transaction, _original):
            raise OSError("synthetic finalize interruption")

        monkeypatch.setattr(
            records._RecordMigrationTransaction,
            "finalize",
            stop_before_finalize,
        )
        expected_failure = RecordError

    with pytest.raises(expected_failure):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )
    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "commit",
        original_commit,
    )
    monkeypatch.setattr(
        records._RecordMigrationTransaction,
        "finalize",
        original_finalize,
    )
    store.records[RECORD_ID] = copy.deepcopy(divergent_value)

    with pytest.raises(RecordError):
        pack.records("library").reveal(
            "prompt-record",
            RECORD_ID,
            "use",
            authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            ),
        )

    assert store.records[RECORD_ID] == divergent_value
    state = migration._load_state()
    obligation = next(iter(state["obligations"].values()))
    assert state["transactions"] == {}
    if phase == "prepared":
        assert obligation["disposition"] == "unresolved"
        assert state["receipts"] == {}
    else:
        assert obligation["disposition"] == "migrated"
        assert len(state["receipts"]) == 1
    assert reader.read_calls == 1


def test_concurrent_legacy_reveals_share_one_verified_migration(
    legacy_record_pack,
    monkeypatch,
):
    pack, _store, reader, request, _tmp_path = legacy_record_pack
    barrier = threading.Barrier(3)
    entered = threading.Event()
    release = threading.Event()
    failed = threading.Event()
    results = []
    failures = []
    original_read = reader.read

    def blocking_read(source, context):
        entered.set()
        assert release.wait(timeout=5)
        return original_read(source, context)

    monkeypatch.setattr(reader, "read", blocking_read)

    def reveal():
        try:
            authorization = authorize_privacy_request(
                request,
                "record.use",
                pack_id=pack.profile.id,
            )
            barrier.wait(timeout=5)
            results.append(
                pack.records("library").reveal(
                    "prompt-record",
                    RECORD_ID,
                    "use",
                    authorization,
                ).value
            )
        except Exception as exc:  # pragma: no cover - asserted below.
            failures.append(exc)
            failed.set()

    threads = [threading.Thread(target=reveal) for _index in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=5)
    assert entered.wait(timeout=5)
    assert failed.wait(timeout=5)
    release.set()
    for thread in threads:
        thread.join(timeout=5)

    assert len(failures) == 1
    assert isinstance(failures[0], RecordError)
    assert failures[0].code == "PRIVACY_RECORD_VERIFICATION_FAILED"
    assert len(results) == 1
    assert all(result == {"prompt": "SYNTHETIC_LEGACY_PROMPT"} for result in results)
    assert reader.read_calls == 1
    status = pack.migration.status()[0]
    assert status.discovered == 1
    assert status.resolved == 1


def test_authorized_use_can_persist_product_activity_under_shared_crypto(reveal_pack):
    pack, store, record_id, request = reveal_pack
    store.project_replacement = {
        "prompt": "SYNTHETIC_PRIVATE_PROMPT",
        "summary": "SYNTHETIC_PRIVATE_SUMMARY",
        "last_used_at": "2030-01-01T00:00:00Z",
    }
    revealed = pack.records("library").reveal(
        "prompt-record",
        record_id,
        "use",
        authorize_privacy_request(request, "record.use", pack_id=pack.profile.id),
    )

    assert revealed.value == {"prompt": "SYNTHETIC_PRIVATE_PROMPT"}
    assert PrivacyEnvelopeCodec("helto.record-test.v1").decrypt_state(
        store.records[record_id]
    )["last_used_at"] == "2030-01-01T00:00:00Z"


def test_reveal_rejects_nonallowlisted_projection_without_leaking_values(reveal_pack):
    pack, store, record_id, request = reveal_pack
    store.extra_projection = {"path": "/SYNTHETIC/PRIVATE/PATH"}
    authorization = authorize_privacy_request(
        request,
        "record.details",
        pack_id=pack.profile.id,
    )

    with pytest.raises(RecordError) as unsafe:
        pack.records("library").reveal(
            "prompt-record",
            record_id,
            "details",
            authorization,
        )

    assert unsafe.value.code == "PRIVACY_RECORD_PROJECTION_INVALID"
    assert "SYNTHETIC" not in str(unsafe.value)
    assert "SYNTHETIC" not in repr(unsafe.value)
    assert store.retained_plaintext == {}


def test_reveal_validates_safe_fields_for_the_exact_authorized_operation(reveal_pack):
    pack, store, record_id, request = reveal_pack
    store.extra_projection = {"summary": "SYNTHETIC_WRONG_OPERATION_FIELD"}
    authorization = authorize_privacy_request(
        request,
        "record.use",
        pack_id=pack.profile.id,
    )

    with pytest.raises(RecordError) as unsafe:
        pack.records("library").reveal(
            "prompt-record",
            record_id,
            "use",
            authorization,
        )

    assert unsafe.value.code == "PRIVACY_RECORD_PROJECTION_INVALID"
    assert "SYNTHETIC" not in repr(unsafe.value)


def test_locked_reveal_fails_before_read_or_projection(reveal_pack):
    pack, store, record_id, request = reveal_pack
    authorization = authorize_privacy_request(
        request,
        "record.use",
        pack_id=pack.profile.id,
    )
    keystore.lock_keystore()

    with pytest.raises(PrivacyAuthorizationError) as locked:
        pack.records("library").reveal(
            "prompt-record",
            record_id,
            "use",
            authorization,
        )

    assert locked.value.code == "PRIVACY_AUTHORIZATION_EXPIRED"
    assert store.read_calls == 0
    assert store.project_calls == 0


def test_decrypt_failure_blocks_listing_and_projection(reveal_pack):
    pack, store, record_id, request = reveal_pack
    tampered = dict(store.records[record_id])
    tampered["ciphertext"] = (
        ("A" if tampered["ciphertext"][0] != "A" else "B")
        + tampered["ciphertext"][1:]
    )
    store.records[record_id] = tampered
    authorization = authorize_privacy_request(
        request,
        "record.details",
        pack_id=pack.profile.id,
    )

    with pytest.raises(RecordError) as failed:
        pack.records("library").reveal(
            "prompt-record",
            record_id,
            "details",
            authorization,
        )

    assert failed.value.code == "PRIVACY_RECORD_DECRYPT_FAILED"
    assert store.project_calls == 0
    with pytest.raises(RecordError) as blocked:
        pack.records("library").list_shells("prompt-record")
    assert blocked.value.code == "PRIVACY_RECORD_MODE_BLOCKED"


def test_confirmed_delete_remains_available_while_locked_without_reading(record_pack):
    pack, store = record_pack
    record_id = store.ids[0]
    confirmation = confirm_record_mutation(
        pack_id=pack.profile.id,
        resource_id="library",
        record_kind="prompt-record",
        record_id=record_id,
        operation="delete",
        confirmed=True,
    )
    with pytest.raises(AttributeError):
        confirmation._binding = ("forged",) * 5

    receipt = pack.records("library").delete(
        "prompt-record",
        record_id,
        confirmation,
    )

    assert isinstance(receipt, RecordMutationReceipt)
    assert receipt.operation == "delete"
    assert receipt.correlation_id.startswith("hp-record-")
    assert store.deleted == [record_id]
    assert store.read_calls == 3
    with pytest.raises(RecordError) as reused:
        pack.records("library").delete(
            "prompt-record",
            record_id,
            confirmation,
        )
    assert reused.value.code == "PRIVACY_RECORD_CONFIRMATION_REQUIRED"


def test_confirmed_protected_replacement_works_while_locked_and_rejects_plaintext(
    reveal_pack,
):
    pack, store, record_id, _request = reveal_pack
    protected = store.records[record_id]
    keystore.lock_keystore()
    confirmation = confirm_record_mutation(
        pack_id=pack.profile.id,
        resource_id="library",
        record_kind="prompt-record",
        record_id=record_id,
        operation="replace",
        confirmed=True,
    )

    receipt = pack.records("library").replace(
        "prompt-record",
        record_id,
        protected,
        confirmation,
    )

    assert receipt.operation == "replace"
    assert store.written == [(record_id, protected)]
    assert store.read_calls == 3

    invalid_confirmation = confirm_record_mutation(
        pack_id=pack.profile.id,
        resource_id="library",
        record_kind="prompt-record",
        record_id=record_id,
        operation="replace",
        confirmed=True,
    )
    with pytest.raises(RecordError) as plaintext:
        pack.records("library").replace(
            "prompt-record",
            record_id,
            "SYNTHETIC_PLAINTEXT_CANARY",
            invalid_confirmation,
        )
    assert plaintext.value.code == "PRIVACY_RECORD_REPLACEMENT_INVALID"
    assert "SYNTHETIC" not in str(plaintext.value)
    assert len(store.written) == 1


def test_destructive_failures_use_fresh_value_free_errors(record_pack):
    pack, store = record_pack
    record_id = store.ids[0]
    store.failure = "/SYNTHETIC/PRIVATE/PATH user-authored-name"

    errors = []
    for _attempt in range(2):
        confirmation = confirm_record_mutation(
            pack_id=pack.profile.id,
            resource_id="library",
            record_kind="prompt-record",
            record_id=record_id,
            operation="delete",
            confirmed=True,
        )
        with pytest.raises(RecordError) as failed:
            pack.records("library").delete(
                "prompt-record",
                record_id,
                confirmation,
            )
        errors.append(failed.value)

    assert [error.code for error in errors] == [
        "PRIVACY_RECORD_DELETE_FAILED",
        "PRIVACY_RECORD_DELETE_FAILED",
    ]
    assert errors[0].correlation_id != errors[1].correlation_id
    assert "SYNTHETIC" not in repr(errors)
    assert "user-authored" not in repr(errors)
    assert store.read_calls == 4


def test_record_handle_has_no_locked_duplicate_merge_or_edit_escape_hatch(record_pack):
    handle = record_pack[0].records("library")

    assert not hasattr(handle, "duplicate")
    assert not hasattr(handle, "merge")
    assert not hasattr(handle, "edit")


def test_private_response_defaults_and_diagnostics_are_generic_and_allowlisted():
    headers = private_record_response_headers(download_kind="record")

    assert headers["Cache-Control"] == "private, no-store"
    assert headers["Pragma"] == "no-cache"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Disposition"] == 'attachment; filename="private-record.json"'
    assert headers["X-Helto-Privacy-Correlation-ID"].startswith("hp-record-")
    assert "path" not in str(headers).lower()

    diagnostic = safe_record_diagnostic(stage="reveal", count=2, flag=False)
    assert set(diagnostic) == {"correlationId", "stage", "count", "flag"}
    assert diagnostic["stage"] == "reveal"
    assert diagnostic["count"] == 2
    assert diagnostic["flag"] is False
    assert diagnostic["correlationId"].startswith("hp-record-")

    with pytest.raises(RecordError) as unsafe_stage:
        safe_record_diagnostic(stage="/SYNTHETIC/PRIVATE/PATH")
    assert unsafe_stage.value.code == "PRIVACY_RECORD_DIAGNOSTIC_INVALID"

    with pytest.raises(RecordError) as malformed_stage:
        safe_record_diagnostic(stage=[])  # type: ignore[arg-type]
    assert malformed_stage.value.code == "PRIVACY_RECORD_DIAGNOSTIC_INVALID"

    with pytest.raises(RecordError) as malformed_download:
        private_record_response_headers(download_kind=[])  # type: ignore[arg-type]
    assert malformed_download.value.code == "PRIVACY_RECORD_DIAGNOSTIC_INVALID"


def test_record_error_rejects_caller_supplied_product_data_as_an_error_code():
    error = RecordError("SYNTHETIC_PRIVATE_ERROR_CANARY")

    assert error.code == "PRIVACY_RECORD_OPERATION_FAILED"
    assert "SYNTHETIC" not in str(error)
    assert "SYNTHETIC" not in repr(error)
