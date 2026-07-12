from __future__ import annotations

import copy

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.runtime as runtime
from helto_privacy import (
    LockedRecordShell,
    ProtectedRecordValue,
    RecordError,
    RecordMutationReceipt,
    RecordProjectionResult,
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
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    RecordDeclaration,
    RecordRevealProjection,
    ResourceKind,
)


RECORD_ID = "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
SECOND_RECORD_ID = "hp-rec-Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6"


class ModeAdapter:
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

    def read_protected(self, record_id):
        self.read_calls += 1
        return self.records[record_id]

    def write_protected(self, record_id, value):
        if self.failure:
            raise RuntimeError(self.failure)
        self.written.append((record_id, value))
        if self.corrupt_next_write:
            self.corrupt_next_write = False
            value = copy.deepcopy(value)
            value["ciphertext"] = (
                ("A" if value["ciphertext"][0] != "A" else "B")
                + value["ciphertext"][1:]
            )
        self.records[record_id] = value

    def delete(self, record_id):
        if self.failure:
            raise RuntimeError(self.failure)
        self.deleted.append(record_id)
        self.records.pop(record_id, None)
        self.ids = tuple(item for item in self.ids if item != record_id)

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


def _profile(*, reveal: bool = False, mutations: bool = False) -> PrivacyProfile:
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


def test_locked_listing_returns_only_minimal_shells_without_reading_records(
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
    assert store.read_calls == 0
    assert "A1b2C3d4" not in repr(shells[0])


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


def test_decrypt_failure_keeps_shell_listable_and_blocks_projection(reveal_pack):
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
    assert pack.records("library").list_shells("prompt-record")[0].id == record_id


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
    assert store.read_calls == 0
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
    assert store.read_calls == 0

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
    assert store.read_calls == 0


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
