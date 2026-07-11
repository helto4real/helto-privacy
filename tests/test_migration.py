from __future__ import annotations

import json
import base64
import hashlib
import threading

import pytest

import helto_privacy.keystore as keystore
import helto_privacy._legacy_key_source as legacy_key_source
import helto_privacy.migration as migration
import helto_privacy.runtime as runtime
from helto_privacy.guard import authorize_privacy_request
from helto_privacy.profile import (
    AdapterSlot,
    FieldLocation,
    FieldLocationKind,
    LegacyLocationKind,
    LegacyKeyImportBinding,
    LegacyReaderBinding,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProfileResource,
    ResourceKind,
)


PASSWORD = "synthetic migration password"


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeAdapter:
    def read_declared_mode(self, _scope_id):
        return "private"

    def write_declared_mode(self, *_args):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class StateAdapter:
    def capture(self, *_args):
        return None

    def normalize(self, value, *_args):
        return dict(value)

    def apply_revealed(self, *_args):
        return None

    def clear_plaintext(self, *_args):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class Reader:
    def __init__(self) -> None:
        self.read_obligation_counts = []

    def probe(self, source, _context):
        return source == "SYNTHETIC_LEGACY_VALUE"

    def read(self, _source, context):
        self.read_obligation_counts.append(context.unresolved_count)
        return {"value": "SYNTHETIC_NORMALIZED_VALUE"}


class MigrationTransaction:
    def __init__(self, *, valid_readback=True, fail_finalize=False) -> None:
        self.original = b"SYNTHETIC_ORIGINAL_BYTES"
        self.current = None
        self.staged = None
        self.adjuncts_staged = False
        self.valid_readback = valid_readback
        self.fail_finalize = fail_finalize
        self.rollback_values = []
        self.finalized = False
        self.finalize_calls = 0

    def capture_original(self):
        return self.original

    def stage_current(self, value):
        self.staged = value

    def stage_durable_adjuncts(self, _value):
        self.adjuncts_staged = True

    def commit(self):
        self.current = self.staged

    def read_back(self):
        return migration.MigrationVerification(
            normalized=self.current,
            current_format=self.valid_readback,
            durable_artifacts_current=self.adjuncts_staged,
        )

    def rollback(self, original):
        self.rollback_values.append(original)
        self.original = original
        self.current = None

    def finalize(self, original):
        self.finalize_calls += 1
        if self.fail_finalize:
            raise OSError("synthetic finalize failure")
        if self.original is not None and self.original != original:
            raise OSError("source identity changed")
        self.original = None
        self.finalized = True


def _profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.migration-test",
        distribution="comfyui-migration-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("state", ResourceKind.WORKFLOW, ("state", "state-ui")),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state", ResourceKind.WORKFLOW, "state"),
        ),
        browser_adapters=(
            AdapterSlot("state-ui", ResourceKind.WORKFLOW, "state", ("SyntheticNode",)),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        protected_fields=(
            ProtectedField(
                "private-state",
                "state",
                "main",
                "state",
                "state-ui",
                ("SyntheticNode",),
                FieldLocation(FieldLocationKind.WIDGET, "state"),
                "helto.migration-test.v2",
                "state",
                legacy_reader_ids=("state-v1",),
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "state-v1-binding",
                "state-v1",
                "state",
                LegacyLocationKind.WORKFLOW_FIELD,
                "private-state",
            ),
        ),
        legacy_key_imports=(
            LegacyKeyImportBinding(
                "legacy-json-key-binding",
                "legacy-json-key",
                "state",
                LegacyLocationKind.WORKFLOW_FIELD,
                "private-state",
                migration.LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "legacy-binary-key-binding",
                "legacy-binary-key",
                "state",
                LegacyLocationKind.WORKFLOW_FIELD,
                "private-state",
                migration.LegacyKeyFormat.BINARY,
            ),
        ),
    )


@pytest.fixture
def migration_pack(tmp_path, monkeypatch):
    monkeypatch.setenv(
        migration.MIGRATION_STATE_ENV,
        str(tmp_path / "migration" / "state.json"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    migration.reset_migration_runtime_for_tests()
    reader = Reader()
    migration.register_legacy_reader_units(
        (migration.LegacyReaderUnit("state-v1", "Legacy state", reader),)
    )
    pack = runtime.install(
        _profile(),
        {"mode": ModeAdapter(), "state": StateAdapter()},
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    return pack, reader, token, tmp_path


def test_exact_reader_persists_protected_obligation_before_read(migration_pack):
    pack, reader, token, tmp_path = migration_pack
    request = Request(token)
    authorization = authorize_privacy_request(
        request,
        "migration.read",
        pack_id=pack.profile.id,
    )

    result = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorization,
    )

    assert result.value == {"value": "SYNTHETIC_NORMALIZED_VALUE"}
    assert result.obligation.reader_id == "state-v1"
    assert result.obligation.disposition == "unresolved"
    assert reader.read_obligation_counts == [1]
    assert not hasattr(reader, "write")
    assert "SYNTHETIC" not in repr(result)
    assert "SYNTHETIC" not in json.dumps(result.obligation.to_payload())
    stored = (tmp_path / "migration" / "state.json").read_text(encoding="utf-8")
    assert "SYNTHETIC" not in stored
    assert "state-v1" not in stored
    status = pack.migration.status()
    assert status == (
        migration.ReaderMigrationStatus(
            "state-v1",
            "Legacy state",
            discovered=1,
            resolved=0,
            unresolved=1,
            sealed=False,
        ),
    )
    assert "SYNTHETIC" not in repr(status)

    assert pack.migration.discover_and_read(
        "state-v1-binding",
        "not-legacy",
        authorization,
    ) is None


def test_verified_transaction_receipt_is_all_or_nothing(migration_pack):
    pack, _reader, token, tmp_path = migration_pack
    read_authorization = authorize_privacy_request(
        Request(token),
        "migration.read",
        pack_id=pack.profile.id,
    )
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        read_authorization,
    )
    transaction = MigrationTransaction()
    complete_authorization = authorize_privacy_request(
        Request(token),
        "migration.complete",
        pack_id=pack.profile.id,
    )

    receipt = pack.migration.complete(
        discovered.obligation.id,
        discovered.value,
        transaction,
        complete_authorization,
    )

    assert receipt.disposition == "migrated"
    assert pack.migration.obligation(discovered.obligation.id).disposition == "migrated"
    assert transaction.current == {"value": "SYNTHETIC_NORMALIZED_VALUE"}
    assert transaction.original is None
    assert transaction.finalized is True
    assert transaction.rollback_values == []
    stored = (tmp_path / "migration" / "state.json").read_text(encoding="utf-8")
    assert "SYNTHETIC" not in stored


def test_failed_verification_restores_exact_original_and_keeps_obligation_open(
    migration_pack,
):
    pack, _reader, token, _tmp_path = migration_pack
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )
    transaction = MigrationTransaction(valid_readback=False)
    original = transaction.original

    with pytest.raises(migration.MigrationError) as failure:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            authorize_privacy_request(
                Request(token),
                "migration.complete",
                pack_id=pack.profile.id,
            ),
        )

    assert failure.value.code == "migration_verification_failed"
    assert transaction.rollback_values == [original]
    assert transaction.original == original
    assert pack.migration.obligation(discovered.obligation.id).disposition == "unresolved"


def test_verified_receipt_resumes_pending_source_finalization(migration_pack):
    pack, _reader, token, _tmp_path = migration_pack
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )
    transaction = MigrationTransaction(fail_finalize=True)

    with pytest.raises(migration.MigrationError) as pending:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            authorize_privacy_request(
                Request(token),
                "migration.complete",
                pack_id=pack.profile.id,
            ),
        )
    assert pending.value.code == "migration_finalization_pending"
    assert transaction.original == b"SYNTHETIC_ORIGINAL_BYTES"

    transaction.fail_finalize = False
    receipt = pack.migration.complete(
        discovered.obligation.id,
        discovered.value,
        transaction,
        authorize_privacy_request(
            Request(token),
            "migration.complete",
            pack_id=pack.profile.id,
        ),
    )
    assert receipt.disposition == "migrated"
    assert transaction.original is None


def test_already_retired_exact_original_finalizes_idempotently_after_cleanup_failure(
    migration_pack,
    monkeypatch,
):
    pack, _reader, token, _tmp_path = migration_pack
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )
    transaction = MigrationTransaction()
    real_save = migration._save_state
    failed_once = False

    def fail_first_cleanup(state):
        nonlocal failed_once
        migrated = any(
            isinstance(item, dict) and item.get("disposition") == "migrated"
            for item in state.get("obligations", {}).values()
        )
        if migrated and not state.get("transactions") and not failed_once:
            failed_once = True
            raise migration.MigrationError("migration_state_persist_failed")
        real_save(state)

    monkeypatch.setattr(migration, "_save_state", fail_first_cleanup)
    with pytest.raises(migration.MigrationError) as cleanup_failure:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            authorize_privacy_request(
                Request(token),
                "migration.complete",
                pack_id=pack.profile.id,
            ),
        )
    assert cleanup_failure.value.code == "migration_state_persist_failed"
    assert transaction.original is None

    receipt = pack.migration.complete(
        discovered.obligation.id,
        discovered.value,
        transaction,
        authorize_privacy_request(
            Request(token),
            "migration.complete",
            pack_id=pack.profile.id,
        ),
    )
    assert receipt.disposition == "migrated"
    assert transaction.finalize_calls == 2


def test_prior_process_prepared_transaction_can_restore_journaled_original(
    migration_pack,
):
    pack, _reader, token, _tmp_path = migration_pack
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )

    class InterruptedTransaction(MigrationTransaction):
        def commit(self):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            InterruptedTransaction(),
            authorize_privacy_request(
                Request(token),
                "migration.complete",
                pack_id=pack.profile.id,
            ),
        )

    recovery = MigrationTransaction()
    obligation = pack.migration.recover_pending(
        discovered.obligation.id,
        recovery,
        authorize_privacy_request(
            Request(token),
            "migration.recover",
            pack_id=pack.profile.id,
        ),
    )
    assert obligation.disposition == "unresolved"
    assert recovery.rollback_values == [b"SYNTHETIC_ORIGINAL_BYTES"]


def test_reader_registry_rejects_writers_and_incomplete_dependencies():
    class WriterReader(Reader):
        def write(self):
            return None

    with pytest.raises(migration.MigrationError) as writer_error:
        migration.LegacyReaderUnit("unsafe-v1", "Unsafe", WriterReader())
    assert writer_error.value.code == "legacy_reader_has_writer_capability"

    unit = migration.LegacyReaderUnit(
        "dependent-v1",
        "Dependent",
        Reader(),
        dependencies=("missing-v1",),
    )
    with pytest.raises(migration.MigrationError) as dependency_error:
        migration.register_legacy_reader_units((unit,))
    assert dependency_error.value.code == "missing_legacy_reader_dependency"

    class DisguisedWriter(Reader):
        def update(self):
            return None

    with pytest.raises(migration.MigrationError) as allowlist_error:
        migration.LegacyReaderUnit("disguised-v1", "Disguised", DisguisedWriter())
    assert allowlist_error.value.code == "legacy_reader_has_writer_capability"


def test_only_one_completion_may_commit_an_obligation(migration_pack):
    pack, _reader, token, _tmp_path = migration_pack
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )
    commit_started = threading.Event()
    release_commit = threading.Event()

    class BlockingTransaction(MigrationTransaction):
        def commit(self):
            commit_started.set()
            assert release_commit.wait(timeout=2)
            super().commit()

    first = BlockingTransaction()
    first_result = []

    def complete_first():
        first_result.append(
            pack.migration.complete(
                discovered.obligation.id,
                discovered.value,
                first,
                authorize_privacy_request(
                    Request(token),
                    "migration.complete",
                    pack_id=pack.profile.id,
                ),
            )
        )

    worker = threading.Thread(target=complete_first)
    worker.start()
    assert commit_started.wait(timeout=2)
    second = MigrationTransaction()
    with pytest.raises(migration.MigrationError) as concurrent:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            second,
            authorize_privacy_request(
                Request(token),
                "migration.complete",
                pack_id=pack.profile.id,
            ),
        )
    assert concurrent.value.code == "migration_obligation_in_progress"
    release_commit.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert first_result[0].disposition == "migrated"
    assert first.current == discovered.value
    assert second.current is None


def test_receipt_persistence_failure_rolls_back_exact_original(
    migration_pack,
    monkeypatch,
):
    pack, _reader, token, _tmp_path = migration_pack
    discovered = pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )
    transaction = MigrationTransaction()
    original = transaction.original
    real_save = migration._save_state

    def fail_receipt(state):
        if any(
            isinstance(item, dict) and item.get("disposition") == "migrated"
            for item in state.get("obligations", {}).values()
        ):
            raise migration.MigrationError("migration_state_persist_failed")
        real_save(state)

    monkeypatch.setattr(migration, "_save_state", fail_receipt)
    with pytest.raises(migration.MigrationError) as failure:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            authorize_privacy_request(
                Request(token),
                "migration.complete",
                pack_id=pack.profile.id,
            ),
        )
    assert failure.value.code == "migration_state_persist_failed"
    assert transaction.original == original
    assert transaction.rollback_values == [original]
    assert pack.migration.obligation(discovered.obligation.id).disposition == "unresolved"


def test_user_declared_audit_scope_seals_only_after_every_item_is_checked(
    migration_pack,
):
    pack, _reader, token, _tmp_path = migration_pack
    items = (
        migration.AuditItem("workflow-a", migration.AuditItemKind.WORKFLOW),
        migration.AuditItem("workflow-b", migration.AuditItemKind.WORKFLOW),
    )
    pack.migration.declare_audit_scope(
        "manual-workflows",
        "state-v1",
        items,
        authorize_privacy_request(
            Request(token),
            "migration.audit.declare",
            pack_id=pack.profile.id,
        ),
    )
    audit_authorization = authorize_privacy_request(
        Request(token),
        "migration.audit.read",
        pack_id=pack.profile.id,
    )
    assert pack.migration.audit_source(
        "manual-workflows",
        "workflow-a",
        "state-v1-binding",
        "not-legacy",
        audit_authorization,
    ) is None

    with pytest.raises(migration.MigrationError) as incomplete:
        pack.migration.confirm_retirement_seal(
            "manual-workflows",
            "state-v1",
            authorize_privacy_request(
                Request(token),
                "migration.audit.seal",
                pack_id=pack.profile.id,
            ),
        )
    assert incomplete.value.code == "audit_scope_incomplete"

    assert pack.migration.audit_source(
        "manual-workflows",
        "workflow-b",
        "state-v1-binding",
        "not-legacy",
        audit_authorization,
    ) is None
    seal = pack.migration.confirm_retirement_seal(
        "manual-workflows",
        "state-v1",
        authorize_privacy_request(
            Request(token),
            "migration.audit.seal",
            pack_id=pack.profile.id,
        ),
    )
    assert seal.valid is True

    discovered = pack.migration.audit_source(
        "manual-workflows",
        "workflow-a",
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        audit_authorization,
    )
    assert discovered.obligation.disposition == "unresolved"
    assert pack.migration.retirement_seal(seal.id).valid is False
    with pytest.raises(migration.MigrationError) as unresolved:
        pack.migration.confirm_retirement_seal(
            "manual-workflows",
            "state-v1",
            authorize_privacy_request(
                Request(token),
                "migration.audit.seal",
                pack_id=pack.profile.id,
            ),
        )
    assert unresolved.value.code == "audit_scope_has_unresolved_migrations"


def test_reader_cannot_seal_while_an_obligation_exists_outside_the_scope(
    migration_pack,
):
    pack, _reader, token, _tmp_path = migration_pack
    pack.migration.declare_audit_scope(
        "manual-workflows",
        "state-v1",
        (migration.AuditItem("workflow-a", migration.AuditItemKind.WORKFLOW),),
        authorize_privacy_request(
            Request(token),
            "migration.audit.declare",
            pack_id=pack.profile.id,
        ),
    )
    pack.migration.audit_source(
        "manual-workflows",
        "workflow-a",
        "state-v1-binding",
        "not-legacy",
        authorize_privacy_request(
            Request(token),
            "migration.audit.read",
            pack_id=pack.profile.id,
        ),
    )
    pack.migration.discover_and_read(
        "state-v1-binding",
        "SYNTHETIC_LEGACY_VALUE",
        authorize_privacy_request(
            Request(token),
            "migration.read",
            pack_id=pack.profile.id,
        ),
    )

    with pytest.raises(migration.MigrationError) as unresolved:
        pack.migration.confirm_retirement_seal(
            "manual-workflows",
            "state-v1",
            authorize_privacy_request(
                Request(token),
                "migration.audit.seal",
                pack_id=pack.profile.id,
            ),
        )
    assert unresolved.value.code == "audit_scope_has_unresolved_migrations"


@pytest.mark.parametrize("source_format", tuple(migration.LegacyKeyFormat))
def test_key_import_is_verified_then_unlinks_source_without_plaintext_copy(
    migration_pack,
    source_format,
):
    pack, _reader, token, tmp_path = migration_pack
    key = bytes(range(32))
    key_id = base64.urlsafe_b64encode(hashlib.sha256(key).digest()[:12]).decode(
        "ascii"
    ).rstrip("=")
    source = tmp_path / f"legacy-key.{source_format.value}"
    if source_format is migration.LegacyKeyFormat.JSON:
        source.write_text(
            json.dumps(
                {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "keyId": key_id,
                    "key": base64.urlsafe_b64encode(key).decode("ascii").rstrip("="),
                }
            ),
            encoding="utf-8",
        )
    else:
        source.write_bytes(key)
    migration.register_legacy_reader_units(
        (
            migration.LegacyReaderUnit(
                f"keyed-{source_format.value}-v1",
                "Keyed reader",
                Reader(),
                key_import_ids=(f"legacy-{source_format.value}-key",),
            ),
        )
    )

    receipt = pack.migration.import_legacy_key_source(
        f"legacy-{source_format.value}-key",
        source,
        PASSWORD,
        source_format,
        authorize_privacy_request(
            Request(token),
            "migration.key-import",
            pack_id=pack.profile.id,
        ),
    )

    assert receipt.disposition == "verified-and-unlinked"
    assert not source.exists()
    assert not list(tmp_path.glob("*.migrated"))
    assert keystore.session_key_for(key_id) == key
    stored = (tmp_path / "migration" / "state.json").read_text(encoding="utf-8")
    assert base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") not in stored


def test_failed_key_import_leaves_plaintext_source_authoritative(
    migration_pack,
    monkeypatch,
):
    pack, _reader, token, tmp_path = migration_pack
    source = tmp_path / "legacy-key.bin"
    source.write_bytes(bytes(range(32)))
    migration.register_legacy_reader_units(
        (
            migration.LegacyReaderUnit(
                "keyed-binary-v1",
                "Keyed reader",
                Reader(),
                key_import_ids=("legacy-binary-key",),
            ),
        )
    )
    monkeypatch.setattr(
        keystore,
        "import_decrypt_only_key_verified",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            keystore.PrivacyKeystoreError("synthetic failure")
        ),
    )

    with pytest.raises(migration.MigrationError) as failure:
        pack.migration.import_legacy_key_source(
            "legacy-binary-key",
            source,
            PASSWORD,
            migration.LegacyKeyFormat.BINARY,
            authorize_privacy_request(
                Request(token),
                "migration.key-import",
                pack_id=pack.profile.id,
            ),
        )

    assert failure.value.code == "legacy_key_import_failed"
    assert source.read_bytes() == bytes(range(32))
    assert not list(tmp_path.glob("*.migrated"))


def test_key_source_mutation_after_wrap_is_not_unlinked(
    migration_pack,
    monkeypatch,
):
    pack, _reader, token, tmp_path = migration_pack
    source = tmp_path / "legacy-key.bin"
    source.write_bytes(bytes(range(32)))
    migration.register_legacy_reader_units(
        (
            migration.LegacyReaderUnit(
                "keyed-binary-v1",
                "Keyed reader",
                Reader(),
                key_import_ids=("legacy-binary-key",),
            ),
        )
    )
    real_import = keystore.import_decrypt_only_key_verified

    def import_then_mutate(*args, **kwargs):
        result = real_import(*args, **kwargs)
        source.write_bytes(bytes(reversed(range(32))))
        return result

    monkeypatch.setattr(
        keystore,
        "import_decrypt_only_key_verified",
        import_then_mutate,
    )

    with pytest.raises(migration.MigrationError) as changed:
        pack.migration.import_legacy_key_source(
            "legacy-binary-key",
            source,
            PASSWORD,
            migration.LegacyKeyFormat.BINARY,
            authorize_privacy_request(
                Request(token),
                "migration.key-import",
                pack_id=pack.profile.id,
            ),
        )
    assert changed.value.code == "legacy_key_source_changed"
    assert source.exists()


def test_unlink_pending_retry_repeats_parent_directory_sync(
    migration_pack,
    monkeypatch,
):
    pack, _reader, token, tmp_path = migration_pack
    source = tmp_path / "legacy-key.bin"
    source.write_bytes(bytes(range(32)))
    migration.register_legacy_reader_units(
        (
            migration.LegacyReaderUnit(
                "keyed-binary-v1",
                "Keyed reader",
                Reader(),
                key_import_ids=("legacy-binary-key",),
            ),
        )
    )
    real_sync = legacy_key_source.sync_parent_directory

    def fail_sync(_path):
        raise OSError("synthetic sync failure")

    monkeypatch.setattr(legacy_key_source, "sync_parent_directory", fail_sync)
    with pytest.raises(migration.MigrationError) as pending:
        pack.migration.import_legacy_key_source(
            "legacy-binary-key",
            source,
            PASSWORD,
            migration.LegacyKeyFormat.BINARY,
            authorize_privacy_request(
                Request(token),
                "migration.key-import",
                pack_id=pack.profile.id,
            ),
        )
    assert pending.value.code == "legacy_key_source_unlink_failed"
    assert not source.exists()

    monkeypatch.setattr(legacy_key_source, "sync_parent_directory", real_sync)
    receipt = pack.migration.import_legacy_key_source(
        "legacy-binary-key",
        source,
        PASSWORD,
        migration.LegacyKeyFormat.BINARY,
        authorize_privacy_request(
            Request(keystore.session_token()),
            "migration.key-import",
            pack_id=pack.profile.id,
        ),
    )
    assert receipt.disposition == "verified-and-unlinked"
