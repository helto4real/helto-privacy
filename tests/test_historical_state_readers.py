from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture, ProductStateProtocolFixture

import helto_privacy.keystore as keystore
import helto_privacy.migration as migration
import helto_privacy.runtime as runtime
from helto_privacy import (
    AIO_V1_JSON_KEY_IMPORT_ID,
    AIO_V1_READER_ID,
    DIRECTOR_V1_JSON_KEY_IMPORT_ID,
    SMART_PROMPT_V1_EXPORT_READER_ID,
    SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,
    SMART_PROMPT_V1_READER_ID,
    AdapterSlot,
    FieldLocation,
    FieldLocationKind,
    LegacyKeyFormat,
    LegacyKeyImportBinding,
    LegacyLocationKind,
    LegacyReaderBinding,
    MigrationVerification,
    PrivacyEnvelopeCodec,
    PrivacyProfile,
    PrivacyScope,
    ProtectedStateAuthority,
    ProtectedField,
    ProtectedOperation,
    ProfileResource,
    RecordDeclaration,
    RecordSnapshot,
    ResourceKind,
    aio_v1_reader_unit,
    install,
    register_legacy_reader_units,
    smart_prompt_v1_export_reader_unit,
    smart_prompt_v1_reader_unit,
)
from helto_privacy.guard import authorize_privacy_request


FIXTURES = Path(__file__).parent / "fixtures" / "historical"


class ImportedTestKeys:
    def __init__(self, **keys: bytes) -> None:
        self._keys = keys

    def key_for(self, import_id: str) -> bytes:
        return self._keys[import_id]


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeAdapter(ModeSourceProtocolFixture):
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


class StateAdapter(ProductStateProtocolFixture):
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


class OperationAdapter:
    def invoke(self, *_args):
        return None


class RecordAdapter:
    def list_ids(self, *_args):
        return ()

    def read_record(self, *_args):
        return RecordSnapshot(0)

    def compare_and_swap_record(self, *_args):
        return False

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class RewriteTransaction:
    def __init__(self, original: object, schema: str, *, valid_adjuncts=True) -> None:
        self.original = original
        self.schema = schema
        self.valid_adjuncts = valid_adjuncts
        self.staged = None
        self.current = None
        self.rollback_values = []

    def capture_original(self):
        return self.original

    def stage_current(self, normalized):
        self.staged = PrivacyEnvelopeCodec(self.schema).encrypt_state(normalized)

    def stage_durable_adjuncts(self, _normalized):
        return None

    def commit(self):
        self.current = self.staged

    def read_back(self):
        codec = PrivacyEnvelopeCodec(self.schema)
        return MigrationVerification(
            normalized=codec.decrypt_state(self.current),
            current_format=codec.is_encrypted_payload(self.current),
            durable_artifacts_current=self.valid_adjuncts,
        )

    def rollback(self, original):
        self.rollback_values.append(original)
        self.original = original
        self.current = None

    def finalize(self, original):
        if self.original not in (None, original):
            raise ValueError("source identity changed")
        self.original = None


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _derived_key(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _profile() -> PrivacyProfile:
    fields = (
        ProtectedField(
            "aio-state",
            "workflow",
            "main",
            "state",
            "state-ui",
            ("AioSynthetic",),
            FieldLocation(FieldLocationKind.WIDGET, "aio_state"),
            "helto.aio-image-generate.v2",
            "aio-state",
            ProtectedStateAuthority.SERVER_DURABLE,
            legacy_reader_ids=(AIO_V1_READER_ID,),
        ),
        ProtectedField(
            "smart-state",
            "workflow",
            "main",
            "state",
            "state-ui",
            ("SmartSynthetic",),
            FieldLocation(FieldLocationKind.WIDGET, "spm_data"),
            "helto.smart-prompt-manager",
            "smart-state",
            ProtectedStateAuthority.SERVER_DURABLE,
            legacy_reader_ids=(SMART_PROMPT_V1_READER_ID,),
        ),
        ProtectedField(
            "aio-builder-state",
            "workflow",
            "main",
            "state",
            "state-ui",
            ("AioBuilderSynthetic",),
            FieldLocation(FieldLocationKind.PROPERTY, "aio_builder_state"),
            "helto.aio-image-generate.v2",
            "aio-builder-state",
            ProtectedStateAuthority.SERVER_DURABLE,
            legacy_reader_ids=(AIO_V1_READER_ID,),
        ),
        ProtectedField(
            "director-state",
            "workflow",
            "main",
            "state",
            "state-ui",
            ("DirectorSynthetic",),
            FieldLocation(FieldLocationKind.WIDGET, "timeline"),
            "helto.timeline-director",
            "director-state",
            ProtectedStateAuthority.SERVER_DURABLE,
        ),
    )
    return PrivacyProfile(
        id="helto.historical-state-test",
        distribution="comfyui-historical-state-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource(
                "workflow",
                ResourceKind.WORKFLOW,
                ("state", "operation", "state-ui"),
            ),
            ProfileResource("records", ResourceKind.RECORD, ("records",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state", ResourceKind.WORKFLOW, "workflow"),
            AdapterSlot("operation", ResourceKind.WORKFLOW, "workflow"),
            AdapterSlot("records", ResourceKind.RECORD, "records"),
        ),
        browser_adapters=(
            AdapterSlot(
                "state-ui",
                ResourceKind.WORKFLOW,
                "workflow",
                (
                    "AioSynthetic",
                    "AioBuilderSynthetic",
                    "SmartSynthetic",
                    "DirectorSynthetic",
                ),
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        protected_fields=fields,
        records=(
            RecordDeclaration(
                "aio-private-record",
                "records",
                "main",
                "helto.aio-image-generate.v2",
                "records",
            ),
        ),
        protected_operations=(
            ProtectedOperation(
                "smart-export-import",
                "workflow",
                "operation",
                "/smart-export-import",
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "aio-workflow-v1",
                AIO_V1_READER_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "aio-state",
            ),
            LegacyReaderBinding(
                "aio-record-v1",
                AIO_V1_READER_ID,
                "records",
                LegacyLocationKind.RECORD,
                "aio-private-record",
            ),
            LegacyReaderBinding(
                "aio-builder-v1",
                AIO_V1_READER_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "aio-builder-state",
            ),
            LegacyReaderBinding(
                "smart-workflow-v1",
                SMART_PROMPT_V1_READER_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "smart-state",
            ),
            LegacyReaderBinding(
                "smart-bare-export-v1",
                SMART_PROMPT_V1_READER_ID,
                "workflow",
                LegacyLocationKind.EXPORT,
                "smart-export-import",
            ),
            LegacyReaderBinding(
                "smart-export-v1",
                SMART_PROMPT_V1_EXPORT_READER_ID,
                "workflow",
                LegacyLocationKind.EXPORT,
                "smart-export-import",
            ),
        ),
        legacy_key_imports=(
            LegacyKeyImportBinding(
                "aio-workflow-key-v1",
                AIO_V1_JSON_KEY_IMPORT_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "aio-state",
                LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "aio-record-key-v1",
                AIO_V1_JSON_KEY_IMPORT_ID,
                "records",
                LegacyLocationKind.RECORD,
                "aio-private-record",
                LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "aio-builder-key-v1",
                AIO_V1_JSON_KEY_IMPORT_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "aio-builder-state",
                LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "smart-workflow-key-v1",
                SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "smart-state",
                LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "smart-bare-export-key-v1",
                SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,
                "workflow",
                LegacyLocationKind.EXPORT,
                "smart-export-import",
                LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "smart-export-key-v1",
                SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,
                "workflow",
                LegacyLocationKind.EXPORT,
                "smart-export-import",
                LegacyKeyFormat.JSON,
            ),
            LegacyKeyImportBinding(
                "director-key-v1",
                DIRECTOR_V1_JSON_KEY_IMPORT_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "director-state",
                LegacyKeyFormat.JSON,
            ),
        ),
    )


def _write_key_source(path: Path, key: bytes) -> None:
    import base64

    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "algorithm": "AES-256-GCM",
                "keyId": encode(hashlib.sha256(key).digest()[:12]),
                "key": encode(key),
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def historical_pack(tmp_path, monkeypatch):
    monkeypatch.setenv(
        migration.MIGRATION_STATE_ENV,
        str(tmp_path / "migration" / "state.json"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    migration.reset_migration_runtime_for_tests()
    register_legacy_reader_units(
        (
            aio_v1_reader_unit(),
            smart_prompt_v1_reader_unit(),
            smart_prompt_v1_export_reader_unit(),
        )
    )
    pack = install(
        _profile(),
        {
            "mode": ModeAdapter(),
            "state": StateAdapter(),
            "operation": OperationAdapter(),
            "records": RecordAdapter(),
        },
    )
    token = keystore.initialize_keystore("synthetic historical password")["token"]
    for import_id, label in (
        (AIO_V1_JSON_KEY_IMPORT_ID, "helto-aio-v1-historical-fixture-key"),
        (
            SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,
            "helto-smart-prompt-v1-historical-fixture-key",
        ),
        (
            DIRECTOR_V1_JSON_KEY_IMPORT_ID,
            "helto-director-v1-historical-fixture-key",
        ),
    ):
        source = tmp_path / f"{import_id}.json"
        _write_key_source(source, _derived_key(label))
        pack.migration.import_legacy_key_source(
            import_id,
            source,
            "synthetic historical password",
            LegacyKeyFormat.JSON,
            authorize_privacy_request(
                Request(token),
                "migration.key-import",
                pack_id=pack.profile.id,
            ),
        )
        assert not source.exists()
        token = keystore.session_token()
    return pack, token


def _authorization(pack, token: str, operation_id: str):
    return authorize_privacy_request(
        Request(token),
        operation_id,
        pack_id=pack.profile.id,
    )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def test_aio_v1_reader_decodes_genuine_historical_writer_fixture():
    fixture = _fixture("aio_v1_state.json")
    unit = aio_v1_reader_unit()
    context = ImportedTestKeys(
        **{
            AIO_V1_JSON_KEY_IMPORT_ID: _derived_key(
                "helto-aio-v1-historical-fixture-key"
            )
        }
    )

    assert unit.id == AIO_V1_READER_ID
    assert unit.key_import_ids == (AIO_V1_JSON_KEY_IMPORT_ID,)
    assert unit.reader.probe(fixture["envelope"], context) is True
    assert unit.reader.read(fixture["envelope"], context) == fixture[
        "expectedNormalized"
    ]
    assert not hasattr(unit.reader, "write")

    current = {**fixture["envelope"], "schema": "helto.aio-image-generate.v2"}
    assert unit.reader.probe(current, context) is False


def test_smart_prompt_state_and_export_are_independent_reader_units():
    state_fixture = _fixture("smart_prompt_v1_state.json")
    export_fixture = _fixture("smart_prompt_v1_export.json")
    state_unit = smart_prompt_v1_reader_unit()
    export_unit = smart_prompt_v1_export_reader_unit()
    context = ImportedTestKeys(
        **{
            SMART_PROMPT_V1_JSON_KEY_IMPORT_ID: _derived_key(
                "helto-smart-prompt-v1-historical-fixture-key"
            )
        }
    )

    assert state_unit.id == SMART_PROMPT_V1_READER_ID
    assert export_unit.id == SMART_PROMPT_V1_EXPORT_READER_ID
    assert export_unit.dependencies == (SMART_PROMPT_V1_READER_ID,)
    assert state_unit.reader.probe(state_fixture["envelope"], context) is True
    assert state_unit.reader.read(state_fixture["envelope"], context) == state_fixture[
        "expectedNormalized"
    ]
    assert export_unit.reader.probe(export_fixture["package"], context) is True
    assert export_unit.reader.read(export_fixture["package"], context) == state_fixture[
        "expectedNormalized"
    ]
    assert state_unit.reader.probe(export_fixture["package"], context) is False


def test_malformed_or_tampered_historical_envelopes_fail_closed():
    fixture = _fixture("aio_v1_state.json")
    unit = aio_v1_reader_unit()
    context = ImportedTestKeys(
        **{
            AIO_V1_JSON_KEY_IMPORT_ID: _derived_key(
                "helto-aio-v1-historical-fixture-key"
            )
        }
    )
    malformed = {**fixture["envelope"], "unexpected": True}
    malformed_key_id = {**fixture["envelope"], "keyId": "not-base64!"}
    tampered = dict(fixture["envelope"])
    tampered["ciphertext"] = "A" + tampered["ciphertext"][1:]

    assert unit.reader.probe(malformed, context) is False
    assert unit.reader.probe(malformed_key_id, context) is False
    with pytest.raises(Exception):
        unit.reader.read(tampered, context)


def test_director_continuity_declares_key_import_without_redundant_reader():
    assert DIRECTOR_V1_JSON_KEY_IMPORT_ID == "director-json-key-v1"
    assert DIRECTOR_V1_JSON_KEY_IMPORT_ID not in {
        AIO_V1_READER_ID,
        SMART_PROMPT_V1_READER_ID,
        SMART_PROMPT_V1_EXPORT_READER_ID,
    }


@pytest.mark.parametrize(
    ("fixture_name", "payload_name", "digest_name"),
    (
        ("aio_v1_state.json", "envelope", "envelopeSha256"),
        ("aio_v1_builder_state.json", "envelope", "envelopeSha256"),
        ("director_v1_state.json", "envelope", "envelopeSha256"),
        ("smart_prompt_v1_state.json", "envelope", "envelopeSha256"),
        ("smart_prompt_v1_export.json", "package", "packageSha256"),
    ),
)
def test_historical_fixture_provenance_is_complete_and_content_addressed(
    fixture_name,
    payload_name,
    digest_name,
):
    fixture = _fixture(fixture_name)

    assert fixture["fixtureVersion"] == 1
    assert fixture["producerCommit"]
    assert fixture["producerFunction"]
    assert fixture[digest_name] == _canonical_sha256(fixture[payload_name])


def test_profile_bound_reads_cover_workflow_record_export_and_director_key_continuity(
    historical_pack,
):
    pack, token = historical_pack
    read_authorization = _authorization(pack, token, "migration.read")
    cases = (
        (
            "aio-workflow-v1",
            _fixture("aio_v1_state.json"),
            "envelope",
            "expectedNormalized",
            "helto.aio-image-generate.v2",
        ),
        (
            "aio-builder-v1",
            _fixture("aio_v1_builder_state.json"),
            "envelope",
            "expectedNormalized",
            "helto.aio-image-generate.v2",
        ),
        (
            "smart-workflow-v1",
            _fixture("smart_prompt_v1_state.json"),
            "envelope",
            "expectedNormalized",
            "helto.smart-prompt-manager",
        ),
        (
            "smart-bare-export-v1",
            _fixture("smart_prompt_v1_state.json"),
            "envelope",
            "expectedNormalized",
            "helto.smart-prompt-manager",
        ),
        (
            "smart-export-v1",
            _fixture("smart_prompt_v1_export.json"),
            "package",
            None,
            "helto.smart-prompt-manager",
        ),
    )

    for binding_id, fixture, source_name, expected_name, current_schema in cases:
        expected = (
            fixture[expected_name]
            if expected_name is not None
            else _fixture("smart_prompt_v1_state.json")["expectedNormalized"]
        )
        discovered = pack.migration.discover_and_read(
            binding_id,
            fixture[source_name],
            read_authorization,
        )
        assert discovered is not None
        assert discovered.value == expected

        transaction = RewriteTransaction(fixture[source_name], current_schema)
        receipt = pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            _authorization(pack, token, "migration.complete"),
        )

        assert receipt.disposition == "migrated"
        assert transaction.current["schema"] == current_schema
        assert PrivacyEnvelopeCodec(current_schema).decrypt_state(
            transaction.current
        ) == expected
        assert transaction.original is None
        assert transaction.rollback_values == []

    director = _fixture("director_v1_state.json")
    assert PrivacyEnvelopeCodec("helto.timeline-director").decrypt_state(
        director["envelope"]
    ) == director["expectedNormalized"]
    assert all(
        binding.location_id != "director-state"
        for binding in pack.profile.legacy_bindings
    )
    assert any(
        binding.id == "aio-record-v1"
        and binding.location_kind is LegacyLocationKind.RECORD
        for binding in pack.profile.legacy_bindings
    )


def test_failed_historical_rewrite_restores_exact_source_and_leaves_obligation_open(
    historical_pack,
):
    pack, token = historical_pack
    fixture = _fixture("smart_prompt_v1_state.json")
    original = fixture["envelope"]
    discovered = pack.migration.discover_and_read(
        "smart-workflow-v1",
        original,
        _authorization(pack, token, "migration.read"),
    )
    transaction = RewriteTransaction(
        original,
        "helto.smart-prompt-manager",
        valid_adjuncts=False,
    )

    with pytest.raises(migration.MigrationError) as failure:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            _authorization(pack, token, "migration.complete"),
        )

    assert failure.value.code == "migration_verification_failed"
    assert transaction.rollback_values == [original]
    assert transaction.original == original
    assert transaction.current is None
    assert pack.migration.obligation(
        discovered.obligation.id
    ).disposition == "unresolved"
