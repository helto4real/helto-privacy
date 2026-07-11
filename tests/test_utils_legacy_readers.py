from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.migration as migration
import helto_privacy.runtime as runtime
from helto_privacy import (
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
    ProtectedField,
    ProfileResource,
    ResourceKind,
    UTILS_KEY_BIN_IMPORT_ID,
    UTILS_PRIV1_READER_ID,
    UTILS_PRIV2_READER_ID,
    UTILS_PRIV3_READER_ID,
    UTILS_PRIVACY_KEY_BIN_IMPORT_ID,
    UTILS_QUEUE_JSON_READER_IDS,
    UTILS_QUEUE_SQLITE_READER_IDS,
    UTILS_RAW_XOR_READER_ID,
    UTILS_WORKFLOW_READER_IDS,
    install,
    register_legacy_reader_units,
    utils_legacy_reader_units,
    utils_raw_xor_source,
)
from helto_privacy.guard import authorize_privacy_request


FIXTURES = Path(__file__).parent / "fixtures" / "historical"


class ImportedTestKeys:
    def __init__(self, **keys: bytes) -> None:
        self._keys = keys

    def key_for(self, import_id: str) -> bytes:
        return self._keys[import_id]


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _derived_key(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _utils_fixture() -> dict:
    return _fixture("utils_legacy_formats.json")


def _context() -> ImportedTestKeys:
    return ImportedTestKeys(
        **{
            UTILS_KEY_BIN_IMPORT_ID: _derived_key(
                "helto-utils-key-bin-historical-fixture-key"
            ),
            UTILS_PRIVACY_KEY_BIN_IMPORT_ID: _derived_key(
                "helto-utils-privacy-key-bin-historical-fixture-key"
            ),
        }
    )


def test_utils_byte_generations_are_independent_read_only_units():
    units = {unit.id: unit for unit in utils_legacy_reader_units()}

    assert {
        UTILS_RAW_XOR_READER_ID,
        UTILS_PRIV1_READER_ID,
        UTILS_PRIV2_READER_ID,
        UTILS_PRIV3_READER_ID,
    }.issubset(units)
    for reader_id in (
        UTILS_RAW_XOR_READER_ID,
        UTILS_PRIV1_READER_ID,
        UTILS_PRIV2_READER_ID,
        UTILS_PRIV3_READER_ID,
    ):
        assert not hasattr(units[reader_id].reader, "write")


@pytest.mark.parametrize("generation", ("raw-xor", "priv1", "priv2", "priv3"))
def test_utils_byte_readers_decode_genuine_workflow_and_mask_ciphertext(generation):
    fixture = _utils_fixture()
    item = fixture["generations"][generation]
    units = {unit.id: unit for unit in utils_legacy_reader_units()}
    reader_ids = {
        "raw-xor": UTILS_RAW_XOR_READER_ID,
        "priv1": UTILS_PRIV1_READER_ID,
        "priv2": UTILS_PRIV2_READER_ID,
        "priv3": UTILS_PRIV3_READER_ID,
    }
    unit = units[reader_ids[generation]]
    workflow_source = _decode(item["bytes"]["base64"])
    mask_source = _decode(item["mask"]["base64"])
    if generation == "raw-xor":
        assert unit.reader.probe(workflow_source, _context()) is False
        workflow_source = utils_raw_xor_source(workflow_source, "workflow-field")
        mask_source = utils_raw_xor_source(mask_source, "selector-mask")

    assert unit.reader.probe(workflow_source, _context()) is True
    assert unit.reader.read(workflow_source, _context()) == fixture["expected"][
        "workflow"
    ].encode("utf-8")
    assert unit.reader.probe(mask_source, _context()) is True
    assert unit.reader.read(mask_source, _context()) == _decode(
        fixture["expected"]["maskBase64"]
    )


def test_workflow_containers_are_generation_exact_for_all_historical_locations():
    fixture = _utils_fixture()
    units = {unit.id: unit for unit in utils_legacy_reader_units()}
    locations = fixture["workflowLocations"]

    for location in locations:
        assert location
        for generation, reader_id in UTILS_WORKFLOW_READER_IDS.items():
            unit = units[reader_id]
            source = fixture["generations"][generation]["workflow"]
            assert unit.dependencies == (
                {
                    "raw-xor": UTILS_RAW_XOR_READER_ID,
                    "priv1": UTILS_PRIV1_READER_ID,
                    "priv2": UTILS_PRIV2_READER_ID,
                    "priv3": UTILS_PRIV3_READER_ID,
                }[generation],
            )
            assert unit.reader.probe(source, _context()) is True
            assert unit.reader.read(source, _context()) == fixture["expected"][
                "workflow"
            ]

            other = next(
                value["workflow"]
                for key, value in fixture["generations"].items()
                if key != generation
            )
            assert unit.reader.probe(other, _context()) is False


@pytest.mark.parametrize("generation", ("priv1", "priv2", "priv3"))
def test_queue_json_and_sqlite_containers_decode_exact_historical_forms(generation):
    fixture = _utils_fixture()
    item = fixture["generations"][generation]
    units = {unit.id: unit for unit in utils_legacy_reader_units()}
    json_unit = units[UTILS_QUEUE_JSON_READER_IDS[generation]]
    sqlite_unit = units[UTILS_QUEUE_SQLITE_READER_IDS[generation]]

    assert json_unit.dependencies == (f"utils-{generation}-v1",)
    assert sqlite_unit.dependencies == (f"utils-{generation}-v1",)
    assert json_unit.reader.probe(item["queueJson"]["value"], _context()) is True
    assert json_unit.reader.read(item["queueJson"]["value"], _context()) == fixture[
        "expected"
    ]["queue"]
    assert sqlite_unit.reader.probe(
        item["queueSqlite"]["value"], _context()
    ) is True
    assert sqlite_unit.reader.read(
        item["queueSqlite"]["value"], _context()
    ) == fixture["expected"]["queue"]


def test_utils_fixture_catalog_is_content_addressed_and_provenance_recorded():
    fixture = _utils_fixture()

    assert fixture["fixtureVersion"] == 1
    assert fixture["producerCommit"] == "d19f6845bf3c2f83a3ae3d6c48bce7e7897475a8"
    assert set(fixture["producerFunctions"]) == {
        "raw-xor",
        "priv1",
        "priv2",
        "priv3",
        "workflow",
        "queue-json",
        "queue-sqlite",
    }
    assert len(fixture["workflowLocations"]) == 7
    assert {item["id"] for item in fixture["derivedFailureCases"]} == {
        "priv1-tag-tamper",
        "priv2-tag-tamper",
        "priv3-truncation",
        "raw-xor-ungated",
    }
    for generation, item in fixture["generations"].items():
        for name in ("bytes", "mask"):
            value = _decode(item[name]["base64"])
            assert hashlib.sha256(value).hexdigest() == item[name]["sha256"]
        assert hashlib.sha256(item["workflow"].encode("utf-8")).hexdigest() == item[
            "workflowSha256"
        ]
        if generation != "raw-xor":
            for name in ("queueJson", "queueSqlite"):
                canonical = json.dumps(
                    item[name]["value"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                assert hashlib.sha256(canonical).hexdigest() == item[name]["sha256"]
    for field in fixture["generations"]["priv2"]["selectorMigration"].values():
        assert hashlib.sha256(field["workflow"].encode("utf-8")).hexdigest() == field[
            "workflowSha256"
        ]


def test_authenticated_generations_and_containers_fail_closed_on_derived_mutations():
    fixture = _utils_fixture()
    units = {unit.id: unit for unit in utils_legacy_reader_units()}
    reader_ids = {
        "priv1": UTILS_PRIV1_READER_ID,
        "priv2": UTILS_PRIV2_READER_ID,
        "priv3": UTILS_PRIV3_READER_ID,
    }

    for generation, reader_id in reader_ids.items():
        source = bytearray(_decode(fixture["generations"][generation]["bytes"]["base64"]))
        source[-1] ^= 1
        unit = units[reader_id]
        if generation == "priv3":
            assert unit.reader.probe(bytes(source[:-1]), _context()) is False
        with pytest.raises(Exception):
            unit.reader.read(bytes(source), _context())

    raw = _decode(fixture["generations"]["raw-xor"]["bytes"]["base64"])
    with pytest.raises(ValueError):
        utils_raw_xor_source(raw, "arbitrary-bytes")
    malformed = fixture["generations"]["priv2"]["workflow"].replace(
        "__HELTO_ENC__:",
        "__UNKNOWN__:",
        1,
    )
    assert units[UTILS_WORKFLOW_READER_IDS["priv2"]].reader.probe(
        malformed,
        _context(),
    ) is False


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


class StateAdapter:
    def capture(self, *_args):
        return None

    def normalize(self, value, *_args):
        return value

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


def _profile() -> PrivacyProfile:
    reader_id = UTILS_WORKFLOW_READER_IDS["priv2"]
    raw_reader_id = UTILS_WORKFLOW_READER_IDS["raw-xor"]
    return PrivacyProfile(
        id="helto.utils-legacy-test",
        distribution="comfyui-utils-legacy-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("workflow", ResourceKind.WORKFLOW, ("state", "state-ui")),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state", ResourceKind.WORKFLOW, "workflow"),
        ),
        browser_adapters=(
            AdapterSlot(
                "state-ui",
                ResourceKind.WORKFLOW,
                "workflow",
                ("HeltoImageSelectorSynthetic",),
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        protected_fields=(
            ProtectedField(
                "selected-images",
                "workflow",
                "main",
                "state",
                "state-ui",
                ("HeltoImageSelectorSynthetic",),
                FieldLocation(FieldLocationKind.WIDGET, "selected_images"),
                "helto.comfyui-utils.selector",
                "selected-images",
                legacy_reader_ids=(raw_reader_id, reader_id),
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "selected-images-priv2",
                reader_id,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "selected-images",
            ),
            LegacyReaderBinding(
                "selected-images-raw-xor",
                raw_reader_id,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "selected-images",
            ),
        ),
        legacy_key_imports=(
            LegacyKeyImportBinding(
                "utils-privacy-key",
                UTILS_PRIVACY_KEY_BIN_IMPORT_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "selected-images",
                LegacyKeyFormat.BINARY,
            ),
            LegacyKeyImportBinding(
                "utils-legacy-key",
                UTILS_KEY_BIN_IMPORT_ID,
                "workflow",
                LegacyLocationKind.WORKFLOW_FIELD,
                "selected-images",
                LegacyKeyFormat.BINARY,
            ),
        ),
    )


@pytest.fixture
def utils_pack(tmp_path, monkeypatch):
    monkeypatch.setenv(
        migration.MIGRATION_STATE_ENV,
        str(tmp_path / "migration" / "state.json"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    migration.reset_migration_runtime_for_tests()
    register_legacy_reader_units(utils_legacy_reader_units())
    pack = install(_profile(), {"mode": ModeAdapter(), "state": StateAdapter()})
    password = "synthetic utils migration password"
    token = keystore.initialize_keystore(password)["token"]
    for import_id, filename, key_label in (
        (
            UTILS_PRIVACY_KEY_BIN_IMPORT_ID,
            "privacy_key.bin",
            "helto-utils-privacy-key-bin-historical-fixture-key",
        ),
        (
            UTILS_KEY_BIN_IMPORT_ID,
            "key.bin",
            "helto-utils-key-bin-historical-fixture-key",
        ),
    ):
        key_source = tmp_path / filename
        key_source.write_bytes(_derived_key(key_label))
        pack.migration.import_legacy_key_source(
            import_id,
            key_source,
            password,
            LegacyKeyFormat.BINARY,
            authorize_privacy_request(
                Request(token),
                "migration.key-import",
                pack_id=pack.profile.id,
            ),
        )
        assert not key_source.exists()
        token = keystore.session_token()
    return pack, keystore.session_token()


class SelectorRewriteTransaction:
    def __init__(self, original: dict, *, artifacts_current: bool = True) -> None:
        self.original = original
        self.artifacts_current = artifacts_current
        self.staged = None
        self.current = original
        self.rollback_values = []

    def capture_original(self):
        return self.original

    def stage_current(self, normalized):
        state_codec = PrivacyEnvelopeCodec("helto.comfyui-utils.selector")
        mask_codec = PrivacyEnvelopeCodec("helto.comfyui-utils.selector-mask")
        fields = _utils_fixture()["generations"]["priv2"]["selectorMigration"]
        if normalized != fields["selected_images"]["expected"]:
            raise ValueError("selector primary field changed")
        self.staged = {
            "workflowFields": {
                name: state_codec.encrypt_state({"data": fields[name]["expected"]})
                for name in fields
            },
            "mask": mask_codec.encrypt_bytes(
                _decode(_utils_fixture()["expected"]["maskBase64"]),
                "selector-mask",
            ),
        }

    def stage_durable_adjuncts(self, _normalized):
        return None

    def commit(self):
        self.current = self.staged

    def read_back(self):
        state_codec = PrivacyEnvelopeCodec("helto.comfyui-utils.selector")
        mask_codec = PrivacyEnvelopeCodec("helto.comfyui-utils.selector-mask")
        decoded_fields = {
            name: state_codec.decrypt_state(value)["data"]
            for name, value in self.current["workflowFields"].items()
        }
        expected_fields = {
            name: item["expected"]
            for name, item in _utils_fixture()["generations"]["priv2"][
                "selectorMigration"
            ].items()
        }
        mask_matches = mask_codec.decrypt_bytes(
            self.current["mask"],
            "selector-mask",
        ) == _decode(_utils_fixture()["expected"]["maskBase64"])
        return MigrationVerification(
            normalized=decoded_fields["selected_images"],
            current_format=decoded_fields == expected_fields,
            durable_artifacts_current=self.artifacts_current and mask_matches,
        )

    def rollback(self, original):
        self.rollback_values.append(original)
        self.current = original
        self.original = original

    def finalize(self, original):
        if self.original != original:
            raise ValueError("selector source changed")
        self.original = None


def _selector_original() -> dict:
    fixture = _utils_fixture()["generations"]["priv2"]
    return {
        "workflowFields": {
            name: item["workflow"]
            for name, item in fixture["selectorMigration"].items()
        },
        "mask": fixture["mask"]["base64"],
    }


def _authorization(pack, token: str, operation: str):
    return authorize_privacy_request(
        Request(token),
        operation,
        pack_id=pack.profile.id,
    )


def test_selector_migration_rewrites_workflow_and_mask_as_one_verified_transaction(
    utils_pack,
):
    pack, token = utils_pack
    fixture = _utils_fixture()
    source = fixture["generations"]["priv2"]["selectorMigration"][
        "selected_images"
    ]["workflow"]
    discovered = pack.migration.discover_and_read(
        "selected-images-priv2",
        source,
        _authorization(pack, token, "migration.read"),
    )
    transaction = SelectorRewriteTransaction(_selector_original())

    receipt = pack.migration.complete(
        discovered.obligation.id,
        discovered.value,
        transaction,
        _authorization(pack, token, "migration.complete"),
    )

    assert receipt.disposition == "migrated"
    assert transaction.original is None
    assert transaction.rollback_values == []
    assert all(
        value["schema"] == "helto.comfyui-utils.selector"
        for value in transaction.current["workflowFields"].values()
    )
    assert transaction.current["mask"]["schema"] == (
        "helto.comfyui-utils.selector-mask.bytes"
    )


def test_selector_migration_failure_restores_every_original_authoritative_byte(
    utils_pack,
):
    pack, token = utils_pack
    source = _utils_fixture()["generations"]["priv2"]["selectorMigration"][
        "selected_images"
    ]["workflow"]
    discovered = pack.migration.discover_and_read(
        "selected-images-priv2",
        source,
        _authorization(pack, token, "migration.read"),
    )
    original = _selector_original()
    transaction = SelectorRewriteTransaction(original, artifacts_current=False)

    with pytest.raises(migration.MigrationError) as failure:
        pack.migration.complete(
            discovered.obligation.id,
            discovered.value,
            transaction,
            _authorization(pack, token, "migration.complete"),
        )

    assert failure.value.code == "migration_verification_failed"
    assert transaction.rollback_values == [original]
    assert transaction.current == original
    assert transaction.original == original
    assert pack.migration.obligation(
        discovered.obligation.id
    ).disposition == "unresolved"
