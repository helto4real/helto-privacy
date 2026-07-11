import json
import sys
import types

import pytest

import helto_privacy.comfy_ui as comfy_ui
import helto_privacy.keystore as keystore
from helto_privacy.comfy_ui import (
    _collect_legacy_keys,
    _initialize_and_migrate,
    _unlock_and_migrate,
    register_helto_privacy_ui,
    register_legacy_key_dir,
)
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.keystore import KEYSTORE_CRYPTO_AVAILABLE

pytestmark = pytest.mark.skipif(
    not KEYSTORE_CRYPTO_AVAILABLE,
    reason="cryptography package is required for privacy keystore tests",
)

PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def reset_ui_registry(monkeypatch):
    monkeypatch.setattr(comfy_ui, "_ROUTES_REGISTERED", False)
    monkeypatch.setattr(comfy_ui, "_LEGACY_KEY_DIRS", [])


class _FakeRoutes:
    """Records the paths registered through the aiohttp decorator interface."""

    def __init__(self):
        self.paths = []

    def get(self, path):
        return self._decorator("GET", path)

    def post(self, path):
        return self._decorator("POST", path)

    def _decorator(self, method, path):
        self.paths.append((method, path))
        return lambda handler: handler


class _FakePromptServer:
    def __init__(self):
        self.routes = _FakeRoutes()


def _legacy_key_file(directory, codec_schema="helto.test-pack"):
    codec = PrivacyEnvelopeCodec(codec_schema)
    envelope = codec.encrypt_state({"secret": "legacy"}, base_dir=directory)
    return envelope


def test_register_is_idempotent_and_collects_legacy_dirs(tmp_path, monkeypatch):
    aiohttp = types.ModuleType("aiohttp")
    aiohttp.web = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, "aiohttp", aiohttp)
    server = _FakePromptServer()
    assert register_helto_privacy_ui(tmp_path / "pack_a", prompt_server=server) is True
    first_count = len(server.routes.paths)
    assert first_count >= 6
    assert ("GET", comfy_ui.UI_MODULE_ROUTE) in server.routes.paths
    assert ("GET", comfy_ui.CLIENT_MODULE_ROUTE) in server.routes.paths
    assert ("GET", comfy_ui.SNAPSHOT_MODULE_ROUTE) in server.routes.paths
    assert ("GET", comfy_ui.PROFILE_MODULE_ROUTE) in server.routes.paths
    assert ("GET", f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}") in server.routes.paths

    # A second pack registering only contributes its legacy dir.
    assert register_helto_privacy_ui(tmp_path / "pack_b", prompt_server=server) is True
    assert len(server.routes.paths) == first_count
    assert [d.name for d in comfy_ui._LEGACY_KEY_DIRS] == ["pack_a", "pack_b"]


def test_initialize_migrates_all_registered_legacy_keys(tmp_path):
    pack_a = tmp_path / "pack_a"
    pack_b = tmp_path / "pack_b"
    envelope_a = _legacy_key_file(pack_a, "helto.pack-a")
    envelope_b = _legacy_key_file(pack_b, "helto.pack-b")
    register_legacy_key_dir(pack_a)
    register_legacy_key_dir(pack_b)

    result = _initialize_and_migrate(PASSWORD)

    assert result["token"]
    assert not (pack_a / "privacy_key.json").exists()
    assert (pack_a / "privacy_key.json.migrated").exists()
    assert not (pack_b / "privacy_key.json").exists()
    # Both packs' old envelopes decrypt through the keystore session.
    assert PrivacyEnvelopeCodec("helto.pack-a").decrypt_state(envelope_a) == {"secret": "legacy"}
    assert PrivacyEnvelopeCodec("helto.pack-b").decrypt_state(envelope_b) == {"secret": "legacy"}


def test_unlock_sweeps_legacy_keys_registered_after_init(tmp_path):
    keystore.initialize_keystore(PASSWORD)
    keystore.lock_keystore()

    # A pack adopted after the keystore already exists.
    late_pack = tmp_path / "late_pack"
    envelope = _legacy_key_file(late_pack, "helto.late-pack")
    register_legacy_key_dir(late_pack)

    result = _unlock_and_migrate(PASSWORD)

    assert result["token"]
    assert not (late_pack / "privacy_key.json").exists()
    assert (late_pack / "privacy_key.json.migrated").exists()
    assert PrivacyEnvelopeCodec("helto.late-pack").decrypt_state(envelope) == {"secret": "legacy"}


def test_unlock_without_legacy_keys_is_plain_unlock():
    keystore.initialize_keystore(PASSWORD)
    keystore.lock_keystore()

    result = _unlock_and_migrate(PASSWORD)

    assert result["keystoreLocked"] is False
    assert keystore.session_token() == result["token"]


def test_collect_legacy_keys_skips_malformed_and_duplicate_files(tmp_path):
    good = tmp_path / "good"
    _legacy_key_file(good)
    duplicate = tmp_path / "duplicate"
    duplicate.mkdir(parents=True)
    (duplicate / "privacy_key.json").write_text(
        (good / "privacy_key.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    broken = tmp_path / "broken"
    broken.mkdir(parents=True)
    (broken / "privacy_key.json").write_text("{not json", encoding="utf-8")
    for directory in (good, duplicate, broken):
        register_legacy_key_dir(directory)

    collected = _collect_legacy_keys()

    assert len(collected) == 1
    assert collected[0][2] == good / "privacy_key.json"


def test_ui_module_ships_in_package():
    source = (comfy_ui._WEB_DIR / "privacy_ui.js").read_text(encoding="utf-8")
    assert "export async function showPrivacyKeystoreDialog" in source
    assert "/helto_privacy" in source
    assert "privacy_client.js" in source

    client_source = (comfy_ui._WEB_DIR / "privacy_client.js").read_text(
        encoding="utf-8"
    )
    assert "helto_privacy_token" in client_source
    assert "X-Helto-Privacy-Token" in client_source

    records_source = (comfy_ui._WEB_DIR / "privacy_records.js").read_text(
        encoding="utf-8"
    )
    assert "isOpaquePrivateRecordId" in records_source
    assert "redactPrivateRecordShell" in records_source

    profile_source = (comfy_ui._WEB_DIR / "privacy_profile.js").read_text(encoding="utf-8")
    assert "export async function connectPrivacyPack" in profile_source
    assert 'export const PRIVACY_CONTRACT_V2 = "helto.privacy.v2"' in profile_source

    snapshot_source = (comfy_ui._WEB_DIR / "privacy_snapshot.js").read_text(
        encoding="utf-8"
    )
    assert "createPrivacySnapshotCoordinator" in snapshot_source


def test_register_survives_missing_prompt_server():
    assert register_helto_privacy_ui(prompt_server=None) is False
    assert comfy_ui._ROUTES_REGISTERED is False
