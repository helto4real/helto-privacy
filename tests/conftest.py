import pytest

import helto_privacy.envelope as envelope
import helto_privacy.keystore as keystore


@pytest.fixture(autouse=True)
def isolated_privacy_paths(tmp_path, monkeypatch):
    monkeypatch.setenv(keystore.KEYSTORE_ENV, str(tmp_path / "keystore" / "privacy_keystore.json"))
    monkeypatch.setenv(keystore.SESSION_DIR_ENV, str(tmp_path / "session"))
    monkeypatch.setattr(keystore, "SCRYPT_N", 2**12)
    monkeypatch.setattr(envelope, "config_dir", lambda: tmp_path / "legacy_config")
