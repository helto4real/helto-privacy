import pytest

import helto_privacy.comfy_ui as comfy_ui
import helto_privacy.envelope as envelope
import helto_privacy.keystore as keystore
import helto_privacy.suite_runtime as suite_runtime


@pytest.fixture(autouse=True)
def isolated_privacy_paths(tmp_path, monkeypatch):
    active_operation_gate = envelope._require_active_privacy_operation
    active_route_gate = comfy_ui._require_active_suite
    monkeypatch.setenv(
        keystore.KEYSTORE_ENV,
        str(tmp_path / "keystore" / "privacy_keystore.json"),
    )
    monkeypatch.setenv(keystore.SESSION_DIR_ENV, str(tmp_path / "session"))
    monkeypatch.setattr(keystore, "SCRYPT_N", 2**12)
    monkeypatch.setattr(envelope, "config_dir", lambda: tmp_path / "legacy_config")
    monkeypatch.setattr(
        envelope,
        "_require_active_privacy_operation",
        lambda: None,
    )
    monkeypatch.setattr(comfy_ui, "_require_active_suite", lambda: None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_INSTALLATION", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_CONFLICT", False)
    monkeypatch.setattr(suite_runtime, "_PROCESS_CONSUMER_DECLARATIONS", [])
    return active_operation_gate, active_route_gate
