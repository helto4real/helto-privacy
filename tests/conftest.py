import pytest

import helto_privacy.comfy_ui as comfy_ui
import helto_privacy.envelope as envelope
import helto_privacy.guard as guard
import helto_privacy.keystore as keystore
import helto_privacy.mode_runtime as mode_runtime
import helto_privacy.mode_state as mode_state
import helto_privacy.suite_runtime as suite_runtime


@pytest.fixture(autouse=True)
def isolated_privacy_paths(tmp_path, monkeypatch):
    active_operation_gate = envelope.require_active_process_suite
    active_route_gate = comfy_ui.require_active_process_suite
    active_keystore_gate = keystore.require_active_process_suite
    active_guard_gate = guard.require_active_process_suite
    monkeypatch.setenv(
        keystore.KEYSTORE_ENV,
        str(tmp_path / "keystore" / "privacy_keystore.json"),
    )
    monkeypatch.setenv(keystore.SESSION_DIR_ENV, str(tmp_path / "session"))
    monkeypatch.setenv(
        mode_state.MODE_STATE_ENV,
        str(tmp_path / "mode" / "privacy_mode_state.json"),
    )
    monkeypatch.setattr(keystore, "SCRYPT_N", 2**12)
    monkeypatch.setattr(envelope, "config_dir", lambda: tmp_path / "legacy_config")
    monkeypatch.setattr(
        envelope,
        "require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(comfy_ui, "require_active_process_suite", lambda: None)
    monkeypatch.setattr(keystore, "require_active_process_suite", lambda: None)
    monkeypatch.setattr(guard, "require_active_process_suite", lambda: None)
    monkeypatch.setattr(mode_runtime, "_MODE_TRANSITIONS", {})
    monkeypatch.setattr(mode_runtime, "_ACTIVE_SCOPE_WORK", {})
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_INSTALLATION", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_CONFLICT", False)
    monkeypatch.setattr(suite_runtime, "_PROCESS_CONSUMER_DECLARATIONS", [])
    monkeypatch.setattr(suite_runtime, "_PROCESS_BROWSER_MANIFEST_DIGEST", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_BROWSER_CONFLICT", False)
    return (
        active_operation_gate,
        active_route_gate,
        active_keystore_gate,
        active_guard_gate,
    )
