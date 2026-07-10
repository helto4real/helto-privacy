import pytest

import helto_privacy.runtime as runtime
from helto_privacy.profile import AdapterSlot, PrivacyProfile, ProfileResource, ResourceKind
from helto_privacy.runtime import (
    AdapterBindingError,
    ArtifactHandle,
    ExecutionHandle,
    ModeHandle,
    PackBlockedError,
    ProfileConflictError,
    RecordHandle,
    WorkflowHandle,
    install,
    profile_attestation,
    reconcile_prompt_server,
)


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: False)


def _profile(pack_id="helto.test", distribution="comfyui-helto-test"):
    resources = tuple(
        ProfileResource(resource_id, kind, (f"{resource_id}-adapter",))
        for resource_id, kind in (
            ("privacy-mode", ResourceKind.MODE),
            ("editor-state", ResourceKind.WORKFLOW),
            ("library", ResourceKind.RECORD),
            ("preview", ResourceKind.ARTIFACT),
            ("dispatch", ResourceKind.EXECUTION),
        )
    )
    slots = tuple(
        AdapterSlot(f"{resource.id}-adapter", resource.kind, resource.id)
        for resource in resources
    )
    return PrivacyProfile(
        id=pack_id,
        distribution=distribution,
        resources=resources,
        server_adapters=slots,
    )


def _adapters(profile):
    return {slot.id: object() for slot in reversed(profile.server_adapters)}


def test_install_is_atomic_typed_and_idempotent():
    profile = _profile()
    adapters = _adapters(profile)

    pack = install(profile, adapters)

    assert pack.profile is profile
    assert pack.fingerprint == profile.fingerprint
    assert pack.readiness.state == "waiting_for_prompt_server"
    assert pack.authorization.pack_id == profile.id
    assert isinstance(pack.mode("privacy-mode"), ModeHandle)
    assert isinstance(pack.workflow("editor-state"), WorkflowHandle)
    assert isinstance(pack.records("library"), RecordHandle)
    assert isinstance(pack.artifacts("preview"), ArtifactHandle)
    assert isinstance(pack.execution("dispatch"), ExecutionHandle)
    assert install(profile, dict(reversed(tuple(adapters.items())))) is pack

    adapters.clear()
    assert isinstance(pack.workflow("editor-state"), WorkflowHandle)


def test_missing_or_unknown_adapters_do_not_partially_install():
    profile = _profile(pack_id="helto.atomic")
    adapters = _adapters(profile)
    adapters.pop("editor-state-adapter")

    with pytest.raises(AdapterBindingError) as missing:
        install(profile, adapters)
    assert missing.value.code == "missing_adapter"
    assert profile.id not in runtime._INSTALLATIONS

    complete = _adapters(profile)
    complete["consumer-policy-hook"] = object()
    with pytest.raises(AdapterBindingError) as unknown:
        install(profile, complete)
    assert unknown.value.code == "unknown_adapter"
    assert profile.id not in runtime._INSTALLATIONS

    assert install(profile, _adapters(profile)).profile is profile


def test_conflict_blocks_the_existing_pack_with_sanitized_diagnostics():
    profile = _profile(pack_id="helto.conflict")
    pack = install(profile, _adapters(profile))
    conflicting = _profile(pack_id=profile.id, distribution="different-distribution")

    with pytest.raises(ProfileConflictError) as exc_info:
        install(conflicting, _adapters(conflicting))

    assert exc_info.value.code == "profile_fingerprint_conflict"
    assert profile.id not in str(exc_info.value)
    assert pack.readiness.state == "conflict"
    with pytest.raises(PackBlockedError):
        pack.workflow("editor-state")


def test_same_profile_cannot_rebind_adapters():
    profile = _profile(pack_id="helto.binding-conflict")
    pack = install(profile, _adapters(profile))

    with pytest.raises(ProfileConflictError) as exc_info:
        install(profile, _adapters(profile))

    assert exc_info.value.code == "adapter_binding_conflict"
    assert pack.readiness.state == "conflict"


def test_late_prompt_server_reconciliation_makes_all_packs_ready(monkeypatch):
    first = install(_profile(pack_id="helto.first"), _adapters(_profile(pack_id="helto.first")))
    second_profile = _profile(pack_id="helto.second")
    second = install(second_profile, _adapters(second_profile))
    prompt_server = object()
    calls = []
    monkeypatch.setattr(
        runtime,
        "register_helto_privacy_ui",
        lambda **kwargs: calls.append(kwargs["prompt_server"]) or True,
    )

    assert reconcile_prompt_server(prompt_server) is True

    assert calls == [prompt_server]
    assert first.readiness.state == "ready"
    assert second.readiness.state == "ready"
    first.readiness.require_ready()

    public_state = profile_attestation("helto.first")
    assert public_state == {
        "id": "helto.first",
        "distribution": "comfyui-helto-test",
        "contract": "helto.privacy.v2",
        "fingerprint": first.fingerprint,
        "status": "ready",
        "requiredBrowserAdapters": [],
    }
    assert "token" not in str(public_state).lower()
    assert "secret" not in str(public_state).lower()
