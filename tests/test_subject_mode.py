import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

import helto_privacy.runtime as runtime
import helto_privacy.subject_mode as subject_mode
from helto_privacy.mode import EffectivePrivacyMode
from helto_privacy.profile import (
    AdapterSlot,
    ProfileValidationError,
    ProtectedOperation,
    ResourceKind,
    SubjectModeBinding,
)
from helto_privacy.subject_mode import (
    SubjectModeLease,
    SubjectModeReferenceError,
    consume_subject_mode_reference,
    invalidate_subject_mode_profile,
    invalidate_subject_mode_session,
    prepare_subject_mode_reference,
    revoke_subject_mode_reference,
    validate_pending_subject_mode_reference,
)

from tests.test_protected_operations import (
    ModeAdapter,
    ProjectionAdapter,
    _private_source,
    _projection_profile,
)
from tests.test_execution import _profile as _execution_profile


def _authorization(token: str):
    return SimpleNamespace(
        _session_fingerprint=hashlib.sha256(token.encode()).digest(),
    )


def _profile(*, two_operations=False):
    base = _projection_profile()
    binding = SubjectModeBinding(
        "generation-mode",
        "generate",
        "privacy_mode_reference",
        ("AIOImageGenerate",),
    )
    operation = replace(
        base.protected_operations[0],
        subject_mode_binding_id=binding.id,
    )
    operations = (operation,)
    if two_operations:
        operations = (operation, replace(operation, id="emit-run-info-copy"))
    resources = tuple(
        replace(
            resource,
            adapter_slots=(*resource.adapter_slots, "mode-browser"),
        )
        if resource.id == "privacy-mode"
        else resource
        for resource in base.resources
    )
    return replace(
        base,
        resources=resources,
        scopes=(replace(base.scopes[0], mode_editor_adapter="mode-browser"),),
        browser_adapters=(
            AdapterSlot(
                "mode-browser",
                ResourceKind.MODE,
                "privacy-mode",
                ("AIOImageGenerate",),
            ),
        ),
        subject_mode_bindings=(binding,),
        protected_operations=operations,
    )


def _installation(profile):
    return SimpleNamespace(
        profile=profile,
        status=SimpleNamespace(value="ready"),
    )


def test_profile_subject_bindings_are_strict_and_shareable():
    shared = _profile(two_operations=True)
    assert {
        operation.subject_mode_binding_id
        for operation in shared.protected_operations
    } == {"generation-mode"}

    base = _profile()
    with pytest.raises(ProfileValidationError) as missing_editor:
        replace(
            base,
            scopes=(replace(base.scopes[0], mode_editor_adapter=None),),
        )
    assert missing_editor.value.code == "subject_mode_adapter_missing"

    with pytest.raises(ProfileValidationError) as node_mismatch:
        replace(
            base,
            browser_adapters=(
                replace(base.browser_adapters[0], node_types=("OtherNode",)),
            ),
        )
    assert node_mismatch.value.code == "subject_mode_binding_mismatch"

    with pytest.raises(ProfileValidationError) as unknown_binding:
        replace(
            base,
            protected_operations=(
                replace(
                    base.protected_operations[0],
                    subject_mode_binding_id="missing-binding",
                ),
            ),
        )
    assert unknown_binding.value.code == "unknown_subject_mode_binding"

    with pytest.raises(ProfileValidationError) as unused_binding:
        replace(
            base,
            protected_operations=(
                replace(
                    base.protected_operations[0],
                    subject_mode_binding_id=None,
                ),
            ),
        )
    assert unused_binding.value.code == "unused_subject_mode_binding"

    second_binding = replace(base.subject_mode_bindings[0], id="other-mode")
    with pytest.raises(ProfileValidationError) as input_collision:
        replace(
            base,
            subject_mode_bindings=(*base.subject_mode_bindings, second_binding),
            protected_operations=(
                base.protected_operations[0],
                replace(
                    base.protected_operations[0],
                    id="emit-run-info-copy",
                    subject_mode_binding_id=second_binding.id,
                ),
            ),
        )
    assert input_collision.value.code == "duplicate_execution_input_binding"


def _prepared(
    monkeypatch,
    *,
    profile=None,
    subject="node-7",
    effective=EffectivePrivacyMode.PUBLIC,
):
    invalidate_subject_mode_session("test-reset")
    profile = profile or _profile()
    token = "synthetic-session"
    installation = _installation(profile)
    monkeypatch.setattr(
        subject_mode,
        "require_current_authorization",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(subject_mode.keystore, "session_token", lambda: token)
    prepared = prepare_subject_mode_reference(
        profile=profile,
        binding=profile.subject_mode_bindings[0],
        subject_id=subject,
        effective=effective,
        authorization=_authorization(token),
        installation=installation,
    )
    return profile, installation, prepared


def test_reference_v2_is_fingerprint_binding_bound_and_non_consuming(monkeypatch):
    profile, _installation_value, prepared = _prepared(
        monkeypatch,
        effective=EffectivePrivacyMode.PRIVATE,
    )
    binding = profile.subject_mode_bindings[0]
    assert prepared.reference["version"] == 2
    assert prepared.reference["profileFingerprint"] == profile.fingerprint
    assert prepared.reference["bindingId"] == binding.id
    assert "operationId" not in prepared.reference
    assert "resourceId" not in prepared.reference
    result = validate_pending_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    )
    assert result.valid is True
    assert result.requires_private_execution is True
    assert repr(result) == "PendingSubjectModeValidation()"
    lease = consume_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    )
    assert isinstance(lease, SubjectModeLease)
    assert repr(lease) == "SubjectModeLease()"
    assert lease.requires_private_execution(
        profile=profile,
        binding_id=binding.id,
    ) is True
    with pytest.raises(SubjectModeReferenceError):
        consume_subject_mode_reference(
            prepared.reference,
            profile=profile,
            binding=binding,
            subject_id="node-7",
        )
    lease.close()


def test_lease_serves_all_linked_consumers_then_rejects_wrong_closed_and_replay(
    monkeypatch,
):
    profile = _profile(two_operations=True)
    profile, _installation_value, prepared = _prepared(monkeypatch, profile=profile)
    binding = profile.subject_mode_bindings[0]
    lease = consume_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    )
    assert lease._effective_for(
        profile=profile,
        binding_id=binding.id,
        operation_id="emit-run-info",
    ) is EffectivePrivacyMode.PUBLIC
    assert lease.requires_private_execution(
        profile=profile,
        binding_id=binding.id,
    ) is False
    with pytest.raises(SubjectModeReferenceError):
        lease.requires_private_execution(
            profile=profile,
            binding_id="other-binding",
        )
    assert lease._effective_for(
        profile=profile,
        binding_id=binding.id,
        operation_id="emit-run-info-copy",
    ) is EffectivePrivacyMode.PUBLIC
    with pytest.raises(SubjectModeReferenceError):
        lease._effective_for(
            profile=profile,
            binding_id=binding.id,
            operation_id="unrelated-operation",
        )
    with pytest.raises(SubjectModeReferenceError):
        lease._effective_for(
            profile=profile,
            binding_id="other-binding",
            operation_id="emit-run-info",
        )
    lease.close()
    with pytest.raises(SubjectModeReferenceError):
        lease._effective_for(
            profile=profile,
            binding_id=binding.id,
            operation_id="emit-run-info",
        )


def test_wrong_subject_consumes_pending_reference(monkeypatch):
    profile, _installation_value, prepared = _prepared(monkeypatch)
    binding = profile.subject_mode_bindings[0]
    with pytest.raises(SubjectModeReferenceError):
        consume_subject_mode_reference(
            prepared.reference,
            profile=profile,
            binding=binding,
            subject_id="node-8",
        )
    with pytest.raises(SubjectModeReferenceError):
        consume_subject_mode_reference(
            prepared.reference,
            profile=profile,
            binding=binding,
            subject_id="node-7",
        )


def test_session_and_profile_invalidation_expire_pending_and_active(monkeypatch):
    profile, _installation_value, prepared = _prepared(monkeypatch)
    binding = profile.subject_mode_bindings[0]
    lease = consume_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    )
    invalidate_subject_mode_session("lock")
    with pytest.raises(SubjectModeReferenceError):
        lease._effective_for(
            profile=profile,
            binding_id=binding.id,
            operation_id="emit-run-info",
        )


def test_active_lease_cannot_authorize_after_its_ttl(monkeypatch):
    now = 100.0
    monkeypatch.setattr(subject_mode.time, "monotonic", lambda: now)
    profile, _installation_value, prepared = _prepared(monkeypatch)
    binding = profile.subject_mode_bindings[0]
    lease = consume_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    )

    now += subject_mode._GRANT_TTL_SECONDS
    with pytest.raises(SubjectModeReferenceError):
        lease._effective_for(
            profile=profile,
            binding_id=binding.id,
            operation_id="emit-run-info",
        )


def test_public_execution_only_invocation_consumes_and_closes_once(monkeypatch):
    profile = _execution_profile()
    profile, _installation_value, prepared = _prepared(
        monkeypatch,
        profile=profile,
        effective=EffectivePrivacyMode.PUBLIC,
    )
    binding = profile.subject_mode_bindings[0]

    with consume_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    ):
        pass

    with pytest.raises(SubjectModeReferenceError):
        consume_subject_mode_reference(
            prepared.reference,
            profile=profile,
            binding=binding,
            subject_id="node-7",
        )

    profile, _installation_value, prepared = _prepared(monkeypatch)
    binding = profile.subject_mode_bindings[0]
    lease = consume_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        subject_id="node-7",
    )
    invalidate_subject_mode_profile(profile.id)
    with pytest.raises(SubjectModeReferenceError):
        lease._effective_for(
            profile=profile,
            binding_id=binding.id,
            operation_id="emit-run-info",
        )


def test_revoke_is_exact_and_idempotent(monkeypatch):
    profile, _installation_value, prepared = _prepared(monkeypatch)
    binding = profile.subject_mode_bindings[0]
    tampered = dict(prepared.reference)
    tampered["bindingId"] = "other-binding"
    with pytest.raises(SubjectModeReferenceError):
        revoke_subject_mode_reference(
            tampered,
            profile=profile,
            binding=binding,
            authorization=object(),
        )
    assert revoke_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        authorization=object(),
    ) is True
    assert revoke_subject_mode_reference(
        prepared.reference,
        profile=profile,
        binding=binding,
        authorization=object(),
    ) is False


def test_protected_operations_require_active_linked_lease(monkeypatch):
    profile = _profile(two_operations=True)
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    adapter = ProjectionAdapter()
    pack = runtime.install(
        profile,
        {"mode": ModeAdapter("public"), "run-info": adapter},
    )
    token = "lease-projection-session"
    monkeypatch.setattr(subject_mode, "require_current_authorization", lambda *_a, **_k: None)
    monkeypatch.setattr(subject_mode.keystore, "session_token", lambda: token)
    prepared = prepare_subject_mode_reference(
        profile=pack.profile,
        binding=pack.profile.subject_mode_bindings[0],
        subject_id="node-7",
        effective=EffectivePrivacyMode.PUBLIC,
        authorization=_authorization(token),
        installation=pack._installation,
    )
    with pytest.raises(Exception):
        pack.operations("run-info").project("emit-run-info", _private_source())
    with pack.subject_modes("generation-mode").consume(
        prepared.reference,
        "node-7",
    ) as lease:
        first = pack.operations("run-info").project(
            "emit-run-info",
            _private_source(),
            subject_mode=lease,
        )
        second = pack.operations("run-info").project(
            "emit-run-info-copy",
            _private_source(),
            subject_mode=lease,
        )
    assert first.private is False
    assert second.private is False
