import asyncio

import pytest

import helto_privacy.runtime as runtime
from helto_privacy import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ProtectedOperation,
    ProtectedOperationError,
    ResourceKind,
    SafeDiagnosticField,
    SafeDiagnosticKind,
    SensitiveFieldClass,
    SensitiveFieldDeclaration,
    WorkflowRevealOperationContext,
    WorkflowRevealOperations,
)


class Authorization:
    def __init__(self) -> None:
        self.calls = []

    def authorize_request(self, request, operation_id):
        self.calls.append(("reveal", request, operation_id))
        return "reveal-authorization"

    async def dispatch(self, request, scope_id, operation_id, operation):
        self.calls.append(("dispatch", request, scope_id, operation_id))
        return await operation("operation-authorization")


class Adapter:
    def invoke(self, payload, context):
        assert payload == {"protected": "CURRENT"}
        assert context == WorkflowRevealOperationContext(
            "operation-authorization",
            "reveal-authorization",
            "workflow-handle",
        )
        return {"status": "revealed"}


def test_workflow_reveal_operation_issues_narrow_authority_inside_dispatch():
    authorization = Authorization()
    operations = WorkflowRevealOperations(
        authorization,
        "workflow-handle",
        Adapter(),
        scope_id="display",
        operation_id="display.reveal",
    )

    result = asyncio.run(
        operations.dispatch("request", {"protected": "CURRENT"})
    )

    assert result == {"status": "revealed"}
    assert authorization.calls == [
        ("dispatch", "request", "display", "display.reveal"),
        ("reveal", "request", "snapshot.reveal"),
    ]


class ModeAdapter:
    def __init__(self, mode):
        self.mode = mode

    def read_declared_mode(self, _scope_id):
        return self.mode

    def write_declared_mode(self, _scope_id, mode):
        self.mode = mode

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class ProjectionAdapter:
    def __init__(self):
        self.calls = 0
        self.extra = {}

    def project(self, value, _declaration):
        self.calls += 1
        performance = value["performance"]
        return {
            "performance": {
                "configured": performance["configured"],
                "memory_cleanup_applied": performance["memory_cleanup_applied"],
                "warning_count": performance["warning_count"],
                **self.extra,
            }
        }


def _projection_profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.protected-projection-test",
        distribution="comfyui-protected-projection-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("run-info", ResourceKind.WORKFLOW, ("run-info",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("run-info", ResourceKind.WORKFLOW, "run-info"),
        ),
        scopes=(PrivacyScope("generate", "privacy-mode", "mode"),),
        protected_operations=(
            ProtectedOperation(
                "emit-run-info",
                "run-info",
                "run-info",
                None,
                scope_id="generate",
                sensitive_fields=(
                    SensitiveFieldDeclaration(
                        "*",
                        SensitiveFieldClass.CONSUMER_DERIVED,
                    ),
                    SensitiveFieldDeclaration("debug", SensitiveFieldClass.DEBUG),
                    SensitiveFieldDeclaration(
                        "model_path",
                        SensitiveFieldClass.PATH_OR_NAME,
                    ),
                    SensitiveFieldDeclaration(
                        "settings.prompt",
                        SensitiveFieldClass.USER_AUTHORED,
                    ),
                ),
                safe_projection=(
                    SafeDiagnosticField(
                        "performance.configured",
                        SafeDiagnosticKind.BOOLEAN,
                    ),
                    SafeDiagnosticField(
                        "performance.memory_cleanup_applied",
                        SafeDiagnosticKind.BOOLEAN,
                    ),
                    SafeDiagnosticField(
                        "performance.warning_count",
                        SafeDiagnosticKind.COUNT,
                    ),
                ),
            ),
        ),
    )


def _projection_pack(monkeypatch, mode):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    adapter = ProjectionAdapter()
    pack = runtime.install(
        _projection_profile(),
        {"mode": ModeAdapter(mode), "run-info": adapter},
    )
    return pack, adapter


def _private_source():
    return {
        "model_path": "/SYNTHETIC/PRIVATE/MODEL",
        "settings": {"prompt": "SYNTHETIC_PRIVATE_PROMPT"},
        "debug": {"workflow": "SYNTHETIC_PRIVATE_WORKFLOW"},
        "performance": {
            "configured": True,
            "memory_cleanup_applied": False,
            "warning_count": 2,
        },
    }


def test_private_operation_projection_is_allowlist_only_and_coarse(monkeypatch):
    pack, adapter = _projection_pack(monkeypatch, "private")
    source = _private_source()

    result = pack.operations("run-info").project("emit-run-info", source)

    assert result.private is True
    assert result.value == {
        "performance": {
            "configured": True,
            "memory_cleanup_applied": False,
            "warning_count": 2,
        }
    }
    assert adapter.calls == 1
    assert source["debug"]["workflow"] == "SYNTHETIC_PRIVATE_WORKFLOW"
    assert "SYNTHETIC" not in repr(result)
    assert runtime.profile_attestation(pack.profile.id)["protectedOperations"] == []
    declaration = pack.profile.protected_operations[0]
    assert declaration.scope_id == "generate"
    assert {item.path for item in declaration.safe_projection} == {
        "performance.configured",
        "performance.memory_cleanup_applied",
        "performance.warning_count",
    }
    assert {item.field_class for item in declaration.sensitive_fields} == {
        SensitiveFieldClass.CONSUMER_DERIVED,
        SensitiveFieldClass.DEBUG,
        SensitiveFieldClass.PATH_OR_NAME,
        SensitiveFieldClass.USER_AUTHORED,
    }


def test_public_operation_projection_preserves_product_schema(monkeypatch):
    pack, adapter = _projection_pack(monkeypatch, "public")
    source = _private_source()

    result = pack.operations("run-info").project("emit-run-info", source)

    assert result.private is False
    assert result.value == source
    assert result.value is not source
    assert adapter.calls == 0


def test_private_projection_rejects_extra_or_wrongly_typed_diagnostics(monkeypatch):
    pack, adapter = _projection_pack(monkeypatch, "private")
    adapter.extra = {"prompt_canary": "SYNTHETIC_PRIVATE_PROMPT"}

    with pytest.raises(ProtectedOperationError) as extra:
        pack.operations("run-info").project("emit-run-info", _private_source())
    assert extra.value.code == "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
    assert "SYNTHETIC" not in repr(extra.value)

    adapter.extra = {}
    source = _private_source()
    source["performance"]["configured"] = "SYNTHETIC_PRIVATE_BOOLEAN"
    with pytest.raises(ProtectedOperationError) as invalid:
        pack.operations("run-info").project("emit-run-info", source)
    assert invalid.value.code == "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
