from __future__ import annotations

import asyncio
import inspect
import pickle
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from weakref import ReferenceType

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.artifacts as artifacts
import helto_privacy.keystore as keystore
import helto_privacy.mode_runtime as mode_runtime
import helto_privacy.opaque_references as opaque_references
import helto_privacy.operation_dependencies as operation_dependencies
import helto_privacy.records as records
import helto_privacy.runtime as runtime
import helto_privacy.singletons as singletons
from helto_privacy import (
    AdapterSlot,
    ArtifactDeclaration,
    ArtifactOperationDependency,
    ArtifactRetention,
    OpaqueReferenceCandidate,
    OpaqueReferenceKind,
    OperationReferenceInput,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ProtectedOperation,
    ProtectedOperationAdapterResult,
    ProtectedOperationError,
    RecordDeclaration,
    RecordOperationDependency,
    RecordRevealProjection,
    ResourceKind,
    SafeDiagnosticField,
    SafeDiagnosticKind,
    SensitiveFieldClass,
    SensitiveFieldDeclaration,
    SingletonDeclaration,
    SingletonOperationDependency,
    SingletonPayloadKind,
)
from helto_privacy.mode import ModeTransitionError
from helto_privacy.guard import AuthorizedPrivacyRequest
from helto_privacy.profile import ProfileValidationError
from helto_privacy.artifacts import root_bound_source


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeAdapter(ModeSourceProtocolFixture):
    def __init__(self) -> None:
        self.mode = "private"

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


class TransitionAdapter:
    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class RecordAdapter(TransitionAdapter):
    def list_ids(self, *_args):
        return ()

    def read_record(self, *_args):
        return None

    def compare_and_swap_record(self, *_args):
        return None

    def project(self, *_args):
        return {}


class SingletonAdapter(TransitionAdapter):
    def read_singleton(self, *_args):
        return None

    def begin_singleton_replace(self, *_args):
        return None

    def rollback_singleton_replace(self, *_args):
        return None


class ArtifactAdapter(TransitionAdapter):
    def encode(self, value):
        return bytes(value)

    def decode(self, value):
        return bytes(value)

    def purge_plaintext_derivatives(self, *_args):
        return None


class DependencyAdapter:
    def __init__(self) -> None:
        self.action = "success"
        self.retained_bundle = None
        self.retained_record = None
        self.started = None
        self.release = None
        self.operation_lease = None
        self.observations: dict[str, object] = {}

    async def invoke_with_dependencies(
        self,
        _value,
        _references,
        _declaration,
        dependencies,
    ):
        self.retained_bundle = dependencies
        record = dependencies.record("library", "prompt-record", "use")
        self.retained_record = record
        if self.action == "cancel":
            self.started.set()
            await self.release.wait()
        await asyncio.sleep(0)
        self.observations["record"] = record.reveal("hp-rec-synthetic")
        singleton = dependencies.singleton("settings")
        self.observations["status"] = singleton.status()
        artifact = dependencies.artifact("thumbnail")
        self.observations["artifact"] = await artifact.read("synthetic-reference")

        async def cross_task_use():
            try:
                record.reveal("hp-rec-cross-task")
            except ProtectedOperationError as error:
                return error.code
            return None

        self.observations["cross_task"] = await asyncio.create_task(cross_task_use())
        for name, operation in (
            (
                "record_lookup",
                lambda: dependencies.record("library", "prompt-record", "details"),
            ),
            ("singleton_lookup", lambda: dependencies.singleton("settings-alt")),
        ):
            try:
                operation()
            except ProtectedOperationError as error:
                self.observations[name] = error.code
        try:
            singleton.delete(0)
        except ProtectedOperationError as error:
            self.observations["singleton_verb"] = error.code
        try:
            await artifact.write("hp-owner-synthetic", b"private")
        except ProtectedOperationError as error:
            self.observations["artifact_verb"] = error.code
        return ProtectedOperationAdapterResult(
            {"items": 3},
            lease=self.operation_lease,
        )

    def project(self, payload, _declaration):
        return {"items": payload["items"]}


def _operation(*, dependencies: bool = True) -> ProtectedOperation:
    return ProtectedOperation(
        "consume",
        "operations",
        "operation-adapter",
        "/operation-dependencies/consume",
        scope_id="main",
        sensitive_fields=(
            SensitiveFieldDeclaration("*", SensitiveFieldClass.CONSUMER_DERIVED),
        ),
        safe_projection=(SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),),
        record_dependencies=(
            RecordOperationDependency("library", "prompt-record", "use"),
        )
        if dependencies
        else (),
        singleton_dependencies=(
            SingletonOperationDependency("settings", ("reveal", "status")),
        )
        if dependencies
        else (),
        artifact_dependencies=(
            ArtifactOperationDependency("thumbnail", ("lease.preview", "read")),
        )
        if dependencies
        else (),
    )


def dependency_profile(*, dependencies: bool = True) -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.operation-dependency-test",
        distribution="comfyui-operation-dependency-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("library", ResourceKind.RECORD, ("records",)),
            ProfileResource("state", ResourceKind.SINGLETON, ("singletons",)),
            ProfileResource("media", ResourceKind.ARTIFACT, ("artifacts",)),
            ProfileResource("operations", ResourceKind.OPERATION, ("operation-adapter",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("records", ResourceKind.RECORD, "library"),
            AdapterSlot("singletons", ResourceKind.SINGLETON, "state"),
            AdapterSlot("artifacts", ResourceKind.ARTIFACT, "media"),
            AdapterSlot("operation-adapter", ResourceKind.OPERATION, "operations"),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        records=(
            RecordDeclaration(
                "prompt-record",
                "library",
                "main",
                "helto.record.v1",
                "records",
                projections=(RecordRevealProjection("use", ("prompt",)),),
            ),
        ),
        singletons=(
            SingletonDeclaration(
                "settings",
                "state",
                "main",
                "helto.settings.v1",
                "settings",
                "singletons",
                SingletonPayloadKind.BLOB,
            ),
            SingletonDeclaration(
                "settings-alt",
                "state",
                "main",
                "helto.settings-alt.v1",
                "settings-alt",
                "singletons",
                SingletonPayloadKind.BLOB,
            ),
        ),
        artifacts=(
            ArtifactDeclaration(
                "thumbnail",
                "media",
                "main",
                "thumbnail",
                "artifacts",
                1,
                ArtifactRetention.REGENERABLE_CACHE,
                ("preview",),
                media_type="image/webp",
            ),
            ArtifactDeclaration(
                "preview-alt",
                "media",
                "main",
                "preview-alt",
                "artifacts",
                1,
                ArtifactRetention.REGENERABLE_CACHE,
                ("inspect",),
                media_type="image/webp",
            ),
        ),
        protected_operations=(_operation(dependencies=dependencies),),
    )


def source_dependency_profile() -> PrivacyProfile:
    base = dependency_profile(dependencies=False)
    produce = ProtectedOperation(
        "produce-source",
        "operations",
        "operation-adapter",
        "/operation-dependencies/produce-source",
        scope_id="main",
        sensitive_fields=(
            SensitiveFieldDeclaration("*", SensitiveFieldClass.CONSUMER_DERIVED),
        ),
        safe_projection=(SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),),
        reference_outputs=("operation-result",),
    )
    serve = ProtectedOperation(
        "serve-source",
        "operations",
        "operation-adapter",
        "/operation-dependencies/serve-source",
        scope_id="main",
        reference_inputs=(
            OperationReferenceInput("source", "operation-result", True),
        ),
        returns_lease=True,
        singleton_dependencies=(
            SingletonOperationDependency("settings", ("reveal",)),
        ),
    )
    return replace(
        base,
        opaque_reference_kinds=(
            OpaqueReferenceKind("operation-result", "operations", "main"),
        ),
        protected_operations=(produce, serve),
    )


def artifact_operation_lease_profile() -> PrivacyProfile:
    base = source_dependency_profile()
    produce, serve = base.protected_operations
    return replace(
        base,
        protected_operations=(
            produce,
            replace(
                serve,
                sensitive_fields=(
                    SensitiveFieldDeclaration(
                        "*",
                        SensitiveFieldClass.CONSUMER_DERIVED,
                    ),
                ),
                safe_projection=(
                    SafeDiagnosticField("ready", SafeDiagnosticKind.BOOLEAN),
                ),
                singleton_dependencies=(),
                artifact_dependencies=(
                    ArtifactOperationDependency(
                        "thumbnail",
                        ("lease.preview", "read"),
                    ),
                ),
            ),
        ),
    )


class SyntheticSourceAbort(BaseException):
    pass


class SourceDependencyAdapter:
    def __init__(self, source_path: Path) -> None:
        self.source_path = source_path
        self.action = "success"
        self.started: asyncio.Event | None = None
        self.release: asyncio.Event | None = None
        self.retained_bundle = None
        self.retained_singleton = None
        self.undeclared_code = None
        self.operation_lease = None

    def invoke(self, _value, _references, declaration):
        assert declaration.id == "produce-source"
        return ProtectedOperationAdapterResult(
            {"items": 1},
            (
                OpaqueReferenceCandidate(
                    "operation-result",
                    {"path": str(self.source_path)},
                ),
            ),
        )

    async def invoke_with_dependencies(
        self,
        _value,
        _references,
        declaration,
        dependencies,
    ):
        if self.action != "artifact-lease" or declaration.id != "serve-source":
            raise AssertionError("source publication must use the dedicated binder")
        self.retained_bundle = dependencies
        dependencies.artifact("thumbnail")
        return ProtectedOperationAdapterResult(
            {"ready": True},
            lease=self.operation_lease,
        )

    def project(self, payload, _declaration):
        return (
            {"items": payload["items"]}
            if "items" in payload
            else {"ready": payload["ready"]}
        )

    async def bind_source_with_dependencies(
        self,
        resolved,
        declaration,
        dependencies,
    ):
        assert declaration.id == "serve-source"
        self.retained_bundle = dependencies
        singleton = dependencies.singleton("settings")
        self.retained_singleton = singleton
        try:
            dependencies.singleton("settings-alt")
        except ProtectedOperationError as exc:
            self.undeclared_code = exc.code
        settings = singleton.reveal()
        if self.action in {"block", "cancel", "abort"}:
            assert self.started is not None and self.release is not None
            self.started.set()
            await self.release.wait()
        if self.action == "abort":
            raise SyntheticSourceAbort()
        return root_bound_source(
            resolved.value["path"],
            tuple(Path(value) for value in settings["roots"]),
            media_type="image/png",
        )


def _with_operation(profile: PrivacyProfile, operation: ProtectedOperation) -> PrivacyProfile:
    return replace(profile, protected_operations=(operation,))


def test_dependencies_are_canonical_optional_and_fingerprint_bound():
    empty = dependency_profile(dependencies=False)
    assert "recordDependencies" not in empty._canonical_value()["protectedOperations"][0]
    assert "singletonDependencies" not in empty._canonical_value()["protectedOperations"][0]
    assert "artifactDependencies" not in empty._canonical_value()["protectedOperations"][0]

    base = dependency_profile()
    operation = base.protected_operations[0]
    expanded = replace(
        operation,
        singleton_dependencies=(
            SingletonOperationDependency("settings-alt", ("status",)),
            SingletonOperationDependency("settings", ("status", "reveal")),
        ),
        artifact_dependencies=(
            ArtifactOperationDependency("preview-alt", ("lease.inspect", "read")),
            ArtifactOperationDependency("thumbnail", ("read", "lease.preview")),
        ),
    )
    reordered = replace(
        operation,
        singleton_dependencies=tuple(reversed(expanded.singleton_dependencies)),
        artifact_dependencies=tuple(reversed(expanded.artifact_dependencies)),
    )
    expanded_profile = _with_operation(base, expanded)
    assert expanded_profile.fingerprint == _with_operation(base, reordered).fingerprint
    assert expanded_profile.fingerprint != base.fingerprint
    changed_target = replace(
        operation,
        singleton_dependencies=(SingletonOperationDependency("settings-alt", ("status",)),),
    )
    changed_verb = replace(
        operation,
        singleton_dependencies=(SingletonOperationDependency("settings", ("status",)),),
    )
    assert _with_operation(base, changed_target).fingerprint != base.fingerprint
    assert _with_operation(base, changed_verb).fingerprint != base.fingerprint
    canonical = base._canonical_value()["protectedOperations"][0]
    assert canonical["recordDependencies"] == [
        {"resourceId": "library", "recordKind": "prompt-record", "operation": "use"}
    ]
    assert canonical["singletonDependencies"] == [
        {"singletonId": "settings", "verbs": ["reveal", "status"]}
    ]
    assert canonical["artifactDependencies"] == [
        {"artifactKind": "thumbnail", "verbs": ["lease.preview", "read"]}
    ]
    assert base.server_adapter_contracts["operation-adapter"] == (
        "invoke_with_dependencies",
        "project",
    )
    assert empty.server_adapter_contracts["operation-adapter"] == ("invoke", "project")


def test_dependency_bound_source_requires_the_dedicated_adapter_contract():
    profile = source_dependency_profile()
    assert profile.server_adapter_contracts["operation-adapter"] == (
        "bind_source_with_dependencies",
        "invoke",
        "invoke_with_dependencies",
        "project",
    )
    dependency_free = replace(
        profile,
        protected_operations=tuple(
            replace(operation, singleton_dependencies=())
            if operation.id == "serve-source"
            else operation
            for operation in profile.protected_operations
        ),
    )
    assert dependency_free.server_adapter_contracts["operation-adapter"] == (
        "bind_source",
        "invoke",
        "project",
    )


def test_dependency_bound_source_missing_dedicated_binder_blocks_install(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    root = tmp_path / "source-root"
    root.mkdir()
    source_path = root / "frame.png"
    source_path.write_bytes(b"synthetic")
    adapter = SourceDependencyAdapter(source_path)
    adapter.bind_source_with_dependencies = None
    adapter.bind_source = lambda *_args: root_bound_source(
        source_path,
        (root,),
        media_type="image/png",
    )
    with pytest.raises(runtime.AdapterBindingError):
        runtime.install(
            source_dependency_profile(),
            {
                "mode": ModeAdapter(),
                "records": RecordAdapter(),
                "singletons": SingletonAdapter(),
                "artifacts": ArtifactAdapter(),
                "operation-adapter": adapter,
            },
        )


def test_dependency_declarations_reject_duplicates_unknown_targets_scope_and_verbs():
    record = RecordOperationDependency("library", "prompt-record", "use")
    with pytest.raises(ProfileValidationError) as duplicate:
        replace(_operation(), record_dependencies=(record, record))
    assert duplicate.value.code == "duplicate_record_operation_dependency"
    with pytest.raises(ProfileValidationError) as invalid_singleton_verb:
        SingletonOperationDependency("settings", ("export",))
    assert invalid_singleton_verb.value.code == "invalid_singleton_dependency_verb"
    with pytest.raises(ProfileValidationError) as invalid_artifact_verb:
        ArtifactOperationDependency("thumbnail", ("publish",))
    assert invalid_artifact_verb.value.code == "invalid_artifact_dependency_verb"

    base = dependency_profile()
    operation = base.protected_operations[0]
    with pytest.raises(ProfileValidationError) as wrong_record:
        _with_operation(
            base,
            replace(
                operation,
                record_dependencies=(
                    RecordOperationDependency("library", "missing-record", "use"),
                ),
            ),
        )
    assert wrong_record.value.code == "record_operation_dependency_mismatch"
    with pytest.raises(ProfileValidationError) as wrong_lease:
        _with_operation(
            base,
            replace(
                operation,
                artifact_dependencies=(
                    ArtifactOperationDependency("thumbnail", ("lease.inspect",)),
                ),
            ),
        )
    assert wrong_lease.value.code == "undeclared_artifact_dependency_operation"
    other_scope = PrivacyScope("other", "privacy-mode", "mode")
    moved_singletons = tuple(
        replace(item, scope_id="other") if item.id == "settings" else item
        for item in base.singletons
    )
    with pytest.raises(ProfileValidationError) as wrong_scope:
        replace(
            base,
            scopes=(*base.scopes, other_scope),
            singletons=moved_singletons,
        )
    assert wrong_scope.value.code == "operation_dependency_scope_mismatch"


def test_artifact_dependency_verbs_match_retention_lifecycle():
    base = dependency_profile()
    operation = base.protected_operations[0]
    with pytest.raises(ProfileValidationError) as reconcile_cache:
        _with_operation(
            base,
            replace(
                operation,
                artifact_dependencies=(
                    ArtifactOperationDependency("thumbnail", ("reconcile-owner",)),
                ),
            ),
        )
    assert reconcile_cache.value.code == "invalid_artifact_dependency_retention"

    spill_artifacts = tuple(
        replace(
            item,
            retention=ArtifactRetention.RUN_SCOPED_SPILL,
            operations=(),
        )
        if item.id == "thumbnail"
        else item
        for item in base.artifacts
    )
    with pytest.raises(ProfileValidationError) as write_spill:
        replace(
            base,
            artifacts=spill_artifacts,
            protected_operations=(
                replace(
                    operation,
                    artifact_dependencies=(
                        ArtifactOperationDependency("thumbnail", ("write",)),
                    ),
                ),
            ),
        )
    assert write_spill.value.code == "invalid_artifact_dependency_retention"

    durable_artifacts = tuple(
        replace(item, retention=ArtifactRetention.DURABLE_ADJUNCT)
        if item.id == "thumbnail"
        else item
        for item in base.artifacts
    )
    durable = replace(
        base,
        artifacts=durable_artifacts,
        protected_operations=(
            replace(
                operation,
                artifact_dependencies=(
                    ArtifactOperationDependency("thumbnail", ("reconcile-owner",)),
                ),
            ),
        ),
    )
    writable = _with_operation(
        base,
        replace(
            operation,
            artifact_dependencies=(ArtifactOperationDependency("thumbnail", ("write",)),),
        ),
    )
    assert durable.protected_operations[0].artifact_dependencies[0].verbs == (
        "reconcile-owner",
    )
    assert writable.protected_operations[0].artifact_dependencies[0].verbs == ("write",)


@pytest.fixture
def dependency_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    adapter = DependencyAdapter()
    mode = ModeAdapter()
    pack = runtime.install(
        dependency_profile(),
        {
            "mode": mode,
            "records": RecordAdapter(),
            "singletons": SingletonAdapter(),
            "artifacts": ArtifactAdapter(),
            "operation-adapter": adapter,
        },
    )
    token = keystore.initialize_keystore("synthetic dependency password")["token"]
    return pack, mode, adapter, Request(token)


@pytest.fixture
def source_dependency_pack(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    opaque_references.clear_opaque_references_for_tests()
    root = tmp_path / "source-root"
    root.mkdir()
    source_path = root / "frame.png"
    source_path.write_bytes(b"synthetic source")
    adapter = SourceDependencyAdapter(source_path)
    pack = runtime.install(
        source_dependency_profile(),
        {
            "mode": ModeAdapter(),
            "records": RecordAdapter(),
            "singletons": SingletonAdapter(),
            "artifacts": ArtifactAdapter(),
            "operation-adapter": adapter,
        },
    )
    token = keystore.initialize_keystore("synthetic source dependency password")[
        "token"
    ]
    request = Request(token)
    monkeypatch.setattr(
        singletons,
        "reveal_singleton_blob",
        lambda **_kwargs: {"roots": [str(root)]},
    )
    return pack, adapter, request


def test_dispatch_passes_only_declared_ephemeral_capabilities(
    dependency_pack,
    monkeypatch,
):
    pack, _mode, adapter, request = dependency_pack
    monkeypatch.setattr(
        records,
        "reveal_record",
        lambda **_kwargs: SimpleNamespace(value={"prompt": "SYNTHETIC_PROMPT"}),
    )
    monkeypatch.setattr(
        singletons,
        "singleton_status",
        lambda **_kwargs: {"configured": True},
    )

    async def read_artifact(**_kwargs):
        return b"SYNTHETIC_ARTIFACT"

    monkeypatch.setattr(artifacts, "read_artifact", read_artifact)
    result = asyncio.run(
        pack.operations("operations").dispatch(request, "consume", {"private": True})
    )
    assert result.payload == {"items": 3}
    assert adapter.observations == {
        "record": {"prompt": "SYNTHETIC_PROMPT"},
        "status": {"configured": True},
        "artifact": b"SYNTHETIC_ARTIFACT",
        "cross_task": "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE",
        "record_lookup": "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE",
        "singleton_lookup": "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE",
        "singleton_verb": "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE",
        "artifact_verb": "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE",
    }
    assert not hasattr(adapter.retained_bundle, "__dict__")
    assert "SYNTHETIC" not in repr(adapter.retained_bundle)
    assert "SYNTHETIC" not in repr(adapter.retained_record)
    with pytest.raises(TypeError):
        pickle.dumps(adapter.retained_bundle)
    with pytest.raises(ProtectedOperationError) as expired_bundle:
        adapter.retained_bundle.record("library", "prompt-record", "use")
    assert expired_bundle.value.code == "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE"
    with pytest.raises(ProtectedOperationError) as expired_capability:
        adapter.retained_record.reveal("hp-rec-retained")
    assert expired_capability.value.code == "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE"


def test_artifact_dependency_operation_returns_adapter_supplied_lease(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    opaque_references.clear_opaque_references_for_tests()
    root = tmp_path / "operation-lease-root"
    root.mkdir()
    source_path = root / "frame.png"
    source_path.write_bytes(b"synthetic source")
    adapter = SourceDependencyAdapter(source_path)
    adapter.action = "artifact-lease"
    adapter.operation_lease = artifacts.ArtifactLease(
        f"hp-lease-{'L' * 32}",
        30,
    )
    pack = runtime.install(
        artifact_operation_lease_profile(),
        {
            "mode": ModeAdapter(),
            "records": RecordAdapter(),
            "singletons": SingletonAdapter(),
            "artifacts": ArtifactAdapter(),
            "operation-adapter": adapter,
        },
    )
    token = keystore.initialize_keystore("synthetic operation lease password")[
        "token"
    ]
    request = Request(token)

    async def scenario():
        produced = await pack.operations("operations").dispatch(
            request,
            "produce-source",
            {},
        )
        return await pack.operations("operations").dispatch(
            request,
            "serve-source",
            {},
            references={"source": produced.references[0]["id"]},
        )

    result = asyncio.run(scenario())

    assert result.lease is adapter.operation_lease
    assert result.to_payload()["lease"] == {
        "url": f"/helto_privacy/artifacts/hp-lease-{'L' * 32}",
        "expiresInSeconds": 30,
    }


def test_source_publication_uses_ephemeral_dependencies_and_serializes_transition(
    source_dependency_pack,
):
    pack, adapter, request = source_dependency_pack

    async def scenario():
        produced = await pack.operations("operations").dispatch(
            request,
            "produce-source",
            {},
        )
        reference_id = produced.references[0]["id"]
        adapter.action = "block"
        adapter.started = asyncio.Event()
        adapter.release = asyncio.Event()
        publication = asyncio.create_task(
            pack.operations("operations")
            .source_leases("serve-source")
            .publish(
                reference_id,
                pack.authorization.authorize_request(request, "serve-source"),
            )
        )
        await adapter.started.wait()
        transition_authorization = pack.authorization.authorize_request(
            request,
            "mode.transition",
        )
        with pytest.raises(ModeTransitionError) as blocked:
            mode_runtime.transition_bound_mode(
                pack._installation,
                "privacy-mode",
                "main",
                "private",
                transition_authorization,
                None,
            )
        assert blocked.value.code == "PRIVACY_TRANSITION_IN_PROGRESS"
        adapter.release.set()
        published = await publication
        assert published.to_payload()["lease"]["url"].startswith(
            "/helto_privacy/artifacts/hp-lease-"
        )
        assert adapter.undeclared_code == (
            "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE"
        )
        with pytest.raises(ProtectedOperationError):
            adapter.retained_bundle.singleton("settings")
        with pytest.raises(ProtectedOperationError):
            adapter.retained_singleton.reveal()
        assert mode_runtime._ACTIVE_SCOPE_WORK == {}

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ("cancel", "abort"))
def test_source_publication_failure_expires_dependencies_and_releases_claim(
    source_dependency_pack,
    action,
):
    pack, adapter, request = source_dependency_pack

    async def scenario():
        produced = await pack.operations("operations").dispatch(
            request,
            "produce-source",
            {},
        )
        reference_id = produced.references[0]["id"]
        adapter.action = action
        adapter.started = asyncio.Event()
        adapter.release = asyncio.Event()
        publication = asyncio.create_task(
            pack.operations("operations")
            .source_leases("serve-source")
            .publish(
                reference_id,
                pack.authorization.authorize_request(request, "serve-source"),
            )
        )
        await adapter.started.wait()
        if action == "cancel":
            publication.cancel()
            with pytest.raises(asyncio.CancelledError):
                await publication
        else:
            adapter.release.set()
            with pytest.raises(SyntheticSourceAbort):
                await publication
        with pytest.raises(ProtectedOperationError):
            adapter.retained_bundle.singleton("settings")
        with pytest.raises(ProtectedOperationError):
            adapter.retained_singleton.reveal()
        assert mode_runtime._ACTIVE_SCOPE_WORK == {}

        adapter.action = "success"
        retried = await (
            pack.operations("operations")
            .source_leases("serve-source")
            .publish(
                reference_id,
                pack.authorization.authorize_request(request, "serve-source"),
            )
        )
        assert retried.to_payload()["lease"]["url"].startswith(
            "/helto_privacy/artifacts/hp-lease-"
        )

    asyncio.run(scenario())


def test_module_reflection_cannot_recover_raw_invocation_authority(
    dependency_pack,
    monkeypatch,
):
    pack, _mode, adapter, request = dependency_pack
    monkeypatch.setattr(
        records,
        "reveal_record",
        lambda **_kwargs: SimpleNamespace(value={"prompt": "synthetic"}),
    )
    monkeypatch.setattr(singletons, "singleton_status", lambda **_kwargs: {})

    async def read_artifact(**_kwargs):
        return b"synthetic"

    monkeypatch.setattr(artifacts, "read_artifact", read_artifact)
    asyncio.run(pack.operations("operations").dispatch(request, "consume", {}))
    known_authorization = pack.authorization.authorize_request(request, "consume")
    authorization_fingerprint = known_authorization._session_fingerprint
    forbidden = {
        id(pack): "bound pack",
        id(pack.profile): "profile",
        id(pack._installation): "installation",
        id(pack._installation.adapters): "adapters",
        id(known_authorization): "known authorization",
    }
    found: list[str] = []
    visited: set[int] = set()

    def inspect_reachable(value, depth=0):
        identity = id(value)
        if identity in visited or depth > 10:
            return
        visited.add(identity)
        if identity in forbidden:
            found.append(forbidden[identity])
            return
        if isinstance(value, AuthorizedPrivacyRequest):
            found.append("authorization")
            return
        if isinstance(value, bytes) and value == authorization_fingerprint:
            found.append("authorization fingerprint")
            return
        if inspect.ismodule(value):
            return
        if isinstance(value, Mapping):
            for key, item in tuple(value.items()):
                inspect_reachable(key, depth + 1)
                inspect_reachable(item, depth + 1)
            return
        if isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                inspect_reachable(item, depth + 1)
            return
        if isinstance(value, ReferenceType):
            referenced = value()
            if referenced is not None:
                inspect_reachable(referenced, depth + 1)
            return
        if inspect.isfunction(value):
            for cell in value.__closure__ or ():
                try:
                    inspect_reachable(cell.cell_contents, depth + 1)
                except ValueError:
                    pass
            return
        if inspect.isclass(value):
            inspect_reachable(vars(value), depth + 1)
            return
        fields = getattr(type(value), "__dataclass_fields__", None)
        if fields:
            for name in fields:
                inspect_reachable(getattr(value, name), depth + 1)
        for cls in type(value).__mro__:
            for name, member in vars(cls).items():
                if inspect.ismemberdescriptor(member):
                    try:
                        inspect_reachable(object.__getattribute__(value, name), depth + 1)
                    except (AttributeError, TypeError):
                        pass

    inspect_reachable(vars(operation_dependencies))
    inspect_reachable(adapter.retained_bundle)
    inspect_reachable(adapter.retained_record)
    assert found == []


def test_async_dependency_admission_blocks_transition_and_releases_on_cancel(
    dependency_pack,
    monkeypatch,
):
    pack, _mode, adapter, request = dependency_pack
    adapter.action = "cancel"
    adapter.started = asyncio.Event()
    adapter.release = asyncio.Event()
    monkeypatch.setattr(
        records,
        "reveal_record",
        lambda **_kwargs: SimpleNamespace(value={"prompt": "synthetic"}),
    )
    monkeypatch.setattr(singletons, "singleton_status", lambda **_kwargs: {})
    artifact_started = asyncio.Event()
    artifact_release = asyncio.Event()

    async def read_artifact(**_kwargs):
        artifact_started.set()
        await artifact_release.wait()
        return b"synthetic"

    monkeypatch.setattr(artifacts, "read_artifact", read_artifact)

    async def scenario():
        dispatch = asyncio.create_task(
            pack.operations("operations").dispatch(request, "consume", {})
        )
        await adapter.started.wait()
        adapter.release.set()
        await artifact_started.wait()
        transition_authorization = pack.authorization.authorize_request(
            request,
            "mode.transition",
        )
        with pytest.raises(ModeTransitionError) as blocked:
            mode_runtime.transition_bound_mode(
                pack._installation,
                "privacy-mode",
                "main",
                "private",
                transition_authorization,
                None,
            )
        assert blocked.value.code == "PRIVACY_TRANSITION_IN_PROGRESS"
        dispatch.cancel()
        with pytest.raises(asyncio.CancelledError):
            await dispatch
        assert mode_runtime._ACTIVE_SCOPE_WORK == {}
        with pytest.raises(ProtectedOperationError):
            adapter.retained_bundle.artifact("thumbnail")

    asyncio.run(scenario())


def test_session_lock_invalidates_live_dependency_capability(
    dependency_pack,
    monkeypatch,
):
    pack, _mode, adapter, request = dependency_pack
    monkeypatch.setattr(
        records,
        "reveal_record",
        lambda **_kwargs: SimpleNamespace(value={"prompt": "synthetic"}),
    )
    original = adapter.invoke_with_dependencies

    async def lock_then_invoke(value, references, declaration, dependencies):
        adapter.retained_bundle = dependencies
        capability = dependencies.record("library", "prompt-record", "use")
        keystore.lock_keystore()
        capability.reveal("hp-rec-after-lock")
        return await original(value, references, declaration, dependencies)

    adapter.invoke_with_dependencies = lock_then_invoke
    with pytest.raises(ProtectedOperationError) as expired:
        asyncio.run(pack.operations("operations").dispatch(request, "consume", {}))
    assert expired.value.code == "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE"
    with pytest.raises(ProtectedOperationError):
        adapter.retained_bundle.record("library", "prompt-record", "use")
