"""Atomic compiler for immutable consumer privacy profiles."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, TypeVar

from .comfy_ui import register_helto_privacy_ui
from .profile import PrivacyProfile, ProfileResource, ProtectedField, ResourceKind

if TYPE_CHECKING:
    from .suite import ProfileIdentity


class PrivacyInstallationError(RuntimeError):
    """A stable, product-data-free installation failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class AdapterBindingError(PrivacyInstallationError):
    def __init__(self, code: str) -> None:
        super().__init__(code, "Privacy profile adapters are incomplete or invalid.")


class ProfileConflictError(PrivacyInstallationError):
    def __init__(self, code: str) -> None:
        super().__init__(code, "Conflicting privacy profile installation blocked.")


class PackBlockedError(PrivacyInstallationError):
    def __init__(self, code: str = "privacy_pack_blocked") -> None:
        super().__init__(code, "Privacy operations are blocked until installation is repaired.")


class UnknownResourceError(PrivacyInstallationError):
    def __init__(self) -> None:
        super().__init__("unknown_resource", "Requested privacy resource is not declared.")


class InstallationStatus(str, Enum):
    WAITING_FOR_PROMPT_SERVER = "waiting_for_prompt_server"
    READY = "ready"
    CONFLICT = "conflict"


@dataclass(slots=True)
class _Installation:
    profile: PrivacyProfile
    adapters: Mapping[str, object] = field(repr=False)
    status: InstallationStatus = InstallationStatus.WAITING_FOR_PROMPT_SERVER
    pack: BoundPrivacyPack | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ReadinessHandle:
    """Read-only installation readiness; it cannot reveal product data."""

    _installation: _Installation = field(repr=False, compare=False)

    @property
    def state(self) -> str:
        return self._installation.status.value

    def require_ready(self) -> None:
        if self.state != "ready":
            raise PackBlockedError(f"privacy_pack_{self.state}")


@dataclass(frozen=True, slots=True)
class AuthorizationHandle:
    """Typed authorization seam without credentials or token access."""

    _installation: _Installation = field(repr=False, compare=False)

    @property
    def pack_id(self) -> str:
        return self._installation.profile.id

    def require_ready(self) -> None:
        ReadinessHandle(self._installation).require_ready()
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()

    def authorize_request(self, request, operation_id: str):
        """Issue one pack-bound authorization capability."""

        self.require_ready()
        from .guard import authorize_privacy_request

        return authorize_privacy_request(
            request,
            operation_id,
            pack_id=self.pack_id,
        )

    def authorize_declassification(self, request, scope_id: str, target):
        """Issue one scope/target-bound, one-use transition capability."""

        self.require_ready()
        from .guard import authorize_privacy_request
        from .mode import normalize_declared_mode

        return authorize_privacy_request(
            request,
            "mode.transition",
            pack_id=self.pack_id,
            declassification_scope_id=scope_id,
            declassification_target=normalize_declared_mode(target).value,
        )

    async def dispatch(self, request, scope_id: str, operation_id: str, operation):
        """Authorize and dispatch protected work only through a stable scope."""

        self.require_ready()
        from .guard import PrivacyRouteDispatchError, dispatch_privacy_route
        from .mode import ModePolicyError, ModeTransitionError
        from .mode_runtime import require_stable_bound_scope

        def require_stable(_authorization) -> None:
            try:
                require_stable_bound_scope(self._installation, scope_id)
            except ModeTransitionError as exc:
                raise PrivacyRouteDispatchError(exc.code, 409) from None
            except ModePolicyError as exc:
                if exc.code == "unknown_mode_scope":
                    raise PrivacyRouteDispatchError(
                        "PRIVACY_SCOPE_INVALID",
                        400,
                    ) from None
                raise PrivacyRouteDispatchError(
                    "PRIVACY_MODE_STATE_UNAVAILABLE",
                    409,
                ) from None

        return await dispatch_privacy_route(
            request,
            operation_id,
            operation,
            pack_id=self.pack_id,
            before_dispatch=require_stable,
        )


@dataclass(frozen=True, slots=True)
class _ResourceHandle:
    pack_id: str
    resource_id: str
    _installation: _Installation = field(repr=False, compare=False)
    _adapters: Mapping[str, object] = field(repr=False, compare=False)

    @property
    def readiness(self) -> ReadinessHandle:
        return ReadinessHandle(self._installation)


@dataclass(frozen=True, slots=True)
class ModeHandle(_ResourceHandle):
    def resolve(self, scope_id: str, facts=None):
        from .mode_runtime import resolve_bound_mode

        return resolve_bound_mode(
            self._installation,
            self.resource_id,
            scope_id,
            facts,
        )

    def resolve_declaration(
        self,
        scope_id: str,
        declaration: object,
        facts=None,
    ):
        from .mode_runtime import resolve_bound_declaration

        return resolve_bound_declaration(
            self._installation,
            self.resource_id,
            scope_id,
            declaration,
            facts,
        )

    def transition(
        self,
        scope_id: str,
        target,
        authorization,
        facts=None,
    ):
        self.readiness.require_ready()
        from .mode_runtime import transition_bound_mode

        return transition_bound_mode(
            self._installation,
            self.resource_id,
            scope_id,
            target,
            authorization,
            facts,
        )


@dataclass(frozen=True, slots=True)
class WorkflowHandle(_ResourceHandle):
    def reveal(
        self,
        field_id: str,
        protected_value: object,
        authorization,
    ):
        self.readiness.require_ready()
        from .mode_runtime import require_stable_bound_scope
        from .snapshot import reveal_field_value

        field_declaration, _state_adapter = self._snapshot_field(field_id)
        require_stable_bound_scope(self._installation, field_declaration.scope_id)
        return reveal_field_value(
            pack_id=self.pack_id,
            field_declaration=field_declaration,
            protected_value=protected_value,
            authorization=authorization,
        )

    def inspect_disposition(
        self,
        field_id: str,
        protected_value: object,
        authorization,
    ):
        from .snapshot import inspect_field_disposition

        field_declaration, state_adapter = self._snapshot_field(field_id)
        return inspect_field_disposition(
            pack_id=self.pack_id,
            profile=self._installation.profile,
            field_declaration=field_declaration,
            state_adapter=state_adapter,
            protected_value=protected_value,
            authorization=authorization,
        )

    def protect(self, field_id: str, value: object, authorization):
        self.readiness.require_ready()
        from .snapshot import protect_field_value

        field_declaration, state_adapter = self._snapshot_field(field_id)
        return protect_field_value(
            pack_id=self.pack_id,
            field_declaration=field_declaration,
            state_adapter=state_adapter,
            value=value,
            authorization=authorization,
        )

    def protect_runtime(self, field_id: str, value: object):
        """Protect backend-produced state without accepting a reveal capability."""

        self.readiness.require_ready()
        from .mode_runtime import require_stable_bound_scope
        from .snapshot import protect_runtime_field_value

        field_declaration, state_adapter = self._snapshot_field(field_id)
        require_stable_bound_scope(self._installation, field_declaration.scope_id)
        return protect_runtime_field_value(
            field_declaration=field_declaration,
            state_adapter=state_adapter,
            value=value,
        )

    def _snapshot_field(self, field_id: str):
        from .snapshot import SnapshotError

        field_declaration = _declared_snapshot_field(
            self._installation.profile,
            field_id,
            workflow_resource_id=self.resource_id,
        )
        state_adapter = self._adapters.get(field_declaration.state_adapter)
        if state_adapter is None:
            raise SnapshotError("PRIVACY_SNAPSHOT_ADAPTER_INVALID")
        return field_declaration, state_adapter


@dataclass(frozen=True, slots=True)
class RecordHandle(_ResourceHandle):
    def _require_active(self) -> None:
        self.readiness.require_ready()
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()

    def list_shells(self, record_kind: str):
        self._require_active()
        from .records import list_record_shells

        return list_record_shells(
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
        )

    def reveal(
        self,
        record_kind: str,
        record_id: str,
        operation: str,
        authorization,
    ):
        self._require_active()
        from .records import reveal_record

        return reveal_record(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            record_id=record_id,
            operation=operation,
            authorization=authorization,
        )

    def protect(self, record_kind: str, value: object, authorization):
        self._require_active()
        from .records import protect_record_value

        return protect_record_value(
            installation=self._installation,
            profile=self._installation.profile,
            resource_id=self.resource_id,
            record_kind=record_kind,
            value=value,
            authorization=authorization,
        )

    def mutate(
        self,
        record_kind: str,
        operation: str,
        value: object,
        authorization,
        *,
        record_id: str | None = None,
    ):
        self._require_active()
        from .records import mutate_record

        return mutate_record(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            operation=operation,
            value=value,
            authorization=authorization,
            record_id=record_id,
        )

    def delete(self, record_kind: str, record_id: str, confirmation):
        self._require_active()
        from .records import delete_record

        return delete_record(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            record_id=record_id,
            confirmation=confirmation,
        )

    def replace(
        self,
        record_kind: str,
        record_id: str,
        protected_value: object,
        confirmation,
    ):
        self._require_active()
        from .records import replace_record

        return replace_record(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            record_id=record_id,
            protected_value=protected_value,
            confirmation=confirmation,
        )


@dataclass(frozen=True, slots=True)
class SingletonHandle(_ResourceHandle):
    """Typed façade for one resource containing protected singleton values."""

    def _require_active(self) -> None:
        self.readiness.require_ready()
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()

    def status(self, singleton_id: str):
        self._require_active()
        from .singletons import singleton_status

        return singleton_status(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
        )

    def reveal_field(self, singleton_id: str, authorization):
        self._require_active()
        from .singletons import reveal_singleton_field

        return reveal_singleton_field(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            authorization=authorization,
        )

    def reveal_blob(self, singleton_id: str, authorization):
        self._require_active()
        from .singletons import reveal_singleton_blob

        return reveal_singleton_blob(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            authorization=authorization,
        )

    def protect_field(self, singleton_id: str, value: object, authorization):
        """Protect a field without committing it outside a larger transaction."""

        self._require_active()
        from .singletons import protect_singleton_field

        return protect_singleton_field(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            value=value,
            authorization=authorization,
        )

    def protect_blob(self, singleton_id: str, value: object, authorization):
        """Protect a blob without committing it outside a larger transaction."""

        self._require_active()
        from .singletons import protect_singleton_blob

        return protect_singleton_blob(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            value=value,
            authorization=authorization,
        )

    def replace_field(
        self,
        singleton_id: str,
        value: object,
        expected_revision: int,
        authorization,
    ):
        self._require_active()
        from .singletons import replace_singleton_field

        return replace_singleton_field(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            value=value,
            expected_revision=expected_revision,
            authorization=authorization,
        )

    def replace_blob(
        self,
        singleton_id: str,
        value: object,
        expected_revision: int,
        authorization,
    ):
        self._require_active()
        from .singletons import replace_singleton_blob

        return replace_singleton_blob(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            value=value,
            expected_revision=expected_revision,
            authorization=authorization,
        )

    def delete(self, singleton_id: str, expected_revision: int, authorization):
        self._require_active()
        from .singletons import delete_singleton

        return delete_singleton(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            singleton_id=singleton_id,
            expected_revision=expected_revision,
            authorization=authorization,
        )


@dataclass(frozen=True, slots=True)
class ArtifactHandle(_ResourceHandle):
    async def write(self, artifact_kind: str, owner_id: str, value: object):
        self.readiness.require_ready()
        from .artifacts import write_artifact

        return await write_artifact(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            artifact_kind=artifact_kind,
            owner_id=owner_id,
            value=value,
        )

    async def read(self, artifact_kind: str, reference: object):
        self.readiness.require_ready()
        from .artifacts import read_artifact

        return await read_artifact(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            artifact_kind=artifact_kind,
            reference=reference,
        )

    def run(self, owner_id: str | None = None):
        self.readiness.require_ready()
        from .artifacts import ArtifactRun

        return ArtifactRun(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            owner_id=owner_id,
        )

    async def retire(self, artifact_kind: str, reference: object) -> int:
        self.readiness.require_ready()
        from .artifacts import retire_artifact

        return await retire_artifact(
            profile=self._installation.profile,
            resource_id=self.resource_id,
            artifact_kind=artifact_kind,
            reference=reference,
        )

    async def retire_group(
        self,
        artifacts: tuple[tuple[str, object], ...] | list[tuple[str, object]],
    ) -> int:
        self.readiness.require_ready()
        from .artifacts import retire_artifact_group

        return await retire_artifact_group(
            profile=self._installation.profile,
            resource_id=self.resource_id,
            artifacts=artifacts,
        )

    async def release_owner(self, owner_id: str) -> int:
        self.readiness.require_ready()
        from .artifacts import release_owner_artifacts

        return await release_owner_artifacts(
            profile=self._installation.profile,
            resource_id=self.resource_id,
            owner_id=owner_id,
        )

    async def sweep(self):
        self.readiness.require_ready()
        from .artifacts import sweep_artifacts

        return await sweep_artifacts()

    async def lease(
        self,
        artifact_kind: str,
        reference: object,
        operation: str,
        authorization,
    ):
        self.readiness.require_ready()
        from .artifacts import issue_artifact_lease

        return await issue_artifact_lease(
            installation=self._installation,
            profile=self._installation.profile,
            resource_id=self.resource_id,
            artifact_kind=artifact_kind,
            reference=reference,
            operation=operation,
            authorization=authorization,
        )

    def revoke(self, lease_id: str) -> bool:
        self.readiness.require_ready()
        from .artifacts import revoke_artifact_lease

        return revoke_artifact_lease(lease_id)


@dataclass(frozen=True, slots=True)
class ExecutionHandle(_ResourceHandle):
    def prepare(
        self,
        projection_id: str,
        protected_fields: Mapping[str, object],
        authorization,
    ):
        self.readiness.require_ready()
        from .execution import prepare_execution

        return prepare_execution(
            installation=self._installation,
            profile=self._installation.profile,
            execution_resource_id=self.resource_id,
            projection_id=projection_id,
            protected_fields=protected_fields,
            authorization=authorization,
        )

    def dispatch(self, reference: object, context: object = None):
        self.readiness.require_ready()
        from .execution import dispatch_execution

        return dispatch_execution(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            execution_resource_id=self.resource_id,
            reference=reference,
            context=context,
        )

    def cache_store(self, cache_identity: str, value: object) -> None:
        self.readiness.require_ready()
        from .execution import cache_execution_result

        cache_execution_result(
            pack_id=self.pack_id,
            execution_resource_id=self.resource_id,
            cache_identity=cache_identity,
            value=value,
        )

    def cache_load(self, cache_identity: str) -> object | None:
        self.readiness.require_ready()
        from .execution import load_cached_execution_result

        return load_cached_execution_result(
            pack_id=self.pack_id,
            execution_resource_id=self.resource_id,
            cache_identity=cache_identity,
        )


_Handle = TypeVar("_Handle", bound=_ResourceHandle)


@dataclass(frozen=True, slots=True)
class BoundPrivacyPack:
    """Immutable typed façade produced only by a complete installation."""

    _installation: _Installation = field(repr=False, compare=False)

    @property
    def profile(self) -> PrivacyProfile:
        return self._installation.profile

    @property
    def fingerprint(self) -> str:
        return self.profile.fingerprint

    @property
    def readiness(self) -> ReadinessHandle:
        return ReadinessHandle(self._installation)

    @property
    def authorization(self) -> AuthorizationHandle:
        return AuthorizationHandle(self._installation)

    @property
    def migration(self):
        """Return the shared pack-bound legacy migration capability."""

        from .migration import MigrationHandle

        return MigrationHandle(self.profile)

    def mode(self, resource_id: str) -> ModeHandle:
        return self._resource(resource_id, ResourceKind.MODE, ModeHandle)

    def workflow(self, resource_id: str) -> WorkflowHandle:
        return self._resource(resource_id, ResourceKind.WORKFLOW, WorkflowHandle)

    def snapshot_field(self, field_id: str) -> tuple[WorkflowHandle, ProtectedField]:
        """Resolve one protected field and its declared workflow handle."""

        field_declaration = _declared_snapshot_field(self.profile, field_id)
        return self.workflow(field_declaration.workflow_resource_id), field_declaration

    def records(self, resource_id: str) -> RecordHandle:
        return self._resource(resource_id, ResourceKind.RECORD, RecordHandle)

    def singletons(self, resource_id: str) -> SingletonHandle:
        return self._resource(
            resource_id,
            ResourceKind.SINGLETON,
            SingletonHandle,
        )

    def artifacts(self, resource_id: str) -> ArtifactHandle:
        return self._resource(resource_id, ResourceKind.ARTIFACT, ArtifactHandle)

    def execution(self, resource_id: str) -> ExecutionHandle:
        return self._resource(resource_id, ResourceKind.EXECUTION, ExecutionHandle)

    def _resource(
        self,
        resource_id: str,
        expected_kind: ResourceKind,
        handle_type: type[_Handle],
    ) -> _Handle:
        if self._installation.status is InstallationStatus.CONFLICT:
            raise PackBlockedError()
        resource = next(
            (
                item
                for item in self.profile.resources
                if item.id == resource_id and item.kind is expected_kind
            ),
            None,
        )
        if resource is None:
            raise UnknownResourceError()
        adapters = _adapters_for_resource(self._installation, resource)
        return handle_type(self.profile.id, resource.id, self._installation, adapters)


def _declared_snapshot_field(
    profile: PrivacyProfile,
    field_id: str,
    *,
    workflow_resource_id: str | None = None,
) -> ProtectedField:
    from .snapshot import SnapshotError

    field_declaration = next(
        (
            field
            for field in profile.protected_fields
            if field.id == field_id
            and (
                workflow_resource_id is None
                or field.workflow_resource_id == workflow_resource_id
            )
        ),
        None,
    )
    if field_declaration is None:
        raise SnapshotError("PRIVACY_SNAPSHOT_FIELD_INVALID")
    return field_declaration


_LOCK = RLock()
_INSTALLATIONS: dict[str, _Installation] = {}


def install(
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
) -> BoundPrivacyPack:
    """Atomically validate, bind, and install one complete privacy profile."""

    from .migration import require_registered_readers

    require_registered_readers(profile)
    bound_adapters = _validate_adapter_bindings(profile, adapters)
    if profile.artifacts:
        from .artifacts import initialize_artifact_service

        initialize_artifact_service(profile)
    with _LOCK:
        existing = _INSTALLATIONS.get(profile.id)
        if existing is not None:
            if existing.status is InstallationStatus.CONFLICT:
                raise ProfileConflictError("profile_installation_blocked")
            if existing.profile.fingerprint != profile.fingerprint:
                existing.status = InstallationStatus.CONFLICT
                from .artifacts import invalidate_artifact_profile
                from .execution import invalidate_execution_profile

                invalidate_artifact_profile(profile.id)
                invalidate_execution_profile(profile.id)
                raise ProfileConflictError("profile_fingerprint_conflict")
            if existing.pack is None:  # Defensive invariant; never expose a partial pack.
                existing.status = InstallationStatus.CONFLICT
                raise ProfileConflictError("incomplete_installation")
            return existing.pack

        installation = _Installation(
            profile=profile,
            adapters=MappingProxyType(bound_adapters),
        )
        pack = BoundPrivacyPack(installation)
        installation.pack = pack
        _INSTALLATIONS[profile.id] = installation

    reconcile_prompt_server()
    return pack


def reconcile_prompt_server(prompt_server: Any = None) -> bool:
    """Attach shared routes when PromptServer exists and reconcile all packs."""

    try:
        registered = register_helto_privacy_ui(prompt_server=prompt_server)
    except Exception:  # noqa: BLE001 - optional host timing must not create a partial install.
        return False
    if not registered:
        return False
    with _LOCK:
        for installation in _INSTALLATIONS.values():
            if installation.status is not InstallationStatus.CONFLICT:
                installation.status = InstallationStatus.READY
    return True


def profile_attestation(pack_id: str) -> dict[str, object]:
    """Return only safe declaration identity for browser attestation."""

    with _LOCK:
        installation = _INSTALLATIONS.get(pack_id)
        if installation is None:
            raise PackBlockedError("privacy_pack_missing")
        profile = installation.profile
        result = {
            "id": profile.id,
            "distribution": profile.distribution,
            "contract": profile.contract,
            "fingerprint": profile.fingerprint,
            "status": installation.status.value,
            "requiredBrowserAdapters": [
                {
                    "id": slot.id,
                    "nodeTypes": list(slot.node_types),
                    "methods": list(profile.browser_adapter_contracts[slot.id]),
                }
                for slot in profile.browser_adapters
            ],
            "resources": [
                {"id": resource.id, "kind": resource.kind.value}
                for resource in profile.resources
            ],
            "modeScopes": [
                {
                    "id": scope.id,
                    "modeResourceId": scope.mode_resource_id,
                    "modeEditorAdapter": scope.mode_editor_adapter,
                }
                for scope in profile.scopes
            ],
            "protectedFields": [
                field.contract_payload(browser=True)
                for field in profile.protected_fields
            ],
            "legacyBindings": [
                {
                    "id": binding.id,
                    "readerId": binding.reader_id,
                    "resourceId": binding.resource_id,
                    "locationKind": binding.location_kind.value,
                    "locationId": binding.location_id,
                }
                for binding in profile.legacy_bindings
            ],
            "legacyKeyImports": [
                {
                    "id": key_import.id,
                    "importId": key_import.import_id,
                    "resourceId": key_import.resource_id,
                    "locationKind": key_import.location_kind.value,
                    "locationId": key_import.location_id,
                    "sourceFormat": key_import.source_format.value,
                }
                for key_import in profile.legacy_key_imports
            ],
            "executionProjections": [
                {
                    "id": projection.id,
                    "executionResourceId": projection.execution_resource_id,
                    "workflowResourceId": projection.workflow_resource_id,
                    "inputName": projection.input_name,
                }
                for projection in profile.execution_projections
            ],
            "records": [
                {
                    "id": record.id,
                    "resourceId": record.resource_id,
                    "scopeId": record.scope_id,
                    "revealOperations": list(record.reveal_operations),
                    "mutationOperations": list(record.mutation_operations),
                    "safeProjection": list(record.safe_projection),
                    "fixedPrivateLabel": record.fixed_private_label,
                }
                for record in profile.records
            ],
            "singletons": [
                {
                    "id": singleton.id,
                    "resourceId": singleton.resource_id,
                    "scopeId": singleton.scope_id,
                    "payloadKind": singleton.payload_kind.value,
                }
                for singleton in profile.singletons
            ],
            "artifacts": [
                {
                    "id": artifact.id,
                    "resourceId": artifact.resource_id,
                    "scopeId": artifact.scope_id,
                    "retention": artifact.retention.value,
                    "operations": list(artifact.operations),
                    "mediaType": artifact.media_type,
                }
                for artifact in profile.artifacts
            ],
            "protectedOperations": [
                {
                    "id": operation.id,
                    "resourceId": operation.resource_id,
                    "route": operation.route,
                    "method": operation.method,
                }
                for operation in profile.protected_operations
            ],
        }
    from .suite_runtime import process_suite_status_payload

    return {**result, **process_suite_status_payload()}


def bound_privacy_pack(pack_id: str) -> BoundPrivacyPack:
    """Return an installed pack without exposing the mutable registry entry."""

    with _LOCK:
        installation = _INSTALLATIONS.get(pack_id)
        if (
            installation is None
            or installation.pack is None
            or installation.status is InstallationStatus.CONFLICT
        ):
            raise PackBlockedError("privacy_pack_missing")
        return installation.pack


def installed_profile_identities() -> tuple[ProfileIdentity, ...]:
    """Measure safe identities from the live immutable profile registry."""

    from .suite import ProfileIdentity

    with _LOCK:
        if any(
            installation.status is InstallationStatus.CONFLICT
            for installation in _INSTALLATIONS.values()
        ):
            raise ProfileConflictError("profile_registry_conflict")
        return tuple(
            sorted(
                (
                    ProfileIdentity(
                        id=installation.profile.id,
                        distribution=installation.profile.distribution,
                        fingerprint=installation.profile.fingerprint,
                    )
                    for installation in _INSTALLATIONS.values()
                ),
                key=lambda identity: identity.id,
            )
        )


def _validate_adapter_bindings(
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
) -> dict[str, object]:
    try:
        supplied = dict(adapters)
    except Exception:  # noqa: BLE001 - consumer mappings must fail with sanitized diagnostics.
        raise AdapterBindingError("invalid_adapters") from None

    expected = {slot.id for slot in profile.server_adapters}
    supplied_ids = set(supplied)
    if expected - supplied_ids or any(supplied.get(slot_id) is None for slot_id in expected):
        raise AdapterBindingError("missing_adapter")
    if supplied_ids - expected:
        raise AdapterBindingError("unknown_adapter")
    for adapter_id, methods in profile.server_adapter_contracts.items():
        adapter = supplied[adapter_id]
        if any(not callable(getattr(adapter, method, None)) for method in methods):
            raise AdapterBindingError("adapter_contract_mismatch")
    return {slot_id: supplied[slot_id] for slot_id in sorted(expected)}


def _adapters_for_resource(
    installation: _Installation,
    resource: ProfileResource,
) -> Mapping[str, object]:
    server_slot_ids = {slot.id for slot in installation.profile.server_adapters}
    matches = [slot_id for slot_id in resource.adapter_slots if slot_id in server_slot_ids]
    return MappingProxyType(
        {slot_id: installation.adapters[slot_id] for slot_id in matches}
    )
