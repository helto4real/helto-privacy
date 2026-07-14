"""Atomic compiler for immutable consumer privacy profiles."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
import inspect
from threading import RLock
import secrets
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, TypeVar

from .comfy_ui import register_helto_privacy_ui
from .profile import (
    MODE_TRANSITION_PROTOCOL,
    PrivacyProfile,
    ProfileResource,
    ProtectedField,
    ResourceKind,
)


SERVER_BOOT_EPOCH = "hp-boot-" + secrets.token_urlsafe(24)

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

    def authorize_declassification(
        self,
        request,
        scope_id: str,
        target,
        *,
        operation_id: str = "mode.transition",
    ):
        """Issue one scope/target-bound, one-use transition capability."""

        self.require_ready()
        from .guard import authorize_privacy_request
        from .mode import normalize_declared_mode

        return authorize_privacy_request(
            request,
            operation_id,
            pack_id=self.pack_id,
            declassification_scope_id=scope_id,
            declassification_target=normalize_declared_mode(target).value,
        )

    async def dispatch(self, request, scope_id: str, operation_id: str, operation):
        """Authorize and dispatch protected work only through a stable scope."""

        self.require_ready()
        from .guard import PrivacyRouteDispatchError, dispatch_privacy_route
        from .mode import ModePolicyError, ModeTransitionError
        from .mode_runtime import (
            acquire_bound_mode_work_admission,
            release_bound_mode_work_admission,
        )

        async def admitted_operation(authorization):
            try:
                token = acquire_bound_mode_work_admission(
                    self._installation, (scope_id,)
                )
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
            try:
                result = operation(authorization)
                return await result if inspect.isawaitable(result) else result
            finally:
                release_bound_mode_work_admission(token)

        return await dispatch_privacy_route(
            request,
            operation_id,
            admitted_operation,
            pack_id=self.pack_id,
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
class ProtectedOperationHandle(_ResourceHandle):
    """Typed backend projection seam for a declared protected operation."""

    def project(
        self,
        operation_id: str,
        value: object,
        *,
        subject_mode=None,
    ):
        self.readiness.require_ready()
        from .protected_operations import project_protected_operation
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()
        return project_protected_operation(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            operation_id=operation_id,
            value=value,
            subject_mode=subject_mode,
        )

    async def dispatch(
        self,
        request: object,
        operation_id: str,
        input_value: object,
        *,
        references: object = None,
    ):
        self.readiness.require_ready()
        from .protected_operations import dispatch_protected_operation
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()
        return await dispatch_protected_operation(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            request=request,
            operation_id=operation_id,
            input_value=input_value,
            references={} if references is None else references,
        )

    def defer(
        self,
        operation_id: str,
        adapter_result: object,
        *,
        subject_mode,
    ):
        self.readiness.require_ready()
        from .associations import defer_operation_association
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()
        return defer_operation_association(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            operation_id=operation_id,
            adapter_result=adapter_result,
            subject_mode=subject_mode,
        )

    def source_leases(self, operation_id: str):
        self.readiness.require_ready()
        from .artifact_publication import _ProfileBoundSourceLeasePublisher
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()
        declaration = next(
            (
                item
                for item in self._installation.profile.protected_operations
                if item.id == operation_id
                and item.resource_id == self.resource_id
                and item.returns_lease
                and not item.artifact_dependencies
            ),
            None,
        )
        if declaration is None:
            raise UnknownResourceError()
        adapter = self._installation.adapters.get(declaration.adapter_slot)
        has_dependencies = bool(
            declaration.record_dependencies
            or declaration.singleton_dependencies
            or declaration.artifact_dependencies
        )
        bind_method = (
            "bind_source_with_dependencies" if has_dependencies else "bind_source"
        )
        if adapter is None or not callable(getattr(adapter, bind_method, None)):
            raise UnknownResourceError()
        return _ProfileBoundSourceLeasePublisher(
            self._installation,
            declaration,
            adapter,
        )


@dataclass(frozen=True, slots=True)
class SubjectModeHandle:
    pack_id: str
    binding_id: str
    _installation: _Installation = field(repr=False, compare=False)

    @property
    def readiness(self) -> ReadinessHandle:
        return ReadinessHandle(self._installation)

    @property
    def _binding(self):
        binding = next(
            (
                item
                for item in self._installation.profile.subject_mode_bindings
                if item.id == self.binding_id
            ),
            None,
        )
        if binding is None:
            raise UnknownResourceError()
        return binding

    def prepare(
        self,
        subject_id: object,
        declaration: object,
        facts,
        authorization,
    ):
        self.readiness.require_ready()
        from .guard import require_current_authorization
        from .mode_runtime import resolve_bound_declaration
        from .subject_mode import prepare_subject_mode_reference
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()
        require_current_authorization(
            authorization,
            "subject-mode.prepare",
            pack_id=self.pack_id,
        )
        binding = self._binding
        scope = next(
            item
            for item in self._installation.profile.scopes
            if item.id == binding.scope_id
        )
        resolution = resolve_bound_declaration(
            self._installation,
            scope.mode_resource_id,
            scope.id,
            declaration,
            facts,
        )
        return prepare_subject_mode_reference(
            profile=self._installation.profile,
            binding=binding,
            subject_id=subject_id,
            effective=resolution.effective,
            authorization=authorization,
            installation=self._installation,
        )

    def consume(self, reference: object, subject_id: object):
        self.readiness.require_ready()
        from .subject_mode import consume_subject_mode_reference

        return consume_subject_mode_reference(
            reference,
            profile=self._installation.profile,
            binding=self._binding,
            subject_id=subject_id,
        )

    def revoke(self, reference: object, authorization) -> bool:
        self.readiness.require_ready()
        from .subject_mode import revoke_subject_mode_reference

        return revoke_subject_mode_reference(
            reference,
            profile=self._installation.profile,
            binding=self._binding,
            authorization=authorization,
        )


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
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
        )

    def authorize_request(self, record_kind: str, request, operation_id: str):
        self._require_active()
        from .records import record_authorization_for_request

        return record_authorization_for_request(
            installation=self._installation,
            profile=self._installation.profile,
            resource_id=self.resource_id,
            record_kind=record_kind,
            request=request,
            operation_id=operation_id,
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

    def audit_legacy(
        self,
        record_kind: str,
        record_id: str,
        scope_id: str,
        item_id: str,
        binding_id: str,
        authorization,
    ) -> bool:
        self._require_active()
        from .records import audit_legacy_record_source

        return audit_legacy_record_source(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            record_id=record_id,
            scope_id=scope_id,
            item_id=item_id,
            binding_id=binding_id,
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

    def migrate_legacy_reference(
        self,
        record_kind: str,
        migration_id: str,
        legacy_reference: object,
        authorization,
    ):
        self._require_active()
        from .record_relocation import migrate_legacy_record_reference

        return migrate_legacy_record_reference(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            migration_id=migration_id,
            legacy_reference=legacy_reference,
            authorization=authorization,
        )

    def resolve_legacy_reference(
        self,
        record_kind: str,
        migration_id: str,
        legacy_reference: object,
        authorization,
    ):
        self._require_active()
        from .record_relocation import resolve_legacy_record_reference

        return resolve_legacy_record_reference(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            resource_id=self.resource_id,
            record_kind=record_kind,
            migration_id=migration_id,
            legacy_reference=legacy_reference,
            authorization=authorization,
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

    async def reconcile_owner(
        self,
        artifact_kind: str,
        owner_id: str,
        keep=(),
    ) -> int:
        self.readiness.require_ready()
        from .artifacts import reconcile_owner_artifacts

        return await reconcile_owner_artifacts(
            installation=self._installation,
            resource_id=self.resource_id,
            artifact_kind=artifact_kind,
            owner_id=owner_id,
            keep=keep,
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
        authorization=None,
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
        *,
        subject_id: object,
    ):
        self.readiness.require_ready()
        from .execution import prepare_execution

        return prepare_execution(
            installation=self._installation,
            profile=self._installation.profile,
            execution_resource_id=self.resource_id,
            projection_id=projection_id,
            subject_id=subject_id,
            protected_fields=protected_fields,
            authorization=authorization,
        )

    def dispatch(
        self,
        reference: object,
        context: object = None,
        *,
        subject_id: object,
        cache_discriminator: object = None,
    ):
        self.readiness.require_ready()
        from .execution import dispatch_execution

        return dispatch_execution(
            installation=self._installation,
            profile=self._installation.profile,
            adapters=self._installation.adapters,
            execution_resource_id=self.resource_id,
            reference=reference,
            context=context,
            subject_id=subject_id,
            cache_discriminator=cache_discriminator,
        )

    def revoke(self, reference: object, authorization) -> bool:
        self.readiness.require_ready()
        from .execution import revoke_execution_reference

        return revoke_execution_reference(
            reference,
            pack_id=self.pack_id,
            execution_resource_id=self.resource_id,
            authorization=authorization,
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

    def subject_modes(self, binding_id: str) -> SubjectModeHandle:
        if self._installation.status is InstallationStatus.CONFLICT:
            raise PackBlockedError()
        if not any(
            binding.id == binding_id
            for binding in self.profile.subject_mode_bindings
        ):
            raise UnknownResourceError()
        return SubjectModeHandle(self.profile.id, binding_id, self._installation)

    def operations(self, resource_id: str) -> ProtectedOperationHandle:
        if self._installation.status is InstallationStatus.CONFLICT:
            raise PackBlockedError()
        resource = next(
            (item for item in self.profile.resources if item.id == resource_id),
            None,
        )
        if (
            resource is None
            or resource.kind
            in {ResourceKind.RECORD, ResourceKind.SINGLETON, ResourceKind.ARTIFACT}
        ):
            raise UnknownResourceError()
        if not any(
            operation.resource_id == resource_id
            for operation in self.profile.protected_operations
        ):
            raise UnknownResourceError()
        adapters = _adapters_for_resource(self._installation, resource)
        return ProtectedOperationHandle(
            self.profile.id,
            resource.id,
            self._installation,
            adapters,
        )

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
_SWEPT_MODE_STATE_PATHS: set[str] = set()
_SWEPT_EXTERNAL_OPERATION_STATE_PATHS: set[str] = set()


def install(
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
) -> BoundPrivacyPack:
    """Atomically validate, bind, and install one complete privacy profile."""

    from .migration import require_registered_readers

    require_registered_readers(profile)
    bound_adapters = _validate_adapter_bindings(profile, adapters)
    with _LOCK:
        from .mode_state import mode_state_path, sweep_all_unreferenced_mode_journals

        mode_path = str(mode_state_path().resolve())
        if not _INSTALLATIONS and mode_path not in _SWEPT_MODE_STATE_PATHS:
            sweep_all_unreferenced_mode_journals()
            _SWEPT_MODE_STATE_PATHS.add(mode_path)
        from .external_operation_state import (
            external_operation_state_path,
            sweep_unreferenced_external_operation_journals,
        )

        external_operation_path = str(external_operation_state_path().resolve())
        if (
            not _INSTALLATIONS
            and external_operation_path
            not in _SWEPT_EXTERNAL_OPERATION_STATE_PATHS
        ):
            sweep_unreferenced_external_operation_journals()
            _SWEPT_EXTERNAL_OPERATION_STATE_PATHS.add(external_operation_path)
        if profile.artifacts:
            from .artifacts import initialize_artifact_service

            initialize_artifact_service(profile)
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
                from .subject_mode import invalidate_subject_mode_profile
                from .associations import invalidate_association_session
                from .opaque_references import invalidate_opaque_reference_session

                invalidate_subject_mode_profile(profile.id)
                invalidate_association_session("profile-conflict")
                invalidate_opaque_reference_session("profile-conflict")
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
            "modeTransitionProtocol": MODE_TRANSITION_PROTOCOL,
            "serverBootEpoch": SERVER_BOOT_EPOCH,
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
                    "subjectModeBindingId": projection.subject_mode_binding_id,
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
                    "currentSchema": singleton.current_schema,
                    "purpose": singleton.purpose,
                    "storeAdapter": singleton.store_adapter,
                    "payloadKind": singleton.payload_kind.value,
                    "legacyReaderIds": list(singleton.legacy_reader_ids),
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
                    "payloadMode": artifact.payload_mode.value,
                    "streamContract": (
                        {
                            "codecSchema": artifact.stream_contract.codec_schema,
                            "codecVersion": artifact.stream_contract.codec_version,
                            "maxPlaintextBytes": artifact.stream_contract.max_plaintext_bytes,
                            "maxOwnerPlaintextBytes": artifact.stream_contract.max_owner_plaintext_bytes,
                            "decodedOutput": artifact.stream_contract.decoded_output.value,
                            "maxMaterializedOutputBytes": (
                                artifact.stream_contract.max_materialized_output_bytes
                            ),
                        }
                        if artifact.stream_contract is not None
                        else None
                    ),
                }
                for artifact in profile.artifacts
            ],
            "protectedOperations": [
                _protected_operation_attestation(operation)
                for operation in profile.protected_operations
            ],
            "subjectModeBindings": [
                {
                    "id": binding.id,
                    "scopeId": binding.scope_id,
                    "inputName": binding.input_name,
                    "nodeTypes": list(binding.node_types),
                }
                for binding in profile.subject_mode_bindings
            ],
        }
    if profile.record_reference_migrations:
        result["recordReferenceMigrations"] = [
            {
                "id": migration.id,
                "resourceId": migration.resource_id,
                "recordKind": migration.record_kind,
                "legacyBindingId": migration.legacy_binding_id,
            }
            for migration in profile.record_reference_migrations
        ]
    if profile.opaque_reference_kinds:
        result["opaqueReferenceKinds"] = [
            {
                "id": item.id,
                "resourceId": item.resource_id,
                "scopeId": item.scope_id,
            }
            for item in profile.opaque_reference_kinds
        ]
    if profile.safe_payload_projections:
        result["safePayloadProjections"] = [
            {
                "id": item.id,
                "operationId": item.operation_id,
                "schema": item.schema,
                "purpose": item.purpose,
                "safeLeaves": [
                    {"path": leaf.path, "kind": leaf.kind.value}
                    for leaf in item.safe_leaves
                ],
            }
            for item in profile.safe_payload_projections
        ]
    from .suite_runtime import process_suite_status_payload

    return {**result, **process_suite_status_payload()}


def _protected_operation_attestation(operation) -> dict[str, object]:
    value = {
        "id": operation.id,
        "resourceId": operation.resource_id,
        "route": operation.route,
        "method": operation.method,
        "scopeId": operation.scope_id,
        "subjectModeBindingId": operation.subject_mode_binding_id,
        "sensitiveFields": [
            {"path": field.path, "class": field.field_class.value}
            for field in operation.sensitive_fields
        ],
        "safeProjection": [
            {"path": field.path, "kind": field.kind.value}
            for field in operation.safe_projection
        ],
    }
    if operation.reference_inputs or operation.reference_outputs or operation.returns_lease:
        value.update(
            {
                "referenceInputs": [
                    {
                        "name": item.name,
                        "referenceKindId": item.reference_kind_id,
                        "revokeOnSuccess": item.revoke_on_success,
                    }
                    for item in operation.reference_inputs
                ],
                "referenceOutputs": [
                    {
                        "referenceKindId": item.reference_kind_id,
                        "minimum": item.minimum,
                        "maximum": item.maximum,
                    }
                    for item in operation.reference_outputs
                ],
                "returnsLease": operation.returns_lease,
            }
        )
    if operation.safe_payload_projection_id is not None or operation.deferred_ui:
        value.update(
            {
                "safePayloadProjectionId": operation.safe_payload_projection_id,
                "deferredUi": operation.deferred_ui,
            }
        )
    if operation.record_dependencies:
        value["recordDependencies"] = [
            {
                "resourceId": item.resource_id,
                "recordKind": item.record_kind,
                "operation": item.operation,
            }
            for item in operation.record_dependencies
        ]
    if operation.singleton_dependencies:
        value["singletonDependencies"] = [
            {
                "singletonId": item.singleton_id,
                "verbs": list(item.verbs),
            }
            for item in operation.singleton_dependencies
        ]
    if operation.artifact_dependencies:
        value["artifactDependencies"] = [
            {
                "artifactKind": item.artifact_kind,
                "verbs": list(item.verbs),
            }
            for item in operation.artifact_dependencies
        ]
    return value


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


def submission_profile_snapshot() -> tuple[tuple[PrivacyProfile, bool], ...]:
    """Return immutable declarations and generic readiness for pre-route checks."""

    with _LOCK:
        if any(
            installation.status is InstallationStatus.CONFLICT
            for installation in _INSTALLATIONS.values()
        ):
            raise ProfileConflictError("profile_registry_conflict")
        return tuple(
            (installation.profile, installation.status is InstallationStatus.READY)
            for installation in sorted(
                _INSTALLATIONS.values(),
                key=lambda item: item.profile.id,
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
