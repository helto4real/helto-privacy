"""Immutable consumer privacy profiles and canonical fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, TypeVar


PRIVACY_CONTRACT_V2 = "helto.privacy.v2"
_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MODE_TRANSITION_METHODS = (
    "prepare_mode_transition",
    "commit_mode_transition",
    "rollback_mode_transition",
)


class _Identified(Protocol):
    id: str


_IdentifiedType = TypeVar("_IdentifiedType", bound=_Identified)


class ProfileValidationError(ValueError):
    """A sanitized declaration error safe to expose during startup."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy profile declaration is invalid.")


class ResourceKind(str, Enum):
    """Closed resource vocabulary exposed by the privacy contract suite."""

    MODE = "mode"
    WORKFLOW = "workflow"
    RECORD = "record"
    ARTIFACT = "artifact"
    EXECUTION = "execution"


class FieldLocationKind(str, Enum):
    """Closed product locations shared policy knows how to coordinate."""

    WIDGET = "widget"
    PROPERTY = "property"
    INPUT = "input"
    RECORD = "record"
    BLOB = "blob"


class ArtifactRetention(str, Enum):
    """Shared artifact lifecycle selected by product meaning."""

    DURABLE_ADJUNCT = "durable-adjunct"
    REGENERABLE_CACHE = "regenerable-cache"
    RUN_SCOPED_SPILL = "run-scoped-spill"
    SERVED_TRANSIENT = "served-transient"


@dataclass(frozen=True, slots=True)
class PrivacyScope:
    """A product scope and the adapter that locates its declared mode."""

    id: str
    mode_resource_id: str
    mode_source_adapter: str
    mode_editor_adapter: str | None = None
    parent_id: str | None = None
    floor_scope_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.mode_resource_id)
        _validate_stable_id(self.mode_source_adapter)
        if self.mode_editor_adapter is not None:
            _validate_stable_id(self.mode_editor_adapter)
        if self.parent_id is not None:
            _validate_stable_id(self.parent_id)
        object.__setattr__(
            self,
            "floor_scope_ids",
            _normalized_stable_ids(self.floor_scope_ids, "duplicate_scope_floor"),
        )


@dataclass(frozen=True, slots=True)
class FieldLocation:
    """A non-policy product field location."""

    kind: FieldLocationKind
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, FieldLocationKind):
            raise ProfileValidationError("unknown_field_location")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ProfileValidationError("invalid_field_location")


@dataclass(frozen=True, slots=True)
class ProtectedField:
    """One protected workflow field and its current persisted identity."""

    id: str
    workflow_resource_id: str
    scope_id: str
    state_adapter: str
    browser_adapter: str
    node_types: tuple[str, ...]
    location: FieldLocation
    current_schema: str
    purpose: str
    legacy_reader_ids: tuple[str, ...] = ()
    execution: bool = False

    def __post_init__(self) -> None:
        for value in (
            self.id,
            self.workflow_resource_id,
            self.scope_id,
            self.state_adapter,
            self.browser_adapter,
            self.current_schema,
            self.purpose,
        ):
            _validate_stable_id(value)
        if not isinstance(self.location, FieldLocation):
            raise ProfileValidationError("unknown_field_location")
        object.__setattr__(self, "node_types", _normalized_node_types(self.node_types))
        object.__setattr__(
            self,
            "legacy_reader_ids",
            _normalized_stable_ids(self.legacy_reader_ids, "duplicate_legacy_reader"),
        )
        if not isinstance(self.execution, bool):
            raise ProfileValidationError("invalid_execution_declaration")


@dataclass(frozen=True, slots=True)
class RecordDeclaration:
    """Product facts for one private record kind."""

    id: str
    resource_id: str
    scope_id: str
    current_schema: str
    store_adapter: str
    safe_projection_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (
            self.id,
            self.resource_id,
            self.scope_id,
            self.current_schema,
            self.store_adapter,
        ):
            _validate_stable_id(value)
        fields = _normalized_text_values(
            self.safe_projection_fields,
            "invalid_safe_projection_field",
            "duplicate_safe_projection_field",
        )
        object.__setattr__(self, "safe_projection_fields", fields)


@dataclass(frozen=True, slots=True)
class ArtifactDeclaration:
    """Product facts for one managed privacy artifact kind."""

    id: str
    resource_id: str
    scope_id: str
    purpose: str
    payload_adapter: str
    format_version: int
    retention: ArtifactRetention
    operations: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (
            self.id,
            self.resource_id,
            self.scope_id,
            self.purpose,
            self.payload_adapter,
        ):
            _validate_stable_id(value)
        if (
            not isinstance(self.format_version, int)
            or isinstance(self.format_version, bool)
            or self.format_version < 1
        ):
            raise ProfileValidationError("invalid_artifact_version")
        if not isinstance(self.retention, ArtifactRetention):
            raise ProfileValidationError("unknown_artifact_retention")
        operations = _normalized_stable_ids(self.operations, "duplicate_artifact_operation")
        if not operations:
            raise ProfileValidationError("missing_artifact_operation")
        object.__setattr__(self, "operations", operations)


@dataclass(frozen=True, slots=True)
class ProtectedOperation:
    """A product operation dispatched only after shared authorization."""

    id: str
    resource_id: str
    adapter_slot: str

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.resource_id)
        _validate_stable_id(self.adapter_slot)


@dataclass(frozen=True, slots=True)
class SemanticExecutionProjection:
    """The product projection used by one protected execution resource."""

    id: str
    execution_resource_id: str
    workflow_resource_id: str
    projection_adapter: str
    dispatch_adapter: str

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.execution_resource_id)
        _validate_stable_id(self.workflow_resource_id)
        _validate_stable_id(self.projection_adapter)
        _validate_stable_id(self.dispatch_adapter)


@dataclass(frozen=True, slots=True)
class AdapterSlot:
    """One consumer product adapter required by an immutable profile."""

    id: str
    capability: ResourceKind
    resource_id: str
    node_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.resource_id)
        if not isinstance(self.capability, ResourceKind):
            raise ProfileValidationError("unknown_resource_kind")
        object.__setattr__(
            self,
            "node_types",
            _normalized_text_values(
                self.node_types,
                "invalid_node_type",
                "duplicate_node_type",
            ),
        )


@dataclass(frozen=True, slots=True)
class ProfileResource:
    """A declared privacy resource and the adapter slots that place it."""

    id: str
    kind: ResourceKind
    adapter_slots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        if not isinstance(self.kind, ResourceKind):
            raise ProfileValidationError("unknown_resource_kind")
        object.__setattr__(
            self,
            "adapter_slots",
            _normalized_stable_ids(
                self.adapter_slots,
                "duplicate_adapter_reference",
            ),
        )


@dataclass(frozen=True, slots=True)
class PrivacyProfile:
    """All product facts needed to bind one consumer to the fixed contract."""

    id: str
    distribution: str
    contract: str = PRIVACY_CONTRACT_V2
    resources: tuple[ProfileResource, ...] = ()
    server_adapters: tuple[AdapterSlot, ...] = ()
    browser_adapters: tuple[AdapterSlot, ...] = ()
    scopes: tuple[PrivacyScope, ...] = ()
    protected_fields: tuple[ProtectedField, ...] = ()
    records: tuple[RecordDeclaration, ...] = ()
    artifacts: tuple[ArtifactDeclaration, ...] = ()
    protected_operations: tuple[ProtectedOperation, ...] = ()
    execution_projections: tuple[SemanticExecutionProjection, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.distribution)
        try:
            resources = tuple(self.resources)
            server_adapters = tuple(self.server_adapters)
            browser_adapters = tuple(self.browser_adapters)
            scopes = tuple(self.scopes)
            protected_fields = tuple(self.protected_fields)
            records = tuple(self.records)
            artifacts = tuple(self.artifacts)
            protected_operations = tuple(self.protected_operations)
            execution_projections = tuple(self.execution_projections)
        except TypeError:
            raise ProfileValidationError("invalid_profile_declaration") from None
        if any(not isinstance(item, ProfileResource) for item in resources):
            raise ProfileValidationError("unknown_resource_declaration")
        if any(not isinstance(item, AdapterSlot) for item in server_adapters + browser_adapters):
            raise ProfileValidationError("unknown_adapter_declaration")
        typed_declarations = (
            (scopes, PrivacyScope, "unknown_scope_declaration"),
            (protected_fields, ProtectedField, "unknown_field_declaration"),
            (records, RecordDeclaration, "unknown_record_declaration"),
            (artifacts, ArtifactDeclaration, "unknown_artifact_declaration"),
            (protected_operations, ProtectedOperation, "unknown_operation_declaration"),
            (
                execution_projections,
                SemanticExecutionProjection,
                "unknown_execution_projection",
            ),
        )
        for declarations, expected_type, error_code in typed_declarations:
            if any(not isinstance(item, expected_type) for item in declarations):
                raise ProfileValidationError(error_code)
        object.__setattr__(
            self,
            "resources",
            tuple(sorted(resources, key=lambda item: (item.kind.value, item.id))),
        )
        object.__setattr__(
            self,
            "server_adapters",
            tuple(sorted(server_adapters, key=lambda item: item.id)),
        )
        object.__setattr__(
            self,
            "browser_adapters",
            tuple(sorted(browser_adapters, key=lambda item: item.id)),
        )
        for field_name, declarations in (
            ("scopes", scopes),
            ("protected_fields", protected_fields),
            ("records", records),
            ("artifacts", artifacts),
            ("protected_operations", protected_operations),
            ("execution_projections", execution_projections),
        ):
            object.__setattr__(
                self,
                field_name,
                tuple(sorted(declarations, key=lambda item: item.id)),
            )
        self._validate()

    def _validate(self) -> None:
        if self.contract != PRIVACY_CONTRACT_V2:
            raise ProfileValidationError("contract_mismatch")

        resource_ids = [resource.id for resource in self.resources]
        if len(resource_ids) != len(set(resource_ids)):
            raise ProfileValidationError("duplicate_resource")

        adapters = self.server_adapters + self.browser_adapters
        adapter_ids = [adapter.id for adapter in adapters]
        if len(adapter_ids) != len(set(adapter_ids)):
            raise ProfileValidationError("duplicate_adapter_slot")

        adapter_by_id = {adapter.id: adapter for adapter in adapters}
        resource_by_id = {resource.id: resource for resource in self.resources}
        for resource in self.resources:
            if any(slot_id not in adapter_by_id for slot_id in resource.adapter_slots):
                raise ProfileValidationError("unknown_adapter_slot")

        for adapter in adapters:
            resource = resource_by_id.get(adapter.resource_id)
            if resource is None:
                raise ProfileValidationError("unknown_adapter_resource")
            if adapter.capability is not resource.kind:
                raise ProfileValidationError("adapter_capability_mismatch")
            if adapter.id not in resource.adapter_slots:
                raise ProfileValidationError("unbound_adapter_slot")

        if not self.resources or any(not resource.adapter_slots for resource in self.resources):
            raise ProfileValidationError("partial_profile")

        self._validate_product_facts(resource_by_id, adapter_by_id)

    def _validate_product_facts(
        self,
        resources: dict[str, ProfileResource],
        adapters: dict[str, AdapterSlot],
    ) -> None:
        scopes = _unique_by_id(self.scopes, "duplicate_scope")
        fields = _unique_by_id(self.protected_fields, "duplicate_protected_field")
        records = _unique_by_id(self.records, "duplicate_record_declaration")
        artifacts = _unique_by_id(self.artifacts, "duplicate_artifact_declaration")
        operations = _unique_by_id(self.protected_operations, "duplicate_protected_operation")
        projections = _unique_by_id(
            self.execution_projections,
            "duplicate_execution_projection",
        )
        server_adapter_ids = {adapter.id for adapter in self.server_adapters}
        browser_adapter_ids = {adapter.id for adapter in self.browser_adapters}
        used_server_adapters: set[str] = set()
        used_browser_adapters: set[str] = set()

        for scope in scopes.values():
            resource = _require_resource_kind(
                resources,
                scope.mode_resource_id,
                ResourceKind.MODE,
            )
            _require_adapter_side(
                resource,
                scope.mode_source_adapter,
                server_adapter_ids,
            )
            used_server_adapters.add(scope.mode_source_adapter)
            if scope.mode_editor_adapter is not None:
                _require_adapter_side(
                    resource,
                    scope.mode_editor_adapter,
                    browser_adapter_ids,
                )
                used_browser_adapters.add(scope.mode_editor_adapter)
            for related_scope in (scope.parent_id, *scope.floor_scope_ids):
                if related_scope is not None and related_scope not in scopes:
                    raise ProfileValidationError("unknown_scope_reference")
        _validate_scope_cycles(scopes)

        for protected_field in fields.values():
            resource = _require_resource_kind(
                resources,
                protected_field.workflow_resource_id,
                ResourceKind.WORKFLOW,
            )
            if protected_field.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")
            _require_adapter_side(
                resource,
                protected_field.state_adapter,
                server_adapter_ids,
            )
            _require_adapter_side(
                resource,
                protected_field.browser_adapter,
                browser_adapter_ids,
            )
            used_server_adapters.add(protected_field.state_adapter)
            used_browser_adapters.add(protected_field.browser_adapter)
            browser_node_types = set(adapters[protected_field.browser_adapter].node_types)
            if not set(protected_field.node_types).issubset(browser_node_types):
                raise ProfileValidationError("field_browser_binding_mismatch")

        for record in records.values():
            resource = _require_resource_kind(resources, record.resource_id, ResourceKind.RECORD)
            if record.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")
            _require_adapter_side(resource, record.store_adapter, server_adapter_ids)
            used_server_adapters.add(record.store_adapter)

        for artifact in artifacts.values():
            resource = _require_resource_kind(
                resources,
                artifact.resource_id,
                ResourceKind.ARTIFACT,
            )
            if artifact.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")
            _require_adapter_side(resource, artifact.payload_adapter, server_adapter_ids)
            used_server_adapters.add(artifact.payload_adapter)

        for operation in operations.values():
            resource = resources.get(operation.resource_id)
            if resource is None:
                raise ProfileValidationError("unknown_operation_resource")
            _require_adapter_side(resource, operation.adapter_slot, server_adapter_ids)
            used_server_adapters.add(operation.adapter_slot)

        for projection in projections.values():
            resource = _require_resource_kind(
                resources,
                projection.execution_resource_id,
                ResourceKind.EXECUTION,
            )
            _require_resource_kind(
                resources,
                projection.workflow_resource_id,
                ResourceKind.WORKFLOW,
            )
            _require_adapter_side(
                resource,
                projection.projection_adapter,
                server_adapter_ids,
            )
            _require_adapter_side(
                resource,
                projection.dispatch_adapter,
                server_adapter_ids,
            )
            used_server_adapters.update(
                (projection.projection_adapter, projection.dispatch_adapter)
            )

        facts_by_kind = {
            ResourceKind.MODE: {scope.mode_resource_id for scope in scopes.values()},
            ResourceKind.WORKFLOW: {
                protected_field.workflow_resource_id for protected_field in fields.values()
            },
            ResourceKind.RECORD: {record.resource_id for record in records.values()},
            ResourceKind.ARTIFACT: {artifact.resource_id for artifact in artifacts.values()},
            ResourceKind.EXECUTION: {
                projection.execution_resource_id for projection in projections.values()
            },
        }
        for resource in resources.values():
            if resource.id not in facts_by_kind[resource.kind]:
                raise ProfileValidationError("missing_resource_product_facts")

        if used_server_adapters != server_adapter_ids:
            raise ProfileValidationError("unused_server_adapter")
        if used_browser_adapters != browser_adapter_ids:
            raise ProfileValidationError("unused_browser_adapter")

    @property
    def server_adapter_contracts(self) -> dict[str, tuple[str, ...]]:
        """Fixed method contract derived from typed server-side declarations."""

        contracts: dict[str, set[str]] = {}
        for scope in self.scopes:
            _add_contract(
                contracts,
                scope.mode_source_adapter,
                "read_declared_mode",
                "write_declared_mode",
                *_MODE_TRANSITION_METHODS,
            )
        for field in self.protected_fields:
            _add_contract(
                contracts,
                field.state_adapter,
                "capture",
                "normalize",
                "apply_revealed",
                "clear_plaintext",
                *_MODE_TRANSITION_METHODS,
            )
        for record in self.records:
            _add_contract(
                contracts,
                record.store_adapter,
                "list_ids",
                "read_protected",
                "write_protected",
                "delete",
                *_MODE_TRANSITION_METHODS,
            )
        for artifact in self.artifacts:
            _add_contract(
                contracts,
                artifact.payload_adapter,
                "encode",
                "decode",
                *_MODE_TRANSITION_METHODS,
            )
        for operation in self.protected_operations:
            _add_contract(contracts, operation.adapter_slot, "invoke")
        for projection in self.execution_projections:
            _add_contract(contracts, projection.projection_adapter, "project")
            _add_contract(contracts, projection.dispatch_adapter, "dispatch")
        return {adapter_id: tuple(sorted(methods)) for adapter_id, methods in contracts.items()}

    @property
    def browser_adapter_contracts(self) -> dict[str, tuple[str, ...]]:
        """Fixed method contract derived from typed browser declarations."""

        contracts: dict[str, set[str]] = {}
        for scope in self.scopes:
            if scope.mode_editor_adapter is not None:
                _add_contract(
                    contracts,
                    scope.mode_editor_adapter,
                    "readDeclaredMode",
                    "reconcileNode",
                    "reconcileNodeDefinition",
                    "writeDeclaredMode",
                )
        for field in self.protected_fields:
            _add_contract(
                contracts,
                field.browser_adapter,
                "apply",
                "clear",
                "normalize",
                "reconcileNode",
                "reconcileNodeDefinition",
            )
        return {adapter_id: tuple(sorted(methods)) for adapter_id, methods in contracts.items()}

    @property
    def fingerprint(self) -> str:
        """Return the stable SHA-256 identity shared by Python and the browser."""

        canonical = json.dumps(
            self._canonical_value(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _canonical_value(self) -> dict[str, object]:
        return {
            "id": self.id,
            "distribution": self.distribution,
            "contract": self.contract,
            "resources": [
                {
                    "id": resource.id,
                    "kind": resource.kind.value,
                    "adapterSlots": list(resource.adapter_slots),
                }
                for resource in self.resources
            ],
            "serverAdapters": [_canonical_adapter(slot) for slot in self.server_adapters],
            "browserAdapters": [_canonical_adapter(slot) for slot in self.browser_adapters],
            "scopes": [
                {
                    "id": scope.id,
                    "modeResourceId": scope.mode_resource_id,
                    "modeSourceAdapter": scope.mode_source_adapter,
                    "modeEditorAdapter": scope.mode_editor_adapter,
                    "parentId": scope.parent_id,
                    "floorScopeIds": list(scope.floor_scope_ids),
                }
                for scope in self.scopes
            ],
            "protectedFields": [
                {
                    "id": field.id,
                    "workflowResourceId": field.workflow_resource_id,
                    "scopeId": field.scope_id,
                    "stateAdapter": field.state_adapter,
                    "browserAdapter": field.browser_adapter,
                    "nodeTypes": list(field.node_types),
                    "location": {"kind": field.location.kind.value, "name": field.location.name},
                    "currentSchema": field.current_schema,
                    "purpose": field.purpose,
                    "legacyReaderIds": list(field.legacy_reader_ids),
                    "execution": field.execution,
                }
                for field in self.protected_fields
            ],
            "records": [
                {
                    "id": record.id,
                    "resourceId": record.resource_id,
                    "scopeId": record.scope_id,
                    "currentSchema": record.current_schema,
                    "storeAdapter": record.store_adapter,
                    "safeProjectionFields": list(record.safe_projection_fields),
                }
                for record in self.records
            ],
            "artifacts": [
                {
                    "id": artifact.id,
                    "resourceId": artifact.resource_id,
                    "scopeId": artifact.scope_id,
                    "purpose": artifact.purpose,
                    "payloadAdapter": artifact.payload_adapter,
                    "formatVersion": artifact.format_version,
                    "retention": artifact.retention.value,
                    "operations": list(artifact.operations),
                }
                for artifact in self.artifacts
            ],
            "protectedOperations": [
                {
                    "id": operation.id,
                    "resourceId": operation.resource_id,
                    "adapterSlot": operation.adapter_slot,
                }
                for operation in self.protected_operations
            ],
            "executionProjections": [
                {
                    "id": projection.id,
                    "executionResourceId": projection.execution_resource_id,
                    "workflowResourceId": projection.workflow_resource_id,
                    "projectionAdapter": projection.projection_adapter,
                    "dispatchAdapter": projection.dispatch_adapter,
                }
                for projection in self.execution_projections
            ],
        }


def _canonical_adapter(slot: AdapterSlot) -> dict[str, object]:
    return {
        "id": slot.id,
        "capability": slot.capability.value,
        "resourceId": slot.resource_id,
        "nodeTypes": list(slot.node_types),
    }


def _is_stable_id(value: object) -> bool:
    return isinstance(value, str) and bool(_STABLE_ID.fullmatch(value))


def _validate_stable_id(value: object) -> None:
    if not _is_stable_id(value):
        raise ProfileValidationError("invalid_stable_id")


def _normalized_stable_ids(values: object, duplicate_code: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ProfileValidationError("invalid_stable_ids")
    try:
        normalized = tuple(values)  # type: ignore[arg-type]
    except TypeError:
        raise ProfileValidationError("invalid_stable_ids") from None
    if any(not _is_stable_id(item) for item in normalized):
        raise ProfileValidationError("invalid_stable_id")
    if len(normalized) != len(set(normalized)):
        raise ProfileValidationError(duplicate_code)
    return tuple(sorted(normalized))


def _normalized_node_types(values: object) -> tuple[str, ...]:
    normalized = _normalized_text_values(
        values,
        "invalid_node_type",
        "duplicate_node_type",
    )
    if not normalized:
        raise ProfileValidationError("missing_node_type")
    return normalized


def _normalized_text_values(
    values: object,
    invalid_code: str,
    duplicate_code: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ProfileValidationError(invalid_code)
    try:
        normalized = tuple(values)  # type: ignore[arg-type]
    except TypeError:
        raise ProfileValidationError(invalid_code) from None
    if any(not isinstance(item, str) or not item.strip() for item in normalized):
        raise ProfileValidationError(invalid_code)
    if len(normalized) != len(set(normalized)):
        raise ProfileValidationError(duplicate_code)
    return tuple(sorted(normalized))


def _unique_by_id(
    declarations: tuple[_IdentifiedType, ...],
    error_code: str,
) -> dict[str, _IdentifiedType]:
    by_id = {declaration.id: declaration for declaration in declarations}
    if len(by_id) != len(declarations):
        raise ProfileValidationError(error_code)
    return by_id


def _require_resource_kind(
    resources: dict[str, ProfileResource],
    resource_id: str,
    expected_kind: ResourceKind,
) -> ProfileResource:
    resource = resources.get(resource_id)
    if resource is None or resource.kind is not expected_kind:
        raise ProfileValidationError("resource_kind_mismatch")
    return resource


def _require_adapter_side(
    resource: ProfileResource,
    adapter_id: str,
    allowed_adapter_ids: set[str],
) -> None:
    if adapter_id not in allowed_adapter_ids or adapter_id not in resource.adapter_slots:
        raise ProfileValidationError("resource_adapter_mismatch")


def _add_contract(
    contracts: dict[str, set[str]],
    adapter_id: str,
    *methods: str,
) -> None:
    contracts.setdefault(adapter_id, set()).update(methods)


def _validate_scope_cycles(scopes: dict[str, PrivacyScope]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(scope_id: str) -> None:
        if scope_id in visiting:
            raise ProfileValidationError("scope_cycle")
        if scope_id in visited:
            return
        visiting.add(scope_id)
        scope = scopes[scope_id]
        related = (scope.parent_id, *scope.floor_scope_ids)
        for related_id in related:
            if related_id is not None:
                visit(related_id)
        visiting.remove(scope_id)
        visited.add(scope_id)

    for scope_id in scopes:
        visit(scope_id)
