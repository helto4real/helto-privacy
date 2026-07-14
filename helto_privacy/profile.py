"""Immutable consumer privacy profiles and canonical fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, TypeVar


PRIVACY_CONTRACT_V3 = "helto.privacy.v3"
MODE_TRANSITION_PROTOCOL = "recoverable-v1"
_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")
_BROWSER_EXTERNAL_TRANSITION_METHODS = (
    "settleModeTransition",
    "inventoryModeTransitionOwners",
    "readModeTransitionOwnerExact",
    "applyModeTransitionOwnerExact",
    "extractDetachedModeTransitionOwnerExact",
    "restoreModeTransitionOwnerExact",
    "reloadModeTransitionRuntime",
    "reconcileModeTransitionRuntime",
)
_BROWSER_EXTERNAL_OPERATION_METHODS = (
    "settleExternalOperation",
    "identifyExternalOperationOwner",
    "resolveExternalOperationOwner",
    "readExternalOperationExact",
    "applyExternalOperation",
    "restoreExternalOperationExact",
    "reloadExternalOperationRuntime",
    "reconcileExternalOperationRuntime",
)
_SERVER_EXTERNAL_OPERATION_METHODS = (
    "capture_external_operation",
    "classify_external_operation",
    "prepare_external_operation",
    "finalize_external_operation",
    "rollback_external_operation",
)
_SERVER_EXTERNAL_TRANSITION_METHODS = (
    "classify_mode_transition_representation",
    "decode_mode_transition_representation",
    "normalize_mode_transition_value",
    "encode_public_mode_transition",
)
_MODE_SOURCE_TRANSITION_METHODS = (
    "read_mode_source",
    "compare_and_set_mode_source",
    "classify_mode_source",
    "rollback_mode_source",
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
    SINGLETON = "singleton"
    ARTIFACT = "artifact"
    EXECUTION = "execution"
    OPERATION = "operation"


class FieldLocationKind(str, Enum):
    """Closed product locations shared policy knows how to coordinate."""

    WIDGET = "widget"
    PROPERTY = "property"
    INPUT = "input"
    RECORD = "record"
    BLOB = "blob"


class ProtectedStateAuthority(str, Enum):
    """Authority that can inventory and durably recover one product-state field."""

    EXTERNAL_BROWSER_WORKFLOW = "external-browser-workflow"
    SERVER_DURABLE = "server-durable"


@dataclass(frozen=True, slots=True)
class ExternalTransitionPolicy:
    """Attested bounds for browser-owned workflow transition recovery material."""

    owner_identity: str = "graph-node-field-v1"
    max_owners: int = 1024
    max_original_bytes_per_owner: int = 2 * 1024 * 1024
    max_target_bytes_per_owner: int = 2 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    lease_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            self.owner_identity != "graph-node-field-v1"
            or type(self.max_owners) is not int
            or not 1 <= self.max_owners <= 4096
            or type(self.max_original_bytes_per_owner) is not int
            or not 1024 <= self.max_original_bytes_per_owner <= 16 * 1024 * 1024
            or type(self.max_target_bytes_per_owner) is not int
            or not 1024 <= self.max_target_bytes_per_owner <= 16 * 1024 * 1024
            or type(self.max_total_bytes) is not int
            or not max(
                self.max_original_bytes_per_owner,
                self.max_target_bytes_per_owner,
            ) <= self.max_total_bytes <= 64 * 1024 * 1024
            or type(self.lease_seconds) is not int
            or not 30 <= self.lease_seconds <= 900
        ):
            raise ProfileValidationError("invalid_external_transition_policy")

    def contract_payload(self) -> dict[str, object]:
        return {
            "ownerIdentity": self.owner_identity,
            "maxOwners": self.max_owners,
            "maxOriginalBytesPerOwner": self.max_original_bytes_per_owner,
            "maxTargetBytesPerOwner": self.max_target_bytes_per_owner,
            "maxTotalBytes": self.max_total_bytes,
            "leaseSeconds": self.lease_seconds,
        }


@dataclass(frozen=True, slots=True)
class ExternalOperationPolicy:
    """Attested bounds for one browser-owned exact operation target."""

    owner_identity: str = "graph-node-v1"
    max_identity_bytes: int = 16 * 1024
    max_original_bytes: int = 2 * 1024 * 1024
    max_target_bytes: int = 2 * 1024 * 1024
    lease_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            self.owner_identity != "graph-node-v1"
            or type(self.max_identity_bytes) is not int
            or not 256 <= self.max_identity_bytes <= 64 * 1024
            or type(self.max_original_bytes) is not int
            or not 1024 <= self.max_original_bytes <= 16 * 1024 * 1024
            or type(self.max_target_bytes) is not int
            or not 1024 <= self.max_target_bytes <= 16 * 1024 * 1024
            or type(self.lease_seconds) is not int
            or not 30 <= self.lease_seconds <= 900
        ):
            raise ProfileValidationError("invalid_external_operation_policy")

    def contract_payload(self) -> dict[str, object]:
        return {
            "ownerIdentity": self.owner_identity,
            "maxIdentityBytes": self.max_identity_bytes,
            "maxOriginalBytes": self.max_original_bytes,
            "maxTargetBytes": self.max_target_bytes,
            "leaseSeconds": self.lease_seconds,
        }


class LegacyLocationKind(str, Enum):
    """Closed locations where an exact legacy reader may be bound."""

    WORKFLOW_FIELD = "workflow-field"
    RECORD = "record"
    ARTIFACT = "artifact"
    PACK_STATE = "pack-state"
    EXPORT = "export"


class LegacyKeyFormat(str, Enum):
    """Exact plaintext source formats accepted by historical-key imports."""

    JSON = "json"
    BINARY = "binary"


class ArtifactRetention(str, Enum):
    """Shared artifact lifecycle selected by product meaning."""

    DURABLE_ADJUNCT = "durable-adjunct"
    REGENERABLE_CACHE = "regenerable-cache"
    RUN_SCOPED_SPILL = "run-scoped-spill"
    SERVED_TRANSIENT = "served-transient"


class ArtifactPayloadMode(str, Enum):
    """Closed payload-I/O contracts for managed artifacts."""

    BOUNDED_BYTES_V1 = "bounded-bytes-v1"
    STREAM_V1 = "stream-v1"


class ArtifactDecodedOutput(str, Enum):
    """Whether a streaming codec returns one materialized product value."""

    MATERIALIZED = "materialized"
    STREAM = "stream"


_MAX_SAFE_INTEGER = (1 << 53) - 1


@dataclass(frozen=True, slots=True)
class ArtifactStreamContract:
    """Profile-attested bounds for one forward-only artifact codec."""

    codec_schema: str
    codec_version: int
    max_plaintext_bytes: int
    decoded_output: ArtifactDecodedOutput
    max_materialized_output_bytes: int | None = None
    max_owner_plaintext_bytes: int | None = None

    def __post_init__(self) -> None:
        _validate_stable_id(self.codec_schema)
        numeric = (
            self.codec_version,
            self.max_plaintext_bytes,
            *(
                ()
                if self.max_materialized_output_bytes is None
                else (self.max_materialized_output_bytes,)
            ),
            *(
                ()
                if self.max_owner_plaintext_bytes is None
                else (self.max_owner_plaintext_bytes,)
            ),
        )
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            or value > _MAX_SAFE_INTEGER
            for value in numeric
        ):
            raise ProfileValidationError("invalid_artifact_stream_capacity")
        if not isinstance(self.decoded_output, ArtifactDecodedOutput):
            raise ProfileValidationError("invalid_artifact_decoded_output")
        if (
            self.decoded_output is ArtifactDecodedOutput.MATERIALIZED
        ) is (self.max_materialized_output_bytes is None):
            raise ProfileValidationError("invalid_artifact_decoded_output")
        if (
            self.max_owner_plaintext_bytes is not None
            and self.max_owner_plaintext_bytes < self.max_plaintext_bytes
        ):
            raise ProfileValidationError("invalid_artifact_stream_capacity")


class SensitiveFieldClass(str, Enum):
    """Closed reasons why protected-operation output is private by default."""

    USER_AUTHORED = "user-authored"
    PATH_OR_NAME = "path-or-name"
    DEBUG = "debug"
    CONSUMER_DERIVED = "consumer-derived"


class SafeDiagnosticKind(str, Enum):
    """Coarse primitive kinds allowed in a private diagnostic projection."""

    BOOLEAN = "boolean"
    COUNT = "count"


class SafePayloadKind(str, Enum):
    """Closed scalar kinds permitted in the product-safe payload channel."""

    BOOLEAN = "boolean"
    COUNT = "count"
    NUMBER = "number"
    SAFE_TEXT = "safe-text"


@dataclass(frozen=True, slots=True)
class SafePayloadLeaf:
    """One exact typed leaf in a safe-payload projection."""

    path: str
    kind: SafePayloadKind

    def __post_init__(self) -> None:
        _validate_projection_path(self.path)
        if "*" in self.path.split(".") or not isinstance(self.kind, SafePayloadKind):
            raise ProfileValidationError("invalid_safe_payload_projection")


@dataclass(frozen=True, slots=True)
class SafePayloadProjection:
    """Exact JSON leaf allow-list for a product-safe operation payload."""

    id: str
    operation_id: str
    schema: str
    purpose: str
    safe_leaves: tuple[SafePayloadLeaf, ...]

    def __post_init__(self) -> None:
        for value in (self.id, self.operation_id, self.schema, self.purpose):
            _validate_stable_id(value)
        leaves = tuple(self.safe_leaves)
        if (
            not leaves
            or len(leaves) > 64
            or any(not isinstance(item, SafePayloadLeaf) for item in leaves)
        ):
            raise ProfileValidationError("invalid_safe_payload_projection")
        paths = tuple(item.path for item in leaves)
        if len(paths) != len(set(paths)):
            raise ProfileValidationError("duplicate_safe_payload_leaf")
        object.__setattr__(self, "safe_leaves", tuple(sorted(leaves, key=lambda item: item.path)))

    @property
    def safe_leaf_paths(self) -> tuple[str, ...]:
        """Read-only compatibility view without restoring untyped declarations."""

        return tuple(item.path for item in self.safe_leaves)


class SingletonPayloadKind(str, Enum):
    """Opaque payload families supported by the singleton service."""

    FIELD = "field"
    BLOB = "blob"


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
    state_authority: ProtectedStateAuthority
    external_transition_policy: ExternalTransitionPolicy | None = None
    legacy_reader_ids: tuple[str, ...] = ()
    execution: bool = False
    mirror_locations: tuple[FieldLocation, ...] = ()

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
        try:
            mirror_locations = tuple(self.mirror_locations)
        except TypeError:
            raise ProfileValidationError("unknown_field_location") from None
        if any(not isinstance(item, FieldLocation) for item in mirror_locations):
            raise ProfileValidationError("unknown_field_location")
        location_keys = (
            (self.location.kind, self.location.name),
            *((item.kind, item.name) for item in mirror_locations),
        )
        if len(location_keys) != len(set(location_keys)):
            raise ProfileValidationError("duplicate_field_location")
        object.__setattr__(
            self,
            "mirror_locations",
            tuple(
                sorted(
                    mirror_locations,
                    key=lambda item: (item.kind.value, item.name),
                )
            ),
        )
        object.__setattr__(self, "node_types", _normalized_node_types(self.node_types))
        object.__setattr__(
            self,
            "legacy_reader_ids",
            _normalized_stable_ids(self.legacy_reader_ids, "duplicate_legacy_reader"),
        )
        if not isinstance(self.execution, bool):
            raise ProfileValidationError("invalid_execution_declaration")
        if not isinstance(self.state_authority, ProtectedStateAuthority):
            raise ProfileValidationError("invalid_protected_state_authority")
        if self.state_authority is ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW:
            if not isinstance(self.external_transition_policy, ExternalTransitionPolicy):
                raise ProfileValidationError("missing_external_transition_policy")
        elif self.external_transition_policy is not None:
            raise ProfileValidationError("unexpected_external_transition_policy")

    def contract_payload(self, *, browser: bool = False) -> dict[str, object]:
        """Project this declaration without duplicating contract field lists."""

        declaration: dict[str, object] = {
            "id": self.id,
            "workflowResourceId": self.workflow_resource_id,
            "scopeId": self.scope_id,
            "browserAdapter": self.browser_adapter,
            "nodeTypes": list(self.node_types),
            "location": {
                "kind": self.location.kind.value,
                "name": self.location.name,
            },
            "currentSchema": self.current_schema,
            "purpose": self.purpose,
            "stateAuthority": self.state_authority.value,
            "externalTransitionPolicy": (
                self.external_transition_policy.contract_payload()
                if self.external_transition_policy is not None
                else None
            ),
            "legacyReaderIds": list(self.legacy_reader_ids),
            "execution": self.execution,
        }
        if not browser:
            declaration["stateAdapter"] = self.state_adapter
        if self.mirror_locations:
            declaration["mirrorLocations"] = [
                {"kind": location.kind.value, "name": location.name}
                for location in self.mirror_locations
            ]
        return declaration


@dataclass(frozen=True, slots=True)
class LegacyReaderBinding:
    """Bind one shared read-only legacy reader to one declared product location."""

    id: str
    reader_id: str
    resource_id: str
    location_kind: LegacyLocationKind
    location_id: str

    def __post_init__(self) -> None:
        for value in (self.id, self.reader_id, self.resource_id, self.location_id):
            _validate_stable_id(value)
        if not isinstance(self.location_kind, LegacyLocationKind):
            raise ProfileValidationError("unknown_legacy_location")


@dataclass(frozen=True, slots=True)
class LegacyKeyImportBinding:
    """Declare one historical-key import independently of schema readers."""

    id: str
    import_id: str
    resource_id: str
    location_kind: LegacyLocationKind
    location_id: str
    source_format: LegacyKeyFormat

    def __post_init__(self) -> None:
        for value in (self.id, self.import_id, self.resource_id, self.location_id):
            _validate_stable_id(value)
        if not isinstance(self.location_kind, LegacyLocationKind):
            raise ProfileValidationError("unknown_legacy_location")
        if not isinstance(self.source_format, LegacyKeyFormat):
            raise ProfileValidationError("unknown_legacy_key_format")


@dataclass(frozen=True, slots=True)
class RecordRevealProjection:
    """One authorized record reveal operation and its safe result fields."""

    operation: str
    safe_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_stable_id(self.operation)
        if self.operation not in {"use", "preview", "details"}:
            raise ProfileValidationError("invalid_record_reveal_operation")
        fields = _normalized_text_values(
            self.safe_fields,
            "invalid_safe_projection_field",
            "duplicate_safe_projection_field",
        )
        if not fields or any(not _is_stable_id(field_name) for field_name in fields):
            raise ProfileValidationError("invalid_safe_projection_field")
        object.__setattr__(self, "safe_fields", fields)


@dataclass(frozen=True, slots=True)
class RecordDeclaration:
    """Product facts for one private record kind."""

    id: str
    resource_id: str
    scope_id: str
    current_schema: str
    store_adapter: str
    projections: tuple[RecordRevealProjection, ...] = ()
    mutation_operations: tuple[str, ...] = ()
    safe_projection: tuple[str, ...] = ()
    fixed_private_label: str = "Private record"

    def __post_init__(self) -> None:
        for value in (
            self.id,
            self.resource_id,
            self.scope_id,
            self.current_schema,
            self.store_adapter,
        ):
            _validate_stable_id(value)
        projections = tuple(self.projections)
        if any(not isinstance(item, RecordRevealProjection) for item in projections):
            raise ProfileValidationError("invalid_record_projection_contract")
        operations = tuple(item.operation for item in projections)
        if len(operations) != len(set(operations)):
            raise ProfileValidationError("duplicate_record_reveal_operation")
        object.__setattr__(
            self,
            "projections",
            tuple(sorted(projections, key=lambda item: item.operation)),
        )
        mutations = _normalized_stable_ids(
            self.mutation_operations,
            "duplicate_record_mutation_operation",
        )
        if any(
            operation not in {"create", "replace", "patch", "duplicate"}
            for operation in mutations
        ):
            raise ProfileValidationError("invalid_record_mutation_operation")
        object.__setattr__(self, "mutation_operations", mutations)
        safe_projection = _normalized_text_values(
            self.safe_projection,
            "invalid_safe_projection_field",
            "duplicate_safe_projection_field",
        )
        if safe_projection:
            raise ProfileValidationError("unsafe_record_list_projection")
        object.__setattr__(self, "safe_projection", safe_projection)
        if self.fixed_private_label != "Private record":
            raise ProfileValidationError("invalid_private_record_label")

    @property
    def reveal_operations(self) -> tuple[str, ...]:
        return tuple(projection.operation for projection in self.projections)

    def projection_for(self, operation: str) -> RecordRevealProjection | None:
        return next(
            (
                projection
                for projection in self.projections
                if projection.operation == operation
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class RecordReferenceMigration:
    """One declared relocation from an opaque legacy reference to a private record."""

    id: str
    resource_id: str
    record_kind: str
    legacy_binding_id: str

    def __post_init__(self) -> None:
        for value in (
            self.id,
            self.resource_id,
            self.record_kind,
            self.legacy_binding_id,
        ):
            _validate_stable_id(value)


@dataclass(frozen=True, slots=True)
class SingletonDeclaration:
    """One revisioned protected value whose domain meaning stays product-owned."""

    id: str
    resource_id: str
    scope_id: str
    current_schema: str
    purpose: str
    store_adapter: str
    payload_kind: SingletonPayloadKind
    legacy_reader_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (
            self.id,
            self.resource_id,
            self.scope_id,
            self.current_schema,
            self.purpose,
            self.store_adapter,
        ):
            _validate_stable_id(value)
        if not isinstance(self.payload_kind, SingletonPayloadKind):
            raise ProfileValidationError("unknown_singleton_payload_kind")
        object.__setattr__(
            self,
            "legacy_reader_ids",
            _normalized_stable_ids(
                self.legacy_reader_ids,
                "duplicate_legacy_reader",
            ),
        )


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
    media_type: str = "application/octet-stream"
    payload_mode: ArtifactPayloadMode = ArtifactPayloadMode.BOUNDED_BYTES_V1
    stream_contract: ArtifactStreamContract | None = None

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
        if not isinstance(self.payload_mode, ArtifactPayloadMode):
            raise ProfileValidationError("unknown_artifact_payload_mode")
        if self.payload_mode is ArtifactPayloadMode.STREAM_V1:
            if not isinstance(self.stream_contract, ArtifactStreamContract):
                raise ProfileValidationError("missing_artifact_stream_contract")
            if self.retention is ArtifactRetention.DURABLE_ADJUNCT:
                raise ProfileValidationError("unsupported_artifact_stream_retention")
        elif self.stream_contract is not None:
            raise ProfileValidationError("unexpected_artifact_stream_contract")
        if not isinstance(self.media_type, str) or _MEDIA_TYPE.fullmatch(
            self.media_type
        ) is None:
            raise ProfileValidationError("invalid_artifact_media_type")
        operations = _normalized_stable_ids(
            self.operations,
            "duplicate_artifact_operation",
        )
        if not operations and self.retention is not ArtifactRetention.RUN_SCOPED_SPILL:
            raise ProfileValidationError("missing_artifact_operation")
        object.__setattr__(self, "operations", operations)


@dataclass(frozen=True, slots=True)
class SensitiveFieldDeclaration:
    """One classified sensitive path; ``*`` is the required default rule."""

    path: str
    field_class: SensitiveFieldClass

    def __post_init__(self) -> None:
        if self.path != "*":
            _validate_projection_path(self.path)
        if not isinstance(self.field_class, SensitiveFieldClass):
            raise ProfileValidationError("invalid_sensitive_field_class")


@dataclass(frozen=True, slots=True)
class SafeDiagnosticField:
    """One explicitly safe coarse leaf in a private operation projection."""

    path: str
    kind: SafeDiagnosticKind

    def __post_init__(self) -> None:
        _validate_projection_path(self.path)
        if not isinstance(self.kind, SafeDiagnosticKind):
            raise ProfileValidationError("invalid_safe_diagnostic_kind")


@dataclass(frozen=True, slots=True)
class OpaqueReferenceKind:
    """One opaque, RAM-only reference family owned by an operation resource."""

    id: str
    resource_id: str
    scope_id: str

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.resource_id)
        _validate_stable_id(self.scope_id)


@dataclass(frozen=True, slots=True)
class OperationReferenceInput:
    """One named opaque reference accepted by an operation."""

    name: str
    reference_kind_id: str
    revoke_on_success: bool = False

    def __post_init__(self) -> None:
        _validate_stable_id(self.name)
        _validate_stable_id(self.reference_kind_id)
        if not isinstance(self.revoke_on_success, bool):
            raise ProfileValidationError("invalid_operation_reference_input")


@dataclass(frozen=True, slots=True)
class OperationReferenceOutput:
    """One bounded, ordered opaque-reference output group."""

    reference_kind_id: str
    minimum: int = 1
    maximum: int = 1

    def __post_init__(self) -> None:
        _validate_stable_id(self.reference_kind_id)
        if (
            not isinstance(self.minimum, int)
            or isinstance(self.minimum, bool)
            or not isinstance(self.maximum, int)
            or isinstance(self.maximum, bool)
            or self.minimum < 0
            or self.maximum < self.minimum
            or self.maximum > 256
        ):
            raise ProfileValidationError("invalid_operation_reference_output")


@dataclass(frozen=True, slots=True)
class SubjectModeBinding:
    """One reusable node/input binding for an effective subject mode."""

    id: str
    scope_id: str
    input_name: str
    node_types: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.scope_id)
        _validate_stable_id(self.input_name)
        object.__setattr__(self, "node_types", _normalized_node_types(self.node_types))


_SINGLETON_DEPENDENCY_VERBS = frozenset({"status", "reveal", "replace", "delete"})
_ARTIFACT_DEPENDENCY_VERBS = frozenset(
    {"write", "read", "retire", "release-owner", "reconcile-owner"}
)


@dataclass(frozen=True, slots=True)
class RecordOperationDependency:
    """One exact declared record projection required by a product operation."""

    resource_id: str
    record_kind: str
    operation: str

    def __post_init__(self) -> None:
        _validate_stable_id(self.resource_id)
        _validate_stable_id(self.record_kind)
        _validate_stable_id(self.operation)


@dataclass(frozen=True, slots=True)
class SingletonOperationDependency:
    """Closed verbs over one exact declared singleton."""

    singleton_id: str
    verbs: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_stable_id(self.singleton_id)
        verbs = _normalized_stable_ids(
            self.verbs,
            "duplicate_singleton_dependency_verb",
        )
        if not verbs or any(verb not in _SINGLETON_DEPENDENCY_VERBS for verb in verbs):
            raise ProfileValidationError("invalid_singleton_dependency_verb")
        object.__setattr__(self, "verbs", verbs)


@dataclass(frozen=True, slots=True)
class ArtifactOperationDependency:
    """Closed verbs over one exact declared artifact kind."""

    artifact_kind: str
    verbs: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_stable_id(self.artifact_kind)
        verbs = _normalized_stable_ids(
            self.verbs,
            "duplicate_artifact_dependency_verb",
        )
        if not verbs or any(
            verb not in _ARTIFACT_DEPENDENCY_VERBS and not verb.startswith("lease.")
            for verb in verbs
        ):
            raise ProfileValidationError("invalid_artifact_dependency_verb")
        if any(verb == "lease." for verb in verbs):
            raise ProfileValidationError("invalid_artifact_dependency_verb")
        object.__setattr__(self, "verbs", verbs)


@dataclass(frozen=True, slots=True)
class ExternalOperationBinding:
    """Bind one operation to an exact browser-owned protected field."""

    field_id: str
    browser_adapter: str
    policy: ExternalOperationPolicy = field(default_factory=ExternalOperationPolicy)

    def __post_init__(self) -> None:
        _validate_stable_id(self.field_id)
        _validate_stable_id(self.browser_adapter)
        if not isinstance(self.policy, ExternalOperationPolicy):
            raise ProfileValidationError("invalid_external_operation_binding")


@dataclass(frozen=True, slots=True)
class ProtectedOperation:
    """A routed product action or backend output protected by shared policy."""

    id: str
    resource_id: str
    adapter_slot: str
    route: str | None
    method: str = "POST"
    scope_id: str | None = None
    sensitive_fields: tuple[SensitiveFieldDeclaration, ...] = ()
    safe_projection: tuple[SafeDiagnosticField, ...] = ()
    subject_mode_binding_id: str | None = None
    reference_inputs: tuple[OperationReferenceInput, ...] = ()
    reference_outputs: tuple[OperationReferenceOutput | str, ...] = ()
    returns_lease: bool = False
    safe_payload_projection_id: str | None = None
    deferred_ui: bool = False
    record_dependencies: tuple[RecordOperationDependency, ...] = ()
    singleton_dependencies: tuple[SingletonOperationDependency, ...] = ()
    artifact_dependencies: tuple[ArtifactOperationDependency, ...] = ()
    external_operation_binding: ExternalOperationBinding | None = None

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.resource_id)
        _validate_stable_id(self.adapter_slot)
        if self.route is not None:
            if (
                not isinstance(self.route, str)
                or not self.route.startswith("/")
                or self.route.startswith("//")
                or any(
                    character in self.route
                    for character in ("?", "#", "\\", "{", "}")
                )
            ):
                raise ProfileValidationError("invalid_protected_operation_route")
        normalized_method = str(self.method or "").strip().upper()
        if normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ProfileValidationError("invalid_protected_operation_method")
        object.__setattr__(self, "method", normalized_method)
        if self.scope_id is not None:
            _validate_stable_id(self.scope_id)
        sensitive_fields = tuple(self.sensitive_fields)
        safe_projection = tuple(self.safe_projection)
        if any(
            not isinstance(item, SensitiveFieldDeclaration)
            for item in sensitive_fields
        ):
            raise ProfileValidationError("invalid_sensitive_field_declaration")
        if any(not isinstance(item, SafeDiagnosticField) for item in safe_projection):
            raise ProfileValidationError("invalid_safe_diagnostic_declaration")
        sensitive_paths = tuple(item.path for item in sensitive_fields)
        safe_paths = tuple(item.path for item in safe_projection)
        if len(sensitive_paths) != len(set(sensitive_paths)):
            raise ProfileValidationError("duplicate_sensitive_field")
        if len(safe_paths) != len(set(safe_paths)):
            raise ProfileValidationError("duplicate_safe_diagnostic_field")
        if sensitive_fields or safe_projection:
            if self.scope_id is None:
                raise ProfileValidationError("missing_protected_operation_scope")
            if not any(
                item.path == "*"
                and item.field_class is SensitiveFieldClass.CONSUMER_DERIVED
                for item in sensitive_fields
            ):
                raise ProfileValidationError("missing_sensitive_default")
        if self.safe_payload_projection_id is not None:
            _validate_stable_id(self.safe_payload_projection_id)
        if not isinstance(self.deferred_ui, bool):
            raise ProfileValidationError("invalid_deferred_operation")
        external_binding = self.external_operation_binding
        if external_binding is not None and not isinstance(
            external_binding,
            ExternalOperationBinding,
        ):
            raise ProfileValidationError("invalid_external_operation_binding")
        has_safe_output = bool(safe_projection or self.safe_payload_projection_id)
        if self.route is None and not (has_safe_output or self.reference_outputs):
            raise ProfileValidationError("missing_protected_operation_projection")
        if self.subject_mode_binding_id is not None:
            _validate_stable_id(self.subject_mode_binding_id)
            if (
                self.route is not None
                or self.scope_id is None
                or not (has_safe_output or (self.deferred_ui and self.reference_outputs))
            ):
                raise ProfileValidationError("invalid_subject_mode_binding")
        reference_inputs = tuple(self.reference_inputs)
        if any(not isinstance(item, OperationReferenceInput) for item in reference_inputs):
            raise ProfileValidationError("invalid_operation_reference_input")
        input_names = tuple(item.name for item in reference_inputs)
        if len(input_names) != len(set(input_names)):
            raise ProfileValidationError("duplicate_operation_reference_input")
        reference_outputs = tuple(
            OperationReferenceOutput(item) if isinstance(item, str) else item
            for item in self.reference_outputs
        )
        if any(
            not isinstance(item, OperationReferenceOutput)
            for item in reference_outputs
        ):
            raise ProfileValidationError("invalid_operation_reference_output")
        output_kinds = tuple(item.reference_kind_id for item in reference_outputs)
        if len(output_kinds) != len(set(output_kinds)):
            raise ProfileValidationError("duplicate_operation_reference_output")
        if sum(item.maximum for item in reference_outputs) > 256:
            raise ProfileValidationError("invalid_operation_reference_output")
        if not isinstance(self.returns_lease, bool):
            raise ProfileValidationError("invalid_operation_lease_declaration")
        if (reference_inputs or reference_outputs or self.returns_lease) and self.scope_id is None:
            raise ProfileValidationError("invalid_typed_operation_declaration")
        if self.route is None and not self.deferred_ui and external_binding is None and (
            reference_inputs or reference_outputs or self.returns_lease
        ):
            raise ProfileValidationError("invalid_typed_operation_declaration")
        if self.deferred_ui and (
            self.route is not None
            or self.subject_mode_binding_id is None
            or not (self.safe_payload_projection_id or reference_outputs)
            or reference_inputs
            or self.returns_lease
        ):
            raise ProfileValidationError("invalid_deferred_operation")
        if self.returns_lease and len(reference_inputs) != 1:
            raise ProfileValidationError("invalid_operation_lease_declaration")
        if external_binding is not None and (
            self.route is not None
            or self.method != "POST"
            or self.scope_id is None
            or self.subject_mode_binding_id is not None
            or self.deferred_ui
            or self.returns_lease
            or bool(reference_outputs)
        ):
            raise ProfileValidationError("invalid_external_operation_binding")
        record_dependencies = tuple(self.record_dependencies)
        singleton_dependencies = tuple(self.singleton_dependencies)
        artifact_dependencies = tuple(self.artifact_dependencies)
        if any(
            not isinstance(item, RecordOperationDependency)
            for item in record_dependencies
        ):
            raise ProfileValidationError("invalid_record_operation_dependency")
        if any(
            not isinstance(item, SingletonOperationDependency)
            for item in singleton_dependencies
        ):
            raise ProfileValidationError("invalid_singleton_operation_dependency")
        if any(
            not isinstance(item, ArtifactOperationDependency)
            for item in artifact_dependencies
        ):
            raise ProfileValidationError("invalid_artifact_operation_dependency")
        record_keys = tuple(
            (item.resource_id, item.record_kind, item.operation)
            for item in record_dependencies
        )
        if len(record_keys) != len(set(record_keys)):
            raise ProfileValidationError("duplicate_record_operation_dependency")
        singleton_ids = tuple(item.singleton_id for item in singleton_dependencies)
        if len(singleton_ids) != len(set(singleton_ids)):
            raise ProfileValidationError("duplicate_singleton_operation_dependency")
        artifact_kinds = tuple(item.artifact_kind for item in artifact_dependencies)
        if len(artifact_kinds) != len(set(artifact_kinds)):
            raise ProfileValidationError("duplicate_artifact_operation_dependency")
        if (
            self.returns_lease
            and artifact_dependencies
            and not any(
                any(verb.startswith("lease.") for verb in item.verbs)
                for item in artifact_dependencies
            )
        ):
            raise ProfileValidationError("invalid_operation_lease_declaration")
        if (
            record_dependencies or singleton_dependencies or artifact_dependencies
        ) and self.scope_id is None:
            raise ProfileValidationError("missing_operation_dependency_scope")
        object.__setattr__(
            self,
            "sensitive_fields",
            tuple(sorted(sensitive_fields, key=lambda item: item.path)),
        )
        object.__setattr__(
            self,
            "safe_projection",
            tuple(sorted(safe_projection, key=lambda item: item.path)),
        )
        object.__setattr__(
            self,
            "reference_inputs",
            tuple(sorted(reference_inputs, key=lambda item: item.name)),
        )
        object.__setattr__(self, "reference_outputs", reference_outputs)
        object.__setattr__(
            self,
            "record_dependencies",
            tuple(
                sorted(
                    record_dependencies,
                    key=lambda item: (
                        item.resource_id,
                        item.record_kind,
                        item.operation,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "singleton_dependencies",
            tuple(sorted(singleton_dependencies, key=lambda item: item.singleton_id)),
        )
        object.__setattr__(
            self,
            "artifact_dependencies",
            tuple(sorted(artifact_dependencies, key=lambda item: item.artifact_kind)),
        )


@dataclass(frozen=True, slots=True)
class SemanticExecutionProjection:
    """The product projection used by one protected execution resource."""

    id: str
    execution_resource_id: str
    workflow_resource_id: str
    projection_adapter: str
    dispatch_adapter: str
    subject_mode_binding_id: str
    input_name: str = "private_execution"

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.execution_resource_id)
        _validate_stable_id(self.workflow_resource_id)
        _validate_stable_id(self.projection_adapter)
        _validate_stable_id(self.dispatch_adapter)
        _validate_stable_id(self.subject_mode_binding_id)
        _validate_stable_id(self.input_name)


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
    contract: str = PRIVACY_CONTRACT_V3
    resources: tuple[ProfileResource, ...] = ()
    server_adapters: tuple[AdapterSlot, ...] = ()
    browser_adapters: tuple[AdapterSlot, ...] = ()
    scopes: tuple[PrivacyScope, ...] = ()
    protected_fields: tuple[ProtectedField, ...] = ()
    records: tuple[RecordDeclaration, ...] = ()
    singletons: tuple[SingletonDeclaration, ...] = ()
    artifacts: tuple[ArtifactDeclaration, ...] = ()
    subject_mode_bindings: tuple[SubjectModeBinding, ...] = ()
    protected_operations: tuple[ProtectedOperation, ...] = ()
    execution_projections: tuple[SemanticExecutionProjection, ...] = ()
    legacy_bindings: tuple[LegacyReaderBinding, ...] = ()
    legacy_key_imports: tuple[LegacyKeyImportBinding, ...] = ()
    record_reference_migrations: tuple[RecordReferenceMigration, ...] = ()
    opaque_reference_kinds: tuple[OpaqueReferenceKind, ...] = ()
    safe_payload_projections: tuple[SafePayloadProjection, ...] = ()

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
            record_reference_migrations = tuple(self.record_reference_migrations)
            opaque_reference_kinds = tuple(self.opaque_reference_kinds)
            safe_payload_projections = tuple(self.safe_payload_projections)
            singletons = tuple(self.singletons)
            artifacts = tuple(self.artifacts)
            subject_mode_bindings = tuple(self.subject_mode_bindings)
            protected_operations = tuple(self.protected_operations)
            execution_projections = tuple(self.execution_projections)
            legacy_bindings = tuple(self.legacy_bindings)
            legacy_key_imports = tuple(self.legacy_key_imports)
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
            (
                record_reference_migrations,
                RecordReferenceMigration,
                "unknown_record_reference_migration",
            ),
            (
                opaque_reference_kinds,
                OpaqueReferenceKind,
                "unknown_opaque_reference_kind",
            ),
            (
                safe_payload_projections,
                SafePayloadProjection,
                "unknown_safe_payload_projection",
            ),
            (singletons, SingletonDeclaration, "unknown_singleton_declaration"),
            (artifacts, ArtifactDeclaration, "unknown_artifact_declaration"),
            (
                subject_mode_bindings,
                SubjectModeBinding,
                "unknown_subject_mode_binding",
            ),
            (protected_operations, ProtectedOperation, "unknown_operation_declaration"),
            (
                execution_projections,
                SemanticExecutionProjection,
                "unknown_execution_projection",
            ),
            (legacy_bindings, LegacyReaderBinding, "unknown_legacy_binding"),
            (
                legacy_key_imports,
                LegacyKeyImportBinding,
                "unknown_legacy_key_import",
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
            ("record_reference_migrations", record_reference_migrations),
            ("opaque_reference_kinds", opaque_reference_kinds),
            ("safe_payload_projections", safe_payload_projections),
            ("singletons", singletons),
            ("artifacts", artifacts),
            ("subject_mode_bindings", subject_mode_bindings),
            ("protected_operations", protected_operations),
            ("execution_projections", execution_projections),
            ("legacy_bindings", legacy_bindings),
            ("legacy_key_imports", legacy_key_imports),
        ):
            object.__setattr__(
                self,
                field_name,
                tuple(sorted(declarations, key=lambda item: item.id)),
            )
        self._validate()

    def _validate(self) -> None:
        if self.contract != PRIVACY_CONTRACT_V3:
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
        reference_migrations = _unique_by_id(
            self.record_reference_migrations,
            "duplicate_record_reference_migration",
        )
        reference_migration_locations = {
            (
                item.resource_id,
                item.record_kind,
                item.legacy_binding_id,
            )
            for item in reference_migrations.values()
        }
        if len(reference_migration_locations) != len(reference_migrations):
            raise ProfileValidationError("duplicate_record_reference_migration")
        singletons = _unique_by_id(
            self.singletons,
            "duplicate_singleton_declaration",
        )
        artifacts = _unique_by_id(self.artifacts, "duplicate_artifact_declaration")
        subject_bindings = _unique_by_id(
            self.subject_mode_bindings,
            "duplicate_subject_mode_binding",
        )
        operations = _unique_by_id(self.protected_operations, "duplicate_protected_operation")
        reference_kinds = _unique_by_id(
            self.opaque_reference_kinds,
            "duplicate_opaque_reference_kind",
        )
        safe_payload_projections = _unique_by_id(
            self.safe_payload_projections,
            "duplicate_safe_payload_projection",
        )
        projections = _unique_by_id(
            self.execution_projections,
            "duplicate_execution_projection",
        )
        legacy_bindings = _unique_by_id(
            self.legacy_bindings,
            "duplicate_legacy_binding",
        )
        legacy_key_imports = _unique_by_id(
            self.legacy_key_imports,
            "duplicate_legacy_key_import_binding",
        )
        server_adapter_ids = {adapter.id for adapter in self.server_adapters}
        browser_adapter_ids = {adapter.id for adapter in self.browser_adapters}
        used_server_adapters: set[str] = set()
        used_browser_adapters: set[str] = set()

        for migration in reference_migrations.values():
            _require_resource_kind(
                resources,
                migration.resource_id,
                ResourceKind.RECORD,
            )
            record = records.get(migration.record_kind)
            if record is None or record.resource_id != migration.resource_id:
                raise ProfileValidationError("record_reference_migration_record_mismatch")
            binding = legacy_bindings.get(migration.legacy_binding_id)
            if (
                binding is None
                or binding.location_kind is not LegacyLocationKind.RECORD
                or binding.resource_id != migration.resource_id
                or binding.location_id != migration.record_kind
            ):
                raise ProfileValidationError("record_reference_migration_binding_mismatch")

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

        for binding in legacy_bindings.values():
            resource = resources.get(binding.resource_id)
            if resource is None:
                raise ProfileValidationError("unknown_legacy_resource")
            if binding.location_kind is LegacyLocationKind.WORKFLOW_FIELD:
                field = fields.get(binding.location_id)
                if field is None or field.workflow_resource_id != binding.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")
                if binding.reader_id not in field.legacy_reader_ids:
                    raise ProfileValidationError("undeclared_legacy_reader")
            elif binding.location_kind is LegacyLocationKind.RECORD:
                record = records.get(binding.location_id)
                if record is None or record.resource_id != binding.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")
            elif binding.location_kind is LegacyLocationKind.ARTIFACT:
                artifact = artifacts.get(binding.location_id)
                if artifact is None or artifact.resource_id != binding.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")
            elif binding.location_kind is LegacyLocationKind.PACK_STATE:
                singleton = singletons.get(binding.location_id)
                if (
                    singleton is None
                    or singleton.resource_id != binding.resource_id
                    or binding.reader_id not in singleton.legacy_reader_ids
                ):
                    raise ProfileValidationError("legacy_location_mismatch")
            else:
                operation = operations.get(binding.location_id)
                if operation is None or operation.resource_id != binding.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")

        for key_import in legacy_key_imports.values():
            resource = resources.get(key_import.resource_id)
            if resource is None:
                raise ProfileValidationError("unknown_legacy_resource")
            if key_import.location_kind is LegacyLocationKind.WORKFLOW_FIELD:
                field = fields.get(key_import.location_id)
                if field is None or field.workflow_resource_id != key_import.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")
            elif key_import.location_kind is LegacyLocationKind.RECORD:
                record = records.get(key_import.location_id)
                if record is None or record.resource_id != key_import.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")
            elif key_import.location_kind is LegacyLocationKind.ARTIFACT:
                artifact = artifacts.get(key_import.location_id)
                if artifact is None or artifact.resource_id != key_import.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")
            elif key_import.location_kind is LegacyLocationKind.PACK_STATE:
                singleton = singletons.get(key_import.location_id)
                if (
                    singleton is None
                    or singleton.resource_id != key_import.resource_id
                ):
                    raise ProfileValidationError("legacy_location_mismatch")
            else:
                operation = operations.get(key_import.location_id)
                if operation is None or operation.resource_id != key_import.resource_id:
                    raise ProfileValidationError("legacy_location_mismatch")

        formats_by_import: dict[str, LegacyKeyFormat] = {}
        for key_import in legacy_key_imports.values():
            existing_format = formats_by_import.setdefault(
                key_import.import_id,
                key_import.source_format,
            )
            if existing_format is not key_import.source_format:
                raise ProfileValidationError("legacy_key_import_format_conflict")

        declared_field_readers = {
            (field.id, reader_id)
            for field in fields.values()
            for reader_id in field.legacy_reader_ids
        }
        bound_field_readers = {
            (binding.location_id, binding.reader_id)
            for binding in legacy_bindings.values()
            if binding.location_kind is LegacyLocationKind.WORKFLOW_FIELD
        }
        workflow_bindings = tuple(
            binding
            for binding in legacy_bindings.values()
            if binding.location_kind is LegacyLocationKind.WORKFLOW_FIELD
        )
        if len(bound_field_readers) != len(workflow_bindings):
            raise ProfileValidationError("duplicate_legacy_location_binding")
        if declared_field_readers != bound_field_readers:
            raise ProfileValidationError("legacy_reader_binding_mismatch")

        record_bindings = tuple(
            binding
            for binding in legacy_bindings.values()
            if binding.location_kind is LegacyLocationKind.RECORD
        )
        if len(
            {
                (binding.location_id, binding.reader_id)
                for binding in record_bindings
            }
        ) != len(record_bindings):
            raise ProfileValidationError("duplicate_legacy_location_binding")

        declared_singleton_readers = {
            (singleton.id, reader_id)
            for singleton in singletons.values()
            for reader_id in singleton.legacy_reader_ids
        }
        bound_singleton_readers = {
            (binding.location_id, binding.reader_id)
            for binding in legacy_bindings.values()
            if binding.location_kind is LegacyLocationKind.PACK_STATE
        }
        pack_state_bindings = tuple(
            binding
            for binding in legacy_bindings.values()
            if binding.location_kind is LegacyLocationKind.PACK_STATE
        )
        if len(bound_singleton_readers) != len(pack_state_bindings):
            raise ProfileValidationError("duplicate_legacy_location_binding")
        if declared_singleton_readers != bound_singleton_readers:
            raise ProfileValidationError("legacy_reader_binding_mismatch")

        for record in records.values():
            resource = _require_resource_kind(resources, record.resource_id, ResourceKind.RECORD)
            if record.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")
            _require_adapter_side(resource, record.store_adapter, server_adapter_ids)
            used_server_adapters.add(record.store_adapter)

        for singleton in singletons.values():
            resource = _require_resource_kind(
                resources,
                singleton.resource_id,
                ResourceKind.SINGLETON,
            )
            if singleton.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")
            _require_adapter_side(
                resource,
                singleton.store_adapter,
                server_adapter_ids,
            )
            used_server_adapters.add(singleton.store_adapter)

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

        binding_paths: set[tuple[str, str]] = set()
        for binding in subject_bindings.values():
            scope = scopes.get(binding.scope_id)
            if scope is None:
                raise ProfileValidationError("unknown_scope_reference")
            if scope.mode_editor_adapter is None:
                raise ProfileValidationError("subject_mode_adapter_missing")
            editor = adapters.get(scope.mode_editor_adapter)
            if editor is None or not set(binding.node_types).issubset(editor.node_types):
                raise ProfileValidationError("subject_mode_binding_mismatch")
            for node_type in binding.node_types:
                path = (node_type, binding.input_name)
                if path in binding_paths:
                    raise ProfileValidationError("duplicate_execution_input_binding")
                binding_paths.add(path)

        for operation in operations.values():
            resource = resources.get(operation.resource_id)
            if resource is None:
                raise ProfileValidationError("unknown_operation_resource")
            if resource.kind is ResourceKind.RECORD:
                raise ProfileValidationError("record_operation_must_use_typed_contract")
            if resource.kind is ResourceKind.SINGLETON:
                raise ProfileValidationError("singleton_operation_must_use_typed_contract")
            if resource.kind is ResourceKind.ARTIFACT:
                raise ProfileValidationError("artifact_operation_must_use_typed_contract")
            _require_adapter_side(resource, operation.adapter_slot, server_adapter_ids)
            used_server_adapters.add(operation.adapter_slot)
            if operation.scope_id is not None and operation.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")
            has_dependencies = bool(
                operation.record_dependencies
                or operation.singleton_dependencies
                or operation.artifact_dependencies
            )
            if (
                has_dependencies
                and operation.route is None
                and operation.external_operation_binding is None
            ):
                raise ProfileValidationError("invalid_operation_dependency_dispatch")
            if operation.external_operation_binding is not None:
                binding = operation.external_operation_binding
                field = fields.get(binding.field_id)
                if (
                    resource.kind is not ResourceKind.OPERATION
                    or field is None
                    or field.scope_id != operation.scope_id
                    or field.browser_adapter != binding.browser_adapter
                    or field.state_authority
                    is not ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW
                ):
                    raise ProfileValidationError(
                        "external_operation_binding_mismatch"
                    )
            for dependency in operation.record_dependencies:
                _require_resource_kind(
                    resources,
                    dependency.resource_id,
                    ResourceKind.RECORD,
                )
                record = records.get(dependency.record_kind)
                if record is None or record.resource_id != dependency.resource_id:
                    raise ProfileValidationError("record_operation_dependency_mismatch")
                if dependency.operation not in record.reveal_operations:
                    raise ProfileValidationError("undeclared_record_dependency_operation")
                if record.scope_id != operation.scope_id:
                    raise ProfileValidationError("operation_dependency_scope_mismatch")
            for dependency in operation.singleton_dependencies:
                singleton = singletons.get(dependency.singleton_id)
                if singleton is None:
                    raise ProfileValidationError("unknown_singleton_dependency")
                if singleton.scope_id != operation.scope_id:
                    raise ProfileValidationError("operation_dependency_scope_mismatch")
            for dependency in operation.artifact_dependencies:
                artifact = artifacts.get(dependency.artifact_kind)
                if artifact is None:
                    raise ProfileValidationError("unknown_artifact_dependency")
                if artifact.scope_id != operation.scope_id:
                    raise ProfileValidationError("operation_dependency_scope_mismatch")
                if (
                    "reconcile-owner" in dependency.verbs
                    and artifact.retention is not ArtifactRetention.DURABLE_ADJUNCT
                ) or (
                    "write" in dependency.verbs
                    and artifact.retention is ArtifactRetention.RUN_SCOPED_SPILL
                ):
                    raise ProfileValidationError(
                        "invalid_artifact_dependency_retention"
                    )
                for verb in dependency.verbs:
                    if verb.startswith("lease.") and verb[6:] not in artifact.operations:
                        raise ProfileValidationError(
                            "undeclared_artifact_dependency_operation"
                        )
            if operation.subject_mode_binding_id is not None:
                binding = subject_bindings.get(operation.subject_mode_binding_id)
                if binding is None:
                    raise ProfileValidationError("unknown_subject_mode_binding")
                if operation.scope_id != binding.scope_id:
                    raise ProfileValidationError("subject_mode_binding_scope_mismatch")
            if operation.safe_payload_projection_id is not None:
                projection = safe_payload_projections.get(
                    operation.safe_payload_projection_id
                )
                if projection is None:
                    raise ProfileValidationError("unknown_safe_payload_projection")
                if projection.operation_id != operation.id:
                    raise ProfileValidationError("safe_payload_operation_mismatch")
            if operation.reference_inputs or operation.reference_outputs or operation.returns_lease:
                if resource.kind is not ResourceKind.OPERATION:
                    raise ProfileValidationError("typed_operation_resource_mismatch")
                for reference_input in operation.reference_inputs:
                    reference_kind = reference_kinds.get(reference_input.reference_kind_id)
                    if reference_kind is None:
                        raise ProfileValidationError("unknown_operation_reference_kind")
                    if (
                        reference_kind.resource_id != operation.resource_id
                        or reference_kind.scope_id != operation.scope_id
                    ):
                        raise ProfileValidationError("operation_reference_scope_mismatch")
                for reference_output in operation.reference_outputs:
                    reference_kind = reference_kinds.get(
                        reference_output.reference_kind_id
                    )
                    if reference_kind is None:
                        raise ProfileValidationError("unknown_operation_reference_kind")
                    if (
                        reference_kind.resource_id != operation.resource_id
                        or reference_kind.scope_id != operation.scope_id
                    ):
                        raise ProfileValidationError("operation_reference_scope_mismatch")

        for reference_kind in reference_kinds.values():
            _require_resource_kind(
                resources,
                reference_kind.resource_id,
                ResourceKind.OPERATION,
            )
            if reference_kind.scope_id not in scopes:
                raise ProfileValidationError("unknown_scope_reference")

        bound_safe_payloads = {
            operation.safe_payload_projection_id
            for operation in operations.values()
            if operation.safe_payload_projection_id is not None
        }
        if bound_safe_payloads != set(safe_payload_projections):
            raise ProfileValidationError("unused_safe_payload_projection")

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

            binding = subject_bindings.get(projection.subject_mode_binding_id)
            if binding is None:
                raise ProfileValidationError("unknown_subject_mode_binding")
            execution_fields = tuple(
                protected_field
                for protected_field in fields.values()
                if protected_field.execution
                and protected_field.workflow_resource_id
                == projection.workflow_resource_id
            )
            if not execution_fields:
                raise ProfileValidationError("missing_execution_field")
            field_scopes = {field.scope_id for field in execution_fields}
            field_node_types = {
                node_type
                for field in execution_fields
                for node_type in field.node_types
            }
            if field_scopes != {binding.scope_id}:
                raise ProfileValidationError("execution_subject_scope_mismatch")
            if field_node_types != set(binding.node_types):
                raise ProfileValidationError("execution_subject_node_type_mismatch")

        injected_inputs = set(binding_paths)
        for projection in projections.values():
            binding = subject_bindings[projection.subject_mode_binding_id]
            for node_type in binding.node_types:
                key = (node_type, projection.input_name)
                if key in injected_inputs:
                    raise ProfileValidationError("duplicate_execution_input_binding")
                injected_inputs.add(key)

        used_binding_ids = {
            projection.subject_mode_binding_id for projection in projections.values()
        } | {
            operation.subject_mode_binding_id
            for operation in operations.values()
            if operation.subject_mode_binding_id is not None
        }
        if set(subject_bindings) != used_binding_ids:
            raise ProfileValidationError("unused_subject_mode_binding")

        facts_by_kind = {
            ResourceKind.MODE: {scope.mode_resource_id for scope in scopes.values()},
            ResourceKind.WORKFLOW: {
                protected_field.workflow_resource_id for protected_field in fields.values()
            },
            ResourceKind.RECORD: {record.resource_id for record in records.values()},
            ResourceKind.SINGLETON: {
                singleton.resource_id for singleton in singletons.values()
            },
            ResourceKind.ARTIFACT: {artifact.resource_id for artifact in artifacts.values()},
            ResourceKind.EXECUTION: {
                projection.execution_resource_id for projection in projections.values()
            },
            ResourceKind.OPERATION: {
                reference_kind.resource_id for reference_kind in reference_kinds.values()
            },
        }
        for operation in operations.values():
            facts_by_kind[resources[operation.resource_id].kind].add(
                operation.resource_id
            )
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
                *_MODE_SOURCE_TRANSITION_METHODS,
            )
        for field in self.protected_fields:
            _add_contract(
                contracts,
                field.state_adapter,
                "capture",
                "normalize",
                "apply_revealed",
                "clear_plaintext",
            )
            if field.state_authority is ProtectedStateAuthority.SERVER_DURABLE:
                _add_contract(
                    contracts,
                    field.state_adapter,
                    "plan_mode_transition",
                    "prepare_mode_transition",
                    "classify_mode_transition",
                    "verify_mode_transition",
                    "commit_mode_transition",
                    "rollback_mode_transition",
                    "retire_mode_transition",
                )
            else:
                _add_contract(
                    contracts,
                    field.state_adapter,
                    *_SERVER_EXTERNAL_TRANSITION_METHODS,
                )
        for record in self.records:
            _add_contract(
                contracts,
                record.store_adapter,
                "list_ids",
                "read_record",
                "compare_and_swap_record",
            )
            if record.projections:
                _add_contract(contracts, record.store_adapter, "project")
            if record.mutation_operations:
                _add_contract(contracts, record.store_adapter, "mutate")
        records_by_id = {record.id: record for record in self.records}
        for migration in self.record_reference_migrations:
            adapter_id = records_by_id[migration.record_kind].store_adapter
            _add_contract(
                contracts,
                adapter_id,
                "read_legacy_record",
                "commit_record_relocation",
                "read_record_relocation",
                "rollback_record_relocation",
                "finalize_legacy_record",
                "list_record_reference_mapping_ids",
                "read_record_reference_mapping",
            )
        for singleton in self.singletons:
            _add_contract(
                contracts,
                singleton.store_adapter,
                "read_singleton",
                "begin_singleton_replace",
                "rollback_singleton_replace",
            )
        for artifact in self.artifacts:
            codec_methods = (
                ("encode_to", "decode_from")
                if artifact.payload_mode is ArtifactPayloadMode.STREAM_V1
                else ("encode", "decode")
            )
            _add_contract(
                contracts,
                artifact.payload_adapter,
                *codec_methods,
                "purge_plaintext_derivatives",
            )
        for operation in self.protected_operations:
            if operation.external_operation_binding is not None:
                _add_contract(
                    contracts,
                    operation.adapter_slot,
                    *_SERVER_EXTERNAL_OPERATION_METHODS,
                )
            elif operation.route is not None:
                _add_contract(
                    contracts,
                    operation.adapter_slot,
                    (
                        "invoke_with_dependencies"
                        if operation.record_dependencies
                        or operation.singleton_dependencies
                        or operation.artifact_dependencies
                        else "invoke"
                    ),
                )
            if operation.safe_projection:
                _add_contract(contracts, operation.adapter_slot, "project")
            if operation.safe_payload_projection_id is not None:
                _add_contract(
                    contracts,
                    operation.adapter_slot,
                    "project_safe_payload",
                )
            if operation.returns_lease:
                if not operation.artifact_dependencies:
                    _add_contract(
                        contracts,
                        operation.adapter_slot,
                        (
                            "bind_source_with_dependencies"
                            if operation.record_dependencies
                            or operation.singleton_dependencies
                            else "bind_source"
                        ),
                    )
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
                "readProtected",
                "reconcileNode",
                "reconcileNodeDefinition",
                "writeProtected",
            )
            if field.state_authority is ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW:
                _add_contract(
                    contracts,
                    field.browser_adapter,
                    *_BROWSER_EXTERNAL_TRANSITION_METHODS,
                )
            if field.legacy_reader_ids:
                _add_contract(
                    contracts,
                    field.browser_adapter,
                    "writeWorkflowProjection",
                )
        for operation in self.protected_operations:
            if operation.external_operation_binding is not None:
                _add_contract(
                    contracts,
                    operation.external_operation_binding.browser_adapter,
                    *_BROWSER_EXTERNAL_OPERATION_METHODS,
                )
        for adapter_id in tuple(contracts):
            _add_contract(contracts, adapter_id, "onPrivacySessionChange")
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
        value = {
            "id": self.id,
            "distribution": self.distribution,
            "contract": self.contract,
            "modeTransitionProtocol": MODE_TRANSITION_PROTOCOL,
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
                field.contract_payload()
                for field in self.protected_fields
            ],
            "legacyBindings": [
                {
                    "id": binding.id,
                    "readerId": binding.reader_id,
                    "resourceId": binding.resource_id,
                    "locationKind": binding.location_kind.value,
                    "locationId": binding.location_id,
                }
                for binding in self.legacy_bindings
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
                for key_import in self.legacy_key_imports
            ],
            "records": [
                {
                    "id": record.id,
                    "resourceId": record.resource_id,
                    "scopeId": record.scope_id,
                    "currentSchema": record.current_schema,
                    "storeAdapter": record.store_adapter,
                    "mutationOperations": list(record.mutation_operations),
                    "safeProjection": list(record.safe_projection),
                    "fixedPrivateLabel": record.fixed_private_label,
                    "revealProjections": [
                        {
                            "operation": projection.operation,
                            "safeFields": list(projection.safe_fields),
                        }
                        for projection in record.projections
                    ],
                }
                for record in self.records
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
                for singleton in self.singletons
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
                for artifact in self.artifacts
            ],
            "subjectModeBindings": [
                {
                    "id": binding.id,
                    "scopeId": binding.scope_id,
                    "inputName": binding.input_name,
                    "nodeTypes": list(binding.node_types),
                }
                for binding in self.subject_mode_bindings
            ],
            "protectedOperations": [
                _canonical_protected_operation(operation)
                for operation in self.protected_operations
            ],
            "executionProjections": [
                {
                    "id": projection.id,
                    "executionResourceId": projection.execution_resource_id,
                    "workflowResourceId": projection.workflow_resource_id,
                    "projectionAdapter": projection.projection_adapter,
                    "dispatchAdapter": projection.dispatch_adapter,
                    "subjectModeBindingId": projection.subject_mode_binding_id,
                    "inputName": projection.input_name,
                }
                for projection in self.execution_projections
            ],
        }
        if self.record_reference_migrations:
            value["recordReferenceMigrations"] = [
                {
                    "id": migration.id,
                    "resourceId": migration.resource_id,
                    "recordKind": migration.record_kind,
                    "legacyBindingId": migration.legacy_binding_id,
                }
                for migration in self.record_reference_migrations
            ]
        if self.opaque_reference_kinds:
            value["opaqueReferenceKinds"] = [
                {
                    "id": item.id,
                    "resourceId": item.resource_id,
                    "scopeId": item.scope_id,
                }
                for item in self.opaque_reference_kinds
            ]
        if self.safe_payload_projections:
            value["safePayloadProjections"] = [
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
                for item in self.safe_payload_projections
            ]
        return value


def _canonical_adapter(slot: AdapterSlot) -> dict[str, object]:
    return {
        "id": slot.id,
        "capability": slot.capability.value,
        "resourceId": slot.resource_id,
        "nodeTypes": list(slot.node_types),
    }


def _canonical_protected_operation(operation: ProtectedOperation) -> dict[str, object]:
    value: dict[str, object] = {
        "id": operation.id,
        "resourceId": operation.resource_id,
        "adapterSlot": operation.adapter_slot,
        "route": operation.route,
        "method": operation.method,
        "scopeId": operation.scope_id,
        "sensitiveFields": [
            {"path": field.path, "class": field.field_class.value}
            for field in operation.sensitive_fields
        ],
        "safeProjection": [
            {"path": field.path, "kind": field.kind.value}
            for field in operation.safe_projection
        ],
        "subjectModeBindingId": operation.subject_mode_binding_id,
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
    if operation.external_operation_binding is not None:
        value["externalOperationBinding"] = {
            "fieldId": operation.external_operation_binding.field_id,
            "browserAdapter": operation.external_operation_binding.browser_adapter,
            "policy": operation.external_operation_binding.policy.contract_payload(),
        }
    return value


def _is_stable_id(value: object) -> bool:
    return isinstance(value, str) and bool(_STABLE_ID.fullmatch(value))


def _validate_stable_id(value: object) -> None:
    if not _is_stable_id(value):
        raise ProfileValidationError("invalid_stable_id")


def _validate_projection_path(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or any(not _is_stable_id(segment) for segment in value.split("."))
    ):
        raise ProfileValidationError("invalid_projection_path")


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
