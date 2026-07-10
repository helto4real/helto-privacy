"""Server-authoritative privacy mode normalization and floor resolution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ._suite_codec import is_stable_id



class ModePolicyError(ValueError):
    """Product-data-free mode policy declaration failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy mode facts are invalid.")


class DeclaredPrivacyMode(str, Enum):
    INHERIT = "inherit"
    PRIVATE = "private"
    PUBLIC = "public"


class EffectivePrivacyMode(str, Enum):
    PRIVATE = "private"
    PUBLIC = "public"


class PrivacyFloorKind(str, Enum):
    GLOBAL = "global"
    UPSTREAM = "upstream"
    PARENT = "parent"
    RECORD = "record"
    ARTIFACT = "artifact"
    EXECUTION = "execution"
    CURRENT_STATE = "current-state"
    REQUEST = "request"


class ModeTransitionStatus(str, Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    COMMITTING = "committing"
    BLOCKED = "blocked"


class ModeTransitionError(RuntimeError):
    """Sanitized transition failure that never includes product state."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy mode transition did not complete.")


@dataclass(frozen=True, slots=True)
class ModeEvidence:
    source_id: str
    mode: object

    def __post_init__(self) -> None:
        if not is_stable_id(self.source_id):
            raise ModePolicyError("invalid_mode_evidence_id")


@dataclass(frozen=True, slots=True)
class PrivacyFloor:
    kind: PrivacyFloorKind
    source_id: str


@dataclass(frozen=True, slots=True)
class ModeFacts:
    global_mode: object = None
    request_mode: object = None
    current_mode: object = None
    upstream: tuple[ModeEvidence, ...] = ()
    parents: tuple[ModeEvidence, ...] = ()
    records: tuple[ModeEvidence, ...] = ()
    artifacts: tuple[ModeEvidence, ...] = ()
    executions: tuple[ModeEvidence, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "upstream",
            "parents",
            "records",
            "artifacts",
            "executions",
        ):
            value = getattr(self, field_name)
            if isinstance(value, (str, bytes)):
                raise ModePolicyError("invalid_mode_evidence")
            try:
                normalized = tuple(value)
            except TypeError:
                raise ModePolicyError("invalid_mode_evidence") from None
            if any(not isinstance(item, ModeEvidence) for item in normalized):
                raise ModePolicyError("invalid_mode_evidence")
            if len({item.source_id for item in normalized}) != len(normalized):
                raise ModePolicyError("duplicate_mode_evidence")
            object.__setattr__(
                self,
                field_name,
                tuple(sorted(normalized, key=lambda item: item.source_id)),
            )


@dataclass(frozen=True, slots=True)
class ModeResolution:
    declared: DeclaredPrivacyMode
    effective: EffectivePrivacyMode
    inherited_from: str
    floors: tuple[PrivacyFloor, ...]
    transition_status: ModeTransitionStatus = ModeTransitionStatus.IDLE


@dataclass(frozen=True, slots=True)
class ModeTransitionResult:
    scope_id: str
    declared: DeclaredPrivacyMode
    effective: EffectivePrivacyMode
    status: ModeTransitionStatus


@dataclass(frozen=True, slots=True)
class ModeTransitionContext:
    """Product-data-free transaction identity passed to domain adapters."""

    scope_id: str
    transition_id: str
    prior_mode: EffectivePrivacyMode
    target_mode: EffectivePrivacyMode
    target_declared: DeclaredPrivacyMode

    def __post_init__(self) -> None:
        if not is_stable_id(self.scope_id) or not is_stable_id(self.transition_id):
            raise ModePolicyError("invalid_mode_transition_context")
        if (
            not isinstance(self.prior_mode, EffectivePrivacyMode)
            or not isinstance(self.target_mode, EffectivePrivacyMode)
            or not isinstance(self.target_declared, DeclaredPrivacyMode)
        ):
            raise ModePolicyError("invalid_mode_transition_context")


def normalize_declared_mode(value: object) -> DeclaredPrivacyMode:
    """Map consumer and legacy declarations into the closed three-state model."""

    if isinstance(value, DeclaredPrivacyMode):
        return value
    if value is True:
        return DeclaredPrivacyMode.PRIVATE
    if value is False:
        return DeclaredPrivacyMode.PUBLIC
    if isinstance(value, str):
        normalized = value.strip().lower()
        for mode in DeclaredPrivacyMode:
            if normalized == mode.value:
                return mode
    return DeclaredPrivacyMode.INHERIT


def resolve_privacy_mode(
    declared: object,
    facts: ModeFacts | None = None,
) -> ModeResolution:
    """Resolve one effective server mode; private floors always win."""

    facts = facts if isinstance(facts, ModeFacts) else ModeFacts()
    declared_mode = normalize_declared_mode(declared)
    global_mode = normalize_declared_mode(facts.global_mode)
    floors: list[PrivacyFloor] = []

    if _malformed_declaration(facts.global_mode) or global_mode is DeclaredPrivacyMode.PRIVATE:
        floors.append(PrivacyFloor(PrivacyFloorKind.GLOBAL, "global"))

    for kind, evidence in (
        (PrivacyFloorKind.UPSTREAM, facts.upstream),
        (PrivacyFloorKind.PARENT, facts.parents),
        (PrivacyFloorKind.RECORD, facts.records),
        (PrivacyFloorKind.ARTIFACT, facts.artifacts),
        (PrivacyFloorKind.EXECUTION, facts.executions),
    ):
        floors.extend(
            PrivacyFloor(kind, item.source_id)
            for item in evidence
            if _effective_evidence_mode(item.mode) is EffectivePrivacyMode.PRIVATE
        )

    if (
        _effective_evidence_mode(facts.current_mode, missing_public=True)
        is EffectivePrivacyMode.PRIVATE
    ):
        floors.append(
            PrivacyFloor(PrivacyFloorKind.CURRENT_STATE, "current-state")
        )

    request_mode = normalize_declared_mode(facts.request_mode)
    if facts.request_mode is not None and (
        request_mode is DeclaredPrivacyMode.PRIVATE
        or _malformed_declaration(facts.request_mode)
    ):
        floors.append(PrivacyFloor(PrivacyFloorKind.REQUEST, "request"))

    if declared is None:
        candidate = EffectivePrivacyMode.PRIVATE
        inherited_from = "missing-private"
    elif _malformed_declaration(declared):
        candidate = EffectivePrivacyMode.PRIVATE
        inherited_from = "malformed-private"
    elif declared_mode is DeclaredPrivacyMode.PRIVATE:
        candidate = EffectivePrivacyMode.PRIVATE
        inherited_from = "declared-private"
    elif declared_mode is DeclaredPrivacyMode.PUBLIC:
        candidate = EffectivePrivacyMode.PUBLIC
        inherited_from = "declared-public"
    elif global_mode is DeclaredPrivacyMode.PUBLIC:
        candidate = EffectivePrivacyMode.PUBLIC
        inherited_from = "global-public"
    else:
        candidate = EffectivePrivacyMode.PRIVATE
        inherited_from = "base-private"

    return ModeResolution(
        declared=declared_mode,
        effective=(EffectivePrivacyMode.PRIVATE if floors else candidate),
        inherited_from=inherited_from,
        floors=tuple(floors),
    )


def _effective_evidence_mode(
    value: object,
    *,
    missing_public: bool = False,
) -> EffectivePrivacyMode:
    if value is None and missing_public:
        return EffectivePrivacyMode.PUBLIC
    if isinstance(value, EffectivePrivacyMode):
        return value
    normalized = normalize_declared_mode(value)
    if normalized is DeclaredPrivacyMode.PUBLIC:
        return EffectivePrivacyMode.PUBLIC
    return EffectivePrivacyMode.PRIVATE


def _malformed_declaration(value: object) -> bool:
    if value is None or isinstance(value, (bool, DeclaredPrivacyMode)):
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {mode.value for mode in DeclaredPrivacyMode}
    return True
