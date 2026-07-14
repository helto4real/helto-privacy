"""RAM-only, session-bound deferred UI operation associations."""

from __future__ import annotations

import copy
import hmac
import re
import secrets
import time
from dataclasses import dataclass, field
from threading import RLock

from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .mode import EffectivePrivacyMode, ModePolicyError, ModeTransitionError
from .opaque_references import (
    OpaqueReferenceError,
    ProtectedOperationAdapterResult,
    issue_operation_references,
    discard_issued_operation_references,
    release_operation_reference_capacity,
    reserve_operation_reference_capacity,
)
from .protected_operations import (
    ProtectedOperationDispatchResult,
    ProtectedOperationError,
    project_safe_payload,
)


ASSOCIATION_TTL_SECONDS = 300
ASSOCIATION_CAPACITY = 1024
_ASSOCIATION_ID = re.compile(r"^hp-assoc-[A-Za-z0-9_-]{32}$")
_LOCK = RLock()
_ASSOCIATIONS: dict[str, "_AssociationRecord"] = {}
_CLAIMS: dict[str, str] = {}


class AssociationError(RuntimeError):
    code = "PRIVACY_OPERATION_ASSOCIATION_UNAVAILABLE"

    def __init__(self) -> None:
        self.correlation_id = "hp-operation-" + secrets.token_urlsafe(12)
        super().__init__("Deferred privacy operation association is unavailable.")


@dataclass(frozen=True, slots=True, repr=False)
class DeferredOperationAssociation:
    id: str = field(repr=False)

    def __repr__(self) -> str:
        return "DeferredOperationAssociation()"


@dataclass(slots=True)
class _AssociationRecord:
    pack_id: str
    profile_fingerprint: str
    resource_id: str
    operation_id: str
    scope_id: str
    effective: EffectivePrivacyMode
    session_fingerprint: bytes = field(repr=False)
    safe_payload: dict[str, object] | None = field(repr=False)
    reference_candidates: tuple[object, ...] = field(repr=False)
    expires_at: float


def defer_operation_association(
    *,
    installation,
    profile,
    adapters,
    resource_id: str,
    operation_id: str,
    adapter_result: object,
    subject_mode: object,
) -> DeferredOperationAssociation:
    declaration = next(
        (
            item
            for item in profile.protected_operations
            if item.id == operation_id
            and item.resource_id == resource_id
            and item.deferred_ui
        ),
        None,
    )
    if (
        declaration is None
        or declaration.route is not None
        or declaration.scope_id is None
        or declaration.subject_mode_binding_id is None
        or not isinstance(adapter_result, ProtectedOperationAdapterResult)
    ):
        raise AssociationError()
    from .mode_runtime import (
        bound_mode_work_admission,
        require_stable_bound_scope,
        resolve_bound_mode,
    )
    from .subject_mode import SubjectModeLease

    if not isinstance(subject_mode, SubjectModeLease):
        raise AssociationError()
    try:
        adapter = adapters.get(declaration.adapter_slot)
        safe_payload = project_safe_payload(
            profile=profile,
            declaration=declaration,
            adapter=adapter,
            value=adapter_result.safe_payload,
        )
        candidates = tuple(adapter_result.references)
        _validate_deferred_candidates(declaration, candidates)
    except (AssociationError, ProtectedOperationError):
        raise AssociationError() from None
    except Exception:
        raise AssociationError() from None
    scope = next(item for item in profile.scopes if item.id == declaration.scope_id)
    try:
        with bound_mode_work_admission(installation, (declaration.scope_id,)):
            effective, session_fingerprint = subject_mode._deferred_context(
                profile=profile,
                binding_id=declaration.subject_mode_binding_id,
                operation_id=declaration.id,
            )
            current = resolve_bound_mode(
                installation,
                scope.mode_resource_id,
                scope.id,
                None,
            ).effective
            require_stable_bound_scope(installation, declaration.scope_id)
            if current is EffectivePrivacyMode.PRIVATE:
                effective = EffectivePrivacyMode.PRIVATE
            with _LOCK:
                _expire_locked(time.monotonic())
                if len(_ASSOCIATIONS) >= ASSOCIATION_CAPACITY:
                    raise AssociationError()
                association_id = _new_association_id_locked()
                record = _AssociationRecord(
                    profile.id,
                    profile.fingerprint,
                    resource_id,
                    declaration.id,
                    declaration.scope_id,
                    effective,
                    session_fingerprint,
                    copy.deepcopy(safe_payload),
                    copy.deepcopy(candidates),
                    time.monotonic() + ASSOCIATION_TTL_SECONDS,
                )
                _ASSOCIATIONS[association_id] = record
    except (AssociationError, ModePolicyError, ModeTransitionError):
        raise AssociationError() from None
    return DeferredOperationAssociation(association_id)


def association_operation_id(profile, association_id: object) -> str:
    safe_id = _safe_association_id(association_id)
    with _LOCK:
        _expire_locked(time.monotonic())
        record = _ASSOCIATIONS.get(safe_id)
        if (
            record is None
            or safe_id in _CLAIMS
            or record.pack_id != profile.id
            or record.profile_fingerprint != profile.fingerprint
        ):
            raise AssociationError()
        return record.operation_id


def claim_operation_association(
    *,
    installation,
    profile,
    association_id: object,
    authorization: AuthorizedPrivacyRequest,
) -> ProtectedOperationDispatchResult:
    safe_id = _safe_association_id(association_id)
    operation_id = association_operation_id(profile, safe_id)
    require_current_authorization(authorization, operation_id, pack_id=profile.id)
    declaration = next(
        (
            item
            for item in profile.protected_operations
            if item.id == operation_id and item.deferred_ui
        ),
        None,
    )
    fingerprint = getattr(authorization, "_session_fingerprint", None)
    if declaration is None or not isinstance(fingerprint, bytes):
        raise AssociationError()
    from .mode_runtime import require_stable_bound_scope

    reservation = None
    shells = None
    claim_id = "hp-assoc-claim-" + secrets.token_urlsafe(18)
    try:
        require_stable_bound_scope(installation, declaration.scope_id)
        reservation = reserve_operation_reference_capacity(
            sum(item.maximum for item in declaration.reference_outputs)
        )
        with _LOCK:
            _expire_locked(time.monotonic())
            record = _ASSOCIATIONS.get(safe_id)
            if (
                record is None
                or safe_id in _CLAIMS
                or record.pack_id != profile.id
                or record.profile_fingerprint != profile.fingerprint
                or record.operation_id != declaration.id
                or record.scope_id != declaration.scope_id
                or not hmac.compare_digest(record.session_fingerprint, fingerprint)
            ):
                raise AssociationError()
            _CLAIMS[safe_id] = claim_id
            safe_payload = copy.deepcopy(record.safe_payload)
            candidates = copy.deepcopy(record.reference_candidates)
            private = record.effective is EffectivePrivacyMode.PRIVATE
        shells = issue_operation_references(
            profile=profile,
            declaration=declaration,
            authorization=authorization,
            candidates=candidates,
            reservation=reservation,
        )
        reservation = None
        with _LOCK:
            if _CLAIMS.get(safe_id) != claim_id:
                raise AssociationError()
            _CLAIMS.pop(safe_id, None)
            _ASSOCIATIONS.pop(safe_id, None)
        return ProtectedOperationDispatchResult(
            {},
            safe_payload,
            shells,
            private,
            "hp-operation-" + secrets.token_urlsafe(12),
        )
    except BaseException as exc:
        with _LOCK:
            if _CLAIMS.get(safe_id) == claim_id:
                _CLAIMS.pop(safe_id, None)
        discard_issued_operation_references(shells)
        if isinstance(
            exc,
            (
                AssociationError,
                OpaqueReferenceError,
                ModePolicyError,
                ModeTransitionError,
            ),
        ):
            raise AssociationError() from None
        raise
    finally:
        release_operation_reference_capacity(reservation)


def invalidate_association_session(_reason: str = "session-change") -> None:
    with _LOCK:
        _ASSOCIATIONS.clear()
        _CLAIMS.clear()


def prepare_association_mode_transition(installation, scope_id: str, _context) -> None:
    """Block mode drift while UI state still carries a fixed effective mode."""

    with _LOCK:
        _expire_locked(time.monotonic())
        if any(
            record.pack_id == installation.profile.id and record.scope_id == scope_id
            for record in _ASSOCIATIONS.values()
        ):
            raise AssociationError()


def clear_associations_for_tests() -> None:
    invalidate_association_session("test-reset")


def _expire_locked(now: float) -> None:
    for association_id, record in tuple(_ASSOCIATIONS.items()):
        if record.expires_at <= now:
            _ASSOCIATIONS.pop(association_id, None)
            _CLAIMS.pop(association_id, None)


def _new_association_id_locked() -> str:
    for _attempt in range(4):
        value = "hp-assoc-" + secrets.token_urlsafe(24)
        if _ASSOCIATION_ID.fullmatch(value) and value not in _ASSOCIATIONS:
            return value
    raise AssociationError()


def _safe_association_id(value: object) -> str:
    if not isinstance(value, str) or _ASSOCIATION_ID.fullmatch(value) is None:
        raise AssociationError()
    return value


def _validate_deferred_candidates(declaration, candidates: tuple[object, ...]) -> None:
    offset = 0
    for output in declaration.reference_outputs:
        count = 0
        while (
            offset + count < len(candidates)
            and candidates[offset + count].reference_kind_id == output.reference_kind_id
        ):
            count += 1
        if count < output.minimum or count > output.maximum:
            raise AssociationError()
        offset += count
    if offset != len(candidates):
        raise AssociationError()
