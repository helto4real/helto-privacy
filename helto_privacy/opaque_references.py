"""RAM-only opaque references for typed protected operations."""

from __future__ import annotations

import hmac
import copy
import re
import secrets
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from threading import RLock

from .guard import AuthorizedPrivacyRequest, require_current_authorization


OPAQUE_REFERENCE_TTL_SECONDS = 300
OPAQUE_REFERENCE_CAPACITY = 2048
_REFERENCE_ID = re.compile(r"^hp-ref-[A-Za-z0-9_-]{32}$")
_CLAIM_ID = re.compile(r"^hp-ref-claim-[A-Za-z0-9_-]{24}$")
_LOCK = RLock()
_REFERENCES: dict[str, "_ReferenceRecord"] = {}
_CLAIMS: dict[str, str] = {}
_RESERVATIONS: dict[str, int] = {}


class OpaqueReferenceError(RuntimeError):
    """Indistinguishable product-data-free opaque-reference failure."""

    code = "PRIVACY_OPAQUE_REFERENCE_UNAVAILABLE"

    def __init__(self) -> None:
        self.correlation_id = "hp-operation-" + secrets.token_urlsafe(12)
        super().__init__("Opaque private reference is unavailable.")


@dataclass(frozen=True, slots=True)
class OpaqueReferenceCandidate:
    reference_kind_id: str
    value: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ResolvedOpaqueReference:
    reference_id: str = field(repr=False)
    reference_kind_id: str
    value: object = field(repr=False, compare=False)
    claim_id: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ReferenceCapacityReservation:
    token: str | None = field(repr=False)
    count: int


@dataclass(frozen=True, slots=True)
class ProtectedOperationAdapterResult:
    payload: object = field(repr=False, compare=False)
    references: tuple[OpaqueReferenceCandidate, ...] = ()
    safe_payload: object | None = field(default=None, repr=False, compare=False)
    lease: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        values = tuple(self.references)
        if any(not isinstance(item, OpaqueReferenceCandidate) for item in values):
            raise OpaqueReferenceError()
        object.__setattr__(self, "references", values)


@dataclass(frozen=True, slots=True)
class _ReferenceRecord:
    pack_id: str
    profile_fingerprint: str
    resource_id: str
    scope_id: str
    reference_kind_id: str
    permitted_operations: frozenset[str]
    session_fingerprint: bytes = field(repr=False)
    expires_at: float
    value: object = field(repr=False, compare=False)


def issue_operation_references(
    *,
    profile,
    declaration,
    authorization: AuthorizedPrivacyRequest,
    candidates: Iterable[OpaqueReferenceCandidate],
    reservation: ReferenceCapacityReservation,
) -> tuple[dict[str, str], ...]:
    require_current_authorization(
        authorization,
        declaration.id,
        pack_id=profile.id,
    )
    values = tuple(candidates)
    if any(not isinstance(item, OpaqueReferenceCandidate) for item in values):
        raise OpaqueReferenceError()
    expected: list[str] = []
    offset = 0
    for output in declaration.reference_outputs:
        count = 0
        while (
            offset + count < len(values)
            and values[offset + count].reference_kind_id == output.reference_kind_id
        ):
            count += 1
        if count < output.minimum or count > output.maximum:
            raise OpaqueReferenceError()
        expected.extend([output.reference_kind_id] * count)
        offset += count
    if offset != len(values) or tuple(item.reference_kind_id for item in values) != tuple(expected):
        raise OpaqueReferenceError()
    session_fingerprint = getattr(authorization, "_session_fingerprint", None)
    if not isinstance(session_fingerprint, bytes) or len(session_fingerprint) != 32:
        raise OpaqueReferenceError()
    now = time.monotonic()
    shells: list[dict[str, str]] = []
    with _LOCK:
        _expire_locked(now)
        if (
            not isinstance(reservation, ReferenceCapacityReservation)
            or reservation.count < len(values)
            or (reservation.count == 0 and reservation.token is not None)
            or (
                reservation.count > 0
                and _RESERVATIONS.get(reservation.token) != reservation.count
            )
        ):
            raise OpaqueReferenceError()
        pending: list[tuple[str, _ReferenceRecord]] = []
        for candidate in values:
            reference_kind = next(
                (
                    item
                    for item in profile.opaque_reference_kinds
                    if item.id == candidate.reference_kind_id
                    and item.resource_id == declaration.resource_id
                    and item.scope_id == declaration.scope_id
                ),
                None,
            )
            if reference_kind is None:
                raise OpaqueReferenceError()
            permitted = frozenset(
                operation.id
                for operation in profile.protected_operations
                if operation.resource_id == declaration.resource_id
                and operation.scope_id == declaration.scope_id
                and any(
                    reference_input.reference_kind_id == reference_kind.id
                    for reference_input in operation.reference_inputs
                )
            )
            reference_id = _new_reference_id()
            pending.append(
                (
                    reference_id,
                    _ReferenceRecord(
                        profile.id,
                        profile.fingerprint,
                        declaration.resource_id,
                        declaration.scope_id,
                        reference_kind.id,
                        permitted,
                        bytes(session_fingerprint),
                        now + OPAQUE_REFERENCE_TTL_SECONDS,
                        copy.deepcopy(candidate.value),
                    ),
                )
            )
            shells.append({"id": reference_id, "kind": reference_kind.id})
        if reservation.token is not None:
            del _RESERVATIONS[reservation.token]
        _REFERENCES.update(pending)
    return tuple(shells)


def reserve_operation_reference_capacity(count: int) -> ReferenceCapacityReservation:
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise OpaqueReferenceError()
    with _LOCK:
        _expire_locked(time.monotonic())
        if count == 0:
            return ReferenceCapacityReservation(None, 0)
        if (
            len(_REFERENCES)
            + sum(_RESERVATIONS.values())
            + count
            > OPAQUE_REFERENCE_CAPACITY
        ):
            raise OpaqueReferenceError()
        token = "hp-ref-reservation-" + secrets.token_urlsafe(18)
        _RESERVATIONS[token] = count
        return ReferenceCapacityReservation(token, count)


def release_operation_reference_capacity(
    reservation: ReferenceCapacityReservation | None,
) -> None:
    if not isinstance(reservation, ReferenceCapacityReservation):
        return
    if reservation.token is None:
        return
    with _LOCK:
        _RESERVATIONS.pop(reservation.token, None)


def discard_issued_operation_references(shells: object) -> None:
    """Rollback newly issued shells after a surrounding atomic claim fails."""

    if not isinstance(shells, (tuple, list)):
        return
    with _LOCK:
        for shell in shells:
            if isinstance(shell, Mapping):
                reference_id = shell.get("id")
                if isinstance(reference_id, str):
                    _REFERENCES.pop(reference_id, None)
                    _CLAIMS.pop(reference_id, None)


def resolve_operation_references(
    *,
    profile,
    declaration,
    authorization: AuthorizedPrivacyRequest,
    references: object,
) -> dict[str, ResolvedOpaqueReference]:
    require_current_authorization(
        authorization,
        declaration.id,
        pack_id=profile.id,
    )
    if not isinstance(references, Mapping) or set(references) != {
        item.name for item in declaration.reference_inputs
    }:
        raise OpaqueReferenceError()
    session_fingerprint = getattr(authorization, "_session_fingerprint", None)
    if not isinstance(session_fingerprint, bytes):
        raise OpaqueReferenceError()
    now = time.monotonic()
    resolved: dict[str, ResolvedOpaqueReference] = {}
    with _LOCK:
        _expire_locked(now)
        validated: list[tuple[object, str, _ReferenceRecord, object]] = []
        for reference_input in declaration.reference_inputs:
            reference_id = references.get(reference_input.name)
            if not isinstance(reference_id, str) or _REFERENCE_ID.fullmatch(reference_id) is None:
                raise OpaqueReferenceError()
            record = _REFERENCES.get(reference_id)
            if (
                record is None
                or record.pack_id != profile.id
                or record.profile_fingerprint != profile.fingerprint
                or record.resource_id != declaration.resource_id
                or record.scope_id != declaration.scope_id
                or record.reference_kind_id != reference_input.reference_kind_id
                or declaration.id not in record.permitted_operations
                or not hmac.compare_digest(record.session_fingerprint, session_fingerprint)
                or reference_id in _CLAIMS
            ):
                raise OpaqueReferenceError()
            validated.append(
                (
                    reference_input,
                    reference_id,
                    record,
                    copy.deepcopy(record.value),
                )
            )
        claim_id = (
            "hp-ref-claim-" + secrets.token_urlsafe(18)
            if any(item.revoke_on_success for item, *_rest in validated)
            else None
        )
        if claim_id is not None:
            for reference_input, reference_id, _record, _value in validated:
                if reference_input.revoke_on_success:
                    _CLAIMS[reference_id] = claim_id
        for reference_input, reference_id, record, value in validated:
            resolved[reference_input.name] = ResolvedOpaqueReference(
                reference_id,
                record.reference_kind_id,
                value,
                claim_id if reference_input.revoke_on_success else None,
            )
    return resolved


def revoke_operation_references(
    *,
    profile,
    authorization: AuthorizedPrivacyRequest,
    reference_ids: object,
) -> int:
    require_current_authorization(
        authorization,
        "reference.revoke",
        pack_id=profile.id,
    )
    if (
        isinstance(reference_ids, (str, bytes, Mapping))
        or not isinstance(reference_ids, Iterable)
    ):
        raise OpaqueReferenceError()
    values = tuple(reference_ids)
    if (
        not values
        or len(values) > 256
        or any(not isinstance(value, str) for value in values)
        or len(values) != len(set(values))
    ):
        raise OpaqueReferenceError()
    fingerprint = getattr(authorization, "_session_fingerprint", None)
    with _LOCK:
        _expire_locked(time.monotonic())
        records = tuple(_REFERENCES.get(value) for value in values)
        if any(
            not isinstance(value, str)
            or _REFERENCE_ID.fullmatch(value) is None
            or record is None
            or record.pack_id != profile.id
            or record.profile_fingerprint != profile.fingerprint
            or value in _CLAIMS
            or not isinstance(fingerprint, bytes)
            or not hmac.compare_digest(record.session_fingerprint, fingerprint)
            for value, record in zip(values, records, strict=True)
        ):
            raise OpaqueReferenceError()
        for value in values:
            del _REFERENCES[value]
    return len(values)


def revoke_resolved_on_success(declaration, resolved) -> None:
    with _LOCK:
        for reference_input in declaration.reference_inputs:
            if reference_input.revoke_on_success:
                item = resolved.get(reference_input.name)
                if isinstance(item, ResolvedOpaqueReference):
                    if _CLAIMS.get(item.reference_id) == item.claim_id:
                        _CLAIMS.pop(item.reference_id, None)
                        _REFERENCES.pop(item.reference_id, None)


def retain_external_operation_claims(
    declaration,
    resolved: object,
    *,
    lease_seconds: int,
) -> dict[str, str]:
    """Retain exact revocation claims across a browser-owned transaction."""

    if (
        not isinstance(resolved, Mapping)
        or type(lease_seconds) is not int
        or not 30 <= lease_seconds <= 900
    ):
        raise OpaqueReferenceError()
    claims: dict[str, str] = {}
    with _LOCK:
        _expire_locked(time.monotonic())
        for reference_input in declaration.reference_inputs:
            if not reference_input.revoke_on_success:
                continue
            item = resolved.get(reference_input.name)
            if (
                not isinstance(item, ResolvedOpaqueReference)
                or not isinstance(item.claim_id, str)
                or _CLAIM_ID.fullmatch(item.claim_id) is None
                or _CLAIMS.get(item.reference_id) != item.claim_id
                or item.reference_id not in _REFERENCES
            ):
                raise OpaqueReferenceError()
            claims[item.reference_id] = item.claim_id
        if len(claims) != sum(
            item.revoke_on_success for item in declaration.reference_inputs
        ):
            raise OpaqueReferenceError()
        expires_at = time.monotonic() + lease_seconds
        for reference_id in claims:
            _REFERENCES[reference_id] = replace(
                _REFERENCES[reference_id],
                expires_at=max(_REFERENCES[reference_id].expires_at, expires_at),
            )
    return claims


def settle_external_operation_claims(
    *,
    profile,
    declaration,
    authorization: AuthorizedPrivacyRequest,
    claims: object,
    completed: bool,
) -> None:
    """Revoke completed inputs or release rollback claims idempotently."""

    require_current_authorization(
        authorization,
        declaration.id,
        pack_id=profile.id,
    )
    if (
        type(claims) is not dict
        or not isinstance(completed, bool)
        or any(
            not isinstance(reference_id, str)
            or _REFERENCE_ID.fullmatch(reference_id) is None
            or not isinstance(claim_id, str)
            or _CLAIM_ID.fullmatch(claim_id) is None
            for reference_id, claim_id in claims.items()
        )
        or len(claims)
        != sum(item.revoke_on_success for item in declaration.reference_inputs)
    ):
        raise OpaqueReferenceError()
    fingerprint = getattr(authorization, "_session_fingerprint", None)
    with _LOCK:
        _expire_locked(time.monotonic())
        for reference_id, claim_id in claims.items():
            current_claim = _CLAIMS.get(reference_id)
            record = _REFERENCES.get(reference_id)
            if (completed and current_claim not in {None, claim_id}) or (
                record is not None
                and (
                    record.pack_id != profile.id
                    or record.profile_fingerprint != profile.fingerprint
                    or not isinstance(fingerprint, bytes)
                    or not hmac.compare_digest(
                        record.session_fingerprint,
                        fingerprint,
                    )
                )
            ):
                raise OpaqueReferenceError()
        for reference_id, claim_id in claims.items():
            if _CLAIMS.get(reference_id) == claim_id:
                _CLAIMS.pop(reference_id, None)
            if completed:
                _REFERENCES.pop(reference_id, None)


def release_resolved_claims(resolved: object) -> None:
    if not isinstance(resolved, Mapping):
        return
    with _LOCK:
        for item in resolved.values():
            if (
                isinstance(item, ResolvedOpaqueReference)
                and item.claim_id is not None
                and _CLAIMS.get(item.reference_id) == item.claim_id
            ):
                _CLAIMS.pop(item.reference_id, None)


def clear_opaque_references_for_tests() -> None:
    with _LOCK:
        _REFERENCES.clear()
        _CLAIMS.clear()
        _RESERVATIONS.clear()


def invalidate_opaque_reference_session(_reason: str) -> None:
    with _LOCK:
        _REFERENCES.clear()
        _CLAIMS.clear()
        _RESERVATIONS.clear()


def _expire_locked(now: float) -> None:
    for reference_id, record in tuple(_REFERENCES.items()):
        if record.expires_at <= now:
            del _REFERENCES[reference_id]
            _CLAIMS.pop(reference_id, None)


def _new_reference_id() -> str:
    for _attempt in range(4):
        value = "hp-ref-" + secrets.token_urlsafe(24)
        if _REFERENCE_ID.fullmatch(value) is not None and value not in _REFERENCES:
            return value
    raise OpaqueReferenceError()
