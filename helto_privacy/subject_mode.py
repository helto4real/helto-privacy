"""Reusable subject-mode bindings, one-use references, and active leases."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock

from . import keystore
from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .mode import EffectivePrivacyMode
from .profile import PrivacyProfile, SubjectModeBinding


SUBJECT_MODE_REFERENCE_SCHEMA = "helto.subject-mode-reference"
SUBJECT_MODE_REFERENCE_VERSION = 2
_SUBJECT_DOMAIN = b"helto.subject-mode.subject.v2\x00"
_LOCK = RLock()
_PENDING: dict[str, "_Grant"] = {}
_ACTIVE: dict[str, "_Grant"] = {}
_GRANT_TTL_SECONDS = 30.0
_MAX_GRANTS = 1024


class SubjectModeReferenceError(RuntimeError):
    """Sanitized failure for malformed, stale, mismatched, or closed state."""

    code = "PRIVACY_SUBJECT_MODE_REFERENCE_INVALID"

    def __init__(self) -> None:
        super().__init__("Subject privacy mode reference is invalid or expired.")


class _GrantStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"


@dataclass(frozen=True, slots=True)
class PreparedSubjectModeReference:
    reference: dict[str, object] = field(repr=False)
    effective: str


@dataclass(frozen=True, slots=True, repr=False)
class PendingSubjectModeValidation:
    valid: bool
    requires_private_execution: bool = field(repr=False)

    def __repr__(self) -> str:
        return "PendingSubjectModeValidation()"


@dataclass(slots=True)
class _Grant:
    pack_id: str
    profile_fingerprint: str
    binding_id: str
    scope_id: str
    subject_hash: str
    effective: EffectivePrivacyMode
    allowed_operation_ids: tuple[str, ...]
    session_fingerprint: bytes = field(repr=False)
    expires_at: float
    installation: object = field(repr=False)
    status: _GrantStatus = _GrantStatus.PENDING


class SubjectModeLease:
    """Opaque active mode capability reusable only by linked operations."""

    __slots__ = ("_grant_id", "_closed")

    def __init__(self, grant_id: str) -> None:
        self._grant_id = grant_id
        self._closed = False

    def __enter__(self) -> "SubjectModeLease":
        self._require_active()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def close(self) -> None:
        with _LOCK:
            _ACTIVE.pop(self._grant_id, None)
        self._closed = True

    def _require_active(self) -> _Grant:
        if self._closed:
            raise SubjectModeReferenceError()
        with _LOCK:
            grant = _ACTIVE.get(self._grant_id)
            if grant is None or not _grant_is_current(grant):
                _ACTIVE.pop(self._grant_id, None)
                raise SubjectModeReferenceError()
            return grant

    def _effective_for(
        self,
        *,
        profile: PrivacyProfile,
        binding_id: str,
        operation_id: str,
    ) -> EffectivePrivacyMode:
        grant = self._require_active()
        if (
            grant.pack_id != profile.id
            or grant.profile_fingerprint != profile.fingerprint
            or grant.binding_id != binding_id
            or operation_id not in grant.allowed_operation_ids
        ):
            raise SubjectModeReferenceError()
        return grant.effective

    def requires_private_execution(
        self,
        *,
        profile: PrivacyProfile,
        binding_id: str,
    ) -> bool:
        """Report the attested mode only for this lease's exact profile binding."""

        grant = self._require_active()
        if (
            grant.pack_id != profile.id
            or grant.profile_fingerprint != profile.fingerprint
            or grant.binding_id != binding_id
        ):
            raise SubjectModeReferenceError()
        return grant.effective is EffectivePrivacyMode.PRIVATE

    def _deferred_context(
        self,
        *,
        profile: PrivacyProfile,
        binding_id: str,
        operation_id: str,
    ) -> tuple[EffectivePrivacyMode, bytes]:
        grant = self._require_active()
        if (
            grant.pack_id != profile.id
            or grant.profile_fingerprint != profile.fingerprint
            or grant.binding_id != binding_id
            or operation_id not in grant.allowed_operation_ids
        ):
            raise SubjectModeReferenceError()
        return grant.effective, bytes(grant.session_fingerprint)

    def __repr__(self) -> str:
        return "SubjectModeLease()"


def prepare_subject_mode_reference(
    *,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
    subject_id: object,
    effective: EffectivePrivacyMode,
    authorization: AuthorizedPrivacyRequest,
    installation: object,
) -> PreparedSubjectModeReference:
    require_current_authorization(
        authorization,
        "subject-mode.prepare",
        pack_id=profile.id,
    )
    if binding not in profile.subject_mode_bindings:
        raise SubjectModeReferenceError()
    subject_hash = _subject_hash(profile, binding, subject_id)
    fingerprint = getattr(authorization, "_session_fingerprint", None)
    if not isinstance(fingerprint, bytes) or len(fingerprint) != 32:
        raise SubjectModeReferenceError()
    grant_id = secrets.token_urlsafe(32)
    grant = _Grant(
        profile.id,
        profile.fingerprint,
        binding.id,
        binding.scope_id,
        subject_hash,
        effective,
        tuple(
            sorted(
                operation.id
                for operation in profile.protected_operations
                if operation.subject_mode_binding_id == binding.id
            )
        ),
        bytes(fingerprint),
        time.monotonic() + _GRANT_TTL_SECONDS,
        installation,
    )
    with _LOCK:
        _prune_expired_locked()
        require_current_authorization(
            authorization,
            "subject-mode.prepare",
            pack_id=profile.id,
        )
        _require_active_profile(installation, profile)
        if len(_PENDING) + len(_ACTIVE) >= _MAX_GRANTS:
            raise SubjectModeReferenceError()
        _PENDING[grant_id] = grant
    return PreparedSubjectModeReference(
        {
            "schema": SUBJECT_MODE_REFERENCE_SCHEMA,
            "version": SUBJECT_MODE_REFERENCE_VERSION,
            "packId": profile.id,
            "profileFingerprint": profile.fingerprint,
            "bindingId": binding.id,
            "scopeId": binding.scope_id,
            "subject": subject_hash,
            "grant": grant_id,
        },
        effective.value,
    )


def consume_subject_mode_reference(
    reference: object,
    *,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
    subject_id: object,
) -> SubjectModeLease:
    parsed = _validated_reference_shape(reference, profile, binding)
    with _LOCK:
        _prune_expired_locked()
        grant = _PENDING.pop(parsed["grant"], None)
        if (
            grant is None
            or parsed["subject"] != _subject_hash(profile, binding, subject_id)
            or not _grant_matches(grant, parsed, profile, binding)
        ):
            raise SubjectModeReferenceError()
        if not _grant_is_current(grant):
            raise SubjectModeReferenceError()
        grant.status = _GrantStatus.ACTIVE
        _ACTIVE[parsed["grant"]] = grant
    return SubjectModeLease(parsed["grant"])


def validate_pending_subject_mode_reference(
    reference: object,
    *,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
    subject_id: object,
) -> PendingSubjectModeValidation:
    invalid = PendingSubjectModeValidation(False, False)
    try:
        parsed = _validated_reference(reference, profile, binding, subject_id)
        with _LOCK:
            _prune_expired_locked()
            grant = _PENDING.get(parsed["grant"])
            if (
                grant is None
                or not _grant_matches(grant, parsed, profile, binding)
                or not _grant_is_current(grant)
            ):
                return invalid
            return PendingSubjectModeValidation(
                True,
                grant.effective is EffectivePrivacyMode.PRIVATE,
            )
    except Exception:  # noqa: BLE001 - submission diagnostics are deliberately generic.
        return invalid


def validate_subject_mode_reference_for_revoke(
    reference: object,
    *,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
) -> dict[str, object]:
    if not isinstance(reference, dict):
        raise SubjectModeReferenceError()
    parsed = _validated_reference_shape(reference, profile, binding)
    with _LOCK:
        _prune_expired_locked()
        grant = _PENDING.get(parsed["grant"]) or _ACTIVE.get(parsed["grant"])
        if grant is not None and not _grant_matches(grant, parsed, profile, binding):
            raise SubjectModeReferenceError()
    return parsed


def revoke_subject_mode_reference(
    reference: object,
    *,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
    authorization: AuthorizedPrivacyRequest,
) -> bool:
    require_current_authorization(
        authorization,
        "submission-grants.revoke",
        pack_id=profile.id,
    )
    parsed = validate_subject_mode_reference_for_revoke(
        reference,
        profile=profile,
        binding=binding,
    )
    with _LOCK:
        grant = _PENDING.get(parsed["grant"]) or _ACTIVE.get(parsed["grant"])
        if grant is None:
            return False
        if not _grant_is_current(grant):
            raise SubjectModeReferenceError()
        _PENDING.pop(parsed["grant"], None)
        _ACTIVE.pop(parsed["grant"], None)
        return True


def invalidate_subject_mode_session(_reason: str = "session-invalidated") -> None:
    with _LOCK:
        _PENDING.clear()
        _ACTIVE.clear()


def invalidate_subject_mode_profile(pack_id: str) -> None:
    with _LOCK:
        for registry in (_PENDING, _ACTIVE):
            for grant_id in [
                key for key, value in registry.items() if value.pack_id == pack_id
            ]:
                registry.pop(grant_id, None)


def _validated_reference(
    reference: object,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
    subject_id: object,
) -> dict[str, object]:
    parsed = _validated_reference_shape(reference, profile, binding)
    if parsed["subject"] != _subject_hash(profile, binding, subject_id):
        raise SubjectModeReferenceError()
    return parsed


def _validated_reference_shape(
    reference: object,
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
) -> dict[str, object]:
    if not isinstance(reference, dict):
        raise SubjectModeReferenceError()
    parsed = dict(reference)
    expected_keys = {
        "schema",
        "version",
        "packId",
        "profileFingerprint",
        "bindingId",
        "scopeId",
        "subject",
        "grant",
    }
    if (
        set(parsed) != expected_keys
        or parsed.get("schema") != SUBJECT_MODE_REFERENCE_SCHEMA
        or parsed.get("version") != SUBJECT_MODE_REFERENCE_VERSION
        or parsed.get("packId") != profile.id
        or parsed.get("profileFingerprint") != profile.fingerprint
        or parsed.get("bindingId") != binding.id
        or parsed.get("scopeId") != binding.scope_id
        or not _is_hash(parsed.get("subject"))
        or not isinstance(parsed.get("grant"), str)
        or not parsed.get("grant")
    ):
        raise SubjectModeReferenceError()
    return parsed


def _grant_matches(
    grant: _Grant,
    parsed: dict[str, object],
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
) -> bool:
    return (
        grant.pack_id == profile.id
        and grant.profile_fingerprint == profile.fingerprint
        and grant.binding_id == binding.id
        and grant.scope_id == binding.scope_id
        and grant.subject_hash == parsed["subject"]
    )


def _grant_is_current(grant: _Grant) -> bool:
    if grant.expires_at <= time.monotonic():
        return False
    token = keystore.session_token()
    if token is None:
        return False
    try:
        current = hashlib.sha256(token.encode("utf-8")).digest()
        _require_active_profile(grant.installation, None, expected_grant=grant)
        return hmac.compare_digest(grant.session_fingerprint, current)
    except Exception:
        return False


def _subject_hash(
    profile: PrivacyProfile,
    binding: SubjectModeBinding,
    subject_id: object,
) -> str:
    if isinstance(subject_id, bool) or not isinstance(subject_id, (str, int)):
        raise SubjectModeReferenceError()
    try:
        encoded = str(subject_id).encode("utf-8")
    except UnicodeError:
        raise SubjectModeReferenceError() from None
    if not encoded or len(encoded) > 512:
        raise SubjectModeReferenceError()
    return hashlib.sha256(
        b"\x00".join(
            (
                _SUBJECT_DOMAIN,
                profile.id.encode("utf-8"),
                profile.fingerprint.encode("ascii"),
                binding.id.encode("utf-8"),
                binding.scope_id.encode("utf-8"),
                encoded,
            )
        )
    ).hexdigest()


def _is_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _prune_expired_locked() -> None:
    now = time.monotonic()
    for registry in (_PENDING, _ACTIVE):
        for grant_id in [
            key for key, value in registry.items() if value.expires_at <= now
        ]:
            registry.pop(grant_id, None)


def _require_active_profile(
    installation: object,
    profile: PrivacyProfile | None,
    *,
    expected_grant: _Grant | None = None,
) -> None:
    try:
        installed = getattr(installation, "profile")
        status = getattr(getattr(installation, "status"), "value", None)
        expected_id = profile.id if profile is not None else expected_grant.pack_id
        expected_fingerprint = (
            profile.fingerprint
            if profile is not None
            else expected_grant.profile_fingerprint
        )
        if (
            status != "ready"
            or installed.id != expected_id
            or installed.fingerprint != expected_fingerprint
        ):
            raise SubjectModeReferenceError()
    except SubjectModeReferenceError:
        raise
    except Exception:
        raise SubjectModeReferenceError() from None
