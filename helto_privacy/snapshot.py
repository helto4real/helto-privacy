"""Fail-closed workflow envelope disposition and protection services."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Any

from . import keystore
from .envelope import PrivacyEnvelopeCodec, PrivacyError
from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .profile import ProtectedField


class EnvelopeDisposition(str, Enum):
    """Operational usability of one persisted protected value."""

    VERIFIED_CURRENT = "verified-current"
    LOCKED_CURRENT = "locked-current"
    FAILED_CURRENT = "failed-current"
    READABLE_LEGACY = "readable-legacy"
    UNSUPPORTED = "unsupported"


class SnapshotError(RuntimeError):
    """Sanitized snapshot failure safe for routes and consumer integrations."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy snapshot operation could not complete.")


@dataclass(frozen=True, slots=True)
class DispositionResult:
    disposition: EnvelopeDisposition
    identity: str | None = None
    replacement_envelope: dict[str, Any] | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ProtectedFieldResult:
    disposition: EnvelopeDisposition
    envelope: dict[str, Any] = field(repr=False)


_FAILED_LOCK = RLock()
_FAILED_CURRENT: dict[tuple[str, str, str], str] = {}


def inspect_field_disposition(
    *,
    pack_id: str,
    field_declaration: ProtectedField,
    state_adapter: object,
    protected_value: object,
    authorization: AuthorizedPrivacyRequest | None,
) -> DispositionResult:
    """Classify usability through a real decrypt or exact legacy reader."""

    codec = PrivacyEnvelopeCodec(field_declaration.current_schema)
    serialized = _serialized_protected_value(protected_value)
    failure_key = (
        pack_id,
        field_declaration.id,
        hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    )

    if codec.is_encrypted_payload(protected_value):
        with _FAILED_LOCK:
            known_failure = _FAILED_CURRENT.get(failure_key)
        if known_failure is not None and keystore.session_token() is None:
            return DispositionResult(
                EnvelopeDisposition.FAILED_CURRENT,
                identity=known_failure,
            )
        if keystore.session_token() is None:
            return DispositionResult(EnvelopeDisposition.LOCKED_CURRENT)
        _require_snapshot_authorization(
            authorization,
            "snapshot.disposition",
            pack_id,
        )
        try:
            codec.decrypt_state(protected_value)
        except PrivacyError as exc:
            if "PRIVACY_LOCKED" in str(exc):
                return DispositionResult(EnvelopeDisposition.LOCKED_CURRENT)
            with _FAILED_LOCK:
                identity = _FAILED_CURRENT.setdefault(
                    failure_key,
                    secrets.token_urlsafe(18),
                )
            return DispositionResult(
                EnvelopeDisposition.FAILED_CURRENT,
                identity=identity,
            )
        with _FAILED_LOCK:
            _FAILED_CURRENT.pop(failure_key, None)
        return DispositionResult(EnvelopeDisposition.VERIFIED_CURRENT)

    if field_declaration.legacy_reader_ids and protected_value not in (None, ""):
        _require_snapshot_authorization(
            authorization,
            "snapshot.disposition",
            pack_id,
        )
        reader = getattr(state_adapter, "read_legacy", None)
        if callable(reader):
            for reader_id in field_declaration.legacy_reader_ids:
                try:
                    legacy_value = reader(
                        protected_value,
                        reader_id,
                        field_declaration,
                    )
                    normalized = _normalize_state(
                        state_adapter,
                        legacy_value,
                        field_declaration,
                    )
                    replacement = codec.encrypt_state(normalized)
                except Exception:  # noqa: BLE001 - legacy diagnostics are never exposed.
                    continue
                return DispositionResult(
                    EnvelopeDisposition.READABLE_LEGACY,
                    replacement_envelope=replacement,
                )

    return DispositionResult(EnvelopeDisposition.UNSUPPORTED)


def protect_field_value(
    *,
    pack_id: str,
    field_declaration: ProtectedField,
    state_adapter: object,
    value: object,
    authorization: AuthorizedPrivacyRequest,
) -> ProtectedFieldResult:
    """Normalize consumer state and produce only the declared current envelope."""

    _require_snapshot_authorization(authorization, "snapshot.protect", pack_id)
    normalized = _normalize_state(state_adapter, value, field_declaration)
    try:
        envelope = PrivacyEnvelopeCodec(field_declaration.current_schema).encrypt_state(
            normalized
        )
    except Exception as exc:  # noqa: BLE001 - product and crypto diagnostics stay private.
        raise SnapshotError("PRIVACY_SNAPSHOT_PROTECTION_FAILED") from None
    return ProtectedFieldResult(
        EnvelopeDisposition.VERIFIED_CURRENT,
        envelope,
    )


def clear_failed_current_state() -> None:
    """Clear runtime-only failed identities after an explicit recovery boundary."""

    with _FAILED_LOCK:
        _FAILED_CURRENT.clear()


def _normalize_state(
    state_adapter: object,
    value: object,
    field_declaration: ProtectedField,
) -> Mapping[str, Any]:
    normalize = getattr(state_adapter, "normalize", None)
    if not callable(normalize):
        raise SnapshotError("PRIVACY_SNAPSHOT_ADAPTER_INVALID")
    try:
        normalized = normalize(value, field_declaration)
    except Exception:  # noqa: BLE001
        raise SnapshotError("PRIVACY_SNAPSHOT_NORMALIZATION_FAILED") from None
    if not isinstance(normalized, Mapping):
        raise SnapshotError("PRIVACY_SNAPSHOT_NORMALIZATION_FAILED")
    return dict(normalized)


def _require_snapshot_authorization(
    authorization: AuthorizedPrivacyRequest | None,
    operation_id: str,
    pack_id: str,
) -> None:
    require_current_authorization(
        authorization,  # type: ignore[arg-type]
        operation_id,
        pack_id=pack_id,
    )


def _serialized_protected_value(value: object) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return ""
