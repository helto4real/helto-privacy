"""Sensitive-by-default private record shells, reveals, and mutations."""

from __future__ import annotations

import copy
import json
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

from ._plaintext import clear_mutable_plaintext
from .envelope import PrivacyEnvelopeCodec, PrivacyError
from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .profile import PrivacyProfile, RecordDeclaration


PRIVATE_RECORD_LABEL = "Private record"
PRIVACY_DESTRUCTIVE_CONFIRMATION_HEADER = "X-Helto-Privacy-Destructive"
_DIAGNOSTIC_STAGES = frozenset({"list", "reveal", "delete", "replace", "route"})
_GENERIC_FILENAMES = {
    "record": "private-record.json",
    "media": "private-media.bin",
}
_PRIVATE_RECORD_ID = re.compile(r"^hp-rec-[A-Za-z0-9_-]{32}$")
_CORRELATION_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_RECORD_ERROR_CODES = frozenset(
    {
        "PRIVACY_RECORD_ADAPTER_INVALID",
        "PRIVACY_RECORD_CONFIRMATION_REQUIRED",
        "PRIVACY_RECORD_DECLARATION_INVALID",
        "PRIVACY_RECORD_DELETE_FAILED",
        "PRIVACY_RECORD_DECRYPT_FAILED",
        "PRIVACY_RECORD_DIAGNOSTIC_INVALID",
        "PRIVACY_RECORD_ID_INVALID",
        "PRIVACY_RECORD_LIST_FAILED",
        "PRIVACY_RECORD_MODE_BLOCKED",
        "PRIVACY_RECORD_OPERATION_FAILED",
        "PRIVACY_RECORD_OPERATION_INVALID",
        "PRIVACY_RECORD_PROJECTION_FAILED",
        "PRIVACY_RECORD_PROJECTION_INVALID",
        "PRIVACY_RECORD_READ_FAILED",
        "PRIVACY_RECORD_REPLACEMENT_INVALID",
        "PRIVACY_RECORD_REPLACE_FAILED",
    }
)


class RecordError(RuntimeError):
    """Product-data-free private record failure with an opaque correlation ID."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in _RECORD_ERROR_CODES
            else "PRIVACY_RECORD_OPERATION_FAILED"
        )
        self.correlation_id = "hp-record-" + secrets.token_urlsafe(12)
        super().__init__("Private record operation could not complete.")

    def __repr__(self) -> str:
        return f"RecordError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class LockedRecordShell:
    """Minimal non-decrypting representation of one private record."""

    id: str = field(repr=False)
    kind: str

    @property
    def private(self) -> bool:
        return True

    @property
    def label(self) -> str:
        return PRIVATE_RECORD_LABEL

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "private": True,
            "label": PRIVATE_RECORD_LABEL,
        }


@dataclass(frozen=True, slots=True)
class RevealedRecord:
    """Authorized, allowlist-validated product projection."""

    value: dict[str, object] = field(repr=False)
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RecordMutationReceipt:
    """Product-data-free receipt for one confirmed destructive mutation."""

    record_id: str = field(repr=False)
    kind: str
    operation: str
    correlation_id: str


_CONFIRMATION_MARKER = object()


class _MutationOperation(str, Enum):
    DELETE = "delete"
    REPLACE = "replace"


@dataclass(frozen=True, slots=True)
class _RecordMutationBinding:
    pack_id: str
    resource_id: str
    record_kind: str
    record_id: str = field(repr=False)
    operation: _MutationOperation


class ConfirmedRecordMutation:
    """Opaque, one-use confirmation bound to one destructive record mutation."""

    __slots__ = ("_binding", "_consumed", "_lock")

    def __init__(
        self,
        binding: _RecordMutationBinding,
        *,
        _marker: object | None = None,
    ) -> None:
        if _marker is not _CONFIRMATION_MARKER:
            raise RecordError("PRIVACY_RECORD_CONFIRMATION_REQUIRED")
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_consumed", False)
        object.__setattr__(self, "_lock", Lock())

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("ConfirmedRecordMutation is immutable")

    def __repr__(self) -> str:
        return "ConfirmedRecordMutation()"


def confirm_record_mutation(
    *,
    pack_id: str,
    resource_id: str,
    record_kind: str,
    record_id: str,
    operation: str,
    confirmed: bool,
) -> ConfirmedRecordMutation:
    """Create an opaque confirmation without requiring decryption or unlock."""

    try:
        mutation_operation = _MutationOperation(operation)
    except (TypeError, ValueError):
        raise RecordError("PRIVACY_RECORD_CONFIRMATION_REQUIRED") from None
    if confirmed is not True:
        raise RecordError("PRIVACY_RECORD_CONFIRMATION_REQUIRED")
    safe_record_id = _record_id(record_id)
    values = (pack_id, resource_id, record_kind)
    if any(not isinstance(value, str) or not value for value in values):
        raise RecordError("PRIVACY_RECORD_CONFIRMATION_REQUIRED")
    binding = _RecordMutationBinding(
        pack_id,
        resource_id,
        record_kind,
        safe_record_id,
        mutation_operation,
    )
    return ConfirmedRecordMutation(binding, _marker=_CONFIRMATION_MARKER)


def generate_private_record_id() -> str:
    """Mint one opaque record ID whose public shape cannot be a bare hash."""

    record_id = "hp-rec-" + secrets.token_urlsafe(24)
    if _PRIVATE_RECORD_ID.fullmatch(record_id) is None:
        raise RecordError("PRIVACY_RECORD_ID_INVALID")
    return record_id


def private_record_response_headers(
    *,
    correlation_id: str | None = None,
    download_kind: str | None = None,
) -> dict[str, str]:
    """Return cache-safe private response defaults with generic filenames."""

    correlation = correlation_id or _correlation_id()
    if not _valid_correlation_id(correlation):
        raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID")
    headers = {
        "Cache-Control": "private, no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "Vary": "Cookie, X-Helto-Privacy-Token",
        "X-Content-Type-Options": "nosniff",
        "X-Helto-Privacy-Correlation-ID": correlation,
    }
    if download_kind is not None:
        if not isinstance(download_kind, str):
            raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID")
        filename = _GENERIC_FILENAMES.get(download_kind)
        if filename is None:
            raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID")
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return headers


def safe_record_diagnostic(
    *,
    stage: str,
    count: int | None = None,
    flag: bool | None = None,
) -> dict[str, object]:
    """Build one path/value-free diagnostic from coarse allowlisted facts."""

    if (
        not isinstance(stage, str)
        or stage not in _DIAGNOSTIC_STAGES
        or (
            count is not None
            and (not isinstance(count, int) or isinstance(count, bool) or count < 0)
        )
        or (flag is not None and not isinstance(flag, bool))
    ):
        raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID")
    result: dict[str, object] = {
        "correlationId": _correlation_id(),
        "stage": stage,
    }
    if count is not None:
        result["count"] = count
    if flag is not None:
        result["flag"] = flag
    return result


def list_record_shells(
    *,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
) -> tuple[LockedRecordShell, ...]:
    """List opaque shells without calling the protected-record read seam."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    adapter = adapters.get(declaration.store_adapter)
    list_ids = getattr(adapter, "list_ids", None)
    if not callable(list_ids):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    try:
        values = list_ids()
    except Exception:
        raise RecordError("PRIVACY_RECORD_LIST_FAILED") from None
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
        raise RecordError("PRIVACY_RECORD_LIST_FAILED")
    shells: list[LockedRecordShell] = []
    seen: set[str] = set()
    try:
        for value in values:
            record_id = _record_id(value)
            if record_id in seen:
                raise RecordError("PRIVACY_RECORD_ID_INVALID")
            seen.add(record_id)
            shells.append(LockedRecordShell(record_id, declaration.id))
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_LIST_FAILED") from None
    return tuple(sorted(shells, key=lambda shell: shell.id))


def reveal_record(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    record_id: str,
    operation: str,
    authorization: AuthorizedPrivacyRequest,
) -> RevealedRecord:
    """Authorize, decrypt, project, validate, and clear one private record."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    safe_operation = str(operation or "")
    reveal_projection = declaration.projection_for(safe_operation)
    if reveal_projection is None:
        raise RecordError("PRIVACY_RECORD_OPERATION_INVALID")
    require_current_authorization(
        authorization,
        f"record.{safe_operation}",
        pack_id=profile.id,
    )
    _require_stable_scope(installation, declaration.scope_id)
    safe_record_id = _record_id(record_id)
    adapter = adapters.get(declaration.store_adapter)
    read_protected = getattr(adapter, "read_protected", None)
    project = getattr(adapter, "project", None)
    if not callable(read_protected) or not callable(project):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")

    plaintext: object = None
    projection: object = None
    try:
        try:
            protected = read_protected(safe_record_id)
        except Exception:
            raise RecordError("PRIVACY_RECORD_READ_FAILED") from None
        try:
            plaintext = PrivacyEnvelopeCodec(
                declaration.current_schema
            ).decrypt_state(protected)
        except PrivacyError:
            raise RecordError("PRIVACY_RECORD_DECRYPT_FAILED") from None
        try:
            projection = project(plaintext, safe_operation)
        except Exception:
            raise RecordError("PRIVACY_RECORD_PROJECTION_FAILED") from None
        value = _safe_projection(projection, reveal_projection.safe_fields)
        return RevealedRecord(value, _correlation_id())
    finally:
        clear_mutable_plaintext(projection)
        clear_mutable_plaintext(plaintext)


def delete_record(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    record_id: str,
    confirmation: ConfirmedRecordMutation,
) -> RecordMutationReceipt:
    """Delete without reading protected state after one explicit confirmation."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    _require_stable_scope(installation, declaration.scope_id)
    safe_record_id = _record_id(record_id)
    _consume_confirmation(
        confirmation,
        _RecordMutationBinding(
            profile.id,
            resource_id,
            record_kind,
            safe_record_id,
            _MutationOperation.DELETE,
        ),
    )
    adapter = adapters.get(declaration.store_adapter)
    delete = getattr(adapter, "delete", None)
    if not callable(delete):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    try:
        delete(safe_record_id)
    except Exception:
        raise RecordError("PRIVACY_RECORD_DELETE_FAILED") from None
    return RecordMutationReceipt(
        safe_record_id,
        declaration.id,
        "delete",
        _correlation_id(),
    )


def replace_record(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    record_id: str,
    protected_value: object,
    confirmation: ConfirmedRecordMutation,
) -> RecordMutationReceipt:
    """Replace with a current protected envelope without decrypting old or new state."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    _require_stable_scope(installation, declaration.scope_id)
    safe_record_id = _record_id(record_id)
    _consume_confirmation(
        confirmation,
        _RecordMutationBinding(
            profile.id,
            resource_id,
            record_kind,
            safe_record_id,
            _MutationOperation.REPLACE,
        ),
    )
    protected = _replacement_value(declaration.current_schema, protected_value)
    adapter = adapters.get(declaration.store_adapter)
    write_protected = getattr(adapter, "write_protected", None)
    if not callable(write_protected):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    try:
        write_protected(safe_record_id, protected)
    except Exception:
        raise RecordError("PRIVACY_RECORD_REPLACE_FAILED") from None
    return RecordMutationReceipt(
        safe_record_id,
        declaration.id,
        "replace",
        _correlation_id(),
    )


def _record_declaration(
    profile: PrivacyProfile,
    resource_id: str,
    record_kind: str,
) -> RecordDeclaration:
    declaration = next(
        (
            item
            for item in profile.records
            if item.resource_id == resource_id and item.id == record_kind
        ),
        None,
    )
    if declaration is None:
        raise RecordError("PRIVACY_RECORD_DECLARATION_INVALID")
    return declaration


def _record_id(value: object) -> str:
    record_id = value if isinstance(value, str) else ""
    if _PRIVATE_RECORD_ID.fullmatch(record_id) is None:
        raise RecordError("PRIVACY_RECORD_ID_INVALID")
    return record_id


def _consume_confirmation(
    confirmation: ConfirmedRecordMutation,
    binding: _RecordMutationBinding,
) -> None:
    if not isinstance(confirmation, ConfirmedRecordMutation):
        raise RecordError("PRIVACY_RECORD_CONFIRMATION_REQUIRED")
    with confirmation._lock:
        if confirmation._consumed or confirmation._binding != binding:
            raise RecordError("PRIVACY_RECORD_CONFIRMATION_REQUIRED")
        object.__setattr__(confirmation, "_consumed", True)


def _replacement_value(schema: str, value: object) -> object:
    payload = value
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            raise RecordError("PRIVACY_RECORD_REPLACEMENT_INVALID") from None
    try:
        if not PrivacyEnvelopeCodec(schema).is_encrypted_payload(payload):
            raise RecordError("PRIVACY_RECORD_REPLACEMENT_INVALID")
        return copy.deepcopy(value)
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_REPLACEMENT_INVALID") from None


def _safe_projection(
    value: object,
    allowlist: tuple[str, ...],
) -> dict[str, object]:
    try:
        if not isinstance(value, Mapping) or not set(value).issubset(allowlist):
            raise RecordError("PRIVACY_RECORD_PROJECTION_INVALID")
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return copy.deepcopy(dict(value))
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_PROJECTION_INVALID") from None


def _require_stable_scope(installation, scope_id: str) -> None:
    from .mode import ModePolicyError, ModeTransitionError
    from .mode_runtime import require_stable_bound_scope

    try:
        require_stable_bound_scope(installation, scope_id)
    except (ModePolicyError, ModeTransitionError):
        raise RecordError("PRIVACY_RECORD_MODE_BLOCKED") from None


def _correlation_id() -> str:
    return "hp-record-" + secrets.token_urlsafe(12)


def _valid_correlation_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("hp-record-")
        and _CORRELATION_TOKEN.fullmatch(value.removeprefix("hp-record-")) is not None
    )
