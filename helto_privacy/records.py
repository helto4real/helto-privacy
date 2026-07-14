"""Sensitive-by-default private record shells, reveals, and mutations."""

from __future__ import annotations

import copy
import hmac
import json
import re
import secrets
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

from ._plaintext import clear_mutable_plaintext
from ._private_response import private_response_headers
from .envelope import PrivacyEnvelopeCodec, PrivacyError
from .guard import (
    AuthorizedPrivacyRequest,
    authorize_privacy_request,
    require_current_authorization,
)
from .mode import EffectivePrivacyMode, ModeTransitionStatus
from .mode_values import (
    ModeValueDisposition,
    ModeValueError,
    PreparedModeValue,
    classify_prepared_value,
    classify_state,
    prepare_state_transition,
    protect_state,
    reveal_state,
)
from .profile import LegacyLocationKind, PrivacyProfile, RecordDeclaration


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
        "PRIVACY_RECORD_MUTATION_FAILED",
        "PRIVACY_RECORD_MUTATION_INVALID",
        "PRIVACY_RECORD_NOT_FOUND",
        "PRIVACY_RECORD_OPERATION_FAILED",
        "PRIVACY_RECORD_OPERATION_INVALID",
        "PRIVACY_RECORD_PROJECTION_FAILED",
        "PRIVACY_RECORD_PROJECTION_INVALID",
        "PRIVACY_RECORD_PROTECTION_FAILED",
        "PRIVACY_RECORD_READ_FAILED",
        "PRIVACY_RECORD_REPLACEMENT_INVALID",
        "PRIVACY_RECORD_REPLACE_FAILED",
        "PRIVACY_RECORD_REVISION_CONFLICT",
        "PRIVACY_RECORD_ROLLBACK_FAILED",
        "PRIVACY_RECORD_VERIFICATION_FAILED",
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
    label: str = PRIVATE_RECORD_LABEL

    @property
    def private(self) -> bool:
        return True

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "private": True,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class PublicRecordShell:
    """Minimal closed shell for a current explicitly public record."""

    id: str = field(repr=False)
    kind: str
    label: str = "Public record"

    @property
    def private(self) -> bool:
        return False

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "private": False,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class RevealedRecord:
    """Authorized, allowlist-validated product projection."""

    value: dict[str, object] = field(repr=False)
    correlation_id: str


@dataclass(frozen=True, slots=True)
class ProtectedRecordValue:
    """A current record envelope produced without committing it."""

    envelope: dict[str, object] = field(repr=False)


@dataclass(frozen=True, slots=True)
class RecordSnapshot:
    """One monotonic record revision and its opaque stored representation."""

    revision: int
    protected: object | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
            or (self.revision == 0 and self.protected is not None)
        ):
            raise ValueError("Record snapshot is invalid.")
        object.__setattr__(self, "protected", copy.deepcopy(self.protected))


@dataclass(frozen=True, slots=True)
class RecordModeTransitionValue:
    """Restart-classifiable representation rewrite for one record."""

    record_id: str = field(repr=False)
    original: RecordSnapshot = field(repr=False)
    target: RecordSnapshot = field(repr=False)
    prepared: PreparedModeValue = field(repr=False)

    def __post_init__(self) -> None:
        _record_id(self.record_id)
        if (
            not isinstance(self.original, RecordSnapshot)
            or not isinstance(self.target, RecordSnapshot)
            or not isinstance(self.prepared, PreparedModeValue)
            or self.original.protected is None
            or self.target.revision != self.original.revision + 1
        ):
            raise ValueError("Record transition value is invalid.")


@dataclass(frozen=True, slots=True)
class RecordProjectionResult:
    """Authorized projection with an optional product-owned current rewrite."""

    value: Mapping[str, object] = field(repr=False)
    replacement: Mapping[str, object] | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class RecordMutationReceipt:
    """Product-data-free receipt for one confirmed destructive mutation."""

    record_id: str = field(repr=False)
    kind: str
    operation: str
    correlation_id: str


@dataclass(frozen=True, slots=True)
class _LegacyRecordRead:
    binding_id: str
    obligation_id: str


_CONFIRMATION_MARKER = object()
_MISSING = object()
_RECORD_OPERATION_LOCKS_GUARD = Lock()
_RECORD_OPERATION_LOCKS: dict[tuple[str, str], object] = {}


class _RecordMigrationTransaction:
    """Store-adapter transaction used only by the protected migration journal."""

    def __init__(
        self,
        adapter: object,
        record_id: str,
        schema: str,
        *,
        original: RecordSnapshot | object = _MISSING,
        target_mode: EffectivePrivacyMode = EffectivePrivacyMode.PRIVATE,
    ) -> None:
        self._adapter = adapter
        self._record_id = record_id
        self._codec = PrivacyEnvelopeCodec(schema)
        self._original = (
            _MISSING
            if original is _MISSING
            else _copy_record_snapshot(original)
        )
        self._target_mode = target_mode
        self._staged: object = _MISSING
        self._target: RecordSnapshot | object = _MISSING
        self._committed = False
        self._adjuncts_staged = True

    def capture_original(self) -> object:
        if self._original is _MISSING:
            self._original = self._read()
        return _record_snapshot_payload(self._original)

    def stage_current(self, value: object) -> None:
        if not isinstance(value, Mapping):
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
        self._staged = protect_state(
            self._codec.schema,
            copy.deepcopy(value),
            self._target_mode,
        )

    def stage_durable_adjuncts(self, _value: object) -> None:
        self._adjuncts_staged = True

    def commit(self) -> None:
        if self._staged is _MISSING or not self._adjuncts_staged:
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
        if self._original is _MISSING:
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
        self._target = RecordSnapshot(
            self._original.revision + 1,
            self._staged,
        )
        result = self._compare_and_swap(self._original, self._target)
        if result is False:
            raise RecordError("PRIVACY_RECORD_REVISION_CONFLICT")
        if result is not True:
            raise RecordError("PRIVACY_RECORD_REPLACE_FAILED")
        self._committed = True

    def read_back(self):
        from .migration import MigrationVerification

        snapshot = self._read()
        protected = snapshot.protected
        if protected is None:
            return MigrationVerification(
                normalized=None,
                current_format=False,
                durable_artifacts_current=self._adjuncts_staged,
            )
        try:
            normalized = reveal_state(
                self._codec.schema,
                protected,
                self._target_mode,
            )
            current = True
        except ModeValueError:
            normalized = None
            current = False
        return MigrationVerification(
            normalized=normalized,
            current_format=current,
            durable_artifacts_current=self._adjuncts_staged,
        )

    def classify_recovery(self, original: object, expected: object) -> str:
        original_snapshot = _record_snapshot_from_payload(original)
        try:
            current = self._read()
        except Exception:
            raise RecordError("PRIVACY_RECORD_READ_FAILED") from None

        if _record_snapshot_equal(current, original_snapshot) or (
            current.revision == original_snapshot.revision + 2
            and _protected_record_value_equal(
                current.protected,
                original_snapshot.protected,
            )
        ):
            return "original"
        if current.revision != original_snapshot.revision + 1:
            return "diverged"
        try:
            current_mode = classify_state(self._codec.schema, current.protected)
        except ModeValueError:
            return "diverged"
        normalized: object = None
        try:
            normalized = reveal_state(
                self._codec.schema,
                current.protected,
                current_mode,
            )
            if not isinstance(expected, Mapping):
                return "invalid"
            return (
                "expected-current"
                if hmac.compare_digest(
                    _canonical_record_value(normalized),
                    _canonical_record_value(expected),
                )
                else "diverged"
            )
        except Exception:
            return "diverged"
        finally:
            clear_mutable_plaintext(normalized)

    def rollback(self, original: object) -> None:
        original_snapshot = _record_snapshot_from_payload(original)
        current = self._read()
        if _record_snapshot_equal(current, original_snapshot) or (
            current.revision == original_snapshot.revision + 2
            and _protected_record_value_equal(
                current.protected,
                original_snapshot.protected,
            )
        ):
            return
        if (
            current.revision != original_snapshot.revision + 1
            or self._target is _MISSING
            or (
                not _record_snapshot_equal(current, self._target)
                and not self._committed
            )
        ):
            raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED")
        restored = RecordSnapshot(
            current.revision + 1,
            original_snapshot.protected,
        )
        result = self._compare_and_swap(current, restored)
        if result is not True or not _record_snapshot_equal(self._read(), restored):
            raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED")

    def finalize(self, _original: object) -> None:
        self._original = _MISSING
        self._staged = _MISSING
        self._target = _MISSING
        self._committed = False

    def _read(self) -> RecordSnapshot:
        return _read_record_snapshot(self._adapter, self._record_id)

    def _compare_and_swap(
        self,
        expected: RecordSnapshot,
        replacement: RecordSnapshot,
    ) -> bool:
        return _compare_and_swap_record(
            self._adapter,
            self._record_id,
            expected,
            replacement,
        )


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


def record_authorization_for_request(
    *,
    installation,
    profile: PrivacyProfile,
    resource_id: str,
    record_kind: str,
    request,
    operation_id: str,
) -> AuthorizedPrivacyRequest | None:
    """Authorize a private record request or return no privacy capability publicly."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    mode = _effective_mode(installation, declaration.scope_id)
    if mode is EffectivePrivacyMode.PUBLIC:
        return None
    return authorize_privacy_request(
        request,
        operation_id,
        pack_id=profile.id,
    )


def protect_record_value(
    *,
    installation,
    profile: PrivacyProfile,
    resource_id: str,
    record_kind: str,
    value: object,
    authorization: AuthorizedPrivacyRequest,
) -> ProtectedRecordValue:
    """Protect one product-normalized record without committing it."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    mode = _effective_mode(installation, declaration.scope_id)
    _require_authorization_for_mode(
        mode,
        authorization,
        "record.protect",
        profile.id,
    )
    plaintext = copy.deepcopy(value)
    try:
        if not isinstance(plaintext, Mapping):
            raise RecordError("PRIVACY_RECORD_PROTECTION_FAILED")
        envelope = protect_state(declaration.current_schema, plaintext, mode)
        return ProtectedRecordValue(copy.deepcopy(envelope))
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_PROTECTION_FAILED") from None
    finally:
        clear_mutable_plaintext(plaintext)


def mutate_record(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    operation: str,
    value: object,
    authorization: AuthorizedPrivacyRequest,
    record_id: str | None = None,
) -> RecordMutationReceipt:
    """Authorize, normalize, protect, atomically write, and verify a mutation."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    safe_operation = str(operation or "")
    if safe_operation not in declaration.mutation_operations:
        raise RecordError("PRIVACY_RECORD_MUTATION_INVALID")
    mode = _effective_mode(installation, declaration.scope_id)
    _require_authorization_for_mode(
        mode,
        authorization,
        f"record.{safe_operation}",
        profile.id,
    )
    adapter = adapters.get(declaration.store_adapter)
    mutate = getattr(adapter, "mutate", None)
    if not callable(mutate) or not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")

    source_id = None if safe_operation == "create" else _record_id(record_id)
    target_id: str | None = None
    current: object = None
    legacy_source: object = None
    legacy_read: _LegacyRecordRead | None = None
    request_value = copy.deepcopy(value)
    normalized: object = None
    original: RecordSnapshot | object = _MISSING
    bindings = _record_legacy_bindings(profile, resource_id, record_kind)
    operation_lock = _record_operation_lock(profile.id, resource_id)
    try:
        with _legacy_operation_boundary(bindings):
            with operation_lock:
                target_id = (
                    _new_unique_record_id(adapter)
                    if safe_operation in {"create", "duplicate"}
                    else source_id
                )
                if source_id is not None:
                    _recover_record_migration(
                        profile,
                        bindings,
                        adapter,
                        source_id,
                        declaration.current_schema,
                        authorization,
                        f"record.{safe_operation}",
                        mode,
                    )
                    original = _read_record_snapshot(adapter, source_id)
                    if original.protected is None:
                        raise RecordError("PRIVACY_RECORD_NOT_FOUND")
                    current, legacy_read = _read_current_or_legacy_record(
                        profile,
                        declaration,
                        bindings,
                        original.protected,
                        authorization,
                        f"record.{safe_operation}",
                        mode,
                    )
                    legacy_source = copy.deepcopy(current)
                normalized = mutate(current, safe_operation, request_value)
                if not isinstance(normalized, Mapping) or target_id is None:
                    raise RecordError("PRIVACY_RECORD_MUTATION_FAILED")

                if legacy_read is not None:
                    migration_value = (
                        legacy_source
                        if safe_operation == "duplicate"
                        else normalized
                    )
                    _complete_legacy_record(
                        profile,
                        legacy_read,
                        adapter,
                        source_id,
                        declaration.current_schema,
                        original,
                        migration_value,
                        authorization,
                        f"record.{safe_operation}",
                        mode,
                    )
                    if safe_operation != "duplicate":
                        return RecordMutationReceipt(
                            target_id,
                            declaration.id,
                            safe_operation,
                            _correlation_id(),
                        )

                protected = protect_state(
                    declaration.current_schema,
                    normalized,
                    mode,
                )
                target_original = (
                    original
                    if target_id == source_id
                    else _read_record_snapshot(adapter, target_id)
                )
                _commit_current_record(
                    adapter,
                    target_id,
                    protected,
                    normalized,
                    declaration.current_schema,
                    target_original,
                    mode,
                )
                return RecordMutationReceipt(
                    target_id,
                    declaration.id,
                    safe_operation,
                    _correlation_id(),
                )
    except RecordError:
        raise
    except PrivacyError:
        raise RecordError("PRIVACY_RECORD_DECRYPT_FAILED") from None
    except Exception:
        raise RecordError("PRIVACY_RECORD_MUTATION_FAILED") from None
    finally:
        clear_mutable_plaintext(normalized)
        clear_mutable_plaintext(request_value)
        clear_mutable_plaintext(legacy_source)
        clear_mutable_plaintext(current)


def private_record_response_headers(
    *,
    correlation_id: str | None = None,
    download_kind: str | None = None,
) -> dict[str, str]:
    """Return cache-safe private response defaults with generic filenames."""

    correlation = correlation_id or _correlation_id()
    disposition = None
    filename = None
    if download_kind is not None:
        if not isinstance(download_kind, str):
            raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID")
        filename = _GENERIC_FILENAMES.get(download_kind)
        if filename is None:
            raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID")
        disposition = "attachment"
    try:
        return private_response_headers(
            correlation,
            correlation_prefix="hp-record-",
            disposition=disposition,
            filename=filename,
        )
    except ValueError:
        raise RecordError("PRIVACY_RECORD_DIAGNOSTIC_INVALID") from None


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
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
) -> tuple[LockedRecordShell | PublicRecordShell, ...]:
    """List opaque shells after non-decrypting representation classification."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    mode = _effective_mode(installation, declaration.scope_id)
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
    shells: list[LockedRecordShell | PublicRecordShell] = []
    seen: set[str] = set()
    try:
        for value in values:
            record_id = _record_id(value)
            if record_id in seen:
                raise RecordError("PRIVACY_RECORD_ID_INVALID")
            seen.add(record_id)
            try:
                snapshot = _read_record_snapshot(adapter, record_id)
                if (
                    snapshot.protected is None
                    or classify_state(
                        declaration.current_schema,
                        snapshot.protected,
                    )
                    is not mode
                ):
                    raise RecordError("PRIVACY_RECORD_MODE_BLOCKED")
            except RecordError:
                raise
            except ModeValueError:
                raise RecordError("PRIVACY_RECORD_MODE_BLOCKED") from None
            if mode is EffectivePrivacyMode.PRIVATE:
                shells.append(
                    LockedRecordShell(
                        record_id,
                        declaration.id,
                        declaration.fixed_private_label,
                    )
                )
            else:
                shells.append(PublicRecordShell(record_id, declaration.id))
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_LIST_FAILED") from None
    return tuple(sorted(shells, key=lambda shell: shell.id))


def audit_legacy_record_source(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    record_id: str,
    scope_id: str,
    item_id: str,
    binding_id: str,
    authorization: AuthorizedPrivacyRequest,
) -> bool:
    """Check one declared record audit item without exposing reader plaintext."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    require_current_authorization(
        authorization,
        "record.audit",
        pack_id=profile.id,
    )
    _require_stable_scope(installation, declaration.scope_id)
    safe_record_id = _record_id(record_id)
    adapter = adapters.get(declaration.store_adapter)
    if not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    bindings = _record_legacy_bindings(profile, resource_id, record_kind)
    binding = next(
        (candidate for candidate in bindings if candidate.id == binding_id),
        None,
    )
    if binding is None:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    protected: object = None
    try:
        with _legacy_operation_boundary(bindings):
            with _record_operation_lock(profile.id, resource_id):
                snapshot = _read_record_snapshot(adapter, safe_record_id)
                if snapshot.protected is None:
                    raise RecordError("PRIVACY_RECORD_NOT_FOUND")
                protected = copy.deepcopy(snapshot.protected)
                from .migration import MigrationError, _audit_bound_record_legacy

                try:
                    return _audit_bound_record_legacy(
                        profile,
                        scope_id,
                        item_id,
                        binding.id,
                        protected,
                        authorization,
                        operation_id="record.audit",
                    )
                except MigrationError:
                    raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_READ_FAILED") from None
    finally:
        clear_mutable_plaintext(protected)


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
    mode = _effective_mode(installation, declaration.scope_id)
    _require_authorization_for_mode(
        mode,
        authorization,
        f"record.{safe_operation}",
        profile.id,
    )
    safe_record_id = _record_id(record_id)
    adapter = adapters.get(declaration.store_adapter)
    project = getattr(adapter, "project", None)
    if not _record_adapter_supports_cas(adapter) or not callable(project):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")

    plaintext: object = None
    projection: object = None
    replacement: object = None
    protected: object = None
    legacy_read: _LegacyRecordRead | None = None
    bindings = _record_legacy_bindings(profile, resource_id, record_kind)
    operation_lock = _record_operation_lock(profile.id, resource_id)
    try:
        with _legacy_operation_boundary(bindings):
            with operation_lock:
                _recover_record_migration(
                    profile,
                    bindings,
                    adapter,
                    safe_record_id,
                    declaration.current_schema,
                    authorization,
                    f"record.{safe_operation}",
                    mode,
                )
                try:
                    original_snapshot = _read_record_snapshot(adapter, safe_record_id)
                    if original_snapshot.protected is None:
                        raise RecordError("PRIVACY_RECORD_NOT_FOUND")
                    protected = original_snapshot.protected
                except Exception:
                    raise RecordError("PRIVACY_RECORD_READ_FAILED") from None
                plaintext, legacy_read = _read_current_or_legacy_record(
                    profile,
                    declaration,
                    bindings,
                    protected,
                    authorization,
                    f"record.{safe_operation}",
                    mode,
                )
                try:
                    projected = project(plaintext, safe_operation)
                    if isinstance(projected, RecordProjectionResult):
                        projection = projected.value
                        replacement = projected.replacement
                    else:
                        projection = projected
                except Exception:
                    raise RecordError("PRIVACY_RECORD_PROJECTION_FAILED") from None
                value = _safe_projection(projection, reveal_projection.safe_fields)
                if replacement is not None and not isinstance(replacement, Mapping):
                    raise RecordError("PRIVACY_RECORD_PROJECTION_FAILED")
                expected = replacement if replacement is not None else plaintext
                if legacy_read is not None:
                    _complete_legacy_record(
                        profile,
                        legacy_read,
                        adapter,
                        safe_record_id,
                        declaration.current_schema,
                        original_snapshot,
                        expected,
                        authorization,
                        f"record.{safe_operation}",
                        mode,
                    )
                elif replacement is not None:
                    current = protect_state(
                        declaration.current_schema,
                        replacement,
                        mode,
                    )
                    _commit_current_record(
                        adapter,
                        safe_record_id,
                        current,
                        replacement,
                        declaration.current_schema,
                        original_snapshot,
                        mode,
                    )
                return RevealedRecord(value, _correlation_id())
    finally:
        clear_mutable_plaintext(replacement)
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
    mode = _effective_mode(installation, declaration.scope_id)
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
    if not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    bindings = _record_legacy_bindings(profile, resource_id, record_kind)
    try:
        with _legacy_operation_boundary(bindings):
            with _record_operation_lock(profile.id, resource_id):
                original = _read_record_snapshot(adapter, safe_record_id)
                if original.protected is None:
                    raise RecordError("PRIVACY_RECORD_NOT_FOUND")
                _require_record_stored_mode(
                    declaration.current_schema,
                    original.protected,
                    mode,
                )
                _commit_record_tombstone(adapter, safe_record_id, original)
    except RecordError:
        raise
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
    mode = _effective_mode(installation, declaration.scope_id)
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
    protected = _replacement_value(
        declaration.current_schema,
        protected_value,
        mode,
    )
    adapter = adapters.get(declaration.store_adapter)
    if not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    bindings = _record_legacy_bindings(profile, resource_id, record_kind)
    try:
        with _legacy_operation_boundary(bindings):
            with _record_operation_lock(profile.id, resource_id):
                original = _read_record_snapshot(adapter, safe_record_id)
                if original.protected is None:
                    raise RecordError("PRIVACY_RECORD_NOT_FOUND")
                _require_record_stored_mode(
                    declaration.current_schema,
                    original.protected,
                    mode,
                )
                _replace_record_snapshot_exact(
                    adapter,
                    safe_record_id,
                    original,
                    RecordSnapshot(original.revision + 1, protected),
                )
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_REPLACE_FAILED") from None
    return RecordMutationReceipt(
        safe_record_id,
        declaration.id,
        "replace",
        _correlation_id(),
    )


def _record_legacy_bindings(
    profile: PrivacyProfile,
    resource_id: str,
    record_kind: str,
) -> tuple[object, ...]:
    return tuple(
        binding
        for binding in profile.legacy_bindings
        if binding.location_kind is LegacyLocationKind.RECORD
        and binding.resource_id == resource_id
        and binding.location_id == record_kind
    )


@contextmanager
def _legacy_operation_boundary(bindings: tuple[object, ...]):
    if not bindings:
        yield
        return
    from .migration import MigrationError, bound_legacy_operation

    try:
        with bound_legacy_operation():
            yield
    except MigrationError:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None


def _recover_record_migration(
    profile: PrivacyProfile,
    bindings: tuple[object, ...],
    adapter: object,
    record_id: str,
    schema: str,
    authorization: AuthorizedPrivacyRequest,
    operation_id: str,
    target_mode: EffectivePrivacyMode = EffectivePrivacyMode.PRIVATE,
) -> None:
    if not bindings:
        return
    from .migration import MigrationError, _recover_bound_record_legacy

    try:
        _recover_bound_record_legacy(
            profile,
            tuple(str(binding.id) for binding in bindings),
            record_id,
            _RecordMigrationTransaction(
                adapter,
                record_id,
                schema,
                target_mode=target_mode,
            ),
            authorization,
            operation_id=operation_id,
        )
    except MigrationError:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None


def _read_current_or_legacy_record(
    profile: PrivacyProfile,
    declaration: RecordDeclaration,
    bindings: tuple[object, ...],
    protected: object,
    authorization: AuthorizedPrivacyRequest,
    operation_id: str,
    expected_mode: EffectivePrivacyMode = EffectivePrivacyMode.PRIVATE,
) -> tuple[dict[str, object], _LegacyRecordRead | None]:
    try:
        stored_mode = classify_state(declaration.current_schema, protected)
    except ModeValueError:
        stored_mode = None
    if stored_mode is None and _declared_record_schema(protected) in {
        declaration.current_schema,
        "helto.public-state",
    }:
        raise RecordError("PRIVACY_RECORD_DECRYPT_FAILED")
    if stored_mode is not None:
        if stored_mode is not expected_mode:
            raise RecordError("PRIVACY_RECORD_MODE_BLOCKED")
        try:
            return reveal_state(
                declaration.current_schema,
                protected,
                expected_mode,
            ), None
        except ModeValueError:
            raise RecordError("PRIVACY_RECORD_DECRYPT_FAILED") from None
    if not bindings:
        raise RecordError("PRIVACY_RECORD_DECRYPT_FAILED")

    from .migration import (
        MigrationError,
        _discover_bound_record_legacy,
        probe_registered_legacy_value,
    )

    try:
        matching = tuple(
            binding
            for binding in bindings
            if probe_registered_legacy_value(protected, (binding.reader_id,))
        )
        if len(matching) != 1:
            raise MigrationError("legacy_record_reader_ambiguous")
        binding = matching[0]
        discovered = _discover_bound_record_legacy(
            profile,
            binding.id,
            protected,
            authorization,
            operation_id=operation_id,
        )
        if discovered is None or not isinstance(discovered.value, Mapping):
            raise MigrationError("legacy_reader_read_failed")
        normalized = copy.deepcopy(dict(discovered.value))
        return normalized, _LegacyRecordRead(
            str(binding.id),
            discovered.obligation.id,
        )
    except MigrationError:
        raise RecordError("PRIVACY_RECORD_DECRYPT_FAILED") from None


def _declared_record_schema(value: object) -> str | None:
    candidate = value
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except (TypeError, ValueError):
            return None
    if not isinstance(candidate, Mapping):
        return None
    schema = candidate.get("schema")
    return schema if isinstance(schema, str) else None


def _complete_legacy_record(
    profile: PrivacyProfile,
    legacy_read: _LegacyRecordRead,
    adapter: object,
    record_id: str | None,
    schema: str,
    original: object,
    expected: object,
    authorization: AuthorizedPrivacyRequest,
    operation_id: str,
    target_mode: EffectivePrivacyMode = EffectivePrivacyMode.PRIVATE,
) -> None:
    if record_id is None or not isinstance(expected, Mapping):
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    from .migration import MigrationError, _complete_bound_record_legacy

    transaction = _RecordMigrationTransaction(
        adapter,
        record_id,
        schema,
        original=original,
        target_mode=target_mode,
    )
    try:
        _complete_bound_record_legacy(
            profile,
            legacy_read.binding_id,
            legacy_read.obligation_id,
            expected,
            transaction,
            authorization,
            operation_id=operation_id,
            recovery_locator=record_id,
        )
    except MigrationError:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None


def _new_unique_record_id(adapter: object) -> str:
    list_ids = getattr(adapter, "list_ids", None)
    if not callable(list_ids):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    try:
        values = list_ids()
        if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
            raise RecordError("PRIVACY_RECORD_LIST_FAILED")
        existing = {_record_id(value) for value in values}
    except Exception:
        raise RecordError("PRIVACY_RECORD_LIST_FAILED") from None
    for _attempt in range(4):
        candidate = generate_private_record_id()
        if candidate not in existing:
            return candidate
    raise RecordError("PRIVACY_RECORD_ID_INVALID")


def _record_operation_lock(pack_id: str, resource_id: str):
    key = (pack_id, resource_id)
    with _RECORD_OPERATION_LOCKS_GUARD:
        lock = _RECORD_OPERATION_LOCKS.get(key)
        if lock is None:
            lock = Lock()
            _RECORD_OPERATION_LOCKS[key] = lock
        return lock


def _commit_current_record(
    adapter: object,
    record_id: object,
    protected: object,
    expected: object,
    schema: str,
    original: RecordSnapshot,
    expected_mode: EffectivePrivacyMode = EffectivePrivacyMode.PRIVATE,
) -> None:
    safe_record_id = _record_id(record_id)
    if not _record_adapter_supports_cas(adapter) or not isinstance(
        original,
        RecordSnapshot,
    ):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    replacement = RecordSnapshot(original.revision + 1, protected)
    committed = False
    try:
        result = _compare_and_swap_record(
            adapter,
            safe_record_id,
            original,
            replacement,
        )
        if result is False:
            raise RecordError("PRIVACY_RECORD_REVISION_CONFLICT")
        if result is not True:
            raise RecordError("PRIVACY_RECORD_REPLACE_FAILED")
        committed = True
        reopened = _read_record_snapshot(adapter, safe_record_id)
        if not _record_snapshot_equal(reopened, replacement):
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
        revealed = reveal_state(schema, reopened.protected, expected_mode)
        if not hmac.compare_digest(
            _canonical_record_value(revealed),
            _canonical_record_value(expected),
        ):
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    except Exception as exc:
        if (
            isinstance(exc, RecordError)
            and exc.code == "PRIVACY_RECORD_REVISION_CONFLICT"
            and not committed
        ):
            raise
        current = _read_record_snapshot(adapter, safe_record_id)
        if _record_snapshot_equal(current, replacement) or (
            committed and current.revision == replacement.revision
        ):
            _rollback_record_snapshot(
                adapter,
                safe_record_id,
                current,
                original,
            )
        elif not _record_snapshot_equal(current, original):
            raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED") from None
        if isinstance(exc, RecordError):
            raise
        raise RecordError(
            "PRIVACY_RECORD_VERIFICATION_FAILED"
            if committed
            else "PRIVACY_RECORD_REPLACE_FAILED"
        ) from None
    finally:
        if "revealed" in locals():
            clear_mutable_plaintext(revealed)


def _commit_record_tombstone(
    adapter: object,
    record_id: str,
    original: RecordSnapshot,
) -> None:
    replacement = RecordSnapshot(original.revision + 1)
    committed = False
    try:
        result = _compare_and_swap_record(
            adapter,
            record_id,
            original,
            replacement,
        )
        if result is False:
            raise RecordError("PRIVACY_RECORD_REVISION_CONFLICT")
        if result is not True:
            raise RecordError("PRIVACY_RECORD_DELETE_FAILED")
        committed = True
        if not _record_snapshot_equal(
            _read_record_snapshot(adapter, record_id),
            replacement,
        ):
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    except Exception as exc:
        if (
            isinstance(exc, RecordError)
            and exc.code == "PRIVACY_RECORD_REVISION_CONFLICT"
            and not committed
        ):
            raise
        current = _read_record_snapshot(adapter, record_id)
        if _record_snapshot_equal(current, replacement) or (
            committed and current.revision == replacement.revision
        ):
            _rollback_record_snapshot(
                adapter,
                record_id,
                current,
                original,
            )
        elif not _record_snapshot_equal(current, original):
            raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED") from None
        if isinstance(exc, RecordError):
            raise
        raise RecordError(
            "PRIVACY_RECORD_VERIFICATION_FAILED"
            if committed
            else "PRIVACY_RECORD_DELETE_FAILED"
        ) from None


def _canonical_record_value(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None


def _canonical_stored_record_value(value: object) -> bytes:
    if isinstance(value, bytes):
        return b"bytes\0" + value
    if isinstance(value, str):
        try:
            return b"text\0" + value.encode("utf-8")
        except UnicodeError:
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None
    return b"json\0" + _canonical_record_value(value)


def _record_adapter_supports_cas(adapter: object) -> bool:
    return all(
        callable(getattr(adapter, method, None))
        for method in ("read_record", "compare_and_swap_record")
    )


def _read_record_snapshot(adapter: object, record_id: str) -> RecordSnapshot:
    read = getattr(adapter, "read_record", None)
    if not callable(read):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    try:
        snapshot = read(record_id)
    except Exception:
        raise RecordError("PRIVACY_RECORD_READ_FAILED") from None
    return _copy_record_snapshot(snapshot)


def _copy_record_snapshot(value: object) -> RecordSnapshot:
    if not isinstance(value, RecordSnapshot):
        raise RecordError("PRIVACY_RECORD_READ_FAILED")
    try:
        return RecordSnapshot(value.revision, value.protected)
    except Exception:
        raise RecordError("PRIVACY_RECORD_READ_FAILED") from None


def _compare_and_swap_record(
    adapter: object,
    record_id: str,
    expected: RecordSnapshot,
    replacement: RecordSnapshot,
) -> bool:
    compare_and_swap = getattr(adapter, "compare_and_swap_record", None)
    if not callable(compare_and_swap):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    if replacement.revision != expected.revision + 1:
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    return compare_and_swap(
        record_id,
        _copy_record_snapshot(expected),
        _copy_record_snapshot(replacement),
    )


def _record_snapshot_equal(left: object, right: RecordSnapshot) -> bool:
    return (
        isinstance(left, RecordSnapshot)
        and left.revision == right.revision
        and _protected_record_value_equal(left.protected, right.protected)
    )


def _protected_record_value_equal(left: object, right: object) -> bool:
    try:
        return hmac.compare_digest(
            _canonical_stored_record_value(left),
            _canonical_stored_record_value(right),
        )
    except (RecordError, TypeError, ValueError):
        return False


def _rollback_record_snapshot(
    adapter: object,
    record_id: str,
    committed: RecordSnapshot,
    original: RecordSnapshot,
) -> RecordSnapshot:
    restored = RecordSnapshot(committed.revision + 1, original.protected)
    try:
        result = _compare_and_swap_record(
            adapter,
            record_id,
            committed,
            restored,
        )
        if result is not True:
            raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED")
        reopened = _read_record_snapshot(adapter, record_id)
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED") from None
    if not _record_snapshot_equal(reopened, restored):
        raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED")
    return restored


def _replace_record_snapshot_exact(
    adapter: object,
    record_id: str,
    expected: RecordSnapshot,
    replacement: RecordSnapshot,
) -> None:
    committed = False
    try:
        result = _compare_and_swap_record(
            adapter,
            record_id,
            expected,
            replacement,
        )
        if result is False:
            raise RecordError("PRIVACY_RECORD_REVISION_CONFLICT")
        if result is not True:
            raise RecordError("PRIVACY_RECORD_REPLACE_FAILED")
        committed = True
        if not _record_snapshot_equal(
            _read_record_snapshot(adapter, record_id),
            replacement,
        ):
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    except Exception as exc:
        if (
            isinstance(exc, RecordError)
            and exc.code == "PRIVACY_RECORD_REVISION_CONFLICT"
            and not committed
        ):
            raise
        current = _read_record_snapshot(adapter, record_id)
        if _record_snapshot_equal(current, replacement) or (
            committed and current.revision == replacement.revision
        ):
            _rollback_record_snapshot(
                adapter,
                record_id,
                current,
                expected,
            )
        elif not _record_snapshot_equal(current, expected):
            raise RecordError("PRIVACY_RECORD_ROLLBACK_FAILED") from None
        if isinstance(exc, RecordError):
            raise
        raise RecordError(
            "PRIVACY_RECORD_VERIFICATION_FAILED"
            if committed
            else "PRIVACY_RECORD_REPLACE_FAILED"
        ) from None


def _record_snapshot_payload(snapshot: RecordSnapshot) -> dict[str, object]:
    return {
        "revision": snapshot.revision,
        "protected": copy.deepcopy(snapshot.protected),
    }


def _record_snapshot_from_payload(value: object) -> RecordSnapshot:
    if not isinstance(value, Mapping) or set(value) != {"revision", "protected"}:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    try:
        return RecordSnapshot(value["revision"], value["protected"])
    except Exception:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None


def _require_record_stored_mode(
    schema: str,
    protected: object,
    expected_mode: EffectivePrivacyMode,
) -> None:
    try:
        if classify_state(schema, protected) is not expected_mode:
            raise RecordError("PRIVACY_RECORD_MODE_BLOCKED")
    except RecordError:
        raise
    except ModeValueError:
        raise RecordError("PRIVACY_RECORD_MODE_BLOCKED") from None


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


def _replacement_value(
    schema: str,
    value: object,
    expected_mode: EffectivePrivacyMode,
) -> object:
    payload = value
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            raise RecordError("PRIVACY_RECORD_REPLACEMENT_INVALID") from None
    try:
        if classify_state(schema, payload) is not expected_mode:
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


def prepare_record_mode_transition_value(
    *,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    record_id: str,
    prior_mode: EffectivePrivacyMode,
    target_mode: EffectivePrivacyMode,
) -> RecordModeTransitionValue:
    """Prepare one representation rewrite without mutating record storage."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    safe_record_id = _record_id(record_id)
    adapter = adapters.get(declaration.store_adapter)
    if not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    try:
        original = _read_record_snapshot(adapter, safe_record_id)
        if original.protected is None:
            raise RecordError("PRIVACY_RECORD_NOT_FOUND")
        if (
            classify_state(declaration.current_schema, original.protected)
            is not prior_mode
        ):
            raise RecordError("PRIVACY_RECORD_MODE_BLOCKED")
        prepared = prepare_state_transition(
            declaration.current_schema,
            original.protected,
            prior_mode,
            target_mode,
        )
    except RecordError:
        raise
    except Exception:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED") from None
    return RecordModeTransitionValue(
        safe_record_id,
        original,
        RecordSnapshot(original.revision + 1, prepared.target),
        prepared,
    )


def classify_record_mode_transition_value(
    snapshot: RecordSnapshot,
    transition: RecordModeTransitionValue,
) -> ModeValueDisposition:
    """Classify original/target/diverged state after a process restart."""

    if not isinstance(snapshot, RecordSnapshot) or not isinstance(
        transition,
        RecordModeTransitionValue,
    ):
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    disposition = classify_prepared_value(snapshot.protected, transition.prepared)
    if disposition is ModeValueDisposition.ORIGINAL:
        if snapshot.revision not in {
            transition.original.revision,
            transition.target.revision + 1,
        }:
            return ModeValueDisposition.DIVERGED
    elif disposition is ModeValueDisposition.TARGET:
        if snapshot.revision != transition.target.revision:
            return ModeValueDisposition.DIVERGED
    return disposition


def verify_record_mode_transition_value(
    stored: RecordSnapshot,
    transition: RecordModeTransitionValue,
    expected: ModeValueDisposition,
) -> bool:
    """Verify one expected restart disposition without revealing the record."""

    if expected not in {ModeValueDisposition.ORIGINAL, ModeValueDisposition.TARGET}:
        raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
    return classify_record_mode_transition_value(stored, transition) is expected


def commit_record_mode_transition_value(
    *,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    transition: RecordModeTransitionValue,
) -> None:
    """Commit a prepared target idempotently with exact read-back."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    adapter = adapters.get(declaration.store_adapter)
    if not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    with _record_operation_lock(profile.id, resource_id):
        current = _read_record_snapshot(adapter, transition.record_id)
        state = classify_record_mode_transition_value(current, transition)
        if state is ModeValueDisposition.TARGET:
            return
        if state is not ModeValueDisposition.ORIGINAL:
            raise RecordError("PRIVACY_RECORD_VERIFICATION_FAILED")
        if current.revision != transition.original.revision:
            raise RecordError("PRIVACY_RECORD_REVISION_CONFLICT")
        _replace_record_snapshot_exact(
            adapter,
            transition.record_id,
            current,
            transition.target,
        )


def rollback_record_mode_transition_value(
    *,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    transition: RecordModeTransitionValue,
) -> None:
    """Restore the original representation idempotently after commit/restart."""

    declaration = _record_declaration(profile, resource_id, record_kind)
    adapter = adapters.get(declaration.store_adapter)
    if not _record_adapter_supports_cas(adapter):
        raise RecordError("PRIVACY_RECORD_ADAPTER_INVALID")
    with _record_operation_lock(profile.id, resource_id):
        current = _read_record_snapshot(adapter, transition.record_id)
        state = classify_record_mode_transition_value(current, transition)
        if state is ModeValueDisposition.ORIGINAL:
            return
        if state is not ModeValueDisposition.TARGET:
            raise RecordError("PRIVACY_RECORD_REPLACE_FAILED")
        restored = RecordSnapshot(
            current.revision + 1,
            transition.original.protected,
        )
        _replace_record_snapshot_exact(
            adapter,
            transition.record_id,
            current,
            restored,
        )


def _effective_mode(installation, scope_id: str) -> EffectivePrivacyMode:
    from .mode import ModePolicyError, ModeTransitionError
    from .mode_runtime import require_stable_bound_scope, resolve_bound_mode

    scope = next(
        (item for item in installation.profile.scopes if item.id == scope_id),
        None,
    )
    if scope is None:
        raise RecordError("PRIVACY_RECORD_MODE_BLOCKED")
    try:
        require_stable_bound_scope(installation, scope.id)
        resolution = resolve_bound_mode(
            installation,
            scope.mode_resource_id,
            scope.id,
            None,
        )
        if resolution.transition_status is not ModeTransitionStatus.IDLE:
            raise ModeTransitionError("PRIVACY_TRANSITION_BLOCKED")
        require_stable_bound_scope(installation, scope.id)
        return resolution.effective
    except (ModePolicyError, ModeTransitionError):
        raise RecordError("PRIVACY_RECORD_MODE_BLOCKED") from None


def _require_authorization_for_mode(
    mode: EffectivePrivacyMode,
    authorization: AuthorizedPrivacyRequest | None,
    operation_id: str,
    pack_id: str,
) -> None:
    if mode is EffectivePrivacyMode.PUBLIC:
        return
    require_current_authorization(
        authorization,
        operation_id,
        pack_id=pack_id,
    )


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
