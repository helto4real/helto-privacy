"""Shared, read-only legacy discovery with protected migration obligations."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from pathlib import Path
from threading import RLock, local
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keystore
from ._plaintext import clear_mutable_plaintext
from ._atomic_file import atomic_write_private_bytes, sync_parent_directory
from .guard import require_current_authorization
from .keystore import primary_session_key, session_key_for
from ._legacy_key_source import (
    LegacyKeySourceError,
    read_legacy_key_source,
    unlink_unchanged_legacy_key_source,
)
from .profile import LegacyKeyFormat

if TYPE_CHECKING:
    from .profile import LegacyReaderBinding, PrivacyProfile


MIGRATION_STATE_ENV = "HELTO_PRIVACY_MIGRATION_STATE"
MIGRATION_STATE_SCHEMA = "helto.privacy-migration-state"
MIGRATION_STATE_VERSION = 1
_STATE_AAD = f"{MIGRATION_STATE_SCHEMA}|{MIGRATION_STATE_VERSION}".encode("ascii")
EXTERNAL_MIGRATION_TTL_SECONDS = 300
EXTERNAL_MIGRATION_MAX_PER_PACK = 64
EXTERNAL_MIGRATION_MAX_GLOBAL = 256
_EXTERNAL_MIGRATION_MAX_EXACT_BYTES = 16 * 1024 * 1024
_EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES = 8 * 1024 * 1024
_EXTERNAL_MIGRATION_MAX_DEPTH = 32
_EXTERNAL_MIGRATION_MAX_ITEMS = 65_536
_EXTERNAL_MIGRATION_MAX_CONTAINER_ITEMS = 16_384
_EXTERNAL_MIGRATION_MAX_STRING_BYTES = 1 * 1024 * 1024
_EXTERNAL_MIGRATION_MAX_INTEGER_BITS = 4_096
_EXTERNAL_OWNER = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_EXTERNAL_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._~:-]{1,256}$")
_EXTERNAL_TRANSACTION_ID = re.compile(r"^hp-external-[A-Za-z0-9_-]{32}$")
_EXTERNAL_RESUME_TOKEN = re.compile(r"^hp-resume-[A-Za-z0-9_-]{43}$")
_EXTERNAL_EXPORTED_AT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)


class MigrationError(RuntimeError):
    """A stable migration failure that never includes product values or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Legacy privacy migration could not complete safely.")


class AuditItemKind(str, Enum):
    """User-declared legacy audit inventory kinds."""

    WORKFLOW = "workflow"
    LIBRARY = "library"
    EXPORT = "export"
    PACK_STATE = "pack-state"


@dataclass(frozen=True, slots=True)
class AuditItem:
    """One opaque inventory item the user explicitly placed in audit scope."""

    id: str
    kind: AuditItemKind

    def __post_init__(self) -> None:
        from .profile import _validate_stable_id

        _validate_stable_id(self.id)
        if not isinstance(self.kind, AuditItemKind):
            raise MigrationError("invalid_audit_item")


@dataclass(frozen=True, slots=True)
class LegacyReaderUnit:
    """One separately registered exact-format, read-only legacy reader."""

    id: str
    label: str
    reader: object = field(repr=False, compare=False)
    dependencies: tuple[str, ...] = ()
    key_import_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        from .profile import _validate_stable_id

        _validate_stable_id(self.id)
        if not isinstance(self.label, str) or not self.label.strip():
            raise MigrationError("invalid_legacy_reader_label")
        dependencies = _stable_ids(self.dependencies, "duplicate_reader_dependency")
        key_import_ids = _stable_ids(self.key_import_ids, "duplicate_key_import")
        if self.id in dependencies:
            raise MigrationError("legacy_reader_dependency_cycle")
        if any(not callable(getattr(self.reader, name, None)) for name in ("probe", "read")):
            raise MigrationError("invalid_legacy_reader_contract")
        public_callables = {
            name
            for name in dir(self.reader)
            if not name.startswith("_") and callable(getattr(self.reader, name, None))
        }
        if public_callables != {"probe", "read"}:
            raise MigrationError("legacy_reader_has_writer_capability")
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "key_import_ids", key_import_ids)


@dataclass(frozen=True, slots=True)
class MigrationObligation:
    """Safe status for one protected, unresolved legacy discovery."""

    id: str
    reader_id: str
    disposition: str = "unresolved"

    def to_payload(self) -> dict[str, str]:
        return {"obligationId": self.id, "disposition": self.disposition}


@dataclass(frozen=True, slots=True)
class LegacyReadResult:
    """A legacy value whose repr intentionally cannot reveal the value."""

    obligation: MigrationObligation
    value: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class MigrationVerification:
    """Read-back proof returned by the fixed migration transaction contract."""

    normalized: object = field(repr=False, compare=False)
    current_format: bool
    durable_artifacts_current: bool


class ExternalMigrationMode(str, Enum):
    """Closed import behaviors whose rollback authority must not overlap."""

    MERGE = "merge"
    REPLACE = "replace"


@dataclass(frozen=True, slots=True)
class ExternalMigrationContext:
    """Deterministic, product-data-free context for one imported export."""

    mode: ExternalMigrationMode
    exported_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.mode, ExternalMigrationMode):
            raise MigrationError("external_migration_context_invalid")
        if (
            not isinstance(self.exported_at, str)
            or _EXTERNAL_EXPORTED_AT.fullmatch(self.exported_at) is None
        ):
            raise MigrationError("external_migration_context_invalid")


@dataclass(frozen=True, slots=True)
class ExternalMigrationVerification:
    """Consumer read-back proof for a prepared external migration."""

    normalized: object = field(repr=False, compare=False)
    current_exact: bytes = field(repr=False, compare=False)
    reexported_exact: bytes = field(repr=False, compare=False)
    context: ExternalMigrationContext
    current_format: bool
    durable_artifacts_current: bool

    def __post_init__(self) -> None:
        _external_exact_bytes(self.current_exact)
        _external_exact_bytes(self.reexported_exact)
        if not isinstance(self.context, ExternalMigrationContext):
            raise MigrationError("external_migration_verification_invalid")
        if not isinstance(self.current_format, bool) or not isinstance(
            self.durable_artifacts_current,
            bool,
        ):
            raise MigrationError("external_migration_verification_invalid")


@dataclass(frozen=True, slots=True)
class ExternalRollbackVerification:
    """Exact-byte proof that the external owner was restored."""

    current_exact: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _external_exact_bytes(self.current_exact)


@dataclass(frozen=True, slots=True)
class ExternalMigrationStatus:
    """Product-data-free status for one durable external migration."""

    id: str
    obligation_id: str
    disposition: str
    expires_in_seconds: int = 0
    receipt_id: str | None = None

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "transactionId": self.id,
            "obligationId": self.obligation_id,
            "disposition": self.disposition,
            "expiresInSeconds": self.expires_in_seconds,
        }
        if self.receipt_id is not None:
            payload["receiptId"] = self.receipt_id
        return payload


@dataclass(frozen=True, slots=True)
class PreparedExternalMigration:
    """A prepared external migration and its unpersisted resume capability."""

    status: ExternalMigrationStatus
    resume_token: str = field(repr=False, compare=False)

    def to_payload(self) -> dict[str, object]:
        return {**self.status.to_payload(), "resumeToken": self.resume_token}


@dataclass(frozen=True, slots=True)
class ExternalMigrationResume:
    """Authorized private recovery material for one unresolved participant."""

    status: ExternalMigrationStatus
    expected_normalized: object = field(repr=False, compare=False)
    original_exact: bytes = field(repr=False, compare=False)
    context: ExternalMigrationContext = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _external_exact_bytes(self.original_exact)
        if not isinstance(self.context, ExternalMigrationContext):
            raise MigrationError("external_migration_context_invalid")


@dataclass(frozen=True, slots=True)
class MigrationReceipt:
    """Safe proof that current state and durable adjuncts passed read-back."""

    id: str
    obligation_id: str
    disposition: str = "migrated"

    def to_payload(self) -> dict[str, str]:
        return {
            "receiptId": self.id,
            "obligationId": self.obligation_id,
            "disposition": self.disposition,
        }


@dataclass(frozen=True, slots=True)
class MigrationGroupReceipt:
    """One safe receipt shared by an atomic set of migration obligations."""

    id: str
    obligation_ids: tuple[str, ...]
    disposition: str = "migrated"

    def to_payload(self) -> dict[str, object]:
        return {
            "receiptId": self.id,
            "obligationIds": list(self.obligation_ids),
            "disposition": self.disposition,
        }


@dataclass(frozen=True, slots=True)
class RetirementSeal:
    """Safe per-reader seal over one explicit audit scope and discovery epoch."""

    id: str
    scope_id: str
    reader_id: str
    valid: bool

    def to_payload(self) -> dict[str, object]:
        return {
            "sealId": self.id,
            "scopeId": self.scope_id,
            "readerId": self.reader_id,
            "valid": self.valid,
        }


@dataclass(frozen=True, slots=True)
class KeyImportReceipt:
    """Safe status after verified wrapping and plaintext-source unlink."""

    import_id: str
    disposition: str = "verified-and-unlinked"

    def to_payload(self) -> dict[str, str]:
        return {"importId": self.import_id, "disposition": self.disposition}


@dataclass(frozen=True, slots=True)
class ReaderMigrationStatus:
    """Generic product-data-free lifecycle counts for one declared reader."""

    reader_id: str
    label: str
    discovered: int
    resolved: int
    unresolved: int
    sealed: bool


@dataclass(frozen=True, slots=True)
class _ReaderContext:
    unresolved_count: int
    _keys: Mapping[str, bytes] = field(default_factory=dict, repr=False, compare=False)

    def key_for(self, import_id: str) -> bytes:
        key = self._keys.get(import_id)
        if key is None:
            raise MigrationError("legacy_key_import_required")
        return key


@dataclass(frozen=True, slots=True)
class _KeylessProbeContext:
    """Structural probe context that can never provide historical keys."""

    unresolved_count: int = 0

    def key_for(self, _import_id: str) -> bytes:
        raise MigrationError("legacy_key_import_required")


_LOCK = RLock()
_READERS: dict[str, LegacyReaderUnit] = {}
_MIGRATION_TRANSACTION_LOCAL = local()
_RECOVERY_LOCATOR = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _serialized_migration_operation(operation):
    @wraps(operation)
    def serialized(*args, **kwargs):
        with _exclusive_migration_transaction():
            return operation(*args, **kwargs)

    return serialized


@contextmanager
def bound_legacy_operation():
    """Hold the shared migration boundary around one typed product operation."""

    with _exclusive_migration_transaction():
        yield


def register_legacy_reader_units(units: Iterable[LegacyReaderUnit]) -> None:
    """Atomically register a dependency-complete set of immutable readers."""

    try:
        additions = tuple(units)
    except TypeError:
        raise MigrationError("invalid_legacy_reader_set") from None
    if any(not isinstance(unit, LegacyReaderUnit) for unit in additions):
        raise MigrationError("invalid_legacy_reader_set")
    ids = tuple(unit.id for unit in additions)
    if len(ids) != len(set(ids)):
        raise MigrationError("duplicate_legacy_reader")
    with _LOCK:
        proposed = dict(_READERS)
        for unit in additions:
            existing = proposed.get(unit.id)
            if existing is not None and existing != unit:
                raise MigrationError("legacy_reader_conflict")
            proposed[unit.id] = unit
        for unit in proposed.values():
            if any(dependency not in proposed for dependency in unit.dependencies):
                raise MigrationError("missing_legacy_reader_dependency")
        _validate_reader_graph(proposed)
        _READERS.clear()
        _READERS.update(proposed)


def require_registered_readers(profile: PrivacyProfile) -> None:
    """Fail installation if a profile names an unavailable shared reader."""

    with _LOCK:
        units = tuple(_READERS.get(binding.reader_id) for binding in profile.legacy_bindings)
        if any(unit is None for unit in units):
            raise MigrationError("legacy_reader_not_registered")
        declared_imports = {item.import_id for item in profile.legacy_key_imports}
        if any(
            import_id not in declared_imports
            for unit in units
            if unit is not None
            for import_id in unit.key_import_ids
        ):
            raise MigrationError("legacy_key_import_undeclared")


def probe_registered_legacy_value(source: object, reader_ids: Iterable[str]) -> bool:
    """Run only registered structural probes, without reads or migration state."""

    try:
        requested = tuple(reader_ids)
    except TypeError:
        raise MigrationError("invalid_legacy_reader_set") from None
    if any(not isinstance(reader_id, str) for reader_id in requested):
        raise MigrationError("invalid_legacy_reader_set")
    with _LOCK:
        units = tuple(_READERS.get(reader_id) for reader_id in requested)
    if any(unit is None for unit in units):
        raise MigrationError("legacy_reader_not_registered")
    context = _KeylessProbeContext()
    for unit in units:
        try:
            if unit is not None and unit.reader.probe(source, context) is True:
                return True
        except Exception:
            raise MigrationError("legacy_reader_probe_failed") from None
    return False


def reset_migration_runtime_for_tests() -> None:
    """Clear process-only reader registrations; protected state stays on disk."""

    with _LOCK:
        _READERS.clear()


@_serialized_migration_operation
def discover_bound_legacy(
    profile: PrivacyProfile,
    binding_id: str,
    source: object,
    authorization: object,
    *,
    operation_id: str,
) -> LegacyReadResult | None:
    """Shared-reader entry for typed non-record privacy operations."""

    binding = _binding(profile, binding_id)
    _require_typed_bound_operation(binding, operation_id)
    return _read_bound_legacy(profile, binding, source, authorization, operation_id)


@_serialized_migration_operation
def _discover_bound_record_legacy(
    profile: PrivacyProfile,
    binding_id: str,
    source: object,
    authorization: object,
    *,
    operation_id: str,
) -> LegacyReadResult | None:
    binding = _binding(profile, binding_id)
    _require_record_bound_operation(binding, operation_id)
    return _read_bound_legacy(profile, binding, source, authorization, operation_id)


def _read_bound_legacy(
    profile: PrivacyProfile,
    binding: LegacyReaderBinding,
    source: object,
    authorization: object,
    operation_id: str,
) -> LegacyReadResult | None:
    require_current_authorization(
        authorization,
        operation_id,
        pack_id=profile.id,
    )
    return MigrationHandle._read_legacy(
        profile.id,
        binding,
        source,
    )


@_serialized_migration_operation
def _audit_bound_record_legacy(
    profile: PrivacyProfile,
    scope_id: str,
    item_id: str,
    binding_id: str,
    source: object,
    authorization: object,
    *,
    operation_id: str,
) -> bool:
    """Audit one typed source without returning reader plaintext to the caller."""

    binding = _binding(profile, binding_id)
    _require_record_bound_operation(binding, operation_id)
    require_current_authorization(
        authorization,
        operation_id,
        pack_id=profile.id,
    )
    _require_audit_item(
        profile.id,
        scope_id,
        item_id,
        reader_id=binding.reader_id,
    )
    result = MigrationHandle._read_legacy(
        profile.id,
        binding,
        source,
        audit_scope_id=scope_id,
        audit_item_id=item_id,
    )
    try:
        matched = result is not None
    finally:
        if result is not None:
            clear_mutable_plaintext(result.value)
    with _LOCK:
        state = _load_state()
        state_scope_id = _audit_scope_state_id(profile.id, scope_id)
        item = state["auditScopes"][state_scope_id]["items"][item_id]
        item["checked"] = True
        _save_state(state)
    return matched


def complete_bound_legacy(
    profile: PrivacyProfile,
    binding_id: str,
    obligation_id: str,
    expected_normalized: object,
    transaction: object,
    authorization: object,
    *,
    operation_id: str,
    recovery_locator: str,
) -> MigrationReceipt:
    """Complete one non-record migration under its typed product authority."""

    binding = _binding(profile, binding_id)
    _require_typed_bound_operation(binding, operation_id)
    return _complete_bound_legacy(
        profile,
        binding,
        obligation_id,
        expected_normalized,
        transaction,
        authorization,
        operation_id=operation_id,
        recovery_locator=recovery_locator,
        allow_record_bindings=False,
    )


def _complete_bound_record_legacy(
    profile: PrivacyProfile,
    binding_id: str,
    obligation_id: str,
    expected_normalized: object,
    transaction: object,
    authorization: object,
    *,
    operation_id: str,
    recovery_locator: str,
) -> MigrationReceipt:
    binding = _binding(profile, binding_id)
    _require_record_bound_operation(binding, operation_id)
    return _complete_bound_legacy(
        profile,
        binding,
        obligation_id,
        expected_normalized,
        transaction,
        authorization,
        operation_id=operation_id,
        recovery_locator=recovery_locator,
        allow_record_bindings=True,
    )


def _complete_bound_legacy(
    profile: PrivacyProfile,
    binding: LegacyReaderBinding,
    obligation_id: str,
    expected_normalized: object,
    transaction: object,
    authorization: object,
    *,
    operation_id: str,
    recovery_locator: str,
    allow_record_bindings: bool,
) -> MigrationReceipt:
    locator = _recovery_locator(recovery_locator)
    with _exclusive_migration_transaction():
        receipt = MigrationHandle(profile)._complete_many(
            (obligation_id,),
            expected_normalized,
            transaction,
            authorization,
            authorization_operation_id=operation_id,
            required_binding_ids=(binding.id,),
            recovery_locator=locator,
            allow_record_bindings=allow_record_bindings,
        )
    return MigrationReceipt(receipt.id, obligation_id)


def recover_bound_legacy(
    profile: PrivacyProfile,
    binding_ids: Iterable[str],
    recovery_locator: str,
    transaction: object,
    authorization: object,
    *,
    operation_id: str,
) -> bool:
    """Recover one interrupted non-record transaction before product access."""

    return _recover_bound_legacy(
        profile,
        binding_ids,
        recovery_locator,
        transaction,
        authorization,
        operation_id=operation_id,
        allow_record_bindings=False,
    )


def _recover_bound_record_legacy(
    profile: PrivacyProfile,
    binding_ids: Iterable[str],
    recovery_locator: str,
    transaction: object,
    authorization: object,
    *,
    operation_id: str,
) -> bool:
    return _recover_bound_legacy(
        profile,
        binding_ids,
        recovery_locator,
        transaction,
        authorization,
        operation_id=operation_id,
        allow_record_bindings=True,
    )


def _recover_bound_legacy(
    profile: PrivacyProfile,
    binding_ids: Iterable[str],
    recovery_locator: str,
    transaction: object,
    authorization: object,
    *,
    operation_id: str,
    allow_record_bindings: bool,
) -> bool:

    try:
        required_bindings = tuple(sorted(set(binding_ids)))
    except TypeError:
        raise MigrationError("unknown_legacy_binding") from None
    if not required_bindings:
        return False
    bindings = tuple(_binding(profile, binding_id) for binding_id in required_bindings)
    for binding in bindings:
        if allow_record_bindings:
            _require_record_bound_operation(binding, operation_id)
        else:
            _require_typed_bound_operation(binding, operation_id)
    require_current_authorization(
        authorization,
        operation_id,
        pack_id=profile.id,
    )
    locator = _recovery_locator(recovery_locator)
    if any(
        not callable(getattr(transaction, name, None))
        for name in ("classify_recovery", "rollback", "finalize")
    ):
        raise MigrationError("invalid_migration_transaction")

    with _exclusive_migration_transaction():
        with _LOCK:
            state = _load_state()
            obligations = state.get("obligations", {})
            matches = tuple(
                (transaction_id, pending)
                for transaction_id, pending in state.get("transactions", {}).items()
                if isinstance(pending, dict)
                and pending.get("recoveryLocator") == locator
                and any(
                    isinstance(obligations.get(obligation_id), dict)
                    and obligations[obligation_id].get("packId") == profile.id
                    and obligations[obligation_id].get("bindingId")
                    in required_bindings
                    for obligation_id in _pending_obligation_ids(pending)
                )
            )
            if not matches:
                return False
            if len(matches) != 1:
                raise MigrationError("migration_recovery_ambiguous")
            transaction_id, pending = matches[0]
            obligation_ids = _pending_obligation_ids(pending)
            original = _restore_json_value(pending.get("original"))
            expected = _restore_json_value(pending.get("expected"))
            phase = pending.get("phase")

        try:
            recovery_state = transaction.classify_recovery(original, expected)
        except Exception:
            raise MigrationError("migration_recovery_failed") from None
        if recovery_state not in {
            "original",
            "expected-current",
            "diverged",
            "invalid",
        }:
            raise MigrationError("migration_recovery_failed")

        if recovery_state == "invalid":
            try:
                transaction.rollback(original)
            except Exception:
                raise MigrationError("migration_rollback_failed") from None
            with _LOCK:
                state = _load_state()
                _reopen_recovered_obligations(state, obligation_ids)
                state.get("transactions", {}).pop(transaction_id, None)
                _save_state(state)
            return True

        if recovery_state == "diverged":
            with _LOCK:
                state = _load_state()
                state.get("transactions", {}).pop(transaction_id, None)
                _save_state(state)
            return True

        if phase == "prepared" and recovery_state == "original":
            with _LOCK:
                state = _load_state()
                state.get("transactions", {}).pop(transaction_id, None)
                _save_state(state)
            return True

        if phase == "prepared" and recovery_state == "expected-current":
            receipt_id = f"hp-receipt-{secrets.token_hex(16)}"
            with _LOCK:
                state = _load_state()
                items = tuple(
                    state.get("obligations", {}).get(obligation_id)
                    for obligation_id in obligation_ids
                )
                if any(
                    not isinstance(item, dict)
                    or item.get("disposition") != "unresolved"
                    for item in items
                ):
                    raise MigrationError("migration_obligation_closed")
                for item in items:
                    item["disposition"] = "migrated"
                    item["receiptId"] = receipt_id
                state.setdefault("receipts", {})[receipt_id] = {
                    "obligationIds": list(obligation_ids),
                    "readerIds": sorted(
                        {str(item.get("readerId") or "") for item in items}
                    ),
                    "verified": True,
                    "createdAtNs": time.time_ns(),
                }
                state["transactions"][transaction_id]["phase"] = "finalize-pending"
                _save_state(state)
            try:
                transaction.finalize(original)
            except Exception:
                raise MigrationError("migration_finalization_pending") from None
            with _LOCK:
                state = _load_state()
                state.get("transactions", {}).pop(transaction_id, None)
                _save_state(state)
            return True

        if phase != "finalize-pending":
            raise MigrationError("migration_state_invalid")
        if recovery_state == "expected-current":
            try:
                transaction.finalize(original)
            except Exception:
                raise MigrationError("migration_finalization_pending") from None
            with _LOCK:
                state = _load_state()
                state.get("transactions", {}).pop(transaction_id, None)
                _save_state(state)
            return True

        with _LOCK:
            state = _load_state()
            _reopen_recovered_obligations(state, obligation_ids)
            state.get("transactions", {}).pop(transaction_id, None)
            _save_state(state)
        return True


@dataclass(frozen=True, slots=True)
class ExternalMigrationHandle:
    """Typed durable bridge for a product-owned external commit participant."""

    _profile: PrivacyProfile = field(repr=False, compare=False)
    _binding_id: str
    _operation_id: str

    def prepare(
        self,
        obligation_id: str,
        expected_normalized: object,
        original_exact: bytes,
        context: ExternalMigrationContext,
        owner_id: str,
        idempotency_key: str,
        authorization: object,
    ) -> PreparedExternalMigration:
        """Durably prepare before the external owner mutates its current state."""

        self._authorize(authorization)
        owner = _external_owner(owner_id)
        key_value = _external_idempotency_key(idempotency_key)
        exact = _external_exact_bytes(original_exact)
        if not isinstance(context, ExternalMigrationContext):
            raise MigrationError("external_migration_context_invalid")
        expected_canonical = _external_canonical_normalized(expected_normalized)
        try:
            protected_expected = _protect_json_value(expected_normalized)
        except MigrationError:
            raise MigrationError("external_migration_normalized_invalid") from None
        protected_original = _protect_json_value(exact)
        now_ns = time.time_ns()

        with _exclusive_migration_transaction():
            with _LOCK:
                state = _load_state()
                changed = _expire_external_transactions(state, now_ns)
                obligation = state.get("obligations", {}).get(obligation_id)
                if (
                    not isinstance(obligation, dict)
                    or obligation.get("packId") != self._profile.id
                    or obligation.get("bindingId") != self._binding_id
                ):
                    raise MigrationError("unknown_migration_obligation")

                existing, existing_key, existing_resume = _find_external_idempotency(
                    state,
                    self._profile.id,
                    self._operation_id,
                    owner,
                    key_value,
                )
                if existing is not None:
                    request_digest = _external_request_digest(
                        existing_key,
                        obligation_id,
                        self._binding_id,
                        expected_canonical,
                        exact,
                        context,
                    )
                    if not hmac.compare_digest(
                        str(existing.get("requestDigest") or ""),
                        request_digest,
                    ):
                        raise MigrationError("migration_idempotency_conflict")
                    if changed:
                        _save_state(state)
                    return PreparedExternalMigration(
                        _external_status(existing, now_ns),
                        existing_resume,
                    )

                if obligation.get("disposition") != "unresolved":
                    raise MigrationError("migration_obligation_closed")
                active = state.setdefault("externalTransactions", {})
                if any(
                    isinstance(item, dict)
                    and item.get("packId") == self._profile.id
                    and item.get("ownerId") == owner
                    for item in active.values()
                ):
                    raise MigrationError("external_migration_owner_in_progress")
                active_items = tuple(
                    item for item in active.values() if isinstance(item, dict)
                )
                if len(active_items) >= EXTERNAL_MIGRATION_MAX_GLOBAL:
                    raise MigrationError("external_migration_capacity_exceeded")
                if sum(
                    1
                    for item in active_items
                    if item.get("packId") == self._profile.id
                ) >= EXTERNAL_MIGRATION_MAX_PER_PACK:
                    raise MigrationError("external_migration_capacity_exceeded")

                digest_key, digest_key_id = primary_session_key()
                idempotency_digest = _external_idempotency_digest(
                    digest_key,
                    self._profile.id,
                    self._operation_id,
                    owner,
                    key_value,
                )
                resume_token = _external_resume_token(
                    digest_key,
                    self._profile.id,
                    self._operation_id,
                    owner,
                    key_value,
                )
                transaction_id = f"hp-external-{secrets.token_hex(16)}"
                receipt = {
                    "kind": "external",
                    "packId": self._profile.id,
                    "bindingId": self._binding_id,
                    "operationId": self._operation_id,
                    "ownerId": owner,
                    "obligationId": obligation_id,
                    "disposition": "prepared",
                    "mode": context.mode.value,
                    "exportedAt": context.exported_at,
                    "original": protected_original,
                    "expected": protected_expected,
                    "digestKeyId": digest_key_id,
                    "idempotencyDigest": idempotency_digest,
                    "resumeHash": _external_resume_hash(resume_token),
                    "requestDigest": _external_request_digest(
                        digest_key,
                        obligation_id,
                        self._binding_id,
                        expected_canonical,
                        exact,
                        context,
                    ),
                    "originalDigest": _external_value_digest(
                        digest_key,
                        b"original-exact",
                        exact,
                    ),
                    "expectedDigest": _external_value_digest(
                        digest_key,
                        b"expected-normalized",
                        expected_canonical,
                    ),
                    "contextDigest": _external_context_digest(digest_key, context),
                    "preparedAtNs": now_ns,
                    "expiresAtNs": now_ns
                    + EXTERNAL_MIGRATION_TTL_SECONDS * 1_000_000_000,
                }
                active[transaction_id] = receipt
                _save_state(state)
                return PreparedExternalMigration(
                    _external_status(receipt, now_ns, transaction_id=transaction_id),
                    resume_token,
                )

    def status(
        self,
        transaction_id: str,
        owner_id: str,
        resume_token: str,
        authorization: object,
    ) -> ExternalMigrationStatus:
        """Return a product-data-free status, expiring prepared work safely."""

        self._authorize(authorization)
        return self._status_authorized(transaction_id, owner_id, resume_token)

    def resume(
        self,
        transaction_id: str,
        owner_id: str,
        resume_token: str,
        authorization: object,
    ) -> ExternalMigrationResume:
        """Recover private prepared material after caller or process restart."""

        self._authorize(authorization)
        tx_id = _external_transaction_id(transaction_id)
        owner = _external_owner(owner_id)
        token = _external_resume_capability(resume_token)
        now_ns = time.time_ns()
        with _exclusive_migration_transaction():
            with _LOCK:
                state = _load_state()
                changed = _expire_external_transactions(state, now_ns)
                item, completed = _external_owned_item(
                    state,
                    tx_id,
                    self._profile.id,
                    self._binding_id,
                    self._operation_id,
                    owner,
                    token,
                )
                if completed:
                    if changed:
                        _save_state(state)
                    raise MigrationError("external_migration_closed")
                try:
                    context = ExternalMigrationContext(
                        ExternalMigrationMode(str(item.get("mode") or "")),
                        str(item.get("exportedAt") or ""),
                    )
                    original = _restore_json_value(item.get("original"))
                    expected = _restore_json_value(item.get("expected"))
                except (ValueError, MigrationError):
                    raise MigrationError("migration_state_invalid") from None
                if not isinstance(original, bytes):
                    raise MigrationError("migration_state_invalid")
                if changed:
                    _save_state(state)
                return ExternalMigrationResume(
                    _external_status(item, now_ns, transaction_id=tx_id),
                    expected,
                    original,
                    context,
                )

    def finalize(
        self,
        transaction_id: str,
        owner_id: str,
        resume_token: str,
        verification: ExternalMigrationVerification,
        authorization: object,
    ) -> MigrationReceipt:
        """Issue a receipt only after exact current and re-export read-back."""

        self._authorize(authorization)
        if not isinstance(verification, ExternalMigrationVerification):
            raise MigrationError("external_migration_verification_invalid")
        verification_canonical = _external_canonical_normalized(
            verification.normalized
        )
        tx_id = _external_transaction_id(transaction_id)
        owner = _external_owner(owner_id)
        token = _external_resume_capability(resume_token)
        now_ns = time.time_ns()
        with _exclusive_migration_transaction():
            with _LOCK:
                state = _load_state()
                changed = _expire_external_transactions(state, now_ns)
                item, completed = _external_owned_item(
                    state,
                    tx_id,
                    self._profile.id,
                    self._binding_id,
                    self._operation_id,
                    owner,
                    token,
                )
                digest_key = _external_digest_key(item)
                current_digest = _external_value_digest(
                    digest_key,
                    b"final-current-exact",
                    verification.current_exact,
                )
                reexport_digest = _external_value_digest(
                    digest_key,
                    b"final-reexport-exact",
                    verification.reexported_exact,
                )
                normalized_digest = _external_value_digest(
                    digest_key,
                    b"expected-normalized",
                    verification_canonical,
                )
                context_digest = _external_context_digest(
                    digest_key,
                    verification.context,
                )
                if completed:
                    if item.get("disposition") != "migrated":
                        raise MigrationError("external_migration_closed")
                    if not all(
                        hmac.compare_digest(str(item.get(name) or ""), value)
                        for name, value in (
                            ("finalCurrentDigest", current_digest),
                            ("finalReexportDigest", reexport_digest),
                            ("expectedDigest", normalized_digest),
                            ("contextDigest", context_digest),
                        )
                    ):
                        raise MigrationError("migration_idempotency_conflict")
                    if changed:
                        _save_state(state)
                    return MigrationReceipt(
                        str(item.get("receiptId") or ""),
                        str(item.get("obligationId") or ""),
                    )
                if item.get("disposition") != "prepared":
                    if changed:
                        _save_state(state)
                    raise MigrationError("external_migration_rollback_required")
                valid = (
                    verification.current_format is True
                    and verification.durable_artifacts_current is True
                    and hmac.compare_digest(
                        str(item.get("expectedDigest") or ""),
                        normalized_digest,
                    )
                    and hmac.compare_digest(
                        str(item.get("contextDigest") or ""),
                        context_digest,
                    )
                )
                if not valid:
                    item["disposition"] = "rollback-required"
                    item["rollbackRequiredAtNs"] = now_ns
                    _save_state(state)
                    raise MigrationError("external_migration_verification_failed")

                obligation_id = str(item.get("obligationId") or "")
                obligation = state.get("obligations", {}).get(obligation_id)
                if (
                    not isinstance(obligation, dict)
                    or obligation.get("packId") != self._profile.id
                    or obligation.get("bindingId") != self._binding_id
                    or obligation.get("disposition") != "unresolved"
                ):
                    raise MigrationError("migration_obligation_closed")
                receipt_id = f"hp-receipt-{secrets.token_hex(16)}"
                obligation["disposition"] = "migrated"
                obligation["receiptId"] = receipt_id
                state.setdefault("receipts", {})[receipt_id] = {
                    "obligationIds": [obligation_id],
                    "readerIds": [str(obligation.get("readerId") or "")],
                    "verified": True,
                    "createdAtNs": now_ns,
                }
                tombstone = _external_tombstone(item, disposition="migrated")
                tombstone.update(
                    {
                        "receiptId": receipt_id,
                        "finalCurrentDigest": current_digest,
                        "finalReexportDigest": reexport_digest,
                        "completedAtNs": now_ns,
                    }
                )
                state.setdefault("externalTombstones", {})[tx_id] = tombstone
                state.get("externalTransactions", {}).pop(tx_id, None)
                _save_state(state)
                return MigrationReceipt(receipt_id, obligation_id)

    def cancel(
        self,
        transaction_id: str,
        owner_id: str,
        resume_token: str,
        authorization: object,
    ) -> ExternalMigrationStatus:
        """Require exact rollback after a prepared external write is abandoned."""

        self._authorize(authorization)
        tx_id = _external_transaction_id(transaction_id)
        owner = _external_owner(owner_id)
        token = _external_resume_capability(resume_token)
        now_ns = time.time_ns()
        with _exclusive_migration_transaction():
            with _LOCK:
                state = _load_state()
                changed = _expire_external_transactions(state, now_ns)
                item, completed = _external_owned_item(
                    state,
                    tx_id,
                    self._profile.id,
                    self._binding_id,
                    self._operation_id,
                    owner,
                    token,
                )
                if completed:
                    if changed:
                        _save_state(state)
                    return _external_status(item, now_ns, transaction_id=tx_id)
                if item.get("disposition") == "prepared":
                    item["disposition"] = "rollback-required"
                    item["rollbackRequiredAtNs"] = now_ns
                _save_state(state)
                return _external_status(item, now_ns, transaction_id=tx_id)

    def confirm_rollback(
        self,
        transaction_id: str,
        owner_id: str,
        resume_token: str,
        authorization: object,
        *,
        verification: ExternalRollbackVerification,
    ) -> ExternalMigrationStatus:
        """Retire protected prepared state only after exact original-byte restore."""

        self._authorize(authorization)
        if not isinstance(verification, ExternalRollbackVerification):
            raise MigrationError("external_migration_verification_invalid")
        tx_id = _external_transaction_id(transaction_id)
        owner = _external_owner(owner_id)
        token = _external_resume_capability(resume_token)
        now_ns = time.time_ns()
        with _exclusive_migration_transaction():
            with _LOCK:
                state = _load_state()
                changed = _expire_external_transactions(state, now_ns)
                item, completed = _external_owned_item(
                    state,
                    tx_id,
                    self._profile.id,
                    self._binding_id,
                    self._operation_id,
                    owner,
                    token,
                )
                if completed:
                    if item.get("disposition") != "rolled-back":
                        raise MigrationError("external_migration_closed")
                    restored_digest = _external_value_digest(
                        _external_digest_key(item),
                        b"original-exact",
                        verification.current_exact,
                    )
                    if not hmac.compare_digest(
                        str(item.get("restoredDigest") or ""),
                        restored_digest,
                    ):
                        raise MigrationError("migration_idempotency_conflict")
                    if changed:
                        _save_state(state)
                    return _external_status(item, now_ns, transaction_id=tx_id)
                if item.get("disposition") != "rollback-required":
                    raise MigrationError("external_migration_rollback_not_required")
                restored_digest = _external_value_digest(
                    _external_digest_key(item),
                    b"original-exact",
                    verification.current_exact,
                )
                if not hmac.compare_digest(
                    str(item.get("originalDigest") or ""),
                    restored_digest,
                ):
                    raise MigrationError("external_migration_rollback_unverified")
                tombstone = _external_tombstone(item, disposition="rolled-back")
                tombstone.update(
                    {
                        "restoredDigest": restored_digest,
                        "completedAtNs": now_ns,
                    }
                )
                state.setdefault("externalTombstones", {})[tx_id] = tombstone
                state.get("externalTransactions", {}).pop(tx_id, None)
                _save_state(state)
                return _external_status(tombstone, now_ns, transaction_id=tx_id)

    def _status_authorized(
        self,
        transaction_id: str,
        owner_id: str,
        resume_token: str,
    ) -> ExternalMigrationStatus:
        tx_id = _external_transaction_id(transaction_id)
        owner = _external_owner(owner_id)
        token = _external_resume_capability(resume_token)
        now_ns = time.time_ns()
        with _exclusive_migration_transaction():
            with _LOCK:
                state = _load_state()
                changed = _expire_external_transactions(state, now_ns)
                item, _completed = _external_owned_item(
                    state,
                    tx_id,
                    self._profile.id,
                    self._binding_id,
                    self._operation_id,
                    owner,
                    token,
                )
                if changed:
                    _save_state(state)
                return _external_status(item, now_ns, transaction_id=tx_id)

    def _authorize(self, authorization: object) -> None:
        require_current_authorization(
            authorization,
            self._operation_id,
            pack_id=self._profile.id,
        )


@dataclass(frozen=True, slots=True)
class MigrationHandle:
    """Pack-bound migration capability; it owns no product writer adapter."""

    _profile: PrivacyProfile = field(repr=False, compare=False)

    def external(
        self,
        binding_id: str,
        operation_id: str,
    ) -> ExternalMigrationHandle:
        """Bind an external participant to one exact export import operation."""

        binding = _binding(self._profile, binding_id)
        _require_external_bound_operation(binding, operation_id)
        return ExternalMigrationHandle(self._profile, binding_id, operation_id)

    @_serialized_migration_operation
    def discover_and_read(
        self,
        binding_id: str,
        source: object,
        authorization: object,
    ) -> LegacyReadResult | None:
        require_current_authorization(
            authorization,
            "migration.read",
            pack_id=self._profile.id,
        )
        binding = _binding(self._profile, binding_id)
        _require_generic_migration_binding(binding)
        return self._read_legacy(self._profile.id, binding, source)

    @_serialized_migration_operation
    def declare_audit_scope(
        self,
        scope_id: str,
        reader_id: str,
        items: Iterable[AuditItem],
        authorization: object,
    ) -> None:
        """Persist the exact inventory the user chose to audit."""

        from .profile import _validate_stable_id

        require_current_authorization(
            authorization,
            "migration.audit.declare",
            pack_id=self._profile.id,
        )
        _validate_stable_id(scope_id)
        _validate_stable_id(reader_id)
        try:
            declared_items = tuple(items)
        except TypeError:
            raise MigrationError("invalid_audit_scope") from None
        if not declared_items or any(not isinstance(item, AuditItem) for item in declared_items):
            raise MigrationError("invalid_audit_scope")
        item_ids = tuple(item.id for item in declared_items)
        if len(item_ids) != len(set(item_ids)):
            raise MigrationError("duplicate_audit_item")
        with _LOCK:
            if reader_id not in _READERS:
                raise MigrationError("legacy_reader_not_registered")
            state = _load_state()
            scopes = state.setdefault("auditScopes", {})
            state_scope_id = _audit_scope_state_id(self._profile.id, scope_id)
            declaration = {
                "packId": self._profile.id,
                "readerId": reader_id,
                "createdAtNs": time.time_ns(),
                "items": {
                    item.id: {"kind": item.kind.value, "checked": False}
                    for item in declared_items
                },
            }
            existing = scopes.get(state_scope_id)
            if existing is not None:
                existing_inventory = {
                    item_id: item.get("kind")
                    for item_id, item in existing.get("items", {}).items()
                    if isinstance(item, dict)
                } if isinstance(existing, dict) else {}
                declared_inventory = {
                    item_id: item["kind"]
                    for item_id, item in declaration["items"].items()
                }
                if (
                    not isinstance(existing, dict)
                    or existing.get("packId") != self._profile.id
                    or existing.get("readerId") != reader_id
                    or existing_inventory != declared_inventory
                ):
                    raise MigrationError("audit_scope_conflict")
            if existing is None:
                scopes[state_scope_id] = declaration
                _save_state(state)

    @_serialized_migration_operation
    def audit_source(
        self,
        scope_id: str,
        item_id: str,
        binding_id: str,
        source: object,
        authorization: object,
    ) -> LegacyReadResult | None:
        """Run one exact reader over one declared item and record the check."""

        require_current_authorization(
            authorization,
            "migration.audit.read",
            pack_id=self._profile.id,
        )
        binding = _binding(self._profile, binding_id)
        _require_generic_migration_binding(binding)
        _require_audit_item(
            self._profile.id,
            scope_id,
            item_id,
            reader_id=binding.reader_id,
        )
        result = self._read_legacy(
            self._profile.id,
            binding,
            source,
            audit_scope_id=scope_id,
            audit_item_id=item_id,
        )
        with _LOCK:
            state = _load_state()
            state_scope_id = _audit_scope_state_id(self._profile.id, scope_id)
            item = state["auditScopes"][state_scope_id]["items"][item_id]
            item["checked"] = True
            _save_state(state)
        return result

    @_serialized_migration_operation
    def confirm_retirement_seal(
        self,
        scope_id: str,
        reader_id: str,
        authorization: object,
    ) -> RetirementSeal:
        """Seal only a complete declared scope with zero unresolved discoveries."""

        require_current_authorization(
            authorization,
            "migration.audit.seal",
            pack_id=self._profile.id,
        )
        with _LOCK:
            state = _load_state()
            scope = state.get("auditScopes", {}).get(
                _audit_scope_state_id(self._profile.id, scope_id)
            )
            if (
                not isinstance(scope, dict)
                or scope.get("packId") != self._profile.id
                or scope.get("readerId") != reader_id
            ):
                raise MigrationError("unknown_audit_scope")
            items = scope.get("items", {})
            if not isinstance(items, dict) or not items or any(
                not isinstance(item, dict) or item.get("checked") is not True
                for item in items.values()
            ):
                raise MigrationError("audit_scope_incomplete")
            unresolved = any(
                isinstance(item, dict)
                and item.get("packId") == self._profile.id
                and item.get("readerId") == reader_id
                and item.get("disposition") == "unresolved"
                for item in state.get("obligations", {}).values()
            )
            if unresolved:
                raise MigrationError("audit_scope_has_unresolved_migrations")
            obligations = state.get("obligations", {})
            if any(
                isinstance(pending, dict)
                and pending.get("phase") == "finalize-pending"
                and any(
                    isinstance(obligations.get(obligation_id), dict)
                    and obligations[obligation_id].get("readerId") == reader_id
                    for obligation_id in _pending_obligation_ids(pending)
                )
                for pending in state.get("transactions", {}).values()
            ):
                raise MigrationError("audit_scope_has_pending_finalization")
            unit = _READERS.get(reader_id)
            if unit is None:
                raise MigrationError("legacy_reader_not_registered")
            imports = state.get("keyImports", {})
            if any(
                not isinstance(
                    imports.get(_key_import_state_id(self._profile.id, import_id)),
                    dict,
                )
                or imports[_key_import_state_id(self._profile.id, import_id)].get(
                    "disposition"
                )
                != "complete"
                for import_id in unit.key_import_ids
            ):
                raise MigrationError("legacy_key_import_required")
            epoch = int(state.get("readerEpochs", {}).get(reader_id, 0))
            seal_id = f"hp-seal-{secrets.token_hex(16)}"
            state.setdefault("seals", {})[seal_id] = {
                "packId": self._profile.id,
                "scopeId": scope_id,
                "readerId": reader_id,
                "epoch": epoch,
                "valid": True,
                "createdAtNs": time.time_ns(),
            }
            _save_state(state)
        return RetirementSeal(seal_id, scope_id, reader_id, True)

    @_serialized_migration_operation
    def retirement_seal(self, seal_id: str) -> RetirementSeal:
        """Return seal validity after checking the current reader epoch."""

        with _LOCK:
            state = _load_state()
            item = state.get("seals", {}).get(seal_id)
            if not isinstance(item, dict) or item.get("packId") != self._profile.id:
                raise MigrationError("unknown_retirement_seal")
            reader_id = str(item.get("readerId") or "")
            valid = item.get("valid") is True and int(item.get("epoch", -1)) == int(
                state.get("readerEpochs", {}).get(reader_id, 0)
            )
            return RetirementSeal(
                seal_id,
                str(item.get("scopeId") or ""),
                reader_id,
                valid,
            )

    @_serialized_migration_operation
    def import_legacy_key_source(
        self,
        import_id: str,
        source_path: str | os.PathLike[str],
        password: str,
        source_format: LegacyKeyFormat,
        authorization: object,
    ) -> KeyImportReceipt:
        """Verify-wrap one source key, then unlink and sync its source entry."""

        from .profile import _validate_stable_id

        require_current_authorization(
            authorization,
            "migration.key-import",
            pack_id=self._profile.id,
        )
        _validate_stable_id(import_id)
        if not isinstance(source_format, LegacyKeyFormat):
            raise MigrationError("legacy_key_format_invalid")
        declarations = tuple(
            item
            for item in self._profile.legacy_key_imports
            if item.import_id == import_id
        )
        if not declarations:
            raise MigrationError("legacy_key_import_undeclared")
        if any(item.source_format is not source_format for item in declarations):
            raise MigrationError("legacy_key_format_invalid")
        try:
            source_missing = not os.path.lexists(os.fspath(source_path))
        except (TypeError, ValueError):
            raise MigrationError("legacy_key_source_invalid") from None
        state_import_id = _key_import_state_id(self._profile.id, import_id)
        with _LOCK:
            state = _load_state()
            existing = state.get("keyImports", {}).get(state_import_id)
            if isinstance(existing, dict) and existing.get("disposition") == "complete":
                return KeyImportReceipt(import_id)
            if (
                isinstance(existing, dict)
                and existing.get("disposition") == "unlink-pending"
                and source_missing
                and session_key_for(str(existing.get("keyId") or "")) is not None
            ):
                try:
                    sync_parent_directory(Path(source_path))
                except (OSError, TypeError, ValueError):
                    raise MigrationError("legacy_key_source_unlink_failed") from None
                existing.pop("sourceIdentity", None)
                existing["disposition"] = "complete"
                existing["completedAtNs"] = time.time_ns()
                _save_state(state)
                return KeyImportReceipt(import_id)

        try:
            source = read_legacy_key_source(source_path, source_format.value)
        except LegacyKeySourceError:
            raise MigrationError("legacy_key_source_invalid") from None
        try:
            keystore.import_decrypt_only_key_verified(
                password,
                source.key_id,
                source.key,
            )
        except keystore.PrivacyKeystoreError:
            raise MigrationError("legacy_key_import_failed") from None

        with _LOCK:
            state = _load_state()
            state.setdefault("keyImports", {})[state_import_id] = {
                "keyId": source.key_id,
                "sourceIdentity": [source.device, source.inode],
                "disposition": "unlink-pending",
                "verifiedAtNs": time.time_ns(),
            }
            _save_state(state)

        try:
            unlink_unchanged_legacy_key_source(source)
        except LegacyKeySourceError as exc:
            raise MigrationError(exc.code) from None

        with _LOCK:
            state = _load_state()
            item = state.get("keyImports", {}).get(state_import_id)
            if not isinstance(item, dict) or item.get("keyId") != source.key_id:
                raise MigrationError("migration_state_invalid")
            item.pop("sourceIdentity", None)
            item["disposition"] = "complete"
            item["completedAtNs"] = time.time_ns()
            _save_state(state)
        return KeyImportReceipt(import_id)

    @staticmethod
    def _read_legacy(
        pack_id: str,
        binding: LegacyReaderBinding,
        source: object,
        *,
        audit_scope_id: str | None = None,
        audit_item_id: str | None = None,
    ) -> LegacyReadResult | None:
        with _LOCK:
            unit = _READERS.get(binding.reader_id)
        if unit is None:
            raise MigrationError("legacy_reader_not_registered")

        probe_context = _reader_context(unit, pack_id)
        try:
            matches = unit.reader.probe(source, probe_context)
        except Exception:
            raise MigrationError("legacy_reader_probe_failed") from None
        if matches is not True:
            return None

        obligation = _persist_obligation(
            pack_id,
            binding,
            source,
            audit_scope_id=audit_scope_id,
            audit_item_id=audit_item_id,
        )
        read_context = _reader_context(unit, pack_id)
        try:
            value = unit.reader.read(source, read_context)
        except Exception:
            # The obligation deliberately remains unresolved: discovery happened,
            # but no current-format write has been proven.
            raise MigrationError("legacy_reader_read_failed") from None
        return LegacyReadResult(obligation=obligation, value=value)

    @_serialized_migration_operation
    def obligation(self, obligation_id: str) -> MigrationObligation:
        """Return protected status without returning source identity or values."""

        with _LOCK:
            state = _load_state()
            item = state.get("obligations", {}).get(obligation_id)
        if not isinstance(item, dict) or item.get("packId") != self._profile.id:
            raise MigrationError("unknown_migration_obligation")
        return MigrationObligation(
            obligation_id,
            str(item.get("readerId") or ""),
            str(item.get("disposition") or "unresolved"),
        )

    @_serialized_migration_operation
    def status(self) -> tuple[ReaderMigrationStatus, ...]:
        """Return only generic counts and seal state for profile-bound readers."""

        reader_ids = {binding.reader_id for binding in self._profile.legacy_bindings}
        with _LOCK:
            state = _load_state()
            obligations = tuple(
                item
                for item in state.get("obligations", {}).values()
                if isinstance(item, dict)
                and item.get("packId") == self._profile.id
                and item.get("readerId") in reader_ids
            )
            epochs = state.get("readerEpochs", {})
            seals = tuple(
                item
                for item in state.get("seals", {}).values()
                if isinstance(item, dict) and item.get("packId") == self._profile.id
            )
            return tuple(
                ReaderMigrationStatus(
                    reader_id=reader_id,
                    label=_READERS[reader_id].label,
                    discovered=sum(
                        1 for item in obligations if item.get("readerId") == reader_id
                    ),
                    resolved=sum(
                        1
                        for item in obligations
                        if item.get("readerId") == reader_id
                        and item.get("disposition") == "migrated"
                    ),
                    unresolved=sum(
                        1
                        for item in obligations
                        if item.get("readerId") == reader_id
                        and item.get("disposition") == "unresolved"
                    ),
                    sealed=any(
                        seal.get("readerId") == reader_id
                        and seal.get("valid") is True
                        and int(seal.get("epoch", -1))
                        == int(epochs.get(reader_id, 0))
                        for seal in seals
                    ),
                )
                for reader_id in sorted(reader_ids)
                if reader_id in _READERS
            )

    def recover_pending(
        self,
        obligation_id: str,
        transaction: object,
        authorization: object,
    ) -> MigrationObligation:
        with _exclusive_migration_transaction():
            return self._recover_pending(
                obligation_id,
                transaction,
                authorization,
            )

    def _recover_pending(
        self,
        obligation_id: str,
        transaction: object,
        authorization: object,
    ) -> MigrationObligation:
        """Restore a prepared transaction left by a prior process instance."""

        require_current_authorization(
            authorization,
            "migration.recover",
            pack_id=self._profile.id,
        )
        rollback = getattr(transaction, "rollback", None)
        if not callable(rollback):
            raise MigrationError("invalid_migration_transaction")
        with _LOCK:
            state = _load_state()
            obligation = state.get("obligations", {}).get(obligation_id)
            if not isinstance(obligation, dict) or obligation.get("packId") != self._profile.id:
                raise MigrationError("unknown_migration_obligation")
            _require_generic_migration_binding(
                _binding(self._profile, str(obligation.get("bindingId") or ""))
            )
            pending_id, pending = next(
                (
                    (transaction_id, item)
                    for transaction_id, item in state.get("transactions", {}).items()
                    if isinstance(item, dict)
                    and obligation_id in _pending_obligation_ids(item)
                    and item.get("phase") == "prepared"
                ),
                ("", None),
            )
            if pending is None:
                raise MigrationError("migration_recovery_not_required")
            original = _restore_json_value(pending.get("original"))
        try:
            rollback(original)
        except Exception:
            raise MigrationError("migration_rollback_failed") from None
        with _LOCK:
            state = _load_state()
            state.get("transactions", {}).pop(pending_id, None)
            _save_state(state)
        return self.obligation(obligation_id)

    def complete(
        self,
        obligation_id: str,
        expected_normalized: object,
        transaction: object,
        authorization: object,
    ) -> MigrationReceipt:
        with _exclusive_migration_transaction():
            receipt = self._complete_many(
                (obligation_id,),
                expected_normalized,
                transaction,
                authorization,
            )
        return MigrationReceipt(receipt.id, obligation_id)

    def complete_many(
        self,
        obligation_ids: Iterable[str],
        expected_normalized: object,
        transaction: object,
        authorization: object,
    ) -> MigrationGroupReceipt:
        """Rewrite several obligations under one commit and one receipt."""

        normalized_ids = _normalized_obligation_ids(obligation_ids)
        with _exclusive_migration_transaction():
            return self._complete_many(
                normalized_ids,
                expected_normalized,
                transaction,
                authorization,
            )

    def _complete_many(
        self,
        obligation_ids: tuple[str, ...],
        expected_normalized: object,
        transaction: object,
        authorization: object,
        *,
        authorization_operation_id: str = "migration.complete",
        required_binding_ids: tuple[str, ...] = (),
        recovery_locator: str | None = None,
        allow_record_bindings: bool = False,
    ) -> MigrationGroupReceipt:
        require_current_authorization(
            authorization,
            authorization_operation_id,
            pack_id=self._profile.id,
        )
        if recovery_locator is not None:
            recovery_locator = _recovery_locator(recovery_locator)
        required_methods = (
            "capture_original",
            "stage_current",
            "stage_durable_adjuncts",
            "commit",
            "read_back",
            "rollback",
            "finalize",
        )
        if any(not callable(getattr(transaction, name, None)) for name in required_methods):
            raise MigrationError("invalid_migration_transaction")

        with _LOCK:
            state = _load_state()
            items = tuple(
                state.get("obligations", {}).get(obligation_id)
                for obligation_id in obligation_ids
            )
            if any(
                not isinstance(item, dict) or item.get("packId") != self._profile.id
                for item in items
            ):
                raise MigrationError("unknown_migration_obligation")
            if required_binding_ids and any(
                item.get("bindingId") not in required_binding_ids
                for item in items
            ):
                raise MigrationError("migration_obligation_binding_mismatch")
            if not allow_record_bindings:
                for item in items:
                    _require_generic_migration_binding(
                        _binding(
                            self._profile,
                            str(item.get("bindingId") or ""),
                        )
                    )
            dispositions = tuple(str(item.get("disposition") or "unresolved") for item in items)
            receipt_ids = {str(item.get("receiptId") or "") for item in items}
            if all(disposition == "migrated" for disposition in dispositions):
                if len(receipt_ids) != 1 or "" in receipt_ids:
                    raise MigrationError("migration_obligation_closed")
                existing_receipt_id = next(iter(receipt_ids))
            elif any(disposition != "unresolved" for disposition in dispositions):
                raise MigrationError("migration_obligation_closed")
            else:
                existing_receipt_id = ""
            pending_id, pending = next(
                (
                    (transaction_id, item)
                    for transaction_id, item in state.get("transactions", {}).items()
                    if isinstance(item, dict)
                    and _pending_obligation_ids(item) == obligation_ids
                    and item.get("phase") == "finalize-pending"
                ),
                ("", None),
            )

        if existing_receipt_id:
            if not pending_id or not isinstance(pending, dict):
                return MigrationGroupReceipt(existing_receipt_id, obligation_ids)
            stored_expected = _restore_json_value(pending.get("expected"))
            original = _restore_json_value(pending.get("original"))
            if not hmac.compare_digest(
                _canonical_value(stored_expected),
                _canonical_value(expected_normalized),
            ):
                raise MigrationError("migration_expected_value_mismatch")
            try:
                verification = transaction.read_back()
            except Exception:
                verification = None
            if not _verification_matches(verification, stored_expected):
                try:
                    transaction.rollback(original)
                except Exception:
                    raise MigrationError("migration_rollback_failed") from None
                with _LOCK:
                    state = _load_state()
                    for obligation_id in obligation_ids:
                        item = state.get("obligations", {}).get(obligation_id)
                        if isinstance(item, dict):
                            item["disposition"] = "unresolved"
                            item.pop("receiptId", None)
                    state.get("receipts", {}).pop(existing_receipt_id, None)
                    state.get("transactions", {}).pop(pending_id, None)
                    _save_state(state)
                raise MigrationError("migration_verification_failed")
            with _LOCK:
                _save_state(_load_state())
            try:
                transaction.finalize(original)
            except Exception:
                raise MigrationError("migration_finalization_pending") from None
            with _LOCK:
                state = _load_state()
                state.get("transactions", {}).pop(pending_id, None)
                _save_state(state)
            return MigrationGroupReceipt(existing_receipt_id, obligation_ids)

        try:
            original = transaction.capture_original()
            protected_original = _protect_json_value(original)
            protected_expected = _protect_json_value(expected_normalized)
        except MigrationError:
            raise
        except Exception:
            raise MigrationError("migration_original_capture_failed") from None

        transaction_id = f"hp-transaction-{secrets.token_hex(16)}"
        with _LOCK:
            state = _load_state()
            items = tuple(
                state.get("obligations", {}).get(obligation_id)
                for obligation_id in obligation_ids
            )
            if any(
                not isinstance(item, dict) or item.get("disposition") != "unresolved"
                for item in items
            ):
                raise MigrationError("migration_obligation_closed")
            if any(
                set(_pending_obligation_ids(pending)).intersection(obligation_ids)
                for pending in state.get("transactions", {}).values()
                if isinstance(pending, dict)
            ):
                raise MigrationError("migration_obligation_in_progress")
            state.setdefault("transactions", {})[transaction_id] = {
                "obligationIds": list(obligation_ids),
                "original": protected_original,
                "expected": protected_expected,
                "phase": "prepared",
                "preparedAtNs": time.time_ns(),
            }
            if recovery_locator is not None:
                state["transactions"][transaction_id][
                    "recoveryLocator"
                ] = recovery_locator
            _save_state(state)

        try:
            transaction.stage_current(expected_normalized)
            transaction.stage_durable_adjuncts(expected_normalized)
            transaction.commit()
            verification = transaction.read_back()
            if not _verification_matches(verification, expected_normalized):
                raise MigrationError("migration_verification_failed")
        except Exception as exc:
            try:
                transaction.rollback(original)
            except Exception:
                raise MigrationError("migration_rollback_failed") from None
            with _LOCK:
                state = _load_state()
                state.get("transactions", {}).pop(transaction_id, None)
                _save_state(state)
            if isinstance(exc, MigrationError):
                raise exc
            raise MigrationError("migration_transaction_failed") from None

        receipt_id = f"hp-receipt-{secrets.token_hex(16)}"
        try:
            with _LOCK:
                state = _load_state()
                items = tuple(
                    state.get("obligations", {}).get(obligation_id)
                    for obligation_id in obligation_ids
                )
                if any(
                    not isinstance(item, dict) or item.get("disposition") != "unresolved"
                    for item in items
                ):
                    raise MigrationError("migration_obligation_closed")
                for item in items:
                    item["disposition"] = "migrated"
                    item["receiptId"] = receipt_id
                state.setdefault("receipts", {})[receipt_id] = {
                    "obligationIds": list(obligation_ids),
                    "readerIds": sorted({str(item.get("readerId") or "") for item in items}),
                    "verified": True,
                    "createdAtNs": time.time_ns(),
                }
                state["transactions"][transaction_id]["phase"] = "finalize-pending"
                _save_state(state)
        except MigrationError as persistence_error:
            try:
                transaction.rollback(original)
            except Exception:
                raise MigrationError("migration_rollback_failed") from None
            try:
                with _LOCK:
                    rollback_state = _load_state()
                    for obligation_id in obligation_ids:
                        item = rollback_state.get("obligations", {}).get(obligation_id)
                        if isinstance(item, dict):
                            item["disposition"] = "unresolved"
                            item.pop("receiptId", None)
                    rollback_state.get("receipts", {}).pop(receipt_id, None)
                    rollback_state.get("transactions", {}).pop(transaction_id, None)
                    _save_state(rollback_state)
            except MigrationError:
                pass
            raise persistence_error

        try:
            transaction.finalize(original)
        except Exception:
            raise MigrationError("migration_finalization_pending") from None
        with _LOCK:
            state = _load_state()
            state.get("transactions", {}).pop(transaction_id, None)
            _save_state(state)
        return MigrationGroupReceipt(receipt_id, obligation_ids)



@contextmanager
def _exclusive_migration_transaction():
    """Serialize product commits and dead-owner recovery across processes."""

    depth = int(getattr(_MIGRATION_TRANSACTION_LOCAL, "depth", 0))
    if depth:
        _MIGRATION_TRANSACTION_LOCAL.depth = depth + 1
        try:
            yield
        finally:
            _MIGRATION_TRANSACTION_LOCAL.depth = depth
        return

    lock_path = migration_state_path().with_suffix(
        migration_state_path().suffix + ".transaction.lock"
    )
    descriptor: int | None = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(lock_path.parent, 0o700)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        if descriptor is not None:
            os.close(descriptor)
        raise MigrationError("migration_obligation_in_progress") from None
    except OSError:
        try:
            if descriptor is not None:
                os.close(descriptor)
        except OSError:
            pass
        raise MigrationError("migration_transaction_lock_failed") from None
    try:
        _MIGRATION_TRANSACTION_LOCAL.depth = 1
        yield
    finally:
        _MIGRATION_TRANSACTION_LOCAL.depth = 0
        if descriptor is None:  # Defensive; successful acquisition always sets it.
            raise MigrationError("migration_transaction_lock_failed")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _normalized_obligation_ids(obligation_ids: Iterable[str]) -> tuple[str, ...]:
    try:
        normalized = tuple(obligation_ids)
    except TypeError:
        raise MigrationError("invalid_migration_obligation_set") from None
    if (
        not normalized
        or any(not isinstance(item, str) or not item for item in normalized)
        or len(normalized) != len(set(normalized))
    ):
        raise MigrationError("invalid_migration_obligation_set")
    return tuple(sorted(normalized))


def _pending_obligation_ids(pending: Mapping[str, object]) -> tuple[str, ...]:
    grouped = pending.get("obligationIds")
    if isinstance(grouped, list) and all(isinstance(item, str) for item in grouped):
        return tuple(grouped)
    single = pending.get("obligationId")
    return (single,) if isinstance(single, str) and single else ()


def _reopen_recovered_obligations(
    state: dict[str, object],
    obligation_ids: tuple[str, ...],
) -> None:
    receipt_ids: set[str] = set()
    obligations = state.get("obligations", {})
    if not isinstance(obligations, dict):
        raise MigrationError("migration_state_invalid")
    for obligation_id in obligation_ids:
        item = obligations.get(obligation_id)
        if not isinstance(item, dict):
            raise MigrationError("migration_state_invalid")
        receipt_id = item.pop("receiptId", None)
        if isinstance(receipt_id, str) and receipt_id:
            receipt_ids.add(receipt_id)
        item["disposition"] = "unresolved"
    receipts = state.get("receipts", {})
    if not isinstance(receipts, dict):
        raise MigrationError("migration_state_invalid")
    for receipt_id in receipt_ids:
        receipts.pop(receipt_id, None)


def _external_owner(value: object) -> str:
    owner = value if isinstance(value, str) else ""
    if _EXTERNAL_OWNER.fullmatch(owner) is None:
        raise MigrationError("external_migration_owner_invalid")
    return owner


def _external_idempotency_key(value: object) -> str:
    key = value if isinstance(value, str) else ""
    if _EXTERNAL_IDEMPOTENCY_KEY.fullmatch(key) is None:
        raise MigrationError("external_migration_idempotency_key_invalid")
    return key


def _external_transaction_id(value: object) -> str:
    transaction_id = value if isinstance(value, str) else ""
    if _EXTERNAL_TRANSACTION_ID.fullmatch(transaction_id) is None:
        raise MigrationError("external_migration_transaction_invalid")
    return transaction_id


def _external_resume_capability(value: object) -> str:
    token = value if isinstance(value, str) else ""
    if _EXTERNAL_RESUME_TOKEN.fullmatch(token) is None:
        raise MigrationError("external_migration_resume_invalid")
    return token


def _external_exact_bytes(value: object) -> bytes:
    if (
        not isinstance(value, bytes)
        or not value
        or len(value) > _EXTERNAL_MIGRATION_MAX_EXACT_BYTES
    ):
        raise MigrationError("external_migration_exact_bytes_invalid")
    return value


def _external_canonical_normalized(value: object) -> bytes:
    """Bound and canonicalize normalized state before touching durable state."""

    stack: list[tuple[object, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    item_count = 0
    canonical_size = 0

    def account(size: int) -> None:
        nonlocal canonical_size
        canonical_size += size
        if canonical_size > _EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES:
            raise MigrationError("external_migration_normalized_invalid")

    try:
        while stack:
            current, depth = stack.pop()
            item_count += 1
            if (
                depth > _EXTERNAL_MIGRATION_MAX_DEPTH
                or item_count > _EXTERNAL_MIGRATION_MAX_ITEMS
            ):
                raise MigrationError("external_migration_normalized_invalid")
            if current is None:
                account(4)
                continue
            if type(current) is bool:
                account(4 if current else 5)
                continue
            if type(current) is int:
                if current.bit_length() > _EXTERNAL_MIGRATION_MAX_INTEGER_BITS:
                    raise MigrationError("external_migration_normalized_invalid")
                account(len(str(current).encode("ascii")))
                continue
            if type(current) is float:
                if not (float("-inf") < current < float("inf")):
                    raise MigrationError("external_migration_normalized_invalid")
                account(
                    len(
                        json.dumps(
                            current,
                            ensure_ascii=False,
                            allow_nan=False,
                        ).encode("ascii")
                    )
                )
                continue
            if type(current) is str:
                encoded = current.encode("utf-8")
                if (
                    len(current) > _EXTERNAL_MIGRATION_MAX_STRING_BYTES
                    or len(encoded) > _EXTERNAL_MIGRATION_MAX_STRING_BYTES
                ):
                    raise MigrationError("external_migration_normalized_invalid")
                # Quotes plus UTF-8 bytes, with conservative JSON escaping for
                # controls, quotes, and backslashes. This never underestimates
                # ``json.dumps(..., ensure_ascii=False)``.
                escaped_size = 2 + len(encoded)
                for character in current:
                    codepoint = ord(character)
                    if codepoint <= 0x1F:
                        escaped_size += 5
                    elif character in {'"', "\\"}:
                        escaped_size += 1
                account(escaped_size)
                continue
            if type(current) not in {list, tuple, dict}:
                raise MigrationError("external_migration_normalized_invalid")
            identity = id(current)
            if identity in seen_containers:
                raise MigrationError("external_migration_normalized_invalid")
            seen_containers.add(identity)
            if len(current) > _EXTERNAL_MIGRATION_MAX_CONTAINER_ITEMS:
                raise MigrationError("external_migration_normalized_invalid")
            if type(current) is dict:
                if any(type(key) is not str for key in current):
                    raise MigrationError("external_migration_normalized_invalid")
                # {"$heltoMap":[[key,value],...]}
                account(
                    len(b'{"$heltoMap":[')
                    + len(b"]}")
                    + len(current) * 3
                    + max(0, len(current) - 1)
                )
                for key, item in current.items():
                    stack.append((item, depth + 1))
                    stack.append((key, depth + 1))
            elif type(current) is tuple:
                # {"$heltoTuple":[...]}
                account(
                    len(b'{"$heltoTuple":[')
                    + len(b"]}")
                    + max(0, len(current) - 1)
                )
                stack.extend((item, depth + 1) for item in current)
            else:
                account(2 + max(0, len(current) - 1))
                stack.extend((item, depth + 1) for item in current)
        encoded = _canonical_value(value)
    except MigrationError:
        raise
    except Exception:
        raise MigrationError("external_migration_normalized_invalid") from None
    if len(encoded) > _EXTERNAL_MIGRATION_MAX_NORMALIZED_BYTES:
        raise MigrationError("external_migration_normalized_invalid")
    return encoded


def _require_external_bound_operation(
    binding: LegacyReaderBinding,
    operation_id: str,
) -> None:
    from .profile import LegacyLocationKind

    if (
        binding.location_kind is not LegacyLocationKind.EXPORT
        or not isinstance(operation_id, str)
        or not operation_id
        or binding.location_id != operation_id
    ):
        raise MigrationError("typed_migration_operation_required")


def _external_digest(
    key: bytes,
    domain: bytes,
    *values: bytes,
) -> str:
    message = bytearray(domain)
    for value in values:
        message.extend(len(value).to_bytes(8, "big"))
        message.extend(value)
    return "hp-digest-" + _b64encode(hmac.new(key, bytes(message), hashlib.sha256).digest())


def _external_value_digest(key: bytes, domain: bytes, value: bytes) -> str:
    return _external_digest(key, b"external-value\0" + domain, value)


def _external_context_bytes(context: ExternalMigrationContext) -> bytes:
    return json.dumps(
        {"exportedAt": context.exported_at, "mode": context.mode.value},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _external_context_digest(key: bytes, context: ExternalMigrationContext) -> str:
    return _external_digest(key, b"external-context", _external_context_bytes(context))


def _external_idempotency_digest(
    key: bytes,
    pack_id: str,
    operation_id: str,
    owner_id: str,
    idempotency_key: str,
) -> str:
    return _external_digest(
        key,
        b"external-idempotency",
        pack_id.encode("utf-8"),
        operation_id.encode("utf-8"),
        owner_id.encode("utf-8"),
        idempotency_key.encode("utf-8"),
    )


def _external_resume_token(
    key: bytes,
    pack_id: str,
    operation_id: str,
    owner_id: str,
    idempotency_key: str,
) -> str:
    digest = hmac.new(
        key,
        b"external-resume\0"
        + pack_id.encode("utf-8")
        + b"\0"
        + operation_id.encode("utf-8")
        + b"\0"
        + owner_id.encode("utf-8")
        + b"\0"
        + idempotency_key.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return "hp-resume-" + _b64encode(digest)


def _external_resume_hash(resume_token: str) -> str:
    return "hp-resume-hash-" + hashlib.sha256(resume_token.encode("ascii")).hexdigest()


def _external_request_digest(
    key: bytes,
    obligation_id: str,
    binding_id: str,
    expected_canonical: bytes,
    original_exact: bytes,
    context: ExternalMigrationContext,
) -> str:
    return _external_digest(
        key,
        b"external-request",
        obligation_id.encode("utf-8"),
        binding_id.encode("utf-8"),
        expected_canonical,
        original_exact,
        _external_context_bytes(context),
    )


def _external_digest_key(item: Mapping[str, object]) -> bytes:
    key = session_key_for(str(item.get("digestKeyId") or ""))
    if key is None:
        raise MigrationError("migration_state_invalid")
    return key


def _find_external_idempotency(
    state: Mapping[str, object],
    pack_id: str,
    operation_id: str,
    owner_id: str,
    idempotency_key: str,
) -> tuple[dict[str, object] | None, bytes, str]:
    matches: list[tuple[dict[str, object], bytes, str]] = []
    for collection_name in ("externalTransactions", "externalTombstones"):
        collection = state.get(collection_name, {})
        if not isinstance(collection, dict):
            raise MigrationError("migration_state_invalid")
        for transaction_id, raw_item in collection.items():
            if (
                not isinstance(raw_item, dict)
                or raw_item.get("packId") != pack_id
                or raw_item.get("operationId") != operation_id
                or raw_item.get("ownerId") != owner_id
            ):
                continue
            key = _external_digest_key(raw_item)
            candidate = _external_idempotency_digest(
                key,
                pack_id,
                operation_id,
                owner_id,
                idempotency_key,
            )
            if hmac.compare_digest(
                str(raw_item.get("idempotencyDigest") or ""),
                candidate,
            ):
                item = raw_item
                item.setdefault("transactionId", str(transaction_id))
                matches.append(
                    (
                        item,
                        key,
                        _external_resume_token(
                            key,
                            pack_id,
                            operation_id,
                            owner_id,
                            idempotency_key,
                        ),
                    )
                )
    if len(matches) > 1:
        raise MigrationError("migration_state_invalid")
    if matches:
        return matches[0]
    key, _key_id = primary_session_key()
    return None, key, ""


def _expire_external_transactions(state: dict[str, object], now_ns: int) -> bool:
    collection = state.setdefault("externalTransactions", {})
    if not isinstance(collection, dict):
        raise MigrationError("migration_state_invalid")
    changed = False
    for item in collection.values():
        if (
            isinstance(item, dict)
            and item.get("disposition") == "prepared"
            and int(item.get("expiresAtNs") or 0) <= now_ns
        ):
            item["disposition"] = "rollback-required"
            item["rollbackRequiredAtNs"] = now_ns
            item["expired"] = True
            changed = True
    return changed


def _external_owned_item(
    state: Mapping[str, object],
    transaction_id: str,
    pack_id: str,
    binding_id: str,
    operation_id: str,
    owner_id: str,
    resume_token: str,
) -> tuple[dict[str, object], bool]:
    active = state.get("externalTransactions", {})
    tombstones = state.get("externalTombstones", {})
    if not isinstance(active, dict) or not isinstance(tombstones, dict):
        raise MigrationError("migration_state_invalid")
    completed = transaction_id in tombstones
    item = tombstones.get(transaction_id) if completed else active.get(transaction_id)
    if (
        not isinstance(item, dict)
        or item.get("packId") != pack_id
        or item.get("bindingId") != binding_id
        or item.get("operationId") != operation_id
        or item.get("ownerId") != owner_id
        or not hmac.compare_digest(
            str(item.get("resumeHash") or ""),
            _external_resume_hash(resume_token),
        )
    ):
        raise MigrationError("external_migration_unknown")
    item.setdefault("transactionId", transaction_id)
    return item, completed


def _external_status(
    item: Mapping[str, object],
    now_ns: int,
    *,
    transaction_id: str | None = None,
) -> ExternalMigrationStatus:
    disposition = str(item.get("disposition") or "")
    expires_in_seconds = 0
    if disposition == "prepared":
        remaining_ns = max(0, int(item.get("expiresAtNs") or 0) - now_ns)
        expires_in_seconds = (remaining_ns + 999_999_999) // 1_000_000_000
    return ExternalMigrationStatus(
        transaction_id or str(item.get("transactionId") or ""),
        str(item.get("obligationId") or ""),
        disposition,
        expires_in_seconds,
        str(item.get("receiptId")) if item.get("receiptId") else None,
    )


def _external_tombstone(
    item: Mapping[str, object],
    *,
    disposition: str,
) -> dict[str, object]:
    """Drop protected values and timestamps while retaining retry evidence."""

    return {
        "kind": "external-tombstone",
        "packId": str(item.get("packId") or ""),
        "bindingId": str(item.get("bindingId") or ""),
        "operationId": str(item.get("operationId") or ""),
        "ownerId": str(item.get("ownerId") or ""),
        "obligationId": str(item.get("obligationId") or ""),
        "disposition": disposition,
        "digestKeyId": str(item.get("digestKeyId") or ""),
        "idempotencyDigest": str(item.get("idempotencyDigest") or ""),
        "resumeHash": str(item.get("resumeHash") or ""),
        "requestDigest": str(item.get("requestDigest") or ""),
        "originalDigest": str(item.get("originalDigest") or ""),
        "expectedDigest": str(item.get("expectedDigest") or ""),
        "contextDigest": str(item.get("contextDigest") or ""),
    }


def migration_state_path() -> Path:
    configured = str(os.environ.get(MIGRATION_STATE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    from .keystore import keystore_path

    return keystore_path().with_name("privacy_migration_state.json")


def _binding(profile: PrivacyProfile, binding_id: str) -> LegacyReaderBinding:
    binding = next((item for item in profile.legacy_bindings if item.id == binding_id), None)
    if binding is None:
        raise MigrationError("unknown_legacy_binding")
    return binding


def _require_generic_migration_binding(binding: LegacyReaderBinding) -> None:
    from .profile import LegacyLocationKind

    if binding.location_kind is LegacyLocationKind.RECORD:
        raise MigrationError("typed_migration_operation_required")


def _require_typed_bound_operation(
    binding: LegacyReaderBinding,
    operation_id: str,
) -> None:
    from .profile import LegacyLocationKind

    if not isinstance(operation_id, str) or not operation_id:
        raise MigrationError("typed_migration_operation_required")
    if operation_id.startswith("migration."):
        raise MigrationError("typed_migration_operation_required")
    if binding.location_kind is LegacyLocationKind.RECORD:
        raise MigrationError("typed_migration_operation_required")


def _require_record_bound_operation(
    binding: LegacyReaderBinding,
    operation_id: str,
) -> None:
    from .profile import LegacyLocationKind

    if (
        binding.location_kind is not LegacyLocationKind.RECORD
        or not isinstance(operation_id, str)
        or not operation_id.startswith("record.")
    ):
        raise MigrationError("typed_migration_operation_required")


def _recovery_locator(value: object) -> str:
    locator = value if isinstance(value, str) else ""
    if _RECOVERY_LOCATOR.fullmatch(locator) is None:
        raise MigrationError("migration_recovery_locator_invalid")
    return locator


def _persist_obligation(
    pack_id: str,
    binding: LegacyReaderBinding,
    source: object,
    *,
    audit_scope_id: str | None = None,
    audit_item_id: str | None = None,
) -> MigrationObligation:
    primary_key, _key_id = primary_session_key()
    source_id = _source_identity(primary_key, pack_id, binding.id, source)
    with _LOCK:
        state = _load_state()
        obligations = state.setdefault("obligations", {})
        finalize_pending_ids = {
            obligation_id
            for pending in state.get("transactions", {}).values()
            if isinstance(pending, dict)
            and pending.get("phase") == "finalize-pending"
            for obligation_id in _pending_obligation_ids(pending)
        }
        for obligation_id, item in obligations.items():
            if (
                isinstance(item, dict)
                and item.get("packId") == pack_id
                and item.get("bindingId") == binding.id
                and item.get("sourceId") == source_id
                and (
                    item.get("disposition") == "unresolved"
                    or obligation_id in finalize_pending_ids
                )
            ):
                if audit_scope_id is not None:
                    item["auditScopeId"] = audit_scope_id
                    item["auditItemId"] = audit_item_id
                    _save_state(state)
                return MigrationObligation(obligation_id, binding.reader_id)
        obligation_id = f"hp-obligation-{secrets.token_hex(16)}"
        obligations[obligation_id] = {
            "packId": pack_id,
            "bindingId": binding.id,
            "readerId": binding.reader_id,
            "sourceId": source_id,
            "disposition": "unresolved",
            "createdAtNs": time.time_ns(),
        }
        if audit_scope_id is not None:
            obligations[obligation_id]["auditScopeId"] = audit_scope_id
            obligations[obligation_id]["auditItemId"] = audit_item_id
        epochs = state.setdefault("readerEpochs", {})
        epochs[binding.reader_id] = int(epochs.get(binding.reader_id, 0)) + 1
        seals = state.setdefault("seals", {})
        for seal in seals.values():
            if isinstance(seal, dict) and seal.get("readerId") == binding.reader_id:
                seal["valid"] = False
        _save_state(state)
    return MigrationObligation(obligation_id, binding.reader_id)


def _require_audit_item(
    pack_id: str,
    scope_id: str,
    item_id: str,
    *,
    reader_id: str,
) -> None:
    with _LOCK:
        state = _load_state()
        scope = state.get("auditScopes", {}).get(
            _audit_scope_state_id(pack_id, scope_id)
        )
        if (
            not isinstance(scope, dict)
            or scope.get("packId") != pack_id
            or scope.get("readerId") != reader_id
            or item_id not in scope.get("items", {})
        ):
            raise MigrationError("unknown_audit_item")


def _unresolved_count(pack_id: str, reader_id: str) -> int:
    with _LOCK:
        state = _load_state()
        return sum(
            1
            for item in state.get("obligations", {}).values()
            if isinstance(item, dict)
            and item.get("packId") == pack_id
            and item.get("readerId") == reader_id
            and item.get("disposition") == "unresolved"
        )


def _reader_context(unit: LegacyReaderUnit, pack_id: str) -> _ReaderContext:
    keys: dict[str, bytes] = {}
    with _LOCK:
        state = _load_state()
        imports = state.get("keyImports", {})
        for import_id in unit.key_import_ids:
            item = imports.get(_key_import_state_id(pack_id, import_id))
            if not isinstance(item, dict) or item.get("disposition") != "complete":
                raise MigrationError("legacy_key_import_required")
            key = session_key_for(str(item.get("keyId") or ""))
            if key is None:
                raise MigrationError("legacy_key_import_required")
            keys[import_id] = key
    return _ReaderContext(
        unresolved_count=_unresolved_count(pack_id, unit.id),
        _keys=keys,
    )


def _key_import_state_id(pack_id: str, import_id: str) -> str:
    return f"{pack_id}|{import_id}"


def _audit_scope_state_id(pack_id: str, scope_id: str) -> str:
    return f"{pack_id}|{scope_id}"


def _empty_state() -> dict[str, object]:
    return {
        "version": MIGRATION_STATE_VERSION,
        "obligations": {},
        "receipts": {},
        "readerEpochs": {},
        "auditScopes": {},
        "seals": {},
        "keyImports": {},
        "transactions": {},
        "externalTransactions": {},
        "externalTombstones": {},
    }


def _load_state() -> dict[str, Any]:
    path = migration_state_path()
    if not path.is_file():
        return _empty_state()
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != MIGRATION_STATE_SCHEMA
            or envelope.get("version") != MIGRATION_STATE_VERSION
        ):
            raise ValueError
        key_id = str(envelope.get("keyId") or "")
        key = session_key_for(key_id)
        if key is None:
            raise ValueError
        plaintext = AESGCM(key).decrypt(
            _b64decode(str(envelope.get("nonce") or "")),
            _b64decode(str(envelope.get("ciphertext") or "")),
            _STATE_AAD,
        )
        state = json.loads(plaintext.decode("utf-8"))
        if not isinstance(state, dict) or state.get("version") != MIGRATION_STATE_VERSION:
            raise ValueError
        return state
    except Exception:
        raise MigrationError("migration_state_invalid") from None


def _save_state(state: Mapping[str, object]) -> None:
    try:
        key, key_id = primary_session_key()
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _STATE_AAD)
        envelope = {
            "schema": MIGRATION_STATE_SCHEMA,
            "version": MIGRATION_STATE_VERSION,
            "keyId": key_id,
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }
        atomic_write_private_bytes(
            migration_state_path(),
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
    except MigrationError:
        raise
    except Exception:
        raise MigrationError("migration_state_persist_failed") from None


def _source_identity(key: bytes, pack_id: str, binding_id: str, source: object) -> str:
    try:
        if isinstance(source, bytes):
            encoded = b"bytes\0" + source
        elif isinstance(source, str):
            encoded = b"text\0" + source.encode("utf-8")
        else:
            encoded = b"json\0" + json.dumps(
                source,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
    except (TypeError, ValueError):
        raise MigrationError("legacy_source_identity_invalid") from None
    digest = hmac.new(
        key,
        pack_id.encode("utf-8") + b"\0" + binding_id.encode("utf-8") + b"\0" + encoded,
        hashlib.sha256,
    ).digest()
    return "hp-source-" + _b64encode(digest)


def _canonical_value(value: object) -> bytes:
    try:
        return json.dumps(
            _protect_json_value(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise MigrationError("migration_value_invalid") from None


def _verification_matches(verification: object, expected_normalized: object) -> bool:
    return (
        isinstance(verification, MigrationVerification)
        and verification.current_format is True
        and verification.durable_artifacts_current is True
        and hmac.compare_digest(
            _canonical_value(verification.normalized),
            _canonical_value(expected_normalized),
        )
    )


def _protect_json_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"$heltoBytes": _b64encode(value)}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_protect_json_value(item) for item in value]
    if isinstance(value, tuple):
        return {"$heltoTuple": [_protect_json_value(item) for item in value]}
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise MigrationError("migration_value_invalid")
        return {
            "$heltoMap": [
                [key, _protect_json_value(item)]
                for key, item in sorted(value.items())
            ]
        }
    raise MigrationError("migration_value_invalid")


def _restore_json_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_restore_json_value(item) for item in value]
    if isinstance(value, dict) and set(value) == {"$heltoBytes"}:
        return _b64decode(str(value["$heltoBytes"]))
    if isinstance(value, dict) and set(value) == {"$heltoTuple"}:
        items = value["$heltoTuple"]
        if not isinstance(items, list):
            raise MigrationError("migration_state_invalid")
        return tuple(_restore_json_value(item) for item in items)
    if isinstance(value, dict) and set(value) == {"$heltoMap"}:
        entries = value["$heltoMap"]
        if not isinstance(entries, list):
            raise MigrationError("migration_state_invalid")
        restored: dict[str, object] = {}
        for entry in entries:
            if (
                not isinstance(entry, list)
                or len(entry) != 2
                or not isinstance(entry[0], str)
            ):
                raise MigrationError("migration_state_invalid")
            restored[entry[0]] = _restore_json_value(entry[1])
        return restored
    raise MigrationError("migration_state_invalid")


def _stable_ids(values: Iterable[str], duplicate_code: str) -> tuple[str, ...]:
    from .profile import _validate_stable_id

    try:
        normalized = tuple(values)
    except TypeError:
        raise MigrationError("invalid_legacy_reader_contract") from None
    for value in normalized:
        _validate_stable_id(value)
    if len(normalized) != len(set(normalized)):
        raise MigrationError(duplicate_code)
    return tuple(sorted(normalized))


def _validate_reader_graph(readers: Mapping[str, LegacyReaderUnit]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(reader_id: str) -> None:
        if reader_id in visiting:
            raise MigrationError("legacy_reader_dependency_cycle")
        if reader_id in visited:
            return
        visiting.add(reader_id)
        for dependency in readers[reader_id].dependencies:
            visit(dependency)
        visiting.remove(reader_id)
        visited.add(reader_id)

    for reader_id in readers:
        visit(reader_id)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
