"""Shared, read-only legacy discovery with protected migration obligations."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
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


_LOCK = RLock()
_READERS: dict[str, LegacyReaderUnit] = {}
_MIGRATION_TRANSACTION_LOCAL = local()


def _serialized_migration_operation(operation):
    @wraps(operation)
    def serialized(*args, **kwargs):
        with _exclusive_migration_transaction():
            return operation(*args, **kwargs)

    return serialized


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
    """Internal shared-reader entry for an already typed privacy operation."""

    require_current_authorization(
        authorization,
        operation_id,
        pack_id=profile.id,
    )
    return MigrationHandle._read_legacy(
        profile.id,
        _binding(profile, binding_id),
        source,
    )


@dataclass(frozen=True, slots=True)
class MigrationHandle:
    """Pack-bound migration capability; it owns no product writer adapter."""

    _profile: PrivacyProfile = field(repr=False, compare=False)

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
    ) -> MigrationGroupReceipt:
        require_current_authorization(
            authorization,
            "migration.complete",
            pack_id=self._profile.id,
        )
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
