"""Crash-safe relocation of legacy references into opaque private records."""

from __future__ import annotations

import base64
import copy
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._atomic_file import atomic_write_private_bytes
from .envelope import PrivacyEnvelopeCodec
from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .keystore import (
    primary_session_key,
    require_unlocked_session,
    session_key_for,
    unlocked_session_key_ids,
)
from .profile import PrivacyProfile, RecordReferenceMigration
from .records import generate_private_record_id


RECORD_REFERENCE_MAP_SCHEMA = "helto.private-record-reference-map.v1"
RECORD_RELOCATION_STATE_ENV = "HELTO_PRIVACY_RECORD_RELOCATION_STATE"
RECORD_RELOCATION_STATE_SCHEMA = "helto.private-record-relocation-state.v1"
RECORD_RELOCATION_STATE_VERSION = 1
_STATE_AAD = f"{RECORD_RELOCATION_STATE_SCHEMA}|{RECORD_RELOCATION_STATE_VERSION}".encode()
_MAPPING_ID = re.compile(r"^hp-rmap-[A-Za-z0-9_-]{32}$")
_RECORD_ID = re.compile(r"^hp-rec-[A-Za-z0-9_-]{32}$")
_OPAQUE_REVISION = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_REVISION_TYPES = (str, int)
_LOCK = RLock()
_ERRORS = frozenset(
    {
        "PRIVACY_RECORD_REFERENCE_INVALID",
        "PRIVACY_RECORD_REFERENCE_UNAVAILABLE",
        "PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID",
        "PRIVACY_RECORD_RELOCATION_CONFLICT",
        "PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED",
        "PRIVACY_RECORD_RELOCATION_VERIFICATION_FAILED",
        "PRIVACY_RECORD_RELOCATION_FINALIZATION_PENDING",
        "PRIVACY_RECORD_RELOCATION_BLOCKED",
    }
)


class RecordReferenceError(RuntimeError):
    """Stable relocation failure that never renders a legacy reference."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERRORS else "PRIVACY_RECORD_REFERENCE_UNAVAILABLE"
        self.correlation_id = "hp-relocation-" + secrets.token_urlsafe(12)
        super().__init__("Private record reference operation could not complete.")

    def __repr__(self) -> str:
        return f"RecordReferenceError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class LegacyRecordSource:
    revision: str | int
    value: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_revision(self.revision)
        if not isinstance(self.value, Mapping):
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")


@dataclass(frozen=True, slots=True)
class RecordRelocationWrite:
    transaction_id: str
    migration_id: str
    record_id: str
    mapping_id: str
    source_revision: str | int
    legacy_reference: str = field(repr=False, compare=False)
    protected_record: object = field(repr=False, compare=False)
    protected_mapping: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_opaque_id(self.transaction_id)
        _validate_opaque_id(self.migration_id)
        if _RECORD_ID.fullmatch(self.record_id) is None or _MAPPING_ID.fullmatch(self.mapping_id) is None:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
        _validate_revision(self.source_revision)
        _reference(self.legacy_reference)
        if not isinstance(self.protected_record, Mapping) or not isinstance(self.protected_mapping, Mapping):
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")


@dataclass(frozen=True, slots=True)
class RecordRelocationCommit:
    commit_id: str
    record_revision: str | int
    mapping_revision: str | int

    def __post_init__(self) -> None:
        _validate_opaque_id(self.commit_id)
        _validate_revision(self.record_revision)
        _validate_revision(self.mapping_revision)


@dataclass(frozen=True, slots=True)
class RecordRelocationReadback:
    record_revision: str | int
    mapping_revision: str | int
    protected_record: object = field(repr=False, compare=False)
    protected_mapping: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_revision(self.record_revision)
        _validate_revision(self.mapping_revision)
        if not isinstance(self.protected_record, Mapping) or not isinstance(self.protected_mapping, Mapping):
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")


@dataclass(frozen=True, slots=True)
class RecordRelocationRollback:
    transaction_id: str
    record_id: str
    mapping_id: str
    expected_record_revision: str | int
    expected_mapping_revision: str | int

    def __post_init__(self) -> None:
        _validate_opaque_id(self.transaction_id)
        if _RECORD_ID.fullmatch(self.record_id) is None or _MAPPING_ID.fullmatch(self.mapping_id) is None:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
        _validate_revision(self.expected_record_revision)
        _validate_revision(self.expected_mapping_revision)


@dataclass(frozen=True, slots=True)
class LegacyRecordFinalize:
    transaction_id: str
    migration_id: str
    legacy_reference: str = field(repr=False, compare=False)
    expected_source_revision: str | int = 0
    committed_record_id: str = ""

    def __post_init__(self) -> None:
        _validate_opaque_id(self.transaction_id)
        _validate_opaque_id(self.migration_id)
        _reference(self.legacy_reference)
        _validate_revision(self.expected_source_revision)
        if _RECORD_ID.fullmatch(self.committed_record_id) is None:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")


@dataclass(frozen=True, slots=True)
class RecordReferenceMigrationReceipt:
    record_id: str = field(repr=False)
    disposition: str = "migrated"
    correlation_id: str = field(default_factory=lambda: "hp-relocation-" + secrets.token_urlsafe(12))


@dataclass(frozen=True, slots=True)
class RecordReferenceResolution:
    record_id: str = field(repr=False)
    correlation_id: str = field(default_factory=lambda: "hp-relocation-" + secrets.token_urlsafe(12))


def generate_record_reference_mapping_id() -> str:
    mapping_id = "hp-rmap-" + secrets.token_urlsafe(24)
    if _MAPPING_ID.fullmatch(mapping_id) is None:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_CONFLICT")
    return mapping_id


def migrate_legacy_record_reference(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    migration_id: str,
    legacy_reference: object,
    authorization: AuthorizedPrivacyRequest,
) -> RecordReferenceMigrationReceipt:
    declaration, migration, adapter = _bound_relocation(
        profile, adapters, resource_id, record_kind, migration_id
    )
    require_current_authorization(
        authorization, "record.reference.migrate", pack_id=profile.id
    )
    _require_scope(installation, declaration.scope_id)
    require_unlocked_session()
    reference = _reference(legacy_reference)
    identity_scope = _identity_scope(profile, resource_id, record_kind, migration)

    with _exclusive_state():
        require_current_authorization(
            authorization,
            "record.reference.migrate",
            pack_id=profile.id,
        )
        require_unlocked_session()
        state = _load_state()
        source_identities = _source_identities(identity_scope, reference)
        receipt_matches = [
            (source_identity, state["receipts"].get(source_identity))
            for source_identity in source_identities
            if isinstance(state["receipts"].get(source_identity), dict)
        ]
        if len(receipt_matches) > 1:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")
        if receipt_matches:
            source_identity, receipt = receipt_matches[0]
            if not _owned_state_item(receipt, identity_scope):
                raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")
            record_id = str(receipt.get("recordId") or "")
            _validate_current_target(adapter, declaration.current_schema, record_id)
            for transaction_id, item in tuple(state["transactions"].items()):
                if (
                    isinstance(item, dict)
                    and item.get("sourceIdentity") == source_identity
                    and item.get("phase") == "complete"
                ):
                    del state["transactions"][transaction_id]
                    _save_state(state)
            return RecordReferenceMigrationReceipt(record_id)
        transaction_id, transaction = _transaction_for(state, source_identities)
        if transaction is None:
            source = _legacy_source(adapter, migration.id, reference)
            _identity_key, identity_key_id = primary_session_key()
            source_identity = _source_identity_for_key_id(
                identity_key_id,
                identity_scope,
                reference,
            )
            transaction_id = "hp-rmap-txn-" + secrets.token_urlsafe(24)
            record_id = generate_private_record_id()
            mapping_id = generate_record_reference_mapping_id()
            protected_record = PrivacyEnvelopeCodec(declaration.current_schema).encrypt_state(
                copy.deepcopy(dict(source.value))
            )
            protected_mapping = PrivacyEnvelopeCodec(RECORD_REFERENCE_MAP_SCHEMA).encrypt_state(
                {
                    "pack": profile.id,
                    "fingerprint": profile.fingerprint,
                    "resource": resource_id,
                    "kind": record_kind,
                    "migration": migration.id,
                    "binding": migration.legacy_binding_id,
                    "reference": reference,
                    "target": record_id,
                }
            )
            transaction = {
                "transactionId": transaction_id,
                "phase": "prepared",
                "packId": profile.id,
                "profileFingerprint": profile.fingerprint,
                "resourceId": resource_id,
                "recordKind": record_kind,
                "migrationId": migration.id,
                "bindingId": migration.legacy_binding_id,
                "sourceIdentity": source_identity,
                "sourceIdentityKeyId": identity_key_id,
                "sourceRevision": source.revision,
                "recordId": record_id,
                "mappingId": mapping_id,
                "protectedRecord": protected_record,
                "protectedMapping": protected_mapping,
                "createdAtNs": time.time_ns(),
            }
            state["transactions"][transaction_id] = transaction
            _save_state(state)
        return _resume_relocation(
            state,
            transaction_id,
            transaction,
            adapter,
            declaration.current_schema,
            migration,
            identity_scope,
            reference,
        )


def resolve_legacy_record_reference(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    record_kind: str,
    migration_id: str,
    legacy_reference: object,
    authorization: AuthorizedPrivacyRequest,
) -> RecordReferenceResolution:
    declaration, migration, adapter = _bound_relocation(
        profile, adapters, resource_id, record_kind, migration_id
    )
    require_current_authorization(
        authorization, "record.reference.resolve", pack_id=profile.id
    )
    _require_scope(installation, declaration.scope_id)
    require_unlocked_session()
    reference = _reference(legacy_reference)
    identity_scope = _identity_scope(profile, resource_id, record_kind, migration)
    list_ids = getattr(adapter, "list_record_reference_mapping_ids", None)
    read_mapping = getattr(adapter, "read_record_reference_mapping", None)
    if not callable(list_ids) or not callable(read_mapping):
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
    matches: list[str] = []
    with _exclusive_state():
        require_current_authorization(
            authorization,
            "record.reference.resolve",
            pack_id=profile.id,
        )
        require_unlocked_session()
        state = _load_state()
        pending_mapping_ids = {
            str(item.get("mappingId") or "")
            for item in state["transactions"].values()
            if isinstance(item, dict) and _owned_state_item(item, identity_scope)
        }
        completed_mapping_ids = {
            str(item.get("mappingId") or "")
            for item in state["receipts"].values()
            if isinstance(item, dict) and _owned_state_item(item, identity_scope)
        }
        all_known_mapping_ids = {
            str(item.get("mappingId") or "")
            for collection in (state["transactions"], state["receipts"])
            for item in collection.values()
            if isinstance(item, dict)
        }
        try:
            mapping_ids = tuple(list_ids(migration.id))
        except Exception:
            raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE") from None
        if (
            any(not isinstance(item, str) or _MAPPING_ID.fullmatch(item) is None for item in mapping_ids)
            or pending_mapping_ids.intersection(mapping_ids)
            or any(item not in all_known_mapping_ids for item in mapping_ids)
        ):
            raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE")
        codec = PrivacyEnvelopeCodec(RECORD_REFERENCE_MAP_SCHEMA)
        for mapping_id in mapping_ids:
            try:
                protected = read_mapping(mapping_id)
                mapping = codec.decrypt_state(protected)
                if set(mapping) != {
                    "pack",
                    "fingerprint",
                    "resource",
                    "kind",
                    "migration",
                    "binding",
                    "reference",
                    "target",
                }:
                    raise ValueError
                if not _owned_mapping(mapping, identity_scope):
                    continue
                if mapping_id not in completed_mapping_ids:
                    raise ValueError
                candidate = mapping["reference"] if isinstance(mapping["reference"], str) else ""
                if hmac.compare_digest(candidate.encode(), reference.encode()):
                    matches.append(str(mapping["target"]))
            except Exception:
                raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE") from None
    if len(matches) != 1:
        raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE")
    _validate_current_target(adapter, declaration.current_schema, matches[0])
    return RecordReferenceResolution(matches[0])


def _resume_relocation(
    state,
    transaction_id,
    transaction,
    adapter,
    schema,
    migration,
    identity_scope,
    reference,
):
    phase = str(transaction.get("phase") or "")
    if phase == "blocked":
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")
    if not _owned_state_item(transaction, identity_scope):
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_CONFLICT")
    if transaction.get("sourceIdentity") != _source_identity_for_key_id(
        str(transaction.get("sourceIdentityKeyId") or ""),
        identity_scope,
        reference,
    ):
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_CONFLICT")
    if phase == "rollback-pending":
        _resume_rollback(state, transaction_id, transaction, adapter)
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_VERIFICATION_FAILED")
    commit: RecordRelocationCommit | None = None
    if phase == "prepared":
        write = RecordRelocationWrite(
            transaction_id,
            migration.id,
            str(transaction["recordId"]),
            str(transaction["mappingId"]),
            transaction["sourceRevision"],
            reference,
            copy.deepcopy(transaction["protectedRecord"]),
            copy.deepcopy(transaction["protectedMapping"]),
        )
        try:
            commit = adapter.commit_record_relocation(write)
        except Exception:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED") from None
        if not isinstance(commit, RecordRelocationCommit):
            _block(state, transaction_id)
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
        transaction.update(
            {
                "phase": "committed",
                "commitId": commit.commit_id,
                "recordRevision": commit.record_revision,
                "mappingRevision": commit.mapping_revision,
            }
        )
        _save_state(state)
        phase = "committed"
    if phase == "committed":
        commit = RecordRelocationCommit(
            str(transaction["commitId"]),
            transaction["recordRevision"],
            transaction["mappingRevision"],
        )
        try:
            readback = adapter.read_record_relocation(commit)
        except Exception:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED") from None
        verified = False
        try:
            verified = isinstance(readback, RecordRelocationReadback) and _verify_readback(
                readback,
                transaction,
                schema,
                identity_scope,
                reference,
            )
        except Exception:
            verified = False
        if not verified:
            _begin_rollback(state, transaction_id, transaction, adapter)
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_VERIFICATION_FAILED")
        transaction["phase"] = "verified"
        _save_state(state)
        phase = "verified"
    if phase == "verified":
        receipt_id = "hp-rmap-receipt-" + secrets.token_urlsafe(24)
        transaction.update({"phase": "finalize-pending", "receiptId": receipt_id})
        _save_state(state)
        phase = "finalize-pending"
    if phase == "finalize-pending":
        finalize = LegacyRecordFinalize(
            transaction_id,
            migration.id,
            reference,
            transaction["sourceRevision"],
            str(transaction["recordId"]),
        )
        try:
            result = adapter.finalize_legacy_record(finalize)
        except Exception:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_FINALIZATION_PENDING") from None
        if result == "diverged":
            _block(state, transaction_id)
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")
        if result not in {"finalized", "already-finalized"}:
            raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
        state["receipts"][str(transaction["sourceIdentity"])] = {
            "receiptId": transaction["receiptId"],
            "packId": identity_scope[0],
            "profileFingerprint": identity_scope[1],
            "resourceId": identity_scope[2],
            "recordKind": identity_scope[3],
            "migrationId": migration.id,
            "bindingId": identity_scope[5],
            "recordId": transaction["recordId"],
            "mappingId": transaction["mappingId"],
            "disposition": "complete",
            "completedAtNs": time.time_ns(),
        }
        transaction["phase"] = "complete"
        _save_state(state)
        del state["transactions"][transaction_id]
        _save_state(state)
        return RecordReferenceMigrationReceipt(str(transaction["recordId"]))
    if phase == "complete":
        del state["transactions"][transaction_id]
        _save_state(state)
        return RecordReferenceMigrationReceipt(str(transaction["recordId"]))
    raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")


def _verify_readback(readback, transaction, schema, identity_scope, reference):
    try:
        if (
            readback.record_revision != transaction["recordRevision"]
            or readback.mapping_revision != transaction["mappingRevision"]
            or _canonical(readback.protected_record) != _canonical(transaction["protectedRecord"])
            or _canonical(readback.protected_mapping) != _canonical(transaction["protectedMapping"])
        ):
            return False
        PrivacyEnvelopeCodec(schema).decrypt_state(readback.protected_record)
        mapping = PrivacyEnvelopeCodec(RECORD_REFERENCE_MAP_SCHEMA).decrypt_state(
            readback.protected_mapping
        )
    except Exception:
        return False
    return (
        set(mapping)
        == {
            "pack",
            "fingerprint",
            "resource",
            "kind",
            "migration",
            "binding",
            "reference",
            "target",
        }
        and _owned_mapping(mapping, identity_scope)
        and isinstance(mapping["reference"], str)
        and hmac.compare_digest(mapping["reference"].encode(), reference.encode())
        and mapping["target"] == transaction["recordId"]
    )


def _begin_rollback(state, transaction_id, transaction, adapter):
    transaction["phase"] = "rollback-pending"
    _save_state(state)
    _resume_rollback(state, transaction_id, transaction, adapter)


def _resume_rollback(state, transaction_id, transaction, adapter):
    rollback = RecordRelocationRollback(
        transaction_id,
        str(transaction["recordId"]),
        str(transaction["mappingId"]),
        transaction["recordRevision"],
        transaction["mappingRevision"],
    )
    try:
        result = adapter.rollback_record_relocation(rollback)
    except Exception:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED") from None
    if result in {"rolled-back", "already-original"}:
        del state["transactions"][transaction_id]
        _save_state(state)
    else:
        _block(state, transaction_id)


def _block(state, transaction_id):
    state["transactions"][transaction_id]["phase"] = "blocked"
    _save_state(state)


def _bound_relocation(profile, adapters, resource_id, record_kind, migration_id):
    migration = next(
        (
            item
            for item in profile.record_reference_migrations
            if item.id == migration_id
            and item.resource_id == resource_id
            and item.record_kind == record_kind
        ),
        None,
    )
    declaration = next(
        (
            item
            for item in profile.records
            if item.id == record_kind and item.resource_id == resource_id
        ),
        None,
    )
    if migration is None or declaration is None:
        raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_INVALID")
    adapter = adapters.get(declaration.store_adapter)
    methods = (
        "read_legacy_record",
        "commit_record_relocation",
        "read_record_relocation",
        "rollback_record_relocation",
        "finalize_legacy_record",
        "list_record_reference_mapping_ids",
        "read_record_reference_mapping",
        "list_ids",
        "read_record",
    )
    if adapter is None or any(not callable(getattr(adapter, name, None)) for name in methods):
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
    return declaration, migration, adapter


def _legacy_source(adapter, migration_id, reference):
    try:
        source = adapter.read_legacy_record(migration_id, reference)
    except Exception:
        raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE") from None
    if not isinstance(source, LegacyRecordSource):
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")
    return source


def _validate_current_target(adapter, schema, record_id):
    try:
        from .records import RecordSnapshot

        if record_id not in tuple(adapter.list_ids()):
            raise ValueError
        snapshot = adapter.read_record(record_id)
        if not isinstance(snapshot, RecordSnapshot) or snapshot.protected is None:
            raise ValueError
        PrivacyEnvelopeCodec(schema).decrypt_state(snapshot.protected)
    except Exception:
        raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE") from None


def _require_scope(installation, scope_id):
    from .mode_runtime import require_stable_bound_scope

    try:
        require_stable_bound_scope(installation, scope_id)
    except Exception:
        raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_UNAVAILABLE") from None


def _reference(value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_INVALID")
    return value


def _identity_scope(profile, resource_id, record_kind, migration):
    return (
        profile.id,
        profile.fingerprint,
        resource_id,
        record_kind,
        migration.id,
        migration.legacy_binding_id,
    )


def _owned_state_item(item, identity_scope):
    return (
        item.get("packId"),
        item.get("profileFingerprint"),
        item.get("resourceId"),
        item.get("recordKind"),
        item.get("migrationId"),
        item.get("bindingId"),
    ) == identity_scope


def _owned_mapping(mapping, identity_scope):
    return (
        mapping.get("pack"),
        mapping.get("fingerprint"),
        mapping.get("resource"),
        mapping.get("kind"),
        mapping.get("migration"),
        mapping.get("binding"),
    ) == identity_scope


def _source_identities(identity_scope, reference):
    return {
        _source_identity_for_key_id(key_id, identity_scope, reference): key_id
        for key_id in unlocked_session_key_ids()
    }


def _source_identity_for_key_id(key_id, identity_scope, reference):
    key = session_key_for(key_id)
    if key is None:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")
    message = b"\0".join(value.encode() for value in (*identity_scope, reference))
    return "hp-rmap-source-" + hmac.new(key, message, hashlib.sha256).hexdigest()


def _transaction_for(state, source_identities):
    matches = [
        (transaction_id, item)
        for transaction_id, item in state["transactions"].items()
        if isinstance(item, dict) and item.get("sourceIdentity") in source_identities
    ]
    if len(matches) > 1:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED")
    return matches[0] if matches else ("", None)


def _validate_revision(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, _REVISION_TYPES)
        or (isinstance(value, int) and value < 0)
        or (isinstance(value, str) and _OPAQUE_REVISION.fullmatch(value) is None)
    ):
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")


def _validate_opaque_id(value):
    if not isinstance(value, str) or not value or len(value) > 160:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_ADAPTER_INVALID")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_relocation_state_path() -> Path:
    configured = str(os.environ.get(RECORD_RELOCATION_STATE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    from .keystore import keystore_path

    return keystore_path().with_name("privacy_record_relocations.json")


def _empty_state():
    return {"version": RECORD_RELOCATION_STATE_VERSION, "transactions": {}, "receipts": {}}


def _load_state() -> dict[str, Any]:
    path = record_relocation_state_path()
    if not path.is_file():
        return _empty_state()
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if envelope.get("schema") != RECORD_RELOCATION_STATE_SCHEMA or envelope.get("version") != 1:
            raise ValueError
        key = session_key_for(str(envelope.get("keyId") or ""))
        if key is None:
            raise ValueError
        plaintext = AESGCM(key).decrypt(
            _b64decode(str(envelope["nonce"])),
            _b64decode(str(envelope["ciphertext"])),
            _STATE_AAD,
        )
        state = json.loads(plaintext)
        if (
            not isinstance(state, dict)
            or state.get("version") != 1
            or not isinstance(state.get("transactions"), dict)
            or not isinstance(state.get("receipts"), dict)
        ):
            raise ValueError
        return state
    except Exception:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_BLOCKED") from None


def _save_state(state):
    try:
        key, key_id = primary_session_key()
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _STATE_AAD)
        encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
        envelope = {
            "schema": RECORD_RELOCATION_STATE_SCHEMA,
            "version": 1,
            "keyId": key_id,
            "nonce": encode(nonce),
            "ciphertext": encode(ciphertext),
        }
        atomic_write_private_bytes(
            record_relocation_state_path(),
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(),
        )
    except RecordReferenceError:
        raise
    except Exception:
        raise RecordReferenceError("PRIVACY_RECORD_RELOCATION_TRANSACTION_FAILED") from None


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@contextmanager
def _exclusive_state():
    with _LOCK:
        path = record_relocation_state_path().with_suffix(
            record_relocation_state_path().suffix + ".lock"
        )
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
