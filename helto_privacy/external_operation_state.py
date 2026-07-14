"""Public external-operation index and immutable encrypted journals."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ._atomic_file import atomic_write_private_bytes, sync_parent_directory
from ._encrypted_journal import (
    EncryptedJournalError,
    load_encrypted_json,
    publish_encrypted_json,
)
from ._suite_codec import is_stable_id
from .keystore import keystore_path


EXTERNAL_OPERATION_STATE_ENV = "HELTO_PRIVACY_EXTERNAL_OPERATION_STATE"
EXTERNAL_OPERATION_STATE_SCHEMA = "helto.privacy-external-operation-state"
EXTERNAL_OPERATION_STATE_VERSION = 1
EXTERNAL_OPERATION_JOURNAL_SCHEMA = "helto.privacy-external-operation-journal"
EXTERNAL_OPERATION_JOURNAL_VERSION = 1
EXTERNAL_OPERATION_JOURNAL_AAD = (
    f"{EXTERNAL_OPERATION_JOURNAL_SCHEMA}|{EXTERNAL_OPERATION_JOURNAL_VERSION}"
).encode("ascii")
EXTERNAL_OPERATION_ACTIVE_PHASES = frozenset(
    {"captured", "prepared", "applied", "rollback-required"}
)
EXTERNAL_OPERATION_TERMINAL_PHASES = frozenset({"completed", "rolled-back"})
EXTERNAL_OPERATION_MAX_ACTIVE_PER_PACK = 64
EXTERNAL_OPERATION_MAX_ACTIVE_GLOBAL = 256
EXTERNAL_OPERATION_MAX_RECORDS = 4096
EXTERNAL_OPERATION_MAX_JOURNAL_BYTES = 32 * 1024 * 1024

_TRANSACTION_ID = re.compile(r"^hp-operation-[A-Za-z0-9_-]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class ExternalOperationStateError(RuntimeError):
    """Sanitized durable-state failure for an external operation."""

    def __init__(self) -> None:
        super().__init__("External protected-operation state is unavailable.")


@dataclass(frozen=True, slots=True)
class ExternalOperationRecord:
    transaction_id: str
    pack_id: str
    profile_fingerprint: str
    scope_id: str
    operation_id: str
    owner_digest: str
    request_digest: str
    resume_digest: str
    phase: str
    journal_digest: str
    expires_at_ns: int
    updated_at_ns: int
    receipt_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.transaction_id, str)
            or _TRANSACTION_ID.fullmatch(self.transaction_id) is None
            or not all(
                is_stable_id(value)
                for value in (self.pack_id, self.scope_id, self.operation_id)
            )
            or _DIGEST.fullmatch(self.profile_fingerprint) is None
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.owner_digest,
                    self.request_digest,
                    self.resume_digest,
                    self.journal_digest,
                )
            )
            or self.phase
            not in EXTERNAL_OPERATION_ACTIVE_PHASES
            | EXTERNAL_OPERATION_TERMINAL_PHASES
            or type(self.expires_at_ns) is not int
            or self.expires_at_ns < 0
            or type(self.updated_at_ns) is not int
            or self.updated_at_ns < 1
            or (
                self.receipt_digest is not None
                and _DIGEST.fullmatch(self.receipt_digest) is None
            )
        ):
            raise ExternalOperationStateError()
        terminal = self.phase in EXTERNAL_OPERATION_TERMINAL_PHASES
        if terminal != (self.receipt_digest is not None) or (
            terminal and self.expires_at_ns != 0
        ):
            raise ExternalOperationStateError()

    @property
    def active(self) -> bool:
        return self.phase in EXTERNAL_OPERATION_ACTIVE_PHASES


def external_operation_state_path() -> Path:
    configured = str(os.environ.get(EXTERNAL_OPERATION_STATE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    return keystore_path().with_name("privacy_external_operations.json")


@contextmanager
def exclusive_external_operation_state():
    path = external_operation_state_path()
    lock_path = path.with_suffix(path.suffix + ".lock")
    descriptor: int | None = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(lock_path.parent, 0o700)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise ExternalOperationStateError() from None
    try:
        yield
    finally:
        if descriptor is None:
            raise ExternalOperationStateError()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def load_external_operation_state() -> tuple[int, tuple[ExternalOperationRecord, ...]]:
    path = external_operation_state_path()
    if not path.exists():
        return 0, ()
    try:
        raw = path.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError
        payload = json.loads(raw)
        if (
            type(payload) is not dict
            or set(payload) != {"schema", "version", "revision", "records"}
            or payload["schema"] != EXTERNAL_OPERATION_STATE_SCHEMA
            or payload["version"] != EXTERNAL_OPERATION_STATE_VERSION
            or type(payload["revision"]) is not int
            or payload["revision"] < 1
            or type(payload["records"]) is not list
            or len(payload["records"]) > EXTERNAL_OPERATION_MAX_RECORDS
        ):
            raise ValueError
        records = _validate_record_collection(
            tuple(_record_from_payload(item) for item in payload["records"])
        )
        return payload["revision"], records
    except Exception:
        raise ExternalOperationStateError() from None


def commit_external_operation_state(
    records: Iterable[ExternalOperationRecord],
    *,
    expected_revision: int,
) -> int:
    """CAS, durably replace, reopen, and verify the public index."""

    try:
        values = _validate_record_collection(tuple(records))
        if (
            type(expected_revision) is not int
            or expected_revision < 0
        ):
            raise ValueError
        current_revision, _current = load_external_operation_state()
        if current_revision != expected_revision:
            raise ValueError
        revision = expected_revision + 1
        payload = {
            "schema": EXTERNAL_OPERATION_STATE_SCHEMA,
            "version": EXTERNAL_OPERATION_STATE_VERSION,
            "revision": revision,
            "records": [
                _record_payload(item)
                for item in sorted(values, key=lambda item: item.transaction_id)
            ],
        }
        encoded = _canonical_json(payload)
        atomic_write_private_bytes(external_operation_state_path(), encoded)
        reopened_revision, reopened = load_external_operation_state()
        if reopened_revision != revision or tuple(
            sorted(reopened, key=lambda item: item.transaction_id)
        ) != tuple(sorted(values, key=lambda item: item.transaction_id)):
            raise ValueError
        return revision
    except ExternalOperationStateError:
        raise
    except Exception:
        raise ExternalOperationStateError() from None


def publish_external_operation_journal(
    record_identity: tuple[str, str, str],
    payload: Mapping[str, object],
) -> str:
    pack_id, operation_id, transaction_id = _journal_identity(record_identity)
    try:
        return publish_encrypted_json(
            path_for_digest=lambda digest: external_operation_journal_path(
                pack_id,
                operation_id,
                transaction_id,
                digest,
            ),
            schema=EXTERNAL_OPERATION_JOURNAL_SCHEMA,
            version=EXTERNAL_OPERATION_JOURNAL_VERSION,
            aad=EXTERNAL_OPERATION_JOURNAL_AAD,
            payload=payload,
            maximum_plaintext_bytes=EXTERNAL_OPERATION_MAX_JOURNAL_BYTES,
        )
    except EncryptedJournalError:
        raise ExternalOperationStateError() from None


def load_external_operation_journal(
    record: ExternalOperationRecord,
) -> dict[str, object]:
    if not isinstance(record, ExternalOperationRecord):
        raise ExternalOperationStateError()
    path = external_operation_journal_path(
        record.pack_id,
        record.operation_id,
        record.transaction_id,
        record.journal_digest,
    )
    try:
        payload, digest = load_encrypted_json(
            path=path,
            schema=EXTERNAL_OPERATION_JOURNAL_SCHEMA,
            version=EXTERNAL_OPERATION_JOURNAL_VERSION,
            aad=EXTERNAL_OPERATION_JOURNAL_AAD,
            expected_digest=record.journal_digest,
            maximum_plaintext_bytes=EXTERNAL_OPERATION_MAX_JOURNAL_BYTES,
        )
        if (
            digest != record.journal_digest
            or payload.get("packId") != record.pack_id
            or payload.get("profileFingerprint") != record.profile_fingerprint
            or payload.get("scopeId") != record.scope_id
            or payload.get("operationId") != record.operation_id
            or payload.get("transactionId") != record.transaction_id
            or payload.get("phase") != record.phase
        ):
            raise ValueError
        return payload
    except Exception:
        raise ExternalOperationStateError() from None


def external_operation_journal_path(
    pack_id: str,
    operation_id: str,
    transaction_id: str,
    digest: str,
) -> Path:
    _journal_identity((pack_id, operation_id, transaction_id))
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ExternalOperationStateError()
    stem = hashlib.sha256(
        f"{pack_id}\0{operation_id}\0{transaction_id}".encode("utf-8")
    ).hexdigest()
    state = external_operation_state_path()
    return state.with_name(f"{state.stem}.journals").joinpath(
        f"{stem}.{digest}.json"
    )


def delete_external_operation_journal_revision(
    record: ExternalOperationRecord,
    digest: str,
) -> None:
    try:
        path = external_operation_journal_path(
            record.pack_id,
            record.operation_id,
            record.transaction_id,
            digest,
        )
        path.unlink(missing_ok=True)
        if path.parent.exists():
            sync_parent_directory(path)
    except Exception:
        raise ExternalOperationStateError() from None


def sweep_unreferenced_external_operation_journals() -> None:
    with exclusive_external_operation_state():
        _revision, records = load_external_operation_state()
        referenced = {
            external_operation_journal_path(
                record.pack_id,
                record.operation_id,
                record.transaction_id,
                record.journal_digest,
            ).name
            for record in records
        }
        directory = external_operation_state_path().with_name(
            f"{external_operation_state_path().stem}.journals"
        )
        try:
            if directory.exists():
                for candidate in directory.glob("*.json"):
                    if candidate.name not in referenced:
                        candidate.unlink(missing_ok=True)
                sync_parent_directory(directory)
        except OSError:
            raise ExternalOperationStateError() from None


def has_active_external_operations(
    *,
    pack_id: str | None = None,
    scope_id: str | None = None,
) -> bool:
    _revision, records = load_external_operation_state()
    return any(
        record.active
        and (pack_id is None or record.pack_id == pack_id)
        and (scope_id is None or record.scope_id == scope_id)
        for record in records
    )


def _record_payload(record: ExternalOperationRecord) -> dict[str, object]:
    return {
        "transactionId": record.transaction_id,
        "packId": record.pack_id,
        "profileFingerprint": record.profile_fingerprint,
        "scopeId": record.scope_id,
        "operationId": record.operation_id,
        "ownerDigest": record.owner_digest,
        "requestDigest": record.request_digest,
        "resumeDigest": record.resume_digest,
        "phase": record.phase,
        "journalDigest": record.journal_digest,
        "expiresAtNs": record.expires_at_ns,
        "updatedAtNs": record.updated_at_ns,
        "receiptDigest": record.receipt_digest,
    }


def _validate_record_collection(
    records: tuple[ExternalOperationRecord, ...],
) -> tuple[ExternalOperationRecord, ...]:
    if (
        len(records) > EXTERNAL_OPERATION_MAX_RECORDS
        or any(not isinstance(item, ExternalOperationRecord) for item in records)
        or len({item.transaction_id for item in records}) != len(records)
    ):
        raise ValueError
    active = tuple(item for item in records if item.active)
    if (
        len(active) > EXTERNAL_OPERATION_MAX_ACTIVE_GLOBAL
        or any(
            sum(item.pack_id == pack_id for item in active)
            > EXTERNAL_OPERATION_MAX_ACTIVE_PER_PACK
            for pack_id in {item.pack_id for item in active}
        )
        or len(
            {
                (item.pack_id, item.operation_id, item.request_digest)
                for item in records
            }
        )
        != len(records)
        or len({(item.pack_id, item.owner_digest) for item in active})
        != len(active)
    ):
        raise ValueError
    return records


def _record_from_payload(value: object) -> ExternalOperationRecord:
    if type(value) is not dict or set(value) != {
        "transactionId",
        "packId",
        "profileFingerprint",
        "scopeId",
        "operationId",
        "ownerDigest",
        "requestDigest",
        "resumeDigest",
        "phase",
        "journalDigest",
        "expiresAtNs",
        "updatedAtNs",
        "receiptDigest",
    }:
        raise ExternalOperationStateError()
    return ExternalOperationRecord(
        value["transactionId"],
        value["packId"],
        value["profileFingerprint"],
        value["scopeId"],
        value["operationId"],
        value["ownerDigest"],
        value["requestDigest"],
        value["resumeDigest"],
        value["phase"],
        value["journalDigest"],
        value["expiresAtNs"],
        value["updatedAtNs"],
        value["receiptDigest"],
    )


def _journal_identity(
    value: tuple[str, str, str],
) -> tuple[str, str, str]:
    if (
        type(value) is not tuple
        or len(value) != 3
        or not is_stable_id(value[0])
        or not is_stable_id(value[1])
        or not isinstance(value[2], str)
        or _TRANSACTION_ID.fullmatch(value[2]) is None
    ):
        raise ExternalOperationStateError()
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise ExternalOperationStateError() from None


__all__ = [
    "EXTERNAL_OPERATION_ACTIVE_PHASES",
    "EXTERNAL_OPERATION_MAX_ACTIVE_GLOBAL",
    "EXTERNAL_OPERATION_MAX_ACTIVE_PER_PACK",
    "EXTERNAL_OPERATION_STATE_ENV",
    "EXTERNAL_OPERATION_TERMINAL_PHASES",
    "ExternalOperationRecord",
    "ExternalOperationStateError",
    "commit_external_operation_state",
    "delete_external_operation_journal_revision",
    "exclusive_external_operation_state",
    "has_active_external_operations",
    "load_external_operation_journal",
    "load_external_operation_state",
    "publish_external_operation_journal",
    "sweep_unreferenced_external_operation_journals",
]
