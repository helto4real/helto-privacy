"""Revisioned encrypted singleton fields and blobs with verified replacement."""

from __future__ import annotations

import base64
import copy
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import RLock

from .envelope import ALGORITHM, ENVELOPE_VERSION, PrivacyEnvelopeCodec, PrivacyError
from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .profile import (
    PrivacyProfile,
    SingletonDeclaration,
    SingletonPayloadKind,
)


_ERROR_CODES = frozenset(
    {
        "PRIVACY_SINGLETON_ADAPTER_INVALID",
        "PRIVACY_SINGLETON_DECLARATION_INVALID",
        "PRIVACY_SINGLETON_DECRYPT_FAILED",
        "PRIVACY_SINGLETON_ENCRYPT_FAILED",
        "PRIVACY_SINGLETON_MODE_BLOCKED",
        "PRIVACY_SINGLETON_NOT_FOUND",
        "PRIVACY_SINGLETON_OPERATION_INVALID",
        "PRIVACY_SINGLETON_PAYLOAD_INVALID",
        "PRIVACY_SINGLETON_READ_FAILED",
        "PRIVACY_SINGLETON_REPLACE_FAILED",
        "PRIVACY_SINGLETON_REVISION_CONFLICT",
        "PRIVACY_SINGLETON_ROLLBACK_FAILED",
        "PRIVACY_SINGLETON_STORED_VALUE_INVALID",
        "PRIVACY_SINGLETON_VERIFICATION_FAILED",
    }
)


class SingletonError(RuntimeError):
    """Stable product-data-free singleton failure."""

    def __init__(self, code: str) -> None:
        self.code = (
            code if code in _ERROR_CODES else "PRIVACY_SINGLETON_OPERATION_INVALID"
        )
        self.correlation_id = "hp-singleton-" + secrets.token_urlsafe(12)
        super().__init__("Protected singleton operation could not complete.")

    def __repr__(self) -> str:
        return f"SingletonError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class SingletonSnapshot:
    """One adapter-owned revision and its opaque protected representation."""

    revision: int
    protected: object | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
            or (self.revision == 0 and self.protected is not None)
        ):
            raise ValueError("Singleton snapshot is invalid.")
        object.__setattr__(self, "protected", copy.deepcopy(self.protected))


@dataclass(frozen=True, slots=True)
class SingletonStatus:
    """Generic non-decrypting singleton status safe for locked responses."""

    exists: bool
    revision: int
    current_format: bool

    def to_payload(self) -> dict[str, object]:
        return {
            "exists": self.exists,
            "revision": self.revision,
            "private": True,
            "currentFormat": self.current_format,
        }


@dataclass(frozen=True, slots=True)
class RevealedSingleton:
    """Authorized plaintext kept out of repr and generic projections."""

    revision: int
    value: object = field(repr=False, compare=False)
    correlation_id: str


@dataclass(frozen=True, slots=True)
class ProtectedSingletonValue:
    """Typed current protection result without persistence authority."""

    payload_kind: SingletonPayloadKind
    protected: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.payload_kind, SingletonPayloadKind):
            raise ValueError("Protected singleton value is invalid.")
        object.__setattr__(self, "protected", copy.deepcopy(self.protected))


@dataclass(frozen=True, slots=True)
class SingletonMutationReceipt:
    """Product-data-free proof of one verified revision transition."""

    revision: int
    operation: str
    correlation_id: str

    def to_payload(self) -> dict[str, object]:
        return {
            "revision": self.revision,
            "operation": self.operation,
            "correlationId": self.correlation_id,
        }


_LOCK = RLock()
_SINGLETON_LOCKS: dict[tuple[str, str, str], RLock] = {}


def singleton_status(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
) -> SingletonStatus:
    declaration, adapter = _binding(profile, adapters, resource_id, singleton_id)
    _require_stable_scope(installation, declaration.scope_id)
    with _operation_lock(profile.id, resource_id, singleton_id):
        snapshot = _read_snapshot(adapter, declaration.id)
        if snapshot.protected is None:
            return SingletonStatus(False, snapshot.revision, True)
        if not _is_current_protected(declaration, snapshot.protected):
            raise SingletonError("PRIVACY_SINGLETON_STORED_VALUE_INVALID")
        return SingletonStatus(True, snapshot.revision, True)


def reveal_singleton_field(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    authorization: AuthorizedPrivacyRequest,
) -> RevealedSingleton:
    return _reveal_singleton(
        installation=installation,
        profile=profile,
        adapters=adapters,
        resource_id=resource_id,
        singleton_id=singleton_id,
        expected_kind=SingletonPayloadKind.FIELD,
        authorization=authorization,
    )


def reveal_singleton_blob(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    authorization: AuthorizedPrivacyRequest,
) -> RevealedSingleton:
    return _reveal_singleton(
        installation=installation,
        profile=profile,
        adapters=adapters,
        resource_id=resource_id,
        singleton_id=singleton_id,
        expected_kind=SingletonPayloadKind.BLOB,
        authorization=authorization,
    )


def replace_singleton_field(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    value: object,
    expected_revision: int,
    authorization: AuthorizedPrivacyRequest,
) -> SingletonMutationReceipt:
    declaration, adapter = _authorized_mutation_binding(
        installation,
        profile,
        adapters,
        resource_id,
        singleton_id,
        SingletonPayloadKind.FIELD,
        authorization,
        "singleton.replace",
    )
    protected = _protect_declared_singleton(
        declaration,
        value,
        SingletonPayloadKind.FIELD,
    ).protected
    return _replace_snapshot(
        profile.id,
        declaration,
        adapter,
        expected_revision,
        protected,
        "replace",
    )


def replace_singleton_blob(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    value: object,
    expected_revision: int,
    authorization: AuthorizedPrivacyRequest,
) -> SingletonMutationReceipt:
    declaration, adapter = _authorized_mutation_binding(
        installation,
        profile,
        adapters,
        resource_id,
        singleton_id,
        SingletonPayloadKind.BLOB,
        authorization,
        "singleton.replace",
    )
    protected = _protect_declared_singleton(
        declaration,
        value,
        SingletonPayloadKind.BLOB,
    ).protected
    return _replace_snapshot(
        profile.id,
        declaration,
        adapter,
        expected_revision,
        protected,
        "replace",
    )


def protect_singleton_field(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    value: object,
    authorization: AuthorizedPrivacyRequest,
) -> ProtectedSingletonValue:
    """Protect a field for a larger shared migration transaction."""

    declaration, _adapter = _authorized_mutation_binding(
        installation,
        profile,
        adapters,
        resource_id,
        singleton_id,
        SingletonPayloadKind.FIELD,
        authorization,
        "singleton.replace",
    )
    return _protect_declared_singleton(
        declaration,
        value,
        SingletonPayloadKind.FIELD,
    )


def protect_singleton_blob(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    value: object,
    authorization: AuthorizedPrivacyRequest,
) -> ProtectedSingletonValue:
    """Protect a blob for a larger shared migration transaction."""

    declaration, _adapter = _authorized_mutation_binding(
        installation,
        profile,
        adapters,
        resource_id,
        singleton_id,
        SingletonPayloadKind.BLOB,
        authorization,
        "singleton.replace",
    )
    return _protect_declared_singleton(
        declaration,
        value,
        SingletonPayloadKind.BLOB,
    )


def delete_singleton(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    expected_revision: int,
    authorization: AuthorizedPrivacyRequest,
) -> SingletonMutationReceipt:
    declaration, adapter = _authorized_mutation_binding(
        installation,
        profile,
        adapters,
        resource_id,
        singleton_id,
        None,
        authorization,
        "singleton.delete",
    )
    return _replace_snapshot(
        profile.id,
        declaration,
        adapter,
        expected_revision,
        None,
        "delete",
    )


def _reveal_singleton(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    expected_kind: SingletonPayloadKind,
    authorization: AuthorizedPrivacyRequest,
) -> RevealedSingleton:
    require_current_authorization(
        authorization,
        "singleton.reveal",
        pack_id=profile.id,
    )
    declaration, adapter = _binding(profile, adapters, resource_id, singleton_id)
    if declaration.payload_kind is not expected_kind:
        raise SingletonError("PRIVACY_SINGLETON_OPERATION_INVALID")
    _require_stable_scope(installation, declaration.scope_id)
    with _operation_lock(profile.id, resource_id, singleton_id):
        snapshot = _read_snapshot(adapter, declaration.id)
        if snapshot.protected is None:
            raise SingletonError("PRIVACY_SINGLETON_NOT_FOUND")
        if not _is_current_protected(declaration, snapshot.protected):
            raise SingletonError("PRIVACY_SINGLETON_STORED_VALUE_INVALID")
        codec = PrivacyEnvelopeCodec(declaration.current_schema)
        try:
            value = (
                codec.decrypt_state(snapshot.protected)
                if expected_kind is SingletonPayloadKind.FIELD
                else codec.decrypt_bytes(snapshot.protected, declaration.purpose)
            )
        except Exception:
            raise SingletonError("PRIVACY_SINGLETON_DECRYPT_FAILED") from None
        return RevealedSingleton(
            snapshot.revision,
            value,
            "hp-singleton-" + secrets.token_urlsafe(12),
        )


def _authorized_mutation_binding(
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
    expected_kind: SingletonPayloadKind | None,
    authorization: AuthorizedPrivacyRequest,
    operation_id: str,
) -> tuple[SingletonDeclaration, object]:
    require_current_authorization(
        authorization,
        operation_id,
        pack_id=profile.id,
    )
    declaration, adapter = _binding(profile, adapters, resource_id, singleton_id)
    if expected_kind is not None and declaration.payload_kind is not expected_kind:
        raise SingletonError("PRIVACY_SINGLETON_OPERATION_INVALID")
    _require_stable_scope(installation, declaration.scope_id)
    return declaration, adapter


def _protect_declared_singleton(
    declaration: SingletonDeclaration,
    value: object,
    expected_kind: SingletonPayloadKind,
) -> ProtectedSingletonValue:
    if declaration.payload_kind is not expected_kind:
        raise SingletonError("PRIVACY_SINGLETON_OPERATION_INVALID")
    if expected_kind is SingletonPayloadKind.FIELD:
        if not isinstance(value, Mapping):
            raise SingletonError("PRIVACY_SINGLETON_PAYLOAD_INVALID")
        try:
            normalized = copy.deepcopy(dict(value))
            json.dumps(
                normalized,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            protected = PrivacyEnvelopeCodec(
                declaration.current_schema
            ).encrypt_state(normalized)
        except Exception:
            raise SingletonError("PRIVACY_SINGLETON_ENCRYPT_FAILED") from None
    else:
        if not isinstance(value, bytes):
            raise SingletonError("PRIVACY_SINGLETON_PAYLOAD_INVALID")
        try:
            protected = PrivacyEnvelopeCodec(
                declaration.current_schema
            ).encrypt_bytes(value, declaration.purpose)
        except Exception:
            raise SingletonError("PRIVACY_SINGLETON_ENCRYPT_FAILED") from None
    return ProtectedSingletonValue(expected_kind, protected)


def _replace_snapshot(
    pack_id: str,
    declaration: SingletonDeclaration,
    adapter: object,
    expected_revision: int,
    protected: object | None,
    operation: str,
) -> SingletonMutationReceipt:
    if (
        not isinstance(expected_revision, int)
        or isinstance(expected_revision, bool)
        or expected_revision < 0
    ):
        raise SingletonError("PRIVACY_SINGLETON_REVISION_CONFLICT")
    replacement = SingletonSnapshot(expected_revision + 1, protected)
    with _operation_lock(pack_id, declaration.resource_id, declaration.id):
        original = _read_snapshot(adapter, declaration.id)
        if original.revision != expected_revision:
            raise SingletonError("PRIVACY_SINGLETON_REVISION_CONFLICT")
        if original.protected is not None and not _is_current_protected(
            declaration,
            original.protected,
        ):
            raise SingletonError("PRIVACY_SINGLETON_STORED_VALUE_INVALID")
        begin = getattr(adapter, "begin_singleton_replace", None)
        if not callable(begin):
            raise SingletonError("PRIVACY_SINGLETON_ADAPTER_INVALID")
        try:
            transaction = begin(declaration.id, expected_revision, replacement)
        except Exception:
            raise SingletonError("PRIVACY_SINGLETON_REPLACE_FAILED") from None
        methods = {
            name: getattr(transaction, name, None)
            for name in ("commit", "read_back", "rollback")
        }
        if any(not callable(method) for method in methods.values()):
            raise SingletonError("PRIVACY_SINGLETON_ADAPTER_INVALID")
        committed = False
        try:
            result = methods["commit"]()
            if result is False:
                # False is the adapter's atomic CAS-conflict signal. It must
                # not have changed authoritative state, and shared code must
                # not roll back a concurrent writer's newer revision.
                raise SingletonError("PRIVACY_SINGLETON_REVISION_CONFLICT")
            if result is not True:
                raise SingletonError("PRIVACY_SINGLETON_REPLACE_FAILED")
            committed = True
            try:
                persisted = methods["read_back"]()
            except Exception:
                raise SingletonError(
                    "PRIVACY_SINGLETON_VERIFICATION_FAILED"
                ) from None
            if not _snapshot_equal(persisted, replacement):
                raise SingletonError("PRIVACY_SINGLETON_VERIFICATION_FAILED")
        except SingletonError as exc:
            if committed or exc.code != "PRIVACY_SINGLETON_REVISION_CONFLICT":
                _rollback_transaction(methods, original)
            raise
        except Exception:
            _rollback_transaction(methods, original)
            raise SingletonError("PRIVACY_SINGLETON_REPLACE_FAILED") from None
    return SingletonMutationReceipt(
        replacement.revision,
        operation,
        "hp-singleton-" + secrets.token_urlsafe(12),
    )


def _rollback_transaction(methods: Mapping[str, object], original: SingletonSnapshot) -> None:
    try:
        methods["rollback"]()
        restored = methods["read_back"]()
    except Exception:
        raise SingletonError("PRIVACY_SINGLETON_ROLLBACK_FAILED") from None
    if not _snapshot_equal(restored, original):
        raise SingletonError("PRIVACY_SINGLETON_ROLLBACK_FAILED")


def _binding(
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    resource_id: str,
    singleton_id: str,
) -> tuple[SingletonDeclaration, object]:
    declaration = next(
        (
            item
            for item in profile.singletons
            if item.resource_id == resource_id and item.id == singleton_id
        ),
        None,
    )
    if declaration is None:
        raise SingletonError("PRIVACY_SINGLETON_DECLARATION_INVALID")
    adapter = adapters.get(declaration.store_adapter)
    if adapter is None:
        raise SingletonError("PRIVACY_SINGLETON_ADAPTER_INVALID")
    return declaration, adapter


def _read_snapshot(adapter: object, singleton_id: str) -> SingletonSnapshot:
    read = getattr(adapter, "read_singleton", None)
    if not callable(read):
        raise SingletonError("PRIVACY_SINGLETON_ADAPTER_INVALID")
    try:
        snapshot = read(singleton_id)
    except Exception:
        raise SingletonError("PRIVACY_SINGLETON_READ_FAILED") from None
    if not isinstance(snapshot, SingletonSnapshot):
        raise SingletonError("PRIVACY_SINGLETON_STORED_VALUE_INVALID")
    try:
        return SingletonSnapshot(snapshot.revision, snapshot.protected)
    except Exception:
        raise SingletonError("PRIVACY_SINGLETON_STORED_VALUE_INVALID") from None


def _snapshot_equal(left: object, right: SingletonSnapshot) -> bool:
    if not isinstance(left, SingletonSnapshot) or left.revision != right.revision:
        return False
    try:
        return _canonical_protected(left.protected) == _canonical_protected(
            right.protected
        )
    except (TypeError, ValueError):
        return False


def _canonical_protected(value: object | None) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _is_current_protected(
    declaration: SingletonDeclaration,
    protected: object,
) -> bool:
    payload = protected
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return False
    if not isinstance(payload, Mapping):
        return False
    if declaration.payload_kind is SingletonPayloadKind.FIELD:
        return _exact_state_envelope(payload, declaration.current_schema)
    return _exact_byte_envelope(payload, declaration.current_schema, declaration.purpose)


def _exact_state_envelope(payload: Mapping[str, object], schema: str) -> bool:
    if set(payload) != {
        "version",
        "schema",
        "encrypted",
        "algorithm",
        "keyId",
        "nonce",
        "ciphertext",
    }:
        return False
    return (
        payload.get("version") == ENVELOPE_VERSION
        and payload.get("schema") == schema
        and payload.get("encrypted") is True
        and payload.get("algorithm") == ALGORITHM
        and _canonical_b64(payload.get("keyId"), 12)
        and _canonical_b64(payload.get("nonce"), 12)
        and _canonical_b64(payload.get("ciphertext"), minimum=16)
    )


def _exact_byte_envelope(
    payload: Mapping[str, object],
    schema: str,
    purpose: str,
) -> bool:
    base = PrivacyEnvelopeCodec(schema)
    if payload.get("schema") == base.byte_schema:
        return (
            set(payload)
            == {
                "version",
                "schema",
                "encrypted",
                "algorithm",
                "purpose",
                "keyId",
                "nonce",
                "ciphertext",
            }
            and payload.get("version") == ENVELOPE_VERSION
            and payload.get("encrypted") is True
            and payload.get("algorithm") == ALGORITHM
            and payload.get("purpose") == purpose
            and _canonical_b64(payload.get("keyId"), 12)
            and _canonical_b64(payload.get("nonce"), 12)
            and _canonical_b64(payload.get("ciphertext"), minimum=16)
        )
    if payload.get("schema") != base.chunked_byte_schema or set(payload) != {
        "version",
        "schema",
        "encrypted",
        "algorithm",
        "purpose",
        "keyId",
        "chunkSize",
        "plaintextSize",
        "chunks",
    }:
        return False
    chunks = payload.get("chunks")
    if (
        payload.get("version") != ENVELOPE_VERSION
        or payload.get("encrypted") is not True
        or payload.get("algorithm") != ALGORITHM
        or payload.get("purpose") != purpose
        or not _canonical_b64(payload.get("keyId"), 12)
        or not isinstance(payload.get("chunkSize"), int)
        or isinstance(payload.get("chunkSize"), bool)
        or int(payload["chunkSize"]) < 1
        or not isinstance(payload.get("plaintextSize"), int)
        or isinstance(payload.get("plaintextSize"), bool)
        or int(payload["plaintextSize"]) < 0
        or not isinstance(chunks, list)
        or not chunks
    ):
        return False
    return all(
        isinstance(chunk, Mapping)
        and set(chunk) == {"index", "nonce", "ciphertext"}
        and chunk.get("index") == index
        and _canonical_b64(chunk.get("nonce"), 12)
        and _canonical_b64(chunk.get("ciphertext"), minimum=16)
        for index, chunk in enumerate(chunks)
    )


def _canonical_b64(value: object, length: int | None = None, minimum: int = 0) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        decoded = base64.urlsafe_b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii")
        )
    except Exception:
        return False
    encoded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    return encoded == value and (length is None or len(decoded) == length) and len(
        decoded
    ) >= minimum


def _operation_lock(pack_id: str, resource_id: str, singleton_id: str) -> RLock:
    key = (pack_id, resource_id, singleton_id)
    with _LOCK:
        return _SINGLETON_LOCKS.setdefault(key, RLock())


def _require_stable_scope(installation, scope_id: str) -> None:
    from .mode import ModePolicyError, ModeTransitionError
    from .mode_runtime import require_stable_bound_scope

    try:
        require_stable_bound_scope(installation, scope_id)
    except (ModePolicyError, ModeTransitionError):
        raise SingletonError("PRIVACY_SINGLETON_MODE_BLOCKED") from None


def reset_singleton_runtime_for_tests() -> None:
    """Clear process-only singleton operation locks."""

    with _LOCK:
        _SINGLETON_LOCKS.clear()
