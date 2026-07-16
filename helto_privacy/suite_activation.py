"""Explicit suite activation authorization and atomic rollback records."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._atomic_file import atomic_write_private_bytes, sync_parent_directory
from ._suite_codec import (
    canonical_json_bytes,
    is_sha256,
    is_stable_id,
    is_utc_timestamp,
    sign_canonical_record,
    verify_canonical_record_signature,
)
from .suite import RollbackClass


_ACTIVATION_SIGNATURE_DOMAIN = b"helto.privacy.suite-activation.v2\x00"


class SuiteActivationError(RuntimeError):
    """Sanitized activation failure that never includes product data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Explicit suite activation failed.")


@dataclass(frozen=True, slots=True)
class ActivationRequest:
    manifest_digest: str
    inventory_digest: str
    process_nonce: str
    previous_suite_id: str | None
    rollback: RollbackClass

    def __post_init__(self) -> None:
        _require_sha256(self.manifest_digest, "invalid_activation_manifest")
        _require_sha256(self.inventory_digest, "invalid_activation_inventory")
        _require_sha256(self.process_nonce, "invalid_activation_process_nonce")
        if self.previous_suite_id is not None:
            _require_stable_id(self.previous_suite_id, "invalid_previous_suite")
        if not isinstance(self.rollback, RollbackClass):
            raise SuiteActivationError("invalid_rollback_class")


@dataclass(frozen=True, slots=True)
class SignedActivationAuthorization:
    manifest_digest: str
    inventory_digest: str
    process_nonce: str
    pre_activation_snapshot_digest: str
    authorization_id: str
    authorized_at: str
    signer_key_id: str
    signature: str

    def __post_init__(self) -> None:
        _require_sha256(self.manifest_digest, "invalid_activation_manifest")
        _require_sha256(self.inventory_digest, "invalid_activation_inventory")
        _require_sha256(self.process_nonce, "invalid_activation_process_nonce")
        _require_sha256(
            self.pre_activation_snapshot_digest,
            "invalid_snapshot_digest",
        )
        _require_stable_id(self.authorization_id, "invalid_authorization_id")
        _require_utc_timestamp(self.authorized_at)
        _require_stable_id(self.signer_key_id, "invalid_activation_signer")
        if not isinstance(self.signature, str) or not self.signature:
            raise SuiteActivationError("invalid_activation_signature")

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "manifestDigest": self.manifest_digest,
                "inventoryDigest": self.inventory_digest,
                "processNonce": self.process_nonce,
                "preActivationSnapshotDigest": self.pre_activation_snapshot_digest,
                "authorizationId": self.authorization_id,
                "authorizedAt": self.authorized_at,
            }
        )


@dataclass(frozen=True, slots=True)
class ActivationRecord:
    manifest_digest: str
    inventory_digest: str
    process_nonce: str
    pre_activation_snapshot_digest: str
    authorization_id: str
    activated_at: str
    signer_key_id: str
    authorization_signature: str
    previous_suite_id: str | None
    rollback: RollbackClass

    def __post_init__(self) -> None:
        _require_sha256(self.manifest_digest, "invalid_activation_manifest")
        _require_sha256(self.inventory_digest, "invalid_activation_inventory")
        _require_sha256(self.process_nonce, "invalid_activation_process_nonce")
        _require_sha256(
            self.pre_activation_snapshot_digest,
            "invalid_snapshot_digest",
        )
        _require_stable_id(self.authorization_id, "invalid_authorization_id")
        _require_utc_timestamp(self.activated_at)
        _require_stable_id(self.signer_key_id, "invalid_activation_signer")
        if (
            not isinstance(self.authorization_signature, str)
            or not self.authorization_signature
        ):
            raise SuiteActivationError("invalid_activation_signature")
        if self.previous_suite_id is not None:
            _require_stable_id(self.previous_suite_id, "invalid_previous_suite")
        if not isinstance(self.rollback, RollbackClass):
            raise SuiteActivationError("invalid_rollback_class")


class ActivationRecordStore(Protocol):
    def load(self) -> ActivationRecord | None: ...

    def commit(self, record: ActivationRecord) -> None: ...

    def block(self, record: ActivationRecord) -> None: ...


class FileActivationRecordStore:
    """Atomic local persistence for the product-data-free activation record."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    def load(self) -> ActivationRecord | None:
        if not self._path.exists():
            return None
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            return ActivationRecord(
                manifest_digest=str(payload["manifestDigest"]),
                inventory_digest=str(payload["inventoryDigest"]),
                process_nonce=str(payload["processNonce"]),
                pre_activation_snapshot_digest=str(
                    payload["preActivationSnapshotDigest"]
                ),
                authorization_id=str(payload["authorizationId"]),
                activated_at=str(payload["activatedAt"]),
                signer_key_id=str(payload["signerKeyId"]),
                authorization_signature=str(payload["authorizationSignature"]),
                previous_suite_id=(
                    str(payload["previousSuiteId"])
                    if payload.get("previousSuiteId") is not None
                    else None
                ),
                rollback=RollbackClass(str(payload["rollback"])),
            )
        except (OSError, KeyError, TypeError, ValueError):
            raise SuiteActivationError("activation_record_invalid") from None

    def commit(self, record: ActivationRecord) -> None:
        if not isinstance(record, ActivationRecord):
            raise SuiteActivationError("invalid_activation_record")
        payload = canonical_json_bytes(
            {
                "manifestDigest": record.manifest_digest,
                "inventoryDigest": record.inventory_digest,
                "processNonce": record.process_nonce,
                "preActivationSnapshotDigest": record.pre_activation_snapshot_digest,
                "authorizationId": record.authorization_id,
                "activatedAt": record.activated_at,
                "signerKeyId": record.signer_key_id,
                "authorizationSignature": record.authorization_signature,
                "previousSuiteId": record.previous_suite_id,
                "rollback": record.rollback.value,
            }
        )
        try:
            atomic_write_private_bytes(self._path, payload)
        except Exception:
            raise SuiteActivationError("activation_record_commit_failed") from None

    def block(self, record: ActivationRecord) -> None:
        """Atomically quarantine an activation while retaining its boundary."""

        if not isinstance(record, ActivationRecord):
            raise SuiteActivationError("invalid_activation_record")
        blocked_path = self._path.with_name(
            f"{self._path.name}.blocked.{record.authorization_id}"
        )
        try:
            os.replace(self._path, blocked_path)
            os.chmod(blocked_path, 0o600)
            sync_parent_directory(blocked_path)
        except Exception:
            raise SuiteActivationError("activation_record_block_failed") from None


def sign_activation_authorization(
    request: ActivationRequest,
    *,
    pre_activation_snapshot_digest: str,
    authorization_id: str,
    authorized_at: str,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedActivationAuthorization:
    """Sign a one-use authorization bound to exact verified installation bytes."""

    if not isinstance(request, ActivationRequest):
        raise SuiteActivationError("invalid_activation_request")
    _require_sha256(pre_activation_snapshot_digest, "invalid_snapshot_digest")
    _require_stable_id(authorization_id, "invalid_authorization_id")
    _require_utc_timestamp(authorized_at)
    _require_stable_id(signer_key_id, "invalid_activation_signer")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SuiteActivationError("invalid_activation_signing_key")
    unsigned = SignedActivationAuthorization(
        manifest_digest=request.manifest_digest,
        inventory_digest=request.inventory_digest,
        process_nonce=request.process_nonce,
        pre_activation_snapshot_digest=pre_activation_snapshot_digest,
        authorization_id=authorization_id,
        authorized_at=authorized_at,
        signer_key_id=signer_key_id,
        signature="unsigned",
    )
    signature = sign_canonical_record(
        private_key,
        _ACTIVATION_SIGNATURE_DOMAIN,
        unsigned.canonical_bytes(),
    )
    return SignedActivationAuthorization(
        manifest_digest=unsigned.manifest_digest,
        inventory_digest=unsigned.inventory_digest,
        process_nonce=unsigned.process_nonce,
        pre_activation_snapshot_digest=unsigned.pre_activation_snapshot_digest,
        authorization_id=unsigned.authorization_id,
        authorized_at=unsigned.authorized_at,
        signer_key_id=unsigned.signer_key_id,
        signature=signature,
    )


def verify_activation_authorization(
    authorization: SignedActivationAuthorization,
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    if not isinstance(authorization, SignedActivationAuthorization):
        raise SuiteActivationError("invalid_activation_authorization")
    _require_sha256(authorization.manifest_digest, "invalid_activation_manifest")
    _require_sha256(authorization.inventory_digest, "invalid_activation_inventory")
    _require_sha256(
        authorization.process_nonce,
        "invalid_activation_process_nonce",
    )
    _require_sha256(
        authorization.pre_activation_snapshot_digest,
        "invalid_snapshot_digest",
    )
    _require_stable_id(authorization.authorization_id, "invalid_authorization_id")
    _require_utc_timestamp(authorization.authorized_at)
    _require_stable_id(authorization.signer_key_id, "invalid_activation_signer")
    public_key = trusted_keys.get(authorization.signer_key_id)
    if not isinstance(public_key, Ed25519PublicKey):
        raise SuiteActivationError("untrusted_activation_signer")
    if not verify_canonical_record_signature(
        public_key,
        authorization.signature,
        _ACTIVATION_SIGNATURE_DOMAIN,
        authorization.canonical_bytes(),
    ):
        raise SuiteActivationError("invalid_activation_signature") from None


def _require_sha256(value: object, code: str) -> None:
    if not is_sha256(value):
        raise SuiteActivationError(code)


def _require_stable_id(value: object, code: str) -> None:
    if not is_stable_id(value):
        raise SuiteActivationError(code)


def _require_utc_timestamp(value: object) -> None:
    if not is_utc_timestamp(value):
        raise SuiteActivationError("invalid_activation_timestamp")
