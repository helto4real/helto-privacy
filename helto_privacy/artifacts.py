"""Managed encrypted privacy artifacts with opaque lifecycle references."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock

from . import keystore
from ._atomic_file import atomic_write_private_bytes
from .concurrency import (
    BLOCKING_ADAPTER_MAX_PENDING,
    reset_blocking_adapter_runtime_for_tests,
    run_blocking_adapter,
)
from .envelope import PrivacyEnvelopeCodec, PrivacyError
from .guard import (
    AuthorizedPrivacyRequest,
    PrivacyAuthorizationError,
    authorize_privacy_request,
    require_current_authorization,
)
from .mode import EffectivePrivacyMode, ModePolicyError, ModeTransitionError
from .mode_runtime import require_stable_bound_scope, resolve_bound_mode
from .profile import ArtifactDeclaration, ArtifactRetention, PrivacyProfile
from ._private_response import private_response_headers
from .suite_runtime import require_active_process_suite


ARTIFACT_ROOT_ENV = "HELTO_PRIVACY_ARTIFACT_ROOT"
ARTIFACT_REFERENCE_SCHEMA = "helto.private-artifact-reference"
ARTIFACT_REFERENCE_VERSION = 1
ARTIFACT_LEDGER_SCHEMA = "helto.private-artifact-ledger"
ARTIFACT_LEDGER_VERSION = 1
ARTIFACT_FILE_SCHEMA = "helto.private-artifact-file"
ARTIFACT_FILE_VERSION = 1
ARTIFACT_MAX_PENDING = BLOCKING_ADAPTER_MAX_PENDING
ARTIFACT_STREAM_CHUNK_BYTES = 1024 * 1024
ARTIFACT_MAX_LINE_BYTES = 2 * 1024 * 1024
ARTIFACT_MAX_CHUNKS = 65_536
ARTIFACT_LEASE_TTL_SECONDS = 60.0
REGENERABLE_CACHE_TTL_SECONDS = 24 * 60 * 60.0
REGENERABLE_CACHE_MAX_ENTRIES = 128
SERVED_TRANSIENT_TTL_SECONDS = 5 * 60.0

_ARTIFACT_ID = re.compile(r"^hp-art-[A-Za-z0-9_-]{32}$")
_OWNER_ID = re.compile(r"^hp-owner-[A-Za-z0-9_-]{32}$")
_LEASE_ID = re.compile(r"^hp-lease-[A-Za-z0-9_-]{32}$")
_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ERROR_CODES = frozenset(
    {
        "PRIVACY_ARTIFACT_ADAPTER_INVALID",
        "PRIVACY_ARTIFACT_CLEANUP_FAILED",
        "PRIVACY_ARTIFACT_DECODE_FAILED",
        "PRIVACY_ARTIFACT_ENCODE_FAILED",
        "PRIVACY_ARTIFACT_LEDGER_INVALID",
        "PRIVACY_ARTIFACT_LEASE_INVALID",
        "PRIVACY_ARTIFACT_MODE_BLOCKED",
        "PRIVACY_ARTIFACT_NOT_FOUND",
        "PRIVACY_ARTIFACT_OPERATION_FAILED",
        "PRIVACY_ARTIFACT_OPERATION_INVALID",
        "PRIVACY_ARTIFACT_REFERENCE_INVALID",
        "PRIVACY_ARTIFACT_RETENTION_INVALID",
        "PRIVACY_ARTIFACT_SOURCE_REJECTED",
        "PRIVACY_ARTIFACT_STORAGE_FAILED",
        "PRIVACY_ARTIFACT_UNREADABLE",
    }
)
_PROCESS_EPOCH = secrets.token_urlsafe(18)
_ROOT_BOUND_SOURCE_MARKER = object()
_LOCK = RLock()
_LEASES: dict[str, _LeaseRecord | _SourceLeaseRecord] = {}
_STREAM_END = object()


class ArtifactError(RuntimeError):
    """Stable product-data-free artifact lifecycle failure."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_CODES else "PRIVACY_ARTIFACT_OPERATION_FAILED"
        self.correlation_id = "hp-artifact-" + secrets.token_urlsafe(12)
        super().__init__("Private artifact operation could not complete.")

    def __repr__(self) -> str:
        return f"ArtifactError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    """Opaque serializable reference to one managed encrypted artifact."""

    id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or _ARTIFACT_ID.fullmatch(self.id) is None:
            raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema": ARTIFACT_REFERENCE_SCHEMA,
            "version": ARTIFACT_REFERENCE_VERSION,
            "id": self.id,
        }


@dataclass(frozen=True, slots=True)
class ArtifactSweepReport:
    """Path-free coarse result from one managed lifecycle sweep."""

    retired: int
    pending: int
    temp_variants: int


@dataclass(frozen=True, slots=True)
class ArtifactLease:
    """Opaque short-lived URL capability backed only by server process state."""

    id: str = field(repr=False)
    expires_in_seconds: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.id, str)
            or _LEASE_ID.fullmatch(self.id) is None
            or not isinstance(self.expires_in_seconds, int)
            or isinstance(self.expires_in_seconds, bool)
            or self.expires_in_seconds < 1
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")

    @property
    def url(self) -> str:
        return f"/helto_privacy/artifacts/{self.id}"

    def to_payload(self) -> dict[str, object]:
        return {
            "url": self.url,
            "expiresInSeconds": self.expires_in_seconds,
        }


@dataclass(frozen=True, slots=True)
class _ArtifactLocator:
    pack_id: str
    resource_id: str
    declaration: ArtifactDeclaration = field(repr=False)
    artifact_id: str = field(repr=False)

    @property
    def path(self) -> Path:
        return _artifact_path(
            self.pack_id,
            self.resource_id,
            self.declaration.id,
            self.artifact_id,
        )

    @property
    def schema(self) -> str:
        return _artifact_schema(self.pack_id, self.declaration)

    @property
    def purpose(self) -> str:
        return _artifact_purpose(self.pack_id, self.declaration)

    def matches(self, entry: dict) -> bool:
        return (
            entry.get("artifactId") == self.artifact_id
            and entry.get("artifactKind") == self.declaration.id
            and entry.get("formatVersion") == self.declaration.format_version
            and entry.get("packId") == self.pack_id
            and entry.get("resourceId") == self.resource_id
        )


@dataclass(slots=True)
class _LeaseRecord:
    installation: object = field(repr=False)
    locator: _ArtifactLocator = field(repr=False)
    operation: str
    expires_at: float
    session_fingerprint: bytes = field(repr=False)
    claimed: bool = False
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class RootBoundSource:
    """A validated existing file retained only in server process memory."""

    _root: str = field(repr=False)
    _relative_parts: tuple[str, ...] = field(repr=False)
    _device: int = field(repr=False)
    _inode: int = field(repr=False)
    media_type: str
    _marker: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._marker is not _ROOT_BOUND_SOURCE_MARKER:
            raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED")


@dataclass(slots=True)
class _SourceLeaseRecord:
    pack_id: str
    operation_id: str
    source: RootBoundSource = field(repr=False)
    expires_at: float
    session_fingerprint: bytes = field(repr=False)
    claimed: bool = False
    revoked: bool = False


class ArtifactLeaseStream:
    """Backpressure-aware authenticated plaintext stream held only in memory."""

    __slots__ = (
        "_lease_id",
        "_record",
        "correlation_id",
        "headers",
        "media_type",
    )

    def __init__(self, lease_id: str, record: _LeaseRecord) -> None:
        self._lease_id = lease_id
        self._record = record
        self.media_type = record.locator.declaration.media_type
        self.correlation_id = "hp-artifact-" + secrets.token_urlsafe(12)
        self.headers = private_artifact_response_headers(self.correlation_id)

    def __repr__(self) -> str:
        return "ArtifactLeaseStream()"

    async def iter_chunks(self):
        locator = self._record.locator
        declaration = locator.declaration
        iterator = _iter_artifact_plaintext(locator)
        completed = False
        try:
            while True:
                if not await _run_blocking(_lease_is_current, self._record):
                    raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
                try:
                    chunk = await _run_blocking(_next_chunk, iterator)
                except PrivacyError:
                    raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
                if chunk is _STREAM_END:
                    completed = True
                    break
                if not await _run_blocking(_lease_is_current, self._record):
                    raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
                yield chunk
        finally:
            revoke_artifact_lease(self._lease_id)
            if completed and declaration.retention is ArtifactRetention.SERVED_TRANSIENT:
                await _run_blocking(
                    _retire_matching,
                    lambda entry: (
                        entry.get("packId") == locator.pack_id
                        and entry.get("resourceId") == locator.resource_id
                        and entry.get("artifactKind") == declaration.id
                        and entry.get("artifactId") == locator.artifact_id
                    ),
                    False,
                )


class RootBoundSourceLeaseStream:
    """Backpressure-aware stream over one root-bound existing source file."""

    __slots__ = (
        "_lease_id",
        "_reader",
        "_record",
        "correlation_id",
        "headers",
        "media_type",
    )

    def __init__(self, lease_id: str, record: _SourceLeaseRecord, reader) -> None:
        self._lease_id = lease_id
        self._record = record
        self._reader = reader
        self.media_type = record.source.media_type
        self.correlation_id = "hp-artifact-" + secrets.token_urlsafe(12)
        self.headers = private_artifact_response_headers(self.correlation_id)

    def __repr__(self) -> str:
        return "RootBoundSourceLeaseStream()"

    async def iter_chunks(self):
        try:
            while True:
                if not await _run_blocking(_lease_is_current, self._record):
                    raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
                chunk = await _run_blocking(
                    self._reader.read,
                    ARTIFACT_STREAM_CHUNK_BYTES,
                )
                if not chunk:
                    break
                if not await _run_blocking(_lease_is_current, self._record):
                    raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
                yield chunk
        finally:
            await self.close()

    async def close(self) -> None:
        revoke_artifact_lease(self._lease_id)
        reader = self._reader
        self._reader = None
        if reader is not None:
            await _run_blocking(reader.close)


class ArtifactRun:
    """Exactly-once cleanup scope for run-scoped spill artifacts."""

    __slots__ = (
        "_adapters",
        "_closed",
        "_installation",
        "_owner_id",
        "_profile",
        "_resource_id",
    )

    def __init__(
        self,
        *,
        installation,
        profile,
        adapters,
        resource_id: str,
        owner_id: str | None = None,
    ) -> None:
        self._installation = installation
        self._profile = profile
        self._adapters = adapters
        self._resource_id = resource_id
        self._owner_id = _owner_id(owner_id or generate_artifact_owner_id())
        self._closed = False

    @property
    def owner_id(self) -> str:
        return self._owner_id

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _traceback) -> bool:
        await self.close()
        return False

    async def write(self, artifact_kind: str, value: object) -> ArtifactReference:
        if self._closed:
            raise ArtifactError("PRIVACY_ARTIFACT_RETENTION_INVALID")
        return await write_artifact(
            installation=self._installation,
            profile=self._profile,
            adapters=self._adapters,
            resource_id=self._resource_id,
            artifact_kind=artifact_kind,
            owner_id=self._owner_id,
            value=value,
            _run_scoped=True,
        )

    async def close(self) -> int:
        if self._closed:
            return 0
        self._closed = True
        return await release_owner_artifacts(
            profile=self._profile,
            resource_id=self._resource_id,
            owner_id=self._owner_id,
            retention="run-scoped-spill",
        )


def generate_artifact_owner_id() -> str:
    """Mint one opaque owner ID suitable for durable lifecycle bindings."""

    owner_id = "hp-owner-" + secrets.token_urlsafe(24)
    if _OWNER_ID.fullmatch(owner_id) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    return owner_id


async def write_artifact(
    *,
    installation,
    profile: PrivacyProfile,
    adapters,
    resource_id: str,
    artifact_kind: str,
    owner_id: str,
    value: object,
    _run_scoped: bool = False,
) -> ArtifactReference:
    """Encode and atomically persist one generated artifact as ciphertext."""

    require_active_process_suite()
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    if (declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL) is not _run_scoped:
        raise ArtifactError("PRIVACY_ARTIFACT_RETENTION_INVALID")
    await _run_blocking(_require_private_scope, installation, declaration)
    try:
        await _run_blocking(keystore.require_unlocked_session)
    except keystore.PrivacyKeystoreError:
        raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED") from None
    safe_owner = _owner_id(owner_id)
    adapter = adapters.get(declaration.payload_adapter)
    encode = getattr(adapter, "encode", None)
    if not callable(encode):
        raise ArtifactError("PRIVACY_ARTIFACT_ADAPTER_INVALID")
    try:
        encoded = await _run_blocking(encode, value)
    except Exception:
        raise ArtifactError("PRIVACY_ARTIFACT_ENCODE_FAILED") from None
    if not isinstance(encoded, (bytes, bytearray)):
        raise ArtifactError("PRIVACY_ARTIFACT_ENCODE_FAILED")
    plaintext = bytes(encoded)
    reference = ArtifactReference(_new_artifact_id())
    locator = _ArtifactLocator(
        profile.id,
        resource_id,
        declaration,
        reference.id,
    )
    try:
        await _run_blocking(
            _persist_artifact,
            locator,
            safe_owner,
            plaintext,
        )
    finally:
        if isinstance(encoded, bytearray):
            encoded.clear()
    return reference


async def read_artifact(
    *,
    installation,
    profile: PrivacyProfile,
    adapters,
    resource_id: str,
    artifact_kind: str,
    reference: object,
) -> object:
    """Decrypt in memory and decode one artifact through its declared adapter."""

    require_active_process_suite()
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    await _run_blocking(_require_private_scope, installation, declaration)
    safe_reference = _reference(reference)
    adapter = adapters.get(declaration.payload_adapter)
    decode = getattr(adapter, "decode", None)
    if not callable(decode):
        raise ArtifactError("PRIVACY_ARTIFACT_ADAPTER_INVALID")
    locator = _ArtifactLocator(
        profile.id,
        resource_id,
        declaration,
        safe_reference.id,
    )
    plaintext = await _run_blocking(
        _load_artifact_bytes,
        locator,
    )
    mutable = bytearray(plaintext)
    try:
        try:
            return await _run_blocking(decode, bytes(mutable))
        except Exception:
            raise ArtifactError("PRIVACY_ARTIFACT_DECODE_FAILED") from None
    finally:
        mutable.clear()


async def retire_artifact(
    *,
    profile: PrivacyProfile,
    resource_id: str,
    artifact_kind: str,
    reference: object,
) -> int:
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    safe_reference = _reference(reference)
    return await _run_blocking(
        _retire_matching,
        lambda entry: (
            entry.get("packId") == profile.id
            and entry.get("resourceId") == resource_id
            and entry.get("artifactKind") == declaration.id
            and entry.get("artifactId") == safe_reference.id
        ),
        True,
    )


async def retire_artifact_group(
    *,
    profile: PrivacyProfile,
    resource_id: str,
    artifacts: tuple[tuple[str, object], ...] | list[tuple[str, object]],
) -> int:
    """Revoke a reference group atomically; defer failed file deletion."""

    identities: set[tuple[str, str]] = set()
    for artifact_kind, reference in artifacts:
        declaration = _artifact_declaration(profile, resource_id, artifact_kind)
        safe_reference = _reference(reference)
        identity = (declaration.id, safe_reference.id)
        if identity in identities:
            raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
        identities.add(identity)
    if not identities:
        return 0
    return await _run_blocking(
        _retire_group_matching,
        lambda entry: (
            entry.get("packId") == profile.id
            and entry.get("resourceId") == resource_id
            and (entry.get("artifactKind"), entry.get("artifactId")) in identities
        ),
    )


async def release_owner_artifacts(
    *,
    profile: PrivacyProfile,
    resource_id: str,
    owner_id: str,
    retention: str | None = None,
) -> int:
    safe_owner = _owner_id(owner_id)
    return await _run_blocking(
        _retire_matching,
        lambda entry: (
            entry.get("packId") == profile.id
            and entry.get("resourceId") == resource_id
            and entry.get("ownerId") == safe_owner
            and (retention is None or entry.get("retention") == retention)
        ),
        True,
    )


async def sweep_artifacts() -> ArtifactSweepReport:
    return await _run_blocking(_sweep_artifacts)


async def issue_artifact_lease(
    *,
    installation,
    profile: PrivacyProfile,
    resource_id: str,
    artifact_kind: str,
    reference: object,
    operation: str,
    authorization: AuthorizedPrivacyRequest,
) -> ArtifactLease:
    require_active_process_suite()
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    safe_operation = str(operation or "")
    if safe_operation not in declaration.operations:
        raise ArtifactError("PRIVACY_ARTIFACT_OPERATION_INVALID")
    require_current_authorization(
        authorization,
        f"artifact.{safe_operation}",
        pack_id=profile.id,
    )
    await _run_blocking(_require_private_scope, installation, declaration)
    safe_reference = _reference(reference)
    locator = _ArtifactLocator(
        profile.id,
        resource_id,
        declaration,
        safe_reference.id,
    )
    await _run_blocking(
        _require_artifact_entry,
        locator,
    )
    lease_id = _new_lease_id()
    expires_at = time.time() + ARTIFACT_LEASE_TTL_SECONDS
    session_fingerprint = await _run_blocking(_session_fingerprint)
    record = _LeaseRecord(
        installation,
        locator,
        safe_operation,
        expires_at,
        session_fingerprint,
    )
    with _LOCK:
        _expire_leases_locked()
        _LEASES[lease_id] = record
    if not await _run_blocking(_lease_is_current, record):
        revoke_artifact_lease(lease_id)
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    return ArtifactLease(lease_id, max(1, int(ARTIFACT_LEASE_TTL_SECONDS)))


def root_bound_source(
    path: str | os.PathLike[str],
    allowed_roots: tuple[str | os.PathLike[str], ...] | list[str | os.PathLike[str]],
    *,
    media_type: str,
) -> RootBoundSource:
    """Validate one existing regular file against consumer-declared roots."""

    normalized_media_type = str(media_type or "").strip().lower()
    if _MEDIA_TYPE.fullmatch(normalized_media_type) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED")
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED")
    resolved_path = os.path.realpath(os.path.abspath(os.fspath(path)))
    candidates: list[tuple[int, str, tuple[str, ...]]] = []
    for root in allowed_roots:
        root_path = os.path.realpath(os.path.abspath(os.fspath(root)))
        try:
            if os.path.commonpath((resolved_path, root_path)) != root_path:
                continue
        except ValueError:
            continue
        relative_parts = Path(os.path.relpath(resolved_path, root_path)).parts
        if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
            continue
        candidates.append((len(root_path), root_path, relative_parts))
    if not candidates:
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED")
    _length, root_path, relative_parts = max(candidates, key=lambda item: item[0])
    try:
        source_stat = os.stat(resolved_path, follow_symlinks=False)
    except OSError:
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED") from None
    if not stat.S_ISREG(source_stat.st_mode):
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED")
    return RootBoundSource(
        root_path,
        relative_parts,
        source_stat.st_dev,
        source_stat.st_ino,
        normalized_media_type,
        _ROOT_BOUND_SOURCE_MARKER,
    )


async def issue_root_bound_source_lease(
    *,
    pack_id: str,
    operation_id: str,
    source: RootBoundSource,
    authorization: AuthorizedPrivacyRequest,
) -> ArtifactLease:
    """Issue one opaque lease over an authorized existing source file."""

    require_active_process_suite()
    safe_pack_id = str(pack_id or "")
    safe_operation = str(operation_id or "")
    if (
        _STABLE_ID.fullmatch(safe_pack_id) is None
        or _STABLE_ID.fullmatch(safe_operation) is None
        or not isinstance(source, RootBoundSource)
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED")
    require_current_authorization(
        authorization,
        safe_operation,
        pack_id=safe_pack_id,
    )
    lease_id = _new_lease_id()
    record = _SourceLeaseRecord(
        safe_pack_id,
        safe_operation,
        source,
        time.time() + ARTIFACT_LEASE_TTL_SECONDS,
        await _run_blocking(_session_fingerprint),
    )
    with _LOCK:
        _expire_leases_locked()
        _LEASES[lease_id] = record
    if not await _run_blocking(_lease_is_current, record):
        revoke_artifact_lease(lease_id)
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    return ArtifactLease(lease_id, max(1, int(ARTIFACT_LEASE_TTL_SECONDS)))


async def open_artifact_lease(
    request,
    lease_id: str,
) -> ArtifactLeaseStream | RootBoundSourceLeaseStream:
    safe_lease_id = _lease_id(lease_id)
    with _LOCK:
        _expire_leases_locked()
        record = _LEASES.get(safe_lease_id)
        if record is None or record.claimed:
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
        record.claimed = True
    try:
        if not await _run_blocking(_lease_is_current, record):
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
        await _run_blocking(_authorize_lease_stream, request, record)
        if isinstance(record, _SourceLeaseRecord):
            reader = await _run_blocking(_open_root_bound_source, record.source)
            return RootBoundSourceLeaseStream(safe_lease_id, record, reader)
        await _run_blocking(_require_artifact_file, record.locator)
        return ArtifactLeaseStream(safe_lease_id, record)
    except PrivacyAuthorizationError:
        revoke_artifact_lease(safe_lease_id)
        raise
    except ArtifactError:
        revoke_artifact_lease(safe_lease_id)
        raise
    except Exception:
        revoke_artifact_lease(safe_lease_id)
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID") from None


def _authorize_lease_stream(
    request,
    record: _LeaseRecord | _SourceLeaseRecord,
) -> None:
    if isinstance(record, _SourceLeaseRecord):
        operation_id = record.operation_id
        pack_id = record.pack_id
    else:
        operation_id = f"artifact.{record.operation}"
        pack_id = record.installation.profile.id
    authorize_privacy_request(
        request,
        operation_id,
        pack_id=pack_id,
    )


def revoke_artifact_lease(lease_id: str) -> bool:
    safe_lease_id = _lease_id(lease_id)
    with _LOCK:
        record = _LEASES.pop(safe_lease_id, None)
        if record is not None:
            record.revoked = True
        return record is not None


def invalidate_artifact_session(_reason: str = "session-change") -> None:
    with _LOCK:
        for record in _LEASES.values():
            record.revoked = True
        _LEASES.clear()


def invalidate_artifact_profile(pack_id: str) -> None:
    """Revoke only leases belonging to one conflicting profile identity."""

    with _LOCK:
        revoked = [
            lease_id
            for lease_id, record in _LEASES.items()
            if _lease_record_pack_id(record) == pack_id
        ]
        for lease_id in revoked:
            record = _LEASES.pop(lease_id, None)
            if record is not None:
                record.revoked = True


def initialize_artifact_service(profile: PrivacyProfile) -> ArtifactSweepReport | None:
    """Run the interruption-safe startup sweep before an artifact pack installs."""

    if not profile.artifacts:
        return None
    return _sweep_artifacts()


def prepare_artifact_mode_transition(installation, scope_id: str, context) -> None:
    """Purge declared plaintext derivatives before privacy becomes authoritative."""

    if (
        context.prior_mode is EffectivePrivacyMode.PRIVATE
        or context.target_mode is not EffectivePrivacyMode.PRIVATE
    ):
        return
    _sweep_temp_variants(strict=True)
    declarations = sorted(
        (
            declaration
            for declaration in installation.profile.artifacts
            if declaration.scope_id == scope_id
        ),
        key=lambda declaration: declaration.id,
    )
    try:
        for declaration in declarations:
            adapter = installation.adapters[declaration.payload_adapter]
            purge = getattr(adapter, "purge_plaintext_derivatives", None)
            if not callable(purge):
                raise ArtifactError("PRIVACY_ARTIFACT_ADAPTER_INVALID")
            purge(declaration.id)
    except Exception:
        raise ArtifactError("PRIVACY_ARTIFACT_CLEANUP_FAILED") from None


async def run_artifact_mode_transition(
    mode_handle,
    scope_id: str,
    target: object,
    authorization: object,
):
    """Run transition-time artifact purge behind bounded worker admission."""

    return await _run_blocking(
        mode_handle.transition,
        scope_id,
        target,
        authorization,
    )


def private_artifact_response_headers(correlation_id: str) -> dict[str, str]:
    try:
        return private_response_headers(
            correlation_id,
            correlation_prefix="hp-artifact-",
            disposition="inline",
            filename="private-artifact.bin",
        )
    except ValueError:
        raise ArtifactError("PRIVACY_ARTIFACT_OPERATION_INVALID") from None


def reset_artifact_runtime_for_tests() -> None:
    """Reset process-local admission state for isolated synthetic tests."""

    global _PROCESS_EPOCH
    with _LOCK:
        _PROCESS_EPOCH = secrets.token_urlsafe(18)
        reset_blocking_adapter_runtime_for_tests()
        _LEASES.clear()


def _persist_artifact(
    locator: _ArtifactLocator,
    owner_id: str,
    plaintext: bytes,
) -> None:
    path = locator.path
    declaration = locator.declaration
    codec = PrivacyEnvelopeCodec(locator.schema)
    try:
        protected = codec.encrypt_bytes(
            plaintext,
            locator.purpose,
            chunk_size=ARTIFACT_STREAM_CHUNK_BYTES,
        )
        payload = _encode_artifact_file(protected)
        with _LOCK:
            _ensure_private_tree(path.parent)
            atomic_write_private_bytes(path, payload)
            ledger = _load_ledger()
            created_at = time.time()
            entry = {
                "artifactId": locator.artifact_id,
                "artifactKind": declaration.id,
                "cleanupPending": False,
                "createdAt": created_at,
                "formatVersion": declaration.format_version,
                "ownerId": owner_id,
                "packId": locator.pack_id,
                "processEpoch": _PROCESS_EPOCH,
                "resourceId": locator.resource_id,
                "retention": declaration.retention.value,
            }
            if declaration.retention is ArtifactRetention.REGENERABLE_CACHE:
                entry["expiresAt"] = created_at + REGENERABLE_CACHE_TTL_SECONDS
            elif declaration.retention is ArtifactRetention.SERVED_TRANSIENT:
                entry["expiresAt"] = created_at + SERVED_TRANSIENT_TTL_SECONDS
            ledger["entries"].append(entry)
            retire_ids = _apply_retention_locked(ledger, entry)
            _write_ledger(ledger)
            if retire_ids:
                _retire_from_ledger(
                    ledger,
                    lambda candidate: candidate.get("artifactId") in retire_ids,
                )
                try:
                    _write_ledger(ledger)
                except Exception:
                    # The first committed ledger retains cleanupPending markers;
                    # startup or an explicit sweep will finish the retry.
                    pass
    except ArtifactError:
        _unlink_quietly(path)
        raise
    except Exception:
        _unlink_quietly(path)
        raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED") from None


def _load_artifact_bytes(
    locator: _ArtifactLocator,
) -> bytes:
    _require_artifact_entry(locator)
    return b"".join(_iter_artifact_plaintext(locator))


def _discard_unreadable_cache(locator: _ArtifactLocator) -> None:
    if locator.declaration.retention is ArtifactRetention.REGENERABLE_CACHE:
        _retire_matching(
            locator.matches,
            False,
        )


def _encode_artifact_file(protected: dict[str, object]) -> bytes:
    envelope = dict(protected)
    chunks = envelope.pop("chunks", None)
    if chunks is None:
        chunk_entries: list[object] = []
    elif isinstance(chunks, list) and chunks:
        chunk_entries = chunks
    else:
        raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED")
    header = {
        "schema": ARTIFACT_FILE_SCHEMA,
        "version": ARTIFACT_FILE_VERSION,
        "chunkCount": len(chunk_entries),
        "envelope": envelope,
    }
    lines = [_compact_json(header)]
    lines.extend(_compact_json(chunk) for chunk in chunk_entries)
    return ("\n".join(lines) + "\n").encode("utf-8")


def _compact_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _artifact_declaration(
    profile: PrivacyProfile,
    resource_id: str,
    artifact_kind: str,
) -> ArtifactDeclaration:
    declaration = next(
        (
            item
            for item in profile.artifacts
            if item.resource_id == resource_id and item.id == artifact_kind
        ),
        None,
    )
    if declaration is None:
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    return declaration


def _require_private_scope(installation, declaration: ArtifactDeclaration) -> None:
    scope = next(
        (
            item
            for item in installation.profile.scopes
            if item.id == declaration.scope_id
        ),
        None,
    )
    if scope is None:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    try:
        require_stable_bound_scope(installation, scope.id)
        resolution = resolve_bound_mode(
            installation,
            scope.mode_resource_id,
            scope.id,
            None,
        )
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None
    if resolution.effective is not EffectivePrivacyMode.PRIVATE:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")


def _reference(value: object) -> ArtifactReference:
    if isinstance(value, ArtifactReference):
        return value
    if isinstance(value, dict) and set(value) == {"schema", "version", "id"}:
        if (
            value.get("schema") == ARTIFACT_REFERENCE_SCHEMA
            and value.get("version") == ARTIFACT_REFERENCE_VERSION
        ):
            return ArtifactReference(value.get("id"))
    raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")


def _owner_id(value: object) -> str:
    owner_id = value if isinstance(value, str) else ""
    if _OWNER_ID.fullmatch(owner_id) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    return owner_id


def _new_artifact_id() -> str:
    artifact_id = "hp-art-" + secrets.token_urlsafe(24)
    if _ARTIFACT_ID.fullmatch(artifact_id) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    return artifact_id


def _new_lease_id() -> str:
    lease_id = "hp-lease-" + secrets.token_urlsafe(24)
    if _LEASE_ID.fullmatch(lease_id) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    return lease_id


def _lease_id(value: object) -> str:
    lease_id = value if isinstance(value, str) else ""
    if _LEASE_ID.fullmatch(lease_id) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    return lease_id


def _session_fingerprint() -> bytes:
    token = keystore.session_token()
    if not token:
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    return hashlib.sha256(token.encode("utf-8")).digest()


def _expire_leases_locked() -> None:
    now = time.time()
    expired = [
        lease_id
        for lease_id, record in _LEASES.items()
        if record.expires_at <= now
    ]
    for lease_id in expired:
        record = _LEASES.pop(lease_id, None)
        if record is not None:
            record.revoked = True


def _lease_record_pack_id(record: _LeaseRecord | _SourceLeaseRecord) -> str:
    if isinstance(record, _SourceLeaseRecord):
        return record.pack_id
    return record.installation.profile.id


def _lease_is_current(record: _LeaseRecord | _SourceLeaseRecord) -> bool:
    with _LOCK:
        if record.revoked or record.expires_at <= time.time():
            record.revoked = True
            return False
    try:
        current = _session_fingerprint()
    except Exception:
        return False
    with _LOCK:
        if (
            record.revoked
            or record.expires_at <= time.time()
            or not hmac.compare_digest(record.session_fingerprint, current)
        ):
            record.revoked = True
            return False
        return True


def _open_root_bound_source(source: RootBoundSource):
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        current_fd = os.open(source._root, directory_flags)
        directory_fds.append(current_fd)
        for part in source._relative_parts[:-1]:
            current_fd = os.open(part, directory_flags, dir_fd=current_fd)
            directory_fds.append(current_fd)
        file_fd = os.open(source._relative_parts[-1], file_flags, dir_fd=current_fd)
        source_stat = os.fstat(file_fd)
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_dev != source._device
            or source_stat.st_ino != source._inode
        ):
            raise OSError("Private media source changed after authorization.")
        reader = os.fdopen(file_fd, "rb")
        file_fd = None
        return reader
    except (OSError, ValueError):
        raise ArtifactError("PRIVACY_ARTIFACT_SOURCE_REJECTED") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _artifact_root() -> Path:
    configured = str(os.environ.get(ARTIFACT_ROOT_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    return keystore.keystore_path().parent / "privacy_artifacts"


def _artifact_path(
    pack_id: str,
    resource_id: str,
    artifact_kind: str,
    artifact_id: str,
) -> Path:
    return _artifact_root() / pack_id / resource_id / artifact_kind / f"{artifact_id}.hpa"


def _artifact_schema(pack_id: str, declaration: ArtifactDeclaration) -> str:
    return f"helto.artifact.{pack_id}.{declaration.id}.v{declaration.format_version}"


def _artifact_purpose(pack_id: str, declaration: ArtifactDeclaration) -> str:
    return (
        f"{pack_id}.{declaration.id}.{declaration.purpose}."
        f"v{declaration.format_version}"
    )


def _empty_ledger() -> dict[str, object]:
    return {
        "schema": ARTIFACT_LEDGER_SCHEMA,
        "version": ARTIFACT_LEDGER_VERSION,
        "entries": [],
    }


def _load_ledger() -> dict[str, object]:
    path = _artifact_root() / "ledger.json"
    if not path.exists():
        return _empty_ledger()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID") from None
    if (
        not isinstance(value, dict)
        or value.get("schema") != ARTIFACT_LEDGER_SCHEMA
        or value.get("version") != ARTIFACT_LEDGER_VERSION
        or not isinstance(value.get("entries"), list)
        or any(not _valid_ledger_entry(entry) for entry in value["entries"])
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    return value


def _valid_ledger_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    required = {
        "artifactId",
        "artifactKind",
        "cleanupPending",
        "createdAt",
        "formatVersion",
        "ownerId",
        "packId",
        "processEpoch",
        "resourceId",
        "retention",
    }
    keys = set(entry)
    if keys != required and keys != required | {"expiresAt"}:
        return False
    stable_values = (
        entry.get("artifactKind"),
        entry.get("packId"),
        entry.get("resourceId"),
    )
    numeric_values = (entry.get("createdAt"), entry.get("expiresAt", 0.0))
    return (
        isinstance(entry.get("artifactId"), str)
        and _ARTIFACT_ID.fullmatch(entry["artifactId"]) is not None
        and isinstance(entry.get("ownerId"), str)
        and _OWNER_ID.fullmatch(entry["ownerId"]) is not None
        and all(
            isinstance(value, str) and _STABLE_ID.fullmatch(value) is not None
            for value in stable_values
        )
        and isinstance(entry.get("cleanupPending"), bool)
        and all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and float(value) >= 0
            for value in numeric_values
        )
        and isinstance(entry.get("formatVersion"), int)
        and not isinstance(entry.get("formatVersion"), bool)
        and entry["formatVersion"] >= 1
        and isinstance(entry.get("processEpoch"), str)
        and 8 <= len(entry["processEpoch"]) <= 128
        and entry.get("retention")
        in {
            "durable-adjunct",
            "regenerable-cache",
            "run-scoped-spill",
            "served-transient",
        }
    )


def _write_ledger(ledger: dict[str, object]) -> None:
    root = _artifact_root()
    _ensure_private_tree(root)
    payload = json.dumps(
        ledger,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    atomic_write_private_bytes(root / "ledger.json", payload)


def _ensure_private_tree(path: Path) -> None:
    root = _artifact_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    current = root
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED") from None
    for part in relative.parts:
        current /= part
        current.mkdir(exist_ok=True, mode=0o700)
        os.chmod(current, 0o700)


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _require_artifact_entry(
    locator: _ArtifactLocator,
) -> dict:
    with _LOCK:
        entry = next(
            (
                candidate
                for candidate in _load_ledger()["entries"]
                if locator.matches(candidate)
            ),
            None,
        )
    if entry is None:
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    if _entry_is_stale(entry):
        _retire_matching(
            locator.matches,
            False,
        )
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    return entry


def _require_artifact_file(locator: _ArtifactLocator) -> None:
    try:
        metadata = locator.path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError
    except FileNotFoundError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_NOT_FOUND") from None
    except OSError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None


def _iter_artifact_plaintext(locator: _ArtifactLocator):
    codec = PrivacyEnvelopeCodec(locator.schema)
    try:
        with locator.path.open("r", encoding="utf-8") as stream:
            header = _read_artifact_json_line(stream)
            if (
                not isinstance(header, dict)
                or set(header) != {"schema", "version", "chunkCount", "envelope"}
                or header.get("schema") != ARTIFACT_FILE_SCHEMA
                or header.get("version") != ARTIFACT_FILE_VERSION
                or not isinstance(header.get("envelope"), dict)
                or not isinstance(header.get("chunkCount"), int)
                or isinstance(header.get("chunkCount"), bool)
                or int(header["chunkCount"]) < 0
                or int(header["chunkCount"]) > ARTIFACT_MAX_CHUNKS
            ):
                raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
            envelope = header["envelope"]
            chunk_count = int(header["chunkCount"])
            if chunk_count:
                chunks = _iter_artifact_chunk_lines(stream, chunk_count)
                yield from codec.iter_decrypt_chunked_bytes(
                    envelope,
                    locator.purpose,
                    chunks,
                    chunk_count,
                )
            else:
                if envelope.get("schema") == codec.chunked_byte_schema:
                    raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
                yield from codec.iter_decrypt_bytes(envelope, locator.purpose)
                if stream.read(1):
                    raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
    except FileNotFoundError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_NOT_FOUND") from None
    except ArtifactError:
        _discard_unreadable_cache(locator)
        raise
    except (OSError, UnicodeError, ValueError, PrivacyError):
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None


def _iter_artifact_chunk_lines(stream, chunk_count: int):
    for _index in range(chunk_count):
        chunk = _read_artifact_json_line(stream)
        if not isinstance(chunk, dict) or set(chunk) != {
            "index",
            "nonce",
            "ciphertext",
        }:
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
        yield chunk
    if stream.read(1):
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")


def _read_artifact_json_line(stream) -> object:
    line = stream.readline(ARTIFACT_MAX_LINE_BYTES + 1)
    if not line or len(line) > ARTIFACT_MAX_LINE_BYTES or not line.endswith("\n"):
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
    return json.loads(line)


def _next_chunk(iterator):
    try:
        return next(iterator)
    except StopIteration:
        return _STREAM_END


def _apply_retention_locked(ledger: dict[str, object], new_entry: dict) -> set[str]:
    retention = new_entry["retention"]
    candidates = [
        entry
        for entry in ledger["entries"]
        if entry is not new_entry
        and entry.get("packId") == new_entry["packId"]
        and entry.get("resourceId") == new_entry["resourceId"]
        and entry.get("artifactKind") == new_entry["artifactKind"]
    ]
    retire_ids: set[str] = set()
    if retention == "served-transient":
        retire_ids.update(
            entry["artifactId"]
            for entry in candidates
            if entry.get("ownerId") == new_entry["ownerId"]
        )
    elif retention == "regenerable-cache":
        ordered = sorted(
            [*candidates, new_entry],
            key=lambda entry: float(entry.get("createdAt", 0)),
            reverse=True,
        )
        retire_ids.update(
            entry["artifactId"]
            for entry in ordered[REGENERABLE_CACHE_MAX_ENTRIES:]
        )
    if retire_ids:
        for entry in candidates:
            if entry.get("artifactId") in retire_ids:
                entry["cleanupPending"] = True
    return retire_ids


def _retire_matching(predicate, fail_on_error: bool) -> int:
    with _LOCK:
        ledger = _load_ledger()
        retired, failed = _retire_from_ledger(ledger, predicate)
        _write_ledger(ledger)
    if failed and fail_on_error:
        raise ArtifactError("PRIVACY_ARTIFACT_CLEANUP_FAILED")
    return retired


def _retire_group_matching(predicate) -> int:
    """Revoke group authority even when ciphertext deletion needs a sweep."""

    with _LOCK:
        ledger = _load_ledger()
        retired, _failed = _retire_from_ledger(
            ledger,
            predicate,
            forget_failed=True,
        )
        _write_ledger(ledger)
    return retired


def _retire_from_ledger(
    ledger: dict[str, object],
    predicate,
    *,
    forget_failed: bool = False,
) -> tuple[int, int]:
    remaining = []
    retired = 0
    failed = 0
    for entry in ledger["entries"]:
        if not predicate(entry):
            remaining.append(entry)
            continue
        _revoke_entry_leases_locked(entry)
        try:
            _entry_path(entry).unlink(missing_ok=True)
            retired += 1
        except OSError:
            if not forget_failed:
                entry["cleanupPending"] = True
                remaining.append(entry)
            failed += 1
    ledger["entries"] = remaining
    return retired, failed


def _revoke_entry_leases_locked(entry: dict) -> None:
    for lease_id, record in tuple(_LEASES.items()):
        if not isinstance(record, _LeaseRecord):
            continue
        locator = record.locator
        if (
            locator.pack_id == entry.get("packId")
            and locator.resource_id == entry.get("resourceId")
            and locator.declaration.id == entry.get("artifactKind")
            and locator.artifact_id == entry.get("artifactId")
        ):
            record.revoked = True
            _LEASES.pop(lease_id, None)


def _entry_path(entry: dict) -> Path:
    return _artifact_path(
        str(entry.get("packId") or ""),
        str(entry.get("resourceId") or ""),
        str(entry.get("artifactKind") or ""),
        str(entry.get("artifactId") or ""),
    )


def _entry_is_stale(entry: dict) -> bool:
    expires_at = entry.get("expiresAt")
    if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
        if float(expires_at) <= time.time():
            return True
    return (
        entry.get("retention") in {"run-scoped-spill", "served-transient"}
        and entry.get("processEpoch") != _PROCESS_EPOCH
    )


def _sweep_artifacts() -> ArtifactSweepReport:
    temp_variants = _sweep_temp_variants(strict=True)
    with _LOCK:
        ledger = _load_ledger()
        retired, _failed = _retire_from_ledger(
            ledger,
            lambda entry: bool(entry.get("cleanupPending")) or _entry_is_stale(entry),
        )
        _write_ledger(ledger)
        pending = sum(
            1 for entry in ledger["entries"] if entry.get("cleanupPending") is True
        )
        orphan_retired, orphan_pending = _sweep_orphan_artifacts_locked(ledger)
    return ArtifactSweepReport(
        retired + orphan_retired,
        pending + orphan_pending,
        temp_variants,
    )


def _sweep_orphan_artifacts_locked(ledger: dict[str, object]) -> tuple[int, int]:
    root = _artifact_root()
    if not root.exists():
        return 0, 0
    managed = {_entry_path(entry) for entry in ledger["entries"]}
    retired = 0
    pending = 0
    for path in root.rglob("*.hpa"):
        if path in managed:
            continue
        try:
            path.unlink()
            retired += 1
        except OSError:
            pending += 1
    return retired, pending


def _sweep_temp_variants(*, strict: bool = False) -> int:
    temp_variants = 0
    failed = False
    with _LOCK:
        root = _artifact_root()
        if root.exists():
            for path in root.rglob("*"):
                if path.is_file() and (
                    path.name.endswith((".tmp", ".part", ".plaintext"))
                    or (path.name.startswith(".") and ".hpa." in path.name)
                ):
                    try:
                        path.unlink()
                        temp_variants += 1
                    except OSError:
                        failed = True
    if strict and failed:
        raise ArtifactError("PRIVACY_ARTIFACT_CLEANUP_FAILED")
    return temp_variants


_run_blocking = run_blocking_adapter
