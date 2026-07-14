"""Managed privacy artifacts with opaque references and mode-fixed storage."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import time
import fcntl
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import Event, RLock, local
from typing import Mapping

from . import keystore
from .artifact_stream import (
    ArtifactStreamCancelled,
    ArtifactStreamError,
    PrivateArtifactStreamWriter,
    PublicArtifactStreamWriter,
    open_private_artifact_source,
    open_public_artifact_source,
)
from ._atomic_file import atomic_write_private_bytes, sync_parent_directory
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
from .mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModePolicyError,
    ModeTransitionError,
)
from .mode_runtime import require_stable_bound_scope, resolve_bound_mode
from .profile import (
    ArtifactDeclaration,
    ArtifactPayloadMode,
    ArtifactRetention,
    PrivacyProfile,
)
from ._private_response import private_response_headers
from .suite_runtime import require_active_process_suite


ARTIFACT_ROOT_ENV = "HELTO_PRIVACY_ARTIFACT_ROOT"
ARTIFACT_REFERENCE_SCHEMA = "helto.private-artifact-reference"
ARTIFACT_REFERENCE_VERSION = 1
ARTIFACT_LEDGER_SCHEMA = "helto.private-artifact-ledger"
ARTIFACT_LEDGER_VERSION = 2
ARTIFACT_FILE_SCHEMA = "helto.private-artifact-file"
ARTIFACT_FILE_VERSION = 1
PUBLIC_ARTIFACT_FILE_SCHEMA = "helto.public-artifact-file"
PUBLIC_ARTIFACT_FILE_VERSION = 1
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
_TRANSITION_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
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
_LEDGER_LOCK_LOCAL = local()
_LEASES: dict[str, _LeaseRecord | _SourceLeaseRecord] = {}
_ACTIVE_RUNS: dict[tuple[str, str], int] = {}
_ACTIVE_WRITES: dict[tuple[str, str], int] = {}
_STREAM_END = object()


class ArtifactError(RuntimeError):
    """Stable product-data-free artifact lifecycle failure."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_CODES else "PRIVACY_ARTIFACT_OPERATION_FAILED"
        self.correlation_id = "hp-artifact-" + secrets.token_urlsafe(12)
        super().__init__("Private artifact operation could not complete.")

    def __repr__(self) -> str:
        return f"ArtifactError(code={self.code!r})"


class ArtifactModeTransitionDisposition(str, Enum):
    """Restart-classifiable state of one planned artifact rewrite."""

    PRIOR = "prior"
    PREPARED = "prepared"
    TARGET = "target"
    FINAL = "final"
    DIVERGED = "diverged"


@dataclass(frozen=True, slots=True)
class ArtifactModeTransitionItem:
    """Product-data-free evidence for one artifact transition action."""

    artifact_id: str = field(repr=False)
    artifact_kind: str
    resource_id: str
    owner_id: str = field(repr=False)
    retention: str
    action: str
    expected_revision: int
    prior_file_digest: str = field(repr=False)
    payload_digest: str | None = field(default=None, repr=False)
    target_file_digest: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            _ARTIFACT_ID.fullmatch(self.artifact_id) is None
            or _OWNER_ID.fullmatch(self.owner_id) is None
            or _STABLE_ID.fullmatch(self.artifact_kind) is None
            or _STABLE_ID.fullmatch(self.resource_id) is None
            or self.retention
            not in {
                "durable-adjunct",
                "regenerable-cache",
                "served-transient",
            }
            or self.action not in {"convert", "retire"}
            or type(self.expected_revision) is not int
            or self.expected_revision < 1
            or _DIGEST.fullmatch(self.prior_file_digest) is None
            or (
                self.action == "convert"
                and (
                    not isinstance(self.payload_digest, str)
                    or _DIGEST.fullmatch(self.payload_digest) is None
                )
            )
            or (self.action == "retire" and self.payload_digest is not None)
            or (
                self.target_file_digest is not None
                and _DIGEST.fullmatch(self.target_file_digest) is None
            )
            or (self.action == "retire" and self.target_file_digest is not None)
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")


@dataclass(frozen=True, slots=True)
class ArtifactModeTransitionPlan:
    """Exact artifact work set prepared for the later global coordinator."""

    pack_id: str
    profile_fingerprint: str = field(repr=False)
    scope_id: str
    transition_id: str
    prior_mode: EffectivePrivacyMode
    target_mode: EffectivePrivacyMode
    items: tuple[ArtifactModeTransitionItem, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            _STABLE_ID.fullmatch(self.pack_id) is None
            or _STABLE_ID.fullmatch(self.scope_id) is None
            or _TRANSITION_ID.fullmatch(self.transition_id) is None
            or _DIGEST.fullmatch(self.profile_fingerprint) is None
            or not isinstance(self.prior_mode, EffectivePrivacyMode)
            or not isinstance(self.target_mode, EffectivePrivacyMode)
            or self.prior_mode is self.target_mode
            or any(not isinstance(item, ArtifactModeTransitionItem) for item in self.items)
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")


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

    def path_for(self, storage_mode: str) -> Path:
        if storage_mode == "public":
            return _public_artifact_path(
                self.pack_id,
                self.resource_id,
                self.declaration.id,
                self.artifact_id,
                retention=(
                    "run-scoped-spill"
                    if self.declaration.payload_mode is ArtifactPayloadMode.STREAM_V1
                    else self.declaration.retention.value
                ),
            )
        return self.path

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
    storage_mode: str
    entry_revision: int
    representation_sha256: str | None = field(default=None, repr=False)
    session_fingerprint: bytes | None = field(default=None, repr=False)
    public_identity: _PublicArtifactIdentity | None = field(default=None, repr=False)
    claimed: bool = False
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class _PublicArtifactIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int

    def matches(self, path: Path) -> bool:
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_dev == self.device
            and metadata.st_ino == self.inode
            and metadata.st_size == self.size
            and metadata.st_mtime_ns == self.modified_ns
        )


@dataclass(slots=True)
class _OpenedPublicArtifact:
    stream: object = field(repr=False)
    identity: _PublicArtifactIdentity
    payload_offset: int
    payload_size: int
    closed: bool = False

    def iter_chunks(self):
        if self.closed:
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
        self.stream.seek(self.payload_offset)
        remaining = self.payload_size
        while remaining:
            chunk = self.stream.read(min(remaining, ARTIFACT_STREAM_CHUNK_BYTES))
            if not chunk:
                raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
            remaining -= len(chunk)
            yield chunk

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.stream.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


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
        "_public_artifact",
        "_record",
        "correlation_id",
        "headers",
        "media_type",
    )

    def __init__(
        self,
        lease_id: str,
        record: _LeaseRecord,
        public_artifact: _OpenedPublicArtifact | None = None,
    ) -> None:
        self._lease_id = lease_id
        self._record = record
        self._public_artifact = public_artifact
        self.media_type = record.locator.declaration.media_type
        self.correlation_id = "hp-artifact-" + secrets.token_urlsafe(12)
        self.headers = private_artifact_response_headers(self.correlation_id)

    def __repr__(self) -> str:
        return "ArtifactLeaseStream()"

    async def iter_chunks(self):
        locator = self._record.locator
        declaration = locator.declaration
        iterator = _iter_lease_payload(self._record, self._public_artifact)
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
            if self._public_artifact is not None:
                self._public_artifact.close()
                self._public_artifact = None
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
        "_cleanup_pending",
        "_closed",
        "_installation",
        "_owner_id",
        "_profile",
        "_resource_id",
        "_run_modes",
        "_run_scopes",
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
        self._cleanup_pending = False
        self._run_modes, self._run_scopes = _resolve_run_modes(
            installation,
            profile,
            resource_id,
        )

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
            _run_mode=self._run_modes.get(artifact_kind),
        )

    async def close(self) -> int:
        if self._closed and not self._cleanup_pending:
            return 0
        self._closed = True
        try:
            retired = await release_owner_artifacts(
                profile=self._profile,
                resource_id=self._resource_id,
                owner_id=self._owner_id,
                retention="run-scoped-spill",
            )
        except BaseException:
            self._cleanup_pending = True
            raise
        else:
            self._cleanup_pending = False
            _unregister_active_run(self._profile.id, self._run_scopes)
            return retired


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
    _run_mode: str | None = None,
) -> ArtifactReference:
    """Encode and atomically persist one artifact in its authoritative mode."""

    require_active_process_suite()
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    if (declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL) is not _run_scoped:
        raise ArtifactError("PRIVACY_ARTIFACT_RETENTION_INVALID")
    safe_owner = _owner_id(owner_id)
    adapter = adapters.get(declaration.payload_adapter)
    stream_mode = declaration.payload_mode is ArtifactPayloadMode.STREAM_V1
    encode = getattr(adapter, "encode_to" if stream_mode else "encode", None)
    if not callable(encode):
        raise ArtifactError("PRIVACY_ARTIFACT_ADAPTER_INVALID")
    if _run_scoped and _run_mode not in {"private", "public"}:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    arguments = (
        installation,
        profile,
        declaration,
        resource_id,
        safe_owner,
        encode,
        value,
        _run_mode if _run_scoped else None,
    )
    if not stream_mode:
        return await _run_blocking(_write_artifact_with_authority, *arguments, None)
    cancel = Event()
    task = asyncio.create_task(
        _run_blocking(_write_artifact_with_authority, *arguments, cancel)
    )
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancel.set()
        try:
            await asyncio.shield(task)
        except BaseException:
            pass
        raise


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
    safe_reference = _reference(reference)
    adapter = adapters.get(declaration.payload_adapter)
    stream_mode = declaration.payload_mode is ArtifactPayloadMode.STREAM_V1
    decode = getattr(adapter, "decode_from" if stream_mode else "decode", None)
    if not callable(decode):
        raise ArtifactError("PRIVACY_ARTIFACT_ADAPTER_INVALID")
    locator = _ArtifactLocator(
        profile.id,
        resource_id,
        declaration,
        safe_reference.id,
    )
    if stream_mode:
        cancel = Event()
        task = asyncio.create_task(
            _run_blocking(
                _decode_stream_artifact_with_authority,
                installation,
                locator,
                decode,
                cancel,
            )
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancel.set()
            try:
                await asyncio.shield(task)
            except BaseException:
                pass
            raise
    plaintext = await _run_blocking(_read_artifact_with_authority, installation, locator)
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


async def release_artifact_owner(
    *,
    profile: PrivacyProfile,
    resource_id: str,
    artifact_kind: str,
    owner_id: str,
) -> int:
    """Retire one owner's artifacts for exactly one declared artifact kind."""

    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    safe_owner = _owner_id(owner_id)
    return await _run_blocking(
        _retire_matching,
        lambda entry: (
            entry.get("packId") == profile.id
            and entry.get("resourceId") == resource_id
            and entry.get("artifactKind") == declaration.id
            and entry.get("ownerId") == safe_owner
        ),
        True,
    )


async def reconcile_owner_artifacts(
    *,
    installation,
    resource_id: str,
    artifact_kind: str,
    owner_id: str,
    keep: tuple[ArtifactReference, ...] = (),
) -> int:
    """Retire non-canonical owner artifacts without exposing their identities."""

    require_active_process_suite()
    profile = installation.profile
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    if declaration.retention is not ArtifactRetention.DURABLE_ADJUNCT:
        raise ArtifactError("PRIVACY_ARTIFACT_RETENTION_INVALID")
    safe_owner = _owner_id(owner_id)
    if not isinstance(keep, tuple) or any(
        not isinstance(reference, ArtifactReference) for reference in keep
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    keep_ids = tuple(reference.id for reference in keep)
    if len(set(keep_ids)) != len(keep_ids):
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    try:
        return await _run_blocking(
            _reconcile_owner_with_authority,
            installation,
            profile.id,
            resource_id,
            declaration,
            safe_owner,
            keep_ids,
        )
    except ArtifactError:
        raise
    except Exception:
        raise ArtifactError("PRIVACY_ARTIFACT_OPERATION_FAILED") from None


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
    authorization: AuthorizedPrivacyRequest | None,
) -> ArtifactLease:
    require_active_process_suite()
    declaration = _artifact_declaration(profile, resource_id, artifact_kind)
    safe_operation = str(operation or "")
    if safe_operation not in declaration.operations:
        raise ArtifactError("PRIVACY_ARTIFACT_OPERATION_INVALID")
    safe_reference = _reference(reference)
    locator = _ArtifactLocator(
        profile.id,
        resource_id,
        declaration,
        safe_reference.id,
    )
    entry = await _run_blocking(
        _require_leaseable_artifact,
        installation,
        locator,
    )
    storage_mode = str(entry["storageMode"])
    if (
        storage_mode == "public"
        and declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    if storage_mode == "private":
        require_current_authorization(
            authorization,
            f"artifact.{safe_operation}",
            pack_id=profile.id,
        )
        session_fingerprint = await _run_blocking(_session_fingerprint)
    else:
        session_fingerprint = None
    lease_id = _new_lease_id()
    expires_at = time.time() + ARTIFACT_LEASE_TTL_SECONDS
    record = _LeaseRecord(
        installation=installation,
        locator=locator,
        operation=safe_operation,
        expires_at=expires_at,
        storage_mode=storage_mode,
        entry_revision=int(entry["revision"]),
        representation_sha256=(
            _entry_representation_sha256(entry)
            if storage_mode == "public"
            and declaration.retention is not ArtifactRetention.RUN_SCOPED_SPILL
            and declaration.payload_mode is ArtifactPayloadMode.BOUNDED_BYTES_V1
            else None
        ),
        session_fingerprint=session_fingerprint,
    )
    await _run_blocking(
        _register_artifact_lease,
        locator,
        lease_id,
        record,
    )
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
    try:
        if not await _run_blocking(_lease_is_current, record):
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    except BaseException:
        revoke_artifact_lease(lease_id)
        raise
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
        public_artifact = await _run_blocking(_open_lease_record_file, record)
        try:
            if isinstance(public_artifact, _OpenedPublicArtifact):
                record.public_identity = public_artifact.identity
                if not await _run_blocking(_lease_is_current, record):
                    raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
            return ArtifactLeaseStream(safe_lease_id, record, public_artifact)
        except BaseException:
            if public_artifact is not None:
                public_artifact.close()
            raise
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
        if record.storage_mode == "public":
            return
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
        for lease_id, record in tuple(_LEASES.items()):
            if isinstance(record, _LeaseRecord) and record.storage_mode == "public":
                continue
            record.revoked = True
            _LEASES.pop(lease_id, None)


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


def plan_artifact_mode_transition(
    installation,
    scope_id: str,
    context,
) -> ArtifactModeTransitionPlan:
    """Capture one exact, non-destructive artifact work set."""

    if (
        context.scope_id != scope_id
        or context.prior_mode is context.target_mode
        or context.transition_id is None
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    # Refuse to stage a new authoritative mode while interrupted plaintext
    # cleanup remains unresolved.
    _sweep_artifacts()
    with _LOCK:
        if _ACTIVE_RUNS.get((installation.profile.id, scope_id), 0) or _ACTIVE_WRITES.get(
            (installation.profile.id, scope_id),
            0,
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    declarations = {
        (item.resource_id, item.id): item
        for item in installation.profile.artifacts
        if item.scope_id == scope_id
    }
    run_identities = {
        (item.resource_id, item.id)
        for item in declarations.values()
        if item.retention is ArtifactRetention.RUN_SCOPED_SPILL
    }
    if run_identities:
        _retire_matching(
            lambda entry: entry.get("packId") == installation.profile.id
            and (entry.get("resourceId"), entry.get("artifactKind")) in run_identities,
            True,
        )
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entries = sorted(
            (
                dict(entry)
                for entry in ledger["entries"]
                if entry.get("packId") == installation.profile.id
                and (entry.get("resourceId"), entry.get("artifactKind"))
                in declarations
            ),
            key=lambda entry: (
                str(entry["resourceId"]),
                str(entry["artifactKind"]),
                str(entry["ownerId"]),
                str(entry["artifactId"]),
            ),
        )
    items: list[ArtifactModeTransitionItem] = []
    for entry in entries:
        declaration = declarations[(entry["resourceId"], entry["artifactKind"])]
        if entry.get("transition") is not None or entry.get("cleanupPending") is True:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if entry.get("storageMode") != context.prior_mode.value:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        locator = _ArtifactLocator(
            installation.profile.id,
            declaration.resource_id,
            declaration,
            str(entry["artifactId"]),
        )
        _require_artifact_file(locator, entry)
        prior_digest = _file_digest(locator.path_for(context.prior_mode.value))
        action = (
            "convert"
            if declaration.retention is ArtifactRetention.DURABLE_ADJUNCT
            else "retire"
        )
        payload_digest = None
        target_file_digest = None
        if action == "convert":
            prior_payload = _load_representation_payload(
                locator,
                entry,
                context.prior_mode.value,
            )
            payload_digest = hashlib.sha256(prior_payload).hexdigest()
            if context.target_mode is EffectivePrivacyMode.PUBLIC:
                target_file_digest = hashlib.sha256(
                    _encode_public_artifact_file(locator, prior_payload)
                ).hexdigest()
        items.append(
            ArtifactModeTransitionItem(
                artifact_id=str(entry["artifactId"]),
                artifact_kind=declaration.id,
                resource_id=declaration.resource_id,
                owner_id=str(entry["ownerId"]),
                retention=declaration.retention.value,
                action=action,
                expected_revision=int(entry["revision"]),
                prior_file_digest=prior_digest,
                payload_digest=payload_digest,
                target_file_digest=target_file_digest,
            )
        )
    return ArtifactModeTransitionPlan(
        installation.profile.id,
        installation.profile.fingerprint,
        scope_id,
        context.transition_id,
        context.prior_mode,
        context.target_mode,
        tuple(items),
    )


def prepare_artifact_mode_transition(
    installation,
    plan_or_scope,
    context=None,
) -> None:
    """Prepare a new plan, retaining the old coordinator seam temporarily."""

    if isinstance(plan_or_scope, ArtifactModeTransitionPlan):
        _validate_artifact_plan(installation, plan_or_scope)
        for item in plan_or_scope.items:
            _prepare_artifact_transition_item(installation, plan_or_scope, item)
        return
    _legacy_prepare_artifact_mode_transition(installation, plan_or_scope, context)


def classify_artifact_mode_transition(
    installation,
    plan: ArtifactModeTransitionPlan,
) -> tuple[ArtifactModeTransitionDisposition, ...]:
    _validate_artifact_plan(installation, plan)
    return tuple(
        _classify_artifact_transition_item(installation, plan, item)
        for item in plan.items
    )


def verify_artifact_mode_transition(
    installation,
    plan: ArtifactModeTransitionPlan,
    expected: ArtifactModeTransitionDisposition | tuple[ArtifactModeTransitionDisposition, ...],
) -> bool:
    dispositions = classify_artifact_mode_transition(installation, plan)
    expected_values = (
        tuple(expected for _item in plan.items)
        if isinstance(expected, ArtifactModeTransitionDisposition)
        else tuple(expected)
    )
    if len(expected_values) != len(plan.items) or any(
        not isinstance(value, ArtifactModeTransitionDisposition)
        for value in expected_values
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    return dispositions == expected_values


def commit_artifact_mode_transition(
    installation,
    plan: ArtifactModeTransitionPlan,
) -> None:
    _validate_artifact_plan(installation, plan)
    for item in plan.items:
        _commit_artifact_transition_item(installation, plan, item)


def rollback_artifact_mode_transition(
    installation,
    plan: ArtifactModeTransitionPlan,
) -> None:
    _validate_artifact_plan(installation, plan)
    for item in reversed(plan.items):
        _rollback_artifact_transition_item(installation, plan, item)


def retire_artifact_mode_transition(
    installation,
    plan: ArtifactModeTransitionPlan,
) -> None:
    _validate_artifact_plan(installation, plan)
    for item in plan.items:
        _retire_artifact_transition_item(installation, plan, item)


def _legacy_prepare_artifact_mode_transition(
    installation,
    scope_id: str,
    context,
) -> None:
    """Compatibility seam until the global coordinator adopts artifact plans."""

    with _LOCK:
        if _ACTIVE_RUNS.get((installation.profile.id, scope_id), 0) or _ACTIVE_WRITES.get(
            (installation.profile.id, scope_id),
            0,
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    _sweep_public_run_spills_for_scope(installation.profile, scope_id)
    with _LOCK:
        if _ACTIVE_RUNS.get((installation.profile.id, scope_id), 0) or _ACTIVE_WRITES.get(
            (installation.profile.id, scope_id),
            0,
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
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


def _validate_artifact_plan(installation, plan: ArtifactModeTransitionPlan) -> None:
    if (
        not isinstance(plan, ArtifactModeTransitionPlan)
        or plan.pack_id != installation.profile.id
        or not hmac.compare_digest(
            plan.profile_fingerprint,
            installation.profile.fingerprint,
        )
        or plan.scope_id
        not in {scope.id for scope in installation.profile.scopes}
        or any(
            (
                item.action == "convert"
                and plan.target_mode is EffectivePrivacyMode.PUBLIC
            )
            is not (item.target_file_digest is not None)
            for item in plan.items
        )
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")


def _transition_declaration(
    installation,
    item: ArtifactModeTransitionItem,
) -> ArtifactDeclaration:
    declaration = next(
        (
            candidate
            for candidate in installation.profile.artifacts
            if candidate.resource_id == item.resource_id
            and candidate.id == item.artifact_kind
        ),
        None,
    )
    if declaration is None or declaration.retention.value != item.retention:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    return declaration


def _transition_entry(
    ledger: Mapping[str, object],
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> dict | None:
    matches = [
        entry
        for entry in ledger["entries"]
        if entry.get("artifactId") == item.artifact_id
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    entry = matches[0]
    if (
        entry.get("packId") != plan.pack_id
        or entry.get("resourceId") != item.resource_id
        or entry.get("artifactKind") != item.artifact_kind
        or entry.get("ownerId") != item.owner_id
        or entry.get("retention") != item.retention
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    return entry


def _transition_payload(
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
    phase: str,
) -> dict[str, object]:
    return {
        "action": item.action,
        "phase": phase,
        "priorMode": plan.prior_mode.value,
        "targetMode": plan.target_mode.value,
        "transitionId": plan.transition_id,
    }


def _same_item_transition(
    entry: Mapping[str, object],
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> bool:
    transition = entry.get("transition")
    return (
        isinstance(transition, Mapping)
        and transition.get("transitionId") == plan.transition_id
        and transition.get("action") == item.action
        and transition.get("priorMode") == plan.prior_mode.value
        and transition.get("targetMode") == plan.target_mode.value
    )


def _prepare_artifact_transition_item(
    installation,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> None:
    declaration = _transition_declaration(installation, item)
    locator = _ArtifactLocator(plan.pack_id, item.resource_id, declaration, item.artifact_id)
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition = entry.get("transition")
        if transition is None:
            if (
                entry.get("revision") != item.expected_revision
                or entry.get("storageMode") != plan.prior_mode.value
                or entry.get("cleanupPending") is True
            ):
                raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
            entry["transition"] = _transition_payload(plan, item, "preparing")
            _touch_entry(entry)
            _revoke_entry_leases_locked(entry)
            _write_ledger(ledger)
        elif not _same_item_transition(entry, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        elif transition.get("phase") in {"prepared", "committed", "retiring"}:
            return
        elif transition.get("phase") not in {"preparing", "rolling-back"}:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")

    if not _prior_representation_matches(locator, plan, item):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    if item.action == "convert":
        _ensure_target_representation(locator, plan, item)
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None or not _same_item_transition(entry, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition = dict(entry["transition"])
        if transition.get("phase") == "prepared":
            return
        if transition.get("phase") != "preparing":
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition["phase"] = "prepared"
        entry["transition"] = transition
        _touch_entry(entry)
        _write_ledger(ledger)


def _commit_artifact_transition_item(
    installation,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> None:
    declaration = _transition_declaration(installation, item)
    locator = _ArtifactLocator(plan.pack_id, item.resource_id, declaration, item.artifact_id)
    if item.action == "convert" and not _target_representation_matches(locator, plan, item):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None or not _same_item_transition(entry, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition = dict(entry["transition"])
        if transition.get("phase") in {"committed", "retiring"}:
            return
        if transition.get("phase") != "prepared":
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if item.action == "convert":
            entry["storageMode"] = plan.target_mode.value
            _set_entry_representation_authority(
                entry,
                locator,
                plan.target_mode.value,
                expected_sha256=item.target_file_digest,
            )
        transition["phase"] = "committed"
        entry["transition"] = transition
        _touch_entry(entry)
        _write_ledger(ledger)


def _rollback_artifact_transition_item(
    installation,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> None:
    declaration = _transition_declaration(installation, item)
    locator = _ArtifactLocator(plan.pack_id, item.resource_id, declaration, item.artifact_id)
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if entry.get("transition") is None:
            if (
                entry.get("storageMode") == plan.prior_mode.value
                and _prior_representation_matches(locator, plan, item)
            ):
                return
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if not _same_item_transition(entry, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition = dict(entry["transition"])
        if transition.get("phase") == "retiring":
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        entry["storageMode"] = plan.prior_mode.value
        _set_entry_representation_authority(
            entry,
            locator,
            plan.prior_mode.value,
            expected_sha256=item.prior_file_digest,
        )
        transition["phase"] = "rolling-back"
        entry["transition"] = transition
        _touch_entry(entry)
        _write_ledger(ledger)
    if not _prior_representation_matches(locator, plan, item):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    if item.action == "convert":
        _unlink_representation(locator.path_for(plan.target_mode.value))
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None or not _same_item_transition(entry, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        entry["transition"] = None
        _touch_entry(entry)
        _write_ledger(ledger)


def _retire_artifact_transition_item(
    installation,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> None:
    declaration = _transition_declaration(installation, item)
    locator = _ArtifactLocator(plan.pack_id, item.resource_id, declaration, item.artifact_id)
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None:
            if item.action == "retire":
                return
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if entry.get("transition") is None:
            if (
                item.action == "convert"
                and entry.get("storageMode") == plan.target_mode.value
                and not locator.path_for(plan.prior_mode.value).exists()
                and _target_representation_matches(locator, plan, item)
            ):
                return
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        if not _same_item_transition(entry, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition = dict(entry["transition"])
        if transition.get("phase") not in {"committed", "retiring"}:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        transition["phase"] = "retiring"
        entry["transition"] = transition
        _touch_entry(entry)
        _revoke_entry_leases_locked(entry)
        _write_ledger(ledger)

    if item.action == "convert":
        if not _target_representation_matches(locator, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        _unlink_representation(locator.path_for(plan.prior_mode.value))
        with _exclusive_artifact_ledger():
            ledger = _load_ledger()
            entry = _transition_entry(ledger, plan, item)
            if entry is None or not _same_item_transition(entry, plan, item):
                raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
            entry["transition"] = None
            _touch_entry(entry)
            _write_ledger(ledger)
        return

    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        if entry is None:
            return
        for path in _entry_retirement_paths(entry):
            _unlink_representation(path)
        ledger["entries"].remove(entry)
        _write_ledger(ledger)


def _classify_artifact_transition_item(
    installation,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> ArtifactModeTransitionDisposition:
    declaration = _transition_declaration(installation, item)
    locator = _ArtifactLocator(plan.pack_id, item.resource_id, declaration, item.artifact_id)
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = _transition_entry(ledger, plan, item)
        entry = None if entry is None else dict(entry)
    if entry is None:
        return (
            ArtifactModeTransitionDisposition.FINAL
            if item.action == "retire"
            else ArtifactModeTransitionDisposition.DIVERGED
        )
    transition = entry.get("transition")
    if transition is None:
        if (
            entry.get("storageMode") == plan.prior_mode.value
            and _prior_representation_matches(locator, plan, item)
            and (
                item.action == "retire"
                or not locator.path_for(plan.target_mode.value).exists()
            )
        ):
            return ArtifactModeTransitionDisposition.PRIOR
        if (
            item.action == "convert"
            and entry.get("storageMode") == plan.target_mode.value
            and _target_representation_matches(locator, plan, item)
            and not locator.path_for(plan.prior_mode.value).exists()
        ):
            return ArtifactModeTransitionDisposition.FINAL
        return ArtifactModeTransitionDisposition.DIVERGED
    if not _same_item_transition(entry, plan, item):
        return ArtifactModeTransitionDisposition.DIVERGED
    phase = transition.get("phase")
    if (
        item.action == "convert"
        and phase == "retiring"
        and not locator.path_for(plan.prior_mode.value).exists()
        and _target_representation_matches(locator, plan, item)
    ):
        return ArtifactModeTransitionDisposition.FINAL
    if not _prior_representation_matches(locator, plan, item):
        return ArtifactModeTransitionDisposition.DIVERGED
    if item.action == "retire":
        if phase in {"preparing", "prepared", "rolling-back"}:
            return ArtifactModeTransitionDisposition.PREPARED
        if phase in {"committed", "retiring"}:
            return ArtifactModeTransitionDisposition.TARGET
        return ArtifactModeTransitionDisposition.DIVERGED
    target_exists = locator.path_for(plan.target_mode.value).exists()
    target_matches = target_exists and _target_representation_matches(locator, plan, item)
    if phase == "preparing":
        return (
            ArtifactModeTransitionDisposition.PREPARED
            if target_matches
            else ArtifactModeTransitionDisposition.PRIOR
        )
    if phase in {"prepared", "rolling-back"}:
        return (
            ArtifactModeTransitionDisposition.PREPARED
            if target_matches
            else ArtifactModeTransitionDisposition.PRIOR
        )
    if phase in {"committed", "retiring"} and target_matches:
        return ArtifactModeTransitionDisposition.TARGET
    return ArtifactModeTransitionDisposition.DIVERGED


def _prior_representation_matches(
    locator: _ArtifactLocator,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> bool:
    try:
        return hmac.compare_digest(
            _file_digest(locator.path_for(plan.prior_mode.value)),
            item.prior_file_digest,
        )
    except ArtifactError:
        return False


def _target_representation_matches(
    locator: _ArtifactLocator,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> bool:
    if item.payload_digest is None:
        return False
    try:
        entry = {
            "storageMode": plan.target_mode.value,
            "retention": item.retention,
            "cleanupPending": False,
        }
        if plan.target_mode is EffectivePrivacyMode.PUBLIC:
            entry["representationSha256"] = item.target_file_digest
        payload = _load_representation_payload(
            locator,
            entry,
            plan.target_mode.value,
        )
        return hmac.compare_digest(hashlib.sha256(payload).hexdigest(), item.payload_digest)
    except ArtifactError:
        return False


def _ensure_target_representation(
    locator: _ArtifactLocator,
    plan: ArtifactModeTransitionPlan,
    item: ArtifactModeTransitionItem,
) -> None:
    path = locator.path_for(plan.target_mode.value)
    if path.exists():
        if not _target_representation_matches(locator, plan, item):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        return
    source_entry = {
        "storageMode": plan.prior_mode.value,
        "retention": item.retention,
        "cleanupPending": False,
    }
    if plan.prior_mode is EffectivePrivacyMode.PUBLIC:
        source_entry["representationSha256"] = item.prior_file_digest
    payload = _load_representation_payload(locator, source_entry, plan.prior_mode.value)
    if item.payload_digest is None or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(),
        item.payload_digest,
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    if plan.target_mode is EffectivePrivacyMode.PRIVATE:
        codec = PrivacyEnvelopeCodec(locator.schema)
        protected = codec.encrypt_bytes(
            payload,
            locator.purpose,
            chunk_size=ARTIFACT_STREAM_CHUNK_BYTES,
        )
        encoded = _encode_artifact_file(protected)
    else:
        encoded = _encode_public_artifact_file(locator, payload)
    _ensure_private_tree(path.parent)
    atomic_write_private_bytes(path, encoded)
    if not _target_representation_matches(locator, plan, item):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")


def _load_representation_payload(
    locator: _ArtifactLocator,
    entry: Mapping[str, object],
    mode: str,
) -> bytes:
    if mode == "private":
        return _load_artifact_bytes(locator)
    return _load_public_artifact_bytes(locator, dict(entry))


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            while True:
                chunk = stream.read(ARTIFACT_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _set_entry_representation_authority(
    entry: dict[str, object],
    locator: _ArtifactLocator,
    storage_mode: str,
    *,
    expected_sha256: str | None = None,
) -> None:
    if (
        storage_mode == "public"
        and locator.declaration.retention is not ArtifactRetention.RUN_SCOPED_SPILL
    ):
        digest = _file_digest(locator.path_for("public"))
        if expected_sha256 is not None and not hmac.compare_digest(
            digest,
            expected_sha256,
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        entry["representationSha256"] = digest
        return
    entry.pop("representationSha256", None)


def _unlink_representation(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
        sync_parent_directory(path)
    except OSError:
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
        _ACTIVE_RUNS.clear()
        _ACTIVE_WRITES.clear()


def _write_artifact_with_authority(
    installation,
    profile: PrivacyProfile,
    declaration: ArtifactDeclaration,
    resource_id: str,
    owner_id: str,
    encode,
    value: object,
    captured_run_mode: str | None,
    cancel: Event | None,
) -> ArtifactReference:
    from .mode_runtime import bound_mode_work_admission

    def persist(storage_mode: str) -> ArtifactReference:
        if storage_mode == "private":
            try:
                keystore.require_unlocked_session()
            except keystore.PrivacyKeystoreError:
                raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED") from None
        reference = ArtifactReference(_new_artifact_id())
        locator = _ArtifactLocator(
            profile.id,
            resource_id,
            declaration,
            reference.id,
        )
        if declaration.payload_mode is ArtifactPayloadMode.STREAM_V1:
            _persist_stream_artifact(
                locator,
                owner_id,
                storage_mode,
                encode,
                value,
                cancel,
            )
            return reference
        try:
            encoded = encode(value)
        except Exception:
            raise ArtifactError("PRIVACY_ARTIFACT_ENCODE_FAILED") from None
        if not isinstance(encoded, (bytes, bytearray)):
            raise ArtifactError("PRIVACY_ARTIFACT_ENCODE_FAILED")
        try:
            _persist_artifact(locator, owner_id, bytes(encoded), storage_mode)
        finally:
            if isinstance(encoded, bytearray):
                encoded.clear()
        return reference

    if captured_run_mode is not None:
        return persist(captured_run_mode)
    try:
        with bound_mode_work_admission(installation, (declaration.scope_id,)):
            storage_mode = _current_artifact_storage_mode(installation, declaration)
            _register_active_write(profile.id, declaration.scope_id)
        try:
            return persist(storage_mode)
        finally:
            _unregister_active_write(profile.id, declaration.scope_id)
    except ArtifactError:
        raise
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None


def _read_artifact_with_authority(
    installation,
    locator: _ArtifactLocator,
) -> bytes:
    from .mode_runtime import bound_mode_work_admission

    declaration = locator.declaration
    try:
        with bound_mode_work_admission(installation, (declaration.scope_id,)):
            entry = _require_artifact_entry(locator)
            current_mode = _current_artifact_storage_mode(installation, declaration)
            if entry.get("storageMode") != current_mode:
                raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
            if current_mode == "private":
                return _load_artifact_bytes(locator)
            return _load_public_artifact_bytes(locator, entry)
    except ArtifactError:
        raise
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None


def _decode_stream_artifact_with_authority(
    installation,
    locator: _ArtifactLocator,
    decode_from,
    cancel: Event,
) -> object:
    from .mode_runtime import bound_mode_work_admission

    declaration = locator.declaration
    try:
        with bound_mode_work_admission(installation, (declaration.scope_id,)):
            entry = _require_artifact_entry(locator)
            current_mode = _current_artifact_storage_mode(installation, declaration)
            if entry.get("storageMode") != current_mode:
                raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
            source = _open_stream_artifact_source(locator, entry, cancel)
            try:
                return decode_from(source)
            except ArtifactStreamCancelled:
                raise
            except BaseException as error:
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                raise ArtifactError("PRIVACY_ARTIFACT_DECODE_FAILED") from None
            finally:
                source.close()
    except ArtifactStreamCancelled:
        raise
    except ArtifactError:
        raise
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None
    except ArtifactStreamError:
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None


def _current_artifact_storage_mode(
    installation,
    declaration: ArtifactDeclaration,
) -> str:
    scope = next(
        (item for item in installation.profile.scopes if item.id == declaration.scope_id),
        None,
    )
    if scope is None:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    require_stable_bound_scope(installation, scope.id)
    resolution = resolve_bound_mode(
        installation,
        scope.mode_resource_id,
        scope.id,
        None,
    )
    require_stable_bound_scope(installation, scope.id)
    return resolution.effective.value


def _persist_artifact(
    locator: _ArtifactLocator,
    owner_id: str,
    plaintext: bytes,
    storage_mode: str = "private",
) -> None:
    path = locator.path_for(storage_mode)
    declaration = locator.declaration
    try:
        if storage_mode == "private":
            codec = PrivacyEnvelopeCodec(locator.schema)
            protected = codec.encrypt_bytes(
                plaintext,
                locator.purpose,
                chunk_size=ARTIFACT_STREAM_CHUNK_BYTES,
            )
            payload = _encode_artifact_file(protected)
        elif storage_mode == "public":
            payload = (
                plaintext
                if declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL
                else _encode_public_artifact_file(locator, plaintext)
            )
        else:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        with _exclusive_artifact_ledger():
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
                "payloadMode": ArtifactPayloadMode.BOUNDED_BYTES_V1.value,
                "processEpoch": _PROCESS_EPOCH,
                "resourceId": locator.resource_id,
                "retention": declaration.retention.value,
                "revision": 1,
                "state": "READY",
                "storageMode": storage_mode,
                "transition": None,
            }
            if (
                storage_mode == "public"
                and declaration.retention is not ArtifactRetention.RUN_SCOPED_SPILL
            ):
                entry["representationSha256"] = hashlib.sha256(payload).hexdigest()
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


def _artifact_stream_contract_digest(locator: _ArtifactLocator) -> str:
    declaration = locator.declaration
    contract = declaration.stream_contract
    if contract is None:
        raise ArtifactError("PRIVACY_ARTIFACT_ADAPTER_INVALID")
    payload = {
        "artifactKind": declaration.id,
        "codecSchema": contract.codec_schema,
        "codecVersion": contract.codec_version,
        "formatVersion": declaration.format_version,
        "packId": locator.pack_id,
        "payloadMode": declaration.payload_mode.value,
        "purpose": declaration.purpose,
        "resourceId": locator.resource_id,
        "retention": declaration.retention.value,
        "scopeId": declaration.scope_id,
    }
    return hashlib.sha256(_compact_json(payload).encode("utf-8")).hexdigest()


def _stream_staging_path(path: Path) -> Path:
    return path.with_name(path.name + ".part")


def _stream_ledger_entry(
    locator: _ArtifactLocator,
    owner_id: str,
    storage_mode: str,
    contract_digest: str,
    created_at: float,
) -> dict[str, object]:
    declaration = locator.declaration
    entry: dict[str, object] = {
        "artifactId": locator.artifact_id,
        "artifactKind": declaration.id,
        "cleanupPending": False,
        "createdAt": created_at,
        "fileVersion": 2 if storage_mode == "private" else 1,
        "formatVersion": declaration.format_version,
        "ownerId": owner_id,
        "packId": locator.pack_id,
        "payloadContractDigest": contract_digest,
        "payloadMode": ArtifactPayloadMode.STREAM_V1.value,
        "processEpoch": _PROCESS_EPOCH,
        "resourceId": locator.resource_id,
        "retention": declaration.retention.value,
        "revision": 1,
        "state": "WRITING",
        "storageMode": storage_mode,
        "transition": None,
    }
    if declaration.retention is ArtifactRetention.REGENERABLE_CACHE:
        entry["expiresAt"] = created_at + REGENERABLE_CACHE_TTL_SECONDS
    elif declaration.retention is ArtifactRetention.SERVED_TRANSIENT:
        entry["expiresAt"] = created_at + SERVED_TRANSIENT_TTL_SECONDS
    return entry


def _persist_stream_artifact(
    locator: _ArtifactLocator,
    owner_id: str,
    storage_mode: str,
    encode_to,
    value: object,
    cancel: Event | None,
) -> None:
    declaration = locator.declaration
    contract = declaration.stream_contract
    if contract is None or storage_mode not in {"private", "public"}:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    path = locator.path_for(storage_mode)
    staging = _stream_staging_path(path)
    contract_digest = _artifact_stream_contract_digest(locator)
    chunk_bytes = min(ARTIFACT_STREAM_CHUNK_BYTES, contract.max_plaintext_bytes)
    writer = None
    ledger_registered = False
    try:
        with _exclusive_artifact_ledger():
            ledger = _load_ledger()
            if any(entry.get("artifactId") == locator.artifact_id for entry in ledger["entries"]):
                raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED")
            _ensure_private_tree(path.parent)
            if path.exists() or staging.exists():
                raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED")
            ledger["entries"].append(
                _stream_ledger_entry(
                    locator,
                    owner_id,
                    storage_mode,
                    contract_digest,
                    time.time(),
                )
            )
            _write_ledger(ledger)
            ledger_registered = True

        key: bytes | None = None
        key_id: str | None = None
        if storage_mode == "private":
            try:
                key, key_id = keystore.primary_session_key()
            except keystore.PrivacyKeystoreError:
                raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED") from None
        with staging.open("xb") as handle:
            os.chmod(staging, 0o600)
            if storage_mode == "private":
                assert key is not None and key_id is not None
                writer = PrivateArtifactStreamWriter(
                    handle,
                    master_key=key,
                    key_id=key_id,
                    artifact_id=locator.artifact_id,
                    owner_id=owner_id,
                    contract_digest=contract_digest,
                    codec_schema=contract.codec_schema,
                    codec_version=contract.codec_version,
                    chunk_bytes=chunk_bytes,
                    max_plaintext_bytes=contract.max_plaintext_bytes,
                    cancel=cancel,
                )
            else:
                writer = PublicArtifactStreamWriter(
                    handle,
                    chunk_bytes=chunk_bytes,
                    max_plaintext_bytes=contract.max_plaintext_bytes,
                    cancel=cancel,
                )
            try:
                result = encode_to(value, writer.sink)
            except ArtifactStreamCancelled:
                raise
            except BaseException as error:
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                raise ArtifactError("PRIVACY_ARTIFACT_ENCODE_FAILED") from None
            if result is not None:
                raise ArtifactError("PRIVACY_ARTIFACT_ENCODE_FAILED")
            outcome = writer.finish()
            if storage_mode == "private":
                plaintext_size = int(outcome)
                payload_sha256 = None
            else:
                plaintext_size, payload_sha256 = outcome
            _flush_stream_handle(handle)
            _fsync_stream_handle(handle)

        if cancel is not None and cancel.is_set():
            raise ArtifactStreamCancelled()
        if storage_mode == "private":
            source = _open_private_stream_source(
                locator,
                owner_id,
                contract_digest,
                staging,
                cancel,
                expected_plaintext_bytes=plaintext_size,
            )
        else:
            assert isinstance(payload_sha256, str)
            source = open_public_artifact_source(
                staging,
                expected_size=plaintext_size,
                expected_sha256=payload_sha256,
                chunk_bytes=chunk_bytes,
                cancel=cancel,
            )
        source.close()
        _replace_stream_file(staging, path)
        sync_parent_directory(path)
        _commit_stream_artifact(
            locator,
            owner_id,
            contract_digest,
            plaintext_size,
            payload_sha256,
            cancel,
        )
    except BaseException as error:
        if writer is not None:
            try:
                writer.abort()
            except BaseException:
                pass
        if ledger_registered:
            _abort_stream_artifact(locator)
        _unlink_quietly(staging)
        _unlink_quietly(path)
        if isinstance(
            error,
            (ArtifactError, ArtifactStreamCancelled, KeyboardInterrupt, SystemExit),
        ):
            raise
        raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED") from None


def _flush_stream_handle(handle) -> None:
    handle.flush()


def _fsync_stream_handle(handle) -> None:
    os.fsync(handle.fileno())


def _replace_stream_file(staging: Path, path: Path) -> None:
    os.replace(staging, path)


def _commit_stream_artifact(
    locator: _ArtifactLocator,
    owner_id: str,
    contract_digest: str,
    plaintext_size: int,
    payload_sha256: str | None,
    cancel: Event | None,
) -> None:
    contract = locator.declaration.stream_contract
    if contract is None:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entry = next(
            (candidate for candidate in ledger["entries"] if locator.matches(candidate)),
            None,
        )
        if (
            entry is None
            or entry.get("state") != "WRITING"
            or entry.get("ownerId") != owner_id
            or entry.get("payloadContractDigest") != contract_digest
            or (cancel is not None and cancel.is_set())
        ):
            raise ArtifactStreamCancelled() if cancel is not None and cancel.is_set() else ArtifactError(
                "PRIVACY_ARTIFACT_STORAGE_FAILED"
            )
        if contract.max_owner_plaintext_bytes is not None:
            owned = 0
            owned_entries = [
                candidate
                for candidate in ledger["entries"]
                if candidate is not entry
                and candidate.get("packId") == locator.pack_id
                and candidate.get("resourceId") == locator.resource_id
                and candidate.get("artifactKind") == locator.declaration.id
                and candidate.get("ownerId") == owner_id
                and candidate.get("state", "READY") == "READY"
            ]
            for candidate in owned_entries:
                candidate_locator = _ArtifactLocator(
                    locator.pack_id,
                    locator.resource_id,
                    locator.declaration,
                    str(candidate["artifactId"]),
                )
                source = _open_stream_artifact_source(candidate_locator, candidate)
                source.close()
                owned += int(candidate["plaintextBytes"])
            if owned > contract.max_owner_plaintext_bytes - plaintext_size:
                raise ArtifactError("PRIVACY_ARTIFACT_STORAGE_FAILED")
        entry["plaintextBytes"] = plaintext_size
        if payload_sha256 is not None:
            entry["payloadSha256"] = payload_sha256
        entry["state"] = "READY"
        _touch_entry(entry)
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
                pass


def _abort_stream_artifact(locator: _ArtifactLocator) -> None:
    try:
        with _exclusive_artifact_ledger():
            ledger = _load_ledger()
            entry = next(
                (candidate for candidate in ledger["entries"] if locator.matches(candidate)),
                None,
            )
            if entry is None:
                return
            entry["state"] = "CLEANUP_PENDING"
            entry["cleanupPending"] = True
            _touch_entry(entry)
            _write_ledger(ledger)
            _retire_from_ledger(ledger, locator.matches)
            _write_ledger(ledger)
    except BaseException:
        # The durable CLEANUP_PENDING marker, when it could be written, leaves
        # restart cleanup fail-closed. Never mask the originating exception.
        return


def _load_artifact_bytes(
    locator: _ArtifactLocator,
) -> bytes:
    return b"".join(_iter_artifact_plaintext(locator))


def _load_public_artifact_bytes(locator: _ArtifactLocator, entry: dict) -> bytes:
    if (
        _entry_is_stale(entry)
        or entry.get("storageMode") != "public"
        or entry.get("cleanupPending") is True
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    path = locator.path_for("public")
    try:
        if locator.declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL:
            return _read_regular_file(path)
        return b"".join(
            _iter_public_artifact_payload(
                locator,
                _entry_representation_sha256(entry),
            )
        )
    except FileNotFoundError:
        raise ArtifactError("PRIVACY_ARTIFACT_NOT_FOUND") from None
    except OSError:
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None


def _open_private_stream_source(
    locator: _ArtifactLocator,
    owner_id: str,
    contract_digest: str,
    path: Path,
    cancel: Event | None,
    *,
    expected_plaintext_bytes: int,
):
    contract = locator.declaration.stream_contract
    if contract is None:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    try:
        return open_private_artifact_source(
            path,
            key_for_id=keystore.session_key_for,
            owner_id=owner_id,
            artifact_id=locator.artifact_id,
            contract_digest=contract_digest,
            codec_schema=contract.codec_schema,
            codec_version=contract.codec_version,
            chunk_bytes=min(ARTIFACT_STREAM_CHUNK_BYTES, contract.max_plaintext_bytes),
            max_plaintext_bytes=contract.max_plaintext_bytes,
            expected_plaintext_bytes=expected_plaintext_bytes,
            cancel=cancel,
        )
    except ArtifactStreamError:
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
    except keystore.PrivacyKeystoreError:
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None


def _open_stream_artifact_source(
    locator: _ArtifactLocator,
    entry: Mapping[str, object],
    cancel: Event | None = None,
):
    contract = locator.declaration.stream_contract
    expected_contract = _artifact_stream_contract_digest(locator)
    if (
        contract is None
        or entry.get("payloadMode") != ArtifactPayloadMode.STREAM_V1.value
        or entry.get("state") != "READY"
        or entry.get("payloadContractDigest") != expected_contract
        or type(entry.get("plaintextBytes")) is not int
        or int(entry["plaintextBytes"]) > contract.max_plaintext_bytes
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
    if entry.get("storageMode") == "private":
        return _open_private_stream_source(
            locator,
            str(entry.get("ownerId") or ""),
            expected_contract,
            locator.path_for("private"),
            cancel,
            expected_plaintext_bytes=int(entry["plaintextBytes"]),
        )
    if entry.get("storageMode") == "public":
        payload_sha256 = entry.get("payloadSha256")
        if not isinstance(payload_sha256, str):
            raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
        try:
            return open_public_artifact_source(
                locator.path_for("public"),
                expected_size=int(entry["plaintextBytes"]),
                expected_sha256=payload_sha256,
                chunk_bytes=min(
                    ARTIFACT_STREAM_CHUNK_BYTES,
                    contract.max_plaintext_bytes,
                ),
                cancel=cancel,
            )
        except ArtifactStreamError:
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
    raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")


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


def _encode_public_artifact_file(
    locator: _ArtifactLocator,
    payload: bytes,
) -> bytes:
    header = {
        "artifactSchema": locator.schema,
        "encoding": "identity",
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "payloadSize": len(payload),
        "purpose": locator.purpose,
        "schema": PUBLIC_ARTIFACT_FILE_SCHEMA,
        "version": PUBLIC_ARTIFACT_FILE_VERSION,
    }
    return _compact_json(header).encode("utf-8") + b"\n" + payload


def _iter_public_artifact_payload(
    locator: _ArtifactLocator,
    expected_representation_sha256: str,
):
    opened = _open_validated_public_artifact(
        locator,
        expected_representation_sha256,
    )
    try:
        yield from opened.iter_chunks()
    finally:
        opened.close()


def _open_validated_public_artifact(
    locator: _ArtifactLocator,
    expected_representation_sha256: str,
) -> _OpenedPublicArtifact:
    path = locator.path_for("public")
    descriptor: int | None = None
    stream = None
    try:
        if (
            not isinstance(expected_representation_sha256, str)
            or _DIGEST.fullmatch(expected_representation_sha256) is None
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        header_line = stream.readline(ARTIFACT_MAX_LINE_BYTES + 1)
        if (
            not header_line
            or len(header_line) > ARTIFACT_MAX_LINE_BYTES
            or not header_line.endswith(b"\n")
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
        try:
            header = json.loads(header_line[:-1].decode("utf-8"))
        except (UnicodeError, ValueError):
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
        if (
            not isinstance(header, dict)
            or set(header)
            != {
                "artifactSchema",
                "encoding",
                "payloadSha256",
                "payloadSize",
                "purpose",
                "schema",
                "version",
            }
            or header.get("artifactSchema") != locator.schema
            or header.get("encoding") != "identity"
            or header.get("purpose") != locator.purpose
            or header.get("schema") != PUBLIC_ARTIFACT_FILE_SCHEMA
            or header.get("version") != PUBLIC_ARTIFACT_FILE_VERSION
            or type(header.get("payloadSize")) is not int
            or int(header["payloadSize"]) < 0
            or not isinstance(header.get("payloadSha256"), str)
            or _DIGEST.fullmatch(header["payloadSha256"]) is None
            or header_line != _compact_json(header).encode("utf-8") + b"\n"
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
        remaining = int(header["payloadSize"])
        payload_digest = hashlib.sha256()
        representation_digest = hashlib.sha256(header_line)
        while remaining:
            chunk = stream.read(min(remaining, ARTIFACT_STREAM_CHUNK_BYTES))
            if not chunk:
                raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
            remaining -= len(chunk)
            payload_digest.update(chunk)
            representation_digest.update(chunk)
        if (
            stream.read(1)
            or not hmac.compare_digest(
                payload_digest.hexdigest(),
                header["payloadSha256"],
            )
            or not hmac.compare_digest(
                representation_digest.hexdigest(),
                expected_representation_sha256,
            )
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE")
        final_metadata = os.fstat(stream.fileno())
        identity = _PublicArtifactIdentity(
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
        )
        opened = _OpenedPublicArtifact(
            stream,
            identity,
            len(header_line),
            int(header["payloadSize"]),
        )
        stream = None
        return opened
    except FileNotFoundError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_NOT_FOUND") from None
    except ArtifactError:
        _discard_unreadable_cache(locator)
        raise
    except OSError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
    finally:
        if stream is not None:
            stream.close()
        if descriptor is not None:
            os.close(descriptor)


def _read_regular_file(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            return stream.read()
    except OSError:
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


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


def _resolve_run_modes(installation, profile: PrivacyProfile, resource_id: str):
    declarations = tuple(
        item
        for item in profile.artifacts
        if item.resource_id == resource_id
        and item.retention is ArtifactRetention.RUN_SCOPED_SPILL
    )
    if not declarations:
        raise ArtifactError("PRIVACY_ARTIFACT_RETENTION_INVALID")
    scopes_by_id = {scope.id: scope for scope in profile.scopes}
    scope_ids = frozenset(item.scope_id for item in declarations)
    if any(scope_id not in scopes_by_id for scope_id in scope_ids):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    from .mode_runtime import bound_mode_work_admission

    modes: dict[str, str] = {}
    try:
        with bound_mode_work_admission(installation, sorted(scope_ids)):
            for declaration in declarations:
                scope = scopes_by_id[declaration.scope_id]
                resolution = resolve_bound_mode(
                    installation,
                    scope.mode_resource_id,
                    scope.id,
                    None,
                )
                require_stable_bound_scope(installation, scope.id)
                modes[declaration.id] = (
                    "public"
                    if resolution.declared is DeclaredPrivacyMode.PUBLIC
                    and resolution.effective is EffectivePrivacyMode.PUBLIC
                    else "private"
                )
            _register_active_run(profile.id, scope_ids)
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None
    return modes, scope_ids


def _register_active_run(pack_id: str, scope_ids: frozenset[str]) -> None:
    with _LOCK:
        for scope_id in scope_ids:
            key = (pack_id, scope_id)
            _ACTIVE_RUNS[key] = _ACTIVE_RUNS.get(key, 0) + 1


def _unregister_active_run(pack_id: str, scope_ids: frozenset[str]) -> None:
    with _LOCK:
        for scope_id in scope_ids:
            key = (pack_id, scope_id)
            count = _ACTIVE_RUNS.get(key, 0)
            if count <= 1:
                _ACTIVE_RUNS.pop(key, None)
            else:
                _ACTIVE_RUNS[key] = count - 1


def _register_active_write(pack_id: str, scope_id: str) -> None:
    with _LOCK:
        key = (pack_id, scope_id)
        _ACTIVE_WRITES[key] = _ACTIVE_WRITES.get(key, 0) + 1


def _unregister_active_write(pack_id: str, scope_id: str) -> None:
    with _LOCK:
        key = (pack_id, scope_id)
        count = _ACTIVE_WRITES.get(key, 0)
        if count <= 1:
            _ACTIVE_WRITES.pop(key, None)
        else:
            _ACTIVE_WRITES[key] = count - 1


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


def _require_current_public_run_scope(
    installation,
    declaration: ArtifactDeclaration,
) -> None:
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
        require_stable_bound_scope(installation, scope.id)
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None
    if (
        resolution.declared is not DeclaredPrivacyMode.PUBLIC
        or resolution.effective is not EffectivePrivacyMode.PUBLIC
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")


def _sweep_public_run_spills_for_scope(
    profile: PrivacyProfile,
    scope_id: str,
) -> None:
    declarations = tuple(
        declaration
        for declaration in profile.artifacts
        if declaration.scope_id == scope_id
        and declaration.retention is ArtifactRetention.RUN_SCOPED_SPILL
    )
    identities = {
        (declaration.resource_id, declaration.id) for declaration in declarations
    }
    if not identities:
        return
    try:
        with _exclusive_artifact_ledger():
            ledger = _load_ledger()
            _retired, failed = _retire_from_ledger(
                ledger,
                lambda entry: (
                    entry.get("packId") == profile.id
                    and entry.get("storageMode") == "public"
                    and entry.get("retention") == "run-scoped-spill"
                    and (entry.get("resourceId"), entry.get("artifactKind"))
                    in identities
                ),
            )
            _write_ledger(ledger)
            remaining = any(
                entry.get("packId") == profile.id
                and entry.get("storageMode") == "public"
                and (entry.get("resourceId"), entry.get("artifactKind"))
                in identities
                for entry in ledger["entries"]
            )
            orphan_failed = False
            for resource_id, artifact_kind in identities:
                directory = _artifact_root() / profile.id / resource_id / artifact_kind
                if not directory.exists():
                    continue
                for path in directory.glob("*.spill"):
                    try:
                        path.unlink()
                    except OSError:
                        orphan_failed = True
                if any(directory.glob("*.spill")):
                    orphan_failed = True
        if failed or remaining or orphan_failed:
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    except ArtifactError:
        raise
    except Exception:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None


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
    if isinstance(record, _LeaseRecord):
        try:
            _require_lease_record_authority(record)
        except Exception:
            return False
        if record.storage_mode == "public":
            return True
    try:
        current = _session_fingerprint()
    except Exception:
        return False
    with _LOCK:
        if (
            record.revoked
            or record.expires_at <= time.time()
            or record.session_fingerprint is None
            or not hmac.compare_digest(record.session_fingerprint, current)
        ):
            record.revoked = True
            return False
        return True


def _require_leaseable_artifact(
    installation,
    locator: _ArtifactLocator,
) -> dict:
    from .mode_runtime import bound_mode_work_admission

    try:
        with bound_mode_work_admission(
            installation,
            (locator.declaration.scope_id,),
        ):
            entry = _require_artifact_entry(locator)
            mode = _current_artifact_storage_mode(installation, locator.declaration)
            if entry.get("storageMode") != mode:
                raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
            _require_artifact_file(locator, entry)
            return dict(entry)
    except ArtifactError:
        raise
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None


def _require_lease_record_authority(record: _LeaseRecord) -> dict:
    entry = _require_leaseable_artifact(record.installation, record.locator)
    if (
        entry.get("storageMode") != record.storage_mode
        or entry.get("revision") != record.entry_revision
        or entry.get("representationSha256") != record.representation_sha256
        or (
            record.public_identity is not None
            and not record.public_identity.matches(
                record.locator.path_for("public")
            )
        )
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
    return entry


def _open_lease_record_file(
    record: _LeaseRecord,
):
    entry = _require_lease_record_authority(record)
    _require_artifact_file(record.locator, entry)
    if record.locator.declaration.payload_mode is ArtifactPayloadMode.STREAM_V1:
        return _open_stream_artifact_source(record.locator, entry)
    if record.storage_mode == "public":
        return _open_validated_public_artifact(
            record.locator,
            _entry_representation_sha256(entry),
        )
    return None


def _iter_lease_payload(
    record: _LeaseRecord,
    public_artifact,
):
    _require_lease_record_authority(record)
    if record.locator.declaration.payload_mode is ArtifactPayloadMode.STREAM_V1:
        if public_artifact is None:
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
        while True:
            try:
                chunk = public_artifact.read(public_artifact.max_chunk_bytes)
            except ArtifactStreamError:
                raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None
            if not chunk:
                return
            yield chunk
        return
    if record.storage_mode == "public":
        if public_artifact is None:
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
        yield from public_artifact.iter_chunks()
    else:
        yield from _iter_artifact_plaintext(record.locator)


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


@contextmanager
def _exclusive_artifact_ledger():
    """Serialize ledger and representation authority across processes."""

    with _LOCK:
        depth = int(getattr(_LEDGER_LOCK_LOCAL, "depth", 0))
        if depth:
            _LEDGER_LOCK_LOCAL.depth = depth + 1
            try:
                yield
            finally:
                _LEDGER_LOCK_LOCAL.depth = depth
            return
        root = _artifact_root()
        descriptor: int | None = None
        try:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(root, 0o700)
            descriptor = os.open(
                root / "ledger.lock",
                os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID") from None
        _LEDGER_LOCK_LOCAL.depth = 1
        try:
            yield
        finally:
            _LEDGER_LOCK_LOCAL.depth = 0
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)


def _artifact_path(
    pack_id: str,
    resource_id: str,
    artifact_kind: str,
    artifact_id: str,
) -> Path:
    return _artifact_root() / pack_id / resource_id / artifact_kind / f"{artifact_id}.hpa"


def _public_artifact_path(
    pack_id: str,
    resource_id: str,
    artifact_kind: str,
    artifact_id: str,
    *,
    retention: str | None = None,
) -> Path:
    extension = "spill" if retention == "run-scoped-spill" else "hpu"
    return (
        _artifact_root()
        / pack_id
        / resource_id
        / artifact_kind
        / f"{artifact_id}.{extension}"
    )


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
        "revision": 0,
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
    if not isinstance(value, dict) or value.get("schema") != ARTIFACT_LEDGER_SCHEMA:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    if value.get("version") == 1:
        value = _migrate_ledger_v1(value)
    if not _valid_ledger(value):
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    return value


def _valid_ledger(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "version",
        "revision",
        "entries",
    }:
        return False
    entries = value.get("entries")
    return (
        value.get("schema") == ARTIFACT_LEDGER_SCHEMA
        and value.get("version") == ARTIFACT_LEDGER_VERSION
        and type(value.get("revision")) is int
        and int(value["revision"]) >= 0
        and isinstance(entries, list)
        and all(_valid_ledger_entry(entry) for entry in entries)
        and len({entry["artifactId"] for entry in entries}) == len(entries)
    )


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
        "revision",
        "storageMode",
        "transition",
    }
    keys = set(entry)
    optional = {
        "expiresAt",
        "fileVersion",
        "payloadContractDigest",
        "payloadMode",
        "payloadSha256",
        "plaintextBytes",
        "representationSha256",
        "state",
    }
    if not required.issubset(keys) or not keys.issubset(required | optional):
        return False
    stable_values = (
        entry.get("artifactKind"),
        entry.get("packId"),
        entry.get("resourceId"),
    )
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
        and _finite_nonnegative_timestamp(entry.get("createdAt"))
        and isinstance(entry.get("formatVersion"), int)
        and not isinstance(entry.get("formatVersion"), bool)
        and entry["formatVersion"] >= 1
        and type(entry.get("revision")) is int
        and int(entry["revision"]) >= 1
        and isinstance(entry.get("processEpoch"), str)
        and 8 <= len(entry["processEpoch"]) <= 128
        and entry.get("retention")
        in {
            "durable-adjunct",
            "regenerable-cache",
            "run-scoped-spill",
            "served-transient",
        }
        and entry.get("storageMode") in {"private", "public"}
        and _valid_entry_expiry(entry)
        and _valid_entry_payload_contract(entry)
        and _valid_entry_representation(entry)
        and _valid_entry_transition(entry)
    )


def _finite_nonnegative_timestamp(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _valid_entry_expiry(entry: Mapping[str, object]) -> bool:
    requires_expiry = entry.get("retention") in {
        "regenerable-cache",
        "served-transient",
    }
    if ("expiresAt" in entry) is not requires_expiry:
        return False
    return not requires_expiry or _finite_nonnegative_timestamp(entry.get("expiresAt"))


def _valid_entry_representation(entry: Mapping[str, object]) -> bool:
    requires_digest = (
        entry.get("storageMode") == "public"
        and entry.get("retention") != "run-scoped-spill"
        and entry.get("payloadMode", ArtifactPayloadMode.BOUNDED_BYTES_V1.value)
        == ArtifactPayloadMode.BOUNDED_BYTES_V1.value
    )
    if ("representationSha256" in entry) is not requires_digest:
        return False
    digest = entry.get("representationSha256")
    return not requires_digest or (
        isinstance(digest, str) and _DIGEST.fullmatch(digest) is not None
    )


def _valid_entry_payload_contract(entry: Mapping[str, object]) -> bool:
    payload_mode = entry.get("payloadMode", ArtifactPayloadMode.BOUNDED_BYTES_V1.value)
    state = entry.get("state", "READY")
    if payload_mode == ArtifactPayloadMode.BOUNDED_BYTES_V1.value:
        return (
            state == "READY"
            and not any(
                key in entry
                for key in (
                    "fileVersion",
                    "payloadContractDigest",
                    "payloadSha256",
                    "plaintextBytes",
                )
            )
        )
    if payload_mode != ArtifactPayloadMode.STREAM_V1.value:
        return False
    if (
        state not in {"WRITING", "READY", "CLEANUP_PENDING"}
        or ((entry.get("cleanupPending") is True) != (state == "CLEANUP_PENDING"))
        or type(entry.get("fileVersion")) is not int
        or entry.get("fileVersion") != (2 if entry.get("storageMode") == "private" else 1)
        or not isinstance(entry.get("payloadContractDigest"), str)
        or _DIGEST.fullmatch(str(entry["payloadContractDigest"])) is None
    ):
        return False
    if state != "READY":
        return "plaintextBytes" not in entry and "payloadSha256" not in entry
    if (
        type(entry.get("plaintextBytes")) is not int
        or int(entry["plaintextBytes"]) < 0
    ):
        return False
    if entry.get("storageMode") == "public":
        return (
            isinstance(entry.get("payloadSha256"), str)
            and _DIGEST.fullmatch(str(entry["payloadSha256"])) is not None
        )
    return "payloadSha256" not in entry


def _valid_entry_transition(entry: Mapping[str, object]) -> bool:
    transition = entry.get("transition")
    if transition is None:
        return True
    if entry.get("state", "READY") != "READY":
        return False
    if entry.get("cleanupPending") is True or not isinstance(transition, dict):
        return False
    if set(transition) != {
        "action",
        "phase",
        "priorMode",
        "targetMode",
        "transitionId",
    }:
        return False
    action = transition.get("action")
    phase = transition.get("phase")
    prior_mode = transition.get("priorMode")
    target_mode = transition.get("targetMode")
    if (
        action not in {"convert", "retire"}
        or phase
        not in {"preparing", "prepared", "committed", "rolling-back", "retiring"}
        or prior_mode not in {"private", "public"}
        or target_mode not in {"private", "public"}
        or prior_mode == target_mode
        or not isinstance(transition.get("transitionId"), str)
        or _TRANSITION_ID.fullmatch(transition["transitionId"]) is None
    ):
        return False
    if action == "convert" and entry.get("retention") != "durable-adjunct":
        return False
    if action == "retire" and entry.get("retention") not in {
        "regenerable-cache",
        "served-transient",
    }:
        return False
    expected_authority = (
        target_mode
        if action == "convert" and phase in {"committed", "retiring"}
        else prior_mode
    )
    return entry.get("storageMode") == expected_authority


def _valid_v1_ledger_entry(entry: object) -> bool:
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
    if not required.issubset(entry) or not set(entry).issubset(
        required | {"expiresAt", "payloadMode", "state", "storageMode"}
    ):
        return False
    migrated = dict(entry)
    migrated["revision"] = 1
    migrated["storageMode"] = str(entry.get("storageMode") or "private")
    migrated["transition"] = None
    return _valid_ledger_entry(migrated) and (
        migrated["storageMode"] != "public"
        or migrated["retention"] == "run-scoped-spill"
    )


def _migrate_ledger_v1(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) != {"schema", "version", "entries"}:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    entries = value.get("entries")
    if (
        not isinstance(entries, list)
        or any(not _valid_v1_ledger_entry(entry) for entry in entries)
        or len({entry["artifactId"] for entry in entries}) != len(entries)
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    migrated_entries = []
    for entry in entries:
        migrated = dict(entry)
        migrated["revision"] = 1
        migrated["storageMode"] = str(entry.get("storageMode") or "private")
        migrated["transition"] = None
        migrated_entries.append(migrated)
    migrated_ledger = {
        "schema": ARTIFACT_LEDGER_SCHEMA,
        "version": ARTIFACT_LEDGER_VERSION,
        "revision": 1,
        "entries": migrated_entries,
    }
    _write_ledger_payload(migrated_ledger)
    return migrated_ledger


def _write_ledger(ledger: dict[str, object]) -> None:
    ledger["revision"] = int(ledger.get("revision", 0)) + 1
    if not _valid_ledger(ledger):
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    _write_ledger_payload(ledger)


def _write_ledger_payload(ledger: Mapping[str, object]) -> None:
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
    with _exclusive_artifact_ledger():
        entry = next(
            (
                candidate
                for candidate in _load_ledger()["entries"]
                if locator.matches(candidate)
            ),
            None,
        )
    if (
        entry is None
        or entry.get("cleanupPending") is True
        or entry.get("state", "READY") != "READY"
    ):
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    if entry.get("transition") is not None:
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
    if _entry_is_stale(entry):
        _retire_matching(
            locator.matches,
            False,
        )
        raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
    return dict(entry)


def _require_artifact_file(locator: _ArtifactLocator, entry: Mapping[str, object]) -> None:
    try:
        metadata = locator.path_for(str(entry.get("storageMode"))).lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError
        if (
            entry.get("storageMode") == "public"
            and locator.declaration.retention is not ArtifactRetention.RUN_SCOPED_SPILL
            and locator.declaration.payload_mode is ArtifactPayloadMode.BOUNDED_BYTES_V1
        ):
            opened = _open_validated_public_artifact(
                locator,
                _entry_representation_sha256(entry),
            )
            opened.close()
    except FileNotFoundError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_NOT_FOUND") from None
    except OSError:
        _discard_unreadable_cache(locator)
        raise ArtifactError("PRIVACY_ARTIFACT_UNREADABLE") from None


def _entry_representation_sha256(entry: Mapping[str, object]) -> str:
    value = entry.get("representationSha256")
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    return value


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
                _mark_cleanup_pending_entry(entry)
    return retire_ids


def _touch_entry(entry: dict[str, object]) -> None:
    revision = entry.get("revision")
    if type(revision) is not int or revision < 1:
        raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")
    entry["revision"] = revision + 1


def _retire_matching(predicate, fail_on_error: bool) -> int:
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        retired, failed = _retire_from_ledger(ledger, predicate)
        _write_ledger(ledger)
    if failed and fail_on_error:
        raise ArtifactError("PRIVACY_ARTIFACT_CLEANUP_FAILED")
    return retired


def _reconcile_owner_locked(
    pack_id: str,
    resource_id: str,
    declaration: ArtifactDeclaration,
    owner_id: str,
    keep_ids: tuple[str, ...],
    storage_mode: str,
) -> int:
    """Validate the canonical set and durably revoke losers under one lock."""

    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        entries = ledger["entries"]
        if any(
            entry.get("packId") == pack_id
            and entry.get("resourceId") == resource_id
            and entry.get("artifactKind") == declaration.id
            and entry.get("ownerId") == owner_id
            and entry.get("transition") is not None
            for entry in entries
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
        for artifact_id in keep_ids:
            matches = [
                entry
                for entry in entries
                if entry.get("artifactId") == artifact_id
            ]
            if len(matches) != 1:
                raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")
            entry = matches[0]
            locator = _ArtifactLocator(
                pack_id,
                resource_id,
                declaration,
                artifact_id,
            )
            if (
                not locator.matches(entry)
                or entry.get("ownerId") != owner_id
                or entry.get("retention") != declaration.retention.value
                or entry.get("storageMode") != storage_mode
                or entry.get("cleanupPending") is True
                or entry.get("transition") is not None
                or _entry_is_stale(entry)
                or not _entry_has_regular_file(entry)
            ):
                raise ArtifactError("PRIVACY_ARTIFACT_REFERENCE_INVALID")

        keep_set = set(keep_ids)
        targets = [
            entry
            for entry in entries
            if entry.get("packId") == pack_id
            and entry.get("resourceId") == resource_id
            and entry.get("artifactKind") == declaration.id
            and entry.get("ownerId") == owner_id
            and entry.get("artifactId") not in keep_set
        ]
        if not targets:
            return 0

        target_ids = {entry["artifactId"] for entry in targets}
        for entry in targets:
            if entry.get("transition") is not None:
                raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED")
            _mark_cleanup_pending_entry(entry)
            _revoke_entry_leases_locked(entry)
        # Commit revocation before touching ciphertext. An interruption can then
        # leave only retryable cleanup-pending entries, never restored authority.
        _write_ledger(ledger)
        retired, failed = _retire_from_ledger(
            ledger,
            lambda entry: (
                entry.get("packId") == pack_id
                and entry.get("resourceId") == resource_id
                and entry.get("artifactKind") == declaration.id
                and entry.get("ownerId") == owner_id
                and entry.get("artifactId") in target_ids
            ),
        )
        _write_ledger(ledger)
    if failed:
        raise ArtifactError("PRIVACY_ARTIFACT_CLEANUP_FAILED")
    return retired


def _reconcile_owner_with_authority(
    installation,
    pack_id: str,
    resource_id: str,
    declaration: ArtifactDeclaration,
    owner_id: str,
    keep_ids: tuple[str, ...],
) -> int:
    """Admit reconciliation under stable current scope authority."""

    from .mode_runtime import bound_mode_work_admission

    try:
        with bound_mode_work_admission(installation, (declaration.scope_id,)):
            storage_mode = _current_artifact_storage_mode(installation, declaration)
            return _reconcile_owner_locked(
                pack_id,
                resource_id,
                declaration,
                owner_id,
                keep_ids,
                storage_mode,
            )
    except (ModePolicyError, ModeTransitionError):
        raise ArtifactError("PRIVACY_ARTIFACT_MODE_BLOCKED") from None


def _register_artifact_lease(
    locator: _ArtifactLocator,
    lease_id: str,
    record: _LeaseRecord,
) -> None:
    """Atomically revalidate artifact authority and register its lease."""

    with _exclusive_artifact_ledger():
        entry = _require_artifact_entry(locator)
        if (
            entry.get("storageMode") != record.storage_mode
            or entry.get("revision") != record.entry_revision
        ):
            raise ArtifactError("PRIVACY_ARTIFACT_LEASE_INVALID")
        _require_artifact_file(locator, entry)
        _expire_leases_locked()
        _LEASES[lease_id] = record


def _retire_group_matching(predicate) -> int:
    """Revoke group authority even when ciphertext deletion needs a sweep."""

    with _exclusive_artifact_ledger():
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
    targets = [
        entry
        for entry in ledger["entries"]
        if predicate(entry) and entry.get("transition") is None
    ]
    blocked = sum(
        1
        for entry in ledger["entries"]
        if predicate(entry) and entry.get("transition") is not None
    )
    retired = 0
    failed = blocked

    if forget_failed:
        target_ids = {id(entry) for entry in targets}
        for entry in targets:
            _revoke_entry_leases_locked(entry)
        if targets:
            ledger["entries"] = [
                entry for entry in ledger["entries"] if id(entry) not in target_ids
            ]
            # Group authority is forgotten atomically before deletion. Failed
            # files are then ordinary orphans for the startup sweep.
            _write_ledger(ledger)
        for entry in targets:
            try:
                for path in _entry_retirement_paths(entry):
                    path.unlink(missing_ok=True)
                    sync_parent_directory(path)
                retired += 1
            except OSError:
                failed += 1
        return retired, failed

    marked = False
    for entry in targets:
        _revoke_entry_leases_locked(entry)
        marked = _mark_cleanup_pending_entry(entry) or marked
    if marked:
        # Revocation and a schema-valid retry marker must reach disk before any
        # representation is unlinked. An interruption can never restore read
        # authority or lose the cleanup obligation.
        _write_ledger(ledger)

    successful_ids: set[int] = set()
    for entry in targets:
        try:
            for path in _entry_retirement_paths(entry):
                path.unlink(missing_ok=True)
                sync_parent_directory(path)
            retired += 1
            successful_ids.add(id(entry))
        except OSError:
            failed += 1
    ledger["entries"] = [
        entry for entry in ledger["entries"] if id(entry) not in successful_ids
    ]
    return retired, failed


def _mark_cleanup_pending_entry(entry: dict[str, object]) -> bool:
    """Move one authoritative entry to its schema-valid retry-only state."""

    changed = entry.get("cleanupPending") is not True
    if entry.get("payloadMode") == ArtifactPayloadMode.STREAM_V1.value:
        changed = entry.get("state") != "CLEANUP_PENDING" or changed
        entry["state"] = "CLEANUP_PENDING"
        # READY-only authenticated payload facts cannot remain on a
        # CLEANUP_PENDING stream entry. Contract/file identity stays so the
        # retry knows every representation path it owns.
        if "plaintextBytes" in entry:
            entry.pop("plaintextBytes", None)
            changed = True
        if "payloadSha256" in entry:
            entry.pop("payloadSha256", None)
            changed = True
    entry["cleanupPending"] = True
    if changed:
        _touch_entry(entry)
    return changed


def _entry_retirement_paths(entry: Mapping[str, object]) -> tuple[Path, ...]:
    modes = ("private", "public")
    representations = tuple(
        dict.fromkeys(_entry_representation_path(entry, mode) for mode in modes)
    )
    paths = tuple(
        dict.fromkeys(
            (*representations, *(_stream_staging_path(path) for path in representations))
        )
    )
    return paths


def _entry_has_regular_file(entry: dict) -> bool:
    if entry.get("state", "READY") != "READY":
        return False
    try:
        return stat.S_ISREG(_entry_path(entry).lstat().st_mode)
    except OSError:
        return False


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
    arguments = (
        str(entry.get("packId") or ""),
        str(entry.get("resourceId") or ""),
        str(entry.get("artifactKind") or ""),
        str(entry.get("artifactId") or ""),
    )
    if entry.get("storageMode") == "public":
        return _public_artifact_path(
            *arguments,
            retention=(
                "run-scoped-spill"
                if entry.get("payloadMode") == ArtifactPayloadMode.STREAM_V1.value
                else str(entry.get("retention") or "")
            ),
        )
    return _artifact_path(*arguments)


def _entry_representation_path(entry: Mapping[str, object], mode: str) -> Path:
    arguments = (
        str(entry.get("packId") or ""),
        str(entry.get("resourceId") or ""),
        str(entry.get("artifactKind") or ""),
        str(entry.get("artifactId") or ""),
    )
    if mode == "public":
        return _public_artifact_path(
            *arguments,
            retention=(
                "run-scoped-spill"
                if entry.get("payloadMode") == ArtifactPayloadMode.STREAM_V1.value
                else str(entry.get("retention") or "")
            ),
        )
    if mode == "private":
        return _artifact_path(*arguments)
    raise ArtifactError("PRIVACY_ARTIFACT_LEDGER_INVALID")


def _entry_is_stale(entry: dict) -> bool:
    if (
        entry.get("state", "READY") != "READY"
        and entry.get("processEpoch") != _PROCESS_EPOCH
    ):
        return True
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
    with _exclusive_artifact_ledger():
        ledger = _load_ledger()
        retired, _failed = _retire_from_ledger(
            ledger,
            lambda entry: entry.get("transition") is None
            and (
                bool(entry.get("cleanupPending"))
                or _entry_is_stale(entry)
            ),
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
    managed: set[Path] = set()
    for entry in ledger["entries"]:
        managed.add(_entry_path(entry))
        if entry.get("transition") is not None:
            managed.update(
                _entry_representation_path(entry, mode)
                for mode in ("private", "public")
            )
    retired = 0
    pending = 0
    for path in (
        *root.rglob("*.hpa"),
        *root.rglob("*.hpu"),
        *root.rglob("*.spill"),
    ):
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
    with _exclusive_artifact_ledger():
        root = _artifact_root()
        if root.exists():
            for path in root.rglob("*"):
                if path.is_file() and (
                    path.name.endswith((".tmp", ".part", ".plaintext"))
                    or (
                        path.name.startswith(".")
                        and (".hpa." in path.name or ".hpu." in path.name)
                    )
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
