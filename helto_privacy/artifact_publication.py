"""Reusable write, lease, replacement, and release orchestration."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field

from .artifacts import (
    ArtifactLease,
    ArtifactReference,
    RootBoundSource,
    generate_artifact_owner_id,
    issue_root_bound_source_lease,
)
from .concurrency import run_blocking_adapter


class ArtifactPublicationError(RuntimeError):
    """Stable product-data-free publication failure."""

    def __init__(self, code: str = "PRIVACY_ARTIFACT_PUBLICATION_FAILED") -> None:
        self.code = code
        self.correlation_id = "hp-publication-" + secrets.token_urlsafe(12)
        super().__init__("Private artifact publication could not complete.")

    def __repr__(self) -> str:
        return f"ArtifactPublicationError(code={self.code!r})"


@dataclass(slots=True, repr=False, eq=False)
class PublishedArtifactReference:
    """One managed artifact reference owned by a publication service."""

    _reference: ArtifactReference = field(repr=False)
    _artifact_kind: str = field(repr=False)
    _owner_id: str = field(repr=False)
    _service_identity: object = field(repr=False)
    _is_current: bool = field(default=True, repr=False)

    @property
    def is_current(self) -> bool:
        return self._is_current

    @property
    def artifact_kind(self) -> str:
        return self._artifact_kind

    def to_payload(self) -> dict[str, object]:
        return self._reference.to_payload()

    def __repr__(self) -> str:
        return f"PublishedArtifactReference(is_current={self.is_current!r})"


class ArtifactPublicationService:
    """Coordinate multiple artifact kinds over one resource lifecycle handle."""

    def __init__(self, handle: object) -> None:
        required = ("write", "retire", "release_owner", "sweep")
        if any(not callable(getattr(handle, name, None)) for name in required):
            raise TypeError("A complete artifact handle is required.")
        self._handle = handle
        self._identity = object()
        self._publications: dict[str, list[PublishedArtifactReference]] = {}
        self._lock = asyncio.Lock()

    async def write(
        self,
        artifact_kind: str,
        value: object,
        *,
        owner_id: str | None = None,
        replacing: PublishedArtifactReference | None = None,
    ) -> PublishedArtifactReference:
        safe_kind = str(artifact_kind or "")
        if not safe_kind:
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
        safe_owner = owner_id or generate_artifact_owner_id()
        async with self._lock:
            if replacing is not None:
                self._require_publication(replacing, artifact_kind=safe_kind)
            try:
                reference = await self._handle.write(safe_kind, safe_owner, value)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None
            publication = PublishedArtifactReference(
                reference,
                safe_kind,
                safe_owner,
                self._identity,
            )
            if replacing is not None:
                try:
                    await self._handle.retire(safe_kind, replacing._reference)
                    replacing._is_current = False
                    self._forget(replacing)
                except BaseException as exc:
                    await self._retire_silent(publication)
                    replacing._is_current = False
                    self._forget(replacing)
                    if isinstance(exc, asyncio.CancelledError):
                        raise
                    raise ArtifactPublicationError() from None
            self._publications.setdefault(safe_owner, []).append(publication)
            return publication

    async def retire(self, publication: PublishedArtifactReference) -> int:
        async with self._lock:
            self._require_publication(publication)
            try:
                retired = await self._handle.retire(
                    publication._artifact_kind,
                    publication._reference,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None
            publication._is_current = False
            self._forget(publication)
            return int(retired)

    async def release_owner(self, owner_id: str) -> int:
        async with self._lock:
            try:
                retired = await self._handle.release_owner(owner_id)
            except BaseException as exc:
                for publication in self._publications.pop(owner_id, ()):
                    publication._is_current = False
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise ArtifactPublicationError() from None
            for publication in self._publications.pop(owner_id, ()):
                publication._is_current = False
            return int(retired)

    async def startup_recover(self):
        async with self._lock:
            for publications in self._publications.values():
                for publication in publications:
                    publication._is_current = False
            self._publications.clear()
            try:
                report = await self._handle.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None
            return report

    def _require_publication(
        self,
        publication: object,
        *,
        artifact_kind: str | None = None,
    ) -> None:
        if (
            not isinstance(publication, PublishedArtifactReference)
            or publication._service_identity is not self._identity
            or not publication.is_current
            or (
                artifact_kind is not None
                and publication._artifact_kind != artifact_kind
            )
        ):
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")

    async def _retire_silent(self, publication: PublishedArtifactReference) -> None:
        try:
            await self._handle.retire(
                publication._artifact_kind,
                publication._reference,
            )
        except Exception:
            pass
        publication._is_current = False

    def _forget(self, publication: PublishedArtifactReference) -> None:
        publications = self._publications.get(publication._owner_id)
        if publications is None:
            return
        try:
            publications.remove(publication)
        except ValueError:
            return
        if not publications:
            self._publications.pop(publication._owner_id, None)


@dataclass(frozen=True, slots=True, repr=False)
class PublishedSourceLease:
    _lease: ArtifactLease = field(repr=False)

    def to_payload(self) -> dict[str, object]:
        return {"lease": self._lease.to_payload()}

    def __repr__(self) -> str:
        return "PublishedSourceLease()"


class RootBoundSourceLeasePublisher:
    """Authorize a consumer source descriptor and issue one shared stream lease."""

    def __init__(
        self,
        pack_id: str,
        operation_id: str,
        authorize_source: Callable[[object], RootBoundSource],
    ) -> None:
        if not pack_id or not operation_id or not callable(authorize_source):
            raise TypeError("A complete root-bound source lease binding is required.")
        self._pack_id = str(pack_id)
        self._operation_id = str(operation_id)
        self._authorize_source = authorize_source

    async def publish(
        self,
        source: object,
        authorization: object,
    ) -> PublishedSourceLease:
        try:
            bound_source = await run_blocking_adapter(self._authorize_source, source)
            lease = await issue_root_bound_source_lease(
                pack_id=self._pack_id,
                operation_id=self._operation_id,
                source=bound_source,
                authorization=authorization,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ArtifactPublicationError(
                "PRIVACY_ARTIFACT_SOURCE_REJECTED"
            ) from None
        return PublishedSourceLease(lease)
