"""Reusable write, lease, replacement, and release orchestration."""

from __future__ import annotations

import asyncio
import inspect
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

    async def write_group(
        self,
        artifact_kind: str,
        values: tuple[object, ...] | list[object],
        *,
        replacing: tuple[PublishedArtifactReference, ...]
        | list[PublishedArtifactReference] = (),
    ) -> tuple[PublishedArtifactReference, ...]:
        """Publish a multi-item group and revoke its prior authority at once."""

        safe_kind = str(artifact_kind or "")
        supplied = tuple(values)
        previous = tuple(replacing)
        if not safe_kind or not supplied:
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
        async with self._lock:
            for publication in previous:
                self._require_publication(publication, artifact_kind=safe_kind)
            created: list[PublishedArtifactReference] = []
            try:
                for value in supplied:
                    owner_id = generate_artifact_owner_id()
                    reference = await self._handle.write(
                        safe_kind,
                        owner_id,
                        value,
                    )
                    created.append(
                        PublishedArtifactReference(
                            reference,
                            safe_kind,
                            owner_id,
                            self._identity,
                        )
                    )
                if previous:
                    await self._retire_group_handle(previous)
            except BaseException as exc:
                await self._retire_group_silent(created)
                for publication in previous:
                    publication._is_current = False
                    self._forget(publication)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise ArtifactPublicationError() from None
            for publication in previous:
                publication._is_current = False
                self._forget(publication)
            for publication in created:
                self._publications.setdefault(
                    publication._owner_id,
                    [],
                ).append(publication)
            return tuple(created)

    async def retire_group(
        self,
        publications: tuple[PublishedArtifactReference, ...]
        | list[PublishedArtifactReference],
    ) -> int:
        supplied = tuple(publications)
        if not supplied:
            return 0
        async with self._lock:
            for publication in supplied:
                self._require_publication(publication)
            try:
                retired = await self._retire_group_handle(supplied)
            except asyncio.CancelledError:
                raise
            except Exception:
                for publication in supplied:
                    publication._is_current = False
                    self._forget(publication)
                raise ArtifactPublicationError() from None
            for publication in supplied:
                publication._is_current = False
                self._forget(publication)
            return int(retired)

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

    async def read(self, publication: PublishedArtifactReference) -> object:
        async with self._lock:
            self._require_publication(publication)
            read = getattr(self._handle, "read", None)
            if not callable(read):
                raise ArtifactPublicationError(
                    "PRIVACY_ARTIFACT_PUBLICATION_INVALID"
                )
            try:
                return await read(
                    publication._artifact_kind,
                    publication._reference,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None

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

    async def _retire_group_handle(
        self,
        publications: tuple[PublishedArtifactReference, ...]
        | list[PublishedArtifactReference],
    ) -> int:
        retire_group = getattr(self._handle, "retire_group", None)
        if not callable(retire_group):
            raise ArtifactPublicationError(
                "PRIVACY_ARTIFACT_PUBLICATION_INVALID"
            )
        return int(
            await retire_group(
                tuple(
                    (publication._artifact_kind, publication._reference)
                    for publication in publications
                )
            )
        )

    async def _retire_group_silent(
        self,
        publications: tuple[PublishedArtifactReference, ...]
        | list[PublishedArtifactReference],
    ) -> None:
        if not publications:
            return
        try:
            await self._retire_group_handle(publications)
        except Exception:
            pass
        for publication in publications:
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


@dataclass(slots=True, repr=False, eq=False)
class PublishedRunArtifactReference:
    """Opaque reference whose lifetime is owned by one run-scoped session."""

    _reference: object = field(repr=False)
    _artifact_kind: str = field(repr=False)
    _session_identity: object = field(repr=False)
    _is_current: bool = field(default=True, repr=False)

    @property
    def is_current(self) -> bool:
        return self._is_current

    @property
    def artifact_kind(self) -> str:
        return self._artifact_kind

    def to_payload(self) -> dict[str, object]:
        payload = getattr(self._reference, "to_payload", None)
        if not callable(payload):
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
        return payload()

    def __repr__(self) -> str:
        return f"PublishedRunArtifactReference(is_current={self.is_current!r})"


class RunScopedArtifactPublication:
    """Exactly-once read/write lifecycle over one shared artifact run."""

    def __init__(self, handle: object, run: object) -> None:
        self._handle = handle
        self._run = run
        self._identity = object()
        self._publications: list[PublishedRunArtifactReference] = []
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def owner_id(self) -> str:
        return str(self._run.owner_id)

    async def write(
        self,
        artifact_kind: str,
        value: object,
    ) -> PublishedRunArtifactReference:
        safe_kind = str(artifact_kind or "")
        if not safe_kind:
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
        async with self._lock:
            if self._closed:
                raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
            try:
                reference = await self._run.write(safe_kind, value)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None
            publication = PublishedRunArtifactReference(
                reference,
                safe_kind,
                self._identity,
            )
            self._publications.append(publication)
            return publication

    async def read(self, publication: PublishedRunArtifactReference) -> object:
        async with self._lock:
            self._require_publication(publication)
            try:
                return await self._handle.read(
                    publication._artifact_kind,
                    publication._reference,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None

    async def close(self) -> int:
        async with self._lock:
            if self._closed:
                return 0
            self._closed = True
            try:
                return int(await self._run.close())
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ArtifactPublicationError() from None
            finally:
                for publication in self._publications:
                    publication._is_current = False
                self._publications.clear()

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _traceback) -> bool:
        await self.close()
        return False

    def _require_publication(self, publication: object) -> None:
        if (
            self._closed
            or not isinstance(publication, PublishedRunArtifactReference)
            or publication._session_identity is not self._identity
            or not publication.is_current
        ):
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")


class RunScopedArtifactPublicationService:
    """Open run-scoped artifact sessions without exposing cleanup mechanics."""

    def __init__(self, handle: object) -> None:
        if any(
            not callable(getattr(handle, name, None))
            for name in ("run", "read")
        ):
            raise TypeError("A run-capable artifact handle is required.")
        self._handle = handle

    def open(self, owner_id: str | None = None) -> RunScopedArtifactPublication:
        try:
            run = self._handle.run(owner_id)
        except Exception:
            raise ArtifactPublicationError() from None
        if any(
            not callable(getattr(run, name, None))
            for name in ("write", "close")
        ) or not isinstance(getattr(run, "owner_id", None), str):
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
        return RunScopedArtifactPublication(self._handle, run)


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


class _ProfileBoundSourceLeasePublisher:
    """Compiled operation-bound source publisher; constructed only by a pack handle."""

    def __init__(self, installation, declaration, adapter) -> None:
        self._installation = installation
        self._declaration = declaration
        self._adapter = adapter

    async def publish(
        self,
        reference_id: object,
        authorization: object,
    ) -> PublishedSourceLease:
        from .opaque_references import (
            OpaqueReferenceError,
            release_resolved_claims,
            resolve_operation_references,
            revoke_resolved_on_success,
        )
        from .guard import require_current_authorization
        from .mode_runtime import (
            acquire_bound_mode_work_admission,
            release_bound_mode_work_admission,
        )
        from .runtime import ReadinessHandle
        from .suite_runtime import require_active_process_suite

        declaration = self._declaration
        if not declaration.returns_lease or len(declaration.reference_inputs) != 1:
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_PUBLICATION_INVALID")
        reference_input = declaration.reference_inputs[0]
        has_dependencies = bool(
            declaration.record_dependencies
            or declaration.singleton_dependencies
            or declaration.artifact_dependencies
        )
        resolved = None
        dependencies = None
        admission = None
        succeeded = False
        try:
            ReadinessHandle(self._installation).require_ready()
            require_active_process_suite()
            require_current_authorization(
                authorization,
                declaration.id,
                pack_id=self._installation.profile.id,
            )
            admission = acquire_bound_mode_work_admission(
                self._installation,
                (declaration.scope_id,),
            )
            resolved = resolve_operation_references(
                profile=self._installation.profile,
                declaration=declaration,
                authorization=authorization,
                references={reference_input.name: reference_id},
            )
            bind_source = getattr(
                self._adapter,
                (
                    "bind_source_with_dependencies"
                    if has_dependencies
                    else "bind_source"
                ),
                None,
            )
            if not callable(bind_source):
                raise OpaqueReferenceError()
            if has_dependencies:
                from .operation_dependencies import build_operation_dependencies

                dependencies = build_operation_dependencies(
                    self._installation,
                    declaration,
                    authorization,
                )
                try:
                    candidate = bind_source(
                        resolved[reference_input.name],
                        declaration,
                        dependencies,
                    )
                    source = (
                        await candidate
                        if inspect.isawaitable(candidate)
                        else candidate
                    )
                finally:
                    from .operation_dependencies import (
                        expire_operation_dependencies,
                    )

                    expire_operation_dependencies(dependencies)
                    dependencies = None
            else:
                source = await run_blocking_adapter(
                    bind_source,
                    resolved[reference_input.name],
                    declaration,
                )
            if not isinstance(source, RootBoundSource):
                raise OpaqueReferenceError()
            lease = await issue_root_bound_source_lease(
                pack_id=self._installation.profile.id,
                operation_id=declaration.id,
                source=source,
                authorization=authorization,
            )
            revoke_resolved_on_success(declaration, resolved)
            succeeded = True
            return PublishedSourceLease(lease)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ArtifactPublicationError("PRIVACY_ARTIFACT_SOURCE_REJECTED") from None
        finally:
            if dependencies is not None:
                from .operation_dependencies import expire_operation_dependencies

                expire_operation_dependencies(dependencies)
            if not succeeded:
                release_resolved_claims(resolved)
            if admission is not None:
                release_bound_mode_work_admission(admission)
