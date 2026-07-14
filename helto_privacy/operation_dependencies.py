"""Ephemeral least-authority dependencies for protected product operations."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import inspect
import secrets
from concurrent.futures import Future
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Mapping

from .profile import SingletonPayloadKind
from .protected_operations import ProtectedOperationError


def _denied() -> ProtectedOperationError:
    return ProtectedOperationError(
        "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE"
    )


def _new_token() -> str:
    return "hp-dependency-" + secrets.token_urlsafe(32)


class _OpaqueCapability:
    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        object.__setattr__(self, "_token", token)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Protected operation capabilities are immutable.")

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Protected operation capabilities cannot be serialized.")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Protected operation capabilities cannot be serialized.")

    def __getstate__(self):
        raise TypeError("Protected operation capabilities cannot be serialized.")


class RecordOperationCapability(_OpaqueCapability):
    """One exact record reveal projection for the invocation lifetime."""

    __slots__ = ()

    def reveal(self, record_id: str) -> dict[str, object]:
        return _dispatch_sync(self._token, "record.reveal", (record_id,))


class SingletonOperationCapability(_OpaqueCapability):
    """Closed operations over one exact singleton declaration."""

    __slots__ = ()

    def status(self):
        return _dispatch_sync(self._token, "singleton.status", ())

    def reveal(self):
        return _dispatch_sync(self._token, "singleton.reveal", ())

    def replace(self, value: object, expected_revision: int):
        return _dispatch_sync(
            self._token,
            "singleton.replace",
            (value, expected_revision),
        )

    def delete(self, expected_revision: int):
        return _dispatch_sync(
            self._token,
            "singleton.delete",
            (expected_revision,),
        )


class ArtifactOperationCapability(_OpaqueCapability):
    """Closed operations over one exact managed artifact kind."""

    __slots__ = ()

    async def write(self, owner_id: str, value: object):
        return await _dispatch_async(
            self._token,
            "artifact.write",
            (owner_id, value),
        )

    async def read(self, reference: object):
        return await _dispatch_async(
            self._token,
            "artifact.read",
            (reference,),
        )

    async def retire(self, reference: object) -> int:
        return await _dispatch_async(
            self._token,
            "artifact.retire",
            (reference,),
        )

    async def release_owner(self, owner_id: str) -> int:
        return await _dispatch_async(
            self._token,
            "artifact.release-owner",
            (owner_id,),
        )

    async def reconcile_owner(
        self,
        owner_id: str,
        keep: tuple[object, ...] = (),
    ) -> int:
        return await _dispatch_async(
            self._token,
            "artifact.reconcile-owner",
            (owner_id, keep),
        )

    async def lease(self, reference: object, operation: str):
        return await _dispatch_async(
            self._token,
            "artifact.lease",
            (reference, operation),
        )


class ProtectedOperationDependencies(_OpaqueCapability):
    """Opaque lookup surface containing only one operation's declared needs."""

    __slots__ = ()

    def record(
        self,
        resource_id: str,
        record_kind: str,
        operation: str,
    ) -> RecordOperationCapability:
        token = _lookup_dependency(
            self._token,
            "record",
            (resource_id, record_kind, operation),
        )
        return RecordOperationCapability(token)

    def singleton(self, singleton_id: str) -> SingletonOperationCapability:
        token = _lookup_dependency(self._token, "singleton", singleton_id)
        return SingletonOperationCapability(token)

    def artifact(self, artifact_kind: str) -> ArtifactOperationCapability:
        token = _lookup_dependency(self._token, "artifact", artifact_kind)
        return ArtifactOperationCapability(token)


@dataclass(frozen=True, slots=True)
class _RecordCapabilityState:
    resource_id: str
    record_kind: str
    operation: str


@dataclass(frozen=True, slots=True)
class _SingletonCapabilityState:
    resource_id: str
    singleton_id: str
    payload_kind: SingletonPayloadKind
    verbs: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ArtifactCapabilityState:
    resource_id: str
    artifact_kind: str
    verbs: frozenset[str]


@dataclass(frozen=True, slots=True)
class _InvocationState:
    bundle_token: str
    pack_id: str
    profile_fingerprint: str
    operation_id: str
    scope_id: str
    session_binding: bytes = field(repr=False)
    task_identity: int
    revocation: Future = field(repr=False)
    capabilities: Mapping[str, object] = field(repr=False)
    record_targets: Mapping[tuple[str, str, str], str] = field(repr=False)
    singleton_targets: Mapping[str, str] = field(repr=False)
    artifact_targets: Mapping[str, str] = field(repr=False)
    parent: _InvocationState | None = field(default=None, repr=False)


def _make_context_broker():
    current: ContextVar[_InvocationState | None] = ContextVar(
        "helto_privacy_operation_dependencies",
        default=None,
    )

    def install(state: _InvocationState) -> None:
        current.set(replace(state, parent=current.get()))

    def resolve(token: str) -> tuple[_InvocationState, object | None]:
        state = current.get()
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        if (
            state is None
            or state.revocation.done()
            or task is None
            or id(task) != state.task_identity
        ):
            raise _denied()
        if token == state.bundle_token:
            return state, None
        capability = state.capabilities.get(token)
        if capability is None:
            raise _denied()
        return state, capability

    def expire(bundle_token: str) -> None:
        state = current.get()
        candidate = state
        while candidate is not None and candidate.bundle_token != bundle_token:
            candidate = candidate.parent
        if candidate is None:
            return
        if not candidate.revocation.done():
            candidate.revocation.set_result(None)
        if state is candidate:
            current.set(candidate.parent)

    return install, resolve, expire


_install_invocation, _resolve_invocation, _expire_invocation = (
    _make_context_broker()
)
del _make_context_broker


def build_operation_dependencies(installation, declaration, authorization):
    """Compile one invocation-owned capability bundle from validated facts."""

    owner_task = asyncio.current_task()
    if owner_task is None:
        raise _denied()
    try:
        from .guard import require_current_authorization

        require_current_authorization(
            authorization,
            declaration.id,
            pack_id=installation.profile.id,
        )
        session_binding = hashlib.sha256(
            bytes(authorization._session_fingerprint)
        ).digest()
    except Exception:
        raise _denied() from None

    capabilities: dict[str, object] = {}
    record_targets: dict[tuple[str, str, str], str] = {}
    singleton_targets: dict[str, str] = {}
    artifact_targets: dict[str, str] = {}
    for dependency in declaration.record_dependencies:
        token = _new_token()
        target = (
            dependency.resource_id,
            dependency.record_kind,
            dependency.operation,
        )
        record_targets[target] = token
        capabilities[token] = _RecordCapabilityState(*target)
    for dependency in declaration.singleton_dependencies:
        singleton = next(
            item
            for item in installation.profile.singletons
            if item.id == dependency.singleton_id
        )
        token = _new_token()
        singleton_targets[singleton.id] = token
        capabilities[token] = _SingletonCapabilityState(
            singleton.resource_id,
            singleton.id,
            singleton.payload_kind,
            frozenset(dependency.verbs),
        )
    for dependency in declaration.artifact_dependencies:
        artifact = next(
            item
            for item in installation.profile.artifacts
            if item.id == dependency.artifact_kind
        )
        token = _new_token()
        artifact_targets[artifact.id] = token
        capabilities[token] = _ArtifactCapabilityState(
            artifact.resource_id,
            artifact.id,
            frozenset(dependency.verbs),
        )
    bundle_token = _new_token()
    state = _InvocationState(
        bundle_token,
        installation.profile.id,
        installation.profile.fingerprint,
        declaration.id,
        declaration.scope_id,
        session_binding,
        id(owner_task),
        Future(),
        MappingProxyType(capabilities),
        MappingProxyType(record_targets),
        MappingProxyType(singleton_targets),
        MappingProxyType(artifact_targets),
    )
    _install_invocation(state)
    return ProtectedOperationDependencies(bundle_token)


def expire_operation_dependencies(value: object) -> None:
    token = (
        object.__getattribute__(value, "_token")
        if isinstance(value, ProtectedOperationDependencies)
        else ""
    )
    _expire_invocation(token)


def _lookup_dependency(bundle_token: str, kind: str, target: object) -> str:
    state, capability = _resolve_invocation(bundle_token)
    if capability is not None:
        raise _denied()
    targets = {
        "record": state.record_targets,
        "singleton": state.singleton_targets,
        "artifact": state.artifact_targets,
    }.get(kind)
    token = targets.get(target) if targets is not None else None
    if not isinstance(token, str):
        raise _denied()
    return token


def _require_current_session(state: _InvocationState) -> None:
    from .guard import _session_fingerprint
    from .keystore import keystore_exists, session_token
    from .suite_runtime import require_active_process_suite

    require_active_process_suite()
    if not keystore_exists():
        raise _denied()
    current = session_token()
    if current is None or not hmac.compare_digest(
        state.session_binding,
        hashlib.sha256(_session_fingerprint(current)).digest(),
    ):
        raise _denied()


def _require_current_scope(state: _InvocationState, installation) -> None:
    from .mode_runtime import require_stable_bound_scope

    if (
        installation.profile.id != state.pack_id
        or installation.profile.fingerprint != state.profile_fingerprint
    ):
        raise _denied()
    require_stable_bound_scope(installation, state.scope_id)


def _postcheck(state: _InvocationState, installation) -> None:
    _require_current_session(state)
    resolved, _capability = _resolve_invocation(state.bundle_token)
    if resolved is not state:
        raise _denied()
    from .runtime import bound_privacy_pack

    if bound_privacy_pack(state.pack_id)._installation is not installation:
        raise _denied()
    _require_current_scope(state, installation)


def _dispatch_sync(token: str, action: str, arguments: tuple[object, ...]):
    state, capability = _resolve_invocation(token)
    if action == "record.reveal":
        if not isinstance(capability, _RecordCapabilityState) or len(arguments) != 1:
            raise _denied()
    elif action.startswith("singleton."):
        verb = action.removeprefix("singleton.")
        if (
            not isinstance(capability, _SingletonCapabilityState)
            or verb not in capability.verbs
        ):
            raise _denied()
    else:
        raise _denied()

    _require_current_session(state)
    from .runtime import bound_privacy_pack

    installation = bound_privacy_pack(state.pack_id)._installation
    _require_current_scope(state, installation)
    from .mode_runtime import (
        acquire_bound_mode_work_admission,
        release_bound_mode_work_admission,
    )

    admission = acquire_bound_mode_work_admission(
        installation,
        (state.scope_id,),
    )
    try:
        def authorization_for(operation_id: str):
            from .guard import (
                AuthorizedPrivacyRequest,
                _AUTHORIZED_REQUEST_MARKER,
                _session_fingerprint,
            )
            from .keystore import session_token

            current = session_token()
            if current is None:
                raise _denied()
            fingerprint = _session_fingerprint(current)
            if not hmac.compare_digest(
                state.session_binding,
                hashlib.sha256(fingerprint).digest(),
            ):
                raise _denied()
            return AuthorizedPrivacyRequest(
                operation_id,
                state.pack_id,
                fingerprint,
                None,
                _marker=_AUTHORIZED_REQUEST_MARKER,
            )

        if isinstance(capability, _RecordCapabilityState):
            from .records import reveal_record

            revealed = reveal_record(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                record_kind=capability.record_kind,
                record_id=arguments[0],
                operation=capability.operation,
                authorization=authorization_for(
                    f"record.{capability.operation}"
                ),
            )
            result = copy.deepcopy(revealed.value)
        elif action == "singleton.status":
            from .singletons import singleton_status

            result = singleton_status(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                singleton_id=capability.singleton_id,
            )
        elif action == "singleton.reveal":
            from .singletons import reveal_singleton_blob, reveal_singleton_field

            reveal = (
                reveal_singleton_field
                if capability.payload_kind is SingletonPayloadKind.FIELD
                else reveal_singleton_blob
            )
            result = reveal(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                singleton_id=capability.singleton_id,
                authorization=authorization_for("singleton.reveal"),
            )
        elif action == "singleton.replace" and len(arguments) == 2:
            from .singletons import replace_singleton_blob, replace_singleton_field

            replace_singleton = (
                replace_singleton_field
                if capability.payload_kind is SingletonPayloadKind.FIELD
                else replace_singleton_blob
            )
            result = replace_singleton(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                singleton_id=capability.singleton_id,
                value=arguments[0],
                expected_revision=arguments[1],
                authorization=authorization_for("singleton.replace"),
            )
        elif action == "singleton.delete" and len(arguments) == 1:
            from .singletons import delete_singleton

            result = delete_singleton(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                singleton_id=capability.singleton_id,
                expected_revision=arguments[0],
                authorization=authorization_for("singleton.delete"),
            )
        else:
            raise _denied()
        _postcheck(state, installation)
        return result
    except ProtectedOperationError:
        raise
    except Exception:
        raise _denied() from None
    finally:
        release_bound_mode_work_admission(admission)


async def _dispatch_async(token: str, action: str, arguments: tuple[object, ...]):
    state, capability = _resolve_invocation(token)
    if not isinstance(capability, _ArtifactCapabilityState):
        raise _denied()
    verb = action.removeprefix("artifact.")
    if action == "artifact.lease":
        if len(arguments) != 2 or f"lease.{arguments[1]}" not in capability.verbs:
            raise _denied()
    elif verb not in capability.verbs:
        raise _denied()

    _require_current_session(state)
    from .runtime import bound_privacy_pack

    installation = bound_privacy_pack(state.pack_id)._installation
    _require_current_scope(state, installation)
    from .mode_runtime import (
        acquire_bound_mode_work_admission,
        release_bound_mode_work_admission,
    )

    admission = acquire_bound_mode_work_admission(
        installation,
        (state.scope_id,),
    )
    try:
        if action == "artifact.write" and len(arguments) == 2:
            from .artifacts import write_artifact

            candidate = write_artifact(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                artifact_kind=capability.artifact_kind,
                owner_id=arguments[0],
                value=arguments[1],
            )
        elif action == "artifact.read" and len(arguments) == 1:
            from .artifacts import read_artifact

            candidate = read_artifact(
                installation=installation,
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=capability.resource_id,
                artifact_kind=capability.artifact_kind,
                reference=arguments[0],
            )
        elif action == "artifact.retire" and len(arguments) == 1:
            from .artifacts import retire_artifact

            candidate = retire_artifact(
                profile=installation.profile,
                resource_id=capability.resource_id,
                artifact_kind=capability.artifact_kind,
                reference=arguments[0],
            )
        elif action == "artifact.release-owner" and len(arguments) == 1:
            from .artifacts import release_artifact_owner

            candidate = release_artifact_owner(
                profile=installation.profile,
                resource_id=capability.resource_id,
                artifact_kind=capability.artifact_kind,
                owner_id=arguments[0],
            )
        elif action == "artifact.reconcile-owner" and len(arguments) == 2:
            from .artifacts import reconcile_owner_artifacts

            candidate = reconcile_owner_artifacts(
                installation=installation,
                resource_id=capability.resource_id,
                artifact_kind=capability.artifact_kind,
                owner_id=arguments[0],
                keep=arguments[1],
            )
        elif action == "artifact.lease" and len(arguments) == 2:
            from .artifacts import issue_artifact_lease
            from .guard import (
                AuthorizedPrivacyRequest,
                _AUTHORIZED_REQUEST_MARKER,
                _session_fingerprint,
            )
            from .keystore import session_token

            current = session_token()
            if current is None:
                raise _denied()
            fingerprint = _session_fingerprint(current)
            if not hmac.compare_digest(
                state.session_binding,
                hashlib.sha256(fingerprint).digest(),
            ):
                raise _denied()
            authorization = AuthorizedPrivacyRequest(
                f"artifact.{arguments[1]}",
                state.pack_id,
                fingerprint,
                None,
                _marker=_AUTHORIZED_REQUEST_MARKER,
            )
            candidate = issue_artifact_lease(
                installation=installation,
                profile=installation.profile,
                resource_id=capability.resource_id,
                artifact_kind=capability.artifact_kind,
                reference=arguments[0],
                operation=arguments[1],
                authorization=authorization,
            )
        else:
            raise _denied()
        result = await candidate if inspect.isawaitable(candidate) else candidate
        _postcheck(state, installation)
        return result
    except asyncio.CancelledError:
        raise
    except ProtectedOperationError:
        raise
    except Exception:
        raise _denied() from None
    finally:
        release_bound_mode_work_admission(admission)


__all__ = [
    "ArtifactOperationCapability",
    "ProtectedOperationDependencies",
    "RecordOperationCapability",
    "SingletonOperationCapability",
]
