"""Atomic compiler for immutable consumer privacy profiles."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, TypeVar

from .comfy_ui import register_helto_privacy_ui
from .profile import PrivacyProfile, ProfileResource, ResourceKind


class PrivacyInstallationError(RuntimeError):
    """A stable, product-data-free installation failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class AdapterBindingError(PrivacyInstallationError):
    def __init__(self, code: str) -> None:
        super().__init__(code, "Privacy profile adapters are incomplete or invalid.")


class ProfileConflictError(PrivacyInstallationError):
    def __init__(self, code: str) -> None:
        super().__init__(code, "Conflicting privacy profile installation blocked.")


class PackBlockedError(PrivacyInstallationError):
    def __init__(self, code: str = "privacy_pack_blocked") -> None:
        super().__init__(code, "Privacy operations are blocked until installation is repaired.")


class UnknownResourceError(PrivacyInstallationError):
    def __init__(self) -> None:
        super().__init__("unknown_resource", "Requested privacy resource is not declared.")


class InstallationStatus(str, Enum):
    WAITING_FOR_PROMPT_SERVER = "waiting_for_prompt_server"
    READY = "ready"
    CONFLICT = "conflict"


@dataclass(slots=True)
class _Installation:
    profile: PrivacyProfile
    adapters: Mapping[str, object] = field(repr=False)
    status: InstallationStatus = InstallationStatus.WAITING_FOR_PROMPT_SERVER
    pack: BoundPrivacyPack | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ReadinessHandle:
    """Read-only installation readiness; it cannot reveal product data."""

    _installation: _Installation = field(repr=False, compare=False)

    @property
    def state(self) -> str:
        return self._installation.status.value

    def require_ready(self) -> None:
        if self.state != "ready":
            raise PackBlockedError(f"privacy_pack_{self.state}")


@dataclass(frozen=True, slots=True)
class AuthorizationHandle:
    """Typed authorization seam without credentials or token access."""

    _installation: _Installation = field(repr=False, compare=False)

    @property
    def pack_id(self) -> str:
        return self._installation.profile.id

    def require_ready(self) -> None:
        ReadinessHandle(self._installation).require_ready()
        from .suite_runtime import require_active_process_suite

        require_active_process_suite()


@dataclass(frozen=True, slots=True)
class _ResourceHandle:
    pack_id: str
    resource_id: str
    _installation: _Installation = field(repr=False, compare=False)
    _adapters: Mapping[str, object] = field(repr=False, compare=False)

    @property
    def readiness(self) -> ReadinessHandle:
        return ReadinessHandle(self._installation)


@dataclass(frozen=True, slots=True)
class ModeHandle(_ResourceHandle):
    pass


@dataclass(frozen=True, slots=True)
class WorkflowHandle(_ResourceHandle):
    pass


@dataclass(frozen=True, slots=True)
class RecordHandle(_ResourceHandle):
    pass


@dataclass(frozen=True, slots=True)
class ArtifactHandle(_ResourceHandle):
    pass


@dataclass(frozen=True, slots=True)
class ExecutionHandle(_ResourceHandle):
    pass


_Handle = TypeVar("_Handle", bound=_ResourceHandle)


@dataclass(frozen=True, slots=True)
class BoundPrivacyPack:
    """Immutable typed façade produced only by a complete installation."""

    _installation: _Installation = field(repr=False, compare=False)

    @property
    def profile(self) -> PrivacyProfile:
        return self._installation.profile

    @property
    def fingerprint(self) -> str:
        return self.profile.fingerprint

    @property
    def readiness(self) -> ReadinessHandle:
        return ReadinessHandle(self._installation)

    @property
    def authorization(self) -> AuthorizationHandle:
        return AuthorizationHandle(self._installation)

    def mode(self, resource_id: str) -> ModeHandle:
        return self._resource(resource_id, ResourceKind.MODE, ModeHandle)

    def workflow(self, resource_id: str) -> WorkflowHandle:
        return self._resource(resource_id, ResourceKind.WORKFLOW, WorkflowHandle)

    def records(self, resource_id: str) -> RecordHandle:
        return self._resource(resource_id, ResourceKind.RECORD, RecordHandle)

    def artifacts(self, resource_id: str) -> ArtifactHandle:
        return self._resource(resource_id, ResourceKind.ARTIFACT, ArtifactHandle)

    def execution(self, resource_id: str) -> ExecutionHandle:
        return self._resource(resource_id, ResourceKind.EXECUTION, ExecutionHandle)

    def _resource(
        self,
        resource_id: str,
        expected_kind: ResourceKind,
        handle_type: type[_Handle],
    ) -> _Handle:
        if self._installation.status is InstallationStatus.CONFLICT:
            raise PackBlockedError()
        resource = next(
            (
                item
                for item in self.profile.resources
                if item.id == resource_id and item.kind is expected_kind
            ),
            None,
        )
        if resource is None:
            raise UnknownResourceError()
        adapters = _adapters_for_resource(self._installation, resource)
        return handle_type(self.profile.id, resource.id, self._installation, adapters)


_LOCK = RLock()
_INSTALLATIONS: dict[str, _Installation] = {}


def install(
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
) -> BoundPrivacyPack:
    """Atomically validate, bind, and install one complete privacy profile."""

    bound_adapters = _validate_adapter_bindings(profile, adapters)
    with _LOCK:
        existing = _INSTALLATIONS.get(profile.id)
        if existing is not None:
            if existing.status is InstallationStatus.CONFLICT:
                raise ProfileConflictError("profile_installation_blocked")
            if existing.profile.fingerprint != profile.fingerprint:
                existing.status = InstallationStatus.CONFLICT
                raise ProfileConflictError("profile_fingerprint_conflict")
            if existing.pack is None:  # Defensive invariant; never expose a partial pack.
                existing.status = InstallationStatus.CONFLICT
                raise ProfileConflictError("incomplete_installation")
            return existing.pack

        installation = _Installation(
            profile=profile,
            adapters=MappingProxyType(bound_adapters),
        )
        pack = BoundPrivacyPack(installation)
        installation.pack = pack
        _INSTALLATIONS[profile.id] = installation

    reconcile_prompt_server()
    return pack


def reconcile_prompt_server(prompt_server: Any = None) -> bool:
    """Attach shared routes when PromptServer exists and reconcile all packs."""

    try:
        registered = register_helto_privacy_ui(prompt_server=prompt_server)
    except Exception:  # noqa: BLE001 - optional host timing must not create a partial install.
        return False
    if not registered:
        return False
    with _LOCK:
        for installation in _INSTALLATIONS.values():
            if installation.status is not InstallationStatus.CONFLICT:
                installation.status = InstallationStatus.READY
    return True


def profile_attestation(pack_id: str) -> dict[str, object]:
    """Return only safe declaration identity for browser attestation."""

    with _LOCK:
        installation = _INSTALLATIONS.get(pack_id)
        if installation is None:
            raise PackBlockedError("privacy_pack_missing")
        profile = installation.profile
        result = {
            "id": profile.id,
            "distribution": profile.distribution,
            "contract": profile.contract,
            "fingerprint": profile.fingerprint,
            "status": installation.status.value,
            "requiredBrowserAdapters": [
                {
                    "id": slot.id,
                    "nodeTypes": list(slot.node_types),
                    "methods": list(profile.browser_adapter_contracts[slot.id]),
                }
                for slot in profile.browser_adapters
            ],
            "resources": [
                {"id": resource.id, "kind": resource.kind.value}
                for resource in profile.resources
            ],
        }
    from .suite_runtime import process_suite_status_payload

    return {**result, **process_suite_status_payload()}


def _validate_adapter_bindings(
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
) -> dict[str, object]:
    try:
        supplied = dict(adapters)
    except Exception:  # noqa: BLE001 - consumer mappings must fail with sanitized diagnostics.
        raise AdapterBindingError("invalid_adapters") from None

    expected = {slot.id for slot in profile.server_adapters}
    supplied_ids = set(supplied)
    if expected - supplied_ids or any(supplied.get(slot_id) is None for slot_id in expected):
        raise AdapterBindingError("missing_adapter")
    if supplied_ids - expected:
        raise AdapterBindingError("unknown_adapter")
    for adapter_id, methods in profile.server_adapter_contracts.items():
        adapter = supplied[adapter_id]
        if any(not callable(getattr(adapter, method, None)) for method in methods):
            raise AdapterBindingError("adapter_contract_mismatch")
    return {slot_id: supplied[slot_id] for slot_id in sorted(expected)}


def _adapters_for_resource(
    installation: _Installation,
    resource: ProfileResource,
) -> Mapping[str, object]:
    server_slot_ids = {slot.id for slot in installation.profile.server_adapters}
    matches = [slot_id for slot_id in resource.adapter_slots if slot_id in server_slot_ids]
    return MappingProxyType(
        {slot_id: installation.adapters[slot_id] for slot_id in matches}
    )
