"""Immutable consumer privacy profiles and canonical fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum


PRIVACY_CONTRACT_V2 = "helto.privacy.v2"
_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ProfileValidationError(ValueError):
    """A sanitized declaration error safe to expose during startup."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy profile declaration is invalid.")


class ResourceKind(str, Enum):
    """Closed resource vocabulary exposed by the privacy contract suite."""

    MODE = "mode"
    WORKFLOW = "workflow"
    RECORD = "record"
    ARTIFACT = "artifact"
    EXECUTION = "execution"


@dataclass(frozen=True, slots=True)
class AdapterSlot:
    """One consumer product adapter required by an immutable profile."""

    id: str
    capability: ResourceKind
    resource_id: str
    node_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.resource_id)
        if not isinstance(self.capability, ResourceKind):
            raise ProfileValidationError("unknown_resource_kind")
        try:
            node_types = tuple(self.node_types)
        except TypeError:
            raise ProfileValidationError("invalid_node_types") from None
        if any(not isinstance(item, str) or not item.strip() for item in node_types):
            raise ProfileValidationError("invalid_node_type")
        if len(node_types) != len(set(node_types)):
            raise ProfileValidationError("duplicate_node_type")
        object.__setattr__(self, "node_types", tuple(sorted(node_types)))


@dataclass(frozen=True, slots=True)
class ProfileResource:
    """A declared privacy resource and the adapter slots that place it."""

    id: str
    kind: ResourceKind
    adapter_slots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        if not isinstance(self.kind, ResourceKind):
            raise ProfileValidationError("unknown_resource_kind")
        try:
            adapter_slots = tuple(self.adapter_slots)
        except TypeError:
            raise ProfileValidationError("invalid_adapter_references") from None
        if any(not _is_stable_id(item) for item in adapter_slots):
            raise ProfileValidationError("invalid_stable_id")
        if len(adapter_slots) != len(set(adapter_slots)):
            raise ProfileValidationError("duplicate_adapter_reference")
        object.__setattr__(self, "adapter_slots", tuple(sorted(adapter_slots)))


@dataclass(frozen=True, slots=True)
class PrivacyProfile:
    """All product facts needed to bind one consumer to the fixed contract."""

    id: str
    distribution: str
    contract: str = PRIVACY_CONTRACT_V2
    resources: tuple[ProfileResource, ...] = ()
    server_adapters: tuple[AdapterSlot, ...] = ()
    browser_adapters: tuple[AdapterSlot, ...] = ()

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.distribution)
        try:
            resources = tuple(self.resources)
            server_adapters = tuple(self.server_adapters)
            browser_adapters = tuple(self.browser_adapters)
        except TypeError:
            raise ProfileValidationError("invalid_profile_declaration") from None
        if any(not isinstance(item, ProfileResource) for item in resources):
            raise ProfileValidationError("unknown_resource_declaration")
        if any(not isinstance(item, AdapterSlot) for item in server_adapters + browser_adapters):
            raise ProfileValidationError("unknown_adapter_declaration")
        object.__setattr__(
            self,
            "resources",
            tuple(sorted(resources, key=lambda item: (item.kind.value, item.id))),
        )
        object.__setattr__(
            self,
            "server_adapters",
            tuple(sorted(server_adapters, key=lambda item: item.id)),
        )
        object.__setattr__(
            self,
            "browser_adapters",
            tuple(sorted(browser_adapters, key=lambda item: item.id)),
        )
        self._validate()

    def _validate(self) -> None:
        if self.contract != PRIVACY_CONTRACT_V2:
            raise ProfileValidationError("contract_mismatch")

        resource_ids = [resource.id for resource in self.resources]
        if len(resource_ids) != len(set(resource_ids)):
            raise ProfileValidationError("duplicate_resource")

        adapters = self.server_adapters + self.browser_adapters
        adapter_ids = [adapter.id for adapter in adapters]
        if len(adapter_ids) != len(set(adapter_ids)):
            raise ProfileValidationError("duplicate_adapter_slot")

        adapter_by_id = {adapter.id: adapter for adapter in adapters}
        resource_by_id = {resource.id: resource for resource in self.resources}
        for resource in self.resources:
            if any(slot_id not in adapter_by_id for slot_id in resource.adapter_slots):
                raise ProfileValidationError("unknown_adapter_slot")

        for adapter in adapters:
            resource = resource_by_id.get(adapter.resource_id)
            if resource is None:
                raise ProfileValidationError("unknown_adapter_resource")
            if adapter.capability is not resource.kind:
                raise ProfileValidationError("adapter_capability_mismatch")
            if adapter.id not in resource.adapter_slots:
                raise ProfileValidationError("unbound_adapter_slot")

        if not self.resources or any(not resource.adapter_slots for resource in self.resources):
            raise ProfileValidationError("partial_profile")

    @property
    def fingerprint(self) -> str:
        """Return the stable SHA-256 identity shared by Python and the browser."""

        canonical = json.dumps(
            self._canonical_value(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _canonical_value(self) -> dict[str, object]:
        return {
            "id": self.id,
            "distribution": self.distribution,
            "contract": self.contract,
            "resources": [
                {
                    "id": resource.id,
                    "kind": resource.kind.value,
                    "adapterSlots": list(resource.adapter_slots),
                }
                for resource in self.resources
            ],
            "serverAdapters": [_canonical_adapter(slot) for slot in self.server_adapters],
            "browserAdapters": [_canonical_adapter(slot) for slot in self.browser_adapters],
        }


def _canonical_adapter(slot: AdapterSlot) -> dict[str, object]:
    return {
        "id": slot.id,
        "capability": slot.capability.value,
        "resourceId": slot.resource_id,
        "nodeTypes": list(slot.node_types),
    }


def _is_stable_id(value: object) -> bool:
    return isinstance(value, str) and bool(_STABLE_ID.fullmatch(value))


def _validate_stable_id(value: object) -> None:
    if not _is_stable_id(value):
        raise ProfileValidationError("invalid_stable_id")
