"""Operator-blind maintenance interface for exact suite installations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from ._suite_codec import is_sha256


class MaintenanceCapabilityError(RuntimeError):
    """Sanitized operator-blind maintenance failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Operator-blind maintenance operation failed.")


@dataclass(frozen=True, slots=True)
class OpaqueObjectReference:
    id: str

    def __post_init__(self) -> None:
        _require_opaque_id(self.id)


@dataclass(frozen=True, slots=True)
class EnvelopeHeader:
    version: int
    algorithm: str
    schema: str
    opaque_key_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise MaintenanceCapabilityError("invalid_envelope_header")
        if any(
            not isinstance(value, str) or not value
            for value in (self.algorithm, self.schema)
        ):
            raise MaintenanceCapabilityError("invalid_envelope_header")
        _require_opaque_id(self.opaque_key_id)


@dataclass(frozen=True, slots=True)
class EncryptedCopyReceipt:
    object_id: str
    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        _require_opaque_id(self.object_id)
        if not is_sha256(self.sha256):
            raise MaintenanceCapabilityError("invalid_copy_digest")
        if (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
        ):
            raise MaintenanceCapabilityError("invalid_copy_size")


class MaintenanceBackend(Protocol):
    def read_envelope_header(self, reference: OpaqueObjectReference) -> Mapping: ...

    def opaque_key_available(self, key_id: str) -> bool: ...

    def copy_encrypted(
        self,
        source: OpaqueObjectReference,
        destination: OpaqueObjectReference,
    ) -> EncryptedCopyReceipt: ...


class MaintenanceInstallationView(Protocol):
    @property
    def manifest(self): ...

    @property
    def report(self): ...


class MaintenanceCapability:
    """Restricted installation maintenance with no reveal-capable interface."""

    __slots__ = ("__installation", "__backend")

    def __init__(
        self,
        installation: MaintenanceInstallationView,
        backend: MaintenanceBackend,
    ) -> None:
        self.__installation = installation
        self.__backend = backend

    def manifest(self):
        return self.__installation.manifest

    def readiness(self):
        return self.__installation.report

    def envelope_header(self, reference: OpaqueObjectReference) -> EnvelopeHeader:
        if not isinstance(reference, OpaqueObjectReference):
            raise MaintenanceCapabilityError("invalid_opaque_reference")
        try:
            raw = self.__backend.read_envelope_header(reference)
            version = raw["version"]
            algorithm = raw["algorithm"]
            schema = raw["schema"]
            key_id = raw["keyId"]
        except Exception:
            raise MaintenanceCapabilityError("envelope_header_unavailable") from None
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise MaintenanceCapabilityError("invalid_envelope_header")
        if any(
            not isinstance(value, str) or not value
            for value in (algorithm, schema, key_id)
        ):
            raise MaintenanceCapabilityError("invalid_envelope_header")
        return EnvelopeHeader(version, algorithm, schema, key_id)

    def opaque_key_available(self, key_id: str) -> bool:
        _require_opaque_id(key_id)
        try:
            available = self.__backend.opaque_key_available(key_id)
        except Exception:
            raise MaintenanceCapabilityError("key_preflight_unavailable") from None
        if not isinstance(available, bool):
            raise MaintenanceCapabilityError("invalid_key_preflight_result")
        return available

    def copy_encrypted(
        self,
        source: OpaqueObjectReference,
        destination: OpaqueObjectReference,
    ) -> EncryptedCopyReceipt:
        if not isinstance(source, OpaqueObjectReference) or not isinstance(
            destination,
            OpaqueObjectReference,
        ):
            raise MaintenanceCapabilityError("invalid_opaque_reference")
        self.envelope_header(source)
        try:
            receipt = self.__backend.copy_encrypted(source, destination)
        except Exception:
            raise MaintenanceCapabilityError("encrypted_copy_failed") from None
        if not isinstance(receipt, EncryptedCopyReceipt):
            raise MaintenanceCapabilityError("invalid_copy_receipt")
        return receipt


def create_maintenance_capability(
    installation: MaintenanceInstallationView,
    backend: MaintenanceBackend,
) -> MaintenanceCapability:
    required_methods = (
        "read_envelope_header",
        "opaque_key_available",
        "copy_encrypted",
    )
    if any(not callable(getattr(backend, method, None)) for method in required_methods):
        raise MaintenanceCapabilityError("invalid_maintenance_backend")
    return MaintenanceCapability(installation, backend)


def _require_opaque_id(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(character.isspace() for character in value)
        or "/" in value
        or "\\" in value
    ):
        raise MaintenanceCapabilityError("invalid_opaque_id")
