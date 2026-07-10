"""Exact installed-suite verification and fail-closed runtime state."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._suite_codec import canonical_json_bytes, is_sha256, is_stable_id
from .suite import (
    ArtifactIdentity,
    EnvironmentTuple,
    ProfileIdentity,
    SuiteManifest,
    SuitePublicationStatus,
    VerifiedSuiteRelease,
)
from .suite_activation import (
    ActivationRecord,
    ActivationRecordStore,
    ActivationRequest,
    SignedActivationAuthorization,
    SuiteActivationError,
    verify_activation_authorization,
)
from .suite_maintenance import (
    MaintenanceBackend,
    MaintenanceCapability,
    create_maintenance_capability,
)


_PROCESS_SUITE_LOCK = RLock()
_PROCESS_SUITE_INSTALLATION: SuiteInstallation | None = None
_PROCESS_SUITE_CONFLICT = False


class SuiteStatus(str, Enum):
    CUTOVER_PENDING = "cutover-pending"
    READY = "ready"
    ACTIVATION_REQUIRED = "activation-required"
    ACTIVE = "active"
    INCOMPLETE = "incomplete"
    MISMATCH = "mismatch"
    CONFLICT = "conflict"


class SuiteBlockedError(RuntimeError):
    """Product-data-free suite gate failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy-bearing operations are blocked by suite readiness.")


class SuiteInventoryError(ValueError):
    """Sanitized measured-inventory declaration failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Installed suite inventory is invalid.")


@dataclass(frozen=True, slots=True)
class ConsumerSuiteDeclaration:
    distribution: str
    suite_id: str
    manifest_digest: str

    def __post_init__(self) -> None:
        if not is_stable_id(self.distribution) or not is_stable_id(self.suite_id):
            raise SuiteInventoryError("invalid_consumer_suite_declaration")
        if not is_sha256(self.manifest_digest):
            raise SuiteInventoryError("invalid_consumer_manifest_digest")


@dataclass(frozen=True, slots=True)
class InstalledSuiteInventory:
    artifacts: tuple[ArtifactIdentity, ...]
    profiles: tuple[ProfileIdentity, ...]
    environment: EnvironmentTuple
    consumer_declarations: tuple[ConsumerSuiteDeclaration, ...]
    server_manifest_digest: str
    browser_manifest_digest: str

    def __post_init__(self) -> None:
        artifacts = _inventory_tuple(
            self.artifacts,
            ArtifactIdentity,
            "invalid_installed_artifacts",
        )
        profiles = _inventory_tuple(
            self.profiles,
            ProfileIdentity,
            "invalid_installed_profiles",
        )
        declarations = _inventory_tuple(
            self.consumer_declarations,
            ConsumerSuiteDeclaration,
            "invalid_consumer_declarations",
        )
        if not isinstance(self.environment, EnvironmentTuple):
            raise SuiteInventoryError("invalid_installed_environment")
        if not is_sha256(self.server_manifest_digest) or not is_sha256(
            self.browser_manifest_digest
        ):
            raise SuiteInventoryError("invalid_runtime_manifest_digest")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "profiles", profiles)
        object.__setattr__(self, "consumer_declarations", declarations)

    @property
    def digest(self) -> str:
        return hashlib.sha256(_inventory_canonical_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class SuiteReadinessReport:
    status: SuiteStatus
    manifest_digest: str
    issue_codes: tuple[str, ...]


class SuiteInstallation:
    """One loaded signed suite and its exact local verification state."""

    def __init__(
        self,
        release: VerifiedSuiteRelease,
        *,
        activation_store: ActivationRecordStore | None = None,
        trusted_activation_keys: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        if not isinstance(release, VerifiedSuiteRelease):
            raise SuiteBlockedError("invalid_verified_suite_release")
        self._release = release
        self._activation_store = activation_store
        self._trusted_activation_keys = dict(trusted_activation_keys or {})
        self._lock = RLock()
        self._status = (
            SuiteStatus.CUTOVER_PENDING
            if release.status is SuitePublicationStatus.CUTOVER_PENDING
            else SuiteStatus.READY
        )
        self._inventory: InstalledSuiteInventory | None = None
        self._report = SuiteReadinessReport(
            self._status,
            release.manifest.digest,
            ("installation_verification_required",),
        )

    @property
    def status(self) -> SuiteStatus:
        with self._lock:
            return self._status

    @property
    def report(self) -> SuiteReadinessReport:
        with self._lock:
            return self._report

    @property
    def manifest(self) -> SuiteManifest:
        return self._release.manifest

    def verify(self, inventory: InstalledSuiteInventory) -> SuiteReadinessReport:
        if not isinstance(inventory, InstalledSuiteInventory):
            with self._lock:
                return self._set_status(SuiteStatus.CONFLICT, "invalid_inventory")
        with self._lock:
            self._inventory = inventory

            declaration_pairs = {
                (declaration.suite_id, declaration.manifest_digest)
                for declaration in inventory.consumer_declarations
            }
            declarations_by_distribution: dict[str, set[tuple[str, str]]] = {}
            for declaration in inventory.consumer_declarations:
                declarations_by_distribution.setdefault(
                    declaration.distribution,
                    set(),
                ).add((declaration.suite_id, declaration.manifest_digest))
            if (
                len(declaration_pairs) > 1
                or any(
                    len(values) > 1
                    for values in declarations_by_distribution.values()
                )
                or _has_identity_conflict(inventory.artifacts, "id")
                or _has_identity_conflict(inventory.profiles, "id")
            ):
                return self._set_status(
                    SuiteStatus.CONFLICT,
                    "conflicting_suite_declarations",
                )

            expected_artifact_ids = {artifact.id for artifact in self.manifest.artifacts}
            installed_artifact_ids = {artifact.id for artifact in inventory.artifacts}
            expected_profile_ids = {profile.id for profile in self.manifest.profiles}
            installed_profile_ids = {profile.id for profile in inventory.profiles}
            expected_distributions = {
                profile.distribution for profile in self.manifest.profiles
            }
            installed_distributions = set(declarations_by_distribution)
            if (
                expected_artifact_ids - installed_artifact_ids
                or expected_profile_ids - installed_profile_ids
                or expected_distributions - installed_distributions
            ):
                return self._set_status(SuiteStatus.INCOMPLETE, "suite_components_missing")

            expected_declarations = {
                ConsumerSuiteDeclaration(
                    distribution=profile.distribution,
                    suite_id=self.manifest.id,
                    manifest_digest=self.manifest.digest,
                )
                for profile in self.manifest.profiles
            }
            if (
                len(inventory.artifacts) != len(self.manifest.artifacts)
                or len(inventory.profiles) != len(self.manifest.profiles)
                or len(inventory.consumer_declarations) != len(self.manifest.profiles)
                or set(inventory.artifacts) != set(self.manifest.artifacts)
                or set(inventory.profiles) != set(self.manifest.profiles)
                or inventory.environment not in self.manifest.environments
                or set(inventory.consumer_declarations) != expected_declarations
                or inventory.server_manifest_digest != self.manifest.digest
                or inventory.browser_manifest_digest != self.manifest.digest
            ):
                return self._set_status(SuiteStatus.MISMATCH, "suite_identity_mismatch")

            if self._release.status is SuitePublicationStatus.CUTOVER_PENDING:
                return self._set_status(SuiteStatus.CUTOVER_PENDING, "suite_not_promoted")
            activation_status = self._stored_activation_status(inventory)
            if activation_status is not None:
                return activation_status
            return self._set_status(
                SuiteStatus.ACTIVATION_REQUIRED,
                "explicit_activation_required",
            )

    def require_active(self) -> None:
        status = self.status
        if status is not SuiteStatus.ACTIVE:
            raise SuiteBlockedError(f"suite_{status.value.replace('-', '_')}")

    def maintenance_capability(
        self,
        backend: MaintenanceBackend,
    ) -> MaintenanceCapability:
        return create_maintenance_capability(self, backend)

    def activation_request(self) -> ActivationRequest:
        with self._lock:
            if (
                self._status is not SuiteStatus.ACTIVATION_REQUIRED
                or self._inventory is None
            ):
                raise SuiteActivationError("suite_not_activation_ready")
            return ActivationRequest(
                manifest_digest=self.manifest.digest,
                inventory_digest=self._inventory.digest,
                previous_suite_id=self.manifest.previous_suite_id,
                rollback=self.manifest.rollback,
            )

    def activate(
        self,
        authorization: SignedActivationAuthorization,
    ) -> ActivationRecord:
        with self._lock:
            request = self.activation_request()
            if self._activation_store is None:
                raise SuiteActivationError("activation_store_unavailable")
            if authorization.manifest_digest != request.manifest_digest:
                raise SuiteActivationError("activation_manifest_mismatch")
            if authorization.inventory_digest != request.inventory_digest:
                raise SuiteActivationError("activation_inventory_mismatch")
            verify_activation_authorization(
                authorization,
                self._trusted_activation_keys,
            )
            record = ActivationRecord(
                manifest_digest=authorization.manifest_digest,
                inventory_digest=authorization.inventory_digest,
                pre_activation_snapshot_digest=(
                    authorization.pre_activation_snapshot_digest
                ),
                authorization_id=authorization.authorization_id,
                activated_at=authorization.authorized_at,
                signer_key_id=authorization.signer_key_id,
                authorization_signature=authorization.signature,
                previous_suite_id=request.previous_suite_id,
                rollback=request.rollback,
            )
            try:
                self._activation_store.commit(record)
                stored = self._activation_store.load()
            except SuiteActivationError:
                raise
            except Exception:
                raise SuiteActivationError("activation_record_commit_failed") from None
            if stored != record:
                raise SuiteActivationError("activation_record_readback_mismatch")
            self._status = SuiteStatus.ACTIVE
            self._report = SuiteReadinessReport(
                status=SuiteStatus.ACTIVE,
                manifest_digest=self.manifest.digest,
                issue_codes=(),
            )
            return record

    def _stored_activation_status(
        self,
        inventory: InstalledSuiteInventory,
    ) -> SuiteReadinessReport | None:
        if self._activation_store is None:
            return None
        try:
            record = self._activation_store.load()
        except SuiteActivationError:
            return self._set_status(SuiteStatus.CONFLICT, "activation_record_invalid")
        if record is None or record.manifest_digest != self.manifest.digest:
            return None
        if record.inventory_digest != inventory.digest:
            return self._set_status(SuiteStatus.MISMATCH, "activation_inventory_mismatch")
        authorization = SignedActivationAuthorization(
            manifest_digest=record.manifest_digest,
            inventory_digest=record.inventory_digest,
            pre_activation_snapshot_digest=record.pre_activation_snapshot_digest,
            authorization_id=record.authorization_id,
            authorized_at=record.activated_at,
            signer_key_id=record.signer_key_id,
            signature=record.authorization_signature,
        )
        try:
            verify_activation_authorization(
                authorization,
                self._trusted_activation_keys,
            )
        except SuiteActivationError:
            return self._set_status(SuiteStatus.CONFLICT, "activation_record_invalid")
        if (
            record.previous_suite_id != self.manifest.previous_suite_id
            or record.rollback is not self.manifest.rollback
        ):
            return self._set_status(SuiteStatus.CONFLICT, "rollback_boundary_mismatch")
        return self._set_status(SuiteStatus.ACTIVE)

    def _set_status(
        self,
        status: SuiteStatus,
        issue_code: str | None = None,
    ) -> SuiteReadinessReport:
        self._status = status
        self._report = SuiteReadinessReport(
            status=status,
            manifest_digest=self.manifest.digest,
            issue_codes=((issue_code,) if issue_code else ()),
        )
        return self._report


def _inventory_canonical_bytes(inventory: InstalledSuiteInventory) -> bytes:
    return canonical_json_bytes(
        {
            "artifacts": [
                {
                    "id": artifact.id,
                    "distribution": artifact.distribution,
                    "version": artifact.version,
                    "filename": artifact.filename,
                    "sha256": artifact.sha256,
                    "sourceRepository": artifact.source.repository,
                    "sourceRevision": artifact.source.revision,
                    "sourceTag": artifact.source.tag,
                }
                for artifact in sorted(inventory.artifacts, key=lambda item: item.id)
            ],
            "profiles": [
                {
                    "id": profile.id,
                    "distribution": profile.distribution,
                    "fingerprint": profile.fingerprint,
                }
                for profile in sorted(inventory.profiles, key=lambda item: item.id)
            ],
            "environment": {
                "python": inventory.environment.python,
                "comfyuiBackend": inventory.environment.comfyui_backend,
                "comfyuiFrontend": inventory.environment.comfyui_frontend,
                "renderer": inventory.environment.renderer,
            },
            "consumerDeclarations": [
                {
                    "distribution": declaration.distribution,
                    "suiteId": declaration.suite_id,
                    "manifestDigest": declaration.manifest_digest,
                }
                for declaration in sorted(
                    inventory.consumer_declarations,
                    key=lambda item: (
                        item.distribution,
                        item.suite_id,
                        item.manifest_digest,
                    ),
                )
            ],
            "serverManifestDigest": inventory.server_manifest_digest,
            "browserManifestDigest": inventory.browser_manifest_digest,
        }
    )


def _inventory_tuple(values, expected_type, error_code):
    if isinstance(values, (str, bytes)):
        raise SuiteInventoryError(error_code)
    try:
        normalized = tuple(values)
    except TypeError:
        raise SuiteInventoryError(error_code) from None
    if any(not isinstance(item, expected_type) for item in normalized):
        raise SuiteInventoryError(error_code)
    return normalized


def _has_identity_conflict(values, attribute: str) -> bool:
    identities: dict[object, set[object]] = {}
    for value in values:
        identities.setdefault(getattr(value, attribute), set()).add(value)
    return any(len(entries) > 1 for entries in identities.values())


def register_process_suite(installation: SuiteInstallation) -> SuiteInstallation:
    """Register the one exact suite allowed to gate this Python process."""

    global _PROCESS_SUITE_CONFLICT, _PROCESS_SUITE_INSTALLATION
    if not isinstance(installation, SuiteInstallation):
        raise SuiteBlockedError("invalid_process_suite")
    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_CONFLICT:
            raise SuiteBlockedError("suite_process_conflict")
        if _PROCESS_SUITE_INSTALLATION is None:
            _PROCESS_SUITE_INSTALLATION = installation
            return installation
        if (
            _PROCESS_SUITE_INSTALLATION.manifest.digest
            != installation.manifest.digest
        ):
            _PROCESS_SUITE_CONFLICT = True
            raise SuiteBlockedError("suite_process_conflict")
        return _PROCESS_SUITE_INSTALLATION


def require_active_process_suite() -> SuiteInstallation:
    """Return the active suite or block every privacy-bearing caller."""

    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_CONFLICT:
            raise SuiteBlockedError("suite_conflict")
        if _PROCESS_SUITE_INSTALLATION is None:
            raise SuiteBlockedError("suite_incomplete")
        _PROCESS_SUITE_INSTALLATION.require_active()
        return _PROCESS_SUITE_INSTALLATION


def process_suite_status_payload() -> dict[str, object]:
    """Product-data-free readiness suitable for canonical status routes."""

    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_CONFLICT:
            return {
                "suiteStatus": SuiteStatus.CONFLICT.value,
                "suiteManifestDigest": None,
                "suiteIssueCodes": ["conflicting_suite_manifests"],
            }
        if _PROCESS_SUITE_INSTALLATION is None:
            return {
                "suiteStatus": SuiteStatus.INCOMPLETE.value,
                "suiteManifestDigest": None,
                "suiteIssueCodes": ["suite_not_configured"],
            }
        report = _PROCESS_SUITE_INSTALLATION.report
        return {
            "suiteStatus": report.status.value,
            "suiteManifestDigest": report.manifest_digest,
            "suiteIssueCodes": list(report.issue_codes),
        }
