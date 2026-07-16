"""Exact installed-suite verification and fail-closed runtime state."""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from threading import RLock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._suite_codec import canonical_json_bytes, is_sha256, is_stable_id, typed_tuple
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
_PROCESS_CONSUMER_DECLARATIONS: list[ConsumerSuiteDeclaration] = []
_PROCESS_BROWSER_MANIFEST_DIGEST: str | None = None
_PROCESS_BROWSER_RENDERER: str | None = None
_PROCESS_BROWSER_CONFLICT = False
_PROCESS_ARTIFACT_FILES: Mapping[str, str | Path] | None = None
_PROCESS_ENVIRONMENTS: Mapping[str, EnvironmentTuple] | None = None


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

    def __post_init__(self) -> None:
        if not is_stable_id(self.distribution) or not is_stable_id(self.suite_id):
            raise SuiteInventoryError("invalid_consumer_suite_declaration")


@dataclass(frozen=True, slots=True)
class InstalledSuiteInventory:
    artifacts: tuple[ArtifactIdentity, ...]
    profiles: tuple[ProfileIdentity, ...]
    environment: EnvironmentTuple
    consumer_declarations: tuple[ConsumerSuiteDeclaration, ...]
    server_manifest_digest: str
    browser_manifest_digest: str | None
    installation_generation: str

    def __post_init__(self) -> None:
        artifacts = typed_tuple(
            self.artifacts,
            ArtifactIdentity,
            "invalid_installed_artifacts",
            SuiteInventoryError,
        )
        profiles = typed_tuple(
            self.profiles,
            ProfileIdentity,
            "invalid_installed_profiles",
            SuiteInventoryError,
        )
        declarations = typed_tuple(
            self.consumer_declarations,
            ConsumerSuiteDeclaration,
            "invalid_consumer_declarations",
            SuiteInventoryError,
        )
        if not isinstance(self.environment, EnvironmentTuple):
            raise SuiteInventoryError("invalid_installed_environment")
        if not is_sha256(self.server_manifest_digest):
            raise SuiteInventoryError("invalid_runtime_manifest_digest")
        if self.browser_manifest_digest is not None and not is_sha256(
            self.browser_manifest_digest
        ):
            raise SuiteInventoryError("invalid_browser_manifest_digest")
        if not is_sha256(self.installation_generation):
            raise SuiteInventoryError("invalid_installation_generation")
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
        self._process_nonce = secrets.token_hex(32)
        self._lock = RLock()
        self._restart_required = False
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

    def verify_installed(
        self,
        *,
        artifact_files: Mapping[str, str | Path],
        environment: EnvironmentTuple,
    ) -> SuiteReadinessReport:
        """Measure installed bytes and live registrations before verification."""

        try:
            inventory = measure_installed_suite(
                self,
                artifact_files=artifact_files,
                environment=environment,
            )
        except SuiteInventoryError:
            with self._lock:
                return self._set_blocked_status(
                    SuiteStatus.CONFLICT,
                    "suite_measurement_failed",
                )
        return self._verify_inventory(inventory)

    def _verify_inventory(
        self,
        inventory: InstalledSuiteInventory,
    ) -> SuiteReadinessReport:
        if not isinstance(inventory, InstalledSuiteInventory):
            with self._lock:
                return self._set_blocked_status(
                    SuiteStatus.CONFLICT,
                    "invalid_inventory",
                )
        with self._lock:
            self._inventory = inventory

            if self._restart_required:
                return self._set_status(
                    SuiteStatus.MISMATCH,
                    "process_restart_required",
                )

            declaration_pairs = {
                declaration.suite_id
                for declaration in inventory.consumer_declarations
            }
            declarations_by_distribution: dict[str, set[str]] = {}
            for declaration in inventory.consumer_declarations:
                declarations_by_distribution.setdefault(
                    declaration.distribution,
                    set(),
                ).add(declaration.suite_id)
            if (
                len(declaration_pairs) > 1
                or any(
                    len(values) > 1
                    for values in declarations_by_distribution.values()
                )
                or _has_identity_conflict(inventory.artifacts, "id")
                or _has_identity_conflict(inventory.profiles, "id")
            ):
                return self._set_blocked_status(
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
                or inventory.browser_manifest_digest is None
            ):
                return self._set_blocked_status(
                    SuiteStatus.INCOMPLETE,
                    "suite_components_missing",
                )

            expected_declarations = {
                ConsumerSuiteDeclaration(
                    distribution=profile.distribution,
                    suite_id=self.manifest.id,
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
                return self._set_blocked_status(
                    SuiteStatus.MISMATCH,
                    "suite_identity_mismatch",
                )

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
                process_nonce=self._process_nonce,
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
            if authorization.process_nonce != request.process_nonce:
                raise SuiteActivationError("activation_process_mismatch")
            verify_activation_authorization(
                authorization,
                self._trusted_activation_keys,
            )
            record = ActivationRecord(
                manifest_digest=authorization.manifest_digest,
                inventory_digest=authorization.inventory_digest,
                process_nonce=authorization.process_nonce,
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
            return self._set_blocked_status(
                SuiteStatus.CONFLICT,
                "activation_record_invalid",
            )
        if record is None or record.manifest_digest != self.manifest.digest:
            return None
        authorization = SignedActivationAuthorization(
            manifest_digest=record.manifest_digest,
            inventory_digest=record.inventory_digest,
            process_nonce=record.process_nonce,
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
            return self._set_blocked_status(
                SuiteStatus.CONFLICT,
                "activation_record_invalid",
            )
        if record.inventory_digest != inventory.digest:
            if self._status is SuiteStatus.ACTIVE:
                return self._set_blocked_status(
                    SuiteStatus.MISMATCH,
                    "activation_inventory_mismatch",
                )
            return self._set_status_after_quarantine(
                SuiteStatus.ACTIVATION_REQUIRED,
                "installation_generation_changed",
            )
        if (
            record.previous_suite_id != self.manifest.previous_suite_id
            or record.rollback is not self.manifest.rollback
        ):
            return self._set_blocked_status(
                SuiteStatus.CONFLICT,
                "rollback_boundary_mismatch",
            )
        if self._status is not SuiteStatus.ACTIVE:
            return self._set_status(
                SuiteStatus.ACTIVATION_REQUIRED,
                "explicit_process_activation_required",
            )
        return self._set_status(SuiteStatus.ACTIVE)

    def _set_blocked_status(
        self,
        status: SuiteStatus,
        issue_code: str,
    ) -> SuiteReadinessReport:
        self._restart_required = True
        return self._set_status_after_quarantine(status, issue_code)

    def _set_status_after_quarantine(
        self,
        status: SuiteStatus,
        issue_code: str,
    ) -> SuiteReadinessReport:
        try:
            self._quarantine_activation_record()
        except SuiteActivationError:
            return self._set_status(
                SuiteStatus.CONFLICT,
                "activation_record_block_failed",
            )
        return self._set_status(status, issue_code)

    def _quarantine_activation_record(self) -> None:
        if self._activation_store is None:
            return
        try:
            record = self._activation_store.load()
            if record is not None and record.manifest_digest == self.manifest.digest:
                self._activation_store.block(record)
        except SuiteActivationError:
            raise
        except Exception:
            raise SuiteActivationError("activation_record_block_failed") from None

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
                }
                for declaration in sorted(
                    inventory.consumer_declarations,
                    key=lambda item: (
                        item.distribution,
                        item.suite_id,
                    ),
                )
            ],
            "serverManifestDigest": inventory.server_manifest_digest,
            "browserManifestDigest": inventory.browser_manifest_digest,
            "installationGeneration": inventory.installation_generation,
        }
    )


def _has_identity_conflict(values, attribute: str) -> bool:
    identities: dict[object, set[object]] = {}
    for value in values:
        identities.setdefault(getattr(value, attribute), set()).add(value)
    return any(len(entries) > 1 for entries in identities.values())


def measure_runtime_environment(
    *,
    comfyui_backend: str,
    comfyui_frontend: str,
    renderer: str,
) -> EnvironmentTuple:
    """Measure the interpreter while binding host-reported ComfyUI identities."""

    return EnvironmentTuple(
        python=platform.python_version(),
        comfyui_backend=comfyui_backend,
        comfyui_frontend=comfyui_frontend,
        renderer=renderer,
    )


def register_consumer_suite_declaration(
    declaration: ConsumerSuiteDeclaration,
) -> ConsumerSuiteDeclaration:
    """Record one consumer's embedded exact-suite declaration idempotently."""

    if not isinstance(declaration, ConsumerSuiteDeclaration):
        raise SuiteInventoryError("invalid_consumer_suite_declaration")
    with _PROCESS_SUITE_LOCK:
        if declaration not in _PROCESS_CONSUMER_DECLARATIONS:
            _PROCESS_CONSUMER_DECLARATIONS.append(declaration)
    return declaration


def record_browser_manifest_attestation(
    manifest_digest: str,
    renderer: str,
) -> str:
    """Record the manifest digest and renderer observed by the browser runtime."""

    global _PROCESS_BROWSER_CONFLICT, _PROCESS_BROWSER_MANIFEST_DIGEST
    global _PROCESS_BROWSER_RENDERER, _PROCESS_SUITE_CONFLICT
    if not is_sha256(manifest_digest) or renderer not in {"legacy", "vue"}:
        raise SuiteInventoryError("invalid_browser_attestation")
    with _PROCESS_SUITE_LOCK:
        if _PROCESS_BROWSER_CONFLICT:
            raise SuiteInventoryError("browser_manifest_conflict")
        if (
            _PROCESS_SUITE_INSTALLATION is not None
            and manifest_digest != _PROCESS_SUITE_INSTALLATION.manifest.digest
        ):
            _PROCESS_BROWSER_CONFLICT = True
            _PROCESS_SUITE_CONFLICT = True
            raise SuiteInventoryError("browser_manifest_conflict")
        if _PROCESS_BROWSER_MANIFEST_DIGEST is None:
            _PROCESS_BROWSER_MANIFEST_DIGEST = manifest_digest
        elif _PROCESS_BROWSER_MANIFEST_DIGEST != manifest_digest:
            _PROCESS_BROWSER_CONFLICT = True
            _PROCESS_SUITE_CONFLICT = True
            raise SuiteInventoryError("browser_manifest_conflict")
        if _PROCESS_BROWSER_RENDERER is None:
            _PROCESS_BROWSER_RENDERER = renderer
        elif _PROCESS_BROWSER_RENDERER != renderer:
            _PROCESS_BROWSER_CONFLICT = True
            _PROCESS_SUITE_CONFLICT = True
            raise SuiteInventoryError("browser_renderer_conflict")
        return manifest_digest


def measure_installed_suite(
    installation: SuiteInstallation,
    *,
    artifact_files: Mapping[str, str | Path],
    environment: EnvironmentTuple,
) -> InstalledSuiteInventory:
    """Hash exact artifacts and read profiles/declarations from live registries."""

    if not isinstance(installation, SuiteInstallation):
        raise SuiteInventoryError("invalid_suite_installation")
    if not isinstance(artifact_files, Mapping):
        raise SuiteInventoryError("invalid_artifact_files")
    expected = {
        artifact.distribution: artifact for artifact in installation.manifest.artifacts
    }
    if set(artifact_files) - set(expected):
        raise SuiteInventoryError("unexpected_artifact_file")

    measured_artifacts = []
    generation_entries = []
    for distribution, artifact in expected.items():
        raw_path = artifact_files.get(distribution)
        if raw_path is None:
            continue
        path = Path(raw_path)
        try:
            if not path.is_file():
                continue
            digest, stat = _measure_file(path)
        except OSError:
            continue
        measured_artifacts.append(
            replace(
                artifact,
                filename=path.name,
                sha256=digest,
            )
        )
        generation_entries.append(
            {
                "distribution": distribution,
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "size": stat.st_size,
                "modifiedNs": stat.st_mtime_ns,
                "changedNs": stat.st_ctime_ns,
            }
        )

    try:
        from .runtime import installed_profile_identities

        profiles = installed_profile_identities()
    except Exception:
        raise SuiteInventoryError("profile_registry_conflict") from None
    with _PROCESS_SUITE_LOCK:
        declarations = tuple(_PROCESS_CONSUMER_DECLARATIONS)
        if _PROCESS_BROWSER_CONFLICT:
            raise SuiteInventoryError("browser_manifest_conflict")
        browser_manifest_digest = _PROCESS_BROWSER_MANIFEST_DIGEST
    return InstalledSuiteInventory(
        artifacts=tuple(measured_artifacts),
        profiles=profiles,
        environment=environment,
        consumer_declarations=declarations,
        server_manifest_digest=installation.manifest.digest,
        browser_manifest_digest=browser_manifest_digest,
        installation_generation=hashlib.sha256(
            canonical_json_bytes(generation_entries)
        ).hexdigest(),
    )


def _measure_file(path: Path) -> tuple[str, os.stat_result]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise SuiteInventoryError("artifact_changed_during_measurement")
    return digest.hexdigest(), after


def register_process_suite(installation: SuiteInstallation) -> SuiteInstallation:
    """Register the one exact suite allowed to gate this Python process."""

    global _PROCESS_SUITE_CONFLICT, _PROCESS_SUITE_INSTALLATION
    if not isinstance(installation, SuiteInstallation):
        raise SuiteBlockedError("invalid_process_suite")
    with _PROCESS_SUITE_LOCK:
        if (
            _PROCESS_SUITE_CONFLICT
            or _PROCESS_BROWSER_CONFLICT
            or (
                _PROCESS_BROWSER_MANIFEST_DIGEST is not None
                and _PROCESS_BROWSER_MANIFEST_DIGEST != installation.manifest.digest
            )
        ):
            _PROCESS_SUITE_CONFLICT = True
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


def configure_process_suite_verification(
    installation: SuiteInstallation,
    *,
    artifact_files: Mapping[str, str | Path],
    environments: tuple[EnvironmentTuple, ...],
) -> SuiteInstallation:
    """Bind product-data-free installed-byte inputs to the one process suite."""

    global _PROCESS_ARTIFACT_FILES, _PROCESS_ENVIRONMENTS, _PROCESS_SUITE_CONFLICT
    if not isinstance(installation, SuiteInstallation):
        raise SuiteBlockedError("invalid_process_suite")
    if not isinstance(artifact_files, Mapping) or not isinstance(environments, tuple):
        raise SuiteBlockedError("invalid_suite_verification_configuration")
    normalized = {
        str(distribution): Path(path)
        for distribution, path in artifact_files.items()
    }
    normalized_environments: dict[str, EnvironmentTuple] = {}
    for environment in environments:
        if not isinstance(environment, EnvironmentTuple):
            raise SuiteBlockedError("invalid_suite_verification_configuration")
        if environment.renderer in normalized_environments:
            raise SuiteBlockedError("invalid_suite_verification_configuration")
        normalized_environments[environment.renderer] = environment
    if not normalized_environments:
        raise SuiteBlockedError("invalid_suite_verification_configuration")
    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_INSTALLATION is not installation:
            _PROCESS_SUITE_CONFLICT = True
            raise SuiteBlockedError("suite_process_conflict")
        if _PROCESS_ARTIFACT_FILES is None:
            _PROCESS_ARTIFACT_FILES = normalized
            _PROCESS_ENVIRONMENTS = normalized_environments
        elif (
            dict(_PROCESS_ARTIFACT_FILES) != normalized
            or dict(_PROCESS_ENVIRONMENTS or {}) != normalized_environments
        ):
            _PROCESS_SUITE_CONFLICT = True
            raise SuiteBlockedError("suite_verification_configuration_conflict")
    return installation


def verify_configured_process_suite() -> SuiteReadinessReport:
    """Measure the configured process suite after browser attestation."""

    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_CONFLICT or _PROCESS_SUITE_INSTALLATION is None:
            raise SuiteBlockedError("suite_incomplete")
        if _PROCESS_ARTIFACT_FILES is None or _PROCESS_ENVIRONMENTS is None:
            raise SuiteBlockedError("suite_verification_not_configured")
        if _PROCESS_BROWSER_RENDERER is None:
            raise SuiteBlockedError("suite_browser_not_attested")
        installation = _PROCESS_SUITE_INSTALLATION
        artifact_files = dict(_PROCESS_ARTIFACT_FILES)
        environment = _PROCESS_ENVIRONMENTS.get(_PROCESS_BROWSER_RENDERER)
        if environment is None:
            raise SuiteBlockedError("suite_renderer_not_configured")
    return installation.verify_installed(
        artifact_files=artifact_files,
        environment=environment,
    )


def process_suite_activation_request() -> ActivationRequest:
    """Return the process-bound request for an exact verified installation."""

    verify_configured_process_suite()
    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_CONFLICT or _PROCESS_SUITE_INSTALLATION is None:
            raise SuiteBlockedError("suite_incomplete")
        installation = _PROCESS_SUITE_INSTALLATION
    return installation.activation_request()


def activate_process_suite(
    authorization: SignedActivationAuthorization,
) -> ActivationRecord:
    """Activate the exact verified process with a trusted signed authorization."""

    verify_configured_process_suite()
    with _PROCESS_SUITE_LOCK:
        if _PROCESS_SUITE_CONFLICT or _PROCESS_SUITE_INSTALLATION is None:
            raise SuiteBlockedError("suite_incomplete")
        installation = _PROCESS_SUITE_INSTALLATION
    return installation.activate(authorization)


def block_process_suite_configuration() -> None:
    """Fail closed after a configured suite record cannot be trusted."""

    global _PROCESS_SUITE_CONFLICT
    with _PROCESS_SUITE_LOCK:
        _PROCESS_SUITE_CONFLICT = True


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
