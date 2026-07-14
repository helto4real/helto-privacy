"""Exact supported-suite manifests, verification, and activation."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._suite_codec import (
    canonical_json_bytes,
    is_sha256,
    is_stable_id,
    is_utc_timestamp,
    sign_canonical_record,
    typed_tuple,
    verify_canonical_record_signature,
)
from .profile import PRIVACY_CONTRACT_V3


PRIVACY_SUITE_MANIFEST_V1 = "helto.privacy.suite.v1"
_HEX_40_TO_64 = re.compile(r"^[0-9a-f]{40,64}$")
_MANIFEST_SIGNATURE_DOMAIN = b"helto.privacy.suite-manifest.v1\x00"
_PROMOTION_SIGNATURE_DOMAIN = b"helto.privacy.suite-promotion.v1\x00"
_VERIFIED_RELEASE_MARKER = object()


class SuiteManifestError(ValueError):
    """Sanitized immutable manifest declaration failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Suite manifest declaration is invalid.")


class SuiteSignatureError(ValueError):
    """Sanitized signature verification failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Suite signature verification failed.")


class RollbackClass(str, Enum):
    DATA_SNAPSHOT_REQUIRED_AFTER_ACTIVATION = "data-snapshot-required-after-activation"


class SuitePublicationStatus(str, Enum):
    CUTOVER_PENDING = "cutover-pending"
    READY = "ready"


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    repository: str
    revision: str
    tag: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise SuiteManifestError("invalid_source_repository")
        if not isinstance(self.revision, str) or not _HEX_40_TO_64.fullmatch(self.revision):
            raise SuiteManifestError("invalid_source_revision")
        if self.tag is not None and (not isinstance(self.tag, str) or not self.tag.strip()):
            raise SuiteManifestError("invalid_source_tag")


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    id: str
    distribution: str
    version: str
    filename: str
    sha256: str
    source: SourceIdentity

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.distribution)
        if not isinstance(self.version, str) or not self.version.strip():
            raise SuiteManifestError("invalid_artifact_version")
        if (
            not isinstance(self.filename, str)
            or not self.filename.strip()
            or "/" in self.filename
            or "\\" in self.filename
        ):
            raise SuiteManifestError("invalid_artifact_filename")
        _validate_sha256(self.sha256)
        if not isinstance(self.source, SourceIdentity):
            raise SuiteManifestError("invalid_source_identity")


@dataclass(frozen=True, slots=True)
class ProfileIdentity:
    id: str
    distribution: str
    fingerprint: str

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        _validate_stable_id(self.distribution)
        _validate_sha256(self.fingerprint)


@dataclass(frozen=True, slots=True)
class EnvironmentTuple:
    python: str
    comfyui_backend: str
    comfyui_frontend: str
    renderer: str

    def __post_init__(self) -> None:
        for value in (self.python, self.comfyui_backend, self.comfyui_frontend):
            if not isinstance(value, str) or not value.strip():
                raise SuiteManifestError("invalid_environment_identity")
        if self.renderer not in {"legacy", "vue"}:
            raise SuiteManifestError("unknown_renderer")


@dataclass(frozen=True, slots=True)
class AcceptanceEvidence:
    run_id: str
    evidence_sha256: str
    catalog_sha256: str

    def __post_init__(self) -> None:
        _validate_stable_id(self.run_id)
        _validate_sha256(self.evidence_sha256)
        _validate_sha256(self.catalog_sha256)


@dataclass(frozen=True, slots=True)
class SuiteManifest:
    id: str
    artifacts: tuple[ArtifactIdentity, ...]
    profiles: tuple[ProfileIdentity, ...]
    environments: tuple[EnvironmentTuple, ...]
    acceptance: AcceptanceEvidence
    previous_suite_id: str | None
    rollback: RollbackClass
    schema: str = PRIVACY_SUITE_MANIFEST_V1
    contract: str = PRIVACY_CONTRACT_V3

    def __post_init__(self) -> None:
        _validate_stable_id(self.id)
        if self.previous_suite_id is not None:
            _validate_stable_id(self.previous_suite_id)
        if self.schema != PRIVACY_SUITE_MANIFEST_V1:
            raise SuiteManifestError("suite_schema_mismatch")
        if self.contract != PRIVACY_CONTRACT_V3:
            raise SuiteManifestError("privacy_contract_mismatch")
        if not isinstance(self.acceptance, AcceptanceEvidence):
            raise SuiteManifestError("invalid_acceptance_evidence")
        if not isinstance(self.rollback, RollbackClass):
            raise SuiteManifestError("invalid_rollback_class")

        artifacts = typed_tuple(
            self.artifacts,
            ArtifactIdentity,
            "invalid_artifact_identity",
            SuiteManifestError,
        )
        profiles = typed_tuple(
            self.profiles,
            ProfileIdentity,
            "invalid_profile_identity",
            SuiteManifestError,
        )
        environments = typed_tuple(
            self.environments,
            EnvironmentTuple,
            "invalid_environment_tuple",
            SuiteManifestError,
        )
        if len(artifacts) != 5:
            raise SuiteManifestError("suite_artifact_count_mismatch")
        if len(profiles) != 4:
            raise SuiteManifestError("suite_profile_count_mismatch")
        if not environments:
            raise SuiteManifestError("missing_environment_tuple")
        _require_unique(artifacts, "id", "duplicate_artifact_id")
        _require_unique(artifacts, "distribution", "duplicate_distribution")
        _require_unique(profiles, "id", "duplicate_profile_id")
        _require_unique(profiles, "distribution", "duplicate_profile_distribution")
        _require_unique(environments, None, "duplicate_environment_tuple")
        artifact_distributions = {artifact.distribution for artifact in artifacts}
        if any(profile.distribution not in artifact_distributions for profile in profiles):
            raise SuiteManifestError("unknown_profile_distribution")

        object.__setattr__(self, "artifacts", tuple(sorted(artifacts, key=lambda item: item.id)))
        object.__setattr__(self, "profiles", tuple(sorted(profiles, key=lambda item: item.id)))
        object.__setattr__(
            self,
            "environments",
            tuple(
                sorted(
                    environments,
                    key=lambda item: (
                        item.python,
                        item.comfyui_backend,
                        item.comfyui_frontend,
                        item.renderer,
                    ),
                )
            ),
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def canonical_bytes(self) -> bytes:
        value = {
            "id": self.id,
            "schema": self.schema,
            "contract": self.contract,
            "artifacts": [
                {
                    "id": artifact.id,
                    "distribution": artifact.distribution,
                    "version": artifact.version,
                    "filename": artifact.filename,
                    "sha256": artifact.sha256,
                    "source": {
                        "repository": artifact.source.repository,
                        "revision": artifact.source.revision,
                        "tag": artifact.source.tag,
                    },
                }
                for artifact in self.artifacts
            ],
            "profiles": [
                {
                    "id": profile.id,
                    "distribution": profile.distribution,
                    "fingerprint": profile.fingerprint,
                }
                for profile in self.profiles
            ],
            "environments": [
                {
                    "python": environment.python,
                    "comfyuiBackend": environment.comfyui_backend,
                    "comfyuiFrontend": environment.comfyui_frontend,
                    "renderer": environment.renderer,
                }
                for environment in self.environments
            ],
            "acceptance": {
                "runId": self.acceptance.run_id,
                "evidenceSha256": self.acceptance.evidence_sha256,
                "catalogSha256": self.acceptance.catalog_sha256,
            },
            "previousSuiteId": self.previous_suite_id,
            "rollback": self.rollback.value,
        }
        return canonical_json_bytes(value)


@dataclass(frozen=True, slots=True)
class SignedSuiteManifest:
    manifest: SuiteManifest
    manifest_digest: str
    signer_key_id: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, SuiteManifest):
            raise SuiteManifestError("invalid_signed_manifest")
        _validate_sha256(self.manifest_digest)
        _validate_stable_id(self.signer_key_id)
        if not isinstance(self.signature, str) or not self.signature:
            raise SuiteManifestError("invalid_signature_encoding")


@dataclass(frozen=True, slots=True)
class SignedSuitePromotion:
    manifest_digest: str
    evidence_sha256: str
    promoted_at: str
    signer_key_id: str
    signature: str

    def __post_init__(self) -> None:
        _validate_sha256(self.manifest_digest)
        _validate_sha256(self.evidence_sha256)
        _validate_utc_timestamp(self.promoted_at)
        _validate_stable_id(self.signer_key_id)
        if not isinstance(self.signature, str) or not self.signature:
            raise SuiteManifestError("invalid_signature_encoding")

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "manifestDigest": self.manifest_digest,
                "evidenceSha256": self.evidence_sha256,
                "promotedAt": self.promoted_at,
            }
        )


class VerifiedSuiteRelease:
    """Immutable result obtainable only from full signature verification."""

    __slots__ = ("_manifest", "_status", "_verified_manifest_digest")

    def __init__(
        self,
        manifest: SuiteManifest,
        status: SuitePublicationStatus,
        verified_manifest_digest: str,
        *,
        _verification_marker: object | None = None,
    ) -> None:
        if (
            _verification_marker is not _VERIFIED_RELEASE_MARKER
            or not isinstance(manifest, SuiteManifest)
            or not isinstance(status, SuitePublicationStatus)
            or verified_manifest_digest != manifest.digest
        ):
            raise SuiteSignatureError("unverified_suite_release")
        object.__setattr__(self, "_manifest", manifest)
        object.__setattr__(self, "_status", status)
        object.__setattr__(
            self,
            "_verified_manifest_digest",
            verified_manifest_digest,
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("VerifiedSuiteRelease is immutable")

    @property
    def manifest(self) -> SuiteManifest:
        return self._manifest

    @property
    def status(self) -> SuitePublicationStatus:
        return self._status

    @property
    def verified_manifest_digest(self) -> str:
        return self._verified_manifest_digest


def sign_suite_manifest(
    manifest: SuiteManifest,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedSuiteManifest:
    """Sign one immutable manifest for release tooling."""

    if not isinstance(manifest, SuiteManifest):
        raise SuiteManifestError("invalid_suite_manifest")
    _validate_stable_id(signer_key_id)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SuiteSignatureError("invalid_signing_key")
    digest = manifest.digest
    signature = sign_canonical_record(
        private_key,
        _MANIFEST_SIGNATURE_DOMAIN,
        manifest.canonical_bytes(),
    )
    return SignedSuiteManifest(
        manifest=manifest,
        manifest_digest=digest,
        signer_key_id=signer_key_id,
        signature=signature,
    )


def verify_suite_manifest(
    signed_manifest: SignedSuiteManifest,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
) -> SuiteManifest:
    """Return the manifest only after its exact digest and signature verify."""

    if not isinstance(signed_manifest, SignedSuiteManifest):
        raise SuiteSignatureError("invalid_signed_manifest")
    if signed_manifest.manifest_digest != signed_manifest.manifest.digest:
        raise SuiteSignatureError("manifest_digest_mismatch")
    if not isinstance(trusted_public_keys, Mapping):
        raise SuiteSignatureError("invalid_trusted_suite_keys")
    public_key = trusted_public_keys.get(signed_manifest.signer_key_id)
    if not isinstance(public_key, Ed25519PublicKey):
        raise SuiteSignatureError("untrusted_suite_signer")
    if not verify_canonical_record_signature(
        public_key,
        signed_manifest.signature,
        _MANIFEST_SIGNATURE_DOMAIN,
        signed_manifest.manifest.canonical_bytes(),
    ):
        raise SuiteSignatureError("invalid_suite_signature") from None
    return signed_manifest.manifest


def sign_suite_promotion(
    manifest: SuiteManifest,
    promoted_at: str,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedSuitePromotion:
    """Create a separate immutable readiness promotion for one manifest."""

    if not isinstance(manifest, SuiteManifest):
        raise SuiteManifestError("invalid_suite_manifest")
    _validate_utc_timestamp(promoted_at)
    _validate_stable_id(signer_key_id)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SuiteSignatureError("invalid_signing_key")
    unsigned = SignedSuitePromotion(
        manifest_digest=manifest.digest,
        evidence_sha256=manifest.acceptance.evidence_sha256,
        promoted_at=promoted_at,
        signer_key_id=signer_key_id,
        signature="unsigned",
    )
    signature = sign_canonical_record(
        private_key,
        _PROMOTION_SIGNATURE_DOMAIN,
        unsigned.canonical_bytes(),
    )
    return SignedSuitePromotion(
        manifest_digest=unsigned.manifest_digest,
        evidence_sha256=unsigned.evidence_sha256,
        promoted_at=unsigned.promoted_at,
        signer_key_id=signer_key_id,
        signature=signature,
    )


def verify_suite_release(
    signed_manifest: SignedSuiteManifest,
    promotion: SignedSuitePromotion | None,
    trusted_manifest_keys: Mapping[str, Ed25519PublicKey],
    trusted_promotion_keys: Mapping[str, Ed25519PublicKey],
) -> VerifiedSuiteRelease:
    """Verify the candidate and its optional readiness promotion."""

    manifest = verify_suite_manifest(signed_manifest, trusted_manifest_keys)
    if promotion is None:
        return VerifiedSuiteRelease(
            manifest,
            SuitePublicationStatus.CUTOVER_PENDING,
            manifest.digest,
            _verification_marker=_VERIFIED_RELEASE_MARKER,
        )
    if not isinstance(promotion, SignedSuitePromotion):
        raise SuiteSignatureError("invalid_suite_promotion")
    if (
        promotion.manifest_digest != manifest.digest
        or promotion.evidence_sha256 != manifest.acceptance.evidence_sha256
    ):
        raise SuiteSignatureError("promotion_manifest_mismatch")
    if not isinstance(trusted_promotion_keys, Mapping):
        raise SuiteSignatureError("invalid_trusted_promotion_keys")
    public_key = trusted_promotion_keys.get(promotion.signer_key_id)
    if not isinstance(public_key, Ed25519PublicKey):
        raise SuiteSignatureError("untrusted_promotion_signer")
    if not verify_canonical_record_signature(
        public_key,
        promotion.signature,
        _PROMOTION_SIGNATURE_DOMAIN,
        promotion.canonical_bytes(),
    ):
        raise SuiteSignatureError("invalid_promotion_signature") from None
    return VerifiedSuiteRelease(
        manifest,
        SuitePublicationStatus.READY,
        manifest.digest,
        _verification_marker=_VERIFIED_RELEASE_MARKER,
    )


def _validate_stable_id(value: object) -> None:
    if not is_stable_id(value):
        raise SuiteManifestError("invalid_stable_id")


def _validate_sha256(value: object) -> None:
    if not is_sha256(value):
        raise SuiteManifestError("invalid_sha256")


def _validate_utc_timestamp(value: object) -> None:
    if not is_utc_timestamp(value):
        raise SuiteManifestError("invalid_utc_timestamp")


def _require_unique(values, attribute, error_code):
    identities = [getattr(item, attribute) if attribute else item for item in values]
    if len(identities) != len(set(identities)):
        raise SuiteManifestError(error_code)
