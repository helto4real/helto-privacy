"""Signed exact-suite binding and zero-waiver acceptance verification."""

from __future__ import annotations

import itertools
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .._suite_codec import (
    canonical_json_bytes,
    is_sha256,
    is_stable_id,
    sign_canonical_record,
    verify_canonical_record_signature,
)
from ..suite import EnvironmentTuple, SuiteManifest
from .models import (
    AcceptanceCatalog,
    AcceptanceEnvironmentRun,
    AcceptanceError,
    AcceptanceEvidenceManifest,
    EvidenceArtifact,
    EvidenceResult,
    EvidenceSource,
    EvidenceStatus,
)


_SIGNATURE_DOMAIN = b"helto.privacy.acceptance-evidence.v1\x00"
SIGNED_ACCEPTANCE_EVIDENCE_V1 = "helto.privacy.signed-acceptance-evidence.v1"


@dataclass(frozen=True, slots=True)
class SignedAcceptanceEvidence:
    manifest: AcceptanceEvidenceManifest
    evidence_sha256: str
    suite_manifest_digest: str
    signer_key_id: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, AcceptanceEvidenceManifest):
            raise AcceptanceError("invalid_signed_evidence")
        if not is_sha256(self.evidence_sha256) or not is_sha256(
            self.suite_manifest_digest
        ):
            raise AcceptanceError("invalid_signed_evidence_digest")
        if not is_stable_id(self.signer_key_id):
            raise AcceptanceError("invalid_evidence_signer")
        if not isinstance(self.signature, str) or not self.signature:
            raise AcceptanceError("invalid_evidence_signature")

    def binding_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "evidenceSha256": self.evidence_sha256,
                "suiteManifestDigest": self.suite_manifest_digest,
            }
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema": SIGNED_ACCEPTANCE_EVIDENCE_V1,
                "evidenceSha256": self.evidence_sha256,
                "suiteManifestDigest": self.suite_manifest_digest,
                "signerKeyId": self.signer_key_id,
                "signature": self.signature,
                "manifest": self.manifest.canonical_value(),
            }
        )


def load_signed_acceptance_evidence(path: str | Path) -> SignedAcceptanceEvidence:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload["schema"] != SIGNED_ACCEPTANCE_EVIDENCE_V1:
            raise AcceptanceError("signed_evidence_schema_mismatch")
        manifest_payload = payload["manifest"]
        manifest = AcceptanceEvidenceManifest(
            run_id=manifest_payload["runId"],
            harness_version=manifest_payload["harnessVersion"],
            catalog_sha256=manifest_payload["catalogSha256"],
            fixture_catalog_sha256=manifest_payload["fixtureCatalogSha256"],
            artifacts=tuple(
                EvidenceArtifact(item["id"], item["sha256"])
                for item in manifest_payload["artifacts"]
            ),
            sources=tuple(
                EvidenceSource(item["id"], item["repository"], item["revision"])
                for item in manifest_payload["sources"]
            ),
            runs=tuple(_load_environment_run(item) for item in manifest_payload["runs"]),
            schema=manifest_payload["schema"],
        )
        return SignedAcceptanceEvidence(
            manifest,
            payload["evidenceSha256"],
            payload["suiteManifestDigest"],
            payload["signerKeyId"],
            payload["signature"],
        )
    except AcceptanceError:
        raise
    except Exception:
        raise AcceptanceError("signed_evidence_load_failed") from None


def _load_environment_run(payload: Mapping[str, object]) -> AcceptanceEnvironmentRun:
    environment = payload["environment"]
    if not isinstance(environment, Mapping):
        raise AcceptanceError("invalid_environment_tuple")
    return AcceptanceEnvironmentRun(
        EnvironmentTuple(
            environment["python"],
            environment["comfyuiBackend"],
            environment["comfyuiFrontend"],
            environment["renderer"],
        ),
        tuple(tuple(order) for order in payload["registrationOrders"]),
        payload["seed"],
        tuple(
            EvidenceResult(
                item["evidenceId"],
                EvidenceStatus(item["status"]),
                item["observationSha256"],
                item["retryCount"],
                tuple(item["warnings"]),
                tuple(item["errors"]),
                tuple(item["exclusions"]),
            )
            for item in payload["results"]
        ),
    )


def sign_acceptance_evidence(
    manifest: AcceptanceEvidenceManifest,
    suite_manifest_digest: str,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedAcceptanceEvidence:
    if not isinstance(manifest, AcceptanceEvidenceManifest):
        raise AcceptanceError("invalid_evidence_manifest")
    if not is_sha256(suite_manifest_digest):
        raise AcceptanceError("invalid_suite_manifest_digest")
    if not is_stable_id(signer_key_id):
        raise AcceptanceError("invalid_evidence_signer")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AcceptanceError("invalid_evidence_signing_key")
    unsigned = SignedAcceptanceEvidence(
        manifest,
        manifest.digest,
        suite_manifest_digest,
        signer_key_id,
        "unsigned",
    )
    return SignedAcceptanceEvidence(
        manifest,
        manifest.digest,
        suite_manifest_digest,
        signer_key_id,
        sign_canonical_record(
            private_key,
            _SIGNATURE_DOMAIN,
            unsigned.binding_bytes(),
        ),
    )


def verify_acceptance_evidence(
    signed: SignedAcceptanceEvidence,
    catalog: AcceptanceCatalog,
    suite_manifest: SuiteManifest,
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> AcceptanceEvidenceManifest:
    if not isinstance(signed, SignedAcceptanceEvidence):
        raise AcceptanceError("invalid_signed_evidence")
    if not isinstance(catalog, AcceptanceCatalog):
        raise AcceptanceError("invalid_acceptance_catalog")
    if not isinstance(suite_manifest, SuiteManifest):
        raise AcceptanceError("invalid_suite_manifest")
    if signed.evidence_sha256 != signed.manifest.digest:
        raise AcceptanceError("evidence_digest_mismatch")
    if signed.suite_manifest_digest != suite_manifest.digest:
        raise AcceptanceError("evidence_suite_mismatch")
    if not isinstance(trusted_keys, Mapping):
        raise AcceptanceError("invalid_trusted_evidence_keys")
    public_key = trusted_keys.get(signed.signer_key_id)
    if not isinstance(public_key, Ed25519PublicKey):
        raise AcceptanceError("untrusted_evidence_signer")
    if not verify_canonical_record_signature(
        public_key,
        signed.signature,
        _SIGNATURE_DOMAIN,
        signed.binding_bytes(),
    ):
        raise AcceptanceError("invalid_evidence_signature")

    manifest = signed.manifest
    if (
        manifest.catalog_sha256 != catalog.digest
        or manifest.fixture_catalog_sha256 != catalog.fixture_catalog_sha256
        or suite_manifest.acceptance.run_id != manifest.run_id
        or suite_manifest.acceptance.evidence_sha256 != manifest.digest
        or suite_manifest.acceptance.catalog_sha256 != catalog.digest
    ):
        raise AcceptanceError("evidence_catalog_or_suite_mismatch")

    expected_artifacts = {
        artifact.id: artifact.sha256 for artifact in suite_manifest.artifacts
    }
    actual_artifacts = {artifact.id: artifact.sha256 for artifact in manifest.artifacts}
    if actual_artifacts != expected_artifacts:
        raise AcceptanceError("evidence_artifact_mismatch")
    expected_sources = {
        artifact.id: (artifact.source.repository, artifact.source.revision)
        for artifact in suite_manifest.artifacts
    }
    actual_sources = {
        source.id: (source.repository, source.revision)
        for source in manifest.sources
    }
    if actual_sources != expected_sources:
        raise AcceptanceError("evidence_source_mismatch")

    catalog_environments = set(catalog.environments)
    suite_environments = set(suite_manifest.environments)
    run_environments = {run.environment for run in manifest.runs}
    if not (
        catalog_environments == suite_environments == run_environments
    ):
        raise AcceptanceError("support_matrix_mismatch")

    profile_ids = tuple(sorted(profile.id for profile in suite_manifest.profiles))
    required_orders = set(itertools.permutations(profile_ids))
    required_ids = {requirement.id for requirement in catalog.requirements}
    for run in manifest.runs:
        if set(run.registration_orders) != required_orders:
            raise AcceptanceError("registration_matrix_incomplete")
        results = {result.evidence_id: result for result in run.results}
        if set(results) != required_ids:
            raise AcceptanceError("evidence_result_set_incomplete")
        if any(
            result.status is not EvidenceStatus.PASS
            or result.retry_count != 0
            or result.warnings
            or result.errors
            or result.exclusions
            for result in results.values()
        ):
            raise AcceptanceError("zero_waiver_gate_failed")
    return manifest
