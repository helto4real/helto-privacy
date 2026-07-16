import json
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import helto_privacy.runtime as runtime
import helto_privacy.suite_bootstrap as suite_bootstrap
import helto_privacy.suite_runtime as suite_runtime
from helto_privacy.suite import sign_suite_manifest, sign_suite_promotion
from helto_privacy.suite_runtime import (
    ConsumerSuiteDeclaration,
    SuiteStatus,
    process_suite_status_payload,
    record_browser_manifest_attestation,
    register_consumer_suite_declaration,
    verify_configured_process_suite,
)
from tests.test_suite_manifest import suite_manifest


def _reset(monkeypatch):
    monkeypatch.setattr(suite_bootstrap, "_ATTEMPTED", False)
    monkeypatch.setattr(suite_bootstrap, "_RESULT", False)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_INSTALLATION", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_CONFLICT", False)
    monkeypatch.setattr(suite_runtime, "_PROCESS_CONSUMER_DECLARATIONS", [])
    monkeypatch.setattr(suite_runtime, "_PROCESS_BROWSER_MANIFEST_DIGEST", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_BROWSER_RENDERER", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_BROWSER_CONFLICT", False)
    monkeypatch.setattr(suite_runtime, "_PROCESS_ARTIFACT_FILES", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_ENVIRONMENTS", None)


def _public_key(path, private_key):
    path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _signed_manifest_payload(signed):
    return {
        "schema": "helto.privacy.signed-suite-manifest.v1",
        "manifest": json.loads(signed.manifest.canonical_bytes()),
        "manifestDigest": signed.manifest_digest,
        "signerKeyId": signed.signer_key_id,
        "signature": signed.signature,
    }


def _promotion_payload(promotion):
    return {
        "schema": "helto.privacy.signed-suite-promotion.v1",
        "manifestDigest": promotion.manifest_digest,
        "evidenceSha256": promotion.evidence_sha256,
        "promotedAt": promotion.promoted_at,
        "signerKeyId": promotion.signer_key_id,
        "signature": promotion.signature,
    }


def test_detached_ready_suite_bootstraps_then_verifies_after_browser_attestation(
    monkeypatch,
    tmp_path,
):
    _reset(monkeypatch)
    base = suite_manifest()
    artifact_files = {}
    artifacts = []
    for artifact in base.artifacts:
        path = tmp_path / artifact.filename
        payload = f"public artifact {artifact.distribution}".encode()
        path.write_bytes(payload)
        artifact_files[artifact.distribution] = path
        import hashlib

        artifacts.append(replace(artifact, sha256=hashlib.sha256(payload).hexdigest()))
    manifest = replace(
        base,
        artifacts=tuple(artifacts),
        environments=(
            base.environments[0],
            replace(base.environments[0], renderer="legacy"),
        ),
    )
    manifest_key = Ed25519PrivateKey.generate()
    promotion_key = Ed25519PrivateKey.generate()
    signed = sign_suite_manifest(
        manifest,
        suite_bootstrap.MANIFEST_SIGNER_KEY_ID,
        manifest_key,
    )
    promotion = sign_suite_promotion(
        manifest,
        "2026-07-16T14:00:00Z",
        suite_bootstrap.PROMOTION_SIGNER_KEY_ID,
        promotion_key,
    )
    manifest_public = tmp_path / "manifest.pub.pem"
    promotion_public = tmp_path / "promotion.pub.pem"
    _public_key(manifest_public, manifest_key)
    _public_key(promotion_public, promotion_key)
    monkeypatch.setattr(suite_bootstrap, "_MANIFEST_PUBLIC_KEY", manifest_public)
    monkeypatch.setattr(suite_bootstrap, "_PROMOTION_PUBLIC_KEY", promotion_public)
    config = tmp_path / "process-suite.json"
    config.write_text(
        json.dumps(
            {
                "schema": suite_bootstrap.PROCESS_SUITE_CONFIG_SCHEMA_V1,
                "signedManifest": _signed_manifest_payload(signed),
                "promotion": _promotion_payload(promotion),
                "artifactFiles": {
                    distribution: str(path)
                    for distribution, path in artifact_files.items()
                },
                "environment": {
                    "python": manifest.environments[0].python,
                    "comfyuiBackend": manifest.environments[0].comfyui_backend,
                    "comfyuiFrontend": manifest.environments[0].comfyui_frontend,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HELTO_PRIVACY_SUITE_CONFIG", str(config))
    monkeypatch.setattr(runtime, "installed_profile_identities", lambda: manifest.profiles)

    assert suite_bootstrap.bootstrap_configured_process_suite() is True
    assert process_suite_status_payload()["suiteStatus"] == "ready"

    for profile in manifest.profiles:
        register_consumer_suite_declaration(
            ConsumerSuiteDeclaration(profile.distribution, manifest.id)
        )
    record_browser_manifest_attestation(manifest.digest, "legacy")
    report = verify_configured_process_suite()

    assert report.status is SuiteStatus.ACTIVATION_REQUIRED
    assert report.issue_codes == ("explicit_activation_required",)
    assert suite_bootstrap.bootstrap_configured_process_suite() is True


def test_invalid_configured_suite_fails_closed(monkeypatch, tmp_path):
    _reset(monkeypatch)
    config = tmp_path / "process-suite.json"
    config.write_text(
        json.dumps(
            {
                "schema": suite_bootstrap.PROCESS_SUITE_CONFIG_SCHEMA_V1,
                "signedManifest": {},
                "promotion": {},
                "artifactFiles": {},
                "environment": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HELTO_PRIVACY_SUITE_CONFIG", str(config))

    assert suite_bootstrap.bootstrap_configured_process_suite() is False
    assert process_suite_status_payload() == {
        "suiteStatus": "conflict",
        "suiteManifestDigest": None,
        "suiteIssueCodes": ["conflicting_suite_manifests"],
    }


def test_signed_wrapper_schema_is_not_inferred(monkeypatch, tmp_path):
    _reset(monkeypatch)
    config = tmp_path / "process-suite.json"
    config.write_text(
        json.dumps(
            {
                "schema": suite_bootstrap.PROCESS_SUITE_CONFIG_SCHEMA_V1,
                "signedManifest": {
                    "schema": "helto.privacy.signed-suite-manifest.v2"
                },
                "promotion": {
                    "schema": "helto.privacy.signed-suite-promotion.v1"
                },
                "artifactFiles": {},
                "environment": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HELTO_PRIVACY_SUITE_CONFIG", str(config))

    assert suite_bootstrap.bootstrap_configured_process_suite() is False
    assert process_suite_status_payload()["suiteStatus"] == "conflict"
