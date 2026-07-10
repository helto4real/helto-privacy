from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helto_privacy.suite import (
    PRIVACY_SUITE_MANIFEST_V1,
    AcceptanceEvidence,
    ArtifactIdentity,
    EnvironmentTuple,
    ProfileIdentity,
    RollbackClass,
    SuitePublicationStatus,
    SuiteSignatureError,
    SourceIdentity,
    SuiteManifest,
    VerifiedSuiteRelease,
    sign_suite_manifest,
    sign_suite_promotion,
    verify_suite_release,
    verify_suite_manifest,
)


def _artifact(index, distribution):
    return ArtifactIdentity(
        id=f"artifact-{index}",
        distribution=distribution,
        version=f"1.0.{index}",
        filename=f"{distribution}-1.0.{index}.whl",
        sha256=str(index) * 64,
        source=SourceIdentity(
            repository=f"https://github.com/helto4real/{distribution}",
            revision=hex(index)[2:] * 40,
            tag=f"v1.0.{index}",
        ),
    )


def suite_manifest():
    artifacts = tuple(
        _artifact(index, distribution)
        for index, distribution in enumerate(
            (
                "helto-privacy",
                "comfyui-utils",
                "comfyui-all-on-one-image-generation-node",
                "comfyui-helto-director",
                "comfyui-helto-smartprompt",
            ),
            start=1,
        )
    )
    profiles = tuple(
        ProfileIdentity(
            id=profile_id,
            distribution=distribution,
            fingerprint=str(index + 5) * 64,
        )
        for index, (profile_id, distribution) in enumerate(
            (
                ("helto.utils", "comfyui-utils"),
                ("helto.aio-image-generation", "comfyui-all-on-one-image-generation-node"),
                ("helto.director", "comfyui-helto-director"),
                ("helto.smart-prompt", "comfyui-helto-smartprompt"),
            ),
            start=1,
        )
    )
    return SuiteManifest(
        id="helto-suite-2026-07-10.1",
        schema=PRIVACY_SUITE_MANIFEST_V1,
        contract="helto.privacy.v2",
        artifacts=artifacts,
        profiles=profiles,
        environments=(
            EnvironmentTuple(
                python="3.13.14",
                comfyui_backend="e2a6e30d",
                comfyui_frontend="1.45.20",
                renderer="vue",
            ),
        ),
        acceptance=AcceptanceEvidence(
            run_id="acceptance-2026-07-10.1",
            evidence_sha256="b" * 64,
            catalog_sha256="c" * 64,
        ),
        previous_suite_id="helto-suite-2026-06-01.1",
        rollback=RollbackClass.DATA_SNAPSHOT_REQUIRED_AFTER_ACTIVATION,
    )


def test_manifest_digest_is_canonical_and_order_independent():
    manifest = suite_manifest()

    assert manifest.digest == (
        "02ff493b3f4860389fca83ba7053ebfb9df8b345c2e978a53702febd5dc8eafd"
    )

    reordered = SuiteManifest(
        id=manifest.id,
        schema=manifest.schema,
        contract=manifest.contract,
        artifacts=tuple(reversed(manifest.artifacts)),
        profiles=tuple(reversed(manifest.profiles)),
        environments=manifest.environments,
        acceptance=manifest.acceptance,
        previous_suite_id=manifest.previous_suite_id,
        rollback=manifest.rollback,
    )
    assert reordered.digest == manifest.digest


def test_signed_manifest_requires_an_exact_trusted_signature():
    manifest = suite_manifest()
    private_key = Ed25519PrivateKey.generate()
    signed = sign_suite_manifest(manifest, "release-root-2026", private_key)

    assert signed.manifest_digest == manifest.digest
    assert verify_suite_manifest(
        signed,
        {"release-root-2026": private_key.public_key()},
    ) is manifest

    tampered = replace(signed, signature="A" + signed.signature[1:])
    with pytest.raises(SuiteSignatureError) as exc_info:
        verify_suite_manifest(
            tampered,
            {"release-root-2026": private_key.public_key()},
        )

    assert exc_info.value.code == "invalid_suite_signature"
    assert manifest.id not in str(exc_info.value)


def test_verified_release_cannot_be_constructed_or_promoted_without_verification():
    manifest = suite_manifest()

    with pytest.raises(SuiteSignatureError) as direct:
        VerifiedSuiteRelease(
            manifest=manifest,
            status=SuitePublicationStatus.READY,
            verified_manifest_digest=manifest.digest,
            _verification_marker=object(),
        )
    assert direct.value.code == "unverified_suite_release"

    release_key = Ed25519PrivateKey.generate()
    signed = sign_suite_manifest(manifest, "release-root-2026", release_key)
    release = verify_suite_release(
        signed,
        None,
        {"release-root-2026": release_key.public_key()},
        {},
    )
    assert release.status is SuitePublicationStatus.CUTOVER_PENDING
    with pytest.raises(AttributeError):
        release.status = SuitePublicationStatus.READY
    with pytest.raises(TypeError):
        replace(release, status=SuitePublicationStatus.READY)


def test_signed_promotion_changes_status_without_mutating_manifest():
    manifest = suite_manifest()
    release_key = Ed25519PrivateKey.generate()
    promotion_key = Ed25519PrivateKey.generate()
    signed = sign_suite_manifest(manifest, "release-root-2026", release_key)

    pending = verify_suite_release(
        signed,
        None,
        {"release-root-2026": release_key.public_key()},
        {"promotion-root-2026": promotion_key.public_key()},
    )
    assert pending.status is SuitePublicationStatus.CUTOVER_PENDING

    promotion = sign_suite_promotion(
        manifest,
        "2026-07-10T20:00:00Z",
        "promotion-root-2026",
        promotion_key,
    )
    ready = verify_suite_release(
        signed,
        promotion,
        {"release-root-2026": release_key.public_key()},
        {"promotion-root-2026": promotion_key.public_key()},
    )

    assert ready.status is SuitePublicationStatus.READY
    assert ready.manifest is manifest
    assert ready.manifest.digest == pending.manifest.digest
