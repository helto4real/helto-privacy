import hashlib
import types
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helto_privacy.suite import sign_suite_manifest, sign_suite_promotion, verify_suite_release
from helto_privacy.profile import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
)
from helto_privacy.suite import ProfileIdentity
from helto_privacy.suite_runtime import (
    ConsumerSuiteDeclaration,
    InstalledSuiteInventory,
    SuiteBlockedError,
    SuiteInstallation,
    SuiteStatus,
    measure_runtime_environment,
    process_suite_status_payload,
    record_browser_manifest_attestation,
    register_consumer_suite_declaration,
    register_process_suite,
    require_active_process_suite,
)
from test_suite_manifest import suite_manifest


def _release(*, ready, manifest=None):
    manifest = manifest or suite_manifest()
    release_key = Ed25519PrivateKey.generate()
    promotion_key = Ed25519PrivateKey.generate()
    signed = sign_suite_manifest(manifest, "release-root-2026", release_key)
    promotion = (
        sign_suite_promotion(
            manifest,
            "2026-07-10T20:00:00Z",
            "promotion-root-2026",
            promotion_key,
        )
        if ready
        else None
    )
    return verify_suite_release(
        signed,
        promotion,
        {"release-root-2026": release_key.public_key()},
        {"promotion-root-2026": promotion_key.public_key()},
    )


def _inventory(manifest):
    return InstalledSuiteInventory(
        artifacts=manifest.artifacts,
        profiles=manifest.profiles,
        environment=manifest.environments[0],
        consumer_declarations=tuple(
            ConsumerSuiteDeclaration(
                distribution=profile.distribution,
                suite_id=manifest.id,
                manifest_digest=manifest.digest,
            )
            for profile in manifest.profiles
        ),
        server_manifest_digest=manifest.digest,
        browser_manifest_digest=manifest.digest,
        installation_generation="a" * 64,
    )


def _install_manifest_profiles(manifest, monkeypatch):
    import helto_privacy.runtime as runtime

    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    identities = []
    for declared in manifest.profiles:
        profile = PrivacyProfile(
            id=declared.id,
            distribution=declared.distribution,
            resources=(
                ProfileResource(
                    "privacy-mode",
                    ResourceKind.MODE,
                    ("mode-source",),
                ),
            ),
            server_adapters=(
                AdapterSlot(
                    "mode-source",
                    ResourceKind.MODE,
                    "privacy-mode",
                ),
            ),
            scopes=(
                PrivacyScope(
                    "default",
                    "privacy-mode",
                    "mode-source",
                ),
            ),
        )
        runtime.install(
            profile,
            {
                "mode-source": types.SimpleNamespace(
                    read_declared_mode=lambda: None,
                    write_declared_mode=lambda: None,
                )
            },
        )
        identities.append(
            ProfileIdentity(
                id=profile.id,
                distribution=profile.distribution,
                fingerprint=profile.fingerprint,
            )
        )
    return tuple(identities)


def test_pending_suite_verifies_but_cannot_activate():
    release = _release(ready=False)
    installation = SuiteInstallation(release)

    report = installation._verify_inventory(_inventory(release.manifest))

    assert report.status is SuiteStatus.CUTOVER_PENDING
    assert report.issue_codes == ("suite_not_promoted",)
    with pytest.raises(SuiteBlockedError) as exc_info:
        installation.require_active()
    assert exc_info.value.code == "suite_cutover_pending"


def test_public_verification_hashes_artifacts_and_live_profile_registry(
    tmp_path,
    monkeypatch,
):
    base = suite_manifest()
    profiles = _install_manifest_profiles(base, monkeypatch)
    environment = measure_runtime_environment(
        comfyui_backend="e2a6e30d",
        comfyui_frontend="1.45.20",
        renderer="vue",
    )
    artifact_files = {}
    artifacts = []
    for artifact in base.artifacts:
        path = tmp_path / artifact.filename
        payload = f"synthetic artifact: {artifact.distribution}".encode()
        path.write_bytes(payload)
        artifact_files[artifact.distribution] = path
        artifacts.append(
            replace(artifact, sha256=hashlib.sha256(payload).hexdigest())
        )
    manifest = replace(
        base,
        artifacts=tuple(artifacts),
        profiles=profiles,
        environments=(environment,),
    )
    release = _release(ready=True, manifest=manifest)
    for profile in profiles:
        register_consumer_suite_declaration(
            ConsumerSuiteDeclaration(
                distribution=profile.distribution,
                suite_id=manifest.id,
                manifest_digest=manifest.digest,
            )
        )

    unattested = SuiteInstallation(release).verify_installed(
        artifact_files=artifact_files,
        environment=environment,
    )
    assert unattested.status is SuiteStatus.INCOMPLETE

    record_browser_manifest_attestation(manifest.digest)
    installation = SuiteInstallation(release)
    exact = installation.verify_installed(
        artifact_files=artifact_files,
        environment=environment,
    )
    assert exact.status is SuiteStatus.ACTIVATION_REQUIRED

    next(iter(artifact_files.values())).write_bytes(b"tampered artifact")
    tampered = SuiteInstallation(release).verify_installed(
        artifact_files=artifact_files,
        environment=environment,
    )
    assert tampered.status is SuiteStatus.MISMATCH


def test_ready_suite_reports_incomplete_mismatch_conflict_then_activation_required():
    release = _release(ready=True)
    manifest = release.manifest
    exact = _inventory(manifest)
    incomplete = replace(exact, artifacts=exact.artifacts[:-1])
    assert (
        SuiteInstallation(release)._verify_inventory(incomplete).status
        is SuiteStatus.INCOMPLETE
    )

    wrong_artifact = replace(exact.artifacts[0], sha256="f" * 64)
    mismatch = replace(exact, artifacts=(wrong_artifact, *exact.artifacts[1:]))
    assert (
        SuiteInstallation(release)._verify_inventory(mismatch).status
        is SuiteStatus.MISMATCH
    )

    duplicated = replace(exact, artifacts=(*exact.artifacts, exact.artifacts[0]))
    assert (
        SuiteInstallation(release)._verify_inventory(duplicated).status
        is SuiteStatus.MISMATCH
    )

    conflicting = replace(
        exact,
        consumer_declarations=(
            *exact.consumer_declarations,
            replace(exact.consumer_declarations[0], suite_id="other-suite"),
        ),
    )
    assert (
        SuiteInstallation(release)._verify_inventory(conflicting).status
        is SuiteStatus.CONFLICT
    )

    installation = SuiteInstallation(release)
    report = installation._verify_inventory(exact)
    assert report.status is SuiteStatus.ACTIVATION_REQUIRED
    assert report.issue_codes == ("explicit_activation_required",)
    with pytest.raises(SuiteBlockedError):
        installation.require_active()


def test_failed_installation_requires_a_fresh_process_before_activation():
    release = _release(ready=True)
    installation = SuiteInstallation(release)
    exact = _inventory(release.manifest)

    incomplete = replace(exact, artifacts=exact.artifacts[:-1])
    assert installation._verify_inventory(incomplete).status is SuiteStatus.INCOMPLETE

    repaired = installation._verify_inventory(exact)
    assert repaired.status is SuiteStatus.MISMATCH
    assert repaired.issue_codes == ("process_restart_required",)


def test_process_gate_blocks_missing_pending_and_conflicting_suites(monkeypatch):
    import helto_privacy.suite_runtime as suite_runtime

    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_INSTALLATION", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_CONFLICT", False)
    assert process_suite_status_payload() == {
        "suiteStatus": "incomplete",
        "suiteManifestDigest": None,
        "suiteIssueCodes": ["suite_not_configured"],
    }
    with pytest.raises(SuiteBlockedError) as missing:
        require_active_process_suite()
    assert missing.value.code == "suite_incomplete"

    pending_release = _release(ready=False)
    pending = SuiteInstallation(pending_release)
    pending._verify_inventory(_inventory(pending_release.manifest))
    assert register_process_suite(pending) is pending
    assert process_suite_status_payload()["suiteStatus"] == "cutover-pending"
    with pytest.raises(SuiteBlockedError):
        require_active_process_suite()

    other_manifest = replace(suite_manifest(), id="helto-suite-other")
    other = SuiteInstallation(_release(ready=True, manifest=other_manifest))
    with pytest.raises(SuiteBlockedError) as conflict:
        register_process_suite(other)
    assert conflict.value.code == "suite_process_conflict"
    assert process_suite_status_payload()["suiteStatus"] == "conflict"
