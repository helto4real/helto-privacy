"""Load one detached signed suite into a ComfyUI process fail closed."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from threading import RLock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._suite_codec import is_stable_id
from .suite import (
    AcceptanceEvidence,
    ArtifactIdentity,
    EnvironmentTuple,
    ProfileIdentity,
    RollbackClass,
    SignedSuiteManifest,
    SignedSuitePromotion,
    SourceIdentity,
    SuiteManifest,
    verify_suite_release,
)
from .suite_activation import FileActivationRecordStore
from .suite_runtime import (
    SuiteInstallation,
    block_process_suite_configuration,
    configure_process_suite_verification,
    register_process_suite,
)


PROCESS_SUITE_CONFIG_SCHEMA_V1 = "helto.privacy.process-suite-config.v1"
PROCESS_SUITE_CONFIG_SCHEMA_V2 = "helto.privacy.process-suite-config.v2"
DEFAULT_PROCESS_SUITE_CONFIG = Path("~/.config/helto/process-suite.json")
MANIFEST_SIGNER_KEY_ID = "helto-suite-release-ed25519-e94ef2d597eb4276"
PROMOTION_SIGNER_KEY_ID = "helto-suite-promotion-ed25519-96aad83c09c02860"
_TRUST_ROOT = Path(__file__).resolve().parent / "trust"
_MANIFEST_PUBLIC_KEY = _TRUST_ROOT / f"{MANIFEST_SIGNER_KEY_ID}.pub.pem"
_PROMOTION_PUBLIC_KEY = _TRUST_ROOT / f"{PROMOTION_SIGNER_KEY_ID}.pub.pem"
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_LOCK = RLock()
_ATTEMPTED = False
_RESULT = False


class SuiteBootstrapError(RuntimeError):
    """Sanitized configured-suite bootstrap failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Configured privacy suite bootstrap failed.")


def configured_process_suite_path() -> Path:
    """Return the one operator-controlled detached suite configuration path."""

    configured = os.environ.get("HELTO_PRIVACY_SUITE_CONFIG")
    path = Path(configured) if configured else DEFAULT_PROCESS_SUITE_CONFIG.expanduser()
    if not path.is_absolute():
        raise SuiteBootstrapError("suite_config_path_not_absolute")
    return path


def bootstrap_configured_process_suite() -> bool:
    """Register a signed ready suite once, or leave an absent config incomplete."""

    global _ATTEMPTED, _RESULT
    with _LOCK:
        if _ATTEMPTED:
            return _RESULT
        _ATTEMPTED = True
        try:
            path = configured_process_suite_path()
            if not path.exists():
                return False
            payload = _read_config(path)
            signed_manifest = _signed_manifest(payload.get("signedManifest"))
            promotion = _signed_promotion(payload.get("promotion"))
            release = verify_suite_release(
                signed_manifest,
                promotion,
                {MANIFEST_SIGNER_KEY_ID: _public_key(_MANIFEST_PUBLIC_KEY)},
                {PROMOTION_SIGNER_KEY_ID: _public_key(_PROMOTION_PUBLIC_KEY)},
            )
            artifact_files = _artifact_files(payload.get("artifactFiles"), release.manifest)
            environment_identity = _environment_identity(payload.get("environment"))
            environments = tuple(
                environment
                for environment in release.manifest.environments
                if (
                    environment.python,
                    environment.comfyui_backend,
                    environment.comfyui_frontend,
                )
                == environment_identity
            )
            if not environments:
                raise SuiteBootstrapError("environment_identity_invalid")
            activation_path = payload.get("activationRecord")
            if activation_path is None:
                activation_record = path.with_name("suite-activation.json")
            else:
                activation_record = Path(str(activation_path))
                if not activation_record.is_absolute():
                    raise SuiteBootstrapError("activation_record_path_not_absolute")
            activation_keys = (
                _activation_public_keys(payload.get("activationPublicKeys"))
                if payload.get("schema") == PROCESS_SUITE_CONFIG_SCHEMA_V2
                else {}
            )
            installation = SuiteInstallation(
                release,
                activation_store=FileActivationRecordStore(activation_record),
                trusted_activation_keys=activation_keys,
            )
            register_process_suite(installation)
            configure_process_suite_verification(
                installation,
                artifact_files=artifact_files,
                environments=environments,
            )
            _RESULT = True
            return _RESULT
        except Exception:
            block_process_suite_configuration()
            return _RESULT


def _read_config(path: Path) -> Mapping[str, object]:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_CONFIG_BYTES:
            raise SuiteBootstrapError("suite_config_invalid")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SuiteBootstrapError("suite_config_invalid") from None
    if not isinstance(payload, Mapping) or payload.get("schema") not in {
        PROCESS_SUITE_CONFIG_SCHEMA_V1,
        PROCESS_SUITE_CONFIG_SCHEMA_V2,
    }:
        raise SuiteBootstrapError("suite_config_schema_mismatch")
    return payload


def _public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError):
        raise SuiteBootstrapError("suite_trust_root_invalid") from None
    if not isinstance(key, Ed25519PublicKey):
        raise SuiteBootstrapError("suite_trust_root_invalid")
    return key


def _activation_public_keys(value: object) -> dict[str, Ed25519PublicKey]:
    payload = _mapping(value, "activation_public_keys_invalid")
    if not payload or len(payload) > 16:
        raise SuiteBootstrapError("activation_public_keys_invalid")
    result: dict[str, Ed25519PublicKey] = {}
    for key_id, configured_path in payload.items():
        if not is_stable_id(key_id):
            raise SuiteBootstrapError("activation_public_keys_invalid")
        path = Path(str(configured_path))
        if not path.is_absolute():
            raise SuiteBootstrapError("activation_public_key_path_not_absolute")
        try:
            key = serialization.load_pem_public_key(path.read_bytes())
        except (OSError, ValueError, TypeError):
            raise SuiteBootstrapError("activation_public_key_invalid") from None
        if not isinstance(key, Ed25519PublicKey):
            raise SuiteBootstrapError("activation_public_key_invalid")
        result[str(key_id)] = key
    return result


def _signed_manifest(value: object) -> SignedSuiteManifest:
    payload = _mapping(value, "signed_manifest_invalid")
    if payload.get("schema") != "helto.privacy.signed-suite-manifest.v1":
        raise SuiteBootstrapError("signed_manifest_invalid")
    manifest_payload = _mapping(payload.get("manifest"), "signed_manifest_invalid")
    try:
        manifest = SuiteManifest(
            id=str(manifest_payload["id"]),
            schema=str(manifest_payload["schema"]),
            contract=str(manifest_payload["contract"]),
            artifacts=tuple(_artifact(item) for item in _sequence(manifest_payload["artifacts"])),
            profiles=tuple(_profile(item) for item in _sequence(manifest_payload["profiles"])),
            environments=tuple(
                _environment(item) for item in _sequence(manifest_payload["environments"])
            ),
            acceptance=_acceptance(manifest_payload["acceptance"]),
            previous_suite_id=(
                str(manifest_payload["previousSuiteId"])
                if manifest_payload.get("previousSuiteId") is not None
                else None
            ),
            rollback=RollbackClass(str(manifest_payload["rollback"])),
        )
        return SignedSuiteManifest(
            manifest=manifest,
            manifest_digest=str(payload["manifestDigest"]),
            signer_key_id=str(payload["signerKeyId"]),
            signature=str(payload["signature"]),
        )
    except (KeyError, TypeError, ValueError):
        raise SuiteBootstrapError("signed_manifest_invalid") from None


def _signed_promotion(value: object) -> SignedSuitePromotion:
    payload = _mapping(value, "signed_promotion_invalid")
    if payload.get("schema") != "helto.privacy.signed-suite-promotion.v1":
        raise SuiteBootstrapError("signed_promotion_invalid")
    try:
        return SignedSuitePromotion(
            manifest_digest=str(payload["manifestDigest"]),
            evidence_sha256=str(payload["evidenceSha256"]),
            promoted_at=str(payload["promotedAt"]),
            signer_key_id=str(payload["signerKeyId"]),
            signature=str(payload["signature"]),
        )
    except (KeyError, TypeError, ValueError):
        raise SuiteBootstrapError("signed_promotion_invalid") from None


def _artifact(value: object) -> ArtifactIdentity:
    payload = _mapping(value, "artifact_identity_invalid")
    source = _mapping(payload.get("source"), "artifact_identity_invalid")
    return ArtifactIdentity(
        id=str(payload["id"]),
        distribution=str(payload["distribution"]),
        version=str(payload["version"]),
        filename=str(payload["filename"]),
        sha256=str(payload["sha256"]),
        source=SourceIdentity(
            repository=str(source["repository"]),
            revision=str(source["revision"]),
            tag=str(source["tag"]) if source.get("tag") is not None else None,
        ),
    )


def _profile(value: object) -> ProfileIdentity:
    payload = _mapping(value, "profile_identity_invalid")
    return ProfileIdentity(
        id=str(payload["id"]),
        distribution=str(payload["distribution"]),
        fingerprint=str(payload["fingerprint"]),
    )


def _environment(value: object) -> EnvironmentTuple:
    payload = _mapping(value, "environment_identity_invalid")
    return EnvironmentTuple(
        python=str(payload["python"]),
        comfyui_backend=str(payload["comfyuiBackend"]),
        comfyui_frontend=str(payload["comfyuiFrontend"]),
        renderer=str(payload["renderer"]),
    )


def _environment_identity(value: object) -> tuple[str, str, str]:
    payload = _mapping(value, "environment_identity_invalid")
    if set(payload) != {"python", "comfyuiBackend", "comfyuiFrontend"}:
        raise SuiteBootstrapError("environment_identity_invalid")
    try:
        identity = (
            str(payload["python"]),
            str(payload["comfyuiBackend"]),
            str(payload["comfyuiFrontend"]),
        )
    except KeyError:
        raise SuiteBootstrapError("environment_identity_invalid") from None
    if any(not item.strip() for item in identity):
        raise SuiteBootstrapError("environment_identity_invalid")
    return identity


def _acceptance(value: object) -> AcceptanceEvidence:
    payload = _mapping(value, "acceptance_identity_invalid")
    return AcceptanceEvidence(
        run_id=str(payload["runId"]),
        evidence_sha256=str(payload["evidenceSha256"]),
        catalog_sha256=str(payload["catalogSha256"]),
    )


def _artifact_files(value: object, manifest: SuiteManifest) -> dict[str, Path]:
    payload = _mapping(value, "artifact_files_invalid")
    expected = {artifact.distribution for artifact in manifest.artifacts}
    if set(payload) != expected:
        raise SuiteBootstrapError("artifact_files_invalid")
    result = {distribution: Path(str(path)) for distribution, path in payload.items()}
    if any(not path.is_absolute() for path in result.values()):
        raise SuiteBootstrapError("artifact_path_not_absolute")
    return result


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SuiteBootstrapError(code)
    return value


def _sequence(value: object) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise SuiteBootstrapError("suite_sequence_invalid")
    return tuple(value)


__all__ = [
    "DEFAULT_PROCESS_SUITE_CONFIG",
    "PROCESS_SUITE_CONFIG_SCHEMA_V1",
    "PROCESS_SUITE_CONFIG_SCHEMA_V2",
    "SuiteBootstrapError",
    "bootstrap_configured_process_suite",
    "configured_process_suite_path",
]
