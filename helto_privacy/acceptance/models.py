"""Immutable models for the versioned zero-waiver acceptance gate."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .._suite_codec import canonical_json_bytes, is_sha256, is_stable_id, typed_tuple
from ..suite import EnvironmentTuple, SourceIdentity


ACCEPTANCE_CATALOG_V1 = "helto.privacy.acceptance-catalog.v1"
ACCEPTANCE_EVIDENCE_V1 = "helto.privacy.acceptance-evidence.v1"


class AcceptanceError(ValueError):
    """Sanitized catalog, evidence, or gate failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy acceptance evidence is invalid or incomplete.")


class EvidenceOwner(str, Enum):
    SHARED = "shared"
    CONSUMER = "consumer"
    INSTALLATION = "installation"
    BROWSER = "browser"
    RELEASE = "release"


class EvidenceStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    XFAIL = "xfail"


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    id: str
    owner: EvidenceOwner
    fixture_ids: tuple[str, ...] = ()
    allowed_sinks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _stable(self.id, "invalid_evidence_id")
        if not isinstance(self.owner, EvidenceOwner):
            raise AcceptanceError("invalid_evidence_owner")
        fixtures = _stable_values(self.fixture_ids, "invalid_fixture_reference")
        sinks = _stable_values(self.allowed_sinks, "invalid_observation_sink")
        object.__setattr__(self, "fixture_ids", fixtures)
        object.__setattr__(self, "allowed_sinks", sinks)


@dataclass(frozen=True, slots=True)
class AcceptanceCatalog:
    id: str
    version: int
    environments: tuple[EnvironmentTuple, ...]
    fixture_catalog_sha256: str
    requirements: tuple[EvidenceRequirement, ...]
    schema: str = ACCEPTANCE_CATALOG_V1

    def __post_init__(self) -> None:
        _stable(self.id, "invalid_catalog_id")
        if self.schema != ACCEPTANCE_CATALOG_V1:
            raise AcceptanceError("catalog_schema_mismatch")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise AcceptanceError("invalid_catalog_version")
        _sha(self.fixture_catalog_sha256, "invalid_fixture_catalog_digest")
        environments = typed_tuple(
            self.environments,
            EnvironmentTuple,
            "invalid_environment_tuple",
            AcceptanceError,
        )
        requirements = typed_tuple(
            self.requirements,
            EvidenceRequirement,
            "invalid_evidence_requirement",
            AcceptanceError,
        )
        if not environments:
            raise AcceptanceError("missing_environment_tuple")
        if not requirements:
            raise AcceptanceError("missing_evidence_requirement")
        _unique(environments, "duplicate_environment_tuple")
        _unique((item.id for item in requirements), "duplicate_evidence_id")
        object.__setattr__(
            self,
            "environments",
            tuple(sorted(environments, key=_environment_key)),
        )
        object.__setattr__(
            self,
            "requirements",
            tuple(sorted(requirements, key=lambda item: item.id)),
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "id": self.id,
                "schema": self.schema,
                "version": self.version,
                "fixtureCatalogSha256": self.fixture_catalog_sha256,
                "environments": [
                    _environment_value(environment)
                    for environment in self.environments
                ],
                "requirements": [
                    {
                        "id": requirement.id,
                        "owner": requirement.owner.value,
                        "fixtureIds": list(requirement.fixture_ids),
                        "allowedSinks": list(requirement.allowed_sinks),
                    }
                    for requirement in self.requirements
                ],
            }
        )


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    evidence_id: str
    status: EvidenceStatus
    observation_sha256: str
    retry_count: int = 0
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _stable(self.evidence_id, "invalid_evidence_id")
        if not isinstance(self.status, EvidenceStatus):
            raise AcceptanceError("invalid_evidence_status")
        _sha(self.observation_sha256, "invalid_observation_digest")
        if (
            not isinstance(self.retry_count, int)
            or isinstance(self.retry_count, bool)
            or self.retry_count < 0
        ):
            raise AcceptanceError("invalid_retry_count")
        for name in ("warnings", "errors", "exclusions"):
            object.__setattr__(
                self,
                name,
                _stable_values(getattr(self, name), f"invalid_{name}"),
            )


@dataclass(frozen=True, slots=True)
class AcceptanceEnvironmentRun:
    environment: EnvironmentTuple
    registration_orders: tuple[tuple[str, ...], ...]
    seed: int
    results: tuple[EvidenceResult, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.environment, EnvironmentTuple):
            raise AcceptanceError("invalid_environment_tuple")
        if not isinstance(self.seed, int) or isinstance(self.seed, bool) or self.seed < 0:
            raise AcceptanceError("invalid_test_seed")
        try:
            orders = tuple(tuple(order) for order in self.registration_orders)
        except TypeError:
            raise AcceptanceError("invalid_registration_orders") from None
        if not orders:
            raise AcceptanceError("missing_registration_orders")
        normalized_orders = tuple(
            _ordered_stable_values(order, "invalid_registration_order")
            for order in orders
        )
        if any(not order for order in normalized_orders):
            raise AcceptanceError("invalid_registration_order")
        _unique(normalized_orders, "duplicate_registration_order")
        results = typed_tuple(
            self.results,
            EvidenceResult,
            "invalid_evidence_result",
            AcceptanceError,
        )
        if not results:
            raise AcceptanceError("missing_evidence_result")
        _unique((item.evidence_id for item in results), "duplicate_evidence_result")
        object.__setattr__(self, "registration_orders", tuple(sorted(normalized_orders)))
        object.__setattr__(self, "results", tuple(sorted(results, key=lambda item: item.evidence_id)))


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    id: str
    sha256: str

    def __post_init__(self) -> None:
        _stable(self.id, "invalid_artifact_id")
        _sha(self.sha256, "invalid_artifact_digest")


@dataclass(frozen=True, slots=True)
class EvidenceSource:
    id: str
    repository: str
    revision: str

    def __post_init__(self) -> None:
        _stable(self.id, "invalid_source_id")
        try:
            SourceIdentity(self.repository, self.revision)
        except Exception:
            raise AcceptanceError("invalid_source_identity") from None


@dataclass(frozen=True, slots=True)
class AcceptanceEvidenceManifest:
    run_id: str
    harness_version: str
    catalog_sha256: str
    fixture_catalog_sha256: str
    artifacts: tuple[EvidenceArtifact, ...]
    sources: tuple[EvidenceSource, ...]
    runs: tuple[AcceptanceEnvironmentRun, ...]
    schema: str = ACCEPTANCE_EVIDENCE_V1

    def __post_init__(self) -> None:
        _stable(self.run_id, "invalid_run_id")
        _stable(self.harness_version, "invalid_harness_version")
        if self.schema != ACCEPTANCE_EVIDENCE_V1:
            raise AcceptanceError("evidence_schema_mismatch")
        _sha(self.catalog_sha256, "invalid_catalog_digest")
        _sha(self.fixture_catalog_sha256, "invalid_fixture_catalog_digest")
        artifacts = typed_tuple(
            self.artifacts,
            EvidenceArtifact,
            "invalid_evidence_artifact",
            AcceptanceError,
        )
        sources = typed_tuple(
            self.sources,
            EvidenceSource,
            "invalid_evidence_source",
            AcceptanceError,
        )
        runs = typed_tuple(
            self.runs,
            AcceptanceEnvironmentRun,
            "invalid_environment_run",
            AcceptanceError,
        )
        if not artifacts or not sources or not runs:
            raise AcceptanceError("incomplete_evidence_manifest")
        _unique((item.id for item in artifacts), "duplicate_evidence_artifact")
        _unique((item.id for item in sources), "duplicate_evidence_source")
        _unique((item.environment for item in runs), "duplicate_environment_run")
        object.__setattr__(self, "artifacts", tuple(sorted(artifacts, key=lambda item: item.id)))
        object.__setattr__(self, "sources", tuple(sorted(sources, key=lambda item: item.id)))
        object.__setattr__(self, "runs", tuple(sorted(runs, key=lambda item: _environment_key(item.environment))))

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value())

    def canonical_value(self) -> dict[str, object]:
        return {
                "runId": self.run_id,
                "schema": self.schema,
                "harnessVersion": self.harness_version,
                "catalogSha256": self.catalog_sha256,
                "fixtureCatalogSha256": self.fixture_catalog_sha256,
                "artifacts": [
                    {"id": item.id, "sha256": item.sha256}
                    for item in self.artifacts
                ],
                "sources": [
                    {
                        "id": item.id,
                        "repository": item.repository,
                        "revision": item.revision,
                    }
                    for item in self.sources
                ],
                "runs": [
                    {
                        "environment": _environment_value(run.environment),
                        "registrationOrders": [list(order) for order in run.registration_orders],
                        "seed": run.seed,
                        "results": [
                            {
                                "evidenceId": result.evidence_id,
                                "status": result.status.value,
                                "observationSha256": result.observation_sha256,
                                "retryCount": result.retry_count,
                                "warnings": list(result.warnings),
                                "errors": list(result.errors),
                                "exclusions": list(result.exclusions),
                            }
                            for result in run.results
                        ],
                    }
                    for run in self.runs
                ],
            }


def load_acceptance_catalog(path: str | Path) -> AcceptanceCatalog:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return AcceptanceCatalog(
            id=payload["id"],
            version=payload["version"],
            environments=tuple(
                EnvironmentTuple(
                    item["python"],
                    item["comfyuiBackend"],
                    item["comfyuiFrontend"],
                    item["renderer"],
                )
                for item in payload["environments"]
            ),
            fixture_catalog_sha256=payload["fixtureCatalogSha256"],
            requirements=tuple(
                EvidenceRequirement(
                    item["id"],
                    EvidenceOwner(item["owner"]),
                    tuple(item.get("fixtureIds", ())),
                    tuple(item.get("allowedSinks", ())),
                )
                for item in payload["requirements"]
            ),
            schema=payload["schema"],
        )
    except AcceptanceError:
        raise
    except Exception:
        raise AcceptanceError("catalog_load_failed") from None


def _environment_value(environment: EnvironmentTuple) -> dict[str, str]:
    return {
        "python": environment.python,
        "comfyuiBackend": environment.comfyui_backend,
        "comfyuiFrontend": environment.comfyui_frontend,
        "renderer": environment.renderer,
    }


def _environment_key(environment: EnvironmentTuple) -> tuple[str, str, str, str]:
    return (
        environment.python,
        environment.comfyui_backend,
        environment.comfyui_frontend,
        environment.renderer,
    )


def _stable(value: object, code: str) -> None:
    if not is_stable_id(value):
        raise AcceptanceError(code)


def _sha(value: object, code: str) -> None:
    if not is_sha256(value):
        raise AcceptanceError(code)


def _stable_values(values, code: str) -> tuple[str, ...]:
    try:
        normalized = tuple(values)
    except TypeError:
        raise AcceptanceError(code) from None
    if any(not is_stable_id(value) for value in normalized):
        raise AcceptanceError(code)
    _unique(normalized, code)
    return tuple(sorted(normalized))


def _ordered_stable_values(values, code: str) -> tuple[str, ...]:
    try:
        normalized = tuple(values)
    except TypeError:
        raise AcceptanceError(code) from None
    if any(not is_stable_id(value) for value in normalized):
        raise AcceptanceError(code)
    _unique(normalized, code)
    return normalized


def _unique(values, code: str) -> None:
    normalized = tuple(values)
    if len(normalized) != len(set(normalized)):
        raise AcceptanceError(code)
