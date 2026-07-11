"""Shared zero-waiver acceptance catalog and execution harness."""

from .catalogs import (
    ACCEPTANCE_DATA_ROOT,
    BUILTIN_ACCEPTANCE_CATALOG,
    BUILTIN_FIXTURE_GENERATOR_ENVIRONMENT,
    BUILTIN_HISTORICAL_FIXTURE_CATALOG,
    load_builtin_acceptance_catalog,
    load_builtin_historical_fixture_catalog,
)

from .fixtures import (
    HISTORICAL_FIXTURE_CATALOG_V1,
    FixtureKind,
    HistoricalFixtureCatalog,
    HistoricalFixtureEntry,
    load_historical_fixture_catalog,
    verify_fixture_files,
    verify_regenerated_fixtures,
)
from .harness import (
    AcceptanceCase,
    AcceptanceCaseContext,
    AcceptanceObservation,
    AcceptanceRunner,
    AcceptanceSkip,
    AcceptanceXfail,
    CanaryKind,
    CanaryLeakOracle,
    CaseOutcome,
    ContractAdapterCase,
    ContractAdapterResult,
    ContractSurface,
    DeterministicFaultController,
    FaultKind,
    FaultSpec,
    InjectedAcceptanceBaseFault,
    InjectedAcceptanceFault,
    ObservationSink,
    RegistrationOrderEvidence,
    RegistrationOrderRunner,
    SyntheticCanary,
)
from .models import (
    ACCEPTANCE_CATALOG_V1,
    ACCEPTANCE_EVIDENCE_V1,
    AcceptanceCatalog,
    AcceptanceEnvironmentRun,
    AcceptanceError,
    AcceptanceEvidenceManifest,
    EvidenceArtifact,
    EvidenceOwner,
    EvidenceRequirement,
    EvidenceResult,
    EvidenceSource,
    EvidenceStatus,
    load_acceptance_catalog,
)
from .signing import (
    SIGNED_ACCEPTANCE_EVIDENCE_V1,
    SignedAcceptanceEvidence,
    load_signed_acceptance_evidence,
    sign_acceptance_evidence,
    verify_acceptance_evidence,
)
from .static_checks import (
    DEFAULT_CONSUMER_PRIVACY_RULES,
    StaticCheckRule,
    StaticCheckViolation,
    scan_consumer_privacy_duplication,
    static_check_digest,
)


__all__ = [name for name in globals() if not name.startswith("_")]
