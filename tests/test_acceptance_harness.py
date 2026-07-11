from __future__ import annotations

import hashlib
import itertools
import logging
import warnings
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from helto_privacy import (
    ACCEPTANCE_CATALOG_V1,
    AcceptanceCase,
    AcceptanceCatalog,
    AcceptanceEnvironmentRun,
    AcceptanceError,
    AcceptanceEvidence,
    AcceptanceEvidenceManifest,
    AcceptanceObservation,
    AcceptanceRunner,
    AcceptanceSkip,
    AcceptanceXfail,
    ArtifactIdentity,
    CanaryKind,
    CanaryLeakOracle,
    CaseOutcome,
    ContractAdapterCase,
    ContractAdapterResult,
    ContractSurface,
    DeterministicFaultController,
    EvidenceArtifact,
    EvidenceOwner,
    EvidenceRequirement,
    EvidenceResult,
    EvidenceSource,
    EvidenceStatus,
    EnvironmentTuple,
    FaultKind,
    FaultSpec,
    FixtureKind,
    HistoricalFixtureCatalog,
    HistoricalFixtureEntry,
    InjectedAcceptanceBaseFault,
    InjectedAcceptanceFault,
    ObservationSink,
    ProfileIdentity,
    RegistrationOrderRunner,
    RollbackClass,
    SourceIdentity,
    StaticCheckRule,
    SuiteManifest,
    SyntheticCanary,
    scan_consumer_privacy_duplication,
    sign_acceptance_evidence,
    static_check_digest,
    verify_acceptance_evidence,
    verify_fixture_files,
    verify_regenerated_fixtures,
    load_builtin_acceptance_catalog,
    load_builtin_historical_fixture_catalog,
    load_signed_acceptance_evidence,
)
from helto_privacy.acceptance.generate_fixtures import (
    fixture_names,
    regenerate_fixture,
)


def test_acceptance_catalog_has_stable_versioned_identity():
    catalog = AcceptanceCatalog(
        id="synthetic-catalog",
        version=1,
        environments=(
            EnvironmentTuple("3.13.14", "comfy-e2a6e30d", "1.45.20", "legacy"),
        ),
        fixture_catalog_sha256="0" * 64,
        requirements=(
            EvidenceRequirement(
                "shared.synthetic-contract",
                EvidenceOwner.SHARED,
            ),
        ),
    )

    assert catalog.schema == ACCEPTANCE_CATALOG_V1
    assert len(catalog.digest) == 64


def test_builtin_catalogs_are_exactly_bound_and_historical_fixtures_regenerate():
    fixture_catalog = load_builtin_historical_fixture_catalog()
    catalog = load_builtin_acceptance_catalog()
    root = Path(__file__).parent / "fixtures" / "historical"

    assert catalog.fixture_catalog_sha256 == fixture_catalog.digest
    assert {environment.renderer for environment in catalog.environments} == {
        "legacy",
        "vue",
    }
    assert {requirement.id for requirement in catalog.requirements} >= {
        "fixtures.historical-readers",
        "consumer.real-adapters",
        "registration.all-orders",
        "oracle.synthetic-canaries",
        "faults.deterministic-campaigns",
    }
    verify_fixture_files(fixture_catalog, root)
    generated = {name: regenerate_fixture(name) for name in fixture_names()}
    verify_regenerated_fixtures(
        fixture_catalog,
        lambda entry: generated[entry.source_path],
    )


ENVIRONMENT = EnvironmentTuple(
    "3.13.14",
    "comfy-e2a6e30d",
    "1.45.20",
    "legacy",
)
PROFILE_IDS = ("aio", "director", "smart-prompt", "utils")


def _catalog(*requirements: EvidenceRequirement) -> AcceptanceCatalog:
    return AcceptanceCatalog(
        id="synthetic-catalog",
        version=1,
        environments=(ENVIRONMENT,),
        fixture_catalog_sha256="1" * 64,
        requirements=requirements
        or (EvidenceRequirement("shared.synthetic", EvidenceOwner.SHARED),),
    )


def _pass_result(evidence_id: str) -> EvidenceResult:
    return EvidenceResult(
        evidence_id,
        EvidenceStatus.PASS,
        hashlib.sha256(evidence_id.encode("utf-8")).hexdigest(),
    )


def _evidence_manifest(catalog: AcceptanceCatalog, result=None):
    results = (
        (result,)
        if result is not None
        else tuple(_pass_result(item.id) for item in catalog.requirements)
    )
    return AcceptanceEvidenceManifest(
        run_id="synthetic-run",
        harness_version="acceptance-v1",
        catalog_sha256=catalog.digest,
        fixture_catalog_sha256=catalog.fixture_catalog_sha256,
        artifacts=tuple(EvidenceArtifact(f"artifact-{index}", str(index) * 64) for index in range(1, 6)),
        sources=tuple(
            EvidenceSource(
                f"artifact-{index}",
                f"https://example.invalid/repo-{index}",
                str(index) * 40,
            )
            for index in range(1, 6)
        ),
        runs=(
            AcceptanceEnvironmentRun(
                ENVIRONMENT,
                tuple(itertools.permutations(PROFILE_IDS)),
                12345,
                results,
            ),
        ),
    )


def _suite(catalog: AcceptanceCatalog, evidence: AcceptanceEvidenceManifest):
    artifacts = tuple(
        ArtifactIdentity(
            f"artifact-{index}",
            f"distribution-{index}",
            "1.0.0",
            f"artifact-{index}.whl",
            str(index) * 64,
            SourceIdentity(
                f"https://example.invalid/repo-{index}",
                str(index) * 40,
            ),
        )
        for index in range(1, 6)
    )
    profiles = tuple(
        ProfileIdentity(
            profile_id,
            f"distribution-{index}",
            str(index + 5) * 64,
        )
        for index, profile_id in enumerate(PROFILE_IDS, start=1)
    )
    return SuiteManifest(
        id="synthetic-suite",
        artifacts=artifacts,
        profiles=profiles,
        environments=(ENVIRONMENT,),
        acceptance=AcceptanceEvidence(
            evidence.run_id,
            evidence.digest,
            catalog.digest,
        ),
        previous_suite_id=None,
        rollback=RollbackClass.DATA_SNAPSHOT_REQUIRED_AFTER_ACTIVATION,
    )


def test_signed_evidence_is_bound_to_exact_suite_and_complete_zero_waiver_gate():
    catalog = _catalog(
        EvidenceRequirement("shared.contract", EvidenceOwner.SHARED),
        EvidenceRequirement("consumer.adapters", EvidenceOwner.CONSUMER),
    )
    evidence = _evidence_manifest(catalog)
    suite = _suite(catalog, evidence)
    private_key = Ed25519PrivateKey.generate()
    signed = sign_acceptance_evidence(
        evidence,
        suite.digest,
        "acceptance-signer",
        private_key,
    )

    verified = verify_acceptance_evidence(
        signed,
        catalog,
        suite,
        {"acceptance-signer": private_key.public_key()},
    )

    assert verified is evidence
    assert signed.evidence_sha256 == suite.acceptance.evidence_sha256
    assert signed.suite_manifest_digest == suite.digest


def test_signed_evidence_has_machine_readable_canonical_round_trip(tmp_path):
    catalog = _catalog()
    evidence = _evidence_manifest(catalog)
    suite = _suite(catalog, evidence)
    key = Ed25519PrivateKey.generate()
    signed = sign_acceptance_evidence(evidence, suite.digest, "signer", key)
    path = tmp_path / "acceptance-evidence.json"
    path.write_bytes(signed.canonical_bytes())

    loaded = load_signed_acceptance_evidence(path)

    assert loaded == signed
    assert loaded.canonical_bytes() == signed.canonical_bytes()


@pytest.mark.parametrize(
    "bad_result",
    (
        EvidenceResult("shared.synthetic", EvidenceStatus.SKIP, "2" * 64),
        EvidenceResult("shared.synthetic", EvidenceStatus.XFAIL, "2" * 64),
        EvidenceResult("shared.synthetic", EvidenceStatus.FAIL, "2" * 64),
        EvidenceResult(
            "shared.synthetic",
            EvidenceStatus.PASS,
            "2" * 64,
            retry_count=1,
        ),
        EvidenceResult(
            "shared.synthetic",
            EvidenceStatus.PASS,
            "2" * 64,
            warnings=("unexpected-warning",),
        ),
        EvidenceResult(
            "shared.synthetic",
            EvidenceStatus.PASS,
            "2" * 64,
            errors=("unrelated-failure",),
        ),
        EvidenceResult(
            "shared.synthetic",
            EvidenceStatus.PASS,
            "2" * 64,
            exclusions=("unsupported-cell",),
        ),
    ),
)
def test_skips_xfails_retries_noise_and_exclusions_all_block_gate(bad_result):
    catalog = _catalog(EvidenceRequirement("shared.synthetic", EvidenceOwner.SHARED))
    evidence = _evidence_manifest(catalog, bad_result)
    suite = _suite(catalog, evidence)
    key = Ed25519PrivateKey.generate()
    signed = sign_acceptance_evidence(evidence, suite.digest, "signer", key)

    with pytest.raises(AcceptanceError) as failure:
        verify_acceptance_evidence(
            signed,
            catalog,
            suite,
            {"signer": key.public_key()},
        )

    assert failure.value.code == "zero_waiver_gate_failed"


def test_canary_oracle_allows_only_declared_sink_and_never_allows_key_bytes():
    prompt = SyntheticCanary("prompt", "SYNTHETIC_PROMPT_CANARY")
    key = SyntheticCanary(
        "key",
        b"SYNTHETIC_KEY_BYTES_CANARY",
        CanaryKind.KEY,
    )
    oracle = CanaryLeakOracle((prompt, key))

    oracle.assert_allowed(
        (
            AcceptanceObservation(
                ObservationSink.UI_PAYLOAD,
                {"prompt": "SYNTHETIC_PROMPT_CANARY"},
            ),
        ),
        (ObservationSink.UI_PAYLOAD.value,),
    )
    with pytest.raises(AcceptanceError) as forbidden:
        oracle.assert_allowed(
            (
                AcceptanceObservation(
                    ObservationSink.LOG,
                    "SYNTHETIC_PROMPT_CANARY",
                ),
            ),
            (ObservationSink.UI_PAYLOAD.value,),
        )
    assert forbidden.value.code == "synthetic_canary_leak"
    with pytest.raises(AcceptanceError) as key_leak:
        oracle.assert_allowed(
            (
                AcceptanceObservation(
                    ObservationSink.UI_PAYLOAD,
                    b"SYNTHETIC_KEY_BYTES_CANARY",
                ),
            ),
            (ObservationSink.UI_PAYLOAD.value,),
        )
    assert key_leak.value.code == "synthetic_canary_leak"


def test_deterministic_fault_controller_replays_exception_and_baseexception():
    controller = DeterministicFaultController(
        97,
        (
            FaultSpec("persist", 2),
            FaultSpec("cleanup", 1, FaultKind.BASE_EXCEPTION),
        ),
    )

    controller.checkpoint("persist")
    with pytest.raises(InjectedAcceptanceFault):
        controller.checkpoint("persist")
    with pytest.raises(InjectedAcceptanceBaseFault):
        controller.checkpoint("cleanup")
    assert controller.randrange(1000) == DeterministicFaultController(97).randrange(1000)


def test_acceptance_runner_supplies_declared_fault_campaign_to_case():
    catalog = _catalog(EvidenceRequirement("fault.cleanup", EvidenceOwner.SHARED))

    def exercise(context):
        try:
            context.faults.checkpoint("cleanup")
        except InjectedAcceptanceBaseFault:
            return CaseOutcome()
        raise AssertionError("declared fault did not run")

    run = AcceptanceRunner().run(
        catalog,
        ENVIRONMENT,
        tuple(itertools.permutations(PROFILE_IDS)),
        42,
        (AcceptanceCase("fault.cleanup", exercise),),
        fault_campaigns={
            "fault.cleanup": (FaultSpec("cleanup", 1, FaultKind.BASE_EXCEPTION),)
        },
    )

    assert run.results[0].status is EvidenceStatus.PASS


def test_registration_order_runner_executes_all_24_orders_and_duplicate_imports():
    state = []
    duplicate_calls = 0

    def reset():
        nonlocal duplicate_calls
        state.clear()
        duplicate_calls = 0

    def register(identifier):
        nonlocal duplicate_calls
        if identifier in state:
            duplicate_calls += 1
            return
        state.append(identifier)

    evidence = RegistrationOrderRunner().run(
        PROFILE_IDS,
        reset,
        register,
        lambda: {"registered": sorted(state), "duplicates": duplicate_calls},
    )

    assert len(evidence.orders) == 24
    assert set(evidence.orders) == set(itertools.permutations(PROFILE_IDS))
    assert len(evidence.snapshot_sha256) == 64


def test_registration_order_runner_rejects_order_dependent_state():
    state = []

    with pytest.raises(AcceptanceError) as mismatch:
        RegistrationOrderRunner().run(
            PROFILE_IDS,
            state.clear,
            lambda identifier: state.append(identifier),
            lambda: list(state),
        )

    assert mismatch.value.code == "registration_order_mismatch"


def test_acceptance_runner_captures_contract_reach_leaks_warnings_and_skips():
    catalog = _catalog(
        EvidenceRequirement("contract.adapter", EvidenceOwner.CONSUMER),
        EvidenceRequirement("shared.warning", EvidenceOwner.SHARED),
        EvidenceRequirement("shared.skip", EvidenceOwner.SHARED),
    )

    def warning_case(_context):
        warnings.warn("synthetic warning")
        logging.error("synthetic error")
        return CaseOutcome()

    def skip_case(_context):
        raise AcceptanceSkip()

    run = AcceptanceRunner().run(
        catalog,
        ENVIRONMENT,
        tuple(itertools.permutations(PROFILE_IDS)),
        42,
        (
            ContractAdapterCase(
                "contract.adapter",
                ContractSurface.WORKFLOW,
                "workflow.protect",
                lambda _context: ContractAdapterResult(("workflow.protect",)),
            ),
            AcceptanceCase("shared.warning", warning_case),
            AcceptanceCase("shared.skip", skip_case),
        ),
    )
    results = {item.evidence_id: item for item in run.results}

    assert results["contract.adapter"].status is EvidenceStatus.PASS
    assert results["shared.warning"].status is EvidenceStatus.FAIL
    assert results["shared.warning"].warnings == ("unexpected-warning",)
    assert results["shared.warning"].errors == ("unexpected-error-log",)
    assert results["shared.skip"].status is EvidenceStatus.SKIP
    assert results["shared.skip"].retry_count == 0


def test_contract_adapter_case_fails_when_shared_handle_was_not_reached():
    catalog = _catalog(EvidenceRequirement("contract.adapter", EvidenceOwner.CONSUMER))
    run = AcceptanceRunner().run(
        catalog,
        ENVIRONMENT,
        tuple(itertools.permutations(PROFILE_IDS)),
        1,
        (
            ContractAdapterCase(
                "contract.adapter",
                ContractSurface.RECORD,
                "records.reveal",
                lambda _context: ContractAdapterResult(("local.mock",)),
            ),
        ),
    )

    assert run.results[0].status is EvidenceStatus.FAIL
    assert run.results[0].errors == ("case-failure",)


def test_static_duplication_checks_report_consumer_privacy_engines_only_by_digest():
    rules = (
        StaticCheckRule("aes", r"AESGCM\s*\("),
        StaticCheckRule("local-encrypt", r"def encrypt_state\s*\("),
    )
    violations = scan_consumer_privacy_duplication(
        {
            "consumer/privacy.py": "from cryptography import AESGCM\nAESGCM(key)\ndef encrypt_state(value): ...",
            "consumer/domain.py": "def normalize_queue(value): ...",
        },
        rules,
    )

    assert [(item.rule_id, item.source_id) for item in violations] == [
        ("aes", "consumer/privacy.py"),
        ("local-encrypt", "consumer/privacy.py"),
    ]
    assert len(static_check_digest(violations)) == 64


def test_historical_fixture_catalog_verifies_files_and_reproducible_generator(tmp_path):
    payload = b"SYNTHETIC_GENUINE_HISTORICAL_FIXTURE"
    fixture_path = tmp_path / "historical.json"
    fixture_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    historical = HistoricalFixtureEntry(
        id="historical-state",
        kind=FixtureKind.HISTORICAL,
        source_path="historical.json",
        fixture_sha256=digest,
        ciphertext_sha256="3" * 64,
        expected_normalized_sha256="4" * 64,
        reader_id="state-v1",
        format="aes-gcm-v1",
        schema="helto.synthetic",
        purpose=None,
        producer_repository="https://example.invalid/repo",
        producer_commit="a" * 40,
        producer_function="privacy.py:encrypt_state",
        generator_command=("python", "generate.py", "historical-state"),
        generator_environment="python-cryptography-v1",
        generator_environment_sha256="6" * 64,
        key_provenance="sha256:synthetic-key",
    )
    derived = HistoricalFixtureEntry(
        id="historical-state-tampered",
        kind=FixtureKind.DERIVED,
        source_path="historical.json",
        fixture_sha256=digest,
        ciphertext_sha256="5" * 64,
        expected_normalized_sha256="4" * 64,
        reader_id="state-v1",
        format="aes-gcm-v1",
        schema="helto.synthetic",
        purpose=None,
        producer_repository=None,
        producer_commit=None,
        producer_function=None,
        generator_command=("python", "generate.py", "historical-state-tampered"),
        generator_environment="python-cryptography-v1",
        generator_environment_sha256="6" * 64,
        key_provenance=None,
        source_fixture_id="historical-state",
        mutation="flip-final-byte",
    )
    catalog = HistoricalFixtureCatalog(
        "synthetic-fixtures",
        1,
        (derived, historical),
    )

    verify_fixture_files(catalog, tmp_path)
    verify_regenerated_fixtures(catalog, lambda _entry: payload)
    assert [entry.id for entry in catalog.entries] == [
        "historical-state",
        "historical-state-tampered",
    ]
    assert len(catalog.digest) == 64

    fixture_path.write_bytes(b"tampered")
    with pytest.raises(AcceptanceError) as mismatch:
        verify_fixture_files(catalog, tmp_path)
    assert mismatch.value.code == "fixture_file_digest_mismatch"
