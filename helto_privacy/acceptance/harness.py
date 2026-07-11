"""Contract cases, leak oracle, deterministic faults, and order runner."""

from __future__ import annotations

import hashlib
import itertools
import logging
import random
import warnings
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum

from .._suite_codec import canonical_json_bytes, is_stable_id
from ..suite import EnvironmentTuple
from .models import (
    AcceptanceCatalog,
    AcceptanceEnvironmentRun,
    AcceptanceError,
    EvidenceResult,
    EvidenceStatus,
)


class ObservationSink(str, Enum):
    WORKFLOW = "workflow"
    EXECUTION = "execution"
    RECORD_SHELL = "record-shell"
    ROUTE_BODY = "route-body"
    ROUTE_HEADER = "route-header"
    ROUTE_URL = "route-url"
    UI_PAYLOAD = "ui-payload"
    DOM = "dom"
    ACCESSIBILITY = "accessibility"
    LOG = "log"
    EXCEPTION = "exception"
    FILENAME = "filename"
    CACHE = "cache"
    TEMP = "temp"
    SIDECAR = "sidecar"
    METADATA = "metadata"
    CONSOLE = "console"
    NETWORK = "network"
    ARTIFACT = "artifact"


class CanaryKind(str, Enum):
    PRODUCT = "product"
    KEY = "key"


@dataclass(frozen=True, slots=True)
class SyntheticCanary:
    id: str
    value: str | bytes = field(repr=False, compare=False)
    kind: CanaryKind = CanaryKind.PRODUCT

    def __post_init__(self) -> None:
        if not is_stable_id(self.id):
            raise AcceptanceError("invalid_canary_id")
        if not isinstance(self.value, (str, bytes)) or not self.value:
            raise AcceptanceError("invalid_canary_value")
        if not isinstance(self.kind, CanaryKind):
            raise AcceptanceError("invalid_canary_kind")


@dataclass(frozen=True, slots=True)
class AcceptanceObservation:
    sink: ObservationSink
    value: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.sink, ObservationSink):
            raise AcceptanceError("invalid_observation_sink")


class CanaryLeakOracle:
    def __init__(self, canaries: Iterable[SyntheticCanary]) -> None:
        try:
            values = tuple(canaries)
        except TypeError:
            raise AcceptanceError("invalid_canary_set") from None
        if any(not isinstance(item, SyntheticCanary) for item in values):
            raise AcceptanceError("invalid_canary_set")
        ids = tuple(item.id for item in values)
        if len(ids) != len(set(ids)):
            raise AcceptanceError("duplicate_canary_id")
        encoded = tuple(_canary_bytes(item) for item in values)
        if len(encoded) != len(set(encoded)):
            raise AcceptanceError("duplicate_canary_value")
        self._canaries = values

    def assert_allowed(
        self,
        observations: Iterable[AcceptanceObservation],
        allowed_sinks: Iterable[str],
    ) -> None:
        try:
            values = tuple(observations)
            allowed = frozenset(str(value) for value in allowed_sinks)
        except TypeError:
            raise AcceptanceError("invalid_observation_set") from None
        if any(not isinstance(item, AcceptanceObservation) for item in values):
            raise AcceptanceError("invalid_observation_set")
        for observation in values:
            fragments = tuple(_observation_fragments(observation.value))
            for canary in self._canaries:
                if not any(_contains_canary(fragment, canary) for fragment in fragments):
                    continue
                if canary.kind is CanaryKind.KEY or observation.sink.value not in allowed:
                    raise AcceptanceError("synthetic_canary_leak")


class FaultKind(str, Enum):
    EXCEPTION = "exception"
    BASE_EXCEPTION = "base-exception"


@dataclass(frozen=True, slots=True)
class FaultSpec:
    point: str
    occurrence: int
    kind: FaultKind = FaultKind.EXCEPTION

    def __post_init__(self) -> None:
        if not is_stable_id(self.point):
            raise AcceptanceError("invalid_fault_point")
        if (
            not isinstance(self.occurrence, int)
            or isinstance(self.occurrence, bool)
            or self.occurrence < 1
            or not isinstance(self.kind, FaultKind)
        ):
            raise AcceptanceError("invalid_fault_spec")


class InjectedAcceptanceFault(RuntimeError):
    pass


class InjectedAcceptanceBaseFault(BaseException):
    pass


class DeterministicFaultController:
    def __init__(self, seed: int, faults: Iterable[FaultSpec] = ()) -> None:
        if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
            raise AcceptanceError("invalid_test_seed")
        values = tuple(faults)
        if any(not isinstance(item, FaultSpec) for item in values):
            raise AcceptanceError("invalid_fault_set")
        identities = tuple((item.point, item.occurrence) for item in values)
        if len(identities) != len(set(identities)):
            raise AcceptanceError("duplicate_fault_spec")
        self.seed = seed
        self._faults = {identity: item for identity, item in zip(identities, values)}
        self._counts: dict[str, int] = {}
        self._random = random.Random(seed)

    def checkpoint(self, point: str) -> None:
        if not is_stable_id(point):
            raise AcceptanceError("invalid_fault_point")
        count = self._counts.get(point, 0) + 1
        self._counts[point] = count
        fault = self._faults.get((point, count))
        if fault is None:
            return
        if fault.kind is FaultKind.BASE_EXCEPTION:
            raise InjectedAcceptanceBaseFault()
        raise InjectedAcceptanceFault()

    def randrange(self, stop: int) -> int:
        return self._random.randrange(stop)


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    observations: tuple[AcceptanceObservation, ...] = ()

    def __post_init__(self) -> None:
        values = tuple(self.observations)
        if any(not isinstance(item, AcceptanceObservation) for item in values):
            raise AcceptanceError("invalid_observation_set")
        object.__setattr__(self, "observations", values)


@dataclass(frozen=True, slots=True)
class AcceptanceCase:
    evidence_id: str
    exercise: Callable[[AcceptanceCaseContext], CaseOutcome | None] = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not is_stable_id(self.evidence_id) or not callable(self.exercise):
            raise AcceptanceError("invalid_acceptance_case")


class ContractSurface(str, Enum):
    AUTHORIZATION = "authorization"
    MODE = "mode"
    WORKFLOW = "workflow"
    RECORD = "record"
    SINGLETON = "singleton"
    ARTIFACT = "artifact"
    EXECUTION = "execution"
    LEGACY = "legacy"


@dataclass(frozen=True, slots=True)
class ContractAdapterResult:
    reached_shared_handles: tuple[str, ...]
    observations: tuple[AcceptanceObservation, ...] = ()

    def __post_init__(self) -> None:
        reached = tuple(self.reached_shared_handles)
        if not reached or any(not is_stable_id(value) for value in reached):
            raise AcceptanceError("invalid_contract_adapter_result")
        if len(reached) != len(set(reached)):
            raise AcceptanceError("invalid_contract_adapter_result")
        observations = tuple(self.observations)
        if any(not isinstance(item, AcceptanceObservation) for item in observations):
            raise AcceptanceError("invalid_contract_adapter_result")
        object.__setattr__(self, "reached_shared_handles", tuple(sorted(reached)))
        object.__setattr__(self, "observations", observations)


@dataclass(frozen=True, slots=True)
class ContractAdapterCase:
    evidence_id: str
    surface: ContractSurface
    shared_handle_id: str
    exercise: Callable[[AcceptanceCaseContext], ContractAdapterResult] = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            not is_stable_id(self.evidence_id)
            or not isinstance(self.surface, ContractSurface)
            or not is_stable_id(self.shared_handle_id)
            or not callable(self.exercise)
        ):
            raise AcceptanceError("invalid_contract_adapter_case")

    def as_case(self) -> AcceptanceCase:
        def run(context: AcceptanceCaseContext) -> CaseOutcome:
            result = self.exercise(context)
            if (
                not isinstance(result, ContractAdapterResult)
                or self.shared_handle_id not in result.reached_shared_handles
            ):
                raise AcceptanceError("shared_handle_not_reached")
            return CaseOutcome(result.observations)

        return AcceptanceCase(self.evidence_id, run)


@dataclass(frozen=True, slots=True)
class AcceptanceCaseContext:
    evidence_id: str
    faults: DeterministicFaultController = field(repr=False, compare=False)


class AcceptanceSkip(RuntimeError):
    pass


class AcceptanceXfail(RuntimeError):
    pass


class _ErrorLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.seen = False

    def emit(self, _record: logging.LogRecord) -> None:
        self.seen = True


class AcceptanceRunner:
    def run(
        self,
        catalog: AcceptanceCatalog,
        environment: EnvironmentTuple,
        registration_orders: Iterable[tuple[str, ...]],
        seed: int,
        cases: Iterable[AcceptanceCase | ContractAdapterCase],
        canaries: Iterable[SyntheticCanary] = (),
        fault_campaigns: Mapping[str, Iterable[FaultSpec]] | None = None,
    ) -> AcceptanceEnvironmentRun:
        if not isinstance(catalog, AcceptanceCatalog) or environment not in catalog.environments:
            raise AcceptanceError("unsupported_environment_tuple")
        prepared: dict[str, AcceptanceCase] = {}
        for candidate in tuple(cases):
            case = candidate.as_case() if isinstance(candidate, ContractAdapterCase) else candidate
            if not isinstance(case, AcceptanceCase) or case.evidence_id in prepared:
                raise AcceptanceError("invalid_acceptance_case_set")
            prepared[case.evidence_id] = case
        required = {item.id: item for item in catalog.requirements}
        if set(prepared) != set(required):
            raise AcceptanceError("acceptance_case_set_incomplete")
        if fault_campaigns is None:
            fault_campaigns = {}
        if not isinstance(fault_campaigns, Mapping) or any(
            evidence_id not in required for evidence_id in fault_campaigns
        ):
            raise AcceptanceError("invalid_fault_campaigns")
        campaigns: dict[str, tuple[FaultSpec, ...]] = {}
        try:
            for evidence_id, specifications in fault_campaigns.items():
                values = tuple(specifications)
                if any(not isinstance(item, FaultSpec) for item in values):
                    raise AcceptanceError("invalid_fault_campaigns")
                campaigns[evidence_id] = values
        except TypeError:
            raise AcceptanceError("invalid_fault_campaigns") from None
        oracle = CanaryLeakOracle(canaries)
        results = tuple(
            self._run_case(
                prepared[evidence_id],
                required[evidence_id].allowed_sinks,
                DeterministicFaultController(seed, campaigns.get(evidence_id, ())),
                oracle,
            )
            for evidence_id in sorted(required)
        )
        return AcceptanceEnvironmentRun(
            environment,
            tuple(registration_orders),
            seed,
            results,
        )

    @staticmethod
    def _run_case(
        case: AcceptanceCase,
        allowed_sinks: tuple[str, ...],
        faults: DeterministicFaultController,
        oracle: CanaryLeakOracle,
    ) -> EvidenceResult:
        status = EvidenceStatus.PASS
        errors: list[str] = []
        warning_codes: list[str] = []
        observations: tuple[AcceptanceObservation, ...] = ()
        log_handler = _ErrorLogHandler()
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                try:
                    outcome = case.exercise(AcceptanceCaseContext(case.evidence_id, faults))
                    if outcome is None:
                        outcome = CaseOutcome()
                    if not isinstance(outcome, CaseOutcome):
                        raise AcceptanceError("invalid_case_outcome")
                    observations = outcome.observations
                    oracle.assert_allowed(observations, allowed_sinks)
                except AcceptanceSkip:
                    status = EvidenceStatus.SKIP
                    errors.append("skip")
                except AcceptanceXfail:
                    status = EvidenceStatus.XFAIL
                    errors.append("xfail")
                except InjectedAcceptanceBaseFault:
                    status = EvidenceStatus.FAIL
                    errors.append("base-exception")
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException:
                    status = EvidenceStatus.FAIL
                    errors.append("case-failure")
                if caught:
                    status = EvidenceStatus.FAIL
                    warning_codes.append("unexpected-warning")
            if log_handler.seen:
                status = EvidenceStatus.FAIL
                errors.append("unexpected-error-log")
        finally:
            root_logger.removeHandler(log_handler)
        return EvidenceResult(
            case.evidence_id,
            status,
            _observation_digest(observations),
            retry_count=0,
            warnings=tuple(sorted(set(warning_codes))),
            errors=tuple(sorted(set(errors))),
            exclusions=(),
        )


@dataclass(frozen=True, slots=True)
class RegistrationOrderEvidence:
    orders: tuple[tuple[str, ...], ...]
    snapshot_sha256: str


class RegistrationOrderRunner:
    def run(
        self,
        identifiers: Iterable[str],
        reset: Callable[[], None],
        register: Callable[[str], None],
        observe: Callable[[], object],
    ) -> RegistrationOrderEvidence:
        ids = tuple(sorted(identifiers))
        if (
            len(ids) != 4
            or len(set(ids)) != 4
            or any(not is_stable_id(value) for value in ids)
            or not all(callable(item) for item in (reset, register, observe))
        ):
            raise AcceptanceError("invalid_registration_runner_input")
        orders = tuple(itertools.permutations(ids))
        baseline = None
        for order in orders:
            try:
                reset()
                for identifier in order:
                    register(identifier)
                register(order[0])
                snapshot = canonical_json_bytes(observe())
            except Exception:
                raise AcceptanceError("registration_order_failed") from None
            if baseline is None:
                baseline = snapshot
            elif snapshot != baseline:
                raise AcceptanceError("registration_order_mismatch")
        return RegistrationOrderEvidence(
            orders,
            hashlib.sha256(baseline or b"").hexdigest(),
        )


def _canary_bytes(canary: SyntheticCanary) -> bytes:
    return canary.value.encode("utf-8") if isinstance(canary.value, str) else canary.value


def _contains_canary(fragment: str | bytes, canary: SyntheticCanary) -> bool:
    if isinstance(fragment, str):
        value = canary.value.decode("utf-8", "ignore") if isinstance(canary.value, bytes) else canary.value
        return bool(value) and value in fragment
    return _canary_bytes(canary) in fragment


def _observation_fragments(value: object):
    if isinstance(value, bytes):
        yield value
    elif isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _observation_fragments(key)
            yield from _observation_fragments(item)
    elif isinstance(value, Iterable):
        for item in value:
            yield from _observation_fragments(item)
    elif value is not None:
        yield str(value)


def _observation_digest(observations: tuple[AcceptanceObservation, ...]) -> str:
    values = [
        {
            "sink": observation.sink.value,
            "valueSha256": hashlib.sha256(
                b"\x00".join(
                    fragment.encode("utf-8") if isinstance(fragment, str) else fragment
                    for fragment in _observation_fragments(observation.value)
                )
            ).hexdigest(),
        }
        for observation in observations
    ]
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()
