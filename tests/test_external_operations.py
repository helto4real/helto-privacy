from __future__ import annotations

import asyncio
import base64

import pytest

import helto_privacy.external_operation_state as operation_state
import helto_privacy.keystore as keystore
import helto_privacy.runtime as runtime
import helto_privacy.suite_runtime as suite_runtime
from helto_privacy.external_mode_transition import (
    ExternalModeTransitionError,
    reserve_external_transition,
)
from helto_privacy.external_operations import (
    ExternalOperationCapture,
    ExternalOperationClassification,
    ExternalOperationDisposition,
    ExternalOperationError,
    apply_external_operation,
    prepare_external_operation,
    resume_external_operation,
    rollback_external_operation,
)
from helto_privacy.mode import DeclaredPrivacyMode
from helto_privacy.opaque_references import ProtectedOperationAdapterResult
from helto_privacy.profile import (
    AdapterSlot,
    ExternalOperationBinding,
    ExternalOperationPolicy,
    ExternalTransitionPolicy,
    FieldLocation,
    FieldLocationKind,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProtectedOperation,
    ProtectedStateAuthority,
    ProfileResource,
    ResourceKind,
    SafeDiagnosticField,
    SafeDiagnosticKind,
    SensitiveFieldClass,
    SensitiveFieldDeclaration,
)
from helto_privacy.protected_operations import ProtectedOperationError
from tests.mode_protocol_fixtures import ModeSourceProtocolFixture


PASSWORD = "synthetic external operation password"
REQUEST_ID = "hp-operation-request-" + "r" * 24
ORIGINAL = b'{"captured":false}'
TARGET = b'{"captured":true}'
OWNER = {
    "rootGraphId": "root",
    "graphId": "root",
    "nodeId": "node-7",
    "fieldId": "timeline-state",
}


class Request:
    def __init__(self, token: str):
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeSource(ModeSourceProtocolFixture):
    def __init__(self):
        self.declared = DeclaredPrivacyMode.PRIVATE

    def read_declared_mode(self, _scope_id):
        return self.declared

    def write_declared_mode(self, _scope_id, declared):
        self.declared = declared


class ExternalFieldAdapter:
    def capture(self, *_args):
        return None

    def normalize(self, value, *_args):
        return value

    def apply_revealed(self, *_args):
        return None

    def clear_plaintext(self, *_args):
        return None

    def decode_mode_transition_representation(self, value, _context):
        return value

    def classify_mode_transition_representation(self, _value, _context):
        return "private"

    def normalize_mode_transition_value(self, value, _context):
        return value

    def encode_public_mode_transition(self, value, _context):
        return value


class ExternalOperationAdapter:
    def __init__(self):
        self.phase = ExternalOperationDisposition.ABSENT
        self.calls: list[tuple[str, object]] = []
        self.fail_prepare_after_mutation = False
        self.fail_prepare_before_mutation = False
        self.fail_finalize_after_mutation = False

    def _called(self, name, dependencies):
        self.calls.append((name, dependencies))

    def capture_external_operation(
        self,
        value,
        references,
        invocation,
        _declaration,
        dependencies,
    ):
        self._called("capture", dependencies)
        assert references == {}
        assert invocation.transaction_id.startswith("hp-operation-")
        return ExternalOperationCapture(
            {"takeId": str(value["takeId"])},
            {"captured": True},
        )

    def classify_external_operation(
        self,
        _capture_context,
        invocation,
        _declaration,
        dependencies,
    ):
        self._called("classify", dependencies)
        assert invocation.transaction_id.startswith("hp-operation-")
        if self.phase is ExternalOperationDisposition.PREPARED:
            return ExternalOperationClassification(
                self.phase,
                {"preparedTakeId": "take-7"},
            )
        if self.phase is ExternalOperationDisposition.COMPLETED:
            return ExternalOperationClassification(
                self.phase,
                result=ProtectedOperationAdapterResult(
                    {"privateMetadata": "CANARY", "items": 1},
                ),
            )
        return ExternalOperationClassification(self.phase)

    def prepare_external_operation(
        self,
        _capture_context,
        invocation,
        _declaration,
        dependencies,
    ):
        self._called("prepare", dependencies)
        assert invocation.transaction_id.startswith("hp-operation-")
        if self.fail_prepare_before_mutation:
            raise RuntimeError("synthetic pre-mutation prepare crash")
        self.phase = ExternalOperationDisposition.PREPARED
        if self.fail_prepare_after_mutation:
            raise RuntimeError("synthetic prepare crash")
        return {"preparedTakeId": "take-7"}

    def finalize_external_operation(
        self,
        _prepared_context,
        invocation,
        _declaration,
        dependencies,
    ):
        self._called("finalize", dependencies)
        assert invocation.transaction_id.startswith("hp-operation-")
        self.phase = ExternalOperationDisposition.COMPLETED
        if self.fail_finalize_after_mutation:
            raise RuntimeError("synthetic finalize crash")
        return ProtectedOperationAdapterResult(
            {"privateMetadata": "CANARY", "items": 1},
        )

    def rollback_external_operation(
        self,
        _prepared_context,
        invocation,
        _declaration,
        dependencies,
    ):
        self._called("rollback", dependencies)
        assert invocation.transaction_id.startswith("hp-operation-")
        self.phase = ExternalOperationDisposition.ROLLED_BACK
        return True

    def project(self, payload, _declaration):
        return {"items": int(payload["items"])}


def _profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.external-operation-test",
        distribution="comfyui-external-operation-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource(
                "timeline",
                ResourceKind.WORKFLOW,
                ("timeline-state", "timeline-ui"),
            ),
            ProfileResource(
                "operations",
                ResourceKind.OPERATION,
                ("operation-adapter",),
            ),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("timeline-state", ResourceKind.WORKFLOW, "timeline"),
            AdapterSlot(
                "operation-adapter",
                ResourceKind.OPERATION,
                "operations",
            ),
        ),
        browser_adapters=(
            AdapterSlot(
                "timeline-ui",
                ResourceKind.WORKFLOW,
                "timeline",
                ("TimelineNode",),
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        protected_fields=(
            ProtectedField(
                "timeline-state",
                "timeline",
                "main",
                "timeline-state",
                "timeline-ui",
                ("TimelineNode",),
                FieldLocation(FieldLocationKind.WIDGET, "timeline"),
                "helto.timeline.v1",
                "timeline-state",
                ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW,
                ExternalTransitionPolicy(),
            ),
        ),
        protected_operations=(
            ProtectedOperation(
                "associate-captured-take",
                "operations",
                "operation-adapter",
                None,
                scope_id="main",
                sensitive_fields=(
                    SensitiveFieldDeclaration(
                        "*",
                        SensitiveFieldClass.CONSUMER_DERIVED,
                    ),
                ),
                safe_projection=(
                    SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),
                ),
                external_operation_binding=ExternalOperationBinding(
                    "timeline-state",
                    "timeline-ui",
                    ExternalOperationPolicy(
                        max_identity_bytes=1024,
                        max_original_bytes=1024,
                        max_target_bytes=1024,
                        lease_seconds=30,
                    ),
                ),
            ),
        ),
    )


@pytest.fixture
def external_operation_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(suite_runtime, "require_active_process_suite", lambda: None)
    source = ModeSource()
    adapter = ExternalOperationAdapter()
    pack = runtime.install(
        _profile(),
        {
            "mode": source,
            "timeline-state": ExternalFieldAdapter(),
            "operation-adapter": adapter,
        },
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    return pack, source, adapter, token


def _authorization(pack, token):
    return pack.authorization.authorize_request(
        Request(token),
        "associate-captured-take",
    )


def _prepare(pack, token):
    return asyncio.run(
        prepare_external_operation(
            pack._installation,
            "associate-captured-take",
            _authorization(pack, token),
            request_id=REQUEST_ID,
            owner_identity=OWNER,
            original_exact=ORIGINAL,
            input_value={"takeId": "take-7"},
            references={},
        )
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def test_external_operation_prepares_applies_and_retries_exactly(
    external_operation_pack,
):
    pack, _source, adapter, token = external_operation_pack
    prepared = _prepare(pack, token)

    assert prepared["phase"] == "prepared"
    assert prepared["originalExact"] == _b64(ORIGINAL)
    assert prepared["targetExact"] is None
    assert prepared["browserValue"] == {"captured": True}
    assert prepared["resumeCapability"].startswith("hp-operation-resume-")

    completed = asyncio.run(
        apply_external_operation(
            pack._installation,
            "associate-captured-take",
            prepared["transactionId"],
            _authorization(pack, token),
            resume_capability=prepared["resumeCapability"],
            current_exact=TARGET,
        )
    )
    assert completed["phase"] == "completed"
    assert completed["exact"] == _b64(TARGET)
    assert completed["result"]["data"] == {"items": 1}
    assert "CANARY" not in repr(completed)
    assert completed["receiptId"].startswith("hp-operation-receipt-")

    retried = _prepare(pack, token)
    assert retried == completed
    dependencies = [item for _phase, item in adapter.calls]
    assert all(
        left is not right
        for index, left in enumerate(dependencies)
        for right in dependencies[index + 1 :]
    )
    for dependency in dependencies:
        with pytest.raises(ProtectedOperationError):
            dependency.record("records", "take", "use")


def test_prepare_failure_persists_rollback_required_and_can_be_rolled_back(
    external_operation_pack,
):
    pack, _source, adapter, token = external_operation_pack
    adapter.fail_prepare_after_mutation = True
    with pytest.raises(ExternalOperationError) as failed:
        _prepare(pack, token)
    assert failed.value.code == "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED"

    _revision, records = operation_state.load_external_operation_state()
    assert [record.phase for record in records] == ["rollback-required"]
    adapter.fail_prepare_after_mutation = False
    resumed = _prepare(pack, token)
    assert resumed["phase"] == "rollback-required"

    rolled_back = asyncio.run(
        rollback_external_operation(
            pack._installation,
            "associate-captured-take",
            resumed["transactionId"],
            _authorization(pack, token),
            resume_capability=resumed["resumeCapability"],
        )
    )
    assert rolled_back["phase"] == "rolled-back"
    assert rolled_back["exact"] == _b64(ORIGINAL)


def test_rollback_invokes_cleanup_even_when_prepare_left_no_classifiable_state(
    external_operation_pack,
):
    pack, _source, adapter, token = external_operation_pack
    adapter.fail_prepare_before_mutation = True
    with pytest.raises(ExternalOperationError):
        _prepare(pack, token)
    adapter.fail_prepare_before_mutation = False

    resumed = _prepare(pack, token)
    rolled_back = asyncio.run(
        rollback_external_operation(
            pack._installation,
            "associate-captured-take",
            resumed["transactionId"],
            _authorization(pack, token),
            resume_capability=resumed["resumeCapability"],
        )
    )
    assert rolled_back["phase"] == "rolled-back"
    assert [name for name, _dependencies in adapter.calls].count("rollback") == 1


def test_finalize_crash_is_classified_as_completed_on_rollback(
    external_operation_pack,
):
    pack, _source, adapter, token = external_operation_pack
    prepared = _prepare(pack, token)
    adapter.fail_finalize_after_mutation = True
    with pytest.raises(ExternalOperationError):
        asyncio.run(
            apply_external_operation(
                pack._installation,
                "associate-captured-take",
                prepared["transactionId"],
                _authorization(pack, token),
                resume_capability=prepared["resumeCapability"],
                current_exact=TARGET,
            )
        )
    adapter.fail_finalize_after_mutation = False

    resumed = asyncio.run(
        resume_external_operation(
            pack._installation,
            "associate-captured-take",
            prepared["transactionId"],
            _authorization(pack, token),
            resume_capability=prepared["resumeCapability"],
        )
    )
    assert resumed["phase"] == "rollback-required"
    completed = asyncio.run(
        rollback_external_operation(
            pack._installation,
            "associate-captured-take",
            prepared["transactionId"],
            _authorization(pack, token),
            resume_capability=prepared["resumeCapability"],
        )
    )
    assert completed["phase"] == "completed"
    assert completed["exact"] == _b64(TARGET)


def test_external_operation_fences_capability_tampering_and_normal_dispatch(
    external_operation_pack,
):
    pack, _source, _adapter, token = external_operation_pack
    prepared = _prepare(pack, token)
    with pytest.raises(ExternalOperationError) as fenced:
        asyncio.run(
            resume_external_operation(
                pack._installation,
                "associate-captured-take",
                prepared["transactionId"],
                _authorization(pack, token),
                resume_capability="hp-operation-resume-" + "x" * 43,
            )
        )
    assert fenced.value.code == "PRIVACY_EXTERNAL_OPERATION_FENCED"

    with pytest.raises(ProtectedOperationError) as dispatched:
        asyncio.run(
            pack.operations("operations").dispatch(
                Request(token),
                "associate-captured-take",
                {"takeId": "take-7"},
            )
        )
    assert (
        dispatched.value.code
        == "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID"
    )


def test_external_operation_journal_tamper_fails_closed(external_operation_pack):
    pack, _source, _adapter, token = external_operation_pack
    _prepare(pack, token)
    _revision, records = operation_state.load_external_operation_state()
    record = records[0]
    path = operation_state.external_operation_journal_path(
        record.pack_id,
        record.operation_id,
        record.transaction_id,
        record.journal_digest,
    )
    path.write_bytes(path.read_bytes() + b"tampered")

    with pytest.raises(operation_state.ExternalOperationStateError):
        operation_state.load_external_operation_journal(record)


def test_key_rotation_is_blocked_only_while_external_operation_is_active(
    external_operation_pack,
):
    pack, _source, _adapter, token = external_operation_pack
    prepared = _prepare(pack, token)

    with pytest.raises(keystore.PrivacyKeystoreError) as active:
        keystore.rotate_primary_key(PASSWORD)
    assert "active external protected operation" in str(active.value)

    completed = asyncio.run(
        apply_external_operation(
            pack._installation,
            "associate-captured-take",
            prepared["transactionId"],
            _authorization(pack, token),
            resume_capability=prepared["resumeCapability"],
            current_exact=TARGET,
        )
    )
    rotated = keystore.rotate_primary_key(PASSWORD)
    assert rotated["keystoreLocked"] is False
    assert _prepare(pack, rotated["token"]) == completed


def test_external_mode_transition_is_blocked_by_durable_active_operation(
    external_operation_pack,
):
    pack, _source, _adapter, token = external_operation_pack
    _prepare(pack, token)
    authorization = pack.authorization.authorize_request(
        Request(token),
        "mode.transition.reserve",
    )

    with pytest.raises(ExternalModeTransitionError) as active:
        reserve_external_transition(
            pack._installation,
            "privacy-mode",
            "main",
            "private",
            authorization,
            request_id="external-mode-request-0001",
            coordinator_id="external-coordinator-0001",
            resume_secret="hp-mode-resume-" + "r" * 43,
            offline_representation_count=0,
            expected_mode_epoch=0,
            server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
        )
    assert active.value.code == "PRIVACY_TRANSITION_IN_PROGRESS"
