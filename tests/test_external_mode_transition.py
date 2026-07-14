import base64
import threading
from dataclasses import replace

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.mode_state as mode_state
import helto_privacy.mode_runtime as mode_runtime
import helto_privacy.runtime as runtime
import helto_privacy.suite_runtime as suite_runtime
import helto_privacy.external_mode_transition as external_transition
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.external_mode_transition import (
    ExternalModeTransitionError,
    acknowledge_external_apply,
    external_transition_status,
    finalize_external_transition,
    heartbeat_external_client,
    prepare_external_transition,
    rebase_external_owner_exact,
    reserve_external_transition,
    resume_external_transition,
    rollback_external_transition,
    verify_external_transition,
)
from helto_privacy.mode import DeclaredPrivacyMode
from helto_privacy.profile import (
    AdapterSlot,
    ExternalTransitionPolicy,
    FieldLocation,
    FieldLocationKind,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProtectedStateAuthority,
    ProfileResource,
    ResourceKind,
)
from tests.mode_protocol_fixtures import ModeSourceProtocolFixture


PASSWORD = "synthetic external mode password"
RESUME_SECRET = "hp-mode-resume-" + "r" * 43
REQUEST_ID = "external-request-0001"
COORDINATOR_ID = "external-coordinator-0001"


class Request:
    def __init__(self, token, *, confirm=False):
        self.headers = {"X-Helto-Privacy-Token": token}
        if confirm:
            self.headers["X-Helto-Privacy-Declassification"] = "confirmed"
        self.cookies = {}


class ModeSource(ModeSourceProtocolFixture):
    def __init__(self):
        self.declared = DeclaredPrivacyMode.PRIVATE
        self.fail_cas = False

    def read_declared_mode(self, _scope_id):
        return self.declared

    def write_declared_mode(self, _scope_id, declared):
        if self.fail_cas:
            self.fail_cas = False
            raise RuntimeError("synthetic source failure")
        self.declared = declared


class ExternalStateCodec:
    def capture(self, *_args):
        return None

    def normalize(self, value, *_args):
        return value

    def apply_revealed(self, *_args):
        return None

    def clear_plaintext(self, *_args):
        return None

    def decode_mode_transition_representation(self, value, _context):
        prefix, payload = value.split(b":", 1)
        if prefix not in {b"private", b"public"}:
            raise ValueError("invalid synthetic representation")
        return payload.decode("utf-8")

    def classify_mode_transition_representation(self, value, _context):
        return value.split(b":", 1)[0].decode("ascii")

    def normalize_mode_transition_value(self, value, _context):
        return {"value": str(value)}

    def encode_public_mode_transition(self, value, _context):
        return b"public:" + value["value"].encode("utf-8")

def _profile():
    return PrivacyProfile(
        id="helto.external-transition-test",
        distribution="comfyui-external-transition-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode-source",)),
            ProfileResource("workflow", ResourceKind.WORKFLOW, ("state", "state-ui")),
        ),
        server_adapters=(
            AdapterSlot("mode-source", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state", ResourceKind.WORKFLOW, "workflow"),
        ),
        browser_adapters=(
            AdapterSlot("state-ui", ResourceKind.WORKFLOW, "workflow", ("ExternalNode",)),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode-source"),),
        protected_fields=(
            ProtectedField(
                "workflow-state",
                "workflow",
                "main",
                "state",
                "state-ui",
                ("ExternalNode",),
                FieldLocation(FieldLocationKind.WIDGET, "state"),
                "helto.external.v1",
                "workflow-state",
                ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW,
                ExternalTransitionPolicy(
                    max_owners=4,
                    max_original_bytes_per_owner=1024,
                    max_target_bytes_per_owner=2048,
                    max_total_bytes=4096,
                    lease_seconds=60,
                ),
            ),
        ),
    )


@pytest.fixture
def external_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(suite_runtime, "require_active_process_suite", lambda: None)
    monkeypatch.setattr(external_transition, "_ACTIVE_CLIENTS", {})
    source = ModeSource()
    pack = runtime.install(_profile(), {"mode-source": source, "state": ExternalStateCodec()})
    token = keystore.initialize_keystore(PASSWORD)["token"]
    return pack, source, token


def _auth(pack, token, operation, *, confirm=False):
    request = Request(token, confirm=confirm)
    if confirm:
        return pack.authorization.authorize_declassification(
            request,
            "main",
            "public",
            operation_id=operation,
        )
    return pack.authorization.authorize_request(request, operation)


def _reserve(pack, token):
    return reserve_external_transition(
        pack._installation,
        "privacy-mode",
        "main",
        "public",
        _auth(pack, token, "mode.transition.reserve", confirm=True),
        request_id=REQUEST_ID,
        coordinator_id=COORDINATOR_ID,
        resume_secret=RESUME_SECRET,
        offline_representation_count=0,
        expected_mode_epoch=0,
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )


def _capability(reservation):
    return {
        "resume_secret": RESUME_SECRET,
        "coordinator_id": COORDINATOR_ID,
        "client_lease": reservation["clientLease"],
        "client_lease_epoch": reservation["clientLeaseEpoch"],
        "mode_epoch": reservation["modeEpoch"],
        "server_boot_epoch": runtime.SERVER_BOOT_EPOCH,
    }


def _owner(original=b"private:synthetic-secret"):
    return {
        "locator": {
            "rootGraphId": "root",
            "graphId": "root",
            "nodeId": "node-7",
            "fieldId": "workflow-state",
        },
        "originalExact": _b64(original),
    }


def _prepare(pack, token, reservation, owners=None):
    return prepare_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.prepare"),
        owners=[_owner()] if owners is None else owners,
        **_capability(reservation),
    )


def test_external_transition_derives_target_server_side_and_completes(external_pack):
    pack, source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)

    assert prepared["ownerCount"] == 1
    assert prepared["pendingOwners"][0]["exact"] == _b64(
        b"public:synthetic-secret"
    )
    owner_id = prepared["pendingOwners"][0]["ownerId"]
    acknowledgements = [{"ownerId": owner_id, "exact": _b64(b"public:synthetic-secret")}]
    applied = acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=acknowledgements,
        **_capability(reservation),
    )
    assert applied["externalPhase"] == "applied"
    verified = verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=acknowledgements,
        snapshot_id="snapshot-generation-0001",
        snapshot_generation=1,
        **_capability(reservation),
    )
    assert verified["externalPhase"] == "verified"
    completed = finalize_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.finalize"),
        **_capability(reservation),
    )

    assert completed == {
        "scopeId": "main",
        "declared": "public",
        "effective": "public",
        "transitionStatus": "idle",
        "modeEpoch": 1,
    }
    assert source.declared is DeclaredPrivacyMode.PUBLIC
    state = mode_state.load_mode_scope_state(pack.profile.id, "main")
    assert state.transition is None
    assert state.cleanup_journal_digest is None
    assert list(mode_state.mode_journal_path(pack.profile.id, "main").parent.glob("*.json")) == []
    retried = finalize_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.finalize"),
        **_capability(reservation),
    )
    assert retried == completed


def test_external_owner_rebase_uses_current_mode_and_fences_stale_or_active_calls(
    external_pack,
):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner_id = prepared["pendingOwners"][0]["ownerId"]
    acknowledgements = [{
        "ownerId": owner_id,
        "exact": _b64(b"public:synthetic-secret"),
    }]
    acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=acknowledgements,
        **_capability(reservation),
    )
    verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=acknowledgements,
        snapshot_id="snapshot-generation-rebase",
        snapshot_generation=1,
        **_capability(reservation),
    )
    finalize_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.finalize"),
        **_capability(reservation),
    )

    authorization = _auth(pack, token, "mode.transition.rebase")
    rebased = rebase_external_owner_exact(
        pack._installation,
        "main",
        authorization,
        field_id="workflow-state",
        exact=_b64(b"private:stale-secret"),
        mode_epoch=1,
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    assert rebased == {
        "scopeId": "main",
        "fieldId": "workflow-state",
        "exact": _b64(b"public:stale-secret"),
        "modeEpoch": 1,
        "serverBootEpoch": runtime.SERVER_BOOT_EPOCH,
    }

    with pytest.raises(ExternalModeTransitionError) as stale:
        rebase_external_owner_exact(
            pack._installation,
            "main",
            _auth(pack, token, "mode.transition.rebase"),
            field_id="workflow-state",
            exact=_b64(b"private:stale-secret"),
            mode_epoch=0,
            server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
        )
    assert stale.value.code == "PRIVACY_EXTERNAL_TRANSITION_FENCED"

    reserve_external_transition(
        pack._installation,
        "privacy-mode",
        "main",
        "private",
        _auth(pack, token, "mode.transition.reserve"),
        request_id="external-request-rebase-active",
        coordinator_id=COORDINATOR_ID,
        resume_secret=RESUME_SECRET,
        offline_representation_count=0,
        expected_mode_epoch=1,
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    with pytest.raises(ExternalModeTransitionError) as active:
        rebase_external_owner_exact(
            pack._installation,
            "main",
            _auth(pack, token, "mode.transition.rebase"),
            field_id="workflow-state",
            exact=_b64(b"private:stale-secret"),
            mode_epoch=1,
            server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
        )
    assert active.value.code == "PRIVACY_EXTERNAL_TRANSITION_FENCED"


def test_resume_fences_old_tab_and_returns_pending_exact_values(external_pack):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    resumed = resume_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.resume"),
        resume_secret=RESUME_SECRET,
        coordinator_id=COORDINATOR_ID,
        mode_epoch=reservation["modeEpoch"],
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )

    assert resumed["clientLeaseEpoch"] == reservation["clientLeaseEpoch"] + 1
    assert resumed["pendingOwners"] == prepared["pendingOwners"]
    with pytest.raises(ExternalModeTransitionError) as fenced:
        acknowledge_external_apply(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.apply-ack"),
            acknowledgements=[],
            **_capability(reservation),
        )
    assert fenced.value.code == "PRIVACY_EXTERNAL_TRANSITION_FENCED"


def test_mixed_owner_representations_preserve_owners_already_at_target(external_pack):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    public_owner = _owner(b"public:already-public")
    public_owner["locator"]["nodeId"] = "node-8"
    prepared = _prepare(pack, token, reservation, [_owner(), public_owner])

    exact_values = {item["exact"] for item in prepared["pendingOwners"]}
    assert exact_values == {
        _b64(b"public:synthetic-secret"),
        _b64(b"public:already-public"),
    }


def test_private_target_uses_shared_current_envelope_not_consumer_crypto(external_pack):
    pack, source, token = external_pack
    source.declared = DeclaredPrivacyMode.PUBLIC
    reservation = reserve_external_transition(
        pack._installation,
        "privacy-mode",
        "main",
        "private",
        _auth(pack, token, "mode.transition.reserve"),
        request_id=REQUEST_ID,
        coordinator_id=COORDINATOR_ID,
        resume_secret=RESUME_SECRET,
        offline_representation_count=0,
        expected_mode_epoch=0,
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    prepared = _prepare(
        pack,
        token,
        reservation,
        [_owner(b"public:synthetic-secret")],
    )
    protected_exact = _unb64(prepared["pendingOwners"][0]["exact"])
    envelope = __import__("json").loads(protected_exact)

    assert envelope["schema"] == "helto.external.v1"
    assert PrivacyEnvelopeCodec("helto.external.v1").decrypt_state(envelope) == {
        "value": "synthetic-secret"
    }
    assert "encode_private_mode_transition" not in pack.profile.server_adapter_contracts["state"]


def test_detached_verify_requires_one_complete_generation(external_pack):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    second = _owner(b"private:second")
    second["locator"]["nodeId"] = "node-8"
    prepared = _prepare(pack, token, reservation, [_owner(), second])
    acknowledgements = [
        {"ownerId": item["ownerId"], "exact": item["exact"]}
        for item in prepared["pendingOwners"]
    ]
    acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=acknowledgements,
        **_capability(reservation),
    )

    with pytest.raises(ExternalModeTransitionError) as partial:
        verify_external_transition(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.verify"),
            acknowledgements=acknowledgements[:1],
            snapshot_id="snapshot-generation-0001",
            snapshot_generation=1,
            **_capability(reservation),
        )
    assert partial.value.code == "PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED"

    verified = verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=acknowledgements,
        snapshot_id="snapshot-generation-0001",
        snapshot_generation=1,
        **_capability(reservation),
    )
    assert verified["externalPhase"] == "verified"
    with pytest.raises(ExternalModeTransitionError) as different_generation:
        verify_external_transition(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.verify"),
            acknowledgements=acknowledgements,
            snapshot_id="snapshot-generation-0002",
            snapshot_generation=2,
            **_capability(reservation),
        )
    assert different_generation.value.code == "PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED"


def test_live_source_target_forces_forward_recovery_after_unpersisted_cas(external_pack):
    pack, source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner = prepared["pendingOwners"][0]
    ack = [{"ownerId": owner["ownerId"], "exact": owner["exact"]}]
    acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=ack,
        **_capability(reservation),
    )
    verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=ack,
        snapshot_id="snapshot-generation-0001",
        snapshot_generation=1,
        **_capability(reservation),
    )
    prior = source.read_mode_source("main")
    source.compare_and_set_mode_source(
        "main", prior["revision"], prior["declared"], DeclaredPrivacyMode.PUBLIC
    )

    with pytest.raises(ExternalModeTransitionError) as forward_only:
        rollback_external_transition(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.rollback"),
            **_capability(reservation),
        )
    assert forward_only.value.code == "PRIVACY_EXTERNAL_TRANSITION_FORWARD_ONLY"
    completed = finalize_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.finalize"),
        **_capability(reservation),
    )
    assert completed["effective"] == "public"


def test_restart_boot_epoch_forces_browser_apply_and_detached_verify_again(
    external_pack, monkeypatch
):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner = prepared["pendingOwners"][0]
    ack = [{"ownerId": owner["ownerId"], "exact": owner["exact"]}]
    acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=ack,
        **_capability(reservation),
    )
    verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=ack,
        snapshot_id="snapshot-generation-0001",
        snapshot_generation=1,
        **_capability(reservation),
    )
    monkeypatch.setattr(runtime, "SERVER_BOOT_EPOCH", "hp-boot-restarted-server-epoch")

    resumed = resume_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.resume"),
        resume_secret=RESUME_SECRET,
        coordinator_id=COORDINATOR_ID,
        mode_epoch=reservation["modeEpoch"],
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    assert resumed["externalPhase"] == "prepared"
    assert resumed["appliedOwnerCount"] == 0
    assert resumed["verifiedOwnerCount"] == 0
    assert resumed["pendingOwners"] == prepared["pendingOwners"]


def test_ordinary_finalize_cannot_reuse_pre_restart_evidence(external_pack, monkeypatch):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner = prepared["pendingOwners"][0]
    acknowledgement = [{"ownerId": owner["ownerId"], "exact": owner["exact"]}]
    acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=acknowledgement,
        **_capability(reservation),
    )
    verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=acknowledgement,
        snapshot_id="snapshot-generation-0001",
        snapshot_generation=1,
        **_capability(reservation),
    )
    monkeypatch.setattr(runtime, "SERVER_BOOT_EPOCH", "hp-boot-restarted-server-epoch")

    with pytest.raises(ExternalModeTransitionError) as fenced:
        finalize_external_transition(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.finalize"),
            **_capability(reservation),
        )
    assert fenced.value.code == "PRIVACY_EXTERNAL_TRANSITION_FENCED"


@pytest.mark.parametrize("restart", [False, True])
def test_resume_preserves_partial_rollback_direction_and_reissues_restore_evidence(
    external_pack, monkeypatch, restart
):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    second = _owner(b"private:second")
    second["locator"]["nodeId"] = "node-8"
    prepared = _prepare(pack, token, reservation, [_owner(), second])
    pending = rollback_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.rollback"),
        **_capability(reservation),
    )
    first = pending["pendingOwners"][0]
    pending = rollback_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.rollback"),
        acknowledgements=[{"ownerId": first["ownerId"], "exact": first["exact"]}],
        **_capability(reservation),
    )
    assert pending["externalPhase"] == "rollback-restoring"
    assert pending["restoredOwnerCount"] == 1
    if restart:
        monkeypatch.setattr(runtime, "SERVER_BOOT_EPOCH", "hp-boot-restarted-server-epoch")

    resumed = resume_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.resume"),
        resume_secret=RESUME_SECRET,
        coordinator_id=COORDINATOR_ID,
        mode_epoch=reservation["modeEpoch"],
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )

    assert resumed["externalPhase"] == "rollback-restoring"
    assert resumed["restoredOwnerCount"] == 0
    assert {item["ownerId"] for item in resumed["pendingOwners"]} == {
        item["ownerId"] for item in prepared["pendingOwners"]
    }


def test_resume_reissues_restore_evidence_after_rolling_back_failure(
    external_pack, monkeypatch
):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner = prepared["pendingOwners"][0]
    monkeypatch.setattr(
        external_transition,
        "rollback_participant",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic rollback failure")),
    )
    with pytest.raises(ExternalModeTransitionError) as failed:
        rollback_external_transition(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.rollback"),
            acknowledgements=[{
                "ownerId": owner["ownerId"],
                "exact": _b64(b"private:synthetic-secret"),
            }],
            **_capability(reservation),
        )
    assert failed.value.code == "PRIVACY_EXTERNAL_TRANSITION_ROLLBACK_FAILED"
    status = external_transition_status(
        pack._installation,
        "main",
        _auth(pack, token, "mode.transition.status"),
    )
    assert status["externalPhase"] == "rolling-back"

    resumed = resume_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.resume"),
        resume_secret=RESUME_SECRET,
        coordinator_id=COORDINATOR_ID,
        mode_epoch=reservation["modeEpoch"],
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    assert resumed["externalPhase"] == "rollback-restoring"
    assert resumed["restoredOwnerCount"] == 0
    assert resumed["pendingOwners"][0]["exact"] == _b64(
        b"private:synthetic-secret"
    )


def test_same_boot_resume_discards_persisted_apply_and_verify_evidence(external_pack):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner = prepared["pendingOwners"][0]
    ack = [{"ownerId": owner["ownerId"], "exact": owner["exact"]}]
    acknowledge_external_apply(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.apply-ack"),
        acknowledgements=ack,
        **_capability(reservation),
    )
    verify_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.verify"),
        acknowledgements=ack,
        snapshot_id="snapshot-generation-0001",
        snapshot_generation=1,
        **_capability(reservation),
    )

    resumed = resume_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.resume"),
        resume_secret=RESUME_SECRET,
        coordinator_id=COORDINATOR_ID,
        mode_epoch=reservation["modeEpoch"],
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    assert resumed["externalPhase"] == "prepared"
    assert resumed["appliedOwnerCount"] == 0
    assert resumed["verifiedOwnerCount"] == 0
    assert resumed["pendingOwners"] == prepared["pendingOwners"]


def test_rollback_returns_original_before_internal_rollback(external_pack):
    pack, source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    pending = rollback_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.rollback"),
        **_capability(reservation),
    )
    assert pending["externalPhase"] == "rollback-restoring"
    assert pending["pendingOwners"][0]["exact"] == _b64(
        b"private:synthetic-secret"
    )
    owner_id = prepared["pendingOwners"][0]["ownerId"]
    completed = rollback_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.rollback"),
        acknowledgements=[{
            "ownerId": owner_id,
            "exact": _b64(b"private:synthetic-secret"),
        }],
        **_capability(reservation),
    )
    assert completed["transitionStatus"] == "idle"
    assert completed["modeEpoch"] == 1
    assert source.declared is DeclaredPrivacyMode.PRIVATE
    retried = rollback_external_transition(
        pack._installation,
        "main",
        reservation["transitionId"],
        _auth(pack, token, "mode.transition.rollback"),
        acknowledgements=[],
        **_capability(reservation),
    )
    assert retried == completed


def test_ack_rejects_duplicate_owner_and_status_never_returns_exact_values(external_pack):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    prepared = _prepare(pack, token, reservation)
    owner = prepared["pendingOwners"][0]
    duplicate = [
        {"ownerId": owner["ownerId"], "exact": owner["exact"]},
        {"ownerId": owner["ownerId"], "exact": owner["exact"]},
    ]
    with pytest.raises(ExternalModeTransitionError) as rejected:
        acknowledge_external_apply(
            pack._installation,
            "main",
            reservation["transitionId"],
            _auth(pack, token, "mode.transition.apply-ack"),
            acknowledgements=duplicate,
            **_capability(reservation),
        )
    assert rejected.value.code == "PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED"

    status = external_transition_status(
        pack._installation,
        "main",
        _auth(pack, token, "mode.transition.status"),
    )
    assert "pendingOwners" not in status
    assert "originalExact" not in repr(status)
    assert "targetExact" not in repr(status)


def test_generic_transition_authorization_cannot_drive_external_steps(external_pack):
    pack, _source, token = external_pack
    reservation = _reserve(pack, token)
    generic = pack.authorization.authorize_request(Request(token), "mode.transition")
    with pytest.raises(ExternalModeTransitionError) as rejected:
        prepare_external_transition(
            pack._installation,
            "main",
            reservation["transitionId"],
            generic,
            owners=[_owner()],
            **_capability(reservation),
        )
    assert rejected.value.code == "PRIVACY_TRANSITION_UNAUTHORIZED"


def test_reserve_rejects_stale_mode_and_boot_epochs(external_pack):
    pack, _source, token = external_pack
    authorization = _auth(pack, token, "mode.transition.reserve", confirm=True)
    with pytest.raises(ExternalModeTransitionError) as stale_mode:
        reserve_external_transition(
            pack._installation,
            "privacy-mode",
            "main",
            "public",
            authorization,
            request_id=REQUEST_ID,
            coordinator_id=COORDINATOR_ID,
            resume_secret=RESUME_SECRET,
            offline_representation_count=0,
            expected_mode_epoch=9,
            server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
        )
    assert stale_mode.value.code == "PRIVACY_EXTERNAL_TRANSITION_FENCED"

    authorization = _auth(pack, token, "mode.transition.reserve", confirm=True)
    with pytest.raises(ExternalModeTransitionError) as stale_boot:
        reserve_external_transition(
            pack._installation,
            "privacy-mode",
            "main",
            "public",
            authorization,
            request_id=REQUEST_ID,
            coordinator_id=COORDINATOR_ID,
            resume_secret=RESUME_SECRET,
            offline_representation_count=0,
            expected_mode_epoch=0,
            server_boot_epoch="hp-boot-stale-server-epoch",
        )
    assert stale_boot.value.code == "PRIVACY_EXTERNAL_TRANSITION_FENCED"


def test_active_client_heartbeat_fences_a_second_coordinator(external_pack):
    pack, _source, token = external_pack
    heartbeat = heartbeat_external_client(
        pack._installation,
        "main",
        _auth(pack, token, "mode.transition.client-heartbeat"),
        coordinator_id=COORDINATOR_ID,
        resume_secret=RESUME_SECRET,
        server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
    )
    assert heartbeat["coordinatorId"] == COORDINATOR_ID

    with pytest.raises(ExternalModeTransitionError) as occupied:
        heartbeat_external_client(
            pack._installation,
            "main",
            _auth(pack, token, "mode.transition.client-heartbeat"),
            coordinator_id="external-coordinator-0002",
            resume_secret="hp-mode-resume-" + "s" * 43,
            server_boot_epoch=runtime.SERVER_BOOT_EPOCH,
        )
    assert occupied.value.code == "PRIVACY_EXTERNAL_ACTIVE_CLIENT"


def test_later_install_cannot_sweep_a_journal_saved_before_its_cas(
    external_pack, monkeypatch
):
    pack, _source, token = external_pack
    entered_cas = threading.Event()
    release_cas = threading.Event()
    original_commit = mode_runtime._commit_scope_state

    def delayed_commit(*args, **kwargs):
        entered_cas.set()
        assert release_cas.wait(timeout=5)
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(mode_runtime, "_commit_scope_state", delayed_commit)
    result = {}

    def reserve_in_thread():
        try:
            result["reservation"] = _reserve(pack, token)
        except BaseException as exc:  # pragma: no cover - asserted below
            result["error"] = exc

    worker = threading.Thread(target=reserve_in_thread)
    worker.start()
    assert entered_cas.wait(timeout=5)
    second_profile = replace(
        _profile(),
        id="helto.external-transition-second",
        distribution="comfyui-external-transition-second",
    )
    runtime.install(
        second_profile,
        {"mode-source": ModeSource(), "state": ExternalStateCodec()},
    )
    release_cas.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert "error" not in result
    state = mode_state.load_mode_scope_state(pack.profile.id, "main")
    assert state.transition is not None
    assert mode_state.mode_journal_path(
        pack.profile.id, "main", state.transition.journal_digest
    ).exists()


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
