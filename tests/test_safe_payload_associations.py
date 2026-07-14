from __future__ import annotations

import hashlib
import fcntl
import os
from dataclasses import replace
from types import SimpleNamespace
import threading

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.associations as associations
import helto_privacy.keystore as keystore
import helto_privacy.opaque_references as opaque
import helto_privacy.runtime as runtime
import helto_privacy.subject_mode as subject_mode
import helto_privacy.mode_runtime as mode_runtime
from helto_privacy import (
    AdapterSlot,
    OpaqueReferenceCandidate,
    OpaqueReferenceKind,
    OperationReferenceOutput,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ProfileValidationError,
    ProtectedOperation,
    ProtectedOperationAdapterResult,
    ResourceKind,
    SafePayloadProjection,
    SafePayloadKind,
    SafePayloadLeaf,
    SubjectModeBinding,
)
from helto_privacy.associations import AssociationError
from helto_privacy.guard import authorize_privacy_request
from helto_privacy.mode import EffectivePrivacyMode
from helto_privacy.protected_operations import ProtectedOperationError, project_safe_payload
from helto_privacy.subject_mode import (
    consume_subject_mode_reference,
    prepare_subject_mode_reference,
)


class ModeAdapter(ModeSourceProtocolFixture):
    def __init__(self, mode="public"):
        self.mode = mode

    def read_declared_mode(self, _scope_id):
        return self.mode

    def write_declared_mode(self, *_args):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class BrowserModeAdapter:
    def readDeclaredMode(self, *_args):
        return "private"

    def writeDeclaredMode(self, *_args):
        return None

    def reconcileNode(self, *_args):
        return None

    def reconcileNodeDefinition(self, *_args):
        return None

    def onPrivacySessionChange(self, *_args):
        return None


class DeferredAdapter:
    def project_safe_payload(self, value, declaration):
        assert declaration.schema == "director.folder-list.v1"
        return value


class Request:
    def __init__(self, token):
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


def _profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.association-test",
        distribution="comfyui-association-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode", "mode-ui")),
            ProfileResource("operations", ResourceKind.OPERATION, ("operations",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("operations", ResourceKind.OPERATION, "operations"),
        ),
        browser_adapters=(
            AdapterSlot(
                "mode-ui",
                ResourceKind.MODE,
                "privacy-mode",
                ("HeltoDirector",),
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode", "mode-ui"),),
        subject_mode_bindings=(
            SubjectModeBinding(
                "director-mode",
                "main",
                "privacy_mode_reference",
                ("HeltoDirector",),
            ),
        ),
        opaque_reference_kinds=(
            OpaqueReferenceKind("folder", "operations", "main"),
        ),
        safe_payload_projections=(
            SafePayloadProjection(
                "folder-list-safe",
                "list-folders",
                "director.folder-list.v1",
                "director.folder-list",
                (
                    SafePayloadLeaf("count", SafePayloadKind.COUNT),
                    SafePayloadLeaf("page.has_more", SafePayloadKind.BOOLEAN),
                ),
            ),
        ),
        protected_operations=(
            ProtectedOperation(
                "list-folders",
                "operations",
                "operations",
                None,
                scope_id="main",
                subject_mode_binding_id="director-mode",
                reference_outputs=(OperationReferenceOutput("folder", 0, 3),),
                safe_payload_projection_id="folder-list-safe",
                deferred_ui=True,
            ),
        ),
    )


@pytest.fixture
def association_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    associations.clear_associations_for_tests()
    opaque.clear_opaque_references_for_tests()
    subject_mode.invalidate_subject_mode_session("test-reset")
    pack = runtime.install(
        _profile(),
        {
            "mode": ModeAdapter(),
            "operations": DeferredAdapter(),
        },
    )
    token = keystore.initialize_keystore("synthetic association password")["token"]
    request = Request(token)
    authorization = authorize_privacy_request(
        request,
        "subject-mode.prepare",
        pack_id=pack.profile.id,
    )
    prepared = prepare_subject_mode_reference(
        profile=pack.profile,
        binding=pack.profile.subject_mode_bindings[0],
        subject_id="node-1",
        effective=EffectivePrivacyMode.PUBLIC,
        authorization=authorization,
        installation=pack._installation,
    )
    lease = consume_subject_mode_reference(
        prepared.reference,
        profile=pack.profile,
        binding=pack.profile.subject_mode_bindings[0],
        subject_id="node-1",
    )
    return pack, request, lease


def test_safe_payload_projection_is_exact_finite_and_bounded():
    profile = _profile()
    declaration = profile.protected_operations[0]
    adapter = DeferredAdapter()
    assert project_safe_payload(
        profile=profile,
        declaration=declaration,
        adapter=adapter,
        value={"count": 2, "page": {"has_more": False}},
    ) == {"count": 2, "page": {"has_more": False}}
    for invalid in (
        {"count": 2},
        {"count": 2, "page": {"has_more": False}, "secret": "leak"},
        {"count": float("nan"), "page": {"has_more": False}},
        {"count": b"bytes", "page": {"has_more": False}},
        {"count": [1], "page": {"has_more": False}},
        {"count": "SYNTHETIC_PRIVATE_CANARY", "page": {"has_more": False}},
    ):
        with pytest.raises(ProtectedOperationError):
            project_safe_payload(
                profile=profile,
                declaration=declaration,
                adapter=adapter,
                value=invalid,
            )


def test_safe_payload_leaf_types_are_fingerprinted_and_untyped_paths_rejected():
    profile = _profile()
    canonical = profile._canonical_value()["safePayloadProjections"]
    assert canonical == [{
        "id": "folder-list-safe",
        "operationId": "list-folders",
        "schema": "director.folder-list.v1",
        "purpose": "director.folder-list",
        "safeLeaves": [
            {"path": "count", "kind": "count"},
            {"path": "page.has_more", "kind": "boolean"},
        ],
    }]
    changed_projection = replace(
        profile.safe_payload_projections[0],
        safe_leaves=(
            SafePayloadLeaf("count", SafePayloadKind.NUMBER),
            SafePayloadLeaf("page.has_more", SafePayloadKind.BOOLEAN),
        ),
    )
    assert replace(
        profile,
        safe_payload_projections=(changed_projection,),
    ).fingerprint != profile.fingerprint
    with pytest.raises(ProfileValidationError):
        SafePayloadProjection(
            "unsafe",
            "list-folders",
            "unsafe.schema",
            "unsafe.purpose",
            ("path",),  # type: ignore[arg-type]
        )


def test_safe_payload_typed_number_and_text_reject_path_url_and_range_probes():
    profile = _profile()
    declaration = profile.protected_operations[0]
    projection = replace(
        profile.safe_payload_projections[0],
        safe_leaves=(
            SafePayloadLeaf("label", SafePayloadKind.SAFE_TEXT),
            SafePayloadLeaf("ratio", SafePayloadKind.NUMBER),
        ),
    )
    profile = replace(profile, safe_payload_projections=(projection,))
    adapter = DeferredAdapter()
    assert project_safe_payload(
        profile=profile,
        declaration=declaration,
        adapter=adapter,
        value={"label": "Private folder 1", "ratio": 0.5},
    ) == {"label": "Private folder 1", "ratio": 0.5}
    for label in (
        "/private/path",
        r"C:\private\path",
        "file://private/path",
        "https://example.invalid/private",
        "../private",
        "%2Fprivate",
        "\ud800",
    ):
        with pytest.raises(ProtectedOperationError):
            project_safe_payload(
                profile=profile,
                declaration=declaration,
                adapter=adapter,
                value={"label": label, "ratio": 0.5},
            )
    for number in (
        float("nan"),
        float("inf"),
        1_000_000_000_000_001,
        10**10_000,
    ):
        with pytest.raises(ProtectedOperationError):
            project_safe_payload(
                profile=profile,
                declaration=declaration,
                adapter=adapter,
                value={"label": "Private folder 1", "ratio": number},
            )


def test_deferred_association_is_repr_safe_one_shot_and_variable_cardinality(
    association_pack,
):
    pack, request, lease = association_pack
    result = ProtectedOperationAdapterResult(
        payload=None,
        references=(
            OpaqueReferenceCandidate("folder", {"path": "SYNTHETIC_A"}),
            OpaqueReferenceCandidate("folder", {"path": "SYNTHETIC_B"}),
        ),
        safe_payload={"count": 2, "page": {"has_more": False}},
    )
    association = pack.operations("operations").defer(
        "list-folders",
        result,
        subject_mode=lease,
    )
    assert repr(association) == "DeferredOperationAssociation()"
    assert "hp-assoc-" not in repr(association)
    authorization = authorize_privacy_request(
        request,
        "list-folders",
        pack_id=pack.profile.id,
    )
    claimed = associations.claim_operation_association(
        installation=pack._installation,
        profile=pack.profile,
        association_id=association.id,
        authorization=authorization,
    )
    payload = claimed.to_payload()
    assert set(payload) == {
        "association",
        "correlationId",
        "data",
        "lease",
        "ok",
        "private",
        "references",
        "safePayload",
    }
    assert payload["safePayload"] == {"count": 2, "page": {"has_more": False}}
    assert payload["association"] is None
    assert [item["kind"] for item in payload["references"]] == ["folder", "folder"]
    with pytest.raises(AssociationError):
        associations.claim_operation_association(
            installation=pack._installation,
            profile=pack.profile,
            association_id=association.id,
            authorization=authorization,
        )
    lease.close()


def test_deferred_association_invalidates_on_lock(association_pack):
    pack, request, lease = association_pack
    association = pack.operations("operations").defer(
        "list-folders",
        ProtectedOperationAdapterResult(
            payload=None,
            safe_payload={"count": 0, "page": {"has_more": False}},
        ),
        subject_mode=lease,
    )
    keystore.lock_keystore()
    fake_authorization = SimpleNamespace(
        _session_fingerprint=hashlib.sha256(b"stale").digest()
    )
    with pytest.raises(AssociationError):
        associations.claim_operation_association(
            installation=pack._installation,
            profile=pack.profile,
            association_id=association.id,
            authorization=fake_authorization,
        )


def test_association_id_collision_does_not_overwrite_and_mode_transition_blocks(
    association_pack,
    monkeypatch,
):
    pack, _request, lease = association_pack
    monkeypatch.setattr(
        associations.secrets,
        "token_urlsafe",
        lambda _size: "A" * 32,
    )
    result = ProtectedOperationAdapterResult(
        payload=None,
        safe_payload={"count": 0, "page": {"has_more": False}},
    )
    outcomes = []

    def defer():
        try:
            outcomes.append(
                pack.operations("operations").defer(
                    "list-folders",
                    result,
                    subject_mode=lease,
                )
            )
        except AssociationError as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=defer) for _index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert sum(not isinstance(item, AssociationError) for item in outcomes) == 1
    assert len(associations._ASSOCIATIONS) == 1
    with pytest.raises(AssociationError):
        associations.prepare_association_mode_transition(
            pack._installation,
            "main",
            SimpleNamespace(),
        )


def test_unexpected_claim_failure_restores_one_shot_claim(
    association_pack,
    monkeypatch,
):
    pack, request, lease = association_pack
    association = pack.operations("operations").defer(
        "list-folders",
        ProtectedOperationAdapterResult(
            payload=None,
            safe_payload={"count": 0, "page": {"has_more": False}},
        ),
        subject_mode=lease,
    )
    authorization = authorize_privacy_request(
        request,
        "list-folders",
        pack_id=pack.profile.id,
    )
    original_issue = associations.issue_operation_references
    monkeypatch.setattr(
        associations,
        "issue_operation_references",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic failure")),
    )
    with pytest.raises(RuntimeError):
        associations.claim_operation_association(
            installation=pack._installation,
            profile=pack.profile,
            association_id=association.id,
            authorization=authorization,
        )
    assert association.id not in associations._CLAIMS
    monkeypatch.setattr(associations, "issue_operation_references", original_issue)
    claimed = associations.claim_operation_association(
        installation=pack._installation,
        profile=pack.profile,
        association_id=association.id,
        authorization=authorization,
    )
    assert claimed.safe_payload == {"count": 0, "page": {"has_more": False}}


def test_association_admission_serializes_registry_insert_with_transition(
    association_pack,
    monkeypatch,
):
    pack, _request, lease = association_pack
    entered_insert = threading.Event()
    release_insert = threading.Event()
    transition_acquired = threading.Event()
    original_new_id = associations._new_association_id_locked

    def paused_new_id():
        entered_insert.set()
        assert release_insert.wait(timeout=5)
        return original_new_id()

    monkeypatch.setattr(associations, "_new_association_id_locked", paused_new_id)
    result = ProtectedOperationAdapterResult(
        payload=None,
        safe_payload={"count": 0, "page": {"has_more": False}},
    )
    outcomes = []
    worker = threading.Thread(
        target=lambda: outcomes.append(
            pack.operations("operations").defer(
                "list-folders",
                result,
                subject_mode=lease,
            )
        )
    )
    worker.start()
    assert entered_insert.wait(timeout=5)
    def transition():
        descriptor = mode_runtime._open_scope_lock(pack.profile.id, "main")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            transition_acquired.set()
        finally:
            os.close(descriptor)

    transition_worker = threading.Thread(target=transition)
    transition_worker.start()
    assert transition_acquired.wait(timeout=0.05) is False
    release_insert.set()
    worker.join(timeout=5)
    transition_worker.join(timeout=5)
    assert len(outcomes) == 1
    assert transition_acquired.is_set()


def test_transition_first_clamps_stale_public_subject_mode_to_current_private(
    association_pack,
):
    pack, _request, lease = association_pack
    mode = pack._installation.adapters["mode"]
    started = threading.Event()
    outcomes = []
    result = ProtectedOperationAdapterResult(
        payload=None,
        safe_payload={"count": 0, "page": {"has_more": False}},
    )

    def defer():
        started.set()
        outcomes.append(
            pack.operations("operations").defer(
                "list-folders",
                result,
                subject_mode=lease,
            )
        )

    with mode_runtime._TRANSITION_LOCK:
        worker = threading.Thread(target=defer)
        worker.start()
        assert started.wait(timeout=5)
        mode.mode = "private"
    worker.join(timeout=5)
    assert len(outcomes) == 1
    assert associations._ASSOCIATIONS[outcomes[0].id].effective is EffectivePrivacyMode.PRIVATE
