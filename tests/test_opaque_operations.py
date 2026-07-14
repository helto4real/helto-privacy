from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import threading
import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.keystore as keystore
import helto_privacy.opaque_references as opaque
import helto_privacy.runtime as runtime
from helto_privacy import (
    OpaqueReferenceCandidate,
    OpaqueReferenceKind,
    OperationReferenceInput,
    ProtectedOperationAdapterResult,
)
from helto_privacy.profile import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ProfileValidationError,
    ProtectedOperation,
    ResourceKind,
    SafeDiagnosticField,
    SafeDiagnosticKind,
    SensitiveFieldClass,
    SensitiveFieldDeclaration,
)
from helto_privacy.protected_operations import ProtectedOperationError
from helto_privacy.mode import EffectivePrivacyMode
from helto_privacy.artifacts import root_bound_source
from helto_privacy.artifact_publication import ArtifactPublicationError


class ModeAdapter(ModeSourceProtocolFixture):
    def __init__(self, mode="private"):
        self.mode = mode

    def read_declared_mode(self, _scope_id):
        return self.mode

    def write_declared_mode(self, _scope_id, mode):
        self.mode = mode

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class OperationAdapter:
    def __init__(self):
        self.calls = []
        self.fail = False

    def invoke(self, value, references, declaration):
        self.calls.append((declaration.id, references))
        if self.fail:
            raise RuntimeError("synthetic private adapter failure")
        if declaration.id == "produce":
            return ProtectedOperationAdapterResult(
                {"secret": "SYNTHETIC_PRIVATE_PAYLOAD", "items": 2},
                (
                    OpaqueReferenceCandidate(
                        "operation-result",
                        {"secret": "SYNTHETIC_REFERENCE_VALUE"},
                    ),
                ),
            )
        return ProtectedOperationAdapterResult(
            {"secret": "SYNTHETIC_CONSUMED_PAYLOAD", "items": 1},
        )

    def project(self, payload, _declaration):
        return {"items": int(payload["items"])}

    def bind_source(self, _resolved, _declaration):
        raise RuntimeError("not a source profile")


class Request:
    def __init__(self, token):
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


def operation_profile(*, pack_id="helto.operation-test"):
    return PrivacyProfile(
        id=pack_id,
        distribution=f"comfyui-{pack_id}",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("operations", ResourceKind.OPERATION, ("operation-adapter",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot(
                "operation-adapter",
                ResourceKind.OPERATION,
                "operations",
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        opaque_reference_kinds=(
            OpaqueReferenceKind("operation-result", "operations", "main"),
        ),
        protected_operations=(
            ProtectedOperation(
                "produce",
                "operations",
                "operation-adapter",
                "/consumer/produce",
                scope_id="main",
                sensitive_fields=(
                    SensitiveFieldDeclaration("*", SensitiveFieldClass.CONSUMER_DERIVED),
                ),
                safe_projection=(
                    SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),
                ),
                reference_outputs=("operation-result",),
            ),
            ProtectedOperation(
                "consume",
                "operations",
                "operation-adapter",
                "/consumer/consume",
                scope_id="main",
                sensitive_fields=(
                    SensitiveFieldDeclaration("*", SensitiveFieldClass.CONSUMER_DERIVED),
                ),
                safe_projection=(
                    SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),
                ),
                reference_inputs=(
                    OperationReferenceInput("source", "operation-result", True),
                ),
            ),
            ProtectedOperation(
                "inspect",
                "operations",
                "operation-adapter",
                None,
                scope_id="main",
                sensitive_fields=(
                    SensitiveFieldDeclaration("*", SensitiveFieldClass.CONSUMER_DERIVED),
                ),
                safe_projection=(
                    SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),
                ),
            ),
        ),
    )


@pytest.fixture
def operation_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(
        "helto_privacy.artifacts.require_active_process_suite",
        lambda: None,
    )
    opaque.clear_opaque_references_for_tests()
    mode = ModeAdapter()
    adapter = OperationAdapter()
    pack = runtime.install(
        operation_profile(),
        {"mode": mode, "operation-adapter": adapter},
    )
    token = keystore.initialize_keystore("synthetic operation password")["token"]
    return pack, mode, adapter, Request(token)


def test_profile_canonicalizes_typed_operation_contract_and_changes_fingerprint():
    profile = operation_profile()
    canonical = profile._canonical_value()
    assert canonical["opaqueReferenceKinds"] == [
        {"id": "operation-result", "resourceId": "operations", "scopeId": "main"}
    ]
    assert canonical["protectedOperations"][0]["referenceInputs"] == [
        {
            "name": "source",
            "referenceKindId": "operation-result",
            "revokeOnSuccess": True,
        }
    ]
    assert profile.fingerprint != PrivacyProfile(
        id="helto.operation-test",
        distribution="comfyui-helto.operation-test",
        resources=profile.resources,
        server_adapters=profile.server_adapters,
        scopes=profile.scopes,
        protected_operations=tuple(
            ProtectedOperation(
                item.id,
                item.resource_id,
                item.adapter_slot,
                item.route,
                scope_id=item.scope_id,
                sensitive_fields=item.sensitive_fields,
                safe_projection=item.safe_projection,
            )
            for item in profile.protected_operations
        ),
    ).fingerprint


def test_profile_rejects_unknown_and_cross_scope_reference_kinds():
    base = operation_profile()
    consume = next(item for item in base.protected_operations if item.id == "consume")
    with pytest.raises(ProfileValidationError):
        PrivacyProfile(
            id=base.id,
            distribution=base.distribution,
            resources=base.resources,
            server_adapters=base.server_adapters,
            scopes=base.scopes,
            protected_operations=(
                ProtectedOperation(
                    consume.id,
                    consume.resource_id,
                    consume.adapter_slot,
                    consume.route,
                    scope_id=consume.scope_id,
                    sensitive_fields=consume.sensitive_fields,
                    safe_projection=consume.safe_projection,
                    reference_inputs=(OperationReferenceInput("source", "missing"),),
                ),
            ),
            opaque_reference_kinds=base.opaque_reference_kinds,
        )


def test_private_dispatch_returns_only_coarse_diagnostic_and_reference_shell(
    operation_pack,
):
    pack, _mode, adapter, request = operation_pack
    result = asyncio.run(
        pack.operations("operations").dispatch(
            request,
            "produce",
            {"request": "SYNTHETIC_PRIVATE_INPUT"},
        )
    )
    assert result.private is True
    assert result.payload == {"items": 2}
    assert result.references[0]["kind"] == "operation-result"
    assert result.references[0]["id"].startswith("hp-ref-")
    assert "SYNTHETIC" not in repr(result)
    assert adapter.calls == [("produce", {})]


def test_public_dispatch_returns_json_and_success_revokes_input(
    operation_pack,
    monkeypatch,
):
    pack, mode, _adapter, request = operation_pack
    produced = asyncio.run(
        pack.operations("operations").dispatch(request, "produce", {})
    )
    reference_id = produced.references[0]["id"]
    mode.mode = "public"
    monkeypatch.setattr(
        "helto_privacy.mode_runtime.resolve_bound_mode",
        lambda *_args: SimpleNamespace(effective=EffectivePrivacyMode.PUBLIC),
    )
    consumed = asyncio.run(
        pack.operations("operations").dispatch(
            request,
            "consume",
            {},
            references={"source": reference_id},
        )
    )
    assert consumed.private is False
    assert consumed.payload == {
        "secret": "SYNTHETIC_CONSUMED_PAYLOAD",
        "items": 1,
    }
    with pytest.raises(ProtectedOperationError):
        asyncio.run(
            pack.operations("operations").dispatch(
                request,
                "consume",
                {},
                references={"source": reference_id},
            )
        )


def test_authorization_and_reference_validation_run_before_adapter(operation_pack):
    pack, _mode, adapter, _request = operation_pack
    bad = Request("wrong-token")
    with pytest.raises(Exception):
        asyncio.run(pack.operations("operations").dispatch(bad, "produce", {}))
    assert adapter.calls == []
    token = keystore.session_token()
    with pytest.raises(ProtectedOperationError) as unavailable:
        asyncio.run(
            pack.operations("operations").dispatch(
                Request(token),
                "consume",
                {},
                references={"source": "hp-ref-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            )
        )
    assert unavailable.value.code == "PRIVACY_PROTECTED_OPERATION_REFERENCE_UNAVAILABLE"
    assert adapter.calls == []


def test_failed_consumer_does_not_revoke_but_success_does(operation_pack):
    pack, _mode, adapter, request = operation_pack
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    reference_id = produced.references[0]["id"]
    adapter.fail = True
    with pytest.raises(ProtectedOperationError):
        asyncio.run(
            pack.operations("operations").dispatch(
                request,
                "consume",
                {},
                references={"source": reference_id},
            )
        )
    adapter.fail = False
    consumed = asyncio.run(
        pack.operations("operations").dispatch(
            request,
            "consume",
            {},
            references={"source": reference_id},
        )
    )
    assert consumed.payload == {"items": 1}


def test_capacity_fails_before_adapter_invocation(operation_pack, monkeypatch):
    pack, _mode, adapter, request = operation_pack
    monkeypatch.setattr(opaque, "OPAQUE_REFERENCE_CAPACITY", 0)
    with pytest.raises(ProtectedOperationError):
        asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    assert adapter.calls == []


def test_explicit_revoke_and_lock_invalidate_references(operation_pack):
    pack, _mode, _adapter, request = operation_pack
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    reference_id = produced.references[0]["id"]
    authorization = pack.authorization.authorize_request(request, "reference.revoke")
    assert opaque.revoke_operation_references(
        profile=pack.profile,
        authorization=authorization,
        reference_ids=(reference_id,),
    ) == 1
    with pytest.raises(ProtectedOperationError):
        asyncio.run(
            pack.operations("operations").dispatch(
                request,
                "consume",
                {},
                references={"source": reference_id},
            )
        )
    asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    assert opaque._REFERENCES
    keystore.lock_keystore()
    assert opaque._REFERENCES == {}


def test_profile_bound_source_publisher_uses_compiled_operation_and_root_policy(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(
        "helto_privacy.artifacts.require_active_process_suite",
        lambda: None,
    )
    opaque.clear_opaque_references_for_tests()
    root = tmp_path / "allowed"
    root.mkdir()
    source_path = root / "frame.png"
    source_path.write_bytes(b"synthetic image")

    class SourceAdapter(OperationAdapter):
        def __init__(self):
            super().__init__()
            self.source_path = source_path
            self.bind_calls = 0

        def invoke(self, value, references, declaration):
            if declaration.id == "produce":
                return ProtectedOperationAdapterResult(
                    {"items": 1},
                    (
                        OpaqueReferenceCandidate(
                            "operation-result",
                            {"path": str(self.source_path)},
                        ),
                    ),
                )
            return super().invoke(value, references, declaration)

        def bind_source(self, resolved, declaration):
            self.bind_calls += 1
            assert declaration.id == "serve-source"
            return root_bound_source(
                resolved.value["path"],
                (root,),
                media_type="image/png",
            )

    base = operation_profile(pack_id="helto.operation-source-test")
    serve = ProtectedOperation(
        "serve-source",
        "operations",
        "operation-adapter",
        "/consumer/serve-source",
        scope_id="main",
        reference_inputs=(
            OperationReferenceInput("source", "operation-result", True),
        ),
        returns_lease=True,
    )
    profile = replace(
        base,
        protected_operations=(*base.protected_operations, serve),
    )
    adapter = SourceAdapter()
    pack = runtime.install(
        profile,
        {"mode": ModeAdapter(), "operation-adapter": adapter},
    )
    token = keystore.initialize_keystore("synthetic source password")["token"]
    request = Request(token)
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    reference_id = produced.references[0]["id"]
    authorization = pack.authorization.authorize_request(request, "serve-source")
    published = asyncio.run(
        pack.operations("operations")
        .source_leases("serve-source")
        .publish(reference_id, authorization)
    )
    assert published.to_payload()["lease"]["url"].startswith(
        "/helto_privacy/artifacts/hp-lease-"
    )

    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    blocked_reference = produced.references[0]["id"]
    before_bind = adapter.bind_calls
    with monkeypatch.context() as unstable:
        unstable.setattr(
            "helto_privacy.mode_runtime.require_stable_bound_scope",
            lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic unstable")),
        )
        with pytest.raises(ArtifactPublicationError):
            asyncio.run(
                pack.operations("operations")
                .source_leases("serve-source")
                .publish(
                    blocked_reference,
                    pack.authorization.authorize_request(request, "serve-source"),
                )
            )
    assert adapter.bind_calls == before_bind

    entered = threading.Event()
    release = threading.Event()
    original_bind_source = adapter.bind_source

    def blocking_bind_source(resolved, declaration):
        entered.set()
        assert release.wait(timeout=5)
        return original_bind_source(resolved, declaration)

    adapter.bind_source = blocking_bind_source
    first_results = []
    first_failures = []

    def first_publisher():
        try:
            first_results.append(
                asyncio.run(
                    pack.operations("operations")
                    .source_leases("serve-source")
                    .publish(
                        blocked_reference,
                        pack.authorization.authorize_request(request, "serve-source"),
                    )
                )
            )
        except Exception as exc:  # pragma: no cover - asserted through failures.
            first_failures.append(exc)

    thread = threading.Thread(target=first_publisher)
    thread.start()
    assert entered.wait(timeout=5)
    with pytest.raises(ArtifactPublicationError):
        asyncio.run(
            pack.operations("operations")
            .source_leases("serve-source")
            .publish(
                blocked_reference,
                pack.authorization.authorize_request(request, "serve-source"),
            )
        )
    release.set()
    thread.join(timeout=5)
    assert first_failures == []
    assert len(first_results) == 1
    assert adapter.bind_calls == before_bind + 1
    adapter.bind_source = original_bind_source

    adapter.source_path = tmp_path / "outside.png"
    adapter.source_path.write_bytes(b"outside")
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    with pytest.raises(ArtifactPublicationError):
        asyncio.run(
            pack.operations("operations")
            .source_leases("serve-source")
            .publish(
                produced.references[0]["id"],
                pack.authorization.authorize_request(request, "serve-source"),
            )
        )


def test_attestation_and_browser_transport_keep_reference_contract_typed(
    operation_pack,
):
    pack, _mode, _adapter, _request = operation_pack
    attestation = runtime.profile_attestation(pack.profile.id)
    assert attestation["opaqueReferenceKinds"] == [
        {"id": "operation-result", "resourceId": "operations", "scopeId": "main"}
    ]
    consume = next(
        item for item in attestation["protectedOperations"] if item["id"] == "consume"
    )
    assert consume["referenceInputs"] == [
        {
            "name": "source",
            "referenceKindId": "operation-result",
            "revokeOnSuccess": True,
        }
    ]
    root = Path(__file__).resolve().parents[1]
    profile_js = (root / "helto_privacy" / "web" / "privacy_profile.js").read_text()
    client_js = (root / "helto_privacy" / "web" / "privacy_client.js").read_text()
    assert "{ input, references: { ...references } }" in profile_js
    assert "/references/revoke`" in client_js
    assert "encodeURIComponent(references" not in client_js


def test_expired_reference_and_extra_reference_keys_are_indistinguishable(
    operation_pack,
    monkeypatch,
):
    pack, _mode, adapter, request = operation_pack
    monkeypatch.setattr(opaque, "OPAQUE_REFERENCE_TTL_SECONDS", -1)
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    reference_id = produced.references[0]["id"]
    before = len(adapter.calls)
    for references in (
        {"source": reference_id},
        {"source": reference_id, "extra": reference_id},
    ):
        with pytest.raises(ProtectedOperationError) as unavailable:
            asyncio.run(
                pack.operations("operations").dispatch(
                    request,
                    "consume",
                    {},
                    references=references,
                )
            )
        assert unavailable.value.code == "PRIVACY_PROTECTED_OPERATION_REFERENCE_UNAVAILABLE"
    assert len(adapter.calls) == before


def test_revoke_on_success_claim_is_atomic_across_concurrent_dispatch(operation_pack):
    pack, _mode, adapter, request = operation_pack
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    reference_id = produced.references[0]["id"]
    entered = threading.Event()
    release = threading.Event()
    original_invoke = adapter.invoke

    def blocking_invoke(value, references, declaration):
        if declaration.id == "consume":
            entered.set()
            assert release.wait(timeout=5)
        return original_invoke(value, references, declaration)

    adapter.invoke = blocking_invoke
    results = []
    failures = []

    def first_consumer():
        try:
            results.append(
                asyncio.run(
                    pack.operations("operations").dispatch(
                        request,
                        "consume",
                        {},
                        references={"source": reference_id},
                    )
                )
            )
        except Exception as exc:  # pragma: no cover - asserted through failures.
            failures.append(exc)

    thread = threading.Thread(target=first_consumer)
    thread.start()
    assert entered.wait(timeout=5)
    with pytest.raises(ProtectedOperationError) as claimed:
        asyncio.run(
            pack.operations("operations").dispatch(
                request,
                "consume",
                {},
                references={"source": reference_id},
            )
        )
    assert claimed.value.code == "PRIVACY_PROTECTED_OPERATION_REFERENCE_UNAVAILABLE"
    release.set()
    thread.join(timeout=5)
    assert failures == []
    assert len(results) == 1
    assert [item[0] for item in adapter.calls].count("consume") == 1


def test_external_operation_claims_survive_until_exact_terminal_settlement(
    operation_pack,
):
    pack, _mode, _adapter, request = operation_pack
    produced = asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    reference_id = produced.references[0]["id"]
    declaration = next(
        item for item in pack.profile.protected_operations if item.id == "consume"
    )
    authorization = pack.authorization.authorize_request(request, "consume")

    first = opaque.resolve_operation_references(
        profile=pack.profile,
        declaration=declaration,
        authorization=authorization,
        references={"source": reference_id},
    )
    first_claims = opaque.retain_external_operation_claims(
        declaration,
        first,
        lease_seconds=30,
    )
    with pytest.raises(opaque.OpaqueReferenceError):
        opaque.resolve_operation_references(
            profile=pack.profile,
            declaration=declaration,
            authorization=authorization,
            references={"source": reference_id},
        )

    opaque.settle_external_operation_claims(
        profile=pack.profile,
        declaration=declaration,
        authorization=authorization,
        claims=first_claims,
        completed=False,
    )
    second = opaque.resolve_operation_references(
        profile=pack.profile,
        declaration=declaration,
        authorization=authorization,
        references={"source": reference_id},
    )
    second_claims = opaque.retain_external_operation_claims(
        declaration,
        second,
        lease_seconds=30,
    )

    # A retry of the old rollback must not release a newer exact claim.
    opaque.settle_external_operation_claims(
        profile=pack.profile,
        declaration=declaration,
        authorization=authorization,
        claims=first_claims,
        completed=False,
    )
    assert opaque._CLAIMS[reference_id] == second_claims[reference_id]
    opaque.settle_external_operation_claims(
        profile=pack.profile,
        declaration=declaration,
        authorization=authorization,
        claims=second_claims,
        completed=True,
    )
    assert reference_id not in opaque._REFERENCES
    assert reference_id not in opaque._CLAIMS


def test_capacity_reservation_allows_only_one_concurrent_adapter_call(
    operation_pack,
    monkeypatch,
):
    pack, _mode, adapter, request = operation_pack
    monkeypatch.setattr(opaque, "OPAQUE_REFERENCE_CAPACITY", 1)
    entered = threading.Event()
    release = threading.Event()
    original_invoke = adapter.invoke

    def blocking_invoke(value, references, declaration):
        if declaration.id == "produce":
            entered.set()
            assert release.wait(timeout=5)
        return original_invoke(value, references, declaration)

    adapter.invoke = blocking_invoke
    results = []

    thread = threading.Thread(
        target=lambda: results.append(
            asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
        )
    )
    thread.start()
    assert entered.wait(timeout=5)
    with pytest.raises(ProtectedOperationError):
        asyncio.run(pack.operations("operations").dispatch(request, "produce", {}))
    release.set()
    thread.join(timeout=5)
    assert len(results) == 1
    assert [item[0] for item in adapter.calls].count("produce") == 1
    assert opaque._RESERVATIONS == {}


def test_zero_output_reservations_are_untracked_and_backend_dispatch_works(
    operation_pack,
):
    pack, _mode, _adapter, request = operation_pack
    for _index in range(5000):
        reservation = opaque.reserve_operation_reference_capacity(0)
        assert reservation.count == 0
        assert reservation.token is None
        opaque.release_operation_reference_capacity(reservation)
    assert opaque._RESERVATIONS == {}
    result = asyncio.run(
        pack.operations("operations").dispatch(request, "inspect", {})
    )
    assert result.payload == {"items": 1}
    assert result.references == ()
    assert opaque._RESERVATIONS == {}
