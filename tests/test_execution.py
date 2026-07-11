from __future__ import annotations

import asyncio
import copy
import json

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.runtime as runtime
from helto_privacy import (
    EXECUTION_REFERENCE_SCHEMA,
    EXECUTION_REFERENCE_VERSION,
    ExecutionError,
    ExecutionResult,
    PreparedExecution,
)
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.guard import authorize_privacy_request
from helto_privacy.mode import ModeTransitionError
from helto_privacy.profile import (
    AdapterSlot,
    FieldLocation,
    FieldLocationKind,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProfileResource,
    ResourceKind,
    SemanticExecutionProjection,
)
from helto_privacy.runtime import ProfileConflictError


PASSWORD = "synthetic execution password"


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeAdapter:
    def read_declared_mode(self, _scope_id):
        return "private"

    def write_declared_mode(self, _scope_id, _mode):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class StateAdapter:
    def capture(self):
        return {}

    def normalize(self, value, *_args):
        return value

    def apply_revealed(self, _value):
        return None

    def clear_plaintext(self):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class ProjectionAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def project(self, fields, _declaration):
        self.calls += 1
        return {"prompt": fields["private-state"]["prompt"]}


class DispatchAdapter:
    def __init__(self) -> None:
        self.retained_value = None
        self.dispatch_count = 0
        self.lock_during_dispatch = False
        self.rotate_during_dispatch = False
        self.lock_after_checkpoint = False
        self.before_checkpoint = None
        self.async_dispatch = False

    def dispatch(self, value, context, cancellation):
        self.dispatch_count += 1
        if self.async_dispatch:
            return self._dispatch_async(value, context, cancellation)
        self.retained_value = value
        if self.lock_during_dispatch:
            keystore.lock_keystore()
        if self.rotate_during_dispatch:
            keystore.rotate_primary_key(PASSWORD)
        if self.before_checkpoint is not None:
            self.before_checkpoint()
        cancellation.checkpoint()
        if self.lock_after_checkpoint:
            keystore.lock_keystore()
        return {
            "result": value["prompt"].upper(),
            "request": context["request"],
        }

    async def _dispatch_async(self, value, context, cancellation):
        self.retained_value = value
        await asyncio.sleep(0)
        cancellation.checkpoint()
        if self.lock_after_checkpoint:
            keystore.lock_keystore()
        return {
            "result": value["prompt"].upper(),
            "request": context["request"],
        }


def _profile(
    pack_id: str = "helto.execution-test",
    distribution: str = "comfyui-execution-test",
) -> PrivacyProfile:
    return PrivacyProfile(
        id=pack_id,
        distribution=distribution,
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("state", ResourceKind.WORKFLOW, ("state", "state-ui")),
            ProfileResource(
                "dispatch",
                ResourceKind.EXECUTION,
                ("projection", "dispatcher"),
            ),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state", ResourceKind.WORKFLOW, "state"),
            AdapterSlot("projection", ResourceKind.EXECUTION, "dispatch"),
            AdapterSlot("dispatcher", ResourceKind.EXECUTION, "dispatch"),
        ),
        browser_adapters=(
            AdapterSlot(
                "state-ui",
                ResourceKind.WORKFLOW,
                "state",
                ("SyntheticNode",),
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        protected_fields=(
            ProtectedField(
                "private-state",
                "state",
                "main",
                "state",
                "state-ui",
                ("SyntheticNode",),
                FieldLocation(FieldLocationKind.WIDGET, "state"),
                "helto.execution-test.v1",
                "execution-state",
                execution=True,
            ),
        ),
        execution_projections=(
            SemanticExecutionProjection(
                "product-execution",
                "dispatch",
                "state",
                "projection",
                "dispatcher",
            ),
        ),
    )


@pytest.fixture
def execution_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    projection = ProjectionAdapter()
    dispatcher = DispatchAdapter()
    pack = runtime.install(
        _profile(),
        {
            "mode": ModeAdapter(),
            "state": StateAdapter(),
            "projection": projection,
            "dispatcher": dispatcher,
        },
    )
    token = keystore.initialize_keystore(PASSWORD)["token"]
    return pack, projection, dispatcher, Request(token)


def _authorization(pack, request):
    return authorize_privacy_request(
        request,
        "execution.prepare",
        pack_id=pack.profile.id,
    )


def _protected(prompt: str):
    return PrivacyEnvelopeCodec("helto.execution-test.v1").encrypt_state(
        {"prompt": prompt}
    )


def test_prepare_and_single_use_dispatch_keep_plaintext_inside_product_lifetime(
    execution_pack,
):
    pack, projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")

    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("synthetic prompt")},
        _authorization(pack, request),
    )

    assert isinstance(prepared, PreparedExecution)
    assert prepared.reference["schema"] == EXECUTION_REFERENCE_SCHEMA
    assert prepared.reference["version"] == EXECUTION_REFERENCE_VERSION
    assert prepared.reference["packId"] == pack.profile.id
    assert prepared.reference["executionResourceId"] == "dispatch"
    assert prepared.reference["projectionId"] == "product-execution"
    assert "cacheIdentity" not in prepared.reference
    assert "synthetic prompt" not in json.dumps(prepared.reference)
    assert "synthetic prompt" not in repr(prepared)
    assert projection.calls == 0

    result = handle.dispatch(
        prepared.reference,
        {"request": "synthetic-request"},
    )

    assert isinstance(result, ExecutionResult)
    assert result.cache_identity.startswith("hp-exec-v1:")
    assert result.value == {
        "result": "SYNTHETIC PROMPT",
        "request": "synthetic-request",
    }
    assert "SYNTHETIC PROMPT" not in repr(result)
    assert projection.calls == 1
    assert dispatcher.retained_value == {}
    with pytest.raises(ExecutionError) as replay:
        handle.dispatch(prepared.reference, {"request": "replay"})
    assert replay.value.code == "PRIVACY_EXECUTION_GRANT_INVALID"


def test_semantic_identity_and_private_cache_are_session_bound(execution_pack):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    authorization = _authorization(pack, request)

    first_prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("same semantic prompt")},
        authorization,
    )
    second_prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("same semantic prompt")},
        authorization,
    )

    first = handle.dispatch(first_prepared.reference, {"request": "first"})
    second = handle.dispatch(second_prepared.reference, {"request": "second"})

    assert first.cache_identity == second.cache_identity
    assert first_prepared.reference["fields"] != second_prepared.reference["fields"]
    handle.cache_store(first.cache_identity, {"private": ["synthetic-result"]})
    cached = handle.cache_load(first.cache_identity)
    assert cached == {"private": ["synthetic-result"]}
    cached["private"].append("mutated-copy")
    assert handle.cache_load(first.cache_identity) == {
        "private": ["synthetic-result"]
    }
    cached_prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("same semantic prompt")},
        authorization,
    )
    cached_execution = handle.dispatch(
        cached_prepared.reference,
        {"request": "cache-hit"},
    )
    assert cached_execution.value == {"private": ["synthetic-result"]}
    assert cached_execution.cache_identity == first.cache_identity
    assert dispatcher.dispatch_count == 2

    keystore.lock_keystore()
    with pytest.raises(ExecutionError) as locked_cache:
        handle.cache_load(first.cache_identity)
    assert locked_cache.value.code == "PRIVACY_EXECUTION_LOCKED"
    token = keystore.unlock_keystore(PASSWORD)["token"]
    fresh_prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("same semantic prompt")},
        _authorization(pack, Request(token)),
    )
    fresh = handle.dispatch(fresh_prepared.reference, {"request": "fresh"})
    assert fresh.cache_identity != first.cache_identity
    assert handle.cache_load(first.cache_identity) is None


def test_key_rotation_revokes_grants_and_private_cache(execution_pack):
    pack, _projection, _dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    protected = _protected("rotate synthetic prompt")
    executed_prepared = handle.prepare(
        "product-execution",
        {"private-state": protected},
        _authorization(pack, request),
    )
    executed = handle.dispatch(
        executed_prepared.reference,
        {"request": "establish-cache-identity"},
    )
    handle.cache_store(executed.cache_identity, {"private": "synthetic-result"})
    pending = handle.prepare(
        "product-execution",
        {"private-state": protected},
        _authorization(pack, request),
    )

    rotated = keystore.rotate_primary_key(PASSWORD)

    with pytest.raises(ExecutionError) as revoked:
        handle.dispatch(pending.reference, {"request": "stale-rotation"})
    assert revoked.value.code == "PRIVACY_EXECUTION_GRANT_INVALID"
    assert handle.cache_load(executed.cache_identity) is None

    fresh_prepared = handle.prepare(
        "product-execution",
        {"private-state": protected},
        _authorization(pack, Request(rotated["token"])),
    )
    fresh = handle.dispatch(fresh_prepared.reference, {"request": "fresh-rotation"})
    assert fresh.cache_identity != executed.cache_identity


def test_lock_requests_safe_cancellation_of_active_dispatch(execution_pack):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("cancel me")},
        _authorization(pack, request),
    )
    dispatcher.lock_during_dispatch = True

    with pytest.raises(ExecutionError) as cancelled:
        handle.dispatch(prepared.reference, {"request": "synthetic-request"})

    assert cancelled.value.code == "PRIVACY_EXECUTION_CANCELLED"
    assert dispatcher.retained_value == {}


def test_lock_revokes_pending_grant_before_projection_or_product_logic(
    execution_pack,
):
    pack, projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("pending lock")},
        _authorization(pack, request),
    )

    keystore.lock_keystore()

    with pytest.raises(ExecutionError) as locked:
        handle.dispatch(prepared.reference, {"request": "must-not-run"})
    assert locked.value.code == "PRIVACY_EXECUTION_LOCKED"
    assert projection.calls == 0
    assert dispatcher.dispatch_count == 0


def test_shared_final_checkpoint_blocks_result_reveal_after_adapter_checkpoint(
    execution_pack,
):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("lock before return")},
        _authorization(pack, request),
    )
    dispatcher.lock_after_checkpoint = True

    with pytest.raises(ExecutionError) as cancelled:
        handle.dispatch(prepared.reference, {"request": "synthetic-request"})

    assert cancelled.value.code == "PRIVACY_EXECUTION_CANCELLED"
    assert dispatcher.retained_value == {}


def test_key_rotation_requests_safe_cancellation_of_active_dispatch(
    execution_pack,
):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("rotate active execution")},
        _authorization(pack, request),
    )
    dispatcher.rotate_during_dispatch = True

    with pytest.raises(ExecutionError) as cancelled:
        handle.dispatch(prepared.reference, {"request": "synthetic-request"})

    assert cancelled.value.code == "PRIVACY_EXECUTION_CANCELLED"
    assert dispatcher.retained_value == {}


def test_prepare_rejects_missing_unsupported_and_failed_protected_state(
    execution_pack,
):
    pack, _projection, _dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    authorization = _authorization(pack, request)

    with pytest.raises(ExecutionError) as missing:
        handle.prepare("product-execution", {}, authorization)
    assert missing.value.code == "PRIVACY_EXECUTION_REFERENCE_MISMATCH"

    with pytest.raises(ExecutionError) as unsupported:
        handle.prepare(
            "product-execution",
            {"private-state": "SYNTHETIC_PLAINTEXT_CANARY"},
            authorization,
        )
    assert unsupported.value.code == "PRIVACY_EXECUTION_REFERENCE_INVALID"

    tampered = _protected("synthetic prompt")
    tampered["ciphertext"] = (
        ("A" if tampered["ciphertext"][0] != "A" else "B")
        + tampered["ciphertext"][1:]
    )
    failed_prepared = handle.prepare(
        "product-execution",
        {"private-state": tampered},
        authorization,
    )
    with pytest.raises(ExecutionError) as failed:
        handle.dispatch(failed_prepared.reference, {"request": "failed-decrypt"})
    assert failed.value.code == "PRIVACY_EXECUTION_DECRYPT_FAILED"


def test_reference_tampering_and_replay_after_lock_are_rejected(execution_pack):
    pack, _projection, _dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("synthetic prompt")},
        _authorization(pack, request),
    )
    tampered = copy.deepcopy(prepared.reference)
    tampered["projectionId"] = "forged-projection"

    with pytest.raises(ExecutionError) as mismatch:
        handle.dispatch(tampered, {"request": "synthetic-request"})
    assert mismatch.value.code == "PRIVACY_EXECUTION_REFERENCE_MISMATCH"

    keystore.lock_keystore()
    token = keystore.unlock_keystore(PASSWORD)["token"]
    with pytest.raises(ExecutionError) as expired:
        handle.dispatch(
            prepared.reference,
            {"request": token and "fresh-session"},
        )
    assert expired.value.code == "PRIVACY_EXECUTION_GRANT_INVALID"


def test_profile_conflict_requests_safe_cancellation_and_blocks_handle(
    execution_pack,
):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("cancel on conflict")},
        _authorization(pack, request),
    )

    def conflict_profile():
        with pytest.raises(ProfileConflictError):
            runtime.install(
                _profile(distribution="conflicting-distribution"),
                {
                    "mode": ModeAdapter(),
                    "state": StateAdapter(),
                    "projection": ProjectionAdapter(),
                    "dispatcher": DispatchAdapter(),
                },
            )

    dispatcher.before_checkpoint = conflict_profile
    with pytest.raises(ExecutionError) as cancelled:
        handle.dispatch(prepared.reference, {"request": "synthetic-request"})
    assert cancelled.value.code == "PRIVACY_EXECUTION_CANCELLED"

    with pytest.raises(runtime.PackBlockedError):
        handle.cache_load("hp-exec-v1:" + "a" * 43)


def test_incomplete_mode_transition_blocks_dispatch_before_product_logic(
    execution_pack,
    monkeypatch,
):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("blocked transition")},
        _authorization(pack, request),
    )

    def blocked_scope(_installation, _scope_id):
        raise ModeTransitionError("PRIVACY_TRANSITION_BLOCKED")

    monkeypatch.setattr(
        "helto_privacy.mode_runtime.require_stable_bound_scope",
        blocked_scope,
    )
    with pytest.raises(ExecutionError) as blocked:
        handle.dispatch(prepared.reference, {"request": "must-not-run"})

    assert blocked.value.code == "PRIVACY_EXECUTION_MODE_BLOCKED"
    assert dispatcher.retained_value is None


def test_async_product_dispatch_keeps_and_then_clears_plaintext_lifetime(
    execution_pack,
):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("async synthetic")},
        _authorization(pack, request),
    )
    dispatcher.async_dispatch = True

    result = asyncio.run(
        handle.dispatch(prepared.reference, {"request": "async-request"})
    )

    assert isinstance(result, ExecutionResult)
    assert result.cache_identity.startswith("hp-exec-v1:")
    assert result.value == {
        "result": "ASYNC SYNTHETIC",
        "request": "async-request",
    }
    assert dispatcher.retained_value == {}


def test_async_final_checkpoint_blocks_result_reveal_after_lock(execution_pack):
    pack, _projection, dispatcher, request = execution_pack
    handle = pack.execution("dispatch")
    prepared = handle.prepare(
        "product-execution",
        {"private-state": _protected("async lock before return")},
        _authorization(pack, request),
    )
    dispatcher.async_dispatch = True
    dispatcher.lock_after_checkpoint = True

    with pytest.raises(ExecutionError) as cancelled:
        asyncio.run(
            handle.dispatch(prepared.reference, {"request": "async-cancel"})
        )

    assert cancelled.value.code == "PRIVACY_EXECUTION_CANCELLED"
    assert dispatcher.retained_value == {}
