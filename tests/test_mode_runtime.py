import asyncio
from pathlib import Path
import threading

import helto_privacy.artifacts as artifacts
import helto_privacy.keystore as keystore
import helto_privacy.mode_runtime as mode_runtime
import helto_privacy.runtime as runtime
import helto_privacy.suite_runtime as suite_runtime
import pytest
from tests.mode_protocol_fixtures import ModeSourceProtocolFixture, ProductStateProtocolFixture
from helto_privacy.records import RecordSnapshot
from helto_privacy.guard import (
    AuthorizedPrivacyRequest,
    PrivacyRouteDispatchError,
    authorize_privacy_request,
)
from helto_privacy.mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeEvidence,
    ModeFacts,
    ModeTransitionError,
    ModeTransitionContext,
    ModeTransitionStatus,
    PrivacyFloorKind,
)
from helto_privacy.profile import (
    AdapterSlot,
    ArtifactDeclaration,
    ArtifactRetention,
    FieldLocation,
    FieldLocationKind,
    PrivacyProfile,
    PrivacyScope,
    ProtectedStateAuthority,
    ProtectedField,
    ProfileResource,
    RecordDeclaration,
    ResourceKind,
)


class ModeSourceAdapter(ModeSourceProtocolFixture):
    def __init__(self, declarations):
        self.declarations = declarations

    def read_declared_mode(self, scope_id):
        return self.declarations.get(scope_id)

    def write_declared_mode(self, scope_id, mode):
        self.declarations[scope_id] = mode

    def prepare_mode_transition(self, *_args):
        pass

    def commit_mode_transition(self, *_args):
        pass

    def rollback_mode_transition(self, *_args):
        pass


class Request:
    def __init__(self, token, *, confirm_declassification=False):
        self.headers = {"X-Helto-Privacy-Token": token}
        if confirm_declassification:
            self.headers["X-Helto-Privacy-Declassification"] = "confirmed"
        self.cookies = {}


class TransitionParticipant:
    def __init__(self, name, log, *, mode=EffectivePrivacyMode.PUBLIC):
        self.name = name
        self.log = log
        self.mode = mode
        self.pending = {}
        self.fail_commit = False
        self.fail_rollback = False

    def prepare_mode_transition(
        self,
        context,
    ):
        assert isinstance(context, ModeTransitionContext)
        self.log.append(("prepare", self.name))
        self.pending[context.transition_id] = (
            self.mode,
            context.target_mode,
            context.target_declared,
        )

    def commit_mode_transition(self, scope_id, transition_id):
        self.log.append(("commit", self.name))
        if self.fail_commit:
            raise RuntimeError("SYNTHETIC_PRIVATE_CANARY")
        self.mode = self.pending[transition_id][1]

    def rollback_mode_transition(self, scope_id, transition_id):
        self.log.append(("rollback", self.name))
        if transition_id in self.pending:
            self.mode = self.pending[transition_id][0]


class TransactionalModeSource(ModeSourceProtocolFixture):
    def __init__(self, declarations, log):
        self.name = "mode-source"
        self.log = log
        self.declarations = declarations

    def read_declared_mode(self, scope_id):
        return self.declarations.get(scope_id)

    def write_declared_mode(self, scope_id, mode):
        self.declarations[scope_id] = mode

    def compare_and_set_mode_source(self, *args):
        self.log.append(("commit", self.name))
        return super().compare_and_set_mode_source(*args)

    def rollback_mode_source(self, *args):
        self.log.append(("rollback", self.name))
        return super().rollback_mode_source(*args)


class StateParticipant(ProductStateProtocolFixture, TransitionParticipant):
    def capture(self):
        return {}

    def normalize(self, value):
        return value

    def apply_revealed(self, value):
        return None

    def clear_plaintext(self):
        return None

    def prepare_mode_transition(self, context, plan):
        self.log.append(("prepare", self.name))
        return ProductStateProtocolFixture.prepare_mode_transition(self, context, plan)

    def commit_mode_transition(self, context, plan):
        self.log.append(("commit", self.name))
        if self.fail_commit:
            raise RuntimeError("SYNTHETIC_PRIVATE_CANARY")
        result = ProductStateProtocolFixture.commit_mode_transition(self, context, plan)
        self.mode = context.target_mode
        return result

    def rollback_mode_transition(self, context, plan):
        self.log.append(("rollback", self.name))
        if self.fail_rollback:
            raise RuntimeError("SYNTHETIC_PRIVATE_CANARY")
        result = ProductStateProtocolFixture.rollback_mode_transition(self, context, plan)
        self.mode = context.prior_mode
        return result


class RecordParticipant(TransitionParticipant):
    def list_ids(self):
        return ()

    def read_record(self, record_id):
        return RecordSnapshot(0)

    def compare_and_swap_record(self, record_id, expected, replacement):
        return False


class ArtifactParticipant(TransitionParticipant):
    def __init__(self, name, log):
        super().__init__(name, log)
        self.fail_purge = False

    def encode(self, value):
        return value

    def decode(self, value):
        return value

    def purge_plaintext_derivatives(self, _artifact_kind):
        self.log.append(("purge-plaintext", self.name))
        if self.fail_purge:
            raise RuntimeError("SYNTHETIC_PRIVATE_PATH_CANARY")
        return None


class BrowserStateAdapter:
    def apply(self):
        return None

    def clear(self):
        return None

    def normalize(self):
        return None

    def reconcileNode(self):
        return None

    def reconcileNodeDefinition(self):
        return None


def _profile():
    return PrivacyProfile(
        id="helto.mode-runtime-test",
        distribution="comfyui-mode-runtime-test",
        resources=(
            ProfileResource(
                "privacy-mode",
                ResourceKind.MODE,
                ("mode-source",),
            ),
        ),
        server_adapters=(
            AdapterSlot("mode-source", ResourceKind.MODE, "privacy-mode"),
        ),
        scopes=(
            PrivacyScope("global", "privacy-mode", "mode-source"),
            PrivacyScope(
                "local",
                "privacy-mode",
                "mode-source",
                floor_scope_ids=("global",),
            ),
        ),
    )


def _transaction_profile():
    return PrivacyProfile(
        id="helto.mode-transition-test",
        distribution="comfyui-mode-transition-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode-source",)),
            ProfileResource("state", ResourceKind.WORKFLOW, ("state-store", "state-ui")),
            ProfileResource("records", ResourceKind.RECORD, ("record-store",)),
            ProfileResource("artifacts", ResourceKind.ARTIFACT, ("artifact-store",)),
        ),
        server_adapters=(
            AdapterSlot("mode-source", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state-store", ResourceKind.WORKFLOW, "state"),
            AdapterSlot("record-store", ResourceKind.RECORD, "records"),
            AdapterSlot("artifact-store", ResourceKind.ARTIFACT, "artifacts"),
        ),
        browser_adapters=(
            AdapterSlot(
                "state-ui",
                ResourceKind.WORKFLOW,
                "state",
                ("HeltoTransitionTest",),
            ),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode-source"),),
        protected_fields=(
            ProtectedField(
                id="private-state",
                workflow_resource_id="state",
                scope_id="main",
                state_adapter="state-store",
                browser_adapter="state-ui",
                node_types=("HeltoTransitionTest",),
                location=FieldLocation(FieldLocationKind.WIDGET, "state"),
                current_schema="helto.transition-test.v1",
                purpose="state",
                state_authority=ProtectedStateAuthority.SERVER_DURABLE,
            ),
        ),
        records=(
            RecordDeclaration(
                id="private-records",
                resource_id="records",
                scope_id="main",
                current_schema="helto.transition-record.v1",
                store_adapter="record-store",
            ),
        ),
        artifacts=(
            ArtifactDeclaration(
                id="private-artifacts",
                resource_id="artifacts",
                scope_id="main",
                purpose="preview",
                payload_adapter="artifact-store",
                format_version=1,
                retention=ArtifactRetention.REGENERABLE_CACHE,
                operations=("preview",),
            ),
        ),
    )


def _transaction_pack(
    monkeypatch,
    *,
    fail_participant=None,
    confirm_declassification=False,
):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(suite_runtime, "require_active_process_suite", lambda: None)
    log = []
    declarations = {"main": DeclaredPrivacyMode.PUBLIC}
    adapters = {
        "mode-source": TransactionalModeSource(declarations, log),
        "state-store": StateParticipant("state-store", log),
        "record-store": RecordParticipant("record-store", log),
        "artifact-store": ArtifactParticipant("artifact-store", log),
    }
    if fail_participant:
        adapters[fail_participant].fail_commit = True
    pack = runtime.install(_transaction_profile(), adapters)
    token = keystore.initialize_keystore("synthetic password")["token"]
    request = Request(
        token,
        confirm_declassification=confirm_declassification,
    )
    authorization = (
        pack.authorization.authorize_declassification(
            request,
            "main",
            DeclaredPrivacyMode.PUBLIC,
        )
        if confirm_declassification
        else authorize_privacy_request(
            request,
            "mode.transition",
            pack_id=pack.profile.id,
        )
    )
    return pack, adapters, declarations, log, authorization


def test_bound_mode_handle_reads_declaration_and_profile_floors(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    adapter = ModeSourceAdapter(
        {
            "global": DeclaredPrivacyMode.PRIVATE,
            "local": DeclaredPrivacyMode.PUBLIC,
        }
    )
    pack = runtime.install(_profile(), {"mode-source": adapter})

    resolution = pack.mode("privacy-mode").resolve("local")

    assert resolution.declared is DeclaredPrivacyMode.PUBLIC
    assert resolution.effective is EffectivePrivacyMode.PUBLIC
    assert resolution.transition_status is ModeTransitionStatus.BLOCKED
    assert [(floor.kind, floor.source_id) for floor in resolution.floors] == [
        (PrivacyFloorKind.PARENT, "global")
    ]

    adapter.declarations["global"] = DeclaredPrivacyMode.PUBLIC
    after_floor_removed = pack.mode("privacy-mode").resolve("local")
    assert after_floor_removed.effective is EffectivePrivacyMode.PUBLIC
    assert after_floor_removed.transition_status is ModeTransitionStatus.BLOCKED


def test_bound_mode_handle_allows_explicit_public_without_floor(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    adapter = ModeSourceAdapter(
        {
            "global": DeclaredPrivacyMode.PUBLIC,
            "local": DeclaredPrivacyMode.PUBLIC,
        }
    )
    pack = runtime.install(_profile(), {"mode-source": adapter})

    resolution = pack.mode("privacy-mode").resolve(
        "local",
        ModeFacts(request_mode=DeclaredPrivacyMode.PUBLIC),
    )

    assert resolution.effective is EffectivePrivacyMode.PUBLIC
    assert resolution.floors == ()


def test_bound_mode_handle_resolves_node_local_declaration_and_floors(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    adapter = ModeSourceAdapter(
        {
            "global": DeclaredPrivacyMode.PUBLIC,
            "local": DeclaredPrivacyMode.PRIVATE,
        }
    )
    pack = runtime.install(_profile(), {"mode-source": adapter})
    mode = pack.mode("privacy-mode")

    public = mode.resolve_declaration("local", DeclaredPrivacyMode.PUBLIC)
    private = mode.resolve_declaration(
        "local",
        DeclaredPrivacyMode.PUBLIC,
        ModeFacts(
            upstream=(
                ModeEvidence("private-input", EffectivePrivacyMode.PRIVATE),
            )
        ),
    )
    malformed = mode.resolve_declaration("local", "false")

    assert public.effective is EffectivePrivacyMode.PUBLIC
    assert private.effective is EffectivePrivacyMode.PRIVATE
    assert [(floor.kind, floor.source_id) for floor in private.floors] == [
        (PrivacyFloorKind.UPSTREAM, "private-input")
    ]
    assert malformed.effective is EffectivePrivacyMode.PRIVATE


def test_node_local_resolution_holds_transition_lock_through_policy(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    adapter = ModeSourceAdapter(
        {
            "global": DeclaredPrivacyMode.PUBLIC,
            "local": DeclaredPrivacyMode.PRIVATE,
        }
    )
    pack = runtime.install(_profile(), {"mode-source": adapter})
    entered = threading.Event()
    release = threading.Event()
    contender_acquired = threading.Event()
    errors = []
    original = mode_runtime._resolve_declared_mode

    def blocking_resolution(*args, **kwargs):
        entered.set()
        if not release.wait(2):
            raise AssertionError("resolution test did not release")
        return original(*args, **kwargs)

    monkeypatch.setattr(mode_runtime, "_resolve_declared_mode", blocking_resolution)

    def resolve():
        try:
            pack.mode("privacy-mode").resolve_declaration(
                "local",
                DeclaredPrivacyMode.PUBLIC,
            )
        except BaseException as exc:
            errors.append(exc)

    def contend():
        with mode_runtime._TRANSITION_LOCK:
            contender_acquired.set()

    resolver = threading.Thread(target=resolve)
    resolver.start()
    assert entered.wait(1)
    contender = threading.Thread(target=contend)
    contender.start()
    assert not contender_acquired.wait(0.05)
    release.set()
    resolver.join(2)
    contender.join(2)

    assert errors == []
    assert contender_acquired.is_set()


def test_persistent_floor_change_blocks_until_protection_reconciles(monkeypatch):
    pack, _adapters, declarations, _log, authorization = _transaction_pack(monkeypatch)
    mode = pack.mode("privacy-mode")
    assert mode.resolve("main").effective is EffectivePrivacyMode.PUBLIC
    facts = ModeFacts(
        upstream=(ModeEvidence("private-input", EffectivePrivacyMode.PRIVATE),),
    )

    blocked = mode.resolve("main", facts)

    assert blocked.effective is EffectivePrivacyMode.PUBLIC
    assert blocked.transition_status is ModeTransitionStatus.BLOCKED
    reconciled = mode.transition(
        "main",
        DeclaredPrivacyMode.PUBLIC,
        authorization,
        facts,
    )
    assert reconciled.effective is EffectivePrivacyMode.PRIVATE
    assert declarations["main"] is DeclaredPrivacyMode.PUBLIC


def test_first_private_floor_blocks_an_explicit_public_surface(monkeypatch):
    pack, _adapters, _declarations, _log, _authorization = _transaction_pack(
        monkeypatch
    )

    resolution = pack.mode("privacy-mode").resolve(
        "main",
        ModeFacts(
            records=(ModeEvidence("private-record", EffectivePrivacyMode.PRIVATE),),
        ),
    )

    assert resolution.effective is EffectivePrivacyMode.PUBLIC
    assert resolution.transition_status is ModeTransitionStatus.BLOCKED


@pytest.mark.parametrize(
    "declared",
    (
        None,
        "unknown-mode",
        DeclaredPrivacyMode.INHERIT,
        DeclaredPrivacyMode.PRIVATE,
    ),
)
def test_initial_private_target_cannot_override_known_public_data(
    monkeypatch,
    declared,
):
    pack, _adapters, declarations, _log, _authorization = _transaction_pack(
        monkeypatch
    )
    declarations["main"] = declared

    resolution = pack.mode("privacy-mode").resolve(
        "main",
        ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC),
    )

    assert resolution.effective is EffectivePrivacyMode.PUBLIC
    assert resolution.transition_status is ModeTransitionStatus.BLOCKED


def test_request_only_strengthening_does_not_change_established_mode(monkeypatch):
    pack, _adapters, _declarations, _log, _authorization = _transaction_pack(
        monkeypatch
    )
    mode = pack.mode("privacy-mode")

    strengthened = mode.resolve(
        "main",
        ModeFacts(request_mode=DeclaredPrivacyMode.PRIVATE),
    )

    assert strengthened.effective is EffectivePrivacyMode.PRIVATE
    assert strengthened.transition_status is ModeTransitionStatus.IDLE
    assert mode.resolve("main").effective is EffectivePrivacyMode.PUBLIC


def test_bound_mode_handle_resolves_the_complete_parent_chain(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    base = _profile()
    profile = PrivacyProfile(
        id="helto.mode-parent-chain",
        distribution="comfyui-mode-parent-chain",
        resources=base.resources,
        server_adapters=base.server_adapters,
        scopes=(
            PrivacyScope("global", "privacy-mode", "mode-source"),
            PrivacyScope(
                "middle",
                "privacy-mode",
                "mode-source",
                parent_id="global",
            ),
            PrivacyScope(
                "local",
                "privacy-mode",
                "mode-source",
                parent_id="middle",
            ),
        ),
    )
    adapter = ModeSourceAdapter(
        {
            "global": DeclaredPrivacyMode.PRIVATE,
            "middle": DeclaredPrivacyMode.PUBLIC,
            "local": DeclaredPrivacyMode.PUBLIC,
        }
    )
    pack = runtime.install(profile, {"mode-source": adapter})

    resolution = pack.mode("privacy-mode").resolve("local")

    assert resolution.effective is EffectivePrivacyMode.PUBLIC
    assert resolution.transition_status is ModeTransitionStatus.BLOCKED
    assert [(floor.kind, floor.source_id) for floor in resolution.floors] == [
        (PrivacyFloorKind.PARENT, "middle")
    ]


def test_transition_prepares_every_surface_and_commits_mode_last(monkeypatch):
    pack, adapters, declarations, log, authorization = _transaction_pack(monkeypatch)

    result = pack.mode("privacy-mode").transition(
        "main",
        DeclaredPrivacyMode.PRIVATE,
        authorization,
        ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC),
    )

    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert result.status is ModeTransitionStatus.IDLE
    assert declarations["main"] is DeclaredPrivacyMode.PRIVATE
    assert log == [
        ("prepare", "state-store"),
        ("commit", "state-store"),
        ("commit", "mode-source"),
    ]
    assert adapters["state-store"].classify_mode_transition is not None


def test_private_transition_aborts_before_prepare_when_derivative_purge_fails(
    monkeypatch,
):
    pack, _adapters, declarations, log, authorization = _transaction_pack(monkeypatch)

    def fail_artifact_plan(*_args, **_kwargs):
        raise RuntimeError("SYNTHETIC_PRIVATE_PATH_CANARY")

    monkeypatch.setattr(artifacts, "plan_artifact_mode_transition", fail_artifact_plan)

    with pytest.raises(ModeTransitionError) as failed:
        pack.mode("privacy-mode").transition(
            "main",
            DeclaredPrivacyMode.PRIVATE,
            authorization,
            ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC),
        )

    assert failed.value.code == "PRIVACY_TRANSITION_FAILED"
    assert declarations["main"] is DeclaredPrivacyMode.PUBLIC
    assert log == []
    assert "SYNTHETIC" not in str(failed.value)


def test_private_transition_aborts_when_plaintext_temp_cleanup_fails(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "artifacts"
    root.mkdir()
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
    pack, _adapters, declarations, log, authorization = _transaction_pack(monkeypatch)
    plaintext_temp = root / "interrupted.plaintext"
    plaintext_temp.write_bytes(b"SYNTHETIC_PLAINTEXT_TEMP")
    original_unlink = Path.unlink

    def fail_plaintext_unlink(path, *args, **kwargs):
        if path == plaintext_temp:
            raise OSError("/SYNTHETIC/PRIVATE/PATH")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_plaintext_unlink)

    with pytest.raises(ModeTransitionError) as failed:
        pack.mode("privacy-mode").transition(
            "main",
            DeclaredPrivacyMode.PRIVATE,
            authorization,
            ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC),
        )

    assert failed.value.code == "PRIVACY_TRANSITION_FAILED"
    assert declarations["main"] is DeclaredPrivacyMode.PUBLIC
    assert log == []
    assert plaintext_temp.exists()
    assert "SYNTHETIC" not in str(failed.value)


def test_malformed_transition_target_cannot_inherit_public(monkeypatch):
    pack, _adapters, declarations, _log, authorization = _transaction_pack(monkeypatch)

    result = pack.mode("privacy-mode").transition(
        "main",
        "unknown-mode",
        authorization,
        ModeFacts(global_mode=DeclaredPrivacyMode.PUBLIC),
    )

    assert result.declared is DeclaredPrivacyMode.INHERIT
    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert declarations["main"] is DeclaredPrivacyMode.INHERIT


def test_direct_declaration_change_blocks_until_shared_transition_runs(monkeypatch):
    pack, adapters, declarations, _log, authorization = _transaction_pack(monkeypatch)
    mode = pack.mode("privacy-mode")
    assert mode.resolve("main").effective is EffectivePrivacyMode.PUBLIC

    declarations["main"] = DeclaredPrivacyMode.PRIVATE
    drifted = mode.resolve("main")

    assert drifted.effective is EffectivePrivacyMode.PUBLIC
    assert drifted.declared is DeclaredPrivacyMode.PUBLIC
    assert drifted.transition_status is ModeTransitionStatus.BLOCKED

    monkeypatch.setattr(mode_runtime, "_MODE_TRANSITIONS", {})
    assert mode.resolve("main").transition_status is ModeTransitionStatus.BLOCKED

    completed = mode.transition(
        "main",
        DeclaredPrivacyMode.PRIVATE,
        authorization,
    )
    assert completed.effective is EffectivePrivacyMode.PRIVATE
    assert adapters["state-store"].mode is EffectivePrivacyMode.PRIVATE

    declarations["main"] = DeclaredPrivacyMode.PUBLIC
    assert mode.resolve("main").transition_status is ModeTransitionStatus.BLOCKED
    restored = mode.transition(
        "main",
        DeclaredPrivacyMode.PRIVATE,
        authorization,
    )
    assert restored.effective is EffectivePrivacyMode.PRIVATE
    assert declarations["main"] is DeclaredPrivacyMode.PRIVATE


def test_authorized_private_to_public_transition_rewrites_every_surface(monkeypatch):
    pack, adapters, declarations, log, authorization = _transaction_pack(
        monkeypatch,
        confirm_declassification=True,
    )
    declarations["main"] = DeclaredPrivacyMode.PRIVATE
    for adapter_id, participant in adapters.items():
        if adapter_id != "mode-source":
            participant.mode = EffectivePrivacyMode.PRIVATE
    mode = pack.mode("privacy-mode")
    assert mode.resolve("main").effective is EffectivePrivacyMode.PRIVATE

    result = mode.transition(
        "main",
        DeclaredPrivacyMode.PUBLIC,
        authorization,
        ModeFacts(current_mode=EffectivePrivacyMode.PRIVATE),
    )

    assert result.effective is EffectivePrivacyMode.PUBLIC
    assert declarations["main"] is DeclaredPrivacyMode.PUBLIC
    assert mode.resolve("main").effective is EffectivePrivacyMode.PUBLIC
    assert adapters["state-store"].mode is EffectivePrivacyMode.PUBLIC
    assert log[-1] == ("commit", "mode-source")


def test_private_to_public_requires_explicit_confirmation_evidence(monkeypatch):
    pack, adapters, declarations, log, authorization = _transaction_pack(monkeypatch)
    declarations["main"] = DeclaredPrivacyMode.PRIVATE
    for adapter_id, participant in adapters.items():
        if adapter_id != "mode-source":
            participant.mode = EffectivePrivacyMode.PRIVATE
    mode = pack.mode("privacy-mode")
    assert mode.resolve("main").effective is EffectivePrivacyMode.PRIVATE

    with pytest.raises(ModeTransitionError) as confirmation:
        mode.transition(
            "main",
            DeclaredPrivacyMode.PUBLIC,
            authorization,
            ModeFacts(current_mode=EffectivePrivacyMode.PRIVATE),
        )

    assert confirmation.value.code == (
        "PRIVACY_DECLASSIFICATION_CONFIRMATION_REQUIRED"
    )
    assert log == []


def test_transition_failure_rolls_back_to_idle_before_returning(monkeypatch):
    pack, adapters, declarations, log, authorization = _transaction_pack(
        monkeypatch,
        fail_participant="state-store",
    )
    mode = pack.mode("privacy-mode")
    facts = ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC)

    with pytest.raises(ModeTransitionError) as failed:
        mode.transition(
            "main",
            DeclaredPrivacyMode.PRIVATE,
            authorization,
            facts,
        )

    assert failed.value.code == "PRIVACY_TRANSITION_FAILED"
    assert "SYNTHETIC_PRIVATE_CANARY" not in str(failed.value)
    restored = mode.resolve("main", facts)
    assert restored.effective is EffectivePrivacyMode.PUBLIC
    assert restored.transition_status is ModeTransitionStatus.IDLE
    assert declarations["main"] is DeclaredPrivacyMode.PUBLIC
    assert adapters["state-store"].mode is EffectivePrivacyMode.PUBLIC

    assert any(action == "rollback" for action, _name in log)


def test_bound_route_dispatch_cannot_cross_a_blocked_transition(monkeypatch):
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(suite_runtime, "require_active_process_suite", lambda: None)
    pack, adapters, _declarations, _log, authorization = _transaction_pack(monkeypatch)
    adapters["state-store"].fail_commit = True
    adapters["state-store"].fail_rollback = True
    assert runtime.reconcile_prompt_server(object()) is True
    mode = pack.mode("privacy-mode")
    facts = ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC)

    with pytest.raises(ModeTransitionError):
        mode.transition(
            "main",
            DeclaredPrivacyMode.PRIVATE,
            authorization,
            facts,
        )

    called = False

    async def protected_operation(_authorization):
        nonlocal called
        called = True
        return {"ok": True}

    request = Request(keystore.session_token())
    with pytest.raises(PrivacyRouteDispatchError) as blocked:
        asyncio.run(
            pack.authorization.dispatch(
                request,
                "main",
                "record.use",
                protected_operation,
            )
        )

    assert blocked.value.code == "PRIVACY_TRANSITION_BLOCKED"
    assert called is False

    adapters["state-store"].fail_commit = False
    adapters["state-store"].fail_rollback = False
    mode.transition(
        "main",
        DeclaredPrivacyMode.PUBLIC,
        authorization,
        facts,
    )

    async def restored_operation(route_authorization):
        assert isinstance(route_authorization, AuthorizedPrivacyRequest)
        assert route_authorization.pack_id == pack.profile.id
        assert route_authorization.operation_id == "record.use"
        return {"ok": True}

    assert asyncio.run(
        pack.authorization.dispatch(
            request,
            "main",
            "record.use",
            restored_operation,
        )
    ) == {"ok": True}


def test_declassification_is_rejected_while_a_floor_is_active(monkeypatch):
    pack, _adapters, _declarations, log, authorization = _transaction_pack(monkeypatch)

    with pytest.raises(ModeTransitionError) as blocked:
        pack.mode("privacy-mode").transition(
            "main",
            DeclaredPrivacyMode.PUBLIC,
            authorization,
            ModeFacts(
                current_mode=EffectivePrivacyMode.PRIVATE,
                upstream=(
                    ModeEvidence("private-input", EffectivePrivacyMode.PRIVATE),
                ),
            ),
        )

    assert blocked.value.code == "PRIVACY_FLOOR_ACTIVE"
    assert log == []


def test_transition_rejects_a_capability_after_the_privacy_session_is_locked(
    monkeypatch,
):
    pack, _adapters, _declarations, log, authorization = _transaction_pack(monkeypatch)
    keystore.lock_keystore()

    with pytest.raises(ModeTransitionError) as unauthorized:
        pack.mode("privacy-mode").transition(
            "main",
            DeclaredPrivacyMode.PRIVATE,
            authorization,
        )

    assert unauthorized.value.code == "PRIVACY_TRANSITION_UNAUTHORIZED"
    assert log == []
