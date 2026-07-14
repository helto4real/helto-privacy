from __future__ import annotations

import copy
import fcntl
import json
import multiprocessing
from types import SimpleNamespace

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.keystore as keystore
import helto_privacy.mode_runtime as mode_runtime
import helto_privacy.runtime as runtime
from helto_privacy import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    RecordDeclaration,
    RecordRevealProjection,
    RecordSnapshot,
    ResourceKind,
    SingletonDeclaration,
    SingletonPayloadKind,
    SingletonSnapshot,
)
from helto_privacy.guard import authorize_privacy_request
from helto_privacy.mode import DeclaredPrivacyMode, EffectivePrivacyMode, ModeFacts, ModeTransitionError
from helto_privacy.mode_values import ModeValueDisposition, classify_bytes, classify_state
from helto_privacy.mode_values import protect_state
from helto_privacy.records import (
    PublicRecordShell,
    RecordError,
    classify_record_mode_transition_value,
    commit_record_mode_transition_value,
    prepare_record_mode_transition_value,
    rollback_record_mode_transition_value,
    _replace_record_snapshot_exact,
)
from helto_privacy.singletons import (
    SingletonError,
    classify_singleton_mode_transition_value,
    commit_singleton_mode_transition_value,
    prepare_singleton_mode_transition_value,
    rollback_singleton_mode_transition_value,
)


class MutableModeAdapter(ModeSourceProtocolFixture):
    def __init__(self, mode: str = "public") -> None:
        self.mode = mode

    def read_declared_mode(self, _scope_id):
        return self.mode

    def write_declared_mode(self, _scope_id, mode):
        self.mode = str(getattr(mode, "value", mode))

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class RecordStore:
    def __init__(self) -> None:
        self.records = {}
        self.revisions = {}
        self.read_calls = 0

    def list_ids(self):
        return tuple(self.records)

    def read_record(self, record_id):
        self.read_calls += 1
        return RecordSnapshot(
            self.revisions.get(record_id, 0),
            copy.deepcopy(self.records.get(record_id)),
        )

    def compare_and_swap_record(self, record_id, expected, replacement):
        current = self.read_record(record_id)
        if current != expected:
            return False
        self.revisions[record_id] = replacement.revision
        if replacement.protected is None:
            self.records.pop(record_id, None)
        else:
            self.records[record_id] = copy.deepcopy(replacement.protected)
        return True

    def mutate(self, current, _operation, value):
        return {**dict(current or {}), **dict(value["record"])}

    def project(self, value, operation):
        return {"summary": value["summary"]} if operation == "details" else {
            "prompt": value["prompt"]
        }

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class MultiprocessRecordStore:
    def __init__(self, path) -> None:
        self.path = path

    def read_record(self, record_id):
        with self.path.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_SH)
            state = json.load(handle)
            fcntl.flock(handle, fcntl.LOCK_UN)
        value = state.get(record_id, {"revision": 0, "protected": None})
        return RecordSnapshot(value["revision"], value["protected"])

    def compare_and_swap_record(self, record_id, expected, replacement):
        with self.path.open("r+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            state = json.load(handle)
            value = state.get(record_id, {"revision": 0, "protected": None})
            if RecordSnapshot(value["revision"], value["protected"]) != expected:
                fcntl.flock(handle, fcntl.LOCK_UN)
                return False
            state[record_id] = {
                "revision": replacement.revision,
                "protected": copy.deepcopy(replacement.protected),
            }
            handle.seek(0)
            json.dump(state, handle, sort_keys=True)
            handle.truncate()
            handle.flush()
            fcntl.flock(handle, fcntl.LOCK_UN)
            return True


def _multiprocess_record_replace(store, record_id, expected, replacement, start, results):
    start.wait()
    try:
        _replace_record_snapshot_exact(store, record_id, expected, replacement)
    except RecordError as exc:
        results.put(exc.code)
    else:
        results.put("ok")


class SingletonTransaction:
    def __init__(self, store, singleton_id, revision, replacement) -> None:
        self.store = store
        self.singleton_id = singleton_id
        self.revision = revision
        self.replacement = copy.deepcopy(replacement)
        self.original = copy.deepcopy(store.snapshots[singleton_id])

    def commit(self):
        if self.store.snapshots[self.singleton_id].revision != self.revision:
            return False
        self.store.snapshots[self.singleton_id] = copy.deepcopy(self.replacement)
        if self.store.fail_after_commit:
            raise RuntimeError("synthetic ambiguous singleton commit")
        return True

    def read_back(self):
        if self.store.concurrent_after_commit is not None:
            self.store.snapshots[self.singleton_id] = copy.deepcopy(
                self.store.concurrent_after_commit
            )
            self.store.concurrent_after_commit = None
        return copy.deepcopy(self.store.snapshots[self.singleton_id])

    def rollback(self):
        self.store.snapshots[self.singleton_id] = copy.deepcopy(self.original)


class SingletonStore:
    def __init__(self) -> None:
        self.snapshots = {
            "settings": SingletonSnapshot(0),
            "blob": SingletonSnapshot(0),
        }
        self.fail_after_commit = False
        self.concurrent_after_commit = None
        self.concurrent_before_rollback = None

    def read_singleton(self, singleton_id):
        return copy.deepcopy(self.snapshots[singleton_id])

    def begin_singleton_replace(self, singleton_id, revision, replacement):
        return SingletonTransaction(self, singleton_id, revision, replacement)

    def rollback_singleton_replace(self, singleton_id, expected, replacement):
        if self.concurrent_before_rollback is not None:
            self.snapshots[singleton_id] = copy.deepcopy(
                self.concurrent_before_rollback
            )
            self.concurrent_before_rollback = None
            return False
        if self.snapshots[singleton_id] != expected:
            return False
        self.snapshots[singleton_id] = copy.deepcopy(replacement)
        return True

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


def _profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.dual-mode-test",
        distribution="comfyui-dual-mode-test",
        resources=(
            ProfileResource("mode", ResourceKind.MODE, ("mode-store",)),
            ProfileResource("records", ResourceKind.RECORD, ("record-store",)),
            ProfileResource("state", ResourceKind.SINGLETON, ("singleton-store",)),
        ),
        server_adapters=(
            AdapterSlot("mode-store", ResourceKind.MODE, "mode"),
            AdapterSlot("record-store", ResourceKind.RECORD, "records"),
            AdapterSlot("singleton-store", ResourceKind.SINGLETON, "state"),
        ),
        scopes=(PrivacyScope("main", "mode", "mode-store"),),
        records=(
            RecordDeclaration(
                "prompt",
                "records",
                "main",
                "helto.dual-mode.record.v1",
                "record-store",
                projections=(
                    RecordRevealProjection("details", ("summary",)),
                    RecordRevealProjection("use", ("prompt",)),
                ),
                mutation_operations=("create", "patch"),
            ),
        ),
        singletons=(
            SingletonDeclaration(
                "settings",
                "state",
                "main",
                "helto.dual-mode.settings.v1",
                "settings",
                "singleton-store",
                SingletonPayloadKind.FIELD,
            ),
            SingletonDeclaration(
                "blob",
                "state",
                "main",
                "helto.dual-mode.blob.v1",
                "blob",
                "singleton-store",
                SingletonPayloadKind.BLOB,
            ),
        ),
    )


@pytest.fixture
def public_pack(tmp_path, monkeypatch):
    monkeypatch.setenv("HELTO_PRIVACY_KEYSTORE", str(tmp_path / "keystore.json"))
    monkeypatch.setenv("HELTO_PRIVACY_MODE_STATE", str(tmp_path / "mode.json"))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(mode_runtime, "_MODE_TRANSITIONS", {})
    mode = MutableModeAdapter()
    records = RecordStore()
    singletons = SingletonStore()
    pack = runtime.install(
        _profile(),
        {
            "mode-store": mode,
            "record-store": records,
            "singleton-store": singletons,
        },
    )
    keystore.initialize_keystore("synthetic dual mode password")
    keystore.lock_keystore()
    return pack, mode, records, singletons


def test_public_records_work_locked_and_expose_only_closed_projections(public_pack):
    pack, _mode, store, _singletons = public_pack
    handle = pack.records("records")
    assert handle.authorize_request(
        "prompt",
        object(),
        "record.create",
    ) is None
    receipt = handle.mutate(
        "prompt",
        "create",
        {"record": {"prompt": "SYNTHETIC_PRIVATE_TEXT", "summary": "safe"}},
        None,
    )

    stored = store.records[receipt.record_id]
    assert stored == {
        "version": 1,
        "schema": "helto.public-state",
        "valueSchema": "helto.dual-mode.record.v1",
        "private": False,
        "value": {"prompt": "SYNTHETIC_PRIVATE_TEXT", "summary": "safe"},
    }
    shells = handle.list_shells("prompt")
    assert shells == (PublicRecordShell(receipt.record_id, "prompt"),)
    assert shells[0].to_payload() == {
        "id": receipt.record_id,
        "kind": "prompt",
        "private": False,
        "label": "Public record",
    }
    revealed = handle.reveal("prompt", receipt.record_id, "details", None)
    assert revealed.value == {"summary": "safe"}
    assert "SYNTHETIC_PRIVATE_TEXT" not in repr(revealed)


def test_public_singletons_work_locked_with_revisioned_cas(public_pack):
    pack, _mode, _records, store = public_pack
    handle = pack.singletons("state")

    field = handle.replace_field(
        "settings",
        {"path": "/synthetic/public/path"},
        0,
        None,
    )
    blob = handle.replace_blob("blob", b"SYNTHETIC_PUBLIC_BLOB", 0, None)

    assert field.revision == blob.revision == 1
    assert handle.status("settings").to_payload() == {
        "exists": True,
        "revision": 1,
        "private": False,
        "currentFormat": True,
    }
    assert handle.reveal_field("settings", None).value == {
        "path": "/synthetic/public/path"
    }
    assert handle.reveal_blob("blob", None).value == b"SYNTHETIC_PUBLIC_BLOB"
    with pytest.raises(SingletonError) as conflict:
        handle.replace_field("settings", {"path": "changed"}, 0, None)
    assert conflict.value.code == "PRIVACY_SINGLETON_REVISION_CONFLICT"


def test_direct_mode_drift_blocks_public_values_without_reinterpretation(public_pack):
    pack, mode, records, singletons = public_pack
    record = pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "canary", "summary": "safe"}},
        None,
    )
    pack.singletons("state").replace_field("settings", {"value": "canary"}, 0, None)
    original_record = copy.deepcopy(records.records[record.record_id])
    original_singleton = copy.deepcopy(singletons.snapshots["settings"])

    mode.mode = "private"
    with pytest.raises(RecordError) as list_blocked:
        pack.records("records").list_shells("prompt")
    with pytest.raises(RecordError) as record_blocked:
        pack.records("records").reveal("prompt", record.record_id, "details", None)
    with pytest.raises(SingletonError) as singleton_blocked:
        pack.singletons("state").status("settings")

    assert list_blocked.value.code == "PRIVACY_RECORD_MODE_BLOCKED"
    assert record_blocked.value.code == "PRIVACY_RECORD_MODE_BLOCKED"
    assert singleton_blocked.value.code == "PRIVACY_SINGLETON_MODE_BLOCKED"
    assert records.records[record.record_id] == original_record
    assert singletons.snapshots["settings"] == original_singleton


def test_record_transition_hooks_commit_classify_and_rollback_after_restart(public_pack):
    pack, _mode, store, _singletons = public_pack
    receipt = pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "transition canary", "summary": "safe"}},
        None,
    )
    keystore.unlock_keystore("synthetic dual mode password")
    transition = prepare_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        record_id=receipt.record_id,
        prior_mode=EffectivePrivacyMode.PUBLIC,
        target_mode=EffectivePrivacyMode.PRIVATE,
    )
    assert "transition canary" not in repr(transition)

    commit_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        transition=transition,
    )
    assert classify_record_mode_transition_value(
        store.read_record(receipt.record_id), transition
    ) is ModeValueDisposition.TARGET
    commit_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        transition=transition,
    )

    rollback_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        transition=transition,
    )
    assert classify_record_mode_transition_value(
        store.read_record(receipt.record_id), transition
    ) is ModeValueDisposition.ORIGINAL


def test_mixed_public_private_record_listing_blocks_whole_result(public_pack):
    pack, mode, store, _singletons = public_pack
    first = pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "first", "summary": "safe"}},
        None,
    )
    pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "second", "summary": "safe"}},
        None,
    )
    keystore.unlock_keystore("synthetic dual mode password")
    transition = prepare_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        record_id=first.record_id,
        prior_mode=EffectivePrivacyMode.PUBLIC,
        target_mode=EffectivePrivacyMode.PRIVATE,
    )
    commit_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        transition=transition,
    )
    mode.mode = "private"
    keystore.lock_keystore()

    with pytest.raises(RecordError) as blocked:
        pack.records("records").list_shells("prompt")
    assert blocked.value.code == "PRIVACY_RECORD_MODE_BLOCKED"
    assert len(store.records) == 2


def test_singleton_transition_hooks_commit_classify_and_rollback_after_restart(public_pack):
    pack, _mode, _records, store = public_pack
    pack.singletons("state").replace_field("settings", {"value": "canary"}, 0, None)
    keystore.unlock_keystore("synthetic dual mode password")
    transition = prepare_singleton_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="state",
        singleton_id="settings",
        prior_mode=EffectivePrivacyMode.PUBLIC,
        target_mode=EffectivePrivacyMode.PRIVATE,
    )
    assert "canary" not in repr(transition)

    commit_singleton_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="state",
        transition=transition,
    )
    assert classify_singleton_mode_transition_value(
        store.snapshots["settings"], transition
    ) is ModeValueDisposition.TARGET
    rollback_singleton_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="state",
        transition=transition,
    )
    assert store.snapshots["settings"].revision == 3
    assert classify_singleton_mode_transition_value(
        store.snapshots["settings"], transition
    ) is ModeValueDisposition.ORIGINAL
    with pytest.raises(SingletonError) as stale:
        pack.singletons("state").replace_field(
            "settings",
            {"value": "stale"},
            1,
            None,
        )
    assert stale.value.code == "PRIVACY_SINGLETON_REVISION_CONFLICT"


def _mode_transition_authorization(pack):
    request = SimpleNamespace(
        headers={"X-Helto-Privacy-Token": keystore.session_token()},
        cookies={},
    )
    return authorize_privacy_request(
        request,
        "mode.transition",
        pack_id=pack.profile.id,
    )


def _create_public_transition_values(pack):
    record = pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "transition canary", "summary": "safe"}},
        None,
    )
    pack.singletons("state").replace_field(
        "settings",
        {"value": "transition canary"},
        0,
        None,
    )
    pack.singletons("state").replace_blob(
        "blob",
        b"transition canary",
        0,
        None,
    )
    return record.record_id


def test_shared_transition_commits_every_record_and_singleton_before_mode_source(
    public_pack,
):
    pack, mode, records, singletons = public_pack
    record_id = _create_public_transition_values(pack)
    keystore.unlock_keystore("synthetic dual mode password")

    result = pack.mode("mode").transition(
        "main",
        DeclaredPrivacyMode.PRIVATE,
        _mode_transition_authorization(pack),
        ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC),
    )

    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert mode.mode == "private"
    assert classify_state(
        "helto.dual-mode.record.v1",
        records.records[record_id],
    ) is EffectivePrivacyMode.PRIVATE
    assert classify_state(
        "helto.dual-mode.settings.v1",
        singletons.snapshots["settings"].protected,
    ) is EffectivePrivacyMode.PRIVATE
    assert classify_bytes(
        "helto.dual-mode.blob.v1",
        "blob",
        singletons.snapshots["blob"].protected,
    ) is EffectivePrivacyMode.PRIVATE


def test_shared_transition_rolls_back_all_dual_mode_values_on_commit_failure(
    public_pack,
):
    pack, mode, records, singletons = public_pack
    record_id = _create_public_transition_values(pack)
    keystore.unlock_keystore("synthetic dual mode password")
    singletons.fail_after_commit = True

    with pytest.raises(ModeTransitionError) as failed:
        pack.mode("mode").transition(
            "main",
            DeclaredPrivacyMode.PRIVATE,
            _mode_transition_authorization(pack),
            ModeFacts(current_mode=EffectivePrivacyMode.PUBLIC),
        )

    assert failed.value.code == "PRIVACY_TRANSITION_FAILED"
    assert mode.mode == "public"
    assert classify_state(
        "helto.dual-mode.record.v1",
        records.records[record_id],
    ) is EffectivePrivacyMode.PUBLIC
    assert classify_state(
        "helto.dual-mode.settings.v1",
        singletons.snapshots["settings"].protected,
    ) is EffectivePrivacyMode.PUBLIC
    assert classify_bytes(
        "helto.dual-mode.blob.v1",
        "blob",
        singletons.snapshots["blob"].protected,
    ) is EffectivePrivacyMode.PUBLIC


def test_transition_hooks_reject_divergence_and_rollback_ambiguous_singleton_commit(
    public_pack,
):
    pack, _mode, records, singletons = public_pack
    receipt = pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "canary", "summary": "safe"}},
        None,
    )
    pack.singletons("state").replace_field("settings", {"value": "canary"}, 0, None)
    keystore.unlock_keystore("synthetic dual mode password")
    record_transition = prepare_record_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="records",
        record_kind="prompt",
        record_id=receipt.record_id,
        prior_mode=EffectivePrivacyMode.PUBLIC,
        target_mode=EffectivePrivacyMode.PRIVATE,
    )
    singleton_transition = prepare_singleton_mode_transition_value(
        profile=pack.profile,
        adapters=pack._installation.adapters,
        resource_id="state",
        singleton_id="settings",
        prior_mode=EffectivePrivacyMode.PUBLIC,
        target_mode=EffectivePrivacyMode.PRIVATE,
    )

    records.records[receipt.record_id] = {
        **records.records[receipt.record_id],
        "value": {"prompt": "diverged", "summary": "safe"},
    }
    with pytest.raises(RecordError) as diverged:
        commit_record_mode_transition_value(
            profile=pack.profile,
            adapters=pack._installation.adapters,
            resource_id="records",
            record_kind="prompt",
            transition=record_transition,
        )
    assert diverged.value.code == "PRIVACY_RECORD_VERIFICATION_FAILED"

    singletons.fail_after_commit = True
    with pytest.raises(SingletonError) as failed:
        commit_singleton_mode_transition_value(
            profile=pack.profile,
            adapters=pack._installation.adapters,
            resource_id="state",
            transition=singleton_transition,
        )
    assert failed.value.code == "PRIVACY_SINGLETON_REPLACE_FAILED"
    assert classify_singleton_mode_transition_value(
        singletons.snapshots["settings"], singleton_transition
    ) is ModeValueDisposition.ORIGINAL


def test_public_records_and_singletons_work_with_no_keystore_file(
    tmp_path,
    monkeypatch,
):
    keystore_path = tmp_path / "never-created-keystore.json"
    monkeypatch.setenv("HELTO_PRIVACY_KEYSTORE", str(keystore_path))
    monkeypatch.setenv("HELTO_PRIVACY_MODE_STATE", str(tmp_path / "mode.json"))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: None,
    )
    monkeypatch.setattr(mode_runtime, "_MODE_TRANSITIONS", {})
    mode = MutableModeAdapter()
    records = RecordStore()
    singletons = SingletonStore()
    pack = runtime.install(
        _profile(),
        {
            "mode-store": mode,
            "record-store": records,
            "singleton-store": singletons,
        },
    )

    assert not keystore.keystore_exists()
    record = pack.records("records").mutate(
        "prompt",
        "create",
        {"record": {"prompt": "public", "summary": "safe"}},
        None,
    )
    assert pack.records("records").list_shells("prompt")[0].id == record.record_id
    assert pack.records("records").reveal(
        "prompt",
        record.record_id,
        "use",
        None,
    ).value == {"prompt": "public"}
    pack.singletons("state").replace_field("settings", {"value": "public"}, 0, None)
    pack.singletons("state").replace_blob("blob", b"public", 0, None)
    assert pack.singletons("state").reveal_field("settings", None).value == {
        "value": "public"
    }
    assert pack.singletons("state").reveal_blob("blob", None).value == b"public"
    assert not keystore.keystore_exists()


def test_install_rejects_blind_record_write_adapter(monkeypatch):
    class BlindRecordStore:
        def list_ids(self):
            return ()

        def read_protected(self, _record_id):
            return None

        def write_protected(self, _record_id, _value):
            return None

        def delete(self, _record_id):
            return None

        def mutate(self, current, _operation, _value):
            return current

        def project(self, value, _operation):
            return value

        def prepare_mode_transition(self, *_args):
            return None

        def commit_mode_transition(self, *_args):
            return None

        def rollback_mode_transition(self, *_args):
            return None

    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    with pytest.raises(runtime.AdapterBindingError) as failed:
        runtime.install(
            _profile(),
            {
                "mode-store": MutableModeAdapter(),
                "record-store": BlindRecordStore(),
                "singleton-store": SingletonStore(),
            },
        )
    assert failed.value.code == "adapter_contract_mismatch"


def test_record_exact_snapshot_cas_serializes_competing_processes(tmp_path):
    context = multiprocessing.get_context("spawn")
    schema = "helto.dual-mode.record.v1"
    record_id = "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    original = RecordSnapshot(
        1,
        protect_state(schema, {"prompt": "original"}, EffectivePrivacyMode.PUBLIC),
    )
    left = RecordSnapshot(
        2,
        protect_state(schema, {"prompt": "left"}, EffectivePrivacyMode.PUBLIC),
    )
    right = RecordSnapshot(
        2,
        protect_state(schema, {"prompt": "right"}, EffectivePrivacyMode.PUBLIC),
    )
    state_path = tmp_path / "record-state.json"
    state_path.write_text(
        json.dumps({
            record_id: {
                "revision": original.revision,
                "protected": original.protected,
            }
        }),
        encoding="utf-8",
    )
    store = MultiprocessRecordStore(state_path)
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_multiprocess_record_replace,
            args=(store, record_id, original, replacement, start, results),
        )
        for replacement in (left, right)
    ]
    for process in processes:
        process.start()
    start.set()
    outcomes = sorted(results.get(timeout=5) for _process in processes)
    for process in processes:
        process.join(timeout=5)
        assert process.exitcode == 0

    assert outcomes == ["PRIVACY_RECORD_REVISION_CONFLICT", "ok"]
    stored = store.read_record(record_id)
    assert stored.revision == 2
    assert stored == left or stored == right


def test_ambiguous_record_commit_never_rolls_back_concurrent_newer_write():
    schema = "helto.dual-mode.record.v1"
    record_id = "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    original = RecordSnapshot(
        1,
        protect_state(schema, {"prompt": "original"}, EffectivePrivacyMode.PUBLIC),
    )
    replacement = RecordSnapshot(
        2,
        protect_state(schema, {"prompt": "replacement"}, EffectivePrivacyMode.PUBLIC),
    )
    concurrent = RecordSnapshot(
        3,
        protect_state(schema, {"prompt": "concurrent"}, EffectivePrivacyMode.PUBLIC),
    )

    class AmbiguousStore:
        def __init__(self):
            self.snapshot = original

        def read_record(self, _record_id):
            return copy.deepcopy(self.snapshot)

        def compare_and_swap_record(self, _record_id, expected, target):
            if self.snapshot != expected:
                return False
            self.snapshot = copy.deepcopy(target)
            self.snapshot = copy.deepcopy(concurrent)
            raise RuntimeError("synthetic ambiguous commit")

    store = AmbiguousStore()
    with pytest.raises(RecordError) as failed:
        _replace_record_snapshot_exact(
            store,
            record_id,
            original,
            replacement,
        )
    assert failed.value.code == "PRIVACY_RECORD_ROLLBACK_FAILED"
    assert store.snapshot == concurrent


def test_singleton_rollback_conflict_preserves_concurrent_newer_revision(public_pack):
    pack, _mode, _records, store = public_pack
    concurrent = SingletonSnapshot(
        2,
        protect_state(
            "helto.dual-mode.settings.v1",
            {"value": "concurrent"},
            EffectivePrivacyMode.PUBLIC,
        ),
    )
    store.concurrent_after_commit = concurrent

    with pytest.raises(SingletonError) as failed:
        pack.singletons("state").replace_field(
            "settings",
            {"value": "replacement"},
            0,
            None,
        )
    assert failed.value.code == "PRIVACY_SINGLETON_ROLLBACK_FAILED"
    assert store.snapshots["settings"] == concurrent


def test_singleton_rollback_cas_cannot_overwrite_writer_arriving_during_rollback(
    public_pack,
):
    pack, _mode, _records, store = public_pack
    concurrent = SingletonSnapshot(
        2,
        protect_state(
            "helto.dual-mode.settings.v1",
            {"value": "concurrent"},
            EffectivePrivacyMode.PUBLIC,
        ),
    )
    store.fail_after_commit = True
    store.concurrent_before_rollback = concurrent

    with pytest.raises(SingletonError) as failed:
        pack.singletons("state").replace_field(
            "settings",
            {"value": "replacement"},
            0,
            None,
        )
    assert failed.value.code == "PRIVACY_SINGLETON_ROLLBACK_FAILED"
    assert store.snapshots["settings"] == concurrent
