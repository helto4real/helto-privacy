from __future__ import annotations

import asyncio
import fcntl
import json
import os
import stat
import threading
import time as wall_time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.artifacts as artifacts
import helto_privacy.concurrency as concurrency
import helto_privacy.keystore as keystore
import helto_privacy.runtime as runtime
import helto_privacy.mode_runtime as mode_runtime
from helto_privacy import (
    ArtifactDeclaration,
    ArtifactError,
    ArtifactReference,
    ArtifactRetention,
    generate_artifact_owner_id,
)
from helto_privacy.guard import PrivacyAuthorizationError, authorize_privacy_request
from helto_privacy.mode import EffectivePrivacyMode, ModeTransitionError
from helto_privacy.profile import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
)
from helto_privacy.suite_runtime import SuiteBlockedError


class ModeAdapter(ModeSourceProtocolFixture):
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


class PublicModeAdapter(ModeAdapter):
    def read_declared_mode(self, _scope_id):
        return "public"


class MutableModeAdapter(ModeAdapter):
    def __init__(self, mode):
        self.mode = mode

    def read_declared_mode(self, _scope_id):
        return self.mode


class ArtifactAdapter:
    def encode(self, value):
        return bytes(value)

    def decode(self, value):
        return bytes(value)

    def purge_plaintext_derivatives(self, _artifact_kind):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


def _profile() -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.artifact-test",
        distribution="comfyui-artifact-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("media", ResourceKind.ARTIFACT, ("artifact-codec",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("artifact-codec", ResourceKind.ARTIFACT, "media"),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        artifacts=(
            ArtifactDeclaration(
                "durable-mask",
                "media",
                "main",
                "selector-mask",
                "artifact-codec",
                1,
                ArtifactRetention.DURABLE_ADJUNCT,
                ("use",),
                media_type="image/png",
            ),
            ArtifactDeclaration(
                "thumbnail",
                "media",
                "main",
                "timeline-thumbnail",
                "artifact-codec",
                2,
                ArtifactRetention.REGENERABLE_CACHE,
                ("preview",),
                media_type="image/webp",
            ),
            ArtifactDeclaration(
                "spill",
                "media",
                "main",
                "execution-spill",
                "artifact-codec",
                1,
                ArtifactRetention.RUN_SCOPED_SPILL,
                ("use",),
            ),
            ArtifactDeclaration(
                "replay",
                "media",
                "main",
                "served-replay",
                "artifact-codec",
                1,
                ArtifactRetention.SERVED_TRANSIENT,
                ("view",),
            ),
        ),
    )


@pytest.fixture
def artifact_pack(tmp_path, monkeypatch):
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(tmp_path / "artifacts"))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    pack = runtime.install(
        _profile(),
        {"mode": ModeAdapter(), "artifact-codec": ArtifactAdapter()},
    )
    token = keystore.initialize_keystore("synthetic artifact password")["token"]
    return pack, tmp_path / "artifacts", token


def test_durable_artifact_write_is_atomic_encrypted_and_purpose_bound(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    monkeypatch.setattr(
        "helto_privacy.artifacts.secrets.token_urlsafe",
        lambda _size: "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
    )
    owner_id = generate_artifact_owner_id()
    handle = pack.artifacts("media")

    async def exercise():
        reference = await asyncio.wait_for(
            handle.write(
                "durable-mask",
                owner_id,
                b"SYNTHETIC_PRIVATE_ARTIFACT_CANARY",
            ),
            timeout=5,
        )
        revealed = await asyncio.wait_for(
            handle.read("durable-mask", reference),
            timeout=5,
        )
        with pytest.raises(ArtifactError) as wrong_kind:
            await asyncio.wait_for(
                handle.read("thumbnail", reference),
                timeout=5,
            )
        return reference, revealed, wrong_kind.value

    reference, revealed, wrong_kind = asyncio.run(exercise())

    assert isinstance(reference, ArtifactReference)
    assert reference.to_payload() == {
        "schema": "helto.private-artifact-reference",
        "version": 1,
        "id": "hp-art-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
    }
    assert "A1b2C3d4" not in repr(reference)
    assert revealed == b"SYNTHETIC_PRIVATE_ARTIFACT_CANARY"

    stored_files = list(root.rglob("*.hpa"))
    assert len(stored_files) == 1
    stored = stored_files[0]
    assert b"SYNTHETIC_PRIVATE_ARTIFACT_CANARY" not in stored.read_bytes()
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert stat.S_IMODE(stored.parent.stat().st_mode) == 0o700
    assert not list(root.rglob("*.tmp"))

    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"][0]["artifactKind"] == "durable-mask"
    assert ledger["entries"][0]["ownerId"] == owner_id
    assert "SYNTHETIC" not in json.dumps(ledger)

    assert wrong_kind.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert "durable-mask" not in str(wrong_kind)


def test_blocking_executor_recovers_when_asyncio_completion_signal_is_missed(
    monkeypatch,
):
    async def exercise():
        loop = asyncio.get_running_loop()
        missed_completion = loop.create_future()
        monkeypatch.setattr(
            concurrency.asyncio,
            "wrap_future",
            lambda _future, *, loop: missed_completion,
        )
        return await asyncio.wait_for(
            concurrency.run_blocking_adapter(lambda: "synthetic-result"),
            timeout=1,
        )

    assert asyncio.run(exercise()) == "synthetic-result"


def test_blocking_executor_keeps_cancelled_workers_inside_process_admission_bound():
    release = threading.Event()
    all_started = threading.Event()
    fifth_started = threading.Event()
    started = 0
    started_lock = threading.Lock()

    def blocking_operation():
        nonlocal started
        with started_lock:
            started += 1
            if started == artifacts.ARTIFACT_MAX_PENDING:
                all_started.set()
        release.wait(timeout=2)

    async def cancel_first_loop():
        tasks = [
            asyncio.create_task(concurrency.run_blocking_adapter(blocking_operation))
            for _ in range(artifacts.ARTIFACT_MAX_PENDING)
        ]
        deadline = asyncio.get_running_loop().time() + 2
        while not all_started.is_set():
            if asyncio.get_running_loop().time() >= deadline:
                raise AssertionError("Blocking adapter workers did not start.")
            await asyncio.sleep(0.01)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(cancel_first_loop())

    async def enter_from_new_loop():
        fifth = asyncio.create_task(
            concurrency.run_blocking_adapter(
                lambda: fifth_started.set() or "fifth-result"
            )
        )
        await asyncio.sleep(0.05)
        assert fifth_started.is_set() is False
        release.set()
        assert await asyncio.wait_for(fifth, timeout=2) == "fifth-result"

    asyncio.run(enter_from_new_loop())


def test_artifact_write_rejects_locked_session_before_encoding(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    encode_calls = []

    def encode(_self, value):
        encode_calls.append(value)
        return bytes(value)

    monkeypatch.setattr(ArtifactAdapter, "encode", encode)
    keystore.lock_keystore()
    handle = pack.artifacts("media")

    async def exercise():
        with pytest.raises(ArtifactError) as locked:
            await handle.write(
                "durable-mask",
                generate_artifact_owner_id(),
                b"SYNTHETIC_LOCKED_ARTIFACT",
            )
        return locked.value

    failure = asyncio.run(exercise())

    assert failure.code == "PRIVACY_ARTIFACT_STORAGE_FAILED"
    assert encode_calls == []
    assert not list(root.rglob("*.hpa"))
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"] == []


def test_retention_classes_replace_expire_sweep_and_release_by_owner(
    artifact_pack,
    monkeypatch,
):
    pack, _root, _token = artifact_pack
    handle = pack.artifacts("media")
    clock = [1000.0]
    monkeypatch.setattr(artifacts.time, "time", lambda: clock[0])
    monkeypatch.setattr(artifacts, "REGENERABLE_CACHE_MAX_ENTRIES", 2)
    monkeypatch.setattr(artifacts, "REGENERABLE_CACHE_TTL_SECONDS", 10.0)
    owner = generate_artifact_owner_id()
    cache_owner_a = generate_artifact_owner_id()
    cache_owner_b = generate_artifact_owner_id()
    cache_owner_c = generate_artifact_owner_id()

    class SyntheticInterruption(BaseException):
        pass

    async def exercise():
        transient_a = await handle.write("replay", owner, b"TRANSIENT_A")
        transient_b = await handle.write("replay", owner, b"TRANSIENT_B")
        with pytest.raises(ArtifactError) as replaced:
            await handle.read("replay", transient_a)

        cache_a = await handle.write("thumbnail", cache_owner_a, b"CACHE_A")
        clock[0] += 1
        cache_b = await handle.write("thumbnail", cache_owner_b, b"CACHE_B")
        clock[0] += 1
        cache_c = await handle.write("thumbnail", cache_owner_c, b"CACHE_C")
        with pytest.raises(ArtifactError) as evicted:
            await handle.read("thumbnail", cache_a)

        run_reference = None
        try:
            async with handle.run() as run:
                run_reference = await run.write("spill", b"RUN_SPILL")
                raise SyntheticInterruption()
        except SyntheticInterruption:
            pass
        with pytest.raises(ArtifactError) as run_cleaned:
            await handle.read("spill", run_reference)

        durable = await handle.write("durable-mask", owner, b"DURABLE")
        clock[0] += 20
        artifacts.reset_artifact_runtime_for_tests()
        report = await handle.sweep()
        with pytest.raises(ArtifactError) as expired_b:
            await handle.read("thumbnail", cache_b)
        with pytest.raises(ArtifactError) as expired_c:
            await handle.read("thumbnail", cache_c)
        with pytest.raises(ArtifactError) as transient_swept:
            await handle.read("replay", transient_b)
        assert await handle.read("durable-mask", durable) == b"DURABLE"

        released = await handle.release_owner(owner)
        with pytest.raises(ArtifactError) as durable_released:
            await handle.read("durable-mask", durable)
        return {
            "replaced": replaced.value,
            "evicted": evicted.value,
            "run_cleaned": run_cleaned.value,
            "expired_b": expired_b.value,
            "expired_c": expired_c.value,
            "transient_swept": transient_swept.value,
            "report": report,
            "released": released,
            "durable_released": durable_released.value,
        }

    result = asyncio.run(exercise())

    for key in (
        "replaced",
        "evicted",
        "run_cleaned",
        "expired_b",
        "expired_c",
        "transient_swept",
        "durable_released",
    ):
        assert result[key].code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert result["report"].retired >= 3
    assert result["released"] == 1


def test_release_artifact_owner_is_constrained_to_exact_artifact_kind(artifact_pack):
    pack, _root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()

    async def exercise():
        durable = await handle.write("durable-mask", owner, b"DURABLE")
        thumbnail = await handle.write("thumbnail", owner, b"THUMBNAIL")
        retired = await artifacts.release_artifact_owner(
            profile=pack.profile,
            resource_id="media",
            artifact_kind="thumbnail",
            owner_id=owner,
        )
        with pytest.raises(ArtifactError) as thumbnail_released:
            await handle.read("thumbnail", thumbnail)
        return retired, await handle.read("durable-mask", durable), thumbnail_released.value

    retired, durable_value, released_error = asyncio.run(exercise())
    assert retired == 1
    assert durable_value == b"DURABLE"
    assert released_error.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"


def test_reconcile_owner_keeps_canonical_and_deletes_all_other_owner_artifacts(
    artifact_pack,
):
    pack, _root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    empty_owner = generate_artifact_owner_id()

    async def exercise():
        canonical = await handle.write("durable-mask", owner, b"CANONICAL")
        losers = (
            await handle.write("durable-mask", owner, b"LOSER_A"),
            await handle.write("durable-mask", owner, b"LOSER_B"),
        )
        empty_losers = (
            await handle.write("durable-mask", empty_owner, b"EMPTY_A"),
            await handle.write("durable-mask", empty_owner, b"EMPTY_B"),
        )
        retired = await handle.reconcile_owner(
            "durable-mask",
            owner,
            keep=(canonical,),
        )
        emptied = await handle.reconcile_owner("durable-mask", empty_owner)
        assert await handle.read("durable-mask", canonical) == b"CANONICAL"
        for reference in (*losers, *empty_losers):
            with pytest.raises(ArtifactError) as removed:
                await handle.read("durable-mask", reference)
            assert removed.value.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"

        for non_durable_kind in ("thumbnail", "spill", "replay"):
            with pytest.raises(ArtifactError) as rejected:
                await handle.reconcile_owner(
                    non_durable_kind,
                    generate_artifact_owner_id(),
                )
            assert rejected.value.code == "PRIVACY_ARTIFACT_RETENTION_INVALID"
        return retired, emptied

    assert asyncio.run(exercise()) == (2, 2)


def test_reconcile_owner_requires_active_suite_and_exact_stable_scope(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()

    async def create():
        return (
            await handle.write("durable-mask", owner, b"CANONICAL"),
            await handle.write("durable-mask", owner, b"LOSER"),
        )

    canonical, loser = asyncio.run(create())
    before = (root / "ledger.json").read_bytes()

    def suite_blocked():
        raise SuiteBlockedError("suite_incomplete")

    with monkeypatch.context() as blocked_suite:
        blocked_suite.setattr(
            artifacts,
            "require_active_process_suite",
            suite_blocked,
        )
        with pytest.raises(SuiteBlockedError) as rejected:
            asyncio.run(
                handle.reconcile_owner(
                    "durable-mask",
                    owner,
                    keep=(canonical,),
                )
            )
        assert rejected.value.code == "suite_incomplete"
    assert (root / "ledger.json").read_bytes() == before

    checked_scopes = []

    def transition_blocked(_installation, scope_id):
        checked_scopes.append(scope_id)
        raise ModeTransitionError("PRIVACY_TRANSITION_BLOCKED")

    with monkeypatch.context() as blocked_transition:
        blocked_transition.setattr(
            mode_runtime,
            "require_stable_bound_scope",
            transition_blocked,
        )
        with pytest.raises(ArtifactError) as rejected:
            asyncio.run(
                handle.reconcile_owner(
                    "durable-mask",
                    owner,
                    keep=(canonical,),
                )
            )
        assert rejected.value.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"
    assert checked_scopes == ["main"]
    assert (root / "ledger.json").read_bytes() == before
    assert asyncio.run(handle.read("durable-mask", loser)) == b"LOSER"

    entered_reconcile = threading.Event()
    reconcile_results = []
    failures = []
    original_reconcile = artifacts._reconcile_owner_locked

    def observe_reconcile(*args):
        entered_reconcile.set()
        return original_reconcile(*args)

    def reconcile_worker():
        try:
            reconcile_results.append(
                asyncio.run(
                    handle.reconcile_owner(
                        "durable-mask",
                        owner,
                        keep=(canonical,),
                    )
                )
            )
        except BaseException as exc:
            failures.append(exc)

    with monkeypatch.context() as ordered:
        ordered.setattr(
            artifacts,
            "_reconcile_owner_locked",
            observe_reconcile,
        )
        with mode_runtime._TRANSITION_LOCK:
            worker = threading.Thread(target=reconcile_worker)
            worker.start()
            assert entered_reconcile.wait(timeout=0.05) is False
        worker.join(timeout=5)

    assert worker.is_alive() is False
    assert failures == []
    assert reconcile_results == [1]


def test_reconcile_owner_blocks_inflight_lease_registration(
    artifact_pack,
    monkeypatch,
):
    pack, _root, token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    request = Request(token)

    async def create():
        return (
            await handle.write("durable-mask", owner, b"CANONICAL"),
            await handle.write("durable-mask", owner, b"LOSER"),
        )

    canonical, loser = asyncio.run(create())
    authorization = authorize_privacy_request(
        request,
        "artifact.use",
        pack_id=pack.profile.id,
    )
    entered_registration = threading.Event()
    release_registration = threading.Event()
    original_register = artifacts._register_artifact_lease

    def pause_registration(*args):
        entered_registration.set()
        assert release_registration.wait(timeout=5)
        return original_register(*args)

    leases = []
    failures = []

    def issue_lease():
        try:
            leases.append(
                asyncio.run(
                    handle.lease(
                        "durable-mask",
                        loser,
                        "use",
                        authorization,
                    )
                )
            )
        except BaseException as exc:
            failures.append(exc)

    with monkeypatch.context() as concurrent:
        concurrent.setattr(
            artifacts,
            "_register_artifact_lease",
            pause_registration,
        )
        worker = threading.Thread(target=issue_lease)
        worker.start()
        assert entered_registration.wait(timeout=5)
        assert asyncio.run(
            handle.reconcile_owner(
                "durable-mask",
                owner,
                keep=(canonical,),
            )
        ) == 1
        release_registration.set()
        worker.join(timeout=5)

    assert worker.is_alive() is False
    assert leases == []
    assert len(failures) == 1
    assert isinstance(failures[0], ArtifactError)
    assert failures[0].code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert artifacts._LEASES == {}


def test_reconcile_owner_rejects_duplicate_foreign_and_stale_kept_references(
    artifact_pack,
):
    pack, root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    foreign_owner = generate_artifact_owner_id()

    async def create():
        return {
            "canonical": await handle.write("durable-mask", owner, b"CANONICAL"),
            "loser": await handle.write("durable-mask", owner, b"LOSER"),
            "owner": await handle.write(
                "durable-mask",
                foreign_owner,
                b"FOREIGN_OWNER",
            ),
            "kind": await handle.write("thumbnail", owner, b"FOREIGN_KIND"),
            "stale": await handle.write("durable-mask", owner, b"STALE"),
        }

    references = asyncio.run(create())
    declaration = next(
        item for item in pack.profile.artifacts if item.id == "durable-mask"
    )
    foreign_pack = ArtifactReference(artifacts._new_artifact_id())
    artifacts._persist_artifact(
        artifacts._ArtifactLocator(
            "helto.foreign-artifact-test",
            "media",
            declaration,
            foreign_pack.id,
        ),
        owner,
        b"FOREIGN_PACK",
    )
    foreign_resource = ArtifactReference(artifacts._new_artifact_id())
    foreign_declaration = replace(declaration, resource_id="alternate-media")
    artifacts._persist_artifact(
        artifacts._ArtifactLocator(
            pack.profile.id,
            "alternate-media",
            foreign_declaration,
            foreign_resource.id,
        ),
        owner,
        b"FOREIGN_RESOURCE",
    )
    missing = ArtifactReference(artifacts._new_artifact_id())
    artifacts.reset_artifact_runtime_for_tests()
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    stale_entry = next(
        entry
        for entry in ledger["entries"]
        if entry["artifactId"] == references["stale"].id
    )
    stale_entry["cleanupPending"] = True
    artifacts._touch_entry(stale_entry)
    artifacts._write_ledger(ledger)
    before = json.loads((root / "ledger.json").read_text(encoding="utf-8"))

    invalid_keeps = (
        (references["canonical"], references["canonical"]),
        (references["owner"],),
        (references["kind"],),
        (foreign_pack,),
        (foreign_resource,),
        (missing,),
        (references["stale"],),
    )
    for keep in invalid_keeps:
        with pytest.raises(ArtifactError) as rejected:
            asyncio.run(handle.reconcile_owner("durable-mask", owner, keep=keep))
        assert rejected.value.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
        assert str(root) not in repr(rejected.value)
        assert owner not in repr(rejected.value)
    after = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert after == before
    assert asyncio.run(handle.read("durable-mask", references["canonical"])) == b"CANONICAL"
    assert asyncio.run(handle.read("durable-mask", references["loser"])) == b"LOSER"


def test_reconcile_owner_cleanup_failure_is_pending_sanitized_and_retryable(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()

    async def create():
        return (
            await handle.write("durable-mask", owner, b"CANONICAL"),
            await handle.write("durable-mask", owner, b"PLAINTEXT_CANARY"),
        )

    canonical, loser = asyncio.run(create())
    loser_path = next(root.rglob(f"{loser.id}.hpa"))
    original_unlink = Path.unlink

    def fail_loser(path, *args, **kwargs):
        if path == loser_path:
            raise OSError("/SYNTHETIC/PRIVATE/PATH/PLAINTEXT_CANARY")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as blocked:
        blocked.setattr(Path, "unlink", fail_loser)
        with pytest.raises(ArtifactError) as failed:
            asyncio.run(
                handle.reconcile_owner(
                    "durable-mask",
                    owner,
                    keep=(canonical,),
                )
            )

    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    loser_entry = next(
        entry for entry in ledger["entries"] if entry["artifactId"] == loser.id
    )
    assert loser_entry["cleanupPending"] is True
    assert failed.value.code == "PRIVACY_ARTIFACT_CLEANUP_FAILED"
    assert "SYNTHETIC" not in repr(failed.value)
    assert "PLAINTEXT_CANARY" not in repr(failed.value)
    assert str(root) not in repr(failed.value)
    with pytest.raises(ArtifactError) as revoked:
        asyncio.run(handle.read("durable-mask", loser))
    assert revoked.value.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert asyncio.run(handle.read("durable-mask", canonical)) == b"CANONICAL"
    assert asyncio.run(
        handle.reconcile_owner("durable-mask", owner, keep=(canonical,))
    ) == 1


def test_reconcile_owner_interruption_and_concurrent_commit_remain_retry_safe(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()

    async def create():
        return (
            await handle.write("durable-mask", owner, b"CANONICAL"),
            await handle.write("durable-mask", owner, b"LOSER_A"),
            await handle.write("durable-mask", owner, b"LOSER_B"),
        )

    canonical, loser_a, loser_b = asyncio.run(create())

    class SyntheticInterruption(BaseException):
        pass

    original_unlink = Path.unlink
    interrupted = False

    def interrupt_once(path, *args, **kwargs):
        nonlocal interrupted
        if path.suffix == ".hpa" and not interrupted:
            interrupted = True
            raise SyntheticInterruption()
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as interrupted_cleanup:
        interrupted_cleanup.setattr(Path, "unlink", interrupt_once)
        with pytest.raises(SyntheticInterruption):
            asyncio.run(
                handle.reconcile_owner(
                    "durable-mask",
                    owner,
                    keep=(canonical,),
                )
            )
    pending = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert {
        entry["artifactId"]
        for entry in pending["entries"]
        if entry["cleanupPending"] is True
    } == {loser_a.id, loser_b.id}
    assert asyncio.run(
        handle.reconcile_owner("durable-mask", owner, keep=(canonical,))
    ) == 2

    late_owner = generate_artifact_owner_id()
    late_canonical = asyncio.run(
        handle.write("durable-mask", late_owner, b"INITIAL_CANONICAL")
    )
    late_loser = asyncio.run(handle.write("durable-mask", late_owner, b"LATE_LOSER"))
    entered_reconcile = threading.Event()
    release_reconcile = threading.Event()
    original_write_ledger = artifacts._write_ledger
    paused = False

    def pause_reconcile(ledger):
        nonlocal paused
        if not paused and any(
            entry.get("cleanupPending") is True for entry in ledger["entries"]
        ):
            paused = True
            entered_reconcile.set()
            assert release_reconcile.wait(timeout=5)
        return original_write_ledger(ledger)

    reconcile_results = []
    writer_results = []
    failures = []

    def reconcile_worker():
        try:
            reconcile_results.append(
                asyncio.run(
                    handle.reconcile_owner(
                        "durable-mask",
                        late_owner,
                        keep=(late_canonical,),
                    )
                )
            )
        except BaseException as exc:
            failures.append(exc)

    def writer_worker():
        try:
            writer_results.append(
                asyncio.run(
                    handle.write("durable-mask", late_owner, b"COMMITTED_AFTER")
                )
            )
        except BaseException as exc:
            failures.append(exc)

    with monkeypatch.context() as concurrent:
        concurrent.setattr(artifacts, "_write_ledger", pause_reconcile)
        reconcile_thread = threading.Thread(target=reconcile_worker)
        reconcile_thread.start()
        assert entered_reconcile.wait(timeout=5)
        writer_thread = threading.Thread(target=writer_worker)
        writer_thread.start()
        wall_time.sleep(0.05)
        release_reconcile.set()
        reconcile_thread.join(timeout=5)
        writer_thread.join(timeout=5)

    assert failures == []
    assert reconcile_results == [1]
    assert len(writer_results) == 1
    with pytest.raises(ArtifactError):
        asyncio.run(handle.read("durable-mask", late_loser))
    assert asyncio.run(handle.read("durable-mask", late_canonical)) == b"INITIAL_CANONICAL"
    assert asyncio.run(handle.read("durable-mask", writer_results[0])) == b"COMMITTED_AFTER"
    artifacts.reset_artifact_runtime_for_tests()
    assert asyncio.run(handle.read("durable-mask", late_canonical)) == b"INITIAL_CANONICAL"
    assert asyncio.run(handle.read("durable-mask", writer_results[0])) == b"COMMITTED_AFTER"


def test_public_run_spill_is_plain_ephemeral_mode_fixed_and_never_leased(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "public-artifacts"
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    pack = runtime.install(
        _profile(),
        {"mode": PublicModeAdapter(), "artifact-codec": ArtifactAdapter()},
    )
    token = keystore.initialize_keystore("synthetic public spill password")["token"]
    handle = pack.artifacts("media")

    async def exercise():
        run = handle.run()
        with pytest.raises(ArtifactError) as transition_blocked:
            artifacts.prepare_artifact_mode_transition(
                pack._installation,
                "main",
                SimpleNamespace(
                    prior_mode=EffectivePrivacyMode.PUBLIC,
                    target_mode=EffectivePrivacyMode.PRIVATE,
                ),
            )
        reference = await run.write("spill", b"SYNTHETIC_PUBLIC_SPILL")
        assert await handle.read("spill", reference) == b"SYNTHETIC_PUBLIC_SPILL"
        authorization = authorize_privacy_request(
            Request(token),
            "artifact.use",
            pack_id=pack.profile.id,
        )
        with pytest.raises(ArtifactError) as no_lease:
            await handle.lease("spill", reference, "use", authorization)
        keystore.lock_keystore()
        assert await handle.read("spill", reference) == b"SYNTHETIC_PUBLIC_SPILL"
        await run.close()
        return transition_blocked.value, no_lease.value

    transition_blocked, no_lease = asyncio.run(exercise())
    assert transition_blocked.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"
    assert no_lease.code == "PRIVACY_ARTIFACT_LEASE_INVALID"
    assert not list(root.rglob("*.spill"))
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"] == []


def test_artifact_run_admission_serializes_registration_with_transition(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "admission-artifacts"
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    pack = runtime.install(
        _profile(),
        {"mode": PublicModeAdapter(), "artifact-codec": ArtifactAdapter()},
    )
    keystore.initialize_keystore("synthetic admission password")
    entered_register = threading.Event()
    release_register = threading.Event()
    transition_acquired = threading.Event()
    original_register = artifacts._register_active_run

    def paused_register(pack_id, scope_ids):
        entered_register.set()
        assert release_register.wait(timeout=5)
        return original_register(pack_id, scope_ids)

    monkeypatch.setattr(artifacts, "_register_active_run", paused_register)
    runs = []
    worker = threading.Thread(target=lambda: runs.append(pack.artifacts("media").run()))
    worker.start()
    assert entered_register.wait(timeout=5)
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
    release_register.set()
    worker.join(timeout=5)
    transition_worker.join(timeout=5)
    assert len(runs) == 1
    assert transition_acquired.is_set()
    asyncio.run(runs[0].close())


def test_transition_first_makes_artifact_run_capture_new_mode(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        artifacts.ARTIFACT_ROOT_ENV,
        str(tmp_path / "transition-first-artifacts"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    mode = MutableModeAdapter("public")
    pack = runtime.install(
        _profile(),
        {"mode": mode, "artifact-codec": ArtifactAdapter()},
    )
    keystore.initialize_keystore("synthetic transition-first password")
    started = threading.Event()
    runs = []

    def create_run():
        started.set()
        runs.append(pack.artifacts("media").run())

    with mode_runtime._TRANSITION_LOCK:
        worker = threading.Thread(target=create_run)
        worker.start()
        assert started.wait(timeout=5)
        mode.mode = "private"
    worker.join(timeout=5)
    assert len(runs) == 1
    assert runs[0]._run_modes["spill"] == "private"
    asyncio.run(runs[0].close())


def test_public_spill_cleanup_failure_blocks_reads_and_transition_until_retry(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "cleanup-blocked-artifacts"
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    mode = MutableModeAdapter("public")
    pack = runtime.install(
        _profile(),
        {"mode": mode, "artifact-codec": ArtifactAdapter()},
    )
    keystore.initialize_keystore("synthetic cleanup-blocked password")
    handle = pack.artifacts("media")
    run = handle.run()
    reference = asyncio.run(run.write("spill", b"PUBLIC_CLEANUP_CANARY"))
    original_unlink = Path.unlink

    def fail_public_spill(path, *args, **kwargs):
        if path.suffix == ".spill":
            raise OSError("/SYNTHETIC/PRIVATE/PATH")
        return original_unlink(path, *args, **kwargs)

    context = SimpleNamespace(
        prior_mode=EffectivePrivacyMode.PUBLIC,
        target_mode=EffectivePrivacyMode.PRIVATE,
    )
    with monkeypatch.context() as blocked:
        blocked.setattr(Path, "unlink", fail_public_spill)
        with pytest.raises(ArtifactError) as cleanup_failed:
            asyncio.run(run.close())
        with pytest.raises(ArtifactError) as read_blocked:
            asyncio.run(handle.read("spill", reference))
        with pytest.raises(ArtifactError) as transition_blocked:
            artifacts.prepare_artifact_mode_transition(
                pack._installation,
                "main",
                context,
            )
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"][0]["cleanupPending"] is True
    assert ledger["entries"][0]["state"] == "READY"
    assert ledger["entries"][0]["payloadMode"] == "bounded-bytes-v1"
    assert cleanup_failed.value.code == "PRIVACY_ARTIFACT_CLEANUP_FAILED"
    assert read_blocked.value.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert transition_blocked.value.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"
    assert list(root.rglob("*.spill"))

    assert asyncio.run(run.close()) == 1
    artifacts.prepare_artifact_mode_transition(pack._installation, "main", context)
    assert not list(root.rglob("*.spill"))
    assert json.loads((root / "ledger.json").read_text(encoding="utf-8"))["entries"] == []


def test_public_spill_read_fails_when_current_scope_mode_drifts_private(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        artifacts.ARTIFACT_ROOT_ENV,
        str(tmp_path / "public-mode-drift-artifacts"),
    )
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    mode = MutableModeAdapter("public")
    pack = runtime.install(
        _profile(),
        {"mode": mode, "artifact-codec": ArtifactAdapter()},
    )
    keystore.initialize_keystore("synthetic public drift password")
    handle = pack.artifacts("media")
    run = handle.run()
    reference = asyncio.run(run.write("spill", b"PUBLIC_MODE_DRIFT_CANARY"))
    mode.mode = "private"
    with pytest.raises(ArtifactError) as blocked:
        asyncio.run(handle.read("spill", reference))
    assert blocked.value.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"
    asyncio.run(run.close())


def test_opaque_operation_scoped_lease_streams_and_revokes_with_session(
    artifact_pack,
    monkeypatch,
):
    pack, root, token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    clock = [2000.0]
    monkeypatch.setattr(artifacts.time, "time", lambda: clock[0])
    monkeypatch.setattr(artifacts, "ARTIFACT_STREAM_CHUNK_BYTES", 4)
    request = Request(token)
    original_read_text = Path.read_text

    def reject_whole_artifact_reads(path, *args, **kwargs):
        if path.suffix == ".hpa":
            raise AssertionError("artifact serving must not load the whole file")
        return original_read_text(path, *args, **kwargs)

    async def exercise():
        reference = await handle.write("thumbnail", owner, b"abcdefghijkl")
        authorization = authorize_privacy_request(
            request,
            "artifact.preview",
            pack_id=pack.profile.id,
        )
        monkeypatch.setattr(Path, "read_text", reject_whole_artifact_reads)
        lease = await handle.lease("thumbnail", reference, "preview", authorization)
        stream = await artifacts.open_artifact_lease(request, lease.id)
        chunks = [chunk async for chunk in stream.iter_chunks()]

        with pytest.raises(PrivacyAuthorizationError):
            wrong_authorization = authorize_privacy_request(
                request,
                "artifact.use",
                pack_id=pack.profile.id,
            )
            await handle.lease(
                "thumbnail",
                reference,
                "preview",
                wrong_authorization,
            )

        expiring = await handle.lease(
            "thumbnail",
            reference,
            "preview",
            authorization,
        )
        clock[0] += artifacts.ARTIFACT_LEASE_TTL_SECONDS + 1
        with pytest.raises(ArtifactError) as expired:
            await artifacts.open_artifact_lease(request, expiring.id)

        clock[0] = 2000.0
        restarted = await handle.lease(
            "thumbnail",
            reference,
            "preview",
            authorization,
        )
        artifacts.reset_artifact_runtime_for_tests()
        with pytest.raises(ArtifactError) as after_restart:
            await artifacts.open_artifact_lease(request, restarted.id)

        revoked = await handle.lease(
            "thumbnail",
            reference,
            "preview",
            authorization,
        )
        active = await handle.lease(
            "thumbnail",
            reference,
            "preview",
            authorization,
        )
        active_stream = await artifacts.open_artifact_lease(request, active.id)
        active_chunks = active_stream.iter_chunks()
        first_active_chunk = await anext(active_chunks)
        keystore.lock_keystore()
        with pytest.raises(ArtifactError) as active_locked:
            await anext(active_chunks)
        with pytest.raises(ArtifactError) as locked:
            await artifacts.open_artifact_lease(request, revoked.id)
        return (
            reference,
            lease,
            stream,
            chunks,
            expired.value,
            after_restart.value,
            locked.value,
            first_active_chunk,
            active_locked.value,
        )

    (
        reference,
        lease,
        stream,
        chunks,
        expired,
        after_restart,
        locked,
        first_active_chunk,
        active_locked,
    ) = asyncio.run(exercise())

    assert b"".join(chunks) == b"abcdefghijkl"
    assert len(chunks) == 3
    assert lease.url == f"/helto_privacy/artifacts/{lease.id}"
    serialized = json.dumps(lease.to_payload())
    assert reference.id not in serialized
    assert token not in serialized
    assert str(root) not in serialized
    assert stream.media_type == "image/webp"
    assert stream.headers["Cache-Control"] == "private, no-store"
    assert stream.headers["Content-Disposition"] == (
        'inline; filename="private-artifact.bin"'
    )
    assert expired.code == "PRIVACY_ARTIFACT_LEASE_INVALID"
    assert after_restart.code == "PRIVACY_ARTIFACT_LEASE_INVALID"
    assert locked.code == "PRIVACY_ARTIFACT_LEASE_INVALID"
    assert first_active_chunk == b"abcd"
    assert active_locked.code == "PRIVACY_ARTIFACT_LEASE_INVALID"


def test_root_bound_source_lease_streams_without_materializing_or_copying_source(
    artifact_pack,
    monkeypatch,
    tmp_path,
):
    pack, root, token = artifact_pack
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source_path = source_root / "clip.webm"
    source_path.write_bytes(b"abcdefghijkl")
    request = Request(token)
    monkeypatch.setattr(artifacts, "ARTIFACT_STREAM_CHUNK_BYTES", 4)

    async def exercise():
        source = artifacts.root_bound_source(
            source_path,
            (source_root,),
            media_type="video/webm",
        )
        authorization = authorize_privacy_request(
            request,
            "serve-source-media",
            pack_id=pack.profile.id,
        )
        lease = await artifacts.issue_root_bound_source_lease(
            pack_id=pack.profile.id,
            operation_id="serve-source-media",
            source=source,
            authorization=authorization,
        )
        stream = await artifacts.open_artifact_lease(request, lease.id)
        chunks = [chunk async for chunk in stream.iter_chunks()]
        return lease, stream, chunks

    lease, stream, chunks = asyncio.run(exercise())

    assert chunks == [b"abcd", b"efgh", b"ijkl"]
    assert stream.media_type == "video/webm"
    assert stream.headers["Cache-Control"] == "private, no-store"
    assert stream.headers["Content-Disposition"] == (
        'inline; filename="private-artifact.bin"'
    )
    serialized = json.dumps(lease.to_payload())
    assert str(source_path) not in serialized
    assert source_path.name not in serialized
    assert token not in serialized
    assert not list(root.rglob("*clip*"))


def test_cancelled_source_lease_issue_revokes_inserted_unreturned_lease(
    artifact_pack,
    monkeypatch,
    tmp_path,
):
    pack, _root, token = artifact_pack
    source_root = tmp_path / "cancelled-source"
    source_root.mkdir()
    source_path = source_root / "clip.webm"
    source_path.write_bytes(b"synthetic")
    request = Request(token)
    original_run_blocking = artifacts._run_blocking
    entered = asyncio.Event()
    release = asyncio.Event()

    async def controlled_run_blocking(operation, *args):
        if operation is artifacts._lease_is_current:
            entered.set()
            await release.wait()
        return await original_run_blocking(operation, *args)

    monkeypatch.setattr(artifacts, "_run_blocking", controlled_run_blocking)

    async def exercise():
        source = artifacts.root_bound_source(
            source_path,
            (source_root,),
            media_type="video/webm",
        )
        authorization = authorize_privacy_request(
            request,
            "serve-source-media",
            pack_id=pack.profile.id,
        )
        pending = asyncio.create_task(
            artifacts.issue_root_bound_source_lease(
                pack_id=pack.profile.id,
                operation_id="serve-source-media",
                source=source,
                authorization=authorization,
            )
        )
        await entered.wait()
        with artifacts._LOCK:
            inserted = tuple(artifacts._LEASES)
        assert len(inserted) == 1
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        with artifacts._LOCK:
            assert all(lease_id not in artifacts._LEASES for lease_id in inserted)

    asyncio.run(exercise())


def test_root_bound_source_rejects_escape_symlink_and_wrong_authorization(
    artifact_pack,
    tmp_path,
):
    pack, _root, token = artifact_pack
    source_root = tmp_path / "sources"
    source_root.mkdir()
    outside = tmp_path / "outside.webm"
    outside.write_bytes(b"outside")
    linked = source_root / "linked.webm"
    linked.symlink_to(outside)

    with pytest.raises(ArtifactError) as escaped:
        artifacts.root_bound_source(outside, (source_root,), media_type="video/webm")
    with pytest.raises(ArtifactError) as symlinked:
        artifacts.root_bound_source(linked, (source_root,), media_type="video/webm")
    assert escaped.value.code == "PRIVACY_ARTIFACT_SOURCE_REJECTED"
    assert symlinked.value.code == "PRIVACY_ARTIFACT_SOURCE_REJECTED"

    request = Request(token)
    allowed = source_root / "allowed.webm"
    allowed.write_bytes(b"allowed")
    source = artifacts.root_bound_source(
        allowed,
        (source_root,),
        media_type="video/webm",
    )
    correct = authorize_privacy_request(
        request,
        "serve-source-media",
        pack_id=pack.profile.id,
    )
    lease = asyncio.run(
        artifacts.issue_root_bound_source_lease(
            pack_id=pack.profile.id,
            operation_id="serve-source-media",
            source=source,
            authorization=correct,
        )
    )
    allowed.unlink()
    with pytest.raises(ArtifactError) as removed_before_open:
        asyncio.run(artifacts.open_artifact_lease(request, lease.id))
    assert removed_before_open.value.code == "PRIVACY_ARTIFACT_SOURCE_REJECTED"

    allowed.write_bytes(b"allowed")
    source = artifacts.root_bound_source(
        allowed,
        (source_root,),
        media_type="video/webm",
    )
    wrong = authorize_privacy_request(
        request,
        "artifact.view",
        pack_id=pack.profile.id,
    )
    with pytest.raises(PrivacyAuthorizationError):
        asyncio.run(
            artifacts.issue_root_bound_source_lease(
                pack_id=pack.profile.id,
                operation_id="serve-source-media",
                source=source,
                authorization=wrong,
            )
        )


def test_artifact_retirement_revokes_an_active_browser_lease(artifact_pack):
    pack, _root, token = artifact_pack
    handle = pack.artifacts("media")
    request = Request(token)

    async def exercise():
        reference = await handle.write(
            "thumbnail",
            generate_artifact_owner_id(),
            b"replacement-sensitive-preview",
        )
        authorization = authorize_privacy_request(
            request,
            "artifact.preview",
            pack_id=pack.profile.id,
        )
        lease = await handle.lease(
            "thumbnail",
            reference,
            "preview",
            authorization,
        )
        stream = await artifacts.open_artifact_lease(request, lease.id)
        chunks = stream.iter_chunks()
        first = await anext(chunks)
        await handle.retire("thumbnail", reference)
        with pytest.raises(ArtifactError) as revoked:
            await anext(chunks)
        await chunks.aclose()
        return first, revoked.value

    first, revoked = asyncio.run(exercise())

    assert first
    assert revoked.code == "PRIVACY_ARTIFACT_LEASE_INVALID"


def test_served_transient_batch_items_require_distinct_lifecycle_owners(
    artifact_pack,
):
    pack, _root, _token = artifact_pack
    handle = pack.artifacts("media")

    async def exercise():
        shared_owner = generate_artifact_owner_id()
        retired = await handle.write("replay", shared_owner, b"first")
        current = await handle.write("replay", shared_owner, b"second")
        with pytest.raises(ArtifactError) as stale:
            await handle.read("replay", retired)

        first_distinct = await handle.write(
            "replay",
            generate_artifact_owner_id(),
            b"batch-a",
        )
        second_distinct = await handle.write(
            "replay",
            generate_artifact_owner_id(),
            b"batch-b",
        )
        return (
            stale.value,
            await handle.read("replay", current),
            await handle.read("replay", first_distinct),
            await handle.read("replay", second_distinct),
        )

    stale, current, first_distinct, second_distinct = asyncio.run(exercise())
    assert stale.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert (current, first_distinct, second_distinct) == (
        b"second",
        b"batch-a",
        b"batch-b",
    )


def test_served_transients_retire_after_consumption_and_bad_caches_are_discarded(
    artifact_pack,
):
    pack, root, token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    request = Request(token)

    async def exercise():
        transient = await handle.write("replay", owner, b"ONE_USE_TRANSIENT")
        authorization = authorize_privacy_request(
            request,
            "artifact.view",
            pack_id=pack.profile.id,
        )
        lease = await handle.lease("replay", transient, "view", authorization)
        stream = await artifacts.open_artifact_lease(request, lease.id)
        chunks = [chunk async for chunk in stream.iter_chunks()]
        with pytest.raises(ArtifactError) as consumed:
            await handle.read("replay", transient)

        cache = await handle.write("thumbnail", owner, b"DISPOSABLE_CACHE")
        cache_path = next(root.rglob(f"{cache.id}.hpa"))
        cache_path.write_text("{not-an-envelope", encoding="utf-8")
        with pytest.raises(ArtifactError) as unreadable:
            await handle.read("thumbnail", cache)
        return b"".join(chunks), consumed.value, unreadable.value, cache

    plaintext, consumed, unreadable, cache = asyncio.run(exercise())

    assert plaintext == b"ONE_USE_TRANSIENT"
    assert consumed.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert unreadable.code == "PRIVACY_ARTIFACT_UNREADABLE"
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert all(entry["artifactId"] != cache.id for entry in ledger["entries"])
    assert not list(root.rglob(f"{cache.id}.hpa"))


def test_artifact_blocking_work_is_bounded_and_does_not_stall_the_event_loop(
    artifact_pack,
    monkeypatch,
):
    pack, _root, _token = artifact_pack
    handle = pack.artifacts("media")
    release = threading.Event()
    state_lock = threading.Lock()
    active = 0
    peak = 0

    def blocking_persist(*_args):
        nonlocal active, peak
        with state_lock:
            active += 1
            peak = max(peak, active)
        release.wait(timeout=5)
        with state_lock:
            active -= 1

    monkeypatch.setattr(artifacts, "_persist_artifact", blocking_persist)

    async def exercise():
        owner = generate_artifact_owner_id()
        tasks = [
            asyncio.create_task(handle.write("thumbnail", owner, bytes([index])))
            for index in range(8)
        ]
        heartbeat = 0
        for _ in range(2_000):
            await asyncio.sleep(0.001)
            heartbeat += 1
            with state_lock:
                if peak == artifacts.ARTIFACT_MAX_PENDING:
                    break
        release.set()
        await asyncio.gather(*tasks)
        return heartbeat

    heartbeat = asyncio.run(exercise())

    assert peak == artifacts.ARTIFACT_MAX_PENDING
    assert heartbeat > 0


def test_cleanup_failures_are_ledgered_retried_and_never_expose_paths(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()

    async def create():
        return await handle.write("durable-mask", owner, b"CLEANUP_CANARY")

    reference = asyncio.run(create())
    original_unlink = Path.unlink

    def fail_artifact_unlink(path, *args, **kwargs):
        if path.suffix == ".hpa":
            raise OSError("/SYNTHETIC/PRIVATE/PATH")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as blocked:
        blocked.setattr(Path, "unlink", fail_artifact_unlink)

        async def fail_cleanup():
            with pytest.raises(ArtifactError) as failed:
                await handle.retire("durable-mask", reference)
            return failed.value

        failure = asyncio.run(fail_cleanup())

    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"][0]["cleanupPending"] is True
    assert ledger["entries"][0]["state"] == "READY"
    assert ledger["entries"][0]["payloadMode"] == "bounded-bytes-v1"
    assert failure.code == "PRIVACY_ARTIFACT_CLEANUP_FAILED"
    assert "SYNTHETIC" not in repr(failure)
    assert str(root) not in repr(failure)

    report = asyncio.run(handle.sweep())
    assert report.retired == 1
    assert report.pending == 0
    assert not list(root.rglob("*.hpa"))


def test_group_retirement_revokes_all_authority_before_orphan_sweep(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    handle = pack.artifacts("media")

    async def create():
        return (
            await handle.write(
                "replay",
                generate_artifact_owner_id(),
                b"group-a",
            ),
            await handle.write(
                "replay",
                generate_artifact_owner_id(),
                b"group-b",
            ),
        )

    first, second = asyncio.run(create())
    blocked_path = next(root.rglob(f"{first.id}.hpa"))
    original_unlink = Path.unlink

    def fail_one(path, *args, **kwargs):
        if path == blocked_path:
            raise OSError("synthetic cleanup fault")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as blocked:
        blocked.setattr(Path, "unlink", fail_one)
        retired = asyncio.run(
            handle.retire_group(
                (("replay", first), ("replay", second))
            )
        )

    assert retired == 1
    for reference in (first, second):
        with pytest.raises(ArtifactError) as revoked:
            asyncio.run(handle.read("replay", reference))
        assert revoked.value.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    report = asyncio.run(handle.sweep())
    assert report.retired == 1
    assert not list(root.rglob("*.hpa"))


def test_startup_sweep_retires_interrupted_runs_and_rejects_unsafe_ledgers(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    run = pack.artifacts("media").run()

    async def leave_interrupted_run():
        return await run.write("spill", b"INTERRUPTED_RUN_CANARY")

    asyncio.run(leave_interrupted_run())
    assert list(root.rglob("*.hpa"))
    orphan = root / "helto.artifact-test" / "media" / "spill" / "orphan.hpa"
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"SYNTHETIC_ORPHAN_CIPHERTEXT")

    artifacts.reset_artifact_runtime_for_tests()
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    restarted = runtime.install(
        _profile(),
        {"mode": ModeAdapter(), "artifact-codec": ArtifactAdapter()},
    )
    assert restarted.profile.id == pack.profile.id
    assert not list(root.rglob("*.hpa"))

    outside = root.parent / "outside-canary"
    outside.write_text("must remain", encoding="utf-8")
    unsafe = {
        "schema": artifacts.ARTIFACT_LEDGER_SCHEMA,
        "version": artifacts.ARTIFACT_LEDGER_VERSION,
        "entries": [{
            "artifactId": "hp-art-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "artifactKind": "../outside-canary",
            "cleanupPending": True,
            "createdAt": 1.0,
            "formatVersion": 1,
            "ownerId": "hp-owner-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "packId": "helto.artifact-test",
            "processEpoch": "synthetic-epoch",
            "resourceId": "media",
            "retention": "run-scoped-spill",
        }],
    }
    (root / "ledger.json").write_text(json.dumps(unsafe), encoding="utf-8")

    with pytest.raises(ArtifactError) as rejected:
        asyncio.run(restarted.artifacts("media").sweep())
    assert rejected.value.code == "PRIVACY_ARTIFACT_LEDGER_INVALID"
    assert outside.read_text(encoding="utf-8") == "must remain"


def test_startup_fails_closed_when_plaintext_temp_cleanup_cannot_finish(
    artifact_pack,
    monkeypatch,
):
    pack, root, _token = artifact_pack
    plaintext_temp = root / "interrupted.plaintext"
    plaintext_temp.write_bytes(b"SYNTHETIC_STARTUP_PLAINTEXT")
    original_unlink = Path.unlink

    def fail_plaintext_unlink(path, *args, **kwargs):
        if path == plaintext_temp:
            raise OSError("/SYNTHETIC/PRIVATE/PATH")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_plaintext_unlink)
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    artifacts.reset_artifact_runtime_for_tests()

    with pytest.raises(ArtifactError) as blocked:
        runtime.install(
            _profile(),
            {"mode": ModeAdapter(), "artifact-codec": ArtifactAdapter()},
        )

    assert blocked.value.code == "PRIVACY_ARTIFACT_CLEANUP_FAILED"
    assert pack.profile.id not in runtime._INSTALLATIONS
    assert plaintext_temp.exists()
    assert "SYNTHETIC" not in str(blocked.value)
