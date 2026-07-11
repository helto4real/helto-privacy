from __future__ import annotations

import asyncio
import json
import stat
import threading
from pathlib import Path

import pytest

import helto_privacy.artifacts as artifacts
import helto_privacy.keystore as keystore
import helto_privacy.runtime as runtime
from helto_privacy import (
    ArtifactDeclaration,
    ArtifactError,
    ArtifactReference,
    ArtifactRetention,
    generate_artifact_owner_id,
)
from helto_privacy.guard import PrivacyAuthorizationError, authorize_privacy_request
from helto_privacy.profile import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
)


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
    assert locked.code == "PRIVACY_ARTIFACT_LEASE_INVALID"
    assert first_active_chunk == b"abcd"
    assert active_locked.code == "PRIVACY_ARTIFACT_LEASE_INVALID"


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
    assert failure.code == "PRIVACY_ARTIFACT_CLEANUP_FAILED"
    assert "SYNTHETIC" not in repr(failure)
    assert str(root) not in repr(failure)

    report = asyncio.run(handle.sweep())
    assert report.retired == 1
    assert report.pending == 0
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
