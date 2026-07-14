from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.artifacts as artifacts
import helto_privacy.keystore as keystore
import helto_privacy.runtime as runtime
from helto_privacy.guard import authorize_privacy_request
from helto_privacy.artifact_stream import (
    ArtifactStreamError,
    PrivateArtifactStreamWriter,
    open_private_artifact_source,
)
from helto_privacy.profile import (
    AdapterSlot,
    ArtifactDecodedOutput,
    ArtifactDeclaration,
    ArtifactPayloadMode,
    ArtifactRetention,
    ArtifactStreamContract,
    PrivacyProfile,
    ProfileValidationError,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
)


class _ModeAdapter(ModeSourceProtocolFixture):
    def __init__(self, mode: str = "private") -> None:
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


class _StreamAdapter:
    def __init__(self) -> None:
        self.sources = []

    def encode_to(self, value, sink):
        for chunk in value:
            sink.write(chunk)

    def decode_from(self, source):
        self.sources.append(source)
        chunks = []
        while True:
            chunk = source.read(source.max_chunk_bytes)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def purge_plaintext_derivatives(self, _artifact_kind):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class _CancelledStreamAdapter(_StreamAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def encode_to(self, value, sink):
        sink.write(value)
        self.entered.set()
        assert self.release.wait(timeout=5)
        sink.write(value)


class _Request:
    def __init__(self, token: str) -> None:
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


def _profile(*, max_plaintext: int = 64, max_owner: int = 128) -> PrivacyProfile:
    return PrivacyProfile(
        id="helto.stream-test",
        distribution="comfyui-stream-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("media", ResourceKind.ARTIFACT, ("stream-codec",)),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("stream-codec", ResourceKind.ARTIFACT, "media"),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        artifacts=(
            ArtifactDeclaration(
                "segment",
                "media",
                "main",
                "execution-segment",
                "stream-codec",
                1,
                ArtifactRetention.RUN_SCOPED_SPILL,
                ("use",),
                payload_mode=ArtifactPayloadMode.STREAM_V1,
                stream_contract=ArtifactStreamContract(
                    "raw-segment-v1",
                    1,
                    max_plaintext,
                    ArtifactDecodedOutput.MATERIALIZED,
                    max_materialized_output_bytes=max_plaintext,
                    max_owner_plaintext_bytes=max_owner,
                ),
            ),
        ),
    )


def _install(tmp_path, monkeypatch, *, mode="private", adapter=None, profile=None):
    root = tmp_path / "artifacts"
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
    artifacts.reset_artifact_runtime_for_tests()
    stream_adapter = adapter or _StreamAdapter()
    pack = runtime.install(
        profile or _profile(),
        {"mode": _ModeAdapter(mode), "stream-codec": stream_adapter},
    )
    keystore.initialize_keystore("synthetic stream password")
    return pack, root, stream_adapter


def test_hpa_v2_preflights_authenticated_transcript_before_source(tmp_path):
    path = tmp_path / "stream.hpa"
    master = b"k" * 32
    with path.open("xb") as handle:
        writer = PrivateArtifactStreamWriter(
            handle,
            master_key=master,
            key_id="key-1",
            artifact_id="hp-art-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            owner_id="hp-owner-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            contract_digest="c" * 64,
            codec_schema="raw-segment-v1",
            codec_version=1,
            chunk_bytes=8,
            max_plaintext_bytes=16,
        )
        writer.sink.write(b"1234")
        writer.sink.write(b"5678")
        assert writer.finish() == 8
        handle.flush()
        os.fsync(handle.fileno())

    source = open_private_artifact_source(
        path,
        key_for_id=lambda key_id: master if key_id == "key-1" else None,
        owner_id="hp-owner-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        artifact_id="hp-art-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        contract_digest="c" * 64,
        codec_schema="raw-segment-v1",
        codec_version=1,
        chunk_bytes=8,
        max_plaintext_bytes=16,
        expected_plaintext_bytes=8,
    )
    assert source.read(8) == b"1234"
    assert source.read(8) == b"5678"
    assert source.read(8) == b""
    source.close()
    with pytest.raises(ArtifactStreamError):
        source.read(1)

    damaged = bytearray(path.read_bytes())
    damaged[len(damaged) // 2] ^= 1
    path.write_bytes(damaged)
    with pytest.raises(ArtifactStreamError):
        open_private_artifact_source(
            path,
            key_for_id=lambda _key_id: master,
            owner_id="hp-owner-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            artifact_id="hp-art-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            contract_digest="c" * 64,
            codec_schema="raw-segment-v1",
            codec_version=1,
            chunk_bytes=8,
            max_plaintext_bytes=16,
            expected_plaintext_bytes=8,
        )


@pytest.mark.parametrize("mode,extension", [("private", "hpa"), ("public", "spill")])
def test_stream_artifact_round_trip_is_ready_bounded_and_direct(
    tmp_path,
    monkeypatch,
    mode,
    extension,
):
    pack, root, adapter = _install(tmp_path, monkeypatch, mode=mode)
    handle = pack.artifacts("media")

    async def exercise():
        run = handle.run()
        reference = await run.write("segment", (b"abc", b"def"))
        value = await handle.read("segment", reference)
        return run, reference, value

    run, reference, value = asyncio.run(exercise())
    assert value == b"abcdef"
    assert len(list(root.rglob(f"*.{extension}"))) == 1
    assert not list(root.rglob("*.part"))
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    entry = ledger["entries"][0]
    assert entry["state"] == "READY"
    assert entry["payloadMode"] == "stream-v1"
    assert entry["plaintextBytes"] == 6
    assert entry["fileVersion"] == (2 if mode == "private" else 1)
    with pytest.raises(ArtifactStreamError):
        adapter.sources[-1].read(1)
    assert asyncio.run(run.close()) == 1
    assert not list(root.rglob(f"*.{extension}"))


def test_cancelled_stream_write_waits_for_cleanup(tmp_path, monkeypatch):
    adapter = _CancelledStreamAdapter()
    pack, root, _adapter = _install(tmp_path, monkeypatch, adapter=adapter)
    run = pack.artifacts("media").run()

    async def exercise():
        task = asyncio.create_task(run.write("segment", b"1234"))
        while not adapter.entered.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        adapter.release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"] == []
    assert not list(root.rglob("*.hpa"))
    assert not list(root.rglob("*.part"))
    assert asyncio.run(run.close()) == 0


@pytest.mark.parametrize(
    "boundary",
    ["construction", "finish", "flush", "fsync", "replace"],
)
def test_post_registration_stream_storage_failures_are_sanitized_and_cleaned(
    tmp_path,
    monkeypatch,
    boundary,
):
    pack, root, _adapter = _install(tmp_path, monkeypatch)
    original_writer = artifacts.PrivateArtifactStreamWriter
    secret = f"/SYNTHETIC/{boundary}/PRIVATE"

    if boundary == "construction":
        def fail_construction(*_args, **_kwargs):
            raise ArtifactStreamError(secret)

        monkeypatch.setattr(artifacts, "PrivateArtifactStreamWriter", fail_construction)
    elif boundary == "finish":
        class FailFinish:
            def __init__(self, *args, **kwargs):
                self._writer = original_writer(*args, **kwargs)
                self.sink = self._writer.sink

            def finish(self):
                raise ArtifactStreamError(secret)

            def abort(self):
                self._writer.abort()

        monkeypatch.setattr(artifacts, "PrivateArtifactStreamWriter", FailFinish)
    else:
        monkeypatch.setattr(
            artifacts,
            f"_{boundary}_stream_{'file' if boundary == 'replace' else 'handle'}",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(secret)),
        )

    run = pack.artifacts("media").run()
    with pytest.raises(artifacts.ArtifactError) as failed:
        asyncio.run(run.write("segment", (b"1234",)))
    assert failed.value.code == "PRIVACY_ARTIFACT_STORAGE_FAILED"
    assert secret not in str(failed.value)
    assert secret not in repr(failed.value)
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["entries"] == []
    assert not list(root.rglob("*.part"))
    assert not list(root.rglob("*.hpa"))
    assert asyncio.run(run.close()) == 0


def test_owner_capacity_is_enforced_at_ready_commit(tmp_path, monkeypatch):
    profile = _profile(max_plaintext=8, max_owner=12)
    pack, root, _adapter = _install(tmp_path, monkeypatch, profile=profile)
    run = pack.artifacts("media").run()
    first = asyncio.run(run.write("segment", (b"12345678",)))
    with pytest.raises(artifacts.ArtifactError) as rejected:
        asyncio.run(run.write("segment", (b"abcde",)))
    assert rejected.value.code == "PRIVACY_ARTIFACT_STORAGE_FAILED"
    ledger = json.loads((root / "ledger.json").read_text(encoding="utf-8"))
    assert [entry["artifactId"] for entry in ledger["entries"]] == [first.id]
    assert not list(root.rglob("*.part"))
    assert asyncio.run(run.close()) == 1


def test_authenticated_footer_rejects_ledger_size_tamper_before_quota_commit(
    tmp_path,
    monkeypatch,
):
    profile = _profile(max_plaintext=8, max_owner=12)
    pack, root, _adapter = _install(tmp_path, monkeypatch, profile=profile)
    handle = pack.artifacts("media")
    run = handle.run()
    first = asyncio.run(run.write("segment", (b"12345678",)))
    stored = next(root.rglob(f"{first.id}.hpa"))
    before = stored.read_bytes()
    ledger_path = root / "ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["entries"][0]["plaintextBytes"] = 1
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(artifacts.ArtifactError) as unreadable:
        asyncio.run(handle.read("segment", first))
    assert unreadable.value.code == "PRIVACY_ARTIFACT_UNREADABLE"
    with pytest.raises(artifacts.ArtifactError):
        asyncio.run(run.write("segment", (b"abcde",)))

    after = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert [entry["artifactId"] for entry in after["entries"]] == [first.id]
    assert stored.read_bytes() == before
    assert not list(root.rglob("*.part"))
    assert asyncio.run(run.close()) == 1


@pytest.mark.parametrize("mode,extension", [("private", "hpa"), ("public", "spill")])
def test_stream_cleanup_failure_persists_valid_marker_for_restart_retry(
    tmp_path,
    monkeypatch,
    mode,
    extension,
):
    pack, root, _adapter = _install(tmp_path, monkeypatch, mode=mode)
    handle = pack.artifacts("media")
    run = handle.run()
    reference = asyncio.run(run.write("segment", (b"cleanup",)))
    original_unlink = Path.unlink
    predelete_markers = []

    def fail_representation(path, *args, **kwargs):
        if path.suffix == f".{extension}":
            durable = json.loads(
                (root / "ledger.json").read_text(encoding="utf-8")
            )["entries"][0]
            predelete_markers.append(
                (durable["cleanupPending"], durable["state"])
            )
            raise OSError("/SYNTHETIC/PRIVATE/CLEANUP")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as blocked:
        blocked.setattr(Path, "unlink", fail_representation)
        with pytest.raises(artifacts.ArtifactError) as failed:
            asyncio.run(run.close())
    assert failed.value.code == "PRIVACY_ARTIFACT_CLEANUP_FAILED"
    assert predelete_markers == [(True, "CLEANUP_PENDING")]

    ledger_path = root / "ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert len(ledger["entries"]) == 1
    pending = ledger["entries"][0]
    assert pending["cleanupPending"] is True
    assert pending["state"] == "CLEANUP_PENDING"
    assert "plaintextBytes" not in pending
    assert "payloadSha256" not in pending
    assert "payloadContractDigest" in pending
    assert "fileVersion" in pending
    with pytest.raises(artifacts.ArtifactError) as revoked:
        asyncio.run(handle.read("segment", reference))
    assert revoked.value.code == "PRIVACY_ARTIFACT_REFERENCE_INVALID"
    assert list(root.rglob(f"*.{extension}"))

    artifacts.reset_artifact_runtime_for_tests()
    report = asyncio.run(handle.sweep())
    assert report.retired == 1
    assert report.pending == 0
    assert json.loads(ledger_path.read_text(encoding="utf-8"))["entries"] == []
    assert not list(root.rglob(f"*.{extension}"))


def test_bounded_bytes_cleanup_marker_retains_ready_payload_schema():
    entry = {
        "artifactId": "hp-art-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "artifactKind": "spill",
        "cleanupPending": False,
        "createdAt": 1.0,
        "formatVersion": 1,
        "ownerId": "hp-owner-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "packId": "helto.test",
        "payloadMode": "bounded-bytes-v1",
        "processEpoch": "synthetic-process-epoch",
        "resourceId": "media",
        "retention": "run-scoped-spill",
        "revision": 1,
        "state": "READY",
        "storageMode": "private",
        "transition": None,
    }
    assert artifacts._valid_ledger_entry(entry)
    assert artifacts._mark_cleanup_pending_entry(entry) is True
    assert entry["cleanupPending"] is True
    assert entry["state"] == "READY"
    assert entry["payloadMode"] == "bounded-bytes-v1"
    assert entry["revision"] == 2
    assert artifacts._valid_ledger_entry(entry)


def test_durable_stream_declaration_is_rejected_until_bounded_conversion_exists():
    contract = ArtifactStreamContract(
        "raw-segment-v1",
        1,
        64,
        ArtifactDecodedOutput.MATERIALIZED,
        max_materialized_output_bytes=64,
        max_owner_plaintext_bytes=128,
    )
    with pytest.raises(ProfileValidationError) as rejected:
        ArtifactDeclaration(
            "segment",
            "media",
            "main",
            "execution-segment",
            "stream-codec",
            1,
            ArtifactRetention.DURABLE_ADJUNCT,
            ("use",),
            payload_mode=ArtifactPayloadMode.STREAM_V1,
            stream_contract=contract,
        )
    assert rejected.value.code == "unsupported_artifact_stream_retention"


def test_stream_contract_requires_truthful_materialization_capacity():
    with pytest.raises(ProfileValidationError) as missing:
        ArtifactStreamContract(
            "raw-segment-v1",
            1,
            64,
            ArtifactDecodedOutput.MATERIALIZED,
        )
    assert missing.value.code == "invalid_artifact_decoded_output"

    with pytest.raises(ProfileValidationError) as contradictory:
        ArtifactStreamContract(
            "raw-segment-v1",
            1,
            64,
            ArtifactDecodedOutput.STREAM,
            max_materialized_output_bytes=64,
        )
    assert contradictory.value.code == "invalid_artifact_decoded_output"


def test_private_stream_lease_preflights_then_streams_the_same_fd(tmp_path, monkeypatch):
    pack, root, _adapter = _install(tmp_path, monkeypatch)
    token = keystore.session_token()
    assert token is not None
    handle = pack.artifacts("media")

    async def exercise():
        run = handle.run()
        reference = await run.write("segment", (b"first-", b"second"))
        authorization = authorize_privacy_request(
            _Request(token),
            "artifact.use",
            pack_id=pack.profile.id,
        )
        lease = await handle.lease("segment", reference, "use", authorization)
        stream = await artifacts.open_artifact_lease(_Request(token), lease.id)
        path = next(root.rglob("*.hpa"))
        replacement = path.with_name("replacement.hpa")
        replacement.write_bytes(b"untrusted replacement")
        os.replace(replacement, path)
        chunks = [chunk async for chunk in stream.iter_chunks()]
        await run.close()
        return chunks

    assert b"".join(asyncio.run(exercise())) == b"first-second"
