from __future__ import annotations

import asyncio
import hashlib
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from tests.mode_protocol_fixtures import ModeSourceProtocolFixture

import helto_privacy.artifacts as artifacts
import helto_privacy.keystore as keystore
import helto_privacy.mode_runtime as mode_runtime
import helto_privacy.runtime as runtime
from helto_privacy import (
    AdapterSlot,
    ArtifactDeclaration,
    ArtifactModeTransitionDisposition,
    ArtifactRetention,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
    generate_artifact_owner_id,
)
from helto_privacy.mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeTransitionContext,
)


class MutableModeAdapter(ModeSourceProtocolFixture):
    def __init__(self, mode: str) -> None:
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


class BytesArtifactAdapter:
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


def _profile(*, retention: ArtifactRetention = ArtifactRetention.DURABLE_ADJUNCT):
    return PrivacyProfile(
        id="helto.dual-artifact-test",
        distribution="comfyui-dual-artifact-test",
        resources=(
            ProfileResource("mode", ResourceKind.MODE, ("mode-store",)),
            ProfileResource("media", ResourceKind.ARTIFACT, ("artifact-codec",)),
        ),
        server_adapters=(
            AdapterSlot("mode-store", ResourceKind.MODE, "mode"),
            AdapterSlot("artifact-codec", ResourceKind.ARTIFACT, "media"),
        ),
        scopes=(PrivacyScope("main", "mode", "mode-store"),),
        artifacts=(
            ArtifactDeclaration(
                "payload",
                "media",
                "main",
                "dual-payload",
                "artifact-codec",
                1,
                retention,
                ()
                if retention is ArtifactRetention.RUN_SCOPED_SPILL
                else ("view",),
                media_type="application/octet-stream",
            ),
        ),
    )


@pytest.fixture
def install_pack(tmp_path, monkeypatch):
    def install(*, mode="public", retention=ArtifactRetention.DURABLE_ADJUNCT):
        root = tmp_path / f"artifacts-{mode}-{retention.value}"
        monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
        monkeypatch.setenv("HELTO_PRIVACY_KEYSTORE", str(tmp_path / "keystore.json"))
        monkeypatch.setenv(
            "HELTO_PRIVACY_MODE_STATE",
            str(tmp_path / f"mode-{mode}-{retention.value}.json"),
        )
        monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
        monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
        monkeypatch.setattr(artifacts, "require_active_process_suite", lambda: None)
        monkeypatch.setattr(mode_runtime, "_MODE_TRANSITIONS", {})
        artifacts.reset_artifact_runtime_for_tests()
        mode_adapter = MutableModeAdapter(mode)
        profile = _profile(retention=retention)
        pack = runtime.install(
            profile,
            {
                "mode-store": mode_adapter,
                "artifact-codec": BytesArtifactAdapter(),
            },
        )
        if not keystore.keystore_exists():
            keystore.initialize_keystore("synthetic dual artifact password")
        keystore.lock_keystore()
        return pack, mode_adapter, root

    return install


def _transition(prior: EffectivePrivacyMode, target: EffectivePrivacyMode, suffix="0"):
    return ModeTransitionContext(
        "main",
        (suffix * 32)[:32],
        prior,
        target,
        (
            DeclaredPrivacyMode.PRIVATE
            if target is EffectivePrivacyMode.PRIVATE
            else DeclaredPrivacyMode.PUBLIC
        ),
    )


def _multiprocess_public_persist(
    root,
    declaration,
    artifact_id,
    owner_id,
    payload,
    results,
):
    os.environ[artifacts.ARTIFACT_ROOT_ENV] = str(root)
    try:
        artifacts._persist_artifact(
            artifacts._ArtifactLocator(
                "helto.dual-artifact-test",
                "media",
                declaration,
                artifact_id,
            ),
            owner_id,
            payload,
            "public",
        )
    except BaseException as exc:
        results.put(type(exc).__name__)
    else:
        results.put("ok")


def _replace_with_valid_public_payload(pack, root: Path, reference, payload: bytes):
    declaration = pack.profile.artifacts[0]
    locator = artifacts._ArtifactLocator(
        pack.profile.id,
        declaration.resource_id,
        declaration,
        reference.id,
    )
    path = next(root.rglob(f"{reference.id}.hpu"))
    replacement = path.with_name(f"{reference.id}.replacement")
    replacement.write_bytes(artifacts._encode_public_artifact_file(locator, payload))
    os.replace(replacement, path)
    return path


def _persist_direct(pack, payload: bytes, storage_mode: str):
    declaration = pack.profile.artifacts[0]
    reference = artifacts.ArtifactReference(artifacts._new_artifact_id())
    locator = artifacts._ArtifactLocator(
        pack.profile.id,
        declaration.resource_id,
        declaration,
        reference.id,
    )
    artifacts._persist_artifact(
        locator,
        generate_artifact_owner_id(),
        payload,
        storage_mode,
    )
    return reference, locator.path_for(storage_mode)


def test_public_hpu_is_exact_and_operates_while_locked_without_authorization(
    install_pack,
):
    pack, _mode, root = install_pack()
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    reference = asyncio.run(handle.write("payload", owner, b"PUBLIC_PAYLOAD"))

    path = next(root.rglob("*.hpu"))
    header_line, payload = path.read_bytes().split(b"\n", 1)
    header = json.loads(header_line)
    assert list(header) == sorted(header)
    assert header == {
        "artifactSchema": "helto.artifact.helto.dual-artifact-test.payload.v1",
        "encoding": "identity",
        "payloadSha256": (
            "acb3fd4faea67ea222a11eae919526473ecda085621b649dd8701eac4516cc3b"
        ),
        "payloadSize": 14,
        "purpose": "helto.dual-artifact-test.payload.dual-payload.v1",
        "schema": "helto.public-artifact-file",
        "version": 1,
    }
    assert payload == b"PUBLIC_PAYLOAD"
    assert path.stat().st_mode & 0o777 == 0o600
    ledger = json.loads((root / "ledger.json").read_text())
    assert ledger["entries"][0]["representationSha256"] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    assert asyncio.run(handle.read("payload", reference)) == b"PUBLIC_PAYLOAD"

    lease = asyncio.run(handle.lease("payload", reference, "view"))
    artifacts.invalidate_artifact_session("synthetic-lock")

    async def reveal():
        stream = await artifacts.open_artifact_lease(object(), lease.id)
        return b"".join([chunk async for chunk in stream.iter_chunks()])

    assert asyncio.run(reveal()) == b"PUBLIC_PAYLOAD"


def test_public_artifact_path_does_not_call_keystore_session_apis(
    install_pack,
    monkeypatch,
):
    pack, _mode, _root = install_pack()
    keystore.keystore_path().unlink()
    assert not keystore.keystore_exists()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("public artifact operation called a keystore session API")

    monkeypatch.setattr(keystore, "require_unlocked_session", forbidden)
    monkeypatch.setattr(keystore, "session_token", forbidden)
    handle = pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"NO_KEYSTORE")
    )
    assert asyncio.run(handle.read("payload", reference)) == b"NO_KEYSTORE"
    assert asyncio.run(handle.lease("payload", reference, "view")).url.startswith(
        "/helto_privacy/artifacts/hp-lease-"
    )


def test_public_reference_rejects_another_valid_same_kind_hpu(install_pack):
    pack, _mode, root = install_pack()
    handle = pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"LEDGER_OWNED")
    )
    _replace_with_valid_public_payload(pack, root, reference, b"FOREIGN_VALID_HPU")

    with pytest.raises(artifacts.ArtifactError) as failed:
        asyncio.run(handle.read("payload", reference))
    assert failed.value.code == "PRIVACY_ARTIFACT_UNREADABLE"


def test_public_lease_rejects_path_swap_after_prevalidation(install_pack):
    pack, _mode, root = install_pack()
    handle = pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"LEASE_OWNED")
    )
    lease = asyncio.run(handle.lease("payload", reference, "view"))
    stream = asyncio.run(artifacts.open_artifact_lease(object(), lease.id))
    _replace_with_valid_public_payload(pack, root, reference, b"FOREIGN_LEASE_HPU")
    revealed = []

    async def consume():
        async for chunk in stream.iter_chunks():
            revealed.append(chunk)

    with pytest.raises(artifacts.ArtifactError) as failed:
        asyncio.run(consume())
    assert failed.value.code == "PRIVACY_ARTIFACT_LEASE_INVALID"
    assert revealed == []


@pytest.mark.parametrize(
    "mutation",
    (
        lambda header, payload: ({**header, "payloadSize": len(payload) + 1}, payload),
        lambda header, payload: ({**header, "purpose": "wrong.purpose"}, payload),
        lambda header, payload: ({**header, "payloadSha256": "0" * 64}, payload),
        lambda header, payload: (header, payload + b"TRAILING"),
    ),
)
def test_public_hpu_corruption_never_falls_back(install_pack, mutation):
    pack, _mode, root = install_pack()
    handle = pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"PUBLIC_PAYLOAD")
    )
    path = next(root.rglob("*.hpu"))
    header_line, payload = path.read_bytes().split(b"\n", 1)
    header, payload = mutation(json.loads(header_line), payload)
    path.write_bytes(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
        + payload
    )
    with pytest.raises(artifacts.ArtifactError) as lease_failed:
        asyncio.run(handle.lease("payload", reference, "view"))
    assert lease_failed.value.code == "PRIVACY_ARTIFACT_UNREADABLE"
    with pytest.raises(artifacts.ArtifactError) as failed:
        asyncio.run(handle.read("payload", reference))
    assert failed.value.code == "PRIVACY_ARTIFACT_UNREADABLE"


def test_private_write_fails_locked_and_mode_drift_blocks_without_fallback(install_pack):
    private_pack, _private_mode, _root = install_pack(mode="private")
    with pytest.raises(artifacts.ArtifactError) as locked:
        asyncio.run(
            private_pack.artifacts("media").write(
                "payload",
                generate_artifact_owner_id(),
                b"PRIVATE_PAYLOAD",
            )
        )
    assert locked.value.code == "PRIVACY_ARTIFACT_STORAGE_FAILED"

    public_pack, public_mode, root = install_pack(mode="public")
    handle = public_pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"PUBLIC_PAYLOAD")
    )
    public_mode.mode = "private"
    next(root.rglob("*.hpu")).with_suffix(".hpa").write_bytes(b"NOT_AUTHORITY")
    with pytest.raises(artifacts.ArtifactError) as drifted:
        asyncio.run(handle.read("payload", reference))
    assert drifted.value.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"


def test_durable_transition_prepare_classify_rollback_commit_and_retire(install_pack):
    pack, _mode, root = install_pack()
    handle = pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"TRANSITION_PAYLOAD")
    )
    keystore.unlock_keystore("synthetic dual artifact password")
    context = _transition(EffectivePrivacyMode.PUBLIC, EffectivePrivacyMode.PRIVATE, "a")
    plan = artifacts.plan_artifact_mode_transition(pack._installation, "main", context)
    assert "TRANSITION_PAYLOAD" not in repr(plan)

    artifacts.prepare_artifact_mode_transition(pack._installation, plan)
    artifacts.reset_artifact_runtime_for_tests()
    assert artifacts.classify_artifact_mode_transition(pack._installation, plan) == (
        ArtifactModeTransitionDisposition.PREPARED,
    )
    assert list(root.rglob("*.hpa")) and list(root.rglob("*.hpu"))
    with pytest.raises(artifacts.ArtifactError) as staged:
        asyncio.run(handle.read("payload", reference))
    assert staged.value.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"

    artifacts.rollback_artifact_mode_transition(pack._installation, plan)
    assert artifacts.classify_artifact_mode_transition(pack._installation, plan) == (
        ArtifactModeTransitionDisposition.PRIOR,
    )
    assert not list(root.rglob("*.hpa"))
    assert asyncio.run(handle.read("payload", reference)) == b"TRANSITION_PAYLOAD"

    second = artifacts.plan_artifact_mode_transition(
        pack._installation,
        "main",
        _transition(EffectivePrivacyMode.PUBLIC, EffectivePrivacyMode.PRIVATE, "b"),
    )
    artifacts.prepare_artifact_mode_transition(pack._installation, second)
    artifacts.commit_artifact_mode_transition(pack._installation, second)
    assert artifacts.classify_artifact_mode_transition(pack._installation, second) == (
        ArtifactModeTransitionDisposition.TARGET,
    )
    artifacts.retire_artifact_mode_transition(pack._installation, second)
    assert artifacts.classify_artifact_mode_transition(pack._installation, second) == (
        ArtifactModeTransitionDisposition.FINAL,
    )
    assert list(root.rglob("*.hpa")) and not list(root.rglob("*.hpu"))


def test_private_to_public_durable_transition_builds_exact_hpu(install_pack):
    pack, _mode, root = install_pack(mode="private")
    keystore.unlock_keystore("synthetic dual artifact password")
    asyncio.run(
        pack.artifacts("media").write(
            "payload",
            generate_artifact_owner_id(),
            b"DECLASSIFIED_PAYLOAD",
        )
    )
    plan = artifacts.plan_artifact_mode_transition(
        pack._installation,
        "main",
        _transition(EffectivePrivacyMode.PRIVATE, EffectivePrivacyMode.PUBLIC, "f"),
    )
    artifacts.prepare_artifact_mode_transition(pack._installation, plan)
    artifacts.commit_artifact_mode_transition(pack._installation, plan)
    artifacts.retire_artifact_mode_transition(pack._installation, plan)
    assert artifacts.classify_artifact_mode_transition(pack._installation, plan) == (
        ArtifactModeTransitionDisposition.FINAL,
    )
    assert not list(root.rglob("*.hpa"))
    public_path = next(root.rglob("*.hpu"))
    assert public_path.read_bytes().endswith(b"DECLASSIFIED_PAYLOAD")


@pytest.mark.parametrize(
    "retention",
    (ArtifactRetention.REGENERABLE_CACHE, ArtifactRetention.SERVED_TRANSIENT),
)
def test_regenerable_artifacts_stage_retirement_non_destructively(
    install_pack,
    retention,
):
    pack, _mode, root = install_pack(retention=retention)
    handle = pack.artifacts("media")
    reference = asyncio.run(
        handle.write("payload", generate_artifact_owner_id(), b"REGENERABLE")
    )
    context = _transition(EffectivePrivacyMode.PUBLIC, EffectivePrivacyMode.PRIVATE, "c")
    plan = artifacts.plan_artifact_mode_transition(pack._installation, "main", context)
    assert plan.items[0].action == "retire"
    artifacts.prepare_artifact_mode_transition(pack._installation, plan)
    assert list(root.rglob("*.hpu"))
    artifacts.rollback_artifact_mode_transition(pack._installation, plan)
    assert asyncio.run(handle.read("payload", reference)) == b"REGENERABLE"

    plan = artifacts.plan_artifact_mode_transition(
        pack._installation,
        "main",
        _transition(EffectivePrivacyMode.PUBLIC, EffectivePrivacyMode.PRIVATE, "d"),
    )
    artifacts.prepare_artifact_mode_transition(pack._installation, plan)
    artifacts.commit_artifact_mode_transition(pack._installation, plan)
    artifacts.retire_artifact_mode_transition(pack._installation, plan)
    assert artifacts.classify_artifact_mode_transition(pack._installation, plan) == (
        ArtifactModeTransitionDisposition.FINAL,
    )
    assert not list(root.rglob("*.hpu"))


def test_owner_reconciliation_rejects_staged_entries_without_partial_retirement(
    install_pack,
):
    pack, _mode, _root = install_pack()
    handle = pack.artifacts("media")
    owner = generate_artifact_owner_id()
    canonical = asyncio.run(handle.write("payload", owner, b"CANONICAL"))
    loser = asyncio.run(handle.write("payload", owner, b"LOSER"))
    keystore.unlock_keystore("synthetic dual artifact password")
    plan = artifacts.plan_artifact_mode_transition(
        pack._installation,
        "main",
        _transition(EffectivePrivacyMode.PUBLIC, EffectivePrivacyMode.PRIVATE, "e"),
    )
    artifacts.prepare_artifact_mode_transition(pack._installation, plan)
    with pytest.raises(artifacts.ArtifactError) as blocked:
        asyncio.run(handle.reconcile_owner("payload", owner, keep=(canonical,)))
    assert blocked.value.code == "PRIVACY_ARTIFACT_MODE_BLOCKED"
    artifacts.rollback_artifact_mode_transition(pack._installation, plan)
    assert asyncio.run(handle.read("payload", loser)) == b"LOSER"


def test_v1_ledger_migrates_atomically_without_touching_ciphertext(install_pack):
    pack, _mode, root = install_pack(mode="private")
    keystore.unlock_keystore("synthetic dual artifact password")
    reference = asyncio.run(
        pack.artifacts("media").write(
            "payload",
            generate_artifact_owner_id(),
            b"MIGRATION_PAYLOAD",
        )
    )
    keystore.lock_keystore()
    artifact_path = next(root.rglob("*.hpa"))
    before = artifact_path.read_bytes()
    ledger_path = root / "ledger.json"
    ledger = json.loads(ledger_path.read_text())
    entry = ledger["entries"][0]
    entry.pop("revision")
    entry.pop("storageMode")
    entry.pop("transition")
    ledger = {
        "schema": ledger["schema"],
        "version": 1,
        "entries": [entry],
    }
    ledger_path.write_text(json.dumps(ledger))

    artifacts._sweep_artifacts()

    migrated = json.loads(ledger_path.read_text())
    assert migrated["version"] == 2
    assert migrated["revision"] >= 1
    assert migrated["entries"][0]["storageMode"] == "private"
    assert migrated["entries"][0]["transition"] is None
    assert artifact_path.read_bytes() == before
    assert migrated["entries"][0]["artifactId"] == reference.id


@pytest.mark.parametrize(
    ("retention", "mutation"),
    (
        (ArtifactRetention.DURABLE_ADJUNCT, "extra-expiry"),
        (ArtifactRetention.RUN_SCOPED_SPILL, "extra-expiry"),
        (ArtifactRetention.REGENERABLE_CACHE, "missing-expiry"),
        (ArtifactRetention.SERVED_TRANSIENT, "nonfinite-expiry"),
        (ArtifactRetention.DURABLE_ADJUNCT, "nonfinite-created"),
    ),
)
def test_v2_invalid_timestamps_fail_before_staleness_sweep(
    install_pack,
    retention,
    mutation,
):
    pack, _mode, root = install_pack(retention=retention)
    _reference, artifact_path = _persist_direct(pack, b"MUST_SURVIVE", "public")
    before = artifact_path.read_bytes()
    ledger_path = root / "ledger.json"
    ledger = json.loads(ledger_path.read_text())
    entry = ledger["entries"][0]
    if mutation == "extra-expiry":
        entry["expiresAt"] = 0.0
    elif mutation == "missing-expiry":
        entry.pop("expiresAt")
    elif mutation == "nonfinite-expiry":
        entry["expiresAt"] = float("inf")
    else:
        entry["createdAt"] = float("nan")
    ledger_path.write_text(json.dumps(ledger))

    with pytest.raises(artifacts.ArtifactError) as failed:
        artifacts._sweep_artifacts()
    assert failed.value.code == "PRIVACY_ARTIFACT_LEDGER_INVALID"
    assert artifact_path.read_bytes() == before


@pytest.mark.parametrize(
    ("retention", "mutation"),
    (
        (ArtifactRetention.DURABLE_ADJUNCT, "extra-expiry"),
        (ArtifactRetention.REGENERABLE_CACHE, "missing-expiry"),
        (ArtifactRetention.SERVED_TRANSIENT, "nonfinite-expiry"),
        (ArtifactRetention.DURABLE_ADJUNCT, "nonfinite-created"),
    ),
)
def test_v1_invalid_timestamps_fail_before_migration_or_staleness_sweep(
    install_pack,
    retention,
    mutation,
):
    pack, _mode, root = install_pack(mode="private", retention=retention)
    keystore.unlock_keystore("synthetic dual artifact password")
    _reference, artifact_path = _persist_direct(pack, b"V1_MUST_SURVIVE", "private")
    before = artifact_path.read_bytes()
    ledger_path = root / "ledger.json"
    current = json.loads(ledger_path.read_text())
    entry = current["entries"][0]
    entry.pop("revision")
    entry.pop("storageMode")
    entry.pop("transition")
    if mutation == "extra-expiry":
        entry["expiresAt"] = 0.0
    elif mutation == "missing-expiry":
        entry.pop("expiresAt")
    elif mutation == "nonfinite-expiry":
        entry["expiresAt"] = float("-inf")
    else:
        entry["createdAt"] = float("inf")
    ledger_path.write_text(
        json.dumps(
            {
                "schema": current["schema"],
                "version": 1,
                "entries": [entry],
            }
        )
    )

    with pytest.raises(artifacts.ArtifactError) as failed:
        artifacts._sweep_artifacts()
    assert failed.value.code == "PRIVACY_ARTIFACT_LEDGER_INVALID"
    assert artifact_path.read_bytes() == before


def test_artifact_storage_change_does_not_change_profile_fingerprint():
    profile = _profile()
    assert profile.fingerprint == _profile().fingerprint


def test_cross_process_ledger_lock_prevents_lost_public_writes(tmp_path, monkeypatch):
    root = tmp_path / "multiprocess-artifacts"
    monkeypatch.setenv(artifacts.ARTIFACT_ROOT_ENV, str(root))
    declaration = _profile().artifacts[0]
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    workers = [
        context.Process(
            target=_multiprocess_public_persist,
            args=(
                root,
                declaration,
                artifacts._new_artifact_id(),
                generate_artifact_owner_id(),
                f"PAYLOAD_{index}".encode(),
                results,
            ),
        )
        for index in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert worker.exitcode == 0
    assert [results.get(timeout=1) for _worker in workers] == ["ok"] * 4
    ledger = json.loads((root / "ledger.json").read_text())
    assert len(ledger["entries"]) == 4
    assert ledger["revision"] == 4
