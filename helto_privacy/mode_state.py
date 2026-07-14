"""Revisioned public mode authority state and encrypted recovery journals."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._atomic_file import atomic_write_private_bytes, sync_parent_directory
from ._suite_codec import is_stable_id
from .keystore import keystore_path, primary_session_key, session_key_for
from .mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeResolution,
    ModeTransitionStatus,
    PrivacyFloor,
    PrivacyFloorKind,
)


MODE_STATE_ENV = "HELTO_PRIVACY_MODE_STATE"
MODE_STATE_SCHEMA = "helto.privacy-mode-state"
MODE_STATE_VERSION = 3
MODE_TRANSITION_PROTOCOL = "recoverable-v1"
MODE_JOURNAL_SCHEMA = "helto.privacy-mode-journal"
MODE_JOURNAL_VERSION = 1
_JOURNAL_AAD = f"{MODE_JOURNAL_SCHEMA}|{MODE_JOURNAL_VERSION}".encode("ascii")
_TRANSITION_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_MAX_JOURNAL_BYTES = 64 * 1024 * 1024


class ModeStateError(RuntimeError):
    """Sanitized persistence failure for privacy mode authority state."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy mode authority state is unavailable.")


class TransitionRecoveryKind(str, Enum):
    PREPARED = "prepared"
    DECLARATION_DRIFT = "declaration-drift"
    PROTECTION_DRIFT = "protection-drift"

    @property
    def can_restore_prior(self) -> bool:
        return self is not TransitionRecoveryKind.PROTECTION_DRIFT

    @property
    def allows_protection_reconciliation(self) -> bool:
        return self is TransitionRecoveryKind.PROTECTION_DRIFT

    @property
    def requires_participant_rollback(self) -> bool:
        return self is TransitionRecoveryKind.PREPARED


@dataclass(frozen=True, slots=True)
class PersistedModeTransition:
    transition_id: str
    status: ModeTransitionStatus
    prior: ModeResolution
    target: DeclaredPrivacyMode
    participant_ids: tuple[str, ...]
    recovery_kind: TransitionRecoveryKind
    profile_fingerprint: str = "0" * 64
    journal_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.transition_id, str) or not _TRANSITION_ID.fullmatch(
            self.transition_id
        ):
            raise ModeStateError("mode_state_invalid")
        if (
            not isinstance(self.status, ModeTransitionStatus)
            or self.status is ModeTransitionStatus.IDLE
            or not isinstance(self.prior, ModeResolution)
            or not isinstance(self.target, DeclaredPrivacyMode)
            or not isinstance(self.recovery_kind, TransitionRecoveryKind)
            or not _DIGEST.fullmatch(self.profile_fingerprint)
        ):
            raise ModeStateError("mode_state_invalid")
        if self.journal_digest is not None and not _DIGEST.fullmatch(self.journal_digest):
            raise ModeStateError("mode_state_invalid")
        if (
            not isinstance(self.prior.declared, DeclaredPrivacyMode)
            or not isinstance(self.prior.effective, EffectivePrivacyMode)
            or self.prior.transition_status is not ModeTransitionStatus.IDLE
        ):
            raise ModeStateError("mode_state_invalid")
        participant_ids = tuple(self.participant_ids)
        if (
            not participant_ids
            or len(set(participant_ids)) != len(participant_ids)
            or any(not is_stable_id(value) for value in participant_ids)
        ):
            raise ModeStateError("mode_state_invalid")
        if not is_stable_id(self.prior.inherited_from) or any(
            not isinstance(floor, PrivacyFloor)
            or not isinstance(floor.kind, PrivacyFloorKind)
            or not is_stable_id(floor.source_id)
            for floor in self.prior.floors
        ):
            raise ModeStateError("mode_state_invalid")
        object.__setattr__(self, "participant_ids", participant_ids)


@dataclass(frozen=True, slots=True)
class CompletedModeTransition:
    """Bounded product-free receipt for idempotent terminal retries."""

    transition_id: str
    request_digest: str
    coordinator_digest: str
    resume_secret_digest: str
    target: DeclaredPrivacyMode
    established_mode: EffectivePrivacyMode
    mode_epoch: int
    disposition: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.transition_id, str)
            or _TRANSITION_ID.fullmatch(self.transition_id) is None
            or _DIGEST.fullmatch(self.request_digest) is None
            or _DIGEST.fullmatch(self.coordinator_digest) is None
            or _DIGEST.fullmatch(self.resume_secret_digest) is None
            or not isinstance(self.target, DeclaredPrivacyMode)
            or not isinstance(self.established_mode, EffectivePrivacyMode)
            or type(self.mode_epoch) is not int
            or self.mode_epoch < 0
            or self.disposition not in {"completed", "rolled-back"}
        ):
            raise ModeStateError("mode_state_invalid")


@dataclass(frozen=True, slots=True)
class ModeScopeState:
    established_mode: EffectivePrivacyMode | None = None
    established_declared: DeclaredPrivacyMode | None = None
    transition: PersistedModeTransition | None = None
    revision: int = 0
    mode_source_revision: int = 0
    mode_epoch: int = 0
    cleanup_journal_digest: str | None = None
    completed_transition: CompletedModeTransition | None = None

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise ModeStateError("mode_state_invalid")
        if type(self.mode_source_revision) is not int or self.mode_source_revision < 0:
            raise ModeStateError("mode_state_invalid")
        if type(self.mode_epoch) is not int or self.mode_epoch < 0:
            raise ModeStateError("mode_state_invalid")
        if self.cleanup_journal_digest is not None and not _DIGEST.fullmatch(
            self.cleanup_journal_digest
        ):
            raise ModeStateError("mode_state_invalid")
        if self.transition is not None and self.cleanup_journal_digest is not None:
            raise ModeStateError("mode_state_invalid")
        if self.completed_transition is not None and not isinstance(
            self.completed_transition, CompletedModeTransition
        ):
            raise ModeStateError("mode_state_invalid")
        if self.transition is not None and self.completed_transition is not None:
            raise ModeStateError("mode_state_invalid")
        if self.established_mode is not None and not isinstance(
            self.established_mode, EffectivePrivacyMode
        ):
            raise ModeStateError("mode_state_invalid")
        if self.established_declared is not None and not isinstance(
            self.established_declared, DeclaredPrivacyMode
        ):
            raise ModeStateError("mode_state_invalid")
        if (self.established_mode is None) != (self.established_declared is None):
            raise ModeStateError("mode_state_invalid")
        if self.transition is not None and not isinstance(
            self.transition, PersistedModeTransition
        ):
            raise ModeStateError("mode_state_invalid")


def mode_state_path() -> Path:
    configured = str(os.environ.get(MODE_STATE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    return keystore_path().with_name("privacy_mode_state.json")


def mode_journal_path(
    pack_id: str,
    scope_id: str,
    journal_digest: str | None = None,
) -> Path:
    _require_scope_key(pack_id, scope_id)
    digest = hashlib.sha256(f"{pack_id}\0{scope_id}".encode()).hexdigest()
    path = mode_state_path()
    name = f"{digest}.{journal_digest}.json" if journal_digest is not None else f"{digest}.json"
    if journal_digest is not None and not _DIGEST.fullmatch(journal_digest):
        raise ModeStateError("mode_journal_invalid")
    return path.with_name(f"{path.stem}.journals").joinpath(name)


def load_mode_scope_state(pack_id: str, scope_id: str) -> ModeScopeState:
    _require_scope_key(pack_id, scope_id)
    state = _load_records().get((pack_id, scope_id), ModeScopeState())
    if state.cleanup_journal_digest is None:
        return state
    delete_mode_transition_journal_revision(
        pack_id, scope_id, state.cleanup_journal_digest
    )
    try:
        return commit_mode_scope_state(
            pack_id,
            scope_id,
            replace(state, cleanup_journal_digest=None),
            expected_revision=state.revision,
        )
    except ModeStateError as exc:
        if exc.code != "mode_state_revision_conflict":
            raise
        refreshed = _load_records().get((pack_id, scope_id), ModeScopeState())
        if refreshed.cleanup_journal_digest is None:
            return refreshed
        raise


def commit_mode_scope_state(
    pack_id: str,
    scope_id: str,
    state: ModeScopeState,
    *,
    expected_revision: int | None = None,
) -> ModeScopeState:
    """CAS one scope record, atomically replace, reopen, and verify it."""

    _require_scope_key(pack_id, scope_id)
    if not isinstance(state, ModeScopeState):
        raise ModeStateError("mode_state_invalid")
    with _exclusive_state_file():
        records = _load_records(migrate=False)
        current = records.get((pack_id, scope_id), ModeScopeState())
        expected = current.revision if expected_revision is None else expected_revision
        if type(expected) is not int or current.revision != expected:
            raise ModeStateError("mode_state_revision_conflict")
        committed = replace(state, revision=expected + 1)
        records[(pack_id, scope_id)] = committed
        _write_records(records)
        reopened = _load_records(migrate=False).get((pack_id, scope_id))
        if reopened != committed:
            raise ModeStateError("mode_state_persist_failed")
        return committed


def save_mode_transition_journal(
    pack_id: str,
    scope_id: str,
    transition_id: str,
    payload: Mapping[str, object],
) -> str:
    """Encrypt, atomically replace, reopen, and authenticate one journal."""

    _require_scope_key(pack_id, scope_id)
    if not _TRANSITION_ID.fullmatch(str(transition_id)) or not isinstance(payload, Mapping):
        raise ModeStateError("mode_journal_invalid")
    try:
        plaintext = _canonical_json(dict(payload))
        if len(plaintext) > _MAX_JOURNAL_BYTES:
            raise ValueError
        key, key_id = primary_session_key()
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _JOURNAL_AAD)
        envelope = {
            "schema": MODE_JOURNAL_SCHEMA,
            "version": MODE_JOURNAL_VERSION,
            "keyId": key_id,
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        }
        encoded = _canonical_json(envelope)
        digest = hashlib.sha256(encoded).hexdigest()
        path = mode_journal_path(pack_id, scope_id, digest)
        atomic_write_private_bytes(path, encoded)
        reopened, reopened_digest = load_mode_transition_journal(
            pack_id, scope_id, transition_id, expected_digest=digest
        )
        if reopened_digest != digest or _canonical_json(reopened) != plaintext:
            raise ValueError
        return digest
    except ModeStateError:
        raise
    except Exception:
        raise ModeStateError("mode_journal_persist_failed") from None


def load_mode_transition_journal(
    pack_id: str,
    scope_id: str,
    transition_id: str,
    *,
    expected_digest: str | None = None,
) -> tuple[dict[str, object], str]:
    _require_scope_key(pack_id, scope_id)
    if not _TRANSITION_ID.fullmatch(str(transition_id)):
        raise ModeStateError("mode_journal_invalid")
    try:
        if expected_digest is not None:
            path = mode_journal_path(pack_id, scope_id, expected_digest)
        else:
            base = mode_journal_path(pack_id, scope_id)
            candidates = sorted(base.parent.glob(f"{base.stem}.*.json"))
            if len(candidates) != 1:
                raise ValueError
            path = candidates[0]
        raw = path.read_bytes()
        if len(raw) > _MAX_JOURNAL_BYTES * 2:
            raise ValueError
        digest = hashlib.sha256(raw).hexdigest()
        if expected_digest is not None and digest != expected_digest:
            raise ValueError
        envelope = json.loads(raw)
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema", "version", "keyId", "nonce", "ciphertext"}
            or envelope["schema"] != MODE_JOURNAL_SCHEMA
            or envelope["version"] != MODE_JOURNAL_VERSION
        ):
            raise ValueError
        key = session_key_for(str(envelope["keyId"]))
        if key is None:
            raise ModeStateError("mode_journal_locked")
        plaintext = AESGCM(key).decrypt(
            _unb64(str(envelope["nonce"])),
            _unb64(str(envelope["ciphertext"])),
            _JOURNAL_AAD,
        )
        payload = json.loads(plaintext)
        if not isinstance(payload, dict) or payload.get("transitionId") != transition_id:
            raise ValueError
        return payload, digest
    except ModeStateError:
        raise
    except Exception:
        raise ModeStateError("mode_journal_invalid") from None


def delete_mode_transition_journal(pack_id: str, scope_id: str) -> None:
    path = mode_journal_path(pack_id, scope_id)
    try:
        for candidate in path.parent.glob(f"{path.stem}.*.json"):
            candidate.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        if path.parent.exists():
            sync_parent_directory(path)
    except OSError:
        raise ModeStateError("mode_journal_persist_failed") from None


def delete_mode_transition_journal_revision(
    pack_id: str,
    scope_id: str,
    journal_digest: str | None,
) -> None:
    if journal_digest is None:
        return
    path = mode_journal_path(pack_id, scope_id, journal_digest)
    try:
        path.unlink(missing_ok=True)
        if path.parent.exists():
            sync_parent_directory(path)
    except OSError:
        raise ModeStateError("mode_journal_persist_failed") from None


def has_non_idle_mode_transition() -> bool:
    """Read only public metadata; used to block primary-key rotation."""

    return any(state.transition is not None for state in _load_records().values())


def sweep_unreferenced_mode_journals(pack_id: str, scope_id: str) -> None:
    """Remove crash-orphaned immutable revisions during single-threaded startup."""

    _require_scope_key(pack_id, scope_id)
    with exclusive_mode_journal_publication(), _exclusive_state_file():
        records = _load_records(migrate=False)
        state = records.get((pack_id, scope_id), ModeScopeState())
        base = mode_journal_path(pack_id, scope_id)
        _sweep_journal_candidates(base, _referenced_journal_digests(state))


def sweep_all_unreferenced_mode_journals() -> None:
    """Sweep immutable crash orphans while journal publication is quiescent."""

    with exclusive_mode_journal_publication(), _exclusive_state_file():
        records = _load_records(migrate=False)
        referenced_names = {
            mode_journal_path(pack_id, scope_id, digest).name
            for (pack_id, scope_id), state in records.items()
            for digest in _referenced_journal_digests(state)
        }
        journal_dir = mode_state_path().with_name(f"{mode_state_path().stem}.journals")
        try:
            if journal_dir.exists():
                for candidate in journal_dir.glob("*.json"):
                    parts = candidate.name.removesuffix(".json").split(".")
                    if (
                        len(parts) == 2
                        and _DIGEST.fullmatch(parts[0]) is not None
                        and _DIGEST.fullmatch(parts[1]) is not None
                        and candidate.name not in referenced_names
                    ):
                        candidate.unlink(missing_ok=True)
                sync_parent_directory(journal_dir)
        except OSError:
            raise ModeStateError("mode_journal_persist_failed") from None


def _referenced_journal_digests(state: ModeScopeState) -> set[str]:
    return {
        digest
        for digest in (
            state.transition.journal_digest if state.transition is not None else None,
            state.cleanup_journal_digest,
        )
        if digest is not None
    }


def _sweep_journal_candidates(base: Path, referenced: set[str]) -> None:
    try:
        for candidate in base.parent.glob(f"{base.stem}.*.json"):
            digest = candidate.name.removeprefix(f"{base.stem}.").removesuffix(".json")
            if _DIGEST.fullmatch(digest) is not None and digest not in referenced:
                candidate.unlink(missing_ok=True)
        if base.parent.exists():
            sync_parent_directory(base)
    except OSError:
        raise ModeStateError("mode_journal_persist_failed") from None


def _load_records(*, migrate: bool = True) -> dict[tuple[str, str], ModeScopeState]:
    path = mode_state_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != MODE_STATE_SCHEMA or not isinstance(payload.get("scopes"), list):
            raise ValueError
        version = payload.get("version")
        if version == 1:
            records = _decode_v1_records(payload)
            if migrate:
                with _exclusive_state_file():
                    current = json.loads(path.read_text(encoding="utf-8"))
                    if current.get("version") == 1:
                        _write_records(records)
            return records
        if version == 2:
            records = _decode_v2_records(payload)
            if migrate:
                with _exclusive_state_file():
                    current = json.loads(path.read_text(encoding="utf-8"))
                    if current.get("version") == 2:
                        _write_records(records)
            return records
        if version != MODE_STATE_VERSION:
            raise ValueError
        records: dict[tuple[str, str], ModeScopeState] = {}
        for item in payload["scopes"]:
            key = (str(item["packId"]), str(item["scopeId"]))
            _require_scope_key(*key)
            if key in records:
                raise ValueError
            established = item.get("establishedMode")
            transition_payload = item.get("transition")
            records[key] = ModeScopeState(
                established_mode=EffectivePrivacyMode(str(established)) if established is not None else None,
                established_declared=DeclaredPrivacyMode(str(item["establishedDeclared"])) if established is not None else None,
                transition=_decode_transition(transition_payload) if transition_payload is not None else None,
                revision=int(item["revision"]),
                mode_source_revision=int(item["modeSourceRevision"]),
                mode_epoch=int(item["modeEpoch"]),
                cleanup_journal_digest=(
                    str(item["cleanupJournalDigest"])
                    if item.get("cleanupJournalDigest") is not None
                    else None
                ),
                completed_transition=_decode_completed_transition(
                    item.get("completedTransition")
                ),
            )
        return records
    except (AttributeError, OSError, KeyError, TypeError, ValueError, ModeStateError):
        raise ModeStateError("mode_state_invalid") from None


def _decode_v1_records(payload: Mapping[str, object]) -> dict[tuple[str, str], ModeScopeState]:
    records: dict[tuple[str, str], ModeScopeState] = {}
    for item in payload["scopes"]:  # type: ignore[index]
        if not isinstance(item, dict) or item.get("transition") is not None:
            raise ModeStateError("mode_state_legacy_transition")
        key = (str(item["packId"]), str(item["scopeId"]))
        _require_scope_key(*key)
        established = item.get("establishedMode")
        records[key] = ModeScopeState(
            established_mode=EffectivePrivacyMode(str(established)) if established is not None else None,
            established_declared=DeclaredPrivacyMode(str(item["establishedDeclared"])) if established is not None else None,
            revision=1,
            mode_source_revision=0,
            mode_epoch=0,
        )
    return records


def _decode_v2_records(payload: Mapping[str, object]) -> dict[tuple[str, str], ModeScopeState]:
    """Migrate the released revisioned layout before durable epochs existed."""

    records: dict[tuple[str, str], ModeScopeState] = {}
    for item in payload["scopes"]:  # type: ignore[index]
        if not isinstance(item, dict):
            raise ModeStateError("mode_state_invalid")
        key = (str(item["packId"]), str(item["scopeId"]))
        _require_scope_key(*key)
        if key in records:
            raise ModeStateError("mode_state_invalid")
        established = item.get("establishedMode")
        transition_payload = item.get("transition")
        records[key] = ModeScopeState(
            established_mode=(
                EffectivePrivacyMode(str(established))
                if established is not None
                else None
            ),
            established_declared=(
                DeclaredPrivacyMode(str(item["establishedDeclared"]))
                if established is not None
                else None
            ),
            transition=(
                _decode_transition(transition_payload)
                if transition_payload is not None
                else None
            ),
            revision=int(item["revision"]),
            mode_source_revision=int(item["modeSourceRevision"]),
            mode_epoch=0,
        )
    return records


def _decode_transition(payload: object) -> PersistedModeTransition:
    if not isinstance(payload, dict):
        raise ValueError
    floors = payload["priorFloors"]
    participants = payload["participantIds"]
    if not isinstance(floors, list) or not isinstance(participants, list):
        raise ValueError
    return PersistedModeTransition(
        transition_id=str(payload["transitionId"]),
        status=ModeTransitionStatus(str(payload["status"])),
        prior=ModeResolution(
            declared=DeclaredPrivacyMode(str(payload["priorDeclared"])),
            effective=EffectivePrivacyMode(str(payload["priorEffective"])),
            inherited_from=str(payload["priorInheritedFrom"]),
            floors=tuple(PrivacyFloor(PrivacyFloorKind(str(item["kind"])), str(item["sourceId"])) for item in floors),
        ),
        target=DeclaredPrivacyMode(str(payload["target"])),
        participant_ids=tuple(str(value) for value in participants),
        recovery_kind=TransitionRecoveryKind(str(payload["recoveryKind"])),
        profile_fingerprint=str(payload["profileFingerprint"]),
        journal_digest=(str(payload["journalDigest"]) if payload.get("journalDigest") is not None else None),
    )


def _write_records(records: Mapping[tuple[str, str], ModeScopeState]) -> None:
    payload = {
        "schema": MODE_STATE_SCHEMA,
        "version": MODE_STATE_VERSION,
        "modeTransitionProtocol": MODE_TRANSITION_PROTOCOL,
        "scopes": [
            {
                "packId": pack_id,
                "scopeId": scope_id,
                "revision": state.revision,
                "modeSourceRevision": state.mode_source_revision,
                "modeEpoch": state.mode_epoch,
                "cleanupJournalDigest": state.cleanup_journal_digest,
                "completedTransition": _encode_completed_transition(
                    state.completed_transition
                ),
                "establishedMode": state.established_mode.value if state.established_mode else None,
                "establishedDeclared": state.established_declared.value if state.established_declared else None,
                "transition": _encode_transition(state.transition) if state.transition else None,
            }
            for (pack_id, scope_id), state in sorted(records.items())
        ],
    }
    try:
        atomic_write_private_bytes(mode_state_path(), _canonical_json(payload))
    except Exception:
        raise ModeStateError("mode_state_persist_failed") from None


def _encode_transition(value: PersistedModeTransition) -> dict[str, object]:
    return {
        "transitionId": value.transition_id,
        "status": value.status.value,
        "priorDeclared": value.prior.declared.value,
        "priorEffective": value.prior.effective.value,
        "priorInheritedFrom": value.prior.inherited_from,
        "priorFloors": [{"kind": item.kind.value, "sourceId": item.source_id} for item in value.prior.floors],
        "target": value.target.value,
        "participantIds": list(value.participant_ids),
        "recoveryKind": value.recovery_kind.value,
        "profileFingerprint": value.profile_fingerprint,
        "journalDigest": value.journal_digest,
    }


def _decode_completed_transition(value: object) -> CompletedModeTransition | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError
    return CompletedModeTransition(
        transition_id=str(value["transitionId"]),
        request_digest=str(value["requestDigest"]),
        coordinator_digest=str(value["coordinatorDigest"]),
        resume_secret_digest=str(value["resumeSecretDigest"]),
        target=DeclaredPrivacyMode(str(value["target"])),
        established_mode=EffectivePrivacyMode(str(value["establishedMode"])),
        mode_epoch=int(value["modeEpoch"]),
        disposition=str(value["disposition"]),
    )


def _encode_completed_transition(
    value: CompletedModeTransition | None,
) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "transitionId": value.transition_id,
        "requestDigest": value.request_digest,
        "coordinatorDigest": value.coordinator_digest,
        "resumeSecretDigest": value.resume_secret_digest,
        "target": value.target.value,
        "establishedMode": value.established_mode.value,
        "modeEpoch": value.mode_epoch,
        "disposition": value.disposition,
    }


@contextmanager
def _exclusive_state_file():
    path = mode_state_path().with_suffix(mode_state_path().suffix + ".lock")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def exclusive_mode_journal_publication():
    """Serialize save-before-CAS publication with startup orphan sweeping."""

    path = mode_state_path().with_suffix(mode_state_path().suffix + ".journal.lock")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _require_scope_key(pack_id: str, scope_id: str) -> None:
    if not is_stable_id(pack_id) or not is_stable_id(scope_id):
        raise ModeStateError("mode_state_invalid")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
