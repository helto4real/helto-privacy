"""Durable, product-data-free privacy mode and transition state."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ._atomic_file import atomic_write_private_bytes
from ._suite_codec import is_stable_id
from .keystore import keystore_path
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
MODE_STATE_VERSION = 1
_TRANSITION_ID = re.compile(r"^[a-f0-9]{32}$")


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
        ):
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
class ModeScopeState:
    established_mode: EffectivePrivacyMode | None = None
    established_declared: DeclaredPrivacyMode | None = None
    transition: PersistedModeTransition | None = None

    def __post_init__(self) -> None:
        if self.established_mode is not None and not isinstance(
            self.established_mode,
            EffectivePrivacyMode,
        ):
            raise ModeStateError("mode_state_invalid")
        if self.established_declared is not None and not isinstance(
            self.established_declared,
            DeclaredPrivacyMode,
        ):
            raise ModeStateError("mode_state_invalid")
        if (self.established_mode is None) != (self.established_declared is None):
            raise ModeStateError("mode_state_invalid")
        if self.transition is not None and not isinstance(
            self.transition,
            PersistedModeTransition,
        ):
            raise ModeStateError("mode_state_invalid")


def mode_state_path() -> Path:
    configured = str(os.environ.get(MODE_STATE_ENV) or "").strip()
    if configured:
        return Path(configured).expanduser()
    return keystore_path().with_name("privacy_mode_state.json")


def load_mode_scope_state(pack_id: str, scope_id: str) -> ModeScopeState:
    _require_scope_key(pack_id, scope_id)
    records = _load_records()
    return records.get((pack_id, scope_id), ModeScopeState())


def commit_mode_scope_state(
    pack_id: str,
    scope_id: str,
    state: ModeScopeState,
) -> None:
    _require_scope_key(pack_id, scope_id)
    if not isinstance(state, ModeScopeState):
        raise ModeStateError("mode_state_invalid")
    records = _load_records()
    records[(pack_id, scope_id)] = state
    _write_records(records)


def _load_records() -> dict[tuple[str, str], ModeScopeState]:
    path = mode_state_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            payload.get("schema") != MODE_STATE_SCHEMA
            or payload.get("version") != MODE_STATE_VERSION
            or not isinstance(payload.get("scopes"), list)
        ):
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
            )
        return records
    except (AttributeError, OSError, KeyError, TypeError, ValueError, ModeStateError):
        raise ModeStateError("mode_state_invalid") from None


def _decode_transition(payload: object) -> PersistedModeTransition:
    if not isinstance(payload, dict):
        raise ValueError
    floors_payload = payload["priorFloors"]
    participant_payload = payload["participantIds"]
    if not isinstance(floors_payload, list) or not isinstance(
        participant_payload,
        list,
    ):
        raise ValueError
    participant_ids = tuple(str(value) for value in participant_payload)
    if len(set(participant_ids)) != len(participant_ids):
        raise ValueError
    prior = ModeResolution(
        declared=DeclaredPrivacyMode(str(payload["priorDeclared"])),
        effective=EffectivePrivacyMode(str(payload["priorEffective"])),
        inherited_from=str(payload["priorInheritedFrom"]),
        floors=tuple(
            PrivacyFloor(
                PrivacyFloorKind(str(floor["kind"])),
                str(floor["sourceId"]),
            )
            for floor in floors_payload
        ),
    )
    status = ModeTransitionStatus(str(payload["status"]))
    if status is ModeTransitionStatus.IDLE:
        raise ValueError
    return PersistedModeTransition(
        transition_id=str(payload["transitionId"]),
        status=status,
        prior=prior,
        target=DeclaredPrivacyMode(str(payload["target"])),
        participant_ids=participant_ids,
        recovery_kind=TransitionRecoveryKind(str(payload["recoveryKind"])),
    )


def _write_records(records: dict[tuple[str, str], ModeScopeState]) -> None:
    path = mode_state_path()
    payload = {
        "schema": MODE_STATE_SCHEMA,
        "version": MODE_STATE_VERSION,
        "scopes": [
            {
                "packId": pack_id,
                "scopeId": scope_id,
                "establishedMode": (
                    state.established_mode.value
                    if state.established_mode is not None
                    else None
                ),
                "establishedDeclared": (
                    state.established_declared.value
                    if state.established_declared is not None
                    else None
                ),
                "transition": (
                    _encode_transition(state.transition)
                    if state.transition is not None
                    else None
                ),
            }
            for (pack_id, scope_id), state in sorted(records.items())
        ],
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        atomic_write_private_bytes(path, encoded)
    except Exception:
        raise ModeStateError("mode_state_commit_failed") from None


def _encode_transition(transition: PersistedModeTransition) -> dict[str, object]:
    return {
        "transitionId": transition.transition_id,
        "status": transition.status.value,
        "priorDeclared": transition.prior.declared.value,
        "priorEffective": transition.prior.effective.value,
        "priorInheritedFrom": transition.prior.inherited_from,
        "priorFloors": [
            {"kind": floor.kind.value, "sourceId": floor.source_id}
            for floor in transition.prior.floors
        ],
        "target": transition.target.value,
        "participantIds": list(transition.participant_ids),
        "recoveryKind": transition.recovery_kind.value,
    }


def _require_scope_key(pack_id: str, scope_id: str) -> None:
    if not is_stable_id(pack_id) or not is_stable_id(scope_id):
        raise ModeStateError("mode_state_invalid")
