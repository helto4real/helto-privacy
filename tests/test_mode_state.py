import json
import stat

import pytest

from helto_privacy.mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeResolution,
    ModeTransitionStatus,
    PrivacyFloor,
    PrivacyFloorKind,
)
from helto_privacy.mode_state import (
    ModeScopeState,
    ModeStateError,
    PersistedModeTransition,
    TransitionRecoveryKind,
    commit_mode_scope_state,
    load_mode_scope_state,
    mode_state_path,
)


def test_mode_state_round_trips_an_atomic_private_record():
    prior = ModeResolution(
        declared=DeclaredPrivacyMode.PUBLIC,
        effective=EffectivePrivacyMode.PRIVATE,
        inherited_from="declared-public",
        floors=(PrivacyFloor(PrivacyFloorKind.PARENT, "global"),),
    )
    state = ModeScopeState(
        established_mode=EffectivePrivacyMode.PRIVATE,
        established_declared=DeclaredPrivacyMode.PUBLIC,
        transition=PersistedModeTransition(
            transition_id="a" * 32,
            status=ModeTransitionStatus.BLOCKED,
            prior=prior,
            target=DeclaredPrivacyMode.PUBLIC,
            participant_ids=("state-store", "mode-source"),
            recovery_kind=TransitionRecoveryKind.PREPARED,
        ),
    )

    commit_mode_scope_state("helto.test", "main", state)

    assert load_mode_scope_state("helto.test", "main") == state
    assert stat.S_IMODE(mode_state_path().stat().st_mode) == 0o600
    assert stat.S_IMODE(mode_state_path().parent.stat().st_mode) == 0o700
    serialized = mode_state_path().read_text(encoding="utf-8")
    assert "private" in serialized
    assert "prompt" not in serialized
    assert "token" not in serialized


def test_malformed_mode_state_fails_closed():
    path = mode_state_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema": "helto.privacy-mode-state",
                "version": 1,
                "scopes": "not-a-list",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ModeStateError) as exc_info:
        load_mode_scope_state("helto.test", "main")

    assert exc_info.value.code == "mode_state_invalid"
    assert "not-a-list" not in str(exc_info.value)
