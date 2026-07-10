import pytest

from helto_privacy.mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeEvidence,
    ModeFacts,
    PrivacyFloorKind,
    normalize_declared_mode,
    resolve_privacy_mode,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        (None, DeclaredPrivacyMode.INHERIT),
        ("", DeclaredPrivacyMode.INHERIT),
        ("unknown", DeclaredPrivacyMode.INHERIT),
        (True, DeclaredPrivacyMode.PRIVATE),
        (False, DeclaredPrivacyMode.PUBLIC),
        ("private", DeclaredPrivacyMode.PRIVATE),
        ("public", DeclaredPrivacyMode.PUBLIC),
        ("inherit", DeclaredPrivacyMode.INHERIT),
    ),
)
def test_declared_mode_normalization_is_fail_closed(raw, expected):
    assert normalize_declared_mode(raw) is expected


def test_missing_and_inherited_mode_use_private_base_but_explicit_public_opts_out():
    inherited = resolve_privacy_mode(None)
    explicit_public = resolve_privacy_mode(False)
    global_public = resolve_privacy_mode(
        DeclaredPrivacyMode.INHERIT,
        ModeFacts(global_mode=DeclaredPrivacyMode.PUBLIC),
    )

    assert inherited.effective is EffectivePrivacyMode.PRIVATE
    assert inherited.inherited_from == "missing-private"
    assert explicit_public.effective is EffectivePrivacyMode.PUBLIC
    assert explicit_public.inherited_from == "declared-public"
    assert global_public.effective is EffectivePrivacyMode.PUBLIC
    assert global_public.inherited_from == "global-public"


@pytest.mark.parametrize("malformed", ("unknown", "", 7, object()))
def test_malformed_local_mode_cannot_inherit_a_public_default(malformed):
    result = resolve_privacy_mode(
        malformed,
        ModeFacts(global_mode=DeclaredPrivacyMode.PUBLIC),
    )

    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert result.inherited_from == "malformed-private"


def test_missing_local_mode_cannot_inherit_a_public_default():
    result = resolve_privacy_mode(
        None,
        ModeFacts(global_mode=DeclaredPrivacyMode.PUBLIC),
    )

    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert result.inherited_from == "missing-private"


@pytest.mark.parametrize(
    ("facts", "kind", "source_id"),
    (
        (
            ModeFacts(global_mode=DeclaredPrivacyMode.PRIVATE),
            PrivacyFloorKind.GLOBAL,
            "global",
        ),
        (
            ModeFacts(upstream=(ModeEvidence("input-1", EffectivePrivacyMode.PRIVATE),)),
            PrivacyFloorKind.UPSTREAM,
            "input-1",
        ),
        (
            ModeFacts(parents=(ModeEvidence("parent-1", EffectivePrivacyMode.PRIVATE),)),
            PrivacyFloorKind.PARENT,
            "parent-1",
        ),
        (
            ModeFacts(records=(ModeEvidence("record-1", EffectivePrivacyMode.PRIVATE),)),
            PrivacyFloorKind.RECORD,
            "record-1",
        ),
        (
            ModeFacts(artifacts=(ModeEvidence("artifact-1", EffectivePrivacyMode.PRIVATE),)),
            PrivacyFloorKind.ARTIFACT,
            "artifact-1",
        ),
        (
            ModeFacts(executions=(ModeEvidence("execution-1", EffectivePrivacyMode.PRIVATE),)),
            PrivacyFloorKind.EXECUTION,
            "execution-1",
        ),
        (
            ModeFacts(current_mode=EffectivePrivacyMode.PRIVATE),
            PrivacyFloorKind.CURRENT_STATE,
            "current-state",
        ),
        (
            ModeFacts(request_mode=DeclaredPrivacyMode.PRIVATE),
            PrivacyFloorKind.REQUEST,
            "request",
        ),
    ),
)
def test_every_private_floor_overrides_explicit_public(facts, kind, source_id):
    result = resolve_privacy_mode(DeclaredPrivacyMode.PUBLIC, facts)

    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert [(floor.kind, floor.source_id) for floor in result.floors] == [
        (kind, source_id)
    ]


def test_public_request_and_public_captured_state_never_weaken_private_policy():
    result = resolve_privacy_mode(
        DeclaredPrivacyMode.PRIVATE,
        ModeFacts(
            request_mode=DeclaredPrivacyMode.PUBLIC,
            upstream=(ModeEvidence("input-1", EffectivePrivacyMode.PUBLIC),),
            records=(ModeEvidence("record-1", EffectivePrivacyMode.PUBLIC),),
        ),
    )

    assert result.effective is EffectivePrivacyMode.PRIVATE
    assert result.floors == ()
