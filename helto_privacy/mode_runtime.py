"""Bound profile mode resolution behind the typed runtime handle."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from threading import RLock

from .guard import (
    AuthorizedPrivacyRequest,
    PrivacyAuthorizationError,
    require_declassification_confirmation,
    require_current_authorization,
)
from .mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeEvidence,
    ModeFacts,
    ModePolicyError,
    ModeResolution,
    ModeTransitionError,
    ModeTransitionContext,
    ModeTransitionResult,
    ModeTransitionStatus,
    PrivacyFloorKind,
    normalize_declared_mode,
    resolve_privacy_mode,
)
from .mode_state import (
    ModeScopeState,
    ModeStateError,
    PersistedModeTransition,
    TransitionRecoveryKind,
    commit_mode_scope_state,
    load_mode_scope_state,
)


_TRANSITION_LOCK = RLock()
_MODE_TRANSITIONS: dict[tuple[str, str], _TransitionRecord] = {}


@dataclass(slots=True)
class _TransitionRecord:
    persisted: PersistedModeTransition
    participants: dict[str, object] = field(repr=False)


def require_stable_bound_scope(installation, scope_id: str) -> None:
    """Refuse protected work while a scope transition is incomplete."""

    scope = next(
        (candidate for candidate in installation.profile.scopes if candidate.id == scope_id),
        None,
    )
    if scope is None:
        raise ModePolicyError("unknown_mode_scope")
    key = (installation.profile.id, scope.id)
    with _TRANSITION_LOCK:
        state = _load_scope_state(installation.profile.id, scope.id)
        if _transition_record(installation, scope, state) is not None:
            raise ModeTransitionError("PRIVACY_TRANSITION_BLOCKED")


def resolve_bound_mode(
    installation,
    mode_resource_id: str,
    scope_id: str,
    facts: ModeFacts | None,
) -> ModeResolution:
    scope = _scope(installation, mode_resource_id, scope_id)
    supplied_facts = facts if isinstance(facts, ModeFacts) else ModeFacts()
    declared = _read_declared(installation, scope)
    with _TRANSITION_LOCK:
        state = _load_scope_state(installation.profile.id, scope.id)
        transition = _transition_record(installation, scope, state)
        if transition is not None:
            return replace(
                transition.persisted.prior,
                transition_status=transition.persisted.status,
            )
        if state.established_mode is EffectivePrivacyMode.PRIVATE:
            supplied_facts = replace(
                supplied_facts,
                current_mode=EffectivePrivacyMode.PRIVATE,
            )
        resolution = _resolve_declared_mode(
            installation,
            mode_resource_id,
            scope,
            declared,
            supplied_facts,
        )
        if state.established_mode is None:
            state = ModeScopeState(
                established_mode=_initial_established_mode(
                    resolution,
                    supplied_facts,
                ),
                established_declared=resolution.declared,
            )
            _commit_scope_state(
                installation.profile.id,
                scope.id,
                state,
            )
        declaration_changed = state.established_declared is not resolution.declared
        protection_changed = (
            state.established_mode is not resolution.effective
            and not (
                resolution.floors
                and all(
                    floor.kind is PrivacyFloorKind.REQUEST
                    for floor in resolution.floors
                )
            )
        )
        if declaration_changed or protection_changed:
            transition = _block_mode_drift(
                installation,
                scope,
                state,
                resolution,
                (
                    TransitionRecoveryKind.DECLARATION_DRIFT
                    if declaration_changed
                    else TransitionRecoveryKind.PROTECTION_DRIFT
                ),
            )
            return replace(
                transition.persisted.prior,
                transition_status=ModeTransitionStatus.BLOCKED,
            )
        return resolution


def _initial_established_mode(
    resolution: ModeResolution,
    facts: ModeFacts,
) -> EffectivePrivacyMode:
    if (
        facts.current_mode is EffectivePrivacyMode.PUBLIC
        or normalize_declared_mode(facts.current_mode)
        is DeclaredPrivacyMode.PUBLIC
    ):
        return EffectivePrivacyMode.PUBLIC
    if any(
        floor.kind is PrivacyFloorKind.CURRENT_STATE
        for floor in resolution.floors
    ):
        return EffectivePrivacyMode.PRIVATE
    if resolution.inherited_from in {"declared-public", "global-public"}:
        return EffectivePrivacyMode.PUBLIC
    return EffectivePrivacyMode.PRIVATE


def transition_bound_mode(
    installation,
    mode_resource_id: str,
    scope_id: str,
    target: object,
    authorization: AuthorizedPrivacyRequest,
    facts: ModeFacts | None,
) -> ModeTransitionResult:
    try:
        require_current_authorization(
            authorization,
            "mode.transition",
            pack_id=installation.profile.id,
        )
    except PrivacyAuthorizationError:
        raise ModeTransitionError("PRIVACY_TRANSITION_UNAUTHORIZED")
    scope = _scope(installation, mode_resource_id, scope_id)
    target_declared = normalize_declared_mode(target)
    supplied_facts = facts if isinstance(facts, ModeFacts) else ModeFacts()
    key = (installation.profile.id, scope.id)

    with _TRANSITION_LOCK:
        retry_prior = None
        allow_protection_reconciliation = False
        try:
            state = _load_scope_state(installation.profile.id, scope.id)
            blocked = _transition_record(installation, scope, state)
        except ModePolicyError:
            raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED") from None
        if blocked is not None:
            if blocked.persisted.status is not ModeTransitionStatus.BLOCKED:
                raise ModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS")
            recovery_kind = blocked.persisted.recovery_kind
            if (
                target_declared is blocked.persisted.prior.declared
                and recovery_kind.can_restore_prior
            ):
                _restore_blocked_transition(installation, scope.id, blocked)
                del _MODE_TRANSITIONS[key]
                return ModeTransitionResult(
                    scope.id,
                    blocked.persisted.prior.declared,
                    blocked.persisted.prior.effective,
                    ModeTransitionStatus.IDLE,
                )
            if target_declared is not blocked.persisted.target:
                raise ModeTransitionError("PRIVACY_TRANSITION_BLOCKED")
            _restore_blocked_transition(installation, scope.id, blocked)
            del _MODE_TRANSITIONS[key]
            retry_prior = blocked.persisted.prior
            allow_protection_reconciliation = (
                recovery_kind.allows_protection_reconciliation
            )

        prior = retry_prior or resolve_bound_mode(
            installation,
            mode_resource_id,
            scope.id,
            supplied_facts,
        )
        target_facts = replace(
            supplied_facts,
            current_mode=None,
            request_mode=None,
        )
        target_resolution = _resolve_declared_mode(
            installation,
            mode_resource_id,
            scope,
            target,
            target_facts,
        )
        if (
            target_declared is DeclaredPrivacyMode.PUBLIC
            and target_resolution.floors
            and not allow_protection_reconciliation
        ):
            raise ModeTransitionError("PRIVACY_FLOOR_ACTIVE")
        if (
            prior.effective is EffectivePrivacyMode.PRIVATE
            and target_resolution.effective is EffectivePrivacyMode.PUBLIC
        ):
            try:
                require_declassification_confirmation(
                    authorization,
                    scope_id=scope.id,
                    target=target_declared.value,
                )
            except PrivacyAuthorizationError as exc:
                raise ModeTransitionError(exc.code) from None

        participant_ids = _transition_participant_ids(installation.profile, scope)
        participants = {
            adapter_id: installation.adapters[adapter_id]
            for adapter_id in participant_ids
        }
        _validate_transition_participants(participants)
        record = _TransitionRecord(
            persisted=PersistedModeTransition(
                transition_id=secrets.token_hex(16),
                status=ModeTransitionStatus.PREPARING,
                prior=prior,
                target=target_declared,
                participant_ids=participant_ids,
                recovery_kind=TransitionRecoveryKind.PREPARED,
            ),
            participants=participants,
        )
        context = ModeTransitionContext(
            scope_id=scope.id,
            transition_id=record.persisted.transition_id,
            prior_mode=prior.effective,
            target_mode=target_resolution.effective,
            target_declared=target_declared,
        )
        _MODE_TRANSITIONS[key] = record
        try:
            _persist_transition(
                installation.profile.id,
                scope.id,
                prior.effective,
                record,
            )
        except ModeTransitionError:
            del _MODE_TRANSITIONS[key]
            raise
        attempted: list[str] = []
        try:
            for adapter_id in participant_ids:
                attempted.append(adapter_id)
                participants[adapter_id].prepare_mode_transition(context)
            record.persisted = replace(
                record.persisted,
                status=ModeTransitionStatus.COMMITTING,
            )
            _persist_transition(
                installation.profile.id,
                scope.id,
                prior.effective,
                record,
            )
            for adapter_id in participant_ids:
                participants[adapter_id].commit_mode_transition(
                    scope.id,
                    record.persisted.transition_id,
                )
            _commit_scope_state(
                installation.profile.id,
                scope.id,
                ModeScopeState(
                    established_mode=target_resolution.effective,
                    established_declared=target_declared,
                ),
            )
        except Exception:
            rollback_failed = _rollback_attempted(
                participants,
                attempted,
                scope.id,
                record.persisted.transition_id,
            )
            record.persisted = replace(
                record.persisted,
                status=ModeTransitionStatus.BLOCKED,
            )
            persistence_failed = False
            try:
                _persist_transition(
                    installation.profile.id,
                    scope.id,
                    prior.effective,
                    record,
                )
            except ModeTransitionError:
                persistence_failed = True
            if rollback_failed:
                code = "PRIVACY_TRANSITION_ROLLBACK_FAILED"
            elif persistence_failed:
                code = "PRIVACY_TRANSITION_STATE_FAILED"
            else:
                code = "PRIVACY_TRANSITION_FAILED"
            raise ModeTransitionError(code) from None

        del _MODE_TRANSITIONS[key]
        return ModeTransitionResult(
            scope.id,
            target_declared,
            target_resolution.effective,
            ModeTransitionStatus.IDLE,
        )


def _block_mode_drift(
    installation,
    scope,
    state: ModeScopeState,
    target: ModeResolution,
    recovery_kind: TransitionRecoveryKind,
) -> _TransitionRecord:
    if state.established_mode is None or state.established_declared is None:
        raise ModePolicyError("mode_state_unavailable")
    participant_ids = _transition_participant_ids(installation.profile, scope)
    participants = {
        adapter_id: installation.adapters[adapter_id]
        for adapter_id in participant_ids
    }
    _validate_transition_participants(participants)
    record = _TransitionRecord(
        persisted=PersistedModeTransition(
            transition_id=secrets.token_hex(16),
            status=ModeTransitionStatus.BLOCKED,
            prior=ModeResolution(
                declared=state.established_declared,
                effective=state.established_mode,
                inherited_from="established-state",
                floors=target.floors,
            ),
            target=target.declared,
            participant_ids=participant_ids,
            recovery_kind=recovery_kind,
        ),
        participants=participants,
    )
    _MODE_TRANSITIONS[(installation.profile.id, scope.id)] = record
    _persist_transition(
        installation.profile.id,
        scope.id,
        state.established_mode,
        record,
    )
    return record


def _load_scope_state(pack_id: str, scope_id: str) -> ModeScopeState:
    try:
        return load_mode_scope_state(pack_id, scope_id)
    except ModeStateError:
        raise ModePolicyError("mode_state_unavailable") from None


def _commit_scope_state(
    pack_id: str,
    scope_id: str,
    state: ModeScopeState,
) -> None:
    try:
        commit_mode_scope_state(pack_id, scope_id, state)
    except ModeStateError:
        raise ModePolicyError("mode_state_unavailable") from None


def _transition_record(
    installation,
    scope,
    state: ModeScopeState,
) -> _TransitionRecord | None:
    key = (installation.profile.id, scope.id)
    current = _MODE_TRANSITIONS.get(key)
    if current is not None:
        return current
    persisted = state.transition
    if persisted is None:
        return None
    expected_ids = _transition_participant_ids(installation.profile, scope)
    if persisted.participant_ids != expected_ids:
        raise ModePolicyError("mode_transition_participants_changed")
    participants = {
        adapter_id: installation.adapters[adapter_id]
        for adapter_id in persisted.participant_ids
    }
    _validate_transition_participants(participants)
    recovered = _TransitionRecord(
        persisted=replace(persisted, status=ModeTransitionStatus.BLOCKED),
        participants=participants,
    )
    _MODE_TRANSITIONS[key] = recovered
    return recovered


def _persist_transition(
    pack_id: str,
    scope_id: str,
    established_mode: EffectivePrivacyMode,
    record: _TransitionRecord,
) -> None:
    try:
        _commit_scope_state(
            pack_id,
            scope_id,
            ModeScopeState(
                established_mode=established_mode,
                established_declared=record.persisted.prior.declared,
                transition=record.persisted,
            ),
        )
    except ModePolicyError:
        raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED") from None


def _restore_blocked_transition(
    installation,
    scope_id: str,
    record: _TransitionRecord,
) -> None:
    if record.persisted.recovery_kind.requires_participant_rollback:
        _rollback_participants(record, scope_id)
    else:
        mode_source = record.participants[record.persisted.participant_ids[-1]]
        try:
            mode_source.write_declared_mode(
                scope_id,
                record.persisted.prior.declared,
            )
        except Exception:
            raise ModeTransitionError("PRIVACY_TRANSITION_ROLLBACK_FAILED") from None
    try:
        _commit_scope_state(
            installation.profile.id,
            scope_id,
            ModeScopeState(
                established_mode=record.persisted.prior.effective,
                established_declared=record.persisted.prior.declared,
            ),
        )
    except ModePolicyError:
        raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED") from None


def _resolve_declared_mode(
    installation,
    mode_resource_id: str,
    scope,
    declared: object,
    supplied_facts: ModeFacts,
) -> ModeResolution:
    global_mode, parent_evidence = _resolve_scope_relationships(
        installation,
        mode_resource_id,
        scope,
        global_mode=supplied_facts.global_mode,
        evidence=list(supplied_facts.parents),
        visited={scope.id},
    )

    merged_facts = replace(
        supplied_facts,
        global_mode=global_mode,
        parents=_unique_evidence(parent_evidence),
    )
    return resolve_privacy_mode(declared, merged_facts)


def _resolve_scope_relationships(
    installation,
    mode_resource_id: str,
    scope,
    *,
    global_mode: object,
    evidence: list[ModeEvidence],
    visited: set[str],
) -> tuple[object, list[ModeEvidence]]:
    if scope.parent_id is not None:
        parent_mode = _resolve_related_scope(
            installation,
            mode_resource_id,
            scope.parent_id,
            visited,
        )
        if parent_mode is EffectivePrivacyMode.PRIVATE:
            evidence.append(ModeEvidence(scope.parent_id, parent_mode))
        elif global_mode is None:
            global_mode = DeclaredPrivacyMode.PUBLIC
    for related_scope_id in scope.floor_scope_ids:
        related_mode = _resolve_related_scope(
            installation,
            mode_resource_id,
            related_scope_id,
            visited,
        )
        if related_mode is EffectivePrivacyMode.PRIVATE:
            evidence.append(ModeEvidence(related_scope_id, related_mode))
    return global_mode, evidence


def _transition_participant_ids(profile, scope) -> tuple[str, ...]:
    domain_ids = {
        field.state_adapter
        for field in profile.protected_fields
        if field.scope_id == scope.id
    }
    domain_ids.update(
        record.store_adapter for record in profile.records if record.scope_id == scope.id
    )
    domain_ids.update(
        artifact.payload_adapter
        for artifact in profile.artifacts
        if artifact.scope_id == scope.id
    )
    domain_ids.discard(scope.mode_source_adapter)
    return (*sorted(domain_ids), scope.mode_source_adapter)


def _validate_transition_participants(participants: dict[str, object]) -> None:
    methods = (
        "prepare_mode_transition",
        "commit_mode_transition",
        "rollback_mode_transition",
    )
    if any(
        not callable(getattr(participant, method, None))
        for participant in participants.values()
        for method in methods
    ):
        raise ModeTransitionError("PRIVACY_TRANSITION_ADAPTER_INVALID")


def _rollback_attempted(
    participants: dict[str, object],
    attempted: list[str],
    scope_id: str,
    transition_id: str,
) -> bool:
    failed = False
    for adapter_id in reversed(attempted):
        try:
            participants[adapter_id].rollback_mode_transition(
                scope_id,
                transition_id,
            )
        except Exception:
            failed = True
    return failed


def _rollback_participants(record: _TransitionRecord, scope_id: str) -> None:
    failed = _rollback_attempted(
        record.participants,
        list(record.persisted.participant_ids),
        scope_id,
        record.persisted.transition_id,
    )
    if failed:
        raise ModeTransitionError("PRIVACY_TRANSITION_ROLLBACK_FAILED")


def _resolve_related_scope(
    installation,
    mode_resource_id: str,
    scope_id: str,
    visited: set[str],
) -> EffectivePrivacyMode:
    if scope_id in visited:
        raise ModePolicyError("mode_scope_cycle")
    scope = _scope(installation, mode_resource_id, scope_id)
    declared = _read_declared(installation, scope)
    state = _load_scope_state(installation.profile.id, scope.id)
    transition = _transition_record(installation, scope, state)
    if transition is not None:
        return transition.persisted.prior.effective

    global_mode, related_evidence = _resolve_scope_relationships(
        installation,
        mode_resource_id,
        scope,
        global_mode=None,
        evidence=[],
        visited={*visited, scope.id},
    )

    return resolve_privacy_mode(
        declared,
        ModeFacts(
            global_mode=global_mode,
            current_mode=(
                EffectivePrivacyMode.PRIVATE
                if state.established_mode is EffectivePrivacyMode.PRIVATE
                else None
            ),
            parents=_unique_evidence(related_evidence),
        ),
    ).effective


def _scope(installation, mode_resource_id: str, scope_id: str):
    scope = next(
        (
            candidate
            for candidate in installation.profile.scopes
            if candidate.id == scope_id
            and candidate.mode_resource_id == mode_resource_id
        ),
        None,
    )
    if scope is None:
        raise ModePolicyError("unknown_mode_scope")
    return scope


def _read_declared(installation, scope):
    adapter = installation.adapters[scope.mode_source_adapter]
    try:
        return adapter.read_declared_mode(scope.id)
    except Exception:
        raise ModePolicyError("mode_source_unavailable") from None


def _unique_evidence(evidence: list[ModeEvidence]) -> tuple[ModeEvidence, ...]:
    by_id = {item.source_id: item for item in evidence}
    return tuple(by_id[source_id] for source_id in sorted(by_id))
