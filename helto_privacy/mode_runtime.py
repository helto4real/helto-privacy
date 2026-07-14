"""Bound profile mode resolution behind the typed runtime handle."""

from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, replace
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
    delete_mode_transition_journal,
    delete_mode_transition_journal_revision,
    load_mode_scope_state,
    load_mode_transition_journal,
    mode_state_path,
    save_mode_transition_journal,
)
from .mode_participants import (
    MODE_SOURCE_KIND,
    ModeParticipantError,
    commit_participant,
    participant_manifest,
    prepare_participant,
    prepare_participant_plans,
    retire_participant,
    rollback_participant,
    mode_source_snapshot as _mode_source_snapshot_value,
    verify_prepared_participant,
)


_TRANSITION_LOCK = RLock()
_MODE_TRANSITIONS: dict[tuple[str, str], _TransitionRecord] = {}
_ACTIVE_SCOPE_WORK: dict[tuple[str, str], int] = {}


@dataclass(slots=True)
class _BoundModeWorkToken:
    keys: tuple[tuple[str, str], ...]
    descriptors: tuple[int, ...]
    released: bool = False


def acquire_bound_mode_work_admission(installation, scope_ids) -> _BoundModeWorkToken:
    """Admit work without retaining a thread lock across an async suspension."""

    normalized = tuple(sorted(dict.fromkeys(scope_ids)))
    if not normalized:
        raise ModePolicyError("unknown_mode_scope")
    descriptors: list[int] = []
    with _TRANSITION_LOCK:
        keys = tuple((installation.profile.id, scope_id) for scope_id in normalized)
        try:
            for key in keys:
                descriptor = _open_scope_lock(*key)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except OSError:
                    os.close(descriptor)
                    raise ModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS") from None
                descriptors.append(descriptor)
        except Exception:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise
        for scope_id in normalized:
            try:
                require_stable_bound_scope(installation, scope_id)
            except Exception:
                for descriptor in reversed(descriptors):
                    os.close(descriptor)
                raise
        for key in keys:
            _ACTIVE_SCOPE_WORK[key] = _ACTIVE_SCOPE_WORK.get(key, 0) + 1
        return _BoundModeWorkToken(keys, tuple(descriptors))


def release_bound_mode_work_admission(token: _BoundModeWorkToken) -> None:
    if not isinstance(token, _BoundModeWorkToken) or token.released:
        return
    with _TRANSITION_LOCK:
        for key in token.keys:
            count = _ACTIVE_SCOPE_WORK.get(key, 0)
            if count <= 1:
                _ACTIVE_SCOPE_WORK.pop(key, None)
            else:
                _ACTIVE_SCOPE_WORK[key] = count - 1
        for descriptor in reversed(token.descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        token.released = True


@contextmanager
def bound_mode_work_admission(installation, scope_ids):
    """Serialize stable-scope work admission with mode transitions.

    Callers may acquire only their own artifact/association registry lock while
    inside this context. The global lock order is transition lock first.
    """

    token = acquire_bound_mode_work_admission(installation, scope_ids)
    try:
        yield
    finally:
        release_bound_mode_work_admission(token)


@dataclass(slots=True)
class _TransitionRecord:
    persisted: PersistedModeTransition
    journal: dict[str, object] | None = None


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
                mode_source_revision=_mode_source_snapshot(installation, scope).revision,
            )
            state = _commit_scope_state(
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


def resolve_bound_declaration(
    installation,
    mode_resource_id: str,
    scope_id: str,
    declaration: object,
    facts: ModeFacts | None,
) -> ModeResolution:
    """Resolve a consumer-normalized node-local declaration server-side."""

    scope = _scope(installation, mode_resource_id, scope_id)
    supplied_facts = facts if isinstance(facts, ModeFacts) else ModeFacts()
    with _TRANSITION_LOCK:
        require_stable_bound_scope(installation, scope.id)
        return _resolve_declared_mode(
            installation,
            mode_resource_id,
            scope,
            declaration,
            supplied_facts,
        )


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
    from .external_mode_transition import has_external_workflow_participants

    if has_external_workflow_participants(installation.profile, scope.id):
        raise ModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_REQUIRED")
    target_declared = normalize_declared_mode(target)
    supplied_facts = facts if isinstance(facts, ModeFacts) else ModeFacts()
    key = (installation.profile.id, scope.id)
    descriptor = _open_scope_lock(*key)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS") from None
        with _TRANSITION_LOCK:
            if _ACTIVE_SCOPE_WORK.get(key, 0):
                raise ModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS")
            try:
                from .external_operation_state import has_active_external_operations

                if has_active_external_operations(
                    pack_id=installation.profile.id,
                    scope_id=scope.id,
                ):
                    raise ModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS")
            except ModeTransitionError:
                raise
            except Exception:
                raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED") from None
            return _transition_under_exclusive_lock(
                installation,
                mode_resource_id,
                scope,
                target,
                target_declared,
                authorization,
                supplied_facts,
            )
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _transition_under_exclusive_lock(
    installation,
    mode_resource_id: str,
    scope,
    target: object,
    target_declared: DeclaredPrivacyMode,
    authorization: AuthorizedPrivacyRequest,
    supplied_facts: ModeFacts,
) -> ModeTransitionResult:
    allow_protection_reconciliation = False
    try:
        state = _load_scope_state(installation.profile.id, scope.id)
        incomplete = _transition_record(installation, scope, state)
        if incomplete is not None:
            state = _recover_transition(installation, scope, state, incomplete)
            allow_protection_reconciliation = incomplete.persisted.recovery_kind.allows_protection_reconciliation
            prior = replace(
                incomplete.persisted.prior,
                transition_status=ModeTransitionStatus.IDLE,
            )
        else:
            prior = resolve_bound_mode(
                installation, mode_resource_id, scope.id, supplied_facts
            )
            state = _load_scope_state(installation.profile.id, scope.id)
    except ModeTransitionError:
        raise
    except (ModePolicyError, ModeParticipantError):
        raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED") from None

    target_facts = replace(supplied_facts, current_mode=None, request_mode=None)
    target_resolution = _resolve_declared_mode(
        installation, mode_resource_id, scope, target, target_facts
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
                authorization, scope_id=scope.id, target=target_declared.value
            )
        except PrivacyAuthorizationError as exc:
            raise ModeTransitionError(exc.code) from None

    transition_id = secrets.token_hex(16)
    context = ModeTransitionContext(
        scope.id,
        transition_id,
        prior.effective,
        target_resolution.effective,
        target_declared,
    )
    try:
        from .associations import prepare_association_mode_transition

        prepare_association_mode_transition(installation, scope.id, context)
        plans = prepare_participant_plans(installation, scope, context)
    except Exception:
        raise ModeTransitionError("PRIVACY_TRANSITION_FAILED") from None
    participant_ids = tuple(str(item["id"]) for item in plans)
    persisted = PersistedModeTransition(
        transition_id=transition_id,
        status=ModeTransitionStatus.PREPARING,
        prior=prior,
        target=target_declared,
        participant_ids=participant_ids,
        recovery_kind=TransitionRecoveryKind.PREPARED,
        profile_fingerprint=installation.profile.fingerprint,
    )
    journal: dict[str, object] = {
        "schema": "helto.privacy-mode-transition",
        "version": 1,
        "protocol": "recoverable-v1",
        "packId": installation.profile.id,
        "profileFingerprint": installation.profile.fingerprint,
        "scopeId": scope.id,
        "transitionId": transition_id,
        "phase": ModeTransitionStatus.PREPARING.value,
        "priorEffective": prior.effective.value,
        "targetEffective": target_resolution.effective.value,
        "targetDeclared": target_declared.value,
        "participantIds": list(participant_ids),
        "participants": plans,
        "prepared": [],
        "committed": [],
        "retired": [],
    }
    record = _TransitionRecord(persisted, journal)
    try:
        record, state = _persist_journal_transition(
            installation.profile.id, scope.id, state, record
        )
    except Exception:
        try:
            delete_mode_transition_journal(installation.profile.id, scope.id)
        except ModeStateError:
            pass
        raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED") from None

    mode_source_committed = False
    try:
        for item in plans[:-1]:
            prepare_participant(installation, scope.id, context, item)
            verify_prepared_participant(installation, context, item)
            journal["prepared"].append(item["id"])
            record, state = _persist_journal_transition(
                installation.profile.id, scope.id, state, record
            )
        journal["phase"] = ModeTransitionStatus.COMMITTING.value
        record.persisted = replace(record.persisted, status=ModeTransitionStatus.COMMITTING)
        record, state = _persist_journal_transition(
            installation.profile.id, scope.id, state, record
        )
        for item in plans[:-1]:
            commit_participant(installation, context, item)
            journal["committed"].append(item["id"])
            record, state = _persist_journal_transition(
                installation.profile.id, scope.id, state, record
            )
        journal["phase"] = ModeTransitionStatus.RETIRING.value
        record.persisted = replace(record.persisted, status=ModeTransitionStatus.RETIRING)
        record, state = _persist_journal_transition(
            installation.profile.id, scope.id, state, record
        )
        for item in plans[:-1]:
            retire_participant(installation, context, item)
            journal["retired"].append(item["id"])
            record, state = _persist_journal_transition(
                installation.profile.id, scope.id, state, record
            )
        source_item = plans[-1]
        _commit_or_reconcile_mode_source(installation, context, source_item)
        mode_source_committed = True
        journal["committed"].append(source_item["id"])
        record, state = _persist_journal_transition(
            installation.profile.id, scope.id, state, record
        )
        source_target = plans[-1].get("target")
        source_revision = int(source_target["revision"]) if isinstance(source_target, dict) else state.mode_source_revision + 1
        _commit_scope_state(
            installation.profile.id,
            scope.id,
            ModeScopeState(
                target_resolution.effective,
                target_declared,
                revision=state.revision,
                mode_source_revision=source_revision,
                mode_epoch=state.mode_epoch + 1,
                cleanup_journal_digest=record.persisted.journal_digest,
            ),
            expected_revision=state.revision,
        )
        _load_scope_state(installation.profile.id, scope.id)
    except Exception:
        if mode_source_committed or record.persisted.status is ModeTransitionStatus.RETIRING:
            raise ModeTransitionError("PRIVACY_TRANSITION_RETIRE_FAILED") from None
        try:
            journal["phase"] = ModeTransitionStatus.ROLLING_BACK.value
            record.persisted = replace(record.persisted, status=ModeTransitionStatus.ROLLING_BACK)
            record, state = _persist_journal_transition(
                installation.profile.id, scope.id, state, record
            )
            _rollback_journal(installation, scope, state, record)
        except Exception:
            raise ModeTransitionError("PRIVACY_TRANSITION_ROLLBACK_FAILED") from None
        raise ModeTransitionError("PRIVACY_TRANSITION_FAILED") from None
    return ModeTransitionResult(
        scope.id, target_declared, target_resolution.effective, ModeTransitionStatus.IDLE
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
    manifest = participant_manifest(installation.profile, scope)
    if recovery_kind is TransitionRecoveryKind.DECLARATION_DRIFT:
        manifest = manifest[-1:]
    participant_ids = tuple(item["id"] for item in manifest)
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
            profile_fingerprint=installation.profile.fingerprint,
        ),
    )
    _commit_scope_state(
        installation.profile.id, scope.id,
        ModeScopeState(
            state.established_mode,
            state.established_declared,
            record.persisted,
            revision=state.revision,
            mode_source_revision=state.mode_source_revision,
            mode_epoch=state.mode_epoch,
        ),
        expected_revision=state.revision,
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
    *,
    expected_revision: int | None = None,
) -> ModeScopeState:
    try:
        return commit_mode_scope_state(
            pack_id, scope_id, state, expected_revision=expected_revision
        )
    except ModeStateError:
        raise ModePolicyError("mode_state_unavailable") from None


def _transition_record(
    installation,
    scope,
    state: ModeScopeState,
) -> _TransitionRecord | None:
    persisted = state.transition
    if persisted is None:
        return None
    full_ids = tuple(item["id"] for item in participant_manifest(installation.profile, scope))
    allowed_ids = {full_ids, full_ids[-1:]}
    if persisted.participant_ids not in allowed_ids or persisted.profile_fingerprint != installation.profile.fingerprint:
        raise ModePolicyError("mode_transition_participants_changed")
    expected_ids = persisted.participant_ids
    if persisted.journal_digest is None:
        return _TransitionRecord(persisted)
    try:
        journal, _digest = load_mode_transition_journal(
            installation.profile.id, scope.id, persisted.transition_id,
            expected_digest=persisted.journal_digest,
        )
    except ModeStateError:
        raise ModePolicyError("mode_transition_journal_unavailable") from None
    if (
        journal.get("profileFingerprint") != installation.profile.fingerprint
        or tuple(journal.get("participantIds", ())) != expected_ids
        or journal.get("phase") != persisted.status.value
    ):
        raise ModePolicyError("mode_transition_manifest_changed")
    return _TransitionRecord(persisted, journal)


def _persist_journal_transition(pack_id, scope_id, state, record):
    from .mode_state import exclusive_mode_journal_publication

    with exclusive_mode_journal_publication():
        prior_digest = record.persisted.journal_digest
        digest = save_mode_transition_journal(
            pack_id, scope_id, record.persisted.transition_id, record.journal
        )
        record.persisted = replace(record.persisted, journal_digest=digest)
        try:
            state = _commit_scope_state(
                pack_id, scope_id,
                ModeScopeState(
                    record.persisted.prior.effective,
                    record.persisted.prior.declared,
                    record.persisted,
                    revision=state.revision,
                    mode_source_revision=state.mode_source_revision,
                    mode_epoch=state.mode_epoch,
                ),
                expected_revision=state.revision,
            )
        except Exception:
            try:
                current = load_mode_scope_state(pack_id, scope_id)
            except Exception:
                raise
            if (
                current.transition is not None
                and current.transition.transition_id == record.persisted.transition_id
                and current.transition.journal_digest == digest
            ):
                state = current
            else:
                delete_mode_transition_journal_revision(pack_id, scope_id, digest)
                record.persisted = replace(
                    record.persisted, journal_digest=prior_digest
                )
                raise
        delete_mode_transition_journal_revision(
            pack_id, scope_id, prior_digest
        )
        return record, state


def _recover_transition(installation, scope, state, record):
    if record.persisted.journal_digest is None:
        return _restore_drift_transition(installation, scope, state, record)
    if record.journal is None:
        raise ModeTransitionError("PRIVACY_TRANSITION_STATE_FAILED")
    if record.journal.get("schema") == "helto.privacy-external-mode-transition":
        raise ModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_REQUIRED")
    if record.persisted.status is ModeTransitionStatus.RETIRING:
        context = _context_from_journal(record.journal)
        participants = record.journal["participants"]
        for item in participants[:-1]:
            retire_participant(installation, context, item)
        _commit_or_reconcile_mode_source(installation, context, participants[-1])
        record, state = _persist_journal_transition(
            installation.profile.id, scope.id, state, record
        )
        source_target = participants[-1].get("target")
        source_revision = int(source_target["revision"])
        final = _commit_scope_state(
            installation.profile.id, scope.id,
            ModeScopeState(
                EffectivePrivacyMode(str(record.journal["targetEffective"])),
                record.persisted.target,
                revision=state.revision,
                mode_source_revision=source_revision,
                mode_epoch=state.mode_epoch + 1,
                cleanup_journal_digest=record.persisted.journal_digest,
            ), expected_revision=state.revision,
        )
        return _load_scope_state(installation.profile.id, scope.id)
    record.journal["phase"] = ModeTransitionStatus.ROLLING_BACK.value
    record.persisted = replace(record.persisted, status=ModeTransitionStatus.ROLLING_BACK)
    record, state = _persist_journal_transition(
        installation.profile.id, scope.id, state, record
    )
    return _rollback_journal(installation, scope, state, record)


def _rollback_journal(installation, scope, state, record):
    context = _context_from_journal(record.journal)
    for item in reversed(record.journal["participants"]):
        rollback_participant(installation, context, item)
    restored = _commit_scope_state(
        installation.profile.id, scope.id,
        ModeScopeState(
            record.persisted.prior.effective,
            record.persisted.prior.declared,
            revision=state.revision,
            mode_source_revision=state.mode_source_revision,
            mode_epoch=state.mode_epoch + 1,
            cleanup_journal_digest=record.persisted.journal_digest,
        ), expected_revision=state.revision,
    )
    return _load_scope_state(installation.profile.id, scope.id)


def _restore_drift_transition(installation, scope, state, record):
    adapter = installation.adapters[scope.mode_source_adapter]
    current = _mode_source_snapshot(installation, scope)
    if current.declared is not record.persisted.prior.declared:
        restored = adapter.compare_and_set_mode_source(
            scope.id, current.revision, current.declared, record.persisted.prior.declared
        )
        current = _mode_source_snapshot_value(restored)
    return _commit_scope_state(
        installation.profile.id, scope.id,
        ModeScopeState(
            record.persisted.prior.effective,
            record.persisted.prior.declared,
            revision=state.revision,
            mode_source_revision=current.revision,
            mode_epoch=state.mode_epoch + 1,
        ), expected_revision=state.revision,
    )


def _context_from_journal(journal):
    return ModeTransitionContext(
        str(journal["scopeId"]), str(journal["transitionId"]),
        EffectivePrivacyMode(str(journal["priorEffective"])),
        EffectivePrivacyMode(str(journal["targetEffective"])),
        DeclaredPrivacyMode(str(journal["targetDeclared"])),
    )


def _commit_or_reconcile_mode_source(installation, context, item):
    adapter = installation.adapters[str(item["adapterId"])]
    prior = _mode_source_snapshot_value(item["prior"])
    current = _mode_source_snapshot_value(adapter.read_mode_source(context.scope_id))
    if current.revision == prior.revision and current.declared is prior.declared:
        commit_participant(installation, context, item)
        return
    if (
        current.revision == prior.revision + 1
        and current.declared is context.target_declared
    ):
        item["target"] = current.to_payload()
        return
    raise ModeParticipantError("mode_source_cas_failed")


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


def _open_scope_lock(pack_id: str, scope_id: str) -> int:
    digest = hashlib.sha256(f"{pack_id}\0{scope_id}".encode()).hexdigest()
    root = mode_state_path().with_name(f"{mode_state_path().stem}.locks")
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        descriptor = os.open(root / f"{digest}.lock", os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(descriptor, 0o600)
        return descriptor
    except OSError:
        raise ModePolicyError("mode_scope_admission_unavailable") from None


def _mode_source_snapshot(installation, scope):
    try:
        return _mode_source_snapshot_value(
            installation.adapters[scope.mode_source_adapter].read_mode_source(scope.id)
        )
    except Exception:
        raise ModePolicyError("mode_source_unavailable") from None
