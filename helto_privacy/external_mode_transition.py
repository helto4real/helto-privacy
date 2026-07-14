"""Recoverable coordination for browser-authoritative workflow mode changes."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from dataclasses import replace
from threading import RLock
from typing import Mapping

from .guard import (
    AuthorizedPrivacyRequest,
    PrivacyAuthorizationError,
    require_current_authorization,
    require_declassification_confirmation,
)
from .mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeFacts,
    ModeTransitionContext,
    ModeTransitionError,
    ModeTransitionStatus,
    normalize_declared_mode,
)
from .mode_participants import (
    EXTERNAL_WORKFLOW_KIND,
    MODE_SOURCE_KIND,
    commit_participant,
    mode_source_snapshot,
    participant_manifest,
    prepare_participant,
    prepare_participant_plans,
    retire_participant,
    rollback_participant,
    verify_prepared_participant,
)
from .mode_values import protect_state
from .mode_state import (
    CompletedModeTransition,
    ModeScopeState,
    PersistedModeTransition,
    TransitionRecoveryKind,
    load_mode_scope_state,
)
from .profile import ProtectedStateAuthority


_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SECRET = re.compile(r"^hp-mode-resume-[A-Za-z0-9_-]{43}$")
_LEASE = re.compile(r"^hp-mode-client-[A-Za-z0-9_-]{43}$")
_LOCATOR = re.compile(r"^[A-Za-z0-9._~:-]{1,128}$")
_OWNER_ID = re.compile(r"^hp-owner-[A-Za-z0-9_-]{43}$")
_ACTIVE_CLIENT_LOCK = RLock()
_ACTIVE_CLIENTS: dict[tuple[str, str], tuple[str, str, int]] = {}


class ExternalModeTransitionError(ModeTransitionError):
    """Sanitized external transition protocol failure."""


def has_external_workflow_participants(profile, scope_id: str) -> bool:
    return bool(_external_fields(profile, scope_id))


def heartbeat_external_client(
    installation,
    scope_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    coordinator_id: str,
    resume_secret: str,
    server_boot_epoch: str,
) -> dict[str, object]:
    """Claim/refresh the single live browser coordinator for one scope."""

    _authorize(
        authorization, "mode.transition.client-heartbeat", installation.profile.id
    )
    coordinator_id = _token(coordinator_id)
    resume_secret = _resume_secret(resume_secret)
    boot_epoch = _require_server_boot_epoch(server_boot_epoch)
    fields = _external_fields(installation.profile, scope_id)
    if not fields:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_NOT_REQUIRED")
    ttl = min(field.external_transition_policy.lease_seconds for field in fields)
    with _exclusive_scope(installation.profile.id, scope_id):
        state = load_mode_scope_state(installation.profile.id, scope_id)
        if state.transition is not None:
            _state, record = _load_external(
                installation, scope_id, state.transition.transition_id
            )
            if (
                record.journal.get("coordinatorId") != coordinator_id
                or not hmac.compare_digest(
                    str(record.journal.get("resumeSecretDigest")),
                    _secret_digest(resume_secret),
                )
            ):
                raise ExternalModeTransitionError("PRIVACY_EXTERNAL_ACTIVE_CLIENT")
        expires_ns = _claim_active_client(
            installation.profile.id, scope_id, coordinator_id, boot_epoch, ttl
        )
    return {
        "scopeId": scope_id,
        "coordinatorId": coordinator_id,
        "serverBootEpoch": boot_epoch,
        "expiresInSeconds": max(0, (expires_ns - time.time_ns()) // 1_000_000_000),
    }


def reserve_external_transition(
    installation,
    mode_resource_id: str,
    scope_id: str,
    target: object,
    authorization: AuthorizedPrivacyRequest,
    *,
    request_id: str,
    coordinator_id: str,
    resume_secret: str,
    offline_representation_count: int,
    expected_mode_epoch: int,
    server_boot_epoch: str,
    facts: ModeFacts | None = None,
) -> dict[str, object]:
    """Idempotently reserve a scope before the browser freezes serialization."""

    from . import mode_runtime

    _authorize(authorization, "mode.transition.reserve", installation.profile.id)
    request_id = _token(request_id)
    coordinator_id = _token(coordinator_id)
    resume_secret = _resume_secret(resume_secret)
    if type(offline_representation_count) is not int or offline_representation_count != 0:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_OFFLINE_REPRESENTATIONS")
    scope = mode_runtime._scope(installation, mode_resource_id, scope_id)
    fields = _external_fields(installation.profile, scope_id)
    if not fields:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_NOT_REQUIRED")
    target_declared = normalize_declared_mode(target)
    supplied_facts = facts if isinstance(facts, ModeFacts) else ModeFacts()

    with _exclusive_scope(installation.profile.id, scope_id):
        try:
            from .external_operation_state import has_active_external_operations

            if has_active_external_operations(
                pack_id=installation.profile.id,
                scope_id=scope_id,
            ):
                raise ExternalModeTransitionError(
                    "PRIVACY_TRANSITION_IN_PROGRESS"
                )
        except ExternalModeTransitionError:
            raise
        except Exception:
            raise ExternalModeTransitionError(
                "PRIVACY_TRANSITION_STATE_FAILED"
            ) from None
        state = load_mode_scope_state(installation.profile.id, scope_id)
        current_boot_epoch = _require_server_boot_epoch(server_boot_epoch)
        if type(expected_mode_epoch) is not int or expected_mode_epoch != state.mode_epoch:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
        if state.transition is not None:
            state, record = _load_external(
                installation, scope_id, state.transition.transition_id
            )
            journal = record.journal
            if not (
                journal.get("requestId") == request_id
                and journal.get("coordinatorId") == coordinator_id
                and journal.get("resumeSecretDigest") == _secret_digest(resume_secret)
                and journal.get("targetDeclared") == target_declared.value
            ):
                raise ExternalModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS")
            _claim_active_client(
                installation.profile.id,
                scope_id,
                coordinator_id,
                current_boot_epoch,
                min(field.external_transition_policy.lease_seconds for field in fields),
            )
            lease = _rotate_lease(journal, fields)
            record, _ = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
            return _reservation(record.journal, fields, lease)

        _claim_active_client(
            installation.profile.id,
            scope_id,
            coordinator_id,
            current_boot_epoch,
            min(field.external_transition_policy.lease_seconds for field in fields),
        )

        prior = mode_runtime.resolve_bound_mode(
            installation, mode_resource_id, scope_id, supplied_facts
        )
        state = load_mode_scope_state(installation.profile.id, scope_id)
        target_resolution = mode_runtime._resolve_declared_mode(
            installation,
            mode_resource_id,
            scope,
            target_declared,
            replace(supplied_facts, current_mode=None, request_mode=None),
        )
        if target_declared is DeclaredPrivacyMode.PUBLIC and target_resolution.floors:
            raise ExternalModeTransitionError("PRIVACY_FLOOR_ACTIVE")
        if (
            prior.effective is EffectivePrivacyMode.PRIVATE
            and target_resolution.effective is EffectivePrivacyMode.PUBLIC
        ):
            try:
                require_declassification_confirmation(
                    authorization, scope_id=scope_id, target=target_declared.value
                )
            except PrivacyAuthorizationError as exc:
                raise ExternalModeTransitionError(exc.code) from None

        transition_id = secrets.token_hex(16)
        manifest = participant_manifest(installation.profile, scope)
        if prior.effective is target_resolution.effective:
            manifest = manifest[-1:]
        participant_ids = tuple(item["id"] for item in manifest)
        persisted = PersistedModeTransition(
            transition_id,
            ModeTransitionStatus.PREPARING,
            prior,
            target_declared,
            participant_ids,
            TransitionRecoveryKind.PREPARED,
            installation.profile.fingerprint,
        )
        lease = "hp-mode-client-" + secrets.token_urlsafe(32)
        lease_seconds = min(field.external_transition_policy.lease_seconds for field in fields)
        journal: dict[str, object] = {
            "schema": "helto.privacy-external-mode-transition",
            "version": 1,
            "protocol": "recoverable-v1",
            "packId": installation.profile.id,
            "profileFingerprint": installation.profile.fingerprint,
            "scopeId": scope_id,
            "transitionId": transition_id,
            "requestId": request_id,
            "coordinatorId": coordinator_id,
            "resumeSecretDigest": _secret_digest(resume_secret),
            "phase": ModeTransitionStatus.PREPARING.value,
            "externalPhase": "reserved",
            "priorDeclared": prior.declared.value,
            "priorEffective": prior.effective.value,
            "targetEffective": target_resolution.effective.value,
            "targetDeclared": target_declared.value,
            "participantIds": list(participant_ids),
            "participants": [],
            "prepared": [],
            "committed": [],
            "retired": [],
            "rolledBack": [],
            "externalOwners": [],
            "appliedOwnerIds": [],
            "verifiedOwnerIds": [],
            "verifiedSnapshotId": None,
            "verifiedSnapshotGeneration": None,
            "restoredOwnerIds": [],
            "expectedModeEpoch": state.mode_epoch,
            "targetModeEpoch": state.mode_epoch + 1,
            "serverBootEpochAtReserve": current_boot_epoch,
            "evidenceBootEpoch": current_boot_epoch,
            "clientLeaseEpoch": 1,
            "clientLeaseDigest": _lease_digest(lease),
            "clientLeaseExpiresNs": time.time_ns() + lease_seconds * 1_000_000_000,
            "clientLeaseBootEpoch": current_boot_epoch,
        }
        record = mode_runtime._TransitionRecord(persisted, journal)
        record, _ = mode_runtime._persist_journal_transition(
            installation.profile.id, scope_id, state, record
        )
        return _reservation(record.journal, fields, lease)


def prepare_external_transition(
    installation,
    scope_id: str,
    transition_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    resume_secret: str,
    coordinator_id: str,
    client_lease: str,
    client_lease_epoch: int,
    mode_epoch: int,
    server_boot_epoch: str,
    owners: object,
) -> dict[str, object]:
    """Close the owner manifest, derive targets server-side, and prepare internals."""

    from . import mode_runtime

    _authorize(authorization, "mode.transition.prepare", installation.profile.id)
    with _exclusive_scope(installation.profile.id, scope_id):
        state, record = _load_external(installation, scope_id, transition_id)
        journal = record.journal
        _require_client(
            journal, resume_secret, coordinator_id, client_lease,
            client_lease_epoch, mode_epoch, server_boot_epoch,
        )
        if journal["externalPhase"] == "reserved":
            context = mode_runtime._context_from_journal(journal)
            journal["externalOwners"] = _prepare_owners(
                installation, scope_id, resume_secret, context, owners
            )
            journal["externalPhase"] = "owner-manifest-closed"
            record, state = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
        else:
            _verify_prepare_retry(
                installation.profile, scope_id, resume_secret,
                journal["externalOwners"], owners,
            )
        if journal["externalPhase"] == "owner-manifest-closed":
            scope = next(item for item in installation.profile.scopes if item.id == scope_id)
            context = mode_runtime._context_from_journal(journal)
            plans = prepare_participant_plans(installation, scope, context)
            if tuple(item["id"] for item in plans) != tuple(journal["participantIds"]):
                raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_STATE_FAILED")
            journal["participants"] = plans
            journal["externalPhase"] = "preparing"
            record, state = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
        if journal["externalPhase"] == "preparing":
            context = mode_runtime._context_from_journal(journal)
            for item in journal["participants"]:
                if item["id"] in journal["prepared"] or item["kind"] in {
                    EXTERNAL_WORKFLOW_KIND, MODE_SOURCE_KIND,
                }:
                    continue
                prepare_participant(installation, scope_id, context, item)
                verify_prepared_participant(installation, context, item)
                journal["prepared"].append(item["id"])
                record, state = mode_runtime._persist_journal_transition(
                    installation.profile.id, scope_id, state, record
                )
            journal["externalPhase"] = "prepared"
            record, _ = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
        if journal["externalPhase"] not in {
            "prepared", "applying", "applied", "verified",
        }:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PHASE_INVALID")
        return _recovery_payload(journal)


def acknowledge_external_apply(
    installation,
    scope_id: str,
    transition_id: str,
    authorization: AuthorizedPrivacyRequest,
    **payload,
) -> dict[str, object]:
    return _ack_owners(
        installation, scope_id, transition_id, authorization,
        operation_id="mode.transition.apply-ack",
        acknowledgements=payload.pop("acknowledgements", None),
        expected_key="targetExact",
        completed_key="appliedOwnerIds",
        allowed_phases={"prepared", "applying", "applied"},
        active_phase="applying",
        complete_phase="applied",
        **payload,
    )


def verify_external_transition(
    installation,
    scope_id: str,
    transition_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    acknowledgements: object,
    snapshot_id: str,
    snapshot_generation: int,
    **capability,
) -> dict[str, object]:
    """Verify one complete detached serialization generation atomically."""

    from . import mode_runtime

    _authorize(authorization, "mode.transition.verify", installation.profile.id)
    snapshot_id = _token(snapshot_id)
    if type(snapshot_generation) is not int or snapshot_generation < 0:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
    with _exclusive_scope(installation.profile.id, scope_id):
        state, record = _load_external(installation, scope_id, transition_id)
        journal = record.journal
        _require_client_from_kwargs(journal, capability)
        if journal["externalPhase"] not in {"applied", "verified"}:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PHASE_INVALID")
        if journal["externalPhase"] == "verified" and (
            journal["verifiedSnapshotId"] != snapshot_id
            or journal["verifiedSnapshotGeneration"] != snapshot_generation
        ):
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
        journal["verifiedOwnerIds"] = []
        _merge_acknowledgements(
            installation.profile,
            scope_id,
            journal,
            acknowledgements,
            "targetExact",
            "verifiedOwnerIds",
            require_full=True,
        )
        journal["verifiedSnapshotId"] = snapshot_id
        journal["verifiedSnapshotGeneration"] = snapshot_generation
        journal["evidenceBootEpoch"] = _current_server_boot_epoch()
        journal["externalPhase"] = "verified"
        record, _ = mode_runtime._persist_journal_transition(
            installation.profile.id, scope_id, state, record
        )
        return _recovery_payload(record.journal)


def finalize_external_transition(
    installation,
    scope_id: str,
    transition_id: str,
    authorization: AuthorizedPrivacyRequest,
    **capability,
) -> dict[str, object]:
    """Idempotently commit shared state and the revisioned source last."""

    from . import mode_runtime

    _authorize(authorization, "mode.transition.finalize", installation.profile.id)
    with _exclusive_scope(installation.profile.id, scope_id):
        terminal = _terminal_retry(
            installation, scope_id, transition_id, capability, "completed"
        )
        if terminal is not None:
            return terminal
        state, record = _load_external(installation, scope_id, transition_id)
        journal = record.journal
        _require_client_from_kwargs(journal, capability)
        if journal["externalPhase"] not in {"verified", "finalizing", "retiring"}:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PHASE_INVALID")
        context = mode_runtime._context_from_journal(journal)
        if journal["externalPhase"] == "verified":
            journal["phase"] = ModeTransitionStatus.COMMITTING.value
            journal["externalPhase"] = "finalizing"
            record.persisted = replace(record.persisted, status=ModeTransitionStatus.COMMITTING)
            record, state = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
        if journal["externalPhase"] == "finalizing":
            try:
                for item in journal["participants"]:
                    if item["kind"] in {EXTERNAL_WORKFLOW_KIND, MODE_SOURCE_KIND} or item["id"] in journal["committed"]:
                        continue
                    commit_participant(installation, context, item)
                    journal["committed"].append(item["id"])
                    record, state = mode_runtime._persist_journal_transition(
                        installation.profile.id, scope_id, state, record
                    )
            except Exception:
                if item.get("target") is not None:
                    try:
                        record, state = mode_runtime._persist_journal_transition(
                            installation.profile.id, scope_id, state, record
                        )
                    except Exception:
                        pass
                if not _source_committed(journal):
                    journal["phase"] = ModeTransitionStatus.ROLLING_BACK.value
                    journal["externalPhase"] = "rollback-restoring"
                    record.persisted = replace(
                        record.persisted, status=ModeTransitionStatus.ROLLING_BACK
                    )
                    try:
                        mode_runtime._persist_journal_transition(
                            installation.profile.id, scope_id, state, record
                        )
                    except Exception:
                        pass
                raise ExternalModeTransitionError(
                    "PRIVACY_EXTERNAL_TRANSITION_FINALIZE_FAILED"
                ) from None
            journal["phase"] = ModeTransitionStatus.RETIRING.value
            journal["externalPhase"] = "retiring"
            record.persisted = replace(record.persisted, status=ModeTransitionStatus.RETIRING)
            record, state = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
        try:
            for item in journal["participants"]:
                if item["kind"] in {EXTERNAL_WORKFLOW_KIND, MODE_SOURCE_KIND} or item["id"] in journal["retired"]:
                    continue
                retire_participant(installation, context, item)
                journal["retired"].append(item["id"])
                record, state = mode_runtime._persist_journal_transition(
                    installation.profile.id, scope_id, state, record
                )
            source_item = journal["participants"][-1]
            if source_item["kind"] != MODE_SOURCE_KIND:
                raise ExternalModeTransitionError(
                    "PRIVACY_EXTERNAL_TRANSITION_STATE_FAILED"
                )
            if source_item["id"] not in journal["committed"]:
                try:
                    _reconcile_mode_source(installation, context, source_item)
                    journal["committed"].append(source_item["id"])
                    record, state = mode_runtime._persist_journal_transition(
                        installation.profile.id, scope_id, state, record
                    )
                except Exception:
                    if source_item.get("target") is not None:
                        try:
                            mode_runtime._persist_journal_transition(
                                installation.profile.id, scope_id, state, record
                            )
                        except Exception:
                            pass
                    raise
            source = source_item["target"]
            mode_runtime._commit_scope_state(
                installation.profile.id,
                scope_id,
                ModeScopeState(
                    EffectivePrivacyMode(str(journal["targetEffective"])),
                    DeclaredPrivacyMode(str(journal["targetDeclared"])),
                    revision=state.revision,
                    mode_source_revision=int(source["revision"]),
                    mode_epoch=int(journal["targetModeEpoch"]),
                    cleanup_journal_digest=record.persisted.journal_digest,
                    completed_transition=_completed_transition(
                        journal,
                        DeclaredPrivacyMode(str(journal["targetDeclared"])),
                        EffectivePrivacyMode(str(journal["targetEffective"])),
                        "completed",
                    ),
                ),
                expected_revision=state.revision,
            )
            completed = load_mode_scope_state(installation.profile.id, scope_id)
        except Exception:
            raise ExternalModeTransitionError(
                "PRIVACY_EXTERNAL_TRANSITION_RETIRE_FAILED"
            ) from None
        return _complete_payload(scope_id, completed)


def rollback_external_transition(
    installation,
    scope_id: str,
    transition_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    acknowledgements: object = None,
    **capability,
) -> dict[str, object]:
    """Return exact originals, then rollback internals only after restore acks."""

    from . import mode_runtime

    _authorize(authorization, "mode.transition.rollback", installation.profile.id)
    with _exclusive_scope(installation.profile.id, scope_id):
        terminal = _terminal_retry(
            installation, scope_id, transition_id, capability, "rolled-back"
        )
        if terminal is not None:
            return terminal
        state, record = _load_external(installation, scope_id, transition_id)
        journal = record.journal
        _require_client_from_kwargs(journal, capability)
        context = mode_runtime._context_from_journal(journal)
        if _live_source_is_target(installation, state, context, journal):
            record, _ = mode_runtime._persist_journal_transition(
                installation.profile.id, scope_id, state, record
            )
            raise ExternalModeTransitionError(
                "PRIVACY_EXTERNAL_TRANSITION_FORWARD_ONLY"
            )
        if _source_committed(journal):
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FORWARD_ONLY")
        if journal["externalPhase"] in {"reserved", "owner-manifest-closed"}:
            journal["externalPhase"] = "rollback-restoring"
        elif journal["externalPhase"] not in {
            "preparing", "prepared", "applying", "applied", "verifying",
            "verified", "finalizing", "rollback-restoring", "rolling-back",
        }:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PHASE_INVALID")
        journal["phase"] = ModeTransitionStatus.ROLLING_BACK.value
        journal["externalPhase"] = "rollback-restoring"
        record.persisted = replace(record.persisted, status=ModeTransitionStatus.ROLLING_BACK)
        if acknowledgements is not None:
            _merge_acknowledgements(
                installation.profile, scope_id, journal, acknowledgements,
                "originalExact", "restoredOwnerIds",
            )
        record, state = mode_runtime._persist_journal_transition(
            installation.profile.id, scope_id, state, record
        )
        if len(journal["restoredOwnerIds"]) != len(journal["externalOwners"]):
            return _recovery_payload(journal)
        journal["externalPhase"] = "rolling-back"
        record, state = mode_runtime._persist_journal_transition(
            installation.profile.id, scope_id, state, record
        )
        context = mode_runtime._context_from_journal(journal)
        try:
            for item in reversed(journal["participants"]):
                if item["kind"] == EXTERNAL_WORKFLOW_KIND or item["id"] in journal["rolledBack"]:
                    continue
                rollback_participant(installation, context, item)
                journal["rolledBack"].append(item["id"])
                record, state = mode_runtime._persist_journal_transition(
                    installation.profile.id, scope_id, state, record
                )
            mode_runtime._commit_scope_state(
                installation.profile.id,
                scope_id,
                ModeScopeState(
                    record.persisted.prior.effective,
                    record.persisted.prior.declared,
                    revision=state.revision,
                    mode_source_revision=state.mode_source_revision,
                    mode_epoch=int(journal["targetModeEpoch"]),
                    cleanup_journal_digest=record.persisted.journal_digest,
                    completed_transition=_completed_transition(
                        journal,
                        record.persisted.prior.declared,
                        record.persisted.prior.effective,
                        "rolled-back",
                    ),
                ),
                expected_revision=state.revision,
            )
            completed = load_mode_scope_state(installation.profile.id, scope_id)
        except Exception:
            raise ExternalModeTransitionError(
                "PRIVACY_EXTERNAL_TRANSITION_ROLLBACK_FAILED"
            ) from None
        return _complete_payload(scope_id, completed)


def external_transition_status(
    installation,
    scope_id: str,
    authorization: AuthorizedPrivacyRequest,
) -> dict[str, object]:
    _authorize(authorization, "mode.transition.status", installation.profile.id)
    state = load_mode_scope_state(installation.profile.id, scope_id)
    if state.transition is None:
        return {
            "scopeId": scope_id,
            "transitionStatus": "idle",
            "modeEpoch": state.mode_epoch,
        }
    _state, record = _load_external(
        installation, scope_id, state.transition.transition_id
    )
    return _safe_status(record.journal)


def rebase_external_owner_exact(
    installation,
    scope_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    field_id: str,
    exact: object,
    mode_epoch: int,
    server_boot_epoch: str,
) -> dict[str, object]:
    """Derive the canonical current-mode bytes for one stale browser owner."""

    from .mode import ModeTransitionContext

    _authorize(authorization, "mode.transition.rebase", installation.profile.id)
    _require_server_boot_epoch(server_boot_epoch)
    with _exclusive_scope(installation.profile.id, scope_id):
        state = load_mode_scope_state(installation.profile.id, scope_id)
        if (
            state.transition is not None
            or type(mode_epoch) is not int
            or mode_epoch != state.mode_epoch
        ):
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
        field = next(
            (item for item in _external_fields(installation.profile, scope_id)
             if item.id == field_id),
            None,
        )
        if field is None:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        maximum = max(
            field.external_transition_policy.max_original_bytes_per_owner,
            field.external_transition_policy.max_target_bytes_per_owner,
        )
        original = _exact(exact, maximum)
        context = ModeTransitionContext(
            scope_id,
            f"mode-rebase-{state.mode_epoch}",
            state.established_mode,
            state.established_mode,
            state.established_declared,
        )
        target = _encode_target_exact(
            installation.adapters[field.state_adapter], field, original, context,
        )
        if (
            len(target)
            > field.external_transition_policy.max_target_bytes_per_owner
        ):
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        return {
            "scopeId": scope_id,
            "fieldId": field.id,
            "exact": _b64(target),
            "modeEpoch": state.mode_epoch,
            "serverBootEpoch": _current_server_boot_epoch(),
        }


def resume_external_transition(
    installation,
    scope_id: str,
    transition_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    resume_secret: str,
    coordinator_id: str,
    mode_epoch: int,
    server_boot_epoch: str,
) -> dict[str, object]:
    """Fence stale tabs and return only the exact values needed for recovery."""

    from . import mode_runtime

    _authorize(authorization, "mode.transition.resume", installation.profile.id)
    with _exclusive_scope(installation.profile.id, scope_id):
        state, record = _load_external(installation, scope_id, transition_id)
        journal = record.journal
        current_boot_epoch = _require_resume(
            journal,
            resume_secret,
            coordinator_id,
            mode_epoch,
            server_boot_epoch,
        )
        rollback_direction = journal["externalPhase"] in {
            "rollback-restoring", "rolling-back",
        }
        journal["appliedOwnerIds"] = []
        journal["verifiedOwnerIds"] = []
        journal["restoredOwnerIds"] = []
        journal["verifiedSnapshotId"] = None
        journal["verifiedSnapshotGeneration"] = None
        journal["evidenceBootEpoch"] = current_boot_epoch
        journal["phase"] = (
            ModeTransitionStatus.ROLLING_BACK.value
            if rollback_direction
            else ModeTransitionStatus.PREPARING.value
        )
        journal["externalPhase"] = (
            "rollback-restoring" if rollback_direction else "prepared"
        )
        record.persisted = replace(
            record.persisted,
            status=(
                ModeTransitionStatus.ROLLING_BACK
                if rollback_direction
                else ModeTransitionStatus.PREPARING
            ),
        )
        lease = _rotate_lease(journal, _external_fields(installation.profile, scope_id))
        record, _ = mode_runtime._persist_journal_transition(
            installation.profile.id, scope_id, state, record
        )
        return {**_recovery_payload(record.journal), "clientLease": lease}


def _ack_owners(
    installation, scope_id, transition_id, authorization, *, operation_id,
    acknowledgements, expected_key, completed_key, allowed_phases,
    active_phase, complete_phase, **capability,
):
    from . import mode_runtime

    _authorize(authorization, operation_id, installation.profile.id)
    with _exclusive_scope(installation.profile.id, scope_id):
        state, record = _load_external(installation, scope_id, transition_id)
        journal = record.journal
        _require_client_from_kwargs(journal, capability)
        if journal["externalPhase"] not in allowed_phases:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PHASE_INVALID")
        _merge_acknowledgements(
            installation.profile, scope_id, journal, acknowledgements,
            expected_key, completed_key,
        )
        journal["externalPhase"] = (
            complete_phase
            if len(journal[completed_key]) == len(journal["externalOwners"])
            else active_phase
        )
        record, _ = mode_runtime._persist_journal_transition(
            installation.profile.id, scope_id, state, record
        )
        return _recovery_payload(record.journal)


def _prepare_owners(installation, scope_id, resume_secret, context, owners):
    if not isinstance(owners, list):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
    fields = {field.id: field for field in _external_fields(installation.profile, scope_id)}
    counts = {field_id: 0 for field_id in fields}
    totals = {field_id: 0 for field_id in fields}
    identities: set[tuple[str, str, str, str]] = set()
    owner_ids: set[str] = set()
    normalized = []
    cumulative_journal_bytes = 0
    cumulative_limit = min(
        48 * 1024 * 1024,
        *(field.external_transition_policy.max_total_bytes for field in fields.values()),
    )
    for value in owners:
        if not isinstance(value, Mapping) or set(value) != {"locator", "originalExact"}:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        locator = _locator(value["locator"])
        field = fields.get(locator["fieldId"])
        if field is None:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        identity = tuple(locator[name] for name in ("rootGraphId", "graphId", "nodeId", "fieldId"))
        if identity in identities:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        identities.add(identity)
        policy = field.external_transition_policy
        original = _exact(value["originalExact"], policy.max_original_bytes_per_owner)
        target = _encode_target_exact(
            installation.adapters[field.state_adapter], field, original, context,
        )
        if len(target) > policy.max_target_bytes_per_owner:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        counts[field.id] += 1
        totals[field.id] += len(original) + len(target)
        if counts[field.id] > policy.max_owners or totals[field.id] > policy.max_total_bytes:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        owner_id = _opaque_owner_id(
            resume_secret,
            installation.profile.id,
            installation.profile.fingerprint,
            scope_id,
            locator,
        )
        if owner_id in owner_ids:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        owner_ids.add(owner_id)
        prepared_owner = {
            "ownerId": owner_id,
            "fieldId": field.id,
            "originalExact": _b64(original),
            "targetExact": _b64(target),
            "originalDigest": hashlib.sha256(original).hexdigest(),
            "targetDigest": hashlib.sha256(target).hexdigest(),
        }
        cumulative_journal_bytes += len(json.dumps(
            prepared_owner,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        if cumulative_journal_bytes > cumulative_limit:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
        normalized.append(prepared_owner)
    return sorted(normalized, key=lambda item: item["ownerId"])


def _encode_target_exact(adapter, field, original, context):
    try:
        representation = str(
            adapter.classify_mode_transition_representation(original, context)
        )
        if representation not in {"private", "public"}:
            raise ValueError("invalid representation")
        decoded = adapter.decode_mode_transition_representation(original, context)
        normalized_value = adapter.normalize_mode_transition_value(decoded, context)
        target_representation = context.target_mode.value
        if representation == target_representation:
            target = original
        elif context.target_mode is EffectivePrivacyMode.PUBLIC:
            target = adapter.encode_public_mode_transition(normalized_value, context)
        else:
            target = json.dumps(
                protect_state(field.current_schema, normalized_value, context.target_mode),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
    except Exception:
        raise ExternalModeTransitionError(
            "PRIVACY_EXTERNAL_TRANSITION_ENCODING_FAILED"
        ) from None
    if not isinstance(target, (bytes, bytearray, memoryview)):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_ENCODING_FAILED")
    return bytes(target)


def _verify_prepare_retry(profile, scope_id, resume_secret, stored, owners):
    if not isinstance(owners, list) or len(owners) != len(stored):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CONFLICT")
    expected = {item["ownerId"]: item for item in stored}
    seen = set()
    fields = {field.id: field for field in _external_fields(profile, scope_id)}
    for value in owners:
        if not isinstance(value, Mapping) or set(value) != {"locator", "originalExact"}:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CONFLICT")
        locator = _locator(value["locator"])
        owner_id = _opaque_owner_id(
            resume_secret, profile.id, profile.fingerprint, scope_id, locator
        )
        if owner_id in seen or owner_id not in expected:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CONFLICT")
        seen.add(owner_id)
        field = fields.get(locator["fieldId"])
        if field is None:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CONFLICT")
        exact = _exact(
            value["originalExact"],
            field.external_transition_policy.max_original_bytes_per_owner,
        )
        if not hmac.compare_digest(_b64(exact), expected[owner_id]["originalExact"]):
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CONFLICT")


def _merge_acknowledgements(
    profile, scope_id, journal, acknowledgements, expected_key, completed_key,
    *, require_full=False,
):
    if not isinstance(acknowledgements, list):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
    expected = {item["ownerId"]: item for item in journal["externalOwners"]}
    fields = {field.id: field for field in _external_fields(profile, scope_id)}
    seen = set()
    completed = set(journal[completed_key])
    for value in acknowledgements:
        if not isinstance(value, Mapping) or set(value) != {"ownerId", "exact"}:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
        owner_id = str(value["ownerId"])
        if owner_id in seen or _OWNER_ID.fullmatch(owner_id) is None or owner_id not in expected:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
        seen.add(owner_id)
        owner = expected[owner_id]
        field = fields[owner["fieldId"]]
        maximum = (
            field.external_transition_policy.max_original_bytes_per_owner
            if expected_key == "originalExact"
            else field.external_transition_policy.max_target_bytes_per_owner
        )
        exact = _exact(value["exact"], maximum)
        if not hmac.compare_digest(_b64(exact), owner[expected_key]):
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
        completed.add(owner_id)
    if require_full and seen != set(expected):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_VERIFY_FAILED")
    journal[completed_key] = sorted(completed)


def _load_external(installation, scope_id, transition_id):
    from . import mode_runtime

    state = load_mode_scope_state(installation.profile.id, scope_id)
    if state.transition is None or state.transition.transition_id != transition_id:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_NOT_FOUND")
    scope = next((item for item in installation.profile.scopes if item.id == scope_id), None)
    if scope is None:
        raise ExternalModeTransitionError("PRIVACY_SCOPE_INVALID")
    try:
        record = mode_runtime._transition_record(installation, scope, state)
    except Exception:
        raise ExternalModeTransitionError(
            "PRIVACY_EXTERNAL_TRANSITION_STATE_FAILED"
        ) from None
    if record is None or record.journal is None or record.journal.get("schema") != "helto.privacy-external-mode-transition":
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_NOT_FOUND")
    return state, record


def _reconcile_mode_source(installation, context, item):
    adapter = installation.adapters[str(item["adapterId"])]
    prior = mode_source_snapshot(item["prior"])
    current = mode_source_snapshot(adapter.read_mode_source(context.scope_id))
    if current.revision == prior.revision and current.declared is prior.declared:
        commit_participant(installation, context, item)
        return
    if current.revision == prior.revision + 1 and current.declared is context.target_declared:
        item["target"] = current.to_payload()
        return
    raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_SOURCE_DIVERGED")


def _source_committed(journal):
    source = next(
        (item for item in journal["participants"] if item["kind"] == MODE_SOURCE_KIND),
        None,
    )
    return source is not None and (
        source["id"] in journal["committed"] or source.get("target") is not None
    )


def _live_source_is_target(installation, state, context, journal):
    scope = next(item for item in installation.profile.scopes if item.id == context.scope_id)
    adapter = installation.adapters[scope.mode_source_adapter]
    current = mode_source_snapshot(adapter.read_mode_source(context.scope_id))
    source = next(
        (item for item in journal["participants"] if item["kind"] == MODE_SOURCE_KIND),
        None,
    )
    if source is None:
        prior_revision = state.mode_source_revision
        prior_declared = journal["priorDeclared"]
    else:
        prior = mode_source_snapshot(source["prior"])
        prior_revision = prior.revision
        prior_declared = prior.declared.value
    if current.revision == prior_revision and current.declared.value == prior_declared:
        return False
    if (
        current.revision == prior_revision + 1
        and current.declared is context.target_declared
    ):
        if source is not None:
            source["target"] = current.to_payload()
        return True
    raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_SOURCE_DIVERGED")


def _recovery_payload(journal):
    phase = journal["externalPhase"]
    if phase in {"rollback-restoring", "rolling-back"}:
        completed = set(journal["restoredOwnerIds"])
    elif phase in {"verifying", "verified"}:
        completed = set(journal["verifiedOwnerIds"])
    else:
        completed = set(journal["appliedOwnerIds"])
    exact_key = "originalExact" if phase in {"rollback-restoring", "rolling-back"} else "targetExact"
    return {
        **_safe_status(journal),
        "pendingOwners": [
            {"ownerId": item["ownerId"], "fieldId": item["fieldId"], "exact": item[exact_key]}
            for item in journal["externalOwners"]
            if item["ownerId"] not in completed
        ],
    }


def _safe_status(journal):
    expires = max(
        0, (int(journal["clientLeaseExpiresNs"]) - time.time_ns()) // 1_000_000_000
    )
    return {
        "scopeId": journal["scopeId"],
        "transitionId": journal["transitionId"],
        "transitionStatus": journal["phase"],
        "externalPhase": journal["externalPhase"],
        "modeEpoch": journal["expectedModeEpoch"],
        "targetModeEpoch": journal["targetModeEpoch"],
        "clientLeaseEpoch": journal["clientLeaseEpoch"],
        "leaseExpiresInSeconds": expires,
        "ownerCount": len(journal["externalOwners"]),
        "appliedOwnerCount": len(journal["appliedOwnerIds"]),
        "verifiedOwnerCount": len(journal["verifiedOwnerIds"]),
        "restoredOwnerCount": len(journal["restoredOwnerIds"]),
        "priorDeclared": journal["priorDeclared"],
        "priorEffective": journal["priorEffective"],
        "targetEffective": journal["targetEffective"],
        "targetDeclared": journal["targetDeclared"],
        "serverBootEpoch": _current_server_boot_epoch(),
    }


def _reservation(journal, fields, lease):
    return {
        **_safe_status(journal),
        "requestId": journal["requestId"],
        "coordinatorId": journal["coordinatorId"],
        "clientLease": lease,
        "fields": [_field_payload(field) for field in fields],
    }


def _complete_payload(scope_id, state):
    return {
        "scopeId": scope_id,
        "declared": state.established_declared.value,
        "effective": state.established_mode.value,
        "transitionStatus": ModeTransitionStatus.IDLE.value,
        "modeEpoch": state.mode_epoch,
    }


def _completed_transition(journal, declared, effective, disposition):
    return CompletedModeTransition(
        transition_id=str(journal["transitionId"]),
        request_digest=_terminal_token_digest(
            str(journal["resumeSecretDigest"]),
            "request",
            str(journal["requestId"]),
        ),
        coordinator_digest=_terminal_token_digest(
            str(journal["resumeSecretDigest"]),
            "coordinator",
            str(journal["coordinatorId"]),
        ),
        resume_secret_digest=str(journal["resumeSecretDigest"]),
        target=declared,
        established_mode=effective,
        mode_epoch=int(journal["targetModeEpoch"]),
        disposition=disposition,
    )


def _terminal_retry(installation, scope_id, transition_id, capability, disposition):
    state = load_mode_scope_state(installation.profile.id, scope_id)
    terminal = state.completed_transition
    if terminal is None or terminal.transition_id != transition_id:
        return None
    if terminal.disposition != disposition:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_NOT_FOUND")
    try:
        resume_secret = _resume_secret(capability["resume_secret"])
        coordinator_id = _token(capability["coordinator_id"])
        mode_epoch = capability["mode_epoch"]
    except Exception:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED") from None
    if (
        not hmac.compare_digest(
            _terminal_token_digest(
                terminal.resume_secret_digest, "coordinator", coordinator_id
            ),
            terminal.coordinator_digest,
        )
        or type(mode_epoch) is not int
        or mode_epoch + 1 != terminal.mode_epoch
        or not hmac.compare_digest(
            _secret_digest(resume_secret), terminal.resume_secret_digest
        )
    ):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
    return _complete_payload(scope_id, state)


def _external_fields(profile, scope_id):
    return tuple(sorted(
        (
            field for field in profile.protected_fields
            if field.scope_id == scope_id
            and field.state_authority is ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW
        ),
        key=lambda field: field.id,
    ))


def _field_payload(field):
    return {
        "fieldId": field.id,
        "browserAdapter": field.browser_adapter,
        "nodeTypes": list(field.node_types),
        "location": {"kind": field.location.kind.value, "name": field.location.name},
        "policy": field.external_transition_policy.contract_payload(),
    }


def _authorize(authorization, operation_id, pack_id):
    try:
        require_current_authorization(authorization, operation_id, pack_id=pack_id)
    except PrivacyAuthorizationError:
        raise ExternalModeTransitionError("PRIVACY_TRANSITION_UNAUTHORIZED") from None


def _require_client_from_kwargs(journal, values):
    required = {
        "resume_secret", "coordinator_id", "client_lease",
        "client_lease_epoch", "mode_epoch", "server_boot_epoch",
    }
    if set(values) != required:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
    _require_client(
        journal, values["resume_secret"], values["coordinator_id"],
        values["client_lease"], values["client_lease_epoch"], values["mode_epoch"],
        values["server_boot_epoch"],
    )


def _require_client(
    journal, resume_secret, coordinator_id, lease, lease_epoch, mode_epoch,
    server_boot_epoch,
):
    current_boot_epoch = _require_resume(
        journal, resume_secret, coordinator_id, mode_epoch, server_boot_epoch
    )
    if (
        journal.get("evidenceBootEpoch") != current_boot_epoch
        or journal.get("clientLeaseBootEpoch") != current_boot_epoch
    ):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
    if (
        not isinstance(lease, str)
        or _LEASE.fullmatch(lease) is None
        or type(lease_epoch) is not int
        or lease_epoch != journal["clientLeaseEpoch"]
        or time.time_ns() >= int(journal["clientLeaseExpiresNs"])
        or not hmac.compare_digest(_lease_digest(lease), str(journal["clientLeaseDigest"]))
    ):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
    _touch_active_client(journal)


def _require_resume(
    journal, resume_secret, coordinator_id, mode_epoch, server_boot_epoch,
):
    resume_secret = _resume_secret(resume_secret)
    current_boot_epoch = _require_server_boot_epoch(server_boot_epoch)
    if (
        _token(coordinator_id) != journal["coordinatorId"]
        or type(mode_epoch) is not int
        or mode_epoch != journal["expectedModeEpoch"]
        or not hmac.compare_digest(
            _secret_digest(resume_secret), str(journal["resumeSecretDigest"])
        )
    ):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
    return current_boot_epoch


def _claim_active_client(pack_id, scope_id, coordinator_id, boot_epoch, ttl_seconds):
    now = time.time_ns()
    key = (pack_id, scope_id)
    expires = now + int(ttl_seconds) * 1_000_000_000
    with _ACTIVE_CLIENT_LOCK:
        current = _ACTIVE_CLIENTS.get(key)
        if current is not None:
            current_id, current_boot, current_expires = current
            if (
                current_expires > now
                and current_boot == boot_epoch
                and current_id != coordinator_id
            ):
                raise ExternalModeTransitionError("PRIVACY_EXTERNAL_ACTIVE_CLIENT")
        _ACTIVE_CLIENTS[key] = (coordinator_id, boot_epoch, expires)
    return expires


def _touch_active_client(journal):
    _claim_active_client(
        str(journal["packId"]),
        str(journal["scopeId"]),
        str(journal["coordinatorId"]),
        _current_server_boot_epoch(),
        max(30, int(
            (int(journal["clientLeaseExpiresNs"]) - time.time_ns()) // 1_000_000_000
        )),
    )


def _current_server_boot_epoch():
    from .runtime import SERVER_BOOT_EPOCH

    return SERVER_BOOT_EPOCH


def _require_server_boot_epoch(value):
    current = _current_server_boot_epoch()
    if not isinstance(value, str) or not hmac.compare_digest(value, current):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
    return current


def _rotate_lease(journal, fields):
    lease = "hp-mode-client-" + secrets.token_urlsafe(32)
    lease_seconds = min(field.external_transition_policy.lease_seconds for field in fields)
    journal["clientLeaseEpoch"] = int(journal["clientLeaseEpoch"]) + 1
    journal["clientLeaseDigest"] = _lease_digest(lease)
    journal["clientLeaseExpiresNs"] = time.time_ns() + lease_seconds * 1_000_000_000
    journal["clientLeaseBootEpoch"] = _current_server_boot_epoch()
    return lease


def _locator(value):
    if not isinstance(value, Mapping) or set(value) != {
        "rootGraphId", "graphId", "nodeId", "fieldId",
    }:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
    result = {name: str(value[name]) for name in (
        "rootGraphId", "graphId", "nodeId", "fieldId",
    )}
    if result["rootGraphId"] != "root" or any(
        _LOCATOR.fullmatch(item) is None for item in result.values()
    ):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
    return result


def _opaque_owner_id(resume_secret, pack_id, profile_fingerprint, scope_id, locator):
    message = "\0".join((
        "graph-node-field-v1", pack_id, profile_fingerprint, scope_id,
        locator["rootGraphId"], locator["graphId"], locator["nodeId"], locator["fieldId"],
    )).encode("utf-8")
    digest = hmac.new(resume_secret.encode("ascii"), message, hashlib.sha256).digest()
    return "hp-owner-" + _b64(digest)


def _exact(value, maximum):
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID") from None
    if len(decoded) > maximum or _b64(decoded) != value.rstrip("="):
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_PLAN_INVALID")
    return decoded


def _token(value):
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CAPABILITY_INVALID")
    return value


def _resume_secret(value):
    if not isinstance(value, str) or _SECRET.fullmatch(value) is None:
        raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_CAPABILITY_INVALID")
    return value


def _secret_digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _terminal_token_digest(resume_digest, domain, value):
    return hmac.new(
        bytes.fromhex(resume_digest),
        f"helto.privacy-terminal-{domain}\0{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _lease_digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@contextmanager
def _exclusive_scope(pack_id, scope_id):
    from .mode_runtime import _open_scope_lock

    descriptor = _open_scope_lock(pack_id, scope_id)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ExternalModeTransitionError("PRIVACY_TRANSITION_IN_PROGRESS") from None
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
