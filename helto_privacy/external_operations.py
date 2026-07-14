"""Durable coordination for exact browser-owned protected operations."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import inspect
import json
import re
import secrets
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Mapping

from ._plaintext import clear_mutable_plaintext
from .external_operation_state import (
    EXTERNAL_OPERATION_MAX_ACTIVE_GLOBAL,
    EXTERNAL_OPERATION_MAX_ACTIVE_PER_PACK,
    EXTERNAL_OPERATION_TERMINAL_PHASES,
    ExternalOperationRecord,
    ExternalOperationStateError,
    commit_external_operation_state,
    delete_external_operation_journal_revision,
    exclusive_external_operation_state,
    load_external_operation_journal,
    load_external_operation_state,
    publish_external_operation_journal,
)
from .guard import AuthorizedPrivacyRequest, PrivacyAuthorizationError, require_current_authorization
from .keystore import primary_session_key, session_key_for, unlocked_session_key_ids
from .opaque_references import ProtectedOperationAdapterResult
from .profile import ExternalOperationBinding
from .protected_operations import (
    ProtectedOperationDispatchResult,
    _json_mapping,
    _safe_diagnostic_projection,
    project_safe_payload,
)


_REQUEST_ID = re.compile(r"^hp-operation-request-[A-Za-z0-9_-]{24,64}$")
_TRANSACTION_ID = re.compile(r"^hp-operation-[A-Za-z0-9_-]{32}$")
_RESUME_CAPABILITY = re.compile(
    r"^hp-operation-resume-[A-Za-z0-9_-]{43}$"
)
_MAX_CONTEXT_BYTES = 8 * 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_ITEMS = 65_536


class ExternalOperationError(RuntimeError):
    """Product-data-free failure for the exact external-operation protocol."""

    _CODES = frozenset(
        {
            "PRIVACY_EXTERNAL_OPERATION_ACTIVE",
            "PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID",
            "PRIVACY_EXTERNAL_OPERATION_FENCED",
            "PRIVACY_EXTERNAL_OPERATION_INVALID",
            "PRIVACY_EXTERNAL_OPERATION_NOT_FOUND",
            "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED",
            "PRIVACY_EXTERNAL_OPERATION_ROLLBACK_REQUIRED",
            "PRIVACY_EXTERNAL_OPERATION_STATE_FAILED",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in self._CODES
            else "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED"
        )
        super().__init__("External protected operation could not complete safely.")


class ExternalOperationDisposition(str, Enum):
    ABSENT = "absent"
    PREPARED = "prepared"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled-back"


@dataclass(frozen=True, slots=True)
class ExternalOperationInvocation:
    """Public opaque identity for one exact durable external transaction."""

    transaction_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.transaction_id, str)
            or _TRANSACTION_ID.fullmatch(self.transaction_id) is None
        ):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")


@dataclass(frozen=True, slots=True)
class ExternalOperationCapture:
    """Pure adapter capture persisted before product mutation begins."""

    context: object = field(repr=False, compare=False)
    browser_value: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ExternalOperationClassification:
    """Restart classification of product state for one captured plan."""

    disposition: ExternalOperationDisposition
    context: object | None = field(default=None, repr=False, compare=False)
    result: ProtectedOperationAdapterResult | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, ExternalOperationDisposition):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
        if self.disposition is ExternalOperationDisposition.ABSENT and (
            self.context is not None or self.result is not None
        ):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
        if self.disposition is ExternalOperationDisposition.PREPARED and (
            self.context is None or self.result is not None
        ):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
        if self.disposition is ExternalOperationDisposition.COMPLETED and not isinstance(
            self.result,
            ProtectedOperationAdapterResult,
        ):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
        if self.disposition is ExternalOperationDisposition.ROLLED_BACK and (
            self.context is not None or self.result is not None
        ):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")


async def prepare_external_operation(
    installation,
    operation_id: str,
    authorization: AuthorizedPrivacyRequest,
    *,
    request_id: object,
    owner_identity: object,
    original_exact: object,
    input_value: object,
    references: object,
) -> dict[str, object]:
    """Capture and prepare one idempotent exact browser operation."""

    declaration, binding, adapter = _binding(installation, operation_id)
    _authorize(authorization, declaration.id, installation.profile.id)
    request_id = _request_id(request_id)
    identity = _owner_identity(owner_identity, binding)
    original = _exact_bytes(original_exact, binding.policy.max_original_bytes)
    reference_ids = _reference_ids(declaration, references)
    (
        request_digest,
        owner_digest,
        request_digest_candidates,
        owner_digest_candidates,
    ) = _request_digests(
        installation.profile.id,
        declaration.id,
        request_id,
        identity,
        original,
        input_value,
        reference_ids,
    )
    admission = _acquire_admission(installation, declaration.scope_id)
    resolved = None
    captured = None
    claims_retained = False
    try:
        with exclusive_external_operation_state():
            revision, records = load_external_operation_state()
            existing = next(
                (
                    record
                    for record in records
                    if record.pack_id == installation.profile.id
                    and record.operation_id == declaration.id
                    and any(
                        hmac.compare_digest(record.request_digest, candidate)
                        for candidate in request_digest_candidates
                    )
                ),
                None,
            )
            if existing is not None:
                journal = load_external_operation_journal(existing)
                if not hmac.compare_digest(
                    str(journal.get("requestId") or ""),
                    request_id,
                ) or not any(
                    hmac.compare_digest(existing.owner_digest, candidate)
                    for candidate in owner_digest_candidates
                ):
                    raise ExternalOperationError(
                        "PRIVACY_EXTERNAL_OPERATION_FENCED"
                    )
                existing, journal, revision, records = await _recover_locked(
                    installation,
                    declaration,
                    binding,
                    adapter,
                    authorization,
                    existing,
                    journal,
                    revision,
                    records,
                )
                return _private_response(existing, journal, include_resume=True)

            active = tuple(record for record in records if record.active)
            if (
                sum(record.pack_id == installation.profile.id for record in active)
                >= EXTERNAL_OPERATION_MAX_ACTIVE_PER_PACK
                or len(active) >= EXTERNAL_OPERATION_MAX_ACTIVE_GLOBAL
                or any(
                    record.pack_id == installation.profile.id
                    and any(
                        hmac.compare_digest(record.owner_digest, candidate)
                        for candidate in owner_digest_candidates
                    )
                    for record in active
                )
            ):
                raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_ACTIVE")

            from .opaque_references import resolve_operation_references

            transaction_id = _new_transaction_id()
            resolved = resolve_operation_references(
                profile=installation.profile,
                declaration=declaration,
                authorization=authorization,
                references=references,
            )
            captured = await _adapter_phase(
                installation,
                declaration,
                authorization,
                adapter,
                "capture_external_operation",
                copy.deepcopy(input_value),
                resolved,
                transaction_id=transaction_id,
            )
            if not isinstance(captured, ExternalOperationCapture):
                raise ExternalOperationError(
                    "PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID"
                )
            context = _bounded_json(captured.context, _MAX_CONTEXT_BYTES)
            browser_value = _bounded_json(
                captured.browser_value,
                binding.policy.max_target_bytes,
            )
            from .opaque_references import retain_external_operation_claims

            reference_claims = retain_external_operation_claims(
                declaration,
                resolved,
                lease_seconds=binding.policy.lease_seconds,
            )
            resume_capability = "hp-operation-resume-" + secrets.token_urlsafe(32)
            now_ns = time.time_ns()
            expires_at_ns = now_ns + binding.policy.lease_seconds * 1_000_000_000
            journal = {
                "packId": installation.profile.id,
                "profileFingerprint": installation.profile.fingerprint,
                "scopeId": declaration.scope_id,
                "operationId": declaration.id,
                "transactionId": transaction_id,
                "requestId": request_id,
                "requestDigest": request_digest,
                "ownerDigest": owner_digest,
                "ownerIdentity": identity,
                "resumeCapability": resume_capability,
                "phase": "captured",
                "originalExact": _b64(original),
                "targetExact": None,
                "captureContext": context,
                "preparedContext": None,
                "browserValue": browser_value,
                "referenceIds": list(reference_ids),
                "referenceClaims": reference_claims,
                "createdAtNs": now_ns,
                "expiresAtNs": expires_at_ns,
            }
            journal_digest = publish_external_operation_journal(
                (installation.profile.id, declaration.id, transaction_id),
                journal,
            )
            record = ExternalOperationRecord(
                transaction_id,
                installation.profile.id,
                installation.profile.fingerprint,
                declaration.scope_id,
                declaration.id,
                owner_digest,
                request_digest,
                _plain_digest(resume_capability.encode("ascii")),
                "captured",
                journal_digest,
                expires_at_ns,
                now_ns,
            )
            records = (*records, record)
            revision = commit_external_operation_state(
                records,
                expected_revision=revision,
            )
            claims_retained = True
            try:
                record, journal, revision, records = await _prepare_locked(
                    installation,
                    declaration,
                    binding,
                    adapter,
                    authorization,
                    record,
                    journal,
                    revision,
                    records,
                )
            except BaseException:
                # Preparation may have changed the product before its adapter
                # failed.  Persist the uncertainty before control can leave
                # this request so a retry can only recover or roll back.
                if record.active:
                    rollback_journal = {**journal, "phase": "rollback-required"}
                    try:
                        record, revision, records = _persist_locked(
                            record,
                            rollback_journal,
                            revision,
                            records,
                            phase="rollback-required",
                        )
                        journal = rollback_journal
                    except Exception:
                        # The already committed captured revision remains a
                        # valid recovery point if advancing the index fails.
                        pass
                raise
            return _private_response(record, journal, include_resume=True)
    except (ExternalOperationError, PrivacyAuthorizationError):
        raise
    except ExternalOperationStateError:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED") from None
    finally:
        from .opaque_references import release_resolved_claims

        if not claims_retained:
            release_resolved_claims(resolved)
        clear_mutable_plaintext(captured)
        clear_mutable_plaintext(resolved)
        clear_mutable_plaintext(input_value)
        _release_admission(admission)


async def apply_external_operation(
    installation,
    operation_id: str,
    transaction_id: object,
    authorization: AuthorizedPrivacyRequest,
    *,
    resume_capability: object,
    current_exact: object,
) -> dict[str, object]:
    declaration, binding, adapter = _binding(installation, operation_id)
    _authorize(authorization, declaration.id, installation.profile.id)
    transaction_id = _transaction_id(transaction_id)
    resume_capability = _resume_capability(resume_capability)
    current = _exact_bytes(current_exact, binding.policy.max_target_bytes)
    admission = _acquire_admission(installation, declaration.scope_id)
    try:
        with exclusive_external_operation_state():
            revision, records = load_external_operation_state()
            record = _record(records, installation, declaration, transaction_id)
            journal = load_external_operation_journal(record)
            _require_resume(record, resume_capability)
            if record.phase in EXTERNAL_OPERATION_TERMINAL_PHASES:
                return _private_response(record, journal)
            if record.phase not in {"prepared", "applied"}:
                raise ExternalOperationError(
                    "PRIVACY_EXTERNAL_OPERATION_ROLLBACK_REQUIRED"
                )
            if record.phase == "prepared":
                journal = {**journal, "phase": "applied", "targetExact": _b64(current)}
                record, revision, records = _persist_locked(
                    record,
                    journal,
                    revision,
                    records,
                    phase="applied",
                )
            elif not hmac.compare_digest(
                _unb64(str(journal.get("targetExact") or "")),
                current,
            ):
                raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_FENCED")
            try:
                record, journal, revision, records = await _finalize_locked(
                    installation,
                    declaration,
                    adapter,
                    authorization,
                    record,
                    journal,
                    revision,
                    records,
                )
            except BaseException:
                if record.active:
                    rollback_journal = {**journal, "phase": "rollback-required"}
                    try:
                        _persist_locked(
                            record,
                            rollback_journal,
                            revision,
                            records,
                            phase="rollback-required",
                        )
                    except Exception:
                        pass
                raise
            return _private_response(record, journal)
    except (ExternalOperationError, PrivacyAuthorizationError):
        raise
    except ExternalOperationStateError:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED") from None
    finally:
        _release_admission(admission)


async def rollback_external_operation(
    installation,
    operation_id: str,
    transaction_id: object,
    authorization: AuthorizedPrivacyRequest,
    *,
    resume_capability: object,
) -> dict[str, object]:
    declaration, _binding_value, adapter = _binding(installation, operation_id)
    _authorize(authorization, declaration.id, installation.profile.id)
    transaction_id = _transaction_id(transaction_id)
    resume_capability = _resume_capability(resume_capability)
    admission = _acquire_admission(installation, declaration.scope_id)
    try:
        with exclusive_external_operation_state():
            revision, records = load_external_operation_state()
            record = _record(records, installation, declaration, transaction_id)
            journal = load_external_operation_journal(record)
            _require_resume(record, resume_capability)
            if record.phase in EXTERNAL_OPERATION_TERMINAL_PHASES:
                return _private_response(record, journal)
            if record.phase != "rollback-required":
                journal = {**journal, "phase": "rollback-required"}
                record, revision, records = _persist_locked(
                    record,
                    journal,
                    revision,
                    records,
                    phase="rollback-required",
                )
            record, journal, _revision, _records = await _rollback_locked(
                installation,
                declaration,
                adapter,
                authorization,
                record,
                journal,
                revision,
                records,
            )
            return _private_response(record, journal)
    except (ExternalOperationError, PrivacyAuthorizationError):
        raise
    except ExternalOperationStateError:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED") from None
    finally:
        _release_admission(admission)


async def resume_external_operation(
    installation,
    operation_id: str,
    transaction_id: object,
    authorization: AuthorizedPrivacyRequest,
    *,
    resume_capability: object,
) -> dict[str, object]:
    declaration, binding, adapter = _binding(installation, operation_id)
    _authorize(authorization, declaration.id, installation.profile.id)
    transaction_id = _transaction_id(transaction_id)
    resume_capability = _resume_capability(resume_capability)
    admission = _acquire_admission(installation, declaration.scope_id)
    try:
        with exclusive_external_operation_state():
            revision, records = load_external_operation_state()
            record = _record(records, installation, declaration, transaction_id)
            journal = load_external_operation_journal(record)
            _require_resume(record, resume_capability)
            record, journal, _revision, _records = await _recover_locked(
                installation,
                declaration,
                binding,
                adapter,
                authorization,
                record,
                journal,
                revision,
                records,
            )
            return _private_response(record, journal)
    except (ExternalOperationError, PrivacyAuthorizationError):
        raise
    except ExternalOperationStateError:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED") from None
    finally:
        _release_admission(admission)


def external_operation_status(
    installation,
    operation_id: str,
    transaction_id: object,
    authorization: AuthorizedPrivacyRequest,
) -> dict[str, object]:
    declaration, _binding_value, _adapter = _binding(installation, operation_id)
    _authorize(authorization, declaration.id, installation.profile.id)
    transaction_id = _transaction_id(transaction_id)
    try:
        _revision, records = load_external_operation_state()
        record = _record(records, installation, declaration, transaction_id)
        return _status_payload(record)
    except ExternalOperationError:
        raise
    except ExternalOperationStateError:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None


async def _recover_locked(
    installation,
    declaration,
    binding,
    adapter,
    authorization,
    record,
    journal,
    revision,
    records,
):
    if record.phase in EXTERNAL_OPERATION_TERMINAL_PHASES:
        return record, journal, revision, records
    if record.expires_at_ns <= time.time_ns() and record.phase != "rollback-required":
        journal = {**journal, "phase": "rollback-required"}
        record, revision, records = _persist_locked(
            record,
            journal,
            revision,
            records,
            phase="rollback-required",
        )
    if record.phase == "captured":
        return await _prepare_locked(
            installation,
            declaration,
            binding,
            adapter,
            authorization,
            record,
            journal,
            revision,
            records,
        )
    if record.phase == "applied":
        try:
            return await _finalize_locked(
                installation,
                declaration,
                adapter,
                authorization,
                record,
                journal,
                revision,
                records,
            )
        except BaseException:
            rollback_journal = {**journal, "phase": "rollback-required"}
            try:
                _persist_locked(
                    record,
                    rollback_journal,
                    revision,
                    records,
                    phase="rollback-required",
                )
            except Exception:
                pass
            raise
    return record, journal, revision, records


async def _prepare_locked(
    installation,
    declaration,
    binding,
    adapter,
    authorization,
    record,
    journal,
    revision,
    records,
):
    classification = await _classify(
        installation,
        declaration,
        adapter,
        authorization,
        journal["captureContext"],
        journal["transactionId"],
    )
    if classification.disposition is ExternalOperationDisposition.ABSENT:
        prepared_context = await _adapter_phase(
            installation,
            declaration,
            authorization,
            adapter,
            "prepare_external_operation",
            copy.deepcopy(journal["captureContext"]),
            transaction_id=journal["transactionId"],
        )
        prepared_context = _bounded_json(prepared_context, _MAX_CONTEXT_BYTES)
    elif classification.disposition is ExternalOperationDisposition.PREPARED:
        prepared_context = _bounded_json(
            classification.context,
            _MAX_CONTEXT_BYTES,
        )
    elif classification.disposition is ExternalOperationDisposition.ROLLED_BACK:
        _settle_reference_claims(
            installation,
            declaration,
            authorization,
            journal,
            completed=False,
        )
        return _terminalize_locked(
            record,
            journal,
            revision,
            records,
            disposition="rolled-back",
            result=None,
        )
    else:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED")
    journal = {
        **journal,
        "phase": "prepared",
        "preparedContext": prepared_context,
    }
    record, revision, records = _persist_locked(
        record,
        journal,
        revision,
        records,
        phase="prepared",
    )
    return record, journal, revision, records


async def _finalize_locked(
    installation,
    declaration,
    adapter,
    authorization,
    record,
    journal,
    revision,
    records,
):
    classification = await _classify(
        installation,
        declaration,
        adapter,
        authorization,
        journal["captureContext"],
        journal["transactionId"],
    )
    if classification.disposition is ExternalOperationDisposition.COMPLETED:
        adapter_result = classification.result
    elif classification.disposition is ExternalOperationDisposition.PREPARED:
        adapter_result = await _adapter_phase(
            installation,
            declaration,
            authorization,
            adapter,
            "finalize_external_operation",
            copy.deepcopy(
                journal.get("preparedContext") or classification.context
            ),
            transaction_id=journal["transactionId"],
        )
    else:
        raise ExternalOperationError(
            "PRIVACY_EXTERNAL_OPERATION_ROLLBACK_REQUIRED"
        )
    if not isinstance(adapter_result, ProtectedOperationAdapterResult):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID")
    result = _wire_result(installation, declaration, adapter, adapter_result)
    _settle_reference_claims(
        installation,
        declaration,
        authorization,
        journal,
        completed=True,
    )
    return _terminalize_locked(
        record,
        journal,
        revision,
        records,
        disposition="completed",
        result=result,
    )


async def _rollback_locked(
    installation,
    declaration,
    adapter,
    authorization,
    record,
    journal,
    revision,
    records,
):
    classification = await _classify(
        installation,
        declaration,
        adapter,
        authorization,
        journal["captureContext"],
        journal["transactionId"],
    )
    if classification.disposition is ExternalOperationDisposition.COMPLETED:
        result = _wire_result(
            installation,
            declaration,
            adapter,
            classification.result,
        )
        _settle_reference_claims(
            installation,
            declaration,
            authorization,
            journal,
            completed=True,
        )
        return _terminalize_locked(
            record,
            journal,
            revision,
            records,
            disposition="completed",
            result=result,
        )
    if classification.disposition in {
        ExternalOperationDisposition.ABSENT,
        ExternalOperationDisposition.PREPARED,
    }:
        rollback_context = (
            journal.get("preparedContext") or classification.context
            if classification.disposition is ExternalOperationDisposition.PREPARED
            else journal["captureContext"]
        )
        rolled_back = await _adapter_phase(
            installation,
            declaration,
            authorization,
            adapter,
            "rollback_external_operation",
            copy.deepcopy(rollback_context),
            transaction_id=journal["transactionId"],
        )
        if rolled_back is not True:
            raise ExternalOperationError(
                "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED"
            )
        classification = await _classify(
            installation,
            declaration,
            adapter,
            authorization,
            journal["captureContext"],
            journal["transactionId"],
        )
    if classification.disposition not in {
        ExternalOperationDisposition.ABSENT,
        ExternalOperationDisposition.ROLLED_BACK,
    }:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED")
    _settle_reference_claims(
        installation,
        declaration,
        authorization,
        journal,
        completed=False,
    )
    return _terminalize_locked(
        record,
        journal,
        revision,
        records,
        disposition="rolled-back",
        result=None,
    )


async def _classify(
    installation,
    declaration,
    adapter,
    authorization,
    capture_context,
    transaction_id,
) -> ExternalOperationClassification:
    result = await _adapter_phase(
        installation,
        declaration,
        authorization,
        adapter,
        "classify_external_operation",
        copy.deepcopy(capture_context),
        transaction_id=transaction_id,
    )
    if not isinstance(result, ExternalOperationClassification):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID")
    return result


def _settle_reference_claims(
    installation,
    declaration,
    authorization,
    journal,
    *,
    completed: bool,
) -> None:
    from .opaque_references import settle_external_operation_claims

    try:
        settle_external_operation_claims(
            profile=installation.profile,
            declaration=declaration,
            authorization=authorization,
            claims=journal.get("referenceClaims"),
            completed=completed,
        )
    except Exception:
        raise ExternalOperationError(
            "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED"
        ) from None


async def _adapter_phase(
    installation,
    declaration,
    authorization,
    adapter,
    method_name: str,
    *arguments,
    transaction_id: str,
):
    method = getattr(adapter, method_name, None)
    if not callable(method):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID")
    dependencies = None
    try:
        from .operation_dependencies import build_operation_dependencies

        dependencies = build_operation_dependencies(
            installation,
            declaration,
            authorization,
        )
        candidate = method(
            *arguments,
            ExternalOperationInvocation(_transaction_id(transaction_id)),
            declaration,
            dependencies,
        )
        return await candidate if inspect.isawaitable(candidate) else candidate
    finally:
        if dependencies is not None:
            from .operation_dependencies import expire_operation_dependencies

            expire_operation_dependencies(dependencies)


def _wire_result(installation, declaration, adapter, adapter_result):
    try:
        if adapter_result.references:
            raise ExternalOperationError(
                "PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID"
            )
        from .mode import EffectivePrivacyMode
        from .mode_runtime import resolve_bound_mode

        scope = next(
            item
            for item in installation.profile.scopes
            if item.id == declaration.scope_id
        )
        effective = resolve_bound_mode(
            installation,
            scope.mode_resource_id,
            scope.id,
            None,
        ).effective
        if effective is EffectivePrivacyMode.PUBLIC:
            data = _json_mapping(adapter_result.payload)
            private = False
        else:
            project = getattr(adapter, "project", None)
            if not callable(project):
                raise ExternalOperationError(
                    "PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID"
                )
            data = _safe_diagnostic_projection(
                project(adapter_result.payload, declaration),
                declaration.safe_projection,
            )
            private = True
        safe_payload = project_safe_payload(
            profile=installation.profile,
            declaration=declaration,
            adapter=adapter,
            value=adapter_result.safe_payload,
        )
        return ProtectedOperationDispatchResult(
            data,
            safe_payload,
            (),
            private,
            "hp-operation-" + secrets.token_urlsafe(12),
        ).to_payload()
    except ExternalOperationError:
        raise
    except Exception:
        raise ExternalOperationError(
            "PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID"
        ) from None
    finally:
        clear_mutable_plaintext(adapter_result)


def _terminalize_locked(
    record,
    journal,
    revision,
    records,
    *,
    disposition,
    result,
):
    exact = (
        journal.get("targetExact")
        if disposition == "completed"
        else journal.get("originalExact")
    )
    if not isinstance(exact, str):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED")
    terminal = {
        "packId": record.pack_id,
        "profileFingerprint": record.profile_fingerprint,
        "scopeId": record.scope_id,
        "operationId": record.operation_id,
        "transactionId": record.transaction_id,
        "requestId": journal["requestId"],
        "requestDigest": record.request_digest,
        "ownerDigest": record.owner_digest,
        "ownerIdentity": journal["ownerIdentity"],
        "phase": disposition,
        "exact": exact,
        "result": result,
        "terminalAtNs": time.time_ns(),
    }
    receipt_digest = _keyed_digest(
        b"receipt\0",
        _canonical_json(
            {
                "transactionId": record.transaction_id,
                "disposition": disposition,
                "exact": exact,
                "result": result,
            }
        ),
    )
    updated, next_revision, updated_records = _persist_locked(
        record,
        terminal,
        revision,
        records,
        phase=disposition,
        receipt_digest=receipt_digest,
    )
    return updated, terminal, next_revision, updated_records


def _persist_locked(
    record,
    journal,
    revision,
    records,
    *,
    phase,
    receipt_digest=None,
):
    old_digest = record.journal_digest
    journal_digest = publish_external_operation_journal(
        (record.pack_id, record.operation_id, record.transaction_id),
        journal,
    )
    updated = replace(
        record,
        phase=phase,
        journal_digest=journal_digest,
        expires_at_ns=0 if phase in EXTERNAL_OPERATION_TERMINAL_PHASES else record.expires_at_ns,
        updated_at_ns=time.time_ns(),
        receipt_digest=receipt_digest,
    )
    updated_records = tuple(
        updated if item.transaction_id == record.transaction_id else item
        for item in records
    )
    next_revision = commit_external_operation_state(
        updated_records,
        expected_revision=revision,
    )
    try:
        delete_external_operation_journal_revision(record, old_digest)
    except ExternalOperationStateError:
        pass
    return updated, next_revision, updated_records


def _private_response(
    record: ExternalOperationRecord,
    journal: Mapping[str, object],
    *,
    include_resume: bool = False,
) -> dict[str, object]:
    payload = _status_payload(record)
    if record.phase in EXTERNAL_OPERATION_TERMINAL_PHASES:
        payload.update(
            {
                "ownerIdentity": copy.deepcopy(journal.get("ownerIdentity")),
                "exact": journal.get("exact"),
                "result": copy.deepcopy(journal.get("result")),
            }
        )
    else:
        payload.update(
            {
                "ownerIdentity": copy.deepcopy(journal.get("ownerIdentity")),
                "originalExact": journal.get("originalExact"),
                "targetExact": journal.get("targetExact"),
                "browserValue": copy.deepcopy(journal.get("browserValue")),
            }
        )
        if include_resume:
            payload["resumeCapability"] = journal.get("resumeCapability")
    return payload


def _status_payload(record: ExternalOperationRecord) -> dict[str, object]:
    return {
        "transactionId": record.transaction_id,
        "operationId": record.operation_id,
        "phase": record.phase,
        "active": record.active,
        "expiresInSeconds": (
            max(0, (record.expires_at_ns - time.time_ns()) // 1_000_000_000)
            if record.active
            else 0
        ),
        "receiptId": (
            None
            if record.receipt_digest is None
            else "hp-operation-receipt-" + record.receipt_digest[:32]
        ),
    }


def _binding(installation, operation_id):
    declaration = next(
        (
            item
            for item in installation.profile.protected_operations
            if item.id == operation_id
            and isinstance(item.external_operation_binding, ExternalOperationBinding)
        ),
        None,
    )
    if declaration is None or declaration.scope_id is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    adapter = installation.adapters.get(declaration.adapter_slot)
    if adapter is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID")
    return declaration, declaration.external_operation_binding, adapter


def _record(records, installation, declaration, transaction_id):
    result = next(
        (
            item
            for item in records
            if item.transaction_id == transaction_id
            and item.pack_id == installation.profile.id
            and item.profile_fingerprint == installation.profile.fingerprint
            and item.operation_id == declaration.id
            and item.scope_id == declaration.scope_id
        ),
        None,
    )
    if result is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_NOT_FOUND")
    return result


def _authorize(authorization, operation_id, pack_id):
    try:
        require_current_authorization(
            authorization,
            operation_id,
            pack_id=pack_id,
        )
    except PrivacyAuthorizationError:
        raise
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_FENCED") from None


def _request_digests(
    pack_id,
    operation_id,
    request_id,
    owner_identity,
    original_exact,
    input_value,
    reference_ids,
):
    try:
        primary_key, _primary_key_id = primary_session_key()
        owner = _canonical_json(owner_identity)
        request = _canonical_json(
            {
                "packId": pack_id,
                "operationId": operation_id,
                "requestId": request_id,
                "ownerIdentity": owner_identity,
                "originalExact": _b64(original_exact),
                "input": _bounded_json(input_value, _MAX_CONTEXT_BYTES),
                "referenceIds": list(reference_ids),
            }
        )
        keys = [
            key
            for key_id in unlocked_session_key_ids()
            if (key := session_key_for(key_id)) is not None
        ]
        if not any(hmac.compare_digest(key, primary_key) for key in keys):
            keys.append(primary_key)
        request_candidates = tuple(
            hmac.new(key, b"request\0" + request, hashlib.sha256).hexdigest()
            for key in keys
        )
        owner_candidates = tuple(
            hmac.new(key, b"owner\0" + owner, hashlib.sha256).hexdigest()
            for key in keys
        )
        return (
            hmac.new(
                primary_key,
                b"request\0" + request,
                hashlib.sha256,
            ).hexdigest(),
            hmac.new(
                primary_key,
                b"owner\0" + owner,
                hashlib.sha256,
            ).hexdigest(),
            request_candidates,
            owner_candidates,
        )
    except ExternalOperationError:
        raise
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID") from None


def _reference_ids(declaration, references) -> tuple[str, ...]:
    if type(references) is not dict:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    expected = tuple(sorted(item.name for item in declaration.reference_inputs))
    if tuple(sorted(references)) != expected:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    values = tuple(references[name] for name in expected)
    if any(
        not isinstance(value, str)
        or re.fullmatch(r"hp-ref-[A-Za-z0-9_-]{32}", value) is None
        for value in values
    ):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    return tuple(values)


def _owner_identity(value: object, binding: ExternalOperationBinding) -> dict[str, str]:
    expected = {"rootGraphId", "graphId", "nodeId", "fieldId"}
    if type(value) is not dict or set(value) != expected:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    normalized = {key: value[key] for key in sorted(expected)}
    if (
        any(
            not isinstance(item, str)
            or re.fullmatch(r"[A-Za-z0-9._~:-]{1,128}", item) is None
            for item in normalized.values()
        )
        or normalized["rootGraphId"] != "root"
        or normalized["fieldId"] != binding.field_id
        or len(_canonical_json(normalized)) > binding.policy.max_identity_bytes
    ):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    return normalized


def _bounded_json(value: object, maximum_bytes: int) -> object:
    items = 0

    def visit(candidate: object, depth: int) -> object:
        nonlocal items
        items += 1
        if depth > _MAX_JSON_DEPTH or items > _MAX_JSON_ITEMS:
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
        if candidate is None or type(candidate) in {bool, int, str}:
            if type(candidate) is int and candidate.bit_length() > 4096:
                raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
            return candidate
        if type(candidate) is float:
            if candidate != candidate or candidate in {float("inf"), float("-inf")}:
                raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
            return candidate
        if type(candidate) is list:
            return [visit(item, depth + 1) for item in candidate]
        if type(candidate) is dict and all(type(key) is str for key in candidate):
            return {
                key: visit(candidate[key], depth + 1)
                for key in sorted(candidate)
            }
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")

    normalized = visit(value, 0)
    if len(_canonical_json(normalized)) > maximum_bytes:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    return normalized


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID") from None


def _exact_bytes(value: object, maximum: int) -> bytes:
    if type(value) not in {bytes, bytearray}:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    result = bytes(value)
    if len(result) > maximum:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    return result


def _request_id(value: object) -> str:
    if not isinstance(value, str) or _REQUEST_ID.fullmatch(value) is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    return value


def _transaction_id(value: object) -> str:
    if not isinstance(value, str) or _TRANSACTION_ID.fullmatch(value) is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_INVALID")
    return value


def _resume_capability(value: object) -> str:
    if not isinstance(value, str) or _RESUME_CAPABILITY.fullmatch(value) is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_FENCED")
    return value


def _require_resume(record, resume_capability):
    if not hmac.compare_digest(
        record.resume_digest,
        _plain_digest(resume_capability.encode("ascii")),
    ):
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_FENCED")


def _new_transaction_id() -> str:
    value = "hp-operation-" + secrets.token_urlsafe(24)
    if _TRANSACTION_ID.fullmatch(value) is None:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED")
    return value


def _plain_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _keyed_digest(domain: bytes, value: bytes) -> str:
    try:
        key, _key_id = primary_session_key()
        return hmac.new(key, domain + value, hashlib.sha256).hexdigest()
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None


def _acquire_admission(installation, scope_id):
    try:
        from .mode_runtime import acquire_bound_mode_work_admission

        return acquire_bound_mode_work_admission(installation, (scope_id,))
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_ACTIVE") from None


def _release_admission(value):
    if value is None:
        return
    try:
        from .mode_runtime import release_bound_mode_work_admission

        release_bound_mode_work_admission(value)
    except Exception:
        raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_STATE_FAILED") from None


__all__ = [
    "ExternalOperationCapture",
    "ExternalOperationClassification",
    "ExternalOperationDisposition",
    "ExternalOperationError",
    "apply_external_operation",
    "external_operation_status",
    "prepare_external_operation",
    "resume_external_operation",
    "rollback_external_operation",
]
