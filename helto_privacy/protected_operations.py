"""Shared protected-operation lifecycle for authorized workflow reveals."""

from __future__ import annotations

import copy
import inspect
import json
import math
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field

from ._plaintext import clear_mutable_plaintext
from .mode import EffectivePrivacyMode
from .profile import SafeDiagnosticKind, SafePayloadKind


_PROJECTION_ERROR_CODES = frozenset(
    {
        "PRIVACY_PROTECTED_OPERATION_ADAPTER_INVALID",
        "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID",
        "PRIVACY_PROTECTED_OPERATION_DEPENDENCY_UNAVAILABLE",
        "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED",
        "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID",
        "PRIVACY_PROTECTED_OPERATION_REFERENCE_UNAVAILABLE",
        "PRIVACY_PROTECTED_OPERATION_RESULT_INVALID",
    }
)
_PROJECTION_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SAFE_PAYLOAD_MAX_BYTES = 64 * 1024
SAFE_PAYLOAD_MAX_DEPTH = 8
SAFE_PAYLOAD_MAX_COUNT = 2_147_483_647
SAFE_PAYLOAD_MAX_NUMBER = 1_000_000_000_000_000.0
SAFE_PAYLOAD_MAX_TEXT_CHARS = 256
SAFE_PAYLOAD_MAX_TEXT_BYTES = 512
_SAFE_TEXT_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_SAFE_TEXT_DRIVE = re.compile(r"^[A-Za-z]:")


class ProtectedOperationError(RuntimeError):
    """Product-data-free protected-operation projection failure."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in _PROJECTION_ERROR_CODES
            else "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED"
        )
        self.correlation_id = "hp-operation-" + secrets.token_urlsafe(12)
        super().__init__("Protected privacy operation could not complete.")


@dataclass(frozen=True, slots=True)
class ProtectedOperationProjection:
    """Server-mode-resolved public or coarse private operation output."""

    value: dict[str, object] = field(repr=False)
    private: bool


@dataclass(frozen=True, slots=True)
class ProtectedOperationDispatchResult:
    data: dict[str, object] = field(repr=False)
    safe_payload: dict[str, object] | None = field(repr=False)
    references: tuple[dict[str, str], ...] = field(repr=False)
    private: bool
    correlation_id: str
    lease: object | None = field(default=None, repr=False, compare=False)

    @property
    def payload(self) -> dict[str, object]:
        """Backward-compatible in-process alias; the wire channel is ``data``."""

        return copy.deepcopy(self.data)

    def to_payload(self) -> dict[str, object]:
        return {
            "ok": True,
            "data": copy.deepcopy(self.data),
            "safePayload": copy.deepcopy(self.safe_payload),
            "references": [dict(item) for item in self.references],
            "lease": (
                None
                if self.lease is None
                else self.lease.to_payload()
            ),
            "association": None,
            "private": self.private,
            "correlationId": self.correlation_id,
        }


def protected_operation_response_payload(
    result: ProtectedOperationDispatchResult,
) -> dict[str, object]:
    if not isinstance(result, ProtectedOperationDispatchResult):
        raise ProtectedOperationError("PRIVACY_PROTECTED_OPERATION_RESULT_INVALID")
    return result.to_payload()


def protected_operation_error_payload(error: ProtectedOperationError) -> dict[str, object]:
    if not isinstance(error, ProtectedOperationError):
        error = ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED"
        )
    return {
        "ok": False,
        "error": error.code,
        "correlationId": error.correlation_id,
    }


@dataclass(frozen=True, slots=True)
class WorkflowRevealOperationContext:
    authorization: object
    reveal_authorization: object
    workflow: object


class WorkflowRevealOperations:
    """Dispatch one protected product operation with narrow reveal authority."""

    def __init__(
        self,
        authorization: object,
        workflow: object,
        adapter: object,
        *,
        scope_id: str,
        operation_id: str,
    ) -> None:
        if not scope_id or not operation_id:
            raise ValueError("Protected workflow operation identity is required.")
        self._authorization = authorization
        self._workflow = workflow
        self._adapter = adapter
        self._scope_id = scope_id
        self._operation_id = operation_id

    async def dispatch(self, request: object, payload: object) -> object:
        async def invoke(authorization: object) -> object:
            reveal_authorization = self._authorization.authorize_request(
                request,
                "snapshot.reveal",
            )
            result = self._adapter.invoke(
                payload,
                WorkflowRevealOperationContext(
                    authorization,
                    reveal_authorization,
                    self._workflow,
                ),
            )
            return await result if inspect.isawaitable(result) else result

        return await self._authorization.dispatch(
            request,
            self._scope_id,
            self._operation_id,
            invoke,
        )


async def dispatch_protected_operation(
    *,
    installation,
    profile,
    adapters: Mapping[str, object],
    resource_id: str,
    request: object,
    operation_id: str,
    input_value: object,
    references: object,
) -> ProtectedOperationDispatchResult:
    """Authorize, resolve, invoke, project, and revoke one typed operation."""

    declaration = next(
        (
            item
            for item in profile.protected_operations
            if item.id == operation_id and item.resource_id == resource_id
        ),
        None,
    )
    if (
        declaration is None
        or declaration.scope_id is None
        or declaration.external_operation_binding is not None
    ):
        raise ProtectedOperationError("PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID")
    adapter = adapters.get(declaration.adapter_slot)
    has_dependencies = bool(
        declaration.record_dependencies
        or declaration.singleton_dependencies
        or declaration.artifact_dependencies
    )
    invoke = getattr(
        adapter,
        "invoke_with_dependencies" if has_dependencies else "invoke",
        None,
    )
    if not callable(invoke):
        raise ProtectedOperationError("PRIVACY_PROTECTED_OPERATION_ADAPTER_INVALID")

    from .guard import PrivacyAuthorizationError, authorize_privacy_request
    from .mode_runtime import require_stable_bound_scope, resolve_bound_mode
    from .opaque_references import (
        OpaqueReferenceError,
        ProtectedOperationAdapterResult,
        issue_operation_references,
        release_operation_reference_capacity,
        release_resolved_claims,
        reserve_operation_reference_capacity,
        resolve_operation_references,
        revoke_resolved_on_success,
    )

    def require_stable(_authorization) -> None:
        require_stable_bound_scope(installation, declaration.scope_id)

    async def authorized(authorization):
        resolved = None
        adapter_result = None
        dependencies = None
        reservation = None
        succeeded = False
        try:
            reservation = reserve_operation_reference_capacity(
                sum(item.maximum for item in declaration.reference_outputs)
            )
            resolved = resolve_operation_references(
                profile=profile,
                declaration=declaration,
                authorization=authorization,
                references=references,
            )
            if has_dependencies:
                from .operation_dependencies import build_operation_dependencies

                dependencies = build_operation_dependencies(
                    installation,
                    declaration,
                    authorization,
                )
                try:
                    candidate = invoke(
                        copy.deepcopy(input_value),
                        resolved,
                        declaration,
                        dependencies,
                    )
                    adapter_result = (
                        await candidate if inspect.isawaitable(candidate) else candidate
                    )
                finally:
                    from .operation_dependencies import expire_operation_dependencies

                    expire_operation_dependencies(dependencies)
            else:
                candidate = invoke(copy.deepcopy(input_value), resolved, declaration)
                adapter_result = (
                    await candidate if inspect.isawaitable(candidate) else candidate
                )
            if not isinstance(adapter_result, ProtectedOperationAdapterResult):
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_RESULT_INVALID"
                )
            from .artifacts import ArtifactLease

            operation_lease = adapter_result.lease
            expects_adapter_lease = bool(
                declaration.returns_lease and declaration.artifact_dependencies
            )
            if expects_adapter_lease:
                if not isinstance(operation_lease, ArtifactLease):
                    raise ProtectedOperationError(
                        "PRIVACY_PROTECTED_OPERATION_RESULT_INVALID"
                    )
            elif operation_lease is not None:
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_RESULT_INVALID"
                )
            scope = next(item for item in profile.scopes if item.id == declaration.scope_id)
            effective = resolve_bound_mode(
                installation,
                scope.mode_resource_id,
                scope.id,
                None,
            ).effective
            if effective is EffectivePrivacyMode.PUBLIC:
                payload = _json_mapping(adapter_result.payload)
                private = False
            else:
                project = getattr(adapter, "project", None)
                if not callable(project):
                    raise ProtectedOperationError(
                        "PRIVACY_PROTECTED_OPERATION_ADAPTER_INVALID"
                    )
                projected = project(adapter_result.payload, declaration)
                payload = _safe_diagnostic_projection(
                    projected,
                    declaration.safe_projection,
                )
                private = True
            safe_payload = project_safe_payload(
                profile=profile,
                declaration=declaration,
                adapter=adapter,
                value=adapter_result.safe_payload,
            )
            shells = issue_operation_references(
                profile=profile,
                declaration=declaration,
                authorization=authorization,
                candidates=adapter_result.references,
                reservation=reservation,
            )
            reservation = None
            revoke_resolved_on_success(declaration, resolved)
            succeeded = True
            return ProtectedOperationDispatchResult(
                payload,
                safe_payload,
                shells,
                private,
                "hp-operation-" + secrets.token_urlsafe(12),
                operation_lease,
            )
        except OpaqueReferenceError:
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_REFERENCE_UNAVAILABLE"
            ) from None
        finally:
            release_operation_reference_capacity(reservation)
            if not succeeded:
                release_resolved_claims(resolved)
            clear_mutable_plaintext(adapter_result)
            clear_mutable_plaintext(resolved)

    try:
        authorization = authorize_privacy_request(
            request,
            declaration.id,
            pack_id=profile.id,
        )
        require_stable(authorization)
        return await authorized(authorization)
    except (ProtectedOperationError, PrivacyAuthorizationError):
        raise
    except Exception:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED"
        ) from None
    finally:
        clear_mutable_plaintext(input_value)


def project_protected_operation(
    *,
    installation,
    profile,
    adapters: Mapping[str, object],
    resource_id: str,
    operation_id: str,
    value: object,
    subject_mode=None,
) -> ProtectedOperationProjection:
    """Resolve server mode and release only a validated private projection."""

    declaration = next(
        (
            operation
            for operation in profile.protected_operations
            if operation.resource_id == resource_id and operation.id == operation_id
        ),
        None,
    )
    if declaration is None or declaration.scope_id is None:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID"
        )
    from .mode_runtime import require_stable_bound_scope, resolve_bound_mode

    scope = next(
        (item for item in profile.scopes if item.id == declaration.scope_id),
        None,
    )
    if scope is None:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID"
        )
    require_stable_bound_scope(installation, scope.id)
    source = copy.deepcopy(value)
    candidate: object = None
    try:
        if declaration.subject_mode_binding_id is not None:
            from .subject_mode import SubjectModeLease

            if not isinstance(subject_mode, SubjectModeLease):
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID"
                )
            try:
                effective = subject_mode._effective_for(
                    profile=profile,
                    binding_id=declaration.subject_mode_binding_id,
                    operation_id=operation_id,
                )
            except Exception:
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID"
                ) from None
        else:
            if subject_mode is not None:
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID"
                )
            resolution = resolve_bound_mode(
                installation,
                scope.mode_resource_id,
                scope.id,
                None,
            )
            effective = resolution.effective
        if effective is EffectivePrivacyMode.PUBLIC:
            return ProtectedOperationProjection(_json_mapping(source), False)
        adapter = adapters.get(declaration.adapter_slot)
        project = getattr(adapter, "project", None)
        if not callable(project):
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_ADAPTER_INVALID"
            )
        try:
            candidate = project(source, declaration)
        except ProtectedOperationError:
            raise
        except Exception:
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED"
            ) from None
        return ProtectedOperationProjection(
            _safe_diagnostic_projection(candidate, declaration.safe_projection),
            True,
        )
    finally:
        clear_mutable_plaintext(candidate)
        clear_mutable_plaintext(source)


def _json_mapping(value: object) -> dict[str, object]:
    try:
        if not isinstance(value, Mapping):
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
            )
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return copy.deepcopy(dict(value))
    except ProtectedOperationError:
        raise
    except Exception:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
        ) from None


def project_safe_payload(
    *,
    profile,
    declaration,
    adapter: object,
    value: object,
) -> dict[str, object] | None:
    """Project and validate the declaration's independent safe JSON channel."""

    projection_id = declaration.safe_payload_projection_id
    if projection_id is None:
        if value is not None:
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_RESULT_INVALID"
            )
        return None
    projection = next(
        (
            item
            for item in profile.safe_payload_projections
            if item.id == projection_id and item.operation_id == declaration.id
        ),
        None,
    )
    projector = getattr(adapter, "project_safe_payload", None)
    if projection is None or not callable(projector):
        raise ProtectedOperationError("PRIVACY_PROTECTED_OPERATION_ADAPTER_INVALID")
    try:
        candidate = projector(copy.deepcopy(value), projection)
    except ProtectedOperationError:
        raise
    except Exception:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED"
        ) from None
    try:
        return _exact_safe_payload(candidate, projection.safe_leaves)
    finally:
        clear_mutable_plaintext(candidate)


def _exact_safe_payload(value: object, safe_leaves) -> dict[str, object]:
    if not isinstance(value, Mapping) or not value:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
        )
    expected = {item.path: item.kind for item in safe_leaves}
    leaves: dict[str, object] = {}

    def visit(current: object, prefix: tuple[str, ...]) -> None:
        if len(prefix) > SAFE_PAYLOAD_MAX_DEPTH:
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
            )
        if isinstance(current, Mapping):
            if not current:
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
                )
            for key, item in current.items():
                if not isinstance(key, str) or _PROJECTION_SEGMENT.fullmatch(key) is None:
                    raise ProtectedOperationError(
                        "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
                    )
                visit(item, (*prefix, key))
            return
        path = ".".join(prefix)
        if path not in expected or path in leaves or not _safe_payload_leaf(
            current,
            expected[path],
        ):
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
            )
        leaves[path] = current

    visit(value, ())
    if frozenset(leaves) != frozenset(expected):
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
        )
    result: dict[str, object] = {}
    for path, item in leaves.items():
        target = result
        segments = path.split(".")
        for segment in segments[:-1]:
            target = target.setdefault(segment, {})  # type: ignore[assignment]
        target[segments[-1]] = item
    try:
        payload = json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
        ) from None
    if len(payload) > SAFE_PAYLOAD_MAX_BYTES:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
        )
    return copy.deepcopy(result)


def _safe_payload_leaf(value: object, kind: SafePayloadKind) -> bool:
    if kind is SafePayloadKind.BOOLEAN:
        return isinstance(value, bool)
    if kind is SafePayloadKind.COUNT:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= SAFE_PAYLOAD_MAX_COUNT
        )
    if kind is SafePayloadKind.NUMBER:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        try:
            number = float(value)
        except (OverflowError, TypeError, ValueError):
            return False
        return math.isfinite(number) and abs(number) <= SAFE_PAYLOAD_MAX_NUMBER
    if kind is SafePayloadKind.SAFE_TEXT:
        return _is_safe_payload_text(value)
    return False


def _is_safe_payload_text(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    if (
        len(value) > SAFE_PAYLOAD_MAX_TEXT_CHARS
        or len(encoded) > SAFE_PAYLOAD_MAX_TEXT_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    lowered = value.lower()
    return not (
        "/" in value
        or "\\" in value
        or ".." in value
        or "://" in value
        or lowered.startswith(("file:", "~", "%2f", "%5c"))
        or "%2f" in lowered
        or "%5c" in lowered
        or _SAFE_TEXT_SCHEME.match(value)
        or _SAFE_TEXT_DRIVE.match(value)
    )


def _safe_diagnostic_projection(value: object, declarations) -> dict[str, object]:
    if not isinstance(value, Mapping) or not value:
        raise ProtectedOperationError(
            "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
        )
    allowed = {declaration.path: declaration.kind for declaration in declarations}
    leaves: dict[str, object] = {}

    def visit(current: object, prefix: tuple[str, ...]) -> None:
        if isinstance(current, Mapping):
            if not current:
                raise ProtectedOperationError(
                    "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
                )
            for key, item in current.items():
                if (
                    not isinstance(key, str)
                    or _PROJECTION_SEGMENT.fullmatch(key) is None
                ):
                    raise ProtectedOperationError(
                        "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
                    )
                visit(item, (*prefix, key))
            return
        path = ".".join(prefix)
        kind = allowed.get(path)
        if kind is SafeDiagnosticKind.BOOLEAN:
            valid = isinstance(current, bool)
        elif kind is SafeDiagnosticKind.COUNT:
            valid = (
                isinstance(current, int)
                and not isinstance(current, bool)
                and current >= 0
            )
        else:
            valid = False
        if not valid or path in leaves:
            raise ProtectedOperationError(
                "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID"
            )
        leaves[path] = current

    visit(value, ())
    result: dict[str, object] = {}
    for path, item in leaves.items():
        target = result
        segments = path.split(".")
        for segment in segments[:-1]:
            target = target.setdefault(segment, {})  # type: ignore[assignment]
        target[segments[-1]] = item
    return _json_mapping(result)
