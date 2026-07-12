"""Shared protected-operation lifecycle for authorized workflow reveals."""

from __future__ import annotations

import copy
import inspect
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from ._plaintext import clear_mutable_plaintext
from .mode import EffectivePrivacyMode
from .profile import SafeDiagnosticKind


_PROJECTION_ERROR_CODES = frozenset(
    {
        "PRIVACY_PROTECTED_OPERATION_ADAPTER_INVALID",
        "PRIVACY_PROTECTED_OPERATION_DECLARATION_INVALID",
        "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED",
        "PRIVACY_PROTECTED_OPERATION_PROJECTION_INVALID",
    }
)
_PROJECTION_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class ProtectedOperationError(RuntimeError):
    """Product-data-free protected-operation projection failure."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in _PROJECTION_ERROR_CODES
            else "PRIVACY_PROTECTED_OPERATION_PROJECTION_FAILED"
        )
        super().__init__("Protected privacy operation could not complete.")


@dataclass(frozen=True, slots=True)
class ProtectedOperationProjection:
    """Server-mode-resolved public or coarse private operation output."""

    value: dict[str, object] = field(repr=False)
    private: bool


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


def project_protected_operation(
    *,
    installation,
    profile,
    adapters: Mapping[str, object],
    resource_id: str,
    operation_id: str,
    value: object,
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
    resolution = resolve_bound_mode(
        installation,
        scope.mode_resource_id,
        scope.id,
        None,
    )
    source = copy.deepcopy(value)
    candidate: object = None
    try:
        if resolution.effective is EffectivePrivacyMode.PUBLIC:
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
