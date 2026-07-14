"""Shared HTTP token guard for Helto privacy routes."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import re
from typing import Any, Mapping

from . import keystore
from .suite_runtime import SuiteBlockedError, require_active_process_suite


PRIVACY_TOKEN_HEADER = "X-Helto-Privacy-Token"
PRIVACY_TOKEN_COOKIE = "helto_privacy_token"
PRIVACY_DECLASSIFICATION_HEADER = "X-Helto-Privacy-Declassification"
_OPERATION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_AUTHORIZED_REQUEST_MARKER = object()


class PrivacyRouteError(RuntimeError):
    """Sanitized typed failure shared by protected route dispatch."""

    def __init__(self, code: str, http_status: int) -> None:
        self.code = code
        self.http_status = http_status
        super().__init__("Privacy route operation was not authorized or completed.")


class PrivacyAuthorizationError(PrivacyRouteError):
    pass


class PrivacyRouteDispatchError(PrivacyRouteError):
    pass


class AuthorizedPrivacyRequest:
    __slots__ = (
        "_declassification_binding",
        "_declassification_consumed",
        "_operation_id",
        "_pack_id",
        "_session_fingerprint",
    )

    def __init__(
        self,
        operation_id: str,
        pack_id: str | None,
        session_fingerprint: bytes,
        declassification_binding: tuple[str, str] | None,
        *,
        _marker: object | None = None,
    ) -> None:
        if _marker is not _AUTHORIZED_REQUEST_MARKER:
            raise PrivacyAuthorizationError("PRIVACY_AUTHORIZATION_INVALID", 403)
        if not isinstance(session_fingerprint, bytes) or len(session_fingerprint) != 32:
            raise PrivacyAuthorizationError("PRIVACY_AUTHORIZATION_INVALID", 403)
        if declassification_binding is not None and (
            not isinstance(declassification_binding, tuple)
            or len(declassification_binding) != 2
            or not all(
                isinstance(value, str) and _OPERATION_ID.fullmatch(value)
                for value in declassification_binding
            )
        ):
            raise PrivacyAuthorizationError("PRIVACY_AUTHORIZATION_INVALID", 403)
        object.__setattr__(self, "_operation_id", operation_id)
        object.__setattr__(self, "_pack_id", pack_id)
        object.__setattr__(self, "_session_fingerprint", session_fingerprint)
        object.__setattr__(
            self,
            "_declassification_binding",
            declassification_binding,
        )
        object.__setattr__(self, "_declassification_consumed", False)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("AuthorizedPrivacyRequest is immutable")

    @property
    def operation_id(self) -> str:
        return self._operation_id

    @property
    def pack_id(self) -> str | None:
        return self._pack_id

    def __repr__(self) -> str:
        return "AuthorizedPrivacyRequest()"


def authorize_privacy_request(
    request: Any,
    operation_id: str,
    *,
    pack_id: str | None = None,
    declassification_scope_id: str | None = None,
    declassification_target: str | None = None,
) -> AuthorizedPrivacyRequest:
    """Return an opaque capability only for one authorized route operation."""

    if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
        raise PrivacyAuthorizationError("PRIVACY_OPERATION_INVALID", 400)
    if pack_id is not None and (
        not isinstance(pack_id, str) or not _OPERATION_ID.fullmatch(pack_id)
    ):
        raise PrivacyAuthorizationError("PRIVACY_PACK_INVALID", 400)
    if (declassification_scope_id is None) != (declassification_target is None):
        raise PrivacyAuthorizationError("PRIVACY_OPERATION_INVALID", 400)
    if declassification_scope_id is not None and (
        operation_id not in {"mode.transition", "mode.transition.reserve"}
        or not isinstance(declassification_scope_id, str)
        or not _OPERATION_ID.fullmatch(declassification_scope_id)
        or not isinstance(declassification_target, str)
        or declassification_target not in {"inherit", "private", "public"}
    ):
        raise PrivacyAuthorizationError("PRIVACY_OPERATION_INVALID", 400)
    try:
        require_active_process_suite()
    except SuiteBlockedError:
        raise PrivacyAuthorizationError("PRIVACY_SUITE_BLOCKED", 409) from None
    if not keystore.keystore_exists():
        raise PrivacyAuthorizationError("PRIVACY_KEYSTORE_UNINITIALIZED", 409)
    expected = keystore.session_token()
    if expected is None:
        raise PrivacyAuthorizationError("PRIVACY_LOCKED", 401)

    headers = _mapping(getattr(request, "headers", {}))
    cookies = _mapping(getattr(request, "cookies", {}))
    provided = str(
        headers.get(PRIVACY_TOKEN_HEADER)
        or cookies.get(PRIVACY_TOKEN_COOKIE)
        or ""
    )
    if not provided or not hmac.compare_digest(provided, expected):
        raise PrivacyAuthorizationError("PRIVACY_TOKEN_REQUIRED", 401)
    confirmed = (
        str(headers.get(PRIVACY_DECLASSIFICATION_HEADER) or "").strip().lower()
        == "confirmed"
    )
    declassification_binding = (
        (declassification_scope_id, declassification_target)
        if confirmed and declassification_scope_id is not None
        else None
    )
    return AuthorizedPrivacyRequest(
        operation_id,
        pack_id,
        _session_fingerprint(expected),
        declassification_binding,
        _marker=_AUTHORIZED_REQUEST_MARKER,
    )


def require_current_authorization(
    authorization: AuthorizedPrivacyRequest,
    operation_id: str,
    *,
    pack_id: str | None = None,
) -> None:
    """Reject retained capabilities after lock, rotation, or suite loss."""

    if (
        not isinstance(authorization, AuthorizedPrivacyRequest)
        or getattr(authorization, "_operation_id", None) != operation_id
        or getattr(authorization, "_pack_id", None) != pack_id
        or not isinstance(
            getattr(authorization, "_session_fingerprint", None),
            bytes,
        )
    ):
        raise PrivacyAuthorizationError("PRIVACY_AUTHORIZATION_INVALID", 403)
    try:
        require_active_process_suite()
    except SuiteBlockedError:
        raise PrivacyAuthorizationError("PRIVACY_SUITE_BLOCKED", 409) from None
    if not keystore.keystore_exists():
        raise PrivacyAuthorizationError("PRIVACY_KEYSTORE_UNINITIALIZED", 409)
    current = keystore.session_token()
    if current is None or not hmac.compare_digest(
        authorization._session_fingerprint,
        _session_fingerprint(current),
    ):
        raise PrivacyAuthorizationError("PRIVACY_AUTHORIZATION_EXPIRED", 401)


def _derive_operation_dependency_authorization(
    authorization: AuthorizedPrivacyRequest,
    parent_operation_id: str,
    child_operation_id: str,
    *,
    pack_id: str,
) -> AuthorizedPrivacyRequest:
    """Derive one internal child capability without exposing parent authority."""

    require_current_authorization(
        authorization,
        parent_operation_id,
        pack_id=pack_id,
    )
    if not isinstance(child_operation_id, str) or not _OPERATION_ID.fullmatch(
        child_operation_id
    ):
        raise PrivacyAuthorizationError("PRIVACY_AUTHORIZATION_INVALID", 403)
    return AuthorizedPrivacyRequest(
        child_operation_id,
        pack_id,
        authorization._session_fingerprint,
        None,
        _marker=_AUTHORIZED_REQUEST_MARKER,
    )


def require_declassification_confirmation(
    authorization: AuthorizedPrivacyRequest,
    *,
    scope_id: str,
    target: str,
) -> None:
    """Consume scope- and target-bound declassification confirmation once."""

    if (
        getattr(authorization, "_declassification_binding", None)
        != (scope_id, target)
        or getattr(authorization, "_declassification_consumed", True) is not False
    ):
        raise PrivacyAuthorizationError(
            "PRIVACY_DECLASSIFICATION_CONFIRMATION_REQUIRED",
            409,
        )
    object.__setattr__(authorization, "_declassification_consumed", True)


async def dispatch_privacy_route(
    request: Any,
    operation_id: str,
    operation,
    *,
    pack_id: str | None = None,
    before_dispatch=None,
):
    """Authorize and dispatch one route without leaking product exceptions."""

    authorization = authorize_privacy_request(
        request,
        operation_id,
        pack_id=pack_id,
    )
    if not callable(operation):
        raise PrivacyRouteDispatchError("PRIVACY_OPERATION_INVALID", 500)
    try:
        if before_dispatch is not None:
            if not callable(before_dispatch):
                raise PrivacyRouteDispatchError("PRIVACY_OPERATION_INVALID", 500)
            before_dispatch(authorization)
        result = operation(authorization)
        return await result if inspect.isawaitable(result) else result
    except PrivacyRouteError:
        raise
    except Exception:
        raise PrivacyRouteDispatchError("PRIVACY_OPERATION_FAILED", 500) from None


def check_privacy_token(request: Any) -> dict[str, Any] | None:
    """Return None when allowed, otherwise a small HTTP error description."""
    try:
        authorize_privacy_request(request, "privacy.route")
        return None
    except PrivacyAuthorizationError as exc:
        return {"status": exc.http_status, "error": exc.code}


def aiohttp_check_privacy_token(request: Any):
    """Return an aiohttp JSON response on denial, or None when allowed."""
    denied = check_privacy_token(request)
    if denied is None:
        return None
    try:
        from aiohttp import web
    except Exception as exc:  # noqa: BLE001 - keep base package importable without aiohttp.
        raise RuntimeError("aiohttp is required for aiohttp_check_privacy_token") from exc
    return web.json_response({"ok": False, "error": denied["error"]}, status=int(denied["status"]))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _session_fingerprint(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
