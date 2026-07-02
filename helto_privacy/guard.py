"""Shared HTTP token guard for Helto privacy routes."""

from __future__ import annotations

import hmac
from typing import Any, Mapping

from . import keystore


PRIVACY_TOKEN_HEADER = "X-Helto-Privacy-Token"
PRIVACY_TOKEN_COOKIE = "helto_privacy_token"


def check_privacy_token(request: Any) -> dict[str, Any] | None:
    """Return None when allowed, otherwise a small HTTP error description."""
    if not keystore.keystore_exists():
        return None
    expected = keystore.session_token()
    if expected is None:
        return {
            "status": 401,
            "error": f"{keystore.ERROR_LOCKED}: Privacy keystore is locked. Unlock it with your privacy password.",
        }

    headers = _mapping(getattr(request, "headers", {}))
    cookies = _mapping(getattr(request, "cookies", {}))
    provided = str(headers.get(PRIVACY_TOKEN_HEADER) or cookies.get(PRIVACY_TOKEN_COOKIE) or "")
    if not provided or not hmac.compare_digest(provided, expected):
        return {
            "status": 401,
            "error": (
                "PRIVACY_TOKEN_REQUIRED: This ComfyUI has a privacy keystore; "
                "unlock it to obtain a session token."
            ),
        }
    return None


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
