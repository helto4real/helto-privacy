"""Shared cache and disclosure policy for private HTTP responses."""

from __future__ import annotations

import re


_CORRELATION_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_GENERIC_FILENAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def private_response_headers(
    correlation_id: object,
    *,
    correlation_prefix: str,
    disposition: str | None = None,
    filename: str | None = None,
) -> dict[str, str]:
    """Build one validated private no-store response policy."""

    if (
        not isinstance(correlation_id, str)
        or not isinstance(correlation_prefix, str)
        or not correlation_prefix
        or not correlation_id.startswith(correlation_prefix)
        or _CORRELATION_TOKEN.fullmatch(
            correlation_id.removeprefix(correlation_prefix)
        )
        is None
    ):
        raise ValueError("invalid private response correlation")
    if (disposition is None) is not (filename is None):
        raise ValueError("incomplete private response disposition")
    if disposition is not None and (
        disposition not in {"attachment", "inline"}
        or not isinstance(filename, str)
        or _GENERIC_FILENAME.fullmatch(filename) is None
    ):
        raise ValueError("invalid private response disposition")
    headers = {
        "Cache-Control": "private, no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "Vary": "Cookie, X-Helto-Privacy-Token",
        "X-Content-Type-Options": "nosniff",
        "X-Helto-Privacy-Correlation-ID": correlation_id,
    }
    if disposition is not None:
        headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
    return headers
