"""Shared canonical encoding and lexical checks for signed suite records."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime


_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_signature(value: str) -> bytes:
    return base64.b64decode(
        value.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def is_stable_id(value: object) -> bool:
    return isinstance(value, str) and bool(_STABLE_ID.fullmatch(value))


def is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0
