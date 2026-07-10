"""Shared canonical encoding and lexical checks for signed suite records."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from datetime import datetime
from typing import TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_Item = TypeVar("_Item")


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


def sign_canonical_record(
    private_key: Ed25519PrivateKey,
    domain: bytes,
    canonical_bytes: bytes,
) -> str:
    signature = private_key.sign(domain + canonical_bytes)
    return base64.urlsafe_b64encode(signature).decode("ascii")


def verify_canonical_record_signature(
    public_key: Ed25519PublicKey,
    signature: str,
    domain: bytes,
    canonical_bytes: bytes,
) -> bool:
    try:
        public_key.verify(
            decode_signature(signature),
            domain + canonical_bytes,
        )
    except (InvalidSignature, ValueError, UnicodeEncodeError):
        return False
    return True


def typed_tuple(
    values: object,
    expected_type: type[_Item],
    error_code: str,
    error_factory: Callable[[str], Exception],
) -> tuple[_Item, ...]:
    if isinstance(values, (str, bytes)):
        raise error_factory(error_code)
    try:
        normalized = tuple(values)  # type: ignore[arg-type]
    except TypeError:
        raise error_factory(error_code) from None
    if any(not isinstance(item, expected_type) for item in normalized):
        raise error_factory(error_code)
    return normalized


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
