"""Shared primitives for exact Utils historical reader units."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping


UTILS_KEY_BIN_IMPORT_ID = "utils-key-bin-v0"
UTILS_PRIVACY_KEY_BIN_IMPORT_ID = "utils-privacy-key-bin-v1"
UTILS_WORKFLOW_PREFIX = "__HELTO_ENC__:"
UTILS_QUEUE_PREFIX = "HELTO_QUEUE_MANAGER_STATE_V1:"
UTILS_RAW_SOURCE_SCHEMA = "helto.utils-raw-xor-source"
UTILS_RAW_SOURCE_LOCATIONS = frozenset({"selector-mask", "workflow-field"})


def imported_key(context: object, import_id: str) -> bytes:
    key_for = getattr(context, "key_for", None)
    if not callable(key_for):
        raise ValueError("Historical key import is unavailable.")
    key = key_for(import_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Historical binary key import is invalid.")
    return key


def standard_b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def standard_b64decode(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Historical base64 value is invalid.")
    decoded = base64.b64decode(value.encode("ascii"), validate=True)
    if standard_b64encode(decoded) != value:
        raise ValueError("Historical base64 value is not canonical.")
    return decoded


def raw_xor_source(payload: bytes, location: str) -> dict[str, object]:
    if not isinstance(payload, bytes) or location not in UTILS_RAW_SOURCE_LOCATIONS:
        raise ValueError("Raw historical Utils source is invalid.")
    return {
        "schema": UTILS_RAW_SOURCE_SCHEMA,
        "version": 1,
        "location": location,
        "payload": standard_b64encode(payload),
    }


def raw_xor_payload(source: object) -> bytes | None:
    if not isinstance(source, Mapping) or set(source) != {
        "schema",
        "version",
        "location",
        "payload",
    }:
        return None
    if (
        source.get("schema") != UTILS_RAW_SOURCE_SCHEMA
        or source.get("version") != 1
        or source.get("location") not in UTILS_RAW_SOURCE_LOCATIONS
    ):
        return None
    try:
        payload = standard_b64decode(source.get("payload"))
    except ValueError:
        return None
    return payload if len(payload) >= 16 else None


def decode_json_object(plaintext: bytes) -> dict[str, object]:
    loaded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError("Historical Utils payload did not contain an object.")
    return dict(loaded)


def xor_hmac_stream(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < len(ciphertext):
        stream.extend(
            hmac.new(
                key,
                iv + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return bytes(left ^ right for left, right in zip(ciphertext, stream))
