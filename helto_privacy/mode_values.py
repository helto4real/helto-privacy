"""Exact public/private value representations used by typed storage services.

This module owns representation mechanics only. Mode authorization, participant
ordering, and durable transition journals are owned by the shared mode
coordinator.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

from .envelope import ALGORITHM, ENVELOPE_VERSION, PrivacyEnvelopeCodec, PrivacyError
from .mode import EffectivePrivacyMode


PUBLIC_STATE_SCHEMA = "helto.public-state"
PUBLIC_BYTES_SCHEMA = "helto.public-bytes"
PUBLIC_VALUE_VERSION = 1


class ModeValueError(ValueError):
    """A stored representation is malformed or has the wrong captured mode."""


class ModeValueKind(str, Enum):
    STATE = "state"
    BYTES = "bytes"


class ModeValueDisposition(str, Enum):
    ORIGINAL = "original"
    TARGET = "target"
    DIVERGED = "diverged"


@dataclass(frozen=True, slots=True)
class PreparedModeValue:
    """One in-memory representation rewrite for a later durable coordinator."""

    kind: ModeValueKind
    prior_mode: EffectivePrivacyMode
    target_mode: EffectivePrivacyMode
    original: object = field(repr=False, compare=False)
    target: object = field(repr=False, compare=False)
    normalized_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, ModeValueKind)
            or not isinstance(self.prior_mode, EffectivePrivacyMode)
            or not isinstance(self.target_mode, EffectivePrivacyMode)
            or self.prior_mode is self.target_mode
            or not _is_digest(self.normalized_digest)
        ):
            raise ModeValueError("invalid prepared mode value")
        object.__setattr__(self, "original", copy.deepcopy(self.original))
        object.__setattr__(self, "target", copy.deepcopy(self.target))


def protect_state(
    schema: str,
    value: object,
    mode: EffectivePrivacyMode,
) -> dict[str, object]:
    normalized = _state_value(value)
    if mode is EffectivePrivacyMode.PRIVATE:
        return PrivacyEnvelopeCodec(schema).encrypt_state(normalized)
    if mode is EffectivePrivacyMode.PUBLIC:
        return {
            "version": PUBLIC_VALUE_VERSION,
            "schema": PUBLIC_STATE_SCHEMA,
            "valueSchema": schema,
            "private": False,
            "value": normalized,
        }
    raise ModeValueError("invalid storage mode")


def reveal_state(
    schema: str,
    stored: object,
    expected_mode: EffectivePrivacyMode,
) -> dict[str, object]:
    actual = classify_state(schema, stored)
    if actual is not expected_mode:
        raise ModeValueError("stored state mode mismatch")
    if actual is EffectivePrivacyMode.PRIVATE:
        try:
            return _state_value(PrivacyEnvelopeCodec(schema).decrypt_state(stored))
        except PrivacyError:
            raise ModeValueError("private state is unreadable") from None
    payload = _mapping(stored)
    return _state_value(payload["value"])


def classify_state(schema: str, stored: object) -> EffectivePrivacyMode:
    codec = PrivacyEnvelopeCodec(schema)
    payload = _mapping(stored)
    if _exact_private_state(payload, codec):
        return EffectivePrivacyMode.PRIVATE
    if (
        set(payload) == {"version", "schema", "valueSchema", "private", "value"}
        and payload.get("version") == PUBLIC_VALUE_VERSION
        and payload.get("schema") == PUBLIC_STATE_SCHEMA
        and payload.get("valueSchema") == schema
        and payload.get("private") is False
    ):
        _state_value(payload.get("value"))
        return EffectivePrivacyMode.PUBLIC
    raise ModeValueError("stored state representation is invalid")


def protect_bytes(
    schema: str,
    purpose: str,
    value: object,
    mode: EffectivePrivacyMode,
) -> dict[str, object]:
    normalized = _bytes_value(value)
    if mode is EffectivePrivacyMode.PRIVATE:
        return PrivacyEnvelopeCodec(schema).encrypt_bytes(normalized, purpose)
    if mode is EffectivePrivacyMode.PUBLIC:
        return {
            "version": PUBLIC_VALUE_VERSION,
            "schema": PUBLIC_BYTES_SCHEMA,
            "valueSchema": schema,
            "purpose": purpose,
            "private": False,
            "encoding": "base64url",
            "value": _b64encode(normalized),
        }
    raise ModeValueError("invalid storage mode")


def reveal_bytes(
    schema: str,
    purpose: str,
    stored: object,
    expected_mode: EffectivePrivacyMode,
) -> bytes:
    actual = classify_bytes(schema, purpose, stored)
    if actual is not expected_mode:
        raise ModeValueError("stored bytes mode mismatch")
    if actual is EffectivePrivacyMode.PRIVATE:
        try:
            return PrivacyEnvelopeCodec(schema).decrypt_bytes(stored, purpose)
        except PrivacyError:
            raise ModeValueError("private bytes are unreadable") from None
    return _b64decode(_mapping(stored)["value"])


def classify_bytes(
    schema: str,
    purpose: str,
    stored: object,
) -> EffectivePrivacyMode:
    codec = PrivacyEnvelopeCodec(schema)
    payload = _mapping(stored)
    if _exact_private_bytes(payload, codec, purpose):
        return EffectivePrivacyMode.PRIVATE
    if (
        set(payload)
        == {
            "version",
            "schema",
            "valueSchema",
            "purpose",
            "private",
            "encoding",
            "value",
        }
        and payload.get("version") == PUBLIC_VALUE_VERSION
        and payload.get("schema") == PUBLIC_BYTES_SCHEMA
        and payload.get("valueSchema") == schema
        and payload.get("purpose") == purpose
        and payload.get("private") is False
        and payload.get("encoding") == "base64url"
    ):
        _b64decode(payload.get("value"))
        return EffectivePrivacyMode.PUBLIC
    raise ModeValueError("stored bytes representation is invalid")


def prepare_state_transition(
    schema: str,
    stored: object,
    prior_mode: EffectivePrivacyMode,
    target_mode: EffectivePrivacyMode,
) -> PreparedModeValue:
    value = reveal_state(schema, stored, prior_mode)
    return PreparedModeValue(
        ModeValueKind.STATE,
        prior_mode,
        target_mode,
        stored,
        protect_state(schema, value, target_mode),
        normalized_digest(value),
    )


def prepare_bytes_transition(
    schema: str,
    purpose: str,
    stored: object,
    prior_mode: EffectivePrivacyMode,
    target_mode: EffectivePrivacyMode,
) -> PreparedModeValue:
    value = reveal_bytes(schema, purpose, stored, prior_mode)
    return PreparedModeValue(
        ModeValueKind.BYTES,
        prior_mode,
        target_mode,
        stored,
        protect_bytes(schema, purpose, value, target_mode),
        normalized_digest(value),
    )


def classify_prepared_value(
    stored: object,
    prepared: PreparedModeValue,
) -> ModeValueDisposition:
    candidate = canonical_representation(stored)
    if hmac.compare_digest(candidate, canonical_representation(prepared.original)):
        return ModeValueDisposition.ORIGINAL
    if hmac.compare_digest(candidate, canonical_representation(prepared.target)):
        return ModeValueDisposition.TARGET
    return ModeValueDisposition.DIVERGED


def verify_prepared_value(
    stored: object,
    prepared: PreparedModeValue,
    expected: ModeValueDisposition,
) -> bool:
    if expected not in {ModeValueDisposition.ORIGINAL, ModeValueDisposition.TARGET}:
        raise ModeValueError("invalid expected disposition")
    return classify_prepared_value(stored, prepared) is expected


def canonical_representation(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise ModeValueError("representation is not canonical JSON") from None


def normalized_digest(value: object) -> str:
    if isinstance(value, bytes):
        payload = value
    else:
        payload = canonical_representation(value)
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ModeValueError("representation is not an object") from None
    if not isinstance(value, Mapping):
        raise ModeValueError("representation is not an object")
    return value


def _state_value(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ModeValueError("state value is not an object")
    normalized = copy.deepcopy(dict(value))
    canonical_representation(normalized)
    return normalized


def _bytes_value(value: object) -> bytes:
    if type(value) is not bytes:
        raise ModeValueError("bytes value is invalid")
    return value


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise ModeValueError("public bytes encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception:
        raise ModeValueError("public bytes encoding is invalid") from None
    if not hmac.compare_digest(_b64encode(decoded), value):
        raise ModeValueError("public bytes encoding is invalid")
    return decoded


def _exact_private_bytes(
    payload: Mapping[str, object],
    codec: PrivacyEnvelopeCodec,
    purpose: str,
) -> bool:
    if payload.get("schema") == codec.byte_schema:
        return (
            set(payload)
            == {
                "version",
                "schema",
                "encrypted",
                "algorithm",
                "purpose",
                "keyId",
                "nonce",
                "ciphertext",
            }
            and payload.get("version") == ENVELOPE_VERSION
            and payload.get("encrypted") is True
            and payload.get("algorithm") == ALGORITHM
            and payload.get("purpose") == purpose
            and _canonical_b64(payload.get("keyId"), length=12)
            and _canonical_b64(payload.get("nonce"), length=12)
            and _canonical_b64(payload.get("ciphertext"), minimum=16)
        )
    if payload.get("schema") != codec.chunked_byte_schema or set(payload) != {
        "version",
        "schema",
        "encrypted",
        "algorithm",
        "purpose",
        "keyId",
        "chunkSize",
        "plaintextSize",
        "chunks",
    }:
        return False
    chunks = payload.get("chunks")
    return (
        payload.get("version") == ENVELOPE_VERSION
        and payload.get("encrypted") is True
        and payload.get("algorithm") == ALGORITHM
        and payload.get("purpose") == purpose
        and _canonical_b64(payload.get("keyId"), length=12)
        and type(payload.get("chunkSize")) is int
        and int(payload["chunkSize"]) > 0
        and type(payload.get("plaintextSize")) is int
        and int(payload["plaintextSize"]) >= 0
        and isinstance(chunks, list)
        and bool(chunks)
        and all(
            isinstance(chunk, Mapping)
            and set(chunk) == {"index", "nonce", "ciphertext"}
            and chunk.get("index") == index
            and _canonical_b64(chunk.get("nonce"), length=12)
            and _canonical_b64(chunk.get("ciphertext"), minimum=16)
            for index, chunk in enumerate(chunks)
        )
    )


def _exact_private_state(
    payload: Mapping[str, object],
    codec: PrivacyEnvelopeCodec,
) -> bool:
    return (
        set(payload)
        == {
            "version",
            "schema",
            "encrypted",
            "algorithm",
            "keyId",
            "nonce",
            "ciphertext",
        }
        and payload.get("version") == ENVELOPE_VERSION
        and payload.get("schema") == codec.schema
        and payload.get("encrypted") is True
        and payload.get("algorithm") == ALGORITHM
        and _canonical_b64(payload.get("keyId"), length=12)
        and _canonical_b64(payload.get("nonce"), length=12)
        and _canonical_b64(payload.get("ciphertext"), minimum=16)
    )


def _canonical_b64(
    value: object,
    *,
    length: int | None = None,
    minimum: int = 0,
) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        decoded = base64.urlsafe_b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii")
        )
    except Exception:
        return False
    return (
        hmac.compare_digest(_b64encode(decoded), value)
        and (length is None or len(decoded) == length)
        and len(decoded) >= minimum
    )


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
