"""Reusable product adapter primitives with fixed privacy semantics."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Mapping
from threading import RLock

from .envelope import PrivacyEnvelopeCodec


_DECLARED_MODES = frozenset({"private", "public"})
_ENVELOPE_KEYS = frozenset(
    {"version", "schema", "encrypted", "algorithm", "keyId", "nonce", "ciphertext"}
)
_PROTECTED_MARKERS = frozenset(
    {"algorithm", "ciphertext", "encrypted", "keyId", "nonce", "private", "schema"}
)


class PrivateByDefaultModeAdapter:
    """Thread-safe revisioned mode source for private-by-default product scopes."""

    def __init__(self, declarations: Mapping[str, object] | None = None) -> None:
        self._declarations = {
            str(scope_id): _legacy_declared_mode(value)
            for scope_id, value in dict(declarations or {}).items()
        }
        self._revisions = {scope_id: 0 for scope_id in self._declarations}
        self._mode_lock = RLock()

    def read_declared_mode(self, scope_id: str) -> str:
        return str(self.read_mode_source(scope_id)["declared"])

    def write_declared_mode(self, scope_id: str, mode: object) -> None:
        target = _declared_mode(mode)
        with self._mode_lock:
            self._ensure_scope(scope_id)
            if self._declarations[scope_id] == target:
                return
            self._declarations[scope_id] = target
            self._revisions[scope_id] += 1

    def read_mode_source(self, scope_id: str) -> dict[str, object]:
        with self._mode_lock:
            self._ensure_scope(scope_id)
            return self._snapshot(scope_id)

    def compare_and_set_mode_source(
        self,
        scope_id: str,
        expected_revision: object,
        expected_declared: object,
        target_declared: object,
    ) -> dict[str, object]:
        expected = _mode_source_snapshot(
            {"revision": expected_revision, "declared": expected_declared}
        )
        target = _declared_mode(target_declared)
        with self._mode_lock:
            self._ensure_scope(scope_id)
            if self._snapshot(scope_id) != expected:
                raise RuntimeError("Privacy mode source changed concurrently.")
            self._declarations[scope_id] = target
            self._revisions[scope_id] = int(expected["revision"]) + 1
            return self._snapshot(scope_id)

    def classify_mode_source(
        self,
        scope_id: str,
        prior: object,
        target: object,
    ) -> str:
        current = self.read_mode_source(scope_id)
        if current == _mode_source_snapshot(prior):
            return "prior"
        if current == _mode_source_snapshot(target):
            return "target"
        return "diverged"

    def rollback_mode_source(
        self,
        scope_id: str,
        target: object,
        prior: object,
    ) -> dict[str, object]:
        normalized_target = _mode_source_snapshot(target)
        normalized_prior = _mode_source_snapshot(prior)
        restored = {
            "revision": int(normalized_target["revision"]) + 1,
            "declared": normalized_prior["declared"],
        }
        with self._mode_lock:
            self._ensure_scope(scope_id)
            current = self._snapshot(scope_id)
            if current == restored:
                return current
            if current != normalized_target:
                raise RuntimeError("Privacy mode source changed concurrently.")
            self._declarations[scope_id] = str(restored["declared"])
            self._revisions[scope_id] = int(restored["revision"])
            return self._snapshot(scope_id)

    def _ensure_scope(self, scope_id: object) -> None:
        if not isinstance(scope_id, str) or not scope_id:
            raise ValueError("Invalid privacy scope.")
        if scope_id not in self._declarations:
            self._declarations[scope_id] = "private"
            self._revisions[scope_id] = 0

    def _snapshot(self, scope_id: str) -> dict[str, object]:
        return {
            "revision": self._revisions[scope_id],
            "declared": self._declarations[scope_id],
        }


class ExternalJsonValueTransitionAdapter:
    """Strict exact-byte codec for browser-authoritative JSON value wrappers."""

    def __init__(self, schema: str) -> None:
        if not isinstance(schema, str) or not schema:
            raise ValueError("Invalid privacy transition schema.")
        self._transition_schema = schema

    def classify_mode_transition_representation(
        self,
        value: object,
        context: object,
    ) -> str:
        payload = _decode_exact_value(value)
        if isinstance(payload, Mapping) and _is_exact_current_envelope(
            payload,
            self._transition_schema,
        ):
            return "private"
        if isinstance(payload, Mapping) and _PROTECTED_MARKERS.intersection(payload):
            raise ValueError("Privacy mode transition representation is invalid.")
        self.normalize_mode_transition_value(payload, context)
        return "public"

    def decode_mode_transition_representation(
        self,
        value: object,
        context: object,
    ) -> object:
        payload = _decode_exact_value(value)
        if self.classify_mode_transition_representation(value, context) == "private":
            revealed = PrivacyEnvelopeCodec(self._transition_schema).decrypt_state(payload)
            if not isinstance(revealed, Mapping) or set(revealed) != {"value"}:
                raise ValueError("Privacy mode transition representation is invalid.")
            return dict(revealed)
        return payload

    def normalize_mode_transition_value(
        self,
        value: object,
        context: object,
    ) -> dict[str, object]:
        del context
        candidate = (
            value["value"]
            if isinstance(value, Mapping) and set(value) == {"value"}
            else value
        )
        normalized = {"value": copy.deepcopy(candidate)}
        _canonical_json_bytes(normalized)
        return normalized

    def encode_public_mode_transition(
        self,
        value: object,
        context: object,
    ) -> bytes:
        return _canonical_json_bytes(
            self.normalize_mode_transition_value(value, context)
        )


def _legacy_declared_mode(value: object) -> str:
    return "public" if value is False or value == "public" else "private"


def _declared_mode(value: object) -> str:
    candidate = getattr(value, "value", value)
    if candidate is True:
        candidate = "private"
    elif candidate is False:
        candidate = "public"
    if not isinstance(candidate, str) or candidate not in _DECLARED_MODES:
        raise ValueError("Invalid declared privacy mode.")
    return candidate


def _mode_source_snapshot(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"revision", "declared"}:
        raise ValueError("Invalid privacy mode source snapshot.")
    revision = value["revision"]
    if type(revision) is not int or revision < 0:
        raise ValueError("Invalid privacy mode source snapshot.")
    return {"revision": revision, "declared": _declared_mode(value["declared"])}


def _decode_exact_value(value: object) -> object:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("Privacy mode transition representation is invalid.")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError

    try:
        text = bytes(value).decode("utf-8", errors="strict")
        if not text.strip():
            raise ValueError
        try:
            return json.loads(
                text,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except json.JSONDecodeError:
            if text.lstrip().startswith(("{", "[")):
                raise ValueError
            return text
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("Privacy mode transition representation is invalid.") from None


def _is_exact_current_envelope(value: Mapping[str, object], schema: str) -> bool:
    return (
        set(value) == _ENVELOPE_KEYS
        and value.get("version") == 1
        and value.get("schema") == schema
        and value.get("encrypted") is True
        and value.get("algorithm") == "AES-256-GCM"
        and isinstance(value.get("keyId"), str)
        and bool(value.get("keyId"))
        and _valid_base64url(value.get("nonce"), exact_bytes=12)
        and _valid_base64url(value.get("ciphertext"), minimum_bytes=16)
    )


def _valid_base64url(
    value: object,
    *,
    exact_bytes: int | None = None,
    minimum_bytes: int | None = None,
) -> bool:
    if not isinstance(value, str) or not value or "=" in value:
        return False
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError, UnicodeError):
        return False
    return (
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value
        and (exact_bytes is None or len(decoded) == exact_bytes)
        and (minimum_bytes is None or len(decoded) >= minimum_bytes)
    )


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("Privacy mode transition representation is invalid.") from None
