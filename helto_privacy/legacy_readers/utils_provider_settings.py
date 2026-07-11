"""Exact read-only readers for historical Utils provider settings wrappers."""

from __future__ import annotations

import base64
import copy
from collections.abc import Mapping

from ..migration import LegacyReaderUnit


UTILS_PROVIDER_SETTINGS_PLAINTEXT_READER_ID = (
    "utils-provider-settings-plaintext-v1"
)
UTILS_PROVIDER_SETTINGS_WRAPPER_READER_ID = "utils-provider-settings-wrapper-v2"
_UTILS_SCHEMA = "helto.comfyui-utils"
_ENVELOPE_FIELDS = {
    "version",
    "schema",
    "encrypted",
    "algorithm",
    "keyId",
    "nonce",
    "ciphertext",
}


def _canonical_b64url(
    value: object,
    exact_length: int | None = None,
    minimum_length: int | None = None,
) -> bool:
    if not isinstance(value, str) or not value or "=" in value:
        return False
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    return (
        canonical == value
        and (exact_length is None or len(decoded) == exact_length)
        and (minimum_length is None or len(decoded) >= minimum_length)
    )


def _exact_current_envelope(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == _ENVELOPE_FIELDS
        and value.get("version") == 1
        and value.get("schema") == _UTILS_SCHEMA
        and value.get("encrypted") is True
        and value.get("algorithm") == "AES-256-GCM"
        and _canonical_b64url(value.get("keyId"), 12)
        and _canonical_b64url(value.get("nonce"), 12)
        and _canonical_b64url(value.get("ciphertext"), minimum_length=16)
    )


class _UtilsProviderSettingsPlaintextReader:
    def probe(self, source: object, _context: object) -> bool:
        return (
            isinstance(source, Mapping)
            and set(source) == {"version", "hf_token"}
            and source.get("version") == 1
            and isinstance(source.get("hf_token"), str)
            and bool(source.get("hf_token").strip())
            and source.get("hf_token") == source.get("hf_token").strip()
        )

    def read(self, source: object, context: object) -> dict[str, str]:
        if not self.probe(source, context):
            raise ValueError("Historical Utils provider settings are invalid.")
        return {"hf_token": source["hf_token"]}


class _UtilsProviderSettingsWrapperReader:
    def probe(self, source: object, _context: object) -> bool:
        return (
            isinstance(source, Mapping)
            and set(source) == {"version", "hf_token_encrypted"}
            and source.get("version") == 2
            and _exact_current_envelope(source.get("hf_token_encrypted"))
        )

    def read(self, source: object, context: object) -> object:
        if not self.probe(source, context):
            raise ValueError("Historical Utils provider wrapper is invalid.")
        return copy.deepcopy(source["hf_token_encrypted"])


def utils_provider_settings_reader_units() -> tuple[LegacyReaderUnit, ...]:
    return (
        LegacyReaderUnit(
            UTILS_PROVIDER_SETTINGS_PLAINTEXT_READER_ID,
            "Utils provider settings plaintext v1",
            _UtilsProviderSettingsPlaintextReader(),
        ),
        LegacyReaderUnit(
            UTILS_PROVIDER_SETTINGS_WRAPPER_READER_ID,
            "Utils provider settings encrypted wrapper v2",
            _UtilsProviderSettingsWrapperReader(),
        ),
    )
