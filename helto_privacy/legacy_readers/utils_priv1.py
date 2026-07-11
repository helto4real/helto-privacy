"""Authenticated Utils HELTO_PRIV1 byte reader unit."""

from __future__ import annotations

import hashlib
import hmac

from ..migration import LegacyReaderUnit
from ._utils_common import (
    UTILS_PRIVACY_KEY_BIN_IMPORT_ID,
    imported_key,
    xor_hmac_stream,
)


UTILS_PRIV1_READER_ID = "utils-priv1-v1"
UTILS_PRIV1_MAGIC = b"HELTO_PRIV1:"


class _UtilsPriv1Reader:
    def probe(self, source: object, _context: object) -> bool:
        return (
            isinstance(source, bytes)
            and source.startswith(UTILS_PRIV1_MAGIC)
            and len(source) >= len(UTILS_PRIV1_MAGIC) + 48
        )

    def read(self, source: object, context: object) -> bytes:
        if not self.probe(source, context):
            raise ValueError("Historical HELTO_PRIV1 payload is invalid.")
        key = imported_key(context, UTILS_PRIVACY_KEY_BIN_IMPORT_ID)
        payload = source[len(UTILS_PRIV1_MAGIC) :]
        iv = payload[:16]
        ciphertext = payload[16:-32]
        tag = payload[-32:]
        expected = hmac.new(
            key,
            UTILS_PRIV1_MAGIC + iv + ciphertext,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Historical HELTO_PRIV1 authentication failed.")
        return xor_hmac_stream(key, iv, ciphertext)


def utils_priv1_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        UTILS_PRIV1_READER_ID,
        "Utils HELTO_PRIV1 bytes",
        _UtilsPriv1Reader(),
        key_import_ids=(UTILS_PRIVACY_KEY_BIN_IMPORT_ID,),
    )
