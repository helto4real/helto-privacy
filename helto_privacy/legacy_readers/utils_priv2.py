"""Authenticated Utils HELTO_PRIV2 byte reader unit."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..migration import LegacyReaderUnit
from ._utils_common import UTILS_PRIVACY_KEY_BIN_IMPORT_ID, imported_key


UTILS_PRIV2_READER_ID = "utils-priv2-v1"
UTILS_PRIV2_MAGIC = b"HELTO_PRIV2:"


class _UtilsPriv2Reader:
    def probe(self, source: object, _context: object) -> bool:
        return (
            isinstance(source, bytes)
            and source.startswith(UTILS_PRIV2_MAGIC)
            and len(source) >= len(UTILS_PRIV2_MAGIC) + 28
        )

    def read(self, source: object, context: object) -> bytes:
        if not self.probe(source, context):
            raise ValueError("Historical HELTO_PRIV2 payload is invalid.")
        key = imported_key(context, UTILS_PRIVACY_KEY_BIN_IMPORT_ID)
        payload = source[len(UTILS_PRIV2_MAGIC) :]
        return AESGCM(key).decrypt(payload[:12], payload[12:], UTILS_PRIV2_MAGIC)


def utils_priv2_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        UTILS_PRIV2_READER_ID,
        "Utils HELTO_PRIV2 bytes",
        _UtilsPriv2Reader(),
        key_import_ids=(UTILS_PRIVACY_KEY_BIN_IMPORT_ID,),
    )
