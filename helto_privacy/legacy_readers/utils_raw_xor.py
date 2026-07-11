"""Strictly gated unauthenticated Utils raw-XOR reader unit."""

from __future__ import annotations

from ..migration import LegacyReaderUnit
from ._utils_common import (
    UTILS_KEY_BIN_IMPORT_ID,
    imported_key,
    raw_xor_payload,
    raw_xor_source,
    xor_hmac_stream,
)


UTILS_RAW_XOR_READER_ID = "utils-raw-xor-v0"


class _UtilsRawXorReader:
    def probe(self, source: object, _context: object) -> bool:
        return raw_xor_payload(source) is not None

    def read(self, source: object, context: object) -> bytes:
        payload = raw_xor_payload(source)
        if payload is None:
            raise ValueError("Historical raw-XOR source is not explicitly gated.")
        key = imported_key(context, UTILS_KEY_BIN_IMPORT_ID)
        iv = payload[:16]
        ciphertext = payload[16:]
        return xor_hmac_stream(key, iv, ciphertext)


def utils_raw_xor_source(payload: bytes, location: str) -> dict[str, object]:
    """Bind unauthenticated historical bytes to one enumerated safe location."""

    return raw_xor_source(payload, location)


def utils_raw_xor_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        UTILS_RAW_XOR_READER_ID,
        "Utils raw XOR bytes",
        _UtilsRawXorReader(),
        key_import_ids=(UTILS_KEY_BIN_IMPORT_ID,),
    )
