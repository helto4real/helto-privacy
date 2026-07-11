"""Authenticated chunked Utils HELTO_PRIV3 byte reader unit."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..migration import LegacyReaderUnit
from ._utils_common import UTILS_PRIVACY_KEY_BIN_IMPORT_ID, imported_key


UTILS_PRIV3_READER_ID = "utils-priv3-v1"
UTILS_PRIV3_MAGIC = b"HELTO_PRIV3:"
_HEADER_BYTES = 20


class _UtilsPriv3Reader:
    def probe(self, source: object, _context: object) -> bool:
        if (
            not isinstance(source, bytes)
            or not source.startswith(UTILS_PRIV3_MAGIC)
            or len(source) < len(UTILS_PRIV3_MAGIC) + _HEADER_BYTES
        ):
            return False
        payload = source[len(UTILS_PRIV3_MAGIC) :]
        chunk_size = int.from_bytes(payload[:8], "big")
        total_length = int.from_bytes(payload[8:16], "big")
        if chunk_size < 1:
            return False
        chunk_count = (total_length + chunk_size - 1) // chunk_size
        return len(payload) == _HEADER_BYTES + total_length + 16 * chunk_count

    def read(self, source: object, context: object) -> bytes:
        if not self.probe(source, context):
            raise ValueError("Historical HELTO_PRIV3 payload is invalid.")
        key = imported_key(context, UTILS_PRIVACY_KEY_BIN_IMPORT_ID)
        payload = source[len(UTILS_PRIV3_MAGIC) :]
        header = payload[:_HEADER_BYTES]
        chunk_size = int.from_bytes(header[:8], "big")
        remaining = int.from_bytes(header[8:16], "big")
        nonce_prefix = header[16:20]
        offset = _HEADER_BYTES
        counter = 0
        chunks: list[bytes] = []
        aesgcm = AESGCM(key)
        while remaining:
            plaintext_length = min(chunk_size, remaining)
            end = offset + plaintext_length + 16
            nonce = nonce_prefix + counter.to_bytes(8, "big")
            aad = UTILS_PRIV3_MAGIC + header + counter.to_bytes(8, "big")
            chunks.append(aesgcm.decrypt(nonce, payload[offset:end], aad))
            offset = end
            remaining -= plaintext_length
            counter += 1
        return b"".join(chunks)


def utils_priv3_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        UTILS_PRIV3_READER_ID,
        "Utils HELTO_PRIV3 bytes",
        _UtilsPriv3Reader(),
        key_import_ids=(UTILS_PRIVACY_KEY_BIN_IMPORT_ID,),
    )
