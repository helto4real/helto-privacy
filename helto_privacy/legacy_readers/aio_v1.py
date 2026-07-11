"""AIO Image Generate v1 historical state reader removal unit."""

from __future__ import annotations

from ..migration import LegacyReaderUnit
from ._state_envelope import ExactStateEnvelopeReader


AIO_V1_READER_ID = "aio-state-v1"
AIO_V1_JSON_KEY_IMPORT_ID = "aio-json-key-v1"
AIO_V1_SCHEMA = "helto.aio-image-generate"


class _AioV1Reader(ExactStateEnvelopeReader):
    def __init__(self) -> None:
        super().__init__(AIO_V1_SCHEMA, AIO_V1_JSON_KEY_IMPORT_ID)


def aio_v1_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        AIO_V1_READER_ID,
        "AIO state v1",
        _AioV1Reader(),
        key_import_ids=(AIO_V1_JSON_KEY_IMPORT_ID,),
    )
