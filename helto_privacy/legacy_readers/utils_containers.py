"""Exact Utils workflow and queue container reader units."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from ..envelope import ALGORITHM, PrivacyEnvelopeCodec

from ..migration import LegacyReaderUnit
from ._utils_common import (
    UTILS_QUEUE_PREFIX,
    UTILS_WORKFLOW_PREFIX,
    decode_json_object,
    raw_xor_source,
    standard_b64decode,
)
from .utils_priv1 import (
    UTILS_PRIV1_MAGIC,
    UTILS_PRIV1_READER_ID,
    utils_priv1_reader_unit,
)
from .utils_priv2 import (
    UTILS_PRIV2_MAGIC,
    UTILS_PRIV2_READER_ID,
    utils_priv2_reader_unit,
)
from .utils_priv3 import (
    UTILS_PRIV3_MAGIC,
    UTILS_PRIV3_READER_ID,
    utils_priv3_reader_unit,
)
from .utils_raw_xor import UTILS_RAW_XOR_READER_ID, utils_raw_xor_reader_unit
from .utils_provider_settings import utils_provider_settings_reader_units


_GENERATIONS = ("raw-xor", "priv1", "priv2", "priv3")
_AUTHENTICATED_MAGICS = (UTILS_PRIV1_MAGIC, UTILS_PRIV2_MAGIC, UTILS_PRIV3_MAGIC)
UTILS_WORKFLOW_READER_IDS = MappingProxyType(
    {generation: f"utils-workflow-{generation}-v1" for generation in _GENERATIONS}
)
UTILS_QUEUE_JSON_READER_IDS = MappingProxyType(
    {
        generation: f"utils-queue-json-{generation}-v1"
        for generation in _GENERATIONS[1:]
    }
)
UTILS_QUEUE_SQLITE_READER_IDS = MappingProxyType(
    {
        generation: f"utils-queue-sqlite-{generation}-v1"
        for generation in _GENERATIONS[1:]
    }
)
UTILS_QUEUE_CURRENT_JSON_READER_ID = "utils-queue-current-json-v1"
UTILS_QUEUE_CURRENT_SQLITE_READER_ID = "utils-queue-current-sqlite-v1"
_CURRENT_SCHEMA = "helto.comfyui-utils"
_QUEUE_PURPOSE = "queue-manager-state"


def _generation_units() -> dict[str, LegacyReaderUnit]:
    return {
        "raw-xor": utils_raw_xor_reader_unit(),
        "priv1": utils_priv1_reader_unit(),
        "priv2": utils_priv2_reader_unit(),
        "priv3": utils_priv3_reader_unit(),
    }


def _source_for_generation(generation: str, payload: bytes, location: str) -> object:
    return raw_xor_source(payload, location) if generation == "raw-xor" else payload


class _UtilsWorkflowReader:
    def __init__(self, generation: str, byte_reader: object) -> None:
        self._generation = generation
        self._byte_reader = byte_reader

    def probe(self, source: object, context: object) -> bool:
        if not isinstance(source, str) or not source.startswith(UTILS_WORKFLOW_PREFIX):
            return False
        try:
            payload = standard_b64decode(source[len(UTILS_WORKFLOW_PREFIX) :])
        except ValueError:
            return False
        if self._generation == "raw-xor" and payload.startswith(
            _AUTHENTICATED_MAGICS
        ):
            return False
        candidate = _source_for_generation(
            self._generation,
            payload,
            "workflow-field",
        )
        return self._byte_reader.probe(candidate, context) is True

    def read(self, source: object, context: object) -> str:
        if not self.probe(source, context):
            raise ValueError("Historical Utils workflow value is invalid.")
        payload = standard_b64decode(source[len(UTILS_WORKFLOW_PREFIX) :])
        candidate = _source_for_generation(
            self._generation,
            payload,
            "workflow-field",
        )
        return self._byte_reader.read(candidate, context).decode("utf-8")


class _UtilsQueueJsonReader:
    _FIELDS = {
        "version",
        "privacy_enabled",
        "server_session_id",
        "payload",
    }

    def __init__(self, byte_reader: object) -> None:
        self._byte_reader = byte_reader

    def probe(self, source: object, context: object) -> bool:
        if (
            not isinstance(source, Mapping)
            or set(source) != self._FIELDS
            or source.get("version") != 1
            or source.get("privacy_enabled") is not True
            or not isinstance(source.get("server_session_id"), str)
            or not source.get("server_session_id")
        ):
            return False
        payload = source.get("payload")
        if not isinstance(payload, str) or not payload.startswith(UTILS_QUEUE_PREFIX):
            return False
        try:
            encrypted = standard_b64decode(payload[len(UTILS_QUEUE_PREFIX) :])
        except ValueError:
            return False
        return self._byte_reader.probe(encrypted, context) is True

    def read(self, source: object, context: object) -> dict[str, object]:
        if not self.probe(source, context):
            raise ValueError("Historical Utils queue JSON is invalid.")
        encrypted = standard_b64decode(
            source["payload"][len(UTILS_QUEUE_PREFIX) :]
        )
        return decode_json_object(self._byte_reader.read(encrypted, context))


class _UtilsQueueSqliteReader:
    _FIELDS = {
        "version",
        "privacy_enabled",
        "encrypted_at_rest",
        "server_session_id",
        "updated_at",
        "payload",
    }

    def __init__(self, byte_reader: object) -> None:
        self._byte_reader = byte_reader

    def probe(self, source: object, context: object) -> bool:
        if (
            not isinstance(source, Mapping)
            or set(source) != self._FIELDS
            or source.get("version") != 1
            or source.get("privacy_enabled") is not True
            or source.get("encrypted_at_rest") is not True
            or not isinstance(source.get("server_session_id"), str)
            or not source.get("server_session_id")
            or not isinstance(source.get("updated_at"), int)
            or isinstance(source.get("updated_at"), bool)
        ):
            return False
        try:
            encrypted = standard_b64decode(source.get("payload"))
        except ValueError:
            return False
        return self._byte_reader.probe(encrypted, context) is True

    def read(self, source: object, context: object) -> dict[str, object]:
        if not self.probe(source, context):
            raise ValueError("Historical Utils queue SQLite row is invalid.")
        encrypted = standard_b64decode(source["payload"])
        return decode_json_object(self._byte_reader.read(encrypted, context))


class _UtilsQueueCurrentJsonReader:
    _PAYLOAD_FIELDS = {"version", "privacy_enabled", "server_session_id", "payload"}
    _STATE_FIELDS = {"version", "privacy_enabled", "server_session_id", "state"}

    def probe(self, source: object, _context: object) -> bool:
        if (
            not isinstance(source, Mapping)
            or frozenset(source)
            not in {frozenset(self._PAYLOAD_FIELDS), frozenset(self._STATE_FIELDS)}
            or source.get("version") != 1
            or not isinstance(source.get("server_session_id"), str)
            or not source.get("server_session_id")
        ):
            return False
        if source.get("privacy_enabled") is False:
            value = source.get("payload") if "payload" in source else source.get("state")
            return isinstance(value, Mapping)
        if source.get("privacy_enabled") is not True or not isinstance(
            source.get("payload"), str
        ):
            return False
        try:
            envelope = decode_json_object(source["payload"].encode("utf-8"))
        except ValueError:
            return False
        return PrivacyEnvelopeCodec(_CURRENT_SCHEMA).is_encrypted_payload(envelope)

    def read(self, source: object, context: object) -> dict[str, object]:
        if not self.probe(source, context):
            raise ValueError("Current Utils queue JSON is invalid.")
        if source.get("privacy_enabled") is False:
            value = source.get("payload") if "payload" in source else source.get("state")
            return dict(value)
        decoded = PrivacyEnvelopeCodec(_CURRENT_SCHEMA).decrypt_state(
            decode_json_object(source["payload"].encode("utf-8"))
        )
        state = decoded.get("state") if isinstance(decoded, Mapping) else None
        if not isinstance(state, Mapping):
            raise ValueError("Current Utils queue JSON is invalid.")
        return dict(state)


class _UtilsQueueCurrentSqliteReader:
    _FIELDS = {
        "version",
        "privacy_enabled",
        "encrypted_at_rest",
        "server_session_id",
        "updated_at",
        "payload",
    }

    def probe(self, source: object, _context: object) -> bool:
        if (
            not isinstance(source, Mapping)
            or set(source) != self._FIELDS
            or source.get("version") != 1
            or not isinstance(source.get("server_session_id"), str)
            or not source.get("server_session_id")
            or not isinstance(source.get("updated_at"), int)
            or isinstance(source.get("updated_at"), bool)
        ):
            return False
        try:
            payload = standard_b64decode(source.get("payload"))
        except ValueError:
            return False
        if (
            source.get("privacy_enabled") is False
            and source.get("encrypted_at_rest") is False
        ):
            try:
                decode_json_object(payload)
            except ValueError:
                return False
            return True
        if (
            source.get("privacy_enabled") is not True
            or source.get("encrypted_at_rest") is not True
        ):
            return False
        try:
            envelope = decode_json_object(payload)
        except ValueError:
            return False
        codec = PrivacyEnvelopeCodec(_CURRENT_SCHEMA)
        return (
            envelope.get("encrypted") is True
            and envelope.get("algorithm") == ALGORITHM
            and envelope.get("purpose") == _QUEUE_PURPOSE
            and envelope.get("schema")
            in {codec.byte_schema, codec.chunked_byte_schema}
        )

    def read(self, source: object, context: object) -> dict[str, object]:
        if not self.probe(source, context):
            raise ValueError("Current Utils queue SQLite row is invalid.")
        payload = standard_b64decode(source["payload"])
        if source.get("encrypted_at_rest") is False:
            return decode_json_object(payload)
        envelope = decode_json_object(payload)
        decoded = PrivacyEnvelopeCodec(_CURRENT_SCHEMA).decrypt_bytes(
            envelope,
            _QUEUE_PURPOSE,
        )
        return decode_json_object(decoded)


def utils_workflow_reader_units() -> tuple[LegacyReaderUnit, ...]:
    units = _generation_units()
    return tuple(
        LegacyReaderUnit(
            UTILS_WORKFLOW_READER_IDS[generation],
            f"Utils {generation} workflow container",
            _UtilsWorkflowReader(generation, units[generation].reader),
            dependencies=(units[generation].id,),
            key_import_ids=units[generation].key_import_ids,
        )
        for generation in _GENERATIONS
    )


def utils_queue_reader_units() -> tuple[LegacyReaderUnit, ...]:
    units = _generation_units()
    readers: list[LegacyReaderUnit] = []
    for generation in _GENERATIONS[1:]:
        unit = units[generation]
        readers.extend(
            (
                LegacyReaderUnit(
                    UTILS_QUEUE_JSON_READER_IDS[generation],
                    f"Utils {generation} queue JSON container",
                    _UtilsQueueJsonReader(unit.reader),
                    dependencies=(unit.id,),
                    key_import_ids=unit.key_import_ids,
                ),
                LegacyReaderUnit(
                    UTILS_QUEUE_SQLITE_READER_IDS[generation],
                    f"Utils {generation} queue SQLite container",
                    _UtilsQueueSqliteReader(unit.reader),
                    dependencies=(unit.id,),
                    key_import_ids=unit.key_import_ids,
                ),
            )
        )
    readers.extend(
        (
            LegacyReaderUnit(
                UTILS_QUEUE_CURRENT_JSON_READER_ID,
                "Utils current queue JSON container",
                _UtilsQueueCurrentJsonReader(),
            ),
            LegacyReaderUnit(
                UTILS_QUEUE_CURRENT_SQLITE_READER_ID,
                "Utils current queue SQLite container",
                _UtilsQueueCurrentSqliteReader(),
            ),
        )
    )
    return tuple(readers)


def utils_legacy_reader_units() -> tuple[LegacyReaderUnit, ...]:
    """Return one dependency-complete registration set for Utils history."""

    return (
        utils_raw_xor_reader_unit(),
        utils_priv1_reader_unit(),
        utils_priv2_reader_unit(),
        utils_priv3_reader_unit(),
        *utils_workflow_reader_units(),
        *utils_queue_reader_units(),
        *utils_provider_settings_reader_units(),
    )
