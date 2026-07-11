"""Smart Prompt Manager v1 state and export reader removal units."""

from __future__ import annotations

import json
from collections.abc import Mapping

from ..migration import LegacyReaderUnit
from ._state_envelope import ExactStateEnvelopeReader


SMART_PROMPT_V1_READER_ID = "smart-prompt-state-v1"
SMART_PROMPT_V1_EXPORT_READER_ID = "smart-prompt-export-v1"
SMART_PROMPT_V1_JSON_KEY_IMPORT_ID = "smart-prompt-json-key-v1"
SMART_PROMPT_V1_SCHEMA = "comfyui-helto-prompts.smart-prompt-manager"
SMART_PROMPT_V1_EXPORT_FORMAT = "comfyui-helto-prompts.smart-prompt-manager.export"


class _SmartPromptV1Reader(ExactStateEnvelopeReader):
    def __init__(self) -> None:
        super().__init__(SMART_PROMPT_V1_SCHEMA, SMART_PROMPT_V1_JSON_KEY_IMPORT_ID)


class _SmartPromptExportV1Reader:
    _FIELDS = {"format", "version", "encrypted", "spm_data", "exportedAt"}

    def __init__(self) -> None:
        self._state_reader = _SmartPromptV1Reader()

    def probe(self, source: object, context: object) -> bool:
        package = self._package(source)
        return (
            package is not None
            and set(package) == self._FIELDS
            and package.get("format") == SMART_PROMPT_V1_EXPORT_FORMAT
            and package.get("version") == 1
            and package.get("encrypted") is True
            and isinstance(package.get("exportedAt"), str)
            and bool(str(package.get("exportedAt") or "").strip())
            and self._state_reader.probe(package.get("spm_data"), context)
        )

    def read(self, source: object, context: object) -> dict[str, object]:
        package = self._package(source)
        if package is None or not self.probe(package, context):
            raise ValueError("Historical Smart Prompt export is not an exact supported format.")
        return self._state_reader.read(package["spm_data"], context)

    @staticmethod
    def _package(source: object) -> dict[str, object] | None:
        if isinstance(source, str):
            try:
                source = json.loads(source)
            except (TypeError, ValueError):
                return None
        return dict(source) if isinstance(source, Mapping) else None


def smart_prompt_v1_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        SMART_PROMPT_V1_READER_ID,
        "Smart Prompt state v1",
        _SmartPromptV1Reader(),
        key_import_ids=(SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,),
    )


def smart_prompt_v1_export_reader_unit() -> LegacyReaderUnit:
    return LegacyReaderUnit(
        SMART_PROMPT_V1_EXPORT_READER_ID,
        "Smart Prompt export v1",
        _SmartPromptExportV1Reader(),
        dependencies=(SMART_PROMPT_V1_READER_ID,),
        key_import_ids=(SMART_PROMPT_V1_JSON_KEY_IMPORT_ID,),
    )
