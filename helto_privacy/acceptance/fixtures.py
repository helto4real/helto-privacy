"""Genuine historical fixture catalog and deterministic regeneration seams."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .._suite_codec import canonical_json_bytes, is_sha256, is_stable_id, typed_tuple
from ..suite import SourceIdentity
from .models import AcceptanceError


HISTORICAL_FIXTURE_CATALOG_V1 = "helto.privacy.historical-fixtures.v1"


class FixtureKind(str, Enum):
    HISTORICAL = "historical"
    DERIVED = "derived"


@dataclass(frozen=True, slots=True)
class HistoricalFixtureEntry:
    id: str
    kind: FixtureKind
    source_path: str
    fixture_sha256: str
    ciphertext_sha256: str
    expected_normalized_sha256: str
    reader_id: str
    format: str
    schema: str | None
    purpose: str | None
    producer_repository: str | None
    producer_commit: str | None
    producer_function: str | None
    generator_command: tuple[str, ...]
    generator_environment: str
    generator_environment_sha256: str
    key_provenance: str | None
    source_fixture_id: str | None = None
    mutation: str | None = None

    def __post_init__(self) -> None:
        for value, code in (
            (self.id, "invalid_fixture_id"),
            (self.reader_id, "invalid_fixture_reader"),
            (self.format, "invalid_fixture_format"),
            (self.generator_environment, "invalid_generator_environment"),
        ):
            if not is_stable_id(value):
                raise AcceptanceError(code)
        if not isinstance(self.kind, FixtureKind):
            raise AcceptanceError("invalid_fixture_kind")
        if (
            not isinstance(self.source_path, str)
            or not self.source_path
            or self.source_path.startswith("/")
            or ".." in Path(self.source_path).parts
        ):
            raise AcceptanceError("invalid_fixture_path")
        for digest in (
            self.fixture_sha256,
            self.ciphertext_sha256,
            self.expected_normalized_sha256,
        ):
            if not is_sha256(digest):
                raise AcceptanceError("invalid_fixture_digest")
        command = tuple(self.generator_command)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise AcceptanceError("invalid_generator_command")
        object.__setattr__(self, "generator_command", command)
        if not is_sha256(self.generator_environment_sha256):
            raise AcceptanceError("invalid_generator_environment_digest")
        for optional in (self.schema, self.purpose):
            if optional is not None and not is_stable_id(optional):
                raise AcceptanceError("invalid_fixture_binding")
        if self.kind is FixtureKind.HISTORICAL:
            required = (
                self.producer_repository,
                self.producer_commit,
                self.producer_function,
                self.key_provenance,
            )
            if any(not isinstance(value, str) or not value for value in required):
                raise AcceptanceError("missing_historical_provenance")
            try:
                SourceIdentity(self.producer_repository, self.producer_commit)
            except Exception:
                raise AcceptanceError("invalid_historical_source_identity") from None
            if self.source_fixture_id is not None or self.mutation is not None:
                raise AcceptanceError("historical_fixture_marked_derived")
        else:
            if not is_stable_id(self.source_fixture_id) or not is_stable_id(self.mutation):
                raise AcceptanceError("missing_derived_fixture_provenance")


@dataclass(frozen=True, slots=True)
class HistoricalFixtureCatalog:
    id: str
    version: int
    entries: tuple[HistoricalFixtureEntry, ...]
    schema: str = HISTORICAL_FIXTURE_CATALOG_V1

    def __post_init__(self) -> None:
        if not is_stable_id(self.id):
            raise AcceptanceError("invalid_fixture_catalog_id")
        if self.schema != HISTORICAL_FIXTURE_CATALOG_V1:
            raise AcceptanceError("fixture_catalog_schema_mismatch")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise AcceptanceError("invalid_fixture_catalog_version")
        entries = typed_tuple(
            self.entries,
            HistoricalFixtureEntry,
            "invalid_fixture_entry",
            AcceptanceError,
        )
        if not entries:
            raise AcceptanceError("missing_fixture_entry")
        ids = tuple(entry.id for entry in entries)
        if len(ids) != len(set(ids)):
            raise AcceptanceError("duplicate_fixture_id")
        historical_ids = {
            entry.id for entry in entries if entry.kind is FixtureKind.HISTORICAL
        }
        if any(
            entry.kind is FixtureKind.DERIVED
            and entry.source_fixture_id not in historical_ids
            for entry in entries
        ):
            raise AcceptanceError("unknown_derived_fixture_source")
        object.__setattr__(self, "entries", tuple(sorted(entries, key=lambda item: item.id)))

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "id": self.id,
                "schema": self.schema,
                "version": self.version,
                "entries": [
                    {
                        "id": entry.id,
                        "kind": entry.kind.value,
                        "sourcePath": entry.source_path,
                        "fixtureSha256": entry.fixture_sha256,
                        "ciphertextSha256": entry.ciphertext_sha256,
                        "expectedNormalizedSha256": entry.expected_normalized_sha256,
                        "readerId": entry.reader_id,
                        "format": entry.format,
                        "schema": entry.schema,
                        "purpose": entry.purpose,
                        "producerRepository": entry.producer_repository,
                        "producerCommit": entry.producer_commit,
                        "producerFunction": entry.producer_function,
                        "generatorCommand": list(entry.generator_command),
                        "generatorEnvironment": entry.generator_environment,
                        "generatorEnvironmentSha256": entry.generator_environment_sha256,
                        "keyProvenance": entry.key_provenance,
                        "sourceFixtureId": entry.source_fixture_id,
                        "mutation": entry.mutation,
                    }
                    for entry in self.entries
                ],
            }
        )


def load_historical_fixture_catalog(path: str | Path) -> HistoricalFixtureCatalog:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = tuple(
            HistoricalFixtureEntry(
                id=item["id"],
                kind=FixtureKind(item["kind"]),
                source_path=item["sourcePath"],
                fixture_sha256=item["fixtureSha256"],
                ciphertext_sha256=item["ciphertextSha256"],
                expected_normalized_sha256=item["expectedNormalizedSha256"],
                reader_id=item["readerId"],
                format=item["format"],
                schema=item.get("schema"),
                purpose=item.get("purpose"),
                producer_repository=item.get("producerRepository"),
                producer_commit=item.get("producerCommit"),
                producer_function=item.get("producerFunction"),
                generator_command=tuple(item["generatorCommand"]),
                generator_environment=item["generatorEnvironment"],
                generator_environment_sha256=item["generatorEnvironmentSha256"],
                key_provenance=item.get("keyProvenance"),
                source_fixture_id=item.get("sourceFixtureId"),
                mutation=item.get("mutation"),
            )
            for item in payload["entries"]
        )
        return HistoricalFixtureCatalog(
            id=payload["id"],
            version=payload["version"],
            entries=entries,
            schema=payload["schema"],
        )
    except AcceptanceError:
        raise
    except Exception:
        raise AcceptanceError("fixture_catalog_load_failed") from None


def verify_fixture_files(catalog: HistoricalFixtureCatalog, root: str | Path) -> None:
    if not isinstance(catalog, HistoricalFixtureCatalog):
        raise AcceptanceError("invalid_fixture_catalog")
    root_path = Path(root)
    for entry in catalog.entries:
        try:
            payload = (root_path / entry.source_path).read_bytes()
        except OSError:
            raise AcceptanceError("fixture_file_missing") from None
        if hashlib.sha256(payload).hexdigest() != entry.fixture_sha256:
            raise AcceptanceError("fixture_file_digest_mismatch")


def verify_regenerated_fixtures(
    catalog: HistoricalFixtureCatalog,
    generator: Callable[[HistoricalFixtureEntry], bytes],
) -> None:
    if not isinstance(catalog, HistoricalFixtureCatalog) or not callable(generator):
        raise AcceptanceError("invalid_fixture_generator")
    for entry in catalog.entries:
        try:
            payload = generator(entry)
        except Exception:
            raise AcceptanceError("fixture_generation_failed") from None
        if not isinstance(payload, bytes) or hashlib.sha256(payload).hexdigest() != entry.fixture_sha256:
            raise AcceptanceError("fixture_generation_mismatch")
