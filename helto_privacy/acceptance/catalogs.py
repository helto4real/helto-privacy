"""Built-in acceptance and historical-fixture catalogs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .fixtures import HistoricalFixtureCatalog, load_historical_fixture_catalog
from .models import AcceptanceCatalog, AcceptanceError, load_acceptance_catalog


ACCEPTANCE_DATA_ROOT = Path(__file__).resolve().parent / "data"
BUILTIN_ACCEPTANCE_CATALOG = ACCEPTANCE_DATA_ROOT / "catalog-v2.json"
BUILTIN_HISTORICAL_FIXTURE_CATALOG = (
    ACCEPTANCE_DATA_ROOT / "historical-fixtures-v1.json"
)
BUILTIN_FIXTURE_GENERATOR_ENVIRONMENT = (
    ACCEPTANCE_DATA_ROOT / "generator-environment-v1.json"
)


def load_builtin_acceptance_catalog() -> AcceptanceCatalog:
    catalog = load_acceptance_catalog(BUILTIN_ACCEPTANCE_CATALOG)
    fixtures = load_builtin_historical_fixture_catalog()
    if catalog.fixture_catalog_sha256 != fixtures.digest:
        raise AcceptanceError("builtin_fixture_catalog_digest_mismatch")
    fixture_ids = {entry.id for entry in fixtures.entries}
    if any(
        fixture_id not in fixture_ids
        for requirement in catalog.requirements
        for fixture_id in requirement.fixture_ids
    ):
        raise AcceptanceError("unknown_catalog_fixture_reference")
    return catalog


def load_builtin_historical_fixture_catalog() -> HistoricalFixtureCatalog:
    catalog = load_historical_fixture_catalog(BUILTIN_HISTORICAL_FIXTURE_CATALOG)
    try:
        environment_bytes = BUILTIN_FIXTURE_GENERATOR_ENVIRONMENT.read_bytes()
        environment_digest = hashlib.sha256(environment_bytes).hexdigest()
        environment = json.loads(environment_bytes)
        generator_digest = hashlib.sha256(
            (Path(__file__).resolve().parent / "generate_fixtures.py").read_bytes()
        ).hexdigest()
    except (OSError, ValueError, TypeError):
        raise AcceptanceError("fixture_generator_environment_missing") from None
    if (
        not isinstance(environment, dict)
        or environment.get("generatorSha256") != generator_digest
    ):
        raise AcceptanceError("fixture_generator_source_mismatch")
    if any(
        entry.generator_environment_sha256 != environment_digest
        for entry in catalog.entries
    ):
        raise AcceptanceError("fixture_generator_environment_mismatch")
    return catalog
