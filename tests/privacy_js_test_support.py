from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "helto_privacy" / "web"


def write_privacy_client_dependencies(target: Path) -> None:
    """Copy dependency-neutral modules imported by the shared browser client."""

    for filename in ("privacy_records.js", "privacy_artifacts.js"):
        (target / filename).write_text(
            (WEB / filename).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
