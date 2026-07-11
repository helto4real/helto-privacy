"""Reusable product adapter primitives with fixed privacy semantics."""

from __future__ import annotations

from collections.abc import Mapping


class PrivateByDefaultModeAdapter:
    """In-memory declared-mode adapter for private-by-default product scopes."""

    def __init__(self, declarations: Mapping[str, object] | None = None) -> None:
        self._declarations = dict(declarations or {})

    def read_declared_mode(self, scope_id: str) -> str:
        value = self._declarations.get(scope_id, "private")
        return "public" if value in {False, "public"} else "private"

    def write_declared_mode(self, scope_id: str, mode: object) -> None:
        if mode not in {"private", "public"}:
            raise ValueError("Invalid declared privacy mode.")
        self._declarations[scope_id] = mode

    def prepare_mode_transition(self, *_args) -> None:
        return None

    def commit_mode_transition(self, *_args) -> None:
        return None

    def rollback_mode_transition(self, *_args) -> None:
        return None
