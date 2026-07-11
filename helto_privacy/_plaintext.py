"""Internal best-effort clearing for mutable semantic plaintext containers."""

from __future__ import annotations


def clear_mutable_plaintext(
    value: object,
    seen: set[int] | None = None,
) -> None:
    """Recursively clear built-in mutable containers without retaining values."""

    if value is None:
        return
    seen = seen or set()
    identity = id(value)
    if identity in seen:
        return
    seen.add(identity)
    if isinstance(value, dict):
        for item in tuple(value.values()):
            clear_mutable_plaintext(item, seen)
        value.clear()
    elif isinstance(value, list):
        for item in value:
            clear_mutable_plaintext(item, seen)
        value.clear()
    elif isinstance(value, tuple):
        for item in value:
            clear_mutable_plaintext(item, seen)
    elif isinstance(value, set):
        for item in tuple(value):
            clear_mutable_plaintext(item, seen)
        value.clear()
