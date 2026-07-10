"""Atomic private-file persistence shared by privacy authority records."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_private_bytes(path: Path, payload: bytes) -> None:
    """Durably replace one private file and its directory entry."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
        sync_parent_directory(path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def sync_parent_directory(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
