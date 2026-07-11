"""Exact historical-key source validation and unchanged-source retirement."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ._atomic_file import sync_parent_directory


KEY_BYTES = 32
JSON_FORMAT = "json"
BINARY_FORMAT = "binary"
_MAX_JSON_BYTES = 16 * 1024


class LegacyKeySourceError(RuntimeError):
    """A path- and key-free exact-source failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Historical key source operation failed safely.")


@dataclass(frozen=True, slots=True)
class LegacyKeySource:
    path: Path = field(repr=False)
    source_format: str
    key_id: str
    key: bytes = field(repr=False)
    device: int = field(repr=False)
    inode: int = field(repr=False)
    content_digest: bytes = field(repr=False)


def read_legacy_key_source(
    path: str | os.PathLike[str],
    source_format: str,
) -> LegacyKeySource:
    """Read one regular non-symlink source and validate its exact bytes."""

    if source_format not in {JSON_FORMAT, BINARY_FORMAT}:
        raise LegacyKeySourceError("legacy_key_format_invalid")
    source_path = Path(path)
    descriptor = _open_source(source_path)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise LegacyKeySourceError("legacy_key_source_invalid")
        payload = _read_bounded(
            descriptor,
            KEY_BYTES if source_format == BINARY_FORMAT else _MAX_JSON_BYTES,
        )
    finally:
        os.close(descriptor)

    if source_format == BINARY_FORMAT:
        if len(payload) != KEY_BYTES:
            raise LegacyKeySourceError("legacy_key_source_invalid")
        key = payload
        key_id = _key_id_for(key)
    else:
        key, key_id = _parse_json_key(payload)
    return LegacyKeySource(
        path=source_path,
        source_format=source_format,
        key_id=key_id,
        key=key,
        device=details.st_dev,
        inode=details.st_ino,
        content_digest=hashlib.sha256(payload).digest(),
    )


def unlink_unchanged_legacy_key_source(source: LegacyKeySource) -> None:
    """Lock, re-read, compare, unlink, and sync only the verified source bytes."""

    descriptor = _open_source(source.path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        details = os.fstat(descriptor)
        payload = _read_bounded(
            descriptor,
            KEY_BYTES if source.source_format == BINARY_FORMAT else _MAX_JSON_BYTES,
        )
        current_path = source.path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or (details.st_dev, details.st_ino) != (source.device, source.inode)
            or (current_path.st_dev, current_path.st_ino) != (source.device, source.inode)
            or not hmac.compare_digest(
                hashlib.sha256(payload).digest(),
                source.content_digest,
            )
        ):
            raise LegacyKeySourceError("legacy_key_source_changed")
        source.path.unlink()
        sync_parent_directory(source.path)
    except LegacyKeySourceError:
        raise
    except OSError:
        raise LegacyKeySourceError("legacy_key_source_unlink_failed") from None
    finally:
        os.close(descriptor)


def _open_source(path: Path) -> int:
    try:
        return os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (OSError, TypeError, ValueError):
        raise LegacyKeySourceError("legacy_key_source_invalid") from None


def _read_bounded(descriptor: int, limit: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_json_key(payload: bytes) -> tuple[bytes, str]:
    try:
        document = json.loads(payload.decode("utf-8"))
        if (
            not isinstance(document, dict)
            or set(document) != {"version", "algorithm", "keyId", "key"}
            or document.get("version") != 1
            or document.get("algorithm") != "AES-256-GCM"
        ):
            raise ValueError
        encoded_key = str(document.get("key") or "")
        key = _b64decode(encoded_key)
        key_id = str(document.get("keyId") or "")
        if (
            len(key) != KEY_BYTES
            or _b64encode(key) != encoded_key
            or key_id != _key_id_for(key)
        ):
            raise ValueError
        return key, key_id
    except Exception:
        raise LegacyKeySourceError("legacy_key_source_invalid") from None


def _key_id_for(key: bytes) -> str:
    return _b64encode(hashlib.sha256(key).digest()[:12])


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
