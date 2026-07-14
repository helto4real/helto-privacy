"""Bounded authenticated byte streams for managed artifact payloads."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
from pathlib import Path
from threading import Event
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PRIVATE_STREAM_MAGIC = b"HPASTRM2"
PRIVATE_STREAM_FOOTER_MAGIC = b"HPAFTR2!"
PRIVATE_STREAM_VERSION = 2
PRIVATE_STREAM_ALGORITHM = "AES-256-GCM-HKDF-SHA256-CHUNKED"
PRIVATE_STREAM_HEADER_MAX_BYTES = 4096
PRIVATE_STREAM_FOOTER_BYTES = 8 + 8 + 8 + 32 + 16
PRIVATE_STREAM_TAG_BYTES = 16
PRIVATE_STREAM_MANIFEST_NONCE = b"\xff" * 12
_HEADER_PREFIX = struct.Struct(">8sI")
_FRAME_PREFIX = struct.Struct(">I")
_FOOTER_CORE = struct.Struct(">8sQQ32s")
_MAX_COUNTER = (1 << 96) - 2


class ArtifactStreamError(RuntimeError):
    """Sanitized internal framing or bounded-I/O failure."""


class ArtifactStreamCancelled(BaseException):
    """Cooperative cancellation observed by a synchronous codec capability."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ArtifactStreamError()
    try:
        return base64.urlsafe_b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii")
        )
    except Exception:
        raise ArtifactStreamError() from None


def _derive_key(
    master_key: bytes,
    salt: bytes,
    contract_digest: str,
    artifact_id: str,
    owner_id: str,
) -> bytes:
    if len(master_key) != 32 or len(salt) != 16:
        raise ArtifactStreamError()
    info = (
        "helto.private-artifact-stream.v2|"
        f"{contract_digest}|{artifact_id}|{owner_id}"
    ).encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(master_key)


def _chunk_nonce(index: int) -> bytes:
    if type(index) is not int or index < 0 or index > _MAX_COUNTER:
        raise ArtifactStreamError()
    return index.to_bytes(12, "big")


def _chunk_aad(
    header_digest: bytes,
    contract_digest: str,
    artifact_id: str,
    index: int,
    plaintext_size: int,
) -> bytes:
    return b"|".join(
        (
            b"helto.private-artifact-stream.chunk.v2",
            header_digest.hex().encode("ascii"),
            contract_digest.encode("ascii"),
            artifact_id.encode("ascii"),
            str(index).encode("ascii"),
            str(plaintext_size).encode("ascii"),
        )
    )


def _manifest_aad(header_digest: bytes, footer_core: bytes) -> bytes:
    return b"|".join(
        (
            b"helto.private-artifact-stream.manifest.v2",
            header_digest.hex().encode("ascii"),
            footer_core,
        )
    )


class BoundedArtifactSink:
    """Invocation-scoped forward-only codec sink."""

    __slots__ = (
        "_cancel",
        "_closed",
        "_write",
        "max_chunk_bytes",
        "total_bytes",
    )

    def __init__(
        self,
        max_chunk_bytes: int,
        write: Callable[[memoryview], None],
        cancel: Event | None = None,
    ) -> None:
        self.max_chunk_bytes = max_chunk_bytes
        self._write = write
        self._cancel = cancel
        self._closed = False
        self.total_bytes = 0

    def __repr__(self) -> str:
        return "BoundedArtifactSink()"

    def write(self, value) -> int:
        if self._closed:
            raise ArtifactStreamError()
        if self._cancel is not None and self._cancel.is_set():
            raise ArtifactStreamCancelled()
        try:
            view = memoryview(value).cast("B")
        except (TypeError, ValueError):
            raise ArtifactStreamError() from None
        size = len(view)
        if size < 1 or size > self.max_chunk_bytes:
            raise ArtifactStreamError()
        self._write(view)
        self.total_bytes += size
        return size

    def close(self) -> None:
        self._closed = True
        self._write = _expired_write


def _expired_write(_value: memoryview) -> None:
    raise ArtifactStreamError()


class PrivateArtifactStreamWriter:
    """Write an HPA-v2 chunk-authenticated stream to one private handle."""

    __slots__ = (
        "_aes",
        "_artifact_id",
        "_closed",
        "_contract_digest",
        "_handle",
        "_header_digest",
        "_index",
        "_max_plaintext_bytes",
        "_total",
        "_transcript",
        "sink",
    )

    def __init__(
        self,
        handle,
        *,
        master_key: bytes,
        key_id: str,
        artifact_id: str,
        owner_id: str,
        contract_digest: str,
        codec_schema: str,
        codec_version: int,
        chunk_bytes: int,
        max_plaintext_bytes: int,
        cancel: Event | None = None,
    ) -> None:
        salt = secrets.token_bytes(16)
        header = {
            "algorithm": PRIVATE_STREAM_ALGORITHM,
            "artifactId": artifact_id,
            "chunkBytes": chunk_bytes,
            "codecSchema": codec_schema,
            "codecVersion": codec_version,
            "contractDigest": contract_digest,
            "keyId": key_id,
            "salt": _b64(salt),
            "schema": "helto.private-artifact-stream",
            "version": PRIVATE_STREAM_VERSION,
        }
        header_payload = _canonical_json(header)
        if len(header_payload) > PRIVATE_STREAM_HEADER_MAX_BYTES:
            raise ArtifactStreamError()
        prefix = _HEADER_PREFIX.pack(PRIVATE_STREAM_MAGIC, len(header_payload))
        handle.write(prefix)
        handle.write(header_payload)
        self._handle = handle
        self._artifact_id = artifact_id
        self._contract_digest = contract_digest
        self._header_digest = hashlib.sha256(prefix + header_payload).digest()
        self._transcript = hashlib.sha256(prefix + header_payload)
        self._aes = AESGCM(
            _derive_key(master_key, salt, contract_digest, artifact_id, owner_id)
        )
        self._index = 0
        self._total = 0
        self._max_plaintext_bytes = max_plaintext_bytes
        self._closed = False
        self.sink = BoundedArtifactSink(chunk_bytes, self._write_chunk, cancel)

    def _write_chunk(self, chunk: memoryview) -> None:
        size = len(chunk)
        if self._total > self._max_plaintext_bytes - size:
            raise ArtifactStreamError()
        ciphertext = self._aes.encrypt(
            _chunk_nonce(self._index),
            bytes(chunk),
            _chunk_aad(
                self._header_digest,
                self._contract_digest,
                self._artifact_id,
                self._index,
                size,
            ),
        )
        frame = _FRAME_PREFIX.pack(len(ciphertext))
        self._handle.write(frame)
        self._handle.write(ciphertext)
        self._transcript.update(frame)
        self._transcript.update(ciphertext)
        self._index += 1
        self._total += size

    def finish(self) -> int:
        if self._closed:
            raise ArtifactStreamError()
        if self._index == 0:
            self._write_chunk(memoryview(b""))
        digest = self._transcript.digest()
        footer_core = _FOOTER_CORE.pack(
            PRIVATE_STREAM_FOOTER_MAGIC,
            self._index,
            self._total,
            digest,
        )
        tag = self._aes.encrypt(
            PRIVATE_STREAM_MANIFEST_NONCE,
            b"",
            _manifest_aad(self._header_digest, footer_core),
        )
        self._handle.write(footer_core)
        self._handle.write(tag)
        self._closed = True
        self.sink.close()
        return self._total

    def abort(self) -> None:
        self._closed = True
        self.sink.close()


class BoundedArtifactSource:
    """Invocation-scoped forward-only authenticated codec source."""

    __slots__ = (
        "_aes",
        "_artifact_id",
        "_cancel",
        "_closed",
        "_contract_digest",
        "_footer_offset",
        "_handle",
        "_header_digest",
        "_index",
        "_pending",
        "_pending_offset",
        "_total_chunks",
        "_total_plaintext",
        "_total_read",
        "max_chunk_bytes",
    )

    def __init__(
        self,
        handle,
        *,
        aes: AESGCM,
        artifact_id: str,
        contract_digest: str,
        header_digest: bytes,
        payload_offset: int,
        footer_offset: int,
        total_chunks: int,
        total_plaintext: int,
        max_chunk_bytes: int,
        cancel: Event | None,
    ) -> None:
        self._handle = handle
        self._aes = aes
        self._artifact_id = artifact_id
        self._contract_digest = contract_digest
        self._header_digest = header_digest
        self._footer_offset = footer_offset
        self._total_chunks = total_chunks
        self._total_plaintext = total_plaintext
        self.max_chunk_bytes = max_chunk_bytes
        self._cancel = cancel
        self._index = 0
        self._total_read = 0
        self._pending = b""
        self._pending_offset = 0
        self._closed = False
        handle.seek(payload_offset)

    def __repr__(self) -> str:
        return "BoundedArtifactSource()"

    def _next_plaintext(self) -> bytes:
        if self._index >= self._total_chunks:
            return b""
        position = self._handle.tell()
        if position + _FRAME_PREFIX.size > self._footer_offset:
            raise ArtifactStreamError()
        prefix = self._handle.read(_FRAME_PREFIX.size)
        if len(prefix) != _FRAME_PREFIX.size:
            raise ArtifactStreamError()
        (ciphertext_size,) = _FRAME_PREFIX.unpack(prefix)
        if (
            ciphertext_size < PRIVATE_STREAM_TAG_BYTES
            or ciphertext_size > self.max_chunk_bytes + PRIVATE_STREAM_TAG_BYTES
            or self._handle.tell() + ciphertext_size > self._footer_offset
        ):
            raise ArtifactStreamError()
        ciphertext = self._handle.read(ciphertext_size)
        if len(ciphertext) != ciphertext_size:
            raise ArtifactStreamError()
        plaintext_size = ciphertext_size - PRIVATE_STREAM_TAG_BYTES
        try:
            plaintext = self._aes.decrypt(
                _chunk_nonce(self._index),
                ciphertext,
                _chunk_aad(
                    self._header_digest,
                    self._contract_digest,
                    self._artifact_id,
                    self._index,
                    plaintext_size,
                ),
            )
        except Exception:
            raise ArtifactStreamError() from None
        self._index += 1
        self._total_read += len(plaintext)
        return plaintext

    def readinto(self, destination) -> int:
        if self._closed:
            raise ArtifactStreamError()
        if self._cancel is not None and self._cancel.is_set():
            raise ArtifactStreamCancelled()
        try:
            view = memoryview(destination).cast("B")
        except (TypeError, ValueError):
            raise ArtifactStreamError() from None
        if len(view) < 1 or len(view) > self.max_chunk_bytes or view.readonly:
            raise ArtifactStreamError()
        if self._pending_offset >= len(self._pending):
            self._pending = self._next_plaintext()
            self._pending_offset = 0
        if not self._pending:
            if (
                self._index != self._total_chunks
                or self._total_read != self._total_plaintext
                or self._handle.tell() != self._footer_offset
            ):
                raise ArtifactStreamError()
            return 0
        count = min(len(view), len(self._pending) - self._pending_offset)
        view[:count] = self._pending[self._pending_offset : self._pending_offset + count]
        self._pending_offset += count
        return count

    def read(self, size: int) -> bytes:
        if type(size) is not int or size < 1 or size > self.max_chunk_bytes:
            raise ArtifactStreamError()
        buffer = bytearray(size)
        count = self.readinto(buffer)
        return bytes(buffer[:count])

    def close(self) -> None:
        self._closed = True
        self._pending = b""
        self._handle.close()


def open_private_artifact_source(
    path: Path,
    *,
    key_for_id: Callable[[str], bytes | None],
    owner_id: str,
    artifact_id: str,
    contract_digest: str,
    codec_schema: str,
    codec_version: int,
    chunk_bytes: int,
    max_plaintext_bytes: int,
    expected_plaintext_bytes: int,
    cancel: Event | None = None,
):
    """Authenticate the complete ciphertext transcript before returning a source."""

    descriptor: int | None = None
    handle = None
    try:
        if (
            type(expected_plaintext_bytes) is not int
            or expected_plaintext_bytes < 0
            or expected_plaintext_bytes > max_plaintext_bytes
        ):
            raise ArtifactStreamError()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < (
            _HEADER_PREFIX.size + PRIVATE_STREAM_FOOTER_BYTES
        ):
            raise ArtifactStreamError()
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        prefix = handle.read(_HEADER_PREFIX.size)
        if len(prefix) != _HEADER_PREFIX.size:
            raise ArtifactStreamError()
        magic, header_size = _HEADER_PREFIX.unpack(prefix)
        if (
            magic != PRIVATE_STREAM_MAGIC
            or header_size < 2
            or header_size > PRIVATE_STREAM_HEADER_MAX_BYTES
        ):
            raise ArtifactStreamError()
        header_payload = handle.read(header_size)
        if len(header_payload) != header_size:
            raise ArtifactStreamError()
        try:
            header = json.loads(header_payload.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise ArtifactStreamError() from None
        expected_keys = {
            "algorithm", "artifactId", "chunkBytes", "codecSchema",
            "codecVersion", "contractDigest", "keyId", "salt", "schema", "version",
        }
        if (
            not isinstance(header, dict)
            or set(header) != expected_keys
            or header_payload != _canonical_json(header)
            or header.get("algorithm") != PRIVATE_STREAM_ALGORITHM
            or header.get("artifactId") != artifact_id
            or header.get("chunkBytes") != chunk_bytes
            or header.get("codecSchema") != codec_schema
            or header.get("codecVersion") != codec_version
            or header.get("contractDigest") != contract_digest
            or header.get("schema") != "helto.private-artifact-stream"
            or header.get("version") != PRIVATE_STREAM_VERSION
            or not isinstance(header.get("keyId"), str)
        ):
            raise ArtifactStreamError()
        salt = _unb64(header.get("salt"))
        master_key = key_for_id(header["keyId"])
        if master_key is None:
            raise ArtifactStreamError()
        aes = AESGCM(
            _derive_key(master_key, salt, contract_digest, artifact_id, owner_id)
        )
        header_bytes = prefix + header_payload
        header_digest = hashlib.sha256(header_bytes).digest()
        payload_offset = handle.tell()
        footer_offset = metadata.st_size - PRIVATE_STREAM_FOOTER_BYTES
        handle.seek(footer_offset)
        footer = handle.read(PRIVATE_STREAM_FOOTER_BYTES)
        footer_core = footer[:-PRIVATE_STREAM_TAG_BYTES]
        tag = footer[-PRIVATE_STREAM_TAG_BYTES:]
        footer_magic, total_chunks, total_plaintext, expected_digest = _FOOTER_CORE.unpack(
            footer_core
        )
        if (
            footer_magic != PRIVATE_STREAM_FOOTER_MAGIC
            or total_chunks < 1
            or total_chunks > _MAX_COUNTER
            or total_plaintext > max_plaintext_bytes
            or total_plaintext != expected_plaintext_bytes
        ):
            raise ArtifactStreamError()
        try:
            aes.decrypt(
                PRIVATE_STREAM_MANIFEST_NONCE,
                tag,
                _manifest_aad(header_digest, footer_core),
            )
        except Exception:
            raise ArtifactStreamError() from None
        transcript = hashlib.sha256(header_bytes)
        handle.seek(payload_offset)
        observed_chunks = 0
        observed_plaintext = 0
        while handle.tell() < footer_offset:
            prefix = handle.read(_FRAME_PREFIX.size)
            if len(prefix) != _FRAME_PREFIX.size:
                raise ArtifactStreamError()
            (ciphertext_size,) = _FRAME_PREFIX.unpack(prefix)
            if (
                ciphertext_size < PRIVATE_STREAM_TAG_BYTES
                or ciphertext_size > chunk_bytes + PRIVATE_STREAM_TAG_BYTES
                or handle.tell() + ciphertext_size > footer_offset
            ):
                raise ArtifactStreamError()
            ciphertext = handle.read(ciphertext_size)
            if len(ciphertext) != ciphertext_size:
                raise ArtifactStreamError()
            transcript.update(prefix)
            transcript.update(ciphertext)
            observed_chunks += 1
            observed_plaintext += ciphertext_size - PRIVATE_STREAM_TAG_BYTES
        if (
            handle.tell() != footer_offset
            or observed_chunks != total_chunks
            or observed_plaintext != total_plaintext
            or not hmac.compare_digest(transcript.digest(), expected_digest)
        ):
            raise ArtifactStreamError()
        source = BoundedArtifactSource(
            handle,
            aes=aes,
            artifact_id=artifact_id,
            contract_digest=contract_digest,
            header_digest=header_digest,
            payload_offset=payload_offset,
            footer_offset=footer_offset,
            total_chunks=total_chunks,
            total_plaintext=total_plaintext,
            max_chunk_bytes=chunk_bytes,
            cancel=cancel,
        )
        handle = None
        return source
    except ArtifactStreamError:
        raise
    except Exception:
        raise ArtifactStreamError() from None
    finally:
        if handle is not None:
            handle.close()
        if descriptor is not None:
            os.close(descriptor)


class PublicArtifactStreamWriter:
    """Bounded direct-copy sink for one explicit-public spill file."""

    __slots__ = ("_digest", "_handle", "_max", "_total", "sink")

    def __init__(
        self,
        handle,
        *,
        chunk_bytes: int,
        max_plaintext_bytes: int,
        cancel: Event | None = None,
    ) -> None:
        self._handle = handle
        self._max = max_plaintext_bytes
        self._total = 0
        self._digest = hashlib.sha256()
        self.sink = BoundedArtifactSink(chunk_bytes, self._write, cancel)

    def _write(self, chunk: memoryview) -> None:
        if self._total > self._max - len(chunk):
            raise ArtifactStreamError()
        self._handle.write(chunk)
        self._digest.update(chunk)
        self._total += len(chunk)

    def finish(self) -> tuple[int, str]:
        self.sink.close()
        return self._total, self._digest.hexdigest()

    def abort(self) -> None:
        self.sink.close()


class PublicArtifactSource:
    """Preflighted bounded source over an explicit-public spill."""

    __slots__ = ("_cancel", "_closed", "_handle", "max_chunk_bytes")

    def __init__(self, handle, max_chunk_bytes: int, cancel: Event | None) -> None:
        self._handle = handle
        self.max_chunk_bytes = max_chunk_bytes
        self._cancel = cancel
        self._closed = False
        handle.seek(0)

    def readinto(self, destination) -> int:
        if self._closed:
            raise ArtifactStreamError()
        if self._cancel is not None and self._cancel.is_set():
            raise ArtifactStreamCancelled()
        try:
            view = memoryview(destination).cast("B")
        except (TypeError, ValueError):
            raise ArtifactStreamError() from None
        if len(view) < 1 or len(view) > self.max_chunk_bytes or view.readonly:
            raise ArtifactStreamError()
        return self._handle.readinto(view)

    def read(self, size: int) -> bytes:
        if (
            self._closed
            or type(size) is not int
            or size < 1
            or size > self.max_chunk_bytes
        ):
            raise ArtifactStreamError()
        return self._handle.read(size)

    def close(self) -> None:
        self._closed = True
        self._handle.close()


def open_public_artifact_source(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    chunk_bytes: int,
    cancel: Event | None = None,
) -> PublicArtifactSource:
    descriptor: int | None = None
    handle = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != expected_size
        ):
            raise ArtifactStreamError()
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        digest = hashlib.sha256()
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
        if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
            raise ArtifactStreamError()
        source = PublicArtifactSource(handle, chunk_bytes, cancel)
        handle = None
        return source
    except ArtifactStreamError:
        raise
    except Exception:
        raise ArtifactStreamError() from None
    finally:
        if handle is not None:
            handle.close()
        if descriptor is not None:
            os.close(descriptor)
