"""Deterministically regenerate the committed synthetic historical fixtures.

The recipes below are literal reproductions of the pinned historical writer
algorithms.  All keys, nonces, timestamps, and plaintexts are public test-only
constants.  No runtime configuration or user data is read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "historical"
_UTILS_COMMIT = "d19f6845bf3c2f83a3ae3d6c48bce7e7897475a8"
_AIO_COMMIT = "3e3e656a4b0dd9b40535a900b2f198264b21b0c1"
_SMART_COMMIT = "b2db6fffbb1653f266f0c32982dbb8f5d7096b8c"
_DIRECTOR_COMMIT = "73b7255952211d9dab3b9497f2a4a64a43c2837f"


def canonical_fixture_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def regenerate_fixture(name: str) -> bytes:
    recipes = {
        "aio_v1_state.json": _aio_state,
        "aio_v1_builder_state.json": _aio_builder_state,
        "director_v1_state.json": _director_state,
        "smart_prompt_v1_state.json": _smart_state,
        "smart_prompt_v1_export.json": _smart_export,
        "utils_legacy_formats.json": _utils_formats,
    }
    try:
        return canonical_fixture_bytes(recipes[name]())
    except KeyError:
        raise ValueError("Unknown historical fixture recipe.") from None


def fixture_names() -> tuple[str, ...]:
    return (
        "aio_v1_builder_state.json",
        "aio_v1_state.json",
        "director_v1_state.json",
        "smart_prompt_v1_export.json",
        "smart_prompt_v1_state.json",
        "utils_legacy_formats.json",
    )


def _state_envelope(
    state: object,
    *,
    key_label: str,
    nonce_hex: str,
    schema: str,
    pretty_plaintext: bool = False,
) -> dict[str, Any]:
    key = hashlib.sha256(key_label.encode("utf-8")).digest()
    key_id = _b64url(hashlib.sha256(key).digest()[:12])
    nonce = bytes.fromhex(nonce_hex)
    algorithm = "AES-256-GCM"
    aad = f"{schema}|1|{algorithm}|{key_id}".encode("utf-8")
    plaintext = json.dumps(
        state,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if pretty_plaintext else None,
        separators=None if pretty_plaintext else (",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "version": 1,
        "schema": schema,
        "encrypted": True,
        "algorithm": algorithm,
        "keyId": key_id,
        "nonce": _b64url(nonce),
        "ciphertext": _b64url(ciphertext),
    }


def _envelope_digest(envelope: object) -> str:
    return hashlib.sha256(
        json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _aio_state() -> dict[str, Any]:
    expected = {"value": "SYNTHETIC_AIO_LEGACY_PROMPT"}
    envelope = _state_envelope(
        expected,
        key_label="helto-aio-v1-historical-fixture-key",
        nonce_hex="15ff12ccf6377e3bbd561434",
        schema="helto.aio-image-generate",
    )
    return {
        "fixtureVersion": 1,
        "producerCommit": _AIO_COMMIT,
        "producerFunction": "services/privacy.py:encrypt_state",
        "testKeyDerivation": "sha256:helto-aio-v1-historical-fixture-key",
        "envelope": envelope,
        "envelopeSha256": _envelope_digest(envelope),
        "expectedNormalized": expected,
    }


def _aio_builder_state() -> dict[str, Any]:
    expected = {
        "active": 0,
        "bbox_order": "yx",
        "bg_brightness": 25,
        "coord_mode": "normalized",
        "elements": [
            {
                "description": "SYNTHETIC_AIO_BUILDER_ELEMENT",
                "id": "synthetic-element",
            }
        ],
        "output_format": "compact",
        "style_palette": ["#fab387"],
        "version": 1,
        "widgets": {
            "high_level_description": "SYNTHETIC_AIO_BUILDER_DESCRIPTION",
            "privacy_mode": True,
        },
    }
    envelope = _state_envelope(
        expected,
        key_label="helto-aio-v1-historical-fixture-key",
        nonce_hex="3e507ef7c7e9deec0a357581",
        schema="helto.aio-image-generate",
    )
    return {
        "fixtureVersion": 1,
        "producerCommit": _AIO_COMMIT,
        "producerFunction": "services/privacy.py:encrypt_state",
        "testKeyDerivation": "sha256:helto-aio-v1-historical-fixture-key",
        "envelope": envelope,
        "envelopeSha256": _envelope_digest(envelope),
        "expectedNormalized": expected,
    }


def _director_state() -> dict[str, Any]:
    expected = {
        "timeline": {
            "title": "SYNTHETIC_DIRECTOR_LEGACY_TIMELINE",
            "version": 1,
        }
    }
    envelope = _state_envelope(
        expected,
        key_label="helto-director-v1-historical-fixture-key",
        nonce_hex="8f499d19a0dc930d59a036f7",
        schema="helto.timeline-director",
    )
    return {
        "fixtureVersion": 1,
        "producerCommit": _DIRECTOR_COMMIT,
        "producerFunction": "shared/privacy.py:encrypt_state",
        "testKeyDerivation": "sha256:helto-director-v1-historical-fixture-key",
        "envelope": envelope,
        "envelopeSha256": _envelope_digest(envelope),
        "expectedNormalized": expected,
    }


def _smart_expected() -> dict[str, Any]:
    return {
        "cycleState": {},
        "folders": [],
        "privacyMode": True,
        "prompts": [
            {
                "createdAt": "2026-07-01T00:00:00Z",
                "description": "",
                "favorite": False,
                "folderId": "",
                "hidden": False,
                "id": "prompt_fixture",
                "locked": False,
                "tags": ["synthetic"],
                "text": "SYNTHETIC_SMART_PROMPT_LEGACY_TEXT",
                "title": "Synthetic fixture",
                "updatedAt": "2026-07-01T00:00:00Z",
            }
        ],
        "search": "",
        "selectedFolderId": "all",
        "selectedPromptId": "prompt_fixture",
        "ui": {"collapsedSections": {}},
        "variables": {},
        "version": 1,
    }


def _smart_state() -> dict[str, Any]:
    expected = _smart_expected()
    envelope = _state_envelope(
        expected,
        key_label="helto-smart-prompt-v1-historical-fixture-key",
        nonce_hex="ad84b27a530d45e603ba00f5",
        schema="comfyui-helto-prompts.smart-prompt-manager",
        pretty_plaintext=True,
    )
    return {
        "fixtureVersion": 1,
        "producerCommit": _SMART_COMMIT,
        "producerFunction": "privacy.py:encrypt_state",
        "testKeyDerivation": "sha256:helto-smart-prompt-v1-historical-fixture-key",
        "envelope": envelope,
        "envelopeSha256": _envelope_digest(envelope),
        "expectedNormalized": expected,
    }


def _smart_export() -> dict[str, Any]:
    envelope = _smart_state()["envelope"]
    package = {
        "format": "comfyui-helto-prompts.smart-prompt-manager.export",
        "version": 1,
        "exportedAt": "2026-07-01T00:00:00Z",
        "encrypted": True,
        "spm_data": json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    return {
        "fixtureVersion": 1,
        "producerCommit": _SMART_COMMIT,
        "producerFunction": "web/js/smart_prompt_manager.js:buildSpmExportPackage",
        "sourceEnvelopeFixture": "smart_prompt_v1_state.json",
        "package": package,
        "packageSha256": _envelope_digest(package),
    }


def _utils_formats() -> dict[str, Any]:
    workflow = '{"selected":["SYNTHETIC_UTILS_WORKFLOW_VALUE"]}'
    mask = base64.b64decode(
        "iVBORw0KGgpTWU5USEVUSUNfVVRJTFNfU0VMRUNUT1JfTUFTS19CWVRFUw=="
    )
    queue = {
        "active_run_id": "synthetic-run",
        "history": [],
        "paused": True,
        "privacy_enabled": True,
        "queue": [{"id": "synthetic-queue-item"}],
        "resume_required": True,
        "updated_at": 1751328000000,
        "version": 1,
    }
    queue_bytes = json.dumps(queue, sort_keys=True, separators=(",", ":")).encode()
    key = hashlib.sha256(
        b"helto-utils-privacy-key-bin-historical-fixture-key"
    ).digest()
    raw_key = hashlib.sha256(b"helto-utils-key-bin-historical-fixture-key").digest()
    generations: dict[str, Any] = {}
    specifications = {
        "raw-xor": (
            lambda plain, nonce: _raw_xor(plain, raw_key, nonce),
            {
                "bytes": "e74508e4c8344adb703912117fd25d36",
                "mask": "bf53f02c0c142a0d544723b459305f81",
            },
        ),
        "priv1": (
            lambda plain, nonce: _priv1(plain, key, nonce),
            {
                "bytes": "fccf5597a63e55c976a591defce529b5",
                "mask": "b861163cf4cc5f32205a22ea39e90cb6",
                "queue": "6e3a854e27b367fc6fc55f74d5dafabd",
            },
        ),
        "priv2": (
            lambda plain, nonce: _priv2(plain, key, nonce),
            {
                "bytes": "73a36064e102610b5ed15e34",
                "mask": "cf67cff9dc8fc7eb6be0d1b8",
                "queue": "ec42afc25ae5e6f610680a78",
            },
        ),
        "priv3": (
            lambda plain, nonce: _priv3(plain, key, nonce, 17),
            {
                "bytes": "6257d428",
                "mask": "2611fbf3",
                "queue": "df193c6f",
            },
        ),
    }
    for generation, (encrypt, nonces) in specifications.items():
        workflow_bytes = encrypt(workflow.encode(), bytes.fromhex(nonces["bytes"]))
        mask_bytes = encrypt(mask, bytes.fromhex(nonces["mask"]))
        item: dict[str, Any] = {
            "bytes": _binary_value(workflow_bytes),
            "mask": _binary_value(mask_bytes),
            "workflow": "__HELTO_ENC__:" + base64.b64encode(workflow_bytes).decode(),
            "workflowSha256": _sha(
                ("__HELTO_ENC__:" + base64.b64encode(workflow_bytes).decode()).encode()
            ),
        }
        if generation != "raw-xor":
            queue_encrypted = encrypt(queue_bytes, bytes.fromhex(nonces["queue"]))
            encoded = base64.b64encode(queue_encrypted).decode()
            queue_json = {
                "version": 1,
                "privacy_enabled": True,
                "server_session_id": "synthetic-session",
                "payload": "HELTO_QUEUE_MANAGER_STATE_V1:" + encoded,
            }
            queue_sqlite = {
                "version": 1,
                "privacy_enabled": True,
                "server_session_id": "synthetic-session",
                "updated_at": 1751328000000,
                "encrypted_at_rest": True,
                "payload": encoded,
            }
            item["queueJson"] = {
                "value": queue_json,
                "sha256": _canonical_sha(queue_json),
            }
            item["queueSqlite"] = {
                "value": queue_sqlite,
                "sha256": _canonical_sha(queue_sqlite),
            }
        generations[generation] = item

    selector_values = {
        "edited_bboxes": (
            '{"/synthetic/root/a.png":[{"height":4,"width":3,"x":1,"y":2}]}'
        ),
        "edited_masks": (
            '{"/synthetic/root/a.png":{"key":"synthetic-legacy-mask"}}'
        ),
        "selected_images": '["/synthetic/root/a.png"]',
    }
    nonce_lengths = {"raw-xor": 16, "priv1": 16, "priv2": 12, "priv3": 4}
    for generation, (encrypt, _nonces) in specifications.items():
        generations[generation]["selectorMigration"] = {}
        for name, plain in selector_values.items():
            nonce = hashlib.sha256(
                f"selector-{generation}-{name}".encode("ascii")
            ).digest()[: nonce_lengths[generation]]
            encrypted = encrypt(plain.encode(), nonce)
            workflow_value = "__HELTO_ENC__:" + base64.b64encode(encrypted).decode()
            generations[generation]["selectorMigration"][name] = {
                "expected": plain,
                "workflow": workflow_value,
                "workflowSha256": _sha(workflow_value.encode()),
            }

    prompt_enhancer_values = {
        "script": "A synthetic {{style}} portrait",
        "variables": (
            '[{"fixed_index":1,"mode":"fixed","name":"style",'
            '"values":["cinematic","documentary"]}]'
        ),
    }
    for generation, (encrypt, _nonces) in specifications.items():
        generations[generation]["promptEnhancerMigration"] = {}
        for name, plain in prompt_enhancer_values.items():
            nonce = hashlib.sha256(
                f"prompt-enhancer-{generation}-{name}".encode("ascii")
            ).digest()[: nonce_lengths[generation]]
            encrypted = encrypt(plain.encode(), nonce)
            workflow_value = "__HELTO_ENC__:" + base64.b64encode(encrypted).decode()
            generations[generation]["promptEnhancerMigration"][name] = {
                "expected": plain,
                "workflow": workflow_value,
                "workflowSha256": _sha(workflow_value.encode()),
            }

    return {
        "fixtureVersion": 1,
        "producerCommit": _UTILS_COMMIT,
        "producerFunctions": {
            "priv1": "shared/privacy.py:_encrypt_bytes_v1",
            "priv2": "shared/privacy.py:_encrypt_bytes_v2",
            "priv3": "shared/privacy.py:_encrypt_bytes_v3",
            "queue-json": "shared/queue_manager_store.py:encrypted_state_payload",
            "queue-sqlite": "shared/queue_manager_store.py:_payload_for_state",
            "raw-xor": "helto_selector_backend/crypto.py:_legacy_encrypt_bytes",
            "workflow": "helto_selector_backend/crypto.py:encrypt_selection",
        },
        "testKeyDerivations": {
            "priv1-3": "sha256:helto-utils-privacy-key-bin-historical-fixture-key",
            "raw-xor": "sha256:helto-utils-key-bin-historical-fixture-key",
        },
        "workflowLocations": [
            "selector-selected-images",
            "selector-edited-masks",
            "selector-edited-bboxes",
            "prompt-enhancer-script",
            "prompt-enhancer-variables",
            "privacy-show-any-widget",
            "privacy-show-any-property",
        ],
        "expected": {
            "workflow": workflow,
            "maskBase64": base64.b64encode(mask).decode(),
            "queue": queue,
        },
        "generations": generations,
        "derivedFailureCases": [
            {
                "id": "priv1-tag-tamper",
                "generation": "priv1",
                "mutation": "flip-final-byte",
                "expected": "read-fails",
            },
            {
                "id": "priv2-tag-tamper",
                "generation": "priv2",
                "mutation": "flip-final-byte",
                "expected": "read-fails",
            },
            {
                "id": "priv3-truncation",
                "generation": "priv3",
                "mutation": "remove-final-byte",
                "expected": "probe-fails",
            },
            {
                "id": "raw-xor-ungated",
                "generation": "raw-xor",
                "mutation": "remove-location-carrier",
                "expected": "probe-fails",
            },
        ],
    }


def _raw_xor(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return iv + bytes(a ^ b for a, b in zip(plaintext, _keystream(key, iv, len(plaintext))))


def _priv1(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    magic = b"HELTO_PRIV1:"
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, _keystream(key, iv, len(plaintext))))
    return magic + iv + ciphertext + hmac.new(key, magic + iv + ciphertext, hashlib.sha256).digest()


def _priv2(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    magic = b"HELTO_PRIV2:"
    return magic + nonce + AESGCM(key).encrypt(nonce, plaintext, magic)


def _priv3(plaintext: bytes, key: bytes, prefix: bytes, chunk_size: int) -> bytes:
    magic = b"HELTO_PRIV3:"
    header = chunk_size.to_bytes(8, "big") + len(plaintext).to_bytes(8, "big") + prefix
    chunks = [magic, header]
    aes = AESGCM(key)
    for counter, start in enumerate(range(0, len(plaintext), chunk_size)):
        nonce = prefix + counter.to_bytes(8, "big")
        aad = magic + header + counter.to_bytes(8, "big")
        chunks.append(aes.encrypt(nonce, plaintext[start : start + chunk_size], aad))
    return b"".join(chunks)


def _keystream(key: bytes, iv: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hmac.new(key, iv + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(output[:length])


def _binary_value(payload: bytes) -> dict[str, str]:
    return {"base64": base64.b64encode(payload).decode(), "sha256": _sha(payload)}


def _canonical_sha(value: object) -> str:
    return _sha(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--fixture", choices=fixture_names(), action="append")
    parser.add_argument("--root", type=Path, default=FIXTURE_ROOT)
    args = parser.parse_args(argv)
    selected = tuple(args.fixture or fixture_names())
    mismatches = []
    for name in selected:
        generated = regenerate_fixture(name)
        path = args.root / name
        if args.check:
            if not path.is_file() or path.read_bytes() != generated:
                mismatches.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(generated)
    if mismatches:
        parser.error("fixture mismatch: " + ", ".join(mismatches))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
