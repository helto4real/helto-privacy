"""Local operator CLI for explicit, process-bound suite activation."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from ._suite_codec import canonical_json_bytes, is_sha256, is_stable_id
from .suite import RollbackClass
from .suite_activation import (
    ActivationRequest,
    SignedActivationAuthorization,
    SuiteActivationError,
    sign_activation_authorization,
)


class OperatorActivationError(RuntimeError):
    """Sanitized operator activation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Operator suite activation failed.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="helto-privacy-activate")
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate-key")
    generate.add_argument("--private-key", required=True, type=Path)
    generate.add_argument("--public-key", required=True, type=Path)

    activate = commands.add_parser("activate")
    activate.add_argument("--server", default="http://127.0.0.1:8188")
    activate.add_argument("--private-key", required=True, type=Path)
    activate.add_argument("--signer-key-id", required=True)
    activate.add_argument("--pre-activation-snapshot-digest", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate-key":
            result = generate_operator_key(args.private_key, args.public_key)
        else:
            result = activate_operator_suite(
                server=args.server,
                private_key_path=args.private_key,
                signer_key_id=args.signer_key_id,
                pre_activation_snapshot_digest=(
                    args.pre_activation_snapshot_digest
                ),
            )
    except (OperatorActivationError, SuiteActivationError) as exc:
        code = getattr(exc, "code", "operator_activation_failed")
        print(json.dumps({"ok": False, "error": code}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def generate_operator_key(private_key_path: Path, public_key_path: Path) -> dict[str, object]:
    """Generate one non-exported operator key pair at explicit absolute paths."""

    private_path = _absolute_path(private_key_path, "private_key_path_invalid")
    public_path = _absolute_path(public_key_path, "public_key_path_invalid")
    if private_path.exists() or public_path.exists():
        raise OperatorActivationError("activation_key_path_exists")
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        _write_new_file(private_path, private_bytes, 0o600)
        _write_new_file(public_path, public_bytes, 0o644)
    except Exception:
        try:
            private_path.unlink(missing_ok=True)
            public_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise OperatorActivationError("activation_key_write_failed") from None
    return {
        "ok": True,
        "privateKeyCreated": True,
        "publicKeyCreated": True,
    }


def activate_operator_suite(
    *,
    server: str,
    private_key_path: Path,
    signer_key_id: str,
    pre_activation_snapshot_digest: str,
) -> dict[str, object]:
    """Fetch, sign, and submit one process-bound product-data-free activation."""

    base_url = _loopback_server(server)
    if not is_stable_id(signer_key_id):
        raise OperatorActivationError("activation_signer_invalid")
    if not is_sha256(pre_activation_snapshot_digest):
        raise OperatorActivationError("snapshot_digest_invalid")
    request_payload = _request_json(
        "GET",
        f"{base_url}/helto_privacy/suite/activation-request",
    )
    try:
        activation_request = ActivationRequest(
            manifest_digest=str(request_payload["manifestDigest"]),
            inventory_digest=str(request_payload["inventoryDigest"]),
            process_nonce=str(request_payload["processNonce"]),
            previous_suite_id=(
                str(request_payload["previousSuiteId"])
                if request_payload.get("previousSuiteId") is not None
                else None
            ),
            rollback=RollbackClass(str(request_payload["rollback"])),
        )
    except (KeyError, TypeError, ValueError, SuiteActivationError):
        raise OperatorActivationError("activation_request_invalid") from None
    private_key = _load_private_key(private_key_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    authorization = sign_activation_authorization(
        activation_request,
        pre_activation_snapshot_digest=pre_activation_snapshot_digest,
        authorization_id=(
            f"activation-{now.strftime('%Y%m%dt%H%M%Sz').lower()}-"
            f"{secrets.token_hex(8)}"
        ),
        authorized_at=now.isoformat().replace("+00:00", "Z"),
        signer_key_id=signer_key_id,
        private_key=private_key,
    )
    response = _request_json(
        "POST",
        f"{base_url}/helto_privacy/suite/activate",
        {
            "manifestDigest": authorization.manifest_digest,
            "inventoryDigest": authorization.inventory_digest,
            "processNonce": authorization.process_nonce,
            "preActivationSnapshotDigest": (
                authorization.pre_activation_snapshot_digest
            ),
            "authorizationId": authorization.authorization_id,
            "authorizedAt": authorization.authorized_at,
            "signerKeyId": authorization.signer_key_id,
            "signature": authorization.signature,
        },
    )
    if response.get("ok") is not True or response.get("suiteStatus") != "active":
        raise OperatorActivationError("activation_response_invalid")
    return {
        "ok": True,
        "suiteStatus": "active",
        "suiteManifestDigest": response.get("suiteManifestDigest"),
        "suiteIssueCodes": response.get("suiteIssueCodes", []),
    }


def _absolute_path(value: Path, code: str) -> Path:
    path = value.expanduser()
    if not path.is_absolute():
        raise OperatorActivationError(code)
    return path


def _load_private_key(path_value: Path) -> Ed25519PrivateKey:
    path = _absolute_path(path_value, "private_key_path_invalid")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024:
            raise OperatorActivationError("activation_private_key_invalid")
        if metadata.st_mode & 0o077:
            raise OperatorActivationError("activation_private_key_permissions_invalid")
        with os.fdopen(descriptor, "rb") as key_file:
            descriptor = -1
            key = serialization.load_pem_private_key(key_file.read(), password=None)
    except OperatorActivationError:
        raise
    except (OSError, ValueError, TypeError):
        raise OperatorActivationError("activation_private_key_invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(key, Ed25519PrivateKey):
        raise OperatorActivationError("activation_private_key_invalid")
    return key


def _write_new_file(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _loopback_server(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError
        parsed.port
    except (TypeError, ValueError):
        raise OperatorActivationError("activation_server_invalid") from None
    return value.rstrip("/")


def _request_json(
    method: str,
    url: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    body = canonical_json_bytes(payload) if payload is not None else None
    request = Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise OperatorActivationError("activation_server_rejected")
            decoded = json.loads(response.read().decode("utf-8"))
    except OperatorActivationError:
        raise
    except (HTTPError, URLError, OSError, UnicodeError, json.JSONDecodeError):
        raise OperatorActivationError("activation_server_unavailable") from None
    if not isinstance(decoded, dict) or decoded.get("ok") is not True:
        raise OperatorActivationError("activation_server_rejected")
    return decoded


if __name__ == "__main__":
    raise SystemExit(main())
