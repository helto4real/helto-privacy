"""ComfyUI integration: canonical privacy routes and the shared unlock UI.

Every Helto node pack calls :func:`register_helto_privacy_ui` at load time.
All packs share one ``helto_privacy`` module instance inside the ComfyUI
process, so registration is naturally idempotent — the first pack wins and
later calls only contribute their legacy key directory.

Registered surface (pack-neutral, stable):

- ``GET  /helto_privacy/status``
- ``GET  /helto_privacy/profiles/{pack_id}`` — safe profile attestation
- ``GET  /helto_privacy/profiles/{pack_id}/modes`` — safe mode status
- ``POST /helto_privacy/profiles/{pack_id}/modes/{scope_id}/transition``
- ``POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/disposition``
- ``POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/protect``
- ``POST /helto_privacy/unlock`` / ``/lock``
- ``POST /helto_privacy/keystore/init`` / ``/keystore/change_password``
- ``GET  /helto_privacy/ui/privacy.js`` — the shared unlock dialog as an ES
  module any pack frontend can ``import()``.
- ``GET  /helto_privacy/ui/privacy_snapshot.js`` — runtime-only snapshot and
  serialization barrier mechanics.
- ``GET  /helto_privacy/ui/privacy_profile/{manifest_digest}.js`` — exact-suite
  browser profile runtime.

Legacy migration is automatic: packs register the directory holding their old
plaintext ``privacy_key.json``; whenever the keystore is created or unlocked
(the only moments the password is available), every registered legacy key is
imported as a decrypt-only entry and its file renamed to ``.migrated``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from pathlib import Path
from typing import Any

from . import keystore
from .keystore import KEY_BYTES, PrivacyKeystoreError
from .suite_runtime import SuiteBlockedError, require_active_process_suite

ROUTE_PREFIX = "/helto_privacy"
UI_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy.js"
CLIENT_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_client.js"
SNAPSHOT_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_snapshot.js"
PROFILE_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_profile/{{manifest_digest}}.js"
_WEB_DIR = Path(__file__).resolve().parent / "web"

_ROUTES_REGISTERED = False
_LEGACY_KEY_DIRS: list[Path] = []


def register_legacy_key_dir(path: str | os.PathLike[str] | None) -> None:
    """Record a pack's legacy ``privacy_key.json`` directory for migration."""
    if not path:
        return
    resolved = Path(path).expanduser()
    if resolved not in _LEGACY_KEY_DIRS:
        _LEGACY_KEY_DIRS.append(resolved)


def register_helto_privacy_ui(
    legacy_key_dir: str | os.PathLike[str] | None = None,
    *,
    prompt_server: Any = None,
) -> bool:
    """Register the canonical privacy endpoints and shared UI module route.

    Safe to call from every pack; returns True once the routes are (already)
    registered. ``legacy_key_dir`` is remembered even when another pack
    registered the routes first.
    """
    global _ROUTES_REGISTERED
    register_legacy_key_dir(legacy_key_dir)
    if _ROUTES_REGISTERED:
        return True

    if prompt_server is None:
        try:
            import server

            prompt_server = getattr(server.PromptServer, "instance", None)
        except Exception as exc:  # noqa: BLE001 - not running inside ComfyUI.
            logging.debug("helto-privacy UI routes unavailable: %s", exc)
            return False
    if prompt_server is None:
        return False

    try:
        from aiohttp import web
    except Exception as exc:  # noqa: BLE001 - aiohttp comes with ComfyUI.
        logging.debug("helto-privacy UI routes unavailable: %s", exc)
        return False

    routes = prompt_server.routes

    @routes.get(f"{ROUTE_PREFIX}/status")
    async def get_helto_privacy_status(_request):
        from .suite_runtime import process_suite_status_payload

        return web.json_response(
            {
                "ok": True,
                **_safe_keystore_status(),
                **process_suite_status_payload(),
            },
            headers={"Cache-Control": "no-store"},
        )

    @routes.get(f"{ROUTE_PREFIX}/profiles/{{pack_id}}")
    async def get_helto_privacy_profile(request):
        from .runtime import PackBlockedError, profile_attestation

        try:
            result = profile_attestation(str(request.match_info.get("pack_id") or ""))
            return web.json_response(
                {"ok": True, **result},
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return web.json_response(
                {"ok": False, "error": "PRIVACY_PROFILE_UNAVAILABLE"},
                status=404,
                headers={"Cache-Control": "no-store"},
            )

    @routes.post(f"{ROUTE_PREFIX}/suite/browser-attestation")
    async def post_helto_privacy_browser_attestation(request):
        from .suite_runtime import (
            SuiteInventoryError,
            record_browser_manifest_attestation,
        )

        try:
            payload = await request.json()
            digest = str(payload.get("manifestDigest") or "")
            record_browser_manifest_attestation(digest)
            return web.json_response(
                {"ok": True, "suiteManifestDigest": digest},
                headers={"Cache-Control": "no-store"},
            )
        except SuiteInventoryError:
            return web.json_response(
                {"ok": False, "error": "PRIVACY_SUITE_ASSET_MISMATCH"},
                status=409,
                headers={"Cache-Control": "no-store"},
            )

    @routes.get(f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes")
    async def get_helto_privacy_modes(request):
        from .mode import ModePolicyError, ModeTransitionError
        from .runtime import PackBlockedError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(
                str(request.match_info.get("pack_id") or "")
            )
            scopes = []
            for scope in pack.profile.scopes:
                resolution = pack.mode(scope.mode_resource_id).resolve(scope.id)
                scopes.append(
                    _mode_resolution_payload(
                        scope.id,
                        scope.mode_resource_id,
                        resolution,
                    )
                )
            return web.json_response(
                {"ok": True, "packId": pack.profile.id, "scopes": scopes},
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(
                web,
                "PRIVACY_PROFILE_UNAVAILABLE",
                404,
            )
        except (ModePolicyError, ModeTransitionError):
            return _privacy_error_response(
                web,
                "PRIVACY_MODE_STATE_UNAVAILABLE",
                409,
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_MODE_STATUS_FAILED",
                500,
            )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/fields/{{field_id}}/disposition"
    )
    async def post_helto_privacy_field_disposition(request):
        from .guard import PrivacyAuthorizationError, PrivacyRouteError
        from .runtime import PackBlockedError, bound_privacy_pack
        from .snapshot import SnapshotError

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            field_id = str(request.match_info.get("field_id") or "")
            workflow, field = pack.snapshot_field(field_id)
            payload = await request.json()
            if not isinstance(payload, dict) or "protectedValue" not in payload:
                return _privacy_error_response(
                    web,
                    "PRIVACY_SNAPSHOT_INPUT_INVALID",
                    400,
                )
            try:
                authorization = pack.authorization.authorize_request(
                    request,
                    "snapshot.disposition",
                )
            except PrivacyAuthorizationError as exc:
                if exc.code not in {
                    "PRIVACY_LOCKED",
                    "PRIVACY_KEYSTORE_UNINITIALIZED",
                }:
                    raise
                authorization = None
            result = workflow.inspect_disposition(
                field.id,
                payload["protectedValue"],
                authorization,
            )
            response = {
                "ok": True,
                "fieldId": field.id,
                "disposition": result.disposition.value,
            }
            if result.replacement_envelope is not None:
                response["replacementEnvelope"] = result.replacement_envelope
            return web.json_response(
                response,
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except PrivacyRouteError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except SnapshotError as exc:
            return _privacy_error_response(
                web,
                exc.code,
                _snapshot_error_status(exc.code),
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_SNAPSHOT_DISPOSITION_FAILED",
                500,
            )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/fields/{{field_id}}/protect"
    )
    async def post_helto_privacy_field_protect(request):
        from .guard import PrivacyRouteError
        from .runtime import PackBlockedError, bound_privacy_pack
        from .snapshot import SnapshotError

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            field_id = str(request.match_info.get("field_id") or "")
            workflow, field = pack.snapshot_field(field_id)
            payload = await request.json()
            if not isinstance(payload, dict) or "value" not in payload:
                return _privacy_error_response(
                    web,
                    "PRIVACY_SNAPSHOT_INPUT_INVALID",
                    400,
                )
            authorization = pack.authorization.authorize_request(
                request,
                "snapshot.protect",
            )
            result = workflow.protect(
                field.id,
                payload["value"],
                authorization,
            )
            return web.json_response(
                {
                    "ok": True,
                    "fieldId": field.id,
                    "disposition": result.disposition.value,
                    "envelope": result.envelope,
                },
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except PrivacyRouteError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except SnapshotError as exc:
            return _privacy_error_response(
                web,
                exc.code,
                _snapshot_error_status(exc.code),
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_SNAPSHOT_PROTECTION_FAILED",
                500,
            )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition"
    )
    async def post_helto_privacy_mode_transition(request):
        from .guard import PrivacyRouteError
        from .mode import ModePolicyError, ModeTransitionError
        from .runtime import PackBlockedError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(
                str(request.match_info.get("pack_id") or "")
            )
            scope_id = str(request.match_info.get("scope_id") or "")
            scope = next(
                (item for item in pack.profile.scopes if item.id == scope_id),
                None,
            )
            if scope is None:
                return _privacy_error_response(web, "PRIVACY_SCOPE_INVALID", 400)
            payload = await request.json()
            if not isinstance(payload, dict):
                return _privacy_error_response(web, "PRIVACY_MODE_INVALID", 400)
            target = str(payload.get("target") or "")
            if target not in {"inherit", "private", "public"}:
                return _privacy_error_response(web, "PRIVACY_MODE_INVALID", 400)
            if target == "public":
                authorization = pack.authorization.authorize_declassification(
                    request,
                    scope_id,
                    target,
                )
            else:
                authorization = pack.authorization.authorize_request(
                    request,
                    "mode.transition",
                )
            result = pack.mode(scope.mode_resource_id).transition(
                scope_id,
                target,
                authorization,
            )
            return web.json_response(
                {
                    "ok": True,
                    "scopeId": result.scope_id,
                    "declared": result.declared.value,
                    "effective": result.effective.value,
                    "transitionStatus": result.status.value,
                },
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(
                web,
                "PRIVACY_PROFILE_UNAVAILABLE",
                404,
            )
        except PrivacyRouteError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except ModeTransitionError as exc:
            return _privacy_error_response(web, exc.code, 409)
        except ModePolicyError:
            return _privacy_error_response(
                web,
                "PRIVACY_MODE_STATE_UNAVAILABLE",
                409,
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_MODE_TRANSITION_FAILED",
                500,
            )

    @routes.post(f"{ROUTE_PREFIX}/unlock")
    async def post_helto_privacy_unlock(request):
        try:
            require_active_process_suite()
            payload = await request.json()
            password = str(payload.get("password") or "")
            # scrypt is deliberately slow; keep it off the event loop.
            result = await asyncio.to_thread(_unlock_and_migrate, password)
            return web.json_response({"ok": True, **result})
        except PrivacyKeystoreError as exc:
            return _privacy_error_response(web, _keystore_error_code(exc), 400)
        except SuiteBlockedError:
            return _suite_blocked_response(web)
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_KEYSTORE_OPERATION_FAILED",
                500,
            )

    @routes.post(f"{ROUTE_PREFIX}/lock")
    async def post_helto_privacy_lock(_request):
        try:
            return web.json_response({"ok": True, **keystore.lock_keystore()})
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_KEYSTORE_OPERATION_FAILED",
                500,
            )

    @routes.post(f"{ROUTE_PREFIX}/keystore/init")
    async def post_helto_privacy_init(request):
        try:
            require_active_process_suite()
            payload = await request.json()
            password = str(payload.get("password") or "")
            result = await asyncio.to_thread(_initialize_and_migrate, password)
            return web.json_response({"ok": True, **result})
        except PrivacyKeystoreError as exc:
            return _privacy_error_response(web, _keystore_error_code(exc), 400)
        except SuiteBlockedError:
            return _suite_blocked_response(web)
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_KEYSTORE_OPERATION_FAILED",
                500,
            )

    @routes.post(f"{ROUTE_PREFIX}/keystore/change_password")
    async def post_helto_privacy_change_password(request):
        try:
            require_active_process_suite()
            payload = await request.json()
            result = await asyncio.to_thread(
                keystore.change_keystore_password,
                str(payload.get("current_password") or ""),
                str(payload.get("new_password") or ""),
            )
            return web.json_response({"ok": True, **result})
        except PrivacyKeystoreError as exc:
            return _privacy_error_response(web, _keystore_error_code(exc), 400)
        except SuiteBlockedError:
            return _suite_blocked_response(web)
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_KEYSTORE_OPERATION_FAILED",
                500,
            )

    @routes.get(UI_MODULE_ROUTE)
    async def get_helto_privacy_ui_module(_request):
        try:
            source = (_WEB_DIR / "privacy_ui.js").read_text(encoding="utf-8")
        except OSError:
            return _privacy_error_response(
                web,
                "PRIVACY_BROWSER_MODULE_UNAVAILABLE",
                500,
            )
        return web.Response(
            text=source,
            content_type="application/javascript",
            charset="utf-8",
            headers={"Cache-Control": "no-cache"},
        )

    @routes.get(CLIENT_MODULE_ROUTE)
    async def get_helto_privacy_client_module(_request):
        try:
            source = (_WEB_DIR / "privacy_client.js").read_text(encoding="utf-8")
        except OSError:
            return _privacy_error_response(
                web,
                "PRIVACY_BROWSER_MODULE_UNAVAILABLE",
                500,
            )
        return web.Response(
            text=source,
            content_type="application/javascript",
            charset="utf-8",
            headers={"Cache-Control": "no-cache"},
        )

    @routes.get(SNAPSHOT_MODULE_ROUTE)
    async def get_helto_privacy_snapshot_module(_request):
        try:
            source = (_WEB_DIR / "privacy_snapshot.js").read_text(encoding="utf-8")
        except OSError:
            return _privacy_error_response(
                web,
                "PRIVACY_BROWSER_MODULE_UNAVAILABLE",
                500,
            )
        return web.Response(
            text=source,
            content_type="application/javascript",
            charset="utf-8",
            headers={"Cache-Control": "no-cache"},
        )

    @routes.get(PROFILE_MODULE_ROUTE)
    async def get_helto_privacy_profile_module(request):
        from .suite_runtime import process_suite_status_payload

        suite_status = process_suite_status_payload()
        requested_digest = str(request.match_info.get("manifest_digest") or "")
        if (
            not suite_status["suiteManifestDigest"]
            or requested_digest != suite_status["suiteManifestDigest"]
        ):
            return web.json_response(
                {"ok": False, "error": "PRIVACY_SUITE_ASSET_MISMATCH"},
                status=409,
                headers={"Cache-Control": "no-store"},
            )
        try:
            source = (_WEB_DIR / "privacy_profile.js").read_text(encoding="utf-8")
        except OSError:
            return web.json_response(
                {"ok": False, "error": "PRIVACY_BROWSER_MODULE_UNAVAILABLE"},
                status=500,
            )
        return web.Response(
            text=source,
            content_type="application/javascript",
            charset="utf-8",
            headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )

    _ROUTES_REGISTERED = True
    return True


def _initialize_and_migrate(password: str) -> dict[str, Any]:
    require_active_process_suite()
    legacy = _collect_legacy_keys()
    result = keystore.initialize_keystore(
        password, legacy_keys=[(key_id, key) for key_id, key, _path in legacy]
    )
    _retire_legacy_files([path for _key_id, _key, path in legacy])
    return result


def _unlock_and_migrate(password: str) -> dict[str, Any]:
    require_active_process_suite()
    result = keystore.unlock_keystore(password)
    legacy = _collect_legacy_keys()
    if legacy:
        # Packs adopted after keystore creation get their old keys imported
        # the first time the user unlocks with the password in hand.
        result = keystore.add_keys_to_keystore(
            password, [(key_id, key) for key_id, key, _path in legacy]
        )
        _retire_legacy_files([path for _key_id, _key, path in legacy])
    return result


def _suite_blocked_response(web):
    return web.json_response(
        {"ok": False, "error": "PRIVACY_SUITE_BLOCKED"},
        status=409,
    )


def _safe_keystore_status() -> dict[str, bool]:
    status = keystore.keystore_status()
    return {
        "keystoreAvailable": bool(status.get("keystoreAvailable", False)),
        "keystoreInitialized": bool(status.get("keystoreInitialized", False)),
        "keystoreLocked": bool(status.get("keystoreLocked", False)),
    }


def _keystore_error_code(error: Exception) -> str:
    candidate = str(error).partition(":")[0]
    if candidate in {
        keystore.ERROR_LOCKED,
        keystore.ERROR_UNINITIALIZED,
        keystore.ERROR_ALREADY_INITIALIZED,
        keystore.ERROR_PASSWORD_INVALID,
        keystore.ERROR_PASSWORD_TOO_SHORT,
        keystore.ERROR_KEYSTORE_INVALID,
    }:
        return candidate
    return "PRIVACY_KEYSTORE_OPERATION_FAILED"


def _privacy_error_response(web, code: str, status: int):
    return web.json_response(
        {"ok": False, "error": code},
        status=status,
        headers={"Cache-Control": "no-store"},
    )


def _snapshot_error_status(code: str) -> int:
    return 400 if code == "PRIVACY_SNAPSHOT_FIELD_INVALID" else 409


def _mode_resolution_payload(
    scope_id: str,
    mode_resource_id: str,
    resolution,
) -> dict[str, object]:
    return {
        "id": scope_id,
        "modeResourceId": mode_resource_id,
        "declared": resolution.declared.value,
        "effective": resolution.effective.value,
        "inheritedFrom": resolution.inherited_from,
        "floors": [
            {"kind": floor.kind.value, "sourceId": floor.source_id}
            for floor in resolution.floors
        ],
        "transitionStatus": resolution.transition_status.value,
    }


def _collect_legacy_keys() -> list[tuple[str, bytes, Path]]:
    collected: list[tuple[str, bytes, Path]] = []
    seen_ids: set[str] = set()
    for directory in _LEGACY_KEY_DIRS:
        path = directory / "privacy_key.json"
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            key = _b64url_decode(str(payload.get("key", "")))
            key_id = str(payload.get("keyId", "")).strip()
        except Exception:  # noqa: BLE001 - unreadable legacy keys are skipped, not fatal.
            logging.warning("helto-privacy: could not read a registered legacy key file")
            continue
        if len(key) != KEY_BYTES or not key_id or key_id in seen_ids:
            continue
        collected.append((key_id, key, path))
        seen_ids.add(key_id)
    return collected


def _retire_legacy_files(paths: list[Path]) -> None:
    for path in paths:
        migrated = path.with_name(path.name + ".migrated")
        try:
            path.replace(migrated)
            os.chmod(migrated, 0o600)
        except OSError:
            logging.warning("helto-privacy: could not retire a registered legacy key file")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
