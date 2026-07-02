"""ComfyUI integration: canonical privacy routes and the shared unlock UI.

Every Helto node pack calls :func:`register_helto_privacy_ui` at load time.
All packs share one ``helto_privacy`` module instance inside the ComfyUI
process, so registration is naturally idempotent — the first pack wins and
later calls only contribute their legacy key directory.

Registered surface (pack-neutral, stable):

- ``GET  /helto_privacy/status``
- ``POST /helto_privacy/unlock`` / ``/lock``
- ``POST /helto_privacy/keystore/init`` / ``/keystore/change_password``
- ``GET  /helto_privacy/ui/privacy.js`` — the shared unlock dialog as an ES
  module any pack frontend can ``import()``.

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

ROUTE_PREFIX = "/helto_privacy"
UI_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy.js"
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
        return web.json_response({"ok": True, **keystore.keystore_status()})

    @routes.post(f"{ROUTE_PREFIX}/unlock")
    async def post_helto_privacy_unlock(request):
        try:
            payload = await request.json()
            password = str(payload.get("password") or "")
            # scrypt is deliberately slow; keep it off the event loop.
            result = await asyncio.to_thread(_unlock_and_migrate, password)
            return web.json_response({"ok": True, **result})
        except PrivacyKeystoreError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            return web.json_response({"ok": False, "error": str(exc)}, status=500)

    @routes.post(f"{ROUTE_PREFIX}/lock")
    async def post_helto_privacy_lock(_request):
        try:
            return web.json_response({"ok": True, **keystore.lock_keystore()})
        except Exception as exc:  # noqa: BLE001
            return web.json_response({"ok": False, "error": str(exc)}, status=500)

    @routes.post(f"{ROUTE_PREFIX}/keystore/init")
    async def post_helto_privacy_init(request):
        try:
            payload = await request.json()
            password = str(payload.get("password") or "")
            result = await asyncio.to_thread(_initialize_and_migrate, password)
            return web.json_response({"ok": True, **result})
        except PrivacyKeystoreError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            return web.json_response({"ok": False, "error": str(exc)}, status=500)

    @routes.post(f"{ROUTE_PREFIX}/keystore/change_password")
    async def post_helto_privacy_change_password(request):
        try:
            payload = await request.json()
            result = await asyncio.to_thread(
                keystore.change_keystore_password,
                str(payload.get("current_password") or ""),
                str(payload.get("new_password") or ""),
            )
            return web.json_response({"ok": True, **result})
        except PrivacyKeystoreError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            return web.json_response({"ok": False, "error": str(exc)}, status=500)

    @routes.get(UI_MODULE_ROUTE)
    async def get_helto_privacy_ui_module(_request):
        try:
            source = (_WEB_DIR / "privacy_ui.js").read_text(encoding="utf-8")
        except OSError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=500)
        return web.Response(
            text=source,
            content_type="application/javascript",
            charset="utf-8",
            headers={"Cache-Control": "no-cache"},
        )

    _ROUTES_REGISTERED = True
    return True


def _initialize_and_migrate(password: str) -> dict[str, Any]:
    legacy = _collect_legacy_keys()
    result = keystore.initialize_keystore(
        password, legacy_keys=[(key_id, key) for key_id, key, _path in legacy]
    )
    _retire_legacy_files([path for _key_id, _key, path in legacy])
    return result


def _unlock_and_migrate(password: str) -> dict[str, Any]:
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
            logging.warning("helto-privacy: could not read legacy key file %s", path)
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
            logging.warning("helto-privacy: could not retire legacy key file %s", path)


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
