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
- ``POST /helto_privacy/profiles/{pack_id}/executions/{execution_id}/prepare``
- ``GET  /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/reveal/{operation}``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/delete``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/replace``
- ``POST /helto_privacy/profiles/{pack_id}/artifacts/{resource_id}/{artifact_kind}/{artifact_id}/lease/{operation}``
- ``GET  /helto_privacy/artifacts/{lease_id}`` — authenticated private stream
- ``POST /helto_privacy/unlock`` / ``/lock``
- ``POST /helto_privacy/keystore/init`` / ``/keystore/change_password``
- ``GET  /helto_privacy/ui/privacy.js`` — the shared unlock dialog as an ES
  module any pack frontend can ``import()``.
- ``GET  /helto_privacy/ui/privacy_records.js`` — record-ID validation and
  locked-shell redaction.
- ``GET  /helto_privacy/ui/privacy_artifacts.js`` — opaque artifact-lease URL
  validation and resolution.
- ``GET  /helto_privacy/ui/privacy_snapshot.js`` — runtime-only snapshot and
  serialization barrier mechanics.
- ``GET  /helto_privacy/ui/privacy_profile/{manifest_digest}.js`` — exact-suite
  browser profile runtime.

The legacy directory registration seam remains temporarily for coordinated
consumer cutover. Imported plaintext sources are unlinked only after their
wrapped entries have been verified; no ``.migrated`` plaintext copy is kept.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import keystore
from .keystore import PrivacyKeystoreError
from ._legacy_key_source import (
    JSON_FORMAT,
    LegacyKeySource,
    LegacyKeySourceError,
    read_legacy_key_source,
    unlink_unchanged_legacy_key_source,
)
from .suite_runtime import SuiteBlockedError, require_active_process_suite

ROUTE_PREFIX = "/helto_privacy"
UI_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy.js"
CLIENT_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_client.js"
RECORDS_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_records.js"
ARTIFACTS_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_artifacts.js"
SNAPSHOT_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_snapshot.js"
PROFILE_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_profile/{{manifest_digest}}.js"
_WEB_DIR = Path(__file__).resolve().parent / "web"

_ROUTES_REGISTERED = False
_LEGACY_KEY_DIRS: list[Path] = []


def _bootstrap_mutation_denial(
    request: object,
    *,
    require_json: bool,
) -> tuple[str, int] | None:
    """Reject browser cross-origin bootstrap mutations before state changes."""

    candidate_headers = getattr(request, "headers", {})
    headers = candidate_headers if isinstance(candidate_headers, Mapping) else {}
    fetch_site = str(headers.get("Sec-Fetch-Site") or "").strip().lower()
    if fetch_site and fetch_site != "same-origin":
        return "PRIVACY_REQUEST_ORIGIN_INVALID", 403

    origin = str(headers.get("Origin") or "").strip()
    if origin:
        host = str(headers.get("Host") or "").strip().lower()
        scheme = str(getattr(request, "scheme", "") or "").strip().lower()
        supplied_origin = _origin_identity(origin)
        effective_origin = _origin_identity(f"{scheme}://{host}")
        if (
            supplied_origin is None
            or effective_origin is None
            or supplied_origin != effective_origin
        ):
            return "PRIVACY_REQUEST_ORIGIN_INVALID", 403

    if require_json:
        content_type = str(
            getattr(request, "content_type", "")
            or headers.get("Content-Type")
            or ""
        ).partition(";")[0].strip().lower()
        if content_type != "application/json":
            return "PRIVACY_REQUEST_CONTENT_TYPE_INVALID", 415
    return None


def _origin_identity(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme, parsed.hostname.lower(), port
    except (TypeError, ValueError):
        return None


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

        denied = _bootstrap_mutation_denial(request, require_json=True)
        if denied is not None:
            return _privacy_error_response(web, *denied)
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
            migration_obligation_id = getattr(
                result,
                "migration_obligation_id",
                None,
            )
            if migration_obligation_id is not None:
                response["migrationObligationId"] = migration_obligation_id
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
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/executions/"
        "{execution_id}/prepare"
    )
    async def post_helto_privacy_execution_prepare(request):
        from .execution import ExecutionError
        from .guard import PrivacyRouteError
        from .runtime import (
            PackBlockedError,
            UnknownResourceError,
            bound_privacy_pack,
        )

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            execution_id = str(request.match_info.get("execution_id") or "")
            payload = await request.json()
            if not isinstance(payload, dict):
                raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
            projection_id = str(payload.get("projectionId") or "")
            field_items = payload.get("fields")
            if not projection_id or not isinstance(field_items, list):
                raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
            protected_fields: dict[str, object] = {}
            for item in field_items:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("fieldId"), str)
                    or not item["fieldId"]
                    or "protectedValue" not in item
                    or item["fieldId"] in protected_fields
                ):
                    raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
                protected_fields[item["fieldId"]] = item["protectedValue"]
            authorization = pack.authorization.authorize_request(
                request,
                "execution.prepare",
            )
            prepared = pack.execution(execution_id).prepare(
                projection_id,
                protected_fields,
                authorization,
            )
            return web.json_response(
                {
                    "ok": True,
                    "reference": prepared.reference,
                },
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except UnknownResourceError:
            return _privacy_error_response(
                web,
                "PRIVACY_EXECUTION_RESOURCE_INVALID",
                400,
            )
        except PrivacyRouteError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except ExecutionError as exc:
            return _privacy_error_response(
                web,
                exc.code,
                _execution_error_status(exc.code),
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_EXECUTION_PREPARATION_FAILED",
                500,
            )

    record_base = (
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/records/"
        "{resource_id}/{record_kind}"
    )

    @routes.get(record_base)
    async def get_helto_privacy_record_shells(request):
        from .records import RecordError, safe_record_diagnostic
        from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            resource_id = str(request.match_info.get("resource_id") or "")
            record_kind = str(request.match_info.get("record_kind") or "")
            shells = pack.records(resource_id).list_shells(record_kind)
            diagnostic = safe_record_diagnostic(stage="list", count=len(shells))
            correlation = str(diagnostic["correlationId"])
            return web.json_response(
                {
                    "ok": True,
                    "records": [shell.to_payload() for shell in shells],
                    "correlationId": correlation,
                },
                headers=_record_response_headers(correlation),
            )
        except PackBlockedError:
            return _record_route_error_response(
                web,
                "PRIVACY_PROFILE_UNAVAILABLE",
                404,
            )
        except UnknownResourceError:
            return _record_route_error_response(
                web,
                "PRIVACY_RECORD_RESOURCE_INVALID",
                400,
            )
        except SuiteBlockedError:
            return _record_route_error_response(web, "PRIVACY_SUITE_BLOCKED", 409)
        except RecordError as exc:
            return _record_route_error_response(
                web,
                exc.code,
                _record_error_status(exc.code),
                exc.correlation_id,
            )
        except Exception:  # noqa: BLE001
            return _record_route_error_response(
                web,
                "PRIVACY_RECORD_LIST_FAILED",
                500,
            )

    @routes.post(record_base + "/{record_id}/reveal/{operation}")
    async def post_helto_privacy_record_reveal(request):
        from .guard import PrivacyRouteError
        from .records import RecordError
        from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            resource_id = str(request.match_info.get("resource_id") or "")
            record_kind = str(request.match_info.get("record_kind") or "")
            record_id = str(request.match_info.get("record_id") or "")
            operation = str(request.match_info.get("operation") or "")
            authorization = pack.authorization.authorize_request(
                request,
                f"record.{operation}",
            )
            revealed = pack.records(resource_id).reveal(
                record_kind,
                record_id,
                operation,
                authorization,
            )
            return web.json_response(
                {
                    "ok": True,
                    "value": revealed.value,
                    "correlationId": revealed.correlation_id,
                },
                headers=_record_response_headers(revealed.correlation_id),
            )
        except PackBlockedError:
            return _record_route_error_response(
                web,
                "PRIVACY_PROFILE_UNAVAILABLE",
                404,
            )
        except UnknownResourceError:
            return _record_route_error_response(
                web,
                "PRIVACY_RECORD_RESOURCE_INVALID",
                400,
            )
        except PrivacyRouteError as exc:
            return _record_route_error_response(web, exc.code, exc.http_status)
        except RecordError as exc:
            return _record_route_error_response(
                web,
                exc.code,
                _record_error_status(exc.code),
                exc.correlation_id,
            )
        except Exception:  # noqa: BLE001
            return _record_route_error_response(
                web,
                "PRIVACY_RECORD_REVEAL_FAILED",
                500,
            )

    @routes.post(record_base + "/{record_id}/delete")
    async def post_helto_privacy_record_delete(request):
        return await _destructive_record_route(request, web, operation="delete")

    @routes.post(record_base + "/{record_id}/replace")
    async def post_helto_privacy_record_replace(request):
        return await _destructive_record_route(request, web, operation="replace")

    artifact_lease_route = (
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/artifacts/"
        "{resource_id}/{artifact_kind}/{artifact_id}/lease/{operation}"
    )

    @routes.post(artifact_lease_route)
    async def post_helto_privacy_artifact_lease(request):
        from .artifacts import ArtifactError, ArtifactReference
        from .guard import PrivacyRouteError
        from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            resource_id = str(request.match_info.get("resource_id") or "")
            artifact_kind = str(request.match_info.get("artifact_kind") or "")
            operation = str(request.match_info.get("operation") or "")
            authorization = pack.authorization.authorize_request(
                request,
                f"artifact.{operation}",
            )
            lease = await pack.artifacts(resource_id).lease(
                artifact_kind,
                ArtifactReference(str(request.match_info.get("artifact_id") or "")),
                operation,
                authorization,
            )
            correlation = "hp-artifact-" + os.urandom(12).hex()
            return web.json_response(
                {"ok": True, "lease": lease.to_payload()},
                headers=_artifact_response_headers(correlation),
            )
        except PackBlockedError:
            return _artifact_route_error_response(
                web,
                "PRIVACY_PROFILE_UNAVAILABLE",
                404,
            )
        except UnknownResourceError:
            return _artifact_route_error_response(
                web,
                "PRIVACY_ARTIFACT_RESOURCE_INVALID",
                400,
            )
        except PrivacyRouteError as exc:
            return _artifact_route_error_response(web, exc.code, exc.http_status)
        except SuiteBlockedError:
            return _artifact_route_error_response(web, "PRIVACY_SUITE_BLOCKED", 409)
        except ArtifactError as exc:
            return _artifact_route_error_response(
                web,
                exc.code,
                _artifact_error_status(exc.code),
                exc.correlation_id,
            )
        except Exception:  # noqa: BLE001
            return _artifact_route_error_response(
                web,
                "PRIVACY_ARTIFACT_LEASE_INVALID",
                409,
            )

    @routes.get(f"{ROUTE_PREFIX}/artifacts/{{lease_id}}")
    async def get_helto_privacy_artifact(request):
        from .artifacts import ArtifactError, open_artifact_lease
        from .guard import PrivacyRouteError

        try:
            stream = await open_artifact_lease(
                request,
                str(request.match_info.get("lease_id") or ""),
            )
        except PrivacyRouteError as exc:
            return _artifact_route_error_response(web, exc.code, exc.http_status)
        except SuiteBlockedError:
            return _artifact_route_error_response(web, "PRIVACY_SUITE_BLOCKED", 409)
        except ArtifactError as exc:
            return _artifact_route_error_response(
                web,
                exc.code,
                _artifact_error_status(exc.code),
                exc.correlation_id,
            )
        except Exception:  # noqa: BLE001
            return _artifact_route_error_response(
                web,
                "PRIVACY_ARTIFACT_LEASE_INVALID",
                409,
            )

        response = web.StreamResponse(
            status=200,
            headers={**stream.headers, "Content-Type": stream.media_type},
        )
        try:
            await response.prepare(request)
        except BaseException:
            close = getattr(stream, "close", None)
            if callable(close):
                await close()
            raise
        chunks = stream.iter_chunks()
        try:
            async for chunk in chunks:
                await response.write(chunk)
        except ArtifactError:
            return response
        finally:
            await chunks.aclose()
        await response.write_eof()
        return response

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition"
    )
    async def post_helto_privacy_mode_transition(request):
        from .artifacts import run_artifact_mode_transition
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
            result = await run_artifact_mode_transition(
                pack.mode(scope.mode_resource_id),
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
        denied = _bootstrap_mutation_denial(request, require_json=True)
        if denied is not None:
            return _privacy_error_response(web, *denied)
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
    async def post_helto_privacy_lock(request):
        denied = _bootstrap_mutation_denial(request, require_json=True)
        if denied is not None:
            return _privacy_error_response(web, *denied)
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
        denied = _bootstrap_mutation_denial(request, require_json=True)
        if denied is not None:
            return _privacy_error_response(web, *denied)
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
        denied = _bootstrap_mutation_denial(request, require_json=True)
        if denied is not None:
            return _privacy_error_response(web, *denied)
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

    @routes.get(RECORDS_MODULE_ROUTE)
    async def get_helto_privacy_records_module(_request):
        try:
            source = (_WEB_DIR / "privacy_records.js").read_text(encoding="utf-8")
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

    @routes.get(ARTIFACTS_MODULE_ROUTE)
    async def get_helto_privacy_artifacts_module(_request):
        try:
            source = (_WEB_DIR / "privacy_artifacts.js").read_text(encoding="utf-8")
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
    result = keystore.initialize_keystore(password)
    for source in legacy:
        result = keystore.import_decrypt_only_key_verified(
            password,
            source.key_id,
            source.key,
        )
    _retire_legacy_files(legacy)
    return result


def _unlock_and_migrate(password: str) -> dict[str, Any]:
    require_active_process_suite()
    result = keystore.unlock_keystore(password)
    legacy = _collect_legacy_keys()
    if legacy:
        # Packs adopted after keystore creation get their old keys imported
        # the first time the user unlocks with the password in hand.
        for source in legacy:
            result = keystore.import_decrypt_only_key_verified(
                password,
                source.key_id,
                source.key,
            )
        _retire_legacy_files(legacy)
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


def _execution_error_status(code: str) -> int:
    return 400 if code.endswith(("_INVALID", "_MISMATCH")) else 409


async def _destructive_record_route(request, web, *, operation: str):
    from .records import (
        PRIVACY_DESTRUCTIVE_CONFIRMATION_HEADER,
        RecordError,
        confirm_record_mutation,
    )
    from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

    try:
        pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
        resource_id = str(request.match_info.get("resource_id") or "")
        record_kind = str(request.match_info.get("record_kind") or "")
        record_id = str(request.match_info.get("record_id") or "")
        confirmed = (
            str(getattr(request, "headers", {}).get(
                PRIVACY_DESTRUCTIVE_CONFIRMATION_HEADER,
                "",
            )).strip().lower()
            == "confirmed"
        )
        confirmation = confirm_record_mutation(
            pack_id=pack.profile.id,
            resource_id=resource_id,
            record_kind=record_kind,
            record_id=record_id,
            operation=operation,
            confirmed=confirmed,
        )
        records = pack.records(resource_id)
        if operation == "delete":
            receipt = records.delete(record_kind, record_id, confirmation)
        else:
            payload = await request.json()
            if not isinstance(payload, dict) or "protectedValue" not in payload:
                raise RecordError("PRIVACY_RECORD_REPLACEMENT_INVALID")
            receipt = records.replace(
                record_kind,
                record_id,
                payload["protectedValue"],
                confirmation,
            )
        return web.json_response(
            {
                "ok": True,
                "operation": receipt.operation,
                "correlationId": receipt.correlation_id,
            },
            headers=_record_response_headers(receipt.correlation_id),
        )
    except PackBlockedError:
        return _record_route_error_response(
            web,
            "PRIVACY_PROFILE_UNAVAILABLE",
            404,
        )
    except UnknownResourceError:
        return _record_route_error_response(
            web,
            "PRIVACY_RECORD_RESOURCE_INVALID",
            400,
        )
    except SuiteBlockedError:
        return _record_route_error_response(web, "PRIVACY_SUITE_BLOCKED", 409)
    except RecordError as exc:
        return _record_route_error_response(
            web,
            exc.code,
            _record_error_status(exc.code),
            exc.correlation_id,
        )
    except Exception:  # noqa: BLE001
        return _record_route_error_response(
            web,
            f"PRIVACY_RECORD_{operation.upper()}_FAILED",
            500,
        )


def _record_error_status(code: str) -> int:
    if code.endswith(("_INVALID", "_REQUIRED")):
        return 400
    return 409


def _record_response_headers(correlation_id: str) -> dict[str, str]:
    from .records import private_record_response_headers

    return private_record_response_headers(correlation_id=correlation_id)


def _record_route_error_response(
    web,
    code: str,
    status: int,
    correlation_id: str | None = None,
):
    from .records import private_record_response_headers, safe_record_diagnostic

    correlation = correlation_id or str(
        safe_record_diagnostic(stage="route")["correlationId"]
    )
    return web.json_response(
        {"ok": False, "error": code, "correlationId": correlation},
        status=status,
        headers=private_record_response_headers(correlation_id=correlation),
    )


def _artifact_error_status(code: str) -> int:
    if code.endswith(("_INVALID", "_REQUIRED")):
        return 400
    if code == "PRIVACY_ARTIFACT_NOT_FOUND":
        return 404
    return 409


def _artifact_response_headers(correlation_id: str) -> dict[str, str]:
    from .artifacts import private_artifact_response_headers

    return private_artifact_response_headers(correlation_id)


def _artifact_route_error_response(
    web,
    code: str,
    status: int,
    correlation_id: str | None = None,
):
    correlation = correlation_id or "hp-artifact-" + os.urandom(12).hex()
    return web.json_response(
        {"ok": False, "error": code, "correlationId": correlation},
        status=status,
        headers=_artifact_response_headers(correlation),
    )


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


def _collect_legacy_keys() -> list[LegacyKeySource]:
    collected: list[LegacyKeySource] = []
    for directory in _LEGACY_KEY_DIRS:
        path = directory / "privacy_key.json"
        if not path.is_file():
            continue
        try:
            source = read_legacy_key_source(path, JSON_FORMAT)
        except LegacyKeySourceError as exc:
            raise PrivacyKeystoreError(
                "PRIVACY_LEGACY_KEY_INVALID: Registered legacy key source is invalid."
            ) from exc
        collected.append(source)
    return collected


def _retire_legacy_files(sources: list[LegacyKeySource]) -> None:
    for source in sources:
        try:
            unlink_unchanged_legacy_key_source(source)
        except LegacyKeySourceError as exc:
            raise PrivacyKeystoreError(
                "PRIVACY_LEGACY_KEY_UNLINK_FAILED: Imported legacy key source remains."
            ) from exc
