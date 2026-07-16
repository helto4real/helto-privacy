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
- ``POST /helto_privacy/profiles/{pack_id}/modes/{scope_id}/transition/reserve``
- ``GET /helto_privacy/profiles/{pack_id}/modes/{scope_id}/transition/status``
- ``POST /helto_privacy/profiles/{pack_id}/modes/{scope_id}/transition/{transition_id}/{phase}``
- ``POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/disposition``
- ``POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/protect``
- ``POST /helto_privacy/profiles/{pack_id}/fields/{field_id}/reveal``
- ``POST /helto_privacy/profiles/{pack_id}/executions/{execution_id}/prepare``
- ``POST /helto_privacy/profiles/{pack_id}/submission-grants/revoke``
- ``GET  /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/mutate/create``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/mutate/{operation}``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/reveal/{operation}``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/delete``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/{record_id}/replace``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/reference-migrations/{migration_id}/migrate``
- ``POST /helto_privacy/profiles/{pack_id}/records/{resource_id}/{record_kind}/reference-migrations/{migration_id}/resolve``
- ``POST /helto_privacy/profiles/{pack_id}/references/revoke``
- ``POST /helto_privacy/profiles/{pack_id}/operations/{operation_id}/external/prepare``
- ``GET  /helto_privacy/profiles/{pack_id}/operations/{operation_id}/external/{transaction_id}/status``
- ``POST /helto_privacy/profiles/{pack_id}/operations/{operation_id}/external/{transaction_id}/{resume|apply|rollback}``
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
- ``GET  /helto_privacy/ui/privacy_submission.js`` — guarded prompt transport
  ownership and completion mechanics.
- ``GET  /helto_privacy/ui/privacy_queue.js`` — settled queue capture and
  fresh-grant replay orchestration.
- ``GET  /helto_privacy/ui/privacy_profile/{manifest_digest}.js`` — exact-suite
  browser profile runtime.

The legacy directory registration seam remains temporarily for coordinated
consumer cutover. Imported plaintext sources are unlinked only after their
wrapped entries have been verified; no ``.migrated`` plaintext copy is kept.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import secrets
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
SUBMISSION_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_submission.js"
QUEUE_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_queue.js"
PROFILE_MODULE_ROUTE = f"{ROUTE_PREFIX}/ui/privacy_profile/{{manifest_digest}}.js"
_WEB_DIR = Path(__file__).resolve().parent / "web"
_EXTERNAL_RESUME_HEADER = "X-Helto-Privacy-Resume-Capability"
_EXTERNAL_OPERATION_RESUME_HEADER = (
    "X-Helto-Privacy-Operation-Resume-Capability"
)
_SERVER_BOOT_EPOCH_HEADER = "X-Helto-Privacy-Boot-Epoch"

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
    from .suite_bootstrap import bootstrap_configured_process_suite

    bootstrap_configured_process_suite()
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

    from .submission_middleware import install_prompt_submission_middleware

    install_prompt_submission_middleware(prompt_server)

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
            SuiteBlockedError,
            SuiteInventoryError,
            process_suite_status_payload,
            record_browser_manifest_attestation,
            verify_configured_process_suite,
        )

        denied = _bootstrap_mutation_denial(request, require_json=True)
        if denied is not None:
            return _privacy_error_response(web, *denied)
        try:
            payload = await request.json()
            if not isinstance(payload, Mapping):
                raise SuiteInventoryError("invalid_browser_attestation")
            digest = str(payload.get("manifestDigest") or "")
            renderer = str(payload.get("renderer") or "")
            record_browser_manifest_attestation(digest, renderer)
            try:
                report = verify_configured_process_suite()
                status = report.status.value
            except SuiteBlockedError as exc:
                if exc.code != "suite_verification_not_configured":
                    raise
                status = process_suite_status_payload()["suiteStatus"]
            return web.json_response(
                {
                    "ok": True,
                    "suiteManifestDigest": digest,
                    "suiteStatus": status,
                },
                headers={"Cache-Control": "no-store"},
            )
        except (SuiteBlockedError, SuiteInventoryError):
            return web.json_response(
                {"ok": False, "error": "PRIVACY_SUITE_ASSET_MISMATCH"},
                status=409,
                headers={"Cache-Control": "no-store"},
            )

    @routes.get(f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes")
    async def get_helto_privacy_modes(request):
        from .mode import ModePolicyError, ModeTransitionError
        from .mode_state import load_mode_scope_state
        from .runtime import SERVER_BOOT_EPOCH, PackBlockedError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(
                str(request.match_info.get("pack_id") or "")
            )
            scopes = []
            for scope in pack.profile.scopes:
                resolution = pack.mode(scope.mode_resource_id).resolve(scope.id)
                payload = _mode_resolution_payload(
                    scope.id,
                    scope.mode_resource_id,
                    resolution,
                )
                payload["modeEpoch"] = load_mode_scope_state(
                    pack.profile.id, scope.id
                ).mode_epoch
                scopes.append(payload)
            return web.json_response(
                {
                    "ok": True,
                    "packId": pack.profile.id,
                    "serverBootEpoch": SERVER_BOOT_EPOCH,
                    "scopes": scopes,
                },
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
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/resolve"
    )
    async def post_helto_privacy_mode_resolution(request):
        from .mode import ModePolicyError, ModeTransitionError
        from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            payload = await request.json()
            declaration = payload.get("declaration")
            facts = _mode_facts_from_payload(payload.get("facts"))
            scope = next(
                (item for item in pack.profile.scopes if item.id == scope_id),
                None,
            )
            if scope is None:
                raise UnknownResourceError()
            resolution = pack.mode(scope.mode_resource_id).resolve_declaration(
                scope.id,
                declaration,
                facts,
            )
            return web.json_response(
                _mode_resolution_payload(
                    scope.id,
                    scope.mode_resource_id,
                    resolution,
                ),
                headers={"Cache-Control": "no-store"},
            )
        except (ModePolicyError, ModeTransitionError):
            return _privacy_error_response(
                web,
                "PRIVACY_MODE_STATE_UNAVAILABLE",
                409,
            )
        except (AttributeError, TypeError, ValueError):
            return _privacy_error_response(
                web,
                "PRIVACY_MODE_DECLARATION_INVALID",
                400,
            )
        except (PackBlockedError, UnknownResourceError):
            return _privacy_error_response(
                web,
                "PRIVACY_PROFILE_UNAVAILABLE",
                404,
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
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/fields/{{field_id}}/reveal"
    )
    async def post_helto_privacy_field_reveal(request):
        from .guard import PrivacyRouteError
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
            authorization = pack.authorization.authorize_request(
                request,
                "snapshot.reveal",
            )
            result = workflow.reveal(
                field.id,
                payload["protectedValue"],
                authorization,
            )
            return web.json_response(
                {"ok": True, "fieldId": field.id, "value": result.value},
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
                "PRIVACY_SNAPSHOT_REVEAL_FAILED",
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
            subject_id = payload.get("subjectId")
            field_items = payload.get("fields")
            if (
                set(payload) != {"projectionId", "subjectId", "fields"}
                or not projection_id
                or subject_id is None
                or not isinstance(field_items, list)
            ):
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
                subject_id=subject_id,
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

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/subject-modes/"
        "{binding_id}/prepare"
    )
    async def post_helto_privacy_subject_mode_prepare(request):
        from .guard import PrivacyRouteError
        from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack
        from .subject_mode import SubjectModeReferenceError

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            binding_id = str(request.match_info.get("binding_id") or "")
            payload = await request.json()
            if not isinstance(payload, dict) or set(payload) - {
                "subjectId", "declaration", "facts",
            }:
                raise SubjectModeReferenceError()
            prepared = pack.subject_modes(binding_id).prepare(
                payload.get("subjectId"),
                payload.get("declaration"),
                _mode_facts_from_payload(payload.get("facts")),
                pack.authorization.authorize_request(
                    request,
                    "subject-mode.prepare",
                ),
            )
            return web.json_response(
                {
                    "ok": True,
                    "reference": prepared.reference,
                    "effective": prepared.effective,
                },
                headers={"Cache-Control": "no-store"},
            )
        except (PackBlockedError, UnknownResourceError):
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except PrivacyRouteError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except (SubjectModeReferenceError, AttributeError, TypeError, ValueError):
            return _privacy_error_response(
                web,
                "PRIVACY_SUBJECT_MODE_REFERENCE_INVALID",
                400,
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_SUBJECT_MODE_REFERENCE_INVALID",
                409,
            )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/submission-grants/revoke"
    )
    async def post_helto_privacy_submission_grants_revoke(request):
        from .execution import (
            EXECUTION_REFERENCE_SCHEMA,
            ExecutionError,
            validate_execution_reference_for_revoke,
        )
        from .guard import PrivacyRouteError
        from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack
        from .subject_mode import (
        SUBJECT_MODE_REFERENCE_SCHEMA,
            SubjectModeReferenceError,
            validate_subject_mode_reference_for_revoke,
        )

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            authorization = pack.authorization.authorize_request(
                request,
                "submission-grants.revoke",
            )
            payload = await request.json()
            if (
                not isinstance(payload, dict)
                or set(payload) != {"references"}
                or not isinstance(payload["references"], list)
                or len(payload["references"]) > 2048
            ):
                raise ValueError("invalid submission grant batch")
            plans = []
            seen = set()
            for reference in payload["references"]:
                if not isinstance(reference, dict):
                    raise ValueError("invalid submission grant")
                grant_id = reference.get("grant")
                schema = reference.get("schema")
                identity = (schema, grant_id)
                if (
                    not isinstance(grant_id, str)
                    or not grant_id
                    or identity in seen
                ):
                    raise ValueError("invalid submission grant")
                seen.add(identity)
                if schema == EXECUTION_REFERENCE_SCHEMA:
                    execution_id = reference.get("executionResourceId")
                    if not isinstance(execution_id, str):
                        raise ValueError("invalid submission grant")
                    validate_execution_reference_for_revoke(
                        reference,
                        pack_id=pack.profile.id,
                        execution_resource_id=execution_id,
                    )
                    plans.append(("execution", pack.execution(execution_id), reference))
                elif schema == SUBJECT_MODE_REFERENCE_SCHEMA:
                    binding_id = reference.get("bindingId")
                    binding = next(
                        (
                            item
                            for item in pack.profile.subject_mode_bindings
                            if item.id == binding_id
                        ),
                        None,
                    )
                    if binding is None:
                        raise SubjectModeReferenceError()
                    validate_subject_mode_reference_for_revoke(
                        reference,
                        profile=pack.profile,
                        binding=binding,
                    )
                    plans.append(("subject", pack.subject_modes(binding.id), reference))
                else:
                    raise ValueError("invalid submission grant")
            for kind, handle, reference in plans:
                if kind == "execution":
                    handle.revoke(reference, authorization)
                else:
                    handle.revoke(reference, authorization)
            return web.Response(status=204, headers={"Cache-Control": "no-store"})
        except PackBlockedError:
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except PrivacyRouteError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except (
            UnknownResourceError,
            ExecutionError,
            SubjectModeReferenceError,
            AttributeError,
            TypeError,
            ValueError,
        ):
            return _privacy_error_response(
                web,
                "PRIVACY_SUBMISSION_GRANTS_INVALID",
                400,
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_SUBMISSION_GRANTS_FAILED",
                409,
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
            records = pack.records(resource_id)
            authorize = getattr(records, "authorize_request", None)
            authorization = (
                authorize(record_kind, request, f"record.{operation}")
                if callable(authorize)
                else pack.authorization.authorize_request(
                    request,
                    f"record.{operation}",
                )
            )
            if authorization is None:
                denied = _bootstrap_mutation_denial(request, require_json=False)
                if denied is not None:
                    return _record_route_error_response(web, denied[0], denied[1])
            revealed = records.reveal(
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

    @routes.post(record_base + "/mutate/create")
    async def post_helto_privacy_record_create(request):
        return await _authorized_record_mutation_route(
            request,
            web,
            operation="create",
        )

    @routes.post(record_base + "/{record_id}/mutate/{operation}")
    async def post_helto_privacy_record_mutation(request):
        return await _authorized_record_mutation_route(
            request,
            web,
            operation=str(request.match_info.get("operation") or ""),
        )

    @routes.post(record_base + "/{record_id}/delete")
    async def post_helto_privacy_record_delete(request):
        return await _destructive_record_route(request, web, operation="delete")

    @routes.post(record_base + "/{record_id}/replace")
    async def post_helto_privacy_record_replace(request):
        return await _destructive_record_route(request, web, operation="replace")

    reference_migration_base = (
        record_base + "/reference-migrations/{migration_id}"
    )

    @routes.post(reference_migration_base + "/migrate")
    async def post_helto_privacy_record_reference_migrate(request):
        return await _record_reference_route(request, web, operation="migrate")

    @routes.post(reference_migration_base + "/resolve")
    async def post_helto_privacy_record_reference_resolve(request):
        return await _record_reference_route(request, web, operation="resolve")

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/associations/{{association_id}}/claim"
    )
    async def post_helto_privacy_association_claim(request):
        from .associations import (
            AssociationError,
            association_operation_id,
            claim_operation_association,
        )
        from .guard import PrivacyAuthorizationError
        from .protected_operations import protected_operation_response_payload
        from .runtime import PackBlockedError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            payload = await request.json()
            if not isinstance(payload, dict) or payload:
                raise AssociationError()
            association_id = str(request.match_info.get("association_id") or "")
            operation_id = association_operation_id(pack.profile, association_id)
            authorization = pack.authorization.authorize_request(
                request,
                operation_id,
            )
            result = claim_operation_association(
                installation=pack._installation,
                profile=pack.profile,
                association_id=association_id,
                authorization=authorization,
            )
            return web.json_response(
                protected_operation_response_payload(result),
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except PrivacyAuthorizationError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except AssociationError as exc:
            return web.json_response(
                {"ok": False, "error": exc.code, "correlationId": exc.correlation_id},
                status=409,
                headers={"Cache-Control": "no-store"},
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_OPERATION_ASSOCIATION_UNAVAILABLE",
                409,
            )

    @routes.post(f"{ROUTE_PREFIX}/profiles/{{pack_id}}/references/revoke")
    async def post_helto_privacy_reference_revoke(request):
        from .guard import PrivacyAuthorizationError
        from .opaque_references import OpaqueReferenceError, revoke_operation_references
        from .runtime import PackBlockedError, bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            payload = await request.json()
            if not isinstance(payload, dict) or set(payload) != {"references"}:
                raise OpaqueReferenceError()
            authorization = pack.authorization.authorize_request(
                request,
                "reference.revoke",
            )
            count = revoke_operation_references(
                profile=pack.profile,
                authorization=authorization,
                reference_ids=payload["references"],
            )
            correlation = "hp-operation-" + secrets.token_urlsafe(12)
            return web.json_response(
                {"ok": True, "revoked": count, "correlationId": correlation},
                headers={"Cache-Control": "no-store"},
            )
        except PackBlockedError:
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        except PrivacyAuthorizationError as exc:
            return _privacy_error_response(web, exc.code, exc.http_status)
        except OpaqueReferenceError as exc:
            return web.json_response(
                {"ok": False, "error": exc.code, "correlationId": exc.correlation_id},
                status=409,
                headers={"Cache-Control": "no-store"},
            )
        except Exception:  # noqa: BLE001
            return _privacy_error_response(
                web,
                "PRIVACY_OPAQUE_REFERENCE_UNAVAILABLE",
                409,
            )

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

    def _external_transition_capability(request, payload):
        return {
            "resume_secret": _required_external_resume_secret(request),
            "coordinator_id": payload.get("coordinatorId"),
            "client_lease": payload.get("clientLease"),
            "client_lease_epoch": payload.get("clientLeaseEpoch"),
            "mode_epoch": payload.get("modeEpoch"),
            "server_boot_epoch": _required_external_boot_epoch(request),
        }

    def _required_external_header(request, name, pattern):
        from .external_mode_transition import ExternalModeTransitionError

        value = request.headers.get(name)
        if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
            raise ExternalModeTransitionError("PRIVACY_EXTERNAL_TRANSITION_FENCED")
        return value

    def _required_external_resume_secret(request):
        return _required_external_header(
            request,
            _EXTERNAL_RESUME_HEADER,
            r"hp-mode-resume-[A-Za-z0-9_-]{43}",
        )

    def _required_external_boot_epoch(request):
        return _required_external_header(
            request,
            _SERVER_BOOT_EPOCH_HEADER,
            r"hp-boot-[A-Za-z0-9_-]{16,64}",
        )

    async def _external_json_payload(request, maximum):
        length = request.content_length
        if length is not None and (length < 0 or length > maximum):
            raise ValueError("external transition request too large")
        content = getattr(request, "content", None)
        if content is not None and callable(getattr(content, "iter_chunked", None)):
            chunks = []
            size = 0
            async for chunk in content.iter_chunked(64 * 1024):
                size += len(chunk)
                if size > maximum:
                    raise ValueError("external transition request too large")
                chunks.append(bytes(chunk))
            raw = b"".join(chunks)
        else:
            raw = await request.read()
            if len(raw) > maximum:
                raise ValueError("external transition request too large")
        try:
            payload = json.loads(raw)
        except Exception:
            raise ValueError("external transition request invalid") from None
        if not isinstance(payload, dict):
            raise ValueError("external transition request invalid")
        return payload

    def _external_payload_keys(payload, expected):
        if set(payload) != set(expected):
            raise ValueError("external transition request invalid")
        return payload

    def _external_owner_request_limit(pack, scope_id):
        from .profile import ProtectedStateAuthority

        totals = [
            field.external_transition_policy.max_total_bytes
            for field in pack.profile.protected_fields
            if field.scope_id == scope_id
            and field.state_authority is ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW
        ]
        if not totals:
            raise ValueError("external transition scope invalid")
        return min(49 * 1024 * 1024, min(totals) + 1024 * 1024)

    def _external_transition_error(web, exc):
        from .external_mode_transition import ExternalModeTransitionError
        from .guard import PrivacyRouteError
        from .mode import ModePolicyError
        from .runtime import PackBlockedError

        if isinstance(exc, PackBlockedError):
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        if isinstance(exc, PrivacyRouteError):
            return _privacy_error_response(web, exc.code, exc.http_status)
        if isinstance(exc, ExternalModeTransitionError):
            return _privacy_error_response(web, exc.code, 409)
        if isinstance(exc, ModePolicyError):
            return _privacy_error_response(web, "PRIVACY_MODE_STATE_UNAVAILABLE", 409)
        if isinstance(exc, ValueError):
            return _privacy_error_response(web, "PRIVACY_MODE_INVALID", 400)
        return _privacy_error_response(web, "PRIVACY_MODE_TRANSITION_FAILED", 500)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/reserve"
    )
    async def post_helto_privacy_external_transition_reserve(request):
        from .external_mode_transition import reserve_external_transition
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            scope = next((item for item in pack.profile.scopes if item.id == scope_id), None)
            if scope is None:
                return _privacy_error_response(web, "PRIVACY_SCOPE_INVALID", 400)
            payload = await _external_json_payload(request, 64 * 1024)
            _external_payload_keys(payload, {
                "target",
                "requestId",
                "coordinatorId",
                "offlineRepresentationCount",
                "expectedModeEpoch",
            })
            target = str(payload.get("target") or "")
            if target not in {"inherit", "private", "public"}:
                return _privacy_error_response(web, "PRIVACY_MODE_INVALID", 400)
            authorization = (
                pack.authorization.authorize_declassification(
                    request,
                    scope_id,
                    target,
                    operation_id="mode.transition.reserve",
                )
                if target == "public"
                else pack.authorization.authorize_request(
                    request, "mode.transition.reserve"
                )
            )
            result = await asyncio.to_thread(
                reserve_external_transition,
                pack._installation,
                scope.mode_resource_id,
                scope_id,
                target,
                authorization,
                request_id=payload.get("requestId"),
                coordinator_id=payload.get("coordinatorId"),
                resume_secret=_required_external_resume_secret(request),
                offline_representation_count=payload.get("offlineRepresentationCount"),
                expected_mode_epoch=payload.get("expectedModeEpoch"),
                server_boot_epoch=_required_external_boot_epoch(request),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/client-heartbeat"
    )
    async def post_helto_privacy_external_transition_client_heartbeat(request):
        from .external_mode_transition import heartbeat_external_client
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            payload = await _external_json_payload(request, 64 * 1024)
            _external_payload_keys(payload, {"coordinatorId"})
            authorization = pack.authorization.authorize_request(
                request, "mode.transition.client-heartbeat"
            )
            result = await asyncio.to_thread(
                heartbeat_external_client,
                pack._installation,
                str(request.match_info.get("scope_id") or ""),
                authorization,
                coordinator_id=payload.get("coordinatorId"),
                resume_secret=_required_external_resume_secret(request),
                server_boot_epoch=_required_external_boot_epoch(request),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.get(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/status"
    )
    async def get_helto_privacy_external_transition_status(request):
        from .external_mode_transition import external_transition_status
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            authorization = pack.authorization.authorize_request(
                request, "mode.transition.status"
            )
            result = await asyncio.to_thread(
                external_transition_status,
                pack._installation,
                scope_id,
                authorization,
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/rebase"
    )
    async def post_helto_privacy_external_transition_rebase(request):
        from .external_mode_transition import rebase_external_owner_exact
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            payload = await _external_json_payload(
                request, _external_owner_request_limit(pack, scope_id)
            )
            _external_payload_keys(payload, {"fieldId", "exact", "modeEpoch"})
            authorization = pack.authorization.authorize_request(
                request, "mode.transition.rebase"
            )
            result = await asyncio.to_thread(
                rebase_external_owner_exact,
                pack._installation,
                scope_id,
                authorization,
                field_id=payload.get("fieldId"),
                exact=payload.get("exact"),
                mode_epoch=payload.get("modeEpoch"),
                server_boot_epoch=_required_external_boot_epoch(request),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/{{transition_id}}/prepare"
    )
    async def post_helto_privacy_external_transition_prepare(request):
        from .external_mode_transition import prepare_external_transition
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            payload = await _external_json_payload(
                request, _external_owner_request_limit(pack, scope_id)
            )
            _external_payload_keys(payload, {
                "coordinatorId",
                "clientLease",
                "clientLeaseEpoch",
                "modeEpoch",
                "owners",
            })
            authorization = pack.authorization.authorize_request(
                request, "mode.transition.prepare"
            )
            result = await asyncio.to_thread(
                prepare_external_transition,
                pack._installation,
                scope_id,
                str(request.match_info.get("transition_id") or ""),
                authorization,
                owners=payload.get("owners"),
                **_external_transition_capability(request, payload),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/{{transition_id}}/resume"
    )
    async def post_helto_privacy_external_transition_resume(request):
        from .external_mode_transition import resume_external_transition
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            payload = await _external_json_payload(request, 64 * 1024)
            _external_payload_keys(payload, {"coordinatorId", "modeEpoch"})
            authorization = pack.authorization.authorize_request(
                request, "mode.transition.resume"
            )
            result = await asyncio.to_thread(
                resume_external_transition,
                pack._installation,
                str(request.match_info.get("scope_id") or ""),
                str(request.match_info.get("transition_id") or ""),
                authorization,
                resume_secret=_required_external_resume_secret(request),
                coordinator_id=payload.get("coordinatorId"),
                mode_epoch=payload.get("modeEpoch"),
                server_boot_epoch=_required_external_boot_epoch(request),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    async def _external_ack_route(request, operation_id, function):
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            payload = await _external_json_payload(
                request, _external_owner_request_limit(pack, scope_id)
            )
            _external_payload_keys(payload, {
                "coordinatorId",
                "clientLease",
                "clientLeaseEpoch",
                "modeEpoch",
                "acknowledgements",
            })
            authorization = pack.authorization.authorize_request(request, operation_id)
            result = await asyncio.to_thread(
                function,
                pack._installation,
                scope_id,
                str(request.match_info.get("transition_id") or ""),
                authorization,
                acknowledgements=payload.get("acknowledgements"),
                **_external_transition_capability(request, payload),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/{{transition_id}}/apply-ack"
    )
    async def post_helto_privacy_external_transition_apply_ack(request):
        from .external_mode_transition import acknowledge_external_apply

        return await _external_ack_route(
            request, "mode.transition.apply-ack", acknowledge_external_apply
        )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/{{transition_id}}/verify"
    )
    async def post_helto_privacy_external_transition_verify(request):
        from .external_mode_transition import verify_external_transition
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            scope_id = str(request.match_info.get("scope_id") or "")
            payload = await _external_json_payload(
                request, _external_owner_request_limit(pack, scope_id)
            )
            _external_payload_keys(payload, {
                "coordinatorId",
                "clientLease",
                "clientLeaseEpoch",
                "modeEpoch",
                "acknowledgements",
                "snapshotId",
                "snapshotGeneration",
            })
            authorization = pack.authorization.authorize_request(
                request, "mode.transition.verify"
            )
            result = await asyncio.to_thread(
                verify_external_transition,
                pack._installation,
                scope_id,
                str(request.match_info.get("transition_id") or ""),
                authorization,
                acknowledgements=payload.get("acknowledgements"),
                snapshot_id=payload.get("snapshotId"),
                snapshot_generation=payload.get("snapshotGeneration"),
                **_external_transition_capability(request, payload),
            )
            return web.json_response(
                {"ok": True, **result}, headers={"Cache-Control": "no-store"}
            )
        except Exception as exc:  # noqa: BLE001
            return _external_transition_error(web, exc)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/{{transition_id}}/finalize"
    )
    async def post_helto_privacy_external_transition_finalize(request):
        from .external_mode_transition import finalize_external_transition

        async def finalize_route(req, operation_id, function):
            from .runtime import bound_privacy_pack

            try:
                pack = bound_privacy_pack(str(req.match_info.get("pack_id") or ""))
                payload = await _external_json_payload(req, 64 * 1024)
                _external_payload_keys(payload, {
                    "coordinatorId",
                    "clientLease",
                    "clientLeaseEpoch",
                    "modeEpoch",
                })
                authorization = pack.authorization.authorize_request(req, operation_id)
                result = await asyncio.to_thread(
                    function,
                    pack._installation,
                    str(req.match_info.get("scope_id") or ""),
                    str(req.match_info.get("transition_id") or ""),
                    authorization,
                    **_external_transition_capability(req, payload),
                )
                return web.json_response(
                    {"ok": True, **result}, headers={"Cache-Control": "no-store"}
                )
            except Exception as exc:  # noqa: BLE001
                return _external_transition_error(web, exc)

        return await finalize_route(
            request, "mode.transition.finalize", finalize_external_transition
        )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition/{{transition_id}}/rollback"
    )
    async def post_helto_privacy_external_transition_rollback(request):
        from .external_mode_transition import rollback_external_transition

        return await _external_ack_route(
            request, "mode.transition.rollback", rollback_external_transition
        )

    def _external_operation_declaration(pack, operation_id):
        from .profile import ExternalOperationBinding

        declaration = next(
            (
                item
                for item in pack.profile.protected_operations
                if item.id == operation_id
                and isinstance(
                    item.external_operation_binding,
                    ExternalOperationBinding,
                )
            ),
            None,
        )
        if declaration is None:
            raise ValueError("external operation declaration invalid")
        return declaration

    def _required_external_operation_resume(request):
        from .external_operations import ExternalOperationError

        value = request.headers.get(_EXTERNAL_OPERATION_RESUME_HEADER)
        if (
            not isinstance(value, str)
            or re.fullmatch(r"hp-operation-resume-[A-Za-z0-9_-]{43}", value)
            is None
        ):
            raise ExternalOperationError("PRIVACY_EXTERNAL_OPERATION_FENCED")
        return value

    def _external_operation_exact(value, maximum):
        if (
            not isinstance(value, str)
            or len(value) > maximum * 2 + 8
            or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None
        ):
            raise ValueError("external operation exact value invalid")
        try:
            decoded = base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_",
                validate=True,
            )
        except Exception:
            raise ValueError("external operation exact value invalid") from None
        if len(decoded) > maximum:
            raise ValueError("external operation exact value invalid")
        return decoded

    def _external_operation_error(web, exc):
        from .external_operations import ExternalOperationError
        from .guard import PrivacyRouteError
        from .runtime import PackBlockedError

        if isinstance(exc, PackBlockedError):
            return _privacy_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
        if isinstance(exc, PrivacyRouteError):
            return _privacy_error_response(web, exc.code, exc.http_status)
        if isinstance(exc, ExternalOperationError):
            status = (
                404
                if exc.code == "PRIVACY_EXTERNAL_OPERATION_NOT_FOUND"
                else 400
                if exc.code == "PRIVACY_EXTERNAL_OPERATION_INVALID"
                else 500
                if exc.code in {
                    "PRIVACY_EXTERNAL_OPERATION_ADAPTER_INVALID",
                    "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED",
                    "PRIVACY_EXTERNAL_OPERATION_STATE_FAILED",
                }
                else 409
            )
            return _privacy_error_response(web, exc.code, status)
        if isinstance(exc, SuiteBlockedError):
            return _suite_blocked_response(web)
        if isinstance(exc, ValueError):
            return _privacy_error_response(
                web,
                "PRIVACY_EXTERNAL_OPERATION_INVALID",
                400,
            )
        return _privacy_error_response(
            web,
            "PRIVACY_EXTERNAL_OPERATION_RECOVERY_FAILED",
            500,
        )

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/operations/{{operation_id}}/external/prepare"
    )
    async def post_helto_privacy_external_operation_prepare(request):
        from ._plaintext import clear_mutable_plaintext
        from .external_operations import prepare_external_operation
        from .runtime import bound_privacy_pack

        payload = None
        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            operation_id = str(request.match_info.get("operation_id") or "")
            declaration = _external_operation_declaration(pack, operation_id)
            policy = declaration.external_operation_binding.policy
            maximum = min(
                49 * 1024 * 1024,
                policy.max_original_bytes * 2
                + policy.max_identity_bytes * 2
                + 10 * 1024 * 1024,
            )
            payload = await _external_json_payload(request, maximum)
            _external_payload_keys(
                payload,
                {
                    "requestId",
                    "ownerIdentity",
                    "originalExact",
                    "input",
                    "references",
                },
            )
            authorization = pack.authorization.authorize_request(
                request,
                operation_id,
            )
            result = await prepare_external_operation(
                pack._installation,
                operation_id,
                authorization,
                request_id=payload.get("requestId"),
                owner_identity=payload.get("ownerIdentity"),
                original_exact=_external_operation_exact(
                    payload.get("originalExact"),
                    policy.max_original_bytes,
                ),
                input_value=payload.get("input"),
                references=payload.get("references"),
            )
            return web.json_response(
                {"ok": True, **result},
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:  # noqa: BLE001
            return _external_operation_error(web, exc)
        finally:
            clear_mutable_plaintext(payload)

    @routes.get(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/operations/{{operation_id}}/external/"
        "{transaction_id}/status"
    )
    async def get_helto_privacy_external_operation_status(request):
        from .external_operations import external_operation_status
        from .runtime import bound_privacy_pack

        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            operation_id = str(request.match_info.get("operation_id") or "")
            _external_operation_declaration(pack, operation_id)
            authorization = pack.authorization.authorize_request(
                request,
                operation_id,
            )
            result = external_operation_status(
                pack._installation,
                operation_id,
                str(request.match_info.get("transaction_id") or ""),
                authorization,
            )
            return web.json_response(
                {"ok": True, **result},
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:  # noqa: BLE001
            return _external_operation_error(web, exc)

    async def _external_operation_action_route(request, action):
        from ._plaintext import clear_mutable_plaintext
        from .external_operations import (
            apply_external_operation,
            resume_external_operation,
            rollback_external_operation,
        )
        from .runtime import bound_privacy_pack

        payload = None
        try:
            pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
            operation_id = str(request.match_info.get("operation_id") or "")
            declaration = _external_operation_declaration(pack, operation_id)
            policy = declaration.external_operation_binding.policy
            maximum = (
                policy.max_target_bytes * 2 + 64 * 1024
                if action == "apply"
                else 64 * 1024
            )
            payload = await _external_json_payload(request, maximum)
            _external_payload_keys(
                payload,
                {"currentExact"} if action == "apply" else set(),
            )
            authorization = pack.authorization.authorize_request(
                request,
                operation_id,
            )
            arguments = (
                {
                    "current_exact": _external_operation_exact(
                        payload.get("currentExact"),
                        policy.max_target_bytes,
                    )
                }
                if action == "apply"
                else {}
            )
            function = {
                "apply": apply_external_operation,
                "resume": resume_external_operation,
                "rollback": rollback_external_operation,
            }[action]
            result = await function(
                pack._installation,
                operation_id,
                str(request.match_info.get("transaction_id") or ""),
                authorization,
                resume_capability=_required_external_operation_resume(request),
                **arguments,
            )
            return web.json_response(
                {"ok": True, **result},
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:  # noqa: BLE001
            return _external_operation_error(web, exc)
        finally:
            clear_mutable_plaintext(payload)

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/operations/{{operation_id}}/external/"
        "{transaction_id}/resume"
    )
    async def post_helto_privacy_external_operation_resume(request):
        return await _external_operation_action_route(request, "resume")

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/operations/{{operation_id}}/external/"
        "{transaction_id}/apply"
    )
    async def post_helto_privacy_external_operation_apply(request):
        return await _external_operation_action_route(request, "apply")

    @routes.post(
        f"{ROUTE_PREFIX}/profiles/{{pack_id}}/operations/{{operation_id}}/external/"
        "{transaction_id}/rollback"
    )
    async def post_helto_privacy_external_operation_rollback(request):
        return await _external_operation_action_route(request, "rollback")

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

    @routes.get(SUBMISSION_MODULE_ROUTE)
    async def get_helto_privacy_submission_module(_request):
        try:
            source = (_WEB_DIR / "privacy_submission.js").read_text(encoding="utf-8")
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

    @routes.get(QUEUE_MODULE_ROUTE)
    async def get_helto_privacy_queue_module(_request):
        try:
            source = (_WEB_DIR / "privacy_queue.js").read_text(encoding="utf-8")
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


async def _authorized_record_mutation_route(request, web, *, operation: str):
    from ._plaintext import clear_mutable_plaintext
    from .guard import PrivacyRouteError
    from .records import RecordError
    from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

    payload: object = None
    try:
        pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
        resource_id = str(request.match_info.get("resource_id") or "")
        record_kind = str(request.match_info.get("record_kind") or "")
        record_id = (
            None
            if operation == "create"
            else str(request.match_info.get("record_id") or "")
        )
        payload = await request.json()
        if not isinstance(payload, dict) or "value" not in payload:
            raise RecordError("PRIVACY_RECORD_MUTATION_INVALID")
        records = pack.records(resource_id)
        authorize = getattr(records, "authorize_request", None)
        authorization = (
            authorize(record_kind, request, f"record.{operation}")
            if callable(authorize)
            else pack.authorization.authorize_request(
                request,
                f"record.{operation}",
            )
        )
        if authorization is None:
            denied = _bootstrap_mutation_denial(request, require_json=True)
            if denied is not None:
                return _record_route_error_response(web, denied[0], denied[1])
        receipt = records.mutate(
            record_kind,
            operation,
            payload["value"],
            authorization,
            record_id=record_id,
        )
        return web.json_response(
            {
                "ok": True,
                "recordId": receipt.record_id,
                "kind": receipt.kind,
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
            "PRIVACY_RECORD_MUTATION_FAILED",
            500,
        )
    finally:
        clear_mutable_plaintext(payload)


async def _record_reference_route(request, web, *, operation: str):
    from ._plaintext import clear_mutable_plaintext
    from .guard import PrivacyRouteError
    from .record_relocation import RecordReferenceError
    from .runtime import PackBlockedError, UnknownResourceError, bound_privacy_pack

    payload: object = None
    try:
        pack = bound_privacy_pack(str(request.match_info.get("pack_id") or ""))
        resource_id = str(request.match_info.get("resource_id") or "")
        record_kind = str(request.match_info.get("record_kind") or "")
        migration_id = str(request.match_info.get("migration_id") or "")
        payload = await request.json()
        if not isinstance(payload, dict) or set(payload) != {"reference"}:
            raise RecordReferenceError("PRIVACY_RECORD_REFERENCE_INVALID")
        authorization = pack.authorization.authorize_request(
            request,
            f"record.reference.{operation}",
        )
        records = pack.records(resource_id)
        result = (
            records.migrate_legacy_reference(
                record_kind,
                migration_id,
                payload["reference"],
                authorization,
            )
            if operation == "migrate"
            else records.resolve_legacy_reference(
                record_kind,
                migration_id,
                payload["reference"],
                authorization,
            )
        )
        response = {
            "ok": True,
            "recordId": result.record_id,
            "correlationId": result.correlation_id,
        }
        if operation == "migrate":
            response["disposition"] = result.disposition
        return web.json_response(
            response,
            headers=_record_response_headers(result.correlation_id),
        )
    except PackBlockedError:
        return _record_route_error_response(web, "PRIVACY_PROFILE_UNAVAILABLE", 404)
    except UnknownResourceError:
        return _record_route_error_response(web, "PRIVACY_RECORD_RESOURCE_INVALID", 400)
    except SuiteBlockedError:
        return _record_route_error_response(web, "PRIVACY_SUITE_BLOCKED", 409)
    except PrivacyRouteError as exc:
        return _record_route_error_response(web, exc.code, exc.http_status)
    except RecordReferenceError as exc:
        return _record_route_error_response(
            web,
            exc.code,
            _record_error_status(exc.code),
            exc.correlation_id,
        )
    except Exception:  # noqa: BLE001
        return _record_route_error_response(
            web,
            "PRIVACY_RECORD_REFERENCE_UNAVAILABLE",
            409,
        )
    finally:
        clear_mutable_plaintext(payload)


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


def _mode_facts_from_payload(value):
    from .mode import ModeEvidence, ModeFacts

    if value is None:
        return ModeFacts()
    if not isinstance(value, dict):
        raise ValueError("Invalid mode facts.")
    allowed = {
        "globalMode",
        "requestMode",
        "currentMode",
        "upstream",
        "parents",
        "records",
        "artifacts",
        "executions",
    }
    if set(value) - allowed:
        raise ValueError("Invalid mode facts.")

    def evidence(name: str) -> tuple[ModeEvidence, ...]:
        items = value.get(name, [])
        if not isinstance(items, list):
            raise ValueError("Invalid mode evidence.")
        result = []
        for item in items:
            if not isinstance(item, dict) or set(item) != {"sourceId", "mode"}:
                raise ValueError("Invalid mode evidence.")
            result.append(ModeEvidence(str(item["sourceId"]), item["mode"]))
        return tuple(result)

    return ModeFacts(
        global_mode=value.get("globalMode"),
        request_mode=value.get("requestMode"),
        current_mode=value.get("currentMode"),
        upstream=evidence("upstream"),
        parents=evidence("parents"),
        records=evidence("records"),
        artifacts=evidence("artifacts"),
        executions=evidence("executions"),
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
