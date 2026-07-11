import asyncio
import sys
import types

import helto_privacy.comfy_ui as comfy_ui
import helto_privacy.runtime as runtime
import helto_privacy.suite_runtime as suite_runtime
from helto_privacy.profile import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
)
from helto_privacy.suite_runtime import SuiteInstallation, register_process_suite
from helto_privacy.snapshot import SnapshotError
from test_suite_runtime import _inventory, _release


class _Response:
    def __init__(self, data=None, *, status=200, headers=None, **kwargs):
        self.data = data
        self.status = status
        self.headers = headers or {}
        self.kwargs = kwargs


class _Routes:
    def __init__(self):
        self.handlers = {}

    def get(self, path):
        return self._decorator("GET", path)

    def post(self, path):
        return self._decorator("POST", path)

    def _decorator(self, method, path):
        def register(handler):
            self.handlers[(method, path)] = handler
            return handler

        return register


def _profile():
    return PrivacyProfile(
        id="helto.route-test",
        distribution="comfyui-helto-route-test",
        resources=(
            ProfileResource(
                "privacy-mode",
                ResourceKind.MODE,
                ("mode-browser", "mode-server"),
            ),
        ),
        server_adapters=(
            AdapterSlot("mode-server", ResourceKind.MODE, "privacy-mode"),
        ),
        browser_adapters=(
            AdapterSlot(
                "mode-browser",
                ResourceKind.MODE,
                "privacy-mode",
                ("HeltoRouteTest",),
            ),
        ),
        scopes=(
            PrivacyScope(
                "route-test",
                "privacy-mode",
                "mode-server",
                mode_editor_adapter="mode-browser",
            ),
        ),
    )


def test_profile_routes_are_safe_and_independent_of_aiohttp(
    monkeypatch,
    tmp_path,
    isolated_privacy_paths,
):
    monkeypatch.setattr(comfy_ui, "_ROUTES_REGISTERED", False)
    monkeypatch.setattr(comfy_ui, "_LEGACY_KEY_DIRS", [])
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_INSTALLATION", None)
    monkeypatch.setattr(suite_runtime, "_PROCESS_SUITE_CONFLICT", False)

    server_module = types.ModuleType("server")
    server_module.PromptServer = types.SimpleNamespace(instance=None)
    monkeypatch.setitem(sys.modules, "server", server_module)

    web = types.SimpleNamespace(
        json_response=lambda data, **kwargs: _Response(data, **kwargs),
        Response=_Response,
    )
    aiohttp = types.ModuleType("aiohttp")
    aiohttp.web = web
    monkeypatch.setitem(sys.modules, "aiohttp", aiohttp)

    profile = _profile()
    runtime.install(
        profile,
        {
            "mode-server": types.SimpleNamespace(
                read_declared_mode=lambda: None,
                write_declared_mode=lambda: None,
                prepare_mode_transition=lambda *_args: None,
                commit_mode_transition=lambda *_args: None,
                rollback_mode_transition=lambda *_args: None,
            ),
        },
    )
    prompt_server = types.SimpleNamespace(routes=_Routes())
    assert runtime.reconcile_prompt_server(prompt_server) is True

    monkeypatch.setattr(
        comfy_ui.keystore,
        "keystore_status",
        lambda: {
            "keystoreAvailable": True,
            "keystoreInitialized": True,
            "keystoreLocked": True,
            "keystorePath": "/SYNTHETIC_PRIVATE_PATH",
            "sessionPath": "/SYNTHETIC_PRIVATE_SESSION",
        },
    )
    status_handler = prompt_server.routes.handlers[
        ("GET", f"{comfy_ui.ROUTE_PREFIX}/status")
    ]
    status_response = asyncio.run(status_handler(types.SimpleNamespace()))
    assert status_response.data == {
        "ok": True,
        "keystoreAvailable": True,
        "keystoreInitialized": True,
        "keystoreLocked": True,
        "suiteStatus": "incomplete",
        "suiteManifestDigest": None,
        "suiteIssueCodes": ["suite_not_configured"],
    }
    assert status_response.headers == {"Cache-Control": "no-store"}
    assert "SYNTHETIC_PRIVATE" not in str(status_response.data)

    monkeypatch.setattr(
        comfy_ui,
        "require_active_process_suite",
        isolated_privacy_paths[1],
    )

    async def unlock_payload():
        return {"password": "synthetic password"}

    unlock_handler = prompt_server.routes.handlers[
        ("POST", f"{comfy_ui.ROUTE_PREFIX}/unlock")
    ]
    blocked_unlock = asyncio.run(
        unlock_handler(types.SimpleNamespace(json=unlock_payload))
    )
    assert blocked_unlock.status == 409
    assert blocked_unlock.data == {
        "ok": False,
        "error": "PRIVACY_SUITE_BLOCKED",
    }

    handler = prompt_server.routes.handlers[
        ("GET", f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}")
    ]
    response = asyncio.run(
        handler(types.SimpleNamespace(match_info={"pack_id": profile.id}))
    )

    assert response.status == 200
    assert response.headers == {"Cache-Control": "no-store"}
    assert response.data["ok"] is True
    assert response.data["status"] == "ready"
    assert response.data["fingerprint"] == profile.fingerprint
    assert response.data["suiteStatus"] == "incomplete"
    assert response.data["suiteManifestDigest"] is None
    assert response.data["resources"] == [{"id": "privacy-mode", "kind": "mode"}]
    assert response.data["modeScopes"] == [
        {"id": "route-test", "modeResourceId": "privacy-mode"}
    ]
    assert response.data["protectedFields"] == []
    assert response.data["executionProjections"] == []
    assert response.data["protectedOperations"] == []
    assert "token" not in str(response.data).lower()
    assert "secret" not in str(response.data).lower()

    class Resolution:
        declared = types.SimpleNamespace(value="private")
        effective = types.SimpleNamespace(value="private")
        inherited_from = "base-private"
        floors = ()
        transition_status = types.SimpleNamespace(value="idle")

    class Mode:
        def resolve(self, scope_id):
            assert scope_id == "route-test"
            return Resolution()

        def transition(self, scope_id, target, authorization):
            assert (scope_id, target, authorization) == (
                "route-test",
                "public",
                "synthetic-authorization",
            )
            return types.SimpleNamespace(
                scope_id=scope_id,
                declared=types.SimpleNamespace(value="public"),
                effective=types.SimpleNamespace(value="public"),
                status=types.SimpleNamespace(value="idle"),
            )

    class Authorization:
        def authorize_declassification(self, request, scope_id, target):
            assert request.headers["X-Helto-Privacy-Declassification"] == "confirmed"
            assert (scope_id, target) == ("route-test", "public")
            return "synthetic-authorization"

        def authorize_request(self, _request, operation):
            assert operation in {
                "snapshot.disposition",
                "snapshot.protect",
                "execution.prepare",
            }
            return f"synthetic-{operation}"

    fake_pack = types.SimpleNamespace(
        profile=profile,
        authorization=Authorization(),
        mode=lambda resource_id: Mode(),
    )
    monkeypatch.setattr(runtime, "bound_privacy_pack", lambda pack_id: fake_pack)

    mode_handler = prompt_server.routes.handlers[
        ("GET", f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}/modes")
    ]
    mode_response = asyncio.run(
        mode_handler(types.SimpleNamespace(match_info={"pack_id": profile.id}))
    )
    assert mode_response.data == {
        "ok": True,
        "packId": profile.id,
        "scopes": [
            {
                "id": "route-test",
                "modeResourceId": "privacy-mode",
                "declared": "private",
                "effective": "private",
                "inheritedFrom": "base-private",
                "floors": [],
                "transitionStatus": "idle",
            }
        ],
    }
    assert mode_response.headers == {"Cache-Control": "no-store"}

    async def transition_payload():
        return {"target": "public"}

    transition_handler = prompt_server.routes.handlers[
        (
            "POST",
            f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}/modes/{{scope_id}}/transition",
        )
    ]
    transition_response = asyncio.run(
        transition_handler(
            types.SimpleNamespace(
                match_info={"pack_id": profile.id, "scope_id": "route-test"},
                headers={"X-Helto-Privacy-Declassification": "confirmed"},
                json=transition_payload,
            )
        )
    )
    assert transition_response.data == {
        "ok": True,
        "scopeId": "route-test",
        "declared": "public",
        "effective": "public",
        "transitionStatus": "idle",
    }
    assert transition_response.headers == {"Cache-Control": "no-store"}

    snapshot_field = types.SimpleNamespace(
        id="private-state",
        workflow_resource_id="state",
    )

    class Workflow:
        def inspect_disposition(self, field_id, protected_value, authorization):
            assert (field_id, protected_value, authorization) == (
                "private-state",
                "SYNTHETIC_CIPHERTEXT",
                "synthetic-snapshot.disposition",
            )
            return types.SimpleNamespace(
                disposition=types.SimpleNamespace(value="verified-current"),
                replacement_envelope=None,
            )

        def protect(self, field_id, value, authorization):
            assert (field_id, value, authorization) == (
                "private-state",
                {"value": "SYNTHETIC_PLAINTEXT_CANARY"},
                "synthetic-snapshot.protect",
            )
            return types.SimpleNamespace(
                disposition=types.SimpleNamespace(value="verified-current"),
                envelope={"encrypted": True, "ciphertext": "opaque"},
            )

    class Execution:
        def prepare(self, projection_id, protected_fields, authorization):
            assert projection_id == "product-execution"
            assert protected_fields == {"private-state": "SYNTHETIC_CIPHERTEXT"}
            assert authorization == "synthetic-execution.prepare"
            return types.SimpleNamespace(
                reference={
                    "schema": "helto.private-execution-reference",
                    "version": 1,
                    "packId": profile.id,
                    "executionResourceId": "dispatch",
                    "projectionId": projection_id,
                    "workflowResourceId": "state",
                    "grant": "opaque-grant",
                    "fields": [
                        {
                            "fieldId": "private-state",
                            "protectedValue": "SYNTHETIC_CIPHERTEXT",
                        }
                    ],
                },
            )

    fake_pack.profile = types.SimpleNamespace(
        id=profile.id,
        scopes=profile.scopes,
        protected_fields=(snapshot_field,),
    )
    def resolve_snapshot_field(field_id):
        if field_id != snapshot_field.id:
            raise SnapshotError("PRIVACY_SNAPSHOT_FIELD_INVALID")
        return Workflow(), snapshot_field

    fake_pack.snapshot_field = resolve_snapshot_field
    fake_pack.execution = lambda resource_id: Execution()

    async def disposition_payload():
        return {"protectedValue": "SYNTHETIC_CIPHERTEXT"}

    disposition_handler = prompt_server.routes.handlers[
        (
            "POST",
            f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}/fields/{{field_id}}/disposition",
        )
    ]
    disposition_response = asyncio.run(
        disposition_handler(
            types.SimpleNamespace(
                match_info={"pack_id": profile.id, "field_id": "private-state"},
                headers={},
                cookies={},
                json=disposition_payload,
            )
        )
    )
    assert disposition_response.data == {
        "ok": True,
        "fieldId": "private-state",
        "disposition": "verified-current",
    }

    async def protect_payload():
        return {"value": {"value": "SYNTHETIC_PLAINTEXT_CANARY"}}

    protect_handler = prompt_server.routes.handlers[
        (
            "POST",
            f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}/fields/{{field_id}}/protect",
        )
    ]
    protect_response = asyncio.run(
        protect_handler(
            types.SimpleNamespace(
                match_info={"pack_id": profile.id, "field_id": "private-state"},
                headers={},
                cookies={},
                json=protect_payload,
            )
        )
    )
    assert protect_response.data == {
        "ok": True,
        "fieldId": "private-state",
        "disposition": "verified-current",
        "envelope": {"encrypted": True, "ciphertext": "opaque"},
    }
    assert "SYNTHETIC_PLAINTEXT_CANARY" not in str(protect_response.data)

    invalid_field_response = asyncio.run(
        disposition_handler(
            types.SimpleNamespace(
                match_info={"pack_id": profile.id, "field_id": "missing-field"},
                headers={},
                cookies={},
                json=disposition_payload,
            )
        )
    )
    assert invalid_field_response.status == 400
    assert invalid_field_response.data == {
        "ok": False,
        "error": "PRIVACY_SNAPSHOT_FIELD_INVALID",
    }

    async def execution_payload():
        return {
            "projectionId": "product-execution",
            "fields": [
                {
                    "fieldId": "private-state",
                    "protectedValue": "SYNTHETIC_CIPHERTEXT",
                }
            ],
        }

    execution_handler = prompt_server.routes.handlers[
        (
            "POST",
            f"{comfy_ui.ROUTE_PREFIX}/profiles/{{pack_id}}/executions/"
            "{execution_id}/prepare",
        )
    ]
    execution_response = asyncio.run(
        execution_handler(
            types.SimpleNamespace(
                match_info={"pack_id": profile.id, "execution_id": "dispatch"},
                headers={},
                cookies={},
                json=execution_payload,
            )
        )
    )
    assert execution_response.status == 200
    assert execution_response.headers == {"Cache-Control": "no-store"}
    assert execution_response.data["ok"] is True
    assert "cacheIdentity" not in execution_response.data
    assert execution_response.data["reference"]["grant"] == "opaque-grant"
    assert "SYNTHETIC_PLAINTEXT_CANARY" not in str(execution_response.data)

    missing = asyncio.run(
        handler(types.SimpleNamespace(match_info={"pack_id": "helto.missing"}))
    )
    assert missing.status == 404
    assert missing.headers == {"Cache-Control": "no-store"}
    assert missing.data == {"ok": False, "error": "PRIVACY_PROFILE_UNAVAILABLE"}

    module_handler = prompt_server.routes.handlers[
        ("GET", comfy_ui.PROFILE_MODULE_ROUTE)
    ]
    client_module_handler = prompt_server.routes.handlers[
        ("GET", comfy_ui.CLIENT_MODULE_ROUTE)
    ]
    snapshot_module_handler = prompt_server.routes.handlers[
        ("GET", comfy_ui.SNAPSHOT_MODULE_ROUTE)
    ]
    client_module_response = asyncio.run(
        client_module_handler(types.SimpleNamespace())
    )
    assert client_module_response.status == 200
    assert "connectAttestedPrivacyProfileClient" in client_module_response.kwargs["text"]
    snapshot_module_response = asyncio.run(
        snapshot_module_handler(types.SimpleNamespace())
    )
    assert snapshot_module_response.status == 200
    assert "createPrivacySnapshotCoordinator" in snapshot_module_response.kwargs["text"]
    release = _release(ready=False)
    suite = SuiteInstallation(release)
    suite._verify_inventory(_inventory(release.manifest))
    register_process_suite(suite)

    async def browser_attestation_payload():
        return {"manifestDigest": release.manifest.digest}

    browser_attestation_handler = prompt_server.routes.handlers[
        ("POST", f"{comfy_ui.ROUTE_PREFIX}/suite/browser-attestation")
    ]
    browser_attestation = asyncio.run(
        browser_attestation_handler(
            types.SimpleNamespace(json=browser_attestation_payload)
        )
    )
    assert browser_attestation.status == 200
    assert browser_attestation.data == {
        "ok": True,
        "suiteManifestDigest": release.manifest.digest,
    }
    module_request = types.SimpleNamespace(
        match_info={"manifest_digest": release.manifest.digest}
    )
    module_response = asyncio.run(module_handler(module_request))
    assert module_response.status == 200
    assert module_response.headers == {
        "Cache-Control": "public, max-age=31536000, immutable"
    }
    assert module_response.kwargs["content_type"] == "application/javascript"
    assert "export async function connectPrivacyPack" in module_response.kwargs["text"]

    wrong_digest = asyncio.run(
        module_handler(
            types.SimpleNamespace(match_info={"manifest_digest": "e" * 64})
        )
    )
    assert wrong_digest.status == 409
    assert wrong_digest.data == {
        "ok": False,
        "error": "PRIVACY_SUITE_ASSET_MISMATCH",
    }

    monkeypatch.setattr(comfy_ui, "_WEB_DIR", tmp_path / "missing-web-directory")
    unavailable = asyncio.run(module_handler(module_request))
    assert unavailable.status == 500
    assert unavailable.data == {
        "ok": False,
        "error": "PRIVACY_BROWSER_MODULE_UNAVAILABLE",
    }

    conflicting_browser = asyncio.run(
        browser_attestation_handler(
            types.SimpleNamespace(
                json=lambda: _async_value({"manifestDigest": "e" * 64})
            )
        )
    )
    assert conflicting_browser.status == 409
    assert suite_runtime.process_suite_status_payload()["suiteStatus"] == "conflict"


async def _async_value(value):
    return value
