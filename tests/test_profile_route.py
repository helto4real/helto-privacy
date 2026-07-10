import asyncio
import sys
import types

import helto_privacy.comfy_ui as comfy_ui
import helto_privacy.runtime as runtime
from helto_privacy.profile import (
    AdapterSlot,
    PrivacyProfile,
    PrivacyScope,
    ProfileResource,
    ResourceKind,
)


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
            PrivacyScope("route-test", "privacy-mode", "mode-server"),
        ),
    )


def test_profile_route_is_no_store_safe_and_independent_of_aiohttp(monkeypatch):
    monkeypatch.setattr(comfy_ui, "_ROUTES_REGISTERED", False)
    monkeypatch.setattr(comfy_ui, "_LEGACY_KEY_DIRS", [])
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})

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
    runtime.install(profile, {"mode-server": object()})
    prompt_server = types.SimpleNamespace(routes=_Routes())
    assert runtime.reconcile_prompt_server(prompt_server) is True

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
    assert response.data["resources"] == [{"id": "privacy-mode", "kind": "mode"}]
    assert "token" not in str(response.data).lower()
    assert "secret" not in str(response.data).lower()

    missing = asyncio.run(
        handler(types.SimpleNamespace(match_info={"pack_id": "helto.missing"}))
    )
    assert missing.status == 404
    assert missing.headers == {"Cache-Control": "no-store"}
    assert missing.data == {"ok": False, "error": "PRIVACY_PROFILE_UNAVAILABLE"}
