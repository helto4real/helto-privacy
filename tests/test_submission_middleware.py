from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

import helto_privacy.submission_middleware as submission
from helto_privacy.subject_mode import PendingSubjectModeValidation


class _FakeApp:
    def __init__(self, middlewares=()):
        self.middlewares = list(middlewares)
        self.pre_frozen = False
        self.frozen = False


class _FakeServer:
    def __init__(self, app=None):
        self.app = app if app is not None else _FakeApp()


def test_installer_is_first_app_scoped_and_idempotent(monkeypatch):
    monkeypatch.setattr(submission, "_INSTALLED", submission.WeakKeyDictionary())

    async def sentinel(request, handler):
        return await handler(request)

    app = _FakeApp([sentinel])
    server = _FakeServer(app)
    assert submission.install_prompt_submission_middleware(server) is True
    assert app.middlewares == [submission._prompt_submission_middleware, sentinel]
    assert submission.install_prompt_submission_middleware(server) is False
    assert app.middlewares == [submission._prompt_submission_middleware, sentinel]


@pytest.mark.parametrize("flag", ["pre_frozen", "frozen"])
def test_installer_rejects_frozen_apps(monkeypatch, flag):
    monkeypatch.setattr(submission, "_INSTALLED", submission.WeakKeyDictionary())
    app = _FakeApp()
    setattr(app, flag, True)
    with pytest.raises(submission.PromptSubmissionMiddlewareError) as error:
        submission.install_prompt_submission_middleware(_FakeServer(app))
    assert error.value.code == "prompt_server_frozen"
    assert app.middlewares == []


def test_installer_rejects_missing_and_conflicting_hooks(monkeypatch):
    monkeypatch.setattr(submission, "_INSTALLED", submission.WeakKeyDictionary())
    with pytest.raises(submission.PromptSubmissionMiddlewareError) as missing:
        submission.install_prompt_submission_middleware(SimpleNamespace())
    assert missing.value.code == "prompt_server_missing"

    async def conflict(request, handler):
        return await handler(request)

    setattr(conflict, submission._MIDDLEWARE_MARKER, True)
    app = _FakeApp([conflict])
    with pytest.raises(submission.PromptSubmissionMiddlewareError) as error:
        submission.install_prompt_submission_middleware(_FakeServer(app))
    assert error.value.code == "prompt_middleware_conflict"


def test_real_aiohttp_prompt_paths_run_first_and_preserve_cached_body(monkeypatch):
    pytest.importorskip("aiohttp")
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    order = []
    routed = []

    def validator(body):
        order.append("validator")
        assert body["prompt"]["1"]["class_type"] == "OtherNode"
        return True

    monkeypatch.setattr(submission, "validate_prompt_submission", validator)
    monkeypatch.setattr(submission, "_INSTALLED", submission.WeakKeyDictionary())

    @web.middleware
    async def sentinel(request, handler):
        order.append("sentinel")
        return await handler(request)

    async def scenario():
        app = web.Application(middlewares=[sentinel])

        async def route(request):
            first = await request.json()
            second = await request.json()
            routed.append((first, second))
            order.append("route")
            return web.json_response({"ok": first == second})

        app.router.add_post("/prompt", route)
        app.router.add_post("/api/prompt", route)
        server_shape = SimpleNamespace(app=app)
        assert submission.install_prompt_submission_middleware(server_shape) is True
        assert submission.install_prompt_submission_middleware(server_shape) is False
        async with TestClient(TestServer(app)) as client:
            body = {"prompt": {"1": {"class_type": "OtherNode", "inputs": {}}}}
            for path in ("/prompt", "/api/prompt"):
                response = await client.post(path, json=body)
                assert response.status == 200
                assert await response.json() == {"ok": True}

    asyncio.run(scenario())
    assert order == [
        "validator", "sentinel", "route",
        "validator", "sentinel", "route",
    ]
    assert routed == [(routed[0][0], routed[0][0]), (routed[1][0], routed[1][0])]


def test_real_aiohttp_rejections_are_empty_no_store_and_never_route(monkeypatch):
    pytest.importorskip("aiohttp")
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    routed = []
    monkeypatch.setattr(submission, "_INSTALLED", submission.WeakKeyDictionary())

    async def scenario():
        app = web.Application()

        async def route(_request):
            routed.append(True)
            return web.Response(text="routed")

        app.router.add_post("/prompt", route)
        submission.install_prompt_submission_middleware(SimpleNamespace(app=app))
        async with TestClient(TestServer(app)) as client:
            cases = (
                {"data": b"{", "headers": {"Content-Type": "application/json"}},
                {"data": b"{}", "headers": {"Content-Type": "text/plain"}},
                {
                    "json": {"prompt": {}},
                    "headers": {"Origin": "https://attacker.invalid"},
                },
            )
            for kwargs in cases:
                response = await client.post("/prompt", **kwargs)
                assert response.status == 400
                assert await response.read() == b""
                assert response.headers["Cache-Control"] == "no-store"

            monkeypatch.setattr(
                submission,
                "validate_prompt_submission",
                lambda _body: (_ for _ in ()).throw(RuntimeError("private reason")),
            )
            response = await client.post("/prompt", json={"prompt": {}})
            assert response.status == 400
            assert await response.read() == b""
            assert response.headers["Cache-Control"] == "no-store"

    asyncio.run(scenario())
    assert routed == []


def test_nonprompt_requests_bypass_validation(monkeypatch):
    pytest.importorskip("aiohttp")
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    monkeypatch.setattr(submission, "_INSTALLED", submission.WeakKeyDictionary())
    monkeypatch.setattr(
        submission,
        "validate_prompt_submission",
        lambda _body: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    async def scenario():
        app = web.Application()

        async def other(_request):
            return web.Response(text="unchanged")

        app.router.add_post("/other", other)
        submission.install_prompt_submission_middleware(SimpleNamespace(app=app))
        async with TestClient(TestServer(app)) as client:
            response = await client.post("/other", data="not-json")
            assert response.status == 200
            assert await response.text() == "unchanged"

    asyncio.run(scenario())


def test_downstream_exception_is_not_caught(monkeypatch):
    monkeypatch.setattr(submission, "validate_prompt_submission", lambda _body: True)

    class Request:
        method = "POST"
        path = "/prompt"
        content_type = "application/json"
        content_length = 2
        headers = {}
        scheme = "http"
        host = "127.0.0.1"

        async def read(self):
            return b"{}"

        async def json(self):
            return {"prompt": {}}

    async def downstream(_request):
        raise RuntimeError("downstream sentinel")

    with pytest.raises(RuntimeError, match="downstream sentinel"):
        asyncio.run(submission._prompt_submission_middleware(Request(), downstream))


def _profile_view(*, ready=True):
    field = SimpleNamespace(
        execution=True,
        workflow_resource_id="workflow",
        node_types=("HeltoNode",),
        legacy_reader_ids=("legacy-v1",),
    )
    operation = SimpleNamespace(
        id="render",
        resource_id="result",
        scope_id="main",
        subject_mode_binding_id="render-mode",
    )
    binding = SimpleNamespace(
        id="render-mode",
        scope_id="main",
        input_name="privacy_mode_reference",
        node_types=("HeltoNode",),
    )
    projection = SimpleNamespace(
        id="execute",
        execution_resource_id="execution",
        workflow_resource_id="workflow",
        subject_mode_binding_id="render-mode",
        input_name="private_execution",
    )
    profile = SimpleNamespace(
        id="helto.test",
        server_adapters=(),
        browser_adapters=(SimpleNamespace(node_types=("HeltoNode",)),),
        protected_fields=(field,),
        subject_mode_bindings=(binding,),
        protected_operations=(operation,),
        execution_projections=(projection,),
    )
    return submission._ProfileView(profile, ready)


def _reference(schema, grant):
    return {"schema": schema, "grant": grant}


def _body(*, subject=True, execution=True, moved=False, legacy=False):
    inputs = {}
    if subject:
        inputs["privacy_mode_reference"] = json.dumps(
            _reference(submission.SUBJECT_MODE_REFERENCE_SCHEMA, "subject-grant")
        )
    if execution:
        name = "moved" if moved else "private_execution"
        inputs[name] = json.dumps(
            _reference(submission.EXECUTION_REFERENCE_SCHEMA, "execution-grant")
        )
    return {
        "prompt": {"1": {"class_type": "HeltoNode", "inputs": inputs}},
        "extra_data": {
            "extra_pnginfo": {
                "workflow": {
                    "nodes": [
                        {
                            "id": 1,
                            "type": "HeltoNode",
                            "properties": {"value": "LEGACY" if legacy else "CURRENT"},
                        }
                    ]
                }
            }
        },
    }


@pytest.fixture
def validator_runtime(monkeypatch):
    monkeypatch.setattr(submission, "_profile_views", lambda: (_profile_view(),))
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite", lambda: object(),
    )
    monkeypatch.setattr(
        submission,
        "probe_registered_legacy_value",
        lambda value, _reader_ids: value == "LEGACY",
    )
    monkeypatch.setattr(
        submission,
        "validate_pending_subject_mode_reference",
        lambda *_args, **_kwargs: PendingSubjectModeValidation(True, True),
    )
    monkeypatch.setattr(
        submission,
        "validate_pending_execution_reference",
        lambda *_args, **_kwargs: True,
    )


def test_validator_accepts_exact_refs_without_consuming(validator_runtime):
    body = _body()
    before = json.dumps(body, sort_keys=True)
    assert submission.validate_prompt_submission(body) is True
    assert json.dumps(body, sort_keys=True) == before


def test_validator_rejects_execution_grants_swapped_between_same_type_nodes(
    validator_runtime, monkeypatch,
):
    first = _body()
    first_node = first["prompt"].pop("1")
    first_node["inputs"]["privacy_mode_reference"] = json.dumps(
        _reference(submission.SUBJECT_MODE_REFERENCE_SCHEMA, "subject-1")
    )
    first_node["inputs"]["private_execution"] = json.dumps(
        _reference(submission.EXECUTION_REFERENCE_SCHEMA, "execution-1")
    )
    second_node = {
        "class_type": "HeltoNode",
        "inputs": {
            "privacy_mode_reference": json.dumps(
                _reference(submission.SUBJECT_MODE_REFERENCE_SCHEMA, "subject-2")
            ),
            "private_execution": json.dumps(
                _reference(submission.EXECUTION_REFERENCE_SCHEMA, "execution-2")
            ),
        },
    }
    first["prompt"] = {"1": first_node, "2": second_node}
    first["extra_data"]["extra_pnginfo"]["workflow"]["nodes"].append(
        {"id": 2, "type": "HeltoNode"}
    )
    monkeypatch.setattr(
        submission,
        "validate_pending_execution_reference",
        lambda reference, *, subject_id, **_kwargs: (
            reference.get("grant") == f"execution-{subject_id}"
        ),
    )
    assert submission.validate_prompt_submission(first) is True

    swapped = json.loads(json.dumps(first))
    left = swapped["prompt"]["1"]["inputs"]["private_execution"]
    swapped["prompt"]["1"]["inputs"]["private_execution"] = swapped["prompt"]["2"][
        "inputs"
    ]["private_execution"]
    swapped["prompt"]["2"]["inputs"]["private_execution"] = left
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(swapped)


@pytest.mark.parametrize(
    "body",
    [
        _body(subject=False),
        _body(execution=False),
        _body(moved=True),
        _body(legacy=True),
    ],
)
def test_validator_rejects_missing_moved_and_legacy_refs(validator_runtime, body):
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(body)


def test_validator_rejects_stale_refs_and_inactive_profiles(
    validator_runtime, monkeypatch,
):
    monkeypatch.setattr(
        submission,
        "validate_pending_subject_mode_reference",
        lambda *_args, **_kwargs: PendingSubjectModeValidation(False, False),
    )
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(_body())


def test_validator_rejects_duplicate_nested_and_malformed_refs(
    validator_runtime, monkeypatch,
):
    duplicate = _body()
    duplicate["prompt"]["1"]["inputs"]["duplicate"] = duplicate["prompt"]["1"][
        "inputs"
    ]["private_execution"]
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(duplicate)

    nested = _body()
    nested["prompt"]["1"]["inputs"]["private_execution"] = {
        "nested": json.loads(
            nested["prompt"]["1"]["inputs"]["private_execution"]
        )
    }
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(nested)

    malformed = _body()
    malformed["prompt"]["1"]["inputs"]["private_execution"] = json.dumps(
        {"schema": submission.EXECUTION_REFERENCE_SCHEMA}
    )
    monkeypatch.setattr(
        submission,
        "validate_pending_execution_reference",
        lambda reference, **_kwargs: bool(reference.get("grant")),
    )
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(malformed)

    monkeypatch.setattr(submission, "_profile_views", lambda: (_profile_view(ready=False),))
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(_body())


def test_validator_fails_closed_at_traversal_bounds(validator_runtime):
    body = _body()
    cursor = body["extra_data"]["extra_pnginfo"]["workflow"]["nodes"][0]
    for _index in range(submission._MAX_DEPTH + 1):
        nested = {}
        cursor["nested"] = nested
        cursor = nested
    with pytest.raises(ValueError):
        submission.validate_prompt_submission(body)


def test_legacy_probe_cannot_mutate_incoming_workflow(
    validator_runtime, monkeypatch,
):
    body = _body()
    before = json.dumps(body, sort_keys=True)

    def mutating_probe(value, _reader_ids):
        if isinstance(value, dict):
            value["mutated"] = True
        return False

    monkeypatch.setattr(submission, "probe_registered_legacy_value", mutating_probe)
    with pytest.raises(TypeError):
        submission.validate_prompt_submission(body)
    assert json.dumps(body, sort_keys=True) == before


def test_unrelated_prompt_passes_without_suite_or_workflow(monkeypatch):
    monkeypatch.setattr(submission, "_profile_views", lambda: (_profile_view(),))
    body = {"prompt": {"1": {"class_type": "OtherNode", "inputs": {}}}}
    assert submission.validate_prompt_submission(body) is True


def test_workflow_only_helto_nodes_still_enter_fail_closed_validation(monkeypatch):
    body = {
        "prompt": {"1": {"class_type": "OtherNode", "inputs": {}}},
        "extra_data": {
            "extra_pnginfo": {
                "workflow": {
                    "nodes": [
                        {
                            "id": 7,
                            "type": "HeltoNode",
                            "properties": {"value": "LEGACY"},
                        }
                    ]
                }
            }
        },
    }
    monkeypatch.setattr(submission, "_profile_views", lambda: (_profile_view(),))
    monkeypatch.setattr(
        "helto_privacy.suite_runtime.require_active_process_suite",
        lambda: object(),
    )
    monkeypatch.setattr(
        submission,
        "probe_registered_legacy_value",
        lambda value, _reader_ids: value == "LEGACY",
    )

    with pytest.raises(ValueError):
        submission.validate_prompt_submission(body)


def test_workflow_only_helto_nodes_require_a_ready_profile(monkeypatch):
    body = {
        "prompt": {"1": {"class_type": "OtherNode", "inputs": {}}},
        "extra_data": {
            "extra_pnginfo": {
                "workflow": {"nodes": [{"id": 7, "type": "HeltoNode"}]},
            }
        },
    }
    monkeypatch.setattr(
        submission,
        "_profile_views",
        lambda: (_profile_view(ready=False),),
    )

    with pytest.raises(ValueError):
        submission.validate_prompt_submission(body)


@pytest.mark.parametrize(
    "workflow",
    [None, {"arbitrary": ["metadata"]}, "arbitrary scalar workflow metadata"],
)
def test_unrelated_prompt_ignores_missing_or_non_graph_workflow(
    monkeypatch,
    workflow,
):
    monkeypatch.setattr(submission, "_profile_views", lambda: (_profile_view(),))
    body = {"prompt": {"1": {"class_type": "OtherNode", "inputs": {}}}}
    if workflow is not None:
        body["extra_data"] = {"extra_pnginfo": {"workflow": workflow}}
    assert submission.validate_prompt_submission(body) is True


@pytest.mark.parametrize(
    "workflow",
    [None, {"arbitrary": ["metadata"]}, "arbitrary scalar workflow metadata"],
)
def test_helto_prompt_with_missing_or_non_graph_workflow_is_empty_400(
    validator_runtime,
    workflow,
):
    pytest.importorskip("aiohttp")
    body = _body()
    if workflow is None:
        body.pop("extra_data")
    else:
        body["extra_data"]["extra_pnginfo"]["workflow"] = workflow
    routed = []

    class Request:
        method = "POST"
        path = "/prompt"
        content_type = "application/json"
        headers = {}
        scheme = "http"
        host = "127.0.0.1"

        def __init__(self, value):
            self.value = value
            self.raw = json.dumps(value).encode("utf-8")
            self.content_length = len(self.raw)

        async def read(self):
            return self.raw

        async def json(self):
            return self.value

    async def downstream(_request):
        routed.append(True)
        raise AssertionError("downstream must not run")

    response = asyncio.run(
        submission._prompt_submission_middleware(Request(body), downstream)
    )
    assert response.status == 400
    assert response.body == b""
    assert response.headers["Cache-Control"] == "no-store"
    assert routed == []
