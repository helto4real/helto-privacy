"""Pre-route fail-closed validation for ComfyUI prompt submissions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from urllib.parse import urlsplit
from weakref import WeakKeyDictionary

from .execution import (
    EXECUTION_REFERENCE_SCHEMA,
    validate_pending_execution_reference,
)
from .migration import probe_registered_legacy_value
from .subject_mode import (
    SUBJECT_MODE_REFERENCE_SCHEMA,
    validate_pending_subject_mode_reference,
)


_PROMPT_PATHS = frozenset({"/prompt", "/api/prompt"})
_MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_ITEMS = 100_000
_MAX_DEPTH = 32
_MAX_REFERENCE_TEXT_BYTES = 1024 * 1024
_MIDDLEWARE_MARKER = "__helto_privacy_prompt_submission_middleware__"
_INSTALL_LOCK = RLock()
_INSTALLED: WeakKeyDictionary[object, object] = WeakKeyDictionary()


class PromptSubmissionMiddlewareError(RuntimeError):
    """Sanitized startup failure for an unavailable exact middleware hook."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Helto privacy prompt validation could not be installed safely.")


class _SubmissionRejected(ValueError):
    pass


class _FrozenDict(dict):
    def _blocked(self, *_args, **_kwargs):
        raise TypeError("immutable structural probe value")

    __setitem__ = _blocked
    __delitem__ = _blocked
    clear = _blocked
    pop = _blocked
    popitem = _blocked
    setdefault = _blocked
    update = _blocked
    __ior__ = _blocked


class _FrozenList(list):
    def _blocked(self, *_args, **_kwargs):
        raise TypeError("immutable structural probe value")

    __setitem__ = _blocked
    __delitem__ = _blocked
    append = _blocked
    clear = _blocked
    extend = _blocked
    insert = _blocked
    pop = _blocked
    remove = _blocked
    reverse = _blocked
    sort = _blocked
    __iadd__ = _blocked
    __imul__ = _blocked


@dataclass(frozen=True, slots=True)
class _ProfileView:
    profile: object
    ready: bool


@dataclass(frozen=True, slots=True)
class _LocatedReference:
    node_id: str
    input_name: str
    reference: dict[str, object]
    exact_input: bool


async def _prompt_submission_middleware(request, handler):
    if request.method != "POST" or request.path not in _PROMPT_PATHS:
        return await handler(request)

    try:
        if request.content_type != "application/json" or not _same_origin(request):
            raise _SubmissionRejected()
        declared_length = request.content_length
        if declared_length is not None and declared_length > _MAX_BODY_BYTES:
            raise _SubmissionRejected()
        raw = await request.read()
        if len(raw) > _MAX_BODY_BYTES:
            raise _SubmissionRejected()
        body = await request.json()
        if validate_prompt_submission(body) is not True:
            raise _SubmissionRejected()
    except Exception:  # noqa: BLE001 - every pre-route failure is the same empty 400.
        from aiohttp import web

        return web.Response(
            status=400,
            body=b"",
            headers={"Cache-Control": "no-store"},
        )

    # Downstream failures intentionally retain ComfyUI's normal behavior.
    return await handler(request)


setattr(_prompt_submission_middleware, "__middleware_version__", 1)
setattr(_prompt_submission_middleware, _MIDDLEWARE_MARKER, True)


def install_prompt_submission_middleware(prompt_server=None) -> bool:
    """Insert the exact validator once, before every existing app middleware."""

    if prompt_server is None:
        try:
            import server

            prompt_server = getattr(server.PromptServer, "instance", None)
        except Exception:
            raise PromptSubmissionMiddlewareError("prompt_server_missing") from None
    try:
        app = getattr(prompt_server, "app", None)
    except Exception:
        raise PromptSubmissionMiddlewareError("prompt_server_invalid") from None
    if app is None:
        raise PromptSubmissionMiddlewareError("prompt_server_missing")
    try:
        frozen = bool(getattr(app, "pre_frozen", False)) or bool(
            getattr(app, "frozen", False)
        )
    except Exception:
        raise PromptSubmissionMiddlewareError("prompt_server_invalid") from None
    if frozen:
        raise PromptSubmissionMiddlewareError("prompt_server_frozen")

    try:
        middlewares = app.middlewares
        middleware_snapshot = tuple(middlewares)
        known = _INSTALLED.get(app)
    except Exception:
        raise PromptSubmissionMiddlewareError("prompt_server_invalid") from None

    with _INSTALL_LOCK:
        marked = tuple(
            middleware
            for middleware in middleware_snapshot
            if bool(getattr(middleware, _MIDDLEWARE_MARKER, False))
        )
        if known is not None and known is not _prompt_submission_middleware:
            raise PromptSubmissionMiddlewareError("prompt_middleware_conflict")
        if any(item is not _prompt_submission_middleware for item in marked):
            raise PromptSubmissionMiddlewareError("prompt_middleware_conflict")
        occurrences = sum(
            item is _prompt_submission_middleware for item in middlewares
        )
        if occurrences:
            if occurrences != 1 or middlewares[0] is not _prompt_submission_middleware:
                raise PromptSubmissionMiddlewareError("prompt_middleware_conflict")
            try:
                _INSTALLED[app] = _prompt_submission_middleware
            except Exception:
                raise PromptSubmissionMiddlewareError("prompt_server_invalid") from None
            return False
        if known is not None or marked:
            raise PromptSubmissionMiddlewareError("prompt_middleware_conflict")
        try:
            middlewares.insert(0, _prompt_submission_middleware)
        except Exception:
            raise PromptSubmissionMiddlewareError("prompt_middleware_install_failed") from None
        if middlewares[0] is not _prompt_submission_middleware:
            raise PromptSubmissionMiddlewareError("prompt_middleware_install_failed")
        try:
            _INSTALLED[app] = _prompt_submission_middleware
        except Exception:
            raise PromptSubmissionMiddlewareError("prompt_server_invalid") from None
        return True


def validate_prompt_submission(body: object) -> bool:
    """Validate a parsed incoming prompt body without mutating or consuming it."""

    if not isinstance(body, Mapping):
        raise _SubmissionRejected()
    prompt = body.get("prompt")
    if not isinstance(prompt, Mapping):
        raise _SubmissionRejected()

    profile_views = _profile_views()
    helto_types = {
        node_type
        for view in profile_views
        for node_type in _profile_node_types(view.profile)
    }
    output_nodes = _output_nodes(prompt)
    references = _submission_references(output_nodes)

    workflow = _workflow_from_body(body)
    output_helto = tuple(
        (node_id, node_type, inputs)
        for node_id, node_type, inputs in output_nodes
        if node_type in helto_types
    )
    workflow_privacy_hint = _workflow_contains_node_type(workflow, helto_types)
    privacy_bearing = bool(output_helto or references or workflow_privacy_hint)
    if not privacy_bearing:
        return True
    if workflow is None:
        raise _SubmissionRejected()
    workflow_nodes = _workflow_nodes(workflow)
    workflow_helto = tuple(
        item for item in workflow_nodes if item[1] in helto_types
    )

    relevant = tuple(
        view
        for view in profile_views
        if _profile_node_types(view.profile) & {
            *(node_type for _, node_type, _ in output_helto),
            *(node_type for _, node_type in workflow_helto),
        }
    )
    if not relevant or any(not view.ready for view in relevant):
        raise _SubmissionRejected()
    from .suite_runtime import require_active_process_suite

    require_active_process_suite()

    reader_ids = tuple(
        sorted(
            {
                reader_id
                for view in relevant
                for field in view.profile.protected_fields
                for reader_id in field.legacy_reader_ids
            }
        )
    )
    if reader_ids:
        probe_workflow = _frozen_json_copy(workflow)
        for value in _bounded_values(probe_workflow):
            if probe_registered_legacy_value(value, reader_ids):
                raise _SubmissionRejected()

    workflow_by_id: dict[str, list[str]] = {}
    for node_id, node_type in workflow_nodes:
        workflow_by_id.setdefault(node_id, []).append(node_type)
    for node_id, node_type, _inputs in output_helto:
        declared = workflow_by_id.get(node_id, [])
        if declared != [node_type]:
            raise _SubmissionRejected()
    for node_id, node_type in workflow_helto:
        output = [item[1] for item in output_nodes if item[0] == node_id]
        if output and output != [node_type]:
            raise _SubmissionRejected()

    expected_paths: set[tuple[str, str]] = set()
    seen_grants: set[tuple[object, object]] = set()
    located_by_path: dict[tuple[str, str], list[_LocatedReference]] = {}
    for located in references:
        identity = (located.reference.get("schema"), located.reference.get("grant"))
        if identity in seen_grants:
            raise _SubmissionRejected()
        seen_grants.add(identity)
        located_by_path.setdefault((located.node_id, located.input_name), []).append(
            located
        )

    for node_id, node_type, inputs in output_helto:
        matching = tuple(
            view for view in relevant if node_type in _profile_node_types(view.profile)
        )
        binding_modes: dict[tuple[str, str], bool] = {}
        execution_bindings: list[tuple[object, object]] = []
        for view in matching:
            profile = view.profile
            bindings_by_id = {
                binding.id: binding for binding in profile.subject_mode_bindings
            }
            for binding in profile.subject_mode_bindings:
                if node_type not in binding.node_types:
                    continue
                path = (node_id, binding.input_name)
                if path in expected_paths:
                    raise _SubmissionRejected()
                expected_paths.add(path)
                reference = _exact_reference_input(
                    inputs,
                    binding.input_name,
                    path,
                    located_by_path,
                )
                result = validate_pending_subject_mode_reference(
                    reference,
                    profile=profile,
                    binding=binding,
                    subject_id=node_id,
                )
                if not result.valid:
                    raise _SubmissionRejected()
                binding_modes[(profile.id, binding.id)] = (
                    result.requires_private_execution
                )

            for projection in profile.execution_projections:
                binding = bindings_by_id.get(projection.subject_mode_binding_id)
                if binding is None:
                    raise _SubmissionRejected()
                if node_type in binding.node_types:
                    execution_bindings.append((profile, projection))

        for profile, projection in execution_bindings:
            path = (node_id, projection.input_name)
            if path in expected_paths:
                raise _SubmissionRejected()
            expected_paths.add(path)
            present = projection.input_name in inputs
            private_required = binding_modes.get(
                (profile.id, projection.subject_mode_binding_id)
            )
            if private_required is None:
                raise _SubmissionRejected()
            if private_required and not present:
                raise _SubmissionRejected()
            if not private_required and present:
                raise _SubmissionRejected()
            if not present:
                continue
            reference = _exact_reference_input(
                inputs,
                projection.input_name,
                path,
                located_by_path,
            )
            if not validate_pending_execution_reference(
                reference,
                pack_id=profile.id,
                execution_resource_id=projection.execution_resource_id,
                projection_id=projection.id,
                workflow_resource_id=projection.workflow_resource_id,
                subject_id=node_id,
            ):
                raise _SubmissionRejected()

    if any(path not in expected_paths for path in located_by_path):
        raise _SubmissionRejected()
    return True


def _profile_views() -> tuple[_ProfileView, ...]:
    from .runtime import submission_profile_snapshot

    return tuple(
        _ProfileView(profile, ready)
        for profile, ready in submission_profile_snapshot()
    )


def _profile_node_types(profile: object) -> set[str]:
    return {
        node_type
        for slot in (*profile.server_adapters, *profile.browser_adapters)
        for node_type in slot.node_types
    } | {
        node_type
        for field in profile.protected_fields
        for node_type in field.node_types
    } | {
        node_type
        for binding in profile.subject_mode_bindings
        for node_type in binding.node_types
    }


def _workflow_from_body(body: Mapping[object, object]) -> Mapping | None:
    extra = body.get("extra_data")
    if not isinstance(extra, Mapping):
        return None
    png_info = extra.get("extra_pnginfo")
    if not isinstance(png_info, Mapping):
        return None
    workflow = png_info.get("workflow")
    return workflow if isinstance(workflow, Mapping) else None


def _output_nodes(prompt: Mapping) -> tuple[tuple[str, str, Mapping], ...]:
    if len(prompt) > _MAX_ITEMS:
        raise _SubmissionRejected()
    result = []
    for raw_id, value in prompt.items():
        node_id = str(raw_id)
        if not node_id or not isinstance(value, Mapping):
            raise _SubmissionRejected()
        node_type = value.get("class_type")
        inputs = value.get("inputs", {})
        if not isinstance(node_type, str) or not node_type or not isinstance(inputs, Mapping):
            raise _SubmissionRejected()
        result.append((node_id, node_type, inputs))
    return tuple(result)


def _workflow_nodes(workflow: Mapping | None) -> tuple[tuple[str, str], ...]:
    if workflow is None:
        return ()
    tuple(_bounded_values(workflow))
    result: list[tuple[str, str]] = []
    stack = [workflow]
    seen: set[int] = set()
    while stack:
        graph = stack.pop()
        identity = id(graph)
        if identity in seen:
            raise _SubmissionRejected()
        seen.add(identity)
        nodes = graph.get("nodes")
        if not isinstance(nodes, list):
            raise _SubmissionRejected()
        for node in nodes:
            if not isinstance(node, Mapping):
                raise _SubmissionRejected()
            node_id = str(node.get("id", ""))
            node_type = node.get("type")
            if not node_id or not isinstance(node_type, str) or not node_type:
                raise _SubmissionRejected()
            result.append((node_id, node_type))
        definitions = graph.get("definitions")
        if definitions is not None:
            if not isinstance(definitions, Mapping):
                raise _SubmissionRejected()
            nested = definitions.get("subgraphs", [])
            if not isinstance(nested, list):
                raise _SubmissionRejected()
            stack.extend(_mapping_items(nested))
        nested = graph.get("subgraphs", [])
        if not isinstance(nested, list):
            raise _SubmissionRejected()
        stack.extend(_mapping_items(nested))
    return tuple(result)


def _workflow_contains_node_type(
    workflow: Mapping | None,
    node_types: set[str],
) -> bool:
    """Recognize privacy-bearing workflow metadata before strict graph parsing."""

    if workflow is None or not node_types:
        return False
    return any(
        isinstance(value, Mapping) and value.get("type") in node_types
        for value in _bounded_values(workflow)
    )


def _mapping_items(values: list[object]) -> list[Mapping]:
    if any(not isinstance(item, Mapping) for item in values):
        raise _SubmissionRejected()
    return list(values)


def _frozen_json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return _FrozenDict(
            (key, _frozen_json_copy(item)) for key, item in value.items()
        )
    if isinstance(value, list):
        return _FrozenList(_frozen_json_copy(item) for item in value)
    return value


def _bounded_values(root: object):
    stack = [(root, 0)]
    seen: set[int] = set()
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > _MAX_ITEMS or depth > _MAX_DEPTH:
            raise _SubmissionRejected()
        children = ()
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in seen:
                raise _SubmissionRejected()
            seen.add(identity)
            children = tuple((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            identity = id(value)
            if identity in seen:
                raise _SubmissionRejected()
            seen.add(identity)
            children = tuple((item, depth + 1) for item in value)
        yield value
        stack.extend(children)


def _submission_references(
    nodes: tuple[tuple[str, str, Mapping], ...],
) -> tuple[_LocatedReference, ...]:
    located: list[_LocatedReference] = []
    count = 0
    for node_id, _node_type, inputs in nodes:
        for raw_name, value in inputs.items():
            if not isinstance(raw_name, str) or not raw_name:
                raise _SubmissionRejected()
            stack = [(value, True, 0)]
            seen: set[int] = set()
            while stack:
                candidate, exact_input, depth = stack.pop()
                count += 1
                if count > _MAX_ITEMS or depth > _MAX_DEPTH:
                    raise _SubmissionRejected()
                parsed = _reference_candidate(candidate)
                if parsed is not None:
                    located.append(
                        _LocatedReference(node_id, raw_name, parsed, exact_input)
                    )
                    candidate = parsed
                if isinstance(candidate, Mapping):
                    identity = id(candidate)
                    if identity in seen:
                        raise _SubmissionRejected()
                    seen.add(identity)
                    stack.extend((item, False, depth + 1) for item in candidate.values())
                elif isinstance(candidate, list):
                    identity = id(candidate)
                    if identity in seen:
                        raise _SubmissionRejected()
                    seen.add(identity)
                    stack.extend((item, False, depth + 1) for item in candidate)
    return tuple(located)


def _reference_candidate(value: object) -> dict[str, object] | None:
    candidate = value
    if isinstance(value, str) and value.lstrip().startswith("{"):
        if len(value.encode("utf-8")) > _MAX_REFERENCE_TEXT_BYTES:
            raise _SubmissionRejected()
        try:
            candidate = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(candidate, Mapping):
        return None
    schema = candidate.get("schema")
    if schema not in {EXECUTION_REFERENCE_SCHEMA, SUBJECT_MODE_REFERENCE_SCHEMA}:
        return None
    return dict(candidate)


def _exact_reference_input(
    inputs: Mapping,
    input_name: str,
    path: tuple[str, str],
    located_by_path: Mapping[tuple[str, str], list[_LocatedReference]],
) -> dict[str, object]:
    if input_name not in inputs:
        raise _SubmissionRejected()
    located = located_by_path.get(path, [])
    if len(located) != 1 or not located[0].exact_input:
        raise _SubmissionRejected()
    parsed = _reference_candidate(inputs[input_name])
    if parsed is None or parsed != located[0].reference:
        raise _SubmissionRejected()
    return parsed


def _same_origin(request: object) -> bool:
    origin = str(getattr(request, "headers", {}).get("Origin") or "").strip()
    if not origin:
        return True
    supplied = _origin_identity(origin)
    effective = _origin_identity(
        f"{str(getattr(request, 'scheme', '') or '').lower()}://"
        f"{str(getattr(request, 'host', '') or '').lower()}"
    )
    return supplied is not None and supplied == effective


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
        return (
            parsed.scheme,
            parsed.hostname.lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    except (TypeError, ValueError):
        return None
