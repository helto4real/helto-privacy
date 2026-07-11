"""Session-bound protected execution references, grants, and RAM caches."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import inspect
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Any

from ._plaintext import clear_mutable_plaintext
from . import keystore
from .envelope import PrivacyEnvelopeCodec, PrivacyError
from .guard import AuthorizedPrivacyRequest, require_current_authorization
from .profile import PrivacyProfile, SemanticExecutionProjection


EXECUTION_REFERENCE_SCHEMA = "helto.private-execution-reference"
EXECUTION_REFERENCE_VERSION = 1
EXECUTION_IDENTITY_PREFIX = "hp-exec-v1:"
_IDENTITY_DOMAIN = b"helto.private-execution.identity.v1\x00"


class ExecutionError(RuntimeError):
    """Sanitized execution failure safe for routes and consumer integrations."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Private execution could not complete.")


@dataclass(frozen=True, slots=True)
class PreparedExecution:
    """Opaque protected queue input that can be dispatched once."""

    reference: dict[str, Any] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Product result plus its opaque dispatch-time semantic identity."""

    value: object = field(repr=False)
    cache_identity: str


class _GrantStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"


@dataclass(frozen=True, slots=True)
class _CacheKey:
    session_fingerprint: bytes = field(repr=False)
    pack_id: str
    execution_resource_id: str
    cache_identity: str


@dataclass(slots=True)
class _Grant:
    pack_id: str
    execution_resource_id: str
    projection_id: str
    session_fingerprint: bytes = field(repr=False)
    reference_digest: bytes = field(repr=False)
    status: _GrantStatus = _GrantStatus.PENDING
    cancel_requested: bool = False


class ExecutionCancellation:
    """Cooperative cancellation checkpoint scoped to one active grant."""

    __slots__ = ("_grant_id",)

    def __init__(self, grant_id: str) -> None:
        self._grant_id = grant_id

    @property
    def is_cancelled(self) -> bool:
        with _LOCK:
            grant = _GRANTS.get(self._grant_id)
            return grant is None or grant.cancel_requested

    def checkpoint(self) -> None:
        if self.is_cancelled:
            raise ExecutionError("PRIVACY_EXECUTION_CANCELLED")

    def __repr__(self) -> str:
        return "ExecutionCancellation()"


_LOCK = RLock()
_GRANTS: dict[str, _Grant] = {}
_CACHE_MISS = object()
_CACHE: dict[_CacheKey, object] = {}
_ISSUED_IDENTITIES: set[_CacheKey] = set()


def prepare_execution(
    *,
    installation,
    profile: PrivacyProfile,
    execution_resource_id: str,
    projection_id: str,
    protected_fields: Mapping[str, object],
    authorization: AuthorizedPrivacyRequest,
) -> PreparedExecution:
    """Validate one protected snapshot and issue a single-use session grant."""

    require_current_authorization(
        authorization,
        "execution.prepare",
        pack_id=profile.id,
    )
    projection = _projection(profile, execution_resource_id, projection_id)
    fields = _execution_fields(profile, projection)
    _require_stable_scopes(installation, fields)
    supplied = _protected_field_mapping(protected_fields)
    if set(supplied) != {item.id for item in fields}:
        raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_MISMATCH")

    protected = {
        declaration.id: _validated_protected_value(
            declaration.current_schema,
            supplied[declaration.id],
        )
        for declaration in fields
    }
    session = _session_fingerprint()

    grant_id = secrets.token_urlsafe(24)
    reference = {
        "schema": EXECUTION_REFERENCE_SCHEMA,
        "version": EXECUTION_REFERENCE_VERSION,
        "packId": profile.id,
        "executionResourceId": execution_resource_id,
        "projectionId": projection.id,
        "workflowResourceId": projection.workflow_resource_id,
        "grant": grant_id,
        "fields": [
            {
                "fieldId": declaration.id,
                "protectedValue": protected[declaration.id],
            }
            for declaration in fields
        ],
    }
    grant = _Grant(
        pack_id=profile.id,
        execution_resource_id=execution_resource_id,
        projection_id=projection.id,
        session_fingerprint=session,
        reference_digest=_reference_digest(reference),
    )
    with _LOCK:
        if not hmac.compare_digest(session, _session_fingerprint()):
            raise ExecutionError("PRIVACY_EXECUTION_GRANT_INVALID")
        _GRANTS[grant_id] = grant
    return PreparedExecution(_isolated_copy(reference))


def dispatch_execution(
    *,
    installation,
    profile: PrivacyProfile,
    adapters: Mapping[str, object],
    execution_resource_id: str,
    reference: object,
    context: object,
):
    """Consume one grant and invoke product logic with short-lived plaintext."""

    parsed = _validated_reference(reference, profile.id, execution_resource_id)
    grant_id = parsed["grant"]
    current_session, identity_key = _execution_session_material()
    with _LOCK:
        grant = _GRANTS.get(grant_id)
        if (
            grant is None
            or grant.status is not _GrantStatus.PENDING
            or grant.pack_id != profile.id
            or grant.execution_resource_id != execution_resource_id
            or not hmac.compare_digest(grant.session_fingerprint, current_session)
        ):
            raise ExecutionError("PRIVACY_EXECUTION_GRANT_INVALID")
        if not hmac.compare_digest(
            grant.reference_digest,
            _reference_digest(parsed),
        ):
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_MISMATCH")
        if grant.projection_id != parsed["projectionId"]:
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_MISMATCH")
        grant.status = _GrantStatus.ACTIVE

    values: dict[str, object] = {}
    semantic: object = None
    async_result = False
    try:
        projection = _projection(
            profile,
            execution_resource_id,
            parsed["projectionId"],
        )
        if parsed["workflowResourceId"] != projection.workflow_resource_id:
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_MISMATCH")
        fields = _execution_fields(profile, projection)
        _require_stable_scopes(installation, fields)
        supplied = {
            item["fieldId"]: item["protectedValue"] for item in parsed["fields"]
        }
        if set(supplied) != {item.id for item in fields}:
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_MISMATCH")
        for declaration in fields:
            values[declaration.id] = _decrypt_field(
                declaration.current_schema,
                supplied[declaration.id],
            )
        semantic = _project(adapters, projection, values)
        identity = _semantic_identity(
            profile.id,
            projection,
            semantic,
            session=current_session,
            key=identity_key,
        )
        cancellation = ExecutionCancellation(grant_id)
        cancellation.checkpoint()
        _issue_cache_identity(grant_id, current_session, identity)
        cached = _load_cache_value(
            current_session,
            profile.id,
            execution_resource_id,
            identity,
        )
        if cached is not _CACHE_MISS:
            _complete_dispatch(grant_id)
            return ExecutionResult(cached, identity)
        dispatcher = adapters.get(projection.dispatch_adapter)
        dispatch = getattr(dispatcher, "dispatch", None)
        if not callable(dispatch):
            raise ExecutionError("PRIVACY_EXECUTION_ADAPTER_INVALID")
        result = dispatch(semantic, context, cancellation)
        if inspect.isawaitable(result):
            async_result = True
            return _await_dispatch(
                result,
                grant_id,
                semantic,
                values,
                cancellation,
                identity,
            )
        _complete_dispatch(grant_id)
        return ExecutionResult(result, identity)
    except ExecutionError:
        raise
    except Exception:
        raise ExecutionError("PRIVACY_EXECUTION_DISPATCH_FAILED") from None
    finally:
        if not async_result:
            _finish_dispatch(grant_id, semantic, values)


async def _await_dispatch(
    awaitable,
    grant_id: str,
    semantic: object,
    values: dict[str, object],
    cancellation: ExecutionCancellation,
    cache_identity: str,
):
    try:
        result = await awaitable
        _complete_dispatch(grant_id)
        return ExecutionResult(result, cache_identity)
    except ExecutionError:
        raise
    except Exception:
        raise ExecutionError("PRIVACY_EXECUTION_DISPATCH_FAILED") from None
    finally:
        _finish_dispatch(grant_id, semantic, values)


def _finish_dispatch(
    grant_id: str,
    semantic: object,
    values: dict[str, object],
) -> None:
    clear_mutable_plaintext(semantic)
    clear_mutable_plaintext(values)
    with _LOCK:
        _GRANTS.pop(grant_id, None)


def _complete_dispatch(grant_id: str) -> None:
    """Linearize successful completion before a later lock can cancel it."""

    with _LOCK:
        grant = _GRANTS.get(grant_id)
        if (
            grant is None
            or grant.status is not _GrantStatus.ACTIVE
            or grant.cancel_requested
        ):
            raise ExecutionError("PRIVACY_EXECUTION_CANCELLED")
        _GRANTS.pop(grant_id, None)


def _issue_cache_identity(
    grant_id: str,
    session: bytes,
    cache_identity: str,
) -> None:
    with _LOCK:
        grant = _GRANTS.get(grant_id)
        if (
            grant is None
            or grant.status is not _GrantStatus.ACTIVE
            or grant.cancel_requested
            or not hmac.compare_digest(grant.session_fingerprint, session)
        ):
            raise ExecutionError("PRIVACY_EXECUTION_CANCELLED")
        _ISSUED_IDENTITIES.add(
            _CacheKey(
                session,
                grant.pack_id,
                grant.execution_resource_id,
                cache_identity,
            )
        )


def _load_cache_value(
    session: bytes,
    pack_id: str,
    execution_resource_id: str,
    cache_identity: str,
) -> object:
    key = _cache_key(
        session,
        pack_id,
        execution_resource_id,
        cache_identity,
    )
    with _LOCK:
        value = _CACHE.get(key, _CACHE_MISS)
        return (
            _isolated_copy(value, "PRIVACY_EXECUTION_CACHE_FAILED")
            if value is not _CACHE_MISS
            else _CACHE_MISS
        )


def cache_execution_result(
    *,
    pack_id: str,
    execution_resource_id: str,
    cache_identity: str,
    value: object,
) -> None:
    """Store one private result only in unlocked-session process memory."""

    session = _session_fingerprint()
    key = _cache_key(
        session,
        pack_id,
        execution_resource_id,
        cache_identity,
    )
    copied = _isolated_copy(value, "PRIVACY_EXECUTION_CACHE_FAILED")
    with _LOCK:
        if key not in _ISSUED_IDENTITIES:
            raise ExecutionError("PRIVACY_EXECUTION_IDENTITY_INVALID")
        _CACHE[key] = copied


def load_cached_execution_result(
    *,
    pack_id: str,
    execution_resource_id: str,
    cache_identity: str,
) -> object | None:
    """Return an isolated copy from the current unlocked-session RAM cache."""

    session = _session_fingerprint()
    key = _cache_key(
        session,
        pack_id,
        execution_resource_id,
        cache_identity,
    )
    with _LOCK:
        value = _CACHE.get(key, _CACHE_MISS)
        return (
            _isolated_copy(value, "PRIVACY_EXECUTION_CACHE_FAILED")
            if value is not _CACHE_MISS
            else None
        )


def invalidate_execution_session(_reason: str = "session-change") -> None:
    """Revoke pending work, request active cancellation, and clear RAM caches."""

    with _LOCK:
        for grant_id, grant in tuple(_GRANTS.items()):
            if grant.status is _GrantStatus.ACTIVE:
                grant.cancel_requested = True
            else:
                _GRANTS.pop(grant_id, None)
        _CACHE.clear()
        _ISSUED_IDENTITIES.clear()


def invalidate_execution_profile(pack_id: str) -> None:
    """Invalidate all execution state owned by one conflicting profile."""

    with _LOCK:
        for grant_id, grant in tuple(_GRANTS.items()):
            if grant.pack_id != pack_id:
                continue
            if grant.status is _GrantStatus.ACTIVE:
                grant.cancel_requested = True
            else:
                _GRANTS.pop(grant_id, None)
        for key in tuple(_CACHE):
            if key.pack_id == pack_id:
                _CACHE.pop(key, None)
        for key in tuple(_ISSUED_IDENTITIES):
            if key.pack_id == pack_id:
                _ISSUED_IDENTITIES.discard(key)


def _projection(
    profile: PrivacyProfile,
    execution_resource_id: str,
    projection_id: str,
) -> SemanticExecutionProjection:
    projection = next(
        (
            item
            for item in profile.execution_projections
            if item.id == projection_id
            and item.execution_resource_id == execution_resource_id
        ),
        None,
    )
    if projection is None:
        raise ExecutionError("PRIVACY_EXECUTION_PROJECTION_INVALID")
    return projection


def _execution_fields(
    profile: PrivacyProfile,
    projection: SemanticExecutionProjection,
):
    fields = tuple(
        sorted(
            (
                item
                for item in profile.protected_fields
                if item.workflow_resource_id == projection.workflow_resource_id
                and item.execution
            ),
            key=lambda item: item.id,
        )
    )
    if not fields:
        raise ExecutionError("PRIVACY_EXECUTION_FIELD_INVALID")
    return fields


def _require_stable_scopes(installation, fields) -> None:
    from .mode import ModePolicyError, ModeTransitionError
    from .mode_runtime import require_stable_bound_scope

    try:
        for scope_id in sorted({field.scope_id for field in fields}):
            require_stable_bound_scope(installation, scope_id)
    except (ModePolicyError, ModeTransitionError):
        raise ExecutionError("PRIVACY_EXECUTION_MODE_BLOCKED") from None


def _protected_field_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
    result: dict[str, object] = {}
    for field_id, protected_value in value.items():
        if not isinstance(field_id, str) or not field_id:
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
        result[field_id] = protected_value
    return result


def _validated_protected_value(schema: str, protected_value: object) -> object:
    _protected_payload(schema, protected_value)
    return _isolated_copy(protected_value)


def _protected_payload(
    schema: str,
    protected_value: object,
) -> tuple[PrivacyEnvelopeCodec, object]:
    payload = protected_value
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID") from None
    codec = PrivacyEnvelopeCodec(schema)
    if not codec.is_encrypted_payload(payload):
        raise ExecutionError("PRIVACY_EXECUTION_UNSUPPORTED")
    return codec, payload


def _decrypt_field(schema: str, protected_value: object) -> dict[str, Any]:
    codec, payload = _protected_payload(schema, protected_value)
    try:
        return codec.decrypt_state(payload)
    except PrivacyError as exc:
        if "PRIVACY_LOCKED" in str(exc):
            raise ExecutionError("PRIVACY_EXECUTION_LOCKED") from None
        raise ExecutionError("PRIVACY_EXECUTION_DECRYPT_FAILED") from None


def _project(
    adapters: Mapping[str, object],
    projection: SemanticExecutionProjection,
    fields: Mapping[str, object],
) -> object:
    adapter = adapters.get(projection.projection_adapter)
    project = getattr(adapter, "project", None)
    if not callable(project):
        raise ExecutionError("PRIVACY_EXECUTION_ADAPTER_INVALID")
    try:
        value = project(fields, projection)
        _canonical_bytes(value)
        return value
    except ExecutionError:
        raise
    except Exception:
        raise ExecutionError("PRIVACY_EXECUTION_PROJECTION_FAILED") from None


def _semantic_identity(
    pack_id: str,
    projection: SemanticExecutionProjection,
    semantic: object,
    *,
    session: bytes,
    key: bytes,
) -> str:
    message = b"\x00".join(
        (
            _IDENTITY_DOMAIN,
            pack_id.encode("utf-8"),
            projection.execution_resource_id.encode("utf-8"),
            projection.id.encode("utf-8"),
            session,
            _canonical_bytes(semantic),
        )
    )
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return EXECUTION_IDENTITY_PREFIX + base64.urlsafe_b64encode(digest).decode(
        "ascii"
    ).rstrip("=")


def _validated_reference(
    value: object,
    pack_id: str,
    execution_resource_id: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
    reference = _isolated_copy(dict(value))
    if (
        reference.get("schema") != EXECUTION_REFERENCE_SCHEMA
        or reference.get("version") != EXECUTION_REFERENCE_VERSION
        or reference.get("packId") != pack_id
        or reference.get("executionResourceId") != execution_resource_id
        or not isinstance(reference.get("projectionId"), str)
        or not isinstance(reference.get("workflowResourceId"), str)
        or not isinstance(reference.get("grant"), str)
        or not isinstance(reference.get("fields"), list)
    ):
        raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
    for item in reference["fields"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("fieldId"), str)
            or "protectedValue" not in item
        ):
            raise ExecutionError("PRIVACY_EXECUTION_REFERENCE_INVALID")
    return reference


def _reference_digest(reference: object) -> bytes:
    return hashlib.sha256(_canonical_bytes(reference)).digest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ExecutionError("PRIVACY_EXECUTION_PROJECTION_INVALID") from None


def _cache_identity(value: object) -> str:
    identity = str(value or "")
    encoded = identity.removeprefix(EXECUTION_IDENTITY_PREFIX)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if (
        not identity.startswith(EXECUTION_IDENTITY_PREFIX)
        or len(encoded) != 43
        or any(character not in alphabet for character in encoded)
    ):
        raise ExecutionError("PRIVACY_EXECUTION_IDENTITY_INVALID")
    return identity


def _cache_key(
    session: bytes,
    pack_id: str,
    execution_resource_id: str,
    cache_identity: str,
) -> _CacheKey:
    return _CacheKey(
        session,
        pack_id,
        execution_resource_id,
        _cache_identity(cache_identity),
    )


def _isolated_copy(
    value: object,
    error_code: str = "PRIVACY_EXECUTION_REFERENCE_INVALID",
):
    try:
        return copy.deepcopy(value)
    except Exception:
        raise ExecutionError(error_code) from None


def _session_fingerprint() -> bytes:
    token = keystore.session_token()
    if not token:
        raise ExecutionError("PRIVACY_EXECUTION_LOCKED")
    return hashlib.sha256(token.encode("utf-8")).digest()


def _execution_session_material() -> tuple[bytes, bytes]:
    token = keystore.session_token()
    if not token:
        raise ExecutionError("PRIVACY_EXECUTION_LOCKED")
    try:
        key, _key_id = keystore.primary_session_key()
    except keystore.PrivacyKeystoreError:
        raise ExecutionError("PRIVACY_EXECUTION_LOCKED") from None
    confirmation = keystore.session_token()
    if not confirmation or not hmac.compare_digest(token, confirmation):
        raise ExecutionError("PRIVACY_EXECUTION_GRANT_INVALID")
    return hashlib.sha256(token.encode("utf-8")).digest(), key
