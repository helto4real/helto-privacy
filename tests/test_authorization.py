import asyncio

import pytest

import helto_privacy.keystore as keystore
from helto_privacy.guard import (
    AuthorizedPrivacyRequest,
    PrivacyAuthorizationError,
    PrivacyRouteDispatchError,
    authorize_privacy_request,
    dispatch_privacy_route,
    require_declassification_confirmation,
    require_current_authorization,
)


PASSWORD = "synthetic password"


class Request:
    def __init__(self, *, header=None, cookie=None, confirm_declassification=False):
        self.headers = {}
        self.cookies = {}
        if header is not None:
            self.headers["X-Helto-Privacy-Token"] = header
        if cookie is not None:
            self.cookies["helto_privacy_token"] = cookie
        if confirm_declassification:
            self.headers["X-Helto-Privacy-Declassification"] = "confirmed"


def test_authorization_is_typed_and_keystore_absence_never_authorizes():
    with pytest.raises(PrivacyAuthorizationError) as missing:
        authorize_privacy_request(Request(), "record.use")

    assert missing.value.code == "PRIVACY_KEYSTORE_UNINITIALIZED"
    assert missing.value.http_status == 409
    assert "record.use" not in str(missing.value)


def test_authorization_requires_current_header_or_cookie_token():
    token = keystore.initialize_keystore(PASSWORD)["token"]

    with pytest.raises(PrivacyAuthorizationError) as absent:
        authorize_privacy_request(Request(), "record.use")
    with pytest.raises(PrivacyAuthorizationError) as wrong:
        authorize_privacy_request(Request(header="wrong"), "record.use")

    assert absent.value.code == "PRIVACY_TOKEN_REQUIRED"
    assert wrong.value.code == "PRIVACY_TOKEN_REQUIRED"
    header = authorize_privacy_request(Request(header=token), "record.use")
    cookie = authorize_privacy_request(Request(cookie=token), "record.use")
    assert isinstance(header, AuthorizedPrivacyRequest)
    assert cookie.operation_id == "record.use"
    assert "token" not in repr(header).lower()
    assert not hasattr(header, "token")


def test_locked_keystore_has_one_sanitized_failure():
    token = keystore.initialize_keystore(PASSWORD)["token"]
    keystore.lock_keystore()

    with pytest.raises(PrivacyAuthorizationError) as locked:
        authorize_privacy_request(Request(header=token), "record.use")

    assert locked.value.code == "PRIVACY_LOCKED"
    assert locked.value.http_status == 401


def test_uninitialized_capability_object_is_rejected_with_a_typed_failure():
    forged = object.__new__(AuthorizedPrivacyRequest)

    with pytest.raises(PrivacyAuthorizationError) as invalid:
        require_current_authorization(forged, "record.use")

    assert invalid.value.code == "PRIVACY_AUTHORIZATION_INVALID"


def test_declassification_confirmation_is_scope_target_bound_and_one_use():
    token = keystore.initialize_keystore(PASSWORD)["token"]
    authorization = authorize_privacy_request(
        Request(header=token, confirm_declassification=True),
        "mode.transition",
        pack_id="helto.test",
        declassification_scope_id="main",
        declassification_target="public",
    )

    with pytest.raises(PrivacyAuthorizationError) as wrong_scope:
        require_declassification_confirmation(
            authorization,
            scope_id="other",
            target="public",
        )
    assert wrong_scope.value.code == "PRIVACY_DECLASSIFICATION_CONFIRMATION_REQUIRED"

    require_declassification_confirmation(
        authorization,
        scope_id="main",
        target="public",
    )
    with pytest.raises(PrivacyAuthorizationError) as reused:
        require_declassification_confirmation(
            authorization,
            scope_id="main",
            target="public",
        )
    assert reused.value.code == "PRIVACY_DECLASSIFICATION_CONFIRMATION_REQUIRED"


def test_shared_dispatch_passes_only_authorization_and_sanitizes_failures():
    token = keystore.initialize_keystore(PASSWORD)["token"]
    request = Request(header=token)

    async def allowed(authorization):
        assert isinstance(authorization, AuthorizedPrivacyRequest)
        return {"ok": True}

    assert asyncio.run(
        dispatch_privacy_route(request, "record.use", allowed)
    ) == {"ok": True}

    async def failed(_authorization):
        raise RuntimeError("SYNTHETIC_PRIVATE_CANARY")

    with pytest.raises(PrivacyRouteDispatchError) as failure:
        asyncio.run(dispatch_privacy_route(request, "record.use", failed))
    assert failure.value.code == "PRIVACY_OPERATION_FAILED"
    assert "SYNTHETIC_PRIVATE_CANARY" not in str(failure.value)
