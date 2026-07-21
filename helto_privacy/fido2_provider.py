"""Optional FIDO2 hmac-secret provider for hardware-backed unlocks."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any


ERROR_YUBIKEY_UNAVAILABLE = "PRIVACY_YUBIKEY_UNAVAILABLE"
ERROR_YUBIKEY_NOT_FOUND = "PRIVACY_YUBIKEY_NOT_FOUND"
ERROR_YUBIKEY_PIN_INVALID = "PRIVACY_YUBIKEY_PIN_INVALID"
ERROR_YUBIKEY_POLICY_INVALID = "PRIVACY_YUBIKEY_POLICY_INVALID"
ERROR_YUBIKEY_TOUCH_REQUIRED = "PRIVACY_YUBIKEY_TOUCH_REQUIRED"
ERROR_YUBIKEY_ENROLLMENT_FAILED = "PRIVACY_YUBIKEY_ENROLLMENT_FAILED"

FIDO2_RP_ID = "helto-privacy.local"
FIDO2_ORIGIN = f"https://{FIDO2_RP_ID}"
FIDO2_ALGORITHM = "FIDO2-HMAC-SECRET-SHA256"
FIDO2_CREDENTIAL_PROTECTION = "userVerificationRequired"
FIDO2_TIMEOUT_MS = 30_000
FIDO2_SECRET_BYTES = 32


class Fido2ProviderError(RuntimeError):
    """Raised when a FIDO2 device operation cannot complete safely."""


@dataclass(frozen=True)
class Fido2Identity:
    credential_id: bytes
    aaguid: bytes
    public_key_cbor: bytes
    public_key_sha256: str
    salt: bytes


@dataclass(frozen=True)
class Fido2Enrollment:
    identity: Fido2Identity
    secret: bytes


def runtime_available() -> bool:
    try:
        import fido2.client  # noqa: F401
        import fido2.hid  # noqa: F401
    except Exception:
        return False
    return True


def public_key_fingerprint(public_key_cbor: bytes) -> str:
    import base64

    return (
        base64.urlsafe_b64encode(hashlib.sha256(public_key_cbor).digest())
        .decode("ascii")
        .rstrip("=")
    )


def validate_pin_format(pin: str) -> str:
    pin = str(pin or "")
    encoded = pin.encode("utf-8")
    if not encoded:
        raise Fido2ProviderError(
            f"{ERROR_YUBIKEY_PIN_INVALID}: FIDO2 PIN is required."
        )
    if len(encoded) > 63:
        raise Fido2ProviderError(
            f"{ERROR_YUBIKEY_PIN_INVALID}: FIDO2 PIN is too long."
        )
    return pin


class _PinInteraction:
    def __init__(self, pin: str):
        self.pin = pin
        self.pin_requests = 0
        self.touch_requests = 0

    def prompt_up(self) -> None:
        self.touch_requests += 1

    def request_pin(self, _permissions, _rp_id) -> str:
        self.pin_requests += 1
        return self.pin

    def request_uv(self, _permissions, _rp_id) -> bool:
        return False


class YubiKeyFido2Provider:
    """Production provider backed by python-fido2 over USB HID."""

    def enroll(
        self,
        *,
        pin: str,
        device_path: str | None = None,
    ) -> Fido2Enrollment:
        pin = validate_pin_format(pin)
        modules = self._modules()
        device = self._select_device(modules, device_path=device_path)
        try:
            client, interaction = self._client(device, pin, modules)
            self._validate_info(client.info)
            response = client.make_credential(
                {
                    "rp": {"id": FIDO2_RP_ID, "name": "Helto Privacy"},
                    "user": {
                        "id": secrets.token_bytes(32),
                        "name": "helto-privacy",
                        "displayName": "Helto Privacy",
                    },
                    "challenge": secrets.token_bytes(32),
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": FIDO2_TIMEOUT_MS,
                    "authenticatorSelection": {
                        "residentKey": "discouraged",
                        "userVerification": "required",
                    },
                    "extensions": {
                        "hmacCreateSecret": True,
                        "credentialProtectionPolicy": FIDO2_CREDENTIAL_PROTECTION,
                        "enforceCredentialProtectionPolicy": True,
                    },
                }
            )
            identity = self._identity_from_registration(response, client.info, modules)
            if interaction.pin_requests != 1:
                raise Fido2ProviderError(
                    f"{ERROR_YUBIKEY_POLICY_INVALID}: Enrollment did not perform "
                    "exactly one PIN verification."
                )
        except Fido2ProviderError:
            raise
        except Exception as exc:
            raise self._map_error(
                exc,
                operation="enrollment",
                pin_attempts=self._pin_retries(device, modules),
            ) from exc
        finally:
            device.close()

        # Firmware 5.2 supports hmac-secret only on GetAssertion, so verify the
        # credential and obtain its stable secret in a second authenticated touch.
        secret = self.derive(identity, pin)
        return Fido2Enrollment(identity=identity, secret=secret)

    def derive(self, identity: Fido2Identity, pin: str) -> bytes:
        pin = validate_pin_format(pin)
        modules = self._modules()
        device = self._select_device(modules, aaguid=identity.aaguid)
        try:
            client, interaction = self._client(device, pin, modules)
            self._validate_info(client.info)
            selection = client.get_assertion(
                {
                    "challenge": secrets.token_bytes(32),
                    "timeout": FIDO2_TIMEOUT_MS,
                    "rpId": FIDO2_RP_ID,
                    "allowCredentials": [
                        {"type": "public-key", "id": identity.credential_id}
                    ],
                    "userVerification": "required",
                    "extensions": {
                        "hmacGetSecret": {"salt1": identity.salt},
                    },
                }
            )
            assertions = selection.get_assertions()
            if len(assertions) != 1:
                raise Fido2ProviderError(
                    f"{ERROR_YUBIKEY_POLICY_INVALID}: FIDO2 assertion was ambiguous."
                )
            response = selection.get_response(0)
            secret = self._verify_assertion(response, identity, modules)
            if interaction.pin_requests != 1:
                raise Fido2ProviderError(
                    f"{ERROR_YUBIKEY_POLICY_INVALID}: Unlock did not perform "
                    "exactly one PIN verification."
                )
            return secret
        except Fido2ProviderError:
            raise
        except Exception as exc:
            raise self._map_error(
                exc,
                operation="unlock",
                pin_attempts=self._pin_retries(device, modules),
            ) from exc
        finally:
            device.close()

    @staticmethod
    def _modules() -> dict[str, Any]:
        try:
            from fido2 import cbor
            from fido2.client import (
                ClientError,
                DefaultClientDataCollector,
                Fido2Client,
            )
            from fido2.cose import CoseKey
            from fido2.ctap import CtapError
            from fido2.ctap2 import Ctap2
            from fido2.ctap2.extensions import CredProtectExtension, HmacSecretExtension
            from fido2.ctap2.pin import ClientPin
            from fido2.hid import CtapHidDevice
            from fido2.webauthn import AuthenticatorData
        except Exception as exc:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_UNAVAILABLE}: Install helto-privacy[yubikey] "
                "and allow access to the FIDO HID device."
            ) from exc
        return locals()

    @staticmethod
    def _client(device: Any, pin: str, modules: dict[str, Any]):
        interaction = _PinInteraction(pin)
        client = modules["Fido2Client"](
            device,
            modules["DefaultClientDataCollector"](FIDO2_ORIGIN),
            interaction,
            extensions=[
                modules["HmacSecretExtension"](allow_hmac_secret=True),
                modules["CredProtectExtension"](),
            ],
        )
        return client, interaction

    def _select_device(
        self,
        modules: dict[str, Any],
        *,
        device_path: str | None = None,
        aaguid: bytes | None = None,
    ):
        try:
            devices = list(modules["CtapHidDevice"].list_devices())
        except Exception as exc:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_UNAVAILABLE}: Could not enumerate FIDO2 security keys."
            ) from exc

        candidates = []
        policy_errors: list[Fido2ProviderError] = []
        for device in devices:
            try:
                path = str(device.descriptor.path)
                info = modules["Ctap2"](device).info
                if device_path is not None and path != device_path:
                    continue
                if aaguid is not None and bytes(info.aaguid) != aaguid:
                    continue
                self._validate_info(info)
                candidates.append(device)
            except Fido2ProviderError as exc:
                policy_errors.append(exc)
            except Exception:
                continue

        for device in devices:
            if device not in candidates:
                device.close()
        if not candidates:
            if policy_errors:
                raise policy_errors[0]
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_NOT_FOUND}: Connect the enrolled FIDO2 YubiKey and try again."
            )
        if len(candidates) != 1:
            for device in candidates:
                device.close()
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_NOT_FOUND}: Multiple matching FIDO2 keys are "
                "connected; leave only the intended key connected."
            )
        return candidates[0]

    @staticmethod
    def _validate_info(info: Any) -> None:
        versions = set(info.versions or [])
        extensions = set(info.extensions or [])
        options = dict(info.options or {})
        if not versions.intersection({"FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"}):
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Security key does not support FIDO2."
            )
        missing = {"hmac-secret", "credProtect"} - extensions
        if missing:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Security key lacks required "
                f"FIDO2 extensions: {', '.join(sorted(missing))}."
            )
        if not options.get("clientPin"):
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: A FIDO2 PIN must already be configured."
            )

    @staticmethod
    def _identity_from_registration(
        response: Any, info: Any, modules: dict[str, Any]
    ) -> Fido2Identity:
        auth_data = response.response.attestation_object.auth_data
        flags = modules["AuthenticatorData"].FLAG
        credential = auth_data.credential_data
        if auth_data.rp_id_hash != hashlib.sha256(FIDO2_RP_ID.encode()).digest():
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Enrollment relying-party binding is invalid."
            )
        if not (auth_data.flags & flags.UP and auth_data.flags & flags.UV):
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Enrollment did not prove PIN and touch."
            )
        if credential is None or bytes(credential.credential_id) != bytes(response.raw_id):
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Enrollment credential is malformed."
            )
        extensions = auth_data.extensions or {}
        if extensions.get("credProtect") != 3:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Credential is not protected "
                "by required user verification."
            )
        if response.client_extension_results.hmac_create_secret is not True:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Credential did not enable hmac-secret."
            )
        public_key_cbor = modules["cbor"].encode(dict(credential.public_key))
        return Fido2Identity(
            credential_id=bytes(response.raw_id),
            aaguid=bytes(info.aaguid),
            public_key_cbor=public_key_cbor,
            public_key_sha256=public_key_fingerprint(public_key_cbor),
            salt=secrets.token_bytes(FIDO2_SECRET_BYTES),
        )

    @staticmethod
    def _verify_assertion(response: Any, identity: Fido2Identity, modules: dict[str, Any]) -> bytes:
        if bytes(response.raw_id) != identity.credential_id:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: FIDO2 credential does not match the keystore."
            )
        auth_data = response.response.authenticator_data
        flags = modules["AuthenticatorData"].FLAG
        if auth_data.rp_id_hash != hashlib.sha256(FIDO2_RP_ID.encode()).digest():
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: FIDO2 relying-party binding is invalid."
            )
        if not (auth_data.flags & flags.UP and auth_data.flags & flags.UV):
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: FIDO2 assertion did not prove PIN and touch."
            )
        if public_key_fingerprint(identity.public_key_cbor) != identity.public_key_sha256:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: Stored FIDO2 public key fingerprint is invalid."
            )
        public_key = modules["CoseKey"].parse(modules["cbor"].decode(identity.public_key_cbor))
        public_key.verify(
            bytes(auth_data) + response.response.client_data.hash,
            response.response.signature,
        )
        hmac_output = response.client_extension_results.hmac_get_secret
        secret = bytes(hmac_output.output1) if hmac_output else b""
        if len(secret) != FIDO2_SECRET_BYTES:
            raise Fido2ProviderError(
                f"{ERROR_YUBIKEY_POLICY_INVALID}: FIDO2 hmac-secret output is missing or malformed."
            )
        return secret

    @staticmethod
    def _pin_retries(device: Any, modules: dict[str, Any]) -> int | None:
        try:
            retries, _power_cycle = modules["ClientPin"](
                modules["Ctap2"](device)
            ).get_pin_retries()
            return int(retries)
        except Exception:
            return None

    def _map_error(
        self,
        exc: Exception,
        *,
        operation: str,
        pin_attempts: int | None = None,
    ) -> Fido2ProviderError:
        modules = self._modules()
        cause = getattr(exc, "cause", None)
        ctap_error = cause if isinstance(cause, modules["CtapError"]) else None
        if ctap_error is not None:
            code = ctap_error.code
            if code in {
                modules["CtapError"].ERR.PIN_INVALID,
                modules["CtapError"].ERR.PIN_AUTH_INVALID,
            }:
                suffix = (
                    ""
                    if pin_attempts is None
                    else f" {pin_attempts} attempt(s) remain."
                )
                return Fido2ProviderError(
                    f"{ERROR_YUBIKEY_PIN_INVALID}: FIDO2 PIN is incorrect.{suffix}"
                )
            if code in {
                modules["CtapError"].ERR.PIN_BLOCKED,
                modules["CtapError"].ERR.PIN_AUTH_BLOCKED,
            }:
                return Fido2ProviderError(
                    f"{ERROR_YUBIKEY_PIN_INVALID}: FIDO2 PIN is blocked or temporarily blocked."
                )
            if code == modules["CtapError"].ERR.NO_CREDENTIALS:
                return Fido2ProviderError(
                    f"{ERROR_YUBIKEY_NOT_FOUND}: Connected FIDO2 key does not "
                    "contain the enrolled credential."
                )
        if isinstance(exc, modules["ClientError"]):
            if exc.code == modules["ClientError"].ERR.TIMEOUT:
                return Fido2ProviderError(
                    f"{ERROR_YUBIKEY_TOUCH_REQUIRED}: FIDO2 {operation} timed "
                    "out waiting for touch."
                )
            if exc.code == modules["ClientError"].ERR.DEVICE_INELIGIBLE:
                return Fido2ProviderError(
                    f"{ERROR_YUBIKEY_NOT_FOUND}: Connected FIDO2 key does not "
                    "contain the enrolled credential."
                )
        return Fido2ProviderError(
            f"{ERROR_YUBIKEY_UNAVAILABLE}: FIDO2 {operation} failed."
        )
