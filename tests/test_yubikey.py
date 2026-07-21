import hashlib
import json
import secrets
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.client import ClientError
from fido2.cose import CoseKey, ES256
from fido2.ctap import CtapError
from fido2.webauthn import Aaguid, AuthenticatorData, AttestedCredentialData, CollectedClientData

import helto_privacy.cli as cli
import helto_privacy.keystore as keystore
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.fido2_provider import (
    FIDO2_CREDENTIAL_PROTECTION,
    FIDO2_RP_ID,
    Fido2Enrollment,
    Fido2Identity,
    Fido2ProviderError,
    YubiKeyFido2Provider,
    public_key_fingerprint,
    validate_pin_format,
)
from helto_privacy.keystore import PrivacyKeystoreError


PASSWORD = "correct horse battery"
PIN = "654321"
DEVICE_PATH = "/dev/hidraw2"
AAGUID = bytes.fromhex("2fc0579f811347eab116bb5a8db9202a")
SECRET = b"S" * 32


def _identity() -> Fido2Identity:
    public_key = cbor.encode({1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32})
    return Fido2Identity(
        credential_id=b"credential-id",
        aaguid=AAGUID,
        public_key_cbor=public_key,
        public_key_sha256=public_key_fingerprint(public_key),
        salt=b"H" * 32,
    )


class FakeFidoProvider:
    def __init__(self):
        self.identity = _identity()
        self.enroll_calls = []
        self.derive_pins = []

    def enroll(self, *, pin, device_path=None):
        self.enroll_calls.append((pin, device_path))
        if pin != PIN:
            raise Fido2ProviderError(
                "PRIVACY_YUBIKEY_PIN_INVALID: FIDO2 PIN is incorrect. 2 attempt(s) remain."
            )
        return Fido2Enrollment(identity=self.identity, secret=SECRET)

    def derive(self, identity, pin):
        self.derive_pins.append(pin)
        if pin != PIN:
            raise Fido2ProviderError(
                "PRIVACY_YUBIKEY_PIN_INVALID: FIDO2 PIN is incorrect. 2 attempt(s) remain."
            )
        assert identity == self.identity
        return SECRET


def enroll(provider, *, current_password=None):
    return keystore.enroll_yubikey_keystore(
        pin=PIN,
        current_password=current_password,
        fido_provider=provider,
    )


def test_fresh_yubikey_keystore_round_trip_and_reauthenticates_when_unlocked():
    provider = FakeFidoProvider()

    result = enroll(provider)
    first_token = result["token"]
    raw = json.loads(keystore.keystore_path().read_text(encoding="utf-8"))

    assert raw["version"] == 2
    assert raw["unlock"]["method"] == "yubikey-fido2"
    assert raw["unlock"]["credentialProtection"] == "userVerificationRequired"
    assert raw["unlock"]["userVerification"] == "required"
    assert raw["unlock"]["userPresence"] == "required"
    assert raw["unlock"]["residentKey"] is False
    assert "serial" not in json.dumps(raw["unlock"]).lower()
    assert "kdf" not in raw
    status = keystore.keystore_status()
    assert status["unlockMethod"] == "yubikey-fido2"
    assert status["touchRequired"] is True
    assert "credential" not in json.dumps(status).lower()

    second = keystore.unlock_keystore(PIN, fido_provider=provider)

    assert second["token"] != first_token
    assert provider.derive_pins == [PIN]
    assert keystore.primary_session_key()[0]


def test_password_conversion_preserves_existing_envelopes_and_removes_fallback():
    provider = FakeFidoProvider()
    codec = PrivacyEnvelopeCodec("helto.yubikey-test")
    password_result = keystore.initialize_keystore(PASSWORD)
    envelope = codec.encrypt_state({"secret": "existing workflow"})

    result = enroll(provider, current_password=PASSWORD)

    assert result["unlockMethod"] == "yubikey-fido2"
    assert result["token"] != password_result["token"]
    assert codec.decrypt_state(envelope) == {"secret": "existing workflow"}
    keystore.lock_keystore()
    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_YUBIKEY_PIN_INVALID"):
        keystore.unlock_keystore(PASSWORD, fido_provider=provider)
    keystore.unlock_keystore(PIN, fido_provider=provider)
    assert codec.decrypt_state(envelope) == {"secret": "existing workflow"}
    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_AUTH_METHOD_INVALID"):
        keystore.change_keystore_password(PIN, "replacement password")


def test_legacy_version_one_password_keystore_remains_readable():
    salt = secrets.token_bytes(keystore.SCRYPT_SALT_BYTES)
    kek = keystore._derive_kek(
        PASSWORD, salt, keystore.SCRYPT_N, keystore.SCRYPT_R, keystore.SCRYPT_P
    )
    key = secrets.token_bytes(keystore.KEY_BYTES)
    key_id = keystore._key_id_for(key)
    payload = {
        "schema": keystore.KEYSTORE_SCHEMA,
        "version": 1,
        "kdf": {
            "name": "scrypt",
            "salt": keystore._b64url_encode(salt),
            "n": keystore.SCRYPT_N,
            "r": keystore.SCRYPT_R,
            "p": keystore.SCRYPT_P,
        },
        "keys": [keystore._wrap_entry(kek, key_id, key, primary=True, version=1)],
    }
    keystore._write_private_json(keystore.keystore_path(), payload)

    result = keystore.unlock_keystore(PASSWORD)

    assert result["unlockMethod"] == "password"
    assert keystore.primary_session_key() == (key, key_id)


def test_wrong_pin_does_not_destroy_existing_session():
    provider = FakeFidoProvider()
    first = enroll(provider)

    with pytest.raises(PrivacyKeystoreError, match="2 attempt.*remain"):
        keystore.unlock_keystore("000000", fido_provider=provider)

    assert keystore.session_token() == first["token"]
    assert keystore.keystore_status()["keystoreLocked"] is False


def test_yubikey_unlock_imports_legacy_keys_in_same_transaction():
    provider = FakeFidoProvider()
    enroll(provider)
    legacy_key = b"L" * keystore.KEY_BYTES
    legacy_id = keystore._key_id_for(legacy_key)

    keystore.unlock_keystore(
        PIN,
        legacy_keys=[(legacy_id, legacy_key)],
        fido_provider=provider,
    )
    keystore.lock_keystore()
    keystore.unlock_keystore(PIN, fido_provider=provider)

    assert keystore.session_key_for(legacy_id) == legacy_key


def test_conversion_verifies_password_before_fido_enrollment():
    provider = FakeFidoProvider()
    keystore.initialize_keystore(PASSWORD)

    with pytest.raises(PrivacyKeystoreError, match="PRIVACY_PASSWORD_INVALID"):
        enroll(provider, current_password="wrong password")

    assert provider.enroll_calls == []
    assert keystore.keystore_unlock_method() == "password"


def test_failed_finalization_leaves_password_store_intact(monkeypatch):
    provider = FakeFidoProvider()
    keystore.initialize_keystore(PASSWORD)
    original = keystore.keystore_path().read_bytes()
    real_write = keystore._write_private_json

    def fail_conversion(path, payload):
        if payload.get("unlock", {}).get("method") == "yubikey-fido2":
            raise OSError("disk full")
        return real_write(path, payload)

    monkeypatch.setattr(keystore, "_write_private_json", fail_conversion)

    with pytest.raises(PrivacyKeystoreError, match="disk full"):
        enroll(provider, current_password=PASSWORD)

    assert keystore.keystore_path().read_bytes() == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("credentialProtection", "userVerificationOptional"),
        ("userVerification", "discouraged"),
        ("userPresence", "preferred"),
        ("residentKey", True),
    ],
)
def test_yubikey_metadata_fails_closed_when_policy_is_weakened(field, value):
    provider = FakeFidoProvider()
    enroll(provider)
    raw = json.loads(keystore.keystore_path().read_text(encoding="utf-8"))
    raw["unlock"][field] = value
    keystore.keystore_path().write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(PrivacyKeystoreError, match="policies are invalid"):
        keystore.unlock_keystore(PIN, fido_provider=provider)


def test_fido_pin_format_rejected_before_device_use():
    assert validate_pin_format(PIN) == PIN
    with pytest.raises(Fido2ProviderError, match="required"):
        validate_pin_format("")
    with pytest.raises(Fido2ProviderError, match="too long"):
        validate_pin_format("x" * 64)


def _info(*, extensions=("hmac-secret", "credProtect"), client_pin=True):
    return SimpleNamespace(
        versions=("FIDO_2_0",),
        extensions=extensions,
        options={"clientPin": client_pin, "up": True},
        aaguid=AAGUID,
    )


def test_fido_capabilities_require_hmac_secret_credprotect_and_pin():
    YubiKeyFido2Provider._validate_info(_info())
    with pytest.raises(Fido2ProviderError, match="hmac-secret"):
        YubiKeyFido2Provider._validate_info(_info(extensions=("credProtect",)))
    with pytest.raises(Fido2ProviderError, match="credProtect"):
        YubiKeyFido2Provider._validate_info(_info(extensions=("hmac-secret",)))
    with pytest.raises(Fido2ProviderError, match="PIN must already be configured"):
        YubiKeyFido2Provider._validate_info(_info(client_pin=False))


def test_fido_device_selection_rejects_missing_and_multiple_matching_devices():
    class Device:
        def __init__(self, path):
            self.descriptor = SimpleNamespace(path=path)
            self.closed = False

        def close(self):
            self.closed = True

    class Hid:
        devices = []

        @classmethod
        def list_devices(cls):
            return iter(cls.devices)

    modules = {
        "CtapHidDevice": Hid,
        "Ctap2": lambda _device: SimpleNamespace(info=_info()),
    }
    provider = YubiKeyFido2Provider()

    with pytest.raises(Fido2ProviderError, match="PRIVACY_YUBIKEY_NOT_FOUND"):
        provider._select_device(modules)

    Hid.devices = [Device("/dev/hidraw1"), Device("/dev/hidraw2")]
    with pytest.raises(Fido2ProviderError, match="Multiple matching"):
        provider._select_device(modules)
    assert all(device.closed for device in Hid.devices)

    Hid.devices = [Device("/dev/hidraw1"), Device("/dev/hidraw2")]
    selected = provider._select_device(modules, device_path="/dev/hidraw2")
    assert selected.descriptor.path == "/dev/hidraw2"
    selected.close()


def _signed_assertion(identity: Fido2Identity, private_key, *, flags=None, secret=SECRET):
    flags = flags or (AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(FIDO2_RP_ID.encode()).digest(), flags, 1
    )
    client_data = CollectedClientData.create(
        type=CollectedClientData.TYPE.GET,
        origin=f"https://{FIDO2_RP_ID}",
        challenge=secrets.token_bytes(32),
    )
    signature = private_key.sign(
        bytes(auth_data) + client_data.hash,
        ec.ECDSA(hashes.SHA256()),
    )
    return SimpleNamespace(
        raw_id=identity.credential_id,
        response=SimpleNamespace(
            authenticator_data=auth_data,
            client_data=client_data,
            signature=signature,
        ),
        client_extension_results=SimpleNamespace(
            hmac_get_secret=SimpleNamespace(output1=secret)
        ),
    )


def test_fido_assertion_verifies_signature_pin_touch_and_hmac_secret():
    private_key = ec.generate_private_key(ec.SECP256R1())
    cose_key = ES256.from_cryptography_key(private_key.public_key())
    public_key_cbor = cbor.encode(dict(cose_key))
    identity = Fido2Identity(
        credential_id=b"credential-id",
        aaguid=AAGUID,
        public_key_cbor=public_key_cbor,
        public_key_sha256=public_key_fingerprint(public_key_cbor),
        salt=b"H" * 32,
    )
    modules = {
        "AuthenticatorData": AuthenticatorData,
        "CoseKey": CoseKey,
        "cbor": cbor,
    }

    assert (
        YubiKeyFido2Provider._verify_assertion(
            _signed_assertion(identity, private_key), identity, modules
        )
        == SECRET
    )

    no_uv = AuthenticatorData.FLAG.UP
    with pytest.raises(Fido2ProviderError, match="PIN and touch"):
        YubiKeyFido2Provider._verify_assertion(
            _signed_assertion(identity, private_key, flags=no_uv), identity, modules
        )


def test_fido_registration_requires_hmac_secret_and_credprotect():
    private_key = ec.generate_private_key(ec.SECP256R1())
    cose_key = ES256.from_cryptography_key(private_key.public_key())
    credential_id = b"credential-id"
    credential = AttestedCredentialData.create(
        Aaguid(AAGUID), credential_id, cose_key
    )
    auth_data = AuthenticatorData.create(
        hashlib.sha256(FIDO2_RP_ID.encode()).digest(),
        AuthenticatorData.FLAG.UP
        | AuthenticatorData.FLAG.UV
        | AuthenticatorData.FLAG.AT
        | AuthenticatorData.FLAG.ED,
        0,
        credential,
        {"hmac-secret": True, "credProtect": 3},
    )
    response = SimpleNamespace(
        raw_id=credential_id,
        response=SimpleNamespace(
            attestation_object=SimpleNamespace(auth_data=auth_data)
        ),
        client_extension_results=SimpleNamespace(hmac_create_secret=True),
    )
    modules = {"AuthenticatorData": AuthenticatorData, "cbor": cbor}

    identity = YubiKeyFido2Provider._identity_from_registration(
        response, _info(), modules
    )

    assert identity.credential_id == credential_id
    assert identity.aaguid == AAGUID
    assert identity.public_key_sha256 == public_key_fingerprint(identity.public_key_cbor)


def test_fido_wrong_pin_and_touch_errors_are_stable():
    provider = YubiKeyFido2Provider()
    pin_error = ClientError(
        ClientError.ERR.BAD_REQUEST,
        CtapError(CtapError.ERR.PIN_INVALID),
    )
    touch_error = ClientError(ClientError.ERR.TIMEOUT)

    assert "PRIVACY_YUBIKEY_PIN_INVALID" in str(
        provider._map_error(pin_error, operation="unlock", pin_attempts=2)
    )
    assert "2 attempt(s) remain" in str(
        provider._map_error(pin_error, operation="unlock", pin_attempts=2)
    )
    assert "PRIVACY_YUBIKEY_TOUCH_REQUIRED" in str(
        provider._map_error(touch_error, operation="unlock")
    )


def test_cli_prompts_for_secrets_and_does_not_echo_them(monkeypatch, capsys):
    prompts = iter([PASSWORD, PIN])
    captured = {}
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(prompts))
    monkeypatch.setattr(cli.keystore, "keystore_unlock_method", lambda: "password")

    def fake_enroll(**kwargs):
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(cli.keystore, "enroll_yubikey_keystore", fake_enroll)

    assert cli.main(["yubikey", "enroll", "--device", DEVICE_PATH]) == 0
    output = capsys.readouterr()

    assert captured["current_password"] == PASSWORD
    assert captured["pin"] == PIN
    assert captured["device_path"] == DEVICE_PATH
    assert PASSWORD not in output.out + output.err
    assert PIN not in output.out + output.err


def test_cli_fresh_enrollment_does_not_prompt_for_a_privacy_password(monkeypatch):
    prompts = []
    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or PIN,
    )
    monkeypatch.setattr(cli.keystore, "keystore_unlock_method", lambda: None)
    monkeypatch.setattr(cli.keystore, "enroll_yubikey_keystore", lambda **_kwargs: {})

    assert cli.main(["yubikey", "enroll"]) == 0
    assert len(prompts) == 1
    assert all("privacy password" not in prompt.lower() for prompt in prompts)


@pytest.mark.parametrize(
    ("method", "answers"),
    [
        (None, [PIN]),
        (keystore.AUTH_PASSWORD, [PASSWORD, PIN]),
    ],
)
def test_cli_enrollment_paths_fail_closed_without_echoing_secrets(
    method, answers, monkeypatch, capsys
):
    secret_answers = list(answers)
    prompts = iter(secret_answers)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(prompts))
    monkeypatch.setattr(cli.keystore, "keystore_unlock_method", lambda: method)
    monkeypatch.setattr(
        cli.keystore,
        "enroll_yubikey_keystore",
        lambda **_kwargs: (_ for _ in ()).throw(
            PrivacyKeystoreError(
                "PRIVACY_YUBIKEY_ENROLLMENT_FAILED: hardware operation failed"
            )
        ),
    )

    assert cli.main(["yubikey", "enroll"]) == 1
    output = capsys.readouterr()
    combined = output.out + output.err
    assert "PRIVACY_YUBIKEY_ENROLLMENT_FAILED" in combined
    assert all(secret not in combined for secret in secret_answers)
