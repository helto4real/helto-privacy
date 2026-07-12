import json

import pytest

import helto_privacy.keystore as keystore
import helto_privacy.migration as migration
import helto_privacy.runtime as runtime
from helto_privacy import (
    DispositionResult,
    RevealedFieldResult,
    is_verified_current_disposition,
    protected_envelope_mapping,
    protected_envelope_text,
)
from helto_privacy.envelope import PrivacyEnvelopeCodec
from helto_privacy.guard import PrivacyAuthorizationError, authorize_privacy_request
from helto_privacy.profile import (
    AdapterSlot,
    FieldLocation,
    FieldLocationKind,
    LegacyLocationKind,
    LegacyReaderBinding,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProfileResource,
    ResourceKind,
)
from helto_privacy.snapshot import EnvelopeDisposition, SnapshotError


class Request:
    def __init__(self, token):
        self.headers = {"X-Helto-Privacy-Token": token}
        self.cookies = {}


class ModeAdapter:
    def read_declared_mode(self, _scope_id):
        return "private"

    def write_declared_mode(self, _scope_id, _mode):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class StateAdapter:
    def capture(self):
        return {}

    def normalize(self, value, *_args):
        return {"normalized": value.get("value", value)}

    def apply_revealed(self, _value):
        return None

    def clear_plaintext(self):
        return None

    def prepare_mode_transition(self, *_args):
        return None

    def commit_mode_transition(self, *_args):
        return None

    def rollback_mode_transition(self, *_args):
        return None


class LegacyStateReader:
    def probe(self, value, _context):
        return value == "LEGACY_SYNTHETIC"

    def read(self, _value, _context):
        return {"value": "legacy"}


def _profile():
    return PrivacyProfile(
        id="helto.snapshot-test",
        distribution="comfyui-snapshot-test",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
            ProfileResource("state", ResourceKind.WORKFLOW, ("state", "state-ui")),
        ),
        server_adapters=(
            AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("state", ResourceKind.WORKFLOW, "state"),
        ),
        browser_adapters=(
            AdapterSlot("state-ui", ResourceKind.WORKFLOW, "state", ("SyntheticNode",)),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
        protected_fields=(
            ProtectedField(
                "private-state",
                "state",
                "main",
                "state",
                "state-ui",
                ("SyntheticNode",),
                FieldLocation(FieldLocationKind.WIDGET, "state"),
                "helto.snapshot-test.v1",
                "state",
                legacy_reader_ids=("state-v0",),
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "state-v0-binding",
                "state-v0",
                "state",
                LegacyLocationKind.WORKFLOW_FIELD,
                "private-state",
            ),
        ),
    )


@pytest.fixture
def snapshot_pack(monkeypatch):
    monkeypatch.setattr(runtime, "_INSTALLATIONS", {})
    monkeypatch.setattr(runtime, "register_helto_privacy_ui", lambda **_kwargs: True)
    migration.reset_migration_runtime_for_tests()
    migration.register_legacy_reader_units(
        (migration.LegacyReaderUnit("state-v0", "Legacy state", LegacyStateReader()),)
    )
    profile = _profile()
    pack = runtime.install(
        profile,
        {"mode": ModeAdapter(), "state": StateAdapter()},
    )
    token = keystore.initialize_keystore("synthetic password")["token"]
    request = Request(token)
    return pack, token, request


def _authorization(pack, request, operation):
    return authorize_privacy_request(
        request,
        operation,
        pack_id=pack.profile.id,
    )


def test_disposition_requires_real_decrypt_and_preserves_failed_identity(
    snapshot_pack,
):
    pack, _token, request = snapshot_pack
    workflow = pack.workflow("state")
    codec = PrivacyEnvelopeCodec("helto.snapshot-test.v1")
    envelope = codec.encrypt_state({"normalized": "current"})

    verified = workflow.inspect_disposition(
        "private-state",
        envelope,
        _authorization(pack, request, "snapshot.disposition"),
    )
    assert verified.disposition is EnvelopeDisposition.VERIFIED_CURRENT

    tampered = json.loads(json.dumps(envelope))
    tampered["ciphertext"] = (
        "A" if tampered["ciphertext"][0] != "A" else "B"
    ) + tampered["ciphertext"][1:]
    failed = workflow.inspect_disposition(
        "private-state",
        tampered,
        _authorization(pack, request, "snapshot.disposition"),
    )
    repeated = workflow.inspect_disposition(
        "private-state",
        tampered,
        _authorization(pack, request, "snapshot.disposition"),
    )
    assert failed.disposition is EnvelopeDisposition.FAILED_CURRENT
    assert repeated.disposition is EnvelopeDisposition.FAILED_CURRENT
    assert failed.identity == repeated.identity
    assert "ciphertext" not in repr(failed)

    workflow.protect(
        "private-state",
        {"value": "unrelated-owner"},
        _authorization(pack, request, "snapshot.protect"),
    )
    keystore.lock_keystore()
    locked_recheck = workflow.inspect_disposition(
        "private-state",
        tampered,
        None,
    )
    assert locked_recheck.disposition is EnvelopeDisposition.FAILED_CURRENT
    assert locked_recheck.identity == failed.identity


def test_authorized_workflow_reveal_is_typed_and_plaintext_safe_in_repr(snapshot_pack):
    pack, _token, request = snapshot_pack
    workflow = pack.workflow("state")
    envelope = PrivacyEnvelopeCodec("helto.snapshot-test.v1").encrypt_state(
        {"normalized": "SYNTHETIC_REVEALED_FIELD_CANARY"}
    )

    revealed = workflow.reveal(
        "private-state",
        envelope,
        _authorization(pack, request, "snapshot.reveal"),
    )

    assert isinstance(revealed, RevealedFieldResult)
    assert revealed.value == {"normalized": "SYNTHETIC_REVEALED_FIELD_CANARY"}
    assert revealed.correlation_id.startswith("hp-field-")
    assert "SYNTHETIC_REVEALED_FIELD_CANARY" not in repr(revealed)

    serialized = workflow.reveal(
        "private-state",
        json.dumps(envelope),
        _authorization(pack, request, "snapshot.reveal"),
    )
    assert serialized.value == revealed.value


def test_workflow_reveal_rejects_wrong_capability_legacy_and_lock(snapshot_pack):
    pack, _token, request = snapshot_pack
    workflow = pack.workflow("state")
    envelope = PrivacyEnvelopeCodec("helto.snapshot-test.v1").encrypt_state(
        {"normalized": "synthetic current"}
    )

    with pytest.raises(PrivacyAuthorizationError):
        workflow.reveal(
            "private-state",
            envelope,
            _authorization(pack, request, "snapshot.disposition"),
        )
    with pytest.raises(SnapshotError) as legacy:
        workflow.reveal(
            "private-state",
            "LEGACY_SYNTHETIC",
            _authorization(pack, request, "snapshot.reveal"),
        )
    assert legacy.value.code == "PRIVACY_SNAPSHOT_REVEAL_FAILED"

    wrong_version = dict(envelope)
    wrong_version["version"] = 0
    with pytest.raises(SnapshotError) as unsupported:
        workflow.reveal(
            "private-state",
            wrong_version,
            _authorization(pack, request, "snapshot.reveal"),
        )
    assert unsupported.value.code == "PRIVACY_SNAPSHOT_REVEAL_FAILED"

    authorization = _authorization(pack, request, "snapshot.reveal")
    keystore.lock_keystore()
    with pytest.raises(PrivacyAuthorizationError):
        workflow.reveal("private-state", envelope, authorization)


def test_locked_current_is_classified_without_decrypting(snapshot_pack):
    pack, _token, _request = snapshot_pack
    codec = PrivacyEnvelopeCodec("helto.snapshot-test.v1")
    envelope = codec.encrypt_state({"normalized": "locked"})
    keystore.lock_keystore()

    result = pack.workflow("state").inspect_disposition(
        "private-state",
        envelope,
        None,
    )

    assert result.disposition is EnvelopeDisposition.LOCKED_CURRENT
    assert result.replacement_envelope is None


def test_readable_legacy_is_rewritten_current_and_unsupported_never_substitutes(
    snapshot_pack,
):
    pack, _token, request = snapshot_pack
    workflow = pack.workflow("state")
    authorization = _authorization(pack, request, "snapshot.disposition")

    legacy = workflow.inspect_disposition(
        "private-state",
        "LEGACY_SYNTHETIC",
        authorization,
    )
    assert legacy.disposition is EnvelopeDisposition.READABLE_LEGACY
    assert legacy.migration_obligation_id.startswith("hp-obligation-")
    assert PrivacyEnvelopeCodec("helto.snapshot-test.v1").decrypt_state(
        legacy.replacement_envelope
    ) == {"normalized": "legacy"}

    unsupported = workflow.inspect_disposition(
        "private-state",
        "PLAINTEXT_SYNTHETIC_CANARY",
        _authorization(pack, request, "snapshot.disposition"),
    )
    assert unsupported.disposition is EnvelopeDisposition.UNSUPPORTED
    assert unsupported.replacement_envelope is None


def test_protect_normalizes_and_returns_only_current_envelope(snapshot_pack):
    pack, _token, request = snapshot_pack

    protected = pack.workflow("state").protect(
        "private-state",
        {"value": "synthetic"},
        _authorization(pack, request, "snapshot.protect"),
    )

    assert protected.disposition is EnvelopeDisposition.VERIFIED_CURRENT
    assert PrivacyEnvelopeCodec("helto.snapshot-test.v1").decrypt_state(
        protected.envelope
    ) == {"normalized": "synthetic"}
    assert protected_envelope_mapping(protected) == protected.envelope
    assert json.loads(protected_envelope_text(protected)) == protected.envelope
    assert is_verified_current_disposition(
        DispositionResult(EnvelopeDisposition.VERIFIED_CURRENT)
    ) is True
    with pytest.raises(TypeError):
        protected_envelope_text({"value": "PLAINTEXT_SYNTHETIC_CANARY"})
    with pytest.raises(TypeError):
        is_verified_current_disposition(
            type("ForgedDisposition", (), {"disposition": "verified-current"})()
        )
    assert "synthetic" not in repr(protected)


def test_runtime_protect_has_no_request_or_reveal_capability(snapshot_pack):
    pack, _token, _request = snapshot_pack

    protected = pack.workflow("state").protect_runtime(
        "private-state",
        {"value": "synthetic-runtime-result"},
    )

    assert protected.disposition is EnvelopeDisposition.VERIFIED_CURRENT
    assert PrivacyEnvelopeCodec("helto.snapshot-test.v1").decrypt_state(
        protected.envelope
    ) == {"normalized": "synthetic-runtime-result"}
    keystore.lock_keystore()
    with pytest.raises(SnapshotError) as locked:
        pack.workflow("state").protect_runtime(
            "private-state",
            {"value": "must-not-fall-back"},
        )
    assert locked.value.code == "PRIVACY_SNAPSHOT_PROTECTION_FAILED"


def test_unknown_field_and_forged_authorization_fail_closed(snapshot_pack):
    pack, _token, request = snapshot_pack
    workflow = pack.workflow("state")

    with pytest.raises(SnapshotError) as unknown:
        workflow.protect(
            "missing-field",
            {"value": "synthetic"},
            _authorization(pack, request, "snapshot.protect"),
        )
    assert unknown.value.code == "PRIVACY_SNAPSHOT_FIELD_INVALID"

    with pytest.raises(Exception) as forged:
        workflow.protect("private-state", {"value": "synthetic"}, object())
    assert "synthetic" not in str(forged.value)
