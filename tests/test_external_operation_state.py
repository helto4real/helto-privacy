from __future__ import annotations

import os
from dataclasses import replace

import pytest

import helto_privacy.keystore as keystore
from helto_privacy.external_operation_state import (
    ExternalOperationRecord,
    ExternalOperationStateError,
    commit_external_operation_state,
    exclusive_external_operation_state,
    external_operation_journal_path,
    external_operation_state_path,
    load_external_operation_journal,
    load_external_operation_state,
    publish_external_operation_journal,
)


def _active_record(transaction_id: str, journal_digest: str) -> ExternalOperationRecord:
    return ExternalOperationRecord(
        transaction_id,
        "helto.external-state-test",
        "a" * 64,
        "main",
        "associate-captured-take",
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "captured",
        journal_digest,
        2_000_000_000,
        1,
    )


def _journal(transaction_id: str) -> dict[str, object]:
    return {
        "packId": "helto.external-state-test",
        "profileFingerprint": "a" * 64,
        "scopeId": "main",
        "operationId": "associate-captured-take",
        "transactionId": transaction_id,
        "phase": "captured",
        "privateCanary": "SYNTHETIC_EXTERNAL_JOURNAL_CANARY",
    }


def test_external_operation_state_is_private_exact_and_cas_guarded():
    keystore.initialize_keystore("synthetic external state password")
    transaction_id = "hp-operation-" + "t" * 32
    identity = (
        "helto.external-state-test",
        "associate-captured-take",
        transaction_id,
    )
    digest = publish_external_operation_journal(identity, _journal(transaction_id))
    record = _active_record(transaction_id, digest)

    with exclusive_external_operation_state():
        revision = commit_external_operation_state((record,), expected_revision=0)
    assert revision == 1
    assert load_external_operation_state() == (1, (record,))
    assert load_external_operation_journal(record) == _journal(transaction_id)

    state_path = external_operation_state_path()
    journal_path = external_operation_journal_path(*identity, digest)
    assert os.stat(state_path).st_mode & 0o777 == 0o600
    assert os.stat(journal_path).st_mode & 0o777 == 0o600
    assert b"SYNTHETIC_EXTERNAL_JOURNAL_CANARY" not in journal_path.read_bytes()

    state_before = state_path.read_bytes()
    with exclusive_external_operation_state():
        with pytest.raises(ExternalOperationStateError):
            commit_external_operation_state((record,), expected_revision=0)
    assert state_path.read_bytes() == state_before


def test_invalid_duplicate_owner_or_request_never_replaces_valid_index():
    keystore.initialize_keystore("synthetic external duplicate password")
    first_id = "hp-operation-" + "a" * 32
    second_id = "hp-operation-" + "b" * 32
    first_digest = publish_external_operation_journal(
        ("helto.external-state-test", "associate-captured-take", first_id),
        _journal(first_id),
    )
    second_digest = publish_external_operation_journal(
        ("helto.external-state-test", "associate-captured-take", second_id),
        _journal(second_id),
    )
    first = _active_record(first_id, first_digest)
    second = replace(
        _active_record(second_id, second_digest),
        request_digest="e" * 64,
    )
    with exclusive_external_operation_state():
        commit_external_operation_state((first,), expected_revision=0)
    state_before = external_operation_state_path().read_bytes()

    with exclusive_external_operation_state():
        with pytest.raises(ExternalOperationStateError):
            commit_external_operation_state((first, second), expected_revision=1)
    assert external_operation_state_path().read_bytes() == state_before

    distinct_owner = replace(second, owner_digest="f" * 64)
    duplicate_request = replace(distinct_owner, request_digest=first.request_digest)
    with exclusive_external_operation_state():
        with pytest.raises(ExternalOperationStateError):
            commit_external_operation_state(
                (first, duplicate_request),
                expected_revision=1,
            )
    assert external_operation_state_path().read_bytes() == state_before


def test_external_operation_lock_releases_after_base_exception():
    class SyntheticCancellation(BaseException):
        pass

    with pytest.raises(SyntheticCancellation):
        with exclusive_external_operation_state():
            raise SyntheticCancellation
    with exclusive_external_operation_state():
        assert load_external_operation_state() == (0, ())

