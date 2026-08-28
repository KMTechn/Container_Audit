import json

import pytest

from recovery_two_phase import (
    STATE_CLEANUP_INTENT_DURABLE,
    STATE_COMMIT_INTENT_DURABLE,
    STATE_COMPLETE,
    STATE_LOCAL_PACKAGE_DURABLE,
    STATE_LOCAL_PERSISTED,
    STATE_PREPARED,
    STATE_PREPARE_INTENT_DURABLE,
    STATE_SERVER_COMMITTED,
    RecoveryTwoPhaseJournal,
    RecoveryTwoPhaseStateError,
)


def _bindings(suffix="01"):
    return {
        "authorization_id": f"authorization-{suffix}",
        "authorization_audit_event_id": f"audit-{suffix}",
        "client_request_id": f"prepare-{suffix}",
        "commit_id": f"commit-{suffix}",
        "producer_id": "container-producer",
        "producer_install_id": "container-install",
        "source_host_id": "container-host",
        "manifest_hash": "a" * 64,
        "possession_key_fingerprint": (
            "EIEjk1nsv9vwrOp-3GrBvZz2WZPvy48vdViRVd6Llvg"
        ),
    }


def test_recovery_two_phase_journal_enforces_durable_transition_order(tmp_path):
    journal = RecoveryTwoPhaseJournal(tmp_path / "journal.json")

    assert journal.initialize(_bindings())["state"] == STATE_PREPARE_INTENT_DURABLE
    assert journal.record_prepared(
        prepare_id="prepare-server-01",
        prepare_expires_at="2999-01-01T00:00:00Z",
        proposed_credential_epoch=2,
        prepared_key_id="key-02",
        prepared_secret_fingerprint_sha256="b" * 64,
    )["state"] == STATE_PREPARED
    assert journal.stage_sealed_package(b"dpapi-sealed-package")["state"] == (
        STATE_LOCAL_PACKAGE_DURABLE
    )
    assert journal.read_sealed_package() == b"dpapi-sealed-package"
    assert journal.mark_commit_intent()["state"] == STATE_COMMIT_INTENT_DURABLE
    assert journal.mark_server_committed(
        committed_at="2026-08-29T00:00:00Z",
        credential_epoch=2,
    )["state"] == STATE_SERVER_COMMITTED
    assert journal.mark_local_persisted()["state"] == STATE_LOCAL_PERSISTED
    assert journal.mark_cleanup_intent()["state"] == STATE_CLEANUP_INTENT_DURABLE
    assert journal.mark_complete()["state"] == STATE_COMPLETE
    journal.remove_sealed_package_after_complete()

    payload = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    serialized = json.dumps(payload, sort_keys=True)
    assert "dpapi-sealed-package" not in serialized
    assert "recovery_token" not in serialized
    assert "nonce" not in serialized
    assert not journal.sealed_package_path.exists()
    assert [row["to"] for row in payload["transitions"]] == [
        STATE_PREPARE_INTENT_DURABLE,
        STATE_PREPARED,
        STATE_LOCAL_PACKAGE_DURABLE,
        STATE_COMMIT_INTENT_DURABLE,
        STATE_SERVER_COMMITTED,
        STATE_LOCAL_PERSISTED,
        STATE_CLEANUP_INTENT_DURABLE,
        STATE_COMPLETE,
    ]


def test_recovery_two_phase_forbids_commit_before_durable_package(tmp_path):
    journal = RecoveryTwoPhaseJournal(tmp_path / "journal.json")
    journal.initialize(_bindings())
    journal.record_prepared(
        prepare_id="prepare-server-01",
        prepare_expires_at="2999-01-01T00:00:00Z",
        proposed_credential_epoch=2,
        prepared_key_id="key-02",
        prepared_secret_fingerprint_sha256="b" * 64,
    )

    with pytest.raises(RecoveryTwoPhaseStateError, match="forbidden"):
        journal.transition(
            {STATE_PREPARED},
            STATE_COMMIT_INTENT_DURABLE,
        )


def test_recovery_two_phase_rejects_secret_fields_in_journal(tmp_path):
    journal = RecoveryTwoPhaseJournal(tmp_path / "journal.json")
    journal.initialize(_bindings())

    with pytest.raises(RecoveryTwoPhaseStateError, match="secret fields"):
        journal.transition(
            {STATE_PREPARE_INTENT_DURABLE},
            STATE_PREPARED,
            recovery_token="must-never-persist",
        )


def test_completed_journal_is_archived_before_a_new_authorization(tmp_path):
    journal = RecoveryTwoPhaseJournal(tmp_path / "journal.json")
    journal.initialize(_bindings("01"))
    journal.record_prepared(
        prepare_id="prepare-server-01",
        prepare_expires_at="2999-01-01T00:00:00Z",
        proposed_credential_epoch=2,
        prepared_key_id="key-02",
        prepared_secret_fingerprint_sha256="b" * 64,
    )
    journal.stage_sealed_package(b"sealed")
    journal.mark_commit_intent()
    journal.mark_server_committed(
        committed_at="2026-08-29T00:00:00Z",
        credential_epoch=2,
    )
    journal.mark_local_persisted()
    journal.mark_cleanup_intent()
    journal.mark_complete()
    journal.remove_sealed_package_after_complete()

    restarted = journal.initialize(_bindings("02"))

    assert restarted["state"] == STATE_PREPARE_INTENT_DURABLE
    assert restarted["bindings"] == _bindings("02")
    assert (tmp_path / "completed-prepare-01.json").is_file()
