"""Original-lease seal transport against the audited HTTP contract, offline."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Lock

import pytest
import requests

import terminal_operation_lease
import transfer_seal
from operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from terminal_operation_lease import OperationLeaseManager, OperationLeaseStore, utc_text
from test_terminal_operation_lease import (
    TransferSealCoordinator,
    TransferSealStore,
    _accepted_coordinator,
    _consumed_receipt,
)
from test_transfer_seal import FakeResponse, ITEM, _fields_from_compact_qr
from transfer_seal import TransferSealError, source_identity_from_label

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock")


class ContractServer:
    def __init__(self):
        self.posts = []
        self.receipts = {}
        self.effects = 0
        self.failure = None
        self.expires_at = None
        self.consume_result = None
        self._lock = Lock()

    def __call__(self, call):
        # The real server checks/replays the receipt in its write transaction.
        with self._lock:
            return self._seal(call)

    def _seal(self, call):
        assert call["url"].endswith("/transfers/seal")
        command = call["json"]
        self.posts.append(json.dumps(command, sort_keys=True, separators=(",", ":")))
        evidence = command["payload"]["operation_lease"]
        assert set(evidence) == {
            "token", "lease_id", "fence", "snapshot_hash", "operation_completed_at",
        }
        assert "resumed_completion" not in command["payload"]
        key = command["idempotency_key"]
        assert call["headers"]["Idempotency-Key"] == key
        if key in self.receipts:
            return FakeResponse(200, {"ok": True, "status": "committed", "data": self.receipts[key]})
        if self.failure == "timeout":
            raise requests.Timeout("<timeout>")
        if self.failure is not None and self.failure != "lost_ack":
            status, code, retryable = self.failure
            return FakeResponse(status, {"ok": False, "status": "error",
                "retryable": retryable, "committed": False, "error": {
                "code": code, "message": "<server refusal>",
            }})
        receipt = _consumed_receipt(command)
        self.receipts[key] = receipt
        self.effects += 1
        # e6f5a03a operation_lease/service.py:798–870,981–986: these marks
        # stay in the server lease row, outside the exact consumption receipt.
        self.consume_result = dict(receipt["data"]["operation_lease_consumption"])
        completed = datetime.fromisoformat(evidence["operation_completed_at"].replace("Z", "+00:00"))
        if completed > self.expires_at:
            self.consume_result["resumed_completion"] = True
        if transfer_seal.datetime.now(timezone.utc) > self.expires_at + timedelta(seconds=60):
            self.consume_result["late_reflection"] = True
        if self.failure == "lost_ack":
            self.failure = None
            raise requests.Timeout("<response lost after commit>")
        return FakeResponse(200, {"ok": True, "status": "committed", "data": receipt})


def _set_time(monkeypatch, instant):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls.fromtimestamp(instant.timestamp(), timezone.utc)
            return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(transfer_seal, "datetime", Clock)
    monkeypatch.setattr(terminal_operation_lease, "datetime", Clock)


def _scan_completion(tmp_path, monkeypatch, *, timely=False):
    server = ContractServer()
    coordinator, manager, session, resolved, scan_payload, db_path = _accepted_coordinator(
        tmp_path, server, lease_id="original-lease-placeholder",
    )
    artifact = manager.store.artifact("original-lease-placeholder")
    expires = datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00"))
    server.expires_at = expires
    completed = expires + timedelta(seconds=-1 if timely else 1)
    scan_context = {"local_completed_at": utc_text(completed), "short_confirmed": False}
    fields = _fields_from_compact_qr(scan_payload)
    row = coordinator.store.prepare(
        master_label=scan_payload,
        source_identity={**source_identity_from_label(fields),
                         "local_completion_round": scan_context["local_completed_at"]},
        item_id=ITEM, operator="<worker>",
        scanned_barcodes=[member['normalized_barcode'] for member in resolved['work_group_source']['members']],
        require_completion_checkpoint=True, scan_context=scan_context,
    )
    intent_id = row["intent_id"]
    coordinator.store.bind_scan_lease(intent_id, artifact["lease_id"])
    coordinator.confirm_completion_checkpoint(intent_id)
    coordinator.store.mark_scan_completion_projected(intent_id)
    _set_time(monkeypatch, expires + timedelta(hours=1))
    return server, coordinator, manager, session, db_path, intent_id, artifact, completed


def _restart(coordinator, manager, db_path):
    restarted_manager = OperationLeaseManager(OperationLeaseStore(db_path), manager.keyring)
    return TransferSealCoordinator(
        TransferSealStore(db_path), coordinator.client,
        operation_lease_manager=restarted_manager,
    ), restarted_manager


def _immutable(row):
    return tuple(row[name] for name in (
        "local_completion_id", "idempotency_key", "command_json", "command_hash",
        "source_identity_json", "scan_context_json", "scanned_barcodes_json",
    ))


@pytest.mark.parametrize("timely", [True, False])
def test_original_lease_completion_arrives_after_expiry(tmp_path, monkeypatch, timely):
    server, coordinator, manager, _, _, intent_id, artifact, completed = _scan_completion(
        tmp_path, monkeypatch, timely=timely,
    )
    result = coordinator.attempt(intent_id)
    assert result.status == "ACKED"
    command = json.loads(coordinator.store.load(intent_id)["command_json"])
    evidence = command["payload"]["operation_lease"]
    assert evidence == {
        "token": artifact["token"], "lease_id": artifact["lease_id"],
        "fence": artifact["fence"], "snapshot_hash": artifact["snapshot_hash"],
        "operation_completed_at": utc_text(completed),
    }
    assert manager.store.state(artifact["lease_id"]) == "ACKED"
    assert json.loads(coordinator.store.load(intent_id)["receipt_json"])["data"][
        "operation_lease_consumption"]["status"] == "CONSUMED"
    assert server.effects == 1
    assert server.consume_result["status"] == "CONSUMED"
    assert server.consume_result["late_reflection"] is True
    assert ("resumed_completion" in server.consume_result) is not timely
    assert coordinator.attempt(intent_id).status == "ACKED"
    assert len(server.posts) == 1
    # A lost ACK replay uses the original receipt and has no second business effect.
    coordinator.client.seal_transfer(command)
    assert server.effects == 1
    assert server.posts[0] == server.posts[1]


@pytest.mark.parametrize(("status", "code"), [
    (409, "OPERATION_LEASE_NOT_ACTIVE"),
    (409, "OPERATION_LEASE_EVIDENCE_MISMATCH"),
    (409, "OPERATION_LEASE_DEVICE_MISMATCH"),
    (409, "OPERATION_LEASE_RECONCILIATION_REQUIRED"),
    (409, "OPERATION_LEASE_FENCE_EXPIRED"),
    (409, "OPERATION_LEASE_SNAPSHOT_CONFLICT"),
    (409, "IDEMPOTENCY_CONFLICT"),
    (403, "OPERATION_LEASE_MACHINE_SCOPE_FORBIDDEN"),
])
def test_refusals_preserve_original_completion_and_require_explicit_retry(
    tmp_path, monkeypatch, status, code,
):
    server, coordinator, manager, _, db_path, intent_id, artifact, _ = _scan_completion(
        tmp_path, monkeypatch,
    )
    # Even an incorrectly retryable denial must never cause an automatic loop.
    server.failure = (status, code, True)
    assert coordinator.attempt(intent_id).status == "OPERATOR_REVIEW"
    before = _immutable(coordinator.store.load(intent_id))
    completion = dict(manager.store.completion(artifact["lease_id"]))
    review = coordinator.store.post_review_case_for_intent(intent_id)
    assert review["error_code"] == code
    assert coordinator.store.load(intent_id)["last_error_code"] == code
    coordinator, manager = _restart(coordinator, manager, db_path)
    for cycle in range(5):
        _set_time(monkeypatch, datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00"))
                  + timedelta(hours=2, seconds=cycle * 30))
        assert coordinator.drain_pending() == []
        assert coordinator.attempt(intent_id).status == "OPERATOR_REVIEW"
        assert not coordinator.store.has_scan_transport_work()
    assert len(server.posts) == 1
    assert server.effects == 0
    assert dict(manager.store.completion(artifact["lease_id"])) == completion
    assert _immutable(coordinator.store.load(intent_id)) == before
    audits = []
    assert coordinator.retry_operator_review(
        intent_id, acting_operator={"worker": "<worker>", "role": "WORKER"},
        authorize=lambda: True, record_audit=lambda evidence: audits.append(evidence) or True,
    ).status == "OPERATOR_REVIEW"
    assert len(audits) == 1
    assert server.posts[0] == server.posts[1]
    assert coordinator.drain_pending() == []
    if code != "OPERATION_LEASE_FENCE_EXPIRED":
        # An upgraded server cannot revive a released lease or undo an actual
        # ownership/snapshot conflict. Preserve these denials for reconciliation.
        assert manager.store.state(artifact["lease_id"]) == "OPERATOR_REVIEW"
        assert _immutable(coordinator.store.load(intent_id)) == before
        assert dict(manager.store.completion(artifact["lease_id"])) == completion
        assert server.effects == 0
        return
    # The upgraded server can accept the exact command the old server refused.
    server.failure = None
    assert coordinator.retry_operator_review(
        intent_id, acting_operator={"worker": "<worker>", "role": "WORKER"},
        authorize=lambda: True, record_audit=lambda evidence: True,
    ).status == "ACKED"
    assert len(set(server.posts)) == 1
    assert server.effects == 1
    assert _immutable(coordinator.store.load(intent_id)) == before
    assert dict(manager.store.completion(artifact["lease_id"])) == completion
    assert manager.store.state(artifact["lease_id"]) == "ACKED"


@pytest.mark.parametrize("failure", [(503, "SERVICE_UNAVAILABLE", True), "timeout"])
def test_network_retry_restarts_with_the_same_bound_command(tmp_path, monkeypatch, failure):
    server, coordinator, manager, _, db_path, intent_id, artifact, _ = _scan_completion(
        tmp_path, monkeypatch,
    )
    server.failure = failure
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    before = _immutable(coordinator.store.load(intent_id))
    assert intent_id in coordinator.store.pending_ids()
    coordinator, manager = _restart(coordinator, manager, db_path)
    server.failure = None
    assert coordinator.drain_pending()[0].status == "ACKED"
    assert server.posts[0] == server.posts[1]
    assert _immutable(coordinator.store.load(intent_id)) == before
    assert manager.store.state(artifact["lease_id"]) == "ACKED"
    assert server.effects == 1


def test_restart_after_server_commit_replays_receipt_without_second_effect(tmp_path, monkeypatch):
    server, coordinator, manager, _, db_path, intent_id, artifact, _ = _scan_completion(tmp_path, monkeypatch)
    server.failure = "lost_ack"
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    assert server.effects == 1
    before = _immutable(coordinator.store.load(intent_id))
    completion = dict(manager.store.completion(artifact["lease_id"]))

    coordinator, manager = _restart(coordinator, manager, db_path)
    assert coordinator.drain_pending()[0].status == "ACKED"
    assert len(server.posts) == 2 and server.posts[0] == server.posts[1]
    assert server.effects == 1
    assert _immutable(coordinator.store.load(intent_id)) == before
    assert dict(manager.store.completion(artifact["lease_id"])) == completion
    assert manager.store.state(artifact["lease_id"]) == "ACKED"
    with coordinator.store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM transfer_completion_ledger WHERE intent_id=?", (intent_id,)
        ).fetchone()[0] == 1


def test_concurrent_replays_of_expired_completion_have_one_server_effect(tmp_path, monkeypatch):
    server, coordinator, manager, _, db_path, intent_id, artifact, _ = _scan_completion(tmp_path, monkeypatch)
    server.failure = "timeout"
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    before = _immutable(coordinator.store.load(intent_id))
    command = json.loads(coordinator.store.load(intent_id)["command_json"])
    server.failure = None
    # Transport may redeliver concurrently; the coordinator/store still have
    # their existing single owner. Do not weaken that admission rule for a test.
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(coordinator.client.seal_transfer, [command, command]))
    assert replies[0] == replies[1]
    assert server.effects == 1
    assert len(set(server.posts)) == 1

    coordinator, manager = _restart(coordinator, manager, db_path)
    assert coordinator.drain_pending()[0].status == "ACKED"
    assert _immutable(coordinator.store.load(intent_id)) == before
    assert manager.store.state(artifact["lease_id"]) == "ACKED"
    assert server.effects == 1


def test_prepare_still_rejects_an_expired_lease(tmp_path, monkeypatch):
    server = ContractServer()
    coordinator, manager, _, resolved, scan_payload, _ = _accepted_coordinator(
        tmp_path, server, lease_id="original-lease-placeholder",
    )
    artifact = manager.store.artifact("original-lease-placeholder")
    expires = datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00"))
    _set_time(monkeypatch, expires + timedelta(seconds=1))
    with pytest.raises(TransferSealError) as caught:
        coordinator.prepare(
            master_label=scan_payload, master_label_fields=_fields_from_compact_qr(scan_payload),
            item_id=ITEM, operator="<worker>",
            scanned_barcodes=[member['normalized_barcode'] for member in resolved['work_group_source']['members']],
            operation_lease_id=artifact["lease_id"],
        )
    assert caught.value.code == "OPERATION_LEASE_EXPIRED"
    assert manager.store.completion(artifact["lease_id"]) is None
    assert server.posts == []


@pytest.mark.parametrize("mutation", ["signature", "fence", "snapshot"])
def test_expired_completion_still_verifies_original_evidence(tmp_path, monkeypatch, mutation):
    server, coordinator, manager, _, _, intent_id, _, _ = _scan_completion(tmp_path, monkeypatch)
    server.failure = "timeout"
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    before = _immutable(coordinator.store.load(intent_id))
    original_artifact = manager.store.artifact

    def changed_artifact(lease_id):
        artifact = json.loads(json.dumps(original_artifact(lease_id)))
        if mutation == "signature":
            artifact["token"] += "<tampered>"
        elif mutation == "fence":
            artifact["fence"] += 1
        else:
            artifact["operation_snapshot"]["authority_scope_id"] = "<other scope>"
        return artifact

    monkeypatch.setattr(manager.store, "artifact", changed_artifact)
    server.failure = None
    assert coordinator.attempt(intent_id).status == "OPERATOR_REVIEW"
    assert len(server.posts) == 1
    assert server.effects == 0
    assert _immutable(coordinator.store.load(intent_id)) == before
