"""HTTP status fallback keeps transient commands in their durable retry queues."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from Container_Audit import ContainerAudit
from terminal_operation_lease import OperationLeaseStore
from tests.test_transfer_seal import (
    FakeResponse, TransferSealCoordinator, TransferSealError, TransferSealStore,
    _client, _LogisticsServer, _prepare, _receipt,
)


@pytest.mark.parametrize("status_code", [408, 429, 500])
def test_seal_without_retryable_recovers_with_original_command(tmp_path, status_code):
    server = _LogisticsServer()

    def respond(call):
        if call["method"] == "POST" and server.mode == "busy":
            return FakeResponse(status_code, {"ok": False, "error": {"code": "SERVER_BUSY"}})
        return server(call)

    client, session = _client(respond)
    store = TransferSealStore(tmp_path / "seal.db")
    coordinator = TransferSealCoordinator(store, client)
    prepared = _prepare(coordinator, require_completion_checkpoint=True)
    coordinator.confirm_completion_checkpoint(prepared.intent_id)

    assert coordinator.attempt(prepared.intent_id).status == "RETRY_WAIT"
    before = dict(store.load(prepared.intent_id))
    assert store.pending_ids() == [prepared.intent_id]
    with pytest.raises(KeyError):
        store.post_review_case_for_intent(prepared.intent_id)

    server.mode = "answering"
    assert coordinator.drain_pending_through(prepared.intent_id)[0].status == "ACKED"
    after = dict(store.load(prepared.intent_id))
    for field in ("command_json", "idempotency_key", "local_completion_id", "scanned_barcodes_json"):
        assert after[field] == before[field]
    posts = [call for call in session.calls if call["method"] == "POST"]
    assert len(posts) == 2
    assert posts[0]["json"] == posts[1]["json"]
    assert posts[0]["headers"]["Idempotency-Key"] == posts[1]["headers"]["Idempotency-Key"]
    assert store.pending_ids() == []


@pytest.mark.parametrize("status_code,code", [
    (409, "VERSION_CONFLICT"), (412, "VERSION_CONFLICT"),
    (429, "RESIDUAL_TAG_NOT_ALLOWED"), (429, "SOURCE_IDENTITY_MISMATCH"),
    (429, "PHS2_CONTRACT_INVALID"), (429, "OPERATION_LEASE_INVALID"),
    (400, "REQUEST_INVALID"), (403, "FORBIDDEN"), (422, "INVALID"),
])
def test_seal_status_fallback_preserves_definite_refusals(tmp_path, status_code, code):
    store = TransferSealStore(tmp_path / "refusal.db")
    prepared = store.prepare(master_label="MASTER", source_identity={"source_bundle_id": "SOURCE"},
                             item_id="ITEM", operator="worker", scanned_barcodes=["BC-1"])
    row = store.record_error(prepared["intent_id"], TransferSealError(
        code, "fixture refusal", status_code=status_code, retryable=False,
    ))
    assert row["status"] == "OPERATOR_REVIEW"
    assert store.pending_ids() == []


def test_committed_seal_429_recovers_receipt_without_resubmitting(tmp_path):
    server = _LogisticsServer()
    received = []

    def respond(call):
        if call["method"] == "POST":
            received.append(call["json"])
            return FakeResponse(429, {"ok": False, "committed": True,
                                      "error": {"code": "SERVER_BUSY"}})
        if "/receipts/" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": _receipt(received[0])})
        return server(call)

    client, _ = _client(respond)
    store = TransferSealStore(tmp_path / "committed.db")
    coordinator = TransferSealCoordinator(store, client)
    prepared = _prepare(coordinator, require_completion_checkpoint=True)
    coordinator.confirm_completion_checkpoint(prepared.intent_id)
    assert coordinator.attempt(prepared.intent_id).status == "ACKED"
    assert len(received) == 1
    assert store.pending_ids() == []


def _release_app(store, client):
    app = ContainerAudit.__new__(ContainerAudit)
    coordinator = SimpleNamespace(client=client, operation_lease_manager=SimpleNamespace(store=store))
    app._transfer_seal_runtime = lambda: coordinator
    app._work_operation_lease_release_allowed = lambda *args: True
    app._log_event = Mock()
    return app


@pytest.mark.parametrize("status_code", [408, 429, 503])
def test_release_without_retryable_survives_restart_and_retries(tmp_path, status_code):
    ready = [False]

    def respond(call):
        if not ready[0]:
            return FakeResponse(status_code, {"ok": False, "error": {"code": "SERVER_BUSY"}})
        return FakeResponse(200, {"ok": True, "data": {"status": "RELEASED", "lease_id": "LEASE"}})

    client, session = _client(respond)
    database = tmp_path / "release.db"
    store = OperationLeaseStore(database)
    store.queue_release("LEASE", {"authority_scope_id": "SCOPE", "operation": "SEAL_TRANSFER_BUNDLE",
                                  "token": "fixture-only", "expires_at": "2099-01-01T00:00:00Z"})
    before = store.pending_releases()
    app = _release_app(store, client)
    assert app._work_operation_lease_releases_serial((), active_lease_id="") == 1
    assert store.pending_releases() == before
    app._log_event.assert_not_called()

    ready[0] = True
    reopened = OperationLeaseStore(database)
    resumed = _release_app(reopened, client)
    assert resumed._work_operation_lease_releases_serial((), active_lease_id="") == 0
    assert reopened.pending_releases() == {}
    assert len(session.calls) == 2
    assert session.calls[0]["json"] == session.calls[1]["json"]
    assert session.calls[0]["headers"]["Idempotency-Key"] == session.calls[1]["headers"]["Idempotency-Key"]
    assert resumed._log_event.call_args.kwargs["detail"]["result"] == "RELEASED"


@pytest.mark.parametrize("status_code", [400, 404, 409, 412])
def test_release_definite_refusal_still_settles(tmp_path, status_code):
    client, _ = _client(lambda call: FakeResponse(status_code, {"ok": False, "error": {"code": "REFUSED"}}))
    store = OperationLeaseStore(tmp_path / "refused.db")
    store.queue_release("LEASE", {"authority_scope_id": "SCOPE", "operation": "SEAL_TRANSFER_BUNDLE",
                                  "token": "fixture-only", "expires_at": "2099-01-01T00:00:00Z"})
    app = _release_app(store, client)
    assert app._work_operation_lease_releases_serial((), active_lease_id="") == 0
    assert store.pending_releases() == {}
    assert app._log_event.call_args.kwargs["detail"]["result"] == "REFUSED"
