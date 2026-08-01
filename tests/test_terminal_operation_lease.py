import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from operation_lease_fixtures import signed_transfer_artifact
from terminal_operation_lease import (
    CONSUME_CONTRACT_VERSION,
    OperationLeaseError,
    OperationLeaseManager,
    OperationLeaseStore,
    PinnedOperationLeaseKeyring,
    TRANSFER_OPERATION,
    utc_text,
)
from test_transfer_seal import (
    FakeResponse,
    ITEM,
    SCOPE,
    _fields_from_compact_qr,
    _resolved_work_group_phs2,
    _work_group_client,
    _work_group_receipt,
)
from transfer_seal import (
    TransferSealCoordinator,
    TransferSealError,
    TransferSealStore,
    transfer_operation_lease_binding,
    validate_compact_phs2_preflight,
)


def _lease_setup(tmp_path, *, lease_id="operation-lease-test-01"):
    resolved = _resolved_work_group_phs2(mode="merge")
    scan_payload = resolved["phs_work_group"]["scan_payload"]
    client, session = _work_group_client(
        lambda call: (_ for _ in ()).throw(AssertionError(call))
    )
    preflight = validate_compact_phs2_preflight(
        _fields_from_compact_qr(scan_payload), resolved
    )
    binding = transfer_operation_lease_binding(
        client=client,
        scan_payload=scan_payload,
        preflight=preflight,
        operation_snapshot=resolved,
        site_id="SITE-01",
    )
    artifact, claims = signed_transfer_artifact(
        resolved,
        scan_payload=scan_payload,
        device_id=client.device_id,
        source_host_id=client.source_host_id,
        authority_scope_id=SCOPE,
        lease_id=lease_id,
    )
    store = OperationLeaseStore(tmp_path / "transfer-seal.db")
    manager = OperationLeaseManager(
        store,
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )
    issue_request = {
        "authority_scope_id": SCOPE,
        "operation": TRANSFER_OPERATION,
        "scan_payload": scan_payload,
    }
    issue_key = manager.issue_idempotency_key(
        device_id=client.device_id,
        source_host_id=client.source_host_id,
        authority_scope_id=SCOPE,
        scan_payload=scan_payload,
    )
    return {
        "resolved": resolved,
        "scan_payload": scan_payload,
        "client": client,
        "session": session,
        "binding": binding,
        "artifact": artifact,
        "claims": claims,
        "store": store,
        "manager": manager,
        "issue_request": issue_request,
        "issue_key": issue_key,
    }


def _accept(context):
    return context["manager"].accept_authenticated(
        artifact=context["artifact"],
        expected=context["binding"],
        issue_request=context["issue_request"],
        issue_idempotency_key=context["issue_key"],
    )


def _consumed_receipt(command, *, fence=1):
    receipt = _work_group_receipt(command)
    receipt["data"]["operation_lease_consumption"] = {
        "contract_version": CONSUME_CONTRACT_VERSION,
        "lease_id": command["payload"]["operation_lease"]["lease_id"],
        "status": "CONSUMED",
        "fence": fence,
        "operation_result_id": receipt["receipt_id"],
        "consumed_at": "2026-08-01T00:05:00Z",
    }
    return receipt


def _accepted_coordinator(tmp_path, handler, *, lease_id="operation-lease-test-01"):
    resolved = _resolved_work_group_phs2(mode="merge")
    scan_payload = resolved["phs_work_group"]["scan_payload"]
    client, session = _work_group_client(handler)
    preflight = validate_compact_phs2_preflight(
        _fields_from_compact_qr(scan_payload), resolved
    )
    binding = transfer_operation_lease_binding(
        client=client,
        scan_payload=scan_payload,
        preflight=preflight,
        operation_snapshot=resolved,
        site_id="SITE-01",
    )
    artifact, _claims = signed_transfer_artifact(
        resolved,
        scan_payload=scan_payload,
        device_id=client.device_id,
        source_host_id=client.source_host_id,
        authority_scope_id=SCOPE,
        lease_id=lease_id,
    )
    db_path = tmp_path / "transfer-seal.db"
    manager = OperationLeaseManager(
        OperationLeaseStore(db_path),
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )
    issue_request = {
        "authority_scope_id": SCOPE,
        "operation": TRANSFER_OPERATION,
        "scan_payload": scan_payload,
    }
    issue_key = manager.issue_idempotency_key(
        device_id=client.device_id,
        source_host_id=client.source_host_id,
        authority_scope_id=SCOPE,
        scan_payload=scan_payload,
    )
    manager.accept_authenticated(
        artifact=artifact,
        expected=binding,
        issue_request=issue_request,
        issue_idempotency_key=issue_key,
    )
    coordinator = TransferSealCoordinator(
        TransferSealStore(db_path), client, manager
    )
    return coordinator, manager, session, resolved, scan_payload, db_path


def _prepare_lease_transfer(coordinator, resolved, scan_payload, lease_id):
    return coordinator.prepare(
        master_label=scan_payload,
        master_label_fields=_fields_from_compact_qr(scan_payload),
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=[
            member["normalized_barcode"]
            for member in resolved["work_group_source"]["members"]
        ],
        operation_lease_id=lease_id,
    )


def test_issue_endpoint_uses_exact_machine_headers_and_body():
    observed = {}

    def handler(call):
        observed.update(call)
        return FakeResponse(200, {"ok": True, "data": {"lease_id": "lease-1"}})

    client, _session = _work_group_client(handler)
    result = client.issue_operation_lease(
        authority_scope_id=SCOPE,
        operation=TRANSFER_OPERATION,
        scan_payload="PHS=2|PHYSICAL=ONE",
        idempotency_key="issue-key-01",
    )

    assert result == {"lease_id": "lease-1"}
    assert observed["method"] == "POST"
    assert observed["url"].endswith(
        "/logistics/api/v1/operation-leases/issue"
    )
    assert observed["json"] == {
        "authority_scope_id": SCOPE,
        "operation": TRANSFER_OPERATION,
        "scan_payload": "PHS=2|PHYSICAL=ONE",
    }
    assert observed["headers"]["Authorization"] == "Bearer secret-token"
    assert observed["headers"]["X-Logistics-API-Token"] == "secret-token"
    assert observed["headers"]["X-Logistics-Source-Host-Id"] == "PC-01"
    assert observed["headers"]["X-Logistics-Device-Id"] == "PC-01"
    assert observed["headers"]["X-Logistics-Program"] == "Container_Audit"
    assert observed["headers"]["Idempotency-Key"] == "issue-key-01"


def test_authenticated_lease_is_pinned_and_durable_with_zero_expected_version(
    tmp_path,
):
    context = _lease_setup(tmp_path)

    normalized, claims = _accept(context)

    transfer_id = context["resolved"]["work_group_source"][
        "transfer_bundle_id"
    ]
    assert claims["resource_id"] == (
        "phs-work-group:"
        + context["resolved"]["phs_work_group"]["group_id"]
    )
    assert claims["expected_versions"][f"bundle:{transfer_id}"] == 0
    assert normalized["lease_id"] == claims["lease_id"]
    assert context["store"].state(claims["lease_id"]) == "PREFETCHED"
    assert context["manager"].keyring.path.read_text(encoding="utf-8").find(
        '"d"'
    ) == -1
    context["artifact"]["replayed"] = True
    replay, replay_claims = _accept(context)
    assert replay["token"] == normalized["token"]
    assert replay["replayed"] is True
    assert replay_claims == claims
    with context["store"]._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_artifacts"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    ("mutation", "error_code"),
    [
        (
            lambda context: context["binding"].update(
                {"device_id": "OTHER-DEVICE"}
            ),
            "OPERATION_LEASE_BINDING_MISMATCH",
        ),
        (
            lambda context: context["binding"].update(
                {"source_host_id": "OTHER-HOST"}
            ),
            "OPERATION_LEASE_BINDING_MISMATCH",
        ),
        (
            lambda context: context["binding"].update(
                {"membership_hash": "0" * 64}
            ),
            "OPERATION_LEASE_BINDING_MISMATCH",
        ),
        (
            lambda context: context["binding"]["expected_versions"].update(
                {next(iter(context["binding"]["expected_versions"])): 999}
            ),
            "OPERATION_LEASE_BINDING_MISMATCH",
        ),
    ],
)
def test_lease_fails_closed_for_wrong_terminal_or_snapshot(
    tmp_path, mutation, error_code
):
    context = _lease_setup(tmp_path)
    mutation(context)

    with pytest.raises(OperationLeaseError) as exc_info:
        _accept(context)

    assert exc_info.value.code == error_code
    with context["store"]._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_artifacts"
        ).fetchone()[0] == 0


def test_lease_fails_closed_for_token_tamper(tmp_path):
    context = _lease_setup(tmp_path)
    token = context["artifact"]["token"]
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    context["artifact"]["token"] = (
        f"{header}.{payload}.{replacement}{signature[1:]}"
    )

    with pytest.raises(OperationLeaseError) as exc_info:
        _accept(context)

    assert exc_info.value.code == "OPERATION_LEASE_SIGNATURE_INVALID"


def test_lease_fails_closed_after_expiry(tmp_path):
    context = _lease_setup(tmp_path)
    now = datetime.now(timezone.utc)
    context["artifact"], context["claims"] = signed_transfer_artifact(
        context["resolved"],
        scan_payload=context["scan_payload"],
        device_id=context["client"].device_id,
        source_host_id=context["client"].source_host_id,
        authority_scope_id=SCOPE,
        issued_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )

    with pytest.raises(OperationLeaseError) as exc_info:
        _accept(context)

    assert exc_info.value.code == "OPERATION_LEASE_EXPIRED"


def test_admin_released_attempt_preserves_history_and_allows_fresh_same_qr(
    tmp_path,
):
    context = _lease_setup(tmp_path, lease_id="operation-lease-released-01")
    first_key = context["issue_key"]
    context["artifact"]["status"] = "RELEASED"
    context["artifact"]["replayed"] = True

    normalized, claims = context["manager"].accept_authenticated_nonactive(
        artifact=context["artifact"],
        expected=context["binding"],
        issue_request=context["issue_request"],
        issue_idempotency_key=first_key,
    )
    second_key = context["manager"].issue_idempotency_key(
        device_id=context["client"].device_id,
        source_host_id=context["client"].source_host_id,
        authority_scope_id=SCOPE,
        scan_payload=context["scan_payload"],
        explicit_new=True,
    )

    assert normalized["status"] == "RELEASED"
    assert claims["lease_id"] == "operation-lease-released-01"
    assert second_key != first_key
    with context["store"]._connect() as connection:
        attempts = connection.execute(
            """SELECT issue_idempotency_key,status
                 FROM terminal_operation_lease_issue_attempts
                 ORDER BY rowid"""
        ).fetchall()
    assert [row["status"] for row in attempts] == ["RELEASED", "PENDING"]
    assert [row["issue_idempotency_key"] for row in attempts] == [
        first_key,
        second_key,
    ]


def test_prefetch_lost_ack_restart_reuses_durable_issue_nonce(tmp_path):
    context = _lease_setup(tmp_path)
    first_key = context["issue_key"]
    restarted = OperationLeaseManager(
        OperationLeaseStore(tmp_path / "transfer-seal.db"),
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )

    replay_key = restarted.issue_idempotency_key(
        device_id=context["client"].device_id,
        source_host_id=context["client"].source_host_id,
        authority_scope_id=SCOPE,
        scan_payload=context["scan_payload"],
        explicit_new=True,
    )

    assert replay_key == first_key
    with context["store"]._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_issue_attempts"
        ).fetchone()[0] == 1


def test_local_completion_outbox_and_receipt_are_append_only_and_idempotent(
    tmp_path,
):
    context = _lease_setup(tmp_path)
    _normalized, claims = _accept(context)
    completed_at = utc_text()
    first = context["store"].record_local_completion(
        lease_id=claims["lease_id"],
        transfer_intent_id="intent-01",
        transfer_idempotency_key="transfer-key-01",
        operation_completed_at=completed_at,
    )
    replay = context["store"].record_local_completion(
        lease_id=claims["lease_id"],
        transfer_intent_id="intent-01",
        transfer_idempotency_key="transfer-key-01",
        operation_completed_at=completed_at,
    )

    assert replay["operation_result_id"] == first["operation_result_id"]
    assert context["store"].state(claims["lease_id"]) == "LOCAL_COMPLETED"
    with pytest.raises(sqlite3.IntegrityError):
        context["store"].record_local_completion(
            lease_id=claims["lease_id"],
            transfer_intent_id="intent-other",
            transfer_idempotency_key="transfer-key-other",
            operation_completed_at=completed_at,
        )
    receipt = {
        "receipt_id": "receipt-01",
        "data": {
            "receipt_id": "receipt-01",
            "operation_lease_consumption": {
                "contract_version": CONSUME_CONTRACT_VERSION,
                "lease_id": claims["lease_id"],
                "status": "CONSUMED",
                "fence": claims["fence"],
                "operation_result_id": "receipt-01",
                "consumed_at": "2026-08-01T00:05:00Z",
            },
        },
    }
    ack = context["store"].record_receipt(
        lease_id=claims["lease_id"],
        transfer_intent_id="intent-01",
        receipt=receipt,
    )
    replay_ack = context["store"].record_receipt(
        lease_id=claims["lease_id"],
        transfer_intent_id="intent-01",
        receipt=receipt,
    )

    assert replay_ack["receipt_hash"] == ack["receipt_hash"]
    assert context["store"].state(claims["lease_id"]) == "ACKED"
    with context["store"]._connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM terminal_operation_lease_completions"
            )
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_outbox"
        ).fetchone()[0] == 1


def test_prefetched_lease_completes_locally_while_transport_is_offline(
    tmp_path,
):
    def handler(call):
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            raise ConnectionError("offline")
        if call["method"] == "GET" and "/receipts/" in call["url"]:
            return FakeResponse(404, {"ok": False})
        raise AssertionError(call)

    coordinator, manager, session, resolved, scan_payload, _db_path = (
        _accepted_coordinator(tmp_path, handler)
    )
    prepared = _prepare_lease_transfer(
        coordinator, resolved, scan_payload, "operation-lease-test-01"
    )
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "RETRY_WAIT"
    assert result.operation_lease_state == "LOCAL_COMPLETED"
    assert manager.store.state(result.operation_lease_id) == "LOCAL_COMPLETED"
    assert [call["method"] for call in session.calls] == ["POST", "GET"]
    command = json.loads(coordinator.store.load(prepared.intent_id)["command_json"])
    evidence = command["payload"]["operation_lease"]
    artifact = manager.store.artifact(result.operation_lease_id)
    assert evidence == {
        "token": artifact["token"],
        "lease_id": artifact["lease_id"],
        "fence": artifact["fence"],
        "snapshot_hash": artifact["snapshot_hash"],
        "operation_completed_at": manager.store.completion(
            result.operation_lease_id
        )["operation_completed_at"],
    }


def test_lost_ack_restart_replays_same_command_and_records_one_receipt(
    tmp_path,
):
    posted = []
    committed_receipt = None
    mutation_count = 0

    def handler(call):
        nonlocal committed_receipt, mutation_count
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            posted.append(call)
            if len(posted) == 1:
                mutation_count += 1
                committed_receipt = _consumed_receipt(call["json"])
                raise ConnectionError("lost ack")
            assert call["json"] == posted[0]["json"]
            assert (
                call["headers"]["Idempotency-Key"]
                == posted[0]["headers"]["Idempotency-Key"]
            )
            return FakeResponse(
                200,
                {"ok": True, "status": "replayed", "data": committed_receipt},
            )
        if call["method"] == "GET" and "/receipts/" in call["url"]:
            return FakeResponse(404, {"ok": False})
        raise AssertionError(call)

    coordinator, manager, _session, resolved, scan_payload, db_path = (
        _accepted_coordinator(tmp_path, handler)
    )
    prepared = _prepare_lease_transfer(
        coordinator, resolved, scan_payload, "operation-lease-test-01"
    )
    waiting = coordinator.attempt(prepared.intent_id)
    assert waiting.status == "RETRY_WAIT"

    restarted_client, _restart_session = _work_group_client(handler)
    restarted_manager = OperationLeaseManager(
        OperationLeaseStore(db_path),
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )
    restarted = TransferSealCoordinator(
        TransferSealStore(db_path), restarted_client, restarted_manager
    )
    recovered = restarted.attempt(prepared.intent_id)

    assert recovered.status == "ACKED"
    assert recovered.operation_lease_state == "ACKED"
    assert mutation_count == 1
    assert len(posted) == 2
    assert posted[0]["json"]["payload"]["operation_lease"]["fence"] == 1
    with manager.store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_completions"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_receipts"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    ("status_code", "error_code"),
    [
        (409, "OPERATION_LEASE_DEVICE_MISMATCH"),
        (412, "OPERATION_LEASE_EXPECTED_VERSIONS_MISMATCH"),
    ],
)
def test_terminal_lease_conflict_preserves_local_evidence_for_review(
    tmp_path, status_code, error_code
):
    def handler(call):
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            return FakeResponse(
                status_code,
                {
                    "ok": False,
                    "retryable": False,
                    "committed": False,
                    "error": {"code": error_code, "message": "rejected"},
                },
            )
        raise AssertionError(call)

    coordinator, manager, _session, resolved, scan_payload, _db_path = (
        _accepted_coordinator(tmp_path, handler)
    )
    prepared = _prepare_lease_transfer(
        coordinator, resolved, scan_payload, "operation-lease-test-01"
    )
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.operation_lease_state == "OPERATOR_REVIEW"
    assert result.error_code == error_code
    assert manager.store.state(result.operation_lease_id) == "OPERATOR_REVIEW"
    with manager.store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_completions"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_outbox"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_reviews"
        ).fetchone()[0] == 1


def test_durable_lease_completion_failure_blocks_transfer_attempt(tmp_path):
    coordinator, manager, session, resolved, scan_payload, _db_path = (
        _accepted_coordinator(
            tmp_path,
            lambda call: (_ for _ in ()).throw(AssertionError(call)),
        )
    )
    with manager.store._connect() as connection:
        connection.executescript(
            """
            CREATE TRIGGER fail_terminal_lease_completion
            BEFORE INSERT ON terminal_operation_lease_completions
            BEGIN SELECT RAISE(ABORT, 'forced lease durability failure'); END;
            """
        )

    with pytest.raises(TransferSealError) as exc_info:
        _prepare_lease_transfer(
            coordinator, resolved, scan_payload, "operation-lease-test-01"
        )

    assert exc_info.value.code == "OPERATION_LEASE_LOCAL_DURABILITY_FAILED"
    assert session.calls == []
    assert manager.store.state("operation-lease-test-01") == "PREFETCHED"
    with manager.store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_outbox"
        ).fetchone()[0] == 0
