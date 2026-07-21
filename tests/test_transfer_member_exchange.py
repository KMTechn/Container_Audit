from __future__ import annotations

import datetime
import json
from urllib.parse import parse_qs, urlsplit

from Container_Audit import ContainerAudit, TraySession
from transfer_member_exchange import (
    EXCHANGE_CAPABILITY_ID,
    GOOD_SOURCE_CONTRACT_VERSION,
    GOOD_SOURCE_RESOLVER_PATH,
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
    _empty_membership_hash,
)
from transfer_seal import LogisticsTransferClient, membership_hash


SCOPE = "scope-exchange"
ITEM = "AAA2270730100"
IIN = "IIN-EXCHANGE"
TARGET = "PHS-TARGET"
SOURCE = "PHS-SOURCE"
OLD_1 = f"{ITEM}-OLD-1"
OLD_2 = f"{ITEM}-OLD-2"
NEW_1 = f"{ITEM}-NEW-1"
MASTER = f"PHS=2|BND={TARGET}|AUTH_SCOPE={SCOPE}|CLC={ITEM}|QT=2"


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _NonJsonResponse(_Response):
    def json(self):
        raise ValueError("non-JSON 500 body")


class _Session:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kwargs):
        call = {"method": method, "url": url, **kwargs}
        self.calls.append(call)
        return self.handler(call)


def _capabilities():
    capability = {
        "enabled": True,
        "command_type": "REPLACE_BUNDLE_MEMBERS",
        "resolver_contract_version": GOOD_SOURCE_CONTRACT_VERSION,
        "resolver_path": GOOD_SOURCE_RESOLVER_PATH,
        "resolver_aliases": ["/logistics/api/v1/good-units/resolve"],
        "max_pairs": 2,
        "atomic": True,
        "two_bundle_cas": True,
        "sealed_transfer_package": False,
        "replacement_source_bundle_cardinality": "EXACTLY_ONE_ACTIVE_MEMBER",
        "multi_member_source_policy": "REJECT_STALE_PHYSICAL_LABEL",
        "multi_member_source_error_code": "REPLACEMENT_SOURCE_NOT_SINGLETON",
        "target_label_action": "RETAIN_IDENTITY_LABEL",
        "target_label_identity_remains_valid": True,
        "target_label_membership_bound": False,
    }
    return {
        "contract_version": "logistics-v1",
        "capability_ids": [EXCHANGE_CAPABILITY_ID],
        "capabilities": {EXCHANGE_CAPABILITY_ID: capability},
    }


def _target_projection():
    member_ids = ["unit-old-1", "unit-old-2"]
    barcodes = [OLD_1, OLD_2]
    return {
        "candidate_count": 1,
        "bundle": {
            "authority_scope_id": SCOPE,
            "authority_epoch": 4,
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 2,
            "bundle_id": TARGET,
            "bundle_role": "TRANSFER_SOURCE",
            "bundle_type": "PHS",
            "bundle_state": "AVAILABLE",
            "item_id": ITEM,
            "uom": "EA",
            "source_iin": IIN,
            "current_location": "PHS_GOOD",
            "entity_version": 5,
            "member_ids": member_ids,
            "member_count": 2,
            "membership_hash": membership_hash(member_ids),
            "barcode_member_count": 2,
            "barcode_membership_hash": membership_hash(barcodes),
            "members": [
                {
                    "unit_id": unit_id,
                    "normalized_barcode": barcode,
                    "unit_state": "CONSUMED",
                    "location_code": "PHS_GOOD",
                }
                for unit_id, barcode in zip(member_ids, barcodes, strict=True)
            ],
        },
    }


def _good_projection(*, singleton=True):
    member_ids = ["unit-new-1"]
    members = [
        {
            "unit_id": "unit-new-1",
            "normalized_barcode": NEW_1,
            "inbound_iin": IIN,
            "item_id": ITEM,
            "uom": "EA",
            "unit_state": "CONSUMED",
            "location_code": "PHS_GOOD",
        }
    ]
    if not singleton:
        member_ids.append("unit-source-remainder")
        members.append(
            {
                "unit_id": "unit-source-remainder",
                "normalized_barcode": f"{ITEM}-SOURCE-REMAINDER",
                "inbound_iin": IIN,
                "item_id": ITEM,
                "uom": "EA",
                "unit_state": "CONSUMED",
                "location_code": "PHS_GOOD",
            }
        )
    source_bundle = {
        "bundle_id": SOURCE,
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "inbound_iin": IIN,
        "item_id": ITEM,
        "uom": "EA",
        "current_location": "PHS_GOOD",
        "entity_version": 7,
        "member_ids": member_ids,
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
        "members": members,
    }
    return {
        "contract_version": GOOD_SOURCE_CONTRACT_VERSION,
        "candidate_count": 1,
        "authority_scope_id": SCOPE,
        "authority_epoch": 4,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 2,
        "unit_id": "unit-new-1",
        "normalized_barcode": NEW_1,
        "inbound_iin": IIN,
        "item_id": ITEM,
        "uom": "EA",
        "current_location": "PHS_GOOD",
        "unit": {
            "unit_id": "unit-new-1",
            "normalized_barcode": NEW_1,
            "inbound_iin": IIN,
            "item_id": ITEM,
            "uom": "EA",
            "state": "CONSUMED",
            "current_location": "PHS_GOOD",
            "entity_version": 3,
        },
        "source_bundle_id": SOURCE,
        "source_bundle_entity_version": 7,
        "source_bundle": source_bundle,
        "replacement_evidence": {
            "new_unit_id": "unit-new-1",
            "new_source_bundle_id": SOURCE,
            "expected_source_bundle_version": 7,
            "source_member_ids": member_ids,
            "source_membership_hash": membership_hash(member_ids),
            "inbound_iin": IIN,
            "item_id": ITEM,
            "uom": "EA",
        },
    }


def _receipt(command):
    payload = command["payload"]
    members = ["unit-new-1", "unit-old-2"]
    barcodes = [NEW_1, OLD_2]
    return {
        "receipt_id": "receipt-exchange-1",
        "contract_version": "logistics-v1",
        "command_type": "REPLACE_BUNDLE_MEMBERS",
        "status": "COMMITTED",
        "authority_scope_id": SCOPE,
        "authority_epoch": 4,
        "resolved_ledger_plane": "AUTHORITATIVE",
        "resolved_plane_epoch": 2,
        "committed_at": "2026-07-21T00:00:00Z",
        "event_ids": ["event-exchange-1"],
        "outbox_ids": ["outbox-exchange-1"],
        "entity_versions": {
            f"bundle:{TARGET}": 6,
            f"bundle:{SOURCE}": 8,
            f"bundle:{payload['damage_bundle_id']}": 1,
        },
        "data": {
            "idempotency_key": command["idempotency_key"],
            "target_bundle_id": TARGET,
            "target_bundle_type": "PHS",
            "target_location": "PHS_GOOD",
            "member_ids": members,
            "members": [
                {"unit_id": "unit-new-1", "normalized_barcode": NEW_1},
                {"unit_id": "unit-old-2", "normalized_barcode": OLD_2},
            ],
            "member_count": 2,
            "membership_hash": membership_hash(members),
            "normalized_barcodes": barcodes,
            "barcode_membership_hash": membership_hash(barcodes),
            "pairs": payload["pairs"],
            "pair_count": 1,
            "sources": [
                {
                    "source_bundle_id": SOURCE,
                    "source_version_before": 7,
                    "source_version_after": 8,
                    "source_member_ids_before": ["unit-new-1"],
                    "source_members_before": [
                        {"unit_id": "unit-new-1", "normalized_barcode": NEW_1}
                    ],
                    "source_member_count_before": 1,
                    "source_membership_hash_before": membership_hash(["unit-new-1"]),
                    "source_normalized_barcodes_before": [NEW_1],
                    "source_barcode_membership_hash_before": membership_hash([NEW_1]),
                    "selected_member_ids": ["unit-new-1"],
                    "selected_members": [
                        {"unit_id": "unit-new-1", "normalized_barcode": NEW_1}
                    ],
                    "remainder_member_ids": [],
                    "remainder_members": [],
                    "remainder_member_count": 0,
                    "remainder_membership_hash": _empty_membership_hash(),
                    "remainder_normalized_barcodes": [],
                    "remainder_barcode_membership_hash": _empty_membership_hash(),
                    "source_bundle_state_after": "CONSUMED",
                }
            ],
            "damage_bundle_id": payload["damage_bundle_id"],
            "damage_member_ids": ["unit-old-1"],
            "damage_members": [
                {"unit_id": "unit-old-1", "normalized_barcode": OLD_1}
            ],
            "damage_membership_hash": membership_hash(["unit-old-1"]),
            "damage_location": "PROCESS_DAMAGE_HOLD",
            "movement_ids": ["movement-old", "movement-new"],
            "requires_reseal": False,
            "target_label_action": "RETAIN_IDENTITY_LABEL",
            "target_label_identity_remains_valid": True,
            "target_label_membership_bound": False,
            "replacement_source_bundle_cardinality": "EXACTLY_ONE_ACTIVE_MEMBER",
            "multi_member_source_policy": "REJECT_STALE_PHYSICAL_LABEL",
            "atomic": True,
        },
    }


def _runtime(tmp_path, *, mutate_receipt=None, multi_member_source=False):
    posted = []

    def handler(call):
        path = urlsplit(call["url"]).path
        if path.endswith("/capabilities"):
            return _Response(200, {"ok": True, "data": _capabilities()})
        if path.endswith("/bundles/resolve"):
            return _Response(200, {"ok": True, "data": _target_projection()})
        if path.endswith("/replacements/good-source/resolve"):
            query = parse_qs(urlsplit(call["url"]).query)
            assert query == {"authority_scope_id": [SCOPE], "barcode": [NEW_1]}
            return _Response(
                200,
                {
                    "ok": True,
                    "data": _good_projection(singleton=not multi_member_source),
                },
            )
        if path.endswith(f"/bundles/{TARGET}/members/replace"):
            command = call["json"]
            posted.append(command)
            receipt = _receipt(command)
            if mutate_receipt is not None:
                mutate_receipt(receipt)
            return _Response(200, {"ok": True, "data": receipt})
        raise AssertionError(path)

    session = _Session(handler)
    client = LogisticsTransferClient(
        "https://logistics.test",
        "token",
        "host-1",
        device_id="device-1",
        session=session,
    )
    store = TransferMemberExchangeStore(tmp_path / "exchange.db")
    return TransferMemberExchangeCoordinator(store, client), posted, session


def _prepare(coordinator):
    return coordinator.prepare(
        master_label=MASTER,
        master_label_fields={"BND": TARGET, "AUTH_SCOPE": SCOPE, "CLC": ITEM},
        item_id=ITEM,
        operator="tester",
        old_barcodes=[OLD_1],
        new_barcodes=[NEW_1],
    )


def test_preseal_exchange_posts_one_atomic_multi_bundle_cas_and_persists_receipt(tmp_path):
    coordinator, posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert result.local_apply_status == "PENDING"
    assert result.target_bundle_id == TARGET
    assert result.receipt_id == "receipt-exchange-1"
    assert len(posted) == 1
    command = posted[0]
    assert command["command_type"] == "REPLACE_BUNDLE_MEMBERS"
    assert command["expected_versions"] == {
        f"bundle:{TARGET}": 5,
        f"bundle:{SOURCE}": 7,
    }
    assert command["payload"]["pairs"] == [
        {
            "old_unit_id": "unit-old-1",
            "new_unit_id": "unit-new-1",
            "new_source_bundle_id": SOURCE,
        }
    ]
    reopened = TransferMemberExchangeStore(tmp_path / "exchange.db").load(
        prepared.intent_id
    )
    assert reopened["status"] == "ACKED"
    assert reopened["command_json"] == json.dumps(
        command, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def test_receipt_mismatch_is_operator_review_and_never_locally_applied(tmp_path):
    coordinator, _posted, _session = _runtime(
        tmp_path,
        mutate_receipt=lambda receipt: receipt["data"].update(
            {"member_ids": ["unit-old-1", "unit-old-2"]}
        ),
    )
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"
    assert coordinator.pending_local_attempts(master_label=MASTER) == []
    assert coordinator.store.blocking_rows(master_label=MASTER)


def test_non_json_500_recovers_committed_receipt_without_duplicate_post(tmp_path):
    posted = []
    receipt_gets = []
    committed = {}

    def handler(call):
        path = urlsplit(call["url"]).path
        if path.endswith("/capabilities"):
            return _Response(200, {"ok": True, "data": _capabilities()})
        if path.endswith("/bundles/resolve"):
            return _Response(200, {"ok": True, "data": _target_projection()})
        if path.endswith("/replacements/good-source/resolve"):
            return _Response(200, {"ok": True, "data": _good_projection()})
        if path.endswith(f"/bundles/{TARGET}/members/replace"):
            posted.append(call["json"])
            committed["receipt"] = _receipt(call["json"])
            return _NonJsonResponse(500, None)
        if "/receipts/" in path:
            receipt_gets.append(path)
            return _Response(200, {"ok": True, "data": committed["receipt"]})
        raise AssertionError(path)

    client = LogisticsTransferClient(
        "https://logistics.test",
        "token",
        "host-1",
        device_id="device-1",
        session=_Session(handler),
    )
    coordinator = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(tmp_path / "lost-500.db"), client
    )

    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert result.status == "ACKED"
    assert len(posted) == 1
    assert len(receipt_gets) == 1


def test_restart_recovers_saved_exchange_receipt_before_reposting(tmp_path):
    posted = []
    committed = {}

    def first_handler(call):
        path = urlsplit(call["url"]).path
        if path.endswith("/capabilities"):
            return _Response(200, {"ok": True, "data": _capabilities()})
        if path.endswith("/bundles/resolve"):
            return _Response(200, {"ok": True, "data": _target_projection()})
        if path.endswith("/replacements/good-source/resolve"):
            return _Response(200, {"ok": True, "data": _good_projection()})
        if path.endswith(f"/bundles/{TARGET}/members/replace"):
            posted.append(call["json"])
            committed["receipt"] = _receipt(call["json"])
            return _NonJsonResponse(500, None)
        if "/receipts/" in path:
            return _Response(
                404,
                {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}},
            )
        raise AssertionError(path)

    db_path = tmp_path / "restart-lost-500.db"
    first_client = LogisticsTransferClient(
        "https://logistics.test",
        "token",
        "host-1",
        device_id="device-1",
        session=_Session(first_handler),
    )
    first = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(db_path), first_client
    )
    retry = first.attempt(_prepare(first).intent_id)

    assert retry.status == "RETRY_WAIT"
    assert len(posted) == 1
    receipt_gets = []

    def recovery_handler(call):
        path = urlsplit(call["url"]).path
        if "/receipts/" in path:
            receipt_gets.append(path)
            return _Response(200, {"ok": True, "data": committed["receipt"]})
        if call["method"] == "POST":
            raise AssertionError("restart receipt recovery must not POST again")
        raise AssertionError(path)

    recovery_client = LogisticsTransferClient(
        "https://logistics.test",
        "token",
        "host-1",
        device_id="device-1",
        session=_Session(recovery_handler),
    )
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(db_path), recovery_client
    )
    recovered = restarted.drain_pending()

    assert [attempt.status for attempt in recovered] == ["ACKED"]
    assert len(receipt_gets) == 1


def test_invalid_receipt_remains_blocked_on_restart_and_never_reposts(
    tmp_path, monkeypatch
):
    coordinator, posted, _session = _runtime(
        tmp_path,
        mutate_receipt=lambda receipt: receipt["data"].update(
            {"member_ids": ["unit-old-1", "unit-old-2"]}
        ),
    )
    review = coordinator.attempt(_prepare(coordinator).intent_id)
    command = json.loads(coordinator.store.load(review.intent_id)["command_json"])
    invalid_receipt = _receipt(command)
    invalid_receipt["data"]["member_ids"] = ["unit-old-1", "unit-old-2"]

    class ReceiptOnlyClient:
        def get_receipt(self, scope_id, idempotency_key):
            assert scope_id == SCOPE
            assert idempotency_key == command["idempotency_key"]
            return invalid_receipt

        def replace_bundle_members(self, _command):
            raise AssertionError("operator review must never repost")

    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path), ReceiptOnlyClient()
    )
    recovered = restarted.drain_pending()

    assert len(posted) == 1
    assert [attempt.status for attempt in recovered] == ["OPERATOR_REVIEW"]
    assert restarted.store.blocking_rows(master_label=MASTER)
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(master_label_code=MASTER)
    app.transfer_member_exchange_coordinator = restarted
    app._active_transfer_exchange_intent_id = ""
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror", lambda *args, **kwargs: None
    )
    assert app._transfer_member_exchange_blocks_local_action("다음 스캔") is True
    assert app._cancel_exchange() is False


def test_receipt_missing_command_idempotency_is_operator_review(tmp_path):
    coordinator, _posted, _session = _runtime(
        tmp_path,
        mutate_receipt=lambda receipt: receipt["data"].pop("idempotency_key"),
    )

    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_multi_member_donor_is_rejected_before_replace_command(tmp_path):
    coordinator, posted, _session = _runtime(tmp_path, multi_member_source=True)
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "REPLACEMENT_SOURCE_NOT_SINGLETON"
    assert posted == []


def test_target_identity_label_must_be_explicitly_retained_by_receipt(tmp_path):
    coordinator, posted, _session = _runtime(
        tmp_path,
        mutate_receipt=lambda receipt: receipt["data"].update(
            {"target_label_identity_remains_valid": False}
        ),
    )

    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert len(posted) == 1
    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_singleton_donor_must_be_consumed_in_exact_receipt(tmp_path):
    coordinator, posted, _session = _runtime(
        tmp_path,
        mutate_receipt=lambda receipt: receipt["data"]["sources"][0].update(
            {"source_bundle_state_after": "AVAILABLE"}
        ),
    )

    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert len(posted) == 1
    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_local_tray_application_is_all_or_none_and_marks_durable_local_receipt(tmp_path):
    coordinator, _posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)
    attempt = coordinator.attempt(prepared.intent_id)
    app = ContainerAudit.__new__(ContainerAudit)
    scan_time = datetime.datetime(2026, 7, 21, 10, 0, 0)
    app.current_tray = TraySession(
        master_label_code=MASTER,
        item_code=ITEM,
        item_name="테스트",
        scanned_barcodes=[OLD_1, OLD_2],
        scan_times=[scan_time, scan_time],
        tray_size=2,
    )
    app._active_transfer_exchange_master_label = MASTER
    app._transfer_member_exchange_runtime = lambda: coordinator
    saved_snapshots = []
    events = []
    app._save_current_tray_state = lambda: saved_snapshots.append(
        list(app.current_tray.scanned_barcodes)
    ) or True
    app._log_event = lambda event, detail=None, synchronous=False: events.append(
        (event, detail, synchronous)
    ) or True
    app._redraw_active_tray_scans = lambda: None

    assert app._apply_acked_member_exchange(attempt) is True
    assert app.current_tray.scanned_barcodes == [NEW_1, OLD_2]
    assert saved_snapshots == [[NEW_1, OLD_2]]
    assert events[0][0] == "PRODUCT_EXCHANGE_COMPLETED"
    assert events[0][1]["central_atomic"] is True
    row = coordinator.store.load(prepared.intent_id)
    assert row["local_apply_status"] == "APPLIED"


def test_local_save_failure_keeps_original_tray_and_recoverable_ack(tmp_path):
    coordinator, _posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)
    attempt = coordinator.attempt(prepared.intent_id)
    app = ContainerAudit.__new__(ContainerAudit)
    scan_time = datetime.datetime(2026, 7, 21, 10, 0, 0)
    app.current_tray = TraySession(
        master_label_code=MASTER,
        item_code=ITEM,
        scanned_barcodes=[OLD_1, OLD_2],
        scan_times=[scan_time, scan_time],
        tray_size=2,
    )
    app._active_transfer_exchange_master_label = MASTER
    app._transfer_member_exchange_runtime = lambda: coordinator
    app._save_current_tray_state = lambda: False

    assert app._apply_acked_member_exchange(attempt) is False
    assert app.current_tray.scanned_barcodes == [OLD_1, OLD_2]
    assert coordinator.store.load(prepared.intent_id)["local_apply_status"] == "PENDING"


def test_exchange_prepare_rejects_more_than_two_pairs_before_network(tmp_path):
    coordinator, _posted, session = _runtime(tmp_path)

    try:
        coordinator.prepare(
            master_label=MASTER,
            master_label_fields={"BND": TARGET, "AUTH_SCOPE": SCOPE, "CLC": ITEM},
            item_id=ITEM,
            operator="tester",
            old_barcodes=[OLD_1, OLD_2, f"{ITEM}-OLD-3"],
            new_barcodes=[NEW_1, f"{ITEM}-NEW-2", f"{ITEM}-NEW-3"],
        )
    except ValueError as exc:
        assert "one or two" in str(exc)
    else:
        raise AssertionError("three-pair exchange must fail")
    assert session.calls == []
