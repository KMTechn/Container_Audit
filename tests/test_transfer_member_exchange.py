from __future__ import annotations

import datetime
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from Container_Audit import ContainerAudit, ProductExchangeSession, TraySession
from transfer_member_exchange import (
    EXCHANGE_CAPABILITY_ID,
    GOOD_SOURCE_CONTRACT_VERSION,
    GOOD_SOURCE_RESOLVER_PATH,
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
    _empty_membership_hash,
)
from transfer_seal import LogisticsTransferClient, TransferSealError, membership_hash


SCOPE = "scope-exchange"
ITEM = "AAA2270730100"
IIN = "IIN-EXCHANGE"
TARGET = "PHS-TARGET"
SOURCE = "PHS-SOURCE"
OLD_1 = f"{ITEM}-OLD-1"
OLD_2 = f"{ITEM}-OLD-2"
NEW_1 = f"{ITEM}-NEW-1"
MASTER = f"PHS=2|BND={TARGET}|AUTH_SCOPE={SCOPE}|CLC={ITEM}|QT=2"
INPUT_TAG = "ITAG-PHS2-EXCHANGE"
INPUT_LABEL = "LBL-PHS2-EXCHANGE"
INPUT_LABEL_HASH = "a" * 64
INPUT_CORE_HASH = "b" * 64
INPUT_HASH_PREFIX = INPUT_LABEL_HASH[:16]
PHS2_MASTER = (
    f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={INPUT_TAG}|CLC={ITEM}|"
    f"LBL={INPUT_LABEL}|HSH={INPUT_HASH_PREFIX}"
)


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


def _phs2_target_projection():
    resolved = _target_projection()
    bundle = resolved["bundle"]
    bundle.update(
        {
            "external_label": PHS2_MASTER,
            "source_session_id": INPUT_TAG,
            "current_locations": ["PHS_GOOD"],
        }
    )
    for member in bundle["members"]:
        member.update(
            {
                "inbound_iin": IIN,
                "current_inbound_iin": IIN,
                "item_id": ITEM,
                "uom": "EA",
            }
        )
    resolved["input_tag"] = {
        "input_tag_id": INPUT_TAG,
        "label_id": INPUT_LABEL,
        "item_id": ITEM,
        "tag_core_hash": INPUT_CORE_HASH,
        "label_instance_hash": INPUT_LABEL_HASH,
        "hash_prefix": INPUT_HASH_PREFIX,
        "lifecycle": "INSPECTION_COMPLETED",
        "qr_payload": PHS2_MASTER,
    }
    return resolved


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


def _runtime(
    tmp_path,
    *,
    mutate_receipt=None,
    multi_member_source=False,
    target_response=None,
    replace_error=None,
):
    posted = []

    def handler(call):
        path = urlsplit(call["url"]).path
        if path.endswith("/capabilities"):
            return _Response(200, {"ok": True, "data": _capabilities()})
        if path.endswith("/bundles/resolve"):
            return _Response(
                200,
                {
                    "ok": True,
                    "data": target_response or _target_projection(),
                },
            )
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
            if replace_error is not None:
                raise replace_error
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


def test_phs2_preseal_exchange_revalidates_registry_qr_and_forwards_label_evidence(tmp_path):
    coordinator, posted, session = _runtime(
        tmp_path,
        target_response=_phs2_target_projection(),
    )
    prepared = coordinator.prepare(
        master_label=PHS2_MASTER,
        master_label_fields={
            "PHS": "2",
            "SRC": "KMTECH_INPUT_TAG",
            "ITG": INPUT_TAG,
            "CLC": ITEM,
            "LBL": INPUT_LABEL,
            "HSH": INPUT_HASH_PREFIX,
        },
        item_id=ITEM,
        operator="tester",
        old_barcodes=[OLD_1],
        new_barcodes=[NEW_1],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert len(posted) == 1
    resolve_call = next(
        call for call in session.calls if urlsplit(call["url"]).path.endswith("/bundles/resolve")
    )
    query = parse_qs(urlsplit(resolve_call["url"]).query)
    assert query["input_tag_id"] == [INPUT_TAG]
    assert query["input_tag_label_id"] == [INPUT_LABEL]
    assert query["input_tag_hash_prefix"] == [INPUT_HASH_PREFIX]
    assert query["item_id"] == [ITEM]


def test_phs2_preseal_exchange_fails_closed_when_registry_qr_drifts(tmp_path):
    target = _phs2_target_projection()
    target["input_tag"]["qr_payload"] = target["input_tag"]["qr_payload"].replace(
        INPUT_LABEL,
        "OTHER-LABEL",
    )
    coordinator, posted, _session = _runtime(tmp_path, target_response=target)
    prepared = coordinator.prepare(
        master_label=PHS2_MASTER,
        master_label_fields={
            "PHS": "2",
            "SRC": "KMTECH_INPUT_TAG",
            "ITG": INPUT_TAG,
            "CLC": ITEM,
            "LBL": INPUT_LABEL,
            "HSH": INPUT_HASH_PREFIX,
        },
        item_id=ITEM,
        operator="tester",
        old_barcodes=[OLD_1],
        new_barcodes=[NEW_1],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "PHS2_REGISTRY_IDENTITY_MISMATCH"
    assert posted == []


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


@pytest.mark.parametrize("failure_kind", ("http-500", "transport"))
def test_rotation_lost_ack_never_uses_generic_receipt_get(failure_kind):
    def handler(call):
        if call["method"] != "POST":
            pytest.fail("rotation recovery must replay the exact POST, not receipt GET")
        if failure_kind == "transport":
            raise ConnectionError("lost response after commit")
        return _Response(
            500,
            {
                "ok": False,
                "committed": True,
                "retryable": True,
                "error": {"code": "ACK_LOST", "message": "lost response"},
            },
        )

    session = _Session(handler)
    client = LogisticsTransferClient(
        "https://logistics.test",
        "token",
        "host-1",
        device_id="device-1",
        session=session,
    )
    command = {
        "authority_scope_id": SCOPE,
        "idempotency_key": "rotation-lost-ack",
        "payload": {
            "target_bundle_id": TARGET,
            "operation_lease_rotation": {
                "contract_version": "terminal-operation-lease-rotation-request-v1"
            },
        },
    }

    with pytest.raises(TransferSealError):
        client.replace_bundle_members(command)

    assert [call["method"] for call in session.calls] == ["POST"]


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


def test_preflight_review_without_central_command_can_be_cancelled(
    tmp_path, monkeypatch
):
    coordinator, posted, _session = _runtime(tmp_path, multi_member_source=True)
    result = coordinator.attempt(_prepare(coordinator).intent_id)
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(master_label_code=MASTER)
    app.transfer_member_exchange_coordinator = coordinator
    app._active_transfer_exchange_intent_id = result.intent_id
    app.current_exchange_session = ProductExchangeSession()
    app.exchange_dialog = None
    app._update_action_button_states = lambda: None
    errors = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror",
        lambda *args, **kwargs: errors.append(args),
    )

    assert result.status == "OPERATOR_REVIEW"
    assert result.idempotency_key == ""
    assert posted == []
    assert coordinator.store.blocking_rows(master_label=MASTER)
    assert app._cancel_exchange(reason="operator_cancel_after_preflight") is True
    assert errors == []
    assert coordinator.store.blocking_rows(master_label=MASTER) == []
    assert coordinator.drain_pending() == []
    with coordinator.store._connect() as conn:
        dismissal = conn.execute(
            """SELECT reason FROM transfer_member_exchange_dismissals
                WHERE intent_id=?""",
            (result.intent_id,),
        ).fetchone()
    assert dismissal["reason"] == "operator_cancel_after_preflight"
    assert coordinator.store.load(result.intent_id)["status"] == "OPERATOR_REVIEW"


class _NeverCentralClient:
    def __init__(self):
        self.calls = []

    def get_capabilities(self, *args, **kwargs):
        self.calls.append(("get_capabilities", args, kwargs))
        raise AssertionError("dismissed preflight must not query the central server")

    def resolve_source(self, *args, **kwargs):
        self.calls.append(("resolve_source", args, kwargs))
        raise AssertionError("dismissed preflight must not query the central server")

    def resolve_good_source(self, *args, **kwargs):
        self.calls.append(("resolve_good_source", args, kwargs))
        raise AssertionError("dismissed preflight must not query the central server")

    def get_receipt(self, *args, **kwargs):
        self.calls.append(("get_receipt", args, kwargs))
        raise AssertionError("explicit preflight retry must not query the central server")

    def replace_bundle_members(self, *args, **kwargs):
        self.calls.append(("replace_bundle_members", args, kwargs))
        raise AssertionError("explicit preflight retry must not write the central server")


def _explicit_retry_app(coordinator):
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = None
    app.current_tray = TraySession(master_label_code=MASTER)
    app.transfer_member_exchange_coordinator = coordinator
    app._operator_review_blocks_mutation = lambda: False
    app._render_warning_state = lambda: None
    app._exact_transfer_exchange_blocked = lambda: True
    app._block_unsafe_exact_exchange = lambda: True
    return app


def test_restart_explicit_retry_dismisses_only_preflight_review_without_central_io(
    tmp_path, monkeypatch
):
    coordinator, posted, _session = _runtime(tmp_path, multi_member_source=True)
    result = coordinator.attempt(_prepare(coordinator).intent_id)
    central = _NeverCentralClient()
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path),
        central,
    )
    app = _explicit_retry_app(restarted)
    warnings = []
    errors = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showwarning",
        lambda *args, **kwargs: warnings.append(args),
    )
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror",
        lambda *args, **kwargs: errors.append(args),
    )

    app.show_exchange_dialog()

    assert result.status == "OPERATOR_REVIEW"
    assert posted == []
    assert central.calls == []
    assert errors == []
    assert warnings and warnings[0][0] == "교체 대상 없음"
    assert restarted.store.blocking_rows(master_label=MASTER) == []
    with restarted.store._connect() as conn:
        dismissal = conn.execute(
            """SELECT reason FROM transfer_member_exchange_dismissals
                WHERE intent_id=?""",
            (result.intent_id,),
        ).fetchone()
    assert dismissal["reason"] == "operator_retry_after_preflight"


def test_restart_explicit_retry_keeps_durable_review_locked_without_central_io(
    tmp_path, monkeypatch
):
    coordinator, _posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)
    with coordinator.store._connect() as conn:
        conn.execute(
            """UPDATE transfer_member_exchange_intents
                  SET status='OPERATOR_REVIEW',command_id='durable-command',
                      command_json='{}',command_hash='durable-hash'
                WHERE intent_id=?""",
            (prepared.intent_id,),
        )
        conn.execute(
            """INSERT INTO transfer_member_exchange_dismissals (
                   intent_id,reason,dismissed_at
               ) VALUES (?,?,?)""",
            (prepared.intent_id, "legacy_race_tombstone", "2026-07-28T00:00:00Z"),
        )
        conn.commit()
    central = _NeverCentralClient()
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path),
        central,
    )
    app = _explicit_retry_app(restarted)
    errors = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror",
        lambda *args, **kwargs: errors.append(args),
    )

    app.show_exchange_dialog()

    assert central.calls == []
    assert restarted.store.blocking_rows(master_label=MASTER)
    with restarted.store._connect() as conn:
        dismissal_count = conn.execute(
            """SELECT COUNT(*) FROM transfer_member_exchange_dismissals
                WHERE intent_id=?""",
            (prepared.intent_id,),
        ).fetchone()[0]
    assert dismissal_count == 1
    assert errors and errors[0][0] == "중앙 제품 교체 확인 필요"


def test_restart_explicit_retry_keeps_invalid_command_ready_attempt_locked(
    tmp_path, monkeypatch
):
    coordinator, _posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)
    with coordinator.store._connect() as conn:
        conn.execute(
            """UPDATE transfer_member_exchange_intents
                  SET status='COMMAND_READY'
                WHERE intent_id=?""",
            (prepared.intent_id,),
        )
        conn.commit()
    central = _NeverCentralClient()
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path),
        central,
    )
    app = _explicit_retry_app(restarted)
    errors = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror",
        lambda *args, **kwargs: errors.append(args),
    )

    app.show_exchange_dialog()

    assert central.calls == []
    assert restarted.store.blocking_rows(master_label=MASTER)
    assert errors and errors[0][0] == "중앙 제품 교체 응답 대기"


def test_restart_explicit_retry_dismissal_failure_keeps_preflight_lock(
    tmp_path, monkeypatch
):
    coordinator, _posted, _session = _runtime(tmp_path, multi_member_source=True)
    result = coordinator.attempt(_prepare(coordinator).intent_id)
    central = _NeverCentralClient()
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path),
        central,
    )
    app = _explicit_retry_app(restarted)
    errors = []

    def fail_dismissal(*_args, **_kwargs):
        raise ValueError("simulated guarded dismissal failure")

    monkeypatch.setattr(
        restarted.store,
        "dismiss_without_durable_command",
        fail_dismissal,
    )
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror",
        lambda *args, **kwargs: errors.append(args),
    )

    app.show_exchange_dialog()

    assert central.calls == []
    assert restarted.store.blocking_rows(master_label=MASTER)
    assert errors and errors[0][0] == "교체 다시 시작 실패"
    with restarted.store._connect() as conn:
        dismissal_count = conn.execute(
            """SELECT COUNT(*) FROM transfer_member_exchange_dismissals
                WHERE intent_id=?""",
            (result.intent_id,),
        ).fetchone()[0]
    assert dismissal_count == 0


def test_dismissed_prepared_attempt_is_fenced_before_central_read_or_write(tmp_path):
    coordinator, _posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)
    coordinator.store.dismiss_without_durable_command(
        prepared.intent_id,
        "operator_retry_after_preflight",
    )
    central = _NeverCentralClient()
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path),
        central,
    )

    result = restarted.attempt(prepared.intent_id)

    assert result.status == "PREPARED"
    assert result.idempotency_key == ""
    assert central.calls == []
    assert restarted.store.blocking_rows(master_label=MASTER) == []


def test_dismissal_racing_after_preflight_fences_command_binding_and_post(
    tmp_path, monkeypatch
):
    coordinator, posted, _session = _runtime(tmp_path)
    prepared = _prepare(coordinator)
    original_bind = coordinator.store.bind_command

    def dismiss_then_bind(intent_id, command):
        coordinator.store.dismiss_without_durable_command(
            intent_id,
            "operator_retry_after_preflight",
        )
        return original_bind(intent_id, command)

    monkeypatch.setattr(coordinator.store, "bind_command", dismiss_then_bind)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "RETRY_WAIT"
    assert result.idempotency_key == ""
    assert posted == []
    row = coordinator.store.load(prepared.intent_id)
    assert row["command_id"] is None
    assert row["command_json"] is None
    assert row["receipt_json"] is None
    assert coordinator.store.blocking_rows(master_label=MASTER) == []


def test_same_key_prepare_revives_dismissed_preflight_and_uncertain_post_stays_blocked(
    tmp_path
):
    first, first_posts, _session = _runtime(tmp_path, multi_member_source=True)
    reviewed = first.attempt(_prepare(first).intent_id)
    first.store.dismiss_without_durable_command(
        reviewed.intent_id,
        "operator_retry_after_preflight",
    )
    restarted, restarted_posts, _session = _runtime(
        tmp_path,
        replace_error=TimeoutError("response lost after possible commit"),
    )

    revived = _prepare(restarted)
    result = restarted.attempt(revived.intent_id)

    assert first_posts == []
    assert revived.status == "PREPARED"
    assert result.status == "RETRY_WAIT"
    assert result.idempotency_key
    assert len(restarted_posts) == 1
    assert restarted.store.blocking_rows(master_label=MASTER)
    assert restarted.store.pending_ids() == [reviewed.intent_id]
    with restarted.store._connect() as conn:
        dismissal_count = conn.execute(
            """SELECT COUNT(*) FROM transfer_member_exchange_dismissals
                WHERE intent_id=?""",
            (reviewed.intent_id,),
        ).fetchone()[0]
    assert dismissal_count == 0


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
