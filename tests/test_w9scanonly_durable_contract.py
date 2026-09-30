"""Contract v1.2: durable scanner completion and unchanged exact receipt proof."""
import copy
import json
import sqlite3
import threading
from types import SimpleNamespace
from label_qr import parse_new_format_qr
import pytest
from transfer_seal import TransferSealCoordinator, TransferSealStore, TransferSealError, source_identity_from_label, membership_hash, validate_compact_phs2_preflight, _sha256
from tests.test_phs2_master_preflight import _resolved, COMPACT_QR
from tests.test_transfer_seal import _resolved_work_group_phs2, _compact_phs2_qr, _compact_phs2_fields, _work_group_receipt
from transfer_member_exchange import TransferMemberExchangeCoordinator, TransferMemberExchangeStore
from terminal_operation_lease import OperationLeaseStore, OperationLeaseManager, PinnedOperationLeaseKeyring


def test_seven_field_quantity_matches_issued_label_even_after_membership_changes():
    resolved = _resolved(count=2)
    seven = COMPACT_QR + "|QT=3"
    resolved["phs_work_group"]["scan_payload"] = seven
    label = resolved["phs_label_resolution"]["scanned_label"]
    label["qr_payload"] = seven
    label["scan_payload"] = seven
    for label in resolved["phs_label_resolution"]["effective_labels"]:
        label["qr_payload"] = seven
        label["scan_payload"] = seven
    source = resolved["work_group_source"]
    topology = _sha256({"phs_work_group":resolved["phs_work_group"],
        "source_bundles":source["source_bundles"], "remainder_cover_groups":source.get("remainder_cover_groups",[]),
        "source_iin":source["source_iin"], "barcode_membership_hash":source["barcode_membership_hash"],
        "transfer_bundle_id":source["transfer_bundle_id"]})
    source["topology_hash"] = resolved["topology_hash"] = topology
    assert validate_compact_phs2_preflight(parse_new_format_qr(seven), resolved).member_count == 2
    with pytest.raises(TransferSealError, match="QT"):
        validate_compact_phs2_preflight(parse_new_format_qr(COMPACT_QR + "|QT=4"), resolved)


@pytest.mark.parametrize("defect", [None, "pair", "barcode_hash", "scope", "version", "label", "source_kind"])
def test_scan_registered_good_receipt_keeps_exact_target_proof(tmp_path, defect):
    resolved = _resolved_work_group_phs2(mode="merge")
    source = resolved["work_group_source"]
    old = source["members"][0]["normalized_barcode"]
    new = source["item_id"] + "-NEW-GOOD"
    store = TransferMemberExchangeStore(tmp_path / "exchange.db", owner_thread_id_provider=threading.get_ident)
    client = SimpleNamespace(resolve_source=lambda identity: resolved, authority_epoch=7,
        assert_authority=lambda *a, **k: None)
    coordinator = TransferMemberExchangeCoordinator(store, client, owner_thread_id_provider=threading.get_ident)
    row = store.prepare(master_label=resolved["phs_work_group"]["scan_payload"],
        source_identity=source_identity_from_label(parse_new_format_qr(resolved["phs_work_group"]["scan_payload"])),
        item_id=source["item_id"], operator="fixture", old_barcodes=[old], new_barcodes=[new],
        scan_context={"exchanged_at":"2026-09-30T12:00:00+09:00", "predecessor_keys":[]})
    command = coordinator._build_command(row)
    assert command["payload"]["pairs"] == [{"old_barcode":old, "new_barcode":new}]
    assert command["payload"]["replacement_mode"] == "SCAN_REGISTER_GOOD"
    assert store.pending_ids() == []
    before = command["client_exact_evidence"]["target"]
    old_id = next(member["unit_id"] for member in before["members"] if member["normalized_barcode"] == old)
    members = [dict(member) for member in before["members"] if member["unit_id"] != old_id]
    members.append({"unit_id":"new-registered", "normalized_barcode":new})
    ids = sorted(member["unit_id"] for member in members)
    barcodes = sorted(member["normalized_barcode"] for member in members)
    receipt = {"status":"COMMITTED", "contract_version":command["contract_version"],
        "command_type":command["command_type"], "authority_scope_id":command["authority_scope_id"],
        "authority_epoch":command["authority_epoch"], "resolved_ledger_plane":command["ledger_plane"],
        "resolved_plane_epoch":command["plane_epoch"], "receipt_id":"receipt-new-good",
        "committed_at":"2026-09-30T03:00:00Z", "event_ids":["event"], "outbox_ids":["outbox"],
        "entity_versions":{key:value+1 for key,value in command["expected_versions"].items()},
        "source_membership_changes":[], "data":{
        "idempotency_key":command["idempotency_key"], "target_bundle_id":before["bundle_id"],
        "target_bundle_type":"PHS", "target_location":"PHS_GOOD", "atomic":True,
        "members":members, "member_ids":ids, "member_count":len(ids), "membership_hash":membership_hash(ids),
        "normalized_barcodes":barcodes, "barcode_membership_hash":membership_hash(barcodes), "pair_count":1,
        "pairs":[{"old_unit_id":old_id,"new_unit_id":"new-registered", "old_barcode":old, "new_barcode":new,
            "new_source_kind":"EXCHANGE_GOOD_REGISTERED", "new_source_bundle_id":None}],
        "damage_bundle_id":"damage", "damage_member_ids":[old_id],
        "damage_members":[{"unit_id":old_id,"normalized_barcode":old}], "damage_membership_hash":membership_hash([old_id]),
        "damage_location":"PROCESS_DAMAGE_HOLD", "movement_ids":["old-move","new-move"],
        "requires_reseal":False,"target_label_action":"RETAIN_IDENTITY_LABEL",
        "target_label_identity_remains_valid":True,"target_label_membership_bound":False}}
    if defect is None:
        coordinator._validate_receipt(command, receipt)
        assert len(ids) == before["source_member_count"]
        return
    if defect == "pair": receipt["data"]["pairs"][0]["old_unit_id"] = "outside"
    elif defect == "barcode_hash": receipt["data"]["barcode_membership_hash"] = "0"*64
    elif defect == "scope": receipt["authority_scope_id"] = "OTHER"
    elif defect == "version": receipt["entity_versions"] = {}
    elif defect == "label": receipt["data"]["target_label_identity_remains_valid"] = False
    elif defect == "source_kind": receipt["data"]["pairs"][0]["new_source_kind"] = "NG"
    with pytest.raises(TransferSealError):
        coordinator._validate_receipt(command, receipt)


def test_deferred_issue_request_replays_a_prefetch_body_without_rewriting_evidence(tmp_path):
    manager = OperationLeaseManager(OperationLeaseStore(tmp_path / "lease.db"),
        PinnedOperationLeaseKeyring(tmp_path / "keys.json"))
    identity = dict(device_id="device",source_host_id="host",authority_scope_id="scope",scan_payload="QR")
    key = manager.issue_idempotency_key(**identity)
    repeated = manager.issue_idempotency_key(**identity, deferred_completion={
        "local_completion_id":"local-id","local_completed_at":"2026-09-30T12:00:00+09:00"})
    assert key == repeated
    assert manager.issue_request_for_key(key) == {
        "authority_scope_id":"scope", "operation":"SEAL_TRANSFER_BUNDLE", "scan_payload":"QR"}


def prepared(tmp_path, mode="merge"):
    source = _resolved_work_group_phs2(mode=mode)
    member = source["work_group_source"]["members"][0]
    provider = threading.get_ident
    store = TransferSealStore(tmp_path / "scan.db", owner_thread_id_provider=provider)
    client = SimpleNamespace(authority_epoch=7, assert_authority=lambda *a, **k: None)
    coordinator = TransferSealCoordinator(store, client, owner_thread_id_provider=provider)
    master_label = source["phs_work_group"]["scan_payload"]
    row = store.prepare(master_label=master_label, source_identity=source_identity_from_label(parse_new_format_qr(master_label)),
        item_id=source["work_group_source"]["item_id"], operator="fixture", scanned_barcodes=[member["normalized_barcode"]],
        scan_context={"local_completed_at":"2026-09-30T12:00:00+09:00", "short_confirmed":True})
    return store,coordinator,row,source


@pytest.mark.parametrize("mode", ["merge", "split"])
def test_short_command_keeps_full_topology_and_scans_subset(tmp_path, mode):
    store,coordinator,row,source = prepared(tmp_path,mode)
    store.mark_scan_completion_projected(row["intent_id"])
    assert store.pending_ids() == []
    store.settle_short_confirmation(row["intent_id"])
    row = store.load(row["intent_id"])
    command = dict(coordinator._build_work_group_command(row,json.loads(row["source_identity_json"]),source))
    command["payload"]["short_confirmed"] = True
    assert command["payload"]["source_bundles"] == source["work_group_source"]["source_bundles"]
    assert command["client_exact_evidence"]["source_member_ids"] == source["work_group_source"]["member_ids"]
    assert len(command["payload"]["member_ids"]) == 1
    receipt = _work_group_receipt(command)
    coordinator._validate_receipt(command,receipt)
    bad = copy.deepcopy(receipt)
    bad["data"]["remainder_member_ids"] = []
    with pytest.raises(TransferSealError,match="잔량"):
        coordinator._validate_receipt(command,bad)
    bad = copy.deepcopy(receipt)
    bad["data"]["source_transitions"][0]["selected_member_count"] += 1
    with pytest.raises(TransferSealError):
        coordinator._validate_receipt(command,bad)


def test_short_hold_undo_and_original_link_survive_reopen(tmp_path):
    store,coordinator,row,source = prepared(tmp_path)
    store.mark_scan_completion_projected(row["intent_id"])
    reopened = TransferSealStore(store.db_path,owner_thread_id_provider=threading.get_ident)
    assert reopened.pending_ids() == []
    reopened.settle_short_confirmation(row["intent_id"],undo=True)
    reopened.settle_short_confirmation(row["intent_id"],undo=True)
    assert reopened.pending_ids() == []
    saved = reopened.load(row["intent_id"])
    assert saved["local_completion_id"] == row["local_completion_id"]
    assert saved["scan_context_state"] == "CANCELLED"
    with sqlite3.connect(store.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM transfer_scan_context")


def test_upstream_pending_409_retries_while_review_409_is_scoped(tmp_path):
    store,coordinator,row,source = prepared(tmp_path)
    retry = store.record_error(row["intent_id"],TransferSealError("UPSTREAM_COMPLETION_PENDING", "waiting",status_code=409,retryable=True))
    assert retry["status"] == "RETRY_WAIT"
    review = store.record_error(row["intent_id"],TransferSealError("COMPLETION_REVIEW_REQUIRED", "review",status_code=409,retryable=False))
    assert review["status"] == "OPERATOR_REVIEW"
    assert store.post_review_cases()[0]["intent_id"] == row["intent_id"]
