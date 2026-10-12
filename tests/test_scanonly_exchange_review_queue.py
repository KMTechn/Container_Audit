"""A reviewed exchange holds its tray, while other trays keep transmitting."""
import copy
import json
import socket
import threading

import pytest

from label_qr import parse_new_format_qr
from transfer_member_exchange import TransferMemberExchangeStore
from transfer_seal import (
    TransferSealCoordinator, TransferSealError, TransferSealStore,
    source_identity_from_label, membership_hash, _sha256, _deterministic_id,
)
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, _active, COMPACT_QR,
    ITEM, _pump_until, _resolved, OfflineSealClient,
)
from tests.test_transfer_seal import _resolved_work_group_phs2, _work_group_receipt
from tests.test_legacy_label_transition import OLD_QR

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


@pytest.fixture(autouse=True)
def no_network_or_known_folders(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("native network is outside this isolated harness")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    import ctypes
    if hasattr(ctypes, "windll"):
        monkeypatch.setattr(ctypes.windll.shell32, "SHGetKnownFolderPath", denied)


def _exchange_receipt(command):
    before = command["client_exact_evidence"]["target"]
    pair = command["payload"]["pairs"][0]
    old, new = pair["old_barcode"], pair["new_barcode"]
    old_id = next(member["unit_id"] for member in before["members"]
                  if member["normalized_barcode"] == old)
    new_id = "new-registered"
    members = [dict(member) for member in before["members"] if member["unit_id"] != old_id]
    members.append({"unit_id": new_id, "normalized_barcode": new})
    ids = sorted(member["unit_id"] for member in members)
    barcodes = sorted(member["normalized_barcode"] for member in members)
    return {"status": "COMMITTED", "contract_version": command["contract_version"],
        "command_type": command["command_type"], "authority_scope_id": command["authority_scope_id"],
        "authority_epoch": command["authority_epoch"], "resolved_ledger_plane": command["ledger_plane"],
        "resolved_plane_epoch": command["plane_epoch"], "receipt_id": "receipt-new-good",
        "committed_at": "2026-09-30T03:00:00Z", "event_ids": ["event"], "outbox_ids": ["outbox"],
        "entity_versions": {key: value + 1 for key, value in command["expected_versions"].items()},
        "source_membership_changes": [], "data": {
        "idempotency_key": command["idempotency_key"], "target_bundle_id": before["bundle_id"],
        "target_bundle_type": "PHS", "target_location": "PHS_GOOD", "atomic": True,
        "members": members, "member_ids": ids, "member_count": len(ids), "membership_hash": membership_hash(ids),
        "normalized_barcodes": barcodes, "barcode_membership_hash": membership_hash(barcodes), "pair_count": 1,
        "pairs": [{"old_unit_id": old_id, "new_unit_id": new_id, "old_barcode": old, "new_barcode": new,
            "new_source_kind": "EXCHANGE_GOOD_REGISTERED", "new_source_bundle_id": None}],
        "damage_bundle_id": "damage", "damage_member_ids": [old_id],
        "damage_members": [{"unit_id": old_id, "normalized_barcode": old}],
        "damage_membership_hash": membership_hash([old_id]), "damage_location": "PROCESS_DAMAGE_HOLD",
        "movement_ids": ["old-move", "new-move"], "requires_reseal": False,
        "target_label_action": "RETAIN_IDENTITY_LABEL", "target_label_identity_remains_valid": True,
        "target_label_membership_bound": False}}


class QueueServer(OfflineSealClient):
    def __init__(self):
        super().__init__(_resolved(3))
        self.authority_epoch = 7
        self.good_source = _resolved_work_group_phs2(mode="merge")
        self.exchange_posts = []
        self.receipt_reads = []
        self.seal_posts = []

    def resolve_source(self, identity):
        compact = source_identity_from_label(parse_new_format_qr(COMPACT_QR))
        return self.response if identity.get("input_tag_id") == compact["input_tag_id"] else self.good_source

    def get_receipt(self, scope, key):
        self.receipt_reads.append(key)
        return None

    def replace_bundle_members(self, command):
        self.exchange_posts.append(copy.deepcopy(command))
        if command["payload"]["pairs"][0]["new_barcode"].endswith("REJECT"):
            raise TransferSealError("SOURCE_NOT_AVAILABLE", "synthetic replacement refused",
                                    status_code=409, retryable=False)
        receipt = _exchange_receipt(command)
        self.good_source = _after_exchange_source(self.good_source)
        return receipt

    def seal_transfer(self, command):
        self.seal_posts.append(copy.deepcopy(command))
        return _work_group_receipt(command)


def _after_exchange_source(source):
    old, new = ITEM + "-SERIAL-001", ITEM + "-GOOD"
    old_id, new_id = "unit-001", "new-registered"
    replacements = {old: new, old_id: new_id}
    group_ids = source["work_group_source"]["member_ids"]
    for ids in (group_ids, source["work_group_source"]["source_bundles"][0]["source_member_ids"]):
        replacements[membership_hash(ids)] = membership_hash([new_id if value == old_id else value for value in ids])
    barcodes = [row["normalized_barcode"] for row in source["work_group_source"]["members"]]
    replacements[membership_hash(barcodes)] = membership_hash([new if value == old else value for value in barcodes])
    def replace(value):
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        return replacements.get(value, value) if isinstance(value, str) else value
    result = replace(source)
    work = result["work_group_source"]
    group = result["phs_work_group"]
    previous_transfer = work["transfer_bundle_id"]
    work["transfer_bundle_id"] = _deterministic_id("TRANSFER", {
        "group_id": group["group_id"], "label_id": group["label_id"], "member_ids": work["member_ids"]})
    work["transfer_external_label"] = work["transfer_bundle_id"]
    target = work["source_bundles"][0]
    target["entity_version"] += 1
    for versions in (work["entity_versions"], result["entity_versions"]):
        versions.pop("bundle:" + previous_transfer, None)
        versions["bundle:" + work["transfer_bundle_id"]] = 0
        versions["bundle:" + target["bundle_id"]] = target["entity_version"]
    work["topology_hash"] = result["topology_hash"] = _sha256({
        "phs_work_group": group, "source_bundles": work["source_bundles"],
        "remainder_cover_groups": work.get("remainder_cover_groups", []),
        "source_iin": work["source_iin"], "barcode_membership_hash": work["barcode_membership_hash"],
        "transfer_bundle_id": work["transfer_bundle_id"]})
    return result


def _prepare_exchange(store, label, old, new, predecessors=()):
    row = store.prepare(master_label=label,
        source_identity=source_identity_from_label(parse_new_format_qr(label) or {}),
        item_id=ITEM, operator="fixture", old_barcodes=[old], new_barcodes=[new],
        scan_context={"exchanged_at": "2026-09-30T12:00:00+09:00", "predecessor_keys": list(predecessors)})
    store.mark_scan_exchange_projected(row["intent_id"])
    return dict(row)


def _cycle(app):
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy()
                and not app._scanonly_transport_lane().is_busy())
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._scanonly_transport_lane().is_busy())


@pytest.mark.parametrize("review_kind", ["legacy", "rejected"])
def test_review_keeps_same_tray_order_and_other_tray_exchange_and_seal_continue(
        flow, windows, review_kind):
    server = QueueServer()
    app = flow(transition=True, client=server)
    provider = threading.get_ident
    exchanges = TransferMemberExchangeStore(app.transfer_seal_coordinator.store.db_path,
                                             owner_thread_id_provider=provider)
    first_label = OLD_QR if review_kind == "legacy" else COMPACT_QR
    app._process_barcode_logic(first_label)
    _pump_until(app.root, lambda: bool(app.current_tray.master_label_code)
                and not app._preflight_context_blocks_mutation())
    for value in (ITEM + "-SERIAL-001", "KMCMD:EXCHANGE", ITEM + "-SERIAL-001", ITEM + "-REJECT"):
        app._process_barcode_logic(value)
    _cycle(app)
    first = dict(exchanges.load(exchanges.scan_exchange_rows()[0]["intent_id"]))
    assert first["status"] == "OPERATOR_REVIEW"
    assert first["last_error_code"] == ("PHS2_CANONICAL_EVIDENCE_REQUIRED"
        if review_kind == "legacy" else "SOURCE_NOT_AVAILABLE")
    first_key = "container-member-exchange:" + first["intent_hash"]
    same_tray = _prepare_exchange(exchanges, first_label, ITEM + "-SERIAL-002",
                                 ITEM + "-NEXT", [first_key])
    good_label = server.good_source["phs_work_group"]["scan_payload"]
    good = _prepare_exchange(exchanges, good_label, ITEM + "-SERIAL-001", ITEM + "-GOOD")
    good_key = "container-member-exchange:" + good["intent_hash"]
    seals = TransferSealStore(exchanges.db_path, owner_thread_id_provider=provider)
    # Bind a real exact-membership command, with the exchange dependency still
    # enforced by the product's transport loop before its real seal attempt.
    source = _after_exchange_source(server.good_source)
    scanned = [member["normalized_barcode"] for member in source["work_group_source"]["members"]]
    seal = seals.prepare(master_label=good_label,
        source_identity=source_identity_from_label(parse_new_format_qr(good_label)),
        item_id=ITEM, operator="fixture", scanned_barcodes=scanned,
        scan_context={"local_completed_at": "2026-09-30T12:00:00+09:00",
                      "exchange_idempotency_keys": [good_key]})
    coordinator = TransferSealCoordinator(seals, server, owner_thread_id_provider=provider)
    command = coordinator._build_work_group_command(seal, json.loads(seal["source_identity_json"]), source)
    seals.mark_scan_completion_projected(seal["intent_id"])
    seals.bind_command(seal["intent_id"], command)
    reviewed_seal = None
    if review_kind == "rejected":
        reviewed_seal = seals.prepare(master_label=first_label,
            source_identity=source_identity_from_label(parse_new_format_qr(first_label)),
            item_id=ITEM, operator="fixture", scanned_barcodes=[ITEM + "-REJECT"],
            scan_context={"local_completed_at": "2026-09-30T12:00:00+09:00",
                          "exchange_idempotency_keys": [first_key]})
        seals.mark_scan_completion_projected(reviewed_seal["intent_id"])
    _cycle(app)
    assert exchanges.load(same_tray["intent_id"])["status"] == "PREPARED"
    assert exchanges.load(good["intent_id"])["status"] == "ACKED"
    assert exchanges.load(good["intent_id"])["local_apply_status"] == "APPLIED"
    assert seals.load(seal["intent_id"])["status"] == "ACKED"
    if reviewed_seal is not None:
        assert seals.load(reviewed_seal["intent_id"])["status"] == "PREPARED"
    assert server.seal_posts[0]["payload"]["scanned_barcodes"] == scanned
    assert len(server.seal_posts) == 1
    assert len(server.exchange_posts) == (1 if review_kind == "legacy" else 2)
    before = dict(exchanges.load(good["intent_id"]))
    _cycle(app)
    assert dict(exchanges.load(good["intent_id"])) == before
    assert dict(exchanges.load(first["intent_id"])) == first
    assert exchanges.load(same_tray["intent_id"])["status"] == "PREPARED"
    assert len(server.seal_posts) == 1
    assert windows == []


def test_inline_exchange_displays_saved_pending_company_confirmation(flow, windows):
    app = _active(flow)
    old, new = ITEM + "-SERIAL-001", ITEM + "-SERIAL-999"
    for value in (old, "KMCMD:EXCHANGE", old, new):
        app._process_barcode_logic(value)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    messages = [str(status[0]) for status in app.statuses]
    assert any("저장됨" in message and "회사 서버 확인 중" in message for message in messages)
    assert not any("제품을 교환했습니다" in message for message in messages)
    assert windows == []
