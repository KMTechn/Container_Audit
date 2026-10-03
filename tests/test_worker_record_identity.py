"""Roster stage 2: durable identity, old wire bodies and immutable retries."""
import csv
import datetime
import io
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import Container_Audit as ca
from event_log_store import EVENT_LOG_HEADERS, EventLogOutbox
from parked_tray_store import ParkedTrayStore
from preflight_scan_hold import PreflightScanHoldStore
from tests.test_worker_roster import response, row, store
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR, ITEM
from transfer_member_exchange import TransferMemberExchangeStore
from transfer_seal import TransferSealCoordinator, TransferSealStore
from tests.test_transfer_seal import FakeResponse, _client, _receipt, _resolved_bundle
from tray_state import tray_session_from_state, tray_session_to_state, validate_tray_state
from worker_roster import record_identity, record_identity_enabled, record_owner_matches

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")
WORKER_ID = "9d8a70b1-c2d3-4e5f-8a90-112233445566"
IDENTITY = {"worker_id": WORKER_ID, "worker_name_snapshot": "tester"}


def _app(flow, tmp_path, *, enabled=False, roster=True):
    app = flow(transition=False)
    if roster:
        app.worker_roster = store(tmp_path, row(worker_id=WORKER_ID))
        app._selected_roster_id = WORKER_ID
    app._worker_record_identity_enabled = enabled
    app._schedule_scanonly_transport = lambda **kwargs: False
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    assert app.current_tray.master_label_code
    return app


@pytest.mark.parametrize("value,expected", [(None, False), ({}, False),
    ({"capabilities": {"worker_record_identity_v1": {"enabled": False}}}, False),
    ({"capabilities": {"worker_record_identity_v1": {"enabled": "true"}}}, False),
    ({"capabilities": {"worker_record_identity_v1": {"enabled": 1}}}, False),
    ({"capabilities": {"worker_record_identity_v1": {"enabled": True}}}, True)])
def test_capability_requires_explicit_true(value, expected):
    assert record_identity_enabled(value) is expected


@pytest.mark.parametrize("roster", [True, False])
def test_new_tray_and_offline_restart_keep_start_identity(flow, windows, tmp_path, roster):
    app = _app(flow, tmp_path, roster=roster)
    app._process_barcode_logic(ITEM + "-SERIAL-001")
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    assert state["worker_id"] == (WORKER_ID if roster else None)
    assert state["worker_name_snapshot"] == state["worker_name"] == "tester"
    restarted = tray_session_from_state(state, session_factory=ca.TraySession, default_tray_size=60)
    assert tray_session_to_state(restarted, worker_name="changed login")["worker_name"] == "tester"
    assert restarted.worker_id == state["worker_id"]
    assert restarted.scanned_barcodes == [ITEM + "-SERIAL-001"]
    probe = """import json, sys
from pathlib import Path
from Container_Audit import TraySession
from tray_state import tray_session_from_state, tray_session_to_state
state = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
tray = tray_session_from_state(state, session_factory=TraySession, default_tray_size=60)
assert tray_session_to_state(tray, worker_name='different login') == state
"""
    fresh = subprocess.run([sys.executable, "-B", "-c", probe,
        str(Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE)], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    assert fresh.returncode == 0, "fresh-process identity roundtrip failed"
    assert windows == []


def test_rename_affects_next_tray_and_uuid_restores_old_snapshot(flow, windows, tmp_path):
    app = _app(flow, tmp_path)
    original = app._current_tray_state_snapshot()
    app.worker_roster.apply(response(row("corrected", worker_id=WORKER_ID), version=2), requested_version=1)
    assert app._record_worker_name() == "tester"
    assert app._worker_record_context()["worker_name_snapshot"] == "tester"
    app.worker_name = "corrected"
    assert app._owns_worker_record(original)
    app._restore_tray_from_state(original)
    assert app._current_tray_state_snapshot()["worker_name"] == "tester"
    assert app._completion_projection_log_path().name.startswith("이적작업이벤트로그_tester_")
    app.current_tray = ca.TraySession()
    app._process_barcode_logic(COMPACT_QR.replace("LBL-COMPACT-001", "LBL-COMPACT-002") + "|QT=3")
    assert app.current_tray.worker_id == WORKER_ID
    assert app.current_tray.worker_name_snapshot == "corrected"
    assert windows == []


def test_uuid_ownership_does_not_fall_back_to_same_name():
    assert record_owner_matches({**IDENTITY, "worker_name": "tester"}, worker_name="renamed", worker_id=WORKER_ID)
    assert not record_owner_matches({**IDENTITY, "worker_name": "tester"}, worker_name="tester", worker_id="different")
    assert not record_owner_matches({**IDENTITY, "worker_name": "tester"}, worker_name="tester")
    assert record_owner_matches({"worker_name": "tester"}, worker_name="tester", worker_id=WORKER_ID)


def test_parked_lookup_uses_uuid_and_keeps_old_filename(flow, windows, tmp_path):
    app = _app(flow, tmp_path)
    state = app._current_tray_state_snapshot()
    parked = ParkedTrayStore(tmp_path / "parked")
    path = parked.save_state(state, worker_name="tester", master_label=state["master_label_code"])
    assert "tester" in path.name
    assert [entry.path for entry in parked.scan_for_worker("corrected", worker_id=WORKER_ID, strict=True)] == [path]
    assert parked.scan_for_worker("tester", worker_id="different", strict=True) == []
    app.worker_name = "corrected"
    app.current_tray = ca.TraySession()
    contract = app._build_parked_restore_contract(parked_path=path, restored_state=state,
                                                restore_detail={"master_label_code": state["master_label_code"]})
    event = contract["projection_events"][-1]
    assert event["projection_worker_name"] == "tester"
    assert event["projection_log_name"].startswith("이적작업이벤트로그_tester_")
    assert record_identity(event["worker_record"]) == IDENTITY
    old = {key: value for key, value in state.items() if key not in IDENTITY}
    validate_tray_state(old, default_tray_size=60)
    restored = tray_session_from_state(old, session_factory=ca.TraySession, default_tray_size=60)
    assert not restored.worker_name_snapshot
    assert "worker_id" not in tray_session_to_state(restored, worker_name="tester")


def test_preflight_upgrade_preserves_old_and_new_fifo(tmp_path):
    store = PreflightScanHoldStore(tmp_path / "hold.json", capacity=8)
    original = store.start(worker="tester", master_raw=COMPACT_QR, scan_epoch=1, **IDENTITY)
    store.append(ITEM + "-SERIAL-001")
    recovered = PreflightScanHoldStore.load_path(store.path)
    assert record_identity(recovered.to_payload()) == IDENTITY
    assert record_owner_matches(recovered.to_payload(), worker_name="corrected", worker_id=WORKER_ID)
    assert recovered.preflight_id == original.preflight_id
    assert len(recovered.items) == 1
    old = recovered.to_payload()
    for field in IDENTITY:
        old.pop(field)
    store.path.write_text(json.dumps(old), encoding="utf-8")
    assert PreflightScanHoldStore.load_path(store.path).to_payload() == old


def test_park_after_rename_keeps_snapshot_filename(flow, windows, tmp_path):
    app = _app(flow, tmp_path)
    app.worker_name = "corrected"
    assert app.park_current_tray(confirm=False)
    entries = app._parked_store().scan_for_worker("corrected", worker_id=WORKER_ID, strict=True)
    assert len(entries) == 1
    assert "tester" in entries[0].path.name
    assert "corrected" not in entries[0].path.name
    saved = app._parked_store().load(entries[0].path)
    assert saved["worker_name"] == "tester"
    assert record_identity(saved) == IDENTITY
    assert windows == []


@pytest.mark.parametrize("enabled", [False, True])
def test_csv_wire_golden_and_enabled_details(flow, windows, tmp_path, enabled):
    app = _app(flow, tmp_path, enabled=enabled)
    entry = app._prepare_event_log_entry("PRODUCT_SCAN", detail={"product_barcode": "part"},
        idempotency_key="identity-golden", event_timestamp="2026-10-04T00:00:00")["log_entry"]
    golden = json.loads((Path(__file__).parent / "fixtures/worker_record_identity_disabled.json").read_text(encoding="utf-8"))
    if enabled:
        assert record_identity(json.loads(entry["details"])) == IDENTITY
        assert list(entry) == EVENT_LOG_HEADERS
    else:
        actual_csv, expected_csv = io.StringIO(newline=""), io.StringIO(newline="")
        for stream, value in ((actual_csv, entry), (expected_csv, golden)):
            writer = csv.DictWriter(stream, fieldnames=EVENT_LOG_HEADERS)
            writer.writeheader()
            writer.writerow(value)
        assert actual_csv.getvalue().encode("utf-8-sig") == expected_csv.getvalue().encode("utf-8-sig")


@pytest.mark.parametrize("enabled", [False, True])
def test_audit_retry_freezes_capability_and_name(flow, windows, tmp_path, monkeypatch, enabled):
    app = _app(flow, tmp_path, enabled=enabled)
    contract = app._audit_event_contract(event_type="PRODUCT_SCAN", event_detail={"product_barcode": "part"},
        idempotency_key="audit-identity-retry", observed_at=datetime.datetime.now())
    submitted = []
    def unavailable(self, path, entry, **kwargs):
        submitted.append(dict(entry))
        raise OSError("outbox temporarily unavailable")
    with monkeypatch.context() as patch:
        patch.setattr(EventLogOutbox, "stage", unavailable)
        assert not app._project_audit_event_contract(contract)
    path = app._completion_projection_log_path(contract["projection_log_name"])
    app._worker_record_identity_enabled = not enabled
    app.worker_name = "corrected"
    app.current_tray = ca.TraySession()
    assert app._project_audit_event_contract(contract)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [entry for entry in rows if "audit-identity-retry" in entry["details"]] == submitted
    before = path.read_bytes()
    app._worker_record_identity_enabled = enabled
    assert app._project_audit_event_contract(contract)
    assert path.read_bytes() == before


@pytest.mark.parametrize("enabled", [False, True])
def test_seal_identity_is_local_and_command_is_immutable_across_reopen(tmp_path, enabled):
    record = {**IDENTITY, "enabled": enabled}
    path = tmp_path / "seal.db"
    store = TransferSealStore(path, owner_thread_id_provider=threading.get_ident)
    args = dict(master_label=COMPACT_QR, source_identity={"item_id": ITEM}, item_id=ITEM,
                operator="tester", scanned_barcodes=["part"],
                scan_context={**IDENTITY, "worker_record": record})
    intent = store.prepare(**args)
    assert json.loads(intent["worker_record_json"]) == record
    command = {"idempotency_key": intent["idempotency_key"], "payload": {"item_id": ITEM}}
    store.mark_scan_completion_projected(intent["intent_id"])
    bound = store.bind_command(intent["intent_id"], command)
    assert (json.loads(bound["command_json"])["payload"].get("worker_identity") == IDENTITY) is enabled
    reopened = TransferSealStore(path).load(intent["intent_id"])
    assert reopened["command_json"] == bound["command_json"]
    assert reopened["command_hash"] == bound["command_hash"]
    assert record_identity(store._linked_event_payload(intent)["intent"]) == IDENTITY
    original = store.preview_intent(master_label=COMPACT_QR, source_identity={"item_id": ITEM},
                                   item_id=ITEM, scanned_barcodes=["part"])
    assert (original["intent_id"] == intent["intent_id"]) is (not enabled)


@pytest.mark.parametrize("enabled", [False, True])
def test_exchange_command_uses_saved_identity_decision(tmp_path, enabled):
    store = TransferMemberExchangeStore(tmp_path / "exchange.db", owner_thread_id_provider=threading.get_ident)
    context = {**IDENTITY, "worker_record": {**IDENTITY, "enabled": enabled}}
    row = store.prepare(master_label=COMPACT_QR, source_identity={"item_id": ITEM}, item_id=ITEM,
        operator="tester", old_barcodes=["old"], new_barcodes=["new"], scan_context=context)
    saved = TransferMemberExchangeStore(store.db_path).scan_exchange_context(row["intent_id"])
    store.mark_scan_exchange_projected(row["intent_id"])
    bound = store.bind_command(row["intent_id"], {"idempotency_key": "exchange-command", "payload": {"item_id": ITEM}})
    command = json.loads(bound["command_json"])
    assert (command["payload"].get("worker_identity") == IDENTITY) is enabled
    assert record_identity(saved) == IDENTITY


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("roster", [False, True])
def test_fake_http_capability_and_lost_ack_keep_original_command(tmp_path, enabled, roster):
    posts = []
    capability = [enabled]
    def handler(call):
        if call["url"].endswith("/capabilities"):
            return FakeResponse(200, {"ok": True, "data": {"capabilities": {
                "worker_record_identity_v1": {"enabled": capability[0]}}}})
        if "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        if call["method"] == "POST":
            posts.append(call["json"])
            if len(posts) == 1:
                raise ConnectionError("lost acknowledgement")
            return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})
        if "/receipts/" in call["url"]:
            return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        raise AssertionError("unexpected fake route")
    client, _ = _client(handler)
    identity = {**IDENTITY, "worker_id": WORKER_ID if roster else None}
    record = {**identity, "enabled": record_identity_enabled(client.get_capabilities())}
    path = tmp_path / "http.db"
    coordinator = TransferSealCoordinator(TransferSealStore(path), client,
        owner_thread_id_provider=threading.get_ident)
    prepared = coordinator.prepare(master_label="PHS=1|BND=PHS-SERVER-001|ITG=ITAG-001|CLC=AAA2270730100|QT=3",
        master_label_fields={"ITG": "ITAG-001", "LBL": "INPUT-LABEL-001", "WID": "WORK-001", "CLC": ITEM,
                             "QT": "3", "BND": "PHS-SERVER-001"}, item_id=ITEM, operator="tester",
        scanned_barcodes=["BC-1", "BC-2", "BC-3"], worker_record=record)
    preview = coordinator.preview(master_label="PHS=1|BND=PHS-SERVER-001|ITG=ITAG-001|CLC=AAA2270730100|QT=3",
        master_label_fields={"ITG": "ITAG-001", "LBL": "INPUT-LABEL-001", "WID": "WORK-001", "CLC": ITEM,
                             "QT": "3", "BND": "PHS-SERVER-001"}, item_id=ITEM,
        scanned_barcodes=["BC-1", "BC-2", "BC-3"], worker_record=record)
    assert preview.intent_id == prepared.intent_id
    assert coordinator.attempt(prepared.intent_id).status == "RETRY_WAIT"
    before = coordinator.store.load(prepared.intent_id)
    assert (posts[0]["payload"].get("worker_identity") == identity) is enabled
    if not enabled:
        golden = json.loads((Path(__file__).parent / "fixtures/worker_record_identity_disabled_command.json").read_text())
        assert before["command_hash"] == golden["command_hash"]
        assert before["command_json"] == golden["command_json"]
    capability[0] = not enabled
    assert record_identity_enabled(client.get_capabilities()) is (not enabled)
    restarted = TransferSealCoordinator(TransferSealStore(path), client,
        owner_thread_id_provider=threading.get_ident)
    assert restarted.attempt(prepared.intent_id).status == "ACKED"
    after = restarted.store.load(prepared.intent_id)
    assert posts[1] == posts[0]
    assert after["command_hash"] == before["command_hash"]
    assert after["command_json"] == before["command_json"]
