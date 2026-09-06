"""Regressions for the scanner and completion failures observed on ca10."""

import csv
import datetime
import threading
from types import SimpleNamespace

import pytest
from tests.operation_lease_fixtures import fixed_operation_lease_clock

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock')

from Container_Audit import ContainerAudit, TraySession
from tests.test_container_audit_contracts import _completion_app
from tests.test_phs2_master_preflight import (
    BlockingClient,
    COMPACT_QR,
    ITEM,
    ScheduledRoot,
    _app,
    _pump_until,
    _resolved,
)
from transfer_member_exchange import (
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
)
from transfer_seal import SealAttempt
from tests.operation_lease_fixtures import signed_transfer_artifact
from warning_presenter import Notice, NoticeSeverity


class ScannerEntry:
    """Tk Entry ignores insert/delete while disabled and retains its focus."""

    def __init__(self, value=""):
        self.value = value
        self.state = "normal"
        self.focused = True

    def get(self):
        return self.value

    def configure(self, *, state):
        self.state = state

    def insert(self, _index, text):
        if self.state == "normal":
            self.value += text

    def delete(self, *_args):
        if self.state == "normal":
            self.value = ""


def _scan_app():
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = ScheduledRoot()
    app.scan_entry = ScannerEntry(COMPACT_QR + "\r\n")
    app._scan_callback_epoch = 1
    app.COLOR_DANGER = "danger"
    app.statuses = []
    app.show_status_message = lambda *args, **kwargs: app.statuses.append(args)
    return app


def test_scanner_consumes_suffix_once_then_accepts_next_barcode_without_clearing():
    app = _scan_app()
    accepted = []
    app._process_barcode_logic = accepted.append
    app.process_barcode()
    app.process_barcode()  # A duplicate Enter cannot enqueue the same input.
    assert len(app.root.jobs) == 1
    assert app.scan_entry.state == "disabled"
    app.root.run_next()
    assert accepted == [COMPACT_QR]
    assert app.scan_entry.get() == ""
    assert app.scan_entry.state == "normal"
    assert app.scan_entry.focused

    product = ITEM + "-NEXT-PRODUCT"
    app.scan_entry.insert("end", product + "\r\n")
    app.process_barcode()
    app.root.run_next()
    assert accepted == [COMPACT_QR, product]
    assert app.scan_entry.get() == ""
    assert app.scan_entry.focused


def test_stale_callback_preserves_next_input_and_does_not_admit_old_scan():
    app = _scan_app()
    accepted = []
    app._process_barcode_logic = accepted.append
    app.process_barcode()
    app._invalidate_pending_scan_callbacks()
    app.scan_entry.delete(0, "end")
    app.scan_entry.insert("end", ITEM + "-NEW-CONTEXT")
    app.root.run_next()
    assert accepted == []
    assert app.scan_entry.get() == ITEM + "-NEW-CONTEXT"
    assert app.scan_entry.state == "normal"


def test_durable_held_scan_clears_disabled_entry_and_preserves_new_lock(tmp_path):
    app = _scan_app()
    app._preflight_hold_store = lambda: hold_store
    from preflight_scan_hold import PreflightScanHoldStore

    hold_store = PreflightScanHoldStore(tmp_path / "hold.json", capacity=4)
    hold_store.start(worker="tester", master_raw=COMPACT_QR, scan_epoch=1)
    submissions = []
    app._preflight_hold_writer = lambda: SimpleNamespace(
        submit=lambda work, finish, fail: (
            submissions.append((work, finish)), SimpleNamespace(accepted=True)
        )[1]
    )
    app._master_preflight_pending = True
    app.COLOR_PRIMARY = "primary"
    app.scan_entry.value = ITEM + "-HELD\r\n"
    app.process_barcode()
    app.process_barcode()
    assert len(submissions) == 1
    assert app.scan_entry.state == "disabled"
    # Preflight may finish while the independent durable append is in flight.
    app._preflight_scan_input_locked = True
    work, finish = submissions[0]
    finish(work())
    assert [row.raw_barcode for row in hold_store.load().items] == [ITEM + "-HELD"]
    assert app.scan_entry.get() == ""
    assert app.scan_entry.state == "disabled"
    app._set_preflight_scan_input_locked(False)
    app.scan_entry.insert("end", ITEM + "-NEXT")
    assert app.scan_entry.get() == ITEM + "-NEXT"


def _bind_member_store(app, tmp_path):
    app._transfer_coordinator_ui_owner_thread_id = threading.get_ident()
    app.transfer_member_exchange_coordinator = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(
            tmp_path / "transfer-seal.db",
            ui_thread_id_provider=app._transfer_coordinator_ui_thread_id,
        ),
        app.transfer_seal_coordinator.client,
        owner_thread_id_provider=app._transfer_coordinator_owner_thread_id,
    )


def test_activation_preserves_actual_pending_exchange_and_blocks_submit(tmp_path, monkeypatch):
    seed_store = TransferMemberExchangeStore(
        tmp_path / "transfer-seal.db",
        owner_thread_id_provider=lambda: threading.get_ident(),
    )
    pending = seed_store.prepare(
        master_label=COMPACT_QR, source_identity={"fixture": "current-tray"},
        item_id=ITEM, operator="tester", old_barcodes=[ITEM + "-OLD"],
        new_barcodes=[ITEM + "-REPLACEMENT"],
    )
    app = _app(tmp_path, BlockingClient(_resolved(count=2)))
    _bind_member_store(app, tmp_path)
    warnings = []
    monkeypatch.setattr("Container_Audit.messagebox.showerror", lambda *args, **kwargs: warnings.append(args))
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(
        app.root,
        lambda: bool(app.current_tray.master_label_code)
        and not app._preflight_hold_store().exists()
        and not getattr(app, "_preflight_scan_input_locked", False),
    )
    try:
        attempt = app._current_transfer_member_exchange_attempt()
        assert attempt.intent_id == pending["intent_id"]
        assert attempt.status == "PREPARED"
        app.current_tray.scanned_barcodes = [ITEM + "-A", ITEM + "-B"]
        assert app.request_complete_tray() is False
        assert warnings and "중앙 제품 교체" in warnings[0][0]
    finally:
        app._ui_lane.close_idle()


def test_new_preflight_activation_publishes_real_current_member_readiness(tmp_path):
    app = _app(tmp_path, BlockingClient(_resolved(count=2)))
    completion_defaults = _completion_app(tmp_path)
    for name, value in vars(completion_defaults).items():
        if name not in vars(app):
            setattr(app, name, value)
    # Use the actual state and completion-event writes in this combined path.
    for name in ("_save_current_tray_state", "_delete_current_tray_state", "_log_event"):
        vars(app).pop(name, None)
    _bind_member_store(app, tmp_path)
    app._transfer_member_exchange_attempt_snapshot = {
        "known": True, "master_label": "", "attempt": None,
    }
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(
        app.root,
        lambda: bool(app.current_tray.master_label_code)
        and not app._preflight_hold_store().exists()
        and not getattr(app, "_preflight_scan_input_locked", False),
    )
    try:
        snapshot = app._transfer_member_exchange_attempt_snapshot
        assert snapshot["known"] is True
        assert snapshot["master_label"] == app.current_tray.master_label_code
        assert app._transfer_member_exchange_blocks_local_action("이적 봉인 및 완료") is False
        app.current_tray.scanned_barcodes = [ITEM + "-A", ITEM + "-B"]
        app.current_tray.scan_times = [datetime.datetime.now()] * 2
        attempts = []
        def prepare_snapshot(**kwargs):
            attempts.append(kwargs["scanned_barcodes"])
            return SealAttempt("intent-new-tray", "ACKED", receipt_id="receipt-new-tray")

        app._prepare_and_attempt_transfer_seal_snapshot = prepare_snapshot
        completed = []
        assert app.request_complete_tray(completion_callback=completed.append), app.statuses
        _pump_until(app.root, lambda: bool(completed))
        assert completed == [True]
        assert attempts == [(ITEM + "-A", ITEM + "-B")]
        with open(app.log_file_path, encoding="utf-8-sig", newline="") as stream:
            assert [row["event"] for row in csv.DictReader(stream)] == [
                "MASTER_LABEL_SCANNED_NEW", "TRAY_COMPLETE",
            ]
        assert app.current_tray.master_label_code == ""
    finally:
        app._ui_lane.close_idle()


def test_future_lease_warning_waits_then_ack_retries_same_signed_lease(tmp_path, monkeypatch):
    issued = datetime.datetime(2026, 9, 5, 3, 28, 54, tzinfo=datetime.timezone.utc)
    artifact, _claims = signed_transfer_artifact(
        _resolved(count=2), scan_payload=COMPACT_QR, issued_at=issued,
    )
    client = BlockingClient(_resolved(count=2))
    keys = []
    def issue(**kwargs):
        keys.append(kwargs["idempotency_key"])
        return artifact

    client.issue_operation_lease = issue
    app = _app(tmp_path, client)
    app._stop_warning_beep = lambda: None
    manager = app.transfer_seal_coordinator.operation_lease_manager
    original_accept = manager.accept_authenticated
    pc_time = [issued - datetime.timedelta(seconds=40)]
    monkeypatch.setattr(
        manager, "accept_authenticated",
        lambda **kwargs: original_accept(**kwargs, now=pc_time[0]),
    )
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(
        app.root,
        lambda: not app._master_preflight_pending
        and app._preflight_hold_snapshot is not None
        and app._preflight_hold_snapshot.state == "LOOKUP_FAILED",
    )
    assert app.current_tray.master_label_code == ""
    assert app._preflight_hold_snapshot.error_code == "OPERATION_LEASE_NOT_YET_VALID"
    assert app.warnings
    for title, message, _color in app.warnings:
        assert "시간" in title
        assert "잠시 기다린 뒤" in message
        assert "자동 재조회" in message
        assert "다시 스캔하지 마세요" in message
        assert "IT 담당자" in message

    app._warning_state_presenter().present(Notice(
        code="clock-fixture", title=app.warnings[-1][0],
        message=app.warnings[-1][1], severity=NoticeSeverity.ERROR, blocking=True,
    ))
    pc_time[0] = issued + datetime.timedelta(seconds=1)
    app._acknowledge_active_notice()
    _pump_until(
        app.root,
        lambda: bool(app.current_tray.master_label_code)
        and not app._preflight_hold_store().exists(),
    )
    assert len(keys) == 2 and keys[0] == keys[1]
    assert app.current_tray.operation_lease_id == artifact["lease_id"]
    assert app.current_tray.scanned_barcodes == []
    app._ui_lane.close_idle()


@pytest.mark.parametrize("busy", [False, True])
def test_full_tray_center_and_notice_describe_completion_not_next_scan(busy):
    class Label(dict):
        def winfo_exists(self):
            return True

        def configure(self, **kwargs):
            self.update(kwargs)

    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(
        master_label_code=COMPACT_QR, tray_size=2, scanned_barcodes=["A", "B"],
    )
    app.master_label_replace_state = None
    app._completion_lane_busy = busy
    app.current_item_label = Label()
    app.notice_title_label = Label()
    app.notice_message_label = Label()
    app.COLOR_TEXT = "text"
    app._schedule_notice_message_wrap_refresh = lambda **kwargs: None
    app._update_current_item_label()
    app._render_warning_state()
    center = app.current_item_label["text"]
    assert center == app.notice_message_label["text"]
    assert app.notice_title_label["text"] == "이적 완료 확인"
    assert "다음 제품" not in center
    assert ("중앙 이적 확인 중" if busy else "'제출'") in center


@pytest.mark.parametrize("lose_local_ack", [False, True])
def test_acked_completion_projects_once_after_own_lane_releases(tmp_path, lose_local_ack):
    app = _completion_app(tmp_path)
    app._load_session_state()
    app.root = ScheduledRoot()
    app._scan_callback_epoch = 1
    app.current_tray.master_label_code = COMPACT_QR
    app.current_tray.active_label_qr_payload = COMPACT_QR
    app.current_tray.operation_lease_id = "lease-completion-fixture"
    app.current_tray.tray_size = 2
    app.current_tray.start_time = datetime.datetime.now() - datetime.timedelta(seconds=20)
    app.current_tray.scan_times = [
        app.current_tray.start_time + datetime.timedelta(seconds=1),
        app.current_tray.start_time + datetime.timedelta(seconds=2),
    ]
    app._schedule_focus_return = lambda *args, **kwargs: None
    app.transfer_seal_coordinator = SimpleNamespace(client=object())
    _bind_member_store(app, tmp_path)
    app._transfer_member_exchange_attempt_snapshot = {
        "known": True, "master_label": COMPACT_QR, "attempt": None,
    }
    attempted = []
    callbacks = []
    # Transport is isolated; all admission, lane, snapshot, completion and CSV
    # projection code is real. Existing seal tests cover signed receipt binding.
    def prepare_snapshot(**kwargs):
        attempted.append(kwargs["scanned_barcodes"])
        return SealAttempt("intent-acked-fixture", "ACKED", receipt_id="receipt-fixture")

    app._prepare_and_attempt_transfer_seal_snapshot = prepare_snapshot
    log_event = app._log_event
    lost_ack = []
    def project_event(event, **kwargs):
        result = log_event(event, **kwargs)
        if event == "TRAY_COMPLETE" and lose_local_ack and not lost_ack:
            lost_ack.append(kwargs["idempotency_key"])
            return False
        return result

    app._log_event = project_event
    assert app.request_complete_tray(completion_callback=callbacks.append)
    # Unrelated completion requests still cannot enter the active lane.
    assert app.request_complete_tray() is False
    _pump_until(app.root, lambda: bool(callbacks))
    try:
        if lose_local_ack:
            assert callbacks == [False]
            assert app.current_tray.master_label_code == COMPACT_QR
            assert app._active_completion_event_contract()["idempotency_key"] == lost_ack[0]
            assert app.request_complete_tray(completion_callback=callbacks.append)
            _pump_until(app.root, lambda: len(callbacks) == 2)
        assert callbacks == ([False, True] if lose_local_ack else [True])
        with open(app.log_file_path, encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        assert [row["event"] for row in rows] == ["TRAY_COMPLETE"]
        assert attempted == [("BC-1", "BC-2")] * (2 if lose_local_ack else 1)
        assert app.current_tray.master_label_code == ""
        assert app.total_tray_count == 1
        assert app._warning_state_presenter().state.completion.receipt_id == "receipt-fixture"
    finally:
        app._ui_lane.close_idle()
