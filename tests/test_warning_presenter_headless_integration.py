import datetime

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit, TraySession
from item_catalog import ItemCatalog
from scan_display import format_scan_list_row
from transfer_seal import SealAttempt
from warning_presenter import CompletionOutcome, WarningPresenter


ITEM_CODE = "AAA2270730100"
FIRST_BARCODE = f"{ITEM_CODE}|SERIAL=SERIAL-0001|TRACE=TRACE-0001"
SECOND_BARCODE = f"{ITEM_CODE}|SERIAL=SERIAL-0002|TRACE=TRACE-0002"
THIRD_BARCODE = f"{ITEM_CODE}|SERIAL=SERIAL-0003|TRACE=TRACE-0003"
MASTER_LABEL = f"PHS=1|CLC={ITEM_CODE}|QT=3"


def _display_row(position, barcode):
    return format_scan_list_row(position, barcode, item_code=ITEM_CODE)


class HeadlessRoot:
    def after(self, _delay, _callback, *_args):
        return "after-id"

    def after_cancel(self, _job):
        return None


class HeadlessListbox:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def insert(self, index, value):
        if index == 0:
            self.rows.insert(0, value)
        else:
            self.rows.append(value)

    def delete(self, index, *rest):
        if rest:
            self.rows.clear()
        elif self.rows:
            del self.rows[index]

    def itemconfig(self, *_args, **_kwargs):
        return None

    def winfo_exists(self):
        return True

    def size(self):
        return len(self.rows)

    def get(self, index):
        return self.rows[index]


class OrderedPresenter(WarningPresenter):
    def __init__(self, events):
        super().__init__()
        self.events = events

    def record_normal_scan(self, barcode):
        self.events.append(("record_normal_scan", barcode))
        return super().record_normal_scan(barcode)

    def present_completion(self, snapshot):
        self.events.append(("present_completion", snapshot.outcome))
        return super().present_completion(snapshot)


def _raise(message):
    raise AssertionError(message)


def _scan_app(*, save_succeeds, events):
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(
        master_label_code=MASTER_LABEL,
        item_code=ITEM_CODE,
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=[FIRST_BARCODE],
        scan_times=[datetime.datetime(2026, 7, 15, 9, 0, 0)],
        tray_size=3,
        start_time=datetime.datetime(2026, 7, 15, 8, 59, 0),
    )
    app.items_data = [
        {"Item Code": ITEM_CODE, "Item Name": "fixture item", "Spec": "fixture spec"}
    ]
    app.item_catalog = ItemCatalog(app.items_data)
    app.master_label_replace_state = None
    app.internal_test_commands_enabled = False
    app.warning_presenter = OrderedPresenter(events)
    app.warning_presenter.record_normal_scan(FIRST_BARCODE)
    events.clear()
    app.root = HeadlessRoot()
    app.scanned_listbox = HeadlessListbox([_display_row(1, FIRST_BARCODE)])
    app.undo_button = {"state": container_audit_module.tk.NORMAL}
    app.success_sound = None
    app.error_sound = None
    app._warning_beep_active = False
    app.notice_frame = object()
    app.COLOR_DANGER = "danger"
    app.COLOR_SUCCESS = "success"
    app.COLOR_PRIMARY = "primary"
    app.COLOR_SIDEBAR_BG = "sidebar"
    app.COLOR_TEXT = "text"
    app._update_last_activity_time = lambda: None
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda *args, **kwargs: None
    app._render_warning_state = lambda: events.append(("render", None))
    app._save_current_tray_state = lambda: events.append(("save_state", save_succeeds)) or save_succeeds
    app._log_event = lambda event, **kwargs: events.append(("log_event", event)) or True
    app.show_status_message = lambda *args, **kwargs: events.append(("status", args[0]))
    app.complete_tray = lambda: _raise("a two-of-three tray must not complete")
    return app


def _completion_app(*, seal_status, ledger_succeeds, events):
    app = ContainerAudit.__new__(ContainerAudit)
    scan_times = [
        datetime.datetime(2026, 7, 15, 9, 0, index)
        for index in range(3)
    ]
    app.current_tray = TraySession(
        master_label_code=MASTER_LABEL,
        item_code=ITEM_CODE,
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=[FIRST_BARCODE, SECOND_BARCODE, THIRD_BARCODE],
        scan_times=scan_times,
        tray_size=3,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 7, 15, 8, 59, 0),
        has_error_or_reset=True,
    )
    app.warning_presenter = OrderedPresenter(events)
    for barcode in app.current_tray.scanned_barcodes:
        app.warning_presenter.record_normal_scan(barcode)
    events.clear()
    app.worker_name = "홍길동"
    app.completed_master_labels = set()
    app.work_summary = {}
    app.total_tray_count = 0
    app.completed_tray_times = []
    app.tray_last_end_time = None
    app._scan_callback_epoch = 0
    app.scanned_listbox = HeadlessListbox(
        [
            _display_row(3, THIRD_BARCODE),
            _display_row(2, SECOND_BARCODE),
            _display_row(1, FIRST_BARCODE),
        ]
    )
    app.undo_button = {"state": container_audit_module.tk.NORMAL}
    app.COLOR_DANGER = "danger"
    app.COLOR_SUCCESS = "success"
    app.COLOR_PRIMARY = "primary"
    app.status_message_job = None
    app.root = HeadlessRoot()
    app._warning_beep_active = False
    app.error_sound = None
    app._prepare_and_attempt_transfer_seal = lambda **kwargs: SealAttempt(
        intent_id="intent-1",
        status=seal_status,
        receipt_id="receipt-1" if seal_status == "ACKED" else "",
        error_code="MEMBERSHIP_CONFLICT" if seal_status == "OPERATOR_REVIEW" else "",
        error_message="membership conflict" if seal_status == "OPERATOR_REVIEW" else "",
        retryable=seal_status == "RETRY_WAIT",
    )

    def log_event(event, detail=None, synchronous=False, **kwargs):
        events.append(("log_event", event, synchronous))
        if event == "TRAY_COMPLETE":
            return ledger_succeeds
        return True

    app._log_event = log_event
    app.show_status_message = lambda *args, **kwargs: events.append(("status", args[0]))
    app._stop_stopwatch = lambda: events.append(("stop_stopwatch", None))
    app._stop_idle_checker = lambda: events.append(("stop_idle", None))
    app._remember_completed_master_label = lambda label: events.append(("remember_label", label))
    app._update_best_time_records = lambda value: None
    app._delete_current_tray_state = lambda: events.append(("delete_state", None)) or True
    app._update_all_summaries = lambda: events.append(("update_summaries", None))
    app._reset_ui_to_waiting_state = lambda: events.append(("reset_ui", None))
    app._render_warning_state = lambda: events.append(("render", None))
    app._update_action_button_states = lambda: events.append(("update_actions", None))
    app._start_warning_beep = lambda: events.append(("start_beep", None))
    app._stop_warning_beep = lambda: events.append(("stop_beep", None))
    return app


def test_last_normal_scan_advances_only_after_current_state_save_succeeds():
    events = []
    app = _scan_app(save_succeeds=True, events=events)

    app._process_barcode_logic(SECOND_BARCODE)

    assert app.warning_presenter.state.last_normal_scan == SECOND_BARCODE
    assert app.current_tray.scanned_barcodes == [FIRST_BARCODE, SECOND_BARCODE]
    assert events.index(("save_state", True)) < events.index(("record_normal_scan", SECOND_BARCODE))


def test_state_save_failure_rolls_back_scan_and_preserves_previous_last_normal():
    events = []
    app = _scan_app(save_succeeds=False, events=events)

    app._process_barcode_logic(SECOND_BARCODE)

    assert app.warning_presenter.state.last_normal_scan == FIRST_BARCODE
    assert app.current_tray.scanned_barcodes == [FIRST_BARCODE]
    assert app.scanned_listbox.rows == [_display_row(1, FIRST_BARCODE)]
    assert not any(event[0] == "record_normal_scan" for event in events)
    assert not any(event[:2] == ("log_event", "SCAN_OK") for event in events)


def test_duplicate_scan_preserves_tray_rows_and_previous_last_normal():
    events = []
    app = _scan_app(save_succeeds=True, events=events)
    original_tray = app.current_tray
    original_rows = list(app.scanned_listbox.rows)

    app._process_barcode_logic(FIRST_BARCODE)

    assert app.current_tray is original_tray
    assert app.current_tray.scanned_barcodes == [FIRST_BARCODE]
    assert app.scanned_listbox.rows == original_rows
    assert app.warning_presenter.state.last_normal_scan == FIRST_BARCODE
    assert app.warning_presenter.state.active_notice.code == "scan.바코드_중복"
    assert FIRST_BARCODE not in app.warning_presenter.state.active_notice.message
    assert "|" not in app.warning_presenter.state.active_notice.message
    assert "=" not in app.warning_presenter.state.active_notice.message
    assert not any(event[0] == "record_normal_scan" for event in events)


def test_operator_review_preserves_active_tray_and_center_rows_without_completion_or_reset():
    events = []
    app = _completion_app(seal_status="OPERATOR_REVIEW", ledger_succeeds=True, events=events)
    original_tray = app.current_tray
    original_rows = list(app.scanned_listbox.rows)

    assert app.complete_tray() is False

    assert app.current_tray is original_tray
    assert app.current_tray.scanned_barcodes == [FIRST_BARCODE, SECOND_BARCODE, THIRD_BARCODE]
    assert app.scanned_listbox.rows == original_rows
    assert app.warning_presenter.state.completion.outcome is CompletionOutcome.OPERATOR_REVIEW
    assert app.warning_presenter.state.is_blocking is True
    assert not any(event[:2] == ("log_event", "TRAY_COMPLETE") for event in events)
    assert not any(event[0] == "reset_ui" for event in events)
    assert not any(event[0] == "delete_state" for event in events)


def test_acknowledging_operator_notice_does_not_release_completion_block():
    events = []
    app = _completion_app(seal_status="OPERATOR_REVIEW", ledger_succeeds=True, events=events)
    app.complete_tray()
    app._schedule_focus_return = lambda: _raise("blocked review must not return scan focus")

    app._acknowledge_active_notice()

    assert app.warning_presenter.state.active_notice is None
    assert app.warning_presenter.state.completion.outcome is CompletionOutcome.OPERATOR_REVIEW
    assert app.warning_presenter.state.is_blocking is True


@pytest.mark.parametrize(
    ("seal_status", "expected_outcome"),
    [("ACKED", CompletionOutcome.ACKED), ("RETRY_WAIT", CompletionOutcome.RETRY_WAIT)],
)
def test_acked_and_retry_wait_snapshots_are_published_after_synchronous_tray_complete(
    seal_status,
    expected_outcome,
):
    events = []
    app = _completion_app(seal_status=seal_status, ledger_succeeds=True, events=events)

    assert app.complete_tray() is True

    completion_event = ("log_event", "TRAY_COMPLETE", True)
    snapshot_event = ("present_completion", expected_outcome)
    assert completion_event in events
    assert snapshot_event in events
    assert events.index(completion_event) < events.index(snapshot_event)
    assert app.warning_presenter.state.completion.outcome is expected_outcome


@pytest.mark.parametrize("seal_status", ["ACKED", "RETRY_WAIT"])
def test_completion_log_failure_does_not_publish_snapshot_or_reset_active_tray(seal_status):
    events = []
    app = _completion_app(seal_status=seal_status, ledger_succeeds=False, events=events)
    original_tray = app.current_tray
    original_rows = list(app.scanned_listbox.rows)

    assert app.complete_tray() is False

    assert ("log_event", "TRAY_COMPLETE", True) in events
    assert not any(event[0] == "present_completion" for event in events)
    assert app.warning_presenter.state.completion is None
    assert app.current_tray is original_tray
    assert app.scanned_listbox.rows == original_rows
    assert not any(event[0] == "reset_ui" for event in events)
