import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit, TraySession
from parked_tray_store import ParkedTrayStore
from transfer_seal import SealAttempt
from tray_state import tray_session_to_state
from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    WarningPresenter,
)


ITEM_CODE = "AAA2270730100"
MASTER_LABEL = f"PHS=1|CLC={ITEM_CODE}|QT=1"
PRODUCT_BARCODE = f"{ITEM_CODE}-001"


class RecordingRoot:
    def __init__(self):
        self.callbacks = {}
        self.cancelled = set()
        self._next_job = 1

    def after(self, _delay, callback, *args):
        job_id = f"after-{self._next_job}"
        self._next_job += 1
        self.callbacks[job_id] = (callback, args)
        return job_id

    def after_cancel(self, job_id):
        self.cancelled.add(job_id)

    def fire(self, job_id):
        if job_id in self.cancelled:
            return
        callback, args = self.callbacks[job_id]
        callback(*args)


class DummyWidget:
    def __init__(self, **options):
        self.options = dict(options)

    def configure(self, **options):
        self.options.update(options)

    config = configure

    def __getitem__(self, key):
        return self.options[key]

    def __setitem__(self, key, value):
        self.options[key] = value

    def winfo_exists(self):
        return True


class DummyListbox:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def delete(self, index, *rest):
        if rest:
            self.rows.clear()
        elif self.rows:
            del self.rows[index]

    def insert(self, index, value):
        if index == 0:
            self.rows.insert(0, value)
        else:
            self.rows.append(value)

    def itemconfig(self, *_args, **_kwargs):
        return None

    def winfo_exists(self):
        return True

    def size(self):
        return len(self.rows)

    def get(self, index):
        return self.rows[index]


class DummyVar:
    def __init__(self, value=False):
        self.value = value

    def set(self, value):
        self.value = value


class RecordingParkedStore:
    def __init__(self, calls):
        self.calls = calls

    def save_state(self, state, *, worker_name, master_label):
        self.calls.append(("save_parked", state, worker_name, master_label))
        return Path("parked-review-fixture.json")


def _active_tray(*, master_label=MASTER_LABEL, barcode=PRODUCT_BARCODE):
    return TraySession(
        master_label_code=master_label,
        item_code=ITEM_CODE,
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=[barcode],
        scan_times=[datetime.datetime(2026, 7, 15, 9, 0, 0)],
        tray_size=1,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 7, 15, 8, 59, 0),
        has_error_or_reset=True,
    )


def _review_snapshot():
    return CompletionOutcomeSnapshot(
        outcome=CompletionOutcome.OPERATOR_REVIEW,
        item_name="fixture item",
        master_label=MASTER_LABEL,
        scan_count=1,
        target_count=1,
        message="담당자 확인이 필요한 서버 판정입니다.",
        error_code="MEMBERSHIP_CONFLICT",
    )


def _operator_review_app(*, active_tray=True):
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = _active_tray() if active_tray else TraySession()
    app.worker_name = "review-worker"
    app.warning_presenter = WarningPresenter()
    if active_tray:
        app.warning_presenter.record_normal_scan(PRODUCT_BARCODE)
    app.warning_presenter.present_completion(_review_snapshot())
    app.root = RecordingRoot()
    app.status_message_job = None
    app.COLOR_DANGER = "danger"
    app.COLOR_SUCCESS = "success"
    app.COLOR_PRIMARY = "primary"
    app.COLOR_TEXT = "text"
    app.COLOR_TEXT_SUBTLE = "subtle"
    app.COLOR_SIDEBAR_BG = "sidebar"
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.current_exchange_session = SimpleNamespace(defective_barcodes=[], good_barcodes=[])
    app.exchange_dialog = None
    app.error_sound = None
    app._warning_beep_active = False
    app._render_warning_state = lambda: None
    app._start_warning_beep = lambda: None
    app._stop_warning_beep = lambda: None
    return app


def _stub_guard_feedback(app):
    app._update_action_button_states = lambda: None
    app._schedule_focus_return = lambda: None


def _completion_app(*, delete_succeeds, prior_operator_review):
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = _active_tray()
    app.worker_name = "completion-worker"
    app.warning_presenter = WarningPresenter()
    app.warning_presenter.record_normal_scan(PRODUCT_BARCODE)
    if prior_operator_review:
        app.warning_presenter.present_completion(_review_snapshot())
    app.root = RecordingRoot()
    app.status_message_job = None
    app.COLOR_DANGER = "danger"
    app.COLOR_SUCCESS = "success"
    app.COLOR_PRIMARY = "primary"
    app.COLOR_TEXT = "text"
    app.completed_master_labels = set()
    app.work_summary = {}
    app.total_tray_count = 0
    app.completed_tray_times = []
    app.tray_last_end_time = None
    app.error_sound = None
    app._warning_beep_active = False
    app.scanned_listbox = DummyListbox([f"(1) {PRODUCT_BARCODE}"])
    app.undo_button = DummyWidget(state=container_audit_module.tk.NORMAL)
    app._prepare_and_attempt_transfer_seal = lambda **_kwargs: SealAttempt(
        intent_id="intent-acked",
        status="ACKED",
        receipt_id="receipt-acked",
    )
    app._log_event = lambda *_args, **_kwargs: True
    app._stop_stopwatch = lambda: None
    app._stop_idle_checker = lambda: None
    app._remember_completed_master_label = lambda _label: None
    app._delete_current_tray_state = lambda: delete_succeeds
    app._invalidate_pending_scan_callbacks = lambda: None
    app._update_all_summaries = lambda: None
    app._reset_ui_to_waiting_state = lambda: None
    app._render_warning_state = lambda: None
    app._update_action_button_states = lambda: None
    app._start_warning_beep = lambda: None
    app._stop_warning_beep = lambda: None
    return app


def test_operator_review_disables_active_tray_mutation_buttons():
    app = _operator_review_app()
    app.reset_button = DummyWidget()
    app.park_button = DummyWidget()
    app.undo_button = DummyWidget()
    app.submit_tray_button = DummyWidget()
    app.replace_master_label_button = DummyWidget()
    app.exchange_button = DummyWidget()
    app._exact_transfer_exchange_blocked = lambda: False
    app._use_compact_action_labels = lambda: False

    app._update_action_button_states()

    actual_states = {
        "reset": app.reset_button["state"],
        "park": app.park_button["state"],
        "undo": app.undo_button["state"],
        "submit": app.submit_tray_button["state"],
    }
    assert actual_states == {
        "reset": container_audit_module.tk.DISABLED,
        "park": container_audit_module.tk.DISABLED,
        "undo": container_audit_module.tk.DISABLED,
        "submit": container_audit_module.tk.DISABLED,
    }


def test_operator_review_does_not_expose_submit_retry_command_or_label():
    app = _operator_review_app()
    app.reset_button = DummyWidget()
    app.park_button = DummyWidget()
    app.undo_button = DummyWidget()
    app.submit_tray_button = DummyWidget()
    app.replace_master_label_button = DummyWidget()
    app.exchange_button = DummyWidget()
    app._exact_transfer_exchange_blocked = lambda: False
    app._use_compact_action_labels = lambda: False

    app._update_action_button_states()

    command = app.submit_tray_button.options.get("command")
    assert app.submit_tray_button["state"] == container_audit_module.tk.DISABLED
    assert "다시" not in str(app.submit_tray_button.options.get("text", ""))
    assert getattr(command, "__name__", "") != "_retry_operator_review_completion"


def test_stale_operator_review_disables_replacement_and_exchange_buttons():
    app = _operator_review_app(active_tray=False)
    app.reset_button = DummyWidget()
    app.park_button = DummyWidget()
    app.undo_button = DummyWidget()
    app.submit_tray_button = DummyWidget()
    app.replace_master_label_button = DummyWidget()
    app.exchange_button = DummyWidget()
    app._exact_transfer_exchange_blocked = lambda: False
    app._use_compact_action_labels = lambda: False

    app._update_action_button_states()

    assert app.replace_master_label_button["state"] == container_audit_module.tk.DISABLED
    assert app.exchange_button["state"] == container_audit_module.tk.DISABLED


def test_operator_review_blocks_undo_without_mutating_or_persisting_scan():
    app = _operator_review_app()
    calls = []
    original_tray = app.current_tray
    original_barcodes = list(original_tray.scanned_barcodes)
    original_scan_times = list(original_tray.scan_times)
    app.scanned_listbox = DummyListbox([f"(1) {PRODUCT_BARCODE}"])
    original_rows = list(app.scanned_listbox.rows)
    app.undo_button = DummyWidget(state=container_audit_module.tk.NORMAL)
    app._update_last_activity_time = lambda: None
    app._save_current_tray_state = lambda: calls.append("save") or True
    app._log_event = lambda *_args, **_kwargs: calls.append("log") or True
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda: None
    _stub_guard_feedback(app)

    app.undo_last_scan()

    assert app.current_tray is original_tray
    assert app.current_tray.scanned_barcodes == original_barcodes
    assert app.current_tray.scan_times == original_scan_times
    assert app.scanned_listbox.rows == original_rows
    assert calls == []


def test_operator_review_blocks_reset_before_confirmation_or_state_delete(monkeypatch):
    app = _operator_review_app()
    calls = []
    prompts = []
    original_tray = app.current_tray
    app.scanned_listbox = DummyListbox([f"(1) {PRODUCT_BARCODE}"])
    app.undo_button = DummyWidget(state=container_audit_module.tk.NORMAL)
    app._update_last_activity_time = lambda: None
    app._current_tray_state_snapshot = lambda: calls.append("snapshot") or {}
    app._delete_current_tray_state = lambda: calls.append("delete") or True
    app._log_event = lambda *_args, **_kwargs: calls.append("log") or True
    app._stop_stopwatch = lambda: None
    app._stop_idle_checker = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app._sync_last_normal_scan_from_active_tray = lambda **_kwargs: None
    app._update_all_summaries = lambda: None
    app._reset_ui_to_waiting_state = lambda: None
    _stub_guard_feedback(app)
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        lambda *_args, **_kwargs: prompts.append("reset") or True,
    )
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *_args, **_kwargs: None)

    app.reset_current_work()

    assert app.current_tray is original_tray
    assert prompts == []
    assert calls == []


def test_operator_review_blocks_park_without_writing_parked_or_current_state():
    app = _operator_review_app()
    calls = []
    original_tray = app.current_tray
    app.scanned_listbox = DummyListbox([f"(1) {PRODUCT_BARCODE}"])
    app._current_tray_state_snapshot = lambda: calls.append("snapshot") or {"fixture": True}
    app._parked_store = lambda: RecordingParkedStore(calls)
    app._delete_current_tray_state = lambda: calls.append("delete_current") or True
    app._log_event = lambda *_args, **_kwargs: calls.append("log") or True
    app._invalidate_pending_scan_callbacks = lambda: None
    app._sync_last_normal_scan_from_active_tray = lambda **_kwargs: None
    app._reset_ui_to_waiting_state = lambda: None
    app._update_all_summaries = lambda: None
    app._update_parked_trays_list = lambda: None
    _stub_guard_feedback(app)

    result = app.park_current_tray(confirm=False)

    assert result is False
    assert app.current_tray is original_tray
    assert calls == []


def test_operator_review_blocks_restore_without_replacing_current_tray(monkeypatch, tmp_path):
    app = _operator_review_app()
    calls = []
    original_tray = app.current_tray
    restored_tray = _active_tray(
        master_label=f"PHS=1|CLC={ITEM_CODE}|QT=1|LOT=RESTORED",
        barcode=f"{ITEM_CODE}-RESTORED-001",
    )
    saved_state = tray_session_to_state(restored_tray, worker_name=app.worker_name)
    app.save_folder = str(tmp_path)
    app._is_parked_tray_path = lambda _path: True
    app._is_completed_master_label = lambda _label: False
    app._save_tray_state_snapshot = lambda _state: calls.append("save_restored") or True
    app._log_current_tray_discarded = lambda **_kwargs: calls.append("discard_current") or True
    app._log_event = lambda *_args, **_kwargs: calls.append("log_restore") or True
    app._invalidate_pending_scan_callbacks = lambda: None
    app.show_validation_screen = lambda: None
    app.show_tray_image_var = DummyVar()
    app._update_tray_image_display = lambda: None
    app._update_parked_trays_list = lambda: None
    _stub_guard_feedback(app)
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ParkedTrayStore, "load", staticmethod(lambda _path: saved_state))
    monkeypatch.setattr(
        ParkedTrayStore,
        "delete",
        staticmethod(lambda _path: calls.append("delete_parked")),
    )

    app.restore_parked_tray(str(tmp_path / "parked-review-fixture.json"))

    assert app.current_tray is original_tray
    assert calls == []


def test_operator_review_blocks_worker_change_before_pause_or_context_reset(monkeypatch):
    app = _operator_review_app()
    calls = []
    prompts = []
    original_tray = app.current_tray
    original_worker = app.worker_name
    app._save_current_tray_state = lambda: calls.append("save") or True
    app._log_event = lambda *_args, **_kwargs: calls.append("log_pause") or True
    app._cancel_all_jobs = lambda: calls.append("cancel_jobs")
    app._invalidate_pending_scan_callbacks = lambda: calls.append("invalidate_scans")
    app._reset_master_label_replacement_state = lambda: calls.append("reset_replacement")
    app.show_worker_input_screen = lambda: calls.append("show_login")
    _stub_guard_feedback(app)
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        lambda *_args, **_kwargs: prompts.append("change_worker") or True,
    )
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *_args, **_kwargs: None)

    app.change_worker()

    assert app.worker_name == original_worker
    assert app.current_tray is original_tray
    assert prompts == []
    assert calls == []


def test_stale_operator_review_blocks_replacement_entrypoint(monkeypatch):
    app = _operator_review_app(active_tray=False)
    calls = []
    app._log_event = lambda event, **_kwargs: calls.append(event) or True
    app._invalidate_pending_scan_callbacks = lambda: calls.append("invalidate_scans")
    app._update_current_item_label = lambda: None
    _stub_guard_feedback(app)
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *_args, **_kwargs: None)

    app.initiate_master_label_replacement()

    assert app.master_label_replace_state is None
    assert calls == []


def test_stale_operator_review_blocks_exchange_entrypoint(monkeypatch):
    app = _operator_review_app(active_tray=False)
    calls = []

    class ExchangeDialogReached(RuntimeError):
        pass

    def open_exchange_dialog(*_args, **_kwargs):
        calls.append("open_exchange_dialog")
        raise ExchangeDialogReached

    app._block_unsafe_exact_exchange = lambda: False
    app._invalidate_pending_scan_callbacks = lambda: calls.append("invalidate_scans")
    _stub_guard_feedback(app)
    monkeypatch.setattr(container_audit_module.tk, "Toplevel", open_exchange_dialog)

    try:
        app.show_exchange_dialog()
    except ExchangeDialogReached:
        pass

    assert calls == []


def test_state_delete_failure_releases_stale_operator_review_block_after_durable_completion():
    app = _completion_app(delete_succeeds=False, prior_operator_review=True)
    # Isolate the post-ledger cleanup path: this models a completion attempt
    # already admitted before a stale presenter snapshot became observable.
    app._operator_review_blocks_mutation = lambda: False

    assert app.complete_tray() is True

    state = app.warning_presenter.state
    assert state.is_blocking is False
    assert state.completion is None or state.completion.outcome is not CompletionOutcome.OPERATOR_REVIEW


def test_old_status_timer_cannot_clear_new_completion_notice():
    app = _completion_app(delete_succeeds=True, prior_operator_review=False)
    app.show_status_message("이전 임시 상태", app.COLOR_PRIMARY, duration=4000)
    old_job = app.status_message_job

    assert old_job is not None
    assert app.complete_tray() is True
    assert app.warning_presenter.state.active_notice is not None
    assert app.warning_presenter.state.active_notice.code == "completion.acked"

    app.root.fire(old_job)

    assert app.warning_presenter.state.completion is not None
    assert app.warning_presenter.state.completion.outcome is CompletionOutcome.ACKED
    assert app.warning_presenter.state.active_notice is not None
    assert app.warning_presenter.state.active_notice.code == "completion.acked"
