"""Fault recovery preserves UNKNOWN originals before accepting another tray."""
import copy
import datetime
import csv
import json
from pathlib import Path
from types import SimpleNamespace
import threading
import time
import uuid

import pytest

import Container_Audit as module
import tk_serial_ui_lane as serial
from tests.test_scan_persistence_lane import ITEM, app, pump, rows


@pytest.fixture
def recovery_app(app, tmp_path):
    app.computer_id = tmp_path.name
    app.parked_trays_dir = str(tmp_path / "parked")
    app._show_left_sidebar_view = lambda _view: None
    app._update_parked_trays_list = lambda: setattr(
        app, "parked_summaries", app._parked_store().scan_for_worker(app.worker_name, strict=True)
    )
    app._show_field_notice = lambda *args: app.messages.append((args, {}))
    app.show_fullscreen_warning = lambda *args: app.messages.append((args, {}))
    return app


def checkpoint(app):
    assert app._save_current_tray_state()
    source = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    return source, source.read_bytes()


def break_after_work(app, *, barcode=None, work=lambda: None):
    lane = app._ui_task_lane()
    def failed_finish(_value):
        raise RuntimeError("injected callback failure")
    admission = lane.submit(serial.LaneTask(
        "scan-persistence", app._scan_callback_epoch, work, failed_finish,
        lambda _exc: None, barcode=barcode or ITEM + uuid.uuid4().hex,
    ))
    assert admission.accepted
    pump(app, lambda: lane.state in {serial.LANE_CLOSED, serial.LANE_BROKEN})
    return lane, admission.handle, lane.last_task


def _fault_audit_rows(app):
    from event_stream_policy import local_only_event_log_path
    path = local_only_event_log_path(
        app.log_file_path, local_events_dir=getattr(app, "local_events_folder", None))
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def test_fault_preserves_original_unknown_and_accepts_next_tray(recovery_app):
    app = recovery_app
    app.current_tray.scanned_barcodes = [ITEM + uuid.uuid4().hex]
    app.current_tray.scan_times = [datetime.datetime.now()]
    source, original = checkpoint(app)
    label = app.current_tray.master_label_code
    before = copy.deepcopy((app.work_summary, app.total_tray_count, app.completed_master_labels))
    generation = app._scan_callback_epoch
    held_barcode = ITEM + "000002"
    app._scans_behind_save = [held_barcode]
    old, handle, task = break_after_work(app)
    assert not old.worker_thread.is_alive() and handle.join(0)
    assert old is not app._ui_lane and app._ui_lane.state == serial.LANE_IDLE
    assert app._scan_callback_epoch == generation + 1
    assert not source.exists()
    assert next(source.parent.glob(source.name + ".bad-*")).read_bytes() == original
    saved = app._parked_store().load(next(Path(app.parked_trays_dir).glob("parked_recovery_*.json")))
    fault = saved["ui_lane_fault"]
    assert fault["result"] == "UNKNOWN" and fault["barcode"] == task.barcode
    assert fault["master_label_code"] == label and fault["generation"] == generation
    assert fault["task"] == task.name and fault["occurred_at"]
    assert fault["held_scans"] == [held_barcode] and not app._scans_behind_save
    assert saved["scanned_barcodes"] == json.loads(original)["scanned_barcodes"]
    assert (app.work_summary, app.total_tray_count, app.completed_master_labels) == before
    durable = [json.loads(row["details"]) for row in _fault_audit_rows(app) if row["event"] == "UI_LANE_FAULT"]
    assert len(durable) == 1 and durable[0]["result"] == "UNKNOWN"
    assert app.parked_summaries and "관리자 확인 대기" in app.parked_summaries[0].item_name
    assert not app._scan_entry_admission_block_reason()
    assert app._paired_preflight_blocks_label(label)
    # Exercise the existing transition-mode scanner route, including activation
    # checkpoint/audit and the next product's actual persistence worker.
    app.legacy_label_transition = True
    app.show_tray_image_var = SimpleNamespace(set=lambda _value: None)
    app._update_tray_image_display = lambda: None
    app._start_stopwatch = lambda: None
    app.scan_entry.insert(0, ITEM)
    app.process_barcode()
    pump(app, lambda: app.current_tray.master_label_code == ITEM)
    barcode = ITEM + "000001"
    app.scan_entry.insert(0, barcode)
    app.process_barcode()
    pump(app, lambda: app.current_tray.scanned_barcodes == [barcode] and not app._ui_lane.is_busy())
    assert json.loads(source.read_text(encoding="utf-8"))["scanned_barcodes"] == [barcode]
    app.scan_entry.insert(0, barcode)
    app.process_barcode()
    pump(app, lambda: not app._ui_lane.is_busy() and not app._scan_callback_pending)
    assert app.current_tray.scanned_barcodes == [barcode]
    assert saved["ui_lane_fault"]["result"] == "UNKNOWN"


def test_late_old_envelopes_and_callbacks_cannot_change_replacement(recovery_app):
    app = recovery_app
    checkpoint(app)
    old, _, task = break_after_work(app)
    applied = []
    late_task = serial.LaneTask(task.name, task.generation, lambda: None,
                                applied.append, applied.append)
    old._apply_terminal_result(serial._Envelope(1, 1, task.generation, "success", late_task, "late"))
    ui_call = serial._UiCall(applied.append, ("late-ui",), {}, threading.Event())
    old._apply_ui_call(serial._Envelope(1, 1, task.generation, "ui_call", None, ui_call))
    app._process_barcode_if_current(ITEM + "000002", task.generation)
    assert not applied and isinstance(ui_call.error, serial.StaleUiGenerationError)
    assert not app.current_tray.master_label_code and not app.current_tray.scanned_barcodes
    assert not (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).exists()


def test_break_releases_ui_checkpoint_waiter_before_join(recovery_app):
    app = recovery_app
    checkpoint(app)
    old = app._ui_task_lane()
    applied = []
    admission = old.submit(serial.LaneTask(
        "checkpoint", app._scan_callback_epoch,
        lambda: old.call_ui_sync(applied.append, "late"), applied.append, applied.append,
    ))
    # Wait for enqueue without pumping the UI checkpoint.
    deadline = time.monotonic() + 5
    while old._result_queue.empty():
        assert time.monotonic() < deadline
        threading.Event().wait(0.002)
    old._break_lane(RuntimeError("injected checkpoint break"))
    assert not old.worker_thread.is_alive() and admission.handle.join(0)
    assert not applied and old is not app._ui_lane


def test_stuck_worker_stays_blocked_without_new_writer(recovery_app):
    app = recovery_app
    source, original = checkpoint(app)
    old = app._ui_task_lane()
    started, release = threading.Event(), threading.Event()
    old.submit(serial.LaneTask("blocked-disk", app._scan_callback_epoch,
                              lambda: (started.set(), release.wait()), lambda _: None, lambda _: None))
    assert started.wait(5)
    try:
        began = time.perf_counter()
        old._break_lane(RuntimeError("injected while disk is blocked"))
        assert time.perf_counter() - began < 2.5
        assert old.worker_thread.is_alive() and app._ui_task_lane() is old
        assert app._ui_lane_fault_blocked and app._scan_entry_admission_block_reason()
        assert source.read_bytes() == original and not app.current_tray.scanned_barcodes
    finally:
        release.set()
        old.worker_thread.join(5)
        old.close_idle()


@pytest.mark.parametrize("failure", ["record", "parked", "quarantine"])
def test_failed_durability_keeps_original_and_stops(recovery_app, monkeypatch, failure):
    app = recovery_app
    source, original = checkpoint(app)
    def denied(*_args, **_kwargs):
        raise OSError("injected preservation failure")
    if failure == "record":
        monkeypatch.setattr(app, "_log_event", lambda *a, **k: False)
    elif failure == "parked":
        monkeypatch.setattr(app._parked_store(), "defer_recovery_state", denied)
    else:
        monkeypatch.setattr(app, "_quarantine_current_tray_state", lambda _reason: None)
    old, _, _ = break_after_work(app)
    assert app._ui_lane_fault_blocked and app._ui_task_lane() is old
    assert app._scan_entry_admission_block_reason() and app._operator_review_blocks_mutation()
    assert source.read_bytes() == original and app.current_tray.master_label_code
    if failure == "record":
        assert old.state == serial.LANE_BROKEN
        assert not Path(app.parked_trays_dir).exists()


@pytest.mark.parametrize("same_tray", [False, True])
def test_fault_budget_stops_third_in_ten_minutes_or_second_same_tray(recovery_app, same_tray):
    app = recovery_app
    label = app.current_tray.master_label_code
    initial = copy.deepcopy(app.current_tray)
    attempts = 2 if same_tray else 3
    for number in range(attempts):
        app.current_tray = copy.deepcopy(initial)
        if not same_tray:
            app.current_tray.master_label_code = label + str(number)
        elif number:
            app._ui_lane_fault_times = [time.monotonic() - 601]
        checkpoint(app)
        old, _, _ = break_after_work(app)
        if number < attempts - 1:
            assert not app._ui_lane_fault_blocked and app._ui_lane is not old
        else:
            assert app._ui_lane_fault_blocked and app._ui_task_lane() is old
            assert not old.worker_thread.is_alive()
            assert app._scan_entry_admission_block_reason()


def test_faults_older_than_ten_minutes_do_not_exhaust_budget(recovery_app):
    app = recovery_app
    app._ui_lane_fault_times = [time.monotonic() - 601] * 2
    checkpoint(app)
    old, _, _ = break_after_work(app)
    assert not app._ui_lane_fault_blocked and app._ui_lane is not old
    assert len(app._ui_lane_fault_times) == 1


def test_unknown_parked_restore_preserves_file_without_reprocessing(recovery_app):
    app = recovery_app
    checkpoint(app)
    break_after_work(app)
    parked = next(Path(app.parked_trays_dir).glob("parked_recovery_*.json"))
    original = parked.read_bytes()
    app.restore_parked_tray(str(parked))
    assert parked.read_bytes() == original
    assert not app.current_tray.master_label_code and not app.current_tray.scanned_barcodes
    assert app.messages and "관리자 확인 대기" in app.messages[-1][0][0]


def test_fault_record_precedes_stop_and_original_release(recovery_app, monkeypatch):
    app = recovery_app
    source, original = checkpoint(app)
    old = app._ui_task_lane()
    original_log, original_close = app._log_event, old.close_idle
    stages = []
    def logged(*args, **kwargs):
        assert source.read_bytes() == original and old.worker_thread.is_alive()
        result = original_log(*args, **kwargs)
        stages.append("durable")
        return result
    def closed():
        assert stages == ["durable"] and source.exists()
        assert app._scan_callback_epoch == old.last_task.generation
        original_close()
        stages.append("stopped")
    monkeypatch.setattr(app, "_log_event", logged)
    monkeypatch.setattr(old, "close_idle", closed)
    break_after_work(app)
    assert stages == ["durable", "stopped"] and not old.worker_thread.is_alive()


@pytest.mark.parametrize("active_tray", [True, False])
def test_preflight_original_and_unknown_hold_survive_without_replay(recovery_app, active_tray):
    app = recovery_app
    master = app.current_tray.master_label_code
    if active_tray:
        checkpoint(app)
    else:
        app.current_tray = module.TraySession()
    hold = app._preflight_hold_store()
    held = hold.start(master_raw=master,
                      worker=app.worker_name, scan_epoch=app._scan_callback_epoch)
    hold.append(ITEM + "000002")
    app._preflight_hold_snapshot = hold.load()
    original = hold.path.read_bytes()
    break_after_work(app)
    quarantined = next(app._preflight_hold_quarantine_directory().glob("preflight_hold_*.json"))
    assert not hold.exists() and quarantined.read_bytes() == original
    saved = app._parked_store().load(next(Path(app.parked_trays_dir).glob("parked_recovery_*.json")))
    assert saved["ui_lane_fault"]["result"] == "UNKNOWN"
    assert saved["ui_lane_fault"]["master_label_code"] == master
    assert saved["ui_lane_fault"]["preflight_hold"]["preflight_id"] == held.preflight_id
    assert app._preflight_hold_snapshot is None
    assert app._paired_preflight_blocks_label(held.master_raw, restoring_paths=(quarantined,))
    assert not app.current_tray.scanned_barcodes
    assert not app._scan_entry_admission_block_reason()


def test_fault_during_shutdown_records_but_does_not_resume(recovery_app):
    app = recovery_app
    source, original = checkpoint(app)
    app._ui_close_requested = True
    old, _, _ = break_after_work(app)
    assert app._ui_task_lane() is old and old.state == serial.LANE_BROKEN
    assert source.read_bytes() == original and app._ui_lane_fault_blocked
    assert any(row["event"] == "UI_LANE_FAULT" for row in _fault_audit_rows(app))


@pytest.mark.parametrize("pending", ["write", "result"])
def test_pending_hold_writer_prevents_a_new_lane(recovery_app, pending):
    import queue
    app = recovery_app
    source, original = checkpoint(app)
    tasks, results = queue.Queue(), queue.Queue()
    (tasks if pending == "write" else results).put(object())
    app._preflight_hold_writer_instance = SimpleNamespace(tasks=tasks, results=results)
    old, _, _ = break_after_work(app)
    assert not old.worker_thread.is_alive() and app._ui_task_lane() is old
    assert app._ui_lane_fault_blocked and source.read_bytes() == original


def test_callback_clearing_tray_cannot_erase_original_request_identity(recovery_app):
    app = recovery_app
    source, original = checkpoint(app)
    old = app._ui_task_lane()
    label = app.current_tray.master_label_code
    def fail_after_reset(_value):
        app.current_tray = module.TraySession()
        raise RuntimeError("injected after callback reset")
    old.submit(serial.LaneTask("tray-completion", app._scan_callback_epoch,
                              lambda: None, fail_after_reset, lambda _: None))
    pump(app, lambda: old.state == serial.LANE_CLOSED)
    saved = app._parked_store().load(next(Path(app.parked_trays_dir).glob("parked_recovery_*.json")))
    assert saved["master_label_code"] == label
    assert saved["ui_lane_fault"]["master_label_code"] == label
    assert saved["ui_lane_fault"]["result"] == "UNKNOWN"
    assert next(source.parent.glob(source.name + ".bad-*")).read_bytes() == original
    assert not app._scan_entry_admission_block_reason()
