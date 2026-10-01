"""Durable ACK, UI affinity and FIFO regressions without native Tk or audio."""
import csv
import datetime
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as module
import storage_utils
from Container_Audit import TraySession
from tests.test_container_audit_contracts import _completion_app, CapturingListbox
from tests.test_observed_scanner_completion import ScannerEntry
from tests.test_tk_serial_ui_lane import FakeTkRoot
from transfer_seal import SealAttempt

pytestmark = pytest.mark.usefixtures("owned_tk_workers")
ITEM = "AAA2270730100"


@pytest.fixture
def app(tmp_path):
    instance = _completion_app(tmp_path)
    instance.root = FakeTkRoot()
    instance.root.tk = object()  # Select the live entrypoint, without creating Tk.
    instance.scan_entry = ScannerEntry()
    instance.scanned_listbox = CapturingListbox()
    instance.current_tray = TraySession(
        master_label_code=f"PHS=1|CLC={ITEM}|QT=3", item_code=ITEM,
        item_name="fixture item", tray_size=3, start_time=datetime.datetime.now(),
    )
    instance.items_data = [{"Item Code": ITEM}]
    instance.master_label_replace_state = None
    instance._scan_callback_epoch = 1
    instance.is_idle = False
    instance.last_activity_time = datetime.datetime.now()
    instance._update_last_activity_time = lambda: None
    instance._schedule_startup_transfer_recovery = lambda: None
    instance._schedule_focus_return = lambda *args, **kwargs: None
    instance._trigger_session_direct_sync = lambda reason: None
    instance._update_action_button_states = lambda: None
    instance._stop_warning_beep = lambda: None
    instance._start_warning_beep = lambda: None
    instance.sounds = []
    instance.renders = []
    owner = threading.get_ident()

    def render():
        assert threading.get_ident() == owner
        instance.renders.append(tuple(instance.current_tray.scanned_barcodes))

    instance._update_center_display = render
    instance._update_current_item_label = lambda: None
    instance._render_warning_state = lambda: None
    instance.success_sound = SimpleNamespace(play=lambda: instance.sounds.append(threading.get_ident()))
    instance.log_thread = threading.Thread(target=instance._event_log_writer, name="test-event-writer")
    instance.log_thread.start()
    try:
        yield instance
    finally:
        try:
            lane = getattr(instance, "_ui_lane", None)
            if lane is not None:
                try:
                    if lane.is_busy():
                        instance.root.run_until(lambda: not lane.is_busy(), timeout=10)
                finally:
                    lane.close_idle()
        finally:
            if instance.log_thread.is_alive():
                instance.log_queue.put(None)
                instance.log_thread.join(timeout=10)
            assert not instance.log_thread.is_alive()


def pump(app, predicate):
    def ready():
        complete = predicate()
        if not complete:
            # FakeTkRoot ignores after() delays; yield as Tk's real event wait
            # does, so its polling callbacks cannot starve the durable worker.
            time.sleep(0.002)
        return complete
    app.root.run_until(ready, timeout=10)


def rows(app):
    with open(app.log_file_path, encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


@pytest.mark.parametrize("held", [False, True])
def test_scan_ack_keeps_count_sound_and_next_input_behind_worker_fsync(app, monkeypatch, held):
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot
    fsync = storage_utils.os.fsync
    fsync_threads = []
    owner = threading.get_ident()

    def fsync_spy(fd):
        fsync_threads.append(threading.get_ident())
        return fsync(fd)

    def delayed(state):
        assert threading.get_ident() != owner, "durable scan persistence must not block Tk"
        entered.set()
        assert release.wait(timeout=5)
        return save(state)

    monkeypatch.setattr(storage_utils.os, "fsync", fsync_spy)
    app._save_tray_state_snapshot = delayed
    try:
        # Keep the 100 ms execution budget, excluding host descheduling. The
        # unreleased worker barrier and thread assertion separately prove that
        # fsync cannot synchronously block this call or publish success early.
        started = time.thread_time()
        app._process_barcode_logic(ITEM + "-1", _durable_scan_log=held,
                                  _durable_scan_id="held-1" if held else "")
        assert time.thread_time() - started < 0.1
        pump(app, entered.is_set)
        assert app.current_tray.scanned_barcodes == []
        assert app.scanned_listbox.rows == []
        assert app.sounds == []
        app.scan_entry.insert("end", ITEM + "-2")
        app.process_barcode()
        # The next scan leaves the entry at once and waits behind the fsync.
        assert app.scan_entry.get() == ""
        assert app._scans_behind_save == [ITEM + "-2"]
        release.set()
        pump(app, lambda: not app._ui_lane.is_busy())
        assert app.current_tray.scanned_barcodes == [ITEM + "-1"]
        assert app.sounds == [owner]
        assert app.renders == [(ITEM + "-1",)]
        app._save_tray_state_snapshot = save
        pump(app, lambda: len(app.current_tray.scanned_barcodes) == 2 and not app._ui_lane.is_busy())
        app.log_queue.join()
        assert [json.loads(row["details"])["product_barcode"] for row in rows(app)] == [ITEM + "-1", ITEM + "-2"]
        assert fsync_threads and owner not in fsync_threads
    finally:
        release.set()


@pytest.mark.parametrize("failure", ["write", "admission"])
def test_scan_write_failure_retains_previous_disk_state_without_receipt_or_success(app, monkeypatch, failure):
    assert app._save_current_tray_state()
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    original = path.read_bytes()
    if failure == "write":
        monkeypatch.setattr(module, "atomic_write_json", lambda *a, **k: (_ for _ in ()).throw(OSError("disk failed")))
    else:
        app._save_tray_state_snapshot = lambda state: (_ for _ in ()).throw(TimeoutError("admission failed"))
    app._process_barcode_logic(ITEM + "-1", _durable_scan_log=True, _durable_scan_id="held-1")
    pump(app, lambda: not app._ui_lane.is_busy())
    assert app.current_tray.scanned_barcodes == []
    assert not getattr(app.current_tray, "preflight_scan_receipts", {})
    assert app.scanned_listbox.rows == [] and app.sounds == []
    assert path.read_bytes() == original
    assert not Path(app.log_file_path).exists()


def test_scan_late_ack_does_not_mutate_replacement_tray(app):
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot
    def delayed(state):
        entered.set()
        assert release.wait(timeout=5)
        return save(state)
    app._save_tray_state_snapshot = delayed
    try:
        app._process_barcode_logic(ITEM + "-1")
        pump(app, entered.is_set)
        app.current_tray = TraySession(master_label_code="NEW", tray_size=3)
        app._scan_callback_epoch += 1
        release.set()
        pump(app, lambda: not app._ui_lane.is_busy())
        assert app.current_tray.master_label_code == "NEW"
        assert app.current_tray.scanned_barcodes == []
        assert app.sounds == [] and app.scanned_listbox.rows == []
        assert app._scan_persistence_task_handle.stale_generation_error is not None
    finally:
        release.set()


@pytest.mark.parametrize("restart", [False, True])
def test_held_append_ack_loss_replays_csv_content_once_before_fifo_tail(app, monkeypatch, restart):
    store = app._preflight_hold_store()
    store.start(worker=app.worker_name, master_raw=app.current_tray.master_label_code, scan_epoch=1)
    first = store.append(ITEM + "-1")
    second = store.append(ITEM + "-2")
    app._preflight_hold_snapshot = store.mark_draining()
    app._preflight_hold_draining = True
    original = module.append_event_log_entry_idempotent
    calls = []
    def lose_ack(*args, **kwargs):
        calls.append((kwargs["idempotency_key"], threading.get_ident()))
        result = original(*args, **kwargs)
        if len(calls) == 1:
            raise OSError("crash after durable CSV append, before FIFO ACK")
        return result
    monkeypatch.setattr(module, "append_event_log_entry_idempotent", lose_ack)
    app._drain_preflight_hold_head()
    pump(app, lambda: not app._ui_lane.is_busy())
    assert store.load().items[0].scan_id == second.scan_id  # durable outbox ACK advances the FIFO
    assert app.current_tray.scanned_barcodes == [ITEM + "-1"]
    assert len(rows(app)) == 1
    if restart:
        from tray_state import tray_session_from_state, validate_tray_state
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text())
        validate_tray_state(state, default_tray_size=3)
        app.current_tray = tray_session_from_state(state, session_factory=TraySession, default_tray_size=3)
        app._preflight_hold_snapshot = store.load()
        app._scan_callback_epoch += 1
    app._drain_preflight_hold_head()
    pump(app, lambda: app._preflight_hold_snapshot is None and not app._ui_lane.is_busy())
    assert not store.exists()
    assert app.current_tray.scanned_barcodes == [ITEM + "-1", ITEM + "-2"]
    assert [json.loads(row["details"])["product_barcode"] for row in rows(app)] == [ITEM + "-1", ITEM + "-2"]
    assert len(app.sounds) == 2
    keys = [key for key, _ in calls]
    assert keys[0] == f"preflight-held-scan:{first.scan_id}"
    assert keys[-1] == f"preflight-held-scan:{second.scan_id}"
    assert set(keys) == {f"preflight-held-scan:{first.scan_id}", f"preflight-held-scan:{second.scan_id}"}
    assert all(thread != threading.get_ident() for _, thread in calls)


def test_close_drains_admitted_scan_and_event_before_destroy(app, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot
    def delayed(state):
        entered.set()
        assert release.wait(timeout=5)
        return save(state)
    app._save_tray_state_snapshot = delayed
    app._end_work_session = lambda **kwargs: True
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: None
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *a, **k: True)
    try:
        app._process_barcode_logic(ITEM + "-1")
        pump(app, entered.is_set)
        app.on_closing(_confirmed=True)
        assert not app.root.destroyed
        release.set()
        pump(app, lambda: app.root.destroyed)
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text())
        assert state["scanned_barcodes"] == [ITEM + "-1"]
        assert len(rows(app)) == 1
        assert app.log_queue.unfinished_tasks == 0
        assert not app.log_thread.is_alive() and not app._ui_lane.worker_thread.is_alive()
    finally:
        release.set()


def test_final_held_ack_finishes_before_completion_is_admitted(app):
    app.current_tray.tray_size = 2
    app.current_tray.master_label_code = f"PHS=1|CLC={ITEM}|QT=2"
    store = app._preflight_hold_store()
    store.start(worker=app.worker_name, master_raw=app.current_tray.master_label_code, scan_epoch=1)
    store.append(ITEM + "-1")
    store.append(ITEM + "-2")
    app._preflight_hold_snapshot = store.mark_draining()
    app._preflight_hold_draining = True
    completed = []

    def complete(**kwargs):
        assert not app._ui_lane.is_busy()
        assert not store.exists()
        assert app._preflight_hold_snapshot is None
        assert [json.loads(row["details"])["product_barcode"] for row in rows(app)] == [ITEM + "-1", ITEM + "-2"]
        completed.append(tuple(app.current_tray.scanned_barcodes))
        return True

    app.request_complete_tray = complete
    app._drain_preflight_hold_head()
    pump(app, lambda: bool(completed))
    assert completed == [(ITEM + "-1", ITEM + "-2")]
    assert not app._preflight_hold_draining


def test_completion_checkpoint_and_csv_fsync_execute_on_worker_in_order(app, monkeypatch):
    now = datetime.datetime.now()
    app.current_tray.scanned_barcodes = [ITEM + "-1"]
    app.current_tray.scan_times = [now]
    app.current_tray.tray_size = 1
    app.current_tray.master_label_code = f"PHS=1|CLC={ITEM}|QT=1"
    app.current_tray.start_time = now - datetime.timedelta(seconds=10)
    app.current_tray.has_error_or_reset = True
    app._transfer_seal_runtime = lambda: SimpleNamespace()
    app._work_transfer_coordinator_ui_snapshot = lambda **kwargs: {}
    app._apply_transfer_coordinator_ui_snapshot = lambda snapshot: None
    app._transfer_member_exchange_blocks_local_action = lambda action: False
    order, fsync_threads = [], []
    fsync = storage_utils.os.fsync
    save = app._save_tray_state_snapshot
    def saved(state):
        result = save(state)
        order.append("checkpoint")
        return result
    def prepare(*, on_prepared, **kwargs):
        attempt = SealAttempt("intent-worker", "ACKED", receipt_id="fixture-receipt")
        on_prepared(attempt)
        order.append("central")
        return attempt
    def synced(fd):
        fsync_threads.append(threading.get_ident())
        return fsync(fd)
    app._save_tray_state_snapshot = saved
    app._prepare_and_attempt_transfer_seal_snapshot = prepare
    monkeypatch.setattr(storage_utils.os, "fsync", synced)
    completed = []
    assert app.request_complete_tray(completion_callback=completed.append)
    pump(app, lambda: bool(completed))
    assert completed == [True]
    assert order == ["checkpoint", "central", "checkpoint"]
    assert [row["event"] for row in rows(app)] == ["TRAY_COMPLETE"]
    assert app.total_tray_count == 1 and app.current_tray.master_label_code == ""
    assert fsync_threads and threading.get_ident() not in fsync_threads


@pytest.mark.parametrize("barcode", [ITEM + "-1", "BBB2270730100-1"])
def test_scan_idle_resume_and_rejection_also_keep_fsync_off_tk(app, monkeypatch, barcode):
    app.is_idle = True
    app.last_activity_time = datetime.datetime.now() - datetime.timedelta(seconds=60)
    app._set_idle_style = lambda **kwargs: None
    app._start_idle_checker = lambda **kwargs: None
    app._start_stopwatch = lambda **kwargs: None
    app.show_fullscreen_warning = lambda *args, **kwargs: None
    fsync = storage_utils.os.fsync
    threads = []
    def synced(fd):
        threads.append(threading.get_ident())
        return fsync(fd)
    monkeypatch.setattr(storage_utils.os, "fsync", synced)
    app._process_barcode_logic(barcode)
    pump(app, lambda: not app._ui_lane.is_busy())
    app.log_queue.join()
    assert threads and threading.get_ident() not in threads
    local_path = module.local_only_event_log_path(app.log_file_path)
    with local_path.open(encoding="utf-8-sig", newline="") as handle:
        local_rows = list(csv.DictReader(handle))
    assert [row["event"] for row in local_rows] == ["IDLE_END"]
    assert local_rows[0]["timestamp"] <= rows(app)[0]["timestamp"]
    assert rows(app)[-1]["event"] == ("SCAN_OK" if barcode.startswith(ITEM) else "SCAN_FAIL_MISMATCH")


def test_completion_freezes_checkpoint_before_worker_and_stops_stale_command(app):
    now = datetime.datetime.now()
    app.current_tray.scanned_barcodes = [ITEM + "-1"]
    app.current_tray.scan_times = [now]
    app.current_tray.tray_size = 1
    original_master = app.current_tray.master_label_code = f"PHS=1|CLC={ITEM}|QT=1"
    app._transfer_seal_runtime = lambda: SimpleNamespace()
    app._transfer_member_exchange_blocks_local_action = lambda action: False
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot
    commands = []
    def delayed(state):
        entered.set()
        assert release.wait(timeout=5)
        return save(state)
    def prepare(*, on_prepared, **kwargs):
        attempt = SealAttempt("intent-frozen", "ACKED")
        on_prepared(attempt)
        commands.append(attempt.intent_id)
        return attempt
    app._save_tray_state_snapshot = delayed
    app._prepare_and_attempt_transfer_seal_snapshot = prepare
    completed = []
    try:
        assert app.request_complete_tray(completion_callback=completed.append)
        pump(app, entered.is_set)
        app.current_tray = TraySession(master_label_code="NEW", item_code=ITEM, tray_size=3)
        app._scan_callback_epoch += 1
        release.set()
        pump(app, lambda: not app._ui_lane.is_busy())
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text())
        assert state["master_label_code"] == original_master
        assert state["scanned_barcodes"] == [ITEM + "-1"]
        assert app.current_tray.master_label_code == "NEW"
        assert app.current_tray.scanned_barcodes == []
        assert commands == [] and completed == []
    finally:
        release.set()


def _scanner(app, barcode):
    """A scanner types into the entry (ignored while locked) and presses Enter."""
    app.scan_entry.insert("end", barcode)
    app.process_barcode()


def _only_lane_pump_pending(app):
    lane = app._ui_lane
    return all(callback == lane._pump for _job, _delay, callback, _args in app.root.jobs)


def _settled(app):
    return (
        not app._ui_lane.is_busy()
        and not getattr(app, "_live_scan_save_pending", False)
        and not getattr(app, "_scans_behind_save", None)
        and _only_lane_pump_pending(app)
    )


def settle(app):
    # Several durable saves run back to back here; the budget only bounds a hang.
    app.root.run_until(lambda: _settled(app), timeout=60)


def _blocked_save(app, result=None):
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot

    def delayed(state):
        entered.set()
        assert release.wait(timeout=5)
        return save(state) if result is None else result

    app._save_tray_state_snapshot = delayed
    return entered, release, save


def _refusals(app):
    return [args[0] for args, _kwargs in app.messages if args[1:2] == ("danger",)]


def test_scans_during_a_product_save_stay_separate_products_in_scan_order(app):
    """w9scanflow F1: scans arriving while a save runs were joined in the entry."""
    app.error_sounds = []
    app.error_sound = SimpleNamespace(play=lambda: app.error_sounds.append(1))
    app.current_tray.tray_size = 5  # stay below the automatic completion
    first, second, third = (f"{ITEM}T0929D0{number}" for number in (1, 2, 3))
    entered, release, save = _blocked_save(app)
    try:
        _scanner(app, first)
        pump(app, entered.is_set)
        _scanner(app, second)
        _scanner(app, third)
        app._save_tray_state_snapshot = save
        release.set()
        settle(app)
        # The operator's next Enter (or the next scan's) must find nothing joined.
        app.process_barcode()
        settle(app)
    finally:
        release.set()
    app.log_queue.join()
    assert app.current_tray.scanned_barcodes == [first, second, third]
    assert [json.loads(row["details"])["product_barcode"] for row in rows(app)] == [first, second, third]
    assert app.scan_entry.get() == ""
    assert len(app.sounds) == 3 and app.error_sounds == []


def test_scans_behind_an_unsaved_product_are_refused_with_a_sound(app):
    _counted_error_sound(app)
    entered, release, _save = _blocked_save(app, result=False)
    try:
        _scanner(app, ITEM + "-1")
        pump(app, entered.is_set)
        _scanner(app, ITEM + "-2")
        release.set()
        settle(app)
    finally:
        release.set()
    assert app.current_tray.scanned_barcodes == []
    assert app.scan_entry.get() == "" and app.sounds == []
    assert app.error_sounds == [-1]
    assert _refusals(app)[-1] == (
        "앞 스캔 저장 확인이 필요해 이어서 들어온 스캔 1개는 받지 않았습니다. 다시 스캔하세요."
    )


def test_scan_behind_the_last_product_is_retained_while_the_tray_completes(app):
    """DESIGN §1: local completion preserves the already admitted next scan."""
    app.error_sounds = []
    app.error_sound = SimpleNamespace(play=lambda: app.error_sounds.append(1))
    app.current_tray.tray_size = 1
    completions = []
    def completing(**kwargs):
        completions.append(tuple(app.current_tray.scanned_barcodes))
        app._set_completion_lane_busy(True)
        return True
    app.request_complete_tray = completing
    entered, release, save = _blocked_save(app)
    try:
        _scanner(app, ITEM + "-1")
        pump(app, entered.is_set)
        _scanner(app, "PHS=1|CLC=AAA2270730100|QT=1")
        app._save_tray_state_snapshot = save
        release.set()
        pump(app, lambda: not app._ui_lane.is_busy() and _only_lane_pump_pending(app))
    finally:
        release.set()
    assert completions == [(ITEM + "-1",)]
    assert app._completion_lane_busy is True
    assert app.current_tray.scanned_barcodes == [ITEM + "-1"]
    assert app._scans_behind_save == ["PHS=1|CLC=AAA2270730100|QT=1"]
    assert app.error_sounds == [] and _refusals(app) == []


def test_scan_while_completion_runs_is_queued_from_the_enabled_entry(app):
    """DESIGN §1: completion writes leave the scanner entry ready for FIFO input."""
    app.error_sounds = []
    app.error_sound = SimpleNamespace(play=lambda: app.error_sounds.append(1))
    app._set_completion_lane_busy(True)
    assert app.scan_entry.state == "normal"
    _scanner(app, ITEM + "-9")
    assert app.scan_entry.get() == "" and not app.root.jobs
    assert app._scans_behind_save == [ITEM + "-9"]
    assert app.error_sounds == [] and _refusals(app) == []
    assert app.current_tray.scanned_barcodes == []


def test_scan_held_before_a_warning_acknowledges_it_and_runs(app):
    from warning_presenter import Notice, NoticeSeverity

    app.show_fullscreen_warning = lambda title, message, color: app._warning_state_presenter().present(
        Notice(code="scan.fixture", title=title, message=message,
               severity=NoticeSeverity.ERROR, blocking=True)
    )
    app._precommand_operator_review_retry_context = lambda: None
    wrong, product = "BBB2270730100-1", ITEM + "-2"
    _scanner(app, wrong)
    app.root.run_one()  # the scan callback submits the save; its first UI step waits
    _scanner(app, product)
    assert app._scans_behind_save == [product]
    settle(app)
    assert not app._warning_state_presenter().state.is_blocking
    assert app.current_tray.scanned_barcodes == [product]
    assert app.scan_entry.get() == ""


def _counted_error_sound(app):
    app.error_sounds = []
    # G10 exercises the real repeating-error adapter through a fake sound,
    # instead of the fixture's native-audio suppression callback.
    app._start_warning_beep = module.ContainerAudit._start_warning_beep.__get__(app)
    app.error_sound = SimpleNamespace(play=lambda loops=0: app.error_sounds.append(loops), stop=lambda: None)


def test_close_during_a_save_refuses_the_held_scan_out_loud(app, monkeypatch):
    """w9scanfixrev: a scan held behind a save vanished without a sound at a normal close."""
    _counted_error_sound(app)
    app.current_tray.tray_size = 8
    app._end_work_session = lambda **kwargs: True
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: None
    warnings = []
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(app, "_show_field_notice",
                        lambda title, message, **kwargs: warnings.append((title, message)))
    entered, release, save = _blocked_save(app)
    try:
        _scanner(app, ITEM + "-1")
        pump(app, entered.is_set)
        _scanner(app, ITEM + "-2")
        assert app._scans_behind_save == [ITEM + "-2"]
        app.on_closing(_confirmed=True)
        app._save_tray_state_snapshot = save
        release.set()
        pump(app, lambda: app.root.destroyed)
    finally:
        release.set()
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    notice = "종료 전에 이어서 들어온 스캔 1개는 저장하지 않았습니다. 다시 실행한 뒤 그 제품을 다시 스캔하세요."
    assert state["scanned_barcodes"] == [ITEM + "-1"]
    assert app.error_sounds == [-1] and notice in _refusals(app)
    assert warnings == [("스캔 다시 필요", notice)]


def test_reset_between_ack_and_queue_drain_refuses_the_held_scan_out_loud(app, monkeypatch):
    """w9scanfixrev: reset right after the save's ACK cleared the held scan without a sound."""
    _counted_error_sound(app)
    app.current_tray.tray_size = 8
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *a, **k: True)
    app._delete_current_tray_state = module.ContainerAudit._delete_current_tray_state.__get__(app)
    entered, release, save = _blocked_save(app)
    try:
        _scanner(app, ITEM + "-1")
        pump(app, entered.is_set)
        _scanner(app, ITEM + "-2")
        app._save_tray_state_snapshot = save
        release.set()
        pump(app, lambda: not app._ui_lane.is_busy())
        assert app._scans_behind_save == [ITEM + "-2"]
        app.reset_current_work()
        settle(app)  # the refusal follows the reset's own notice
    finally:
        release.set()
    assert app.current_tray.master_label_code == ""
    assert app.error_sounds == [-1]
    assert _refusals(app)[-1] == "작업이 바뀌어 이어서 들어온 스캔 1개는 받지 않았습니다. 다시 스캔하세요."


def test_lane_fault_refuses_held_scans_in_its_notice(app):
    _counted_error_sound(app)
    app._scans_behind_save = [ITEM + "-2", ITEM + "-3"]
    app._live_scan_save_pending = True
    app._handle_ui_lane_fault(RuntimeError("fixture fault"))
    assert app._scans_behind_save == [] and app._live_scan_save_pending is False
    assert app.error_sounds == [-1]
    assert _refusals(app)[-1].endswith("이어서 들어온 스캔 2개는 받지 않았습니다. 다시 스캔하세요.")
