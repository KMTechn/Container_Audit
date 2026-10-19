"""A delayed close reports once without replacing the admitted drain."""
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

import Container_Audit as module
from writer_session_fence import WriterFencedError
from tk_serial_ui_lane import LaneTask
from tests.test_scan_persistence_lane import ITEM, app, pump, rows


# Approved worker copy: 02d3f3e9fa6e (Container_Audit.py:17044).
NOTICE = '종료가 끝나지 않았습니다.\n창을 그대로 두고 현장 관리자에게 알리세요.'


def close_clock(app, monkeypatch):
    clock, timers, messages = [0.0], [], []
    original_after = app.root.after
    def after(delay, callback):
        if delay == 60000:
            timers.append((clock[0] + 60, callback))
            return "close-delay"
        return original_after(delay, callback)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    app.root.after = after
    app.show_status_message = lambda message, *a, **k: messages.append(message)
    app._end_work_session = lambda **k: True
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: None
    def advance(seconds):
        clock[0] = seconds
        due = [callback for deadline, callback in timers if deadline <= seconds]
        timers[:] = [(deadline, callback) for deadline, callback in timers if deadline > seconds]
        for callback in due:
            callback()
    return advance, messages, timers


@pytest.mark.parametrize("log_state", ["available", "denied", "closing"])
def test_sixty_seconds_notifies_once_and_keeps_real_lane_drain(app, monkeypatch, log_state):
    advance, messages, timers = close_clock(app, monkeypatch)
    entered, release, attempted = threading.Event(), threading.Event(), threading.Event()
    original_save, original_append = app._save_current_tray_state, module.append_event_log_entry_idempotent
    writes, log_calls = [], []
    owner = threading.get_ident()
    def blocked_work():
        entered.set()
        assert release.wait(10)
        return True
    def save():
        writes.append(True)
        return original_save()
    def append(path, entry, **kwargs):
        if entry["event"] == "APP_CLOSE_DELAY":
            assert threading.get_ident() != owner
            log_calls.append(entry["event"])
            attempted.set()
            if log_state == "denied":
                raise WriterFencedError("SYNTHETIC_REFUSAL", "synthetic writer refusal")
        return original_append(path, entry, **kwargs)
    app._save_current_tray_state = save
    monkeypatch.setattr(module, "append_event_log_entry_idempotent", append)
    try:
        lane = app._ui_task_lane()
        assert lane.submit(LaneTask("close-delay-test", app._scan_callback_epoch,
                                    blocked_work, lambda value: None, lambda exc: pytest.fail(type(exc).__name__)))
        pump(app, entered.is_set)
        scans_before = tuple(app.current_tray.scanned_barcodes)
        app.on_closing(_confirmed=True)
        lane, generation = app._ui_lane, app._scan_callback_epoch
        assert len(timers) == 1
        assert lane.is_busy() and not app.root.destroyed
        if log_state == "closing":
            app._event_log_close_requested = True
        advance(59.999)
        assert NOTICE not in messages
        advance(60)
        advance(120)
        assert messages.count(NOTICE) == 1
        assert app._ui_close_requested and not app.root.destroyed
        assert app._ui_lane is lane and lane.is_busy() and lane.worker_thread.is_alive()
        assert app._scan_callback_epoch == generation and writes == []
        assert tuple(app.current_tray.scanned_barcodes) == scans_before
        if log_state == "closing":
            assert not attempted.is_set()
            app._event_log_close_requested = False
        else:
            assert attempted.wait(2)
            assert log_calls == ["APP_CLOSE_DELAY"]
        if log_state == "available":
            pump(app, lambda: Path(app.log_file_path).exists()
                 and sum(r["event"] == "APP_CLOSE_DELAY" for r in rows(app)) == 1)
        if log_state == "denied":
            assert not getattr(app, "_event_log_outbox_instance", None) or not app._event_log_outbox_instance.has_unstaged
        release.set()
        pump(app, lambda: app.root.destroyed)
        assert not lane.worker_thread.is_alive() and not app.log_thread.is_alive()
        if log_state == "denied":
            assert not Path(app.log_file_path).exists() or not any(r["event"] == "APP_CLOSE_DELAY" for r in rows(app))
    finally:
        release.set()


def test_finished_close_suppresses_late_notice(app, monkeypatch):
    advance, messages, timers = close_clock(app, monkeypatch)
    app.on_closing(_confirmed=True)
    pump(app, lambda: app.root.destroyed)
    assert app._application_close_complete
    advance(60)
    assert NOTICE not in messages
    assert not app.log_thread.is_alive()


def test_aborted_close_does_not_notify_and_retry_gets_its_own_sixty_seconds(app, monkeypatch):
    advance, messages, timers = close_clock(app, monkeypatch)
    original_save = app._save_current_tray_state
    app._save_current_tray_state = lambda: False
    app.on_closing(_confirmed=True)
    assert not app._ui_close_requested
    advance(60)
    assert NOTICE not in messages
    app._save_current_tray_state = original_save
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot
    def blocked(state):
        entered.set()
        assert release.wait(5)
        return save(state)
    app._save_tray_state_snapshot = blocked
    try:
        app._process_barcode_logic(ITEM + "-retry")
        pump(app, entered.is_set)
        app.on_closing(_confirmed=True)
        advance(119.999)
        assert NOTICE not in messages
        advance(120)
        assert messages.count(NOTICE) == 1 and not app.root.destroyed
        release.set()
        pump(app, lambda: app.root.destroyed)
    finally:
        release.set()
