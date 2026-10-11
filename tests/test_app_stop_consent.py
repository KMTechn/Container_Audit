"""A remote request keeps live input open until the worker consents."""
import datetime
import json
from pathlib import Path
import threading

import pytest

import Container_Audit as module
import user_relay
from tests.test_scan_persistence_lane import ITEM, app, pump, rows


@pytest.fixture
def stop_app(app, tmp_path, monkeypatch):
    app.direct_sync_program_data_root = str(tmp_path / "relay")
    app.closed = []
    app.on_closing = lambda: app.closed.append(True)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    return app


def request(app):
    return user_relay.request_app_stop(app.direct_sync_program_data_root)


def scanned(app):
    app.current_tray.scanned_barcodes = [ITEM + "000001"]
    app.current_tray.scan_times = [datetime.datetime.now()]
    assert app._save_current_tray_state()


def settle(app):
    pump(app, lambda: not getattr(app, "_live_scan_save_pending", False)
         and not getattr(app, "_scan_callback_pending", False)
         and (getattr(app, "_ui_lane", None) is None or not app._ui_lane.is_busy()))


def deferred_rows(app):
    return [row for row in rows(app) if row["event"] == "APP_STOP_DEFERRED"]


def test_idle_request_uses_immediate_normal_close(stop_app):
    app = stop_app
    request(app)
    app._poll_app_stop_request()
    assert app.closed == [True]
    assert not user_relay.app_stop_path(app.direct_sync_program_data_root).exists()
    assert not getattr(app, "_deferred_app_stop_request", None)


@pytest.mark.parametrize("busy", ["scans", "_live_scan_save_pending", "_completion_lane_busy",
                                   "_preflight_hold_draining", "_preflight_hold_append_pending",
                                   "_preflight_hold_switch_pending", "_scan_callback_pending"])
def test_working_request_defers_once_and_never_auto_closes_after_work(stop_app, busy):
    app = stop_app
    if busy == "scans":
        scanned(app)
    else:
        setattr(app, busy, True)
    original = request(app)
    app._poll_app_stop_request()
    assert not app.closed and not getattr(app, "_ui_close_requested", False)
    assert user_relay.app_stop_path(app.direct_sync_program_data_root).exists()
    if busy != "scans":
        # Recording waits for the pre-existing admitted save/drain/input.
        assert getattr(app, "_ui_lane", None) is None
        setattr(app, busy, False)
        app._poll_app_stop_request()
    settle(app)
    assert len(deferred_rows(app)) == 1
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    assert state["deferred_app_stop_request"]["request_id"] == original["request_id"]
    app.current_tray = module.TraySession()
    for _ in range(5):
        app._poll_app_stop_request()
    assert not app.closed and user_relay.app_stop_path(app.direct_sync_program_data_root).exists()
    assert len(deferred_rows(app)) == 1
    assert sum(args[0] == module._APP_STOP_DEFERRED_MESSAGE for args, _ in app.messages) == 1
    app.on_closing()
    assert app.closed == [True]


def test_deferred_logging_and_checkpoint_keep_queued_scans_in_order(stop_app, monkeypatch):
    app = stop_app
    scanned(app)
    entered, release = threading.Event(), threading.Event()
    owner = threading.get_ident()
    logged = app._log_event
    def delayed(event, **kwargs):
        if event == "APP_STOP_DEFERRED":
            assert threading.get_ident() != owner
            entered.set()
            assert release.wait(5)
        return logged(event, **kwargs)
    monkeypatch.setattr(app, "_log_event", delayed)
    request(app)
    try:
        app._poll_app_stop_request()
        pump(app, entered.is_set)
        assert not app.closed
        for tail in ("000002", "000003"):
            app.scan_entry.insert(0, ITEM + tail)
            app.process_barcode()
        assert app.scan_entry.get() == ""
        assert app._scans_behind_save == [ITEM + "000002", ITEM + "000003"]
        release.set()
        pump(app, lambda: len(app.current_tray.scanned_barcodes) == 3 and not app._ui_lane.is_busy())
        assert app.current_tray.scanned_barcodes == [ITEM + "000001", ITEM + "000002", ITEM + "000003"]
        assert not app.closed and len(deferred_rows(app)) == 1
    finally:
        release.set()


@pytest.mark.parametrize("failure", ["false", "exception", "checkpoint"])
def test_recording_failure_preserves_request_and_accepts_next_scan(stop_app, monkeypatch, failure):
    app = stop_app
    scanned(app)
    logged = app._log_event
    attempts = []
    def faulty_log(event, **kwargs):
        if event == "APP_STOP_DEFERRED":
            attempts.append(event)
            if failure == "false":
                return False
            if failure == "exception":
                raise OSError("injected deferred log failure")
        return logged(event, **kwargs)
    monkeypatch.setattr(app, "_log_event", faulty_log)
    if failure == "checkpoint":
        monkeypatch.setattr(app, "_current_tray_save_operation", lambda: lambda: False)
    request(app)
    app._poll_app_stop_request()
    settle(app)
    app._poll_app_stop_request()
    assert len(attempts) == 1 and not app.closed
    assert user_relay.app_stop_path(app.direct_sync_program_data_root).exists()
    app.scan_entry.insert(0, ITEM + "000002")
    app.process_barcode()
    pump(app, lambda: len(app.current_tray.scanned_barcodes) == 2 and not app._ui_lane.is_busy())
    assert not getattr(app, "_ui_lane_fault_blocked", False)


def prepare_final_close(app, monkeypatch):
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: None
    monkeypatch.setattr(module, "stop_all_sounds", lambda: None)


def test_actual_close_consumes_deferred_request(stop_app, monkeypatch):
    app = stop_app
    scanned(app)
    request(app)
    app._poll_app_stop_request()
    settle(app)
    prepare_final_close(app, monkeypatch)
    app._finalize_application_close()
    assert app.root.destroyed and app._application_close_complete
    assert not user_relay.app_stop_path(app.direct_sync_program_data_root).exists()


def test_actual_close_preserves_a_newer_unobserved_request(stop_app, monkeypatch):
    app = stop_app
    scanned(app)
    first = request(app)
    app._poll_app_stop_request()
    settle(app)
    newer = request(app)
    assert newer["request_id"] != first["request_id"]
    prepare_final_close(app, monkeypatch)
    app._finalize_application_close()
    assert app.root.destroyed
    assert user_relay.read_app_stop_request(app.direct_sync_program_data_root)["request_id"] == newer["request_id"]


def test_failed_actual_close_keeps_request(stop_app, monkeypatch):
    app = stop_app
    scanned(app)
    request(app)
    app._poll_app_stop_request()
    settle(app)
    prepare_final_close(app, monkeypatch)
    monkeypatch.setattr(app.root, "destroy", lambda: (_ for _ in ()).throw(RuntimeError("injected close failure")))
    with pytest.raises(RuntimeError):
        app._finalize_application_close()
    assert not getattr(app, "_application_close_complete", False)
    assert user_relay.app_stop_path(app.direct_sync_program_data_root).exists()


def test_notice_remains_visible_after_other_notices_are_cleared(stop_app):
    app = stop_app
    scanned(app)
    request(app)
    app._poll_app_stop_request()
    settle(app)
    class Widget:
        def __init__(self):
            self.values, self.visible = {}, False
        def configure(self, **kwargs):
            self.values.update(kwargs)
        def grid(self):
            self.visible = True
        def grid_remove(self):
            self.visible = False
    app.notice_frame, app.notice_title_label, app.notice_message_label = Widget(), Widget(), Widget()
    app.COLOR_TEXT = "text"
    app._schedule_notice_message_wrap_refresh = lambda **kwargs: None
    app._warning_state_presenter().acknowledge()
    module.ContainerAudit._render_warning_state(app)
    assert module._APP_STOP_DEFERRED_MESSAGE in app.notice_message_label.values["text"]
    assert app.notice_frame.visible and app.notice_message_label.visible
    assert not app._warning_state_presenter().state.is_blocking
    assert not app._scan_entry_admission_block_reason()
