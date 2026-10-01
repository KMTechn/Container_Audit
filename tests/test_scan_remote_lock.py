"""Public scan admission stays durable while the real transfer client waits."""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_scan_persistence_lane import ITEM, app, pump
from transfer_client import LogisticsTransferClient
from tk_serial_ui_lane import LaneTask


@pytest.mark.parametrize("delay", [0.3, 6.0, 35.0])
def test_public_scans_settle_before_delayed_transfer_response(app, ca_remote_lock_guard, delay):
    entered, finished = threading.Event(), threading.Event()
    failures, published = [], []

    def request(*args, **kwargs):
        entered.set()
        time.sleep(delay)  # Real transport delay, including the full 35 seconds.
        finished.set()
        return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {"ready": True}})

    client = LogisticsTransferClient(
        "https://fixture.invalid", "synthetic", "fixture-host",
        session=SimpleNamespace(request=ca_remote_lock_guard.wrap_transport(request)),
        timeout_seconds=60,
    )
    app._tray_state_persist_lock = ca_remote_lock_guard.wrap_lock(threading.RLock(), label="tray checkpoint")

    lane = app._scanonly_transport_lane()
    admission = lane.submit(LaneTask(
        name="delayed-transfer", generation=app._scan_callback_epoch,
        work=client.get_capabilities, finish=published.append, fail=failures.append,
    ))
    assert admission.accepted
    try:
        pump(app, lambda: entered.is_set() or failures)
        assert entered.is_set(), f"transport not entered: {[type(error).__name__ for error in failures]}"
        started = time.monotonic()
        for index in (1, 2):
            assert app.scan_entry.state == "normal"
            app.scan_entry.insert("end", ITEM + f"-{index}")
            app.process_barcode()
            pump(app, lambda: app.scan_entry.get() == "")
            assert app.scan_entry.get() == ""
        pump(app, lambda: len(app.current_tray.scanned_barcodes) == 2 and not app._ui_lane.is_busy())
        elapsed = time.monotonic() - started
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
        assert state["scanned_barcodes"] == [ITEM + "-1", ITEM + "-2"]
        assert app.scan_entry.state == "normal"
        assert not finished.is_set(), "both durable scans must settle during the remote wait"
        assert not published
        assert elapsed < 1.0
        assert app.sounds and not failures
        print(json.dumps({"delay_seconds": delay, "second_scan_durable_seconds": elapsed,
                          "input_enabled": True, "scan_failures": 0}))
    finally:
        def idle():
            if lane.is_busy():
                time.sleep(0.002)
                return False
            return True
        app.root.run_until(idle, timeout=delay + 2)
        assert not lane.is_busy()
    assert not failures
    assert published == [{"ready": True}]


@pytest.mark.parametrize("delay", [0.3, 6.0, 35.0])
def test_public_scans_stay_durable_during_an_independent_transfer_process(
    app, tmp_path, ca_remote_lock_guard, delay
):
    entered, result = tmp_path / "entered", tmp_path / "result.json"
    script = tmp_path / "remote.py"
    script.write_text('''
import json, sys, time
from pathlib import Path
from types import SimpleNamespace
from tests.conftest import _tracked_ca_mutex_acquire
from tests.lock_remote_guard import LockRemoteGuard
from transfer_client import LogisticsTransferClient
import writer_session_fence as fence
entered, result = Path(sys.argv[1]), Path(sys.argv[2])
delay = float(sys.argv[3])
guard = LockRemoteGuard()
fence._acquire_named_mutex = _tracked_ca_mutex_acquire(guard, fence._acquire_named_mutex)
def request(*args, **kwargs):
    entered.write_text('ready', encoding='utf-8')
    time.sleep(delay)
    return SimpleNamespace(status_code=200, json=lambda: {'ok': True, 'data': {'ready': True}})
try:
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'fixture-host',
        session=SimpleNamespace(request=guard.wrap_transport(request)), timeout_seconds=60)
    answer = client.get_capabilities()
    guard.assert_clean()
    result.write_text(json.dumps({'answer': answer, 'mutex': fence.writer_admission_mutex_name(fence.canonical_control_root())}), encoding='utf-8')
except BaseException as error:
    result.write_text(json.dumps({'error': type(error).__name__}), encoding='utf-8')
    raise
''', encoding="utf-8")
    child = subprocess.Popen(
        [sys.executable, "-B", str(script), str(entered), str(result), str(delay)],
        env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    try:
        pump(app, lambda: entered.exists() or result.exists())
        assert entered.exists(), "independent client must reach its delayed transport"
        started = time.monotonic()
        for index in (1, 2):
            assert app.scan_entry.state == "normal"
            app.scan_entry.insert("end", ITEM + f"-{index}")
            app.process_barcode()
            pump(app, lambda: app.scan_entry.get() == "")
        pump(app, lambda: len(app.current_tray.scanned_barcodes) == 2 and not app._ui_lane.is_busy())
        elapsed = time.monotonic() - started
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
        assert state["scanned_barcodes"] == [ITEM + "-1", ITEM + "-2"]
        assert not result.exists() and child.poll() is None
        assert app.scan_entry.state == "normal" and elapsed < 1.0
        print(json.dumps({"process": "independent", "delay_seconds": delay,
                          "second_scan_durable_seconds": elapsed, "input_enabled": True, "scan_failures": 0}))
    finally:
        child.wait(timeout=delay + 5)
    assert child.returncode == 0
    answer = json.loads(result.read_text(encoding="utf-8"))
    import writer_session_fence as fence
    assert answer == {"answer": {"ready": True}, "mutex": fence.writer_admission_mutex_name(fence.canonical_control_root())}
