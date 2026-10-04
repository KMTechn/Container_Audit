"""Exercise the real main/run boundary with native, test-only instance handles."""
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest


def _child(directory, mode):
    import tkinter
    from tkinter import messagebox
    def no_window(*args, **kwargs):
        raise AssertionError("native GUI is forbidden in the child probe")
    tkinter.Tk.__init__ = no_window
    tkinter.Toplevel.__init__ = no_window
    messagebox._show = no_window
    import Container_Audit as module
    import runtime_instance
    from tests.test_container_audit_contracts import _completion_app
    from tests.test_tk_serial_ui_lane import FakeTkRoot
    from tk_serial_ui_lane import LaneTask, TkSerialUiLane
    from preflight_scan_hold import PreflightScanHoldWriter

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    runtime_instance.runtime_mutex_name = lambda root: (
        "Local\\KMTech.Test.CA.Loop." + hashlib.sha256(str(directory).encode()).hexdigest()[:20]
    )
    lease = runtime_instance.acquire_runtime_instance(directory)
    assert lease is not None
    app = _completion_app(directory)
    events = []
    saved_path = directory / app.CURRENT_TRAY_STATE_FILE
    restored_scans = None
    if saved_path.exists():
        from tray_state import tray_session_from_state, validate_tray_state
        saved = json.loads(saved_path.read_text(encoding="utf-8"))
        validate_tray_state(saved, default_tray_size=app.TRAY_SIZE)
        app.current_tray = tray_session_from_state(
            saved, session_factory=module.TraySession, default_tray_size=app.TRAY_SIZE,
        )
        restored_scans = list(app.current_tray.scanned_barcodes)
    original_release = lease.release
    blocked_release = threading.Event()

    def release():
        events.append("release")
        original_release()

    lease.release = release
    assert app._save_current_tray_state()
    # The stalled case keeps an actual durable outbox for the next process.
    if mode == "blocked":
        store = app._event_log_outbox(app.log_file_path)
        def unavailable(**kwargs):
            raise OSError("synthetic unavailable CSV sink")
        store.drain = unavailable
        app.LOOP_CLEANUP_TIMEOUT_SECONDS = 0.2
    app._log_event("SHUTDOWN_PROBE", detail={"probe": 1}, synchronous=True)
    app._recover_checkpoint_audit_events = lambda: []
    app._clear_projected_checkpoint_audits = lambda staged: None
    app.save_settings = lambda: events.append("settings")
    app._cancel_all_jobs = lambda: events.append("cancel")
    app._preserve_preflight_hold_for_close = lambda: (True, False)
    app._operator_review_blocks_mutation = lambda: False
    app._end_work_session = lambda **kwargs: True
    app._preflight_context_blocks_mutation = lambda: False
    app._set_preflight_scan_input_locked = lambda value: None
    app._set_scan_callback_pending = lambda value: None
    app._refuse_scans_behind_save = lambda text: ""
    app._show_field_notice = lambda *args, **kwargs: events.append("notice")
    module.stop_all_sounds = lambda: events.append("sounds")

    class Root(FakeTkRoot):
        def destroy(self):
            super().destroy()
            events.append("destroy")

        def mainloop(self):
            if mode == "normal":
                app.on_closing(_confirmed=True)
                self.run_until(lambda: self.destroyed, timeout=8)
            elif mode == "refused":
                save = app._save_current_tray_state
                app._save_current_tray_state = lambda: False
                app.on_closing(_confirmed=True)
                self.run_until(lambda: not app._ui_close_requested, timeout=8)
                assert not self.destroyed and not app._ui_close_requested
                events.append("refused")
                app._save_current_tray_state = save
                app.on_closing(_confirmed=True)
                self.run_until(lambda: self.destroyed, timeout=8)
            elif mode == "early":
                app.on_closing(_confirmed=True)
            elif mode == "raise":
                raise RuntimeError("loop probe")
            elif mode == "interrupt":
                raise KeyboardInterrupt
            elif mode == "exit":
                raise SystemExit(17)

    app.root = Root()
    app.log_thread = threading.Thread(target=app._event_log_writer, daemon=True,
                                      name="ca-loop-event-writer")
    app.log_thread.start()
    app._ui_lane = TkSerialUiLane(app.root)
    app._central_transport_lane = TkSerialUiLane(app.root)
    app._preflight_hold_writer_instance = PreflightScanHoldWriter(app.root, queue_capacity=2)
    workers = [app._ui_lane.worker_thread, app._central_transport_lane.worker_thread,
               app._preflight_hold_writer_instance.thread, app.log_thread]
    admitted = app._ui_lane.submit(LaneTask(
        "shutdown-checkpoint", 0,
        (lambda: blocked_release.wait()) if mode == "blocked" else
        (lambda: app._ui_lane.call_ui_sync(lambda: events.append("checkpoint") or True)),
        lambda result: events.append("finish"),
        lambda exc: events.append("failure"),
    ))
    assert admitted.accepted
    module._prepare_gui_startup = lambda **kwargs: (app, lease)
    error = None
    code = 0
    try:
        code = module.main([])
    except BaseException as exc:
        error = type(exc).__name__
        if isinstance(exc, SystemExit):
            code = exc.code
    finally:
        state = directory / app.CURRENT_TRAY_STATE_FILE
        second = runtime_instance.acquire_runtime_instance(directory)
        mutex_retained = second is None
        if second is not None:
            second.release()
        (directory / "observation.json").write_text(json.dumps({
            "events": events, "error": error, "code": code,
            "state_exists": state.exists(),
            "restored_scans": restored_scans,
            "mutex_retained": mutex_retained,
            "pending_audits": len(list((directory / "_event_outbox").glob("*.json"))),
            "workers": [{"name": t.name, "daemon": t.daemon, "alive": t.is_alive()}
                        for t in workers],
        }), encoding="utf-8")
    # RED cleanup is controlled by the parent and is never counted as product exit.
    if any(t.is_alive() and not t.daemon for t in workers):
        def rescue():
            while not (directory / "rescue").exists():
                time.sleep(0.02)
            blocked_release.set()
            for lane in (app._ui_lane, app._central_transport_lane):
                lane._task_queue.put(__import__("tk_serial_ui_lane")._STOP)
            # Release an outstanding UI checkpoint without pretending it applied.
            while not app._ui_lane._result_queue.empty():
                envelope = app._ui_lane._result_queue.get_nowait()
                if envelope.kind == "ui_call":
                    envelope.value.error = RuntimeError("test rescue")
                    envelope.value.event.set()
        threading.Thread(target=rescue, daemon=True).start()
    raise SystemExit(code)


@pytest.mark.parametrize("mode", ["normal", "refused", "raise", "return", "early", "interrupt", "exit", "blocked"])
def test_loop_exit_drains_workers_and_allows_same_root_restart(tmp_path, mode):
    command = [sys.executable, "-B", "-c",
               "from tests.test_app_loop_cleanup import _child; import sys; _child(sys.argv[1],sys.argv[2])",
               str(tmp_path), mode]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        try:
            output, error_output = process.communicate(timeout=12)
            natural_exit = True
        except subprocess.TimeoutExpired:
            natural_exit = False
            # Do not terminate a hung child: release only our synthetic work.
            (tmp_path / "rescue").touch()
            output, error_output = process.communicate(timeout=10)
        observation = json.loads((tmp_path / "observation.json").read_text(encoding="utf-8"))
        assert natural_exit, observation
        assert process.returncode == (17 if mode == "exit" else 0), error_output[-1000:]
        if mode == "blocked":
            assert any(worker["alive"] for worker in observation["workers"]), observation
            assert all(worker["daemon"] for worker in observation["workers"] if worker["alive"])
            assert observation["mutex_retained"] and observation["pending_audits"] == 1
            assert "release" not in observation["events"]
        else:
            assert all(not worker["alive"] for worker in observation["workers"]), observation
            assert observation["events"].count("release") == 1
            assert observation["events"].index("finish") < observation["events"].index("release")
            assert not observation["mutex_retained"]
        assert observation["events"].count("destroy") == 1
        assert observation["error"] == {"raise": "RuntimeError", "interrupt": "KeyboardInterrupt",
                                         "exit": "SystemExit"}.get(mode)
        assert observation["state_exists"]
        restart = subprocess.run(command[:-1] + ["normal"], capture_output=True, timeout=12,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert restart.returncode == 0, restart.stderr[-1000:]
        recovered = json.loads((tmp_path / "observation.json").read_text(encoding="utf-8"))
        assert recovered["restored_scans"] == ["BC-1", "BC-2"]
        with (tmp_path / "events.csv").open(encoding="utf-8-sig", newline="") as stream:
            assert sum(row["event"] == "SHUTDOWN_PROBE" for row in csv.DictReader(stream)) == 2
    finally:
        assert process.poll() is not None, "owned child remains alive; preserve its evidence"


@pytest.mark.parametrize("original", [RuntimeError("loop probe"), KeyboardInterrupt(), SystemExit(17)])
@pytest.mark.parametrize("stage", ["cancel", "sounds", "destroy"])
def test_cleanup_failure_preserves_loop_exception_and_attempts_destroy_once(monkeypatch, original, stage):
    import Container_Audit as module
    calls = []
    def action(name):
        calls.append(name)
        if name == stage:
            raise RuntimeError("cleanup probe")
    class Root:
        def mainloop(self):
            raise original
        def destroy(self):
            action("destroy")
    app = module.ContainerAudit.__new__(module.ContainerAudit)
    app.root = Root()
    app._cancel_all_jobs = lambda: action("cancel")
    monkeypatch.setattr(module, "stop_all_sounds", lambda: action("sounds"))
    monkeypatch.setattr(module, "_prepare_gui_startup", lambda **kwargs: (
        app, type("Lease", (), {"release": lambda self: calls.append("release")})(),
    ))
    with pytest.raises(type(original)) as caught:
        module.main([])
    assert caught.value is original
    assert calls == ["cancel", "sounds", "destroy", "release"]
    app._cleanup_after_mainloop()
    assert calls.count("destroy") == 1
