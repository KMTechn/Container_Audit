"""Normal screen cleanup must finish before the shell closes its own threads."""
import json
import _thread
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest


SHELL_WAITERS = (
    "shell-force-exit", "shell-start-watch", "shell-exit",
    "shell-test-control", "shell-closing", "shell-start-destroy",
)


def _screen_cleanup_child(directory, mode):
    import Container_Audit as ca
    from app_data_workers import register_data_worker

    sys.path.insert(0, str(Path(ca.__file__).parent / "shell"))
    from bridge import Bridge

    directory = Path(directory)
    bridge = Bridge(directory / "shell", "rw", owner="external")
    stop = threading.Event()
    residents = [threading.Thread(target=stop.wait, name=name, daemon=True)
                 for name in SHELL_WAITERS]
    for thread in residents:
        thread.start()
    ca.CA_SCREEN_HOST["active"] = not mode.endswith("tk")
    app = SimpleNamespace(
        _application_close_complete=True,
        _runtime_data_root=directory,
        LOOP_CLEANUP_TIMEOUT_SECONDS=0.5,
        LOOP_CLEANUP_NOTICE_SECONDS=0.05,
    )
    writer = None
    if mode in {"stalled", "stalled-tk", "finite", "finite-tk", "same-name-writer", "unknown"}:
        def write():
            if mode in {"finite", "finite-tk"}:
                time.sleep(0.1)
                with (directory / "writer-finished").open("w", encoding="utf-8") as stream:
                    stream.write("complete durable work")
                    stream.flush()
                    import os
                    os.fsync(stream.fileno())
            else:
                stop.wait()
        writer = threading.Thread(target=write,
                                  name="shell-push" if mode == "same-name-writer" else "data-writer",
                                  daemon=mode != "same-name-writer")
        if mode != "unknown":
            register_data_worker(writer)
        else:
            writer.daemon = False
        writer.start()
    if mode == "dummy":
        appeared = threading.Event()
        def native_thread():
            threading.current_thread()
            appeared.set()
        _thread.start_new_thread(native_thread, ())
        assert appeared.wait(1)
        assert any(isinstance(thread, threading._DummyThread) and thread.is_alive()
                   for thread in threading.enumerate())
    if mode in {"session", "bootstrap", "startup-report"}:
        def finish_write(*args, **kwargs):
            time.sleep(0.1)
            (directory / "producer-finished").write_text("complete", encoding="utf-8")
            return {"status": "PASS"}
        if mode == "startup-report":
            import startup_check_report as report
            report._publish_gui_ready = finish_write
            report.gui_ready(ca.CURRENT_VERSION, "test-build")
        else:
            import direct_sync_auto_bootstrap as bootstrap
            bootstrap._session_sync_trigger_enabled = lambda: True
            arguments = dict(app_root=Path(ca.__file__).parent,
                             direct_sync_root=directory / "relay", scan_source_dir=directory)
            if mode == "session":
                bootstrap.run_session_direct_sync_once = finish_write
                writer = bootstrap.start_session_direct_sync(**arguments)
            else:
                bootstrap.run_direct_sync_auto_bootstrap = finish_write
                writer = bootstrap.start_direct_sync_auto_bootstrap(**arguments)
            assert writer is not None
    errors = []

    def cleanup():
        try:
            ca.ContainerAudit._cleanup_after_mainloop(app)
            # Duplicate stop/close delivery must remain harmless.
            ca.ContainerAudit._cleanup_after_mainloop(app)
        except BaseException as error:
            errors.append(type(error).__name__)

    owner = threading.Thread(target=cleanup, name="app-owner", daemon=True)
    try:
        owner.start()
        owner.join(3)
        assert not owner.is_alive()
        assert not errors
        assert app._loop_cleanup_finished
        assert bridge._publisher.is_alive() and bridge.pedal._worker.is_alive()
        assert all(thread.is_alive() for thread in residents)
        assert not (directory / "shutdown-stalled.json").exists()
        if mode in {"finite", "finite-tk"}:
            assert (directory / "writer-finished").read_text(encoding="utf-8") == "complete durable work"
        if mode == "unknown":
            assert writer.is_alive()
        if mode in {"session", "bootstrap", "startup-report"}:
            assert (directory / "producer-finished").read_text(encoding="utf-8") == "complete"
        (directory / "cleanup-finished").touch()
    finally:
        stop.set()
        for thread in residents:
            thread.join(1)
        if writer is not None:
            writer.join(1)
        bridge.close()
    assert not bridge._publisher.is_alive()
    assert not bridge.pedal._worker.is_alive()


@pytest.mark.parametrize("mode", ["screen", "tk", "unknown", "dummy", "finite", "finite-tk",
                                 "stalled", "stalled-tk", "same-name-writer",
                                 "session", "bootstrap", "startup-report"])
def test_screen_residents_do_not_block_cleanup_but_data_writers_do(tmp_path, mode):
    command = [sys.executable, "-B", "-c",
               "from tests.test_screen_stop_cleanup import _screen_cleanup_child; "
               "import sys; _screen_cleanup_child(*sys.argv[1:])", str(tmp_path), mode]
    process = subprocess.run(command, capture_output=True, timeout=8,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    expected = 1 if mode in {"stalled", "stalled-tk", "same-name-writer"} else 0
    finished = tmp_path / "cleanup-finished"
    marker = tmp_path / "shutdown-stalled.json"
    (tmp_path / "cleanup-observation.json").write_text(json.dumps({
        "mode": mode, "returncode": process.returncode,
        "cleanup_finished": finished.exists(), "stall_marker": marker.exists(),
        "finite_writer_finished": (tmp_path / "writer-finished").exists(),
    }), encoding="utf-8")
    assert process.returncode == expected
    assert finished.exists() == (expected == 0)
    assert marker.exists() == (expected == 1)
    if marker.exists():
        assert json.loads(marker.read_text(encoding="utf-8"))["pid"] > 0
