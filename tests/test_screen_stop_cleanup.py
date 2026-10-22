"""Normal screen cleanup must finish before the shell closes its own threads."""
import json
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

    sys.path.insert(0, str(Path(ca.__file__).parent / "shell"))
    from bridge import Bridge

    directory = Path(directory)
    bridge = Bridge(directory / "shell", "rw", owner="external")
    stop = threading.Event()
    residents = [threading.Thread(target=stop.wait, name=name, daemon=True)
                 for name in SHELL_WAITERS]
    for thread in residents:
        thread.start()
    ca.CA_SCREEN_HOST["active"] = mode != "tk"
    app = SimpleNamespace(
        _application_close_complete=True,
        _runtime_data_root=directory,
        LOOP_CLEANUP_TIMEOUT_SECONDS=0.5,
        LOOP_CLEANUP_NOTICE_SECONDS=0.05,
    )
    writer = None
    if mode in {"stalled", "finite", "same-name-writer"}:
        def write():
            if mode == "finite":
                time.sleep(0.1)
                (directory / "writer-finished").touch()
            else:
                stop.wait()
        writer = threading.Thread(target=write,
                                  name="shell-push" if mode == "same-name-writer" else "data-writer",
                                  daemon=mode != "same-name-writer")
        writer.start()
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
        if mode == "finite":
            assert (directory / "writer-finished").exists()
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


@pytest.mark.parametrize("mode", ["screen", "finite", "stalled", "tk", "same-name-writer"])
def test_screen_residents_do_not_block_cleanup_but_data_writers_do(tmp_path, mode):
    command = [sys.executable, "-B", "-c",
               "from tests.test_screen_stop_cleanup import _screen_cleanup_child; "
               "import sys; _screen_cleanup_child(*sys.argv[1:])", str(tmp_path), mode]
    process = subprocess.run(command, capture_output=True, timeout=8,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    expected = 0 if mode in {"screen", "finite"} else 1
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
