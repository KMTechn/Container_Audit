"""Abrupt process exits at the real CSV projection boundaries."""
import csv
import io
import json
import os
from pathlib import Path
import sys
import threading
import time

import event_log_store as logs


root, mode, cut = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
csv_path = root / "events.csv"
directory = root / "outbox"
store = logs.EventLogOutbox(directory)


def entry(key):
    return {"timestamp": "2026-10-08T06:00:00", "worker_name": "fixture",
            "event": "SCAN_OK", "details": json.dumps({"idempotency_key": key})}


if mode == "shutdown":
    import _tkinter
    _tkinter.create = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("HOST_GUI_BOUNDARY"))
    import Container_Audit as ca
    from tests.test_container_audit_contracts import _completion_app
    from tests.test_tk_serial_ui_lane import FakeTkRoot

    ca.stop_all_sounds = lambda: None
    app = _completion_app(root)
    app.root = FakeTkRoot()
    app.save_settings = app._cancel_all_jobs = lambda: None
    app.show_status_message = lambda *args, **kwargs: None
    store = app._event_log_outbox(app.log_file_path)
    for index in range(280):
        store.stage(app.log_file_path, entry(str(index)))
    entered = threading.Event()
    sync = os.fsync
    def delayed(fd):
        if Path(app.log_file_path).exists() and os.fstat(fd).st_ino == Path(app.log_file_path).stat().st_ino:
            entered.set()
            time.sleep(.2)
        return sync(fd)
    os.fsync = delayed
    app.log_thread = threading.Thread(target=app._event_log_writer, daemon=True)
    app.log_thread.start()
    assert entered.wait(10)
    started = time.monotonic()
    for _ in range(app.EVENT_LOG_CLOSE_MAX_JOIN_ATTEMPTS):
        app._finalize_application_close()
    close_seconds = time.monotonic() - started
    pending = len(list(store.directory.glob("*.json")))
    # A real process exit abandons any daemon projection still in its fsync.
    (root / "shutdown-summary.json").write_text(json.dumps({
        "destroyed": app.root.destroyed, "close_seconds": close_seconds,
        "pending": pending, "worker_alive": app.log_thread.is_alive(),
        "log_path": app.log_file_path, "outbox_path": str(store.directory),
    }), encoding="utf-8")
    raise SystemExit(0)
elif mode == "shutdown-recover":
    summary = json.loads((root / "shutdown-summary.json").read_text(encoding="utf-8"))
    store = logs.EventLogOutbox(summary["outbox_path"])
    store.drain()
    store.drain()
    raise SystemExit(0)
elif mode == "cut":
    for key in ("first", "second"):
        store.stage(str(csv_path), entry(key))
    append, sync, unlink = logs.append_event_log_entry_idempotent, os.fsync, Path.unlink

    def interrupted_append(*args, **kwargs):
        if cut in {"half", "no-newline", "nul", "nul-newline"}:
            row = io.StringIO(newline="")
            csv.DictWriter(row, fieldnames=logs.EVENT_LOG_HEADERS).writerow(entry("first"))
            raw = row.getvalue().encode("utf-8")
            tail = (raw[:len(raw) // 2] if cut == "half" else raw[:-2])
            if cut.startswith("nul"):
                tail += b"\0" * 128 + (b"\n" if cut == "nul-newline" else b"")
            with csv_path.open("wb") as handle:
                handle.write((",".join(logs.EVENT_LOG_HEADERS) + "\r\n").encode("utf-8-sig"))
                handle.write(tail)
                handle.flush()
            os._exit(77)
        result = append(*args, **kwargs)
        if cut == "after-append":
            os._exit(77)
        return result

    def interrupted_sync(fd):
        result = sync(fd)
        if cut == "after-sync" and csv_path.exists() and os.fstat(fd).st_ino == csv_path.stat().st_ino:
            os._exit(77)
        return result

    def interrupted_ack(path, *args, **kwargs):
        result = unlink(path, *args, **kwargs)
        if cut == "after-ack" and path.parent == directory:
            os._exit(77)
        return result

    os.fsync, Path.unlink = interrupted_sync, interrupted_ack
    store.drain(append=interrupted_append)
    raise AssertionError("interruption was not reached")

store.drain()
store.drain()
