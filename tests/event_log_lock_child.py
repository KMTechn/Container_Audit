"""Real process owners and a crash/restart at the CSV lock boundary."""
import _tkinter
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

_tkinter.create = lambda *a, **kw: (_ for _ in ()).throw(AssertionError("HOST_GUI_BOUNDARY"))
def guard(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "winreg.SetValue", "winreg.DeleteKey"}:
        raise AssertionError("HOST_NETWORK_OR_REGISTRY_BOUNDARY")
    if event == "ctypes.dlsym" and args[1] in {"CredReadW", "CredReadA", "CryptUnprotectData"}:
        raise AssertionError("HOST_CREDENTIAL_BOUNDARY")
sys.addaudithook(guard)
import event_log_store as logs
from auto_update import native_process_identity

root, mode = Path(sys.argv[1]), sys.argv[2]
csv_path = root / "events.csv"
lock_path = Path(logs._lock_file_path(str(csv_path)))
entry = {"timestamp": "2026-10-08T10:00:00", "worker_name": "fixture",
         "event": "SCAN_OK", "details": json.dumps({"idempotency_key": "first"})}

if mode == "cut":
    store = logs.EventLogOutbox(root / "outbox")
    store.stage(str(csv_path), entry)
    write = os.write
    def interrupted(fd, payload):
        result = write(fd, payload)
        if lock_path.exists():
            os._exit(77)
        return result
    os.write = interrupted
    store.drain()
    raise AssertionError("lock interruption was not reached")
elif mode == "restart":
    from tests.test_container_audit_contracts import _completion_app
    import writer_session_fence as fence
    app = _completion_app(root)
    store = logs.EventLogOutbox(root / "outbox")
    entered = threading.Event()
    original = logs.os.open
    def opened(path, flags, *args, **kwargs):
        if str(path) == str(lock_path):
            entered.set()  # The projector already owns writer admission.
        return original(path, flags, *args, **kwargs)
    logs.os.open = opened
    projection_errors = []
    def project():
        try:
            store.drain()
        except Exception as exc:
            projection_errors.append(type(exc).__name__)
    started = time.monotonic()
    worker = threading.Thread(target=project)
    worker.start()
    assert entered.wait(10)
    failures = []
    while True:
        try:
            assert app._save_current_tray_state()
            break
        except fence.WriterFenceError as exc:
            failures.append(exc.code)
    first_save_seconds = time.monotonic() - started
    worker.join()
    (root / "restart-summary.json").write_text(json.dumps({
        "first_tray_save_seconds": first_save_seconds,
        "failure_count": len(failures), "failure_codes": failures,
        "projection_errors": projection_errors,
        "pending": len(list(store.directory.glob("*.json"))),
        "csv_exists": csv_path.exists(),
        "event_log_store_source_path": str(Path(logs.__file__).resolve()),
        "event_log_store_source_sha256": hashlib.sha256(Path(logs.__file__).read_bytes()).hexdigest(),
    }), encoding="utf-8")
elif mode == "owner":
    owner = {"pid": os.getpid(), **native_process_identity(os.getpid())}
    (root / "owner.json").write_text(json.dumps(owner), encoding="utf-8")
    print("ready", flush=True)
    sys.stdin.readline()  # The test releases its own child without killing it.
elif mode == "append":
    logs.LOCK_TIMEOUT_SECONDS = float(sys.argv[3])
    started = time.monotonic()
    try:
        logs.append_event_log_entry(str(csv_path), entry)
        result = {"status": "APPENDED"}
    except TimeoutError:
        result = {"status": "TIMEOUT"}
    result["seconds"] = time.monotonic() - started
    (root / "append-summary.json").write_text(json.dumps(result), encoding="utf-8")
    print(json.dumps(result), flush=True)
else:
    raise ValueError(mode)
