"""Stop requests survive startup and UI lifecycle transitions."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import auto_update
import user_relay
from tests.test_startup_catalog_notice import startup
from tests.test_w9scanonly_workflow import flow, fixed_operation_lease_clock


@pytest.fixture(autouse=True)
def isolated_process_snapshot(monkeypatch):
    monkeypatch.setattr(user_relay, "native_app_process_snapshot", lambda: [])


def test_portable_stop_precedes_account_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    path = Path(ca.__file__).parent / "portable/main.py"
    spec = importlib.util.spec_from_file_location("stop_portable_main", path)
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    data = tmp_path / "data"
    data.mkdir()
    relay = tmp_path / "relay"
    gates = []
    monkeypatch.setattr(auto_update, "startup_gate", lambda *a, **k: gates.append(True) or 20)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    monkeypatch.setattr(ca, "main", lambda: pytest.fail("stop constructed the GUI"))
    monkeypatch.setattr("sys.argv", [str(path), "--container-audit-user-relay",
                       "--request-app-stop", "--data-root", str(data),
                       "--direct-sync-root", str(relay)])
    assert portable.main() == 0
    assert not gates
    assert user_relay.read_app_stop_request(relay) is not None


def test_portable_other_modes_keep_account_gate(monkeypatch):
    from portable import main as portable
    calls = []
    monkeypatch.setattr(auto_update, "startup_gate", lambda *a, **k: calls.append("gate") or 20)
    monkeypatch.setattr(user_relay, "main", lambda *a, **k: pytest.fail("ordinary relay bypassed the gate"))
    monkeypatch.setattr(sys, "argv", ["main.py", "--container-audit-user-relay"])
    assert portable.main() == 20
    assert calls == ["gate"]


@pytest.mark.parametrize("stage", ["before-pending", "pending", "onboarding", "catalog", "catalog-error"])
def test_startup_stop_finishes_current_unit_and_releases_lease(startup, monkeypatch, stage):
    app, released = startup
    # Use the startup storage selection, rather than the flow fixture's relay.
    paths = ca.build_container_audit_storage_paths(application_path=str(Path(ca.__file__).parent))
    root = paths.direct_sync_root
    stages = []
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    def pending(*a, **k):
        stages.append("pending")
        if stage == "pending":
            user_relay.request_app_stop(root)
        return None
    def onboarding(*a, **k):
        stages.append("onboarding")
        if stage == "onboarding":
            user_relay.request_app_stop(root)
        return {"status": "READY"}
    def catalog():
        stages.append("catalog")
        if stage.startswith("catalog"):
            user_relay.request_app_stop(root)
        if stage == "catalog-error":
            raise ca.ItemCatalogSyncError("synthetic catalog failure", cause_code=ca.SNAPSHOT_UNAVAILABLE_AFTER_VERIFY)
        return "unused"
    monkeypatch.setattr(ca, "consume_pending_machine_onboarding", pending)
    monkeypatch.setattr(ca, "_first_run_onboarding_enabled", lambda: True)
    monkeypatch.setattr(ca, "onboard_current_user", onboarding)
    monkeypatch.setattr(ca, "prepare_startup_item_catalog", catalog)
    monkeypatch.setattr(ca, "ContainerAudit", lambda: pytest.fail("startup stop admitted the GUI"))
    monkeypatch.setattr(ca, "_show_item_catalog_startup_error", lambda *a, **k: pytest.fail("stop opened a failure dialog"))
    if stage == "before-pending":
        user_relay.request_app_stop(root)
    assert ca._prepare_gui_startup() == 0
    assert stages == {"before-pending": [], "pending": ["pending"],
                      "onboarding": ["pending", "onboarding"],
                      "catalog": ["pending", "onboarding", "catalog"],
                      "catalog-error": ["pending", "onboarding", "catalog"]}[stage]
    assert released == [True]
    assert user_relay.read_app_stop_request(root) is None


def test_operator_screen_poll_survives_job_cancellation(tmp_path, monkeypatch):
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    jobs, canceled, closed = {}, [], []
    def after(delay, callback):
        name = str(len(jobs) + len(canceled) + 1)
        jobs[name] = (delay, callback)
        return name
    app.root = SimpleNamespace(after=after, after_cancel=lambda job: canceled.append(job), winfo_exists=lambda: True)
    app.direct_sync_program_data_root = str(tmp_path)
    app.on_closing = lambda: closed.append(True)
    app.clock_job = app.stopwatch_job = app.idle_check_job = app.focus_return_job = None
    app._cancel_master_preflight = app._cancel_status_message_timer = app._stop_warning_beep = lambda: None
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    app._start_app_stop_poll()
    first = app._app_stop_poll_job
    app._cancel_all_jobs()
    assert first not in canceled
    user_relay.request_app_stop(tmp_path)
    jobs.pop(first)[1]()
    assert closed == [True]
    assert app._app_stop_poll_job in jobs
    user_relay.request_app_stop(tmp_path)
    jobs.pop(app._app_stop_poll_job)[1]()
    assert closed == [True, True]


def test_request_during_first_load_is_seen_before_work(startup, monkeypatch):
    assert Path(ca.__file__).resolve().parent == Path.cwd().resolve()
    app, released = startup
    paths = ca.build_container_audit_storage_paths(application_path=str(Path(ca.__file__).parent))
    callbacks, closed = [], []
    original_factory = ca.ContainerAudit
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    monkeypatch.setattr(ca, "consume_pending_machine_onboarding", lambda *a, **k: None)
    monkeypatch.setattr(ca, "prepare_startup_item_catalog", lambda: None)
    def create_app():
        user_relay.request_app_stop(paths.direct_sync_root)
        result = original_factory()
        result.direct_sync_program_data_root = str(paths.direct_sync_root)
        result.root.after = lambda delay, callback: callbacks.append((delay, callback)) or len(callbacks)
        result.root.winfo_exists = lambda: True
        result.on_closing = lambda: closed.append(True)
        return result
    monkeypatch.setattr(ca, "ContainerAudit", create_app)
    result = ca._prepare_gui_startup()
    assert result[0] is app
    # Invoke only the stop callback; periodic fake Tk queues are never drained.
    assert callbacks[0][0] == 0
    callbacks[0][1]()
    assert closed == [True]
    assert not user_relay.app_stop_path(paths.direct_sync_root).exists()
    assert released == []
    result[1].release()
    assert released == [True]


def test_unstaged_close_keeps_stop_poll_running(tmp_path, monkeypatch):
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    callbacks = []
    app.root = SimpleNamespace(after=lambda delay, callback: callbacks.append(callback) or len(callbacks),
                               winfo_exists=lambda: True)
    app.direct_sync_program_data_root = str(tmp_path)
    app._event_log_close_requested = True
    app._ui_close_requested = True
    app._event_log_outbox_instance = SimpleNamespace(has_unstaged=True)
    app.log_thread = SimpleNamespace(is_alive=lambda: False)
    app._event_log_writer = lambda: None
    app.show_status_message = app._poll_event_log_notice = lambda *a, **k: None
    monkeypatch.setattr(ca.threading, "Thread", lambda *a, **k: SimpleNamespace(start=lambda: None))
    app._start_app_stop_poll()
    app._finalize_application_close()
    assert not app._ui_close_requested
    closed = []
    app.on_closing = lambda: closed.append(True)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    user_relay.request_app_stop(tmp_path)
    callbacks[0]()
    assert closed == [True]


def _deadline_child(directory, mode):
    from event_log_store import EventLogOutbox
    from tests.test_container_audit_contracts import _completion_app
    from tests.test_event_log_projection import entry, rows
    directory = Path(directory)
    app = _completion_app(directory)
    if mode == "recover":
        state = json.loads((directory / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
        assert state["scanned_barcodes"] == ["BC-1", "BC-2"]
        store = EventLogOutbox(directory / "_event_outbox")
        store.drain()
        assert len(rows(Path(app.log_file_path))) == 1
        assert not list(store.directory.glob("*.json"))
        return
    assert app._save_current_tray_state()
    store = app._event_log_outbox(app.log_file_path)
    store.stage(app.log_file_path, entry("deadline"))
    app._runtime_data_root = directory
    app._application_close_complete = mode == "stop-thread"
    app.LOOP_CLEANUP_TIMEOUT_SECONDS = 0.15
    app.LOOP_CLEANUP_NOTICE_SECONDS = 0.05
    def blocked():
        while not (directory / "rescue").exists():
            time.sleep(0.01)
    if mode == "stop-thread":
        worker = threading.Thread(target=blocked, daemon=False)
        worker.start()
    else:
        app.root = SimpleNamespace(after_cancel=lambda job: None, destroy=lambda: None)
        app._cancel_all_jobs = lambda: None
        ca.stop_all_sounds = lambda: None
        app._ui_lane = SimpleNamespace(close_idle=blocked, worker_thread=SimpleNamespace(is_alive=lambda: False))
    app._cleanup_after_mainloop()


@pytest.mark.parametrize("pending", ["thread", "pump"])
def test_cleanup_deadline_exits_and_next_process_replays_durable_state(tmp_path, pending):
    command = [sys.executable, "-B", "-c",
               "from tests.test_app_stop_lifecycle import _deadline_child; import sys; _deadline_child(*sys.argv[1:])",
               str(tmp_path), "stop-" + pending]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    natural = True
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        natural = False
        (tmp_path / "rescue").touch()
        process.communicate(timeout=5)
    assert natural
    assert process.returncode == 1
    marker = json.loads((tmp_path / "shutdown-stalled.json").read_text(encoding="utf-8"))
    assert marker["pid"] == process.pid
    assert len(list((tmp_path / "_event_outbox").glob("*.json"))) == 1
    recovered = subprocess.run(command[:-1] + ["recover"], capture_output=True,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert recovered.returncode == 0
