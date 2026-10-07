"""Interrupted projections retain their original durable events."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest
import event_log_store as logs
import writer_session_fence as fence
from tests.test_event_log_projection import entry, rows


def test_real_shutdown_budget_preserves_backlog_for_next_process(tmp_path):
    child = Path(__file__).with_name("event_log_projection_child.py")
    command = [sys.executable, "-B", str(child), str(tmp_path)]
    closing = subprocess.run([*command, "shutdown", ""], capture_output=True, text=True)
    assert closing.returncode == 0, closing.stderr
    summary = json.loads((tmp_path / "shutdown-summary.json").read_text(encoding="utf-8"))
    assert summary["destroyed"], summary
    assert summary["close_seconds"] < 5, summary
    assert summary["pending"] > 0, summary
    recovered = subprocess.run([*command, "shutdown-recover", ""], capture_output=True, text=True)
    assert recovered.returncode == 0, recovered.stderr
    keys = [json.loads(row["details"])["idempotency_key"] for row in rows(Path(summary["log_path"]))]
    assert keys == [str(index) for index in range(280)]
    assert not list(Path(summary["outbox_path"]).glob("*.json"))



@pytest.mark.parametrize("cut", ["append", "sync"])
def test_cancelled_projection_retains_original_before_sync_or_ack(tmp_path, monkeypatch, cut):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    append, sync = logs.append_event_log_entry_idempotent, os.fsync
    cancelled, sync_calls = [False], []
    def appended(*args, **kwargs):
        value = append(*args, **kwargs)
        if cut == "append":
            cancelled[0] = True
        return value
    def synced(fd):
        sync_calls.append(True)
        result = sync(fd)
        cancelled[0] = True
        return result
    monkeypatch.setattr(logs.os, "fsync", synced)
    assert store.drain(append=appended, should_stop=lambda: cancelled[0]) == {}
    assert target.exists()
    assert sync_calls == ([] if cut == "append" else [True])
    monkeypatch.setattr(logs.os, "fsync", sync)
    store.drain()
    assert not target.exists()
    assert len(rows(csv_path)) == 1



def test_flush_keeps_checkpoint_audits_when_projection_is_cancelled(tmp_path, monkeypatch):
    from tests.test_container_audit_contracts import _completion_app
    app = _completion_app(tmp_path)
    store = app._event_log_outbox(app.log_file_path)
    target = store.stage(app.log_file_path, entry("first"))
    cleared = []
    monkeypatch.setattr(app, "_recover_checkpoint_audit_events", lambda: ["checkpoint"])
    monkeypatch.setattr(app, "_clear_projected_checkpoint_audits", lambda items: cleared.extend(items))
    app._event_log_close_deadline = time.monotonic() - 1
    assert not app._flush_pending_event_logs()
    assert target.exists() and cleared == []
    app._event_log_close_deadline = None
    assert app._flush_pending_event_logs()
    assert cleared == ["checkpoint"] and not target.exists()
    assert len(rows(Path(app.log_file_path))) == 1


def test_close_does_not_wait_on_slow_recovery_holding_outbox_lock(tmp_path, monkeypatch):
    from tests.test_container_audit_contracts import _completion_app
    from tests.test_tk_serial_ui_lane import FakeTkRoot
    import Container_Audit as ca
    app = _completion_app(tmp_path)
    app.root = FakeTkRoot()
    app.save_settings = app._cancel_all_jobs = lambda: None
    app.show_status_message = lambda *args, **kwargs: None
    monkeypatch.setattr(ca, "stop_all_sounds", lambda: None)
    store = app._event_log_outbox(app.log_file_path)
    target = store.stage(app.log_file_path, entry("first"))
    Path(app.log_file_path).write_bytes((",".join(logs.EVENT_LOG_HEADERS) + "\r\nunfinished").encode("utf-8-sig"))
    sync = os.fsync
    entered, release = threading.Event(), threading.Event()
    def delayed(fd):
        if int(getattr(fence._WRITER_LOCAL, "depth", 0)) > 0:
            entered.set()
            release.wait(6)
        return sync(fd)
    monkeypatch.setattr(logs.os, "fsync", delayed)
    app.log_thread = threading.Thread(target=app._event_log_writer, daemon=True)
    app.log_thread.start()
    try:
        assert entered.wait(5)
        started = time.monotonic()
        for _ in range(app.EVENT_LOG_CLOSE_MAX_JOIN_ATTEMPTS):
            app._finalize_application_close()
        assert app.root.destroyed
        assert time.monotonic() - started < 5
        assert target.exists()
    finally:
        release.set()
        app.log_thread.join(10)
    assert not app.log_thread.is_alive() and target.exists()
    monkeypatch.setattr(logs.os, "fsync", sync)
    app._event_log_close_deadline = None
    assert app._flush_pending_event_logs()
    assert len(rows(Path(app.log_file_path))) == 1 and not target.exists()
