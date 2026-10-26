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


def test_nested_durable_receipt_projection_preserves_existing_sync_path(tmp_path, monkeypatch):
    path = str(tmp_path / "events.csv")
    sync, depths, receipts = os.fsync, [], []
    def observe(fd):
        depths.append(int(getattr(fence._WRITER_LOCAL, "depth", 0)))
        return sync(fd)
    monkeypatch.setattr(logs.os, "fsync", observe)
    with fence.writer_admission("nested-receipt"):
        logs.project_event_log_entry_durably(path, entry("same"), event_type="SCAN_OK",
            idempotency_key="same", acknowledge=receipts.append)
        logs.project_event_log_entry_durably(path, entry("same"), event_type="SCAN_OK",
            idempotency_key="same", acknowledge=receipts.append)
    assert len(depths) == 2 and all(depths) and receipts == [True, False]
    assert len(rows(Path(path))) == 1


def test_nested_projection_defers_sync_and_ack(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    sync, depths = os.fsync, []
    def observed(fd):
        if csv_path.exists() and os.fstat(fd).st_ino == csv_path.stat().st_ino:
            depths.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        return sync(fd)
    monkeypatch.setattr(logs.os, "fsync", observed)
    with fence.writer_admission("event_outbox_project"):
        assert store.drain(through=target) == {}
        assert target.exists()
        assert depths == []
    assert len(rows(csv_path)) == 1
    store.drain()
    assert depths == [0]
    assert not target.exists()
    assert len(rows(csv_path)) == 1



def test_nested_projection_does_not_wait_for_background_ack(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    sync = os.fsync
    entered, release = threading.Event(), threading.Event()
    errors = []
    def delayed(fd):
        entered.set()
        assert release.wait(5)
        return sync(fd)
    def project():
        try:
            store.drain()
        except Exception as exc:
            errors.append(exc)
    monkeypatch.setattr(logs.os, "fsync", delayed)
    worker = threading.Thread(target=project)
    worker.start()
    try:
        assert entered.wait(5)
        with fence.writer_admission("event_outbox_project"):
            started = time.monotonic()
            assert store.drain(through=target) == {}
            assert time.monotonic() - started < 1
            assert target.exists()
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and not errors
    assert not target.exists()
    assert len(rows(csv_path)) == 1



@pytest.mark.parametrize("event", ["SCAN_OK", "TRAY_COMPLETE"])
def test_sync_nested_accepts_durable_original_without_projection_wait(tmp_path, monkeypatch, event):
    from tests.test_container_audit_contracts import _completion_app
    app = _completion_app(tmp_path)
    original = entry("nested-target")
    original["event"] = event
    monkeypatch.setattr(app.log_queue, "join", lambda: pytest.fail("nested queue wait"))
    with fence.writer_admission("event_outbox_project"):
        assert app._write_event_log_entry({"log_file_path": app.log_file_path,
            "log_entry": original, "worker_record": {}, "local_only": True}, synchronous=True)
        assert app._last_log_event_projection_pending
        assert len(list(app._event_log_outbox_instance.directory.glob("*.json"))) == 1
    assert app._flush_pending_event_logs()
    assert len(rows(Path(app.log_file_path))) == 1



def test_nested_damaged_tail_defers_all_mutation_until_background_repair(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    damaged = (",".join(logs.EVENT_LOG_HEADERS) + "\r\n").encode("utf-8-sig") + b"unfinished\0\0\n"
    csv_path.write_bytes(damaged)
    sync, observations = os.fsync, []
    def observed(fd):
        observations.append((getattr(fence._WRITER_LOCAL, "depth", 0), os.fstat(fd).st_size))
        return sync(fd)
    monkeypatch.setattr(logs.os, "fsync", observed)
    with fence.writer_admission("event_outbox_project"):
        assert store.drain() == {}
        assert csv_path.read_bytes() == damaged
        assert target.exists() and observations == []
    store.drain()
    assert len(observations) == 2
    assert observations[0][0] > 0 and observations[1][0] == 0
    assert len(rows(csv_path)) == 1 and not target.exists()


def test_nested_flush_keeps_checkpoint_originals_until_background_projection(tmp_path, monkeypatch):
    from tests.test_container_audit_contracts import _completion_app
    app = _completion_app(tmp_path)
    store = app._event_log_outbox(app.log_file_path)
    target = store.stage(app.log_file_path, entry("first"))
    cleared = []
    monkeypatch.setattr(app, "_recover_checkpoint_audit_events", lambda: ["checkpoint"])
    monkeypatch.setattr(app, "_clear_projected_checkpoint_audits", lambda items, projected: cleared.extend(items))
    with fence.writer_admission("event_outbox_project"):
        assert not app._flush_pending_event_logs()
        assert target.exists() and cleared == []
    assert app._flush_pending_event_logs()
    assert cleared == ["checkpoint"] and not target.exists()
    assert len(rows(Path(app.log_file_path))) == 1
