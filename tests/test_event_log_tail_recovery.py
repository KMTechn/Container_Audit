"""Interrupted projections retain their original durable events."""
import json
import builtins
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


@pytest.mark.parametrize("cut", ["half", "no-newline", "nul", "nul-newline",
                                 "after-append", "after-sync", "after-ack"])
def test_real_process_interruption_replays_complete_rows_once(tmp_path, cut):
    child = Path(__file__).with_name("event_log_projection_child.py")
    command = [sys.executable, "-B", str(child), str(tmp_path)]
    crashed = subprocess.run([*command, "cut", cut], capture_output=True, text=True)
    assert crashed.returncode == 77, crashed.stderr
    restarted = subprocess.run([*command, "recover", cut], capture_output=True, text=True)
    assert restarted.returncode == 0, restarted.stderr
    csv_path = tmp_path / "events.csv"
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)] == ["first", "second"]
    assert csv_path.read_bytes().endswith(b"\n")
    assert b"\0" not in csv_path.read_bytes()
    assert not list((tmp_path / "outbox").glob("*.json"))


def test_tail_repair_preserves_complete_prefix_and_invalidates_cached_keys(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    original = entry("first", value=1)
    logs.append_event_log_entry_idempotent(str(csv_path), original,
                                         event_type="SCAN_OK", idempotency_key="first")
    # Simulate an externally changed, previously indexed last row.
    raw = csv_path.read_bytes()
    csv_path.write_bytes(raw[:-2] + b"\0" * 9000 + b"\n")
    sync, sync_sizes = os.fsync, []
    def observed(fd):
        sync_sizes.append(os.fstat(fd).st_size)
        return sync(fd)
    monkeypatch.setattr(logs.os, "fsync", observed)
    store = logs.EventLogOutbox(tmp_path / "outbox")
    store.stage(str(csv_path), original)
    sync_sizes.clear()
    store.drain()
    assert rows(csv_path) == [original]
    assert len(sync_sizes) == 2  # One recovery sync, then the projection sync.
    with pytest.raises(ValueError, match="different details"):
        logs.append_event_log_entry_idempotent(str(csv_path), entry("first", value=2),
                                             event_type="SCAN_OK", idempotency_key="first")


@pytest.mark.parametrize("header", [b"timestamp,worker_name,event,details", b"bad\0header\n"])
def test_damaged_header_is_not_replaced_or_acknowledged(tmp_path, header):
    csv_path = tmp_path / "events.csv"
    csv_path.write_bytes(header)
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    with pytest.raises(ValueError, match="header is invalid"):
        store.drain()
    assert csv_path.read_bytes() == header and target.exists()


def test_changed_csv_after_sync_keeps_original_until_repaired_and_resynced(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    sync = os.fsync
    def changed(fd):
        value = sync(fd)
        raw = csv_path.read_bytes()
        csv_path.write_bytes(raw[:-2])
        return value
    monkeypatch.setattr(logs.os, "fsync", changed)
    assert store.drain() == {}
    assert target.exists()
    monkeypatch.setattr(logs.os, "fsync", sync)
    store.drain()
    assert not target.exists()
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)] == ["first"]


def test_missing_csv_after_sync_does_not_claim_projection(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("first"))
    class RemovedAfterClose:
        def __init__(self, handle):
            self.handle = handle
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def close(self):
            self.handle.close()
            csv_path.unlink()
    def opened(path, mode="r", *args, **kwargs):
        handle = builtins.open(path, mode, *args, **kwargs)
        return RemovedAfterClose(handle) if Path(path) == csv_path and mode == "ab" else handle
    with monkeypatch.context() as fault:
        fault.setattr(logs, "open", opened, raising=False)
        assert store.drain() == {}
        assert target.exists()
    store.drain()
    assert not target.exists()
    assert len(rows(csv_path)) == 1
