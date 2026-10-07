"""CSV projection cannot retain scan admission while flushing another event."""
import builtins
import csv
import json
import os
from pathlib import Path
import threading

import pytest

import event_log_store as logs
import writer_session_fence as fence


def entry(key, **details):
    return {"timestamp": "2026-10-08T04:00:00", "worker_name": "fixture",
            "event": "SCAN_OK",
            "details": json.dumps({"idempotency_key": key, **details})}


def rows(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def test_csv_fsync_releases_admission_and_outbox_for_scan(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    store.stage(str(csv_path), entry("first"))
    entered, release, staged = threading.Event(), threading.Event(), threading.Event()
    sync = os.fsync
    depths, errors = [], []

    def delayed(fd):
        if csv_path.exists() and os.fstat(fd).st_ino == csv_path.stat().st_ino:
            depths.append(getattr(fence._WRITER_LOCAL, "depth", 0))
            entered.set()
            assert release.wait(5)
        return sync(fd)

    def drain():
        try:
            store.drain()
        except Exception as exc:
            errors.append(exc)

    def scan():
        try:
            store.stage(str(csv_path), entry("next"))
            staged.set()
        except Exception as exc:
            errors.append(exc)

    monkeypatch.setattr(logs.os, "fsync", delayed)
    projection = threading.Thread(target=drain)
    foreground = threading.Thread(target=scan)
    projection.start()
    try:
        assert entered.wait(5)
        foreground.start()
        progressed = staged.wait(1)
    finally:
        release.set()
        projection.join(10)
        if foreground.ident is not None:
            foreground.join(10)
    assert not projection.is_alive() and not foreground.is_alive()
    assert not errors
    assert depths == [0], "CSV fsync retained writer admission"
    assert progressed, "an unrelated CSV fsync blocked durable scan staging"
    store.drain()
    assert len(rows(csv_path)) == 2


@pytest.mark.parametrize("cut", ["append", "fsync", "before_ack", "after_ack"])
def test_projection_restart_at_each_durability_boundary(tmp_path, monkeypatch, cut):
    csv_path = tmp_path / "events.csv"
    directory = tmp_path / "outbox"
    store = logs.EventLogOutbox(directory)
    store.stage(str(csv_path), entry("same", product_barcode="synthetic"))
    append, sync, unlink = logs.append_event_log_entry_idempotent, os.fsync, Path.unlink
    pending = [True]

    def append_cut(*args, **kwargs):
        result = append(*args, **kwargs)
        if cut == "append" and pending[0]:
            pending[0] = False
            raise OSError("synthetic interruption after append")
        return result

    def sync_cut(fd):
        if cut == "fsync" and pending[0]:
            pending[0] = False
            raise OSError("synthetic interruption at CSV fsync")
        return sync(fd)

    def ack_cut(path, *args, **kwargs):
        if path.parent == directory and pending[0]:
            pending[0] = False
            if cut == "after_ack":
                unlink(path, *args, **kwargs)
            raise OSError("synthetic interruption at projection ACK")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(logs.os, "fsync", sync_cut)
        if cut in {"before_ack", "after_ack"}:
            fault.setattr(Path, "unlink", ack_cut)
        with pytest.raises(OSError):
            store.drain(append=append_cut)
    restarted = logs.EventLogOutbox(directory)
    restarted.drain()
    restarted.drain()
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)] == ["same"]
    assert not list(directory.glob("*.json"))


def test_projection_index_reads_csv_once_then_rebuilds_on_external_change(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    logs.append_event_log_entry_idempotent(str(csv_path), entry("seed"),
                                        event_type="SCAN_OK", idempotency_key="seed")
    reads = []

    def opened(path, mode="r", *args, **kwargs):
        if Path(path) == csv_path and mode == "r":
            reads.append(path)
        return builtins.open(path, mode, *args, **kwargs)

    monkeypatch.setattr(logs, "open", opened, raising=False)
    # A new process must build its index from the actual CSV, not its outbox.
    if hasattr(logs, "_CSV_INDEXES"):
        logs._CSV_INDEXES.clear()
    for key in ("a", "b", "c"):
        assert logs.append_event_log_entry_idempotent(str(csv_path), entry(key),
                   event_type="SCAN_OK", idempotency_key=key)
    assert len(reads) == 1
    with csv_path.open("a", newline="", encoding="utf-8") as stream:
        csv.DictWriter(stream, fieldnames=logs.EVENT_LOG_HEADERS).writerow(entry("outside", value=1))
    assert not logs.append_event_log_entry_idempotent(str(csv_path), entry("outside", value=1),
               event_type="SCAN_OK", idempotency_key="outside")
    assert len(reads) == 2
    with pytest.raises(ValueError, match="different details"):
        logs.append_event_log_entry_idempotent(str(csv_path), entry("outside", value=2),
                   event_type="SCAN_OK", idempotency_key="outside")
    assert len(rows(csv_path)) == 5


def test_durable_duplicate_syncs_a_row_whose_projection_has_not_synced(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    original = entry("same")
    assert logs.append_event_log_entry_idempotent(str(csv_path), original,
               event_type="SCAN_OK", idempotency_key="same", durable=False)
    sync = os.fsync
    synced = []
    def observed(fd):
        synced.append(os.fstat(fd).st_ino)
        return sync(fd)
    monkeypatch.setattr(logs.os, "fsync", observed)
    assert not logs.append_event_log_entry_idempotent(str(csv_path), original,
               event_type="SCAN_OK", idempotency_key="same", durable=True)
    assert synced == [csv_path.stat().st_ino]


def test_sync_scan_projects_fifo_through_its_target_without_waiting_for_tail(tmp_path, monkeypatch):
    from tests.test_container_audit_contracts import _completion_app
    app = _completion_app(tmp_path)
    store = app._event_log_outbox(app.log_file_path)
    store.stage(app.log_file_path, entry("before"))
    stage = store.stage
    def add_tail(*args, **kwargs):
        target = stage(*args, **kwargs)
        for index in range(30):
            stage(app.log_file_path, entry(f"tail-{index}"))
        return target
    monkeypatch.setattr(store, "stage", add_tail)
    joins = []
    def unrelated_join():
        joins.append(True)
        raise AssertionError("synchronous scan waited for the entire log queue")
    monkeypatch.setattr(app.log_queue, "join", unrelated_join)
    assert app._write_event_log_entry({"log_file_path": app.log_file_path,
        "log_entry": entry("target"), "worker_record": {}, "local_only": False}, synchronous=True)
    assert joins == []
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(Path(app.log_file_path))] == ["before", "target"]
    assert len(list(store.directory.glob("*.json"))) == 30
    store.drain()
    assert len(rows(Path(app.log_file_path))) == 32


def test_concurrent_drains_project_once_in_fifo_order_and_target_skips_tail_wait(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    store.stage(str(csv_path), entry("first"))
    target = store.stage(str(csv_path), entry("target"))
    store.stage(str(csv_path), entry("tail"))
    first_entered, first_release = threading.Event(), threading.Event()
    tail_entered, tail_release, target_done = threading.Event(), threading.Event(), threading.Event()
    local = threading.local()
    calls, errors = [], []
    append, sync = logs.append_event_log_entry_idempotent, os.fsync
    def observed_append(*args, **kwargs):
        local.key = kwargs["idempotency_key"]
        calls.append(local.key)
        return append(*args, **kwargs)
    def delayed(fd):
        key = getattr(local, "key", "")
        if key == "first":
            first_entered.set()
            assert first_release.wait(5)
        if key == "tail":
            tail_entered.set()
            assert tail_release.wait(5)
        return sync(fd)
    def project(through=None):
        try:
            store.drain(append=observed_append, through=through)
            if through is not None:
                target_done.set()
        except Exception as exc:
            errors.append(exc)
    monkeypatch.setattr(logs.os, "fsync", delayed)
    background = threading.Thread(target=project)
    foreground = threading.Thread(target=project, args=(target,))
    background.start()
    try:
        assert first_entered.wait(5)
        foreground.start()
        first_release.set()
        assert tail_entered.wait(5)
        progressed = target_done.wait(2)
    finally:
        first_release.set()
        tail_release.set()
        background.join(10)
        if foreground.ident is not None:
            foreground.join(10)
    assert not background.is_alive() and not foreground.is_alive()
    assert not errors
    assert progressed, "target completion waited for a later CSV fsync"
    assert calls == ["first", "target", "tail"]
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)] == calls
    assert not list(store.directory.glob("*.json"))


def test_new_fence_between_csv_fsync_and_ack_preserves_original_for_retry(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    store.stage(str(csv_path), entry("same"))
    sync = os.fsync
    blocked = [False]
    monkeypatch.setattr(fence, "active_fence", lambda *args, **kwargs:
        {"status": "PREPARED", "delegated_sources": []} if blocked[0] else None)
    def activated(fd):
        result = sync(fd)
        blocked[0] = True
        return result
    monkeypatch.setattr(logs.os, "fsync", activated)
    with pytest.raises(fence.WriterFencedError) as failure:
        store.drain()
    assert failure.value.code == "ACTIVE_WRITER_FENCE"
    assert len(list(store.directory.glob("*.json"))) == 1
    blocked[0] = False
    monkeypatch.setattr(logs.os, "fsync", sync)
    store.drain()
    assert len(rows(csv_path)) == 1
    assert not list(store.directory.glob("*.json"))
