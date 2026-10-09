"""CSV projection cannot retain scan admission while flushing another event."""
import builtins
from contextlib import contextmanager
import csv
import json
import os
import subprocess
import sys
from pathlib import Path
import threading
import time

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


@pytest.mark.parametrize("duplicate", [False, True])
def test_durable_receipt_projection_fsync_releases_admission_for_scan(tmp_path, monkeypatch, duplicate):
    from tests.test_feed_publish_admission import _observe_admissions
    path = str(tmp_path / "events.csv")
    if duplicate:
        logs.append_event_log_entry_idempotent(path, entry("same"), event_type="SCAN_OK", idempotency_key="same")
    records = _observe_admissions(monkeypatch, ["durable-projection"])
    sync = os.fsync
    started = threading.Event()
    held, waits, receipts, errors = [], [], [], []

    def delayed(fd):
        held.append(int(getattr(fence._WRITER_LOCAL, "depth", 0)))
        started.set()
        time.sleep(3)
        return sync(fd)

    def scan():
        try:
            assert started.wait(5)
            before = time.perf_counter()
            with fence.writer_admission("scan", timeout_seconds=5):
                waits.append(time.perf_counter() - before)
        except BaseException as exc:
            errors.append(exc)

    def legacy(path, original, *, event_type, idempotency_key, acknowledge):
        appended = logs.append_event_log_entry_idempotent(path, original, event_type=event_type,
                                                         idempotency_key=idempotency_key, durable=True)
        return acknowledge(appended)

    project = getattr(logs, "project_event_log_entry_durably", legacy)
    monkeypatch.setattr(logs.os, "fsync", delayed)
    worker = threading.Thread(target=scan)
    worker.start()
    try:
        project(path, entry("same"), event_type="SCAN_OK", idempotency_key="same", acknowledge=receipts.append)
    finally:
        worker.join(6)
    assert not worker.is_alive() and not errors and receipts == [not duplicate]
    assert held and not any(held), held
    assert waits and max(waits) < 1, waits
    assert records and max(row["hold_ms"] for row in records) < 500, records


@pytest.mark.parametrize("failure", ["fsync", "replace", "shrink", "admission", "receipt"])
def test_receipt_projection_failure_leaves_replayable_single_row(tmp_path, monkeypatch, failure):
    path = tmp_path / "events.csv"
    receipts = []
    admit, sync = logs.writer_admission, os.fsync
    calls = []

    @contextmanager
    def interleave(source, **kwargs):
        outer = int(getattr(fence._WRITER_LOCAL, "depth", 0)) == 0
        if outer:
            calls.append(source)
        if outer and len(calls) == 2:
            if failure == "replace":
                replacement = tmp_path / "replacement.csv"
                replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
            elif failure == "shrink":
                path.write_bytes((",".join(logs.EVENT_LOG_HEADERS) + "\r\n").encode("utf-8-sig"))
            elif failure == "admission":
                raise fence.WriterFencedError("ACTIVE_WRITER_FENCE", "test fence")
        with admit(source, **kwargs):
            yield

    def failed_sync(fd):
        raise OSError("disk failed")

    def acknowledge(appended):
        assert int(getattr(fence._WRITER_LOCAL, "depth", 0)) > 0
        if failure == "receipt":
            raise OSError("receipt failed")
        receipts.append(appended)

    with monkeypatch.context() as fault:
        fault.setattr(logs, "writer_admission", interleave)
        if failure == "fsync":
            fault.setattr(logs.os, "fsync", failed_sync)
        with pytest.raises((OSError, fence.WriterFencedError)):
            logs.project_event_log_entry_durably(str(path), entry("same"), event_type="SCAN_OK",
                idempotency_key="same", acknowledge=acknowledge)
    assert not receipts
    logs.project_event_log_entry_durably(str(path), entry("same"), event_type="SCAN_OK",
        idempotency_key="same", acknowledge=receipts.append)
    assert len(receipts) == 1 and len(rows(path)) == 1


def test_receipt_projection_allows_later_append_and_acknowledges_after_sync(tmp_path, monkeypatch):
    path = tmp_path / "events.csv"
    synced, receipts = [], []
    sync = os.fsync

    def interleave(fd):
        assert int(getattr(fence._WRITER_LOCAL, "depth", 0)) == 0
        sync(fd)
        synced.append(True)
        logs.append_event_log_entry_idempotent(str(path), entry("later"), event_type="SCAN_OK",
                                               idempotency_key="later", durable=False)

    def acknowledge(appended):
        assert synced and int(getattr(fence._WRITER_LOCAL, "depth", 0)) > 0
        receipts.append(appended)

    monkeypatch.setattr(logs.os, "fsync", interleave)
    logs.project_event_log_entry_durably(str(path), entry("first"), event_type="SCAN_OK",
        idempotency_key="first", acknowledge=acknowledge)
    assert receipts == [True] and len(rows(path)) == 2


@pytest.mark.parametrize("cut", ["after-append", "after-sync"])
def test_receipt_projection_process_crash_replays_one_row_and_one_receipt(tmp_path, cut):
    command = [sys.executable, "-B", str(Path(__file__).with_name("event_log_projection_child.py")), str(tmp_path)]
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    child = subprocess.run(command + ["receipt-cut", cut], capture_output=True, creationflags=flags)
    assert child.returncode == 78, (child.returncode, len(child.stderr))
    recovered = subprocess.run(command + ["receipt-recover", "none"], capture_output=True, creationflags=flags)
    assert recovered.returncode == 0, (recovered.returncode, len(recovered.stderr))
    assert len(rows(tmp_path / "events.csv")) == 1
    import sqlite3
    with sqlite3.connect(tmp_path / "receipt.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM phs_replacement_waiting_projection_receipts").fetchone()[0] == 1


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


@pytest.mark.parametrize("append_after_sync", [False, True])
def test_normal_appends_during_projection_do_not_defer_ack(tmp_path, monkeypatch, append_after_sync):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    targets = [store.stage(str(csv_path), entry(f"own-{index}")) for index in range(5)]
    originals = [target.read_bytes() for target in targets]
    sync = os.fsync
    competing_keys, errors = [], []

    def competing_sync(fd):
        index = len(competing_keys)
        assert targets[index].read_bytes() == originals[index]
        key = f"other-{index}"
        competing_keys.append(key)

        def append():
            try:
                logs.append_event_log_entry_idempotent(str(csv_path), entry(key),
                    event_type="SCAN_OK", idempotency_key=key, durable=False)
            except Exception as exc:
                errors.append(exc)

        if append_after_sync:
            sync(fd)
        thread = threading.Thread(target=append)
        thread.start()
        thread.join(5)
        assert not thread.is_alive()
        assert getattr(fence._WRITER_LOCAL, "depth", 0) == 0
        if not append_after_sync:
            sync(fd)

    with monkeypatch.context() as fault:
        fault.setattr(logs.os, "fsync", competing_sync)
        projected = store.drain()
    assert not errors
    assert len(projected) == 5
    assert competing_keys == [f"other-{index}" for index in range(5)]
    assert not list(store.directory.glob("*.json"))
    store.drain()
    keys = [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)]
    assert keys == [key for index in range(5) for key in (f"own-{index}", f"other-{index}")]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("change", ["missing", "replaced", "truncated"])
def test_projection_ack_preserves_original_when_csv_changes(tmp_path, monkeypatch, change):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("own"))
    original = target.read_bytes()
    sync, stat = os.fsync, os.stat
    synced = [False]

    def observed_sync(fd):
        sync(fd)
        synced[0] = True

    def changed_stat(path, *args, **kwargs):
        if synced[0] and path == str(csv_path):
            synced[0] = False  # Mutate after the projection handle has closed.
            prior = stat(csv_path)
            if change == "missing":
                csv_path.unlink()
            elif change == "replaced":
                replacement = tmp_path / "replacement.csv"
                replacement.write_bytes(csv_path.read_bytes())
                os.replace(replacement, csv_path)
                assert stat(csv_path).st_ino != prior.st_ino
            else:
                with csv_path.open("r+b") as stream:
                    stream.truncate(len(stream.readline()))
                assert stat(csv_path).st_ino == prior.st_ino
                assert stat(csv_path).st_size < prior.st_size
        return stat(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(logs.os, "fsync", observed_sync)
        fault.setattr(logs.os, "stat", changed_stat)
        assert store.drain() == {}
    assert target.read_bytes() == original
    assert store._projection_results == {}
    store.drain()
    store.drain()
    assert not target.exists()
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)] == ["own"]


def test_tail_repair_after_projection_signature_preserves_own_complete_row(tmp_path, monkeypatch):
    csv_path = tmp_path / "events.csv"
    store = logs.EventLogOutbox(tmp_path / "outbox")
    target = store.stage(str(csv_path), entry("own"))
    sync = os.fsync
    repaired = []

    def repair_during_sync(fd):
        if not repaired:
            own_bytes = csv_path.read_bytes()
            repaired.append(True)
            with fence.writer_admission("event_outbox_project"):
                with csv_path.open("ab") as stream:
                    stream.write(b"unfinished")
                logs.append_event_log_entry_idempotent(str(csv_path), entry("other"),
                    event_type="SCAN_OK", idempotency_key="other", durable=False)
            assert csv_path.read_bytes().startswith(own_bytes)
        return sync(fd)

    with monkeypatch.context() as fault:
        fault.setattr(logs.os, "fsync", repair_during_sync)
        assert len(store.drain()) == 1
    assert repaired == [True]
    assert not target.exists()
    assert [json.loads(row["details"])["idempotency_key"] for row in rows(csv_path)] == ["own", "other"]
