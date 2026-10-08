"""A crash must not leave CSV admission blocking the next durable scan."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
import event_log_store as logs
from tests.test_event_log_projection import rows

CHILD = Path(__file__).with_name("event_log_lock_child.py")


def run_child(root, mode, *args):
    process = subprocess.run([sys.executable, "-B", str(CHILD), str(root), mode, *args],
                             capture_output=True, text=True)
    assert process.returncode == 0, process.stderr
    return process


def test_real_crashed_append_restarts_without_blocking_tray_save(tmp_path):
    cut = subprocess.run([sys.executable, "-B", str(CHILD), str(tmp_path), "cut"],
                         capture_output=True, text=True)
    assert cut.returncode == 77, cut.stderr
    lock = Path(logs._lock_file_path(str(tmp_path / "events.csv")))
    assert lock.exists() and time.time() - lock.stat().st_mtime < 300
    started = time.monotonic()
    run_child(tmp_path, "restart")
    summary = json.loads((tmp_path / "restart-summary.json").read_text(encoding="utf-8"))
    summary["restart_process_seconds"] = time.monotonic() - started
    (tmp_path / "restart-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    assert summary["failure_count"] == 0, summary
    assert summary["first_tray_save_seconds"] < 5, summary
    assert summary["projection_errors"] == [] and summary["pending"] == 0, summary
    assert [json.loads(row["details"])["idempotency_key"]
            for row in rows(tmp_path / "events.csv")] == ["first"]
    assert not lock.exists()


@pytest.mark.parametrize("record", ["reused", "live", "legacy-dead", "legacy-live"])
def test_real_process_lock_owner_branches(tmp_path, record):
    owner = subprocess.Popen([sys.executable, "-B", str(CHILD), str(tmp_path), "owner"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        assert owner.stdout.readline().strip() == "ready"
        identity = json.loads((tmp_path / "owner.json").read_text(encoding="utf-8"))
        assert identity["status"] == "LIVE" and identity["pid"] == owner.pid
        lock = Path(logs._lock_file_path(str(tmp_path / "events.csv")))
        if record.startswith("legacy"):
            lock.write_text(str(owner.pid), encoding="ascii")
        else:
            creation = identity["creation_identity"]
            if record == "reused":
                creation = str(int(creation) - 1)  # Same actual PID, earlier lifetime.
            lock.write_text(json.dumps({"pid": owner.pid, "creation_identity": creation}), encoding="ascii")
        original = lock.read_bytes()
        if record == "legacy-dead":
            owner.communicate("exit\n")
            assert owner.returncode == 0
        if record in {"live", "legacy-live"}:
            # A valid live owner is authoritative even for an old lock file.
            past = time.time() - logs.LOCK_STALE_SECONDS - 1
            os.utime(lock, (past, past))
        result = json.loads(run_child(tmp_path, "append", ".25").stdout)
        if record in {"live", "legacy-live"}:
            assert result["status"] == "TIMEOUT", result
            assert lock.read_bytes() == original
            assert not (tmp_path / "events.csv").exists()
        else:
            assert result["status"] == "APPENDED", result
            assert not lock.exists()
    finally:
        if owner.poll() is None:
            owner.communicate("exit\n")
        assert owner.returncode == 0, owner.stderr.read() if not owner.stderr.closed else ""


@pytest.mark.parametrize("old", [False, True])
def test_unreadable_lock_record_keeps_age_fallback(tmp_path, old):
    lock = Path(logs._lock_file_path(str(tmp_path / "events.csv")))
    lock.write_text("incomplete owner", encoding="ascii")
    original = lock.read_bytes()
    if old:
        past = time.time() - logs.LOCK_STALE_SECONDS - 1
        os.utime(lock, (past, past))
    result = json.loads(run_child(tmp_path, "append", ".25").stdout)
    assert result["status"] == ("APPENDED" if old else "TIMEOUT"), result
    if not old:
        assert lock.read_bytes() == original


def test_inaccessible_owner_is_not_reclaimed(tmp_path, monkeypatch):
    lock = Path(logs._lock_file_path(str(tmp_path / "events.csv")))
    lock.write_text(json.dumps({"pid": os.getpid(), "creation_identity": "1"}), encoding="ascii")
    past = time.time() - logs.LOCK_STALE_SECONDS - 1
    os.utime(lock, (past, past))
    original = lock.read_bytes()
    observation = logs.native_process_identity
    calls = [0]
    def inaccessible(pid):
        calls[0] += 1
        return observation(pid) if calls[0] == 1 else {"status": "UNKNOWN"}
    monkeypatch.setattr(logs, "native_process_identity", inaccessible)
    monkeypatch.setattr(logs, "LOCK_TIMEOUT_SECONDS", .05)
    with pytest.raises(TimeoutError):
        with logs._interprocess_file_lock(str(tmp_path / "events.csv")):
            pytest.fail("an inaccessible owner must retain its lock")
    assert lock.read_bytes() == original
