from __future__ import annotations

import csv
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict


EVENT_LOG_HEADERS = ["timestamp", "worker_name", "event", "details"]
LOCK_TIMEOUT_SECONDS = 10.0
LOCK_STALE_SECONDS = 300.0
_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}


def _lock_for_path(log_file_path: str) -> threading.Lock:
    key = os.path.abspath(log_file_path)
    with _LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


def _lock_file_path(log_file_path: str) -> str:
    return f"{os.path.abspath(log_file_path)}.lock"


@contextmanager
def _interprocess_file_lock(log_file_path: str):
    lock_path = _lock_file_path(log_file_path)
    Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, str(os.getpid()).encode("ascii", errors="ignore"))
        except (FileExistsError, PermissionError):
            if not os.path.exists(lock_path):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
                continue
            try:
                age = time.time() - os.path.getmtime(lock_path)
                if age > LOCK_STALE_SECONDS:
                    try:
                        os.unlink(lock_path)
                    except (FileNotFoundError, PermissionError):
                        pass
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"event log lock timeout: {lock_path}")
            time.sleep(0.01)
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(lock_path)
        except FileNotFoundError:
            pass


def append_event_log_entry(
    log_file_path: str,
    log_entry: Dict[str, Any],
    *,
    durable: bool = False,
) -> None:
    with _lock_for_path(log_file_path):
        with _interprocess_file_lock(log_file_path):
            needs_header = not os.path.exists(log_file_path) or os.stat(log_file_path).st_size == 0
            with open(log_file_path, "a", newline="", encoding="utf-8-sig") as f_handle:
                writer = csv.DictWriter(f_handle, fieldnames=EVENT_LOG_HEADERS)
                if needs_header:
                    writer.writeheader()
                writer.writerow(log_entry)
                if durable:
                    f_handle.flush()
                    os.fsync(f_handle.fileno())
