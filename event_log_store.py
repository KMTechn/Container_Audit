from __future__ import annotations

import csv
import os
import threading
from typing import Any, Dict


EVENT_LOG_HEADERS = ["timestamp", "worker_name", "event", "details"]
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


def append_event_log_entry(
    log_file_path: str,
    log_entry: Dict[str, Any],
    *,
    durable: bool = False,
) -> None:
    with _lock_for_path(log_file_path):
        needs_header = not os.path.exists(log_file_path) or os.stat(log_file_path).st_size == 0
        with open(log_file_path, "a", newline="", encoding="utf-8-sig") as f_handle:
            writer = csv.DictWriter(f_handle, fieldnames=EVENT_LOG_HEADERS)
            if needs_header:
                writer.writeheader()
            writer.writerow(log_entry)
            if durable:
                f_handle.flush()
                os.fsync(f_handle.fileno())
