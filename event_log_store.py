from __future__ import annotations

import csv
import json
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
            _append_event_log_entry_unlocked(
                log_file_path,
                log_entry,
                durable=durable,
            )


def _append_event_log_entry_unlocked(
    log_file_path: str,
    log_entry: Dict[str, Any],
    *,
    durable: bool,
) -> None:
    needs_header = not os.path.exists(log_file_path) or os.stat(log_file_path).st_size == 0
    with open(log_file_path, "a", newline="", encoding="utf-8-sig") as f_handle:
        writer = csv.DictWriter(f_handle, fieldnames=EVENT_LOG_HEADERS)
        if needs_header:
            writer.writeheader()
        writer.writerow(log_entry)
        if durable:
            f_handle.flush()
            os.fsync(f_handle.fileno())


def append_event_log_entry_idempotent(
    log_file_path: str,
    log_entry: Dict[str, Any],
    *,
    event_type: str,
    idempotency_key: str,
    durable: bool = True,
) -> bool:
    """Append once by event plus details idempotency key.

    The existing-row check and append share the same process and interprocess
    locks.  Returning ``False`` proves that an identical durable projection is
    already present, which lets a SQLite projection receipt recover a crash
    after the CSV append without creating a second relay event.
    """

    normalized_event = str(event_type or "").strip()
    normalized_key = str(idempotency_key or "").strip()
    if not normalized_event or not normalized_key:
        raise ValueError("event_type and idempotency_key are required")
    if str(log_entry.get("event") or "").strip() != normalized_event:
        raise ValueError("log entry event differs from idempotent event type")
    try:
        expected_details = json.loads(str(log_entry.get("details") or ""))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("idempotent event details must be JSON") from exc
    if (
        not isinstance(expected_details, dict)
        or str(expected_details.get("idempotency_key") or "").strip()
        != normalized_key
    ):
        raise ValueError("idempotent event details key is missing or mismatched")

    with _lock_for_path(log_file_path):
        with _interprocess_file_lock(log_file_path):
            if os.path.exists(log_file_path) and os.stat(log_file_path).st_size:
                with open(
                    log_file_path,
                    newline="",
                    encoding="utf-8-sig",
                ) as f_handle:
                    reader = csv.DictReader(f_handle)
                    if reader.fieldnames != EVENT_LOG_HEADERS:
                        raise ValueError("event log header is invalid")
                    for row in reader:
                        if str(row.get("event") or "").strip() != normalized_event:
                            continue
                        try:
                            existing_details = json.loads(
                                str(row.get("details") or "")
                            )
                        except (TypeError, ValueError, json.JSONDecodeError):
                            continue
                        if (
                            not isinstance(existing_details, dict)
                            or str(
                                existing_details.get("idempotency_key") or ""
                            ).strip()
                            != normalized_key
                        ):
                            continue
                        if existing_details != expected_details:
                            raise ValueError(
                                "event log idempotency key has different details"
                            )
                        return False
            _append_event_log_entry_unlocked(
                log_file_path,
                log_entry,
                durable=durable,
            )
            return True
