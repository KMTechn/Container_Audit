from __future__ import annotations

import csv
import json
import os
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict

from writer_session_fence import writer_admission, writer_sink
from storage_utils import atomic_write_json


EVENT_LOG_HEADERS = ["timestamp", "worker_name", "event", "details"]
LOCK_TIMEOUT_SECONDS = 10.0
LOCK_STALE_SECONDS = 300.0
_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}


class EventLogOutbox:
    """Keep original payloads until their idempotent CSV projection is durable."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self._lock = threading.RLock()
        self._unstaged: deque[dict[str, Any]] = deque()

    @property
    def has_unstaged(self) -> bool:
        with self._lock:
            return bool(self._unstaged)

    @writer_sink("event_outbox_stage")
    def stage(self, log_file_path: str, log_entry: Dict[str, Any]) -> None:
        with self._lock:
            self._unstaged.append({"log_file_path": log_file_path, "log_entry": dict(log_entry)})
            self._persist_unstaged()

    def _persist_unstaged(self) -> None:
        while self._unstaged:
            path = self.directory / f"{time.time_ns():020d}-{uuid.uuid4().hex}.json"
            atomic_write_json(path, self._unstaged[0])
            self._unstaged.popleft()

    @writer_sink("event_outbox_project")
    def drain(self) -> None:
        with self._lock:
            self._persist_unstaged()
            for path in sorted(self.directory.glob("*.json")):
                payload = json.loads(path.read_text(encoding="utf-8"))
                entry = payload["log_entry"]
                detail = json.loads(entry["details"])
                appended = append_event_log_entry_idempotent(
                    payload["log_file_path"], entry,
                    event_type=entry["event"], idempotency_key=detail["idempotency_key"],
                    durable=True,
                )
                if not appended:
                    # A prior fsync/ACK may have failed after the row reached CSV.
                    with open(payload["log_file_path"], "ab") as handle:
                        handle.flush()
                        os.fsync(handle.fileno())
                path.unlink()


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
    with writer_admission("event_interprocess_lock"):
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


@writer_sink("event_csv_append")
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


@writer_sink("event_csv_unlocked_append")
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


@writer_sink("event_csv_idempotent_append")
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
