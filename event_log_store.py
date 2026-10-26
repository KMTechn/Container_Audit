from __future__ import annotations

import csv
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict

from auto_update import native_process_identity
from writer_session_fence import _WRITER_LOCAL, writer_admission, writer_sink
from storage_utils import atomic_write_json


EVENT_LOG_HEADERS = ["timestamp", "worker_name", "event", "details"]
LOCK_TIMEOUT_SECONDS = 10.0
LOCK_STALE_SECONDS = 300.0
_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}
_CSV_INDEXES: dict[str, tuple[tuple[int, int, int], dict[tuple[str, str], Any]]] = {}


class _ProjectionPending(RuntimeError):
    """A nested caller must leave damaged-tail recovery to the log worker."""


class EventLogOutbox:
    """Keep original payloads until their idempotent CSV projection is durable."""

    def __init__(self, directory: str | Path, *, read_retry=None):
        self.directory = Path(directory)
        self._lock = threading.RLock()
        self._projection_condition = threading.Condition(self._lock)
        self._projecting: set[Path] = set()
        self._unstaged: deque[dict[str, Any]] = deque()
        self._staged_payloads = set()
        self._staged_paths: dict[str, Path] = {}
        for path in self.directory.glob('*.json'):
            try:
                read = lambda: path.read_text(encoding='utf-8')
                raw = read() if read_retry is None else read_retry(read)
                encoded = json.dumps(json.loads(raw), sort_keys=True)
                self._staged_payloads.add(encoded)
                self._staged_paths[encoded] = path
            except FileNotFoundError:
                pass  # Another admitted writer finished this projection.
        self._projection_results = {}
        self._sequence = max(
            (int(path.name[:20]) for path in self.directory.glob("*.json")
             if path.name[:20].isdigit()), default=0,
        )

    @property
    def has_unstaged(self) -> bool:
        # A deque item is removed only after its original is durable. This
        # atomic snapshot also lets close inspect it during a slow file sync.
        return bool(self._unstaged)

    def stage(self, log_file_path: str, log_entry: Dict[str, Any], *, worker_record=None) -> Path | None:
        with self._lock:
            payload = {"log_file_path": log_file_path, "log_entry": dict(log_entry)}
            if worker_record:
                payload["worker_record"] = dict(worker_record)
            self._unstaged.append(payload)
        # Retain before admission can fail; release the lock before waiting for
        # admission, matching drain's admission -> outbox lock order.
        self._persist_unstaged()
        with self._lock:
            # None means a concurrent projector has already synced/ACKed it.
            return self._staged_paths.get(json.dumps(payload, sort_keys=True))

    @writer_sink("event_outbox_stage")
    def _persist_unstaged(self) -> None:
        with self._lock:
            while self._unstaged:
                encoded = json.dumps(self._unstaged[0], sort_keys=True)
                if encoded in self._staged_payloads:
                    self._unstaged.popleft()
                    continue
                self._sequence = max(self._sequence + 1, time.time_ns())
                path = self.directory / f"{self._sequence:020d}-{uuid.uuid4().hex}.json"
                atomic_write_json(path, self._unstaged[0])
                self._staged_payloads.add(encoded)
                self._staged_paths[encoded] = path
                self._unstaged.popleft()

    def drain(self, *, append=None, through: Path | None = None, should_stop=None) -> dict[tuple[str, str, str], bool]:
        projected = {}
        append = append or append_event_log_entry_idempotent
        if through is not None and through.parent != self.directory:
            raise ValueError("projection target must belong to this outbox")
        if should_stop is not None and should_stop():
            return projected
        nested = int(getattr(_WRITER_LOCAL, "depth", 0)) > 0
        if nested:
            if self.has_unstaged:
                return projected
        else:
            self._persist_unstaged()
        paths = sorted(self.directory.glob("*.json"))
        if through is not None and through not in paths:
            return projected
        for path in paths:
            reserved = False
            try:
                while not reserved:
                    if should_stop is not None and should_stop():
                        return projected
                    with writer_admission("event_outbox_project"):
                        with self._lock:
                            if should_stop is not None and should_stop():
                                return projected
                            try:
                                original = path.read_text(encoding="utf-8")
                            except FileNotFoundError:
                                break  # Another projector synced/ACKed it.
                            if path not in self._projecting:
                                self._projecting.add(path)
                                reserved = True
                                payload = json.loads(original)
                                entry = payload["log_entry"]
                                detail = json.loads(entry["details"])
                                appended = append(
                                    payload["log_file_path"], entry,
                                    event_type=entry["event"], idempotency_key=detail["idempotency_key"],
                                    durable=False,
                                    defer_repair=nested,
                                )
                                handle = open(payload["log_file_path"], "ab")
                                stat = os.fstat(handle.fileno())
                                projection_signature = (stat.st_size, stat.st_ino)
                            elif nested:
                                return projected  # The background worker needs the outer admission for ACK.
                    if not reserved:
                        # Never pass an earlier row still being synced. Both
                        # admission and the RLock are released while waiting.
                        with self._projection_condition:
                            self._projection_condition.wait_for(
                                lambda: path not in self._projecting or (should_stop is not None and should_stop()),
                                timeout=.05 if should_stop is not None else None,
                            )
                if reserved:
                    if nested or (should_stop is not None and should_stop()):
                        handle.close()
                        return projected  # Append only; sync and ACK belong to a nonnested drain.
                    try:
                        # A readable row may not have survived a prior fsync.
                        handle.flush()
                        os.fsync(handle.fileno())
                    finally:
                        handle.close()
                    if should_stop is not None and should_stop():
                        return projected
                    with writer_admission("event_outbox_project"):
                        with self._lock:
                            if should_stop is not None and should_stop():
                                return projected
                            try:
                                stat = os.stat(payload["log_file_path"])
                            except FileNotFoundError:
                                return projected  # A removed CSV is not an acknowledged outbox row.
                            if stat.st_ino != projection_signature[1] or stat.st_size < projection_signature[0]:
                                # Replacement/shrinkage invalidates this receipt;
                                # later appends preserve our already synced row.
                                return projected
                            try:
                                if path.read_text(encoding="utf-8") != original:
                                    raise ValueError("event outbox payload changed during projection")
                                path.unlink()
                            except FileNotFoundError:
                                pass
                            encoded = json.dumps(payload, sort_keys=True)
                            self._staged_payloads.discard(encoded)
                            self._staged_paths.pop(encoded, None)
                            key = (payload["log_file_path"], entry["event"], detail["idempotency_key"])
                            projected[key] = appended
                            self._projection_results[key] = appended
                            while len(self._projection_results) > 256:
                                self._projection_results.pop(next(iter(self._projection_results)))
            except _ProjectionPending:
                return projected
            finally:
                if reserved:
                    with self._projection_condition:
                        self._projecting.discard(path)
                        self._projection_condition.notify_all()
            if path == through:
                break
            # A waiting foreground admission gets a turn between rows.
            time.sleep(0)
        return projected

    def take_projection_result(self, log_file_path, log_entry):
        key = (log_file_path, log_entry['event'], json.loads(log_entry['details'])['idempotency_key'])
        with self._lock:
            return self._projection_results.pop(key, True)


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


def _lock_owner_is_dead(lock_path: str) -> bool | None:
    """Return None only for an unreadable record, which uses the age fallback."""
    try:
        with open(lock_path, "rb") as handle:
            raw = handle.read(4097)
        if len(raw) > 4096:
            return None
        text = raw.decode("ascii").strip()
        if text.isdecimal():
            pid, creation = int(text), None  # Previous releases wrote PID only.
        else:
            record = json.loads(text)
            pid, creation = record["pid"], record["creation_identity"]
            if not isinstance(creation, str) or not creation.isdecimal():
                return None
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
            return None
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        return None
    owner = native_process_identity(pid)
    if owner["status"] == "ABSENT":
        return True
    if owner["status"] == "LIVE" and creation is not None:
        return owner["creation_identity"] != creation
    # An inaccessible process is not evidence that its owner died.
    return None


@contextmanager
def _interprocess_file_lock(log_file_path: str):
    with writer_admission("event_interprocess_lock"):
        lock_path = _lock_file_path(log_file_path)
        Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
        owner = native_process_identity(os.getpid())
        if owner["status"] != "LIVE":
            raise OSError("event log lock owner creation identity is unobservable")
        payload = json.dumps({"pid": os.getpid(),
                              "creation_identity": owner["creation_identity"]}).encode("ascii")
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        fd: int | None = None
        while fd is None:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            except (FileExistsError, PermissionError):
                if not os.path.exists(lock_path):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
                    continue
                try:
                    dead = _lock_owner_is_dead(lock_path)
                    if dead or (dead is None and
                                time.time() - os.path.getmtime(lock_path) > LOCK_STALE_SECONDS):
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
            os.write(fd, payload)
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
    _repair_event_log_tail_unlocked(log_file_path)
    needs_header = not os.path.exists(log_file_path) or os.stat(log_file_path).st_size == 0
    with open(log_file_path, "a", newline="", encoding="utf-8-sig") as f_handle:
        writer = csv.DictWriter(f_handle, fieldnames=EVENT_LOG_HEADERS)
        if needs_header:
            writer.writeheader()
        writer.writerow(log_entry)
        if durable:
            f_handle.flush()
            os.fsync(f_handle.fileno())


@writer_sink("event_csv_unlocked_append")
def _repair_event_log_tail_unlocked(log_file_path: str, *, defer: bool = False) -> None:
    """Discard only the incomplete suffix while the caller holds both file locks."""
    if not os.path.exists(log_file_path) or not os.stat(log_file_path).st_size:
        return
    with open(log_file_path, "r+b") as handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(size - 1)
        terminated = handle.read(1) == b"\n"
        line_end, cursor = size, size - int(terminated)
        line_nul = removed_nul = False
        keep = 0
        while cursor:
            start = max(0, cursor - 4096)
            handle.seek(start)
            chunk = handle.read(cursor - start)
            newline = chunk.rfind(b"\n")
            line_nul |= b"\0" in chunk[newline + 1:]
            if newline < 0:
                cursor = start
                continue
            if terminated and not line_nul:
                keep = line_end
                break
            removed_nul |= line_nul
            line_end = start + newline + 1
            cursor = line_end - 1
            terminated, line_nul = True, False
        else:
            if terminated and not line_nul:
                keep = line_end
            removed_nul |= line_nul
        if keep == size:
            return
        _CSV_INDEXES.pop(os.path.abspath(log_file_path), None)
        handle.seek(0)
        header = handle.readline(65536)
        try:
            valid_header = (header.endswith(b"\n") and
                            next(csv.reader([header.decode("utf-8-sig")])) == EVENT_LOG_HEADERS)
        except (UnicodeError, csv.Error, StopIteration):
            valid_header = False
        if not keep or not valid_header:
            raise ValueError("event log header is invalid")
        if defer:
            raise _ProjectionPending("EVENT_CSV_TAIL_RECOVERY_PENDING")
        handle.truncate(keep)
        handle.flush()
        # Exceptional recovery only: preserve admission -> file-lock ordering.
        # Ordinary projection fsync remains outside writer admission.
        os.fsync(handle.fileno())
        logging.getLogger(__name__).warning(
            "EVENT_CSV_TAIL_REPAIRED bytes=%d reason=%s", size - keep,
            "NUL_TAIL" if removed_nul else "UNTERMINATED_TAIL",
        )


def project_event_log_entry_durably(
    log_file_path: str,
    log_entry: Dict[str, Any],
    *,
    event_type: str,
    idempotency_key: str,
    acknowledge: Callable[[bool], Any],
) -> Any:
    """Sync the exact appended file before admitting its projection receipt."""
    if int(getattr(_WRITER_LOCAL, "depth", 0)) > 0:
        appended = append_event_log_entry_idempotent(
            log_file_path, log_entry, event_type=event_type,
            idempotency_key=idempotency_key, durable=True,
        )
        return acknowledge(appended)
    with writer_admission("event_csv_idempotent_append"):
        appended = append_event_log_entry_idempotent(
            log_file_path, log_entry, event_type=event_type,
            idempotency_key=idempotency_key, durable=False,
        )
        handle = open(log_file_path, "ab")
        try:
            stat = os.fstat(handle.fileno())
            signature = (stat.st_size, stat.st_ino)
        except BaseException:
            handle.close()
            raise
    try:
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()
    with writer_admission("event_csv_idempotent_append"):
        stat = os.stat(log_file_path)
        if stat.st_ino != signature[1] or stat.st_size < signature[0]:
            raise OSError("EVENT_CSV_PROJECTION_CHANGED")
        return acknowledge(appended)


@writer_sink("event_csv_idempotent_append")
def append_event_log_entry_idempotent(
    log_file_path: str,
    log_entry: Dict[str, Any],
    *,
    event_type: str,
    idempotency_key: str,
    durable: bool = True,
    defer_repair: bool = False,
) -> bool:
    """Append once by event plus details idempotency key.

    The existing-row check and append share the same process and interprocess
    locks. With ``durable=True``, returning ``False`` also syncs the existing
    projection before a SQLite receipt acknowledges it. An outbox projector
    uses ``durable=False`` and must sync separately before its own ACK.
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
            _repair_event_log_tail_unlocked(log_file_path, defer=defer_repair)
            path_key = os.path.abspath(log_file_path)
            stat = os.stat(log_file_path) if os.path.exists(log_file_path) else None
            signature = (stat.st_size, stat.st_mtime_ns, stat.st_ino) if stat else (0, 0, 0)
            cached = _CSV_INDEXES.get(path_key)
            if cached is not None and cached[0] == signature:
                index = cached[1]
            else:
                index = {}
            if (cached is None or cached[0] != signature) and stat and stat.st_size:
                with open(
                    log_file_path,
                    newline="",
                    encoding="utf-8-sig",
                ) as f_handle:
                    reader = csv.DictReader(f_handle)
                    if reader.fieldnames != EVENT_LOG_HEADERS:
                        raise ValueError("event log header is invalid")
                    for row in reader:
                        existing_event = str(row.get("event") or "").strip()
                        try:
                            existing_details = json.loads(
                                str(row.get("details") or "")
                            )
                        except (TypeError, ValueError, json.JSONDecodeError):
                            continue
                        if not isinstance(existing_details, dict):
                            continue
                        existing_key = str(existing_details.get("idempotency_key") or "").strip()
                        if existing_event and existing_key:
                            index.setdefault((existing_event, existing_key), existing_details)
            _CSV_INDEXES[path_key] = (signature, index)
            key = (normalized_event, normalized_key)
            if key in index:
                if index[key] != expected_details:
                    raise ValueError("event log idempotency key has different details")
                if durable:
                    # Another projector may have appended this row but still
                    # be syncing it outside admission. A durable caller must
                    # establish its own receipt before returning a replay.
                    with open(log_file_path, "ab") as handle:
                        handle.flush()
                        os.fsync(handle.fileno())
                return False
            try:
                _append_event_log_entry_unlocked(
                    log_file_path,
                    log_entry,
                    durable=durable,
                )
            except BaseException:
                _CSV_INDEXES.pop(path_key, None)
                raise
            stat = os.stat(log_file_path)
            index[key] = expected_details
            _CSV_INDEXES[path_key] = ((stat.st_size, stat.st_mtime_ns, stat.st_ino), index)
            return True
