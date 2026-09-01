"""Restart-durable FIFO for scans captured during a PHS2 preflight lookup."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import threading
from typing import Any, Callable, Mapping

from storage_utils import atomic_write_json
from writer_session_fence import writer_sink


HOLD_SCHEMA_VERSION = "container-audit-preflight-scan-hold-v1"
HOLD_LOOKUP = "LOOKUP"
HOLD_LOOKUP_FAILED = "LOOKUP_FAILED"
HOLD_DRAINING = "DRAINING"
_HOLD_STATES = {HOLD_LOOKUP, HOLD_LOOKUP_FAILED, HOLD_DRAINING}


class PreflightHoldError(RuntimeError):
    pass


class PreflightHoldFull(PreflightHoldError):
    pass


class PreflightHoldConflict(PreflightHoldError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class HeldScan:
    scan_id: str
    sequence: int
    raw_barcode: str
    admitted_at: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "HeldScan":
        scan_id = str(payload.get("scan_id") or "").strip()
        raw = str(payload.get("raw_barcode") or "")
        admitted_at = str(payload.get("admitted_at") or "").strip()
        sequence = payload.get("sequence")
        if not scan_id or not raw or not admitted_at or not isinstance(sequence, int) or sequence < 1:
            raise PreflightHoldError("preflight hold item is invalid")
        return cls(scan_id, sequence, raw, admitted_at)

    def to_payload(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "sequence": self.sequence,
            "raw_barcode": self.raw_barcode,
            "admitted_at": self.admitted_at,
        }


@dataclass(frozen=True)
class PreflightHoldSnapshot:
    preflight_id: str
    scan_epoch: int
    worker: str
    master_raw: str
    created_at: str
    updated_at: str
    state: str
    items: tuple[HeldScan, ...]
    error_code: str = ""

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PreflightHoldSnapshot":
        if str(payload.get("schema_version") or "") != HOLD_SCHEMA_VERSION:
            raise PreflightHoldError("preflight hold schema is invalid")
        preflight_id = str(payload.get("preflight_id") or "").strip()
        worker = str(payload.get("worker") or "").strip()
        master_raw = str(payload.get("master_raw") or "")
        created_at = str(payload.get("created_at") or "").strip()
        updated_at = str(payload.get("updated_at") or "").strip()
        state = str(payload.get("state") or "").strip()
        scan_epoch = payload.get("scan_epoch")
        raw_items = payload.get("items")
        if (
            not preflight_id
            or not worker
            or not master_raw
            or not created_at
            or not updated_at
            or state not in _HOLD_STATES
            or not isinstance(scan_epoch, int)
            or scan_epoch < 0
            or not isinstance(raw_items, list)
        ):
            raise PreflightHoldError("preflight hold snapshot is invalid")
        items = tuple(HeldScan.from_payload(item) for item in raw_items if isinstance(item, Mapping))
        if len(items) != len(raw_items):
            raise PreflightHoldError("preflight hold items are invalid")
        sequences = [item.sequence for item in items]
        if sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
            raise PreflightHoldError("preflight hold FIFO sequence is invalid")
        return cls(
            preflight_id,
            scan_epoch,
            worker,
            master_raw,
            created_at,
            updated_at,
            state,
            items,
            str(payload.get("error_code") or "").strip(),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": HOLD_SCHEMA_VERSION,
            "preflight_id": self.preflight_id,
            "scan_epoch": self.scan_epoch,
            "worker": self.worker,
            "master_raw": self.master_raw,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "state": self.state,
            "items": [item.to_payload() for item in self.items],
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class QuarantinedPreflightHold:
    path: Path
    snapshot: PreflightHoldSnapshot
    snapshot_hash: str


class PreflightScanHoldStore:
    def __init__(self, path: str | os.PathLike[str], *, capacity: int) -> None:
        self.path = Path(path)
        self.capacity = max(1, int(capacity))
        self._lock = threading.RLock()

    def exists(self) -> bool:
        return self.path.is_file()

    @staticmethod
    def load_path(path: str | os.PathLike[str]) -> PreflightHoldSnapshot:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PreflightHoldError("preflight hold cannot be read") from exc
        if not isinstance(payload, dict):
            raise PreflightHoldError("preflight hold must be an object")
        return PreflightHoldSnapshot.from_payload(payload)

    def load(self) -> PreflightHoldSnapshot:
        with self._lock:
            return self.load_path(self.path)

    @staticmethod
    def snapshot_hash(snapshot: PreflightHoldSnapshot) -> str:
        if not isinstance(snapshot, PreflightHoldSnapshot):
            raise TypeError("preflight hold snapshot is required")
        return _hash(snapshot.to_payload())

    @classmethod
    def list_quarantined(
        cls,
        directory: str | os.PathLike[str],
    ) -> tuple[QuarantinedPreflightHold, ...]:
        root = Path(directory)
        if not root.is_dir():
            return ()
        quarantined: list[QuarantinedPreflightHold] = []
        for path in sorted(root.glob("preflight_hold_*.json")):
            try:
                snapshot = cls.load_path(path)
            except PreflightHoldError:
                continue
            quarantined.append(
                QuarantinedPreflightHold(
                    path=path,
                    snapshot=snapshot,
                    snapshot_hash=cls.snapshot_hash(snapshot),
                )
            )
        return tuple(quarantined)

    @writer_sink("preflight_scan_hold")
    def _write(self, snapshot: PreflightHoldSnapshot) -> PreflightHoldSnapshot:
        payload = snapshot.to_payload()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, payload, indent=2, ensure_ascii=False)
        loaded = self.load()
        if _hash(loaded.to_payload()) != _hash(payload):
            raise PreflightHoldError("preflight hold readback mismatch")
        return loaded

    def start(
        self,
        *,
        worker: str,
        master_raw: str,
        scan_epoch: int,
    ) -> PreflightHoldSnapshot:
        normalized_worker = str(worker or "").strip()
        master = str(master_raw or "")
        if not normalized_worker or not master:
            raise ValueError("preflight worker and master are required")
        with self._lock:
            if self.exists():
                existing = self.load()
                if existing.worker == normalized_worker and existing.master_raw == master:
                    return existing
                raise PreflightHoldConflict("another preflight hold is already active")
            created_at = _utc_now()
            identity = {
                "worker": normalized_worker,
                "master_raw": master,
                "scan_epoch": int(scan_epoch),
                "created_at": created_at,
            }
            snapshot = PreflightHoldSnapshot(
                preflight_id="preflight-" + _hash(identity)[:32],
                scan_epoch=max(0, int(scan_epoch)),
                worker=normalized_worker,
                master_raw=master,
                created_at=created_at,
                updated_at=created_at,
                state=HOLD_LOOKUP,
                items=(),
            )
            return self._write(snapshot)

    def append(self, raw_barcode: str) -> HeldScan:
        raw = str(raw_barcode or "")
        if not raw:
            raise ValueError("held barcode is required")
        with self._lock:
            snapshot = self.load()
            if snapshot.state != HOLD_LOOKUP:
                raise PreflightHoldConflict("preflight hold is not accepting scans")
            if len(snapshot.items) >= self.capacity:
                raise PreflightHoldFull("preflight hold is full")
            sequence = snapshot.items[-1].sequence + 1 if snapshot.items else 1
            admitted_at = _utc_now()
            item = HeldScan(
                scan_id="held-scan-"
                + hashlib.sha256(
                    f"{snapshot.preflight_id}:{sequence}".encode("utf-8")
                ).hexdigest()[:32],
                sequence=sequence,
                raw_barcode=raw,
                admitted_at=admitted_at,
            )
            self._write(
                PreflightHoldSnapshot(
                    **{
                        **snapshot.__dict__,
                        "updated_at": admitted_at,
                        "items": (*snapshot.items, item),
                    }
                )
            )
            return item

    def mark_failed(self, *, error_code: str) -> PreflightHoldSnapshot:
        with self._lock:
            snapshot = self.load()
            return self._write(
                PreflightHoldSnapshot(
                    **{
                        **snapshot.__dict__,
                        "updated_at": _utc_now(),
                        "state": HOLD_LOOKUP_FAILED,
                        "error_code": str(error_code or "PHS2_PREFLIGHT_FAILED").strip(),
                    }
                )
            )

    def resume(self, *, master_raw: str, worker: str) -> PreflightHoldSnapshot:
        with self._lock:
            snapshot = self.load()
            if snapshot.master_raw != str(master_raw or "") or snapshot.worker != str(worker or "").strip():
                raise PreflightHoldConflict("preflight retry context does not match the hold")
            return self._write(
                PreflightHoldSnapshot(
                    **{
                        **snapshot.__dict__,
                        "updated_at": _utc_now(),
                        "state": HOLD_LOOKUP,
                        "error_code": "",
                    }
                )
            )

    def mark_draining(self) -> PreflightHoldSnapshot | None:
        with self._lock:
            snapshot = self.load()
            if snapshot.state != HOLD_LOOKUP:
                raise PreflightHoldConflict("preflight hold is not ready to drain")
            if not snapshot.items:
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
                return None
            return self._write(
                PreflightHoldSnapshot(
                    **{
                        **snapshot.__dict__,
                        "updated_at": _utc_now(),
                        "state": HOLD_DRAINING,
                    }
                )
            )

    @writer_sink("preflight_scan_hold")
    def ack_head(self, scan_id: str) -> PreflightHoldSnapshot | None:
        with self._lock:
            snapshot = self.load()
            if snapshot.state != HOLD_DRAINING or not snapshot.items:
                raise PreflightHoldConflict("preflight hold has no drainable head")
            if snapshot.items[0].scan_id != str(scan_id or ""):
                raise PreflightHoldConflict("preflight hold head identity mismatch")
            remaining = snapshot.items[1:]
            if not remaining:
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
                return None
            return self._write(
                PreflightHoldSnapshot(
                    **{
                        **snapshot.__dict__,
                        "updated_at": _utc_now(),
                        "items": remaining,
                    }
                )
            )

    @writer_sink("preflight_scan_hold_quarantine")
    def quarantine(
        self,
        target_directory: str | os.PathLike[str],
        *,
        reason: str,
    ) -> QuarantinedPreflightHold:
        with self._lock:
            snapshot = self.load()
            target_root = Path(target_directory)
            target_root.mkdir(parents=True, exist_ok=True)
            snapshot_hash = self.snapshot_hash(snapshot)
            timestamp = re.sub(r"[^0-9A-Za-z]", "", snapshot.updated_at)[:15]
            suffix = snapshot_hash[:16]
            target = target_root / (
                f"preflight_hold_{snapshot.preflight_id}_{timestamp}_{suffix}.json"
            )
            if target.exists():
                existing = self.load_path(target)
                if self.snapshot_hash(existing) != snapshot_hash:
                    raise PreflightHoldConflict("preflight quarantine identity collision")
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
            else:
                os.replace(self.path, target)
            readback = self.load_path(target)
            if self.snapshot_hash(readback) != snapshot_hash:
                raise PreflightHoldError("preflight quarantine readback mismatch")
            return QuarantinedPreflightHold(target, readback, snapshot_hash)

    @writer_sink("preflight_scan_hold_quarantine_restore")
    def restore_quarantined(
        self,
        quarantined_path: str | os.PathLike[str],
    ) -> PreflightHoldSnapshot:
        with self._lock:
            source = Path(quarantined_path)
            snapshot = self.load_path(source)
            snapshot_hash = self.snapshot_hash(snapshot)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.exists():
                existing = self.load()
                if self.snapshot_hash(existing) != snapshot_hash:
                    raise PreflightHoldConflict(
                        "another preflight hold is already active"
                    )
                try:
                    source.unlink()
                except FileNotFoundError:
                    pass
            else:
                os.replace(source, self.path)
            readback = self.load()
            if self.snapshot_hash(readback) != snapshot_hash:
                raise PreflightHoldError("restored preflight hold readback mismatch")
            return readback


@dataclass(frozen=True)
class HoldWriteAdmission:
    accepted: bool
    reason: str = ""


@dataclass(frozen=True)
class _WriteTask:
    work: Callable[[], Any]
    finish: Callable[[Any], None]
    fail: Callable[[BaseException], None]


class PreflightScanHoldWriter:
    """Short serial durable writer whose callbacks are applied by a Tk pump."""

    def __init__(self, root: Any, *, queue_capacity: int, poll_ms: int = 10) -> None:
        self.root = root
        self.owner_thread_id = threading.get_ident()
        self.poll_ms = max(1, int(poll_ms))
        self.tasks: queue.Queue[Any] = queue.Queue(maxsize=max(1, int(queue_capacity)))
        self.results: queue.Queue[tuple[_WriteTask, Any, BaseException | None]] = queue.Queue()
        self._closing = False
        self._closed = False
        self._pump_job: Any = None
        self._drain_callbacks: list[Callable[[], None]] = []
        self._stop = object()
        self.thread = threading.Thread(
            target=self._worker,
            name="container-audit-preflight-hold-writer",
            # Normal shutdown drains this independent durable sink explicitly.
            # If Tk is destroyed abnormally, it must not keep a headless
            # process alive after its result pump is gone.
            daemon=True,
        )
        self.thread.start()
        self._schedule_pump()

    def _assert_owner(self) -> None:
        if threading.get_ident() != self.owner_thread_id:
            raise RuntimeError("preflight hold writer control is Tk-owned")

    def submit(
        self,
        work: Callable[[], Any],
        finish: Callable[[Any], None],
        fail: Callable[[BaseException], None],
    ) -> HoldWriteAdmission:
        self._assert_owner()
        if self._closing or self._closed:
            return HoldWriteAdmission(False, "closing")
        try:
            self.tasks.put_nowait(_WriteTask(work, finish, fail))
        except queue.Full:
            return HoldWriteAdmission(False, "full")
        return HoldWriteAdmission(True)

    def _worker(self) -> None:
        while True:
            task = self.tasks.get()
            try:
                if task is self._stop:
                    return
                assert isinstance(task, _WriteTask)
                try:
                    self.results.put((task, task.work(), None))
                except BaseException as exc:
                    self.results.put((task, None, exc))
            finally:
                self.tasks.task_done()

    def _schedule_pump(self) -> None:
        self._assert_owner()
        if self._closed or self._pump_job is not None:
            return
        self._pump_job = self.root.after(self.poll_ms, self._pump)

    def _pump(self) -> None:
        self._assert_owner()
        self._pump_job = None
        for _index in range(16):
            try:
                task, value, error = self.results.get_nowait()
            except queue.Empty:
                break
            try:
                if error is None:
                    task.finish(value)
                else:
                    task.fail(error)
            finally:
                self.results.task_done()
        if self._closing and not self.tasks.unfinished_tasks and self.results.empty():
            self._complete_close()
            return
        if not self._closed:
            self._schedule_pump()

    def close_idle(self) -> bool:
        self._assert_owner()
        if self._closed:
            return True
        if self.tasks.unfinished_tasks or not self.results.empty():
            self._closing = True
            return False
        self._closing = True
        return self._complete_close()

    def drain_then(self, callback: Callable[[], None]) -> None:
        self._assert_owner()
        if not callable(callback):
            raise TypeError("preflight hold drain callback must be callable")
        if self._closed:
            callback()
            return
        self._drain_callbacks.append(callback)
        self._closing = True
        if not self.tasks.unfinished_tasks and self.results.empty():
            self._complete_close()

    def _complete_close(self) -> bool:
        if self._closed:
            return True
        self.tasks.put_nowait(self._stop)
        self.thread.join(timeout=2.0)
        if self.thread.is_alive():
            return False
        self._closed = True
        if self._pump_job is not None:
            try:
                self.root.after_cancel(self._pump_job)
            except Exception:
                pass
            self._pump_job = None
        callbacks = list(self._drain_callbacks)
        self._drain_callbacks.clear()
        for callback in callbacks:
            callback()
        return True


__all__ = [
    "HOLD_DRAINING",
    "HOLD_LOOKUP",
    "HOLD_LOOKUP_FAILED",
    "HeldScan",
    "HoldWriteAdmission",
    "PreflightHoldConflict",
    "PreflightHoldError",
    "PreflightHoldFull",
    "PreflightHoldSnapshot",
    "PreflightScanHoldStore",
    "PreflightScanHoldWriter",
    "QuarantinedPreflightHold",
]
