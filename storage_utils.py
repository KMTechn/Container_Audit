from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
import hashlib
import time
import math
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from writer_session_fence import writer_admission, writer_sink


class StorageFailureQuarantine:
    """Retain a failed item's original slot and UNKNOWN attempt in the same root."""

    def __init__(self, root):
        self.root = Path(root)
        self.directory = self.root / "_storage_failures"

    def records(self) -> list[dict]:
        if self.directory.is_symlink():
            raise OSError("storage quarantine must not be a link")
        records = []
        try:
            with os.scandir(self.directory) as entries:
                paths = sorted(Path(entry.path) for entry in entries if entry.name.endswith(".json"))
        except FileNotFoundError:
            return []
        for path in paths:
            if path.is_symlink():
                raise OSError("storage quarantine record must not be a link")
            record = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(record, dict) or record.get("schema") != "ca-storage-failure-v1"
                    or record.get("outcome") != "UNKNOWN"
                    or type(record.get("sequence")) is not int or record["sequence"] < 1
                    or type(record.get("timestamp")) not in (int, float)
                    or not math.isfinite(record["timestamp"])
                    or not isinstance(record.get("snapshot"), dict)
                    or record.get("slot") not in {"tray", "session"}
                    or not isinstance(record.get("item_id"), str)
                    or path.name != record["item_id"] + ".json"):
                raise ValueError("storage quarantine record cannot be verified")
            for field in ("source_file", "replacement_file"):
                name = record.get(field)
                if (not isinstance(name, str) or not name.endswith(".json")
                        or ":" in name or Path(name).name != name):
                    raise ValueError("storage quarantine slot cannot be verified")
            if record["replacement_file"] != f"{Path(record['source_file']).stem}_sf_{record['sequence']}.json":
                raise ValueError("storage quarantine replacement differs")
            records.append(record)
        if len({record["sequence"] for record in records}) != len(records):
            raise ValueError("storage quarantine sequence is ambiguous")
        return sorted(records, key=lambda record: record["sequence"])

    def next_path(self, path: Path) -> Path:
        for record in self.records():
            if path.name == record["source_file"]:
                path = path.with_name(record["replacement_file"])
        return path

    @writer_sink("storage_failure_quarantine")
    def hold(self, path: Path, snapshot: dict, slot: str, reason: str) -> dict:
        path = Path(path)
        if path.is_symlink() or path.parent.resolve() != self.root.resolve():
            raise ValueError("storage failure is outside its data root")
        records = self.records()
        item = (snapshot.get("session_id") if slot == "session" else
                [snapshot.get("master_label_code") or path.name, snapshot.get("start_time")])
        item_id = hashlib.sha256(json.dumps([slot, item or path.name], sort_keys=True).encode()).hexdigest()
        probe = self.root / (".storage-check-" + uuid.uuid4().hex + ".tmp")
        try:
            with probe.open("xb") as stream:
                stream.write(b"storage-check")
                stream.flush()
                os.fsync(stream.fileno())
            if probe.read_bytes() != b"storage-check":
                raise OSError("storage check readback differs")
        finally:
            probe.unlink(missing_ok=True)
        for record in records:
            if record["item_id"] == item_id:
                return record
        now = time.time()
        if sum(record["timestamp"] >= now - 600 for record in records) >= 3:
            raise OSError("four distinct storage failures within ten minutes")
        sequence = max((record["sequence"] for record in records), default=0) + 1
        record = {
            "schema": "ca-storage-failure-v1", "outcome": "UNKNOWN",
            "item_id": item_id, "slot": slot, "sequence": sequence, "timestamp": now,
            "source_file": path.name,
            "replacement_file": f"{path.stem}_sf_{sequence}.json",
            "reason": reason, "snapshot": snapshot,
        }
        if (self.root / record["replacement_file"]).exists():
            raise OSError("storage quarantine replacement is already occupied")
        target = self.directory / (item_id + ".json")
        atomic_write_json(target, record, ensure_ascii=False)
        readback = json.loads(target.read_text(encoding="utf-8"))
        if readback != record:
            raise OSError("storage quarantine readback differs")
        return readback


def close_sqlite_connection(conn: sqlite3.Connection) -> None:
    """Try to truncate WAL without waiting; retain close's rollback semantics."""
    try:
        if conn.in_transaction:
            conn.rollback()
        conn.execute("PRAGMA busy_timeout=0")
        checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint and checkpoint[0]:
            logging.getLogger(__name__).warning("SQLite WAL checkpoint busy during close")
    except sqlite3.Error as exc:
        logging.getLogger(__name__).warning(
            "SQLite WAL checkpoint failed during close: %s", type(exc).__name__,
        )
    finally:
        conn.close()


@dataclass(frozen=True)
class RemoteAttempt:
    """Durable, per-target generation; application and comparison share admission."""

    marker_path: Path
    attempt_id: str

    @classmethod
    @writer_sink("remote_attempt_generation")
    def begin(cls, owner_path, operation: str, *, discriminator: str = ""):
        owner = Path(owner_path).expanduser()
        if owner.is_symlink():
            raise OSError("remote attempt owner must not be a link")
        owner = owner.resolve()
        scope = hashlib.sha256((operation + "\n" + discriminator).encode()).hexdigest()[:16]
        marker = owner.with_name(owner.name + ".attempt-" + scope + ".json")
        if marker.is_symlink():
            raise OSError("remote attempt marker must not be a link")
        attempt = cls(marker, uuid.uuid4().hex)
        atomic_write_json(marker, {"schema": "ca-remote-attempt-v1", "attempt_id": attempt.attempt_id})
        return attempt

    def is_current(self) -> bool:
        try:
            if self.marker_path.is_symlink() or self.marker_path.stat().st_size > 4096:
                return False
            value = json.loads(self.marker_path.read_bytes())
            return value == {"schema": "ca-remote-attempt-v1", "attempt_id": self.attempt_id}
        except (OSError, ValueError, TypeError):
            return False

    @contextmanager
    def apply(self):
        with writer_admission("remote_attempt_generation"):
            yield self.is_current()


@writer_sink("storage_atomic_json")
def atomic_write_json(
    path: str | os.PathLike[str],
    payload: Any,
    *,
    indent: int = 4,
    ensure_ascii: bool = True,
    trailing_newline: bool = False,
) -> None:
    serialized = json.dumps(payload, indent=indent, ensure_ascii=ensure_ascii)
    if trailing_newline:
        serialized += "\n"

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_name(f"{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")

    try:
        with temp_path.open("w", encoding="utf-8") as f:
            f.write(serialized)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
