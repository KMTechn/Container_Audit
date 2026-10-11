from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from writer_session_fence import writer_admission, writer_sink


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
