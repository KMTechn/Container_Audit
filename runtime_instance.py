from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

from writer_session_fence import writer_sink
from storage_utils import atomic_write_json
from storage_policy import ensure_user_runtime_directory
from runtime_instance_win32 import (
    acquire_runtime_instance, runtime_mutex_name, RuntimeInstanceLease,
    ERROR_ALREADY_EXISTS, SYNCHRONIZE, process_identity,
)
import tempfile


ERROR_ALREADY_EXISTS = 183
SYNCHRONIZE = 0x00100000


@writer_sink("runtime_shutdown_diagnostic")
def write_shutdown_stall(data_root: str | os.PathLike[str]) -> None:
    """Record a diagnostic only; accepted business work remains in its stores."""
    path = Path(data_root) / "shutdown-stalled.json"
    atomic_write_json(path, {
        "pid": os.getpid(), "executable": sys.executable,
        "threads": [t.name[:96] for t in threading.enumerate()
                    if t is not threading.current_thread()][:16],
    })


@writer_sink("runtime_shutdown_diagnostic")
def clear_shutdown_stall(data_root: str | os.PathLike[str]) -> None:
    (Path(data_root) / "shutdown-stalled.json").unlink(missing_ok=True)


def read_shutdown_stall(data_root: str | os.PathLike[str]) -> dict | None:
    """Read bounded recovery evidence without establishing process ownership."""
    try:
        path = Path(data_root) / "shutdown-stalled.json"
        if path.stat().st_size > 4096:
            return None
        with path.open("rb") as stream:
            payload = stream.read(4097)
        if len(payload) > 4096:
            return None
        record = json.loads(payload)
        pid = record["pid"]
        executable = record["executable"]
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF or not isinstance(executable, str):
            return None
        return record
    except (OSError, ValueError, TypeError, KeyError):
        return None


def shutdown_stall_is_live(data_root: str | os.PathLike[str]) -> bool:
    """A stale or unreadable diagnostic never establishes process ownership."""
    record = read_shutdown_stall(data_root)
    if record is None:
        return False
    try:
        identity = process_identity(record["pid"])
        return bool(identity is not None and os.path.normcase(identity["exe"]) == os.path.normcase(record["executable"]))
    except (OSError, ValueError, TypeError, KeyError):
        return False


@writer_sink("runtime_instance_marker", report_only=True)
def _write_entry_marker(entry) -> None:
    """Only this owner mutex's bounded, per-user PID/state report."""
    from atomic_replace import atomic_replace
    from runtime_entry import instance_marker_path
    if entry.lease._released or entry.lease.mutex_name != runtime_mutex_name(entry.root):
        raise ValueError("instance marker requires the live owner lease")
    path = instance_marker_path(entry.root)
    record = {"pid": os.getpid(), "exe": entry.identity["exe"],
              "started_at": entry.identity["started_at"], "state": entry.state}
    payload = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > 4096:
        raise ValueError("instance marker exceeds its byte limit")
    ensure_user_runtime_directory(path.parent)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        atomic_replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@writer_sink("runtime_instance_marker", report_only=True)
def _clear_entry_marker(entry) -> None:
    from runtime_entry import instance_marker_path, read_instance_marker
    if entry.lease._released or entry.lease.mutex_name != runtime_mutex_name(entry.root):
        return
    record = read_instance_marker(entry.root)
    if (record is not None and entry.identity is not None and record["pid"] == os.getpid()
            and record["started_at"] == entry.identity["started_at"]
            and os.path.normcase(record["exe"]) == os.path.normcase(entry.identity["exe"])):
        instance_marker_path(entry.root).unlink(missing_ok=True)
