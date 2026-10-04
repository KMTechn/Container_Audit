from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from writer_session_fence import writer_sink


ERROR_ALREADY_EXISTS = 183
SYNCHRONIZE = 0x00100000


@writer_sink("runtime_shutdown_diagnostic")
def write_shutdown_stall(data_root: str | os.PathLike[str]) -> None:
    """Record a diagnostic only; accepted business work remains in its stores."""
    path = Path(data_root) / "shutdown-stalled.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "pid": os.getpid(), "executable": sys.executable,
        "threads": [t.name[:96] for t in threading.enumerate()
                    if t is not threading.current_thread()][:16],
    }), encoding="utf-8")


@writer_sink("runtime_shutdown_diagnostic")
def clear_shutdown_stall(data_root: str | os.PathLike[str]) -> None:
    (Path(data_root) / "shutdown-stalled.json").unlink(missing_ok=True)


def shutdown_stall_is_live(data_root: str | os.PathLike[str]) -> bool:
    """A stale or unreadable diagnostic never establishes process ownership."""
    try:
        path = Path(data_root) / "shutdown-stalled.json"
        if path.stat().st_size > 4096:
            return False
        with path.open("rb") as stream:
            payload = stream.read(4097)
        if len(payload) > 4096:
            return False
        record = json.loads(payload)
        pid = record["pid"]
        executable = record["executable"]
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF or not isinstance(executable, str):
            return False
        if os.name != "nt":
            return False
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        api.OpenProcess.restype = ctypes.c_void_p
        api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        api.WaitForSingleObject.restype = ctypes.c_ulong
        api.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                                  ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
        api.QueryFullProcessImageNameW.restype = ctypes.c_int
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int
        handle = api.OpenProcess(SYNCHRONIZE | 0x1000, False, pid)
        if not handle:
            return False
        try:
            image = ctypes.create_unicode_buffer(32768)
            size = ctypes.c_ulong(len(image))
            return bool(api.WaitForSingleObject(handle, 0) == 258
                        and api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size))
                        and os.path.normcase(image.value) == os.path.normcase(executable))
        finally:
            api.CloseHandle(handle)
    except (OSError, ValueError, TypeError, KeyError):
        return False


def runtime_mutex_name(data_root: str | os.PathLike[str]) -> str:
    """Return a machine-local mutex name scoped to one canonical data root."""

    canonical_root = os.path.normcase(str(Path(data_root).resolve(strict=False)))
    digest = hashlib.sha256(canonical_root.encode("utf-8")).hexdigest()[:24]
    # Global is machine-wide across interactive/RDP sessions. It remains local
    # to one Windows kernel, so identical paths on different factory PCs never
    # block each other.
    return rf"Global\KMTech.ContainerAudit.{digest}"


@dataclass
class RuntimeInstanceLease:
    """Owned Windows mutex handle kept alive for the complete UI lifetime."""

    mutex_name: str
    _handle: int
    _released: bool = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        if os.name == "nt" and self._handle:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            kernel32.CloseHandle(ctypes.c_void_p(self._handle))
        self._handle = 0

    def __enter__(self) -> "RuntimeInstanceLease":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.release()


def acquire_runtime_instance(
    data_root: str | os.PathLike[str],
) -> RuntimeInstanceLease | None:
    """Acquire the per-data-root Windows runtime lease.

    Named mutexes live in the machine-wide Windows kernel namespace. Consequently,
    two programs on different PCs never block each other, while two processes
    on the same PC and data root cannot concurrently mutate the same tray,
    SQLite, relay, and configuration files.
    """

    mutex_name = runtime_mutex_name(data_root)
    if os.name != "nt":
        # The production scanner runtime is Windows-only. Keeping a no-op lease
        # on other platforms lets parser and contract tests remain portable.
        return RuntimeInstanceLease(mutex_name=mutex_name, _handle=0)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexExW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
    ]
    kernel32.CreateMutexExW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    ctypes.set_last_error(0)
    # Keep the creator's default security descriptor. This lease only needs a
    # live handle; full access would deny an ordinary process opening the same
    # user's existing mutex after an elevated installer started the relay.
    handle = kernel32.CreateMutexExW(None, mutex_name, 0, SYNCHRONIZE)
    if not handle:
        error_code = ctypes.get_last_error()
        raise OSError(error_code, "Container_Audit 실행 잠금을 만들 수 없습니다.")
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    return RuntimeInstanceLease(mutex_name=mutex_name, _handle=int(handle))
