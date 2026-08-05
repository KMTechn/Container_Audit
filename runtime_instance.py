from __future__ import annotations

import ctypes
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


ERROR_ALREADY_EXISTS = 183


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
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, False, mutex_name)
    if not handle:
        error_code = ctypes.get_last_error()
        raise OSError(error_code, "Container_Audit 실행 잠금을 만들 수 없습니다.")
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    return RuntimeInstanceLease(mutex_name=mutex_name, _handle=int(handle))
