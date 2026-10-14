"""Native boundary for the unchanged data-root lease and window activation."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

ERROR_ALREADY_EXISTS = 183
SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WAIT_TIMEOUT = 258
SW_RESTORE = 9
MB_OK = 0
NOTICE_TIMEOUT_MS = 5000


def runtime_mutex_name(data_root: str | os.PathLike[str]) -> str:
    canonical_root = os.path.normcase(str(Path(data_root).resolve(strict=False)))
    digest = hashlib.sha256(canonical_root.encode("utf-8")).hexdigest()[:24]
    return rf"Global\KMTech.ContainerAudit.{digest}"


@dataclass
class RuntimeInstanceLease:
    mutex_name: str
    _handle: int
    _released: bool = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        if os.name == "nt" and self._handle:
            api = ctypes.WinDLL("kernel32", use_last_error=True)
            api.CloseHandle.argtypes = [wintypes.HANDLE]
            api.CloseHandle.restype = wintypes.BOOL
            api.CloseHandle(self._handle)
        self._handle = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.release()


def acquire_runtime_instance(data_root: str | os.PathLike[str]) -> RuntimeInstanceLease | None:
    name = runtime_mutex_name(data_root)
    if os.name != "nt":
        return RuntimeInstanceLease(name, 0)
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateMutexExW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    api.CreateMutexExW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    handle = api.CreateMutexExW(None, name, 0, SYNCHRONIZE)
    if not handle:
        raise OSError(ctypes.get_last_error(), "runtime instance lease could not be acquired")
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        api.CloseHandle(handle)
        return None
    return RuntimeInstanceLease(name, int(handle))


def process_identity(pid: int) -> dict | None:
    if os.name != "nt" or type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        return None
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    api.QueryFullProcessImageNameW.restype = wintypes.BOOL
    api.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    api.GetProcessTimes.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    handle = api.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        image = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(image))
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if (api.WaitForSingleObject(handle, 0) != WAIT_TIMEOUT
                or not api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size))
                or not api.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user))):
            return None
        return {"exe": image.value, "started_at": (created.dwHighDateTime << 32) | created.dwLowDateTime}
    finally:
        api.CloseHandle(handle)


def visible_top_level_windows(pid: int) -> list[tuple[int, str]]:
    if os.name != "nt":
        return []
    api = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    api.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    api.EnumWindows.restype = wintypes.BOOL
    api.IsWindowVisible.argtypes = [wintypes.HWND]
    api.IsWindowVisible.restype = wintypes.BOOL
    api.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    api.GetWindowThreadProcessId.restype = wintypes.DWORD
    api.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    api.GetClassNameW.restype = ctypes.c_int
    found = []
    def visit(hwnd, _param):
        owner = wintypes.DWORD()
        api.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and api.IsWindowVisible(hwnd):
            name = ctypes.create_unicode_buffer(256)
            api.GetClassNameW(hwnd, name, len(name))
            kind = "web" if name.value.startswith(("WindowsForms10.", "Chrome_WidgetWin")) else "tk" if name.value == "TkTopLevel" else "other"
            found.append((int(hwnd), kind))
        return True
    callback = callback_type(visit)
    if not api.EnumWindows(callback, 0):
        return []
    return found


def activate_window(hwnd: int) -> None:
    if os.name != "nt":
        return
    api = ctypes.WinDLL("user32", use_last_error=True)
    api.IsIconic.argtypes = [wintypes.HWND]
    api.IsIconic.restype = wintypes.BOOL
    api.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    api.ShowWindow.restype = wintypes.BOOL
    api.SetForegroundWindow.argtypes = [wintypes.HWND]
    api.SetForegroundWindow.restype = wintypes.BOOL
    class FLASHWINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND), ("dwFlags", wintypes.DWORD),
                    ("uCount", wintypes.UINT), ("dwTimeout", wintypes.DWORD)]
    api.FlashWindowEx.argtypes = [ctypes.POINTER(FLASHWINFO)]
    api.FlashWindowEx.restype = wintypes.BOOL
    if api.IsIconic(hwnd):
        api.ShowWindow(hwnd, SW_RESTORE)
    if not api.SetForegroundWindow(hwnd):
        info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 2, 3, 0)
        api.FlashWindowEx(ctypes.byref(info))


def timed_notice(text: str, title: str, flags: int = MB_OK, timeout_ms: int = NOTICE_TIMEOUT_MS) -> None:
    if os.name != "nt":
        return
    api = ctypes.WinDLL("user32", use_last_error=True)
    notice = api.MessageBoxTimeoutW
    notice.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT, wintypes.WORD, wintypes.DWORD]
    notice.restype = ctypes.c_int
    notice(None, text, title, flags, 0, timeout_ms)
