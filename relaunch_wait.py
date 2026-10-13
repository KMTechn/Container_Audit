"""Wait for the previous process before application admission; stdlib only."""
import ctypes
from ctypes import wintypes
import logging
import os

RELAUNCH_WAIT_S = 30


def _wait_for_previous_process(pid, timeout):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(0x00100000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 87
    try:
        return kernel32.WaitForSingleObject(handle, int(timeout * 1000)) == 0
    finally:
        kernel32.CloseHandle(handle)


def wait_previous_from_argv(argv, timeout=RELAUNCH_WAIT_S):
    if "--after-pid" not in argv:
        return True
    try:
        index = argv.index("--after-pid")
        if argv.count("--after-pid") != 1:
            raise ValueError
        pid = int(argv[index + 1])
        if pid <= 0 or pid == os.getpid():
            raise ValueError
    except (ValueError, IndexError):
        logging.error("SHELL_RELAUNCH_WAIT_INVALID")
        return False
    del argv[index:index + 2]
    try:
        ended = _wait_for_previous_process(pid, timeout)
    except Exception:
        ended = False
    if not ended:
        logging.error("SHELL_RELAUNCH_WAIT_TIMEOUT")
    return bool(ended)
