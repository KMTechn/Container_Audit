"""Application atomic publication boundary; callers retain their writer admission."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from time import monotonic, sleep

RETRY_SECONDS = 1.5
RETRY_INTERVAL_SECONDS = 0.05


def _replace_once(source, destination, write_through: bool) -> None:
    if write_through and os.name == "nt":
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move.restype = wintypes.BOOL
        if not move(os.fspath(source), os.fspath(destination), 0x1 | 0x8):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.replace(source, destination)


def atomic_replace(source, destination, *, write_through: bool = False) -> None:
    """Replace one prepared file; this function never acquires or bypasses admission."""
    deadline = monotonic() + RETRY_SECONDS
    first_error = None
    first_traceback = None
    while True:
        try:
            _replace_once(source, destination, write_through)
            return
        except OSError as error:
            if getattr(error, "winerror", None) not in (5, 32):
                raise
            if first_error is None:
                first_error, first_traceback = error, error.__traceback__
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise first_error.with_traceback(first_traceback) from None
            sleep(min(RETRY_INTERVAL_SECONDS, remaining))
