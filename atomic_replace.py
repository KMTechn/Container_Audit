"""Application atomic publication boundary; callers retain their writer admission."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from time import monotonic, sleep

RETRY_SECONDS = 1.5
RETRY_INTERVAL_SECONDS = 0.05


def _replace_once(source, destination, write_through: bool, *, retry_check=None) -> None:
    prepared_source, prepared_destination = os.fspath(source), os.fspath(destination)
    if write_through and os.name == "nt":
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move.restype = wintypes.BOOL
        if retry_check is not None:
            retry_check()
        if not move(prepared_source, prepared_destination, 0x1 | 0x8):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        if retry_check is not None:
            retry_check()
        os.replace(prepared_source, prepared_destination)


def atomic_replace(source, destination, *, write_through: bool = False, deadline: float | None = None) -> None:
    """Replace one prepared file; this function never acquires or bypasses admission."""
    local_deadline = monotonic() + RETRY_SECONDS
    deadline = local_deadline if deadline is None else min(local_deadline, deadline)
    first_error = None
    first_traceback = None
    def check_deadline():
        if monotonic() >= deadline:
            if first_error is not None:
                raise first_error.with_traceback(first_traceback) from None
            raise TimeoutError("ATOMIC_REPLACE_DEADLINE_EXCEEDED")

    while True:
        check_deadline()
        try:
            _replace_once(source, destination, write_through,
                          retry_check=check_deadline)
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
