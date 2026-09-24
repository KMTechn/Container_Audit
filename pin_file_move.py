"""Durable, byte-pinned moves for a consumed local administrator PIN."""

from __future__ import annotations

import hashlib
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from writer_session_fence import writer_sink


class PinnedMoveError(OSError):
    pass


class PinnedTargetChanged(PinnedMoveError):
    pass


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextmanager
def locked_pinned_source(path: Path, expected_sha256: str | None) -> Iterator[None]:
    """Hold a Windows share-read-only handle across a CSV/marker effect."""
    if sys.platform == "win32":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel32.CreateFileW
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p)
        create.restype = ctypes.c_void_p
        handle = create(str(path), 0x80000000, 0x1, None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "cannot lock PIN source")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        except Exception:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            raise
        with os.fdopen(fd, "rb") as stream:
            if (expected_sha256 is not None
                    and hashlib.sha256(stream.read()).hexdigest() != expected_sha256):
                raise PinnedTargetChanged("locked source differs from PIN source")
            yield
    else:
        with path.open("rb") as stream:
            if (expected_sha256 is not None
                    and hashlib.sha256(stream.read()).hexdigest() != expected_sha256):
                raise PinnedTargetChanged("source differs from PIN source")
            yield


@writer_sink("admin_pin_verified_file_move")
def recover_pinned_move(source: Path, target: Path, expected_sha256: str) -> str:
    """Inspect a journaled move; restore changed bytes without replacing an active file."""
    if target.is_file():
        if file_sha256(target) != expected_sha256:
            if source.exists():
                raise PinnedMoveError("changed held target and occupied active slot")
            target.rename(source)
            raise PinnedTargetChanged("moved target differs from PIN source")
        if source.exists():
            raise PinnedMoveError("both active and held originals exist")
        return "MOVED_VERIFIED"
    if source.is_file():
        if file_sha256(source) != expected_sha256:
            raise PinnedTargetChanged("active target differs from PIN source")
        return "SOURCE_UNMOVED"
    raise PinnedMoveError("neither active nor held original exists")


@writer_sink("admin_pin_verified_file_move")
def pinned_move(
    source: Path, target: Path, expected_sha256: str,
    before_move: Callable[[Path, Path, str], None],
) -> Path:
    """Journal before the rename, then verify the bytes in their new location."""
    before_move(source, target, expected_sha256)
    if target.exists():
        if recover_pinned_move(source, target, expected_sha256) == "MOVED_VERIFIED":
            return target
    # rename is atomic on the same volume and refuses an occupied destination on Windows.
    source.rename(target)
    if recover_pinned_move(source, target, expected_sha256) != "MOVED_VERIFIED":
        raise PinnedMoveError("move readback is incomplete")
    return target
