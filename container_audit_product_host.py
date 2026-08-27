"""Dispatch non-GUI product modes through the packaged Container_Audit host."""

from __future__ import annotations

from contextlib import contextmanager
import io
import sys
from typing import Iterator, Sequence


DIRECT_SYNC_RELAY_MODE = "--container-audit-direct-sync-relay"
PRODUCT_MODES = frozenset({DIRECT_SYNC_RELAY_MODE})


@contextmanager
def _usable_output_streams() -> Iterator[None]:
    """Give the windowed PyInstaller host sinks for console-oriented modes."""

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    if sys.stdout is None:
        sys.stdout = io.StringIO()
    if sys.stderr is None:
        sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr


def dispatch_product_mode(argv: Sequence[str]) -> int | None:
    """Run a packaged implementation without introducing a helper PE."""

    arguments = list(argv)
    if not arguments or arguments[0] not in PRODUCT_MODES:
        return None
    mode = arguments.pop(0)

    with _usable_output_streams():
        if mode == DIRECT_SYNC_RELAY_MODE:
            from tools import direct_sync_relay_runner

            return int(direct_sync_relay_runner.main(arguments))
    raise AssertionError(f"unhandled Container_Audit product mode: {mode}")
