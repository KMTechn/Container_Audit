"""Process-local ownership of threads that must finish durable application work."""
from __future__ import annotations

import threading
from weakref import WeakSet


_workers: WeakSet[threading.Thread] = WeakSet()
_lock = threading.Lock()


def register_data_worker(thread: threading.Thread) -> threading.Thread:
    """Register at creation, before starting; thread names carry no authority."""
    with _lock:
        _workers.add(thread)
    return thread


def data_workers() -> tuple[threading.Thread, ...]:
    """Take a stable snapshot without retaining completed workers forever."""
    with _lock:
        return tuple(_workers)
