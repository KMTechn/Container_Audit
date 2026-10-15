"""No first publication after an exhausted caller budget, including preparation."""
import os

import pytest

import atomic_replace as atomic


@pytest.mark.parametrize("write_through", (False, True))
@pytest.mark.parametrize("stage", ("already_expired", "path_preparation", "consumer_fsync"))
def test_first_publication_expiry_preserves_destination(tmp_path, monkeypatch, write_through, stage):
    clock = [0.0]
    calls, fsync_calls = [], []
    source, destination = tmp_path / "prepared", tmp_path / "published"
    source.write_bytes(b"prepared bytes")
    destination.write_bytes(b"previous bytes")
    monkeypatch.setattr(atomic, "monotonic", lambda: clock[0])
    monkeypatch.setattr(atomic.os, "replace", lambda *args: calls.append(args))

    class Move:
        def __call__(self, *args):
            calls.append(args)
            return True

    original_dll = atomic.ctypes.WinDLL

    class Kernel:
        MoveFileExW = Move()

        def __init__(self, *args, **kwargs):
            self.native = original_dll(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.native, name)

    monkeypatch.setattr(atomic.ctypes, "WinDLL", Kernel)

    class PreparedPath:
        def __fspath__(self):
            clock[0] = 2.0
            return os.fspath(source)

    if stage == "already_expired":
        clock[0] = 2.0
    with pytest.raises(TimeoutError, match="^ATOMIC_REPLACE_DEADLINE_EXCEEDED$"):
        if stage == "consumer_fsync":
            import user_relay
            original = atomic.atomic_replace
            monkeypatch.setattr(atomic, "atomic_replace", lambda src, dst, **kw: original(
                src, dst, write_through=write_through, **kw))
            def expire_during_fsync(fd):
                fsync_calls.append(fd)
                clock[0] = 2.0
            monkeypatch.setattr(user_relay.os, "fsync", expire_during_fsync)
            user_relay._write_json_atomic(destination, {"status": "READY"}, deadline=1.0)
            assert False, "expired consumer was admitted"
        else:
            atomic.atomic_replace(PreparedPath() if stage == "path_preparation" else source,
                                  destination, write_through=write_through, deadline=1.0)
    assert calls == []
    assert len(fsync_calls) == (1 if stage == "consumer_fsync" else 0)
    assert destination.read_bytes() == b"previous bytes"
    assert source.read_bytes() == b"prepared bytes"
    assert not list(tmp_path.glob(".*.tmp"))


def test_first_write_through_native_preparation_expiry(tmp_path, monkeypatch):
    clock = [0.0]
    calls, preparations = [], []
    source, destination = tmp_path / "prepared", tmp_path / "published"
    source.write_bytes(b"prepared bytes")
    destination.write_bytes(b"previous bytes")

    class Move:
        def __call__(self, *args):
            calls.append(args)
            return True

    class Kernel:
        MoveFileExW = Move()

    def prepare(*args, **kwargs):
        preparations.append(True)
        clock[0] = 2.0
        return Kernel()

    monkeypatch.setattr(atomic, "monotonic", lambda: clock[0])
    monkeypatch.setattr(atomic.ctypes, "WinDLL", prepare)
    with pytest.raises(TimeoutError, match="^ATOMIC_REPLACE_DEADLINE_EXCEEDED$"):
        atomic.atomic_replace(source, destination, write_through=True, deadline=1.0)
    assert preparations == [True]
    assert calls == []
    assert destination.read_bytes() == b"previous bytes"
    assert source.read_bytes() == b"prepared bytes"
