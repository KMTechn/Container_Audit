"""The shipped shell delegates every local write to the existing CA admission."""
from contextlib import contextmanager
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from tests.test_ca_new_screen_entry import entry
from tests.test_ca_screen_bridge import _meta, _Pedal, _Sound
from writer_session_fence import WriterFencedError
import writer_session_fence as fence

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fileio(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "shell"))
    module = importlib.import_module("shell_fileio")
    return module.FileIO(screen.admission_write_guard)


def test_app_installs_the_shell_guard_at_the_existing_entry(entry, monkeypatch, tmp_path):
    received = []

    def run_app(profile, data, *, write_guard, **kwargs):
        received.append(write_guard)
        return 0

    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=run_app))
    assert ca.main([ca.CA_NEW_SCREEN_ARGUMENT]) == 0
    assert received == [screen.admission_write_guard]


@pytest.mark.parametrize("operation", ["make_dirs", "append_bytes", "create_new", "truncate", "replace_atomic", "probe_writable", "remove"])
def test_each_shell_write_enters_and_releases_ca_admission(fileio, monkeypatch, tmp_path, operation):
    calls = []

    @contextmanager
    def admission(source):
        calls.append(("enter", source))
        try:
            yield
        finally:
            calls.append(("exit", source))

    monkeypatch.setattr(screen, "writer_admission", admission)
    target = tmp_path / "receipt"
    if operation == "make_dirs":
        fileio.make_dirs(target, "udf")
        assert target.is_dir()
    elif operation == "append_bytes":
        fileio.append_bytes(target, b"accepted", "events", fsync=True)
        assert target.read_bytes() == b"accepted"
    elif operation == "create_new":
        fileio.create_new(target, b"accepted", "journal")
        assert target.read_bytes() == b"accepted"
    elif operation == "truncate":
        target.write_bytes(b"accepted-tail")
        fileio.truncate(target, 8, "journal")
        assert target.read_bytes() == b"accepted"
    elif operation == "probe_writable":
        fileio.probe_writable(target, "udf")
        assert not target.exists()
    elif operation == "remove":
        target.write_bytes(b"accepted")
        fileio.remove(target, "udf")
        assert not target.exists()
    else:
        fileio.replace_atomic(target, b"accepted", "test_control")
        assert target.read_bytes() == b"accepted"
    if operation == "probe_writable":
        assert calls == [("enter", "screen_shell_fileio"), ("enter", "screen_shell_fileio"),
                         ("exit", "screen_shell_fileio"), ("exit", "screen_shell_fileio")]
    else:
        assert calls == [("enter", "screen_shell_fileio"), ("exit", "screen_shell_fileio")]


def test_refused_shell_writes_preserve_the_file(fileio, monkeypatch, tmp_path):
    @contextmanager
    def refused(source):
        raise WriterFencedError("ACTIVE_WRITER_FENCE", "test admission refused")
        yield

    monkeypatch.setattr(screen, "writer_admission", refused)
    target = tmp_path / "receipt"
    target.write_bytes(b"original")
    with pytest.raises(WriterFencedError):
        fileio.replace_atomic(target, b"replacement", "test_control")
    assert target.read_bytes() == b"original"
    assert not target.with_name(target.name + ".tmp").exists()


def test_raw_shell_io_runs_inside_the_real_ca_admission(fileio, monkeypatch, tmp_path):
    import builtins

    observed = []

    def admitted_open(*args, **kwargs):
        observed.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        assert observed[-1] > 0
        return builtins.open(*args, **kwargs)

    monkeypatch.setattr(importlib.import_module("shell_fileio"), "open", admitted_open, raising=False)
    fileio.append_bytes(tmp_path / "receipt", b"accepted", "journal", fsync=True)
    assert observed == [1]
    assert getattr(fence._WRITER_LOCAL, "depth", 0) == 0


def test_refused_diagnostics_and_receipt_writes_keep_scans_and_state_running(fileio, monkeypatch, tmp_path):
    from bridge import Bridge

    allowed = [True]
    calls = []

    @contextmanager
    def admission(source):
        calls.append(source)
        if not allowed[0]:
            raise WriterFencedError("ACTIVE_WRITER_FENCE", "test admission refused")
        yield

    class Processor:
        def __init__(self):
            self.seen = []

        def state(self):
            return {"seen": len(self.seen)}

        def scan(self, text, info):
            self.seen.append(text)
            return {"accepted": True, "verdict": "ok", "sound": None}

    monkeypatch.setattr(screen, "writer_admission", admission)
    processor = Processor()
    bridge = Bridge(tmp_path, "rw", pedal=_Pedal(), sound=_Sound(),
                    processor_factory=lambda: processor,
                    write_guard=screen.admission_write_guard)
    try:
        allowed[0] = False
        assert bridge.scan("first", _meta(1))["accepted"] is True
        assert bridge.scan("second", _meta(2))["accepted"] is True
        assert bridge.scan("first", _meta(1))["accepted"] is True
        assert processor.seen == ["first", "second"]
        state = bridge.state()
        assert state["seen"] == 2
        assert state["events_dropped"] > 0
        assert calls and set(calls) == {"screen_shell_fileio"}
        assert not (tmp_path / "journal.jsonl").exists()
    finally:
        bridge.close()


def test_shell_copy_matches_the_ready_v3163_manifest():
    ready_path = ROOT / "shell" / "SHELL-READY-v3.16.json"
    assert ready_path.is_file()
    ready = json.loads(ready_path.read_text(encoding="utf-8"))
    assert ready["version"] == "v3.16.3.1"
    for row in ready["files"]:
        relative = Path(row["path"])
        assert relative.parts[0] == "shell-v3.16.3.1"
        path = ROOT / "shell" / Path(*relative.parts[1:])
        assert path.stat().st_size == row["bytes"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    for row in ready["kit_only_files"]:
        assert not (ROOT / row["path"]).exists()
