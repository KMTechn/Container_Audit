"""Bounded diagnostics must neither grant ownership nor block an owned start."""
from contextlib import contextmanager
import json
import os
import subprocess
import sys

import pytest

import runtime_instance as runtime


def test_shutdown_notice_recognizes_live_process_and_clears_stale_marker(tmp_path):
    runtime.write_shutdown_stall(tmp_path)
    assert runtime.shutdown_stall_is_live(tmp_path)
    record = json.loads((tmp_path / "shutdown-stalled.json").read_text(encoding="utf-8"))
    assert record["pid"] == os.getpid() and len(record["threads"]) <= 16
    runtime.clear_shutdown_stall(tmp_path)
    assert not runtime.shutdown_stall_is_live(tmp_path)
    runtime.clear_shutdown_stall(tmp_path)


@pytest.mark.parametrize("change", [
    {"pid": True}, {"pid": 0}, {"pid": -1}, {"pid": 0x100000000},
    {"pid": "invalid"}, {"executable": None}, {"executable": "different.exe"},
])
def test_invalid_shutdown_marker_does_not_change_duplicate_launch_notice(tmp_path, change):
    record = {"pid": os.getpid(), "executable": sys.executable}
    record.update(change)
    (tmp_path / "shutdown-stalled.json").write_text(json.dumps(record), encoding="utf-8")
    assert not runtime.shutdown_stall_is_live(tmp_path)


@pytest.mark.parametrize("payload", ["{", "[]", "{}", " " * 4097])
def test_corrupt_or_oversized_shutdown_marker_is_ignored(tmp_path, payload):
    (tmp_path / "shutdown-stalled.json").write_text(payload, encoding="utf-8")
    assert not runtime.shutdown_stall_is_live(tmp_path)


def test_dead_process_shutdown_marker_is_ignored(tmp_path):
    child = subprocess.Popen([sys.executable, "-B", "-c", "pass"],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    child.wait(timeout=10)
    (tmp_path / "shutdown-stalled.json").write_text(json.dumps({
        "pid": child.pid, "executable": sys.executable,
    }), encoding="utf-8")
    assert not runtime.shutdown_stall_is_live(tmp_path)


def test_shutdown_marker_mutations_require_ordinary_writer_admission(monkeypatch, tmp_path):
    import writer_session_fence as fence
    @contextmanager
    def denied(source):
        assert source == "runtime_shutdown_diagnostic"
        raise fence.WriterFencedError("SYNTHETIC_FENCE", "synthetic denial")
        yield
    monkeypatch.setattr(fence, "writer_admission", denied)
    path = tmp_path / "shutdown-stalled.json"
    with pytest.raises(fence.WriterFencedError):
        runtime.write_shutdown_stall(tmp_path)
    assert not path.exists()
    path.write_text("preserve", encoding="utf-8")
    with pytest.raises(fence.WriterFencedError):
        runtime.clear_shutdown_stall(tmp_path)
    assert path.read_text(encoding="utf-8") == "preserve"
