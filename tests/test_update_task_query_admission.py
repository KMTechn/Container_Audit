"""Existing writer admission must precede both read-only task queries."""
import subprocess

import pytest

import auto_update as update
import writer_session_fence as fence
from tests.test_writer_session_fence import _active_payload, _write_active


@pytest.mark.parametrize("query", ("supported_tasks_absent", "supported_task_present"))
@pytest.mark.parametrize("fenced", (False, True))
@pytest.mark.parametrize("observation", (True, False))
def test_task_query_checks_admission_before_spawn(tmp_path, monkeypatch, query, fenced, observation):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    root = fence.canonical_control_root()
    if fenced:
        _write_active(root, _active_payload())
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()}
    fixed = tmp_path / "managed/current"
    identity = "-".join(map(str, (5, 21, 111, 222, 333, 1001)))
    identity = "S-1-" + identity
    calls = []

    def observe(argv, **kwargs):
        calls.append(argv)
        if query == "supported_task_present":
            text = update.logon_task_xml(app_root=fixed, operator_sid=identity) if observation else "invalid owned XML"
            return subprocess.CompletedProcess(argv, 0, text, "")
        return subprocess.CompletedProcess(argv, 0 if observation else 5, b"", b"")

    monkeypatch.setattr(subprocess, "run", observe)
    function = getattr(update, query)
    args = (fixed, identity) if query == "supported_task_present" else (fixed,)
    if fenced:
        with pytest.raises(fence.WriterFencedError) as error:
            function(*args)
        assert error.value.code == "ACTIVE_WRITER_FENCE"
        assert calls == []
    else:
        assert function(*args) is observation
        assert len(calls) == 1
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()} == before
