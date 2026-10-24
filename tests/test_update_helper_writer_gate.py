"""Read-only Observe must leave admission available to trial writers."""
from contextlib import contextmanager
from types import SimpleNamespace
import subprocess
import threading

import pytest

import auto_update as updates
import writer_session_fence as fence


@pytest.fixture
def helper_gate(monkeypatch, tmp_path):
    gate = threading.Lock()
    entries, calls = [], []

    @contextmanager
    def admission(source, **kwargs):
        if not gate.acquire(blocking=False):
            raise RuntimeError("writer admission is already held")
        entries.append(source)
        try:
            yield
        finally:
            gate.release()

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs, gate.locked()))
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(fence, "writer_admission", admission)
    monkeypatch.setattr(updates, "system_executable", lambda name: tmp_path / "powershell.exe")
    monkeypatch.setattr(subprocess, "run", run)
    return SimpleNamespace(control=tmp_path / "update-control", gate=gate,
                           entries=entries, calls=calls)


@pytest.mark.parametrize("mode", ["Authority", "Apply", "Verify"])
def test_mutating_and_verifying_helpers_keep_writer_admission(helper_gate, mode):
    h = helper_gate
    assert updates.fixed_helper(h.control, mode) == "[]"
    assert h.entries == ["auto_update_control"]
    assert len(h.calls) == 1 and h.calls[0][2] is True
    assert h.calls[0][0][-2:] == ["-Mode", mode]
    assert not h.gate.locked()


def test_process_observe_does_not_acquire_writer_admission(helper_gate):
    h = helper_gate
    assert updates.process_snapshot(h.control) == []
    assert h.entries == []
    assert len(h.calls) == 1 and h.calls[0][2] is False
    assert h.calls[0][0][-2:] == ["-Mode", "Observe"]


@pytest.mark.parametrize("consumer", ["current_user_onboarding", "persistent_relay_status"])
def test_gui_and_relay_can_admit_while_observe_is_running(helper_gate, monkeypatch, consumer):
    h = helper_gate
    observing, release = threading.Event(), threading.Event()
    errors = []

    def run(arguments, **kwargs):
        observing.set()
        assert release.wait(10), "test did not release its pending Observe"
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    def observe():
        try:
            assert updates.process_snapshot(h.control) == []
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(subprocess, "run", run)
    worker = threading.Thread(target=observe)
    worker.start()
    try:
        assert observing.wait(10), "Observe child boundary was not reached"
        with fence.writer_admission(consumer):
            assert h.gate.locked()
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and not errors
    assert h.entries == [consumer]
