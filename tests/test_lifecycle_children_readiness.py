"""The observation bound permits supported cycles and still rejects no readiness."""
import json
from types import SimpleNamespace
import pytest
from tests import lifecycle_children as lifecycle

def observer(monkeypatch, *, ready_at=None, exit_code=None):
    clock = SimpleNamespace(value=0.0)
    def sleep(seconds):
        clock.value += seconds
    monkeypatch.setattr(lifecycle, 'time', SimpleNamespace(monotonic=lambda:clock.value, sleep=sleep))
    status = SimpleNamespace(exists=lambda:True, read_text=lambda **kwargs:json.dumps({'status':'RUNNING' if ready_at is not None and clock.value >= ready_at else 'STOPPED'}))
    monkeypatch.setattr(lifecycle, 'user_relay_status_path', lambda root:status)
    return clock, SimpleNamespace(poll=lambda:exit_code)

def test_readiness_accepts_a_live_supported_45_second_cycle(monkeypatch, tmp_path):
    clock, child = observer(monkeypatch, ready_at=45)
    lifecycle.OwnedRelay(tmp_path).wait_running(tmp_path, child)
    assert 45 <= clock.value < 60

def test_readiness_still_rejects_a_live_child_without_running(monkeypatch, tmp_path):
    clock, child = observer(monkeypatch)
    with pytest.raises(AssertionError, match='did not become RUNNING; exit=None'):
        lifecycle.OwnedRelay(tmp_path).wait_running(tmp_path, child)
    assert 60 <= clock.value < 60.1

def test_readiness_rejects_an_exited_child_with_a_stale_running_file(monkeypatch, tmp_path):
    clock, child = observer(monkeypatch, ready_at=0, exit_code=1)
    with pytest.raises(AssertionError, match='did not become RUNNING; exit=1'):
        lifecycle.OwnedRelay(tmp_path).wait_running(tmp_path, child)
    assert clock.value == 0
