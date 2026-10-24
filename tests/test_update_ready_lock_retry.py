"""SYSTEM retries acquisition-only busy within the original READY window."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

import auto_update as updates
from tests.test_auto_update_trial_supervision import NEW, OLD, scene, stamp


BUSY_MESSAGE = "update mutex ownership is busy or abandoned"


def lock_error(result=0x102, message=BUSY_MESSAGE):
    error = RuntimeError(message)
    if result is not None:
        error.wait_result = result
    return error


@pytest.fixture(params=["candidate", "rollback"])
def ready_window(scene, monkeypatch, request):
    s = scene
    rollback = request.param == "rollback"
    sha = OLD if rollback else NEW
    if rollback:
        s.state.update(phase="ROLLBACK_PENDING_READY", rollback_at=stamp(0))
        s.write(s.control / "transition.json", s.state)
        s.write(s.control / "active.json", {"schema": updates.SCHEMA, "sha": sha})
    s.rows.extend([
        dict(pid=101, observable=True, sha=sha, sid=s.policy["operator_sid"],
             role="gui", ordinary_user=True, created_at=stamp(0)),
        dict(pid=102, observable=True, sha=sha, sid=s.policy["operator_sid"],
             role="relay", ordinary_user=True, created_at=stamp(0)),
    ])
    s.write(s.stage / "ready.json", {
        **{check: True for check in updates.READY_CHECKS},
        "pid": 101, "nonce": s.state["nonce"],
        "transition_id": s.state["transition_id"], "sha": sha,
        "ready_at": stamp(0),
    })
    monkeypatch.setattr(updates, "new_apply_claim", lambda: {})
    original_snapshot = updates.process_snapshot
    attempts, depth = [], [0]
    failures = []

    @contextmanager
    def acquire(control, operator_sid, *, timeout_ms=5000):
        assert depth[0] == 0, "SYSTEM must hold no lock while acquiring"
        assert control == s.control and operator_sid == s.policy["operator_sid"]
        attempts.append((s.clock[0], timeout_ms))
        # Both entry points read the journal once before their READY loop.
        if len(attempts) > 1 and failures:
            error = failures.pop(0)
            if error is not None:
                s.clock[0] += timeout_ms / 1000
                raise error
        depth[0] += 1
        try:
            yield
        finally:
            depth[0] -= 1

    def snapshot(control):
        assert depth[0] == 1, "proof observation requires acquired ownership"
        return original_snapshot(control)

    monkeypatch.setattr(updates, "update_lock", acquire)
    monkeypatch.setattr(updates, "process_snapshot", snapshot)
    invoke = (lambda: updates.wait_for_rollback_ready(s.control, s.policy)) if rollback else (
        lambda: updates._apply_prepared_once(s.control))
    return SimpleNamespace(s=s, invoke=invoke, attempts=attempts,
                           failures=failures, depth=depth, rollback=rollback)


def test_acquisition_busy_retries_then_confirms(ready_window):
    w = ready_window
    w.failures.extend([lock_error(), lock_error(), None])
    assert w.invoke() == 0
    assert len(w.attempts) == 4
    assert all(timeout == 5000 for _, timeout in w.attempts)
    result = updates.read_json(w.s.control / "transition.json")
    assert result["phase"] == ("ROLLED_BACK" if w.rollback else "CONFIRMED")
    assert result["applied_at"] == stamp(0)
    if w.rollback:
        assert result["rollback_at"] == stamp(0)
    assert w.depth[0] == 0


@pytest.mark.parametrize("result,message", [
    (0x80, BUSY_MESSAGE), (0xFFFFFFFF, BUSY_MESSAGE),
    (None, BUSY_MESSAGE), (0x102, "different lock failure"),
])
def test_non_exact_busy_is_rejected_immediately(ready_window, result, message):
    w = ready_window
    error = lock_error(result, message)
    w.failures.extend([error, None])
    before = (w.s.control / "transition.json").read_bytes()
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == 2
    assert (w.s.control / "transition.json").read_bytes() == before


def test_exact_busy_from_acquired_body_is_not_retried(ready_window, monkeypatch):
    w = ready_window
    error = lock_error()
    observe = updates.observe_trial_ready

    def fail(*args, **kwargs):
        assert w.depth[0] == 1
        raise error

    monkeypatch.setattr(updates, "observe_trial_ready", fail)
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == 2
    assert w.depth[0] == 0
    monkeypatch.setattr(updates, "observe_trial_ready", observe)


@pytest.mark.parametrize("elapsed", [0, 113, 115, 119])
def test_busy_at_original_deadline_is_rejected_without_a_new_window(ready_window, elapsed):
    w = ready_window
    w.s.clock[0] = elapsed
    error = lock_error()
    w.failures.extend([error] * 25)
    before = (w.s.control / "transition.json").read_bytes()
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == 1 + (120 - elapsed + 4) // 5
    assert w.attempts[-1][0] < 120
    assert w.s.clock[0] >= 120
    assert (w.s.control / "transition.json").read_bytes() == before


def test_busy_on_initial_journal_read_is_not_retried(ready_window, monkeypatch):
    error = lock_error()
    calls = []

    @contextmanager
    def reject(*args, **kwargs):
        calls.append(True)
        raise error
        yield

    monkeypatch.setattr(updates, "update_lock", reject)
    with pytest.raises(RuntimeError) as caught:
        ready_window.invoke()
    assert caught.value is error
    assert len(calls) == 1


def test_busy_after_window_keeps_final_settlement_fail_closed(ready_window):
    w = ready_window
    w.s.clock[0] = 120
    error = lock_error()
    w.failures.append(error)
    before = (w.s.control / "transition.json").read_bytes()
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == 2
    assert w.attempts[-1][0] == 120
    assert (w.s.control / "transition.json").read_bytes() == before
