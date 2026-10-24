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
    fail_initial, on_acquire = [False], [lambda: None]

    @contextmanager
    def acquire(control, operator_sid, *, timeout_ms=5000):
        assert depth[0] == 0, "SYSTEM must hold no lock while acquiring"
        assert control == s.control and operator_sid == s.policy["operator_sid"]
        attempts.append((s.clock[0], timeout_ms))
        # Both entry points read the journal once before their READY loop.
        if (len(attempts) > 1 or fail_initial[0]) and failures:
            error = failures.pop(0)
            if error is not None:
                s.clock[0] += timeout_ms / 1000
                raise error
        depth[0] += 1
        try:
            on_acquire[0]()
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
                           failures=failures, depth=depth, rollback=rollback,
                           fail_initial=fail_initial, on_acquire=on_acquire)


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
@pytest.mark.parametrize("initial", [False, True])
def test_non_exact_busy_is_rejected_immediately(ready_window, result, message, initial):
    w = ready_window
    w.fail_initial[0] = initial
    error = lock_error(result, message)
    w.failures.extend([error, None])
    before = (w.s.control / "transition.json").read_bytes()
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == (1 if initial else 2)
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


def test_exact_busy_from_initial_locked_body_is_not_retried(ready_window, monkeypatch):
    w = ready_window
    error = lock_error()
    original = updates.read_json

    def read(path, **kwargs):
        if path == w.s.control / "transition.json" and w.depth[0] == 1:
            raise error
        return original(path, **kwargs)

    monkeypatch.setattr(updates, "read_json", read)
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == 1
    assert w.depth[0] == 0


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


def test_busy_on_initial_journal_read_after_window_is_not_retried(ready_window, monkeypatch):
    ready_window.s.clock[0] = 120
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


def test_initial_acquisition_busy_retries_inside_durable_window(ready_window):
    w = ready_window
    w.fail_initial[0] = True
    w.failures.extend([lock_error(), lock_error(), None])
    assert w.invoke() == 0
    assert len(w.attempts) == 4  # Two busy, initial acquisition, READY acquisition.
    assert all(timeout == 5000 for _, timeout in w.attempts)
    result = updates.read_json(w.s.control / "transition.json")
    assert result["phase"] == ("ROLLED_BACK" if w.rollback else "CONFIRMED")
    assert result["applied_at"] == stamp(0)
    if w.rollback:
        assert result["rollback_at"] == stamp(0)


@pytest.mark.parametrize("elapsed", [0, 113, 115, 119, 120])
def test_initial_busy_keeps_the_original_durable_deadline(ready_window, elapsed):
    w = ready_window
    w.fail_initial[0] = True
    w.s.clock[0] = elapsed
    error = lock_error()
    w.failures.extend([error] * 25)
    before = (w.s.control / "transition.json").read_bytes()
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == max(1, (120 - elapsed + 4) // 5)
    assert (w.s.control / "transition.json").read_bytes() == before


@pytest.mark.parametrize("defect", ["unreadable", "not_object", "schema", "phase",
                                     "missing_time", "invalid_time", "future_time"])
def test_initial_busy_rejects_unreadable_or_invalid_window(ready_window, monkeypatch, defect):
    w = ready_window
    w.fail_initial[0] = True
    error = lock_error()
    w.failures.extend([error, None])
    original = updates.read_json
    probes = []

    def read(path, **kwargs):
        if path == w.s.control / "transition.json" and w.depth[0] == 0:
            probes.append(True)
            if defect == "unreadable":
                raise OSError("protected journal unavailable")
            if defect == "not_object":
                return []
            state = {**w.s.state}
            if defect == "schema":
                state["schema"] = "unknown"
            elif defect == "phase":
                state["phase"] = "PREPARED"
            else:
                name = "rollback_at" if w.rollback else "applied_at"
                if defect == "missing_time":
                    state.pop(name, None)
                    state.pop("applied_at", None)
                else:
                    state[name] = "invalid" if defect == "invalid_time" else stamp(100)
            return state
        return original(path, **kwargs)

    monkeypatch.setattr(updates, "read_json", read)
    with pytest.raises(RuntimeError) as caught:
        w.invoke()
    assert caught.value is error
    assert len(w.attempts) == 1
    assert len(probes) == 1


def test_initial_acquisition_rereads_phase_after_ownership(ready_window, monkeypatch):
    w = ready_window
    w.fail_initial[0] = True
    w.failures.extend([lock_error(), None])

    def changed():
        assert w.depth[0] == 1
        w.s.write(w.s.control / "transition.json", {**w.s.state, "phase": "DEFERRED"})

    w.on_acquire[0] = changed
    observed = []
    monkeypatch.setattr(updates, "observe_trial_ready", lambda *a, **k: observed.append(True))
    assert w.invoke() == (20 if w.rollback else 0)
    assert len(w.attempts) == 2
    assert not observed
    assert updates.read_json(w.s.control / "transition.json")["phase"] == "DEFERRED"


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
