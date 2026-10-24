"""Slow bootstrap reads release ownership and discard changed observations."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import auto_update as updates


@pytest.fixture
def poll_scene(monkeypatch, tmp_path):
    control, stage = tmp_path / "control", tmp_path / "stage"
    policy = {"operator_sid": "test-operator", "staging_root": str(stage)}
    epoch = datetime(2026, 10, 24, tzinfo=timezone.utc)
    clock, held, intervals, order = [0.0], [], [], []
    identities = {101: {"status": "LIVE", "creation_identity": "first-lifetime"}}
    state = {"schema": updates.SCHEMA, "phase": "APPLIED_PENDING_READY",
             "transition_id": "f" * 32, "nonce": "1" * 32,
             "applied_at": epoch.isoformat(), "trial_pid": 101,
             "trial_started_at": epoch.isoformat()}
    records = {control / "policy.json": policy,
               control / "transition.json": state,
               control / "active.json": {"schema": updates.SCHEMA, "sha": "b" * 40},
               control / "apply-claim.json": {"pid": 101, "status": "RUNNING"},
               stage / "trial.json": {"pid": 101, "nonce": state["nonce"],
                                       "transition_id": state["transition_id"]}}

    @contextmanager
    def lock(kind):
        if kind == "update":
            assert held == []
        else:
            assert held == ["update"]
        held.append(kind)
        order.append(("enter", kind))
        entered = clock[0]
        try:
            yield
        finally:
            assert held.pop() == kind
            intervals.append((kind, clock[0] - entered))
            order.append(("leave", kind))

    @contextmanager
    def startup(*args, **kwargs):
        with lock("update"):
            yield True

    def identity(pid):
        return deepcopy(identities.get(pid, {"status": "ABSENT"}))

    def sleep(seconds):
        assert not held
        clock[0] += seconds

    monkeypatch.setattr(updates, "optional_record", lambda path: deepcopy(records.get(Path(path))))
    monkeypatch.setattr(updates, "read_json", lambda path: deepcopy(records[Path(path)]))
    monkeypatch.setattr(updates, "startup_update_lock", startup)
    monkeypatch.setattr(updates, "update_lock", lambda *a, **k: lock("trial" if k.get("trial") else "update"))
    monkeypatch.setattr(updates, "native_process_identity", identity)
    monkeypatch.setattr(updates.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(updates.time, "sleep", sleep)
    monkeypatch.setattr(updates, "now_utc", lambda: (epoch + timedelta(seconds=clock[0])).isoformat())
    return SimpleNamespace(**locals())


@pytest.mark.parametrize("seconds", [15, 30])
@pytest.mark.parametrize("trial", [False, True])
def test_slow_read_releases_update_and_trial_and_admits_system(poll_scene, seconds, trial):
    s = poll_scene

    def observe():
        assert s.held == []
        with s.lock("update"):  # SYSTEM can own the same mutex during Observe.
            pass
        s.clock[0] += seconds
        return []

    with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
        if trial:
            with poll.trial():
                assert poll.read(observe) == []
                assert s.held == ["update", "trial"]
        else:
            assert poll.read(observe) == []
            assert s.held == ["update"]
    assert s.held == []
    assert max(duration for _, duration in s.intervals) <= 1
    assert poll.deadline == 120


@pytest.mark.parametrize("record,key,value", [
    ("transition", "transition_id", "changed"),
    ("transition", "nonce", "changed"),
    ("transition", "phase", "ROLLBACK_PENDING_READY"),
    ("transition", "trial_pid", 202),
    ("transition", "trial_started_at", "changed"),
    ("active", "sha", "changed"),
    ("apply-claim", "pid", 202),
    ("trial", "nonce", "changed"),
    ("trial", "pid", 202),
    ("ready", "pid", 202),
    ("trial-failure", "nonce", "changed"),
    ("prepared", "sha", "changed"),
])
def test_changed_protected_context_discards_read(poll_scene, record, key, value):
    s = poll_scene
    parent = s.control if record in {"transition", "active", "apply-claim"} else s.stage
    path = parent / (record + ".json")

    def observe():
        assert s.held == []
        s.records.setdefault(path, {})[key] = value
        return []

    with pytest.raises(updates._BootstrapObservationChanged):
        with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
            with poll.trial():
                poll.read(observe)
    assert s.held == []


@pytest.mark.parametrize("replacement", [
    {"status": "LIVE", "creation_identity": "reused-pid"},
    {"status": "ABSENT"}, {"status": "UNKNOWN"},
])
def test_changed_native_lifetime_discards_read(poll_scene, replacement):
    s = poll_scene

    def observe():
        s.identities[101] = replacement
        return []

    with pytest.raises(updates._BootstrapObservationChanged):
        with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
            poll.read(observe)
    assert s.held == []


def test_stable_absent_apply_owner_keeps_existing_recovery_path(poll_scene):
    s = poll_scene
    s.identities[101] = {"status": "ABSENT"}
    with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
        assert poll.read(lambda: "ALLOW") == "ALLOW"


def test_existing_unknown_system_apply_owner_does_not_add_query_permission(poll_scene, monkeypatch):
    s = poll_scene
    s.records[s.control / "apply-claim.json"] = {"pid": 202, "creation_identity": "protected-system-birth", "status": "RUNNING"}
    s.identities[202] = {"status": "UNKNOWN"}
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "UNKNOWN")
    with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
        assert poll.read(lambda: "ALLOW") == "ALLOW"


def test_changed_apply_owner_status_discards_read(poll_scene, monkeypatch):
    s = poll_scene
    status = ["LIVE"]
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: status[0])

    def observe():
        status[0] = "UNKNOWN"
        return []

    with pytest.raises(updates._BootstrapObservationChanged):
        with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
            poll.read(observe)


@pytest.mark.parametrize("change", ["none", "birth", "reused", "unknown"])
def test_observed_row_requires_matching_native_birth_and_reacquired_lifetime(poll_scene, monkeypatch, change):
    s = poll_scene
    ticks = (s.epoch - datetime(1601, 1, 1, tzinfo=timezone.utc)).days * 86400 * 10**7
    s.identities[202] = {"status": "LIVE", "creation_identity": str(ticks)}
    row = {"pid": 202, "observable": True, "role": "relay", "created_at": s.epoch.isoformat()}
    if change == "birth":
        row["created_at"] = (s.epoch + timedelta(seconds=1)).isoformat()
    elif change == "unknown":
        s.identities[202] = {"status": "UNKNOWN"}
    elif change == "reused":
        calls = []

        def identity(pid):
            if pid == 202:
                calls.append(pid)
                return {"status": "LIVE", "creation_identity": str(ticks + (10**7 if len(calls) > 1 else 0))}
            return s.identity(pid)

        monkeypatch.setattr(updates, "native_process_identity", identity)
    if change == "none":
        with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
            assert poll.read(lambda: [row]) == [row]
    else:
        with pytest.raises(updates._BootstrapObservationChanged):
            with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
                poll.read(lambda: [row])
    assert s.held == []


def test_read_error_preserved_after_unchanged_reacquisition(poll_scene):
    s = poll_scene
    error = ValueError("observation failed")

    def observe():
        assert s.held == []
        raise error

    with pytest.raises(ValueError) as caught:
        with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
            with poll.trial():
                poll.read(observe)
    assert caught.value is error and s.held == []


def test_original_deadline_not_reopened_by_slow_read(poll_scene):
    s = poll_scene

    def observe():
        s.clock[0] = 120
        return []

    with pytest.raises(updates._BootstrapObservationChanged):
        with updates._BootstrapPoll(s.control, s.policy, deadline=120) as poll:
            poll.read(observe)
    assert poll.deadline == 120 and s.held == []


@pytest.mark.parametrize("seconds", [15, 30])
def test_bootstrap_trial_observe_runs_outside_both_locks_and_discards_stale_state(poll_scene, monkeypatch, seconds):
    s = poll_scene
    launches, snapshots = [], []
    monkeypatch.setattr(updates, "control_root", lambda *_: s.control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_: True)
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "NONE" if s.records[s.control / "apply-claim.json"]["status"] == "SETTLED" else "LIVE")
    monkeypatch.setattr(updates, "prepared_pending", lambda *_: False)
    monkeypatch.setattr(updates, "_bootstrap_recovery_gui", lambda *a, **k: None)
    monkeypatch.setattr(updates, "request_apply_task", lambda *_: None)
    monkeypatch.setattr(updates, "launch_version", lambda *a, **k: launches.append((a, k)) or 202)
    monkeypatch.setattr(updates, "emit_progress_guidance", lambda: None)

    def observe(*_):
        assert s.held == []
        with s.lock("update"):
            pass
        s.clock[0] += seconds
        snapshots.append(seconds)
        s.records[s.control / "transition.json"]["phase"] = "CONFIRMED"
        s.records[s.control / "apply-claim.json"]["status"] = "SETTLED"
        return []

    monkeypatch.setattr(updates, "process_snapshot", observe)
    assert updates._bootstrap(s.control / "app", [], role="gui") == 0
    assert snapshots == [seconds] and launches == [] and s.held == []
    assert max(duration for _, duration in s.intervals) <= 1
