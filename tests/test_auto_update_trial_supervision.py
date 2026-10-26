"""Fake-clock acceptance scenes for the fixed installed update controller."""
import contextlib
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest

import auto_update as updates
from _update_native_rows import native_row_identity
from tests.test_current_user_onboarding import existing_possession_key_contract
from user_relay import user_relay_stop_path


OLD, NEW = "a" * 40, "b" * 40
EPOCH = datetime(2026, 10, 17, tzinfo=timezone.utc)
START_CURRENT = updates.start_current


def stamp(seconds):
    return (EPOCH + timedelta(seconds=seconds)).isoformat()


@pytest.fixture
def scene(tmp_path, monkeypatch):
    control, stage, local = (tmp_path / name for name in ("control", "stage", "local"))
    for directory in (control, stage, local):
        directory.mkdir()
    policy = {"operator_sid": "S-1-5-21-100-200-300-1001",
              "operator_local_app_data": str(local), "staging_root": str(stage)}
    clock = [0.0]
    tick = [lambda: None]
    launches, requests, terminal = [], [], []
    rows = []
    lock = threading.RLock()

    def write(path, value):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(value), encoding="utf-8")

    state = updates.prepare_transition(previous_sha=OLD, candidate_sha=NEW,
        packet_sha256="c" * 64, forward_pin="d" * 64, rollback_pin="e" * 64,
        transition_id="f" * 32, nonce="1" * 32, now=stamp(0))
    state = updates.apply_transition(state, writers_absent=True, packet_verified=True,
                                    durable_prepared=True, now=stamp(0))
    write(control / "policy.json", policy)
    write(control / "active.json", {"schema": updates.SCHEMA, "sha": NEW})
    write(control / "transition.json", state)
    write(stage / "trial.json", {"pid": 101, "nonce": state["nonce"],
                                 "transition_id": state["transition_id"]})

    def sleep(seconds):
        with lock:
            clock[0] += seconds
            tick[0]()

    @contextlib.contextmanager
    def startup_lock(*args, **kwargs):
        with lock:
            yield True

    def launch(control, sha, arguments, **kwargs):
        launches.append((clock[0], sha, arguments, kwargs))
        return 101 if arguments[:1] != ["--container-audit-user-relay"] else 102

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(updates, "now_utc", lambda: stamp(clock[0]))
    monkeypatch.setattr(updates, "write_json_durable", write)
    monkeypatch.setattr(updates, "control_root", lambda *_: control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_: True)
    monkeypatch.setattr(updates, "startup_update_lock", startup_lock)
    monkeypatch.setattr(updates, "update_lock", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "LIVE")
    monkeypatch.setattr(updates, "prepared_pending", lambda *a: False)
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: list(rows))
    monkeypatch.setattr(updates, "native_process_identity", lambda pid: native_row_identity(rows, pid, current_pid=os.getpid()))
    monkeypatch.setattr(updates, "request_apply_task", lambda *a: requests.append(clock[0]))
    monkeypatch.setattr(updates, "launch_version", launch)
    monkeypatch.setattr(updates, "_bootstrap_recovery_gui", lambda *a, **k: None)
    monkeypatch.setattr(updates, "_bootstrap_existing_writers", lambda *a, **k: None)
    monkeypatch.setattr(updates, "current_generation_status", lambda *a: "ALLOW")
    monkeypatch.setattr(updates, "start_current", lambda *a, **k: terminal.append(clock[0]) or 0)
    monkeypatch.setattr(updates, "emit_progress_guidance", lambda: None)
    monkeypatch.setattr(updates, "record_confirmed_policy", lambda *a: None)
    monkeypatch.setattr(updates, "fixed_helper", lambda *a, **k: "")

    def relay(sha=NEW):
        return dict(pid=102, observable=True, sha=sha, sid=policy["operator_sid"],
                    ordinary_user=True, role="relay", created_at=stamp(clock[0]))

    marker = user_relay_stop_path(local / "KMTech/DirectSync/container_audit")
    return SimpleNamespace(**locals())


def test_a_slow_rollback_is_supervised_after_240_seconds(scene, monkeypatch):
    s = scene
    s.rows.append(s.relay())

    def advance():
        state = updates.read_json(s.control / "transition.json")
        if s.clock[0] >= 300:
            state.update(phase="ROLLED_BACK")
        elif s.clock[0] >= 220:
            state.update(phase="ROLLBACK_PENDING_READY", rollback_at=stamp(220), nonce="2" * 32)
            s.write(s.control / "active.json", {"sha": OLD})
            s.rows[:] = [s.relay(OLD)]
        elif s.clock[0] >= 120:
            state.update(phase="ROLLBACK_PENDING", normal_stop_started_at=stamp(120))
        s.write(s.control / "transition.json", state)

    s.tick[0] = advance
    assert updates._bootstrap(s.control.parent, [], role="gui") == 0
    assert 300 <= s.terminal[-1] < 301
    # A durable future phase cannot extend the overall READY-plus-240-second cap.
    assert updates.bootstrap_supervision_deadline(
        {**s.state, "applied_at": stamp(1000)}, started=0, now=0, utc_now=stamp(0)) == updates.BOOTSTRAP_OBSERVATION_CAP_SECONDS
    # The candidate normal-stop window must start with a durable UTC record.
    s.clock[0] = 0
    s.tick[0] = lambda: None
    s.write(s.control / "transition.json", s.state)
    s.write(s.control / "active.json", {"sha": NEW})
    s.write(s.stage / "trial.json", {"pid": 101, "nonce": s.state["nonce"],
                                    "transition_id": s.state["transition_id"]})

    class StopObserved(Exception):
        pass

    def sample(*args):
        state = updates.read_json(s.control / "transition.json")
        if state["phase"] == "UNKNOWN":
            assert state["normal_stop_started_at"] == stamp(240)
            raise StopObserved
        return [dict(s.relay(), pid=101, role="gui")]

    monkeypatch.setattr(updates, "process_snapshot", sample)
    monkeypatch.setattr(updates, "new_apply_claim", lambda: {})
    with pytest.raises(StopObserved):
        updates._apply_prepared_once(s.control)


def test_b_relay_oserror_once_then_one_relay_ready(scene, monkeypatch):
    s = scene
    s.write(s.control / "transition.json", {**s.state, "trial_pid": 101,
                                           "trial_started_at": stamp(0)})
    launch = updates.launch_version

    def start(*args, **kwargs):
        if not s.launches:
            s.launches.append((s.clock[0], "failed"))
            raise OSError("synthetic process creation failure")
        pid = launch(*args, **kwargs)
        s.rows[:] = [s.relay()]
        state = updates.read_json(s.control / "transition.json")
        s.write(s.control / "transition.json", {**state, "phase": "CONFIRMED"})
        return pid

    monkeypatch.setattr(updates, "launch_version", start)
    assert updates._bootstrap(s.control.parent, [], role="gui") == 0
    assert len(s.launches) == 2
    assert s.launches[1][0] - s.launches[0][0] >= 2
    assert len(s.rows) == 1


def test_c_three_failed_relay_starts_record_code_without_duplicate(scene, monkeypatch):
    s = scene

    def fail(*args, **kwargs):
        s.launches.append(s.clock[0])
        raise OSError("synthetic process creation failure")

    monkeypatch.setattr(updates, "launch_version", fail)
    assert updates._bootstrap(s.control.parent, [], role="gui") == 20
    assert len(s.launches) == 3
    assert all(b - a >= 2 for a, b in zip(s.launches, s.launches[1:]))
    assert updates.read_json(s.stage / "startup-support.json")["reason_code"] == "TRIAL_RELAY_START_FAILED"
    assert updates.read_json(s.control / "transition.json") == s.state
    assert s.rows == []


def stop_before_apply(s, monkeypatch):
    s.marker.parent.mkdir(parents=True, exist_ok=True)
    s.marker.write_bytes(b"{}")
    s.write(s.control / "transition.json", {**s.state, "phase": "PREPARED"})
    s.write(s.control / "active.json", {"sha": OLD})
    monkeypatch.setattr(updates, "prepared_pending", lambda *a: True)
    monkeypatch.setattr(updates, "create_protected_stage", lambda *a: pytest.fail("stop must precede packet staging"))


def test_d_stop_defers_system_and_bootstrap_without_pointer_or_marker_change(scene, monkeypatch, capsys):
    s = scene
    stop_before_apply(s, monkeypatch)
    pointer, marker = (s.control / "active.json").read_bytes(), s.marker.read_bytes()
    assert updates._apply_prepared_once(s.control) == 0
    state = updates.read_json(s.control / "transition.json")
    assert (state["phase"], state.get("recovery_pending", False), state["reason_code"]) == (
        "DEFERRED", False, "UPDATE_RELAY_STOP_REQUESTED")
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "NONE")
    monkeypatch.setattr(updates, "start_current", START_CURRENT)
    for role in ("gui", "relay"):
        s.launches.clear()
        arguments = [] if role == "gui" else ["--container-audit-user-relay"]
        assert updates._bootstrap(s.control.parent, arguments, role=role) == 0
        assert s.requests == []
        assert len(s.launches) == 1 and s.launches[0][2] == []
        assert updates.read_json(s.stage / "startup-support.json")["reason_code"] == "UPDATE_RELAY_STOP_REQUESTED"
        assert capsys.readouterr().out.count("CONTAINER_AUDIT_SUPPORT=") == 1
    assert (s.control / "active.json").read_bytes() == pointer
    assert s.marker.read_bytes() == marker
    # A repeated SYSTEM invocation must retain the same stopped pre-apply state.
    assert updates._apply_prepared_once(s.control) == 0
    repeated = updates.read_json(s.control / "transition.json")
    assert repeated["phase"] == "DEFERRED" and not repeated.get("recovery_pending")
    # The marker can appear after Run's precheck but before SYSTEM applies.
    s.launches.clear()
    monkeypatch.setattr(updates, "update_relay_stop_requested", lambda *_: False)

    def late_stop(*args):
        s.requests.append(s.clock[0])
        updates.defer_stopped_update(s.control, updates.read_json(s.control / "transition.json"))

    monkeypatch.setattr(updates, "request_apply_task", late_stop)
    assert updates._bootstrap(s.control.parent, ["--container-audit-user-relay"], role="relay") == 0
    assert len(s.requests) == 1 and len(s.launches) == 1
    assert s.launches[0][2] == []
    assert capsys.readouterr().out.count("CONTAINER_AUDIT_SUPPORT=") == 1
    assert (s.control / "active.json").read_bytes() == pointer
    assert s.marker.read_bytes() == marker


def test_e_onboarding_cleared_stop_allows_next_apply_request(scene, monkeypatch,
                                                           existing_possession_key_contract):
    s = scene
    stop_before_apply(s, monkeypatch)
    assert updates._apply_prepared_once(s.control) == 0
    assert updates.read_json(s.control / "transition.json")["reason_code"] == "UPDATE_RELAY_STOP_REQUESTED"
    # Exercise the existing onboarding helper, with local fake registration only.
    import current_user_onboarding as onboarding
    from tests.test_current_user_onboarding import (
        _ready_state, _profile_loader, _credential_loader, _ledger_factory,
        _autostart, _relay_start,
    )

    app = s.control.parent / "onboarding-app"
    app.mkdir()
    environment = {"LOCALAPPDATA": str(s.local)}
    import data_generation_guard
    from tools import register_container_audit_worker_pc as registration
    monkeypatch.setattr(data_generation_guard, "_runtime_release", lambda: {
        "version": "v2.0.112", "build_id": NEW,
        "data_compatible_min_version": "v2.0.112", "compatibility_verified": False})
    monkeypatch.setattr(registration, "_current_user_sid", lambda: s.policy["operator_sid"])

    def register(paths):
        _ready_state(paths)
        return 0

    report = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=_profile_loader, credential_loader=_credential_loader,
        ledger_factory=_ledger_factory, autostart_installer=_autostart,
        relay_launcher=_relay_start)
    assert report["status"] == "READY"
    assert not s.marker.exists()
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "NONE")

    def apply(*args):
        s.requests.append(s.clock[0])
        s.write(s.control / "transition.json", {**s.state, "phase": "CONFIRMED"})

    monkeypatch.setattr(updates, "request_apply_task", apply)
    monkeypatch.setattr(updates, "prepared_pending", lambda _control, _policy, state: state["phase"] != "CONFIRMED")
    assert updates._bootstrap(s.control.parent, [], role="gui") == 0
    assert len(s.requests) == 1
    assert not s.marker.exists()


def test_restart_rollback_uses_only_original_remaining_window(scene, monkeypatch):
    s = scene
    original = {**s.state, "phase": "ROLLBACK_PENDING_READY", "rollback_at": stamp(0),
                "nonce": "2" * 32, "trial_pid": None, "trial_started_at": None}
    s.write(s.control / "active.json", {"sha": OLD})
    s.write(s.control / "transition.json", original)
    s.write(s.stage / "trial.json", {"pid": 101, "nonce": original["nonce"],
                                    "transition_id": original["transition_id"]})
    s.clock[0] = 100
    launch = updates.launch_version

    def start(*args, **kwargs):
        pid = launch(*args, **kwargs)
        if args[2][:1] == ["--container-audit-user-relay"]:
            state = updates.read_json(s.control / "transition.json")
            rows = [dict(s.relay(OLD), pid=101, role="gui"), s.relay(OLD)]
            receipt = {**{check: True for check in updates.READY_CHECKS},
                       "nonce": state["nonce"], "transition_id": state["transition_id"],
                       "sha": OLD, "pid": 101, "ready_at": stamp(s.clock[0])}
            # Drive the real shared READY predicate, including relay exactly one.
            _, confirmed, _ = updates.observe_trial_ready(s.control, s.policy, state,
                rows, {"pid": 101, "nonce": state["nonce"], "transition_id": state["transition_id"]},
                receipt, deadline=120)
            assert confirmed
        return pid

    monkeypatch.setattr(updates, "launch_version", start)
    assert updates._bootstrap(s.control.parent, [], role="gui") == 0
    assert updates.read_json(s.control / "transition.json")["phase"] == "ROLLED_BACK"
    # Re-enter after the original window: no new GUI/relay trial is permitted.
    s.write(s.control / "transition.json", original)
    s.clock[0] = updates.READY_WINDOW_SECONDS + 1
    s.launches.clear()
    assert updates._bootstrap(s.control.parent, [], role="gui") == 20
    assert s.launches == []
    assert updates.wait_for_rollback_ready(s.control, s.policy) == 20
    state = updates.read_json(s.control / "transition.json")
    assert state["phase"] == "FAILED" and state["rollback_at"] == original["rollback_at"]
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "ABSENT")
    terminal_before = len(s.terminal)
    assert updates._bootstrap(s.control.parent, [], role='gui') == 0
    assert len(s.terminal) == terminal_before + 1


def test_overlapping_run_and_gui_reuse_sampled_single_trial_relay(scene, monkeypatch):
    s = scene
    launch = updates.launch_version
    observed = []
    match = updates.process_matches_trial
    s.rows[:] = [dict(s.relay(), pid=101, role="gui")]

    def matches(*args, **kwargs):
        observed.append(kwargs["role"])
        return match(*args, **kwargs)

    def start(*args, **kwargs):
        pid = launch(*args, **kwargs)
        s.rows[:] = [s.relay()]
        return pid

    monkeypatch.setattr(updates, "process_matches_trial", matches)
    monkeypatch.setattr(updates, "launch_version", start)

    def ready():
        if s.rows and len(observed) >= 2:
            state = updates.read_json(s.control / "transition.json")
            s.write(s.control / "transition.json", {**state, "phase": "CONFIRMED"})

    s.tick[0] = ready
    results = []
    threads = [threading.Thread(target=lambda role=role: results.append(
        updates._bootstrap(s.control.parent, [], role=role))) for role in ("relay", "gui")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    (s.control.parent / "overlapping-trial-observed.json").write_text(json.dumps({
        "results": results, "launches": s.launches, "observed": observed,
        "row_roles": [row["role"] for row in s.rows],
        "phase": updates.read_json(s.control / "transition.json")["phase"],
    }, default=str), encoding="utf-8")
    assert results == [0, 0]
    assert sum(args[:1] == ["--container-audit-user-relay"]
               for _, _, args, _ in s.launches) == 1
    assert len(s.rows) == 1
    assert "relay" in observed
