"""A recovery GUI must receive one relay in its original ordinary cohort."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import uuid

import pytest

import auto_update as updates
import writer_session_fence as fence


SHA = "a" * 40
BOUNDARY = "2026-10-16T00:00:00Z"
CREATED = "2026-10-16T00:00:01Z"
NOW = "2026-10-16T00:01:00Z"
RELAY = ["--container-audit-user-relay", "--data-root", "isolated-data"]
CASES = ("absent", "failed", "unknown", "request-error", "after-request", "stale")


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    control, stage = tmp_path / "control", tmp_path / "stage"
    control.mkdir()
    stage.mkdir()
    policy = {"operator_sid": uuid.uuid4().hex, "staging_root": str(stage)}
    state = {"schema": updates.SCHEMA, "phase": "APPLIED_PENDING_READY", "trial_pid": 42}
    records = {
        control / "policy.json": policy,
        control / "active.json": {"sha": SHA},
        control / "transition.json": state,
        control / "apply-claim.json": {"status": "UNKNOWN"},
        stage / "trial.json": {"preserved": True},
        stage / "startup-support.json": {"preserved": True},
    }
    for path, value in records.items():
        path.write_text(json.dumps(value), encoding="utf-8")
    os.utime(control / "apply-claim.json", (1, 1))
    original = {path: path.read_bytes() for path in records}
    parent = dict(pid=os.getpid() + 100000, observable=True, bootstrap=False,
                  role="gui", sha=SHA, sid=policy["operator_sid"],
                  ordinary_user=True, created_at=CREATED)
    rows, launches, guidance = [parent], [], []
    clock, case = [0.0], ["absent"]
    mutex = threading.RLock()
    held = threading.local()

    @contextlib.contextmanager
    def locked(*args, **kwargs):
        with mutex:
            held.depth = getattr(held, "depth", 0) + 1
            try:
                yield True
            finally:
                held.depth -= 1

    @contextlib.contextmanager
    def admitted(*args, **kwargs):
        yield

    def snapshot(*args):
        assert held.depth > 0
        return list(rows)

    def launch(command, **kwargs):
        assert held.depth > 0
        launches.append((command, kwargs))
        pid = parent["pid"] + len(launches)
        rows.append({**parent, "pid": pid, "role": "relay"})
        return SimpleNamespace(pid=pid)

    def claim(*args):
        if case[0] == "absent":
            return "ABSENT"
        if case[0] == "stale":
            return "UNKNOWN"
        if case[0] == "after-request":
            claim.calls += 1
            return "ABSENT" if claim.calls >= 3 else "NONE"
        return "NONE"
    claim.calls = 0

    def prepared(_control, _policy, observed):
        # Fault injection covers the defensive request-error fallback even when
        # an observer advances PREPARED after the initial apply_started check.
        if case[0] == "request-error":
            observed["phase"] = "APPLIED_PENDING_READY"
        return False

    def request(*args):
        if case[0] == "request-error":
            raise OSError("injected task request failure")

    monkeypatch.setattr(updates, "control_root", lambda *_: control)
    monkeypatch.setattr(updates, "optional_record", lambda p: state if p.name == "transition.json" else updates.read_json(p))
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_: True)
    monkeypatch.setattr(updates, "startup_update_lock", locked)
    monkeypatch.setattr(updates, "update_lock", locked)
    monkeypatch.setattr(updates, "process_snapshot", snapshot)
    monkeypatch.setattr(updates, "current_generation_status", lambda *_: "ALLOW")
    monkeypatch.setattr(updates, "prepared_pending", prepared)
    monkeypatch.setattr(updates, "apply_claim_status", claim)
    monkeypatch.setattr(updates, "request_apply_task", request)
    monkeypatch.setattr(updates, "version_bundle", lambda *_: tmp_path / "bundle")
    monkeypatch.setattr(updates, "version_manifest", lambda *_: {"source_commit": SHA})
    monkeypatch.setattr(updates, "emit_progress_guidance", lambda: guidance.append(True))
    monkeypatch.setattr(updates, "now_utc", lambda: NOW)
    monkeypatch.setattr(updates.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(updates.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + 240))
    monkeypatch.setattr(fence, "writer_admission", admitted)
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setenv("KMTECH_CA_UPDATE_DEFERRED_AT", BOUNDARY)
    monkeypatch.delenv("KMTECH_CA_UPDATE_TRIAL_NONCE", raising=False)

    def configure(value):
        case[0] = value
        state["phase"] = {"failed": "FAILED", "unknown": "UNKNOWN", "stale": "UNKNOWN",
                          "request-error": "PREPARED"}.get(value, "APPLIED_PENDING_READY")

    def invoke(role="relay", arguments=None):
        return updates._bootstrap(tmp_path / "app", RELAY if arguments is None else arguments, role=role)

    def unchanged():
        assert all(path.read_bytes() == before for path, before in original.items())
        assert set(control.iterdir()) == {p for p in records if p.parent == control}
        assert set(stage.iterdir()) == {p for p in records if p.parent == stage}

    return SimpleNamespace(**locals())


@pytest.mark.parametrize("case", CASES)
def test_recovery_gui_launches_one_relay_with_original_boundary(recovery, case):
    r = recovery
    r.configure(case)
    assert r.invoke() == 0
    assert len(r.launches) == 1
    command, options = r.launches[0]
    assert command[-len(RELAY):] == RELAY
    assert options["env"]["KMTECH_CA_UPDATE_DEFERRED_AT"] == BOUNDARY
    assert "KMTECH_CA_UPDATE_TRIAL_NONCE" not in options["env"]
    assert updates.startup_gate(r.tmp_path / "app", RELAY, role="relay") is None
    r.unchanged()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("boundary", (None, "2026-10-16T00:00:02Z"))
def test_unproven_parent_fails_instead_of_claiming_relay_success(recovery, monkeypatch, case, boundary):
    r = recovery
    r.configure(case)
    if boundary is None:
        monkeypatch.delenv("KMTECH_CA_UPDATE_DEFERRED_AT")
    else:
        monkeypatch.setenv("KMTECH_CA_UPDATE_DEFERRED_AT", boundary)
    assert r.invoke() == 20
    assert not r.launches and r.guidance
    r.unchanged()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("with_boundary", (True, False))
def test_existing_cohort_relay_is_reused(recovery, monkeypatch, case, with_boundary):
    r = recovery
    r.configure(case)
    r.rows.append({**r.parent, "pid": r.parent["pid"] + 1, "role": "relay"})
    if not with_boundary:
        monkeypatch.delenv("KMTECH_CA_UPDATE_DEFERRED_AT")
    assert r.invoke() == 0
    assert not r.launches
    r.unchanged()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("defect", ("sha", "sid", "elevated", "role", "unobservable", "generation", "active"))
def test_recovery_rejects_unrelated_or_unproven_writers(recovery, monkeypatch, case, defect):
    r = recovery
    r.configure(case)
    if defect == "sha":
        r.parent["sha"] = "b" * 40
    elif defect == "sid":
        r.parent["sid"] = uuid.uuid4().hex
    elif defect == "elevated":
        r.parent["ordinary_user"] = False
    elif defect == "role":
        r.parent["role"] = "writer"
    elif defect == "unobservable":
        r.parent["observable"] = False
    elif defect == "generation":
        monkeypatch.setattr(updates, "current_generation_status", lambda *_: "UNKNOWN")
    else:
        native_read = updates.read_json
        reads = [0]
        def changed_active(path):
            value = native_read(path)
            if path.name == "active.json":
                reads[0] += 1
                if reads[0] > 1:
                    return {"sha": "b" * 40}
            return value
        monkeypatch.setattr(updates, "read_json", changed_active)
    assert r.invoke() == 20
    assert not r.launches
    r.unchanged()


@pytest.mark.parametrize("boundary", ("invalid", "2026-10-16T00:00:00", NOW, "2026-10-17T00:00:00Z"))
def test_invalid_or_future_boundary_fails(recovery, monkeypatch, boundary):
    monkeypatch.setenv("KMTECH_CA_UPDATE_DEFERRED_AT", boundary)
    assert recovery.invoke() == 20
    assert not recovery.launches
    recovery.unchanged()


@pytest.mark.parametrize("case", CASES)
def test_launch_failure_is_retryable_without_state_writes(recovery, monkeypatch, case):
    r = recovery
    r.configure(case)
    original_launch = subprocess.Popen
    def fail(*args, **kwargs):
        raise OSError("injected launch failure")
    monkeypatch.setattr(subprocess, "Popen", fail)
    assert r.invoke() == 20
    assert not r.launches
    r.unchanged()
    monkeypatch.setattr(subprocess, "Popen", original_launch)
    r.clock[0] = 0
    r.claim.calls = 0
    if case == "request-error":
        r.configure(case)
    assert r.invoke() == 0
    assert len(r.launches) == 1
    r.unchanged()


def test_concurrent_requests_launch_exactly_one_relay(recovery):
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda _: recovery.invoke(), range(2))) == [0, 0]
    assert len(recovery.launches) == 1
    recovery.unchanged()


@pytest.mark.parametrize("case", CASES)
def test_gui_duplicate_behavior_is_preserved(recovery, monkeypatch, case):
    recovery.configure(case)
    monkeypatch.delenv("KMTECH_CA_UPDATE_DEFERRED_AT")
    assert recovery.invoke(role="gui", arguments=[]) == 0
    assert not recovery.launches
    recovery.unchanged()


def test_recovery_relay_timeout_retries_until_existing_deadline(recovery, monkeypatch):
    r = recovery
    attempts = []
    real_launch = updates.launch_version
    def busy(*args, **kwargs):
        attempts.append(True)
        if len(attempts) < 3:
            raise fence.WriterFencedError("WRITER_GATE_TIMEOUT", "injected transient admission")
        return real_launch(*args, **kwargs)
    monkeypatch.setattr(updates, "launch_version", busy)
    monkeypatch.setattr(updates.time, "sleep", lambda seconds: r.clock.__setitem__(0, r.clock[0] + seconds))
    assert r.invoke() == 0
    assert len(attempts) == 3 and len(r.launches) == 1
    r.unchanged()


def test_recovery_relay_timeout_deadline_is_failure(recovery, monkeypatch):
    def busy(*args, **kwargs):
        raise fence.WriterFencedError("WRITER_GATE_TIMEOUT", "injected admission deadline")
    monkeypatch.setattr(updates, "launch_version", busy)
    assert recovery.invoke() == 20
    assert recovery.clock[0] >= 240 and not recovery.launches
    recovery.unchanged()


def test_bootstrap_still_requires_ordinary_operator(recovery, monkeypatch):
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_: False)
    with pytest.raises(ValueError):
        recovery.invoke()
    assert not recovery.launches
    recovery.unchanged()


def test_direct_sync_reentry_uses_same_relay_recovery_contract(recovery):
    arguments = ["--container-audit-direct-sync-relay", "--db-path", "isolated-queue"]
    assert recovery.invoke(arguments=arguments) == 0
    assert len(recovery.launches) == 1
    command, options = recovery.launches[0]
    assert command[-len(arguments):] == arguments
    assert options["env"]["KMTECH_CA_UPDATE_DEFERRED_AT"] == BOUNDARY
    recovery.unchanged()


@pytest.mark.parametrize("defect", ("sha", "sid", "ordinary_user", "created_at", "generation"))
def test_boundaryless_reuse_requires_proven_ordinary_relay(recovery, monkeypatch, defect):
    r = recovery
    monkeypatch.delenv("KMTECH_CA_UPDATE_DEFERRED_AT")
    relay = {**r.parent, "pid": r.parent["pid"] + 1, "role": "relay"}
    if defect == "generation":
        monkeypatch.setattr(updates, "current_generation_status", lambda *_: "UNKNOWN")
    elif defect == "ordinary_user":
        relay[defect] = False
    else:
        relay[defect] = uuid.uuid4().hex
    r.rows.append(relay)
    assert r.invoke() == 20
    assert not r.launches
    r.unchanged()
