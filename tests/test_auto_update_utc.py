"""Representable READY times are required without aborting durable recovery."""
from contextlib import nullcontext
from datetime import datetime, timezone
import time

import pytest

import auto_update as updates
from tests.test_auto_update import LATER, NEW, NOW, OLD, ready, trial

EXTREMES = ("0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00")


@pytest.mark.parametrize("timestamp", EXTREMES)
@pytest.mark.parametrize("rollback", (False, True))
def test_unrepresentable_ready_is_unconfirmed_in_both_trial_phases(timestamp, rollback):
    state = trial()
    if rollback:
        pending = updates.request_rollback(state, reason="candidate failed")
        # D-16 requires an observed unchanged G before the old-code trial.
        pending["failure_decision"] = {"selected_sha": OLD}
        state = updates.rollback_transition(pending,
            writers_absent=True, previous_verified=True, durable_rollback=True, nonce="8" * 32, now=NOW)
        state = updates.bind_trial(state, sha=OLD, pid=42, ordinary_user=True, now=NOW)
    receipt = {**ready(state), "sha": state["trial_sha"], "ready_at": timestamp}
    assert updates.ready_matches(state, receipt, process_matches=True, relay_matches=True, now=LATER) is False
    with pytest.raises(ValueError):
        updates.confirm_transition(state, receipt, process_matches=True, relay_matches=True, now=LATER)
    assert state["phase"] == ("ROLLBACK_PENDING_READY" if rollback else "APPLIED_PENDING_READY")


@pytest.mark.parametrize("timestamp,expected", (
    ("0001-01-01T14:00:00+14:00", "0001-01-01T00:00:00+00:00"),
    ("9999-12-31T09:59:59-14:00", "9999-12-31T23:59:59+00:00"),
    ("2026-10-01T13:00:01+09:00", LATER),
))
def test_representable_offset_times_remain_exact(timestamp, expected):
    assert updates._utc(timestamp) == datetime.fromisoformat(expected).astimezone(timezone.utc)
    if expected == LATER:
        state = trial()
        assert updates.ready_matches(state, {**ready(state), "ready_at": timestamp},
            process_matches=True, relay_matches=True, now=LATER)


@pytest.mark.parametrize("timestamp", EXTREMES)
@pytest.mark.parametrize("previous_ready", (False, True))
def test_extreme_ready_keeps_deadline_and_code_rollback_alive(tmp_path, monkeypatch, timestamp, previous_ready):
    control, stage = tmp_path / "control", tmp_path / "stage"
    control.mkdir()
    stage.mkdir()
    sid = "S-1-5-21-455"
    policy = {
        "operator_sid": sid, "staging_root": str(stage),
        "operator_local_app_data": str(tmp_path / "user"),
    }
    updates.write_json_durable(control / "policy.json", policy)
    updates.write_json_durable(control / "active.json", {"schema": updates.SCHEMA, "sha": NEW})
    state = {**trial(), "generation_before": updates.read_trial_generation(policy),
             "generation_previous_release": {"version": "v2.0.98", "source_commit": OLD},
             "generation_candidate_release": {"version": "v2.0.99", "source_commit": NEW}}
    updates.write_json_durable(control / "transition.json", state)
    business = tmp_path / "unfinished-and-ledger.bin"
    business.write_bytes(b"unchanged business state")
    policy_before = (control / "policy.json").read_bytes()
    monkeypatch.setattr(updates, "update_lock", lambda *_args, **_kwargs: nullcontext())
    helpers, phases = [], []
    monkeypatch.setattr(updates, "fixed_helper", lambda _control, mode, **_kwargs: helpers.append(mode) or "")
    monkeypatch.setattr(updates, "now_utc", lambda: LATER)
    ticks = iter(range(0, 10000, 10))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(time, "sleep", lambda _: None)

    def snapshot(_control):
        state = updates.read_json(control / "transition.json")
        phases.append(state["phase"])
        if state["phase"] == "ROLLBACK_PENDING":
            return []  # Supported normal stop has completed before old code is selected.
        rollback = state["phase"] == "ROLLBACK_PENDING_READY"
        sha, pid = (OLD, 44) if rollback else (NEW, 42)
        proof = {**ready(state), "sha": sha, "pid": pid,
            "ready_at": LATER if rollback and previous_ready else timestamp}
        updates.write_json_durable(stage / "ready.json", proof)
        updates.write_json_durable(stage / "trial.json", {
            "nonce": state["nonce"], "transition_id": state["transition_id"], "pid": pid,
        })
        return [dict(pid=value, observable=True, sha=sha, sid=sid, role=role,
            ordinary_user=True, created_at=NOW if not rollback else LATER)
            for value, role in ((pid, "gui"), (pid + 1, "relay"))]

    monkeypatch.setattr(updates, "process_snapshot", snapshot)
    code = updates.apply_prepared(control)
    state = updates.read_json(control / "transition.json")
    assert code == (0 if previous_ready else 20)
    assert state["phase"] == ("ROLLED_BACK" if previous_ready else "FAILED")
    assert state["failed_shas"] == [NEW]
    assert updates.read_json(control / "active.json")["sha"] == OLD
    assert "APPLIED_PENDING_READY" in phases and "ROLLBACK_PENDING" in phases and "ROLLBACK_PENDING_READY" in phases
    assert "Verify" in helpers
    assert business.read_bytes() == b"unchanged business state"
    assert (control / "policy.json").read_bytes() == policy_before
