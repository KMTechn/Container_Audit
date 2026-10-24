"""Retained candidate startup and SYSTEM confirmation contracts."""
import json

import pytest

import auto_update as updates
from tests.test_auto_update_trial_supervision import NEW, scene, stamp


@pytest.mark.parametrize("pending", [True, False])
def test_retained_start_requests_distinct_prepared_before_ordinary_return(scene, monkeypatch, pending):
    s = scene
    s.clock[0] = 130
    state = {
        **s.state,
        "phase": "DEFERRED",
        "retained_candidate": True,
        "deferred_at": stamp(120),
        "failure_decision": {"selected_sha": NEW, "code": "TRIAL_GENERATION_ADVANCED"},
    }
    s.write(s.control / "transition.json", state)
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "NONE")
    monkeypatch.setattr(updates, "prepared_pending", lambda *_: pending)
    pointer = (s.control / "active.json").read_bytes()

    assert updates._bootstrap(s.control.parent, [], role="gui") == 0
    assert len(s.requests) == int(pending)
    assert (s.control / "active.json").read_bytes() == pointer
    assert json.loads((s.control / "transition.json").read_bytes()) == state


def test_retained_prepared_request_rereads_system_writer_deferral(scene, monkeypatch):
    s = scene
    s.clock[0] = 130
    state = {**s.state, "phase": "DEFERRED", "retained_candidate": True,
             "deferred_at": stamp(120),
             "failure_decision": {"selected_sha": NEW, "code": "TRIAL_GENERATION_ADVANCED"}}
    s.write(s.control / "transition.json", state)
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "NONE")
    monkeypatch.setattr(updates, "prepared_pending", lambda *_: True)

    def request(*_):
        s.requests.append(s.clock[0])
        s.write(s.control / "transition.json", {
            **state, "deferred_at": updates.now_utc(),
            "reason_code": "UPDATE_EXISTING_WRITER"})

    monkeypatch.setattr(updates, "request_apply_task", request)
    assert updates._bootstrap(s.control.parent, [], role="gui") == 0
    assert s.requests == [130]
    assert s.launches == []
    assert s.terminal == [130]
    assert updates.read_json(s.control / "transition.json")["reason_code"] == "UPDATE_EXISTING_WRITER"


def _actual_retained_failure(s, monkeypatch, reason):
    from kmtech_shared import data_generation
    monkeypatch.setattr(updates, "read_trial_generation", lambda *_: {"status": "UNKNOWN"})
    monkeypatch.setattr(data_generation, "probe_downgrade", lambda *a, **k: {"status": "UNKNOWN"})
    state = updates.request_rollback(s.state, reason=reason)
    state = {**state, "normal_stop_started_at": stamp(120), "recovery_pending": False}
    return updates.decide_trial_failure(state, s.policy)


@pytest.mark.parametrize("case", ["other_transition_failure", "other_reason",
                                  "rollback_executed", "rollback_waiting",
                                  "insufficient_records"])
def test_retained_late_ready_cannot_confirm_without_timeout_provenance(scene, monkeypatch, case):
    s = scene
    s.clock[0] = 130
    reason = "candidate startup failed or readiness timed out"
    if case == "other_reason":
        reason = "a separately classified startup failure"
    state = _actual_retained_failure(s, monkeypatch, reason)
    if case == "other_transition_failure":
        state = {**state, "transition_id": "2" * 32}
    elif case == "rollback_executed":
        state = {**state, "rollback_at": stamp(125)}
    elif case == "rollback_waiting":
        state = {**state, "recovery_pending": True}
    elif case == "insufficient_records":
        state = {**state, "failure_decision": {}}
    state = {**state, "trial_pid": 101, "trial_sha": NEW, "trial_started_at": stamp(125)}
    ready = {"pid": 101, "sha": NEW, "nonce": state["nonce"],
             "transition_id": state["transition_id"], "ready_at": stamp(129),
             **{check: True for check in updates.READY_CHECKS}}
    before = json.dumps(state, sort_keys=True)
    assert not updates.ready_matches(state, ready, process_matches=True,
                                     relay_matches=True, now=stamp(130))
    with pytest.raises(ValueError, match="readiness is unproven"):
        updates.confirm_transition(state, ready, process_matches=True,
                                   relay_matches=True, now=stamp(130))
    assert json.dumps(state, sort_keys=True) == before
    assert state["failed_shas"] == [NEW]


def test_current_schema_retention_loses_original_failure_reason(scene, monkeypatch):
    s = scene
    timeout = _actual_retained_failure(s, monkeypatch, "candidate startup failed or readiness timed out")
    other = _actual_retained_failure(s, monkeypatch, "a separately classified startup failure")
    assert timeout == other
    assert timeout["reason"] == "TRIAL_GENERATION_UNKNOWN"
    assert timeout["failed_shas"] == [NEW]


@pytest.mark.parametrize("interrupt_after_claim", [False, True])
def test_interrupted_system_claim_cannot_partially_confirm_retained_state(scene, monkeypatch, interrupt_after_claim):
    s = scene
    s.clock[0] = 130
    state = _actual_retained_failure(s, monkeypatch, "candidate startup failed or readiness timed out")
    s.write(s.control / "transition.json", state)
    before = (s.control / "transition.json").read_bytes()
    write = updates.write_json_durable

    def interrupted(path, value):
        if path.name == "apply-claim.json":
            if interrupt_after_claim:
                write(path, value)
            raise OSError("injected claim interruption")
        write(path, value)

    monkeypatch.setattr(updates, "write_json_durable", interrupted)
    with pytest.raises(OSError, match="injected claim interruption"):
        updates._apply_prepared_once(s.control)
    assert (s.control / "transition.json").read_bytes() == before
    assert updates.read_json(s.control / "transition.json")["failed_shas"] == [NEW]
    assert (s.control / "apply-claim.json").exists() is interrupt_after_claim


@pytest.mark.parametrize("other_live_identity", [False, True])
def test_system_repeated_late_receipt_keeps_retained_journal_and_audit_unchanged(scene, monkeypatch, other_live_identity):
    s = scene
    s.clock[0] = 130
    state = _actual_retained_failure(s, monkeypatch, "candidate startup failed or readiness timed out")
    state = {**state, "trial_pid": 101, "trial_sha": NEW, "trial_started_at": stamp(125)}
    s.write(s.control / "transition.json", state)
    gui = {**s.relay(), "pid": 999 if other_live_identity else 101, "role": "gui"}
    s.rows[:] = [gui, s.relay()]
    s.write(s.stage / "ready.json", {"pid": 101, "sha": NEW, "nonce": state["nonce"],
        "transition_id": state["transition_id"], "ready_at": stamp(129),
        **{check: True for check in updates.READY_CHECKS}})
    before = (s.control / "transition.json").read_bytes()
    audit = []
    monkeypatch.setattr(updates, "record_confirmed_policy", lambda *a: audit.append(a))
    for _ in range(2):
        assert updates._apply_prepared_once(s.control) == 0
        assert (s.control / "transition.json").read_bytes() == before
    assert audit == []
    assert s.launches == []
    assert len([row for row in s.rows if row["role"] == "relay"]) == 1
    assert s.rows[0]["pid"] == gui["pid"]
