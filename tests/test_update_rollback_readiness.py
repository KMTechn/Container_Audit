"""Rollback completion requires a fresh, ordinary, process-bound relay READY."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
import threading
import time

import pytest
import auto_update as update

OLD, NEW = "1" * 40, "2" * 40
NOW = "2026-10-16T00:00:00Z"
SID = "S-1-5-21-11-22-33-1001"


def recovery_fixture(tmp_path, monkeypatch, defect=None):
    control = tmp_path / "managed/update-control"
    control.mkdir(parents=True)
    stage = tmp_path / "stage"
    stage.mkdir()
    policy = {"operator_sid": SID, "operator_local_app_data": str(tmp_path / "operator"),
              "staging_root": str(stage)}
    update.write_json_durable(control / "policy.json", policy)
    state = update.rollback_transition({
        "schema": update.SCHEMA, "phase": "ROLLBACK_PENDING", "previous_sha": OLD,
        "candidate_sha": NEW, "failed_shas": [NEW], "transition_id": "d" * 32,
        "nonce": "a" * 32, "applied_at": "2026-10-15T23:59:00Z",
        "failure_decision": {"selected_sha": OLD}, "confirmed_at": "2026-10-15T23:00:00Z",
    }, writers_absent=True, previous_verified=True, durable_rollback=True,
       nonce="b" * 32, now=NOW)
    update.persist_switch(control, state, OLD)
    business = tmp_path / "business.bin"
    business.write_bytes(b"ledger membership quantity queue and pending work preserved")
    rows = [dict(pid=pid, observable=True, sha=OLD, sid=SID, role=role,
                 ordinary_user=True, created_at=NOW) for pid, role in ((44, "gui"), (45, "relay"))]
    claim = {"pid": 44, "nonce": state["nonce"], "transition_id": state["transition_id"]}
    receipt = {**{check: True for check in update.READY_CHECKS}, **claim, "sha": OLD, "ready_at": NOW}
    if defect == "stale_nonce":
        receipt["nonce"] = "a" * 32
    elif defect == "foreign_transition":
        receipt["transition_id"] = "e" * 32
    elif defect == "candidate_sha":
        receipt["sha"] = NEW
    elif defect == "elevated_relay":
        rows[1]["ordinary_user"] = False
    elif defect == "foreign_sid":
        rows[1]["sid"] = "S-1-5-32-544"
    elif defect == "stale_relay":
        rows[1]["created_at"] = "2026-10-15T23:59:59Z"
    elif defect == "unobservable_relay":
        rows[1]["observable"] = False
    elif defect == "missing_relay":
        rows.pop()
    elif defect == "duplicate_relay":
        rows.append({**rows[1], "pid": 46})
    elif defect == "wrong_process_sha":
        rows[1]["sha"] = NEW
    elif defect == "stale_receipt":
        receipt["ready_at"] = "2026-10-15T23:59:59Z"
    elif defect == "future_receipt":
        receipt["ready_at"] = "2026-10-16T00:00:01Z"
    elif defect == "incomplete_receipt":
        receipt[update.READY_CHECKS[0]] = False
    elif defect == "foreign_claim":
        claim["transition_id"] = "e" * 32
    elif defect == "missing_process":
        rows.clear()
    elif defect == "malformed_process_time":
        rows[1]["created_at"] = "invalid"
    update.write_json_durable(stage / "trial.json", claim)
    if defect != "no_ready":
        update.write_json_durable(stage / "ready.json", receipt)
    monkeypatch.setattr(update, "update_lock", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(update, "fixed_helper", lambda *args, **kwargs: "")
    monkeypatch.setattr(update, "new_apply_claim", lambda: {})
    monkeypatch.setattr(update, "complete_apply_claim", lambda *args: None)
    monkeypatch.setattr(update, "process_snapshot", lambda *args: rows)
    monkeypatch.setattr(update, "now_utc", lambda: NOW)
    monkeypatch.setattr(time, "sleep", lambda *args: None)
    ticks = iter(range(0, 100000, 10))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    return control, policy, state, business


@pytest.mark.parametrize("defect", ["no_ready", "stale_nonce", "foreign_transition", "candidate_sha",
    "elevated_relay", "foreign_sid", "stale_relay", "unobservable_relay", "missing_relay",
    "duplicate_relay", "wrong_process_sha", "stale_receipt", "future_receipt", "incomplete_receipt",
    "foreign_claim", "missing_process", "malformed_process_time"])
def test_actual_apply_never_completes_unproven_rollback(tmp_path, monkeypatch, defect):
    control, policy, state, business = recovery_fixture(tmp_path, monkeypatch, defect)
    assert state["phase"] == "ROLLBACK_PENDING_READY"
    assert "confirmed_at" not in state
    before = business.read_bytes(), (control / "policy.json").read_bytes()
    assert update.apply_prepared(control) == 20
    result = update.read_json(control / "transition.json")
    assert result["phase"] == "FAILED"
    assert "confirmed_at" not in result
    assert result["failed_shas"] == [NEW]
    assert result["nonce"] == state["nonce"]
    assert update.read_json(control / "active.json")["sha"] == OLD
    assert (business.read_bytes(), (control / "policy.json").read_bytes()) == before


@pytest.mark.parametrize("interrupted_pointer", [False, True])
def test_actual_apply_resumes_same_recovery_and_confirms_only_after_ready(tmp_path, monkeypatch, interrupted_pointer):
    control, policy, state, business = recovery_fixture(tmp_path, monkeypatch)
    assert state["phase"] == "ROLLBACK_PENDING_READY"
    if interrupted_pointer:
        update.write_json_durable(control / "active.json", {"schema": update.SCHEMA, "sha": NEW})
        # No writers exist while the durable pointer publication is repaired.
        real_snapshot = update.process_snapshot
        monkeypatch.setattr(update, "process_snapshot", lambda *args:
                            [] if update.read_json(control / "active.json")["sha"] == NEW else real_snapshot(*args))
    before = business.read_bytes(), (control / "policy.json").read_bytes()
    assert update.apply_prepared(control) == 0
    result = update.read_json(control / "transition.json")
    assert result["phase"] == "ROLLED_BACK"
    assert result["confirmed_at"] == NOW
    assert result["nonce"] == state["nonce"]
    assert result["rollback_at"] == state["rollback_at"]
    assert result["failed_shas"] == [NEW]
    assert update.read_json(control / "active.json")["sha"] == OLD
    assert (business.read_bytes(), (control / "policy.json").read_bytes()) == before


def test_restart_does_not_renew_expired_rollback_window(tmp_path, monkeypatch):
    control, policy, state, business = recovery_fixture(tmp_path, monkeypatch)
    assert state["phase"] == "ROLLBACK_PENDING_READY"
    monkeypatch.setattr(update, "now_utc", lambda: "2026-10-16T00:02:01Z")
    monkeypatch.setattr(update, "process_snapshot", lambda *args: pytest.fail("expired READY window observed processes"))
    assert update.apply_prepared(control) == 20
    result = update.read_json(control / "transition.json")
    assert result["phase"] == "FAILED"
    assert "confirmed_at" not in result
    assert result["rollback_at"] == state["rollback_at"]


def test_two_supervisors_publish_rollback_completion_once(tmp_path, monkeypatch):
    control, policy, state, business = recovery_fixture(tmp_path, monkeypatch)
    assert state["phase"] == "ROLLBACK_PENDING_READY"
    lock = threading.Lock()
    monkeypatch.setattr(update, "update_lock", lambda *args, **kwargs: lock)
    # A constant test clock keeps scheduling from consuming the recovery budget.
    monkeypatch.setattr(time, "monotonic", lambda: 1.0)
    original = update.write_json_durable
    completed = []
    def write(path, payload):
        if path.name == "transition.json" and payload.get("phase") == "ROLLED_BACK":
            completed.append(payload)
        return original(path, payload)
    monkeypatch.setattr(update, "write_json_durable", write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(update.wait_for_rollback_ready, control, policy) for _ in range(2)]
        assert [f.result() for f in futures] == [0, 0]
    assert len(completed) == 1
    assert update.read_json(control / "transition.json")["phase"] == "ROLLED_BACK"
