from types import MethodType, SimpleNamespace

import pytest

import Container_Audit as module
from Container_Audit import ContainerAudit
from preflight_scan_hold import PreflightScanHoldStore
from tests.test_container_p0_contracts import _startup_transfer_recovery_app


@pytest.mark.parametrize("actor,bound", [("", True), ("other-worker", False)])
def test_unbound_actor_cannot_send_held_startup_work(tmp_path, actor, bound):
    app, root, lane, hold, seals, _members, calls = _startup_transfer_recovery_app(
        tmp_path, seal_intent_ids=("seal-1",), hold_active=True
    )
    app.worker_name = actor
    app._work_session_identity_bound = bound
    original = hold.path.read_bytes()
    try:
        assert app._preflight_context_blocks_mutation() is True
        assert app._schedule_startup_transfer_recovery() is True
        root.run_until(lambda: app._startup_transfer_recovery_waiting_for_hold and not lane.is_busy())
        app._run_background_seal_retry()
        root.run_until(lambda: not lane.is_busy())
        assert calls["seal"] == []
        assert seals.intent_ids == ["seal-1"]
        assert hold.path.read_bytes() == original
    finally:
        lane.close_idle()
        root.run_until(lambda: lane.state == "CLOSED")


def test_unbound_actor_blocks_another_workers_named_hold_slot(tmp_path):
    app, root, lane, hold, _seals, _members, _calls = _startup_transfer_recovery_app(tmp_path)
    slot = PreflightScanHoldStore(hold.path.with_name(hold.path.stem + "_other.json"), capacity=hold.capacity)
    slot.start(worker="other-worker", master_raw="MASTER", scan_epoch=1)
    app.worker_name = ""
    app._work_session_identity_bound = False
    try:
        assert app._preflight_context_blocks_mutation() is True
    finally:
        lane.close_idle()
        root.run_until(lambda: lane.state == "CLOSED")


def test_bound_worker_keeps_other_workers_original_hold_slot(tmp_path):
    app, root, lane, hold, _seals, _members, calls = _startup_transfer_recovery_app(
        tmp_path, seal_intent_ids=("seal-1",), hold_active=True
    )
    app.worker_name = "other-worker"
    app._work_session_identity_bound = True
    original = hold.path.read_bytes()
    try:
        assert app._preflight_context_blocks_mutation() is False
        assert app._schedule_startup_transfer_recovery() is True
        root.run_until(lambda: not lane.is_busy() and not app._startup_transfer_recovery_inflight)
        assert len(calls["seal"]) == 1
        assert hold.path.read_bytes() == original
    finally:
        lane.close_idle()
        root.run_until(lambda: lane.state == "CLOSED")


def test_actual_session_start_save_failure_does_not_admit_held_work(tmp_path, monkeypatch):
    app, root, lane, hold, seals, _members, calls = _startup_transfer_recovery_app(
        tmp_path, seal_intent_ids=("seal-1",), hold_active=True
    )
    app.worker_name = ""
    app.worker_entry = SimpleNamespace(get=lambda: "other-worker")
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._work_session_state_path = lambda: tmp_path / "session.json"
    app._audit_event_contract = lambda **kwargs: {"event_type": kwargs["event_type"]}
    saves = []
    app._save_work_session_state = lambda state: saves.append(state["phase"]) or False
    app._restore_preflight_scan_hold = lambda: True
    app.show_worker_input_screen = lambda: None
    monkeypatch.setattr(module.messagebox, "showerror", lambda *args, **kwargs: None)
    original = hold.path.read_bytes()
    try:
        app.start_work()
        assert saves
        assert app.worker_name == ""
        assert app._work_session_identity_bound is False
        app._run_background_seal_retry()
        root.run_until(lambda: not lane.is_busy() and not app._startup_transfer_recovery_inflight)
        assert calls["seal"] == []
        assert seals.intent_ids == ["seal-1"]
        assert hold.path.read_bytes() == original
    finally:
        lane.close_idle()
        root.run_until(lambda: lane.state == "CLOSED")
