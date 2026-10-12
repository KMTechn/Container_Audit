"""Real scan invalidation must fence outside work, not abandon its own PIN chain."""
import hashlib
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import container_admin_pin as pin
from product_exchange import ProductExchangeSession
from tests.test_admin_pin_move_timing import _business_case
from tests.test_admin_pin_ui_lane import PinRoot, recovery, settle
from tk_serial_ui_lane import Admission

pytestmark = pytest.mark.usefixtures("owned_tk_workers")


def real_invalidation(app):
    import Container_Audit as module
    app._scan_callback_epoch = 0
    app._invalidate_pending_scan_callbacks = module.ContainerAudit._invalidate_pending_scan_callbacks.__get__(app)
    app._set_scan_callback_pending = lambda value: None
    app._cancel_master_preflight = lambda: None


def prepare_close(app, root):
    closed = []
    app._scan_callback_pending = False
    app._preflight_hold_writer_instance = None
    app._central_transport_lane = None
    app.master_label_replace_state = None
    # 48c5f9f: the close path reads the whole idle exchange session (current_step).
    app.current_exchange_session = ProductExchangeSession()
    app._refuse_scans_behind_save = lambda message: ""
    app._preserve_preflight_hold_for_close = lambda: (True, False)
    app._operator_review_blocks_mutation = lambda: False
    app._save_current_tray_state = lambda: True
    app._end_work_session = lambda **kwargs: True

    def finalize():
        lane = app._ui_lane
        assert lane.state == "CLOSED" and not lane.worker_thread.is_alive()
        closed.append(True)
        root.destroy()
    app._finalize_application_close = finalize
    return closed


@pytest.fixture
def triplet(monkeypatch, tmp_path):
    import Container_Audit as module
    app, server, audits, original, label, invoke = _business_case(
        monkeypatch, tmp_path, "CA.TRAY_HOLD")
    assert invoke()
    first = app._admin_pin_store().list_pending()[0]
    prepared = app._admin_pin_store().write(dict(
        first, state="PREPARED", verification_id="", moving=[],
        operation_key="ffffffff-ffff-4fff-8fff-fffffffffffd",
        request_id="ffffffff-ffff-4fff-8fff-fffffffffffd"))
    snapshot = dict(first["source_snapshot"])
    other = Path(app.save_folder) / "other-original.json"
    other.write_text(json.dumps(snapshot["tray"], ensure_ascii=False), encoding="utf-8")
    snapshot.update(source_file=other.name,
                    current_sha256=hashlib.sha256(other.read_bytes()).hexdigest())
    verified = app._admin_pin_store().write(dict(
        first, state="VERIFIED", source_snapshot=snapshot,
        source_evidence_sha256=pin.fingerprint(snapshot),
        target=dict(first["target"], state_fingerprint=pin.fingerprint(snapshot)),
        moving=[], operation_key="ffffffff-ffff-4fff-8fff-fffffffffffe",
        request_id="ffffffff-ffff-4fff-8fff-fffffffffffe"))
    assert app._admin_pin_store().list_pending()[0]["operation_key"] == first["operation_key"]
    assert app._admin_pin_target_missing(prepared)
    assert not app._admin_pin_target_missing(verified)
    server.consumed = False
    server.calls.clear()
    audits.clear()
    root = PinRoot()
    app.root = root
    real_invalidation(app)
    ui = []

    def present(*args, **kwargs):
        assert threading.get_ident() == root.owner_thread_id
        assert not root.destroyed
        ui.append(args)
        return True
    for name in ["showinfo", "showwarning", "showerror", "askyesno"]:
        monkeypatch.setattr(module.messagebox, name, present)
    for name in ["_update_parked_trays_list", "_reset_ui_to_waiting_state",
                 "_update_all_summaries", "_render_warning_state", "_update_action_button_states"]:
        setattr(app, name, present)
    return SimpleNamespace(app=app, server=server, audits=audits, root=root, ui=ui,
                           intents=[first, prepared, verified], tmp_path=tmp_path)


def finish_recheck(case):
    if getattr(case.app, "_admin_pin_ui_pending", False):
        case.root.run_until(lambda: not case.app._admin_pin_ui_pending)


def assert_triplet(case):
    states = [case.app._admin_pin_store().read(item["operation_key"])["state"]
              for item in case.intents]
    (case.tmp_path / "generation-readback.json").write_text(json.dumps({
        "states": states, "epoch": case.app._scan_callback_epoch,
        "handoff_audits": case.audits.count("ADMIN_PIN_HANDOFF_UNKNOWN"),
        "superseded_audits": case.audits.count("ADMIN_PIN_SUPERSEDED"),
        "status_requests": sum(path.endswith("/status") for path, _ in case.server.calls),
    }, indent=2), encoding="utf-8")
    assert states == ["APPLIED", "HANDED_OFF_UNKNOWN", "SUPERSEDED"]
    assert case.audits.count("ADMIN_PIN_HANDOFF_UNKNOWN") == 1
    assert case.audits.count("ADMIN_PIN_SUPERSEDED") == 1
    assert len(case.server.calls) == 1 and case.server.calls[0][0].endswith("/status")


def test_real_invalidation_finishes_three_intents_in_one_press(triplet):
    triplet.app._recheck_admin_pin_intents()
    finish_recheck(triplet)
    assert triplet.app._scan_callback_epoch == 1
    assert_triplet(triplet)


def test_worker_unverified_detachment_continues_after_its_real_invalidation(monkeypatch, tmp_path):
    import Container_Audit as module
    def offline(*args):
        raise TimeoutError("injected unavailable response")
    app, server, audits, original, label, invoke = _business_case(
        monkeypatch, tmp_path, "CA.TRAY_HOLD", transport=offline)
    rename = Path.rename
    with monkeypatch.context() as interrupted:
        def stop_before_move(path, target):
            if path == original:
                raise KeyboardInterrupt("injected interrupted detachment")
            return rename(path, target)
        interrupted.setattr(Path, "rename", stop_before_move)
        with pytest.raises(KeyboardInterrupt):
            invoke()
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "UNVERIFIED_DETACHING"
    app.root = PinRoot()
    real_invalidation(app)
    for name in ["showinfo", "showwarning", "showerror", "askyesno"]:
        monkeypatch.setattr(module.messagebox, name, lambda *args, **kwargs: True)
    app._recheck_admin_pin_intents()
    finish_recheck(SimpleNamespace(app=app, root=app.root))
    assert app._scan_callback_epoch == 1
    assert app._admin_pin_store().read(intent["operation_key"])["state"] == "HANDED_OFF_UNKNOWN"
    assert audits.count("ADMIN_PIN_UNVERIFIED_HOLD") == 1
    assert audits.count("ADMIN_PIN_HANDOFF_UNKNOWN") == 1
    assert not original.exists()


def test_hold_chain_uses_real_invalidation_and_finishes(monkeypatch, tmp_path):
    app, server, audits, original, label, invoke = _business_case(
        monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    app.root = PinRoot()
    real_invalidation(app)
    redeem = app._admin_pin_client.redeem
    def invalidate_after_redeem(**request):
        result = redeem(**request)
        bridge = getattr(app, "_call_admin_pin_ui", None)
        if bridge is None:
            app._invalidate_pending_scan_callbacks()
        else:
            bridge(app._invalidate_pending_scan_callbacks)
        return result
    monkeypatch.setattr(app._admin_pin_client, "redeem", invalidate_after_redeem)
    app._quarantine_preflight_hold_from_operations()
    finish_recheck(SimpleNamespace(app=app, root=app.root))
    assert app._scan_callback_epoch == 1
    assert app._admin_pin_store().list_pending()[0]["state"] == "APPLIED"
    assert audits.count("ADMIN_PIN_APPLIED") == 1
    assert [path.rsplit("/", 1)[-1] for path, _ in server.calls] == [
        "verifications", "redemptions"]


def test_outside_invalidation_discards_and_next_press_recovers(triplet, monkeypatch):
    case = triplet
    entered, release = threading.Event(), threading.Event()
    complete = case.app._admin_pin_complete
    def blocked(*args):
        value = complete(*args)
        entered.set()
        release.wait()
        return value
    monkeypatch.setattr(case.app, "_admin_pin_complete", blocked)
    try:
        case.app._recheck_admin_pin_intents()
        case.root.run_until(entered.is_set)
        case.app._invalidate_pending_scan_callbacks()
        release.set()
        finish_recheck(case)
        assert not case.app._admin_pin_ui_pending
        assert not case.server.calls and not case.audits
        assert case.app._admin_pin_store().read(case.intents[1]["operation_key"])["state"] == "PREPARED"
        monkeypatch.setattr(case.app, "_admin_pin_complete", complete)
        case.app._recheck_admin_pin_intents()
        finish_recheck(case)
        assert_triplet(case)
    finally:
        release.set()


@pytest.mark.parametrize("error_result", [False, True])
def test_resume_delivers_unsent_value_or_error_once(triplet, error_result):
    app, root = triplet.app, triplet.root
    result = object()
    error = OSError("injected operation error")
    calls, received = [], []
    def operation():
        calls.append("operation")
        if error_result:
            raise error
        return result
    def steps():
        yield lambda: calls.append("first")
        app._call_admin_pin_ui(app._invalidate_pending_scan_callbacks)
        try:
            received.append((yield operation))
        except OSError as caught:
            received.append(caught)
        yield lambda: calls.append("tail")
    assert app._submit_admin_pin_steps(steps(), "admin-pin-result")
    root.run_until(lambda: not app._admin_pin_ui_pending)
    assert received == [error if error_result else result]
    assert calls == ["first", "operation", "tail"]
    assert app._scan_callback_epoch == 1


@pytest.mark.parametrize("outside", [False, True])
def test_delayed_readmission_checks_identity_and_generation(triplet, monkeypatch, outside):
    case = triplet
    lane = case.app._ui_task_lane()
    submissions = []
    submit = lane.submit
    def counted(task):
        submissions.append(task.generation)
        return submit(task)
    monkeypatch.setattr(lane, "submit", counted)
    case.app._recheck_admin_pin_intents()
    case.root.run_until(lambda: case.app._admin_pin_ui_request["job"] is not None)
    request = case.app._admin_pin_ui_request
    assert case.app._admin_pin_ui_pending and submissions == [0]
    if outside:
        case.app._invalidate_pending_scan_callbacks()
        finish_recheck(case)
        assert submissions == [0]
        assert not case.server.calls
    else:
        case.app._admin_pin_ui_request = object()
        case.root.run_until(lambda: request["job"] is None)
        assert submissions == [0]
        assert case.app._admin_pin_ui_pending  # An old callback cannot clear another request.
        case.app._admin_pin_ui_request = request
        case.app._admin_pin_task_epoch = -1
        assert request["steps"].gi_frame is None
        case.app._admin_pin_ui_pending = False


@pytest.mark.parametrize("closing", [False, True])
def test_duplicate_or_close_in_continuation_keeps_one_request(triplet, monkeypatch, closing):
    case = triplet
    closed = prepare_close(case.app, case.root) if closing else []
    after = case.root.after
    resumed = []
    shown = []
    entered, release = threading.Event(), threading.Event()
    status = case.app._admin_pin_client.status
    def blocked_status(*args):
        entered.set()
        release.wait()
        return status(*args)
    if closing:
        monkeypatch.setattr(case.app._admin_pin_client, "status", blocked_status)
    def intercept(delay, callback, *args):
        if callback.__name__ == "resume":
            def before_resume():
                assert case.app._admin_pin_ui_pending
                count = len(case.server.calls)
                if not closing:
                    case.app._recheck_admin_pin_intents()
                assert len(case.server.calls) == count
                resumed.append(True)
                callback(*args)
            return after(delay, before_resume)
        return after(delay, callback, *args)
    monkeypatch.setattr(case.root, "after", intercept)
    try:
        case.app._recheck_admin_pin_intents()
        if closing:
            case.root.run_until(entered.is_set)
            case.app.on_closing(_confirmed=True)
            case.app.on_closing(_confirmed=True)
            assert case.app._ui_lane.state == "BUSY"
            shown.append(len(case.ui))
            release.set()
        finish_recheck(case)
        assert resumed == [True]
        assert_triplet(case)
        if closing:
            case.root.run_until(lambda: closed)
            assert closed == [True] and case.root.destroyed
            assert len(case.ui) == shown[0]
    finally:
        release.set()


def test_readmission_rejection_closes_generator_and_releases_pending(triplet, monkeypatch):
    case = triplet
    lane = case.app._ui_task_lane()
    submit = lane.submit
    attempts = []
    def reject_resume(task):
        attempts.append(task)
        return submit(task) if len(attempts) == 1 else Admission(False, reason="busy")
    monkeypatch.setattr(lane, "submit", reject_resume)
    case.app._recheck_admin_pin_intents()
    request = case.app._admin_pin_ui_request
    finish_recheck(case)
    assert len(attempts) == 2
    assert request["steps"].gi_frame is None
    assert case.app._admin_pin_ui_request is None
    assert not case.server.calls
    assert any(pin.operator_message("VERIFY_UNAVAILABLE") in str(args) for args in case.ui)


def test_close_during_unanswered_request_uses_existing_timeout_and_finalizes_once(recovery):
    import Container_Audit as module
    case = recovery
    real_invalidation(case.app)
    closed = prepare_close(case.app, case.root)
    case.app._preserve_preflight_hold_for_close = module.ContainerAudit._preserve_preflight_hold_for_close.__get__(case.app)
    entered = threading.Event()
    never_released = threading.Event()
    timeouts = []
    def unanswered(*args, **kwargs):
        timeouts.append(kwargs["timeout"])
        entered.set()
        assert not never_released.wait(kwargs["timeout"])
        raise requests.Timeout("injected unanswered request")
    case.app._admin_pin_client.transport = None
    case.app._admin_pin_client.session = SimpleNamespace(post=unanswered)
    case.app._quarantine_preflight_hold_from_operations()
    case.root.run_until(entered.is_set)
    started = time.monotonic()
    case.app.on_closing(_confirmed=True)
    shown = len(case.ui)
    assert case.app._admin_pin_ui_pending and case.app._ui_lane.state == "BUSY"
    case.root.run_until(lambda: closed, timeout=timeouts[0] + 2)
    assert time.monotonic() - started >= timeouts[0] - 1
    assert timeouts == [10]  # The unchanged production request bound; no new app constant.
    assert not never_released.is_set()
    assert closed == [True]
    assert not case.app._admin_pin_ui_pending
    assert len(case.ui) == shown
    intent = case.app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "UNKNOWN"
    assert case.original.exists()
    assert case.audits.count("ADMIN_PIN_UNVERIFIED") == 1
    assert case.audits.count("PHS2_PREFLIGHT_HOLD_CLOSE_HANDOFF") == 1


@pytest.mark.parametrize("exit_kind", ["normal", "exception", "stale", "rejected"])
def test_every_terminal_exit_resumes_deferred_close(triplet, monkeypatch, exit_kind):
    case = triplet
    closed = prepare_close(case.app, case.root)
    entered, release = threading.Event(), threading.Event()
    finished = []
    lane = case.app._ui_task_lane()
    submit = lane.submit
    submissions = []
    def admission(task):
        submissions.append(task)
        if exit_kind == "rejected" and len(submissions) > 1:
            return Admission(False, reason="closing")
        return submit(task)
    monkeypatch.setattr(lane, "submit", admission)
    def operation():
        entered.set()
        release.wait()
        if exit_kind == "exception":
            raise OSError("injected terminal operation error")
        return True
    def steps():
        yield lambda: None
        case.app._call_admin_pin_ui(case.app._invalidate_pending_scan_callbacks)
        value = yield operation
        assert value is True
        yield lambda: finished.append(True)
    generator = steps()
    try:
        case.app._submit_admin_pin_steps(generator, "admin-pin-close-exit")
        case.root.run_until(entered.is_set)
        case.app.on_closing(_confirmed=True)
        shown = len(case.ui)
        if exit_kind == "stale":
            case.app._invalidate_pending_scan_callbacks()
        release.set()
        case.root.run_until(lambda: closed)
        assert closed == [True]
        assert not case.app._admin_pin_ui_pending
        assert case.app._admin_pin_ui_request is None
        assert generator.gi_frame is None
        assert len(case.ui) == shown
        assert finished == ([True] if exit_kind == "normal" else [])
    finally:
        release.set()


def test_close_requested_inside_cancelled_prompt_is_resumed(recovery):
    case = recovery
    closed = prepare_close(case.app, case.root)
    def cancelled_prompt(**request):
        case.app.on_closing(_confirmed=True)
        return None
    case.app._prompt_blocked_work_admin_pin = cancelled_prompt
    case.app._quarantine_preflight_hold_from_operations()
    assert not case.app._admin_pin_ui_pending
    case.root.run_until(lambda: closed)
    assert closed == [True]
    assert not case.server.calls and not case.writes
    assert case.original.exists()


def test_outside_change_before_own_invalidation_cannot_extend_ownership(triplet):
    case = triplet
    reached = []
    def steps():
        yield lambda: None
        case.app._invalidate_pending_scan_callbacks()  # External Tk change first.
        case.app._call_admin_pin_ui(case.app._invalidate_pending_scan_callbacks)
        assert case.app._admin_pin_task_epoch == 0
        yield lambda: None
        reached.append(True)
    case.app._submit_admin_pin_steps(steps(), "admin-pin-outside-before-own")
    finish_recheck(case)
    assert reached == []
    assert case.app._scan_callback_epoch == 2


def test_closed_window_during_deferred_continuation_preserves_active_durable_tail(triplet):
    case = triplet
    durable = []
    def steps():
        yield lambda: None
        case.app._call_admin_pin_ui(case.app._invalidate_pending_scan_callbacks)
        yield lambda: durable.append("first") or True
        case.app._call_admin_pin_ui(case.app._update_parked_trays_list)
        yield lambda: durable.append("tail")
    case.app._submit_admin_pin_steps(steps(), "admin-pin-closed-tail")
    case.root.run_until(lambda: case.app._admin_pin_ui_request["job"] is not None)
    shown = len(case.ui)
    case.root.destroy()
    finish_recheck(case)
    assert durable == ["first", "tail"]
    assert len(case.ui) == shown


def test_worker_invalidation_error_after_epoch_change_is_delivered_once(triplet):
    case = triplet
    error = OSError("injected scan callback cleanup error")
    received = []
    def failed_cleanup(value):
        raise error
    case.app._set_scan_callback_pending = failed_cleanup
    def steps():
        try:
            yield lambda: case.app._call_admin_pin_ui(case.app._invalidate_pending_scan_callbacks)
        except OSError as caught:
            received.append(caught)
        yield lambda: True
    case.app._submit_admin_pin_steps(steps(), "admin-pin-invalidation-error")
    finish_recheck(case)
    assert received == [error]
    assert case.app._scan_callback_epoch == 1


def test_deferred_callback_failure_still_closes_and_resumes_shutdown(triplet, monkeypatch):
    case = triplet
    closed = prepare_close(case.app, case.root)
    entered, release = threading.Event(), threading.Event()
    after = case.root.after
    def failed_after(delay, callback, *args):
        if delay == 0:
            raise RuntimeError("injected deferred callback failure")
        return after(delay, callback, *args)
    monkeypatch.setattr(case.root, "after", failed_after)
    def work():
        entered.set()
        release.wait()
        return True
    def steps():
        yield lambda: None
        case.app._call_admin_pin_ui(case.app._invalidate_pending_scan_callbacks)
        yield work
        pytest.fail("rejected continuation must not advance")
    generator = steps()
    try:
        case.app._submit_admin_pin_steps(generator, "admin-pin-defer-error")
        case.root.run_until(entered.is_set)
        case.app.on_closing(_confirmed=True)
        shown = len(case.ui)
        release.set()
        case.root.run_until(lambda: closed)
        assert closed == [True]
        assert not case.app._admin_pin_ui_pending
        assert generator.gi_frame is None
        assert len(case.ui) == shown
    finally:
        release.set()
