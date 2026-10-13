"""Administrator recovery keeps HTTP/durable work off the Tk owner."""

import hashlib
import threading
import uuid
from types import SimpleNamespace

import pytest

import container_admin_pin as pin
from tests.test_admin_pin_move_timing import _business_case
from tests.test_container_admin_pin import make_client
from tests.test_tk_serial_ui_lane import FakeTkRoot


class PinRoot(FakeTkRoot):
    tk = True

    def winfo_exists(self):
        assert threading.get_ident() == self.owner_thread_id
        return not self.destroyed


@pytest.fixture
def recovery(monkeypatch, tmp_path):
    import Container_Audit as module

    app, server, audits, original, label, invoke = _business_case(
        monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    hold = app._preflight_hold_store()
    hold.mark_failed(error_code="PHS2_PREFLIGHT_LOCAL_ERROR")
    app._preflight_hold_snapshot = hold.load()
    root = PinRoot()
    app.root = root
    ui = []

    def present(kind):
        def callback(*args, **kwargs):
            assert threading.get_ident() == root.owner_thread_id
            assert not root.destroyed
            ui.append((kind, args))
            return True
        return callback

    for name in ("showinfo", "showwarning", "showerror", "askyesno"):
        monkeypatch.setattr(module.messagebox, name, present(name))
    credentials = app._prompt_blocked_work_admin_pin

    def prompt(**request):
        present("pin")()
        assert not server.calls  # Human input precedes the first HTTP.
        return credentials(**request)

    app._prompt_blocked_work_admin_pin = prompt
    for name in ("_update_parked_trays_list", "_schedule_startup_transfer_recovery",
                 "_reset_ui_to_waiting_state", "_update_all_summaries",
                 "_render_warning_state", "_update_action_button_states",
                 "show_status_message"):
        setattr(app, name, present(name))
    app.scan_entry = SimpleNamespace(configure=present("entry"))
    entered, release = threading.Event(), threading.Event()
    transport_threads = []

    def transport(path, body, headers):
        transport_threads.append(threading.get_ident())
        assert threading.get_ident() != root.owner_thread_id
        entered.set()
        release.wait()
        return server(path, body, headers)

    app._admin_pin_client = make_client(monkeypatch, transport)
    writes = []
    real_write = pin.AdminPinIntentStore.write

    def write(store, intent):
        writes.append(threading.get_ident())
        return real_write(store, intent)

    monkeypatch.setattr(pin.AdminPinIntentStore, "write", write)
    try:
        yield SimpleNamespace(app=app, server=server, audits=audits, original=original,
                              label=label, hold=hold, root=root, ui=ui, entered=entered,
                              release=release, writes=writes, transport=transport,
                              transport_threads=transport_threads, credentials=credentials)
    finally:
        release.set()


def settle(case, *, expect_writes=True):
    case.root.run_until(lambda: not getattr(case.app, "_admin_pin_ui_pending", False))
    assert not case.app._ui_lane.is_busy()
    if expect_writes:
        assert case.writes
        assert set(case.writes) == {case.app._ui_lane.worker_thread_id}
    else:
        assert not case.writes


def seed_recheck(case, state="PREPARED"):
    from Container_Audit import canonical_master_label_key

    snapshot = case.hold.load()
    source = {"preflight_id": snapshot.preflight_id, "state": snapshot.state,
              "items": len(snapshot.items), "hold_sha256": hashlib.sha256(
                  case.original.read_bytes()).hexdigest(), "current_sha256": ""}
    intent = case.app._admin_pin_store().write({
        "schema": "container-admin-pin-intent-v1", "state": state,
        "operation_key": str(uuid.uuid4()), "request_id": str(uuid.uuid4()),
        "verification_id": "" if state == "PREPARED" else case.server.verification_id,
        "admin_id": "manager-1", "action": "CA.PRECHECK_HOLD",
        "target": {"kind": "precheck_hold", "id": hashlib.sha256(
            canonical_master_label_key(case.label).encode()).hexdigest(),
            "state_fingerprint": pin.fingerprint(source)},
        "operator": {"local_id": pin.operator_local_id(case.app.worker_name),
                     "login_epoch": case.app._admin_pin_login_epoch},
        "operator_raw": case.app.worker_name, "source_evidence_sha256": pin.fingerprint(source),
        "source_snapshot": source, "labels": [case.label], "reason": "",
    })
    case.writes.clear()
    return intent


@pytest.mark.parametrize("action", ("recheck", "hold"))
@pytest.mark.parametrize("closed", (False, True))
def test_pin_http_allows_after_duplicate_is_single_and_closed_window_keeps_durability(
        recovery, action, closed):
    case = recovery
    if action == "recheck":
        intent = seed_recheck(case)
        invoke = case.app._recheck_admin_pin_intents
    else:
        invoke = case.app._quarantine_preflight_hold_from_operations
    invoke()
    case.root.run_until(lambda: case.transport_threads)
    assert case.root.owner_thread_id not in case.transport_threads
    case.root.run_until(case.entered.is_set)
    assert case.app._admin_pin_ui_pending
    heartbeat = []
    case.root.after(0, lambda: heartbeat.append(True))
    case.root.run_until(lambda: heartbeat)
    invoke()
    assert len([kind for kind, _ in case.ui if kind == "pin"]) == 1
    shown = len(case.ui)
    if closed:
        case.root.destroy()
    case.release.set()
    settle(case)
    routes = [path.rsplit("/", 1)[-1] for path, _ in case.server.calls]
    assert routes == (["verifications", "status"] if action == "recheck"
                      else ["verifications", "redemptions"])
    if action == "recheck":
        assert case.app._admin_pin_store().read(intent["operation_key"])["state"] == "SUPERSEDED"
    else:
        assert not case.original.exists()
        assert case.app._admin_pin_store().list_pending()[0]["state"] == "APPLIED"
        assert case.audits.count("ADMIN_PIN_APPLIED") == 1
        assert not case.app._preflight_scan_input_locked
    if closed:
        assert len(case.ui) == shown
    else:
        expected = ("관리자 확인 다시 필요" if action == "recheck"
                    else "사전조회 보류 묶음을 복원 가능한 목록으로 옮겼습니다.")
        assert any(expected in str(args) for _, args in case.ui)


@pytest.mark.parametrize("action", ("recheck", "hold"))
def test_pin_cancel_and_prompt_exception_release_pending(recovery, action):
    case = recovery
    if action == "recheck":
        seed_recheck(case)
        invoke = case.app._recheck_admin_pin_intents
    else:
        invoke = case.app._quarantine_preflight_hold_from_operations
    case.app._prompt_blocked_work_admin_pin = lambda **_request: None
    invoke()
    assert not case.app._admin_pin_ui_pending
    assert not case.entered.is_set()

    def failed_prompt(**_request):
        raise RuntimeError("injected UI callback failure")
    case.app._prompt_blocked_work_admin_pin = failed_prompt
    with pytest.raises(RuntimeError):
        invoke()
    assert not case.app._admin_pin_ui_pending
    assert not case.entered.is_set()


@pytest.mark.parametrize("action", ("recheck", "hold"))
def test_pin_remote_error_keeps_existing_notice_and_releases_pending(recovery, action, monkeypatch):
    case = recovery
    if action == "recheck":
        intent = seed_recheck(case)
        invoke = case.app._recheck_admin_pin_intents
    else:
        invoke = case.app._quarantine_preflight_hold_from_operations

    def unavailable(*_args, **_kwargs):
        raise pin.AdminPinError("PIN_LOCKED")
    monkeypatch.setattr(case.app._admin_pin_client, "verify", unavailable)
    invoke()
    settle(case, expect_writes=action == "hold")
    if action == "recheck":
        assert case.app._admin_pin_store().read(intent["operation_key"])["state"] == "PREPARED"
    assert any(pin.operator_message("PIN_LOCKED") in str(args) for _, args in case.ui)
    assert case.original.exists()


def test_consumed_requery_finishes_same_local_effect_after_window_closes(recovery):
    case = recovery
    intent = seed_recheck(case, "CONSUMED")
    case.server.consumed = True
    case.hold.quarantine(case.app._preflight_hold_quarantine_directory(), reason="interrupted")
    case.writes.clear()
    case.app._recheck_admin_pin_intents()
    case.root.run_until(case.entered.is_set)
    shown = len(case.ui)
    case.root.destroy()
    case.release.set()
    settle(case)
    assert case.app._admin_pin_store().read(intent["operation_key"])["state"] == "APPLIED"
    assert case.audits.count("ADMIN_PIN_APPLIED") == 1
    assert case.audits.count("PHS2_PREFLIGHT_HOLD_QUARANTINED") == 1
    assert len(case.ui) == shown


def test_submission_failure_releases_pending(recovery, monkeypatch):
    case = recovery
    lane = case.app._ui_task_lane()

    def failed_submit(_task):
        raise RuntimeError("injected admission failure")
    monkeypatch.setattr(lane, "submit", failed_submit)
    with pytest.raises(RuntimeError):
        case.app._quarantine_preflight_hold_from_operations()
    assert not case.app._admin_pin_ui_pending
    assert not case.writes
    assert not case.server.calls


@pytest.mark.parametrize("action", ("recheck", "hold"))
def test_empty_verification_result_keeps_original_and_existing_fallback(recovery, action, monkeypatch):
    case = recovery
    if action == "recheck":
        seed_recheck(case)
        invoke = case.app._recheck_admin_pin_intents
    else:
        invoke = case.app._quarantine_preflight_hold_from_operations
    monkeypatch.setattr(case.app._admin_pin_client, "verify", lambda **_request: None)
    invoke()
    settle(case, expect_writes=action == "hold")
    assert case.original.exists()
    assert len([args for kind, args in case.ui if kind == "showwarning"
                and pin.operator_message("VERIFY_UNAVAILABLE") in str(args)]) == 1
    assert not case.server.calls


def test_terminal_notice_exception_releases_pending(recovery, monkeypatch):
    import Container_Audit as module

    case = recovery
    def failed_verify(**_request):
        raise RuntimeError("injected unexpected remote error")
    def failed_notice(*_args, **_kwargs):
        raise RuntimeError("injected terminal notice error")
    monkeypatch.setattr(case.app._admin_pin_client, "verify", failed_verify)
    monkeypatch.setattr(module.messagebox, "showwarning", failed_notice)
    # 9c9f5d5: a lane fault durably records itself, quarantines the original
    # hold and admits a new lane generation instead of staying BROKEN.
    case.app.computer_id = "test-host"
    original = case.original.read_bytes()
    held_id = case.hold.load().preflight_id
    faults = []
    real_log_event = case.app._log_event

    def log_event(event, *args, **kwargs):
        written = real_log_event(event, *args, **kwargs)
        if event == "UI_LANE_FAULT":
            faults.append(written)
        return written

    case.app._log_event = log_event
    case.app._quarantine_preflight_hold_from_operations()
    old_lane = case.app._ui_lane
    case.root.run_until(lambda: case.app._ui_lane is not old_lane)
    assert not case.app._admin_pin_ui_pending
    assert old_lane.state == "CLOSED" and not old_lane.worker_thread.is_alive()
    assert case.app._ui_lane.state == "IDLE"
    assert faults == [True]
    quarantined = next(case.app._preflight_hold_quarantine_directory().glob("preflight_hold_*.json"))
    assert not case.original.exists() and quarantined.read_bytes() == original
    store = case.app._parked_store()
    saved = [store.load(path) for path in store.directory.glob("parked_recovery_*.json")]
    assert len(saved) == 1 and saved[0]["ui_lane_fault"]["result"] == "UNKNOWN"
    assert saved[0]["ui_lane_fault"]["preflight_hold"]["preflight_id"] == held_id


def test_applied_requery_updates_list_once_without_repeating_effect(recovery):
    case = recovery
    case.release.set()
    case.app._quarantine_preflight_hold_from_operations()
    settle(case)
    intent = case.app._admin_pin_store().list_pending()[0]
    held = list(case.app._preflight_hold_quarantine_directory().glob("*.json"))
    preserved = {path: path.read_bytes() for path in held}
    requests = len(case.server.calls)
    audits = list(case.audits)
    case.writes.clear()
    case.ui.clear()
    case.app._recheck_admin_pin_intents()
    settle(case, expect_writes=False)
    assert case.app._admin_pin_store().read(intent["operation_key"])["state"] == "APPLIED"
    assert len(case.server.calls) == requests
    assert case.audits == audits
    assert {path: path.read_bytes() for path in held} == preserved
    assert len([kind for kind, _ in case.ui if kind == "_update_parked_trays_list"]) == 1
    assert [args for kind, args in case.ui if kind == "showinfo"] == [
        ("관리자 확인 완료", "같은 key의 완료 효과와 입력 정리를 확인했습니다.")]


def test_existing_hold_verification_status_precedes_new_pin_on_ui(recovery):
    case = recovery
    previous = seed_recheck(case, "VERIFIED")
    prompts = []

    def prompt(**request):
        assert threading.get_ident() == case.root.owner_thread_id
        assert [path.rsplit("/", 1)[-1] for path, _ in case.server.calls] == ["status"]
        prompts.append(request)
        return case.credentials(**request)

    case.app._prompt_blocked_work_admin_pin = prompt
    case.app._quarantine_preflight_hold_from_operations()
    case.root.run_until(case.entered.is_set)
    case.app._quarantine_preflight_hold_from_operations()
    case.release.set()
    settle(case)
    assert len(prompts) == 1
    assert [path.rsplit("/", 1)[-1] for path, _ in case.server.calls] == [
        "status", "verifications", "redemptions"]
    assert case.app._admin_pin_store().read(previous["operation_key"])["state"] == "SUPERSEDED"
    assert case.app._admin_pin_store().list_pending()[0]["state"] == "APPLIED"


def test_lost_redemption_uses_one_same_key_status_on_lane(recovery):
    case = recovery
    case.server.drop_redemption_once = True
    case.app._quarantine_preflight_hold_from_operations()
    case.root.run_until(case.entered.is_set)
    case.release.set()
    settle(case)
    assert [path.rsplit("/", 1)[-1] for path, _ in case.server.calls] == [
        "verifications", "redemptions", "status"]
    assert case.server.calls[-1][1]["operation_key"] == case.server.calls[-2][1]["operation_key"]
    assert case.app._admin_pin_store().list_pending()[0]["state"] == "APPLIED"
    assert case.audits.count("ADMIN_PIN_APPLIED") == 1
