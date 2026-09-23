from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from Container_Audit import ContainerAudit, TraySession
from paired_preflight_handoff import PairedHandoffError, PairedPreflightHandoffStore
from preflight_scan_hold import PreflightScanHoldStore
from protected_admin import PROTECTED_ADMIN_OPERATOR_ID
from storage_utils import atomic_write_json
from tests.test_container_audit_contracts import CapturingTree
from tests.test_container_p0_contracts import _preflight_hold_ownership_app, _saved_tray_state


def _app(tmp_path, monkeypatch):
    _, app, hold_store = _preflight_hold_ownership_app(tmp_path, monkeypatch)
    app.root = SimpleNamespace()
    app.worker_name = PROTECTED_ADMIN_OPERATOR_ID
    app.worker_role = "ADMIN"
    app._authenticated_protected_admin = True
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app._invalidate_pending_scan_callbacks = lambda: None
    app._reset_ui_to_waiting_state = lambda: None
    app._update_all_summaries = lambda: None
    current = _saved_tray_state()
    current["worker_name"] = "current worker"
    app.current_tray = TraySession(
        master_label_code=current["master_label_code"],
        scanned_barcodes=list(current["scanned_barcodes"]),
    )
    atomic_write_json(hold_store.path.parent / "current.json", current)
    hold_store.start(worker="hold worker", master_raw="OTHER-MASTER", scan_epoch=1)
    hold_store.append("HELD-PRODUCT")
    hold_store.mark_draining()
    app._preflight_hold_snapshot = hold_store.load()
    return app, hold_store, current


def test_paired_handoff_blocks_only_original_labels_and_keeps_bytes(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    original_hold = hold_store.path.read_bytes()
    original_current = (hold_store.path.parent / "current.json").read_bytes()
    assert app._defer_paired_preflight_from_operations() is True
    path = app._paired_preflight_store().paths()[0]
    assert (path.parent / "hold.original").read_bytes() == original_hold
    assert (path.parent / "current.original").read_bytes() == original_current
    assert app._paired_preflight_store().is_released(path)
    assert not app._preflight_context_blocks_mutation()
    assert app._paired_preflight_blocks_label(current["master_label_code"])
    assert app._paired_preflight_blocks_label("OTHER-MASTER")
    assert not app._paired_preflight_blocks_label("PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-OTHER|CLC=AAA2270730100|LBL=OTHER|HSH=0123456789abcdef")


def test_paired_label_cannot_be_reactivated_from_quarantine(tmp_path, monkeypatch):
    app, active, current = _app(tmp_path, monkeypatch)
    label = current["master_label_code"]
    previous = PreflightScanHoldStore(tmp_path / "previous" / "hold.json", capacity=4)
    previous.start(worker="tester", master_raw=label, scan_epoch=1)
    previous.append("PREVIOUS-PRODUCT")
    previous.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")
    quarantined = previous.quarantine(app._preflight_hold_quarantine_directory(), reason="previous_attempt")
    original = quarantined.path.read_bytes()

    assert app._defer_paired_preflight_from_operations() is True
    assert app._paired_preflight_blocks_label(label)
    assert app.restore_quarantined_preflight_hold(str(quarantined.path)) is False
    assert quarantined.path.read_bytes() == original
    assert not app._preflight_hold_store().exists()


def test_paired_label_cannot_be_restored_from_parked_tray(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    saved_state = {**current, "worker_name": app.worker_name}
    parked = app._parked_store().save_state(
        saved_state, worker_name=app.worker_name, master_label=current["master_label_code"]
    )
    original = parked.read_bytes()

    app.restore_parked_tray(str(parked))

    assert parked.read_bytes() == original
    assert not app.current_tray.master_label_code
    assert not (hold_store.path.parent / "current.json").exists()


def test_paired_parked_rejection_keeps_original_bytes_before_worker_normalization(
    tmp_path, monkeypatch
):
    app, _, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    parked = app._parked_store().save_state(
        {**current, "worker_name": "tester"},
        worker_name="tester",
        master_label=current["master_label_code"],
    )
    payload = json.loads(parked.read_text(encoding="utf-8"))
    payload["worker_name"] = PROTECTED_ADMIN_OPERATOR_ID
    atomic_write_json(parked, payload)
    original = parked.read_bytes()
    notices = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showwarning",
        lambda _title, message, **_kwargs: notices.append(message),
    )

    app.restore_parked_tray(str(parked))

    assert parked.read_bytes() == original
    assert any("짝 인계 보류 중" in message for message in notices)
    assert not app.current_tray.master_label_code


def test_paired_parked_original_survives_list_refresh_and_duplicate_search(
    tmp_path, monkeypatch,
):
    app, _, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    parked = app._parked_store().save_state(
        {**current, "worker_name": "tester"},
        worker_name="tester",
        master_label=current["master_label_code"],
    )
    payload = json.loads(parked.read_text(encoding="utf-8"))
    payload["worker_name"] = PROTECTED_ADMIN_OPERATOR_ID
    atomic_write_json(parked, payload)
    original = parked.read_bytes()

    app.parked_tree = CapturingTree()
    app._sync_left_sidebar_switch = lambda: None
    app._update_parked_trays_list()
    notices = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda _title, message, **_kwargs: notices.append(message) or False,
    )
    app._show_paired_preflight_handoffs()
    assert len(notices) == 1
    assert "관리자 보류" in notices[0]
    app._parked_store().existing_label_path_any_worker(
        master_label=current["master_label_code"]
    )
    assert parked.read_bytes() == original
    app.restore_parked_tray(str(parked))
    assert parked.read_bytes() == original
    assert not app.current_tray.master_label_code


def test_paired_label_cannot_be_restored_from_stale_current_state(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    stale_path = hold_store.path.parent / "current.json"
    atomic_write_json(stale_path, current)
    original = stale_path.read_bytes()

    app._load_current_tray_state()

    assert not stale_path.exists()
    preserved = list(stale_path.parent.glob("current.json.bad-*"))
    assert len(preserved) == 1 and preserved[0].read_bytes() == original
    assert not app.current_tray.master_label_code
    assert not app._preflight_context_blocks_mutation()


def test_unpreserved_stale_current_state_keeps_mutation_locked(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    stale_path = hold_store.path.parent / "current.json"
    atomic_write_json(stale_path, current)
    original = stale_path.read_bytes()
    app._quarantine_current_tray_state = lambda _reason: None

    app._load_current_tray_state()

    assert stale_path.read_bytes() == original
    assert app._preflight_context_blocks_mutation()
    assert not app.current_tray.master_label_code


def test_stale_current_preservation_retry_then_continue_blocks_only_paired_label(
    tmp_path, monkeypatch,
):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    stale_path = hold_store.path.parent / "current.json"
    atomic_write_json(stale_path, current)
    original = stale_path.read_bytes()
    quarantine = app._quarantine_current_tray_state
    app._quarantine_current_tray_state = lambda _reason: None
    app._load_current_tray_state()
    assert app._paired_stale_current_blocked
    assert stale_path.read_bytes() == original
    assert app._continue_after_paired_stale_current() is False
    assert stale_path.read_bytes() == original
    assert app._preflight_context_blocks_mutation()

    app._quarantine_current_tray_state = quarantine
    assert app._retry_paired_stale_current_preservation() is True
    assert app._preflight_context_blocks_mutation()
    assert not stale_path.exists()
    assert list(stale_path.parent.glob("current.json.bad-*"))[0].read_bytes() == original
    assert app._continue_after_paired_stale_current() is True
    assert not app._preflight_context_blocks_mutation()
    assert app._paired_preflight_blocks_label(current["master_label_code"])
    assert not app._paired_preflight_blocks_label("OTHER-NEW-LABEL")


def test_stale_current_audit_failure_keeps_other_work_locked(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    stale_path = hold_store.path.parent / "current.json"
    atomic_write_json(stale_path, current)
    quarantine = app._quarantine_current_tray_state
    app._quarantine_current_tray_state = lambda _reason: None
    app._load_current_tray_state()
    app._quarantine_current_tray_state = quarantine
    app._log_event = lambda event, **_kwargs: event.endswith("PRESERVATION_REQUESTED")
    assert app._continue_after_paired_stale_current() is False
    assert app._preflight_context_blocks_mutation()
    assert not stale_path.exists()
    assert list(stale_path.parent.glob("current.json.bad-*"))


def test_stale_current_preservation_audit_failure_keeps_original_in_slot(
    tmp_path, monkeypatch,
):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    stale_path = hold_store.path.parent / "current.json"
    atomic_write_json(stale_path, current)
    original = stale_path.read_bytes()
    quarantine = app._quarantine_current_tray_state
    app._quarantine_current_tray_state = lambda _reason: None
    app._load_current_tray_state()
    app._quarantine_current_tray_state = quarantine
    app._log_event = lambda *_args, **_kwargs: False

    assert app._retry_paired_stale_current_preservation() is False
    assert stale_path.read_bytes() == original
    assert not list(stale_path.parent.glob("current.json.bad-*"))
    assert app._preflight_context_blocks_mutation()


def test_paired_handoff_denies_actor_change_after_manager_confirmation(tmp_path, monkeypatch):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    original_hold = hold_store.path.read_bytes()
    current_path = hold_store.path.parent / "current.json"
    original_current = current_path.read_bytes()
    notices = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda *_args, **_kwargs: setattr(app, "worker_name", "another worker") or True,
    )
    monkeypatch.setattr(
        "Container_Audit.messagebox.showwarning",
        lambda _title, message, **_kwargs: notices.append(message),
    )
    assert app._defer_paired_preflight_from_operations() is False
    assert hold_store.path.read_bytes() == original_hold
    assert current_path.read_bytes() == original_current
    assert not app._paired_preflight_store().paths()
    assert any("로그인 작업자 또는 역할이 바뀌었습니다" in message for message in notices)


def test_paired_handoff_denies_role_change_after_code_approval(tmp_path, monkeypatch):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    app.worker_name = "tester"
    app.worker_role = "WORKER"
    app._authenticated_protected_admin = False
    original_hold = hold_store.path.read_bytes()
    monkeypatch.setattr("Container_Audit.simpledialog.askstring", lambda *_a, **_k: "entered-code")
    monkeypatch.setattr("Container_Audit.is_protected_admin_code", lambda _code: True)
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda *_a, **_k: setattr(app, "worker_role", "ADMIN") or True,
    )
    assert app._defer_paired_preflight_from_operations() is False
    assert hold_store.path.read_bytes() == original_hold
    assert not app._paired_preflight_store().paths()


def test_paired_handoff_audit_binds_actor_and_approving_manager(tmp_path, monkeypatch):
    app, _, _ = _app(tmp_path, monkeypatch)
    audits = []
    app._log_event = lambda _event, detail=None, **_kwargs: audits.append(detail) or True
    assert app._defer_paired_preflight_from_operations()
    assert audits[0]["acting_worker"] == "보호된 관리자"
    assert audits[0]["acting_role"] == "ADMIN"
    assert audits[0]["approving_supervisor"] == "보호된 관리자"
    assert audits[0]["approving_role"] == "ADMIN"


def test_worker_start_does_not_preview_paired_label_as_active(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    hold_store.start(worker="tester", master_raw=current["master_label_code"], scan_epoch=2)
    hold_store.append("LATE-PRODUCT")
    hold_store.mark_draining()
    original_hold = hold_store.path.read_bytes()
    stale_path = hold_store.path.parent / "current.json"
    atomic_write_json(stale_path, current)
    original_current = stale_path.read_bytes()
    app.worker_entry = SimpleNamespace(get=lambda: "tester")
    app._ensure_worker_login_name = lambda name: name
    app._load_session_state = lambda: None
    app._schedule_startup_transfer_recovery = lambda: None
    app._begin_or_resume_work_session = lambda: True
    app.root = SimpleNamespace(winfo_exists=lambda: False)

    app.start_work()

    assert not app.current_tray.master_label_code
    assert hold_store.path.read_bytes() == original_hold
    preserved = list(stale_path.parent.glob("current.json.bad-*"))
    assert len(preserved) == 1 and preserved[0].read_bytes() == original_current


def test_paired_label_cannot_be_restored_from_stale_active_hold(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True
    hold_store.start(worker="tester", master_raw=current["master_label_code"], scan_epoch=2)
    hold_store.append("LATE-PRODUCT")
    hold_store.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")
    original = hold_store.path.read_bytes()

    assert app._restore_preflight_scan_hold() is True
    assert hold_store.path.read_bytes() == original
    assert not app.current_tray.master_label_code


def test_paired_label_cannot_be_activated_by_late_preflight(tmp_path, monkeypatch):
    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations() is True

    activated = app._activate_master_label_tray(
        barcode=current["master_label_code"],
        item_code=current["item_code"],
        tray_quantity=current["tray_size"],
        matched_item={"Item Name": current["item_name"]},
        event_name="MASTER_LABEL_SCANNED_NEW",
        event_detail={},
        preflight_hold_owner=True,
    )

    assert activated is False
    assert not app.current_tray.master_label_code
    assert not (hold_store.path.parent / "current.json").exists()


@pytest.mark.parametrize("stage", ["capture", "record_readback"])
def test_paired_handoff_prepare_interruption_keeps_originals_locked(tmp_path, monkeypatch, stage):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    paired = app._paired_preflight_store()
    app._paired_preflight_store = lambda: paired
    hold_bytes = hold_store.path.read_bytes()
    current_path = hold_store.path.parent / "current.json"
    current_bytes = current_path.read_bytes()
    name = "_part" if stage == "capture" else "read"
    original = getattr(paired, name)

    def interrupted(*args):
        raise OSError("injected preparation interruption")

    monkeypatch.setattr(paired, name, interrupted)
    assert app._defer_paired_preflight_from_operations() is False
    assert app._preflight_context_blocks_mutation()
    assert hold_store.path.read_bytes() == hold_bytes
    assert current_path.read_bytes() == current_bytes
    monkeypatch.setattr(paired, name, original)
    assert app._defer_paired_preflight_from_operations() is True


@pytest.mark.parametrize("stage", ["audit", "first_move", "second_move", "release"])
def test_paired_handoff_interruption_keeps_lock_and_replays_same_record(tmp_path, monkeypatch, stage):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    paired = app._paired_preflight_store()
    app._paired_preflight_store = lambda: paired
    if stage == "audit":
        app._log_event = lambda *a, **k: False
    else:
        original = paired.release if stage == "release" else paired.move_original
        calls = 0

        def fail_once(*args):
            nonlocal calls
            calls += 1
            if calls == (2 if stage == "second_move" else 1):
                raise OSError("injected interruption")
            return original(*args)

        monkeypatch.setattr(paired, "release" if stage == "release" else "move_original", fail_once)
    assert app._defer_paired_preflight_from_operations() is False
    paths = paired.paths()
    assert len(paths) == 1 and paired.pending()
    assert app._preflight_context_blocks_mutation()
    if stage == "audit":
        app._log_event = lambda *a, **k: True
    else:
        monkeypatch.setattr(paired, "release" if stage == "release" else "move_original", original)
    assert app._defer_paired_preflight_from_operations() is True
    assert paired.paths() == paths
    assert not paired.pending()


def test_paired_handoff_hash_mismatch_keeps_lock(tmp_path, monkeypatch):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    paired = app._paired_preflight_store()
    path = paired.prepare(hold_store.path, hold_store.path.parent / "current.json")
    hold_store.path.write_bytes(b"tampered")
    app._paired_preflight_store = lambda: paired
    assert app._defer_paired_preflight_from_operations() is False
    assert paired.pending() and app._preflight_context_blocks_mutation()
    record = paired.read(path)
    hold_store.path.write_bytes(paired._bytes(record["hold"]))
    assert app._defer_paired_preflight_from_operations() is True


def test_worker_cannot_defer_paired_handoff(tmp_path, monkeypatch):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    app.worker_name = "tester"
    app.worker_role = "WORKER"
    app._authenticated_protected_admin = False
    app._authorize_blocked_work_supervisor = lambda: False
    assert app._defer_paired_preflight_from_operations() is False
    assert hold_store.path.exists()
    assert not app._paired_preflight_store().paths()


def test_mismatched_draining_hold_allows_normal_close_handoff(tmp_path, monkeypatch):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    assert app._restore_preflight_scan_hold() is True
    assert app._preflight_context_blocks_mutation()
    assert app._preserve_preflight_hold_for_close() == (True, True)
    assert hold_store.path.exists()
    assert (hold_store.path.parent / "current.json").exists()


def test_pending_pair_after_first_move_stays_locked_on_restart(tmp_path, monkeypatch):
    app, hold_store, _ = _app(tmp_path, monkeypatch)
    paired = app._paired_preflight_store()
    path = paired.prepare(hold_store.path, hold_store.path.parent / "current.json")
    paired.move_original(path, "hold")
    _, restarted, _ = _preflight_hold_ownership_app(tmp_path, monkeypatch)
    restarted.parked_trays_dir = app.parked_trays_dir
    restarted.save_folder = app.save_folder
    restarted.CURRENT_TRAY_STATE_FILE = app.CURRENT_TRAY_STATE_FILE
    assert restarted._restore_preflight_scan_hold() is True
    assert restarted._preflight_context_blocks_mutation()
    assert restarted._preserve_preflight_hold_for_close() == (True, True)


def test_manager_handoff_list_shows_both_originals(tmp_path, monkeypatch):
    app, _, _ = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    notices = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda _title, message, **_kwargs: notices.append(message) or False,
    )
    app._show_paired_preflight_handoffs()
    assert len(notices) == 1
    for expected in ("hold worker", "current worker", "DRAINING", "SHA256", "관리자 보류"):
        assert expected in notices[0]


def test_later_archived_damage_blocks_pair_without_stopping_other_labels(tmp_path, monkeypatch):
    app, _, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    paired = app._paired_preflight_store()
    path = paired.paths()[0]
    (path.parent / "hold.original").write_bytes(b"later damage")
    assert paired.is_released(path) and not paired.originals_match(path)
    assert not app._preflight_context_blocks_mutation()
    assert app._paired_preflight_blocks_label(current["master_label_code"])
    notices = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda _title, message, **_kwargs: notices.append(message) or False,
    )
    app._show_paired_preflight_handoffs()
    assert "원본 파일 재대조 필요" in notices[0]


def test_paired_receipt_recheck_reads_same_key_without_settling(tmp_path, monkeypatch):
    app, _, current = _app(tmp_path, monkeypatch)
    calls = []
    messages = []
    row = {"command_json": json.dumps({"authority_scope_id": "scope", "idempotency_key": "original-key"})}
    coordinator = SimpleNamespace(
        store=SimpleNamespace(bound_operator_review_for_tray=lambda **_kwargs: row),
        client=SimpleNamespace(get_receipt=lambda scope, key: calls.append((scope, key)) or {"receipt_id": "r"}),
        _validate_bound_command=lambda *_args: None,
        _validate_receipt=lambda *_args: None,
    )
    lane = SimpleNamespace(is_busy=lambda: False, submit=lambda task: calls.append(task))
    app._ui_task_lane = lambda: lane
    app._transfer_seal_runtime = lambda: coordinator
    monkeypatch.setattr("Container_Audit.messagebox.showinfo", lambda _title, message, **_kwargs: messages.append(message))
    app._recheck_paired_preflight_receipt(current)
    task = calls.pop()
    task.finish(task.work())
    assert calls == [("scope", "original-key")]
    assert "관리자 보류 상태로 유지" in messages[0]


def test_paired_receipt_recheck_denies_actor_change_before_lane_runs(tmp_path, monkeypatch):
    app, _, current = _app(tmp_path, monkeypatch)
    calls = []
    tasks = []
    app._ui_task_lane = lambda: SimpleNamespace(
        is_busy=lambda: False, submit=lambda task: tasks.append(task),
    )
    app._transfer_seal_runtime = lambda: calls.append("runtime")
    app._recheck_paired_preflight_receipt(current)
    assert len(tasks) == 1
    app.worker_name = "another worker"
    assert "관리자 확인을 다시 받으세요" in tasks[0].work()
    assert calls == []
