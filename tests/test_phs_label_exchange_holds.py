import copy
from contextlib import contextmanager
import datetime
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

import Container_Audit as container_module
import phs_label_workflow
from Container_Audit import ContainerAudit, TraySession
from label_qr import parse_new_format_qr
from parked_tray_store import ParkedTrayStore
from storage_utils import atomic_write_json
from tests.test_operator_review_safety_contracts import DummyListbox, RecordingRoot
from tests.test_phs_label_workflow import (
    FakeCentral, TARGET_LABEL, TARGET_PREFIX, _coordinator, _qr, _target_candidate, _tray,
)
from tests.test_phs_reconciliation_workflow import _ImmediateLane
from transfer_seal import validate_compact_phs2_fields
from tray_state import tray_session_from_state, tray_session_to_state, validate_tray_state
from warning_presenter import WarningPresenter


def _app(tmp_path, *, journal=None, worker=None):
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = worker or uuid.uuid4().hex
    app.worker_role = "WORKER"
    app.current_tray = _tray()
    app.TRAY_SIZE = 60
    app.parked_trays_dir = str(tmp_path / "parked_trays")
    app.save_folder = str(tmp_path / "events")
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.log_file_path = str(tmp_path / "events.csv")
    app.root = RecordingRoot()
    app.scanned_listbox = DummyListbox()
    app.warning_presenter = WarningPresenter()
    app.COLOR_DANGER = "red"
    app.COLOR_PRIMARY = "blue"
    app.COLOR_SUCCESS = "green"
    app.master_label_replace_state = None
    app.messages = []
    app.show_status_message = lambda message, *_args, **_kwargs: app.messages.append(message)
    app._show_field_notice = lambda *_args, **_kwargs: None
    app._preflight_hold_store = lambda **_kwargs: SimpleNamespace(exists=lambda: False)
    app._preflight_context_blocks_mutation = lambda: False
    app._reject_mutation_during_preflight_hold = lambda: False
    app._operator_review_blocks_mutation = lambda: False
    app._transfer_member_exchange_blocks_local_action = lambda *_args: False
    app._paired_preflight_blocks_label = lambda *_args, **_kwargs: False
    app._is_completed_tray_state = lambda _state: False
    app._current_tray_state_snapshot = lambda: tray_session_to_state(app.current_tray, worker_name=app.worker_name)
    app._stage_checkpoint_audit_events = lambda _state: True
    app._flush_pending_event_logs = lambda: True
    app._completion_projection_log_path = lambda *_args, **_kwargs: Path(app.log_file_path)
    app._project_audit_event_contract = lambda _event: True
    app._save_tray_state_snapshot = lambda state: atomic_write_json(
        Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE, state,
    ) or True
    app.show_tray_image_var = SimpleNamespace(set=lambda _value: None)
    for method in (
        "_invalidate_pending_scan_callbacks", "_sync_last_normal_scan_from_active_tray",
        "_reset_ui_to_waiting_state", "_update_all_summaries", "_update_parked_trays_list",
        "_show_left_sidebar_view", "_update_action_button_states", "_schedule_focus_return",
        "_update_last_activity_time", "show_validation_screen", "_update_tray_image_display",
        "_update_current_item_label", "_update_center_display",
    ):
        setattr(app, method, lambda *_args, **_kwargs: None)

    def checkpoint(event, *, detail):
        return {"log_file_name": "events.csv", "local_only": False, "log_entry": {
            "timestamp": datetime.datetime.now().isoformat(), "worker_name": app.worker_name,
            "event": event, "details": json.dumps({**detail, "idempotency_key": uuid.uuid4().hex}),
        }}

    app._checkpoint_audit_event = checkpoint
    app.phs_label_exchange_coordinator = SimpleNamespace(journal=journal or
        phs_label_workflow.PHSLabelExchangeJournal(tmp_path / "phs_label_exchange" / "phs_label_exchange_recovery.json"))
    app._save_tray_state_snapshot(app._current_tray_state_snapshot())
    return app


def _pending(app, *, workflow="SINGLE", label=None, status="ACTIVATE_PENDING"):
    state = {"workflow_kind": workflow, "status": status}
    label = label or app.current_tray.master_label_code
    if workflow == "RECONCILIATION":
        state["reconciliation_context"] = {"actions": [{"sources": [{"qr_payload": label}]}]}
    else:
        state["canonical_input_tag_qr"] = label
    app.phs_label_exchange_coordinator.journal.save(state)


def _other_qr():
    original_tag = parse_new_format_qr(_qr())["ITG"]
    return _qr(str(uuid.uuid4()), uuid.uuid4().hex[:16]).replace(original_tag, str(uuid.uuid4()))


def _parked(app):
    rows = app._parked_store().scan_for_worker(app.worker_name, strict=True)
    assert len(rows) == 1 and not rows[0].problem
    state = ParkedTrayStore.load(rows[0].path)
    validate_tray_state(state, default_tray_size=app.TRAY_SIZE)
    return rows[0].path, state


def _scan(app, barcode):
    validate_compact_phs2_fields(parse_new_format_qr(barcode))
    accepted = []
    app._intercept_phs_reconciliation_scan = lambda _barcode: False
    app._intercept_active_tray_phs2_scan = lambda _barcode: False
    app._offline_waiting_preflight_holds = lambda: []
    app._is_completed_master_label = lambda _barcode: False
    app._roster_allows_new_tray = lambda: True
    app._reject_legacy_master_label = lambda _fields: False
    app._item_catalog = lambda: SimpleNamespace(find_by_code=lambda _code: {"name": "item"})
    app._begin_compact_phs2_preflight = lambda **kwargs: accepted.append(kwargs["barcode"])
    list(app._process_barcode_steps(barcode))
    return accepted


@pytest.mark.parametrize("workflow", ["SINGLE", "RECONCILIATION"])
@pytest.mark.parametrize("status", ["PREPARE_PENDING", "ACTIVATE_PENDING", "COMMITTED_LOCAL_REFRESH_PENDING"])
def test_pending_exchange_parks_exact_tray_and_accepts_other_label(tmp_path, workflow, status):
    app = _app(tmp_path)
    before = copy.deepcopy(app.current_tray)
    _pending(app, workflow=workflow, status=status)
    journal = app.phs_label_exchange_coordinator.journal
    original_journal = journal.path.read_bytes()
    callbacks = []
    app._invalidate_pending_scan_callbacks = lambda *_args, **_kwargs: callbacks.append(True)
    assert not _scan(app, _other_qr())
    assert app.current_tray == before and callbacks == []

    assert app.park_current_tray(confirm=False)
    path, state = _parked(app)
    assert state["scanned_barcodes"] == before.scanned_barcodes
    assert state["scan_times"] == [stamp.isoformat() for stamp in before.scan_times]
    assert state["tray_size"] == before.tray_size
    assert state["start_time"] == before.start_time.isoformat()
    assert json.loads(state["pending_audit_events"][-1]["log_entry"]["details"])["reason"] == "phs_label_exchange_pending"
    assert not app.current_tray.master_label_code
    assert not (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).exists()
    assert journal.path.read_bytes() == original_journal
    assert _scan(app, _other_qr())
    assert not _scan(app, "|".join(reversed(before.master_label_code.split("|"))))
    app.restore_parked_tray(str(path))
    assert not app.current_tray.master_label_code and path.exists()


@pytest.mark.parametrize("raw", [b"{", b"\xff", b"{}"])
def test_unreadable_exchange_preserves_bytes_unknown_and_item_scope_across_restart(tmp_path, monkeypatch, raw):
    app = _app(tmp_path)
    journal = app.phs_label_exchange_coordinator.journal
    journal.path.parent.mkdir(parents=True, exist_ok=True)
    journal.path.write_bytes(raw)
    app.current_tray.active_label_qr_payload = _qr(TARGET_LABEL, TARGET_PREFIX)
    app.current_tray.active_label_id = TARGET_LABEL
    master = app.current_tray.master_label_code
    assert app.park_current_tray(confirm=False)
    path, state = _parked(app)
    receipt = journal.quarantine_unreadable(master_label="", active_label="", reason="retry")
    assert receipt["status"] == "UNKNOWN"
    assert receipt["canonical_input_tag_qr"] == master
    assert receipt["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert Path(receipt["preserved_path"]).read_bytes() == journal.path.read_bytes() == raw
    assert _scan(app, _other_qr())
    assert not _scan(app, master)
    assert not _scan(app, _qr(TARGET_LABEL, TARGET_PREFIX))

    next_day = datetime.datetime.now() + datetime.timedelta(days=1)
    monkeypatch.setattr(phs_label_workflow, "_utc_now", lambda: next_day.isoformat())

    restarted = _app(tmp_path, journal=journal, worker=app.worker_name)
    restarted.current_tray = TraySession()
    assert not _scan(restarted, master)
    assert _scan(restarted, _other_qr())
    restarted.restore_parked_tray(str(path))
    assert not restarted.current_tray.master_label_code
    assert ParkedTrayStore.load(path) == state
    assert len(list(journal.path.parent.glob("*.bin"))) == 1


@pytest.mark.parametrize("failure", ["copy", "fsync"])
def test_failed_journal_preservation_keeps_current_tray_and_blocks_next_label(tmp_path, monkeypatch, failure):
    app = _app(tmp_path)
    journal = app.phs_label_exchange_coordinator.journal
    journal.path.parent.mkdir(parents=True, exist_ok=True)
    journal.path.write_bytes(b"{")
    tray = app.current_tray
    current_path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    original_state = current_path.read_bytes()
    if failure == "copy":
        original_open = Path.open

        def fail_copy(path, mode="r", *args, **kwargs):
            if ".quarantine-" in path.name and mode == "xb":
                raise PermissionError("injected copy failure")
            return original_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(Path, "open", fail_copy)
    else:
        monkeypatch.setattr(phs_label_workflow.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("injected fsync failure")))
    assert not app.park_current_tray(confirm=False)
    assert app.current_tray is tray and current_path.read_bytes() == original_state
    assert journal.path.read_bytes() == b"{"
    assert not _scan(app, _other_qr())
    assert not list(Path(app.parked_trays_dir).glob("*.json"))


def test_failed_park_write_keeps_pending_tray_and_journal(tmp_path, monkeypatch):
    app = _app(tmp_path)
    _pending(app)
    tray = app.current_tray
    journal = app.phs_label_exchange_coordinator.journal
    original = journal.path.read_bytes()
    monkeypatch.setattr(app._parked_store(), "save_state", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected park failure")))
    assert app._phs_label_exchange_blocks_tray_transition("현재 작업 초기화")
    assert app.current_tray is tray and journal.path.read_bytes() == original


def test_unrelated_reconciliation_does_not_block_tray_switch_but_its_source_stays_blocked(tmp_path):
    app = _app(tmp_path)
    other = _other_qr()
    _pending(app, workflow="RECONCILIATION", label=other)
    assert not app._phs_label_exchange_transition_pending()
    assert not app._phs_label_exchange_blocks_tray_transition("작업자 변경")
    assert app.park_current_tray(confirm=False)
    assert _scan(app, _other_qr())
    assert not _scan(app, other)


@pytest.mark.parametrize("terminal", ["COMMITTED", "CANCELLED"])
def test_overnight_exchange_hold_restores_only_after_terminal_ack(tmp_path, monkeypatch, terminal):
    app = _app(tmp_path)
    _pending(app)
    before = copy.deepcopy(app.current_tray)
    assert app.park_current_tray(confirm=False)
    path, state = _parked(app)
    real_datetime = datetime.datetime

    class NextDay(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + datetime.timedelta(days=1)

    monkeypatch.setattr(container_module.datetime, "datetime", NextDay)
    assert not _scan(app, before.master_label_code)
    app.restore_parked_tray(str(path))
    assert not app.current_tray.master_label_code and ParkedTrayStore.load(path) == state
    _pending(app, label=before.master_label_code, status=terminal)
    app.restore_parked_tray(str(path))
    assert app.current_tray.master_label_code == before.master_label_code
    assert app.current_tray.scanned_barcodes == before.scanned_barcodes
    assert app.current_tray.start_time == before.start_time
    assert not path.exists()


def test_single_exchange_recovery_updates_parked_label_without_mutating_next_tray(tmp_path):
    app = _app(tmp_path)
    client = FakeCentral()
    coordinator = _coordinator(tmp_path, client)
    app.phs_label_exchange_coordinator = coordinator
    result = coordinator.execute_single(app.current_tray, _target_candidate(), defer_local_refresh=True)
    assert result.success and coordinator.journal.load()["status"] == "COMMITTED_LOCAL_REFRESH_PENDING"
    assert app.park_current_tray(confirm=False)
    path, state = _parked(app)
    assert not _scan(app, _qr(TARGET_LABEL, TARGET_PREFIX))
    app.current_tray = _tray()
    app.current_tray.master_label_code = _other_qr()
    app.current_tray.canonical_input_tag_qr = app.current_tray.master_label_code
    app.current_tray.active_label_qr_payload = app.current_tray.master_label_code
    app.current_tray.active_label_id = parse_new_format_qr(app.current_tray.master_label_code)["LBL"]
    validate_tray_state(tray_session_to_state(app.current_tray, worker_name=app.worker_name), default_tray_size=app.TRAY_SIZE)
    next_tray = copy.deepcopy(app.current_tray)
    lane = _ImmediateLane()
    app._ui_task_lane = lambda: lane
    app._capture_mutation_finish_identity = lambda: object()
    app._mutation_finish_can_apply = lambda *_args, **_kwargs: True
    app._schedule_phs_label_exchange_recovery()
    assert coordinator.journal.load()["status"] == "COMMITTED"
    restored = ParkedTrayStore.load(path)
    assert restored["active_label_qr_payload"] == _qr(TARGET_LABEL, TARGET_PREFIX)
    assert restored["scanned_barcodes"] == state["scanned_barcodes"]
    assert restored["pending_audit_events"] == state["pending_audit_events"]
    assert app.current_tray == next_tray


def test_f8_recovers_parked_single_exchange_with_an_unrelated_active_tray(tmp_path):
    app = _app(tmp_path)
    _pending(app)
    assert app.park_current_tray(confirm=False)
    app.current_tray = _tray()
    app.current_tray.master_label_code = _other_qr()
    app.current_tray.canonical_input_tag_qr = app.current_tray.master_label_code
    app.current_tray.active_label_qr_payload = app.current_tray.master_label_code
    app.current_tray.active_label_id = parse_new_format_qr(app.current_tray.master_label_code)["LBL"]
    app._phs_label_exchange_recovery_visible = True
    calls = []
    app._schedule_phs_label_exchange_recovery = lambda: calls.append(True)
    assert app._on_phs_label_exchange_shortcut() == "break"
    assert calls == [True]


def test_journal_preservation_releases_read_lock_before_writer_admission(tmp_path, monkeypatch):
    app = _app(tmp_path)
    journal = app.phs_label_exchange_coordinator.journal
    journal.path.parent.mkdir(parents=True, exist_ok=True)
    journal.path.write_bytes(b"{")
    admit = phs_label_workflow.writer_admission

    @contextmanager
    def ordered_admission(kind):
        assert not journal._lock.locked()
        with admit(kind):
            yield

    monkeypatch.setattr(phs_label_workflow, "writer_admission", ordered_admission)
    assert app.park_current_tray(confirm=False)


def test_unknown_copy_record_cannot_claim_a_terminal_result(tmp_path):
    app = _app(tmp_path)
    journal = app.phs_label_exchange_coordinator.journal
    journal.path.parent.mkdir(parents=True, exist_ok=True)
    journal.path.write_bytes(b"{")
    assert app.park_current_tray(confirm=False)
    record_path = next(journal.path.parent.glob("*.quarantine-*.json"))
    record = phs_label_workflow.PHSLabelExchangeJournal(record_path)
    record.save({**record.load(), "status": "COMMITTED"})
    assert not _scan(app, _other_qr())
    assert journal.path.read_bytes() == b"{"


def test_stale_parked_generation_cannot_be_overwritten_by_exchange_finish(tmp_path):
    app = _app(tmp_path)
    _pending(app)
    before = copy.deepcopy(app.current_tray)
    assert app.park_current_tray(confirm=False)
    path, state = _parked(app)
    captured = path.read_bytes()
    updated_tray = tray_session_from_state(state, session_factory=TraySession, default_tray_size=60)
    updated_tray.active_label_business_date = datetime.date.today().isoformat()
    changed = {**state, "stopwatch_seconds": state["stopwatch_seconds"] + 1}
    atomic_write_json(path, changed)
    assert not app._apply_phs_label_exchange_snapshot(
        captured_tray=before, captured_master_label=before.master_label_code,
        updated_tray=updated_tray, force_persist=True, parked_path=path, parked_bytes=captured,
    )
    assert ParkedTrayStore.load(path) == changed
