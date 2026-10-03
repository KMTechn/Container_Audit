"""Scanner UNDO preserves stage boundaries and restartable timing evidence."""
import json
import datetime
from pathlib import Path

import pytest
import Container_Audit as ca

from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_w9scanonly_workflow import (
    _active, _own_coordinators_on_lane, flow, windows,  # noqa: F401
)
from tests.test_phs2_master_preflight import COMPACT_QR, ITEM
from tests.test_phs2_master_preflight import _pump_until
from tests.test_scanonly_review_regressions import public_scan, real_notice
from tk_serial_ui_lane import LaneTask
from tray_state import validate_tray_state

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


def test_short_undo_preserves_original_clock_and_restart_checkpoint(flow, windows):
    app = _active(flow)
    app.root.tk = object()
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    public_scan(app, ITEM + '-SERIAL-001')
    app.current_tray.start_time -= datetime.timedelta(seconds=10)
    app.current_tray.scan_times[0] = app.current_tray.start_time + datetime.timedelta(seconds=1)
    app.current_tray.stopwatch_seconds = 10
    original_start = app.current_tray.start_time
    original_times = list(app.current_tray.scan_times)
    original_elapsed = app.current_tray.stopwatch_seconds
    # The shared flow normally replaces UI timers; exercise the real resume decision.
    app._start_stopwatch = ca.ContainerAudit._start_stopwatch.__get__(app)
    app.stopwatch_job = None
    app._update_stopwatch = lambda: None
    real_notice(app)
    public_scan(app, COMPACT_QR)
    assert app._short_confirmation_undo
    public_scan(app, 'KMCMD:UNDO')
    assert app.current_tray.start_time == original_start
    assert app.current_tray.scan_times == original_times
    assert app.current_tray.stopwatch_seconds >= original_elapsed
    assert app._save_current_tray_state()
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding='utf-8'))
    validate_tray_state(state, default_tray_size=app.TRAY_SIZE)
    assert state['start_time'] == original_start.isoformat()
    assert state['scanned_barcodes'] == [ITEM + '-SERIAL-001']
    assert windows == []


@pytest.mark.parametrize('stage', ['old', 'new'])
def test_exchange_selection_undo_leaves_existing_product_in_place(flow, windows, stage):
    app = _active(flow)
    public_scan(app, ITEM + '-SERIAL-001')
    original = app._current_tray_state_snapshot()
    public_scan(app, 'KMCMD:EXCHANGE')
    if stage == 'new':
        public_scan(app, ITEM + '-SERIAL-001')
    assert app._inline_exchange_mode == stage
    public_scan(app, 'KMCMD:UNDO')
    assert app.current_tray.scanned_barcodes == original['scanned_barcodes']
    assert [value.isoformat() for value in app.current_tray.scan_times] == original['scan_times']
    assert app.current_tray.exchange_idempotency_keys == original.get('exchange_idempotency_keys', [])
    assert app._inline_exchange_mode == ''
    assert app._inline_exchange_target == ''
    assert windows == []


def test_undo_without_active_scan_uses_existing_rejection_sound(flow, windows, monkeypatch):
    app = flow(transition=True)
    sounds = []
    monkeypatch.setattr(app, '_start_warning_beep', lambda: sounds.append('error'))
    public_scan(app, 'KMCMD:UNDO')
    assert sounds == ['error']
    assert not app.current_tray.scanned_barcodes
    assert not app.current_tray.master_label_code
    assert windows == []


def _exchange_rows(app):
    result = []
    lane = app._ui_task_lane()
    assert lane.submit(LaneTask(name='read-exchange-undo-evidence',
        generation=app._scan_callback_epoch,
        work=lambda: [dict(row) for row in app.transfer_member_exchange_coordinator.store.scan_exchange_rows()],
        finish=result.append, fail=lambda error: pytest.fail(str(error)))).accepted
    _pump_until(app.root, lambda: bool(result) and not lane.is_busy())
    return result[0]


@pytest.mark.parametrize('restore', [False, True])
@pytest.mark.parametrize('replace_last', [False, True])
def test_durable_exchange_undo_is_rejected_and_reexchange_uses_replacement(
        flow, windows, monkeypatch, restore, replace_last):
    app = _active(flow, count=4)
    app.root.tk = object()
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    # Hold the offline transport between observations; its independent retries
    # change attempt metadata without any UNDO. Wire behavior is tested separately.
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda: None)
    old, other, first, second = [ITEM + '-SERIAL-' + value for value in ('001', '002', '997', '998')]
    public_scan(app, old)
    if not replace_last:
        public_scan(app, other)
    for value in ('KMCMD:EXCHANGE', old, first):
        public_scan(app, value)
    if restore:
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding='utf-8'))
        app._restore_tray_from_state(state)
    before = app._current_tray_state_snapshot()
    records = _exchange_rows(app)
    sounds, messages = [], []
    monkeypatch.setattr(app, '_start_warning_beep', lambda: sounds.append('error'))
    show_notice = ca.ContainerAudit.show_status_message.__get__(app)
    monkeypatch.setattr(app, 'show_status_message',
        lambda message, *args, **kwargs: messages.append(message) or show_notice(message, *args, **kwargs))
    public_scan(app, 'KMCMD:UNDO')
    assert sounds == ['error']
    assert '교환은 이미 확정됨 — 바꾸려면 교환을 다시 하세요' in messages
    assert app._warning_state_presenter().state.active_notice.message == messages[-1]
    assert not app._warning_state_presenter().state.is_blocking
    assert app._current_tray_state_snapshot() == before
    assert _exchange_rows(app) == records
    for value in ('KMCMD:EXCHANGE', first, second):
        public_scan(app, value)
    assert first not in app.current_tray.scanned_barcodes
    assert second in app.current_tray.scanned_barcodes
    records = _exchange_rows(app)
    assert len(records) == 2
    assert any(json.loads(row['old_barcodes_json']) == [first]
               and json.loads(row['new_barcodes_json']) == [second] for row in records)
    assert windows == []


def test_ordinary_scan_after_exchange_can_be_undone_without_undoing_exchange(flow, windows):
    app = _active(flow, count=4)
    old, replacement, later = [ITEM + '-SERIAL-' + value for value in ('001', '997', '002')]
    for value in (old, 'KMCMD:EXCHANGE', old, replacement, later):
        public_scan(app, value)
    public_scan(app, 'KMCMD:UNDO')
    assert app.current_tray.scanned_barcodes == [replacement]
    public_scan(app, 'KMCMD:UNDO')
    assert app.current_tray.scanned_barcodes == [replacement]
    assert len(_exchange_rows(app)) == 1
    assert windows == []
