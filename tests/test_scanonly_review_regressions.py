"""Regressions from independent review: scanner admission and durable exchanges."""
import csv
import json
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
import pytest
import Container_Audit as ca
import writer_session_fence as fence
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, _active, _own_coordinators_on_lane, OfflineSealClient,
    COMPACT_QR, OTHER_LABEL, ITEM, _resolved, _pump_until, _rows,
)
from tests.test_observed_scanner_completion import ScannerEntry

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')

def public_scan(app, value):
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    if not getattr(app, 'scan_entry', None):
        app.scan_entry = ScannerEntry('')
    app.scan_entry.insert(0, value)
    app.process_barcode()
    _pump_until(app.root, lambda: not getattr(app, '_scan_callback_pending', False)
                and not app._ui_task_lane().is_busy())

def real_notice(app):
    vars(app).pop('show_fullscreen_warning', None)
    app._start_warning_beep = lambda: None
    app._stop_warning_beep = lambda: None
    app._render_warning_state = lambda: None


class ScannerUndoButton:
    """Tk button adapter: a disabled control cannot invoke its command."""
    def __init__(self, command):
        self.options = {'state': ca.tk.DISABLED, 'command': command}

    def configure(self, **options):
        self.options.update(options)

    def __getitem__(self, key):
        return self.options[key]

    def __setitem__(self, key, value):
        self.options[key] = value

    def invoke(self):
        if self.options['state'] == ca.tk.NORMAL:
            return self.options['command']()


@pytest.mark.parametrize('action', ['short', 'park'])
def test_waiting_undo_button_restores_the_last_field_action(flow, windows, tmp_path, action):
    app = _active(flow)
    app.root.tk = object()
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    app.undo_button = ScannerUndoButton(app.undo_last_scan)
    vars(app).pop('_update_action_button_states', None)
    app.parked_trays_dir = str(tmp_path / 'parked')
    app._update_parked_trays_list = lambda: None
    app._show_left_sidebar_view = lambda view: None
    app._start_stopwatch = lambda resume=False: None
    app.show_validation_screen = lambda: pytest.fail('UNDO keeps the scanner surface')
    public_scan(app, ITEM + '-SERIAL-001')
    real_notice(app)
    if action == 'short':
        public_scan(app, COMPACT_QR)
        assert app._partial_submission_state() is not None
        assert app._continue_partial_submission()
        ca.ContainerAudit._update_action_button_states(app)
        assert app.undo_button["state"] == ca.tk.NORMAL
        app.undo_button.invoke()
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
        assert app.current_tray.master_label_code == COMPACT_QR
        assert app.current_tray.scanned_barcodes == []
        assert windows == []
        return
    else:
        assert app.park_current_tray() is True
        assert Path(app._parked_tray_undo['path']).is_file()
    assert app.current_tray.master_label_code == ''
    assert app.undo_button['state'] == ca.tk.NORMAL
    ca.ContainerAudit._update_action_button_states(app)
    assert app.undo_button['state'] == ca.tk.NORMAL
    app.undo_button.invoke()
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
    assert windows == []

@pytest.mark.parametrize('following', ['undo', 'next_label'])
def test_public_scanner_continues_after_short_notice(flow, windows, following):
    app = _active(flow)
    app.root.tk = object()
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    public_scan(app, ITEM + '-SERIAL-001')
    real_notice(app)
    public_scan(app, COMPACT_QR)
    assert app._partial_submission_state() is not None
    public_scan(app, "")
    assert app._short_confirmation_undo is None
    assert not app.current_tray.master_label_code
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    app.scan_entry = ScannerEntry('KMCMD:UNDO' if following == 'undo' else OTHER_LABEL + '|QT=1')
    app.process_barcode()
    _pump_until(app.root, lambda: not getattr(app, '_scan_callback_pending', False)
                and not app._ui_task_lane().is_busy())
    if following == 'undo':
        assert not app.current_tray.master_label_code
    else:
        assert app.current_tray.master_label_code == OTHER_LABEL + '|QT=1', str(app.statuses[-3:])
    assert windows == []

def test_public_scanner_refuses_during_nonmember_notice_then_accepts_member_after_ack(flow, windows):
    app = _active(flow)
    real_notice(app)
    public_scan(app, ITEM + '-OUTSIDE-999')
    assert app.current_tray.scanned_barcodes == []
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    # D-01: 띠가 떠 있는 동안의 스캔은 받지 않고 보이게 거절한다. 확인한 뒤 다시 찍으면 받는다.
    app.scan_entry = ScannerEntry(ITEM + '-SERIAL-001')
    app.process_barcode()
    assert app.current_tray.scanned_barcodes == [] and app._warning_state_presenter().state.is_blocking
    assert app._scan_refusal_visible is True
    app.scan_entry = ScannerEntry('')
    app.process_barcode()  # 빈 Enter = 확인
    assert not app._warning_state_presenter().state.is_blocking
    app.scan_entry = ScannerEntry(ITEM + '-SERIAL-001')
    app.process_barcode()
    if app.root.jobs:
        _pump_until(app.root, lambda: not getattr(app, '_scan_callback_pending', False))
    assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001'], str(app.statuses[-3:])
    assert windows == []


def test_empty_scanner_enter_acknowledges_a_field_notice(flow, windows):
    app = _active(flow)
    real_notice(app)
    app.show_fullscreen_warning('입력 확인', '제품을 다시 스캔하세요.', app.COLOR_DANGER)
    app.scan_entry = ScannerEntry('')
    app.process_barcode()
    assert not app._warning_state_presenter().state.is_blocking
    assert app.current_tray.scanned_barcodes == [] and windows == []

@pytest.mark.parametrize('seven', [False, True])
def test_exchanged_tray_can_complete_at_target(flow, windows, seven):
    app = _active(flow) if not seven else flow(transition=False, client=OfflineSealClient(_resolved(3)))
    if seven:
        app._process_barcode_logic(COMPACT_QR + '|QT=3')
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    original_lease = app.current_tray.operation_lease_id
    app._process_barcode_logic(old)
    app._process_barcode_logic('KMCMD:EXCHANGE')
    app._process_barcode_logic(old)
    app._process_barcode_logic(new)
    _pump_until(app.root, lambda: app.current_tray.scanned_barcodes == [new])
    assert app.current_tray.operation_lease_id == original_lease
    for number in (2, 3):
        app._process_barcode_logic(ITEM + f'-SERIAL-{number:03d}')
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1, str(app.statuses[-5:])
    assert app.current_tray.master_label_code == ''
    assert windows == []

def test_exchange_audit_failure_preserves_replacement_in_current_state(flow, windows, monkeypatch):
    app = _active(flow)
    old, first, second = [ITEM + suffix for suffix in ('-SERIAL-001', '-SERIAL-991', '-SERIAL-992')]
    app._process_barcode_logic(old)
    original = app._log_event
    fail_once = [True]
    def event(event, **kwargs):
        if event == 'PRODUCT_EXCHANGE_COMPLETED' and fail_once[0]:
            fail_once[0] = False
            return False
        return original(event, **kwargs)
    monkeypatch.setattr(app, '_log_event', event)
    # Keep central transport out until the local failure has been observed;
    # this is the same disconnected local boundary covered by the task.
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    app._process_barcode_logic('KMCMD:EXCHANGE')
    app._process_barcode_logic(old)
    app._process_barcode_logic(first)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    assert json.loads(path.read_text(encoding='utf-8'))['scanned_barcodes'] == [first]
    # A subsequent product arrives after the failed audit, without a new
    # exchange command. It must not silently overwrite the accepted replacement.
    app._process_barcode_logic(second)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    state = json.loads(path.read_text(encoding='utf-8'))
    assert first in state['scanned_barcodes'], {
        'memory': app.current_tray.scanned_barcodes, 'durable': state['scanned_barcodes'],
        'statuses': app.statuses[-4:],
    }

def test_exchange_recovery_replays_intent_after_later_durable_scan(flow, windows, monkeypatch):
    app = _active(flow)
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    app._process_barcode_logic(old)
    original_event, original_transport = app._log_event, app._schedule_scanonly_transport
    failed = [False]
    def event(event, **kwargs):
        if event == 'PRODUCT_EXCHANGE_COMPLETED' and not failed[0]:
            failed[0] = True
            return False
        return original_event(event, **kwargs)
    monkeypatch.setattr(app, '_log_event', event)
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    app._process_barcode_logic('KMCMD:EXCHANGE')
    app._process_barcode_logic(old)
    app._process_barcode_logic(new)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    # Restore the actual saved checkpoint, as the supported restart path does.
    app._restore_tray_from_state(json.loads(path.read_text(encoding='utf-8')))
    app._inline_exchange_mode = ''
    app._inline_exchange_target = ''
    app._process_barcode_logic(ITEM + '-SERIAL-002')
    assert app.current_tray.scanned_barcodes == [new, ITEM + '-SERIAL-002']
    monkeypatch.setattr(app, '_schedule_scanonly_transport', original_transport)
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    with sqlite3.connect(app.transfer_seal_coordinator.store.db_path) as connection:
        states = [row[0] for row in connection.execute('SELECT state FROM transfer_scan_exchanges')]
    assert states == ['READY'], {'exchange_states': states,
        'checkpoint': json.loads(path.read_text(encoding='utf-8'))['scanned_barcodes'],
        'review_count': getattr(app, '_scanonly_review_count', None)}

def test_exchange_recovery_preserves_an_unrelated_checkpoint_for_review(flow, windows, monkeypatch):
    app = _active(flow)
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    public_scan(app, old)
    transport, log = app._schedule_scanonly_transport, app._log_event
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    monkeypatch.setattr(app, '_log_event', lambda event, **kwargs:
                        False if event == 'PRODUCT_EXCHANGE_COMPLETED' else log(event, **kwargs))
    for value in ('KMCMD:EXCHANGE', old, new):
        public_scan(app, value)
    state = app._current_tray_state_snapshot()
    state['master_label_code'] = OTHER_LABEL + '|QT=3'
    state['exchange_idempotency_keys'] = []
    app._restore_tray_from_state(state)
    assert app._save_current_tray_state()
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    preserved = path.read_bytes()
    monkeypatch.setattr(app, '_schedule_scanonly_transport', transport)
    monkeypatch.setattr(app, '_log_event', log)
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    assert path.read_bytes() == preserved
    assert app._scanonly_review_count == 1 and app._scanonly_transport_retry_job
    with sqlite3.connect(app.transfer_seal_coordinator.store.db_path) as connection:
        assert connection.execute('SELECT state FROM transfer_scan_exchanges').fetchall() == [('LOCAL_PENDING',)]
    assert _rows(app, 'PRODUCT_EXCHANGE_COMPLETED') == [] and windows == []


@pytest.mark.parametrize('delayed_phase', ['product', 'completion'])
def test_next_label_during_final_product_save_is_retained(flow, windows, monkeypatch, delayed_phase):
    app = flow(transition=False, client=OfflineSealClient(_resolved(1)))
    app._process_barcode_logic(COMPACT_QR + '|QT=1')
    app.root.tk = object()  # Select production scanner persistence without Tk.
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    entered, release = threading.Event(), threading.Event()
    save = app._save_tray_state_snapshot
    log = app._log_event
    first = [True]
    def delayed(state):
        if delayed_phase == 'product' and first[0] and state['scanned_barcodes']:
            first[0] = False
            entered.set()
            assert release.wait(10), 'probe owns delayed local write'
        return save(state)
    monkeypatch.setattr(app, '_save_tray_state_snapshot', delayed)
    def delayed_log(event, **kwargs):
        if delayed_phase == 'completion' and event == 'TRAY_COMPLETE' and first[0]:
            first[0] = False
            entered.set()
            assert release.wait(10), 'probe owns delayed completion write'
        return log(event, **kwargs)
    monkeypatch.setattr(app, '_log_event', delayed_log)
    app.scan_entry = ScannerEntry(ITEM + '-SERIAL-001')
    following = OTHER_LABEL + '|QT=1'
    try:
        app.process_barcode()
        _pump_until(app.root, entered.is_set)
        assert app.scan_entry.state == 'normal'
        app.scan_entry.insert(0, following)
        app.process_barcode()
        product = ITEM + '-SERIAL-002'
        app.scan_entry.insert(0, product)
        app.process_barcode()
        assert app._scans_behind_save == [following, product]
        release.set()
        _pump_until(app.root, lambda: len(_rows(app, 'TRAY_COMPLETE')) == 2
                    and not app._ui_task_lane().is_busy())
        assert app.current_tray.master_label_code == ''
        assert app._scans_behind_save == []
        details = [json.loads(row['details']) for row in _rows(app, 'TRAY_COMPLETE')]
        assert [row['product_barcodes'] for row in details] == [[ITEM + '-SERIAL-001'], [product]]
        assert windows == []
    finally:
        release.set()

def test_automatic_other_worker_restore_uses_inline_notice(flow, windows, monkeypatch):
    app = flow(transition=False)
    snapshot = SimpleNamespace(worker='another-operator', state='WAITING_LABEL', master_raw=COMPACT_QR,
                               to_payload=lambda: {'worker': 'another-operator'})
    monkeypatch.setattr(app, '_preflight_hold_store', lambda: SimpleNamespace(
        exists=lambda: True, load=lambda: snapshot))
    monkeypatch.setattr(app, '_paired_preflight_store', lambda: SimpleNamespace(
        unidentified_pending=lambda: False))
    monkeypatch.setattr(app, '_paired_preflight_blocks_label', lambda label: False)
    monkeypatch.setattr(app, '_is_preflight_hold_supervisor', lambda: True)
    quarantined = []
    monkeypatch.setattr(app, '_quarantine_preflight_hold_for_supervisor', lambda **kwargs: quarantined.append(kwargs) or True)
    assert app._restore_preflight_scan_hold() is True
    assert quarantined == []
    # G6 coordinator decision: preserve foreign bytes in place and keep input
    # open for other labels; operating on this hold still uses the PIN path.
    assert not getattr(app, '_inline_scan_choices', None)
    assert not app._preflight_scan_input_locked
    assert app._preflight_hold_snapshot is None
    assert windows == [], windows


@pytest.mark.parametrize('audit_failure', ['before_write', 'lost_ack'])
@pytest.mark.parametrize('completion_kind', ['target', 'short'])
@pytest.mark.parametrize('log_rotated', [False, True])
def test_exchange_audit_replays_after_local_completion(flow, windows, monkeypatch, audit_failure, completion_kind, log_rotated):
    app = _active(flow)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    app._process_barcode_logic(old)
    original_log, transport = app._log_event, app._schedule_scanonly_transport
    failed = []
    def log(event, **kwargs):
        if event == 'PRODUCT_EXCHANGE_COMPLETED' and not failed:
            failed.append(True)
            if audit_failure == 'lost_ack':
                assert original_log(event, **kwargs)
                raise OSError('synthetic exchange audit ACK loss')
            return False
        return original_log(event, **kwargs)
    monkeypatch.setattr(app, '_log_event', log)
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    for value in ('KMCMD:EXCHANGE', old, new):
        public_scan(app, value)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    assert app.current_tray.scanned_barcodes == [new]
    if completion_kind == 'short':
        public_scan(app, COMPACT_QR)
        assert app._partial_submission_state() is not None
        public_scan(app, "")
        assert app._short_confirmation_undo is None
    else:
        for number in (2, 3):
            public_scan(app, ITEM + f'-SERIAL-{number:03d}')
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert app.current_tray.master_label_code == ''
    original_log_path, original_worker = app.log_file_path, app.worker_name
    if log_rotated:
        app.log_file_path = str(Path(app.save_folder) / 'next-shift.csv')
        app.worker_name = 'next-operator'
    monkeypatch.setattr(app, '_schedule_scanonly_transport', transport)
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    with sqlite3.connect(app.transfer_seal_coordinator.store.db_path) as connection:
        assert [row[0] for row in connection.execute('SELECT state FROM transfer_scan_exchanges')] == ['READY']
    with open(original_log_path, encoding='utf-8-sig', newline='') as handle:
        rows = [row for row in csv.DictReader(handle) if row['event'] == 'PRODUCT_EXCHANGE_COMPLETED']
    assert len(rows) == 1 and rows[0]['worker_name'] == original_worker
    if log_rotated:
        assert _rows(app, 'PRODUCT_EXCHANGE_COMPLETED') == []
    assert app.current_tray.master_label_code == '' and windows == []


@pytest.mark.parametrize('audit_failure', ['before_write', 'lost_ack'])
def test_exchange_for_an_unscanned_member_completes_at_target_after_audit_failure(flow, windows, monkeypatch, audit_failure):
    app = _active(flow)
    for number in (1, 2):
        public_scan(app, ITEM + f'-SERIAL-{number:03d}')
    original_log, transport = app._log_event, app._schedule_scanonly_transport
    failed = []
    def log(event, **kwargs):
        if event == 'PRODUCT_EXCHANGE_COMPLETED' and not failed:
            failed.append(True)
            if audit_failure == 'lost_ack':
                assert original_log(event, **kwargs)
                raise OSError('synthetic exchange audit ACK loss at target')
            return False
        return original_log(event, **kwargs)
    monkeypatch.setattr(app, '_log_event', log)
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    replacement = ITEM + '-SERIAL-999'
    for value in ('KMCMD:EXCHANGE', ITEM + '-SERIAL-003', replacement):
        public_scan(app, value)
    _pump_until(app.root, lambda: len(_rows(app, 'TRAY_COMPLETE')) == 1
                and not app._ui_task_lane().is_busy())
    detail = json.loads(_rows(app, 'TRAY_COMPLETE')[0]['details'])
    assert detail['product_barcodes'] == [ITEM + '-SERIAL-001', ITEM + '-SERIAL-002', replacement]
    monkeypatch.setattr(app, '_schedule_scanonly_transport', transport)
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    assert len(_rows(app, 'PRODUCT_EXCHANGE_COMPLETED')) == 1
    assert app.current_tray.master_label_code == '' and windows == []


@pytest.mark.parametrize('at_target', [False, True])
def test_exchange_checkpoint_retry_keeps_the_prepared_replacement(flow, windows, monkeypatch, at_target):
    app = _active(flow)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    old, new = ITEM + ('-SERIAL-003' if at_target else '-SERIAL-001'), ITEM + '-SERIAL-999'
    for number in ((1, 2) if at_target else (1,)):
        public_scan(app, ITEM + f'-SERIAL-{number:03d}')
    before = list(app.current_tray.scanned_barcodes)
    save, transport = app._save_tray_state_snapshot, app._schedule_scanonly_transport
    failed = []
    def failing_save(state):
        if state.get('exchange_idempotency_keys') and not failed:
            failed.append(True)
            return False
        return save(state)
    monkeypatch.setattr(app, '_save_tray_state_snapshot', failing_save)
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    for value in ('KMCMD:EXCHANGE', old, new):
        public_scan(app, value)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    assert app.current_tray.scanned_barcodes == before
    app.scan_entry.insert(0, ITEM + '-SERIAL-998')
    app.process_barcode()
    assert app.current_tray.scanned_barcodes == before
    monkeypatch.setattr(app, '_schedule_scanonly_transport', transport)
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    if at_target:
        _pump_until(app.root, lambda: len(_rows(app, 'TRAY_COMPLETE')) == 1
                    and not app._ui_task_lane().is_busy())
        detail = json.loads(_rows(app, 'TRAY_COMPLETE')[0]['details'])
        assert detail['product_barcodes'] == [*before, new]
        assert app.current_tray.master_label_code == ''
    else:
        assert app.current_tray.scanned_barcodes == [new]
    assert app._scan_entry_admission_block_reason() == ''
    assert len(_rows(app, 'PRODUCT_EXCHANGE_COMPLETED')) == 1 and windows == []


def test_checkpoint_recovery_waits_for_an_admitted_save_without_lock_inversion(flow, windows, monkeypatch):
    app = _active(flow)
    app.root.tk = object()
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    public_scan(app, old)
    # Schema initialization also needs writer admission; finish it before
    # deliberately holding the save admission to exercise checkpoint ordering.
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    save, transport = app._save_tray_state_snapshot, app._schedule_scanonly_transport
    monkeypatch.setattr(app, '_save_tray_state_snapshot', lambda state:
        False if state.get('exchange_idempotency_keys') else save(state))
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    for value in ('KMCMD:EXCHANGE', old, new):
        public_scan(app, value)
    assert app._local_exchange_checkpoint_pending is app.current_tray
    before = app._current_tray_state_snapshot()
    monkeypatch.setattr(app, '_save_tray_state_snapshot', save)
    monkeypatch.setattr(app, '_schedule_scanonly_transport', transport)
    held, release, saved, recovery_waiting = [threading.Event() for _ in range(4)]
    admission = fence.writer_admission
    @contextmanager
    def observed_admission(source, **kwargs):
        central = getattr(app, '_central_transport_lane', None)
        if (source == 'gui_tray_state_save' and central is not None
                and threading.get_ident() == central.worker_thread_id):
            recovery_waiting.set()
        with admission(source, **kwargs):
            yield
    monkeypatch.setattr(fence, 'writer_admission', observed_admission)
    monkeypatch.setattr(ca, 'writer_admission', observed_admission, raising=False)
    def admitted_save():
        with fence.writer_admission('gui_tray_state_save'):
            held.set()
            assert release.wait(timeout=5)
            result = save(before)
            saved.set()
            return result
    def steps():
        return (yield admitted_save)
    try:
        assert app._submit_scan_steps(steps())
        _pump_until(app.root, held.is_set)
        assert app._schedule_scanonly_transport()
        _pump_until(app.root, recovery_waiting.is_set)
        release.set()
        _pump_until(app.root, saved.is_set, timeout=3,
                    phase='admitted save must finish before the five-second mutex timeout')
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy()
                    and not app._central_transport_lane.is_busy())
        assert app.current_tray.scanned_barcodes == [new]
        assert app._scan_entry_admission_block_reason() == ''
        assert len(_rows(app, 'PRODUCT_EXCHANGE_COMPLETED')) == 1 and windows == []
    finally:
        release.set()
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy()
                    and not getattr(getattr(app, '_central_transport_lane', None), 'is_busy', lambda: False)())


@pytest.mark.parametrize('next_label', [False, True])
def test_park_button_saves_without_confirmation_and_scanner_undo_is_scoped(flow, windows, tmp_path, next_label):
    app = _active(flow)
    app.parked_trays_dir = str(tmp_path / 'parked')
    app._update_parked_trays_list = lambda: None
    app._show_left_sidebar_view = lambda view: None
    app.undo_button = {'state': ca.tk.DISABLED}
    app._start_stopwatch = lambda resume=False: None
    app.show_validation_screen = lambda: pytest.fail('park UNDO stays on the scanner surface')
    public_scan(app, ITEM + '-SERIAL-001')
    assert app.park_current_tray() is True
    assert app.current_tray.master_label_code == '' and windows == []
    parked = Path(app._parked_tray_undo['path'])
    assert parked.is_file() and len(_rows(app, 'TRAY_PARKED')) == 1
    if next_label:
        public_scan(app, OTHER_LABEL + '|QT=1')
    public_scan(app, 'KMCMD:UNDO')
    if next_label:
        assert app.current_tray.master_label_code == OTHER_LABEL + '|QT=1'
        assert app.current_tray.scanned_barcodes == [] and parked.is_file()
    else:
        assert app.current_tray.master_label_code == COMPACT_QR
        assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
        assert app.scanned_listbox.rows == [app._format_scanned_list_row(1, ITEM + '-SERIAL-001')]
        assert app.undo_button['state'] == ca.tk.NORMAL
        assert not parked.exists() and len(_rows(app, 'TRAY_RESTORED_FROM_PARK')) == 1
    assert windows == []
