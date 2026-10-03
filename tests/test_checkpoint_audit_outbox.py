"""CSV is a retryable projection of an already durable operator action."""
import csv
import json
from pathlib import Path

import pytest
import event_log_store
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, _active, ITEM, COMPACT_QR,
    OTHER_LABEL, _pump_until, _rows,
)

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


def stop_writer(app):
    app.log_queue.put(None)
    app.log_thread.join(10)
    assert not app.log_thread.is_alive()


def audit_rows(app, event):
    if event != 'TRAY_SHORT_CONFIRMATION_UNDONE':
        return _rows(app, event)
    app.log_queue.join()
    result = []
    for path in (Path(app.save_folder) / 'local_only').glob('*.csv'):
        with path.open(encoding='utf-8-sig', newline='') as handle:
            result.extend(row for row in csv.DictReader(handle) if row['event'] == event)
    return result


@pytest.mark.parametrize('replay', ['retry', 'next_scan', 'restart'])
@pytest.mark.parametrize('action,event', [
    ('undo', 'SCAN_UNDO'), ('park', 'TRAY_PARKED'), ('reset', 'TRAY_RESET'),
    ('exchange', 'PRODUCT_EXCHANGE_COMPLETED'), ('complete', 'TRAY_COMPLETE'),
    ('short', 'TRAY_COMPLETE'), ('short_undo', 'TRAY_SHORT_CONFIRMATION_UNDONE'),
])
def test_saved_action_survives_csv_failure(flow, windows, monkeypatch, tmp_path, action, event, replay):
    app = _active(flow)
    app.parked_trays_dir = str(tmp_path / 'parked')
    app._update_parked_trays_list = lambda: None
    app._show_left_sidebar_view = lambda view: None
    app._start_stopwatch = lambda resume=False: None
    app._process_barcode_logic(ITEM + '-SERIAL-001')
    app.log_queue.join()
    append = event_log_store._append_event_log_entry_unlocked
    blocked = [True]

    def failing(path, entry, **kwargs):
        if blocked[0] and entry['event'] in {event, 'TRAY_COMPLETE'}:
            raise OSError('synthetic audit CSV failure')
        return append(path, entry, **kwargs)

    monkeypatch.setattr(event_log_store, '_append_event_log_entry_unlocked', failing)
    if action == 'undo':
        app.undo_last_scan()
        assert app.current_tray.scanned_barcodes == []
    elif action == 'park':
        assert app.park_current_tray() is True
        assert app.current_tray.master_label_code == ''
        assert len(list(Path(app.parked_trays_dir).glob('*.json'))) == 1
    elif action == 'reset':
        app.reset_current_work()
        assert app.current_tray.master_label_code == ''
    elif action == 'exchange':
        for value in ('KMCMD:EXCHANGE', ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'):
            app._process_barcode_logic(value)
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
        assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-999']
    elif action == 'complete':
        app._process_barcode_logic(ITEM + '-SERIAL-002')
        app._process_barcode_logic(ITEM + '-SERIAL-003')
        assert app.current_tray.master_label_code == ''
    else:
        app._process_barcode_logic(COMPACT_QR)
        assert app._short_confirmation_undo
        if action == 'short_undo':
            assert app._undo_short_confirmation() is True
            assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
        else:
            assert app._commit_short_confirmation() is True
    assert Path(app.save_folder, '_event_outbox').exists() or any(
        'pending_audit_events' in path.read_text(encoding='utf-8')
        for path in Path(app.save_folder).rglob('*.json')
    ), 'the original audit must survive independently of RAM'
    if replay == 'restart':
        stop_writer(app)
        blocked[0] = False
        restarted = flow(transition=False, root=Path(app.save_folder))
        restarted.log_queue.join()
        assert restarted._flush_pending_event_logs()
        projection_app = restarted
    elif replay == 'next_scan':
        blocked[0] = False
        app._process_barcode_logic(f'{OTHER_LABEL}|QT=2' if not app.current_tray.master_label_code
                                   else ITEM + '-SERIAL-002')
        projection_app = app
    else:
        blocked[0] = False
        assert app._flush_pending_event_logs()
        projection_app = app
    rows = audit_rows(projection_app, event)
    assert len(rows) == 1
    original = dict(rows[0])
    assert json.loads(original['details'])['idempotency_key']
    assert original['worker_name'] == 'tester'
    for _ in range(2):
        assert projection_app._flush_pending_event_logs()
    assert audit_rows(projection_app, event) == [original]
    if action == 'short_undo':
        assert len(_rows(projection_app, 'TRAY_COMPLETE')) == 1
    assert windows == []


def test_synchronous_audit_replays_original_worker_time_and_path(flow, monkeypatch, tmp_path):
    app = flow(transition=False)
    stop_writer(app)
    original_path = app.log_file_path
    original_time = '2026-09-30T08:09:10'
    append = event_log_store._append_event_log_entry_unlocked
    with monkeypatch.context() as fault:
        fault.setattr(event_log_store, '_append_event_log_entry_unlocked',
                      lambda *a, **kw: (_ for _ in ()).throw(OSError('synthetic CSV failure')))
        assert app._log_event('TRAY_PARKED', detail={'master_label_code': COMPACT_QR},
                              synchronous=True, event_timestamp=original_time)
    app.worker_name = 'later-worker'
    app.log_file_path = str(tmp_path / 'later.csv')
    assert app._flush_pending_event_logs()
    app.log_file_path = original_path
    row, = _rows(app, 'TRAY_PARKED')
    assert row['worker_name'] == 'tester'
    assert row['timestamp'] == original_time
    assert not Path(tmp_path / 'later.csv').exists()


@pytest.mark.parametrize('action,event', [('undo', 'SCAN_UNDO'), ('park', 'TRAY_PARKED'),
                                        ('reset', 'TRAY_RESET'),
                                        ('short_undo', 'TRAY_SHORT_CONFIRMATION_UNDONE')])
def test_crash_between_checkpoint_and_outbox_staging_replays_once(flow, windows, monkeypatch, tmp_path, action, event):
    app = _active(flow)
    app.parked_trays_dir = str(tmp_path / 'parked')
    app._update_parked_trays_list = lambda: None
    app._show_left_sidebar_view = lambda view: None
    app._start_stopwatch = lambda resume=False: None
    app._process_barcode_logic(ITEM + '-SERIAL-001')
    if action == 'short_undo':
        app._process_barcode_logic(COMPACT_QR)
    app.log_queue.join()
    stop_writer(app)
    def power_loss(state):
        if any(e['log_entry']['event'] == event for e in state.get('pending_audit_events', [])):
            raise SystemExit('synthetic crash after atomic checkpoint')
        return True
    monkeypatch.setattr(app, '_stage_checkpoint_audit_events', power_loss)
    with pytest.raises(SystemExit, match='synthetic crash'):
        {'undo': app.undo_last_scan, 'park': app.park_current_tray,
         'reset': app.reset_current_work, 'short_undo': app._undo_short_confirmation}[action]()
    restarted = flow(transition=False, root=Path(app.save_folder))
    restarted.parked_trays_dir = app.parked_trays_dir
    assert restarted._flush_pending_event_logs()
    row, = audit_rows(restarted, event)
    assert json.loads(row['details'])['idempotency_key']
    assert restarted._flush_pending_event_logs()
    assert audit_rows(restarted, event) == [row]
    assert windows == []


def test_undo_checkpoint_keeps_audit_when_outbox_storage_is_unavailable(flow, monkeypatch):
    app = _active(flow)
    app._process_barcode_logic(ITEM + '-SERIAL-001')
    with monkeypatch.context() as fault:
        fault.setattr(event_log_store.EventLogOutbox, '_persist_unstaged',
                      lambda self: (_ for _ in ()).throw(OSError('synthetic outbox failure')))
        app.undo_last_scan()
        assert app.current_tray.scanned_barcodes == []
        path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
        state = json.loads(path.read_text(encoding='utf-8'))
        row, = [e for e in state['pending_audit_events'] if e['log_entry']['event'] == 'SCAN_UNDO']
        app._process_barcode_logic(ITEM + '-SERIAL-002')
        assert row in json.loads(path.read_text(encoding='utf-8'))['pending_audit_events']
    assert app._flush_pending_event_logs()
    assert len(_rows(app, 'SCAN_UNDO')) == 1


def test_exchange_rejection_and_later_undo_replay_original_events(flow, windows, monkeypatch):
    app = _active(flow)
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    app._process_barcode_logic(old)
    append = event_log_store._append_event_log_entry_unlocked
    with monkeypatch.context() as fault:
        def fail(path, entry, **kwargs):
            if entry['event'] in {'PRODUCT_EXCHANGE_COMPLETED', 'SCAN_UNDO'}:
                raise OSError('synthetic exchange/undo CSV failure')
            return append(path, entry, **kwargs)
        fault.setattr(event_log_store, '_append_event_log_entry_unlocked', fail)
        for value in ('KMCMD:EXCHANGE', old, new):
            app._process_barcode_logic(value)
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
        before = app._current_tray_state_snapshot()
        app.undo_last_scan()
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
        # sub-228 decision: a durable exchange is final even while CSV retries.
        assert app._current_tray_state_snapshot() == before
        assert app.current_tray.scanned_barcodes == [new]
        assert _rows(app, 'SCAN_UNDO') == []
        later = ITEM + '-SERIAL-002'
        app._process_barcode_logic(later)
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
        app.undo_last_scan()
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
        assert app.current_tray.scanned_barcodes == [new]
    assert app._flush_pending_event_logs()
    exchange, = _rows(app, 'PRODUCT_EXCHANGE_COMPLETED')
    undone, = _rows(app, 'SCAN_UNDO')
    assert json.loads(exchange['details'])['defective_barcodes'] == [old]
    assert json.loads(exchange['details'])['good_barcodes'] == [new]
    assert json.loads(undone['details'])['undone_barcode'] == later
    assert app._flush_pending_event_logs()
    assert _rows(app, 'PRODUCT_EXCHANGE_COMPLETED') == [exchange]
    assert _rows(app, 'SCAN_UNDO') == [undone]
    assert windows == []


def test_unreadable_parked_checkpoint_preserves_source_and_does_not_stop_other_audits(flow, tmp_path):
    app = flow(transition=False)
    app.parked_trays_dir = str(tmp_path / 'parked')
    Path(app.parked_trays_dir).mkdir()
    corrupt = Path(app.parked_trays_dir) / 'parked-broken.json'
    corrupt.write_bytes(b'original unreadable checkpoint')
    assert app._log_event('WORK_PAUSE', detail={'reason': 'fixture'}, synchronous=False)
    app.log_queue.join()
    assert app._flush_pending_event_logs()
    assert len(_rows(app, 'WORK_PAUSE')) == 1
    assert corrupt.read_bytes() == b'original unreadable checkpoint'
