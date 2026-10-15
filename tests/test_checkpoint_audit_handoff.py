"""Pending audits survive short-completion handoff and exchange recovery."""
import csv
import json
import sqlite3
from pathlib import Path
import pytest
import event_log_store
from tests.test_w9scanonly_workflow import _pump_until
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, _active, ITEM, COMPACT_QR, _rows,
)
from tests.test_checkpoint_audit_outbox import stop_writer
from tests.test_w9scanonly_workflow import OfflineSealClient
from tests.test_phs2_master_preflight import _resolved
from transfer_seal import TransferSealError
from tests.test_scanonly_review_regressions import public_scan

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')

def _persisted_undo_rows(app):
    # The log writer is deliberately stopped in this probe. A failure diagnostic
    # must read its committed CSV without waiting on queued asynchronous notices.
    with open(app.log_file_path, encoding='utf-8-sig', newline='') as handle:
        return [row for row in csv.DictReader(handle) if row['event'] == 'SCAN_UNDO']

@pytest.mark.parametrize('followup', ['settle', 'undo'])
@pytest.mark.parametrize('legacy_nested', [False, True])
def test_pending_undo_audit_survives_short_completion_after_outbox_failure(flow, windows, monkeypatch, followup, legacy_nested):
    app = _active(flow)
    app._process_barcode_logic(ITEM + '-SERIAL-001')
    app._process_barcode_logic(ITEM + '-SERIAL-002')
    app.log_queue.join()
    stop_writer(app)
    root = Path(app.save_folder)
    with monkeypatch.context() as fault:
        def unavailable(self):
            raise OSError('synthetic outbox unavailable while checkpoint remains writable')
        fault.setattr(event_log_store.EventLogOutbox, '_persist_unstaged', unavailable)
        app.undo_last_scan()
        checkpoint = json.loads((root / app.CURRENT_TRAY_STATE_FILE).read_text(encoding='utf-8'))
        pending, = [e for e in checkpoint['pending_audit_events'] if e['log_entry']['event'] == 'SCAN_UNDO']
        assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
        app._process_barcode_logic(COMPACT_QR)
        assert app._partial_submission_state() is not None
        assert app._confirm_partial_submission()
        assert not app.current_tray.master_label_code
        short_path, = app._short_projection_path("unused").parent.glob("*.json")
        short = json.loads(short_path.read_bytes())
        completion_id = short['contract']['idempotency_key']
        short_path = app._short_projection_path(completion_id)
        short = json.loads(short_path.read_text(encoding='utf-8'))
        assert pending in short['state']['pending_audit_events']
        assert not (root / app.CURRENT_TRAY_STATE_FILE).exists()
        assert not _persisted_undo_rows(app)
    if legacy_nested:
        # The preceding release stored the original rows only in state.
        short.pop('pending_audit_events', None)
        short_path.write_text(json.dumps(short), encoding='utf-8')
    # A new instance loses the old instance's unstaged RAM rows; every source
    # file remains unchanged. Only durable product recovery may replay them.
    restarted = flow(transition=False, root=root)
    if followup == 'settle':
        assert restarted._settle_short_completion_projection(completion_id)
    else:
        recovered = restarted._recover_short_completion_projections(restarted.transfer_seal_coordinator)
        assert "error" not in recovered
        assert not restarted._undo_short_confirmation()
    assert restarted._flush_pending_event_logs()
    rows = _rows(restarted, 'SCAN_UNDO')
    assert len(rows) == 1, {'followup': followup, 'undo_rows': rows,
        'nested_audit_survives': pending in short['state']['pending_audit_events'],
        'key': json.loads(pending['log_entry']['details'])['idempotency_key']}
    assert rows[0] == pending['log_entry']
    for _ in range(2):
        assert restarted._flush_pending_event_logs()
    assert _rows(restarted, 'SCAN_UNDO') == rows
    recovered = json.loads(short_path.read_text(encoding='utf-8'))
    assert not recovered['state'].get('pending_audit_events')
    assert not recovered.get('pending_audit_events')
    assert not recovered.get('undo_state', {}).get('pending_audit_events')
    assert windows == []


def test_source_not_available_review_allows_the_next_product_scan(flow, windows):
    class RejectedSourceClient(OfflineSealClient):
        def replace_bundle_members(self, command):
            raise TransferSealError('SOURCE_NOT_AVAILABLE', 'synthetic source refusal',
                                    status_code=409, retryable=False)

    app = _active(flow, client=RejectedSourceClient(_resolved(3)))
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    app._process_barcode_logic(old)
    for value in ('KMCMD:EXCHANGE', old, new):
        app._process_barcode_logic(value)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    with sqlite3.connect(app.transfer_member_exchange_coordinator.store.db_path) as connection:
        assert connection.execute('SELECT status,last_error_code FROM transfer_member_exchange_intents').fetchall() == [
            ('OPERATOR_REVIEW', 'SOURCE_NOT_AVAILABLE')]
    assert app._scanonly_review_count == 1
    assert app._scan_entry_admission_block_reason() == ''
    public_scan(app, ITEM + '-SERIAL-002')
    assert app.current_tray.scanned_barcodes == [new, ITEM + '-SERIAL-002']
    assert windows == []


def test_nested_audit_cleanup_keeps_a_newer_checkpoint_row(flow):
    app = flow(transition=False)
    stop_writer(app)
    first = app._checkpoint_audit_event('SCAN_UNDO', detail={'undone_barcode': ITEM + '-SERIAL-001'})
    second = app._checkpoint_audit_event('SCAN_UNDO', detail={'undone_barcode': ITEM + '-SERIAL-002'})
    path = app._short_projection_path('fixture-nested-audits')
    path.parent.mkdir()
    record = {'state': {'pending_audit_events': [first]}}
    path.write_text(json.dumps(record), encoding='utf-8')
    staged = app._recover_checkpoint_audit_events()
    assert len(staged) == 1
    app._event_log_outbox(app.log_file_path).drain()
    record['state']['pending_audit_events'].append(second)
    path.write_text(json.dumps(record), encoding='utf-8')
    app._clear_projected_checkpoint_audits(staged)
    assert json.loads(path.read_text(encoding='utf-8')) == record
    assert app._flush_pending_event_logs()
    assert _rows(app, 'SCAN_UNDO') == [first['log_entry'], second['log_entry']]
    assert not json.loads(path.read_text(encoding='utf-8'))['state'].get('pending_audit_events')


def test_exchange_checkpoint_retry_ignores_an_already_projected_pending_audit(flow, windows, monkeypatch):
    app = _active(flow)
    old, new = ITEM + '-SERIAL-001', ITEM + '-SERIAL-999'
    app._process_barcode_logic(old)
    app._process_barcode_logic(ITEM + '-SERIAL-002')
    app.log_queue.join()
    stop_writer(app)
    append = event_log_store._append_event_log_entry_unlocked
    blocked = [True]
    def csv(path, entry, **kwargs):
        if blocked[0] and entry['event'] == 'SCAN_UNDO':
            raise OSError('synthetic delayed undo audit')
        return append(path, entry, **kwargs)
    monkeypatch.setattr(event_log_store, '_append_event_log_entry_unlocked', csv)
    app.undo_last_scan()
    checkpoint = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    assert json.loads(checkpoint.read_text(encoding='utf-8'))['pending_audit_events']
    schedule = app._schedule_scanonly_transport
    monkeypatch.setattr(app, '_schedule_scanonly_transport', lambda **kwargs: False)
    save = app._save_tray_state_snapshot
    failed = [False]
    def save_after_audit_projection(state):
        if state.get('exchange_idempotency_keys') and not failed[0]:
            failed[0] = True
            blocked[0] = False
            assert app._flush_pending_event_logs()
            assert not json.loads(checkpoint.read_text(encoding='utf-8')).get('pending_audit_events')
            return False  # The next supported recovery must use the immutable intent.
        return save(state)
    monkeypatch.setattr(app, '_save_tray_state_snapshot', save_after_audit_projection)
    for value in ('KMCMD:EXCHANGE', old, new):
        app._process_barcode_logic(value)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    assert failed[0]
    monkeypatch.setattr(app, '_save_tray_state_snapshot', save)
    monkeypatch.setattr(app, '_schedule_scanonly_transport', schedule)
    assert app._schedule_scanonly_transport()
    _pump_until(app.root, lambda: not app._central_transport_lane.is_busy())
    state = json.loads(checkpoint.read_text(encoding='utf-8'))
    with sqlite3.connect(app.transfer_member_exchange_coordinator.store.db_path) as connection:
        context = json.loads(connection.execute(
            'SELECT context_json FROM transfer_scan_exchanges').fetchone()[0])
    before = context['before_state']
    assert state['scanned_barcodes'] == [new], {
        'checkpoint': state['scanned_barcodes'],
        'before_state_differences': sorted(k for k in set(before) | set(state)
                                           if before.get(k) != state.get(k)),
        'admission': app._scan_entry_admission_block_reason(),
        'review_count': getattr(app, '_scanonly_review_count', None),
        'undo_audit_rows': len(_persisted_undo_rows(app)),
    }
    assert app._scan_entry_admission_block_reason() == ''
    assert app._scanonly_review_count == 0
    public_scan(app, ITEM + '-SERIAL-002')
    assert app.current_tray.scanned_barcodes == [new, ITEM + '-SERIAL-002']
    assert windows == []
