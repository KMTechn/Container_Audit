"""Public scanner regressions for G6/G8/G10; real durable storage, fake UI."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import Container_Audit as ca
from tests.test_scanonly_review_regressions import public_scan, real_notice
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, ITEM, _rows, _pump_until,
)
from tests.test_observed_scanner_completion import ScannerEntry

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


@pytest.mark.parametrize('other_worker', [False, True])
@pytest.mark.parametrize('next_scan', ['label', 'card'])
def test_recovery_choice_parks_original_before_public_scan(flow, windows, other_worker, next_scan):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    public_scan(app, ITEM + '-SERIAL-001')
    saved = app._current_tray_state_snapshot()
    if other_worker:
        saved['worker_name'] = 'other-worker'
        assert app._save_tray_state_snapshot(saved)
    app.current_tray = ca.TraySession()
    app._load_current_tray_state()
    assert app._inline_scan_choices
    calls = []
    app.show_exchange_dialog = lambda: calls.append('exchange')
    raw = f'CLC={ITEM}|QT=4' if next_scan == 'label' else 'KMCMD:EXCHANGE'
    public_scan(app, raw)
    assert not app._inline_scan_choices
    parked = [json.loads(p.read_text(encoding='utf-8')) for p in Path(app.parked_trays_dir).glob('*.json')]
    assert any(p['master_label_code'] == saved['master_label_code']
               and p['scanned_barcodes'] == saved['scanned_barcodes']
               and p['worker_name'] == saved['worker_name'] for p in parked)
    if next_scan == 'label':
        assert app.current_tray.master_label_code == raw
        assert app.current_tray.tray_size == 4
    else:
        assert calls == ['exchange']
    assert windows == []


def test_switch_choice_keeps_current_and_selected_originals_for_next_card(flow, windows):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    public_scan(app, ITEM + '-SERIAL-001')
    selected = app._parked_store().save_state(app._current_tray_state_snapshot(),
        worker_name=app.worker_name, master_label=app.current_tray.master_label_code)
    before = selected.read_bytes()
    app.restore_parked_tray(str(selected))
    assert app._inline_scan_choices
    public_scan(app, 'KMCMD:UNDO')
    assert not app._inline_scan_choices
    assert app.current_tray.scanned_barcodes == []
    assert selected.read_bytes() == before
    assert windows == []


@pytest.mark.parametrize('same_label', [False, True])
def test_foreign_hold_is_unchanged_and_only_its_label_needs_pin(flow, windows, same_label):
    app = flow(transition=True)
    store = app._preflight_hold_store()
    label = f'CLC={ITEM}|QT=3'
    store.start(worker='another-operator', master_raw=label, scan_epoch=0)
    store.append(ITEM + '-SERIAL-001')
    original = store.path.read_bytes()
    assert app._restore_preflight_scan_hold()
    public_scan(app, label if same_label else f'CLC={ITEM}|QT=4')
    assert store.path.read_bytes() == original
    if same_label:
        assert app.current_tray.master_label_code == ''
        assert any('관리자 PIN' in message for _, message, *_ in app.warnings)
        public_scan(app, f'CLC={ITEM}|QT=4')
    assert app.current_tray.tray_size == 4
    assert windows == []


def test_failed_recovery_park_keeps_original_and_does_not_accept_next_label(flow, windows, monkeypatch):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    public_scan(app, ITEM + '-SERIAL-001')
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    original = path.read_bytes()
    app.current_tray = ca.TraySession()
    app._load_current_tray_state()
    monkeypatch.setattr(app, '_defer_saved_recovery_state', lambda *a, **k: False)
    public_scan(app, f'CLC={ITEM}|QT=4')
    assert app._inline_scan_choices
    assert path.read_bytes() == original
    assert app.current_tray.master_label_code == ''
    assert app.scan_entry.get() == ''
    assert windows == []


@pytest.mark.parametrize('change', ['pending_audit', 'business_state'])
def test_recovery_choice_preserves_newer_source_before_next_scan(flow, windows, change, monkeypatch):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    public_scan(app, ITEM + '-SERIAL-001')
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    app.current_tray = ca.TraySession()
    app._load_current_tray_state()
    state = json.loads(path.read_text(encoding='utf-8'))
    if change == 'business_state':
        state['tray_size'] = 4
    else:
        event = app._checkpoint_audit_event('SCAN_UNDO', detail={'g6_late_audit': True},
            idempotency_key='g6-late-audit')
        state.setdefault('pending_audit_events', []).append(event)
    assert app._save_tray_state_snapshot(state)
    original = path.read_bytes()
    if change == 'pending_audit':
        # Keep projection unavailable through the next input: a crash after
        # deferral must recover the new audit from the parked durable owner.
        monkeypatch.setattr(app, '_flush_pending_event_logs', lambda: None)
    public_scan(app, f'CLC={ITEM}|QT=5')
    if change == 'business_state':
        assert app._inline_scan_choices
        assert path.read_bytes() == original
        assert not app.current_tray.master_label_code
    else:
        parked = [json.loads(p.read_text(encoding='utf-8')) for p in Path(app.parked_trays_dir).glob('*.json')]
        assert any(event in p.get('pending_audit_events', []) for p in parked)
        assert app.current_tray.tray_size == 5
    assert windows == []


