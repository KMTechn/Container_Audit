"""A restarted FIFO head retains its first audit through a lost hold ACK."""
import json
from pathlib import Path
import pytest
from preflight_scan_hold import PreflightScanHoldStore
from tests.test_worker_record_identity import _app, IDENTITY
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, ITEM

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('accepted', [False, True], ids=['rejected', 'accepted'])
def test_reopened_hold_head_replays_first_audit_before_ack(flow, windows, tmp_path, monkeypatch, enabled, accepted):
    app = _app(flow, tmp_path, enabled=enabled)
    store = app._preflight_hold_store()
    store.start(worker='tester', master_raw=app.current_tray.master_label_code, scan_epoch=0, **IDENTITY)
    store.append((ITEM if accepted else 'BBB2270730100') + '-SERIAL-001')
    app._preflight_hold_snapshot = store.mark_draining()
    native_ack = PreflightScanHoldStore.ack_head
    calls = []
    def ack_once_fails(self, scan_id):
        calls.append(scan_id)
        if len(calls) == 1:
            raise OSError('synthetic ACK write failure')
        return native_ack(self, scan_id)
    monkeypatch.setattr(PreflightScanHoldStore, 'ack_head', ack_once_fails)
    assert not app._run_durable_ui_steps(app._drain_preflight_hold_steps())
    app.log_queue.join()
    original_csv = Path(app.log_file_path).read_bytes()
    reopened = PreflightScanHoldStore(store.path, capacity=store.capacity).load()
    event = reopened.items[0].audit_event
    assert event['worker_record'] == {**IDENTITY, 'enabled': enabled}
    assert event['log_entry']['event'] == ('SCAN_OK' if accepted else 'SCAN_FAIL_MISMATCH')
    checkpoint = json.loads(Path(app.save_folder, app.CURRENT_TRAY_STATE_FILE).read_text(encoding='utf-8'))
    app._restore_tray_from_state(checkpoint, preserve_held_scans=True)
    app._preflight_hold_snapshot = reopened
    app._worker_record_identity_enabled = not enabled
    app._warning_state_presenter().clear()
    monkeypatch.setattr(app, '_worker_record_context', lambda: pytest.fail('reopened head consulted live identity'))
    assert app._run_durable_ui_steps(app._drain_preflight_hold_steps())
    app.log_queue.join()
    assert not store.exists()
    assert Path(app.log_file_path).read_bytes() == original_csv
    assert len(app.current_tray.scanned_barcodes) == int(accepted)
    assert not list(app._event_log_outbox(app.log_file_path).directory.glob('*.json'))
    assert windows == []


@pytest.mark.parametrize('enabled', [False, True, None], ids=['off', 'on', 'legacy'])
def test_pre_binding_outbox_replay_keeps_stored_record(flow, windows, tmp_path, monkeypatch, enabled):
    import event_log_store
    app = _app(flow, tmp_path, enabled=enabled is True)
    app.log_queue.join()
    native_append = event_log_store._append_event_log_entry_unlocked
    def unavailable(path, entry, **kwargs):
        if entry['event'] == 'SCAN_OK':
            raise OSError('synthetic CSV failure before hold audit binding existed')
        return native_append(path, entry, **kwargs)
    monkeypatch.setattr(event_log_store, '_append_event_log_entry_unlocked', unavailable)
    barcode = ITEM + '-SERIAL-001'
    app._process_barcode_logic(barcode, _durable_scan_log=True, _durable_scan_id='pre-binding-audit')
    outbox = app._event_log_outbox(app.log_file_path)
    original = next(path for path in outbox.directory.glob('*.json')
                    if json.loads(path.read_text(encoding='utf-8'))['log_entry']['event'] == 'SCAN_OK')
    payload = json.loads(original.read_text(encoding='utf-8'))
    expected = payload.get('worker_record', {})
    if enabled is None:
        payload.pop('worker_record', None)
        original.write_text(json.dumps(payload), encoding='utf-8')
        expected = {}
    monkeypatch.setattr(event_log_store, '_append_event_log_entry_unlocked', native_append)
    captured = []
    native_stage = outbox.stage
    def stage(path, row, *, worker_record):
        captured.append(worker_record)
        return native_stage(path, row, worker_record=worker_record)
    monkeypatch.setattr(outbox, 'stage', stage)
    monkeypatch.setattr(app, '_worker_record_context', lambda: pytest.fail('old outbox replay consulted live identity'))
    app._worker_record_identity_enabled = enabled is not True
    assert app._persist_existing_held_scan_audit(barcode, scan_id='pre-binding-audit', scan_position=1)
    assert captured == [expected]
    assert not list(outbox.directory.glob('*.json'))
    assert windows == []
