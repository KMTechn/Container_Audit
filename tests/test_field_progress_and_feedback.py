"""Public scanner regressions for G6/G8/G10; real durable storage, fake UI."""
import json
import threading
from urllib.parse import parse_qs, urlsplit
from pathlib import Path
from types import SimpleNamespace

import pytest
import Container_Audit as ca
from tests.test_scanonly_review_regressions import public_scan, real_notice
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, ITEM, _rows, _pump_until,
)
from tests.test_observed_scanner_completion import ScannerEntry
from tests.test_transfer_seal import FakeSession, FakeResponse
from transfer_client import LogisticsTransferClient

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


@pytest.mark.parametrize('completion_busy', [False, True])
def test_progress_scan_returns_to_work_and_enters_existing_fifo(flow, windows, completion_busy):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    app._progress_visible = True
    app._progress_panel = SimpleNamespace(place_forget=lambda: None)
    app._progress_work_scan_entry = app.scan_entry
    app.scan_entry = ScannerEntry('')
    app._completion_lane_busy = completion_busy
    public_scan(app, ITEM + '-SERIAL-001')
    assert not app._progress_visible
    if completion_busy:
        assert app._scans_behind_save == [ITEM + '-SERIAL-001']
        app._completion_lane_busy = False
        app._process_next_scan_behind_save()
    assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
    assert len(_rows(app, 'SCAN_OK')) == 1
    assert windows == []


def progress_data():
    return {'date': '2026-10-01', 'items': [{'item_id': ITEM, 'name': '품목',
        'plan_qty': 60, 'transferred_qty': 30, 'remaining_qty': 30, 'remaining_boxes': 1}],
        'generated_at': '2026-10-01T01:00:00Z'}


def test_progress_uses_device_authenticated_read_request():
    session = FakeSession(lambda _: FakeResponse(200, {'ok': True, 'data': progress_data()}))
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        device_id='device', authority_scope_id='scope', session=session)
    assert client.get_progress(date='2026-10-01') == progress_data()
    request = session.calls[0]
    assert request['method'] == 'GET'
    assert urlsplit(request['url']).path == '/logistics/api/v1/progress'
    assert parse_qs(urlsplit(request['url']).query) == {
        'date': ['2026-10-01'], 'stage': ['transfer'], 'authority_scope_id': ['scope']}
    assert request['headers']['X-Logistics-Device-Id'] == 'device'
    assert request['allow_redirects'] is False


def test_progress_rejects_malformed_counts_instead_of_replacing_last_values():
    data = progress_data()
    data['items'][0]['transferred_qty'] = '30'
    session = FakeSession(lambda _: FakeResponse(200, {'ok': True, 'data': data}))
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        authority_scope_id='scope', session=session)
    with pytest.raises(ca.TransferSealError, match='진행 현황 수량'):
        client.get_progress(date='2026-10-01')


def test_late_progress_response_keeps_work_screen_and_refresh_is_background(flow, windows, monkeypatch):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    entered, release = threading.Event(), threading.Event()
    def get_progress(**kwargs):
        entered.set()
        assert release.wait(5)
        return progress_data()
    monkeypatch.setattr(app.transfer_seal_coordinator.client, 'get_progress', get_progress, raising=False)
    monkeypatch.setattr(app, '_render_logistics_progress', lambda: None)
    app._progress_visible = True
    app._progress_panel = SimpleNamespace(place_forget=lambda: None)
    app._progress_work_scan_entry = app.scan_entry
    app.scan_entry = ScannerEntry('')
    try:
        app._refresh_logistics_progress()
        assert entered.wait(3)
        assert app._progress_pending
        public_scan(app, ITEM + '-SERIAL-001')
        assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
        assert not app._progress_visible
        release.set()
        _pump_until(app.root, lambda: not app._progress_pending)
        assert app._progress_data == progress_data()
        assert not app._progress_visible
    finally:
        release.set()
        if getattr(app, '_progress_pending', False):
            _pump_until(app.root, lambda: not app._progress_pending)
    assert windows == []


def test_disconnected_progress_retains_last_values_and_success_time(flow, windows, monkeypatch):
    app = flow(transition=True)
    monkeypatch.setattr(app, '_render_logistics_progress', lambda: None)
    app._progress_data = progress_data()
    app._progress_last_success = '10-01 10:00'
    app._progress_visible = True
    app._progress_pending = True
    import queue
    app._progress_results = queue.Queue()
    app._progress_results.put((None, 'tester'))
    app._poll_logistics_progress_result()
    assert app._progress_data == progress_data()
    assert app._progress_last_success == '10-01 10:00'
    assert app._progress_disconnected
    assert any(delay == 60000 for _, delay, *_ in app.root.jobs)


def test_progress_request_does_not_block_refresh_after_session_jobs_cancel(flow, windows):
    app = flow(transition=True)
    app._progress_pending = True
    for name in ('clock_job', 'stopwatch_job', 'idle_check_job', 'focus_return_job'):
        setattr(app, name, None)
    app._cancel_all_jobs()
    assert app._progress_pending is False


