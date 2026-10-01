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
from terminal_operation_lease import TRANSFER_OPERATION

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


@pytest.mark.parametrize('status,body', [
    (302, {'ok': True, 'data': {'items': []}}),
    (401, {'ok': False, 'error': {'code': 'UNAUTHORIZED'}}),
    (403, {'ok': False, 'error': {'code': 'FORBIDDEN'}}),
    (404, {'ok': False, 'error': {'code': 'NOT_FOUND'}}),
    (409, {'ok': False, 'error': {'code': 'CONFLICT'}}),
    (200, {'ok': False, 'error': {'code': 'REJECTED'}}),
    (200, ['invalid-shape']),
])
def test_rejected_progress_keeps_observed_disconnection(status, body):
    def offline(_request):
        raise ConnectionError('synthetic offline')

    session = FakeSession(offline)
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        authority_scope_id='scope', session=session)
    with pytest.raises(ConnectionError):
        client.get_progress(date='2026-10-01')
    assert client.connection_state == 'disconnected'
    session.handler = lambda _: FakeResponse(status, body)
    with pytest.raises(ca.TransferSealError):
        client.get_progress(date='2026-10-01')
    assert client.last_successful_transmission_at == ''
    assert client.connection_state == 'disconnected'


@pytest.mark.parametrize('operation', ['progress', 'receipt', 'lease', 'seal'])
def test_connection_recovers_only_after_valid_response_and_preserves_send_time(operation, monkeypatch):
    observed = ca.datetime.datetime.fromisoformat('2026-10-01T01:00:00+00:00')
    monkeypatch.setattr('transfer_client.datetime', SimpleNamespace(now=lambda _: observed))
    session = FakeSession(lambda _: FakeResponse(403, {'ok': False}))
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        authority_scope_id='scope', session=session)

    def request():
        if operation == 'progress':
            return client.get_progress(date='2026-10-01')
        if operation == 'receipt':
            return client.get_receipt('scope', 'synthetic-key')
        if operation == 'lease':
            return client.issue_operation_lease(authority_scope_id='scope',
                operation=TRANSFER_OPERATION, scan_payload='synthetic-label',
                idempotency_key='synthetic-key')
        return client.seal_transfer({'authority_scope_id': 'scope',
            'idempotency_key': 'synthetic-key'})

    with pytest.raises(ca.TransferSealError):
        request()
    assert client.connection_state == 'unknown'
    assert client.last_successful_transmission_at == ''
    session.handler = lambda _: FakeResponse(200, {'ok': True, 'data': progress_data()})
    request()
    assert client.connection_state == 'normal'
    sent_at = observed.isoformat() if operation in {'lease', 'seal'} else ''
    assert client.last_successful_transmission_at == sent_at

    def offline(_request):
        raise ConnectionError('synthetic offline')

    session.handler = offline
    with pytest.raises(ConnectionError):
        client.get_progress(date='2026-10-01')
    session.handler = lambda _: FakeResponse(403, {'ok': False})
    with pytest.raises(ca.TransferSealError):
        request()
    assert client.connection_state == 'disconnected'
    assert client.last_successful_transmission_at == sent_at

    observed = ca.datetime.datetime.fromisoformat('2026-10-01T02:00:00+00:00')
    response_time = observed.isoformat()

    def decode():
        nonlocal observed
        assert client.connection_state == 'disconnected'
        assert client.last_successful_transmission_at == sent_at
        observed = ca.datetime.datetime.fromisoformat('2026-10-01T03:00:00+00:00')
        return {'ok': True, 'data': progress_data()}

    session.handler = lambda _: SimpleNamespace(status_code=200, json=decode)
    request()
    assert client.connection_state == 'normal'
    assert client.last_successful_transmission_at == (
        response_time if operation in {'lease', 'seal'} else sent_at)


@pytest.mark.parametrize('state', ['unknown', 'disconnected', 'normal'])
def test_missing_receipt_does_not_invent_success(state):
    session = FakeSession(lambda _: FakeResponse(404, {'ok': False}))
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        authority_scope_id='scope', session=session)
    client.connection_state = state
    client.last_successful_transmission_at = '2026-10-01T01:00:00+00:00'
    assert client.get_receipt('scope', 'synthetic-key') is None
    assert client.connection_state == state
    assert client.last_successful_transmission_at == '2026-10-01T01:00:00+00:00'


@pytest.mark.parametrize('old_result,new_result', [
    ('offline', 'success'), ('invalid_json', 'success'), ('5xx', 'success'),
    ('success', 'offline'), ('success', 'reject'), ('success', 'success'),
])
def test_late_old_request_cannot_overwrite_newer_connection_observation(old_result, new_result, monkeypatch):
    old_time = ca.datetime.datetime.fromisoformat('2026-10-01T03:00:00+00:00')
    new_time = ca.datetime.datetime.fromisoformat('2026-10-01T02:00:00+00:00')
    prior_time = '2026-10-01T01:00:00+00:00'
    observed = new_time
    new_failures = []

    def response(result):
        if result == 'offline':
            raise ConnectionError('synthetic offline')
        if result == 'invalid_json':
            def invalid_json():
                raise ValueError('synthetic invalid JSON')
            return SimpleNamespace(status_code=200, json=invalid_json)
        if result in {'5xx', 'reject'}:
            return FakeResponse(503 if result == '5xx' else 403, {'ok': False})
        return FakeResponse(200, {'ok': True, 'data': {}})

    def handler(request):
        nonlocal observed
        if request['url'].endswith('/old'):
            # Nest the later request in the fake transport to order responses
            # deterministically while keeping real writer admission enabled.
            try:
                client._request('POST', '/new')
            except Exception as exc:
                new_failures.append(exc)
            observed = old_time
            return response(old_result)
        return response(new_result)

    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        authority_scope_id='scope', session=FakeSession(handler))
    client.connection_state = 'disconnected'
    client.last_successful_transmission_at = prior_time

    monkeypatch.setattr('transfer_client.datetime', SimpleNamespace(now=lambda _: observed))
    if old_result == 'success':
        client._request('POST', '/old')
    else:
        with pytest.raises(ConnectionError if old_result == 'offline' else ca.TransferSealError):
            client._request('POST', '/old')
    assert len(new_failures) == (new_result != 'success')
    assert all(isinstance(exc, (ConnectionError, ca.TransferSealError)) for exc in new_failures)
    assert client.connection_state == ('normal' if new_result == 'success' else 'disconnected')
    expected_time = (new_time.isoformat() if new_result == 'success' else
        old_time.isoformat() if old_result == 'success' else prior_time)
    assert client.last_successful_transmission_at == expected_time


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


