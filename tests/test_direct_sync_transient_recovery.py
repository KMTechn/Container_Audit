"""Additional lane scope: transient errors never strand an uncommitted row."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import sqlite3
from types import SimpleNamespace

import pytest
from requests import exceptions

import Container_Audit as ca
import ca_screen_bridge as screen
import direct_sync_health as health_model
import direct_sync_push as push
import direct_sync_runtime as runtime
import producer_runtime_client as lease
from tests.test_direct_sync_clock_stale import enqueue, queue_row, rejection
from tests import test_direct_sync_push as push_helpers
from tests import test_direct_sync_runtime as runtime_helpers
from tests.test_ca_screen_bridge import _app
from tests.test_work_details_visibility import Widget, install_sync_display, catalog_notice_text
from tests.test_w9scanonly_workflow import flow, windows  # noqa: F401


@pytest.fixture(autouse=True)
def local_runtime(monkeypatch):
    monkeypatch.setattr(push, 'prepare_runtime_metadata',
                        lambda **kw: lease.RuntimePreparation(metadata=dict(kw['metadata'])))


@pytest.mark.parametrize('stage', ['upload', 'lease'])
@pytest.mark.parametrize('status', [408, 429, 500, 501, 503, 505, 599])
def test_uncommitted_http_transients_preserve_row_for_retry(tmp_path, monkeypatch, stage, status):
    _, credentials = enqueue(tmp_path)
    response = rejection('temporarily_unavailable', date=None, status=status)
    if stage == 'lease':
        _, preparation = lease._post_lease_request(
            request_value={}, credentials=credentials,
            session=SimpleNamespace(post=lambda *args, **kw: response), timeout=5)
        monkeypatch.setattr(push, 'prepare_runtime_metadata', lambda **kw: preparation)
    result = push.drain_one_relay_batch(
        db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=push_helpers.FakeSession(response), now='2099-01-01T00:00:00Z')
    assert result.retryable is True
    row = queue_row(tmp_path)
    assert row['status'] == 'retry_wait' and row['next_attempt_at']
    assert row['attempt_count'] == 1
    assert Path(row['spooled_file_path']).is_file()


@pytest.mark.parametrize('stage', ['upload', 'lease'])
@pytest.mark.parametrize('error', [ConnectionRefusedError, socket.gaierror, OSError,
                                  exceptions.SSLError, exceptions.ConnectTimeout,
                                  exceptions.ReadTimeout, TimeoutError])
def test_network_and_timeout_errors_keep_original_for_automatic_retry(tmp_path, monkeypatch, stage, error):
    _, credentials = enqueue(tmp_path)
    def fail(*args, **kw):
        raise error('synthetic transport failure')
    session = SimpleNamespace(post=fail)
    if stage == 'lease':
        _, preparation = lease._post_lease_request(
            request_value={}, credentials=credentials, session=session, timeout=5)
        monkeypatch.setattr(push, 'prepare_runtime_metadata', lambda **kw: preparation)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      session=session, now='2099-01-01T00:00:00Z')
    assert result.retryable is True
    first = queue_row(tmp_path)
    assert first['status'] == 'retry_wait'
    monkeypatch.setattr(push, 'prepare_runtime_metadata',
                        lambda **kw: lease.RuntimePreparation(metadata=dict(kw['metadata'])))
    recovered = push.drain_one_relay_batch(
        db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=runtime_helpers.EchoAcceptedSession(), now='2100-01-01T00:00:00Z')
    assert recovered.success
    current = queue_row(tmp_path)
    assert current['status'] == 'acked'
    assert current['relay_id'] == first['relay_id']
    assert current['content_sha256'] == first['content_sha256']


def test_terminal_file_count_survives_non_scan_cycle_then_scan_zero_clears_it(tmp_path):
    config = runtime_helpers.make_config(tmp_path)
    status = runtime.record_scan_status(config, status='existing_terminal_blocked',
                                        scan_enqueued_count=0, scan_attempted_count=0,
                                        scan_terminal_blocked_count=2)
    health = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert health.scan_terminal_blocked_count == 2
    assert health_model.relay_blocked_files_warning_model(health) == {
        'kind': 'warn', 'text': '회사 서버로 못 보낸 기록 파일 2개 — 현장 관리자에게 알리세요'}
    runtime._write_runtime_status(config, status='idle', queue=status['queue'], disk={})
    reread = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert reread.scan_terminal_blocked_count == 2
    runtime.record_scan_status(config, status='scan_no_new_rows',
                                scan_enqueued_count=0, scan_attempted_count=0,
                                scan_terminal_blocked_count=0)
    cleared = health_model.read_relay_health(db_path=config.db_path,
                                           runtime_status_path=config.runtime_status_path)
    assert health_model.relay_blocked_files_warning_model(cleared) == {}


def test_send_band_priority_preserves_existing_catalog_notice(flow):
    app = _app(flow)
    app._startup_item_catalog_context = {'transition_cause_code': 'synthetic-cause'}
    app._direct_sync_health = ca.RelayHealth(
        state='pending', pending_count=1, failed_permanent_count=0, operator_review_count=0,
        last_acked_at='', oldest_pending_at='', observed_at='', scan_terminal_blocked_count=3,
        clock_warning={'status_code': 401, 'error_code': 'stale_timestamp'})
    install_sync_display(app)
    catalog = catalog_notice_text(app)
    app.relay_notice_frame = Widget()
    app.relay_notice_label = Widget(app.relay_notice_frame)
    app.relay_notice_details_label = Widget(app.relay_notice_frame)
    ca.ContainerAudit._apply_relay_warning_layout(app)
    assert app.relay_notice_label.options['text'].startswith('이 PC 시계가 회사 서버와')
    assert catalog_notice_text(app) == catalog
    alerts = screen.CaProcessor(app).state()['alerts']
    assert sum(alert['kind'] == 'warn' for alert in alerts) >= 2
    assert not any(alert['text'].startswith('회사 서버가 받지 않은 기록') for alert in alerts)
    assert all('choices' not in alert for alert in alerts if alert['text'].startswith(('이 PC 시계', '회사 서버로 못 보낸 기록 파일')))
    app._direct_sync_health = replace(app._direct_sync_health, clock_warning={}, scan_terminal_blocked_count=0)
    ca.ContainerAudit._apply_relay_warning_layout(app)
    assert not app.relay_notice_frame.visible
    assert catalog_notice_text(app) == catalog
