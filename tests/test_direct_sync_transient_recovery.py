"""Additional lane scope: transient errors never strand an uncommitted row."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import sqlite3
from types import SimpleNamespace
import hashlib

import pytest
from requests import exceptions

import Container_Audit as ca
import ca_screen_bridge as screen
import direct_sync_health as health_model
import direct_sync_push as push
import direct_sync_runtime as runtime
import producer_runtime_client as lease
import tools.direct_sync_relay_runner as runner
from tests.test_direct_sync_clock_stale import enqueue, queue_row, rejection
from tests import test_direct_sync_push as push_helpers
from tests import test_direct_sync_runtime as runtime_helpers
from tests.test_ca_screen_bridge import _app
from tests.test_work_details_visibility import Widget, install_sync_display, catalog_notice_text
from tests.test_w9scanonly_workflow import flow, windows  # noqa: F401
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


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
                                        scan_terminal_blocked_count=2,
                                        scan_terminal_blocked_record_count=7)
    health = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert health.scan_terminal_blocked_count == 2
    warning = health_model.relay_blocked_files_warning_model(health)
    assert warning['kind'] == 'warn'
    assert warning['text'] == '회사 서버가 받지 않은 기록이 있어 그 뒤 기록 7건을 보내지 못하고 있습니다 — 현장 관리자에게 알리세요'
    assert warning['tail'].endswith('막힌 기록 파일 2개')
    runtime._write_runtime_status(config, status='idle', queue=status['queue'], disk={})
    reread = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert reread.scan_terminal_blocked_count == 2
    assert reread.scan_terminal_blocked_record_count == 7
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
    assert all('choices' not in alert for alert in alerts if alert['text'].startswith(('이 PC 시계', '회사 서버가 받지 않은 기록')))
    app._direct_sync_health = replace(app._direct_sync_health, clock_warning={}, scan_terminal_blocked_count=0)
    ca.ContainerAudit._apply_relay_warning_layout(app)
    assert not app.relay_notice_frame.visible
    assert catalog_notice_text(app) == catalog


@pytest.mark.parametrize('start_after_first', [False, True])
def test_blocked_record_count_uses_csv_records_and_includes_terminal_and_new_tail(tmp_path, start_after_first):
    import csv
    path = tmp_path / 'source.csv'
    with path.open('w', encoding='utf-8-sig', newline='') as out:
        writer = csv.writer(out)
        writer.writerow(['timestamp', 'worker_name', 'event', 'details'])
        writer.writerow(['2026-10-26', 'worker', 'SCAN', '{}'])
    first_end = path.stat().st_size
    with path.open('a', encoding='utf-8', newline='') as out:
        writer = csv.writer(out)
        writer.writerow(['2026-10-26', 'worker\nname', 'SCAN', '{}'])
    blocked_end = path.stat().st_size
    raw = path.read_bytes()
    start = first_end if start_after_first else 0
    header = raw[:raw.index(b'\n') + 1]
    digest = hashlib.sha256((header if start else b'') + raw[start:blocked_end]).hexdigest()
    blocked = runner.ExistingTerminalDeltaBlocked(str(path), start_byte=start,
                                                 end_byte=blocked_end, content_sha256=digest)
    with path.open('a', encoding='utf-8', newline='') as out:
        csv.writer(out).writerow(['2026-10-26', 'worker', 'SCAN', '{}'])
    assert runner._count_blocked_source_records(path, blocked) == (2 if start_after_first else 3)


@pytest.mark.parametrize('problem', ['hash', 'partial', 'malformed', 'changed', 'missing_range'])
def test_blocked_record_count_is_unknown_when_snapshot_is_not_proven(tmp_path, monkeypatch, problem):
    path = tmp_path / 'source.csv'
    raw = b'timestamp,worker_name,event,details\n2026,w,SCAN,{}\n'
    path.write_bytes(raw)
    blocked = runner.ExistingTerminalDeltaBlocked(str(path), start_byte=0, end_byte=len(raw),
                                                 content_sha256=hashlib.sha256(raw).hexdigest())
    if problem == 'hash':
        blocked.content_sha256 = '0' * 64
    elif problem == 'partial':
        path.write_bytes(raw + b'2026,w,SCAN,{}')
    elif problem == 'malformed':
        path.write_bytes(raw + b'2026,w,SCAN,"unterminated\n')
    elif problem == 'missing_range':
        blocked = runner.ExistingTerminalDeltaBlocked(str(path))
    else:
        original = runner.os.fstat
        calls = []
        def changed(fd):
            result = original(fd)
            calls.append(fd)
            return result if len(calls) == 1 else SimpleNamespace(
                st_dev=result.st_dev, st_ino=result.st_ino,
                st_size=result.st_size + 1, st_mtime_ns=result.st_mtime_ns)
        monkeypatch.setattr(runner.os, 'fstat', changed)
    assert runner._count_blocked_source_records(path, blocked) is None


def test_one_send_band_preserves_all_four_existing_alert_slots():
    from warning_presenter import NoticeSeverity
    health = ca.RelayHealth(state='pending', pending_count=1, failed_permanent_count=0,
                           operator_review_count=0, last_acked_at='', oldest_pending_at='', observed_at='',
                           clock_warning={'status_code': 401, 'error_code': 'stale_timestamp'},
                           scan_terminal_blocked_count=2, scan_terminal_blocked_record_count=7)
    app = SimpleNamespace(_direct_sync_health=health, _scan_entry_broken=True, is_idle=True,
                          _operator_review_blocks_mutation=lambda: True,
                          _catalog_notice_for_display=lambda: 'catalog warning')
    notice = SimpleNamespace(blocking=True, severity=NoticeSeverity.ERROR, title='blocked', message='message')
    alerts = screen._alerts(app, SimpleNamespace(active_notice=notice), [], None)
    assert len(alerts) == 5
    assert alerts[0]['text'].startswith('이 PC 시계')
    assert alerts[0]['tail'].endswith('막혀서 못 보낸 기록 7건 · 막힌 기록 파일 2개')
    assert [alert['text'] for alert in alerts[1:]] == [
        '입력 칸 오류 — 프로그램을 다시 켜세요', 'blocked — message',
        '휴식 상태 — 스캔하면 작업을 다시 시작합니다', 'catalog warning']
    assert 'choices' not in alerts[0]


def test_blocked_then_plain_delayed_send_band_priority():
    health = ca.RelayHealth(state='pending', pending_count=3, failed_permanent_count=0,
                           operator_review_count=0, last_acked_at='', oldest_pending_at='2000-01-01T00:00:00Z',
                           observed_at='', scan_terminal_blocked_count=2,
                           scan_terminal_blocked_record_count=7)
    assert '그 뒤 기록 7건' in health_model.relay_send_warning_model(health)['text']
    delayed = replace(health, scan_terminal_blocked_count=0, scan_terminal_blocked_record_count=0)
    assert health_model.relay_send_warning_model(delayed)['text'] == '회사 서버로 기록을 보내지 못하고 있습니다 — 현장 관리자에게 알리세요'


def test_send_band_hides_old_review_line_and_fallback_stays_amber(flow):
    app = _app(flow)
    health = ca.RelayHealth(state='review', pending_count=1, failed_permanent_count=1,
                           operator_review_count=0, last_acked_at='', oldest_pending_at='', observed_at='',
                           clock_warning={'status_code': 401, 'error_code': 'stale_timestamp'})
    app._direct_sync_health = health
    install_sync_display(app)
    app._render_direct_sync_status_line()
    assert '관리자 확인' not in app.direct_sync_status_label.options['text']
    connection, counts = screen._conn(app)
    assert connection['state'] != 'review' and counts['failed'] == 1
    app._direct_sync_health = replace(health, clock_warning={})
    app._render_direct_sync_status_line()
    assert '관리자 확인' in app.direct_sync_status_label.options['text']
    assert app.direct_sync_status_label.options['fg'] == app.COLOR_IDLE_TEXT


def test_blocked_since_is_first_scan_utc_until_clear_and_new_episode(tmp_path, monkeypatch):
    config = runtime_helpers.make_config(tmp_path)
    first_time, second_time = '2026-10-26T06:00:00Z', '2026-10-26T07:00:00Z'
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: first_time)
    first = runtime.record_scan_status(config, status='existing_terminal_blocked',
                                       scan_enqueued_count=0, scan_attempted_count=0,
                                       scan_terminal_blocked_count=1, scan_terminal_blocked_record_count=2)
    assert first['scan_terminal_blocked_since_utc'] == first_time
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: second_time)
    idle = runtime._write_runtime_status(config, status='idle', queue=first['queue'], disk={})
    assert idle['scan_terminal_blocked_since_utc'] == first_time
    again = runtime.record_scan_status(config, status='existing_terminal_blocked',
                                       scan_enqueued_count=0, scan_attempted_count=0,
                                       scan_terminal_blocked_count=2, scan_terminal_blocked_record_count=4)
    assert again['scan_terminal_blocked_since_utc'] == first_time
    health = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert health.scan_terminal_blocked_since_utc == first_time
    clear = runtime.record_scan_status(config, status='scan_no_new_rows',
                                       scan_enqueued_count=0, scan_attempted_count=0,
                                       scan_terminal_blocked_count=0, scan_terminal_blocked_record_count=0)
    assert 'scan_terminal_blocked_since_utc' not in clear
    new = runtime.record_scan_status(config, status='existing_terminal_blocked',
                                     scan_enqueued_count=0, scan_attempted_count=0,
                                     scan_terminal_blocked_count=1, scan_terminal_blocked_record_count=2)
    assert new['scan_terminal_blocked_since_utc'] == second_time


@pytest.mark.parametrize('records,expected', [(7, '찍은 기록은 이 PC에 그대로 있습니다 · 막힌 기록 파일 2개'),
                                             (None, '찍은 기록은 이 PC에 그대로 있습니다 · 막힌 기록 파일 2개')])
def test_blocked_small_line_preserves_record_and_file_units(records, expected):
    health = ca.RelayHealth(state='review', pending_count=0, failed_permanent_count=1,
                           operator_review_count=0, last_acked_at='', oldest_pending_at='', observed_at='',
                           scan_terminal_blocked_count=2, scan_terminal_blocked_record_count=records)
    assert health_model.relay_blocked_files_warning_model(health)['tail'] == expected
