"""Clock rejection recovery through upload, lease, relay, and both UI adapters."""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
import direct_sync_health as health_model
import direct_sync_push as push
import direct_sync_runtime as runtime
import producer_runtime_client as lease
import tools.direct_sync_relay_runner as runner
from tests import test_direct_sync_push as push_helpers
from tests import test_direct_sync_runtime as runtime_helpers
from tests import test_direct_sync_relay_runner as runner_helpers
from tests.test_ca_screen_bridge import _app
from tests.test_work_details_visibility import Widget
from tests.test_w9scanonly_workflow import flow, windows  # noqa: F401


DATE = 'Mon, 26 Oct 2026 04:00:00 GMT'
PC_TIME = '2026-10-26T04:10:00Z'
TITLE = '이 PC 시계가 회사 서버와 5분 넘게 달라 기록을 보내지 못하고 있습니다 — 현장 관리자에게 알리세요'
DETAIL = '찍은 기록은 이 PC에 그대로 있고, 시계를 맞추면 저절로 보내집니다'


@pytest.fixture(autouse=True)
def local_runtime(monkeypatch):
    monkeypatch.setattr(push, 'prepare_runtime_metadata',
                        lambda **kw: lease.RuntimePreparation(metadata=dict(kw['metadata'])))
    monkeypatch.setattr(runtime, 'ensure_runtime_authority', lambda **kw: lease.RuntimePreparation())


def rejection(code='stale_timestamp', *, date=DATE, status=401):
    return push_helpers.FakeResponse(status, {
        'committed': False, 'retryable': False,
        'error': {'code': code, 'message': 'request rejected'},
    }, headers={} if date is None else {'dAtE': date})


def enqueue(tmp_path):
    _, manifest = push_helpers.make_manifest(tmp_path)
    credentials = push_helpers.make_credentials()
    row = push.enqueue_source_file_for_relay(
        db_path=tmp_path / 'relay.sqlite3', spool_dir=tmp_path / 'spool',
        source_file_path=push_helpers.write_csv(tmp_path),
        producer_manifest_path=manifest, credentials=credentials)
    return row, credentials


def queue_row(tmp_path):
    with sqlite3.connect(tmp_path / 'relay.sqlite3') as conn:
        conn.row_factory = sqlite3.Row
        return dict(conn.execute('SELECT * FROM direct_sync_relay_batches').fetchone())


@pytest.mark.parametrize('code,status,retryable', [
    ('stale_timestamp', 401, True), ('invalid_signature', 401, False),
    ('credential_rejected', 401, False), ('stale_timestamp', 403, False),
])
def test_upload_only_clock_401_waits(tmp_path, code, status, retryable):
    _, credentials = enqueue(tmp_path)
    result = push.drain_one_relay_batch(
        db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=push_helpers.FakeSession(rejection(code, status=status)),
        status_dir=tmp_path / 'status', now='2099-01-01T00:00:00Z')
    assert result.retryable is retryable
    row = queue_row(tmp_path)
    expected = 'retry_wait' if retryable else 'operator_review'
    # Legacy exact replay keeps its original review guard for every other 401.
    assert row['status'] == expected
    assert bool(row['next_attempt_at']) is retryable
    artifact = json.loads(Path(result.status_path).read_text(encoding='utf-8'))
    assert artifact['error_code'] == code


@pytest.mark.parametrize('code,status,retryable', [
    ('stale_timestamp', 401, True), ('invalid_signature', 401, False),
    ('stale_timestamp', 403, False),
])
def test_row_lease_clock_401_uses_same_retry_schedule(tmp_path, monkeypatch, code, status, retryable):
    _, credentials = enqueue(tmp_path)
    _, preparation = lease._post_lease_request(
        request_value={}, credentials=credentials,
        session=SimpleNamespace(post=lambda *args, **kw: rejection(code, status=status)), timeout=5)
    assert preparation.retryable is retryable
    monkeypatch.setattr(push, 'prepare_runtime_metadata', lambda **kw: preparation)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      now='2099-01-01T00:00:00Z')
    assert result.retryable is retryable
    row = queue_row(tmp_path)
    assert row['status'] == ('retry_wait' if retryable else 'failed_permanent')
    assert bool(row['next_attempt_at']) is retryable


@pytest.mark.parametrize('date,expected', [(DATE, True), (None, False),
                                        ('not a date', False), ('Mon, 26 Oct 2026 04:00:00', False)])
@pytest.mark.parametrize('stage', ['upload', 'lease'])
def test_http_date_records_pc_minus_server_only_when_valid(tmp_path, monkeypatch, date, expected, stage):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 26, 4, 10, tzinfo=timezone.utc).astimezone(tz)
    monkeypatch.setattr(lease, 'datetime', FixedDatetime)
    _, credentials = enqueue(tmp_path)
    if stage == 'lease':
        _, preparation = lease._post_lease_request(
            request_value={}, credentials=credentials,
            session=SimpleNamespace(post=lambda *args, **kw: rejection(date=date)), timeout=5)
        monkeypatch.setattr(push, 'prepare_runtime_metadata', lambda **kw: preparation)
    result = push.drain_one_relay_batch(
        db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=push_helpers.FakeSession(rejection(date=date)),
        status_dir=tmp_path / 'status', now='2099-01-01T00:00:00Z')
    assert bool(result.clock_skew) is expected
    if expected:
        assert result.clock_skew == {'pc_time_utc': PC_TIME,
                                     'server_time_utc': '2026-10-26T04:00:00Z',
                                     'offset_seconds': 600}
    if stage == 'upload':
        artifact = json.loads(Path(result.status_path).read_text(encoding='utf-8'))
        assert ('clock_skew' in artifact) is expected


def test_stale_retry_restart_idle_warning_then_upload_recovers(tmp_path, monkeypatch):
    config = replace(runtime_helpers.make_config(tmp_path), retry_base_seconds=300)
    credentials = push_helpers.make_credentials()
    runtime.enqueue_completed_source_file(config, source_file_path=runtime_helpers.write_csv(tmp_path),
                                          credentials=credentials)
    first = runtime.run_relay_once(config, credentials=credentials,
                                  session=push_helpers.FakeSession(rejection()))
    assert first['status'] == 'retry_wait'
    assert first['queue']['counts'].get('failed_permanent', 0) == 0
    health = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert health.error_code == 'stale_timestamp'
    assert health.operator_attention is False
    notice = health_model.relay_clock_warning_model(health)
    assert notice['text'] == TITLE and notice['tail'].startswith(DETAIL)
    assert notice['kind'] == 'warn' and 'choices' not in notice
    # A fresh read/cycle before the scheduled retry must retain the warning.
    idle = runtime.run_relay_once(config, credentials=credentials,
                                 session=push_helpers.FakeSession(rejection()))
    assert idle['status'] == 'idle'
    assert idle['clock_warning'] == first['clock_warning']
    with sqlite3.connect(config.db_path) as conn:
        conn.execute('UPDATE direct_sync_relay_batches SET next_attempt_at = ?', ('2000-01-01T00:00:00Z',))
    recovered = runtime.run_relay_once(config, credentials=credentials,
                                      session=runtime_helpers.EchoAcceptedSession())
    assert recovered['status'] == 'acked'
    assert 'clock_warning' not in recovered
    assert recovered['queue']['counts'] == {'acked': 1}
    health = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert health_model.relay_clock_warning_model(health) == {}


def test_preflight_lease_clock_warning_does_not_make_terminal_rows(tmp_path, monkeypatch):
    config = runtime_helpers.make_config(tmp_path)
    credentials = push_helpers.make_credentials()
    _, preparation = lease._post_lease_request(
        request_value={}, credentials=credentials,
        session=SimpleNamespace(post=lambda *args, **kw: rejection()), timeout=5)
    monkeypatch.setattr(runtime, 'ensure_runtime_authority', lambda **kw: preparation)
    result = runtime.run_relay_once(config, credentials=credentials)
    assert result['status'] == 'runtime_error'
    assert result['queue']['counts'] == {}
    health = health_model.read_relay_health(db_path=config.db_path,
                                          runtime_status_path=config.runtime_status_path)
    assert health.error_code == 'stale_timestamp' and not health.operator_attention


def test_stale_upload_does_not_block_next_source_scan(tmp_path, monkeypatch, capsys):
    source = tmp_path / 'sync'
    csv = runner_helpers.write_container_csv(source)
    args = runner_helpers.runner_args(tmp_path, scan_dir=source)
    monkeypatch.setattr(runner, 'run_relay_once',
                        lambda config, **kw: runtime.run_relay_once(
                            config, session=push_helpers.FakeSession(rejection()), **kw))
    first_rc = runner.main(args + ['--drain-after-scan'])
    first = capsys.readouterr().out
    with csv.open('a', encoding='utf-8') as output:
        output.write('2026-06-22T00:00:02,worker,SCAN,{}\n')
    scan_rc = runner.main(args)
    output = capsys.readouterr().out
    assert (first_rc, scan_rc, 'direct_sync_relay_status=retry_wait' in first,
            'existing_terminal_blocked' in output) == (0, 0, True, False)
    assert 'direct_sync_scan_enqueued_count=1' in output


def test_both_screen_adapters_show_warning_without_scan_gate(flow):
    app = _app(flow)
    warning = {'error_code': 'stale_timestamp', 'status_code': 401,
               'clock_skew': {'pc_time_utc': PC_TIME, 'server_time_utc': '2026-10-26T04:00:00Z',
                              'offset_seconds': 600}}
    health = ca.RelayHealth(state='pending', pending_count=1, failed_permanent_count=0,
                           operator_review_count=0, last_acked_at='', oldest_pending_at='',
                           observed_at='', error_code='stale_timestamp', clock_warning=warning)
    app._direct_sync_health = health
    alerts = screen.CaProcessor(app).state()['alerts']
    band = next(alert for alert in alerts if alert['text'] == TITLE)
    assert band['kind'] == 'warn' and band['tail'].startswith(DETAIL)
    assert '이 PC ' in band['tail'] and '회사 서버 ' in band['tail']
    assert 'choices' not in band
    assert app._operator_review_blocks_mutation() is False
    # The Tk warning uses the same model in its existing amber sidebar layout.
    assert ca.relay_clock_warning_model(app._direct_sync_health) == band
    app.relay_notice_frame = Widget()
    app.relay_notice_label = Widget(app.relay_notice_frame)
    app.relay_notice_details_label = Widget(app.relay_notice_frame)
    ca.ContainerAudit._apply_relay_warning_layout(app)
    assert app.relay_notice_label.options['text'] == TITLE
    assert app.relay_notice_details_label.options['text'].startswith(DETAIL)
    app._direct_sync_health = replace(health, state='ready', pending_count=0, error_code='', clock_warning={})
    assert all(alert['text'] != TITLE for alert in screen.CaProcessor(app).state()['alerts'])
    assert ca.relay_clock_warning_model(app._direct_sync_health) == {}
    ca.ContainerAudit._apply_relay_warning_layout(app)
    assert not app.relay_notice_frame.visible
