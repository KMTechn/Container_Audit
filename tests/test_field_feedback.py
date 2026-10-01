"""Public scanner regressions for G6/G8/G10; real durable storage, fake UI."""
import json
import sqlite3
import threading
import wave
from datetime import datetime
from urllib.parse import parse_qs, urlsplit
from pathlib import Path
from types import SimpleNamespace

import pytest
import Container_Audit as ca
from tests.test_scanonly_review_regressions import public_scan, real_notice
from tests.test_w9scanonly_workflow import (
    flow, windows, fixed_operation_lease_clock, ITEM, COMPACT_QR, _rows, _pump_until,
)
from tests.test_observed_scanner_completion import ScannerEntry
from tests.test_transfer_seal import FakeSession, FakeResponse
from transfer_client import LogisticsTransferClient
from direct_sync_health import RelayHealth, relay_health_detail_model
from tests.test_container_p0_contracts import _health_card, _insert_relay_row
from direct_sync_push import init_relay_queue_schema

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


@pytest.mark.parametrize('transition', [False, True])
def test_target_completion_uses_longer_existing_sound_after_durable_completion(flow, windows, monkeypatch, transition):
    app = flow(transition=transition)
    signals = []
    monkeypatch.setattr(ca.WavSound, 'play', lambda sound, loops=0:
        signals.append((Path(sound.path).name, len(_rows(app, 'TRAY_COMPLETE')))))
    monkeypatch.setattr(ca.WavSound, 'stop', lambda sound: None)
    app.success_sound = ca.WavSound('assets/success.wav')
    app.completion_sound = ca.WavSound('assets/combo.wav')
    public_scan(app, f'CLC={ITEM}|QT=2' if transition else COMPACT_QR)
    _pump_until(app.root, lambda: bool(app.current_tray.master_label_code)
                and not app._preflight_context_blocks_mutation())
    public_scan(app, ITEM + '-SERIAL-001')
    public_scan(app, ITEM + '-SERIAL-002')
    assert signals[-1] == ('combo.wav', 1)
    assert ('success.wav', 0) in signals
    with wave.open('assets/combo.wav') as longer, wave.open('assets/success.wav') as shorter:
        assert longer.getnframes()/longer.getframerate() > shorter.getnframes()/shorter.getframerate()
    assert windows == []


def test_logistics_connection_failure_preserves_last_successful_send_and_get_does_not_advance_it():
    session = FakeSession(lambda _: FakeResponse(200, {'ok': True, 'data': {'items': []}}))
    client = LogisticsTransferClient('https://fixture.invalid', 'synthetic', 'host',
        authority_scope_id='scope', session=session)
    client._request('POST', '/synthetic-write')
    successful_send = client.last_successful_transmission_at
    assert successful_send and client.connection_state == 'normal'
    client.get_progress(date='2026-10-01')
    assert client.last_successful_transmission_at == successful_send
    def offline(_call):
        raise ConnectionError('synthetic disconnect')
    session.handler = offline
    with pytest.raises(ConnectionError):
        client.get_progress(date='2026-10-01')
    assert client.connection_state == 'disconnected'
    assert client.last_successful_transmission_at == successful_send


def test_connection_card_combines_status_send_time_and_existing_queues(flow, windows):
    app = flow(transition=True)
    card = _health_card()
    app.info_cards = {'direct_sync': card}
    client = app.transfer_seal_coordinator.client
    client.connection_state = 'disconnected'
    client.last_successful_transmission_at = '2026-10-01T01:30:00+00:00'
    app._pending_seal_intent_count = 2
    health = RelayHealth('pending', 3, 0, 0, '2026-10-01T01:00:00+00:00', '', '')
    app._apply_direct_sync_health(health)
    text = card['value'].options['text']
    assert '서버 연결: 끊김' in text
    assert '마지막 성공 전송' in text
    assert '보낼 것 5건' in text
    assert '완료 전송 대기 2건' in text


def test_relay_read_failure_preserves_observed_counts_and_ack_until_read_recovers(flow, windows, monkeypatch):
    app = flow(transition=True)
    card = _health_card()
    app.info_cards = {'direct_sync': card}
    app.transfer_seal_coordinator.client.connection_state = 'normal'
    app.transfer_seal_coordinator.client.last_successful_transmission_at = ''
    app._pending_seal_intent_count = 2
    prior = RelayHealth('pending', 3, 0, 0, '2026-10-01T01:00:00+00:00', '', '')
    app._apply_direct_sync_health(prior)
    last_success_text = card['value'].options['text'].splitlines()[1]

    def unreadable(**kwargs):
        raise OSError('synthetic relay read failure')

    monkeypatch.setattr(ca, 'read_relay_health', unreadable)
    monkeypatch.setattr(app, '_schedule_direct_sync_health_refresh', lambda **kwargs: None)
    app._start_direct_sync_health_refresh()
    _pump_until(app.root, lambda: not app._direct_sync_health_pending)
    assert app._direct_sync_health.pending_count == 3
    assert app._direct_sync_health.last_acked_at == prior.last_acked_at
    text = card['value'].options['text']
    assert '서버 연결: 정상' in text
    assert '보낼 것 5건' in text and '마지막 확인' in text
    assert '대기 건수 확인 불가(읽기 실패)' in text
    assert last_success_text in text

    for code in ('relay_db_open_failed', 'relay_db_schema_unavailable'):
        app._apply_direct_sync_health(RelayHealth('blocked', 0, 0, 0, '', '', '', code))
        assert app._direct_sync_health.pending_count == 3
        assert app._direct_sync_health.last_acked_at == prior.last_acked_at
        assert '대기 건수 확인 불가(읽기 실패)' in card['value'].options['text']

    del app._direct_sync_last_read_health
    app._apply_direct_sync_health(RelayHealth('blocked', 0, 0, 0, '', '', '', 'relay_health_read_failed'))
    text = card['value'].options['text']
    assert '대기 건수 확인 불가(읽기 실패)' in text
    assert '보낼 것 0건' not in text and '대기 0건' not in text
    assert '마지막 성공 전송 없음' not in text

    recovered = RelayHealth('pending', 1, 0, 0, '2026-10-01T02:00:00+00:00', '', '')
    app._apply_direct_sync_health(recovered)
    assert app._direct_sync_health == recovered
    text = card['value'].options['text']
    assert '보낼 것 3건' in text
    assert '읽기 실패' not in text and '마지막 확인' not in text
    assert windows == []


@pytest.mark.parametrize('phase', ['not_loaded', 'first_failure', 'failure_after_read'])
def test_public_relay_detail_distinguishes_unknown_stale_and_recovered_values(
        flow, windows, tmp_path, monkeypatch, phase):
    app = flow(transition=True)
    public_scan(app, f'CLC={ITEM}|QT=3')
    public_scan(app, ITEM + '-SERIAL-001')
    app.direct_sync_program_data_root = str(tmp_path / 'relay')
    app.info_cards = {'direct_sync': _health_card()}
    monkeypatch.setattr(app, '_schedule_direct_sync_health_refresh', lambda **kwargs: None)
    monkeypatch.setattr(app, '_schedule_focus_return', lambda: None)
    captured = []
    monkeypatch.setattr(ca.messagebox, 'showinfo',
                        lambda title, text, **kwargs: captured.append(text))
    db = Path(app.direct_sync_program_data_root) / 'queue/direct_sync_relay.sqlite3'
    db.parent.mkdir(parents=True)

    def refresh():
        app._start_direct_sync_health_refresh()
        _pump_until(app.root, lambda: not app._direct_sync_health_pending)

    if phase == 'failure_after_read':
        init_relay_queue_schema(db)
        _insert_relay_row(db, relay_id='pending', status='pending',
                          created_at='2026-10-01T01:00:00+00:00',
                          updated_at='2026-10-01T01:00:00+00:00')
        _insert_relay_row(db, relay_id='acked', status='acked',
                          created_at='2026-10-01T01:00:00+00:00',
                          updated_at='2026-10-01T02:00:00+00:00')
        refresh()
        prior = app._direct_sync_last_read_health
        with sqlite3.connect(db) as conn:
            conn.execute('ALTER TABLE direct_sync_relay_batches RENAME TO preserved_batches')
    elif phase == 'first_failure':
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE synthetic_schema(id INTEGER)')
    if phase != 'not_loaded':
        refresh()
        assert app._direct_sync_health.error_code == 'relay_db_schema_unavailable'
    app._show_direct_sync_status_details()
    detail = captured[-1]
    if phase == 'failure_after_read':
        assert '대기: 1' in detail and '마지막 확인' in detail and '읽기 실패' in detail
        ack_time = datetime.fromisoformat(prior.last_acked_at).astimezone().strftime('%m-%d %H:%M')
        read_time = datetime.fromisoformat(prior.observed_at).astimezone().strftime('%m-%d %H:%M')
        assert f'마지막 ACK: {ack_time}' in detail
        assert f'마지막 확인 시각: {read_time}' in detail
        with sqlite3.connect(db) as conn:
            conn.execute('ALTER TABLE preserved_batches RENAME TO direct_sync_relay_batches')
            conn.execute("UPDATE direct_sync_relay_batches SET status='acked', "
                         "updated_at='2026-10-01T03:00:00+00:00' WHERE relay_id='pending'")
        refresh()
        app._show_direct_sync_status_details()
        recovered = captured[-1]
        assert '대기: 0' in recovered and '미확인' not in recovered
        assert '읽기 실패' not in recovered and '마지막 확인값' not in recovered
        new_ack_time = datetime.fromisoformat('2026-10-01T03:00:00+00:00').astimezone().strftime('%m-%d %H:%M')
        assert f'마지막 ACK: {new_ack_time}' in recovered
    else:
        for label in ('대기', '영구 실패', '담당자 확인', '가장 오래된 대기', '마지막 ACK'):
            assert f'{label}: 미확인' in detail
        assert '대기: 0' not in detail and '마지막 ACK: 없음' not in detail
        if phase == 'first_failure':
            assert '읽기 실패' in detail
    public_scan(app, ITEM + '-SERIAL-002')
    assert len(app.current_tray.scanned_barcodes) == 2
    assert windows == []


@pytest.mark.parametrize('code', [
    'relay_health_read_failed', 'relay_status_unreadable',
    'relay_db_open_failed', 'relay_db_schema_unavailable', 'relay_health_not_loaded',
])
def test_relay_detail_never_treats_unread_counts_as_measured_zero(code):
    failed = RelayHealth('blocked', 0, 0, 0, '', '', '', code)
    detail = relay_health_detail_model(failed)
    assert detail['대기'] == detail['마지막 ACK'] == '미확인'
    # A measured empty queue is a valid last value, unlike the failed placeholder.
    previous = RelayHealth('ready', 0, 0, 0, '', '', '2026-10-01T01:00:00+00:00')
    detail = relay_health_detail_model(failed, last_read_health=previous)
    assert detail['대기'] == '0' and detail['마지막 ACK'] == '없음'
    assert detail['확인 상태'] == '읽기 실패 · 마지막 확인값'
    assert detail['마지막 확인 시각'] != '없음'


def test_public_refused_scan_uses_repeating_error_sound(flow, windows):
    app = flow(transition=True)
    sounds = []
    app.error_sound = SimpleNamespace(play=lambda loops=0: sounds.append(loops), stop=lambda: None)
    app._ui_close_requested = True
    public_scan(app, 'KMCMD:UNDO')
    assert sounds == [-1]
    assert app.scan_entry.get() == ''
    assert windows == []


def test_sound_device_failure_does_not_interrupt_durable_completion_or_scan_refusal(flow, windows):
    app = flow(transition=True)
    def unavailable(*args, **kwargs):
        raise OSError('synthetic sound device unavailable')
    app.completion_sound = SimpleNamespace(play=unavailable)
    app.error_sound = SimpleNamespace(play=unavailable, stop=unavailable)
    public_scan(app, f'CLC={ITEM}|QT=1')
    public_scan(app, ITEM + '-SERIAL-001')
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert app.current_tray.master_label_code == ''
    app._ui_close_requested = True
    public_scan(app, 'KMCMD:UNDO')
    assert app.scan_entry.get() == ''
    assert windows == []
