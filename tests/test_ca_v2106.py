"""Headless regressions for the specified v2.0.106 adapter changes."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from preflight_scan_hold import PreflightHoldSnapshot, QuarantinedPreflightHold, HOLD_LOOKUP, HOLD_LOOKUP_FAILED
from tests.test_ca_screen_bridge import _app, _schema_errors
from tests.test_observed_scanner_completion import ScannerEntry
from tests.test_ca_new_screen_entry import entry
from tests.test_worker_roster_registration import application, roster, worker
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'windows', 'owned_tk_workers')


def test_held_quarantine_and_server_wait_have_identifiable_read_only_rows(flow, tmp_path):
    app = _app(flow)
    holds = []
    for index, state in enumerate((HOLD_LOOKUP_FAILED, HOLD_LOOKUP)):
        snapshot = PreflightHoldSnapshot('synthetic-hold', 1, app.worker_name, COMPACT_QR,
                                        '', '', state, (), 'PHS2_PREFLIGHT_UNAVAILABLE')
        holds.append(QuarantinedPreflightHold(tmp_path / f'hold-{index}.json', snapshot, ''))
    app._quarantined_preflight_holds = lambda: tuple(holds)
    app._parked_store = lambda: SimpleNamespace(scan_for_worker=lambda *a, **kw: [])
    writes = []
    app.restore_parked_tray = lambda path: writes.append(path)
    processor = screen.CaProcessor(app)
    processor.command('open', {'id': 'held'})
    state = processor.state()
    assert state['held_count'] == len(state['park']) == 2
    assert _schema_errors(state, screen.json.loads(screen.CONTRACT.read_bytes())['state']) == []
    fields = app._parse_new_format_qr(COMPACT_QR)
    for row, kind, title in zip(state['park'], ('quarantine', 'server_wait'), ('사전조회 격리', '서버 확인 대기')):
        assert row['kind'] == kind and row['restorable'] is False
        assert fields['CLC'] in row['label'] and fields['LBL'] in row['label']
        assert row['note'].startswith(title + ' — ')
        assert 'PHS2_PREFLIGHT_UNAVAILABLE' not in row['note'] and str(tmp_path) not in row['note']
        assert processor.command('restore', {'id': row['id']})['ok'] is False
    assert not writes


def test_registration_selects_existing_identity_and_distinguishes_another_person(flow, tmp_path):
    app = application(flow, tmp_path)
    app.worker_entry = ScannerEntry("")
    existing = worker('작업자')
    app.worker_roster = roster(tmp_path / 'named-roster', existing)
    processor = screen.CaProcessor(app)
    assert processor.command('register_worker', {'name': '작업자'})['ok']
    assert not app.worker_roster.pending_requests()
    state = processor.state()
    assert state['register']['name'] == '작업자'
    assert state['register']['cands'] == [{'id': existing['worker_id'], 'label': ca.worker_choice_label(existing)}]
    assert _schema_errors(state, screen.json.loads(screen.CONTRACT.read_bytes())['state']) == []
    app._select_worker = lambda *_args, **_kwargs: True
    assert processor.command('start_work', {'id': existing['worker_id']})['ok']
    assert app.worker_roster.pending_requests()[0]['existing_worker_id'] == existing['worker_id']
    assert processor.command('register_worker', {'name': '작업자B'})['ok']
    pending = app.worker_roster.pending_requests()
    assert any(row['mode'] == 'create' and row['display_name'] == '작업자B' for row in pending)


def test_registration_rechecks_candidate_identity_when_roster_changes(flow, tmp_path):
    app = application(flow, tmp_path)
    app.worker_entry = ScannerEntry("")
    existing = worker('작업자')
    app.worker_roster = roster(tmp_path / 'named-roster', existing)
    processor = screen.CaProcessor(app)
    processor.command('register_worker', {'name': '작업자'})
    app.worker_roster.duplicate_workers = lambda name: []
    app._select_worker = lambda *_a, **_k: pytest.fail('A stale identity must not start work')
    assert processor.command('start_work', {'id': existing['worker_id']})['ok'] is False
    assert not app.worker_roster.pending_requests()


@pytest.mark.parametrize('arguments', [['--ui', 'tk'], ['--ui=tk'], ['--old-screen', '--ui', 'web']])
def test_emergency_ui_alias_uses_the_existing_tk_entry(entry, arguments):
    assert ca.main(arguments) == 0
    assert not entry.host_calls and entry.releases == [True]


@pytest.mark.parametrize('arguments', [['--ui', 'web'], ['--ui', 'unknown'], ['--ui=unknown']])
def test_web_and_unknown_ui_values_use_the_default_screen(entry, arguments):
    assert ca.main(arguments) == 0
    assert len(entry.host_calls) == 1 and entry.releases == [True]


@pytest.mark.parametrize('value', [None, ''])
def test_shell_data_requires_a_user_data_root(monkeypatch, value):
    if value is None:
        monkeypatch.delenv('LOCALAPPDATA', raising=False)
    else:
        monkeypatch.setenv('LOCALAPPDATA', value)
    with pytest.raises(RuntimeError):
        screen.shell_data_dir()


def test_empty_inherited_pythonpath_does_not_add_the_current_directory(tmp_path, monkeypatch):
    from tests.conftest import isolate_product_state
    monkeypatch.setenv('PYTHONPATH', '')
    isolate_product_state.__wrapped__(tmp_path / 'second-isolation', monkeypatch)
    if any(not part for part in os.environ['PYTHONPATH'].split(os.pathsep)):
        raise AssertionError('A child search path includes an empty component')
