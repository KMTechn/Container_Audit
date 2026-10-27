"""Item-file notices finish the real startup route once, with fake windows only."""
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock
import json
import sys

import pytest

import auto_update
import Container_Audit as ca
import ca_screen_bridge as screen
import data_generation_guard
import logistics_runtime_profile
import runtime_instance
import startup_check_report
import user_relay
from tests.test_startup_notice_stop import FakeRoot, FakeTk, STOP_TRACE

REAL_STARTUP_OBSERVE = ca._startup_check_observe


class StartupRoot(FakeRoot):
    def minsize(self, *_args, **_kwargs):
        pass

    geometry = state = configure = iconbitmap = minsize

    def bind(self, name, callback, **_kwargs):
        super().bind(name, callback)


class StartupTk(FakeTk):
    def Tk(self):
        root = StartupRoot(self)
        self.roots.append(root)
        return root


@pytest.fixture
def item_startup(monkeypatch, tmp_path):
    paths = ca.build_container_audit_storage_paths(data_root=tmp_path / 'data')
    paths.data_root.mkdir()
    lease = SimpleNamespace(release=Mock())
    fake = StartupTk(manual=True)
    # Reproduce the constructor's next Tk call after its root was destroyed.
    fake.BooleanVar = Mock(side_effect=RuntimeError('destroyed application'))
    traces, observations, shell_failures = [], [], []
    monkeypatch.setattr(ca, 'tk', fake)
    monkeypatch.setattr(screen, '_HiddenTk', fake.Tk)
    monkeypatch.setattr(ca, 'CA_SCREEN_HOST', {'active': False, 'requested': False, 'run': None})
    monkeypatch.setattr(ca, '_record_startup_notice_stop', lambda **fields: traces.append(fields))
    native_notice = Mock()
    monkeypatch.setattr(ca, '_show_startup_notice_native', native_notice)

    def observe(action, *args, **kwargs):
        observations.append((action, args, kwargs))
        return action == 'finish' and kwargs.get('refused', False)

    monkeypatch.setattr(ca, '_startup_check_observe', observe)
    monkeypatch.setattr(ca, 'begin_gui_entry', lambda *_args, **_kwargs: True)
    monkeypatch.setattr(ca, 'end_gui_entry', Mock())
    monkeypatch.setattr(auto_update, 'startup_gate', lambda *_args: None)
    monkeypatch.setattr(auto_update, 'trial_context', lambda *_args: None)
    monkeypatch.setattr(ca, 'dispatch_product_mode', lambda *_args: None)
    monkeypatch.setattr(ca, 'build_container_audit_storage_paths', lambda **_kwargs: paths)
    monkeypatch.setattr(ca, 'acquire_runtime_instance', lambda *_args: lease)
    monkeypatch.setattr(ca, 'writer_admission', lambda *_args: nullcontext())
    for name in ('verify_factory_contract_startup', 'probe_before_owner_paths',
                 'record_before_owner_paths', 'validate_existing_data_root',
                 'clear_shutdown_stall', 'write_item_catalog_startup_diagnostic'):
        monkeypatch.setattr(ca, name, Mock())
    monkeypatch.setattr(data_generation_guard, 'warm_runtime_release', Mock())
    monkeypatch.setattr(runtime_instance, 'read_shutdown_stall', lambda *_args: None)
    monkeypatch.setattr(logistics_runtime_profile, 'resolve_logistics_profile_path',
                        lambda: tmp_path / 'profile.json')
    monkeypatch.setattr(ca, 'default_protected_admin_profile_path',
                        lambda: tmp_path / 'protected.json')
    monkeypatch.setattr(ca, 'consume_pending_machine_onboarding', lambda *_args: None)
    monkeypatch.setattr(ca, '_first_run_onboarding_enabled', lambda: False)
    monkeypatch.setattr(ca, 'prepare_startup_item_catalog', lambda: str(tmp_path / 'Item.csv'))
    monkeypatch.setenv(ca.ACTIVE_PATH_ENV, str(tmp_path / 'Item.csv'))
    monkeypatch.setattr(ca, 'get_catalog_attempt_context', lambda: {})
    monkeypatch.setattr(ca, 'get_verified_catalog_snapshot', lambda *_args: None)
    monkeypatch.setattr(ca, 'requires_verified_catalog_snapshot', lambda *_args: False)
    monkeypatch.setattr(ca, 'container_startup_logistics_client', lambda **_kwargs: None)
    monkeypatch.setattr(ca, 'legacy_label_transition_enabled', lambda: False)
    monkeypatch.setattr(ca, 'fit_restored_window_to_work_area', Mock())

    def setup(app):
        app.data_root = paths.data_root
        app.config_folder = str(paths.data_root / 'config')
        app.direct_sync_program_data_root = paths.direct_sync_root
        app.direct_sync_scan_source_dir = paths.data_root / 'events'
        app.parked_trays_dir = paths.data_root / 'parked'

    monkeypatch.setattr(ca.ContainerAudit, '_setup_paths_and_dirs', setup)
    monkeypatch.setattr(ca.ContainerAudit, 'load_app_settings', lambda _self: {})
    monkeypatch.setattr(ca.ContainerAudit, '_load_best_time_records', lambda _self: None)
    for name in ('OperationLeaseManager', 'OperationLeaseStore', 'PinnedOperationLeaseKeyring',
                 'TransferSealCoordinator', 'TransferSealStore', 'TransferMemberExchangeCoordinator',
                 'TransferMemberExchangeStore', 'PHSLabelExchangeCoordinator',
                 'PHSLabelExchangeJournal', 'PHSLabelRenderer', 'WorkerRegistry',
                 'WorkerRoster', 'ParkedTrayStore', 'start_direct_sync_auto_bootstrap'):
        monkeypatch.setattr(ca, name, Mock())

    monkeypatch.setattr(user_relay, 'native_app_process_snapshot', lambda: [])
    monkeypatch.setattr(user_relay, 'request_user_relay_stop',
                        lambda *_args, **_kwargs: {'status': 'STOPPED'})
    monkeypatch.setattr(screen, '_check_screen_ready', lambda: None)
    monkeypatch.setattr(screen, 'shell_data_dir', lambda: tmp_path / 'shell')
    bridge = SimpleNamespace(fail_owner=shell_failures.append)
    shell_calls = []

    def run_app(*_args, **kwargs):
        shell_calls.append(True)
        kwargs['owner_main'](bridge)
        if shell_failures:
            raise shell_failures[-1]
        return 'web'

    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    monkeypatch.setitem(sys.modules, 'webview', SimpleNamespace(windows=[]))
    return SimpleNamespace(paths=paths, lease=lease, tk=fake, traces=traces,
                           observations=observations, native=native_notice,
                           shell_calls=shell_calls, shell_failures=shell_failures)


@pytest.mark.parametrize('web', [False, True], ids=['tk', 'web'])
@pytest.mark.parametrize('stop', [False, True], ids=['close', 'stop'])
@pytest.mark.parametrize('failure', ['missing', 'read', 'encoding'])
def test_item_notice_finishes_main_without_second_notice_or_fallback(
        item_startup, monkeypatch, failure, stop, web):
    state = item_startup
    if stop:
        state.tk.manual = False

        def publish_once():
            state.tk.publish = None
            user_relay.request_app_stop(state.paths.direct_sync_root, timeout_seconds=0)

        state.tk.publish = publish_once

    def fail_open(*_args, **_kwargs):
        raise {'missing': FileNotFoundError('missing'), 'read': OSError('unreadable'),
               'encoding': UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid')}[failure]

    reader = Mock(side_effect=fail_open)
    monkeypatch.setattr(ca, 'open', reader, raising=False)
    outcome = None
    try:
        outcome = ca.main([] if web else [ca.CA_OLD_SCREEN_ARGUMENT])
    except Exception as error:
        outcome = type(error).__name__

    assert len(state.tk.buttons) == 1, 'exactly one acknowledged startup notice'
    assert outcome == 0
    assert len(state.tk.roots) == 3  # app, visible owner, notice
    assert all(root.destroyed and not root.jobs for root in state.tk.roots)
    state.tk.BooleanVar.assert_not_called()
    assert reader.call_count == (4 if failure == 'encoding' else 1)
    state.lease.release.assert_called_once()
    assert state.traces == ([STOP_TRACE] if stop else [])
    assert user_relay.read_app_stop_request(state.paths.direct_sync_root) is None
    assert not [row for row in state.observations if row[2].get('refused')]
    assert not [row for row in state.observations if 'FALLBACK' in str(row[1])]
    assert len(state.shell_calls) == int(web)
    if web:
        assert len(state.shell_failures) == 1
        assert isinstance(state.shell_failures[0], screen.CaStartupRefused)
        assert state.shell_failures[0].code == 0
    state.native.assert_not_called()


@pytest.mark.parametrize('stop', [False, True], ids=['close', 'stop'])
def test_missing_item_notice_rewrites_real_start_check(item_startup, monkeypatch, stop):
    state = item_startup
    program_data = state.paths.data_root / 'program-data'
    folder = program_data / 'KMTech' / 'start-check'
    folder.mkdir(parents=True)
    monkeypatch.setenv('PROGRAMDATA', str(program_data))
    monkeypatch.delenv('KMTECH_START_CHECK_TEST_CATEGORY', raising=False)
    monkeypatch.setattr(ca, '_startup_check_observe', REAL_STARTUP_OBSERVE)
    if stop:
        state.tk.manual = False

        def publish_once():
            state.tk.publish = None
            user_relay.request_app_stop(state.paths.direct_sync_root, timeout_seconds=0)

        state.tk.publish = publish_once

    startup_check_report.finish()
    try:
        assert ca.main([]) == 0
        files = list(folder.glob('*-CA.json'))
        assert len(files) == 1
        result = json.loads(files[0].read_text(encoding='utf-8'))
        assert result['startable'] is False
        assert result['category'] == 'UNKNOWN'
        assert 'UNKNOWN_CHECK' in result['reasons']
        assert len(state.tk.buttons) == 1
        assert state.traces == ([STOP_TRACE] if stop else [])
        state.tk.BooleanVar.assert_not_called()
        state.lease.release.assert_called_once()
        state.native.assert_not_called()
    finally:
        startup_check_report.finish()


def test_both_item_notice_backends_failing_keep_general_error_path(item_startup, monkeypatch):
    state = item_startup
    original_factory = state.tk.Tk

    def only_app_root():
        if not state.tk.roots:
            return original_factory()
        raise RuntimeError('Tk notice unavailable')

    monkeypatch.setattr(state.tk, 'Tk', only_app_root)
    state.native.side_effect = OSError('native notice unavailable')
    with pytest.raises(RuntimeError, match='destroyed application'):
        ca.main([ca.CA_OLD_SCREEN_ARGUMENT])
    state.tk.BooleanVar.assert_called_once()
    assert state.native.call_count == 2  # Item notice, then the existing generic refusal.
    assert any(row[2].get('failed') and row[2].get('refused') for row in state.observations)
    state.lease.release.assert_called_once()


def test_native_item_notice_success_still_finishes_quietly(item_startup, monkeypatch):
    state = item_startup
    original_factory = state.tk.Tk

    def only_app_root():
        if not state.tk.roots:
            return original_factory()
        raise RuntimeError('Tk notice unavailable')

    monkeypatch.setattr(state.tk, 'Tk', only_app_root)
    assert ca.main([ca.CA_OLD_SCREEN_ARGUMENT]) == 0
    state.native.assert_called_once()
    state.tk.BooleanVar.assert_not_called()
    state.lease.release.assert_called_once()


def test_integrity_banner_preserves_recent_note_when_other_bands_are_present():
    notice = SimpleNamespace(blocking=True, code='test.notice', severity=None,
                             title='공지', message='확인할 일')
    app = SimpleNamespace(_bootstrap_integrity_absent=True, is_idle=True,
                          _operator_review_blocks_mutation=lambda: False,
                          _catalog_notice_for_display=lambda: '품목 안내')
    notes = [{'kind': 'info', 'text': '최근 처리 알림'}]
    alerts = screen._alerts(app, SimpleNamespace(active_notice=notice), notes,
                            ca.datetime.datetime.now())
    assert [band['text'] for band in alerts] == [
        '공지 — 확인할 일', '휴식 상태 — 스캔하면 작업을 다시 시작합니다',
        '품목 안내', '최근 처리 알림']
    assert alerts[-1]['choices'][0]['id'] == 'note_ok'
    app.is_idle = False
    app._catalog_notice_for_display = lambda: ''
    alerts = screen._alerts(app, SimpleNamespace(active_notice=None), [],
                            ca.datetime.datetime.now())
    assert alerts == [{'kind': 'warn', 'text': ca.BOOTSTRAP_INTEGRITY_WARNING_MESSAGE}]
