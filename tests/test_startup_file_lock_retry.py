from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import errno
import io
import json

import pytest

import Container_Audit as app_module
import legacy_state_migration as migration
import event_log_store


def locked(kind):
    if kind == 'permission':
        return PermissionError('locked')
    error = OSError('locked')
    error.winerror = kind
    return error


@pytest.mark.parametrize('kind', ['permission', 5, 32, 33])
@pytest.mark.parametrize('release', [True, False])
def test_items_retry_only_file_locks(monkeypatch, kind, release):
    reader = Mock(side_effect=[locked(kind), locked(kind)] + (
        [io.StringIO('Item Code,Item Name\n123,Part\n')] if release
        else [locked(kind), locked(kind)]))
    sleeps = Mock()
    errors = Mock()
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    app.root = SimpleNamespace(destroy=Mock())
    monkeypatch.setattr(app_module, 'open', reader, raising=False)
    monkeypatch.setattr(app_module.time, 'sleep', sleeps)
    monkeypatch.setattr(app_module, 'get_verified_catalog_snapshot', lambda path: None)
    monkeypatch.setattr(app_module, 'requires_verified_catalog_snapshot', lambda path: False)
    monkeypatch.setattr(app_module.messagebox, 'showerror', errors)

    rows = app.load_items(read_retry=app_module.StartupReadRetry())

    assert reader.call_count == (3 if release else 4)
    assert sleeps.call_args_list == [((1,),)] * (2 if release else 3)
    if release:
        assert rows[0]['Item Code'] == '123'
        errors.assert_not_called()
        app.root.destroy.assert_not_called()
    else:
        assert rows == []
        assert errors.call_args.args[0] == '파일 읽기 오류'
        app.root.destroy.assert_called_once()


@pytest.mark.parametrize('error,title', [
    (OSError(errno.EIO, 'disk error'), '파일 읽기 오류'),
    (FileNotFoundError('absent'), '필수 파일 없음'),
])
def test_items_other_errors_keep_existing_failure(monkeypatch, error, title):
    reader = Mock(side_effect=error)
    sleeps = Mock()
    errors = Mock()
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    app.root = SimpleNamespace(destroy=Mock())
    monkeypatch.setattr(app_module, 'open', reader, raising=False)
    monkeypatch.setattr(app_module.time, 'sleep', sleeps)
    monkeypatch.setattr(app_module, 'get_verified_catalog_snapshot', lambda path: None)
    monkeypatch.setattr(app_module, 'requires_verified_catalog_snapshot', lambda path: False)
    monkeypatch.setattr(app_module.messagebox, 'showerror', errors)
    assert app.load_items() == []
    reader.assert_called_once()
    sleeps.assert_not_called()
    assert errors.call_args.args[0] == title
    app.root.destroy.assert_called_once()


@pytest.mark.parametrize('kind', ['permission', 5, 32, 33])
@pytest.mark.parametrize('release', [True, False])
def test_migration_marker_lock_keeps_existing_state(monkeypatch, tmp_path, kind, release):
    code = tmp_path / 'code'
    code.mkdir()
    config = tmp_path / 'state' / 'config'
    parked = tmp_path / 'state' / 'parked'
    config.mkdir(parents=True)
    marker = config / migration.MIGRATION_MARKER_NAME
    payload = json.dumps({'schema_version': migration.MIGRATION_SCHEMA, 'status': 'PASS'})
    marker.write_text(payload, encoding='utf-8')
    original_read = Path.read_text
    reads = Mock(side_effect=[locked(kind), locked(kind)] + (
        [payload] if release else [locked(kind), locked(kind)]))
    def read(path, *args, **kwargs):
        return reads() if path == marker else original_read(path, *args, **kwargs)
    sleeps = Mock()
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(app_module.time, 'sleep', sleeps)
    if release:
        result = migration.migrate_legacy_code_root_state(
            application_path=code, config_dir=config, parked_trays_dir=parked,
            read_retry=app_module.StartupReadRetry())
        assert result['status'] == 'REUSED'
    else:
        with pytest.raises(ValueError, match='marker is invalid'):
            migration.migrate_legacy_code_root_state(
                application_path=code, config_dir=config, parked_trays_dir=parked,
                read_retry=app_module.StartupReadRetry())
    assert reads.call_count == (3 if release else 4)
    assert sleeps.call_args_list == [((1,),)] * (2 if release else 3)
    assert original_read(marker, encoding='utf-8') == payload


@pytest.mark.parametrize('failure', [OSError(errno.EIO, 'disk error'), '{invalid'])
def test_marker_other_errors_are_not_retried(monkeypatch, tmp_path, failure):
    code = tmp_path / 'code'
    code.mkdir()
    config = tmp_path / 'state' / 'config'
    config.mkdir(parents=True)
    marker = config / migration.MIGRATION_MARKER_NAME
    marker.write_text('{}', encoding='utf-8')
    reads = Mock(side_effect=failure) if isinstance(failure, OSError) else Mock(return_value=failure)
    monkeypatch.setattr(Path, 'read_text', reads)
    sleeps = Mock()
    monkeypatch.setattr(app_module.time, 'sleep', sleeps)
    with pytest.raises(ValueError, match='marker is invalid'):
        migration.migrate_legacy_code_root_state(
            application_path=code, config_dir=config, parked_trays_dir=tmp_path / 'state' / 'parked')
    reads.assert_called_once()
    sleeps.assert_not_called()


@pytest.mark.parametrize('kind', ['permission', 5, 32, 33])
@pytest.mark.parametrize('release', [True, False])
def test_startup_pending_outbox_lock_preserves_original(monkeypatch, tmp_path, kind, release):
    path = tmp_path / '00000000000000000001-pending.json'
    payload = json.dumps({'log_file_path': 'events.csv', 'log_entry': {'event': 'APP_START'}})
    path.write_text(payload, encoding='utf-8')
    original_read = Path.read_text
    reads = Mock(side_effect=[locked(kind), locked(kind)] + (
        [payload] if release else [locked(kind), locked(kind)]))
    def read(target, *args, **kwargs):
        return reads() if target == path else original_read(target, *args, **kwargs)
    sleeps = Mock()
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(event_log_store.time, 'sleep', sleeps)
    if release:
        outbox = event_log_store.EventLogOutbox(tmp_path, read_retry=app_module.StartupReadRetry())
        assert list(outbox._staged_paths.values()) == [path]
    else:
        with pytest.raises(OSError):
            event_log_store.EventLogOutbox(tmp_path, read_retry=app_module.StartupReadRetry())
    assert reads.call_count == (3 if release else 4)
    assert sleeps.call_args_list == [((1,),)] * (2 if release else 3)
    assert original_read(path, encoding='utf-8') == payload


def test_item_lock_wait_budget_is_shared_across_encoding_fallbacks(monkeypatch):
    undecodable = UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid')
    reader = Mock(side_effect=[PermissionError('locked'), undecodable] + [locked(32)] * 3)
    sleeps = Mock()
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    app.root = SimpleNamespace(destroy=Mock())
    monkeypatch.setattr(app_module, 'open', reader, raising=False)
    monkeypatch.setattr(app_module.time, 'sleep', sleeps)
    monkeypatch.setattr(app_module, 'get_verified_catalog_snapshot', lambda path: None)
    monkeypatch.setattr(app_module, 'requires_verified_catalog_snapshot', lambda path: False)
    with pytest.raises(OSError):
        app.load_items(show_errors=False, read_retry=app_module.StartupReadRetry())
    assert reader.call_count == 5
    assert sleeps.call_args_list == [((1,),)] * 3
    app.root.destroy.assert_not_called()


@pytest.mark.parametrize('failure', [OSError(errno.EIO, 'disk error'), ValueError('invalid')])
def test_pending_outbox_other_failure_does_not_retry_or_mutate(monkeypatch, tmp_path, failure):
    path = tmp_path / '00000000000000000001-pending.json'
    path.write_text('{}', encoding='utf-8')
    reads = Mock(side_effect=failure)
    sleeps = Mock()
    monkeypatch.setattr(Path, 'read_text', reads)
    monkeypatch.setattr(event_log_store.time, 'sleep', sleeps)
    with pytest.raises(type(failure)):
        event_log_store.EventLogOutbox(tmp_path)
    reads.assert_called_once()
    sleeps.assert_not_called()
    assert path.read_bytes() == b'{}'


@pytest.mark.parametrize('release', [True, False])
def test_work_session_startup_read_retries_without_changing_state(monkeypatch, tmp_path, release):
    path = tmp_path / 'session.json'
    path.write_text('{}', encoding='utf-8')
    reads = Mock(side_effect=[locked(32), locked(32)] + (
        [io.StringIO('{"phase":"ACTIVE"}')] if release else [locked(32), locked(32)]))
    original_open = Path.open
    def open_state(target, *args, **kwargs):
        return reads() if target == path else original_open(target, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', open_state)
    sleeps = Mock()
    monkeypatch.setattr(app_module.time, 'sleep', sleeps)
    monkeypatch.setattr(app_module, 'validate_work_session_state', lambda value: value)
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    app._work_session_state_path = lambda: path
    if release:
        assert app._load_work_session_state(read_retry=app_module.StartupReadRetry()) == {'phase': 'ACTIVE'}
    else:
        with pytest.raises(OSError):
            app._load_work_session_state(read_retry=app_module.StartupReadRetry())
    assert reads.call_count == (3 if release else 4)
    assert sleeps.call_count == (2 if release else 3)


def test_work_session_startup_caller_passes_budget_but_runtime_does_not():
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    app._work_session_state_path = Mock(return_value='session.json')
    app._load_work_session_state = Mock(return_value=None)
    budget = app_module.StartupReadRetry()
    assert app._reconcile_work_session_state(read_retry=budget)
    app._load_work_session_state.assert_called_once_with(read_retry=budget)
    app._load_work_session_state.reset_mock()
    assert app._reconcile_work_session_state()
    app._load_work_session_state.assert_called_once_with()


def test_profile_factory_passes_startup_budget_only_when_given(monkeypatch):
    import transfer_client
    profile_loader = Mock(return_value=None)
    monkeypatch.setattr(transfer_client, 'load_logistics_runtime_profile', profile_loader)
    budget = app_module.StartupReadRetry()
    assert transfer_client.logistics_transfer_client_from_env(
        environ={}, probe_required=False, read_retry=budget) is None
    assert profile_loader.call_args.kwargs['read_retry'] is budget
    profile_loader.reset_mock()
    transfer_client.logistics_transfer_client_from_env(environ={}, probe_required=False)
    assert 'read_retry' not in profile_loader.call_args.kwargs
