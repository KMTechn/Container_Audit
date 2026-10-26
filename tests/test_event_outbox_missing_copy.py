"""A removed retry copy cannot authorize deletion of a live audit source."""
import json
from pathlib import Path

import pytest
import event_log_store as logs
from tests.test_container_audit_contracts import _completion_app
from tests.test_event_log_projection import entry, rows


@pytest.mark.parametrize('source_name', [None, 'state', 'undo_state'])
def test_missing_outbox_after_csv_failure_replays_checkpoint_once(tmp_path, monkeypatch, source_name):
    app = _completion_app(tmp_path)
    original = entry('missing-copy-checkpoint')
    event = {'log_file_name': Path(app.log_file_path).name, 'local_only': False,
             'log_entry': original, 'worker_record': {}}
    source = {'pending_audit_events': [event]}
    state = source if source_name is None else {source_name: source}
    checkpoint = tmp_path / app.CURRENT_TRAY_STATE_FILE
    checkpoint.write_text(json.dumps(state), encoding='utf-8')
    app.current_tray.pending_audit_events = [event]
    store = app._event_log_outbox(app.log_file_path)

    def locked_csv(*args, **kwargs):
        raise PermissionError('synthetic CSV lock')

    with monkeypatch.context() as fault:
        fault.setattr(logs, 'append_event_log_entry_idempotent', locked_csv)
        assert app._flush_pending_event_logs() is False
        pending, = store.directory.glob('*.json')
        pending.unlink()  # Only the fake retry copy is removed, not the source.
        assert app._flush_pending_event_logs() is False
        saved = json.loads(checkpoint.read_text(encoding='utf-8'))
        saved_source = saved if source_name is None else saved[source_name]
        assert saved_source['pending_audit_events'] == [event]
        assert app.current_tray.pending_audit_events == [event]
        assert '재시도' in app._event_log_notice

    assert app._flush_pending_event_logs() is True
    assert rows(Path(app.log_file_path)) == [original]
    assert app._flush_pending_event_logs() is True
    assert rows(Path(app.log_file_path)) == [original]
    assert app.current_tray.pending_audit_events == []


def test_cached_stage_recreates_removed_pending_copy(tmp_path):
    store = logs.EventLogOutbox(tmp_path / '_event_outbox')
    path = str(tmp_path / 'events.csv')
    original = entry('same-payload')
    first = store.stage(path, original)
    first.unlink()
    replacement = store.stage(path, original)
    assert replacement is not None and replacement.is_file()
    assert json.loads(replacement.read_text(encoding='utf-8'))['log_entry'] == original
    store.drain()
    store.drain()
    assert rows(Path(path)) == [original]


def test_missing_ordinary_scan_copy_is_rebuilt_before_csv_retry(tmp_path, monkeypatch):
    app = _completion_app(tmp_path)
    original = entry('ordinary-missing-copy')
    store = app._event_log_outbox(app.log_file_path)
    assert app._write_event_log_entry({
        'log_file_path': app.log_file_path, 'log_entry': original,
        'worker_record': {}, 'local_only': False,
    }, synchronous=False) is True
    assert app.log_queue.qsize() == 1
    assert app.current_tray.pending_audit_events == []

    def locked_csv(*args, **kwargs):
        raise PermissionError('synthetic CSV lock')

    with monkeypatch.context() as fault:
        fault.setattr(logs, 'append_event_log_entry_idempotent', locked_csv)
        assert app._flush_pending_event_logs() is False
        pending, = store.directory.glob('*.json')
        saved = pending.read_bytes()
        pending.unlink()
        assert app._flush_pending_event_logs() is False
        replacement, = store.directory.glob('*.json')
        assert json.loads(replacement.read_bytes()) == json.loads(saved)
        assert '로그 저장 실패' in app._event_log_notice

    # A second copy reappearing after quarantine still projects exactly once.
    pending.write_bytes(saved)
    restarted = logs.EventLogOutbox(store.directory)
    restarted.drain()
    store.drain()
    assert rows(Path(app.log_file_path)) == [original]
    assert list(store.directory.glob('*.json')) == []
    assert app._flush_pending_event_logs() is True


def test_missing_copy_restage_write_failure_keeps_original_for_retry(tmp_path, monkeypatch):
    store = logs.EventLogOutbox(tmp_path / '_event_outbox')
    path = str(tmp_path / 'events.csv')
    original = entry('ordinary-restage-write-failure')
    pending = store.stage(path, original)
    pending.unlink()

    def locked_outbox(*args, **kwargs):
        raise PermissionError('synthetic outbox lock')

    with monkeypatch.context() as fault:
        fault.setattr(logs, 'atomic_write_json', locked_outbox)
        with pytest.raises(PermissionError):
            store.drain()
        assert store.has_unstaged

    store.drain()
    store.drain()
    assert rows(Path(path)) == [original]


def test_copy_removed_between_recovery_and_drain_clears_only_after_projection(tmp_path, monkeypatch):
    app = _completion_app(tmp_path)
    original = entry('removed-before-drain')
    event = {'log_file_name': Path(app.log_file_path).name, 'local_only': False,
             'log_entry': original, 'worker_record': {}}
    checkpoint = tmp_path / app.CURRENT_TRAY_STATE_FILE
    checkpoint.write_text(json.dumps({'pending_audit_events': [event]}), encoding='utf-8')
    store = app._event_log_outbox(app.log_file_path)
    drain = store.drain

    def remove_then_drain(**kwargs):
        for path in store.directory.glob('*.json'):
            path.unlink()
        return drain(**kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(store, 'drain', remove_then_drain)
        assert app._flush_pending_event_logs() is True
        assert rows(Path(app.log_file_path)) == [original]
        assert json.loads(checkpoint.read_text(encoding='utf-8')).get('pending_audit_events', []) == []
    assert app._flush_pending_event_logs() is True
    assert rows(Path(app.log_file_path)) == [original]
