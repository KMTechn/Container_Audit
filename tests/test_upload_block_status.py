"""Shared seven-field observer record, using isolated application data only."""
from datetime import datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import direct_sync_push as push
import direct_sync_runtime as runtime
import producer_runtime_client as lease
from tests import test_direct_sync_push as push_helpers
from tests import test_direct_sync_runtime as runtime_helpers


FIELDS = {'schema', 'app', 'blocked_files', 'blocked_records', 'install_review', 'since', 'updated'}


@pytest.fixture
def target(tmp_path, monkeypatch):
    path = tmp_path / 'app-root' / 'upload_block_status.json'
    monkeypatch.setattr(runtime, '_upload_block_status_path', lambda: path, raising=False)
    return path


def test_status_uses_canonical_app_root(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'build_container_audit_storage_paths',
                        lambda **kw: SimpleNamespace(data_root=tmp_path / 'app-root'), raising=False)
    assert runtime._upload_block_status_path() == tmp_path / 'app-root' / 'upload_block_status.json'


def test_seven_fields_utf8_and_clear_record_remains_on_disk(target, monkeypatch):
    now = '2026-10-26T06:00:00Z'
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: now)
    runtime._publish_upload_block_status({'scan_terminal_blocked_count': 0,
                                          'scan_terminal_blocked_record_count': 0}, force=True)
    raw = target.read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf')
    record = json.loads(raw)
    assert set(record) == FIELDS
    assert record == {'schema': 1, 'app': 'CA', 'blocked_files': 0, 'blocked_records': 0,
                      'install_review': False, 'since': None, 'updated': now}
    assert datetime.fromisoformat(record['updated'].replace('Z', '+00:00')).tzinfo is not None


def test_changed_counts_and_each_relay_tick_refresh_without_payload_details(target, monkeypatch):
    first, later = '2026-10-26T06:00:00Z', '2026-10-26T07:00:00Z'
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: first)
    status = {'scan_terminal_blocked_count': 1, 'scan_terminal_blocked_record_count': 4,
              'scan_terminal_blocked_source_files': ['not-emitted.csv'], 'worker_name': 'not-emitted'}
    runtime._publish_upload_block_status(status, force=False)
    initial = target.read_bytes()
    record = json.loads(initial)
    assert record['blocked_files'] == 1 and record['blocked_records'] == 4 and record['since'] == first
    assert set(record) == FIELDS and b'not-emitted' not in initial
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: later)
    runtime._publish_upload_block_status(status, force=False)
    assert target.read_bytes() == initial
    runtime._publish_upload_block_status(status, force=True)
    refreshed = json.loads(target.read_bytes())
    assert refreshed['updated'] == later and refreshed['since'] == first
    runtime._publish_upload_block_status({'scan_terminal_blocked_count': 0,
                                          'scan_terminal_blocked_record_count': 0}, force=False)
    cleared = json.loads(target.read_bytes())
    assert (cleared['blocked_files'], cleared['blocked_records'], cleared['install_review'], cleared['since']) == (0, 0, False, None)


def test_observer_write_failure_is_one_log_line_and_keeps_upload_result(target, tmp_path, monkeypatch, caplog):
    real_write = runtime._write_json_atomic
    def fail_observer(path, payload):
        if Path(path) == target:
            raise PermissionError('synthetic observer failure')
        return real_write(path, payload)
    monkeypatch.setattr(runtime, '_write_json_atomic', fail_observer)
    monkeypatch.setattr(push, 'prepare_runtime_metadata',
                        lambda **kw: lease.RuntimePreparation(metadata=dict(kw['metadata'])))
    monkeypatch.setattr(runtime, 'ensure_runtime_authority', lambda **kw: lease.RuntimePreparation())
    config = runtime_helpers.make_config(tmp_path)
    credentials = push_helpers.make_credentials()
    runtime.enqueue_completed_source_file(config, source_file_path=runtime_helpers.write_csv(tmp_path),
                                          credentials=credentials)
    caplog.clear()
    status = runtime.run_relay_once(config, credentials=credentials,
                                   session=runtime_helpers.EchoAcceptedSession())
    assert status['status'] == 'acked'
    assert sum('upload_block_status_write_failed' in record.message for record in caplog.records) == 1


def test_atomic_replace_failure_preserves_existing_status(target, monkeypatch):
    runtime._publish_upload_block_status({'scan_terminal_blocked_count': 0,
                                          'scan_terminal_blocked_record_count': 0}, force=True)
    original = target.read_bytes()
    import atomic_replace
    monkeypatch.setattr(atomic_replace, 'atomic_replace',
                        lambda *args, **kw: (_ for _ in ()).throw(PermissionError('synthetic replace failure')))
    runtime._publish_upload_block_status({'scan_terminal_blocked_count': 1,
                                          'scan_terminal_blocked_record_count': 4}, force=True)
    assert target.read_bytes() == original
    assert set(json.loads(original)) == FIELDS


def test_unknown_record_count_stays_null_and_scan_since_uses_utc_z(target, monkeypatch):
    first = '2026-10-26T06:00:00Z'
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: '2026-10-26T07:00:00Z')
    runtime._publish_upload_block_status({
        'scan_terminal_blocked_count': 2, 'scan_terminal_blocked_record_count': None,
        'scan_terminal_blocked_since_utc': first}, force=True)
    record = json.loads(target.read_bytes())
    assert record['blocked_records'] is None and record['since'] == first
    assert record['since'].endswith('Z') and record['updated'].endswith('Z')
    runtime._publish_upload_block_status({'status': 'idle'}, force=True)
    assert json.loads(target.read_bytes())['blocked_records'] is None


def test_install_review_requires_authority_and_preserves_one_continuous_episode(target, monkeypatch):
    first, later = '2026-10-26T06:00:00Z', '2026-10-26T07:00:00Z'
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: first)
    runtime._publish_upload_block_status({'runtime_lease': {'status': 'operator_review'}}, force=True)
    assert json.loads(target.read_bytes())['install_review'] is True
    monkeypatch.setattr(runtime, 'utc_now_text', lambda: later)
    for status in ({'status': 'idle'}, {'status': 'runtime_error'},
                   {'runtime_lease': {'status': 'ACTIVE', 'server_grant_accepted': False}},
                   {'scan_terminal_blocked_count': 1, 'scan_terminal_blocked_record_count': 3}):
        runtime._publish_upload_block_status(status, force=True)
        record = json.loads(target.read_bytes())
        assert record['install_review'] is True and record['since'] == first
    runtime._publish_upload_block_status({
        'runtime_lease': {'status': 'ACTIVE', 'server_grant_accepted': True}}, force=True)
    record = json.loads(target.read_bytes())
    assert record['install_review'] is False and record['since'] == first
    runtime._publish_upload_block_status({'scan_terminal_blocked_count': 0}, force=True)
    record = json.loads(target.read_bytes())
    assert record['install_review'] is False and record['since'] is None
    runtime._publish_upload_block_status({'last_result': {'status': 'operator_review'}}, force=True)
    assert json.loads(target.read_bytes())['install_review'] is False
    runtime._publish_upload_block_status({'runtime_lease': {'status': 'operator_review'}}, force=True)
    assert json.loads(target.read_bytes())['since'] == later
