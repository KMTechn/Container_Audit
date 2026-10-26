"""A terminal spool loss must not strand the authority behind a missing ACK."""
import csv
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest
import direct_sync_push as push
import direct_sync_runtime as runtime
from tools import direct_sync_relay_runner as runner
from tests.test_producer_runtime_client import (
    _DataPathServer, _authority_row, _credentials, _data_path_cycle, _make_pending_relay,
)
from tests.test_direct_sync_runtime import _isolate_legacy_runtime_tests_from_runtime_lease

_REAL_PREPARE = push.prepare_runtime_metadata
_REAL_MODE = push.client_runtime_lease_mode
_REAL_ENSURE = runtime.ensure_runtime_authority


@pytest.fixture(autouse=True)
def isolated_release_identity(monkeypatch):
    # Match the focused LM CLI fixture: retain the real generation/owner guard,
    # while giving synthetic owner roots a stable test release identity.
    import data_generation_guard as generation
    from tools.check_release_version import read_current_version
    version = read_current_version(Path(__file__).resolve().parents[1] / 'Container_Audit.py')
    monkeypatch.setattr(generation, '_portable_runtime_release', lambda **kw: {
        'version': version, 'build_id': 'a' * 40,
        'data_compatible_min_version': version, 'compatibility_verified': False,
    })


def _row(database, relay_id='original'):
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        return dict(conn.execute('SELECT * FROM direct_sync_relay_batches WHERE relay_id=?', (relay_id,)).fetchone())


def _seed(tmp_path, monkeypatch, *, direct=False):
    monkeypatch.setattr(push, 'prepare_runtime_metadata', _REAL_PREPARE)
    monkeypatch.setattr(push, 'client_runtime_lease_mode', _REAL_MODE)
    database = tmp_path / 'relay.sqlite3'
    config = SimpleNamespace(db_path=database, spool_dir=tmp_path / 'spool')
    source = tmp_path / '이적작업이벤트로그_held.csv'
    with source.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['timestamp', 'worker_name', 'event', 'details'])
        writer.writerow(['2026-10-26T00:00:00Z', 'test', 'APP_START', '{}'])
    push.init_relay_queue_schema(database)
    delta, relative, _, _ = runner._build_delta_source_file(config, source)
    if direct:
        relative = source.name
    body = delta.read_bytes()
    server = _DataPathServer()
    _data_path_cycle(database, server, 0, tmp_path)
    _make_pending_relay(database, tmp_path, 'original', payload=body)
    row = _row(database)
    metadata = json.loads(row['metadata_json'])
    digest = hashlib.sha256(body).hexdigest()
    metadata.update(relative_path=relative, content_sha256=digest, byte_length=len(body))
    config.spool_dir.mkdir(exist_ok=True)
    canonical_spool = config.spool_dir / 'original.csv'
    canonical_spool.write_bytes(body)
    with sqlite3.connect(database) as conn:
        conn.execute('UPDATE direct_sync_relay_batches SET spooled_file_path=?,source_file_path=?,relative_path=?,content_sha256=?,byte_length=?,metadata_json=? WHERE relay_id=?',
                     (str(canonical_spool), str(source if direct else delta), relative, digest, len(body), push.canonical_json(metadata), 'original'))
    server.lose_source_ack = True
    _, first = _data_path_cycle(database, server, 1, tmp_path)
    assert first.retryable is True
    server.lose_source_ack = False
    held = dict(_authority_row(database))
    wire = json.loads(_row(database)['metadata_json'])
    Path(_row(database)['spooled_file_path']).unlink()
    delta.unlink()
    _, missing = _data_path_cycle(database, server, 2, tmp_path)
    assert missing.success is False
    assert _row(database)['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert dict(_authority_row(database)) == held
    return database, config, source, server, held, wire, body


def _scan(config, source):
    try:
        return runner._build_delta_source_file(config, source)
    except runner.ExistingTerminalDeltaBlocked:
        return None


def _run_cli(tmp_path, monkeypatch, source, server, wire, *, single=False, source_glob=None, drain=False):
    from tests.test_direct_sync_relay_runner import runner_args
    credentials = _credentials()
    args = runner_args(tmp_path, scan_dir=source.parent)
    manifest_path = Path(args[args.index('--producer-manifest-path') + 1])
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest['pc_identity']['producer_install_id'] = wire['producer_install_id']
    manifest['pc_identity']['source_host_id'] = wire['source_host_id']
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    monkeypatch.setattr(runtime, 'load_credentials_from_json', lambda *a, **kw: credentials)
    if single:
        position = args.index('--scan-source-dir')
        del args[position:position + 2]
        args += ['--enqueue-source-file', str(source)]
    if source_glob is not None:
        args[args.index('--source-glob') + 1] = source_glob
    if drain:
        args += ['--drain-after-scan']
    monkeypatch.setattr(runtime, 'ensure_runtime_authority', _REAL_ENSURE)
    monkeypatch.setattr(runner, 'run_relay_once', lambda current, **kw: runtime.run_relay_once(
        current, credentials=credentials, session=server, **kw))
    outcome = runner.main(args)
    return outcome


@pytest.mark.parametrize('direct', [False, True])
@pytest.mark.parametrize('spool_error', ['spooled_file_missing', 'spooled_file_unreadable', 'source_file_unreadable'])
def test_same_range_replay_recovers_lost_ack_and_unblocks_following(tmp_path, monkeypatch, direct, spool_error):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET last_error_code=? WHERE relay_id='original'", (spool_error,))
    with source.open('a', encoding='utf-8', newline='') as stream:
        csv.writer(stream).writerow(['2026-10-26T00:01:00Z', 'test', 'APP_START', '{}'])
    _scan(config, source)
    _make_pending_relay(database, tmp_path, 'following')
    server.at(3)
    result = push.drain_one_relay_batch(db_path=database, credentials=_credentials(), session=server,
                                      target_relay_id='following')
    assert result is not None and result.success is True
    assert _row(database, 'following')['status'] == push.RELAY_STATUS_PENDING
    assert _row(database)['status'] == push.RELAY_STATUS_ACKED
    assert Path(_row(database)['spooled_file_path']).read_bytes() == body
    assert server.source_calls[-1]['idempotency_key'] == wire['idempotency_key']
    assert _authority_row(database)['assigned_relay_id'] is None
    _, following = _data_path_cycle(database, server, 4, tmp_path)
    assert following.success is True
    assert _row(database, 'following')['status'] == push.RELAY_STATUS_ACKED
    assert server.audit == []


@pytest.mark.parametrize('failure', ['changed', 'missing'])
@pytest.mark.parametrize('direct', [False, True])
def test_unrecoverable_original_retains_binding_and_shows_all_waiting_records(tmp_path, monkeypatch, failure, direct):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    if failure == 'changed':
        source.write_bytes(body.replace(b'APP_START', b'APP_OTHER'))
    else:
        source.unlink()
    _run_cli(tmp_path, monkeypatch, source, server, wire)
    _make_pending_relay(database, tmp_path, 'following')
    _, result = _data_path_cycle(database, server, 3, tmp_path)
    assert result is None
    reviewed = _authority_row(database)
    assert reviewed['status'] == 'OPERATOR_REVIEW'
    for field in ('assigned_relay_id', 'next_request_token', 'next_request_sequence'):
        assert reviewed[field] == held[field]
    assert json.loads(_row(database)['metadata_json']) == wire
    assert len(server.source_calls) == 1
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['install_review'] is True
    assert public['blocked_files'] == 1 and public['blocked_records'] is None
    files, records, _ = runner._held_runtime_backlog(config, [source] if source.exists() else [])
    assert files == 2 and records is None


def test_recovery_transient_response_keeps_binding_and_retries_after_backoff(tmp_path, monkeypatch):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    _scan(config, source)
    server.lose_source_ack = True
    _, first = _data_path_cycle(database, server, 3, tmp_path)
    assert first is not None and first.retryable is True
    assert len(server.source_calls) == 2
    assert dict(_authority_row(database)) == held
    assert json.loads(_row(database)['metadata_json']) == wire
    assert _row(database)['next_attempt_at']
    assert push.drain_one_relay_batch(db_path=database, credentials=_credentials(), session=server,
                                     target_relay_id='original') is None
    server.lose_source_ack = False
    due = _row(database)['next_attempt_at']
    _scan(config, source)  # A restarted scan must retain the persisted backoff.
    assert _row(database)['next_attempt_at'] == due
    _make_pending_relay(database, tmp_path, 'following')
    monkeypatch.setattr(push, 'utc_now_text', lambda: due)
    recovered = push.drain_one_relay_batch(db_path=database, credentials=_credentials(), session=server,
                                         target_relay_id='following')
    assert recovered.success is True
    assert _row(database)['status'] == push.RELAY_STATUS_ACKED
    assert server.audit == []


@pytest.mark.parametrize('status,valid_json,committed', [
    (408, True, False), (408, True, True), (429, True, False), (429, True, True),
    (500, True, False), (500, True, True), (599, True, False), (599, True, True),
    (409, True, False), (409, True, True), (400, False, False), (200, False, False),
])
def test_recovery_server_refusal_does_not_release_the_prior_assignment(tmp_path, monkeypatch, status, valid_json, committed):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    _scan(config, source)
    post = server.post
    attempts = []
    def rejected(url, **kwargs):
        if '/source-file' not in url:
            return post(url, **kwargs)
        attempts.append(json.loads(kwargs['data']['metadata']))
        def payload():
            if not valid_json:
                raise ValueError('synthetic invalid response')
            return {'committed': committed, 'retryable': False, 'error': {'code': 'CONTENT_CONFLICT'}}
        return SimpleNamespace(status_code=status, headers={}, json=payload, text='')
    monkeypatch.setattr(server, 'post', rejected)
    _, refused = _data_path_cycle(database, server, 3, tmp_path)
    assert refused.retryable is True
    assert len(attempts) == 1
    assert attempts[0] == wire
    assert dict(_authority_row(database)) == held
    assert json.loads(_row(database)['metadata_json']) == wire
    due = _row(database)['next_attempt_at']
    assert due
    assert push.drain_one_relay_batch(db_path=database, credentials=_credentials(), session=server,
                                     target_relay_id='original') is None
    monkeypatch.setattr(server, 'post', post)
    monkeypatch.setattr(push, 'utc_now_text', lambda: due)
    _, recovered = _data_path_cycle(database, server, 4, tmp_path)
    assert recovered.success is True
    assert server.audit == []


def _queue_delta(database, config, source, relay_id):
    delta, relative, _, _ = runner._build_delta_source_file(config, source)
    body = delta.read_bytes()
    _make_pending_relay(database, source.parent, relay_id)
    row = _row(database, relay_id)
    metadata = json.loads(row['metadata_json'])
    digest = hashlib.sha256(body).hexdigest()
    metadata.update(relative_path=relative, content_sha256=digest, byte_length=len(body))
    Path(row['spooled_file_path']).write_bytes(body)
    with sqlite3.connect(database) as conn:
        conn.execute('UPDATE direct_sync_relay_batches SET source_file_path=?,relative_path=?,content_sha256=?,byte_length=?,metadata_json=? WHERE relay_id=?',
                     (str(delta), relative, digest, len(body), push.canonical_json(metadata), relay_id))


def test_backlog_counts_original_records_once_across_queued_ranges(tmp_path, monkeypatch):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    with source.open('a', encoding='utf-8', newline='') as stream:
        csv.writer(stream).writerow(['2026-10-26T00:01:00Z', 'test', 'APP_START', '{}'])
    other = source.with_name('이적작업이벤트로그_other.csv')
    other.write_bytes(source.read_bytes())
    _queue_delta(database, config, other, 'other')
    with sqlite3.connect(database) as conn:
        columns = [item[1] for item in conn.execute('PRAGMA table_info(direct_sync_relay_batches)')]
        values = dict(_row(database))
        values.update(relay_id='overlap', status='pending')
        overlap_metadata = json.loads(values['metadata_json'])
        overlap_metadata['client_batch_id'] = 'overlap'
        for field in push.RUNTIME_METADATA_FIELDS:
            overlap_metadata.pop(field, None)
        values['metadata_json'] = push.canonical_json(overlap_metadata)
        conn.execute('INSERT INTO direct_sync_relay_batches (' + ','.join(columns) + ') VALUES (' + ','.join('?' for _ in columns) + ')',
                     [values[name] for name in columns])
    files, records, originals = runner._held_runtime_backlog(config, [source, other], [source])
    assert files == 2 and records == 4
    assert set(originals) == {str(source), str(other)}
    import os
    import direct_sync_health as health
    payload = {'scan_terminal_blocked_count': files, 'scan_terminal_blocked_record_count': records}
    runtime._publish_upload_block_status(payload, force=True)
    record = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert set(record) == {'schema', 'app', 'blocked_files', 'blocked_records', 'install_review', 'since', 'updated'}
    assert (record['blocked_records'], record['blocked_files']) == (4, 2)
    model = health.RelayHealth('review', 1, 1, 0, '', '', '',
        scan_terminal_blocked_count=files, scan_terminal_blocked_record_count=records)
    band = ' '.join(health.relay_send_warning_model(model).values())
    assert '4건' in band and '파일 2개' in band and '관리자' in band



def test_existing_abandon_command_reports_missing_spool_without_clearing_assignment(tmp_path, monkeypatch):
    from direct_sync_operator import retry_dead_relay_batch
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    source.unlink()
    runner._review_missing_held_originals(config, [])
    outcome = retry_dead_relay_batch(db_path=database, relay_id='original', operator_id='test-admin',
                                    reason='synthetic recovery check', audit_log_path=tmp_path / 'operator.jsonl')
    assert outcome['status'] == 'BLOCKED'
    assert outcome['error_code'] == 'spooled_file_missing'
    assert _authority_row(database)['assigned_relay_id'] == held['assigned_relay_id']


@pytest.mark.parametrize('restore', ['original', 'other', 'changed', 'delta_copy'])
@pytest.mark.parametrize('direct', [False, True])
def test_admin_original_recovery_requires_the_original_bytes_and_does_not_auto_resume(tmp_path, monkeypatch, restore, direct):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    source.unlink()
    runner._review_missing_held_originals(config, [])
    assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
    candidate = source if restore != 'other' else source.with_name('이적작업이벤트로그_different.csv')
    if restore == 'delta_copy':
        digest = hashlib.sha256(body).hexdigest()
        candidate = config.spool_dir / '_scan_delta_inputs' / runner._source_delta_key(source) / f'bytes-0-{len(body)}-sha256-{digest[:16]}.csv'
        candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(body if restore != 'changed' else body.replace(b'APP_START', b'APP_OTHER'))
    _scan(config, candidate)
    assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
    assert len(server.source_calls) == 1
    repaired = runner._repair_held_assignments_before_scan(config, candidate, administrator=True)
    if restore != 'original':
        assert repaired == []
        assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
        assert _authority_row(database)['assigned_relay_id'] == 'original'
    else:
        assert repaired == ['original']
        assert _authority_row(database)['status'] == 'ACTIVE'
        assert json.loads(_row(database)['metadata_json']) == wire
        _, recovered = _data_path_cycle(database, server, 3, tmp_path)
        assert recovered.success is True
        assert _row(database)['status'] == push.RELAY_STATUS_ACKED
        assert _authority_row(database)['assigned_relay_id'] is None


def test_admin_recovery_rejects_a_different_runtime_assignment(tmp_path, monkeypatch):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    source.unlink()
    runner._review_missing_held_originals(config, [])
    source.write_bytes(body)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE direct_sync_runtime_authority SET runtime_instance_id='different-runtime'")
    assert runner._repair_held_assignments_before_scan(config, source, administrator=True) == []
    assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
    assert _authority_row(database)['assigned_relay_id'] == 'original'
    assert len(server.source_calls) == 1


@pytest.mark.parametrize('direct', [False, True])
def test_existing_single_source_cli_replays_and_clears_the_public_review(tmp_path, monkeypatch, capsys, direct):
    import os
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    source.unlink()
    runner._review_missing_held_originals(config, [])
    source.write_bytes(body)
    runtime._publish_upload_block_status({'scan_terminal_blocked_count': 1,
        'scan_terminal_blocked_record_count': None, 'runtime_lease': {'status': 'operator_review'}}, force=True)
    assert _run_cli(tmp_path, monkeypatch, source, server, wire, single=True) == 0
    capsys.readouterr()
    assert _row(database)['status'] == push.RELAY_STATUS_ACKED
    assert _authority_row(database)['assigned_relay_id'] is None
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['blocked_files'] == public['blocked_records'] == 0
    assert public['install_review'] is False
    assert public['since'] is None


def test_narrow_scan_pattern_does_not_treat_an_existing_original_as_missing(tmp_path, monkeypatch, capsys):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    _run_cli(tmp_path, monkeypatch, source, server, wire, source_glob='이적작업이벤트로그_other*.csv')
    capsys.readouterr()
    assert _authority_row(database)['status'] == 'ACTIVE'
    assert _authority_row(database)['assigned_relay_id'] == 'original'
    assert len(server.source_calls) == 1


@pytest.mark.parametrize('direct', [False, True])
def test_automatic_scan_drains_recovered_assignment_without_a_new_enqueue(tmp_path, monkeypatch, capsys, direct):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    assert _run_cli(tmp_path, monkeypatch, source, server, wire, drain=True) == 0
    capsys.readouterr()
    assert _row(database)['status'] == push.RELAY_STATUS_ACKED
    assert _authority_row(database)['assigned_relay_id'] is None
    assert len(server.source_calls) == 2
    assert server.source_calls[-1]['idempotency_key'] == wire['idempotency_key']
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['blocked_files'] == public['blocked_records'] == 0
    assert public['install_review'] is False and public['since'] is None
    assert _scan(config, source) is None
    with sqlite3.connect(database) as conn:
        assert conn.execute('SELECT COUNT(*) FROM direct_sync_relay_batches').fetchone()[0] == 1


def test_recovery_failure_cannot_overwrite_a_later_claim(tmp_path, monkeypatch):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    _scan(config, source)
    server.lose_source_ack = True
    original = push.upload_source_file
    def superseded(*args, **kwargs):
        result = original(*args, **kwargs)
        with sqlite3.connect(database) as conn:
            conn.execute("UPDATE direct_sync_relay_batches SET lease_owner='later-worker',attempt_count=attempt_count+1 WHERE relay_id='original'")
        return result
    monkeypatch.setattr(push, 'upload_source_file', superseded)
    _, result = _data_path_cycle(database, server, 3, tmp_path)
    assert result.error_code == 'relay_status_update_conflict'
    assert _row(database)['lease_owner'] == 'later-worker'
    assert _row(database)['status'] == push.RELAY_STATUS_LEASED
    assert json.loads(_row(database)['metadata_json']) == wire
    assert dict(_authority_row(database)) == held


@pytest.mark.parametrize('direct', [False, True])
def test_append_during_recovery_waits_for_next_scan_without_operator_review(tmp_path, monkeypatch, direct):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    original_stamp = runner._source_scan_signature
    seen = []
    def append_during_validation(path):
        if path == source:
            seen.append(True)
            if len(seen) == 2:
                with source.open('a', encoding='utf-8', newline='') as stream:
                    csv.writer(stream).writerow(['2026-10-26T00:01:00Z', 'test', 'APP_START', '{}'])
        return original_stamp(path)
    monkeypatch.setattr(runner, '_source_scan_signature', append_during_validation)
    runner._repair_held_assignments_before_scan(config, source)
    assert _authority_row(database)['status'] == 'ACTIVE'
    assert _row(database)['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert json.loads(_row(database)['metadata_json']) == wire
    assert len(server.source_calls) == 1
    assert runner._repair_held_assignments_before_scan(config, source) == ['original']
    _, recovered = _data_path_cycle(database, server, 3, tmp_path)
    assert recovered.success is True
    assert Path(_row(database)['spooled_file_path']).read_bytes() == body
    assert server.source_calls[-1]['idempotency_key'] == wire['idempotency_key']


@pytest.mark.parametrize('administrator', [False, True])
@pytest.mark.parametrize('direct', [False, True])
def test_writer_lock_during_recovery_defers_without_review(tmp_path, monkeypatch, administrator, direct):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    lock = runner._source_writer_lock_path(source)
    lock.touch()
    before = dict(_row(database))
    assert runner._repair_held_assignments_before_scan(config, source, administrator=administrator) == []
    assert dict(_authority_row(database)) == held
    assert dict(_row(database)) == before
    assert not Path(before['spooled_file_path']).exists()
    assert len(server.source_calls) == 1
    lock.unlink()
    assert runner._repair_held_assignments_before_scan(config, source) == ['original']
    _, recovered = _data_path_cycle(database, server, 3, tmp_path)
    assert recovered.success is True
    assert Path(_row(database)['spooled_file_path']).read_bytes() == body
    assert server.source_calls[-1]['idempotency_key'] == wire['idempotency_key']
    assert _authority_row(database)['assigned_relay_id'] is None


@pytest.mark.parametrize('single', [False, True])
@pytest.mark.parametrize('direct', [False, True])
def test_cli_writer_lock_just_before_recovery_retries_next_scan(tmp_path, monkeypatch, capsys, single, direct):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    original_read = runner._original_delta_content
    lock = runner._source_writer_lock_path(source)
    def lock_before_validation(*args):
        lock.touch()
        return original_read(*args)
    monkeypatch.setattr(runner, '_original_delta_content', lock_before_validation)
    assert _run_cli(tmp_path, monkeypatch, source, server, wire, single=single, drain=True) == 2
    capsys.readouterr()
    authority = _authority_row(database)
    for field in ('status', 'assigned_relay_id', 'next_request_token', 'next_request_sequence'):
        assert authority[field] == held[field]
    assert _row(database)['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert json.loads(_row(database)['metadata_json']) == wire
    assert len(server.source_calls) == 1
    monkeypatch.setattr(runner, '_original_delta_content', original_read)
    lock.unlink()
    assert _run_cli(tmp_path, monkeypatch, source, server, wire, drain=True) == 0
    capsys.readouterr()
    assert _row(database)['status'] == push.RELAY_STATUS_ACKED
    assert _authority_row(database)['assigned_relay_id'] is None
    assert Path(_row(database)['spooled_file_path']).read_bytes() == body
    assert server.source_calls[-1]['idempotency_key'] == wire['idempotency_key']
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['install_review'] is False
    assert public['blocked_files'] == public['blocked_records'] == 0


def test_single_source_with_unproven_original_keeps_only_the_bound_row(tmp_path, monkeypatch, capsys):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch)
    source.unlink()
    runner._review_missing_held_originals(config, [])
    source.write_bytes(body.replace(b'APP_START', b'APP_OTHER'))
    _run_cli(tmp_path, monkeypatch, source, server, wire, single=True)
    capsys.readouterr()
    assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
    with sqlite3.connect(database) as conn:
        assert conn.execute('SELECT COUNT(*) FROM direct_sync_relay_batches').fetchone()[0] == 1
    assert json.loads(_row(database)['metadata_json']) == wire
    assert len(server.source_calls) == 1
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['install_review'] is True
    assert public['blocked_files'] == 1 and public['blocked_records'] is None


@pytest.mark.parametrize('direct', [False, True])
@pytest.mark.parametrize('field', ['relative_path', 'byte_length', 'content_sha256'])
def test_replay_requires_original_metadata_path_length_and_hash(tmp_path, monkeypatch, direct, field):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=direct)
    altered = dict(wire)
    altered[field] = (wire[field] + 1 if field == 'byte_length' else wire[field] + '-changed')
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET metadata_json=? WHERE relay_id='original'",
                     (push.canonical_json(altered),))
    runner._repair_held_assignments_before_scan(config, source)
    assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
    assert _authority_row(database)['assigned_relay_id'] == held['assigned_relay_id']
    assert _row(database)['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert json.loads(_row(database)['metadata_json']) == altered
    assert len(server.source_calls) == 1


def test_raw_recovery_and_later_tail_do_not_enqueue_the_prefix_again(tmp_path, monkeypatch, capsys):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=True)
    with source.open('a', encoding='utf-8', newline='') as stream:
        csv.writer(stream).writerow(['2026-10-26T00:01:00Z', 'test', 'APP_START', '{}'])
    _run_cli(tmp_path, monkeypatch, source, server, wire, drain=True)
    capsys.readouterr()
    assert _row(database)['status'] == push.RELAY_STATUS_ACKED
    assert Path(_row(database)['spooled_file_path']).read_bytes() == body
    with sqlite3.connect(database) as conn:
        queued = conn.execute("SELECT relay_id,relative_path FROM direct_sync_relay_batches WHERE relay_id!='original'").fetchall()
    assert len(queued) == 1
    assert f'bytes-{len(body)}-' in queued[0][1]
    _run_cli(tmp_path, monkeypatch, source, server, wire, drain=True)
    capsys.readouterr()
    assert _row(database, queued[0][0])['status'] == push.RELAY_STATUS_ACKED
    with sqlite3.connect(database) as conn:
        assert conn.execute('SELECT COUNT(*) FROM direct_sync_relay_batches').fetchone()[0] == 2
    assert len(server.stored) == 2
    assert server.audit == []


def test_raw_overlap_preserves_both_rows_and_blocks_scan_and_administrator_replay(tmp_path, monkeypatch, capsys):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=True)
    digest = hashlib.sha256(body).hexdigest()
    delta = config.spool_dir / '_scan_delta_inputs' / runner._source_delta_key(source) / f'bytes-0-{len(body)}-sha256-{digest[:16]}.csv'
    delta.parent.mkdir(parents=True, exist_ok=True)
    delta.write_bytes(body)
    relative = runner._delta_relative_path(source, 0, len(body), digest)
    _make_pending_relay(database, tmp_path, 'overlap', payload=body)
    other = _row(database, 'overlap')
    metadata = json.loads(other['metadata_json'])
    metadata['relative_path'] = relative
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET source_file_path=?,relative_path=?,metadata_json=? WHERE relay_id='overlap'",
                     (str(delta), relative, push.canonical_json(metadata)))
    other = _row(database, 'overlap')
    for single in (False, True):
        _run_cli(tmp_path, monkeypatch, source, server, wire, single=single, drain=not single)
        capsys.readouterr()
        assert _authority_row(database)['status'] == 'OPERATOR_REVIEW'
        assert _authority_row(database)['assigned_relay_id'] == held['assigned_relay_id']
        assert _row(database)['last_error_code'] == 'spooled_file_missing'
        assert json.loads(_row(database)['metadata_json']) == wire
        assert _row(database, 'overlap') == other
        assert Path(other['spooled_file_path']).read_bytes() == body
        assert source.read_bytes() == delta.read_bytes() == body
        assert len(server.source_calls) == 1
        public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
        assert public['install_review'] is True
        assert (public['blocked_files'], public['blocked_records']) == (1, 1)


def test_raw_ack_and_partial_queued_delta_do_not_create_another_tail(tmp_path, monkeypatch):
    database, config, source, server, held, wire, body = _seed(tmp_path, monkeypatch, direct=True)
    assert runner._repair_held_assignments_before_scan(config, source) == ['original']
    assert _data_path_cycle(database, server, 3, tmp_path)[1].success is True
    with source.open('a', encoding='utf-8', newline='') as stream:
        csv.writer(stream).writerow(['2026-10-26T00:01:00Z', 'test', 'APP_START', '{}'])
    complete = source.read_bytes()
    start, end = complete.index(b'\n') + 1, len(complete)
    digest = hashlib.sha256(complete).hexdigest()
    delta = config.spool_dir / '_scan_delta_inputs' / runner._source_delta_key(source) / f'bytes-{start}-{end}-sha256-{digest[:16]}.csv'
    delta.parent.mkdir(parents=True, exist_ok=True)
    delta.write_bytes(complete)
    relative = runner._delta_relative_path(source, start, end, digest)
    _make_pending_relay(database, tmp_path, 'legacy-overlap', payload=complete)
    row = _row(database, 'legacy-overlap')
    metadata = json.loads(row['metadata_json'])
    metadata['relative_path'] = relative
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET source_file_path=?,relative_path=?,metadata_json=? WHERE relay_id='legacy-overlap'",
                     (str(delta), relative, push.canonical_json(metadata)))
    assert runner._build_delta_source_file(config, source) is None
    assert len(server.source_calls) == 2
