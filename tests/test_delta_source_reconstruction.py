"""Recover the original relay identity from an unchanged CSV byte range."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

import direct_sync_health as health
import direct_sync_push as push
import direct_sync_runtime as runtime
import test_direct_sync_relay_runner as helpers
from tools import direct_sync_relay_runner as runner
from tests.test_spool_loss_classification import _REAL_MODE, _REAL_PREPARE
from tests.test_producer_runtime_client import (
    _DataPathServer, _authority_row, _credentials, _data_path_cycle, _make_pending_relay,
)


def _queued_source(tmp_path, capsys, *, producer_install_id=None):
    source = helpers.write_container_csv(tmp_path / 'sources')
    args = helpers.runner_args(tmp_path, scan_dir=source.parent)
    if producer_install_id is not None:
        manifest_path = Path(args[args.index('--producer-manifest-path') + 1])
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        manifest['pc_identity']['producer_install_id'] = producer_install_id
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    runner.main(args)
    assert 'direct_sync_relay_status=enqueued' in capsys.readouterr().out
    row = dict(helpers.relay_rows(tmp_path / 'relay.sqlite3')[0])
    return source, args, row


def _append_record(source):
    with source.open('ab') as stream:
        stream.write(b'2026-06-22T00:01:00,worker,SCAN_OK,detail\n')


def _drain(tmp_path, relay_id, monkeypatch):
    session = helpers.AcceptedReceiptSession()
    helpers.install_receipt_test_runtime(monkeypatch, session)
    result = push.drain_one_relay_batch(
        db_path=tmp_path / 'relay.sqlite3',
        credentials=runtime.load_credentials_from_json(tmp_path / 'credential.json'),
        session=session,
        status_dir=tmp_path / 'status',
        target_relay_id=relay_id,
    )
    return result, session


@pytest.mark.parametrize('missing', ['neither', 'spool', 'input', 'both'])
def test_scan_preserves_the_same_row_and_bytes_for_all_copy_loss_scenes(
    tmp_path, capsys, monkeypatch, missing
):
    source, args, before = _queued_source(tmp_path, capsys)
    spool = Path(before['spooled_file_path'])
    delta = Path(before['source_file_path'])
    payload = spool.read_bytes()
    original_input = delta.stat().st_mtime_ns
    original_spool = spool.stat().st_mtime_ns
    if missing in {'spool', 'both'}:
        spool.unlink()
    if missing in {'input', 'both'}:
        delta.unlink()

    runner.main(args)
    capsys.readouterr()
    rows = helpers.relay_rows(tmp_path / 'relay.sqlite3')
    assert len(rows) == 1
    after = dict(rows[0])
    assert after['relay_id'] == before['relay_id']
    assert after['status'] == push.RELAY_STATUS_PENDING
    assert after['relative_path'] == before['relative_path']
    assert after['content_sha256'] == hashlib.sha256(payload).hexdigest()
    assert after['byte_length'] == len(payload)
    assert after['metadata_json'] == before['metadata_json']
    assert spool.read_bytes() == payload
    if missing in {'neither', 'spool'}:
        assert delta.stat().st_mtime_ns == original_input
    if missing in {'neither', 'input'}:
        assert spool.stat().st_mtime_ns == original_spool
    if missing == 'both':
        assert delta.read_bytes() == payload

    result, session = _drain(tmp_path, before['relay_id'], monkeypatch)
    assert result is not None and result.success is True
    assert len(session.calls) == 1
    assert session.calls[0]['file_bytes'] == payload
    assert session.calls[0]['metadata']['client_batch_id'] == before['relay_id']
    assert helpers.relay_rows(tmp_path / 'relay.sqlite3')[0]['status'] == push.RELAY_STATUS_ACKED


def test_missing_both_copies_recovers_a_nonzero_range_with_the_original_header(
    tmp_path, capsys, monkeypatch
):
    source, args, first = _queued_source(tmp_path, capsys)
    result, _session = _drain(tmp_path, first['relay_id'], monkeypatch)
    assert result is not None and result.success
    start = source.stat().st_size
    _append_record(source)
    runner.main(args)
    capsys.readouterr()
    before = next(dict(row) for row in helpers.relay_rows(tmp_path / 'relay.sqlite3')
                  if row['relay_id'] != first['relay_id'])
    assert f'/bytes-{start}-' in before['relative_path']
    spool, delta = Path(before['spooled_file_path']), Path(before['source_file_path'])
    payload = spool.read_bytes()
    spool.unlink()
    delta.unlink()
    runner.main(args)
    capsys.readouterr()
    assert spool.read_bytes() == payload
    assert delta.read_bytes() == payload
    result, session = _drain(tmp_path, before['relay_id'], monkeypatch)
    assert result is not None and result.success
    assert session.calls[0]['file_bytes'] == payload
    assert len(helpers.relay_rows(tmp_path / 'relay.sqlite3')) == 2


@pytest.mark.parametrize('change', ['changed', 'truncated'])
def test_missing_both_copies_with_mismatched_original_stays_terminal(
    tmp_path, capsys, monkeypatch, change
):
    source, args, before = _queued_source(tmp_path, capsys)
    spool, delta = Path(before['spooled_file_path']), Path(before['source_file_path'])
    spool.unlink()
    delta.unlink()
    result, session = _drain(tmp_path, before['relay_id'], monkeypatch)
    assert result is not None and result.success is False and result.retryable is False
    assert not session.calls
    if change == 'changed':
        source.write_bytes(source.read_bytes().replace(b'BC-1', b'BC-9'))
    else:
        source.write_bytes(source.read_bytes()[:10])
    runner.main(args)
    capsys.readouterr()
    after = next(row for row in helpers.relay_rows(tmp_path / 'relay.sqlite3')
                 if row['relay_id'] == before['relay_id'])
    assert after['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert after['content_sha256'] == before['content_sha256']
    assert not spool.exists() and not delta.exists()
    assert len(helpers.relay_rows(tmp_path / 'relay.sqlite3')) == 1


@pytest.mark.parametrize('change', ['changed', 'truncated', 'missing'])
def test_unrecoverable_loss_remains_visible_and_only_blocks_its_original(
    tmp_path, capsys, monkeypatch, change
):
    source, args, before = _queued_source(tmp_path, capsys)
    Path(before['spooled_file_path']).unlink()
    Path(before['source_file_path']).unlink()
    result, _session = _drain(tmp_path, before['relay_id'], monkeypatch)
    assert result is not None and result.retryable is False
    if change == 'changed':
        source.write_bytes(source.read_bytes().replace(b'BC-1', b'BC-9'))
        _append_record(source)
    elif change == 'truncated':
        source.write_bytes(source.read_bytes()[:10])
    else:
        source.unlink()
    helpers.write_container_csv(source.parent, name='이적작업이벤트로그_other_20260622.csv')

    runner.main(args)
    capsys.readouterr()
    status_path = tmp_path / 'runtime' / 'status.json'
    status = json.loads(status_path.read_text(encoding='utf-8'))
    assert status['scan_terminal_blocked_count'] == 1
    assert status['scan_terminal_blocked_record_count'] is None
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['blocked_files'] == 1
    assert public['blocked_records'] is None
    warning = health.relay_send_warning_model(health.read_relay_health(
        db_path=tmp_path / 'relay.sqlite3', runtime_status_path=status_path,
    ))
    assert '회사 서버가 받지 않은 기록' in warning['text']
    assert '막힌 기록 파일 1개' in warning['tail']
    rows = helpers.relay_rows(tmp_path / 'relay.sqlite3')
    assert len(rows) == 2
    assert next(row for row in rows if row['relay_id'] == before['relay_id'])['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert next(row for row in rows if row['relay_id'] != before['relay_id'])['status'] == push.RELAY_STATUS_PENDING
    if change == 'missing':
        assert status['scan_terminal_blocked_source_files'] == [before['source_file_path']]


def _missing_terminal(tmp_path, capsys, monkeypatch):
    source, args, before = _queued_source(tmp_path, capsys)
    payload = Path(before['spooled_file_path']).read_bytes()
    Path(before['spooled_file_path']).unlink()
    Path(before['source_file_path']).unlink()
    result, _session = _drain(tmp_path, before['relay_id'], monkeypatch)
    assert result is not None and not result.retryable
    terminal = dict(helpers.relay_rows(tmp_path / 'relay.sqlite3')[0])
    return source, args, terminal, payload


@pytest.mark.parametrize('copies', ['missing', 'delta', 'spool', 'both'])
def test_exact_missing_terminal_reenters_the_same_row_without_reallocating(
    tmp_path, capsys, monkeypatch, copies
):
    source, args, before, payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    for name, column in [('delta', 'source_file_path'), ('spool', 'spooled_file_path')]:
        if copies in {name, 'both'}:
            Path(before[column]).write_bytes(payload)
    runner.main(args)
    capsys.readouterr()
    rows = helpers.relay_rows(tmp_path / 'relay.sqlite3')
    assert len(rows) == 1
    after = dict(rows[0])
    assert after['status'] == push.RELAY_STATUS_RETRY_WAIT
    for field in ('relay_id', 'metadata_json', 'attempt_count', 'relative_path', 'content_sha256',
                  'byte_length', 'receipt_json', 'source_file_path', 'spooled_file_path'):
        assert after[field] == before[field]
    assert Path(after['source_file_path']).read_bytes() == payload
    assert Path(after['spooled_file_path']).read_bytes() == payload
    result, session = _drain(tmp_path, before['relay_id'], monkeypatch)
    assert result is not None and result.success
    assert len(session.calls) == 1
    assert session.calls[0]['metadata']['client_batch_id'] == before['relay_id']
    assert session.calls[0]['file_bytes'] == payload


@pytest.mark.parametrize('column', ['source_file_path', 'spooled_file_path'])
def test_conflicting_existing_copy_prevents_terminal_reentry_without_overwriting(
    tmp_path, capsys, monkeypatch, column
):
    _source, args, before, payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    conflict = Path(before[column])
    conflict.write_bytes(b'X' * len(payload))
    runner.main(args)
    capsys.readouterr()
    after = dict(helpers.relay_rows(tmp_path / 'relay.sqlite3')[0])
    assert after == before
    assert conflict.read_bytes() == b'X' * len(payload)
    assert not Path(before['spooled_file_path' if column == 'source_file_path' else 'source_file_path']).exists()
    status = json.loads((tmp_path / 'runtime' / 'status.json').read_text(encoding='utf-8'))
    assert status['scan_terminal_blocked_count'] == 1


@pytest.mark.parametrize('receipt', [
    {'committed': True}, {'_local_upload_result_committed': True},
    {'committed': 'true'}, {'committed': None}, [], 'invalid-json',
])
def test_received_or_invalid_receipt_never_reenters_automatically(
    tmp_path, capsys, monkeypatch, receipt
):
    _source, args, before, _payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    with sqlite3.connect(tmp_path / 'relay.sqlite3') as conn:
        conn.execute('UPDATE direct_sync_relay_batches SET receipt_json=? WHERE relay_id=?',
                     (receipt if isinstance(receipt, str) else json.dumps(receipt), before['relay_id']))
    runner.main(args)
    capsys.readouterr()
    after = helpers.relay_rows(tmp_path / 'relay.sqlite3')[0]
    assert after['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert not Path(before['spooled_file_path']).exists()
    assert not Path(before['source_file_path']).exists()


@pytest.mark.parametrize('stop_after', ['source_file_path', 'spooled_file_path'])
def test_process_death_after_copy_publication_rolls_back_and_the_next_process_recovers(
    tmp_path, capsys, monkeypatch, stop_after
):
    _source, args, before, payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    child = tmp_path / 'interrupt_repair.py'
    child.write_text(
        'import os, sys\n'
        'from pathlib import Path\n'
        'from tools import direct_sync_relay_runner as runner\n'
        'target = Path(sys.argv[1])\n'
        'link = os.link\n'
        'def interrupted(source, destination, *args, **kwargs):\n'
        '    link(source, destination, *args, **kwargs)\n'
        '    if Path(destination) == target:\n'
        '        os._exit(91)\n'
        'os.link = interrupted\n'
        'sys.exit(runner.main(sys.argv[2:]))\n', encoding='utf-8',
    )
    stopped = subprocess.run([sys.executable, '-B', str(child), before[stop_after], *args],
                             capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert stopped.returncode == 91
    interrupted = dict(helpers.relay_rows(tmp_path / 'relay.sqlite3')[0])
    assert interrupted == before
    assert Path(before[stop_after]).read_bytes() == payload
    resumed = subprocess.run([sys.executable, '-B', str(Path(runner.__file__)), *args],
                             capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert resumed.returncode == 0
    after = helpers.relay_rows(tmp_path / 'relay.sqlite3')[0]
    assert after['status'] == push.RELAY_STATUS_RETRY_WAIT
    assert after['relay_id'] == before['relay_id']
    assert after['metadata_json'] == before['metadata_json']
    assert after['attempt_count'] == before['attempt_count']
    assert Path(after['source_file_path']).read_bytes() == payload
    assert Path(after['spooled_file_path']).read_bytes() == payload


def test_two_processes_repair_one_terminal_identity_once(tmp_path, capsys, monkeypatch):
    _source, args, before, payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    def scan():
        return subprocess.run([sys.executable, '-B', str(Path(runner.__file__)), *args],
                              capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs = list(pool.map(lambda _index: scan(), range(2)))
    assert all(run.returncode == 0 for run in runs)
    rows = helpers.relay_rows(tmp_path / 'relay.sqlite3')
    assert len(rows) == 1
    assert rows[0]['relay_id'] == before['relay_id']
    assert rows[0]['status'] == push.RELAY_STATUS_RETRY_WAIT
    assert rows[0]['metadata_json'] == before['metadata_json']
    assert rows[0]['attempt_count'] == before['attempt_count']
    assert Path(rows[0]['spooled_file_path']).read_bytes() == payload


@pytest.mark.parametrize('mode', ['observe', 'enforce'])
def test_repair_after_lost_ack_preserves_the_binding_until_that_same_row_sends(
    tmp_path, capsys, monkeypatch, mode
):
    server = _DataPathServer()
    monkeypatch.setattr(push, 'utc_now_text', lambda: server.now.isoformat().replace('+00:00', 'Z'))
    monkeypatch.setattr(runtime, 'load_credentials_from_json',
                        lambda _path, **_kwargs: _credentials(runtime_lease_mode=mode))
    _source, args, queued = _queued_source(tmp_path, capsys, producer_install_id='install-test')
    database = tmp_path / 'relay.sqlite3'
    monkeypatch.setattr(push, 'prepare_runtime_metadata', _REAL_PREPARE)
    monkeypatch.setattr(push, 'client_runtime_lease_mode', _REAL_MODE)
    _live, initial = _data_path_cycle(database, server, 0, tmp_path, mode=mode)
    assert initial is not None and initial.success
    # The first queued range is settled; a second range must carry a real binding.
    _append_record(_source)
    runner.main(args)
    capsys.readouterr()
    active = next(dict(row) for row in helpers.relay_rows(database)
                  if row['relay_id'] != queued['relay_id'])
    server.lose_source_ack = True
    _live, lost = _data_path_cycle(database, server, 10, tmp_path, mode=mode)
    server.lose_source_ack = False
    assert lost is not None and lost.retryable
    authority = dict(_authority_row(database))
    bound = next(dict(row) for row in helpers.relay_rows(database)
                 if row['relay_id'] == active['relay_id'])
    payload = Path(bound['spooled_file_path']).read_bytes()
    Path(bound['spooled_file_path']).unlink()
    Path(bound['source_file_path']).unlink()
    _live, closed = _data_path_cycle(database, server, 20, tmp_path, mode=mode)
    assert closed is not None and not closed.retryable
    terminal = next(dict(row) for row in helpers.relay_rows(database) if row['relay_id'] == active['relay_id'])
    assert dict(_authority_row(database)) == authority
    calls_before_repair = len(server.source_calls)

    runner.main(args)
    capsys.readouterr()
    repaired = next(dict(row) for row in helpers.relay_rows(database)
                    if row['relay_id'] == active['relay_id'])
    assert repaired['status'] == push.RELAY_STATUS_RETRY_WAIT
    assert repaired['metadata_json'] == bound['metadata_json']
    assert repaired['attempt_count'] == terminal['attempt_count']
    assert dict(_authority_row(database)) == authority
    _make_pending_relay(database, tmp_path, 'following')
    following = push.drain_one_relay_batch(
        db_path=database, credentials=_credentials(runtime_lease_mode=mode), session=server,
        target_relay_id='following',
    )
    assert following is not None and following.retryable
    assert len(server.source_calls) == calls_before_repair
    assert dict(_authority_row(database)) == authority
    server.at(30)
    sent = push.drain_one_relay_batch(
        db_path=database, credentials=_credentials(runtime_lease_mode=mode), session=server,
        target_relay_id=active['relay_id'], status_dir=tmp_path / 'status',
    )
    assert sent is not None and sent.success
    assert len(server.source_calls) == calls_before_repair + 1
    assert len(server.stored) == 2
    assert server.source_calls[-1] == server.source_calls[calls_before_repair - 1]
    final = next(row for row in helpers.relay_rows(database) if row['relay_id'] == active['relay_id'])
    assert final['status'] == push.RELAY_STATUS_ACKED
    assert Path(final['spooled_file_path']).read_bytes() == payload


def test_recovery_clears_the_existing_public_block_episode(tmp_path, capsys, monkeypatch):
    source, args, _before, _payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    original = source.read_bytes()
    source.write_bytes(original.replace(b'BC-1', b'BC-9'))
    runner.main(args)
    capsys.readouterr()
    assert json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))['blocked_files'] == 1
    source.write_bytes(original)
    runner.main(args)
    capsys.readouterr()
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['blocked_files'] == 0
    assert public['blocked_records'] == 0


def test_spool_write_failure_keeps_terminal_and_the_next_scan_continues_partial_repair(
    tmp_path, capsys, monkeypatch
):
    _source, args, before, payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    def denied(*_args, **_kwargs):
        raise PermissionError('test write denied')
    with monkeypatch.context() as blocked:
        blocked.setattr(runner, '_copy_spool_file_atomic', denied)
        runner.main(args)
    capsys.readouterr()
    after = dict(helpers.relay_rows(tmp_path / 'relay.sqlite3')[0])
    assert after == before
    assert Path(before['source_file_path']).read_bytes() == payload
    assert not Path(before['spooled_file_path']).exists()
    assert json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))['blocked_files'] == 1
    runner.main(args)
    capsys.readouterr()
    assert helpers.relay_rows(tmp_path / 'relay.sqlite3')[0]['status'] == push.RELAY_STATUS_RETRY_WAIT
    assert Path(before['spooled_file_path']).read_bytes() == payload


@pytest.mark.parametrize('status,code', [
    ('failed_permanent', 'spooled_file_unreadable'), ('operator_review', 'spooled_file_missing'),
])
def test_other_terminal_reason_never_enters_this_repair(tmp_path, capsys, monkeypatch, status, code):
    _source, args, before, _payload = _missing_terminal(tmp_path, capsys, monkeypatch)
    with sqlite3.connect(tmp_path / 'relay.sqlite3') as conn:
        conn.execute('UPDATE direct_sync_relay_batches SET status=?,last_error_code=? WHERE relay_id=?',
                     (status, code, before['relay_id']))
    runner.main(args)
    capsys.readouterr()
    after = helpers.relay_rows(tmp_path / 'relay.sqlite3')[0]
    assert after['status'] == status
    assert after['last_error_code'] == code
    assert not Path(before['spooled_file_path']).exists()
    assert not Path(before['source_file_path']).exists()


def test_active_lease_prevents_both_copy_repair_and_tail_enqueue(tmp_path, capsys):
    source, args, before = _queued_source(tmp_path, capsys)
    claimed = push.claim_next_relay_batch(db_path=tmp_path / 'relay.sqlite3', worker_id='active',
                                        lease_seconds=60, now='2099-01-01T00:00:00Z')
    assert claimed is not None
    leased = dict(helpers.relay_rows(tmp_path / 'relay.sqlite3')[0])
    Path(before['spooled_file_path']).unlink()
    Path(before['source_file_path']).unlink()
    _append_record(source)
    runner.main(args)
    capsys.readouterr()
    rows = helpers.relay_rows(tmp_path / 'relay.sqlite3')
    assert len(rows) == 1 and dict(rows[0]) == leased
    assert not Path(before['spooled_file_path']).exists()
    assert not Path(before['source_file_path']).exists()


def test_missing_original_is_counted_once_for_multiple_lost_ranges(tmp_path, capsys, monkeypatch):
    source, args, _first = _queued_source(tmp_path, capsys)
    _append_record(source)
    runner.main(args)
    capsys.readouterr()
    rows = helpers.relay_rows(tmp_path / 'relay.sqlite3')
    assert len(rows) == 2
    for row in rows:
        Path(row['spooled_file_path']).unlink()
        Path(row['source_file_path']).unlink()
        result, _session = _drain(tmp_path, row['relay_id'], monkeypatch)
        assert result is not None and not result.retryable
    source.unlink()
    runner.main(args)
    capsys.readouterr()
    public = json.loads(runtime._upload_block_status_path().read_text(encoding='utf-8'))
    assert public['blocked_files'] == 1
    assert public['blocked_records'] is None
    assert len(helpers.relay_rows(tmp_path / 'relay.sqlite3')) == 2
