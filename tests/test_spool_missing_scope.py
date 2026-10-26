"""Missing no-runtime bodies close only their row, without reviewing the PC."""
from pathlib import Path
import json
import sqlite3

import pytest

import direct_sync_push as push
from tests.test_spool_loss_classification import _REAL_MODE, _REAL_PREPARE
from tests.test_producer_runtime_client import _credentials, _LegacyReceiptSession, _make_pending_relay


def _row(database, relay_id):
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        return dict(conn.execute('SELECT * FROM direct_sync_relay_batches WHERE relay_id=?', (relay_id,)).fetchone())


def _authority_statuses(database):
    with sqlite3.connect(database) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='direct_sync_runtime_authority'").fetchone():
            return []
        return [row[0] for row in conn.execute('SELECT status FROM direct_sync_runtime_authority')]


@pytest.mark.parametrize('installation', ['legacy_exact_replay', 'observe_legacy_disabled'])
@pytest.mark.parametrize('failure', ['missing', 'io'])
def test_body_loss_without_runtime_fields_does_not_review_the_pc_or_block_the_next_post(
    tmp_path, monkeypatch, installation, failure
):
    monkeypatch.setattr(push, 'prepare_runtime_metadata', _REAL_PREPARE)
    monkeypatch.setattr(push, 'client_runtime_lease_mode', _REAL_MODE)
    database = tmp_path / 'relay.sqlite3'
    session = _LegacyReceiptSession()
    credentials = _credentials(runtime_lease_mode='observe')
    if installation == 'observe_legacy_disabled':
        _make_pending_relay(database, tmp_path, 'warmup')
        warmup = push.drain_one_relay_batch(db_path=database, credentials=credentials, session=session,
                                           target_relay_id='warmup')
        assert warmup is not None and warmup.success
        assert _authority_statuses(database) == ['LEGACY_DISABLED']
    _make_pending_relay(database, tmp_path, 'lost', runtime_fencing_policy=(
        'legacy_exact_replay' if installation == 'legacy_exact_replay' else 'runtime_required'
    ))
    before = _row(database, 'lost')
    spool = Path(before['spooled_file_path'])
    assert spool.resolve().is_relative_to(tmp_path.resolve())
    original_open = Path.open
    reads = 0
    posts_before = len(session.source_calls)
    def reopen(path, mode='r', *args, **kwargs):
        nonlocal reads
        if path == spool and mode == 'rb':
            reads += 1
            if reads == 2:
                if failure == 'missing':
                    spool.unlink()
                    raise FileNotFoundError('test body removed between digest and reopen')
                raise OSError('test body read I/O failure')
        return original_open(path, mode, *args, **kwargs)
    with monkeypatch.context() as blocked:
        blocked.setattr(Path, 'open', reopen)
        result = push.drain_one_relay_batch(db_path=database, credentials=credentials, session=session,
                                           target_relay_id='lost')
    assert reads == 2
    assert result is not None and not result.success and not result.retryable
    after = _row(database, 'lost')
    assert after['status'] == push.RELAY_STATUS_FAILED_PERMANENT
    assert not any(name in json.loads(after['metadata_json']) for name in push.RUNTIME_METADATA_FIELDS)
    assert len(session.source_calls) == posts_before
    assert 'OPERATOR_REVIEW' not in _authority_statuses(database)
    _make_pending_relay(database, tmp_path, 'following')
    following = push.drain_one_relay_batch(db_path=database, credentials=credentials, session=session,
                                          target_relay_id='following')
    assert following is not None and following.success
    assert len(session.source_calls) == posts_before + 1
    assert 'OPERATOR_REVIEW' not in _authority_statuses(database)
