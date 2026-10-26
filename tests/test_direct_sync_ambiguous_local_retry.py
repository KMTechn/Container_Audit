"""A prior ambiguous POST keeps its binding through later local failures."""
import json
import sqlite3

import pytest

import direct_sync_push as push
import producer_runtime_client as lease
from tests import test_producer_runtime_client as helpers


def state(db, relay_id='relay-a'):
    with sqlite3.connect(db) as connection:
        row = connection.execute('SELECT status,metadata_json FROM direct_sync_relay_batches WHERE relay_id=?',
                                 (relay_id,)).fetchone()
        authority = connection.execute('SELECT status,assigned_relay_id FROM direct_sync_runtime_authority').fetchone()
    return row[0], json.loads(row[1]), authority


def test_incomplete_review_response_keeps_authority_active_for_next_row(tmp_path):
    class ReviewSession(helpers._RelaySession):
        def post(self, url, **kwargs):
            if not str(url).endswith(lease.ENDPOINT_PATH):
                return helpers._Response(403, {'error': {'code': 'STALE_RUNTIME_FENCE'}}, {})
            return super().post(url, **kwargs)

    db = tmp_path / 'relay.sqlite3'
    helpers._make_pending_relay(db, tmp_path, 'relay-a')
    session = ReviewSession()
    first = push.drain_one_relay_batch(db_path=db, credentials=helpers._credentials(), session=session)
    assert first.retryable is True
    assert state(db)[0] == 'retry_wait'
    assert state(db)[2] == ('ACTIVE', 'relay-a')
    helpers._make_pending_relay(db, tmp_path, 'relay-b')
    following = push.drain_one_relay_batch(db_path=db, credentials=helpers._credentials(), session=session,
                                          target_relay_id='relay-b')
    assert following.retryable is True and following.error_code == 'runtime_request_in_flight'
    assert state(db, 'relay-b')[0] == 'retry_wait'
    assert state(db)[2] == ('ACTIVE', 'relay-a')


def install_local_failure(monkeypatch, stage):
    def fail(*args, **kwargs):
        raise PermissionError('synthetic local failure')
    if stage == 'spool':
        monkeypatch.setattr(push, '_read_file_digest', fail)
    elif stage == 'signing':
        monkeypatch.setattr(push, 'signed_headers', fail)
    else:
        original = push._read_open_file_digest
        reads = []
        def fail_source(handle):
            reads.append(True)
            if len(reads) == 2:
                return fail()
            return original(handle)
        monkeypatch.setattr(push, '_read_open_file_digest', fail_source)


@pytest.mark.parametrize('stage', ['spool', 'source_read', 'signing'])
def test_lost_ack_then_local_failure_keeps_original_binding_until_replayed(tmp_path, monkeypatch, stage):
    db = tmp_path / 'relay.sqlite3'
    server = helpers._DataPathServer()
    helpers._make_pending_relay(db, tmp_path, 'relay-a')
    server.lose_source_ack = True
    _, lost = helpers._data_path_cycle(db, server, 0, tmp_path)
    assert lost.retryable is True and 'relay-a' in server.stored
    before = state(db)[1]
    assert state(db)[2] == ('ACTIVE', 'relay-a')
    server.lose_source_ack = False
    with monkeypatch.context() as local:
        install_local_failure(local, stage)
        _, failed = helpers._data_path_cycle(db, server, 1, tmp_path)
    assert failed.retryable is True
    status, after, authority = state(db)
    assert status == 'retry_wait' and authority == ('ACTIVE', 'relay-a')
    assert all(after.get(name) == before[name] for name in lease.METADATA_FIELDS)
    assert len(server.source_calls) == 1

    helpers._make_pending_relay(db, tmp_path, 'relay-b')
    following = push.drain_one_relay_batch(db_path=db, credentials=helpers._credentials(runtime_lease_mode='observe'),
        session=server, target_relay_id='relay-b', now=server.at(2))
    assert following.retryable is True and following.error_code == 'runtime_request_in_flight'
    assert state(db)[2] == ('ACTIVE', 'relay-a')
    _, replayed = helpers._data_path_cycle(db, server, 3, tmp_path)
    _, next_row = helpers._data_path_cycle(db, server, 4, tmp_path)
    assert replayed.success is True and next_row.success is True
    assert state(db)[0] == state(db, 'relay-b')[0] == 'acked'
    assert server.audit == [] and set(server.stored) == {'relay-a', 'relay-b'}


@pytest.mark.parametrize('stage', ['source_read', 'signing'])
def test_fresh_binding_releases_on_local_failure_before_first_post(tmp_path, monkeypatch, stage):
    db = tmp_path / 'relay.sqlite3'
    server = helpers._DataPathServer()
    helpers._make_pending_relay(db, tmp_path, 'relay-a')
    with monkeypatch.context() as local:
        install_local_failure(local, stage)
        _, failed = helpers._data_path_cycle(db, server, 0, tmp_path)
    assert failed.retryable is True and server.source_calls == []
    status, metadata, authority = state(db)
    assert status == 'retry_wait' and authority == ('ACTIVE', None)
    assert not any(name in metadata for name in lease.METADATA_FIELDS)
    _, recovered = helpers._data_path_cycle(db, server, 1, tmp_path)
    assert recovered.success is True and server.audit == []
