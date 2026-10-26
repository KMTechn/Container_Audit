"""Retry keeps source identity while returning per-row runtime allocation."""
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

import direct_sync_push as push
import producer_runtime_client as lease
from tests import test_producer_runtime_client as helpers
from tests.test_direct_sync_clock_stale import enqueue, queue_row


@pytest.mark.parametrize('failure', ['timeout', '503', 'stale_timestamp'])
def test_retry_releases_allocation_and_reissues_after_ttl(tmp_path, monkeypatch, failure):
    clock = [datetime(2026, 10, 26, tzinfo=timezone.utc)]
    def now():
        return clock[0].isoformat().replace('+00:00', 'Z')
    monkeypatch.setattr(push, 'utc_now_text', now)
    monkeypatch.setattr(lease, '_utc_now_text', now)
    class ExpiringSession(helpers._RelaySession):
        def post(self, url, **kwargs):
            response = super().post(url, **kwargs)
            if str(url).endswith(lease.ENDPOINT_PATH):
                response.payload.update(issued_at=now(), expires_at=(clock[0] + timedelta(minutes=15)).isoformat().replace('+00:00', 'Z'))
            elif len(self.source_calls) == 1:
                response = helpers._Response(401 if failure == 'stale_timestamp' else 503,
                    {'committed': False, 'retryable': False,
                     'error': {'code': failure}}, {})
            return response
    session = ExpiringSession(source_failures=1 if failure == 'timeout' else 0)
    db = tmp_path / 'relay.sqlite3'
    helpers._make_pending_relay(db, tmp_path, 'relay-a')
    credentials = helpers._credentials()
    result = push.drain_one_relay_batch(db_path=db, credentials=credentials, session=session, now=now())
    assert result.retryable is True
    with sqlite3.connect(db) as connection:
        status, metadata = connection.execute('SELECT status,metadata_json FROM direct_sync_relay_batches').fetchone()
        assigned = connection.execute('SELECT assigned_relay_id FROM direct_sync_runtime_authority').fetchone()[0]
    assert status == 'retry_wait'
    if failure == 'timeout':
        assert assigned == 'relay-a'
        assert all(field in json.loads(metadata) for field in lease.METADATA_FIELDS)
    else:
        assert assigned is None
        assert not any(field in json.loads(metadata) for field in lease.METADATA_FIELDS)
    first_runtime = session.source_calls[0][0]['runtime_instance_id']
    clock[0] += timedelta(days=2)
    result = push.drain_one_relay_batch(db_path=db, credentials=credentials, session=session, now=now())
    assert result.success and len(session.calls) == (1 if failure == 'timeout' else 2)
    assert (session.source_calls[1][0]['runtime_instance_id'] == first_runtime) is (failure == 'timeout')
    assert session.source_calls[1][0]['client_batch_id'] == session.source_calls[0][0]['client_batch_id']


@pytest.mark.parametrize('claim', ['next', 'by_id'])
@pytest.mark.parametrize('kind', ['stale_backward', 'stale_forward', 'other_backward'])
def test_only_stale_clock_backward_bypasses_retry_date(tmp_path, monkeypatch, claim, kind):
    row, _ = enqueue(tmp_path)
    error = 'stale_timestamp' if kind.startswith('stale_') else 'other_error'
    with sqlite3.connect(tmp_path / 'relay.sqlite3') as connection:
        connection.execute('UPDATE direct_sync_relay_batches SET status=?, last_error_code=?, updated_at=?, next_attempt_at=?',
            ('retry_wait', error, '2099-01-01T12:00:00Z', '2099-01-01T12:10:00Z'))
    when = '2099-01-01T12:00:01Z' if kind == 'stale_forward' else '2099-01-01T11:00:00Z'
    args = dict(db_path=tmp_path / 'relay.sqlite3', worker_id='retry-test', now=when)
    result = (push.claim_next_relay_batch(**args) if claim == 'next' else
              push.claim_relay_batch_by_id(relay_id=queue_row(tmp_path)['relay_id'], **args))
    assert (result is not None) is (kind == 'stale_backward')
