"""Pre-request file locks retry; uncertain post-request results stay protected."""
from pathlib import Path
from types import SimpleNamespace

import pytest

import direct_sync_push as push
import producer_runtime_client as lease
from tests.test_direct_sync_clock_stale import enqueue, queue_row
from tests import test_direct_sync_runtime as helpers


@pytest.fixture(autouse=True)
def local_runtime(monkeypatch):
    monkeypatch.setattr(push, 'prepare_runtime_metadata',
                        lambda **kw: lease.RuntimePreparation(metadata=dict(kw['metadata'])))


@pytest.mark.parametrize('error_type,winerror', [(PermissionError, 5), (PermissionError, 32),
                                              (PermissionError, 33), (OSError, None),
                                              (FileNotFoundError, None)])
def test_spool_read_oserror_retries_same_batch_then_recovers(tmp_path, monkeypatch, error_type, winerror):
    _, credentials = enqueue(tmp_path)
    original = queue_row(tmp_path)
    digest = push._read_file_digest
    error = error_type('synthetic local read failure')
    if winerror is not None:
        error.winerror = winerror
    def fail(path):
        raise error
    monkeypatch.setattr(push, '_read_file_digest', fail)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      session=helpers.EchoAcceptedSession(), now='2099-01-01T00:00:00Z')
    current = queue_row(tmp_path)
    assert result.retryable is True and current['status'] == 'retry_wait'
    assert current['next_attempt_at'] and current['attempt_count'] == 1
    assert Path(current['spooled_file_path']).is_file()
    monkeypatch.setattr(push, '_read_file_digest', digest)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      session=helpers.EchoAcceptedSession(), now='2100-01-01T00:00:00Z')
    assert result.success and queue_row(tmp_path)['status'] == 'acked'
    assert queue_row(tmp_path)['relay_id'] == original['relay_id']
    assert queue_row(tmp_path)['content_sha256'] == original['content_sha256']


@pytest.mark.parametrize('site', ['source_read', 'signing'])
def test_local_oserror_before_source_post_retries(tmp_path, monkeypatch, site):
    _, credentials = enqueue(tmp_path)
    calls = []
    session = SimpleNamespace(post=lambda *a, **kw: calls.append(True))
    if site == 'source_read':
        digest = push._read_open_file_digest
        reads = []
        def fail_second(handle):
            reads.append(True)
            if len(reads) == 2:
                raise PermissionError('synthetic local read failure')
            return digest(handle)
        monkeypatch.setattr(push, '_read_open_file_digest', fail_second)
    else:
        def fail(*a, **kw):
            raise PermissionError('synthetic pre-request failure')
        monkeypatch.setattr(push, 'signed_headers', fail)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      session=session, now='2099-01-01T00:00:00Z')
    assert not calls
    assert result.retryable is True
    assert queue_row(tmp_path)['status'] == 'retry_wait' and queue_row(tmp_path)['next_attempt_at']


def test_oserror_after_source_post_stays_operator_review(tmp_path, monkeypatch):
    _, credentials = enqueue(tmp_path)
    calls = []
    def post(*a, **kw):
        calls.append(True)
        return SimpleNamespace(status_code=200)
    def fail(*a, **kw):
        raise PermissionError('synthetic post-request failure')
    monkeypatch.setattr(push, '_upload_response_result', fail)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      session=SimpleNamespace(post=post), now='2099-01-01T00:00:00Z')
    assert calls == [True]
    assert result.retryable is False and queue_row(tmp_path)['status'] == 'operator_review'


def test_spool_content_mismatch_stays_terminal(tmp_path):
    _, credentials = enqueue(tmp_path)
    with Path(queue_row(tmp_path)['spooled_file_path']).open('ab') as handle:
        handle.write(b'\n')
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
                                      session=helpers.EchoAcceptedSession(), now='2099-01-01T00:00:00Z')
    assert result.error_code == 'spooled_file_digest_mismatch'
    assert result.retryable is False and queue_row(tmp_path)['status'] == 'failed_permanent'


@pytest.mark.parametrize('stage', ['upload', 'lease'])
@pytest.mark.parametrize('status', [400, 401, 403, 404, 408, 429, 500, 520, 524, 599])
def test_non_json_http_errors_retry_without_terminal_row(tmp_path, monkeypatch, stage, status):
    _, credentials = enqueue(tmp_path)
    def invalid_json():
        raise ValueError('synthetic HTML response')
    response = SimpleNamespace(status_code=status, headers={}, json=invalid_json)
    if stage == 'lease':
        _, preparation = lease._post_lease_request(request_value={}, credentials=credentials,
            session=SimpleNamespace(post=lambda *a, **kw: response), timeout=5)
        monkeypatch.setattr(push, 'prepare_runtime_metadata', lambda **kw: preparation)
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=SimpleNamespace(post=lambda *a, **kw: response), now='2099-01-01T00:00:00Z')
    assert result.retryable is True and result.committed is False
    assert queue_row(tmp_path)['status'] == 'retry_wait' and queue_row(tmp_path)['next_attempt_at']


def test_json_4xx_without_committed_retries_but_explicit_rejection_stays_terminal(tmp_path, monkeypatch):
    _, credentials = enqueue(tmp_path)
    response = SimpleNamespace(status_code=403, headers={},
        json=lambda: {'error': {'code': 'proxy_rejection'}})
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=SimpleNamespace(post=lambda *a, **kw: response), now='2099-01-01T00:00:00Z')
    assert result.retryable is True and queue_row(tmp_path)['status'] == 'retry_wait'
    response.json = lambda: {'committed': False, 'retryable': False, 'error': {'code': 'bad_request'}}
    result = push.drain_one_relay_batch(db_path=tmp_path / 'relay.sqlite3', credentials=credentials,
        session=SimpleNamespace(post=lambda *a, **kw: response), now='2100-01-01T00:00:00Z')
    assert result.retryable is False
    assert queue_row(tmp_path)['status'] == 'operator_review'
