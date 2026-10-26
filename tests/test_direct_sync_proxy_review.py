"""Incomplete proxy rejections cannot quarantine runtime authority."""
import json
import sqlite3
from types import SimpleNamespace

import pytest

import direct_sync_push as push
import producer_runtime_client as lease
from tests import test_producer_runtime_client as helpers


@pytest.mark.parametrize('stage', ['upload', 'lease'])
@pytest.mark.parametrize('committed_present', [False, True])
def test_missing_commit_ignores_review_but_explicit_rejection_keeps_review(tmp_path, stage, committed_present):
    class ReviewSession(helpers._RelaySession):
        def post(self, url, **kwargs):
            is_lease = str(url).endswith(lease.ENDPOINT_PATH)
            if is_lease == (stage == 'lease'):
                payload = {'status': 'operator_review', 'operator_review': True,
                           'retryable': False, 'error': {'code': 'STALE_RUNTIME_FENCE'}}
                if committed_present:
                    payload['committed'] = False
                return helpers._Response(403, payload, {})
            return super().post(url, **kwargs)
    db = tmp_path / 'relay.sqlite3'
    helpers._make_pending_relay(db, tmp_path, 'relay-a')
    result = push.drain_one_relay_batch(db_path=db, credentials=helpers._credentials(),
        session=ReviewSession(), now='2026-10-26T00:00:00Z')
    with sqlite3.connect(db) as connection:
        status, metadata = connection.execute('SELECT status,metadata_json FROM direct_sync_relay_batches').fetchone()
        authority = connection.execute('SELECT status,assigned_relay_id FROM direct_sync_runtime_authority').fetchone()
    if committed_present:
        assert status == 'operator_review' and result.retryable is False
        assert authority[0] == 'OPERATOR_REVIEW'
    else:
        assert status == 'retry_wait' and result.retryable is True
        assert authority[0] != 'OPERATOR_REVIEW'
        if stage == 'upload':
            assert authority[1] == 'relay-a'
            assert all(name in json.loads(metadata) for name in lease.METADATA_FIELDS)


def test_incomplete_lease_failure_does_not_publish_install_review(tmp_path):
    response = SimpleNamespace(status_code=403, headers={}, json=lambda: {
        'status': 'operator_review', 'operator_review': True,
        'error': {'code': 'STALE_RUNTIME_FENCE'}})
    _, preparation = lease._post_lease_request(request_value={}, credentials=helpers._credentials(),
        session=SimpleNamespace(post=lambda *a, **kw: response), timeout=5)
    assert preparation.retryable is True and preparation.operator_review is False
    assert preparation.receipt.get('status') != 'operator_review'
