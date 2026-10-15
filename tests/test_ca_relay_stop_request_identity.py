"""Installer-selected stop identity still uses the real atomic publisher."""
import json
from types import SimpleNamespace

import pytest

import user_relay


@pytest.mark.parametrize('explicit', (False, True))
def test_stop_request_binds_selected_identity_without_changing_default(tmp_path, monkeypatch, explicit):
    import runtime_instance_win32
    monkeypatch.setattr(runtime_instance_win32, 'known_program_data', lambda: tmp_path / 'machine')
    options = {'request_id': '10901090109010901090109010901090'} if explicit else {}
    result = user_relay.request_user_relay_stop(tmp_path / 'state',
        lease_factory=lambda path: SimpleNamespace(release=lambda: None), **options)
    marker = json.loads(user_relay.user_relay_stop_path(tmp_path / 'state').read_bytes())
    assert result['status'] == 'ABSENT'
    assert marker['schema_version'] == 'container-audit-user-relay-stop-v1'
    assert marker['request_id'] == result['request_id']
    assert len(result['request_id']) == 32
    if explicit:
        assert result['request_id'] == options['request_id']


@pytest.mark.parametrize('request_id', ('g' * 32, 'a' * 31, b'a' * 32, 109))
def test_invalid_selected_stop_identity_refuses_before_publication(tmp_path, monkeypatch, request_id):
    def forbidden(*args, **kwargs):
        raise AssertionError('invalid request reached mutation')
    monkeypatch.setattr(user_relay, '_write_json_atomic', forbidden)
    with pytest.raises(ValueError, match='relay stop request identity is invalid'):
        user_relay.request_user_relay_stop(tmp_path / 'state', request_id=request_id, lease_factory=forbidden)
    assert not (tmp_path / 'state').exists()
