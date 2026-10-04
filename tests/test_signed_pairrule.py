"""Inspection rules adapted to CA's authenticated user/SYSTEM feed boundary."""
import hashlib
import json

import pytest
import auto_update as update
import update_service

OLD, NEW = '1' * 40, '2' * 40


def identities():
    return ({'source_commit': OLD, 'version': 'v2.0.99', 'contract_sha256': 'a' * 64,
             'data_api_contract_sha256': 'c' * 64},
            {'source_commit': NEW, 'version': 'v2.0.100', 'contract_sha256': 'b' * 64,
             'data_api_contract_sha256': 'd' * 64})


def signed(current, candidate):
    forward = dict(from_commit=current['source_commit'], to_commit=candidate['source_commit'],
                   from_contract_sha256=current['contract_sha256'], to_contract_sha256=candidate['contract_sha256'])
    reverse = dict(from_commit=forward['to_commit'], to_commit=forward['from_commit'],
                   from_contract_sha256=forward['to_contract_sha256'], to_contract_sha256=forward['from_contract_sha256'])
    pin = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
    return dict(version=candidate['version'], auto_update=dict(from_commit=OLD, to_commit=NEW,
                forward_contract_sha256=pin(forward), rollback_contract_sha256=pin(reverse)),
                approved_transitions=[forward, reverse])


def test_signed_exact_pair_accepts_hotfix_and_changed_data_api_as_evidence():
    current, candidate = identities()
    result = update.authorize_feed_transition(signed(current, candidate), current=current, candidate=candidate)
    assert result['authority'] == 'SIGNED_EXACT_PAIR'
    assert result['evidence']['consumer_bytes_equal'] is False
    assert result['rollback']['from_commit'] == NEW


@pytest.mark.parametrize('version', ['v2.0.99', 'v2.0.98', 'v2.0.99.0'])
def test_feed_never_authorizes_equal_or_lower_version(version):
    current, candidate = identities(); candidate['version'] = version
    with pytest.raises(ValueError, match='version_must_increase'):
        update.authorize_feed_transition(signed(current, candidate), current=current, candidate=candidate)


@pytest.mark.parametrize('mutation', ['absent', 'one', 'duplicate', 'extra', 'contract', 'pin', 'from', 'signed-version'])
def test_rejects_unsigned_ambiguous_or_mismatched_pairs(mutation):
    current, candidate = identities(); manifest = signed(current, candidate)
    if mutation == 'absent': manifest.pop('auto_update')
    elif mutation == 'one': manifest['approved_transitions'].pop()
    elif mutation == 'duplicate': manifest['approved_transitions'][1] = manifest['approved_transitions'][0]
    elif mutation == 'extra': manifest['approved_transitions'].append(manifest['approved_transitions'][0])
    elif mutation == 'contract': current['contract_sha256'] = 'f' * 64
    elif mutation == 'pin': manifest['auto_update']['forward_contract_sha256'] = 'e' * 64
    elif mutation == 'from': current['source_commit'] = '3' * 40
    else: manifest['version'] = 'v2.0.101'
    with pytest.raises(ValueError): update.authorize_feed_transition(manifest, current=current, candidate=candidate)


@pytest.mark.parametrize('source', [b'CURRENT_VERSION = get_version()', b'CURRENT_VERSION="v2.0.99"\nCURRENT_VERSION="v2.0.100"',
                                   b'CURRENT_VERSION="v2.0.99"\nCURRENT_VERSION: str="v2.0.100"'])
def test_dynamic_and_duplicate_version_source_cannot_define_stock_identity(source):
    with pytest.raises(ValueError): update.source_version_literal(source)


def test_stock_identity_requires_recorded_version_and_rehashes_contract_bytes():
    packet = {'portable-manifest.json': json.dumps(dict(schema='container-audit-portable-tree-v1', source_commit=OLD,
                version='v2.0.99')).encode(), 'app/Container_Audit.py': b'CURRENT_VERSION="v2.0.99"'}
    for name in update.CONTRACT_FILES + tuple('app/' + name for name in update.DATA_API_FILES): packet[name] = b'raw bytes\r\n'
    packet['app/Container_Audit.py'] = b'CURRENT_VERSION="v2.0.99"'
    first = update.version_identity(packet.__getitem__)
    packet[update.CONTRACT_FILES[0]] += b' '
    second = update.version_identity(packet.__getitem__)
    assert first['contract_sha256'] != second['contract_sha256']
    packet['portable-manifest.json'] = json.dumps(dict(schema='container-audit-portable-tree-v1', source_commit=OLD)).encode()
    with pytest.raises(ValueError, match='stock_version_record_missing'): update.version_identity(packet.__getitem__)


@pytest.mark.parametrize('url', ['https://\u4f8b\u3048.test/feed', 'https://example\uff0etest/feed',
                               'https://example.test:/feed', 'https://user@example.test/feed', 'https://example.test/feed#fragment'])
def test_feed_rejects_non_ascii_or_ambiguous_authority(url):
    with pytest.raises(ValueError): update_service.assert_https_update_url(url)


def test_ascii_punycode_and_numeric_version_order():
    assert update_service.assert_https_update_url('https://xn--r8jz45g.test/feed')
    assert update_service.is_newer_version('v2.0.100', 'v2.0.99')
    assert not update_service.is_newer_version('v2.0.99.0', 'v2.0.99')
