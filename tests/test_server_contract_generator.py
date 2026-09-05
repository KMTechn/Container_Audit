"""Maintenance must reject regressions instead of blessing new golden values."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.contracts.generate_server_contracts import reviewed_exchange_expectation


@pytest.fixture(params=['exchange.json', 'exchange-conflict.json'])
def exchange_observation(request):
    path = Path(__file__).parent / 'contracts' / request.param
    vector = json.loads(path.read_text(encoding='utf-8'))
    return SimpleNamespace(**vector['expected']), vector['requests'][-1], 'conflict' in request.param


@pytest.mark.parametrize('field,bad_value', [
    ('status', 'REVIEW_WRONG_STATUS'),
    ('error_code', 'REVIEW_WRONG_ERROR'),
    ('target_label_action', 'REVIEW_WRONG_LABEL_ACTION'),
    ('target_label_identity_remains_valid', None),
    ('target_label_membership_bound', None),
])
def test_regeneration_rejects_each_wrong_desktop_outcome(exchange_observation, field, bad_value):
    result, final_request, conflict = exchange_observation
    assert reviewed_exchange_expectation(result, final_request, conflict=conflict) == vars(result)
    setattr(result, field, bad_value)
    with pytest.raises(AssertionError, match='desktop exchange observation differs'):
        reviewed_exchange_expectation(result, final_request, conflict=conflict)


def test_regeneration_requires_the_pinned_server_contract(exchange_observation):
    result, final_request, conflict = exchange_observation
    changed = deepcopy(final_request)
    if conflict:
        changed['response']['error']['code'] = 'REVIEW_WRONG_SERVER_ERROR'
    else:
        changed['response']['data']['data']['target_label_action'] = 'REPRINT'
    with pytest.raises(AssertionError):
        reviewed_exchange_expectation(result, changed, conflict=conflict)
