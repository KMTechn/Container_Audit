"""Desktop conformance to pinned server responses; server CAS remains server-owned."""
import threading

import pytest

from tests.contracts.http_replay import load_contract, replay_server
from transfer_member_exchange import TransferMemberExchangeCoordinator, TransferMemberExchangeStore
from transfer_seal import LogisticsTransferClient


@pytest.mark.parametrize('contract_name', ['exchange.json', 'exchange-conflict.json'])
def test_container_exchange_obeys_server_wire_and_persists_outcome(tmp_path, contract_name):
    contract = load_contract(contract_name)
    owner = threading.get_ident()
    owner_provider = lambda: owner
    store = TransferMemberExchangeStore(tmp_path / 'desktop' / 'exchange.sqlite3',
                                       owner_thread_id_provider=owner_provider)
    with replay_server(contract['requests']) as (session, observed):
        client = LogisticsTransferClient(
            'https://logistics.test.invalid', 'contract-only', 'container-contract-host',
            device_id='container-contract-device', session=session,
        )
        coordinator = TransferMemberExchangeCoordinator(store, client,
                                                        owner_thread_id_provider=owner_provider)
        prepared = coordinator.prepare(**contract['inputs'])
        result = coordinator.attempt(prepared.intent_id)
        for field, expected in contract['expected'].items():
            assert getattr(result, field) == expected, field
        assert observed == [request['method'] for request in contract['requests']]
    persisted = store.load(prepared.intent_id)
    assert persisted['status'] == contract['expected']['status']
    assert bool(persisted['receipt_json']) == (result.status == 'ACKED')
