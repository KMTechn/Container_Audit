"""Explicit maintenance command; ordinary pytest never imports the server checkout.

python -B tests/contracts/generate_server_contracts.py --server-root <checkout> \
    --scratch <new-owned-directory> --output <new-output-directory>
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime as RealDatetime, timezone, timedelta
import hashlib
import itertools
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
from urllib.parse import urlsplit
import uuid
import zipfile

SERVER_COMMIT = "c04343ce17516714a0aafffd914a8e72e071a7be"
REPO = Path(__file__).resolve().parents[2]
WHEN = RealDatetime(2026, 9, 6, 0, 0, tzinfo=timezone.utc)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


class FixedDatetime(RealDatetime):
    @classmethod
    def now(cls, tz=None):
        return cls.fromtimestamp(WHEN.timestamp(), tz=tz)

    @classmethod
    def utcnow(cls):
        return cls.fromtimestamp(WHEN.timestamp(), timezone.utc).replace(tzinfo=None)


def deny_network(*args, **kwargs):
    raise AssertionError("contract generation must remain in-process without network")


def reviewed_exchange_expectation(result, final_request, *, conflict):
    """Fail closed against the reviewed wire/label contract, not desktop output."""
    if conflict:
        expected = {
            'status': 'OPERATOR_REVIEW', 'error_code': 'STALE_VERSION',
            'target_label_action': '',
            'target_label_identity_remains_valid': False,
            'target_label_membership_bound': True,
        }
        assert final_request['status_code'] == 409
        assert final_request['response']['error']['code'] == 'STALE_VERSION'
    else:
        expected = {
            'status': 'ACKED', 'error_code': '',
            'target_label_action': 'RETAIN_IDENTITY_LABEL',
            'target_label_identity_remains_valid': True,
            'target_label_membership_bound': False,
        }
        assert final_request['status_code'] == 200
        receipt = final_request['response']['data']
        assert receipt['status'] == 'COMMITTED'
        for field in ('target_label_action', 'target_label_identity_remains_valid',
                      'target_label_membership_bound'):
            assert receipt['data'][field] == expected[field], field
    observed = {field: getattr(result, field) for field in expected}
    assert observed == expected, 'desktop exchange observation differs from reviewed contract'
    return expected


def exchange_contract(scratch, api, package, *, conflict=False):
    from transfer_member_exchange import TransferMemberExchangeCoordinator, TransferMemberExchangeStore
    from transfer_seal import LogisticsTransferClient

    label = 'conflict' if conflict else 'accepted'
    server_root = scratch / ("exchange-server-" + label)
    server_root.mkdir()
    app, _database = api._app(server_root, opening_qty=3)
    web = app.test_client()
    target_id, _, target_members = package._complete_phs(
        web, session_id="CONTRACT-TARGET", count=2, label="CONTRACT-TARGET", start_index=0,
    )
    source_id, _, source_members = package._complete_phs(
        web, session_id="CONTRACT-SOURCE", count=1, label="CONTRACT-SOURCE", start_index=10,
    )
    target = web.get(f"/logistics/api/v1/bundles/{api.SCOPE}/{target_id}", headers=api._headers()).get_json()['data']
    source = web.get(f"/logistics/api/v1/bundles/{api.SCOPE}/{source_id}", headers=api._headers()).get_json()['data']
    old = next(row['normalized_barcode'] for row in target['members'] if row['unit_id']==target_members[0])
    new = next(row['normalized_barcode'] for row in source['members'] if row['unit_id']==source_members[0])
    records = []

    class Response:
        def __init__(self, response):
            self.status_code = response.status_code
            self.payload = response.get_json()
        def json(self):
            return self.payload

    class Session:
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            path = parsed.path + (('?' + parsed.query) if parsed.query else '')
            if conflict and method=='POST':
                competitor=json.loads(json.dumps(kwargs['json']))
                competitor['idempotency_key']='other-worker-'+competitor['idempotency_key']
                competitor_headers=dict(kwargs.get('headers') or {})
                competitor_headers['Idempotency-Key']=competitor['idempotency_key']
                committed=web.open(path,method=method,headers=competitor_headers,json=competitor)
                (scratch/'competing-exchange.json').write_text(canonical({'status':committed.status_code,'response':committed.get_json()}),encoding='utf-8')
                assert committed.status_code==200, 'competing exchange must commit before the stale request'
            response = Response(web.open(path, method=method, headers=kwargs.get('headers'), json=kwargs.get('json')))
            records.append({
                'method': method, 'path': path, 'body': kwargs.get('json'),
                'headers': {key:('contract-only' if key.lower()=='x-logistics-api-token' else value)
                            for key,value in kwargs.get('headers',{}).items()
                            if key.lower()!='authorization'},
                'status_code': response.status_code, 'response': response.payload,
            })
            return response

    inputs = {
        'master_label': f'BND={target_id}',
        'master_label_fields': {'BND':target_id, 'AUTH_SCOPE':api.SCOPE, 'CLC':'ITEM-API'},
        'item_id':'ITEM-API', 'operator':'contract-fixture',
        'old_barcodes':[old], 'new_barcodes':[new],
    }
    owner = threading.get_ident()
    owner_provider = lambda: owner
    client = LogisticsTransferClient('https://logistics.test.invalid',api.TOKEN,'container-contract-host',
        device_id='container-contract-device',session=Session())
    store = TransferMemberExchangeStore(scratch/'desktop'/('exchange-'+label+'.sqlite3'),owner_thread_id_provider=owner_provider)
    coordinator = TransferMemberExchangeCoordinator(store,client,owner_thread_id_provider=owner_provider)
    prepared = coordinator.prepare(**inputs)
    result = coordinator.attempt(prepared.intent_id)
    (scratch/('exchange-diagnostic-'+label+'.json')).write_text(canonical({'status':result.status,'error_code':result.error_code,'requests':records}),encoding='utf-8')
    expected = reviewed_exchange_expectation(result, records[-1], conflict=conflict)
    document = {'schema':'container-exchange-wire-contract-v1','inputs':inputs,'requests':records,
                'expected':expected}
    # SQLite emits this informational timestamp from its own real clock. Preserve
    # raw server evidence in scratch before normalizing only that field for replay.
    (scratch/('raw-exchange-'+label+'.json')).write_text(canonical(document),encoding='utf-8')
    for record in records:
        data=record['response'].get('data',{})
        if isinstance(data,dict) and 'committed_at' in data:
            RealDatetime.fromisoformat(data['committed_at'].replace('Z','+00:00'))
            data['committed_at']=WHEN.isoformat().replace('+00:00','Z')
    return document


def runtime_contract(scratch, server):
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.derive_private_key(7,ec.SECP256R1()).public_key().public_numbers()
    encode = lambda value:base64.urlsafe_b64encode(value.to_bytes(32,'big')).decode('ascii').rstrip('=')
    public_jwk={'kty':'EC','crv':'P-256','x':encode(key.x),'y':encode(key.y)}
    runtime_id='runtime-contract-fixture-01'
    database=scratch/'runtime-server.sqlite3'
    server.initialize_schema(database,now=WHEN)
    service=server.ProducerRuntimeLeaseService(database)
    grant=service.acquire(producer_install_id='install-test',runtime_instance_id=runtime_id,
        public_jwk=public_jwk,issue_idempotency_key='clone-seed',ttl_seconds=600,now=WHEN)
    outcomes=[]
    for i in (1,2):
        with sqlite3.connect(database,isolation_level=None) as connection:
            connection.row_factory=sqlite3.Row
            connection.execute('BEGIN IMMEDIATE')
            try:
                rotation=service.consume_request_in_transaction(connection,
                    producer_install_id='install-test',runtime_instance_id=runtime_id,public_jwk=public_jwk,
                    fence=grant['fence'],runtime_request_token=grant['next_request_token'],
                    runtime_request_sequence=grant['next_request_sequence'],
                    request_fingerprint=hashlib.sha256(f'relay-{i}'.encode()).hexdigest(),
                    receipt_request_id=f'receipt-{i}',now=WHEN+timedelta(seconds=i))
            except server.ProducerRuntimeLeaseError as exc:
                connection.commit() if exc.audit_recorded else connection.rollback()
                outcomes.append({'status':'rejected','error':exc.to_dict()})
            else:
                connection.commit()
                outcomes.append({'status':'accepted','runtime_lease':rotation})
    assert outcomes[0]['status']=='accepted'
    assert outcomes[1]['error']['error']['code']==server.STALE_RUNTIME_REQUEST_TOKEN
    return {'schema':'producer-runtime-token-contract-v1','now':WHEN.isoformat(),
            'runtime_instance_id':runtime_id,'public_jwk':public_jwk,'grant':grant,'outcomes':outcomes}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-root',type=Path,required=True)
    parser.add_argument('--source-archive',type=Path,
                        help='Pinned git archive ZIP used to populate a read-only source snapshot')
    parser.add_argument('--scratch',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    server_root=args.server_root.resolve()
    archive_sha256=None
    if args.source_archive:
        archive_sha256=hashlib.file_digest(args.source_archive.open('rb'),'sha256').hexdigest()
        with zipfile.ZipFile(args.source_archive) as archive:
            commit=archive.comment.decode('ascii')
            assert commit==SERVER_COMMIT, 'archive source commit differs'
            for member in archive.infolist():
                if not member.is_dir():
                    path=server_root/member.filename
                    assert path.resolve().is_relative_to(server_root)
                    assert hashlib.sha256(path.read_bytes()).digest()==hashlib.sha256(archive.read(member)).digest(), member.filename
    else:
        commit=subprocess.run(['git','-C',str(server_root),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
        assert commit==SERVER_COMMIT, 'server source commit differs'
        dirty=subprocess.run(['git','-C',str(server_root),'status','--porcelain'],capture_output=True,text=True,check=True).stdout
        assert not dirty.strip(), 'server source must be clean'
    scratch=args.scratch.resolve(); scratch.mkdir(parents=True,exist_ok=False)
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    for name in ('LOCALAPPDATA','APPDATA','PROGRAMDATA','TEMP','TMP'):
        path=scratch/name.lower();path.mkdir();os.environ[name]=str(path)
    os.environ['WORKER_ANALYSIS_ENV']='development'
    os.environ['WORKER_ANALYSIS_ACCESS_CODE_FILE']=str(scratch/'access-code')
    os.environ['WORKER_ANALYSIS_SECRET_KEY_FILE']=str(scratch/'secret-key')
    sys.dont_write_bytecode=True
    sys.path[:0]=[str(server_root/'tests'),str(server_root),str(REPO)]
    import test_logistics_api_v1 as api
    import test_logistics_p3_transfer_package as package
    import producer_runtime_lease as runtime_server
    import transfer_member_exchange
    import writer_session_fence as fence
    # Only the OS name boundary is isolated; writer admission itself still executes.
    original_name=fence.writer_admission_mutex_name
    fence.writer_admission_mutex_name=lambda root,**kwargs: original_name(root,**kwargs)+'.contract-generation'
    numbers=itertools.count(1)
    uuid.uuid4=lambda:uuid.UUID(int=next(numbers))
    secrets.token_urlsafe=lambda count=32:base64.urlsafe_b64encode(hashlib.sha256(str(next(numbers)).encode()).digest()).decode().rstrip('=')
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and (Path(path).resolve().is_relative_to(server_root) or Path(path).resolve().is_relative_to(REPO)):
            for key,value in tuple(vars(module).items()):
                if value is RealDatetime:setattr(module,key,FixedDatetime)
    socket.create_connection=deny_network
    socket.socket.connect=deny_network
    contracts={'exchange.json':exchange_contract(scratch,api,package),
               'exchange-conflict.json':exchange_contract(scratch,api,package,conflict=True),
               'runtime-token.json':runtime_contract(scratch,runtime_server)}
    for name,payload in contracts.items():(output/name).write_text(canonical(payload),encoding='utf-8',newline='\n')
    sources={}
    for module in tuple(sys.modules.values()):
        filename=getattr(module,'__file__',None)
        if filename:
            path=Path(filename).resolve()
            if path.is_relative_to(server_root) and path.is_file():
                sources[path.relative_to(server_root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    provenance={'source_repository':'WorkerAnalysisGUI-web','source_commit':commit,
                'source_archive_sha256':archive_sha256,
                'source_files':dict(sorted(sources.items())),
                'generator':'tests/contracts/generate_server_contracts.py',
                'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'outputs':{name:hashlib.sha256((output/name).read_bytes()).hexdigest() for name in contracts},
                'normalizations':['Only response.data.committed_at (SQLite wall-clock metadata) is fixed after actual client/server success; raw response retained in generator scratch',
                                  'X-Logistics-API-Token is replaced with the inert contract-only replay credential'],
                'scope':'in-process ephemeral instance, no network; desktop wire/state conformance only'}
    (output/'provenance.json').write_text(canonical(provenance),encoding='utf-8',newline='\n')
    print(json.dumps({'outputs':list(contracts),'exchange_requests':len(contracts['exchange.json']['requests']),
                      'server_source_files':len(sources)}))


if __name__=='__main__':
    main()
