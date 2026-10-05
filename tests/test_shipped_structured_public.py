"""The four additional vectors are P1 checks only at public diagnostic sinks."""
import hashlib
import json
from pathlib import Path
import re
from contextlib import nullcontext

import pytest

FIXTURE = Path(__file__).parent / 'fixtures/structured_public_vectors.json'
VECTORS = json.loads(FIXTURE.read_bytes())['vectors']


def _absent(vector, value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)
    if any(fragment in text for fragment in re.findall(r'[0-9a-f]{64}', vector['text'])):
        pytest.fail('Structured diagnostic fragment reached a public sink', pytrace=False)


@pytest.mark.parametrize('vector', VECTORS, ids=lambda item: item['id'])
def test_structured_values_at_every_python_support_boundary(tmp_path, monkeypatch, capsys, vector):
    from auto_update import emit_support_record, mixed_status_record, support_record
    from tools import direct_sync_relay_operator as operator
    from tools import direct_sync_relay_install_pack as installer
    from tools import register_container_audit_worker_pc as registration
    import direct_sync_auto_bootstrap as bootstrap
    import direct_sync_operator as audit
    import direct_sync_push as push
    import direct_sync_runtime as runtime
    import current_user_onboarding as onboarding
    import auto_update as update

    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == '556c1826975f0c73f1a945be802ce761715274dce83cecdba02cd0093f77438c'
    payload = {'status': 'FAIL', 'error_message': vector['text'], 'stdout': vector['text'],
               'stderr': vector['text'], 'argv': [vector['text']],
               'stdout_tail': vector['text'], 'stderr_tail': vector['text'],
               'failure_details': [{'type': 'builtins.RuntimeError', 'message': vector['text']}],
               'blocked_reason': vector['text']}
    payload['command_results'] = [{'command': ['icacls.exe', vector['text']], 'returncode': 0}]
    stages = ('relay_operator', 'relay_runtime', 'relay_host', 'relay_bootstrap',
              'registration', 'runtime_profile_check', 'runtime_profile_install',
              'protected_admin_install', 'update_archive_check', 'relay_install',
              'argument_parse', 'portable_entrypoint', 'user_relay')
    for stage in stages:
        emit_support_record(payload, stage=stage, error=RuntimeError(vector['text']))
        _absent(vector, support_record(payload, stage=stage))
    _absent(vector, capsys.readouterr().out)
    operator._emit(payload, str(tmp_path / 'operator.json'))
    installer._write_json(tmp_path / 'installer.json', payload)
    bootstrap._write_json(tmp_path / 'bootstrap.json', payload)
    audit._append_operator_audit(tmp_path / 'audit.jsonl', action='pause', report=payload)
    push._write_json_atomic(tmp_path / 'push.json', payload)
    runtime._append_jsonl(tmp_path / 'runtime.jsonl', payload)
    captured = []
    monkeypatch.setattr(registration, '_write_registration_json',
                        lambda path, value, **kwargs: captured.append(value))
    registration._write_registration_report(tmp_path / 'registration.json', payload)
    _absent(vector, captured)
    error=RuntimeError(vector['text'])
    error.stdout=error.stderr=vector['text']
    onboarding_report={'status':'FAILED','owner':{'sid':'S-1-5-21-101-202-303-1001'}}
    onboarding._persist_failure_report(tmp_path/'onboarding.json',onboarding_report,error)
    assert onboarding_report['owner']=={'sid':'S-1-5-21-101-202-303-1001'}
    assert onboarding_report['failure_evidence_refs']==[]
    onboarding.emit_installer_failure(error,'onboarding')
    _absent(vector,capsys.readouterr().err)
    control=tmp_path/'update-control'
    control.mkdir()
    (control/'policy.json').write_text(json.dumps({'operator_sid':'S-1-5-21-101-202-303-1001'}),encoding='utf-8')
    pointer={'schema':update.SCHEMA,'sha':'a'*40,'transition_id':'b'*32}
    (control/'active.json').write_text(json.dumps(pointer),encoding='utf-8')
    monkeypatch.setattr(update,'fixed_helper',lambda *args,**kwargs:'')
    monkeypatch.setattr(update,'update_lock',lambda *args,**kwargs:nullcontext())
    def fail_prepared(_control):
        raise error
    monkeypatch.setattr(update,'_apply_prepared',fail_prepared)
    assert update.apply_prepared(control)==0
    assert json.loads((control/'active.json').read_bytes())==pointer
    assert json.loads((control/'transition.json').read_bytes())['phase']=='DEFERRED'
    assert not list(control.glob('failure-text-*.json'))
    for path in control.glob('*.json'):
        _absent(vector,path.read_text(encoding='utf-8'))
    for path in tmp_path.iterdir():
        if path.suffix in ('.json', '.jsonl'):
            _absent(vector, path.read_text(encoding='utf-8'))
    for name in ('installer.json', 'bootstrap.json'):
        command_result = json.loads((tmp_path / name).read_bytes())['command_results'][0]
        assert command_result['command'] == ['SUPPORT_FAILURE', 'SUPPORT_FAILURE']
        assert command_result['returncode'] == 0
    _absent(vector, capsys.readouterr().out)
    original = {'worker_id': 'arbitrary-machine-identity', 'status': 'RUNNING',
                'credential_ref': 'unchanged-reference', 'queue': {'pending': 2},
                'runtime_lease': {'status': 'held', 'nonce': 'unchanged-nonce'},
                'last_result': {'status': 'acked', 'receipt': {'unchanged': 'state'},
                                'error_message': vector['text']}}
    projected = mixed_status_record(original)
    assert projected.keys() == original.keys()
    for name in ('worker_id', 'status', 'credential_ref', 'queue', 'runtime_lease'):
        assert projected[name] == original[name]
    assert projected['last_result'].keys() == original['last_result'].keys()
    assert projected['last_result']['receipt'] == original['last_result']['receipt']
    assert projected['last_result']['error_message'] == 'SUPPORT_FAILURE'
    _absent(vector, projected)
