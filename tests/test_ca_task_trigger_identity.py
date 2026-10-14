from pathlib import Path
import subprocess
from types import SimpleNamespace
import xml.etree.ElementTree as xml

import pytest
import auto_update as update
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SID = 'S-1-5-21-101-202-303-1001'
OTHER = 'S-1-5-21-101-202-303-1002'
NS = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}


def _task(root, case):
    task = xml.fromstring(update.logon_task_xml(app_root=root, operator_sid=SID))
    trigger = task.find('t:Triggers/t:LogonTrigger', NS)
    user = trigger.find('t:UserId', NS)
    text = {'sid': SID, 'lower_sid': SID.lower(), 'local': 'worker',
            'qualified': r'HOST\worker', 'case': r'host\WORKER',
            'other': OTHER, 'admin': r'HOST\administrator', 'service': 'SYSTEM',
            'unknown': 'missing-account', 'bad_sid': 'S-1-broken', 'empty': ''}
    if case in text:
        user.text = text[case]
    elif case == 'multiple_user':
        xml.SubElement(trigger, user.tag).text = SID
    elif case == 'multiple_trigger':
        task.find('t:Triggers', NS).append(xml.fromstring(xml.tostring(trigger)))
    elif case == 'nested':
        xml.SubElement(user, 'nested').text = SID
    elif case == 'missing':
        trigger.remove(user)
    elif case == 'other_field':
        task.find('t:Settings/t:Hidden', NS).text = 'false'
    else:
        raise AssertionError('unknown task case')
    return task


EXPECTED = {case: 'MATCHED' for case in ('sid', 'lower_sid', 'local', 'qualified', 'case')}
EXPECTED.update({case: 'DIFFERS' for case in ('other', 'admin', 'service')})
EXPECTED.update({case: 'INVALID' for case in ('empty', 'multiple_user', 'multiple_trigger', 'nested', 'missing', 'bad_sid')})
EXPECTED['unknown'] = 'UNKNOWN'


def _resolver(identity):
    if identity[:2].upper() == 'S-':
        if identity == 'S-1-broken':
            raise ValueError('invalid SID')
        return 'S-' + identity[2:]
    if identity.casefold() in ('worker', r'host\worker'):
        return SID
    if identity.casefold() == r'host\administrator':
        return OTHER
    if identity == 'SYSTEM':
        return 'S-1-5-18'
    raise OSError('unknown account')


@pytest.mark.parametrize('case', tuple(EXPECTED))
def test_python_trigger_identity_classification(tmp_path, monkeypatch, case):
    monkeypatch.setattr(update, '_resolve_task_principal_sid', _resolver)
    assert update.task_trigger_identity_status(_task(tmp_path, case), SID) == EXPECTED[case]


@pytest.mark.parametrize('case', (*EXPECTED, 'other_field'))
def test_real_python_task_reader_preserves_other_fields(tmp_path, monkeypatch, case):
    monkeypatch.setattr(update, '_resolve_task_principal_sid', _resolver)
    payload = xml.tostring(_task(tmp_path, case), encoding='unicode')
    calls = []
    def query(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=payload)
    monkeypatch.setattr(subprocess, 'run', query)
    assert update.supported_task_present(tmp_path, SID) is (EXPECTED.get(case) == 'MATCHED')
    assert len(calls) == 1


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
@pytest.mark.parametrize('case', tuple(EXPECTED))
def test_powershell_trigger_uses_existing_sid_resolver(tmp_path, engine, case):
    path = tmp_path / 'task.xml'
    path.write_bytes(xml.tostring(_task(tmp_path, case), encoding='utf-8'))
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1',
        ['ConvertTo-BootstrapPrincipalSid', 'Get-BootstrapTaskTriggerIdentityStatus'],
        (ROOT / 'tests/ca_task_trigger_identity_probe.ps1').read_text(encoding='utf-8-sig'),
        engine=engine, values={'CA_TRIGGER_XML': str(path), 'CA_TRIGGER_EXPECTED': EXPECTED[case],
                              'CA_TRIGGER_POLICY': SID})
    assert result.returncode == 0
    assert 'TRIGGER_IDENTITY_PASS' in result.stdout
