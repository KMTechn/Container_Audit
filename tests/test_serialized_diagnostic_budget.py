"""Bound serialized diagnostic reports; preserve machine metadata and public codes."""
import json
from pathlib import Path
import pytest
import auto_update as update
import current_user_onboarding as onboarding
from tests.powershell_contracts import run_functions
from tests.test_installation_stage_evidence import FUNCTIONS

ROOT = Path(__file__).resolve().parents[1]
CAP = 65536
INPUTS = [
    ('escape', '"\\\n' * 50000),
    ('multilingual', '가😀é' * 30000),
    ('boundary', 'v' * CAP),
]
POWERSHELL_INPUTS = {
    'escape': '("a"+[char]34+[char]92+[char]10)*50000',
    'multilingual': "('가'+[char]0xd83d+[char]0xde00+'é')*30000",
    'boundary': "'v'*65536",
}

@pytest.mark.parametrize('name,body', INPUTS, ids=[v[0] for v in INPUTS])
@pytest.mark.parametrize('create_new', (False, True), ids=('replace', 'create-new'))
def test_onboarding_diagnostics_are_codes(tmp_path, create_new, name, body):
    path = tmp_path / 'report.json'
    report = {'status': 'FAILED', 'binding_sha256': 'a' * 64,
              'owner': {'identity': 'exact-original-identity'}}
    onboarding._persist_failure_report(
        path, report, ValueError('FIRST-CONTEXT' + body + 'LAST-CONTEXT'), create_new=create_new)
    data = path.read_bytes()
    parsed = json.loads(data)
    assert len(data) <= CAP
    assert parsed['status']=='FAILED' and parsed['binding_sha256']=='a'*64
    assert parsed['owner']==report['owner']
    assert parsed['failure']=='SUPPORT_FAILURE'
    assert parsed['failure_evidence_status']=='REPORT_UNAVAILABLE'
    assert b'FIRST-CONTEXT' not in data and b'LAST-CONTEXT' not in data

@pytest.mark.parametrize('name,body', INPUTS, ids=[v[0] for v in INPUTS])
def test_diagnostic_serializer_final_bytes(name, body):
    result = update.serialize_json_for_sink({
        'status': 'FAILED', 'binding_sha256': 'b' * 64,
        'failure': 'FIRST-CONTEXT' + body + 'LAST-CONTEXT'})
    data = (result + '\n').encode('utf-8')
    parsed = json.loads(data)
    assert len(data) <= CAP
    assert parsed['status']=='FAILED' and parsed['binding_sha256']=='b'*64
    assert 'FIRST-CONTEXT' in parsed['failure'] and 'LAST-CONTEXT' in parsed['failure']
    assert '[TRUNCATED:' in parsed['failure']

@pytest.mark.parametrize('excess', (0, 1), ids=('exact', 'one-over'))
def test_serialized_json_boundary(excess):
    wrapper = len(json.dumps({'failure': ''}, separators=(',', ':')).encode('utf-8')) + 1
    body = ('FIRST-CONTEXT' + 'a' * (CAP - wrapper - len('FIRST-CONTEXTLAST-CONTEXT') + excess)
            + 'LAST-CONTEXT')
    data = (update.serialize_json_for_sink({'failure': body}) + '\n').encode('utf-8')
    parsed = json.loads(data)
    assert len(data) <= CAP
    if excess:
        assert parsed['sink_json_bounded'] is True and '[TRUNCATED:' in parsed['failure']
    else:
        assert len(data)==CAP and parsed['failure']==body

@pytest.mark.parametrize('create_new', (False, True), ids=('replace', 'create-new'))
def test_machine_metadata_is_not_bounded(tmp_path, create_new):
    payload = {'status': 'READY', 'identity_data': 'm' * 70000, 'identity_sha256': 'c' * 64}
    writer = onboarding._write_json_atomic_create_new if create_new else onboarding._write_json_atomic
    path = tmp_path / 'machine.json'
    writer(path, payload)
    data = path.read_bytes()
    assert len(data) > CAP
    assert data == (update.serialize_machine_metadata(payload) + '\n').encode('utf-8')
    assert json.loads(data) == payload

@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('name,body',INPUTS,ids=[v[0] for v in INPUTS])
def test_protected_original_failure_final_bytes(tmp_path, engine, name, body):
    script = """
function Set-InstallationEvidenceAcl {param($Path,$Sid)}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'bounded') ''
$message='FIRST-CONTEXT'+(%s)+'LAST-CONTEXT'
Write-InstallationCaughtFailure ([InvalidOperationException]::new($message))
$ref=$Script:InstallationOriginalFailure
if(-not $ref.path -or $ref.complete){throw 'truncation not marked'}
$raw=[IO.File]::ReadAllBytes($ref.path)
if($raw.Length -gt 65536 -or $ref.saved_bytes -ne $raw.Length){throw 'serialized bound or readback differs'}
$parsed=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json
if($parsed.schema -cne 'container-audit-original-installation-failure-v1' -or -not $parsed.truncated){throw 'required metadata missing'}
$value=$parsed.failure.exception_chain[0].message
if(-not $value.StartsWith('FIRST-CONTEXT') -or -not $value.EndsWith('LAST-CONTEXT')){throw 'head or tail missing'}
'PASS'
""" % POWERSHELL_INPUTS[name]
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1', FUNCTIONS, script, engine=engine)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('name,body', INPUTS, ids=[v[0] for v in INPUTS])
def test_private_canonical_audit_final_bytes(tmp_path, engine, name, body):
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['ConvertTo-CanonicalAuditJson', 'Save'], r'''
function Set-InstallationEvidenceAcl {param($Path,$Sid)}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'bounded') ''
$path=Join-Path $root 'audit.json'
$message='FIRST-CONTEXT'+(<DIAGNOSTIC_INPUT>)+'LAST-CONTEXT'
Save $path @{schema='audit-fixture';binding_sha256=('a'*64);failure=@{message=$message}}
$raw=[IO.File]::ReadAllBytes($path)
if($raw.Length -gt 65536){throw 'serialized bound exceeded'}
$parsed=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json
if($parsed.schema -cne 'audit-fixture' -or $parsed.binding_sha256 -cne ('a'*64)){throw 'metadata changed'}
if(-not $parsed.failure.message.Contains('[TRUNCATED:')){throw 'truncation not marked'}
if(-not $parsed.failure.message.StartsWith('FIRST-CONTEXT') -or -not $parsed.failure.message.EndsWith('LAST-CONTEXT')){throw 'head or tail missing'}
'PASS'
'''.replace('<DIAGNOSTIC_INPUT>', POWERSHELL_INPUTS[name]), engine=engine)
    assert result.returncode == 0, result.stderr
