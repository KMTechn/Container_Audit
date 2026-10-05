"""No fragment of a sensitive structured value reaches legacy public lines."""
import json
import ast
import hashlib
from pathlib import Path
import re
import secrets

import pytest

import auto_update
import current_user_onboarding as onboarding
from tools import direct_sync_relay_install_pack as install_pack
from tests.powershell_contracts import run_functions
from tests.test_shared_redaction_capture import capture_vector
from tests.test_installation_redaction_contract import _check
from tests.test_failure_public_lines import MODES, PREFIX, _cli, _invoke

SHAPES = ('mapping', 'list', 'nested', 'unbalanced')
STYLES = ('assignment', 'quoted-key')
FIXTURE = Path(__file__).with_name('fixtures') / 'installation_structured_redaction_vectors.json'
assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == '556c1826975f0c73f1a945be802ce761715274dce83cecdba02cd0093f77438c'
STRUCTURED_VECTORS = json.loads(FIXTURE.read_bytes())['vectors']


def _vector_fragments(vector):
    fragments = []
    for match in re.finditer(r'''"(?:\\.|[^"\\])*"|'(?:''|\\.|[^'\\])*' ''', vector['text'], re.VERBOSE):
        if vector['text'][match.end():].lstrip().startswith(':'):
            continue
        value = ast.literal_eval(match.group())
        if len(value) >= 4:
            fragments.append(value)
    if not fragments:
        pytest.fail('Structured vector marker count=0', pytrace=False)
    return fragments


@pytest.mark.parametrize('vector', STRUCTURED_VECTORS, ids=lambda vector: vector['id'])
def test_shared_python_structured_sinks(tmp_path, vector):
    text, fragments = vector['text'], _vector_fragments(vector)
    core = auto_update.redact_for_sink(text, vector['environ'])
    outputs = {'common': core, 'public_user_line': auto_update.failure_user_line(RuntimeError(text)),
               'public_install_pack': install_pack._redact_install_diagnostic(text)}
    outputs['public_json_envelope'] = auto_update.redact_for_sink(json.dumps({'message': text}), {})
    for name in ('status', 'summary', 'audit', 'diagnostic', 'log'):
        outputs[name] = auto_update.serialize_json_for_sink({'message': text})
    report_path = tmp_path / 'protected-failure.json'
    onboarding._persist_failure_report(report_path, {'status': 'FAILED'}, RuntimeError(text))
    outputs['protected'] = report_path.read_bytes()
    counts = {name: _original_count(value, fragments) for name, value in outputs.items()}
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Shared structured fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)
    _check(vector, core)
    try:
        envelope = json.loads(auto_update.redact_for_sink(json.dumps({'message': text}), {}))
    except ValueError:
        pytest.fail('Structured JSON envelope parse failures=1', pytrace=False)
    if _original_count(json.dumps(envelope), fragments):
        pytest.fail('Structured JSON envelope original count exceeds zero', pytrace=False)


@pytest.mark.parametrize('vector', STRUCTURED_VECTORS, ids=lambda vector: vector['id'])
@pytest.mark.parametrize('mode', MODES)
def test_shared_structured_installer_failure_sinks(tmp_path, monkeypatch, capsys, vector, mode):
    text, fragments = vector['text'], _vector_fragments(vector)
    report_path = tmp_path / 'protected.json'
    def operation(*args, **kwargs):
        cause = RuntimeError(text)
        if mode != 'preflight':
            onboarding._persist_failure_report(report_path, {'status': 'FAILED'}, cause)
            raise onboarding.CurrentUserOnboardingError('synthetic wrapper', report_path=report_path) from cause
        raise cause
    raw = _invoke(_cli(monkeypatch, tmp_path, mode, operation), capsys)
    protected = report_path.read_bytes() if report_path.exists() else b''
    counts = {'public': _original_count(raw, fragments), 'protected': _original_count(protected, fragments)}
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Structured installer fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)
    record = json.loads(raw.strip().removeprefix(PREFIX))
    if mode == 'preflight':
        if record.get('report_status') != 'REPORT_UNAVAILABLE' or report_path.exists():
            pytest.fail('Read-only structured failure wrote a report count=1', pytrace=False)
    elif record.get('report_sha256') != hashlib.sha256(protected).hexdigest() or record.get('report_path') != str(report_path):
        pytest.fail('Structured protected publication binding mismatches=1', pytrace=False)


def _sample(shape, style):
    fragments = ['STRUCTURAL-' + secrets.token_hex(16) for _ in range(2)]
    if shape == 'mapping':
        value = {'first': fragments[0], 'second': fragments[1]}
    elif shape == 'list':
        value = fragments
    else:
        value = {'first': [fragments[0], {'second': fragments[1]}]}
    value = json.dumps(value, separators=(',', ':'))
    if shape == 'unbalanced':
        value = value[:-3]
    key = 'password=' if style == 'assignment' else '"password": '
    return 'RuntimeError: ' + key + value, fragments


def _original_count(text, fragments):
    data = text.encode('utf-8') if isinstance(text, str) else text
    return sum(data.count(fragment.encode('utf-8')) for fragment in fragments)


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('style', STYLES)
def test_python_structured_value_is_removed_as_a_whole(tmp_path, shape, style):
    text, fragments = _sample(shape, style)
    error = RuntimeError(text)
    common = auto_update.redact_for_sink(text, {})
    public = auto_update.failure_user_line(error)
    public_install_pack = install_pack._redact_install_diagnostic(text)
    report_path = tmp_path / 'protected-failure.json'
    onboarding._persist_failure_report(report_path, {'status': 'FAILED'}, error)
    protected = report_path.read_bytes()
    counts = {name: _original_count(value, fragments) for name, value in
              [('common', common), ('public', public), ('public_install_pack', public_install_pack),
               ('protected', protected)]}
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Structured fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('style', STYLES)
def test_powershell_structured_value_is_removed_as_a_whole(tmp_path, engine, shape, style):
    text, fragments = _sample(shape, style)
    payload = tmp_path / 'input.json'
    payload.write_text(json.dumps({'text': text, 'fragments': fragments}), encoding='utf-8')
    result = run_functions(tmp_path, Path(__file__).resolve().parents[1] / 'tools/bootstrap_integrity.ps1',
                           ['Protect-InstallationText', 'ConvertTo-KmtechRedactedSinkText'], r'''
$sample=Get-Content -LiteralPath $env:CA_STRUCTURED_INPUT -Raw -Encoding UTF8|ConvertFrom-Json
$outputs=@{common=(Protect-InstallationText $sample.text -1 -Environment @{} -CommonOnly);
 public=(ConvertTo-KmtechRedactedSinkText $sample.text -UserLine);
 protected=(Protect-InstallationText $sample.text -1 -Environment @{})}
$counts=[ordered]@{}
foreach($name in $outputs.Keys){
 $count=0
 foreach($fragment in $sample.fragments){$count+=([regex]::Matches([string]$outputs[$name],[regex]::Escape($fragment))).Count}
 $counts[$name]=$count
}
$counts|ConvertTo-Json -Compress
''', engine=engine, values={'CA_STRUCTURED_INPUT': str(payload)})
    if result.returncode:
        pytest.fail('Structured PowerShell execution failed count=1', pytrace=False)
    counts = json.loads(result.stdout)
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Structured fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('style', STYLES)
def test_native_capture_removes_structured_value_before_bounding(tmp_path, engine, shape, style):
    text, fragments = _sample(shape, style)
    vector = {'text': text, 'environ': {}, 'expected_properties': {'max_utf8_bytes': 65536}}
    capture_vector(tmp_path, engine, vector)
    counts = {name: _original_count((tmp_path / (name + '.safe')).read_bytes(), fragments)
              for name in ('stdout', 'stderr')}
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Structured capture fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', STRUCTURED_VECTORS, ids=lambda vector: vector['id'])
def test_shared_powershell_structured_sinks(tmp_path, engine, vector):
    fragments = _vector_fragments(vector)
    payload = tmp_path / 'input.json'
    payload.write_text(json.dumps({'text': vector['text'], 'fragments': fragments}), encoding='utf-8')
    result = run_functions(tmp_path, Path(__file__).resolve().parents[1] / 'tools/bootstrap_integrity.ps1',
                           ['Protect-InstallationText', 'ConvertTo-KmtechRedactedSinkText', 'Get-InstallationFailureDetails'], r'''
$sample=Get-Content -LiteralPath $env:CA_STRUCTURED_INPUT -Raw -Encoding UTF8|ConvertFrom-Json
$outputs=@{common=(Protect-InstallationText $sample.text -1 -Environment @{} -CommonOnly);
 public_line=(ConvertTo-KmtechRedactedSinkText $sample.text -UserLine);
 public_log=(ConvertTo-KmtechRedactedSinkText $sample.text);
 protected=(Get-InstallationFailureDetails ([Exception]::new($sample.text))|ConvertTo-Json -Depth 16 -Compress)}
$envelope=([ordered]@{message=$sample.text}|ConvertTo-Json -Compress)
$outputs.public_status=ConvertTo-KmtechRedactedSinkText $envelope
foreach($name in @('status','summary','audit','diagnostic','log')){
 $outputs[$name]=Protect-InstallationText $envelope -1 -Environment @{}
}
$counts=[ordered]@{}
foreach($name in $outputs.Keys){
 $count=0
 foreach($fragment in $sample.fragments){$count+=([regex]::Matches([string]$outputs[$name],[regex]::Escape($fragment))).Count}
 $counts[$name]=$count
}
$valid=$true
try{$null=ConvertFrom-Json -InputObject $outputs.summary -ErrorAction Stop}catch{$valid=$false}
[ordered]@{counts=$counts;common=$outputs.common;valid_json=$valid}|ConvertTo-Json -Depth 8 -Compress
''', engine=engine, values={'CA_STRUCTURED_INPUT': str(payload)})
    if result.returncode:
        pytest.fail('Shared structured PowerShell protocol failures=1', pytrace=False)
    output = json.loads(result.stdout)
    counts = output['counts']
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Shared structured fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)
    if not output['valid_json']:
        pytest.fail('Structured PowerShell envelope parse failures=1', pytrace=False)
    _check(vector, output['common'])


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', STRUCTURED_VECTORS, ids=lambda vector: vector['id'])
def test_shared_native_structured_sinks(tmp_path, engine, vector):
    fragments = _vector_fragments(vector)
    capture_vector(tmp_path, engine, vector)
    counts = {name: _original_count((tmp_path / (name + '.safe')).read_bytes(), fragments)
              for name in ('stdout', 'stderr')}
    (tmp_path / 'counts.json').write_text(json.dumps(counts), encoding='utf-8')
    if any(counts.values()):
        pytest.fail('Shared structured capture fragments: ' + ','.join(f'{name}={count}' for name, count in counts.items()), pytrace=False)
