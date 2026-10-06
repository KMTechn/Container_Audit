"""Observe serialized bytes using synthetic values, never product match logic."""
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
IS_IW = (ROOT / 'core/installation_failure_redaction.py').is_file()


def cases():
    for value in ('SyntheticOpaque429Abcd', 'Synthetic한글429Abcd🙂', 'Synthetic/\\"429Abcd'):
        units = value.encode('utf-16-be').hex()
        units = [units[i:i + 4] for i in range(0, len(units), 4)]
        for spelling in ('lower', 'upper', 'mixed', 'nested'):
            opaque = ''.join('\\u' + (unit.upper() if spelling == 'upper' else unit) for unit in units)
            if spelling == 'mixed':
                opaque = ''.join('\\u' + unit if i % 2 else json.dumps(chr(int(unit, 16)), ensure_ascii=True)[1:-1] for i, unit in enumerate(units))
            inner = '{"opaque":"' + opaque + '","password":"field-only"}'
            if spelling == 'nested':
                inner = json.dumps({'opaque': inner})
            yield value, json.dumps({'message': inner}, ensure_ascii=False)


def check_bytes(raw, value):
    def visit(node):
        if isinstance(node, dict):
            return all(visit(name) and visit(item) for name, item in node.items())
        if isinstance(node, list):
            return all(visit(item) for item in node)
        if not isinstance(node, str):
            return True
        if value in node:
            return False
        try:
            parsed = json.loads(node)
        except (ValueError, TypeError):
            return True
        return visit(parsed) if parsed != node else True
    if not visit(raw.decode('utf-8')):
        pytest.fail('Synthetic known value survived JSON decoding of sink bytes', pytrace=False)


def test_python_text_after_structured_redaction():
    if IS_IW:
        from core.installation_failure_redaction import redact_for_sink
    else:
        from auto_update import redact_for_sink
    for value, text in cases():
        safe = redact_for_sink(text, {'REVIEW_SECRET': value})
        check_bytes(safe.encode(), value)
        assert 'REDACTED' in safe


def test_python_final_serialization_and_short_metadata():
    if IS_IW:
        from core.installation_failure_redaction import json_text_for_sink as serialize
    else:
        from auto_update import serialize_json_for_sink as serialize
    for value, text in cases():
        with patch.dict(os.environ, {'REVIEW_SECRET': value}, clear=True):
            encoded = serialize({'message': text, value: 'ordinary', 'fixed_count': 7})
        check_bytes(encoded.encode(), value)
        assert json.loads(encoded)['fixed_count'] == 7
    with patch.dict(os.environ, {'REVIEW_SECRET': 'abc'}, clear=True):
        encoded = serialize({'fixed_count': 7, 'enabled': False, 'absent': None})
    assert json.loads(encoded) == {'fixed_count': 7, 'enabled': False, 'absent': None}
    # Replacing a known numeric spelling must never publish invalid JSON.
    with patch.dict(os.environ, {'REVIEW_SECRET': '1234'}, clear=True):
        with pytest.raises(ValueError, match='^REPORT_UNAVAILABLE$'):
            serialize({'fixed_count': 1234})


def test_known_value_remaining_refuses_publication(tmp_path):
    if IS_IW:
        from core.current_user_onboarding import _write_json_atomic as publish
        from core.installation_failure_redaction import redact_for_sink
    else:
        from auto_update import redact_for_sink, serialize_json_for_sink
    # A marker containing the same known value cannot be certified safe.
    environment = {'REVIEW_SECRET': 'REVIEW_SECRET', 'LOCALAPPDATA': str(tmp_path / 'profile')}
    with pytest.raises(ValueError, match='^REPORT_UNAVAILABLE$'):
        redact_for_sink('{"opaque":"REVIEW_SECRET"}', environment)
    path = tmp_path / 'failure-refused.json'
    with patch.dict(os.environ, environment, clear=True):
        with pytest.raises(ValueError, match='^REPORT_UNAVAILABLE$'):
            payload = {'failure': 'REVIEW_SECRET', 'message': 'REVIEW_SECRET'}
            if IS_IW:
                publish(path, payload)
            else:
                serialize_json_for_sink(payload)
    if IS_IW:
        assert not path.exists()


def test_python_atomic_failure_report(tmp_path):
    if IS_IW:
        from core.current_user_onboarding import _write_json_atomic as publish
    else:
        from auto_update import write_json_durable as publish
    for index, (value, text) in enumerate(cases()):
        path = tmp_path / ('failure-probe-' + str(index) + '.json')
        with patch.dict(os.environ, {'REVIEW_SECRET': value, 'LOCALAPPDATA': str(tmp_path / 'profile')}, clear=True):
            publish(path, {'failure': text, 'message': text, 'fixed_count': 7})
        raw = path.read_bytes()
        assert len(raw) <= 65536
        assert json.loads(raw)['fixed_count'] == 7
        check_bytes(raw, value)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_powershell_text_and_published_bytes(tmp_path, engine):
    inputs = tmp_path / 'synthetic.json'
    inputs.write_text(json.dumps([{'value': value, 'text': text} for value, text in cases()]), encoding='utf-8')
    # Import only top-level function ASTs; installer entrypoints never execute.
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1', ['Protect-InstallationText'], r'''
$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($env:ESC_SOURCE,[ref]$null,[ref]$parseErrors)
if($parseErrors.Count){throw 'PROBE_SOURCE_PARSE_FAILED'}
foreach($node in $tree.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
 $parent=$node.Parent;$nested=$false
 while($null -ne $parent){if($parent -is [Management.Automation.Language.FunctionDefinitionAst]){$nested=$true;break};$parent=$parent.Parent}
 if(-not $nested){Invoke-Expression ($node.Extent.Text -replace '^function\s+','function global:')}
}
$Script:InstallationEvidenceSensitiveValues=@()
function Assert-InstallationEvidenceWriteRoot {}
function Assert-InstallationEvidenceProtectedPath {}
function Set-InstallationEvidenceAcl {}
function Write-InstallationPreparationEvent {}
$Script:InstallationEvidenceRoot=$env:ESC_ROOT
$Script:InstallationEvidenceSid='S-1-5-21-1-2-3-1001'
$Script:InstallationEvidenceFailureCodes=[Collections.Generic.List[string]]::new()
$cases=Get-Content -LiteralPath $env:ESC_INPUT -Raw -Encoding UTF8|ConvertFrom-Json
$index=0
foreach($case in $cases){
 $environment=@{REVIEW_SECRET=[string]$case.value}
 $safe=ConvertTo-KmtechRedactedSinkText -Text $case.text -Environment $environment
 [IO.File]::WriteAllText((Join-Path $env:ESC_ROOT ('text-'+$index+'.txt')),$safe,[Text.UTF8Encoding]::new($false))
 [Environment]::SetEnvironmentVariable('REVIEW_SECRET',[string]$case.value,'Process')
 Write-InstallationEvidenceEvent @{failure=$case.text;fixed_count=7}
 $index++
}
$oversizedValue='OversizedOpaque429Abcd'
[Environment]::SetEnvironmentVariable('REVIEW_SECRET',$oversizedValue,'Process')
Write-InstallationEvidenceEvent @{event=$oversizedValue;failure=('x'*70000);fixed_count=7}
$refused=$false
try{ConvertTo-KmtechRedactedSinkText -Text '{"opaque":"REVIEW_SECRET"}' -Environment @{REVIEW_SECRET='REVIEW_SECRET'}|Out-Null}
catch{if($_.Exception.Message -ne 'REPORT_UNAVAILABLE'){throw 'PROBE_REFUSAL_DIFFERS'};$refused=$true}
if(-not $refused){throw 'PROBE_EXPECTED_REFUSAL'}
$beforeLength=(Get-ChildItem -LiteralPath $env:ESC_ROOT -Filter 'stages*.jsonl' | Measure-Object Length -Sum).Sum
[Environment]::SetEnvironmentVariable('REVIEW_SECRET','REVIEW_SECRET','Process')
try{Write-InstallationEvidenceEvent @{failure='REVIEW_SECRET'}}catch{if($_.Exception.Message -ne 'REPORT_UNAVAILABLE'){throw 'PROBE_PUBLICATION_REFUSAL_DIFFERS'}}
if((Get-ChildItem -LiteralPath $env:ESC_ROOT -Filter 'stages*.jsonl' | Measure-Object Length -Sum).Sum -ne $beforeLength){throw 'PROBE_REFUSED_REPORT_CHANGED'}
if(-not $Script:InstallationEvidenceFailureCodes.Contains('REPORT_UNAVAILABLE')){throw 'PROBE_REFUSAL_CODE_DIFFERS'}
''', engine=engine, values={'ESC_SOURCE': str(ROOT / 'tools/bootstrap_integrity.ps1'), 'ESC_ROOT': str(tmp_path), 'ESC_INPUT': str(inputs)})
    (tmp_path / 'native-stdout.log').write_text(result.stdout or '', encoding='utf-8')
    (tmp_path / 'native-stderr.log').write_text(result.stderr or '', encoding='utf-8')
    if result.returncode:
        pytest.fail('PowerShell synthetic sink probe failed', pytrace=False)
    values = list(cases())
    for index, (value, _) in enumerate(values):
        check_bytes((tmp_path / ('text-' + str(index) + '.txt')).read_bytes(), value)
    # The product event writer appends one serialized diagnostic per call.
    paths = [p for p in tmp_path.rglob('*') if p.is_file() and p.suffix == '.jsonl']
    assert paths, 'Product diagnostic publisher wrote no report'
    for path in paths:
        for line in path.read_bytes().splitlines():
            assert len(line) + 1 <= 65536
            assert isinstance(json.loads(line), dict)
            for value in [value for value, _ in values] + ['OversizedOpaque429Abcd']:
                check_bytes(line, value)
