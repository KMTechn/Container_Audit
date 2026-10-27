"""Authorization credentials must be removed before assignment values are split."""
import json
from pathlib import Path
import secrets

import pytest

import auto_update
import current_user_onboarding
from tests.powershell_contracts import run_functions


SHAPES = ('header', 'assignment', 'json', 'proxy_header', 'proxy_assignment', 'nested_json',
          'header_newline', 'scheme_newline', 'value_newline', 'mixed_header')
SCHEMES = ('Bearer', 'Basic', 'bEaReR', 'bAsIc')
ROOT = Path(__file__).resolve().parents[1]


def sample(shape, scheme):
    material = secrets.token_urlsafe(32) + '=='
    name = 'Proxy-Authorization' if shape.startswith('proxy_') else 'Authorization'
    if shape == 'mixed_header':
        name = 'AUTHORIZATION'
    value = scheme + ' ' + material
    if shape in ('json', 'nested_json'):
        text = json.dumps({name: value})
        if shape == 'nested_json':
            text = 'native failure: ' + text
    else:
        separator = '=' if shape.endswith('assignment') else ': '
        text = name + separator + value
        if shape == 'header_newline':
            text = name + ':\r\n' + value
        elif shape == 'scheme_newline':
            text = name + ': ' + scheme + '\r\n' + material
        elif shape == 'value_newline':
            text += '\r\nnative failure: access denied'
    return text, material


def require_absent(material, value):
    raw = value if isinstance(value, bytes) else str(value).encode('utf-8')
    if material.encode('utf-8') in raw:
        pytest.fail('authorization credential remains', pytrace=False)


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('scheme', SCHEMES)
@pytest.mark.parametrize('sink', ('common', 'failure'))
def test_authorization_scheme_value_is_fully_masked(shape, scheme, sink):
    text, material = sample(shape, scheme)
    safe = (auto_update.redact_for_sink(text, {}) if sink == 'common'
            else auto_update._failure_text(text))
    require_absent(material, safe)


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('scheme', SCHEMES)
@pytest.mark.parametrize('link', ('__cause__', '__context__'))
def test_deep_failure_chain_and_streams_mask_authorization(shape, scheme, link):
    text, material = sample(shape, scheme)
    native = OSError(5, text)
    native.winerror = 32
    native.exit_code = 7
    native.stdout = text
    native.stderr = text.encode('utf-8')
    middle = RuntimeError('intermediate native failure')
    outer = RuntimeError('outer native failure')
    setattr(outer, link, middle)
    setattr(middle, link, native)
    details = auto_update._failure_details(outer)
    require_absent(material, json.dumps(details))
    assert len(details) == 3
    assert details[2]['type'] == type(native).__module__ + '.' + type(native).__name__
    assert {key: details[2][key] for key in ('errno', 'winerror', 'exit_code')} == {
        'errno': 5, 'winerror': 32, 'exit_code': 7}
    assert details[0]['message'] == str(outer)
    assert details[1]['message'] == str(middle)
    assert details[2]['stdout_truncated'] is False
    assert details[2]['stderr_truncated'] is False


@pytest.mark.parametrize('shape', SHAPES)
@pytest.mark.parametrize('scheme', SCHEMES)
def test_support_report_readback_has_no_authorization_credential(tmp_path, monkeypatch, shape, scheme):
    text, material = sample(shape, scheme)
    error = RuntimeError(text)
    error.stdout = text
    error.stderr = text.encode('utf-8')
    writer = current_user_onboarding._write_json_atomic
    monkeypatch.setattr(current_user_onboarding, '_write_json_atomic', writer.__wrapped__)
    path = tmp_path / 'support.json'
    current_user_onboarding._persist_failure_report(path, {'status': 'FAILED'}, error, environ={})
    if not path.is_file():
        pytest.fail('support report was not published', pytrace=False)
    raw = path.read_bytes()
    require_absent(material, raw)
    record = json.loads(raw)
    assert record['status'] == 'FAILED'
    assert record['failure_details'][0]['type'] == 'builtins.RuntimeError'
    assert record['failure_details'][0]['stdout_truncated'] is False
    assert record['failure_details'][0]['stderr_truncated'] is False


def test_ordinary_bearer_word_and_native_diagnostics_are_preserved():
    text = 'Native error: access denied (Bearer); errno=5; winerror=32; exit_code=7'
    assert auto_update.redact_for_sink(text, {}) == text
    assert auto_update._failure_text(text) == text
    assert auto_update.failure_user_line(RuntimeError(text)) == text
    for ordinary in ('Bearer', 'bearer', 'Basic', 'AUTHORIZATION check unavailable'):
        assert auto_update.redact_for_sink(ordinary, {}) == ordinary
        assert auto_update._failure_text(ordinary) == ordinary


@pytest.mark.parametrize('scheme', ('Bearer', 'Basic'))
@pytest.mark.parametrize('sink', ('common', 'failure'))
def test_authorization_mask_preserves_adjacent_native_diagnostics(scheme, sink):
    material = secrets.token_urlsafe(32) + '=='
    prefix, suffix = 'Native error: errno=5; ', '; winerror=32; exit_code=7'
    text = prefix + 'Authorization: ' + scheme + ' ' + material + suffix
    safe = (auto_update.redact_for_sink(text, {}) if sink == 'common'
            else auto_update._failure_text(text))
    require_absent(material, safe)
    assert safe.startswith(prefix)
    assert safe.endswith(suffix)


@pytest.mark.parametrize('scheme', ('Bearer', 'Basic'))
@pytest.mark.parametrize('sink', ('common', 'failure'))
def test_native_assignment_on_next_line_is_not_a_scheme_credential(scheme, sink):
    text = 'Authorization: ' + scheme + '\r\nwinerror=32; exit_code=7'
    safe = (auto_update.redact_for_sink(text, {}) if sink == 'common'
            else auto_update._failure_text(text))
    assert safe.endswith('\r\nwinerror=32; exit_code=7')


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_powershell_authorization_schemes_and_sink_readback(tmp_path, engine):
    cases = []
    for shape in SHAPES:
        for scheme in SCHEMES:
            text, material = sample(shape, scheme)
            cases.append({'id': shape + '_' + scheme, 'text': text, 'material': material})
    (tmp_path / 'cases.json').write_text(json.dumps(cases), encoding='utf-8')
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1', [
        'Test-InstallationShortSecretValue', 'Protect-InstallationText',
        'ConvertTo-KmtechRedactedSinkText'], r'''
$cases=Get-Content -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'cases.json') -Raw|ConvertFrom-Json
$rows=@()
foreach($case in $cases){
    $safe=ConvertTo-KmtechRedactedSinkText -Text $case.text -Environment @{}
    $path=Join-Path $env:CA_CONTRACT_ROOT ($case.id+'.txt')
    [IO.File]::WriteAllText($path,$safe,[Text.UTF8Encoding]::new($false))
    $readback=[IO.File]::ReadAllText($path)
    $rows+=@{id=$case.id;remaining=$readback.Contains($case.material)}
}
$ordinary='Native error: access denied (Bearer); errno=5; winerror=32; exit_code=7'
$preserved=(ConvertTo-KmtechRedactedSinkText -Text $ordinary -Environment @{}) -ceq $ordinary
@{rows=$rows;ordinary_preserved=$preserved}|ConvertTo-Json -Depth 5 -Compress
''', engine=engine)
    record = json.loads(result.stdout)
    if any(row['remaining'] for row in record['rows']):
        pytest.fail('PowerShell authorization credential remains', pytrace=False)
    assert record['ordinary_preserved'] is True
