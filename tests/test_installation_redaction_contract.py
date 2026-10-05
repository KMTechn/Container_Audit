"""Shared synthetic sink vectors; no real environment values enter test evidence."""
import hashlib
import json
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/installation_redaction_vectors.json"
assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == "3106bccafd881396b7bbf1a6b3356ccd41853e4a74bbd7b6918ac2b6a599bfc7"
VECTORS = json.loads(FIXTURE.read_bytes())["vectors"]


def _text(vector):
    if "text" in vector:
        return vector["text"]
    if "json" in vector:
        return json.dumps(vector["json"])
    generator = vector["text_generator"]
    return generator["head"] + generator["fill_char"] * generator["fill_bytes"] + generator["tail"]


def _check(vector, actual):
    checks = []
    if "expected_json" in vector:
        try:
            checks.append(json.loads(actual) == vector["expected_json"])
        except (ValueError, TypeError):
            checks.append(False)
    elif "expected" in vector:
        checks.append(actual == vector["expected"])
    else:
        expected = vector["expected_properties"]
        checks.append(len(actual.encode()) <= expected.get("max_utf8_bytes", 65536))
        if "starts_with" in expected:
            checks.append(actual.startswith(expected["starts_with"]))
        if "ends_with" in expected:
            checks.append(actual.endswith(expected["ends_with"]))
        if "contains_regex" in expected:
            checks.append(bool(re.search(expected["contains_regex"], actual)))
        if "not_contains" in expected:
            checks.append(expected["not_contains"] not in actual)
    if not all(checks):
        pytest.fail(f"Sink contract mismatches: {checks.count(False)}", pytrace=False)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
def test_shared_python_vectors(vector):
    import auto_update
    if "json" in vector:
        actual = json.dumps(auto_update.redact_json_for_sink(vector["json"], vector["environ"]))
    else:
        actual = auto_update.redact_for_sink(_text(vector), vector["environ"])
    _check(vector, actual)


def _assert_no_raw_environment_bytes(vector, text):
    encoded = text.encode('utf-8')
    for name, value in vector['environ'].items():
        # Identifier exceptions are contract output, independent of the implementation.
        expected = vector.get('expected', '')
        if value in expected and '[REDACTED:' + name + ']' not in expected:
            continue
        if len(value) < 4 or re.search(r'(?i)_(FILE|PATH|DIR|ROOT)$', name):
            continue
        for variant in (value, json.dumps(value, ensure_ascii=True)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]):
            if variant.encode('utf-8') in encoded:
                pytest.fail('Raw synthetic environment value survived sink byte search', pytrace=False)


@pytest.mark.parametrize('vector', VECTORS, ids=lambda vector: vector['id'])
def test_install_pack_wrapper_vectors(vector, monkeypatch):
    from tools import direct_sync_relay_install_pack as pack
    # Use exactly the synthetic environment supplied by the shared contract.
    monkeypatch.setattr(pack.os, 'environ', dict(vector['environ']))
    actual = pack._redact_install_diagnostic(vector.get('json', _text(vector)))
    text = json.dumps(actual) if isinstance(actual, dict) else actual
    _check(vector, text)
    _assert_no_raw_environment_bytes(vector, text)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', VECTORS, ids=lambda vector: vector['id'])
def test_canonical_wrapper_vectors(tmp_path, engine, vector):
    path = tmp_path / 'synthetic-vector.json'
    path.write_text(json.dumps({'text': _text(vector), 'environment': vector['environ']}), encoding='utf-8')
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1', ['ConvertTo-CanonicalSafeDiagnostic'], r'''
$vector=Get-Content -LiteralPath $env:CA_VECTOR_PATH -Raw -Encoding UTF8|ConvertFrom-Json
foreach($property in $vector.environment.PSObject.Properties){[Environment]::SetEnvironmentVariable($property.Name,[string]$property.Value,'Process')}
ConvertTo-CanonicalSafeDiagnostic $vector.text
''', engine=engine, values={'CA_VECTOR_PATH': str(path)})
    if result.returncode:
        pytest.fail('Canonical sink wrapper protocol failed', pytrace=False)
    text = result.stdout.rstrip('\r\n')
    _check(vector, text)
    _assert_no_raw_environment_bytes(vector, text)


def test_install_pack_json_sink_redacts_and_bounds_the_whole_envelope(tmp_path, monkeypatch):
    from tools import direct_sync_relay_install_pack as pack
    synthetic = 'private-install-sink-fixture-credential'
    monkeypatch.setattr(pack.os, 'environ', {'CUSTOM_SERVICE_SECRET': synthetic})
    target = tmp_path / 'result.json'
    body = 'HEAD ' + synthetic + ' ' + '가나다' * 40000 + ' TAIL ' + synthetic
    pack._write_json.__wrapped__(target, {'failure': body, 'stderr': body, 'nested': {'admin_pin': 'synthetic-only-pin'}})
    data = target.read_bytes()
    assert len(data) <= 65536
    assert synthetic.encode() not in data
    assert b'synthetic-only-pin' not in data
    assert json.loads(data)['nested']['admin_pin'] == '[REDACTED:field]'


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
def test_shared_powershell_vectors(tmp_path, engine, vector):
    # Inputs are private synthetic files so large vectors never become argv/env.
    path = tmp_path / "vector.json"
    path.write_text(json.dumps({"text": _text(vector), "environment": vector["environ"]}), encoding="utf-8")
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Protect-InstallationText", "ConvertTo-KmtechRedactedSinkText"], r'''
$vector=Get-Content -LiteralPath $env:CA_VECTOR_PATH -Raw -Encoding UTF8|ConvertFrom-Json
$environment=@{}
foreach($property in $vector.environment.PSObject.Properties){$environment[$property.Name]=$property.Value}
Protect-InstallationText $vector.text -1 -Environment $environment -CommonOnly
''', engine=engine, values={"CA_VECTOR_PATH": str(path)})
    if result.returncode:
        pytest.fail("PowerShell synthetic vector runner failed", pytrace=False)
    _check(vector, result.stdout.rstrip("\r\n"))


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_utf8_head_tail_budget_preserves_last_exception(engine, tmp_path):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Protect-InstallationText", "ConvertTo-KmtechRedactedSinkText"], r'''
$text='HEAD-'+('가나다'*40000)+' ValueError: last synthetic exception'
$safe=Protect-InstallationText $text -1 -Environment @{} -CommonOnly
if([Text.Encoding]::UTF8.GetByteCount($safe) -gt 65536 -or -not $safe.StartsWith('HEAD-') -or -not $safe.EndsWith('ValueError: last synthetic exception')){throw 'UTF8 head/tail bound differs.'}
if($safe.Contains([char]0xFFFD)){throw 'UTF8 boundary split.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, "UTF8 head/tail vector failed"


PROCESS_VECTORS = [vector for vector in VECTORS if 'pid-start-mutex' in vector['id']]


@pytest.mark.parametrize('vector', PROCESS_VECTORS, ids=lambda vector: vector['id'])
def test_process_identifier_machine_metadata_follows_shared_contract(vector):
    import auto_update
    environment = {name: value for name, value in vector['environ'].items()
                   if name.endswith(('_PID', '_START', '_MUTEX'))}
    assert environment
    for name, value in environment.items():
        text = json.dumps({'process_identity': value})
        if vector['id'].endswith('-kept'):
            auto_update.assert_machine_metadata_no_secrets(text, {name: value})
        else:
            with pytest.raises(ValueError, match='^MACHINE_METADATA_SECRET_DETECTED$'):
                auto_update.assert_machine_metadata_no_secrets(text, {name: value})


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', PROCESS_VECTORS, ids=lambda vector: vector['id'])
def test_process_identifier_powershell_machine_metadata_follows_shared_contract(tmp_path, engine, vector):
    environment = {name: value for name, value in vector['environ'].items()
                   if name.endswith(('_PID', '_START', '_MUTEX'))}
    path = tmp_path / 'process-vector.json'
    path.write_text(json.dumps({'environment': environment, 'allowed': vector['id'].endswith('-kept')}), encoding='utf-8')
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1',
        ['Protect-InstallationText', 'Assert-InstallationMachineMetadataNoSecrets'], r'''
$vector=Get-Content -LiteralPath $env:CA_VECTOR_PATH -Raw -Encoding UTF8|ConvertFrom-Json
foreach($p in $vector.environment.PSObject.Properties){[Environment]::SetEnvironmentVariable($p.Name,[string]$p.Value,'Process')}
foreach($p in $vector.environment.PSObject.Properties){
    $text=@{process_identity=[string]$p.Value}|ConvertTo-Json -Compress
    $rejected=$false
    try{Assert-InstallationMachineMetadataNoSecrets $text}catch{$rejected=$true}
    if($rejected -eq $vector.allowed){throw 'process identifier metadata policy differs'}
}
'PASS'
''', engine=engine, values={'CA_VECTOR_PATH': str(path)})
    assert result.returncode == 0, 'Process identifier metadata vector failed; raw values suppressed'
    assert result.stdout.strip() == 'PASS'
