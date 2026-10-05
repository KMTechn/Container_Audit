"""Shared synthetic sink vectors; no real environment values enter test evidence."""
import hashlib
import json
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/installation_redaction_vectors.json"
assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == "3c6b87ae65e4e1496f94bdfbba7908ea0427411855b8b69bfbd1854ed646add5"
VECTORS = json.loads(FIXTURE.read_bytes())["vectors"]


def _text(vector):
    if "text" in vector:
        return vector["text"]
    if "json" in vector:
        return json.dumps(vector["json"])
    generator = vector["text_generator"]
    return generator["head"] + generator["fill_char"] * generator["fill_bytes"] + generator["tail"]


def _check(vector, actual):
    if "expected_json" in vector:
        assert json.loads(actual) == vector["expected_json"]
    elif "expected" in vector:
        assert actual == vector["expected"]
    else:
        expected = vector["expected_properties"]
        assert len(actual.encode()) <= expected.get("max_utf8_bytes", 65536)
        if "starts_with" in expected:
            assert actual.startswith(expected["starts_with"])
        if "ends_with" in expected:
            assert actual.endswith(expected["ends_with"])
        if "contains_regex" in expected:
            assert re.search(expected["contains_regex"], actual)
        if "not_contains" in expected and expected["not_contains"] in actual:
            pytest.fail("Synthetic secret survived sink redaction", pytrace=False)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
def test_shared_python_vectors(vector):
    import auto_update
    if "json" in vector:
        actual = json.dumps(auto_update.redact_json_for_sink(vector["json"], vector["environ"]))
    else:
        actual = auto_update.redact_for_sink(_text(vector), vector["environ"])
    _check(vector, actual)


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
def test_shared_powershell_vectors(tmp_path, engine, vector):
    # Inputs are private synthetic files so large vectors never become argv/env.
    path = tmp_path / "vector.json"
    path.write_text(json.dumps({"text": _text(vector), "environment": vector["environ"]}), encoding="utf-8")
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Protect-InstallationText"], r'''
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
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Protect-InstallationText"], r'''
$text='HEAD-'+('가나다'*40000)+' ValueError: last synthetic exception'
$safe=Protect-InstallationText $text -1 -Environment @{} -CommonOnly
if([Text.Encoding]::UTF8.GetByteCount($safe) -gt 65536 -or -not $safe.StartsWith('HEAD-') -or -not $safe.EndsWith('ValueError: last synthetic exception')){throw 'UTF8 head/tail bound differs.'}
if($safe.Contains([char]0xFFFD)){throw 'UTF8 boundary split.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, "UTF8 head/tail vector failed"
