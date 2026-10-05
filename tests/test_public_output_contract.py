"""Shared public-output vectors are independent of diagnostic redaction."""
import hashlib
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/public_output_vectors.json'
assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == '767ece42ad23dbbcacee4bb98509b35749655017664476ae3d05d852784eb5a5'
VECTORS = json.loads(FIXTURE.read_bytes())['vectors']


def _check(vector, actual):
    if list(actual.items()) != list(vector['expected'].items()):
        pytest.fail('Public vector differs; rejected-value output count=0', pytrace=False)


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['id'])
def test_python_public_vectors(vector):
    import auto_update
    function = getattr(auto_update, 'public_record', None)
    if function is None:
        pytest.fail('Public record function count=0', pytrace=False)
    _check(vector, function(vector['fields'], vector['allowed_codes'], vector['safe_messages']))


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['id'])
def test_powershell_public_vectors(tmp_path, engine, vector):
    path = tmp_path / 'public-vector.json'
    path.write_text(json.dumps(vector), encoding='utf-8')
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1',
                           ['ConvertTo-KmtechPublicRecord'], r'''
$json=Get-Content -LiteralPath $env:CA_PUBLIC_VECTOR -Raw -Encoding UTF8
# PS 7.5 otherwise converts a JSON UTC string to DateTime before the tested API.
$v=if((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')){
    $json|ConvertFrom-Json -DateKind String
}else{$json|ConvertFrom-Json}
$fields=[ordered]@{}
foreach($p in $v.fields.PSObject.Properties){$fields[$p.Name]=$p.Value}
$record=ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes @($v.allowed_codes) -SafeMessages @($v.safe_messages)
ConvertTo-Json -InputObject $record -Depth 20 -Compress
''', engine=engine, values={'CA_PUBLIC_VECTOR': str(path)})
    if result.returncode:
        pytest.fail('Public record PowerShell protocol failed', pytrace=False)
    _check(vector, json.loads(result.stdout))
