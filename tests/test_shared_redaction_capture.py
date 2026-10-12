"""Run all shared vectors through the actual native stdout/stderr capture."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tests.test_installation_redaction_contract import VECTORS, _text, _check

ROOT = Path(__file__).resolve().parents[1]


def capture_vector(tmp_path, engine, vector, root=ROOT):
    source = tmp_path / 'vector.json'
    source.write_text(json.dumps({'text': _text(vector), 'environment': vector['environ']}), encoding='utf-8')
    child = tmp_path / 'child.py'
    child.write_text('import json,pathlib,sys\ntext=json.loads(pathlib.Path(sys.argv[1]).read_bytes())["text"]\nsys.stdout.write(text)\nsys.stderr.write(text)\n', encoding='utf-8')
    driver = tmp_path / 'capture.ps1'
    driver.write_text('''param($Root,$Python,$Child,$Vector,$OutputRoot)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'tools/bootstrap_integrity.ps1')
$inputVector=Get-Content -LiteralPath $Vector -Raw -Encoding UTF8|ConvertFrom-Json
foreach($p in $inputVector.environment.PSObject.Properties){[Environment]::SetEnvironmentVariable($p.Name,[string]$p.Value,'Process')}
Initialize-InstallationChildCapture
$result=[KMTechInstallationChildCapture]::Run($Python,@('-B',$Child,$Vector),$OutputRoot,$null)
foreach($name in @('stdout','stderr')){
 $safe=ConvertTo-SafeInstallationOutput $result.$name
 [IO.File]::WriteAllBytes((Join-Path $OutputRoot ($name+'.safe')),$safe.bytes)
}
''', encoding='utf-8')
    completed = subprocess.run([shutil.which(engine), '-NoProfile', '-NonInteractive', '-File',
                                str(driver), str(root), sys.executable, str(child), str(source), str(tmp_path)],
                               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if completed.returncode:
        pytest.fail('Native shared-vector capture protocol failed', pytrace=False)
    for name in ('stdout', 'stderr'):
        actual = (tmp_path / (name + '.safe')).read_text(encoding='utf-8')
        _check(vector, actual)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', VECTORS, ids=lambda vector: vector['id'])
def test_shared_native_capture_vectors(tmp_path, engine, vector):
    capture_vector(tmp_path, engine, vector)
