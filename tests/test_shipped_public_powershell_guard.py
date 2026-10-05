"""Use both native parsers for the shipped support PowerShell source set."""
import json
from pathlib import Path
import shutil

import pytest

from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('added', (False, True), ids=('shipped', 'new-five-source-sink'))
def test_shipped_powershell_public_provenance(tmp_path, engine, added):
    executable = shutil.which(engine)
    assert executable, 'Required native parser is unavailable'
    extra = r'''
function NewDiagnosticProbe {
 try { throw 'synthetic' } catch { $sentence=$_.Exception.Message;Write-Host $sentence }
  $child=[pscustomobject]@{stdout='synthetic'};Write-Output $child.stdout
  Write-Output $args
  Write-Output $env:CA_SYNTHETIC_VALUE
  $joined=$sentence+$child.stdout;Write-Output $joined
}
''' if added else ''
    result = run_powershell([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
        '-File', str(ROOT / 'tests/public_support_guard.ps1'), '-Root', str(ROOT),
        '-ExtraSource', extra])
    assert result.returncode == 0, 'Shipped PowerShell syntax/provenance probe failed'
    findings = json.loads(result.stdout)
    if added:
        added_findings = [row for row in findings if row['function'] == 'NewDiagnosticProbe']
        assert {row['sources'] for row in added_findings} == {1, 2, 3, 4, 8}
    else:
        assert not findings, findings
