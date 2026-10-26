"""An optional wait diagnostic must not poison mandatory installer evidence."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('already_failed', [False, True])
def test_wait_diagnostic_failure_preserves_the_existing_evidence_state(tmp_path, already_failed):
    canonical = tmp_path / 'canonical.ps1'
    journal = tmp_path / 'journal.ps1'
    canonical.write_text((ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').read_text(encoding='utf-8-sig'), encoding='utf-8-sig')
    journal.write_text((ROOT / 'tools/bootstrap_integrity.ps1').read_text(encoding='utf-8-sig'), encoding='utf-8-sig')
    driver = tmp_path / 'fault.ps1'
    driver.write_text(r'''
param([string]$Canonical,[string]$Journal,[string]$Initial)
$ErrorActionPreference='Stop'
foreach($source in @(@{path=$Canonical;name='Get-CanonicalWriterPreimageForQuiesce'},@{path=$Canonical;name='Write-CanonicalWaitElapsed'},@{path=$Journal;name='Write-InstallationEvidenceEvent'})){
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($source.path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'parse failed'}
 $node=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $source.name},$true))
 if($node.Count -eq 0 -and $source.name -ceq 'Write-CanonicalWaitElapsed'){continue}
 if($node.Count -ne 1){throw 'selected writer missing'}
 Invoke-Expression $node[0].Extent.Text
}
$Script:InstallationEvidenceRoot='isolated-fixture'
$Script:InstallationEvidenceFailed=($Initial -ceq 'true')
$Script:InstallationEvidenceFailureCodes=[Collections.Generic.List[string]]::new()
if($Script:InstallationEvidenceFailed){$Script:InstallationEvidenceFailureCodes.Add('PREEXISTING_FIXTURE')}
function Assert-InstallationEvidenceWriteRoot($Root){throw 'injected-journal-write-denial'}
function Get-CanonicalWriterSnapshot($Root){return @{restore_required=$false}}
$null=Get-CanonicalWriterPreimageForQuiesce 'isolated-fixture'
[Console]::Out.WriteLine((@{failed=$Script:InstallationEvidenceFailed;codes=@($Script:InstallationEvidenceFailureCodes.ToArray())}|ConvertTo-Json -Compress))
''', encoding='utf-8-sig')
    result = subprocess.run([shutil.which('powershell.exe'), '-NoProfile', '-NonInteractive', '-File',
                             str(driver), '-Canonical', str(canonical), '-Journal', str(journal),
                             '-Initial', str(already_failed).lower()], capture_output=True,
                            text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0
    assert result.stderr == ''
    assert json.loads(result.stdout) == {
        'failed': already_failed, 'codes': ['PREEXISTING_FIXTURE'] if already_failed else [],
    }
