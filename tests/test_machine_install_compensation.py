"""Machine publication compensation, using owned files and COM transport only."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_machine_artifact_compensation_restores_original_bytes_acl_and_absence(tmp_path, engine):
    result = run_functions(tmp_path, INSTALLER,
        ["Full", "Sha", "Get-CanonicalMachineArtifactPreimage", "Restore-CanonicalMachineArtifacts"], r'''
$prior=Join-Path $env:CA_CONTRACT_ROOT 'prior.json'
$added=Join-Path $env:CA_CONTRACT_ROOT 'added.lnk'
$absent=Join-Path $env:CA_CONTRACT_ROOT 'never-created.json'
[IO.File]::WriteAllText($prior,'original publication bytes')
$sha=Sha $prior;$acl=Get-BootstrapAclComparisonKey ((Get-Acl -LiteralPath $prior).Sddl)
$before=Get-CanonicalMachineArtifactPreimage @($prior,$added,$absent)
[IO.File]::WriteAllText($prior,'replacement publication bytes')
[IO.File]::WriteAllText($added,'new publication bytes')
Restore-CanonicalMachineArtifacts $before
if((Sha $prior) -cne $sha -or (Get-BootstrapAclComparisonKey ((Get-Acl -LiteralPath $prior).Sddl)) -cne $acl){throw 'Original bytes or ACL differ'}
if((Test-Path -LiteralPath $added) -or (Test-Path -LiteralPath $absent)){throw 'New publication survived compensation'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("state", ("owned", "changed_shortcut", "other_pending"))
def test_machine_removal_only_removes_bound_pending_and_owned_direct_shortcut(tmp_path, engine, state):
    result = run_functions(tmp_path, INSTALLER,
        ["Full", "Same", "Sha", "Get-CanonicalMachineShortcutArguments", "Remove-CanonicalMachineArtifacts"], r'''
function ConvertTo-ProcessArgument([string]$Value){return '"'+$Value+'"'}
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
$pending=Join-Path $env:CA_CONTRACT_ROOT 'pending.json'
$shortcut=Join-Path $env:CA_CONTRACT_ROOT 'direct.lnk'
$worker=@{sid='fixture-worker'}
$marker=@{schema='container-audit-machine-pending-v1';target_sid=$worker.sid;install_root=$root}
if($env:CA_PUBLICATION_STATE -ceq 'other_pending'){$marker.install_root=Join-Path $env:CA_CONTRACT_ROOT 'other'}
[IO.File]::WriteAllText($pending,($marker|ConvertTo-Json))
[IO.File]::WriteAllText($shortcut,'preserve original shortcut bytes')
$pendingSha=Sha $pending;$shortcutSha=Sha $shortcut
$script:link=@{TargetPath=(Join-Path $root 'runtime\pythonw.exe');Arguments=('-I -B "'+(Join-Path $root 'app\main.py')+'"');WorkingDirectory=(Join-Path $root 'app')}
if($env:CA_PUBLICATION_STATE -ceq 'changed_shortcut'){$script:link.TargetPath=Join-Path $root 'legacy.exe'}
$script:shell=[pscustomobject]@{}
$script:shell|Add-Member ScriptMethod CreateShortcut {param($Path);return $script:link}
$body=${function:Remove-CanonicalMachineArtifacts}.ToString().Replace('New-Object -ComObject WScript.Shell','$script:shell')
$body=$body.Replace('[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)','')
Set-Item Function:Remove-CanonicalMachineArtifacts ([scriptblock]::Create($body))
$rejected=$false
try{Remove-CanonicalMachineArtifacts $root $worker @($pending,$shortcut)}catch{$rejected=$true}
if($env:CA_PUBLICATION_STATE -ceq 'other_pending'){
 if(-not $rejected -or (Sha $pending) -cne $pendingSha -or (Sha $shortcut) -cne $shortcutSha){throw 'Unbound publication changed'}
}else{
 if($rejected -or (Test-Path -LiteralPath $pending)){throw 'Bound pending survived removal'}
 if($env:CA_PUBLICATION_STATE -ceq 'owned'){
  if(Test-Path -LiteralPath $shortcut){throw 'Owned direct shortcut survived removal'}
 }elseif((Sha $shortcut) -cne $shortcutSha){throw 'Changed shortcut was not preserved'}
}
'PASS'
''', engine=engine, values={"CA_PUBLICATION_STATE": state})
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout
