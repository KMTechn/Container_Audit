"""Machine publication compensation, using owned files and COM transport only."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_unproved_child_compensation_is_recorded_under_product_strict_mode(tmp_path, engine):
    result = run_functions(tmp_path, INSTALLER,
        ["Full", "Same", "ConvertFrom-CanonicalMachineArtifactJournal", "Restore-CanonicalMachineArtifacts",
         "Restore-CanonicalMachineInstallationPrestate"], r'''
Set-StrictMode -Version Latest
$state=Join-Path $env:CA_CONTRACT_ROOT 'state'
[void][IO.Directory]::CreateDirectory($state)
function Get-ContainerMachineInstallStateRoot {return $state}
function Invoke-InstallationEvidenceChild {throw 'unproved child must not cause another launch'}
function Save-CanonicalMachineFailureAudit {}
function Stop-ContainerWriterFence {throw 'unproved child fence must remain'}
$items=@('pending-onboarding.json','shortcut.lnk' | ForEach-Object {
 [pscustomobject]@{path=(Join-Path $state $_);exists=$false;bytes=$null;sha256='';acl_sddl=''}
})
$prestate=[ordered]@{run_id=('b'*32);startup_before=@();artifact_before=$items;worker_preparation=$null;worker_run_before=$null}
$audit=[ordered]@{placement_child=@{status='EXIT_UNPROVEN'};compensation_child=@{status='NOT_STARTED'};
 machine_prestate=@{path='';sha256=''};code_replacement=@{status='';receipt_path=''}}
$worker=[pscustomobject]@{same_caller=$false;sid='unused-compensation-principal'}
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
if(Restore-CanonicalMachineInstallationPrestate $worker $root $root @{} $prestate @() '' (Join-Path $state 'audit.json') $audit $null){throw 'unproved compensation was released'}
if($audit.compensation.child_exit -cne 'UNPROVEN' -or $audit.artifact_restore -cne 'PASS' -or -not $audit.fence_retained){throw 'strict-mode compensation record differs'}
'STRICT_COMPENSATION_PASS'
''', engine=engine)
    (tmp_path / "strict-stderr.log").write_text(result.stderr, encoding="utf-8")
    assert result.returncode == 0, "Strict-mode diagnostic is retained in the owned test directory"
    assert "STRICT_COMPENSATION_PASS" in result.stdout


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
def test_machine_recovery_recreates_withheld_preimage_from_persisted_journal(tmp_path, engine):
    result = run_functions(tmp_path, INSTALLER,
        ["Full", "Sha", "Get-CanonicalMachineArtifactPreimage", "Restore-CanonicalMachineArtifacts",
         "ConvertTo-CanonicalMachineArtifactJournal", "ConvertFrom-CanonicalMachineArtifactJournal"], r'''
$prior=Join-Path $env:CA_CONTRACT_ROOT 'withheld-pending.json'
[IO.File]::WriteAllText($prior,'old incomplete onboarding intent')
$sha=Sha $prior;$acl=Get-BootstrapAclComparisonKey ((Get-Acl -LiteralPath $prior).Sddl)
$before=Get-CanonicalMachineArtifactPreimage @($prior)
$journal=ConvertTo-CanonicalMachineArtifactJournal $before | ConvertTo-Json -Depth 8 | ConvertFrom-Json
Remove-Item -LiteralPath $prior -ErrorAction Stop
Restore-CanonicalMachineArtifacts (ConvertFrom-CanonicalMachineArtifactJournal @($journal))
if((Sha $prior) -cne $sha -or (Get-BootstrapAclComparisonKey ((Get-Acl -LiteralPath $prior).Sddl)) -cne $acl){throw 'Withheld publication bytes or ACL differ'}
'RECREATED_PREIMAGE_PASS'
''', engine=engine)
    assert result.returncode == 0, "Recovery artifact evidence stays in the owned test directory"
    assert "RECREATED_PREIMAGE_PASS" in result.stdout


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
