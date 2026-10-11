from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("valid", "local_mismatch", "folder_escape", "reparse"))
def test_same_worker_plan_runs_readonly_scope_admission_before_return(tmp_path, engine, case):
    driver = r'''
$testMode=$true;$PlanOnly=$true;$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$profile=Join-Path $env:CA_CONTRACT_ROOT 'worker'
$local=Join-Path $profile 'AppData\Local'
[void][IO.Directory]::CreateDirectory($local)
$env:LOCALAPPDATA=if($env:CA_PLAN_CASE -ceq 'local_mismatch'){$env:CA_CONTRACT_ROOT}else{$local}
$script:scopeReads=0
$body=${function:Get-CanonicalWorkerPreparationPaths}.ToString().Replace(
 '[Environment]::GetFolderPath([Environment+SpecialFolder]::$folder,[Environment+SpecialFolderOption]::DoNotVerify)',
 '$(if($env:CA_PLAN_CASE -ceq ''folder_escape''){$env:CA_CONTRACT_ROOT}else{Join-Path ([string]$Worker.profile_root) $folder})')
Set-Item Function:Get-CanonicalWorkerPreparationPaths ([scriptblock]::Create($body))
function Get-ContainerMachineInstallStateRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'machine-state')}
function Assert-ContainerDataGenerationTarget {}
function Assert-BootstrapNoReparsePoint {
 param($Path,$Purpose,[switch]$PathOnly)
 $script:scopeReads++
 if($env:CA_PLAN_CASE -ceq 'reparse' -and $Purpose -ceq 'worker preparation ancestor'){throw 'owned reparse boundary'}
}
function Initialize-InstallationEvidence {throw 'plan reached evidence writer'}
function Start-ContainerWriterFence {throw 'plan reached fence writer'}
function Get-CanonicalMachineArtifactPreimage {throw 'plan reached preimage capture'}
$worker=[pscustomobject]@{profile_root=$profile;sid='unused-plan-principal';same_caller=$true}
$before=@([IO.Directory]::GetFileSystemEntries($env:CA_CONTRACT_ROOT,'*',[IO.SearchOption]::AllDirectories)|Sort-Object)
$failed=$false;$output=@()
try{$output=@(Invoke-CanonicalMachineInstallation $worker (Join-Path $env:CA_CONTRACT_ROOT 'source') (Join-Path $env:CA_CONTRACT_ROOT 'current') @{} $null)}catch{$failed=$true}
if($failed -ne ($env:CA_PLAN_CASE -cne 'valid')){throw 'plan scope admission result differs'}
if(-not $failed -and $output -cnotcontains 'install_status=PLAN_ONLY'){throw 'valid plan did not return'}
$after=@([IO.Directory]::GetFileSystemEntries($env:CA_CONTRACT_ROOT,'*',[IO.SearchOption]::AllDirectories)|Sort-Object)
if(($before -join "`n") -cne ($after -join "`n")){throw 'plan changed the owned filesystem'}
if($env:CA_PLAN_CASE -cin @('valid','reparse') -and $script:scopeReads -lt 2){throw 'worker ancestor admission was skipped'}
'MACHINE_PLAN_SCOPE_ADMISSION_PASS'
'''
    result = run_functions(tmp_path, INSTALLER,
                           ["Full", "Same", "Get-CanonicalWorkerPreparationPaths", "Invoke-CanonicalMachineInstallation"],
                           driver, engine=engine, values={"CA_PLAN_CASE": case})
    (tmp_path / "plan-stderr.log").write_text(result.stderr, encoding="utf-8")
    (tmp_path / "plan-stdout.log").write_text(result.stdout, encoding="utf-8")
    assert result.returncode == 0, "Plan admission diagnostic is retained in the owned test directory"
    assert "MACHINE_PLAN_SCOPE_ADMISSION_PASS" in result.stdout
