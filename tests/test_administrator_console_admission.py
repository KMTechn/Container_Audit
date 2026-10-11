"""Read-only current-console binding; no host process or profile discovery."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"

@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_console_admission_preserves_elevated_console_and_defers_session_zero(tmp_path, engine):
    result = run_functions(tmp_path, INSTALLER,
        ["Full", "Same", "Resolve-CanonicalWorkerSid", "Get-CanonicalConsoleWorkerSecurity", "Resolve-CanonicalMachineWorker"], r'''
$ownSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$otherSid=$ownSid.Substring(0,$ownSid.LastIndexOf('-')+1)+'100001'
$profile=Join-Path $env:CA_CONTRACT_ROOT 'worker'
[void][IO.Directory]::CreateDirectory($profile)
$script:consoleSid=$ownSid
$script:ownerReturn=0
$script:owners=@($ownSid)
$script:profileReads=0
function Get-CanonicalWorkerProfileRoot {param($Sid)
 $script:profileReads++; if($Sid -cnotin @($ownSid,$otherSid)){throw 'Unexpected profile read'};return $profile
}
function Get-CimInstance {
 [CmdletBinding()]param($ClassName,$Filter,$Property)
 if($ClassName -ceq 'Win32_ComputerSystem'){
  if($Property -cne 'UserName'){throw 'Console scope differs'}
  return [pscustomobject]@{UserName=$script:consoleSid}
 }
 if($ClassName -cne 'Win32_Process' -or $Filter -cne "Name='explorer.exe'"){throw 'Census scope differs'}
 foreach($sid in $script:owners){[pscustomobject]@{SessionId=7;OwnerSid=$sid}}
}
function Invoke-CimMethod {
 [CmdletBinding()]param($InputObject,$MethodName)
 if($MethodName -cne 'GetOwnerSid'){throw 'Unexpected process operation'}
 return [pscustomobject]@{ReturnValue=$script:ownerReturn;Sid=$InputObject.OwnerSid}
}
$caller=[pscustomobject]@{sid=$ownSid;session_id=7;elevated=$true}
if($null -ne (Resolve-CanonicalMachineWorker '' '' $caller)){throw 'Elevated console path changed'}
$caller.session_id=0
$worker=Resolve-CanonicalMachineWorker '' '' $caller
if($worker.sid -cne $ownSid -or -not $worker.same_caller -or $worker.survey_path -or
 $worker.survey_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $worker.target_source -cne 'CURRENT_CONSOLE'){throw 'Session zero binding differs'}
$script:consoleSid=$otherSid
$script:owners=@($otherSid,$otherSid)
$worker=Resolve-CanonicalMachineWorker '' '' $caller
if($worker.sid -cne $otherSid -or $worker.same_caller){throw 'Different worker binding differs'}
foreach($case in @('none','ambiguous','no_console','owner_failure','invalid_owner')){
 $script:owners=@($ownSid);$script:consoleSid=$ownSid;$script:ownerReturn=0
 switch($case){
  'none'{$script:owners=@()}
  'ambiguous'{$script:owners=@($ownSid,$otherSid)}
  'no_console'{$script:consoleSid=''}
  'owner_failure'{$script:ownerReturn=2}
  'invalid_owner'{$script:owners=@('S-1-5-18')}
 }
 $reads=$script:profileReads;$refused=$false
 try{Resolve-CanonicalMachineWorker '' '' $caller|Out-Null}catch{$refused=$true}
 if(-not $refused -or $script:profileReads -ne $reads){throw 'Ambiguous worker was admitted or profile read'}
}
$caller.session_id=7;$caller.elevated=$false
if($null -ne (Resolve-CanonicalMachineWorker '' '' $caller)){throw 'Ordinary path changed'}
if(@(Get-ChildItem -LiteralPath $profile -Recurse -File).Count){throw 'Admission wrote worker files'}
'CONSOLE_ADMISSION_PASS'
''', engine=engine)
    assert result.returncode == 0, "Console admission contract failed; captured streams remain private"
    assert result.stdout.strip() == "CONSOLE_ADMISSION_PASS"
