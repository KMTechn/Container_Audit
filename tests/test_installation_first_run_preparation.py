"""First installation contracts with in-memory ACLs and no host elevation."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "tools/bootstrap_integrity.ps1"

MEMORY_PATHS = r'''
. $env:CA_CONTRACT_SOURCE
$script:realEvidenceWriter=${function:Write-InstallationEvidenceEvent}
$script:acls=@{};$script:writes=@();$script:events=@();$script:created=@()
$default='O:BAG:BAD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;0xe0010000;;;AU)'
$target='O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;;0x1200af;;;AU)(A;OICIIO;0xe0010000;;;AU)'
$sealed='O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)'
foreach($path in @('C:\','C:\KMTech','C:\KMTech\Apps','C:\KMTech\Apps\Container_Audit')){
 if($path -ceq 'C:\KMTech\Apps\Container_Audit' -and $env:CA_PREP_SCENARIO -in @('empty','app_failure')){continue}
 $sddl=if($path -in @('C:\KMTech','C:\KMTech\Apps')){$default}else{$sealed}
 if($env:CA_PREP_SCENARIO -ceq 'target' -and $path -in @('C:\KMTech','C:\KMTech\Apps')){$sddl=$target}
 if($path -ceq 'C:\KMTech\Apps'){
  if($env:CA_PREP_SCENARIO -ceq 'owner'){$sddl=$sddl.Replace('O:BA','O:S-1-5-21-1-2-3-1000')}
  if($env:CA_PREP_SCENARIO -ceq 'shape'){$sddl+='(A;;WD;;;WD)'}
 }
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm($sddl);$script:acls[$path]=$acl
}
function Test-Path {param($LiteralPath,$PathType)
 if($LiteralPath -in @('C:\','C:\KMTech','C:\KMTech\Apps') -or $LiteralPath.StartsWith('C:\KMTech\Apps\')){return $script:acls.ContainsKey($LiteralPath)}
 return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath)
}
function Get-Item {param($LiteralPath,$ErrorAction)
 if($LiteralPath -in @('C:\','C:\KMTech','C:\KMTech\Apps') -or $LiteralPath.StartsWith('C:\KMTech\Apps\')){
  if(-not $script:acls.ContainsKey($LiteralPath)){throw 'fixture path is absent'}
  return [pscustomobject]@{Attributes=if($env:CA_PREP_SCENARIO -ceq 'reparse' -and $LiteralPath -ceq 'C:\KMTech\Apps'){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory}}
 }
 return (Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath)
}
function Get-Acl {param($LiteralPath,$ErrorAction)
 $copy=[Security.AccessControl.DirectorySecurity]::new();$copy.SetSecurityDescriptorBinaryForm($script:acls[$LiteralPath].GetSecurityDescriptorBinaryForm());return $copy
}
function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction)
 if($LiteralPath -notin @('C:\KMTech','C:\KMTech\Apps')){throw 'unexpected native ACL target'}
 $script:writes+=,$LiteralPath;$script:acls[$LiteralPath]=$AclObject
}
function Write-InstallationEvidenceEvent {param($Payload) $script:events+=,$Payload}
function Test-InstallationEvidencePrivileged {return $false}
function Assert-BootstrapNoReparsePoint {param($Path,$Purpose,[switch]$PathOnly)}
function ConvertTo-ProcessArgument {param([string]$Value) return '"'+$Value+'"'}
'''


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("scenario", ("empty", "legacy", "target", "reparse", "owner", "shape"))
def test_ordinary_preflight_admits_only_supported_first_run_shapes(tmp_path, engine, scenario):
    result = run_functions(tmp_path, LIBRARY, ["Invoke-InstallationElevationCapture"], MEMORY_PATHS + r'''
$Script:InstallationEvidenceRoot=$env:CA_CONTRACT_ROOT
$script:reached=$false
function Start-Process {param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
 $script:reached=$true;throw 'fixture stops before elevation'
}
$installer=Join-Path (Split-Path -Parent (Split-Path -Parent $env:CA_CONTRACT_SOURCE)) 'INSTALL_THIS_PC.ps1'
try{[void](Invoke-InstallationElevationCapture $installer @('-File',$installer) 'unused-audit' 'S-1-5-21-1-2-3-1000')}catch{}
$expected=$env:CA_PREP_SCENARIO -in @('empty','legacy','target')
if($script:reached -ne $expected){throw ('supported elevation reachability differs: '+$env:CA_PREP_SCENARIO)}
if($script:writes.Count -or $script:created.Count){throw 'ordinary preflight mutated folders'}
'PASS'
''', engine=engine, values={"CA_PREP_SCENARIO": scenario})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_protected_path_refusal_retains_original_native_exception(tmp_path, engine):
    result = run_functions(tmp_path, LIBRARY, ["Assert-InstallationEvidenceProtectedPath"], r'''
. $env:CA_CONTRACT_SOURCE
$script:events=@()
function Write-InstallationEvidenceEvent {param($Payload) $script:events+=,$Payload}
function Assert-BootstrapProtectedRelayPath {param($Path)
 throw [ComponentModel.Win32Exception]::new(5,'synthetic permission failure')
}
try{Assert-InstallationEvidenceProtectedPath 'C:\KMTech\Apps';throw 'accepted'}catch{
 if($_.Exception.Message -notlike '설치 증거 폴더를 사용할 수 없습니다:*'){throw}
 $details=Get-InstallationFailureDetails $_
 if(@($details.exception_chain | Where-Object {$_.win32_error -eq 5 -and $_.message -ceq 'synthetic permission failure'}).Count -ne 1){throw 'original native cause disappeared'}
 if(@($script:events | Where-Object {$_.event -ceq 'CAUGHT_FAILURE'}).Count -ne 1){throw 'original error record was not journaled before replacement'}
}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("scenario", ("empty", "legacy", "target", "reparse", "owner", "shape", "app_failure", "control_failure", "other_failure"))
def test_real_preparation_orders_protection_creation_and_durable_evidence(tmp_path, engine, scenario):
    result = run_functions(tmp_path, LIBRARY, ["New-InstallationProtectedEvidenceRun"], MEMORY_PATHS + r'''
Set-Item -Path function:Write-InstallationEvidenceEvent -Value $script:realEvidenceWriter
function Test-InstallationEvidencePrivileged {return $true}
$script:realStrictPath=${function:Get-StrictFullPath}
$script:realProtectedPath=${function:Assert-InstallationEvidenceProtectedPath}
function Convert-MemoryPath([string]$Path){
 $volume=Join-Path $env:CA_CONTRACT_ROOT 'volume'
 if($Path.Equals($volume,[StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($volume+'\',[StringComparison]::OrdinalIgnoreCase)){return $Path}
 if($Path.StartsWith('C:\')){return (Join-Path $env:CA_CONTRACT_ROOT ('volume\'+$Path.Substring(3)))}
 return $Path
}
function Convert-CodePath([string]$Path){
 $prefix=(Join-Path $env:CA_CONTRACT_ROOT 'volume')+'\'
 if($Path.StartsWith($prefix)){return ('C:\'+$Path.Substring($prefix.Length))}
 return $Path
}
function Get-StrictFullPath {param($Path,$Purpose)
 $full=& $script:realStrictPath $Path $Purpose
 if($Purpose -ceq 'protected installation run'){return (Convert-MemoryPath $full)}
 return $full
}
function Test-BootstrapSamePath {param($Left,$Right) return (Convert-MemoryPath $Left).Equals((Convert-MemoryPath $Right),[StringComparison]::OrdinalIgnoreCase)}
function Assert-InstallationEvidenceProtectedPath {param($Path,[switch]$AllowSupportedPreparation)
 # Only the returned run uses an owned-volume seam; trust is still checked
 # against the real function and in-memory ACLs for its exact C: counterpart.
 & $script:realProtectedPath (Convert-CodePath $Path) -AllowSupportedPreparation:$AllowSupportedPreparation
}
function Get-ChildItem {param($LiteralPath,[switch]$Directory,[switch]$Force)}
function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction)
 if($LiteralPath.StartsWith($env:CA_CONTRACT_ROOT+'\')){return}
 if($LiteralPath -notin @('C:\KMTech','C:\KMTech\Apps')){throw 'unexpected native ACL target'}
 $script:writes+=,$LiteralPath;$script:acls[$LiteralPath]=$AclObject
}
function New-InstallationProtectedDirectory {param($Path,$Sid)
 $code=Convert-CodePath $Path
 if($code -ceq 'C:\KMTech\Apps\Container_Audit'){Assert-InstallationEvidenceProtectedPath $code -AllowSupportedPreparation}
 else{Assert-InstallationEvidenceProtectedPath (Split-Path -Parent $code)}
 if(-not $script:acls.ContainsKey($code)){
  if(($env:CA_PREP_SCENARIO -ceq 'app_failure' -and $code -ceq 'C:\KMTech\Apps\Container_Audit') -or
     ($env:CA_PREP_SCENARIO -ceq 'control_failure' -and $code -ceq 'C:\KMTech\Apps\Container_Audit\update-control')){throw [ComponentModel.Win32Exception]::new(112,'synthetic directory creation failure')}
  # Substitute only native directory/ACL persistence. The real protected ACL
  # constructor runs, and all files are created below this test's owned root.
  $script:acls[$code]=Set-InstallationEvidenceAcl $code $Sid -Directory -PrepareOnly
  $script:created+=,$code
  [void][IO.Directory]::CreateDirectory((Convert-MemoryPath $code))
 }
 Assert-InstallationEvidenceProtectedPath $code
}
function Assert-ProtectedCodeAncestors {param($Path) Assert-BootstrapProtectedRelayPath $Path}
if($env:CA_PREP_SCENARIO -ceq 'other_failure'){
 function Protect-KmtechCodeAncestors {param($CodeParent,[switch]$AdmissionOnly,[switch]$BeforeAppCreation)
  if(-not $AdmissionOnly){throw 'synthetic unclassified preparation failure'}
 }
}
$expected=@{reparse=62;owner=63;shape=61;app_failure=64;control_failure=65;other_failure=66}
$failure=$null;$root=''
try{$root=New-InstallationProtectedEvidenceRun 'S-1-5-21-1-2-3-1000'}catch{$failure=$_}
if($expected.ContainsKey($env:CA_PREP_SCENARIO)){
 if($null -eq $failure -or (Get-InstallationPreparationExitCode $failure) -ne $expected[$env:CA_PREP_SCENARIO]){throw 'preparation failure classification differs'}
 if($env:CA_PREP_SCENARIO -in @('shape','owner','reparse') -and ($script:created.Count -or $script:writes.Count)){throw 'rejected shape changed folders'}
 if($env:CA_PREP_SCENARIO -in @('app_failure','control_failure')){
  if(@((Get-InstallationFailureDetails $failure).exception_chain | Where-Object {$_.win32_error -eq 112}).Count -ne 1){throw 'intermediate native cause disappeared'}
 }
}else{
 if($failure){throw $failure}
 $events=Get-Content -LiteralPath (Join-Path $root 'preparation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
 if($events[0].event -cne 'PREPARATION_START' -or $events[-1].event -cne 'PREPARATION_END'){throw 'preparation boundaries were not immediately durable'}
 $before=@($events | Where-Object {$_.event -ceq 'ANCESTOR_ACL_BEFORE'})
 $after=@($events | Where-Object {$_.event -ceq 'ANCESTOR_ACL_AFTER'})
 if($before.Count -ne 2 -or $after.Count -ne 2 -or -not $after[0].record.before_sddl -or -not $after[0].record.after_sddl){throw 'before/after SDDL missing'}
 $firstCreation=if($env:CA_PREP_SCENARIO -ceq 'empty'){'C:\KMTech\Apps\Container_Audit'}else{'C:\KMTech\Apps\Container_Audit\update-control'}
 if($script:created[0] -cne $firstCreation -or $script:created[-1] -notlike '*\installation-evidence\run-*'){throw 'app/control/run creation order differs'}
 $writeCount=if($env:CA_PREP_SCENARIO -ceq 'target'){0}else{2}
 if($script:writes.Count -ne $writeCount){throw 'B mutation count differs'}
 $second=Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit'
 if($script:writes.Count -ne $writeCount -or @($second.records | Where-Object {$_.changed}).Count){throw 'later B rewrote hardened ancestors'}
 # Opening an existing run must stop buffering so helper capture stays durable.
 $again=New-InstallationProtectedEvidenceRun 'S-1-5-21-1-2-3-1000' $root
 if($again -cne $root -or $null -ne $Script:InstallationPreparationEvents){throw 'existing run left evidence buffering active'}
}
'PASS'
''', engine=engine, values={"CA_PREP_SCENARIO": scenario})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("code", range(61, 67))
def test_parent_journals_pre_run_exit_code_without_privileged_fallback(tmp_path, engine, code):
    result = run_functions(tmp_path, LIBRARY, ["Invoke-InstallationElevationCapture"], MEMORY_PATHS + r'''
$Script:InstallationEvidenceRoot=$env:CA_CONTRACT_ROOT
function Start-Process {param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
 return [pscustomobject]@{Id=4321;ExitCode=[int]$env:CA_PREP_EXIT_CODE}
}
$installer=Join-Path (Split-Path -Parent (Split-Path -Parent $env:CA_CONTRACT_SOURCE)) 'INSTALL_THIS_PC.ps1'
try{[void](Invoke-InstallationElevationCapture $installer @('-File',$installer) 'unused-audit' 'S-1-5-21-1-2-3-1000');throw 'failure accepted'}catch{
 if((Get-InstallationPreparationExitCode $_) -ne [int]$env:CA_PREP_EXIT_CODE -or $_.Exception.Message -notmatch '[가-힣]' -or $_.Exception.Message -match "`r|`n"){throw 'parent lost preparation diagnostic'}
}
$events=@($script:events | Where-Object {$_.event -ceq 'PREPARATION_FAILED'})
if($events.Count -ne 1 -or $events[0].exit_code -ne [int]$env:CA_PREP_EXIT_CODE -or
   -not $events[0].diagnostic_code -or $events[0].original_failure_available -or $script:writes.Count -or $script:created.Count){throw 'parent evidence or fallback contract differs'}
'PASS'
''', engine=engine, values={"CA_PREP_SCENARIO": "legacy", "CA_PREP_EXIT_CODE": str(code)})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("code", range(61, 67))
def test_real_memory_wrapper_returns_pre_run_failure_code(tmp_path, engine, code):
    result = run_functions(tmp_path, LIBRARY, ["Get-InstallationElevationWrapperSource"], r'''
. $env:CA_CONTRACT_SOURCE
$library=Join-Path $env:CA_CONTRACT_ROOT 'library.ps1'
$override=@'
function Initialize-InstallationEvidence {param($BasePath,$OperatorSid,$SensitiveValues)
 $failure=[IO.IOException]::new('synthetic preparation failure')
 $failure.Data['installation_preparation_exit_code']=[int]$env:CA_PREP_EXIT_CODE
 throw $failure
}
'@
[IO.File]::WriteAllText($library,([IO.File]::ReadAllText($env:CA_CONTRACT_SOURCE)+"`n"+$override),[Text.UTF8Encoding]::new($true))
$librarySha=Get-FileSha256 $library
$resultPath=Join-Path $env:CA_CONTRACT_ROOT 'run\result.json';$sid='S-1-5-21-1-2-3-1000';$sensitive=@()
$tokens=$null;$errors=$null
$wrapper=[Management.Automation.Language.Parser]::ParseInput((Get-InstallationElevationWrapperSource),[ref]$tokens,[ref]$errors)
$initializers=@($wrapper.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Extent.Text.Contains('$captureRoot=Initialize-InstallationEvidence')})
if($errors.Count -or $initializers.Count -ne 1){throw 'actual wrapper preparation boundary unavailable'}
# Execute the real wrapper's pinned-library/initialization/catch AST only.
# Its failure exits this ordinary contract child; elevation is never invoked.
Invoke-Expression $initializers[0].Extent.Text
throw 'wrapper continued after failed preparation'
''', engine=engine, values={"CA_PREP_EXIT_CODE": str(code)})
    assert result.returncode == code, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_real_direct_helper_returns_pre_run_failure_code(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1", ["Assert-ProtectedCodeAncestors"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1')
function Test-InstallationEvidencePrivileged {return $true}
function Initialize-InstallationEvidence {param($BasePath,$OperatorSid,$SensitiveValues)
 $failure=[ComponentModel.Win32Exception]::new(112,'synthetic app parent failure')
 $failure.Data['installation_preparation_exit_code']=64;throw $failure
}
$DryRun=[switch]$false;$ElevationLogPath='';$OperatorSid='S-1-5-21-1-2-3-1000';$WriterFenceDelegationToken=''
$tokens=$null;$errors=$null
$helper=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$tokens,[ref]$errors)
$initializers=@($helper.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('$helperInstallationEvidenceRoot=Initialize-InstallationEvidence')})
if($errors.Count -or $initializers.Count -ne 1){throw 'actual direct helper preparation boundary unavailable'}
Invoke-Expression $initializers[0].Extent.Text
throw 'helper continued to writer fence after failed preparation'
''', engine=engine)
    assert result.returncode == 64, result.stdout + result.stderr
