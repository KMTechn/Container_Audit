"""Source and write boundaries without actual elevation or installer execution."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

SOURCE = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_tls_bootstrap_rejects_reparse_before_creating_output(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE.with_name('INSTALL_THIS_PC.ps1'),
        ['Assert-NoReparsePoint', 'Install-CurrentUserTlsCaBootstrap'], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1')
$source=Join-Path $env:CA_CONTRACT_ROOT 'ca.pem';[IO.File]::WriteAllText($source,'isolated public CA fixture')
$user=Join-Path $env:CA_CONTRACT_ROOT 'user';$sink=Join-Path $env:CA_CONTRACT_ROOT 'sink'
[void][IO.Directory]::CreateDirectory($user);[void][IO.Directory]::CreateDirectory($sink)
[void](New-Item -ItemType Junction -Path (Join-Path $user 'KMTech') -Target $sink)
try{[void](Install-CurrentUserTlsCaBootstrap $source $user);throw 'reparse admitted'}catch{
 if($_.Exception.Message -notlike '*contains a reparse point:*'){throw}
}
if(@(Get-ChildItem -LiteralPath $sink).Count){throw 'created output before ancestor rejection'}
$safe=Join-Path $env:CA_CONTRACT_ROOT 'safe-user';[void][IO.Directory]::CreateDirectory($safe)
$target=Install-CurrentUserTlsCaBootstrap $source $safe
if((Get-FileSha256 $source) -cne (Get-FileSha256 $target)){throw 'TLS configuration bytes changed'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_uninstall_and_restore_keep_active_evidence_at_the_same_path(tmp_path, engine):
    helper = SOURCE.with_name("INSTALL_THIS_PC.ps1")
    atomic_source = tmp_path / "startup-publication.ps1"
    atomic_source.write_text(
        helper.read_text(encoding="utf-8-sig") + "\n"
        + (Path(__file__).resolve().parents[1] / "tools/bootstrap_integrity.ps1").read_text(encoding="utf-8-sig"),
        encoding="utf-8",
    )
    result = run_functions(tmp_path, atomic_source, [
        "Save-ContainerStartupUpdatePreimage", "Restore-ContainerStartupUpdatePreimage",
        "Write-ContainerStartupUpdateRecord", "Invoke-ContainerAtomicReplaceOnce", "Invoke-ContainerAtomicReplace"], r'''
function Assert-ContainerStartupUpdateTrust {param($Root) if(-not $Root.StartsWith($env:CA_CONTRACT_ROOT)){throw 'escaped owned input'}}
function Get-StrictFullPath {param($Path,$Purpose) return [IO.Path]::GetFullPath($Path)}
function Test-PathWithin {param($Child,$Parent) return $Child.StartsWith($Parent+'\',[StringComparison]::OrdinalIgnoreCase)}
function Test-SamePath {param($Left,$Right) return $Left.Equals($Right,[StringComparison]::OrdinalIgnoreCase)}
function Assert-NoReparsePoint {param($Path,$Purpose) if((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'reparse'}}
function Set-HardenedCodeAcl {}
function Get-FileSha256 {param($Path) return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Get-ContainerStartupUpdateTaskPreimage {return [pscustomobject]@{name=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24));exists=$false}}
function Get-ScheduledTask {return $null}
function Invoke-ContainerStartupUpdateTaskMutation {param($Action) & $Action}
$OperatorSid=@('S','1','5','21','111','222','333','1001') -join '-'
$WriterFenceAttemptId='a'*32
$managed=Join-Path $env:CA_CONTRACT_ROOT 'managed';$root=Join-Path $managed 'current'
$control=Join-Path $managed 'update-control'
[void][IO.Directory]::CreateDirectory($root)
[void][IO.Directory]::CreateDirectory((Join-Path $control 'installation-evidence\run'))
$active=Join-Path $control 'installation-evidence\run\stages.jsonl'
[IO.File]::WriteAllText($active,'unique active journal')
$policy=Join-Path $control 'policy.json';[IO.File]::WriteAllText($policy,'unique policy')
$saved=Save-ContainerStartupUpdatePreimage $root 'uninstall'
if(-not(Test-Path -LiteralPath $active) -or [IO.File]::ReadAllText($policy) -cne 'unique policy' -or
    [IO.File]::ReadAllText((Join-Path $saved.path 'policy.json')) -cne 'unique policy'){throw 'removal moved evidence or lost updater preimage'}
[IO.File]::AppendAllText($active,' continues')
[IO.File]::WriteAllText($policy,'candidate policy')
Restore-ContainerStartupUpdatePreimage $root $saved.path $saved.sha256
if([IO.File]::ReadAllText($policy) -cne 'unique policy' -or
    [IO.File]::ReadAllText($active) -cne 'unique active journal continues'){throw 'rollback changed evidence or updater bytes'}
$displaced=@(Get-ChildItem -LiteralPath $saved.path -Filter 'failed-*-policy.json')
if($displaced.Count -ne 1 -or [IO.File]::ReadAllText($displaced[0].FullName) -cne 'candidate policy'){throw 'rollback lost displaced updater bytes'}
try{[void](Save-ContainerStartupUpdatePreimage $root 'uninstall');throw 'collision accepted'}catch{
    if($_.Exception.Message -cne 'STARTUP_UPDATE_PREIMAGE_PATH_INVALID'){throw}
}
if([IO.File]::ReadAllText($policy) -cne 'unique policy' -or
    [IO.File]::ReadAllText($active) -cne 'unique active journal continues'){throw 'collision overwrote current state'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_operator_cannot_replace_elevated_wrapper_before_open(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
function Set-InstallationEvidenceAcl {}
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'update-control')}
function Assert-InstallationEvidenceProtectedPath {param($Path) if(-not $Path.StartsWith($env:CA_CONTRACT_ROOT)){throw 'escaped owned input'}}
$sid='S-1-5-21-111-222-333-1001';$base=Join-Path $env:CA_CONTRACT_ROOT 'audit.jsonl'
$root=Initialize-InstallationEvidence $base $sid
$target=Join-Path $env:CA_CONTRACT_ROOT 'target.ps1';[IO.File]::WriteAllText($target,'exit 0')
[void][IO.Directory]::CreateDirectory((Join-Path $env:CA_CONTRACT_ROOT 'tools'))
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1') -Destination (Join-Path $env:CA_CONTRACT_ROOT 'tools\bootstrap_integrity.ps1')
function ConvertTo-ProcessArgument([string]$Value){if($Value -match '\s'){return '"'+$Value+'"'};return $Value}

$script:boundary=$false
function Start-Process {
 param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
 if($Verb -cne 'RunAs' -or $WindowStyle -cne 'Hidden' -or -not $Wait -or -not $PassThru){throw 'supported elevation boundary changed'}
 if($ArgumentList -match '(?i)(?:^| )-File(?: |$)' -or $ArgumentList -notmatch ' -EncodedCommand ([A-Za-z0-9+/=]+)$'){throw 'mutable wrapper file reached elevated execution'}
 $command=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseInput($command,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'memory wrapper is not executable PowerShell'}
 if(Test-Path -LiteralPath (Join-Path $root 'elevation-capture.ps1')){throw 'persisted elevated wrapper'}
 $script:boundary=$true
 throw 'fixture stops before actual elevation'
}
try{[void](Invoke-InstallationElevationCapture $target @('-NoProfile','-File',$target) $base $sid)}catch{}
if(-not $script:boundary){throw 'memory boundary was not reached'}
if(Test-Path -LiteralPath (Join-Path $root 'replacement-executed.txt')){throw 'operator-controlled wrapper reached the requested elevated executable boundary'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_privileged_evidence_acl_is_admin_owned_operator_read_only(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$Script:InstallationEvidencePrivileged=$true
$sid='S-1-5-21-111-222-333-1001'
function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction) $script:seen=$AclObject}
foreach($directory in @($false,$true)){
 Set-InstallationEvidenceAcl (Join-Path $env:CA_CONTRACT_ROOT 'not-created') $sid -Directory:$directory
 if($script:seen.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or -not $script:seen.AreAccessRulesProtected){throw 'privileged owner/DACL differs'}
 $rules=@($script:seen.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 foreach($rule in $rules){
  $expected=if($rule.IdentityReference.Value -ceq $sid){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
  $withoutSynchronize=-bnot [int64][Security.AccessControl.FileSystemRights]::Synchronize
  if(([int64]$rule.FileSystemRights -band $withoutSynchronize) -ne ([int64]$expected -band $withoutSynchronize)){throw 'operator can modify privileged evidence'}
 }
 if($rules.Count -ne 3){throw 'unexpected evidence ACL principal'}
}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_privileged_run_retention_write_roots_and_untrusted_parent(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$Script:InstallationEvidencePrivileged=$true
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'update-control')}
function Set-InstallationEvidenceAcl {}
function Initialize-InstallationProtectedBase {param($Sid) Assert-InstallationEvidenceProtectedPath (Split-Path -Parent (Get-InstallationEvidenceControlRoot))}
function New-InstallationProtectedDirectory {param($Path,$Sid)
 Assert-InstallationEvidenceProtectedPath (Split-Path -Parent $Path)
 [void][IO.Directory]::CreateDirectory($Path)
 Assert-InstallationEvidenceProtectedPath $Path
}
# The actual native trust reader sees the ordinary owner of this owned tmp.
try{[void](New-InstallationProtectedEvidenceRun 'S-1-5-21-111-222-333-1001');throw 'untrusted parent admitted'}catch{
 if($_.Exception.Message -notlike '설치 증거 폴더를 사용할 수 없습니다:*' -or $_.Exception.Message -match "`r|`n"){throw}
}
if(Test-Path -LiteralPath (Get-InstallationEvidenceControlRoot)){throw 'created under untrusted parent'}
function Assert-BootstrapProtectedRelayPath {param($Path) Assert-BootstrapNoReparsePoint $Path 'owned synthetic protected folder' -PathOnly}
$sid='S-1-5-21-111-222-333-1001';$runs=@()
for($i=0;$i -lt 6;$i++){
 $Script:InstallationProtectedRunRoot=''
 $root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'operator-audit') $sid
 $runs+=@(Split-Path -Parent $root)
 [IO.Directory]::SetCreationTimeUtc($runs[-1],[DateTime]::UtcNow.AddMinutes($i-10))
 $summary=Complete-InstallationEvidence
 if($summary.status -cne 'COMPLETE' -or -not $summary.summary_path.StartsWith($runs[-1]+'\')){throw 'privileged summary escaped protected run'}
}
if(Test-Path -LiteralPath $runs[0]){throw 'old sixth run retained'}
if(@(Get-ChildItem -LiteralPath (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence') -Directory).Count -ne 5){throw 'retention count differs'}
if(Test-Path -LiteralPath ((Join-Path $env:CA_CONTRACT_ROOT 'operator-audit')+'.evidence.'+$PID)){throw 'privileged writer used operator root'}
$Script:InstallationEvidenceRoot=Join-Path $env:CA_CONTRACT_ROOT 'operator'
[void][IO.Directory]::CreateDirectory($Script:InstallationEvidenceRoot)
$summary=Complete-InstallationEvidence
if($summary.status -cne 'INCOMPLETE' -or (Test-Path -LiteralPath $summary.summary_path)){throw 'privileged summary accepted operator write root'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("race", ("library", "helper"))
def test_elevation_wrapper_binds_the_bytes_it_checks(tmp_path, engine, race):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''

$target=Join-Path $env:CA_CONTRACT_ROOT ($env:CA_CONTRACT_RACE+'.ps1')
$original=@'
param([string]$ExpectedPath,[switch]$Chosen)
if(-not $Chosen -or $PSCommandPath -cne $ExpectedPath -or $PSScriptRoot -cne (Split-Path -Parent $ExpectedPath)){throw 'memory filename/parameter metadata lost'}
'original verified bytes'
'@
[IO.File]::WriteAllText($target,$original,[Text.UTF8Encoding]::new($true))
$sha=Get-FileSha256 $target
$shared=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
try{$block=Get-InstallationVerifiedScript $target $sha}finally{$shared.Dispose()}
[IO.File]::WriteAllText($target,"throw 'replacement bytes executed'")
if($env:CA_CONTRACT_RACE -ceq 'library'){$value=. $block -ExpectedPath $target -Chosen}
else{$value=& $block -ExpectedPath $target -Chosen}
if($value -cne 'original verified bytes'){throw 'evaluated bytes differ from checked bytes'}
try{[void](Get-InstallationVerifiedScript $target $sha);throw 'replacement accepted'}catch{if($_.Exception.Message -cne 'Pinned installation source bytes differ.'){throw}}
'PASS'
''', engine=engine, values={"CA_CONTRACT_RACE": race})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_final_summary_never_follows_replaced_evidence_root(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
function Set-InstallationEvidenceAcl {}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'audit') 'S-1-5-21-111-222-333-1001'
$kept=$root+'.preserved';$sink=Join-Path $env:CA_CONTRACT_ROOT 'isolated-sink'
$bound=[IO.Path]::GetFullPath($env:CA_CONTRACT_ROOT)+'\'
foreach($path in @($root,$kept,$sink)){if(-not([IO.Path]::GetFullPath($path).StartsWith($bound,[StringComparison]::OrdinalIgnoreCase))){throw 'probe target escaped own input root'}}
[void][IO.Directory]::CreateDirectory($sink)
Move-Item -LiteralPath $root -Destination $kept
[void](New-Item -ItemType Junction -Path $root -Target $sink)
$summary=Complete-InstallationEvidence
if(Test-Path -LiteralPath (Join-Path $sink 'evidence-status.json') -PathType Leaf){throw 'evidence summary write followed substituted root'}
if($summary.status -ceq 'COMPLETE'){throw 'replaced root was reported complete'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
