"""Exercise finite user capture and in-memory delegation without native launches."""
from pathlib import Path
import re
import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_native_normal_launch_failure_keeps_original_chain_and_final_summary(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$producer=Join-Path $env:CA_CONTRACT_ROOT 'producer';[void][IO.Directory]::CreateDirectory((Join-Path $producer 'tools'))
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1') -Destination (Join-Path $producer 'tools\bootstrap_integrity.ps1')
function Get-BootstrapRelaySecurity {return [pscustomobject]@{sid=$sid;session_id=1;elevated=$true;integrity_level=12288}}
function Import-BootstrapCanonicalUserProcessApi {}
function Start-BootstrapNormalProducerWrapper {$failure=[ComponentModel.Win32Exception]::new(5);$failure.Data['canonical_api']='CreateProcessWithTokenW';throw $failure}
$failed=$false;try{[void](Invoke-BootstrapNormalFiniteProducer $producer 'inert.exe' @('inert.py') (Join-Path $env:CA_CONTRACT_ROOT 'failure'))}catch{$failed=$true}
if(-not $failed){throw 'native failure was swallowed'}
$events=@(Get-Content -LiteralPath (Join-Path $Script:InstallationEvidenceRoot 'stages.jsonl')|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.event -ceq 'CAUGHT_FAILURE'})
if($events.Count -ne 1 -or @($events[0].failure.exception_chain|Where-Object {$_.win32_error -eq 5}).Count -ne 1){throw 'native finite producer failure chain was lost'}
if(-not(Test-Path -LiteralPath (Join-Path $Script:InstallationEvidenceRoot 'evidence-status.json'))){throw 'failed finite producer final summary was lost'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_ordinary_caller_finite_capture_is_durable_without_outer_journal(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Get-BootstrapRelaySecurity {return [pscustomobject]@{sid=$sid;session_id=1;elevated=$false;integrity_level=8192}}
$target=Join-Path $env:CA_CONTRACT_ROOT 'harmless.ps1';[IO.File]::WriteAllText($target,"Write-Output 'finite ordinary fixture'; exit 0",[Text.UTF8Encoding]::new($true))
$winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$result=Invoke-BootstrapNormalFiniteProducer $env:CA_CONTRACT_ROOT $winps @('-NoLogo','-NoProfile','-NonInteractive','-File',$target) (Join-Path $env:CA_CONTRACT_ROOT 'capture')
if($result.ExitCode -ne 0 -or -not(Test-Path -LiteralPath ([string]$result.Streams.stdout.path) -PathType Leaf) -or
 $result.EvidenceSummary.status -cne 'COMPLETE'){throw 'ordinary finite capture has no durable private journal/streams'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_normal_user_api_import_requires_actual_installer_byte_pin(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$producer=Join-Path $env:CA_CONTRACT_ROOT 'api-producer';[void][IO.Directory]::CreateDirectory($producer)
$path=Join-Path $producer 'INSTALL_CANONICAL_PORTABLE.ps1';Copy-Item -LiteralPath $env:CA_CONTRACT_SOURCE -Destination $path
$manifest=Join-Path $producer 'portable-manifest.json'
[IO.File]::WriteAllText($manifest,(@{installer_sha256=(Get-FileSha256 $path)}|ConvertTo-Json))
Import-BootstrapCanonicalUserProcessApi $producer
if($null -eq [ContainerAuditCanonicalUserProcess].GetMethod('StartLimitedWithOverrides')){throw 'real verified native API was not compiled'}
[IO.File]::AppendAllText($path,"`n# synthetic byte drift`n")
$rejected=$false;try{Import-BootstrapCanonicalUserProcessApi $producer}catch{$rejected=$_.Exception.Message.Contains('byte pin differs')}
if(-not $rejected){throw 'changed native source reused previously compiled API'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_normal_producer_environment_overrides_are_exact_and_in_memory(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Initialize-CanonicalUserProcessApi"], r'''
Initialize-CanonicalUserProcessApi
$method=[ContainerAuditCanonicalUserProcess].GetMethod('OverrideEnvironment',[Reflection.BindingFlags]'Static,NonPublic')
$source=[Runtime.InteropServices.Marshal]::StringToHGlobalUni("=C:=C:\fixture`0KEEP=kept`0CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=old-synthetic`0`0")
$output=[IntPtr]::Zero
try{
 $names=[string[]]@('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','CONTAINER_AUDIT_DATA_ROOT')
 $values=[string[]]@('new-synthetic','C:\isolated-data')
 $output=$method.Invoke($null,[object[]]@($source,$names,$values))
 $entries=@();$offset=0
 while($true){$entry=[Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]::Add($output,$offset*2));if(-not $entry){break};$entries+=$entry;$offset+=$entry.Length+1}
 if($entries.Count -ne 4 -or $entries -cnotcontains '=C:=C:\fixture' -or $entries -cnotcontains 'KEEP=kept' -or
  $entries -cnotcontains 'CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=new-synthetic' -or $entries -cnotcontains 'CONTAINER_AUDIT_DATA_ROOT=C:\isolated-data') {throw 'synthetic block override lost unrelated entries'}
 foreach($case in @('unknown','duplicate','nul','shape')){
  $names=[string[]]@('CONTAINER_AUDIT_DATA_ROOT');$values=[string[]]@('value')
  if($case -ceq 'unknown'){$names=[string[]]@('UNSUPPORTED_NAME')}
  if($case -ceq 'duplicate'){$names=[string[]]@('CONTAINER_AUDIT_DATA_ROOT','CONTAINER_AUDIT_DATA_ROOT');$values=[string[]]@('a','b')}
  if($case -ceq 'nul'){$values=[string[]]@("bad`0value")}
  if($case -ceq 'shape'){$values=[string[]]@()}
  $rejected=$false;try{[void]$method.Invoke($null,[object[]]@($source,$names,$values))}catch{$rejected=$true}
  if(-not $rejected){throw 'unsupported environment override accepted'}
 }
}finally{if($output -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($output)};[Runtime.InteropServices.Marshal]::FreeHGlobal($source)}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("legacy", "managed", "missing_auto_source", "child_failed"))
def test_real_lifecycle_adapter_dispatch_and_conditional_delegation(tmp_path, engine, case):
    adapter = ROOT / "tools/container_writer_session.ps1"
    names = re.findall(r"^function\s+([^\s(]+)", adapter.read_text(encoding="utf-8-sig"), re.M)
    result = run_functions(tmp_path, adapter, names, r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'bootstrap_integrity.ps1')
$text=[IO.File]::ReadAllText($env:CA_CONTRACT_SOURCE)
$initialization=[regex]::Match($text,'(?ms)^\$Script:LifecycleDelegatedWriterSources\s*=\s*@\(.*?^\)')
if(-not $initialization.Success){throw 'actual delegated source initialization missing'}
Invoke-Expression $initialization.Value
$Script:PlainLocalDriveCache=@{}
$producer=Join-Path $env:CA_CONTRACT_ROOT 'failed-new';$root=Join-Path $env:CA_CONTRACT_ROOT 'install\current'
foreach($p in @((Join-Path $producer 'runtime'),(Join-Path $producer 'app'),(Join-Path $root 'app'))){[void][IO.Directory]::CreateDirectory($p)}
foreach($p in @((Join-Path $producer 'runtime\python.exe'),(Join-Path $producer 'app\main.py'))){[IO.File]::WriteAllText($p,'inert fixture')}
if($env:CA_DISPATCH_CASE -cne 'legacy'){[IO.File]::WriteAllText((Join-Path $root 'app\auto-update-settings.json'),'{}')}
$report=Join-Path $env:CA_CONTRACT_ROOT 'audit\restore.json';[void][IO.Directory]::CreateDirectory((Split-Path -Parent $report))
$replacementPath=Join-Path $env:CA_CONTRACT_ROOT 'replacement.json';$transaction=('c'*32)
$replacement=[pscustomobject]@{transaction_id=$transaction;receipt_path=$replacementPath;failed_root=$producer;old=@{};new=@{}}
$script:calls=0;$script:clears=0;$script:delegated=@();$script:contained=0
# All external receipt/tree/fence observations use isolated fixtures. The
# adapter's control flow, tuple lifetime, selection and finite dispatch are real.
function Assert-NoReparseAncestorChain {}
function Open-PinnedReadLock {return [IO.MemoryStream]::new()}
function Read-BoundedJson {return $replacement}
function Test-ReplacementReceiptShape {return $true}
function Test-ContainerRestoredTreesAgainstReceipt {return $true}
function Open-ContainerVerifiedTreeReadLocks {return $null}
function Close-ContainerVerifiedTreeReadLocks {}
function Read-ContainerWriterPublicContract {return @{}}
function Read-ContainerWriterSinkInventory {
 if($env:CA_DISPATCH_CASE -ceq 'missing_auto_source'){return @($Script:LifecycleDelegatedWriterSources)}
 return @($Script:LifecycleDelegatedWriterSources)+@('auto_update_control')
}
function Set-ContainerWriterFenceDelegation {
 param($SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken,$DelegatedSources,$LifetimeSeconds)
 $script:delegated=@($DelegatedSources)
}
function Clear-ContainerWriterFenceDelegation {param($SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken);$script:clears++}
function Register-ContainerSystemMutationAttempt {}
function Invoke-BootstrapNormalFiniteProducer {
 param($VerifiedProducerRoot,$Executable,[string[]]$Arguments,$EvidenceBase)
 $script:calls++
 if($VerifiedProducerRoot -cne $producer -or $Executable -cne (Join-Path $producer 'runtime\python.exe') -or
  $Arguments -cnotcontains '--restore-current-user-lifecycle-after-replacement' -or $Arguments -cnotcontains $report -or
  $EvidenceBase -cne ($report+'.producer')){throw 'verified producer finite dispatch differs'}
 [IO.File]::WriteAllText($report,'{}')
 return [pscustomobject]@{ExitCode=if($env:CA_DISPATCH_CASE -ceq 'child_failed'){1}else{0};Stdout='replacement_lifecycle_restore_status=READY';Stderr='';EvidenceSummary=@{status='COMPLETE'}}
}
function Test-ContainerLifecycleRestoreReceipt {return [pscustomobject]@{status='PASS'}}
function Invoke-ContainerLifecycleFailureContainment {$script:contained++;return [pscustomobject]@{status='PASS'}}
$names=@('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID','CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID','CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID')
$before=@{};foreach($name in $names){$before[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
$result=Invoke-ContainerLifecycleRestoreProduct $producer $root $report ('a'*32) ('b'*32) ([DateTime]::UtcNow.ToString('o')) ('d'*64) $transaction ('e'*64) $replacementPath ('f'*64)
foreach($name in $names){if([Environment]::GetEnvironmentVariable($name,'Process') -cne $before[$name]){throw 'delegation environment was not restored'}}
if($env:CA_DISPATCH_CASE -ceq 'missing_auto_source'){
 if($result.status -cne 'FAIL' -or $script:calls -ne 0 -or $script:clears -ne 0){throw 'unpinned bootstrap delegation reached producer'}
}else{
 if($script:calls -ne 1 -or $script:clears -ne 1){throw 'finite dispatch or delegation cleanup missed'}
 if(($script:delegated -ccontains 'auto_update_control') -ne ($env:CA_DISPATCH_CASE -cne 'legacy')){throw 'bootstrap delegation was broadened without actual bootstrap restore'}
 if($env:CA_DISPATCH_CASE -ceq 'child_failed'){
  if($result.status -cne 'FAIL' -or $result.child_exit_code -ne 1 -or $script:contained -ne 1){throw 'finite producer failure did not contain'}
 }elseif($result.status -cne 'PASS'){throw 'valid finite producer rejected'}
}
'PASS'
''', values={"CA_DISPATCH_CASE": case}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_highest_adapter_uses_real_finite_wrapper_at_mocked_token_boundary(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$fixture=Join-Path $env:CA_CONTRACT_ROOT 'verified-producer';[void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tools'))
$library=Join-Path $fixture 'tools\bootstrap_integrity.ps1'
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1') -Destination $library
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# Replace only native security observation in the isolated child library. No
# native token launch or actual product action occurs in this host regression.
$override="`nfunction Get-BootstrapRelaySecurity {return [pscustomobject]@{sid='$sid';session_id=1;elevated=`$false;integrity_level=8192}}`n"
[IO.File]::AppendAllText($library,$override,[Text.UTF8Encoding]::new($false))
$target=Join-Path $fixture 'harmless.ps1'
[IO.File]::WriteAllText($target,"Write-Output 'replacement_lifecycle_restore_status=READY'; exit 0",[Text.UTF8Encoding]::new($true))
function Get-BootstrapRelaySecurity {return [pscustomobject]@{sid=$sid;session_id=1;elevated=$true;integrity_level=12288}}
function Import-BootstrapCanonicalUserProcessApi([string]$Root){if($Root -cne $fixture){throw 'wrong verified producer'}}
function Start-BootstrapNormalProducerWrapper {
 param([string]$Line,$Caller,[string[]]$EnvironmentNames,[string[]]$EnvironmentValues)
 if($EnvironmentNames.Count -ne 5 -or $EnvironmentValues.Count -ne 5 -or $Caller.sid -cne $sid){throw 'ordinary launch delegation shape differs'}
 $parts=@([regex]::Matches($Line,'"([^"\r\n]*)"|([^\s]+)')|ForEach-Object {if($_.Groups[1].Success){$_.Groups[1].Value}else{$_.Groups[2].Value}})
 & $parts[0] @($parts|Select-Object -Skip 1) | Out-Null
 $paths=@(Get-ChildItem -LiteralPath $env:CA_CONTRACT_ROOT -Filter '*.normal-producer-result.*.json' -Recurse -File)
 if($paths.Count -ne 1){throw 'missing isolated finite result'}
 $record=Get-Content -LiteralPath $paths[0].FullName -Raw -Encoding UTF8|ConvertFrom-Json
 return [int]$record.wrapper_process_id
}
$winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$child=Invoke-BootstrapNormalFiniteProducer $fixture $winps @('-NoLogo','-NoProfile','-NonInteractive','-File',$target) (Join-Path $env:CA_CONTRACT_ROOT 'restore')
if($child.ExitCode -ne 0 -or $child.ProcessId -le 0 -or $child.Stdout -notmatch 'replacement_lifecycle_restore_status=READY' -or
 $child.EvidenceSummary.status -cne 'COMPLETE' -or -not $child.Streams.stdout.complete){throw 'finite normal producer proof missing'}
$record=Get-Content -LiteralPath $child.NormalProducerResultPath -Raw -Encoding UTF8|ConvertFrom-Json
if($record.wrapper_process_id -eq $record.producer_process_id -or $record.security.elevated -or $record.security.integrity_level -ne 8192){throw 'native-boundary proof or child identity collapsed'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_normal_wrapper_refuses_high_token_before_any_operator_evidence_write(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$fixture=Join-Path $env:CA_CONTRACT_ROOT 'bad-token';[void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tools'))
$library=Join-Path $fixture 'tools\bootstrap_integrity.ps1'
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1') -Destination $library
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$override="`nfunction Get-BootstrapRelaySecurity {return [pscustomobject]@{sid='$sid';session_id=1;elevated=`$true;integrity_level=12288}}`n"
[IO.File]::AppendAllText($library,$override,[Text.UTF8Encoding]::new($false))
$resultPath=Join-Path $fixture 'ordinary-result.json'
$winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$encoded=ConvertTo-InstallationMemoryCommand (Get-InstallationNormalProducerWrapperSource) @($library,(Get-FileSha256 $library),$resultPath,[string]$PID,$sid,$winps,'-NoProfile','-Command','exit 0')
$child=Invoke-InstallationEvidenceChild 'bad-token' $winps @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded)
if($child.ExitCode -eq 0 -or $child.Stderr -notlike '*not the ordinary operator*'){throw 'wrong token reached finite producer'}
if((Test-Path -LiteralPath $resultPath) -or @(Get-ChildItem -LiteralPath $fixture -Directory -Filter 'normal-producer-capture*').Count){throw 'wrong token wrote operator evidence'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
