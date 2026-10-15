"""Placement boundaries and abandoned rollback, without installer entrypoints."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'INSTALL_THIS_PC.ps1'
LIBRARY = ROOT / 'tools/bootstrap_integrity.ps1'

ABANDONED_FIXTURE = r'''
. $env:CA_FENCE_HELPER
$Script:ContainerWriterFenceAdmissionMutexName='Local\KMTech.ContainerAudit.Sub127.'+[Guid]::NewGuid().ToString('N')
$testMode=$true;$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$lad=Join-Path $env:CA_CONTRACT_ROOT 'profile';$env:LOCALAPPDATA=$lad
$install=Join-Path $env:CA_CONTRACT_ROOT 'app\current';$stop=Join-Path $lad 'KMTech\DirectSync\container_audit\control\container_audit_user_relay.stop.json'
$auditRoot=Join-Path $lad 'KMTech\ContainerAudit\install-audit'
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$controlRoot=Join-Path $lad 'KMTech\DirectSync\container_audit\control\writer-session'
$Script:fixtureControl=Join-Path (Split-Path -Parent $install) 'update-control'
function Get-InstallationEvidenceControlRoot {return $Script:fixtureControl}
function Get-ContainerWriterFenceProfileLocalAppDataRoot {return $lad}
function Assert-BootstrapIntegrityRecord {return @{aggregate_sha256='5d074dab5676b9dd5f2f8ab2a8ad4ddec05c22a3e65b1c4b04d7268335c6517a'}}
function Get-Process {param([int]$Id);if($Id -eq $PID){return [pscustomobject]@{Id=$PID;StartTime=[DateTime]::UtcNow.AddMinutes(-1)}};if($env:CA_REENTRY_CASE -ceq 'live_pid'){return [pscustomobject]@{Id=$PID}};return @()}
function Assert-BootstrapProtectedRelayPath {}
foreach($path in @($install,$auditRoot,$controlRoot,(Split-Path -Parent $stop))){[void][IO.Directory]::CreateDirectory($path)}
[IO.File]::WriteAllText((Join-Path $install 'portable-manifest.json'),'{"schema":"fixture-old-manifest"}')
[IO.File]::WriteAllText((Join-Path $install 'bootstrap-integrity.json'),'{"schema":"fixture-old-integrity"}')
$prior=@{schema='container-audit-canonical-portable-install-v2';operation='INSTALL';source_manifest_sha256=('a'*64);
 preimage=@{exists=$true;kind='String';data=''};code_replacement=@{transaction_id=[Guid]::NewGuid().ToString('N');receipt_path='';receipt_sha256=''};
 scheduled_writer=@{preimage=@{present=$false}}}
$runId='20261003T000000000Z-'+[Guid]::NewGuid().ToString('N');$prior.run_id=$runId
$stage=Join-Path $auditRoot ('canonical-portable-'+$runId+'.json.evidence.'+$PID)
[void][IO.Directory]::CreateDirectory($stage)
[void](Set-InstallationEvidenceAcl $stage $operatorSid -Directory)
[IO.File]::WriteAllText((Join-Path $stage 'stages.jsonl'),'{"event":"INITIALIZED","process_id":2704}')
$prior.install_root=$install;$prior.stop_marker_path=$stop;$prior.stage_evidence_root=$stage
$prior.preimage.data=(ConvertTo-BootstrapRelayArgument (Join-Path $install 'runtime\pythonw.exe'))+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $install 'app\main.py'))+' --container-audit-user-relay'
$priorPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'.json')
[IO.File]::WriteAllText($priorPath,($prior|ConvertTo-Json -Depth 12))
$preparedPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'-writer-prepared.json')
$sid=[Guid]::NewGuid().ToString('N');$attempt=[Guid]::NewGuid().ToString('N');$transaction=[string]$prior.code_replacement.transaction_id
$orchestrator=('e'*64)
$contract=('d'*64);$inventory=$Script:ContainerWriterFenceInventorySha256
$prepared=@{schema='container-audit-canonical-writer-prepared-v1';status='PREPARED';app_id='container_audit';session_id=$sid;attempt_id=$attempt;replacement_transaction_id=$transaction;
 session_started_at_utc='2026-10-02T14:35:01.980Z';orchestrator_sha256=$orchestrator;writer_contract_sha256=$contract;writer_inventory_sha256=$inventory;
 source_manifest_sha256=('a'*64);operator_sid=$operatorSid;operator_local_appdata_root=$lad;created_at_utc='2026-10-02T14:35:01.980Z';secret_values_recorded=$false}
[IO.File]::WriteAllText($preparedPath,($prepared|ConvertTo-Json))
$active=@{schema='container-audit-all-writer-fence-active-v1';status='INSTALLING';app_id='container_audit';session_id=$sid;attempt_id=$attempt;replacement_transaction_id=$transaction;
 session_started_at_utc=$prepared.session_started_at_utc;orchestrator_sha256=$orchestrator;writer_contract_sha256=$contract;writer_inventory_sha256=$inventory;owner_kind='canonical_installer';
 session_authority_mutex_name=(Get-ContainerWriterSessionAuthorityMutexName $sid $attempt $orchestrator $transaction $contract);prepared_receipt_path=$preparedPath;prepared_receipt_sha256=(Get-FileSha256 $preparedPath);
 delegation_sha256=('b'*64);delegated_sources=@('canonical_code_placement');delegation_expires_at_utc='2026-10-02T14:55:01.980Z';activated_at_utc='2026-10-02T14:35:01.980Z';secret_values_recorded=$false}
$activePath=Join-Path $controlRoot 'active.json';[IO.File]::WriteAllText($activePath,($active|ConvertTo-Json))
[IO.File]::WriteAllText($stop,'captured INSTALLING stop-marker shape')
$removalPath=Join-Path $env:CA_CONTRACT_ROOT 'removal.json';[IO.File]::WriteAllText($removalPath,'{"status":"PASS_DATA_PRESERVED"}')
$Script:InstallationEvidenceRoot=$stage;$sourceManifestSha256=('a'*64);$audit=$prior;$before=$prior.preimage;$writerBefore=@{present=$false}
function Assert-InstallationEvidenceWriteRoot {}
function Set-InstallationEvidenceAcl {}
function Write-InstallationEvidenceEvent {}
Write-CanonicalInstallReentryRecord 'PREIMAGE_SAVED'
Write-CanonicalInstallReentryRecord 'RUNTIME_QUIESCED_UNPLACED'
Write-CanonicalInstallReentryRecord 'PLACEMENT_ATTEMPTED'
$Script:fixtureRun=@{exists=$false;kind='';data=''};$Script:fixtureOrder=[Collections.Generic.List[string]]::new()
$Script:fixtureBefore=$prior.preimage
function Snapshot {return $Script:fixtureRun}
function Relays {return @()}
function Restore($Before){$Script:fixtureOrder.Add('Run');$Script:fixtureRun=$Before}
function Test-InstallationEvidencePrivileged {return $true}
function New-InstallationProtectedDirectory {$Script:fixtureOrder.Add('protection')}
function Initialize-InstallationEvidence([string]$Path,[string]$Sid){$Script:InstallationEvidenceRoot=Join-Path $env:CA_CONTRACT_ROOT ('journal-'+[Guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($Script:InstallationEvidenceRoot);return $Script:InstallationEvidenceRoot}
function Write-InstallationEvidenceEvent {}
function Write-InstallationCaughtFailure {}
function Set-InstallationEvidenceStage {}
function Complete-InstallationEvidence {return @{status='COMPLETE'}}
function Assert-RollbackRelayPreimage {}
function Start-CanonicalRelayAfterFenceRelease {
 if((Test-Path -LiteralPath $activePath) -or (Test-Path -LiteralPath $stop) -or $Script:fixtureRun.data -cne $Script:fixtureBefore.data){throw 'relay started before exact recovery'}
 $Script:fixtureOrder.Add('relay-ready');return 999
}
'''


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', ('dead', 'legacy_missing_record', 'live_pid', 'live_mutex', 'tampered_prepared', 'tampered_code', 'tampered_run', 'tampered_record', 'incomplete_removal'))
def test_durable_reentry_recovers_before_install_and_legacy_or_ambiguous_state_refuses(tmp_path, engine, case):
    script = ABANDONED_FIXTURE + r'''
$held=$null
if($env:CA_REENTRY_CASE -ceq 'live_mutex'){$held=Enter-ContainerWriterSessionAuthority -SessionId $sid -AttemptId $attempt -OrchestratorSha256 $orchestrator -ReplacementTransactionId $transaction -WriterContractSha256 $contract}
if($env:CA_REENTRY_CASE -ceq 'tampered_prepared'){[IO.File]::AppendAllText($preparedPath,' ')}
if($env:CA_REENTRY_CASE -ceq 'tampered_code'){[IO.File]::AppendAllText((Join-Path $install 'bootstrap-integrity.json'),' ')}
if($env:CA_REENTRY_CASE -ceq 'tampered_run'){$prior.preimage.data+=' --extra';[IO.File]::WriteAllText($priorPath,($prior|ConvertTo-Json -Depth 12))}
if($env:CA_REENTRY_CASE -ceq 'legacy_missing_record'){Remove-Item -LiteralPath (Join-Path $stage 'reentry-record.json')}
if($env:CA_REENTRY_CASE -in @('tampered_record','incomplete_removal')){
 $rp=Join-Path $stage 'reentry-record.json';$r=Get-Content -LiteralPath $rp -Raw|ConvertFrom-Json
 if($env:CA_REENTRY_CASE -ceq 'tampered_record'){$r.delegation_sha256=('c'*64)}else{$r.removal_completed=$false}
 [IO.File]::WriteAllText($rp,($r|ConvertTo-Json -Depth 10))
}
$beforeActive=Get-FileSha256 $activePath;$beforeStop=Get-FileSha256 $stop
try{
 $failure=$null;try{$result=Resume-CanonicalAbandonedRollback}catch{$failure=$_}
 if($env:CA_REENTRY_CASE -ceq 'dead'){
  if($null -ne $failure){$e=$failure.Exception;while($null -ne $e.InnerException){$e=$e.InnerException};throw $e}
  if($result.status -cne 'PROVEN_OLD_RUNTIME_RESTORED' -or ($Script:fixtureOrder -join ',') -cne 'protection,Run,relay-ready'){throw 'recovery did not precede next install'}
  $recovered=Get-Content -LiteralPath $result.path -Raw|ConvertFrom-Json
  if(-not $recovered.fence_released -or -not $recovered.old_relay_ready -or -not $recovered.steps[1].reused_completed_removal){throw 'recovery evidence incomplete'}
  'PASS'
 }else{
  if($null -eq $failure -or -not $failure.Exception.Message.Contains('이전 설치')){throw 'ambiguous/live state admitted'}
  if($Script:fixtureOrder.Count -ne 0 -or (Get-FileSha256 $activePath) -cne $beforeActive -or (Get-FileSha256 $stop) -cne $beforeStop -or $Script:fixtureRun.exists){throw 'refused state was changed'}
  'PASS'
 }
}finally{if($null -ne $held){Exit-ContainerWriterSessionAuthority $held}}
'''
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
                           ['Restore-CanonicalApplicationProtection', 'Write-CanonicalInstallReentryRecord', 'Resume-CanonicalAbandonedRollback', 'Invoke-CanonicalRollbackRuntimePreimage', 'ConvertTo-CanonicalAuditJson', 'Save', 'Sha'],
                           script, engine=engine, values={'CA_REENTRY_CASE': case, 'CA_FENCE_HELPER': str(ROOT / 'tools/container_writer_fence.ps1')})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_actual_placement_parent_setup_preserves_ntfs_control_and_unknown_items(tmp_path, engine):
    result = run_functions(tmp_path, HELPER, ['Set-HardenedCodeAcl'], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class PlacementFixtureAcl {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 public static extern bool SetFileSecurityW(string path,uint flags,byte[] descriptor);
}
'@
function Restore-OwnFixtureDacl([string]$Path,[string]$Sddl){
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
 $bytes=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($bytes,0)
 if(-not[PlacementFixtureAcl]::SetFileSecurityW($Path,[uint32]2147483652,$bytes)){throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())}
}
$applicationParent=Join-Path 'D:\KMTech\program-improvement-20260912\work\program\w9setupprep\sub-127\ntfs' ([Guid]::NewGuid().ToString('N').Substring(0,8))
[void][IO.Directory]::CreateDirectory($applicationParent)
$acl=Get-Acl -LiteralPath $applicationParent
$acl.SetAccessRuleProtection($true,$true)
Set-Acl -LiteralPath $applicationParent -AclObject $acl
foreach($name in @('current','update-control','update-control\installation-evidence','unknown')){
 $path=Join-Path $applicationParent $name
 [void][IO.Directory]::CreateDirectory($path)
 $childAcl=Get-Acl -LiteralPath $path
 $childAcl.SetAccessRuleProtection($true,$true)
 Set-Acl -LiteralPath $path -AclObject $childAcl
}
$paths=@($applicationParent,(Join-Path $applicationParent 'update-control'),(Join-Path $applicationParent 'update-control\installation-evidence'),(Join-Path $applicationParent 'unknown'))
$before=@{};foreach($path in $paths){$before[$path]=(Get-Acl -LiteralPath $path).Sddl}
function Assert-NoReparsePoint {}
function Assert-HardenedCodeAcl {}
function Assert-InstallationEvidenceProtectedPath([string]$Path){if(-not(Get-Acl -LiteralPath $Path).AreAccessRulesProtected){throw 'parent protection lost'}}
function Write-InstallationCaughtFailure {}
function Invoke-InstallationEvidenceChild([string]$Name,[string]$Executable,[string[]]$Arguments){
 if($Name -ceq 'acl-owner'){return [pscustomobject]@{ExitCode=0}}
 & $Executable @Arguments | Out-Null
 return [pscustomobject]@{ExitCode=$LASTEXITCODE}
}
$applyHardenedAcl=$true
$source=Get-Content -LiteralPath $env:CA_CONTRACT_SOURCE -Raw -Encoding UTF8
$start=$source.IndexOf('New-Item -ItemType Directory -Path $applicationParent -Force | Out-Null')
$end=$source.IndexOf('New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null',$start)
if($start -lt 0 -or $end -lt $start){throw 'actual placement boundary not found'}
try{
 Invoke-Expression $source.Substring($start,$end-$start)
 foreach($path in $paths){if((Get-Acl -LiteralPath $path).Sddl -cne $before[$path]){throw 'placement changed non-code ACL'}}
 $code=Join-Path $applicationParent 'current'
 [IO.File]::WriteAllText((Join-Path $code 'code.txt'),'own code')
 $codeBefore=(Get-Acl -LiteralPath $code).Sddl
 try{
  Set-HardenedCodeAcl $code -Recursive
  if(-not(Get-Acl -LiteralPath $code).AreAccessRulesProtected -or (Get-Acl -LiteralPath $code).Sddl -ceq $codeBefore){throw 'code ACL was not normalized'}
  foreach($path in $paths){if((Get-Acl -LiteralPath $path).Sddl -cne $before[$path]){throw 'code normalization escaped its tree'}}
 }finally{
  Restore-OwnFixtureDacl $code $codeBefore
 }
 [IO.File]::WriteAllText((Join-Path $paths[2] 'append-proof.txt'),'preserved')
 [IO.File]::WriteAllText((Join-Path $applicationParent 'proof.json'),(@{engine=$PSVersionTable.PSVersion.ToString();native_reset=$true;owner_assignment='SEAM';preserved_paths=$paths}|ConvertTo-Json))
 'PASS'
}finally{
 # Only this owned fixture: restore its original DACL for ordinary cleanup.
 Restore-OwnFixtureDacl $applicationParent $before[$applicationParent]
}
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_fallback_line_retains_original_native_cause_in_parent_journal(tmp_path, engine):
    from tests.test_installation_stage_evidence import FUNCTIONS
    result = run_functions(tmp_path, LIBRARY, [*FUNCTIONS, 'Get-InstallationFallbackDiagnostic'], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'parent') $sid @('fixture-value-sentinel')
$native=[ComponentModel.Win32Exception]::new(5,'native reset denied; fixture-value-sentinel')
$failure=[InvalidOperationException]::new('original helper failure',$native)
$Script:InstallationLastChildCapture=@{stage='acl-reset';pid=1234;exit_code=7;stdout='original stdout';stderr='native reset denied'}
$Script:InstallationLastChildEvidenceFailure=Get-InstallationFailureDetails ([InvalidOperationException]::new('evidence denied',$native))
$diagnostic=Get-InstallationFallbackDiagnostic $failure
$json=$diagnostic | ConvertTo-Json -Depth 10 -Compress
if($json.Length -gt 4000 -or $diagnostic.exit_code -ne 71 -or $json.Contains('fixture-value-sentinel')){throw 'fallback bound/table/redaction failed'}
$script=Join-Path $env:CA_CONTRACT_ROOT 'emit.ps1'
$quote=[string][char]39
$emit='[Console]::Out.WriteLine('+$quote+'installation_failure_summary='+$json.Replace($quote,$quote+$quote)+$quote+');exit 71'
[IO.File]::WriteAllText($script,$emit,[Text.UTF8Encoding]::new($true))
$child=Invoke-InstallationEvidenceChild 'placement-helper' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',$script)
$events=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl')|ForEach-Object {$_|ConvertFrom-Json})
$fallback=@($events|Where-Object {$_.event -ceq 'CHILD_FAILURE_FALLBACK'})
if($child.ExitCode -ne 71 -or $fallback.Count -ne 1 -or $fallback[0].diagnostic.child.exit_code -ne 7 -or $fallback[0].diagnostic.failure.exception_chain[-1].win32_error -ne 5){throw 'parent lost original/native failure'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_native_unprotected_parent_repair_preserves_protected_children(tmp_path, engine):
    result = run_functions(tmp_path, LIBRARY,
                           ['New-InstallationProtectedDirectory', 'Set-InstallationEvidenceAcl',
                            'Assert-BootstrapNoReparsePoint', 'Get-StrictFullPath'], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$nativeRoot=if($env:CA_NTFS_TEST_ROOT){$env:CA_NTFS_TEST_ROOT}else{$env:CA_CONTRACT_ROOT}
$fixture=Join-Path $nativeRoot ([Guid]::NewGuid().ToString('N').Substring(0,8))
[void][IO.Directory]::CreateDirectory($fixture)
$original=(Get-Acl -LiteralPath $fixture).Sddl
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class RepairFixtureAcl {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 public static extern bool SetFileSecurityW(string path,uint flags,byte[] descriptor);
}
'@
function Set-FixtureDacl([string]$Path,[string]$Sddl){
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl);$bytes=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($bytes,0)
 if(-not[RepairFixtureAcl]::SetFileSecurityW($Path,[uint32]2147483652,$bytes)){throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())}
}
$app=Join-Path $fixture 'app';$Script:fixtureControl=Join-Path $app 'update-control'
function Get-InstallationEvidenceControlRoot {return $Script:fixtureControl}
function Test-InstallationEvidencePrivileged {return $true}
function Write-InstallationCaughtFailure {}
function Assert-InstallationEvidenceProtectedPath([string]$Path){if(-not(Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path).AreAccessRulesProtected){throw 'native parent remains unprotected'}}
# Only owner admission/assignment are translated for this non-admin host.
# ACL inheritance, exact five native rules, and protection writes remain real.
$setter=${function:Set-InstallationEvidenceAcl}.ToString().Replace("`$owner=if(`$privileged){'S-1-5-32-544'}else{`$Sid}",'$owner=$Sid')
Invoke-Expression ('function Set-InstallationEvidenceAcl {'+$setter+'}')
function Get-Acl([string]$LiteralPath){
 $acl=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $LiteralPath
 if($LiteralPath -ceq $app -and -not $acl.AreAccessRulesProtected){$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))}
 return $acl
}
try{
 Set-FixtureDacl $fixture ('O:'+$sid+'D:P(A;;0x1301bf;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
 [void][IO.Directory]::CreateDirectory($app)
 $beforeApp=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $app
 if($beforeApp.AreAccessRulesProtected){throw 'fixture did not inherit'}
 $children=@((Join-Path $app 'update-control'),(Join-Path $app 'update-control\installation-evidence'),(Join-Path $app 'unknown'))
 $before=@{}
 foreach($path in $children){[void][IO.Directory]::CreateDirectory($path);$acl=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path;$acl.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath $path -AclObject $acl;$before[$path]=(Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path).Sddl}
 New-InstallationProtectedDirectory $app $sid -RecoverAbandoned
 if(-not(Microsoft.PowerShell.Security\Get-Acl -LiteralPath $app).AreAccessRulesProtected){throw 'repair did not protect parent'}
 foreach($path in $children){if((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path).Sddl -cne $before[$path]){throw 'repair changed protected child'}}
 'PASS'
}finally{
 if(Test-Path -LiteralPath $app){Set-FixtureDacl $app $original}
 Set-FixtureDacl $fixture $original
}
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('failed_step', ('none', 'product_removal', 'run_preimage'))
def test_runtime_rollback_attempts_remaining_steps_after_failure(tmp_path, engine, failed_step):
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
                           ['Restore-CanonicalApplicationProtection', 'Invoke-CanonicalRollbackRuntimePreimage', 'Assert-CanonicalRollbackStopCleanup'], r'''
$testMode=$false;$install=Join-Path $env:CA_CONTRACT_ROOT 'app\current';$operatorSid='S-1-5-21-100-100-100-1000'
[void][IO.Directory]::CreateDirectory($install)
$stop=Join-Path $env:CA_CONTRACT_ROOT 'stop.json';[IO.File]::WriteAllText($stop,'owned marker')
$Script:order=[Collections.Generic.List[string]]::new();$Script:restored=$null
function Set-InstallationEvidenceStage {}
function Write-InstallationEvidenceEvent {}
function Write-InstallationCaughtFailure {}
function Test-InstallationEvidencePrivileged {return $true}
function New-InstallationProtectedDirectory {[void]$Script:order.Add('app_protection')}
function Product {[void]$Script:order.Add('product_removal');if($env:CA_FAILED_STEP -ceq 'product_removal'){throw 'original removal failure'}}
function Assert-RollbackRelayPreimage {}
function Restore($Before){[void]$Script:order.Add('run_preimage');if($env:CA_FAILED_STEP -ceq 'run_preimage'){throw 'original Run failure'};$Script:restored=$Before}
function Snapshot {return $Script:restored}
$before=@{exists=$true;kind='String';data='exact original Run'}
$steps=Invoke-CanonicalRollbackRuntimePreimage $before
if(($Script:order -join ',') -cne 'app_protection,product_removal,run_preimage' -or (Test-Path -LiteralPath $stop) -or $steps.Count -ne 4){throw 'remaining rollback steps skipped'}
$failed=@($steps|Where-Object {$_.status -ceq 'FAILED'})
if($env:CA_FAILED_STEP -ceq 'none'){if($failed.Count){throw 'unexpected rollback failure'}}
else{if($failed.Count -ne 1 -or $failed[0].step -cne $env:CA_FAILED_STEP -or -not $failed[0].failure.exception_chain[0].message.Contains('original')){throw 'original rollback failure hidden'}}
'PASS'
''', engine=engine, values={'CA_FAILED_STEP': failed_step})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_evidence_refusal_preserves_native_exit_and_redacted_streams_in_memory(tmp_path, engine):
    from tests.test_installation_stage_evidence import FUNCTIONS
    result = run_functions(tmp_path, LIBRARY, FUNCTIONS, r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'refused') $sid @('fixture-value-sentinel')
function Assert-InstallationEvidenceWriteRoot {throw [InvalidOperationException]::new('protected evidence denied',[ComponentModel.Win32Exception]::new(5))}
$command='[Console]::Out.WriteLine("original child stdout"); [Console]::Error.WriteLine("native reset denied; password=fixture-value-sentinel"); exit 7'
$child=Invoke-InstallationEvidenceChild 'acl-reset' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoLogo','-NoProfile','-NonInteractive','-Command',$command)
if($child.ExitCode -ne 7 -or -not $child.Stdout.Contains('original child stdout') -or -not $child.Stderr.Contains('native reset denied')){throw 'native result was lost'}
if($child.Stderr.Contains('fixture-value-sentinel')){throw 'credential escaped'}
if(-not $Script:InstallationEvidenceFailed -or $null -eq $child.EvidenceFailure){throw 'evidence refusal was hidden'}
if($child.EvidenceFailure.exception_chain[-1].win32_error -ne 5){throw 'inner evidence refusal was lost'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('mode', ('abandoned', 'owned'))
@pytest.mark.parametrize('claim_kind', ('valid', 'missing', 'wrong'))
def test_ordinary_repair_preflight_checks_owned_lease_before_uac(tmp_path, engine, mode, claim_kind):
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1', ['Sha'], r'''
. $env:CA_FENCE_HELPER
$Script:ContainerWriterFenceAdmissionMutexName='Local\KMTech.ContainerAudit.Sub127.'+[Guid]::NewGuid().ToString('N')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Join-Path $env:CA_CONTRACT_ROOT 'private';[void][IO.Directory]::CreateDirectory($root)
$Script:InstallationEvidenceRoot=$root;$Script:preflightControl=Join-Path $root 'control'
function Test-InstallationEvidencePrivileged {return $false}
function Get-InstallationEvidenceControlRoot {return $Script:preflightControl}
$source=Join-Path $root 'source';[void][IO.Directory]::CreateDirectory((Join-Path $source 'tools'))
$target=Join-Path $source 'INSTALL_THIS_PC.ps1';[IO.File]::WriteAllText($target,'param()')
[IO.File]::WriteAllText((Join-Path $source 'tools\bootstrap_integrity.ps1'),'# never executed')
[IO.File]::WriteAllText((Join-Path $source 'portable-manifest.json'),'{}')
$lease=Enter-ContainerWriterSessionAuthority ([Guid]::NewGuid().ToString('N')) ([Guid]::NewGuid().ToString('N')) ('e'*64) ([Guid]::NewGuid().ToString('N')) ('d'*64)
$Script:preflightActive=[pscustomobject]@{session_authority_mutex_name=$lease.name}
function Read-InstallationAbandonedRollback {return [pscustomobject]@{active=$Script:preflightActive}}
function Read-InstallationOwnedParentRepair {return [pscustomobject]@{active=$Script:preflightActive}}
$Script:reachedUac=$false
function Start-Process {$Script:reachedUac=$true;throw 'owned test stops before UAC'}
$flag=if($env:CA_REPAIR_MODE -ceq 'owned'){'-RepairOwnedInstallationParent'}else{'-RepairAbandonedInstallationParent'}
$arguments=@($flag,'-InstallRoot','C:\KMTech\Apps\Container_Audit\current','-OperatorLocalAppDataRoot',$root)
try{
 if(Test-ContainerWriterSessionAuthorityHeldByOther $lease.name){throw 'same-thread fixture is not reentrant'}
 $provided=if($env:CA_CLAIM_KIND -ceq 'missing'){$null}elseif($env:CA_CLAIM_KIND -ceq 'wrong'){@{acquired=$true;name='wrong';mutex=$lease.mutex}}else{$lease}
 $parameters=@{Target=$target;Arguments=$arguments;AuditBase=(Join-Path $root 'audit');OperatorSid=$sid}
 # The old signature cannot accept the owned lease: that is the RED condition.
 if((Get-Command Invoke-InstallationElevationCapture).Parameters.ContainsKey('AuthorityLease')){$parameters.AuthorityLease=$provided}
 $caught=$null;try{[void](Invoke-InstallationElevationCapture @parameters)}catch{$caught=$_}
 if($env:CA_CLAIM_KIND -ceq 'valid' -and -not $Script:reachedUac -and $null -ne $caught){throw $caught}
 if($Script:reachedUac -ne ($env:CA_CLAIM_KIND -ceq 'valid')){throw 'ordinary owned-authority admission differs'}
 'PASS'
}finally{Exit-ContainerWriterSessionAuthority $lease}
''', engine=engine, values={'CA_REPAIR_MODE': mode, 'CA_CLAIM_KIND': claim_kind,
                           'CA_FENCE_HELPER': str(ROOT / 'tools/container_writer_fence.ps1')})
    assert result.returncode == 0, result.stdout + result.stderr
