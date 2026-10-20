"""Recover an interrupted machine fence through the actual product helpers."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"
FUNCTIONS = [
    "Full", "Same", "Sha", "Test-ExactPropertySet", "Test-ExactStringProperties",
    "ConvertTo-CanonicalAuditJson", "Save",
    "Get-CanonicalMachineArtifactPreimage", "Restore-CanonicalMachineArtifacts",
    "ConvertTo-CanonicalMachineArtifactJournal", "ConvertFrom-CanonicalMachineArtifactJournal",
    "New-CanonicalWriterFencePreparedReceipt", "New-CanonicalWriterFenceReleaseAuthorization",
    "Test-CanonicalMachineCodePrestate", "Save-CanonicalMachineFailureAudit",
    "Restore-CanonicalMachineInstallationPrestate", "Read-CanonicalMachineInstallationRecovery",
    "Invoke-CanonicalMachineInstallationRecovery", "Get-CanonicalMachinePlacementArguments",
    "Write-CanonicalMachinePublicRecord", "Get-CanonicalMachineRecoveryEntry",
]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case, expected", (
    ("preparing_absent", "PASS"),
    ("failed_unproved_absent", "PASS"),
    ("preparing_reused", "PASS"),
    ("failed_exited", "PASS"),
    ("preparing_not_started", "PASS"),
    ("preparing_live", "MACHINE_RECOVERY_CHILD_ACTIVE"),
    ("compensation_live", "MACHINE_RECOVERY_CHILD_ACTIVE"),
    ("unrecorded", "PASS"),
    ("unrecorded_live_run", "MACHINE_RECOVERY_CHILD_UNRECORDED"),
    ("grandchild_live_run", "MACHINE_RECOVERY_CHILD_ACTIVE"),
    ("not_started_live_run", "MACHINE_RECOVERY_CHILD_ACTIVE"),
    ("authority_abandoned", "PASS"),
    ("recovery_process_only", "PASS"),
    ("quoted_live_run", "MACHINE_RECOVERY_CHILD_ACTIVE"),
    ("invalid_identity", "MACHINE_RECOVERY_CHILD_IDENTITY_INVALID"),
    ("missing_creation", "MACHINE_RECOVERY_CHILD_IDENTITY_INVALID"),
    ("compensation_unrecorded", "PASS"),
    ("observation_failure", "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN"),
    ("authority_busy", "CONTAINER_WRITER_SESSION_AUTHORITY_ALREADY_EXISTS"),
    ("unaccepted_status", "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS"),
))
def test_interrupted_recovery_proves_children_before_mutation(tmp_path, engine, case, expected):
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, r'''
# Only protected-file ACL checks use an owned test boundary. All recovery,
# tuple/hash checks, compensation, authority and fence operations are original.
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\container_writer_fence.ps1')
$Script:ContainerWriterFenceAdmissionMutexName+='.'+[Guid]::NewGuid().ToString('N')
function Assert-InstallationEvidenceProtectedPath {param($Path) if(-not (Test-Path -LiteralPath $Path)){throw 'test protected path absent'}}
function Set-InstallationEvidenceAcl {param($Path,$OperatorSid)}
# Literal original blocks keep PSCommandPath bound to an actual file. Loading
# them with Invoke-Expression would erase the orchestrator file context.
$actualHelpers=Join-Path $env:CA_CONTRACT_ROOT 'recovery-helpers.ps1'
$blocks=@($definition_nodes|Where-Object {$_.Name -cin $env:CA_CONTRACT_NAMES.Split(',') -or $_.Name -ceq 'Confirm-CanonicalMachineRecoveryChildExit'}|ForEach-Object {$_.Extent.Text})
[IO.File]::WriteAllText($actualHelpers,($blocks -join [Environment]::NewLine),[Text.UTF8Encoding]::new($true))
. $actualHelpers
$testMode=$true;$EvidencePath=''
$state=Get-ContainerMachineInstallStateRoot
$control=Join-Path $state 'control\writer-session'
$source=Join-Path $env:CA_CONTRACT_ROOT 'source'
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
[void][IO.Directory]::CreateDirectory($source)
[void][IO.Directory]::CreateDirectory((Join-Path $state 'install-audit'))
[IO.File]::WriteAllText((Join-Path $source 'portable-manifest.json'),'{}')
$worker=[pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;profile_root=$env:CA_CONTRACT_ROOT;same_caller=$false}
$Script:CanonicalWriterFenceSessionId=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceAttemptId=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceTransactionId=[Guid]::NewGuid().ToString('N')
$run=$Script:CanonicalWriterFenceTransactionId
$orchestrator=Sha $actualHelpers
$manifest=@{writer_session_contract_sha256=Sha $env:CA_CONTRACT_SOURCE;writer_fence_helper_sha256=Sha $env:CA_CONTRACT_SOURCE}
$tuple=@{SessionId=$Script:CanonicalWriterFenceSessionId;AttemptId=$Script:CanonicalWriterFenceAttemptId;
 OrchestratorSha256=$orchestrator;ReplacementTransactionId=$run;WriterContractSha256=$manifest.writer_session_contract_sha256;ObserverSid=''}
$started=[DateTime]::UtcNow.ToString('o')
$prepared=New-CanonicalWriterFencePreparedReceipt (Join-Path $state 'install-audit\prepared.json') `
 $tuple.SessionId $tuple.AttemptId $run $started $orchestrator $tuple.WriterContractSha256 `
 (Sha (Join-Path $source 'portable-manifest.json')) $worker.sid (Join-Path $worker.profile_root 'AppData\Local')
$pending=Join-Path $state 'pending-onboarding.json'
[IO.File]::WriteAllText($pending,'original pending publication')
$pendingSha=Sha $pending
$before=Get-CanonicalMachineArtifactPreimage @($pending)
[IO.File]::WriteAllText($pending,'interrupted publication')
$interruptedSha=Sha $pending
$prestate=[ordered]@{schema='container-audit-machine-install-prestate-v1';run_id=$run;install_root=$root;
 worker_sid=$worker.sid;profile_root=$worker.profile_root;source_manifest_sha256=Sha (Join-Path $source 'portable-manifest.json');
 before_manifest_sha256='';artifact_before=@(ConvertTo-CanonicalMachineArtifactJournal $before);startup_before=@();
 worker_preparation=$null;worker_run_before=$null;session_id=$tuple.SessionId;attempt_id=$tuple.AttemptId;
 orchestrator_sha256=$orchestrator;prepared_receipt=$prepared;secret_values_recorded=$false}
$journal=Join-Path $state ('install-audit\machine-prestate-'+$run+'\prestate.json')
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $journal))
Write-Utf8Json $journal $prestate
$absentId=[int]::MaxValue
if(@(Get-Process|Where-Object {$_.Id -eq $absentId}).Count){throw 'absent PID fixture is occupied'}
$audit=[ordered]@{schema='container-audit-canonical-portable-install-v2';operation='INSTALL';status='MACHINE_PREPARING';
 run_id=$run;install_root=$root;worker_sid=$worker.sid;source_manifest_sha256=$prestate.source_manifest_sha256;
 machine_prestate=@{path=$journal;sha256=Sha $journal};code_replacement=@{receipt_path=''};
 placement_child=@{status='EXIT_UNPROVEN';process_id=$absentId;started_at_utc=$started};compensation_child=@{status='NOT_STARTED'}}
switch($env:CA_RECOVERY_CASE){
 'failed_unproved_absent' {$audit.status='MACHINE_INSTALL_FAILED'}
 'failed_exited' {$audit.status='MACHINE_INSTALL_FAILED';$audit.placement_child=@{status='EXITED';exit_code=1}}
 'preparing_not_started' {$audit.placement_child=@{status='NOT_STARTED'}}
 'preparing_live' {$audit.placement_child.process_id=$PID;$audit.placement_child.started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')}
 'preparing_reused' {$audit.placement_child.process_id=$PID;$audit.placement_child.started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().AddTicks(-1).ToString('o')}
 'compensation_live' {$audit.compensation_child=@{status='EXIT_UNPROVEN';process_id=$PID;started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')}}
 'unrecorded' {$audit.placement_child.Remove('process_id');$audit.placement_child.Remove('started_at_utc')}
 'unrecorded_live_run' {$audit.placement_child.Remove('process_id');$audit.placement_child.Remove('started_at_utc')}
 'not_started_live_run' {$audit.placement_child=@{status='NOT_STARTED'}}
 'invalid_identity' {$audit.placement_child.started_at_utc='not a creation time'}
 'missing_creation' {$audit.placement_child.Remove('started_at_utc')}
 'compensation_unrecorded' {$audit.compensation_child=@{status='EXIT_UNPROVEN'}}
 'unaccepted_status' {$audit.status='PASS_MACHINE_WORKER_PENDING'}
}
$auditPath=Join-Path $state ('install-audit\canonical-portable-'+$run+'.json')
Save $auditPath $audit
$auditSha=Sha $auditPath
$lease=Enter-ContainerWriterSessionAuthority @tuple
[void](Start-ContainerWriterFence -ControlRoot $control -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
 -SessionId $tuple.SessionId -AttemptId $tuple.AttemptId -ReplacementTransactionId $run -SessionStartedAtUtc $started `
 -OrchestratorSha256 $orchestrator -WriterContractSha256 $tuple.WriterContractSha256 `
 -PreparedReceiptPath $prepared.path -PreparedReceiptSha256 $prepared.sha256 -AuthorityLease $lease)
$fencePath=Get-ContainerWriterFenceActivePath $control
$fenceSha=Sha $fencePath
Exit-ContainerWriterSessionAuthority $lease
$lease=$null;$holder=$null
if($env:CA_RECOVERY_CASE -cin @('authority_busy','authority_abandoned')){
 Add-Type -TypeDefinition @'
using System; using System.Threading;
public sealed class RecoveryAuthorityHolder : IDisposable {
 readonly ManualResetEvent ready=new ManualResetEvent(false), done=new ManualResetEvent(false);
 readonly Thread thread; readonly Mutex mutex;
 public RecoveryAuthorityHolder(string name,bool abandon) { mutex=new Mutex(false,name);thread=new Thread(()=>{mutex.WaitOne();ready.Set();if(!abandon){done.WaitOne();mutex.ReleaseMutex();}});thread.Start();ready.WaitOne();if(abandon){thread.Join();} }
 public void Dispose() {done.Set();thread.Join();mutex.Dispose();ready.Dispose();done.Dispose();}
}
'@
 $holder=[RecoveryAuthorityHolder]::new((Read-ContainerWriterFence $control).session_authority_mutex_name,($env:CA_RECOVERY_CASE -ceq 'authority_abandoned'))
}
$Script:RecoveryProcessReads=0
function Get-CimInstance {
 param($ClassName,$Property,$OperationTimeoutSec,$ErrorAction)
 $Script:RecoveryProcessReads++
 if($ClassName -cne 'Win32_Process' -or $OperationTimeoutSec -ne 5){throw 'PROCESS_QUERY_NOT_BOUNDED'}
 if($env:CA_RECOVERY_CASE -ceq 'observation_failure'){throw [UnauthorizedAccessException]::new('owned process observation denied')}
 if($env:CA_RECOVERY_CASE -cin @('unrecorded_live_run','grandchild_live_run','not_started_live_run')){
  return [pscustomobject]@{ProcessId=$PID;CommandLine=('-WriterFenceReplacementTransactionId '+$run)}
 }
 if($env:CA_RECOVERY_CASE -ceq 'recovery_process_only'){
  return [pscustomobject]@{ProcessId=$PID;CommandLine=('-RecoverMachineInstallation -MachineRecoveryAuditPath canonical-portable-'+$run+'.json')}
 }
 if($env:CA_RECOVERY_CASE -ceq 'quoted_live_run'){
  return [pscustomobject]@{ProcessId=$PID;CommandLine=('"-WriterFenceReplacementTransactionId" "'+$run+'"')}
 }
 if($env:CA_RECOVERY_CASE -ceq 'preparing_absent'){return @(CimCmdlets\Get-CimInstance @PSBoundParameters)}
}
$observed='PASS'
try{
 $context=Read-CanonicalMachineInstallationRecovery $worker $source $root $manifest $auditPath $auditSha
 $lease=Enter-ContainerWriterSessionAuthority @tuple -RecoverExisting
 Invoke-CanonicalMachineInstallationRecovery $worker $source $root $manifest $context $lease
}catch{$observed=$_.Exception.Message}
finally{Exit-ContainerWriterSessionAuthority $lease;if($null -ne $holder){$holder.Dispose()}}
if($observed -cne $env:CA_RECOVERY_EXPECTED){throw ('recovery outcome differs: '+$observed)}
if($env:CA_RECOVERY_CASE -cnotin @('failed_exited','authority_busy','unaccepted_status') -and $Script:RecoveryProcessReads -ne 1){throw 'PROCESS_QUERY_COUNT_DIFFERS'}
if($observed -ceq 'PASS'){
 if((Test-Path -LiteralPath $fencePath) -or (Sha $pending) -cne $pendingSha){throw 'recovery did not restore and release'}
 $saved=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-ContainerWriterFenceJson
 if($saved.fence_retained -or $saved.compensation.child_exit -cne 'PASS' -or $saved.compensation.code_restore -cne 'PASS'){throw 'recovery compensation proof differs'}
 $lease=Enter-ContainerWriterSessionAuthority @tuple
 Exit-ContainerWriterSessionAuthority $lease
}else{
 if((Sha $fencePath) -cne $fenceSha -or (Sha $pending) -cne $interruptedSha -or (Sha $auditPath) -cne $auditSha){throw 'refused recovery mutated original state'}
}
'RECOVERY_CONTRACT_PASS'
''', engine=engine, values={"CA_RECOVERY_CASE": case, "CA_RECOVERY_EXPECTED": expected})
    (tmp_path / "recovery-stderr.log").write_text(result.stderr, encoding="utf-8")
    assert result.returncode == 0, f"Recovery diagnostic retained in {tmp_path}"
    assert "RECOVERY_CONTRACT_PASS" in result.stdout
    assert "-WriterFenceReplacementTransactionId" not in result.stdout
