"""Failure preservation and interruption contracts for general completion recovery."""
import hashlib
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions
from tests.test_general_completed_release_recovery import DRIVER, FUNCTIONS, INSTALLER


MUTATIONS = r'''
$variant=$env:CA_GENERAL_CASE
$script:ConcurrentWriterBlocked=$false
$payload=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-ContainerWriterFenceJson
$proof=$payload.completed_fence_release
$active=Read-ContainerWriterFence -AllowAbsent
$fixed=Join-Path (Split-Path -Parent $auditPath) ('recovered-release-'+[string]$proof.fence.replacement_transaction_id+'.json')
switch($variant){
 'old_audit'{$payload.PSObject.Properties.Remove('completed_fence_release')}
 'schema'{$proof.schema='UNSUPPORTED'}
 'status'{$payload.status='PASS'}
 'source'{$proof.source_manifest_sha256='a'*64}
 'worker'{$proof.operator_sid='S-1-5-21-1-2-3-9999'}
 'tuple'{$proof.fence.attempt_id=[Guid]::NewGuid().ToString('N')}
 'root'{$proof.install_root=Join-Path $base 'foreign'}
 'owner_missing'{$proof.PSObject.Properties.Remove('owner_process_id')}
 'owner_start_invalid'{$proof.owner_started_at_utc='INVALID'}
 'owner_boolean'{$proof.owner_process_id=$true}
 'inventory'{$proof.fence.writer_inventory_sha256='f'*64}
 'run_changed'{function Snapshot{[pscustomobject]@{exists=$true;kind='String';data='foreign command'}}}
 'writer_changed'{function Get-CanonicalWriterSnapshot($Root){[pscustomobject]@{present=$true;enabled=$true;binding_sha256=('a'*64)}}}
 'stop_present'{[void][IO.Directory]::CreateDirectory((Split-Path -Parent $stop));[IO.File]::WriteAllText($stop,'preserve this stop')}
 'manifest_changed'{[IO.File]::AppendAllText((Join-Path $install 'portable-manifest.json'),' ')}
 'bootstrap_changed'{[IO.File]::AppendAllText((Join-Path $install 'bootstrap-integrity.json'),' ')}
 'prepared_changed'{[IO.File]::AppendAllText([string]$proof.fence.prepared_receipt_path,' ')}
 'foreign_fence'{$active.owner_kind='foreign_owner';Save $activePath $active}
 'authorization_corrupt'{[IO.File]::AppendAllText([string]$active.prepared_receipt_path,' ')}
 'authorization_missing'{Remove-Item -LiteralPath ([string]$active.prepared_receipt_path) -ErrorAction Stop}
 'result_proof'{$proof.result.current_exists=-not $proof.result.current_exists}
 'pending_followups'{$proof.pending_followups=@('COMPLETE')}
 'not_proven'{$payload.rollback.steps[0].status='FAILED'}
 'handover_changed'{[IO.File]::AppendAllText([string]$proof.protected_handover_path,' ')}
 'child_alive'{function Get-CimInstance{param($ClassName,$Property,$ErrorAction);[pscustomobject]@{ProcessId=1;CommandLine=$proof.fence.replacement_transaction_id}}}
 'child_unknown'{function Get-CimInstance{param($ClassName,$Property,$ErrorAction);throw 'PROCESS_OBSERVATION_UNKNOWN'}}
 'acl_unprotected'{$acl=Get-Acl -LiteralPath $payload.stage_evidence_root;$acl.SetAccessRuleProtection($false,$true);Set-Acl -LiteralPath $payload.stage_evidence_root -AclObject $acl}
 'acl_foreign_allow'{$acl=Get-Acl -LiteralPath $payload.stage_evidence_root;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $payload.stage_evidence_root -AclObject $acl}
}
if($variant -in @('owner_alive','owner_unknown','owner_reused','helper_alive','helper_unknown')){
    if($variant -like 'helper_*'){
        $proof.helper_process_id=43210
        $handover=Get-Content -LiteralPath $proof.protected_handover_path -Raw|ConvertFrom-ContainerWriterFenceJson
        $handover.helper_process_id=43210
        Save $proof.protected_handover_path $handover
        $proof.protected_handover_sha256=Sha $proof.protected_handover_path
    }
    Add-Type -TypeDefinition @'
using System;
public static class KMTechInstallationChildCapture {
 public static string Started;
 public static bool Unknown;
 public static int ObservedId;
 public static string ReadProcessStartTimeUtc(int id) {
  if(id!=ObservedId)return "";
  if(Unknown)throw new System.IO.IOException("observation unavailable");
  return Started;
 }
}
'@
    [KMTechInstallationChildCapture]::ObservedId=if($variant -like 'helper_*'){43210}else{[int]$proof.owner_process_id}
    [KMTechInstallationChildCapture]::Unknown=$variant -like '*unknown'
    [KMTechInstallationChildCapture]::Started=if($variant -like 'helper_*'){[string]$proof.helper_started_at_utc}else{[string]$proof.owner_started_at_utc}
    if($variant -ceq 'owner_reused'){[KMTechInstallationChildCapture]::Started=([DateTime]$proof.owner_started_at_utc).ToUniversalTime().AddDays(1).ToString('o')}
}
if($variant -in @('audit_during_read','fence_during_read','current_during_read','writer_contends')){
    $originalResult=(Get-Command Assert-CanonicalCompletedFenceResult).Definition
    $script:ResultCalls=0;$script:ConcurrentWriterBlocked=$false
    if($variant -ceq 'writer_contends'){
        Add-Type -TypeDefinition @'
using System;using System.Threading;using System.Threading.Tasks;
public static class GeneralWriterProbe {
 public static bool Blocked(string name){return Task.Factory.StartNew(()=>{
  using(Mutex m=Mutex.OpenExisting(name)){bool got;
   try{got=m.WaitOne(0);}catch(AbandonedMutexException){got=true;}
   if(got)m.ReleaseMutex();return !got;
  }
 }).Result;}
}
'@
    }
    function Assert-CanonicalCompletedFenceResult($Proof,$Audit,$Manifest){
        & ([scriptblock]::Create($originalResult)) $Proof $Audit $Manifest
        $script:ResultCalls++
        if(($script:ResultCalls -eq 1 -and $variant -cne 'fence_during_read') -or ($script:ResultCalls -eq 2 -and $variant -ceq 'fence_during_read')){
            switch($variant){
                'audit_during_read'{[IO.File]::AppendAllText($auditPath,' ')}
                'current_during_read'{[IO.File]::AppendAllText((Join-Path $install 'portable-manifest.json'),' ')}
                'fence_during_read'{[IO.File]::AppendAllText($activePath,' ')}
                'writer_contends'{$script:ConcurrentWriterBlocked=[GeneralWriterProbe]::Blocked((Get-ContainerWriterAdmissionMutexName))}
            }
        }
    }
}
if($variant -ceq 'interrupt_authorization'){
    $originalCreate=(Get-Command New-CanonicalCompletedFenceAuthorization).Definition
    function New-CanonicalCompletedFenceAuthorization($Path,$Proof,$AuditPath,$AuditSha256,$Phase){
        [void](& ([scriptblock]::Create($originalCreate)) $Path $Proof $AuditPath $AuditSha256 $Phase)
        exit 74
    }
}
if($variant -ceq 'interrupt_prepared'){
    $originalPrepare=(Get-Command Set-ContainerWriterFencePrepared).Definition
    function Set-ContainerWriterFencePrepared{
        param($SessionId,$AttemptId,$ReplacementTransactionId,$PreparedReceiptPath,$PreparedReceiptSha256,$Status,$AuthorityLease)
        [void](& ([scriptblock]::Create($originalPrepare)) @PSBoundParameters)
        exit 74
    }
}
if($variant -ceq 'interrupt_release_receipt'){
    $originalStop=(Get-Command Stop-ContainerWriterFence).Definition
    $stopLine='Remove-Item -LiteralPath (Get-ContainerWriterFenceActivePath $root) -Force'
    if(-not $originalStop.Contains($stopLine)){throw 'ACTUAL_STOP_DELETE_MISSING'}
    Set-Item Function:Stop-ContainerWriterFence ([scriptblock]::Create($originalStop.Replace($stopLine,'exit 74')))
}
if($variant -in @('old_audit','schema','status','source','worker','tuple','root','owner_missing','owner_start_invalid','owner_boolean','inventory','result_proof','pending_followups','not_proven','helper_alive','helper_unknown')){
    Save $auditPath $payload
}
$auditBefore=Sha $auditPath
$fenceBefore=if(Test-Path -LiteralPath $activePath){Sha $activePath}else{''}
'''


def driver_with_mutation():
    text = DRIVER.replace('    $Error.Clear()', MUTATIONS + '\n    $Error.Clear()')
    return text.replace('fence_present=(Test-Path -LiteralPath $activePath);audit_preserved=',
                        'concurrent_writer_blocked=$script:ConcurrentWriterBlocked;'
                        'fence_preserved=($(if(Test-Path -LiteralPath $activePath){Sha $activePath}else{\'\'}) -ceq $fenceBefore);'
                        'fence_present=(Test-Path -LiteralPath $activePath);audit_preserved=')


def setup(tmp_path, engine, boundary):
    values = {'CA_GENERAL_STAGE': 'setup', 'CA_GENERAL_BOUNDARY': boundary}
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 73, 'producer failed; diagnostics suppressed'
    return values


COMMON = ('old_audit', 'schema', 'status', 'source', 'worker', 'tuple', 'root', 'owner_missing',
          'owner_start_invalid', 'owner_boolean', 'inventory',
          'owner_alive', 'owner_unknown', 'run_changed', 'writer_changed', 'stop_present',
          'prepared_changed', 'foreign_fence', 'result_proof', 'pending_followups',
          'child_alive', 'child_unknown', 'audit_during_read', 'fence_during_read')
CASES = [('A_AFTER_SET', case) for case in COMMON + ('manifest_changed', 'bootstrap_changed',
         'authorization_corrupt', 'authorization_missing', 'current_during_read', 'acl_unprotected', 'acl_foreign_allow')]
CASES += [('B_RESTORING_BEFORE_SET', case) for case in COMMON + ('helper_alive', 'helper_unknown',
          'not_proven', 'handover_changed')]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('boundary,case', CASES)
def test_unproven_general_completion_preserves_fence(tmp_path, engine, boundary, case):
    values = setup(tmp_path, engine, boundary)
    values.update(CA_GENERAL_STAGE='recover', CA_GENERAL_CASE=case)
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver_with_mutation(), values=values, engine=engine)
    assert result.returncode == 0, 'guard probe failed; diagnostics suppressed'
    observed = json.loads((tmp_path/'general-recovery-result.json').read_text(encoding='utf-8-sig'))
    assert observed['code'] == 'CANONICAL_COMPLETED_RELEASE_PROOF_DIFFERS'
    assert observed['fence_present']
    if case != 'audit_during_read':
        assert observed['audit_preserved']
    if case != 'fence_during_read':
        assert observed['fence_preserved']
    assert not list(tmp_path.rglob('recovered-release-*.json'))


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('boundary', ('A_AFTER_SET', 'B_RESTORING_BEFORE_SET'))
@pytest.mark.parametrize('case', ('owner_reused', 'writer_contends'))
def test_completed_general_recovery_keeps_process_birth_and_admission_rules(tmp_path, engine, boundary, case):
    values = setup(tmp_path, engine, boundary)
    values.update(CA_GENERAL_STAGE='recover', CA_GENERAL_CASE=case)
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver_with_mutation(), values=values, engine=engine)
    assert result.returncode == 0, 'identity/admission probe failed; diagnostics suppressed'
    observed = json.loads((tmp_path/'general-recovery-result.json').read_text(encoding='utf-8-sig'))
    assert observed['code'] == '' and not observed['fence_present'] and observed['audit_preserved']
    if case == 'writer_contends':
        assert observed['concurrent_writer_blocked'] is True


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('boundary', ('A_AFTER_SET', 'B_RESTORING_BEFORE_SET'))
@pytest.mark.parametrize('case', ('interrupt_authorization', 'interrupt_prepared', 'interrupt_release_receipt'))
def test_general_release_interruption_reuses_the_same_proof(tmp_path, engine, boundary, case):
    values = setup(tmp_path, engine, boundary)
    values.update(CA_GENERAL_STAGE='recover', CA_GENERAL_CASE=case)
    interrupted = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver_with_mutation(), values=values, engine=engine)
    assert interrupted.returncode == 74, 'release interruption was not reached'
    authorizations = list(tmp_path.rglob('recovered-release-*.json'))
    assert len(authorizations) == 1
    fixed = authorizations[0]
    original = (fixed.read_bytes(), fixed.stat().st_mtime_ns)
    values.pop('CA_GENERAL_CASE')
    releases = None
    for attempt in range(2):
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
        assert result.returncode == 0, 'release retry failed; diagnostics suppressed'
        observed = json.loads((tmp_path/'general-recovery-result.json').read_text(encoding='utf-8-sig'))
        assert observed['code'] == '' and not observed['fence_present'] and observed['audit_preserved']
        assert (fixed.read_bytes(), fixed.stat().st_mtime_ns) == original
        assert len(list(tmp_path.rglob('recovered-release-*.json'))) == 1
        current = {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                   for path in tmp_path.rglob('release-*.json')}
        assert len(current) == 1
        if releases is not None:
            assert current == releases
        releases = current
