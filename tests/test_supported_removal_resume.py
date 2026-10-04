"""Actual public fence/removal dispatch on owned NTFS; OS authority is a seam.

The first controller exits immediately after an owned-file rename, without any
controller catch/finally. Actual named session claims, fence bytes, journal
hashes and content custody run on Windows; ACL/CIM/task/Run/UAC are fixtures.
"""
import os
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from tests.powershell_contracts import run_powershell

REPO = Path(__file__).resolve().parents[1]

DRIVER = r'''
$ErrorActionPreference='Stop'
. $env:CA_RESUME_LIBRARY
. (Get-BootstrapSharedPortableLeaf (Split-Path -Parent $env:CA_RESUME_CANONICAL))
. $env:CA_RESUME_FENCE
Set-StrictMode -Off
$base=$env:CA_RESUME_ROOT;$source=$env:CA_RESUME_SOURCE;$uninstallSource=$source
$install=Join-Path $base 'current';$installRootFull=$install;$lad=Join-Path $base 'profile';$operatorSid='S-1-5-21-1-2-3-1001'
$OperatorSid=$operatorSid;$OperatorLocalAppDataRoot=$lad
$protected=Join-Path $base 'protected';$fenceRoot=Join-Path $base 'fence'
$Script:ContainerWriterFenceAdmissionProductionRoot=$fenceRoot
function Get-ContainerWriterFenceControlRoot([string]$ControlRoot=''){return $fenceRoot}
function Get-InstallationEvidenceControlRoot{return $protected}
function Test-InstallationEvidencePrivileged{return $true}
function Assert-InstallationEvidenceProtectedPath([string]$Path){
 if(-not $Path.StartsWith($protected+'\',[StringComparison]::OrdinalIgnoreCase) -or -not(Test-Path -LiteralPath $Path)){throw 'FIXTURE_UNPROTECTED_PATH'}
 Assert-BootstrapNoReparsePoint $Path 'fixture protected boundary'
}
function New-InstallationProtectedDirectory([string]$Path,[string]$Sid){[void][IO.Directory]::CreateDirectory($Path);Assert-InstallationEvidenceProtectedPath $Path}
function Set-InstallationEvidenceAcl{}
function Write-InstallationEvidenceEvent{}
function Write-InstallationCaughtFailure{}
function Write-ContainerStartupUpdateRecord([string]$Path,$Payload){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Payload|ConvertTo-Json -Depth 12)+"`n")
 $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Load-Functions([string]$Path,[string[]]$Names){
 $parsed=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$null,[ref]$null)
 foreach($name in $Names){$fn=@($parsed.EndBlock.Statements|Where-Object {$_.Name -ceq $name});if($fn.Count -eq 1){. ([scriptblock]::Create($fn[0].Extent.Text))}else{throw ('missing product function '+$name)}}
}
# Function definitions must enter this driver's script scope.
$canonical=[Management.Automation.Language.Parser]::ParseFile($env:CA_RESUME_CANONICAL,[ref]$null,[ref]$null)
$lower=[Management.Automation.Language.Parser]::ParseFile($env:CA_RESUME_LOWER,[ref]$null,[ref]$null)
foreach($name in @('Full','Same','Sha','Test-JsonPositiveInt32','Test-JsonInteger','Assert-RetirementOwnerExited',
 'Read-CanonicalSupportedRemovalResume','Resume-CanonicalSupportedRemovalFence')){
 $fn=@($canonical.EndBlock.Statements|Where-Object {$_.Name -ceq $name});if($fn.Count -eq 1){Invoke-Expression $fn[0].Extent.Text}
}
foreach($name in @('Test-SamePath','Assert-NoReparsePoint','Write-ContainerSupportedRemovalJournal','Get-ContainerRemovalIoPath',
 'Assert-ContainerRemovalBoundary','Assert-ContainerRemovalQuiescent','Get-ContainerRemovalTaskNames','Remove-ContainerScheduledTasks',
 'Test-ContainerRemovalFile','Get-ContainerArtifactFilePlan','Get-ContainerRemovalArtifacts','Remove-ContainerEmptiedParents','Invoke-ContainerConvergentRemoval')){
 $fn=@($lower.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object {$_.Name -ceq $name});if($fn.Count -eq 1){Invoke-Expression $fn[0].Extent.Text}
}
$sourceManifest=Get-Content -LiteralPath (Join-Path $source 'portable-manifest.json') -Raw|ConvertFrom-Json
$sourceManifestSha256=Sha (Join-Path $source 'portable-manifest.json')
$canonicalWriterFenceOrchestratorSha256=Sha (Join-Path $source 'INSTALL_CANONICAL_PORTABLE.ps1')
$canonicalWriterFenceContractSha256=$sourceManifest.writer_session_contract_sha256
$Script:CanonicalWriterFenceSessionId='1'*32;$Script:CanonicalWriterFenceAttemptId='2'*32;$Script:CanonicalWriterFenceTransactionId='3'*32
$canonicalWriterFenceStartedAtUtc='2026-10-04T00:00:00Z';$Script:CanonicalWriterFenceDelegationToken='4'*64
$canonicalWriterFenceDelegatedSources=@('canonical_code_placement')
$prepared=Join-Path $base 'prepared.json'
$canonicalWriterFencePreparedReceipt=[pscustomobject]@{path=$prepared;sha256=Sha $prepared}
$WriterFencePreparedReceiptPath=$prepared;$WriterFencePreparedReceiptSha256=Sha $prepared
$continuationPriorFence=$null;$rollbackContinuation=$null;$retirementResume=$null;$supportedRemovalResume=$null
$dispatch=@($canonical.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq '$continuationPriorFence' -and $n.Extent.Text.Contains('Start-ContainerWriterFence')},$true))
if($dispatch.Count -ne 1){throw 'actual public fence dispatch ambiguous'}
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public class RemovalFolder {
 public HashSet<string> Tasks=new HashSet<string>();
 public object[] GetTasks(int flags){return new object[0];}
 public object GetTask(string name){throw new COMException("absent",unchecked((int)0x80070002));}
 public void DeleteTask(string name,int flags){throw new Exception("unexpected task recreation");}
}
'@
$folder=[RemovalFolder]::new();$testOverride=$true
function Get-CimInstance{return [pscustomobject]@{ProcessId=$PID;ExecutablePath='fixture';CommandLine='fixture'}}
$cut=$env:CA_RESUME_PHASE -cin @('first','resume-cut')
$cutName=if($env:CA_RESUME_PHASE -ceq 'first'){'owned.bin'}else{'portable-manifest.json'}
function Move-Item {
 [CmdletBinding()]param([string]$LiteralPath,[string]$Destination)
 Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
 if($cut -and (Split-Path -Leaf $LiteralPath) -ceq $cutName){[Environment]::Exit(73)}
}
function Product {
 [IO.Directory]::CreateDirectory((Split-Path -Parent $stop))|Out-Null
 [IO.File]::WriteAllText($stop,'original stop request')
 [IO.File]::WriteAllText($removalPath,'{"status":"PASS_DATA_PRESERVED"}')
}
function Confirm-CanonicalRuntimeQuiescence{}
function Set-InstallationEvidenceStage{}
function Snapshot{return [pscustomobject]@{exists=$false;kind='';data=''}}
function Relays{return @()}
function Save([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))}
function New-CanonicalWriterFenceReleaseAuthorization{return [pscustomobject]@{fixture='OS release authentication seam'}}
function Set-CanonicalWriterFenceReleaseAuthorization{}
function Clear-CanonicalWriterFenceReleaseDelegation{}
function Stop-CanonicalWriterFenceRelease {
 [void](Abort-ContainerWriterFence -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
 -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -AuthorityLease $canonicalWriterFenceAuthority)
}
$content=@($lower.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
 $n.Left.Extent.Text -ceq '$removed' -and $n.Extent.Text.Contains('Invoke-ContainerConvergentRemoval')},$true))
$journalCaller=@($lower.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq '$UninstallAuditPath' -and $n.Extent.Text.Contains('Write-ContainerSupportedRemovalJournal')},$true))
function Invoke-InstallationEvidenceChild([string]$Label,[string]$Executable,[object[]]$Arguments){
 $excluded=@($PID)
 if($Label -cne 'supported-content-removal' -or $content.Count -ne 1){throw 'actual public removal child ambiguous'}
 foreach($name in @('UninstallAuditPath','UninstallAuditSha256')){
  $index=[Array]::IndexOf($Arguments,('-'+$name))
  if($index -ge 0){Set-Variable -Name $name -Value ([string]$Arguments[$index+1]) -Scope Script}
 }
 if($journalCaller.Count -eq 1){Invoke-Expression $journalCaller[0].Extent.Text}
 Invoke-Expression $content[0].Extent.Text
 return [pscustomobject]@{ExitCode=0}
}
$publicRemoval=@($canonical.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq '$Uninstall -and -not $CompleteRetiredRemoval' -and
 $n.Extent.Text.Contains("Invoke-InstallationEvidenceChild 'supported-content-removal'")},$true))
if($publicRemoval.Count -ne 1){throw 'actual public supported uninstall branch ambiguous'}
$Uninstall=$true;$CompleteRetiredRemoval=$false;$testMode=$true;$winps='fixture';$elevationLogPath='fixture';$evidenceFull=''
$stop=Join-Path $base 'status/stop.json';$removalPath=Join-Path $base 'status/removal.json'
$auditPath=Join-Path $base 'audit.json';$old=@();$productCompleteAuthorizationPath=Join-Path $base 'release.json'
$audit=[ordered]@{schema='container-audit-canonical-portable-install-v2';operation='UNINSTALL';status='PREIMAGE_SAVED';
 install_root=$install;source_manifest_sha256=$sourceManifestSha256;code_replacement=@{transaction_id=$Script:CanonicalWriterFenceTransactionId};stage_evidence_root=('audit.evidence.'+$PID)}
Save $auditPath $audit
if($env:CA_RESUME_PHASE -ceq 'first'){
 $canonicalWriterFenceAuthority=Enter-ContainerWriterSessionAuthority $Script:CanonicalWriterFenceSessionId $Script:CanonicalWriterFenceAttemptId $canonicalWriterFenceOrchestratorSha256 $Script:CanonicalWriterFenceTransactionId $canonicalWriterFenceContractSha256
 Invoke-Expression $dispatch[0].Extent.Text
 $UninstallAuditPath=Join-Path $base 'audit.json'
 $origin=[ordered]@{schema='container-audit-canonical-portable-install-v2';operation='UNINSTALL';status='PREIMAGE_SAVED';
 install_root=$install;source_manifest_sha256=$sourceManifestSha256;code_replacement=@{transaction_id=$Script:CanonicalWriterFenceTransactionId};stage_evidence_root=('audit.evidence.'+$PID)}
 [IO.File]::WriteAllText($UninstallAuditPath,($origin|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));$UninstallAuditSha256=Sha $UninstallAuditPath
 if(Get-Command Write-ContainerSupportedRemovalJournal -ErrorAction SilentlyContinue){Write-ContainerSupportedRemovalJournal @($PID)}
 else {
  # Baseline has no journal producer. The fixture supplies the exact new protected
  # precondition so RED exercises its actual caller's already-active fence error.
  $directory=Join-Path $protected ('supported-removals\'+$Script:CanonicalWriterFenceTransactionId);[void][IO.Directory]::CreateDirectory($directory)
  Copy-Item -LiteralPath $UninstallAuditPath -Destination (Join-Path $directory 'original-audit.json')
  $active=Read-ContainerWriterFence
  $record=[ordered]@{schema='container-audit-supported-removal-journal-v1';install_root=$install;operator_sid=$operatorSid;operator_local_appdata_root=$lad;
   owner_process_id=$PID;owner_started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o');authority_mutex_name=$active.session_authority_mutex_name;
   original_audit_path=$UninstallAuditPath;original_audit_sha256=$UninstallAuditSha256;audit_copy_path=Join-Path $directory 'original-audit.json';
   source_manifest_sha256=$sourceManifestSha256;prepared_receipt_path=$prepared;secret_values_recorded=$false}
  foreach($name in @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','writer_contract_sha256','writer_inventory_sha256','prepared_receipt_sha256')){$record[$name]=[string]$active.$name}
  Write-ContainerStartupUpdateRecord (Join-Path $directory 'removal-journal.json') $record
 }
 if($env:CA_RESUME_VARIANT -ceq 'live-owner'){
  try{Read-CanonicalSupportedRemovalResume;throw 'LIVE_OWNER_ACCEPTED'}catch{if($_.Exception.Message -cne 'RETIREMENT_ORIGINAL_OWNER_STILL_LIVE'){throw}}
  'LIVE_OWNER_REJECTED';exit 0
 }
 Invoke-Expression $publicRemoval[0].Extent.Text;throw 'controller cut was not reached'
}
if(Get-Command Read-CanonicalSupportedRemovalResume -ErrorAction SilentlyContinue){$supportedRemovalResume=Read-CanonicalSupportedRemovalResume}
$canonicalWriterFenceAuthority=Enter-ContainerWriterSessionAuthority $Script:CanonicalWriterFenceSessionId $Script:CanonicalWriterFenceAttemptId $canonicalWriterFenceOrchestratorSha256 $Script:CanonicalWriterFenceTransactionId $canonicalWriterFenceContractSha256
try {
 Invoke-Expression $dispatch[0].Extent.Text
 Invoke-Expression $publicRemoval[0].Extent.Text
 if((Get-Content -LiteralPath (Join-Path $base 'removed.json') -Raw|ConvertFrom-Json).lifecycle_state -cne 'REMOVED'){throw 'removal did not converge'}
 'PUBLIC_REMOVAL_RESUMED'
}finally{Exit-ContainerWriterSessionAuthority $canonicalWriterFenceAuthority}
'''


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('variant', ['interrupted', 'repeated', 'live-owner', 'forged-audit', 'tuple', 'manifest', 'unprotected'])
def test_public_uninstall_reclaims_only_exact_protected_dead_owner(tmp_path, engine, variant):
    from tests.test_convergent_removal import setup_tree
    root, originals = setup_tree()
    source = root / 'external-stock'
    source.mkdir()
    shutil.copyfile(REPO / 'INSTALL_CANONICAL_PORTABLE.ps1', source / 'INSTALL_CANONICAL_PORTABLE.ps1')
    manifest = dict(installer_sha256=hashlib.sha256((source / 'INSTALL_CANONICAL_PORTABLE.ps1').read_bytes()).hexdigest(),
                    writer_session_contract_sha256='5' * 64)
    (source / 'portable-manifest.json').write_text(json.dumps(manifest))
    (root / 'prepared.json').write_text('{"fixture":"original prepared bytes"}')
    driver = tmp_path / 'public-removal.ps1'
    driver.write_text(DRIVER, encoding='utf-8-sig')
    env = dict(os.environ, CA_RESUME_ROOT=str(root), CA_RESUME_SOURCE=str(source), CA_RESUME_PHASE='first',
               CA_RESUME_VARIANT=variant, CA_RESUME_LIBRARY=str(REPO / 'tools/bootstrap_integrity.ps1'),
               CA_RESUME_FENCE=str(REPO / 'tools/container_writer_fence.ps1'),
               CA_RESUME_CANONICAL=str(REPO / 'INSTALL_CANONICAL_PORTABLE.ps1'), CA_RESUME_LOWER=str(REPO / 'INSTALL_THIS_PC.ps1'))
    executable = shutil.which(engine)
    assert executable, engine + ' is required'
    def run():
        return run_powershell([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(driver)], env=env, timeout=30)
    first = run()
    if variant == 'live-owner':
        assert first.returncode == 0 and 'LIVE_OWNER_REJECTED' in first.stdout, first.stdout + first.stderr
        assert all(path.read_bytes() == original for path, original in originals.items())
        return
    assert first.returncode == 73, first.stdout + first.stderr
    assert not (root / 'current/owned.bin').exists()
    journal = root / ('protected/supported-removals/' + '3' * 32 + '/removal-journal.json')
    journal_bytes = journal.read_bytes()
    if variant == 'forged-audit':
        journal.with_name('original-audit.json').write_text('{"operation":"UNINSTALL"}')
    elif variant in ('tuple', 'manifest'):
        record = json.loads(journal_bytes)
        record['session_id' if variant == 'tuple' else 'source_manifest_sha256'] = ('9' * 32 if variant == 'tuple' else '9' * 64)
        journal.write_text(json.dumps(record))
    elif variant == 'unprotected':
        # Redirecting the machine evidence root to user-writable data is rejected
        # by the fixture's protected-path seam, as by the real ACL validator.
        driver.write_text(DRIVER.replace("function Get-InstallationEvidenceControlRoot{return $protected}",
            "function Get-InstallationEvidenceControlRoot{return (Join-Path $base 'user-writable')}"), encoding='utf-8-sig')
        shutil.copytree(root / 'protected/supported-removals', root / 'user-writable/supported-removals')
    if variant == 'repeated':
        env['CA_RESUME_PHASE'] = 'resume-cut'
        again = run()
        assert again.returncode == 73, again.stdout + again.stderr
        assert not (root / 'current/portable-manifest.json').exists()
        assert journal.read_bytes() == journal_bytes
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file() and p.name != 'audit.json'}
    env['CA_RESUME_PHASE'] = 'resume'
    resumed = run()
    if variant in ('interrupted', 'repeated'):
        assert resumed.returncode == 0 and 'PUBLIC_REMOVAL_RESUMED' in resumed.stdout, resumed.stdout + resumed.stderr
        assert journal.read_bytes() == journal_bytes
        for path, original in originals.items():
            assert not path.exists()
            assert any(p.read_bytes() == original for p in (root / 'removal-evidence').rglob('*') if p.is_file())
        assert not (root / 'current').exists()
        assert not (root / 'fence/active.json').exists()
    else:
        assert resumed.returncode != 0, resumed.stdout + resumed.stderr
        assert before == {p: p.read_bytes() for p in root.rglob('*') if p.is_file() and p.name != 'audit.json'}
