"""Completed machine placement recovery keeps code and releases its exact fence."""
import json
import re
from contextlib import nullcontext
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions
from tests.test_container_writer_session import _held_session_authority


INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"
FUNCTIONS = [
    "Read-CanonicalMachineInstallationRecovery",
    "Invoke-CanonicalMachineInstallationRecovery",
    "Confirm-CanonicalMachineRecoveryChildExit",
    "New-CanonicalWriterFenceReleaseAuthorization",
    "Test-ExactPropertySet", "Test-ExactStringProperties",
]

# Extraction dependencies are selected when present, including the new result readers.
_available_functions = set(re.findall(r"(?m)^function ([A-Za-z0-9_-]+)", INSTALLER.read_text(encoding="utf-8-sig")))
FUNCTIONS += [name for name in (
    "Find-CanonicalRemovalMoveJournal", "ReadReplacementRestoreEvidence",
    "Read-CanonicalMachineRemovalResult", "Read-CanonicalMachineRestoreResult",
) if name in _available_functions]

DRIVER = r'''
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$case=$env:CA_COMPLETED_CASE
$base=$env:CA_CONTRACT_ROOT
$source=Join-Path $base 'packet'
$root=Join-Path $base 'current'
$state=Join-Path $base 'machine-install'
$control=Join-Path $state 'control\writer-session'
$originalSource=$env:CA_CONTRACT_SOURCE
. (Join-Path (Split-Path -Parent $originalSource) 'tools\container_writer_fence.ps1')
# Extraction changes PSCommandPath; retain its original product-file meaning.
$reader=(Get-Command Read-CanonicalMachineInstallationRecovery).Definition
Set-Item Function:Read-CanonicalMachineInstallationRecovery ([scriptblock]::Create(
    $reader.Replace('$PSCommandPath','$originalSource')))
function Full([string]$Path,[string]$Label) { return [IO.Path]::GetFullPath($Path) }
function Same([string]$Left,[string]$Right) {
    return [IO.Path]::GetFullPath($Left).Equals([IO.Path]::GetFullPath($Right),[StringComparison]::OrdinalIgnoreCase)
}
function Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Save([string]$Path,$Value) {
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    [IO.File]::WriteAllText($Path,(($Value | ConvertTo-Json -Depth 40)+[char]10),[Text.UTF8Encoding]::new($false))
}
function Write-Utf8Json([string]$Path,$Value) { Save $Path $Value }
function Get-ContainerMachineInstallStateRoot { return $state }
function Assert-BootstrapNoReparsePoint { param($Path,$Label,[switch]$PathOnly) }
function Assert-InstallationEvidenceProtectedPath { param($Path) }
function InstalledManifest($Root,$UnsignedOk) {
    $script:InstalledChecks++
    return Get-Content -LiteralPath (Join-Path $Root 'portable-manifest.json') -Raw | ConvertFrom-Json
}
function Assert-BootstrapIntegrityRecord($Root) {
    $script:IntegrityChecks++
    if($case -ceq 'integrity_failure'){throw 'TEST_INTEGRITY_UNPROVEN'}
}
function Get-CimInstance {
    param($ClassName,$Property,$OperationTimeoutSec,$ErrorAction)
    $script:ProcessChecks++
    if($case -ceq 'process_unknown'){throw 'TEST_PROCESS_UNPROVEN'}
    if($case -ceq 'live_child'){
        return [pscustomobject]@{ProcessId=1;CommandLine=('-WriterFenceReplacementTransactionId '+$run)}
    }
    return @()
}
function Save-CanonicalMachineFailureAudit($Path,$Audit) { $script:AuditWrites++;Save $Path $Audit }
function Initialize-InstallationEvidence { throw 'TEST_COMPENSATION_STARTED' }
function Get-CanonicalMachinePlacementArguments { throw 'TEST_COMPENSATION_STARTED' }
function Restore-CanonicalMachineInstallationPrestate { $script:Restores++;throw 'TEST_COMPENSATION_STARTED' }
function Write-CanonicalMachinePublicRecord($Code,$Status) { $script:PublicCode=$Code }
$testMode=$true
$SkipSignatureValidationForTest=$true
$EvidencePath=''
$script:InstalledChecks=0;$script:IntegrityChecks=0;$script:AuditWrites=0
$script:ProcessChecks=0;$script:Restores=0;$script:PublicCode=''

# Extract the established receipt reader without executing bootstrap entry code.
$bootstrap=Join-Path (Split-Path -Parent $originalSource) 'tools\bootstrap_integrity.ps1'
$bootstrapTokens=$null;$bootstrapErrors=$null
$bootstrapAst=[Management.Automation.Language.Parser]::ParseFile($bootstrap,[ref]$bootstrapTokens,[ref]$bootstrapErrors)
$receiptFunction=$bootstrapAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-BootstrapReplacementReceipt'},$false)
. ([ScriptBlock]::Create($receiptFunction[0].Extent.Text))
function Get-StrictFullPath([string]$Path,[string]$Label){Full $Path $Label}
function Get-FileSha256([string]$Path){Sha $Path}
function Initialize-InstallationChildCapture {}
if($case -like 'recorded_child_*') {
    Add-Type -TypeDefinition @'
public static class KMTechInstallationChildCapture {
 public static string ObservedStart;
 public static bool Unreadable;
 public static string ReadProcessStartTimeUtc(int processId) {
  if (Unreadable) throw new System.IO.IOException("process observation denied");
  return ObservedStart;
 }
}
'@
    if($case -eq 'recorded_child_alive'){[KMTechInstallationChildCapture]::ObservedStart='2026-10-21T00:00:00.0000000Z'}
    if($case -eq 'recorded_child_unknown'){[KMTechInstallationChildCapture]::Unreadable=$true}
}

$idsPath=Join-Path $base 'ids.json'
if($env:CA_COMPLETED_STAGE -ceq 'setup'){
    $run=[Guid]::NewGuid().ToString('N')
    $session=[Guid]::NewGuid().ToString('N')
    $attempt=[Guid]::NewGuid().ToString('N')
    $contract=Sha (Join-Path (Split-Path -Parent $originalSource) 'tools\container_writer_session_contract.json')
    $manifest=[ordered]@{source_commit=('c'*40);version='2.0.117';writer_session_contract_sha256=$contract}
    foreach($dir in @($source,$root,$control)){[IO.Directory]::CreateDirectory($dir)|Out-Null}
    Save (Join-Path $source 'portable-manifest.json') $manifest
    Save (Join-Path $root 'portable-manifest.json') $manifest
    [IO.File]::WriteAllText((Join-Path $root 'keep.bin'),'installed-code-is-preserved')
    $preparedPath=Join-Path $state 'prepared.json';Save $preparedPath @{status='PREPARED'}
    $prepared=@{path=$preparedPath;sha256=Sha $preparedPath}
    $worker=@{sid='S-1-5-21-101-202-303-1001';profile_root=(Join-Path $base 'profile');same_caller=$true}
    $prestate=[ordered]@{schema='container-audit-machine-install-prestate-v1';operation='INSTALL';run_id=$run;
        install_root=$root;worker_sid=$worker.sid;profile_root=$worker.profile_root;session_id=$session;attempt_id=$attempt;
        source_manifest_sha256=Sha (Join-Path $source 'portable-manifest.json');orchestrator_sha256=Sha $originalSource;
        worker_preparation=$null;prepared_receipt=$prepared}
    if($case -ceq 'tuple_differs'){$prestate.attempt_id=[Guid]::NewGuid().ToString('N')}
    $journal=Join-Path $state ('install-audit\machine-prestate-'+$run+'\prestate.json');Save $journal $prestate
    $audit=[ordered]@{schema='container-audit-canonical-portable-install-v2';operation='INSTALL';status='PASS_MACHINE_WORKER_PENDING';
        run_id=$run;install_root=$root;worker_sid=$worker.sid;source_commit=$manifest.source_commit;
        source_manifest_sha256=$prestate.source_manifest_sha256;code_replacement=@{receipt_path=''};
        machine_prestate=@{path=$journal;sha256=Sha $journal};
        placement_child=@{status='EXITED'};compensation_child=@{status='NOT_STARTED'}}
    if($case -ceq 'root_differs'){$audit.install_root=Join-Path $base 'other'}
    if($case -ceq 'source_differs'){$audit.source_manifest_sha256='d'*64}
    if($case -ceq 'worker_differs'){$audit.worker_sid='S-1-5-21-101-202-303-1002'}
    if($case -ceq 'commit_differs'){$audit.source_commit='d'*40}
    if($case -ceq 'unsupported_status'){$audit.status='UNSUPPORTED_COMPLETION';$audit.operation='UNINSTALL'}

if($case -like 'recorded_child_*') {
    $audit.placement_child=@{status='EXITED';process_id=12345;started_at_utc='2026-10-21T00:00:00.0000000Z';exit_code=0}
}

$auditPath=Join-Path $state ('install-audit\canonical-portable-'+$run+'.json');Save $auditPath $audit
    $authority=Enter-ContainerWriterSessionAuthority -SessionId $session -AttemptId $attempt `
        -OrchestratorSha256 (Sha $originalSource) -ReplacementTransactionId $run -WriterContractSha256 $contract
    try{
        if($case -cne 'no_fence'){
            $status=if($case -ceq 'prepared_fence'){'PREPARED'}else{'INSTALLING'}
            $active=Start-ContainerWriterFence -ControlRoot $control -Status $status -OwnerKind 'canonical_installer' `
                -SessionId $session -AttemptId $attempt -ReplacementTransactionId $run -SessionStartedAtUtc ([DateTime]::UtcNow.ToString('o')) `
                -OrchestratorSha256 (Sha $originalSource) -WriterContractSha256 $contract -PreparedReceiptPath $prepared.path `
                -PreparedReceiptSha256 $prepared.sha256 -AuthorityLease $authority
            $authorityName=[string]$active.session_authority_mutex_name
        }else{$authorityName=''}
    }finally{Exit-ContainerWriterSessionAuthority $authority}
    Save $idsPath @{run=$run;session=$session;attempt=$attempt;contract=$contract;worker=$worker;authority=$authorityName;manifest=$manifest}
    Write-Output 'SETUP_PASS'
    return
}
$ids=Get-Content -LiteralPath $idsPath -Raw | ConvertFrom-Json
$run=$ids.run;$worker=$ids.worker;$manifest=$ids.manifest
$auditPath=Join-Path $state ('install-audit\canonical-portable-'+$run+'.json')
$originalAudit=[IO.File]::ReadAllBytes($auditPath)
$codeBefore=Sha (Join-Path $root 'keep.bin')
$code='';$authority=$null
try{
    $context=Read-CanonicalMachineInstallationRecovery $worker $source $root $manifest $auditPath (Sha $auditPath)
    if($case -ceq 'audit_changed'){
        $changed=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-Json
        $changed.worker_sid='S-1-5-21-101-202-303-1002';Save $auditPath $changed
    }
    if($case -ceq 'installed_changed'){
        [IO.File]::AppendAllText((Join-Path $root 'portable-manifest.json'),' ')
    }
    $authority=Enter-ContainerWriterSessionAuthority -SessionId $ids.session -AttemptId $ids.attempt `
        -OrchestratorSha256 (Sha $originalSource) -ReplacementTransactionId $run -WriterContractSha256 $ids.contract -RecoverExisting
    Invoke-CanonicalMachineInstallationRecovery $worker $source $root $manifest $context $authority | Out-Null
}catch{$code=$_.Exception.Message}
finally{if($null -ne $authority){Exit-ContainerWriterSessionAuthority $authority}}
Save (Join-Path $base 'completed-result.json') @{
    code=$code;fence_present=(Test-Path -LiteralPath (Join-Path $control 'active.json'));
    restored=$script:Restores;audit_writes=$script:AuditWrites;
    code_preserved=((Sha (Join-Path $root 'keep.bin')) -ceq $codeBefore);
    audit_spaced=([Text.Encoding]::UTF8.GetString($originalAudit) -match '\r?\n\s+"schema"\s*:\s+');audit_preserved=([Convert]::ToBase64String([IO.File]::ReadAllBytes($auditPath)) -ceq [Convert]::ToBase64String($originalAudit));
    installed_checks=$script:InstalledChecks;integrity_checks=$script:IntegrityChecks;process_checks=$script:ProcessChecks;
    public_code=$script:PublicCode;release_receipts=@(Get-ChildItem -LiteralPath $control -Filter 'release-*.json' -File).Count
}
'''


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("case,accepted", (
    ("completed", True), ("prepared_fence", True),
    ("root_differs", False), ("source_differs", False),
    ("worker_differs", False), ("tuple_differs", False),
    ("commit_differs", False), ("owner_alive", False),
    ("live_child", False), ("process_unknown", False),
    ("integrity_failure", False), ("installed_changed", False),
    ("audit_changed", False), ("unsupported_status", False), ("no_fence", False),

    ("recorded_child_exited", True),
    ("recorded_child_alive", False),
    ("recorded_child_unknown", False),
))
def test_completed_installation_only_releases_proven_fence(tmp_path, engine, case, accepted):
    values = {"CA_COMPLETED_STAGE": "setup", "CA_COMPLETED_CASE": case}
    setup = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert setup.returncode == 0, "isolated fixture preparation failed"
    ids = json.loads((tmp_path / "ids.json").read_text(encoding="utf-8-sig"))
    authority = _held_session_authority(ids["authority"]) if case == "owner_alive" else nullcontext()
    with authority:
        values["CA_COMPLETED_STAGE"] = "recover"
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 0, "isolated recovery driver failed"
    summary = json.loads((tmp_path / "completed-result.json").read_text(encoding="utf-8-sig"))
    assert summary["audit_spaced"], "audit must use indented ConvertTo-Json"
    assert summary["restored"] == 0
    assert summary["audit_writes"] == 0
    assert summary["code_preserved"]
    if case != "audit_changed":
        assert summary["audit_preserved"]
    if accepted:
        assert summary["code"] == "", "completed installation must finish without compensation"
        assert not summary["fence_present"]
        assert summary["release_receipts"] == 1
        assert summary["installed_checks"] > 0 and summary["integrity_checks"] > 0
        assert summary["process_checks"] > 0
        assert summary["public_code"] == "PASS_MACHINE_RECOVERED"
    else:
        assert summary["code"], "unproven recovery must refuse"
        expected = {
            "root_differs": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "source_differs": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "worker_differs": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "tuple_differs": "MACHINE_RECOVERY_AUTHORITY_BINDING_DIFFERS",
            "commit_differs": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "owner_alive": "CONTAINER_WRITER_SESSION_AUTHORITY_ALREADY_EXISTS",
            "live_child": "MACHINE_RECOVERY_CHILD_UNRECORDED",
            "process_unknown": "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN",
            "integrity_failure": "TEST_INTEGRITY_UNPROVEN",
            "installed_changed": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "audit_changed": "MACHINE_RECOVERY_AUDIT_CHANGED",
            "unsupported_status": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",

            "recorded_child_alive": "MACHINE_RECOVERY_CHILD_ACTIVE",
            "recorded_child_unknown": "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN",
        }
        if case in expected:
            assert summary["code"] == expected[case]
        assert summary["fence_present"] == (case != "no_fence")
        assert summary["release_receipts"] == 0
