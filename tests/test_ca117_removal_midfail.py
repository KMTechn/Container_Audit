"""Transfer 117 fix B: a removal that fails or dies part-way restores exactly what it moved.

Stage 1 runs the actual helper removal (INSTALL_THIS_PC.ps1) on a disposable NTFS tree and cuts it
part-way. Stage 2 runs the actual canonical compensation / recovery functions over that tree with the
real writer fence, session mutex and audit files.
"""
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

import pytest

from tests import test_convergent_removal as removal
from tests.powershell_contracts import run_functions

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "INSTALL_CANONICAL_PORTABLE.ps1"
HELPER = REPO / "INSTALL_THIS_PC.ps1"
INSTALLER_TEXT = INSTALLER.read_text(encoding="utf-8-sig")

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
# Functions the fix adds; absent before the fix (RED run) so the harness still starts.
OPTIONAL = ["Restore-CanonicalRemovalFromMoveJournal", "Restore-CanonicalRemovalScheduledTasks",
            "ConvertTo-CanonicalRemovalIoPath", "Find-CanonicalRemovalMoveJournal", "Get-CanonicalRemovalFileSha256"]
FUNCTIONS += [n for n in OPTIONAL if re.search(rf"(?m)^function {re.escape(n)}\b", INSTALLER_TEXT)]
FUNCTIONS = [n for n in FUNCTIONS if re.search(rf"(?m)^function {re.escape(n)}\b", INSTALLER_TEXT)]

HELPER_DRIVER = r'''
. $env:CA_REMOVAL_LIBRARY
$root=$env:CA_REMOVAL_ROOT;$testOverride=$true;$script:cut=$env:CA_REMOVAL_CUT
$MachineControlRoot='isolated-machine-control'
$WriterFenceReplacementTransactionId=$env:CA_REMOVAL_RUN
$Script:ContainerRemovalAttestedNewPlacement=$false
$Script:ContainerMachineRemovalProofKind='USER_RECEIPT';$Script:ContainerMachineRemovalWorkerRunPresent=$null
CENSUS
function Write-ContainerStartupUpdateRecord {
 param([string]$Path,$Payload)
 [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
}
function Move-Item {
 [CmdletBinding()]param([string]$LiteralPath,[string]$Destination)
 Microsoft.PowerShell.Management\Move-Item @PSBoundParameters
 if($script:cut -and (Split-Path -Leaf $LiteralPath) -ceq $script:cut){throw 'injected after rename'}
}
try { [void](Invoke-ContainerConvergentRemoval (Join-Path $root 'current') $null); 'HELPER DONE' }
catch { 'HELPER FAILED ' + $_.Exception.Message }
'''

RECOVERY_DRIVER = r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\container_writer_fence.ps1')
$Script:ContainerWriterFenceAdmissionMutexName+='.'+[Guid]::NewGuid().ToString('N')
function Assert-InstallationEvidenceProtectedPath {param($Path) if(-not (Test-Path -LiteralPath $Path)){throw 'test protected path absent'}}
function Set-InstallationEvidenceAcl {param($Path,$OperatorSid)}
$actualHelpers=Join-Path $env:CA_CONTRACT_ROOT 'recovery-helpers.ps1'
$blocks=@($definition_nodes|Where-Object {$_.Name -cin $env:CA_CONTRACT_NAMES.Split(',') -or $_.Name -ceq 'Confirm-CanonicalMachineRecoveryChildExit'}|ForEach-Object {$_.Extent.Text})
[IO.File]::WriteAllText($actualHelpers,($blocks -join [Environment]::NewLine),[Text.UTF8Encoding]::new($true))
. $actualHelpers
# Byte check of the fixture tree only; the real record format is covered by its own suite.
function Assert-BootstrapIntegrityRecord([string]$Root) {
 $record=Get-Content -LiteralPath (Join-Path $Root 'bootstrap-integrity.json') -Raw -Encoding UTF8|ConvertFrom-Json
 foreach($row in $record.files){ if((Sha (Join-Path $Root ([string]$row.path))) -cne [string]$row.sha256){throw 'INTEGRITY_FIXTURE_DIFFERS'} }
}
function Assert-BootstrapSupportQuiescent {param($ApplicationRoot,$ExcludeProcessIds) if($env:CA_RECOVERY_CASE -ceq 'dead_writer_running'){throw 'REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP'}}
function Get-CimInstance {
 param($ClassName,$Property,$OperationTimeoutSec,$ErrorAction)
 if($env:CA_RECOVERY_CASE -ceq 'dead_live_run'){return [pscustomobject]@{ProcessId=$PID;CommandLine=('-WriterFenceReplacementTransactionId '+$run)}}
}
$testMode=$true;$EvidencePath=''
$state=Get-ContainerMachineInstallStateRoot
$control=Join-Path $state 'control\writer-session'
$source=Join-Path $env:CA_CONTRACT_ROOT 'source'
$app=$env:CA_REMOVAL_ROOT
$root=Join-Path $app 'current'
[void][IO.Directory]::CreateDirectory($source)
[void][IO.Directory]::CreateDirectory((Join-Path $state 'install-audit'))
[IO.File]::WriteAllText((Join-Path $source 'portable-manifest.json'),'{}')
$worker=[pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;profile_root=$env:CA_CONTRACT_ROOT;same_caller=$false}
$Script:CanonicalWriterFenceSessionId=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceAttemptId=[Guid]::NewGuid().ToString('N')
$run=$env:CA_REMOVAL_RUN
$Script:CanonicalWriterFenceTransactionId=$run
$orchestrator=Sha $actualHelpers
$manifest=@{writer_session_contract_sha256=Sha $env:CA_CONTRACT_SOURCE;writer_fence_helper_sha256=Sha $env:CA_CONTRACT_SOURCE}
$tuple=@{SessionId=$Script:CanonicalWriterFenceSessionId;AttemptId=$Script:CanonicalWriterFenceAttemptId;
 OrchestratorSha256=$orchestrator;ReplacementTransactionId=$run;WriterContractSha256=$manifest.writer_session_contract_sha256;ObserverSid=''}
$started=[DateTime]::UtcNow.ToString('o')
$prepared=New-CanonicalWriterFencePreparedReceipt (Join-Path $state ('install-audit\prepared-'+$run+'.json')) `
 $tuple.SessionId $tuple.AttemptId $run $started $orchestrator $tuple.WriterContractSha256 `
 (Sha (Join-Path $source 'portable-manifest.json')) $worker.sid (Join-Path $worker.profile_root 'AppData\Local')
$pending=Join-Path $state 'pending-onboarding.json'
[IO.File]::WriteAllText($pending,'pending publication')
$pendingSha=Sha $pending
$before=Get-CanonicalMachineArtifactPreimage @($pending)
$prestate=[ordered]@{schema='container-audit-machine-install-prestate-v1';run_id=$run;install_root=$root;
 worker_sid=$worker.sid;profile_root=$worker.profile_root;source_manifest_sha256=Sha (Join-Path $source 'portable-manifest.json');
 before_manifest_sha256=$env:CA_BEFORE_MANIFEST_SHA;artifact_before=@(ConvertTo-CanonicalMachineArtifactJournal $before);startup_before=@();
 worker_preparation=$null;worker_run_before=$null;session_id=$tuple.SessionId;attempt_id=$tuple.AttemptId;
 orchestrator_sha256=$orchestrator;prepared_receipt=$prepared;secret_values_recorded=$false;
 operation='UNINSTALL';removal_recovery=[ordered]@{schema='container-audit-machine-removal-recovery-v1';
  application=$app;evidence_parent=(Join-Path $app 'removal-evidence');journal_name='removal-move-journal.jsonl'}}
$journal=Join-Path $state ('install-audit\machine-prestate-'+$run+'\prestate.json')
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $journal))
Write-Utf8Json $journal $prestate
$audit=[ordered]@{schema='container-audit-canonical-portable-install-v2';operation='UNINSTALL';status='PREIMAGE_SAVED';
 run_id=$run;install_root=$root;worker_sid=$worker.sid;source_manifest_sha256=$prestate.source_manifest_sha256;
 machine_prestate=@{path=$journal;sha256=Sha $journal};code_replacement=@{transaction_id=$run;receipt_path=''};
 placement_child=@{status='EXIT_UNPROVEN'};compensation_child=@{status='NOT_STARTED'}}
if($env:CA_RECOVERY_CASE -ceq 'auto'){$audit.status='MACHINE_INSTALL_FAILED';$audit.placement_child=@{status='EXITED';exit_code=73}}
$auditPath=Join-Path $state ('install-audit\canonical-portable-'+$run+'.json')
Save $auditPath $audit
$auditSha=Sha $auditPath
$staleFence=Get-ContainerWriterFenceActivePath $control
if(Test-Path -LiteralPath $staleFence){Remove-Item -LiteralPath $staleFence -Force}
$lease=Enter-ContainerWriterSessionAuthority @tuple
[void](Start-ContainerWriterFence -ControlRoot $control -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
 -SessionId $tuple.SessionId -AttemptId $tuple.AttemptId -ReplacementTransactionId $run -SessionStartedAtUtc $started `
 -OrchestratorSha256 $orchestrator -WriterContractSha256 $tuple.WriterContractSha256 `
 -PreparedReceiptPath $prepared.path -PreparedReceiptSha256 $prepared.sha256 -AuthorityLease $lease)
$fencePath=Get-ContainerWriterFenceActivePath $control
$observed='PASS'
if($env:CA_RECOVERY_CASE -ceq 'auto'){
 $Script:ContainerMachineInstallControlRoot=$control;$Script:ContainerWriterFenceAdmissionProductionRoot=$control
 $Script:CanonicalWriterFenceDelegationToken=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
 [void](Set-ContainerWriterFenceDelegation -ControlRoot $control -SessionId $tuple.SessionId -AttemptId $tuple.AttemptId -ReplacementTransactionId $run `
  -DelegationToken $Script:CanonicalWriterFenceDelegationToken -DelegatedSources @('canonical_code_placement') -LifetimeSeconds 300 -AuthorityLease $lease)
 try{ if(-not (Restore-CanonicalMachineInstallationPrestate $worker $source $root $manifest $prestate @() '' $auditPath $audit $lease)){$observed='UNPROVEN'} }
 catch{$observed=$_.Exception.Message}
 Exit-ContainerWriterSessionAuthority $lease
} else {
 Exit-ContainerWriterSessionAuthority $lease
 $lease=$null
 $holder=$null
 if($env:CA_RECOVERY_CASE -ceq 'dead_authority_busy'){
  Add-Type -TypeDefinition @'
using System; using System.Threading;
public sealed class RemovalAuthorityHolder : IDisposable {
 readonly ManualResetEvent ready=new ManualResetEvent(false), done=new ManualResetEvent(false);
 readonly Thread thread; readonly Mutex mutex;
 public RemovalAuthorityHolder(string name) { mutex=new Mutex(false,name);thread=new Thread(()=>{mutex.WaitOne();ready.Set();done.WaitOne();mutex.ReleaseMutex();});thread.Start();ready.WaitOne(); }
 public void Dispose() {done.Set();thread.Join();mutex.Dispose();ready.Dispose();done.Dispose();}
}
'@
  $holder=[RemovalAuthorityHolder]::new((Read-ContainerWriterFence $control).session_authority_mutex_name)
 }
 try{
  $context=Read-CanonicalMachineInstallationRecovery $worker $source $root $manifest $auditPath $auditSha
  $lease=Enter-ContainerWriterSessionAuthority @tuple -RecoverExisting
  Invoke-CanonicalMachineInstallationRecovery $worker $source $root $manifest $context $lease
 }catch{$observed=$_.Exception.Message}
 finally{Exit-ContainerWriterSessionAuthority $lease;if($null -ne $holder){$holder.Dispose()}}
}
$saved=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-ContainerWriterFenceJson
function Prop($Object,[string]$Name){if($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]){return $Object.$Name};return $null}
$comp=Prop $saved 'compensation'
$pendingSame=(Test-Path -LiteralPath $pending) -and ((Sha $pending) -ceq $pendingSha)
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'outcome.json'),(@{observed=$observed;fence_present=(Test-Path -LiteralPath $fencePath);
 pending_same=$pendingSame;status=[string](Prop $saved 'status');code_restore=[string](Prop $comp 'code_restore');
 support_recovery=[string](Prop $saved 'support_recovery');fence_retained=[bool](Prop $saved 'fence_retained')}|ConvertTo-Json))
if(Test-Path -LiteralPath $fencePath){Remove-Item -LiteralPath $fencePath -Force}
'STAGE2 DONE'
'''


def _tree(tmp_path, monkeypatch):
    monkeypatch.setenv("CA_NTFS_TEST_ROOT", str(tmp_path))
    app, originals = removal.setup_tree()
    # extra directory depth so emptied parents are exercised
    deep = app / "current" / "runtime" / "lib" / "x.bin"
    deep.parent.mkdir(parents=True)
    deep.write_bytes(b"deep code")
    record = app / "current" / "bootstrap-integrity.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    data["files"].append(dict(path="runtime/lib/x.bin", size=9, sha256=hashlib.sha256(b"deep code").hexdigest()))
    record.write_text(json.dumps(data), encoding="utf-8")
    originals[deep] = b"deep code"
    originals[record] = record.read_bytes()
    return app, originals


def _snapshot(app):
    rows = {}
    for path in sorted((app / "current").rglob("*")):
        stat = path.stat()
        rows[path.relative_to(app).as_posix()] = (
            None if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest(), stat.st_mtime_ns)
    return rows


def _stage1(tmp_path, app, run, cut):
    census = re.search(r"(?ms)^function Get-CimInstance.*?^}", removal.DRIVER)
    assert census
    result = run_functions(tmp_path, HELPER, removal.NAMES, HELPER_DRIVER.replace("CENSUS", census.group()),
                           values={"CA_REMOVAL_ROOT": str(app), "CA_REMOVAL_CUT": cut, "CA_REMOVAL_RUN": run,
                                   "CA_REMOVAL_LIBRARY": str(REPO / "tools/bootstrap_integrity.ps1")})
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _journals(app, run):
    found = []
    for path in (app / "removal-evidence").glob("*/removal-move-journal.jsonl"):
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines and lines[0].get("run_id") == run:
            found.append((path, lines))
    return found


def _stage2(tmp_path, app, case, run, manifest_sha):
    sub = tmp_path / "stage2"
    sub.mkdir()
    result = run_functions(sub, INSTALLER, FUNCTIONS, RECOVERY_DRIVER, values={
        "CA_RECOVERY_CASE": case, "CA_REMOVAL_ROOT": str(app), "CA_REMOVAL_RUN": run,
        "CA_BEFORE_MANIFEST_SHA": manifest_sha})
    assert result.returncode == 0 and "STAGE2 DONE" in result.stdout, result.stdout + result.stderr
    outcome = json.loads((sub / "outcome.json").read_text(encoding="utf-8-sig"))
    return outcome


def _run_id():
    return uuid.uuid4().hex


# ---- RED 1: failure while moving code leaves current different; automatic compensation must restore it
@pytest.mark.parametrize("cut", ["portable-manifest.json", "second.bin", ""])
def test_mid_removal_failure_is_compensated_to_the_exact_prestate(tmp_path, monkeypatch, cut):
    app, originals = _tree(tmp_path, monkeypatch)
    manifest_sha = hashlib.sha256((app / "current" / "portable-manifest.json").read_bytes()).hexdigest()
    before = _snapshot(app)
    run = _run_id()
    out = _stage1(tmp_path, app, run, cut)
    assert ("HELPER FAILED" in out) == bool(cut)
    assert not (app / "current" / "owned.bin").exists()  # code really moved away
    outcome = _stage2(tmp_path, app, "auto", run, manifest_sha)
    assert outcome["observed"] == "PASS", outcome
    assert outcome["code_restore"] == "PASS"
    assert not outcome["fence_present"] and not outcome["fence_retained"]
    assert _snapshot(app) == before          # bytes AND modification times, directories recreated
    assert not (app / "removed.json").exists()
    assert outcome["status"] == "FAILED_ROLLED_BACK"


# ---- RED 2: the remover died (audit PREIMAGE_SAVED, child EXIT_UNPROVEN)
def test_dead_remover_is_recovered_exactly_and_can_remove_again(tmp_path, monkeypatch):
    app, originals = _tree(tmp_path, monkeypatch)
    manifest_sha = hashlib.sha256((app / "current" / "portable-manifest.json").read_bytes()).hexdigest()
    before = _snapshot(app)
    run = _run_id()
    _stage1(tmp_path, app, run, "portable-manifest.json")
    outcome = _stage2(tmp_path, app, "dead", run, manifest_sha)
    assert outcome["observed"] == "PASS", outcome
    assert outcome["code_restore"] == "PASS" and not outcome["fence_present"]
    assert outcome["status"] == "FAILED_ROLLED_BACK" and outcome["pending_same"]
    assert _snapshot(app) == before
    # the official removal can run again over the restored tree
    again = _run_id()
    assert "HELPER DONE" in _stage1(tmp_path, app, again, "")
    marker = json.loads((app / "removed.json").read_text(encoding="utf-8-sig"))
    assert marker["lifecycle_state"] == "REMOVED" and not (app / "current").exists()


@pytest.mark.parametrize("case, expected", [
    ("dead_live_run", "MACHINE_RECOVERY_CHILD_UNRECORDED"),
    ("dead_authority_busy", "CONTAINER_WRITER_SESSION_AUTHORITY_ALREADY_EXISTS"),
    ("dead_writer_running", "MACHINE_RECOVERY_COMPENSATION_UNPROVEN"),
])
def test_recovery_still_refuses_live_installer_foreign_fence_and_running_writers(tmp_path, monkeypatch, case, expected):
    app, _ = _tree(tmp_path, monkeypatch)
    manifest_sha = hashlib.sha256((app / "current" / "portable-manifest.json").read_bytes()).hexdigest()
    run = _run_id()
    _stage1(tmp_path, app, run, "portable-manifest.json")
    moved = _snapshot(app)
    outcome = _stage2(tmp_path, app, case, run, manifest_sha)
    assert outcome["observed"] == expected, outcome
    assert _snapshot(app) == moved            # refused: nothing restored
    if case != "dead_authority_busy":
        assert outcome["fence_present"] or outcome["observed"] != "PASS"


@pytest.mark.parametrize("damage", ["evidence-changed", "journal-absent", "other-run", "current-conflict"])
def test_contradicting_records_keep_the_fence_and_change_nothing(tmp_path, monkeypatch, damage):
    app, _ = _tree(tmp_path, monkeypatch)
    manifest_sha = hashlib.sha256((app / "current" / "portable-manifest.json").read_bytes()).hexdigest()
    run = _run_id()
    _stage1(tmp_path, app, run, "portable-manifest.json")
    (journal, lines), = _journals(app, run)
    moves = [row for row in lines if row.get("record") == "MOVE"]
    assert moves, "helper wrote no move records"
    if damage == "evidence-changed":
        Path(moves[0]["destination"]).write_bytes(b"tampered evidence")
    elif damage == "journal-absent":
        journal.unlink()
    elif damage == "other-run":
        lines[0]["run_id"] = _run_id()
        journal.write_text("".join(json.dumps(row) + "\n" for row in lines), encoding="utf-8")
    else:
        Path(moves[0]["path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(moves[0]["path"]).write_bytes(b"someone else's file")
    moved = _snapshot(app)
    outcome = _stage2(tmp_path, app, "dead", run, manifest_sha)
    assert outcome["observed"] == "MACHINE_RECOVERY_COMPENSATION_UNPROVEN", outcome
    assert outcome["fence_present"] and outcome["fence_retained"]
    assert outcome["code_restore"] == "UNPROVEN"
    assert _snapshot(app) == moved
    assert outcome["status"] == "ROLLBACK_FAILED"


# ---- RED 1/3: the journal and recovery context exist before the first change
def test_helper_journals_every_move_with_run_binding_before_moving(tmp_path, monkeypatch):
    app, originals = _tree(tmp_path, monkeypatch)
    run = _run_id()
    _stage1(tmp_path, app, run, "portable-manifest.json")
    found = _journals(app, run)
    assert len(found) == 1
    journal, lines = found[0]
    assert lines[0]["record"] == "HEADER" and lines[0]["run_id"] == run
    assert Path(lines[0]["application"]) == app
    moves = {Path(row["path"]): row for row in lines if row["record"] == "MOVE"}
    assert Path(app / "current" / "owned.bin") in moves
    for row in moves.values():
        assert re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
        assert Path(row["destination"]).is_relative_to(journal.parent)
    assert any(row["record"] == "DIR" for row in lines)


def test_journal_is_not_written_for_ordinary_removal(tmp_path, monkeypatch):
    app, _ = _tree(tmp_path, monkeypatch)
    census = re.search(r"(?ms)^function Get-CimInstance.*?^}", removal.DRIVER)
    driver = HELPER_DRIVER.replace("CENSUS", census.group()).replace(
        "$MachineControlRoot='isolated-machine-control'", "$MachineControlRoot=''")
    result = run_functions(tmp_path, HELPER, removal.NAMES, driver, values={
        "CA_REMOVAL_ROOT": str(app), "CA_REMOVAL_CUT": "", "CA_REMOVAL_RUN": "",
        "CA_REMOVAL_LIBRARY": str(REPO / "tools/bootstrap_integrity.ps1")})
    assert result.returncode == 0 and "HELPER DONE" in result.stdout
    assert not list((app / "removal-evidence").glob("*/removal-move-journal.jsonl"))


def test_removal_saves_recovery_context_in_the_prestate_before_the_first_change():
    body = INSTALLER_TEXT[INSTALLER_TEXT.index("function Invoke-CanonicalMachineInstallation"):]
    prestate = body.index("$prestate=[ordered]@{schema='container-audit-machine-install-prestate-v1'")
    assert "removal_recovery" in body[prestate:body.index("Write-Utf8Json $journal $prestate")]
    assert body.index("Write-Utf8Json $journal $prestate") < body.index("Start-ContainerWriterFence")
    assert "operation=" in body[prestate:body.index("Write-Utf8Json $journal $prestate")]


# ---- RED 3: guidance points at an entry that really accepts the failed UNINSTALL audit
def test_failed_uninstall_guidance_names_the_exact_accepting_entry(tmp_path, monkeypatch):
    app, _ = _tree(tmp_path, monkeypatch)
    manifest_sha = hashlib.sha256((app / "current" / "portable-manifest.json").read_bytes()).hexdigest()
    run = _run_id()
    _stage1(tmp_path, app, run, "portable-manifest.json")
    outcome = _stage2(tmp_path, app, "auto", run, manifest_sha)
    text = outcome["support_recovery"]
    for token in ("-RecoverMachineInstallation", "-SourceRoot", "-WorkerAccount",
                  "-MachineRecoveryAuditPath", "-MachineRecoveryAuditSha256"):
        assert token in text, text
    assert "-Uninstall" not in text
    # and that entry accepts the operation (recovery of a dead remover above); gate is not INSTALL-only
    gate = INSTALLER_TEXT[INSTALLER_TEXT.index("function Read-CanonicalMachineInstallationRecovery"):
                          INSTALLER_TEXT.index("function Confirm-CanonicalMachineRecoveryChildExit")]
    assert "-cnotin @('INSTALL','UNINSTALL')" in gate and "'PREIMAGE_SAVED'" in gate
