"""Power loss before durable fresh preparation and after filesystem rename."""
import json
from pathlib import Path
import re

import pytest

from tests.test_fresh_server_registration import old_pc, transition, fresh_context
from tests.powershell_contracts import run_functions


@pytest.mark.parametrize("cut", ["initial_record", "initial_prepared", "initial_audit", "initial_fence",
                                 "resume_prepared", "resume_audit", "resume_fence"])
@pytest.mark.parametrize("fault", ["", "foreign", "tampered", "foreign_fence", "live_owner", "outside_audit", "prepared_source"])
def test_native_preparation_recovers_only_its_publication(tmp_path, cut, fault):
    source = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"
    names = ["Full", "Same", "Sha", "Save", "Test-JsonTrue", "Test-JsonInteger", "Test-JsonPositiveInt32",
             "Test-ExactPropertySet", "Test-ExactStringProperties", "Assert-RetirementOwnerExited",
             "Assert-RollbackRelayPreimage", "Read-CanonicalFreshResume", "New-CanonicalWriterFencePreparedReceipt"]
    # Load new dependencies when present; the RED still executes the old public
    # resume reader against the same independently assembled crash evidence.
    for name in ("Read-CanonicalFreshPreparation", "Resolve-CanonicalFreshPreparation",
                 "Set-CanonicalFreshPreparationBinding", "Assert-CanonicalFreshPreparationIdentity",
                 "Assert-CanonicalFreshPreparationPreimage"):
        if re.search(r"^function " + name + r"\b", source.read_text(encoding="utf-8-sig"), re.M):
            names.append(name)
    result = run_functions(tmp_path, source, names, r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
function Sha([string]$Path) {
    if (-not $Path) { $Path=$env:CA_CONTRACT_SOURCE }
    return Get-KmtechFileSha $Path
}
function Snapshot { return [ordered]@{exists=$false;kind='';data=''} }
function Relays { return @() }
$install=Join-Path $env:CA_CONTRACT_ROOT 'current'
$activeDataRoot=Join-Path $env:CA_CONTRACT_ROOT 'data'
$auditRoot=Join-Path $activeDataRoot 'install-audit'
$FreshArchiveRoot=Join-Path $env:CA_CONTRACT_ROOT 'archive'
[void](New-Item -ItemType Directory -Path $install,$auditRoot,$FreshArchiveRoot)
$FreshTransitionInput=Join-Path $env:CA_CONTRACT_ROOT 'input.json'
Set-Content -LiteralPath $FreshTransitionInput -Value '{}' -Encoding UTF8
$FreshTransitionId='b'*32
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sourceManifestSha256='c'*64
$lifecycleManifest=@{writer_session_contract_sha256='d'*64}
$stop=Join-Path $env:CA_CONTRACT_ROOT 'absent.stop'
$wanted='exact fixture relay command'
$orchestrator=Sha $env:CA_CONTRACT_SOURCE
$owner=2147483000; $ownerStart='2025-01-01T00:00:00.0000000Z'
if ($env:CA_FAULT -ceq 'live_owner') {
    $owner=$PID; $ownerStart=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')
}
function FixtureAudit([string]$Run,[string]$Session,[string]$Attempt,[string]$Transaction,[bool]$Quiesced) {
    return [ordered]@{
        schema='container-audit-canonical-portable-install-v2';operation='PREPARE_FRESH_SERVER_REGISTRATION'
        status='PREIMAGE_SAVED';run_id=$Run;install_root=$install;source_manifest_sha256=$sourceManifestSha256
        code_replacement=@{transaction_id=$Transaction};preimage=(Snapshot)
        fresh_transition=[ordered]@{
            transition_id=$FreshTransitionId;sid=$operatorSid;input_sha256=(Sha $FreshTransitionInput)
            archive_root=$FreshArchiveRoot;orchestrator_sha256=$orchestrator;session_id=$Session;attempt_id=$Attempt
            quiesced=$Quiesced;prepared_receipt_path='';prepared_receipt_sha256='';stop_sha256=''
            authority_mutex_name=(Get-ContainerWriterSessionAuthorityMutexName $Session $Attempt $orchestrator $Transaction $lifecycleManifest.writer_session_contract_sha256)
            owner_process_id=$owner;owner_started_at_utc=$ownerStart
            original_preimage=(Snapshot);original_relays=@();original_removal=$null
            original_scheduled_writer=@{present=$false};original_task_xml=''
        }
    }
}
$resuming=$env:CA_CUT.StartsWith('resume_')
$parentPath='';$parentSha='';$priorFenceSha=''
if ($resuming) {
    $parent=FixtureAudit 'old' ('a'*32) ('c'*32) ('d'*32) $true
    $oldPrepared=Join-Path $auditRoot 'old-prepared.json'
    Save $oldPrepared @{}
    $parent.fresh_transition.prepared_receipt_path=$oldPrepared
    $parent.fresh_transition.prepared_receipt_sha256=Sha $oldPrepared
    $parentPath=Join-Path $auditRoot 'canonical-portable-old.json'
    Save $parentPath $parent
    $parentSha=Sha $parentPath
    $payload=New-ContainerWriterFencePayload -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
        -SessionId ('a'*32) -AttemptId ('c'*32) -ReplacementTransactionId ('d'*32) `
        -SessionStartedAtUtc $ownerStart -OrchestratorSha256 $orchestrator `
        -WriterContractSha256 $lifecycleManifest.writer_session_contract_sha256 `
        -PreparedReceiptPath $oldPrepared -PreparedReceiptSha256 (Sha $oldPrepared)
    [void](Write-ContainerWriterFenceAtomic '' $payload)
    $priorFenceSha=Sha (Get-ContainerWriterFenceActivePath)
}
$next=FixtureAudit 'next' ('e'*32) ('f'*32) ('a'*32) $resuming
if ($env:CA_FAULT -ceq 'foreign') { $next.fresh_transition.sid='S-1-5-21-999-998-997-1001' }
$nextPath=Join-Path $auditRoot 'canonical-portable-next.json'
$record=[ordered]@{
    schema='container-audit-fresh-preparation-v1';audit_path=$nextPath;audit=$next
    parent_receipt_path=$parentPath;parent_receipt_sha256=$parentSha
    origin_receipt_path=$parentPath;origin_receipt_sha256=$parentSha;prior_fence_sha256=$priorFenceSha
    install_preimage=@{exists=$true;manifest_sha256='';integrity_sha256=''}
}
if ($env:CA_FAULT -ceq 'outside_audit') {
    $record.audit_path=Join-Path $env:CA_CONTRACT_ROOT 'canonical-portable-next.json'
}
$scratch=Join-Path $auditRoot 'record.json'
Save $scratch $record
$recordSha=Sha $scratch
$recordPath=Join-Path $auditRoot ('fa-'+$recordSha+'.json')
Move-Item -LiteralPath $scratch -Destination $recordPath
$preparedPath=Join-Path $auditRoot ('fp-'+$recordSha+'.json')
$preparedSha=''
if ($env:CA_CUT -cne 'initial_record' -or $env:CA_FAULT -ceq 'prepared_source') {
    $preparedSource=if ($env:CA_FAULT -ceq 'prepared_source') { 'f'*64 } else { $sourceManifestSha256 }
    $prepared=New-CanonicalWriterFencePreparedReceipt $preparedPath ('e'*32) ('f'*32) ('a'*32) `
        $ownerStart $orchestrator $lifecycleManifest.writer_session_contract_sha256 $preparedSource `
        $operatorSid $env:LOCALAPPDATA
    $preparedSha=$prepared.sha256
}
$next.fresh_transition.prepared_receipt_path=$preparedPath
$next.fresh_transition.prepared_receipt_sha256=$preparedSha
$next.fresh_transition.preparation_receipt_path=$recordPath
$next.fresh_transition.preparation_receipt_sha256=$recordSha
$next.fresh_transition.resume_origin_path=$parentPath
$next.fresh_transition.resume_origin_sha256=$parentSha
if ($env:CA_CUT -cin @('initial_audit','initial_fence','resume_audit','resume_fence')) { Save $nextPath $next }
if ($env:CA_CUT.EndsWith('_fence')) {
    $payload=New-ContainerWriterFencePayload -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
        -SessionId ('e'*32) -AttemptId ('f'*32) -ReplacementTransactionId ('a'*32) `
        -SessionStartedAtUtc $ownerStart -OrchestratorSha256 $orchestrator `
        -WriterContractSha256 $lifecycleManifest.writer_session_contract_sha256 `
        -PreparedReceiptPath $preparedPath -PreparedReceiptSha256 $preparedSha
    [void](Write-ContainerWriterFenceAtomic '' $payload)
}
if ($env:CA_FAULT -ceq 'audit_advanced') {
    $next.status='FRESH_TRANSITION_QUIESCED'
    $next.fresh_transition.quiesced=$true
    Save $nextPath $next
}
# Before a replacement is published the old receipt remains authoritative.
# Fault cases inspect the new record directly, so a foreign pending preparation
# is never silently accepted merely because the old fence still exists.
$ResumeFreshTransitionReceiptPath=if ($resuming -and -not $env:CA_FAULT) { $parentPath } else { $recordPath }
$ResumeFreshTransitionReceiptSha256=Sha $ResumeFreshTransitionReceiptPath
if ($env:CA_FAULT -ceq 'tampered') { [IO.File]::AppendAllText($recordPath,' ') }
if ($env:CA_FAULT -ceq 'foreign_fence') {
    $foreignPrepared=Join-Path $auditRoot 'foreign-prepared.json'
    $foreignProof=New-CanonicalWriterFencePreparedReceipt $foreignPrepared ('a'*32) ('b'*32) ('c'*32) `
        $ownerStart $orchestrator $lifecycleManifest.writer_session_contract_sha256 $sourceManifestSha256 `
        $operatorSid $env:LOCALAPPDATA
    $payload=New-ContainerWriterFencePayload -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
        -SessionId ('a'*32) -AttemptId ('b'*32) -ReplacementTransactionId ('c'*32) `
        -SessionStartedAtUtc $ownerStart -OrchestratorSha256 $orchestrator `
        -WriterContractSha256 $lifecycleManifest.writer_session_contract_sha256 `
        -PreparedReceiptPath $foreignPrepared -PreparedReceiptSha256 $foreignProof.sha256
    [void](Write-ContainerWriterFenceAtomic '' $payload)
}
$activePath=Get-ContainerWriterFenceActivePath
$fenceBefore=if (Test-Path -LiteralPath $activePath) { Sha $activePath } else { '' }
$recordBefore=Sha $recordPath
$accepted=$false
$hint=@{}
try { $read=Read-CanonicalFreshResume; $accepted=$true } catch { $failure=$_.Exception.Message; $hint=$_.Exception.Data }
if ((Sha $recordPath) -cne $recordBefore -or
    $(if (Test-Path -LiteralPath $activePath) { Sha $activePath } else { '' }) -cne $fenceBefore) {
    throw 'Resume inspection mutated durable evidence'
}
if ($env:CA_FAULT) {
    if ($accepted) { throw 'Foreign, tampered, or live preparation was accepted' }
    if ($env:CA_FAULT -ceq 'audit_advanced' -and
        ($failure -cne 'FRESH_RESUME_CURRENT_AUDIT_REQUIRED' -or
         -not (Same ([string]$hint['receipt_path']) $nextPath) -or
         [string]$hint['receipt_sha256'] -cne (Sha $nextPath))) {
        throw 'The current supported receipt and its hash were lost'
    }
    'REJECTED'
} else {
    if (-not $accepted) { throw $failure }
    $expected=if ($resuming -and -not $env:CA_CUT.EndsWith('_fence')) { 'c'*32 } else { 'f'*32 }
    if ([string]$read.fresh_transition.attempt_id -cne $expected) { throw 'Resume selected the wrong attempt' }
    'RECOVERABLE'
}
''', values={"CA_CUT": cut, "CA_FAULT": fault})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("REJECTED" if fault else "RECOVERABLE")


@pytest.mark.parametrize('cut', ['initial_fence', 'resume_fence'])
def test_advanced_preparation_identifies_current_resume_receipt(tmp_path, cut):
    test_native_preparation_recovers_only_its_publication(tmp_path, cut, 'audit_advanced')


@pytest.mark.parametrize("cut", ["detach", "restore"])
def test_restore_reads_disk_when_rename_precedes_journal(transition, old_pc, monkeypatch, cut):
    app, _, archive = old_pc
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda *_: {})
    save = transition._save

    class PowerCut(BaseException):
        pass

    if cut == "restore":
        plan = transition.archive_state(plan, confirm_pending=True)

    def cut_after_rename(value):
        moved = [entry for entry in value["entries"] if not entry.get("shared_read_only")
                 and (Path(entry["inactive"]).exists() if cut == "detach"
                      else Path(entry["source"]).exists())]
        if moved:
            raise PowerCut
        return save(value)

    monkeypatch.setattr(transition, "_save", cut_after_rename)
    with pytest.raises(PowerCut):
        if cut == "detach":
            transition.archive_state(plan, confirm_pending=True)
        else:
            transition.restore_archive(plan)
    durable = json.loads((archive / "transition-journal.json").read_text(encoding="utf-8"))
    assert durable["phase"] == ("ARCHIVE_VERIFIED" if cut == "detach" else "DETACHED")
    assert all(entry["detached"] is (cut == "restore") for entry in durable["entries"]
               if not entry.get("shared_read_only"))
    monkeypatch.setattr(transition, "_save", save)

    restored = transition.restore_archive(durable)

    assert restored["phase"] == "RESTORE_PENDING_RELEASE"
    for entry in restored["entries"]:
        assert transition._same_files(Path(entry["source"]), entry, original=True)
        if not entry.get("shared_read_only"):
            assert not Path(entry["inactive"]).exists()


@pytest.mark.parametrize("after_save", [False, True])
def test_first_journal_publication_resumes_same_transition(transition, fresh_context, monkeypatch, after_save):
    save = transition._save
    cut = False

    class PowerCut(BaseException):
        pass

    def stop_at_first_journal(plan):
        nonlocal cut
        if not cut and plan["phase"] == "PLANNED":
            cut = True
            if after_save:
                save(plan)
            raise PowerCut
        return save(plan)

    monkeypatch.setattr(transition, "_save", stop_at_first_journal)
    with pytest.raises(PowerCut):
        fresh_context.prepare()
    assert not transition._pointer_path().exists()
    journal = fresh_context.archive / "transition-journal.json"
    assert journal.exists() is after_save
    original = json.loads(journal.read_text()) if after_save else None
    result = fresh_context.prepare()
    assert result["phase"] == "DETACHED" and result["transition_id"] == "b" * 32
    if original:
        assert result["candidate"] == original["candidate"]
