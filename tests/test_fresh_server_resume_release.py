"""Finish only the exact old transition after its controller exits at release."""
import hashlib
import json
from pathlib import Path

import pytest

import writer_session_fence as fence
from tests.powershell_contracts import run_functions
from tests.test_fresh_server_registration import fresh_context, old_pc, transition


@pytest.mark.parametrize("phase", ["PRODUCT_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_NATURAL_TRIGGER"])
@pytest.mark.parametrize("cut", ["prepared", "released"])
@pytest.mark.parametrize("fault", ["", "foreign", "foreign_fence", "tampered", "live_owner"])
def test_native_fresh_resume_recognizes_only_its_release(tmp_path, phase, cut, fault):
    source = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"
    result = run_functions(tmp_path, source, [
        "Full", "Same", "Sha", "Save", "Test-JsonTrue", "Test-JsonInteger", "Test-JsonPositiveInt32",
        "Test-ExactPropertySet", "Test-ExactStringProperties", "Assert-RetirementOwnerExited",
        "Read-CanonicalFreshResume", "New-CanonicalWriterFenceReleaseAuthorization",
        "Complete-CanonicalFreshReleasedResume", "Enter-RetirementResumeClaim", "Exit-RetirementResumeClaim",
        "Assert-RollbackRelayPreimage",
    ], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
# An extracted function has no automatic PSCommandPath; bind only that missing
# fixture value to the real source while retaining actual byte hashing.
function Sha([string]$Path) {
    if (-not $Path) { $Path=$env:CA_CONTRACT_SOURCE }
    return Get-KmtechFileSha $Path
}
$install=Join-Path $env:CA_CONTRACT_ROOT 'current'
$FreshArchiveRoot=Join-Path $env:CA_CONTRACT_ROOT 'archive'
[void](New-Item -ItemType Directory -Path $install,$FreshArchiveRoot)
$FreshTransitionInput=Join-Path $env:CA_CONTRACT_ROOT 'input.json'
Set-Content -LiteralPath $FreshTransitionInput -Value '{}' -Encoding UTF8
$FreshTransitionId='b'*32
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sourceManifestSha256='c'*64
$lifecycleManifest=@{writer_session_contract_sha256='d'*64}
$stop=Join-Path $env:CA_CONTRACT_ROOT 'absent.stop'
$session='a'*32; $attempt='c'*32; $transaction='d'*32
$orchestrator=Sha $env:CA_CONTRACT_SOURCE
$prepared=Join-Path $env:CA_CONTRACT_ROOT 'prepared.json'
Set-Content -LiteralPath $prepared -Value '{}' -Encoding UTF8
$ownerId=2147483000; $ownerStart='2025-01-01T00:00:00.0000000Z'
if ($env:CA_FAULT -ceq 'live_owner') {
    $ownerId=$PID; $ownerStart=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')
}
$ResumeFreshTransitionReceiptPath=Join-Path $env:CA_CONTRACT_ROOT 'canonical-portable-test.json'
$prior=[ordered]@{
    schema='container-audit-canonical-portable-install-v2'; operation='PREPARE_FRESH_SERVER_REGISTRATION'
    install_root=$install; source_manifest_sha256=$sourceManifestSha256; run_id='test'
    status='FRESH_TRANSITION_AWAITING_FENCE_RELEASE'
    code_replacement=@{transaction_id=$transaction}
    fresh_transition=@{transition_id=$FreshTransitionId;sid=$operatorSid;input_sha256=(Sha $FreshTransitionInput)
        archive_root=$FreshArchiveRoot;orchestrator_sha256=$orchestrator;session_id=$session;attempt_id=$attempt
        quiesced=$true;prepared_receipt_path=$prepared;prepared_receipt_sha256=(Sha $prepared)
        authority_mutex_name=(Get-ContainerWriterSessionAuthorityMutexName $session $attempt $orchestrator $transaction $lifecycleManifest.writer_session_contract_sha256)
        owner_process_id=$ownerId;owner_started_at_utc=$ownerStart;stop_sha256=''
        original_preimage=@{exists=$false;kind='';data=''};original_relays=@()
        original_scheduled_writer=@{present=$false}
    }
}
Save $ResumeFreshTransitionReceiptPath $prior
$ResumeFreshTransitionReceiptSha256=Sha $ResumeFreshTransitionReceiptPath
$Script:CanonicalWriterFenceSessionId=$session
$Script:CanonicalWriterFenceAttemptId=$attempt
$Script:CanonicalWriterFenceTransactionId=$transaction
$suffix=if ($env:CA_PHASE -ceq 'PRODUCT_COMPLETE') { 'product-complete' } else { 'rollback-complete' }
$releasePath=Join-Path $env:CA_CONTRACT_ROOT ('canonical-portable-test-'+$suffix+'-release.json')
$baseline=if ($env:CA_PHASE -ceq 'ROLLBACK_NATURAL_TRIGGER') {
    @{readback=@{task_name='owned';task_path='\';binding_sha256=('e'*64)};future_natural_trigger_utc='2030-01-01T00:00:00Z'}
} else { $null }
$authorization=New-CanonicalWriterFenceReleaseAuthorization $releasePath $env:CA_PHASE $ResumeFreshTransitionReceiptPath $baseline
$journalPhase=if ($env:CA_PHASE -ceq 'PRODUCT_COMPLETE') { 'ACTIVATION_PENDING_RELEASE' } else { 'RESTORE_PENDING_RELEASE' }
Save (Join-Path $FreshArchiveRoot 'transition-journal.json') @{schema='container-audit-fresh-server-transition-v1';phase=$journalPhase;sid=$operatorSid;transition_id=$FreshTransitionId}
$payload=New-ContainerWriterFencePayload -Status 'PREPARED' -OwnerKind 'canonical_installer' `
    -SessionId $session -AttemptId $attempt -ReplacementTransactionId $transaction `
    -SessionStartedAtUtc '2025-01-01T00:00:00Z' -OrchestratorSha256 $orchestrator `
    -WriterContractSha256 $lifecycleManifest.writer_session_contract_sha256 `
    -PreparedReceiptPath $releasePath -PreparedReceiptSha256 $authorization.sha256
if ($env:CA_CUT -ceq 'original_prepared') {
    $payload.prepared_receipt_path=$prepared
    $payload.prepared_receipt_sha256=Sha $prepared
}
[void](Write-ContainerWriterFenceAtomic '' $payload)
if ($env:CA_CUT -ceq 'released') {
    $authority=Enter-ContainerWriterSessionAuthority -SessionId $session -AttemptId $attempt `
        -OrchestratorSha256 $orchestrator -ReplacementTransactionId $transaction `
        -WriterContractSha256 $lifecycleManifest.writer_session_contract_sha256
    try {
        [void](Stop-ContainerWriterFence -SessionId $session -AttemptId $attempt -ReplacementTransactionId $transaction `
            -ReleaseAuthorizationPath $releasePath -ReleaseAuthorizationSha256 $authorization.sha256 -AuthorityLease $authority)
    } finally { Exit-ContainerWriterSessionAuthority $authority }
}
if ($env:CA_FAULT -ceq 'foreign') {
    $data=Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    $data.attempt_id='e'*32
    Save $releasePath $data
} elseif ($env:CA_FAULT -ceq 'tampered') {
    $data=Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    $data.install_audit_sha256='f'*64
    Save $releasePath $data
} elseif ($env:CA_FAULT -ceq 'foreign_fence') {
    $payload.attempt_id='e'*32
    $payload.session_authority_mutex_name=Get-ContainerWriterSessionAuthorityMutexName `
        $session $payload.attempt_id $orchestrator $transaction $lifecycleManifest.writer_session_contract_sha256
    [void](Write-ContainerWriterFenceAtomic '' $payload)
}
$activePath=Get-ContainerWriterFenceActivePath
$fenceBefore=if (Test-Path -LiteralPath $activePath) { Sha $activePath } else { '' }
$wanted='synthetic exact current-user command'
$script:observedRelays=@()
$script:completed=$false
function Snapshot {
    if ($env:CA_PHASE -ceq 'PRODUCT_COMPLETE') { return @{exists=$true;kind='String';data=$wanted} }
    return @{exists=$false;kind='';data=''}
}
function Relays { return $script:observedRelays }
function StartRaw([string]$Command) {
    if ($null -ne (Read-ContainerWriterFence -AllowAbsent)) { throw 'relay started behind fence' }
    $script:observedRelays += [pscustomobject]@{ExecutablePath=(Join-Path $install 'runtime\pythonw.exe');CommandLine=$Command}
    return 123
}
function Start-Sleep { param($Seconds) }
function Product {
    param($Root,$Mode,$Action)
    if ($Action -cne 'complete' -or $null -ne (Read-ContainerWriterFence -AllowAbsent)) { throw 'completed before release' }
    $script:completed=$true
}
try {
    $value=Read-CanonicalFreshResume
    if ($env:CA_FAULT) { throw 'unexpected acceptance' }
    if ($env:CA_CUT -ceq 'original_prepared') {
        if ($null -ne $value.resume_release -or (Sha $activePath) -cne $fenceBefore) { throw 'original prepared fence changed' }
        'ACCEPTED_BOUND_RELEASE'
        return
    }
    if ($value.resume_release.phase -cne $env:CA_PHASE -or
        [bool]$value.resume_release.released -ne ($env:CA_CUT -ceq 'released')) { throw 'release readback missing' }
    Complete-CanonicalFreshReleasedResume $value
    if (-not $script:completed -or $null -ne (Read-ContainerWriterFence -AllowAbsent)) { throw 'ordinary writer remains fenced' }
    Complete-CanonicalFreshReleasedResume $value
    if (@(Relays).Count -gt 1) { throw 'duplicate resume duplicated the relay' }
    'ACCEPTED_BOUND_RELEASE'
} catch {
    if (-not $env:CA_FAULT -or $_.Exception.Message -ceq 'unexpected acceptance') { throw }
    if ($env:CA_FAULT -ceq 'live_owner' -and $_.Exception.Message -cne 'RETIREMENT_ORIGINAL_OWNER_STILL_LIVE') { throw }
    $fenceAfter=if (Test-Path -LiteralPath $activePath) { Sha $activePath } else { '' }
    if ($fenceBefore -cne $fenceAfter) { throw 'refusal changed the active fence' }
    'REJECTED_PRESERVED'
}
''', values={"CA_PHASE": phase, "CA_CUT": cut, "CA_FAULT": fault})
    assert result.returncode == 0, result.stderr
    assert ("REJECTED_PRESERVED" if fault else "ACCEPTED_BOUND_RELEASE") in result.stdout


def test_native_original_prepared_resume_is_preserved(tmp_path):
    test_native_fresh_resume_recognizes_only_its_release(tmp_path, "PRODUCT_COMPLETE", "original_prepared", "")


@pytest.mark.parametrize("action", ["preflight", "complete"])
def test_native_product_forwards_completion_or_resume_proof(tmp_path, action):
    source = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"
    result = run_functions(tmp_path, source, ["Arg", "Product"], r'''
$FreshTransitionInput=Join-Path $env:CA_CONTRACT_ROOT 'input.json'
$FreshArchiveRoot=Join-Path $env:CA_CONTRACT_ROOT 'archive'
$FreshTransitionId='a'*32
$ConfirmFreshServerRegistration='confirmed fixture'
$ConfirmArchivePending=$false
$ResumeFreshTransitionReceiptPath=Join-Path $env:CA_CONTRACT_ROOT 'receipt with space.json'
$releaseAuthorization=@{path=(Join-Path $env:CA_CONTRACT_ROOT 'release with space.json');sha256=('b'*64)}
if ($env:CA_ACTION -ceq 'complete') { $auditPath=$ResumeFreshTransitionReceiptPath }
function Start-Process {
    param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru)
    $script:arguments=$ArgumentList
    $process=[pscustomobject]@{ExitCode=0}
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }
    return $process
}
[void](Product $env:CA_CONTRACT_ROOT '--fresh-server-registration' $env:CA_ACTION)
$script:arguments | ConvertTo-Json -Compress
''', values={"CA_ACTION": action})
    assert result.returncode == 0, result.stderr
    command = json.loads(result.stdout)
    assert f'--lifecycle-receipt "{tmp_path / "receipt with space.json"}"' in command
    if action == "complete":
        assert f'--release-authorization-path "{tmp_path / "release with space.json"}"' in command
        assert "--release-authorization-sha256" in command and "b" * 64 in command
    else:
        assert "--release-authorization-path" not in command


def test_incomplete_public_preflight_requires_original_receipt(transition, fresh_context):
    fresh_context.prepare()
    target = fresh_context.target
    confirm = f"이 PC의 옛 자료를 보관하고 {target['origin']} / {target['scope']} / {target['deployment_id']}에 새로 등록합니다"
    arguments = ["--app-root", str(fresh_context.app), "--action", "preflight", "--input", str(fresh_context.input),
                 "--archive-root", str(fresh_context.archive), "--transition-id", "b" * 32, "--confirm", confirm]
    assert transition.transition_main(arguments) == 4
    assert transition.transition_main(arguments + ["--lifecycle-receipt", str(fresh_context.app.parent / "lifecycle.json")]) == 10


def _release_fixture(transition, plan, phase):
    receipt = Path(plan["lifecycle_receipt"])
    receipt.parent.mkdir(parents=True, exist_ok=True)
    audit = {"schema": "container-audit-canonical-portable-install-v2",
             "operation": "PREPARE_FRESH_SERVER_REGISTRATION",
             "fresh_transition": {"transition_id": plan["transition_id"], "sid": plan["sid"],
                                  "quiesced": True, "session_id": "a" * 32, "attempt_id": "b" * 32},
             "code_replacement": {"transaction_id": "c" * 32}}
    receipt.write_text(json.dumps(audit))
    authorization = receipt.parent / "release-authorization.json"
    data = {"schema": "container-audit-writer-release-authorization-v1", "status": "AUTHORIZED",
            "app_id": "container_audit", "phase": phase, "session_id": "a" * 32,
            "attempt_id": "b" * 32, "replacement_transaction_id": "c" * 32,
            "writer_inventory_sha256": fence.WRITER_INVENTORY_SHA256,
            "install_audit_path": str(receipt), "install_audit_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest()}
    authorization.write_text(json.dumps(data))
    digest = hashlib.sha256(authorization.read_bytes()).hexdigest()
    release_path = fence.canonical_control_root() / ("release-" + "c" * 32 + "-" + digest + ".json")
    release_path.parent.mkdir(parents=True, exist_ok=True)
    released = {"schema": fence.RELEASE_SCHEMA, "status": "RELEASED", "app_id": "container_audit",
                "session_id": "a" * 32, "attempt_id": "b" * 32, "replacement_transaction_id": "c" * 32,
                "writer_inventory_sha256": fence.WRITER_INVENTORY_SHA256,
                "release_authorization_path": str(authorization), "release_authorization_sha256": digest,
                "released_at_utc": "2026-09-26T00:00:00Z", "secret_values_recorded": False}
    release_path.write_text(json.dumps(released))
    return authorization, digest, release_path


@pytest.mark.parametrize("phase,release_phase,final", [
    ("ACTIVATION_PENDING_RELEASE", "PRODUCT_COMPLETE", "ACTIVATED"),
    ("RESTORE_PENDING_RELEASE", "ROLLBACK_COMPLETE", "RESTORED"),
])
@pytest.mark.parametrize("fault", ["", "active_fence", "missing_receipt", "foreign", "audit"])
def test_final_phase_requires_bound_release_and_opens_ordinary_writer(transition, fresh_context, monkeypatch,
                                                                   phase, release_phase, final, fault):
    plan = fresh_context.prepare()
    plan["phase"] = phase
    transition._save(plan)
    authorization, digest, receipt = _release_fixture(transition, plan, release_phase)
    if fault == "active_fence":
        monkeypatch.setattr(transition, "active_fence", lambda: {"status": "INSTALLING"})
    elif fault == "missing_receipt":
        receipt.unlink()
    elif fault == "foreign":
        data = json.loads(receipt.read_text())
        data["attempt_id"] = "d" * 32
        receipt.write_text(json.dumps(data))
    elif fault == "audit":
        Path(plan["lifecycle_receipt"]).write_text("{}")
    before = transition._journal_path(plan).read_bytes()
    if fault:
        with pytest.raises(ValueError):
            transition.finalize_transition(plan, authorization, digest)
        assert transition._journal_path(plan).read_bytes() == before
    else:
        assert transition.finalize_transition(plan, authorization, digest)["phase"] == final
        assert transition.current_transition()["phase"] == final
        assert transition.finalize_transition(plan, authorization, digest)["phase"] == final
        with fence.writer_admission("current_user_onboarding_storage"):
            assert fence.active_fence() is None
