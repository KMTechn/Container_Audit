"""A repeated release must be backed by the same authorization and receipt."""
import json

import pytest

from tests.powershell_contracts import run_functions
from tests.test_machine_install_completed_recovery import INSTALLER
from tests.test_machine_completed_owner_identity import completed_fixture
from tests.test_machine_operation_completed_recovery import RUN_STAGE, SUMMARY_FILE


CASES = [
    ("INSTALL", "authorization_only"), ("INSTALL_COMPENSATED", "authorization_only"),
    ("INSTALL", "prepared_only"), ("INSTALL_COMPENSATED", "prepared_only"),
    ("INSTALL", "pre_auth_audit"), ("INSTALL", "pre_auth_tuple"),
    ("INSTALL", "pre_auth_phase"), ("INSTALL", "pre_auth_inventory"),
    ("INSTALL", "authorization_changed"), ("INSTALL", "authorization_missing"),
    ("INSTALL", "release_missing"), ("INSTALL", "release_tuple_differs"),
    ("INSTALL", "legacy_guid_only"), ("INSTALL", "foreign_fence"),
    ("INSTALL", "audit_changed"), ("INSTALL", "owner_active_after_release"),
    ("INSTALL", "owner_unknown_after_release"), ("INSTALL", "child_active_after_release"),
    ("INSTALL", "child_unknown_after_release"), ("INSTALL", "result_changed"),
    ("UNINSTALL", "result_changed"), ("RESTORE_VERIFIED_REPLACEMENT", "result_changed"),
    ("INSTALL_COMPENSATED", "result_changed"), ("UNINSTALL_COMPENSATED", "result_changed"),
    ("INSTALL", "evidence_output"),
]

PROBE = r"""
$probe=$env:CA_RELEASE_PROBE
$probePhase=$env:CA_RELEASE_PROBE_PHASE
$authorizationPath=Join-Path $state ('install-audit\recovered-release-'+$run+'.json')
if($probe -ceq 'evidence_output') {$EvidencePath=Join-Path $state 'completed-recovery-evidence.json'}
if($probePhase -ceq 'prime') {
    $Script:CanonicalWriterFenceSessionId=[string]$ids.session
    $Script:CanonicalWriterFenceAttemptId=[string]$ids.attempt
    $Script:CanonicalWriterFenceTransactionId=$run
    $saved=Get-Content -LiteralPath $auditPath -Raw -Encoding UTF8|ConvertFrom-Json
    $phase=if($saved.status -ceq 'MACHINE_INSTALL_FAILED'){'ROLLBACK_COMPLETE'}else{'PRODUCT_COMPLETE'}
    $authorization=New-CanonicalWriterFenceReleaseAuthorization $authorizationPath $phase $auditPath
    if($probe -like 'pre_auth_*') {
        $changed=Get-Content -LiteralPath $authorizationPath -Raw -Encoding UTF8|ConvertFrom-Json
        switch($probe) {
            'pre_auth_audit' {$changed.install_audit_sha256='0'*64}
            'pre_auth_tuple' {$changed.attempt_id=[Guid]::NewGuid().ToString('N')}
            'pre_auth_phase' {$changed.phase='ROLLBACK_COMPLETE'}
            'pre_auth_inventory' {$changed.writer_inventory_sha256='0'*64}
        }
        Save $authorizationPath $changed
    }
    if($probe -ceq 'prepared_only') {
        $primeAuthority=Enter-ContainerWriterSessionAuthority -SessionId $ids.session -AttemptId $ids.attempt -OrchestratorSha256 (Sha $originalSource) -ReplacementTransactionId $run -WriterContractSha256 $ids.contract -RecoverExisting
        try {
            [void](Set-ContainerWriterFencePrepared -ControlRoot $control -SessionId $ids.session -AttemptId $ids.attempt -ReplacementTransactionId $run -PreparedReceiptPath $authorization.path -PreparedReceiptSha256 $authorization.sha256 -Status 'PREPARED' -AuthorityLease $primeAuthority)
        } finally {Exit-ContainerWriterSessionAuthority $primeAuthority}
    }
    return
}
if($probePhase -ceq 'mutate') {
    $saved=Get-Content -LiteralPath $auditPath -Raw -Encoding UTF8|ConvertFrom-Json
    switch($probe) {
        'authorization_changed' {
            $changed=Get-Content -LiteralPath $authorizationPath -Raw -Encoding UTF8|ConvertFrom-Json
            $changed.install_audit_sha256='0'*64;Save $authorizationPath $changed
        }
        'authorization_missing' {[IO.File]::Delete($authorizationPath)}
        'legacy_guid_only' {[IO.File]::Move($authorizationPath,($authorizationPath.Replace('.json','-')+[Guid]::NewGuid().ToString('N')+'.json'))}
        'release_missing' {foreach($entry in @(Get-ChildItem -LiteralPath $control -Filter 'release-*.json' -File)){[IO.File]::Delete($entry.FullName)}}
        'release_tuple_differs' {
            $entry=@(Get-ChildItem -LiteralPath $control -Filter 'release-*.json' -File)[0]
            $changed=Get-Content -LiteralPath $entry.FullName -Raw -Encoding UTF8|ConvertFrom-Json
            $changed.attempt_id=[Guid]::NewGuid().ToString('N');Save $entry.FullName $changed
        }
        'foreign_fence' {
            $newSession=[Guid]::NewGuid().ToString('N');$newAttempt=[Guid]::NewGuid().ToString('N');$newRun=[Guid]::NewGuid().ToString('N')
            $foreign=Enter-ContainerWriterSessionAuthority -SessionId $newSession -AttemptId $newAttempt -OrchestratorSha256 (Sha $originalSource) -ReplacementTransactionId $newRun -WriterContractSha256 $ids.contract
            try {
                [void](Start-ContainerWriterFence -ControlRoot $control -Status 'INSTALLING' -OwnerKind 'canonical_installer' -SessionId $newSession -AttemptId $newAttempt -ReplacementTransactionId $newRun -SessionStartedAtUtc ([DateTime]::UtcNow.ToString('o')) -OrchestratorSha256 (Sha $originalSource) -WriterContractSha256 $ids.contract -PreparedReceiptPath ([string]$saved.machine_prestate.path) -PreparedReceiptSha256 (Sha ([string]$saved.machine_prestate.path)) -AuthorityLease $foreign)
            } finally {Exit-ContainerWriterSessionAuthority $foreign}
        }
        'audit_changed' {$saved.source_commit='f'*40;Save $auditPath $saved}
        'result_changed' {
            if($saved.status -ceq 'PASS_UNINSTALLED_DATA_PRESERVED') {
                $retained=[string]$saved.retained_paths[0]
                if(Test-Path -LiteralPath $retained -PathType Container){[IO.Directory]::Move($retained,($retained+'.moved'))}else{[IO.File]::Move($retained,($retained+'.moved'))}
            } elseif($saved.status -ceq 'PASS_RESTORED_VERIFIED') {
                [IO.File]::AppendAllText([string]$saved.code_replacement.restore_evidence_path,' ')
            } else {[IO.File]::AppendAllText((Join-Path $root 'portable-manifest.json'),' ')}
        }
    }
    return
}
if($probePhase -ceq 'second') {
    switch($probe) {
        'owner_active_after_release' {[KMTechInstallationChildCapture]::OwnerObservedStart='2026-01-01T00:00:00.0000000Z'}
        'owner_unknown_after_release' {[KMTechInstallationChildCapture]::OwnerUnreadable=$true}
        'child_active_after_release' {$case='live_child'}
        'child_unknown_after_release' {$case='process_unknown'}
    }
}
"""


def state_files(tmp_path):
    audit = list(tmp_path.rglob("canonical-portable-*.json"))
    assert len(audit) == 1
    return audit[0].parent.parent


def snapshot(folder):
    return {str(path.relative_to(folder)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in folder.rglob("*") if path.is_file()}


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("kind,scenario", CASES)
def test_completed_release_proof_is_reused_and_rechecked(tmp_path, engine, kind, scenario):
    functions, driver, values = completed_fixture(kind, "completed")
    assert driver.count("$codeBefore=") == 1
    driver = driver.replace("$codeBefore=", PROBE + "\n$codeBefore=", 1)
    values["CA_RELEASE_PROBE"] = scenario
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "release fixture setup failed"
    values["CA_COMPLETED_STAGE"] = RUN_STAGE
    before_stop = scenario in ("authorization_only", "prepared_only") or scenario.startswith("pre_auth_")
    values["CA_RELEASE_PROBE_PHASE"] = "prime" if before_stop else "first"
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "release priming failed"
    state = state_files(tmp_path)
    if before_stop:
        authorization = list((state / "install-audit").glob("recovered-release-*.json"))
        assert len(authorization) == 1
        authorization_before = (authorization[0].read_bytes(), authorization[0].stat().st_mtime_ns)
    else:
        first = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8-sig"))
        assert not first["code"] and not first["fence_present"], "initial completed release failed"
        values["CA_RELEASE_PROBE_PHASE"] = "mutate"
        result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
        assert result.returncode == 0, "release mutation failed"
    before = snapshot(state)
    values["CA_RELEASE_PROBE_PHASE"] = "second"
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "release recovery driver failed"
    summary = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8-sig"))
    assert summary["restored"] == summary["audit_writes"] == 0
    assert summary["audit_preserved"] and summary["code_preserved"]
    if scenario in ("authorization_only", "prepared_only"):
        assert not summary["code"] and not summary["fence_present"]
        assert (authorization[0].read_bytes(), authorization[0].stat().st_mtime_ns) == authorization_before
        before = snapshot(state)
        result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
        assert result.returncode == 0
        repeated = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8-sig"))
        assert not repeated["code"] and repeated["public_code"] == "PASS_MACHINE_RECOVERED"
        assert repeated["restored"] == repeated["audit_writes"] == 0
        assert snapshot(state) == before, "idempotent recovery must not rewrite any state proof"
    elif scenario == "evidence_output":
        assert not summary["code"] and summary["public_code"] == "PASS_MACHINE_RECOVERED"
        assert snapshot(state) == before, "a released retry must not rewrite an explicit evidence output"
    else:
        assert summary["code"], "unbound, live, or changed release evidence must refuse"
        assert summary["fence_present"] == (before_stop or scenario == "foreign_fence")
        assert snapshot(state) == before, "refusal must preserve all release state proof bytes and mtimes"
