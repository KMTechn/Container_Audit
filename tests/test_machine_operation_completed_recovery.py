"""Terminal removal and replacement restore read their own persisted results."""
import json
import re
from contextlib import nullcontext

import pytest

from tests.powershell_contracts import run_functions
from tests.test_container_writer_session import _held_session_authority
from tests.test_machine_install_completed_recovery import DRIVER, FUNCTIONS, INSTALLER

SETUP_STAGE = 'setup'
RUN_STAGE = 'recover'
IDS_FILE = 'ids.json'
SUMMARY_FILE = 'completed-result.json'
AUTHORITY_KEY = 'authority'

_RESULT_SETUP = r"""
$resultOperation=$env:CA_RESULT_OPERATION
$application=Split-Path -Parent $root
$dataPath=Join-Path $base 'business-data\records.dat'
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $dataPath))
[IO.File]::WriteAllText($dataPath,'retained business fixture',[Text.UTF8Encoding]::new($false))
$prestate.before_manifest_sha256=Sha (Join-Path $root 'portable-manifest.json')
$prestate.operation=$resultOperation
$audit.operation=$resultOperation
if($resultOperation -eq 'UNINSTALL') {
    $prestate.removal_recovery=@{schema='container-audit-machine-removal-recovery-v1';application=$application;
        evidence_parent=(Join-Path $application 'removal-evidence');journal_name='removal-move-journal.jsonl';run_id=$run}
    [IO.Directory]::Delete($root,$true)
    $removalEvidence=Join-Path (Join-Path $application 'removal-evidence') ([Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($removalEvidence)
    $header=@{record='HEADER';schema='container-audit-removal-move-journal-v1';run_id=$run;application=$application;evidence=$removalEvidence;secret_values_recorded=$false}
    if($case -eq 'journal_run_differs'){$header.run_id=('f'*32)}
    [IO.File]::WriteAllText((Join-Path $removalEvidence 'removal-move-journal.jsonl'),(($header|ConvertTo-Json -Depth 4 -Compress)+[char]10),[Text.UTF8Encoding]::new($false))
    $markerPath=Join-Path $application 'removed.json'
    $marker=@{schema='container-audit-supported-removal-v1';lifecycle_state='REMOVED';evidence_root=$removalEvidence;
        business_data_and_registration_preserved=$true;retained_paths=@($dataPath)}
    if($case -eq 'marker_schema_differs'){$marker.schema='unsupported-removal'}
    if($case -eq 'marker_preservation_false'){$marker.business_data_and_registration_preserved=$false}
    Save $markerPath $marker
    if($case -in @('marker_at_limit','marker_oversized')) {
        $limit=131072+$(if($case -eq 'marker_oversized'){1}else{0})
        $padding=$limit-(Get-Item -LiteralPath $markerPath).Length
        [IO.File]::AppendAllText($markerPath,(' '*$padding),[Text.UTF8Encoding]::new($false))
    }
    $audit.status='PASS_UNINSTALLED_DATA_PRESERVED'
    $audit.retained_paths=@($dataPath);$audit.removal_evidence_root=$removalEvidence
    $audit.removal_marker_path=$markerPath;$audit.removal_marker_sha256=Sha $markerPath
    if($case -eq 'marker_hash_differs'){$audit.removal_marker_sha256=('0'*64)}
    if($case -eq 'retained_list_differs') {
        $other=Join-Path $base 'business-data\other.dat';[IO.File]::WriteAllText($other,'other retained fixture')
        $audit.retained_paths=@($other)
    }
    if($case -eq 'missing_retained_path'){[IO.File]::Delete($dataPath)}
    if($case -eq 'uninstalled_current_present'){Save (Join-Path $root 'portable-manifest.json') $manifest}
    if($case -eq 'legacy_unbound') {
        foreach($name in @('retained_paths','removal_evidence_root','removal_marker_path','removal_marker_sha256')){$audit.Remove($name)}
    }
} else {
    $restoredManifest=Get-Content -LiteralPath (Join-Path $root 'portable-manifest.json') -Raw|ConvertFrom-Json
    $restoredManifest.source_commit=('b'*40)
    Save (Join-Path $root 'portable-manifest.json') $restoredManifest
    $receiptPath=Join-Path $state ('install-audit\original-replacement-'+$run+'.json')
    $oldTransaction=[Guid]::NewGuid().ToString('N')
    $receipt=@{transaction_id=$oldTransaction;install_root=$root;old=@{manifest_sha256=Sha (Join-Path $root 'portable-manifest.json')}}
    if($case -eq 'restore_receipt_root_differs'){$receipt.install_root=Join-Path $base 'other-current'}
    Save $receiptPath $receipt
    $restoreEvidencePath=Join-Path $state ('install-audit\restore-'+$run+'.json')
    $restoreEvidence=@{schema_version='container-audit-verified-replacement-code-restore-v1';status='PASS';action='RESTORED';app_id='container_audit';
        transaction_id=$oldTransaction;receipt_path=$receiptPath;receipt_sha256=Sha $receiptPath;install_root=$root;
        failed_new_root=(Join-Path $base 'failed-new');prior_code_exact=$true;failed_new_preserved=$true;identity_or_credential_copied=$false;
        completed_at=[DateTime]::UtcNow.ToString('o')}
    if($case -eq 'restore_evidence_binding_differs'){$restoreEvidence.transaction_id=('f'*32)}
    Save $restoreEvidencePath $restoreEvidence
    $audit.status='PASS_RESTORED_VERIFIED'
    $audit.code_replacement.receipt_path=$receiptPath;$audit.code_replacement.receipt_sha256=Sha $receiptPath
    $audit.code_replacement.restore_evidence_path=$restoreEvidencePath;$audit.code_replacement.restore_evidence_sha256=Sha $restoreEvidencePath
    if($case -eq 'restore_target_differs'){$restoredManifest.source_commit=('c'*40);Save (Join-Path $root 'portable-manifest.json') $restoredManifest}
    if($case -eq 'restore_receipt_changed'){[IO.File]::AppendAllText($receiptPath,[string][char]10)}
    if($case -eq 'restore_evidence_changed'){[IO.File]::AppendAllText($restoreEvidencePath,[string][char]10)}
    if($case -eq 'legacy_operation_absent'){$prestate.Remove('operation')}
    if($case -eq 'legacy_unbound') {
        foreach($name in @('receipt_sha256','restore_evidence_path','restore_evidence_sha256')){$audit.code_replacement.Remove($name)}
    }
}
Save $journal $prestate
$audit.machine_prestate.sha256=Sha $journal
"""
RESULT_DRIVER = DRIVER.replace("$auditPath=Join-Path", _RESULT_SETUP + "\n$auditPath=Join-Path", 1)
RESULT_DRIVER = re.sub(
    r"(?m)^\$codeBefore=.*$",
    "$codeBefore=if(Test-Path -LiteralPath $root){Sha (Join-Path $root 'portable-manifest.json')}else{'ABSENT'}",
    RESULT_DRIVER,
)
RESULT_DRIVER = re.sub(
    r"code_preserved=[^;\r\n]*",
    "code_preserved=($codeBefore -ceq $(if(Test-Path -LiteralPath $root){Sha (Join-Path $root 'portable-manifest.json')}else{'ABSENT'}))",
    RESULT_DRIVER,
)

COMMON = [
    ("completed", True), ("owner_alive", False), ("tuple_differs", False),
    ("live_child", False), ("process_unknown", False),
    ("recorded_child_exited", True), ("recorded_child_alive", False),
    ("recorded_child_unknown", False), ("legacy_unbound", False),
]
CASES = [(op, case, accepted) for op in ("UNINSTALL", "RESTORE_VERIFIED_REPLACEMENT") for case, accepted in COMMON]
CASES += [("UNINSTALL", case, accepted) for case, accepted in (
    ("missing_retained_path", False), ("marker_hash_differs", False),
    ("marker_schema_differs", False), ("marker_preservation_false", False),
    ("uninstalled_current_present", False), ("journal_run_differs", False),
    ("marker_at_limit", True), ("marker_oversized", False), ("retained_list_differs", False),
)]
CASES += [("RESTORE_VERIFIED_REPLACEMENT", case, False) for case in (
    "restore_target_differs", "restore_receipt_changed", "restore_evidence_changed",
    "restore_evidence_binding_differs", "legacy_operation_absent", "restore_receipt_root_differs",
)]


def run_result_recovery(tmp_path, engine, operation, case, *, setup=True):
    values = {"CA_COMPLETED_STAGE": SETUP_STAGE if setup else RUN_STAGE,
              "CA_COMPLETED_CASE": case, "CA_RESULT_OPERATION": operation}
    if setup:
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, RESULT_DRIVER, values=values, engine=engine)
        assert result.returncode == 0, "terminal-result fixture setup failed"
        ids = json.loads((tmp_path / IDS_FILE).read_text(encoding="utf-8"))
        # The normal recovery-stage assertion below checks the actual audit too.
    ids = json.loads((tmp_path / IDS_FILE).read_text(encoding="utf-8"))
    authority = _held_session_authority(ids[AUTHORITY_KEY]) if case == "owner_alive" else nullcontext()
    with authority:
        values["CA_COMPLETED_STAGE"] = RUN_STAGE
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, RESULT_DRIVER, values=values, engine=engine)
    assert result.returncode == 0, "terminal-result recovery driver failed"
    summary = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8"))
    assert summary["audit_spaced"], "audit must use indented ConvertTo-Json"
    return summary


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("operation,case,accepted", CASES)
def test_completed_operation_only_releases_its_verified_result(tmp_path, engine, operation, case, accepted):
    summary = run_result_recovery(tmp_path, engine, operation, case)
    assert summary["restored"] == summary["audit_writes"] == 0
    assert summary["audit_preserved"] and summary["code_preserved"]
    if accepted:
        assert summary["code"] == "", "verified terminal result was not recovered"
        assert not summary["fence_present"]
        assert summary["release_receipts"] == 1
        assert summary["process_checks"] > 0
        assert summary["public_code"] == "PASS_MACHINE_RECOVERED"
        if operation == "RESTORE_VERIFIED_REPLACEMENT":
            assert summary["integrity_checks"] > 0
    else:
        expected = {
            "owner_alive": "CONTAINER_WRITER_SESSION_AUTHORITY_ALREADY_EXISTS",
            "tuple_differs": "MACHINE_RECOVERY_AUTHORITY_BINDING_DIFFERS",
            "live_child": "MACHINE_RECOVERY_CHILD_UNRECORDED",
            "process_unknown": "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN",
            "recorded_child_alive": "MACHINE_RECOVERY_CHILD_ACTIVE",
            "recorded_child_unknown": "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN",
        }
        if case in expected:
            assert summary["code"] == expected[case]
        else:
            assert summary["code"].startswith("MACHINE_RECOVERY_")
        assert summary["fence_present"]
        assert summary["release_receipts"] == 0
