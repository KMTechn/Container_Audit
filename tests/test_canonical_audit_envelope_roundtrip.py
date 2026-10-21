import hashlib
import json

import pytest
from tests.powershell_contracts import run_functions
from tests.test_canonical_audit_timestamp_binding import ENGINES, STAMPS, _record
from tests.test_general_completed_release_recovery import INSTALLER


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("stamp", STAMPS)
def test_private_audit_redaction_keeps_original_time_bytes(tmp_path, engine, stamp):
    payload = {
        "status": "RESTORE_AWAITING_FENCE_RELEASE",
        "completed_fence_release": {"fence": {"session_started_at_utc": stamp}},
        "failure": {"password": "[REDACTED:field]"},
    }
    expected = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    script = r'''
$payload=$env:CA_AUDIT_ENVELOPE_WIRE|ConvertFrom-ContainerWriterFenceJson
$payload.failure.password=[Guid]::NewGuid().ToString('N')
$json=ConvertTo-CanonicalAuditJson $payload -PrivateDiagnostics
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'private-audit.json'),$json,[Text.UTF8Encoding]::new($false))
'''
    result = run_functions(tmp_path, INSTALLER, ["ConvertTo-CanonicalAuditJson"], script,
                           values={"CA_AUDIT_ENVELOPE_WIRE": expected.decode("utf-8")}, engine=engine)
    assert result.returncode == 0
    actual = (tmp_path / "private-audit.json").read_bytes()
    parsed = json.loads(actual)
    _record("private-redaction", engine, stamp,
            redaction_preserved=parsed["failure"]["password"] == "[REDACTED:field]",
            timestamp_preserved=parsed["completed_fence_release"]["fence"]["session_started_at_utc"] == stamp,
            expected_sha256=hashlib.sha256(expected).hexdigest(), actual_sha256=hashlib.sha256(actual).hexdigest(),
            exact_wire_match=actual == expected)
    assert parsed["failure"]["password"] == "[REDACTED:field]"
    assert actual == expected


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("stamp", STAMPS)
def test_actual_final_audit_branch_preserves_both_saved_envelopes(tmp_path, engine, stamp):
    payload = {
        "status": "RESTORE_AWAITING_FENCE_RELEASE",
        "completed_fence_release": {"fence": {"session_started_at_utc": stamp}},
    }
    wire = json.dumps(payload, separators=(",", ":"))
    script = r'''
$audit=$env:CA_AUDIT_ENVELOPE_WIRE|ConvertFrom-ContainerWriterFenceJson
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'final-audit.json'
$Script:InstallationEvidenceRoot=Join-Path $env:CA_CONTRACT_ROOT 'protected'
$evidenceFull=Join-Path $Script:InstallationEvidenceRoot 'final-evidence.json'
$retirementAuditSealed=$false
function Assert-InstallationEvidenceWriteRoot([string]$Root){}
function Complete-InstallationEvidenceStage($Stage,$Failure){}
function Complete-InstallationEvidence{return [ordered]@{status='fixture-evidence-complete'}}
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
$condition='Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue'
$entries=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -ceq $condition},$true))
if($entries.Count -ne 1){throw 'ACTUAL_FINAL_AUDIT_BRANCH_MISSING'}
. ([scriptblock]::Create($entries[0].Extent.Text))
'''
    result = run_functions(tmp_path, INSTALLER, ["ConvertTo-CanonicalAuditJson", "Save"], script,
                           values={"CA_AUDIT_ENVELOPE_WIRE": wire}, engine=engine)
    assert result.returncode == 0
    payload["installation_evidence"] = {"status": "fixture-evidence-complete"}
    expected = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    public = (tmp_path / "final-audit.json").read_bytes()
    private = (tmp_path / "protected/final-evidence.json").read_bytes()
    _record("final-resave", engine, stamp,
            public_sha256=hashlib.sha256(public).hexdigest(), private_sha256=hashlib.sha256(private).hexdigest(),
            expected_sha256=hashlib.sha256(expected).hexdigest(),
            public_wire_match=public == expected, private_wire_match=private == expected,
            awaiting_status_preserved=json.loads(public)["status"] == "RESTORE_AWAITING_FENCE_RELEASE")
    assert public == expected
    assert private == expected
