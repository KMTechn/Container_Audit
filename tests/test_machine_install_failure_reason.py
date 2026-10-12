"""IA-01: machine installation failures keep MACHINE_INSTALL_FAILED, exit 4 and
one public JSON line, and add only an allowlisted reason code."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions
from tests.test_machine_recovery_guidance import _machine_fence

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "CONTAINER_AUDIT_INSTALL_CANONICAL="
NAMES = ["Write-CanonicalMachinePublicRecord", "Get-CanonicalMachineFailureReason", "Get-CanonicalMachineHelperReason"]
PRIVATE = "C:\\Users\\private-operator\\AppData\\Local\\owned-secret-marker"
DRIVER = r'''
$case=$env:CA_REASON_CASE
$summary='installation_failure_summary='
function New-Helper([string]$Code){return ('helper line'+"`n"+$summary+(@{status='FAILED';reason_code=$Code}|ConvertTo-Json -Compress))}
try{
    switch -CaseSensitive ($case){
        'fence_active' {
            . (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
            [void](Start-ContainerWriterFence -ControlRoot $env:CA_REASON_CONTROL -Status 'INSTALLING' -OwnerKind 'canonical_installer')
        }
        'worker_fence' {throw 'Existing worker deployment requires recovery.'}
        'not_admin' {throw 'Machine installation requires an already privileged token.'}
        'writer_semantics' {throw [InvalidOperationException]::new('outer wrapper',[Management.Automation.RuntimeException]::new('CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'))}
        'case_differs' {throw 'code_prestate_writer_semantics_differ'}
        'unknown' {throw ('Failure at '+$env:CA_REASON_PRIVATE)}
        default {
            $stdout=switch -CaseSensitive ($case){
                'helper_lifecycle' {New-Helper 'lifecycle_task_absence_or_unknown'}
                'helper_startup' {New-Helper 'STARTUP_UPDATE_OWNED_TASK_DIFFERS'}
                'helper_generic' {New-Helper 'INSTALLER_HELPER_FAILURE'}
                'helper_untrusted' {New-Helper $env:CA_REASON_PRIVATE}
                'helper_broken' {'helper line'+"`n"+$summary+'{not json '+$env:CA_REASON_PRIVATE}
                'helper_absent' {'helper line only'}
            }
            $helperReason=Get-CanonicalMachineHelperReason $stdout
            try{throw 'MACHINE_INSTALL_FAILED'}
            catch{$_.Exception.Data['canonical_machine_helper_reason']=$helperReason;throw}
        }
    }
}catch{
    $outputFailure=$_
    Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED'
}
'''
EXPECTED = {
    "fence_active": "PRIOR_INSTALL_UNFINISHED",
    "worker_fence": "WORKER_INSTALL_UNFINISHED",
    "not_admin": "ADMINISTRATOR_REQUIRED",
    "writer_semantics": "INSTALLED_WRITER_SEMANTICS_DIFFER",
    "case_differs": "UNCLASSIFIED",
    "unknown": "UNCLASSIFIED",
    "helper_lifecycle": "lifecycle_task_absence_or_unknown",
    "helper_startup": "STARTUP_UPDATE_OWNED_TASK_DIFFERS",
    "helper_generic": "PLACEMENT_HELPER_FAILED",
    "helper_untrusted": "PLACEMENT_HELPER_FAILED",
    "helper_broken": "PLACEMENT_HELPER_FAILED",
    "helper_absent": "PLACEMENT_HELPER_FAILED",
}


def _public(output):
    lines = [line for line in output.splitlines() if line.startswith(PREFIX)]
    assert len(lines) == 1
    return json.loads(lines[0][len(PREFIX):])


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_machine_failure_publishes_only_allowlisted_reason(tmp_path, engine, case):
    control = _machine_fence(tmp_path)[0] if case == "fence_active" else tmp_path / "unused"
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", NAMES, DRIVER, engine=engine,
                           values={"CA_REASON_CASE": case, "CA_REASON_CONTROL": str(control),
                                   "CA_REASON_PRIVATE": PRIVATE})
    assert result.returncode == 0, result.stdout + result.stderr
    public = _public(result.stdout)
    reason = EXPECTED[case]
    assert public["status"] == "FAILED" and public["code"] == "MACHINE_INSTALL_FAILED"
    assert public["reason_code"] == reason
    assert public["summary_message"] == "MACHINE_INSTALL_FAILED reason=" + reason
    assert public["guidance"]
    assert "nonconforming_fields" not in public
    assert PRIVATE not in result.stdout + result.stderr
    assert "owned-secret-marker" not in result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("code", ("PASS_MACHINE_WORKER_PENDING", "MACHINE_RECOVERY_CHILD_ACTIVE"))
def test_other_codes_keep_existing_record_shape(tmp_path, engine, code):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", NAMES,
                           "$outputFailure=$null;Write-CanonicalMachinePublicRecord $env:CA_REASON_CODE 'PASS'",
                           engine=engine, values={"CA_REASON_CODE": code})
    assert result.returncode == 0, result.stdout + result.stderr
    public = _public(result.stdout)
    assert set(public) == {"status", "code", "stage", "guidance", "report_status"}


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize(("message", "reason"), (
    ("STARTUP_UPDATE_OWNED_TASK_DIFFERS", "STARTUP_UPDATE_OWNED_TASK_DIFFERS"),
    ("STARTUP_UPDATE_WRITER_HELPER_PIN_DIFFERS", "STARTUP_UPDATE_WRITER_HELPER_PIN_DIFFERS"),
    ("startup_update_owned_task_differs", "INSTALLER_HELPER_FAILURE"),
    ("STARTUP_UPDATE_UNLISTED_FAILURE", "INSTALLER_HELPER_FAILURE"),
    (PRIVATE, "INSTALLER_HELPER_FAILURE"),
))
def test_helper_publishes_only_listed_startup_update_codes(tmp_path, engine, message, reason):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1", ["Get-InstallationHelperPublicFailure"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
try{throw [InvalidOperationException]::new('fence mutation failed',[Management.Automation.RuntimeException]::new($env:CA_HELPER_MESSAGE))}
catch{'installation_failure_summary='+((Get-InstallationHelperPublicFailure $_ 1)|ConvertTo-Json -Depth 4 -Compress)}
''', engine=engine, values={"CA_HELPER_MESSAGE": message})
    assert result.returncode == 0, result.stdout + result.stderr
    prefix = "installation_failure_summary="
    lines = [line[len(prefix):] for line in result.stdout.splitlines() if line.startswith(prefix)]
    assert len(lines) == 1
    public = json.loads(lines[0])
    assert public["reason_code"] == reason
    assert "nonconforming_fields" not in public
    assert PRIVATE not in result.stdout + result.stderr
