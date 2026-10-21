"""Completed recovery requires the original process identity as well as its mutex."""
import json

import pytest

from tests.powershell_contracts import run_functions
from tests.test_machine_install_completed_recovery import DRIVER, FUNCTIONS, INSTALLER
from tests.test_machine_compensation_completed_recovery import COMPENSATED_DRIVER, COMPENSATED_FUNCTIONS
from tests.test_machine_actual_compensation_completed_recovery import ACTUAL_COMPENSATED_DRIVER
from tests.test_machine_operation_completed_recovery import RESULT_DRIVER, SETUP_STAGE, RUN_STAGE, SUMMARY_FILE


KINDS = ["INSTALL", "UNINSTALL", "RESTORE_VERIFIED_REPLACEMENT", "INSTALL_COMPENSATED", "UNINSTALL_COMPENSATED"]
CASES = [("owner_identity_exited", True), ("owner_identity_alive", False),
         ("owner_identity_reused", True), ("owner_identity_unknown", False),
         ("owner_identity_absent", False), ("owner_identity_invalid", False)]


def completed_fixture(kind, case):
    values = {"CA_COMPLETED_STAGE": SETUP_STAGE, "CA_COMPLETED_CASE": case}
    functions = FUNCTIONS
    if kind.endswith("_COMPENSATED"):
        driver = ACTUAL_COMPENSATED_DRIVER if kind == "INSTALL_COMPENSATED" else COMPENSATED_DRIVER
        functions = COMPENSATED_FUNCTIONS
        values["CA_COMPLETED_OPERATION"] = kind.removesuffix("_COMPENSATED")
    elif kind == "INSTALL":
        driver = DRIVER
    else:
        driver = RESULT_DRIVER
        values["CA_RESULT_OPERATION"] = kind
    if case == "owner_identity_absent":
        marker = "$originalAudit=[IO.File]::ReadAllBytes($auditPath)"
        assert driver.count(marker) == 1
        driver = driver.replace(marker, marker + "\n$ownerFenceBefore=Sha (Join-Path $control 'active.json')", 1)
        marker = "code=$code;fence_present="
        assert driver.count(marker) == 1
        driver = driver.replace(marker,
            "owner_fence_preserved=((Test-Path -LiteralPath (Join-Path $control 'active.json')) -and "
            "((Sha (Join-Path $control 'active.json')) -ceq $ownerFenceBefore));" + marker, 1)
    return functions, driver, values


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("case,accepted", CASES)
def test_completed_recovery_requires_original_owner_exit(tmp_path, engine, kind, case, accepted):
    functions, driver, values = completed_fixture(kind, case)
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "owner fixture setup failed"
    values["CA_COMPLETED_STAGE"] = RUN_STAGE
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "owner recovery driver failed"
    summary = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8-sig"))
    assert summary["restored"] == summary["audit_writes"] == 0
    assert summary["audit_preserved"] and summary["code_preserved"] and summary["audit_spaced"]
    if accepted:
        assert not summary["code"], "a proven dead or reused original PID must recover"
        assert not summary["fence_present"] and summary["release_receipts"] == 1
        assert summary["owner_checks"] > 0
        assert summary["public_code"] == "PASS_MACHINE_RECOVERED"
    else:
        assert summary["code"], "a live, unobservable, or unbound original owner must refuse"
        assert summary["fence_present"] and summary["release_receipts"] == 0
        if case == "owner_identity_absent":
            assert summary["code"] == "MACHINE_RECOVERY_AUTHORITY_BINDING_DIFFERS"
            assert summary["owner_fence_preserved"]


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_incomplete_legacy_recovery_keeps_compensation_entry(tmp_path, engine):
    functions, driver, values = completed_fixture("INSTALL_COMPENSATED", "completed")
    marker = "$auditPath=Join-Path"
    setup = """
$audit.compensation.code_restore='UNPROVEN'
$prestate.Remove('owner_process_id');$prestate.Remove('owner_started_at_utc')
Save $journal $prestate;$audit.machine_prestate.sha256=Sha $journal
"""
    assert driver.count(marker) == 2
    driver = driver.replace(marker, setup + marker, 1)
    driver += "\n"
    # These seams only observe entry into the pre-existing incomplete compensation path.
    driver = driver.replace("function Initialize-InstallationEvidence {", "function Original-Initialize-InstallationEvidence {")
    driver = driver.replace("function Get-CanonicalMachinePlacementArguments {", "function Original-Get-CanonicalMachinePlacementArguments {")
    driver = driver.replace("function Restore-CanonicalMachineInstallationPrestate {", "function Original-Restore-CanonicalMachineInstallationPrestate {")
    seams = """
function Initialize-InstallationEvidence {}
function Get-CanonicalMachinePlacementArguments { return @() }
function Restore-CanonicalMachineInstallationPrestate { $script:Restores++;return $true }
"""
    driver = driver.replace("$idsPath=Join-Path", seams + "$idsPath=Join-Path", 1)
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "legacy fixture setup failed"
    values["CA_COMPLETED_STAGE"] = RUN_STAGE
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "legacy driver failed"
    summary = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8-sig"))
    assert summary["restored"] == 1 and summary["audit_writes"] == 1
    assert summary["owner_checks"] == 0
