"""Narrow removal audit readback, using extracted functions rather than an entrypoint."""
import json
import re
import pytest

from tests import test_convergent_removal as removal


@pytest.mark.parametrize("proof,run_present", [
    ("NEVER_STARTED", False), ("PROFILE_ABSENT", None),
    ("USER_RECEIPT", None), ("ACCOUNT_UNAVAILABLE", True),
])
def test_removed_marker_worker_proof_matches_disposition(tmp_path, monkeypatch, proof, run_present):
    monkeypatch.setenv("CA_NTFS_TEST_ROOT", str(tmp_path))
    root, originals = removal.setup_tree()
    ps_run = {True: "$true", False: "$false", None: "$null"}[run_present]
    prefix = (
        "$MachineControlRoot='isolated-machine-control';"
        "$Script:ContainerRemovalAttestedNewPlacement=$false;"
        f"$Script:ContainerMachineRemovalProofKind='{proof}';"
        f"$Script:ContainerMachineRemovalWorkerRunPresent={ps_run};"
    )
    census = re.search(r"(?ms)^function Get-CimInstance.*?^}", removal.DRIVER)
    assert census
    driver = r'''
. $env:CA_REMOVAL_LIBRARY
$root=$env:CA_REMOVAL_ROOT
$testOverride=$true
function Write-ContainerStartupUpdateRecord($Path,$Payload) { Write-Utf8Json $Path $Payload }
[void](Invoke-ContainerConvergentRemoval (Join-Path $env:CA_REMOVAL_ROOT 'current') $null)
'''
    result = removal.run_functions(
        tmp_path, removal.REPO / "INSTALL_THIS_PC.ps1", removal.NAMES,
        prefix + "\n" + census.group() + "\n" + driver, engine="powershell", values={
            "CA_REMOVAL_ROOT": str(root),
            "CA_REMOVAL_LIBRARY": str(removal.REPO / "tools/bootstrap_integrity.ps1"),
        })
    assert result.returncode == 0, "isolated removal helper failed"
    marker = json.loads((root / "removed.json").read_text(encoding="utf-8-sig"))
    expected = {"proof": proof, "worker_run_present": run_present}
    assert marker["worker_removal_proof"] == expected
    rows = [r for r in marker["artifact_dispositions"]
            if r["disposition"].startswith("WORKER_PART_")]
    assert rows == [{"path": "application", "disposition": "WORKER_PART_" + proof,
                     "worker_run_present": expected["worker_run_present"]}]
    assert marker["schema"] == "container-audit-supported-removal-v1"
    for path, raw in originals.items():
        archived = list((root / "removal-evidence").glob("*/" + path.relative_to(root).as_posix()))
        assert len(archived) == 1 and archived[0].read_bytes() == raw


def test_uncommitted_machine_removal_without_proof_has_no_worker_disposition(tmp_path, monkeypatch):
    proof, run_present = "", None
    monkeypatch.setenv("CA_NTFS_TEST_ROOT", str(tmp_path))
    root, originals = removal.setup_tree()
    ps_run = {True: "$true", False: "$false", None: "$null"}[run_present]
    prefix = (
        "$RemoveUncommittedPlacement=$true;$MachineControlRoot='isolated-machine-control';"
        "$Script:ContainerRemovalAttestedNewPlacement=$false;"
        f"$Script:ContainerMachineRemovalProofKind='{proof}';"
        f"$Script:ContainerMachineRemovalWorkerRunPresent={ps_run};"
    )
    census = re.search(r"(?ms)^function Get-CimInstance.*?^}", removal.DRIVER)
    assert census
    driver = r'''
. $env:CA_REMOVAL_LIBRARY
$root=$env:CA_REMOVAL_ROOT
$testOverride=$true
function Write-ContainerStartupUpdateRecord($Path,$Payload) { Write-Utf8Json $Path $Payload }
[void](Invoke-ContainerConvergentRemoval (Join-Path $env:CA_REMOVAL_ROOT 'current') $null)
'''
    result = removal.run_functions(
        tmp_path, removal.REPO / "INSTALL_THIS_PC.ps1", removal.NAMES,
        prefix + "\n" + census.group() + "\n" + driver, engine="powershell", values={
            "CA_REMOVAL_ROOT": str(root),
            "CA_REMOVAL_LIBRARY": str(removal.REPO / "tools/bootstrap_integrity.ps1"),
        })
    assert result.returncode == 0, "isolated removal helper failed"
    marker = json.loads((root / "removed.json").read_text(encoding="utf-8-sig"))
    assert marker["worker_removal_proof"] is None
    assert not [r for r in marker["artifact_dispositions"] if r["disposition"].startswith("WORKER_PART_")]
    assert marker["schema"] == "container-audit-supported-removal-v1"
    for path, raw in originals.items():
        archived = list((root / "removal-evidence").glob("*/" + path.relative_to(root).as_posix()))
        assert len(archived) == 1 and archived[0].read_bytes() == raw
