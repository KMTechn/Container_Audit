"""Completed compensation checkpoints release only their already restored fence."""
import json
import re
from contextlib import nullcontext

import pytest

from tests.powershell_contracts import run_functions
from tests.test_container_writer_session import _held_session_authority
from tests.test_machine_install_completed_recovery import DRIVER, FUNCTIONS, INSTALLER

COMPENSATED_FUNCTIONS = [*FUNCTIONS, "Test-CanonicalMachineCodePrestate"]

# Reuse the real fence/session harness and change only its persisted audit/prestate.
_PRESTATE = r'''
$compOperation=$env:CA_COMPLETED_OPERATION
if(-not $compOperation){$compOperation='UNINSTALL'}
$prestate.operation=$compOperation
if($compOperation -eq 'UNINSTALL'){
    $prestate.removal_recovery=@{schema='container-audit-machine-removal-recovery-v1';application=(Split-Path -Parent $root)}
}
$prestate.before_manifest_sha256=Sha (Join-Path $root 'portable-manifest.json')
$audit.operation=$compOperation;$audit.status='FAILED_ROLLED_BACK';$audit.fence_retained=$true
$audit.compensation=@{child_exit='PASS';code_restore='PASS';artifact_restore='PASS';worker_run_restore='NOT_CHANGED';worker_directory_restore='NOT_CHANGED'}
if($case -in @('new_install_absent','new_install_present')) {
    $prestate.operation='INSTALL';$prestate.Remove('removal_recovery');$prestate.before_manifest_sha256=''
    $audit.operation='INSTALL'
    if($case -eq 'new_install_absent'){[IO.Directory]::Delete($root,$true)}
}
if($case -eq 'preimage_differs'){$prestate.before_manifest_sha256=('e'*64)}
if($case -eq 'compensation_unproven'){$audit.compensation.code_restore='UNPROVEN'}
Save $journal $prestate
$audit.machine_prestate.sha256=Sha $journal
'''
COMPENSATED_DRIVER = DRIVER.replace("$auditPath=Join-Path", _PRESTATE + "\n$auditPath=Join-Path", 1)
COMPENSATED_DRIVER = re.sub(
    r"(?m)^\$codeBefore=.*$",
    "$codeBefore=if(Test-Path -LiteralPath $root){Sha (Join-Path $root 'portable-manifest.json')}else{'ABSENT'}",
    COMPENSATED_DRIVER,
)
COMPENSATED_DRIVER = re.sub(
    r"code_preserved=[^;\r\n]*",
    "code_preserved=($codeBefore -ceq $(if(Test-Path -LiteralPath $root){Sha (Join-Path $root 'portable-manifest.json')}else{'ABSENT'}))",
    COMPENSATED_DRIVER,
)


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("operation,case,accepted", [
    ('INSTALL', 'completed', True),
    ('INSTALL', 'preimage_differs', False),
    ('INSTALL', 'compensation_unproven', False),
    ('INSTALL', 'owner_alive', False),
    ('INSTALL', 'tuple_differs', False),
    ('INSTALL', 'live_child', False),
    ('INSTALL', 'process_unknown', False),
    ('INSTALL', 'recorded_child_exited', True),
    ('INSTALL', 'recorded_child_alive', False),
    ('INSTALL', 'recorded_child_unknown', False),
    ('UNINSTALL', 'completed', True),
    ('UNINSTALL', 'preimage_differs', False),
    ('UNINSTALL', 'compensation_unproven', False),
    ('UNINSTALL', 'owner_alive', False),
    ('UNINSTALL', 'tuple_differs', False),
    ('UNINSTALL', 'live_child', False),
    ('UNINSTALL', 'process_unknown', False),
    ('UNINSTALL', 'recorded_child_exited', True),
    ('UNINSTALL', 'recorded_child_alive', False),
    ('UNINSTALL', 'recorded_child_unknown', False),
    ('INSTALL', 'new_install_absent', True),
    ('INSTALL', 'new_install_present', False),
])
def test_completed_compensation_only_releases_proven_fence(tmp_path, engine, operation, case, accepted):
    values = {"CA_COMPLETED_OPERATION": operation, "CA_COMPLETED_STAGE": 'setup', "CA_COMPLETED_CASE": case}
    result = run_functions(tmp_path, INSTALLER, COMPENSATED_FUNCTIONS, COMPENSATED_DRIVER,
                           values=values, engine=engine)
    assert result.returncode == 0, "compensation fixture setup failed"
    ids = json.loads((tmp_path / 'ids.json').read_text(encoding="utf-8"))
    authority = _held_session_authority(ids['authority']) if case == "owner_alive" else nullcontext()
    with authority:
        values["CA_COMPLETED_STAGE"] = 'recover'
        result = run_functions(tmp_path, INSTALLER, COMPENSATED_FUNCTIONS, COMPENSATED_DRIVER,
                               values=values, engine=engine)
    assert result.returncode == 0, "compensation recovery driver failed"
    summary = json.loads((tmp_path / 'completed-result.json').read_text(encoding="utf-8"))
    assert summary["audit_spaced"], "audit must use indented ConvertTo-Json"
    assert summary["restored"] == 0
    assert summary["audit_writes"] == 0
    assert summary["code_preserved"] and summary["audit_preserved"]
    if accepted:
        assert summary["code"] == "", "completed compensation was not recovered"
        assert not summary["fence_present"]
        assert summary["release_receipts"] == 1
        assert summary["process_checks"] > 0
        if case != "new_install_absent":
            assert summary["integrity_checks"] > 0
        assert summary["public_code"] == "PASS_MACHINE_RECOVERED"
    else:
        expected = {
            "preimage_differs": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "new_install_present": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "compensation_unproven": "MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS",
            "owner_alive": "CONTAINER_WRITER_SESSION_AUTHORITY_ALREADY_EXISTS",
            "tuple_differs": "MACHINE_RECOVERY_AUTHORITY_BINDING_DIFFERS",
            "live_child": "MACHINE_RECOVERY_CHILD_UNRECORDED",
            "process_unknown": "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN",

            "recorded_child_alive": "MACHINE_RECOVERY_CHILD_ACTIVE",
            "recorded_child_unknown": "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN",
        }
        assert summary["code"] == expected[case]
        assert summary["fence_present"]
        assert summary["release_receipts"] == 0
