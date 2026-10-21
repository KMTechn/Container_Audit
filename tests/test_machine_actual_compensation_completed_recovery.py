"""The real INSTALL compensation producer keeps MACHINE_INSTALL_FAILED."""
import json
from contextlib import nullcontext
import pytest

from tests.powershell_contracts import run_functions
from tests.test_container_writer_session import _held_session_authority
from tests.test_machine_install_completed_recovery import INSTALLER
from tests.test_machine_compensation_completed_recovery import COMPENSATED_DRIVER, COMPENSATED_FUNCTIONS

assert COMPENSATED_DRIVER.count("$audit.status='FAILED_ROLLED_BACK'") == 1
ACTUAL_COMPENSATED_DRIVER = COMPENSATED_DRIVER.replace(
    "$audit.status='FAILED_ROLLED_BACK'", "$audit.status='MACHINE_INSTALL_FAILED'", 1,
)
_ACTUAL_SAVE = r"""
if($case -ceq 'worker_pass') {
    $audit.compensation.worker_run_restore='PASS'
    $audit.compensation.worker_directory_restore='PASS'
}
if($audit.status -cne 'MACHINE_INSTALL_FAILED' -or
    $audit.compensation.child_exit -cne 'PASS' -or $audit.compensation.code_restore -cne 'PASS' -or
    $audit.compensation.artifact_restore -cne 'PASS' -or
    $audit.compensation.worker_run_restore -cnotin @('PASS','NOT_CHANGED') -or
    $audit.compensation.worker_directory_restore -cnotin @('PASS','NOT_CHANGED')) {
    throw 'actual compensation Save fixture does not match producer completion'
}
"""
ACTUAL_COMPENSATED_DRIVER = ACTUAL_COMPENSATED_DRIVER.replace("$auditPath=Join-Path", _ACTUAL_SAVE + "$auditPath=Join-Path", 1)

@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("operation,case,accepted", [
    ('INSTALL', 'completed', True),
    ('INSTALL', 'new_install_absent', True),
    ('INSTALL', 'worker_pass', True),
    ('INSTALL', 'preimage_differs', False),
    ('INSTALL', 'owner_alive', False),
    ('INSTALL', 'tuple_differs', False),
    ('INSTALL', 'recorded_child_alive', False),
    ('INSTALL', 'recorded_child_unknown', False),
    ('INSTALL', 'process_unknown', False),
])
def test_actual_install_compensation_keeps_its_completed_state(tmp_path, engine, operation, case, accepted):
    values = {"CA_COMPLETED_OPERATION": operation, "CA_COMPLETED_STAGE": 'setup', "CA_COMPLETED_CASE": case}
    result = run_functions(tmp_path, INSTALLER, COMPENSATED_FUNCTIONS, ACTUAL_COMPENSATED_DRIVER,
                           values=values, engine=engine)
    assert result.returncode == 0, "compensation fixture setup failed"
    ids = json.loads((tmp_path / 'ids.json').read_text(encoding="utf-8"))
    authority = _held_session_authority(ids['authority']) if case == "owner_alive" else nullcontext()
    with authority:
        values["CA_COMPLETED_STAGE"] = 'recover'
        result = run_functions(tmp_path, INSTALLER, COMPENSATED_FUNCTIONS, ACTUAL_COMPENSATED_DRIVER,
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
