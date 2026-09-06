"""Execute the product recovery state machine with file-producing actions."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('failure,expected_actions,expected_status', [
    ('', ['code', 'lifecycle', 'writer'], 'PASS'),
    ('code', ['code'], 'CODE_RESTORE_FAILED'),
    ('lifecycle', ['code', 'lifecycle'], 'LIFECYCLE_RESTORE_FAILED'),
    ('writer', ['code', 'lifecycle', 'writer'], 'WRITER_RESTORE_FAILED'),
])
def test_recovery_flow_stops_at_failed_action_and_preserves_completed_evidence(
    tmp_path, failure, expected_actions, expected_status
):
    result = run_functions(tmp_path, ROOT/'tools/container_writer_session.ps1',
                           ['Invoke-RecoveryStateMachine'], r'''
function Invoke-OwnedRecoveryAction($Name) {
    [IO.File]::AppendAllText((Join-Path $env:CA_CONTRACT_ROOT 'actions.txt'),$Name+"`n")
    if ($Name -ceq $env:CA_RECOVERY_FAIL) { throw ('owned '+$Name+' action failed') }
    [IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT ($Name+'.json')),'{"status":"PASS"}')
    return [pscustomobject]@{status='PASS';silently_ignored=$false}
}
Invoke-RecoveryStateMachine -CodeRestoreAction {Invoke-OwnedRecoveryAction 'code'} -LifecycleRestoreAction {Invoke-OwnedRecoveryAction 'lifecycle'} -WriterRestoreAction {Invoke-OwnedRecoveryAction 'writer'} | ConvertTo-Json -Depth 8 -Compress
''', values={'CA_RECOVERY_FAIL':failure})
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert (report['failure_code'] or report['status']) == expected_status
    assert (tmp_path/'actions.txt').read_text().splitlines() == expected_actions
    for stage in ['code', 'lifecycle', 'writer']:
        completed = stage in expected_actions and stage != failure
        assert (tmp_path/(stage+'.json')).exists() is completed
        if stage not in expected_actions:
            assert report[stage+'_restore']['status'] == 'NOT_RUN'
        elif stage == failure:
            assert report[stage+'_restore']['silently_ignored'] is False
