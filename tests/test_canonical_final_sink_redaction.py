"""Sub-291 final-output probe port: actual CA catch/finally, synthetic secrets only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _assert_recovery_preserves_state(result, case):
    counts = result['counts']
    recovery = result['recovery']
    if case == 'failure':
        # Rejection before placement must preserve the entire supplied prestate.
        assert all(counts[name] == 0 for name in (
            'product_removal', 'code_restore', 'run_restore', 'task_restore', 'relay_start', 'fence_release'))
        assert recovery['state'] == dict(code='changed', data='before', run='changed', task='changed', relay='absent')
        assert recovery['actual_g_calls'] == 0
        assert recovery['actual_commit_point_calls'] == 0
        assert not recovery['fence_active_after']
        return

    assert counts['product_removal'] == 1
    assert recovery['actual_commit_point_calls'] == 1
    assert recovery['commit_point_status'] == 'NOT_REACHED'
    assert all(counts[name] == 1 for name in (
        'code_restore', 'run_restore', 'task_restore', 'relay_start', 'fence_release'))
    assert recovery['state'] == dict.fromkeys(('code', 'data', 'run', 'task', 'relay'), 'before')
    assert recovery['actual_g_calls'] >= 3
    assert recovery['actual_g_passed'] == recovery['actual_g_calls']
    assert recovery['actual_g_blocked'] == 0
    assert recovery['code_exact'] and recovery['runtime_restored'] and recovery['recovery_verified']
    assert not recovery['fence_active_after']
    steps = recovery['steps']
    for name in ('code_restore', 'run_restore', 'generation_readback', 'recovery_identity',
                 'scheduled_writer_restore', 'fence_release', 'relay_restart'):
        assert steps[name]['status'] == 'PASS'
        assert steps[name]['failure_type'] == ''
    if case == 'rollback':
        assert recovery['rollback_status'] == 'FAILED_ROLLED_BACK'
        assert steps['code_quiescence'] == dict(status='PASS', failure_type='')
        assert steps['completion'] == dict(status='PASS', failure_type='')
    else:
        # A refused first removal remains a recorded failure after independent
        # code, G, Run, task and relay recovery succeeds.
        assert case == 'rollback_failure'
        assert recovery['rollback_status'] == 'CODE_ROLLBACK_FAILED'
        assert steps['code_quiescence'] == dict(status='FAILED', failure_type='RuntimeException')
        assert steps['completion'] == dict(status='FAILED', failure_type='RuntimeException')


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', ('failure', 'rollback', 'rollback_failure'))
def test_final_exception_and_console_are_redacted_without_losing_original(tmp_path, engine, case):
    output = tmp_path / 'counts.json'
    environment = dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path))
    # Use the same native utility modules as the actual-G recovery fixture.
    # A PowerShell 7 module path inherited by PS5 can hide Get-FileHash and
    # turn the intended successful rollback into an unrelated admission failure.
    environment['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
    process = subprocess.run([
        shutil.which(engine), '-NoProfile', '-NonInteractive', '-File',
        str(ROOT / 'tests/canonical_final_sink_probe.ps1'),
        str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'), str(output), sys.executable,
        str(ROOT / 'tests/canonical_rollback_generation_child.py'), str(tmp_path / 'sandbox'), case,
    ], env=environment, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
    if process.returncode or not output.is_file():
        pytest.fail('Isolated final sink probe failed to produce counts', pytrace=False)
    result = json.loads(output.read_bytes())
    assert result['real_product_catch_and_finally'] and result['native_host_calls'] == 0
    assert result['failed']
    assert result['console_raw_hits'] == result['exception_raw_hits'] == 0
    assert result['original_object_preserved'] and result['inner_chain_preserved']
    _assert_recovery_preserves_state(result, case)
