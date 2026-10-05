"""A failed task or Run restore cannot release writers or restart old relay."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
@pytest.mark.parametrize('failure', ('normal','task-restore-failure','run-restore-failure'))
def test_restore_failure_retains_writer_fence(tmp_path, engine, failure):
    executable=shutil.which(engine)
    assert executable
    output=tmp_path/'counts.json'
    environment=dict(os.environ,TEMP=str(tmp_path),TMP=str(tmp_path),PYTHONDONTWRITEBYTECODE='1')
    result=subprocess.run([executable,'-NoProfile','-NonInteractive','-File',
        str(ROOT/'tests/canonical_rollback_actual_g_allowed.ps1'),
        str(ROOT/'INSTALL_CANONICAL_PORTABLE.ps1'),str(output),sys.executable,
        str(ROOT/'tests/canonical_rollback_generation_child.py'),str(tmp_path/'sandbox'),failure],
        env=environment,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0, 'native-free catch probe failed; raw diagnostics suppressed'
    counts=json.loads(output.read_text(encoding='utf-8-sig'))
    assert counts['actual_host_lifecycle_calls']==0
    assert counts['actual_g_passed']>=1
    assert counts['observed']['run_restore']==1 and counts['observed']['task_restore']==1
    if failure=='normal':
        assert counts['recovery_verified'] and not counts['fence_active_after']
        assert counts['observed']['fence_release']==1 and counts['observed']['relay_start']==1
        assert counts['state_restored']
    else:
        assert not counts['recovery_verified'] and counts['fence_active_after']
        assert counts['observed']['fence_release']==0 and counts['observed']['relay_start']==0
        assert counts['rollback_steps']['relay_restart']['status']=='UNPROVEN_FENCE_RETAINED'
        step='scheduled_writer_restore' if failure=='task-restore-failure' else 'run_restore_attempt'
        assert counts['rollback_steps'][step]['status']=='FAILED'
        assert counts['rollback_steps'][step]['failure']=='IOException'
