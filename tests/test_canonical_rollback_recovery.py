"""A failed recovery stage must not suppress later safe recovery attempts."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('shell',['powershell.exe','pwsh.exe'])
@pytest.mark.parametrize('kind,case',[
    ('allowed','normal'), ('refusal','normal'),
    ('refusal','code-mismatch'), ('refusal','g-unknown'),
])
def test_canonical_rollback_attempts_remaining_recovery_with_actual_g(tmp_path,shell,kind,case):
    executable=shutil.which(shell)
    assert executable is not None
    output=tmp_path/'result.json'
    sandbox=tmp_path/'sandbox'
    environment=os.environ.copy()
    environment.update(TEMP=str(tmp_path),TMP=str(tmp_path),PYTHONDONTWRITEBYTECODE='1')
    environment['PSModulePath']=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/Modules')
    argv=[executable,'-NoProfile','-NonInteractive','-File',
          str(REPO/'tests'/f'canonical_rollback_actual_g_{kind}.ps1'),
          str(REPO/'INSTALL_CANONICAL_PORTABLE.ps1'),str(output),sys.executable,
          str(REPO/'tests/canonical_rollback_generation_child.py'),str(sandbox),case]
    process=subprocess.run(argv,env=environment,capture_output=True,text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW,timeout=90)
    assert process.returncode==0, 'isolated actual-G fixture failed'
    result=json.loads(output.read_text(encoding='utf-8-sig'))
    assert result['actual_g_calls']>=1
    assert result['full_installer_executed'] is False
    assert result['actual_host_lifecycle_calls']==0
    assert result['child_changes']==0
    counts=result['observed']
    assert counts['run_restore']==1
    assert counts['task_restore']==1
    if case=='normal':
        assert counts['code_restore']==1
        assert counts['fence_release']==1
        assert result['generation_readback']=='PASS'
        assert result['fence_active_after'] is False
        assert counts['relay_start']==1
        assert result['state_restored'] is True
        if kind=='refusal':
            assert result['code_rollback_failure']
            assert result['rollback_status']=='CODE_ROLLBACK_FAILED'
            assert result['rollback_steps']['code_quiescence']['status']=='FAILED'
    else:
        assert counts['fence_release']==0
        assert result['generation_readback']=='FAILED'
        assert result['operator_notice_saved'] is True
        assert result['support_procedure']=='docs/spec/operations.md#canonical-rollback-support-recovery'
        assert result['fence_active_after'] is True
        assert counts['relay_start']==0
        assert result['rollback_steps']['relay_restart']['status']=='UNPROVEN_FENCE_RETAINED'
        assert '관리자 지원 복구' in process.stdout+process.stderr
        if case=='g-unknown':
            assert counts['code_restore']==0
            assert result['actual_g_blocked']>=1
        else:
            assert counts['code_restore']==1
        assert result['code_rollback_failure']
