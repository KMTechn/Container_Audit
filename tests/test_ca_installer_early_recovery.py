"""Actual preparation route and nested catches with isolated native boundaries."""
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
@pytest.mark.parametrize('phase', ('after-stop', 'before-fence', 'before-audit'))
@pytest.mark.parametrize('case', ('owned', 'foreign-marker', 'same-id-changed', 'missing-proof', 'bad-ready'))
def test_actual_early_failure_restores_only_owned_stop_then_proves_old_ready(tmp_path, engine, phase, case):
    output = tmp_path / 'observation.json'
    environment = os.environ.copy()
    environment.update(TEMP=str(tmp_path), TMP=str(tmp_path), PYTHONDONTWRITEBYTECODE='1')
    environment['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
    result = run_powershell([shutil.which(engine), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        str(ROOT / 'tests/canonical_installer_early_recovery.ps1'), str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'),
        str(tmp_path / 'sandbox'), sys.executable, phase, case, str(output)],
        env=environment, capture_output=True, text=True, timeout=75)
    assert result.returncode == 1
    data = json.loads(output.read_text(encoding='utf-8-sig'))
    assert data['injected'] is True and data['stop_calls'] == 1
    assert data['original_cause_preserved'] is True
    assert data['run_unchanged'] is True and data['code_unchanged'] is True
    assert data['fence_present'] is False and data['prepared_present'] is False
    assert data['audit_present'] is True
    if case == 'owned':
        assert data['stop_deletes'] == 1 and data['marker_present'] is False
        assert data['restarts'] == 1 and data['resident_present'] is True
        assert data['recovery']['status'] == 'RESTORED'
        assert data['recovery']['ready_proven'] is True
        assert 'INSTALLER_EARLY_RELAY_RESTORED' in data['events']
    else:
        assert data['recovery']['status'] == 'RECOVERY_REQUIRED'
        assert data['recovery']['ready_proven'] is False
        assert 'RECOVERY_REQUIRED' in result.stdout
        if case == 'bad-ready':
            assert data['stop_deletes'] == 1 and data['restarts'] == 1
        else:
            assert data['stop_deletes'] == 0 and data['restarts'] == 0
            assert data['marker_present'] is True and data['marker_unchanged'] is True
    assert data['audit_recovery'] == data['recovery']
