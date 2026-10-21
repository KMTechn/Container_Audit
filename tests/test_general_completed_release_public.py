"""Use the real dedicated entry branch without running any installer lifecycle."""
import hashlib
import json

import pytest

from tests.powershell_contracts import run_functions
from tests.test_general_completed_release_recovery import DRIVER, FUNCTIONS, INSTALLER
from tests.test_general_completed_release_guards import setup


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('boundary', ('A_AFTER_SET', 'B_RESTORING_BEFORE_SET'))
def test_public_general_completion_reports_pending_followups(tmp_path, engine, boundary):
    values = setup(tmp_path, engine, boundary)
    values['CA_GENERAL_STAGE'] = 'public'
    artifacts = None
    for attempt in range(2):
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
        assert result.returncode == 0, 'public recovery failed; diagnostics suppressed'
        records = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        assert records['completed_fence_recovery_status'] == 'FENCE_RELEASED_FOLLOWUP_PENDING'
        assert records['original_audit_status'] == ('RESTORE_AWAITING_FENCE_RELEASE' if boundary.startswith('A_')
                                                     else 'ROLLBACK_AWAITING_FENCE_RELEASE')
        assert records['pending_followups'] == ('relay,User_shortcuts' if boundary.startswith('A_') else 'relay,execution_state')
        assert 'PASS' not in records['completed_fence_recovery_status']
        current = {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                   for path in tmp_path.rglob('*.json') if path.name.startswith(('recovered-release-', 'release-'))}
        assert len(current) == 2
        if artifacts is not None:
            assert current == artifacts
        artifacts = current


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', ('mixed_machine', 'mixed_uninstall', 'mixed_restore', 'no_switch',
                                 'bad_hash', 'missing_hash', 'wrong_source', 'wrong_root', 'plan', 'worker'))
def test_public_general_recovery_arguments_refuse_without_effects(tmp_path, engine, case):
    values = setup(tmp_path, engine, 'A_AFTER_SET')
    context = json.loads((tmp_path/'boundary-context.json').read_text(encoding='utf-8-sig'))
    from pathlib import Path
    audit = Path(context['audit_path'])
    fence = next(tmp_path.rglob('writer-session/active.json'))
    before = audit.read_bytes(), fence.read_bytes()
    values.update(CA_GENERAL_STAGE='public', CA_PUBLIC_CASE=case)
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 1
    assert result.stdout.splitlines() == ['CANONICAL_COMPLETED_RELEASE_PROOF_DIFFERS']
    assert (audit.read_bytes(), fence.read_bytes()) == before
    assert not list(tmp_path.rglob('recovered-release-*.json'))


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_general_public_entry_rejects_an_actual_machine_audit(tmp_path, engine):
    from tests.test_machine_install_completed_recovery import DRIVER as MACHINE_DRIVER, FUNCTIONS as MACHINE_FUNCTIONS
    values = setup(tmp_path, engine, 'A_AFTER_SET')
    machine_root = tmp_path/'machine'
    machine_root.mkdir()
    seed = run_functions(machine_root, INSTALLER, MACHINE_FUNCTIONS, MACHINE_DRIVER,
                         values={'CA_COMPLETED_STAGE': 'setup', 'CA_COMPLETED_CASE': 'valid'}, engine=engine)
    assert seed.returncode == 0, 'machine audit preparation failed; diagnostics suppressed'
    audit = next((machine_root/'machine-install/install-audit').glob('canonical-portable-*.json'))
    active = next(machine_root.rglob('writer-session/active.json'))
    before = audit.read_bytes(), active.read_bytes()
    values.update(CA_GENERAL_STAGE='public', CA_CROSS_AUDIT_PATH=str(audit))
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 1
    assert result.stdout.splitlines() == ['CANONICAL_COMPLETED_RELEASE_PROOF_DIFFERS']
    assert (audit.read_bytes(), active.read_bytes()) == before
    assert not list(tmp_path.rglob('recovered-release-*.json'))
