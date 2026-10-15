from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
def test_actual_machine_shortcut_functions_create_readback_and_remove(tmp_path, engine):
    result = run_functions(
        tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['New-CanonicalMachineShortcut', 'Get-CanonicalMachineShortcutArguments',
         'Remove-CanonicalMachineArtifacts', 'Get-CanonicalMachineArtifactPaths',
         'Get-CanonicalMachineArtifactPreimage', 'Restore-CanonicalMachineArtifacts'],
        ". '" + str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''") + "'\n" + (ROOT / 'tests/ca_machine_emergency_probe.ps1').read_text(encoding='utf-8-sig'),
        engine=engine, values=dict({'CA_BOOTSTRAP_SOURCE': str(ROOT / 'tools/bootstrap_integrity.ps1')}, KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=str(tmp_path / "shortcuts")),
    )
    assert result.returncode == 0
    assert 'MACHINE_EMERGENCY_PASS' in result.stdout


def test_machine_entry_and_removal_reach_actual_shortcut_functions():
    # Keep the real installation/removal call sites; the executable probes above
    # run their shortcut functions with real WScript links in the temporary root.
    source = (ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').read_text(encoding='utf-8-sig')
    start = source.index('function Invoke-CanonicalMachineInstallation(')
    end = source.index('\n}', start)
    machine = source[start:end]
    assert 'New-CanonicalMachineShortcut $Root' in machine
    assert 'Remove-CanonicalMachineArtifacts $Root $Worker $artifactPaths' in machine
    assert 'Get-CanonicalMachineArtifactPaths $state $Root' in machine
