from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
@pytest.mark.parametrize('shape', (
    'public', 'legacy', 'missing_exit', 'string_exit', 'null_exit', 'bool_exit',
    'fraction_exit', 'mismatch', 'null', 'array', 'one_array', 'corrupt',
    'oversize', 'unknown_schema', 'writer_failure', 'public_empty', 'corrupt_empty',
))
def test_real_child_fallback_keeps_primary_failure(tmp_path, engine, shape):
    result = run_functions(
        tmp_path, ROOT / 'tools/bootstrap_integrity.ps1',
        ['Initialize-InstallationChildCapture', 'ConvertTo-SafeInstallationOutput',
         'Invoke-InstallationEvidenceChild'],
        (ROOT / 'tests/ca_fallback_shape_probe.ps1').read_text(encoding='utf-8-sig'),
        engine=engine, values={'CA_FALLBACK_SHAPE': shape},
    )
    assert result.returncode == 0
    assert 'FALLBACK_SHAPE_PASS' in result.stdout
