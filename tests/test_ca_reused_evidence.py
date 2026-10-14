from pathlib import Path

import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
@pytest.mark.parametrize('case', ('valid', 'absent', 'run', 'transaction', 'pid',
    'evidence_run', 'source_manifest', 'installed_manifest', 'inventory', 'aggregate',
    'replacement', 'unknown_field', 'changed_source'))
def test_reused_evidence_requires_current_bound_child_and_exact_stock(tmp_path, engine, case):
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Read-CanonicalHelperArtifact', 'Read-CanonicalReusedPlacementEvidence'],
        (ROOT / 'tests/ca_reused_evidence_probe.ps1').read_text(encoding='utf-8-sig'),
        engine=engine, values={'CA_REUSED_CASE': case,
                              'CA_BOOTSTRAP_SOURCE': str(ROOT / 'tools/bootstrap_integrity.ps1')})
    assert result.returncode == 0
    assert 'REUSED_EVIDENCE_PASS' in result.stdout
