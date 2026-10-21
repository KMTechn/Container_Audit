import json
import os
from pathlib import Path

import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_existing_audit_encoder_retains_fence_timestamp(tmp_path, engine):
    script = r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
function Assert-InstallationMachineMetadataNoSecrets {param($Json,$Environment)}
$stamp='2026-10-21T00:00:00.1234500Z'
$original=[ordered]@{completed_fence_release=[ordered]@{fence=[ordered]@{session_started_at_utc=$stamp}}}
$json=ConvertTo-CanonicalAuditJson $original
$roundtrip=$json|ConvertFrom-ContainerWriterFenceJson
$seen=$roundtrip.completed_fence_release.fence.session_started_at_utc
$summary=@{lexically_equal=($seen -ceq $stamp);is_string=($seen -is [string]);same_instant=([DateTime]::Parse($seen).Ticks -eq [DateTime]::Parse($stamp).Ticks)}
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'roundtrip-summary.json'),($summary|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
'''
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1', ['ConvertTo-CanonicalAuditJson'], script, engine=engine)
    assert result.returncode == 0
    summary = json.loads((tmp_path / 'roundtrip-summary.json').read_text(encoding='utf-8-sig'))
    evidence = Path(os.environ['KMTECH_TEST_CA_EVIDENCE_ROOT']) / (engine + '-roundtrip-summary.json')
    evidence.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    assert summary['same_instant'] and summary['is_string']
    assert summary['lexically_equal']
