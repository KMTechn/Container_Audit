import json
import os
from pathlib import Path

import pytest
import writer_session_fence as fence
from tests.powershell_contracts import run_functions
from tests.test_general_completed_release_recovery import DRIVER, FUNCTIONS, INSTALLER


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_real_waiting_audit_encoder_preserves_recovery_binding(tmp_path, engine):
    driver = DRIVER
    original = '[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 40)+[char]10,[Text.UTF8Encoding]::new($false))'
    replacement = r'''$encoded=if($Value -is [Collections.IDictionary] -and $Value.Contains('completed_fence_release')){ConvertTo-CanonicalAuditJson $Value}else{($Value|ConvertTo-Json -Depth 40)+[char]10}
    [IO.File]::WriteAllText($Path,$encoded,[Text.UTF8Encoding]::new($false))'''
    assert driver.count(original) == 1
    driver = driver.replace(original, replacement)
    original = "$canonicalWriterFenceStartedAtUtc=[DateTime]::UtcNow.ToString('o')"
    assert driver.count(original) == 1
    driver = driver.replace(original, "$canonicalWriterFenceStartedAtUtc='2026-10-21T00:00:00.1234500Z'")
    driver = 'function Assert-InstallationMachineMetadataNoSecrets {param($Json,$Environment)}\n' + driver
    values = {'CA_GENERAL_BOUNDARY': 'A_AFTER_SET', 'CA_GENERAL_STAGE': 'setup'}
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    assert result.returncode == 73
    values['CA_GENERAL_STAGE'] = 'observe'
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    assert result.returncode == 0
    observed = json.loads((tmp_path / 'general-observed.json').read_text(encoding='utf-8-sig'))
    assert all(observed['refusals'].values())
    control = Path(observed['control_root'])
    environment = {'LOCALAPPDATA': observed['local_appdata']}
    with pytest.raises(fence.WriterFencedError) as blocked:
        with fence._writer_admission('ledger_storage', control_root=control, environ=environment):
            pytest.fail('writer crossed a waiting fence')
    assert blocked.value.code == 'ACTIVE_WRITER_FENCE'
    values['CA_GENERAL_STAGE'] = 'recover'
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    assert result.returncode == 0
    summary = json.loads((tmp_path / 'general-recovery-result.json').read_text(encoding='utf-8-sig'))
    compact = {name: summary[name] for name in ('code','audit_preserved','fence_present')}
    context = json.loads((tmp_path / 'boundary-context.json').read_text(encoding='utf-8-sig'))
    audit = json.loads(Path(context['audit_path']).read_text(encoding='utf-8-sig'))
    proof = audit['completed_fence_release']
    prepared = json.loads(Path(proof['fence']['prepared_receipt_path']).read_text(encoding='utf-8-sig'))
    compact['timestamp_binding_equal'] = proof['fence']['session_started_at_utc'] == prepared['session_started_at_utc']
    values['CA_GENERAL_STAGE'] = 'public'
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    compact['public_exit_code'] = result.returncode
    compact['writer_blocked_after_public'] = False
    try:
        with fence._writer_admission('ledger_storage', control_root=control, environ=environment):
            pass
    except fence.WriterFencedError as error:
        compact['writer_blocked_after_public'] = error.code == 'ACTIVE_WRITER_FENCE'
    failure_sites = tmp_path / 'recovery-failure-sites.json'
    if failure_sites.exists():
        compact['failure_sites'] = json.loads(failure_sites.read_text(encoding='utf-8-sig'))[:3]
    (Path(os.environ['KMTECH_TEST_CA_EVIDENCE_ROOT']) / (engine + '-actual-audit-summary.json')).write_text(json.dumps(compact, indent=2), encoding='utf-8')
    assert summary['code'] == ''
    assert compact['public_exit_code'] == 0 and not compact['writer_blocked_after_public']
    assert summary['audit_preserved'] and not summary['fence_present']
