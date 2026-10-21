"""Preserve real producer result meanings across each supported preimage."""
import hashlib
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions
from tests.test_general_completed_release_recovery import DRIVER, FUNCTIONS, INSTALLER


PREIMAGES = (('A_AFTER_SET', 'run_present'), ('A_AFTER_SET', 'different_inventory'), ('A_AFTER_SET', 'receipt_transaction'),
             ('B_RESTORING_BEFORE_SET', 'run_present'), ('B_RESTORING_BEFORE_SET', 'prior_code'),
             ('B_RESTORING_BEFORE_SET', 'commit_reached'), ('B_RESTORING_BEFORE_SET', 'scheduled_writer'),
             ('B_RESTORING_BEFORE_SET', 'legacy_writer'))


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('boundary,preimage', PREIMAGES)
def test_completed_general_recovery_preserves_proven_preimages(tmp_path, engine, boundary, preimage):
    values = {'CA_GENERAL_STAGE': 'setup', 'CA_GENERAL_BOUNDARY': boundary, 'CA_GENERAL_PREIMAGE': preimage}
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 73, 'producer preimage boundary failed; diagnostics suppressed'
    context = json.loads((tmp_path/'boundary-context.json').read_text(encoding='utf-8-sig'))
    audit = Path(context['audit_path'])
    original_audit = audit.read_bytes()
    protected = [path for folder in ('current', 'data', 'packet') for path in (tmp_path/folder).rglob('*') if path.is_file()]
    before = {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) for path in protected}
    values['CA_GENERAL_STAGE'] = 'recover'
    first_artifacts = None
    for attempt in range(2):
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
        assert result.returncode == 0, 'preimage recovery failed; diagnostics suppressed'
        observed = json.loads((tmp_path/'general-recovery-result.json').read_text(encoding='utf-8-sig'))
        assert observed['code'] == '' and not observed['fence_present'] and observed['audit_preserved']
        assert audit.read_bytes() == original_audit
        assert {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) for path in protected} == before
        artifacts = {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                     for path in tmp_path.rglob('*.json') if path.name.startswith(('release-', 'recovered-release-'))}
        assert len(artifacts) == 2
        if first_artifacts is not None:
            assert artifacts == first_artifacts
        first_artifacts = artifacts
    saved = json.loads(audit.read_text(encoding='utf-8-sig'))
    assert saved['status'].endswith('_AWAITING_FENCE_RELEASE')
    if preimage == 'commit_reached':
        assert saved['rollback']['commit_point_status'] == 'REACHED'
