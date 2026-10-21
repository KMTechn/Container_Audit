"""A missing/changed final release proof never recreates an authority or fence."""
import json
import uuid
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions
from tests.test_general_completed_release_recovery import DRIVER, FUNCTIONS, INSTALLER
from tests.test_general_completed_release_guards import setup


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('boundary', ('A_AFTER_SET', 'B_RESTORING_BEFORE_SET'))
@pytest.mark.parametrize('case', ('authorization_missing', 'authorization_changed', 'receipt_missing', 'receipt_changed', 'foreign_active'))
def test_absent_general_fence_requires_the_exact_final_proof(tmp_path, engine, boundary, case):
    values = setup(tmp_path, engine, boundary)
    active = next(tmp_path.rglob('writer-session/active.json'))
    original_fence = json.loads(active.read_text(encoding='utf-8-sig'))
    values['CA_GENERAL_STAGE'] = 'recover'
    first = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert first.returncode == 0
    observed = json.loads((tmp_path/'general-recovery-result.json').read_text(encoding='utf-8-sig'))
    assert observed['code'] == '' and not observed['fence_present']
    fixed = next(tmp_path.rglob('recovered-release-*.json'))
    release = next(tmp_path.rglob('release-*.json'))
    for path in (fixed, release):
        assert path.resolve(strict=True).is_relative_to(tmp_path.resolve(strict=True)) and not path.is_symlink()
    if case == 'authorization_missing':
        fixed.unlink()
    elif case == 'authorization_changed':
        fixed.write_bytes(fixed.read_bytes() + b' ')
    elif case == 'receipt_missing':
        release.unlink()
    elif case == 'receipt_changed':
        data = json.loads(release.read_text(encoding='utf-8-sig'))
        data['attempt_id'] = uuid.uuid4().hex
        release.write_text(json.dumps(data), encoding='utf-8')
    else:
        original_fence['attempt_id'] = uuid.uuid4().hex
        active.write_text(json.dumps(original_fence), encoding='utf-8')
    context = json.loads((tmp_path/'boundary-context.json').read_text(encoding='utf-8-sig'))
    audit = Path(context['audit_path'])
    names = [audit, fixed, release, active]
    before = {str(path): (path.read_bytes(), path.stat().st_mtime_ns) if path.exists() else None for path in names}
    retry = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert retry.returncode == 0
    observed = json.loads((tmp_path/'general-recovery-result.json').read_text(encoding='utf-8-sig'))
    assert observed['code'] == 'CANONICAL_COMPLETED_RELEASE_PROOF_DIFFERS'
    assert observed['fence_present'] == (case == 'foreign_active') and observed['audit_preserved']
    assert {str(path): (path.read_bytes(), path.stat().st_mtime_ns) if path.exists() else None for path in names} == before


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('size,accepted', ((131072, True), (131073, False)))
def test_general_completion_reader_enforces_approved_byte_bound(tmp_path, engine, size, accepted):
    path = tmp_path/'bounded.json'
    prefix, suffix = b'{"value":"', b'"}'
    payload = prefix + b'x' * (size - len(prefix) - len(suffix)) + suffix
    path.write_bytes(payload)
    original = payload, path.stat().st_mtime_ns
    result = run_functions(tmp_path, INSTALLER, ['Full', 'Sha', 'Read-CanonicalCompletedFenceJson'], r'''
$path=Join-Path $env:CA_CONTRACT_ROOT 'bounded.json'
try{[void](Read-CanonicalCompletedFenceJson $path (Sha $path));'ACCEPTED'}catch{'REFUSED'}
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.splitlines() == ['ACCEPTED' if accepted else 'REFUSED']
    assert (path.read_bytes(), path.stat().st_mtime_ns) == original
