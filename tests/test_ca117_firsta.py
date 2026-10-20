"""Transfer 117 fix A: removal entry helper loading, bootstrap record location, one-read integrity."""
import hashlib
import inspect
import json
import re
import shutil
from pathlib import Path

import pytest

import current_user_onboarding as cuo
from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'


def _ps(mode):
    engine = shutil.which('powershell.exe')
    assert engine, 'Windows PowerShell 5.1 required'
    result = run_powershell([engine, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', str(ROOT / 'tests/canonical_removal_entry_cause.ps1'), '-Root', str(ROOT), '-Mode', mode])
    assert result.returncode == 0
    return result.stdout.strip()


def test_removal_worker_resolution_runs_after_the_fence_helper_is_loaded():
    text = INSTALLER.read_text(encoding='utf-8-sig')
    call = text.index('Resolve-CanonicalMachineRemovalWorker $WorkerAccount')
    load = text.rindex('\n. $writerFenceHelperPath')
    assert call > load


def test_undefined_state_helper_is_not_reported_as_worker_part_pending():
    code = _ps('UNDEFINED')
    assert code.startswith('CODE MACHINE_')
    assert code != 'CODE MACHINE_REMOVAL_WORKER_PART_PENDING'


def test_genuinely_unproven_worker_part_still_reports_worker_part_pending():
    assert _ps('DEFINED_NO_MARKER') == 'CODE MACHINE_REMOVAL_WORKER_PART_PENDING'


def _packet(tmp_path, *, record=True, flat=False):
    packet = tmp_path / 'current'
    app = packet if flat else packet / 'app'
    app.mkdir(parents=True)
    (app / 'Container_Audit.py').write_bytes(b'main')
    (app / 'helper.py').write_bytes(b'helper')
    if not flat:
        (packet / 'portable-manifest.json').write_bytes(b'{}')
    entries = []
    for path in sorted((p for p in packet.rglob('*') if p.is_file()), key=lambda p: p.relative_to(packet).as_posix()):
        data = path.read_bytes()
        entries.append({'path': path.relative_to(packet).as_posix(), 'size': len(data),
                        'sha256': hashlib.sha256(data).hexdigest()})
    aggregate = hashlib.sha256(''.join(f"{e['sha256']} {e['size']} {e['path']}\n" for e in entries).encode()).hexdigest()
    if record:
        (packet / 'bootstrap-integrity.json').write_text(json.dumps({
            'schema_version': 'container-audit-bootstrap-integrity-v1', 'status': 'PASS', 'code_root': '.',
            'file_count': len(entries), 'aggregate_sha256': aggregate, 'files': entries}), encoding='utf-8')
    return packet, app, len(entries)


def _paths(app, tmp_path):
    return cuo.resolve_current_user_onboarding_paths(app, environ={'CONTAINER_AUDIT_DATA_ROOT': str(tmp_path / 'state')})


def _options(**extra):
    parameters = inspect.signature(cuo.verify_bootstrap_integrity).parameters
    return {k: v for k, v in extra.items() if k in parameters}


def test_installed_layout_record_under_current_is_found_and_verified(tmp_path):
    packet, app, count = _packet(tmp_path)
    paths = _paths(app, tmp_path)
    detail = cuo.verify_bootstrap_integrity(paths, required=True, expected_entrypoint='app/Container_Audit.py')
    assert detail['status'] == 'PASS'
    assert detail['file_count'] == count
    assert Path(detail['record_path']) == (packet / 'bootstrap-integrity.json').resolve()


def test_installed_layout_without_record_stops_with_public_code(tmp_path):
    _, app, _ = _packet(tmp_path, record=False)
    paths = _paths(app, tmp_path)
    with pytest.raises(cuo.CurrentUserOnboardingError) as raised:
        cuo.verify_bootstrap_integrity(paths, required=True, expected_entrypoint='app/Container_Audit.py',
                                       **_options(absent_blocks=True))
    assert raised.value.reason_code == 'BOOTSTRAP_INTEGRITY_RECORD_ABSENT'
    assert re.search('[가-힣]', str(raised.value))


def test_source_mode_stays_not_tested(tmp_path):
    _, app, _ = _packet(tmp_path, record=False, flat=True)
    detail = cuo.verify_bootstrap_integrity(_paths(app, tmp_path), required=False)
    assert detail['status'] == 'NOT_TESTED'


def test_same_process_reads_the_tree_once(tmp_path, monkeypatch):
    packet, app, count = _packet(tmp_path)
    paths = _paths(app, tmp_path)
    reads = []
    original = cuo._file_sha256
    monkeypatch.setattr(cuo, '_file_sha256', lambda p: reads.append(p) or original(p))
    options = _options(reuse_in_process=True)
    for _ in range(3):
        detail = cuo.verify_bootstrap_integrity(paths, required=True, expected_entrypoint='app/Container_Audit.py', **options)
        assert detail['status'] == 'PASS'
    assert len(reads) == count
    # a changed record is never answered from the cache
    record = packet / 'bootstrap-integrity.json'
    record.write_text(record.read_text(encoding='utf-8') + ' ', encoding='utf-8')
    cuo.verify_bootstrap_integrity(paths, required=True, expected_entrypoint='app/Container_Audit.py', **options)
    assert len(reads) == 2 * count
