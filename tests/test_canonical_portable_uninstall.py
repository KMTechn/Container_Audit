"""Real CA removal and PowerShell fence/recovery on isolated temporary trees.

Only registry, process census/launch, and fixture signature observations are
adapted. Product dispatch/removal, relay loop/stop mutex, source and installed
identity, session authority, delegation, and code removal/recovery are real.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import pytest

from tests.test_zero_touch_installer import _portable_release_fixture, _powershell

ROOT = Path(__file__).resolve().parents[1]


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root):
    return {str(p.relative_to(root)): _sha(p) for p in root.rglob('*') if p.is_file()}


PY_HOST = r'''
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ['CA_UNINSTALL_REPO'])
import writer_session_fence as fence
assert os.environ['CA_UNINSTALL_MUTEX'] != fence.WRITER_MUTEX_NAME
fence.writer_admission_mutex_name = lambda root, environ=None: os.environ['CA_UNINSTALL_MUTEX']
import user_relay
import current_user_onboarding as onboarding
root = Path(os.environ['CA_UNINSTALL_ROOT'])
registry = root / 'registry.json'
direct = Path(os.environ['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit'
if sys.argv[1] == 'relay':
    lease = user_relay.acquire_runtime_instance(direct / 'user-relay-instance')
    assert lease is not None
    (root / 'relay.pid').write_text(str(os.getpid()))
    (root / 'relay.ready').touch()
    stop = user_relay.user_relay_stop_path(direct)
    try:
        if os.environ.get('CA_UNINSTALL_REFUSE') == '1':
            import time
            while not (root / 'finish').exists(): time.sleep(.05)
        else:
            user_relay.run_persistent_relay_loop(
                lambda: {'status': 'PASS'}, status_path=direct / 'status/test-relay.json',
                interval_seconds=1, stop_requested=lambda: stop.exists() or (root / 'finish').exists(),
            )
    finally:
        lease.release()
        (root / 'relay.ready').unlink(missing_ok=True)
else:
    def delete():
        registry.write_text(json.dumps({'exists': False, 'kind': '', 'data': ''}))
    def get():
        return json.loads(registry.read_text())['data']
    defaults = onboarding.remove_current_user_setup.__wrapped__.__kwdefaults__
    defaults['autostart_remover'] = lambda: user_relay.remove_user_relay_autostart(deleter=delete, getter=get)
    from container_audit_product_host import dispatch_product_mode
    raise SystemExit(dispatch_product_mode(['--remove-current-user-setup', '--app-root', sys.argv[2]]))
'''

OS_BOUNDARIES = r'''
function Get-AuthenticodeSignature { return [pscustomobject]@{ Status='NotTested' } }
function Snapshot { return Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') -Raw | ConvertFrom-Json }
function Restore($Before) { Save (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') $Before }
function Relays {
    if (Test-Path -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'relay.ready')) {
        $relayPid = [int](Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'relay.pid'))
        if (Get-Process -Id $relayPid -ErrorAction SilentlyContinue) {
            return [pscustomobject]@{ ProcessId=$relayPid; ExecutablePath=(Join-Path $InstallRoot 'runtime\pythonw.exe'); CommandLine=(Command $InstallRoot) }
        }
    }
    return @()
}
function Product([string]$Root, [string]$Mode) {
    if ($Mode -cne '--remove-current-user-setup') { throw 'Unexpected product mode' }
    & $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST remove (Join-Path $Root 'app')
    if ($LASTEXITCODE -ne 0) { throw "Real current-user removal failed: $LASTEXITCODE" }
}
function StartRaw([string]$Line) {
    if (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\control\writer-session\active.json')) {
        throw 'Ordinary relay restarted while writer fence was active'
    }
    $arguments = '-I -B ' + (Arg $env:CA_UNINSTALL_HOST) + ' relay'
    $child = Start-Process -FilePath $env:CA_UNINSTALL_PYTHON -ArgumentList $arguments -WindowStyle Hidden -PassThru
    return $child.Id
}
'''

HELPER_OS = r'''
function Test-CurrentUserRelayPersistencePresent { return [bool](Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') -Raw | ConvertFrom-Json).exists }
function Get-CimInstance {
    if ($env:CA_UNINSTALL_INTERACTIVE -ceq '1') {
        return [pscustomobject]@{ ProcessId=1; ExecutablePath=(Join-Path $InstallRoot 'runtime\pythonw.exe'); CommandLine='interactive fixture' }
    }
    return @()
}
'''


def _ps(path, env, *args):
    return subprocess.run(
        [_powershell(), '-NoLogo', '-NoProfile', '-NonInteractive',
         '-ExecutionPolicy', 'Bypass', '-File', str(path), *args],
        env=env, capture_output=True, text=True, timeout=90,
    )


def _setup(tmp_path, fault=''):
    env = os.environ.copy()
    for name in ('LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA', 'TEMP', 'TMP'):
        target = tmp_path / name
        target.mkdir()
        env[name] = str(target)
    env.update(PYTHONDONTWRITEBYTECODE='1', KMTECH_FACTORY_INSTALL_TEST_MODE='1',
               CA_UNINSTALL_REPO=str(ROOT), CA_UNINSTALL_ROOT=str(tmp_path),
               CA_UNINSTALL_PYTHON=sys.executable,
               CA_UNINSTALL_MUTEX='Local\\Container.UninstallTest.' + uuid.uuid4().hex)
    env['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
    env.pop('CONTAINER_AUDIT_DATA_ROOT', None)
    env.pop('KMTECH_CONTAINER_WRITER_CONTROL_ROOT', None)
    host = tmp_path / 'host.py'
    host.write_text(PY_HOST, encoding='utf-8')
    env['CA_UNINSTALL_HOST'] = str(host)
    source = _portable_release_fixture(tmp_path, directory='packet')
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig').replace('$wanted = Command $install', OS_BOUNDARIES + '\n$wanted = Command $install')
    if fault == 'after_removal':
        text = text.replace("if ($LASTEXITCODE -ne 0) { throw \"Code removal failed: $LASTEXITCODE\" }",
                            "if ($LASTEXITCODE -ne 0) { throw \"Code removal failed: $LASTEXITCODE\" }\n        throw 'AFTER_REMOVAL_INJECTED_FAILURE'")
    elif fault in {'final_evidence', 'audit_unavailable'}:
        condition = "$Value['status'] -ceq 'PASS_UNINSTALLED_DATA_PRESERVED' -and $Path -ceq $EvidencePath"
        if fault == 'audit_unavailable':
            condition = "($Value['status'] -ceq 'UNINSTALL_AWAITING_FENCE_RELEASE' -or $Value['status'] -ceq 'FAILED_ROLLED_BACK')"
        text = text.replace('function Save([string]$Path, $Value) {',
                            "function Save([string]$Path, $Value) {\n    if ($Value -is [Collections.IDictionary] -and $Value.Contains('status') -and (" + condition + ")) { throw 'AUDIT_INJECTED_FAILURE' }")
    elif fault == 'forged':
        text = text.replace('& $winps @uninstallArguments',
                            "$uninstallArguments[$uninstallArguments.IndexOf('-WriterFenceDelegationToken') + 1] = ('e' * 64)\n        & $winps @uninstallArguments")
    elif fault == 'fence_release':
        text = text.replace('Clear-CanonicalWriterFenceReleaseDelegation\n        Stop-CanonicalWriterFenceRelease $releaseAuthorization',
                            "Clear-CanonicalWriterFenceReleaseDelegation\n        throw 'FENCE_RELEASE_INJECTED_FAILURE'\n        Stop-CanonicalWriterFenceRelease $releaseAuthorization")
    canonical.write_text(text, encoding='utf-8-sig')
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig').replace('$testOverride = (', HELPER_OS + '\n$testOverride = (')
    if fault in {'partial', 'restore_failure'}:
        target = '        Remove-Item -LiteralPath $installRootFull -Recurse -Force -ErrorAction Stop'
        assert text.count(target) == 1
        text = text.replace(target, "        Remove-Item -LiteralPath (Join-Path $installRootFull 'app\\main.py') -Force\n        throw 'PARTIAL_REMOVAL_INJECTED_FAILURE'")
        if fault == 'restore_failure':
            text = text.replace('        if ($uninstallMutationStarted) {', "        if ($uninstallMutationStarted) {\n            throw 'RESTORE_INJECTED_FAILURE'")
    elif fault == 'helper_after_removal':
        text = text.replace("        Write-Output 'uninstall_status=PASS_CODE_REMOVED_STATE_PRESERVED'",
                            "        throw 'HELPER_AFTER_REMOVAL_INJECTED_FAILURE'")
    helper.write_text(text, encoding='utf-8-sig')
    fence = source / 'tools/container_writer_fence.ps1'
    text = fence.read_text(encoding='utf-8-sig').replace(
        "'Local\\KMTech.ContainerAudit.WriterAdmission.v1'", "'" + env['CA_UNINSTALL_MUTEX'] + "'")
    fence.write_text(text, encoding='utf-8-sig')
    manifest_path = source / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    for field, name in [('installer', canonical), ('helper', helper), ('writer_fence_helper', fence)]:
        manifest[field + '_sha256'] = _sha(name)
    files = [p for p in source.rglob('*') if p.is_file() and p != manifest_path]
    manifest['file_count_before_manifest'] = len(files)
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    install = tmp_path / 'owned/current'
    shutil.copytree(source, install)
    record = tmp_path / 'record.ps1'
    record.write_text(". '" + str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''") + "'\n"
                      + "Write-BootstrapIntegrityRecord -Root '" + str(install).replace("'", "''")
                      + "' -CodeRootIdentity '" + str(install).replace("'", "''") + "' | Out-Null", encoding='utf-8-sig')
    result = _ps(record, env)
    assert result.returncode == 0, result.stderr
    command = subprocess.list2cmdline([str(install / 'runtime/pythonw.exe'), '-I', '-B',
                                      str(install / 'app/main.py'), '--container-audit-user-relay'])
    (tmp_path / 'registry.json').write_text(json.dumps({'exists': True, 'kind': 'String', 'data': command}))
    protected = []
    for relative in ('KMTech/ContainerAudit/events/event.csv', 'KMTech/ContainerAudit/parked_trays/tray.json',
                     'KMTech/ContainerAudit/config/settings.json', 'KMTech/ContainerAudit/identity/key.bin',
                     'KMTech/DirectSync/container_audit/credentials.json', 'KMTech/Logistics/profile.json',
                     'KMTech/DirectSync/container_audit/queue/pending.json'):
        path = Path(env['LOCALAPPDATA']) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'protected-fixture-must-be-preserved')
        protected.append(path)
    return env, source, install, protected


def _launch_relay(tmp_path, env):
    child = subprocess.Popen([sys.executable, '-I', '-B', env['CA_UNINSTALL_HOST'], 'relay'],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while not (tmp_path / 'relay.ready').exists() and child.poll() is None and time.monotonic() < deadline:
        time.sleep(.05)
    assert (tmp_path / 'relay.ready').exists(), 'isolated relay did not start'
    return child


def _finish(tmp_path, child):
    (tmp_path / 'finish').touch()
    try:
        child.wait(timeout=12)
    except subprocess.TimeoutExpired:
        child.terminate()
        child.wait(timeout=5)
    deadline = time.monotonic() + 10
    while (tmp_path / 'relay.ready').exists() and time.monotonic() < deadline:
        time.sleep(.05)
    assert not (tmp_path / 'relay.ready').exists(), 'owned recovery relay did not exit'


def _run(tmp_path, env, source, install, *extra):
    result = _ps(source / 'INSTALL_CANONICAL_PORTABLE.ps1', env,
                 '-SourceRoot', str(source), '-InstallRoot', str(install),
                 '-EvidencePath', str(tmp_path / 'audit.json'), '-Uninstall',
                 '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest', *extra)
    (tmp_path / 'stdout.log').write_text(result.stdout, encoding='utf-8')
    (tmp_path / 'stderr.log').write_text(result.stderr, encoding='utf-8')
    return result


@pytest.mark.parametrize('scenario', ['success', 'partial', 'refusal', 'forged', 'interactive',
                                      'after_removal', 'helper_after_removal', 'final_evidence', 'audit_unavailable', 'fence_release'])
def test_normal_uninstall_real_removal_and_exact_recovery(tmp_path, scenario):
    env, source, install, protected = _setup(tmp_path, scenario)
    original = _tree(install)
    if scenario == 'refusal':
        env['CA_UNINSTALL_REFUSE'] = '1'
    if scenario == 'interactive':
        env['CA_UNINSTALL_INTERACTIVE'] = '1'
    child = _launch_relay(tmp_path, env)
    try:
        result = _run(tmp_path, env, source, install)
        control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control'
        assert all(p.read_bytes() == b'protected-fixture-must-be-preserved' for p in protected)
        assert not (control / 'writer-session/active.json').exists(), result.stderr
        assert not (control / 'container_audit_user_relay.stop.json').exists(), result.stderr
        if scenario == 'success':
            assert result.returncode == 0, result.stderr
            assert 'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED' in result.stdout
            assert not install.exists()
            assert json.loads((tmp_path / 'registry.json').read_text())['exists'] is False
        else:
            assert result.returncode != 0
            assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' in result.stdout, result.stderr
            expected_failure = {
                'partial': 'PARTIAL_REMOVAL_INJECTED_FAILURE',
                'refusal': 'Real current-user removal failed',
                'forged': 'CONTAINER_WRITER_FENCE_DELEGATED_OPERATION_MISMATCH',
                'interactive': 'Replacement restore requires zero Container product processes',
                'after_removal': 'AFTER_REMOVAL_INJECTED_FAILURE',
                'helper_after_removal': 'HELPER_AFTER_REMOVAL_INJECTED_FAILURE',
                'final_evidence': 'AUDIT_INJECTED_FAILURE',
                'audit_unavailable': 'AUDIT_INJECTED_FAILURE',
                'fence_release': 'FENCE_RELEASE_INJECTED_FAILURE',
            }
            assert expected_failure[scenario] in result.stderr, result.stderr
            assert _tree(install) == original
            assert json.loads((tmp_path / 'registry.json').read_text()) == json.loads((tmp_path / 'audit.json').read_text())['preimage']
            assert (tmp_path / 'relay.ready').exists()
            if scenario == 'partial':
                assert 'code_restore_status=PASS_VERIFIED' in result.stdout
            if scenario == 'audit_unavailable':
                assert 'rollback_audit_status=UNAVAILABLE' in result.stdout
            if scenario in {'after_removal', 'final_evidence', 'audit_unavailable', 'fence_release'}:
                assert 'bootstrap_status=PASS' in result.stdout
                assert 'uninstall_status=PASS_CODE_REMOVED_STATE_PRESERVED' in result.stdout
            if scenario == 'helper_after_removal':
                assert 'bootstrap_status=PASS' in result.stdout
            if scenario == 'refusal':
                assert child.poll() is None, 'refusing original relay was terminated'
        assert _tree(source) == {k: v for k, v in original.items() if k != 'bootstrap-integrity.json'}
    finally:
        _finish(tmp_path, child)


@pytest.mark.parametrize('scenario', ['tampered_code', 'missing_record', 'foreign_registry', 'missing_target', 'old_manifest'])
def test_uninstall_identity_rejection_precedes_mutation(tmp_path, scenario):
    env, source, install, _ = _setup(tmp_path)
    if scenario == 'tampered_code':
        path = install / 'app/main.py'
        path.write_bytes(b'X' * path.stat().st_size)
    elif scenario == 'missing_record':
        (install / 'bootstrap-integrity.json').unlink()
    elif scenario == 'foreign_registry':
        (tmp_path / 'registry.json').write_text(json.dumps({'exists': True, 'kind': 'String', 'data': 'unrelated-command'}))
    elif scenario == 'missing_target':
        assert install.resolve().is_relative_to(tmp_path.resolve())
        shutil.rmtree(install)
    else:
        manifest_path = install / 'portable-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['source_commit'] = 'c' * 40
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        result = _ps(tmp_path / 'record.ps1', env)
        assert result.returncode == 0, result.stderr
    original = _tree(install)
    state = _tree(Path(env['LOCALAPPDATA']))
    registry = (tmp_path / 'registry.json').read_bytes()
    result = _run(tmp_path, env, source, install)
    assert result.returncode != 0
    assert _tree(install) == original
    assert _tree(Path(env['LOCALAPPDATA'])) == state
    assert (tmp_path / 'registry.json').read_bytes() == registry
    assert not (tmp_path / 'audit.json').exists()
    expected = {'tampered_code': 'integrity', 'missing_record': 'integrity',
                'foreign_registry': 'CANONICAL_HKCU_RUN_BINDING_MISMATCH',
                'missing_target': 'Uninstall requires the exact installed tree',
                'old_manifest': 'Uninstall installed/source identity differs'}
    assert expected[scenario] in result.stderr, result.stderr


@pytest.mark.parametrize('mode', ['uninstall', 'recover'])
def test_bare_uninstall_and_recovery_require_exact_fence(tmp_path, mode):
    env, source, install, _ = _setup(tmp_path)
    original = _tree(install)
    args = ['-Uninstall'] if mode == 'uninstall' else ['-RestoreUninstallRecordPath', str(install / 'bootstrap-integrity.json')]
    result = _ps(source / 'INSTALL_THIS_PC.ps1', env, *args, '-SourceRoot', str(source),
                 '-InstallRoot', str(install), '-AllowNoncanonicalLayoutForTest')
    assert result.returncode != 0
    assert 'requires exact attempt-bound writer fence parameters' in result.stderr, result.stderr
    assert _tree(install) == original


def test_uninstall_plan_is_read_only_and_does_not_claim_installed_identity(tmp_path):
    env, source, install, _ = _setup(tmp_path)
    original = _tree(tmp_path)
    result = _run(tmp_path, env, source, install, '-PlanOnly')
    assert result.returncode == 0, result.stderr
    assert 'operation=UNINSTALL' in result.stdout
    assert 'uninstall_identity_status=NOT_CHECKED_PLAN_ONLY' in result.stdout
    assert 'registry_changed=false' in result.stdout
    assert {k: v for k, v in _tree(tmp_path).items() if k not in {'stdout.log', 'stderr.log'}} == original
