"""Real CA removal and PowerShell fence/recovery on isolated temporary trees.

Only registry, process census/launch, and fixture signature observations are
adapted. Product dispatch/removal, relay loop/stop mutex, source and installed
identity, session authority, delegation, and code removal/recovery are real.
"""
from __future__ import annotations

from contextlib import contextmanager
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
from tests.native_process_fixtures import native_python_environment, native_python_executable
from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root):
    return {str(p.relative_to(root)): _sha(p) for p in root.rglob('*') if p.is_file()}


PY_HOST = r'''
import json, os, subprocess, sys, time
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
    observation = {
        'ProcessId': os.getpid(),
        'ExecutablePath': os.environ['CA_UNINSTALL_LAUNCH_EXECUTABLE'],
        'CommandLine': os.environ['CA_UNINSTALL_LAUNCH_COMMAND'],
        'fence_active': (direct / 'control/writer-session/active.json').exists(),
    }
    (root / 'relay-observation.json').write_text(json.dumps(observation))
    with (root / 'relay-launches.jsonl').open('a') as stream:
        stream.write(json.dumps(observation) + '\n')
    (root / 'relay.pid').write_text(str(os.getpid()))
    (root / 'relay.ready').touch()
    stop = user_relay.user_relay_stop_path(direct)
    try:
        if os.environ.get('CA_UNINSTALL_REFUSE') == '1':
            import time
            while not (root / 'finish').exists(): time.sleep(.05)
        else:
            user_relay.run_persistent_relay_loop(
                lambda: {'status': 'PASS'}, status_path=user_relay.user_relay_status_path(direct),
                interval_seconds=1, stop_requested=lambda: stop.exists() or (root / 'finish').exists(),
            )
    finally:
        lease.release()
        (root / 'relay.ready').unlink(missing_ok=True)
elif sys.argv[1] == 'remove':
    def delete():
        registry.write_text(json.dumps({'exists': False, 'kind': '', 'data': ''}))
    def get():
        return json.loads(registry.read_text())['data']
    removal = onboarding.remove_current_user_setup
    defaults = getattr(removal, '__wrapped__', removal).__kwdefaults__
    defaults['autostart_remover'] = lambda: user_relay.remove_user_relay_autostart(deleter=delete, getter=get)
    from container_audit_product_host import dispatch_product_mode
    raise SystemExit(dispatch_product_mode(['--remove-current-user-setup', '--app-root', sys.argv[2]]))
else:
    assert sys.argv[1] == 'onboard'
    from tests.test_current_user_onboarding import (
        _FakeExistingPossessionKey, _ready_state, _profile_loader, _credential_loader,
    )
    # Registration, DPAPI/key access and OS launch are isolated boundaries;
    # state inspection, onboarding, autostart readback and ledger creation are real.
    onboarding.PersistentPossessionKey.open_existing = classmethod(
        lambda cls, *args, **kwargs: _FakeExistingPossessionKey()
    )
    app = Path(sys.argv[2])
    sys.executable = str(app.parent / 'runtime/pythonw.exe')
    def register(paths):
        _ready_state(paths)
        return 0
    def setter(command):
        registry.write_text(json.dumps({'exists': True, 'kind': 'String', 'data': command}))
    def launch(arguments):
        environment = dict(os.environ)
        environment['__PYVENV_LAUNCHER__'] = environment['CA_UNINSTALL_VENV_LAUNCHER']
        environment['CA_UNINSTALL_LAUNCH_EXECUTABLE'] = arguments[0]
        environment['CA_UNINSTALL_LAUNCH_COMMAND'] = subprocess.list2cmdline(arguments)
        child = subprocess.Popen(
            [os.environ['CA_UNINSTALL_PYTHON'], '-I', '-B', __file__, 'relay'],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and child.poll() is None:
                if (root / 'relay.ready').exists() and int((root / 'relay.pid').read_text()) == child.pid:
                    return child.pid
                time.sleep(.05)
            raise AssertionError('delegated onboarding relay did not start')
        except BaseException:
            (root / 'finish').touch()
            try:
                child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
            raise
    def relay_launcher(selected_app):
        result = user_relay.start_user_relay_process(selected_app, launcher=launch)
        result['process_id'] = result.pop('launcher_result')
        return result
    defaults = onboarding.onboard_current_user.__wrapped__.__kwdefaults__
    defaults.update(
        registration_runner=register, profile_loader=_profile_loader,
        credential_loader=_credential_loader,
        autostart_installer=lambda selected_app: user_relay.install_user_relay_autostart(
            selected_app, setter=setter, getter=lambda: json.loads(registry.read_text())['data'],
        ),
        relay_launcher=relay_launcher,
    )
    from container_audit_product_host import dispatch_product_mode
    raise SystemExit(dispatch_product_mode(['--onboard-current-user', '--app-root', str(app)]))
'''

OS_BOUNDARIES = r'''
function Get-AuthenticodeSignature { return [pscustomobject]@{ Status='NotTested' } }
function Snapshot { return Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') -Raw | ConvertFrom-Json }
function Restore($Before) { Save (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') $Before }
function Relays {
    if (Test-Path -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'relay.ready')) {
        $relayPid = [int](Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'relay.pid'))
        if (Get-Process -Id $relayPid -ErrorAction SilentlyContinue) {
            return Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'relay-observation.json') -Raw | ConvertFrom-Json
        }
    }
    return @()
}
function Product([string]$Root, [string]$Mode) {
    $expectedPreimagePath = Join-Path $env:CA_UNINSTALL_ROOT 'expected-registry-preimage.json'
    if (Test-Path -LiteralPath $expectedPreimagePath) {
        $persistedAudit = Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json
        $expectedPreimage = Get-Content -LiteralPath $expectedPreimagePath -Raw | ConvertFrom-Json
        if ($persistedAudit.preimage.exists -cne $expectedPreimage.exists -or
            $persistedAudit.preimage.kind -cne $expectedPreimage.kind -or
            $persistedAudit.preimage.data -cne $expectedPreimage.data) {
            throw 'Registry preimage was not durable before product mutation'
        }
        Add-Content -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'preimage-readback.log') -Value $Mode
    }
    Add-Content -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'product-calls.log') -Value $Mode
    $operation = switch -CaseSensitive ($Mode) {
        '--remove-current-user-setup' { 'remove' }
        '--onboard-current-user' { 'onboard' }
        default { throw 'Unexpected product mode' }
    }
    & $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST $operation (Join-Path $Root 'app')
    if ($LASTEXITCODE -ne 0) {
        if ($operation -ceq 'remove') { throw "Real current-user removal failed: $LASTEXITCODE" }
        throw "Real current-user onboarding failed: $LASTEXITCODE"
    }
}
function Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter)
    if ($ClassName -ceq 'Win32_Process' -and $Filter -match '^ProcessId = (\d+)$') {
        $selectedPid = [int]$Matches[1]
        foreach ($relay in @(Relays)) {
            if ([int]$relay.ProcessId -eq $selectedPid) { return $relay }
        }
    }
    return CimCmdlets\Get-CimInstance @PSBoundParameters
}
function StartRaw([string]$Line) {
    if (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\control\writer-session\active.json')) {
        throw 'Ordinary relay restarted while writer fence was active'
    }
    # The child records the actual requested raw spelling, including rollback quotes.
    $env:CA_UNINSTALL_LAUNCH_COMMAND = $Line
    $env:CA_UNINSTALL_LAUNCH_EXECUTABLE = Join-Path $InstallRoot 'runtime\pythonw.exe'
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
    return run_powershell(
        [_powershell(), '-NoLogo', '-NoProfile', '-NonInteractive',
         '-ExecutionPolicy', 'Bypass', '-File', str(path), *args],
        env=env, capture_output=True, text=True, timeout=90,
    )


def _setup(tmp_path, fault=''):
    env = native_python_environment()
    for name in ('LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA', 'TEMP', 'TMP'):
        target = tmp_path / name
        target.mkdir()
        env[name] = str(target)
    env.update(PYTHONDONTWRITEBYTECODE='1', KMTECH_FACTORY_INSTALL_TEST_MODE='1',
               CA_UNINSTALL_REPO=str(ROOT), CA_UNINSTALL_ROOT=str(tmp_path),
               CA_UNINSTALL_PYTHON=str(native_python_executable()),
               CA_UNINSTALL_VENV_LAUNCHER=sys.executable,
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
    env['CA_UNINSTALL_LAUNCH_EXECUTABLE'] = str(install / 'runtime/pythonw.exe')
    env['CA_UNINSTALL_LAUNCH_COMMAND'] = command
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


@contextmanager
def _launch_relay(tmp_path, env):
    with (tmp_path / 'relay.stdout').open('xb') as stdout, (tmp_path / 'relay.stderr').open('xb') as stderr:
        child = subprocess.Popen([env['CA_UNINSTALL_PYTHON'], '-I', '-B', env['CA_UNINSTALL_HOST'], 'relay'],
                                 env=env, stdout=stdout, stderr=stderr,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / 'relay.ready').exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        assert (tmp_path / 'relay.ready').exists(), 'isolated relay did not start; see relay.stderr'
        yield child
    finally:
        _finish(tmp_path, child)


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


def _install(tmp_path, env, source, install):
    if (tmp_path/'expected-registry-preimage.json').exists():
        # A reinstall following uninstall starts from the now-absent registry.
        (tmp_path/'expected-registry-preimage.json').write_bytes((tmp_path/'registry.json').read_bytes())
    result = _ps(source / 'INSTALL_CANONICAL_PORTABLE.ps1', env,
                 '-SourceRoot', str(source), '-InstallRoot', str(install),
                 '-EvidencePath', str(tmp_path / 'reinstall-audit.json'),
                 '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest')
    (tmp_path / 'reinstall-stdout.log').write_text(result.stdout, encoding='utf-8')
    (tmp_path / 'reinstall-stderr.log').write_text(result.stderr, encoding='utf-8')
    return result


def _quote_fixture_executable(env):
    executable = env['CA_UNINSTALL_LAUNCH_EXECUTABLE']
    command = env['CA_UNINSTALL_LAUNCH_COMMAND']
    assert command.startswith(executable + ' ')
    env['CA_UNINSTALL_LAUNCH_COMMAND'] = '"' + executable + '"' + command[len(executable):]
    return env['CA_UNINSTALL_LAUNCH_COMMAND']


def _live_preimage(tmp_path, env, source, install, child):
    assert child.poll() is None
    observation = json.loads((tmp_path / 'relay-observation.json').read_text())
    assert observation['ProcessId'] == child.pid
    assert observation['CommandLine'] == env['CA_UNINSTALL_LAUNCH_COMMAND']
    assert observation['ExecutablePath'] == env['CA_UNINSTALL_LAUNCH_EXECUTABLE']
    (tmp_path / 'expected-registry-preimage.json').write_bytes((tmp_path / 'registry.json').read_bytes())
    control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control'
    return {
        'code': _tree(install), 'source': _tree(source),
        'registry': (tmp_path / 'registry.json').read_bytes(),
        'control': _tree(control), 'observation': observation,
    }


def _assert_binding_rejection_untouched(tmp_path, env, source, install, child, before, result):
    assert result.returncode != 0
    assert 'CANONICAL_RELAY_BINDING_MISMATCH' in result.stderr, result.stderr
    assert child.poll() is None
    assert _tree(install) == before['code']
    assert _tree(source) == before['source']
    assert (tmp_path / 'registry.json').read_bytes() == before['registry']
    control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control'
    assert _tree(control) == before['control']
    assert not (control / 'writer-session/active.json').exists()
    assert not (control / 'container_audit_user_relay.stop.json').exists()
    assert not (tmp_path / 'product-calls.log').exists()
    assert not (tmp_path / 'audit.json').exists()
    assert not (tmp_path / 'reinstall-audit.json').exists()
    assert not (Path(env['LOCALAPPDATA']) / 'KMTech/ContainerAudit/install-audit').exists()
    assert json.loads((tmp_path / 'relay-observation.json').read_text()) == before['observation']


def _assert_preserved_and_released(env, protected):
    assert all(p.read_bytes() == b'protected-fixture-must-be-preserved' for p in protected)
    control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control'
    assert not (control / 'writer-session/active.json').exists()
    assert not (control / 'container_audit_user_relay.stop.json').exists()


def _assert_one_live_relay(tmp_path, env):
    launches = [json.loads(line) for line in (tmp_path / 'relay-launches.jsonl').read_text().splitlines()]
    current = json.loads((tmp_path / 'relay-observation.json').read_text())
    assert (tmp_path / 'relay.ready').exists()
    probe = tmp_path / 'live-relays.ps1'
    probe.write_text(
        "$live = @(Get-CimInstance Win32_Process | Where-Object {\n"
        "    $_.CommandLine -and $_.CommandLine.Contains($env:CA_UNINSTALL_HOST) -and\n"
        "    $_.CommandLine -match '\\srelay\\s*$'\n"
        "})\n"
        f"if ($live.Count -ne 1 -or $live[0].ProcessId -ne {current['ProcessId']}) {{ exit 1 }}\n",
        encoding='utf-8-sig',
    )
    result = _ps(probe, env)
    assert result.returncode == 0, result.stderr
    status = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/status/container_audit_user_relay.json'
    assert json.loads(status.read_text())['persistent_retry'] is True
    return launches, current


def test_live_relay_census_rejects_pid_reuse_as_process_identity(tmp_path):
    env, _, _, _ = _setup(tmp_path)
    with _launch_relay(tmp_path, env) as child:
        status = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/status/container_audit_user_relay.json'
        deadline = time.monotonic() + 10
        while not status.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert status.exists()
        # A retired relay PID can now belong to this unrelated pytest process.
        # The real relay is still alive and remains the observed current PID.
        history = tmp_path / 'relay-launches.jsonl'
        retired = json.loads(history.read_text().splitlines()[0])
        retired['ProcessId'] = os.getpid()
        with history.open('a') as stream:
            stream.write(json.dumps(retired) + '\n')
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert len(launches) == 2
        assert current['ProcessId'] == child.pid


@pytest.mark.parametrize('operation', ['uninstall_then_reinstall', 'reinstall_live'])
def test_quoted_live_relay_uninstall_and_reinstall(tmp_path, operation):
    env, source, install, protected = _setup(tmp_path)
    quoted = _quote_fixture_executable(env)
    canonical_registry = (tmp_path / 'registry.json').read_bytes()
    assert json.loads(canonical_registry)['data'] != quoted
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        if operation == 'uninstall_then_reinstall':
            result = _run(tmp_path, env, source, install)
            if 'CANONICAL_RELAY_BINDING_MISMATCH' in result.stderr:
                _assert_binding_rejection_untouched(tmp_path, env, source, install, child, before, result)
            assert result.returncode == 0, result.stderr
            assert 'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED' in result.stdout
            assert not install.exists()
            assert child.poll() is not None
            assert not (tmp_path / 'relay.ready').exists()
            assert json.loads((tmp_path / 'registry.json').read_text()) == {
                'exists': False, 'kind': '', 'data': '',
            }
            _assert_preserved_and_released(env, protected)
        result = _install(tmp_path, env, source, install)
        if 'CANONICAL_RELAY_BINDING_MISMATCH' in result.stderr:
            _assert_binding_rejection_untouched(tmp_path, env, source, install, child, before, result)
        assert result.returncode == 0, result.stderr
        assert 'install_status=TEST_ONLY_PARTIAL' in result.stdout
        placement = 'PASS_NEW_VERIFIED' if operation == 'uninstall_then_reinstall' else 'REUSED_VERIFIED'
        assert 'code_placement_status=' + placement in result.stdout
        assert json.loads((tmp_path / 'registry.json').read_text()) == json.loads(canonical_registry)
        assert _tree(source) == before['source']
        assert {k: v for k, v in _tree(install).items() if k != 'bootstrap-integrity.json'} == before['source']
        _assert_preserved_and_released(env, protected)
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert launches[0]['CommandLine'] == quoted
        assert current['CommandLine'] == json.loads(canonical_registry)['data']
        assert len(launches) == 3  # original, delegated onboarding, ordinary post-fence restart
        assert [row['fence_active'] for row in launches] == [False, True, False]
        calls = (tmp_path / 'product-calls.log').read_text(encoding='utf-8-sig').splitlines()
        assert calls.count('--onboard-current-user') == 1
        assert calls.count('--remove-current-user-setup') == (2 if operation == 'uninstall_then_reinstall' else 1)
        assert (tmp_path/'preimage-readback.log').read_text(encoding='utf-8-sig').splitlines() == calls


@pytest.mark.parametrize('difference', [
    'executable', 'entrypoint', 'executable_case', 'argument_case', 'added_argument', 'missing_argument',
])
def test_live_relay_command_difference_rejected_before_mutation(tmp_path, difference):
    env, source, install, protected = _setup(tmp_path)
    quoted = _quote_fixture_executable(env)
    commands = {
        'executable': quoted.replace('pythonw.exe', 'python.exe'),
        'entrypoint': quoted.replace('main.py', 'foreign.py'),
        'executable_case': quoted.replace('pythonw.exe', 'PYTHONW.EXE'),
        'argument_case': quoted.replace(' -I ', ' -i '),
        'added_argument': quoted + ' --foreign',
        'missing_argument': quoted.replace(' -B ', ' '),
    }
    env['CA_UNINSTALL_LAUNCH_COMMAND'] = commands[difference]
    if difference == 'executable':
        env['CA_UNINSTALL_LAUNCH_EXECUTABLE'] = env['CA_UNINSTALL_LAUNCH_EXECUTABLE'].replace('pythonw.exe', 'python.exe')
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _run(tmp_path, env, source, install)
        _assert_binding_rejection_untouched(tmp_path, env, source, install, child, before, result)
        _assert_preserved_and_released(env, protected)
        launches, _ = _assert_one_live_relay(tmp_path, env)
        assert len(launches) == 1


def test_incompatible_installed_writer_identity_is_rejected_before_fence_or_relay_mutation(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    inventory_path = install/'tools/container_writer_sink_inventory.json'
    inventory = json.loads(inventory_path.read_text())
    inventory['writer_sinks'][0]['function'] += '_incompatible'
    inventory_path.write_text(json.dumps(inventory), encoding='utf-8')
    manifest_path = install/'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['writer_sink_inventory_sha256'] = _sha(inventory_path)
    files = [p for p in install.rglob('*') if p.is_file() and p not in
             (manifest_path, install/'bootstrap-integrity.json')]
    manifest['file_count_before_manifest'] = len(files)
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    refreshed = _ps(tmp_path/'record.ps1', env)
    assert refreshed.returncode == 0, refreshed.stderr
    _quote_fixture_executable(env)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _install(tmp_path, env, source, install)
        assert result.returncode != 0
        assert child.poll() is None
        assert _tree(install) == before['code']
        assert _tree(source) == before['source']
        assert (tmp_path/'registry.json').read_bytes() == before['registry']
        assert not (tmp_path/'product-calls.log').exists()
        assert not (tmp_path/'reinstall-audit.json').exists()
        assert 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER' in result.stderr
        _assert_preserved_and_released(env, protected)


def test_quoted_live_relay_post_removal_rollback_preserves_raw_command(tmp_path):
    env, source, install, protected = _setup(tmp_path, 'after_removal')
    quoted = _quote_fixture_executable(env)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _run(tmp_path, env, source, install)
        if 'CANONICAL_RELAY_BINDING_MISMATCH' in result.stderr:
            _assert_binding_rejection_untouched(tmp_path, env, source, install, child, before, result)
        assert result.returncode != 0
        assert 'AFTER_REMOVAL_INJECTED_FAILURE' in result.stderr, result.stderr
        assert 'uninstall_status=PASS_CODE_REMOVED_STATE_PRESERVED' in result.stdout
        assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' in result.stdout
        assert _tree(install) == before['code']
        assert _tree(source) == before['source']
        assert json.loads((tmp_path / 'registry.json').read_text()) == json.loads(before['registry'])
        _assert_preserved_and_released(env, protected)
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert len(launches) == 2
        assert child.poll() is not None
        assert current['ProcessId'] != child.pid
        assert all(row['CommandLine'] == quoted for row in launches)
        assert all(row['ExecutablePath'] == before['observation']['ExecutablePath'] for row in launches)
        assert all(row['fence_active'] is False for row in launches)


@pytest.mark.parametrize('scenario', ['success', 'partial', 'refusal', 'forged', 'interactive',
                                      'after_removal', 'helper_after_removal', 'final_evidence', 'audit_unavailable', 'fence_release'])
def test_normal_uninstall_real_removal_and_exact_recovery(tmp_path, scenario):
    env, source, install, protected = _setup(tmp_path, scenario)
    original = _tree(install)
    if scenario == 'refusal':
        env['CA_UNINSTALL_REFUSE'] = '1'
    if scenario == 'interactive':
        env['CA_UNINSTALL_INTERACTIVE'] = '1'
    with _launch_relay(tmp_path, env) as child:
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
