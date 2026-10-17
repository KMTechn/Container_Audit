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
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import pytest

from tests.test_zero_touch_installer import _portable_release_fixture, _powershell
from tests.native_process_fixtures import native_python_environment, native_python_executable
from tests.powershell_contracts import run_powershell, run_functions

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
            while (root / 'refusal-armed').exists() and not (root / 'finish').exists(): time.sleep(.05)
        if not (root / 'finish').exists():
            user_relay.run_persistent_relay_loop(
                lambda: {'status': 'PASS'}, status_path=user_relay.user_relay_status_path(direct),
                interval_seconds=1, stop_requested=lambda: stop.exists() or (root / 'finish').exists(),
            )
    finally:
        lease.release()
        (root / 'relay.ready').unlink(missing_ok=True)
elif sys.argv[1] == 'preflight':
    assert sys.argv[2] == '--onboard-current-user'
    raise SystemExit(onboarding.onboarding_main(sys.argv[3:]))
elif sys.argv[1] == 'prepare-ready':
    from tests.test_current_user_onboarding import _ready_state
    paths = onboarding.resolve_current_user_onboarding_paths(sys.argv[2])
    _ready_state(paths)
    onboarding._create_ledger(paths.ledger_path)
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
    def relay_launcher(selected_app, *, environ=None):
        result = user_relay.start_user_relay_process(selected_app, environ=environ, launcher=launch)
        if result['status'] != 'DEFERRED_CANONICAL_RELEASE':
            result['process_id'] = result.pop('launcher_result')
        return result
    defaults = onboarding.onboard_current_user.__wrapped__.__kwdefaults__
    defaults.update(
        registration_runner=register, profile_loader=_profile_loader,
        credential_loader=_credential_loader,
        autostart_installer=lambda selected_app, **kwargs: user_relay.install_user_relay_autostart(
            selected_app, **kwargs, setter=setter, getter=lambda: json.loads(registry.read_text())['data'],
        ),
        relay_launcher=relay_launcher,
    )
    from container_audit_product_host import dispatch_product_mode
    raise SystemExit(dispatch_product_mode(['--onboard-current-user', '--app-root', str(app)]))
'''

OS_BOUNDARIES = r'''
# PowerShell 7 prepends its own module directory after Python env isolation.
# Restore this fixture's existing Windows PowerShell module path for the
# actual WinPS placement child; keep every child/receipt assertion intact.
$env:PSModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_UNINSTALL_ROOT 'protected-removal')}
function Get-AuthenticodeSignature { return [pscustomobject]@{ Status='NotTested' } }
# Preserve the actual read-only binding reader and adapt only executable/entry
# transport: this minimal packet intentionally contains non-executable PE doubles.
$fixtureReader=(Get-Command Get-CanonicalOnboardingInputBinding).ScriptBlock.ToString()
$fixtureReader=$fixtureReader.Replace('(Join-Path $Root ''runtime\python.exe'')', '$env:CA_UNINSTALL_PYTHON')
$fixtureReader=$fixtureReader.Replace('(Join-Path $Root ''app\main.py'')', '$env:CA_UNINSTALL_PREFLIGHT')
Set-Item Function:Get-CanonicalOnboardingInputBinding ([scriptblock]::Create($fixtureReader))
function Snapshot { return Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') -Raw | ConvertFrom-Json }
function Restore($Before) { Save (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') $Before }
function Relays {
    if (Test-Path -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'relay.ready')) {
        $relayPid = [int](Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'relay.pid'))
        $nativeRelay = Get-Process -Id $relayPid -ErrorAction SilentlyContinue
        if ($null -ne $nativeRelay) {
            $observation = Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'relay-observation.json') -Raw | ConvertFrom-Json
            $observation | Add-Member -NotePropertyName CreationDate -NotePropertyValue $nativeRelay.StartTime -Force
            return $observation
        }
    }
    return @()
}
function Product([string]$Root, [string]$Mode, [string]$AppRoot='') {
    if (-not $AppRoot) { $AppRoot = Join-Path $Root 'app' }
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
    & $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST $operation $AppRoot
    if ($LASTEXITCODE -ne 0) {
        if ($operation -ceq 'remove') { throw "Real current-user removal failed: $LASTEXITCODE" }
        throw "Real current-user onboarding failed: $LASTEXITCODE"
    }
}
function Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter, [string[]]$Property, [uint32]$OperationTimeoutSec)
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

$script:FixtureCaughtFailureWriter=${function:Write-InstallationCaughtFailure}
function Write-InstallationCaughtFailure($Failure) {
    $entries=@();$exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    for($depth=0;$null -ne $exception -and $depth -lt 8;$depth++){
        $entries+=@{type=$exception.GetType().FullName;message=$exception.Message};$exception=$exception.InnerException
    }
    $record=@{exceptions=$entries;script=[string]$Failure.InvocationInfo.ScriptName;line=$Failure.InvocationInfo.ScriptLineNumber;stack=[string]$Failure.ScriptStackTrace}
    [IO.File]::AppendAllText((Join-Path $env:CA_UNINSTALL_ROOT 'caught-failure-private.jsonl'),(($record|ConvertTo-Json -Depth 6 -Compress)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
    & $script:FixtureCaughtFailureWriter $Failure
}

function Test-UninstallFixtureRootPath([string]$Path) {
    if([string]::IsNullOrWhiteSpace($env:CA_UNINSTALL_ROOT) -or [string]::IsNullOrWhiteSpace($Path)){return $false}
    $root=[IO.Path]::GetFullPath($env:CA_UNINSTALL_ROOT).TrimEnd('\')
    $full=[IO.Path]::GetFullPath($Path)
    return ($full.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase))
}
function Test-UninstallFixtureProtectedPath([string]$Path) {
    return (Test-UninstallFixtureRootPath $Path)
}
function Assert-InstallationEvidenceProtectedPath([string]$Path,[switch]$AllowSupportedPreparation) {
    if(Test-UninstallFixtureProtectedPath $Path){
        if(-not(Test-Path -LiteralPath $Path)){throw 'FIXTURE_PROTECTED_PATH_MISSING'}
        Assert-BootstrapNoReparsePoint $Path 'fixture protected boundary' -PathOnly
        return
    }
    & $Script:CAUninstallOriginalProtectionFunctions['Assert-InstallationEvidenceProtectedPath'] $Path -AllowSupportedPreparation:$AllowSupportedPreparation
}
function Assert-BootstrapProtectedRelayPath([string]$Path,[switch]$AllowSupportedPreparation) {
    if(Test-UninstallFixtureProtectedPath $Path){
        if(-not(Test-Path -LiteralPath $Path)){throw 'FIXTURE_PROTECTED_PATH_MISSING'}
        Assert-BootstrapNoReparsePoint $Path 'fixture protected relay boundary' -PathOnly
        return
    }
    & $Script:CAUninstallOriginalProtectionFunctions['Assert-BootstrapProtectedRelayPath'] $Path -AllowSupportedPreparation:$AllowSupportedPreparation
}

function Invoke-InstallationElevationCapture {
    param([string]$Target,[string[]]$Arguments,[string]$AuditBase,[string]$OperatorSid,$AuthorityLease=$null)
    $engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $argv=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Target)+$Arguments
    $child=Invoke-InstallationEvidenceChild 'fixture-retired-elevated-helper' $engine $argv
    [pscustomobject]@{Id=$child.ProcessId;ExitCode=$child.ExitCode;Streams=$child.Streams}
}
'''

HELPER_OS = r'''
function Test-CurrentUserRelayPersistencePresent { return [bool](Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') -Raw | ConvertFrom-Json).exists }
function Get-CimInstance {
    if ($env:CA_UNINSTALL_INTERACTIVE -ceq '1') {
        return [pscustomobject]@{ ProcessId=1; ExecutablePath=(Join-Path $InstallRoot 'runtime\pythonw.exe'); CommandLine='interactive fixture' }
    }
    $ownedRows=@(); $selectedPid=$PID
    for ($depth=0; $selectedPid -gt 0 -and $depth -lt 8; $depth++) {
        $actual=CimCmdlets\Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId='+$selectedPid) -ErrorAction Stop
        if ($null -eq $actual) { throw 'owned helper process disappeared' }
        if ($depth -gt 0 -and ([string]$actual.CommandLine).IndexOf($env:CA_UNINSTALL_ROOT,[StringComparison]::OrdinalIgnoreCase) -lt 0) { break }
        $ownedRows += $actual
        $selectedPid=[int]$actual.ParentProcessId
    }
    if ($ownedRows.Count -lt 2) { throw 'owned helper parent chain was not exercised' }
    Add-Content -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'helper-boundary-phases.txt') -Value 'owned_process_ancestry'
    return $ownedRows
}

Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public class RemovalTask {
 public string Name="fixture"; public string Xml="<Task><Fixture/></Task>";
 public string GetSecurityDescriptor(int flags){return "fixture-sddl";} public void Stop(int flags){}
}
public class RemovalFolder {
 public HashSet<string> Tasks=new HashSet<string>{"direct-sync-relay-container-audit","container-audit-isolated-qualification-authority"};
 public object[] GetTasks(int flags){return new object[0];}
 public RemovalTask GetTask(string name){if(!Tasks.Contains(name))throw new COMException("absent",unchecked((int)0x80070002)); return new RemovalTask();}
 public void DeleteTask(string name,int flags){Tasks.Remove(name);}
}
'@

# The empty task folder is the same implementation as test_convergent_removal.
$script:CAUninstallTaskFolder=[RemovalFolder]::new()
$script:CAUninstallTaskFolder.Tasks.Clear()
$script:CAUninstallTaskService=[pscustomobject]@{Folder=$script:CAUninstallTaskFolder}
$script:CAUninstallTaskService | Add-Member ScriptMethod Connect {}
$script:CAUninstallTaskService | Add-Member ScriptMethod GetFolder {
    param($Path)
    if ($Path -cne '\') { throw 'unexpected task folder' }
    Add-Content -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'helper-boundary-phases.txt') -Value 'isolated_task_folder'
    return $this.Folder
}
function New-Object {
    param([string]$TypeName,[object[]]$ArgumentList,[string]$ComObject)
    if ($ComObject) {
        if ($ComObject -ceq 'WScript.Shell') { return Microsoft.PowerShell.Utility\New-Object -ComObject 'WScript.Shell' }
        if ($ComObject -cne 'Schedule.Service') { throw 'unexpected COM consumer' }
        return $script:CAUninstallTaskService
    }
    return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

# Only OS protection is simulated; journal bytes, tuple and process are real.
$Script:CAUninstallOriginalProtectionFunctions=@{}
foreach($name in @('Test-InstallationEvidencePrivileged','Get-InstallationEvidenceControlRoot','Assert-InstallationEvidenceProtectedPath','New-InstallationProtectedDirectory','Set-InstallationEvidenceAcl','Assert-BootstrapProtectedRelayPath')) {
    $Script:CAUninstallOriginalProtectionFunctions[$name]=(Get-Command $name -CommandType Function -ErrorAction Stop).ScriptBlock
}
function Test-UninstallFixtureRootPath([string]$Path) {
    if([string]::IsNullOrWhiteSpace($env:CA_UNINSTALL_ROOT) -or [string]::IsNullOrWhiteSpace($Path)){return $false}
    $root=[IO.Path]::GetFullPath($env:CA_UNINSTALL_ROOT).TrimEnd('\')
    $full=[IO.Path]::GetFullPath($Path)
    return ($full.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase))
}
function Test-UninstallFixtureProtectedPath([string]$Path) {
    return (Test-UninstallFixtureRootPath $Path)
}
function Protect-KmtechCodeAncestors([string]$CodeParent,[switch]$AdmissionOnly,[switch]$BeforeAppCreation,[string]$ProtectedAncestor) {
    if(-not (Test-UninstallFixtureRootPath $CodeParent)){throw 'FIXTURE_OWNER_BOUNDARY_ESCAPED'}
    Assert-BootstrapNoReparsePoint $CodeParent 'fixture owner boundary' -PathOnly
}
function Test-InstallationEvidencePrivileged {
    if(Test-UninstallFixtureRootPath $UninstallAuditPath){return $true}
    return (& $Script:CAUninstallOriginalProtectionFunctions['Test-InstallationEvidencePrivileged'])
}
function Get-InstallationEvidenceControlRoot {
    if(-not [string]::IsNullOrWhiteSpace($env:CA_UNINSTALL_ROOT)){return (Join-Path $env:CA_UNINSTALL_ROOT 'protected-removal')}
    return (& $Script:CAUninstallOriginalProtectionFunctions['Get-InstallationEvidenceControlRoot'])
}
function Assert-InstallationEvidenceProtectedPath([string]$Path,[switch]$AllowSupportedPreparation) {
    if(Test-UninstallFixtureProtectedPath $Path){
        if(-not(Test-Path -LiteralPath $Path)){throw 'FIXTURE_PROTECTED_PATH_MISSING'}
        Assert-BootstrapNoReparsePoint $Path 'fixture protected boundary' -PathOnly
        return
    }
    & $Script:CAUninstallOriginalProtectionFunctions['Assert-InstallationEvidenceProtectedPath'] $Path -AllowSupportedPreparation:$AllowSupportedPreparation
}
function New-InstallationProtectedDirectory([string]$Path,[string]$Sid,[switch]$RecoverAbandoned) {
    if(Test-UninstallFixtureProtectedPath $Path){
        $existing=$Path
        while(-not(Test-Path -LiteralPath $existing)){$existing=Split-Path -Parent $existing}
        if(-not(Test-UninstallFixtureRootPath $existing)){throw 'FIXTURE_OWNER_BOUNDARY_ESCAPED'}
        Assert-BootstrapNoReparsePoint $existing 'fixture protected directory ancestor' -PathOnly
        [void][IO.Directory]::CreateDirectory($Path)
        Assert-InstallationEvidenceProtectedPath $Path
        return
    }
    & $Script:CAUninstallOriginalProtectionFunctions['New-InstallationProtectedDirectory'] $Path $Sid -RecoverAbandoned:$RecoverAbandoned
}
function Set-InstallationEvidenceAcl([string]$Path,[string]$Sid,[switch]$Directory,[switch]$PrepareOnly) {
    if(Test-UninstallFixtureProtectedPath $Path){Assert-InstallationEvidenceProtectedPath $Path;return}
    & $Script:CAUninstallOriginalProtectionFunctions['Set-InstallationEvidenceAcl'] $Path $Sid -Directory:$Directory -PrepareOnly:$PrepareOnly
}

function Assert-BootstrapProtectedRelayPath([string]$Path,[switch]$AllowSupportedPreparation) {
    if(Test-UninstallFixtureProtectedPath $Path){
        if(-not(Test-Path -LiteralPath $Path)){throw 'FIXTURE_PROTECTED_PATH_MISSING'}
        Assert-BootstrapNoReparsePoint $Path 'fixture protected relay boundary' -PathOnly
        return
    }
    & $Script:CAUninstallOriginalProtectionFunctions['Assert-BootstrapProtectedRelayPath'] $Path -AllowSupportedPreparation:$AllowSupportedPreparation
}

$script:FixtureCaughtFailureWriter=${function:Write-InstallationCaughtFailure}
function Write-InstallationCaughtFailure($Failure) {
    $entries=@();$exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    for($depth=0;$null -ne $exception -and $depth -lt 8;$depth++){
        $entries+=@{type=$exception.GetType().FullName;message=$exception.Message};$exception=$exception.InnerException
    }
    $record=@{exceptions=$entries;script=[string]$Failure.InvocationInfo.ScriptName;line=$Failure.InvocationInfo.ScriptLineNumber;stack=[string]$Failure.ScriptStackTrace}
    [IO.File]::AppendAllText((Join-Path $env:CA_UNINSTALL_ROOT 'caught-failure-private.jsonl'),(($record|ConvertTo-Json -Depth 6 -Compress)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
    & $script:FixtureCaughtFailureWriter $Failure
}
'''


def _ps(path, env, *args):
    result = run_powershell(
        [_powershell(), '-NoLogo', '-NoProfile', '-NonInteractive',
         '-ExecutionPolicy', 'Bypass', '-File', str(path), *args],
        # Native contracts finish naturally; task policy forbids timeout kills.
        env=env, capture_output=True, text=True,
    )
    observations = [json.loads(line.removeprefix('ca_fixture_audit='))
                    for line in result.stdout.splitlines() if line.startswith('ca_fixture_audit=')]
    assert len(observations) <= 1
    result.fixture_audit = observations[0] if observations else None
    return result


def _setup(tmp_path, fault='', *, stock_version_identity=False, install_directory=None):
    env = native_python_environment()
    for name in ('LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA', 'TEMP', 'TMP'):
        target = tmp_path / name
        target.mkdir()
        env[name] = str(target)
    env.update(PYTHONDONTWRITEBYTECODE='1', KMTECH_FACTORY_INSTALL_TEST_MODE='1',
               KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=str(tmp_path / 'known-folders'),
               CA_UNINSTALL_REPO=str(ROOT), CA_UNINSTALL_ROOT=str(tmp_path), CA_UNINSTALL_INJECT='1',
               CA_UNINSTALL_PYTHON=str(native_python_executable()),
               CA_UNINSTALL_VENV_LAUNCHER=sys.executable,
               CA_UNINSTALL_MUTEX='Local\\Container.UninstallTest.' + uuid.uuid4().hex)
    env['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
    env.pop('CONTAINER_AUDIT_DATA_ROOT', None)
    env.pop('KMTECH_CONTAINER_WRITER_CONTROL_ROOT', None)
    host = tmp_path / 'host.py'
    host.write_text(PY_HOST, encoding='utf-8')
    env['CA_UNINSTALL_HOST'] = str(host)
    preflight = tmp_path/'preflight.py'
    preflight.write_text(
        "import os, runpy, sys\n"
        "sys.argv=[os.environ['CA_UNINSTALL_HOST'], 'preflight', *sys.argv[1:]]\n"
        "runpy.run_path(os.environ['CA_UNINSTALL_HOST'], run_name='__main__')\n", encoding='utf-8')
    env['CA_UNINSTALL_PREFLIGHT'] = str(preflight)
    source = _portable_release_fixture(tmp_path, directory='packet')
    (source / 'app/assets').mkdir(exist_ok=True)
    (source / 'app/assets/logo.ico').write_bytes(b'isolated-shortcut-icon')
    if stock_version_identity:
        # 416 source admission reads the stock manifest/version before install.
        # Supply real version bytes to this partial packet while retaining both
        # admission guards and every lifecycle assertion.
        from auto_update import source_version_literal

        version_file = ROOT / 'Container_Audit.py'
        shutil.copyfile(version_file, source / 'app/Container_Audit.py')
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig').replace('$wanted = Command $install', OS_BOUNDARIES + '\n$wanted = Command $install')
    audit_assignment = '$auditPath = Join-Path $auditRoot "canonical-portable-$runId.json"'
    assert text.count(audit_assignment) == 1
    # Observe real run/PID provenance; evidence initialization and BasePath stay
    # byte-for-byte product calls (3115733), including their actual tree location.
    text = text.replace(audit_assignment, audit_assignment + '\n'
                        + "[Console]::WriteLine('ca_fixture_audit=' + ([ordered]@{run_id=$runId; process_id=$PID; audit_path=$auditPath} | ConvertTo-Json -Compress))")
    if fault == 'diagnostic':
        env['CA_UNINSTALL_SYNTHETIC'] = uuid.uuid4().hex + uuid.uuid4().hex
        text, replacements = re.subn(r'(?m)^(\$Script:CanonicalWriterFenceDelegationToken\s*=\s*).+$',
                                     r'\1$env:CA_UNINSTALL_SYNTHETIC', text)
        assert replacements == 2  # Initial attempt and rollback-continuation renewal.
    if fault == 'after_removal':
        target = "        $removed=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $install) 'removed.json')"
        assert text.count(target) == 1
        text = text.replace(target, "        if($env:CA_UNINSTALL_INJECT -ceq '1'){throw ('AFTER_REMOVAL_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET)}\n" + target)
        retired_target = '        if ((Test-Path -LiteralPath $install) -or (Snapshot).exists -or @(Relays).Count -ne 0) {'
        assert text.count(retired_target) == 1
        text = text.replace(retired_target, "        if($env:CA_UNINSTALL_INJECT -ceq '1'){throw ('AFTER_REMOVAL_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET)}\n" + retired_target)
    elif fault in {'final_evidence', 'audit_unavailable'}:
        condition = "$Value.status -ceq 'PASS_UNINSTALLED_DATA_PRESERVED' -and $Path -ceq $EvidencePath"
        if fault == 'audit_unavailable':
            condition = "($Value.status -ceq 'UNINSTALL_AWAITING_FENCE_RELEASE' -or $Value.status -ceq 'FAILED_REMOVAL_INCOMPLETE' -or $Value.status -ceq 'FAILED_ROLLED_BACK')"
        target = 'function Save([string]$Path, $Value, [bool]$SanitizeDiagnostics=$false) {'
        assert text.count(target) == 1
        text = text.replace(target, target + "\n    if ($env:CA_UNINSTALL_INJECT -ceq '1' -and (($Value -is [Collections.IDictionary] -and $Value.Contains('status')) -or ($null -ne $Value.PSObject.Properties['status'])) -and (" + condition + ")) { throw ('AUDIT_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET) }")
    elif fault == 'forged':
        target = "$child=Invoke-InstallationEvidenceChild 'supported-content-removal' $winps $args"
        assert text.count(target) == 1
        text = text.replace(target, "if($env:CA_UNINSTALL_INJECT -ceq '1'){$args[$args.IndexOf('-WriterFenceDelegationToken')+1]=('e'*64)}\n        " + target)
        retired_target = "$capturedChild = Invoke-InstallationEvidenceChild 'uninstall-helper' $winps $uninstallArguments"
        assert text.count(retired_target) == 1
        text = text.replace(retired_target, "if($env:CA_UNINSTALL_INJECT -ceq '1'){$uninstallArguments[$uninstallArguments.IndexOf('-WriterFenceDelegationToken')+1]=('e'*64)}\n        " + retired_target)
    elif fault == 'fence_release':
        target = "        Clear-CanonicalWriterFenceReleaseDelegation\n        Stop-CanonicalWriterFenceRelease $releaseAuthorization\n        $canonicalWriterFenceActive=$false"
        assert text.count(target) == 1
        text = text.replace(target, target.replace('        Stop-CanonicalWriterFenceRelease', "        if($env:CA_UNINSTALL_INJECT -ceq '1'){throw ('FENCE_RELEASE_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET)}\n        Stop-CanonicalWriterFenceRelease"))
        retired_target = "        if ($CompleteRetiredRemoval) { Set-InstallationEvidenceStage 'retirement.release_authorized' }\n        Stop-CanonicalWriterFenceRelease $releaseAuthorization"
        assert text.count(retired_target) == 1
        text = text.replace(retired_target, retired_target.replace('        Stop-CanonicalWriterFenceRelease', "        if($env:CA_UNINSTALL_INJECT -ceq '1'){throw ('FENCE_RELEASE_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET)}\n        Stop-CanonicalWriterFenceRelease"))
    canonical.write_text(text, encoding='utf-8-sig')
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig').replace('$testOverride = (', HELPER_OS + '\n$testOverride = (')
    preparation_exit = 'if(Test-InstallationEvidencePrivileged){exit (Get-InstallationPreparationExitCode $_)}'
    assert text.count(preparation_exit) == 1
    text = text.replace(preparation_exit,
        "Write-Output (ConvertTo-KmtechRedactedSinkText -Text ('fixture_preparation_failure='+((Get-InstallationFailureDetails $_)|ConvertTo-Json -Depth 6 -Compress)))\n        " + preparation_exit)
    if fault in {'partial', 'restore_failure', 'partial_foreign', 'partial_damaged', 'diagnostic'}:
        target = '        $removed = Invoke-ContainerConvergentRemoval -InstallRoot $installRootFull -TaskFolder $folder -ExcludeProcessIds $excluded'
        assert text.count(target) == 1
        extra = ''
        if fault == 'partial_foreign':
            extra = "        [IO.File]::WriteAllText((Join-Path $installRootFull 'unknown.txt'),'preserve-unknown')\n"
        elif fault == 'partial_damaged':
            extra = "        [IO.File]::WriteAllText((Join-Path $installRootFull 'app\\Container_Audit.py'),'changed-known-file')\n"
        elif fault == 'diagnostic':
            extra = "        [Console]::Out.WriteLine(('first-cause-'*800)+'END_FIRST_CAUSE'+$WriterFenceDelegationToken)\n"
        text = text.replace(target, "        if($env:CA_UNINSTALL_INJECT -ceq '1'){\n        Remove-Item -LiteralPath (Join-Path $installRootFull 'app\\main.py')\n" + extra + "        throw ('PARTIAL_REMOVAL_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET)\n        }\n" + target)
        if fault == 'restore_failure':
            recovery = '    if ($RestoreUninstallRecordPath) {\n        Copy-Item -LiteralPath $RestoreUninstallRecordPath'
            assert text.count(recovery) == 1
            text = text.replace(recovery, "    if ($RestoreUninstallRecordPath) {\n        throw 'RESTORE_INJECTED_FAILURE'\n        Copy-Item -LiteralPath $RestoreUninstallRecordPath")
    elif fault == 'helper_after_removal':
        target = "        'uninstall_status=PASS_KNOWN_FILES_REMOVED_STATE_PRESERVED'"
        assert text.count(target) == 1
        text = text.replace(target, "        if($env:CA_UNINSTALL_INJECT -ceq '1'){throw ('HELPER_AFTER_REMOVAL_INJECTED_FAILURE'+$env:CUSTOM_REMOVAL_SECRET)}\n" + target)
    helper.write_text(text, encoding='utf-8-sig')
    fence = source / 'tools/container_writer_fence.ps1'
    text = fence.read_text(encoding='utf-8-sig').replace(
        "'Local\\KMTech.ContainerAudit.WriterAdmission.v1'", "'" + env['CA_UNINSTALL_MUTEX'] + "'")
    fence.write_text(text, encoding='utf-8-sig')
    manifest_path = source / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if stock_version_identity:
        manifest['version'] = source_version_literal(version_file.read_bytes())
    for field, name in [('installer', canonical), ('helper', helper), ('writer_fence_helper', fence)]:
        manifest[field + '_sha256'] = _sha(name)
    files = [p for p in source.rglob('*') if p.is_file() and p != manifest_path]
    manifest['file_count_before_manifest'] = len(files)
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    install = tmp_path / (install_directory or 'owned/current')
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
    prepared = Path(env['CA_UNINSTALL_ROOT'])/'prepared-protected.json'
    if prepared.exists():
        before = json.loads(prepared.read_text())
        assert {str(p): _sha(p) for p in protected} == before
    else:
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
    env, source, install, protected = _setup(tmp_path, stock_version_identity=True)
    ready = subprocess.run([env['CA_UNINSTALL_PYTHON'], '-I', '-B', env['CA_UNINSTALL_HOST'],
                            'prepare-ready', str(install/'app')], env=env, capture_output=True, timeout=30)
    assert ready.returncode == 0, 'owned current-user state preparation failed'
    (tmp_path/'prepared-protected.json').write_text(json.dumps({str(p): _sha(p) for p in protected}))
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
        assert len(launches) == 2  # canonical onboarding defers its resident until fence release
        assert [row['fence_active'] for row in launches] == [False, False]
        calls = (tmp_path / 'product-calls.log').read_text(encoding='utf-8-sig').splitlines()
        assert calls.count('--onboard-current-user') == 1
        assert calls.count('--remove-current-user-setup') == (2 if operation == 'uninstall_then_reinstall' else 1)
        assert (tmp_path/'preimage-readback.log').read_text(encoding='utf-8-sig').splitlines() == calls


@pytest.mark.parametrize('difference', [
    'executable', 'entrypoint', 'executable_case', 'argument_case', 'added_argument', 'missing_argument',
])
def test_supported_removal_quiesces_owned_relay_without_machine_identity_precondition(tmp_path, difference):
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
        assert result.returncode == 0, result.stderr
        assert 'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED' in result.stdout
        assert not install.exists() and child.poll() is not None
        assert json.loads((tmp_path/'registry.json').read_text())['exists'] is False
        assert _tree(source) == before['source']
        _assert_preserved_and_released(env, protected)
        launches = (tmp_path/'relay-launches.jsonl').read_text().splitlines()
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
        _assert_canonical_public_failure(result, tmp_path, 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER', source)
        _assert_preserved_and_released(env, protected)


def _assert_canonical_public_failure(result, root, expected_cause, source=None):
    # 405 / redaction contract 0f: preserve the exact original cause in the
    # SHA-bound private record; expose fixed fields through the public boundary.
    records = [json.loads(line.split('=', 1)[1]) for line in result.stdout.splitlines()
               if line.startswith('CONTAINER_AUDIT_INSTALL_CANONICAL=')]
    failures = [record for record in records if record.get('status') == 'FAILED']
    assert len(failures) == 1
    failure = failures[0]
    assert result.returncode == failure['exit_code'] == 1
    assert failure['stage'] == 'canonical_install'
    assert failure['reason_code'] == 'INSTALLER_CANONICAL_FAILURE'
    assert result.stderr == ''
    assert not any(key in failure for key in ('message', 'detail', 'traceback', 'stderr'))
    if failure.get('report_status') == 'REPORT_UNAVAILABLE':
        # The pre-fence preparation guard can precede evidence initialization.
        # Its actual throw location, rather than generic failure alone, proves
        # the exact semantic rejection tested by this fixture.
        assert source is not None
        lines = (source / 'INSTALL_CANONICAL_PORTABLE.ps1').read_text(encoding='utf-8-sig').splitlines()
        if expected_cause == 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER':
            # Bind the current-user preflight guard, independently of machine
            # guards that report the same cause earlier in the source file.
            starts = [number for number, line in enumerate(lines, 1)
                      if line.strip() == '$preflightCandidate = InstalledManifest $install $SkipSignatureValidationForTest']
            assert len(starts) == 1
            ends = [number for number, line in enumerate(lines, 1)
                    if number > starts[0] and line.startswith('$lad = Full $env:LOCALAPPDATA ')]
            assert len(ends) == 1
            guards = [number for number, line in enumerate(lines, 1)
                      if starts[0] < number < ends[0]
                      and line.strip() == "throw 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'"]
            assert len(guards) == 1
        else:
            guards = [number for number, line in enumerate(lines, 1)
                      if 'throw' in line and expected_cause in line]
        assert guards and failure['location_line'] == min(guards)
        assert failure['exception_type'] == 'System.Management.Automation.RuntimeException'
        return
    report = Path(failure['report_path'])
    assert report.resolve().is_relative_to(root.resolve())
    assert failure['report_sha256'] == _sha(report)
    assert report.stat().st_size <= 65536
    detail = json.loads(report.read_bytes())
    assert detail['schema'] == 'container-audit-original-installation-failure-v1'
    bound_cause = any(expected_cause in item.get('message', '')
                      for item in detail['failure']['exception_chain'])
    assert bound_cause, 'SHA-bound protected original cause differs'



def _assert_removed_and_preserved(tmp_path, env, source, install, protected, source_before, retained=None):
    if retained:
        assert _tree(install) == retained
    else:
        assert not install.exists()
    assert json.loads((tmp_path/'registry.json').read_text()) == {'exists': False, 'kind': '', 'data': ''}
    assert not (tmp_path/'relay.ready').exists()
    assert _tree(source) == source_before
    _assert_preserved_and_released(env, protected)
    marker = json.loads((install.parent/'removed.json').read_text())
    assert marker['schema'] == 'container-audit-supported-removal-v1'
    assert marker['lifecycle_state'] == 'REMOVED'


def _rerun_without_fault(tmp_path, env, source, install):
    env['CA_UNINSTALL_INJECT'] = '0'
    env['CA_UNINSTALL_REFUSE'] = '0'
    env['CA_UNINSTALL_INTERACTIVE'] = '0'
    (tmp_path/'refusal-armed').unlink(missing_ok=True)
    result = _run(tmp_path, env, source, install)
    assert result.returncode == 0, result.stderr
    assert 'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED' in result.stdout
    return result


def test_quoted_live_relay_post_removal_failure_converges_without_resurrection(tmp_path):
    env, source, install, protected = _setup(tmp_path, 'after_removal')
    quoted = _quote_fixture_executable(env)
    source_before = _tree(source)
    with _launch_relay(tmp_path, env) as child:
        result = _run(tmp_path, env, source, install)
        _assert_canonical_public_failure(result, tmp_path, 'AFTER_REMOVAL_INJECTED_FAILURE')
        assert child.poll() is not None and not install.exists()
        assert json.loads((tmp_path/'registry.json').read_text())['exists'] is False
        audit = Path(result.fixture_audit['audit_path'])
        first_failure = audit.read_bytes()
        record = json.loads(first_failure)
        assert record['status'] == 'FAILED_REMOVAL_INCOMPLETE'
        assert record['rollback']['applied'] is False and record['rollback']['runtime_restored'] is False
        _rerun_without_fault(tmp_path, env, source, install)
        assert audit.read_bytes() == first_failure
        _assert_removed_and_preserved(tmp_path, env, source, install, protected, source_before)
        launches = [json.loads(line) for line in (tmp_path/'relay-launches.jsonl').read_text().splitlines()]
        assert len(launches) == 1 and launches[0]['CommandLine'] == quoted


@pytest.mark.parametrize('scenario', ['success', 'partial', 'refusal', 'forged', 'interactive',
                                      'after_removal', 'helper_after_removal', 'final_evidence', 'audit_unavailable', 'fence_release'])
def test_normal_uninstall_real_removal_and_forward_convergence(tmp_path, scenario):
    # eb9ecf2 / operations.md:244-253; 1차 19:3x approved replacement of
    # prior PASS_EXACT_PREIMAGE_SAFE_TO_RETRY / Run-and-code revival expectations.
    env, source, install, protected = _setup(tmp_path, scenario)
    source_before = _tree(source)
    env['CUSTOM_REMOVAL_SECRET'] = uuid.uuid4().hex + uuid.uuid4().hex
    retained = None
    if scenario == 'partial':
        unknown = install/'unknown-business.txt'
        unknown.write_bytes(b'preserve-unknown-business')
        retained = {'unknown-business.txt': _sha(unknown)}
    if scenario == 'refusal':
        env['CA_UNINSTALL_REFUSE'] = '1'
        (tmp_path/'refusal-armed').touch()
    if scenario == 'interactive': env['CA_UNINSTALL_INTERACTIVE'] = '1'
    with _launch_relay(tmp_path, env) as child:
        result = _run(tmp_path, env, source, install)
        assert all(p.read_bytes() == b'protected-fixture-must-be-preserved' for p in protected)
        control = Path(env['LOCALAPPDATA'])/'KMTech/DirectSync/container_audit/control'
        assert not (control/'writer-session/active.json').exists(), result.stderr
        first_audit = Path(result.fixture_audit['audit_path'])
        first_record_bytes = first_audit.read_bytes()
        record = json.loads(first_record_bytes)
        if scenario == 'success':
            assert result.returncode == 0, result.stderr
            assert record['status'] == 'PASS_UNINSTALLED_DATA_PRESERVED'
        else:
            assert result.returncode != 0, result.stdout
            assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' not in result.stdout
            assert record['rollback']['applied'] is False and record['rollback']['runtime_restored'] is False
            # A failed audit write leaves its original PREIMAGE record intact;
            # the independent stage evidence retains the first failure.
            if scenario == 'audit_unavailable':
                assert record['status'] == 'PREIMAGE_SAVED'
                _assert_canonical_public_failure(result, tmp_path, 'AUDIT_INJECTED_FAILURE')
            else:
                assert record['status'] == 'FAILED_REMOVAL_INCOMPLETE'
                assert record['failure_type'] and record['failure']
            assert json.loads((tmp_path/'registry.json').read_text())['exists'] is False
            if scenario == 'refusal': assert child.poll() is None
        launches = [json.loads(line) for line in (tmp_path/'relay-launches.jsonl').read_text().splitlines()]
        assert len(launches) == 1, 'failed removal must not restart the old relay'
        raw = env['CUSTOM_REMOVAL_SECRET'].encode()
        assert all(raw not in payload for payload in (result.stdout.encode(), result.stderr.encode(), first_record_bytes))
        _rerun_without_fault(tmp_path, env, source, install)
        assert first_audit.read_bytes() == first_record_bytes, 'original failure record was overwritten'
        _assert_removed_and_preserved(tmp_path, env, source, install, protected, source_before, retained)
        # A further identical run is idempotent, with the same immutable source.
        _rerun_without_fault(tmp_path, env, source, install)
        assert first_audit.read_bytes() == first_record_bytes
        _assert_removed_and_preserved(tmp_path, env, source, install, protected, source_before, retained)


@pytest.mark.parametrize('scenario', ['tampered_code', 'missing_record', 'foreign_registry', 'missing_target', 'old_manifest'])
def test_supported_uninstall_preserves_unverified_content_and_removes_owned_content(tmp_path, scenario):
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
    source_before = _tree(source)
    result = _run(tmp_path, env, source, install)
    assert result.returncode == 0, result.stderr
    assert 'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED' in result.stdout
    assert _tree(source) == source_before
    assert json.loads((tmp_path/'registry.json').read_text())['exists'] is False
    marker = json.loads((install.parent/'removed.json').read_text())
    assert marker['lifecycle_state'] == 'REMOVED'
    if scenario == 'tampered_code':
        assert (install/'app/main.py').read_bytes() == b'X' * len((install/'app/main.py').read_bytes())
        assert not (install/'app/kmtech_shared/portable.py').exists()
        assert marker['retained_paths']
    elif scenario == 'missing_record':
        assert _tree(install) == original and marker['retained_paths']
    else:
        assert not install.exists()
    retained = _tree(install)
    _rerun_without_fault(tmp_path, env, source, install)
    assert _tree(install) == retained and _tree(source) == source_before


@pytest.mark.parametrize('mode', ['uninstall', 'recover'])
def test_bare_uninstall_and_recovery_require_exact_fence(tmp_path, mode):
    env, source, install, _ = _setup(tmp_path)
    original = _tree(install)
    args = ['-Uninstall'] if mode == 'uninstall' else ['-RestoreUninstallRecordPath', str(install / 'bootstrap-integrity.json')]
    result = _ps(source / 'INSTALL_THIS_PC.ps1', env, *args, '-SourceRoot', str(source),
                 '-InstallRoot', str(install), '-AllowNoncanonicalLayoutForTest')
    assert result.returncode != 0
    assert 'CONTAINER_WRITER_FENCE_PARAMETERS_INVALID' in result.stderr, result.stderr
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

@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', ('exact', 'request', 'preexisting_time', 'path', 'byte_mutation'))
def test_supported_removal_cleans_only_exact_current_attempt_stop(tmp_path, engine, case):
    result = run_functions(tmp_path, ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Remove-CanonicalSupportedRemovalAttemptStop','Sha','Same','Full','Test-ExactPropertySet'], r'''
function Snapshot { return @{exists=$false} }
function Assert-ContainerWriterFenceNoReparse([string]$Path) { Assert-BootstrapNoReparsePoint $Path 'owned stop fixture' -PathOnly }
$root=$env:CA_CONTRACT_ROOT
$stop=Join-Path $root 'stop.json';$receiptPath=Join-Path $root 'removal.json';$app=Join-Path $root 'app'
$started=[DateTime]::UtcNow;$at=$started.ToString('o');$request='a'*32
$marker=@{schema_version='container-audit-user-relay-stop-v1';request_id=$request;requested_at=$at}
$receipt=@{report_version='container-audit-current-user-removal-v1';state_scope='current_user';data_preserved=$true;
 machine_code_root=$app;captured_at=$at;relay_autostart=@{status='ABSENT'};
 relay_process=@{status='UNKNOWN';request_id=$request;stop_request_path=$stop}}
Write-Utf8Json $stop $marker
$expected=Sha $stop
switch($env:CA_STOP_CASE){
 request {$receipt.relay_process.request_id='b'*32}
 preexisting_time {$receipt.captured_at=$started.AddSeconds(-2).ToString('o')}
 path {$receipt.relay_process.stop_request_path=Join-Path $root 'foreign.json'}
 byte_mutation {$marker.request_id='b'*32;$receipt.relay_process.request_id='b'*32;Write-Utf8Json $stop $marker}
}
Write-Utf8Json $receiptPath $receipt
$before=Sha $stop;$refused=$false
try{$answer=Remove-CanonicalSupportedRemovalAttemptStop $receiptPath $stop $started $app $expected}catch{$refused=$true}
if($env:CA_STOP_CASE -ceq 'exact'){
 if($refused -or $answer -cne 'REMOVED_EXACT_CURRENT_ATTEMPT' -or (Test-Path $stop)){throw 'owned cleanup failed'}
}else{
 if(-not $refused -or (Sha $stop) -cne $before){throw 'foreign or altered marker changed'}
}
'PASS'
''', engine=engine, values={'CA_STOP_CASE':case})
    assert result.returncode == 0, 'exact stop ownership contract failed; diagnostics retained privately'
    assert result.stdout.strip() == 'PASS'
