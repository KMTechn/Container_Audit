"""Scheduled task census contracts, without querying or mutating host tasks."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'
ADAPTER = ROOT / 'tools/container_writer_session.ps1'
SNAPSHOT_FUNCTIONS = [
    'Full', 'Same', 'ShaText', 'UtcText', 'Sha', 'FileObservation',
    'Get-PrincipalSid', 'Get-CanonicalTaskProperty', 'Get-CanonicalWriterBinding', 'Get-CanonicalWriterSnapshot',
]
READBACK_FUNCTIONS = [
    'Get-ObjectPropertyValue', 'Get-StringSha256', 'Get-CurrentUserSid', 'Test-PrincipalIsCurrentUser',
    'Get-ContainerWriterReadback',
]

TASK_INPUTS = r'''
Set-StrictMode -Version Latest
$root = Join-Path $env:CA_CONTRACT_ROOT 'current'
$env:LOCALAPPDATA = Join-Path $env:CA_CONTRACT_ROOT 'local'
$Script:TaskName = 'direct-sync-relay-container-audit'
$Script:TaskPath = '\'
$Script:RelayMode = '--container-audit-direct-sync-relay'
$CanonicalWriterTaskName = $Script:TaskName
$NoncanonicalQualificationTaskName = 'container-audit-isolated-qualification-authority'
$log = Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\logs\scheduled_direct_sync_relay.jsonl'
$status = Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\status\scheduled_direct_sync_relay_status.json'
$trigger = [pscustomobject]@{
    CimClass=[pscustomobject]@{CimClassName='MSFT_TaskTimeTrigger'}
    Enabled=$true; StartBoundary='2026-09-20T00:00:00Z'
    Repetition=[pscustomobject]@{Interval='PT1M'; Duration=''; StopAtDurationEnd=$false}
}
$task = [pscustomobject]@{
    TaskName=$Script:TaskName; TaskPath='\'; State='Ready'
    Actions=@([pscustomobject]@{
        Execute=(Join-Path $root 'runtime\python.exe')
        Arguments=('"' + (Join-Path $root 'app\main.py') + '" ' + $Script:RelayMode + ' --log-path "' + $log + '" --status-path "' + $status + '"')
        WorkingDirectory=(Join-Path $root 'app')
    })
    Principal=[pscustomobject]@{
        UserId=[Environment]::UserName; LogonType='Interactive'; RunLevel='Limited'
    }
    Triggers=@($trigger)
    Settings=[pscustomobject]@{
        Enabled=$true; StartWhenAvailable=$true; MultipleInstances='IgnoreNew'
        ExecutionTimeLimit='PT2M'; DisallowStartIfOnBatteries=$false; StopIfGoingOnBatteries=$false
    }
}
switch ($env:CA_TRIGGER) {
    'null' { $task.Triggers=$null }
    'empty' { $task.Triggers=@() }
    'missing' { $task.PSObject.Properties.Remove('Triggers') }
    'no_class' { $trigger.PSObject.Properties.Remove('CimClass') }
    'null_class' { $trigger.CimClass=$null }
    'other_cim' { $task.Triggers=@(New-CimInstance -ClassName Win32_Process -ClientOnly) }
    'mixed' { $task.Triggers=@($trigger, (New-CimInstance -ClassName Win32_Process -ClientOnly)) }
    'mixed_null' { $task.Triggers=@($trigger, $null) }
    'no_repetition' { $trigger.PSObject.Properties.Remove('Repetition') }
    'wrong_interval' { $trigger.Repetition.Interval='PT5M' }
}
$script:tasks=@($task)
function Get-ScheduledTask { [CmdletBinding()] param(); return $script:tasks }
function Get-ScheduledTaskInfo {
    [CmdletBinding()] param($TaskName, $TaskPath)
    return [pscustomobject]@{
        LastTaskResult=0; LastRunTime=[datetime]'2026-09-20T00:00:00Z'
        NextRunTime=[datetime]'2026-09-20T00:01:00Z'
    }
}
function Get-CanonicalWriterProcesses { param($Root); return @() }
function Get-ContainerWriterProcessCount { param($Root); return 0 }
function Export-ScheduledTask { [CmdletBinding()] param($TaskName, $TaskPath); return '<Task/>' }
'''


def _snapshot(tmp_path, script, *, trigger='valid', values=None):
    inventory = str(ROOT / 'tools/container_writer_sink_inventory.json').replace("'", "''")
    return run_functions(tmp_path, INSTALLER, SNAPSHOT_FUNCTIONS,
                         f"$sourceWriterInventory=Get-Content -LiteralPath '{inventory}' -Raw | ConvertFrom-Json\n"
                         + TASK_INPUTS + script,
                         values={'CA_TRIGGER': trigger, **(values or {})})


@pytest.mark.parametrize('trigger', ['null', 'empty', 'missing', 'other_cim', 'mixed'])
def test_census_ignores_display_capture_and_non_exec_tasks(tmp_path, trigger):
    result = _snapshot(tmp_path, r'''
$task.TaskName='DisplayCapture'
$task.Actions[0].Execute='powershell.exe'
$task.Actions[0].Arguments='-File D:\capture\Container_Audit\wrapper.ps1 -Title ContainerAudit'
$com = [pscustomobject]@{
    TaskName='WindowsComHandler'; TaskPath='\Microsoft\Windows\'
    Actions=@(New-CimInstance -ClassName MSFT_TaskComHandlerAction -Namespace root/Microsoft/Windows/TaskScheduler -ClientOnly)
    Triggers=$null
}
$script:tasks=@($task, $com)
Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress
''', trigger=trigger)
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    assert observed['present'] is False
    assert observed['noncanonical_disabled'] == []


@pytest.mark.parametrize('mode', [
    '--container-audit-direct-sync-relay', '"--container-audit-direct-sync-relay"',
    '--container-audit-user-relay', '--CONTAINER-AUDIT-USER-RELAY',
])
def test_renamed_relay_actions_still_block_installation(tmp_path, mode):
    result = _snapshot(tmp_path, r'''
$task.TaskName='RenamedWriter'
$task.Actions[0].Arguments=$env:CA_MODE
$task.Actions=@([pscustomobject]@{Execute='other.exe'; Arguments=''; WorkingDirectory=''}, $task.Actions[0])
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', values={'CA_MODE': mode})
    assert result.returncode == 0, result.stderr or result.stdout
    assert json.loads(result.stdout) == {'error': 'NONCANONICAL_WRITER_ENABLED'}


@pytest.mark.parametrize('trigger', [
    'valid', 'null', 'empty',
])
@pytest.mark.parametrize('enabled', [True, False])
def test_renamed_direct_source_relay_is_classified(tmp_path, trigger, enabled):
    result = _snapshot(tmp_path, r'''
$task.TaskName='RenamedLegacyRelay'
$task.Settings.Enabled=($env:CA_ENABLED -ceq 'True')
$task.Actions[0].Execute='C:\Python312\python.exe'
$task.Actions[0].Arguments='"C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py" --db-path "C:\fixture\queue.sqlite3" --spool-dir "C:\fixture\spool" --producer-manifest-path "C:\fixture\manifest.json" --credential-path "C:\fixture\credential.json" --upload-status-dir "C:\fixture\uploads" --runtime-status-path "C:\fixture\status.json" --log-path "C:\fixture\relay.jsonl"'
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', trigger=trigger, values={'CA_ENABLED': str(enabled)})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    if enabled:
        assert observed == {'error': 'NONCANONICAL_WRITER_ENABLED'}
    else:
        assert observed['present'] is False
        assert [task['task_name'] for task in observed['noncanonical_disabled']] == ['RenamedLegacyRelay']


@pytest.mark.parametrize('case', ['unbuffered', 'no_bytecode', 'editor'])
def test_review_python_options_and_source_editor(tmp_path, case):
    result = _snapshot(tmp_path, r'''
$task.TaskName='RenamedLegacyRelay'
$task.Actions[0].Execute='C:\Python312\python.exe'
$task.Actions[0].Arguments='"C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py" --db-path "C:\fixture\queue.sqlite3" --spool-dir "C:\fixture\spool" --producer-manifest-path "C:\fixture\manifest.json" --credential-path "C:\fixture\credential.json" --upload-status-dir "C:\fixture\uploads" --runtime-status-path "C:\fixture\status.json" --log-path "C:\fixture\relay.jsonl"'
switch ($env:CA_CASE) {
    'unbuffered' { $task.Actions[0].Arguments='-u ' + $task.Actions[0].Arguments }
    'no_bytecode' { $task.Actions[0].Arguments='-B ' + $task.Actions[0].Arguments }
    'editor' {
        $task.TaskName='DisplaySource'
        $task.Actions[0].Execute='C:\Windows\System32\notepad.exe'
        $task.Actions[0].Arguments='"C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py"'
    }
}
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', values={'CA_CASE': case})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    if case == 'editor':
        assert observed.get('present') is False
        assert observed['noncanonical_disabled'] == []
    else:
        assert observed == {'error': 'NONCANONICAL_WRITER_ENABLED'}


@pytest.mark.parametrize('trigger', [
    'null', 'empty',
])
@pytest.mark.parametrize('arguments', [
    r'"C:\capture\wrapper.ps1" -Title "C:\Container_Audit\tools\direct_sync_relay_runner.py"',
    r'"C:\Container_Audit\tools\direct_sync_relay_runner.py.backup"',
    r'"C:\Container_Audit\tools\other_direct_sync_relay_runner.py"',
])
def test_census_ignores_runner_mentions_that_are_not_entrypoints(tmp_path, trigger, arguments):
    result = _snapshot(tmp_path, r'''
$task.TaskName='DisplayCapture'
$task.Actions[0].Execute='powershell.exe'
$task.Actions[0].Arguments=$env:CA_ARGUMENTS
Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress
''', trigger=trigger, values={'CA_ARGUMENTS': arguments})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    assert observed['present'] is False
    assert observed['noncanonical_disabled'] == []


@pytest.mark.parametrize('execute,arguments,writer', [
    ('python.exe', r'-uB -X dev -W ignore "C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py"', True),
    ('python.exe', r'-uWignore -Xutf8 tools/direct_sync_relay_runner.py', True),
    ('python.exe', r'--check-hash-based-pycs always tools/direct_sync_relay_runner.py', True),
    ('python.exe', r'-I -- tools/direct_sync_relay_runner.py --help', True),
    (r'"C:\Company Apps\venv\Scripts\pythonw.exe"', r'-B tools/direct_sync_relay_runner.py', True),
    (r'C:\venv\Scripts\python3.12.exe', r'-u tools/direct_sync_relay_runner.py', True),
    ('py.exe', r'-3.12-64 -u tools/direct_sync_relay_runner.py', True),
    ('py.exe', r'-V:PythonCore/3.12 -B tools/direct_sync_relay_runner.py', True),
    ('python.exe', r'-B "C:\Company Apps\Container_Audit\tools"\DIRECT_SYNC_RELAY_RUNNER.PY', True),
    ('python.exe', r'-u "C:/Company Apps/Container_Audit/tools/../tools/direct_sync_relay_runner.py"', True),
    ('python.exe', r'-X "test=escaped\"quote" tools/direct_sync_relay_runner.py', True),
    ('python.exe', r'-W "ignore:ends in slash\\" tools/direct_sync_relay_runner.py', True),
    ('python.exe', r'-X "test=double""quote" tools/direct_sync_relay_runner.py', True),
    ('python.exe', r'-u user_relay.py', True),
    ('python.exe', r'-u Container_Audit.py', True),
    ('notepad.exe', r'"C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py"', False),
    (r'C:\Windows\explorer.exe', r'"C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py"', False),
    ('other.exe', r'-u tools/direct_sync_relay_runner.py', False),
    ('python.exe.backup', r'tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-u -c "print(1)" tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-Bm other_module tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'- tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'--help tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-V tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-W tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-X tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'"" tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-u wrapper.py tools/direct_sync_relay_runner.py', False),
    ('python.exe', r'-B tools/../other/direct_sync_relay_runner.py', False),
    ('python.exe', r'-u tools/direct_sync_relay_runner.py.backup', False),
])
def test_census_parses_python_script_invocation(tmp_path, execute, arguments, writer):
    result = _snapshot(tmp_path, r'''
$task.TaskName='CommandLineWriter'
$task.Actions[0].Execute=$env:CA_EXECUTE
$task.Actions[0].Arguments=$env:CA_ARGUMENTS
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', values={'CA_EXECUTE': execute, 'CA_ARGUMENTS': arguments})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    if writer:
        assert observed == {'error': 'NONCANONICAL_WRITER_ENABLED'}
    else:
        assert observed.get('present') is False
        assert observed['noncanonical_disabled'] == []


@pytest.mark.parametrize('trigger', ['null', 'empty', 'other_cim'])
def test_disabled_python_writer_with_options_is_reported(tmp_path, trigger):
    result = _snapshot(tmp_path, r'''
$task.TaskName='DisabledPythonWriter'
$task.Settings.Enabled=$false
$task.Actions[0].Arguments='-B -u direct_sync_relay_runner.py'
$task.Actions[0].WorkingDirectory='C:\Company Apps\Container_Audit\tools'
$task.Actions=@([pscustomobject]@{Execute='notepad.exe'; Arguments='tools/direct_sync_relay_runner.py'}, $task.Actions[0])
Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress
''', trigger=trigger)
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    assert observed['present'] is False
    assert [task['task_name'] for task in observed['noncanonical_disabled']] == ['DisabledPythonWriter']


@pytest.mark.parametrize('action', ['relative', 'second_action', 'execute'])
def test_direct_source_relay_action_variants_still_block_installation(tmp_path, action):
    result = _snapshot(tmp_path, r'''
$task.TaskName='RenamedLegacyRelay'
$task.Actions[0].Execute='C:\Python312\pythonw.exe'
$task.Actions[0].Arguments='tools/DIRECT_SYNC_RELAY_RUNNER.PY --db-path C:\fixture\queue.sqlite3'
switch ($env:CA_ACTION) {
    'second_action' { $task.Actions=@([pscustomobject]@{Execute='other.exe'; Arguments=''}, $task.Actions[0]) }
    'execute' { $task.Actions[0].Execute='C:\Company Apps\Container_Audit\tools\direct_sync_relay_runner.py'; $task.Actions[0].Arguments='' }
}
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', values={'CA_ACTION': action})
    assert result.returncode == 0, result.stderr or result.stdout
    assert json.loads(result.stdout) == {'error': 'NONCANONICAL_WRITER_ENABLED'}


@pytest.mark.parametrize('trigger', [
    'null', 'empty', 'missing', 'no_class', 'null_class', 'other_cim', 'mixed', 'mixed_null',
    'no_repetition', 'wrong_interval',
])
@pytest.mark.parametrize('enabled', [True, False])
def test_owned_writer_with_invalid_trigger_is_never_canonical(tmp_path, trigger, enabled):
    result = _snapshot(tmp_path, r'''
$task.Settings.Enabled=($env:CA_ENABLED -ceq 'True')
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', trigger=trigger, values={'CA_ENABLED': str(enabled)})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    if enabled:
        assert observed == {'error': 'NONCANONICAL_WRITER_ENABLED'}
    else:
        assert observed['present'] is False
        assert len(observed['noncanonical_disabled']) == 1


@pytest.mark.parametrize('mutation', [
    'none', 'name', 'path', 'mode', 'principal', 'interval', 'extra_action',
    'extra_null_action', 'null_action',
])
def test_canonical_writer_contract_still_requires_exact_identity(tmp_path, mutation):
    result = _snapshot(tmp_path, r'''
switch ($env:CA_MUTATION) {
    'name' { $task.TaskName='UnexpectedRelay' }
    'path' { $task.TaskPath='\Other\' }
    'mode' { $task.Actions[0].Arguments=$task.Actions[0].Arguments.Replace($Script:RelayMode, '--other-mode') }
    'principal' { $task.Principal.RunLevel='Highest' }
    'interval' { $trigger.Repetition.Interval='PT5M' }
    'extra_action' { $task.Actions=@($task.Actions[0], [pscustomobject]@{Execute='other.exe'; Arguments=''; WorkingDirectory=''}) }
    'extra_null_action' { $task.Actions=@($task.Actions[0], $null) }
    'null_action' { $task.Actions=@($null) }
}
try { Get-CanonicalWriterSnapshot $root | ConvertTo-Json -Depth 10 -Compress }
catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
''', values={'CA_MUTATION': mutation})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    if mutation == 'none':
        assert observed['classification'] == 'CANONICAL_QUIESCE_RESTORE'
        assert observed['restore_required'] is True
    else:
        assert observed == {'error': 'NONCANONICAL_WRITER_ENABLED'}


@pytest.mark.parametrize('trigger', [
    'null', 'empty', 'missing', 'no_class', 'null_class', 'other_cim', 'mixed',
    'mixed_null', 'no_repetition',
])
def test_session_readback_rejects_invalid_triggers_without_property_errors(tmp_path, trigger):
    script = ". '" + str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''") + "'\n"
    script += TASK_INPUTS + r'''
try {
    $readback=Get-ContainerWriterReadback $root
    @{status=$readback.identity.status} | ConvertTo-Json -Compress
} catch { @{error=$_.Exception.Message} | ConvertTo-Json -Compress }
'''
    result = run_functions(tmp_path, ADAPTER, READBACK_FUNCTIONS, script,
                           values={'CA_TRIGGER': trigger})
    assert result.returncode == 0, result.stderr or result.stdout
    observed = json.loads(result.stdout)
    if trigger in ('null', 'empty', 'missing', 'mixed', 'mixed_null'):
        assert observed == {'error': 'Container writer action/trigger shape is not exact.'}
    else:
        assert observed == {'status': 'FAIL'}


@pytest.mark.parametrize('reader', ['installer', 'session'])
def test_valid_writer_binding_preserves_pre_fix_sha256(tmp_path, reader):
    source, names = ((INSTALLER, SNAPSHOT_FUNCTIONS) if reader == 'installer'
                     else (ADAPTER, READBACK_FUNCTIONS))
    script = ". '" + str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''") + "'\n"
    # Fixed path/user vector captured from e7e8790; the reader only hashes it.
    script += TASK_INPUTS.replace("$env:CA_CONTRACT_ROOT", "'C:\\fixture'")
    script += r'''
$task.Principal.UserId='fixture-user'
if ($env:CA_READER -ceq 'installer') { (Get-CanonicalWriterBinding $task).sha256 }
else { (Get-ContainerWriterReadback $root).identity.binding_sha256 }
'''
    result = run_functions(tmp_path, source, names, script,
                           values={'CA_TRIGGER': 'valid', 'CA_READER': reader})
    assert result.returncode == 0, result.stderr or result.stdout
    assert result.stdout.strip() == '42a6c937c660da22c592397422b32f90e4541e654460636fa8ede951bee8f7bc'


def test_valid_session_writer_identity_still_passes(tmp_path):
    script = ". '" + str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''") + "'\n"
    script += TASK_INPUTS + "\n(Get-ContainerWriterReadback $root).identity.status\n"
    result = run_functions(tmp_path, ADAPTER, READBACK_FUNCTIONS, script,
                           values={'CA_TRIGGER': 'valid'})
    assert result.returncode == 0, result.stderr or result.stdout
    assert result.stdout.strip() == 'PASS'
