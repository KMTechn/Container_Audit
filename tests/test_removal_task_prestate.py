"""Compensation changes only the scheduled-task state this removal changed."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


REPO = Path(__file__).resolve().parents[1]
DRIVER = r'''
$evidence=Join-Path $env:CA_CONTRACT_ROOT 'application/removal-evidence/attempt'
[void][IO.Directory]::CreateDirectory($evidence)
if($env:CA_TASK_CASE -cin @('canonical','untouched-enabled')){
    [void][IO.Directory]::CreateDirectory((Join-Path $env:CA_CONTRACT_ROOT 'application/current'))
}
Add-Type -TypeDefinition @'
public class CompensationTask {
    private bool enabled=false;
    public int Writes=0;
    public bool IgnoreWrite=false;
    public bool Enabled { get{return enabled;} set{Writes++;if(!IgnoreWrite)enabled=value;} }
    public string Xml {get{return "<Task><Settings><Enabled>"+(enabled?"true":"false")+"</Enabled></Settings></Task>";} }
    public string GetSecurityDescriptor(int flags){return "fixture-sddl";}
}
'@
$task=[CompensationTask]::new()
if($env:CA_TASK_CASE -ceq 'readback'){$task.IgnoreWrite=$true}
if($env:CA_TASK_CASE -ceq 'untouched-enabled'){$task.Enabled=$true;$task.Writes=0}
$folder=[pscustomobject]@{Task=$task}
$folder | Add-Member ScriptMethod GetTask {param($Name) return $this.Task}
$service=[pscustomobject]@{Folder=$folder}
$service | Add-Member ScriptMethod Connect {}
$service | Add-Member ScriptMethod GetFolder {param($Path) return $this.Folder}
function New-Object {
    param([string]$TypeName,[string]$ComObject)
    if($ComObject -ceq 'Schedule.Service'){return $service}
    throw 'unexpected object request'
}
$enabled=$env:CA_TASK_CASE -cnotin @('disabled','unchanged','foreign')
$record=@{name='direct-sync-relay-container-audit';xml=('<Task><Settings><Enabled>'+([string]$enabled).ToLowerInvariant()+'</Enabled></Settings></Task>');sddl='fixture-sddl';enabled=$enabled;changed=($env:CA_TASK_CASE -cne 'disabled')}
if($env:CA_TASK_CASE -ceq 'old'){$record.Remove('enabled');$record.Remove('changed')}
if($env:CA_TASK_CASE -ceq 'foreign'){$record.sddl='other-sddl'}
if($env:CA_TASK_CASE -ceq 'implicit'){$record.xml='<Task><Settings></Settings></Task>'}
[IO.File]::WriteAllText((Join-Path $evidence 'direct-sync-relay-container-audit.json'),($record|ConvertTo-Json))
$result=Restore-CanonicalRemovalScheduledTasks $evidence
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'result.json'),(@{enabled=$task.Enabled;writes=$task.Writes;status=$result.status;states=@($result.tasks|ForEach-Object {$_.state})}|ConvertTo-Json))
'''


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('case', ['disabled', 'enabled', 'implicit', 'unchanged', 'untouched-enabled', 'canonical', 'old', 'foreign', 'readback'])
def test_task_compensation_preserves_the_removal_prestate(tmp_path, engine, case):
    result = run_functions(
        tmp_path, REPO / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Restore-CanonicalRemovalScheduledTasks'], DRIVER,
        values={'CA_TASK_CASE': case}, engine=engine,
    )
    assert result.returncode == 0, 'isolated task compensation driver failed'
    actual = json.loads((tmp_path / 'result.json').read_bytes())
    assert actual['enabled'] is (case in ('enabled', 'implicit', 'untouched-enabled'))
    assert actual['writes'] == (1 if case in ('enabled', 'implicit', 'readback') else 0)
    assert actual['status'] == ('PARTIAL' if case in ('old', 'foreign', 'readback') else 'RESTORED')
    assert set(actual['states']) <= {'RESTORED', 'UNPROVEN'}


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('case', ['disabled', 'enabled', 'foreign'])
def test_removal_snapshots_only_an_admitted_task_change(tmp_path, engine, case):
    script = r'''
$task=[pscustomobject]@{Xml='<Task/>';Enabled=($env:CA_TASK_CASE -cne 'disabled');Stops=0}
$task | Add-Member ScriptMethod GetSecurityDescriptor {param($Flags) return 'fixture-sddl'}
$task | Add-Member ScriptMethod Stop {param($Flags) $this.Stops++}
$folder=[pscustomobject]@{Task=$task}
$folder | Add-Member ScriptMethod GetTask {param($Name) return $this.Task}
function Get-ContainerRemovalTaskNames {param($Folder,$CurrentRoot) return 'direct-sync-relay-container-audit'}
function Get-BootstrapOfficialLegacyRelayIdentity {param($Task,$Xml) return @{matched=($env:CA_TASK_CASE -cne 'foreign')}}
function Write-ContainerStartupUpdateRecord {
    param($Path,$Payload)
    [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json))
}
$removalPreimage=@{tasks=[Collections.ArrayList]::new()}
$failed=$false
try{Remove-ContainerScheduledTasks $folder $env:CA_CONTRACT_ROOT $env:CA_CONTRACT_ROOT}catch{$failed=$true}
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'observed.json'),(@{failed=$failed;enabled=$task.Enabled;stops=$task.Stops;saved=$removalPreimage.tasks.Count}|ConvertTo-Json))
'''
    result = run_functions(tmp_path, REPO / 'INSTALL_THIS_PC.ps1',
                           ['Remove-ContainerScheduledTasks'], script,
                           values={'CA_TASK_CASE': case}, engine=engine)
    assert result.returncode == 0, 'isolated task mutation driver failed'
    observed = json.loads((tmp_path / 'observed.json').read_bytes())
    snapshot = tmp_path / 'direct-sync-relay-container-audit.json'
    if case == 'foreign':
        assert observed == {'failed': True, 'enabled': True, 'stops': 0, 'saved': 0}
        assert not snapshot.exists()
    else:
        before = json.loads(snapshot.read_bytes())
        assert before['enabled'] is (case == 'enabled')
        assert before['changed'] is (case == 'enabled')
        assert observed == {'failed': False, 'enabled': False,
                            'stops': int(case == 'enabled'), 'saved': int(case == 'enabled')}
