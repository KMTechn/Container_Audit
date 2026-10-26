"""Compensation changes only the scheduled-task state this removal changed."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


REPO = Path(__file__).resolve().parents[1]
DRIVER = r'''
$evidence=Join-Path $env:CA_CONTRACT_ROOT 'application/removal-evidence/attempt'
[void][IO.Directory]::CreateDirectory($evidence)
if($env:CA_TASK_CASE -ceq 'canonical'){
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
[IO.File]::WriteAllText((Join-Path $evidence 'direct-sync-relay-container-audit.json'),($record|ConvertTo-Json))
$result=Restore-CanonicalRemovalScheduledTasks $evidence
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'result.json'),(@{enabled=$task.Enabled;writes=$task.Writes;status=$result.status;states=@($result.tasks|ForEach-Object {$_.state})}|ConvertTo-Json))
'''


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('case', ['disabled', 'enabled', 'unchanged', 'canonical', 'old', 'foreign', 'readback'])
def test_task_compensation_preserves_the_removal_prestate(tmp_path, engine, case):
    result = run_functions(
        tmp_path, REPO / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Restore-CanonicalRemovalScheduledTasks'], DRIVER,
        values={'CA_TASK_CASE': case}, engine=engine,
    )
    assert result.returncode == 0, 'isolated task compensation driver failed'
    actual = json.loads((tmp_path / 'result.json').read_bytes())
    assert actual['enabled'] is (case == 'enabled')
    assert actual['writes'] == (1 if case in ('enabled', 'readback') else 0)
    assert actual['status'] == ('PARTIAL' if case in ('old', 'foreign', 'readback') else 'RESTORED')
    assert set(actual['states']) <= {'RESTORED', 'UNPROVEN'}
