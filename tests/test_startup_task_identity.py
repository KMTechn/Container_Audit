"""Run all three task consumers against native-style exported account names."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("consumer", ("preimage", "existing", "readback"))
@pytest.mark.parametrize("variation", (
    "sid", "account", "foreign-trigger", "foreign-principal", "unresolved",
    "command", "arguments",
))
def test_startup_task_consumers_bind_accounts_to_expected_sids(tmp_path, engine, consumer, variation):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1",
                           ["Get-ContainerStartupUpdateTaskPreimage"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1')
$taskMatcher=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Test-ContainerStartupUpdateTaskIdentity'},$true)
if($null -ne $taskMatcher){Invoke-Expression $taskMatcher.Extent.Text}
$operator=[Security.Principal.WindowsIdentity]::GetCurrent()
$OperatorSid=$operator.User.Value
$xml='<Task><Triggers><LogonTrigger><UserId>'+ $OperatorSid +'</UserId></LogonTrigger></Triggers><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Actions><Exec><Command>C:\fixture\python.exe</Command><Arguments>-I -B updater.py</Arguments></Exec></Actions></Task>'
$spec=[pscustomobject]@{name='KMTech.ContainerAudit.StartupUpdate.fixture';xml=$xml}
$actual=[xml]$xml
switch($env:CA_TASK_VARIATION){
 'account' {$actual.Task.Principals.Principal.UserId='NT AUTHORITY\SYSTEM';$actual.Task.Triggers.LogonTrigger.UserId=$operator.Name}
 'foreign-trigger' {$actual.Task.Triggers.LogonTrigger.UserId='S-1-5-19'}
 'foreign-principal' {$actual.Task.Principals.Principal.UserId='S-1-5-19'}
 'unresolved' {$actual.Task.Triggers.LogonTrigger.UserId='KMTech-Nonexistent-Task-Account-156'}
 'command' {$actual.Task.Actions.Exec.Command='C:\fixture\foreign.exe'}
 'arguments' {$actual.Task.Actions.Exec.Arguments='-I -B foreign.py'}
}
$registered=[pscustomobject]@{Xml=$actual.OuterXml}
$registered | Add-Member ScriptMethod GetInstances {param($flags) @()}
$registered | Add-Member ScriptMethod GetSecurityDescriptor {param($flags) 'D:P(A;;GA;;;SY)'}
$registered | Add-Member ScriptMethod SetSecurityDescriptor {param($sddl,$flags)}
$folder=[pscustomobject]@{Registered=$registered}
$folder | Add-Member ScriptMethod GetTask {param($name) $this.Registered}
$service=[pscustomobject]@{Folder=$folder}
$service | Add-Member ScriptMethod Connect {}
$service | Add-Member ScriptMethod GetFolder {param($path) $this.Folder}
function New-Object {param($ComObject) if($ComObject -cne 'Schedule.Service'){throw 'unexpected COM request'};return $service}
function Get-ContainerStartupUpdateTaskSpec {param($Root,$Sid) return $spec}
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($env:CA_TASK_CONSUMER -cne 'readback'){return [pscustomobject]@{State='Ready'}}}
function Export-ScheduledTask {param($TaskName) $actual.OuterXml}
function Register-ScheduledTask {param($TaskName,$Xml,[switch]$Force) $script:registrations++}
function Invoke-ContainerWriterFenceMutation {param($ControlRoot,$SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken,$Action) & $Action}
$accepted=$false;$script:registrations=0
try{
 if($env:CA_TASK_CONSUMER -ceq 'preimage'){
  $preimage=Get-ContainerStartupUpdateTaskPreimage 'C:\fixture'
  if($preimage.xml -cne $actual.OuterXml -or -not $preimage.exists){throw 'preimage bytes changed'}
 }else{
  $initializer=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Initialize-ContainerStartupUpdate'},$true)
  $mutations=@($initializer.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Invoke-ContainerWriterFenceMutation'},$true))
  if($mutations.Count -ne 1){throw 'expected one actual task registration boundary'}
  Invoke-Expression $mutations[0].Extent.Text
 }
 $accepted=$true
}catch{
 if($_.Exception.Message -notmatch 'STARTUP_UPDATE_(OWNED_TASK_DIFFERS|TASK_READBACK_FAILED)|Task user SID cannot be resolved'){throw}
}
$expected=$env:CA_TASK_VARIATION -in @('sid','account')
if($accepted -ne $expected){throw 'native task identity acceptance differs'}
if($env:CA_TASK_CONSUMER -ceq 'preimage' -and $script:registrations){throw 'preimage registered a task'}
if($env:CA_TASK_CONSUMER -ceq 'existing' -and -not $expected -and $script:registrations){throw 'foreign existing task was replaced'}
'PASS'
''', engine=engine, values={"CA_TASK_CONSUMER": consumer, "CA_TASK_VARIATION": variation})
    assert result.returncode == 0, result.stdout + result.stderr
