from pathlib import Path
import re
import pytest
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('scenario',['same','changed','failure'])
def test_reused_startup_repair_records_before_after_and_task_readback(tmp_path,scenario):
    library=str(ROOT/'tools/bootstrap_integrity.ps1').replace("'","''")
    driver=". '"+library+"'\n"+r'''
$ErrorActionPreference='Stop'
$root=Join-Path $env:CA_CONTRACT_ROOT 'application\current'
$OperatorSid='S-1-5-21-100-200-300-1001'
$OperatorLocalAppDataRoot=Join-Path $env:CA_CONTRACT_ROOT 'local'
$WriterFenceAttemptId='repair-fixture'
$bootstrapStatus='REUSED'
$testOverride=$false
$commit='a'*40
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app'))
[void][IO.Directory]::CreateDirectory((Join-Path (Split-Path -Parent $root) ('versions\'+$commit)))
[IO.File]::WriteAllText((Join-Path $root 'app\auto-update-settings.json'),'{"apply_during_work":false}')
[IO.File]::WriteAllText((Join-Path $root 'portable-manifest.json'),(@{source_commit=$commit;startup_update_protocol=1}|ConvertTo-Json))
$code=Join-Path $root 'app\unchanged.dat'
[IO.File]::WriteAllText($code,'code preimage')
$expectedXml='<Task><Actions /></Task>'
$script:taskXml=if($env:CA_REPAIR_SCENARIO -ceq 'changed'){'<Task><Actions /><Legacy /></Task>'}else{$expectedXml}
$script:events=@()
$WriterFenceHelperPath=Join-Path $env:CA_CONTRACT_ROOT 'empty.ps1'
[IO.File]::WriteAllText($WriterFenceHelperPath,'')
$Script:StartupUpdatePreimage=[pscustomobject]@{path=$env:CA_CONTRACT_ROOT}
function Assert-ContainerStartupUpdateTrust {}
function Assert-NoReparsePoint {}
function Get-StrictFullPath([string]$Path,[string]$Purpose){return [IO.Path]::GetFullPath($Path)}
function Set-InstallationEvidenceStage {}
function Complete-InstallationEvidenceStage {}
function New-InstallationProtectedDirectory([string]$Path){[void][IO.Directory]::CreateDirectory($Path)}
function Assert-BootstrapIntegrityRecord {}
function Get-CodeInventory {return @()}
function Get-InventoryAggregate {return 'fixed-code-digest'}
function Get-ItemProperty {return [pscustomobject]@{HiberbootEnabled=0}}
function Get-FileSha256([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Get-ContainerStartupUpdateTaskPreimage {return [pscustomobject]@{exists=$true;xml=$script:taskXml;sddl='fixture-security'}}
function Get-ContainerStartupUpdateTaskSpec {return [pscustomobject]@{name='fixture-task';xml=$expectedXml}}
function Get-InstallationVerifiedScript {return $WriterFenceHelperPath}
function Write-InstallationEvidenceEvent($Record){$script:events+=@($Record)}
function Write-InstallationHelperPublicRecord {}
function ConvertTo-KmtechRedactedSinkText {param($Text) return $Text}
function Invoke-ContainerWriterFenceMutation {param($ControlRoot,$SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken,$Action) & $Action}
function Get-ScheduledTask {return [pscustomobject]@{State='Ready'}}
function Export-ScheduledTask {return $script:taskXml}
function Test-ContainerStartupUpdateTaskIdentity {return $true}
function Register-ScheduledTask {
    param($TaskName,$Xml,[switch]$Force)
    if($env:CA_REPAIR_SCENARIO -ceq 'failure'){throw [IO.IOException]::new('TASK_REPAIR_FIXTURE_FAILURE')}
    $script:taskXml=$Xml
}
function New-Object {
    param([Parameter(Position=0)]$TypeName,[Parameter(Position=1)]$ArgumentList,$ComObject)
    if($ComObject -ceq 'Schedule.Service'){
        $registered=[pscustomobject]@{Xml=$script:taskXml}
        $registered|Add-Member ScriptMethod SetSecurityDescriptor {}
        $folder=[pscustomobject]@{Registered=$registered}
        $folder|Add-Member ScriptMethod GetTask {return $this.Registered}
        $service=[pscustomobject]@{Folder=$folder}
        $service|Add-Member ScriptMethod Connect {}
        $service|Add-Member ScriptMethod GetFolder {return $this.Folder}
        return $service
    }
    if($PSBoundParameters.ContainsKey('ArgumentList')){
        return Microsoft.PowerShell.Utility\New-Object $TypeName -ArgumentList $ArgumentList
    }
    return Microsoft.PowerShell.Utility\New-Object $TypeName
}
$caught=$false
try{Initialize-ContainerStartupUpdate $root}catch{$caught=$true}
if($caught -ne ($env:CA_REPAIR_SCENARIO -ceq 'failure')){throw 'REPAIR_OUTCOME_DIFFERS'}
if($script:events.Count -ne 2 -or $script:events[0].event -cne 'STARTUP_REPAIR_BEFORE' -or
    $script:events[1].event -cne 'STARTUP_REPAIR_AFTER'){throw 'REPAIR_EVENTS_MISSING'}
$after=$script:events[1]
$expectedStatus=if($caught){'FAILED'}else{'PASS'}
$expectedChange=if($env:CA_REPAIR_SCENARIO -ceq 'changed'){'CHANGED'}else{'UNCHANGED'}
if($after.status -cne $expectedStatus -or $after.task_spec_disposition -cne $expectedChange -or
    $after.before.task_spec_sha256.Length -ne 64 -or $after.after.task_spec_sha256.Length -ne 64){throw 'REPAIR_READBACK_DIFFERS'}
if([IO.File]::ReadAllText($code) -cne 'code preimage'){throw 'REUSED_CODE_CHANGED'}
'''
    names=['Initialize-ContainerStartupUpdate','Get-ContainerStartupRepairObservation',
           'Write-ContainerStartupRepairResult','Write-ContainerStartupUpdateRecord']
    result=run_functions(tmp_path,ROOT/'INSTALL_THIS_PC.ps1',names,driver,
                         values={'CA_REPAIR_SCENARIO':scenario})
    if result.returncode:
        kinds=sorted(set(re.findall(r'\b\w+(?:Error|Exception)\b',result.stderr)))
        raise AssertionError('startup repair probe failed: '+','.join(kinds))
