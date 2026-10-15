from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]

DRIVER=r'''
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
$ordinary=Join-Path $env:CA_CONTRACT_ROOT 'ordinary.lnk'
$pending=Join-Path $env:CA_CONTRACT_ROOT 'pending.json'
$first=[IO.IOException]::new('fixture emergency cleanup failure')
$script:steps=[Collections.Generic.List[string]]::new()
$emergencyDirectory=Join-Path $env:CA_CONTRACT_ROOT '관리용'
$emergencyPath=Join-Path $emergencyDirectory '이적 옛 화면 (비상).lnk'
[IO.Directory]::CreateDirectory($root)|Out-Null
[IO.Directory]::CreateDirectory($emergencyDirectory)|Out-Null
[IO.File]::WriteAllText($emergencyPath,'fixture')
[IO.File]::WriteAllText($ordinary,'fixture')
$sid='S-1-5-21-1-2-3-1001'
[IO.File]::WriteAllText($pending,(@{schema='container-audit-machine-pending-v1';target_sid=$sid;install_root=$root}|ConvertTo-Json))
function Assert-BootstrapWorkerShortcutPath {
    param($Path)
    Assert-BootstrapNoReparsePoint $Path -PathOnly
    if($env:CA_CLEANUP_KIND -eq 'guard'){
        $script:steps.Add('emergency.guard');throw [InvalidOperationException]::new('fixture guard denial')
    }
}
function Remove-Item {
    param($LiteralPath,$ErrorAction)
    Assert-BootstrapNoReparsePoint $LiteralPath -PathOnly
    if($LiteralPath -eq $emergencyPath){
        $script:steps.Add('emergency.link')
        if($env:CA_CLEANUP_KIND -eq 'link'){throw $first}
    }elseif($LiteralPath -eq $emergencyDirectory){
        $script:steps.Add('emergency.folder')
        if($env:CA_CLEANUP_KIND -eq 'folder'){throw $first}
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -ErrorAction Stop
}
function Assert-BootstrapNoReparsePoint {param($Path,$Purpose,[switch]$PathOnly)
    if(-not [IO.Path]::GetFullPath($Path).StartsWith($env:CA_CONTRACT_ROOT+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture path escaped.'}
}
function Read-BootstrapWorkerShortcutRecord {
    param($InstallRoot,$RecordPath,$Scope)
    return [pscustomobject]@{entries=@([pscustomobject]@{path=$ordinary;action='created'})}
}
function Same($a,$b){return [IO.Path]::GetFullPath($a).Equals([IO.Path]::GetFullPath($b),[StringComparison]::OrdinalIgnoreCase)}
function New-Object {
    param($ComObject)
    $shell=[pscustomobject]@{}
    $shell|Add-Member ScriptMethod CreateShortcut {
        param($Path)
        if($Path -eq $emergencyPath){
            return [pscustomobject]@{TargetPath=(Join-Path $root 'launch-container-audit.cmd');Arguments='--ui tk';Description='KMTech.ContainerAudit.EmergencyTk.v1'}
        }
        $script:steps.Add('ordinary')
        if($env:CA_CLEANUP_TARGET -eq 'bootstrap'){
            return [pscustomobject]@{TargetPath=(Join-Path $root 'launch-container-audit.cmd');Arguments=''}
        }
        return [pscustomobject]@{TargetPath=(Join-Path $root 'runtime\pythonw.exe');Arguments=(Get-CanonicalMachineShortcutArguments $root);WorkingDirectory=(Join-Path $root 'app')}
    }
    return $shell
}
# Substitute only the native COM release boundary in the actual function.
$t=$null;$e=$null
$a=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$t,[ref]$e)
$name=if($env:CA_CLEANUP_TARGET -eq 'bootstrap'){'Restore-BootstrapWorkerShortcuts'}else{'Remove-CanonicalMachineArtifacts'}
$node=$a.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)[0]
$body=$node.Extent.Text.Replace('[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)','$script:steps.Add(''release'')')
. ([scriptblock]::Create($body))
$bootstrap=Join-Path $env:CA_CONTRACT_BOOTSTRAP 'tools/bootstrap_integrity.ps1'
$a=[Management.Automation.Language.Parser]::ParseFile($bootstrap,[ref]$t,[ref]$e)
foreach($dependency in @('Get-StrictFullPath','Get-BootstrapEmergencyShortcutPath','Test-BootstrapEmergencyShortcutDirectory','Test-BootstrapEmergencyShortcutOwner','Remove-BootstrapEmergencyShortcut')){
    $node=$a.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $dependency},$true)[0]
    $body=$node.Extent.Text.Replace('[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)','$script:steps.Add(''release'')')
    . ([scriptblock]::Create($body))
}
$caught=$null;$passed=$false
try{
    if($env:CA_CLEANUP_TARGET -eq 'bootstrap'){
        Restore-BootstrapWorkerShortcuts $root 'fixture-record' 'Common'|Out-Null
    }else{
        Remove-CanonicalMachineArtifacts $root ([pscustomobject]@{sid=$sid}) @($pending,$ordinary)
    }
    $passed=$true
}catch{$caught=$_}
if($passed -or $null -eq $caught){throw 'Cleanup failure became PASS.'}
if($env:CA_CLEANUP_KIND -eq 'guard'){
    if(-not [IO.File]::Exists($ordinary) -or -not [IO.File]::Exists($pending) -or $script:steps.Count -ne 1){throw 'Guard denial was deferred.'}
}else{
    if(-not [Object]::ReferenceEquals($caught.Exception,$first)){throw 'First cleanup failure changed.'}
    if([IO.File]::Exists($ordinary)){throw 'Independent ordinary shortcut was not removed.'}
    if($script:steps[0] -notlike 'emergency.*' -or $script:steps.IndexOf('ordinary') -le $script:steps.IndexOf('emergency.'+$env:CA_CLEANUP_KIND)){throw 'Independent cleanup ordering differs.'}
    if($env:CA_CLEANUP_KIND -eq 'link' -and -not [IO.File]::Exists($emergencyPath)){throw 'Failed link was not retained.'}
    if($env:CA_CLEANUP_KIND -eq 'folder' -and ([IO.File]::Exists($emergencyPath) -or -not [IO.Directory]::Exists($emergencyDirectory))){throw 'Failed empty folder state differs.'}
    if($env:CA_CLEANUP_TARGET -eq 'machine' -and [IO.File]::Exists($pending)){throw 'Independent pending was not removed.'}
}
'''


DRIVER = ". '" + str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''") + "'\n" + DRIVER


@pytest.mark.parametrize('engine',('powershell','pwsh'))
@pytest.mark.parametrize('kind',('link','folder','guard'))
@pytest.mark.parametrize('target',('bootstrap','machine'))
def test_emergency_failure_does_not_block_independent_removal(tmp_path,engine,kind,target):
    source=ROOT/('tools/bootstrap_integrity.ps1' if target=='bootstrap' else 'INSTALL_CANONICAL_PORTABLE.ps1')
    names=['Restore-BootstrapWorkerShortcuts'] if target=='bootstrap' else ['Remove-CanonicalMachineArtifacts','Get-CanonicalMachineShortcutArguments']
    result=run_functions(tmp_path,source,names,DRIVER,engine=engine,
        values={'CA_CLEANUP_KIND':kind,'CA_CLEANUP_TARGET':target,'CA_CONTRACT_BOOTSTRAP':str(ROOT)})
    assert result.returncode==0


def test_only_verified_machine_controller_defers_helper_emergency_cleanup():
    text=(ROOT/'INSTALL_THIS_PC.ps1').read_text(encoding='utf-8-sig')
    start=text.index('$deferEmergencyCleanup=')
    end=text.index("'uninstall_status=",start)
    body=text[start:end]
    assert '$MachineControlRoot' in body and '-not $RemoveUncommittedPlacement' in body
    assert '$UninstallAuditPath' in body and '$excluded -contains $RemovalControllerProcessId' in body
    assert '-DeferEmergencyCleanup:$deferEmergencyCleanup' in body
    assert text.index('$excluded = @(Get-ContainerRemovalControllerProcessId $rows)')<start
