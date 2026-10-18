"""G71 row contracts; the real COM roundtrip is field-only."""
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions


ROOT = Path(__file__).resolve().parents[1]

DRIVER = r'''
function Get-G71Function([string]$Source,[string]$Name) {
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'G71_SOURCE_PARSE_FAILED'}
    $found=@($tree.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    },$true))
    if($found.Count -ne 1){throw 'G71_FUNCTION_REQUIRED'}
    return $found[0]
}
function Get-G71OwnedRow($Function) {
    $rows=@($Function.Body.FindAll({param($node)
        if($node -isnot [Management.Automation.Language.HashtableAst]){return $false}
        return @($node.KeyValuePairs|Where-Object {
            $_.Item1.Value -ceq 'status' -and $_.Item2.Extent.Text.Trim() -ceq "'OWNED_LINK_RETAINED'"
        }).Count -eq 1
    },$true))
    if($rows.Count -ne 1){throw 'G71_OWNED_ROW_REQUIRED'}
    return $rows[0]
}
function New-G71Readback([string]$Location='start_menu') {
    return [pscustomobject]@{location=$Location;shortcut_path='E:\fixture\owned.lnk';
        target_path='E:\Fixture\runtime\pythonw.exe';arguments='--fixture "quoted value"';
        working_directory='E:\Fixture\app'}
}
function Assert-G71Row($Actual,$Expected,[bool]$Retained=$false) {
    $fields=@('location','shortcut_path','target_path','arguments','working_directory')
    $wanted=@($fields)
    if($Retained){$wanted+=@('status')}
    if((@($Actual.PSObject.Properties.Name|Sort-Object)-join ',') -cne (@($wanted|Sort-Object)-join ',')){
        throw 'G71_ROW_FIELDS_DIFFER'
    }
    foreach($field in $fields){
        if([string]$Actual.$field -cne [string]$Expected.$field){throw 'G71_READBACK_VALUES_DIFFER'}
    }
    if($Retained -and $Actual.status -cne 'OWNED_LINK_RETAINED'){throw 'G71_RETAINED_STATUS_DIFFER'}
}
function Get-BootstrapPublishedShortcut($Shell,[string]$Path,[string]$Location) {
    return $script:G71Readback
}
$exact=Get-G71Function $env:G71_CANONICAL_SOURCE 'Test-ExactPropertySet'
. ([scriptblock]::Create($exact.Extent.Text))
function Invoke-G71PublicationFragment([object[]]$Results) {
    $function=Get-G71Function $env:G71_CANONICAL_SOURCE 'Set-CanonicalPublishedShortcuts'
    $statements=@($function.Body.EndBlock.Statements)
    $tryIndex=-1
    for($i=0;$i -lt $statements.Count;$i++){
        if($statements[$i] -is [Management.Automation.Language.TryStatementAst]){$tryIndex=$i;break}
    }
    if($tryIndex -lt 0){throw 'G71_VALIDATION_BLOCK_REQUIRED'}
    $Audit=[ordered]@{};$published=@();$seen=@{};$shell=$null
    # Execute the actual validation and audit assignments, without COM creation/finalization.
    $body=$statements[$tryIndex].Body.Extent.Text
    . ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
    $tail=@($statements|Select-Object -Skip ($tryIndex+1)|ForEach-Object {$_.Extent.Text})-join "`n"
    . ([scriptblock]::Create($tail))
    return $Audit
}
function Assert-G71PreservedArray($Audit,[int]$Count) {
    if(-not $Audit.shortcuts.Contains('preserved')){throw 'G71_AUDIT_PRESERVED_REQUIRED'}
    if($Audit.shortcuts.preserved -isnot [Array] -or $Audit.shortcuts.preserved.Count -ne $Count){
        throw 'G71_AUDIT_PRESERVED_ARRAY_DIFFER'
    }
    $saved=($Audit|ConvertTo-Json -Depth 12)|ConvertFrom-Json
    if($saved.shortcuts.preserved -isnot [Array] -or $saved.shortcuts.preserved.Count -ne $Count){
        throw 'G71_SAVED_PRESERVED_ARRAY_DIFFER'
    }
}
'''

RETAINED = r'''
$scope=$env:G71_SCOPE
$location=if($scope -ceq 'machine'){'start_menu'}else{'emergency'}
$expected=New-G71Readback $location
$existing=$expected;$path=$expected.shortcut_path
$link=[pscustomobject]@{TargetPath=$expected.target_path;Arguments=$expected.arguments;
    WorkingDirectory=$expected.working_directory}
$script:G71Readback=$expected
$function=if($scope -ceq 'machine'){
    Get-G71Function $env:G71_CANONICAL_SOURCE 'Get-CanonicalMachineShortcutPlacement'
}else{Get-G71Function $env:G71_BOOTSTRAP_SOURCE 'Install-BootstrapEmergencyShortcut'}
$rowAst=Get-G71OwnedRow $function
$row=& ([scriptblock]::Create('[pscustomobject]'+$rowAst.Extent.Text))
Assert-G71Row $row $expected $true
$result=[pscustomobject]@{status='PASS';published=@();preserved=@($row)}
$audit=Invoke-G71PublicationFragment @($result)
Assert-G71PreservedArray $audit 1
Assert-G71Row $audit.shortcuts.preserved[0] $expected $true
if($audit.shortcuts.published.Count -ne 0){throw 'G71_RETAINED_PUBLISHED_CHANGED'}
'''

FRESH = r'''
$expected=New-G71Readback
$script:G71Readback=New-G71Readback
$foreign=@()
if($env:G71_FOREIGN -ceq 'yes'){
    $foreign=@([pscustomobject]@{shortcut_path='E:\fixture\foreign.lnk';status='UNRELATED_LINK_PRESERVED'},
        [pscustomobject]@{shortcut_path='E:\fixture\emergency.lnk';status='FOREIGN_LINK_PRESERVED'})
}
$result=[pscustomobject]@{status='PASS';published=@($expected);preserved=@($foreign)}
$audit=Invoke-G71PublicationFragment @($result)
Assert-G71PreservedArray $audit 0
if($audit.shortcuts.published.Count -ne 1){throw 'G71_FRESH_PUBLISHED_CHANGED'}
Assert-G71Row $audit.shortcuts.published[0] $expected
'''

MISMATCH = r'''
$expected=New-G71Readback
$script:G71Readback=New-G71Readback
$script:G71Readback.arguments='different readback'
$result=[pscustomobject]@{status='PASS';published=@($expected);preserved=@()}
$caught=''
try{$unused=Invoke-G71PublicationFragment @($result)}catch{$caught=$_.Exception.Message}
if($caught -cne 'SHORTCUT_PUBLICATION_READBACK_DIFFERS'){throw 'G71_FAILURE_CONTRACT_CHANGED'}
'''


def _run_fragment(tmp_path, script, **values):
    result = run_functions(
        tmp_path, ROOT / 'tools/bootstrap_integrity.ps1',
        ['Get-BootstrapPublishedShortcut'], DRIVER + script,
        values={
            'G71_CANONICAL_SOURCE': str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'),
            'G71_BOOTSTRAP_SOURCE': str(ROOT / 'tools/bootstrap_integrity.ps1'),
            **values,
        },
    )
    if result.returncode:
        codes = sorted(set(re.findall(r'G71_[A-Z_]+', result.stderr)))
        raise AssertionError('G71 fragment failed: ' + ','.join(codes))


@pytest.mark.parametrize('scope', ['machine', 'emergency'])
def test_owned_retained_rows_preserve_all_readback_fields(tmp_path, scope):
    _run_fragment(tmp_path, RETAINED, G71_SCOPE=scope)


@pytest.mark.parametrize('foreign', ['no', 'yes'])
def test_fresh_publication_keeps_preserved_array_empty(tmp_path, foreign):
    _run_fragment(tmp_path, FRESH, G71_FOREIGN=foreign)


def test_publication_readback_mismatch_keeps_existing_failure(tmp_path):
    _run_fragment(tmp_path, MISMATCH)


NATIVE_DRIVER = r'''
$canonical=$env:G71_CANONICAL_SOURCE
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($canonical,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'G71_NATIVE_PARSE_FAILED'}
foreach($name in @('Get-CanonicalMachineShortcutArguments','Get-CanonicalMachineShortcutPlacement',
    'New-CanonicalMachineShortcut','Set-CanonicalPublishedShortcuts','Test-ExactPropertySet')){
    $function=@($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    },$true))
    if($function.Count -ne 1){throw 'G71_NATIVE_FUNCTION_REQUIRED'}
    . ([scriptblock]::Create($function[0].Extent.Text))
}
# Only the fixture's file publication is substituted; actual .lnk COM readback is used.
function Invoke-ContainerAtomicReplace([string]$Source,[string]$Destination,[string]$Mode){
    $limit=[IO.Path]::GetFullPath($env:CA_CONTRACT_ROOT).TrimEnd('\')+'\'
    foreach($path in @($Source,$Destination)){
        if(-not [IO.Path]::GetFullPath($path).StartsWith($limit,[StringComparison]::OrdinalIgnoreCase)){
            throw 'G71_NATIVE_PATH_OUTSIDE_FIXTURE'
        }
    }
    if($Mode -ceq 'CreateNew' -and [IO.File]::Exists($Destination)){throw 'G71_NATIVE_CREATE_COLLISION'}
    if([IO.File]::Exists($Destination)){[IO.File]::Replace($Source,$Destination,$null)}
    else{[IO.File]::Move($Source,$Destination)}
}
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
$directory=Join-Path $env:CA_CONTRACT_ROOT 'start-menu'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'runtime'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app'))
[void][IO.Directory]::CreateDirectory($directory)
[IO.File]::WriteAllText((Join-Path $root 'launch-container-audit.cmd'),'fixture only')
[IO.File]::WriteAllText((Join-Path $root 'runtime\pythonw.exe'),'fixture only')
$machinePath=Join-Path $directory 'KMTech 이적 검사.lnk'
$emergencyPath=Get-BootstrapEmergencyShortcutPath $root
$scenario=$env:G71_NATIVE_SCENARIO
$shell=New-Object -ComObject WScript.Shell
try{
    if($scenario -ceq 'retained'){
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $emergencyPath))
        $machine=$shell.CreateShortcut($machinePath)
        $machine.TargetPath=Join-Path $root 'runtime\pythonw.exe'
        $machine.Arguments=Get-CanonicalMachineShortcutArguments $root
        $machine.WorkingDirectory=Join-Path $root 'app'
        $machine.WindowStyle=7;$machine.Save()
        $emergency=$shell.CreateShortcut($emergencyPath)
        $emergency.TargetPath=Join-Path $root 'launch-container-audit.cmd'
        $emergency.Arguments='--ui tk';$emergency.WorkingDirectory=$root
        $emergency.WindowStyle=7;$emergency.Description='KMTech.ContainerAudit.EmergencyTk.v1'
        $emergency.Save()
    }elseif($scenario -ceq 'foreign'){
        $foreign=$shell.CreateShortcut($machinePath)
        $foreign.TargetPath=Join-Path $root 'foreign-target.exe'
        $foreign.Arguments='foreign fixture';$foreign.WorkingDirectory=$root;$foreign.Save()
        $foreignBefore=[IO.File]::ReadAllBytes($machinePath)
    }
    $publication=New-CanonicalMachineShortcut $root $directory
    $audit=[ordered]@{}
    if($scenario -ceq 'mismatch'){
        $changed=$shell.CreateShortcut($publication.published[0].shortcut_path)
        $changed.Arguments='different readback';$changed.Save()
        $caught=''
        try{Set-CanonicalPublishedShortcuts $audit @($publication)}catch{$caught=$_.Exception.Message}
        if($caught -cne 'SHORTCUT_PUBLICATION_READBACK_DIFFERS'){throw 'G71_NATIVE_FAILURE_CONTRACT_CHANGED'}
    }else{
        Set-CanonicalPublishedShortcuts $audit @($publication)
        $saved=($audit|ConvertTo-Json -Depth 12)|ConvertFrom-Json
        if($saved.shortcuts.preserved -isnot [Array]){throw 'G71_NATIVE_SAVED_ARRAY_REQUIRED'}
        $retainedCount=if($scenario -ceq 'retained'){2}else{0}
        $publishedCount=if($scenario -ceq 'retained'){0}else{2}
        if($audit.shortcuts.published.Count -ne $publishedCount -or
            $audit.shortcuts.preserved -isnot [Array] -or
            $audit.shortcuts.preserved.Count -ne $retainedCount -or
            $saved.shortcuts.preserved.Count -ne $retainedCount){throw 'G71_NATIVE_AUDIT_ROWS_DIFFER'}
        foreach($row in @($audit.shortcuts.published)+@($audit.shortcuts.preserved)){
            $readback=Get-BootstrapPublishedShortcut $shell $row.shortcut_path $row.location
            $owned=$null -ne $row.PSObject.Properties['status']
            $fieldCount=if($owned){6}else{5}
            if(@($row.PSObject.Properties).Count -ne $fieldCount -or
                ($owned -and $row.status -cne 'OWNED_LINK_RETAINED')){throw 'G71_NATIVE_ROW_FIELDS_DIFFER'}
            foreach($field in @('location','shortcut_path','target_path','arguments','working_directory')){
                if([string]$row.$field -cne [string]$readback.$field){throw 'G71_NATIVE_READBACK_DIFFERS'}
            }
        }
        if($scenario -ceq 'foreign'){
            if(-not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                $foreignBefore,[IO.File]::ReadAllBytes($machinePath))){throw 'G71_NATIVE_FOREIGN_BYTES_CHANGED'}
            $newPath=Join-Path $directory 'KMTech 이적 검사 (새 프로그램 1).lnk'
            if(@($audit.shortcuts.published|Where-Object {$_.shortcut_path -ceq $newPath}).Count -ne 1){
                throw 'G71_NATIVE_SUFFIX_PUBLICATION_DIFFER'
            }
        }
    }
}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
'''


def test_native_shortcut_driver_parses_without_com_execution(tmp_path):
    result = run_functions(
        tmp_path, ROOT / 'tools/bootstrap_integrity.ps1', ['Get-BootstrapPublishedShortcut'],
        "$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput("
        "$env:G71_NATIVE_DRIVER,[ref]$tokens,[ref]$errors);"
        "if($errors.Count){throw 'G71_NATIVE_DRIVER_SYNTAX'}",
        values={'G71_NATIVE_DRIVER': NATIVE_DRIVER},
    )
    assert result.returncode == 0, 'G71 native driver parse failed'


# FIELD ONLY: real WScript.Shell creation; never selected by the host focused runner.
@pytest.mark.parametrize('scenario', ['retained', 'fresh', 'foreign', 'mismatch'])
def test_real_shortcut_audit_contract(tmp_path, scenario):
    from tests.test_ca_emergency_shortcut import run_shortcut_contract

    result = run_shortcut_contract(
        tmp_path, 'powershell.exe', NATIVE_DRIVER,
        G71_CANONICAL_SOURCE=str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'),
        G71_NATIVE_SCENARIO=scenario,
        KMTECH_FACTORY_INSTALL_TEST_MODE='1',
        KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=str(tmp_path / 'known-folders'),
    )
    if result.returncode:
        codes = sorted(set(re.findall(r'G71_[A-Z_]+', result.stderr)))
        raise AssertionError('G71 native field test failed: ' + ','.join(codes))
