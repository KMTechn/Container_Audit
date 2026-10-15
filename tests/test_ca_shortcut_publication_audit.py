from pathlib import Path
import re
import pytest

from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('scenario',['worker','machine','rerun','publication_failure','readback_failure'])
def test_real_shortcuts_match_published_audit_and_fail_closed(tmp_path,scenario):
    library=str(ROOT/'tools/bootstrap_integrity.ps1').replace("'","''")
    driver=". '"+library+"'\n"+r'''
$ErrorActionPreference='Stop'
$base=$env:CA_CONTRACT_ROOT
$script:phase=0
trap {
    $trace=@($_.ScriptStackTrace -split "`n"|ForEach-Object {
        if($_ -match '^at ([\w-]+),.*line (\d+)'){
            [pscustomobject]@{function=$matches[1];line=[int]$matches[2]}
        }
    })
    [IO.File]::WriteAllText((Join-Path $base 'publication-summary.json'),(@{type=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber;phase=$script:phase;trace=$trace}|ConvertTo-Json -Depth 8))
    throw
}
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $base 'shortcuts'
$root=Join-Path $base 'application\current'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app\assets'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'runtime'))
[IO.File]::WriteAllText((Join-Path $root 'launch-container-audit.cmd'),'fixture launcher; never executed')
[IO.File]::WriteAllText((Join-Path $root 'runtime\pythonw.exe'),'fixture target; never executed')
$record=Join-Path $base 'records\record.json'
$folders=@(Get-BootstrapWorkerShortcutFolders)
foreach($folder in $folders){[void][IO.Directory]::CreateDirectory($folder.path)}
$shell=New-Object -ComObject WScript.Shell
try{
    $existing=Join-Path $folders[0].path 'existing.lnk'
    if($env:CA_PUBLICATION_SCENARIO -cin @('rerun','publication_failure')){
        $link=$shell.CreateShortcut($existing)
        $link.TargetPath=Join-Path $root 'removed-old.exe';$link.Arguments='';$link.WorkingDirectory=$root;$link.Save()
    }
    if($env:CA_PUBLICATION_SCENARIO -ceq 'publication_failure'){
        $before=Get-FileSha256 $existing
        function Invoke-ContainerAtomicReplace {
            param($Source,$Destination,$Mode)
            if([IO.Path]::GetExtension($Destination) -ieq '.lnk'){throw [IO.IOException]::new('PUBLICATION_FIXTURE_FAILURE')}
            [IO.File]::Move($Source,$Destination)
        }
        $passed=$false;$caught=$false
        try{$result=Install-BootstrapWorkerShortcuts $root $record;$passed=$true}catch{$caught=$true}
        if(-not $caught -or $passed -or (Get-FileSha256 $existing) -cne $before){throw 'SHORTCUT_FAILURE_WAS_COLLAPSED'}
        if(@(Get-ChildItem -LiteralPath $folders[0].path -Filter '*.tmp.*.lnk').Count){throw 'SHORTCUT_PREPARED_FILE_REMAINS'}
        return
    }
    if($env:CA_PUBLICATION_SCENARIO -ceq 'machine'){
        $directory=($folders|Where-Object {$_.common -and $_.location -ceq 'start_menu'}).path
        $result=New-CanonicalMachineShortcut $root $directory
    }else{$result=Install-BootstrapWorkerShortcuts $root $record}
    $script:phase=1
    if($env:CA_PUBLICATION_SCENARIO -ceq 'rerun'){
        $before=(Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).entries|ConvertTo-Json -Depth 12 -Compress
        $result=Install-BootstrapWorkerShortcuts $root $record
        $after=(Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).entries|ConvertTo-Json -Depth 12 -Compress
        if($before -cne $after){throw 'SHORTCUT_RECOVERY_ENTRIES_CHANGED'}
    }
    if($env:CA_PUBLICATION_SCENARIO -ceq 'readback_failure'){
        $entry=@($result.published)[0]
        $link=$shell.CreateShortcut($entry.shortcut_path);$link.Arguments='changed fixture';$link.Save()
        $caught=$false
        try{Set-CanonicalPublishedShortcuts ([ordered]@{}) @($result)}catch{$caught=$true}
        if(-not $caught){throw 'SHORTCUT_READBACK_DRIFT_ADMITTED'}
        return
    }
    $audit=[ordered]@{shortcuts=[ordered]@{entries=@('original-entry')}}
    $expectedPublished=@($result.published);if($audit.Contains('shortcuts')){$expectedPublished+=@($audit.shortcuts.published)}
    Set-CanonicalPublishedShortcuts $audit @($result)
    $auditPath=Join-Path $base 'published-audit.json'
    Save $auditPath $audit
    $audit=Get-Content -LiteralPath $auditPath -Raw -Encoding UTF8|ConvertFrom-Json
    $script:phase=2
    if($audit.shortcuts.entries.Count -ne 1 -or $audit.shortcuts.entries[0] -cne 'original-entry'){throw 'EXISTING_AUDIT_ENTRIES_CHANGED'}
    if(@($audit.shortcuts.published).Count -ne @($expectedPublished|Select-Object -ExpandProperty shortcut_path -Unique).Count){throw 'PUBLISHED_LIST_MISSING'}
    foreach($entry in @($audit.shortcuts.published)){
        $actual=$shell.CreateShortcut($entry.shortcut_path)
        if($entry.target_path -cne [string]$actual.TargetPath -or $entry.arguments -cne [string]$actual.Arguments -or
            $entry.working_directory -cne [string]$actual.WorkingDirectory){throw 'REAL_SHORTCUT_AUDIT_DIFFERS'}
    }
    $locations=@($audit.shortcuts.published|ForEach-Object location)
    if((@($expectedPublished|Where-Object location -ceq 'emergency').Count -and $locations -cnotcontains 'emergency')){throw 'EMERGENCY_LOCATION_MISSING'}
    if($env:CA_PUBLICATION_SCENARIO -ceq 'worker' -and ((@($expectedPublished|Where-Object location -ceq 'desktop').Count -and $locations -cnotcontains 'desktop') -or (@($expectedPublished|Where-Object location -ceq 'start_menu').Count -and $locations -cnotcontains 'start_menu'))){throw 'NORMAL_LOCATIONS_MISSING'}
}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
'''
    names=['Get-CanonicalMachineShortcutPlacement','New-CanonicalMachineShortcut','Get-CanonicalMachineShortcutArguments',
           'Set-CanonicalPublishedShortcuts','Test-ExactPropertySet','Same','Full',
           'Save','ConvertTo-CanonicalAuditJson']
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',names,driver,
                         values={'CA_PUBLICATION_SCENARIO':scenario})
    if result.returncode:
        kinds=sorted(set(re.findall(r'\b\w+(?:Error|Exception)\b',result.stderr)))
        raise AssertionError('shortcut publication probe failed: '+','.join(kinds))


@pytest.mark.parametrize('target',['tls-ca.crt','bootstrap-integrity.json'])
def test_atomic_prepared_copy_failure_keeps_live_bytes(tmp_path,target):
    driver=r'''
$ErrorActionPreference='Stop'
$base=$env:CA_CONTRACT_ROOT
$source=Join-Path $base 'prepared-source'
$destination=Join-Path $base $env:CA_COPY_TARGET
[IO.File]::WriteAllText($source,'new prepared bytes')
[IO.File]::WriteAllText($destination,'old live bytes')
function Assert-BootstrapNoReparsePoint {}
function Get-FileSha256([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
$script:publicationCalls=0
function Invoke-ContainerAtomicReplace {
    param($Source,$Destination,$Mode)
    $script:publicationCalls++
    if([IO.File]::ReadAllText($Source) -cne 'new prepared bytes'){throw 'PREPARED_BYTES_DIFFER'}
    throw [IO.IOException]::new('ATOMIC_COPY_FIXTURE_FAILURE')
}
$caught=$false
try{Copy-BootstrapPreparedFile $source $destination}catch{$caught=$true}
if(-not $caught -or $script:publicationCalls -ne 1 -or [IO.File]::ReadAllText($destination) -cne 'old live bytes'){
    throw 'ATOMIC_COPY_DAMAGED_LIVE_BYTES'
}
if(@(Get-ChildItem -LiteralPath $base -Filter '*.tmp.*').Count){throw 'PREPARED_COPY_REMAINS'}
'''
    result=run_functions(tmp_path,ROOT/'tools/bootstrap_integrity.ps1',['Copy-BootstrapPreparedFile'],driver,
                         values={'CA_COPY_TARGET':target})
    assert result.returncode==0
