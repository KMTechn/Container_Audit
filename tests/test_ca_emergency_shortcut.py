"""Headless shortcut ownership, lifecycle and unchanged integrity boundary."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


def run_shortcut_contract(tmp_path, engine, script, **values):
    source = str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''")
    # Publication refusal is an error contract; retain the existing foreign-data
    # assertions while observing the actual exception as a distinct result.
    script = script.replace('Install-BootstrapEmergencyShortcut ', 'Invoke-ExpectedEmergencyPublication ')
    script = script.replace('PRESERVED_FOREIGN', 'PRESERVED_FOREIGN')
    script = ". '" + source + "'\n" + r'''
function Invoke-ExpectedEmergencyPublication([string]$InstallRoot) {
    try{return Install-BootstrapEmergencyShortcut $InstallRoot}
    catch{
        if($_.Exception.Message -cne 'EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED'){throw}
        return [pscustomobject]@{status='PRESERVED_FOREIGN'}
    }
}
''' + script
    return run_functions(
        tmp_path, ROOT / 'tools/bootstrap_integrity.ps1', ['Install-BootstrapWorkerShortcuts'],
        f". '{source}'\n" + r'''
$root=Join-Path $env:CA_CONTRACT_ROOT 'product\current'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app\assets'))
[IO.File]::WriteAllText((Join-Path $root 'launch-container-audit.cmd'),'synthetic launcher')
[IO.File]::WriteAllText((Join-Path $root 'app\assets\logo.ico'),'synthetic icon')
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'known-folders'
''' + script, values=values, engine=engine)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('scenario', ('owned', 'foreign', 'directory', 'other_file',
                                     'owned_and_foreign', 'management_file', 'hidden_file', 'corrupt'))
def test_emergency_shortcut_lifecycle_and_foreign_directory(tmp_path, engine, scenario):
    result = run_shortcut_contract(tmp_path, engine, r'''
$path=Get-BootstrapEmergencyShortcutPath $root
$expected=Join-Path (Join-Path (Split-Path -Parent $root) '관리용') '이적 옛 화면 (비상).lnk'
if($path -ine $expected -or $path.StartsWith($root+'\')){throw 'Emergency path is not outside current'}
$directory=Split-Path -Parent $path
$shell=New-Object -ComObject WScript.Shell
try{
    $scenario=$env:CA_EMERGENCY_SCENARIO
    if($scenario -ceq 'management_file'){
        [IO.File]::WriteAllText($directory,'foreign directory occupant')
    }else{
        [void][IO.Directory]::CreateDirectory($directory)
        if($scenario -ceq 'foreign'){
            $link=$shell.CreateShortcut($path)
            $link.TargetPath=Join-Path $root 'other.cmd';$link.Description='foreign';$link.Save()
        }elseif($scenario -ceq 'directory'){
            [void][IO.Directory]::CreateDirectory($path)
        }elseif($scenario -ceq 'corrupt'){
            [IO.File]::WriteAllText($path,'not a shortcut')
        }elseif($scenario -ceq 'owned_and_foreign'){
            [void](Install-BootstrapEmergencyShortcut $root)
        }
        if($scenario -in @('other_file','owned_and_foreign','hidden_file')){
            $other=Join-Path $directory 'foreign.txt'
            [IO.File]::WriteAllText($other,'preserve these bytes')
            if($scenario -ceq 'hidden_file'){[IO.File]::SetAttributes($other,[IO.FileAttributes]::Hidden)}
        }
    }
    $before=@(Get-ChildItem -LiteralPath $directory -Force -Recurse | ForEach-Object {
        if(-not $_.PSIsContainer){$_.FullName+':'+(Get-FileSha256 $_.FullName)}else{$_.FullName}
    }) -join '|'
    $installed=Install-BootstrapEmergencyShortcut $root -WarningVariable warnings
    if($scenario -cne 'owned'){
        if($installed.status -cne 'PRESERVED_FOREIGN' -or @($warnings).Count -ne 1){throw 'Foreign install must preserve and warn once'}
        Remove-BootstrapEmergencyShortcut $root -WarningVariable removalWarnings
        if(@($removalWarnings).Count -ne 1){throw 'Foreign removal must warn once'}
        $after=@(Get-ChildItem -LiteralPath $directory -Force -Recurse | ForEach-Object {
            if(-not $_.PSIsContainer){$_.FullName+':'+(Get-FileSha256 $_.FullName)}else{$_.FullName}
        }) -join '|'
        if($before -cne $after -or -not (Test-Path -LiteralPath $directory)){throw 'Foreign directory changed'}
    }else{
        if($installed.status -cne 'CREATED'){throw 'Missing creation'}
        $link=$shell.CreateShortcut($path)
        $launcher=Join-Path $root 'launch-container-audit.cmd';$icon=(Join-Path $root 'app\assets\logo.ico')+',0'
        if($link.TargetPath -ine $launcher -or $link.Arguments -cne '--ui tk' -or
            $link.WorkingDirectory -ine $root -or $link.IconLocation -ine $icon){throw 'Wrong emergency launch fields'}
        $original=Get-FileSha256 $path
        $again=Install-BootstrapEmergencyShortcut $root
        if($again.status -cne 'RETAINED' -or (Get-FileSha256 $path) -cne $original){throw 'Reinstall changed verified shortcut'}
        # The installer replaces current; the stable launcher path must read back again.
        Remove-Item -LiteralPath $launcher
        [IO.File]::WriteAllText($launcher,'replacement current launcher')
        $link.WorkingDirectory=Split-Path -Parent $root;$link.IconLocation=(Join-Path $root 'other.ico')+',0';$link.Save()
        $updated=Install-BootstrapEmergencyShortcut $root
        $readback=$shell.CreateShortcut($path)
        if($updated.status -cne 'UPDATED' -or $readback.TargetPath -ine $launcher -or
            $readback.Arguments -cne '--ui tk' -or $readback.WorkingDirectory -ine $root -or
            $readback.IconLocation -ine $icon){throw 'Update readback differs'}
        Remove-BootstrapEmergencyShortcut $root
        if(Test-Path -LiteralPath $directory){throw 'Owned link or empty directory remains'}
    }
    'EMERGENCY_SHORTCUT_PASS'
}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
''', CA_EMERGENCY_SCENARIO=scenario)
    assert result.returncode == 0, result.stderr
    assert 'EMERGENCY_SHORTCUT_PASS' in result.stdout


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_emergency_shortcut_preserves_real_code_inventory(tmp_path, engine):
    result = run_shortcut_contract(tmp_path, engine, r'''
$before=ConvertTo-Json -InputObject @(Get-CodeInventory $root) -Depth 6 -Compress
[void](Install-BootstrapEmergencyShortcut $root)
$path=Get-BootstrapEmergencyShortcutPath $root
if(-not [IO.File]::Exists($path)){throw 'Missing emergency link'}
$after=ConvertTo-Json -InputObject @(Get-CodeInventory $root) -Depth 6 -Compress
if($after -cne $before){throw 'Emergency link changed code inventory or hashes'}
Remove-BootstrapEmergencyShortcut $root
if((ConvertTo-Json -InputObject @(Get-CodeInventory $root) -Depth 6 -Compress) -cne $before){throw 'Removal changed inventory'}
'EMERGENCY_INVENTORY_PASS'
''')
    assert result.returncode == 0, result.stderr
    assert 'EMERGENCY_INVENTORY_PASS' in result.stdout


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_worker_shortcut_flow_manages_emergency_link_without_extra_known_folder_links(tmp_path, engine):
    result = run_shortcut_contract(tmp_path, engine, r'''
$record=Join-Path $env:CA_CONTRACT_ROOT 'records\shortcuts.json'
[void](Install-BootstrapWorkerShortcuts $root $record 'Common')
$emergency=Get-BootstrapEmergencyShortcutPath $root
if(-not [IO.File]::Exists($emergency)){throw 'Worker install missed emergency shortcut'}
$shell=New-Object -ComObject WScript.Shell
try{
    $worker=Join-Path $env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT 'CommonDesktopDirectory\이적 검사.lnk'
    $normal=$shell.CreateShortcut($worker);$link=$shell.CreateShortcut($emergency)
    if($normal.TargetPath -ine $link.TargetPath -or $normal.WorkingDirectory -ine $link.WorkingDirectory -or
        $normal.IconLocation -ine $link.IconLocation){throw 'Worker and emergency launcher fields differ'}
    foreach($file in @(Get-ChildItem -LiteralPath $env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT -File -Filter '*.lnk' -Recurse)){
        if($shell.CreateShortcut($file.FullName).Arguments -cne ''){throw 'Emergency shortcut leaked into known folders'}
    }
    [void](Restore-BootstrapWorkerShortcuts $root $record 'Common')
    if(-not [IO.File]::Exists($emergency)){throw 'Rollback with current launcher removed link'}
    [void](Install-BootstrapWorkerShortcuts $root $record 'Common')
    Remove-Item -LiteralPath (Join-Path $root 'launch-container-audit.cmd')
    [void](Restore-BootstrapWorkerShortcuts $root $record 'Common')
    if(Test-Path -LiteralPath (Split-Path -Parent $emergency)){throw 'Worker removal left management directory'}
    'EMERGENCY_FLOW_PASS'
}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
''')
    assert result.returncode == 0, result.stderr
    assert 'EMERGENCY_FLOW_PASS' in result.stdout
