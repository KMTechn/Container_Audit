"""Real shell links in redirected known folders; never run the installer or links."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("scenario", ("legacy", "absent", "repeat", "failure", "foreign", "restore_drift", "existing_file", "existing_directory", "collision"))
def test_worker_shortcut_install_and_restore(tmp_path, engine, scenario):
    source = str(ROOT / "tools/bootstrap_integrity.ps1").replace("'", "''")
    result = run_functions(
        tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
        ["Install-BootstrapWorkerShortcuts", "Restore-BootstrapWorkerShortcuts"],
        f". '{source}'\nSet-StrictMode -Version Latest\n" + r'''
$root=$env:CA_CONTRACT_ROOT
$current=Join-Path $root 'Apps\Container_Audit\current'
$launcher=Join-Path $current 'launch-container-audit.cmd'
$icon=Join-Path $current 'app\assets\logo.ico'
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $icon))
[IO.File]::WriteAllText($launcher,'test launcher -- never executed')
[IO.File]::WriteAllText($icon,'test icon')
$script:folders=@()
foreach($name in @('Desktop','Programs','CommonDesktop','CommonPrograms')){
    $path=Join-Path $root $name
    [void][IO.Directory]::CreateDirectory($path)
    $script:folders+=,[pscustomobject]@{path=$path;common=$name.StartsWith('Common')}
}
function Get-BootstrapWorkerShortcutFolders([string]$Scope='All'){
    @($script:folders|Where-Object {$Scope -ceq 'All' -or ($_.common -eq ($Scope -ceq 'Common'))})
}
$shell=New-Object -ComObject WScript.Shell
$legacy=Join-Path $script:folders[0].path '현장 이적.lnk'
$nested=Join-Path $script:folders[3].path 'KMTech\작업'
[void][IO.Directory]::CreateDirectory($nested)
$legacy2=Join-Path $nested '이적.lnk'
$foreign=Join-Path $script:folders[1].path '포장.lnk'
$other=$shell.CreateShortcut($foreign)
$other.TargetPath=Join-Path $root 'Apps\Label_Match\current\Label_Match.exe'
$other.Arguments='--other-app';$other.Save()
$foreignSha=Get-FileSha256 $foreign
$externalBroken=Join-Path $script:folders[0].path '다른 자리 이적.lnk'
$external=$shell.CreateShortcut($externalBroken)
$external.TargetPath=Join-Path $root 'OtherRoot\Container_Audit\current\Container_Audit.exe'
$external.Save();$externalSha=Get-FileSha256 $externalBroken
$existing=Join-Path $script:folders[0].path '있는 파일.lnk'
$existingSha=''
if($env:CA_SHORTCUT_SCENARIO -cin @('existing_file','existing_directory')){
    $existingTarget=Join-Path $current 'working.exe'
    if($env:CA_SHORTCUT_SCENARIO -ceq 'existing_directory'){[void][IO.Directory]::CreateDirectory($existingTarget)}
    else{[IO.File]::WriteAllText($existingTarget,'existing target -- never executed')}
    $link=$shell.CreateShortcut($existing);$link.TargetPath=$existingTarget;$link.Save()
    $existingSha=Get-FileSha256 $existing
}
$originalTarget=Join-Path $current 'Container_Audit.exe'
$originals=@{}
if($env:CA_SHORTCUT_SCENARIO -ceq 'collision'){
    foreach($folder in @($script:folders|Where-Object common)){
        [IO.File]::Copy($externalBroken,(Join-Path $folder.path '이적 검사.lnk'),$false)
    }
}
if($env:CA_SHORTCUT_SCENARIO -cnotin @('absent','collision')){
    foreach($path in @($legacy,$legacy2)){
        $link=$shell.CreateShortcut($path)
        $link.TargetPath=$originalTarget;$link.Arguments='--saved-worker "test"'
        $link.IconLocation=(Join-Path $root 'old.ico')+',2'
        $link.WorkingDirectory=$root;$link.WindowStyle=1;$link.Description='original'
        $link.Save();$originals[$path]=Get-FileSha256 $path
    }
}
$userRecord=Join-Path $root 'LOCALAPPDATA\install-audit\worker-shortcuts.json'
$commonRecord=Join-Path $root 'ProgramData\install-audit\worker-shortcuts.json'
$installAction={
    [void](Install-BootstrapWorkerShortcuts $current $userRecord 'User')
    [void](Install-BootstrapWorkerShortcuts $current $commonRecord 'Common')
}
if($env:CA_SHORTCUT_SCENARIO -ceq 'failure'){
    $definition=${function:Write-BootstrapWorkerShortcut}
    function Write-BootstrapWorkerShortcut($Path,$Launcher,$Icon){throw 'injected shortcut save failure'}
    $failed=$false
    try{& $installAction}catch{$failed=$true}
    if(-not $failed){throw 'injected save failure was ignored'}
    Set-Item -LiteralPath 'Function:Write-BootstrapWorkerShortcut' -Value $definition
}else{
    & $installAction
    if($env:CA_SHORTCUT_SCENARIO -ceq 'repeat'){
        $beforeRecord=Get-FileSha256 $userRecord
        & $installAction
        if((Get-FileSha256 $userRecord) -cne $beforeRecord){throw 'repeat overwrote original preimage'}
    }
    $owned=@($legacy,$legacy2)
    if($env:CA_SHORTCUT_SCENARIO -cin @('absent','collision')){
        $newName=if($env:CA_SHORTCUT_SCENARIO -ceq 'collision'){'이적 검사 (새 프로그램 1).lnk'}else{'이적 검사.lnk'}
        $owned=@((Join-Path $script:folders[2].path $newName),
            (Join-Path $script:folders[3].path $newName))
    }
    foreach($path in $owned){
        $link=$shell.CreateShortcut($path)
        if($link.TargetPath -ine $launcher -or $link.Arguments -cne '' -or
            $link.IconLocation -ine ($icon+',0') -or $link.WindowStyle -ne 7){
            throw 'installed shortcut does not match verified entrypoint/icon/minimized window'
        }
    }
    if($env:CA_SHORTCUT_SCENARIO -ceq 'foreign'){
        # A foreign shortcut with the normal new name must never be replaced.
        [IO.File]::Copy($foreign,(Join-Path $script:folders[2].path '이적 검사.lnk'),$true)
    }
    if($env:CA_SHORTCUT_SCENARIO -ceq 'restore_drift'){
        $link=$shell.CreateShortcut($legacy);$link.TargetPath=$other.TargetPath;$link.Save()
    }
}
# A restored legacy tree has no portable launcher. No legacy app is executed.
[IO.File]::Delete($launcher)
if($env:CA_SHORTCUT_SCENARIO -ceq 'restore_drift'){
    $failed=$false
    try{[void](Restore-BootstrapWorkerShortcuts $current $userRecord 'User')}catch{$failed=$true}
    if(-not $failed -or $shell.CreateShortcut($legacy).TargetPath -ine $other.TargetPath){
        throw 'restore overwrote a subsequently edited foreign shortcut'
    }
}else{
    [void](Restore-BootstrapWorkerShortcuts $current $userRecord 'User')
    [void](Restore-BootstrapWorkerShortcuts $current $commonRecord 'Common')
    foreach($path in $originals.Keys){
        if((Get-FileSha256 $path) -cne $originals[$path]){throw 'original shortcut bytes were not restored'}
        $link=$shell.CreateShortcut($path)
        if($link.TargetPath -ine $originalTarget -or $link.Arguments -cne '--saved-worker "test"'){
            throw 'original target/arguments were not restored'
        }
    }
    if($env:CA_SHORTCUT_SCENARIO -cin @('absent','collision')){
        foreach($folder in @($script:folders|Where-Object common)){
            if(Test-Path -LiteralPath (Join-Path $folder.path $newName)){throw 'new shortcut survived removal'}
            if($env:CA_SHORTCUT_SCENARIO -ceq 'collision' -and
                (Get-FileSha256 (Join-Path $folder.path '이적 검사.lnk')) -cne $externalSha){throw 'foreign name collision changed'}
        }
    }
}
if((Get-FileSha256 $foreign) -cne $foreignSha){throw 'other app shortcut changed'}
if((Get-FileSha256 $externalBroken) -cne $externalSha){throw 'broken shortcut into another root changed'}
if($existingSha -and (Get-FileSha256 $existing) -cne $existingSha){throw 'shortcut to existing same-root file changed'}
'worker_shortcut_contract=PASS'
''',
        values={"CA_SHORTCUT_SCENARIO": scenario}, engine=engine,
    )
    assert result.returncode == 0, result.stderr
    assert "worker_shortcut_contract=PASS" in result.stdout


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("proven", (False, True))
def test_elevated_commit_prepares_only_public_shortcuts_after_readback(tmp_path, engine, proven):
    """Execute the production COMMIT branch, with readback and transport isolated."""
    source = str(ROOT / "tools/bootstrap_integrity.ps1").replace("'", "''")
    result = run_functions(
        tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
        ["Install-BootstrapWorkerShortcuts"],
        f". '{source}'\nSet-StrictMode -Version Latest\n" + r'''
$root=$env:CA_CONTRACT_ROOT
$current=Join-Path $root 'current'
[void][IO.Directory]::CreateDirectory((Join-Path $current 'app\assets'))
[IO.File]::WriteAllText((Join-Path $current 'launch-container-audit.cmd'),'never executed')
[IO.File]::WriteAllText((Join-Path $current 'app\assets\logo.ico'),'test icon')
function Get-BootstrapWorkerShortcutFolders([string]$Scope='All'){
    if($Scope -cne 'Common'){throw 'elevated helper attempted a worker profile write'}
    foreach($name in @('CommonDesktop','CommonPrograms')){
        [pscustomobject]@{path=(Join-Path $script:workerShortcutTestRoot $name);common=$true}
    }
}
$script:workerShortcutTestRoot=$root
function Get-InstallationEvidenceControlRoot {Join-Path $script:workerShortcutTestRoot 'ProgramData'}
function Read-InstallationTransactionFile {param($Path,$Hash);[pscustomobject]@{Record=@{}}}
function Assert-InstallationTransactionIdentity {param($Record,$Configuration)}
function Get-CanonicalInstallationCommitPoint {return 'REACHED'}
function Assert-CanonicalTransactionCommit {param($Configuration);if($env:CA_READBACK_PROVEN -cne '1'){throw 'injected unproven installed readback'}}
$Configuration=[pscustomobject]@{install_root=$current;source_manifest=@{};operator_sid='test-worker';
    local_appdata_root=$root;data_root=$root;outcome_hashes=@{COMMIT='test-digest'}}
$commit=Join-Path $root 'commit.request';[IO.File]::WriteAllText($commit,'test decision')
$source=$root;$released=$true;$finished=$false
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
$coordinator=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $_.Name -ceq 'Invoke-InstallationTransactionCoordinator'})[0]
$branch=@($coordinator.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -ceq '[IO.File]::Exists($commit)'},$true))
if($branch.Count -ne 1){throw 'actual elevated COMMIT branch is ambiguous'}
$failure=$false
# The production break exits this one-iteration loop after the real branch runs.
for($once=0;$once -lt 1;$once++){
    try{Invoke-Expression $branch[0].Extent.Text}catch{$failure=$true}
}
if($env:CA_READBACK_PROVEN -ceq '1'){
    if($failure -or -not $finished -or $shortcutResult.scope -cne 'Common'){throw 'public shortcut commit failed'}
    foreach($name in @('CommonDesktop','CommonPrograms')){
        if(-not [IO.File]::Exists((Join-Path (Join-Path $root $name) '이적 검사.lnk'))){throw 'public shortcut absent'}
    }
}else{
    if(-not $failure -or $finished -or [IO.Directory]::Exists((Join-Path $root 'CommonDesktop'))){throw 'unproven readback changed shortcuts'}
}
'worker_shortcut_commit=PASS'
''', values={"CA_READBACK_PROVEN": "1" if proven else "0"}, engine=engine,
    )
    assert result.returncode == 0, result.stderr
    assert "worker_shortcut_commit=PASS" in result.stdout
