"""Foreign emergency entries survive both actual shortcut installation callers."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("kind", (
    "parent_file", "emergency_file", "sibling_file", "parent_junction",
    "link_directory", "link_junction",
))
def test_foreign_emergency_entries_are_preserved_by_both_callers(tmp_path, engine, kind):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", [
        "Get-CanonicalMachineShortcutArguments", "Get-CanonicalMachineShortcutPlacement",
        "New-CanonicalMachineShortcut", "Set-CanonicalPublishedShortcuts", "Test-ExactPropertySet",
    ], r'''
Set-StrictMode -Version Latest
. $env:CA_BOOTSTRAP_LIBRARY
function Same($a,$b){return [IO.Path]::GetFullPath($a) -ieq [IO.Path]::GetFullPath($b)}
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'folders'
$root=Join-Path $env:CA_CONTRACT_ROOT 'product\current'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'runtime'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app'))
[IO.File]::WriteAllText((Join-Path $root 'launch-container-audit.cmd'),'isolated launcher')
[IO.File]::WriteAllText((Join-Path $root 'runtime\pythonw.exe'),'isolated runtime')
$path=Get-BootstrapEmergencyShortcutPath $root
$directory=Split-Path -Parent $path
$foreign=Join-Path $env:CA_CONTRACT_ROOT 'foreign'
[void][IO.Directory]::CreateDirectory($foreign)
$sentinel=Join-Path $foreign 'preserved.txt'
[IO.File]::WriteAllText($sentinel,'foreign content')
$originals=@{};$originals[$sentinel]=Get-FileSha256 $sentinel
switch -CaseSensitive ($env:CA_FOREIGN_ENTRY_KIND){
 'parent_file' {[IO.File]::WriteAllText($directory,'foreign parent');$originals[$directory]=Get-FileSha256 $directory}
 'parent_junction' {$null=New-Item -ItemType Junction -Path $directory -Target $foreign}
 default {
  [void][IO.Directory]::CreateDirectory($directory)
  switch -CaseSensitive ($env:CA_FOREIGN_ENTRY_KIND){
   'emergency_file' {[IO.File]::WriteAllText($path,'foreign file');$originals[$path]=Get-FileSha256 $path}
   'sibling_file' {$other=Join-Path $directory 'foreign.txt';[IO.File]::WriteAllText($other,'foreign sibling');$originals[$other]=Get-FileSha256 $other}
   'link_directory' {[void][IO.Directory]::CreateDirectory($path)}
   'link_junction' {$null=New-Item -ItemType Junction -Path $path -Target $foreign}
   default {throw 'fixture kind unknown'}
  }
 }
}
$record=Get-BootstrapWorkerShortcutRecordPath $root (Join-Path $env:CA_CONTRACT_ROOT 'records')
$worker=Install-BootstrapWorkerShortcuts $root $record 'Common'
$programs=Join-Path $env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT 'CommonPrograms'
$machine=New-CanonicalMachineShortcut $root $programs
foreach($result in @($worker,$machine)){
 if($result.status -cne 'PASS'){throw 'foreign emergency entry failed installation'}
 if(@($result.preserved|Where-Object {$_.shortcut_path -ieq $path -and $_.status -clike 'FOREIGN_*_PRESERVED'}).Count -ne 1){throw 'preservation not recorded'}
 if(@($result.published|Where-Object {$_.location -ceq 'emergency' -or $_.shortcut_path -ieq $path}).Count){throw 'foreign emergency entry published'}
}
if(@($worker.published).Count -ne 2 -or @($machine.published).Count -ne 1){throw 'normal shortcut publication differs'}
$audit=@{shortcuts=@{published=@()}}
Set-CanonicalPublishedShortcuts $audit @($worker,$machine)
if(@($audit.shortcuts.published).Count -ne 3){throw 'publication audit differs'}
foreach($original in $originals.Keys){if((Get-FileSha256 $original) -cne $originals[$original]){throw 'foreign bytes changed'}}
if(@(Get-ChildItem -LiteralPath $foreign -Force).Count -ne 1){throw 'junction target modified'}
if($env:CA_FOREIGN_ENTRY_KIND -cin @('parent_junction','link_junction')){
 $entry=if($env:CA_FOREIGN_ENTRY_KIND -ceq 'parent_junction'){$directory}else{$path}
 if(-not ((Get-Item -LiteralPath $entry -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'foreign junction replaced'}
}
'PASS'
''', engine=engine, values={
        "CA_BOOTSTRAP_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"),
        "CA_FOREIGN_ENTRY_KIND": kind,
    })
    assert result.returncode == 0
    assert result.stdout.rstrip().endswith("PASS")


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("failure", ("atomic", "readback"))
def test_owned_emergency_publication_failure_has_fixed_public_reason(tmp_path, engine, failure):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", [
        "Get-CanonicalMachineHelperReason", "Get-CanonicalMachineFailureReason",
    ], r'''
. $env:CA_BOOTSTRAP_LIBRARY
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'folders'
$root=Join-Path $env:CA_CONTRACT_ROOT 'product\current'
[void][IO.Directory]::CreateDirectory($root)
[IO.File]::WriteAllText((Join-Path $root 'launch-container-audit.cmd'),'isolated launcher')
if($env:CA_FAILURE -ceq 'atomic'){
 function Invoke-ContainerAtomicReplace {throw 'INJECTED_ATOMIC_FAILURE'}
}else{
 function Get-BootstrapPublishedShortcut {throw 'INJECTED_READBACK_FAILURE'}
}
$caught=$null
try{$null=Install-BootstrapEmergencyShortcut $root}catch{$caught=$_}
if($null -eq $caught){throw 'owned failure admitted'}
if($caught.Exception.Message -cne 'EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED'){throw 'fixed failure reason missing'}
if((Get-CanonicalMachineFailureReason $caught) -cne 'EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED'){throw 'direct reason missing'}
$summary='installation_failure_summary={"reason_code":"EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED"}'
if((Get-CanonicalMachineHelperReason $summary) -cne 'EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED'){throw 'child reason missing'}
if((Get-CanonicalMachineHelperReason '' 'INJECTED_ATOMIC_FAILURE') -cne 'PLACEMENT_HELPER_FAILED'){throw 'private reason exposed'}
'PASS'
''', engine=engine, values={
        "CA_BOOTSTRAP_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"),
        "CA_FAILURE": failure,
    })
    assert result.returncode == 0
    assert result.stdout.rstrip().endswith("PASS")
