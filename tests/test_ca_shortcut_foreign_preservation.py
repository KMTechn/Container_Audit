"""Real shell links: preserve unrelated existing links and publish only our writes."""
from pathlib import Path

import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("dead_target", (False, True))
@pytest.mark.parametrize("foreign_emergency", (False, True))
def test_foreign_standard_and_dead_target_links_survive_both_install_paths(
    tmp_path, engine, dead_target, foreign_emergency,
):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", [
        "Get-CanonicalMachineShortcutArguments", "Get-CanonicalMachineShortcutPlacement",
        "New-CanonicalMachineShortcut",
    ], r'''
Set-StrictMode -Version Latest
. $env:CA_BOOTSTRAP_LIBRARY
function Same($a,$b){return [IO.Path]::GetFullPath($a) -ieq [IO.Path]::GetFullPath($b)}
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'knownfolders'
$root=Join-Path $env:CA_CONTRACT_ROOT 'app-code\current'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'runtime'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app'))
[IO.File]::WriteAllText((Join-Path $root 'launch-container-audit.cmd'),'fixture')
[IO.File]::WriteAllText((Join-Path $root 'runtime\pythonw.exe'),'fixture')
$target=Join-Path $env:CA_CONTRACT_ROOT 'other-app\old.exe'
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $target))
if($env:CA_DEAD_TARGET -eq '0'){[IO.File]::WriteAllText($target,'foreign fixture')}
$shell=New-Object -ComObject WScript.Shell
$originals=@{}
try{
 foreach($folder in @(Get-BootstrapWorkerShortcutFolders 'Common')){
  [void][IO.Directory]::CreateDirectory($folder.path)
  $path=Join-Path $folder.path '이적 검사.lnk'
  $link=$shell.CreateShortcut($path);$link.TargetPath=$target;$link.Save()
  $originals[$path]=Get-FileSha256 $path
 }
 $programs=Join-Path $env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT 'CommonPrograms'
 $machineForeign=Join-Path $programs 'KMTech 이적 검사.lnk'
 $link=$shell.CreateShortcut($machineForeign);$link.TargetPath=$target;$link.Save()
 $originals[$machineForeign]=Get-FileSha256 $machineForeign
 if($env:CA_FOREIGN_EMERGENCY -eq '1'){
  $emergency=Get-BootstrapEmergencyShortcutPath $root
  [void][IO.Directory]::CreateDirectory((Split-Path -Parent $emergency))
  $link=$shell.CreateShortcut($emergency);$link.TargetPath=$target;$link.Save()
  $originals[$emergency]=Get-FileSha256 $emergency
 }
 $record=Get-BootstrapWorkerShortcutRecordPath $root (Join-Path $env:CA_CONTRACT_ROOT 'records')
 $worker=Install-BootstrapWorkerShortcuts $root $record 'Common'
 $machinePlan=Get-CanonicalMachineShortcutPlacement $root $programs
 $machine=New-CanonicalMachineShortcut $root $programs -ExpectedPath ([string]$machinePlan.path)
 if($worker.status -cne 'PASS' -or $machine.status -cne 'PASS'){throw 'foreign links failed installation'}
 if(@($worker.preserved).Count -lt 3 -or @($machine.preserved).Count -lt 1){throw 'preservation not recorded'}
 $all=@($worker.published)+@($machine.published)
 if($all.Count -ne (4-[int]($env:CA_FOREIGN_EMERGENCY -eq '1'))){throw 'published write count differs'}
 foreach($entry in $all){
  if($originals.ContainsKey($entry.shortcut_path)){throw 'foreign link entered published'}
  $actual=$shell.CreateShortcut($entry.shortcut_path)
  if([string]$actual.TargetPath -ine $entry.target_path -or [string]$actual.Arguments -cne $entry.arguments -or
     [string]$actual.WorkingDirectory -ine $entry.working_directory){throw 'published readback differs'}
 }
 $recordBefore=Get-FileSha256 $record
 $workerAgain=Install-BootstrapWorkerShortcuts $root $record 'Common'
 $machineAgain=New-CanonicalMachineShortcut $root $programs
 if(@($workerAgain.published).Count -or @($machineAgain.published).Count -or (Get-FileSha256 $record) -cne $recordBefore){throw 'retained link counted as this installation write'}
 foreach($path in $originals.Keys){if((Get-FileSha256 $path) -cne $originals[$path]){throw 'foreign bytes changed'}}
 'PASS'
}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
''', engine=engine, values={
        "CA_BOOTSTRAP_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"),
        "CA_DEAD_TARGET": str(int(dead_target)),
        "CA_FOREIGN_EMERGENCY": str(int(foreign_emergency)),
    })
    assert result.returncode == 0
    assert result.stdout.rstrip().endswith("PASS")
