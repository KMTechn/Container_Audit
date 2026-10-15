from pathlib import Path
import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(('entry', 'followup'), [
    ('canonical', 'success'), ('canonical', 'ordinary'), ('canonical', 'pending'),
    ('helper', 'success'), ('helper', 'ordinary')])
def test_emergency_cause_and_retained_marker_survive_followup(tmp_path, entry, followup):
    library = str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''")
    driver = ". '" + library + "'\n" + r'''
$ErrorActionPreference='Stop'
$base=$env:CA_CONTRACT_ROOT
$root=Join-Path $base 'application\current'
[void][IO.Directory]::CreateDirectory($root)
function Get-StrictFullPath([string]$Path,[string]$Purpose){return [IO.Path]::GetFullPath($Path)}
function Assert-BootstrapWorkerShortcutPath {}
function Assert-BootstrapNoReparsePoint {}
function Assert-InstallationMachineMetadataNoSecrets {}
$emergency=Get-BootstrapEmergencyShortcutPath $root
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $emergency))
[IO.File]::WriteAllText($emergency,'retained fixture')
$marker=Join-Path (Split-Path -Parent $root) 'removed.json'
[IO.File]::WriteAllText($marker,(@{schema='container-audit-supported-removal-v1';lifecycle_state='REMOVED';retained_paths=@();artifact_dispositions=@()}|ConvertTo-Json))
$first=[IO.IOException]::new('EMERGENCY_FIXTURE_FAILURE')
function Remove-BootstrapEmergencyShortcut {throw $first}
$pending=Join-Path $base 'pending.json'
$shortcut=Join-Path $base 'ordinary.lnk'
if($env:CA_FOLLOWUP -ceq 'pending'){
    [IO.File]::WriteAllText($pending,'{}')
}
if($env:CA_FOLLOWUP -ceq 'ordinary'){
    [IO.File]::WriteAllText($shortcut,'invalid shortcut fixture')
}
function Read-BootstrapWorkerShortcutRecord {
    return [pscustomobject]@{entries=@($(if($env:CA_FOLLOWUP -ceq 'ordinary'){
        [pscustomobject]@{path=$shortcut;action='created'}
    }))}
}
$caught=$null
try {
    if($env:CA_ENTRY -ceq 'canonical'){
        Remove-CanonicalMachineArtifacts $root ([pscustomobject]@{sid='fixture-worker'}) @($pending,$shortcut)
    }else{[void](Restore-BootstrapWorkerShortcuts $root (Join-Path $base 'record.json'))}
}catch{$caught=$_.Exception}
if($null -eq $caught){throw 'EMERGENCY_FAILURE_WAS_LOST'}
if($env:CA_FOLLOWUP -ceq 'success'){
    if($caught -ne $first){throw 'FIRST_EXCEPTION_IDENTITY_CHANGED'}
}else{
    if($caught -isnot [AggregateException] -or $caught.InnerExceptions.Count -lt 2 -or
        $caught.InnerExceptions[0] -ne $first){throw 'COMPOUND_CAUSES_WERE_LOST'}
}
$state=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json
if($state.retained_paths -cnotcontains $emergency -or -not $state.emergency_shortcut.shortcut_exists -or
    $state.emergency_shortcut.target_exists -or $state.emergency_shortcut.cleanup_status -cne 'FAILED'){
    throw 'RETAINED_EMERGENCY_STATE_DIFFERS'
}
'''
    source = ROOT / ('INSTALL_CANONICAL_PORTABLE.ps1' if entry == 'canonical' else 'tools/bootstrap_integrity.ps1')
    names = ['Remove-CanonicalMachineArtifacts', 'Same', 'Full'] if entry == 'canonical' else ['Restore-BootstrapWorkerShortcuts']
    result = run_functions(tmp_path, source, names, driver,
                           values={'CA_ENTRY': entry, 'CA_FOLLOWUP': followup})
    if result.returncode:
        import re
        kinds = sorted(set(re.findall(r'\b\w+(?:Exception|Error)\b', result.stderr)))
        raise AssertionError('PowerShell probe failed: ' + ','.join(kinds))
