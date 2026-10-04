"""Rollback readiness is bounded and preserves completed recovery steps."""
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions

SOURCE = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_normal_and_rollback_relay_share_observed_readiness_budget(tmp_path, engine):
    names = re.findall(r"^function\s+([^\s(]+)", SOURCE.read_text(encoding="utf-8-sig"), re.M)
    result = run_functions(tmp_path, SOURCE, names, r'''
$install=$env:CA_CONTRACT_ROOT;$wanted='isolated';$relayPath=Join-Path $install 'status.json'
[IO.File]::WriteAllText($relayPath,'{"status":"RUNNING"}')
function Get-BootstrapRelayExpectedIdentity {return @{source_commit=''}}
function Get-BootstrapRelayReadinessSnapshot($Identity) {$script:budget=$TimeoutSeconds;return @{identity=$Identity;settled=$true;phase=''}}
function Get-CanonicalRelaySecurity {return @{}}
function Relays {if($script:queries++ -eq 0){return @()};return [pscustomobject]@{ProcessId=1234}}
function Get-CimInstance {return [pscustomobject]@{ProcessId=1234;ExecutablePath='isolated'}}
function Test-BootstrapRelayReadback {return $true}
function StartRaw {return 999}
function Write-InstallationEvidenceEvent {}
foreach($mode in @('install','rollback')) {
    $script:queries=0
    [void](Start-CanonicalRelayAfterFenceRelease -Root $install -RunCommand $wanted)
    # G: request to first recorded READY = 275.562 s; allow at least 60 s headroom.
    if($script:budget -lt 336 -or $script:budget -gt 600){throw 'shared readiness budget excludes observed lab delay'}
}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_timeout_reports_completed_rollback_without_success(tmp_path, engine):
    names = re.findall(r"^function\s+([^\s(]+)", SOURCE.read_text(encoding="utf-8-sig"), re.M)
    result = run_functions(tmp_path, SOURCE, names, r'''
$source=Get-Content -LiteralPath $env:CA_CONTRACT_SOURCE -Raw
$start=$source.IndexOf('    # Win32_Process.Create does not inherit this process')
$end=$source.IndexOf('    # A fresh placement has no old code tree to restore.',$start)
if($start -lt 0 -or $end -le $start){throw 'real final rollback sequence absent'}
$mutated=$true;$old=@(@{ProcessId=1234});$before=@{exists=$true;kind='String';data='isolated'}
$install=$env:CA_CONTRACT_ROOT;$stop=Join-Path $install 'absent.stop';$auditPath=Join-Path $install 'audit.json';$evidenceFull=''
$audit=@{status='ROLLBACK_AWAITING_FENCE_RELEASE';rollback=@{code_exact=$true;scheduled_writer_restored=$true;runtime_restored=$false}}
function Start-CanonicalRelayAfterFenceRelease {throw 'CANONICAL_RELAY_READY_TIMEOUT'}
function Snapshot {return $before}
function Relays {return @()}
function Set-InstallationEvidenceStage {}
function Write-InstallationCaughtFailure {}
function Get-CanonicalFailureDetails {return @{stage='ROLLBACK_RELAY'}}
function Save($Path,$Value) {[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 10))}
$failure='';$line=''
try {$line=(. ([scriptblock]::Create($source.Substring($start,$end-$start))) -WarningAction SilentlyContinue)|Out-String} catch {$failure=$_.Exception.Message}
if($failure){throw ('rollback aborted before final state reporting: '+$failure)}
if($audit.status -cne 'AUTOSTART_ROLLBACK_FAILED' -or $audit.rollback.runtime_restored){throw 'timeout was reported as success'}
if(-not(Test-Path -LiteralPath $auditPath) -or $line -notmatch 'relay.*READY' -or $line -notmatch 'Run'){throw 'exact terminal state line or durable failure missing'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
