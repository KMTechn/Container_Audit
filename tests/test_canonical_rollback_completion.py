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
    names.append('Record-CanonicalRollbackStep')
    result = run_functions(tmp_path, SOURCE, names, r'''
$parseErrors=$null;$parseTokens=$null
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$parseTokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'canonical parse failed'}
$catch=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CatchClauseAst] -and
    $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true))
if($catch.Count -ne 1){throw 'real rollback catch absent'}
$restart=@($catch[0].FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Extent.Text.StartsWith('if ($mutated -and $rollbackRecoveryVerified -and -not $canonicalWriterFenceActive)')},$true))
if($restart.Count -ne 1){throw 'real rollback restart absent'}
$terminal=@();$collect=$false
foreach($statement in $catch[0].Body.Statements){
    if($statement.Extent.Text.StartsWith('if (-not [string]::IsNullOrWhiteSpace($codeRollbackFailure))')){$collect=$true}
    if($statement.Extent.Text.StartsWith('$publicFailure=')){break}
    if($collect){$terminal+=,$statement.Extent.Text}
}
if($terminal.Count -lt 6){throw 'real rollback completion absent'}
$mutated=$true;$old=@(@{ProcessId=1234});$before=@{exists=$true;kind='String';data='isolated'}
$install=$env:CA_CONTRACT_ROOT;$stop=Join-Path $install 'absent.stop';$auditPath=Join-Path $install 'audit.json';$evidenceFull=''
$audit=@{status='ROLLBACK_AWAITING_FENCE_RELEASE';rollback=@{code_exact=$true;scheduled_writer_restored=$true;runtime_restored=$false;steps=@{}}}
$rollbackRecoveryVerified=$true;$canonicalWriterFenceActive=$false;$RestoreVerifiedReplacement=$false
$codeRollbackFailure='';$writerRollbackFailure='';$autostartRollbackFailure='';$fenceReleaseFailure=''
function Start-CanonicalRelayAfterFenceRelease {throw 'CANONICAL_RELAY_READY_TIMEOUT'}
function Snapshot {return $before}
function Relays {return @()}
function Set-InstallationEvidenceStage {}
function Write-InstallationCaughtFailure {}
function Get-CanonicalFailureDetails {return @{stage='ROLLBACK_RELAY'}}
function Save($Path,$Value) {[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 10))}
function Save-CanonicalRecoveryDiagnostics {param($Stage);Save $auditPath $audit}
function Assert-RollbackRelayPreimage {throw 'CANONICAL_RELAY_READY_TIMEOUT'}
$original=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('isolated original failure'),'IsolatedFailure',[Management.Automation.ErrorCategory]::InvalidOperation,$null)
$failure=''
try {. ([scriptblock]::Create($restart[0].Extent.Text+"`n"+($terminal -join "`n")))}catch{$failure=$_.Exception.GetType().Name}
if($failure -cne 'InvalidOperationException'){throw ('timeout terminal type differs: '+$failure)}
if($audit.status -cne 'AUTOSTART_ROLLBACK_FAILED' -or $audit.rollback.runtime_restored){throw 'timeout was reported as success'}
if(-not(Test-Path -LiteralPath $auditPath) -or $audit.rollback.steps.relay_restart.status -cne 'FAILED' -or
    $audit.rollback.steps.completion.status -cne 'FAILED' -or -not $audit.rollback.code_exact -or
    -not $audit.rollback.scheduled_writer_restored){throw 'exact durable terminal state or preserved recovery steps missing'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
