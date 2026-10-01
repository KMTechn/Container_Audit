"""Keep the forward failure and native recovery failure distinct and bounded."""
import os
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('CA_RUNTIME_INSTALLER_SOURCE', ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'))


def test_limited_launch_requests_explicit_primary_token_rights_proven_in_guest():
    """Win32 error 5 was reproduced with 11 and resolved with these explicit rights."""
    calls = re.findall(r'DuplicateTokenEx\(token,\s*(0x[0-9a-fA-F]+|\d+),', SOURCE.read_text(encoding='utf-8-sig'))
    assert [int(value, 0) for value in calls] == [0x18B]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('scenario', ('native_access_denied', 'native_privilege_missing', 'placement', 'unclassified'))
def test_failure_details_survive_method_wrapper_without_credentials(tmp_path, engine, scenario):
    result = run_functions(tmp_path, SOURCE, ['Get-CanonicalFailureDetails'], r'''
$Script:InstallationEvidenceSensitiveValues=@('sensitive-sentinel-do-not-store')
Add-Type -TypeDefinition @'
using System; using System.ComponentModel;
public static class InjectedLaunchFailure {
 public static void Fail(int error) {
  Win32Exception failure=new Win32Exception(error,"sensitive-sentinel-do-not-store");
  failure.Data["canonical_api"]="CreateProcessWithTokenW";
  throw failure;
 }
}
'@
try {
 if ($env:CA_FAILURE_SCENARIO -ceq 'native_access_denied') { [InjectedLaunchFailure]::Fail(5) }
 elseif ($env:CA_FAILURE_SCENARIO -ceq 'native_privilege_missing') { [InjectedLaunchFailure]::Fail(1314) }
 elseif ($env:CA_FAILURE_SCENARIO -ceq 'placement') { throw '설치 코드 배치 전 중단 (CONTAINER_PLACEMENT_ACCESS_DENIED). sensitive-sentinel-do-not-store' }
 else { throw 'sensitive-sentinel-do-not-store' }
} catch { $failure=$_ }
$details=Get-CanonicalFailureDetails $failure 'INSTALL'
$json=$details | ConvertTo-Json -Depth 6
if ($json.Contains('sensitive-sentinel')) { throw 'raw failure message leaked' }
if ($details.phase -cne 'INSTALL' -or $details.exception_types.Count -lt 1) { throw 'failure identity lost' }
if ($env:CA_FAILURE_SCENARIO -clike 'native_*') {
 $expectedError=if ($env:CA_FAILURE_SCENARIO -ceq 'native_access_denied') {5} else {1314}
 if ($details.api -cne 'CreateProcessWithTokenW' -or $details.win32_error -ne $expectedError) { throw 'native cause lost in MethodInvocationException' }
 if ($details.exception_types -cnotcontains 'System.Management.Automation.MethodInvocationException') { throw 'outer failure not preserved' }
} elseif ($env:CA_FAILURE_SCENARIO -ceq 'placement') {
 if ($details.code -cne 'CONTAINER_PLACEMENT_ACCESS_DENIED') { throw 'forward placement failure lost' }
} elseif ($details.code -cne 'CANONICAL_UNCLASSIFIED_FAILURE') { throw 'unclassified failure invented' }
'PASS'
''', values={'CA_FAILURE_SCENARIO': scenario}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('scenario', ('run_restored', 'run_changed', 'foreign_relay', 'stop_present', 'writer_not_restored'))
def test_real_rollback_catch_records_next_logon_only_for_exact_safe_preimage(tmp_path, engine, scenario):
    result = run_functions(tmp_path, SOURCE, ['Get-CanonicalFailureDetails'], r'''
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$tokens,[ref]$errors)
$blocks=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains("rollback.normal_relay_exact_preimage") -and $n.CatchClauses.Count -eq 1 -and $n.CatchClauses[0].Body.Extent.Text.Contains("$"+'audit.rollback.runtime_restored=$false')},$true))
if ($blocks.Count -ne 1) { throw 'expected actual rollback runtime block' }
$mutated=$true
$old=@([pscustomobject]@{CommandLine='exact-old-command';ExecutablePath='old.exe'})
$before=@{exists=$true;kind='String';data='exact-old-command'}
$stop=Join-Path $env:CA_CONTRACT_ROOT 'stop.json'
if ($env:CA_FAILURE_SCENARIO -ceq 'stop_present') { [IO.File]::WriteAllText($stop,'{}') }
$audit=[ordered]@{failure=@{code='CONTAINER_PLACEMENT_CHILD_FAILED';phase='INSTALL'};rollback=[ordered]@{runtime_restored=$false;scheduled_writer_restored=$true}}
if ($env:CA_FAILURE_SCENARIO -ceq 'writer_not_restored') { $audit.rollback.scheduled_writer_restored=$false }
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json'; $evidenceFull=''
function Start-CanonicalRelayAfterFenceRelease { throw ([ComponentModel.Win32Exception]::new(1314)) }
function Start-Sleep {}
function Save([string]$Path,$Value) { [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 8)) }
function Snapshot {
 $command=if ($env:CA_FAILURE_SCENARIO -ceq 'run_changed') {'foreign-command'} else {'exact-old-command'}
 return @{exists=$true;kind='String';data=$command}
}
function Relays { if ($env:CA_FAILURE_SCENARIO -ceq 'foreign_relay') { return @(@{ProcessId=999}) }; return @() }
function Assert-RollbackRelayPreimage {}
try { Invoke-Expression $blocks[0].Extent.Text } catch { $caught=$_ }
$saved=Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json
if ($saved.rollback.runtime_restored -or -not $caught) { throw 'failed recovery marked successful' }
if ($saved.failure.code -cne 'CONTAINER_PLACEMENT_CHILD_FAILED') { throw 'rollback overwrote forward cause' }
if ($saved.rollback.failure.win32_error -ne 1314 -or $saved.rollback.failure.phase -cne 'ROLLBACK_RELAY') { throw 'rollback native failure lost' }
if ($env:CA_FAILURE_SCENARIO -ceq 'run_restored') {
 if ($saved.rollback.relay_recovery_status -cne 'RUN_RESTORED_RELAY_NEXT_LOGON') { throw 'exact Run recovery not distinguished' }
} elseif ($saved.rollback.relay_recovery_status -ceq 'RUN_RESTORED_RELAY_NEXT_LOGON') { throw 'unsafe or inexact recovery accepted' }
'PASS'
''', values={'CA_FAILURE_SCENARIO': scenario}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
