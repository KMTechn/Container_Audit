"""Canonical final/recovery relay starts keep the interactive user's normal token."""
import os
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("CA_RUNTIME_INSTALLER_SOURCE", ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"))


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("scenario", ("elevated", "normal", "wrong_sid", "wrong_session", "still_elevated", "launch_error", "query_error", "session_zero"))
def test_start_raw_requires_same_user_session_and_normal_token(tmp_path, engine, scenario):
    result = run_functions(tmp_path, SOURCE, ["StartRaw", "Get-CanonicalOperatorSecurity"], r'''
$script:cim=0; $script:limited=0
$command='C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe -I -B C:\KMTech\Apps\Container_Audit\current\app\main.py --container-audit-user-relay'
function Get-CanonicalRelaySecurity([int]$ProcessId) {
    if ($env:CA_START_SCENARIO -ceq 'query_error') { throw 'injected token query failure' }
    $user='S-1-5-21-111-222-333-1001'; $session=1
    $elevated=($env:CA_START_SCENARIO -cne 'normal')
    if ($env:CA_START_SCENARIO -ceq 'session_zero') { $session=0 }
    if ($ProcessId -eq 1234) {
        $elevated=($script:limited -eq 0 -and $env:CA_START_SCENARIO -cne 'normal')
        if ($env:CA_START_SCENARIO -ceq 'wrong_sid') { $user='S-1-5-21-111-222-333-1002' }
        if ($env:CA_START_SCENARIO -ceq 'wrong_session') { $session=2 }
        if ($env:CA_START_SCENARIO -ceq 'still_elevated') { $elevated=$true }
    }
    return [pscustomobject]@{sid=$user;session_id=$session;elevated=$elevated}
}
function Start-CanonicalLimitedRelay([string]$Line,[string]$UserSid,[int]$SessionId) {
    $script:limited++
    if ($Line -cne $command -or $UserSid -cne 'S-1-5-21-111-222-333-1001' -or $SessionId -ne 1) { throw 'launch binding differs' }
    if ($env:CA_START_SCENARIO -ceq 'launch_error') { throw 'interactive normal-user launch refused' }
    return 1234
}
function Invoke-CimMethod { $script:cim++; return @{ReturnValue=0;ProcessId=1234} }
$failure=''; $actual=0
try { $actual=StartRaw $command } catch { $failure=$_.Exception.Message }
if ($env:CA_START_SCENARIO -cin @('elevated','normal')) {
    if ($failure -or $actual -ne 1234) { throw ('supported user launch rejected: '+$failure) }
    $observed=Get-CanonicalRelaySecurity $actual
    if ($observed.elevated) { throw 'relay kept installer elevation' }
    if ($env:CA_START_SCENARIO -ceq 'elevated' -and ($script:cim -ne 0 -or $script:limited -ne 1)) { throw 'elevated caller bypassed normal-user launch' }
    if ($env:CA_START_SCENARIO -ceq 'normal' -and ($script:cim -ne 1 -or $script:limited -ne 0)) { throw 'normal caller launch changed' }
} else {
    if (-not $failure) { throw 'invalid user/session/token accepted' }
    if ($script:cim -ne 0) { throw 'unsafe fallback to installer token' }
}
'PASS'
''', values={"CA_START_SCENARIO": scenario}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_normal_user_native_boundary_compiles_without_running_it(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Initialize-CanonicalUserProcessApi"], r'''
Initialize-CanonicalUserProcessApi
if (-not ('ContainerAuditCanonicalUserProcess' -as [type])) { throw 'native boundary did not compile' }
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
