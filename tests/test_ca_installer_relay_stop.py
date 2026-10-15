"""Exercise the ordinary installer stop boundary without starting a product."""
from pathlib import Path

import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("case", ("normal", "absent", "foreign_sid", "other_session", "elevated", "reused_pid", "other_writer", "stop_failed", "caller-integrity", "relay-integrity", "relay-elevated", "session-zero", "missing-caller-level", "missing-relay-level"))
def test_installer_ordinary_relay_stop_boundary(tmp_path, engine, case):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", [
        "Stop-CanonicalInstallerRelayPreimage", "Test-CanonicalOrdinaryRelaySecurity",
        "Read-CanonicalInstallerOwnedStopMarker", "Full", "Same", "Sha",
    ], r'''
Set-StrictMode -Version Latest
Initialize-BootstrapRelaySecurity
$Script:CanonicalWriterFenceTransactionId='1234567890abcdef1234567890abcdef'
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
if($env:CA_STOP_FIELD_MUTATION -ceq '1'){
 $body=(Get-Command Test-CanonicalOrdinaryRelaySecurity).ScriptBlock.ToString().Replace('integrity_level','integrity_rid')
 Set-Item -LiteralPath Function:Test-CanonicalOrdinaryRelaySecurity -Value ([scriptblock]::Create($body))
}
$script:called=0;$script:events=[Collections.Generic.List[object]]::new()
$script:CanonicalInstallerRelayStopAttempted=$false
$script:process=[pscustomobject]@{ProcessId=4001;CreationDate=[DateTime]'2026-10-15T01:00:00Z';ExecutablePath='X:\current\runtime\pythonw.exe';CommandLine='relay'}
$expected=[pscustomobject]@{ProcessId=4001;CreationDate=$script:process.CreationDate;ExecutablePath=$script:process.ExecutablePath;CommandLine='relay'}
$script:caller=[KMTechBootstrapRelaySecurity+Security]::new()
$script:caller.sid='S-1-5-21-1-2-3-1001'
$script:caller.session_id=1
$script:caller.elevated=$false
$script:caller.integrity_level=8192
$script:security=[KMTechBootstrapRelaySecurity+Security]::new()
$script:security.sid=$script:caller.sid
$script:security.session_id=1
$script:security.elevated=$false
$script:security.integrity_level=8192
$subjectSid=$script:caller.sid
switch($env:CA_STOP_CASE){
 'caller-integrity' {$script:caller.integrity_level=12288}
 'relay-integrity' {$script:security.integrity_level=4096}
 'relay-elevated' {$script:security.elevated=$true}
 'session-zero' {$script:caller.session_id=0}
 'missing-caller-level' {$script:caller=[pscustomobject]@{sid=$subjectSid;session_id=4;elevated=$false}}
 'missing-relay-level' {$script:security=[pscustomobject]@{sid=$subjectSid;session_id=4;elevated=$false}}
 'foreign_sid' {$script:security.sid='S-1-5-21-1-2-3-1002'}
 'other_session' {$script:security.session_id=2}
 'elevated' {$script:caller.elevated=$true}
 'reused_pid' {$script:process.CreationDate=$script:process.CreationDate.AddSeconds(1)}
}
function Get-CanonicalOperatorSecurity {return $script:caller}
function Get-CanonicalRelaySecurity($id){return $script:security}
function Get-CanonicalInstallerProductWriters($root){
 if($env:CA_STOP_CASE -eq 'absent'){return @()}
 if($env:CA_STOP_CASE -eq 'other_writer'){return [pscustomobject]@{ProcessId=4002;CreationDate=$script:process.CreationDate}}
 return $script:process
}
function Assert-RollbackRelayPreimage($rows){return $script:process}
function Get-CanonicalGlobalRelayPreimage {return @([pscustomobject]@{process_id=4001})}
function Write-InstallationEvidenceEvent($event){$script:events.Add($event)}
function Get-BootstrapStringSha256($text){
 $h=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
function Invoke-InstallationEvidenceChild($name,$exe,$arguments){
 if($script:events.Count -ne 1 -or $script:events[0].event -cne 'INSTALLER_RELAY_PREIMAGE'){throw 'preimage order differs'}
 if($arguments[0] -cne '-I' -or $arguments[1] -cne '-B' -or $arguments[2] -cne '-c' -or $arguments[-1] -cne $script:state){throw 'stop command differs'}
 $marker=Join-Path $script:state 'control/container_audit_user_relay.stop.json'
 [void][IO.Directory]::CreateDirectory((Split-Path -Parent $marker))
 [IO.File]::WriteAllText($marker,(@{schema_version='container-audit-user-relay-stop-v1';request_id=[string]$arguments[6]}|ConvertTo-Json -Compress))
 $script:called++
 return [pscustomobject]@{ExitCode=if($env:CA_STOP_CASE -eq 'stop_failed'){4}else{0};EvidenceFailure=$null;Stdout='installer_relay_stop=ABSENT'}
}
function Relays {return @()}
$rows=@();if($env:CA_STOP_CASE -ne 'absent'){$rows=@($expected)}
$script:state=Join-Path $env:CA_CONTRACT_ROOT 'state'
$code=Join-Path $env:CA_CONTRACT_ROOT 'packet'
$current=Join-Path $env:CA_CONTRACT_ROOT 'current'
$refused=$false;$proof=$null
try{$proof=Stop-CanonicalInstallerRelayPreimage $rows $script:state $code $current $subjectSid @{exists=$true}}catch{$refused=$true}
if($env:CA_STOP_CASE -in @('normal','absent')){
 if($refused -or $proof.status -cne 'ABSENT'){throw 'ordinary stop failed'}
 if($script:called -ne [int]($env:CA_STOP_CASE -eq 'normal')){throw 'stop count differs'}
}else{
 if(-not $refused){throw 'unsafe stop admitted'}
 if($script:called -ne [int]($env:CA_STOP_CASE -eq 'stop_failed')){throw 'unsafe child started'}
}
'PASS'
''', engine=engine, values={"CA_STOP_CASE": case, "CA_STOP_FIELD_MUTATION": "0"})
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"


def test_installer_stop_is_before_fence_and_machine_scope_is_deferred(tmp_path):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", ["Resolve-CanonicalWorkerSid"], r'''
$source=Get-Content -LiteralPath $env:CA_CONTRACT_SOURCE -Raw
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failed'}
$calls=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Stop-CanonicalInstallerRelayPreimage'},$true))
if($calls.Count -ne 1){throw 'shared stop route differs'}
$main=$source.Substring($calls[0].Extent.EndOffset)
if($main.IndexOf('Start-ContainerWriterFence') -lt 0){throw 'fence order differs'}
$machine=($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-CanonicalMachineInstallation'},$true))[0].Body.Extent.Text
if($machine -match 'Start-CanonicalRelayAfterFenceRelease|Stop-CanonicalInstallerRelayPreimage' -or $machine -notmatch 'DEFERRED_WORKER_INTERACTIVE_SESSION'){throw 'machine scope differs'}
if($source -notmatch 'earlyFenceMatches -or \$Script:CanonicalInstallerRelayStopAttempted'){throw 'early restoration route missing'}
if($source -notmatch 'savedRelayPreimage' -or $source -notmatch 'Assert-CanonicalTransactionRelayPreimage'){throw 'persistent preimage route missing'}
'PASS'
''', engine="powershell")
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("delay", (0, 1200))
def test_final_native_relay_readback_must_finish_before_deadline(tmp_path, engine, delay):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", ["Wait-CanonicalRelayReady"], r'''
Set-StrictMode -Version Latest
$relayPath=Join-Path $env:CA_CONTRACT_ROOT 'relay.json'
[IO.File]::WriteAllText($relayPath,'{"status":"RUNNING","persistent_retry":true}')
$script:snapshots=0;$script:readyEvents=0
$script:identity=[pscustomobject]@{source_commit=('a'*40);manifest_sha256=('b'*64);aggregate_sha256=('c'*64)}
function Get-CanonicalOperatorSecurity {return [pscustomobject]@{sid='S-1-5-21-1-2-3-1001';session_id=1}}
function Get-BootstrapRelayReadinessSnapshot($identity){
 $script:snapshots++
 if($script:snapshots -eq 2 -and [int]$env:CA_READY_DELAY){Start-Sleep -Milliseconds ([int]$env:CA_READY_DELAY)}
 return [pscustomobject]@{identity=$identity;settled=$true;phase='CONFIRMED'}
}
function Relays {return [pscustomobject]@{ProcessId=4001;ExecutablePath='X:\current\runtime\pythonw.exe'}}
function Get-CimInstance {return [pscustomobject]@{ProcessId=4001;ExecutablePath='X:\current\runtime\pythonw.exe'}}
function Get-CanonicalRelaySecurity {return [pscustomobject]@{sid='S-1-5-21-1-2-3-1001';session_id=1;elevated=$false}}
function Assert-BootstrapNoReparsePoint {param($Path,$Purpose,[switch]$PathOnly)}
function Test-BootstrapRelayReadback {return $true}
function Write-InstallationEvidenceEvent($event){if($event.event -ceq 'RESIDENT_RELAY_READY'){$script:readyEvents++}}
$refused=$false
try{$pidValue=Wait-CanonicalRelayReady $script:identity ([DateTime]::UtcNow) '' @() 1}catch{
 if($_.Exception.Message -cne 'CANONICAL_RELAY_READY_TIMEOUT'){throw};$refused=$true
}
if([int]$env:CA_READY_DELAY){
 if(-not $refused -or $script:readyEvents){throw 'late readback passed'}
}elseif($refused -or $pidValue -ne 4001 -or $script:readyEvents -ne 1){throw 'ready readback failed'}
'PASS'
''', engine=engine, values={"CA_READY_DELAY": str(delay)})
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
def test_missing_native_integrity_field_mutation_fails_allow_oracle(tmp_path, engine, monkeypatch):
    native_run = run_functions
    def mutated(*args, **kwargs):
        kwargs['values']['CA_STOP_FIELD_MUTATION'] = '1'
        return native_run(*args, **kwargs)
    monkeypatch.setitem(globals(), 'run_functions', mutated)
    with pytest.raises(AssertionError):
        test_installer_ordinary_relay_stop_boundary(tmp_path, engine, 'normal')
