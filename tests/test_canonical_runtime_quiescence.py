"""Old relay shutdown must finish before canonical code replacement.

Only the real replacement block runs; product/process/clock boundaries are
injected so these cases never start a relay or use the host registry.
"""
import os
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("CA_RUNTIME_INSTALLER_SOURCE", ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"))


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("scenario", ("exiting", "stuck", "foreign", "receipt", "marker", "query"))
def test_replacement_waits_for_exact_old_relay_exit_and_rejects_unproven_stop(tmp_path, engine, scenario):
    result = run_functions(tmp_path, SOURCE, ["Same", "Get-CanonicalRelayCommandIdentity"], r'''
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $definition.Extent.Text
    }
}
$blocks=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Clauses.Count -eq 1 -and $node.Clauses[0].Item1.Extent.Text -ceq '$replaceExisting' -and
    $node.Extent.Text.Contains('$runtimeQuiescedForReplacement = $true')
}, $true))
if ($blocks.Count -ne 1) { throw 'replacement block is ambiguous' }
$script:reads=0; $script:clock=0; $script:kills=0
$install=Join-Path $env:CA_CONTRACT_ROOT 'current'
$stop=Join-Path $env:CA_CONTRACT_ROOT 'stop.json'
$removalPath=Join-Path $env:CA_CONTRACT_ROOT 'removal.json'
$old=@([pscustomobject]@{
    ExecutablePath=(Join-Path $install 'runtime\pythonw.exe')
    CommandLine=((Join-Path $install 'runtime\pythonw.exe')+' -I -B '+(Join-Path $install 'app\main.py')+' --container-audit-user-relay')
})
$installedInventorySha256='a'*64
$runtimeQuiescedForReplacement=$false; $mutated=$false
$audit=[ordered]@{code_replacement=[ordered]@{status='NOT_STARTED'}}
$auditPath='unused'; $evidenceFull=''
function Sync-CanonicalWriterFenceInventory { }
function Product {
    $receipt=[ordered]@{
        status='PASS_DATA_PRESERVED'; data_preserved=$true
        relay_autostart=@{status='ABSENT'}
        relay_process=@{status='ABSENT';request_id=('a'*32);stop_request_path=$stop}
    }
    if ($env:CA_STOP_SCENARIO -ceq 'receipt') { $receipt.relay_process.status='UNKNOWN' }
    $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $removalPath -Encoding UTF8
    $marker=@{schema_version='container-audit-user-relay-stop-v1';request_id=('a'*32)}
    if ($env:CA_STOP_SCENARIO -ceq 'marker') { $marker.request_id='b'*32 }
    $marker | ConvertTo-Json | Set-Content -LiteralPath $stop -Encoding UTF8
}
function Snapshot { return @{exists=$false} }
function Save { }
function Stop-Process { $script:kills++; throw 'must not force an old relay to exit' }
function Start-Sleep { }
function Get-Date { $script:clock++; return ([DateTime]'2026-10-01T00:00:00Z').AddSeconds($script:clock) }
function Relays {
    $script:reads++
    if ($env:CA_STOP_SCENARIO -ceq 'query') { throw 'injected process query failure' }
    if ($env:CA_STOP_SCENARIO -ceq 'foreign') {
        return @([pscustomobject]@{ExecutablePath=$old[0].ExecutablePath;CommandLine=($old[0].CommandLine+' --foreign')})
    }
    if ($env:CA_STOP_SCENARIO -ceq 'stuck' -or $script:reads -eq 1) { return $old }
    return @()
}
$failure=''
try {
    $body=$blocks[0].Clauses[0].Item2.Extent.Text
    Invoke-Expression $body.Substring(1,$body.Length-2)
}
catch { $failure=$_.Exception.Message }
if ($env:CA_STOP_SCENARIO -ceq 'exiting') {
    if ($failure) { throw ('supported old relay exit rejected: '+$failure) }
    if (-not $runtimeQuiescedForReplacement -or $script:reads -lt 2) { throw 'process exit was not observed' }
} else {
    if (-not $failure -or $runtimeQuiescedForReplacement) { throw 'unproven stop accepted' }
}
if ($script:kills) { throw 'forced termination was attempted' }
'PASS'
''', values={"CA_STOP_SCENARIO": scenario}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
