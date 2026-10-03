"""Exercise the parent's actual post-child receipt consumer, without elevation."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("tamper", (False, True))
def test_direct_child_receipt_is_consumed_from_bound_protected_run(tmp_path, engine, tamper):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", ["Sha", "Full"], r'''
$source=Get-Content -LiteralPath $env:CA_CONTRACT_SOURCE -Raw
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
foreach($name in @('Read-CanonicalHelperArtifact')) {
    foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)) {Invoke-Expression $node.Extent.Text}
}
function Same($a,$b) {return [IO.Path]::GetFullPath($a).Equals([IO.Path]::GetFullPath($b),'OrdinalIgnoreCase')}
function Sha($p) {return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Assert-InstallationEvidenceProtectedPath {}
function Assert-BootstrapNoReparsePoint {}
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'control')}
function ReadReplacementReceipt($Path) {return (Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json)}
$testMode=$false;$replaceExisting=$true
$run=Join-Path (Get-InstallationEvidenceControlRoot) ('installation-evidence/run-'+('a'*32))
$root=Join-Path $run 'helper-audit.evidence.1234'
[void][IO.Directory]::CreateDirectory($root)
$physical=Join-Path $root 'replacement-receipt.json'
$install=Join-Path $env:CA_CONTRACT_ROOT 'current';$rollback=Join-Path $env:CA_CONTRACT_ROOT 'old'
[void][IO.Directory]::CreateDirectory($install);[void][IO.Directory]::CreateDirectory($rollback)
[IO.File]::WriteAllText($physical,(@{receipt_path=$physical;rollback_root=$rollback}|ConvertTo-Json))
$digest=Sha $physical
[IO.File]::WriteAllText((Join-Path $root 'stages.jsonl'),(@{event='REPLACEMENT_RECEIPT_READY';path=$physical;sha256=$digest}|ConvertTo-Json -Compress)+"`n")
if($env:CA_RECEIPT_TAMPER -ceq '1'){[IO.File]::WriteAllText($physical,'{"forged":true}')}
$binding=@{status='BOUND_DIRECT_CHILD';stage_evidence_root=$root;helper_process_id=1234}
$replacementReceiptPath=Join-Path $env:CA_CONTRACT_ROOT 'caller-does-not-exist.json'
$replacementTransactionId='a'*32;$sourceManifest=@{};$sourceManifestSha256='';$sourceHelperSha256='';$sourceIntegrityHelperSha256=''
$audit=@{code_replacement=@{}};$codeRestoreNeeded=$false
# Select the real post-child consumer independently of surrounding entrypoints.
$anchor=$source.IndexOf('            $replacementReceiptSha256 = Sha $replacementReceiptPath')
$start=$source.LastIndexOf('        if ($replaceExisting) {',$anchor)
$end=$source.IndexOf('        else { $placement = ''PASS_NEW_VERIFIED'' }',$anchor)
if($start -lt 0 -or $end -le $start){throw 'post-child consumer missing'}
$failure=''
try {. ([scriptblock]::Create($source.Substring($start,$end-$start)))|Out-Null} catch {$failure=$_.Exception.Message}
if($env:CA_RECEIPT_TAMPER -ceq '1') {
    if(-not $failure){throw 'tampered protected receipt accepted'}
    if($codeRestoreNeeded){throw 'tampered receipt reached mutation admission'}
} else {
    if($failure){throw ('physical receipt not consumed: '+$failure)}
    if(-not(Same $replacementReceiptPath $physical) -or $replacementReceiptSha256 -cne $digest -or -not $codeRestoreNeeded){throw 'parent did not bind protected receipt'}
}
if(Test-Path -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'caller-does-not-exist.json')){throw 'caller copy unexpectedly required'}
'PASS'
''', engine=engine, values={"CA_RECEIPT_TAMPER": "1" if tamper else "0"})
    assert result.returncode == 0, result.stdout + result.stderr
