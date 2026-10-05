"""Run the actual post-swap sequence with isolated files and native boundaries stubbed."""
import json
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("retry", (False, True))
def test_replacement_receipt_is_complete_before_startup_and_created_once(tmp_path, engine, retry):
    (tmp_path / "empty.ps1").write_text("", encoding="utf-8-sig")
    source = ROOT / "INSTALL_THIS_PC.ps1"
    names = re.findall(r"^function\s+([^\s(]+)", source.read_text(encoding="utf-8-sig"), re.M)
    result = run_functions(tmp_path, source, names, r'''
. $env:CA_RECEIPT_LIBRARY
function Set-InstallationEvidenceStage {}
function Complete-InstallationEvidenceStage {}
function Write-InstallationCaughtFailure {}
function Assert-ContainerStartupUpdateTrust {}
function Set-HardenedCodeAcl {}
function Assert-NoReparsePoint {}
function Assert-BootstrapIntegrityRecord {}
function Get-CodeInventory { return @() }
function Get-InventoryAggregate { return ('a'*64) }
function Get-ItemProperty { return [pscustomobject]@{HiberbootEnabled=0} }
function New-InstallationProtectedDirectory($Path,$Sid) { [void][IO.Directory]::CreateDirectory($Path) }
function Get-BootstrapReplacementTreeIdentity { return [pscustomobject]@{aggregate_sha256=('a'*64)} }
function Test-BootstrapReplacementTreeIdentity { return $true }
function Get-BootstrapAclIdentity { return [pscustomobject]@{owner_sid='S-1-5-32-544'} }
function Get-ContainerStartupUpdateTaskPreimage { return @{name=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24));exists=$false} }
function Get-ScheduledTask { return $null }
function Invoke-ContainerStartupUpdateTaskMutation($Action) { & $Action }
function Write-ContainerStartupUpdateRecord($Path,$Payload) {
    if((Split-Path -Leaf $Path) -ceq 'preimage.json') {
        $script:saves++
        [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 12))
        return
    }
    $early=Read-BootstrapReplacementReceipt $replacementReceipt.path $replacementReceipt.sha256
    $script:completeBeforeMutation=$script:completeBeforeMutation -and
        ([string]$early.startup_update_preimage -ceq [string]$Script:StartupUpdatePreimage.path) -and
        ([string]$early.startup_update_preimage_sha256 -ceq [string]$Script:StartupUpdatePreimage.sha256)
    [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 12))
}
function Get-ContainerStartupUpdateTaskSpec { return [pscustomobject]@{name='isolated-native-boundary';xml='<Task/>'} }
function Get-InstallationVerifiedScript { return $env:CA_RECEIPT_EMPTY_SCRIPT }
function Invoke-ContainerWriterFenceMutation {
    param($ControlRoot,$SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken,$Action)
    if($env:CA_RECEIPT_RETRY -ceq '1' -and $run -eq 0){throw 'injected startup failure'}
}
$source=Get-Content -LiteralPath $env:CA_CONTRACT_SOURCE -Raw
$start=$source.IndexOf('    $replacementReceipt = $null')
$end=$source.IndexOf("    Set-InstallationEvidenceStage 'placement.tls_bootstrap'",$start)
if($start -lt 0 -or $end -le $start){throw 'post-swap sequence missing'}
$sequence=[scriptblock]::Create($source.Substring($start,$end-$start))
$applicationParent=Join-Path $env:CA_CONTRACT_ROOT 'managed'
$installRootFull=Join-Path $applicationParent 'current'
[void][IO.Directory]::CreateDirectory((Join-Path $installRootFull 'app'))
[IO.File]::WriteAllText((Join-Path $installRootFull 'app/auto-update-settings.json'),'{"apply_during_work":false,"profile_auth":false,"approved_transitions":[]}')
[IO.File]::WriteAllText((Join-Path $installRootFull 'portable-manifest.json'),'{"source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","startup_update_protocol":1}')
[void][IO.Directory]::CreateDirectory((Join-Path $applicationParent ('versions/'+('a'*40))))
$OperatorSid='S-1-5-21-111-222-333-1001';$OperatorLocalAppDataRoot=Join-Path $env:CA_CONTRACT_ROOT 'operator'
$WriterFenceHelperPath=$env:CA_RECEIPT_EMPTY_SCRIPT;$BootstrapScriptPath=$WriterFenceHelperPath;$BootstrapIntegrityFunctions=$env:CA_RECEIPT_LIBRARY
$replacementApplied=$true;$previousReplacementIdentity=[pscustomobject]@{};$sourceAggregate='a'*64
$testOverride=$false;$aclReadbackStatus='NOT_TESTED';$IntegrityFileName='integrity.json'
$RestoreUninstallRecordPath='';$saves=0;$completeBeforeMutation=$true;$results=@()
$attempts=if($env:CA_RECEIPT_RETRY -ceq '1'){2}else{1}
$preservedPath='';$preservedHash=''
for($run=0;$run -lt $attempts;$run++) {
    $ReplacementTransactionId=[guid]::NewGuid().ToString('N');$WriterFenceAttemptId=[guid]::NewGuid().ToString('N')
    $replacementRollbackRoot=Join-Path $applicationParent ('.current.rollback.'+$ReplacementTransactionId)
    $replacementReceiptFull=Join-Path $env:CA_CONTRACT_ROOT ('run-'+$WriterFenceAttemptId+'/replacement-receipt.json')
    # Privileged placement relocates the caller path into its protected run.
    $BootstrapBoundParameters=@{ReplacementReceiptPath=(Join-Path $env:CA_CONTRACT_ROOT ('caller-run-'+$WriterFenceAttemptId+'/receipt.json'))}
    $Script:StartupUpdatePreimage=$null
    try { . $sequence | Out-Null }
    catch {
        if($env:CA_RECEIPT_RETRY -cne '1' -or $run -ne 0 -or $_.Exception.Message -cne 'injected startup failure'){throw}
        Restore-ContainerStartupUpdatePreimage $installRootFull $Script:StartupUpdatePreimage.path $Script:StartupUpdatePreimage.sha256
        foreach($name in @('policy.json','active.json','transition.json')) {
            if(Test-Path -LiteralPath (Join-Path $applicationParent ('update-control/'+$name))){throw 'startup rollback differed'}
        }
    }
    $saved=Read-BootstrapReplacementReceipt $replacementReceipt.path $replacementReceipt.sha256
    if(-not(Test-BootstrapSamePath $saved.receipt_path $BootstrapBoundParameters['ReplacementReceiptPath'])){throw 'caller/export receipt path differs'}
    if([string]$saved.startup_update_preimage -cne [string]$Script:StartupUpdatePreimage.path){throw 'preimage binding differs'}
    if($saves -ne ($run+1)){throw 'preimage must be captured once per run'}
    if(-not $completeBeforeMutation){throw 'receipt was incomplete before startup mutation'}
    if($preservedPath -and (Get-FileSha256 $preservedPath) -cne $preservedHash){throw 'prior receipt changed'}
    $results+=@{transaction=$ReplacementTransactionId;receipt=$replacementReceipt.path;sha256=$replacementReceipt.sha256}
    if($run -eq 0 -and $attempts -eq 2) {
        # Keep failed-run evidence while the next run uses its own admitted path.
        $preservedPath=$replacementReceipt.path;$preservedHash=$replacementReceipt.sha256
    }
}
@{attempts=$attempts;saves=$saves;complete_before_mutation=$completeBeforeMutation;receipts=$results}|ConvertTo-Json -Depth 5 -Compress
''', engine=engine, values={"CA_RECEIPT_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"),
                           "CA_RECEIPT_EMPTY_SCRIPT": str(tmp_path / "empty.ps1"),
                           "CA_RECEIPT_RETRY": "1" if retry else "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    value = json.loads(result.stdout)
    assert value["attempts"] == value["saves"] == (2 if retry else 1)
    assert value["complete_before_mutation"] is True


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_existing_or_tampered_receipt_remains_rejected(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Write-BootstrapReplacementReceipt"], r'''
. $env:CA_RECEIPT_LIBRARY
$path=Join-Path $env:CA_CONTRACT_ROOT 'receipt.json'
$receipt=Write-BootstrapReplacementReceipt $path @{original='retained'}
try { Write-BootstrapReplacementReceipt $path @{forged='overwrite'}; throw 'overwrite was accepted' }
catch { if($_.Exception.Message -cne 'Replacement receipt path already exists.'){throw} }
if((Get-FileSha256 $path) -cne $receipt.sha256){throw 'existing receipt changed'}
[IO.File]::WriteAllText($path,'{"forged":"valid JSON"}')
try { Read-BootstrapReplacementReceipt $path $receipt.sha256; throw 'forgery was accepted' }
catch { if($_.Exception.Message -cne 'Replacement receipt SHA-256 differs.'){throw} }
'guards-retained'
''', engine=engine, values={"CA_RECEIPT_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1")})
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "guards-retained"
