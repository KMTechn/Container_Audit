"""Execute the production rollback catch after an isolated placement cancellation."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('stage', ('before-placement', 'elevation-cancelled',
    'placement-failed', 'placed-before-onboarding', 'onboarding-failed',
    'existing-current-missing', 'orphaned-run', 'orphaned-relay', 'run-restore-failed'))
def test_placement_failure_restores_absent_current_preimage(tmp_path, engine, stage):
    legacy = tmp_path / 'legacy'
    legacy.mkdir()
    (legacy / 'Container_Audit.exe').write_bytes(b'isolated old executable bytes\x00')
    (legacy / 'state.csv').write_bytes(b'preserved old state\r\n')
    before = {p.name: p.read_bytes() for p in legacy.iterdir()}
    backup = tmp_path / 'legacy.backup'
    legacy.rename(backup)
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Restore-CanonicalApplicationProtection'], r'''
$script:observed=@{g=0;reader=0;remove=0;restore=0;release=0;elevation=0;transport_cleanup=0;parent_repair=0}
$install=Join-Path $env:CA_CONTRACT_ROOT 'apps/current'
$source=Split-Path -Parent $env:CA_CONTRACT_SOURCE
$operatorSid='S-1-5-21-420-420-420-1001'
$lad=Join-Path $env:CA_CONTRACT_ROOT 'local'
$activeDataRoot=Join-Path $env:CA_CONTRACT_ROOT 'data'
$stage=$env:CA_ROLLBACK_STAGE
$currentAbsentBeforePlacement=($stage -cne 'existing-current-missing')
$placement='INSTALL_REQUIRED';$existingVerified=(-not $currentAbsentBeforePlacement)
$before=@{exists=$false;kind='';data=''};$script:run=$before
$old=@();$mutated=$stage -cin @('onboarding-failed','run-restore-failed')
if($stage -ceq 'orphaned-run'){$before=@{exists=$true;kind='String';data='isolated-old-command'};$script:run=$before}
if($stage -ceq 'orphaned-relay'){$old=@(@{ProcessId=420;ExecutablePath='isolated-old-executable';CommandLine='isolated-old-command'})}
$enteredPlacementTry=$true;$Uninstall=$false;$RestoreVerifiedReplacement=$false
$CompleteRetiredRemoval=$false;$testMode=$false;$retirementResume=$null
$codeRestoreNeeded=$false;$writerRestoreNeeded=$false;$legacyRelayRestoreNeeded=$false
$canonicalWriterFenceActive=$true;$canonicalWriterFenceAuthority='isolated-authority'
$audit=@{rollback=@{};scheduled_writer=@{};code_replacement=@{failure_code='CONTAINER_PLACEMENT_ELEVATION_FAILED'}}
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json';$evidenceFull=''
$stop=Join-Path $env:CA_CONTRACT_ROOT 'absent-stop'
$currentTreeInventorySha256='a'*64;$installedInventorySha256='a'*64
$rollbackCompleteAuthorizationPath='isolated-release'
if($stage -cin @('placed-before-onboarding','onboarding-failed')){
    [void][IO.Directory]::CreateDirectory($install)
    [IO.File]::WriteAllText((Join-Path $install 'portable-manifest.json'),'{}')
    $placement='PASS_NEW_VERIFIED'
}
if($stage -ceq 'placement-failed'){[void][IO.Directory]::CreateDirectory((Split-Path -Parent $install))}
if($mutated){$script:run=@{exists=$true;kind='String';data='isolated-new-command'}}
function Write-InstallationCaughtFailure {}
function Fail-InstallationEvidenceStages {}
function Set-InstallationEvidenceStage {}
function Save($Path,$Value,$SanitizeDiagnostics){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 20))}
function Get-CanonicalFailureDetails {return @{stage='INSTALL'}}
function Get-InstallationFailureDetails {return @{exception_type='RuntimeException'}}
function Test-InstallationEvidencePrivileged {return $false}
function Assert-InstallationEvidenceProtectedPath($Path){if(-not(Test-Path -LiteralPath $Path)){throw 'ISOLATED_PARENT_ABSENT'}}
function Invoke-InstallationElevationCapture {$script:observed.parent_repair++;throw 'UNEXPECTED_PARENT_ELEVATION'}
function Sync-CanonicalWriterFenceInventory {}
function Assert-RollbackRelayPreimage {param($ExpectedRelays)}
function Relays {return @()}
function Snapshot {return $script:run}
function Restore($Value){$script:observed.restore++;if($stage -ceq 'run-restore-failed'){throw 'ISOLATED_RUN_RESTORE_FAILED'};$script:run=$Value}
function Product($Root,$Mode){$script:observed.remove++;if(-not(Test-Path -LiteralPath $Root)){throw 'ISOLATED_PRODUCT_ABSENT'};$script:run=$before}
function Assert-ContainerDataGenerationTarget {
    param($CandidateRoot,$TargetSid,$LocalAppDataRoot,$DataRoot,$HelperRoot)
    $script:observed.g++
    if(-not(Test-Path -LiteralPath $CandidateRoot)){throw 'ISOLATED_CURRENT_G_ABSENT'}
}
function Get-CanonicalOnboardingInputBinding($Producer,$Target){$script:observed.reader++;if(-not(Test-Path -LiteralPath $Target)){throw 'ISOLATED_CURRENT_READER_ABSENT'};return @{}}
function New-CanonicalWriterFenceReleaseAuthorization {param($Path,$Phase,$AuditPath);return @{path='isolated';sha256=('a'*64)}}
function Set-CanonicalWriterFenceReleaseAuthorization {}
function Clear-CanonicalWriterFenceReleaseDelegation {}
function Stop-CanonicalWriterFenceRelease {$script:observed.release++}
function ConvertTo-KmtechRedactedSinkText {param($Text,[switch]$UserLine);return $Text}
function Write-CanonicalInstallationPublicRecord {}
if($stage -ceq 'elevation-cancelled'){
    $bootstrapAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $source 'tools/bootstrap_integrity.ps1'),[ref]$null,[ref]$null)
    $capture=@($bootstrapAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-InstallationElevationCapture'},$true))
    if($capture.Count -ne 1){throw 'actual elevation capture missing'}
    Invoke-Expression $capture[0].Extent.Text
    $Script:InstallationEvidenceRoot=$env:CA_CONTRACT_ROOT
    function Get-InstallationEvidenceControlRoot {return Join-Path $env:CA_CONTRACT_ROOT 'control'}
    function Assert-BootstrapNoReparsePoint {}
    function Get-FileSha256 {return ('a'*64)}
    function Get-InstallationElevationWrapperSource {return '# isolated wrapper'}
    function New-InstallationMemoryTransport {return @{Encoded='isolated';Paths=@()}}
    function Remove-InstallationMemoryTransport {$script:observed.transport_cleanup++}
    function ConvertTo-BootstrapRelayArgument($Value){return $Value}
    function Start-Process {
        param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
        if($Verb -cne 'RunAs' -or $WindowStyle -cne 'Hidden'){throw 'elevation boundary changed'}
        $script:observed.elevation++
        throw [InvalidOperationException]::new('ISOLATED_USER_CANCELLED_ELEVATION')
    }
    # The admission ancestor double represents an already checked isolated base.
    function Assert-InstallationEvidenceProtectedPath {}
    try {Invoke-InstallationElevationCapture -Target (Join-Path $source 'INSTALL_THIS_PC.ps1') -Arguments @('-isolated') -AuditBase 'isolated-audit' -OperatorSid $operatorSid;throw 'cancellation seam not reached'}
    catch {$script:cancellation=$_}
    if($script:observed.elevation -ne 1){throw 'RunAs cancellation seam not reached'}
}
$clauses=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true))
if($clauses.Count -ne 1){throw 'actual canonical catch missing'}
$failureType=''
try {. ([ScriptBlock]::Create("try {throw [InvalidOperationException]::new('CONTAINER_PLACEMENT_ELEVATION_FAILED')} catch "+$clauses[0].Body.Extent.Text))}
catch {$failureType=$_.Exception.GetType().Name}
[ordered]@{status=$audit.status;steps=$audit.rollback.steps;runtime_restored=$audit.rollback.runtime_restored;
    fence_active=$canonicalWriterFenceActive;run_restored=([bool]$script:run.exists -eq [bool]$before.exists);
    observed=$script:observed;failure_type=$failureType;app_protection_failed=$audit.rollback.Contains('app_protection_failure')}|ConvertTo-Json -Depth 20 -Compress
''', engine=engine, values={'CA_ROLLBACK_STAGE': stage})
    assert result.returncode == 0, 'isolated rollback probe failed; inspect captured result'
    observed = json.loads(result.stdout.splitlines()[-1])
    (tmp_path / 'observed.json').write_text(json.dumps(observed, indent=2), encoding='utf-8')
    if stage in ('existing-current-missing', 'orphaned-run', 'orphaned-relay', 'run-restore-failed'):
        assert observed['status'] == 'AUTOSTART_ROLLBACK_FAILED'
        assert observed['fence_active'] is True
        assert observed['observed']['release'] == 0
        assert observed['steps']['recovery_identity']['status'] == 'UNPROVEN'
        if stage != 'run-restore-failed':
            assert observed['observed']['g'] == 1
            assert observed['steps']['generation_readback']['status'] == 'FAILED'
        assert not legacy.exists() and backup.is_dir()
        return
    expected = ('FAILED_RUNTIME_RESTORED_CODE_RETAINED' if stage in
                ('placed-before-onboarding', 'onboarding-failed') else 'FAILED_ROLLED_BACK')
    assert observed['status'] == expected
    assert observed['fence_active'] is False
    assert observed['runtime_restored'] is True
    assert observed['run_restored'] is True
    assert observed['observed']['release'] == 1
    assert observed['app_protection_failed'] is False
    if expected == 'FAILED_ROLLED_BACK':
        assert observed['steps']['generation_readback']['status'] == 'NOT_APPLICABLE_NO_CURRENT'
        assert observed['observed']['g'] == observed['observed']['reader'] == 0
        assert observed['observed']['parent_repair'] == 0
    else:
        assert observed['steps']['generation_readback']['status'] == 'PASS'
        assert observed['observed']['g'] == observed['observed']['reader'] == 1
    if stage == 'elevation-cancelled':
        assert observed['observed']['elevation'] == observed['observed']['transport_cleanup'] == 1
    # Model the outer legacy wrapper's restore only after canonical recovery is
    # proven. Keep both originals on refusal, and compare every old file byte.
    backup.rename(legacy)
    assert {p.name: p.read_bytes() for p in legacy.iterdir()} == before
    assert (legacy / 'Container_Audit.exe').is_file()


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_owned_parent_repair_without_current_binds_only_authenticated_source(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / 'tools/bootstrap_integrity.ps1',
        ['Read-InstallationOwnedParentRepair'], r'''
$sid='S-1-5-21-420-420-420-1001'
$local=Join-Path $env:CA_CONTRACT_ROOT 'local'
$current='C:\KMTech\Apps\Container_Audit\current'
$script:ContainerWriterFenceAcceptedInstalledInventorySha256='saved-acceptance'
$script:OwnedRepairManifestSha256='d'*64
$manifest=@{installer_sha256=('a'*64);writer_session_contract_sha256=('b'*64);writer_sink_inventory_contract_sha256=('c'*64)}
function Test-BootstrapSamePath($Left,$Right){return $Left -ceq $Right}
function Get-ContainerWriterFenceProfileLocalAppDataRoot {return $local}
function Get-BootstrapRelaySecurity {return @{sid=$sid;elevated=$false;integrity_level=8192;session_id=1}}
function Assert-BootstrapNoReparsePoint {}
function ConvertFrom-ContainerWriterFenceJson {param([Parameter(ValueFromPipeline=$true)]$Text);process {return $Text|ConvertFrom-Json}}
function Test-Path {
    param($LiteralPath,$ErrorAction)
    if($LiteralPath -cne $current){throw 'unexpected existence probe'}
    if($script:case -ceq 'probe-error'){throw [IO.IOException]::new('ISOLATED_EXISTENCE_UNPROVEN')}
    return $script:case -cin @('installed','installed-no-manifest')
}
function Get-Content {
    param($LiteralPath,[switch]$Raw,$Encoding)
    if($LiteralPath -ceq (Join-Path $current 'portable-manifest.json')){
        $script:manifestReads++
        if($script:case -ceq 'installed-no-manifest'){throw 'ISOLATED_MANIFEST_ABSENT'}
        return (@{writer_sink_inventory_contract_sha256=('e'*64)}|ConvertTo-Json)
    }
    if($LiteralPath.EndsWith('active.json')){
        return (@{orchestrator_sha256=if($script:case -ceq 'wrong-source'){'f'*64}else{'a'*64};
            writer_contract_sha256=('b'*64);writer_inventory_sha256=if($script:case -ceq 'installed'){'e'*64}elseif($script:case -ceq 'foreign-inventory'){'e'*64}elseif($script:case -ceq 'empty-inventory'){''}else{'c'*64}}|ConvertTo-Json)
    }
    if($LiteralPath -ceq 'isolated-prepared'){
        return (@{operator_sid=$sid;source_manifest_sha256=if($script:case -ceq 'wrong-prepared'){'f'*64}else{'d'*64}}|ConvertTo-Json)
    }
    throw 'unexpected manifest/profile read'
}
function Read-ContainerWriterFence {
    $script:fenceReads++
    $expected=if($script:case -ceq 'installed'){'e'*64}else{''}
    if($script:ContainerWriterFenceAcceptedInstalledInventorySha256 -cne $expected){throw 'installed inventory acceptance differs'}
    return @{status='INSTALLING';owner_kind='canonical_installer';prepared_receipt_path='isolated-prepared'}
}
$results=@()
foreach($script:case in @('absent','installed','installed-no-manifest','foreign-inventory','empty-inventory','probe-error','wrong-source','wrong-prepared')){
    $script:manifestReads=0;$script:fenceReads=0;$allowed=$false
    try {$record=Read-InstallationOwnedParentRepair $current $local $sid 420 $manifest;$allowed=($null -ne $record.active)}catch{}
    $results+=@{case=$script:case;allowed=$allowed;manifest_reads=$script:manifestReads;fence_reads=$script:fenceReads;
        acceptance_restored=($script:ContainerWriterFenceAcceptedInstalledInventorySha256 -ceq 'saved-acceptance')}
}
$results|ConvertTo-Json -Compress
''', engine=engine)
    assert result.returncode == 0, 'isolated owned-repair probe failed'
    rows = {row['case']: row for row in json.loads(result.stdout.splitlines()[-1])}
    assert {case for case, row in rows.items() if row['allowed']} == {'absent', 'installed'}
    assert rows['absent']['manifest_reads'] == 0
    assert rows['absent']['fence_reads'] == 1
    assert rows['installed']['manifest_reads'] == 1
    assert rows['installed-no-manifest']['fence_reads'] == 0
    assert rows['foreign-inventory']['manifest_reads'] == rows['foreign-inventory']['fence_reads'] == 0
    assert all(row['acceptance_restored'] for row in rows.values())


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_cancelled_placement_public_status_requires_proven_recovery(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Write-CanonicalInstallationPublicRecord'], r'''
$audit=@{status='FAILED_ROLLED_BACK';rollback=@{runtime_restored=$true};code_replacement=@{failure_code='CONTAINER_PLACEMENT_ELEVATION_FAILED'}}
$canonicalWriterFenceActive=$false
Write-CanonicalInstallationPublicRecord -ExitCode 1
$canonicalWriterFenceActive=$true
Write-CanonicalInstallationPublicRecord -ExitCode 1
''', engine=engine)
    assert result.returncode == 0, 'isolated public status probe failed'
    rows = [json.loads(line.split('=', 1)[1]) for line in result.stdout.splitlines()
            if line.startswith('CONTAINER_AUDIT_INSTALL_CANONICAL=')]
    assert len(rows) == 2
    assert rows[0]['status'] == 'FAILED' and rows[0]['exit_code'] == 1
    assert rows[0]['reason_code'] == 'CONTAINER_PLACEMENT_ELEVATION_FAILED'
    assert rows[0]['install_status'] == 'FAILED_ROLLED_BACK'
    assert rows[0]['runtime_restored'] is True
    assert rows[1]['reason_code'] == 'INSTALLER_CANONICAL_FAILURE'
    assert 'install_status' not in rows[1] and 'runtime_restored' not in rows[1]
    assert all('public_record_code' not in row for row in rows)
