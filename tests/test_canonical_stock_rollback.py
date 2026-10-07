"""Rollback must use an installed reader, rather than uninstalled stock code."""
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SID = 'S-1-5-21-431-431-431-1001'


def _packet(root, *, installed):
    (root / 'app').mkdir(parents=True)
    (root / 'runtime').mkdir()
    # Only executable placement and native identity are adapted. The product's
    # real portable identity, owner resolution and G probes remain in use.
    driver = f'''import sys
from pathlib import Path
sys.path.insert(0, {str(ROOT)!r})
import storage_policy
storage_policy._persisted_data_root = lambda: None
from tools import register_container_audit_worker_pc as registration
registration._current_user_sid = lambda: {SID!r}
import data_generation_guard as guard
guard.__file__ = str(Path(__file__).with_name('data_generation_guard.py'))
from current_user_onboarding import onboarding_main
raise SystemExit(onboarding_main(sys.argv[2:]))
'''
    files = {
        'app/main.py': driver.encode(),
        'app/Container_Audit.py': b'CURRENT_VERSION = "v2.0.99"\n',
        'app/data_generation_guard.py': b'# authenticated fixture identity\n',
        'runtime/pythonw.exe': b'fixture metadata, never executed',
        'portable-manifest.json': json.dumps({
            'schema': 'container-audit-portable-tree-v1',
            'entrypoint': 'runtime/pythonw.exe app/main.py',
            'source_commit': 'a' * 40, 'source_tree': 'b' * 40,
            'version': 'v2.0.99',
        }).encode(),
    }
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    if installed:
        rows = [{'path': name, 'size': len(raw),
                 'sha256': hashlib.sha256(raw).hexdigest()}
                for name, raw in sorted(files.items())]
        aggregate = hashlib.sha256(''.join(
            f"{r['sha256']} {r['size']} {r['path']}\n" for r in rows).encode()).hexdigest()
        (root / 'bootstrap-integrity.json').write_text(json.dumps({
            'schema_version': 'container-audit-bootstrap-integrity-v1',
            'status': 'PASS', 'code_root': '.', 'file_count': len(rows),
            'files': rows, 'aggregate_sha256': aggregate,
        }), encoding='utf-8')


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('failure', ('child-failed', 'tls-exit70', 'verification-failed',
                                    'timeout', 'newer-generation', 'unknown-generation'))
def test_post_placement_stock_failure_preserves_exact_legacy_preimage(tmp_path, engine, failure):
    source = tmp_path / 'stock'
    install = tmp_path / 'apps/current'
    _packet(source, installed=False)
    _packet(install, installed=True)
    legacy = tmp_path / 'legacy'
    legacy.mkdir()
    (legacy / 'Container_Audit.exe').write_bytes(b'old executable\x00')
    (legacy / 'state.csv').write_bytes(b'original business rows\r\n')
    original = {p.name: p.read_bytes() for p in legacy.iterdir()}
    backup = tmp_path / 'legacy.backup'
    legacy.rename(backup)
    if failure.endswith('generation'):
        marker = tmp_path / 'data/data-generation.json'
        marker.parent.mkdir()
        if failure == 'unknown-generation':
            marker.write_text('{}', encoding='utf-8')
        else:
            from kmtech_shared import data_generation as generation
            generation.record_generation(marker, app_id='container_audit', subject_sid=SID,
                version='v99.0.0', build_id='a' * 40,
                data_compatible_min_version='v99.0.0', compatibility_verified=False)
    else:
        from kmtech_shared import data_generation as generation
        (tmp_path / 'data').mkdir()
        generation.record_generation(tmp_path / 'data/data-generation.json',
            app_id='container_audit', subject_sid=SID, version='v2.0.99',
            build_id='a' * 40, data_compatible_min_version='v2.0.99',
            compatibility_verified=False)
    immutable = {str(p.relative_to(tmp_path)): p.read_bytes()
                 for root in (source, install, backup, tmp_path / 'data') if root.exists()
                 for p in root.rglob('*') if p.is_file()}
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Restore-CanonicalApplicationProtection', 'Get-CanonicalOnboardingInputBinding', 'Product',
         'Get-CanonicalInstallationCommitPoint', 'Get-CanonicalRollbackSuccessStatus',
         'Get-CanonicalOperatorSecurity'], r'''
$script:observed=@{g=0;remove=0;restore=0;release=0}
$source=$env:CA_STOCK_ROOT;$install=Join-Path $env:CA_CONTRACT_ROOT 'apps/current'
$sourceManifest=Get-Content -LiteralPath (Join-Path $source 'portable-manifest.json') -Raw | ConvertFrom-Json
$operatorSid='S-1-5-21-431-431-431-1001'
$lad=Join-Path $env:CA_CONTRACT_ROOT 'local';$activeDataRoot=Join-Path $env:CA_CONTRACT_ROOT 'data'
$env:CONTAINER_AUDIT_DATA_ROOT=$activeDataRoot
$env:CONTAINER_AUDIT_WRITER_TEST_MODE='1'
$env:CONTAINER_AUDIT_WRITER_CONTROL_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'control'
$env:LOCALAPPDATA=$lad;$env:APPDATA=Join-Path $env:CA_CONTRACT_ROOT 'roaming'
$currentAbsentBeforePlacement=$true;$placement='PASS_NEW_VERIFIED';$existingVerified=$false
$before=@{exists=$false;kind='';data=''};$script:run=@{exists=$true;kind='String';data='isolated-new-command'}
$old=@();$mutated=$true;$enteredPlacementTry=$true
$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$testMode=$false;$retirementResume=$null;$codeRestoreNeeded=$false
$writerRestoreNeeded=$false;$legacyRelayRestoreNeeded=$false
$canonicalWriterFenceActive=$true;$canonicalWriterFenceAuthority='isolated-authority'
$audit=@{rollback=@{};scheduled_writer=@{};code_replacement=@{}}
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json';$evidenceFull=''
$stop=Join-Path $env:CA_CONTRACT_ROOT 'absent-stop'
$currentTreeInventorySha256='a'*64;$installedInventorySha256='a'*64
$rollbackCompleteAuthorizationPath='isolated-release'
$script:actualG=${function:Assert-ContainerDataGenerationTarget}
$script:actualCommitPoint=${function:Get-CanonicalInstallationCommitPoint}
function Get-CanonicalInstallationCommitPoint {
    param($Manifest,$TargetSid,$LocalAppDataRoot,$DataRoot,$HelperRoot)
    # The small packet omits shared libraries. Route to the real pinned reader
    # while retaining its actual marker/manifest classification and all checks.
    $PSBoundParameters.HelperRoot=Split-Path -Parent $env:CA_CONTRACT_SOURCE
    & $script:actualCommitPoint @PSBoundParameters
}
if($env:CA_STOCK_PRODUCT_INPUT){
    $productAst=[Management.Automation.Language.Parser]::ParseFile($env:CA_STOCK_PRODUCT_INPUT,[ref]$null,[ref]$null)
    $product=@($productAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Product'},$true))
    if($product.Count -ne 1){throw 'baseline Product function missing'}
    Invoke-Expression $product[0].Extent.Text
}
$script:actualProduct=${function:Product}
function Assert-ContainerDataGenerationTarget {
    param($CandidateRoot,$TargetSid,$LocalAppDataRoot,$DataRoot,$HelperRoot)
    $script:observed.g++
    $PSBoundParameters.HelperRoot=Split-Path -Parent $env:CA_CONTRACT_SOURCE
    & $script:actualG @PSBoundParameters
}
function Join-Path {param($Path,$ChildPath)
    if($ChildPath -ceq 'runtime\python.exe'){return $env:CA_STOCK_PYTHON}
    Microsoft.PowerShell.Management\Join-Path $Path $ChildPath
}
function Fail-InstallationEvidenceStages {}
function Set-InstallationEvidenceStage {}
function Save($Path,$Value,$SanitizeDiagnostics){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 25))}
function Get-CanonicalFailureDetails {return @{stage='INSTALL'}}
function Test-InstallationEvidencePrivileged {return $false}
function Assert-InstallationEvidenceProtectedPath($Path){if(-not(Test-Path -LiteralPath $Path)){throw 'ISOLATED_PARENT_ABSENT'}}
function Sync-CanonicalWriterFenceInventory {}
function Assert-RollbackRelayPreimage {param($ExpectedRelays)}
function Relays {return @()}
function Snapshot {return $script:run}
function Restore($Value){$script:observed.restore++;$script:run=$Value}
function Product($Root,$Mode){
    if($Mode -ceq '--remove-current-user-setup'){$script:observed.remove++;$script:run=$before;return}
    & $script:actualProduct $Root $Mode
}
function Invoke-InstallationEvidenceChild {
    param($Name,$Exe,$Arguments)
    $script:childReport=Join-Path $private 'onboarding-original.json'
    [IO.File]::WriteAllText($script:childReport,'isolated original onboarding diagnostic')
    $script:childDigest=Get-FileSha256 $script:childReport
    $exitCode=if($env:CA_STOCK_FAILURE -ceq 'tls-exit70'){70}else{4}
    $record=[ordered]@{status='FAILED';stage='onboarding';reason_code='INSTALLER_CHILD_FAILURE';
        exception_type='builtins.ValueError';exit_code=$exitCode;
        report_path=$script:childReport;report_sha256=$script:childDigest;
        location_module='current_user_onboarding';location_function='onboard_current_user';location_line=1958}
    return @{ExitCode=$exitCode;Stdout=('CONTAINER_AUDIT_INSTALLER_FAILURE='+($record|ConvertTo-Json -Compress));Stderr=''}
}
function New-CanonicalWriterFenceReleaseAuthorization {param($Path,$Phase,$AuditPath);return @{path='isolated';sha256=('a'*64)}}
function Set-CanonicalWriterFenceReleaseAuthorization {}
function Clear-CanonicalWriterFenceReleaseDelegation {}
function Stop-CanonicalWriterFenceRelease {$script:observed.release++}
function Write-CanonicalInstallationPublicRecord {}
$private=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'private') ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_STOCK_CANONICAL_INPUT,[ref]$null,[ref]$null)
$clauses=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true))
if($clauses.Count -ne 1){throw 'actual canonical catch missing'}
$injected=if($env:CA_STOCK_FAILURE -ceq 'timeout'){"throw [TimeoutException]::new('ISOLATED_POST_PLACEMENT_TIMEOUT')"}
    elseif($env:CA_STOCK_FAILURE -ceq 'verification-failed'){"throw [IO.InvalidDataException]::new('ISOLATED_POST_PLACEMENT_VERIFY_FAILED')"}
    elseif($env:CA_STOCK_FAILURE -cin @('child-failed','tls-exit70')){"Product `$install '--onboard-current-user'"}
    else{"throw [InvalidOperationException]::new('ISOLATED_POST_PLACEMENT_FAILURE')"}
try {. ([ScriptBlock]::Create('try {'+$injected+'} catch '+$clauses[0].Body.Extent.Text))}
catch {}
[ordered]@{status=$audit.status;steps=$audit.rollback.steps;runtime_restored=$audit.rollback.runtime_restored;
    fence_active=$canonicalWriterFenceActive;run=$script:run;observed=$script:observed;private_path=$private;
    child_report_path=$script:childReport;child_report_sha256=$script:childDigest}|ConvertTo-Json -Depth 25 -Compress
''', engine=engine, values={'CA_STOCK_ROOT': str(source), 'CA_STOCK_PYTHON': sys.executable,
                          'CA_STOCK_FAILURE': failure,
                          'CA_STOCK_CANONICAL_INPUT': os.environ.get('CA_STOCK_CANONICAL_INPUT',
                              str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'))})
    (tmp_path / 'stdout.txt').write_text(result.stdout, encoding='utf-8')
    (tmp_path / 'stderr.txt').write_text(result.stderr, encoding='utf-8')
    assert result.returncode == 0, 'isolated post-placement catch failed; inspect captured logs'
    observed = json.loads(result.stdout.splitlines()[-1])
    private_reports = list(Path(observed['private_path']).glob('original-failure-*.json'))
    assert private_reports, 'the original install failure must have a protected report'
    assert 'ISOLATED_POST_PLACEMENT' not in result.stdout + result.stderr
    if failure in ('child-failed', 'tls-exit70'):
        failures = [json.loads(p.read_bytes()) for p in private_reports]
        assert any('"location_line":1958' in str(d['failure']['exception_chain'])
                   for d in failures), 'retain the original ValueError location in the protected parent report'
        assert any(observed['child_report_sha256'] in str(d['failure']['exception_chain'])
                   for d in failures), 'retain the full child report pointer beyond the former 240-byte cut'
    assert observed['observed']['g'] == (0 if failure.endswith('generation') else 1)
    assert observed['run'] == {'exists': False, 'kind': '', 'data': ''}
    for name, raw in immutable.items():
        assert (tmp_path / name).read_bytes() == raw
    if failure.endswith('generation'):
        assert len(private_reports) >= 2, 'a recovery failure needs its own protected report'
        # Future or malformed G prevents code identity proof before reader
        # admission; retain the fence rather than inventing a G readback.
        assert observed['status'] == 'CODE_ROLLBACK_FAILED'
        assert observed['steps']['commit_point_readback']['failure_type'] == 'COMMIT_POINT_UNKNOWN'
        assert observed['fence_active'] is True
        assert observed['observed']['release'] == 0
        assert not legacy.exists() and backup.is_dir()
    else:
        assert observed['status'] == 'FAILED_RUNTIME_RESTORED_CODE_RETAINED'
        assert observed['steps']['generation_readback']['status'] == 'PASS'
        assert observed['runtime_restored'] is True
        assert observed['fence_active'] is False
        assert observed['observed']['release'] == 1
        backup.rename(legacy)
        assert {p.name: p.read_bytes() for p in legacy.iterdir()} == original
