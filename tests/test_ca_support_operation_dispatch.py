"""Execute both real top-level worker guards, stopping immediately after them."""
from pathlib import Path
import shutil
import json

import pytest

from tests.powershell_contracts import run_powershell
from tests.test_canonical_portable_uninstall import _setup
from tests.test_canonical_installation_callers import _bind_packet

MACHINE_GATE = "if ($null -ne $machineWorker) { Assert-CanonicalOperatingWorkerAccount $canonicalOperation }"
USER_GATE = "Assert-CanonicalOperatingWorkerAccount $canonicalOperation ([bool]$rollbackContinuation)"

PRELUDE = r'''
$testMode=$false
$SkipSignatureValidationForTest=$false
$CanonicalRoot=$InstallRoot
# Signature transport for the fixture's non-executable PE doubles.
function Get-AuthenticodeSignature {return [pscustomobject]@{Status='Valid'}}
$Script:DispatchCaughtOriginal=(Get-Command Write-InstallationCaughtFailure).ScriptBlock
$Script:DispatchCaughtRows=@()
function Write-DispatchFailureMetadata($Failure){
 $cause=$Failure.Exception;$worker=$false
 for($depth=0;$null -ne $cause -and $depth -lt 12;$depth++){
  if($cause.Message.Contains('WorkerAccount')){$worker=$true}
  $cause=$cause.InnerException
 }
 $row=[ordered]@{line=[int]$Failure.InvocationInfo.ScriptLineNumber;type=$Failure.Exception.GetType().FullName;worker_requirement=$worker;
  stack_lines=@([regex]::Matches([string]$Failure.ScriptStackTrace,': line (\d+)')|ForEach-Object {[int]$_.Groups[1].Value})}
 $Script:DispatchCaughtRows+=@($row)
 [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'dispatch-native-failure.json'),(ConvertTo-Json -InputObject @($Script:DispatchCaughtRows) -Depth 8))
}
function Write-InstallationCaughtFailure($Failure){
 Write-DispatchFailureMetadata $Failure
 & $Script:DispatchCaughtOriginal $Failure
}
$Script:DispatchMachinePublicOriginal=(Get-Command Write-CanonicalMachinePublicRecord).ScriptBlock
function Write-CanonicalMachinePublicRecord([string]$Code,[string]$Status='FAILED',$Failure=(Get-Variable -Name outputFailure -ValueOnly -ErrorAction SilentlyContinue)){
 if($null -ne $Failure){Write-DispatchFailureMetadata $Failure}
 & $Script:DispatchMachinePublicOriginal $Code $Status $Failure
}
function Get-CanonicalInstallationCallerSecurity {
 return [pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session_id=1;elevated=$false}
}
if($env:CA_GUARD_BRANCH -ceq 'machine'){
 function Resolve-CanonicalMachineWorker {
  return [pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;profile_root=$env:USERPROFILE;same_caller=$true}
 }
}
function Write-DispatchBoundary {
 if($testMode -or $PlanOnly -or $SkipSignatureValidationForTest){throw 'production flags required'}
 $value=$canonicalOperation
 if($env:CA_GUARD_OPERATION -ceq 'CONTINUATION'){
  if($null -eq $rollbackContinuation -or $rollbackContinuation.state -cne 'PENDING' -or
    (Sha $rollbackContinuation.record_path) -cne $rollbackContinuation.record_sha256){throw 'verified continuation required'}
  $value='CONTINUATION'
 }
 [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'dispatch-after-guard.txt'),$value)
 exit 23
}
'''

# Real journal/receipt/tree readers run; only protected-store ACL policy is a
# fixture boundary. No native ProgramData store or installation is changed.
CONTINUATION_FIXTURE = r'''
if($env:CA_GUARD_OPERATION -ceq 'CONTINUATION'){
 # The fence dot-source reloads bootstrap functions; bind its store after loading.
 function Get-InstallationEvidenceControlRoot {return Join-Path $env:CA_UNINSTALL_ROOT 'continuation-control'}
 function Assert-InstallationEvidenceProtectedPath([string]$Path){
  if(-not (Full $Path 'fixture protected path').StartsWith((Full $env:CA_UNINSTALL_ROOT 'fixture root')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'fixture protected path escaped'}
  Assert-BootstrapNoReparsePoint $Path 'fixture protected path' -PathOnly
 }
 $tx='0123456789abcdef0123456789abcdef'
 $parent=Split-Path -Parent $install
 $rollback=Join-Path $parent ('.current.rollback.'+$tx)
 $failed=Join-Path $parent ('.current.failed.'+$tx)
 [void](Write-BootstrapIntegrityRecord $install $install)
 $null=Copy-Item -LiteralPath $install -Destination $rollback -Recurse
 $oldManifestPath=Join-Path $rollback 'portable-manifest.json'
 $oldManifest=Get-Content -LiteralPath $oldManifestPath -Raw -Encoding UTF8|ConvertFrom-Json
 $oldManifest.source_commit='1111111111111111111111111111111111111111'
 [IO.File]::WriteAllText($oldManifestPath,($oldManifest|ConvertTo-Json -Depth 24),[Text.UTF8Encoding]::new($false))
 [void](Write-BootstrapIntegrityRecord $rollback $install)
 $control=Get-InstallationEvidenceControlRoot
 if(-not (Full $control 'fixture control').StartsWith((Full $env:CA_UNINSTALL_ROOT 'fixture root')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'continuation control escaped fixture'}
 $journalDirectory=Join-Path (Join-Path $control 'rollback-continuations') $tx
 [void][IO.Directory]::CreateDirectory($journalDirectory)
 $physical=Join-Path $journalDirectory 'replacement-receipt.json'
 $binding=Join-Path (Join-Path (Join-Path (Join-Path $control 'installation-evidence') ('run-'+$tx)) 'child') 'replacement-receipt.json'
 $receipt=[ordered]@{
  schema_version='container-audit-verified-replacement-v1';status='OLD_PRESERVED_NEW_VERIFIED';app_id='container_audit';
  transaction_id=$tx;created_at='2000-01-01T00:00:00Z';helper_sha256=$sourceHelperSha256;
  integrity_helper_sha256=$sourceIntegrityHelperSha256;receipt_path=$binding;install_root=$install;install_parent=$parent;
  rollback_root=$rollback;failed_root=$failed;parent_acl=(Get-BootstrapAclIdentity $parent);
  old=(Get-BootstrapReplacementTreeIdentity $rollback $install);new=(Get-BootstrapReplacementTreeIdentity $install $install);
  identity_or_credential_copied=$false
 }
 [IO.File]::WriteAllText($physical,($receipt|ConvertTo-Json -Depth 32),[Text.UTF8Encoding]::new($false))
 $record=[ordered]@{
  schema='container-audit-rollback-continuation-v1';event='ROLLBACK_CONTINUATION';install_root=$install;
  operator_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;operator_local_appdata_root=$env:LOCALAPPDATA;
  owner_process_id=2147483647;owner_started_at_utc='2000-01-01T00:00:00Z';session_id=$tx;attempt_id=$tx;
  orchestrator_sha256=(Sha (Join-Path $source 'INSTALL_CANONICAL_PORTABLE.ps1'));
  writer_contract_sha256=(Sha (Join-Path $source 'tools\container_writer_session_contract.json'));
  source_manifest_sha256=$sourceManifestSha256;receipt_path=$physical;receipt_binding_path=$binding;receipt_sha256=(Sha $physical);
  old_manifest_sha256=$receipt.old.manifest_sha256;new_manifest_sha256=$receipt.new.manifest_sha256;transaction_id=$tx;
  preimage=[ordered]@{exists=$false;kind='';data=''};relay_count=0;original_relays=@();
  runtime_preimage_binding=[ordered]@{status='PASS';relay_count=0};original_audit_sha256=('2'*64);secret_values_recorded=$false
 }
 [IO.File]::WriteAllText((Join-Path $journalDirectory 'continuation-journal.json'),($record|ConvertTo-Json -Depth 32),[Text.UTF8Encoding]::new($false))
}
'''


def _probe(tmp_path, engine, branch, operation, mutation=None):
    assert "Assert-CanonicalOperatingWorkerAccount" not in PRELUDE + CONTINUATION_FIXTURE
    env, source, install, _ = _setup(tmp_path, install_directory="current")
    env.update(CA_GUARD_BRANCH=branch, CA_GUARD_OPERATION=operation)
    canonical = source / "INSTALL_CANONICAL_PORTABLE.ps1"
    text = canonical.read_text(encoding="utf-8-sig")
    anchor = "try {\nif (-not $SourceRoot) { $SourceRoot = $PSScriptRoot }"
    assert text.count(anchor) == 1
    assert text.count(MACHINE_GATE) == text.count(USER_GATE) == 1
    text = text.replace(anchor, PRELUDE + anchor)
    reader_start = text.index("function Read-CanonicalRollbackContinuation(")
    reader_end = text.index("\nfunction Write-CanonicalRollbackContinuation", reader_start)
    reader = text[reader_start:reader_end]
    assert reader.count("(Get-InstallationEvidenceControlRoot)") == 2
    # Bind only storage location; the actual journal/receipt/tree checks remain.
    reader = reader.replace("(Get-InstallationEvidenceControlRoot)",
                            "(Join-Path $env:CA_UNINSTALL_ROOT 'continuation-control')")
    text = text[:reader_start] + reader + text[reader_end:]
    store_anchor = "$store=Join-Path (Join-Path $env:CA_UNINSTALL_ROOT 'continuation-control') 'rollback-continuations'"
    assert text.count(store_anchor) == 1
    text = text.replace(store_anchor, store_anchor + r"""
    if($env:CA_GUARD_OPERATION -ceq 'CONTINUATION'){
        $proof=[ordered]@{entered=$true;store_exists=[bool](Test-Path -LiteralPath $store -PathType Container);
            store_in_fixture=([IO.Path]::GetFullPath($store).StartsWith([IO.Path]::GetFullPath($env:CA_UNINSTALL_ROOT)+'\',[StringComparison]::OrdinalIgnoreCase))}
        [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'continuation-reader-proof.json'),($proof|ConvertTo-Json))
    }
""")
    if branch == "machine":
        gate = MACHINE_GATE
        marker = "if ($null -ne $machineWorker) { Write-DispatchBoundary }"
    else:
        gate = USER_GATE
        marker = "Write-DispatchBoundary"
    replacement = gate
    if mutation == "force_install":
        replacement = ("if ($null -ne $machineWorker) { Assert-CanonicalOperatingWorkerAccount 'INSTALL' }"
                       if branch == "machine" else USER_GATE.replace("$canonicalOperation", "'INSTALL'"))
    elif mutation == "remove_call":
        replacement = "# mutant: actual worker guard removed"
    text = text.replace(gate, replacement + "\n" + marker)
    fixture_anchor = "$sourceIntegrityHelperSha256 = Sha (Join-Path $source 'tools\\bootstrap_integrity.ps1')"
    assert text.count(fixture_anchor) == 1
    text = text.replace(fixture_anchor, fixture_anchor + "\n" + CONTINUATION_FIXTURE)
    canonical.write_text(text, encoding="utf-8-sig", newline="\n")
    _bind_packet(source)
    if operation == "CONTINUATION":
        shutil.copytree(source, install, dirs_exist_ok=True)
    args = [shutil.which(engine), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(canonical),
            "-SourceRoot", str(source), "-InstallRoot", str(install)]
    if operation == "RESTORE":
        args += ["-RestoreVerifiedReplacement", "-RestoreReceiptPath", str(tmp_path / "receipt.json"),
                 "-RestoreReceiptSha256", "a" * 64]
    elif operation == "COMPLETE_RETIRED_REMOVAL":
        old_source = tmp_path / "old-source"
        shutil.copytree(source, old_source)
        args += ["-CompleteRetiredRemoval", "-OldSourceRoot", str(old_source),
                 "-RetiredRemovalReceiptSha256", "a" * 64, "-RetiredStopMarkerSha256", "b" * 64]
    result = run_powershell(args, env=env, capture_output=True, text=True)
    marker = tmp_path / "dispatch-after-guard.txt"
    return result, marker


def _assert_dispatch(result, marker, operation):
    if operation == "INSTALL":
        assert result.returncode != 23 and result.returncode != 0
        assert not marker.exists()
        rows = json.loads((marker.parent / "dispatch-native-failure.json").read_text(encoding="utf-8-sig"))
        assert any(row["worker_requirement"] for row in rows)
    else:
        assert result.returncode == 23
        assert marker.read_text() == operation
        if operation == "CONTINUATION":
            proof = json.loads((marker.parent / "continuation-reader-proof.json").read_text(encoding="utf-8-sig"))
            assert proof == {"entered": True, "store_exists": True, "store_in_fixture": True}


CASES = [(branch, operation) for branch in ("ordinary", "machine")
         for operation in ("RESTORE", "COMPLETE_RETIRED_REMOVAL", "INSTALL")]
CASES.append(("ordinary", "CONTINUATION"))


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("branch,operation", CASES)
def test_real_top_level_classifies_support_before_worker_requirement(tmp_path, engine, branch, operation):
    _assert_dispatch(*_probe(tmp_path, engine, branch, operation), operation)


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("branch", ("ordinary", "machine"))
@pytest.mark.parametrize("mutation,operation", (
    ("force_install", "RESTORE"), ("remove_call", "INSTALL"),
))
def test_actual_worker_guard_mutations_fail_the_dispatch_oracle(tmp_path, engine, branch, mutation, operation):
    result, marker = _probe(tmp_path, engine, branch, operation, mutation)
    if mutation == "force_install":
        assert result.returncode not in (0, 23) and not marker.exists()
        rows = json.loads((marker.parent / "dispatch-native-failure.json").read_text(encoding="utf-8-sig"))
        assert any(row["worker_requirement"] for row in rows)
    else:
        assert result.returncode == 23 and marker.read_text() == "INSTALL"
    with pytest.raises(AssertionError):
        _assert_dispatch(result, marker, operation)
