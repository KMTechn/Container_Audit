"""Original failure retention and recovery after an earlier step removed current."""
from pathlib import Path
import json
import os

import pytest
from tests.powershell_contracts import run_functions
from tests.test_installation_stage_evidence import FUNCTIONS

ROOT = Path(os.environ.get("CA_COMPARISON_REPO", Path(__file__).resolve().parents[1]))
LIBRARY = ROOT / "tools/bootstrap_integrity.ps1"
HELPER = ROOT / "INSTALL_THIS_PC.ps1"
CANONICAL = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_full_first_failure_and_child_json_survive_with_secret_bytes_removed(tmp_path, engine):
    result = run_functions(tmp_path, LIBRARY, [*FUNCTIONS, "Get-InstallationFallbackDiagnostic", "Invoke-ContainerAtomicReplaceOnce", "Invoke-ContainerAtomicReplace"], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'evidence') $sid
$childPath=Join-Path $env:CA_CONTRACT_ROOT 'child.ps1'
$childSource=@'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$payload=@{schema='container-audit-installation-fallback-v1';exit_code=73;failure=@{message=('x'*5000)+[Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN')+' full child tail'}}
[Console]::Out.WriteLine('installation_failure_summary='+($payload|ConvertTo-Json -Depth 6 -Compress));exit 73
'@
[IO.File]::WriteAllText($childPath,$childSource,[Text.UTF8Encoding]::new($true))
$child=Invoke-InstallationEvidenceChild 'fixture' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile','-NonInteractive','-File',$childPath)
if($child.ExitCode -ne 73 -or $null -eq $child.FailureDiagnostic -or -not $child.FailureDiagnostic.failure.message.EndsWith(' full child tail')){throw 'Full bounded helper JSON disappeared.'}
$message=('original '*700)+[Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN')+' full first tail'
Write-InstallationCaughtFailure ([InvalidOperationException]::new($message))
$first=$Script:InstallationOriginalFailure
if($first.status -cne 'PRESERVED' -or -not $first.complete){throw 'Original error was not completely preserved.'}
$body=Get-Content -LiteralPath $first.path -Raw -Encoding UTF8|ConvertFrom-Json
if(-not $body.failure.exception_chain[0].message.EndsWith(' full first tail')){throw 'First exception was clipped.'}
Write-InstallationCaughtFailure ([InvalidOperationException]::new('later recovery failure'))
if($Script:InstallationOriginalFailure.sha256 -cne $first.sha256){throw 'Recovery replaced the first exception.'}
$diagnostic=Get-InstallationFallbackDiagnostic ([Exception]::new('public failure'))
if($diagnostic.original_failure.sha256 -cne $first.sha256 -or $diagnostic.child_streams.stdout.saved_bytes -lt 5000){throw 'Summary lost full evidence references.'}
$needle=[Text.Encoding]::UTF8.GetBytes([Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN'))
foreach($file in @(Get-ChildItem -LiteralPath $root -File)){
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    $text=[Text.Encoding]::UTF8.GetString($bytes)
    if($text.Contains([Text.Encoding]::UTF8.GetString($needle))){throw 'Opaque authority bytes survived in audit output.'}
}
if(($diagnostic|ConvertTo-Json -Depth 16 -Compress).Contains([Text.Encoding]::UTF8.GetString($needle))){throw 'Opaque authority survived in summary.'}
$ui=ConvertTo-KmtechRedactedSinkText -Text $child.Stdout -UserLine
if($ui.Length -gt 300 -or $ui.Contains([Text.Encoding]::UTF8.GetString($needle))){throw 'User guidance escaped its boundary.'}
'PASS'
''', engine=engine, values={"CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN": "ca-env-authority-fixture"})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_original_failure_bound_is_explicit_and_never_claims_full_retention(tmp_path, engine):
    result = run_functions(tmp_path, LIBRARY, [*FUNCTIONS, "Invoke-ContainerAtomicReplaceOnce", "Invoke-ContainerAtomicReplace"], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'evidence') $sid
Write-InstallationCaughtFailure ([Exception]::new(('x'*1100000)))
$first=$Script:InstallationOriginalFailure
if($first.complete -or $first.status -cne 'INCOMPLETE_SIZE_OR_DEPTH_BOUND' -or $first.saved_bytes -gt 65536){throw 'Original error cap was concealed.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("bad_pin", (False, True))
def test_exact_startup_preimage_restore_does_not_require_current(tmp_path, engine, bad_pin):
    result = run_functions(tmp_path, HELPER, ["Assert-ContainerStartupUpdateTrust", "Save-ContainerStartupUpdatePreimage", "Restore-ContainerStartupUpdatePreimage", "Write-ContainerStartupUpdateRecord"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
$Script:parentChecks=0
function Assert-ProtectedCodeAncestors {param($Path) if(-not $Path.StartsWith($env:CA_CONTRACT_ROOT)){throw 'escaped parent'};$Script:parentChecks++}
function Assert-HardenedCodeAcl {param($Path) if(-not(Test-Path -LiteralPath $Path)){throw 'current unavailable'}}
function Get-StrictFullPath {param($Path,$Purpose) return [IO.Path]::GetFullPath($Path)}
function Test-PathWithin {param($Child,$Parent) return $Child.StartsWith($Parent+'\',[StringComparison]::OrdinalIgnoreCase)}
function Test-SamePath {param($Left,$Right) return $Left.Equals($Right,[StringComparison]::OrdinalIgnoreCase)}
function Assert-NoReparsePoint {param($Path,$Purpose) if((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'reparse'}}
function Set-HardenedCodeAcl {}
function Get-ContainerStartupUpdateTaskPreimage {return [pscustomobject]@{name=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24));exists=$false}}
function Get-ScheduledTask {return $null}
function Invoke-ContainerStartupUpdateTaskMutation {param($Action) & $Action}
$OperatorSid=@('S','1','5','21','111','222','333','1001') -join '-';$WriterFenceAttemptId='a'*32
$managed=Join-Path $env:CA_CONTRACT_ROOT 'managed';$root=Join-Path $managed 'current';$control=Join-Path $managed 'update-control'
[void][IO.Directory]::CreateDirectory($root);[void][IO.Directory]::CreateDirectory($control)
$policy=Join-Path $control 'policy.json';[IO.File]::WriteAllText($policy,'original policy')
$saved=Save-ContainerStartupUpdatePreimage $root 'install'
[IO.File]::WriteAllText($policy,'candidate policy');Remove-Item -LiteralPath $root
$pin=if($env:CA_BAD_PIN -ceq 'true'){'0'*64}else{$saved.sha256}
$failed=$false
try{Restore-ContainerStartupUpdatePreimage $root $saved.path $pin}catch{$failed=$true}
if($env:CA_BAD_PIN -ceq 'true'){
    if(-not $failed -or [IO.File]::ReadAllText($policy) -cne 'candidate policy'){throw 'Invalid preimage pin admitted.'}
}else{
    if($failed -or [IO.File]::ReadAllText($policy) -cne 'original policy' -or (Test-Path -LiteralPath $root) -or $Script:parentChecks -lt 2){throw 'Current removal blocked exact preimage restore.'}
}
'PASS'
''', engine=engine, values={"CA_BAD_PIN": str(bad_pin).lower()})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_code_and_inventory_failure_still_attempt_exact_run_preimage(tmp_path, engine):
    result = run_functions(tmp_path, CANONICAL, ["Record-CanonicalRollbackStep"], r'''
# sub-420 split runtime recovery into independent stages. Select its exact
# production branch and execute every stage; preserve the original assertions.
$blocks=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses.Count -eq 1 -and $n.Clauses[0].Item1.Extent.Text -ceq '$mutated' -and $n.Clauses[0].Item2.Extent.Text.Contains("Record-CanonicalRollbackStep 'runtime_quiescence'") -and $n.Clauses[0].Item2.Extent.Text.Contains("Record-CanonicalRollbackStep 'run_restore_attempt'")},$true))
if($blocks.Count -ne 1){throw 'Actual independent autostart recovery branch missing.'}
$mutated=$true;$testMode=$true;$codeRollbackFailure='Win32Exception';$autostartRollbackFailure=''
$currentTreeInventorySha256='a'*64;$before=@{exists=$true;kind='ExpandString';data='exact original legacy command'};$old=@()
$install=Join-Path $env:CA_CONTRACT_ROOT 'managed/current'
$stop=Join-Path $env:CA_CONTRACT_ROOT 'stop.json';[IO.File]::WriteAllText($stop,'{}')
$audit=[ordered]@{rollback=[ordered]@{runtime_restored=$false;steps=[ordered]@{}}};$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json';$evidenceFull=''
$Script:restored=$null;$Script:runAttempts=0
function Set-InstallationEvidenceStage {}
function Write-InstallationCaughtFailure {}
function Write-InstallationEvidenceEvent {}
function Save-CanonicalRecoveryDiagnostics {}
function Sync-CanonicalWriterFenceInventory {throw 'inventory not restored'}
function Product {throw 'current already removed'}
function Assert-RollbackRelayPreimage {}
function Restore($Before){$Script:runAttempts++;$Script:restored=$Before}
function Snapshot {return $Script:restored}
function Relays {return @()}
Invoke-Expression $blocks[0].Extent.Text
if($Script:runAttempts -ne 1 -or $Script:restored.data -cne $before.data -or (Test-Path -LiteralPath $stop)){throw 'Code failure skipped exact Run recovery.'}
if($codeRollbackFailure -cne 'Win32Exception'){throw 'Code failure was hidden.'}
if($audit.rollback.steps.runtime_quiescence.status -cne 'FAILED' -or $audit.rollback.steps.run_restore.status -cne 'PASS'){throw 'Independent recovery failure/readback was hidden.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("failed_step", ("startup_preimage", "tree_readback"))
def test_helper_recovery_steps_preserve_first_failure_and_attempt_remaining_steps(tmp_path, engine, failed_step):
    names = []
    if "function Invoke-ContainerPlacementRollbackStep" in HELPER.read_text(encoding="utf-8-sig"):
        names.append("Invoke-ContainerPlacementRollbackStep")
    result = run_functions(tmp_path, HELPER, names, r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
$blocks=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('$originalPlacementFailure = $_')},$true))
if($blocks.Count -ne 1){throw 'Actual placement recovery catch missing.'}
$testOverride=$true;$replacementApplied=$true;$replacementReceiptWritten=$true
$applicationParent=Join-Path $env:CA_CONTRACT_ROOT 'managed';$installRootFull=Join-Path $applicationParent 'current'
$replacementRollbackRoot=Join-Path $applicationParent '.old';$stagingRoot=Join-Path $applicationParent '.stage'
$ReplacementTransactionId='a'*32;$replacementReceiptFull=Join-Path $applicationParent 'receipt.json'
foreach($dir in @($installRootFull,$replacementRollbackRoot,$stagingRoot)){[void][IO.Directory]::CreateDirectory($dir)}
[IO.File]::WriteAllText((Join-Path $replacementRollbackRoot 'old.txt'),'exact original bytes')
[IO.File]::WriteAllText($replacementReceiptFull,'{}')
$Script:StartupUpdatePreimage=@{path='isolated-preimage';sha256='a'*64};$Script:startupAttempts=0
$previousReplacementIdentity='exact original bytes'
function Set-InstallationEvidenceStage {}
function Complete-InstallationEvidenceStage {}
function Fail-InstallationEvidenceStages {}
function Write-InstallationCaughtFailure {}
function Write-InstallationEvidenceEvent {}
function Restore-ContainerStartupUpdatePreimage {$Script:startupAttempts++;if($env:CA_FAILED_STEP -ceq 'startup_preimage'){throw 'secondary startup recovery failure'}}
function Get-StrictFullPath {param($Path,$Purpose) return [IO.Path]::GetFullPath($Path)}
function Assert-ContainerDataGenerationTarget {}
function Get-BootstrapReplacementTreeIdentity {param($Root,$Fixed) if($env:CA_FAILED_STEP -ceq 'tree_readback'){throw 'secondary tree readback failure'};return [IO.File]::ReadAllText((Join-Path $Root 'old.txt'))}
function Test-BootstrapReplacementTreeIdentity {param($Expected,$Actual) return $Expected -ceq $Actual}
$body=$blocks[0].Body.Extent.Text;$caught=$null
try{throw 'FIRST_PLACEMENT_FAILURE'}catch{
    try{Invoke-Expression $body.Substring(1,$body.Length-2)}catch{$caught=$_}
}
if($null -eq $caught -or $caught.Exception.Message -cne 'FIRST_PLACEMENT_FAILURE'){throw 'Recovery replaced the first failure.'}
if($Script:startupAttempts -ne 1 -or (Test-Path -LiteralPath $stagingRoot) -or [IO.File]::ReadAllText((Join-Path $installRootFull 'old.txt')) -cne 'exact original bytes'){throw 'Earlier recovery failure skipped remaining code recovery.'}
$failed=@($Script:PlacementRollbackSteps|Where-Object {$_.status -ceq 'FAILED'})
if($Script:PlacementRollbackSteps.Count -ne 4 -or $failed.Count -ne 1){throw 'Independent step results missing.'}
if($env:CA_FAILED_STEP -ceq 'tree_readback'){
    if(-not(Test-Path -LiteralPath $replacementReceiptFull)){throw 'Unverified tree lost its recovery receipt.'}
}elseif(Test-Path -LiteralPath $replacementReceiptFull){throw 'Verified recovery receipt cleanup missing.'}
'PASS'
''', engine=engine, values={"CA_FAILED_STEP": failed_step})
    assert result.returncode == 0, result.stdout + result.stderr


def test_update_failures_replace_opaque_environment_authority_in_all_details(monkeypatch):
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location("ca_failure_contract_target", ROOT / "auto_update.py")
    auto_update = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, auto_update)
    spec.loader.exec_module(auto_update)
    canary = "ca-env-authority-fixture"
    monkeypatch.setenv("CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN", canary)
    error = RuntimeError("opaque " + canary)
    error.stdout = ("child " + canary).encode()
    error.stderr = "child " + canary
    serialized = json.dumps(auto_update._failure_details(error)).encode()
    if canary.encode() in serialized:
        pytest.fail("Opaque environment authority survived update failure redaction", pytrace=False)
    assert b"[REDACTED:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN]" in serialized
