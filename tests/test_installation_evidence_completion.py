"""Evidence completeness and elevated helper identity are separate from success."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("failure", ("journal_directory", "journal_limit"))
def test_journal_failure_survives_final_evidence_summary(tmp_path, engine, failure):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
function Set-InstallationEvidenceAcl {}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'audit.json') 'S-1-5-21-111-222-333-1001'
$journal=Join-Path $root 'stages.jsonl'
if($env:CA_JOURNAL_FAILURE -ceq 'journal_directory'){
 Remove-Item -LiteralPath $journal
 [void][IO.Directory]::CreateDirectory($journal)
}else{[IO.File]::WriteAllBytes($journal,[byte[]]::new(1048576))}
Set-InstallationEvidenceStage 'observable-stage'
Complete-InstallationEvidenceStage 'forward'
if(-not $Script:InstallationEvidenceFailed){throw 'failure injection was invalid'}
$summary=Complete-InstallationEvidence
if($summary.status -cne 'INCOMPLETE' -or -not $summary.recording_failed -or $summary.root -cne $root){throw 'journal failure was reported as complete'}
$persisted=Get-Content -LiteralPath $summary.summary_path -Raw -Encoding UTF8 | ConvertFrom-Json
if($persisted.status -cne 'INCOMPLETE' -or -not $persisted.recording_failed){throw 'durable final evidence flag is absent'}
'PASS'
''', values={"CA_JOURNAL_FAILURE": failure}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_child_incomplete_summary_survives_successful_outer_capture(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
function Set-InstallationEvidenceAcl {}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'parent') 'S-1-5-21-111-222-333-1001'
$childRoot=Join-Path $env:CA_CONTRACT_ROOT 'helper.jsonl.evidence.4111';[void][IO.Directory]::CreateDirectory($childRoot)
[IO.File]::WriteAllText((Join-Path $childRoot 'evidence-status.json'),(@{status='INCOMPLETE';recording_failed=$true;root=$childRoot}|ConvertTo-Json))
$binding=Read-InstallationHelperEvidenceBinding @('installation_stage_evidence_root='+$childRoot) (Join-Path $env:CA_CONTRACT_ROOT 'helper.jsonl') 4111
if($binding.child_stage_evidence_summary.status -cne 'INCOMPLETE'){throw 'child journal failure lost at helper boundary'}
$final=Complete-InstallationEvidence
if($final.status -cne 'INCOMPLETE' -or -not $final.recording_failed -or $final.failure_codes -cnotcontains 'CHILD_EVIDENCE_INCOMPLETE'){throw 'complete outer capture concealed incomplete child diagnostics'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_direct_helper_binding_uses_its_emitted_root(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$log=Join-Path $env:CA_CONTRACT_ROOT 'helper.jsonl'
$actual=$log+'.evidence.4111'
[void][IO.Directory]::CreateDirectory($actual)
$binding=Read-InstallationHelperEvidenceBinding @('installation_stage_evidence_root='+$actual) $log 4111
if($binding.helper_process_id -ne 4111 -or $binding.stage_evidence_root -cne $actual){throw 'actual helper root binding was lost'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_elevated_wrapper_captures_real_finite_child_without_elevation(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$fixture=Join-Path $env:CA_CONTRACT_ROOT 'fixture-helper';[void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tools'))
$lib=Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\bootstrap_integrity.ps1'
Copy-Item -LiteralPath $lib -Destination (Join-Path $fixture 'tools\bootstrap_integrity.ps1')
$fixtureOverrides=@'
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'update-control')}
function Set-InstallationEvidenceAcl {}
function Assert-BootstrapProtectedRelayPath {param($Path) Assert-BootstrapNoReparsePoint $Path 'owned synthetic protected folder' -PathOnly}
'@
[IO.File]::AppendAllText((Join-Path $fixture 'tools\bootstrap_integrity.ps1'),("`n"+$fixtureOverrides))
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'update-control')}
function Assert-BootstrapProtectedRelayPath {param($Path) Assert-BootstrapNoReparsePoint $Path 'owned synthetic protected folder' -PathOnly}
$target=Join-Path $fixture 'helper.ps1';$auditBase=Join-Path $env:CA_CONTRACT_ROOT 'helper-audit.jsonl'
$tokens=$null;$errors=$null
$installer=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'INSTALL_THIS_PC.ps1'),[ref]$tokens,[ref]$errors)
$initializer=@($installer.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('$helperInstallationEvidenceRoot=Initialize-InstallationEvidence')})
if($errors.Count -or $initializer.Count -ne 1){throw 'actual helper evidence initializer is unavailable'}
$payload=@($installer.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$receiptPayload' -and $node.Right.Extent.Text.Contains("schema_version = 'container-audit-verified-replacement-v1'")},$true))
if($payload.Count -ne 1){throw 'actual replacement receipt payload is unavailable'}
$table=@($payload[0].Right.FindAll({param($node) $node -is [Management.Automation.Language.HashtableAst]},$true))[0]
$pathValue=@($table.KeyValuePairs|Where-Object {$_.Item1.SafeGetValue() -ceq 'receipt_path'})
if($pathValue.Count -ne 1){throw 'actual replacement receipt path binding is unavailable'}
# Execute only the real parameter/evidence initialization boundary, then a
# harmless result writer with the real payload path expression; never placement.
$helperSource=$installer.ParamBlock.Extent.Text+"`n"+'$BootstrapBoundParameters=@{ReplacementReceiptPath=$ReplacementReceiptPath}'+"`n"+$initializer[0].Extent.Text+"`n"+'$replacementReceiptFull=$ReplacementReceiptPath'+"`n"+'$boundReceiptPath='+$pathValue[0].Item2.Extent.Text+"`n"+@'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Write-Output '{"authorization":"Bearer synthetic-child-value","credential":"synthetic-child-credential"}'
[void](Write-BootstrapReplacementReceipt $ReplacementReceiptPath @{status='REPLACEMENT_READY';receipt_path=$boundReceiptPath})
[void](Write-BootstrapReplacementReceipt $RestoreEvidencePath @{status='RESTORE_READY'})
[void](Complete-InstallationEvidence)
exit 0
'@
[IO.File]::WriteAllText($target,$helperSource,[Text.UTF8Encoding]::new($true))
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$parentRoot=Initialize-InstallationEvidence $auditBase $sid
function ConvertTo-ProcessArgument([string]$Value){if($Value -match '\s'){return '"'+$Value+'"'};return $Value}
function Start-Process {
 param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
 if($Verb -cne 'RunAs' -or $WindowStyle -cne 'Hidden' -or -not $Wait -or -not $PassThru){throw 'supported elevation boundary changed'}
 # Replace only RunAs with a normal, harmless WinPS child. Its fixed wrapper,
 # private ACL, finite capture, masking and durable PID/root binding are real.
 $parts=@([regex]::Matches($ArgumentList,'"([^"\r\n]*)"|([^\s]+)')|ForEach-Object {if($_.Groups[1].Success){$_.Groups[1].Value}else{$_.Groups[2].Value}})
 & $FilePath @parts | Out-Null
 $code=$LASTEXITCODE
 $paths=@(Get-ChildItem -LiteralPath (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence') -Filter 'elevation-result.json' -Recurse -File)
 if($paths.Count -ne 1){throw 'missing protected finite result'}
 $record=Get-Content -LiteralPath $paths[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
 return [pscustomobject]@{Id=[int]$record.wrapper_process_id;ExitCode=[int]$code}
}
$replacement=Join-Path $env:CA_CONTRACT_ROOT 'ordinary-replacement.json';$restore=Join-Path $env:CA_CONTRACT_ROOT 'ordinary-restore.json'
$childArgs=@('-NoLogo','-NoProfile','-NonInteractive','-File',$target,'-ElevationLogPath',$auditBase,'-OperatorSid',$sid,'-ReplaceExistingVerifiedPortable','-ReplacementReceiptPath',$replacement,'-RestoreEvidencePath',$restore)
$child=Invoke-InstallationElevationCapture $target $childArgs $auditBase $sid
if($child.ExitCode -ne 0 -or $child.Id -le 0 -or $child.WrapperProcessId -le 0 -or $child.Id -eq $child.WrapperProcessId){throw 'finite wrapper/helper identities were collapsed'}
$output=@(('installation_stage_evidence_root='+$child.HelperStageEvidenceRoot),('installation_elevation_result_path='+$child.ResultPath))
$binding=Read-InstallationHelperEvidenceBinding $output $auditBase $PID (Get-FileSha256 $target)
if($binding.status -cne 'BOUND_ELEVATED_CHILD' -or $binding.helper_process_id -ne $child.Id -or $binding.stage_evidence_root -cne $child.HelperStageEvidenceRoot){throw 'actual elevated child journal binding failed'}
$stdout=[IO.File]::ReadAllText([string]$binding.streams.stdout.path)
if($stdout.Contains('synthetic-child-value') -or $stdout.Contains('synthetic-child-credential')){throw 'finite child JSON values survived masking'}
if(-not $binding.streams.stdout.redacted -or -not $binding.streams.stdout.complete){throw 'capture completeness/masking metadata is false'}
if(Test-Path -LiteralPath (Join-Path $parentRoot 'elevation-capture.ps1')){throw 'memory wrapper persisted on disk'}
if(-not $binding.capture_root.StartsWith((Get-InstallationEvidenceControlRoot)+'\') -or -not $binding.stage_evidence_root.StartsWith((Get-InstallationEvidenceControlRoot)+'\')){throw 'privileged evidence was written in operator directory'}
foreach($pair in @(@($replacement,'replacement-receipt.json'),@($restore,'restore-evidence.json'))){
 $protected=Join-Path $binding.stage_evidence_root $pair[1]
 if(-not(Test-Path -LiteralPath $protected) -or (Get-FileSha256 $pair[0]) -cne (Get-FileSha256 $protected)){throw 'ordinary result export differs from protected original'}
}
$receipt=Get-Content -LiteralPath $replacement -Raw -Encoding UTF8|ConvertFrom-Json
if(-not(Test-BootstrapSamePath $receipt.receipt_path $replacement)){throw 'ordinary restore consumer would reject exported receipt path binding'}
$summary=Complete-InstallationEvidence
if($summary.status -cne 'COMPLETE' -or $summary.root -cne $parentRoot){throw 'ordinary final summary did not consume protected child evidence'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
