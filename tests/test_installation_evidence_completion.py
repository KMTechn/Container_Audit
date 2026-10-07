"""Evidence completeness and elevated helper identity are separate from success."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_native_child_fallback_is_returned_and_recorded_before_binding(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
function Set-InstallationEvidenceAcl {}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'parent') 'S-1-5-21-111-222-333-1001'
$child=Join-Path $env:CA_CONTRACT_ROOT 'finite-native-failure.ps1'
$diagnostic=@{schema='container-audit-installation-fallback-v1';exit_code=73;failure=@{message='native task XML rejected'}}|ConvertTo-Json -Depth 8 -Compress
$payload="[Console]::Out.WriteLine('installation_failure_summary="+$diagnostic.Replace("'","''")+"'); exit 73"
[IO.File]::WriteAllText($child,$payload,[Text.UTF8Encoding]::new($true))
$result=Invoke-InstallationEvidenceChild 'placement-helper' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',$child)
if($result.ExitCode -ne 73 -or $result.FailureDiagnostic.failure.message -cne 'native task XML rejected'){throw 'Native fallback was not returned.'}
$events=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl')|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.event -ceq 'CHILD_FAILURE_FALLBACK'})
if($events.Count -ne 1 -or $events[0].child_exit_code -ne 73 -or $events[0].diagnostic.failure.message -cne $result.FailureDiagnostic.failure.message){throw 'Native fallback was not retained in parent journal.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("native_code", (73, 0))
def test_placement_binding_failure_preserves_first_native_failure(tmp_path, engine, native_code):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
function Set-InstallationEvidenceAcl {}
$journalRoot=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'parent') 'S-1-5-21-111-222-333-1001'
$original=@{schema='container-audit-installation-fallback-v1';exit_code=73;failure=@{message='native task XML rejected';exception_chain=@(@{type='CimException';message='LogonType:ServiceAccount'})}}
function Invoke-InstallationEvidenceChild {
 [pscustomobject]@{ExitCode=[int]$env:CA_NATIVE_CODE;ProcessId=4111;Stdout=('installation_failure_summary='+($original|ConvertTo-Json -Depth 8 -Compress));Streams=@{};FailureDiagnostic=$original}
}
function Read-InstallationHelperEvidenceBinding {throw 'Direct helper evidence root binding differs.'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$tokens,[ref]$errors)
$blocks=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('$bootstrapChild = Invoke-InstallationEvidenceChild')},$true)|Sort-Object {$_.Extent.Text.Length})
if($errors.Count -or -not $blocks.Count){throw 'Actual canonical placement block unavailable.'}
$audit=@{code_replacement=@{}};$bootstrapChild=$null;$bootstrapOutput=@();$bootstrapExitCode=1
$elevationLogPath=Join-Path $env:CA_CONTRACT_ROOT 'helper';$sourceManifest=@{helper_sha256='a'*64}
Invoke-Expression $blocks[0].Extent.Text
if([int]$env:CA_NATIVE_CODE -ne 0){
 if($bootstrapExitCode -ne 73 -or $bootstrapOutput.Count -ne 1 -or $audit.code_replacement.child_failure_summary.failure.message -cne 'native task XML rejected'){throw 'Secondary binding failure replaced native code or first summary.'}
}elseif($bootstrapExitCode -eq 0){throw 'Unbound successful child was accepted.'}
if(-not $audit.code_replacement.child_evidence_binding_failure){throw 'Secondary evidence failure was not retained.'}
$events=@(Get-Content -LiteralPath (Join-Path $journalRoot 'stages.jsonl')|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.event -ceq 'CHILD_EVIDENCE_BINDING_FAILED'})
if($events.Count -ne 1 -or $events[0].child_exit_code -ne [int]$env:CA_NATIVE_CODE){throw 'Parent journal lost the actual native exit.'}
'PASS'
''', engine=engine, values={"CA_NATIVE_CODE": str(native_code)})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("shape", ("valid", "wrong_pid", "wrong_run", "foreign_root"))
def test_direct_protected_helper_binding_retains_path_and_pid_guards(tmp_path, engine, shape):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$control=Join-Path $env:CA_CONTRACT_ROOT 'update-control'
function Get-InstallationEvidenceControlRoot {return $control}
function Assert-InstallationEvidenceProtectedPath {param($Path) Assert-BootstrapNoReparsePoint $Path 'owned protected fixture' -PathOnly}
$log=Join-Path $env:CA_CONTRACT_ROOT 'helper.jsonl'
$run=Join-Path $control ('installation-evidence\run-'+('a'*32))
if($env:CA_BINDING_SHAPE -ceq 'wrong_run'){$run=Join-Path $control 'installation-evidence\other'}
if($env:CA_BINDING_SHAPE -ceq 'foreign_root'){$run=Join-Path $env:CA_CONTRACT_ROOT ('foreign\run-'+('a'*32))}
$actual=Join-Path $run ('helper.jsonl.evidence.'+$(if($env:CA_BINDING_SHAPE -ceq 'wrong_pid'){4112}else{4111}))
[void][IO.Directory]::CreateDirectory($actual)
[IO.File]::WriteAllText((Join-Path $actual 'evidence-status.json'),(@{status='COMPLETE';root=$actual;recording_failed=$false}|ConvertTo-Json))
$failed=$false
try{$binding=Read-InstallationHelperEvidenceBinding @('installation_stage_evidence_root='+$actual) $log 4111}catch{$failed=$true;$bindingError=$_}
if($env:CA_BINDING_SHAPE -ceq 'valid'){
 if($failed){throw $bindingError}
 if($binding.helper_process_id -ne 4111 -or $binding.stage_evidence_root -cne $actual){throw 'Actual protected direct helper root was rejected.'}
}elseif(-not $failed){throw 'Foreign protected helper root or PID was accepted.'}
'PASS'
''', engine=engine, values={"CA_BINDING_SHAPE": shape})
    assert result.returncode == 0, result.stdout + result.stderr


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
function Initialize-InstallationProtectedBase {param($Sid) Assert-InstallationEvidenceProtectedPath (Split-Path -Parent (Get-InstallationEvidenceControlRoot))}
function New-InstallationProtectedDirectory {param($Path,$Sid)
 Assert-InstallationEvidenceProtectedPath (Split-Path -Parent $Path)
 [void][IO.Directory]::CreateDirectory($Path)
 Assert-InstallationEvidenceProtectedPath $Path
}
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
# The existing RunAs substitute below runs an ordinary process. Simulate only
# its protected evidence routing in this harmless fixture; the product wrapper
# derives its privilege from the actual token and receives no extra test hook.
$helperSource=$installer.ParamBlock.Extent.Text+"`n"+'$Script:InstallationEvidencePrivileged=$true'+"`n"+'$BootstrapBoundParameters=@{ReplacementReceiptPath=$ReplacementReceiptPath}'+"`n"+$initializer[0].Extent.Text+"`n"+'$replacementReceiptFull=$ReplacementReceiptPath'+"`n"+'$boundReceiptPath='+$pathValue[0].Item2.Extent.Text+"`n"+@'
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
