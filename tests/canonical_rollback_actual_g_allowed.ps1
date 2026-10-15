param([string]$CanonicalSource,[string]$Output,[string]$Python,[string]$Child,[string]$Root,[string]$RecoveryCase='normal')
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($CanonicalSource,[ref]$tokens,[ref]$errors)
$source=Split-Path -Parent $CanonicalSource
if($errors.Count){throw 'parse errors'}
$clauses=$ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true)
if($clauses.Count -ne 1){throw 'exact catch not found'}

$script:RollbackPython=$Python
$script:RollbackChild=$Child
# Commit-point decisions remain actual product code, alongside actual G.
$readerDefinitions=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-CanonicalOnboardingInputBinding','ConvertTo-CanonicalSafeDiagnostic','Get-CanonicalFailureDetails','Assert-CanonicalWriterRestoreReadback','Get-CanonicalInstallationCommitPoint','Get-CanonicalRollbackSuccessStatus')},$true)
foreach($definition in $readerDefinitions) {
    $readerBody=$definition.Extent.Text
    if($definition.Name -ceq 'Get-CanonicalOnboardingInputBinding') {
        $originalArguments=@'
    $preflightArguments=@('-I','-B',(Join-Path $Root 'app\main.py'),
        '--onboard-current-user','--app-root',(Join-Path $Root 'app'),'--preflight-only')
'@
        $fixtureArguments=@'
    $preflightArguments=@('-B',$script:RollbackChild,$script:RollbackSource,'nested-final-target',
        $script:RollbackRoot,$script:RollbackGeneration,'absolute')
'@
        if(-not $readerBody.Contains($originalArguments)){throw 'readonly fixture argv adapter differs'}
        $readerBody=$readerBody.Replace($originalArguments,$fixtureArguments)
        $readerBody=$readerBody.Replace("(Join-Path `$Root 'runtime\python.exe')",'$script:RollbackPython')
    }
    Invoke-Expression $readerBody
}

$body=$clauses[0].Body.Extent.Text
$script:state=@{code='before';data='before';run='before';task='before';relay='before'}
$script:observed=[ordered]@{product_removal=0;code_restore=0;run_restore=0;task_restore=0;relay_start=0;fence_release=0;audit=0}
. (Join-Path $source 'tools/bootstrap_integrity.ps1')

# The lifecycle assembly captures finite children and proves READY through this
# adapter; retain the existing native-free restore/restart observations.
function Invoke-InstallationEvidenceChild {
 param($Name,$File,$Arguments)
 & $File @Arguments
 return [pscustomobject]@{ExitCode=$global:LASTEXITCODE;Stdout='';Stderr='';ProcessId=0}
}
function Start-CanonicalRelayAfterFenceRelease {param($Root,$RunCommand);return (StartRaw $RunCommand)}

function Product {param($Root,$Mode) if($Mode -cne '--remove-current-user-setup'){throw 'unexpected product mode'}; $script:observed.product_removal++;$script:state.run='absent';$script:state.relay='absent'}
function Save {
 param($Path,$Value,$SanitizeDiagnostics)
 $script:observed.audit++
 if ($RecoveryCase -ceq 'audit-save-failure' -and $Path -ceq $auditPath) {
  throw 'ISOLATED_CATCH_AUDIT_STORAGE_UNAVAILABLE'
 }
 if ($RecoveryCase -cin @('audit-save-failure','evidence-save-failure') -and $Path -ceq $evidenceFull) {
  $script:observed.evidence_save=1+[int]$script:observed.evidence_save
  $script:observed.diagnostic_failures=@($Value.diagnostic_write_failures).Count
  if ($RecoveryCase -ceq 'evidence-save-failure') { throw 'ISOLATED_CATCH_EVIDENCE_STORAGE_UNAVAILABLE' }
 }
}
function Sync-CanonicalWriterFenceInventory {param($Digest)}
function Assert-RollbackRelayPreimage {param($ExpectedRelays)}
function Restore {param($Value) $script:observed.run_restore++;if($RecoveryCase -ceq 'run-restore-failure'){throw [IO.IOException]::new('SYNTHETIC_RUN_RESTORE_FAILURE')};$script:state.run='before'}
function Snapshot {return @{exists=($script:state.run -ceq 'before');kind='String';data='synthetic-preserved'}}
function Relays {if($script:state.relay -ceq 'before'){return $old};return @()}
function Read-BootstrapReplacementReceipt {param($Path,$ExpectedSha256) return @{rollback_root=$Root}}
$script:actualGCalls=0; $script:actualGPassed=0; $script:actualGBlocked=0
$script:actualGenerationProbe = ${function:Assert-ContainerDataGenerationTarget}
function Assert-ContainerDataGenerationTarget {
 param([string]$CandidateRoot,[string]$TargetSid,[string]$LocalAppDataRoot,[string]$DataRoot,[string]$HelperRoot)
 $script:actualGCalls++
  $PSBoundParameters['HelperRoot'] = $source
 try { & $script:actualGenerationProbe @PSBoundParameters; $script:actualGPassed++ }
 catch { $script:actualGBlocked++; $script:actualGErrorId=$_.FullyQualifiedErrorId; $script:actualGCommand=$_.Exception.CommandName; throw }
}

# Keep the real commit-point readback bound to the containing packet root.
$script:actualCommitPoint = ${function:Get-CanonicalInstallationCommitPoint}
function Get-CanonicalInstallationCommitPoint {
 param($Manifest,[string]$TargetSid,[string]$LocalAppDataRoot,[string]$DataRoot,[string]$HelperRoot)
 $PSBoundParameters['HelperRoot'] = $source
 & $script:actualCommitPoint @PSBoundParameters
}

function ReadReplacementRestoreEvidence {param($Path,$ExpectedTransactionId,$ExpectedReceiptPath,$ExpectedReceiptSha256,$ExpectedInstallRoot) return @{}}
function Sha {param($Path) return ('a'*64)}
function New-CanonicalWriterFenceReleaseAuthorization {param($Path,$Phase,$AuditPath,$EnabledBaseline) return @{path=$Path;sha256=('a'*64)}}
function Set-CanonicalWriterFenceReleaseAuthorization {param($Authorization)}
function Clear-CanonicalWriterFenceReleaseDelegation {}
function Stop-CanonicalWriterFenceRelease {param($Authorization) $script:observed.fence_release++}
function Enable-CanonicalWriter {
 param($Install,$Before)
 $script:observed.task_restore++
 if($RecoveryCase -ceq 'task-restore-failure'){throw [IO.IOException]::new('SYNTHETIC_TASK_RESTORE_FAILURE')}
 $script:state.task='before'
 # Match the real Enable-CanonicalWriter proof wrapper, not its nested snapshot.
 return @{status='PASS';binding_sha256_exact=$true;future_natural_trigger_utc=[DateTime]::UtcNow.AddSeconds(20).ToString('o');
  readback=@{present=$true;classification='CANONICAL_QUIESCE_RESTORE';enabled=$true;binding_sha256=('a'*64)}}
}
function Confirm-CanonicalWriterRunning {param($Install,$Enabled) return @{}}
function StartRaw {param($Command) $script:observed.relay_start++;$script:state.relay='before';return 42}
function Start-Sleep {param($Seconds)}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) return @{ExecutablePath=(Join-Path $Root 'relay.exe')}}
function Same {param($Left,$Right) return $Left -ceq $Right}
function Remove-Item {throw 'unexpected cleanup blocked'}
$winps={param([Parameter(ValueFromRemainingArguments=$true)]$Rest) $script:observed.code_restore++;$script:state.code='before';$global:LASTEXITCODE=0}
$enteredPlacementTry=$true;$retirementResume=$null;$canonicalWriterFenceActive=$true
$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$codeRestoreNeeded=$true;$writerRestoreNeeded=$true;$runtimeQuiescedForReplacement=$true
$codeRollbackFailure='';$autostartRollbackFailure='';$evidenceFull='';$placement='REPLACED_VERIFIED'
$install=Join-Path $Root 'installed';$stop=Join-Path $Root 'absent-stop.json'
$auditPath='synthetic-evidence';$rollbackCompleteAuthorizationPath='synthetic-release'
$rollbackNaturalTriggerAuthorizationPath='synthetic-natural-release'
$canonicalWriterFenceLastReleaseAuthorizationPath='';$canonicalWriterFenceLastReleaseAuthorizationSha256=''
$currentTreeInventorySha256=('a'*64);$installedInventorySha256=('a'*64)
$before=@{exists=$true;kind='String';data='synthetic-preserved'}
$old=@(@{CommandLine='synthetic-relay-command';ExecutablePath=(Join-Path $Root 'relay.exe');ProcessId=41})
$mutated=$true;$audit=@{rollback=@{};scheduled_writer=@{};code_replacement=@{}}
$sourceManifest=@{writer_fence_helper_sha256=('a'*64)};$canonicalWriterFencePreparedReceipt=@{path='synthetic';sha256=('a'*64)}
$replacementReceiptPath='synthetic';$replacementReceiptSha256=('a'*64);$replacementRestoreEvidencePath='synthetic'
$writerBefore=@{binding_sha256=('a'*64)};$testMode=$true
$operatorSid = 'S-1-5-21-233-233-233-1001'
$lad = Join-Path $Root 'actual-g-local'
$activeDataRoot = Join-Path $Root 'actual-g-data'
# These are lifecycle doubles: the original catch is executed, not a native install.
$script:state.code='changed';$script:state.run='changed';$script:state.task='changed';$script:state.relay='absent'
$processSource=$source
$readerScenario=if($RecoveryCase -ceq 'nested-high'){'nested-onboard-secret-explicit'}else{'nested-readonly'}
$readerGeneration=if($RecoveryCase -ceq 'nested-high'){'newer'}else{'missing'}
$script:RollbackSource=$processSource
$script:RollbackRoot=Join-Path $Root 'child'
$script:RollbackGeneration=$readerGeneration
$raw=@(& $Python -B $Child $processSource $readerScenario (Join-Path $Root 'child') $readerGeneration 'absolute')
if($LASTEXITCODE -ne 0){throw 'isolated onboarding child failed'}
$childResult=($raw[-1]|ConvertFrom-Json)
if($RecoveryCase -ceq 'nested-high') {
  if($childResult.status -cne 'REFUSE'){throw 'nested child did not refuse'}
} elseif($childResult.status -cne 'NONE' -or $childResult.failure_type) {
  throw 'allowed nested readonly child failed'
}
if ($RecoveryCase -ceq 'code-mismatch') {
    function ReadReplacementRestoreEvidence { throw 'ISOLATED_CODE_RESTORE_EVIDENCE_MISMATCH' }
}
if ($RecoveryCase -ceq 'g-unknown') {
    [IO.Directory]::CreateDirectory((Join-Path $activeDataRoot 'control')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $activeDataRoot 'data-generation.json'), 'invalid isolated generation marker')
}
if($RecoveryCase -clike 'relay-*'){. (Join-Path $PSScriptRoot 'ca_rollback_relay_candidate_fixture.ps1')}
$errorType=''
if ($RecoveryCase -cin @('audit-save-failure','evidence-save-failure')) {
 $auditPath=Join-Path $Root 'recovery-audit.json'
 $evidenceFull=Join-Path $Root 'recovery-evidence.json'
}
try {. ([ScriptBlock]::Create("try {throw 'Product mode failed: --onboard-current-user/2'} catch "+$body))}
catch {$errorType=$_.Exception.GetType().Name}
$result=@{rollback_status=$audit.status;commit_point_status=$audit.rollback.commit_point_status;generation_readback=$audit.rollback.steps.generation_readback.status;operator_notice_saved=[bool]$audit.rollback.operator_message;support_procedure=$audit.rollback.support_recovery_procedure;rollback_steps=$audit.rollback.steps;recovery_verified=$rollbackRecoveryVerified;actual_g_error_id=$script:actualGErrorId;actual_g_command=$script:actualGCommand;actual_g_calls=$script:actualGCalls;actual_g_passed=$script:actualGPassed;actual_g_blocked=$script:actualGBlocked;state_restored=(@($script:state.Values|Where-Object {$_ -cne 'before'}).Count -eq 0);observed=$script:observed;fence_active_after=$canonicalWriterFenceActive;child_locator_reads=$childResult.locator_reads;child_payload_reads=$childResult.observed.input_reads;child_changes=$childResult.changed_file_count;child_status=$childResult.status;error_type=$errorType;code_rollback_failure=$codeRollbackFailure;autostart_rollback_failure=$autostartRollbackFailure;full_installer_executed=$false;actual_host_lifecycle_calls=0;changes_before_child=@('code','Run','task','relay')}
if($RecoveryCase -clike 'relay-*'){$result['relay_candidate']=Get-RelayCandidateFixtureObservation}
$result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $Output -Encoding utf8
$result|ConvertTo-Json -Depth 5 -Compress
