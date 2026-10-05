param([string]$Source,[string]$Output,[string]$Python,[string]$Child,[string]$Root,[string]$RecoveryCase='normal')
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse errors'}
$clauses=$ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true)
if($clauses.Count -ne 1){throw 'exact catch not found'}
$body=$clauses[0].Body.Extent.Text
$script:state=@{code='before';data='before';run='before';task='before';relay='before'}
$script:observed=[ordered]@{product_removal=0;code_restore=0;run_restore=0;task_restore=0;relay_start=0;fence_release=0;audit=0}
. (Join-Path (Split-Path -Parent $Source) 'tools/bootstrap_integrity.ps1')
function Product {param($Root,$Mode) $script:observed.product_removal++; throw 'isolated removal refusal'}
function Save {param($Path,$Value) $script:observed.audit++}
function Sync-CanonicalWriterFenceInventory {param($Digest)}
function Assert-RollbackRelayPreimage {param($ExpectedRelays)}
function Restore {param($Value) $script:observed.run_restore++;$script:state.run='before'}
function Snapshot {return @{exists=($script:state.run -ceq 'before');kind='String';data='synthetic-preserved'}}
function Relays {if($script:state.relay -ceq 'before'){return $old};return @()}
function Read-BootstrapReplacementReceipt {param($Path,$ExpectedSha256) return @{rollback_root=$Root}}
$script:actualGCalls=0; $script:actualGPassed=0; $script:actualGBlocked=0
$script:actualGenerationProbe = ${function:Assert-ContainerDataGenerationTarget}
function Assert-ContainerDataGenerationTarget {
 param([string]$CandidateRoot,[string]$TargetSid,[string]$LocalAppDataRoot,[string]$DataRoot,[string]$HelperRoot)
 $script:actualGCalls++
 $PSBoundParameters['HelperRoot'] = Split-Path -Parent $Source
 try { & $script:actualGenerationProbe @PSBoundParameters; $script:actualGPassed++ }
 catch { $script:actualGBlocked++; $script:actualGErrorId=$_.FullyQualifiedErrorId; $script:actualGCommand=$_.Exception.CommandName; throw }
}

function ReadReplacementRestoreEvidence {param($Path,$ExpectedTransactionId,$ExpectedReceiptPath,$ExpectedReceiptSha256,$ExpectedInstallRoot) return @{}}
function Sha {param($Path) return ('a'*64)}
function New-CanonicalWriterFenceReleaseAuthorization {param($Path,$Phase,$AuditPath,$EnabledBaseline) return @{path=$Path;sha256=('a'*64)}}
function Set-CanonicalWriterFenceReleaseAuthorization {param($Authorization)}
function Clear-CanonicalWriterFenceReleaseDelegation {}
function Stop-CanonicalWriterFenceRelease {param($Authorization) $script:observed.fence_release++}
function Enable-CanonicalWriter {param($Install,$Before) $script:observed.task_restore++;$script:state.task='before';return @{}}
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
$writerBefore=@{};$testMode=$true
$operatorSid = 'S-1-5-21-233-233-233-1001'
$lad = Join-Path $Root 'actual-g-local'
$activeDataRoot = Join-Path $Root 'actual-g-data'
# These are lifecycle doubles: the original catch is executed, not a native install.
$script:state.code='changed';$script:state.run='changed';$script:state.task='changed';$script:state.relay='absent'
$processSource=Split-Path -Parent $Source
$raw=@(& $Python -B $Child $processSource 'nested-onboard-secret-explicit' (Join-Path $Root 'child') 'newer' 'absolute')
if($LASTEXITCODE -ne 0){throw 'isolated onboarding child failed'}
$childResult=($raw[-1]|ConvertFrom-Json)
if($childResult.status -cne 'REFUSE'){throw 'nested child did not refuse'}
if ($RecoveryCase -ceq 'code-mismatch') {
    function ReadReplacementRestoreEvidence { throw 'ISOLATED_CODE_RESTORE_EVIDENCE_MISMATCH' }
}
if ($RecoveryCase -ceq 'g-unknown') {
    [IO.Directory]::CreateDirectory((Join-Path $activeDataRoot 'control')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $activeDataRoot 'control/data-generation.json'), 'invalid isolated generation marker')
}
$errorType=''
try {. ([ScriptBlock]::Create("try {throw 'Product mode failed: --onboard-current-user/2'} catch "+$body))}
catch {$errorType=$_.Exception.GetType().Name}
$result=@{rollback_status=$audit.status;rollback_steps=$audit.rollback.steps;recovery_verified=$rollbackRecoveryVerified;actual_g_error_id=$script:actualGErrorId;actual_g_command=$script:actualGCommand;actual_g_calls=$script:actualGCalls;actual_g_passed=$script:actualGPassed;actual_g_blocked=$script:actualGBlocked;state_restored=(@($script:state.Values|Where-Object {$_ -cne 'before'}).Count -eq 0);observed=$script:observed;fence_active_after=$canonicalWriterFenceActive;child_locator_reads=$childResult.locator_reads;child_payload_reads=$childResult.observed.input_reads;child_changes=$childResult.changed_file_count;child_status=$childResult.status;error_type=$errorType;code_rollback_failure=$codeRollbackFailure;autostart_rollback_failure=$autostartRollbackFailure;full_installer_executed=$false;actual_host_lifecycle_calls=0;changes_before_child=@('code','Run','task','relay')}
$result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $Output -Encoding utf8
$result|ConvertTo-Json -Depth 5 -Compress
