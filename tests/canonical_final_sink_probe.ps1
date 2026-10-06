# CA port of sub-291 rollback-sink-probe: actual catch/finally and isolated native boundaries.
param([string]$Source,[string]$Output,[string]$Python,[string]$Child,[string]$Root,[string]$RecoveryCase='normal')
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse errors'}
$clauses=$ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true)
if($clauses.Count -ne 1){throw 'exact catch not found'}

$script:RollbackPython=$Python
$script:RollbackChild=$Child
$readerDefinitions=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Write-CanonicalInstallationPublicRecord','Get-CanonicalOnboardingInputBinding','ConvertTo-CanonicalSafeDiagnostic','Get-CanonicalFailureDetails','Assert-CanonicalWriterRestoreReadback')},$true)
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
. (Join-Path (Split-Path -Parent $Source) 'tools/bootstrap_integrity.ps1')

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
function Enable-CanonicalWriter {
 param($Install,$Before)
 $script:observed.task_restore++
 if($RecoveryCase -ceq 'task-restore-failure'){throw [IO.IOException]::new('SYNTHETIC_TASK_RESTORE_FAILURE')}
 $script:state.task='before'
 return @{present=$true;classification='CANONICAL_QUIESCE_RESTORE';enabled=$true;binding_sha256=('a'*64)}
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
$processSource=Split-Path -Parent $Source
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

$script:SyntheticSinkSecret=[Guid]::NewGuid().ToString('N')
[Environment]::SetEnvironmentVariable('CUSTOM_SERVICE_SECRET',$script:SyntheticSinkSecret,'Process')
$inner=[InvalidOperationException]::new('synthetic inner '+$script:SyntheticSinkSecret)
$script:forwardException=[InvalidOperationException]::new('synthetic forward '+$script:SyntheticSinkSecret,$inner)
$transaction=$clauses[0].Parent
if($null -eq $transaction.Finally){throw 'Actual transaction finally absent.'}
$finallyBody=$transaction.Finally.Extent.Text
function Read-ContainerWriterFence {return $null}
function Start-CanonicalRelayAfterFenceRelease {param($Root,$RunCommand);return (StartRaw $RunCommand)}
function Complete-InstallationEvidenceStage {param($Mode,$Failure)}
function Complete-InstallationEvidence {return @{status='PASS';summary_path=(Join-Path $Root ('synthetic-'+$script:SyntheticSinkSecret))}}
function Exit-ContainerWriterSessionAuthority {param($Lease)}
function Exit-RetirementResumeClaim {param($Lease)}
function Exit-CanonicalRollbackContinuationClaim {param($Lease)}
$legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$false
$canonicalWriterFenceAuthority=$null;$retirementResumeClaim=$null;$continuationOldClaim=$null
$canonicalWriterFenceEnvironmentNames=@();$canonicalWriterFenceEnvironmentBefore=@{}
$retirementAuditSealed=$false;$canonicalWriterFencePreparedPath=Join-Path $Root 'absent-prepared.json'
if($RecoveryCase -ceq 'failure'){$enteredPlacementTry=$false;$canonicalWriterFenceActive=$false;$old=@()}
if($RecoveryCase -ceq 'rollback_failure'){
 function Product {param($Root,$Mode);$script:observed.product_removal++;throw ('synthetic rollback '+$script:SyntheticSinkSecret)}
}
$executeText='try {throw $script:forwardException} catch '+$body+' finally '+$finallyBody
$outer=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains("'CanonicalInstallationOutputFailure'")},$true))
if($outer.Count -gt 1){throw 'Public output boundary duplicated.'}
if($outer.Count -eq 1){$executeText='try {'+$executeText+'} catch '+$outer[0].Body.Extent.Text}
$script:finalError=$null
$script:originalPreserved=$false
$console=(& {
 try{. ([ScriptBlock]::Create($executeText))}catch{$script:finalError=$_;Write-Output ([string]$_.Exception.Message)}
 $script:originalPreserved=$null -ne $original -and [object]::ReferenceEquals($original.Exception,$script:forwardException)
} *>&1|Out-String)
$finalMessage=if($null -ne $script:finalError){[string]$script:finalError.Exception.Message}else{''}
$originalPreserved=$script:originalPreserved
$chainPreserved=$false
$exception=if($null -ne $script:finalError){$script:finalError.Exception}else{$null}
for($depth=0;$null -ne $exception -and $depth -lt 12;$depth++){
 if([object]::ReferenceEquals($exception,$script:forwardException)){$chainPreserved=$true}
 $exception=$exception.InnerException
}
$record=@{case=$RecoveryCase;engine=$PSVersionTable.PSVersion.ToString();console_raw_hits=[int]$console.Contains($script:SyntheticSinkSecret);
 exception_raw_hits=[int]$finalMessage.Contains($script:SyntheticSinkSecret);original_object_preserved=$originalPreserved;inner_chain_preserved=$chainPreserved;
 real_product_catch_and_finally=$true;native_host_calls=0;final_message=(ConvertTo-KmtechRedactedSinkText -Text $finalMessage -UserLine);failed=($null -ne $script:finalError);counts=$script:observed}
[IO.File]::WriteAllText($Output,($record|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
$record|ConvertTo-Json -Depth 5 -Compress
