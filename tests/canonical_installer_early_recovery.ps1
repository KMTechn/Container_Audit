param([string]$CanonicalSource,[string]$Root,[string]$Python,[string]$Phase,[string]$Case,[string]$Output)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($CanonicalSource,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'canonical parse failed'}
$canonicalText=$ast.Extent.Text
$source=Split-Path -Parent $CanonicalSource
. (Join-Path $source 'tools/bootstrap_integrity.ps1')
. (Get-BootstrapSharedPortableLeaf $source)
. (Join-Path $source 'tools/container_writer_fence.ps1')
$definitions=$ast.FindAll({param($n)
    if($n -isnot [Management.Automation.Language.FunctionDefinitionAst]){return $false}
    $parent=$n.Parent
    while($parent){if($parent -is [Management.Automation.Language.FunctionDefinitionAst]){return $false};$parent=$parent.Parent}
    return $true
},$true)
foreach($definition in $definitions){Invoke-Expression $definition.Extent.Text}
$inner=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains('if (-not $enteredPlacementTry)')},$true))
$outer=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text.Contains("`$publicMessage='FAILED_PREPARATION_ADMISSION'")},$true))
if($inner.Count -ne 1 -or $outer.Count -ne 1){throw 'actual catch boundary differs'}
$body=$inner[0].Parent.Body
$stopCommand=@($body.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Stop-CanonicalInstallerRelayPreimage'},$true))
$auditSave=@($body.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Save' -and $n.Extent.Text -ceq 'Save $auditPath $audit $true'},$true) | Sort-Object {$_.Extent.StartOffset} | Select-Object -First 1)
if($stopCommand.Count -ne 1 -or $auditSave.Count -ne 1){throw 'actual preparation route differs'}
$stopStatement=$stopCommand[0]
while($stopStatement.Parent -ne $body){$stopStatement=$stopStatement.Parent}
$preambleStart=$stopStatement.Extent.StartOffset
$preambleEnd=$auditSave[0].Extent.EndOffset
$preamble=$canonicalText.Substring($preambleStart,$preambleEnd-$preambleStart)
if($Phase -ceq 'after-stop'){
    $cut=$stopStatement.Extent.EndOffset-$preambleStart
    $preamble=$preamble.Insert($cut,"`nInvoke-FixtureEarlyFailure`n")
}
$innerBody=$inner[0].Body.Extent.Text
$innerBody=$innerBody.Substring(1,$innerBody.Length-2)
$outerBody=$outer[0].Body.Extent.Text
$outerBody=$outerBody.Substring(1,$outerBody.Length-2)
$scanTokens=$null;$scanErrors=$null
$scan=[Management.Automation.Language.Parser]::ParseInput($preamble+"`n"+$innerBody+"`n"+$outerBody,[ref]$scanTokens,[ref]$scanErrors)
foreach($variable in @($scan.FindAll({param($n) $n -is [Management.Automation.Language.VariableExpressionAst]},$true))){
    if($variable.VariablePath.IsUnscopedVariable){
        $name=$variable.VariablePath.UserPath
        if($name -notin @('_','PSItem','LASTEXITCODE') -and -not(Get-Variable -Name $name -ErrorAction SilentlyContinue)){Set-Variable -Name $name -Value $null}
    }elseif($variable.VariablePath.IsScript){
        $name=$variable.VariablePath.UserPath.Substring(7)
        if(-not(Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue)){Set-Variable -Name $name -Scope Script -Value $null}
    }
}
[void][IO.Directory]::CreateDirectory($Root)
$script:FixtureRoot=[IO.Path]::GetFullPath($Root)
$install=Join-Path $Root 'current';[void][IO.Directory]::CreateDirectory($install)
$activeRelayRoot=Join-Path $Root 'state'
$stop=Join-Path $activeRelayRoot 'control/container_audit_user_relay.stop.json'
$relayPath=Join-Path $activeRelayRoot 'status/container_audit_user_relay.json'
$auditPath=Join-Path $Root 'audit.json';$auditRoot=$Root
$evidenceFull=Join-Path $Root 'evidence.json'
$codePath=Join-Path $install 'installed-code.dat'
[IO.File]::WriteAllText($codePath,'immutable-installed-code')
$codeBefore=Sha $codePath
$executable=Join-Path $install 'runtime/pythonw.exe'
$command='"'+$executable+'" -I -B "'+(Join-Path $install 'app/main.py')+'" --container-audit-user-relay'
$wanted=$command;$runId='fixture-early-recovery'
$operatorSid='S-1-5-21-109'
$runPath=Join-Path $Root 'run.json'
$before=[pscustomobject]@{exists=$true;kind='String';data=$command}
[IO.File]::WriteAllText($runPath,($before|ConvertTo-Json -Compress))
$runBefore=Sha $runPath
$oldSha='d3a1ad7b2364aae808c36a2359b18b04f92025e2'
$script:NativeProcess=[pscustomobject]@{ProcessId=8101;CreationDate=[DateTime]::UtcNow.AddMinutes(-5);ExecutablePath=$executable;CommandLine=$command}
$old=@([pscustomobject]@{ProcessId=$script:NativeProcess.ProcessId;CreationDate=$script:NativeProcess.CreationDate;ExecutablePath=$executable;CommandLine=$command})
Initialize-BootstrapRelaySecurity
$script:NativeSecurity=[KMTechBootstrapRelaySecurity+Security]::new()
$script:NativeSecurity.sid=$operatorSid;$script:NativeSecurity.session_id=3
$script:NativeSecurity.integrity_level=8192;$script:NativeSecurity.elevated=$false
$script:NativeLive=$true;$script:StopCalls=0;$script:Restarts=0;$script:StopDeletes=0
$script:ForwardActive=$true;$script:FailureInjected=$false;$script:MarkerAtFailure=''
$script:Events=[Collections.Generic.List[object]]::new()
$Script:CanonicalWriterFenceSessionId='1234567890abcdef1234567890abcdef'
$Script:CanonicalWriterFenceAttemptId='2234567890abcdef1234567890abcdef'
$Script:CanonicalWriterFenceTransactionId='3234567890abcdef1234567890abcdef'
$Script:CanonicalWriterFenceDelegationToken=[Guid]::NewGuid().ToString('N')
$Script:CanonicalInstallerRelayStopAttempted=$false
$Script:CanonicalInstallerRelayStopOwnership=$null;$Script:CanonicalInstallerEarlyRecovery=$null
$Script:CanonicalRelayProof=$null;$Script:CanonicalRollbackRelayCandidate=$null
$Script:CanonicalPreparationAdmissionFailed=$false
$canonicalWriterFencePreparedPath=Join-Path $Root 'prepared.json'
$canonicalWriterFenceAuthority=[pscustomobject]@{name='fixture-authority'}
$canonicalWriterFenceActive=$false;$enteredPlacementTry=$false;$testMode=$false
$sourceManifest=[pscustomobject]@{source_commit='a'*40}
$sourceManifestSha256='b'*64;$writerBefore=[pscustomobject]@{classification='ABSENT';restore_required=$false}
$fencePath=Join-Path $Root 'fence.json'

function Relays {if($script:NativeLive){return $script:NativeProcess};return @()}
function Snapshot {return Get-Content -LiteralPath $runPath -Raw -Encoding UTF8 | ConvertFrom-Json}
function Get-CanonicalOperatorSecurity {return $script:NativeSecurity}
function Get-CanonicalRelaySecurity {param($ProcessId) return $script:NativeSecurity}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) if($script:NativeLive){return $script:NativeProcess};return $null}
function Get-CanonicalInstallerProductWriters {param($Root) return Relays}
function Get-CanonicalGlobalRelayPreimage {return @([ordered]@{process_id=$script:NativeProcess.ProcessId;session_id=$script:NativeSecurity.session_id})}
function Write-InstallationEvidenceEvent {param($Event) $script:Events.Add($Event)}
function Invoke-ContainerSourceDataAdmission {}
function Fail-InstallationEvidenceStages {}
function Set-InstallationEvidenceStage {}
function Write-InstallationCaughtFailure {}
function ConvertTo-KmtechRedactedSinkText {param($Text,[switch]$UserLine) return 'INJECTED_EARLY_FAILURE'}
function Get-CanonicalFailureDetails {param($Failure,$Stage) return [ordered]@{exception_types=@($Failure.Exception.GetType().FullName);script_line=0}}
function Write-CanonicalInstallReentryRecord {}
function Get-BootstrapRelayExpectedIdentity {
    param($Root,$RunCommand)
    return [pscustomobject]@{root=$Root;install_root=$Root;managed=$false;source_commit=$oldSha;manifest_sha256='b'*64;aggregate_sha256='c'*64;
        executable=$executable;command=$RunCommand;run_command=$RunCommand;requires_status_identity=$true;operator_sid=$operatorSid}
}
function Get-BootstrapRelayReadinessSnapshot {param($Identity) return [pscustomobject]@{identity=$Identity;settled=$true;phase='UNMANAGED'}}
function StartRaw {
    param($RunCommand)
    $script:Restarts++
    if(Test-Path -LiteralPath $stop){throw 'fixture old relay exited on retained stop marker'}
    if($RunCommand -cne $command){throw 'fixture Run command changed'}
    $script:NativeProcess=[pscustomobject]@{ProcessId=8102;CreationDate=[DateTime]::UtcNow;ExecutablePath=$executable;CommandLine=$command}
    $script:NativeLive=$true
    $status=[ordered]@{report_version='container-audit-user-relay-v1';status='RUNNING';principal='current_user';persistent_retry=$true;
        process_id=$script:NativeProcess.ProcessId;updated_at=[DateTime]::UtcNow.ToString('o');source_commit=if($Case -ceq 'bad-ready'){'e'*40}else{$oldSha};ordinary_user=$true}
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $relayPath))
    [IO.File]::WriteAllText($relayPath,($status|ConvertTo-Json -Compress))
    return 8102
}
function Invoke-InstallationEvidenceChild {
    param($Name,$File,$Arguments)
    if($Name -cne 'installer-normal-relay-stop' -or $Arguments[0] -cne '-I' -or $Arguments[2] -cne '-c'){throw 'fixture unexpected child boundary'}
    $script:StopCalls++
    # Keep iwrun guards in this finite child. Only the native machine boundary
    # is replaced; the product probe and actual atomic stop publisher both run.
    $probe="import pathlib, sys; sys.path.insert(0,sys.argv[1]); import runtime_instance_win32; runtime_instance_win32.known_program_data=lambda:pathlib.Path(sys.argv[2])/'machine-boundary'`n"+[string]$Arguments[3]
    $raw=@(& $Python -B -c $probe ([string]$Arguments[4]) ([string]$Arguments[5]) ([string]$Arguments[6]))
    $exitCode=$global:LASTEXITCODE
    $script:ChildExitCode=$exitCode
    $script:ChildProtocolMatches=(($raw -join "`n").Trim() -ceq 'installer_relay_stop=ABSENT')
    if($exitCode -eq 0){$script:NativeLive=$false}
    return [pscustomobject]@{ExitCode=$exitCode;Stdout=($raw -join "`n");Stderr='';EvidenceFailure=$null}
}
function Invoke-FixtureEarlyFailure {
    $script:FailureInjected=$true
    if($Case -ceq 'foreign-marker'){
        $marker=Get-Content -LiteralPath $stop -Raw -Encoding UTF8 | ConvertFrom-Json
        $marker.request_id=[Guid]::NewGuid().ToString('N')
        [IO.File]::WriteAllText($stop,($marker|ConvertTo-Json -Compress))
    }elseif($Case -ceq 'same-id-changed'){
        [IO.File]::AppendAllText($stop,"`n")
    }elseif($Case -ceq 'missing-proof'){$Script:CanonicalInstallerRelayStopOwnership=$null}
    $script:MarkerAtFailure=Sha $stop
    throw 'INJECTED_EARLY_FAILURE'
}
function New-CanonicalWriterFencePreparedReceipt {
    param($Path,$SessionId,$AttemptId,$ReplacementTransactionId,$SessionStartedAtUtc,$OrchestratorSha256,$WriterContractSha256,$SourceManifestSha256,$OperatorSid,$OperatorLocalAppDataRoot)
    [IO.File]::WriteAllText($Path,'fixture-prepared')
    return [pscustomobject]@{path=$Path;sha256=Sha $Path}
}
function Start-ContainerWriterFence {
    param($Status,$OwnerKind,$SessionId,$AttemptId,$ReplacementTransactionId,$SessionStartedAtUtc,$OrchestratorSha256,$WriterContractSha256,$PreparedReceiptPath,$PreparedReceiptSha256,$DelegationToken,$DelegatedSources,$DelegationExpiresAtUtc,$AuthorityLease)
    if($Phase -ceq 'before-fence'){Invoke-FixtureEarlyFailure}
    [IO.File]::WriteAllText($fencePath,(@{session_id=$SessionId;attempt_id=$AttemptId;replacement_transaction_id=$ReplacementTransactionId}|ConvertTo-Json -Compress))
}
function Read-ContainerWriterFence {param([switch]$AllowAbsent) if(Test-Path -LiteralPath $fencePath){return Get-Content -LiteralPath $fencePath -Raw | ConvertFrom-Json};return $null}
function Abort-ContainerWriterFence {
    param($SessionId,$AttemptId,$ReplacementTransactionId,$AuthorityLease)
    [IO.File]::Delete($fencePath)
}
function Save {
    param($Path,$Value,[bool]$AlreadyLocked)
    if($script:ForwardActive -and $Phase -ceq 'before-audit' -and $Path -ceq $auditPath){Invoke-FixtureEarlyFailure}
    Write-Utf8Json $Path $Value
}
$nativeRemove=(Get-Command Microsoft.PowerShell.Management\Remove-Item)
function Remove-Item {
    param([string]$LiteralPath,$ErrorAction)
    $resolved=[IO.Path]::GetFullPath($LiteralPath)
    if(-not $resolved.StartsWith(($script:FixtureRoot.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'fixture removal escaped root'}
    if(Same $resolved $stop){$script:StopDeletes++}
    & $nativeRemove -LiteralPath $resolved -ErrorAction Stop
}
try {
    try {. ([scriptblock]::Create($preamble))}
    catch {
        $script:ForwardFailureType=$_.Exception.GetType().FullName
        $script:ForwardFailureLine=$_.InvocationInfo.ScriptLineNumber
        $script:ForwardFailureStaticCode=if($_.Exception.Message -cmatch '^[A-Z][A-Z_]+$'){$_.Exception.Message}else{''}
        $script:ForwardActive=$false;. ([scriptblock]::Create($innerBody))
    }
} catch {
    . ([scriptblock]::Create($outerBody))
} finally {
    $markerUnchanged=$false
    if(Test-Path -LiteralPath $stop){$markerUnchanged=((Sha $stop) -ceq $script:MarkerAtFailure)}
    $recovery=$Script:CanonicalInstallerEarlyRecovery
    $causePreserved=$false
    $failureRecord=Get-Variable -Name outputFailure -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $failureRecord){
        $cause=$failureRecord.Exception
        while($null -ne $cause){
            if($cause.Message -ceq 'INJECTED_EARLY_FAILURE'){$causePreserved=$true}
            $cause=$cause.InnerException
        }
    }
    $result=[ordered]@{injected=$script:FailureInjected;stop_calls=$script:StopCalls;stop_deletes=$script:StopDeletes;
        forward_failure_type=$script:ForwardFailureType;forward_failure_line=$script:ForwardFailureLine;forward_failure_code=$script:ForwardFailureStaticCode;
        child_exit_code=$script:ChildExitCode;child_protocol_matches=$script:ChildProtocolMatches;
        original_cause_preserved=$causePreserved;
        marker_present=(Test-Path -LiteralPath $stop);marker_unchanged=$markerUnchanged;
        run_unchanged=((Sha $runPath) -ceq $runBefore);code_unchanged=((Sha $codePath) -ceq $codeBefore);
        restarts=$script:Restarts;resident_present=$script:NativeLive;fence_present=(Test-Path -LiteralPath $fencePath);
        prepared_present=(Test-Path -LiteralPath $canonicalWriterFencePreparedPath);recovery=$recovery;
        audit_present=(Test-Path -LiteralPath $auditPath);events=@($script:Events | ForEach-Object {[string]$_.event})}
    if(Test-Path -LiteralPath $auditPath){
        $saved=Get-Content -LiteralPath $auditPath -Raw -Encoding UTF8|ConvertFrom-Json
        if($saved.PSObject.Properties['installer_relay_recovery']){$result.audit_recovery=$saved.installer_relay_recovery}
    }
    [IO.File]::WriteAllText($Output,($result|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
}
