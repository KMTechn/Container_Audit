# Loaded by the existing actual outer-catch/G harness, after its native boundaries.
trap {
    [IO.File]::WriteAllText(($Output+'.candidate-failure.json'),([ordered]@{exception_type=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber;file=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName)}|ConvertTo-Json -Compress))
    break
}
$candidateDefinitions=$ast.FindAll({param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @(
        'Product','Test-CanonicalOrdinaryRelaySecurity','Save-CanonicalRollbackRelayCandidate','Assert-CanonicalRollbackRelayCandidate','Assert-CanonicalRollbackStopCleanup')
},$true)
if($candidateDefinitions.Count -ne 5){throw 'candidate fixture functions differ'}
foreach($definition in $candidateDefinitions){Invoke-Expression $definition.Extent.Text}
$Script:CanonicalWriterFenceTransactionId='1234567890abcdef1234567890abcdef'
$script:CandidateCaller=[pscustomobject]@{sid=$operatorSid;session_id=1;elevated=$false;integrity_level=8192}
$script:CandidateSecurity=[pscustomobject]@{sid=$operatorSid;session_id=1;elevated=$false;integrity_level=8192}
$executable=Join-Path $Root 'relay.exe'
$command='"'+$executable+'" -I -B "'+(Join-Path $Root 'app\main.py')+'" --container-audit-user-relay'
$script:CandidateProcess=[pscustomobject]@{ProcessId=4242;CreationDate=[DateTime]::UtcNow;ExecutablePath=$executable;CommandLine=$command}
$script:CandidateLive=$true;$script:CandidateStopCalls=0
$script:CandidateOriginalPid=$script:CandidateProcess.ProcessId
$script:CandidateOriginalBirth=$script:CandidateProcess.CreationDate
function Get-CanonicalOperatorSecurity {return $script:CandidateCaller}
function Get-CanonicalRelaySecurity {param($ProcessId) return $script:CandidateSecurity}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) if($script:CandidateLive){return $script:CandidateProcess};return $null}
function Relays {
    if($script:CandidateLive){return $script:CandidateProcess}
    if($script:state.relay -ceq 'before'){return $old}
    return @()
}
Save-CanonicalRollbackRelayCandidate $script:CandidateProcess $script:CandidateSecurity $script:CandidateCaller ([DateTime]::UtcNow.AddSeconds(-1))
switch -CaseSensitive ($RecoveryCase){
    'relay-other-session' {$script:CandidateSecurity.session_id=2}
    'relay-other-sid' {$script:CandidateSecurity.sid='S-1-5-18'}
    'relay-pid-reused' {$script:CandidateProcess.CreationDate=$script:CandidateProcess.CreationDate.AddSeconds(1)}
    'relay-other-pid' {$script:CandidateProcess.ProcessId=4243}
    'relay-no-candidate' {$Script:CanonicalRollbackRelayCandidate=$null}
    'relay-other-round' {$Script:CanonicalRollbackRelayCandidate.transaction_id='abcdef1234567890abcdef1234567890'}
    'relay-same-session' {}
    default {throw 'candidate fixture case differs'}
}
$script:CandidateOriginalPid=$script:CandidateProcess.ProcessId
$script:CandidateOriginalBirth=$script:CandidateProcess.CreationDate
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $stop))
[IO.File]::WriteAllText($stop,'preserved pre-existing marker bytes')
$script:CandidateMarkerBefore=[IO.File]::ReadAllBytes($stop)
$script:CandidateChildOriginal=(Get-Command Invoke-InstallationEvidenceChild).ScriptBlock
function Invoke-InstallationEvidenceChild {
    param($Name,$File,$Arguments)
    if($Name -ceq 'productremove-current-user-setup'){
        $script:observed.product_removal++;$script:CandidateStopCalls++
        $script:CandidateLive=$false;$script:state.relay='after';$script:state.run='after'
        [IO.File]::WriteAllText($stop,'owned candidate stop requested')
        return [pscustomobject]@{ExitCode=0;Stdout='';Stderr='';ProcessId=4244}
    }
    & $script:CandidateChildOriginal $Name $File $Arguments
}
$script:CandidateRemoveOriginal=(Get-Command Remove-Item).ScriptBlock
function Remove-Item {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    if($LiteralPath -ceq $stop){
        $script:CandidateMarkerRemovalCalls++
        [IO.File]::Delete($LiteralPath)
        return
    }
    & $script:CandidateRemoveOriginal @PSBoundParameters
}
$script:CandidateMarkerRemovalCalls=0
function Get-RelayCandidateFixtureObservation {
    $markerSame=$false
    if([IO.File]::Exists($stop)){
        $hash=[Security.Cryptography.SHA256]::Create()
        try{$markerSame=([BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($stop))) -ceq [BitConverter]::ToString($hash.ComputeHash($script:CandidateMarkerBefore)))}finally{$hash.Dispose()}
    }
    return [ordered]@{stop_calls=$script:CandidateStopCalls;marker_removal_calls=$script:CandidateMarkerRemovalCalls;
        marker_unchanged=$markerSame;candidate_alive=$script:CandidateLive;
        pid_birth_unchanged=($script:CandidateProcess.ProcessId -eq $script:CandidateOriginalPid -and $script:CandidateProcess.CreationDate -eq $script:CandidateOriginalBirth);
        guard_refused=[bool](Get-Variable -Name CanonicalRollbackRelayStopRefused -Scope Script -ValueOnly -ErrorAction SilentlyContinue)}
}
