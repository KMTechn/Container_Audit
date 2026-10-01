$BootstrapIntegrityFileName = "bootstrap-integrity.json"
$BootstrapIntegritySchema = "container-audit-bootstrap-integrity-v1"

function Protect-InstallationText([string]$Text, [int]$Limit = 4096) {
    # Same known-value replacement and message markers as the runtime redactors.
    $values = [Collections.Generic.List[string]]::new()
    $known = Get-Variable -Name InstallationEvidenceSensitiveValues -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $known) { foreach ($value in $known.Value) { if ($value -is [string] -and $value.Length) { $values.Add($value) } } }
    foreach ($name in @('CanonicalWriterFenceDelegationToken','WriterFenceDelegationToken')) {
        $value = Get-Variable -Name $name -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($value -is [string] -and $value.Length) { $values.Add($value) }
    }
    foreach ($value in $values) { if ($value -is [string] -and $value.Length) { $Text = $Text.Replace($value, '[redacted]') } }
    $lines = @($Text -split '(?<=\n)' | ForEach-Object {
        if ($_ -match '(?i)canonical signed request|hmac_key|producer_signature|raw_payload|raw_secret|receipt_json|secret_hex|should-not-leak|source_file_bytes|source_file_text|x-producer-signature') { '[REDACTED]' + "`n" }
        else { $_ }
    })
    $Text = $lines -join ''
    $Text = [regex]::Replace($Text, '(?i)authorization\s*:\s*[^\r\n]+', '[redacted]')
    $Text = [regex]::Replace($Text, '(?i)\b([A-Za-z0-9_-]*(?:secret|token|signature|password|credential|registration[_-]?(?:value|code)|api[_-]?key)[A-Za-z0-9_-]*)\s*[=:]\s*[^\r\n,;]+', '$1=[redacted]')
    $Text = [regex]::Replace($Text, '(?i)("[^"]*(?:secret|token|signature|password|registration|api[_-]?key|authorization|credential)[^"]*"\s*:\s*")(?:\\.|[^"\\])*', '$1[redacted]')
    $Text = [regex]::Replace($Text, '(https?://)[^\s/@]+:[^\s/@]+@', '$1[redacted]@')
    $Text = [regex]::Replace($Text, '(https?://[^\s?]+)\?[^\s]+', '$1?[redacted]')
    if ($Limit -ge 0 -and $Text.Length -gt $Limit) { return $Text.Substring(0,$Limit) + '[truncated]' }
    return $Text
}

function Get-InstallationFailureDetails($Failure) {
    $line = 0; $file = ''
    if ($Failure -is [Exception]) { $exception = $Failure }
    else {
        $exception = $Failure.Exception
        if ($null -ne $Failure.InvocationInfo) {
            $line = [int]$Failure.InvocationInfo.ScriptLineNumber
            $file = [IO.Path]::GetFileName([string]$Failure.InvocationInfo.ScriptName)
        }
    }
    $chain = @()
    for ($depth=0; $null -ne $exception -and $depth -lt 8; $depth++) {
        $native = $null; if ($exception -is [ComponentModel.Win32Exception]) { $native = $exception.NativeErrorCode }
        $chain += [ordered]@{type=$exception.GetType().FullName; message=(Protect-InstallationText $exception.Message); hresult=$exception.HResult; win32_error=$native}
        $exception = $exception.InnerException
    }
    return [ordered]@{script_file=$file;script_line=$line;exception_chain=$chain}
}

function Set-InstallationEvidenceAcl([string]$Path, [string]$Sid, [switch]$Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($Sid))
    foreach ($identity in @($Sid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $principal = [Security.Principal.SecurityIdentifier]::new($identity)
        if ($Directory) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow') }
        else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','Allow') }
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Initialize-InstallationEvidence([string]$BasePath,[string]$OperatorSid,[string[]]$SensitiveValues=@()) {
    $root = Get-StrictFullPath ($BasePath + '.evidence.' + $PID) 'installation evidence root'
    $parent=Split-Path -Parent $root
    $existing=$parent
    while (-not (Test-Path -LiteralPath $existing)) { $existing=Split-Path -Parent $existing }
    Assert-BootstrapNoReparsePoint $existing 'installation evidence ancestor' -PathOnly
    if (Test-Path -LiteralPath $root) { throw 'Installation evidence directory already exists.' }
    [void][IO.Directory]::CreateDirectory($root)
    Set-InstallationEvidenceAcl $root $OperatorSid -Directory
    $Script:InstallationEvidenceRoot = $root
    $Script:InstallationEvidenceSid = $OperatorSid
    $Script:InstallationEvidenceSensitiveValues = @($SensitiveValues)
    $Script:InstallationEvidenceLanes = @{}
    $Script:InstallationEvidenceSequence = 0
    $Script:InstallationEvidenceFailed = $false
    $Script:InstallationEvidenceFailureCodes = [Collections.Generic.List[string]]::new()
    Write-InstallationEvidenceEvent ([ordered]@{event='INITIALIZED';process_id=$PID;byte_cap_per_stream=1048576;journal_cap_bytes=1048576;raw_command_recorded=$false})
    return $root
}

function Write-InstallationEvidenceEvent($Payload) {
    $root = Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $root) { return }
    try {
        $path=Join-Path $root 'stages.jsonl'
        $Payload['captured_at']=[DateTime]::UtcNow.ToString('o')
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Payload | ConvertTo-Json -Depth 12 -Compress)+"`n")
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length + $bytes.Length -gt 1048576) {
            $Script:InstallationEvidenceFailed=$true
            if(-not $Script:InstallationEvidenceFailureCodes.Contains('JOURNAL_LIMIT')){$Script:InstallationEvidenceFailureCodes.Add('JOURNAL_LIMIT')}
            return
        }
        $newFile=-not (Test-Path -LiteralPath $path)
        $stream=[IO.FileStream]::new($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ($newFile) { Set-InstallationEvidenceAcl $path $Script:InstallationEvidenceSid }
    } catch {
        $Script:InstallationEvidenceFailed=$true
        if(-not $Script:InstallationEvidenceFailureCodes.Contains('JOURNAL_IO_OR_ACL_FAILURE')){$Script:InstallationEvidenceFailureCodes.Add('JOURNAL_IO_OR_ACL_FAILURE')}
    }
}

function Complete-InstallationEvidence {
    $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $failed=Get-Variable -Name InstallationEvidenceFailed -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $codes=Get-Variable -Name InstallationEvidenceFailureCodes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $summary=[ordered]@{status=if(-not $root){'NOT_CONFIGURED'}elseif($failed){'INCOMPLETE'}else{'COMPLETE'};
        recording_failed=[bool]$failed;root=[string]$root;journal_cap_bytes=1048576;failure_codes=@($codes);
        summary_path='';summary_written=$false;business_result_is_separate=$true}
    if(-not $root){return $summary}
    $summary.summary_path=Join-Path $root 'evidence-status.json'
    try {
        $summary.summary_written=$true
        [IO.File]::WriteAllText($summary.summary_path,($summary|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
        Set-InstallationEvidenceAcl $summary.summary_path $Script:InstallationEvidenceSid
    }catch {
        $Script:InstallationEvidenceFailed=$true
        $summary.status='INCOMPLETE';$summary.recording_failed=$true;$summary.summary_written=$false
        # If writing succeeded before an ACL/readback failure, replace the
        # success-looking body where possible; stdout still carries INCOMPLETE.
        try{[IO.File]::WriteAllText($summary.summary_path,($summary|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))}catch{}
        $summary.failure_codes+=@('FINAL_SUMMARY_IO_OR_ACL_FAILURE')
    }
    return $summary
}

function Register-InstallationChildEvidenceSummary($Summary) {
    if($null -eq $Summary -or [string]$Summary.status -cne 'COMPLETE'){
        $Script:InstallationEvidenceFailed=$true
        $codes=Get-Variable -Name InstallationEvidenceFailureCodes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $codes -and -not $codes.Contains('CHILD_EVIDENCE_INCOMPLETE')){$codes.Add('CHILD_EVIDENCE_INCOMPLETE')}
    }
}

function Read-InstallationEvidenceChildSummary([string]$Root) {
    $path=Join-Path $Root 'evidence-status.json'
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){return [ordered]@{status='INCOMPLETE';recording_failed=$true;summary_path=$path;reason='CHILD_SUMMARY_NOT_RECORDED'}}
    Assert-BootstrapNoReparsePoint $path 'child evidence summary' -PathOnly
    if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Child evidence summary is oversized.'}
    $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    if(-not(Test-BootstrapSamePath ([string]$record.root) $Root) -or [string]$record.status -cnotin @('COMPLETE','INCOMPLETE') -or
        $record.recording_failed -isnot [bool] -or ($record.status -ceq 'COMPLETE' -and $record.recording_failed)){throw 'Child evidence summary binding differs.'}
    return [ordered]@{status=[string]$record.status;recording_failed=[bool]$record.recording_failed;summary_path=$path;summary_sha256=Get-FileSha256 $path}
}

function Read-InstallationHelperEvidenceBinding([string[]]$Output,[string]$AuditLogPath,[int]$DirectProcessId,[string]$ExpectedHelperSha256='') {
    $roots=@($Output | Where-Object {$_ -cmatch '^installation_stage_evidence_root=.+$'} | ForEach-Object {$_.Substring('installation_stage_evidence_root='.Length)})
    $results=@($Output | Where-Object {$_ -cmatch '^installation_elevation_result_path=.+$'} | ForEach-Object {$_.Substring('installation_elevation_result_path='.Length)})
    $parentRoot=Get-StrictFullPath ($AuditLogPath+'.evidence.'+$DirectProcessId) 'helper evidence root'
    if($results.Count) {
        $path=Get-StrictFullPath ([string]$results[-1]) 'elevation result'
        if(-not(Test-BootstrapSamePath $path (Join-Path $parentRoot 'elevation-result.json'))){throw 'Elevation result path binding differs.'}
        Assert-BootstrapNoReparsePoint $path 'elevation result' -PathOnly
        if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Elevation result is oversized.'}
        $result=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if([string]$result.schema -cne 'container-audit-installation-elevation-capture-v1' -or
            -not(Test-BootstrapJsonInteger $result.parent_process_id) -or [int64]$result.parent_process_id -ne $DirectProcessId -or
            -not(Test-BootstrapJsonInteger $result.wrapper_process_id) -or [int64]$result.wrapper_process_id -le 0 -or
            -not(Test-BootstrapJsonInteger $result.helper_process_id) -or [int64]$result.helper_process_id -lt 0 -or
            ($ExpectedHelperSha256 -and [string]$result.helper_sha256 -cne $ExpectedHelperSha256)){throw 'Elevation result identity binding differs.'}
        $expectedCapture=Join-Path $parentRoot ('elevation-capture.evidence.'+[int]$result.wrapper_process_id)
        if(-not(Test-BootstrapSamePath ([string]$result.capture_root) $expectedCapture)){throw 'Elevation capture root binding differs.'}
        Assert-BootstrapNoReparsePoint $expectedCapture 'elevation capture root' -PathOnly
        if([int64]$result.helper_process_id -eq 0) {
            if([int]$result.helper_exit_code -eq 0 -or $null -eq $result.failure -or $null -ne $result.streams -or [string]$result.helper_stage_evidence_root){throw 'Unstarted helper failure binding differs.'}
            return [ordered]@{status='CHILD_NOT_STARTED';helper_process_id=0;stage_evidence_root='';outer_stage_evidence_root=$parentRoot;
                capture_root=$expectedCapture;streams=$null;child_exit_code=[int]$result.helper_exit_code;failure=$result.failure;
                result_path=$path;result_sha256=Get-FileSha256 $path;evidence_summary=$result.evidence_summary}
        }
        foreach($name in @('stdout','stderr')) {
            $stream=$result.streams.$name
            $expected=Join-Path $expectedCapture ('elevated-helper-'+[int]$result.helper_process_id+'-'+$name+'.bin')
            if(-not(Test-BootstrapSamePath ([string]$stream.path) $expected)){throw 'Elevation stream path binding differs.'}
            Assert-BootstrapNoReparsePoint $expected 'elevation stream' -PathOnly
            if((Get-Item -LiteralPath $expected).Length -gt 1048576 -or (Get-FileSha256 $expected) -cne [string]$stream.sha256){throw 'Elevation stream hash/size binding differs.'}
        }
        $actualRoot=[string]$result.helper_stage_evidence_root
        if($actualRoot -and -not(Test-BootstrapSamePath $actualRoot ($AuditLogPath+'.evidence.'+[int]$result.helper_process_id))){throw 'Elevated helper journal identity binding differs.'}
        if($actualRoot){Assert-BootstrapNoReparsePoint $actualRoot 'elevated helper evidence' -PathOnly}
        $childSummary=if($actualRoot){Read-InstallationEvidenceChildSummary $actualRoot}else{$null}
        Register-InstallationChildEvidenceSummary $result.evidence_summary
        Register-InstallationChildEvidenceSummary $childSummary
        return [ordered]@{status=if($actualRoot){'BOUND_ELEVATED_CHILD'}else{'CHILD_JOURNAL_NOT_RECORDED'};helper_process_id=[int]$result.helper_process_id;
            stage_evidence_root=$actualRoot;outer_stage_evidence_root=$parentRoot;capture_root=$expectedCapture;streams=$result.streams;
            child_exit_code=[int]$result.helper_exit_code;failure=$result.failure;result_path=$path;result_sha256=Get-FileSha256 $path;evidence_summary=$result.evidence_summary;child_stage_evidence_summary=$childSummary}
    }
    if(-not $roots.Count){return [ordered]@{status='NOT_RECORDED';helper_process_id=$DirectProcessId;stage_evidence_root='';streams=$null}}
    $root=Get-StrictFullPath ([string]$roots[-1]) 'helper emitted evidence root'
    if(-not(Test-BootstrapSamePath $root $parentRoot)){throw 'Direct helper evidence root binding differs.'}
    Assert-BootstrapNoReparsePoint $root 'helper emitted evidence root' -PathOnly
    $childSummary=Read-InstallationEvidenceChildSummary $root
    Register-InstallationChildEvidenceSummary $childSummary
    return [ordered]@{status='BOUND_DIRECT_CHILD';helper_process_id=$DirectProcessId;stage_evidence_root=$root;streams=$null;child_stage_evidence_summary=$childSummary}
}

function Get-InstallationElevationWrapperSource {
    # Fixed source only. Invocation arguments, including delegation, remain
    # in memory/argv and are never embedded in the persisted wrapper.
    return @'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($args.Count -lt 8){exit 1}
$target=[string]$args[0];$resultPath=[string]$args[1];$auditBase=[string]$args[2];$sid=[string]$args[3]
$parentPid=[int]$args[4];$targetSha=[string]$args[5];$librarySha=[string]$args[6]
$childArgs=[string[]]@($args | Select-Object -Skip 7)
$library=Join-Path (Split-Path -Parent $target) 'tools\bootstrap_integrity.ps1'
if((Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant() -cne $librarySha){exit 1}
. $library
$index=[Array]::IndexOf($childArgs,'-WriterFenceDelegationToken')
$sensitive=@();if($index -ge 0 -and $index+1 -lt $childArgs.Length){$sensitive=@($childArgs[$index+1])}
$captureRoot=Initialize-InstallationEvidence (Join-Path (Split-Path -Parent $resultPath) 'elevation-capture') $sid $sensitive
$child=$null;$failure=$null;$helperRoot='';$exitCode=1
try {
 if((Get-FileSha256 $target) -cne $targetSha){throw 'Elevated helper source byte pin differs.'}
 Set-InstallationEvidenceStage 'elevation.helper_capture'
 $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
 $child=Invoke-InstallationEvidenceChild 'elevated-helper' $winps $childArgs
 $exitCode=[int]$child.ExitCode
 $roots=@($child.Stdout -split "`r?`n" | Where-Object {$_ -cmatch '^installation_stage_evidence_root=.+$'} | ForEach-Object {$_.Substring('installation_stage_evidence_root='.Length)})
 if($roots.Count){
  $helperRoot=Get-StrictFullPath ([string]$roots[-1]) 'elevated helper emitted root'
  if(-not(Test-BootstrapSamePath $helperRoot ($auditBase+'.evidence.'+$child.ProcessId))){throw 'Elevated helper emitted journal binding differs.'}
  Assert-BootstrapNoReparsePoint $helperRoot 'elevated helper journal' -PathOnly
 }
 Complete-InstallationEvidenceStage 'forward'
}catch{$failure=Get-InstallationFailureDetails $_;Fail-InstallationEvidenceStages $_;$exitCode=1}
$summary=Complete-InstallationEvidence
$record=[ordered]@{schema='container-audit-installation-elevation-capture-v1';parent_process_id=$parentPid;wrapper_process_id=$PID;
 helper_process_id=if($null -ne $child){[int]$child.ProcessId}else{0};helper_exit_code=$exitCode;helper_sha256=$targetSha;
 helper_stage_evidence_root=$helperRoot;capture_root=$captureRoot;streams=if($null -ne $child){$child.Streams}else{$null};
 evidence_summary=$summary;failure=$failure;raw_arguments_recorded=$false;secret_values_recorded=$false}
Assert-BootstrapNoReparsePoint (Split-Path -Parent $resultPath) 'elevation result parent' -PathOnly
if(Test-Path -LiteralPath $resultPath){throw 'Elevation result already exists.'}
[IO.File]::WriteAllText($resultPath,($record|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
Set-InstallationEvidenceAcl $resultPath $sid
exit $exitCode
'@
}

function Invoke-InstallationElevationCapture([string]$Target,[string[]]$Arguments,[string]$AuditBase,[string]$OperatorSid) {
    $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if(-not $root){throw 'Elevation capture requires initialized private evidence.'}
    Assert-BootstrapNoReparsePoint $root 'elevation capture parent' -PathOnly
    $wrapper=Join-Path $root 'elevation-capture.ps1';$resultPath=Join-Path $root 'elevation-result.json'
    if((Test-Path -LiteralPath $wrapper) -or (Test-Path -LiteralPath $resultPath)){throw 'Elevation capture target already exists.'}
    [IO.File]::WriteAllText($wrapper,(Get-InstallationElevationWrapperSource),[Text.UTF8Encoding]::new($true))
    Set-InstallationEvidenceAcl $wrapper $OperatorSid
    $library=Join-Path (Split-Path -Parent $Target) 'tools\bootstrap_integrity.ps1'
    $targetSha=Get-FileSha256 $Target
    $argv=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$wrapper,$Target,$resultPath,$AuditBase,$OperatorSid,
        [string]$PID,$targetSha,(Get-FileSha256 $library))+$Arguments
    $line=($argv|ForEach-Object {ConvertTo-ProcessArgument ([string]$_)}) -join ' '
    $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    # Verb RunAs cannot share RedirectStandardOutput/Error parameter sets.
    # The supported elevated wrapper captures its finite helper internally.
    $process=Start-Process -FilePath $winps -Verb RunAs -ArgumentList $line -WindowStyle Hidden -Wait -PassThru
    Assert-BootstrapNoReparsePoint $resultPath 'elevation result' -PathOnly
    if((Get-Item -LiteralPath $resultPath).Length -gt 65536){throw 'Elevation result is oversized.'}
    $result=Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$result.schema -cne 'container-audit-installation-elevation-capture-v1' -or
        -not(Test-BootstrapJsonInteger $result.parent_process_id) -or [int64]$result.parent_process_id -ne $PID -or
        -not(Test-BootstrapJsonInteger $result.wrapper_process_id) -or [int64]$result.wrapper_process_id -ne [int64]$process.Id -or
        [int]$result.helper_exit_code -ne [int]$process.ExitCode -or [string]$result.helper_sha256 -cne $targetSha){throw 'Elevated wrapper process/result binding differs.'}
    Write-InstallationEvidenceEvent ([ordered]@{event='ELEVATED_FINITE_CHILD';wrapper_pid=[int]$process.Id;helper_pid=[int]$result.helper_process_id;exit_code=[int]$process.ExitCode;result_path=$resultPath;result_sha256=Get-FileSha256 $resultPath})
    return [pscustomobject]@{ExitCode=[int]$process.ExitCode;Id=[int]$result.helper_process_id;WrapperProcessId=[int]$process.Id;ResultPath=$resultPath;
        HelperStageEvidenceRoot=[string]$result.helper_stage_evidence_root;Streams=$result.streams;EvidenceSummary=$result.evidence_summary}
}

function Import-BootstrapCanonicalUserProcessApi([string]$VerifiedProducerRoot) {
    $path=Join-Path $VerifiedProducerRoot 'INSTALL_CANONICAL_PORTABLE.ps1'
    Assert-BootstrapNoReparsePoint $path 'verified normal-user process API' -PathOnly
    $manifest=Read-KmtechPortableManifest $VerifiedProducerRoot
    if([string]$manifest.installer_sha256 -cnotmatch '^[0-9a-f]{64}$' -or (Get-FileSha256 $path) -cne [string]$manifest.installer_sha256){throw 'Normal-user process API byte pin differs.'}
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Normal-user process API source parse failed.'}
    $functions=@($tree.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Initialize-CanonicalUserProcessApi'})
    if($functions.Count -ne 1){throw 'Normal-user process API definition is ambiguous.'}
    Invoke-Expression $functions[0].Extent.Text
    Initialize-CanonicalUserProcessApi
    if($null -eq [ContainerAuditCanonicalUserProcess].GetMethod('StartLimitedWithOverrides')){throw 'Normal-user finite producer API is unsupported.'}
}

function Get-InstallationNormalProducerWrapperSource {
    return @'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($args.Count -lt 7){exit 1}
$library=[string]$args[0];$librarySha=[string]$args[1];$resultPath=[string]$args[2]
$parentPid=[int]$args[3];$sid=[string]$args[4];$executable=[string]$args[5]
$childArgs=[string[]]@($args|Select-Object -Skip 6)
if((Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant() -cne $librarySha){exit 1}
. $library
$sensitive=@([Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','Process'))
$root=Initialize-InstallationEvidence (Join-Path (Split-Path -Parent $resultPath) 'normal-producer-capture') $sid $sensitive
$child=$null;$failure=$null;$security=$null;$exitCode=1
try {
 $security=Get-BootstrapRelaySecurity $PID
 if($security.elevated -or $security.integrity_level -ne 8192 -or $security.sid -cne $sid -or $security.session_id -le 0){throw 'Finite lifecycle producer wrapper is not the ordinary operator.'}
 Set-InstallationEvidenceStage 'lifecycle.normal_producer_capture'
 $child=Invoke-InstallationEvidenceChild 'normal-producer' $executable $childArgs
 $exitCode=[int]$child.ExitCode
 Complete-InstallationEvidenceStage 'forward'
}catch{$failure=Get-InstallationFailureDetails $_;Fail-InstallationEvidenceStages $_}
$summary=Complete-InstallationEvidence
$record=[ordered]@{schema='container-audit-normal-producer-capture-v1';parent_process_id=$parentPid;wrapper_process_id=$PID;
 producer_process_id=if($null -ne $child){[int]$child.ProcessId}else{0};exit_code=$exitCode;security=$security;
 capture_root=$root;streams=if($null -ne $child){$child.Streams}else{$null};failure=$failure;evidence_summary=$summary;
 raw_arguments_recorded=$false;secret_values_recorded=$false}
Assert-BootstrapNoReparsePoint (Split-Path -Parent $resultPath) 'normal producer result parent' -PathOnly
if(Test-Path -LiteralPath $resultPath){throw 'Normal producer result already exists.'}
[IO.File]::WriteAllText($resultPath,($record|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
Set-InstallationEvidenceAcl $resultPath $sid
exit $exitCode
'@
}

function Start-BootstrapNormalProducerWrapper([string]$Line,$Caller,[string[]]$EnvironmentNames,[string[]]$EnvironmentValues) {
    return [ContainerAuditCanonicalUserProcess]::StartLimitedWithOverrides($Line,[string]$Caller.sid,[int]$Caller.session_id,$EnvironmentNames,$EnvironmentValues)
}

function Invoke-BootstrapNormalFiniteProducer([string]$VerifiedProducerRoot,[string]$Executable,[string[]]$Arguments,[string]$EvidenceBase) {
    $caller=Get-BootstrapRelaySecurity $PID
    if([int]$caller.session_id -le 0){throw 'Lifecycle producer requires the operator interactive session.'}
    $root=Initialize-InstallationEvidence ($EvidenceBase+'.normal') ([string]$caller.sid) @([Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','Process'))
    Set-InstallationEvidenceStage 'lifecycle.normal_producer_prepare'
    try {
    if(-not $caller.elevated){
        Set-InstallationEvidenceStage 'lifecycle.normal_producer_capture'
        $child=Invoke-InstallationEvidenceChild 'lifecycle-producer' $Executable $Arguments
        Complete-InstallationEvidenceStage 'forward';$summary=Complete-InstallationEvidence
        return [pscustomobject]@{ExitCode=$child.ExitCode;ProcessId=$child.ProcessId;Stdout=$child.Stdout;Stderr=$child.Stderr;
            Streams=$child.Streams;EvidenceSummary=$summary;Failure=$null;NormalProducerResultPath=''}
    }
    Import-BootstrapCanonicalUserProcessApi $VerifiedProducerRoot
    $wrapper=Join-Path $root 'normal-producer.ps1';$resultPath=Join-Path $root 'normal-producer-result.json'
    Assert-BootstrapNoReparsePoint $root 'normal producer private parent' -PathOnly
    if((Test-Path -LiteralPath $wrapper) -or (Test-Path -LiteralPath $resultPath)){throw 'Normal producer capture target already exists.'}
    [IO.File]::WriteAllText($wrapper,(Get-InstallationNormalProducerWrapperSource),[Text.UTF8Encoding]::new($true))
    Set-InstallationEvidenceAcl $wrapper ([string]$caller.sid)
    $library=Join-Path $VerifiedProducerRoot 'tools\bootstrap_integrity.ps1'
    $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $argv=@((ConvertTo-BootstrapRelayArgument $winps),'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',
        (ConvertTo-BootstrapRelayArgument $wrapper),(ConvertTo-BootstrapRelayArgument $library),(Get-FileSha256 $library),
        (ConvertTo-BootstrapRelayArgument $resultPath),[string]$PID,[string]$caller.sid,(ConvertTo-BootstrapRelayArgument $Executable))+
        @($Arguments|ForEach-Object {ConvertTo-BootstrapRelayArgument ([string]$_)})
    $names=@('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID','CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID','CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID','CONTAINER_AUDIT_DATA_ROOT')
    $values=[string[]]@($names|ForEach-Object {[string][Environment]::GetEnvironmentVariable($_,'Process')})
    $wrapperPid=Start-BootstrapNormalProducerWrapper ($argv -join ' ') $caller $names $values
    $wrapperExit=$null
    try{$process=[Diagnostics.Process]::GetProcessById($wrapperPid);try{$process.WaitForExit();$wrapperExit=$process.ExitCode}finally{$process.Dispose()}}catch [ArgumentException]{if(-not(Test-Path -LiteralPath $resultPath -PathType Leaf)){throw}}
    Assert-BootstrapNoReparsePoint $resultPath 'normal producer result' -PathOnly
    if((Get-Item -LiteralPath $resultPath).Length -gt 65536){throw 'Normal producer result is oversized.'}
    $result=Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$result.schema -cne 'container-audit-normal-producer-capture-v1' -or
        -not(Test-BootstrapJsonInteger $result.parent_process_id) -or [int64]$result.parent_process_id -ne $PID -or
        -not(Test-BootstrapJsonInteger $result.wrapper_process_id) -or [int64]$result.wrapper_process_id -ne $wrapperPid -or
        -not(Test-BootstrapJsonInteger $result.producer_process_id) -or [int64]$result.producer_process_id -lt 0 -or
        -not(Test-BootstrapJsonInteger $result.exit_code) -or ($null -ne $wrapperExit -and [int]$result.exit_code -ne $wrapperExit) -or
        $result.security.elevated -isnot [bool] -or $result.security.elevated -or
        [int]$result.security.integrity_level -ne 8192 -or [string]$result.security.sid -cne [string]$caller.sid -or
        [int]$result.security.session_id -ne [int]$caller.session_id){throw 'Normal producer result/security binding differs.'}
    $expectedRoot=Join-Path $root ('normal-producer-capture.evidence.'+$wrapperPid)
    if(-not(Test-BootstrapSamePath ([string]$result.capture_root) $expectedRoot)){throw 'Normal producer capture root binding differs.'}
    Assert-BootstrapNoReparsePoint $expectedRoot 'normal producer capture root' -PathOnly
    if([int64]$result.producer_process_id -eq 0 -and ([int]$result.exit_code -eq 0 -or $null -eq $result.failure -or $null -ne $result.streams)){throw 'Unstarted normal producer failure binding differs.'}
    $texts=@{stdout='';stderr=''}
    if([int]$result.producer_process_id -gt 0){foreach($name in @('stdout','stderr')){
        $stream=$result.streams.$name;$path=Join-Path $expectedRoot ('normal-producer-'+[int]$result.producer_process_id+'-'+$name+'.bin')
        if(-not(Test-BootstrapSamePath ([string]$stream.path) $path)){throw 'Normal producer stream path binding differs.'}
        Assert-BootstrapNoReparsePoint $path 'normal producer stream' -PathOnly
        if((Get-Item -LiteralPath $path).Length -gt 1048576 -or (Get-FileSha256 $path) -cne [string]$stream.sha256){throw 'Normal producer stream hash/size binding differs.'}
        $texts[$name]=[Text.Encoding]::GetEncoding([string]$stream.encoding).GetString([IO.File]::ReadAllBytes($path))
    }}
    Write-InstallationEvidenceEvent ([ordered]@{event='NORMAL_FINITE_PRODUCER';wrapper_pid=$wrapperPid;producer_pid=[int]$result.producer_process_id;exit_code=[int]$result.exit_code;result_path=$resultPath;result_sha256=Get-FileSha256 $resultPath})
    Register-InstallationChildEvidenceSummary $result.evidence_summary
    Complete-InstallationEvidenceStage 'forward';$summary=Complete-InstallationEvidence
    return [pscustomobject]@{ExitCode=[int]$result.exit_code;ProcessId=[int]$result.producer_process_id;Stdout=$texts.stdout;Stderr=$texts.stderr;
        Streams=$result.streams;EvidenceSummary=$summary;Failure=$result.failure;NormalProducerResultPath=$resultPath}
    }catch{Fail-InstallationEvidenceStages $_;throw}
    finally{[void](Complete-InstallationEvidence)}
}

function Complete-InstallationEvidenceStage([string]$Lane, $Failure=$null) {
    if (-not (Get-Variable -Name InstallationEvidenceLanes -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { return }
    if (-not $Script:InstallationEvidenceLanes.ContainsKey($Lane)) { return }
    $stage=$Script:InstallationEvidenceLanes[$Lane]
    $stage.watch.Stop()
    $detail=$null; if ($null -ne $Failure) { $detail=Get-InstallationFailureDetails $Failure }
    Write-InstallationEvidenceEvent ([ordered]@{event='END';sequence=$stage.sequence;lane=$Lane;stage=$stage.name;result=if($null -eq $Failure){'PROVEN'}else{'FAILED'};elapsed_ms=$stage.watch.ElapsedMilliseconds;failure=$detail})
    $Script:InstallationEvidenceLanes.Remove($Lane)
}

function Set-InstallationEvidenceStage([string]$Name,[string]$Lane='forward') {
    if (-not (Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { return }
    Complete-InstallationEvidenceStage $Lane
    $Script:InstallationEvidenceSequence++
    $Script:InstallationEvidenceLanes[$Lane]=@{name=$Name;sequence=$Script:InstallationEvidenceSequence;watch=[Diagnostics.Stopwatch]::StartNew()}
    Write-InstallationEvidenceEvent ([ordered]@{event='START';sequence=$Script:InstallationEvidenceSequence;lane=$Lane;stage=$Name})
}

function Write-InstallationCaughtFailure($Failure) {
    $active=@()
    $lanes=Get-Variable -Name InstallationEvidenceLanes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $lanes){foreach($lane in $lanes.Keys){$active+=@{lane=$lane;stage=$lanes[$lane].name;sequence=$lanes[$lane].sequence}}}
    Write-InstallationEvidenceEvent ([ordered]@{event='CAUGHT_FAILURE';active_stages=$active;failure=(Get-InstallationFailureDetails $Failure)})
}

function Fail-InstallationEvidenceStages($Failure) {
    Write-InstallationCaughtFailure $Failure
    $lanes=Get-Variable -Name InstallationEvidenceLanes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $lanes) { foreach ($lane in @($lanes.Keys)) { Complete-InstallationEvidenceStage $lane $Failure } }
}

function Initialize-InstallationChildCapture {
    if ('KMTechInstallationChildCapture' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Threading; using System.Diagnostics;
public static class KMTechInstallationChildCapture {
 public sealed class Output { public byte[] bytes; public long observed; public bool complete; }
 public sealed class Result { public int pid, exit_code; public Output stdout, stderr; }
 sealed class Reader {
  public MemoryStream saved=new MemoryStream(); public long observed; public bool complete; public object gate=new object();
  public void Read(Stream stream) { try { byte[] b=new byte[8192]; int n; while((n=stream.Read(b,0,b.Length))>0) { lock(gate) { observed+=n; int keep=(int)Math.Min(n,1048576-saved.Length); if(keep>0) saved.Write(b,0,keep); } } complete=true; } catch(ObjectDisposedException) {} catch(IOException) {} }
  public Output Snapshot() { lock(gate) { return new Output {bytes=saved.ToArray(),observed=observed,complete=complete}; } }
 }
 static string Quote(string value) {
  StringBuilder b=new StringBuilder("\""); int slashes=0;
  foreach(char c in value) { if(c=='\\') { slashes++; continue; } if(c=='\"') { b.Append('\\',slashes*2+1); b.Append(c); } else { b.Append('\\',slashes); b.Append(c); } slashes=0; }
  b.Append('\\',slashes*2); b.Append('"'); return b.ToString();
 }
 public static Result Run(string executable,string[] arguments,string directory) {
  ProcessStartInfo info=new ProcessStartInfo(executable); info.Arguments=String.Join(" ",Array.ConvertAll(arguments,Quote)); info.WorkingDirectory=directory;
  info.UseShellExecute=false; info.CreateNoWindow=true; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
  using(Process p=new Process()) { p.StartInfo=info; if(!p.Start()) throw new IOException("Installer child did not start.");
   Reader output=new Reader(),error=new Reader(); Thread a=new Thread(()=>output.Read(p.StandardOutput.BaseStream)),b=new Thread(()=>error.Read(p.StandardError.BaseStream)); a.IsBackground=b.IsBackground=true; a.Start(); b.Start(); p.WaitForExit();
   // Wait only for this process. A persistent descendant may retain pipe handles.
   bool outDone=a.Join(750),errDone=b.Join(750); if(!outDone) p.StandardOutput.Dispose(); if(!errDone) p.StandardError.Dispose();
   return new Result {pid=p.Id,exit_code=p.ExitCode,stdout=output.Snapshot(),stderr=error.Snapshot()};
  }
 }
}
'@
}

function ConvertTo-SafeInstallationOutput($Output) {
    $bytes=[byte[]]$Output.bytes
    $truncated=($Output.observed -gt $bytes.Length -or -not $Output.complete)
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) { $encoding=[Text.UnicodeEncoding]::new($false,$true,$true) }
    try { $text=$encoding.GetString($bytes) }
    catch {
        try { $encoding=[Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage,[Text.EncoderFallback]::ExceptionFallback,[Text.DecoderFallback]::ExceptionFallback); $text=$encoding.GetString($bytes) }
        catch { return @{bytes=[Text.Encoding]::UTF8.GetBytes('[redacted: undecodable child output]');redacted=$true;truncated=$truncated;encoding='utf-8'} }
    }
    if ($truncated) {
        # Do not retain a partial credential/assignment at the capture boundary.
        $lastNewline=$text.LastIndexOf("`n")
        $text=if($lastNewline -ge 0){$text.Substring(0,$lastNewline+1)}else{''}
        $known=Get-Variable -Name InstallationEvidenceSensitiveValues -Scope Script -ErrorAction SilentlyContinue
        $values=$known.Value
        foreach($value in $values) {
            if ($value -is [string] -and $value.Length) {
                for($n=[Math]::Min($value.Length-1,$text.Length);$n -gt 0;$n--) {
                    if($text.EndsWith($value.Substring(0,$n),[StringComparison]::Ordinal)){$text=$text.Substring(0,$text.Length-$n);break}
                }
            }
        }
    }
    $safe=Protect-InstallationText $text -1
    $redacted=($safe -cne $text)
    $saved=[byte[]]::new(0)
    if(-not $redacted -and -not $truncated){$saved=$bytes}else{$saved=$encoding.GetBytes($safe)}
    return @{bytes=[byte[]]$saved;redacted=$redacted;truncated=$truncated;encoding=$encoding.WebName}
}

function Invoke-InstallationEvidenceChild([string]$Name,[string]$Executable,[string[]]$Arguments,[string]$WorkingDirectory='') {
    Initialize-InstallationChildCapture
    if (-not $WorkingDirectory) { $WorkingDirectory=[IO.Path]::GetDirectoryName($Executable) }
    Write-InstallationEvidenceEvent ([ordered]@{event='CHILD_START';stage=$Name;executable_leaf=[IO.Path]::GetFileName($Executable);byte_cap_per_stream=1048576;arguments_recorded=$false})
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $result=[KMTechInstallationChildCapture]::Run($Executable,$Arguments,$WorkingDirectory)
    $watch.Stop(); $streams=@{}; $texts=@{}
    foreach ($streamName in @('stdout','stderr')) {
        $output=$result.$streamName; $safe=ConvertTo-SafeInstallationOutput $output
        $path=''
        $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($root) {
            $path=Join-Path $root ($Name+'-'+$result.pid+'-'+$streamName+'.bin')
            if(Test-Path -LiteralPath $path){throw 'Installer child evidence target already exists.'}
            [IO.File]::WriteAllBytes($path,$safe.bytes)
            Set-InstallationEvidenceAcl $path $Script:InstallationEvidenceSid
        }
        $streams[$streamName]=@{path=$path;observed_bytes=$output.observed;saved_bytes=$safe.bytes.Length;complete=$output.complete;truncated=$safe.truncated;redacted=$safe.redacted;sha256=if($path){Get-FileSha256 $path}else{''};encoding=$safe.encoding}
        $texts[$streamName]=[Text.Encoding]::GetEncoding($safe.encoding).GetString($safe.bytes)
    }
    Write-InstallationEvidenceEvent ([ordered]@{event='CHILD_EXIT';stage=$Name;pid=$result.pid;exit_code=$result.exit_code;elapsed_ms=$watch.ElapsedMilliseconds;streams=$streams})
    return [pscustomobject]@{ExitCode=$result.exit_code;ProcessId=$result.pid;Stdout=$texts.stdout;Stderr=$texts.stderr;Streams=$streams}
}

function Get-StrictFullPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose must be an absolute path."
    }
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "$Purpose must not use a device namespace."
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($full) -or $full -eq [IO.Path]::GetPathRoot($full)) {
        throw "$Purpose must not be a filesystem root."
    }
    return $full
}

function Protect-KmtechCodeAncestors([string]$CodeParent) {
    # Deliberately persistent, non-recursive protection of these two shared paths.
    # Never restore their old permissions as part of an app rollback/uninstall.
    if (-not ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($CodeParent))).Equals('C:\KMTech\Apps',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Code parent must be a direct application directory under C:\KMTech\Apps.'
    }
    $records=@(); $plans=@()
    foreach ($path in @('C:\KMTech','C:\KMTech\Apps')) {
        $reason=''
        if (-not (Test-Path -LiteralPath $path)) {
            $ancestor=Split-Path -Parent $path
            $entry=Get-Item -LiteralPath $ancestor -ErrorAction Stop
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $reason='상위 폴더가 재분석 지점입니다' }
            else { [void][IO.Directory]::CreateDirectory($path) }
        }
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $reason='폴더가 재분석 지점입니다' }
        $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
        $before=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $shape=@(
            'S-1-5-32-544|2032127|3|0', 'S-1-5-18|2032127|3|0',
            'S-1-5-32-545|1179817|3|0', 'S-1-5-11|-536805376|3|2'
        )
        $actual=@(); $allInherited=$true; $allExplicit=$true
        foreach($rule in $rules) {
            if ([string]$rule.AccessControlType -cne 'Allow') { $reason='거부 권한 항목이 있습니다' }
            $actual+=([string]$rule.IdentityReference.Value+'|'+[int64]$rule.FileSystemRights+'|'+[int]$rule.InheritanceFlags+'|'+[int]$rule.PropagationFlags)
            $allInherited=$allInherited -and $rule.IsInherited
            $allExplicit=$allExplicit -and -not $rule.IsInherited
        }
        $actualKey=(@($actual | Sort-Object) -join ';')
        $defaultKey=(@(($shape+@('S-1-5-11|1245631|0|0')) | Sort-Object) -join ';')
        $targetKey=(@(($shape+@('S-1-5-11|1179823|0|0')) | Sort-Object) -join ';')
        $defaultShape=($rules.Count -eq 5 -and -not $acl.AreAccessRulesProtected -and $allInherited -and $actualKey -ceq $defaultKey)
        $targetShape=($rules.Count -eq 5 -and $acl.AreAccessRulesProtected -and $allExplicit -and $actualKey -ceq $targetKey)
        if($owner -cne 'S-1-5-32-544'){$reason='폴더 소유자가 예상과 다릅니다'}
        if(-not $reason -and -not $defaultShape -and -not $targetShape){$reason='권한 모양이 지원하는 기본값 또는 보호된 값과 다릅니다'}
        if($reason) {
            Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_REJECTED';path=$path;reason=$reason;before_sddl=$before;changed=$false})
            $failure=[InvalidOperationException]::new("설치 폴더 권한을 확인하세요: $path ($reason). 지원 담당자에게 문의하세요.")
            $failure.Data['canonical_code']='CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED'
            $failure.Data['ancestor_trust_failure']=$failure.Message
            throw $failure
        }
        $plans+=@{path=$path;acl=$acl;before=$before;default_shape=$defaultShape;target_shape=$targetShape}
    }
    # Both existing shapes are admitted before the first ACL write.
    foreach($plan in $plans) {
        $path=$plan.path; $acl=$plan.acl; $before=$plan.before
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Ancestor became a reparse point before protection.'}
        $fresh=Get-Acl -LiteralPath $path -ErrorAction Stop
        $freshSddl=$fresh.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        if($freshSddl -cne $before){throw 'Ancestor ACL changed during protection admission.'}
        Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_BEFORE';path=$path;before_sddl=$before;already_target=$plan.target_shape;intentional_persistent_change=$true})
        if($plan.default_shape) {
            $acl.SetAccessRuleProtection($true,$true)
            # .NET can retain the inherited flag until persistence. Convert each
            # copied ACE explicitly without remapping its generic/inherit-only mask.
            $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
            foreach($ace in $raw.DiscretionaryAcl){$ace.AceFlags=[Security.AccessControl.AceFlags]([int]$ace.AceFlags -band (-bnot [int][Security.AccessControl.AceFlags]::Inherited))}
            $binary=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($binary,0)
            $acl.SetSecurityDescriptorBinaryForm($binary,[Security.AccessControl.AccessControlSections]::Access)
            $self=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
                $_.IdentityReference.Value -ceq 'S-1-5-11' -and [int64]$_.FileSystemRights -eq 1245631 -and [int]$_.InheritanceFlags -eq 0 -and [int]$_.PropagationFlags -eq 0
            })
            if($self.Count -ne 1){throw 'Ancestor ACL copied self-entry readback failed.'}
            $acl.RemoveAccessRuleSpecific($self[0])
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new('S-1-5-11'),
                [Security.AccessControl.FileSystemRights]1179823,'None','None','Allow'))
            Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
        }
        $afterAcl=Get-Acl -LiteralPath $path -ErrorAction Stop
        $after=$afterAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        $afterRules=@($afterAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $afterKey=(@($afterRules | ForEach-Object {
            if($_.IsInherited -or $_.AccessControlType -ne 'Allow'){throw 'Ancestor ACL explicit readback failed.'}
            [string]$_.IdentityReference.Value+'|'+[int64]$_.FileSystemRights+'|'+[int]$_.InheritanceFlags+'|'+[int]$_.PropagationFlags
        } | Sort-Object) -join ';')
        if($afterAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or -not $afterAcl.AreAccessRulesProtected -or $afterRules.Count -ne 5 -or $afterKey -cne $targetKey){throw 'Ancestor ACL protected readback failed.'}
        $record=[ordered]@{path=$path;before_sddl=$before;after_sddl=$after;changed=$plan.default_shape;intentional_persistent_change=$true}
        $records+=$record
        Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_AFTER';record=$record})
    }
    # The app directory is the guarded leaf; Apps/KMTech are higher ancestors,
    # where direct creation remains allowed. This also rejects user-owned squatters.
    try { Assert-ProtectedCodeAncestors $CodeParent }
    catch {
        Write-InstallationCaughtFailure $_
        $failure=[InvalidOperationException]::new("설치 폴더 권한을 확인하세요: $CodeParent (코드 경로의 신뢰 재검사가 실패했습니다). 지원 담당자에게 문의하세요.",$_.Exception)
        $failure.Data['canonical_code']='CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED'
        $failure.Data['ancestor_trust_failure']=$failure.Message
        throw $failure
    }
    return [pscustomobject]@{status='VERIFIED';records=$records;rollback_restores_ancestor_permissions=$false}
}

function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-RelativeCodePath([string]$Root, [string]$Path) {
    $rootFull = (Get-StrictFullPath $Root "inventory root") + '\'
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Inventory path escaped its root."
    }
    return $pathFull.Substring($rootFull.Length).Replace('\', '/')
}

function Get-BootstrapSharedPortableLeaf([string]$Root) {
    # This bootstrap is trusted with the installer. Never use shared code to
    # authenticate itself, or derive the expected release pin from input bytes.
    $rootFull = Get-StrictFullPath $Root 'shared installer root'
    Assert-BootstrapNoReparsePoint $rootFull 'shared installer root' -PathOnly
    $appRoot = $rootFull
    if (Test-Path -LiteralPath (Join-Path $rootFull 'app') -PathType Container) {
        $appRoot = Join-Path $rootFull 'app'
    }
    $lockPath = Join-Path $appRoot 'kmtech_shared.lock.json'
    $manifestPath = Join-Path $appRoot 'kmtech_shared.manifest.json'
    $sharedLeaf = Join-Path $appRoot 'kmtech_shared\powershell\portable.ps1'
    foreach ($path in @($lockPath, $manifestPath, $sharedLeaf)) {
        Assert-BootstrapNoReparsePoint $path 'shared installer input' -PathOnly
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Shared installer input must be a file.'
        }
    }
    $expectedManifestSha = 'feaed459688e915eb5f52f264501a4287261d9dcbdbc50e0c6f4bde59d8e7117'
    if ((Get-Item -LiteralPath $lockPath).Length -gt 65536) { throw 'Shared consumer lock is oversized.' }
    $lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($lock.PSObject.Properties.Name).Count -ne 2 -or
        $lock.version -cne '0.3.1' -or $lock.manifest_sha256 -cne $expectedManifestSha) {
        throw 'Shared consumer lock pin mismatch.'
    }
    if ((Get-FileSha256 $manifestPath) -cne $expectedManifestSha) {
        throw 'Shared manifest pin mismatch.'
    }
    $pinnedSharedManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $expectedLeafSha = $pinnedSharedManifest.files.'kmtech_shared/powershell/portable.ps1'
    if ((Get-FileHash -LiteralPath $sharedLeaf -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedLeafSha) {
        throw 'Shared PowerShell leaf pin mismatch.'
    }
    return $sharedLeaf
}

function Get-CodeInventory([string]$Root) {
    $rootFull = Get-StrictFullPath $Root "code root"
    $result = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($file in @(Get-ChildItem -LiteralPath $rootFull -File -Force -Recurse)) {
        $relative = Get-RelativeCodePath $rootFull $file.FullName
        if ($relative.Equals($BootstrapIntegrityFileName, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $result.Add($relative, [pscustomobject][ordered]@{
            path = $relative
            size = [int64]$file.Length
            sha256 = Get-FileSha256 $file.FullName
        })
    }
    return @($result.Values)
}

function Get-InventoryAggregate([object[]]$Inventory) {
    $lines = @($Inventory | ForEach-Object { "$($_.sha256) $($_.size) $($_.path)" })
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($lines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Write-Utf8Json([string]$Path, $Payload) {
    $temporary = "$Path.tmp.$PID"
    $json = $Payload | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Write-BootstrapIntegrityRecord(
    [string]$Root,
    [string]$CodeRootIdentity,
    [string]$RecordedAt = ""
) {
    $rootFull = Get-StrictFullPath $Root "bootstrap integrity root"
    $inventory = @(Get-CodeInventory $rootFull)
    if ($inventory.Count -eq 0) {
        throw "Bootstrap integrity inventory is empty."
    }
    if ([string]::IsNullOrWhiteSpace($RecordedAt)) {
        $RecordedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    $record = [ordered]@{
        schema_version = $BootstrapIntegritySchema
        status = 'PASS'
        code_root = $CodeRootIdentity
        installed_at = $RecordedAt
        file_count = $inventory.Count
        aggregate_sha256 = Get-InventoryAggregate $inventory
        files = $inventory
        identity_profile_created = $false
        state_scope = 'current_user_first_run'
    }
    Write-Utf8Json (Join-Path $rootFull $BootstrapIntegrityFileName) $record
    return [pscustomobject]$record
}

function Assert-BootstrapIntegrityRecord([string]$Root) {
    $rootFull = Get-StrictFullPath $Root "bootstrap integrity root"
    $recordPath = Join-Path $rootFull $BootstrapIntegrityFileName
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw "Bootstrap integrity record is absent."
    }
    $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$record.schema_version -cne $BootstrapIntegritySchema -or [string]$record.status -cne 'PASS') {
        throw "Bootstrap integrity record schema or status is invalid."
    }
    if ([string]$record.code_root -ceq '.') {
        $declaredCodeRoot = $rootFull
    }
    else {
        $declaredCodeRoot = Get-StrictFullPath ([string]$record.code_root) "bootstrap integrity code root"
    }
    if (-not $declaredCodeRoot.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Bootstrap integrity record code root is invalid."
    }
    $inventory = @(Get-CodeInventoryInRecordOrder $rootFull @($record.files))
    if (
        -not (Test-BootstrapJsonInteger $record.file_count) -or
        [int64]$record.file_count -ne $inventory.Count -or
        @($record.files).Count -ne $inventory.Count
    ) {
        throw "Bootstrap integrity record file count is invalid."
    }
    for ($index = 0; $index -lt $inventory.Count; $index += 1) {
        $actual = $inventory[$index]
        $expected = @($record.files)[$index]
        if (
            -not (Test-BootstrapJsonInteger $expected.size) -or
            -not (Test-BootstrapJsonInteger $actual.size) -or
            [string]$expected.path -cne [string]$actual.path -or
            [int64]$expected.size -ne [int64]$actual.size -or
            [string]$expected.sha256 -cne [string]$actual.sha256
        ) {
            throw "Bootstrap integrity inventory differs at index $index."
        }
    }
    $aggregate = Get-InventoryAggregate $inventory
    if ([string]$record.aggregate_sha256 -cne $aggregate) {
        throw "Bootstrap integrity aggregate is invalid."
    }
    $frozenMainCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'Container_Audit.exe' }
    ).Count
    $portablePythonCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'runtime/pythonw.exe' }
    ).Count
    $portableMainCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'app/main.py' }
    ).Count
    $frozenLayout = $frozenMainCount -eq 1
    $portableLayout = $portablePythonCount -eq 1 -and $portableMainCount -eq 1
    if ($frozenLayout -eq $portableLayout) {
        throw "Bootstrap integrity record does not identify exactly one supported release layout."
    }
    return [pscustomobject]@{
        status = 'PASS'
        record_path = $recordPath
        file_count = $inventory.Count
        aggregate_sha256 = $aggregate
    }
}

function Test-BootstrapJsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}

function Assert-BootstrapProtectedRelayPath([string]$Path) {
    $full=Get-StrictFullPath $Path 'protected relay path';$leaf=$true
    while($full) {
        $entry=Get-Item -LiteralPath $full -ErrorAction Stop
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Relay path contains a reparse point.'}
        $acl=Get-Acl -LiteralPath $full -ErrorAction Stop
        if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin @(
            'S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        )){throw 'Relay path owner is not privileged.'}
        $mask=if($leaf){0x500D0156}else{0x500D0150}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($rule.AccessControlType -eq 'Allow' -and
                -not($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $rule.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544') -and
                ([int64]$rule.FileSystemRights -band $mask)){throw 'Relay path is user mutable.'}
        }
        if($full -eq [IO.Path]::GetPathRoot($full)){break}
        $full=[IO.Path]::GetDirectoryName($full);$leaf=$false
    }
}

function ConvertTo-BootstrapRelayArgument([string]$Value) {
    if($Value.Contains('"')){throw 'Relay path contains a quote.'}
    if($Value -match '\s'){return '"'+$Value+'"'}
    return $Value
}

function Get-BootstrapRelayCommandIdentity([string]$CommandLine,[string]$ExecutablePath) {
    $quoted='"'+$ExecutablePath+'"'
    if($CommandLine.StartsWith($quoted+' ',[StringComparison]::Ordinal)){return $ExecutablePath+$CommandLine.Substring($quoted.Length)}
    return $CommandLine
}

function Initialize-BootstrapRelaySecurity {
    if('KMTechBootstrapRelaySecurity' -as [type]){return}
    Add-Type -TypeDefinition @'
using System; using System.ComponentModel; using System.Runtime.InteropServices; using System.Security.Principal;
public static class KMTechBootstrapRelaySecurity {
 public sealed class Security { public string sid; public int session_id,integrity_level; public bool elevated; }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int needed);
 static void Check(bool ok,string api) { if(!ok) { Win32Exception error=new Win32Exception(Marshal.GetLastWin32Error(),api);error.Data["canonical_api"]=api;throw error; } }
 static int Integer(IntPtr token,int kind) { IntPtr data=Marshal.AllocHGlobal(4);try{int needed;Check(GetTokenInformation(token,kind,data,4,out needed),"GetTokenInformation:"+kind);return Marshal.ReadInt32(data);}finally{Marshal.FreeHGlobal(data);} }
 static int Integrity(IntPtr token) { int needed;GetTokenInformation(token,25,IntPtr.Zero,0,out needed);if(needed<=0||needed>65536)throw new InvalidOperationException("Relay integrity record size is invalid.");
  IntPtr data=Marshal.AllocHGlobal(needed);try{Check(GetTokenInformation(token,25,data,needed,out needed),"GetTokenInformation:integrity");string[] parts=new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value.Split('-');return Int32.Parse(parts[parts.Length-1]);}finally{Marshal.FreeHGlobal(data);} }
 public static Security Read(int pid) { IntPtr process=OpenProcess(0x1000,false,pid);Check(process!=IntPtr.Zero,"OpenProcess:relay-query");
  try{IntPtr token;Check(OpenProcessToken(process,8,out token),"OpenProcessToken:relay-query");try{using(WindowsIdentity identity=new WindowsIdentity(token)){return new Security{sid=identity.User.Value,session_id=Integer(token,12),elevated=Integer(token,20)!=0,integrity_level=Integrity(token)};}}finally{CloseHandle(token);}}finally{CloseHandle(process);} }
}
'@
}

function Get-BootstrapRelaySecurity([int]$ProcessId) {
    Initialize-BootstrapRelaySecurity
    return [KMTechBootstrapRelaySecurity]::Read($ProcessId)
}

function Get-BootstrapRelayExpectedIdentity([string]$Root,[string]$RunCommand) {
    $rootFull=Get-StrictFullPath $Root 'relay install root'
    $runtime=Join-Path $rootFull 'runtime\pythonw.exe'
    $prefix=(ConvertTo-BootstrapRelayArgument $runtime)+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $rootFull 'app\auto_update.py'))+' --bootstrap --role relay --'
    $managed=$RunCommand.StartsWith($prefix+' --container-audit-user-relay',[StringComparison]::Ordinal)
    $sha='';$manifestSha='';$aggregate='';$bundle=$rootFull;$command=$RunCommand;$requiresStatusIdentity=$false
    if($managed) {
        if([IO.Path]::GetFileName($rootFull) -cne 'current'){throw 'Relay bootstrap is outside the installed current root.'}
        $control=Join-Path (Split-Path -Parent $rootFull) 'update-control'
        foreach($path in @((Join-Path $control 'active.json'),(Join-Path $control 'policy.json'))){
            Assert-BootstrapProtectedRelayPath $path
            if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Relay control record is oversized.'}
        }
        $policy=Get-Content -LiteralPath (Join-Path $control 'policy.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if($policy.operator_sid -isnot [string] -or $policy.operator_sid -cnotmatch '^S-1-'){throw 'Relay operator SID is invalid.'}
        $active=Get-Content -LiteralPath (Join-Path $control 'active.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if([string]$active.schema -cne 'container-audit-startup-update-v1' -or $active.sha -isnot [string] -or $active.sha -cnotmatch '^[0-9a-f]{40}$'){throw 'Relay active version identity is invalid.'}
        $sha=[string]$active.sha;$bundle=Join-Path (Split-Path -Parent $rootFull) ('versions\'+$sha)
        foreach($path in @($bundle,(Join-Path $bundle 'portable-manifest.json'),(Join-Path $bundle 'runtime\pythonw.exe'),(Join-Path $bundle 'app\main.py'),(Join-Path $bundle 'bootstrap-integrity.json'))){Assert-BootstrapProtectedRelayPath $path}
        $manifest=Read-KmtechPortableManifest $bundle
        if($manifest.source_commit -isnot [string] -or $manifest.source_commit -cne $sha -or
            -not(Test-BootstrapJsonInteger $manifest.startup_update_protocol) -or [int64]$manifest.startup_update_protocol -ne 1){throw 'Relay active manifest binding differs.'}
        if(@($manifest.PSObject.Properties.Name) -ccontains 'relay_identity_protocol') {
            if(-not(Test-BootstrapJsonInteger $manifest.relay_identity_protocol) -or [int64]$manifest.relay_identity_protocol -ne 1){throw 'Relay identity protocol is unsupported.'}
            $requiresStatusIdentity=$true
        }
        $record=Get-Content -LiteralPath (Join-Path $bundle 'bootstrap-integrity.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $integrity=if([string]$record.code_root -ceq '.' -or (Test-BootstrapSamePath ([string]$record.code_root) $bundle)){
            Assert-BootstrapIntegrityRecord $bundle
        }else{Assert-BootstrapRelocatedIntegrityRecord $bundle $rootFull}
        $aggregate=[string]$integrity.aggregate_sha256
        $manifestSha=Get-FileSha256 (Join-Path $bundle 'portable-manifest.json')
        $runtime=Join-Path $bundle 'runtime\pythonw.exe'
        $command=(ConvertTo-BootstrapRelayArgument $runtime)+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $bundle 'app\main.py'))+$RunCommand.Substring($prefix.Length)
    }
    return [pscustomobject]@{root=$bundle;install_root=$rootFull;managed=$managed;source_commit=$sha;manifest_sha256=$manifestSha;aggregate_sha256=$aggregate;executable=$runtime;command=$command;run_command=$RunCommand;requires_status_identity=$requiresStatusIdentity;operator_sid=if($managed){[string]$policy.operator_sid}else{''}}
}

function Get-BootstrapRelayReadinessSnapshot($Identity) {
    if(-not $Identity.managed){return [pscustomobject]@{identity=$Identity;settled=$true;phase='UNMANAGED'}}
    $control=Join-Path (Split-Path -Parent ([string]$Identity.install_root)) 'update-control'
    $path=Join-Path $control 'active.json'
    Assert-BootstrapProtectedRelayPath $path
    if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Relay active record is oversized.'}
    $active=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    if([string]$active.schema -cne 'container-audit-startup-update-v1' -or $active.sha -isnot [string] -or $active.sha -cnotmatch '^[0-9a-f]{40}$'){throw 'Relay active version identity is invalid.'}
    if([string]$active.sha -cne [string]$Identity.source_commit){$Identity=Get-BootstrapRelayExpectedIdentity ([string]$Identity.install_root) ([string]$Identity.run_command)}
    $transitionPath=Join-Path $control 'transition.json';$phase='ABSENT'
    if(Test-Path -LiteralPath $transitionPath -PathType Leaf){
        Assert-BootstrapProtectedRelayPath $transitionPath
        if((Get-Item -LiteralPath $transitionPath).Length -gt 65536){throw 'Relay transition is oversized.'}
        $transition=Get-Content -LiteralPath $transitionPath -Raw -Encoding UTF8|ConvertFrom-Json
        $phase=[string]$transition.phase
    }
    return [pscustomobject]@{identity=$Identity;settled=($phase -cin @('ABSENT','CONFIRMED','ROLLED_BACK','DEFERRED'));phase=$phase}
}

function Test-BootstrapRelayReadback($Identity,$Process,$Security,$Caller,$Status=$null,[Nullable[DateTime]]$StartedAt=$null,[string]$PreviousStatusSha256='',[string]$StatusSha256='') {
    try {
        if($null -eq $Process -or $null -eq $Security -or $null -eq $Caller -or
            $Process.ProcessId -isnot [int] -and $Process.ProcessId -isnot [long] -and $Process.ProcessId -isnot [uint32]){return $false}
        if([int64]$Process.ProcessId -le 0 -or -not(Test-BootstrapSamePath ([string]$Process.ExecutablePath) ([string]$Identity.executable)) -or
            (Get-BootstrapRelayCommandIdentity ([string]$Process.CommandLine) ([string]$Identity.executable)) -cne
            (Get-BootstrapRelayCommandIdentity ([string]$Identity.command) ([string]$Identity.executable)) -or
            $Security.elevated -isnot [bool] -or $Security.elevated -or
            (@($Security.PSObject.Properties.Name) -ccontains 'integrity_level' -and [int]$Security.integrity_level -ne 8192) -or
            [string]$Security.sid -cne [string]$Caller.sid -or [int]$Security.session_id -ne [int]$Caller.session_id -or
            ([string]$Identity.operator_sid -and [string]$Security.sid -cne [string]$Identity.operator_sid) -or
            [int]$Security.session_id -le 0){return $false}
        if($null -eq $StartedAt){return $true}
        if($null -eq $Status -or [string]$Status.report_version -cne 'container-audit-user-relay-v1' -or
            [string]$Status.status -cne 'RUNNING' -or [string]$Status.principal -cne 'current_user' -or
            $Status.persistent_retry -isnot [bool] -or -not $Status.persistent_retry -or
            ($PreviousStatusSha256 -and $PreviousStatusSha256 -ceq $StatusSha256)){return $false}
        $properties=@($Status.PSObject.Properties.Name)
        if($Identity.requires_status_identity -and @(@('process_id','source_commit','ordinary_user')|Where-Object {$properties -cnotcontains $_}).Count){return $false}
        if($properties -ccontains 'process_id' -and (-not(Test-BootstrapJsonInteger $Status.process_id) -or [int64]$Status.process_id -ne [int64]$Process.ProcessId)){return $false}
        if($properties -ccontains 'source_commit' -and [string]$Status.source_commit -cne [string]$Identity.source_commit){return $false}
        if($properties -ccontains 'ordinary_user' -and ($Status.ordinary_user -isnot [bool] -or -not $Status.ordinary_user)){return $false}
        $updated=[DateTimeOffset]::MinValue
        if($Status.updated_at -is [DateTime]) {
            # PowerShell 7.5+ converts ISO JSON dates; PS5 retains strings.
            if($Status.updated_at.Kind -eq [DateTimeKind]::Unspecified){return $false}
            $updated=[DateTimeOffset]::new($Status.updated_at.ToUniversalTime())
        }elseif([string]$Status.updated_at -cnotmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$' -or
            -not[DateTimeOffset]::TryParse([string]$Status.updated_at,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$updated)){return $false}
        if($Process.CreationDate -isnot [DateTime]){return $false}
        $start=([DateTime]$StartedAt).ToUniversalTime();$created=([DateTime]$Process.CreationDate).ToUniversalTime()
        return $updated.UtcDateTime -ge $start.AddSeconds(-1) -and $updated.UtcDateTime -le [DateTime]::UtcNow.AddSeconds(1) -and
            $created -ge $start.AddSeconds(-1) -and $created -le $updated.UtcDateTime.AddSeconds(1)
    }catch{return $false}
}

function Get-BootstrapStringSha256([string]$Value) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-BootstrapSamePath([string]$Left, [string]$Right) {
    return (Get-StrictFullPath $Left 'left path').Equals(
        (Get-StrictFullPath $Right 'right path'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-BootstrapNoReparsePoint([string]$Path, [string]$Purpose, [switch]$PathOnly) {
    $root = Get-StrictFullPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $root)) { throw "$Purpose is unavailable." }
    $items = @((Get-Item -LiteralPath $root -Force -ErrorAction Stop))
    $ancestor = Split-Path -Parent $root
    while ($ancestor) {
        $items += Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        $next = Split-Path -Parent $ancestor
        if ($next -eq $ancestor) { break }
        $ancestor = $next
    }
    if (-not $PathOnly -and $items[0].PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
    }
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose contains a reparse point: $($item.FullName)"
        }
    }
}

function Get-BootstrapAclIdentity([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $acl = if ($PSVersionTable.PSEdition -ceq 'Core') {
        [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
    }
    else {
        $item.GetAccessControl($sections)
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $sddl = $acl.GetSecurityDescriptorSddlForm($sections)
    if ($acl.AreAccessRulesProtected -isnot [bool]) {
        throw 'Bootstrap ACL protection readback type is invalid.'
    }
    return [pscustomobject][ordered]@{
        owner_sid = [string]$owner
        access_rules_protected = $acl.AreAccessRulesProtected
        sddl_sha256 = Get-BootstrapStringSha256 $sddl
    }
}

function Assert-BootstrapRelocatedIntegrityRecord(
    [string]$Root,
    [string]$ExpectedCodeRoot
) {
    $rootFull = Get-StrictFullPath $Root 'relocated bootstrap root'
    $expectedRoot = Get-StrictFullPath $ExpectedCodeRoot 'declared bootstrap root'
    $recordPath = Join-Path $rootFull $BootstrapIntegrityFileName
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw 'Relocated bootstrap integrity record is absent.'
    }
    if ((Get-Item -LiteralPath $recordPath -Force).Length -gt 1048576) {
        throw 'Relocated bootstrap integrity record is oversized.'
    }
    $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$record.schema_version -cne $BootstrapIntegritySchema -or
        [string]$record.status -cne 'PASS' -or
        -not (Test-BootstrapSamePath ([string]$record.code_root) $expectedRoot)
    ) {
        throw 'Relocated bootstrap integrity identity is invalid.'
    }
    $inventory = @(Get-CodeInventoryInRecordOrder $rootFull @($record.files))
    $aggregate = Get-InventoryAggregate $inventory
    if (
        -not (Test-BootstrapJsonInteger $record.file_count) -or
        [int64]$record.file_count -ne $inventory.Count -or
        @($record.files).Count -ne $inventory.Count -or
        [string]$record.aggregate_sha256 -cne $aggregate
    ) {
        throw 'Relocated bootstrap integrity aggregate differs.'
    }
    $actualByPath = @{}
    foreach ($item in $inventory) { $actualByPath[[string]$item.path] = $item }
    foreach ($expected in @($record.files)) {
        $path = [string]$expected.path
        if (-not $actualByPath.ContainsKey($path)) {
            throw 'Relocated bootstrap integrity inventory is incomplete.'
        }
        $actual = $actualByPath[$path]
        if (
            -not (Test-BootstrapJsonInteger $expected.size) -or
            -not (Test-BootstrapJsonInteger $actual.size) -or
            [int64]$expected.size -ne [int64]$actual.size -or
            [string]$expected.sha256 -cne [string]$actual.sha256
        ) {
            throw 'Relocated bootstrap integrity inventory differs.'
        }
        $actualByPath.Remove($path)
    }
    if ($actualByPath.Count -ne 0) {
        throw 'Relocated bootstrap integrity contains unrecorded files.'
    }
    return [pscustomobject][ordered]@{
        file_count = $inventory.Count
        aggregate_sha256 = $aggregate
        integrity_sha256 = Get-FileSha256 $recordPath
    }
}

function Get-BootstrapReplacementTreeIdentity(
    [string]$Root,
    [string]$DeclaredCodeRoot
) {
    $rootFull = Get-StrictFullPath $Root 'replacement tree'
    Assert-BootstrapNoReparsePoint $rootFull 'replacement tree'
    $integrity = Assert-BootstrapRelocatedIntegrityRecord `
        -Root $rootFull `
        -ExpectedCodeRoot $DeclaredCodeRoot
    $manifestPath = Join-Path $rootFull 'portable-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Replacement tree portable manifest is absent.'
    }
    if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 65536) {
        throw 'Replacement tree portable manifest is oversized.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$manifest.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.source_tree -cnotmatch '^[0-9a-f]{40}$'
    ) {
        throw 'Replacement tree portable identity is invalid.'
    }
    $acl = Get-BootstrapAclIdentity $rootFull
    return [pscustomobject][ordered]@{
        file_count = $integrity.file_count
        aggregate_sha256 = [string]$integrity.aggregate_sha256
        integrity_sha256 = [string]$integrity.integrity_sha256
        manifest_sha256 = Get-FileSha256 $manifestPath
        source_commit = [string]$manifest.source_commit
        source_tree = [string]$manifest.source_tree
        owner_sid = [string]$acl.owner_sid
        access_rules_protected = $acl.access_rules_protected
        acl_sddl_sha256 = [string]$acl.sddl_sha256
        reparse_count = 0
    }
}

function Test-BootstrapReplacementTreeIdentity($Expected, $Actual) {
    if ($null -eq $Expected -or $null -eq $Actual) { return $false }
    foreach ($name in @('file_count', 'reparse_count')) {
        if (
            -not (Test-BootstrapJsonInteger $Expected.$name) -or
            -not (Test-BootstrapJsonInteger $Actual.$name) -or
            [int64]$Expected.$name -ne [int64]$Actual.$name
        ) { return $false }
    }
    if (
        $Expected.access_rules_protected -isnot [bool] -or
        $Actual.access_rules_protected -isnot [bool] -or
        $Expected.access_rules_protected -ne $Actual.access_rules_protected
    ) { return $false }
    foreach ($name in @(
        'aggregate_sha256', 'integrity_sha256', 'manifest_sha256', 'source_commit',
        'source_tree', 'owner_sid', 'acl_sddl_sha256'
    )) {
        if ([string]$Expected.$name -cne [string]$Actual.$name) { return $false }
    }
    return $true
}

function Write-BootstrapReplacementReceipt(
    [string]$Path,
    $Payload,
    [switch]$AllowReplace
) {
    $full = Get-StrictFullPath $Path 'replacement receipt path'
    $parent = Split-Path -Parent $full
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-BootstrapNoReparsePoint $parent 'replacement receipt parent' -PathOnly
    if ((Test-Path -LiteralPath $full) -and -not $AllowReplace.IsPresent) {
        throw 'Replacement receipt path already exists.'
    }
    Write-Utf8Json -Path $full -Payload $Payload
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Replacement receipt write readback failed.'
    }
    return [pscustomobject][ordered]@{
        path = $full
        sha256 = Get-FileSha256 $full
    }
}

function Read-BootstrapReplacementReceipt(
    [string]$Path,
    [string]$ExpectedSha256
) {
    $full = Get-StrictFullPath $Path 'replacement receipt path'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Replacement receipt is absent.'
    }
    Assert-BootstrapNoReparsePoint $full 'replacement receipt'
    $length = (Get-Item -LiteralPath $full -Force).Length
    if ($length -le 0 -or $length -gt 131072) { throw 'Replacement receipt size is invalid.' }
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Replacement receipt SHA-256 is invalid.'
    }
    if ((Get-FileSha256 $full) -cne $ExpectedSha256) {
        throw 'Replacement receipt SHA-256 differs.'
    }
    try { return Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Replacement receipt JSON is invalid.' }
}

function Get-BootstrapVerifiedReplacementRestoreState(
    $Receipt,
    [string]$ReceiptPath,
    [string]$InstallRoot,
    [string]$ExpectedAppId,
    [string]$ExpectedTransactionId,
    [string]$ExpectedHelperSha256
) {
    $current = Get-StrictFullPath $InstallRoot 'restore current root'
    $parent = Get-StrictFullPath (Split-Path -Parent $current) 'restore parent'
    $rollback = Get-StrictFullPath ([string]$Receipt.rollback_root) 'restore rollback root'
    $failed = Get-StrictFullPath ([string]$Receipt.failed_root) 'restore failed root'
    $receiptFull = Get-StrictFullPath $ReceiptPath 'replacement receipt path'
    if (
        [string]$Receipt.schema_version -cne 'container-audit-verified-replacement-v1' -or
        [string]$Receipt.status -cne 'OLD_PRESERVED_NEW_VERIFIED' -or
        [string]$Receipt.app_id -cne $ExpectedAppId -or
        [string]$Receipt.transaction_id -cne $ExpectedTransactionId -or
        [string]$Receipt.helper_sha256 -cne $ExpectedHelperSha256 -or
        -not (Test-BootstrapSamePath ([string]$Receipt.receipt_path) $receiptFull) -or
        -not (Test-BootstrapSamePath ([string]$Receipt.install_root) $current) -or
        -not (Test-BootstrapSamePath ([string]$Receipt.install_parent) $parent) -or
        -not (Test-BootstrapSamePath (Split-Path -Parent $rollback) $parent) -or
        -not (Test-BootstrapSamePath (Split-Path -Parent $failed) $parent) -or
        $ExpectedTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        [IO.Path]::GetFileName($rollback) -cne ".current.rollback.$ExpectedTransactionId" -or
        [IO.Path]::GetFileName($failed) -cne ".current.failed.$ExpectedTransactionId"
    ) {
        throw 'Replacement receipt identity or path binding is invalid.'
    }
    Assert-BootstrapNoReparsePoint $parent 'replacement restore parent' -PathOnly
    $parentAcl = Get-BootstrapAclIdentity $parent
    if (
        [string]$Receipt.parent_acl.owner_sid -cne [string]$parentAcl.owner_sid -or
        $Receipt.parent_acl.access_rules_protected -isnot [bool] -or
        $parentAcl.access_rules_protected -isnot [bool] -or
        $Receipt.parent_acl.access_rules_protected -ne $parentAcl.access_rules_protected -or
        [string]$Receipt.parent_acl.sddl_sha256 -cne [string]$parentAcl.sddl_sha256
    ) { throw 'Replacement restore parent ACL identity differs.' }
    # Only the receipt-selected trees participate in this transaction. Retained
    # history is neither read nor moved; each selected tree is checked recursively.
    foreach ($selected in @($current, $rollback, $failed)) {
        if ((Test-Path -LiteralPath $selected) -and
            -not (Test-Path -LiteralPath $selected -PathType Container)) {
            throw 'Replacement restore selected path is not a directory.'
        }
    }

    $currentExists = Test-Path -LiteralPath $current -PathType Container
    $rollbackExists = Test-Path -LiteralPath $rollback -PathType Container
    $failedExists = Test-Path -LiteralPath $failed -PathType Container
    $currentIdentity = if ($currentExists) { Get-BootstrapReplacementTreeIdentity $current $current } else { $null }
    $rollbackIdentity = if ($rollbackExists) { Get-BootstrapReplacementTreeIdentity $rollback $current } else { $null }
    $failedIdentity = if ($failedExists) { Get-BootstrapReplacementTreeIdentity $failed $current } else { $null }
    $pending = $currentExists -and $rollbackExists -and -not $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $currentIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $rollbackIdentity)
    $displaced = -not $currentExists -and $rollbackExists -and $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $rollbackIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
    $restored = $currentExists -and -not $rollbackExists -and $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $currentIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
    if (-not $pending -and -not $displaced -and -not $restored) {
        throw 'Replacement restore state is ambiguous or drifted.'
    }
    return [pscustomobject][ordered]@{
        status = if ($restored) { 'RESTORED' } elseif ($pending) { 'PENDING' } else { 'DISPLACED' }
        install_root = $current
        rollback_root = $rollback
        failed_new_root = $failed
    }
}

function Invoke-BootstrapVerifiedReplacementRestore(
    $Receipt,
    [string]$ReceiptPath,
    [string]$InstallRoot,
    [string]$ExpectedAppId,
    [string]$ExpectedTransactionId,
    [string]$ExpectedHelperSha256,
    [switch]$InjectFailureAfterDisplace
) {
    $state = Get-BootstrapVerifiedReplacementRestoreState `
        -Receipt $Receipt -ReceiptPath $ReceiptPath -InstallRoot $InstallRoot `
        -ExpectedAppId $ExpectedAppId -ExpectedTransactionId $ExpectedTransactionId `
        -ExpectedHelperSha256 $ExpectedHelperSha256
    $current = [string]$state.install_root
    $rollback = [string]$state.rollback_root
    $failed = [string]$state.failed_new_root
    if ([string]$state.status -ceq 'RESTORED') {
        return [pscustomobject][ordered]@{
            status = 'ALREADY_RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    try {
        if ([string]$state.status -ceq 'PENDING') { Move-Item -LiteralPath $current -Destination $failed -ErrorAction Stop }
        if ($InjectFailureAfterDisplace.IsPresent) { throw 'Injected restore failure after current displacement.' }
        Move-Item -LiteralPath $rollback -Destination $current -ErrorAction Stop
        $restoredOld = Get-BootstrapReplacementTreeIdentity $current $current
        $preservedNew = Get-BootstrapReplacementTreeIdentity $failed $current
        if (
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.old $restoredOld) -or
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.new $preservedNew)
        ) { throw 'Replacement restore exact readback failed.' }
        return [pscustomobject][ordered]@{
            status = 'RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    catch {
        $original = $_.Exception.Message
        $contained = $false
        try {
            if (
                (Test-Path -LiteralPath $current -PathType Container) -and
                -not (Test-Path -LiteralPath $rollback) -and
                (Test-Path -LiteralPath $failed -PathType Container)
            ) {
                Move-Item -LiteralPath $current -Destination $rollback -ErrorAction Stop
            }
            if (
                -not (Test-Path -LiteralPath $current) -and
                (Test-Path -LiteralPath $failed -PathType Container)
            ) {
                Move-Item -LiteralPath $failed -Destination $current -ErrorAction Stop
            }
            $containedCurrent = Get-BootstrapReplacementTreeIdentity $current $current
            $containedRollback = Get-BootstrapReplacementTreeIdentity $rollback $current
            $contained = (
                -not (Test-Path -LiteralPath $failed) -and
                (Test-BootstrapReplacementTreeIdentity $Receipt.new $containedCurrent) -and
                (Test-BootstrapReplacementTreeIdentity $Receipt.old $containedRollback)
            )
        }
        catch { $contained = $false }
        if (-not $contained) { throw "Replacement restore failed and containment also failed: $original" }
        throw "Replacement restore failed; the pre-restore state was contained: $original"
    }
}

function Test-WriterSessionContractExactPropertySet($Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) { return $false }
    }
    return $true
}

function Test-WriterSessionContractExactStringProperties($Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    foreach ($name in $Names) {
        $property = $Value.PSObject.Properties[$name]
        if ($null -eq $property -or -not ($property.Value -is [string])) { return $false }
    }
    return $true
}

function Get-WriterSessionContractMutexName($Fence, $Vector) {
    $values = @(
        [string]$Fence.session_tuple_version,
        [string]$Vector.session_id,
        [string]$Vector.attempt_id,
        [string]$Vector.orchestrator_sha256,
        [string]$Vector.replacement_transaction_id,
        [string]$Vector.writer_contract_sha256
    )
    $normalized = @($values | ForEach-Object {
        $_.Normalize([Text.NormalizationForm]::FormC)
    })
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($normalized -join "`n"))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
    return [string]$Fence.session_mutex_prefix + $digest
}

function Assert-WriterSessionPublicContract([string]$Path, [string]$ExpectedSha256) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 65536) {
        throw "Writer session public contract is oversized."
    }
    if ((Get-FileSha256 $Path) -cne $ExpectedSha256) {
        throw "Writer session public contract hash differs."
    }
    try { $contract = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Writer session public contract JSON is invalid." }
    $bindings = @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','session_authority_mutex_name','adapter_sha256','contract_sha256','evidence_path','historical_capability.receipt_sha256','historical_capability.capability_binding_sha256')
    $fenceFields = @('active_schema','release_schema','control_root','active_filename','release_filename_pattern','admission_mutex_name','noncanonical_mutex_derivation','session_mutex_prefix','session_tuple_version','session_tuple_fields','tuple_separator','tuple_encoding','tuple_normalization','writer_inventory_path','writer_inventory_sha256','canonical_installer_delegation_source','scheduled_task_mutation_rule','natural_trigger_phase_rule','verification_vectors','active_statuses','writer_admission_fail_closed','unknown_or_unobservable_is_denied','denial_mutates_state')
    $fenceStringFields = @('active_schema','release_schema','control_root','active_filename','release_filename_pattern','admission_mutex_name','noncanonical_mutex_derivation','session_mutex_prefix','session_tuple_version','tuple_separator','tuple_encoding','tuple_normalization','writer_inventory_path','writer_inventory_sha256','canonical_installer_delegation_source','scheduled_task_mutation_rule','natural_trigger_phase_rule')
    $vectorFields = @('session_id','attempt_id','orchestrator_sha256','replacement_transaction_id','writer_contract_sha256','expected_mutex_name')
    $vectors = @($contract.all_writer_fence.verification_vectors)
    $vectorsValid = $vectors.Count -eq 2
    foreach ($vector in $vectors) {
        if (
            -not (Test-WriterSessionContractExactPropertySet $vector $vectorFields) -or
            -not (Test-WriterSessionContractExactStringProperties $vector $vectorFields) -or
            [string]$vector.session_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.orchestrator_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$vector.replacement_transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.writer_contract_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$vector.expected_mutex_name -cne (Get-WriterSessionContractMutexName $contract.all_writer_fence $vector)
        ) { $vectorsValid = $false }
    }
    if ($vectors.Count -eq 2) {
        $vectorsValid = $vectorsValid -and
            [string]$vectors[0].expected_mutex_name -ceq 'Local\KMTech.ContainerAudit.DeploymentSession.1121406d92315036b04c14edfea1a09a03938923fa052324623e225d006a7b0c' -and
            [string]$vectors[1].expected_mutex_name -ceq 'Local\KMTech.ContainerAudit.DeploymentSession.7487aff53f2ea39a278e3648037625e8c1484636d80a5177dee05ba06556f071'
    }
    $requiredTrue = @(
        $contract.lifecycle_restore.require_same_session_receipt,
        $contract.lifecycle_restore.require_code_restore_before_writer_restore,
        $contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore,
        $contract.lifecycle_restore.require_live_current_user_lifecycle_before_writer_restore,
        $contract.lifecycle_restore.require_non_elevated_medium_integrity_lifecycle_producer,
        $contract.lifecycle_restore.producer_code_tree_read_locked_through_execution,
        $contract.lifecycle_restore.failure_is_explicit,
        $contract.security.active_session_authority_mutex_required,
        $contract.security.all_writer_fence_required,
        $contract.security.all_writer_sinks_require_admission,
        $contract.security.evidence_paths_outside_install_parent_required,
        $contract.security.evidence_paths_local_fixed_drive_required,
        $contract.security.evidence_path_reparse_ancestors_forbidden,
        $contract.security.evidence_path_aliases_canonicalized
    )
    $requiredFalse = @($contract.security.secret_values_recorded, $contract.security.manual_writer_start_allowed, $contract.security.contract_mode_system_mutation, $contract.all_writer_fence.denial_mutates_state)
    if (
        [string]$contract.schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$contract.app_id -cne 'container_audit' -or
        [string]$contract.cli.relative_path -cne 'tools/container_writer_session.ps1' -or
        (@($contract.cli.public_writer_modes) -join ',') -cne 'Contract,Prepare,ValidatePrepared,RestoreWriter' -or
        -not (Test-BootstrapJsonInteger $contract.cli.success_exit_code) -or [int64]$contract.cli.success_exit_code -ne 0 -or
        @($contract.cli.failure_exit_codes | Where-Object { -not (Test-BootstrapJsonInteger $_) }).Count -ne 0 -or
        (@($contract.cli.failure_exit_codes) -join ',') -cne '1,20' -or
        -not (Test-BootstrapJsonInteger $contract.identifiers.session_max_age_hours) -or [int64]$contract.identifiers.session_max_age_hours -ne 24 -or
        [string]$contract.identifiers.session_authority_mutex_derivation -cne 'Local\KMTech.ContainerAudit.DeploymentSession.<sha256(v1 canonical session tuple)>' -or
        -not (Test-WriterSessionContractExactPropertySet $contract.all_writer_fence $fenceFields) -or
        -not (Test-WriterSessionContractExactStringProperties $contract.all_writer_fence $fenceStringFields) -or
        [string]$contract.all_writer_fence.active_schema -cne 'container-audit-all-writer-fence-active-v1' -or
        [string]$contract.all_writer_fence.release_schema -cne 'container-audit-all-writer-fence-release-v1' -or
        [string]$contract.all_writer_fence.control_root -cne '%LOCALAPPDATA%\KMTech\DirectSync\container_audit\control\writer-session' -or
        [string]$contract.all_writer_fence.active_filename -cne 'active.json' -or
        [string]$contract.all_writer_fence.release_filename_pattern -cne 'release-{replacement_transaction_id}-{release_authorization_sha256}.json' -or
        [string]$contract.all_writer_fence.admission_mutex_name -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1' -or
        [string]$contract.all_writer_fence.noncanonical_mutex_derivation -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1.<first 16 lowercase hex characters of SHA-256 over the absolute control root after slash-to-backslash conversion, trailing-backslash removal, Unicode NFC, and ASCII A-Z to a-z mapping with every other code point unchanged, encoded as UTF-8 without BOM>' -or
        [string]$contract.all_writer_fence.session_mutex_prefix -cne 'Local\KMTech.ContainerAudit.DeploymentSession.' -or
        [string]$contract.all_writer_fence.session_tuple_version -cne 'container-audit-deployment-session-authority-v1' -or
        $contract.all_writer_fence.session_tuple_fields -isnot [Object[]] -or
        @($contract.all_writer_fence.session_tuple_fields | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        (@($contract.all_writer_fence.session_tuple_fields) -join ',') -cne 'session_tuple_version,session_id,attempt_id,orchestrator_sha256,replacement_transaction_id,writer_contract_sha256' -or
        [string]$contract.all_writer_fence.tuple_separator -cne 'LF (U+000A) between ordered fields; no trailing LF' -or
        [string]$contract.all_writer_fence.tuple_encoding -cne 'UTF-8 without BOM' -or
        [string]$contract.all_writer_fence.tuple_normalization -cne 'Unicode NFC applied to each field before joining' -or
        [string]$contract.all_writer_fence.writer_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$contract.all_writer_fence.canonical_installer_delegation_source -cne 'writer_sink_sources from the exact pinned code-derived inventory' -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.scheduled_task_mutation_rule) -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.natural_trigger_phase_rule) -or
        [string]$contract.all_writer_fence.writer_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $contract.all_writer_fence.verification_vectors -isnot [Object[]] -or
        $contract.all_writer_fence.active_statuses -isnot [Object[]] -or
        @($contract.all_writer_fence.active_statuses | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        (@($contract.all_writer_fence.active_statuses) -join ',') -cne 'PREPARING,PREPARED,RESTORING,RESTORE_FAILED,INSTALLING' -or
        $contract.all_writer_fence.writer_admission_fail_closed -isnot [bool] -or -not $contract.all_writer_fence.writer_admission_fail_closed -or
        $contract.all_writer_fence.unknown_or_unobservable_is_denied -isnot [bool] -or -not $contract.all_writer_fence.unknown_or_unobservable_is_denied -or
        -not $vectorsValid -or
        [string]$contract.receipts.prepared_schema -cne 'container-audit-writer-session-prepared-v3' -or
        [string]$contract.receipts.restored_schema -cne 'container-audit-writer-session-restored-v2' -or
        [string]$contract.receipts.lifecycle_restore_schema -cne 'container-audit-replacement-lifecycle-restore-v1' -or
        (@($contract.receipts.prepared_required_bindings) -join ',') -cne ($bindings -join ',') -or
        [string]$contract.lifecycle_restore.product_mode -cne '--restore-current-user-lifecycle-after-replacement' -or
        @($requiredTrue | Where-Object { $_ -isnot [bool] -or -not $_ }).Count -ne 0 -or
        @($requiredFalse | Where-Object { $_ -isnot [bool] -or $_ }).Count -ne 0
    ) { throw "Writer session public contract semantics differ." }
}

function Get-CodeInventoryInRecordOrder([string]$Root, [object[]]$RecordedFiles) {
    # V1 records predate ordinal issuance. Preserve their exact order and digest;
    # only a bijection onto the actual, case-sensitive relative paths is valid.
    # Both consumers still check every size/hash and the original aggregate.
    $inventory = @(Get-CodeInventory $Root)
    if ($RecordedFiles.Count -ne $inventory.Count) {
        throw 'Bootstrap integrity inventory differs: recorded file count.'
    }
    $actualByPath = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($item in $inventory) { $actualByPath.Add([string]$item.path, $item) }
    $ordered = @()
    foreach ($expected in $RecordedFiles) {
        if ($expected.path -isnot [string] -or -not $actualByPath.ContainsKey($expected.path)) {
            throw 'Bootstrap integrity inventory differs: missing, duplicate or changed path.'
        }
        $ordered += $actualByPath[$expected.path]
        [void]$actualByPath.Remove($expected.path)
    }
    return $ordered
}
