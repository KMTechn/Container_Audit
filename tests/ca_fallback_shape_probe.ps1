$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Protect-InstallationText($Text,[int]$Limit=512,[switch]$Configuration){
    if($Configuration){return @{full_byte_cap=65536}}
    return [string]$Text
}
function ConvertTo-KmtechRedactedSinkText([string]$Text){return $Text}
function Get-InstallationFailureDetails($Failure){return @{type=$Failure.Exception.GetType().Name}}
$Script:InstallationEvidenceRoot=''
$Script:InstallationEvidenceSensitiveValues=@()
$Script:InstallationEvidenceFailureCodes=[Collections.Generic.List[string]]::new()
$Script:InstallationOriginalFailure=@{status='PRESERVED';sha256=('a'*64)}
$original=$Script:InstallationOriginalFailure
$Script:events=[Collections.Generic.List[object]]::new()
function Write-InstallationCaughtFailure($Failure){throw 'secondary parser took original failure'}
function Write-InstallationEvidenceEvent($Value){
    if($env:CA_FALLBACK_SHAPE -eq 'writer_failure' -and $Value.event -eq 'CHILD_FAILURE_DIAGNOSTIC_UNKNOWN'){
        throw [IO.IOException]::new('evidence writer denied')
    }
    $Script:events.Add($Value)
}
$shape=$env:CA_FALLBACK_SHAPE
if($shape.EndsWith('_empty')){
    $shape=$shape.Substring(0,$shape.Length-6)
    $Script:InstallationOriginalFailure=$null;$original=$null
}
$legacy=@{schema='container-audit-installation-fallback-v1';exit_code=73;failure=@{message='primary lifecycle cause'}}
$json=switch($shape){
    'public' {'{"code":"MACHINE_INSTALL_FAILED","status":"FAILED","reason":"lifecycle_task_absence_or_unknown"}'}
    'legacy' {$legacy|ConvertTo-Json -Compress}
    'missing_exit' {$legacy.Remove('exit_code');$legacy|ConvertTo-Json -Compress}
    'string_exit' {$legacy.exit_code='73';$legacy|ConvertTo-Json -Compress}
    'null_exit' {$legacy.exit_code=$null;$legacy|ConvertTo-Json -Compress}
    'bool_exit' {$legacy.exit_code=$true;$legacy|ConvertTo-Json -Compress}
    'fraction_exit' {$legacy.exit_code=73.5;$legacy|ConvertTo-Json -Compress}
    'mismatch' {$legacy.exit_code=72;$legacy|ConvertTo-Json -Compress}
    'null' {'null'}
    'array' {'[{},{}]'}
    'one_array' {'[{"schema":"container-audit-installation-fallback-v1","exit_code":73}]'}
    'corrupt' {'{broken'}
    'oversize' {'{"detail":"'+('x'*65536)+'"}'}
    'unknown_schema' {$legacy.schema='unknown';$legacy|ConvertTo-Json -Compress}
    'writer_failure' {'null'}
    default {throw 'unknown shape'}
}
$payload=Join-Path $env:CA_CONTRACT_ROOT 'child-payload.txt'
[IO.File]::WriteAllText($payload,('installation_failure_summary='+$json),[Text.UTF8Encoding]::new($false))
$child=Join-Path $env:CA_CONTRACT_ROOT 'finite-child.ps1'
[IO.File]::WriteAllText($child,@'
param([string]$Payload)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::WriteLine([IO.File]::ReadAllText($Payload))
[Console]::Error.WriteLine('lifecycle_task_absence_or_unknown')
exit 73
'@,[Text.UTF8Encoding]::new($false))
$engine=(Get-Process -Id $PID).Path
$caught=$null
try{$result=Invoke-InstallationEvidenceChild 'machine-placement-helper' $engine @('-NoProfile','-NonInteractive','-File',$child,$payload) $env:CA_CONTRACT_ROOT}
catch{$caught=$_}
if(-not [object]::ReferenceEquals($original,$Script:InstallationOriginalFailure)){throw 'original failure replaced'}
if($Script:InstallationFirstFailedChildCapture.exit_code -ne 73 -or
    $Script:InstallationFirstFailedChildCapture.stderr -notmatch 'lifecycle_task_absence_or_unknown'){throw 'primary child failure lost'}
if($shape -eq 'writer_failure'){
    if($null -eq $caught -or $caught.Exception.Message -notmatch 'evidence writer denied'){throw 'writer failure swallowed'}
}else{
    if($null -ne $caught){throw $caught}
    if($result.ExitCode -ne 73 -or $result.Stderr -notmatch 'lifecycle_task_absence_or_unknown' -or
        $result.Stdout -notmatch 'installation_failure_summary='){throw 'failed child rewritten'}
    if($shape -eq 'legacy'){
        if($null -eq $result.FailureDiagnostic -or $result.FailureDiagnostic.exit_code -ne 73){throw 'legacy selection lost'}
    }elseif($null -ne $result.FailureDiagnostic){throw 'invalid/mismatched fallback selected'}
    if($shape -notin @('legacy','mismatch')){
        $unknown=@($Script:events|Where-Object {$_.event -eq 'CHILD_FAILURE_DIAGNOSTIC_UNKNOWN'})
        if($unknown.Count -ne 1 -or $unknown[0].message -cne '진단 형식 모름'){throw 'unknown diagnostic missing'}
    }
}
Write-Output 'FALLBACK_SHAPE_PASS'
