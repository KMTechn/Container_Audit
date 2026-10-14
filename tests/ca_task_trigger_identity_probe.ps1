$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$originalResolver=${function:ConvertTo-BootstrapPrincipalSid}
$Script:NameResolutionCalls=0
function ConvertTo-BootstrapPrincipalSid([string]$Identity){
    if($Identity.StartsWith('S-',[StringComparison]::OrdinalIgnoreCase)){
        return & $originalResolver $Identity
    }
    $Script:NameResolutionCalls++
    if($Identity -ieq 'worker' -or $Identity -ieq 'HOST\worker'){return $env:CA_TRIGGER_POLICY}
    if($Identity -ieq 'HOST\administrator'){return 'S-1-5-21-101-202-303-1002'}
    if($Identity -ceq 'SYSTEM'){return 'S-1-5-18'}
    throw 'unknown account'
}
[xml]$task=[IO.File]::ReadAllText($env:CA_TRIGGER_XML)
$actual=Get-BootstrapTaskTriggerIdentityStatus $task $env:CA_TRIGGER_POLICY
if($actual -cne $env:CA_TRIGGER_EXPECTED){throw 'trigger identity classification differs'}
if($actual -ceq 'INVALID' -and $Script:NameResolutionCalls -ne 0){throw 'invalid shape reached account resolution'}
Write-Output 'TRIGGER_IDENTITY_PASS'
