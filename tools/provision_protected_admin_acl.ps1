[CmdletBinding()]
param(
    [string]$ReaderPrincipal = "",
    [string]$ProfilePath = "",
    [switch]$Replace,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$installerPath = Join-Path $PSScriptRoot "Container_Audit_Protected_Admin_Install.exe"
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw "Protected administrator installer is missing from the release directory."
}
if ($DryRun -and $Replace) {
    throw "Replace cannot be combined with DryRun."
}
if (-not $DryRun) {
    if ([string]::IsNullOrWhiteSpace($ReaderPrincipal)) {
        throw "ReaderPrincipal must identify the narrow Windows user that runs Container Audit."
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $windowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Protected administrator provisioning requires an elevated PowerShell session."
    }
}

$installerArguments = @()
if ($DryRun) {
    $installerArguments += "--dry-run"
}
else {
    $installerArguments += @("--reader-principal", $ReaderPrincipal)
}
if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) {
    $installerArguments += @("--profile-path", $ProfilePath)
}
if ($Replace) {
    $installerArguments += "--replace"
}

$publicLibrary=Join-Path $PSScriptRoot 'bootstrap_integrity.ps1'
if(-not (Test-Path -LiteralPath $publicLibrary -PathType Leaf)){throw 'Public output contract helper is unavailable.'}
. $publicLibrary
if(-not $DryRun){Write-Host '관리자 암호를 입력한 다음 같은 암호를 다시 입력하세요.'}
try {
    # The caller has no proven protected report writer. Native/bootstrap output
    # is captured and discarded, including output before the Python main runs.
    $previousPreference=$ErrorActionPreference
    try {
        # PS 5.1 represents captured native stderr as nonterminating errors.
        # Hidden-input prompts on that stream must not abort the child.
        $ErrorActionPreference='Continue';$LASTEXITCODE=$null
        $childOutput=@(& $installerPath @installerArguments 2>&1)
        $childCode=$LASTEXITCODE
    } finally {$ErrorActionPreference=$previousPreference}
    if($null -eq $childCode){throw 'Native support child did not return an exit code.'}
    $fields=[ordered]@{status=if($childCode -eq 0){'PASS'}else{'FAILED'};
        stage='protected_admin_install';exit_code=[int]$childCode;
        reason_code=if($childCode -eq 0){'SUPPORT_RESULT'}else{'SUPPORT_FAILURE'};
        report_status='REPORT_UNAVAILABLE';guidance='설정 파일과 설치 경로를 확인하고 다시 실행하세요.'}
} catch {
    $childCode=1
    $fields=[ordered]@{status='FAILED';stage='protected_admin_install';reason_code='SUPPORT_FAILURE';
        exception_type=$_.Exception.GetType().FullName;report_status='REPORT_UNAVAILABLE';
        guidance='설정 파일과 설치 경로를 확인하고 다시 실행하세요.'}
}
$childOutput=$null
$public=ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes @('PASS','FAILED','protected_admin_install','SUPPORT_RESULT','SUPPORT_FAILURE','REPORT_UNAVAILABLE') -SafeMessages @('설정 파일과 설치 경로를 확인하고 다시 실행하세요.')
Write-Output ('CONTAINER_AUDIT_SUPPORT='+($public|ConvertTo-Json -Depth 4 -Compress))
if($childCode -ne 0){exit 1}

$mode = if ($DryRun) { "dry-run" } else { "installed" }
Write-Output "protected_admin_provision=PASS mode=$mode"
