#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [string]$ServerBaseUrl = "https://worker.kmtecherp.com",
    [string]$DataRoot = "",
    [string]$DirectSyncRoot = "C:\ProgramData\KMTech\DirectSync\container_audit",
    [string]$TaskName = "direct-sync-relay-container-audit",
    [string]$EnrollmentTokenEnv = "CONTAINER_AUDIT_ENROLLMENT_TOKEN"
)

$ErrorActionPreference = "Stop"

function Assert-HttpsServerBaseUrl([string]$Value) {
    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "ServerBaseUrl must be an absolute HTTPS origin."
    }
    if (
        $uri.Scheme -cne "https" -or
        -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        -not [string]::IsNullOrWhiteSpace($uri.Fragment)
    ) {
        throw "ServerBaseUrl must be an HTTPS origin without userinfo, query, or fragment."
    }
}
function Remove-NewMachineProfilesFromRegistrationReport([string]$RegistrationReportPath) {
    if (-not (Test-Path -LiteralPath $RegistrationReportPath -PathType Leaf)) {
        return
    }
    $payload = Get-Content -LiteralPath $RegistrationReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $payload.machine_profiles) {
        return
    }
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $profileRoot = Join-Path $programData "KMTech\Logistics"
    $allowed = @(
        [System.IO.Path]::GetFullPath((Join-Path $profileRoot "runtime-profile.json")),
        [System.IO.Path]::GetFullPath((Join-Path $profileRoot "secrets\bearer-token.dpapi"))
    )
    foreach ($property in $payload.machine_profiles.PSObject.Properties) {
        $profile = $property.Value
        if ([string]$profile.status -cne "installed") {
            continue
        }
        foreach ($createdPath in @($profile.created_paths)) {
            $fullPath = [System.IO.Path]::GetFullPath([string]$createdPath)
            if ($allowed -notcontains $fullPath) {
                throw "Refusing to roll back an unexpected machine profile path."
            }
            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop
            }
        }
    }
}


Assert-HttpsServerBaseUrl $ServerBaseUrl
if ($DryRun.IsPresent -and $Uninstall.IsPresent) {
    throw "Use either -DryRun or -Uninstall, not both."
}

$packageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($DataRoot)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is unavailable; pass -DataRoot explicitly."
    }
    $DataRoot = Join-Path $env:LOCALAPPDATA "KMTech\ContainerAudit"
}
$appExe = Join-Path $packageRoot "Container_Audit.exe"
$installExe = Join-Path $packageRoot "Container_Audit_DirectSync_Install.exe"
$runnerExe = Join-Path $packageRoot "Container_Audit_DirectSync_Relay.exe"
$registrationExe = Join-Path $packageRoot "Container_Audit_Worker_PC_Register.exe"
foreach ($required in @($appExe, $installExe, $runnerExe, $registrationExe)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Release package is incomplete. Missing: $required"
    }
}

$eventDir = Join-Path $DataRoot "events"
$statusDir = Join-Path $DirectSyncRoot "status"
$manifestPath = Join-Path $DirectSyncRoot "producer_manifest.json"
$credentialPath = Join-Path $DirectSyncRoot "credential.json"
$registrationReportPath = Join-Path $statusDir "worker_pc_registration.json"
$installReportPath = Join-Path $statusDir "container_audit_direct_sync_install.json"

if ($DryRun.IsPresent) {
    Write-Output "install_status=DRY_RUN"
    Write-Output "package_root=$packageRoot"
    Write-Output "data_root=$DataRoot"
    Write-Output "direct_sync_root=$DirectSyncRoot"
    exit 0
}

if ($Uninstall.IsPresent) {
    & $installExe `
        --apply `
        --uninstall `
        --confirm-production-install `
        --app-root $packageRoot `
        --program-data-root $DirectSyncRoot `
        --task-name $TaskName `
        --report-path $installReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "Container_Audit direct-sync uninstall failed. Report: $installReportPath"
    }
    Write-Output "install_status=UNINSTALLED"
    Write-Output "install_report=$installReportPath"
    exit 0
}

New-Item -ItemType Directory -Path $eventDir -Force | Out-Null
New-Item -ItemType Directory -Path $statusDir -Force | Out-Null

# Preserve the app's established per-user data root. SYSTEM can read that
# source, while the machine-scope DPAPI credential and relay state stay under
# the ProgramData root.

$endpointUrl = "$($ServerBaseUrl.Trim().TrimEnd('/'))/api/producer-ingest/v1/source-file"
& $registrationExe `
    --app-root $packageRoot `
    --endpoint-url $endpointUrl `
    --self-enroll `
    --require-machine-credential-bundle `
    --enrollment-token-env $EnrollmentTokenEnv `
    --manifest-path $manifestPath `
    --credential-path $credentialPath `
    --report-path $registrationReportPath
if ($LASTEXITCODE -ne 0) {
    throw "Container_Audit self-enrollment failed. Report: $registrationReportPath"
}

& $installExe `
    --apply `
    --confirm-production-install `
    --app-root $packageRoot `
    --program-data-root $DirectSyncRoot `
    --producer-manifest-path $manifestPath `
    --credential-path $credentialPath `
    --scan-source-dir $eventDir `
    --source-glob "*.csv" `
    --task-name $TaskName `
    --report-path $installReportPath
if ($LASTEXITCODE -ne 0) {
    throw "Container_Audit direct-sync installation failed. Report: $installReportPath"
}

$report = Get-Content -LiteralPath $installReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    [string]$report.status -cne "PASS" -or
    [string]$report.task_principal.mode -cne "system_service_account" -or
    [string]$report.task_principal.run_user -cne "SYSTEM"
) {
    throw "Container_Audit install report did not prove the SYSTEM task contract."
}
try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
catch {
    $startFailure = $_
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NewMachineProfilesFromRegistrationReport $registrationReportPath
    throw $startFailure
}

Write-Output "install_status=PASS"
Write-Output "registration_report=$registrationReportPath"
Write-Output "install_report=$installReportPath"
