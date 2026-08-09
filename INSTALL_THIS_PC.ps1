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

function Read-BoundedJson([string]$Path, [string]$Purpose) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Purpose is absent." }
    $length = (Get-Item -LiteralPath $Path -Force).Length
    if ($length -le 0 -or $length -gt 1048576) { throw "$Purpose size is invalid." }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Get-RequiredNonNegativeInteger($Object, [string]$Name, [string]$Purpose) {
    $property = if ($null -eq $Object) { $null } else { $Object.PSObject.Properties[$Name] }
    $parsed = [long]0
    if ($null -eq $property -or -not [long]::TryParse([string]$property.Value, [ref]$parsed) -or $parsed -lt 0) {
        throw "$Purpose is invalid."
    }
    return $parsed
}

function Get-RelayQueueCount($Counts, [string]$Name) {
    if ($null -eq $Counts -or $null -eq $Counts.PSObject.Properties[$Name]) { return [long]0 }
    return Get-RequiredNonNegativeInteger $Counts $Name "Relay queue count $Name"
}

function Wait-CleanAcceptedReceipt([datetime]$Started, [string]$ProgramDataRoot, [string]$AuthorizedManifestHash) {
    $runtimePath = Join-Path $ProgramDataRoot "status\direct_sync_relay_status.json"
    $deadline = (Get-Date).AddSeconds(120)
    do {
        if (Test-Path -LiteralPath $runtimePath -PathType Leaf) {
            $runtimeItem = Get-Item -LiteralPath $runtimePath -Force
            if ($runtimeItem.LastWriteTimeUtc -ge $Started) {
                $runtime = Read-BoundedJson $runtimePath "Relay runtime status"
                if ([string]$runtime.manifest_hash -cne $AuthorizedManifestHash) {
                    throw "Relay runtime manifest hash differs from the server-authorized manifest hash."
                }
                $last = $runtime.last_result
                $uploadPath = if ($null -eq $last) { "" } else { [string]$last.upload_status_path }
                if ([string]$runtime.status -ceq "acked" -and [string]$last.status -ceq "acked" -and
                    $last.success -is [bool] -and [bool]$last.success -and
                    $last.committed -is [bool] -and [bool]$last.committed -and
                    -not [string]::IsNullOrWhiteSpace($uploadPath)) {
                    $rootFull = [IO.Path]::GetFullPath($ProgramDataRoot).TrimEnd('\') + '\'
                    $uploadFull = [IO.Path]::GetFullPath($uploadPath)
                    if (-not $uploadFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
                        throw "Relay upload status path escapes DirectSyncRoot."
                    }
                    if ((Get-Item -LiteralPath $uploadFull -Force).LastWriteTimeUtc -lt $Started) {
                        throw "Relay upload status is stale."
                    }
                    $upload = Read-BoundedJson $uploadFull "Relay upload status"
                    if ($upload.success -isnot [bool] -or -not [bool]$upload.success -or
                        $upload.committed -isnot [bool] -or -not [bool]$upload.committed -or
                        [int]$upload.status_code -lt 200 -or [int]$upload.status_code -ge 300 -or
                        -not [string]::IsNullOrWhiteSpace([string]$upload.error_code) -or
                        [string]$upload.receipt.status -cne "accepted" -or
                        $upload.receipt.committed -isnot [bool] -or -not [bool]$upload.receipt.committed) {
                        throw "Relay upload did not prove a committed accepted receipt."
                    }
                    $errors = Get-RequiredNonNegativeInteger $upload.receipt.totals "errors" "Receipt error count"
                    $quarantined = Get-RequiredNonNegativeInteger $upload.receipt.totals "quarantined" "Receipt quarantine count"
                    $inserted = Get-RequiredNonNegativeInteger $upload.receipt.totals "inserted" "Receipt inserted count"
                    $replayed = Get-RequiredNonNegativeInteger $upload.receipt.totals "replayed" "Receipt replayed count"
                    $failed = Get-RelayQueueCount $runtime.queue.counts "failed_permanent"
                    $review = Get-RelayQueueCount $runtime.queue.counts "operator_review"
                    if ($errors -ne 0 -or $quarantined -ne 0 -or ($inserted + $replayed) -le 0 -or $failed -ne 0 -or $review -ne 0) {
                        throw "Relay receipt or queue contains unresolved failures."
                    }
                    return
                }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Relay did not produce a clean accepted receipt within 120 seconds."
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
$registrationReport = Read-BoundedJson $registrationReportPath "Container_Audit registration report"
if (
    [string]$registrationReport.status -cne "SELF_ENROLLMENT_REGISTERED" -or
    $registrationReport.server_registration_verified -isnot [bool] -or -not [bool]$registrationReport.server_registration_verified -or
    $registrationReport.manifest_hash_verified -isnot [bool] -or -not [bool]$registrationReport.manifest_hash_verified -or
    $registrationReport.persisted_manifest_hash_verified -isnot [bool] -or -not [bool]$registrationReport.persisted_manifest_hash_verified
) {
    throw "Container_Audit registration report did not prove the persisted server-authorized manifest."
}
$authorizedManifestHash = ([string]$registrationReport.manifest_hash).ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($authorizedManifestHash)) {
    throw "Container_Audit registration report omitted the authorized manifest hash."
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
    $relayStarted = (Get-Date).ToUniversalTime()
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
catch {
    $startFailure = $_
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NewMachineProfilesFromRegistrationReport $registrationReportPath
    throw $startFailure
}
try {
    Wait-CleanAcceptedReceipt $relayStarted $DirectSyncRoot $authorizedManifestHash
}
catch {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    throw "APPLIED_UNPROVEN: relay task was installed but the first clean accepted receipt was not proven: $($_.Exception.Message)"
}

Write-Output "install_status=PASS"
Write-Output "registration_report=$registrationReportPath"
Write-Output "install_report=$installReportPath"
