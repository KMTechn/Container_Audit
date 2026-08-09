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

function ConvertTo-ElevationArgument([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashCount += 1
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append((('\' * (($slashCount * 2) + 1)) -join ''))
            [void]$builder.Append('"')
            $slashCount = 0
            continue
        }
        if ($slashCount -gt 0) {
            [void]$builder.Append((('\' * $slashCount) -join ''))
            $slashCount = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashCount -gt 0) {
        [void]$builder.Append((('\' * ($slashCount * 2)) -join ''))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-SelfElevated(
    [string]$ScriptPath,
    [hashtable]$BoundParameters,
    [object[]]$RemainingArguments
) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }
    $powershellExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $launchArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    foreach ($name in $BoundParameters.Keys) {
        $value = $BoundParameters[$name]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $launchArguments += "-$name" }
            continue
        }
        $launchArguments += @("-$name", [string]$value)
    }
    $launchArguments += @($RemainingArguments | ForEach-Object { [string]$_ })
    $argumentLine = ($launchArguments | ForEach-Object { ConvertTo-ElevationArgument $_ }) -join ' '
    $process = Start-Process -FilePath $powershellExe -Verb RunAs -ArgumentList $argumentLine -Wait -PassThru -ErrorAction Stop
    exit $process.ExitCode
}

Invoke-SelfElevated $MyInvocation.MyCommand.Path $PSBoundParameters $args

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

function Wait-CurrentRuntimeLease([datetime]$Started, [string]$ProgramDataRoot, [string]$AuthorizedManifestHash) {
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
                $lease = $runtime.runtime_lease
                $leaseExpiry = [datetime]::MinValue
                if (
                    $null -ne $lease -and
                    [string]$lease.status -ceq "ACTIVE" -and
                    $lease.server_grant_accepted -is [bool] -and [bool]$lease.server_grant_accepted -and
                    -not [string]::IsNullOrWhiteSpace([string]$lease.producer_install_id) -and
                    -not [string]::IsNullOrWhiteSpace([string]$lease.runtime_instance_id) -and
                    -not [string]::IsNullOrWhiteSpace([string]$lease.lease_id) -and
                    [datetime]::TryParse([string]$lease.expires_at, [ref]$leaseExpiry) -and
                    $leaseExpiry.ToUniversalTime() -gt (Get-Date).ToUniversalTime()
                ) {
                    return
                }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Relay did not prove a current server runtime lease within 120 seconds."
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
    Wait-CurrentRuntimeLease $relayStarted $DirectSyncRoot $authorizedManifestHash
}
catch {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    throw "APPLIED_UNPROVEN: relay task was installed but current runtime liveness was not proven: $($_.Exception.Message)"
}

Write-Output "install_status=PASS"
Write-Output "registration_report=$registrationReportPath"
Write-Output "install_report=$installReportPath"
