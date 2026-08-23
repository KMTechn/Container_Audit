[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [switch]$PurgeContainerAuditState,
    [switch]$ConfirmPermanentContainerAuditDataRemoval,
    [string]$RollbackReportPath = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$EnableWindowsSandboxQualification,
    [string]$ServerBaseUrl = "https://worker.kmtecherp.com",
    [string]$DataRoot = "",
    [string]$DirectSyncRoot = "C:\ProgramData\KMTech\DirectSync\container_audit",
    [string]$TaskName = "direct-sync-relay-container-audit",
    [string]$EnrollmentTokenEnv = "CONTAINER_AUDIT_ENROLLMENT_TOKEN",
    [string]$ExistingProducerManifestPath = "",
    [string]$ExistingCredentialPath = "",
    [string]$ExistingRegistrationReportPath = "",
    [string]$ProducerIdentityPath = "",
    [string]$ProducerInstallId = "",
    [string]$ProducerId = "",
    [string]$SourceHostId = "",
    [string]$OperatorUserSid = "",
    [string]$OperatorLocalAppDataRoot = ""
)

$ErrorActionPreference = "Stop"

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

function Get-CurrentOperatorContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User -or [string]::IsNullOrWhiteSpace($identity.User.Value)) {
        throw "The invoking operator SID is unavailable."
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "The invoking operator LOCALAPPDATA is unavailable."
    }
    return [ordered]@{
        sid = $identity.User.Value
        local_app_data_root = [System.IO.Path]::GetFullPath($env:LOCALAPPDATA)
    }
}

$currentOperator = Get-CurrentOperatorContext
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$currentIsAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $currentIsAdministrator) {
    if (
        (-not [string]::IsNullOrWhiteSpace($OperatorUserSid) -and $OperatorUserSid -cne $currentOperator.sid) -or
        (-not [string]::IsNullOrWhiteSpace($OperatorLocalAppDataRoot) -and
            -not ([System.IO.Path]::GetFullPath($OperatorLocalAppDataRoot)).Equals(
                $currentOperator.local_app_data_root,
                [System.StringComparison]::OrdinalIgnoreCase
            ))
    ) {
        throw "Operator identity parameters cannot replace the invoking non-elevated operator."
    }
    $OperatorUserSid = $currentOperator.sid
    $OperatorLocalAppDataRoot = $currentOperator.local_app_data_root
    $PSBoundParameters["OperatorUserSid"] = $OperatorUserSid
    $PSBoundParameters["OperatorLocalAppDataRoot"] = $OperatorLocalAppDataRoot
}
else {
    if ([string]::IsNullOrWhiteSpace($OperatorUserSid)) {
        $OperatorUserSid = $currentOperator.sid
    }
    if ([string]::IsNullOrWhiteSpace($OperatorLocalAppDataRoot)) {
        $OperatorLocalAppDataRoot = $currentOperator.local_app_data_root
    }
}

if (-not $DryRun.IsPresent) {
    Invoke-SelfElevated $MyInvocation.MyCommand.Path $PSBoundParameters $args
}


function Assert-HttpsServerBaseUrl([string]$Value, [switch]$AllowExplicitHttp) {
    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "ServerBaseUrl must be an absolute HTTP or HTTPS origin."
    }
    $schemeAllowed = (
        $uri.Scheme -ceq "https" -or
        ($AllowExplicitHttp.IsPresent -and $uri.Scheme -ceq "http")
    )
    if (
        -not $schemeAllowed -or
        -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        -not [string]::IsNullOrWhiteSpace($uri.Fragment)
    ) {
        throw "ServerBaseUrl must be an HTTPS origin, or an HTTP origin authorized by Windows Sandbox qualification, without userinfo, query, or fragment."
    }
}
function Resolve-ProducerSubmissionBaseUrl(
    [string]$RequestedServerBaseUrl,
    [bool]$RequestedServerBaseUrlIsExplicit,
    [string]$QualificationAuthorityServerBaseUrl
) {
    # The qualification authority keeps its loopback origin for its own bounded
    # duties. An explicitly supplied origin stays the product's receipt/projection
    # submission target instead of being replaced by it, production default included.
    if ($RequestedServerBaseUrlIsExplicit) {
        return $RequestedServerBaseUrl.Trim().TrimEnd('/')
    }
    return $QualificationAuthorityServerBaseUrl.Trim().TrimEnd('/')
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
    $profileRoot = Join-Path $programData "KMTech\Logistics\profiles\Container_Audit"
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

function Write-Utf8JsonFile([string]$Path, $Payload) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $json = $Payload | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [System.Environment]::NewLine, $utf8NoBom)
}

function Test-SamePath([string]$Left, [string]$Right) {
    if (
        [string]::IsNullOrWhiteSpace($Left) -or
        [string]::IsNullOrWhiteSpace($Right) -or
        -not [System.IO.Path]::IsPathRooted($Left) -or
        -not [System.IO.Path]::IsPathRooted($Right)
    ) {
        return $false
    }
    $leftFull = [System.IO.Path]::GetFullPath($Left).TrimEnd('\')
    $rightFull = [System.IO.Path]::GetFullPath($Right).TrimEnd('\')
    return $leftFull.Equals($rightFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-StrictFullPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Purpose path is required."
    }
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose path must be absolute."
    }
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "$Purpose path must not use a device namespace."
    }
    if ($Path -match '(^|[\\/])\.\.?(?:[\\/]|$)') {
        throw "$Purpose path must not contain traversal segments."
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($fullPath) -or $fullPath.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose path must not be a filesystem root."
    }
    $rootLength = [System.IO.Path]::GetPathRoot($fullPath).Length
    if ($fullPath.Substring($rootLength).Contains(':')) {
        throw "$Purpose path must not contain an alternate data stream."
    }
    return $fullPath
}

function Assert-ExactCanonicalPath([string]$Actual, [string]$Expected, [string]$Purpose) {
    $actualFull = Get-StrictFullPath $Actual $Purpose
    $expectedFull = Get-StrictFullPath $Expected "$Purpose expected"
    if (-not $actualFull.Equals($expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose path is outside the exact owned location."
    }
    return $actualFull
}

function Test-PathWithin([string]$Candidate, [string]$Container) {
    $candidateFull = (Get-StrictFullPath $Candidate "Candidate").TrimEnd('\')
    $containerFull = (Get-StrictFullPath $Container "Container").TrimEnd('\')
    if ($candidateFull.Equals($containerFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $candidateFull.StartsWith(
        $containerFull + '\',
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Set-ProcessWorkingDirectoryOutsideOwnedTree([string]$OwnedRoot) {
    $ownedFull = Get-StrictFullPath $OwnedRoot "Owned application root"
    $safePath = Get-StrictFullPath ([Environment]::SystemDirectory) "Rollback working directory"
    if (Test-PathWithin $safePath $ownedFull) {
        throw "Rollback working directory must be outside the owned application root."
    }
    Set-Location -LiteralPath $safePath -ErrorAction Stop
    [Environment]::CurrentDirectory = $safePath
    $providerPath = [string](Get-Location).Path
    $processPath = [string][Environment]::CurrentDirectory
    if (-not (Test-SamePath $providerPath $safePath) -or -not (Test-SamePath $processPath $safePath)) {
        throw "Rollback could not relocate both PowerShell and process working directories."
    }
    return [ordered]@{
        status = "PASS"
        provider_location = $providerPath
        process_working_directory = $processPath
        outside_application_root = $true
    }
}

function Assert-NoReparsePoint([string]$Path, [string]$Purpose, [switch]$IncludeDescendants) {
    $fullPath = Get-StrictFullPath $Path $Purpose
    $cursor = $fullPath
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose contains a reparse point: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
    if ($IncludeDescendants.IsPresent -and (Test-Path -LiteralPath $fullPath -PathType Container)) {
        $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
        $pendingDirectories.Push($fullPath)
        while ($pendingDirectories.Count -gt 0) {
            $directory = $pendingDirectories.Pop()
            foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
                if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "$Purpose contains a descendant reparse point: $($child.FullName)"
                }
                if ($child.PSIsContainer) {
                    $pendingDirectories.Push($child.FullName)
                }
            }
        }
    }
}

function Assert-OperatorContext([string]$Sid, [string]$LocalAppDataRoot) {
    try {
        $securityIdentifier = New-Object Security.Principal.SecurityIdentifier -ArgumentList $Sid
    }
    catch {
        throw "OperatorUserSid is not a valid Windows SID."
    }
    if ($securityIdentifier.Value -cne $Sid) {
        throw "OperatorUserSid is not canonical."
    }
    $localRoot = Get-StrictFullPath $LocalAppDataRoot "OperatorLocalAppDataRoot"
    $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    if (-not (Test-Path -LiteralPath $profileKey)) {
        throw "OperatorUserSid has no local Windows profile."
    }
    $profilePathValue = [string](Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
    $profileRoot = Get-StrictFullPath ([Environment]::ExpandEnvironmentVariables($profilePathValue)) "Operator profile"
    $expectedLocalRoot = Join-Path $profileRoot "AppData\Local"
    [void](Assert-ExactCanonicalPath $localRoot $expectedLocalRoot "OperatorLocalAppDataRoot")
    Assert-NoReparsePoint $localRoot "OperatorLocalAppDataRoot"
    return $localRoot
}

function Get-ContainerAuditShortcutName {
    return -join @(
        [char]0xC774,
        [char]0xC801,
        [char]0x20,
        [char]0xAC80,
        [char]0xC0AC,
        [char]0x20,
        [char]0xC2DC,
        [char]0xC2A4,
        [char]0xD15C
    )
}

function Get-OwnedShortcutState(
    [string]$ShortcutPath,
    [string]$ExpectedTarget,
    [string]$ExpectedWorkingDirectory
) {
    Assert-NoReparsePoint $ShortcutPath "Container_Audit Start Menu shortcut"
    if (-not (Test-Path -LiteralPath $ShortcutPath)) {
        return [ordered]@{ status = "ABSENT"; path = $ShortcutPath }
    }
    if (-not (Test-Path -LiteralPath $ShortcutPath -PathType Leaf)) {
        throw "The Container_Audit Start Menu shortcut path is not a file."
    }
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $targetPath = [string]$shortcut.TargetPath
        $workingDirectory = [string]$shortcut.WorkingDirectory
        $arguments = [string]$shortcut.Arguments
        $iconLocation = [string]$shortcut.IconLocation
    }
    finally {
        if ($null -ne $shortcut) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
        }
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    $iconPath = $iconLocation
    $iconIndex = ""
    if ($iconLocation -match '^(.*),\s*(-?\d+)$') {
        $iconPath = $Matches[1].Trim().Trim('"')
        $iconIndex = $Matches[2]
    }
    if (
        -not (Test-SamePath $targetPath $ExpectedTarget) -or
        -not (Test-SamePath $workingDirectory $ExpectedWorkingDirectory) -or
        $arguments -cne "" -or
        -not (Test-SamePath $iconPath $ExpectedTarget) -or
        ($iconIndex -ne "" -and $iconIndex -cne "0")
    ) {
        throw "A conflicting Start Menu shortcut exists; refusing to overwrite or remove it."
    }
    return [ordered]@{
        status = "OWNED"
        path = $ShortcutPath
        target = $targetPath
        working_directory = $workingDirectory
        arguments = $arguments
        icon = $iconLocation
    }
}

function Install-OwnedShortcut(
    [string]$ShortcutPath,
    [string]$ExpectedTarget,
    [string]$ExpectedWorkingDirectory
) {
    $existing = Get-OwnedShortcutState $ShortcutPath $ExpectedTarget $ExpectedWorkingDirectory
    if ($existing.status -ceq "OWNED") {
        return $existing
    }
    $shortcutDirectory = Split-Path -Parent $ShortcutPath
    Assert-NoReparsePoint $shortcutDirectory "KMTech Start Menu group"
    New-Item -ItemType Directory -Path $shortcutDirectory -Force -ErrorAction Stop | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $shortcut.TargetPath = $ExpectedTarget
        $shortcut.WorkingDirectory = $ExpectedWorkingDirectory
        $shortcut.Arguments = ""
        $shortcut.IconLocation = "$ExpectedTarget,0"
        $shortcut.Save()
    }
    finally {
        if ($null -ne $shortcut) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
        }
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    return Get-OwnedShortcutState $ShortcutPath $ExpectedTarget $ExpectedWorkingDirectory
}

function Remove-OwnedShortcut(
    [string]$ShortcutPath,
    [string]$ExpectedTarget,
    [string]$ExpectedWorkingDirectory
) {
    $existing = Get-OwnedShortcutState $ShortcutPath $ExpectedTarget $ExpectedWorkingDirectory
    if ($existing.status -ceq "OWNED") {
        Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $ShortcutPath) {
        throw "Container_Audit Start Menu shortcut removal postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; path = $ShortcutPath }
}

function Get-OwnedScheduledTaskState([string]$Name, [string]$ExpectedLauncherPath) {
    $tasks = @(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) {
        return [ordered]@{ status = "ABSENT"; task_name = $Name }
    }
    if ($tasks.Count -ne 1) {
        throw "Multiple scheduled tasks use the Container_Audit task name."
    }
    $task = $tasks[0]
    if ([string]$task.TaskPath -cne "\") {
        throw "The Container_Audit scheduled task exists outside the owned root task path."
    }
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw "The Container_Audit scheduled task action is not owned."
    }
    $expectedCmd = Join-Path ([Environment]::SystemDirectory) "cmd.exe"
    $actualExecute = [string]$actions[0].Execute
    $actualArguments = ([string]$actions[0].Arguments).Trim()
    $expectedArguments = @(
        "/d /q /c $ExpectedLauncherPath",
        "/d /q /c `"$ExpectedLauncherPath`""
    )
    $argumentMatches = $false
    foreach ($candidate in $expectedArguments) {
        if ($actualArguments.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
            $argumentMatches = $true
            break
        }
    }
    $principal = [string]$task.Principal.UserId
    $principalMatches = @("SYSTEM", "NT AUTHORITY\SYSTEM", "S-1-5-18") -contains $principal
    if (
        -not (Test-SamePath $actualExecute $expectedCmd) -or
        -not $argumentMatches -or
        -not $principalMatches
    ) {
        throw "A conflicting scheduled task exists; refusing to stop or remove it."
    }
    return [ordered]@{
        status = "OWNED"
        task_name = $Name
        task_path = [string]$task.TaskPath
        execute = $actualExecute
        arguments = $actualArguments
        principal = $principal
    }
}

function Remove-OwnedScheduledTask(
    [string]$Name,
    [string]$ExpectedLauncherPath,
    [string]$InstallExecutable,
    [string]$ApplicationRoot,
    [string]$ProgramDataRoot,
    [string]$ReportPath
) {
    $state = Get-OwnedScheduledTaskState $Name $ExpectedLauncherPath
    if ($state.status -ceq "OWNED") {
        Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
        & $InstallExecutable `
            --apply `
            --uninstall `
            --confirm-production-install `
            --app-root $ApplicationRoot `
            --program-data-root $ProgramDataRoot `
            --task-name $Name `
            --report-path $ReportPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Container_Audit exact scheduled-task uninstall failed. Report: $ReportPath"
        }
    }
    if (@(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "Container_Audit scheduled-task removal postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; task_name = $Name }
}

function Get-OwnedQualificationAuthorityTaskState(
    [string]$Name,
    [string]$ExpectedExecutable,
    [string]$ExpectedStateRoot
) {
    $tasks = @(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) {
        return [ordered]@{ status = "ABSENT"; task_name = $Name }
    }
    if ($tasks.Count -ne 1) {
        throw "Multiple scheduled tasks use the Container_Audit qualification authority task name."
    }
    $task = $tasks[0]
    if ([string]$task.TaskPath -cne "\") {
        throw "The Container_Audit qualification authority task exists outside the owned root task path."
    }
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw "The Container_Audit qualification authority task action is not owned."
    }
    $expectedArguments = "serve --state-root `"$ExpectedStateRoot`""
    $actualExecute = [string]$actions[0].Execute
    $actualArguments = ([string]$actions[0].Arguments).Trim()
    $principal = [string]$task.Principal.UserId
    $principalMatches = @("SYSTEM", "NT AUTHORITY\SYSTEM", "S-1-5-18") -contains $principal
    if (
        -not (Test-SamePath $actualExecute $ExpectedExecutable) -or
        -not $actualArguments.Equals($expectedArguments, [System.StringComparison]::Ordinal) -or
        -not $principalMatches
    ) {
        throw "A conflicting qualification authority task exists; refusing to start, stop, or remove it."
    }
    return [ordered]@{
        status = "OWNED"
        task_name = $Name
        task_path = [string]$task.TaskPath
        execute = $actualExecute
        arguments = $actualArguments
        principal = $principal
    }
}

function Install-OwnedQualificationAuthorityTask(
    [string]$Name,
    [string]$Executable,
    [string]$StateRoot
) {
    $state = Get-OwnedQualificationAuthorityTaskState $Name $Executable $StateRoot
    if ($state.status -ceq "ABSENT") {
        $action = New-ScheduledTaskAction `
            -Execute $Executable `
            -Argument "serve --state-root `"$StateRoot`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask `
            -TaskName $Name `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Force | Out-Null
    }
    return (Get-OwnedQualificationAuthorityTaskState $Name $Executable $StateRoot)
}

function Get-OwnedQualificationAuthorityProcesses([string]$Executable) {
    $processes = @(
        Get-CimInstance Win32_Process -Filter "Name='Container_Audit_Qualification_Authority.exe'" -ErrorAction Stop
    )
    foreach ($process in $processes) {
        if ([string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)) {
            throw "Container_Audit qualification authority process identity could not be proven."
        }
    }
    return @($processes | Where-Object {
        Test-SamePath ([string]$_.ExecutablePath) $Executable
    })
}

function Stop-OwnedQualificationAuthorityProcesses([string]$Executable) {
    $graceDeadline = (Get-Date).AddSeconds(3)
    do {
        $owned = @(Get-OwnedQualificationAuthorityProcesses $Executable)
        if ($owned.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $graceDeadline)

    $deadline = (Get-Date).AddSeconds(12)
    do {
        $owned = @(Get-OwnedQualificationAuthorityProcesses $Executable)
        if ($owned.Count -eq 0) { return }
        foreach ($process in $owned) {
            $processId = [uint32]$process.ProcessId
            $current = @(
                Get-CimInstance Win32_Process `
                    -Filter "ProcessId=$processId AND Name='Container_Audit_Qualification_Authority.exe'" `
                    -ErrorAction Stop
            )
            if ($current.Count -gt 1) {
                throw "Container_Audit qualification authority PID identity is ambiguous."
            }
            if ($current.Count -eq 1) {
                if (
                    [string]::IsNullOrWhiteSpace([string]$current[0].ExecutablePath) -or
                    -not (Test-SamePath ([string]$current[0].ExecutablePath) $Executable)
                ) {
                    throw "Container_Audit qualification authority PID identity could not be proven."
                }
                Stop-Process -Id $processId -Force -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    $owned = @(Get-OwnedQualificationAuthorityProcesses $Executable)
    if ($owned.Count -eq 0) { return }
    throw "Container_Audit qualification authority process removal postcondition failed."
}

function Remove-OwnedQualificationAuthorityTask(
    [string]$Name,
    [string]$Executable,
    [string]$StateRoot
) {
    $state = Get-OwnedQualificationAuthorityTaskState $Name $Executable $StateRoot
    if ($state.status -ceq "OWNED") {
        Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop
    }
    if (@(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "Container_Audit qualification authority task removal postcondition failed."
    }
    Stop-OwnedQualificationAuthorityProcesses $Executable
    return [ordered]@{ status = "ABSENT"; task_name = $Name }
}

function Assert-OwnedTree([string]$Path, [string]$ExpectedPath, [string]$Purpose) {
    $fullPath = Assert-ExactCanonicalPath $Path $ExpectedPath $Purpose
    Assert-NoReparsePoint $fullPath $Purpose -IncludeDescendants
    if ((Test-Path -LiteralPath $fullPath) -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "$Purpose exists but is not a directory."
    }
    return $fullPath
}

function Assert-ApplicationParentInventory([string]$ApplicationParent) {
    Assert-NoReparsePoint $ApplicationParent "Container_Audit application parent" -IncludeDescendants
    if (-not (Test-Path -LiteralPath $ApplicationParent)) {
        return
    }
    if (-not (Test-Path -LiteralPath $ApplicationParent -PathType Container)) {
        throw "Container_Audit application parent is not a directory."
    }
    $allowedNames = @("current", ".current.update-backups", ".current.update-evidence")
    foreach ($child in @(Get-ChildItem -LiteralPath $ApplicationParent -Force -ErrorAction Stop)) {
        if ($allowedNames -notcontains $child.Name) {
            throw "Container_Audit application parent contains a foreign child: $($child.Name)"
        }
    }
}

function Assert-DirectSyncOwnership([string]$Root, [string]$InstallReport, [string]$ExpectedName) {
    if (-not (Test-Path -LiteralPath $Root)) {
        return
    }
    $report = Read-BoundedJson $InstallReport "Container_Audit DirectSync install report"
    if (
        [string]$report.task_name -cne $ExpectedName -or
        -not (Test-SamePath ([string]$report.program_data_root) $Root)
    ) {
        throw "Container_Audit DirectSync ownership metadata does not match the exact app scope."
    }
}

function Assert-NoOwnedProcess([string[]]$ProcessNames) {
    foreach ($processName in $ProcessNames) {
        if (@(Get-Process -Name $processName -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "Destructive rollback is blocked while the owned process is running: $processName"
        }
    }
}

function Assert-ExternalRollbackReportPath([string]$Path, [object[]]$DeletionTargets) {
    $fullPath = Get-StrictFullPath $Path "RollbackReportPath"
    if (Test-Path -LiteralPath $fullPath) {
        throw "RollbackReportPath must be a fresh absent external file."
    }
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "RollbackReportPath parent must already exist."
    }
    Assert-NoReparsePoint $parent "RollbackReportPath parent"
    foreach ($target in $DeletionTargets) {
        if ($target.kind -ceq "scheduled_task") {
            continue
        }
        if (Test-PathWithin $fullPath ([string]$target.path)) {
            throw "RollbackReportPath must be outside every deletion target."
        }
    }
    return $fullPath
}

function Remove-ExactOwnedTree([string]$Path, [string]$Purpose) {
    Assert-NoReparsePoint $Path $Purpose -IncludeDescendants
    if (Test-Path -LiteralPath $Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            throw "$Purpose is not a directory."
        }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $Path) {
        throw "$Purpose deletion postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; path = $Path }
}

function Remove-OwnedCurrentApplicationFootprint(
    [string]$InstallRoot,
    [string]$ExpectedInstallRoot
) {
    $ownedInstallRoot = Assert-OwnedTree `
        $InstallRoot `
        $ExpectedInstallRoot `
        "Container_Audit application root"
    Assert-NoOwnedProcess @("Container_Audit", "Container_Audit_DirectSync_Relay")
    [void](Set-ProcessWorkingDirectoryOutsideOwnedTree $ownedInstallRoot)
    return Remove-ExactOwnedTree $ownedInstallRoot "Container_Audit application root"
}

function Initialize-CanonicalApplicationRoot(
    [string]$SourceRoot,
    [string]$InstallRoot,
    [string]$ApplicationParent
) {
    $sourceFull = Get-StrictFullPath $SourceRoot "Container_Audit release source"
    $parentFull = Get-StrictFullPath $ApplicationParent "Container_Audit application parent"
    $targetFull = Assert-ExactCanonicalPath `
        $InstallRoot `
        (Join-Path $parentFull "current") `
        "Container_Audit application root"
    if (Test-SamePath $sourceFull $targetFull) {
        return $targetFull
    }
    if (-not (Test-Path -LiteralPath $sourceFull -PathType Container)) {
        throw "Container_Audit release source is not a directory."
    }
    if ((Test-PathWithin $targetFull $sourceFull) -or (Test-PathWithin $sourceFull $targetFull)) {
        throw "Container_Audit release source and canonical target must be separate trees."
    }
    Assert-NoReparsePoint $sourceFull "Container_Audit release source" -IncludeDescendants
    Assert-NoReparsePoint $parentFull "Container_Audit application parent" -IncludeDescendants
    Assert-ApplicationParentInventory $parentFull
    if (Test-Path -LiteralPath $targetFull) {
        [void](Assert-OwnedTree $targetFull $targetFull "Container_Audit application root")
        throw "The canonical Container_Audit application root already exists; use the installed application's owned update flow."
    }

    if (-not (Test-Path -LiteralPath $parentFull)) {
        New-Item -ItemType Directory -Path $parentFull -Force -ErrorAction Stop | Out-Null
    }
    Assert-NoReparsePoint $parentFull "Container_Audit application parent" -IncludeDescendants
    New-Item -ItemType Directory -Path $targetFull -ErrorAction Stop | Out-Null
    try {
        foreach ($child in @(Get-ChildItem -LiteralPath $sourceFull -Force -ErrorAction Stop)) {
            Copy-Item `
                -LiteralPath $child.FullName `
                -Destination $targetFull `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
        Assert-NoReparsePoint $targetFull "Container_Audit application root" -IncludeDescendants
        return $targetFull
    }
    catch {
        $copyFailure = $_
        [void](Remove-ExactOwnedTree $targetFull "Container_Audit incomplete application root")
        throw $copyFailure
    }
}

function Remove-EmptyOwnedParent([string]$Path, [string]$Purpose, [switch]$RequireEmpty) {
    Assert-NoReparsePoint $Path $Purpose
    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ status = "ABSENT"; path = $Path }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Purpose is not a directory."
    }
    $firstChild = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $firstChild) {
        if ($RequireEmpty.IsPresent) {
            throw "$Purpose contains unexpected state after owned-child deletion."
        }
        return [ordered]@{ status = "PRESERVED_NONEMPTY"; path = $Path }
    }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $Path) {
        throw "$Purpose empty-parent cleanup postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; path = $Path }
}

function Test-RollbackPostconditions([object[]]$Inventory) {
    $remaining = New-Object System.Collections.Generic.List[string]
    foreach ($target in $Inventory) {
        if ($target.kind -ceq "scheduled_task") {
            if (@(Get-ScheduledTask -TaskName ([string]$target.name) -ErrorAction SilentlyContinue).Count -gt 0) {
                [void]$remaining.Add("scheduled_task:$([string]$target.name)")
            }
            continue
        }
        if (Test-Path -LiteralPath ([string]$target.path)) {
            [void]$remaining.Add([string]$target.path)
        }
    }
    return [ordered]@{
        status = if ($remaining.Count -eq 0) { "PASS" } else { "FAIL" }
        remaining = @($remaining)
    }
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

$OperatorLocalAppDataRoot = Assert-OperatorContext $OperatorUserSid $OperatorLocalAppDataRoot
$explicitServerBaseUrl = $PSBoundParameters.ContainsKey("ServerBaseUrl")
if (-not $Uninstall.IsPresent) {
    $allowExplicitHttpServerBaseUrl = $EnableWindowsSandboxQualification.IsPresent
    Assert-HttpsServerBaseUrl $ServerBaseUrl -AllowExplicitHttp:$allowExplicitHttpServerBaseUrl
}
if ($Uninstall.IsPresent -and $EnableWindowsSandboxQualification.IsPresent) {
    throw "EnableWindowsSandboxQualification is an installation-only switch."
}
if (-not $Uninstall.IsPresent -and (
    $PurgeContainerAuditState.IsPresent -or
    $ConfirmPermanentContainerAuditDataRemoval.IsPresent -or
    -not [string]::IsNullOrWhiteSpace($RollbackReportPath)
)) {
    throw "Rollback-only parameters require -Uninstall."
}
if ($Uninstall.IsPresent) {
    if ($PurgeContainerAuditState.IsPresent) {
        if (-not $ConfirmPermanentContainerAuditDataRemoval.IsPresent) {
            throw "Destructive rollback requires -ConfirmPermanentContainerAuditDataRemoval."
        }
        if ([string]::IsNullOrWhiteSpace($RollbackReportPath)) {
            throw "Destructive rollback requires an external -RollbackReportPath."
        }
    }
    elseif (
        $ConfirmPermanentContainerAuditDataRemoval.IsPresent -or
        -not [string]::IsNullOrWhiteSpace($RollbackReportPath)
    ) {
        throw "Permanent-removal confirmation and RollbackReportPath require -PurgeContainerAuditState."
    }
    if ($AllowNoncanonicalLayoutForTest.IsPresent -and -not $DryRun.IsPresent) {
        throw "AllowNoncanonicalLayoutForTest cannot authorize uninstall or destructive deletion."
    }
}

$releaseSourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($DataRoot)) {
    $DataRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\ContainerAudit"
}
$eventDir = Join-Path $DataRoot "events"
$statusDir = Join-Path $DirectSyncRoot "status"
$requiredReleaseNames = @(
    "Container_Audit.exe",
    "Container_Audit_DirectSync_Install.exe",
    "Container_Audit_DirectSync_Relay.exe",
    "Container_Audit_Qualification_Authority.exe"
)
foreach ($requiredName in $requiredReleaseNames) {
    $required = Join-Path $releaseSourceRoot $requiredName
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Release package is incomplete. Missing: $required"
    }
}

$expectedInstallRoot = "C:\KMTech\Apps\Container_Audit\current"
$expectedApplicationParent = "C:\KMTech\Apps\Container_Audit"
$expectedUpdateBackupRoot = "C:\KMTech\Apps\Container_Audit\.current.update-backups"
$expectedUpdateEvidenceRoot = "C:\KMTech\Apps\Container_Audit\.current.update-evidence"
$expectedDirectSyncRoot = "C:\ProgramData\KMTech\DirectSync\container_audit"
$expectedLogisticsProfileRoot = "C:\ProgramData\KMTech\Logistics\profiles\Container_Audit"
$expectedTaskName = "direct-sync-relay-container-audit"
$qualificationAuthorityTaskName = "container-audit-isolated-qualification-authority"
$qualificationStateRoot = Join-Path $expectedDirectSyncRoot "qualification-authority"
$qualificationContextPath = Join-Path $qualificationStateRoot "client-context.json"
$qualificationFixturePath = Join-Path $qualificationStateRoot "operator-fixture.json"
$qualificationInitializeReportPath = Join-Path $statusDir "isolated_qualification_initialize.json"
$qualificationProbeReportPath = Join-Path $statusDir "isolated_qualification_probe.json"
$expectedTaskLauncherPath = Join-Path $expectedDirectSyncRoot "bin\direct-sync-relay-container-audit.cmd"
$expectedStateDbPath = Join-Path $expectedDirectSyncRoot "queue\direct_sync_relay.sqlite3"
$expectedOperatorDataRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\ContainerAudit"
$expectedOperatorCatalogRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\ItemCatalog\Container_Audit"
$operatorCatalogCachePath = Join-Path $expectedOperatorCatalogRoot "Item.csv"
$localTestOverrideEnabled = (
    $AllowNoncanonicalLayoutForTest.IsPresent -and
    [string]$env:KMTECH_FACTORY_INSTALL_TEST_MODE -ceq "1"
)
$packageRoot = $releaseSourceRoot
if (
    -not $DryRun.IsPresent -and
    -not $Uninstall.IsPresent -and
    -not $localTestOverrideEnabled -and
    -not (Test-SamePath $releaseSourceRoot $expectedInstallRoot)
) {
    $packageRoot = Initialize-CanonicalApplicationRoot `
        $releaseSourceRoot `
        $expectedInstallRoot `
        $expectedApplicationParent
}
$appExe = Join-Path $packageRoot "Container_Audit.exe"
$installExe = Join-Path $packageRoot "Container_Audit_DirectSync_Install.exe"
$runnerExe = Join-Path $packageRoot "Container_Audit_DirectSync_Relay.exe"
$qualificationAuthorityExe = Join-Path $packageRoot "Container_Audit_Qualification_Authority.exe"
foreach ($required in @($appExe, $installExe, $runnerExe, $qualificationAuthorityExe)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Release package is incomplete. Missing: $required"
    }
}

$reuseExistingIdentity = (
    -not [string]::IsNullOrWhiteSpace($ExistingProducerManifestPath) -or
    -not [string]::IsNullOrWhiteSpace($ExistingCredentialPath) -or
    -not [string]::IsNullOrWhiteSpace($ExistingRegistrationReportPath)
)
if ($reuseExistingIdentity) {
    if (
        [string]::IsNullOrWhiteSpace($ExistingProducerManifestPath) -or
        [string]::IsNullOrWhiteSpace($ExistingCredentialPath) -or
        [string]::IsNullOrWhiteSpace($ExistingRegistrationReportPath)
    ) {
        throw "Existing producer manifest, credential, and registration report paths must be provided together."
    }
    foreach ($existingPath in @(
        $ExistingProducerManifestPath,
        $ExistingCredentialPath,
        $ExistingRegistrationReportPath
    )) {
        if (-not (Test-Path -LiteralPath $existingPath -PathType Leaf)) {
            throw "Existing registered identity evidence does not exist."
        }
    }
}
$manifestPath = if ($reuseExistingIdentity) { $ExistingProducerManifestPath } else { Join-Path $DirectSyncRoot "producer_manifest.json" }
$credentialPath = if ($reuseExistingIdentity) { $ExistingCredentialPath } else { Join-Path $DirectSyncRoot "credential.json" }
$registrationReportPath = if ($reuseExistingIdentity) { $ExistingRegistrationReportPath } else { Join-Path $statusDir "worker_pc_registration.json" }
$installReportPath = Join-Path $statusDir "container_audit_direct_sync_install.json"
$commonProgramsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)
$shortcutGroupPath = Join-Path $commonProgramsRoot "KMTech"
$shortcutName = Get-ContainerAuditShortcutName
$expectedShortcutPath = Join-Path $shortcutGroupPath ($shortcutName + ".lnk")
$actualInstallRoot = [System.IO.Path]::GetFullPath($packageRoot)
$actualDirectSyncRoot = [System.IO.Path]::GetFullPath($DirectSyncRoot)
$actualTaskLauncherPath = Join-Path $actualDirectSyncRoot ("bin\{0}.cmd" -f $TaskName)
$actualStateDbPath = Join-Path $actualDirectSyncRoot "queue\direct_sync_relay.sqlite3"
$installRootMatches = Test-SamePath $actualInstallRoot $expectedInstallRoot
$directSyncRootMatches = Test-SamePath $actualDirectSyncRoot $expectedDirectSyncRoot
$taskNameMatches = $TaskName -ceq $expectedTaskName
$taskLauncherPathMatches = Test-SamePath $actualTaskLauncherPath $expectedTaskLauncherPath
$stateDbPathMatches = Test-SamePath $actualStateDbPath $expectedStateDbPath
$productionLayoutMatches = (
    $installRootMatches -and
    $directSyncRootMatches -and
    $taskNameMatches -and
    $taskLauncherPathMatches -and
    $stateDbPathMatches
)
$fieldLayoutContract = [ordered]@{
    status = if ($productionLayoutMatches) { "PASS" } else { "MISMATCH" }
    expected_install_root = $expectedInstallRoot
    actual_install_root = $actualInstallRoot
    expected_direct_sync_root = $expectedDirectSyncRoot
    actual_direct_sync_root = $actualDirectSyncRoot
    expected_task_name = $expectedTaskName
    actual_task_name = $TaskName
    expected_task_launcher_path = $expectedTaskLauncherPath
    actual_task_launcher_path = $actualTaskLauncherPath
    expected_state_db_path = $expectedStateDbPath
    actual_state_db_path = $actualStateDbPath
    install_root_matches = $installRootMatches
    direct_sync_root_matches = $directSyncRootMatches
    task_name_matches = $taskNameMatches
    task_launcher_path_matches = $taskLauncherPathMatches
    state_db_path_matches = $stateDbPathMatches
    production_layout_matches = $productionLayoutMatches
    local_test_override_requested = $AllowNoncanonicalLayoutForTest.IsPresent
    local_test_override_enabled = $localTestOverrideEnabled
    production_apply_allowed = $productionLayoutMatches
}

$rollbackInventory = @(
    [ordered]@{ order = 1; kind = "scheduled_task"; name = $qualificationAuthorityTaskName },
    [ordered]@{ order = 2; kind = "scheduled_task"; name = $expectedTaskName },
    [ordered]@{ order = 3; kind = "shortcut"; path = $expectedShortcutPath },
    [ordered]@{ order = 4; kind = "directory"; path = $expectedLogisticsProfileRoot; purpose = "Container_Audit logistics profile" },
    [ordered]@{ order = 5; kind = "directory"; path = $expectedDirectSyncRoot; purpose = "Container_Audit DirectSync root" },
    [ordered]@{ order = 6; kind = "directory"; path = $expectedOperatorDataRoot; purpose = "Container_Audit operator data" },
    [ordered]@{ order = 7; kind = "directory"; path = $expectedOperatorCatalogRoot; purpose = "Container_Audit operator catalog" },
    [ordered]@{ order = 8; kind = "directory"; path = $expectedUpdateBackupRoot; purpose = "Container_Audit update backups" },
    [ordered]@{ order = 9; kind = "directory"; path = $expectedUpdateEvidenceRoot; purpose = "Container_Audit update evidence" },
    [ordered]@{ order = 10; kind = "directory"; path = $expectedInstallRoot; purpose = "Container_Audit application root" }
)

if ($DryRun.IsPresent) {
    if ($Uninstall.IsPresent) {
        if (-not $productionLayoutMatches) {
            throw "Rollback planning requires the canonical Container_Audit production layout."
        }
        if (-not (Test-SamePath $DataRoot $expectedOperatorDataRoot)) {
            throw "Rollback planning requires the captured operator's canonical Container_Audit data root."
        }
        if ($PurgeContainerAuditState.IsPresent) {
            $externalReportPath = Assert-ExternalRollbackReportPath $RollbackReportPath $rollbackInventory
            $dryRunReport = [ordered]@{
                report_version = "container-audit-pristine-rollback-v1"
                status = "DRY_RUN"
                apply = $false
                destructive = $true
                operator_user_sid = $OperatorUserSid
                operator_local_app_data_root = $OperatorLocalAppDataRoot
                deletion_inventory = $rollbackInventory
                application_root_is_last = ($rollbackInventory[-1].path -ceq $expectedInstallRoot)
                report_path = $externalReportPath
                contains_credential_content = $false
            }
            Write-Utf8JsonFile $externalReportPath $dryRunReport
            Write-Output "rollback_status=DRY_RUN"
            Write-Output "rollback_report=$externalReportPath"
        }
        else {
            Write-Output "uninstall_status=DRY_RUN_DATA_PRESERVED"
            Write-Output "data_preserved=true"
        }
        exit 0
    }
    Write-Utf8JsonFile $installReportPath ([ordered]@{
        report_version = "container-audit-one-step-field-layout-plan-v1"
        status = "DRY_RUN"
        apply = $false
        uninstall = $false
        field_layout_contract = $fieldLayoutContract
    })
    Write-Output "install_status=DRY_RUN"
    Write-Output "package_root=$packageRoot"
    Write-Output "data_root=$DataRoot"
    Write-Output "direct_sync_root=$DirectSyncRoot"
    Write-Output "install_report=$installReportPath"
    exit 0
}

if (-not $Uninstall.IsPresent -and -not $productionLayoutMatches -and -not $localTestOverrideEnabled) {
    Write-Utf8JsonFile $installReportPath ([ordered]@{
        report_version = "container-audit-one-step-field-layout-plan-v1"
        status = "BLOCKED"
        blocked_reason = if ($AllowNoncanonicalLayoutForTest.IsPresent) { "noncanonical layout override requires KMTECH_FACTORY_INSTALL_TEST_MODE=1" } else { "production install requires the canonical Container_Audit field layout" }
        apply = $true
        uninstall = $false
        field_layout_contract = $fieldLayoutContract
    })
    throw "Production install requires C:\KMTech\Apps\Container_Audit\current and the fixed Container_Audit DirectSync layout. Report: $installReportPath"
}

if ($Uninstall.IsPresent) {
    if (-not $productionLayoutMatches) {
        throw "Uninstall requires the exact canonical Container_Audit production layout."
    }
    if (-not (Test-SamePath $DataRoot $expectedOperatorDataRoot)) {
        throw "Uninstall requires the captured operator's canonical Container_Audit data root."
    }
    [void](Assert-ExactCanonicalPath $actualInstallRoot $expectedInstallRoot "Container_Audit application root")
    [void](Assert-ExactCanonicalPath $actualDirectSyncRoot $expectedDirectSyncRoot "Container_Audit DirectSync root")
    Assert-NoReparsePoint $installExe "Container_Audit DirectSync installer"
    Assert-NoReparsePoint $installReportPath "Container_Audit DirectSync install report"
    [void](Get-OwnedScheduledTaskState $TaskName $expectedTaskLauncherPath)
    [void](Get-OwnedQualificationAuthorityTaskState `
        $qualificationAuthorityTaskName `
        $qualificationAuthorityExe `
        $qualificationStateRoot)
    [void](Get-OwnedShortcutState $expectedShortcutPath $appExe $expectedInstallRoot)

    if (-not $PurgeContainerAuditState.IsPresent) {
        [void](Remove-OwnedQualificationAuthorityTask `
            $qualificationAuthorityTaskName `
            $qualificationAuthorityExe `
            $qualificationStateRoot)
        [void](Remove-OwnedScheduledTask `
            $TaskName `
            $expectedTaskLauncherPath `
            $installExe `
            $packageRoot `
            $DirectSyncRoot `
            $installReportPath)
        [void](Remove-OwnedShortcut $expectedShortcutPath $appExe $expectedInstallRoot)
        [void](Remove-OwnedCurrentApplicationFootprint $actualInstallRoot $expectedInstallRoot)
        Write-Output "uninstall_status=PASS_DATA_PRESERVED"
        Write-Output "application_root_status=ABSENT"
        Write-Output "scheduled_task_status=ABSENT"
        Write-Output "qualification_authority_task_status=ABSENT"
        Write-Output "qualification_authority_process_status=ABSENT"
        Write-Output "start_menu_shortcut_status=ABSENT"
        Write-Output "data_preserved=true"
        if (Test-Path -LiteralPath $installReportPath -PathType Leaf) {
            Write-Output "install_report=$installReportPath"
        }
        exit 0
    }

    $externalReportPath = Assert-ExternalRollbackReportPath $RollbackReportPath $rollbackInventory
    $rollbackResults = New-Object System.Collections.Generic.List[object]
    $rollbackReport = [ordered]@{
        report_version = "container-audit-pristine-rollback-v1"
        status = "PREFLIGHT"
        apply = $true
        destructive = $true
        purge_container_audit_state = $PurgeContainerAuditState.IsPresent
        permanent_removal_confirmed = $ConfirmPermanentContainerAuditDataRemoval.IsPresent
        operator_user_sid = $OperatorUserSid
        operator_local_app_data_root = $OperatorLocalAppDataRoot
        report_path = $externalReportPath
        deletion_inventory = $rollbackInventory
        application_root_is_last = ($rollbackInventory[-1].path -ceq $expectedInstallRoot)
        working_directory_relocation = [ordered]@{ status = "NOT_TESTED"; outside_application_root = $false }
        results = $rollbackResults
        parent_cleanup = @()
        postconditions = [ordered]@{ status = "NOT_TESTED"; remaining = @() }
        contains_credential_content = $false
        failure = ""
    }
    Write-Utf8JsonFile $externalReportPath $rollbackReport
    try {
        Assert-NoOwnedProcess @("Container_Audit", "Container_Audit_DirectSync_Relay")
        [void](Assert-OwnedTree $expectedApplicationParent $expectedApplicationParent "Container_Audit application parent")
        Assert-ApplicationParentInventory $expectedApplicationParent
        [void](Assert-OwnedTree $expectedLogisticsProfileRoot $expectedLogisticsProfileRoot "Container_Audit logistics profile")
        [void](Assert-OwnedTree $expectedDirectSyncRoot $expectedDirectSyncRoot "Container_Audit DirectSync root")
        [void](Assert-OwnedTree $expectedOperatorDataRoot $expectedOperatorDataRoot "Container_Audit operator data")
        [void](Assert-OwnedTree $expectedOperatorCatalogRoot $expectedOperatorCatalogRoot "Container_Audit operator catalog")
        [void](Assert-OwnedTree $expectedUpdateBackupRoot $expectedUpdateBackupRoot "Container_Audit update backups")
        [void](Assert-OwnedTree $expectedUpdateEvidenceRoot $expectedUpdateEvidenceRoot "Container_Audit update evidence")
        Assert-DirectSyncOwnership $expectedDirectSyncRoot $installReportPath $expectedTaskName
        [void](Get-OwnedScheduledTaskState $TaskName $expectedTaskLauncherPath)
        [void](Get-OwnedQualificationAuthorityTaskState `
            $qualificationAuthorityTaskName `
            $qualificationAuthorityExe `
            $qualificationStateRoot)
        [void](Get-OwnedShortcutState $expectedShortcutPath $appExe $expectedInstallRoot)

        $rollbackReport.status = "APPLYING"
        Write-Utf8JsonFile $externalReportPath $rollbackReport

        [void]$rollbackResults.Add((Remove-OwnedQualificationAuthorityTask `
            $qualificationAuthorityTaskName `
            $qualificationAuthorityExe `
            $qualificationStateRoot))
        Assert-NoOwnedProcess @("Container_Audit_Qualification_Authority")
        [void]$rollbackResults.Add((Remove-OwnedScheduledTask `
            $TaskName `
            $expectedTaskLauncherPath `
            $installExe `
            $packageRoot `
            $DirectSyncRoot `
            $installReportPath))
        [void]$rollbackResults.Add((Remove-OwnedShortcut $expectedShortcutPath $appExe $expectedInstallRoot))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedLogisticsProfileRoot "Container_Audit logistics profile"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedDirectSyncRoot "Container_Audit DirectSync root"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedOperatorDataRoot "Container_Audit operator data"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedOperatorCatalogRoot "Container_Audit operator catalog"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedUpdateBackupRoot "Container_Audit update backups"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedUpdateEvidenceRoot "Container_Audit update evidence"))
        $rollbackReport.working_directory_relocation = Set-ProcessWorkingDirectoryOutsideOwnedTree $expectedInstallRoot
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedInstallRoot "Container_Audit application root"))

        $rollbackReport.parent_cleanup = @(
            (Remove-EmptyOwnedParent $expectedApplicationParent "Container_Audit application parent" -RequireEmpty),
            (Remove-EmptyOwnedParent $shortcutGroupPath "KMTech Start Menu group")
        )
        $rollbackReport.postconditions = Test-RollbackPostconditions $rollbackInventory
        if ($rollbackReport.postconditions.status -cne "PASS") {
            throw "Destructive rollback postconditions did not prove every exact owned resource absent."
        }
        $rollbackReport.status = "PASS"
        Write-Utf8JsonFile $externalReportPath $rollbackReport
        Write-Output "rollback_status=PASS"
        Write-Output "rollback_report=$externalReportPath"
        exit 0
    }
    catch {
        $rollbackReport.status = "FAIL"
        $rollbackReport.failure = $_.Exception.Message
        $rollbackReport.postconditions = Test-RollbackPostconditions $rollbackInventory
        Write-Utf8JsonFile $externalReportPath $rollbackReport
        throw "Container_Audit destructive rollback failed. Report: $externalReportPath. $($_.Exception.Message)"
    }
}

[void](Get-OwnedShortcutState $expectedShortcutPath $appExe $expectedInstallRoot)

New-Item -ItemType Directory -Path $eventDir -Force | Out-Null
New-Item -ItemType Directory -Path $statusDir -Force | Out-Null

$qualificationAuthorityEnabled = $false
if ($EnableWindowsSandboxQualification.IsPresent) {
    $qualificationServerBaseUri = [System.Uri]$ServerBaseUrl
    if (
        $ServerBaseUrl.Trim().TrimEnd('/') -cne "https://worker.kmtecherp.com" -and
        $qualificationServerBaseUri.Scheme -cne "http"
    ) {
        throw "Windows Sandbox qualification ServerBaseUrl override must be an HTTP origin."
    }
    [void](Assert-ExactCanonicalPath $qualificationStateRoot (Join-Path $DirectSyncRoot "qualification-authority") "Qualification authority state")
    if (-not (Test-Path -LiteralPath $qualificationStateRoot)) {
        New-Item -ItemType Directory -Path $qualificationStateRoot -Force | Out-Null
    }
    Assert-NoReparsePoint $qualificationStateRoot "Qualification authority state" -IncludeDescendants
    & icacls.exe $qualificationStateRoot `
        "/inheritance:r" `
        "/grant:r" `
        "*S-1-5-18:(OI)(CI)F" `
        "*S-1-5-32-544:(OI)(CI)F" `
        "*S-1-5-32-545:RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Qualification authority state ACL installation failed."
    }
    & $qualificationAuthorityExe `
        initialize `
        --state-root $qualificationStateRoot `
        --operator-user-sid $OperatorUserSid `
        --operator-local-app-data-root $OperatorLocalAppDataRoot `
        --report-path $qualificationInitializeReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Sandbox qualification authority initialization failed."
    }
    foreach ($publicName in @(
        "client-context.json",
        "qualification-ca.pem",
        "operator-fixture.json"
    )) {
        $publicPath = Join-Path $qualificationStateRoot $publicName
        & icacls.exe $publicPath `
            "/inheritance:r" `
            "/grant:r" `
            "*S-1-5-18:F" `
            "*S-1-5-32-544:F" `
            "*S-1-5-32-545:R" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Qualification authority public-state ACL installation failed."
        }
    }
    foreach ($privateName in @(
        "private-state.json",
        "qualification-server-key.pem",
        "qualification-operation-lease-key.pem"
    )) {
        $privatePath = Join-Path $qualificationStateRoot $privateName
        & icacls.exe $privatePath `
            "/inheritance:r" `
            "/grant:r" `
            "*S-1-5-18:F" `
            "*S-1-5-32-544:F" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Qualification authority private-state ACL installation failed."
        }
    }
    $qualificationInitialize = Read-BoundedJson `
        $qualificationInitializeReportPath `
        "Qualification authority initialization report"
    if (
        @("INITIALIZED", "REUSED") -notcontains [string]$qualificationInitialize.status -or
        [string]$qualificationInitialize.activation_mode -cne "windows_sandbox_qualification" -or
        $qualificationInitialize.loopback_only -isnot [bool] -or -not [bool]$qualificationInitialize.loopback_only -or
        $qualificationInitialize.production_write_enabled -isnot [bool] -or [bool]$qualificationInitialize.production_write_enabled -or
        -not (Test-SamePath ([string]$qualificationInitialize.context_path) $qualificationContextPath) -or
        -not (Test-SamePath ([string]$qualificationInitialize.fixture_path) $qualificationFixturePath)
    ) {
        throw "Qualification authority initialization report did not prove the isolated route."
    }
    $qualificationAuthorityServerBaseUrl = [string]$qualificationInitialize.server_base_url
    Assert-HttpsServerBaseUrl $qualificationAuthorityServerBaseUrl
    $ServerBaseUrl = Resolve-ProducerSubmissionBaseUrl `
        $ServerBaseUrl `
        $explicitServerBaseUrl `
        $qualificationAuthorityServerBaseUrl
    Assert-HttpsServerBaseUrl `
        $ServerBaseUrl `
        -AllowExplicitHttp:$explicitServerBaseUrl
    [void](Install-OwnedQualificationAuthorityTask `
        $qualificationAuthorityTaskName `
        $qualificationAuthorityExe `
        $qualificationStateRoot)
    Start-ScheduledTask -TaskName $qualificationAuthorityTaskName -ErrorAction Stop
    $qualificationProbePassed = $false
    $qualificationDeadline = (Get-Date).AddSeconds(30)
    do {
        & $qualificationAuthorityExe `
            probe `
            --state-root $qualificationStateRoot `
            --report-path $qualificationProbeReportPath | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $qualificationProbePassed = $true
            break
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $qualificationDeadline)
    if (-not $qualificationProbePassed) {
        throw "APPLIED_UNPROVEN: the owned qualification authority task did not prove HTTPS readiness."
    }
    $qualificationProbe = Read-BoundedJson `
        $qualificationProbeReportPath `
        "Qualification authority probe report"
    if (
        [string]$qualificationProbe.status -cne "PASS" -or
        $qualificationProbe.loopback_only -isnot [bool] -or -not [bool]$qualificationProbe.loopback_only -or
        $qualificationProbe.production_write_enabled -isnot [bool] -or [bool]$qualificationProbe.production_write_enabled
    ) {
        throw "Qualification authority probe did not prove the isolated HTTPS route."
    }
    $qualificationAuthorityEnabled = $true
}

# Preserve the app's established per-user data root. SYSTEM can read that
# source, while the machine-scope DPAPI credential and relay state stay under
# the ProgramData root.

$endpointUrl = "$($ServerBaseUrl.Trim().TrimEnd('/'))/api/producer-ingest/v1/source-file"
if (-not $reuseExistingIdentity) {
    if (
        -not [string]::IsNullOrWhiteSpace($ProducerIdentityPath) -and
        -not (Test-Path -LiteralPath $ProducerIdentityPath -PathType Leaf)
    ) {
        throw "Producer identity seed file does not exist."
    }
    $registrationArguments = @(
        "--app-root", $packageRoot,
        "--endpoint-url", $endpointUrl,
        "--self-enroll",
        "--require-machine-credential-bundle",
        "--enrollment-token-env", $EnrollmentTokenEnv,
        "--manifest-path", $manifestPath,
        "--credential-path", $credentialPath,
        "--report-path", $registrationReportPath
    )
    if ($qualificationAuthorityEnabled) {
        $registrationArguments += @(
            "--isolated-qualification-context", $qualificationContextPath
        )
    }
    if (-not [string]::IsNullOrWhiteSpace($ProducerIdentityPath)) {
        $registrationArguments += @("--producer-identity-path", $ProducerIdentityPath)
    }
    if (-not [string]::IsNullOrWhiteSpace($ProducerInstallId)) {
        $registrationArguments += @("--producer-install-id", $ProducerInstallId)
    }
    if (-not [string]::IsNullOrWhiteSpace($ProducerId)) {
        $registrationArguments += @("--producer-id", $ProducerId)
    }
    if (-not [string]::IsNullOrWhiteSpace($SourceHostId)) {
        $registrationArguments += @("--source-host-id", $SourceHostId)
    }
    & $installExe --register-worker-pc @registrationArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Container_Audit self-enrollment failed. Report: $registrationReportPath"
    }
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
if (
    $qualificationAuthorityEnabled -and
    (
        $registrationReport.isolated_qualification_mode -isnot [bool] -or
        -not [bool]$registrationReport.isolated_qualification_mode -or
        [string]$registrationReport.isolated_qualification_authority_id -cne [string]$qualificationInitialize.authority_instance_id
    )
) {
    throw "Container_Audit registration report did not prove the isolated qualification authority binding."
}
$authorizedManifestHash = ([string]$registrationReport.manifest_hash).ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($authorizedManifestHash)) {
    throw "Container_Audit registration report omitted the authorized manifest hash."
}
if ($reuseExistingIdentity) {
    & $installExe --register-worker-pc `
        --manifest-path $manifestPath `
        --verify-manifest-hash $authorizedManifestHash
    if ($LASTEXITCODE -ne 0) {
        throw "Existing producer manifest differs from its verified registration report."
    }
}
$installArguments = @(
    "--apply",
    "--confirm-production-install",
    "--app-root", $packageRoot,
    "--program-data-root", $DirectSyncRoot,
    "--producer-manifest-path", $manifestPath,
    "--credential-path", $credentialPath,
    "--scan-source-dir", $eventDir,
    "--source-glob", "*.csv",
    "--task-name", $TaskName,
    "--report-path", $installReportPath
)
if ($AllowNoncanonicalLayoutForTest.IsPresent) {
    $installArguments += "--allow-noncanonical-layout-for-test"
}
& $installExe @installArguments
if ($LASTEXITCODE -ne 0) {
    throw "Container_Audit direct-sync installation failed. Report: $installReportPath"
}

$report = Get-Content -LiteralPath $installReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    [string]$report.status -cne "PASS" -or
    [string]$report.task_principal.mode -cne "system_service_account" -or
    [string]$report.task_principal.run_user -cne "SYSTEM" -or
    (
        -not $localTestOverrideEnabled -and
        (
            $report.field_layout_contract.production_layout_matches -isnot [bool] -or
            -not [bool]$report.field_layout_contract.production_layout_matches
        )
    )
) {
    throw "Container_Audit install report did not prove the SYSTEM task and canonical field-layout contract."
}
if (
    $qualificationAuthorityEnabled -and
    (
        $report.credential.isolated_qualification -isnot [bool] -or
        -not [bool]$report.credential.isolated_qualification
    )
) {
    throw "Container_Audit install report did not prove the isolated qualification credential boundary."
}
try {
    $relayStarted = (Get-Date).ToUniversalTime()
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
catch {
    $startFailure = $_
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (-not $reuseExistingIdentity) {
        Remove-NewMachineProfilesFromRegistrationReport $registrationReportPath
    }
    throw $startFailure
}
try {
    Wait-CurrentRuntimeLease $relayStarted $DirectSyncRoot $authorizedManifestHash
}
catch {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    throw "APPLIED_UNPROVEN: relay task was installed but current runtime liveness was not proven: $($_.Exception.Message)"
}

$installedShortcut = Install-OwnedShortcut $expectedShortcutPath $appExe $expectedInstallRoot
if ($installedShortcut.status -cne "OWNED") {
    throw "Container_Audit Start Menu shortcut readback did not prove the owned shortcut contract."
}

Write-Output "install_status=PASS"
Write-Output "operator_readiness_status=PENDING_FIRST_LAUNCH"
Write-Output "first_launch_catalog_status=NOT_TESTED"
Write-Output "start_menu_shortcut=$expectedShortcutPath"
Write-Output "operator_catalog_cache_path=$operatorCatalogCachePath"
Write-Output "registration_report=$registrationReportPath"
Write-Output "install_report=$installReportPath"
if ($qualificationAuthorityEnabled) {
    Write-Output "qualification_authority_status=PASS"
    Write-Output "qualification_authority_context=$qualificationContextPath"
    Write-Output "qualification_operator_fixture=$qualificationFixturePath"
}
