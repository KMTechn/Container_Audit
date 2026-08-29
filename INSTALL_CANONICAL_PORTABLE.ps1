[CmdletBinding()]
param(
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\KMTech\Apps\Container_Audit\current",
    [string]$EvidencePath = "",
    [switch]$PlanOnly,
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$SkipSignatureValidationForTest
)

$ErrorActionPreference = 'Stop'
$CanonicalRoot = 'C:\KMTech\Apps\Container_Audit\current'
$RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$RunName = 'KMTech.ContainerAudit.Relay'
$CanonicalWriterTaskName = 'direct-sync-relay-container-audit'
$NoncanonicalQualificationTaskName = 'container-audit-isolated-qualification-authority'
$testMode = $AllowNoncanonicalLayoutForTest -and
    [string]$env:KMTECH_FACTORY_INSTALL_TEST_MODE -ceq '1'
if ($SkipSignatureValidationForTest -and -not $testMode) {
    throw 'Signature bypass is test-only.'
}

function Full([string]$Value, [string]$Purpose) {
    if (-not [IO.Path]::IsPathRooted($Value) -or $Value.StartsWith('\\?\')) {
        throw "$Purpose must be an ordinary absolute path."
    }
    $result = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    if ($result -eq [IO.Path]::GetPathRoot($result)) { throw "$Purpose is too broad." }
    return $result
}
function Same([string]$Left, [string]$Right) {
    return (Full $Left 'left path').Equals((Full $Right 'right path'), 'OrdinalIgnoreCase')
}
function Sha([string]$Path) {
    $stream = [IO.File]::OpenRead($Path); $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose(); $stream.Dispose() }
}
function Arg([string]$Value) {
    if ($Value.Contains('"')) { throw 'A command path contains a quote.' }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}
function Command([string]$Root) {
    return ('{0} -I -B {1} --container-audit-user-relay' -f
        (Arg (Join-Path $Root 'runtime\pythonw.exe')),
        (Arg (Join-Path $Root 'app\main.py')))
}
function Manifest([string]$Root, [bool]$UnsignedOk) {
    foreach ($relative in @('portable-manifest.json','runtime\python.exe','runtime\pythonw.exe','app\main.py','launch-container-audit.cmd')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $relative) -PathType Leaf)) {
            throw "Portable tree is missing $relative."
        }
    }
    foreach ($item in @((Get-Item $Root -Force)) + @(Get-ChildItem $Root -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Portable tree contains a reparse point: $($item.FullName)"
        }
    }
    $path = Join-Path $Root 'portable-manifest.json'
    if ((Get-Item $path).Length -gt 65536) { throw 'Portable manifest is oversized.' }
    $value = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$value.schema -cne 'container-audit-portable-tree-v1' -or
        @($value.allowed_unsigned_app_pe).Count -ne 0 -or
        @($value.forbidden_dependency_paths).Count -ne 0 -or
        (Sha (Join-Path $Root 'runtime\pythonw.exe')) -cne ([string]$value.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'launch-container-audit.cmd')) -cne ([string]$value.launcher_sha256).ToLowerInvariant()) {
        throw 'Portable manifest readback failed.'
    }
    if (-not $UnsignedOk) {
        foreach ($relative in @('runtime\python.exe','runtime\pythonw.exe')) {
            if ([string](Get-AuthenticodeSignature (Join-Path $Root $relative)).Status -cne 'Valid') {
                throw "Signed CPython readback failed: $relative"
            }
        }
    }
    return $value
}
function Snapshot {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RunKey, $false)
    if ($null -eq $key) { return [ordered]@{exists=$false;kind='';data=''} }
    try {
        try { $kind = [string]$key.GetValueKind($RunName) }
        catch [IO.IOException] { return [ordered]@{exists=$false;kind='';data=''} }
        if ($kind -notin @('String','ExpandString')) { throw "Unsupported Run type: $kind" }
        $data = [string]$key.GetValue($RunName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return [ordered]@{exists=$true;kind=$kind;data=$data}
    } finally { $key.Dispose() }
}
function Restore($Before) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunKey,$true)
    try {
        if ([bool]$Before.exists) {
            $key.SetValue($RunName,[string]$Before.data,[Microsoft.Win32.RegistryValueKind]::$($Before.kind))
        } else { $key.DeleteValue($RunName,$false) }
    } finally { $key.Dispose() }
}
function Save([string]$Path, $Value) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $temp = "$Path.tmp.$PID"
    [IO.File]::WriteAllText($temp,($Value|ConvertTo-Json -Depth 8)+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
    Move-Item $temp $Path -Force
}
function Relays {
    return @(Get-CimInstance Win32_Process | Where-Object {
        [string]$_.CommandLine -like '*--container-audit-user-relay*' -and
        [string]$_.ExecutablePath -match '(?i)(pythonw?\.exe|Container_Audit\.exe)$'
    })
}
function Product([string]$Root,[string]$Mode) {
    $args = '-I -B {0} {1} --app-root {2}' -f
        (Arg (Join-Path $Root 'app\main.py')),$Mode,(Arg (Join-Path $Root 'app'))
    $process = Start-Process (Join-Path $Root 'runtime\pythonw.exe') -ArgumentList $args -WindowStyle Hidden -PassThru
    # Start-Process -Wait includes the persistent relay child; this waits only for the host.
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Product mode failed: $Mode/$($process.ExitCode)" }
}
function StartRaw([string]$Line) {
    $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$Line}
    if ([uint32]$created.ReturnValue -ne 0) { throw 'Rollback process start failed.' }
    return [int]$created.ProcessId
}

function UtcText([datetime]$Value) {
    if ($Value.Year -lt 2000) { return '' }
    return $Value.ToUniversalTime().ToString('o')
}
function ShaText([string]$Value) {
    $encoding = New-Object Text.UTF8Encoding($false)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash($encoding.GetBytes($Value)))).Replace('-', '').ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}
function FileObservation([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ exists=$false; path=$Path; bytes=0; mtime_utc=''; sha256='' }
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [ordered]@{
        exists=$true
        path=$Path
        bytes=[int64]$item.Length
        mtime_utc=$item.LastWriteTimeUtc.ToString('o')
        sha256=Sha $Path
    }
}
function SameFileObservation($Left, $Right) {
    return (
        [bool]$Left.exists -eq [bool]$Right.exists -and
        [string]$Left.path -ceq [string]$Right.path -and
        [int64]$Left.bytes -eq [int64]$Right.bytes -and
        [string]$Left.mtime_utc -ceq [string]$Right.mtime_utc -and
        [string]$Left.sha256 -ceq [string]$Right.sha256
    )
}
function Get-CanonicalWriterProcesses([string]$InstallRootValue) {
    $expected = Join-Path $InstallRootValue 'runtime\python.exe'
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $execute = [string]$_.ExecutablePath
        $command = [string]$_.CommandLine
        [IO.Path]::IsPathRooted($execute) -and
        (Same $execute $expected) -and
        $command.IndexOf('--container-audit-direct-sync-relay', [StringComparison]::Ordinal) -ge 0
    } | Select-Object ProcessId, ParentProcessId, ExecutablePath)
}
function Get-PrincipalSid([string]$UserId) {
    if ([string]::IsNullOrWhiteSpace($UserId)) { return '' }
    try {
        $account = New-Object Security.Principal.NTAccount($UserId)
        return [string]$account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch { return '' }
}
function Get-CanonicalWriterBinding($Task) {
    $actions = @($Task.Actions)
    $triggers = @($Task.Triggers)
    $normalized = [ordered]@{
        task_name=[string]$Task.TaskName
        task_path=[string]$Task.TaskPath
        actions=@($actions | ForEach-Object {
            [ordered]@{
                execute=[string]$_.Execute
                arguments=[string]$_.Arguments
                working_directory=[string]$_.WorkingDirectory
            }
        })
        principal=[ordered]@{
            user_id=[string]$Task.Principal.UserId
            logon_type=[string]$Task.Principal.LogonType
            run_level=[string]$Task.Principal.RunLevel
        }
        triggers=@($triggers | ForEach-Object {
            [ordered]@{
                type=[string]$_.CimClass.CimClassName
                enabled=[bool]$_.Enabled
                start_boundary=[string]$_.StartBoundary
                repetition_interval=[string]$_.Repetition.Interval
                repetition_duration=[string]$_.Repetition.Duration
                stop_at_duration_end=[bool]$_.Repetition.StopAtDurationEnd
            }
        })
        settings=[ordered]@{
            start_when_available=[bool]$Task.Settings.StartWhenAvailable
            multiple_instances=[string]$Task.Settings.MultipleInstances
            execution_time_limit=[string]$Task.Settings.ExecutionTimeLimit
            disallow_start_if_on_batteries=[bool]$Task.Settings.DisallowStartIfOnBatteries
            stop_if_going_on_batteries=[bool]$Task.Settings.StopIfGoingOnBatteries
        }
    }
    $json = $normalized | ConvertTo-Json -Depth 8 -Compress
    return [ordered]@{ value=$normalized; sha256=ShaText $json }
}
function Get-CanonicalWriterSnapshot([string]$InstallRootValue) {
    $expectedExecute = Join-Path $InstallRootValue 'runtime\python.exe'
    $expectedMain = Join-Path $InstallRootValue 'app\main.py'
    $local = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
    $logPath = Join-Path $local 'KMTech\DirectSync\container_audit\logs\scheduled_direct_sync_relay.jsonl'
    $statusPath = Join-Path $local 'KMTech\DirectSync\container_audit\status\scheduled_direct_sync_relay_status.json'
    $currentSid = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $canonical = @()
    $noncanonicalDisabled = @()
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($candidate in $allTasks) {
        $actions = @($candidate.Actions)
        $arguments = if ($actions.Count -eq 1) { [string]$actions[0].Arguments } else { '' }
        $execute = if ($actions.Count -eq 1) { [string]$actions[0].Execute } else { '' }
        $owned = (
            [string]$candidate.TaskName -ceq $CanonicalWriterTaskName -or
            [string]$candidate.TaskName -ceq $NoncanonicalQualificationTaskName -or
            $arguments.IndexOf('--container-audit', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $arguments.IndexOf('Container_Audit', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $arguments.IndexOf('ContainerAudit', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $execute.IndexOf('Container_Audit', [StringComparison]::OrdinalIgnoreCase) -ge 0
        )
        if (-not $owned) { continue }
        $triggers = @($candidate.Triggers)
        $executeExact = (
            [IO.Path]::IsPathRooted($execute) -and
            (Same $execute $expectedExecute)
        )
        $actionExact = (
            $actions.Count -eq 1 -and $executeExact -and
            $arguments.IndexOf($expectedMain, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $arguments.IndexOf('--container-audit-direct-sync-relay', [StringComparison]::Ordinal) -ge 0 -and
            $arguments.IndexOf($logPath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $arguments.IndexOf($statusPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
        )
        $principalSid = Get-PrincipalSid ([string]$candidate.Principal.UserId)
        $principalExact = (
            -not [string]::IsNullOrWhiteSpace($principalSid) -and
            $principalSid -ceq $currentSid -and
            [string]$candidate.Principal.LogonType -ceq 'Interactive' -and
            [string]$candidate.Principal.RunLevel -ceq 'Limited'
        )
        $triggerExact = (
            $triggers.Count -eq 1 -and
            [string]$triggers[0].CimClass.CimClassName -ceq 'MSFT_TaskTimeTrigger' -and
            [bool]$triggers[0].Enabled -and
            [string]$triggers[0].Repetition.Interval -ceq 'PT1M' -and
            [bool]$candidate.Settings.StartWhenAvailable -and
            [string]$candidate.Settings.MultipleInstances -ceq 'IgnoreNew' -and
            [string]$candidate.Settings.ExecutionTimeLimit -ceq 'PT2M'
        )
        $binding = Get-CanonicalWriterBinding $candidate
        if ($actionExact -and $principalExact -and $triggerExact) {
            $canonical += $candidate
            continue
        }
        if ([bool]$candidate.Settings.Enabled) { throw 'NONCANONICAL_WRITER_ENABLED' }
        $noncanonicalDisabled += [ordered]@{
            task_name=[string]$candidate.TaskName
            task_path=[string]$candidate.TaskPath
            binding_sha256=[string]$binding.sha256
        }
    }
    if ($canonical.Count -eq 0) {
        return [ordered]@{
            present=$false
            classification='CANONICAL_ABSENT_NONCANONICAL_DISABLED'
            restore_required=$false
            noncanonical_disabled=$noncanonicalDisabled
        }
    }
    if ($canonical.Count -ne 1) { throw 'CANONICAL_WRITER_COUNT_NOT_EXACT' }
    $task = $canonical[0]
    $info = Get-ScheduledTaskInfo -TaskName ([string]$task.TaskName) -TaskPath ([string]$task.TaskPath) -ErrorAction Stop
    $binding = Get-CanonicalWriterBinding $task
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    $enabled = [bool]$task.Settings.Enabled
    $processes = @(Get-CanonicalWriterProcesses $InstallRootValue)
    return [ordered]@{
        present=$true
        classification='CANONICAL_QUIESCE_RESTORE'
        restore_required=$enabled
        task_name=[string]$task.TaskName
        task_path=[string]$task.TaskPath
        binding_sha256=[string]$binding.sha256
        action_execute=if ($actions.Count -eq 1) { [string]$actions[0].Execute } else { '' }
        action_mode='--container-audit-direct-sync-relay'
        principal_user=[string]$task.Principal.UserId
        principal_sid=Get-PrincipalSid ([string]$task.Principal.UserId)
        logon_type=[string]$task.Principal.LogonType
        run_level=[string]$task.Principal.RunLevel
        trigger_type=if ($triggers.Count -eq 1) { [string]$triggers[0].CimClass.CimClassName } else { '' }
        trigger_interval=if ($triggers.Count -eq 1) { [string]$triggers[0].Repetition.Interval } else { '' }
        start_when_available=[bool]$task.Settings.StartWhenAvailable
        multiple_instances=[string]$task.Settings.MultipleInstances
        enabled=$enabled
        state=[string]$task.State
        process_count=$processes.Count
        process_ids=@($processes | ForEach-Object { [int]$_.ProcessId })
        last_task_result=[int64]$info.LastTaskResult
        last_run_time_utc=UtcText ([datetime]$info.LastRunTime)
        next_run_time_utc=UtcText ([datetime]$info.NextRunTime)
        log=FileObservation $logPath
        runtime_status=FileObservation $statusPath
        noncanonical_disabled=$noncanonicalDisabled
    }
}
function Assert-CanonicalWriterRestoreReadback($Before, $After) {
    if (-not [bool]$After.present -or
        [string]$After.classification -cne 'CANONICAL_QUIESCE_RESTORE' -or
        -not [bool]$After.enabled -or
        [string]$After.binding_sha256 -cne [string]$Before.binding_sha256) {
        throw 'CANONICAL_WRITER_RESTORE_BINDING_MISMATCH'
    }
}
function Get-CanonicalWriterPreimageForQuiesce([string]$InstallRootValue) {
    $deadline = (Get-Date).ToUniversalTime().AddSeconds(90)
    do {
        $snapshot = Get-CanonicalWriterSnapshot $InstallRootValue
        if (-not [bool]$snapshot.restore_required) { return $snapshot }
        if ([int64]$snapshot.last_task_result -ne 0) {
            throw 'CANONICAL_WRITER_PRESTATE_LAST_RESULT_NONZERO'
        }
        $next = if ([string]::IsNullOrWhiteSpace([string]$snapshot.next_run_time_utc)) {
            [datetime]::MinValue
        }
        else { [datetime]::Parse([string]$snapshot.next_run_time_utc).ToUniversalTime() }
        $safe = (
            [string]$snapshot.state -cne 'Running' -and
            $next -gt (Get-Date).ToUniversalTime().AddSeconds(10) -and
            $next -le (Get-Date).ToUniversalTime().AddSeconds(120)
        )
        if (-not $safe) { Start-Sleep -Milliseconds 500 }
    } while (-not $safe -and (Get-Date).ToUniversalTime() -lt $deadline)
    if (-not $safe) { throw 'CANONICAL_WRITER_PRESTATE_SAFE_BOUNDARY_NOT_FOUND' }
    return $snapshot
}
function Disable-CanonicalWriter([string]$InstallRootValue, $Before) {
    Disable-ScheduledTask -TaskName ([string]$Before.task_name) -TaskPath ([string]$Before.task_path) -ErrorAction Stop | Out-Null
    $task = Get-ScheduledTask -TaskName ([string]$Before.task_name) -TaskPath ([string]$Before.task_path) -ErrorAction Stop
    if ([string]$task.State -ceq 'Running') {
        Stop-ScheduledTask -TaskName ([string]$Before.task_name) -TaskPath ([string]$Before.task_path) -ErrorAction Stop
    }
    $deadline = (Get-Date).ToUniversalTime().AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 250
        $task = Get-ScheduledTask -TaskName ([string]$Before.task_name) -TaskPath ([string]$Before.task_path) -ErrorAction Stop
    } while ([string]$task.State -ceq 'Running' -and (Get-Date).ToUniversalTime() -lt $deadline)
    $processDeadline = (Get-Date).ToUniversalTime().AddSeconds(30)
    do {
        $processes = @(Get-CanonicalWriterProcesses $InstallRootValue)
        if ($processes.Count -gt 0) { Start-Sleep -Milliseconds 250 }
    } while ($processes.Count -gt 0 -and (Get-Date).ToUniversalTime() -lt $processDeadline)
    if ([string]$task.State -ceq 'Running' -or [bool]$task.Settings.Enabled -or $processes.Count -gt 0) {
        throw 'CANONICAL_WRITER_QUIESCE_READBACK_FAILED'
    }
    Start-Sleep -Seconds 2
    $after = Get-CanonicalWriterSnapshot $InstallRootValue
    if ([string]$after.binding_sha256 -cne [string]$Before.binding_sha256 -or [bool]$after.enabled) {
        throw 'CANONICAL_WRITER_QUIESCE_BINDING_MISMATCH'
    }
    return $after
}
function Confirm-CanonicalWriterStopped([string]$InstallRootValue, $Before, $DisabledBaseline) {
    if ([string]::IsNullOrWhiteSpace([string]$Before.next_run_time_utc)) {
        throw 'CANONICAL_WRITER_NEXT_TRIGGER_UNKNOWN'
    }
    $boundary = [datetime]::Parse([string]$Before.next_run_time_utc).ToUniversalTime()
    $now = (Get-Date).ToUniversalTime()
    if ($boundary -le $now.AddSeconds(-5) -or $boundary -gt $now.AddSeconds(120)) {
        throw 'CANONICAL_WRITER_NEXT_TRIGGER_NOT_BOUNDED'
    }
    while ((Get-Date).ToUniversalTime() -lt $boundary.AddSeconds(5)) { Start-Sleep -Milliseconds 500 }
    $after = Get-CanonicalWriterSnapshot $InstallRootValue
    $unchanged = (
        -not [bool]$after.enabled -and
        [int]$after.process_count -eq 0 -and
        [string]$after.binding_sha256 -ceq [string]$DisabledBaseline.binding_sha256 -and
        [string]$after.last_run_time_utc -ceq [string]$DisabledBaseline.last_run_time_utc -and
        (SameFileObservation $after.log $DisabledBaseline.log) -and
        (SameFileObservation $after.runtime_status $DisabledBaseline.runtime_status)
    )
    if (-not $unchanged) { throw 'CANONICAL_WRITER_STOP_PROOF_FAILED' }
    return [ordered]@{
        status='PASS'
        crossed_trigger_utc=$boundary.ToString('o')
        last_run_time_unchanged=$true
        log_size_mtime_sha256_unchanged=$true
        runtime_status_unchanged=$true
        readback=$after
    }
}
function Enable-CanonicalWriter([string]$InstallRootValue, $Before) {
    Enable-ScheduledTask -TaskName ([string]$Before.task_name) -TaskPath ([string]$Before.task_path) -ErrorAction Stop | Out-Null
    $deadline = (Get-Date).ToUniversalTime().AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $after = Get-CanonicalWriterSnapshot $InstallRootValue
        if ([bool]$after.enabled) { Assert-CanonicalWriterRestoreReadback $Before $after }
        $next = if ([string]::IsNullOrWhiteSpace([string]$after.next_run_time_utc)) {
            [datetime]::MinValue
        }
        else { [datetime]::Parse([string]$after.next_run_time_utc).ToUniversalTime() }
    } while ((-not [bool]$after.enabled -or $next -le (Get-Date).ToUniversalTime().AddSeconds(2)) -and (Get-Date).ToUniversalTime() -lt $deadline)
    Assert-CanonicalWriterRestoreReadback $Before $after
    if ($next -le (Get-Date).ToUniversalTime().AddSeconds(2) -or $next -gt (Get-Date).ToUniversalTime().AddSeconds(120)) {
        throw 'CANONICAL_WRITER_RESTORE_NEXT_TRIGGER_NOT_FUTURE'
    }
    return [ordered]@{
        status='PASS'
        binding_sha256_exact=$true
        future_natural_trigger_utc=$next.ToString('o')
        readback=$after
    }
}
function Confirm-CanonicalWriterRunning([string]$InstallRootValue, $EnabledBaseline) {
    $baseline = $EnabledBaseline.readback
    $boundary = [datetime]::Parse([string]$EnabledBaseline.future_natural_trigger_utc).ToUniversalTime()
    while ((Get-Date).ToUniversalTime() -lt $boundary.AddSeconds(5)) { Start-Sleep -Milliseconds 500 }
    $deadline = $boundary.AddSeconds(45)
    do {
        $after = Get-CanonicalWriterSnapshot $InstallRootValue
        $last = if ([string]::IsNullOrWhiteSpace([string]$after.last_run_time_utc)) {
            [datetime]::MinValue
        }
        else { [datetime]::Parse([string]$after.last_run_time_utc).ToUniversalTime() }
        $logChanged = (
            [bool]$after.log.exists -and
            [int64]$after.log.bytes -gt [int64]$baseline.log.bytes -and
            [string]$after.log.mtime_utc -cne [string]$baseline.log.mtime_utc -and
            [string]$after.log.sha256 -cne [string]$baseline.log.sha256
        )
        $statusChanged = (
            [bool]$after.runtime_status.exists -and
            [string]$after.runtime_status.mtime_utc -cne [string]$baseline.runtime_status.mtime_utc -and
            [string]$after.runtime_status.sha256 -cne [string]$baseline.runtime_status.sha256
        )
        $passed = (
            [bool]$after.enabled -and
            [string]$after.binding_sha256 -ceq [string]$baseline.binding_sha256 -and
            $last -ge $boundary.AddSeconds(-5) -and
            [int64]$after.last_task_result -eq 0 -and
            $logChanged -and $statusChanged
        )
        if (-not $passed) { Start-Sleep -Milliseconds 500 }
    } while (-not $passed -and (Get-Date).ToUniversalTime() -lt $deadline)
    if (-not $passed) { throw 'CANONICAL_WRITER_NATURAL_TRIGGER_PROOF_FAILED' }
    return [ordered]@{
        status='PASS'
        natural_trigger_utc=$boundary.ToString('o')
        last_run_time_advanced=$true
        last_task_result=[int64]$after.last_task_result
        log_actual_write=$true
        runtime_status_actual_write=$true
        readback=$after
    }
}

if (-not $SourceRoot) { $SourceRoot = $PSScriptRoot }
$source = Full $SourceRoot 'SourceRoot'; $install = Full $InstallRoot 'InstallRoot'
if (-not $testMode -and -not (Same $install $CanonicalRoot)) { throw 'InstallRoot is not canonical.' }
$sourceManifest = Manifest $source $SkipSignatureValidationForTest
$wanted = Command $install
if ($PlanOnly) {
    "install_status=PLAN_ONLY"; "install_root=$install"; "autostart_command=$wanted"; 'registry_changed=false'; exit 0
}

$winps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$lad = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
$statusRoot = Join-Path $lad 'KMTech\DirectSync\container_audit\status'
$stop = Join-Path $lad 'KMTech\DirectSync\container_audit\control\container_audit_user_relay.stop.json'
$onboardingPath = Join-Path $statusRoot 'current_user_onboarding.json'
$removalPath = Join-Path $statusRoot 'current_user_removal.json'
$relayPath = Join-Path $statusRoot 'container_audit_user_relay.json'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N')
$auditPath = Join-Path $lad "KMTech\ContainerAudit\install-audit\canonical-portable-$runId.json"
$evidenceFull = if ($EvidencePath) { Full $EvidencePath 'EvidencePath' } else { '' }
$before = Snapshot
$old = @(Relays)
$writerBefore = if ($testMode) {
    [ordered]@{ present=$false; classification='TEST_BYPASS'; restore_required=$false }
}
else { Get-CanonicalWriterPreimageForQuiesce $install }
$audit = [ordered]@{
    schema='container-audit-canonical-portable-install-v2'
    status='PREIMAGE_SAVED'
    run_id=$runId
    captured_at=(Get-Date).ToUniversalTime().ToString('o')
    install_root=$install
    code_placement='NOT_STARTED'
    source_commit=[string]$sourceManifest.source_commit
    runtime_pythonw_sha256=''
    runtime_pythonw_signature=''
    registry_value=$RunName
    preimage=$before
    after=[ordered]@{exists=$true;kind='String';data=$wanted}
    stop_marker_path=$stop
    scheduled_writer=[ordered]@{
        classification=[string]$writerBefore.classification
        preimage=$writerBefore
        disable_readback=$null
        stop_proof=$null
        restore_readback=$null
        natural_trigger_proof=$null
        restore_failure_code=''
    }
    rollback=[ordered]@{
        available=$true
        applied=$false
        runtime_restored=$false
        scheduled_writer_restored=(-not [bool]$writerBefore.restore_required)
    }
}
Save $auditPath $audit
if ($evidenceFull) { Save $evidenceFull $audit }

$mutated = $false
$writerRestoreNeeded = [bool]$writerBefore.restore_required
try {
    if ($writerRestoreNeeded) {
        $writerDisabled = Disable-CanonicalWriter $install $writerBefore
        $audit.scheduled_writer.disable_readback = $writerDisabled
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        $writerStopped = Confirm-CanonicalWriterStopped $install $writerBefore $writerDisabled
        $audit.scheduled_writer.stop_proof = $writerStopped
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
    }

    $placement = 'INSTALL_REQUIRED'
    if (Test-Path $install -PathType Container) {
        try {
            $candidate = Manifest $install $SkipSignatureValidationForTest
            if ([string]$candidate.source_commit -cne [string]$sourceManifest.source_commit -or
                (Sha (Join-Path $install 'runtime\pythonw.exe')) -cne (Sha (Join-Path $source 'runtime\pythonw.exe'))) { throw 'identity differs' }
            $helper = (Join-Path $PSScriptRoot 'tools\bootstrap_integrity.ps1').Replace("'","''")
            $escapedRoot = $install.Replace("'","''")
            & $winps -NoLogo -NoProfile -NonInteractive -Command ". '$helper'; [void](Assert-BootstrapIntegrityRecord '$escapedRoot')"
            if ($LASTEXITCODE -ne 0) { throw 'integrity differs' }
            $placement = 'REUSED_VERIFIED'
        } catch { $placement = 'INSTALL_REQUIRED' }
    }
    if ($placement -eq 'INSTALL_REQUIRED') {
        $bootstrap = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'INSTALL_THIS_PC.ps1'),'-SourceRoot',$source,'-InstallRoot',$install)
        if ($testMode) { $bootstrap += '-AllowNoncanonicalLayoutForTest' }
        & $winps @bootstrap
        if ($LASTEXITCODE -ne 0) { throw "Code placement failed: $LASTEXITCODE" }
        $placement = 'PASS'
    }
    $installedManifest = Manifest $install $SkipSignatureValidationForTest
    if ([string]$installedManifest.source_commit -cne [string]$sourceManifest.source_commit) { throw 'Installed identity differs.' }
    $audit.code_placement=$placement
    $audit.source_commit=[string]$installedManifest.source_commit
    $audit.runtime_pythonw_sha256=Sha (Join-Path $install 'runtime\pythonw.exe')
    $audit.runtime_pythonw_signature=[string](Get-AuthenticodeSignature (Join-Path $install 'runtime\pythonw.exe')).Status
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }

    $mutated = $true
    Product $install '--remove-current-user-setup'
    $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((Snapshot).exists -or [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
        [string]$removal.relay_process.status -cne 'ABSENT') { throw 'Removal readback failed.' }
    $started = (Get-Date).ToUniversalTime()
    Product $install '--onboard-current-user'
    $onboarding = Get-Content $onboardingPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $after = Snapshot
    if ([string]$onboarding.status -cne 'READY' -or [string]$onboarding.relay_autostart.command -cne $wanted -or
        -not $after.exists -or [string]$after.data -cne $wanted) { throw 'Onboarding Run readback failed.' }
    $pidValue = [int]$onboarding.relay_start.process_id
    Start-Sleep -Seconds 5
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction SilentlyContinue
    if ($null -eq $process -or -not (Same ([string]$process.ExecutablePath) (Join-Path $install 'runtime\pythonw.exe'))) { throw 'Relay process proof failed.' }
    $deadline=(Get-Date).AddSeconds(75)
    $relay=$null
    while((Get-Date)-lt $deadline){
        if((Test-Path $relayPath) -and (Get-Item $relayPath).LastWriteTimeUtc -ge $started.AddSeconds(-1)){
            $relay=Get-Content $relayPath -Raw -Encoding UTF8|ConvertFrom-Json
            if([bool]$relay.persistent_retry){break}
        }
        Start-Sleep -Milliseconds 500
    }
    if($null-eq$relay -or -not [bool]$relay.persistent_retry){throw 'Fresh relay status proof failed.'}
    $audit.status='PRODUCT_PHASE_PASS'
    $audit.stop_marker_absent=-not(Test-Path $stop)
    $audit.onboarding=[ordered]@{status=[string]$onboarding.status;action=[string]$onboarding.action;autostart_writer='product_onboarding'}
    $audit.exact_launch=[ordered]@{status='PROVEN';process_id=$pidValue;executable=[string]$process.ExecutablePath;relay_status=[string]$relay.status;persistent_retry=[bool]$relay.persistent_retry}
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }

    if ($writerRestoreNeeded) {
        $writerEnabled = Enable-CanonicalWriter $install $writerBefore
        $audit.scheduled_writer.restore_readback = $writerEnabled
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        $writerRunning = Confirm-CanonicalWriterRunning $install $writerEnabled
        $audit.scheduled_writer.natural_trigger_proof = $writerRunning
        $audit.rollback.scheduled_writer_restored=$true
        $writerRestoreNeeded=$false
    }
    $audit.status='PASS'
    $audit.completed_at=(Get-Date).ToUniversalTime().ToString('o')
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }
    'install_status=PASS'
    "install_root=$install"
    "code_placement_status=$placement"
    'autostart_status=PROVEN_NON_REBOOT_APPROXIMATION'
    "autostart_command=$wanted"
    "autostart_process_id=$pidValue"
    "stop_marker_absent=$($audit.stop_marker_absent.ToString().ToLowerInvariant())"
    'cold_boot_status=UNPROVEN'
    "audit_path=$auditPath"
}
catch {
    $original=$_
    $autostartRollbackFailure=''
    try {
        if($mutated){
            try{Product $install '--remove-current-user-setup'}catch{}
            Restore $before
            if(Test-Path $stop){Remove-Item $stop -Force}
            foreach($item in $old){
                $newPid=StartRaw ([string]$item.CommandLine)
                Start-Sleep -Seconds 3
                $p=Get-CimInstance Win32_Process -Filter "ProcessId = $newPid" -ErrorAction SilentlyContinue
                if($null-eq$p -or -not(Same ([string]$p.ExecutablePath)([string]$item.ExecutablePath))){throw 'runtime restore failed'}
            }
            $check=Snapshot
            if([bool]$check.exists-ne[bool]$before.exists -or [string]$check.data-cne[string]$before.data){throw 'registry restore failed'}
        }
        $audit.rollback.applied=$mutated
        $audit.rollback.runtime_restored=$true
    }
    catch {
        $audit.status='AUTOSTART_ROLLBACK_FAILED'
        $autostartRollbackFailure=$_.Exception.GetType().Name
        $audit.failure_type=$original.Exception.GetType().Name
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
    }
    if ($writerRestoreNeeded) {
        try {
            $writerEnabled = Enable-CanonicalWriter $install $writerBefore
            $audit.scheduled_writer.restore_readback = $writerEnabled
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
            $writerRunning = Confirm-CanonicalWriterRunning $install $writerEnabled
            $audit.scheduled_writer.natural_trigger_proof = $writerRunning
            $audit.rollback.scheduled_writer_restored=$true
            $writerRestoreNeeded=$false
        }
        catch {
            $audit.status='CANONICAL_WRITER_RESTORE_FAILED'
            $audit.scheduled_writer.restore_failure_code='CANONICAL_WRITER_RESTORE_FAILED'
            $audit.failure_type=$original.Exception.GetType().Name
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
            throw "CANONICAL_WRITER_RESTORE_FAILED: $($_.Exception.GetType().Name)"
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($autostartRollbackFailure)) {
        throw "AUTOSTART_ROLLBACK_FAILED: $autostartRollbackFailure"
    }
    $audit.status='FAILED_ROLLED_BACK'
    $audit.failure_type=$original.Exception.GetType().Name
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }
    throw $original
}
