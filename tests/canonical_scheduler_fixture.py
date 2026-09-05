"""Owned scheduler observations for the canonical installer entrypoint.

No scheduled task is registered or queried on the host. Product task binding,
disable/enable fence wrappers, snapshot/file checks and both proof routines run
unchanged. Only scheduler APIs and their clock are deterministic boundaries.
"""

SCHEDULER_OS = r'''
$script:caSchedulerClock = [DateTime]::UtcNow
$script:caSchedulerNext = $script:caSchedulerClock.AddSeconds(20)
$script:caSchedulerLast = $script:caSchedulerClock.AddMinutes(-1)
$script:caSchedulerEnabledOnce = $false
$script:caSchedulerTriggered = $false
$script:caSchedulerLog = Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\logs\scheduled_direct_sync_relay.jsonl'
$script:caSchedulerStatus = Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\status\scheduled_direct_sync_relay_status.json'
foreach ($file in @($script:caSchedulerLog, $script:caSchedulerStatus)) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $file) -Force | Out-Null
    [IO.File]::WriteAllText($file, '{"phase":"before"}')
    [IO.File]::SetLastWriteTimeUtc($file, $script:caSchedulerLast)
}
$script:caSchedulerTask = [pscustomobject]@{
    TaskName=$CanonicalWriterTaskName; TaskPath='\'; State='Ready'
    Actions=@([pscustomobject]@{
        Execute=(Join-Path $install 'runtime\python.exe')
        Arguments=('"' + (Join-Path $install 'app\main.py') + '" --container-audit-direct-sync-relay --log-path "' + $script:caSchedulerLog + '" --status-path "' + $script:caSchedulerStatus + '"')
        WorkingDirectory=$install
    })
    Principal=[pscustomobject]@{
        UserId=[Security.Principal.WindowsIdentity]::GetCurrent().Name
        LogonType='Interactive'; RunLevel='Limited'
    }
    Triggers=@([pscustomobject]@{
        CimClass=[pscustomobject]@{ CimClassName='MSFT_TaskTimeTrigger' }
        Enabled=$true; StartBoundary=$script:caSchedulerNext.ToString('o')
        Repetition=[pscustomobject]@{ Interval='PT1M'; Duration=''; StopAtDurationEnd=$false }
    })
    Settings=[pscustomobject]@{
        Enabled=$true; StartWhenAvailable=$true; MultipleInstances='IgnoreNew'
        ExecutionTimeLimit='PT2M'; DisallowStartIfOnBatteries=$false; StopIfGoingOnBatteries=$false
    }
}
function Write-OwnedSchedulerEvent([string]$Event, $Detail) {
    $record = [ordered]@{ event=$Event; at=$script:caSchedulerClock.ToString('o'); detail=$Detail }
    [IO.File]::AppendAllText((Join-Path $env:CA_UNINSTALL_ROOT 'scheduler-events.jsonl'), (($record | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine))
}
function Test-OwnedSchedulerClock {
    return [bool](@(Get-PSCallStack | Where-Object {
        $_.FunctionName -in @('Get-CanonicalWriterPreimageForQuiesce', 'Disable-CanonicalWriter',
            'Confirm-CanonicalWriterStopped', 'Enable-CanonicalWriter', 'Confirm-CanonicalWriterRunning')
    }).Count)
}
function Get-Date {
    if (Test-OwnedSchedulerClock) { return $script:caSchedulerClock }
    return Microsoft.PowerShell.Utility\Get-Date @args
}
function Start-Sleep {
    param([int]$Seconds=0, [int]$Milliseconds=0)
    if (-not (Test-OwnedSchedulerClock)) {
        Microsoft.PowerShell.Utility\Start-Sleep @PSBoundParameters
        return
    }
    $script:caSchedulerClock = $script:caSchedulerClock.AddSeconds($Seconds).AddMilliseconds($Milliseconds)
    if ($script:caSchedulerEnabledOnce -and -not $script:caSchedulerTriggered -and
        $script:caSchedulerClock -ge $script:caSchedulerNext) {
        $active = Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'KMTech\DirectSync\container_audit\control\writer-session\active.json')
        Write-OwnedSchedulerEvent 'natural_trigger' @{ fence_active=$active }
        if ($active) { throw 'Owned scheduled trigger crossed before writer fence release' }
        $script:caSchedulerTriggered = $true
        $script:caSchedulerLast = $script:caSchedulerNext
        [IO.File]::AppendAllText($script:caSchedulerLog, "`n" + '{"phase":"natural_trigger"}')
        [IO.File]::WriteAllText($script:caSchedulerStatus, '{"phase":"natural_trigger","status":"PASS"}')
        foreach ($file in @($script:caSchedulerLog, $script:caSchedulerStatus)) {
            [IO.File]::SetLastWriteTimeUtc($file, $script:caSchedulerLast)
        }
    }
}
function Get-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    if ($TaskName -and ($TaskName -cne $script:caSchedulerTask.TaskName -or $TaskPath -cne '\')) {
        throw 'Unexpected owned scheduler query'
    }
    return $script:caSchedulerTask
}
function Get-ScheduledTaskInfo {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    if ($TaskName -cne $script:caSchedulerTask.TaskName -or $TaskPath -cne '\') {
        throw 'Unexpected owned scheduler info query'
    }
    return [pscustomobject]@{
        LastTaskResult=0; LastRunTime=$script:caSchedulerLast; NextRunTime=$script:caSchedulerNext
    }
}
function Disable-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    [void](Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath)
    $script:caSchedulerTask.Settings.Enabled = $false
    $script:caSchedulerTask.State = 'Disabled'
    Write-OwnedSchedulerEvent 'disable' @{}
    return $script:caSchedulerTask
}
function Stop-ScheduledTask { throw 'A Ready owned task should not need forced termination' }
function Enable-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    [void](Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath)
    $script:caSchedulerTask.Settings.Enabled = $true
    $script:caSchedulerTask.State = 'Ready'
    $script:caSchedulerEnabledOnce = $true
    $script:caSchedulerNext = $script:caSchedulerClock.AddSeconds(20)
    Write-OwnedSchedulerEvent 'enable' @{}
    return $script:caSchedulerTask
}
'''

PREPLACEMENT_OBSERVER = r'''
    $durable = Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json
    $proof = $durable.scheduled_writer.stop_proof
    if ($proof.status -cne 'PASS' -or -not $proof.last_run_time_unchanged -or
        -not $proof.log_size_mtime_sha256_unchanged -or -not $proof.runtime_status_unchanged -or
        $proof.readback.enabled -or $proof.readback.process_count -ne 0) {
        throw 'Owned product mutation reached without durable scheduled stop proof'
    }
    if ((Sha $script:caSchedulerLog) -cne $proof.readback.log.sha256 -or
        (Sha $script:caSchedulerStatus) -cne $proof.readback.runtime_status.sha256) {
        throw 'Owned product mutation reached with mismatched stopped writer files'
    }
    Write-OwnedSchedulerEvent 'product_mode' @{ mode=$Mode; code_sha256=(Sha (Join-Path $Root 'app\main.py')) }
'''

DURABLE_AUDIT_OBSERVER = r'''
    if ($Value -is [Collections.IDictionary] -and $Value.Contains('scheduled_writer')) {
        $saved = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        Write-OwnedSchedulerEvent 'audit_saved' @{
            status=$saved.status; completed=($null -ne $saved.PSObject.Properties['completed_at'])
            scheduled_writer=$saved.scheduled_writer
        }
    }
'''
