[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'ValidatePrepared', 'ValidateReplacement', 'RestoreWriter', 'Recover', 'SelfTest')]
    [string]$Mode,
    [string]$InstallRoot = 'C:\KMTech\Apps\Container_Audit\current',
    [string]$EvidencePath = '',
    [string]$PreparedReceiptPath = '',
    [string]$PreparedReceiptSha256 = '',
    [string]$HistoricalReceiptPath = '',
    [string]$HistoricalReceiptSha256 = '',
    [string]$SessionId = '',
    [string]$AttemptId = '',
    [string]$SessionStartedAtUtc = '',
    [string]$OrchestratorSha256 = '',
    [string]$ReplacementTransactionId = '',
    [string]$ReplacementReceiptPath = '',
    [string]$ReplacementReceiptSha256 = '',
    [string]$ExpectedSourceCommit = '',
    [string]$ExpectedSourceAggregateSha256 = '',
    [string]$HelperPath = '',
    [string]$ExpectedHelperSha256 = '',
    [string]$RestoreEvidencePath = '',
    [string]$WriterRestoreEvidencePath = '',
    [switch]$RetainDisabledOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:TaskName = 'direct-sync-relay-container-audit'
$Script:TaskPath = '\'
$Script:RelayMode = '--container-audit-direct-sync-relay'
$Script:PreparedSchema = 'container-audit-writer-session-prepared-v1'
$Script:RestoredSchema = 'container-audit-writer-session-restored-v1'
$Script:RecoverySchema = 'container-audit-window-recovery-v1'
$Script:ReplacementSchema = 'container-audit-verified-replacement-v1'
$Script:HistoricalSchema = 'container-audit-canonical-writer-lifecycle-v1'
$Script:AdapterPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$Script:IntegrityHelperPath = Join-Path $PSScriptRoot 'bootstrap_integrity.ps1'
if (-not (Test-Path -LiteralPath $Script:IntegrityHelperPath -PathType Leaf)) {
    throw 'Container writer session adapter cannot load its integrity helper.'
}
. $Script:IntegrityHelperPath
$Script:AdapterSha256 = Get-FileSha256 $Script:AdapterPath

function Get-ObjectPropertyValue($Value, [string]$Name, $Default = $null) {
    if ($null -eq $Value) { return $Default }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Test-ExactPropertySet($Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) { return $false }
    }
    return $true
}

function Get-StringSha256([string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function ConvertTo-RoundTripUtc([string]$Value, [string]$Purpose) {
    try {
        return [DateTime]::Parse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }
    catch { throw "$Purpose is not a round-trip timestamp." }
}

function Assert-Hex([string]$Value, [int]$Length, [string]$Purpose) {
    if ($Value -cnotmatch ("^[0-9a-f]{{$Length}}$")) { throw "$Purpose is malformed." }
}

function Test-PathInside([string]$Candidate, [string]$Parent) {
    try {
        $candidateFull = Get-StrictFullPath $Candidate 'candidate path'
        $parentFull = (Get-StrictFullPath $Parent 'parent path').TrimEnd('\') + '\'
        return $candidateFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Read-BoundedJson([string]$Path, [int64]$MaximumBytes, [string]$ExpectedSha256 = '') {
    $full = Get-StrictFullPath $Path 'JSON evidence path'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'JSON evidence is absent.' }
    Assert-BootstrapNoReparsePoint $full 'JSON evidence'
    $before = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ([int64]$before.Length -le 0 -or [int64]$before.Length -gt $MaximumBytes) {
        throw 'JSON evidence size is invalid.'
    }
    $actualSha = Get-FileSha256 $full
    $after = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ([int64]$before.Length -ne [int64]$after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
        throw 'JSON evidence changed while it was read.'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        Assert-Hex $ExpectedSha256 64 'expected JSON SHA-256'
        if ($actualSha -cne $ExpectedSha256) { throw 'JSON evidence SHA-256 differs.' }
    }
    try { return Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'JSON evidence is invalid.' }
}

function Write-JsonAtomic([string]$Path, $Payload, [switch]$AllowReplace) {
    $full = Get-StrictFullPath $Path 'JSON output path'
    $parent = Split-Path -Parent $full
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-BootstrapNoReparsePoint $parent 'JSON output parent'
    if ((Test-Path -LiteralPath $full) -and -not $AllowReplace.IsPresent) {
        throw 'JSON output path already exists.'
    }
    $temporary = $full + '.tmp.' + [Guid]::NewGuid().ToString('N')
    $json = ($Payload | ConvertTo-Json -Depth 32)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json + [Environment]::NewLine)
    try {
        $stream = New-Object IO.FileStream(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            [IO.File]::Replace($temporary, $full, $null)
        }
        else { [IO.File]::Move($temporary, $full) }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
    return [pscustomobject][ordered]@{
        path = $full
        exists = (Test-Path -LiteralPath $full -PathType Leaf)
        sha256 = Get-FileSha256 $full
        length = [int64](Get-Item -LiteralPath $full -Force).Length
    }
}

function Get-StableFileFingerprint([string]$Path, [string]$Purpose) {
    $full = Get-StrictFullPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Purpose is absent." }
    $before = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    $sha = Get-FileSha256 $full
    $after = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ([int64]$before.Length -ne [int64]$after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
        throw "$Purpose changed while it was observed."
    }
    return [pscustomobject][ordered]@{
        path = $full
        bytes = [int64]$after.Length
        mtime_utc = $after.LastWriteTimeUtc.ToString('o')
        sha256 = $sha
        contents_recorded = $false
    }
}

function Test-FingerprintEqual($Left, $Right) {
    return (
        $null -ne $Left -and $null -ne $Right -and
        [int64]$Left.bytes -eq [int64]$Right.bytes -and
        [string]$Left.mtime_utc -ceq [string]$Right.mtime_utc -and
        [string]$Left.sha256 -ceq [string]$Right.sha256
    )
}

function Wait-ContainerCondition([scriptblock]$Predicate, [int]$TimeoutSeconds, [int]$PollMilliseconds = 1000) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Predicate) { return $true }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ([DateTime]::UtcNow -lt $deadline)
    return [bool](& $Predicate)
}

function Get-CurrentUserSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) { throw 'Current user SID is unavailable.' }
    return [string]$identity.User.Value
}

function Test-PrincipalIsCurrentUser([string]$PrincipalUser) {
    $name = [string][Environment]::UserName
    return (
        $PrincipalUser.Equals($name, [StringComparison]::OrdinalIgnoreCase) -or
        $PrincipalUser.EndsWith("\$name", [StringComparison]::OrdinalIgnoreCase)
    )
}

function Get-ContainerWriterProcessCount([string]$CanonicalInstallRoot) {
    $expectedExecutable = Join-Path $CanonicalInstallRoot 'runtime\python.exe'
    $count = 0
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $executable = [string](Get-ObjectPropertyValue $process 'ExecutablePath' '')
        if ([string]::IsNullOrWhiteSpace($executable) -or -not (Test-BootstrapSamePath $executable $expectedExecutable)) { continue }
        $command = [string](Get-ObjectPropertyValue $process 'CommandLine' '')
        if ([string]::IsNullOrWhiteSpace($command)) {
            throw 'A possible Container writer process has an unreadable command line.'
        }
        if ($command.IndexOf($Script:RelayMode, [StringComparison]::Ordinal) -ge 0) { $count += 1 }
    }
    return $count
}

function Get-ContainerWriterReadback([string]$CanonicalInstallRoot) {
    $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
    $matches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        ([string]$_.TaskName).Equals($Script:TaskName, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($matches.Count -ne 1 -or [string]$matches[0].TaskPath -cne $Script:TaskPath) {
        throw 'Container writer task cardinality or path is not exact.'
    }
    $task = $matches[0]
    $info = Get-ScheduledTaskInfo -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    if ($actions.Count -ne 1 -or $triggers.Count -ne 1) {
        throw 'Container writer action/trigger shape is not exact.'
    }
    $action = $actions[0]
    $trigger = $triggers[0]
    $arguments = [string]$action.Arguments
    $argumentsSha = Get-StringSha256 $arguments
    $expectedExecutable = Join-Path $root 'runtime\python.exe'
    $expectedWorkingDirectory = Join-Path $root 'app'
    $expectedMain = Join-Path $root 'app\main.py'
    $principal = [string]$task.Principal.UserId
    $principalSid = Get-CurrentUserSid
    $definition = Export-ScheduledTask -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop
    $identityMaterial = @(
        [string]$task.TaskPath,
        [string]$task.TaskName,
        [string]$action.Execute,
        [string]$action.WorkingDirectory,
        $argumentsSha,
        $principal,
        $principalSid,
        [string]$task.Principal.LogonType,
        [string]$task.Principal.RunLevel,
        [string]$trigger.CimClass.CimClassName,
        [string]$trigger.StartBoundary,
        [string]$trigger.Enabled,
        [string]$trigger.Repetition.Interval,
        [string]$task.Settings.StartWhenAvailable,
        [string]$task.Settings.MultipleInstances
    ) -join "`n"
    $identityExact = (
        (Test-BootstrapSamePath ([string]$action.Execute) $expectedExecutable) -and
        (Test-BootstrapSamePath ([string]$action.WorkingDirectory) $expectedWorkingDirectory) -and
        $arguments.IndexOf($expectedMain, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $arguments.IndexOf($Script:RelayMode, [StringComparison]::Ordinal) -ge 0 -and
        (Test-PrincipalIsCurrentUser $principal) -and
        [string]$task.Principal.LogonType -ceq 'Interactive' -and
        [string]$task.Principal.RunLevel -ceq 'Limited' -and
        [string]$trigger.CimClass.CimClassName -ceq 'MSFT_TaskTimeTrigger' -and
        [bool]$trigger.Enabled -and
        [string]$trigger.Repetition.Interval -ceq 'PT1M' -and
        [bool]$task.Settings.StartWhenAvailable -and
        [string]$task.Settings.MultipleInstances -ceq 'IgnoreNew'
    )
    return [pscustomobject][ordered]@{
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        enabled = [bool]$task.Settings.Enabled
        state = [string]$task.State
        last_task_result = [int64]$info.LastTaskResult
        last_run_time_utc = $info.LastRunTime.ToUniversalTime().ToString('o')
        next_run_time_utc = $info.NextRunTime.ToUniversalTime().ToString('o')
        exact_writer_process_count = Get-ContainerWriterProcessCount $root
        identity = [pscustomobject][ordered]@{
            status = if ($identityExact) { 'PASS' } else { 'FAIL' }
            task_name = $Script:TaskName
            task_path = $Script:TaskPath
            execute = [string]$action.Execute
            working_directory = [string]$action.WorkingDirectory
            arguments_sha256 = $argumentsSha
            expected_main_bound = ($arguments.IndexOf($expectedMain, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            expected_mode_bound = ($arguments.IndexOf($Script:RelayMode, [StringComparison]::Ordinal) -ge 0)
            raw_arguments_recorded = $false
            principal_user = $principal
            principal_sid = $principalSid
            logon_type = [string]$task.Principal.LogonType
            run_level = [string]$task.Principal.RunLevel
            trigger_type = [string]$trigger.CimClass.CimClassName
            trigger_start_boundary = [string]$trigger.StartBoundary
            trigger_repetition_interval = [string]$trigger.Repetition.Interval
            start_when_available = [bool]$task.Settings.StartWhenAvailable
            multiple_instances = [string]$task.Settings.MultipleInstances
            definition_sha256 = Get-StringSha256 ([string]$definition)
            binding_sha256 = Get-StringSha256 $identityMaterial
        }
    }
}

function Get-ContainerWriterEffects {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is unavailable.' }
    $root = Join-Path ([IO.Path]::GetFullPath($env:LOCALAPPDATA)) 'KMTech\DirectSync\container_audit'
    return [pscustomobject][ordered]@{
        log = Get-StableFileFingerprint (Join-Path $root 'logs\scheduled_direct_sync_relay.jsonl') 'Container writer log'
        runtime_status = Get-StableFileFingerprint (Join-Path $root 'status\scheduled_direct_sync_relay_status.json') 'Container writer runtime status'
    }
}

function Read-ContainerHistoricalCapability([string]$Path, [string]$ExpectedSha256, [string]$CanonicalInstallRoot) {
    $receipt = Read-BoundedJson $Path 1048576 $ExpectedSha256
    $items = @($receipt.items)
    $ids = @($items | ForEach-Object { [int]$_.id } | Sort-Object)
    $itemsExact = (
        $items.Count -eq 8 -and
        (($ids -join ',') -ceq '1,2,3,4,5,6,7,8') -and
        @($items | Where-Object { [string]$_.status -cne 'PASS' }).Count -eq 0
    )
    $preimage = $receipt.preimage
    $exact = (
        [string]$receipt.schema -ceq $Script:HistoricalSchema -and
        [string]$receipt.status -ceq 'PASS' -and
        $receipt.manual_start_used -is [bool] -and -not [bool]$receipt.manual_start_used -and
        $itemsExact -and
        [string]$preimage.classification -ceq 'CANONICAL_QUIESCE_RESTORE' -and
        [bool]$preimage.present -and [bool]$preimage.restore_required -and
        [string]$preimage.task_name -ceq $Script:TaskName -and [string]$preimage.task_path -ceq $Script:TaskPath -and
        (Test-BootstrapSamePath ([string]$preimage.action_execute) (Join-Path $CanonicalInstallRoot 'runtime\python.exe')) -and
        [string]$preimage.action_mode -ceq $Script:RelayMode -and
        [string]$preimage.logon_type -ceq 'Interactive' -and [string]$preimage.run_level -ceq 'Limited' -and
        [string]$preimage.trigger_type -ceq 'MSFT_TaskTimeTrigger' -and [string]$preimage.trigger_interval -ceq 'PT1M' -and
        [bool]$preimage.start_when_available -and [string]$preimage.multiple_instances -ceq 'IgnoreNew' -and
        [string]$preimage.binding_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$receipt.negative_restore_binding.status -ceq 'PASS' -and
        [string]$receipt.negative_restore_binding.failure_code -ceq 'CANONICAL_WRITER_RESTORE_BINDING_MISMATCH' -and
        $receipt.negative_restore_binding.task_mutation -is [bool] -and -not [bool]$receipt.negative_restore_binding.task_mutation
    )
    if (-not $exact) { throw 'Historical Container eight-point writer capability receipt is invalid.' }
    return $receipt
}

function Assert-LiveMatchesHistorical($Live, $Historical, [string]$CanonicalInstallRoot) {
    $preimage = $Historical.preimage
    $exact = (
        [string]$Live.identity.status -ceq 'PASS' -and
        [string]$Live.identity.task_name -ceq [string]$preimage.task_name -and
        [string]$Live.identity.task_path -ceq [string]$preimage.task_path -and
        (Test-BootstrapSamePath ([string]$Live.identity.execute) ([string]$preimage.action_execute)) -and
        (Test-BootstrapSamePath ([string]$Live.identity.working_directory) (Join-Path $CanonicalInstallRoot 'app')) -and
        [bool]$Live.identity.expected_mode_bound -and [bool]$Live.identity.expected_main_bound -and
        [string]$Live.identity.principal_sid -ceq [string]$preimage.principal_sid -and
        [string]$Live.identity.logon_type -ceq [string]$preimage.logon_type -and
        [string]$Live.identity.run_level -ceq [string]$preimage.run_level -and
        [string]$Live.identity.trigger_type -ceq [string]$preimage.trigger_type -and
        [string]$Live.identity.trigger_repetition_interval -ceq [string]$preimage.trigger_interval -and
        [bool]$Live.identity.start_when_available -eq [bool]$preimage.start_when_available -and
        [string]$Live.identity.multiple_instances -ceq [string]$preimage.multiple_instances
    )
    if (-not $exact) { throw 'Live Container writer identity drifted from the eight-point capability receipt.' }
}

function Invoke-ContainerWriterSafetyFence([string]$CanonicalInstallRoot, [string]$ExpectedBindingSha256, [string]$Reason) {
    try {
        $live = Get-ContainerWriterReadback $CanonicalInstallRoot
        if ([string]$live.identity.status -cne 'PASS' -or [string]$live.identity.binding_sha256 -cne $ExpectedBindingSha256) {
            return [pscustomobject][ordered]@{ status = 'FAIL'; reason = 'BINDING_MISMATCH_MUTATION_SUPPRESSED'; task_mutation = $false; failure_type = '' }
        }
        $mutation = $false
        if ([bool]$live.enabled) {
            Disable-ScheduledTask -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop | Out-Null
            $mutation = $true
        }
        $disabled = Wait-ContainerCondition -TimeoutSeconds 45 -Predicate {
            $candidate = Get-ContainerWriterReadback $CanonicalInstallRoot
            return (
                -not [bool]$candidate.enabled -and [string]$candidate.state -ceq 'Disabled' -and
                [string]$candidate.identity.binding_sha256 -ceq $ExpectedBindingSha256 -and
                [int]$candidate.exact_writer_process_count -eq 0
            )
        }
        return [pscustomobject][ordered]@{
            status = if ($disabled) { 'PASS' } else { 'FAIL' }
            reason = $Reason
            task_mutation = $mutation
            live_disabled_exact = $disabled
            failure_type = ''
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            status = 'FAIL'
            reason = $Reason
            task_mutation = $false
            live_disabled_exact = $false
            failure_type = $_.Exception.GetType().Name
        }
    }
}

function Invoke-ContainerWriterPrepare {
    param(
        [string]$CanonicalInstallRoot,
        [string]$OutputPath,
        [string]$CurrentSessionId,
        [string]$CurrentAttemptId,
        [string]$CurrentSessionStartedAtUtc,
        [string]$CurrentOrchestratorSha256,
        [string]$CapabilityPath,
        [string]$CapabilitySha256,
        [switch]$RetainDisabled
    )
    Assert-Hex $CurrentSessionId 32 'session id'
    Assert-Hex $CurrentAttemptId 32 'attempt id'
    Assert-Hex $CurrentOrchestratorSha256 64 'orchestrator SHA-256'
    [void](ConvertTo-RoundTripUtc $CurrentSessionStartedAtUtc 'session start')
    Assert-Hex $CapabilitySha256 64 'historical receipt SHA-256'
    $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
    $outputFull = Get-StrictFullPath $OutputPath 'prepared receipt path'
    if (Test-Path -LiteralPath $outputFull) { throw 'Prepared receipt path already exists.' }
    if (Test-PathInside $outputFull $root) { throw 'Prepared receipt must be outside the mutable code root.' }
    $receipt = [ordered]@{
        schema = $Script:PreparedSchema
        status = 'IN_PROGRESS'
        session_id = $CurrentSessionId
        attempt_id = $CurrentAttemptId
        session_started_at_utc = $CurrentSessionStartedAtUtc
        orchestrator_sha256 = $CurrentOrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        evidence_path = $outputFull
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        completed_at_utc = ''
        secret_values_recorded = $false
        historical_capability = [ordered]@{ schema = $Script:HistoricalSchema; receipt_sha256 = $CapabilitySha256; eight_points_pass = $false; capability_binding_sha256 = '' }
        pre_readback = $null
        disable = [ordered]@{ status = 'NOT_RUN'; post_readback = $null; binding_unchanged = $false }
        quiescence = [ordered]@{ status = 'NOT_RUN'; trigger_boundary_utc = ''; stable_baseline = $null; after_trigger = $null; last_run_time_unchanged = $false; log_unchanged = $false; runtime_status_unchanged = $false; exact_writer_process_count = -1 }
        failure = [ordered]@{ status = 'NONE'; stage = ''; code = ''; failure_type = ''; silently_ignored = $false; emergency_restore_attempted = $false; emergency_restore_succeeded = $null; safety_fence = $null; retain_disabled_requested = $RetainDisabled.IsPresent }
    }
    [void](Write-JsonAtomic $outputFull $receipt)
    $stage = 'CAPABILITY_VALIDATION'
    $mutationStarted = $false
    $pre = $null
    try {
        $historical = Read-ContainerHistoricalCapability $CapabilityPath $CapabilitySha256 $root
        $receipt.historical_capability.eight_points_pass = $true
        $receipt.historical_capability.capability_binding_sha256 = [string]$historical.preimage.binding_sha256
        $stage = 'SAFE_LEAD'
        $safeLead = Wait-ContainerCondition -TimeoutSeconds 90 -Predicate {
            $candidate = Get-ContainerWriterReadback $root
            Assert-LiveMatchesHistorical $candidate $historical $root
            $next = ConvertTo-RoundTripUtc ([string]$candidate.next_run_time_utc) 'next run time'
            return (($next - [DateTime]::UtcNow).TotalSeconds -ge 25)
        }
        if (-not $safeLead) { throw 'No safe lead before the next Container writer trigger.' }
        $stage = 'PRE_READBACK'
        $pre = Get-ContainerWriterReadback $root
        Assert-LiveMatchesHistorical $pre $historical $root
        if (
            -not [bool]$pre.enabled -or [string]$pre.state -cne 'Ready' -or
            [int64]$pre.last_task_result -ne 0 -or [int]$pre.exact_writer_process_count -ne 0
        ) { throw 'Container writer pre-readback is not exact Enabled/Ready/result-zero/process-zero.' }
        $receipt.pre_readback = $pre
        $triggerBoundary = ConvertTo-RoundTripUtc ([string]$pre.next_run_time_utc) 'next run time'
        $receipt.quiescence.trigger_boundary_utc = $triggerBoundary.ToString('o')
        $stage = 'DISABLE'
        $mutationStarted = $true
        Disable-ScheduledTask -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop | Out-Null
        $receipt.disable.status = 'COMMAND_SUCCEEDED'
        $disabled = Wait-ContainerCondition -TimeoutSeconds 45 -Predicate {
            $candidate = Get-ContainerWriterReadback $root
            return (
                -not [bool]$candidate.enabled -and [string]$candidate.state -ceq 'Disabled' -and
                [string]$candidate.identity.binding_sha256 -ceq [string]$pre.identity.binding_sha256 -and
                [int]$candidate.exact_writer_process_count -eq 0
            )
        }
        if (-not $disabled) { throw 'Container writer did not reach exact disabled/process-zero state.' }
        $receipt.disable.post_readback = Get-ContainerWriterReadback $root
        $receipt.disable.binding_unchanged = ([string]$receipt.disable.post_readback.identity.binding_sha256 -ceq [string]$pre.identity.binding_sha256)
        if (-not [bool]$receipt.disable.binding_unchanged) { throw 'Container writer binding changed across disable.' }
        $stage = 'STABLE_BASELINE'
        $baseline = $null
        $stable = Wait-ContainerCondition -TimeoutSeconds 30 -Predicate {
            $first = Get-ContainerWriterEffects
            Start-Sleep -Milliseconds 1000
            $second = Get-ContainerWriterEffects
            if ((Test-FingerprintEqual $first.log $second.log) -and (Test-FingerprintEqual $first.runtime_status $second.runtime_status)) {
                $script:ContainerWriterStableEffects = $second
                return $true
            }
            return $false
        }
        if ($stable) { $baseline = $Script:ContainerWriterStableEffects; $Script:ContainerWriterStableEffects = $null }
        if (-not $stable -or $null -eq $baseline) { throw 'Container writer effects did not reach a stable baseline.' }
        $receipt.quiescence.stable_baseline = $baseline
        $stage = 'NATURAL_BOUNDARY'
        $proofBoundary = $triggerBoundary.AddSeconds(12)
        while ([DateTime]::UtcNow -lt $proofBoundary) { Start-Sleep -Milliseconds 1000 }
        $afterEffects = Get-ContainerWriterEffects
        $after = Get-ContainerWriterReadback $root
        $receipt.quiescence.after_trigger = $afterEffects
        $receipt.quiescence.last_run_time_unchanged = ([string]$after.last_run_time_utc -ceq [string]$pre.last_run_time_utc)
        $receipt.quiescence.log_unchanged = Test-FingerprintEqual $baseline.log $afterEffects.log
        $receipt.quiescence.runtime_status_unchanged = Test-FingerprintEqual $baseline.runtime_status $afterEffects.runtime_status
        $receipt.quiescence.exact_writer_process_count = [int]$after.exact_writer_process_count
        if (
            [bool]$after.enabled -or [string]$after.state -cne 'Disabled' -or
            [string]$after.identity.binding_sha256 -cne [string]$pre.identity.binding_sha256 -or
            -not [bool]$receipt.quiescence.last_run_time_unchanged -or
            -not [bool]$receipt.quiescence.log_unchanged -or
            -not [bool]$receipt.quiescence.runtime_status_unchanged -or
            [int]$receipt.quiescence.exact_writer_process_count -ne 0
        ) { throw 'Container writer was not quiescent across its next natural trigger.' }
        $receipt.quiescence.status = 'PASS'
        $receipt.status = 'PREPARED_DISABLED'
    }
    catch {
        $receipt.status = 'FAIL'
        $receipt.failure.status = 'FAIL'
        $receipt.failure.stage = $stage
        $receipt.failure.code = 'CONTAINER_WRITER_PREPARE_FAILED'
        $receipt.failure.failure_type = $_.Exception.GetType().Name
        if ($mutationStarted -and $null -ne $pre) {
            if ($RetainDisabled.IsPresent) {
                $receipt.failure.safety_fence = Invoke-ContainerWriterSafetyFence $root ([string]$pre.identity.binding_sha256) 'PREPARE_FAILED_RETAIN_DISABLED'
            }
            else {
                $receipt.failure.emergency_restore_attempted = $true
                try {
                    $beforeEnable = Get-ContainerWriterReadback $root
                    if (
                        [string]$beforeEnable.identity.status -cne 'PASS' -or
                        [string]$beforeEnable.identity.binding_sha256 -cne [string]$pre.identity.binding_sha256 -or
                        [bool]$beforeEnable.enabled -or [string]$beforeEnable.state -cne 'Disabled'
                    ) { throw 'Emergency restore precondition is not exact.' }
                    Enable-ScheduledTask -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop | Out-Null
                    $receipt.failure.emergency_restore_succeeded = Wait-ContainerCondition -TimeoutSeconds 45 -Predicate {
                        $candidate = Get-ContainerWriterReadback $root
                        return (
                            [bool]$candidate.enabled -and [string]$candidate.state -ceq 'Ready' -and
                            [string]$candidate.identity.binding_sha256 -ceq [string]$pre.identity.binding_sha256
                        )
                    }
                }
                catch { $receipt.failure.emergency_restore_succeeded = $false }
                if ([bool]$receipt.failure.emergency_restore_succeeded -ne $true) {
                    $receipt.failure.safety_fence = Invoke-ContainerWriterSafetyFence $root ([string]$pre.identity.binding_sha256) 'EMERGENCY_RESTORE_FAILED'
                }
            }
        }
    }
    $receipt.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    $record = Write-JsonAtomic $outputFull $receipt -AllowReplace
    return [pscustomobject][ordered]@{ status = [string]$receipt.status; record = $record; payload = [pscustomobject]$receipt }
}

function Test-PreparedReceiptPayload {
    param(
        $Receipt,
        [string]$ExpectedPath,
        [string]$ExpectedSessionId,
        [string]$ExpectedAttemptId,
        [string]$ExpectedSessionStartedAtUtc,
        [string]$ExpectedOrchestratorSha256,
        [string]$ExpectedCapabilitySha256,
        [string]$ExpectedAdapterSha256
    )
    try {
        $top = @('schema','status','session_id','attempt_id','session_started_at_utc','orchestrator_sha256','adapter_sha256','evidence_path','started_at_utc','completed_at_utc','secret_values_recorded','historical_capability','pre_readback','disable','quiescence','failure')
        if (-not (Test-ExactPropertySet $Receipt $top)) { return $false }
        $sessionStart = ConvertTo-RoundTripUtc ([string]$Receipt.session_started_at_utc) 'receipt session start'
        $started = ConvertTo-RoundTripUtc ([string]$Receipt.started_at_utc) 'receipt start'
        $completed = ConvertTo-RoundTripUtc ([string]$Receipt.completed_at_utc) 'receipt completion'
        return (
            [string]$Receipt.schema -ceq $Script:PreparedSchema -and
            [string]$Receipt.status -ceq 'PREPARED_DISABLED' -and
            [string]$Receipt.session_id -ceq $ExpectedSessionId -and
            [string]$Receipt.attempt_id -ceq $ExpectedAttemptId -and
            [string]$Receipt.session_started_at_utc -ceq $ExpectedSessionStartedAtUtc -and
            [string]$Receipt.orchestrator_sha256 -ceq $ExpectedOrchestratorSha256 -and
            [string]$Receipt.adapter_sha256 -ceq $ExpectedAdapterSha256 -and
            (Test-BootstrapSamePath ([string]$Receipt.evidence_path) $ExpectedPath) -and
            $Receipt.secret_values_recorded -is [bool] -and -not [bool]$Receipt.secret_values_recorded -and
            $started -ge $sessionStart.AddSeconds(-2) -and $completed -ge $started -and
            $completed -le [DateTime]::UtcNow.AddSeconds(5) -and
            [string]$Receipt.historical_capability.schema -ceq $Script:HistoricalSchema -and
            [string]$Receipt.historical_capability.receipt_sha256 -ceq $ExpectedCapabilitySha256 -and
            [bool]$Receipt.historical_capability.eight_points_pass -and
            [string]$Receipt.historical_capability.capability_binding_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$Receipt.pre_readback.identity.status -ceq 'PASS' -and
            [string]$Receipt.pre_readback.identity.binding_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [bool]$Receipt.pre_readback.enabled -and [string]$Receipt.pre_readback.state -ceq 'Ready' -and
            [int64]$Receipt.pre_readback.last_task_result -eq 0 -and [int]$Receipt.pre_readback.exact_writer_process_count -eq 0 -and
            [string]$Receipt.disable.status -ceq 'COMMAND_SUCCEEDED' -and [bool]$Receipt.disable.binding_unchanged -and
            [string]$Receipt.quiescence.status -ceq 'PASS' -and
            [bool]$Receipt.quiescence.last_run_time_unchanged -and [bool]$Receipt.quiescence.log_unchanged -and
            [bool]$Receipt.quiescence.runtime_status_unchanged -and [int]$Receipt.quiescence.exact_writer_process_count -eq 0 -and
            $Receipt.failure.silently_ignored -is [bool] -and -not [bool]$Receipt.failure.silently_ignored
        )
    }
    catch { return $false }
}

function Test-ContainerPreparedReceipt {
    param(
        [string]$CanonicalInstallRoot,
        [string]$Path,
        [string]$ExpectedSha256,
        [string]$CurrentSessionId,
        [string]$CurrentAttemptId,
        [string]$CurrentSessionStartedAtUtc,
        [string]$CurrentOrchestratorSha256,
        [string]$CapabilitySha256,
        [switch]$RequireLiveDisabled
    )
    try {
        $receipt = Read-BoundedJson $Path 1048576 $ExpectedSha256
        $exact = Test-PreparedReceiptPayload $receipt (Get-StrictFullPath $Path 'prepared receipt path') $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $CapabilitySha256 $Script:AdapterSha256
        if (-not $exact -or -not $RequireLiveDisabled.IsPresent) { return [pscustomobject][ordered]@{ status = if ($exact) { 'PASS' } else { 'FAIL' }; payload = $receipt; live_disabled_exact = $null } }
        $live = Get-ContainerWriterReadback $CanonicalInstallRoot
        $effects = Get-ContainerWriterEffects
        $liveExact = (
            -not [bool]$live.enabled -and [string]$live.state -ceq 'Disabled' -and
            [string]$live.identity.binding_sha256 -ceq [string]$receipt.pre_readback.identity.binding_sha256 -and
            [string]$live.last_run_time_utc -ceq [string]$receipt.pre_readback.last_run_time_utc -and
            [int]$live.exact_writer_process_count -eq 0 -and
            (Test-FingerprintEqual $effects.log $receipt.quiescence.after_trigger.log) -and
            (Test-FingerprintEqual $effects.runtime_status $receipt.quiescence.after_trigger.runtime_status)
        )
        return [pscustomobject][ordered]@{ status = if ($liveExact) { 'PASS' } else { 'FAIL' }; payload = $receipt; live_disabled_exact = $liveExact }
    }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; payload = $null; live_disabled_exact = $false; failure_type = $_.Exception.GetType().Name } }
}

function Test-ReplacementReceiptShape($Receipt) {
    try {
        $top = @('schema_version','status','app_id','transaction_id','created_at','helper_sha256','integrity_helper_sha256','receipt_path','install_root','install_parent','rollback_root','failed_root','parent_acl','old','new','identity_or_credential_copied')
        $tree = @('file_count','aggregate_sha256','integrity_sha256','manifest_sha256','source_commit','source_tree','owner_sid','access_rules_protected','acl_sddl_sha256','reparse_count')
        $acl = @('owner_sid','access_rules_protected','sddl_sha256')
        if (-not (Test-ExactPropertySet $Receipt $top) -or -not (Test-ExactPropertySet $Receipt.old $tree) -or -not (Test-ExactPropertySet $Receipt.new $tree) -or -not (Test-ExactPropertySet $Receipt.parent_acl $acl)) { return $false }
        [void](ConvertTo-RoundTripUtc ([string]$Receipt.created_at) 'replacement receipt creation')
        return (
            [string]$Receipt.schema_version -ceq $Script:ReplacementSchema -and
            [string]$Receipt.status -ceq 'OLD_PRESERVED_NEW_VERIFIED' -and
            [string]$Receipt.app_id -ceq 'container_audit' -and
            [string]$Receipt.transaction_id -cmatch '^[0-9a-f]{32}$' -and
            [string]$Receipt.helper_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$Receipt.integrity_helper_sha256 -cmatch '^[0-9a-f]{64}$' -and
            $Receipt.identity_or_credential_copied -is [bool] -and -not [bool]$Receipt.identity_or_credential_copied -and
            [int]$Receipt.old.reparse_count -eq 0 -and [int]$Receipt.new.reparse_count -eq 0
        )
    }
    catch { return $false }
}

function Get-ContainerReplacementReceiptValidation {
    param(
        [string]$CanonicalInstallRoot,
        [string]$Path,
        [string]$ExpectedSha256,
        [string]$ExpectedTransactionId,
        [string]$ExpectedCommit,
        [string]$ExpectedAggregateSha256,
        [string]$CurrentHelperPath,
        [string]$CurrentHelperSha256
    )
    try {
        Assert-Hex $ExpectedTransactionId 32 'replacement transaction id'
        Assert-Hex $ExpectedSha256 64 'replacement receipt SHA-256'
        Assert-Hex $ExpectedCommit 40 'expected source commit'
        Assert-Hex $ExpectedAggregateSha256 64 'expected source aggregate SHA-256'
        Assert-Hex $CurrentHelperSha256 64 'expected helper SHA-256'
        $helperFull = Get-StrictFullPath $CurrentHelperPath 'Container helper path'
        if (-not (Test-Path -LiteralPath $helperFull -PathType Leaf) -or (Get-FileSha256 $helperFull) -cne $CurrentHelperSha256) { throw 'Container helper pin differs.' }
        $receiptFull = Get-StrictFullPath $Path 'replacement receipt path'
        $receipt = Read-BootstrapReplacementReceipt $receiptFull $ExpectedSha256
        if (-not (Test-ReplacementReceiptShape $receipt)) { throw 'Replacement receipt shape is invalid.' }
        $current = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
        $parent = Get-StrictFullPath (Split-Path -Parent $current) 'Container install parent'
        $rollback = Get-StrictFullPath ([string]$receipt.rollback_root) 'replacement rollback root'
        $failed = Get-StrictFullPath ([string]$receipt.failed_root) 'replacement failed root'
        $expectedIntegritySha = Get-FileSha256 $Script:IntegrityHelperPath
        if (
            [string]$receipt.transaction_id -cne $ExpectedTransactionId -or
            [string]$receipt.helper_sha256 -cne $CurrentHelperSha256 -or
            [string]$receipt.integrity_helper_sha256 -cne $expectedIntegritySha -or
            -not (Test-BootstrapSamePath ([string]$receipt.receipt_path) $receiptFull) -or
            -not (Test-BootstrapSamePath ([string]$receipt.install_root) $current) -or
            -not (Test-BootstrapSamePath ([string]$receipt.install_parent) $parent) -or
            -not (Test-BootstrapSamePath (Split-Path -Parent $rollback) $parent) -or
            -not (Test-BootstrapSamePath (Split-Path -Parent $failed) $parent) -or
            [IO.Path]::GetFileName($rollback) -cne ".current.rollback.$ExpectedTransactionId" -or
            [IO.Path]::GetFileName($failed) -cne ".current.failed.$ExpectedTransactionId" -or
            [string]$receipt.new.source_commit -cne $ExpectedCommit -or
            [string]$receipt.new.aggregate_sha256 -cne $ExpectedAggregateSha256
        ) { throw 'Replacement receipt semantic or path binding differs.' }
        Assert-BootstrapNoReparsePoint $parent 'replacement receipt parent'
        if (-not (Test-Path -LiteralPath $current -PathType Container) -or -not (Test-Path -LiteralPath $rollback -PathType Container) -or (Test-Path -LiteralPath $failed)) {
            throw 'Replacement receipt current/rollback/failed state is not pending exact restore.'
        }
        $currentIdentity = Get-BootstrapReplacementTreeIdentity $current $current
        $rollbackIdentity = Get-BootstrapReplacementTreeIdentity $rollback $current
        if (-not (Test-BootstrapReplacementTreeIdentity $receipt.new $currentIdentity) -or -not (Test-BootstrapReplacementTreeIdentity $receipt.old $rollbackIdentity)) {
            throw 'Replacement receipt tree identity readback differs.'
        }
        $parentAcl = Get-BootstrapAclIdentity $parent
        if (
            [string]$receipt.parent_acl.owner_sid -cne [string]$parentAcl.owner_sid -or
            [string]$receipt.parent_acl.access_rules_protected -cne [string]$parentAcl.access_rules_protected -or
            [string]$receipt.parent_acl.sddl_sha256 -cne [string]$parentAcl.sddl_sha256
        ) { throw 'Replacement receipt parent ACL readback differs.' }
        $siblings = @(Get-ChildItem -LiteralPath $parent -Directory -Force | Where-Object { $_.Name -match '^\.current\.(rollback|failed)\.' })
        if ($siblings.Count -ne 1 -or -not (Test-BootstrapSamePath $siblings[0].FullName $rollback)) {
            throw 'Replacement receipt sibling set is ambiguous.'
        }
        return [pscustomobject][ordered]@{ status = 'PASS'; reason = 'EXACT_APP_OWNED_CONTAINER_REPLACEMENT_RECEIPT'; payload = $receipt; receipt_path = $receiptFull; receipt_sha256 = $ExpectedSha256 }
    }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; reason = 'CONTAINER_REPLACEMENT_RECEIPT_INVALID'; payload = $null; failure_type = $_.Exception.GetType().Name } }
}

function Invoke-ContainerWriterRestore {
    param(
        [string]$CanonicalInstallRoot,
        [string]$OutputPath,
        [string]$CurrentSessionId,
        [string]$CurrentAttemptId,
        [string]$CurrentSessionStartedAtUtc,
        [string]$CurrentOrchestratorSha256,
        [string]$PreparedPath,
        [string]$PreparedSha256,
        [string]$CapabilitySha256
    )
    $outputFull = Get-StrictFullPath $OutputPath 'writer restore evidence path'
    if (Test-Path -LiteralPath $outputFull) { throw 'Writer restore evidence path already exists.' }
    $record = [ordered]@{
        schema = $Script:RestoredSchema
        status = 'IN_PROGRESS'
        session_id = $CurrentSessionId
        attempt_id = $CurrentAttemptId
        session_started_at_utc = $CurrentSessionStartedAtUtc
        orchestrator_sha256 = $CurrentOrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        evidence_path = $outputFull
        prepared_receipt = [ordered]@{ path = (Get-StrictFullPath $PreparedPath 'prepared receipt path'); sha256 = $PreparedSha256 }
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        completed_at_utc = ''
        secret_values_recorded = $false
        enable = [ordered]@{ status = 'NOT_RUN'; post_readback = $null; binding_unchanged = $false }
        survival = [ordered]@{ status = 'NOT_RUN'; nominal_next_run_utc = ''; observed_last_run_time_utc = ''; last_run_time_advanced = $false; last_task_result_zero = $false; binding_unchanged = $false; log_effect_observed = $false; runtime_status_effect_observed = $false; manual_start_used = $false }
        failure = [ordered]@{ status = 'NONE'; stage = ''; code = ''; failure_type = ''; silently_ignored = $false; safety_fence = $null }
    }
    [void](Write-JsonAtomic $outputFull $record)
    $stage = 'PREPARED_RECEIPT_VALIDATION'
    $prepared = $null
    $binding = ''
    try {
        $validation = Test-ContainerPreparedReceipt $CanonicalInstallRoot $PreparedPath $PreparedSha256 $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $CapabilitySha256 -RequireLiveDisabled
        if ([string]$validation.status -cne 'PASS' -or -not [bool]$validation.live_disabled_exact) { throw 'Prepared receipt or live-disabled readback is invalid.' }
        $prepared = $validation.payload
        $binding = [string]$prepared.pre_readback.identity.binding_sha256
        $stage = 'ENABLE'
        Enable-ScheduledTask -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop | Out-Null
        $futureReadback = $null
        $futureReady = Wait-ContainerCondition -TimeoutSeconds 90 -Predicate {
            $candidate = Get-ContainerWriterReadback $CanonicalInstallRoot
            if (
                -not [bool]$candidate.enabled -or [string]$candidate.state -cne 'Ready' -or
                [string]$candidate.identity.binding_sha256 -cne $binding
            ) { return $false }
            $next = ConvertTo-RoundTripUtc ([string]$candidate.next_run_time_utc) 'restored next run time'
            if ($next -gt [DateTime]::UtcNow.AddSeconds(5)) { $script:ContainerWriterFutureReadback = $candidate; return $true }
            return $false
        }
        if ($futureReady) { $futureReadback = $Script:ContainerWriterFutureReadback; $Script:ContainerWriterFutureReadback = $null }
        if (-not $futureReady -or $null -eq $futureReadback) { throw 'Restored Container writer did not expose a future natural trigger.' }
        $record.enable.status = 'COMMAND_SUCCEEDED'
        $record.enable.post_readback = $futureReadback
        $record.enable.binding_unchanged = ([string]$futureReadback.identity.binding_sha256 -ceq $binding)
        $nominal = ConvertTo-RoundTripUtc ([string]$futureReadback.next_run_time_utc) 'nominal next run time'
        $record.survival.nominal_next_run_utc = $nominal.ToString('o')
        $stage = 'NATURAL_TRIGGER_SURVIVAL'
        $deadline = $nominal.AddSeconds(45)
        $observed = $null
        $observedEffects = $null
        do {
            if ([DateTime]::UtcNow -ge $nominal) {
                $candidate = Get-ContainerWriterReadback $CanonicalInstallRoot
                if ((ConvertTo-RoundTripUtc ([string]$candidate.last_run_time_utc) 'observed last run') -ge $nominal -and [int64]$candidate.last_task_result -eq 0) {
                    $observed = $candidate
                    $observedEffects = Get-ContainerWriterEffects
                    break
                }
            }
            Start-Sleep -Milliseconds 1000
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $observed -or $null -eq $observedEffects) { throw 'Container writer natural trigger survival was not observed.' }
        $record.survival.observed_last_run_time_utc = [string]$observed.last_run_time_utc
        $record.survival.last_run_time_advanced = ((ConvertTo-RoundTripUtc ([string]$observed.last_run_time_utc) 'observed last run') -gt (ConvertTo-RoundTripUtc ([string]$prepared.pre_readback.last_run_time_utc) 'prepared last run'))
        $record.survival.last_task_result_zero = ([int64]$observed.last_task_result -eq 0)
        $record.survival.binding_unchanged = ([string]$observed.identity.binding_sha256 -ceq $binding)
        $record.survival.log_effect_observed = -not (Test-FingerprintEqual $observedEffects.log $prepared.quiescence.after_trigger.log)
        $record.survival.runtime_status_effect_observed = -not (Test-FingerprintEqual $observedEffects.runtime_status $prepared.quiescence.after_trigger.runtime_status)
        if (
            -not [bool]$record.survival.last_run_time_advanced -or -not [bool]$record.survival.last_task_result_zero -or
            -not [bool]$record.survival.binding_unchanged -or -not [bool]$record.survival.log_effect_observed -or
            -not [bool]$record.survival.runtime_status_effect_observed
        ) { throw 'Container writer restore survival effect is not exact.' }
        $record.survival.status = 'PASS'
        $record.status = 'PASS'
    }
    catch {
        $record.status = 'FAIL'
        $record.failure.status = 'FAIL'
        $record.failure.stage = $stage
        $record.failure.code = 'CONTAINER_WRITER_RESTORE_FAILED'
        $record.failure.failure_type = $_.Exception.GetType().Name
        if (-not [string]::IsNullOrWhiteSpace($binding)) {
            $record.failure.safety_fence = Invoke-ContainerWriterSafetyFence $CanonicalInstallRoot $binding 'RESTORE_FAILED_RETAIN_DISABLED'
        }
    }
    $record.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    $receiptRecord = Write-JsonAtomic $outputFull $record -AllowReplace
    return [pscustomobject][ordered]@{ status = [string]$record.status; record = $receiptRecord; payload = [pscustomobject]$record }
}

function Invoke-RecoveryStateMachine([scriptblock]$CodeRestoreAction, [scriptblock]$WriterRestoreAction) {
    try { $code = & $CodeRestoreAction }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'CODE_RESTORE_FAILED'; code_restore = [pscustomobject][ordered]@{ status = 'FAIL'; failure_type = $_.Exception.GetType().Name; silently_ignored = $false }; writer_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'CODE_RESTORE_NOT_PROVEN' } } }
    if ($null -eq $code -or [string]$code.status -cne 'PASS') {
        return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'CODE_RESTORE_FAILED'; code_restore = $code; writer_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'CODE_RESTORE_NOT_PROVEN' } }
    }
    try { $writer = & $WriterRestoreAction }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'WRITER_RESTORE_FAILED'; code_restore = $code; writer_restore = [pscustomobject][ordered]@{ status = 'FAIL'; failure_type = $_.Exception.GetType().Name; silently_ignored = $false } } }
    if ($null -eq $writer -or [string]$writer.status -cne 'PASS') {
        return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'WRITER_RESTORE_FAILED'; code_restore = $code; writer_restore = $writer }
    }
    return [pscustomobject][ordered]@{ status = 'PASS'; failure_code = ''; code_restore = $code; writer_restore = $writer }
}

function Test-RestoreEvidence([string]$Path, [string]$TransactionId, [string]$ReceiptPath, [string]$ReceiptSha256, [string]$CanonicalInstallRoot) {
    try {
        $evidence = Read-BoundedJson $Path 262144
        $exact = (
            [string]$evidence.schema_version -ceq 'container-audit-verified-replacement-code-restore-v1' -and
            [string]$evidence.status -ceq 'PASS' -and
            [string]$evidence.action -in @('RESTORED','ALREADY_RESTORED') -and
            [string]$evidence.app_id -ceq 'container_audit' -and
            [string]$evidence.transaction_id -ceq $TransactionId -and
            (Test-BootstrapSamePath ([string]$evidence.receipt_path) $ReceiptPath) -and
            [string]$evidence.receipt_sha256 -ceq $ReceiptSha256 -and
            (Test-BootstrapSamePath ([string]$evidence.install_root) $CanonicalInstallRoot) -and
            [bool]$evidence.prior_code_exact -and [bool]$evidence.failed_new_preserved -and
            $evidence.identity_or_credential_copied -is [bool] -and -not [bool]$evidence.identity_or_credential_copied
        )
        return [pscustomobject][ordered]@{ status = if ($exact) { 'PASS' } else { 'FAIL' }; path = (Get-StrictFullPath $Path 'restore evidence path'); sha256 = Get-FileSha256 $Path }
    }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; path = $Path; sha256 = ''; failure_type = $_.Exception.GetType().Name } }
}

function Invoke-ContainerRecovery {
    $combinedPath = Get-StrictFullPath $EvidencePath 'combined recovery evidence path'
    if (Test-Path -LiteralPath $combinedPath) { throw 'Combined recovery evidence path already exists.' }
    $combined = [ordered]@{
        schema = $Script:RecoverySchema
        status = 'IN_PROGRESS'
        failure_code = ''
        session_id = $SessionId
        attempt_id = $AttemptId
        session_started_at_utc = $SessionStartedAtUtc
        orchestrator_sha256 = $OrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        evidence_path = $combinedPath
        replacement_transaction_id = $ReplacementTransactionId
        prepared_receipt = [ordered]@{ path = (Get-StrictFullPath $PreparedReceiptPath 'prepared receipt path'); sha256 = $PreparedReceiptSha256 }
        replacement_receipt = [ordered]@{ path = (Get-StrictFullPath $ReplacementReceiptPath 'replacement receipt path'); sha256 = $ReplacementReceiptSha256 }
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        completed_at_utc = ''
        secret_values_recorded = $false
        code_restore = [ordered]@{ status = 'NOT_RUN' }
        writer_restore = [ordered]@{ status = 'NOT_RUN' }
        mutation_silently_ignored = $false
    }
    [void](Write-JsonAtomic $combinedPath $combined)
    $preparedValidation = Test-ContainerPreparedReceipt $InstallRoot $PreparedReceiptPath $PreparedReceiptSha256 $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $HistoricalReceiptSha256 -RequireLiveDisabled
    if ([string]$preparedValidation.status -cne 'PASS') {
        $combined.status = 'FAIL'; $combined.failure_code = 'PREPARED_RECEIPT_OR_LIVE_DISABLED_INVALID'; $combined.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        [void](Write-JsonAtomic $combinedPath $combined -AllowReplace)
        return [pscustomobject][ordered]@{ status = 'FAIL'; record = [pscustomobject][ordered]@{ path = $combinedPath; sha256 = Get-FileSha256 $combinedPath }; payload = [pscustomobject]$combined }
    }
    $replacementValidation = Get-ContainerReplacementReceiptValidation $InstallRoot $ReplacementReceiptPath $ReplacementReceiptSha256 $ReplacementTransactionId $ExpectedSourceCommit $ExpectedSourceAggregateSha256 $HelperPath $ExpectedHelperSha256
    if ([string]$replacementValidation.status -cne 'PASS') {
        $combined.status = 'FAIL'; $combined.failure_code = 'REPLACEMENT_RECEIPT_INVALID'; $combined.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        [void](Write-JsonAtomic $combinedPath $combined -AllowReplace)
        return [pscustomobject][ordered]@{ status = 'FAIL'; record = [pscustomobject][ordered]@{ path = $combinedPath; sha256 = Get-FileSha256 $combinedPath }; payload = [pscustomobject]$combined }
    }
    $flow = Invoke-RecoveryStateMachine -CodeRestoreAction {
        if (Test-Path -LiteralPath $RestoreEvidencePath) { throw 'Code restore evidence path already exists.' }
        $powerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        & $powerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $HelperPath `
            -InstallRoot $InstallRoot `
            -RestoreVerifiedReplacement `
            -ReplacementTransactionId $ReplacementTransactionId `
            -ReplacementReceiptPath $ReplacementReceiptPath `
            -ReplacementReceiptSha256 $ReplacementReceiptSha256 `
            -RestoreEvidencePath $RestoreEvidencePath | Out-Null
        $childExit = $LASTEXITCODE
        $evidence = Test-RestoreEvidence $RestoreEvidencePath $ReplacementTransactionId $ReplacementReceiptPath $ReplacementReceiptSha256 $InstallRoot
        return [pscustomobject][ordered]@{
            status = if ($childExit -eq 0 -and [string]$evidence.status -ceq 'PASS') { 'PASS' } else { 'FAIL' }
            child_exit_code = $childExit
            evidence = $evidence
            silently_ignored = $false
        }
    } -WriterRestoreAction {
        $restored = Invoke-ContainerWriterRestore $InstallRoot $WriterRestoreEvidencePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $PreparedReceiptPath $PreparedReceiptSha256 $HistoricalReceiptSha256
        return [pscustomobject][ordered]@{ status = [string]$restored.status; evidence = $restored.record; silently_ignored = $false }
    }
    $combined.status = [string]$flow.status
    $combined.failure_code = [string]$flow.failure_code
    $combined.code_restore = $flow.code_restore
    $combined.writer_restore = $flow.writer_restore
    $combined.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    $combinedRecord = Write-JsonAtomic $combinedPath $combined -AllowReplace
    return [pscustomobject][ordered]@{ status = [string]$combined.status; record = $combinedRecord; payload = [pscustomobject]$combined }
}

function Invoke-ContainerWriterSessionSelfTest {
    $session = '1' * 32
    $attempt = '2' * 32
    $orchestrator = '3' * 64
    $capability = '4' * 64
    $startedAt = [DateTime]::UtcNow.AddMinutes(-1).ToString('o')
    $receiptPath = 'E:\selftest\prepared.json'
    $payload = [pscustomobject][ordered]@{
        schema = $Script:PreparedSchema
        status = 'PREPARED_DISABLED'
        session_id = $session
        attempt_id = $attempt
        session_started_at_utc = $startedAt
        orchestrator_sha256 = $orchestrator
        adapter_sha256 = $Script:AdapterSha256
        evidence_path = $receiptPath
        started_at_utc = [DateTime]::UtcNow.AddSeconds(-30).ToString('o')
        completed_at_utc = [DateTime]::UtcNow.AddSeconds(-20).ToString('o')
        secret_values_recorded = $false
        historical_capability = [pscustomobject][ordered]@{ schema = $Script:HistoricalSchema; receipt_sha256 = $capability; eight_points_pass = $true; capability_binding_sha256 = '5' * 64 }
        pre_readback = [pscustomobject][ordered]@{ enabled = $true; state = 'Ready'; last_task_result = 0; exact_writer_process_count = 0; last_run_time_utc = [DateTime]::UtcNow.AddMinutes(-2).ToString('o'); identity = [pscustomobject][ordered]@{ status = 'PASS'; binding_sha256 = '6' * 64 } }
        disable = [pscustomobject][ordered]@{ status = 'COMMAND_SUCCEEDED'; binding_unchanged = $true }
        quiescence = [pscustomobject][ordered]@{ status = 'PASS'; last_run_time_unchanged = $true; log_unchanged = $true; runtime_status_unchanged = $true; exact_writer_process_count = 0 }
        failure = [pscustomobject][ordered]@{ silently_ignored = $false }
    }
    $validPrepared = Test-PreparedReceiptPayload $payload $receiptPath $session $attempt $startedAt $orchestrator $capability $Script:AdapterSha256
    $staleSessionRejected = -not (Test-PreparedReceiptPayload $payload $receiptPath ('7' * 32) $attempt $startedAt $orchestrator $capability $Script:AdapterSha256)
    $replacement = [pscustomobject][ordered]@{
        schema_version = $Script:ReplacementSchema; status = 'WRONG'; app_id = 'container_audit'; transaction_id = '8' * 32; created_at = [DateTime]::UtcNow.ToString('o'); helper_sha256 = '9' * 64; integrity_helper_sha256 = 'a' * 64; receipt_path = 'E:\r.json'; install_root = 'C:\KMTech\Apps\Container_Audit\current'; install_parent = 'C:\KMTech\Apps\Container_Audit'; rollback_root = 'C:\KMTech\Apps\Container_Audit\.current.rollback.' + ('8' * 32); failed_root = 'C:\KMTech\Apps\Container_Audit\.current.failed.' + ('8' * 32); parent_acl = [pscustomobject][ordered]@{ owner_sid = 'S-1-5-32-544'; access_rules_protected = $true; sddl_sha256 = 'b' * 64 }; old = [pscustomobject][ordered]@{ file_count = 1; aggregate_sha256 = 'c' * 64; integrity_sha256 = 'd' * 64; manifest_sha256 = 'e' * 64; source_commit = 'f' * 40; source_tree = '1' * 40; owner_sid = 'S-1-5-32-544'; access_rules_protected = $true; acl_sddl_sha256 = '2' * 64; reparse_count = 0 }; new = [pscustomobject][ordered]@{ file_count = 1; aggregate_sha256 = '3' * 64; integrity_sha256 = '4' * 64; manifest_sha256 = '5' * 64; source_commit = '6' * 40; source_tree = '7' * 40; owner_sid = 'S-1-5-32-544'; access_rules_protected = $true; acl_sddl_sha256 = '8' * 64; reparse_count = 0 }; identity_or_credential_copied = $false
    }
    $invalidReplacementRejected = -not (Test-ReplacementReceiptShape $replacement)
    $writerCalled = $false
    $codeFailure = Invoke-RecoveryStateMachine -CodeRestoreAction { throw 'injected' } -WriterRestoreAction { $script:writerCalled = $true; return [pscustomobject]@{ status = 'PASS' } }
    $codeFailureExplicit = ([string]$codeFailure.status -ceq 'FAIL' -and [string]$codeFailure.failure_code -ceq 'CODE_RESTORE_FAILED' -and [string]$codeFailure.writer_restore.status -ceq 'NOT_RUN' -and -not $writerCalled -and -not [bool]$codeFailure.code_restore.silently_ignored)
    $writerFailure = Invoke-RecoveryStateMachine -CodeRestoreAction { return [pscustomobject]@{ status = 'PASS' } } -WriterRestoreAction { return [pscustomobject]@{ status = 'FAIL'; silently_ignored = $false } }
    $writerFailureExplicit = ([string]$writerFailure.status -ceq 'FAIL' -and [string]$writerFailure.failure_code -ceq 'WRITER_RESTORE_FAILED' -and -not [bool]$writerFailure.writer_restore.silently_ignored)
    $checks = @(
        [pscustomobject][ordered]@{ name = 'valid_current_session_prepared_receipt'; status = if ($validPrepared) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'stale_session_rejected'; status = if ($staleSessionRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'invalid_replacement_receipt_rejected'; status = if ($invalidReplacementRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'code_restore_failure_explicit_and_writer_not_run'; status = if ($codeFailureExplicit) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'writer_restore_failure_explicit'; status = if ($writerFailureExplicit) { 'PASS' } else { 'FAIL' } }
    )
    $passed = @($checks | Where-Object status -cne 'PASS').Count -eq 0
    return [pscustomobject][ordered]@{ schema = 'container-audit-writer-session-self-test-v1'; status = if ($passed) { 'PASS' } else { 'FAIL' }; checks = $checks; system_mutation_attempted = $false; secret_values_recorded = $false }
}

if ($Mode -ceq 'SelfTest') {
    $result = Invoke-ContainerWriterSessionSelfTest
    $result | ConvertTo-Json -Depth 12 -Compress
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

Assert-Hex $SessionId 32 'session id'
Assert-Hex $AttemptId 32 'attempt id'
Assert-Hex $OrchestratorSha256 64 'orchestrator SHA-256'
[void](ConvertTo-RoundTripUtc $SessionStartedAtUtc 'session start')

if ($Mode -ceq 'Prepare') {
    $result = Invoke-ContainerWriterPrepare $InstallRoot $EvidencePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $HistoricalReceiptPath $HistoricalReceiptSha256 -RetainDisabled:$RetainDisabledOnFailure.IsPresent
    Write-Output "writer_session_status=$($result.status)"
    Write-Output "writer_session_receipt=$($result.record.path)"
    Write-Output "writer_session_receipt_sha256=$($result.record.sha256)"
    if ([string]$result.status -ceq 'PREPARED_DISABLED') { exit 0 }
    exit 20
}

if ($Mode -ceq 'ValidatePrepared') {
    $validation = Test-ContainerPreparedReceipt $InstallRoot $PreparedReceiptPath $PreparedReceiptSha256 $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $HistoricalReceiptSha256 -RequireLiveDisabled
    Write-Output "writer_session_validation_status=$($validation.status)"
    if ([string]$validation.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'ValidateReplacement') {
    $validation = Get-ContainerReplacementReceiptValidation $InstallRoot $ReplacementReceiptPath $ReplacementReceiptSha256 $ReplacementTransactionId $ExpectedSourceCommit $ExpectedSourceAggregateSha256 $HelperPath $ExpectedHelperSha256
    $result = [ordered]@{
        schema = 'container-audit-replacement-receipt-validation-v1'
        status = [string]$validation.status
        reason = [string]$validation.reason
        session_id = $SessionId
        attempt_id = $AttemptId
        session_started_at_utc = $SessionStartedAtUtc
        orchestrator_sha256 = $OrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        replacement_transaction_id = $ReplacementTransactionId
        replacement_receipt_sha256 = $ReplacementReceiptSha256
        secret_values_recorded = $false
        validated_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    $record = Write-JsonAtomic $EvidencePath $result
    Write-Output "replacement_receipt_validation_status=$($result.status)"
    Write-Output "replacement_receipt_validation_evidence=$($record.path)"
    Write-Output "replacement_receipt_validation_evidence_sha256=$($record.sha256)"
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'RestoreWriter') {
    $result = Invoke-ContainerWriterRestore $InstallRoot $EvidencePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $PreparedReceiptPath $PreparedReceiptSha256 $HistoricalReceiptSha256
    Write-Output "writer_restore_status=$($result.status)"
    Write-Output "writer_restore_receipt=$($result.record.path)"
    Write-Output "writer_restore_receipt_sha256=$($result.record.sha256)"
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'Recover') {
    $result = Invoke-ContainerRecovery
    Write-Output "container_recovery_status=$($result.status)"
    Write-Output "container_recovery_receipt=$($result.record.path)"
    Write-Output "container_recovery_receipt_sha256=$($result.record.sha256)"
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

throw 'Unsupported Container writer session mode.'
