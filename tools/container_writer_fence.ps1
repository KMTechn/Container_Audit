Set-StrictMode -Version Latest

$Script:ContainerWriterFenceActiveSchema = 'container-audit-all-writer-fence-active-v1'
$Script:ContainerWriterFenceReleaseSchema = 'container-audit-all-writer-fence-release-v1'
$Script:ContainerWriterFenceAppId = 'container_audit'
$Script:ContainerWriterFenceTupleVersion = 'container-audit-deployment-session-authority-v1'
$Script:ContainerWriterFenceSessionMutexPrefix = 'Local\KMTech.ContainerAudit.DeploymentSession.'
$Script:ContainerWriterFenceAdmissionMutexName = 'Local\KMTech.ContainerAudit.WriterAdmission.v1'
$Script:ContainerWriterFenceInventorySha256 = 'd4708bcaae436cbba313b9c6809b0ea2c8ffc7f2ee6637063720c4d2a2db3062'
$Script:ContainerWriterFenceMaximumBytes = 262144
$Script:ContainerWriterFenceActiveFields = @(
    'schema','status','app_id','session_id','attempt_id','replacement_transaction_id',
    'session_started_at_utc','orchestrator_sha256','writer_contract_sha256',
    'session_authority_mutex_name','writer_inventory_sha256','owner_kind',
    'prepared_receipt_path','prepared_receipt_sha256','delegation_sha256',
    'delegated_sources','delegation_expires_at_utc','activated_at_utc',
    'secret_values_recorded'
)
$Script:ContainerWriterFenceReleaseFields = @(
    'schema','status','app_id','session_id','attempt_id','replacement_transaction_id',
    'writer_inventory_sha256','release_authorization_path',
    'release_authorization_sha256','released_at_utc','secret_values_recorded'
)

function Get-ContainerWriterFenceStringSha256([string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Value)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function Get-ContainerWriterFenceFileSha256([string]$PathValue, [int64]$MaximumBytes = 4194304) {
    $full = [IO.Path]::GetFullPath($PathValue)
    Assert-ContainerWriterFenceNoReparse $full
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'CONTAINER_WRITER_FENCE_AUTHORIZATION_ABSENT'
    }
    $stream = New-Object IO.FileStream($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw 'CONTAINER_WRITER_FENCE_AUTHORIZATION_SIZE_INVALID'
        }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Get-ContainerWriterSessionAuthorityMutexName(
    [string]$SessionId,
    [string]$AttemptId,
    [string]$OrchestratorSha256,
    [string]$ReplacementTransactionId,
    [string]$WriterContractSha256
) {
    $tuple = (@(
        $Script:ContainerWriterFenceTupleVersion,
        $SessionId,
        $AttemptId,
        $OrchestratorSha256,
        $ReplacementTransactionId,
        $WriterContractSha256
    ) | ForEach-Object { ([string]$_).Normalize([Text.NormalizationForm]::FormC) }) -join "`n"
    return $Script:ContainerWriterFenceSessionMutexPrefix + (Get-ContainerWriterFenceStringSha256 $tuple)
}

function Get-ContainerWriterFenceControlRoot {
    param([string]$ControlRoot = '')
    if (-not [string]::IsNullOrWhiteSpace($ControlRoot)) {
        return [IO.Path]::GetFullPath($ControlRoot)
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'CONTAINER_WRITER_FENCE_LOCALAPPDATA_UNAVAILABLE'
    }
    return Join-Path ([IO.Path]::GetFullPath($env:LOCALAPPDATA)) 'KMTech\DirectSync\container_audit\control\writer-session'
}

function Get-ContainerWriterFenceNormalizedRoot([string]$ControlRoot) {
    $normalized = [IO.Path]::GetFullPath($ControlRoot).TrimEnd('\').Normalize([Text.NormalizationForm]::FormC)
    return -join @($normalized.ToCharArray() | ForEach-Object {
        $code = [int][char]$_
        if ($code -ge 65 -and $code -le 90) { [char]($code + 32) } else { $_ }
    })
}

function Get-ContainerWriterAdmissionMutexName {
    param([string]$ControlRoot = '')
    $selected = Get-ContainerWriterFenceNormalizedRoot (Get-ContainerWriterFenceControlRoot $ControlRoot)
    $production = ''
    try { $production = Get-ContainerWriterFenceNormalizedRoot (Get-ContainerWriterFenceControlRoot) } catch { }
    if (-not [string]::IsNullOrWhiteSpace($production) -and $selected -ceq $production) {
        return $Script:ContainerWriterFenceAdmissionMutexName
    }
    return $Script:ContainerWriterFenceAdmissionMutexName + '.' + (Get-ContainerWriterFenceStringSha256 $selected).Substring(0, 16)
}

function Test-ContainerWriterFenceExactPropertySet($Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) { return $false }
    }
    return $true
}

function Test-ContainerWriterFenceHex([string]$Value, [int]$Length) {
    return $Value -cmatch ('\A[0-9a-f]{' + $Length.ToString([Globalization.CultureInfo]::InvariantCulture) + '}\z')
}

function ConvertTo-ContainerWriterFenceUtc([string]$Value) {
    if ($Value -cnotmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z') {
        throw 'CONTAINER_WRITER_FENCE_TIMESTAMP_INVALID'
    }
    try {
        return [DateTimeOffset]::Parse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).UtcDateTime
    }
    catch { throw 'CONTAINER_WRITER_FENCE_TIMESTAMP_INVALID' }
}

function Assert-ContainerWriterFenceNoReparse([string]$PathValue) {
    $full = [IO.Path]::GetFullPath($PathValue)
    $root = [IO.Path]::GetPathRoot($full)
    $relative = $full.Substring($root.Length)
    $current = $root
    foreach ($part in @($relative -split '[\\/]' | Where-Object { $_ })) {
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'CONTAINER_WRITER_FENCE_REPARSE_REJECTED'
            }
        }
    }
}

function Enter-ContainerWriterAdmission {
    param([string]$ControlRoot = '', [int]$TimeoutMilliseconds = 5000)
    $name = Get-ContainerWriterAdmissionMutexName $ControlRoot
    $created = $false
    $mutex = New-Object Threading.Mutex($false, $name, [ref]$created)
    try {
        try { $acquired = $mutex.WaitOne([Math]::Max(0, $TimeoutMilliseconds)) }
        catch [Threading.AbandonedMutexException] {
            try { $mutex.ReleaseMutex() } catch { }
            throw 'CONTAINER_WRITER_ADMISSION_MUTEX_ABANDONED'
        }
        if (-not $acquired) { throw 'CONTAINER_WRITER_ADMISSION_MUTEX_TIMEOUT' }
        return [pscustomobject][ordered]@{ mutex = $mutex; name = $name; acquired = $true }
    }
    catch {
        $mutex.Dispose()
        throw
    }
}

function Exit-ContainerWriterAdmission($Lease) {
    if ($null -eq $Lease) { return }
    try {
        if ($Lease.acquired -isnot [bool] -or -not [bool]$Lease.acquired) {
            throw 'CONTAINER_WRITER_ADMISSION_LEASE_INVALID'
        }
        $Lease.mutex.ReleaseMutex()
    }
    finally { $Lease.mutex.Dispose() }
}

function Test-ContainerWriterSessionAuthorityHeldByOther([string]$Name) {
    $mutex = $null
    try {
        $mutex = [Threading.Mutex]::OpenExisting($Name)
        try { $acquired = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { return $false }
        if ($acquired) {
            $mutex.ReleaseMutex()
            return $false
        }
        return $true
    }
    catch { return $false }
    finally { if ($null -ne $mutex) { $mutex.Dispose() } }
}

function Assert-ContainerWriterSessionAuthority {
    param($ActiveFence, $AuthorityLease = $null)
    $expectedName = [string]$ActiveFence.session_authority_mutex_name
    if ($null -ne $AuthorityLease) {
        if (
            $AuthorityLease.acquired -isnot [bool] -or
            -not [bool]$AuthorityLease.acquired -or
            [string]$AuthorityLease.name -cne $expectedName -or
            $AuthorityLease.mutex -isnot [Threading.Mutex]
        ) { throw 'CONTAINER_WRITER_FENCE_CALLER_AUTHORITY_INVALID' }
        try { $owned = $AuthorityLease.mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { throw 'CONTAINER_WRITER_FENCE_CALLER_AUTHORITY_ABANDONED' }
        if (-not $owned) { throw 'CONTAINER_WRITER_FENCE_CALLER_AUTHORITY_NOT_OWNED' }
        $AuthorityLease.mutex.ReleaseMutex()
        return
    }
    if (-not (Test-ContainerWriterSessionAuthorityHeldByOther $expectedName)) {
        throw 'CONTAINER_WRITER_FENCE_SESSION_AUTHORITY_NOT_HELD'
    }
}

function Enter-ContainerWriterSessionAuthority {
    param(
        [string]$SessionId,
        [string]$AttemptId,
        [string]$OrchestratorSha256,
        [string]$ReplacementTransactionId,
        [string]$WriterContractSha256
    )
    $name = Get-ContainerWriterSessionAuthorityMutexName $SessionId $AttemptId $OrchestratorSha256 $ReplacementTransactionId $WriterContractSha256
    $created = $false
    $mutex = New-Object Threading.Mutex($true, $name, [ref]$created)
    if (-not $created) {
        $mutex.Dispose()
        throw 'CONTAINER_WRITER_SESSION_AUTHORITY_ALREADY_EXISTS'
    }
    return [pscustomobject][ordered]@{ mutex = $mutex; name = $name; acquired = $true }
}

function Exit-ContainerWriterSessionAuthority($Lease) {
    if ($null -eq $Lease) { return }
    try { $Lease.mutex.ReleaseMutex() }
    finally { $Lease.mutex.Dispose() }
}

function Get-ContainerWriterFenceActivePath([string]$ControlRoot = '') {
    return Join-Path (Get-ContainerWriterFenceControlRoot $ControlRoot) 'active.json'
}

function Assert-ContainerWriterFencePayload($Payload) {
    if (-not (Test-ContainerWriterFenceExactPropertySet $Payload $Script:ContainerWriterFenceActiveFields)) {
        throw 'CONTAINER_WRITER_FENCE_BINDING_INVALID'
    }
    $sources = @($Payload.delegated_sources)
    $status = [string]$Payload.status
    if (
        $Payload.schema -isnot [string] -or
        $Payload.status -isnot [string] -or
        $Payload.app_id -isnot [string] -or
        $Payload.session_id -isnot [string] -or
        $Payload.attempt_id -isnot [string] -or
        $Payload.replacement_transaction_id -isnot [string] -or
        $Payload.session_started_at_utc -isnot [string] -or
        $Payload.orchestrator_sha256 -isnot [string] -or
        $Payload.writer_contract_sha256 -isnot [string] -or
        $Payload.session_authority_mutex_name -isnot [string] -or
        $Payload.writer_inventory_sha256 -isnot [string] -or
        $Payload.owner_kind -isnot [string] -or
        $Payload.prepared_receipt_path -isnot [string] -or
        $Payload.prepared_receipt_sha256 -isnot [string] -or
        $Payload.delegation_sha256 -isnot [string] -or
        $Payload.delegation_expires_at_utc -isnot [string] -or
        $Payload.activated_at_utc -isnot [string] -or
        [string]$Payload.schema -cne $Script:ContainerWriterFenceActiveSchema -or
        [string]$Payload.app_id -cne $Script:ContainerWriterFenceAppId -or
        $status -cnotin @('PREPARING','PREPARED','RESTORING','RESTORE_FAILED','INSTALLING') -or
        [string]$Payload.owner_kind -cnotin @('session_adapter','canonical_installer') -or
        -not (Test-ContainerWriterFenceHex ([string]$Payload.session_id) 32) -or
        -not (Test-ContainerWriterFenceHex ([string]$Payload.attempt_id) 32) -or
        -not (Test-ContainerWriterFenceHex ([string]$Payload.replacement_transaction_id) 32) -or
        -not (Test-ContainerWriterFenceHex ([string]$Payload.orchestrator_sha256) 64) -or
        -not (Test-ContainerWriterFenceHex ([string]$Payload.writer_contract_sha256) 64) -or
        [string]$Payload.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        $Payload.secret_values_recorded -isnot [bool] -or [bool]$Payload.secret_values_recorded -or
        $Payload.delegated_sources -isnot [Object[]] -or
        @($Payload.delegated_sources | Where-Object { $_ -isnot [string] }).Count -ne 0
    ) { throw 'CONTAINER_WRITER_FENCE_BINDING_INVALID' }
    [void](ConvertTo-ContainerWriterFenceUtc ([string]$Payload.session_started_at_utc))
    [void](ConvertTo-ContainerWriterFenceUtc ([string]$Payload.activated_at_utc))
    $expectedName = Get-ContainerWriterSessionAuthorityMutexName ([string]$Payload.session_id) ([string]$Payload.attempt_id) ([string]$Payload.orchestrator_sha256) ([string]$Payload.replacement_transaction_id) ([string]$Payload.writer_contract_sha256)
    if ([string]$Payload.session_authority_mutex_name -cne $expectedName) {
        throw 'CONTAINER_WRITER_FENCE_AUTHORITY_NAME_INVALID'
    }
    $sorted = @($sources | Sort-Object -Unique)
    if ($sorted.Count -ne $sources.Count) { throw 'CONTAINER_WRITER_FENCE_DELEGATION_INVALID' }
    for ($index = 0; $index -lt $sources.Count; $index++) {
        if ([string]::IsNullOrWhiteSpace([string]$sources[$index]) -or [string]$sources[$index] -cne [string]$sorted[$index]) {
            throw 'CONTAINER_WRITER_FENCE_DELEGATION_INVALID'
        }
    }
    $receiptBoundStatuses = @('PREPARING','PREPARED','RESTORING','RESTORE_FAILED','INSTALLING')
    if ($sources.Count -gt 0 -and $status -cnotin @('PREPARED','RESTORING','RESTORE_FAILED','INSTALLING')) {
        throw 'CONTAINER_WRITER_FENCE_DELEGATION_INVALID'
    }
    if ($status -cin $receiptBoundStatuses -or $sources.Count -gt 0) {
        if ([string]::IsNullOrWhiteSpace([string]$Payload.prepared_receipt_path) -or -not (Test-ContainerWriterFenceHex ([string]$Payload.prepared_receipt_sha256) 64)) {
            throw 'CONTAINER_WRITER_FENCE_PREPARED_BINDING_INVALID'
        }
        $preparedFull = [IO.Path]::GetFullPath([string]$Payload.prepared_receipt_path)
        Assert-ContainerWriterFenceNoReparse $preparedFull
        if (
            -not (Test-Path -LiteralPath $preparedFull -PathType Leaf) -or
            (Get-ContainerWriterFenceFileSha256 $preparedFull) -cne [string]$Payload.prepared_receipt_sha256
        ) { throw 'CONTAINER_WRITER_FENCE_PREPARED_RECEIPT_MISMATCH' }
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Payload.prepared_receipt_sha256) -and -not (Test-ContainerWriterFenceHex ([string]$Payload.prepared_receipt_sha256) 64)) {
        throw 'CONTAINER_WRITER_FENCE_PREPARED_BINDING_INVALID'
    }
    if ($sources.Count -eq 0) {
        if (-not [string]::IsNullOrEmpty([string]$Payload.delegation_sha256) -or -not [string]::IsNullOrEmpty([string]$Payload.delegation_expires_at_utc)) {
            throw 'CONTAINER_WRITER_FENCE_DELEGATION_INVALID'
        }
    }
    else {
        if (-not (Test-ContainerWriterFenceHex ([string]$Payload.delegation_sha256) 64)) { throw 'CONTAINER_WRITER_FENCE_DELEGATION_INVALID' }
        [void](ConvertTo-ContainerWriterFenceUtc ([string]$Payload.delegation_expires_at_utc))
    }
    return $Payload
}

function Read-ContainerWriterFence {
    param([string]$ControlRoot = '', [switch]$AllowAbsent)
    $root = Get-ContainerWriterFenceControlRoot $ControlRoot
    Assert-ContainerWriterFenceNoReparse $root
    $path = Get-ContainerWriterFenceActivePath $root
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        if ($AllowAbsent.IsPresent) { return $null }
        throw 'CONTAINER_WRITER_FENCE_ABSENT'
    }
    Assert-ContainerWriterFenceNoReparse $path
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.Length -le 0 -or $item.Length -gt $Script:ContainerWriterFenceMaximumBytes) {
        throw 'CONTAINER_WRITER_FENCE_SIZE_INVALID'
    }
    $beforeLength = [int64]$item.Length
    $beforeMtime = $item.LastWriteTimeUtc.Ticks
    $payload = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $after = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ([int64]$after.Length -ne $beforeLength -or $after.LastWriteTimeUtc.Ticks -ne $beforeMtime) {
        throw 'CONTAINER_WRITER_FENCE_CHANGED_DURING_READ'
    }
    return Assert-ContainerWriterFencePayload $payload
}

function Read-ContainerWriterFenceReleaseReceipt([string]$PathValue) {
    $path = [IO.Path]::GetFullPath($PathValue)
    Assert-ContainerWriterFenceNoReparse $path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_ABSENT'
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.Length -le 0 -or $item.Length -gt $Script:ContainerWriterFenceMaximumBytes) {
        throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_SIZE_INVALID'
    }
    $beforeLength = [int64]$item.Length
    $beforeMtime = $item.LastWriteTimeUtc.Ticks
    try {
        $payload = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch { throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_JSON_INVALID' }
    $after = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ([int64]$after.Length -ne $beforeLength -or $after.LastWriteTimeUtc.Ticks -ne $beforeMtime) {
        throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_CHANGED_DURING_READ'
    }
    if (
        -not (Test-ContainerWriterFenceExactPropertySet $payload $Script:ContainerWriterFenceReleaseFields) -or
        $payload.schema -isnot [string] -or
        $payload.status -isnot [string] -or
        $payload.app_id -isnot [string] -or
        $payload.session_id -isnot [string] -or
        $payload.attempt_id -isnot [string] -or
        $payload.replacement_transaction_id -isnot [string] -or
        $payload.writer_inventory_sha256 -isnot [string] -or
        $payload.release_authorization_path -isnot [string] -or
        $payload.release_authorization_sha256 -isnot [string] -or
        $payload.released_at_utc -isnot [string] -or
        [string]$payload.schema -cne $Script:ContainerWriterFenceReleaseSchema -or
        [string]$payload.status -cne 'RELEASED' -or
        [string]$payload.app_id -cne $Script:ContainerWriterFenceAppId -or
        -not (Test-ContainerWriterFenceHex ([string]$payload.session_id) 32) -or
        -not (Test-ContainerWriterFenceHex ([string]$payload.attempt_id) 32) -or
        -not (Test-ContainerWriterFenceHex ([string]$payload.replacement_transaction_id) 32) -or
        [string]$payload.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        [string]::IsNullOrWhiteSpace([string]$payload.release_authorization_path) -or
        -not (Test-ContainerWriterFenceHex ([string]$payload.release_authorization_sha256) 64) -or
        $payload.secret_values_recorded -isnot [bool] -or
        [bool]$payload.secret_values_recorded
    ) { throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_INVALID' }
    try {
        [void](ConvertTo-ContainerWriterFenceUtc ([string]$payload.released_at_utc))
        $authorizationFull = [IO.Path]::GetFullPath([string]$payload.release_authorization_path)
    }
    catch { throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_INVALID' }
    if ([string]$payload.release_authorization_path -cne $authorizationFull) {
        throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_INVALID'
    }
    return $payload
}

function Assert-ContainerWriterFenceReleaseReceiptMatches {
    param(
        $Receipt,
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$ReleaseAuthorizationPath,
        [string]$ReleaseAuthorizationSha256
    )
    if (
        [string]$Receipt.session_id -cne $SessionId -or
        [string]$Receipt.attempt_id -cne $AttemptId -or
        [string]$Receipt.replacement_transaction_id -cne $ReplacementTransactionId -or
        [string]$Receipt.release_authorization_path -cne [IO.Path]::GetFullPath($ReleaseAuthorizationPath) -or
        [string]$Receipt.release_authorization_sha256 -cne $ReleaseAuthorizationSha256
    ) { throw 'CONTAINER_WRITER_FENCE_RELEASE_RECEIPT_MISMATCH' }
    return $Receipt
}

function Write-ContainerWriterFenceAtomic([string]$ControlRoot, $Payload) {
    [void](Assert-ContainerWriterFencePayload $Payload)
    $root = Get-ContainerWriterFenceControlRoot $ControlRoot
    Assert-ContainerWriterFenceNoReparse $root
    [void](New-Item -ItemType Directory -Path $root -Force)
    Assert-ContainerWriterFenceNoReparse $root
    $path = Get-ContainerWriterFenceActivePath $root
    $temporary = Join-Path $root ('.active.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = Join-Path $root ('.active.' + [Guid]::NewGuid().ToString('N') + '.bak')
    try {
        $json = ($Payload | ConvertTo-Json -Depth 20) + "`n"
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [IO.File]::Replace($temporary, $path, $backup)
        }
        else { [IO.File]::Move($temporary, $path) }
    }
    finally {
        foreach ($cleanupPath in @($temporary, $backup)) {
            if (Test-Path -LiteralPath $cleanupPath) { Remove-Item -LiteralPath $cleanupPath -Force }
        }
    }
    $readback = Read-ContainerWriterFence $root
    if (($readback | ConvertTo-Json -Depth 20 -Compress) -cne ($Payload | ConvertTo-Json -Depth 20 -Compress)) {
        throw 'CONTAINER_WRITER_FENCE_WRITE_READBACK_FAILED'
    }
    return $readback
}

function New-ContainerWriterFencePayload {
    param(
        [string]$Status,
        [string]$OwnerKind,
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$SessionStartedAtUtc,
        [string]$OrchestratorSha256,
        [string]$WriterContractSha256,
        [string]$PreparedReceiptPath,
        [string]$PreparedReceiptSha256 = '',
        [string]$DelegationToken = '',
        [string[]]$DelegatedSources = @(),
        [string]$DelegationExpiresAtUtc = ''
    )
    $sources = @($DelegatedSources | Sort-Object -Unique)
    return [pscustomobject][ordered]@{
        schema = $Script:ContainerWriterFenceActiveSchema
        status = $Status
        app_id = $Script:ContainerWriterFenceAppId
        session_id = $SessionId
        attempt_id = $AttemptId
        replacement_transaction_id = $ReplacementTransactionId
        session_started_at_utc = $SessionStartedAtUtc
        orchestrator_sha256 = $OrchestratorSha256
        writer_contract_sha256 = $WriterContractSha256
        session_authority_mutex_name = Get-ContainerWriterSessionAuthorityMutexName $SessionId $AttemptId $OrchestratorSha256 $ReplacementTransactionId $WriterContractSha256
        writer_inventory_sha256 = $Script:ContainerWriterFenceInventorySha256
        owner_kind = $OwnerKind
        prepared_receipt_path = $PreparedReceiptPath
        prepared_receipt_sha256 = $PreparedReceiptSha256
        delegation_sha256 = if ([string]::IsNullOrEmpty($DelegationToken)) { '' } else { Get-ContainerWriterFenceStringSha256 $DelegationToken }
        delegated_sources = [Object[]]$sources
        delegation_expires_at_utc = $DelegationExpiresAtUtc
        activated_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_values_recorded = $false
    }
}

function Start-ContainerWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$Status,
        [string]$OwnerKind,
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$SessionStartedAtUtc,
        [string]$OrchestratorSha256,
        [string]$WriterContractSha256,
        [string]$PreparedReceiptPath,
        [string]$PreparedReceiptSha256 = '',
        [string]$DelegationToken = '',
        [string[]]$DelegatedSources = @(),
        [string]$DelegationExpiresAtUtc = '',
        $AuthorityLease = $null
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        if ($null -ne (Read-ContainerWriterFence $ControlRoot -AllowAbsent)) {
            throw 'CONTAINER_WRITER_FENCE_ALREADY_ACTIVE'
        }
        $payload = New-ContainerWriterFencePayload `
            -Status $Status `
            -OwnerKind $OwnerKind `
            -SessionId $SessionId `
            -AttemptId $AttemptId `
            -ReplacementTransactionId $ReplacementTransactionId `
            -SessionStartedAtUtc $SessionStartedAtUtc `
            -OrchestratorSha256 $OrchestratorSha256 `
            -WriterContractSha256 $WriterContractSha256 `
            -PreparedReceiptPath $PreparedReceiptPath `
            -PreparedReceiptSha256 $PreparedReceiptSha256 `
            -DelegationToken $DelegationToken `
            -DelegatedSources $DelegatedSources `
            -DelegationExpiresAtUtc $DelegationExpiresAtUtc
        Assert-ContainerWriterSessionAuthority $payload $AuthorityLease
        return Write-ContainerWriterFenceAtomic $ControlRoot $payload
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Set-ContainerWriterFencePrepared {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$PreparedReceiptPath,
        [string]$PreparedReceiptSha256,
        [string]$Status = 'PREPARED',
        $AuthorityLease = $null
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $active = Read-ContainerWriterFence $ControlRoot
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId -or
            -not (Test-ContainerWriterFenceHex $PreparedReceiptSha256 64)
        ) { throw 'CONTAINER_WRITER_FENCE_PREPARED_SESSION_MISMATCH' }
        $active.status = $Status
        $active.prepared_receipt_path = [IO.Path]::GetFullPath($PreparedReceiptPath)
        $active.prepared_receipt_sha256 = $PreparedReceiptSha256
        return Write-ContainerWriterFenceAtomic $ControlRoot $active
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Set-ContainerWriterFenceDelegation {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken,
        [string[]]$DelegatedSources,
        [int]$LifetimeSeconds = 120,
        $AuthorityLease = $null
    )
    if ($DelegationToken.Length -lt 32) { throw 'CONTAINER_WRITER_FENCE_DELEGATION_TOKEN_INVALID' }
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $active = Read-ContainerWriterFence $ControlRoot
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId -or
            [string]$active.status -cnotin @('PREPARED','RESTORING','INSTALLING')
        ) { throw 'CONTAINER_WRITER_FENCE_DELEGATION_SESSION_MISMATCH' }
        $active.status = if ([string]$active.status -ceq 'INSTALLING') { 'INSTALLING' } else { 'RESTORING' }
        $active.delegation_sha256 = Get-ContainerWriterFenceStringSha256 $DelegationToken
        $active.delegated_sources = [Object[]]@($DelegatedSources | Sort-Object -Unique)
        $active.delegation_expires_at_utc = [DateTime]::UtcNow.AddSeconds([Math]::Max(15, [Math]::Min(300, $LifetimeSeconds))).ToString('o')
        return Write-ContainerWriterFenceAtomic $ControlRoot $active
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Clear-ContainerWriterFenceDelegation {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken,
        $AuthorityLease = $null
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $active = Read-ContainerWriterFence $ControlRoot
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId -or
            [string]$active.delegation_sha256 -cne (Get-ContainerWriterFenceStringSha256 $DelegationToken)
        ) { throw 'CONTAINER_WRITER_FENCE_DELEGATION_CLEAR_MISMATCH' }
        $active.delegation_sha256 = ''
        $active.delegated_sources = [Object[]]@()
        $active.delegation_expires_at_utc = ''
        return Write-ContainerWriterFenceAtomic $ControlRoot $active
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Assert-ContainerWriterFenceOwner {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $active = Read-ContainerWriterFence $ControlRoot
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId
        ) { throw 'CONTAINER_WRITER_FENCE_OWNER_MISMATCH' }
        if (-not [string]::IsNullOrEmpty($DelegationToken) -and [string]$active.delegation_sha256 -cne (Get-ContainerWriterFenceStringSha256 $DelegationToken)) {
            throw 'CONTAINER_WRITER_FENCE_OWNER_DELEGATION_MISMATCH'
        }
        return $active
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Invoke-ContainerWriterFenceMutation {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $root = Get-ContainerWriterFenceControlRoot $ControlRoot
        $activePath = Get-ContainerWriterFenceActivePath $root
        $active = Read-ContainerWriterFence $root
        $activeSha256 = Get-ContainerWriterFenceFileSha256 $activePath
        $preparedReceiptPath = [IO.Path]::GetFullPath([string]$active.prepared_receipt_path)
        $preparedReceiptSha256 = [string]$active.prepared_receipt_sha256
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId
        ) { throw 'CONTAINER_WRITER_FENCE_OWNER_MISMATCH' }
        if (
            [string]$active.status -cnotin @('PREPARING','PREPARED','RESTORING','RESTORE_FAILED','INSTALLING') -or
            -not (Test-ContainerWriterFenceHex $preparedReceiptSha256 64) -or
            (Get-ContainerWriterFenceFileSha256 $preparedReceiptPath) -cne $preparedReceiptSha256
        ) { throw 'CONTAINER_WRITER_FENCE_PREPARED_BINDING_MISMATCH' }
        if (
            -not [string]::IsNullOrEmpty($DelegationToken) -and
            [string]$active.delegation_sha256 -cne (Get-ContainerWriterFenceStringSha256 $DelegationToken)
        ) { throw 'CONTAINER_WRITER_FENCE_OWNER_DELEGATION_MISMATCH' }
        $result = & $Action
        $after = Read-ContainerWriterFence $root
        Assert-ContainerWriterSessionAuthority $after $AuthorityLease
        if (
            (Get-ContainerWriterFenceFileSha256 $activePath) -cne $activeSha256 -or
            [string]$after.session_id -cne $SessionId -or
            [string]$after.attempt_id -cne $AttemptId -or
            [string]$after.replacement_transaction_id -cne $ReplacementTransactionId -or
            [IO.Path]::GetFullPath([string]$after.prepared_receipt_path) -cne $preparedReceiptPath -or
            [string]$after.prepared_receipt_sha256 -cne $preparedReceiptSha256 -or
            (Get-ContainerWriterFenceFileSha256 $preparedReceiptPath) -cne $preparedReceiptSha256
        ) { throw 'CONTAINER_WRITER_FENCE_CHANGED_DURING_MUTATION' }
        return $result
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Disable-ContainerScheduledTaskUnderWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null,
        [string]$TaskName,
        [string]$TaskPath
    )
    return Invoke-ContainerWriterFenceMutation `
        -ControlRoot $ControlRoot `
        -SessionId $SessionId `
        -AttemptId $AttemptId `
        -ReplacementTransactionId $ReplacementTransactionId `
        -DelegationToken $DelegationToken `
        -AuthorityLease $AuthorityLease `
        -Action {
            Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if ([bool]$task.Settings.Enabled) { throw 'CONTAINER_WRITER_TASK_DISABLE_READBACK_FAILED' }
            return $task
        }
}

function Enable-ContainerScheduledTaskUnderWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null,
        [string]$TaskName,
        [string]$TaskPath
    )
    return Invoke-ContainerWriterFenceMutation `
        -ControlRoot $ControlRoot `
        -SessionId $SessionId `
        -AttemptId $AttemptId `
        -ReplacementTransactionId $ReplacementTransactionId `
        -DelegationToken $DelegationToken `
        -AuthorityLease $AuthorityLease `
        -Action {
            Enable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if (-not [bool]$task.Settings.Enabled) { throw 'CONTAINER_WRITER_TASK_ENABLE_READBACK_FAILED' }
            return $task
        }
}

function Stop-ContainerScheduledTaskUnderWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null,
        [string]$TaskName,
        [string]$TaskPath
    )
    return Invoke-ContainerWriterFenceMutation `
        -ControlRoot $ControlRoot `
        -SessionId $SessionId `
        -AttemptId $AttemptId `
        -ReplacementTransactionId $ReplacementTransactionId `
        -DelegationToken $DelegationToken `
        -AuthorityLease $AuthorityLease `
        -Action {
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if ([string]$task.State -ceq 'Running') {
                Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            }
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if ([string]$task.State -ceq 'Running') { throw 'CONTAINER_WRITER_TASK_STOP_READBACK_FAILED' }
            return $task
        }
}

function DisableAndStop-ContainerScheduledTaskUnderWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null,
        [string]$TaskName,
        [string]$TaskPath
    )
    return Invoke-ContainerWriterFenceMutation `
        -ControlRoot $ControlRoot `
        -SessionId $SessionId `
        -AttemptId $AttemptId `
        -ReplacementTransactionId $ReplacementTransactionId `
        -DelegationToken $DelegationToken `
        -AuthorityLease $AuthorityLease `
        -Action {
            Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if ([string]$task.State -ceq 'Running') {
                Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            }
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if ([bool]$task.Settings.Enabled -or [string]$task.State -ceq 'Running') {
                throw 'CONTAINER_WRITER_TASK_QUIESCE_READBACK_FAILED'
            }
            return $task
        }
}

function Remove-ContainerScheduledTaskUnderWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$DelegationToken = '',
        $AuthorityLease = $null,
        [string]$TaskName,
        [string]$TaskPath
    )
    return Invoke-ContainerWriterFenceMutation `
        -ControlRoot $ControlRoot `
        -SessionId $SessionId `
        -AttemptId $AttemptId `
        -ReplacementTransactionId $ReplacementTransactionId `
        -DelegationToken $DelegationToken `
        -AuthorityLease $AuthorityLease `
        -Action {
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            if ([string]$task.State -ceq 'Running') {
                Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
            }
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction Stop
            $remaining = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                [string]$_.TaskName -ceq $TaskName -and [string]$_.TaskPath -ceq $TaskPath
            })
            if ($remaining.Count -ne 0) { throw 'CONTAINER_WRITER_TASK_REMOVE_READBACK_FAILED' }
            return $true
        }
}

function Assert-ContainerWriterFenceActive {
    param([string]$ControlRoot = '')
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try { return Read-ContainerWriterFence $ControlRoot }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Assert-ContainerWriterFencePreparedBinding {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$PreparedReceiptPath,
        [string]$PreparedReceiptSha256,
        $AuthorityLease = $null
    )
    $active = Assert-ContainerWriterFenceOwner -ControlRoot $ControlRoot -SessionId $SessionId -AttemptId $AttemptId -ReplacementTransactionId $ReplacementTransactionId -AuthorityLease $AuthorityLease
    if (
        [string]$active.status -cnotin @('PREPARED','RESTORING','RESTORE_FAILED') -or
        [IO.Path]::GetFullPath([string]$active.prepared_receipt_path) -cne [IO.Path]::GetFullPath($PreparedReceiptPath) -or
        [string]$active.prepared_receipt_sha256 -cne $PreparedReceiptSha256 -or
        (Get-ContainerWriterFenceFileSha256 ([IO.Path]::GetFullPath($PreparedReceiptPath))) -cne $PreparedReceiptSha256
    ) { throw 'CONTAINER_WRITER_FENCE_PREPARED_BINDING_MISMATCH' }
    return $active
}

function Abort-ContainerWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        $AuthorityLease = $null
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $root = Get-ContainerWriterFenceControlRoot $ControlRoot
        $active = Read-ContainerWriterFence $root
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId
        ) { throw 'CONTAINER_WRITER_FENCE_ABORT_MISMATCH' }
        Remove-Item -LiteralPath (Get-ContainerWriterFenceActivePath $root) -Force
        if (Test-Path -LiteralPath (Get-ContainerWriterFenceActivePath $root)) {
            throw 'CONTAINER_WRITER_FENCE_ABORT_READBACK_FAILED'
        }
        return [pscustomobject][ordered]@{ status = 'ABORTED'; session_id = $SessionId; attempt_id = $AttemptId; replacement_transaction_id = $ReplacementTransactionId }
    }
    finally { Exit-ContainerWriterAdmission $lease }
}

function Stop-ContainerWriterFence {
    param(
        [string]$ControlRoot = '',
        [string]$SessionId,
        [string]$AttemptId,
        [string]$ReplacementTransactionId,
        [string]$ReleaseAuthorizationPath,
        [string]$ReleaseAuthorizationSha256,
        $AuthorityLease = $null
    )
    $lease = Enter-ContainerWriterAdmission $ControlRoot
    try {
        $root = Get-ContainerWriterFenceControlRoot $ControlRoot
        $active = Read-ContainerWriterFence $root
        Assert-ContainerWriterSessionAuthority $active $AuthorityLease
        if (
            [string]$active.session_id -cne $SessionId -or
            [string]$active.attempt_id -cne $AttemptId -or
            [string]$active.replacement_transaction_id -cne $ReplacementTransactionId -or
            -not (Test-ContainerWriterFenceHex $ReleaseAuthorizationSha256 64)
        ) { throw 'CONTAINER_WRITER_FENCE_RELEASE_MISMATCH' }
        $authorizationFull = [IO.Path]::GetFullPath($ReleaseAuthorizationPath)
        if (
            [IO.Path]::GetFullPath([string]$active.prepared_receipt_path) -cne $authorizationFull -or
            (Get-ContainerWriterFenceFileSha256 $authorizationFull) -cne $ReleaseAuthorizationSha256 -or
            (
                -not [string]::IsNullOrEmpty([string]$active.prepared_receipt_sha256) -and
                [string]$active.prepared_receipt_sha256 -cne $ReleaseAuthorizationSha256
            )
        ) { throw 'CONTAINER_WRITER_FENCE_RELEASE_AUTHORIZATION_INVALID' }
        $releasePath = Join-Path $root (
            'release-' + $ReplacementTransactionId + '-' + $ReleaseAuthorizationSha256 + '.json'
        )
        if (Test-Path -LiteralPath $releasePath) {
            $release = Read-ContainerWriterFenceReleaseReceipt $releasePath
            [void](Assert-ContainerWriterFenceReleaseReceiptMatches `
                -Receipt $release `
                -SessionId $SessionId `
                -AttemptId $AttemptId `
                -ReplacementTransactionId $ReplacementTransactionId `
                -ReleaseAuthorizationPath $authorizationFull `
                -ReleaseAuthorizationSha256 $ReleaseAuthorizationSha256)
        }
        else {
            $release = [pscustomobject][ordered]@{
                schema = $Script:ContainerWriterFenceReleaseSchema
                status = 'RELEASED'
                app_id = $Script:ContainerWriterFenceAppId
                session_id = $SessionId
                attempt_id = $AttemptId
                replacement_transaction_id = $ReplacementTransactionId
                writer_inventory_sha256 = $Script:ContainerWriterFenceInventorySha256
                release_authorization_path = $authorizationFull
                release_authorization_sha256 = $ReleaseAuthorizationSha256
                released_at_utc = [DateTime]::UtcNow.ToString('o')
                secret_values_recorded = $false
            }
            $temporary = Join-Path $root ('.release.' + [Guid]::NewGuid().ToString('N') + '.tmp')
            try {
                [IO.File]::WriteAllText($temporary, (($release | ConvertTo-Json -Depth 10) + "`n"), (New-Object Text.UTF8Encoding($false)))
                [IO.File]::Move($temporary, $releasePath)
            }
            finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
            $release = Read-ContainerWriterFenceReleaseReceipt $releasePath
            [void](Assert-ContainerWriterFenceReleaseReceiptMatches `
                -Receipt $release `
                -SessionId $SessionId `
                -AttemptId $AttemptId `
                -ReplacementTransactionId $ReplacementTransactionId `
                -ReleaseAuthorizationPath $authorizationFull `
                -ReleaseAuthorizationSha256 $ReleaseAuthorizationSha256)
        }
        Remove-Item -LiteralPath (Get-ContainerWriterFenceActivePath $root) -Force
        if (Test-Path -LiteralPath (Get-ContainerWriterFenceActivePath $root)) {
            throw 'CONTAINER_WRITER_FENCE_CLEAR_READBACK_FAILED'
        }
        return $release
    }
    finally { Exit-ContainerWriterAdmission $lease }
}
