[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Contract', 'Prepare', 'ValidatePrepared', 'ValidateReplacement', 'RestoreWriter', 'Recover', 'SelfTest')]
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
    [string]$ExpectedContractSha256 = '',
    [string]$ReplacementTransactionId = '',
    [string]$ReplacementReceiptPath = '',
    [string]$ReplacementReceiptSha256 = '',
    [string]$LifecycleRestoreReceiptPath = '',
    [string]$LifecycleRestoreReceiptSha256 = '',
    [string]$ExpectedSourceCommit = '',
    [string]$ExpectedSourceAggregateSha256 = '',
    [string]$HelperPath = '',
    [string]$ExpectedHelperSha256 = '',
    [string]$RestoreEvidencePath = '',
    [string]$RestoreEvidenceSha256 = '',
    [string]$WriterRestoreEvidencePath = '',
    [switch]$RetainDisabledOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Mode = $Mode.ToLowerInvariant()

$Script:TaskName = 'direct-sync-relay-container-audit'
$Script:TaskPath = '\'
$Script:RelayMode = '--container-audit-direct-sync-relay'
$Script:UserRelayMode = '--container-audit-user-relay'
$Script:PreparedSchema = 'container-audit-writer-session-prepared-v2'
$Script:RestoredSchema = 'container-audit-writer-session-restored-v2'
$Script:RecoverySchema = 'container-audit-window-recovery-v1'
$Script:ReplacementSchema = 'container-audit-verified-replacement-v1'
$Script:HistoricalSchema = 'container-audit-canonical-writer-lifecycle-v1'
$Script:LifecycleRestoreSchema = 'container-audit-replacement-lifecycle-restore-v1'
$Script:ContractSchema = 'container-audit-writer-session-cli-contract-v1'
$Script:ContractReadbackSchema = 'container-audit-writer-session-contract-readback-v1'
$Script:LifecycleReceiptTopFields = @('schema','report_version','status','action','app_id','captured_at','state_scope','registration_attempted','network_attempted','ledger_opened','identity_or_credential_copied','secret_values_recorded','session_id','attempt_id','session_started_at_utc','orchestrator_sha256','producer_code_root','replacement_transaction_id','replacement_receipt_path','replacement_receipt_sha256','writer_contract_sha256','owner_artifact_count','owner_artifact_paths','owner_state_preserved_exact','containment_status','failure_code','failure','owner_artifact_fingerprints_before','execution_context','code_root','restored_code_identity','failed_new_code_identity','bootstrap_integrity','release_layout','writer_contract_verified','owner_state_readback','owner_artifact_fingerprints_after','completed_at','relay_autostart','relay_start','persistent_relay_principal','system_scheduled_task_required')
$Script:MaximumSessionAge = [TimeSpan]::FromHours(24)
$Script:EvidenceClockTolerance = [TimeSpan]::FromSeconds(2)
$Script:PlainLocalDriveCache = @{}
$Script:SystemMutationAttemptCount = 0
$Script:AdapterPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$Script:IntegrityHelperPath = Join-Path $PSScriptRoot 'bootstrap_integrity.ps1'
$Script:ContractPath = Join-Path $PSScriptRoot 'container_writer_session_contract.json'
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

function Register-ContainerSystemMutationAttempt {
    $Script:SystemMutationAttemptCount += 1
}

function Test-LifecycleReceiptStructuralGuard($Receipt) {
    return (
        (Test-ExactPropertySet $Receipt $Script:LifecycleReceiptTopFields) -and
        $Receipt.owner_state_preserved_exact -is [bool] -and
        $Receipt.writer_contract_verified -is [bool] -and
        $Receipt.system_scheduled_task_required -is [bool] -and
        $Receipt.registration_attempted -is [bool] -and
        $Receipt.network_attempted -is [bool] -and
        $Receipt.ledger_opened -is [bool] -and
        $Receipt.identity_or_credential_copied -is [bool] -and
        $Receipt.secret_values_recorded -is [bool]
    )
}

function Test-ContainerLifecycleExecutionContext($Value) {
    return (
        (Test-ExactPropertySet $Value @('status','token_elevated','integrity_level')) -and
        [string]$Value.status -ceq 'PASS' -and
        $Value.token_elevated -is [bool] -and
        -not [bool]$Value.token_elevated -and
        [string]$Value.integrity_level -ceq 'MEDIUM'
    )
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

function Assert-CurrentSessionWindow([string]$Value) {
    $started = ConvertTo-RoundTripUtc $Value 'session start'
    $now = [DateTime]::UtcNow
    if ($started -gt $now.AddSeconds(5) -or $started -lt $now.Subtract($Script:MaximumSessionAge)) {
        throw 'Session start is not within the current deployment-window lifetime.'
    }
    return $started
}

function Assert-Hex([string]$Value, [int]$Length, [string]$Purpose) {
    if ($Value -cnotmatch ("^[0-9a-f]{$Length}$")) { throw "$Purpose is malformed." }
}

function Test-Base64UrlSha256Fingerprint($Value) {
    return ($Value -is [string] -and [string]$Value -cmatch '^[A-Za-z0-9_-]{43}$')
}

function Get-CanonicalLocalPath([string]$Path, [string]$Purpose) {
    $full = Get-StrictFullPath $Path $Purpose
    if ($full -cnotmatch '^[A-Za-z]:\\') { throw "$Purpose must use a local drive-qualified path." }
    $driveName = $full.Substring(0, 1).ToUpperInvariant()
    if (-not $Script:PlainLocalDriveCache.ContainsKey($driveName)) {
        $drive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction Stop
        $driveInfo = New-Object IO.DriveInfo("$driveName`:\")
        $substExe = Join-Path ([Environment]::SystemDirectory) 'subst.exe'
        $substOutput = @(& $substExe "$driveName`:" 2>&1)
        $isSubst = ($LASTEXITCODE -eq 0 -and $substOutput.Count -gt 0)
        $plain = (
            [string]::IsNullOrWhiteSpace([string]$drive.DisplayRoot) -and
            [string]$driveInfo.DriveType -ceq 'Fixed' -and
            -not $isSubst
        )
        $Script:PlainLocalDriveCache[$driveName] = $plain
    }
    if (-not [bool]$Script:PlainLocalDriveCache[$driveName]) {
        throw "$Purpose must not use a mapped, substituted, or non-fixed drive."
    }
    $missing = @()
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor)) {
        $leaf = Split-Path -Leaf $cursor
        if ([string]::IsNullOrWhiteSpace($leaf)) { throw "$Purpose cannot resolve an existing local ancestor." }
        $missing = @($leaf) + $missing
        $cursor = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($cursor)) { throw "$Purpose cannot resolve an existing local ancestor." }
    }
    $canonical = [string](Get-Item -LiteralPath $cursor -Force -ErrorAction Stop).FullName
    foreach ($component in $missing) { $canonical = Join-Path $canonical $component }
    return [IO.Path]::GetFullPath($canonical).TrimEnd('\')
}

function Test-PathInside([string]$Candidate, [string]$Parent) {
    $candidateFull = Get-CanonicalLocalPath $Candidate 'candidate path'
    $parentFull = (Get-CanonicalLocalPath $Parent 'parent path').TrimEnd('\') + '\'
    return $candidateFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)
}

function Test-CanonicalSamePath([string]$Left, [string]$Right) {
    return (Get-CanonicalLocalPath $Left 'left path').Equals((Get-CanonicalLocalPath $Right 'right path'), [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparseAncestorChain([string]$Path, [string]$Purpose) {
    $full = Get-StrictFullPath $Path $Purpose
    $cursor = if (Test-Path -LiteralPath $full) { $full } else { Split-Path -Parent $full }
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose contains a reparse-point ancestor."
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($cursor, [StringComparison]::OrdinalIgnoreCase)) { break }
        $cursor = $parent
    }
}

function Read-BoundedJson([string]$Path, [int64]$MaximumBytes, [string]$ExpectedSha256 = '') {
    $full = Get-StrictFullPath $Path 'JSON evidence path'
    Assert-NoReparseAncestorChain $full 'JSON evidence path'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'JSON evidence is absent.' }
    Assert-BootstrapNoReparsePoint $full 'JSON evidence'
    $stream = New-Object IO.FileStream(
        $full,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $length = [int64]$stream.Length
        if ($length -le 0 -or $length -gt $MaximumBytes -or $length -gt [int]::MaxValue) {
            throw 'JSON evidence size is invalid.'
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'JSON evidence ended before its declared length.' }
            $offset += $read
        }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try {
            $actualSha = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        }
        finally { $algorithm.Dispose() }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
            Assert-Hex $ExpectedSha256 64 'expected JSON SHA-256'
            if ($actualSha -cne $ExpectedSha256) { throw 'JSON evidence SHA-256 differs.' }
        }
        $decoder = New-Object Text.UTF8Encoding($false, $true)
        $json = $decoder.GetString($bytes)
        if ($json.Length -gt 0 -and $json[0] -eq [char]0xfeff) { $json = $json.Substring(1) }
        try { return ConvertFrom-Json -InputObject $json }
        catch { throw 'JSON evidence is invalid.' }
    }
    finally { $stream.Dispose() }
}

function Open-PinnedReadLock([string]$Path, [int64]$MaximumBytes, [string]$ExpectedSha256) {
    Assert-Hex $ExpectedSha256 64 'locked evidence SHA-256'
    $full = Get-StrictFullPath $Path 'locked evidence path'
    Assert-NoReparseAncestorChain $full 'locked evidence path'
    $stream = $null
    try {
        $stream = New-Object IO.FileStream(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $length = [int64]$stream.Length
        if ($length -le 0 -or $length -gt $MaximumBytes) { throw 'Locked evidence size is invalid.' }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $actualSha = ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
        if ($actualSha -cne $ExpectedSha256) { throw 'Locked evidence SHA-256 differs.' }
        $stream.Position = 0
        return $stream
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Read-ContainerWriterPublicContract([string]$ExpectedSha256) {
    Assert-Hex $ExpectedSha256 64 'expected writer session contract SHA-256'
    $contract = Read-BoundedJson $Script:ContractPath 65536 $ExpectedSha256
    $top = @('schema','app_id','cli','identifiers','operations','receipts','lifecycle_restore','security')
    $cliFields = @('relative_path','public_writer_modes','compatibility_modes','contract_mode','success_exit_code','failure_exit_codes')
    $identifierFields = @('session_id_pattern','attempt_id_pattern','sha256_pattern','commit_pattern','session_max_age_hours')
    $receiptFields = @('prepared_schema','restored_schema','recovery_schema','replacement_schema','replacement_validation_schema','lifecycle_restore_schema','historical_schema','prepared_required_bindings')
    $restoreFields = @('writer_mode','product_mode','product_execution_tree','product_mode_arguments','transaction_argument','replacement_receipt_argument','replacement_receipt_sha256_argument','code_restore_evidence_argument','code_restore_evidence_sha256_argument','writer_mode_output_argument','recover_writer_output_argument','writer_contract_sha256_argument','order','require_same_session_receipt','require_code_restore_before_writer_restore','require_lifecycle_restore_before_writer_restore','require_live_current_user_lifecycle_before_writer_restore','require_non_elevated_medium_integrity_lifecycle_producer','producer_code_tree_read_locked_through_execution','failure_is_explicit')
    $securityFields = @('secret_values_recorded','manual_writer_start_allowed','contract_mode_system_mutation','evidence_paths_outside_install_parent_required','evidence_paths_local_fixed_drive_required','evidence_path_reparse_ancestors_forbidden','evidence_path_aliases_canonicalized')
    if (
        -not (Test-ExactPropertySet $contract $top) -or
        -not (Test-ExactPropertySet $contract.cli $cliFields) -or
        -not (Test-ExactPropertySet $contract.identifiers $identifierFields) -or
        -not (Test-ExactPropertySet $contract.receipts $receiptFields) -or
        -not (Test-ExactPropertySet $contract.lifecycle_restore $restoreFields) -or
        -not (Test-ExactPropertySet $contract.security $securityFields)
    ) { throw 'Writer session public contract property set differs.' }
    $publicModes = @('Contract','Prepare','ValidatePrepared','RestoreWriter')
    $compatibilityModes = @('ValidateReplacement','Recover')
    $operationModes = @($publicModes + $compatibilityModes)
    if (-not (Test-ExactPropertySet $contract.operations $operationModes)) { throw 'Writer session public operation set differs.' }
    $operationContracts = [ordered]@{
        Contract = [ordered]@{ mutation_class = 'NONE'; required_arguments = @('ExpectedContractSha256'); success_output_keys = @('json_stdout') }
        Prepare = [ordered]@{ mutation_class = 'SCHEDULED_WRITER_DISABLE'; required_arguments = @('InstallRoot','EvidencePath','SessionId','AttemptId','ReplacementTransactionId','SessionStartedAtUtc','OrchestratorSha256','ExpectedContractSha256','HistoricalReceiptPath','HistoricalReceiptSha256'); success_output_keys = @('writer_session_status','writer_session_receipt','writer_session_receipt_sha256') }
        ValidatePrepared = [ordered]@{ mutation_class = 'NONE'; required_arguments = @('InstallRoot','PreparedReceiptPath','PreparedReceiptSha256','SessionId','AttemptId','ReplacementTransactionId','SessionStartedAtUtc','OrchestratorSha256','ExpectedContractSha256','HistoricalReceiptSha256'); success_output_keys = @('writer_session_validation_status') }
        RestoreWriter = [ordered]@{ mutation_class = 'SCHEDULED_WRITER_ENABLE_NATURAL_TRIGGER_READBACK_AND_LIFECYCLE_FAILURE_CONTAINMENT'; required_arguments = @('InstallRoot','EvidencePath','PreparedReceiptPath','PreparedReceiptSha256','HistoricalReceiptSha256','LifecycleRestoreReceiptPath','LifecycleRestoreReceiptSha256','RestoreEvidencePath','RestoreEvidenceSha256','ReplacementReceiptPath','ReplacementReceiptSha256','SessionId','AttemptId','ReplacementTransactionId','SessionStartedAtUtc','OrchestratorSha256','ExpectedContractSha256'); success_output_keys = @('writer_restore_status','writer_restore_receipt','writer_restore_receipt_sha256') }
        ValidateReplacement = [ordered]@{ mutation_class = 'EVIDENCE_ONLY'; required_arguments = @('InstallRoot','EvidencePath','PreparedReceiptPath','PreparedReceiptSha256','HistoricalReceiptSha256','ReplacementReceiptPath','ReplacementReceiptSha256','ReplacementTransactionId','ExpectedSourceCommit','ExpectedSourceAggregateSha256','HelperPath','ExpectedHelperSha256','SessionId','AttemptId','SessionStartedAtUtc','OrchestratorSha256','ExpectedContractSha256'); success_output_keys = @('replacement_receipt_validation_status','replacement_receipt_validation_evidence','replacement_receipt_validation_evidence_sha256') }
        Recover = [ordered]@{ mutation_class = 'CODE_LIFECYCLE_AND_WRITER_RESTORE_COMPATIBILITY'; required_arguments = @('InstallRoot','EvidencePath','PreparedReceiptPath','PreparedReceiptSha256','HistoricalReceiptSha256','LifecycleRestoreReceiptPath','ReplacementReceiptPath','ReplacementReceiptSha256','ReplacementTransactionId','ExpectedSourceCommit','ExpectedSourceAggregateSha256','HelperPath','ExpectedHelperSha256','RestoreEvidencePath','WriterRestoreEvidencePath','SessionId','AttemptId','SessionStartedAtUtc','OrchestratorSha256','ExpectedContractSha256'); success_output_keys = @('container_recovery_status','container_recovery_receipt','container_recovery_receipt_sha256') }
    }
    foreach ($operationName in $operationModes) {
        $operation = Get-ObjectPropertyValue $contract.operations $operationName $null
        $expectedOperation = $operationContracts[$operationName]
        if (
            -not (Test-ExactPropertySet $operation @('mutation_class','required_arguments','success_output_keys')) -or
            [string]$operation.mutation_class -cne [string]$expectedOperation.mutation_class -or
            (@($operation.required_arguments) -join ',') -cne (@($expectedOperation.required_arguments) -join ',') -or
            (@($operation.success_output_keys) -join ',') -cne (@($expectedOperation.success_output_keys) -join ',')
        ) { throw "Writer session public operation contract differs: $operationName" }
    }
    $bindings = @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','adapter_sha256','contract_sha256','evidence_path','historical_capability.receipt_sha256','historical_capability.capability_binding_sha256')
    $restoreOrder = @('validate_current_session_prepared_receipt','validate_transaction_bound_replacement_receipt','restore_code','restore_current_user_product_lifecycle','validate_lifecycle_restore_receipt','restore_writer','write_combined_recovery_receipt')
    $productArguments = @('--app-root','--code-root','--replacement-transaction-id','--replacement-receipt-path','--replacement-receipt-sha256','--writer-contract-sha256','--report-path','--session-id','--attempt-id','--session-started-at-utc','--orchestrator-sha256')
    if (
        [string]$contract.schema -cne $Script:ContractSchema -or
        [string]$contract.app_id -cne 'container_audit' -or
        [string]$contract.cli.relative_path -cne 'tools/container_writer_session.ps1' -or
        [string]$contract.cli.contract_mode -cne 'Contract' -or
        [int]$contract.cli.success_exit_code -ne 0 -or
        (@($contract.cli.failure_exit_codes) -join ',') -cne '1,20' -or
        (@($contract.cli.public_writer_modes) -join ',') -cne ($publicModes -join ',') -or
        (@($contract.cli.compatibility_modes) -join ',') -cne ($compatibilityModes -join ',') -or
        [string]$contract.identifiers.session_id_pattern -cne '^[0-9a-f]{32}$' -or
        [string]$contract.identifiers.attempt_id_pattern -cne '^[0-9a-f]{32}$' -or
        [string]$contract.identifiers.sha256_pattern -cne '^[0-9a-f]{64}$' -or
        [string]$contract.identifiers.commit_pattern -cne '^[0-9a-f]{40}$' -or
        [int]$contract.identifiers.session_max_age_hours -ne 24 -or
        [string]$contract.receipts.prepared_schema -cne $Script:PreparedSchema -or
        [string]$contract.receipts.restored_schema -cne $Script:RestoredSchema -or
        [string]$contract.receipts.recovery_schema -cne $Script:RecoverySchema -or
        [string]$contract.receipts.replacement_schema -cne $Script:ReplacementSchema -or
        [string]$contract.receipts.replacement_validation_schema -cne 'container-audit-replacement-receipt-validation-v1' -or
        [string]$contract.receipts.lifecycle_restore_schema -cne $Script:LifecycleRestoreSchema -or
        [string]$contract.receipts.historical_schema -cne $Script:HistoricalSchema -or
        (@($contract.receipts.prepared_required_bindings) -join ',') -cne ($bindings -join ',') -or
        [string]$contract.lifecycle_restore.writer_mode -cne 'RestoreWriter' -or
        [string]$contract.lifecycle_restore.product_mode -cne '--restore-current-user-lifecycle-after-replacement' -or
        [string]$contract.lifecycle_restore.product_execution_tree -cne 'verified_failed_new_tree' -or
        (@($contract.lifecycle_restore.product_mode_arguments) -join ',') -cne ($productArguments -join ',') -or
        [string]$contract.lifecycle_restore.transaction_argument -cne 'ReplacementTransactionId' -or
        [string]$contract.lifecycle_restore.replacement_receipt_argument -cne 'ReplacementReceiptPath' -or
        [string]$contract.lifecycle_restore.replacement_receipt_sha256_argument -cne 'ReplacementReceiptSha256' -or
        [string]$contract.lifecycle_restore.code_restore_evidence_argument -cne 'RestoreEvidencePath' -or
        [string]$contract.lifecycle_restore.code_restore_evidence_sha256_argument -cne 'RestoreEvidenceSha256' -or
        [string]$contract.lifecycle_restore.writer_mode_output_argument -cne 'EvidencePath' -or
        [string]$contract.lifecycle_restore.recover_writer_output_argument -cne 'WriterRestoreEvidencePath' -or
        [string]$contract.lifecycle_restore.writer_contract_sha256_argument -cne 'ExpectedContractSha256' -or
        (@($contract.lifecycle_restore.order) -join ',') -cne ($restoreOrder -join ',') -or
        $contract.lifecycle_restore.require_same_session_receipt -isnot [bool] -or -not [bool]$contract.lifecycle_restore.require_same_session_receipt -or
        $contract.lifecycle_restore.require_code_restore_before_writer_restore -isnot [bool] -or -not [bool]$contract.lifecycle_restore.require_code_restore_before_writer_restore -or
        $contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore -isnot [bool] -or -not [bool]$contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore -or
        $contract.lifecycle_restore.require_live_current_user_lifecycle_before_writer_restore -isnot [bool] -or -not [bool]$contract.lifecycle_restore.require_live_current_user_lifecycle_before_writer_restore -or
        $contract.lifecycle_restore.require_non_elevated_medium_integrity_lifecycle_producer -isnot [bool] -or -not [bool]$contract.lifecycle_restore.require_non_elevated_medium_integrity_lifecycle_producer -or
        $contract.lifecycle_restore.producer_code_tree_read_locked_through_execution -isnot [bool] -or -not [bool]$contract.lifecycle_restore.producer_code_tree_read_locked_through_execution -or
        $contract.lifecycle_restore.failure_is_explicit -isnot [bool] -or -not [bool]$contract.lifecycle_restore.failure_is_explicit -or
        $contract.security.secret_values_recorded -isnot [bool] -or [bool]$contract.security.secret_values_recorded -or
        $contract.security.manual_writer_start_allowed -isnot [bool] -or [bool]$contract.security.manual_writer_start_allowed -or
        $contract.security.contract_mode_system_mutation -isnot [bool] -or [bool]$contract.security.contract_mode_system_mutation -or
        $contract.security.evidence_paths_outside_install_parent_required -isnot [bool] -or -not [bool]$contract.security.evidence_paths_outside_install_parent_required -or
        $contract.security.evidence_paths_local_fixed_drive_required -isnot [bool] -or -not [bool]$contract.security.evidence_paths_local_fixed_drive_required -or
        $contract.security.evidence_path_reparse_ancestors_forbidden -isnot [bool] -or -not [bool]$contract.security.evidence_path_reparse_ancestors_forbidden -or
        $contract.security.evidence_path_aliases_canonicalized -isnot [bool] -or -not [bool]$contract.security.evidence_path_aliases_canonicalized
    ) { throw 'Writer session public contract semantic binding differs.' }
    return $contract
}

function Write-JsonAtomic([string]$Path, $Payload, [switch]$AllowReplace) {
    $full = Get-StrictFullPath $Path 'JSON output path'
    $parent = Split-Path -Parent $full
    Assert-NoReparseAncestorChain $parent 'JSON output parent'
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-NoReparseAncestorChain $parent 'JSON output parent'
    Assert-BootstrapNoReparsePoint $parent 'JSON output parent'
    if ((Test-Path -LiteralPath $full) -and -not $AllowReplace.IsPresent) {
        throw 'JSON output path already exists.'
    }
    $temporary = $full + '.tmp.' + [Guid]::NewGuid().ToString('N')
    $backup = $full + '.bak.' + [Guid]::NewGuid().ToString('N')
    $json = ($Payload | ConvertTo-Json -Depth 32)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json + [Environment]::NewLine)
    $cleanupFailures = @()
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
        if ($AllowReplace.IsPresent) {
            if (Test-Path -LiteralPath $full -PathType Leaf) {
                [IO.File]::Replace($temporary, $full, $backup)
            }
            else { [IO.File]::Move($temporary, $full) }
        }
        else { [IO.File]::Move($temporary, $full) }
    }
    finally {
        foreach ($cleanupPath in @($temporary, $backup)) {
            if (Test-Path -LiteralPath $cleanupPath) {
                try { Remove-Item -LiteralPath $cleanupPath -Force -ErrorAction Stop }
                catch { $cleanupFailures += $_.Exception.GetType().Name }
            }
        }
    }
    return [pscustomobject][ordered]@{
        path = $full
        exists = (Test-Path -LiteralPath $full -PathType Leaf)
        sha256 = Get-FileSha256 $full
        length = [int64](Get-Item -LiteralPath $full -Force).Length
        cleanup_status = if ($cleanupFailures.Count -eq 0) { 'PASS' } else { 'RESIDUE' }
        cleanup_failure_types = @($cleanupFailures)
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
    # Keep this normalized binding byte-for-byte compatible with the canonical
    # installer and the independently observed eight-point lifecycle receipt.
    $bindingValue = [ordered]@{
        task_name = [string]$task.TaskName
        task_path = [string]$task.TaskPath
        actions = @($actions | ForEach-Object {
            [ordered]@{
                execute = [string]$_.Execute
                arguments = [string]$_.Arguments
                working_directory = [string]$_.WorkingDirectory
            }
        })
        principal = [ordered]@{
            user_id = [string]$task.Principal.UserId
            logon_type = [string]$task.Principal.LogonType
            run_level = [string]$task.Principal.RunLevel
        }
        triggers = @($triggers | ForEach-Object {
            [ordered]@{
                type = [string]$_.CimClass.CimClassName
                enabled = [bool]$_.Enabled
                start_boundary = [string]$_.StartBoundary
                repetition_interval = [string]$_.Repetition.Interval
                repetition_duration = [string]$_.Repetition.Duration
                stop_at_duration_end = [bool]$_.Repetition.StopAtDurationEnd
            }
        })
        settings = [ordered]@{
            start_when_available = [bool]$task.Settings.StartWhenAvailable
            multiple_instances = [string]$task.Settings.MultipleInstances
            execution_time_limit = [string]$task.Settings.ExecutionTimeLimit
            disallow_start_if_on_batteries = [bool]$task.Settings.DisallowStartIfOnBatteries
            stop_if_going_on_batteries = [bool]$task.Settings.StopIfGoingOnBatteries
        }
    }
    $bindingJson = $bindingValue | ConvertTo-Json -Depth 8 -Compress
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
            binding_sha256 = Get-StringSha256 $bindingJson
        }
    }
}

function Test-ContainerWriterDisabledBeforeEnable($Readback, [string]$ExpectedBindingSha256) {
    try {
        Assert-Hex $ExpectedBindingSha256 64 'expected Container writer binding SHA-256'
        return (
            $Readback.enabled -is [bool] -and -not [bool]$Readback.enabled -and
            [string]$Readback.state -ceq 'Disabled' -and
            [int]$Readback.exact_writer_process_count -eq 0 -and
            [string]$Readback.identity.status -ceq 'PASS' -and
            [string]$Readback.identity.binding_sha256 -ceq $ExpectedBindingSha256
        )
    }
    catch { return $false }
}

function Test-ContainerHistoricalPreimageBooleanContract($Preimage) {
    return (
        $null -ne $Preimage -and
        $Preimage.present -is [bool] -and [bool]$Preimage.present -and
        $Preimage.restore_required -is [bool] -and [bool]$Preimage.restore_required -and
        $Preimage.start_when_available -is [bool] -and [bool]$Preimage.start_when_available
    )
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
        (Test-ContainerHistoricalPreimageBooleanContract $preimage) -and
        [string]$preimage.task_name -ceq $Script:TaskName -and [string]$preimage.task_path -ceq $Script:TaskPath -and
        (Test-BootstrapSamePath ([string]$preimage.action_execute) (Join-Path $CanonicalInstallRoot 'runtime\python.exe')) -and
        [string]$preimage.action_mode -ceq $Script:RelayMode -and
        [string]$preimage.logon_type -ceq 'Interactive' -and [string]$preimage.run_level -ceq 'Limited' -and
        [string]$preimage.trigger_type -ceq 'MSFT_TaskTimeTrigger' -and [string]$preimage.trigger_interval -ceq 'PT1M' -and
        [string]$preimage.multiple_instances -ceq 'IgnoreNew' -and
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
        [string]$Live.identity.binding_sha256 -ceq [string]$preimage.binding_sha256 -and
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
            Register-ContainerSystemMutationAttempt
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
        [string]$CurrentReplacementTransactionId,
        [string]$CurrentContractSha256,
        [string]$CapabilityPath,
        [string]$CapabilitySha256,
        [switch]$RetainDisabled
    )
    Assert-Hex $CurrentSessionId 32 'session id'
    Assert-Hex $CurrentAttemptId 32 'attempt id'
    Assert-Hex $CurrentOrchestratorSha256 64 'orchestrator SHA-256'
    Assert-Hex $CurrentReplacementTransactionId 32 'replacement transaction id'
    Assert-Hex $CurrentContractSha256 64 'writer session contract SHA-256'
    [void](Assert-CurrentSessionWindow $CurrentSessionStartedAtUtc)
    Assert-Hex $CapabilitySha256 64 'historical receipt SHA-256'
    $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
    $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
    $outputFull = Get-StrictFullPath $OutputPath 'prepared receipt path'
    $capabilityFull = Get-StrictFullPath $CapabilityPath 'historical capability receipt path'
    if (Test-Path -LiteralPath $outputFull) { throw 'Prepared receipt path already exists.' }
    foreach ($externalPath in @($outputFull, $capabilityFull)) {
        Assert-NoReparseAncestorChain $externalPath 'Container writer prepare evidence path'
        if ((Test-PathInside $externalPath $installParent) -or (Test-CanonicalSamePath $externalPath $installParent)) {
            throw 'Prepared and historical receipts must be outside the mutable install parent.'
        }
    }
    $receipt = [ordered]@{
        schema = $Script:PreparedSchema
        status = 'IN_PROGRESS'
        app_id = 'container_audit'
        session_id = $CurrentSessionId
        attempt_id = $CurrentAttemptId
        replacement_transaction_id = $CurrentReplacementTransactionId
        session_started_at_utc = $CurrentSessionStartedAtUtc
        orchestrator_sha256 = $CurrentOrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        contract_sha256 = $CurrentContractSha256
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
        $historical = Read-ContainerHistoricalCapability $capabilityFull $CapabilitySha256 $root
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
        Register-ContainerSystemMutationAttempt
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
                    Register-ContainerSystemMutationAttempt
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
    try {
        $record = Write-JsonAtomic $outputFull $receipt -AllowReplace
    }
    catch {
        $persistenceFailureType = $_.Exception.GetType().Name
        $receipt.status = 'FAIL'
        $receipt.failure.status = 'FAIL'
        $receipt.failure.stage = 'FINAL_EVIDENCE_PERSISTENCE'
        $receipt.failure.code = 'CONTAINER_WRITER_PREPARE_FINAL_EVIDENCE_FAILED'
        $receipt.failure.failure_type = $persistenceFailureType
        if ($null -ne $pre -and -not [string]::IsNullOrWhiteSpace([string]$pre.identity.binding_sha256)) {
            $receipt.failure.safety_fence = Invoke-ContainerWriterSafetyFence $root ([string]$pre.identity.binding_sha256) 'PREPARE_FINAL_EVIDENCE_FAILED_RETAIN_DISABLED'
        }
        $receipt.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        try { [void](Write-JsonAtomic $outputFull $receipt -AllowReplace) } catch { }
        $fenceStatus = if ($null -eq $receipt.failure.safety_fence) { 'NOT_AVAILABLE' } else { [string]$receipt.failure.safety_fence.status }
        throw "Container writer prepare final evidence persistence failed; writer_fence=$fenceStatus."
    }
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
        [string]$ExpectedReplacementTransactionId,
        [string]$ExpectedContractSha256,
        [string]$ExpectedCapabilitySha256,
        [string]$ExpectedAdapterSha256
    )
    try {
        $top = @('schema','status','app_id','session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','adapter_sha256','contract_sha256','evidence_path','started_at_utc','completed_at_utc','secret_values_recorded','historical_capability','pre_readback','disable','quiescence','failure')
        if (-not (Test-ExactPropertySet $Receipt $top)) { return $false }
        $sessionStart = ConvertTo-RoundTripUtc ([string]$Receipt.session_started_at_utc) 'receipt session start'
        $expectedSessionStart = Assert-CurrentSessionWindow $ExpectedSessionStartedAtUtc
        $started = ConvertTo-RoundTripUtc ([string]$Receipt.started_at_utc) 'receipt start'
        $completed = ConvertTo-RoundTripUtc ([string]$Receipt.completed_at_utc) 'receipt completion'
        return (
            [string]$Receipt.schema -ceq $Script:PreparedSchema -and
            [string]$Receipt.status -ceq 'PREPARED_DISABLED' -and
            [string]$Receipt.app_id -ceq 'container_audit' -and
            [string]$Receipt.session_id -ceq $ExpectedSessionId -and
            [string]$Receipt.attempt_id -ceq $ExpectedAttemptId -and
            [string]$Receipt.replacement_transaction_id -ceq $ExpectedReplacementTransactionId -and
            [string]$Receipt.session_started_at_utc -ceq $ExpectedSessionStartedAtUtc -and
            [string]$Receipt.orchestrator_sha256 -ceq $ExpectedOrchestratorSha256 -and
            [string]$Receipt.adapter_sha256 -ceq $ExpectedAdapterSha256 -and
            [string]$Receipt.contract_sha256 -ceq $ExpectedContractSha256 -and
            (Test-BootstrapSamePath ([string]$Receipt.evidence_path) $ExpectedPath) -and
            $Receipt.secret_values_recorded -is [bool] -and -not [bool]$Receipt.secret_values_recorded -and
            $sessionStart -eq $expectedSessionStart -and
            $started -ge $sessionStart.AddSeconds(-2) -and $completed -ge $started -and
            $completed -le [DateTime]::UtcNow.AddSeconds(5) -and
            [string]$Receipt.historical_capability.schema -ceq $Script:HistoricalSchema -and
            [string]$Receipt.historical_capability.receipt_sha256 -ceq $ExpectedCapabilitySha256 -and
            $Receipt.historical_capability.eight_points_pass -is [bool] -and [bool]$Receipt.historical_capability.eight_points_pass -and
            [string]$Receipt.historical_capability.capability_binding_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$Receipt.pre_readback.identity.status -ceq 'PASS' -and
            [string]$Receipt.pre_readback.identity.binding_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$Receipt.pre_readback.identity.binding_sha256 -ceq [string]$Receipt.historical_capability.capability_binding_sha256 -and
            $Receipt.pre_readback.enabled -is [bool] -and [bool]$Receipt.pre_readback.enabled -and [string]$Receipt.pre_readback.state -ceq 'Ready' -and
            [int64]$Receipt.pre_readback.last_task_result -eq 0 -and [int]$Receipt.pre_readback.exact_writer_process_count -eq 0 -and
            [string]$Receipt.disable.status -ceq 'COMMAND_SUCCEEDED' -and $Receipt.disable.binding_unchanged -is [bool] -and [bool]$Receipt.disable.binding_unchanged -and
            [string]$Receipt.quiescence.status -ceq 'PASS' -and
            $Receipt.quiescence.last_run_time_unchanged -is [bool] -and [bool]$Receipt.quiescence.last_run_time_unchanged -and
            $Receipt.quiescence.log_unchanged -is [bool] -and [bool]$Receipt.quiescence.log_unchanged -and
            $Receipt.quiescence.runtime_status_unchanged -is [bool] -and [bool]$Receipt.quiescence.runtime_status_unchanged -and
            [int]$Receipt.quiescence.exact_writer_process_count -eq 0 -and
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
        [string]$CurrentReplacementTransactionId,
        [string]$CurrentContractSha256,
        [string]$CapabilitySha256,
        [switch]$RequireLiveDisabled
    )
    try {
        Assert-Hex $ExpectedSha256 64 'prepared receipt SHA-256'
        Assert-Hex $CapabilitySha256 64 'historical receipt SHA-256'
        $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
        $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
        $receiptPath = Get-StrictFullPath $Path 'prepared receipt path'
        if ((Test-PathInside $receiptPath $installParent) -or (Test-CanonicalSamePath $receiptPath $installParent)) {
            throw 'Prepared receipt must be outside the mutable install parent.'
        }
        $receipt = Read-BoundedJson $Path 1048576 $ExpectedSha256
        $exact = Test-PreparedReceiptPayload $receipt $receiptPath $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $CurrentReplacementTransactionId $CurrentContractSha256 $CapabilitySha256 $Script:AdapterSha256
        if (-not $exact -or -not $RequireLiveDisabled.IsPresent) { return [pscustomobject][ordered]@{ status = if ($exact) { 'PASS' } else { 'FAIL' }; payload = if ($exact) { $receipt } else { $null }; live_disabled_exact = $null } }
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

function Test-ContainerLifecycleMutationEvidence($Receipt, [string]$ExpectedCodeRoot) {
    try {
        $autostartFields = @('status','principal','registry_hive','registry_key','registry_value','command')
        $relayStartFields = @('status','process_id')
        if (
            -not (Test-ExactPropertySet $Receipt.relay_autostart $autostartFields) -or
            -not (Test-ExactPropertySet $Receipt.relay_start $relayStartFields)
        ) { return $false }
        $root = Get-StrictFullPath $ExpectedCodeRoot 'Container install root'
        $runtime = Join-Path $root 'runtime\pythonw.exe'
        $entry = Join-Path $root 'app\main.py'
        $commands = @()
        foreach ($runtimeToken in @($runtime, ('"' + $runtime + '"'))) {
            foreach ($entryToken in @($entry, ('"' + $entry + '"'))) {
                $commands += "$runtimeToken -I -B $entryToken $($Script:UserRelayMode)"
            }
        }
        $relayPid = $Receipt.relay_start.process_id
        return (
            [string]$Receipt.relay_autostart.status -ceq 'PASS' -and
            [string]$Receipt.relay_autostart.principal -ceq 'current_user' -and
            [string]$Receipt.relay_autostart.registry_hive -ceq 'HKEY_CURRENT_USER' -and
            [string]$Receipt.relay_autostart.registry_key -ceq 'Software\Microsoft\Windows\CurrentVersion\Run' -and
            [string]$Receipt.relay_autostart.registry_value -ceq 'KMTech.ContainerAudit.Relay' -and
            $commands -ccontains [string]$Receipt.relay_autostart.command -and
            [string]$Receipt.relay_start.status -ceq 'START_REQUESTED' -and
            ($relayPid -is [int] -or $relayPid -is [long]) -and
            [int64]$relayPid -gt 0
        )
    }
    catch { return $false }
}

function Test-ContainerUserRelayLiveReadbackValues($Receipt, [string]$ExpectedCodeRoot, [string]$RegistryCommand, [string]$RegistryValueKind, $Process, [int]$CandidateProcessCount, [int]$MatchingProcessCount, [string]$CurrentUserSid) {
    try {
        if (-not (Test-ContainerLifecycleMutationEvidence $Receipt $ExpectedCodeRoot)) { return $false }
        $root = Get-StrictFullPath $ExpectedCodeRoot 'Container install root'
        $runtime = Join-Path $root 'runtime\pythonw.exe'
        $expectedCommand = [string]$Receipt.relay_autostart.command
        $relayPid = $Receipt.relay_start.process_id
        $captured = ConvertTo-RoundTripUtc ([string]$Receipt.captured_at) 'lifecycle receipt capture'
        $completed = ConvertTo-RoundTripUtc ([string]$Receipt.completed_at) 'lifecycle receipt completion'
        if ($Process.CreationDate -isnot [DateTime]) { return $false }
        $created = ([DateTime]$Process.CreationDate).ToUniversalTime()
        return (
            $RegistryCommand -ceq $expectedCommand -and
            $RegistryValueKind -ceq 'String' -and
            $null -ne $Process -and
            $CandidateProcessCount -eq 1 -and
            $MatchingProcessCount -eq 1 -and
            ($Process.ProcessId -is [int] -or $Process.ProcessId -is [long] -or $Process.ProcessId -is [uint32]) -and
            [int64]$Process.ProcessId -eq [int64]$relayPid -and
            (Test-BootstrapSamePath ([string]$Process.ExecutablePath) $runtime) -and
            [string]$Process.CommandLine -ceq $expectedCommand -and
            [string]$Process.OwnerSid -ceq $CurrentUserSid -and
            $CurrentUserSid -cmatch '^S-1-' -and
            $created -ge $captured.Subtract($Script:EvidenceClockTolerance) -and
            $created -le $completed.AddSeconds(5)
        )
    }
    catch { return $false }
}

function Test-ContainerUserRelayLiveReadback($Receipt, [string]$ExpectedCodeRoot) {
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $false)
        if ($null -eq $key) { return $false }
        try {
            $registryKind = $key.GetValueKind('KMTech.ContainerAudit.Relay').ToString()
            $registryCommand = [string]$key.GetValue(
                'KMTech.ContainerAudit.Relay',
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
        }
        finally { $key.Dispose() }
        $root = Get-StrictFullPath $ExpectedCodeRoot 'Container install root'
        $runtime = Join-Path $root 'runtime\pythonw.exe'
        $expectedCommand = [string]$Receipt.relay_autostart.command
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $runtimeWql = $runtime.Replace('\', '\\').Replace("'", "''")
        $candidates = @(Get-CimInstance -ClassName Win32_Process -Filter "ExecutablePath = '$runtimeWql'" -ErrorAction Stop)
        $matching = @()
        foreach ($candidate in $candidates) {
            if ([string]$candidate.CommandLine -cne $expectedCommand) { continue }
            $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction Stop
            if ([uint32]$owner.ReturnValue -ne 0) { return $false }
            if ([string]$owner.Sid -cne $currentSid) { continue }
            $matching += [pscustomobject][ordered]@{
                ProcessId = $candidate.ProcessId
                ExecutablePath = [string]$candidate.ExecutablePath
                CommandLine = [string]$candidate.CommandLine
                CreationDate = $candidate.CreationDate
                OwnerSid = [string]$owner.Sid
            }
        }
        if ($candidates.Count -ne 1 -or $matching.Count -ne 1) { return $false }
        return Test-ContainerUserRelayLiveReadbackValues $Receipt $ExpectedCodeRoot $registryCommand $registryKind $matching[0] $candidates.Count $matching.Count $currentSid
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
        Assert-NoReparseAncestorChain $helperFull 'Container helper path'
        if (-not (Test-Path -LiteralPath $helperFull -PathType Leaf) -or (Get-FileSha256 $helperFull) -cne $CurrentHelperSha256) { throw 'Container helper pin differs.' }
        $receiptFull = Get-StrictFullPath $Path 'replacement receipt path'
        Assert-NoReparseAncestorChain $receiptFull 'replacement receipt path'
        $receipt = Read-BoundedJson $receiptFull 1048576 $ExpectedSha256
        if (-not (Test-ReplacementReceiptShape $receipt)) { throw 'Replacement receipt shape is invalid.' }
        $current = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
        $parent = Get-StrictFullPath (Split-Path -Parent $current) 'Container install parent'
        if ((Test-PathInside $receiptFull $parent) -or (Test-CanonicalSamePath $receiptFull $parent)) {
            throw 'Replacement receipt must be outside the mutable application parent.'
        }
        if ((Test-PathInside $helperFull $parent) -or (Test-CanonicalSamePath $helperFull $parent)) {
            throw 'Container restore helper must be outside the mutable application parent.'
        }
        $helperIntegrity = Join-Path (Split-Path -Parent $helperFull) 'tools\bootstrap_integrity.ps1'
        if (-not (Test-BootstrapSamePath $helperIntegrity $Script:IntegrityHelperPath)) {
            throw 'Container restore helper and adapter do not share the pinned integrity helper.'
        }
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

function Test-ContainerLifecycleRestoreReceipt {
    param(
        [string]$Path,
        [string]$ExpectedSha256,
        [string]$ExpectedSessionId,
        [string]$ExpectedAttemptId,
        [string]$ExpectedSessionStartedAtUtc,
        [string]$ExpectedOrchestratorSha256,
        [string]$ExpectedProducerRoot,
        [string]$ExpectedTransactionId,
        [string]$ExpectedReplacementReceiptPath,
        [string]$ExpectedReplacementReceiptSha256,
        [string]$ExpectedContractSha256,
        [string]$ExpectedCodeRoot
    )
    try {
        Assert-Hex $ExpectedSha256 64 'lifecycle restore receipt SHA-256'
        Assert-Hex $ExpectedSessionId 32 'session id'
        Assert-Hex $ExpectedAttemptId 32 'attempt id'
        Assert-Hex $ExpectedOrchestratorSha256 64 'orchestrator SHA-256'
        $expectedSessionStart = Assert-CurrentSessionWindow $ExpectedSessionStartedAtUtc
        Assert-Hex $ExpectedTransactionId 32 'replacement transaction id'
        Assert-Hex $ExpectedReplacementReceiptSha256 64 'replacement receipt SHA-256'
        Assert-Hex $ExpectedContractSha256 64 'writer session contract SHA-256'
        $receiptPath = Get-StrictFullPath $Path 'lifecycle restore receipt path'
        $root = Get-StrictFullPath $ExpectedCodeRoot 'Container install root'
        $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
        if ((Test-PathInside $receiptPath $installParent) -or (Test-CanonicalSamePath $receiptPath $installParent)) {
            throw 'Lifecycle restore receipt must be outside the mutable install parent.'
        }
        $receipt = Read-BoundedJson $receiptPath 1048576 $ExpectedSha256
        $tree = @('file_count','aggregate_sha256','integrity_sha256','manifest_sha256','source_commit','source_tree','owner_sid','access_rules_protected','acl_sddl_sha256','reparse_count')
        $ownerArtifacts = @('identity','producer_manifest','credential','registration_report','logistics_profile','logistics_secret','ledger')
        $ownerReadback = @('status','source_host_id','producer_install_id','manifest_hash','possession_key_fingerprint')
        $captured = ConvertTo-RoundTripUtc ([string]$receipt.captured_at) 'lifecycle receipt capture'
        $completed = ConvertTo-RoundTripUtc ([string]$receipt.completed_at) 'lifecycle receipt completion'
        foreach ($name in $ownerArtifacts) {
            $beforeHash = [string](Get-ObjectPropertyValue $receipt.owner_artifact_fingerprints_before $name '')
            $afterHash = [string](Get-ObjectPropertyValue $receipt.owner_artifact_fingerprints_after $name '')
            Assert-Hex $beforeHash 64 "owner artifact $name SHA-256"
            if ($beforeHash -cne $afterHash) { throw 'Lifecycle restore changed an owner artifact.' }
            $livePath = Get-StrictFullPath ([string](Get-ObjectPropertyValue $receipt.owner_artifact_paths $name '')) "owner artifact $name path"
            Assert-NoReparseAncestorChain $livePath "owner artifact $name path"
            if (
                -not (Test-Path -LiteralPath $livePath -PathType Leaf) -or
                (Test-PathInside $livePath $installParent) -or
                (Test-CanonicalSamePath $livePath $installParent) -or
                (Test-CanonicalSamePath $livePath $receiptPath)
            ) { throw 'Lifecycle restore owner artifact path is unsafe.' }
            Assert-BootstrapNoReparsePoint $livePath "owner artifact $name"
            if ((Get-FileSha256 $livePath) -cne $afterHash) { throw 'Lifecycle restore owner artifact live readback differs.' }
        }
        foreach ($identity in @($receipt.restored_code_identity, $receipt.failed_new_code_identity)) {
            if ([int]$identity.file_count -le 0 -or [int]$identity.reparse_count -ne 0 -or $identity.access_rules_protected -isnot [bool] -or [string]::IsNullOrWhiteSpace([string]$identity.owner_sid)) {
                throw 'Lifecycle receipt code identity is invalid.'
            }
            foreach ($name in @('aggregate_sha256','integrity_sha256','manifest_sha256','acl_sddl_sha256')) { Assert-Hex ([string](Get-ObjectPropertyValue $identity $name '')) 64 "code identity $name" }
            foreach ($name in @('source_commit','source_tree')) { Assert-Hex ([string](Get-ObjectPropertyValue $identity $name '')) 40 "code identity $name" }
        }
        Assert-Hex ([string]$receipt.owner_state_readback.manifest_hash) 64 'owner manifest SHA-256'
        if (-not (Test-Base64UrlSha256Fingerprint $receipt.owner_state_readback.possession_key_fingerprint)) {
            throw 'Owner possession-key fingerprint is not a base64url SHA-256 value.'
        }
        $exact = (
            (Test-LifecycleReceiptStructuralGuard $receipt) -and
            (Test-ExactPropertySet $receipt.restored_code_identity $tree) -and
            (Test-ExactPropertySet $receipt.failed_new_code_identity $tree) -and
            (Test-ExactPropertySet $receipt.owner_artifact_paths $ownerArtifacts) -and
            (Test-ExactPropertySet $receipt.owner_artifact_fingerprints_before $ownerArtifacts) -and
            (Test-ExactPropertySet $receipt.owner_artifact_fingerprints_after $ownerArtifacts) -and
            (Test-ExactPropertySet $receipt.owner_state_readback $ownerReadback) -and
            [string]$receipt.schema -ceq $Script:LifecycleRestoreSchema -and
            [string]$receipt.report_version -ceq $Script:LifecycleRestoreSchema -and
            [string]$receipt.status -ceq 'READY' -and
            [string]$receipt.action -ceq 'REUSED' -and
            [string]$receipt.app_id -ceq 'container_audit' -and
            [string]$receipt.state_scope -ceq 'current_user' -and
            [string]$receipt.session_id -ceq $ExpectedSessionId -and
            [string]$receipt.attempt_id -ceq $ExpectedAttemptId -and
            [string]$receipt.session_started_at_utc -ceq $ExpectedSessionStartedAtUtc -and
            [string]$receipt.orchestrator_sha256 -ceq $ExpectedOrchestratorSha256 -and
            (Test-BootstrapSamePath ([string]$receipt.producer_code_root) $ExpectedProducerRoot) -and
            (ConvertTo-RoundTripUtc ([string]$receipt.session_started_at_utc) 'lifecycle receipt session start') -eq $expectedSessionStart -and
            $captured -ge $expectedSessionStart.AddSeconds(-2) -and
            $completed -ge $captured -and $completed -le [DateTime]::UtcNow.AddSeconds(5) -and
            [string]$receipt.replacement_transaction_id -ceq $ExpectedTransactionId -and
            (Test-BootstrapSamePath ([string]$receipt.replacement_receipt_path) $ExpectedReplacementReceiptPath) -and
            [string]$receipt.replacement_receipt_sha256 -ceq $ExpectedReplacementReceiptSha256 -and
            [string]$receipt.writer_contract_sha256 -ceq $ExpectedContractSha256 -and
            (Test-BootstrapSamePath ([string]$receipt.code_root) $ExpectedCodeRoot) -and
            [int]$receipt.owner_artifact_count -eq 7 -and
            $receipt.owner_state_preserved_exact -is [bool] -and [bool]$receipt.owner_state_preserved_exact -and
            [string]$receipt.containment_status -ceq 'NOT_REQUIRED' -and
            [string]$receipt.failure_code -ceq '' -and
            (Test-ContainerLifecycleExecutionContext $receipt.execution_context) -and
            (Test-ContainerLifecycleMutationEvidence $receipt $root) -and
            (Test-ContainerUserRelayLiveReadback $receipt $root) -and
            [string]$receipt.bootstrap_integrity -ceq 'PASS' -and
            [string]$receipt.release_layout -ceq 'portable_runtime' -and
            $receipt.writer_contract_verified -is [bool] -and [bool]$receipt.writer_contract_verified -and
            [string]$receipt.owner_state_readback.status -ceq 'READY' -and
            [string]$receipt.persistent_relay_principal -ceq 'current_user' -and
            $receipt.system_scheduled_task_required -is [bool] -and -not [bool]$receipt.system_scheduled_task_required -and
            $receipt.registration_attempted -is [bool] -and -not [bool]$receipt.registration_attempted -and
            $receipt.network_attempted -is [bool] -and -not [bool]$receipt.network_attempted -and
            $receipt.ledger_opened -is [bool] -and -not [bool]$receipt.ledger_opened -and
            $receipt.identity_or_credential_copied -is [bool] -and -not [bool]$receipt.identity_or_credential_copied -and
            $receipt.secret_values_recorded -is [bool] -and -not [bool]$receipt.secret_values_recorded -and
            [string]$receipt.failure -ceq ''
        )
        return [pscustomobject][ordered]@{
            status = if ($exact) { 'PASS' } else { 'FAIL' }
            payload = if ($exact) { $receipt } else { $null }
            receipt_path = $receiptPath
            receipt_sha256 = if ($exact) { $ExpectedSha256 } else { '' }
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            status = 'FAIL'
            payload = $null
            receipt_path = $Path
            receipt_sha256 = ''
            failure_type = $_.Exception.GetType().Name
        }
    }
}

function Open-ContainerVerifiedTreeReadLocks([string]$TreeRoot, [string]$DeclaredRoot, $ExpectedIdentity) {
    $root = Get-StrictFullPath $TreeRoot 'verified Container code tree'
    $declared = Get-StrictFullPath $DeclaredRoot 'declared Container install root'
    Assert-NoReparseAncestorChain $root 'verified Container code tree'
    Assert-BootstrapNoReparsePoint $root 'verified Container code tree'
    $entries = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
    foreach ($entry in $entries) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Verified Container code tree contains a reparse point.'
        }
    }
    $files = @($entries | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)
    if ($files.Count -ne [int]$ExpectedIdentity.file_count -or $files.Count -le 0) {
        throw 'Verified Container code tree file cardinality differs.'
    }
    $streams = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
    try {
        foreach ($file in $files) {
            $stream = New-Object IO.FileStream(
                $file.FullName,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            $streams.Add($stream)
        }
        $identity = Get-BootstrapReplacementTreeIdentity $root $declared
        if (-not (Test-BootstrapReplacementTreeIdentity $ExpectedIdentity $identity)) {
            throw 'Verified Container code tree identity differs while read-locked.'
        }
        return [pscustomobject][ordered]@{ root = $root; identity = $identity; streams = @($streams) }
    }
    catch {
        foreach ($stream in $streams) { try { $stream.Dispose() } catch { } }
        throw
    }
}

function Close-ContainerVerifiedTreeReadLocks($LockSet) {
    if ($null -eq $LockSet) { return }
    foreach ($stream in @($LockSet.streams)) { try { $stream.Dispose() } catch { } }
}

function Invoke-ContainerLifecycleRestoreProduct {
    param(
        [string]$ProducerRoot,
        [string]$CanonicalInstallRoot,
        [string]$OutputPath,
        [string]$CurrentSessionId,
        [string]$CurrentAttemptId,
        [string]$CurrentSessionStartedAtUtc,
        [string]$CurrentOrchestratorSha256,
        [string]$CurrentReplacementTransactionId,
        [string]$CurrentContractSha256,
        [string]$ReplacementReceiptPathForBinding,
        [string]$ReplacementReceiptSha256ForBinding
    )
    $producer = Get-StrictFullPath $ProducerRoot 'verified failed-new producer root'
    $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
    $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
    $outputFull = Get-StrictFullPath $OutputPath 'lifecycle restore receipt path'
    Assert-NoReparseAncestorChain $outputFull 'lifecycle restore receipt path'
    if (Test-Path -LiteralPath $outputFull) { throw 'Lifecycle restore receipt path already exists.' }
    if ((Test-PathInside $outputFull $installParent) -or (Test-CanonicalSamePath $outputFull $installParent)) {
        throw 'Lifecycle restore receipt must be outside the mutable install parent.'
    }
    $childExit = -1
    $replacementReceiptLock = $null
    $currentTreeLocks = $null
    $producerTreeLocks = $null
    $lifecycleMutationAttempted = $false
    try {
        $replacementReceiptLock = Open-PinnedReadLock $ReplacementReceiptPathForBinding 1048576 $ReplacementReceiptSha256ForBinding
        $replacement = Read-BoundedJson $ReplacementReceiptPathForBinding 1048576 $ReplacementReceiptSha256ForBinding
        if (
            -not (Test-ReplacementReceiptShape $replacement) -or
            [string]$replacement.transaction_id -cne $CurrentReplacementTransactionId -or
            -not (Test-BootstrapSamePath ([string]$replacement.receipt_path) $ReplacementReceiptPathForBinding) -or
            -not (Test-BootstrapSamePath ([string]$replacement.failed_root) $producer) -or
            -not (Test-ContainerRestoredTreesAgainstReceipt $root $replacement $CurrentReplacementTransactionId)
        ) { throw 'Container lifecycle producer replacement binding is invalid.' }
        $currentTreeLocks = Open-ContainerVerifiedTreeReadLocks $root $root $replacement.old
        $producerTreeLocks = Open-ContainerVerifiedTreeReadLocks $producer $root $replacement.new
        if (-not (Test-ContainerRestoredTreesAgainstReceipt $root $replacement $CurrentReplacementTransactionId)) {
            throw 'Container lifecycle code trees drifted after read locks were acquired.'
        }
        $python = Join-Path $producer 'runtime\python.exe'
        $entry = Join-Path $producer 'app\main.py'
        foreach ($required in @($python, $entry)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'Verified failed-new lifecycle producer is incomplete.' }
            Assert-BootstrapNoReparsePoint $required 'verified failed-new lifecycle producer file'
        }
        Register-ContainerSystemMutationAttempt
        $lifecycleMutationAttempted = $true
        $lines = @(
            & $python -I -B $entry '--restore-current-user-lifecycle-after-replacement' `
                '--app-root' (Join-Path $root 'app') `
                '--code-root' $root `
                '--replacement-transaction-id' $CurrentReplacementTransactionId `
                '--replacement-receipt-path' $ReplacementReceiptPathForBinding `
                '--replacement-receipt-sha256' $ReplacementReceiptSha256ForBinding `
                '--writer-contract-sha256' $CurrentContractSha256 `
                '--report-path' $outputFull `
                '--session-id' $CurrentSessionId `
                '--attempt-id' $CurrentAttemptId `
                '--session-started-at-utc' $CurrentSessionStartedAtUtc `
                '--orchestrator-sha256' $CurrentOrchestratorSha256 2>&1
        )
        $childExit = $LASTEXITCODE
        if (-not (Test-ContainerRestoredTreesAgainstReceipt $root $replacement $CurrentReplacementTransactionId)) {
            throw 'Container lifecycle code trees drifted during producer execution.'
        }
        if ($childExit -ne 0 -or @($lines | ForEach-Object { [string]$_ }) -cnotcontains 'replacement_lifecycle_restore_status=READY') {
            throw 'Container current-user lifecycle producer failed.'
        }
        $actualSha = Get-FileSha256 $outputFull
        $validation = Test-ContainerLifecycleRestoreReceipt $outputFull $actualSha $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $producer $CurrentReplacementTransactionId $ReplacementReceiptPathForBinding $ReplacementReceiptSha256ForBinding $CurrentContractSha256 $root
        if ([string]$validation.status -cne 'PASS') { throw 'Container current-user lifecycle producer receipt is invalid.' }
        return [pscustomobject][ordered]@{ status = 'PASS'; child_exit_code = $childExit; path = $outputFull; sha256 = $actualSha; validation = $validation; containment = $null; failure_type = ''; silently_ignored = $false }
    }
    catch {
        $failureType = $_.Exception.GetType().Name
        Close-ContainerVerifiedTreeReadLocks $producerTreeLocks
        Close-ContainerVerifiedTreeReadLocks $currentTreeLocks
        $producerTreeLocks = $null
        $currentTreeLocks = $null
        if ($null -ne $replacementReceiptLock) { $replacementReceiptLock.Dispose(); $replacementReceiptLock = $null }
        $containment = if ($lifecycleMutationAttempted) {
            Invoke-ContainerLifecycleFailureContainment $producer $root $ReplacementReceiptPathForBinding $ReplacementReceiptSha256ForBinding $CurrentReplacementTransactionId
        } else {
            [pscustomobject][ordered]@{ status = 'NOT_REQUIRED'; child_exit_code = -1; report_path = ''; report_sha256 = ''; failure_type = ''; silently_ignored = $false }
        }
        $observedPath = if (Test-Path -LiteralPath $outputFull -PathType Leaf) { $outputFull } else { '' }
        $observedSha = if ([string]::IsNullOrWhiteSpace($observedPath)) { '' } else { Get-FileSha256 $observedPath }
        return [pscustomobject][ordered]@{
            status = 'FAIL'
            child_exit_code = $childExit
            path = $observedPath
            sha256 = $observedSha
            validation = $null
            containment = $containment
            failure_type = $failureType
            silently_ignored = $false
        }
    }
    finally {
        Close-ContainerVerifiedTreeReadLocks $producerTreeLocks
        Close-ContainerVerifiedTreeReadLocks $currentTreeLocks
        if ($null -ne $replacementReceiptLock) { $replacementReceiptLock.Dispose() }
    }
}

function Invoke-ContainerLifecycleFailureContainment {
    param(
        [string]$ProducerRoot,
        [string]$CanonicalInstallRoot,
        [string]$ReplacementReceiptPathForBinding,
        [string]$ReplacementReceiptSha256ForBinding,
        [string]$CurrentReplacementTransactionId
    )
    $childExit = -1
    $replacementReceiptLock = $null
    $currentTreeLocks = $null
    $producerTreeLocks = $null
    try {
        $producer = Get-StrictFullPath $ProducerRoot 'verified failed-new producer root'
        $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
        Assert-Hex $ReplacementReceiptSha256ForBinding 64 'replacement receipt SHA-256'
        Assert-Hex $CurrentReplacementTransactionId 32 'replacement transaction id'
        $replacementReceiptLock = Open-PinnedReadLock $ReplacementReceiptPathForBinding 1048576 $ReplacementReceiptSha256ForBinding
        $replacement = Read-BoundedJson $ReplacementReceiptPathForBinding 1048576 $ReplacementReceiptSha256ForBinding
        if (
            -not (Test-ReplacementReceiptShape $replacement) -or
            [string]$replacement.transaction_id -cne $CurrentReplacementTransactionId -or
            -not (Test-BootstrapSamePath ([string]$replacement.receipt_path) $ReplacementReceiptPathForBinding) -or
            -not (Test-BootstrapSamePath ([string]$replacement.failed_root) $producer) -or
            -not (Test-ContainerRestoredTreesAgainstReceipt $root $replacement $CurrentReplacementTransactionId)
        ) { throw 'Container containment replacement binding is invalid.' }
        $currentTreeLocks = Open-ContainerVerifiedTreeReadLocks $root $root $replacement.old
        $producerTreeLocks = Open-ContainerVerifiedTreeReadLocks $producer $root $replacement.new
        if (-not (Test-ContainerRestoredTreesAgainstReceipt $root $replacement $CurrentReplacementTransactionId)) {
            throw 'Container containment code trees drifted after read locks were acquired.'
        }
        $python = Join-Path $producer 'runtime\python.exe'
        $entry = Join-Path $producer 'app\main.py'
        foreach ($required in @($python, $entry)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'Verified failed-new containment producer is incomplete.' }
            Assert-BootstrapNoReparsePoint $required 'verified failed-new containment producer file'
        }
        Register-ContainerSystemMutationAttempt
        $lines = @(& $python -I -B $entry '--remove-current-user-setup' '--app-root' (Join-Path $root 'app') 2>&1)
        $childExit = $LASTEXITCODE
        if (-not (Test-ContainerRestoredTreesAgainstReceipt $root $replacement $CurrentReplacementTransactionId)) {
            throw 'Container containment code trees drifted during producer execution.'
        }
        $strings = @($lines | ForEach-Object { [string]$_ })
        $reportLine = @($strings | Where-Object { $_.StartsWith('removal_report=', [StringComparison]::Ordinal) })
        if ($childExit -ne 0 -or $strings -cnotcontains 'removal_status=PASS_DATA_PRESERVED' -or $reportLine.Count -ne 1) {
            throw 'Container lifecycle failure containment producer failed.'
        }
        $reportPath = $reportLine[0].Substring('removal_report='.Length)
        $report = Read-BoundedJson $reportPath 1048576
        $exact = (
            [string]$report.report_version -ceq 'container-audit-current-user-removal-v1' -and
            [string]$report.status -ceq 'PASS_DATA_PRESERVED' -and
            [string]$report.state_scope -ceq 'current_user' -and
            $report.data_preserved -is [bool] -and [bool]$report.data_preserved -and
            (Test-BootstrapSamePath ([string]$report.machine_code_root) (Join-Path $root 'app')) -and
            [string]$report.relay_autostart.status -ceq 'ABSENT' -and
            [string]$report.relay_process.status -ceq 'ABSENT' -and
            [string]$report.failure -ceq ''
        )
        if (-not $exact) { throw 'Container lifecycle failure containment readback is invalid.' }
        return [pscustomobject][ordered]@{ status = 'PASS'; child_exit_code = $childExit; report_path = (Get-StrictFullPath $reportPath 'containment report path'); report_sha256 = Get-FileSha256 $reportPath; failure_type = ''; silently_ignored = $false }
    }
    catch {
        return [pscustomobject][ordered]@{ status = 'FAIL'; child_exit_code = $childExit; report_path = ''; report_sha256 = ''; failure_type = $_.Exception.GetType().Name; silently_ignored = $false }
    }
    finally {
        Close-ContainerVerifiedTreeReadLocks $producerTreeLocks
        Close-ContainerVerifiedTreeReadLocks $currentTreeLocks
        if ($null -ne $replacementReceiptLock) { $replacementReceiptLock.Dispose() }
    }
}

function Invoke-ContainerWriterRestore {
    param(
        [string]$CanonicalInstallRoot,
        [string]$OutputPath,
        [string]$CurrentSessionId,
        [string]$CurrentAttemptId,
        [string]$CurrentSessionStartedAtUtc,
        [string]$CurrentOrchestratorSha256,
        [string]$CurrentReplacementTransactionId,
        [string]$CurrentContractSha256,
        [string]$PreparedPath,
        [string]$PreparedSha256,
        [string]$CapabilitySha256,
        [string]$CodeRestoreEvidencePath,
        [string]$CodeRestoreEvidenceSha256,
        [string]$LifecycleReceiptPath,
        [string]$LifecycleReceiptSha256,
        [string]$ReplacementReceiptPathForBinding,
        [string]$ReplacementReceiptSha256ForBinding
    )
    $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
    $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
    $preparedFull = Get-StrictFullPath $PreparedPath 'prepared receipt path'
    $codeRestoreFull = Get-StrictFullPath $CodeRestoreEvidencePath 'code restore evidence path'
    $lifecycleFull = Get-StrictFullPath $LifecycleReceiptPath 'lifecycle restore receipt path'
    $replacementFull = Get-StrictFullPath $ReplacementReceiptPathForBinding 'replacement receipt path'
    foreach ($externalPath in @($preparedFull, $codeRestoreFull, $lifecycleFull, $replacementFull)) {
        Assert-NoReparseAncestorChain $externalPath 'writer restore input path'
        if ((Test-PathInside $externalPath $installParent) -or (Test-CanonicalSamePath $externalPath $installParent)) {
            throw 'Writer restore paths must be outside the mutable install parent.'
        }
    }
    $outputFull = ''
    $outputPathSafe = $false
    $outputPathFailure = ''
    try {
        $outputCandidate = Get-StrictFullPath $OutputPath 'writer restore evidence path'
        Assert-NoReparseAncestorChain $outputCandidate 'writer restore evidence path'
        if (Test-Path -LiteralPath $outputCandidate) { throw 'Writer restore evidence path already exists.' }
        if ((Test-PathInside $outputCandidate $installParent) -or (Test-CanonicalSamePath $outputCandidate $installParent)) {
            throw 'Writer restore paths must be outside the mutable install parent.'
        }
        $outputFull = $outputCandidate
        $outputPathSafe = $true
    }
    catch { $outputPathFailure = $_.Exception.Message }
    $record = if ($outputPathSafe) {
        [ordered]@{
            schema = $Script:RestoredSchema
            status = 'IN_PROGRESS'
            app_id = 'container_audit'
            session_id = $CurrentSessionId
            attempt_id = $CurrentAttemptId
            replacement_transaction_id = $CurrentReplacementTransactionId
            session_started_at_utc = $CurrentSessionStartedAtUtc
            orchestrator_sha256 = $CurrentOrchestratorSha256
            adapter_sha256 = $Script:AdapterSha256
            contract_sha256 = $CurrentContractSha256
            evidence_path = $outputFull
            prepared_receipt = [ordered]@{ path = $preparedFull; sha256 = $PreparedSha256 }
            code_restore_evidence = [ordered]@{ path = $codeRestoreFull; sha256 = $CodeRestoreEvidenceSha256 }
            lifecycle_restore_receipt = [ordered]@{ path = $lifecycleFull; sha256 = $LifecycleReceiptSha256 }
            started_at_utc = [DateTime]::UtcNow.ToString('o')
            completed_at_utc = ''
            secret_values_recorded = $false
            enable = [ordered]@{ status = 'NOT_RUN'; pre_readback = $null; post_readback = $null; binding_unchanged = $false }
            survival = [ordered]@{ status = 'NOT_RUN'; nominal_next_run_utc = ''; observed_last_run_time_utc = ''; last_run_time_advanced = $false; last_task_result_zero = $false; binding_unchanged = $false; log_effect_observed = $false; runtime_status_effect_observed = $false; manual_start_used = $false }
            failure = [ordered]@{ status = 'NONE'; stage = ''; code = ''; failure_type = ''; silently_ignored = $false; safety_fence = $null; lifecycle_containment = $null }
        }
    }
    else { $null }
    if (-not $outputPathSafe) { throw "Writer restore evidence path is not safe: $outputPathFailure" }
    $stage = 'DIRECT_RESTORE_PROVENANCE'
    $prepared = $null
    $binding = ''
    $producerRoot = ''
    $producerTrusted = $false
    $containmentAuthorized = $false
    $lifecycleValidated = $false
    try {
        $replacementReceipt = Read-BoundedJson $replacementFull 1048576 $ReplacementReceiptSha256ForBinding
        if (
            -not (Test-ReplacementReceiptShape $replacementReceipt) -or
            [string]$replacementReceipt.transaction_id -cne $CurrentReplacementTransactionId -or
            -not (Test-BootstrapSamePath ([string]$replacementReceipt.receipt_path) $replacementFull) -or
            -not (Test-ContainerRestoredTreesAgainstReceipt $root $replacementReceipt $CurrentReplacementTransactionId)
        ) { throw 'Transaction-bound replacement receipt or live tree readback is invalid.' }
        $producerRoot = [string]$replacementReceipt.failed_root
        $codeRestore = Test-RestoreEvidence $codeRestoreFull $CodeRestoreEvidenceSha256 $CurrentReplacementTransactionId $replacementFull $ReplacementReceiptSha256ForBinding $root $producerRoot $CurrentSessionStartedAtUtc
        if ([string]$codeRestore.status -cne 'PASS') { throw 'Transaction-bound code restore evidence is invalid.' }
        $producerTrusted = $true
        $validation = Test-ContainerPreparedReceipt $root $preparedFull $PreparedSha256 $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $CurrentReplacementTransactionId $CurrentContractSha256 $CapabilitySha256 -RequireLiveDisabled
        if ([string]$validation.status -cne 'PASS' -or -not [bool]$validation.live_disabled_exact) { throw 'Prepared receipt or live-disabled readback is invalid.' }
        $prepared = $validation.payload
        $binding = [string]$prepared.pre_readback.identity.binding_sha256
        $containmentAuthorized = $producerTrusted
        $lifecycle = Test-ContainerLifecycleRestoreReceipt $lifecycleFull $LifecycleReceiptSha256 $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $producerRoot $CurrentReplacementTransactionId $replacementFull $ReplacementReceiptSha256ForBinding $CurrentContractSha256 $root
        if (
            [string]$lifecycle.status -cne 'PASS' -or
            -not (Test-BootstrapReplacementTreeIdentity $replacementReceipt.old $lifecycle.payload.restored_code_identity) -or
            -not (Test-BootstrapReplacementTreeIdentity $replacementReceipt.new $lifecycle.payload.failed_new_code_identity) -or
            -not (Test-ContainerRestoreTemporalOrder $prepared $replacementReceipt $codeRestore.payload $lifecycle.payload)
        ) { throw 'Transaction-bound current-user lifecycle restore receipt is invalid.' }
        $lifecycleValidated = $true
        [void](Write-JsonAtomic $outputFull $record)
    }
    catch {
        $preflightFailureType = $_.Exception.GetType().Name
        $safetyStatus = 'NOT_AVAILABLE'
        $containmentStatus = 'NOT_AVAILABLE'
        $safetyResult = $null
        $containmentResult = $null
        if (-not [string]::IsNullOrWhiteSpace($binding)) {
            $safetyResult = Invoke-ContainerWriterSafetyFence $root $binding 'DIRECT_RESTORE_PREFLIGHT_FAILED_RETAIN_DISABLED'
            $safetyStatus = [string]$safetyResult.status
        }
        if ($containmentAuthorized -and $producerTrusted -and -not [string]::IsNullOrWhiteSpace($producerRoot)) {
            $containmentResult = Invoke-ContainerLifecycleFailureContainment $producerRoot $root $replacementFull $ReplacementReceiptSha256ForBinding $CurrentReplacementTransactionId
            $containmentStatus = [string]$containmentResult.status
        }
        if ($outputPathSafe -and $null -ne $record) {
            $record.status = 'FAIL'
            $record.failure.status = 'FAIL'
            $record.failure.stage = 'DIRECT_RESTORE_PREFLIGHT'
            $record.failure.code = 'CONTAINER_WRITER_DIRECT_PREFLIGHT_FAILED'
            $record.failure.failure_type = $preflightFailureType
            $record.failure.safety_fence = $safetyResult
            $record.failure.lifecycle_containment = $containmentResult
            $record.completed_at_utc = [DateTime]::UtcNow.ToString('o')
            try {
                $receiptRecord = Write-JsonAtomic $outputFull $record
                return [pscustomobject][ordered]@{ status = 'FAIL'; record = $receiptRecord; payload = [pscustomobject]$record }
            }
            catch {
                throw "Container writer direct restore preflight evidence failed; writer_fence=$safetyStatus; lifecycle_containment=$containmentStatus."
            }
        }
        throw "Container writer direct restore preflight failed; writer_fence=$safetyStatus; lifecycle_containment=$containmentStatus."
    }
    $stage = 'PREPARED_RECEIPT_VALIDATION'
    try {
        $validation = Test-ContainerPreparedReceipt $root $preparedFull $PreparedSha256 $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $CurrentReplacementTransactionId $CurrentContractSha256 $CapabilitySha256 -RequireLiveDisabled
        if ([string]$validation.status -cne 'PASS' -or -not [bool]$validation.live_disabled_exact) { throw 'Prepared receipt or live-disabled readback is invalid.' }
        $prepared = $validation.payload
        $binding = [string]$prepared.pre_readback.identity.binding_sha256
        $stage = 'REPLACEMENT_RECEIPT_VALIDATION'
        $replacementReceipt = Read-BoundedJson $replacementFull 1048576 $ReplacementReceiptSha256ForBinding
        if (
            -not (Test-ReplacementReceiptShape $replacementReceipt) -or
            [string]$replacementReceipt.transaction_id -cne $CurrentReplacementTransactionId -or
            -not (Test-BootstrapSamePath ([string]$replacementReceipt.receipt_path) $replacementFull)
        ) {
            throw 'Transaction-bound replacement receipt is invalid.'
        }
        $producerRoot = [string]$replacementReceipt.failed_root
        $stage = 'CODE_RESTORE_RECEIPT_VALIDATION'
        $codeRestore = Test-RestoreEvidence $codeRestoreFull $CodeRestoreEvidenceSha256 $CurrentReplacementTransactionId $replacementFull $ReplacementReceiptSha256ForBinding $root $producerRoot $CurrentSessionStartedAtUtc
        if ([string]$codeRestore.status -cne 'PASS' -or -not (Test-ContainerRestoredTreesAgainstReceipt $root $replacementReceipt $CurrentReplacementTransactionId)) {
            throw 'Transaction-bound code restore evidence or live tree readback is invalid.'
        }
        $stage = 'LIFECYCLE_RESTORE_RECEIPT_VALIDATION'
        $lifecycle = Test-ContainerLifecycleRestoreReceipt $lifecycleFull $LifecycleReceiptSha256 $CurrentSessionId $CurrentAttemptId $CurrentSessionStartedAtUtc $CurrentOrchestratorSha256 $producerRoot $CurrentReplacementTransactionId $replacementFull $ReplacementReceiptSha256ForBinding $CurrentContractSha256 $root
        if (
            [string]$lifecycle.status -cne 'PASS' -or
            -not (Test-BootstrapReplacementTreeIdentity $replacementReceipt.old $lifecycle.payload.restored_code_identity) -or
            -not (Test-BootstrapReplacementTreeIdentity $replacementReceipt.new $lifecycle.payload.failed_new_code_identity) -or
            -not (Test-ContainerRestoredTreesAgainstReceipt $root $replacementReceipt $CurrentReplacementTransactionId) -or
            -not (Test-ContainerRestoreTemporalOrder $prepared $replacementReceipt $codeRestore.payload $lifecycle.payload)
        ) { throw 'Transaction-bound current-user lifecycle restore receipt or live tree readback is invalid.' }
        $lifecycleValidated = $true
        $enablePreReadback = Get-ContainerWriterReadback $CanonicalInstallRoot
        $record.enable.pre_readback = $enablePreReadback
        if (-not (Test-ContainerWriterDisabledBeforeEnable $enablePreReadback $binding)) {
            throw 'Container writer drifted before enable.'
        }
        if (-not (Test-ContainerUserRelayLiveReadback $lifecycle.payload $root)) {
            throw 'Container current-user relay drifted before writer enable.'
        }
        $stage = 'ENABLE'
        Register-ContainerSystemMutationAttempt
        Enable-ScheduledTask -TaskName $Script:TaskName -TaskPath $Script:TaskPath -ErrorAction Stop | Out-Null
        $futureReadback = $null
        $futureReady = Wait-ContainerCondition -TimeoutSeconds 90 -Predicate {
            $candidate = Get-ContainerWriterReadback $CanonicalInstallRoot
            if (
                -not [bool]$candidate.enabled -or [string]$candidate.state -cne 'Ready' -or
                [string]$candidate.identity.binding_sha256 -cne $binding -or
                [int]$candidate.exact_writer_process_count -ne 0
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
                if (
                    (ConvertTo-RoundTripUtc ([string]$candidate.last_run_time_utc) 'observed last run') -ge $nominal -and
                    [int64]$candidate.last_task_result -eq 0 -and [bool]$candidate.enabled -and
                    [string]$candidate.state -ceq 'Ready' -and [int]$candidate.exact_writer_process_count -eq 0 -and
                    [string]$candidate.identity.binding_sha256 -ceq $binding
                ) {
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
        if ($lifecycleValidated -and -not [string]::IsNullOrWhiteSpace($producerRoot)) {
            $record.failure.lifecycle_containment = Invoke-ContainerLifecycleFailureContainment $producerRoot $root $replacementFull $ReplacementReceiptSha256ForBinding $CurrentReplacementTransactionId
        }
    }
    $record.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    try {
        $receiptRecord = Write-JsonAtomic $outputFull $record -AllowReplace
    }
    catch {
        $persistenceFailureType = $_.Exception.GetType().Name
        $record.status = 'FAIL'
        $record.failure.status = 'FAIL'
        $record.failure.stage = 'FINAL_EVIDENCE_PERSISTENCE'
        $record.failure.code = 'CONTAINER_WRITER_FINAL_EVIDENCE_FAILED'
        $record.failure.failure_type = $persistenceFailureType
        if ($null -eq $record.failure.safety_fence -and -not [string]::IsNullOrWhiteSpace($binding)) {
            $record.failure.safety_fence = Invoke-ContainerWriterSafetyFence $CanonicalInstallRoot $binding 'FINAL_EVIDENCE_FAILED_RETAIN_DISABLED'
        }
        if ($null -eq $record.failure.lifecycle_containment -and $lifecycleValidated -and -not [string]::IsNullOrWhiteSpace($producerRoot)) {
            $record.failure.lifecycle_containment = Invoke-ContainerLifecycleFailureContainment $producerRoot $root $replacementFull $ReplacementReceiptSha256ForBinding $CurrentReplacementTransactionId
        }
        $record.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        try { [void](Write-JsonAtomic $outputFull $record -AllowReplace) } catch { }
        throw 'Container writer final evidence persistence failed after safety containment.'
    }
    return [pscustomobject][ordered]@{ status = [string]$record.status; record = $receiptRecord; payload = [pscustomobject]$record }
}

function Invoke-RecoveryStateMachine([scriptblock]$CodeRestoreAction, [scriptblock]$LifecycleRestoreAction, [scriptblock]$WriterRestoreAction) {
    try { $code = & $CodeRestoreAction }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'CODE_RESTORE_FAILED'; code_restore = [pscustomobject][ordered]@{ status = 'FAIL'; failure_type = $_.Exception.GetType().Name; silently_ignored = $false }; lifecycle_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'CODE_RESTORE_NOT_PROVEN' }; writer_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'CODE_RESTORE_NOT_PROVEN' } } }
    if ($null -eq $code -or [string]$code.status -cne 'PASS') {
        return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'CODE_RESTORE_FAILED'; code_restore = $code; lifecycle_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'CODE_RESTORE_NOT_PROVEN' }; writer_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'CODE_RESTORE_NOT_PROVEN' } }
    }
    try { $lifecycle = & $LifecycleRestoreAction }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'LIFECYCLE_RESTORE_FAILED'; code_restore = $code; lifecycle_restore = [pscustomobject][ordered]@{ status = 'FAIL'; failure_type = $_.Exception.GetType().Name; silently_ignored = $false }; writer_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'LIFECYCLE_RESTORE_NOT_PROVEN' } } }
    if ($null -eq $lifecycle -or [string]$lifecycle.status -cne 'PASS') {
        return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'LIFECYCLE_RESTORE_FAILED'; code_restore = $code; lifecycle_restore = $lifecycle; writer_restore = [pscustomobject][ordered]@{ status = 'NOT_RUN'; reason = 'LIFECYCLE_RESTORE_NOT_PROVEN' } }
    }
    try { $writer = & $WriterRestoreAction }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'WRITER_RESTORE_FAILED'; code_restore = $code; lifecycle_restore = $lifecycle; writer_restore = [pscustomobject][ordered]@{ status = 'FAIL'; failure_type = $_.Exception.GetType().Name; silently_ignored = $false } } }
    if ($null -eq $writer -or [string]$writer.status -cne 'PASS') {
        return [pscustomobject][ordered]@{ status = 'FAIL'; failure_code = 'WRITER_RESTORE_FAILED'; code_restore = $code; lifecycle_restore = $lifecycle; writer_restore = $writer }
    }
    return [pscustomobject][ordered]@{ status = 'PASS'; failure_code = ''; code_restore = $code; lifecycle_restore = $lifecycle; writer_restore = $writer }
}

function Test-RestoreEvidencePayload($Evidence, [string]$TransactionId, [string]$ReceiptPath, [string]$ReceiptSha256, [string]$CanonicalInstallRoot, [string]$ExpectedFailedNewRoot, [string]$ExpectedSessionStartedAtUtc) {
    try {
        $top = @('schema_version','status','action','app_id','transaction_id','receipt_path','receipt_sha256','install_root','failed_new_root','prior_code_exact','failed_new_preserved','identity_or_credential_copied','completed_at')
        $sessionStarted = Assert-CurrentSessionWindow $ExpectedSessionStartedAtUtc
        $completed = ConvertTo-RoundTripUtc ([string]$Evidence.completed_at) 'code restore evidence completion'
        return (
            (Test-ExactPropertySet $Evidence $top) -and
            [string]$Evidence.schema_version -ceq 'container-audit-verified-replacement-code-restore-v1' -and
            [string]$Evidence.status -ceq 'PASS' -and
            [string]$Evidence.action -in @('RESTORED','ALREADY_RESTORED') -and
            [string]$Evidence.app_id -ceq 'container_audit' -and
            [string]$Evidence.transaction_id -ceq $TransactionId -and
            (Test-BootstrapSamePath ([string]$Evidence.receipt_path) $ReceiptPath) -and
            [string]$Evidence.receipt_sha256 -ceq $ReceiptSha256 -and
            (Test-BootstrapSamePath ([string]$Evidence.install_root) $CanonicalInstallRoot) -and
            (Test-BootstrapSamePath ([string]$Evidence.failed_new_root) $ExpectedFailedNewRoot) -and
            $Evidence.prior_code_exact -is [bool] -and [bool]$Evidence.prior_code_exact -and
            $Evidence.failed_new_preserved -is [bool] -and [bool]$Evidence.failed_new_preserved -and
            $Evidence.identity_or_credential_copied -is [bool] -and -not [bool]$Evidence.identity_or_credential_copied -and
            $completed -ge $sessionStarted.AddSeconds(-2) -and $completed -le [DateTime]::UtcNow.AddSeconds(5)
        )
    }
    catch { return $false }
}

function Test-RestoreEvidence([string]$Path, [string]$ExpectedSha256, [string]$TransactionId, [string]$ReceiptPath, [string]$ReceiptSha256, [string]$CanonicalInstallRoot, [string]$ExpectedFailedNewRoot, [string]$ExpectedSessionStartedAtUtc) {
    try {
        Assert-Hex $ExpectedSha256 64 'code restore evidence SHA-256'
        $evidence = Read-BoundedJson $Path 262144 $ExpectedSha256
        $exact = Test-RestoreEvidencePayload $evidence $TransactionId $ReceiptPath $ReceiptSha256 $CanonicalInstallRoot $ExpectedFailedNewRoot $ExpectedSessionStartedAtUtc
        return [pscustomobject][ordered]@{ status = if ($exact) { 'PASS' } else { 'FAIL' }; path = (Get-StrictFullPath $Path 'restore evidence path'); sha256 = if ($exact) { $ExpectedSha256 } else { '' }; payload = if ($exact) { $evidence } else { $null } }
    }
    catch { return [pscustomobject][ordered]@{ status = 'FAIL'; path = $Path; sha256 = ''; payload = $null; failure_type = $_.Exception.GetType().Name } }
}

function Test-ContainerRestoreTemporalOrder($Prepared, $Replacement, $CodeRestore, $Lifecycle) {
    try {
        if (-not (Test-ContainerPreparedBeforeReplacement $Prepared $Replacement)) { return $false }
        if (-not (Test-ContainerReplacementBeforeCode $Replacement $CodeRestore)) { return $false }
        $codeCompleted = ConvertTo-RoundTripUtc ([string]$CodeRestore.completed_at) 'code restore completion'
        $lifecycleCaptured = ConvertTo-RoundTripUtc ([string]$Lifecycle.captured_at) 'lifecycle restore capture'
        $lifecycleCompleted = ConvertTo-RoundTripUtc ([string]$Lifecycle.completed_at) 'lifecycle restore completion'
        return (
            $lifecycleCaptured -ge $codeCompleted.Subtract($Script:EvidenceClockTolerance) -and
            $lifecycleCompleted -ge $lifecycleCaptured
        )
    }
    catch { return $false }
}

function Test-ContainerPreparedBeforeReplacement($Prepared, $Replacement) {
    try {
        $preparedCompleted = ConvertTo-RoundTripUtc ([string]$Prepared.completed_at_utc) 'prepared receipt completion'
        $replacementCreated = ConvertTo-RoundTripUtc ([string]$Replacement.created_at) 'replacement receipt creation'
        return $replacementCreated -ge $preparedCompleted.Subtract($Script:EvidenceClockTolerance)
    }
    catch { return $false }
}

function Test-ContainerReplacementBeforeCode($Replacement, $CodeRestore) {
    try {
        $replacementCreated = ConvertTo-RoundTripUtc ([string]$Replacement.created_at) 'replacement receipt creation'
        $codeCompleted = ConvertTo-RoundTripUtc ([string]$CodeRestore.completed_at) 'code restore completion'
        return $codeCompleted -ge $replacementCreated.Subtract($Script:EvidenceClockTolerance)
    }
    catch { return $false }
}

function Test-ContainerRestoredTreesAgainstReceipt([string]$CanonicalInstallRoot, $Receipt, [string]$ExpectedTransactionId) {
    try {
        Assert-Hex $ExpectedTransactionId 32 'replacement transaction id'
        $root = Get-StrictFullPath $CanonicalInstallRoot 'Container install root'
        $parent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
        $failed = Get-StrictFullPath ([string]$Receipt.failed_root) 'failed-new root'
        $rollback = Get-StrictFullPath ([string]$Receipt.rollback_root) 'rollback root'
        if (
            -not (Test-BootstrapSamePath ([string]$Receipt.install_root) $root) -or
            -not (Test-BootstrapSamePath ([string]$Receipt.install_parent) $parent) -or
            -not (Test-BootstrapSamePath (Split-Path -Parent $failed) $parent) -or
            -not (Test-BootstrapSamePath (Split-Path -Parent $rollback) $parent) -or
            [IO.Path]::GetFileName($failed) -cne ".current.failed.$ExpectedTransactionId" -or
            [IO.Path]::GetFileName($rollback) -cne ".current.rollback.$ExpectedTransactionId" -or
            -not (Test-Path -LiteralPath $root -PathType Container) -or
            -not (Test-Path -LiteralPath $failed -PathType Container) -or
            (Test-Path -LiteralPath $rollback)
        ) { return $false }
        Assert-BootstrapNoReparsePoint $parent 'Container install parent'
        $parentAcl = Get-BootstrapAclIdentity $parent
        if (
            $Receipt.parent_acl.access_rules_protected -isnot [bool] -or
            [string]$Receipt.parent_acl.owner_sid -cne [string]$parentAcl.owner_sid -or
            [bool]$Receipt.parent_acl.access_rules_protected -ne [bool]$parentAcl.access_rules_protected -or
            [string]$Receipt.parent_acl.sddl_sha256 -cne [string]$parentAcl.sddl_sha256
        ) { return $false }
        $currentIdentity = Get-BootstrapReplacementTreeIdentity $root $root
        $failedIdentity = Get-BootstrapReplacementTreeIdentity $failed $root
        if (
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.old $currentIdentity) -or
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
        ) { return $false }
        $siblings = @(Get-ChildItem -LiteralPath $parent -Directory -Force | Where-Object { $_.Name -match '^\.current\.(rollback|failed)\.' })
        return ($siblings.Count -eq 1 -and (Test-BootstrapSamePath $siblings[0].FullName $failed))
    }
    catch { return $false }
}

function Invoke-ContainerRecovery {
    $root = Get-StrictFullPath $InstallRoot 'Container install root'
    $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
    if (-not [string]::IsNullOrWhiteSpace($LifecycleRestoreReceiptSha256)) {
        throw 'Recover derives the lifecycle restore receipt SHA-256 after production.'
    }
    if (-not [string]::IsNullOrWhiteSpace($RestoreEvidenceSha256)) {
        throw 'Recover derives the code restore evidence SHA-256 after production.'
    }
    $combinedPath = Get-StrictFullPath $EvidencePath 'combined recovery evidence path'
    $codeRestorePath = Get-StrictFullPath $RestoreEvidencePath 'code restore evidence path'
    $lifecycleRestorePath = Get-StrictFullPath $LifecycleRestoreReceiptPath 'lifecycle restore receipt path'
    $writerRestorePath = Get-StrictFullPath $WriterRestoreEvidencePath 'writer restore evidence path'
    $outputPaths = @($combinedPath, $codeRestorePath, $lifecycleRestorePath, $writerRestorePath)
    foreach ($outputPath in $outputPaths) {
        Assert-NoReparseAncestorChain $outputPath 'recovery output path'
        if (Test-Path -LiteralPath $outputPath) {
            throw 'Recovery output paths must be absent, pairwise distinct, and outside the mutable install parent.'
        }
        if ((Test-PathInside $outputPath $installParent) -or (Test-CanonicalSamePath $outputPath $installParent)) {
            throw 'Recovery output paths must be absent, pairwise distinct, and outside the mutable install parent.'
        }
    }
    for ($left = 0; $left -lt $outputPaths.Count; $left++) {
        for ($right = $left + 1; $right -lt $outputPaths.Count; $right++) {
            if (Test-CanonicalSamePath $outputPaths[$left] $outputPaths[$right]) {
                throw 'Recovery output paths must be absent, pairwise distinct, and outside the mutable install parent.'
            }
        }
    }
    $combined = [ordered]@{
        schema = $Script:RecoverySchema
        status = 'IN_PROGRESS'
        failure_code = ''
        session_id = $SessionId
        attempt_id = $AttemptId
        session_started_at_utc = $SessionStartedAtUtc
        orchestrator_sha256 = $OrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        contract_sha256 = $ExpectedContractSha256
        evidence_path = $combinedPath
        replacement_transaction_id = $ReplacementTransactionId
        prepared_receipt = [ordered]@{ path = (Get-StrictFullPath $PreparedReceiptPath 'prepared receipt path'); sha256 = $PreparedReceiptSha256 }
        replacement_receipt = [ordered]@{ path = (Get-StrictFullPath $ReplacementReceiptPath 'replacement receipt path'); sha256 = $ReplacementReceiptSha256 }
        lifecycle_restore_receipt = [ordered]@{ path = $lifecycleRestorePath; sha256 = '' }
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        completed_at_utc = ''
        secret_values_recorded = $false
        code_restore = [ordered]@{ status = 'NOT_RUN' }
        lifecycle_restore = [ordered]@{ status = 'NOT_RUN' }
        writer_restore = [ordered]@{ status = 'NOT_RUN' }
        persistence_failure = [ordered]@{ status = 'NONE'; failure_type = ''; safety_fence = $null; lifecycle_containment = $null }
        mutation_silently_ignored = $false
    }
    [void](Write-JsonAtomic $combinedPath $combined)
    $preparedValidation = Test-ContainerPreparedReceipt $InstallRoot $PreparedReceiptPath $PreparedReceiptSha256 $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $HistoricalReceiptSha256 -RequireLiveDisabled
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
    if (-not (Test-ContainerPreparedBeforeReplacement $preparedValidation.payload $replacementValidation.payload)) {
        $combined.status = 'FAIL'; $combined.failure_code = 'RESTORE_TEMPORAL_ORDER_INVALID'; $combined.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        [void](Write-JsonAtomic $combinedPath $combined -AllowReplace)
        return [pscustomobject][ordered]@{ status = 'FAIL'; record = [pscustomobject][ordered]@{ path = $combinedPath; sha256 = Get-FileSha256 $combinedPath }; payload = [pscustomobject]$combined }
    }
    $Script:ContainerRecoveryCodeEvidenceSha = $null
    $Script:ContainerRecoveryLifecycleEvidenceSha = $null
    $flow = Invoke-RecoveryStateMachine -CodeRestoreAction {
        $powerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $helperLock = $null
        $integrityLock = $null
        $replacementReceiptLock = $null
        try {
            $helperLock = Open-PinnedReadLock $HelperPath 1048576 $ExpectedHelperSha256
            $integrityLock = Open-PinnedReadLock $Script:IntegrityHelperPath 1048576 ([string]$replacementValidation.payload.integrity_helper_sha256)
            $replacementReceiptLock = Open-PinnedReadLock $ReplacementReceiptPath 1048576 $ReplacementReceiptSha256
            Register-ContainerSystemMutationAttempt
            & $powerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $HelperPath `
                -InstallRoot $InstallRoot `
                -RestoreVerifiedReplacement `
                -ReplacementTransactionId $ReplacementTransactionId `
                -ReplacementReceiptPath $ReplacementReceiptPath `
                -ReplacementReceiptSha256 $ReplacementReceiptSha256 `
                -RestoreEvidencePath $codeRestorePath | Out-Null
            $childExit = $LASTEXITCODE
            if ((Get-FileSha256 $HelperPath) -cne $ExpectedHelperSha256) { throw 'Container helper pin changed during restore execution.' }
            if ((Get-FileSha256 $Script:IntegrityHelperPath) -cne [string]$replacementValidation.payload.integrity_helper_sha256) { throw 'Container integrity helper pin changed during restore execution.' }
        }
        finally {
            if ($null -ne $replacementReceiptLock) { $replacementReceiptLock.Dispose() }
            if ($null -ne $integrityLock) { $integrityLock.Dispose() }
            if ($null -ne $helperLock) { $helperLock.Dispose() }
        }
        $actualRestoreSha = Get-FileSha256 $codeRestorePath
        $evidence = Test-RestoreEvidence $codeRestorePath $actualRestoreSha $ReplacementTransactionId $ReplacementReceiptPath $ReplacementReceiptSha256 $root ([string]$replacementValidation.payload.failed_root) $SessionStartedAtUtc
        $liveTreesExact = Test-ContainerRestoredTreesAgainstReceipt $root $replacementValidation.payload $ReplacementTransactionId
        $temporalOrderExact = ([string]$evidence.status -ceq 'PASS' -and (Test-ContainerReplacementBeforeCode $replacementValidation.payload $evidence.payload))
        if ($childExit -eq 0 -and [string]$evidence.status -ceq 'PASS' -and $liveTreesExact -and $temporalOrderExact) { $Script:ContainerRecoveryCodeEvidenceSha = $actualRestoreSha }
        return [pscustomobject][ordered]@{
            status = if ($childExit -eq 0 -and [string]$evidence.status -ceq 'PASS' -and $liveTreesExact -and $temporalOrderExact) { 'PASS' } else { 'FAIL' }
            child_exit_code = $childExit
            evidence = $evidence
            live_trees_exact = $liveTreesExact
            temporal_order_exact = $temporalOrderExact
            silently_ignored = $false
        }
    } -LifecycleRestoreAction {
        $lifecycle = Invoke-ContainerLifecycleRestoreProduct ([string]$replacementValidation.payload.failed_root) $root $lifecycleRestorePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $ReplacementReceiptPath $ReplacementReceiptSha256
        $Script:ContainerRecoveryLifecycleEvidenceSha = [string]$lifecycle.sha256
        return [pscustomobject][ordered]@{ status = [string]$lifecycle.status; evidence = [pscustomobject][ordered]@{ path = [string]$lifecycle.path; sha256 = [string]$lifecycle.sha256 }; child_exit_code = [int]$lifecycle.child_exit_code; containment = $lifecycle.containment; failure_type = [string]$lifecycle.failure_type; silently_ignored = $false }
    } -WriterRestoreAction {
        try {
            $restored = Invoke-ContainerWriterRestore $root $writerRestorePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $PreparedReceiptPath $PreparedReceiptSha256 $HistoricalReceiptSha256 $codeRestorePath ([string]$Script:ContainerRecoveryCodeEvidenceSha) $lifecycleRestorePath ([string]$Script:ContainerRecoveryLifecycleEvidenceSha) $ReplacementReceiptPath $ReplacementReceiptSha256
            return [pscustomobject][ordered]@{ status = [string]$restored.status; evidence = $restored.record; silently_ignored = $false }
        }
        catch {
            $preparedBinding = [string]$preparedValidation.payload.pre_readback.identity.binding_sha256
            $safetyFence = Invoke-ContainerWriterSafetyFence $root $preparedBinding 'WRITER_RESTORE_EXCEPTION_RETAIN_DISABLED'
            $lifecycleContainment = Invoke-ContainerLifecycleFailureContainment ([string]$replacementValidation.payload.failed_root) $root $ReplacementReceiptPath $ReplacementReceiptSha256 $ReplacementTransactionId
            return [pscustomobject][ordered]@{
                status = 'FAIL'
                failure_type = $_.Exception.GetType().Name
                safety_fence = $safetyFence
                lifecycle_containment = $lifecycleContainment
                silently_ignored = $false
            }
        }
    }
    $combined.status = [string]$flow.status
    $combined.failure_code = [string]$flow.failure_code
    $combined.code_restore = $flow.code_restore
    $combined.lifecycle_restore = $flow.lifecycle_restore
    $combined.writer_restore = $flow.writer_restore
    if (-not [string]::IsNullOrWhiteSpace([string]$Script:ContainerRecoveryLifecycleEvidenceSha)) {
        $combined.lifecycle_restore_receipt.sha256 = [string]$Script:ContainerRecoveryLifecycleEvidenceSha
    }
    $Script:ContainerRecoveryCodeEvidenceSha = $null
    $Script:ContainerRecoveryLifecycleEvidenceSha = $null
    $combined.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    try {
        $combinedRecord = Write-JsonAtomic $combinedPath $combined -AllowReplace
    }
    catch {
        $persistenceFailureType = $_.Exception.GetType().Name
        $combined.status = 'FAIL'
        $combined.failure_code = 'COMBINED_RECOVERY_EVIDENCE_FAILED'
        $combined.persistence_failure.status = 'FAIL'
        $combined.persistence_failure.failure_type = $persistenceFailureType
        $preparedBinding = [string]$preparedValidation.payload.pre_readback.identity.binding_sha256
        if (-not [string]::IsNullOrWhiteSpace($preparedBinding)) {
            $combined.persistence_failure.safety_fence = Invoke-ContainerWriterSafetyFence $root $preparedBinding 'COMBINED_EVIDENCE_FAILED_RETAIN_DISABLED'
        }
        if ([string]$flow.lifecycle_restore.status -ceq 'PASS') {
            $combined.persistence_failure.lifecycle_containment = Invoke-ContainerLifecycleFailureContainment ([string]$replacementValidation.payload.failed_root) $root $ReplacementReceiptPath $ReplacementReceiptSha256 $ReplacementTransactionId
        }
        $combined.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        try { [void](Write-JsonAtomic $combinedPath $combined -AllowReplace) } catch { }
        throw 'Combined Container recovery evidence persistence failed after safety containment.'
    }
    return [pscustomobject][ordered]@{ status = [string]$combined.status; record = $combinedRecord; payload = [pscustomobject]$combined }
}

function Invoke-ContainerWriterSessionSelfTest {
    $session = '1' * 32
    $attempt = '2' * 32
    $orchestrator = '3' * 64
    $capability = '4' * 64
    $transaction = '8' * 32
    $contractSha256 = Get-FileSha256 $Script:ContractPath
    $startedAt = [DateTime]::UtcNow.AddMinutes(-1).ToString('o')
    $receiptPath = 'E:\selftest\prepared.json'
    $payload = [pscustomobject][ordered]@{
        schema = $Script:PreparedSchema
        status = 'PREPARED_DISABLED'
        app_id = 'container_audit'
        session_id = $session
        attempt_id = $attempt
        replacement_transaction_id = $transaction
        session_started_at_utc = $startedAt
        orchestrator_sha256 = $orchestrator
        adapter_sha256 = $Script:AdapterSha256
        contract_sha256 = $contractSha256
        evidence_path = $receiptPath
        started_at_utc = [DateTime]::UtcNow.AddSeconds(-30).ToString('o')
        completed_at_utc = [DateTime]::UtcNow.AddSeconds(-20).ToString('o')
        secret_values_recorded = $false
        historical_capability = [pscustomobject][ordered]@{ schema = $Script:HistoricalSchema; receipt_sha256 = $capability; eight_points_pass = $true; capability_binding_sha256 = '5' * 64 }
        pre_readback = [pscustomobject][ordered]@{ enabled = $true; state = 'Ready'; last_task_result = 0; exact_writer_process_count = 0; last_run_time_utc = [DateTime]::UtcNow.AddMinutes(-2).ToString('o'); identity = [pscustomobject][ordered]@{ status = 'PASS'; binding_sha256 = '5' * 64 } }
        disable = [pscustomobject][ordered]@{ status = 'COMMAND_SUCCEEDED'; binding_unchanged = $true }
        quiescence = [pscustomobject][ordered]@{ status = 'PASS'; last_run_time_unchanged = $true; log_unchanged = $true; runtime_status_unchanged = $true; exact_writer_process_count = 0 }
        failure = [pscustomobject][ordered]@{ silently_ignored = $false }
    }
    $validPrepared = Test-PreparedReceiptPayload $payload $receiptPath $session $attempt $startedAt $orchestrator $transaction $contractSha256 $capability $Script:AdapterSha256
    $staleSessionRejected = -not (Test-PreparedReceiptPayload $payload $receiptPath ('7' * 32) $attempt $startedAt $orchestrator $transaction $contractSha256 $capability $Script:AdapterSha256)
    $wrongTransactionRejected = -not (Test-PreparedReceiptPayload $payload $receiptPath $session $attempt $startedAt $orchestrator ('9' * 32) $contractSha256 $capability $Script:AdapterSha256)
    $wrongContractRejected = -not (Test-PreparedReceiptPayload $payload $receiptPath $session $attempt $startedAt $orchestrator $transaction ('a' * 64) $capability $Script:AdapterSha256)
    $bindingMismatchPayload = $payload | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $bindingMismatchPayload.pre_readback.identity.binding_sha256 = '6' * 64
    $bindingMismatchRejected = -not (Test-PreparedReceiptPayload $bindingMismatchPayload $receiptPath $session $attempt $startedAt $orchestrator $transaction $contractSha256 $capability $Script:AdapterSha256)
    $preparedStringBooleanPayload = $payload | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $preparedStringBooleanPayload.quiescence.log_unchanged = 'false'
    $preparedStringBooleanRejected = -not (Test-PreparedReceiptPayload $preparedStringBooleanPayload $receiptPath $session $attempt $startedAt $orchestrator $transaction $contractSha256 $capability $Script:AdapterSha256)
    $expiredStartedAt = [DateTime]::UtcNow.Subtract($Script:MaximumSessionAge).AddMinutes(-1).ToString('o')
    $expiredPayload = $payload | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $expiredPayload.session_started_at_utc = $expiredStartedAt
    $expiredPayload.started_at_utc = (ConvertTo-RoundTripUtc $expiredStartedAt 'expired session').AddSeconds(1).ToString('o')
    $expiredPayload.completed_at_utc = (ConvertTo-RoundTripUtc $expiredStartedAt 'expired session').AddSeconds(2).ToString('o')
    $expiredSessionRejected = -not (Test-PreparedReceiptPayload $expiredPayload $receiptPath $session $attempt $expiredStartedAt $orchestrator $transaction $contractSha256 $capability $Script:AdapterSha256)
    $replacement = [pscustomobject][ordered]@{
        schema_version = $Script:ReplacementSchema; status = 'WRONG'; app_id = 'container_audit'; transaction_id = '8' * 32; created_at = [DateTime]::UtcNow.ToString('o'); helper_sha256 = '9' * 64; integrity_helper_sha256 = 'a' * 64; receipt_path = 'E:\r.json'; install_root = 'C:\KMTech\Apps\Container_Audit\current'; install_parent = 'C:\KMTech\Apps\Container_Audit'; rollback_root = 'C:\KMTech\Apps\Container_Audit\.current.rollback.' + ('8' * 32); failed_root = 'C:\KMTech\Apps\Container_Audit\.current.failed.' + ('8' * 32); parent_acl = [pscustomobject][ordered]@{ owner_sid = 'S-1-5-32-544'; access_rules_protected = $true; sddl_sha256 = 'b' * 64 }; old = [pscustomobject][ordered]@{ file_count = 1; aggregate_sha256 = 'c' * 64; integrity_sha256 = 'd' * 64; manifest_sha256 = 'e' * 64; source_commit = 'f' * 40; source_tree = '1' * 40; owner_sid = 'S-1-5-32-544'; access_rules_protected = $true; acl_sddl_sha256 = '2' * 64; reparse_count = 0 }; new = [pscustomobject][ordered]@{ file_count = 1; aggregate_sha256 = '3' * 64; integrity_sha256 = '4' * 64; manifest_sha256 = '5' * 64; source_commit = '6' * 40; source_tree = '7' * 40; owner_sid = 'S-1-5-32-544'; access_rules_protected = $true; acl_sddl_sha256 = '8' * 64; reparse_count = 0 }; identity_or_credential_copied = $false
    }
    $invalidReplacementRejected = -not (Test-ReplacementReceiptShape $replacement)
    $historicalPreimage = [pscustomobject][ordered]@{ present = $true; restore_required = $true; start_when_available = $true }
    $historicalBooleanTypesAccepted = Test-ContainerHistoricalPreimageBooleanContract $historicalPreimage
    $historicalStringBoolean = $historicalPreimage | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $historicalStringBoolean.present = 'true'
    $historicalStringBooleanRejected = -not (Test-ContainerHistoricalPreimageBooleanContract $historicalStringBoolean)
    $base64UrlFingerprintAccepted = Test-Base64UrlSha256Fingerprint 'EIEjk1nsv9vwrOp-3GrBvZz2WZPvy48vdViRVd6Llvg'
    $hexFingerprintRejected = -not (Test-Base64UrlSha256Fingerprint ('a' * 64))
    $structuralValues = [ordered]@{}
    foreach ($field in $Script:LifecycleReceiptTopFields) { $structuralValues[$field] = $null }
    foreach ($field in @('owner_state_preserved_exact','writer_contract_verified','registration_attempted','network_attempted','ledger_opened','identity_or_credential_copied','secret_values_recorded')) { $structuralValues[$field] = $true }
    $structuralValues['system_scheduled_task_required'] = $false
    $structuralPayload = [pscustomobject]$structuralValues
    $lifecycleStructuralValid = Test-LifecycleReceiptStructuralGuard $structuralPayload
    $stringBooleanPayload = $structuralPayload | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $stringBooleanPayload.owner_state_preserved_exact = 'false'
    $lifecycleStringBooleanRejected = -not (Test-LifecycleReceiptStructuralGuard $stringBooleanPayload)
    $extraFieldPayload = $structuralPayload | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $extraFieldPayload | Add-Member -NotePropertyName unexpected -NotePropertyValue 'value'
    $lifecycleExtraFieldRejected = -not (Test-LifecycleReceiptStructuralGuard $extraFieldPayload)
    $limitedExecutionContext = [pscustomobject][ordered]@{ status = 'PASS'; token_elevated = $false; integrity_level = 'MEDIUM' }
    $limitedExecutionContextAccepted = Test-ContainerLifecycleExecutionContext $limitedExecutionContext
    $elevatedExecutionContext = $limitedExecutionContext | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $elevatedExecutionContext.token_elevated = $true
    $elevatedExecutionContextRejected = -not (Test-ContainerLifecycleExecutionContext $elevatedExecutionContext)
    $stringElevationContext = $limitedExecutionContext | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $stringElevationContext.token_elevated = 'false'
    $stringElevationContextRejected = -not (Test-ContainerLifecycleExecutionContext $stringElevationContext)
    $replacementPath = 'E:\selftest\replacement.json'
    $canonicalRoot = 'C:\KMTech\Apps\Container_Audit\current'
    $relayNow = [DateTime]::UtcNow
    $relayCommand = "$canonicalRoot\runtime\pythonw.exe -I -B $canonicalRoot\app\main.py $($Script:UserRelayMode)"
    $relayReceipt = [pscustomobject][ordered]@{
        captured_at = $relayNow.AddSeconds(-2).ToString('o')
        completed_at = $relayNow.ToString('o')
        relay_autostart = [pscustomobject][ordered]@{
            status = 'PASS'; principal = 'current_user'; registry_hive = 'HKEY_CURRENT_USER'; registry_key = 'Software\Microsoft\Windows\CurrentVersion\Run'; registry_value = 'KMTech.ContainerAudit.Relay'; command = $relayCommand
        }
        relay_start = [pscustomobject][ordered]@{ status = 'START_REQUESTED'; process_id = [int]123 }
    }
    $relayMutationEvidenceAccepted = Test-ContainerLifecycleMutationEvidence $relayReceipt $canonicalRoot
    $relayExtraField = $relayReceipt | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $relayExtraField.relay_autostart | Add-Member -NotePropertyName unexpected -NotePropertyValue 'value'
    $relayExtraFieldRejected = -not (Test-ContainerLifecycleMutationEvidence $relayExtraField $canonicalRoot)
    $relayWrongMode = $relayReceipt | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $relayWrongMode.relay_autostart.command = $relayCommand.Replace($Script:UserRelayMode, $Script:RelayMode)
    $relayWrongModeRejected = -not (Test-ContainerLifecycleMutationEvidence $relayWrongMode $canonicalRoot)
    $relayStringPid = $relayReceipt | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $relayStringPid.relay_start.process_id = '123'
    $relayStringPidRejected = -not (Test-ContainerLifecycleMutationEvidence $relayStringPid $canonicalRoot)
    $currentSid = 'S-1-5-21-1-2-3-1001'
    $liveRelay = [pscustomobject][ordered]@{ ProcessId = [int]123; ExecutablePath = "$canonicalRoot\runtime\pythonw.exe"; CommandLine = $relayCommand; CreationDate = $relayNow.AddSeconds(-1); OwnerSid = $currentSid }
    $liveRelayAccepted = Test-ContainerUserRelayLiveReadbackValues $relayReceipt $canonicalRoot $relayCommand 'String' $liveRelay 1 1 $currentSid
    $liveRelayWrongKindRejected = -not (Test-ContainerUserRelayLiveReadbackValues $relayReceipt $canonicalRoot $relayCommand 'ExpandString' $liveRelay 1 1 $currentSid)
    $liveRelayDuplicateRejected = -not (Test-ContainerUserRelayLiveReadbackValues $relayReceipt $canonicalRoot $relayCommand 'String' $liveRelay 2 2 $currentSid)
    $liveRelayExtraRuntimeRejected = -not (Test-ContainerUserRelayLiveReadbackValues $relayReceipt $canonicalRoot $relayCommand 'String' $liveRelay 2 1 $currentSid)
    $liveRelayWrongOwner = [pscustomobject][ordered]@{ ProcessId = [int]123; ExecutablePath = "$canonicalRoot\runtime\pythonw.exe"; CommandLine = $relayCommand; CreationDate = $relayNow.AddSeconds(-1); OwnerSid = 'S-1-5-21-9-9-9-1001' }
    $liveRelayWrongOwnerRejected = -not (Test-ContainerUserRelayLiveReadbackValues $relayReceipt $canonicalRoot $relayCommand 'String' $liveRelayWrongOwner 1 1 $currentSid)
    $liveRelayStale = [pscustomobject][ordered]@{ ProcessId = [int]123; ExecutablePath = "$canonicalRoot\runtime\pythonw.exe"; CommandLine = $relayCommand; CreationDate = $relayNow.AddMinutes(-5); OwnerSid = $currentSid }
    $liveRelayStaleRejected = -not (Test-ContainerUserRelayLiveReadbackValues $relayReceipt $canonicalRoot $relayCommand 'String' $liveRelayStale 1 1 $currentSid)
    $failedNewRoot = 'C:\KMTech\Apps\Container_Audit\.current.failed.' + $transaction
    $restoreEvidence = [pscustomobject][ordered]@{
        schema_version = 'container-audit-verified-replacement-code-restore-v1'
        status = 'PASS'
        action = 'RESTORED'
        app_id = 'container_audit'
        transaction_id = $transaction
        receipt_path = $replacementPath
        receipt_sha256 = 'a' * 64
        install_root = $canonicalRoot
        failed_new_root = $failedNewRoot
        prior_code_exact = $true
        failed_new_preserved = $true
        identity_or_credential_copied = $false
        completed_at = [DateTime]::UtcNow.ToString('o')
    }
    $restoreEvidenceStructuralValid = Test-RestoreEvidencePayload $restoreEvidence $transaction $replacementPath ('a' * 64) $canonicalRoot $failedNewRoot $startedAt
    $restoreStringBoolean = $restoreEvidence | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $restoreStringBoolean.failed_new_preserved = 'true'
    $restoreStringBooleanRejected = -not (Test-RestoreEvidencePayload $restoreStringBoolean $transaction $replacementPath ('a' * 64) $canonicalRoot $failedNewRoot $startedAt)
    $restoreExtraField = $restoreEvidence | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $restoreExtraField | Add-Member -NotePropertyName unexpected -NotePropertyValue 'value'
    $restoreExtraFieldRejected = -not (Test-RestoreEvidencePayload $restoreExtraField $transaction $replacementPath ('a' * 64) $canonicalRoot $failedNewRoot $startedAt)
    $restoreWrongFailedRoot = $restoreEvidence | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $restoreWrongFailedRoot.failed_new_root = 'C:\KMTech\Apps\Container_Audit\.current.failed.' + ('9' * 32)
    $restoreWrongFailedRootRejected = -not (Test-RestoreEvidencePayload $restoreWrongFailedRoot $transaction $replacementPath ('a' * 64) $canonicalRoot $failedNewRoot $startedAt)
    $preEnableReadback = [pscustomobject][ordered]@{ enabled = $false; state = 'Disabled'; exact_writer_process_count = 0; identity = [pscustomobject][ordered]@{ status = 'PASS'; binding_sha256 = '5' * 64 } }
    $preEnableExactAccepted = Test-ContainerWriterDisabledBeforeEnable $preEnableReadback ('5' * 64)
    $preEnableStringBoolean = $preEnableReadback | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $preEnableStringBoolean.enabled = 'false'
    $preEnableStringBooleanRejected = -not (Test-ContainerWriterDisabledBeforeEnable $preEnableStringBoolean ('5' * 64))
    $preEnableDrift = $preEnableReadback | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $preEnableDrift.identity.binding_sha256 = '6' * 64
    $preEnableDriftRejected = -not (Test-ContainerWriterDisabledBeforeEnable $preEnableDrift ('5' * 64))
    $preEnableProcess = $preEnableReadback | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $preEnableProcess.exact_writer_process_count = 1
    $preEnableProcessRejected = -not (Test-ContainerWriterDisabledBeforeEnable $preEnableProcess ('5' * 64))
    $temporalNow = [DateTime]::UtcNow
    $temporalPrepared = [pscustomobject]@{ completed_at_utc = $temporalNow.AddSeconds(-30).ToString('o') }
    $temporalReplacement = [pscustomobject]@{ created_at = $temporalNow.AddSeconds(-20).ToString('o') }
    $temporalCode = [pscustomobject]@{ completed_at = $temporalNow.AddSeconds(-10).ToString('o') }
    $temporalLifecycle = [pscustomobject]@{ captured_at = $temporalNow.AddSeconds(-5).ToString('o'); completed_at = $temporalNow.ToString('o') }
    $preparedBeforeReplacementAccepted = Test-ContainerPreparedBeforeReplacement $temporalPrepared $temporalReplacement
    $reorderedReplacement = [pscustomobject]@{ created_at = $temporalNow.AddSeconds(-40).ToString('o') }
    $reorderedReplacementRejected = -not (Test-ContainerPreparedBeforeReplacement $temporalPrepared $reorderedReplacement)
    $replacementBeforeCodeAccepted = Test-ContainerReplacementBeforeCode $temporalReplacement $temporalCode
    $reorderedCode = [pscustomobject]@{ completed_at = $temporalNow.AddSeconds(-30).ToString('o') }
    $reorderedCodeRejected = -not (Test-ContainerReplacementBeforeCode $temporalReplacement $reorderedCode)
    $restoreTemporalOrderAccepted = Test-ContainerRestoreTemporalOrder $temporalPrepared $temporalReplacement $temporalCode $temporalLifecycle
    $reorderedLifecycle = [pscustomobject]@{ captured_at = $temporalNow.AddSeconds(-20).ToString('o'); completed_at = $temporalNow.ToString('o') }
    $reorderedLifecycleRejected = -not (Test-ContainerRestoreTemporalOrder $temporalPrepared $temporalReplacement $temporalCode $reorderedLifecycle)
    $Script:SelfTestWriterCalled = $false
    $Script:SelfTestLifecycleCalled = $false
    $codeFailure = Invoke-RecoveryStateMachine -CodeRestoreAction { throw 'injected' } -LifecycleRestoreAction { $Script:SelfTestLifecycleCalled = $true; return [pscustomobject]@{ status = 'PASS' } } -WriterRestoreAction { $Script:SelfTestWriterCalled = $true; return [pscustomobject]@{ status = 'PASS' } }
    $codeFailureExplicit = ([string]$codeFailure.status -ceq 'FAIL' -and [string]$codeFailure.failure_code -ceq 'CODE_RESTORE_FAILED' -and [string]$codeFailure.lifecycle_restore.status -ceq 'NOT_RUN' -and [string]$codeFailure.writer_restore.status -ceq 'NOT_RUN' -and -not [bool]$Script:SelfTestLifecycleCalled -and -not [bool]$Script:SelfTestWriterCalled -and -not [bool]$codeFailure.code_restore.silently_ignored)
    $lifecycleFailure = Invoke-RecoveryStateMachine -CodeRestoreAction { return [pscustomobject]@{ status = 'PASS' } } -LifecycleRestoreAction { return [pscustomobject]@{ status = 'FAIL'; silently_ignored = $false } } -WriterRestoreAction { $Script:SelfTestWriterCalled = $true; return [pscustomobject]@{ status = 'PASS' } }
    $lifecycleFailureExplicit = ([string]$lifecycleFailure.status -ceq 'FAIL' -and [string]$lifecycleFailure.failure_code -ceq 'LIFECYCLE_RESTORE_FAILED' -and [string]$lifecycleFailure.writer_restore.status -ceq 'NOT_RUN' -and -not [bool]$lifecycleFailure.lifecycle_restore.silently_ignored -and -not [bool]$Script:SelfTestWriterCalled)
    $Script:SelfTestWriterCalled = $null
    $Script:SelfTestLifecycleCalled = $null
    $writerFailure = Invoke-RecoveryStateMachine -CodeRestoreAction { return [pscustomobject]@{ status = 'PASS' } } -LifecycleRestoreAction { return [pscustomobject]@{ status = 'PASS' } } -WriterRestoreAction { return [pscustomobject]@{ status = 'FAIL'; silently_ignored = $false } }
    $writerFailureExplicit = ([string]$writerFailure.status -ceq 'FAIL' -and [string]$writerFailure.failure_code -ceq 'WRITER_RESTORE_FAILED' -and -not [bool]$writerFailure.writer_restore.silently_ignored)
    $checks = @(
        [pscustomobject][ordered]@{ name = 'valid_current_session_prepared_receipt'; status = if ($validPrepared) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'stale_session_rejected'; status = if ($staleSessionRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'wrong_transaction_rejected'; status = if ($wrongTransactionRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'wrong_contract_rejected'; status = if ($wrongContractRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'historical_binding_mismatch_rejected'; status = if ($bindingMismatchRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'prepared_string_boolean_rejected'; status = if ($preparedStringBooleanRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'expired_session_rejected'; status = if ($expiredSessionRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'invalid_replacement_receipt_rejected'; status = if ($invalidReplacementRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'historical_boolean_contract_accepts_exact_types'; status = if ($historicalBooleanTypesAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'historical_string_boolean_rejected'; status = if ($historicalStringBooleanRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'base64url_possession_fingerprint_accepted'; status = if ($base64UrlFingerprintAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'hex_possession_fingerprint_rejected'; status = if ($hexFingerprintRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_structural_guard_accepts_exact_boolean_types'; status = if ($lifecycleStructuralValid) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_string_boolean_rejected'; status = if ($lifecycleStringBooleanRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_extra_field_rejected'; status = if ($lifecycleExtraFieldRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_limited_execution_context_accepted'; status = if ($limitedExecutionContextAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_elevated_execution_context_rejected'; status = if ($elevatedExecutionContextRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_string_elevation_context_rejected'; status = if ($stringElevationContextRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_mutation_evidence_accepts_exact_nested_contract'; status = if ($relayMutationEvidenceAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_mutation_evidence_rejects_extra_field'; status = if ($relayExtraFieldRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_mutation_evidence_rejects_writer_mode'; status = if ($relayWrongModeRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_mutation_evidence_rejects_string_pid'; status = if ($relayStringPidRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'live_relay_readback_accepts_exact_current_process'; status = if ($liveRelayAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'live_relay_readback_rejects_registry_kind_drift'; status = if ($liveRelayWrongKindRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'live_relay_readback_rejects_duplicate_process'; status = if ($liveRelayDuplicateRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'live_relay_readback_rejects_extra_runtime_process'; status = if ($liveRelayExtraRuntimeRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'live_relay_readback_rejects_wrong_owner'; status = if ($liveRelayWrongOwnerRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'live_relay_readback_rejects_stale_process'; status = if ($liveRelayStaleRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'code_restore_structural_guard_accepts_exact_boolean_types'; status = if ($restoreEvidenceStructuralValid) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'code_restore_string_boolean_rejected'; status = if ($restoreStringBooleanRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'code_restore_extra_field_rejected'; status = if ($restoreExtraFieldRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'code_restore_failed_root_mismatch_rejected'; status = if ($restoreWrongFailedRootRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'pre_enable_guard_accepts_exact_disabled_readback'; status = if ($preEnableExactAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'pre_enable_guard_rejects_string_boolean'; status = if ($preEnableStringBooleanRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'pre_enable_guard_rejects_binding_drift'; status = if ($preEnableDriftRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'pre_enable_guard_rejects_live_process'; status = if ($preEnableProcessRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'prepared_before_replacement_accepted'; status = if ($preparedBeforeReplacementAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'reordered_replacement_rejected_before_restore'; status = if ($reorderedReplacementRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'replacement_before_code_accepted'; status = if ($replacementBeforeCodeAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'reordered_code_rejected_before_lifecycle'; status = if ($reorderedCodeRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'restore_temporal_order_accepted'; status = if ($restoreTemporalOrderAccepted) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'reordered_lifecycle_receipt_rejected'; status = if ($reorderedLifecycleRejected) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'code_restore_failure_explicit_and_writer_not_run'; status = if ($codeFailureExplicit) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'lifecycle_restore_failure_explicit_and_writer_not_run'; status = if ($lifecycleFailureExplicit) { 'PASS' } else { 'FAIL' } },
        [pscustomobject][ordered]@{ name = 'writer_restore_failure_explicit'; status = if ($writerFailureExplicit) { 'PASS' } else { 'FAIL' } }
    )
    $passed = @($checks | Where-Object status -cne 'PASS').Count -eq 0
    return [pscustomobject][ordered]@{ schema = 'container-audit-writer-session-self-test-v1'; status = if ($passed) { 'PASS' } else { 'FAIL' }; checks = $checks; system_mutation_attempted = ($Script:SystemMutationAttemptCount -ne 0); system_mutation_attempt_count = [int]$Script:SystemMutationAttemptCount; secret_values_recorded = $false }
}

if ($Mode -ceq 'selftest') {
    $result = Invoke-ContainerWriterSessionSelfTest
    $result | ConvertTo-Json -Depth 12 -Compress
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'contract') {
    Assert-Hex $ExpectedContractSha256 64 'expected writer session contract SHA-256'
    $contract = Read-ContainerWriterPublicContract $ExpectedContractSha256
    $result = [ordered]@{
        schema = $Script:ContractReadbackSchema
        status = 'PASS'
        contract_path = $Script:ContractPath
        contract_sha256 = Get-FileSha256 $Script:ContractPath
        adapter_path = $Script:AdapterPath
        adapter_sha256 = $Script:AdapterSha256
        public_modes = @($contract.cli.public_writer_modes)
        compatibility_modes = @($contract.cli.compatibility_modes)
        operations = $contract.operations
        receipt_schemas = [ordered]@{
            prepared = [string]$contract.receipts.prepared_schema
            restored = [string]$contract.receipts.restored_schema
            recovery = [string]$contract.receipts.recovery_schema
            replacement = [string]$contract.receipts.replacement_schema
            replacement_validation = [string]$contract.receipts.replacement_validation_schema
            lifecycle_restore = [string]$contract.receipts.lifecycle_restore_schema
            historical = [string]$contract.receipts.historical_schema
        }
        lifecycle_restore = $contract.lifecycle_restore
        system_mutation_attempted = $false
        secret_values_recorded = $false
    }
    $result | ConvertTo-Json -Depth 12 -Compress
    exit 0
}

Assert-Hex $SessionId 32 'session id'
Assert-Hex $AttemptId 32 'attempt id'
Assert-Hex $OrchestratorSha256 64 'orchestrator SHA-256'
Assert-Hex $ReplacementTransactionId 32 'replacement transaction id'
Assert-Hex $ExpectedContractSha256 64 'expected writer session contract SHA-256'
[void](Assert-CurrentSessionWindow $SessionStartedAtUtc)
[void](Read-ContainerWriterPublicContract $ExpectedContractSha256)

if ($Mode -in @('prepare','validateprepared','validatereplacement','restorewriter','recover')) {
    Assert-Hex $HistoricalReceiptSha256 64 'historical capability receipt SHA-256'
}
if ($Mode -in @('validateprepared','validatereplacement','restorewriter','recover')) {
    Assert-Hex $PreparedReceiptSha256 64 'prepared receipt SHA-256'
}
if ($Mode -in @('validatereplacement','restorewriter','recover')) {
    Assert-Hex $ReplacementReceiptSha256 64 'replacement receipt SHA-256'
}
if ($Mode -in @('validatereplacement','recover')) {
    Assert-Hex $ExpectedSourceCommit 40 'expected source commit'
    Assert-Hex $ExpectedSourceAggregateSha256 64 'expected source aggregate SHA-256'
    Assert-Hex $ExpectedHelperSha256 64 'expected helper SHA-256'
}
if ($Mode -ceq 'restorewriter') {
    Assert-Hex $LifecycleRestoreReceiptSha256 64 'lifecycle restore receipt SHA-256'
    Assert-Hex $RestoreEvidenceSha256 64 'code restore evidence SHA-256'
}

if ($Mode -ceq 'prepare') {
    $result = Invoke-ContainerWriterPrepare $InstallRoot $EvidencePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $HistoricalReceiptPath $HistoricalReceiptSha256 -RetainDisabled:$RetainDisabledOnFailure.IsPresent
    Write-Output "writer_session_status=$($result.status)"
    Write-Output "writer_session_receipt=$($result.record.path)"
    Write-Output "writer_session_receipt_sha256=$($result.record.sha256)"
    if ([string]$result.status -ceq 'PREPARED_DISABLED') { exit 0 }
    exit 20
}

if ($Mode -ceq 'validateprepared') {
    $validation = Test-ContainerPreparedReceipt $InstallRoot $PreparedReceiptPath $PreparedReceiptSha256 $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $HistoricalReceiptSha256 -RequireLiveDisabled
    Write-Output "writer_session_validation_status=$($validation.status)"
    if ([string]$validation.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'validatereplacement') {
    $root = Get-StrictFullPath $InstallRoot 'Container install root'
    $installParent = Get-StrictFullPath (Split-Path -Parent $root) 'Container install parent'
    $validationEvidencePath = Get-StrictFullPath $EvidencePath 'replacement validation evidence path'
    if (
        (Test-PathInside $validationEvidencePath $installParent) -or
        (Test-CanonicalSamePath $validationEvidencePath $installParent)
    ) { throw 'Replacement validation evidence must be outside the mutable install parent.' }
    $preparedValidation = Test-ContainerPreparedReceipt $InstallRoot $PreparedReceiptPath $PreparedReceiptSha256 $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $HistoricalReceiptSha256 -RequireLiveDisabled
    if ([string]$preparedValidation.status -cne 'PASS' -or -not [bool]$preparedValidation.live_disabled_exact) {
        $validation = [pscustomobject][ordered]@{ status = 'FAIL'; reason = 'CURRENT_SESSION_PREPARED_RECEIPT_INVALID'; payload = $null }
    }
    else {
        $validation = Get-ContainerReplacementReceiptValidation $InstallRoot $ReplacementReceiptPath $ReplacementReceiptSha256 $ReplacementTransactionId $ExpectedSourceCommit $ExpectedSourceAggregateSha256 $HelperPath $ExpectedHelperSha256
    }
    $result = [ordered]@{
        schema = 'container-audit-replacement-receipt-validation-v1'
        status = [string]$validation.status
        reason = [string]$validation.reason
        session_id = $SessionId
        attempt_id = $AttemptId
        session_started_at_utc = $SessionStartedAtUtc
        orchestrator_sha256 = $OrchestratorSha256
        adapter_sha256 = $Script:AdapterSha256
        contract_sha256 = $ExpectedContractSha256
        replacement_transaction_id = $ReplacementTransactionId
        replacement_receipt_sha256 = $ReplacementReceiptSha256
        prepared_receipt_sha256 = $PreparedReceiptSha256
        secret_values_recorded = $false
        validated_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    $record = Write-JsonAtomic $validationEvidencePath $result
    Write-Output "replacement_receipt_validation_status=$($result.status)"
    Write-Output "replacement_receipt_validation_evidence=$($record.path)"
    Write-Output "replacement_receipt_validation_evidence_sha256=$($record.sha256)"
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'restorewriter') {
    $result = Invoke-ContainerWriterRestore $InstallRoot $EvidencePath $SessionId $AttemptId $SessionStartedAtUtc $OrchestratorSha256 $ReplacementTransactionId $ExpectedContractSha256 $PreparedReceiptPath $PreparedReceiptSha256 $HistoricalReceiptSha256 $RestoreEvidencePath $RestoreEvidenceSha256 $LifecycleRestoreReceiptPath $LifecycleRestoreReceiptSha256 $ReplacementReceiptPath $ReplacementReceiptSha256
    Write-Output "writer_restore_status=$($result.status)"
    Write-Output "writer_restore_receipt=$($result.record.path)"
    Write-Output "writer_restore_receipt_sha256=$($result.record.sha256)"
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

if ($Mode -ceq 'recover') {
    $result = Invoke-ContainerRecovery
    Write-Output "container_recovery_status=$($result.status)"
    Write-Output "container_recovery_receipt=$($result.record.path)"
    Write-Output "container_recovery_receipt_sha256=$($result.record.sha256)"
    if ([string]$result.status -ceq 'PASS') { exit 0 }
    exit 20
}

throw 'Unsupported Container writer session mode.'
