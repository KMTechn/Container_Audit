[CmdletBinding()]
param(
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\KMTech\Apps\Container_Audit\current",
    [string]$EvidencePath = "",
    [string]$ServerBaseUrl = "",
    [switch]$PlanOnly,
    [switch]$Uninstall,
    [switch]$RestoreVerifiedReplacement,
    [string]$RestoreReceiptPath = "",
    [string]$RestoreReceiptSha256 = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$SkipSignatureValidationForTest
)

$ErrorActionPreference = 'Stop'
$CanonicalRoot = 'C:\KMTech\Apps\Container_Audit\current'
$RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$RunName = 'KMTech.ContainerAudit.Relay'
$CanonicalWriterTaskName = 'direct-sync-relay-container-audit'
$NoncanonicalQualificationTaskName = 'container-audit-isolated-qualification-authority'
$Script:CanonicalWriterFenceSessionId = ''
$Script:CanonicalWriterFenceAttemptId = ''
$Script:CanonicalWriterFenceTransactionId = ''
$Script:CanonicalWriterFenceDelegationToken = ''
$testMode = $AllowNoncanonicalLayoutForTest -and
    [string]$env:KMTECH_FACTORY_INSTALL_TEST_MODE -ceq '1'
if ($SkipSignatureValidationForTest -and -not $testMode) {
    throw 'Signature bypass is test-only.'
}
$onboardingServerBaseUrl = ''
$onboardingServerBaseUri = $null
if (-not [string]::IsNullOrEmpty($ServerBaseUrl)) {
    if (
        $ServerBaseUrl -match '[\s"\\]' -or
        -not [Uri]::TryCreate($ServerBaseUrl, [UriKind]::Absolute, [ref]$onboardingServerBaseUri) -or
        $onboardingServerBaseUri.Scheme -cne 'https' -or
        [string]::IsNullOrEmpty($onboardingServerBaseUri.Host) -or
        $onboardingServerBaseUri.IsLoopback -or
        $onboardingServerBaseUri.Port -lt 1 -or
        $onboardingServerBaseUri.UserInfo -cne '' -or
        $onboardingServerBaseUri.Query -cne '' -or
        $onboardingServerBaseUri.Fragment -cne '' -or
        $onboardingServerBaseUri.AbsolutePath -cnotin @('', '/')
    ) { throw 'ServerBaseUrl must be a credential-free HTTPS origin without path, query, or fragment.' }
    $onboardingServerBaseUrl = $ServerBaseUrl.TrimEnd('/')
}
$onboardingServerBaseUrlLabel = if ($onboardingServerBaseUrl) { $onboardingServerBaseUrl } else { 'PRODUCT_DEFAULT' }

$BootstrapIntegrityFunctions = Join-Path $PSScriptRoot 'tools\bootstrap_integrity.ps1'
# Generated with the writer inventory: authenticate this earlier bootstrap load.
$ExpectedBootstrapIntegritySha256 = '7e2760ec1d54508b395c0d9f1a6343fecd6b665c0c1d904273ddd210f96762a1'
if ((Get-FileHash -LiteralPath $BootstrapIntegrityFunctions -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedBootstrapIntegritySha256) {
    throw 'Bootstrap integrity helper pin mismatch.'
}
. $BootstrapIntegrityFunctions
$sharedLeaf = Get-BootstrapSharedPortableLeaf $PSScriptRoot
. $sharedLeaf

function Full([string]$Value, [string]$Purpose) {
    return ConvertTo-KmtechFullPath $Value $Purpose
}
function Same([string]$Left, [string]$Right) {
    return (Full $Left 'left path').Equals((Full $Right 'right path'), 'OrdinalIgnoreCase')
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
function Test-ExactStringProperties($Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    foreach ($name in $Names) {
        $property = $Value.PSObject.Properties[$name]
        if ($null -eq $property -or -not ($property.Value -is [string])) { return $false }
    }
    return $true
}
function Test-JsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}
function Test-JsonTrue($Value) {
    return ($Value -is [bool] -and $Value)
}
function Test-JsonPositiveInt32($Value) {
    if (-not (Test-JsonInteger $Value)) { return $false }
    return ([int64]$Value -gt 0 -and [int64]$Value -le [int]::MaxValue)
}
function Get-CanonicalInstallSuccessStatus([bool]$IsTestMode) {
    if ($IsTestMode) { return 'TEST_ONLY_PARTIAL' }
    return 'PASS'
}
function Sha([string]$Path) {
    return Get-KmtechFileSha $Path
}
function Get-WriterContractSessionMutexName(
    [string]$SessionId,
    [string]$AttemptId,
    [string]$OrchestratorSha256,
    [string]$ReplacementTransactionId,
    [string]$WriterContractSha256
) {
    $tuple = (@(
        'container-audit-deployment-session-authority-v1',
        $SessionId,
        $AttemptId,
        $OrchestratorSha256,
        $ReplacementTransactionId,
        $WriterContractSha256
    ) | ForEach-Object { ([string]$_).Normalize([Text.NormalizationForm]::FormC) }) -join "`n"
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($tuple)
        $digest = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
    return 'Local\KMTech.ContainerAudit.DeploymentSession.' + $digest
}
function Assert-WriterSessionPublicContract(
    [string]$Path,
    [string]$ExpectedSha256,
    [string]$ExpectedWriterInventorySha256
) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 65536) { throw 'Writer session public contract is oversized.' }
    if ((Sha $Path) -cne $ExpectedSha256) { throw 'Writer session public contract hash differs.' }
    try { $contract = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Writer session public contract JSON is invalid.' }
    $vectors = @($contract.all_writer_fence.verification_vectors)
    $vectorsExact = ($vectors.Count -eq 2)
    foreach ($vector in $vectors) {
        if (
            $vector.session_id -isnot [string] -or
            $vector.attempt_id -isnot [string] -or
            $vector.orchestrator_sha256 -isnot [string] -or
            $vector.replacement_transaction_id -isnot [string] -or
            $vector.writer_contract_sha256 -isnot [string] -or
            $vector.expected_mutex_name -isnot [string] -or
            [string]$vector.expected_mutex_name -cne (Get-WriterContractSessionMutexName `
                ([string]$vector.session_id) `
                ([string]$vector.attempt_id) `
                ([string]$vector.orchestrator_sha256) `
                ([string]$vector.replacement_transaction_id) `
                ([string]$vector.writer_contract_sha256))
        ) { $vectorsExact = $false }
    }
    if (
        [string]$contract.schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$contract.app_id -cne 'container_audit' -or
        [string]$contract.cli.relative_path -cne 'tools/container_writer_session.ps1' -or
        (@($contract.cli.public_writer_modes) -join ',') -cne 'Contract,Prepare,ValidatePrepared,RestoreWriter' -or
        [string]$contract.identifiers.session_authority_mutex_derivation -cne 'Local\KMTech.ContainerAudit.DeploymentSession.<sha256(v1 canonical session tuple)>' -or
        [string]$contract.all_writer_fence.active_schema -cne 'container-audit-all-writer-fence-active-v1' -or
        [string]$contract.all_writer_fence.release_schema -cne 'container-audit-all-writer-fence-release-v1' -or
        [string]$contract.all_writer_fence.control_root -cne '%LOCALAPPDATA%\KMTech\DirectSync\container_audit\control\writer-session' -or
        [string]$contract.all_writer_fence.active_filename -cne 'active.json' -or
        [string]$contract.all_writer_fence.release_filename_pattern -cne 'release-{replacement_transaction_id}-{release_authorization_sha256}.json' -or
        [string]$contract.all_writer_fence.admission_mutex_name -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1' -or
        [string]$contract.all_writer_fence.noncanonical_mutex_derivation -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1.<first 16 lowercase hex characters of SHA-256 over the absolute control root after slash-to-backslash conversion, trailing-backslash removal, Unicode NFC, and ASCII A-Z to a-z mapping with every other code point unchanged, encoded as UTF-8 without BOM>' -or
        [string]$contract.all_writer_fence.session_mutex_prefix -cne 'Local\KMTech.ContainerAudit.DeploymentSession.' -or
        [string]$contract.all_writer_fence.session_tuple_version -cne 'container-audit-deployment-session-authority-v1' -or
        (@($contract.all_writer_fence.session_tuple_fields) -join ',') -cne 'session_tuple_version,session_id,attempt_id,orchestrator_sha256,replacement_transaction_id,writer_contract_sha256' -or
        [string]$contract.all_writer_fence.tuple_separator -cne 'LF (U+000A) between ordered fields; no trailing LF' -or
        [string]$contract.all_writer_fence.tuple_encoding -cne 'UTF-8 without BOM' -or
        [string]$contract.all_writer_fence.tuple_normalization -cne 'Unicode NFC applied to each field before joining' -or
        [string]$contract.all_writer_fence.writer_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$contract.all_writer_fence.canonical_installer_delegation_source -cne 'writer_sink_sources from the exact pinned code-derived inventory' -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.scheduled_task_mutation_rule) -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.natural_trigger_phase_rule) -or
        $ExpectedWriterInventorySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$contract.all_writer_fence.writer_inventory_sha256 -cne $ExpectedWriterInventorySha256 -or
        (@($contract.all_writer_fence.active_statuses) -join ',') -cne 'PREPARING,PREPARED,RESTORING,RESTORE_FAILED,INSTALLING' -or
        -not $vectorsExact -or
        -not (Test-JsonTrue $contract.all_writer_fence.writer_admission_fail_closed) -or
        -not (Test-JsonTrue $contract.all_writer_fence.unknown_or_unobservable_is_denied) -or
        $contract.all_writer_fence.denial_mutates_state -isnot [bool] -or [bool]$contract.all_writer_fence.denial_mutates_state -or
        [string]$contract.receipts.prepared_schema -cne 'container-audit-writer-session-prepared-v3' -or
        [string]$contract.receipts.restored_schema -cne 'container-audit-writer-session-restored-v2' -or
        [string]$contract.receipts.lifecycle_restore_schema -cne 'container-audit-replacement-lifecycle-restore-v1' -or
        (@($contract.receipts.prepared_required_bindings) -join ',') -cne 'session_id,attempt_id,replacement_transaction_id,session_started_at_utc,orchestrator_sha256,session_authority_mutex_name,adapter_sha256,contract_sha256,evidence_path,historical_capability.receipt_sha256,historical_capability.capability_binding_sha256' -or
        [string]$contract.lifecycle_restore.product_mode -cne '--restore-current-user-lifecycle-after-replacement' -or
        -not (Test-JsonTrue $contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore) -or
        -not (Test-JsonTrue $contract.security.active_session_authority_mutex_required) -or
        -not (Test-JsonTrue $contract.security.all_writer_fence_required) -or
        -not (Test-JsonTrue $contract.security.all_writer_sinks_require_admission) -or
        -not (Test-JsonTrue $contract.security.evidence_paths_outside_install_parent_required)
    ) { throw 'Writer session public contract semantics differ.' }
}
function Assert-WriterSinkInventory(
    [string]$Path,
    [string]$ExpectedFileSha256,
    [string]$ExpectedContractSha256
) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 1048576) { throw 'Writer sink inventory is oversized.' }
    if ((Sha $Path) -cne $ExpectedFileSha256) { throw 'Writer sink inventory file hash differs.' }
    try { $inventory = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Writer sink inventory JSON is invalid.' }
    if (
        [string]$inventory.schema_version -cne 'container-audit-writer-sink-inventory-v8' -or
        [string]$inventory.inventory_sha256 -cne $ExpectedContractSha256 -or
        $inventory.writer_sink_sources -isnot [Object[]] -or
        @($inventory.writer_sink_sources).Count -le 0 -or
        @($inventory.writer_sink_sources | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0 -or
        (@($inventory.writer_sink_sources | Sort-Object -Unique) -join "`n") -cne (@($inventory.writer_sink_sources) -join "`n") -or
        @($inventory.uncovered_direct_mutation_functions).Count -ne 0 -or
        @($inventory.caller_fence_reference_failures).Count -ne 0 -or
        @($inventory.powershell_guard_failures).Count -ne 0 -or
        @($inventory.known_route_coverage).Count -le 0 -or
        @($inventory.known_route_coverage | Where-Object { -not (Test-JsonTrue $_.pass) }).Count -ne 0
    ) { throw 'Writer sink inventory contract is not release-admissible.' }
    return $inventory
}
function Arg([string]$Value) {
    if ($Value.Contains('"')) { throw 'A command path contains a quote.' }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}
function Command([string]$Root) {
    $command = ('{0} -I -B {1} --container-audit-user-relay' -f
        (Arg (Join-Path $Root 'runtime\pythonw.exe')),
        (Arg (Join-Path $Root 'app\main.py')))
    if (-not [string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_DATA_ROOT)) {
        $dataRoot = Full $env:CONTAINER_AUDIT_DATA_ROOT 'data root'
        $codeRoot = Full $Root 'code root'
        if (
            $dataRoot.Equals($codeRoot, 'OrdinalIgnoreCase') -or
            $dataRoot.StartsWith($codeRoot + '\', 'OrdinalIgnoreCase') -or
            $codeRoot.StartsWith($dataRoot + '\', 'OrdinalIgnoreCase') -or
            $dataRoot.Equals('C:\Sync', 'OrdinalIgnoreCase') -or
            $dataRoot.StartsWith('C:\Sync\', 'OrdinalIgnoreCase')
        ) { throw 'Custom data root must be outside application code and legacy Syncthing paths.' }
        if (-not (Test-Path -LiteralPath $dataRoot -PathType Container)) {
            throw 'Custom data root is unavailable; restore the existing dataset before installation.'
        }
        $command += ' --data-root ' + (Arg $dataRoot)
    }
    return $command
}
function Manifest([string]$Root, [bool]$UnsignedOk) {
    Assert-KmtechPortableTree $Root @(
        'portable-manifest.json',
        'runtime\python.exe',
        'runtime\pythonw.exe',
        'app\main.py',
        'launch-container-audit.cmd',
        'INSTALL_CANONICAL_PORTABLE.ps1',
        'INSTALL_THIS_PC.ps1',
        'tools\bootstrap_integrity.ps1',
        'tools\container_writer_fence.ps1',
        'tools\container_writer_session.ps1',
        'tools\container_writer_session_contract.json',
        'tools\container_writer_sink_inventory.json'
    )
    $path = Join-Path $Root 'portable-manifest.json'
    $value = Read-KmtechPortableManifest $Root
    if ([string]$value.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$value.entrypoint -cne 'runtime/pythonw.exe app/main.py' -or
        [string]$value.launcher -cne 'launch-container-audit.cmd' -or
        [string]$value.writer_fence_helper_path -cne 'tools/container_writer_fence.ps1' -or
        [string]$value.writer_session_adapter_path -cne 'tools/container_writer_session.ps1' -or
        [string]$value.writer_session_contract_path -cne 'tools/container_writer_session_contract.json' -or
        [string]$value.writer_sink_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$value.writer_session_contract_schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$value.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$value.source_tree -cnotmatch '^[0-9a-f]{40}$' -or
        @($value.allowed_unsigned_app_pe).Count -ne 0 -or
        @($value.forbidden_dependency_paths).Count -ne 0 -or
        (Sha (Join-Path $Root 'runtime\pythonw.exe')) -cne ([string]$value.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'launch-container-audit.cmd')) -cne ([string]$value.launcher_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'INSTALL_CANONICAL_PORTABLE.ps1')) -cne ([string]$value.installer_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'INSTALL_THIS_PC.ps1')) -cne ([string]$value.helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\bootstrap_integrity.ps1')) -cne ([string]$value.integrity_helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_fence.ps1')) -cne ([string]$value.writer_fence_helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session.ps1')) -cne ([string]$value.writer_session_adapter_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session_contract.json')) -cne ([string]$value.writer_session_contract_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_sink_inventory.json')) -cne ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant()) {
        throw 'Portable manifest readback failed.'
    }
    $filesBeforeManifest = @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Where-Object {
                -not (Same $_.FullName $path) -and
                [string]$_.Name -cne 'bootstrap-integrity.json'
            }
    )
    $bytesBeforeManifest = [int64](
        ($filesBeforeManifest | Measure-Object -Property Length -Sum).Sum
    )
    if (
        -not (Test-JsonInteger $value.file_count_before_manifest) -or
        -not (Test-JsonInteger $value.byte_count_before_manifest) -or
        [int64]$value.file_count_before_manifest -lt 0 -or
        [int64]$value.byte_count_before_manifest -lt 0 -or
        [int64]$value.file_count_before_manifest -ne $filesBeforeManifest.Count -or
        [int64]$value.byte_count_before_manifest -ne $bytesBeforeManifest
    ) { throw 'Portable tree metrics differ from the manifest.' }
    Assert-WriterSessionPublicContract `
        (Join-Path $Root 'tools\container_writer_session_contract.json') `
        ([string]$value.writer_session_contract_sha256).ToLowerInvariant() `
        ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant()
    [void](Assert-WriterSinkInventory (Join-Path $Root 'tools\container_writer_sink_inventory.json') ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant() ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant())
    Assert-KmtechCPythonSignature $Root $UnsignedOk
    return $value
}
function InstalledManifest([string]$Root, [bool]$UnsignedOk) {
    foreach ($relative in @(
        'portable-manifest.json',
        'runtime\python.exe',
        'runtime\pythonw.exe',
        'app\main.py',
        'launch-container-audit.cmd',
        'tools\container_writer_fence.ps1',
        'tools\container_writer_session.ps1',
        'tools\container_writer_session_contract.json',
        'tools\container_writer_sink_inventory.json'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $relative) -PathType Leaf)) {
            throw "Installed portable tree is missing $relative."
        }
    }
    foreach ($item in @((Get-Item $Root -Force)) + @(Get-ChildItem $Root -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Installed portable tree contains a reparse point: $($item.FullName)"
        }
    }
    $path = Join-Path $Root 'portable-manifest.json'
    if ((Get-Item $path).Length -gt 65536) { throw 'Installed portable manifest is oversized.' }
    $value = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$value.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$value.entrypoint -cne 'runtime/pythonw.exe app/main.py' -or
        [string]$value.launcher -cne 'launch-container-audit.cmd' -or
        [string]$value.writer_fence_helper_path -cne 'tools/container_writer_fence.ps1' -or
        [string]$value.writer_session_adapter_path -cne 'tools/container_writer_session.ps1' -or
        [string]$value.writer_session_contract_path -cne 'tools/container_writer_session_contract.json' -or
        [string]$value.writer_sink_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$value.writer_session_contract_schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$value.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$value.source_tree -cnotmatch '^[0-9a-f]{40}$' -or
        @($value.allowed_unsigned_app_pe).Count -ne 0 -or
        @($value.forbidden_dependency_paths).Count -ne 0 -or
        (Sha (Join-Path $Root 'runtime\pythonw.exe')) -cne ([string]$value.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'launch-container-audit.cmd')) -cne ([string]$value.launcher_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_fence.ps1')) -cne ([string]$value.writer_fence_helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session.ps1')) -cne ([string]$value.writer_session_adapter_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session_contract.json')) -cne ([string]$value.writer_session_contract_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_sink_inventory.json')) -cne ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant()) {
        throw 'Installed portable manifest readback failed.'
    }
    $filesBeforeManifest = @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Where-Object {
                -not (Same $_.FullName $path) -and
                -not (Same $_.FullName (Join-Path $Root 'bootstrap-integrity.json'))
            }
    )
    $bytesBeforeManifest = [int64](
        ($filesBeforeManifest | Measure-Object -Property Length -Sum).Sum
    )
    if (
        -not (Test-JsonInteger $value.file_count_before_manifest) -or
        -not (Test-JsonInteger $value.byte_count_before_manifest) -or
        [int64]$value.file_count_before_manifest -lt 0 -or
        [int64]$value.byte_count_before_manifest -lt 0 -or
        [int64]$value.file_count_before_manifest -ne $filesBeforeManifest.Count -or
        [int64]$value.byte_count_before_manifest -ne $bytesBeforeManifest
    ) { throw 'Installed portable tree metrics differ from the manifest.' }
    Assert-WriterSessionPublicContract `
        (Join-Path $Root 'tools\container_writer_session_contract.json') `
        ([string]$value.writer_session_contract_sha256).ToLowerInvariant() `
        ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant()
    [void](Assert-WriterSinkInventory (Join-Path $Root 'tools\container_writer_sink_inventory.json') ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant() ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant())
    if (-not $UnsignedOk) {
        foreach ($relative in @('runtime\python.exe','runtime\pythonw.exe')) {
            if ([string](Get-AuthenticodeSignature (Join-Path $Root $relative)).Status -cne 'Valid') {
                throw "Installed signed CPython readback failed: $relative"
            }
        }
    }
    return $value
}
function Get-WriterInventorySemantics($Inventory) {
    # Compare the actual writers and guards. Caller counts and positions are
    # generator evidence, not a new delegated writer or wire contract.
    $membership = [ordered]@{
        schema_version=$Inventory.schema_version
        writer_sink_sources=$Inventory.writer_sink_sources
        writer_sinks=$Inventory.writer_sinks
        powershell_writer_sinks=$Inventory.powershell_writer_sinks
        known_route_coverage=$Inventory.known_route_coverage
    }
    $copy = $membership | ConvertTo-Json -Depth 40 | ConvertFrom-Json
    function Remove-WriterInventoryPositions($Value) {
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            foreach ($property in @($Value.PSObject.Properties)) {
                if ($property.Name -cin @('inventory_sha256','writer_site_count') -or $property.Name -cmatch '(^|_)line$') {
                    $Value.PSObject.Properties.Remove($property.Name)
                } else { Remove-WriterInventoryPositions $property.Value }
            }
        } elseif ($Value -is [array]) {
            foreach ($item in $Value) { Remove-WriterInventoryPositions $item }
        }
    }
    Remove-WriterInventoryPositions $copy
    return ($copy | ConvertTo-Json -Depth 40 -Compress)
}
function Sync-CanonicalWriterFenceInventory([string]$InventorySha256) {
    $active = Read-ContainerWriterFence
    if ([string]$active.writer_inventory_sha256 -ceq $InventorySha256) { return }
    [void](Set-ContainerWriterFenceInventory `
        -SessionId $Script:CanonicalWriterFenceSessionId `
        -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
        -WriterInventorySha256 $InventorySha256 `
        -AuthorityLease $canonicalWriterFenceAuthority)
    $audit.code_replacement.writer_inventory_transitions += $InventorySha256
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
function New-CanonicalWriterFencePreparedReceipt(
    [string]$Path,
    [string]$SessionId,
    [string]$AttemptId,
    [string]$ReplacementTransactionId,
    [string]$SessionStartedAtUtc,
    [string]$OrchestratorSha256,
    [string]$WriterContractSha256,
    [string]$SourceManifestSha256
) {
    if (Test-Path -LiteralPath $Path) {
        throw 'CANONICAL_WRITER_PREPARED_RECEIPT_ALREADY_EXISTS'
    }
    $payload = [ordered]@{
        schema='container-audit-canonical-writer-prepared-v1'
        status='PREPARED'
        app_id='container_audit'
        session_id=$SessionId
        attempt_id=$AttemptId
        replacement_transaction_id=$ReplacementTransactionId
        session_started_at_utc=$SessionStartedAtUtc
        orchestrator_sha256=$OrchestratorSha256
        writer_contract_sha256=$WriterContractSha256
        writer_inventory_sha256=$Script:ContainerWriterFenceInventorySha256
        source_manifest_sha256=$SourceManifestSha256
        created_at_utc=[DateTime]::UtcNow.ToString('o')
        secret_values_recorded=$false
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $json = ($payload | ConvertTo-Json -Depth 8) + "`n"
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    try { $actual = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'CANONICAL_WRITER_PREPARED_RECEIPT_JSON_INVALID' }
    if (
        -not (Test-ExactPropertySet $actual @(
            'schema','status','app_id','session_id','attempt_id',
            'replacement_transaction_id','session_started_at_utc','orchestrator_sha256',
            'writer_contract_sha256','writer_inventory_sha256','source_manifest_sha256',
            'created_at_utc','secret_values_recorded'
        )) -or
        [string]$actual.schema -cne 'container-audit-canonical-writer-prepared-v1' -or
        [string]$actual.status -cne 'PREPARED' -or
        [string]$actual.app_id -cne 'container_audit' -or
        [string]$actual.session_id -cne $SessionId -or
        [string]$actual.attempt_id -cne $AttemptId -or
        [string]$actual.replacement_transaction_id -cne $ReplacementTransactionId -or
        [string]$actual.session_started_at_utc -cne $SessionStartedAtUtc -or
        [string]$actual.orchestrator_sha256 -cne $OrchestratorSha256 -or
        [string]$actual.writer_contract_sha256 -cne $WriterContractSha256 -or
        [string]$actual.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        [string]$actual.source_manifest_sha256 -cne $SourceManifestSha256 -or
        $actual.secret_values_recorded -isnot [bool] -or [bool]$actual.secret_values_recorded
    ) { throw 'CANONICAL_WRITER_PREPARED_RECEIPT_READBACK_FAILED' }
    return [pscustomobject][ordered]@{
        path=[IO.Path]::GetFullPath($Path)
        sha256=Sha $Path
    }
}
function New-CanonicalWriterFenceReleaseAuthorization(
    [string]$Path,
    [string]$Phase,
    [string]$AuditPath,
    $EnabledBaseline = $null
) {
    if ($Phase -cnotin @('PRODUCT_NATURAL_TRIGGER','PRODUCT_COMPLETE','ROLLBACK_NATURAL_TRIGGER','ROLLBACK_COMPLETE')) {
        throw 'CANONICAL_WRITER_RELEASE_PHASE_INVALID'
    }
    if (Test-Path -LiteralPath $Path) { throw 'CANONICAL_WRITER_RELEASE_AUTHORIZATION_ALREADY_EXISTS' }
    $auditFull = [IO.Path]::GetFullPath($AuditPath)
    if (-not (Test-Path -LiteralPath $auditFull -PathType Leaf)) {
        throw 'CANONICAL_WRITER_RELEASE_AUDIT_ABSENT'
    }
    $naturalTrigger = $Phase -cin @('PRODUCT_NATURAL_TRIGGER','ROLLBACK_NATURAL_TRIGGER')
    if ($naturalTrigger -and $null -eq $EnabledBaseline) {
        throw 'CANONICAL_WRITER_RELEASE_BASELINE_ABSENT'
    }
    $readback = if ($naturalTrigger) { $EnabledBaseline.readback } else { $null }
    $payload = [ordered]@{
        schema = 'container-audit-writer-release-authorization-v1'
        status = 'AUTHORIZED'
        phase = $Phase
        app_id = 'container_audit'
        session_id = $Script:CanonicalWriterFenceSessionId
        attempt_id = $Script:CanonicalWriterFenceAttemptId
        replacement_transaction_id = $Script:CanonicalWriterFenceTransactionId
        writer_inventory_sha256 = $Script:ContainerWriterFenceInventorySha256
        task_name = if ($naturalTrigger) { [string]$readback.task_name } else { '' }
        task_path = if ($naturalTrigger) { [string]$readback.task_path } else { '' }
        binding_sha256 = if ($naturalTrigger) { [string]$readback.binding_sha256 } else { '' }
        future_natural_trigger_utc = if ($naturalTrigger) { [string]$EnabledBaseline.future_natural_trigger_utc } else { '' }
        install_audit_path = $auditFull
        install_audit_sha256 = Sha $auditFull
        created_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_values_recorded = $false
    }
    if ($naturalTrigger -and (
        [string]::IsNullOrWhiteSpace([string]$payload.task_name) -or
        [string]::IsNullOrWhiteSpace([string]$payload.task_path) -or
        [string]$payload.binding_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$payload.future_natural_trigger_utc)
    )) { throw 'CANONICAL_WRITER_RELEASE_BASELINE_INVALID' }
    Save $Path $payload
    $expectedFields = @(
        'schema','status','phase','app_id','session_id','attempt_id',
        'replacement_transaction_id','writer_inventory_sha256','task_name','task_path',
        'binding_sha256','future_natural_trigger_utc','install_audit_path',
        'install_audit_sha256','created_at_utc','secret_values_recorded'
    )
    try { $actual = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'CANONICAL_WRITER_RELEASE_AUTHORIZATION_JSON_INVALID' }
    if (
        -not (Test-ExactPropertySet $actual $expectedFields) -or
        -not (Test-ExactStringProperties $actual @($expectedFields | Where-Object { $_ -cne 'secret_values_recorded' })) -or
        $actual.secret_values_recorded -isnot [bool] -or [bool]$actual.secret_values_recorded -or
        [string]$actual.schema -cne 'container-audit-writer-release-authorization-v1' -or
        [string]$actual.status -cne 'AUTHORIZED' -or
        [string]$actual.phase -cne $Phase -or
        [string]$actual.app_id -cne 'container_audit' -or
        [string]$actual.session_id -cne $Script:CanonicalWriterFenceSessionId -or
        [string]$actual.attempt_id -cne $Script:CanonicalWriterFenceAttemptId -or
        [string]$actual.replacement_transaction_id -cne $Script:CanonicalWriterFenceTransactionId -or
        [string]$actual.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        [string]$actual.install_audit_path -cne $auditFull -or
        [string]$actual.install_audit_sha256 -cne (Sha $auditFull)
    ) { throw 'CANONICAL_WRITER_RELEASE_AUTHORIZATION_READBACK_FAILED' }
    return [ordered]@{ path=[IO.Path]::GetFullPath($Path); sha256=Sha $Path }
}
function Set-CanonicalWriterFenceReleaseAuthorization($Authorization) {
    Invoke-CanonicalWriterFenceReleaseStep {
        [void](Set-ContainerWriterFencePrepared `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -PreparedReceiptPath ([string]$Authorization.path) `
            -PreparedReceiptSha256 ([string]$Authorization.sha256) `
            -Status 'PREPARED' `
            -AuthorityLease $canonicalWriterFenceAuthority)
    }
}
function Invoke-CanonicalWriterFenceReleaseStep([scriptblock]$Action) {
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try { return & $Action }
        catch {
            if (
                $_.Exception.Message -cnotin @(
                    'CONTAINER_WRITER_ADMISSION_MUTEX_TIMEOUT',
                    'CONTAINER_WRITER_ADMISSION_MUTEX_ABANDONED'
                ) -or $attempt -ge 6
            ) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}
function Clear-CanonicalWriterFenceReleaseDelegation {
    Invoke-CanonicalWriterFenceReleaseStep {
        [void](Clear-ContainerWriterFenceDelegation `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
            -AuthorityLease $canonicalWriterFenceAuthority)
    }
}
function Stop-CanonicalWriterFenceRelease($Authorization) {
    Invoke-CanonicalWriterFenceReleaseStep {
        [void](Stop-ContainerWriterFence `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -ReleaseAuthorizationPath ([string]$Authorization.path) `
            -ReleaseAuthorizationSha256 ([string]$Authorization.sha256) `
            -AuthorityLease $canonicalWriterFenceAuthority)
    }
}
function Relays {
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        [string]$_.CommandLine -like '*--container-audit-user-relay*' -and
        [string]$_.ExecutablePath -match '(?i)(pythonw?\.exe|Container_Audit\.exe)$'
    })
}
function Stop-CanonicalDelegatedRelay([int]$ProcessId) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if (
        $null -eq $process -or
        -not (Same ([string]$process.ExecutablePath) (Join-Path $install 'runtime\pythonw.exe')) -or
        [string]$process.CommandLine -notlike '*--container-audit-user-relay*'
    ) { throw 'Canonical delegated relay identity changed before writer fence release.' }
    Stop-Process -Id $ProcessId -Force -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 200
        $remaining = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    } while ($null -ne $remaining -and (Get-Date) -lt $deadline)
    if ($null -ne $remaining) { throw 'Canonical delegated relay quiescence timed out.' }
}
function Start-CanonicalRelayAfterFenceRelease {
    $newPid = StartRaw $wanted
    Start-Sleep -Seconds 3
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $newPid" -ErrorAction SilentlyContinue
    if (
        $null -eq $process -or
        -not (Same ([string]$process.ExecutablePath) (Join-Path $install 'runtime\pythonw.exe')) -or
        [string]$process.CommandLine -notlike '*--container-audit-user-relay*'
    ) { throw 'Canonical relay restart after writer fence release failed.' }
    return [int]$newPid
}
function Assert-RollbackRelayPreimage([object[]]$ExpectedRelays) {
    $actualRelays = @(Relays)
    if ($actualRelays.Count -ne $ExpectedRelays.Count) {
        throw 'rollback relay process-count readback failed'
    }
    foreach ($expected in $ExpectedRelays) {
        $matching = @($actualRelays | Where-Object {
            (Same ([string]$_.ExecutablePath) ([string]$expected.ExecutablePath)) -and
            [string]$_.CommandLine -ceq [string]$expected.CommandLine
        })
        if ($matching.Count -ne 1) {
            throw 'rollback relay executable/command readback failed'
        }
    }
    return $actualRelays
}
function Get-CanonicalRelayCommandIdentity([string]$CommandLine, [string]$ExecutablePath) {
    # Windows Run autostart can quote argv[0]; preserve every argument byte and case.
    $quotedExecutable = '"' + $ExecutablePath + '"'
    if ($CommandLine.StartsWith($quotedExecutable + ' ', [StringComparison]::Ordinal)) {
        return $ExecutablePath + $CommandLine.Substring($quotedExecutable.Length)
    }
    return $CommandLine
}
function Assert-CanonicalRuntimePreimage(
    $Before,
    [object[]]$Processes,
    [string]$ExpectedCommand,
    [string]$ExpectedRoot,
    [bool]$StopMarkerExists
) {
    $items = @($Processes)
    if ([bool]$Before.exists) {
        if (
            [string]$Before.kind -cne 'String' -or
            [string]$Before.data -cne $ExpectedCommand
        ) { throw 'CANONICAL_HKCU_RUN_BINDING_MISMATCH' }
    }
    elseif (
        -not [string]::IsNullOrEmpty([string]$Before.kind) -or
        -not [string]::IsNullOrEmpty([string]$Before.data)
    ) { throw 'CANONICAL_HKCU_RUN_ABSENCE_CONTRACT_INVALID' }
    if ($items.Count -gt 1) { throw 'CANONICAL_RELAY_CARDINALITY_INVALID' }
    $expectedExecutable = Join-Path $ExpectedRoot 'runtime\pythonw.exe'
    $expectedIdentity = Get-CanonicalRelayCommandIdentity $ExpectedCommand $expectedExecutable
    foreach ($item in $items) {
        $commandIdentity = Get-CanonicalRelayCommandIdentity ([string]$item.CommandLine) $expectedExecutable
        if (
            -not [bool]$Before.exists -or
            -not (Same ([string]$item.ExecutablePath) $expectedExecutable) -or
            $commandIdentity -cne $expectedIdentity
        ) { throw 'CANONICAL_RELAY_BINDING_MISMATCH' }
    }
    if ($StopMarkerExists) { throw 'CANONICAL_STOP_MARKER_PREEXISTS' }
    return [ordered]@{
        status='PASS'
        hkcu_run_state=if ([bool]$Before.exists) { 'EXACT_CANONICAL' } else { 'ABSENT' }
        relay_count=$items.Count
        relay_binding_exact=$true
        stop_marker_absent=$true
    }
}
function Product([string]$Root,[string]$Mode) {
    $args = '-I -B {0} {1} --app-root {2}' -f
        (Arg (Join-Path $Root 'app\main.py')),$Mode,(Arg (Join-Path $Root 'app'))
    if ($Mode -ceq '--onboard-current-user' -and $onboardingServerBaseUrl) {
        $args += ' --server-base-url ' + (Arg $onboardingServerBaseUrl)
    }
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
function ReadReplacementReceipt(
    [string]$Path,
    [string]$ExpectedTransactionId,
    [string]$ExpectedInstallRoot,
    $ExpectedSourceManifest,
    [string]$ExpectedManifestSha256,
    [string]$ExpectedHelperSha256,
    [string]$ExpectedIntegrityHelperSha256
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Verified replacement receipt is absent.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt 131072) {
        throw 'Verified replacement receipt size is invalid.'
    }
    try { $receipt = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Verified replacement receipt JSON is invalid.' }
    $top = @(
        'schema_version','status','app_id','transaction_id','created_at','helper_sha256',
        'integrity_helper_sha256','receipt_path','install_root','install_parent',
        'rollback_root','failed_root','parent_acl','old','new','identity_or_credential_copied'
    )
    $topStrings = @(
        'schema_version','status','app_id','transaction_id','created_at','helper_sha256',
        'integrity_helper_sha256','receipt_path','install_root','install_parent',
        'rollback_root','failed_root'
    )
    $acl = @('owner_sid','access_rules_protected','sddl_sha256')
    $tree = @(
        'file_count','aggregate_sha256','integrity_sha256','manifest_sha256',
        'source_commit','source_tree','owner_sid','access_rules_protected',
        'acl_sddl_sha256','reparse_count'
    )
    $treeStrings = @(
        'aggregate_sha256','integrity_sha256','manifest_sha256','source_commit',
        'source_tree','owner_sid','acl_sddl_sha256'
    )
    if (
        -not (Test-ExactPropertySet $receipt $top) -or
        -not (Test-ExactStringProperties $receipt $topStrings) -or
        -not (Test-ExactPropertySet $receipt.parent_acl $acl) -or
        -not (Test-ExactStringProperties $receipt.parent_acl @('owner_sid','sddl_sha256')) -or
        -not ($receipt.parent_acl.access_rules_protected -is [bool]) -or
        -not (Test-ExactPropertySet $receipt.old $tree) -or
        -not (Test-ExactPropertySet $receipt.new $tree) -or
        -not (Test-ExactStringProperties $receipt.old $treeStrings) -or
        -not (Test-ExactStringProperties $receipt.new $treeStrings) -or
        -not ($receipt.old.access_rules_protected -is [bool]) -or
        -not ($receipt.new.access_rules_protected -is [bool]) -or
        -not (Test-JsonInteger $receipt.old.file_count) -or
        -not (Test-JsonInteger $receipt.new.file_count) -or
        [int64]$receipt.old.file_count -lt 0 -or
        [int64]$receipt.new.file_count -lt 0 -or
        -not (Test-JsonInteger $receipt.old.reparse_count) -or
        -not (Test-JsonInteger $receipt.new.reparse_count) -or
        [int64]$receipt.old.reparse_count -ne 0 -or
        [int64]$receipt.new.reparse_count -ne 0 -or
        -not ($receipt.identity_or_credential_copied -is [bool]) -or
        [string]$receipt.schema_version -cne 'container-audit-verified-replacement-v1' -or
        [string]$receipt.status -cne 'OLD_PRESERVED_NEW_VERIFIED' -or
        [string]$receipt.app_id -cne 'container_audit' -or
        [string]$receipt.transaction_id -cne $ExpectedTransactionId -or
        -not (Same ([string]$receipt.receipt_path) $Path) -or
        -not (Same ([string]$receipt.install_root) $ExpectedInstallRoot) -or
        [string]$receipt.helper_sha256 -cne $ExpectedHelperSha256 -or
        [string]$receipt.integrity_helper_sha256 -cne $ExpectedIntegrityHelperSha256 -or
        [string]$receipt.new.source_commit -cne [string]$ExpectedSourceManifest.source_commit -or
        [string]$receipt.new.source_tree -cne [string]$ExpectedSourceManifest.source_tree -or
        [string]$receipt.new.manifest_sha256 -cne $ExpectedManifestSha256 -or
        $receipt.identity_or_credential_copied
    ) { throw 'Verified replacement receipt contract readback failed.' }
    return $receipt
}
function ReadReplacementRestoreEvidence(
    [string]$Path,
    [string]$ExpectedTransactionId,
    [string]$ExpectedReceiptPath,
    [string]$ExpectedReceiptSha256,
    [string]$ExpectedInstallRoot
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Verified replacement restore evidence is absent.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt 131072) {
        throw 'Verified replacement restore evidence size is invalid.'
    }
    try { $evidence = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Verified replacement restore evidence JSON is invalid.' }
    $top = @(
        'schema_version','status','action','app_id','transaction_id','receipt_path',
        'receipt_sha256','install_root','failed_new_root','prior_code_exact',
        'failed_new_preserved','identity_or_credential_copied','completed_at'
    )
    $strings = @(
        'schema_version','status','action','app_id','transaction_id','receipt_path',
        'receipt_sha256','install_root','failed_new_root','completed_at'
    )
    if (
        -not (Test-ExactPropertySet $evidence $top) -or
        -not (Test-ExactStringProperties $evidence $strings) -or
        -not ($evidence.prior_code_exact -is [bool]) -or
        -not ($evidence.failed_new_preserved -is [bool]) -or
        -not ($evidence.identity_or_credential_copied -is [bool]) -or
        [string]$evidence.schema_version -cne 'container-audit-verified-replacement-code-restore-v1' -or
        [string]$evidence.status -cne 'PASS' -or
        [string]$evidence.action -notin @('RESTORED','ALREADY_RESTORED') -or
        [string]$evidence.app_id -cne 'container_audit' -or
        [string]$evidence.transaction_id -cne $ExpectedTransactionId -or
        -not (Same ([string]$evidence.receipt_path) $ExpectedReceiptPath) -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        -not (Same ([string]$evidence.install_root) $ExpectedInstallRoot) -or
        -not $evidence.prior_code_exact -or
        -not $evidence.failed_new_preserved -or
        $evidence.identity_or_credential_copied
    ) { throw 'Verified replacement restore evidence contract readback failed.' }
    return $evidence
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
function Read-CanonicalReplacementRestore {
    $receipt = Read-BootstrapReplacementReceipt $restoreReceiptFull $RestoreReceiptSha256
    $receipt = ReadReplacementReceipt `
        -Path $restoreReceiptFull -ExpectedTransactionId ([string]$receipt.transaction_id) `
        -ExpectedInstallRoot $install -ExpectedSourceManifest $sourceManifest `
        -ExpectedManifestSha256 $sourceManifestSha256 -ExpectedHelperSha256 $sourceHelperSha256 `
        -ExpectedIntegrityHelperSha256 $sourceIntegrityHelperSha256
    if ((Sha $restoreReceiptFull) -cne $RestoreReceiptSha256) {
        throw 'Replacement receipt changed during canonical readback.'
    }
    $state = Get-BootstrapVerifiedReplacementRestoreState `
        -Receipt $receipt -ReceiptPath $restoreReceiptFull -InstallRoot $install `
        -ExpectedAppId 'container_audit' -ExpectedTransactionId ([string]$receipt.transaction_id) `
        -ExpectedHelperSha256 $sourceHelperSha256
    if ([string]$state.status -cnotin @('PENDING','RESTORED')) {
        throw 'Canonical restore requires a verified current tree for normal runtime quiescence.'
    }
    $oldRoot = if ([string]$state.status -ceq 'PENDING') { [string]$state.rollback_root } else { $install }
    $oldManifest = InstalledManifest $oldRoot $SkipSignatureValidationForTest
    $oldInventory = Assert-WriterSinkInventory `
        (Join-Path $oldRoot 'tools\container_writer_sink_inventory.json') `
        ([string]$oldManifest.writer_sink_inventory_sha256) `
        ([string]$oldManifest.writer_sink_inventory_contract_sha256)
    if ((Get-WriterInventorySemantics $oldInventory) -cne (Get-WriterInventorySemantics $sourceWriterInventory)) {
        throw 'CODE_RESTORE_WRITER_SEMANTICS_DIFFER'
    }
    return [pscustomobject]@{
        receipt=$receipt
        state=[string]$state.status
        old_inventory_sha256=[string]$oldManifest.writer_sink_inventory_contract_sha256
    }
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
function Get-CanonicalTaskProperty($Value, [string]$Name, $Default = $null) {
    if ($null -eq $Value) { return $Default }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}
function Get-CanonicalWriterBinding($Task) {
    $actions = @($Task.Actions)
    $triggers = @(Get-CanonicalTaskProperty $Task 'Triggers')
    $normalized = [ordered]@{
        task_name=[string]$Task.TaskName
        task_path=[string]$Task.TaskPath
        actions=@($actions | ForEach-Object {
            [ordered]@{
                execute=[string](Get-CanonicalTaskProperty $_ 'Execute' '')
                arguments=[string](Get-CanonicalTaskProperty $_ 'Arguments' '')
                working_directory=[string](Get-CanonicalTaskProperty $_ 'WorkingDirectory' '')
            }
        })
        principal=[ordered]@{
            user_id=[string]$Task.Principal.UserId
            logon_type=[string]$Task.Principal.LogonType
            run_level=[string]$Task.Principal.RunLevel
        }
        triggers=@($triggers | ForEach-Object {
            $class = Get-CanonicalTaskProperty $_ 'CimClass'
            $repetition = Get-CanonicalTaskProperty $_ 'Repetition'
            [ordered]@{
                type=[string](Get-CanonicalTaskProperty $class 'CimClassName' '')
                enabled=[bool](Get-CanonicalTaskProperty $_ 'Enabled' $false)
                start_boundary=[string](Get-CanonicalTaskProperty $_ 'StartBoundary' '')
                repetition_interval=[string](Get-CanonicalTaskProperty $repetition 'Interval' '')
                repetition_duration=[string](Get-CanonicalTaskProperty $repetition 'Duration' '')
                stop_at_duration_end=[bool](Get-CanonicalTaskProperty $repetition 'StopAtDurationEnd' $false)
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
        $arguments = if (
            $actions.Count -eq 1 -and $null -ne $actions[0] -and
            $null -ne $actions[0].PSObject.Properties['Arguments']
        ) { [string]$actions[0].Arguments } else { '' }
        $execute = if (
            $actions.Count -eq 1 -and $null -ne $actions[0] -and
            $null -ne $actions[0].PSObject.Properties['Execute']
        ) { [string]$actions[0].Execute } else { '' }
        # A display/capture command can mention the app without running a writer.
        # Retain all named writers and relay actions, including malformed ones.
        $owned = (
            [string]$candidate.TaskName -ieq $CanonicalWriterTaskName -or
            [string]$candidate.TaskName -ieq $NoncanonicalQualificationTaskName -or
            @($actions | Where-Object {
                $actionArguments = [string](Get-CanonicalTaskProperty $_ 'Arguments' '')
                if ($actionArguments -match '(?:^|\s)["'']?--container-audit-(?:direct-sync-relay|user-relay)["'']?(?:\s|$)') {
                    return $true
                }
                # Execute is a path, not a shell command. Only Python consumes a
                # script from Arguments; a direct script Execute remains owned.
                $actionExecute = ([string](Get-CanonicalTaskProperty $_ 'Execute' '')).Trim().Trim('"')
                $python = [IO.Path]::GetFileName($actionExecute) -imatch '^(?:python[^\\/]*|py)\.exe$'
                $scriptPath = $actionExecute
                if ($python) {
                    # Windows argv quoting: whitespace splits outside quotes;
                    # backslashes are escapes only immediately before a quote.
                    $words = @()
                    $word = ''; $quoted = $false; $started = $false; $slashes = 0
                    for ($i = 0; $i -lt $actionArguments.Length; $i++) {
                        $ch = $actionArguments[$i]
                        if ($ch -ceq '\') { $slashes++; $started = $true; continue }
                        if ($ch -ceq '"') {
                            $word += '\' * [int][Math]::Floor($slashes / 2)
                            if ($slashes % 2) { $word += '"' }
                            elseif ($quoted -and $i + 1 -lt $actionArguments.Length -and $actionArguments[$i + 1] -ceq '"') {
                                $word += '"'; $i++
                            }
                            else { $quoted = -not $quoted }
                            $started = $true
                        }
                        else {
                            $word += '\' * $slashes
                            if (-not $quoted -and [char]::IsWhiteSpace($ch)) {
                                if ($started) { $words += $word; $word = ''; $started = $false }
                            }
                            else { $word += $ch; $started = $true }
                        }
                        $slashes = 0
                    }
                    $word += '\' * $slashes
                    if ($started) { $words += $word }
                    $index = 0
                    while ($index -lt $words.Count -and $words[$index].StartsWith('-')) {
                        $option = $words[$index]
                        $index++
                        if ($option -ceq '--') { break }
                        if ($option -cmatch '^-[bBdEiIOPqRsSuvx]+$') { continue }
                        if ($option -cmatch '^-[bBdEiIOPqRsSuvx]*[WX](.*)$') {
                            if ($Matches[1] -ceq '') { $index++ }
                            continue
                        }
                        if ($option -ceq '--check-hash-based-pycs') { $index++; continue }
                        if ([IO.Path]::GetFileName($actionExecute) -ieq 'py.exe' -and
                            $option -cmatch '^-(?:[23](?:\.\d+)?(?:-(?:32|64))?|V:.+)$') { continue }
                        # -c/-m/stdin, help/version and invalid options do not
                        # execute a following token as a source script.
                        return $false
                    }
                    if ($index -ge $words.Count) { return $false }
                    $scriptPath = $words[$index]
                }
                if ([string]::IsNullOrWhiteSpace($scriptPath) -or [IO.Path]::GetExtension($scriptPath) -ine '.py') {
                    return $false
                }
                try {
                    $workingDirectory = [string](Get-CanonicalTaskProperty $_ 'WorkingDirectory' '')
                    if (-not [IO.Path]::IsPathRooted($scriptPath) -and $workingDirectory) {
                        $scriptPath = Join-Path $workingDirectory $scriptPath
                    }
                    $scriptPath = [IO.Path]::GetFullPath($scriptPath).Replace('/', '\')
                }
                catch { return $false }
                # Reuse the authenticated inventory's executable Python routes;
                # method-level routes are not standalone script entrypoints.
                foreach ($route in $sourceWriterInventory.known_route_coverage) {
                    if ($route.kind -ceq 'python' -and $route.start -cmatch '^([^.]+(?:\.[^.]+)*)\.main$') {
                        $relativeScript = $Matches[1].Replace('.', '\') + '.py'
                        if ($scriptPath.EndsWith(('\' + $relativeScript), [StringComparison]::OrdinalIgnoreCase)) {
                            return $true
                        }
                    }
                }
                return $false
            }).Count -gt 0
        )
        if (-not $owned) { continue }
        $binding = Get-CanonicalWriterBinding $candidate
        $triggers = @($binding.value.triggers)
        $executeExact = (
            $execute.IndexOfAny([IO.Path]::GetInvalidPathChars()) -lt 0 -and
            [IO.Path]::IsPathRooted($execute) -and
            (Same $execute $expectedExecute)
        )
        $actionExact = (
            [string]$candidate.TaskName -ieq $CanonicalWriterTaskName -and
            [string]$candidate.TaskPath -ceq '\' -and
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
            [string]$triggers[0].type -ceq 'MSFT_TaskTimeTrigger' -and
            [bool]$triggers[0].enabled -and
            [string]$triggers[0].repetition_interval -ceq 'PT1M' -and
            [bool]$candidate.Settings.StartWhenAvailable -and
            [string]$candidate.Settings.MultipleInstances -ceq 'IgnoreNew' -and
            [string]$candidate.Settings.ExecutionTimeLimit -ceq 'PT2M'
        )
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
    $triggers = @($binding.value.triggers)
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
        trigger_type=if ($triggers.Count -eq 1) { [string]$triggers[0].type } else { '' }
        trigger_interval=if ($triggers.Count -eq 1) { [string]$triggers[0].repetition_interval } else { '' }
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
    $task = DisableAndStop-ContainerScheduledTaskUnderWriterFence `
        -SessionId $Script:CanonicalWriterFenceSessionId `
        -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
        -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
        -AuthorityLease $canonicalWriterFenceAuthority `
        -TaskName ([string]$Before.task_name) `
        -TaskPath ([string]$Before.task_path)
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
    [void](Enable-ContainerScheduledTaskUnderWriterFence `
        -SessionId $Script:CanonicalWriterFenceSessionId `
        -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
        -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
        -AuthorityLease $canonicalWriterFenceAuthority `
        -TaskName ([string]$Before.task_name) `
        -TaskPath ([string]$Before.task_path))
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
if ($RestoreVerifiedReplacement) {
    if ($Uninstall -or $ServerBaseUrl -or -not $RestoreReceiptPath -or
        $RestoreReceiptSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Canonical restore requires an exact receipt path/hash and cannot combine install or uninstall options.'
    }
}
elseif ($RestoreReceiptPath -or $RestoreReceiptSha256) {
    throw 'Restore receipt arguments require -RestoreVerifiedReplacement.'
}
$source = Full $SourceRoot 'SourceRoot'; $install = Full $InstallRoot 'InstallRoot'
$SourceRoot = $source
if (-not $testMode -and -not (Same $install $CanonicalRoot)) { throw 'InstallRoot is not canonical.' }
if (-not (Same $PSCommandPath (Join-Path $source 'INSTALL_CANONICAL_PORTABLE.ps1'))) {
    throw 'Top-level installer must execute from the admitted SourceRoot.'
}
$sourceManifest = Manifest $source $SkipSignatureValidationForTest
$sourceWriterInventory = Assert-WriterSinkInventory `
    (Join-Path $source 'tools\container_writer_sink_inventory.json') `
    ([string]$sourceManifest.writer_sink_inventory_sha256).ToLowerInvariant() `
    ([string]$sourceManifest.writer_sink_inventory_contract_sha256).ToLowerInvariant()
$writerFenceHelperPath = Join-Path $source 'tools\container_writer_fence.ps1'
if (-not (Test-Path -LiteralPath $writerFenceHelperPath -PathType Leaf)) {
    throw 'Portable tree is missing the all-writer fence helper.'
}
. $writerFenceHelperPath
$sourceManifestSha256 = Sha (Join-Path $source 'portable-manifest.json')
$sourceHelperSha256 = Sha (Join-Path $source 'INSTALL_THIS_PC.ps1')
$sourceIntegrityHelperSha256 = Sha (Join-Path $source 'tools\bootstrap_integrity.ps1')
$wanted = Command $install
if ($PlanOnly) {
    "install_status=PLAN_ONLY"
    if ($Uninstall) { 'operation=UNINSTALL'; 'uninstall_identity_status=NOT_CHECKED_PLAN_ONLY' }
    if ($RestoreVerifiedReplacement) { 'operation=RESTORE_VERIFIED_REPLACEMENT'; 'restore_identity_status=NOT_CHECKED_PLAN_ONLY' }
    "install_root=$install"
    "autostart_command=$wanted"
    "onboarding_server_base_url=$onboardingServerBaseUrlLabel"
    'replacement_prestate_required=VERIFIED_REPLACE'
    'replacement_restore_status=AVAILABLE_RECEIPT_BOUND'
    'registry_changed=false'
    exit 0
}

$winps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
# Preserve the original lifecycle validator binding after source admission.
$BootstrapIntegrityFunctions = Join-Path $source 'tools\bootstrap_integrity.ps1'
. $BootstrapIntegrityFunctions
# Reject incompatible/damaged installed trees before creating a fence that can
# stop a resident relay. Repeat the existing integrity readback under the fence.
if (Test-Path -LiteralPath $install -PathType Container) {
    $preflightCandidate = InstalledManifest $install $SkipSignatureValidationForTest
    [void](Assert-BootstrapIntegrityRecord $install)
    $preflightInventory = Assert-WriterSinkInventory `
        (Join-Path $install 'tools\container_writer_sink_inventory.json') `
        ([string]$preflightCandidate.writer_sink_inventory_sha256) `
        ([string]$preflightCandidate.writer_sink_inventory_contract_sha256)
    if ((Get-WriterInventorySemantics $preflightInventory) -cne (Get-WriterInventorySemantics $sourceWriterInventory)) {
        throw 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
    }
}
$lad = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
if ($RestoreVerifiedReplacement) {
    $codeParent = Split-Path -Parent $install
    $restoreReceiptFull = Full $RestoreReceiptPath 'RestoreReceiptPath'
    foreach ($external in @($source, $lad, $restoreReceiptFull)) {
        if ((Same $external $codeParent) -or
            $external.StartsWith($codeParent + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Canonical restore requires source, receipt and user data outside the code parent.'
        }
    }
    # This preflight is read-only and is repeated under fresh ownership before
    # quiescence. No prepared receipt or authority from the old install is reused.
    $publicRestore = Read-CanonicalReplacementRestore
}
if ($Uninstall) {
    foreach ($pair in @(@($source, $install), @($lad, $install), @($source, $lad))) {
        if ((Same $pair[0] $pair[1]) -or
            $pair[0].StartsWith($pair[1] + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $pair[1].StartsWith($pair[0] + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Uninstall requires separate source, code and current-user data roots.'
        }
    }
    if (-not (Test-Path -LiteralPath $install -PathType Container)) {
        throw 'Uninstall requires the exact installed tree and its integrity record.'
    }
    $uninstallIntegrity = Assert-BootstrapIntegrityRecord $install
    $uninstallAggregate = Get-InventoryAggregate @(Get-CodeInventory $source)
    $uninstallRecordSha256 = Sha (Join-Path $install 'bootstrap-integrity.json')
    if ((Sha (Join-Path $install 'portable-manifest.json')) -cne $sourceManifestSha256 -or
        [string]$uninstallIntegrity.aggregate_sha256 -cne $uninstallAggregate) {
        throw 'Uninstall installed/source identity differs; use the exact installed packet.'
    }
}
$activeDataRoot = Join-Path $lad 'KMTech\ContainerAudit'
$activeRelayRoot = Join-Path $lad 'KMTech\DirectSync\container_audit'
if (-not [string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_DATA_ROOT)) {
    $activeDataRoot = Full $env:CONTAINER_AUDIT_DATA_ROOT 'data root'
    $activeRelayRoot = Join-Path $activeDataRoot 'direct_sync'
}
$statusRoot = Join-Path $activeRelayRoot 'status'
$stop = Join-Path $activeRelayRoot 'control\container_audit_user_relay.stop.json'
$onboardingPath = Join-Path $statusRoot 'current_user_onboarding.json'
$removalPath = Join-Path $statusRoot 'current_user_removal.json'
$relayPath = Join-Path $statusRoot 'container_audit_user_relay.json'
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N')
$auditRoot = Join-Path $activeDataRoot 'install-audit'
$auditPath = Join-Path $auditRoot "canonical-portable-$runId.json"
$canonicalWriterFencePreparedPath = Join-Path $auditRoot "canonical-portable-$runId-writer-prepared.json"
$elevationLogPath = Join-Path $auditRoot "canonical-portable-$runId-elevated.jsonl"
$replacementTransactionId = [Guid]::NewGuid().ToString('N')
$replacementReceiptPath = Join-Path $auditRoot "canonical-portable-$runId-replacement.json"
$replacementRestoreEvidencePath = Join-Path $auditRoot "canonical-portable-$runId-code-restore.json"
$productNaturalTriggerAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-product-natural-trigger-release.json"
$productCompleteAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-product-complete-release.json"
$rollbackNaturalTriggerAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-rollback-natural-trigger-release.json"
$rollbackCompleteAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-rollback-complete-release.json"
$evidenceFull = if ($EvidencePath) { Full $EvidencePath 'EvidencePath' } else { '' }
$Script:CanonicalWriterFenceSessionId = [Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceAttemptId = [Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceTransactionId = $replacementTransactionId
$canonicalWriterFenceStartedAtUtc = [DateTime]::UtcNow.ToString('o')
$canonicalWriterFenceOrchestratorSha256 = Sha $PSCommandPath
$canonicalWriterFenceContractSha256 = ([string]$sourceManifest.writer_session_contract_sha256).ToLowerInvariant()
$Script:CanonicalWriterFenceDelegationToken = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
$canonicalWriterFenceEnvironmentNames = @(
    'CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',
    'CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID',
    'CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID',
    'CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID'
)
$canonicalWriterFenceEnvironmentBefore = @{}
foreach ($name in $canonicalWriterFenceEnvironmentNames) {
    $canonicalWriterFenceEnvironmentBefore[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$canonicalWriterFenceAuthority = $null
$canonicalWriterFenceActive = $false
$canonicalWriterFenceLastReleaseAuthorizationPath = ''
$canonicalWriterFenceLastReleaseAuthorizationSha256 = ''
$canonicalWriterFencePreparedReceipt = $null
$enteredPlacementTry = $false
$canonicalWriterFenceDelegatedSources = [Object[]]@($sourceWriterInventory.writer_sink_sources)
$before = Snapshot
$old = @(Relays)
$runtimePreimageBinding = Assert-CanonicalRuntimePreimage `
    -Before $before `
    -Processes $old `
    -ExpectedCommand $wanted `
    -ExpectedRoot $install `
    -StopMarkerExists (Test-Path -LiteralPath $stop)
$writerBefore = if ($testMode) {
    [ordered]@{ present=$false; classification='TEST_BYPASS'; restore_required=$false }
}
else { Get-CanonicalWriterPreimageForQuiesce $install }
if (($Uninstall -or $RestoreVerifiedReplacement) -and [bool]$writerBefore.present) {
    throw 'Uninstall/restore requires the current-user layout without legacy scheduled writers.'
}
$uninstallCodeStarted = $false
$uninstallRecordPreimagePath = Join-Path $auditRoot "canonical-portable-$runId-integrity-preimage.json"
try {
$canonicalWriterFenceAuthority = Enter-ContainerWriterSessionAuthority `
    -SessionId $Script:CanonicalWriterFenceSessionId `
    -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -WriterContractSha256 $canonicalWriterFenceContractSha256
$canonicalWriterFencePreparedReceipt = New-CanonicalWriterFencePreparedReceipt `
    -Path $canonicalWriterFencePreparedPath `
    -SessionId $Script:CanonicalWriterFenceSessionId `
    -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
    -WriterContractSha256 $canonicalWriterFenceContractSha256 `
    -SourceManifestSha256 $sourceManifestSha256
[void](Start-ContainerWriterFence `
    -Status 'INSTALLING' `
    -OwnerKind 'canonical_installer' `
    -SessionId $Script:CanonicalWriterFenceSessionId `
    -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
    -WriterContractSha256 $canonicalWriterFenceContractSha256 `
    -PreparedReceiptPath ([string]$canonicalWriterFencePreparedReceipt.path) `
    -PreparedReceiptSha256 ([string]$canonicalWriterFencePreparedReceipt.sha256) `
    -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
    -DelegatedSources $canonicalWriterFenceDelegatedSources `
    -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) `
    -AuthorityLease $canonicalWriterFenceAuthority)
$canonicalWriterFenceActive = $true
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN', $Script:CanonicalWriterFenceDelegationToken, 'Process')
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID', $Script:CanonicalWriterFenceSessionId, 'Process')
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID', $Script:CanonicalWriterFenceAttemptId, 'Process')
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID', $Script:CanonicalWriterFenceTransactionId, 'Process')
$audit = [ordered]@{
    schema='container-audit-canonical-portable-install-v2'
    operation=if ($Uninstall) { 'UNINSTALL' } elseif ($RestoreVerifiedReplacement) { 'RESTORE_VERIFIED_REPLACEMENT' } else { 'INSTALL' }
    status='PREIMAGE_SAVED'
    run_id=$runId
    captured_at=(Get-Date).ToUniversalTime().ToString('o')
    install_root=$install
    code_placement='NOT_STARTED'
    source_commit=[string]$sourceManifest.source_commit
    source_manifest_sha256=$sourceManifestSha256
    runtime_pythonw_sha256=''
    runtime_pythonw_signature=''
    registry_value=$RunName
    preimage=$before
    runtime_preimage_binding=$runtimePreimageBinding
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
    code_replacement=[ordered]@{
        status='NOT_REQUIRED'
        prestate='NOT_EVALUATED'
        transaction_id=$replacementTransactionId
        receipt_path=''
        receipt_sha256=''
        rollback_root=''
        restore_evidence_path=''
        restore_evidence_sha256=''
        later_restore_surface='NOT_REQUIRED'
        identity_or_credential_copied=$false
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

$mutated = ($old.Count -gt 0)
$writerRestoreNeeded = [bool]$writerBefore.restore_required
$runtimeQuiescedForReplacement = $false
$codeRestoreNeeded = $false
$replacementReceipt = $null
$replacementReceiptSha256 = ''
$installedInventorySha256 = $Script:ContainerWriterFenceInventorySha256
$currentTreeInventorySha256 = $Script:ContainerWriterFenceInventorySha256
$audit.code_replacement.writer_inventory_transitions = @()
$audit.code_replacement.candidate_writer_inventory_sha256 = $Script:ContainerWriterFenceInventorySha256
$enteredPlacementTry = $true

    $placement = 'INSTALL_REQUIRED'
    $existingVerified = $false
    if (Test-Path $install -PathType Container) {
        try {
            $candidate = InstalledManifest $install $SkipSignatureValidationForTest
            $helper = (Join-Path $source 'tools\bootstrap_integrity.ps1').Replace("'","''")
            $escapedRoot = $install.Replace("'","''")
            & $winps -NoLogo -NoProfile -NonInteractive -Command ". '$helper'; [void](Assert-BootstrapIntegrityRecord '$escapedRoot')"
            if ($LASTEXITCODE -ne 0) { throw 'integrity differs' }
            $installedInventory = Assert-WriterSinkInventory `
                (Join-Path $install 'tools\container_writer_sink_inventory.json') `
                ([string]$candidate.writer_sink_inventory_sha256) `
                ([string]$candidate.writer_sink_inventory_contract_sha256)
            if ((Get-WriterInventorySemantics $installedInventory) -cne (Get-WriterInventorySemantics $sourceWriterInventory)) {
                throw 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
            }
            $installedInventorySha256 = [string]$candidate.writer_sink_inventory_contract_sha256
            $currentTreeInventorySha256 = $installedInventorySha256
            $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $installedInventorySha256
            $audit.code_replacement.installed_writer_inventory_sha256 = $installedInventorySha256
            $audit.code_replacement.writer_semantics_identical = $true
            $existingVerified = $true
            $audit.code_replacement.prestate='VERIFIED_REPLACE'
            if (
                [string]$candidate.source_commit -ceq [string]$sourceManifest.source_commit -and
                [string]$candidate.source_tree -ceq [string]$sourceManifest.source_tree -and
                (Sha (Join-Path $install 'runtime\pythonw.exe')) -ceq (Sha (Join-Path $source 'runtime\pythonw.exe'))
            ) { $placement = 'REUSED_VERIFIED' }
        }
        catch {
            $audit.code_replacement.prestate='UNKNOWN_OR_DAMAGED'
            $audit.code_replacement.prestate_failure_type=$_.Exception.GetType().Name
            if ($_.Exception.Message -ceq 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER') {
                $audit.code_replacement.prestate_failure_code='CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
            }
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
        }
        if (-not $existingVerified) {
            throw 'CODE_PRESTATE_NOT_VERIFIED_REPLACE'
        }
    }
    if ($RestoreVerifiedReplacement) {
        if (-not $existingVerified) { throw 'Canonical restore current tree is not verified.' }
        $publicRestore = Read-CanonicalReplacementRestore
        $selectedReceipt = $publicRestore.receipt
        $selectedTransactionId = [string]$selectedReceipt.transaction_id
        $audit.code_replacement.transaction_id = $selectedTransactionId
        $audit.code_replacement.controller_transaction_id = $Script:CanonicalWriterFenceTransactionId
        $audit.code_replacement.receipt_path = $restoreReceiptFull
        $audit.code_replacement.receipt_sha256 = $RestoreReceiptSha256
        $audit.code_replacement.rollback_root = [string]$selectedReceipt.rollback_root
        $audit.code_replacement.prestate = [string]$publicRestore.state
        Sync-CanonicalWriterFenceInventory $currentTreeInventorySha256
        $mutated = $true
        Product $install '--remove-current-user-setup'
        $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Snapshot).exists -or [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
            [string]$removal.relay_process.status -cne 'ABSENT' -or @(Relays).Count -ne 0) {
            throw 'Canonical restore current-user quiescence readback failed.'
        }
        $restoreStopSha256 = Sha $stop
        $audit.status = 'RESTORE_RUNTIME_QUIESCED'
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256
        $publicRestoreArguments = @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
            '-InstallRoot',$install, '-ElevationLogPath',$elevationLogPath,
            '-RestoreVerifiedReplacement', '-ReplacementTransactionId',$selectedTransactionId,
            '-ReplacementReceiptPath',$restoreReceiptFull, '-ReplacementReceiptSha256',$RestoreReceiptSha256,
            '-RestoreEvidencePath',$replacementRestoreEvidencePath,
            '-WriterFenceHelperPath',$writerFenceHelperPath,
            '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
            '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
            '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
        )
        if ($testMode) { $publicRestoreArguments += '-AllowNoncanonicalLayoutForTest' }
        & $winps @publicRestoreArguments
        if ($LASTEXITCODE -ne 0) { throw "Canonical code restore failed: $LASTEXITCODE" }
        $currentTreeInventorySha256 = [string]$publicRestore.old_inventory_sha256
        $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $currentTreeInventorySha256
        $restoreEvidence = ReadReplacementRestoreEvidence `
            -Path $replacementRestoreEvidencePath -ExpectedTransactionId $selectedTransactionId `
            -ExpectedReceiptPath $restoreReceiptFull -ExpectedReceiptSha256 $RestoreReceiptSha256 `
            -ExpectedInstallRoot $install
        $verifiedRestore = Read-CanonicalReplacementRestore
        if ([string]$verifiedRestore.state -cne 'RESTORED') { throw 'Canonical exact restore readback failed.' }
        $placement = 'RESTORED_VERIFIED'
        $audit.code_placement = $placement
        $audit.code_replacement.status = [string]$restoreEvidence.action
        $audit.code_replacement.restore_evidence_path = $replacementRestoreEvidencePath
        $audit.code_replacement.restore_evidence_sha256 = Sha $replacementRestoreEvidencePath
        $audit.code_replacement.later_restore_surface = 'CONSUMED'
        if ((Sha $stop) -cne $restoreStopSha256) { throw 'Canonical restore stop marker changed.' }
        Restore $before
        Remove-Item -LiteralPath $stop -Force
        $check = Snapshot
        if ([bool]$check.exists -ne [bool]$before.exists -or
            [string]$check.kind -cne [string]$before.kind -or
            [string]$check.data -cne [string]$before.data -or (Test-Path -LiteralPath $stop)) {
            throw 'Canonical restore runtime preimage readback failed.'
        }
        $audit.after = $check
        $audit.status = 'RESTORE_AWAITING_FENCE_RELEASE'
        Save $auditPath $audit
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productCompleteAuthorizationPath -Phase 'PRODUCT_COMPLETE' -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        foreach ($item in $old) { [void](StartRaw ([string]$item.CommandLine)) }
        if ($old.Count -gt 0) { Start-Sleep -Seconds 3 }
        [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
        $audit.status = 'PASS_RESTORED_VERIFIED_DATA_PRESERVED'
        $audit.rollback.applied = $true
        $audit.rollback.runtime_restored = $true
        $audit.rollback.code_exact = $true
        $audit.completed_at = [DateTime]::UtcNow.ToString('o')
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        'restore_status=PASS_RESTORED_VERIFIED_DATA_PRESERVED'
        'prior_code_exact=true'
        'failed_new_preserved=true'
        'current_user_runtime_preimage_restored=true'
        "audit_path=$auditPath"
        return
    }
    if ($Uninstall) {
        if (-not $existingVerified -or $placement -cne 'REUSED_VERIFIED' -or
            (Sha (Join-Path $install 'portable-manifest.json')) -cne $sourceManifestSha256 -or
            (Sha (Join-Path $install 'bootstrap-integrity.json')) -cne $uninstallRecordSha256 -or
            (Get-InventoryAggregate @(Get-CodeInventory $install)) -cne $uninstallAggregate) {
            throw 'Uninstall installed/source identity changed before mutation.'
        }
        Copy-Item -LiteralPath (Join-Path $install 'bootstrap-integrity.json') -Destination $uninstallRecordPreimagePath
        if ((Sha $uninstallRecordPreimagePath) -cne $uninstallRecordSha256) {
            throw 'Uninstall integrity preimage copy readback failed.'
        }
        $audit.code_integrity_preimage_path = $uninstallRecordPreimagePath
        $audit.code_integrity_preimage_sha256 = $uninstallRecordSha256
        $audit.code_recovery_path = Join-Path (Split-Path -Parent $install) ('.current.uninstall.' + $Script:CanonicalWriterFenceAttemptId)
        $mutated = $true
        Product $install '--remove-current-user-setup'
        $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Snapshot).exists -or [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
            [string]$removal.relay_process.status -cne 'ABSENT' -or @(Relays).Count -ne 0) {
            throw 'Uninstall current-user removal readback failed.'
        }
        $uninstallStopSha256 = Sha $stop
        $audit.status = 'UNINSTALL_RUNTIME_QUIESCED'
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        $uninstallArguments = @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'), '-Uninstall',
            '-SourceRoot',$source, '-InstallRoot',$install,
            '-OperatorLocalAppDataRoot',$lad, '-ElevationLogPath',$elevationLogPath,
            '-ExpectedInstalledManifestSha256',$sourceManifestSha256,
            '-ExpectedInstalledAggregateSha256',$uninstallAggregate,
            '-QuiesceReceiptPath',$removalPath, '-ExpectedQuiesceReceiptSha256',(Sha $removalPath),
            '-WriterFenceHelperPath',$writerFenceHelperPath,
            '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
            '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
            '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
        )
        if ($testMode) { $uninstallArguments += '-AllowNoncanonicalLayoutForTest' }
        $uninstallCodeStarted = $true
        & $winps @uninstallArguments
        if ($LASTEXITCODE -ne 0) { throw "Code removal failed: $LASTEXITCODE" }
        if ((Test-Path -LiteralPath $install) -or (Snapshot).exists -or @(Relays).Count -ne 0) {
            throw 'Uninstall independent code/runtime absence readback failed.'
        }
        if ((Sha $stop) -cne $uninstallStopSha256) { throw 'Uninstall stop marker changed.' }
        Remove-Item -LiteralPath $stop -Force
        if (Test-Path -LiteralPath $stop) { throw 'Uninstall stop-marker cleanup failed.' }
        $audit.status = 'UNINSTALL_AWAITING_FENCE_RELEASE'
        $audit.code_placement = 'REMOVED'
        $audit.after = Snapshot
        Save $auditPath $audit
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productCompleteAuthorizationPath -Phase 'PRODUCT_COMPLETE' -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        $audit.status = 'PASS_UNINSTALLED_DATA_PRESERVED'
        $audit.completed_at = [DateTime]::UtcNow.ToString('o')
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED'
        'application_root_status=ABSENT'
        'current_user_relay_status=ABSENT'
        'user_state_preserved=true'
        'server_identity_retired=false'
        "audit_path=$auditPath"
        return
    }
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
    if ($placement -eq 'INSTALL_REQUIRED') {
        $replaceExisting = Test-Path -LiteralPath $install -PathType Container
        if ($replaceExisting) {
            Sync-CanonicalWriterFenceInventory $installedInventorySha256
            $mutated = $true
            Product $install '--remove-current-user-setup'
            $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if (
                (Snapshot).exists -or
                [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
                [string]$removal.relay_process.status -cne 'ABSENT' -or
                @(Relays).Count -ne 0
            ) { throw 'Verified replacement runtime quiescence failed.' }
            $runtimeQuiescedForReplacement = $true
            $audit.code_replacement.status='PRESTATE_VERIFIED_RUNTIME_QUIESCED'
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
        }
        Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256
        $bootstrap = @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
            '-SourceRoot',$source,
            '-InstallRoot',$install,
            '-ElevationLogPath',$elevationLogPath,
            '-WriterFenceHelperPath',(Join-Path $source 'tools\container_writer_fence.ps1'),
            '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
            '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
            '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
        )
        if ($replaceExisting) {
            $bootstrap += @(
                '-ReplaceExistingVerifiedPortable',
                '-ReplacementTransactionId',$replacementTransactionId,
                '-ReplacementReceiptPath',$replacementReceiptPath
            )
        }
        if ($testMode) { $bootstrap += '-AllowNoncanonicalLayoutForTest' }
        $bootstrapOutput = @(& $winps @bootstrap)
        $bootstrapExitCode = $LASTEXITCODE
        if ($bootstrapExitCode -ne 0) { throw "Code placement failed: $bootstrapExitCode" }
        $currentTreeInventorySha256 = $Script:ContainerWriterFenceInventorySha256
        if ($replaceExisting) {
            $replacementReceiptSha256 = Sha $replacementReceiptPath
            $replacementReceipt = ReadReplacementReceipt `
                -Path $replacementReceiptPath `
                -ExpectedTransactionId $replacementTransactionId `
                -ExpectedInstallRoot $install `
                -ExpectedSourceManifest $sourceManifest `
                -ExpectedManifestSha256 $sourceManifestSha256 `
                -ExpectedHelperSha256 $sourceHelperSha256 `
                -ExpectedIntegrityHelperSha256 $sourceIntegrityHelperSha256
            if (
                -not (Test-Path -LiteralPath ([string]$replacementReceipt.rollback_root) -PathType Container) -or
                -not (Test-Path -LiteralPath $install -PathType Container)
            ) { throw 'Verified replacement preserved-tree readback failed.' }
            $codeRestoreNeeded = $true
            $placement = 'REPLACED_VERIFIED'
            $audit.code_replacement.status='OLD_PRESERVED_NEW_VERIFIED'
            $audit.code_replacement.receipt_path=$replacementReceiptPath
            $audit.code_replacement.receipt_sha256=$replacementReceiptSha256
            $audit.code_replacement.rollback_root=[string]$replacementReceipt.rollback_root
            $audit.code_replacement.later_restore_surface='READY_PUBLIC_CANONICAL_RESTORE'
        }
        else { $placement = 'PASS_NEW_VERIFIED' }
    }
    $installedManifest = InstalledManifest $install $SkipSignatureValidationForTest
    if (
        [string]$installedManifest.source_commit -cne [string]$sourceManifest.source_commit -or
        [string]$installedManifest.source_tree -cne [string]$sourceManifest.source_tree -or
        (Sha (Join-Path $install 'portable-manifest.json')) -cne $sourceManifestSha256
    ) { throw 'Installed identity differs.' }
    $installedHelper = (Join-Path $source 'tools\bootstrap_integrity.ps1').Replace("'","''")
    $escapedInstalledRoot = $install.Replace("'","''")
    & $winps -NoLogo -NoProfile -NonInteractive -Command ". '$installedHelper'; [void](Assert-BootstrapIntegrityRecord '$escapedInstalledRoot')"
    if ($LASTEXITCODE -ne 0) { throw 'Installed aggregate integrity differs.' }
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
        [string]$removal.relay_process.status -cne 'ABSENT' -or @(Relays).Count -ne 0) { throw 'Removal readback failed.' }
    $started = (Get-Date).ToUniversalTime()
    Product $install '--onboard-current-user'
    $onboarding = Get-Content $onboardingPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $after = Snapshot
    if ([string]$onboarding.status -cne 'READY' -or [string]$onboarding.relay_autostart.command -cne $wanted -or
        -not $after.exists -or [string]$after.data -cne $wanted) { throw 'Onboarding Run readback failed.' }
    if ($onboardingServerBaseUrl) {
        $boundServerBaseUri = $null
        if (
            -not [Uri]::TryCreate([string]$onboarding.state_readback.base_url, [UriKind]::Absolute, [ref]$boundServerBaseUri) -or
            $boundServerBaseUri.Scheme -cne 'https' -or
            $boundServerBaseUri.Host -ine $onboardingServerBaseUri.Host -or
            $boundServerBaseUri.Port -ne $onboardingServerBaseUri.Port
        ) { throw 'Onboarding server endpoint readback failed.' }
    }
    if (-not (Test-JsonPositiveInt32 $onboarding.relay_start.process_id)) {
        throw 'Onboarding relay process id type/readback failed.'
    }
    $pidValue = [int]$onboarding.relay_start.process_id
    Start-Sleep -Seconds 5
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction SilentlyContinue
    if ($null -eq $process -or -not (Same ([string]$process.ExecutablePath) (Join-Path $install 'runtime\pythonw.exe'))) { throw 'Relay process proof failed.' }
    $deadline=(Get-Date).AddSeconds(75)
    $relay=$null
    while((Get-Date)-lt $deadline){
        if((Test-Path $relayPath) -and (Get-Item $relayPath).LastWriteTimeUtc -ge $started.AddSeconds(-1)){
            $relay=Get-Content $relayPath -Raw -Encoding UTF8|ConvertFrom-Json
            if(Test-JsonTrue $relay.persistent_retry){break}
        }
        Start-Sleep -Milliseconds 500
    }
    if($null-eq$relay -or -not (Test-JsonTrue $relay.persistent_retry)){throw 'Fresh relay status proof failed.'}
    $audit.status=if ($testMode) { 'TEST_ONLY_PARTIAL' } else { 'PRODUCT_PHASE_PASS' }
    $audit.stop_marker_absent=-not(Test-Path $stop)
    $audit.onboarding=[ordered]@{status=[string]$onboarding.status;action=[string]$onboarding.action;autostart_writer='product_onboarding';server_base_url=$onboardingServerBaseUrlLabel;bound_server_base_url=[string]$onboarding.state_readback.base_url}
    $audit.exact_launch=[ordered]@{status='PROVEN';process_id=$pidValue;executable=[string]$process.ExecutablePath;relay_status=[string]$relay.status;persistent_retry=$relay.persistent_retry}
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }

    if ($writerRestoreNeeded) {
        Stop-CanonicalDelegatedRelay $pidValue
        $writerEnabled = Enable-CanonicalWriter $install $writerBefore
        $audit.scheduled_writer.restore_readback = $writerEnabled
        $audit.status='WRITER_ENABLED_AWAITING_NATURAL_TRIGGER'
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productNaturalTriggerAuthorizationPath `
            -Phase 'PRODUCT_NATURAL_TRIGGER' `
            -AuditPath $auditPath `
            -EnabledBaseline $writerEnabled
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        $pidValue = Start-CanonicalRelayAfterFenceRelease
        $writerRunning = Confirm-CanonicalWriterRunning $install $writerEnabled
        $audit.scheduled_writer.natural_trigger_proof = $writerRunning
        $audit.rollback.scheduled_writer_restored=$true
        $writerRestoreNeeded=$false
    }
    $terminalStatus=Get-CanonicalInstallSuccessStatus $testMode
    $audit.status=$terminalStatus
    $audit.completed_at=(Get-Date).ToUniversalTime().ToString('o')
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }
    if ($canonicalWriterFenceActive) {
        Stop-CanonicalDelegatedRelay $pidValue
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productCompleteAuthorizationPath `
            -Phase 'PRODUCT_COMPLETE' `
            -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        $pidValue = Start-CanonicalRelayAfterFenceRelease
    }
    "install_status=$terminalStatus"
    "install_root=$install"
    "code_placement_status=$placement"
    'autostart_status=PROVEN_NON_REBOOT_APPROXIMATION'
    "autostart_command=$wanted"
    "onboarding_server_base_url=$onboardingServerBaseUrlLabel"
    "autostart_process_id=$pidValue"
    "stop_marker_absent=$($audit.stop_marker_absent.ToString().ToLowerInvariant())"
    if ($codeRestoreNeeded) {
        "replacement_receipt_path=$replacementReceiptPath"
        "replacement_receipt_sha256=$replacementReceiptSha256"
        "replacement_transaction_id=$replacementTransactionId"
        'later_phase_replacement_restore_status=READY_PUBLIC_CANONICAL_RESTORE'
    }
    'cold_boot_status=UNPROVEN'
    "audit_path=$auditPath"
}
catch {
    $original=$_
    if (-not $enteredPlacementTry) {
        $earlyFenceMatches = $false
        try {
            $earlyFence = Read-ContainerWriterFence -AllowAbsent
            $earlyFenceMatches = (
                $null -ne $earlyFence -and
                [string]$earlyFence.session_id -ceq $Script:CanonicalWriterFenceSessionId -and
                [string]$earlyFence.attempt_id -ceq $Script:CanonicalWriterFenceAttemptId -and
                [string]$earlyFence.replacement_transaction_id -ceq $Script:CanonicalWriterFenceTransactionId
            )
        }
        catch { $earlyFenceMatches = $canonicalWriterFenceActive }
        if ($earlyFenceMatches) {
            try {
                [void](Abort-ContainerWriterFence `
                    -SessionId $Script:CanonicalWriterFenceSessionId `
                    -AttemptId $Script:CanonicalWriterFenceAttemptId `
                    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                    -AuthorityLease $canonicalWriterFenceAuthority)
                $canonicalWriterFenceActive = $false
            }
            catch { throw "CANONICAL_WRITER_FENCE_EARLY_ABORT_FAILED: $($_.Exception.GetType().Name)" }
        }
        if (Test-Path -LiteralPath $canonicalWriterFencePreparedPath) {
            Remove-Item -LiteralPath $canonicalWriterFencePreparedPath -Force
            if (Test-Path -LiteralPath $canonicalWriterFencePreparedPath) {
                throw 'CANONICAL_WRITER_FENCE_EARLY_RECEIPT_CLEANUP_FAILED'
            }
        }
        if ($earlyFenceMatches -and $old.Count -gt 0) {
            if (@(Relays).Count -eq 0) {
                foreach ($item in $old) { [void](StartRaw ([string]$item.CommandLine)) }
                Start-Sleep -Seconds 3
            }
            [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
        }
        throw $original
    }
    if (-not $canonicalWriterFenceActive) {
        try {
            $refenceStatus = 'INSTALLING'
            $refencePreparedPath = [string]$canonicalWriterFencePreparedReceipt.path
            $refencePreparedSha256 = [string]$canonicalWriterFencePreparedReceipt.sha256
            if (-not [string]::IsNullOrWhiteSpace($canonicalWriterFenceLastReleaseAuthorizationPath)) {
                $refenceStatus = 'RESTORE_FAILED'
                $refencePreparedPath = $canonicalWriterFenceLastReleaseAuthorizationPath
                $refencePreparedSha256 = $canonicalWriterFenceLastReleaseAuthorizationSha256
            }
            [void](Start-ContainerWriterFence `
                -Status $refenceStatus `
                -OwnerKind 'canonical_installer' `
                -SessionId $Script:CanonicalWriterFenceSessionId `
                -AttemptId $Script:CanonicalWriterFenceAttemptId `
                -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
                -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
                -WriterContractSha256 $canonicalWriterFenceContractSha256 `
                -PreparedReceiptPath $refencePreparedPath `
                -PreparedReceiptSha256 $refencePreparedSha256 `
                -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
                -DelegatedSources $canonicalWriterFenceDelegatedSources `
                -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) `
                -AuthorityLease $canonicalWriterFenceAuthority)
            $canonicalWriterFenceActive = $true
        }
        catch {
            throw "CANONICAL_WRITER_REFENCE_FAILED: $($_.Exception.GetType().Name)"
        }
    }
    if ($Uninstall) {
        # The source survives code removal. Renew this same live delegation even
        # if a failed release already cleared it; no foreign session is adopted.
        $uninstallActiveFence = Read-ContainerWriterFence
        [void](Set-ContainerWriterFencePrepared `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -PreparedReceiptPath ([string]$uninstallActiveFence.prepared_receipt_path) `
            -PreparedReceiptSha256 ([string]$uninstallActiveFence.prepared_receipt_sha256) `
            -Status 'RESTORING' -AuthorityLease $canonicalWriterFenceAuthority)
        [void](Set-ContainerWriterFenceDelegation `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
            -DelegatedSources $canonicalWriterFenceDelegatedSources `
            -LifetimeSeconds 300 `
            -AuthorityLease $canonicalWriterFenceAuthority)
        if ($uninstallCodeStarted -and -not (Test-Path -LiteralPath $install)) {
            $recoverCodeArguments = @($uninstallArguments | Where-Object { $_ -cne '-Uninstall' })
            $recoverCodeArguments += @('-RestoreUninstallRecordPath',$uninstallRecordPreimagePath,
                '-ExpectedUninstallRecordSha256',$uninstallRecordSha256)
            & $winps @recoverCodeArguments
            if ($LASTEXITCODE -ne 0) { throw "Uninstall exact code recovery failed: $LASTEXITCODE" }
        }
        [void](Assert-BootstrapIntegrityRecord $install)
        if ((Get-InventoryAggregate @(Get-CodeInventory $install)) -cne $uninstallAggregate -or
            (Sha (Join-Path $install 'bootstrap-integrity.json')) -cne $uninstallRecordSha256) {
            throw 'Uninstall exact code recovery not proven; runtime remains fenced.'
        }
        if ($uninstallCodeStarted) { $audit.code_placement = 'RESTORED_EXACT_PREIMAGE' }
        # A refusing original relay is never killed or duplicated. Restore its
        # persistence/stop preimage and release only this attempt's live fence.
        $remaining = @(Relays)
        foreach ($item in $remaining) {
            if (@($old | Where-Object { [int]$_.ProcessId -eq [int]$item.ProcessId -and
                [string]$_.CommandLine -ceq [string]$item.CommandLine -and
                (Same ([string]$_.ExecutablePath) ([string]$item.ExecutablePath)) }).Count -ne 1) {
                throw 'Uninstall recovery relay identity changed.'
            }
        }
        Restore $before
        if (Test-Path -LiteralPath $stop) { Remove-Item -LiteralPath $stop -Force }
        $check = Snapshot
        if ([bool]$check.exists -ne [bool]$before.exists -or [string]$check.kind -cne [string]$before.kind -or
            [string]$check.data -cne [string]$before.data -or (Test-Path -LiteralPath $stop)) {
            throw 'Uninstall runtime preimage restore failed.'
        }
        # Existing abort is authority/tuple checked and does not depend on audit
        # availability. Code and persistence are exact before writers reopen.
        [void](Abort-ContainerWriterFence -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -AuthorityLease $canonicalWriterFenceAuthority)
        $canonicalWriterFenceActive = $false
        if (@(Relays).Count -eq 0) {
            foreach ($item in $old) { [void](StartRaw ([string]$item.CommandLine)) }
            if ($old.Count -gt 0) { Start-Sleep -Seconds 3 }
        }
        [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
        $audit.status = 'FAILED_ROLLED_BACK'
        $audit.rollback.applied = $mutated
        $audit.rollback.runtime_restored = $true
        $audit.rollback.code_exact = $true
        try { Save $auditPath $audit; if ($evidenceFull) { Save $evidenceFull $audit } }
        catch { Write-Output 'rollback_audit_status=UNAVAILABLE' }
        'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY'
        throw $original
    }
    if ($RestoreVerifiedReplacement) {
        # A child can restore the code and then fail while writing its evidence.
        # Select the exact surviving tree before invoking any product recovery.
        try {
            $survivingRestore = Read-CanonicalReplacementRestore
            if ([string]$survivingRestore.state -ceq 'RESTORED') {
                $currentTreeInventorySha256 = [string]$survivingRestore.old_inventory_sha256
                $placement = 'RESTORED_VERIFIED'
                $audit.code_placement = $placement
            }
            $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $currentTreeInventorySha256
            $audit.code_replacement.status = [string]$survivingRestore.state
        }
        catch {
            $audit.status = 'RESTORE_FAILED_CODE_STATE_UNVERIFIED'
            $audit.failure_type = $original.Exception.GetType().Name
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
            throw 'Canonical restore failed; code state is unverified and writers remain fenced.'
        }
    }
    $autostartRollbackFailure=''
    $codeRollbackFailure=''
    if ($codeRestoreNeeded) {
        try {
            Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256
            Product $install '--remove-current-user-setup'
            if ((Snapshot).exists -or @(Relays).Count -ne 0) {
                throw 'Replacement rollback runtime quiescence failed.'
            }
            $restoreBootstrap = @(
                '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',(Join-Path $install 'INSTALL_THIS_PC.ps1'),
                '-InstallRoot',$install,
                '-ElevationLogPath',$elevationLogPath,
                '-RestoreVerifiedReplacement',
                '-ReplacementTransactionId',$replacementTransactionId,
                '-ReplacementReceiptPath',$replacementReceiptPath,
                '-ReplacementReceiptSha256',$replacementReceiptSha256,
                '-RestoreEvidencePath',$replacementRestoreEvidencePath,
                '-WriterFenceHelperPath',(Join-Path $install 'tools\container_writer_fence.ps1'),
                '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
                '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
                '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
                '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
                '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
            )
            if ($testMode) { $restoreBootstrap += '-AllowNoncanonicalLayoutForTest' }
            $restoreOutput = @(& $winps @restoreBootstrap)
            $restoreExitCode = $LASTEXITCODE
            if ($restoreExitCode -ne 0) { throw "Code restore failed: $restoreExitCode" }
            $currentTreeInventorySha256 = $installedInventorySha256
            $restoreEvidence = ReadReplacementRestoreEvidence `
                -Path $replacementRestoreEvidencePath `
                -ExpectedTransactionId $replacementTransactionId `
                -ExpectedReceiptPath $replacementReceiptPath `
                -ExpectedReceiptSha256 $replacementReceiptSha256 `
                -ExpectedInstallRoot $install
            $audit.code_replacement.status='RESTORED_LATER_PHASE_FAILURE'
            $audit.code_replacement.restore_evidence_path=$replacementRestoreEvidencePath
            $audit.code_replacement.restore_evidence_sha256=Sha $replacementRestoreEvidencePath
            $audit.code_replacement.later_restore_surface='CONSUMED'
            $codeRestoreNeeded=$false
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
        }
        catch {
            $codeRollbackFailure=$_.Exception.GetType().Name
            $audit.status='CODE_ROLLBACK_FAILED'
            $audit.code_replacement.status='ROLLBACK_FAILED_CONTAINED_OR_STOPPED'
            $audit.code_replacement.restore_failure_type=$codeRollbackFailure
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
        }
    }
    $audit.rollback.applied = $mutated
    $audit.rollback.runtime_restored = (-not $mutated)
    try {
        if ($mutated -and [string]::IsNullOrWhiteSpace($codeRollbackFailure)) {
            Sync-CanonicalWriterFenceInventory $currentTreeInventorySha256
            Product $install '--remove-current-user-setup'
            [void](Assert-RollbackRelayPreimage -ExpectedRelays @())
            Restore $before
            if (Test-Path $stop) { Remove-Item $stop -Force }
            $check = Snapshot
            if (
                [bool]$check.exists -ne [bool]$before.exists -or
                [string]$check.kind -cne [string]$before.kind -or
                [string]$check.data -cne [string]$before.data
            ) { throw 'registry restore failed' }
            $audit.rollback.runtime_restored = ($old.Count -eq 0)
        }
    }
    catch {
        $audit.status = 'AUTOSTART_ROLLBACK_FAILED'
        $audit.rollback.runtime_restored = $false
        $autostartRollbackFailure = $_.Exception.GetType().Name
        $audit.failure_type = $original.Exception.GetType().Name
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
    }
    if ($writerRestoreNeeded -and [string]::IsNullOrWhiteSpace($codeRollbackFailure)) {
        try {
            $writerEnabled = Enable-CanonicalWriter $install $writerBefore
            $audit.scheduled_writer.restore_readback = $writerEnabled
            $audit.status='ROLLBACK_WRITER_ENABLED_AWAITING_NATURAL_TRIGGER'
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
            $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
                -Path $rollbackNaturalTriggerAuthorizationPath `
                -Phase 'ROLLBACK_NATURAL_TRIGGER' `
                -AuditPath $auditPath `
                -EnabledBaseline $writerEnabled
            $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
            $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
            Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
            Clear-CanonicalWriterFenceReleaseDelegation
            Stop-CanonicalWriterFenceRelease $releaseAuthorization
            $canonicalWriterFenceActive = $false
            $writerRunning = Confirm-CanonicalWriterRunning $install $writerEnabled
            $audit.scheduled_writer.natural_trigger_proof = $writerRunning
            $audit.rollback.scheduled_writer_restored=$true
            $writerRestoreNeeded=$false
        }
        catch {
            $restoreFailure = $_
            if (-not $canonicalWriterFenceActive) {
                try {
                    [void](Start-ContainerWriterFence `
                        -Status 'RESTORE_FAILED' `
                        -OwnerKind 'canonical_installer' `
                        -SessionId $Script:CanonicalWriterFenceSessionId `
                        -AttemptId $Script:CanonicalWriterFenceAttemptId `
                        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                        -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
                        -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
                        -WriterContractSha256 $canonicalWriterFenceContractSha256 `
                        -PreparedReceiptPath $canonicalWriterFenceLastReleaseAuthorizationPath `
                        -PreparedReceiptSha256 $canonicalWriterFenceLastReleaseAuthorizationSha256 `
                        -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
                        -DelegatedSources $canonicalWriterFenceDelegatedSources `
                        -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) `
                        -AuthorityLease $canonicalWriterFenceAuthority)
                    $canonicalWriterFenceActive = $true
                    [void](Disable-CanonicalWriter $install $writerBefore)
                }
                catch {
                    throw "CANONICAL_WRITER_REFENCE_FAILED: $($_.Exception.GetType().Name)"
                }
            }
            $audit.status='CANONICAL_WRITER_RESTORE_FAILED'
            $audit.scheduled_writer.restore_failure_code='CANONICAL_WRITER_RESTORE_FAILED'
            $audit.failure_type=$original.Exception.GetType().Name
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
            throw "CANONICAL_WRITER_RESTORE_FAILED: $($restoreFailure.Exception.GetType().Name)"
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($autostartRollbackFailure)) {
        throw "AUTOSTART_ROLLBACK_FAILED: $autostartRollbackFailure"
    }
    if (-not [string]::IsNullOrWhiteSpace($codeRollbackFailure)) {
        throw "CODE_ROLLBACK_FAILED: $codeRollbackFailure"
    }
    $audit.status='ROLLBACK_AWAITING_FENCE_RELEASE'
    $audit.failure_type=$original.Exception.GetType().Name
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }
    if ($canonicalWriterFenceActive) {
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $rollbackCompleteAuthorizationPath `
            -Phase 'ROLLBACK_COMPLETE' `
            -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
    }
    # Win32_Process.Create does not inherit this process's delegation. Restore
    # the old relay only after releasing the fence, as on the success path.
    try {
        if ($mutated) {
            foreach ($item in $old) {
                $newPid = StartRaw ([string]$item.CommandLine)
                Start-Sleep -Seconds 3
                $p = Get-CimInstance Win32_Process -Filter "ProcessId = $newPid" -ErrorAction SilentlyContinue
                if ($null -eq $p -or -not (Same ([string]$p.ExecutablePath) ([string]$item.ExecutablePath))) {
                    throw 'runtime restore failed'
                }
            }
            [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
            $audit.rollback.runtime_restored = $true
        }
    }
    catch {
        $audit.status='AUTOSTART_ROLLBACK_FAILED'
        $audit.rollback.runtime_restored=$false
        Save $auditPath $audit
        if ($evidenceFull) { Save $evidenceFull $audit }
        throw "AUTOSTART_ROLLBACK_FAILED: $($_.Exception.GetType().Name)"
    }
    # A fresh placement has no old code tree to restore. Its verified files
    # remain available even after the current-user runtime preimage is restored.
    $audit.status = if ($RestoreVerifiedReplacement) {
        'FAILED_RESTORE_RUNTIME_RECOVERED'
    } elseif ($placement -ceq 'PASS_NEW_VERIFIED') {
        'FAILED_RUNTIME_RESTORED_CODE_RETAINED'
    } else {
        'FAILED_ROLLED_BACK'
    }
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }
    if ($placement -ceq 'PASS_NEW_VERIFIED') {
        Write-Warning "Current-user runtime restored. New verified code remains at $install"
    }
    throw $original
}
finally {
    $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = ''
    foreach ($name in $canonicalWriterFenceEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $canonicalWriterFenceEnvironmentBefore[$name], 'Process')
    }
    if ($null -ne $canonicalWriterFenceAuthority) {
        Exit-ContainerWriterSessionAuthority $canonicalWriterFenceAuthority
    }
}
