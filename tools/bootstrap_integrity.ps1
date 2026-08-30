$BootstrapIntegrityFileName = "bootstrap-integrity.json"
$BootstrapIntegritySchema = "container-audit-bootstrap-integrity-v1"

function Get-StrictFullPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose must be an absolute path."
    }
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "$Purpose must not use a device namespace."
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($full) -or $full -eq [IO.Path]::GetPathRoot($full)) {
        throw "$Purpose must not be a filesystem root."
    }
    return $full
}

function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-RelativeCodePath([string]$Root, [string]$Path) {
    $rootFull = (Get-StrictFullPath $Root "inventory root") + '\'
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Inventory path escaped its root."
    }
    return $pathFull.Substring($rootFull.Length).Replace('\', '/')
}

function Get-CodeInventory([string]$Root) {
    $rootFull = Get-StrictFullPath $Root "code root"
    $result = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $rootFull -File -Force -Recurse | Sort-Object FullName)) {
        $relative = Get-RelativeCodePath $rootFull $file.FullName
        if ($relative.Equals($BootstrapIntegrityFileName, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $result += [pscustomobject][ordered]@{
            path = $relative
            size = [int64]$file.Length
            sha256 = Get-FileSha256 $file.FullName
        }
    }
    return $result
}

function Get-InventoryAggregate([object[]]$Inventory) {
    $lines = @($Inventory | ForEach-Object { "$($_.sha256) $($_.size) $($_.path)" })
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($lines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Write-Utf8Json([string]$Path, $Payload) {
    $temporary = "$Path.tmp.$PID"
    $json = $Payload | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Write-BootstrapIntegrityRecord(
    [string]$Root,
    [string]$CodeRootIdentity,
    [string]$RecordedAt = ""
) {
    $rootFull = Get-StrictFullPath $Root "bootstrap integrity root"
    $inventory = @(Get-CodeInventory $rootFull)
    if ($inventory.Count -eq 0) {
        throw "Bootstrap integrity inventory is empty."
    }
    if ([string]::IsNullOrWhiteSpace($RecordedAt)) {
        $RecordedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    $record = [ordered]@{
        schema_version = $BootstrapIntegritySchema
        status = 'PASS'
        code_root = $CodeRootIdentity
        installed_at = $RecordedAt
        file_count = $inventory.Count
        aggregate_sha256 = Get-InventoryAggregate $inventory
        files = $inventory
        identity_profile_created = $false
        state_scope = 'current_user_first_run'
    }
    Write-Utf8Json (Join-Path $rootFull $BootstrapIntegrityFileName) $record
    return [pscustomobject]$record
}

function Assert-BootstrapIntegrityRecord([string]$Root) {
    $rootFull = Get-StrictFullPath $Root "bootstrap integrity root"
    $recordPath = Join-Path $rootFull $BootstrapIntegrityFileName
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw "Bootstrap integrity record is absent."
    }
    $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$record.schema_version -cne $BootstrapIntegritySchema -or [string]$record.status -cne 'PASS') {
        throw "Bootstrap integrity record schema or status is invalid."
    }
    if ([string]$record.code_root -ceq '.') {
        $declaredCodeRoot = $rootFull
    }
    else {
        $declaredCodeRoot = Get-StrictFullPath ([string]$record.code_root) "bootstrap integrity code root"
    }
    if (-not $declaredCodeRoot.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Bootstrap integrity record code root is invalid."
    }
    $inventory = @(Get-CodeInventory $rootFull)
    if (
        -not (Test-BootstrapJsonInteger $record.file_count) -or
        [int64]$record.file_count -ne $inventory.Count -or
        @($record.files).Count -ne $inventory.Count
    ) {
        throw "Bootstrap integrity record file count is invalid."
    }
    for ($index = 0; $index -lt $inventory.Count; $index += 1) {
        $actual = $inventory[$index]
        $expected = @($record.files)[$index]
        if (
            -not (Test-BootstrapJsonInteger $expected.size) -or
            -not (Test-BootstrapJsonInteger $actual.size) -or
            [string]$expected.path -cne [string]$actual.path -or
            [int64]$expected.size -ne [int64]$actual.size -or
            [string]$expected.sha256 -cne [string]$actual.sha256
        ) {
            throw "Bootstrap integrity inventory differs at index $index."
        }
    }
    $aggregate = Get-InventoryAggregate $inventory
    if ([string]$record.aggregate_sha256 -cne $aggregate) {
        throw "Bootstrap integrity aggregate is invalid."
    }
    $frozenMainCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'Container_Audit.exe' }
    ).Count
    $portablePythonCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'runtime/pythonw.exe' }
    ).Count
    $portableMainCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'app/main.py' }
    ).Count
    $frozenLayout = $frozenMainCount -eq 1
    $portableLayout = $portablePythonCount -eq 1 -and $portableMainCount -eq 1
    if ($frozenLayout -eq $portableLayout) {
        throw "Bootstrap integrity record does not identify exactly one supported release layout."
    }
    return [pscustomobject]@{
        status = 'PASS'
        record_path = $recordPath
        file_count = $inventory.Count
        aggregate_sha256 = $aggregate
    }
}

function Test-BootstrapJsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}

function Get-BootstrapStringSha256([string]$Value) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-BootstrapSamePath([string]$Left, [string]$Right) {
    return (Get-StrictFullPath $Left 'left path').Equals(
        (Get-StrictFullPath $Right 'right path'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-BootstrapNoReparsePoint([string]$Path, [string]$Purpose) {
    $root = Get-StrictFullPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $root)) { throw "$Purpose is unavailable." }
    $items = @((Get-Item -LiteralPath $root -Force -ErrorAction Stop))
    if ($items[0].PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
    }
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose contains a reparse point: $($item.FullName)"
        }
    }
}

function Get-BootstrapAclIdentity([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $acl = if ($item.PSIsContainer) {
        [IO.Directory]::GetAccessControl($item.FullName, $sections)
    }
    else {
        [IO.File]::GetAccessControl($item.FullName, $sections)
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $sddl = $acl.GetSecurityDescriptorSddlForm($sections)
    if ($acl.AreAccessRulesProtected -isnot [bool]) {
        throw 'Bootstrap ACL protection readback type is invalid.'
    }
    return [pscustomobject][ordered]@{
        owner_sid = [string]$owner
        access_rules_protected = $acl.AreAccessRulesProtected
        sddl_sha256 = Get-BootstrapStringSha256 $sddl
    }
}

function Assert-BootstrapRelocatedIntegrityRecord(
    [string]$Root,
    [string]$ExpectedCodeRoot
) {
    $rootFull = Get-StrictFullPath $Root 'relocated bootstrap root'
    $expectedRoot = Get-StrictFullPath $ExpectedCodeRoot 'declared bootstrap root'
    $recordPath = Join-Path $rootFull $BootstrapIntegrityFileName
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw 'Relocated bootstrap integrity record is absent.'
    }
    if ((Get-Item -LiteralPath $recordPath -Force).Length -gt 1048576) {
        throw 'Relocated bootstrap integrity record is oversized.'
    }
    $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$record.schema_version -cne $BootstrapIntegritySchema -or
        [string]$record.status -cne 'PASS' -or
        -not (Test-BootstrapSamePath ([string]$record.code_root) $expectedRoot)
    ) {
        throw 'Relocated bootstrap integrity identity is invalid.'
    }
    $inventory = @(Get-CodeInventory $rootFull)
    $aggregate = Get-InventoryAggregate $inventory
    if (
        -not (Test-BootstrapJsonInteger $record.file_count) -or
        [int64]$record.file_count -ne $inventory.Count -or
        @($record.files).Count -ne $inventory.Count -or
        [string]$record.aggregate_sha256 -cne $aggregate
    ) {
        throw 'Relocated bootstrap integrity aggregate differs.'
    }
    $actualByPath = @{}
    foreach ($item in $inventory) { $actualByPath[[string]$item.path] = $item }
    foreach ($expected in @($record.files)) {
        $path = [string]$expected.path
        if (-not $actualByPath.ContainsKey($path)) {
            throw 'Relocated bootstrap integrity inventory is incomplete.'
        }
        $actual = $actualByPath[$path]
        if (
            -not (Test-BootstrapJsonInteger $expected.size) -or
            -not (Test-BootstrapJsonInteger $actual.size) -or
            [int64]$expected.size -ne [int64]$actual.size -or
            [string]$expected.sha256 -cne [string]$actual.sha256
        ) {
            throw 'Relocated bootstrap integrity inventory differs.'
        }
        $actualByPath.Remove($path)
    }
    if ($actualByPath.Count -ne 0) {
        throw 'Relocated bootstrap integrity contains unrecorded files.'
    }
    return [pscustomobject][ordered]@{
        file_count = $inventory.Count
        aggregate_sha256 = $aggregate
        integrity_sha256 = Get-FileSha256 $recordPath
    }
}

function Get-BootstrapReplacementTreeIdentity(
    [string]$Root,
    [string]$DeclaredCodeRoot
) {
    $rootFull = Get-StrictFullPath $Root 'replacement tree'
    Assert-BootstrapNoReparsePoint $rootFull 'replacement tree'
    $integrity = Assert-BootstrapRelocatedIntegrityRecord `
        -Root $rootFull `
        -ExpectedCodeRoot $DeclaredCodeRoot
    $manifestPath = Join-Path $rootFull 'portable-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Replacement tree portable manifest is absent.'
    }
    if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 65536) {
        throw 'Replacement tree portable manifest is oversized.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$manifest.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.source_tree -cnotmatch '^[0-9a-f]{40}$'
    ) {
        throw 'Replacement tree portable identity is invalid.'
    }
    $acl = Get-BootstrapAclIdentity $rootFull
    return [pscustomobject][ordered]@{
        file_count = $integrity.file_count
        aggregate_sha256 = [string]$integrity.aggregate_sha256
        integrity_sha256 = [string]$integrity.integrity_sha256
        manifest_sha256 = Get-FileSha256 $manifestPath
        source_commit = [string]$manifest.source_commit
        source_tree = [string]$manifest.source_tree
        owner_sid = [string]$acl.owner_sid
        access_rules_protected = $acl.access_rules_protected
        acl_sddl_sha256 = [string]$acl.sddl_sha256
        reparse_count = 0
    }
}

function Test-BootstrapReplacementTreeIdentity($Expected, $Actual) {
    if ($null -eq $Expected -or $null -eq $Actual) { return $false }
    foreach ($name in @('file_count', 'reparse_count')) {
        if (
            -not (Test-BootstrapJsonInteger $Expected.$name) -or
            -not (Test-BootstrapJsonInteger $Actual.$name) -or
            [int64]$Expected.$name -ne [int64]$Actual.$name
        ) { return $false }
    }
    if (
        $Expected.access_rules_protected -isnot [bool] -or
        $Actual.access_rules_protected -isnot [bool] -or
        $Expected.access_rules_protected -ne $Actual.access_rules_protected
    ) { return $false }
    foreach ($name in @(
        'aggregate_sha256', 'integrity_sha256', 'manifest_sha256', 'source_commit',
        'source_tree', 'owner_sid', 'acl_sddl_sha256'
    )) {
        if ([string]$Expected.$name -cne [string]$Actual.$name) { return $false }
    }
    return $true
}

function Write-BootstrapReplacementReceipt(
    [string]$Path,
    $Payload,
    [switch]$AllowReplace
) {
    $full = Get-StrictFullPath $Path 'replacement receipt path'
    $parent = Split-Path -Parent $full
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-BootstrapNoReparsePoint $parent 'replacement receipt parent'
    if ((Test-Path -LiteralPath $full) -and -not $AllowReplace.IsPresent) {
        throw 'Replacement receipt path already exists.'
    }
    Write-Utf8Json -Path $full -Payload $Payload
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Replacement receipt write readback failed.'
    }
    return [pscustomobject][ordered]@{
        path = $full
        sha256 = Get-FileSha256 $full
    }
}

function Read-BootstrapReplacementReceipt(
    [string]$Path,
    [string]$ExpectedSha256
) {
    $full = Get-StrictFullPath $Path 'replacement receipt path'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Replacement receipt is absent.'
    }
    Assert-BootstrapNoReparsePoint $full 'replacement receipt'
    $length = (Get-Item -LiteralPath $full -Force).Length
    if ($length -le 0 -or $length -gt 131072) { throw 'Replacement receipt size is invalid.' }
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Replacement receipt SHA-256 is invalid.'
    }
    if ((Get-FileSha256 $full) -cne $ExpectedSha256) {
        throw 'Replacement receipt SHA-256 differs.'
    }
    try { return Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Replacement receipt JSON is invalid.' }
}

function Invoke-BootstrapVerifiedReplacementRestore(
    $Receipt,
    [string]$ReceiptPath,
    [string]$InstallRoot,
    [string]$ExpectedAppId,
    [string]$ExpectedTransactionId,
    [string]$ExpectedHelperSha256,
    [switch]$InjectFailureAfterDisplace
) {
    $current = Get-StrictFullPath $InstallRoot 'restore current root'
    $parent = Get-StrictFullPath (Split-Path -Parent $current) 'restore parent'
    $rollback = Get-StrictFullPath ([string]$Receipt.rollback_root) 'restore rollback root'
    $failed = Get-StrictFullPath ([string]$Receipt.failed_root) 'restore failed root'
    $receiptFull = Get-StrictFullPath $ReceiptPath 'replacement receipt path'
    if (
        [string]$Receipt.schema_version -cne 'container-audit-verified-replacement-v1' -or
        [string]$Receipt.status -cne 'OLD_PRESERVED_NEW_VERIFIED' -or
        [string]$Receipt.app_id -cne $ExpectedAppId -or
        [string]$Receipt.transaction_id -cne $ExpectedTransactionId -or
        [string]$Receipt.helper_sha256 -cne $ExpectedHelperSha256 -or
        -not (Test-BootstrapSamePath ([string]$Receipt.receipt_path) $receiptFull) -or
        -not (Test-BootstrapSamePath ([string]$Receipt.install_root) $current) -or
        -not (Test-BootstrapSamePath ([string]$Receipt.install_parent) $parent) -or
        -not (Test-BootstrapSamePath (Split-Path -Parent $rollback) $parent) -or
        -not (Test-BootstrapSamePath (Split-Path -Parent $failed) $parent) -or
        [IO.Path]::GetFileName($rollback) -cnotmatch '^\.current\.rollback\.[0-9a-f]{32}$' -or
        [IO.Path]::GetFileName($failed) -cne ".current.failed.$ExpectedTransactionId"
    ) {
        throw 'Replacement receipt identity or path binding is invalid.'
    }
    Assert-BootstrapNoReparsePoint $parent 'replacement restore parent'
    $parentAcl = Get-BootstrapAclIdentity $parent
    if (
        [string]$Receipt.parent_acl.owner_sid -cne [string]$parentAcl.owner_sid -or
        $Receipt.parent_acl.access_rules_protected -isnot [bool] -or
        $parentAcl.access_rules_protected -isnot [bool] -or
        $Receipt.parent_acl.access_rules_protected -ne $parentAcl.access_rules_protected -or
        [string]$Receipt.parent_acl.sddl_sha256 -cne [string]$parentAcl.sddl_sha256
    ) { throw 'Replacement restore parent ACL identity differs.' }
    $siblings = @(Get-ChildItem -LiteralPath $parent -Directory -Force | Where-Object {
        $_.Name -match '^\.current\.(rollback|failed)\.'
    } | ForEach-Object { $_.FullName })
    $allowed = @($rollback, $failed | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
    foreach ($sibling in $siblings) {
        if (@($allowed | Where-Object { Test-BootstrapSamePath $_ $sibling }).Count -ne 1) {
            throw 'An unrelated replacement sibling makes restore ambiguous.'
        }
    }

    $currentExists = Test-Path -LiteralPath $current -PathType Container
    $rollbackExists = Test-Path -LiteralPath $rollback -PathType Container
    $failedExists = Test-Path -LiteralPath $failed -PathType Container
    $currentIdentity = if ($currentExists) { Get-BootstrapReplacementTreeIdentity $current $current } else { $null }
    $rollbackIdentity = if ($rollbackExists) { Get-BootstrapReplacementTreeIdentity $rollback $current } else { $null }
    $failedIdentity = if ($failedExists) { Get-BootstrapReplacementTreeIdentity $failed $current } else { $null }
    $pending = $currentExists -and $rollbackExists -and -not $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $currentIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $rollbackIdentity)
    $displaced = -not $currentExists -and $rollbackExists -and $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $rollbackIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
    $restored = $currentExists -and -not $rollbackExists -and $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $currentIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
    if ($restored) {
        return [pscustomobject][ordered]@{
            status = 'ALREADY_RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    if (-not $pending -and -not $displaced) {
        throw 'Replacement restore state is ambiguous or drifted.'
    }
    try {
        if ($pending) { Move-Item -LiteralPath $current -Destination $failed -ErrorAction Stop }
        if ($InjectFailureAfterDisplace.IsPresent) { throw 'Injected restore failure after current displacement.' }
        Move-Item -LiteralPath $rollback -Destination $current -ErrorAction Stop
        $restoredOld = Get-BootstrapReplacementTreeIdentity $current $current
        $preservedNew = Get-BootstrapReplacementTreeIdentity $failed $current
        if (
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.old $restoredOld) -or
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.new $preservedNew)
        ) { throw 'Replacement restore exact readback failed.' }
        return [pscustomobject][ordered]@{
            status = 'RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    catch {
        $original = $_.Exception.Message
        $contained = $false
        try {
            if (
                (Test-Path -LiteralPath $current -PathType Container) -and
                -not (Test-Path -LiteralPath $rollback) -and
                (Test-Path -LiteralPath $failed -PathType Container)
            ) {
                Move-Item -LiteralPath $current -Destination $rollback -ErrorAction Stop
            }
            if (
                -not (Test-Path -LiteralPath $current) -and
                (Test-Path -LiteralPath $failed -PathType Container)
            ) {
                Move-Item -LiteralPath $failed -Destination $current -ErrorAction Stop
            }
            $containedCurrent = Get-BootstrapReplacementTreeIdentity $current $current
            $containedRollback = Get-BootstrapReplacementTreeIdentity $rollback $current
            $contained = (
                -not (Test-Path -LiteralPath $failed) -and
                (Test-BootstrapReplacementTreeIdentity $Receipt.new $containedCurrent) -and
                (Test-BootstrapReplacementTreeIdentity $Receipt.old $containedRollback)
            )
        }
        catch { $contained = $false }
        if (-not $contained) { throw "Replacement restore failed and containment also failed: $original" }
        throw "Replacement restore failed; the pre-restore state was contained: $original"
    }
}
