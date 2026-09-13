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

function Get-BootstrapSharedPortableLeaf([string]$Root) {
    # This bootstrap is trusted with the installer. Never use shared code to
    # authenticate itself, or derive the expected release pin from input bytes.
    $rootFull = Get-StrictFullPath $Root 'shared installer root'
    Assert-BootstrapNoReparsePoint $rootFull 'shared installer root' -PathOnly
    $appRoot = $rootFull
    if (Test-Path -LiteralPath (Join-Path $rootFull 'app') -PathType Container) {
        $appRoot = Join-Path $rootFull 'app'
    }
    $lockPath = Join-Path $appRoot 'kmtech_shared.lock.json'
    $manifestPath = Join-Path $appRoot 'kmtech_shared.manifest.json'
    $sharedLeaf = Join-Path $appRoot 'kmtech_shared\powershell\portable.ps1'
    foreach ($path in @($lockPath, $manifestPath, $sharedLeaf)) {
        Assert-BootstrapNoReparsePoint $path 'shared installer input' -PathOnly
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Shared installer input must be a file.'
        }
    }
    $expectedManifestSha = 'feaed459688e915eb5f52f264501a4287261d9dcbdbc50e0c6f4bde59d8e7117'
    if ((Get-Item -LiteralPath $lockPath).Length -gt 65536) { throw 'Shared consumer lock is oversized.' }
    $lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($lock.PSObject.Properties.Name).Count -ne 2 -or
        $lock.version -cne '0.3.1' -or $lock.manifest_sha256 -cne $expectedManifestSha) {
        throw 'Shared consumer lock pin mismatch.'
    }
    if ((Get-FileSha256 $manifestPath) -cne $expectedManifestSha) {
        throw 'Shared manifest pin mismatch.'
    }
    $pinnedSharedManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $expectedLeafSha = $pinnedSharedManifest.files.'kmtech_shared/powershell/portable.ps1'
    if ((Get-FileHash -LiteralPath $sharedLeaf -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedLeafSha) {
        throw 'Shared PowerShell leaf pin mismatch.'
    }
    return $sharedLeaf
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

function Assert-BootstrapNoReparsePoint([string]$Path, [string]$Purpose, [switch]$PathOnly) {
    $root = Get-StrictFullPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $root)) { throw "$Purpose is unavailable." }
    $items = @((Get-Item -LiteralPath $root -Force -ErrorAction Stop))
    $ancestor = Split-Path -Parent $root
    while ($ancestor) {
        $items += Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        $next = Split-Path -Parent $ancestor
        if ($next -eq $ancestor) { break }
        $ancestor = $next
    }
    if (-not $PathOnly -and $items[0].PSIsContainer) {
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
    Assert-BootstrapNoReparsePoint $parent 'replacement receipt parent' -PathOnly
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

function Get-BootstrapVerifiedReplacementRestoreState(
    $Receipt,
    [string]$ReceiptPath,
    [string]$InstallRoot,
    [string]$ExpectedAppId,
    [string]$ExpectedTransactionId,
    [string]$ExpectedHelperSha256
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
        $ExpectedTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        [IO.Path]::GetFileName($rollback) -cne ".current.rollback.$ExpectedTransactionId" -or
        [IO.Path]::GetFileName($failed) -cne ".current.failed.$ExpectedTransactionId"
    ) {
        throw 'Replacement receipt identity or path binding is invalid.'
    }
    Assert-BootstrapNoReparsePoint $parent 'replacement restore parent' -PathOnly
    $parentAcl = Get-BootstrapAclIdentity $parent
    if (
        [string]$Receipt.parent_acl.owner_sid -cne [string]$parentAcl.owner_sid -or
        $Receipt.parent_acl.access_rules_protected -isnot [bool] -or
        $parentAcl.access_rules_protected -isnot [bool] -or
        $Receipt.parent_acl.access_rules_protected -ne $parentAcl.access_rules_protected -or
        [string]$Receipt.parent_acl.sddl_sha256 -cne [string]$parentAcl.sddl_sha256
    ) { throw 'Replacement restore parent ACL identity differs.' }
    # Only the receipt-selected trees participate in this transaction. Retained
    # history is neither read nor moved; each selected tree is checked recursively.
    foreach ($selected in @($current, $rollback, $failed)) {
        if ((Test-Path -LiteralPath $selected) -and
            -not (Test-Path -LiteralPath $selected -PathType Container)) {
            throw 'Replacement restore selected path is not a directory.'
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
    if (-not $pending -and -not $displaced -and -not $restored) {
        throw 'Replacement restore state is ambiguous or drifted.'
    }
    return [pscustomobject][ordered]@{
        status = if ($restored) { 'RESTORED' } elseif ($pending) { 'PENDING' } else { 'DISPLACED' }
        install_root = $current
        rollback_root = $rollback
        failed_new_root = $failed
    }
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
    $state = Get-BootstrapVerifiedReplacementRestoreState `
        -Receipt $Receipt -ReceiptPath $ReceiptPath -InstallRoot $InstallRoot `
        -ExpectedAppId $ExpectedAppId -ExpectedTransactionId $ExpectedTransactionId `
        -ExpectedHelperSha256 $ExpectedHelperSha256
    $current = [string]$state.install_root
    $rollback = [string]$state.rollback_root
    $failed = [string]$state.failed_new_root
    if ([string]$state.status -ceq 'RESTORED') {
        return [pscustomobject][ordered]@{
            status = 'ALREADY_RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    try {
        if ([string]$state.status -ceq 'PENDING') { Move-Item -LiteralPath $current -Destination $failed -ErrorAction Stop }
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

function Test-WriterSessionContractExactPropertySet($Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) { return $false }
    }
    return $true
}

function Test-WriterSessionContractExactStringProperties($Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    foreach ($name in $Names) {
        $property = $Value.PSObject.Properties[$name]
        if ($null -eq $property -or -not ($property.Value -is [string])) { return $false }
    }
    return $true
}

function Get-WriterSessionContractMutexName($Fence, $Vector) {
    $values = @(
        [string]$Fence.session_tuple_version,
        [string]$Vector.session_id,
        [string]$Vector.attempt_id,
        [string]$Vector.orchestrator_sha256,
        [string]$Vector.replacement_transaction_id,
        [string]$Vector.writer_contract_sha256
    )
    $normalized = @($values | ForEach-Object {
        $_.Normalize([Text.NormalizationForm]::FormC)
    })
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($normalized -join "`n"))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
    return [string]$Fence.session_mutex_prefix + $digest
}

function Assert-WriterSessionPublicContract([string]$Path, [string]$ExpectedSha256) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 65536) {
        throw "Writer session public contract is oversized."
    }
    if ((Get-FileSha256 $Path) -cne $ExpectedSha256) {
        throw "Writer session public contract hash differs."
    }
    try { $contract = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Writer session public contract JSON is invalid." }
    $bindings = @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','session_authority_mutex_name','adapter_sha256','contract_sha256','evidence_path','historical_capability.receipt_sha256','historical_capability.capability_binding_sha256')
    $fenceFields = @('active_schema','release_schema','control_root','active_filename','release_filename_pattern','admission_mutex_name','noncanonical_mutex_derivation','session_mutex_prefix','session_tuple_version','session_tuple_fields','tuple_separator','tuple_encoding','tuple_normalization','writer_inventory_path','writer_inventory_sha256','canonical_installer_delegation_source','scheduled_task_mutation_rule','natural_trigger_phase_rule','verification_vectors','active_statuses','writer_admission_fail_closed','unknown_or_unobservable_is_denied','denial_mutates_state')
    $fenceStringFields = @('active_schema','release_schema','control_root','active_filename','release_filename_pattern','admission_mutex_name','noncanonical_mutex_derivation','session_mutex_prefix','session_tuple_version','tuple_separator','tuple_encoding','tuple_normalization','writer_inventory_path','writer_inventory_sha256','canonical_installer_delegation_source','scheduled_task_mutation_rule','natural_trigger_phase_rule')
    $vectorFields = @('session_id','attempt_id','orchestrator_sha256','replacement_transaction_id','writer_contract_sha256','expected_mutex_name')
    $vectors = @($contract.all_writer_fence.verification_vectors)
    $vectorsValid = $vectors.Count -eq 2
    foreach ($vector in $vectors) {
        if (
            -not (Test-WriterSessionContractExactPropertySet $vector $vectorFields) -or
            -not (Test-WriterSessionContractExactStringProperties $vector $vectorFields) -or
            [string]$vector.session_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.orchestrator_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$vector.replacement_transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.writer_contract_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$vector.expected_mutex_name -cne (Get-WriterSessionContractMutexName $contract.all_writer_fence $vector)
        ) { $vectorsValid = $false }
    }
    if ($vectors.Count -eq 2) {
        $vectorsValid = $vectorsValid -and
            [string]$vectors[0].expected_mutex_name -ceq 'Local\KMTech.ContainerAudit.DeploymentSession.1121406d92315036b04c14edfea1a09a03938923fa052324623e225d006a7b0c' -and
            [string]$vectors[1].expected_mutex_name -ceq 'Local\KMTech.ContainerAudit.DeploymentSession.7487aff53f2ea39a278e3648037625e8c1484636d80a5177dee05ba06556f071'
    }
    $requiredTrue = @(
        $contract.lifecycle_restore.require_same_session_receipt,
        $contract.lifecycle_restore.require_code_restore_before_writer_restore,
        $contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore,
        $contract.lifecycle_restore.require_live_current_user_lifecycle_before_writer_restore,
        $contract.lifecycle_restore.require_non_elevated_medium_integrity_lifecycle_producer,
        $contract.lifecycle_restore.producer_code_tree_read_locked_through_execution,
        $contract.lifecycle_restore.failure_is_explicit,
        $contract.security.active_session_authority_mutex_required,
        $contract.security.all_writer_fence_required,
        $contract.security.all_writer_sinks_require_admission,
        $contract.security.evidence_paths_outside_install_parent_required,
        $contract.security.evidence_paths_local_fixed_drive_required,
        $contract.security.evidence_path_reparse_ancestors_forbidden,
        $contract.security.evidence_path_aliases_canonicalized
    )
    $requiredFalse = @($contract.security.secret_values_recorded, $contract.security.manual_writer_start_allowed, $contract.security.contract_mode_system_mutation, $contract.all_writer_fence.denial_mutates_state)
    if (
        [string]$contract.schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$contract.app_id -cne 'container_audit' -or
        [string]$contract.cli.relative_path -cne 'tools/container_writer_session.ps1' -or
        (@($contract.cli.public_writer_modes) -join ',') -cne 'Contract,Prepare,ValidatePrepared,RestoreWriter' -or
        -not (Test-BootstrapJsonInteger $contract.cli.success_exit_code) -or [int64]$contract.cli.success_exit_code -ne 0 -or
        @($contract.cli.failure_exit_codes | Where-Object { -not (Test-BootstrapJsonInteger $_) }).Count -ne 0 -or
        (@($contract.cli.failure_exit_codes) -join ',') -cne '1,20' -or
        -not (Test-BootstrapJsonInteger $contract.identifiers.session_max_age_hours) -or [int64]$contract.identifiers.session_max_age_hours -ne 24 -or
        [string]$contract.identifiers.session_authority_mutex_derivation -cne 'Local\KMTech.ContainerAudit.DeploymentSession.<sha256(v1 canonical session tuple)>' -or
        -not (Test-WriterSessionContractExactPropertySet $contract.all_writer_fence $fenceFields) -or
        -not (Test-WriterSessionContractExactStringProperties $contract.all_writer_fence $fenceStringFields) -or
        [string]$contract.all_writer_fence.active_schema -cne 'container-audit-all-writer-fence-active-v1' -or
        [string]$contract.all_writer_fence.release_schema -cne 'container-audit-all-writer-fence-release-v1' -or
        [string]$contract.all_writer_fence.control_root -cne '%LOCALAPPDATA%\KMTech\DirectSync\container_audit\control\writer-session' -or
        [string]$contract.all_writer_fence.active_filename -cne 'active.json' -or
        [string]$contract.all_writer_fence.release_filename_pattern -cne 'release-{replacement_transaction_id}-{release_authorization_sha256}.json' -or
        [string]$contract.all_writer_fence.admission_mutex_name -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1' -or
        [string]$contract.all_writer_fence.noncanonical_mutex_derivation -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1.<first 16 lowercase hex characters of SHA-256 over the absolute control root after slash-to-backslash conversion, trailing-backslash removal, Unicode NFC, and ASCII A-Z to a-z mapping with every other code point unchanged, encoded as UTF-8 without BOM>' -or
        [string]$contract.all_writer_fence.session_mutex_prefix -cne 'Local\KMTech.ContainerAudit.DeploymentSession.' -or
        [string]$contract.all_writer_fence.session_tuple_version -cne 'container-audit-deployment-session-authority-v1' -or
        $contract.all_writer_fence.session_tuple_fields -isnot [Object[]] -or
        @($contract.all_writer_fence.session_tuple_fields | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        (@($contract.all_writer_fence.session_tuple_fields) -join ',') -cne 'session_tuple_version,session_id,attempt_id,orchestrator_sha256,replacement_transaction_id,writer_contract_sha256' -or
        [string]$contract.all_writer_fence.tuple_separator -cne 'LF (U+000A) between ordered fields; no trailing LF' -or
        [string]$contract.all_writer_fence.tuple_encoding -cne 'UTF-8 without BOM' -or
        [string]$contract.all_writer_fence.tuple_normalization -cne 'Unicode NFC applied to each field before joining' -or
        [string]$contract.all_writer_fence.writer_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$contract.all_writer_fence.canonical_installer_delegation_source -cne 'writer_sink_sources from the exact pinned code-derived inventory' -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.scheduled_task_mutation_rule) -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.natural_trigger_phase_rule) -or
        [string]$contract.all_writer_fence.writer_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $contract.all_writer_fence.verification_vectors -isnot [Object[]] -or
        $contract.all_writer_fence.active_statuses -isnot [Object[]] -or
        @($contract.all_writer_fence.active_statuses | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        (@($contract.all_writer_fence.active_statuses) -join ',') -cne 'PREPARING,PREPARED,RESTORING,RESTORE_FAILED,INSTALLING' -or
        $contract.all_writer_fence.writer_admission_fail_closed -isnot [bool] -or -not $contract.all_writer_fence.writer_admission_fail_closed -or
        $contract.all_writer_fence.unknown_or_unobservable_is_denied -isnot [bool] -or -not $contract.all_writer_fence.unknown_or_unobservable_is_denied -or
        -not $vectorsValid -or
        [string]$contract.receipts.prepared_schema -cne 'container-audit-writer-session-prepared-v3' -or
        [string]$contract.receipts.restored_schema -cne 'container-audit-writer-session-restored-v2' -or
        [string]$contract.receipts.lifecycle_restore_schema -cne 'container-audit-replacement-lifecycle-restore-v1' -or
        (@($contract.receipts.prepared_required_bindings) -join ',') -cne ($bindings -join ',') -or
        [string]$contract.lifecycle_restore.product_mode -cne '--restore-current-user-lifecycle-after-replacement' -or
        @($requiredTrue | Where-Object { $_ -isnot [bool] -or -not $_ }).Count -ne 0 -or
        @($requiredFalse | Where-Object { $_ -isnot [bool] -or $_ }).Count -ne 0
    ) { throw "Writer session public contract semantics differ." }
}
