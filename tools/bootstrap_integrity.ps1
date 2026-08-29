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
    if ([int]$record.file_count -ne $inventory.Count -or @($record.files).Count -ne $inventory.Count) {
        throw "Bootstrap integrity record file count is invalid."
    }
    for ($index = 0; $index -lt $inventory.Count; $index += 1) {
        $actual = $inventory[$index]
        $expected = @($record.files)[$index]
        if (
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
