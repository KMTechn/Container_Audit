# Frozen CA functions from adcaf86, before X13-B leaf delegation.

function Full([string]$Value, [string]$Purpose) {
    if (-not [IO.Path]::IsPathRooted($Value) -or $Value.StartsWith('\\?\')) {
        throw "$Purpose must be an ordinary absolute path."
    }
    $result = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    if ($result -eq [IO.Path]::GetPathRoot($result)) { throw "$Purpose is too broad." }
    return $result
}

function Sha([string]$Path) {
    $stream = [IO.File]::OpenRead($Path); $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose(); $stream.Dispose() }
}

function Manifest([string]$Root, [bool]$UnsignedOk) {
    foreach ($relative in @(
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
    )) {
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
    if (-not $UnsignedOk) {
        foreach ($relative in @('runtime\python.exe','runtime\pythonw.exe')) {
            if ([string](Get-AuthenticodeSignature (Join-Path $Root $relative)).Status -cne 'Valid') {
                throw "Signed CPython readback failed: $relative"
            }
        }
    }
    return $value
}
