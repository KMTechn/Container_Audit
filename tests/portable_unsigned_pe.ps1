param([string]$SourceRoot, [string]$PortableRoot)
$ErrorActionPreference = 'Stop'

# Load function definitions only. No installer entrypoint, process, GUI or
# protected host state is executed by this contract probe.
function Load-Functions([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'installer parse failed' }
    foreach ($node in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($node.Extent.Text))
    }
    # Export definitions from this loader's scope.
    foreach ($node in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        Set-Item -Path ('function:script:' + $node.Name) -Value (Get-Item ('function:' + $node.Name)).ScriptBlock
    }
}
Load-Functions (Join-Path $SourceRoot 'INSTALL_CANONICAL_PORTABLE.ps1')
Load-Functions (Join-Path $SourceRoot 'INSTALL_THIS_PC.ps1')

# Run the updater's unchanged native manifest contract slice without its
# protected-root/authority or installation side effects.
$updateText = [IO.File]::ReadAllText((Join-Path $SourceRoot 'tools/apply_prepared_update.ps1'))
$start = $updateText.IndexOf('    $manifest = Read-KmtechPortableManifest $full')
$end = $updateText.IndexOf('    $pins = @{', $start)
if ($start -lt 0 -or $end -le $start) { throw 'updater native contract missing' }
Set-Item function:Assert-StartupUpdateNativeContract -Value ([scriptblock]::Create(
    'param([string]$full, [bool]$Unused)' + [Environment]::NewLine + $updateText.Substring($start, $end - $start)))

function Assert-KmtechPortableTree { }
function Read-KmtechPortableManifest($Root) { Get-Content (Join-Path $Root 'portable-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
function Assert-KmtechCPythonSignature { }
function Assert-WriterSessionPublicContract { }
function Assert-WriterSinkInventory { }
function ConvertTo-KmtechRedactedSinkText { param($Text, [switch]$UserLine) return $Text }
function Write-InstallationCaughtFailure { }
function Assert-ContainerRuntimeFileInventory { }
function Test-BootstrapJsonInteger($Value) { return $Value -is [int] -or $Value -is [long] }
function ConvertTo-KmtechFullPath([string]$Value, [string]$Purpose) { return [IO.Path]::GetFullPath($Value) }
function Get-StrictFullPath([string]$Value, [string]$Purpose) { return [IO.Path]::GetFullPath($Value) }

# Test seam: the three public pins stand in for native bytes in these small
# fixtures. Tampered and missing leaves still take the real refusal branch.
$script:pins = @{
    'site-packages/_cffi_backend.cp312-win_amd64.pyd' = '9af5e4f68a41f26b726f2e9424f9d58a4f5666189f6a48be95f406b257102aec'
    'site-packages/clr_loader/ffi/dlls/amd64/ClrLoader.dll' = '07f62bcb1b70320f221ffb2cfc5ce6133815195f3e7cdb8d833222506188c2ac'
    'site-packages/pythonnet/runtime/Python.Runtime.dll' = '2ebd4492e28442ef1f1af587afe5b3a090c2ebfa220758ded4f1450f2a27f13a'
}
$script:bad = $false
function Sha([string]$Path) {
    foreach ($relative in $script:pins.Keys) {
        if ($Path.Replace('\', '/').EndsWith('/app/' + $relative, [StringComparison]::Ordinal)) {
            if ($script:bad) { return '0' * 64 }
            return $script:pins[$relative]
        }
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Get-FileSha256([string]$Path) { Sha $Path }
function Update-Manifest($Listed) {
    $path = Join-Path $PortableRoot 'portable-manifest.json'
    $value = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $value.allowed_unsigned_app_pe = @(if ($null -ne $Listed) { $Listed })
    $value | Add-Member -MemberType NoteProperty -Name startup_update_protocol -Value 1 -Force
    $files = @(Get-ChildItem -LiteralPath $PortableRoot -Recurse -File | Where-Object { $_.FullName -cne $path })
    $value.file_count_before_manifest = $files.Count
    $value.byte_count_before_manifest = [int64](($files | Measure-Object Length -Sum).Sum)
    $value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8
}
$script:stage = 0
function Check([bool]$Accepted) {
    $script:stage++
    foreach ($reader in @('Manifest', 'InstalledManifest', 'Assert-RequiredRelease', 'Assert-StartupUpdateNativeContract')) {
        $ok = $true
        $failureKind = ''; $failureCommand = ''; $failureLine = 0
        try { $null = & $reader $PortableRoot $true } catch {
            $ok = $false
            $failureKind = $_.Exception.GetType().Name
            $failureCommand = $_.InvocationInfo.MyCommand.Name
            $failureLine = $_.InvocationInfo.ScriptLineNumber
        }
        if ($ok -ne $Accepted) {
            Write-Output (@{reader=$reader;stage=$script:stage;kind=$failureKind;command=$failureCommand;line=$failureLine} | ConvertTo-Json -Compress)
            throw ('unsigned native acceptance differs: ' + $reader)
        }
    }
}
Update-Manifest @()
Check $true
foreach ($relative in $script:pins.Keys) {
    $path = Join-Path (Join-Path $PortableRoot 'app') $relative
    $null = New-Item -ItemType Directory -Path (Split-Path $path -Parent) -ErrorAction SilentlyContinue
    [IO.File]::WriteAllBytes($path, [byte[]](77, 90))
}
$listed = @($script:pins.Keys)
Update-Manifest $listed
Check $true
Update-Manifest @($listed[0], $listed[1])
Check $false
Update-Manifest @($listed[0], $listed[0], $listed[1])
Check $false
Update-Manifest @($listed + 'site-packages/foreign.dll')
Check $false
Update-Manifest @($listed[0].ToUpperInvariant(), $listed[1], $listed[2])
Check $false
Update-Manifest $listed
$script:bad = $true
Check $false
$script:bad = $false
Remove-Item -LiteralPath (Join-Path (Join-Path $PortableRoot 'app') $listed[0])
Update-Manifest $listed
Check $false
Write-Output 'UNSIGNED_NATIVE_CONTRACT_PASS'
