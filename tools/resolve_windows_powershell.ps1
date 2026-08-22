function Get-WindowsPowerShellFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function ConvertFrom-WindowsPowerShellProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ProbeOutput
    )

    if ($ProbeOutput.Count -ne 1 -or $ProbeOutput[0] -isnot [string]) {
        throw "The canonical Windows PowerShell executable identity probe was ambiguous."
    }
    try {
        $probe = ConvertFrom-Json -InputObject ([string]$ProbeOutput[0])
    }
    catch {
        throw "The canonical Windows PowerShell executable returned invalid identity JSON."
    }
    if ($probe -isnot [pscustomobject]) {
        throw "The canonical Windows PowerShell executable identity JSON must be an object."
    }
    $fields = @($probe.PSObject.Properties.Name)
    if (
        $fields.Count -ne 2 -or
        @($fields | Where-Object { $_ -ceq "psedition" }).Count -ne 1 -or
        @($fields | Where-Object { $_ -ceq "powershell_version" }).Count -ne 1
    ) {
        throw "The canonical Windows PowerShell executable identity JSON has invalid fields."
    }
    if ($probe.psedition -isnot [string] -or $probe.powershell_version -isnot [string]) {
        throw "The canonical Windows PowerShell executable identity JSON has invalid field types."
    }
    if ([string]$probe.psedition -cne "Desktop") {
        throw "The canonical Windows PowerShell executable PSEdition is not exactly Desktop."
    }
    try {
        $runtimeVersion = [Version]([string]$probe.powershell_version)
    }
    catch {
        throw "The canonical Windows PowerShell executable returned an invalid runtime version."
    }
    if ($runtimeVersion.Major -ne 5 -or $runtimeVersion.Minor -ne 1) {
        throw "The canonical Windows PowerShell executable is not Windows PowerShell 5.1."
    }
    return [pscustomobject][ordered]@{
        psedition = [string]$probe.psedition
        powershell_version = $runtimeVersion.ToString()
        version_major = $runtimeVersion.Major
        version_minor = $runtimeVersion.Minor
    }
}

function Get-WindowsPowerShellIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedSystemDirectory
    )

    if (
        -not [IO.Path]::IsPathFullyQualified($Path) -or
        -not [IO.Path]::IsPathFullyQualified($ExpectedSystemDirectory)
    ) {
        throw "Windows PowerShell executable and system-directory paths must be fully qualified."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $systemDirectory = [IO.Path]::GetFullPath($ExpectedSystemDirectory).TrimEnd([char[]]"\/")
    $canonicalPath = [IO.Path]::GetFullPath(
        (Join-Path $systemDirectory "WindowsPowerShell\v1.0\powershell.exe")
    )
    if (-not $fullPath.Equals($canonicalPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Windows PowerShell must use the exact canonical Windows PowerShell 5.1 executable path."
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "The canonical Windows PowerShell 5.1 executable does not exist."
    }

    $before = Get-Item -LiteralPath $fullPath -Force
    if ($before -isnot [IO.FileInfo]) {
        throw "The canonical Windows PowerShell 5.1 executable must be an ordinary file."
    }
    if (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The canonical Windows PowerShell 5.1 executable must not be a reparse point."
    }
    $beforeLength = [long]$before.Length
    $beforeSha256 = Get-WindowsPowerShellFileSha256 -Path $fullPath
    $fileProductVersion = ([string]$before.VersionInfo.ProductVersion).Trim()
    if ([string]::IsNullOrWhiteSpace($fileProductVersion)) {
        throw "The canonical Windows PowerShell executable has no product version identity."
    }

    $probeCommand = @'
$identity = [ordered]@{
    psedition = $PSVersionTable.PSEdition
    powershell_version = $PSVersionTable.PSVersion.ToString()
}
[Console]::Out.Write((ConvertTo-Json -Compress -InputObject $identity))
'@
    $probeOutput = @(
        & $fullPath -NoLogo -NoProfile -NonInteractive -Command $probeCommand
    )
    if ($LASTEXITCODE -ne 0) {
        throw "The canonical Windows PowerShell executable identity probe failed."
    }
    $runtime = ConvertFrom-WindowsPowerShellProbe -ProbeOutput $probeOutput

    $after = Get-Item -LiteralPath $fullPath -Force
    $afterSha256 = Get-WindowsPowerShellFileSha256 -Path $fullPath
    if ([long]$after.Length -ne $beforeLength -or $afterSha256 -cne $beforeSha256) {
        throw "The canonical Windows PowerShell executable changed during identity validation."
    }

    return [pscustomobject][ordered]@{
        executable = $fullPath
        system_directory = $systemDirectory
        file_type = "ordinary-file"
        is_reparse_point = $false
        sha256 = $beforeSha256
        size = $beforeLength
        psedition = $runtime.psedition
        powershell_version = $runtime.powershell_version
        version_major = $runtime.version_major
        version_minor = $runtime.version_minor
        file_product_version = $fileProductVersion
    }
}

function Initialize-WindowsPowerShellAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedSystemDirectory
    )

    return Get-WindowsPowerShellIdentity `
        -Path $ExpectedPath `
        -ExpectedSystemDirectory $ExpectedSystemDirectory
}

function Assert-WindowsPowerShellIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$ExpectedIdentity
    )

    $current = Get-WindowsPowerShellIdentity `
        -Path ([string]$ExpectedIdentity.executable) `
        -ExpectedSystemDirectory ([string]$ExpectedIdentity.system_directory)
    foreach ($field in @(
        "executable", "system_directory", "file_type", "is_reparse_point",
        "sha256", "size", "psedition", "powershell_version",
        "version_major", "version_minor", "file_product_version"
    )) {
        if ([string]$current.$field -cne [string]$ExpectedIdentity.$field) {
            throw "The canonical Windows PowerShell $field identity changed."
        }
    }
    return $current
}
