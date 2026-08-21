function Resolve-ReleasePythonApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$DiscoveredSources,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedPath
    )

    $orderedSources = @(
        $DiscoveredSources |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object {
                $source = [string]$_
                if (-not [IO.Path]::IsPathFullyQualified($source)) {
                    throw "Every PATH-discovered Python application must have a fully qualified path."
                }
                [IO.Path]::GetFullPath($source)
            }
    )
    if ($orderedSources.Count -eq 0) {
        throw "No Python application is discoverable on PATH."
    }

    if (-not [IO.Path]::IsPathFullyQualified($ExpectedPath)) {
        throw "The prepared release Python executable path must be fully qualified."
    }
    $expectedFullPath = [IO.Path]::GetFullPath($ExpectedPath)
    $seenSources = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($source in $orderedSources) {
        if (-not $seenSources.Add($source)) {
            throw "Python application discovery is duplicate or ambiguous."
        }
    }

    $selectedFullPath = $orderedSources[0]
    if (-not $selectedFullPath.Equals(
        $expectedFullPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The first PATH-discovered Python application is not the prepared release Python executable."
    }

    $expectedMatches = @(
        $orderedSources |
            Where-Object {
                $_.Equals($expectedFullPath, [StringComparison]::OrdinalIgnoreCase)
            }
    )
    if ($expectedMatches.Count -ne 1) {
        throw "The prepared release Python executable must resolve exactly once."
    }

    $expectedDirectory = [IO.Path]::GetDirectoryName($expectedFullPath)
    $sameDirectoryApplications = @(
        $orderedSources |
            Where-Object {
                [IO.Path]::GetDirectoryName($_).Equals(
                    $expectedDirectory,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($sameDirectoryApplications.Count -ne 1) {
        throw "The prepared release Python directory has ambiguous python applications."
    }
    return $expectedFullPath
}

function Get-ReleaseFileSha256 {
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

function Get-ReleasePythonIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedVersionMajor,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedVersionMinor,

        [Parameter(Mandatory = $true)]
        [ValidateSet(32, 64)]
        [int]$ExpectedArchitectureBits
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "The prepared release Python executable path must be fully qualified."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "The prepared release Python executable does not exist."
    }
    if ([IO.Path]::GetExtension($fullPath) -cne ".exe") {
        throw "The prepared release Python application must be an exact .exe path."
    }

    $before = Get-Item -LiteralPath $fullPath -Force
    if (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The prepared release Python executable must not be a reparse point."
    }
    $beforeLength = [long]$before.Length
    $beforeSha256 = Get-ReleaseFileSha256 -Path $fullPath
    $fileProductVersion = ([string]$before.VersionInfo.ProductVersion).Trim()
    if ([string]::IsNullOrWhiteSpace($fileProductVersion)) {
        throw "The prepared release Python executable has no product version identity."
    }

    $probeCode = @'
import json, platform, struct, sys; print(json.dumps(dict(architecture_bits=struct.calcsize('P') * 8, executable=sys.executable, implementation=platform.python_implementation(), machine=platform.machine(), version=platform.python_version(), version_info=list(sys.version_info[:3])), sort_keys=True))
'@
    $probeOutput = @(& $fullPath -I -c $probeCode)
    if ($LASTEXITCODE -ne 0) {
        throw "The prepared release Python executable identity probe failed."
    }
    if ($probeOutput.Count -ne 1) {
        throw "The prepared release Python executable identity probe was ambiguous."
    }
    try {
        $runtime = ConvertFrom-Json -InputObject ([string]$probeOutput[0])
    }
    catch {
        throw "The prepared release Python executable returned invalid identity JSON."
    }

    if (-not [IO.Path]::IsPathFullyQualified([string]$runtime.executable)) {
        throw "The prepared release Python executable self-reported a non-fully-qualified identity."
    }
    $runtimePath = [IO.Path]::GetFullPath([string]$runtime.executable)
    if (-not $runtimePath.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The prepared release Python executable self-reported a different file identity."
    }
    if ([string]$runtime.implementation -cne "CPython") {
        throw "The prepared release Python executable must be CPython."
    }
    if (
        [int]$runtime.version_info[0] -ne $ExpectedVersionMajor -or
        [int]$runtime.version_info[1] -ne $ExpectedVersionMinor
    ) {
        throw "The prepared release Python executable has the wrong version."
    }
    if ([int]$runtime.architecture_bits -ne $ExpectedArchitectureBits) {
        throw "The prepared release Python executable has the wrong architecture."
    }
    if ([string]::IsNullOrWhiteSpace([string]$runtime.machine)) {
        throw "The prepared release Python executable has no machine architecture identity."
    }
    if ($fileProductVersion -cne [string]$runtime.version) {
        throw "The prepared release Python file and runtime versions disagree."
    }

    $after = Get-Item -LiteralPath $fullPath -Force
    $afterSha256 = Get-ReleaseFileSha256 -Path $fullPath
    if ([long]$after.Length -ne $beforeLength -or $afterSha256 -cne $beforeSha256) {
        throw "The prepared release Python executable changed during identity validation."
    }

    return [pscustomobject][ordered]@{
        executable = $fullPath
        sha256 = $beforeSha256
        size = $beforeLength
        python_version = [string]$runtime.version
        version_major = [int]$runtime.version_info[0]
        version_minor = [int]$runtime.version_info[1]
        version_micro = [int]$runtime.version_info[2]
        architecture_bits = [int]$runtime.architecture_bits
        machine = [string]$runtime.machine
        implementation = [string]$runtime.implementation
        file_product_version = $fileProductVersion
    }
}

function Initialize-ReleasePythonAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApprovedRoot,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedVersionMajor,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedVersionMinor,

        [Parameter(Mandatory = $true)]
        [ValidateSet(32, 64)]
        [int]$ExpectedArchitectureBits
    )

    if (
        -not [IO.Path]::IsPathFullyQualified($ExpectedPath) -or
        -not [IO.Path]::IsPathFullyQualified($ApprovedRoot)
    ) {
        throw "Release Python and approved-root paths must be fully qualified."
    }
    $expectedFullPath = [IO.Path]::GetFullPath($ExpectedPath)
    $approvedFullRoot = [IO.Path]::GetFullPath($ApprovedRoot)
    $approvedPathRoot = [IO.Path]::GetPathRoot($approvedFullRoot)
    if (-not $approvedFullRoot.Equals($approvedPathRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $approvedFullRoot = $approvedFullRoot.TrimEnd([char[]]"\/")
    }
    $approvedPrefix = if ($approvedFullRoot.EndsWith([string][IO.Path]::DirectorySeparatorChar)) {
        $approvedFullRoot
    } else {
        $approvedFullRoot + [IO.Path]::DirectorySeparatorChar
    }
    if (-not $expectedFullPath.StartsWith($approvedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The prepared release Python executable must be below the approved E: task storage root."
    }

    $pathExtensions = @(
        ([string]$env:PATHEXT).Split([IO.Path]::PathSeparator) |
            ForEach-Object { $_.Trim().ToUpperInvariant() }
    )
    if ($pathExtensions.Count -eq 0 -or $pathExtensions -contains "") {
        throw "PATHEXT must contain only explicit application extensions."
    }
    $seenExtensions = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($extension in $pathExtensions) {
        if ($extension -notmatch '^\.[A-Z0-9]+$') {
            throw "PATHEXT contains an invalid application extension."
        }
        if (-not $seenExtensions.Add($extension)) {
            throw "PATHEXT contains duplicate application extensions."
        }
    }
    if (@($pathExtensions | Where-Object { $_ -ceq ".EXE" }).Count -ne 1) {
        throw "PATHEXT must contain .EXE exactly once."
    }

    $expectedDirectory = [IO.Path]::GetDirectoryName($expectedFullPath)
    $orderedPath = [Collections.Generic.List[string]]::new()
    $seenPath = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [void]$seenPath.Add($expectedDirectory)
    $orderedPath.Add($expectedDirectory)
    foreach ($rawEntry in ([string]$env:PATH).Split([IO.Path]::PathSeparator)) {
        $entry = $rawEntry.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($entry) -or -not [IO.Path]::IsPathFullyQualified($entry)) {
            throw "PATH must contain only explicit fully qualified directories."
        }
        $fullEntry = [IO.Path]::GetFullPath($entry)
        $entryRoot = [IO.Path]::GetPathRoot($fullEntry)
        if (-not $fullEntry.Equals($entryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            $fullEntry = $fullEntry.TrimEnd([char[]]"\/")
        }
        if ($seenPath.Add($fullEntry)) {
            $orderedPath.Add($fullEntry)
        }
    }
    $env:PATH = $orderedPath -join [IO.Path]::PathSeparator

    $discoveredPythonSources = @(
        Get-Command python -CommandType Application -All -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Source }
    )
    $resolvedPath = Resolve-ReleasePythonApplication `
        -DiscoveredSources $discoveredPythonSources `
        -ExpectedPath $expectedFullPath
    $identity = Get-ReleasePythonIdentity `
        -Path $resolvedPath `
        -ExpectedVersionMajor $ExpectedVersionMajor `
        -ExpectedVersionMinor $ExpectedVersionMinor `
        -ExpectedArchitectureBits $ExpectedArchitectureBits
    if (-not $identity.executable.Equals($resolvedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Resolved release Python and validated executable identity disagree."
    }
    return $identity
}

function Assert-ReleasePythonIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$ExpectedIdentity
    )

    $current = Get-ReleasePythonIdentity `
        -Path ([string]$ExpectedIdentity.executable) `
        -ExpectedVersionMajor ([int]$ExpectedIdentity.version_major) `
        -ExpectedVersionMinor ([int]$ExpectedIdentity.version_minor) `
        -ExpectedArchitectureBits ([int]$ExpectedIdentity.architecture_bits)
    foreach ($field in @(
        "executable", "sha256", "size", "python_version", "version_major",
        "version_minor", "version_micro", "architecture_bits", "machine",
        "implementation", "file_product_version"
    )) {
        if ([string]$current.$field -cne [string]$ExpectedIdentity.$field) {
            throw "The prepared release Python $field identity changed."
        }
    }
    return $current
}
