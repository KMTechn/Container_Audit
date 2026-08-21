function Get-ReleasePowerShellPrelaunchModulePath {
    [CmdletBinding()]
    param()

    return @(
        [IO.Path]::Combine($PSHOME, "Modules"),
        "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
    ) -join [IO.Path]::PathSeparator
}

function Get-ReleasePowerShellModulePathSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        return [Convert]::ToHexString($digest).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Enter-ReleasePowerShellModuleFence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedCurrentUserModulePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedAllUsersModulePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedAnalysisCachePath
    )

    if (-not $IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) {
        throw "The release PowerShell module fence requires PowerShell 7 on Windows."
    }

    $prelaunchTokenName = "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH"
    $prelaunchDigestTokenName = "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH_SHA256"
    $sealedModulePath = Get-ReleasePowerShellPrelaunchModulePath
    $expectedPrelaunchDigest = Get-ReleasePowerShellModulePathSha256 `
        -Value $sealedModulePath

    $standardCurrentUserModulePath = [IO.Path]::Combine(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments),
        "PowerShell",
        "Modules"
    )
    $standardAllUsersModulePath = [IO.Path]::Combine(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
        "PowerShell",
        "Modules"
    )
    if (
        $ExpectedCurrentUserModulePath -cne $standardCurrentUserModulePath -or
        $ExpectedAllUsersModulePath -cne $standardAllUsersModulePath
    ) {
        throw "Expected PowerShell startup module paths differ from the exact Windows standard paths."
    }

    foreach ($modulePath in @(
        $ExpectedCurrentUserModulePath,
        $ExpectedAllUsersModulePath
    )) {
        if (
            -not [IO.Path]::IsPathFullyQualified($modulePath) -or
            [IO.Path]::GetFullPath($modulePath) -cne $modulePath
        ) {
            throw "Expected PowerShell startup module paths must be exact canonical absolute paths."
        }
    }

    $expectedEffectiveModulePath = @(
        $ExpectedCurrentUserModulePath,
        $ExpectedAllUsersModulePath,
        $sealedModulePath
    ) -join [IO.Path]::PathSeparator
    $expectedEffectiveEntries = @(
        $expectedEffectiveModulePath.Split([IO.Path]::PathSeparator)
    )
    $uniqueEffectiveEntries = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    if ($expectedEffectiveEntries.Count -ne 4) {
        throw "The expected PowerShell startup closure must contain exactly four entries."
    }
    foreach ($modulePath in $expectedEffectiveEntries) {
        if (
            -not [IO.Path]::IsPathFullyQualified($modulePath) -or
            [IO.Path]::GetFullPath($modulePath) -cne $modulePath -or
            -not $uniqueEffectiveEntries.Add($modulePath)
        ) {
            throw "The expected PowerShell startup closure contains a noncanonical or duplicate path."
        }
    }
    $actualPrelaunchToken = [Environment]::GetEnvironmentVariable(
        $prelaunchTokenName,
        [EnvironmentVariableTarget]::Process
    )
    $actualPrelaunchDigestToken = [Environment]::GetEnvironmentVariable(
        $prelaunchDigestTokenName,
        [EnvironmentVariableTarget]::Process
    )
    if (
        [string]$actualPrelaunchToken -cne $sealedModulePath -or
        [string]$actualPrelaunchDigestToken -cne $expectedPrelaunchDigest
    ) {
        throw "The builder child did not receive the exact hash-bound prelaunch module-path token."
    }
    if ([string]$env:PSModulePath -cne $expectedEffectiveModulePath) {
        throw "The builder child module path differs from the exact PowerShell startup closure."
    }

    if (-not [IO.Path]::IsPathFullyQualified($ExpectedAnalysisCachePath)) {
        throw "The PowerShell module-analysis cache path must be fully qualified."
    }
    $canonicalAnalysisCachePath = [IO.Path]::GetFullPath($ExpectedAnalysisCachePath)
    $approvedStorageRoot = [IO.Path]::GetFullPath("E:\KMTech").TrimEnd('\') + '\'
    if (
        $canonicalAnalysisCachePath -cne $ExpectedAnalysisCachePath -or
        -not $canonicalAnalysisCachePath.StartsWith(
            $approvedStorageRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$env:PSModuleAnalysisCachePath -cne $ExpectedAnalysisCachePath
    ) {
        throw "The PowerShell module-analysis cache is not fenced to the exact E:\KMTech path."
    }
    if (
        [Environment]::GetEnvironmentVariable(
            "PSDisableModuleAnalysisCacheCleanup",
            [EnvironmentVariableTarget]::Process
        ) -ne $null
    ) {
        throw "The PowerShell module-analysis cache cleanup override reached the builder child."
    }

    [Environment]::SetEnvironmentVariable(
        "PSModulePath",
        $sealedModulePath,
        [EnvironmentVariableTarget]::Process
    )
    Remove-Item -LiteralPath "Env:$prelaunchTokenName" -ErrorAction Stop
    Remove-Item -LiteralPath "Env:$prelaunchDigestTokenName" -ErrorAction Stop

    if (
        [string]$env:PSModulePath -cne $sealedModulePath -or
        [string]$env:PSModuleAnalysisCachePath -cne $ExpectedAnalysisCachePath -or
        [Environment]::GetEnvironmentVariable(
            $prelaunchTokenName,
            [EnvironmentVariableTarget]::Process
        ) -ne $null -or
        [Environment]::GetEnvironmentVariable(
            $prelaunchDigestTokenName,
            [EnvironmentVariableTarget]::Process
        ) -ne $null
    ) {
        throw "The release PowerShell module fence did not converge to the sealed child environment."
    }
}
