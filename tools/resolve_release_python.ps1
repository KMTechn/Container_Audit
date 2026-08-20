function Resolve-ReleasePythonApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$DiscoveredSources,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedPath
    )

    $orderedSources = @(
        $DiscoveredSources |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    )
    if ($orderedSources.Count -eq 0) {
        throw "No Python application is discoverable on PATH."
    }

    $expectedFullPath = [IO.Path]::GetFullPath($ExpectedPath)
    $selectedFullPath = [IO.Path]::GetFullPath([string]$orderedSources[0])
    if (-not $selectedFullPath.Equals(
        $expectedFullPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The first PATH-discovered Python application is not the prepared release Python executable."
    }
    return $expectedFullPath
}
