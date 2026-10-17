function Assert-ContainerRemovalQuiescent([string]$ApplicationRoot, [int[]]$ExcludeProcessIds = @()) {
    $prefix = (Get-StrictFullPath $ApplicationRoot 'removal process root') + '\'
    $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    if ($rows.Count -eq 0) { throw 'REMOVAL_PROCESS_OBSERVATION_UNKNOWN' }
    foreach ($row in $rows) {
        if ($null -eq $row.ProcessId) { throw 'REMOVAL_PROCESS_OBSERVATION_UNKNOWN' }
        if ([int]$row.ProcessId -eq $PID -or [int]$row.ProcessId -in $ExcludeProcessIds) { continue }
        if (([string]$row.ExecutablePath).StartsWith($prefix, 'OrdinalIgnoreCase') -or
            ([string]$row.CommandLine).IndexOf($prefix, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP'
        }
    }
}