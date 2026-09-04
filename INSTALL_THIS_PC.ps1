[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\KMTech\Apps\Container_Audit\current",
    [string]$TlsCaBundlePath = "",
    [string]$OperatorLocalAppDataRoot = "",
    [string]$ElevationLogPath = "",
    [switch]$ReplaceExistingVerifiedPortable,
    [string]$ReplacementTransactionId = "",
    [string]$ReplacementReceiptPath = "",
    [switch]$ProbeVerifiedReplacementRestore,
    [switch]$RestoreVerifiedReplacement,
    [string]$ReplacementReceiptSha256 = "",
    [string]$RestoreEvidencePath = "",
    [string]$ExpectedInstalledManifestSha256 = "",
    [string]$ExpectedInstalledAggregateSha256 = "",
    [string]$QuiesceReceiptPath = "",
    [string]$ExpectedQuiesceReceiptSha256 = "",
    [string]$RestoreUninstallRecordPath = "",
    [string]$ExpectedUninstallRecordSha256 = "",
    [string]$WriterFenceHelperPath = "",
    [string]$ExpectedWriterFenceHelperSha256 = "",
    [string]$WriterFenceSessionId = "",
    [string]$WriterFenceAttemptId = "",
    [string]$WriterFenceReplacementTransactionId = "",
    [string]$WriterFenceDelegationToken = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$ApplyHardenedAclForTest,
    [switch]$InjectRestoreFailureAfterDisplaceForTest
)

$ErrorActionPreference = "Stop"
$ExpectedInstallRoot = "C:\KMTech\Apps\Container_Audit\current"
$BootstrapIntegrityFunctions = Join-Path $PSScriptRoot "tools\bootstrap_integrity.ps1"
if (-not (Test-Path -LiteralPath $BootstrapIntegrityFunctions -PathType Leaf)) {
    throw "Bootstrap integrity producer is unavailable."
}
. $BootstrapIntegrityFunctions
$IntegrityFileName = $BootstrapIntegrityFileName
$LegacyRelayTaskName = "direct-sync-relay-container-audit"
$LegacyQualificationTaskName = "container-audit-isolated-qualification-authority"
$PlacementWriterSource = "canonical_code_placement"
$BootstrapScriptPath = $MyInvocation.MyCommand.Path
$BootstrapBoundParameters = @{}
foreach ($boundName in $PSBoundParameters.Keys) {
    $BootstrapBoundParameters[$boundName] = $PSBoundParameters[$boundName]
}

function Test-SamePath([string]$Left, [string]$Right) {
    try {
        $leftFull = Get-StrictFullPath $Left "left path"
        $rightFull = Get-StrictFullPath $Right "right path"
        return $leftFull.Equals($rightFull, [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Assert-NoReparsePoint([string]$Path, [string]$Purpose) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $items = @((Get-Item -LiteralPath $Path -Force))
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
    }
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose must not contain a reparse point: $($item.FullName)"
        }
    }
}

function Install-CurrentUserTlsCaBootstrap([string]$SourcePath, [string]$LocalAppDataRoot) {
    if ([string]::IsNullOrWhiteSpace($SourcePath)) { return $null }
    $source = Get-StrictFullPath $SourcePath "TLS CA bundle source"; Assert-NoReparsePoint $source "TLS CA bundle source"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "TLS CA bundle source is unavailable." }
    $sourceLength = (Get-Item -LiteralPath $source -Force).Length
    if ($sourceLength -le 0 -or $sourceLength -gt 131072) { throw "TLS CA bundle source size is invalid." }
    $userRoot = Get-StrictFullPath $LocalAppDataRoot "operator LOCALAPPDATA root"; $target = Join-Path $userRoot "KMTech\Bootstrap\Container_Audit\ca-bundle.pem"
    $targetParent = Split-Path -Parent $target; New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
    Assert-NoReparsePoint $targetParent "TLS CA bootstrap directory"
    Copy-Item -LiteralPath $source -Destination $target -Force; Assert-NoReparsePoint $target "TLS CA bootstrap target"
    if ((Get-FileSha256 $target) -cne (Get-FileSha256 $source)) { throw "TLS CA bootstrap exact readback failed." }
    return $target
}
function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('\', '\').Replace('"', '\"') + '"'
}

function Invoke-SelfElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }
    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $BootstrapScriptPath)
    foreach ($name in $BootstrapBoundParameters.Keys) {
        $value = $BootstrapBoundParameters[$name]
        if ($value -is [Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $arguments += "-$name" }
        }
        else {
            $arguments += @("-$name", [string]$value)
        }
    }
    $argumentLine = ($arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) }) -join ' '
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $argumentLine -Wait -PassThru
    exit $process.ExitCode
}

function Enter-ContainerPlacementWriterFence {
    if (
        [string]::IsNullOrWhiteSpace($WriterFenceHelperPath) -or
        [string]$ExpectedWriterFenceHelperSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$WriterFenceSessionId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$WriterFenceAttemptId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$WriterFenceReplacementTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$WriterFenceDelegationToken -cnotmatch '^[0-9a-f]{64}$'
    ) {
        throw 'Production placement requires exact attempt-bound writer fence parameters.'
    }
    $writerFenceHelperFull = Get-StrictFullPath $WriterFenceHelperPath 'writer fence helper'
    $expectedWriterFenceHelper = Get-StrictFullPath `
        (Join-Path $PSScriptRoot 'tools\container_writer_fence.ps1') `
        'expected writer fence helper'
    if (-not (Test-SamePath $writerFenceHelperFull $expectedWriterFenceHelper)) {
        throw 'Production placement writer fence helper path differs.'
    }
    if (-not (Test-Path -LiteralPath $writerFenceHelperFull -PathType Leaf)) {
        throw 'Production placement writer fence helper is unavailable.'
    }
    if ((Get-FileSha256 $writerFenceHelperFull) -cne $ExpectedWriterFenceHelperSha256) {
        throw 'Production placement writer fence helper byte pin differs.'
    }
    . $writerFenceHelperFull
    $preflightLease = Enter-ContainerWriterDelegatedOperation `
        -SessionId $WriterFenceSessionId `
        -AttemptId $WriterFenceAttemptId `
        -ReplacementTransactionId $WriterFenceReplacementTransactionId `
        -DelegationToken $WriterFenceDelegationToken `
        -Source $PlacementWriterSource `
        -TimeoutMilliseconds 15000
    Exit-ContainerWriterAdmission $preflightLease
    if (-not $testOverride) { Invoke-SelfElevated }
    return Enter-ContainerWriterDelegatedOperation `
        -SessionId $WriterFenceSessionId `
        -AttemptId $WriterFenceAttemptId `
        -ReplacementTransactionId $WriterFenceReplacementTransactionId `
        -DelegationToken $WriterFenceDelegationToken `
        -Source $PlacementWriterSource `
        -TimeoutMilliseconds 15000
}

function Assert-RequiredRelease([string]$Root, [bool]$AllowUnsignedPortableForTest) {
    $frozenFiles = @('Container_Audit.exe', 'contract.lock.json')
    $portableFiles = @(
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
    )
    $frozen = @($frozenFiles | Where-Object {
        Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf
    }).Count -eq $frozenFiles.Count
    $portable = @($portableFiles | Where-Object {
        Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf
    }).Count -eq $portableFiles.Count
    if ($frozen -eq $portable) {
        throw "Release layout must be exactly one of FROZEN_EXE or PORTABLE_CPYTHON."
    }
    if ($frozen) { return 'FROZEN_EXE' }

    $manifestPath = Join-Path $Root 'portable-manifest.json'
    if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 65536) {
        throw "Portable release manifest is oversized."
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    catch {
        throw "Portable release manifest is invalid."
    }
    if (
        [string]$manifest.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$manifest.entrypoint -cne 'runtime/pythonw.exe app/main.py' -or
        [string]$manifest.launcher -cne 'launch-container-audit.cmd' -or
        [string]$manifest.writer_fence_helper_path -cne 'tools/container_writer_fence.ps1' -or
        [string]$manifest.writer_session_adapter_path -cne 'tools/container_writer_session.ps1' -or
        [string]$manifest.writer_session_contract_path -cne 'tools/container_writer_session_contract.json' -or
        [string]$manifest.writer_sink_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$manifest.writer_session_contract_schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.source_tree -cnotmatch '^[0-9a-f]{40}$' -or
        @($manifest.allowed_unsigned_app_pe).Count -ne 0 -or
        @($manifest.forbidden_dependency_paths).Count -ne 0
    ) {
        throw "Portable release manifest contract is invalid."
    }
    $pythonwPath = Join-Path $Root 'runtime\pythonw.exe'
    $launcherPath = Join-Path $Root 'launch-container-audit.cmd'
    $installerPath = Join-Path $Root 'INSTALL_CANONICAL_PORTABLE.ps1'
    $helperPath = Join-Path $Root 'INSTALL_THIS_PC.ps1'
    $integrityHelperPath = Join-Path $Root 'tools\bootstrap_integrity.ps1'
    $writerFenceHelperPath = Join-Path $Root 'tools\container_writer_fence.ps1'
    $writerSessionAdapterPath = Join-Path $Root 'tools\container_writer_session.ps1'
    $writerSessionContractPath = Join-Path $Root 'tools\container_writer_session_contract.json'
    $writerSinkInventoryPath = Join-Path $Root 'tools\container_writer_sink_inventory.json'
    if (
        (Get-FileSha256 $pythonwPath) -cne
            ([string]$manifest.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $launcherPath) -cne
            ([string]$manifest.launcher_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $installerPath) -cne
            ([string]$manifest.installer_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $helperPath) -cne
            ([string]$manifest.helper_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $integrityHelperPath) -cne
            ([string]$manifest.integrity_helper_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $writerFenceHelperPath) -cne
            ([string]$manifest.writer_fence_helper_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $writerSessionAdapterPath) -cne
            ([string]$manifest.writer_session_adapter_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $writerSessionContractPath) -cne
            ([string]$manifest.writer_session_contract_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $writerSinkInventoryPath) -cne
            ([string]$manifest.writer_sink_inventory_sha256).ToLowerInvariant()
    ) {
        throw "Portable release manifest hash readback failed."
    }
    Assert-WriterSessionPublicContract $writerSessionContractPath ([string]$manifest.writer_session_contract_sha256).ToLowerInvariant()
    $writerSessionContract = Get-Content -LiteralPath $writerSessionContractPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((Get-Item -LiteralPath $writerSinkInventoryPath -Force).Length -gt 1048576) {
        throw "Writer sink inventory is oversized."
    }
    try { $writerInventory = Get-Content -LiteralPath $writerSinkInventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Writer sink inventory is invalid." }
    if (
        [string]$writerInventory.schema_version -cne 'container-audit-writer-sink-inventory-v8' -or
        [string]$writerInventory.inventory_sha256 -cne [string]$manifest.writer_sink_inventory_contract_sha256 -or
        [string]$writerInventory.inventory_sha256 -cne [string]$writerSessionContract.all_writer_fence.writer_inventory_sha256 -or
        @($writerInventory.uncovered_direct_mutation_functions).Count -ne 0 -or
        @($writerInventory.caller_fence_reference_failures).Count -ne 0 -or
        @($writerInventory.powershell_guard_failures).Count -ne 0 -or
        @($writerInventory.known_route_coverage).Count -le 0 -or
        @($writerInventory.known_route_coverage | Where-Object {
            $_.pass -isnot [bool] -or -not [bool]$_.pass
        }).Count -ne 0
    ) { throw "Writer sink inventory contract is not release-admissible." }
    $filesBeforeManifest = @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Where-Object {
                -not (Test-SamePath $_.FullName $manifestPath)
            }
    )
    $bytesBeforeManifest = [int64](
        ($filesBeforeManifest | Measure-Object -Property Length -Sum).Sum
    )
    if (
        -not (Test-BootstrapJsonInteger $manifest.file_count_before_manifest) -or
        [int64]$manifest.file_count_before_manifest -ne $filesBeforeManifest.Count -or
        -not (Test-BootstrapJsonInteger $manifest.byte_count_before_manifest) -or
        [int64]$manifest.byte_count_before_manifest -ne $bytesBeforeManifest
    ) {
        throw "Portable release tree metrics differ from the manifest."
    }
    if (-not $AllowUnsignedPortableForTest) {
        foreach ($relativePath in @('runtime\python.exe', 'runtime\pythonw.exe')) {
            $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $Root $relativePath)
            if ([string]$signature.Status -cne 'Valid') {
                throw "Portable CPython signature is not valid: $relativePath"
            }
        }
    }
    return 'PORTABLE_CPYTHON'
}

function Write-ElevationLog([string]$Status, [string]$Message) {
    if ([string]::IsNullOrWhiteSpace($ElevationLogPath)) { return }
    $path = Get-StrictFullPath $ElevationLogPath "ElevationLogPath"
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    $entry = [ordered]@{
        captured_at = (Get-Date).ToUniversalTime().ToString('o')
        process_id = $PID
        elevated = $true
        status = $Status
        message = $Message
    }
    [IO.File]::AppendAllText(
        $path,
        (($entry | ConvertTo-Json -Compress) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
}

function ConvertTo-NormalizedAclRights([int64]$Rights) {
    $synchronize = [int64][System.Security.AccessControl.FileSystemRights]::Synchronize
    return $Rights -band (-bnot $synchronize)
}

function Assert-HardenedCodeAcl([string]$Path, [switch]$Recursive) {
    Assert-NoReparsePoint $Path "Hardened code ACL readback"
    $expected = @{
        'S-1-5-18' = [int64][System.Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = [int64][System.Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-545' = [int64][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    }
    $targets = @((Get-Item -LiteralPath $Path -Force -ErrorAction Stop))
    if ($Recursive.IsPresent) {
        $targets += @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop)
    }
    $expectedRootInheritance = [int](
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    foreach ($target in $targets) {
        $isRoot = Test-SamePath $target.FullName $Path
        $acl = Get-Acl -LiteralPath $target.FullName -ErrorAction Stop
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ([string]$owner.Value -cne 'S-1-5-32-544') {
            throw "Hardened code ACL owner is not BUILTIN\Administrators: $($target.FullName)"
        }
        if ($isRoot -and -not $acl.AreAccessRulesProtected) {
            throw "Hardened code root still inherits access rules: $($target.FullName)"
        }
        if (-not $isRoot -and $acl.AreAccessRulesProtected) {
            throw "Hardened code descendant does not inherit the root DACL: $($target.FullName)"
        }
        $actual = @{}
        foreach ($rule in @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ))) {
            $sid = [string]$rule.IdentityReference.Value
            if (
                [string]$rule.AccessControlType -cne 'Allow' -or
                -not $expected.ContainsKey($sid) -or
                ($isRoot -and $rule.IsInherited) -or
                (-not $isRoot -and -not $rule.IsInherited)
            ) {
                throw "Hardened code DACL contains an unexpected ACE for $sid on $($target.FullName)"
            }
            if (
                $isRoot -and (
                    [int]$rule.InheritanceFlags -ne $expectedRootInheritance -or
                    [string]$rule.PropagationFlags -cne 'None'
                )
            ) {
                throw "Hardened code root inheritance flags differ for $sid."
            }
            if (-not $actual.ContainsKey($sid)) { $actual[$sid] = [int64]0 }
            $actual[$sid] = [int64]$actual[$sid] -bor [int64]$rule.FileSystemRights
        }
        if ($actual.Count -ne $expected.Count) {
            throw "Hardened code DACL principal count differs: $($target.FullName)"
        }
        foreach ($sid in $expected.Keys) {
            if (
                -not $actual.ContainsKey($sid) -or
                (ConvertTo-NormalizedAclRights ([int64]$actual[$sid])) -ne
                (ConvertTo-NormalizedAclRights ([int64]$expected[$sid]))
            ) {
                throw "Hardened code DACL rights differ for $sid on $($target.FullName)"
            }
        }
    }
}

function Set-HardenedCodeAcl([string]$Path, [switch]$Recursive) {
    try {
        Assert-NoReparsePoint $Path "Hardened code ACL target"
        $icacls = Join-Path ([Environment]::SystemDirectory) 'icacls.exe'
        $ownerArgs = @($Path, '/setowner', '*S-1-5-32-544', '/L')
        $resetArgs = @($Path, '/reset', '/L')
        if ($Recursive.IsPresent) {
            $ownerArgs += '/T'
            $resetArgs += '/T'
        }
        & $icacls @ownerArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Hardened code owner assignment failed: $Path" }
        & $icacls @resetArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Hardened code DACL reset failed: $Path" }
        & $icacls $Path `
            '/inheritance:r' `
            '/grant:r' `
            '*S-1-5-18:(OI)(CI)F' `
            '*S-1-5-32-544:(OI)(CI)F' `
            '*S-1-5-32-545:(OI)(CI)RX' `
            '/L' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Hardened code DACL installation failed: $Path" }
        Assert-HardenedCodeAcl $Path -Recursive:$Recursive.IsPresent
    }
    catch {
        Write-Output "acl_readback_status=UNKNOWN"
        throw
    }
}

function Get-LegacyTaskByNameFailClosed([string]$Name) {
    try {
        $taskMatches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            ([string]$_.TaskName).Equals($Name, [StringComparison]::OrdinalIgnoreCase)
        })
    }
    catch {
        throw "Legacy scheduled task observation failed: $Name/$($_.Exception.GetType().Name)"
    }
    if ($taskMatches.Count -gt 1) {
        throw "Legacy scheduled task observation is non-unique: $Name"
    }
    return $taskMatches
}

function Remove-OwnedLegacyTask([string]$Name, [string]$ExpectedRoot) {
    $taskMatches = @(Get-LegacyTaskByNameFailClosed $Name)
    if ($taskMatches.Count -eq 0) { return }
    $task = $taskMatches[0]
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw "Refusing to remove a legacy task with an ambiguous action: $Name"
    }
    $actionText = "$([string]$actions[0].Execute) $([string]$actions[0].Arguments)"
    $ownedFieldLauncher = 'C:\ProgramData\KMTech\DirectSync\container_audit\bin\direct-sync-relay-container-audit.cmd'
    $owned = (
        $actionText.IndexOf($ExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $actionText.IndexOf($ownedFieldLauncher, [StringComparison]::OrdinalIgnoreCase) -ge 0
    )
    if (-not $owned) {
        throw "Refusing to remove a scheduled task not owned by this application: $Name"
    }
    $taskPath = [string]$task.TaskPath
    $manifestPath = Join-Path $ExpectedRoot 'portable-manifest.json'
    $writerFenceHelperPath = Join-Path $ExpectedRoot 'tools\container_writer_fence.ps1'
    if (
        -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $writerFenceHelperPath -PathType Leaf)
    ) { throw 'Legacy task removal requires the admitted all-writer fence helper.' }
    if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 65536) {
        throw 'Legacy task removal manifest is oversized.'
    }
    try { $installedManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Legacy task removal manifest is invalid.' }
    if (
        [string]$installedManifest.writer_fence_helper_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 $writerFenceHelperPath) -cne [string]$installedManifest.writer_fence_helper_sha256
    ) { throw 'Legacy task removal writer-fence helper pin differs.' }
    . $writerFenceHelperPath
    [void](Remove-ContainerScheduledTaskUnderWriterFence `
        -SessionId ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID) `
        -AttemptId ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID) `
        -ReplacementTransactionId ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID) `
        -DelegationToken ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN) `
        -TaskName ([string]$task.TaskName) `
        -TaskPath $taskPath)
    if (@(Get-LegacyTaskByNameFailClosed $Name).Count -ne 0) {
        throw "Legacy scheduled task removal readback failed: $Name"
    }
}

function Test-CurrentUserRelayPersistencePresent {
    $runKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    try {
        $value = Get-ItemPropertyValue `
            -LiteralPath $runKey `
            -Name 'KMTech.ContainerAudit.Relay' `
            -ErrorAction Stop
        return -not [string]::IsNullOrWhiteSpace([string]$value)
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $false
    }
    catch [System.Management.Automation.PSArgumentException] {
        return $false
    }
}

function Test-PathWithin([string]$Candidate, [string]$Root) {
    $candidateFull = Get-StrictFullPath $Candidate 'candidate path'
    $rootFull = (Get-StrictFullPath $Root 'root path') + '\'
    return $candidateFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ContainerReplacementRestoreQuiescent(
    [string]$CurrentRoot,
    [switch]$SkipOwnedTaskCheckForGuardedTest
) {
    $rootPrefix = (Get-StrictFullPath $CurrentRoot 'restore process root') + '\'
    try { $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop) }
    catch { throw 'Replacement restore could not prove process quiescence.' }
    $matches = @($processes | Where-Object {
        if ([int]$_.ProcessId -eq $PID) { return $false }
        $command = [string]$_.CommandLine
        $executable = [string]$_.ExecutablePath
        return (
            (
                -not [string]::IsNullOrWhiteSpace($executable) -and
                $executable.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -and
                [IO.Path]::GetFileName($executable) -in @('python.exe', 'pythonw.exe', 'Container_Audit.exe')
            ) -or
            (
                $command.IndexOf($rootPrefix.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $command.IndexOf('app\main.py', [StringComparison]::OrdinalIgnoreCase) -ge 0
            )
        )
    })
    if ($matches.Count -ne 0) { throw 'Replacement restore requires zero Container product processes.' }
    if (-not $SkipOwnedTaskCheckForGuardedTest.IsPresent) {
        try { $task = Get-ScheduledTask -TaskName $LegacyRelayTaskName -ErrorAction SilentlyContinue }
        catch { throw 'Replacement restore could not prove scheduled-task quiescence.' }
        if ($null -ne $task -and [string]$task.State -cne 'Disabled') {
            throw 'Replacement restore requires the owned scheduled writer to be disabled or absent.'
        }
    }
}

$testOverride = (
    $AllowNoncanonicalLayoutForTest.IsPresent -and
    [string]$env:KMTECH_FACTORY_INSTALL_TEST_MODE -ceq '1'
)
if ([string]::IsNullOrWhiteSpace($OperatorLocalAppDataRoot)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw "The invoking operator LOCALAPPDATA is unavailable." }
    $OperatorLocalAppDataRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
    $BootstrapBoundParameters["OperatorLocalAppDataRoot"] = $OperatorLocalAppDataRoot
}
if ($ApplyHardenedAclForTest.IsPresent -and -not $testOverride) {
    throw "ApplyHardenedAclForTest requires the guarded noncanonical test layout."
}
if ($InjectRestoreFailureAfterDisplaceForTest.IsPresent -and -not $testOverride) {
    throw 'InjectRestoreFailureAfterDisplaceForTest requires the guarded noncanonical test layout.'
}
if ($RestoreUninstallRecordPath -and ($Uninstall -or $ReplaceExistingVerifiedPortable -or $RestoreVerifiedReplacement -or $TlsCaBundlePath)) {
    throw 'Uninstall recovery accepts only exact fenced code placement.'
}
if ($ReplaceExistingVerifiedPortable.IsPresent -and $Uninstall.IsPresent) {
    throw "ReplaceExistingVerifiedPortable cannot be combined with Uninstall."
}
$applyHardenedAcl = (-not $testOverride -or $ApplyHardenedAclForTest.IsPresent)
$aclReadbackStatus = if ($applyHardenedAcl) { 'UNKNOWN' } else { 'NOT_TESTED' }
$installRootFull = Get-StrictFullPath $InstallRoot "InstallRoot"
if (-not (Test-SamePath $installRootFull $ExpectedInstallRoot) -and -not $testOverride) {
    throw "InstallRoot must be the hardened Container_Audit code root."
}
if ($ProbeVerifiedReplacementRestore.IsPresent) {
    if (
        -not $DryRun.IsPresent -or $Uninstall.IsPresent -or
        $ReplaceExistingVerifiedPortable.IsPresent -or $RestoreVerifiedReplacement.IsPresent
    ) { throw 'ProbeVerifiedReplacementRestore is a DryRun-only exclusive operation.' }
    Write-Output 'replacement_restore_status=DRY_RUN'
    Write-Output 'replacement_restore_schema=container-audit-verified-replacement-v1'
    Write-Output 'replacement_restore_receipt_required_at_apply=true'
    Write-Output 'identity_profile_created=false'
    exit 0
}
if (
    $Uninstall.IsPresent -and
    -not $DryRun.IsPresent -and
    -not $testOverride -and
    (Test-CurrentUserRelayPersistencePresent)
) {
    throw (
        "Run the exact packet's INSTALL_CANONICAL_PORTABLE.ps1 -Uninstall as the current user " +
        "before removing hardened code."
    )
}
$placementWriterFenceLease = $null
if (-not $DryRun.IsPresent -and (-not $testOverride -or $Uninstall.IsPresent -or $RestoreUninstallRecordPath)) {
    $placementWriterFenceLease = Enter-ContainerPlacementWriterFence
    . $WriterFenceHelperPath
}
try {
if ($RestoreVerifiedReplacement.IsPresent) {
    if ($DryRun.IsPresent -or $Uninstall.IsPresent -or $ReplaceExistingVerifiedPortable.IsPresent) {
        throw 'RestoreVerifiedReplacement cannot be combined with placement, uninstall, or DryRun.'
    }
    if ($PSBoundParameters.ContainsKey('SourceRoot') -or -not [string]::IsNullOrWhiteSpace($TlsCaBundlePath)) {
        throw 'RestoreVerifiedReplacement does not accept source or TLS mutation inputs.'
    }
    if ($ReplacementTransactionId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Replacement restore transaction id is invalid.'
    }
    if ([string]::IsNullOrWhiteSpace($ReplacementReceiptPath) -or [string]::IsNullOrWhiteSpace($RestoreEvidencePath)) {
        throw 'Replacement restore receipt and evidence paths are required.'
    }
    if (-not $testOverride) {
        Write-ElevationLog 'STARTED' 'Elevated Container verified replacement restore started.'
    }
    $restoreEvidenceFull = Get-StrictFullPath $RestoreEvidencePath 'RestoreEvidencePath'
    try {
        Assert-ContainerReplacementRestoreQuiescent `
            -CurrentRoot $installRootFull `
            -SkipOwnedTaskCheckForGuardedTest:$testOverride
        $receipt = Read-BootstrapReplacementReceipt `
            -Path $ReplacementReceiptPath `
            -ExpectedSha256 $ReplacementReceiptSha256
        $result = Invoke-BootstrapVerifiedReplacementRestore `
            -Receipt $receipt `
            -ReceiptPath $ReplacementReceiptPath `
            -InstallRoot $installRootFull `
            -ExpectedAppId 'container_audit' `
            -ExpectedTransactionId $ReplacementTransactionId `
            -ExpectedHelperSha256 (Get-FileSha256 $BootstrapScriptPath) `
            -InjectFailureAfterDisplace:$InjectRestoreFailureAfterDisplaceForTest.IsPresent
        if (
            $result.prior_code_exact -isnot [bool] -or
            -not $result.prior_code_exact -or
            $result.failed_new_preserved -isnot [bool] -or
            -not $result.failed_new_preserved
        ) { throw 'Replacement restore result Boolean evidence is invalid.' }
        $evidence = [ordered]@{
            schema_version = 'container-audit-verified-replacement-code-restore-v1'
            status = 'PASS'
            action = [string]$result.status
            app_id = 'container_audit'
            transaction_id = $ReplacementTransactionId
            receipt_path = Get-StrictFullPath $ReplacementReceiptPath 'replacement receipt path'
            receipt_sha256 = $ReplacementReceiptSha256
            install_root = $installRootFull
            failed_new_root = [string]$result.failed_new_root
            prior_code_exact = $result.prior_code_exact
            failed_new_preserved = $result.failed_new_preserved
            identity_or_credential_copied = $false
            completed_at = (Get-Date).ToUniversalTime().ToString('o')
        }
        Write-BootstrapReplacementReceipt -Path $restoreEvidenceFull -Payload $evidence | Out-Null
        if (-not $testOverride) { Write-ElevationLog 'PASS' 'Elevated Container verified replacement restore completed.' }
        Write-Output "replacement_restore_status=$($result.status)"
        Write-Output "replacement_restore_evidence=$restoreEvidenceFull"
        Write-Output "replacement_restore_evidence_sha256=$(Get-FileSha256 $restoreEvidenceFull)"
        exit 0
    }
    catch {
        $failure = [ordered]@{
            schema_version = 'container-audit-verified-replacement-code-restore-v1'
            status = 'ROLLBACK_FAILED'
            app_id = 'container_audit'
            transaction_id = $ReplacementTransactionId
            failure_type = $_.Exception.GetType().Name
            mutation_silently_ignored = $false
            identity_or_credential_copied = $false
            failed_at = (Get-Date).ToUniversalTime().ToString('o')
        }
        try { Write-BootstrapReplacementReceipt -Path $restoreEvidenceFull -Payload $failure | Out-Null } catch {}
        if (-not $testOverride) { Write-ElevationLog 'FAILED' 'Elevated Container verified replacement restore failed.' }
        Write-Output 'replacement_restore_status=ROLLBACK_FAILED'
        Write-Output "replacement_restore_evidence=$restoreEvidenceFull"
        throw
    }
}
if (-not $DryRun.IsPresent -and -not $testOverride) {
    Write-ElevationLog 'STARTED' 'Elevated Container code placement started.'
}

if ($Uninstall.IsPresent) {
    if ($DryRun.IsPresent) {
        Write-Output "uninstall_status=DRY_RUN_CODE_ONLY"
        Write-Output "user_state_preserved=true"
        exit 0
    }
    $uninstallSource = Get-StrictFullPath $SourceRoot 'uninstall source'
    if ($ExpectedInstalledManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedInstalledAggregateSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Test-SamePath $uninstallSource $installRootFull) -or
        (Test-PathWithin $uninstallSource $installRootFull) -or
        (Test-PathWithin $installRootFull $uninstallSource)) {
        throw 'UNINSTALL_EXACT_IDENTITY_REQUIRED: use the canonical uninstall entrypoint.'
    }
    Assert-NoReparsePoint $uninstallSource 'uninstall source'
    Assert-NoReparsePoint $installRootFull 'uninstall target'
    [void](Assert-RequiredRelease $uninstallSource $testOverride)
    if (-not (Test-SamePath $BootstrapScriptPath (Join-Path $uninstallSource 'INSTALL_THIS_PC.ps1'))) {
        throw 'Uninstall helper must execute from the admitted SourceRoot.'
    }
    $uninstallRecord = Assert-BootstrapIntegrityRecord $installRootFull
    $uninstallRecordSha = Get-FileSha256 (Join-Path $installRootFull $IntegrityFileName)
    if ((Get-FileSha256 (Join-Path $installRootFull 'portable-manifest.json')) -cne $ExpectedInstalledManifestSha256 -or
        (Get-FileSha256 (Join-Path $uninstallSource 'portable-manifest.json')) -cne $ExpectedInstalledManifestSha256 -or
        (Get-InventoryAggregate @(Get-CodeInventory $uninstallSource)) -cne $ExpectedInstalledAggregateSha256 -or
        [string]$uninstallRecord.aggregate_sha256 -cne $ExpectedInstalledAggregateSha256) {
        throw 'UNINSTALL_IDENTITY_MISMATCH: source or installed bytes differ.'
    }
    $quiesceFull = Get-StrictFullPath $QuiesceReceiptPath 'current-user removal receipt'
    $expectedQuiescePath = Join-Path $OperatorLocalAppDataRoot 'KMTech\DirectSync\container_audit\status\current_user_removal.json'
    Assert-NoReparsePoint $quiesceFull 'current-user removal receipt'
    if (-not (Test-SamePath $quiesceFull $expectedQuiescePath) -or
        $ExpectedQuiesceReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 $quiesceFull) -cne $ExpectedQuiesceReceiptSha256 -or
        (Get-Item -LiteralPath $quiesceFull).Length -gt 65536) {
        throw 'Uninstall current-user removal receipt binding differs.'
    }
    $quiesce = Get-Content -LiteralPath $quiesceFull -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$quiesce.status -cne 'PASS_DATA_PRESERVED' -or
        [string]$quiesce.state_scope -cne 'current_user' -or
        $quiesce.data_preserved -isnot [bool] -or -not $quiesce.data_preserved -or
        [string]$quiesce.relay_autostart.status -cne 'ABSENT' -or
        [string]$quiesce.relay_process.status -cne 'ABSENT' -or
        -not (Test-SamePath ([string]$quiesce.machine_code_root) (Join-Path $installRootFull 'app'))) {
        throw 'Uninstall current-user quiescence was not proven.'
    }
    Assert-ContainerReplacementRestoreQuiescent -CurrentRoot $installRootFull -SkipOwnedTaskCheckForGuardedTest:$testOverride
    if (-not $testOverride) {
        foreach ($name in @($LegacyQualificationTaskName, $LegacyRelayTaskName)) {
            if ($null -ne (Get-LegacyTaskByNameFailClosed $name)) {
                throw 'Uninstall requires the current-user layout without legacy scheduled writers.'
            }
        }
    }
    $uninstallParent = Get-StrictFullPath (Split-Path -Parent $installRootFull) 'uninstall parent'
    $uninstallBackup = Get-StrictFullPath (Join-Path $uninstallParent ('.current.uninstall.' + $WriterFenceAttemptId)) 'uninstall recovery tree'
    if (-not (Test-PathWithin $uninstallBackup $uninstallParent)) { throw 'Uninstall backup escaped its parent.' }
    if (Test-Path -LiteralPath $uninstallBackup) { throw 'Uninstall recovery tree already exists.' }
    $uninstallMutationStarted = $false
    try {
        Copy-Item -LiteralPath $installRootFull -Destination $uninstallBackup -Recurse
        if ($applyHardenedAcl) { Set-HardenedCodeAcl $uninstallBackup -Recursive }
        if ((Get-InventoryAggregate @(Get-CodeInventory $uninstallBackup)) -cne $ExpectedInstalledAggregateSha256 -or
            (Get-FileSha256 (Join-Path $uninstallBackup $IntegrityFileName)) -cne $uninstallRecordSha) {
            throw 'Uninstall code preimage copy readback failed.'
        }
        Assert-ContainerReplacementRestoreQuiescent -CurrentRoot $installRootFull -SkipOwnedTaskCheckForGuardedTest:$testOverride
        $uninstallMutationStarted = $true
        Remove-Item -LiteralPath $installRootFull -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $installRootFull) { throw 'Hardened code root removal postcondition failed.' }
        $uninstallMutationStarted = $false
        try { Remove-Item -LiteralPath $uninstallBackup -Recurse -Force -ErrorAction Stop }
        catch { Write-Output "code_recovery_cleanup_status=RETAINED:$uninstallBackup" }
        if (-not $testOverride) { Write-ElevationLog 'PASS' 'Elevated Container code removal completed.' }
        Write-Output 'uninstall_status=PASS_CODE_REMOVED_STATE_PRESERVED'
        Write-Output 'application_root_status=ABSENT'
        Write-Output 'user_state_preserved=true'
    }
    catch {
        $uninstallFailure = $_
        if ($uninstallMutationStarted) {
            Assert-NoReparsePoint $uninstallBackup 'uninstall recovery tree'
            Assert-NoReparsePoint $installRootFull 'partial uninstall target'
            foreach ($item in @(Get-ChildItem -LiteralPath $uninstallBackup -Force -Recurse)) {
                $destination = Join-Path $installRootFull (Get-RelativeCodePath $uninstallBackup $item.FullName)
                if ($item.PSIsContainer) { New-Item -ItemType Directory -Path $destination -Force | Out-Null }
                else {
                    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
                    if (-not (Test-Path -LiteralPath $destination) -or (Get-FileSha256 $destination) -cne (Get-FileSha256 $item.FullName)) {
                        Copy-Item -LiteralPath $item.FullName -Destination $destination -Force
                    }
                }
            }
            if ($applyHardenedAcl) { Set-HardenedCodeAcl $installRootFull -Recursive }
            [void](Assert-BootstrapIntegrityRecord $installRootFull)
            if ((Get-InventoryAggregate @(Get-CodeInventory $installRootFull)) -cne $ExpectedInstalledAggregateSha256 -or
                (Get-FileSha256 (Join-Path $installRootFull $IntegrityFileName)) -cne $uninstallRecordSha) {
                throw "UNINSTALL_CODE_RESTORE_FAILED: recovery_tree=$uninstallBackup"
            }
            Write-Output 'code_restore_status=PASS_VERIFIED'
        }
        throw $uninstallFailure
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$sourceRootFull = Get-StrictFullPath $SourceRoot "SourceRoot"
if (-not (Test-Path -LiteralPath $sourceRootFull -PathType Container)) {
    throw "SourceRoot does not exist."
}
if (Test-SamePath $sourceRootFull $installRootFull) {
    throw "SourceRoot and InstallRoot must differ."
}
Assert-NoReparsePoint $sourceRootFull "Frozen release"
$releaseLayout = Assert-RequiredRelease $sourceRootFull $testOverride
if ($releaseLayout -ceq 'PORTABLE_CPYTHON') {
    if (-not (Test-SamePath $BootstrapScriptPath (Join-Path $sourceRootFull 'INSTALL_THIS_PC.ps1'))) {
        throw 'Code helper must execute from the admitted SourceRoot.'
    }
    if (-not (Test-SamePath $BootstrapIntegrityFunctions (Join-Path $sourceRootFull 'tools\bootstrap_integrity.ps1'))) {
        throw 'Integrity helper must load from the admitted SourceRoot.'
    }
}
$sourceInventory = @(Get-CodeInventory $sourceRootFull)
if ($sourceInventory.Count -eq 0) {
    throw "Frozen release code inventory is empty."
}
$sourceAggregate = Get-InventoryAggregate $sourceInventory
if ($RestoreUninstallRecordPath) {
    if ($DryRun -or (Test-Path -LiteralPath $installRootFull) -or
        $ExpectedUninstallRecordSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $sourceAggregate -cne $ExpectedInstalledAggregateSha256 -or
        (Get-FileSha256 (Join-Path $sourceRootFull 'portable-manifest.json')) -cne $ExpectedInstalledManifestSha256) {
        throw 'UNINSTALL_RECOVERY_IDENTITY_INVALID: exact source and absent target required.'
    }
    $RestoreUninstallRecordPath = Get-StrictFullPath $RestoreUninstallRecordPath 'uninstall integrity preimage'
    Assert-NoReparsePoint $RestoreUninstallRecordPath 'uninstall integrity preimage'
    if ((Get-FileSha256 $RestoreUninstallRecordPath) -cne $ExpectedUninstallRecordSha256) {
        throw 'UNINSTALL_RECOVERY_RECORD_CHANGED'
    }
    Assert-ContainerReplacementRestoreQuiescent -CurrentRoot $installRootFull -SkipOwnedTaskCheckForGuardedTest:$testOverride
}
if ($DryRun.IsPresent) {
    Write-Output "bootstrap_status=DRY_RUN"
    Write-Output "code_root=$installRootFull"
    Write-Output "release_layout=$releaseLayout"
    Write-Output "file_count=$($sourceInventory.Count)"
    Write-Output "aggregate_sha256=$sourceAggregate"
    Write-Output "identity_profile_created=false"
    Write-Output "tls_ca_bootstrap_configured=$(-not [string]::IsNullOrWhiteSpace($TlsCaBundlePath))"
    Write-Output "elevation_points=1:code_placement"
    exit 0
}

$applicationParent = Split-Path -Parent $installRootFull
$stagingRoot = Join-Path $applicationParent ('.current.bootstrap.' + [Guid]::NewGuid().ToString('N'))
$replacementApplied = $false
$replacementRollbackRoot = ''
$replacementReceiptFull = ''
$replacementReceiptWritten = $false
$previousReplacementIdentity = $null
New-Item -ItemType Directory -Path $applicationParent -Force | Out-Null
if ($applyHardenedAcl) {
    Set-HardenedCodeAcl $applicationParent
}
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
try {
    foreach ($directory in @(Get-ChildItem -LiteralPath $sourceRootFull -Directory -Force -Recurse | Sort-Object FullName)) {
        $relative = Get-RelativeCodePath $sourceRootFull $directory.FullName
        New-Item -ItemType Directory -Path (Join-Path $stagingRoot $relative) -Force | Out-Null
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceRootFull -File -Force -Recurse | Sort-Object FullName)) {
        $relative = Get-RelativeCodePath $sourceRootFull $file.FullName
        if ($relative.Equals($IntegrityFileName, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $destination = Join-Path $stagingRoot $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    }
    $stagedInventory = @(Get-CodeInventory $stagingRoot)
    $stagedAggregate = Get-InventoryAggregate $stagedInventory
    if ($stagedAggregate -cne $sourceAggregate) {
        throw "Staged code integrity readback differs from the frozen release."
    }
    [void](Write-BootstrapIntegrityRecord `
        -Root $stagingRoot `
        -CodeRootIdentity $installRootFull)
    if ($RestoreUninstallRecordPath) {
        Copy-Item -LiteralPath $RestoreUninstallRecordPath -Destination (Join-Path $stagingRoot $IntegrityFileName) -Force
        if ((Get-FileSha256 (Join-Path $stagingRoot $IntegrityFileName)) -cne $ExpectedUninstallRecordSha256) {
            throw 'Uninstall recovery staging record readback failed.'
        }
    }
    if ($applyHardenedAcl) {
        Set-HardenedCodeAcl $stagingRoot -Recursive
    }
    if (Test-Path -LiteralPath $installRootFull) {
        $existingRecordPath = Join-Path $installRootFull $IntegrityFileName
        $existingAggregate = ''
        $existingCodeAggregate = ''
        if (Test-Path -LiteralPath $existingRecordPath -PathType Leaf) {
            try {
                $existingAggregate = [string]((Get-Content -LiteralPath $existingRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json).aggregate_sha256)
                $existingCodeAggregate = Get-InventoryAggregate @(Get-CodeInventory $installRootFull)
            }
            catch {
                $existingAggregate = ''
                $existingCodeAggregate = ''
            }
        }
        if (
            $existingAggregate -cne $sourceAggregate -or
            $existingCodeAggregate -cne $sourceAggregate
        ) {
            if (-not $ReplaceExistingVerifiedPortable.IsPresent) {
                throw "A different or damaged hardened code placement exists; remove it explicitly before replacement."
            }
            if (
                $ReplacementTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
                [string]::IsNullOrWhiteSpace($ReplacementReceiptPath)
            ) { throw 'Verified replacement requires an exact durable receipt binding.' }
            $replacementReceiptFull = Get-StrictFullPath $ReplacementReceiptPath 'ReplacementReceiptPath'
            if (
                (Test-PathWithin $replacementReceiptFull $applicationParent) -or
                (Test-Path -LiteralPath $replacementReceiptFull)
            ) { throw 'Replacement receipt must be a new path outside the code parent.' }
            $ambiguousSiblings = @(Get-ChildItem -LiteralPath $applicationParent -Directory -Force | Where-Object {
                $_.Name -match '^\.current\.(rollback|failed)\.'
            })
            if ($ambiguousSiblings.Count -ne 0) {
                throw 'Verified replacement found an unrelated rollback or failed sibling.'
            }
            Assert-ContainerReplacementRestoreQuiescent `
                -CurrentRoot $installRootFull `
                -SkipOwnedTaskCheckForGuardedTest:$testOverride
            [void](Assert-BootstrapIntegrityRecord -Root $installRootFull)
            Assert-NoReparsePoint $installRootFull 'Verified replacement existing code root'
            if ($applyHardenedAcl) { Assert-HardenedCodeAcl $installRootFull -Recursive }
            $existingManifestPath = Join-Path $installRootFull 'portable-manifest.json'
            if (-not (Test-Path -LiteralPath $existingManifestPath -PathType Leaf)) {
                throw 'Verified replacement requires an existing portable manifest.'
            }
            $existingManifest = Get-Content -LiteralPath $existingManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if (
                [string]$existingManifest.schema -cne 'container-audit-portable-tree-v1' -or
                [string]$existingManifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
                [string]$existingManifest.source_tree -cnotmatch '^[0-9a-f]{40}$'
            ) { throw 'Verified replacement existing portable identity is invalid.' }
            $previousReplacementIdentity = Get-BootstrapReplacementTreeIdentity $installRootFull $installRootFull
            $replacementRollbackRoot = Join-Path $applicationParent ('.current.rollback.' + $ReplacementTransactionId)
            $failedRoot = Join-Path $applicationParent ('.current.failed.' + $ReplacementTransactionId)
            if ((Test-Path -LiteralPath $replacementRollbackRoot) -or (Test-Path -LiteralPath $failedRoot)) {
                throw 'Verified replacement transaction siblings already exist.'
            }
            Move-Item -LiteralPath $installRootFull -Destination $replacementRollbackRoot
            try {
                Move-Item -LiteralPath $stagingRoot -Destination $installRootFull
                $replacementApplied = $true
                $bootstrapStatus = 'REPLACED_VERIFIED'
            }
            catch {
                if (
                    -not (Test-Path -LiteralPath $installRootFull) -and
                    (Test-Path -LiteralPath $replacementRollbackRoot -PathType Container)
                ) {
                    Move-Item -LiteralPath $replacementRollbackRoot -Destination $installRootFull
                }
                throw
            }
        }
        else {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
            $bootstrapStatus = 'REUSED'
        }
    }
    else {
        Move-Item -LiteralPath $stagingRoot -Destination $installRootFull
        $bootstrapStatus = 'PASS'
    }
    if ($applyHardenedAcl) {
        Set-HardenedCodeAcl $installRootFull -Recursive
        $aclReadbackStatus = 'PASS'
    }
    $installedAggregate = Get-InventoryAggregate @(Get-CodeInventory $installRootFull)
    if ($installedAggregate -cne $sourceAggregate) {
        throw "Installed code integrity readback failed."
    }
    $replacementReceipt = $null
    if ($replacementApplied) {
        $newIdentity = Get-BootstrapReplacementTreeIdentity $installRootFull $installRootFull
        $oldIdentity = Get-BootstrapReplacementTreeIdentity $replacementRollbackRoot $installRootFull
        if (
            -not (Test-BootstrapReplacementTreeIdentity $previousReplacementIdentity $oldIdentity) -or
            [string]$newIdentity.aggregate_sha256 -cne $sourceAggregate
        ) { throw 'Verified replacement tree identity readback failed.' }
        $parentAcl = Get-BootstrapAclIdentity $applicationParent
        $receiptPayload = [ordered]@{
            schema_version = 'container-audit-verified-replacement-v1'
            status = 'OLD_PRESERVED_NEW_VERIFIED'
            app_id = 'container_audit'
            transaction_id = $ReplacementTransactionId
            created_at = (Get-Date).ToUniversalTime().ToString('o')
            helper_sha256 = Get-FileSha256 $BootstrapScriptPath
            integrity_helper_sha256 = Get-FileSha256 $BootstrapIntegrityFunctions
            receipt_path = $replacementReceiptFull
            install_root = $installRootFull
            install_parent = $applicationParent
            rollback_root = $replacementRollbackRoot
            failed_root = Join-Path $applicationParent ('.current.failed.' + $ReplacementTransactionId)
            parent_acl = $parentAcl
            old = $oldIdentity
            new = $newIdentity
            identity_or_credential_copied = $false
        }
        $replacementReceipt = Write-BootstrapReplacementReceipt `
            -Path $replacementReceiptFull `
            -Payload $receiptPayload
        $replacementReceiptWritten = $true
    }
    if ($RestoreUninstallRecordPath -and
        (Get-FileSha256 (Join-Path $installRootFull $IntegrityFileName)) -cne $ExpectedUninstallRecordSha256) {
        throw 'Uninstall recovery installed record readback failed.'
    }
    Write-Output "bootstrap_status=$bootstrapStatus"
    Write-Output "acl_readback_status=$aclReadbackStatus"
    if ($aclReadbackStatus -ceq 'PASS') {
        Write-Output "acl_owner_sid=S-1-5-32-544"
        Write-Output "dacl_normalized=true"
    }
    Write-Output "code_root=$installRootFull"
    Write-Output "release_layout=$releaseLayout"
    Write-Output "integrity_record=$(Join-Path $installRootFull $IntegrityFileName)"
    $tlsCaBootstrap = Install-CurrentUserTlsCaBootstrap $TlsCaBundlePath $OperatorLocalAppDataRoot
    if ($null -eq $tlsCaBootstrap) { Write-Output "tls_ca_bootstrap_status=ABSENT" }
    else { Write-Output "tls_ca_bootstrap_status=PASS"; Write-Output "tls_ca_bootstrap_path=$tlsCaBootstrap" }
    Write-Output "file_count=$($sourceInventory.Count)"
    Write-Output "aggregate_sha256=$sourceAggregate"
    Write-Output "identity_profile_created=false"
    Write-Output "elevation_points=1:code_placement"
    if ($replacementApplied) {
        Write-Output 'replacement_rollback_status=PRESERVED'
        Write-Output "replacement_rollback_root=$replacementRollbackRoot"
        Write-Output 'replacement_receipt_status=OLD_PRESERVED_NEW_VERIFIED'
        Write-Output "replacement_receipt_path=$($replacementReceipt.path)"
        Write-Output "replacement_receipt_sha256=$($replacementReceipt.sha256)"
        Write-Output "replacement_transaction_id=$ReplacementTransactionId"
    }
    if (-not $testOverride) {
        Write-ElevationLog 'PASS' "Elevated Container code placement completed: $bootstrapStatus."
    }
}
catch {
    if (-not $testOverride) {
        Write-ElevationLog 'FAILED' ($_.Exception.GetType().Name)
    }
    if (Test-Path -LiteralPath $stagingRoot) {
        $stagingFull = Get-StrictFullPath $stagingRoot "bootstrap staging root"
        $parentFull = (Get-StrictFullPath $applicationParent "application parent") + '\'
        if (-not $stagingFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Bootstrap failed and staging cleanup target escaped its parent."
        }
        Remove-Item -LiteralPath $stagingFull -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($replacementApplied) {
        $failedRoot = Join-Path $applicationParent ('.current.failed.' + $ReplacementTransactionId)
        if (Test-Path -LiteralPath $installRootFull -PathType Container) {
            if (Test-Path -LiteralPath $failedRoot) {
                throw 'Verified replacement failure containment target already exists.'
            }
            Move-Item -LiteralPath $installRootFull -Destination $failedRoot
        }
        if (-not (Test-Path -LiteralPath $replacementRollbackRoot -PathType Container)) {
            throw 'Verified replacement rollback source is unavailable.'
        }
        Move-Item -LiteralPath $replacementRollbackRoot -Destination $installRootFull
        $restoredIdentity = Get-BootstrapReplacementTreeIdentity $installRootFull $installRootFull
        if (-not (Test-BootstrapReplacementTreeIdentity $previousReplacementIdentity $restoredIdentity)) {
            throw 'Verified replacement prior tree restore readback failed.'
        }
        if ($replacementReceiptWritten -and (Test-Path -LiteralPath $replacementReceiptFull -PathType Leaf)) {
            Remove-Item -LiteralPath $replacementReceiptFull -Force -ErrorAction SilentlyContinue
        }
        throw 'Verified replacement failed and the prior canonical tree was restored.'
    }
    throw
}
}
finally {
    if ($null -ne $placementWriterFenceLease) {
        Exit-ContainerWriterAdmission $placementWriterFenceLease
    }
}
