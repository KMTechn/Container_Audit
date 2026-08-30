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
        'tools\container_writer_session.ps1'
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
    $writerSessionAdapterPath = Join-Path $Root 'tools\container_writer_session.ps1'
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
        (Get-FileSha256 $writerSessionAdapterPath) -cne
            ([string]$manifest.writer_session_adapter_sha256).ToLowerInvariant()
    ) {
        throw "Portable release manifest hash readback failed."
    }
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
        [int64]$manifest.file_count_before_manifest -ne $filesBeforeManifest.Count -or
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
    Stop-ScheduledTask `
        -TaskName ([string]$task.TaskName) `
        -TaskPath $taskPath `
        -ErrorAction SilentlyContinue
    Unregister-ScheduledTask `
        -TaskName ([string]$task.TaskName) `
        -TaskPath $taskPath `
        -Confirm:$false `
        -ErrorAction Stop
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
        Invoke-SelfElevated
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
            prior_code_exact = [bool]$result.prior_code_exact
            failed_new_preserved = [bool]$result.failed_new_preserved
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
if (
    $Uninstall.IsPresent -and
    -not $DryRun.IsPresent -and
    -not $testOverride -and
    (Test-CurrentUserRelayPersistencePresent)
) {
    throw (
        "Run Container_Audit.exe --remove-current-user-setup as the current user " +
        "before removing hardened code."
    )
}
if (-not $DryRun.IsPresent -and -not $testOverride) {
    Invoke-SelfElevated
    Write-ElevationLog 'STARTED' 'Elevated Container code placement started.'
}

if ($Uninstall.IsPresent) {
    if ($DryRun.IsPresent) {
        Write-Output "uninstall_status=DRY_RUN_CODE_ONLY"
        Write-Output "user_state_preserved=true"
        exit 0
    }
    [void](Get-StrictFullPath $installRootFull "uninstall target")
    Assert-NoReparsePoint $installRootFull "Container_Audit code root"
    if (-not $testOverride) {
        Remove-OwnedLegacyTask $LegacyQualificationTaskName $installRootFull
        Remove-OwnedLegacyTask $LegacyRelayTaskName $installRootFull
    }
    if (Test-Path -LiteralPath $installRootFull) {
        Remove-Item -LiteralPath $installRootFull -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $installRootFull) {
        throw "Hardened code root removal postcondition failed."
    }
    Write-Output "uninstall_status=PASS_CODE_REMOVED_STATE_PRESERVED"
    Write-Output "application_root_status=ABSENT"
    Write-Output "system_task_status=ABSENT"
    Write-Output "user_state_preserved=true"
    Write-Output "current_user_setup_removal_command=Container_Audit.exe --remove-current-user-setup"
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
