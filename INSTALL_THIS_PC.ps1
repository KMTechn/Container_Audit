[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\KMTech\Apps\Container_Audit\current",
    [string]$TlsCaBundlePath = "",
    [string]$OperatorLocalAppDataRoot = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$ApplyHardenedAclForTest
)

$ErrorActionPreference = "Stop"
$ExpectedInstallRoot = "C:\KMTech\Apps\Container_Audit\current"
. (Join-Path $PSScriptRoot "tools\bootstrap_integrity.ps1")
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
        'launch-container-audit.cmd'
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
        @($manifest.allowed_unsigned_app_pe).Count -ne 0 -or
        @($manifest.forbidden_dependency_paths).Count -ne 0
    ) {
        throw "Portable release manifest contract is invalid."
    }
    $pythonwPath = Join-Path $Root 'runtime\pythonw.exe'
    $launcherPath = Join-Path $Root 'launch-container-audit.cmd'
    if (
        (Get-FileSha256 $pythonwPath) -cne
            ([string]$manifest.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Get-FileSha256 $launcherPath) -cne
            ([string]$manifest.launcher_sha256).ToLowerInvariant()
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

function Remove-OwnedLegacyTask([string]$Name, [string]$ExpectedRoot) {
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }
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
    Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop
    if ($null -ne (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)) {
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
$applyHardenedAcl = (-not $testOverride -or $ApplyHardenedAclForTest.IsPresent)
$aclReadbackStatus = if ($applyHardenedAcl) { 'UNKNOWN' } else { 'NOT_TESTED' }
$installRootFull = Get-StrictFullPath $InstallRoot "InstallRoot"
if (-not (Test-SamePath $installRootFull $ExpectedInstallRoot) -and -not $testOverride) {
    throw "InstallRoot must be the hardened Container_Audit code root."
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
            throw "A different or damaged hardened code placement exists; remove it explicitly before replacement."
        }
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        $bootstrapStatus = 'REUSED'
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
}
catch {
    if (Test-Path -LiteralPath $stagingRoot) {
        $stagingFull = Get-StrictFullPath $stagingRoot "bootstrap staging root"
        $parentFull = (Get-StrictFullPath $applicationParent "application parent") + '\'
        if (-not $stagingFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Bootstrap failed and staging cleanup target escaped its parent."
        }
        Remove-Item -LiteralPath $stagingFull -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
}
