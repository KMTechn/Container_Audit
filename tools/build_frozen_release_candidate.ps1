[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+$')]
    [string]$Tag,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [Parameter(Mandatory = $true)]
    [string]$MirrorRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$factoryContractSha256 = "adaa08684ebb291837327f63f967a4f22650dff72c4c1dc56ce1a9bee6b5404a"
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..")).TrimEnd([char[]]"\/")
$candidateRoot = [IO.Path]::GetFullPath($OutputRoot)
$approvedStorageRoot = [IO.Path]::GetFullPath("E:\KMTech").TrimEnd('\') + '\'
$distRoot = Join-Path $candidateRoot "dist"
$packageRoot = Join-Path $distRoot "Container_Audit"
$pyinstallerRoot = Join-Path $candidateRoot "pyinstaller"
$zipPath = Join-Path $candidateRoot "Container_Audit-$Tag.zip"
$checksumPath = "$zipPath.sha256"
$smokeRoot = Join-Path $candidateRoot "smoke"
$identityRoot = Join-Path $repositoryRoot "build/factory_contract_identity"
$releaseConfigRoot = Join-Path $repositoryRoot "build/release_config"
$releaseToolsRoot = Join-Path $repositoryRoot "build/release_tools"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Failure
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $Failure
    }
}

function Get-GitValue {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $value = (& git @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Git command failed: git $($Arguments -join ' ')"
    }
    # Native commands with no stdout produce $null under PowerShell 7.  Cast to
    # a string array before joining so a clean `git status --porcelain` is the
    # exact empty string instead of a null-method failure.
    return (([string[]]$value) -join "`n").Trim()
}

function Get-GitValueAt {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $value = (& git -C $Repository @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Git command failed in $Repository`: git $($Arguments -join ' ')"
    }
    return (([string[]]$value) -join "`n").Trim()
}

function Get-NormalizedLocalOriginPath {
    param([Parameter(Mandatory = $true)][string]$RemoteUrl)
    if ($RemoteUrl.StartsWith("file://", [StringComparison]::OrdinalIgnoreCase)) {
        return [IO.Path]::GetFullPath(([Uri]$RemoteUrl).LocalPath).TrimEnd([char[]]"\/")
    }
    if (-not [IO.Path]::IsPathRooted($RemoteUrl)) {
        throw "Prepared clone origin must be an absolute local path or file URI."
    }
    return [IO.Path]::GetFullPath($RemoteUrl).TrimEnd([char[]]"\/")
}

function Write-NewUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (Test-Path -LiteralPath $Path) {
        throw "Create-once evidence path already exists: $Path"
    }
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "Use PowerShell 7 or later (pwsh) for the frozen release builder."
}
$mirrorRoot = [IO.Path]::GetFullPath($MirrorRoot).TrimEnd([char[]]"\/")
if (-not (Test-Path -LiteralPath $mirrorRoot -PathType Container)) {
    throw "MirrorRoot must be an existing prepared local bare mirror."
}
if ($repositoryRoot -ceq $mirrorRoot) {
    throw "The release work clone and local bare mirror must be isolated paths."
}
if (-not $candidateRoot.StartsWith($approvedStorageRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputRoot must be a task-specific fresh path below E:\KMTech."
}
foreach ($sourceRoot in @($repositoryRoot, $mirrorRoot)) {
    $sourcePrefix = $sourceRoot.TrimEnd([char[]]"\/") + [IO.Path]::DirectorySeparatorChar
    if ($candidateRoot.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputRoot must be outside the prepared mirror and release work clone."
    }
}
if (Test-Path -LiteralPath $candidateRoot) {
    throw "OutputRoot must be a fresh absent path: $candidateRoot"
}
foreach ($generatedInput in @($identityRoot, $releaseConfigRoot, $releaseToolsRoot)) {
    if (Test-Path -LiteralPath $generatedInput) {
        throw "Generated build input must be absent before the one-shot build: $generatedInput"
    }
}

Push-Location $repositoryRoot
try {
    if ((Get-GitValue -Arguments @("rev-parse", "--is-inside-work-tree")) -cne "true") {
        throw "The builder must run from a non-bare isolated release work clone."
    }
    $worktreeTop = [IO.Path]::GetFullPath(
        (Get-GitValue -Arguments @("rev-parse", "--show-toplevel"))
    ).TrimEnd([char[]]"\/")
    if ($worktreeTop -cne $repositoryRoot) {
        throw "The builder script must belong to the isolated release work clone root."
    }
    if ((Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--is-bare-repository")) -cne "true") {
        throw "MirrorRoot must be a bare Git repository."
    }
    $status = Get-GitValue -Arguments @("status", "--porcelain=v1", "--untracked-files=all")
    if (-not [string]::IsNullOrEmpty($status)) {
        throw "Isolated release work clone must be clean before the one-shot build."
    }
    $originUrl = Get-GitValue -Arguments @("remote", "get-url", "origin")
    $localOriginPath = Get-NormalizedLocalOriginPath -RemoteUrl $originUrl
    if ($localOriginPath -cne $mirrorRoot) {
        throw "Prepared release work clone origin must be the exact supplied local bare mirror."
    }
    if ((Get-GitValue -Arguments @("symbolic-ref", "--quiet", "HEAD")) -cne "refs/heads/main") {
        throw "Prepared release work clone must have exact local main checked out."
    }
    $sourceCommit = (Get-GitValue -Arguments @("rev-parse", "--verify", "HEAD^{commit}")).ToLowerInvariant()
    $sourceTree = (Get-GitValue -Arguments @("rev-parse", "--verify", "HEAD^{tree}")).ToLowerInvariant()
    $localMain = (Get-GitValue -Arguments @("rev-parse", "--verify", "refs/heads/main^{commit}")).ToLowerInvariant()
    $mirrorTrackingMain = (Get-GitValue -Arguments @("rev-parse", "--verify", "refs/remotes/origin/main^{commit}")).ToLowerInvariant()
    $mirrorMain = (Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--verify", "refs/heads/main^{commit}")).ToLowerInvariant()
    if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $sourceTree -cnotmatch '^[0-9a-f]{40}$') {
        throw "Source commit/tree identity is malformed."
    }
    if (
        $sourceCommit -cne $localMain -or
        $sourceCommit -cne $mirrorTrackingMain -or
        $sourceCommit -cne $mirrorMain
    ) {
        throw "HEAD, local main, origin/main, and local bare mirror main must be the exact candidate commit."
    }
    $tagRef = "refs/tags/$Tag"
    $tagObject = (Get-GitValue -Arguments @("rev-parse", "--verify", $tagRef)).ToLowerInvariant()
    $mirrorTagObject = (Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--verify", $tagRef)).ToLowerInvariant()
    if ($tagObject -cnotmatch '^[0-9a-f]{40}$' -or $tagObject -cne $mirrorTagObject) {
        throw "Prepared clone and local mirror must contain the exact same FINAL intended tag object."
    }
    if (
        (Get-GitValue -Arguments @("cat-file", "-t", $tagRef)) -cne "tag" -or
        (Get-GitValueAt -Repository $mirrorRoot -Arguments @("cat-file", "-t", $tagRef)) -cne "tag"
    ) {
        throw "The FINAL intended release ref must be an annotated tag object in clone and mirror."
    }
    $tagPeel = (Get-GitValue -Arguments @("rev-parse", "--verify", "$tagRef^{commit}")).ToLowerInvariant()
    $mirrorTagPeel = (Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--verify", "$tagRef^{commit}")).ToLowerInvariant()
    if ($tagPeel -cne $sourceCommit -or $mirrorTagPeel -cne $sourceCommit) {
        throw "The FINAL intended tag must peel to exact HEAD and local mirror main."
    }

    Invoke-Checked -FilePath "python" -Arguments @(
        "tools/check_release_version.py", "--tag", $Tag
    ) -Failure "Application version does not match the requested candidate tag."
    Invoke-Checked -FilePath "python" -Arguments @(
        "-c",
        "import importlib.metadata as m; assert m.version('pyinstaller') == '6.20.0', m.version('pyinstaller')"
    ) -Failure "The prepared builder must provide exactly PyInstaller 6.20.0."
    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "pip", "check"
    ) -Failure "The prepared Python environment has dependency conflicts."

    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    [IO.Directory]::CreateDirectory($distRoot) | Out-Null
    [IO.Directory]::CreateDirectory($pyinstallerRoot) | Out-Null
    [IO.Directory]::CreateDirectory($identityRoot) | Out-Null
    [IO.Directory]::CreateDirectory($releaseConfigRoot) | Out-Null
    [IO.Directory]::CreateDirectory($releaseToolsRoot) | Out-Null
    $tagIdentityJson = python tools/read_release_qualification_tag.py `
        --repository . --tag-ref $tagRef --expected-tag $Tag
    if ($LASTEXITCODE -ne 0) {
        throw "Canonical FINAL intended annotated tag parsing failed before release-mode build."
    }
    $tagIdentity = ConvertFrom-Json -InputObject ($tagIdentityJson -join "`n")
    if (
        $tagIdentity.tag_object_sha -cne $tagObject -or
        $tagIdentity.peeled_commit_sha -cne $sourceCommit -or
        $tagIdentity.message -cne "Release $Tag"
    ) {
        throw "Canonical tag parser disagrees with the prebound FINAL intended identity."
    }
    $releaseIdentity = [ordered]@{
        schema_version = "container-audit-final-release-identity-v1"
        tag = $Tag
        tag_object_sha = $tagObject
        peeled_commit_sha = $sourceCommit
        source_tree = $sourceTree
        local_main = $localMain
        clone_origin_main = $mirrorTrackingMain
        local_mirror_main = $mirrorMain
    }
    Write-NewUtf8File `
        -Path (Join-Path $candidateRoot "FINAL_RELEASE_IDENTITY.json") `
        -Text (($releaseIdentity | ConvertTo-Json -Depth 3) + "`n")
    $env:SOURCE_DATE_EPOCH = Get-GitValue -Arguments @("show", "-s", "--format=%ct", "HEAD")

    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "kmtech_factory_contracts.build_cli", "prepare",
        "--repository", ".",
        "--stage-root", $identityRoot,
        "--app-id", "container_audit",
        "--app-version", $Tag,
        "--db-schema-current", "0"
    ) -Failure "Factory compatibility identity preparation failed."

    $settings = Get-Content -Raw -Encoding UTF8 `
        -LiteralPath "config/container_audit_settings.json" | ConvertFrom-Json
    $settings | Add-Member -NotePropertyName "update_settings" -NotePropertyValue ([pscustomobject]@{
        provider = "github"
        channel = "stable"
    }) -Force
    $settingsJson = $settings | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText(
        (Join-Path $releaseConfigRoot "container_audit_settings.json"),
        $settingsJson + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    Invoke-Checked -FilePath "python" -Arguments @(
        "tools/check_release_config.py", "--config-dir", $releaseConfigRoot
    ) -Failure "Release-visible configuration validation failed."

    foreach ($relativeTool in @(
        "direct_sync_relay_runner.py",
        "direct_sync_relay_install_pack.py",
        "direct_sync_relay_operator.py",
        "register_container_audit_worker_pc.py",
        "install_logistics_runtime_profile.py",
        "check_logistics_runtime_profile.py"
    )) {
        Copy-Item -LiteralPath (Join-Path "tools" $relativeTool) `
            -Destination (Join-Path $releaseToolsRoot $relativeTool)
    }

    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "PyInstaller", "--clean", "--noconfirm",
        "--distpath", $distRoot,
        "--workpath", (Join-Path $pyinstallerRoot "main"),
        "Container_Audit.spec"
    ) -Failure "Main Container_Audit PyInstaller build failed."

    $oneFileTools = @(
        @("Container_Audit_DirectSync_Relay", "tools/direct_sync_relay_runner.py"),
        @("Container_Audit_DirectSync_Install", "tools/direct_sync_relay_install_pack.py"),
        @("Container_Audit_Worker_PC_Register", "tools/register_container_audit_worker_pc.py"),
        @("Container_Audit_Protected_Admin_Install", "tools/install_protected_admin.py"),
        @("KMTech_Logistics_Profile_Install", "tools/install_logistics_runtime_profile.py"),
        @("KMTech_Logistics_Profile_Check", "tools/check_logistics_runtime_profile.py")
    )
    foreach ($tool in $oneFileTools) {
        $toolName = $tool[0]
        $toolSource = $tool[1]
        Invoke-Checked -FilePath "python" -Arguments @(
            "-m", "PyInstaller", "--paths", ".", "--name", $toolName,
            "--onefile", "--console", "--clean", "--noconfirm",
            "--distpath", $packageRoot,
            "--workpath", (Join-Path $pyinstallerRoot $toolName),
            "--specpath", (Join-Path $pyinstallerRoot $toolName),
            $toolSource
        ) -Failure "Bundled release tool build failed: $toolName"
    }

    Copy-Item -LiteralPath "tools/provision_protected_admin_acl.ps1" `
        -Destination (Join-Path $packageRoot "PROVISION_PROTECTED_ADMIN_ACL.ps1")
    Copy-Item -LiteralPath "docs/PROTECTED_ADMIN_PROVISIONING.md" `
        -Destination (Join-Path $packageRoot "PROTECTED_ADMIN_PROVISIONING.md")
    Copy-Item -LiteralPath "docs/LOGISTICS_RUNTIME_PROFILE.md" `
        -Destination (Join-Path $packageRoot "CENTRAL_LOGISTICS_PC_ROLLOUT.md")
    Copy-Item -LiteralPath "INSTALL_THIS_PC.ps1" `
        -Destination (Join-Path $packageRoot "INSTALL_THIS_PC.ps1")

    Invoke-Checked -FilePath (Join-Path $packageRoot "Container_Audit_Protected_Admin_Install.exe") `
        -Arguments @("--help") -Failure "Protected administrator installer help probe failed."
    Invoke-Checked -FilePath (Join-Path $packageRoot "Container_Audit_Protected_Admin_Install.exe") `
        -Arguments @("--dry-run") -Failure "Protected administrator installer dry-run failed."
    Invoke-Checked -FilePath "powershell.exe" -Arguments @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $packageRoot "PROVISION_PROTECTED_ADMIN_ACL.ps1"), "-DryRun"
    ) -Failure "Protected administrator ACL wrapper dry-run failed."

    $probeBundleSource = [IO.Path]::GetFullPath((Join-Path $repositoryRoot "kmtech_factory_contracts/bundle"))
    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "PyInstaller", "--paths", ".", "--name", "KMTechActiveWorkProbe",
        "--onefile", "--console", "--distpath", $packageRoot,
        "--workpath", (Join-Path $pyinstallerRoot "active_work_probe"),
        "--specpath", (Join-Path $pyinstallerRoot "active_work_probe"),
        "--add-data", "$probeBundleSource;kmtech_factory_contracts/bundle",
        "--collect-submodules", "kmtech_factory_contracts.active_work_probe",
        "--clean", "--noupx", "--noconfirm", "tools/active_work_probe.py"
    ) -Failure "Active-work probe PyInstaller build failed."

    $probePath = Join-Path $packageRoot "KMTechActiveWorkProbe.exe"
    $probeSha256 = (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $independentIdentity = Join-Path $packageRoot "KMTechActiveWorkProbe.independent.build-identity.json"
    $integratedIdentity = Join-Path $packageRoot "KMTechActiveWorkProbe.integrated.build-identity.json"
    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "kmtech_factory_contracts.active_work_probe",
        "-Mode", "build-identity", "-OutputPath", $independentIdentity,
        "-ProbeArtifactPath", $probePath, "-ProbeSourceCommit", $sourceCommit,
        "-WorkflowMode", "independent", "-SupportedApps", "Container_Audit",
        "-ProbeName", "KMTechActiveWorkProbe", "-ProbeVersion", "v1.0.3.4"
    ) -Failure "Independent active-work probe identity generation failed."
    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "kmtech_factory_contracts.active_work_probe",
        "-Mode", "build-identity", "-OutputPath", $integratedIdentity,
        "-ProbeArtifactPath", $probePath, "-ProbeSourceCommit", $sourceCommit,
        "-WorkflowMode", "integrated",
        "-SupportedApps", "Inspection_worker,Rework_worker,Defect_Inspection,Container_Audit,Label_Match",
        "-ProbeName", "KMTechActiveWorkProbe", "-ProbeVersion", "v1.0.3.4"
    ) -Failure "Integrated active-work probe identity generation failed."
    Invoke-Checked -FilePath $probePath -Arguments @("--help") `
        -Failure "Packaged active-work probe help smoke failed."
    $probeSmokeRoot = Join-Path $candidateRoot "probe-identity-smoke"
    [IO.Directory]::CreateDirectory($probeSmokeRoot) | Out-Null
    $packagedIndependentIdentity = Join-Path $probeSmokeRoot "KMTechActiveWorkProbe.independent.build-identity.json"
    $packagedIntegratedIdentity = Join-Path $probeSmokeRoot "KMTechActiveWorkProbe.integrated.build-identity.json"
    Invoke-Checked -FilePath $probePath -Arguments @(
        "-Mode", "build-identity", "-OutputPath", $packagedIndependentIdentity,
        "-ProbeArtifactPath", $probePath, "-ProbeSourceCommit", $sourceCommit,
        "-WorkflowMode", "independent", "-SupportedApps", "Container_Audit",
        "-ProbeName", "KMTechActiveWorkProbe", "-ProbeVersion", "v1.0.3.4"
    ) -Failure "Packaged independent active-work probe identity generation failed."
    Invoke-Checked -FilePath $probePath -Arguments @(
        "-Mode", "build-identity", "-OutputPath", $packagedIntegratedIdentity,
        "-ProbeArtifactPath", $probePath, "-ProbeSourceCommit", $sourceCommit,
        "-WorkflowMode", "integrated",
        "-SupportedApps", "Inspection_worker,Rework_worker,Defect_Inspection,Container_Audit,Label_Match",
        "-ProbeName", "KMTechActiveWorkProbe", "-ProbeVersion", "v1.0.3.4"
    ) -Failure "Packaged integrated active-work probe identity generation failed."
    foreach ($identityPair in @(
        @($independentIdentity, $packagedIndependentIdentity),
        @($integratedIdentity, $packagedIntegratedIdentity)
    )) {
        $sourceIdentityHash = (Get-FileHash -LiteralPath $identityPair[0] -Algorithm SHA256).Hash
        $packagedIdentityHash = (Get-FileHash -LiteralPath $identityPair[1] -Algorithm SHA256).Hash
        if ($sourceIdentityHash -cne $packagedIdentityHash) {
            throw "Source and packaged active-work probe identities differ."
        }
    }

    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "kmtech_factory_contracts.build_cli", "manifest",
        "--stage-root", $packageRoot,
        "--expected-file", "Container_Audit.exe",
        "--expected-file", "KMTechActiveWorkProbe.exe",
        "--expected-file", "KMTechActiveWorkProbe.independent.build-identity.json",
        "--expected-file", "KMTechActiveWorkProbe.integrated.build-identity.json",
        "--expected-file", "contract.lock.json",
        "--expected-file", "build-identity.json",
        "--expected-file", "build-compatibility.json"
    ) -Failure "Factory package manifest sealing failed."
    Invoke-Checked -FilePath "python" -Arguments @(
        "-m", "kmtech_factory_contracts.build_cli", "verify",
        "--stage-root", $packageRoot,
        "--expected-contract-sha256", $factoryContractSha256
    ) -Failure "Sealed factory package verification failed."

    Compress-Archive -LiteralPath $packageRoot -DestinationPath $zipPath -CompressionLevel Optimal
    if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
        throw "Frozen candidate ZIP was not created."
    }
    Invoke-Checked -FilePath "python" -Arguments @(
        "tools/check_update_archive.py",
        "--zip-path", $zipPath,
        "--destination", $smokeRoot,
        "--package-root", $packageRoot
    ) -Failure "Frozen candidate archive smoke verification failed."
    Invoke-Checked -FilePath "python" -Arguments @(
        "-I", (Join-Path $smokeRoot "Container_Audit/tools/direct_sync_relay_runner.py"), "--help"
    ) -Failure "Staged direct-sync relay source help probe failed."
    Invoke-Checked -FilePath "python" -Arguments @(
        "-I", (Join-Path $smokeRoot "Container_Audit/tools/direct_sync_relay_operator.py"), "--help"
    ) -Failure "Staged direct-sync operator source help probe failed."
    Invoke-Checked -FilePath "python" -Arguments @(
        "tools/check_release_config.py",
        "--config-dir", (Join-Path $smokeRoot "Container_Audit/config")
    ) -Failure "Extracted release configuration validation failed."

    $zipInfo = Get-Item -LiteralPath $zipPath
    $zipSha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $mainExeSha256 = (Get-FileHash -LiteralPath (Join-Path $packageRoot "Container_Audit.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksumPath,
        "$zipSha256  $([IO.Path]::GetFileName($zipPath))`n",
        [Text.ASCIIEncoding]::new()
    )
    $postBuildStatus = Get-GitValue -Arguments @("status", "--porcelain=v1", "--untracked-files=all")
    if (-not [string]::IsNullOrEmpty($postBuildStatus)) {
        throw "Isolated release work clone changed during the one-shot candidate build."
    }
    if (
        (Get-GitValue -Arguments @("rev-parse", "--verify", "HEAD^{commit}")).ToLowerInvariant() -cne $sourceCommit -or
        (Get-GitValue -Arguments @("rev-parse", "--verify", "HEAD^{tree}")).ToLowerInvariant() -cne $sourceTree -or
        (Get-GitValue -Arguments @("rev-parse", "--verify", "refs/heads/main^{commit}")).ToLowerInvariant() -cne $sourceCommit -or
        (Get-GitValue -Arguments @("rev-parse", "--verify", "refs/remotes/origin/main^{commit}")).ToLowerInvariant() -cne $sourceCommit -or
        (Get-GitValue -Arguments @("cat-file", "-t", $tagRef)) -cne "tag" -or
        (Get-GitValue -Arguments @("rev-parse", "--verify", $tagRef)).ToLowerInvariant() -cne $tagObject -or
        (Get-GitValue -Arguments @("rev-parse", "--verify", "$tagRef^{commit}")).ToLowerInvariant() -cne $sourceCommit -or
        (Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--verify", "refs/heads/main^{commit}")).ToLowerInvariant() -cne $sourceCommit -or
        (Get-GitValueAt -Repository $mirrorRoot -Arguments @("cat-file", "-t", $tagRef)) -cne "tag" -or
        (Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--verify", $tagRef)).ToLowerInvariant() -cne $tagObject -or
        (Get-GitValueAt -Repository $mirrorRoot -Arguments @("rev-parse", "--verify", "$tagRef^{commit}")).ToLowerInvariant() -cne $sourceCommit
    ) {
        throw "FINAL tag object/type/peel, HEAD, tree, or local mirror main changed during the candidate build."
    }
    $receipt = [ordered]@{
        schema_version = "container-audit-local-artifact-qualification-v1"
        status = "LOCAL_ARTIFACT_QUALIFICATION_PASS"
        tag = $Tag
        tag_object_sha = $tagObject
        source_commit = $sourceCommit
        source_tree = $sourceTree
        local_mirror_main = $mirrorMain
        clone_origin_main = $mirrorTrackingMain
        factory_contract_sha256 = $factoryContractSha256
        zip_name = [IO.Path]::GetFileName($zipPath)
        zip_sha256 = $zipSha256
        zip_size = $zipInfo.Length
        main_exe_sha256 = $mainExeSha256
        probe_sha256 = $probeSha256
    }
    $receiptJson = $receipt | ConvertTo-Json -Depth 5
    Write-NewUtf8File `
        -Path (Join-Path $candidateRoot "local-artifact-qualification-receipt.json") `
        -Text ($receiptJson + "`n")
    Write-Output "frozen_candidate_build=LOCAL_ARTIFACT_QUALIFICATION_PASS"
    Write-Output "candidate_root=$candidateRoot"
    Write-Output "final_intended_tag=$Tag object=$tagObject peel=$sourceCommit"
    Write-Output "zip_sha256=$zipSha256 zip_size=$($zipInfo.Length) main_exe_sha256=$mainExeSha256"
    Write-Output "NEXT: preserve these exact bytes and receipt, complete installation qualification, then push main and satisfy the external immutable-policy and zero-nonterminal-workflow gates before publishing this unchanged tag object; hosted CI is WAIVED_NOT_TESTED as a release gate."
}
catch {
    Write-Error "frozen_candidate_build=FAILED reason=$($_.Exception.Message)"
    Write-Error "No candidate is qualified. Never delete, recreate, or move the prepared FINAL intended tag object; use a new patch version after a failed build."
    throw
}
finally {
    Pop-Location
}
