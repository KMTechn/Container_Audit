[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [ValidateSet('Apply','Observe','Verify','Authority')][string]$Mode = 'Apply',
    [string]$CodeRoot = ''
)
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$ErrorActionPreference = 'Stop'
$script:StartupUpdateBootstrapLoaded=$false
# Pure bootstrap copy: the path must be admitted before that library is loaded.
function Test-BootstrapPrivilegedOwnerSid([string]$Sid) {
    return $Sid -cin @(
        'S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
}

function Assert-Protected([string]$Path, [switch]$Recursive, [hashtable]$Verified = $null) {
    if ($null -eq $Verified) { $Verified = @{} }
    $full = [IO.Path]::GetFullPath($Path)
    $leaf = $true
    while ($full) {
        if (-not $Verified.ContainsKey($full) -or ($leaf -and -not $Verified[$full])) {
        $entry = Get-Item -Force -LiteralPath $full -ErrorAction Stop
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in update storage.' }
        $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if (-not (Test-BootstrapPrivilegedOwnerSid $owner)) { throw 'Update storage owner is not privileged.' }
        if($script:StartupUpdateBootstrapLoaded -and $full -in @('C:\KMTech','C:\KMTech\Apps')){
            try{Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit' -AdmissionOnly -ProtectedAncestor $full}
            catch{
                $code=[int]$_.Exception.Data['installation_preparation_exit_code']
                if($code -notin @(61,62,63)){throw}
                $message=switch($code){62{'Reparse point in update storage.'}63{'Update storage owner is not privileged.'}61{'Update storage is user mutable.'}}
                throw [InvalidOperationException]::new($message,$_.Exception)
            }
            $Verified[$full]=$leaf
            $full=[IO.Path]::GetDirectoryName($full);$leaf=$false;continue
        }
        $mask = if ($leaf) { 0x500D0156 } else { 0x500D0150 }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and
                -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and
                ([int64]$rule.FileSystemRights -band $mask)) { throw 'Update storage is user mutable.' }
        }
        $Verified[$full] = $leaf
        }
        if ($full -eq [IO.Path]::GetPathRoot($full)) { break }
        $full = [IO.Path]::GetDirectoryName($full)
        $leaf = $false
    }
    if ($Recursive) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
            # Reject redirected children before enumerating their contents.
            Assert-Protected $child.FullName -Recursive:($child.PSIsContainer) -Verified $Verified
        }
    }
}
# Validate every executable and data dependency before loading another helper.
$trustedBootstrap = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$trustedApplication = Split-Path -Parent $trustedBootstrap
Assert-Protected $trustedApplication
Assert-Protected $trustedBootstrap -Recursive
Assert-Protected $PSCommandPath
foreach ($directory in @('update-control','versions')) {
    $trustedDirectory = Join-Path $trustedApplication $directory
    if (Test-Path -LiteralPath $trustedDirectory) { Assert-Protected $trustedDirectory -Recursive }
}
$IntegrityHelper = Join-Path $PSScriptRoot 'bootstrap_integrity.ps1'
. $IntegrityHelper
$script:StartupUpdateBootstrapLoaded=$true
# The first pass must validate code before any helper load. Once the validated
# shared library is available, require its exact shared-ancestor target shape.
Assert-Protected $trustedApplication
$SharedLeaf = Get-BootstrapSharedPortableLeaf $InstallRoot
. $SharedLeaf

function Enter-ContainerStartupUpdateAuthority {
    $root = Get-StrictFullPath $InstallRoot 'startup update bootstrap'
    Assert-BootstrapNoReparsePoint $root 'startup update bootstrap'
    if (-not (Test-BootstrapSamePath $PSScriptRoot (Join-Path $root 'tools'))) {
        throw 'STARTUP_UPDATE_FIXED_BOOTSTRAP_REQUIRED'
    }
    [void](Assert-BootstrapIntegrityRecord $root)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($Mode -cne 'Observe' -and $sid -cne 'S-1-5-18') { throw 'STARTUP_UPDATE_SYSTEM_REQUIRED' }
    $policyPath = Join-Path (Split-Path -Parent $root) 'update-control\policy.json'
    Assert-BootstrapNoReparsePoint $policyPath 'startup update policy'
    if ((Get-Item -LiteralPath $policyPath).Length -gt 65536) { throw 'STARTUP_UPDATE_POLICY_OVERSIZED' }
    $policy = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($Mode -ceq 'Observe' -and $sid -cne 'S-1-5-18' -and $sid -cne [string]$policy.operator_sid) {
        throw 'STARTUP_UPDATE_OPERATOR_DIFFERS'
    }
    return [pscustomobject]@{ root=$root; policy=$policy }
}

function Get-StartupUpdateProcesses([string]$Root) {
    # Query only app-related rows; do not log other applications' command lines.
    if (-not ('KMTechStartupUpdateToken' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KMTechStartupUpdateToken {
 [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint rights, bool inherit, uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint rights, out IntPtr token);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int size, out int needed);
 [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
 [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
 public static bool Ordinary(uint pid) {
  IntPtr process=OpenProcess(0x1000,false,pid), token=IntPtr.Zero, data=IntPtr.Zero;
  if(process==IntPtr.Zero) throw new Exception("process token cannot be observed");
  try {
   if(!OpenProcessToken(process,8,out token)) throw new Exception("process token cannot be observed");
   int needed; data=Marshal.AllocHGlobal(4);
   if(!GetTokenInformation(token,20,data,4,out needed)) throw new Exception("process elevation cannot be observed");
   if(Marshal.ReadInt32(data)!=0) return false;
   Marshal.FreeHGlobal(data); data=IntPtr.Zero;
   GetTokenInformation(token,25,IntPtr.Zero,0,out needed); data=Marshal.AllocHGlobal(needed);
   if(!GetTokenInformation(token,25,data,needed,out needed)) throw new Exception("process integrity cannot be observed");
   IntPtr sid=Marshal.ReadIntPtr(data); byte count=Marshal.ReadByte(GetSidSubAuthorityCount(sid));
   if(count==0) throw new Exception("process integrity is malformed");
   int rid=Marshal.ReadInt32(GetSidSubAuthority(sid,(uint)(count-1)));
   return rid>=0x2000 && rid<0x3000;
  } finally { if(data!=IntPtr.Zero) Marshal.FreeHGlobal(data); if(token!=IntPtr.Zero) CloseHandle(token); CloseHandle(process); }
 }
}
'@
    }
    $managed = Split-Path -Parent $Root
    $rows = @()
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $image = [string]$process.ExecutablePath
        if (-not $image -and [string]$process.Name -match '^(pythonw?|Container_Audit)\.exe$') {
            # Exit races are common at logon; re-read the PID before declaring UNKNOWN.
            $process = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $process.ProcessId) -ErrorAction Stop
            if ($null -eq $process) { continue }
            $image = [string]$process.ExecutablePath
            if (-not $image) {
                Start-Sleep -Milliseconds 100
                $process = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $process.ProcessId) -ErrorAction Stop
                if ($null -eq $process) { continue }
                $image = [string]$process.ExecutablePath
            }
        }
        if (-not $image) {
            if ([string]$process.Name -match '^(pythonw?|Container_Audit)\.exe$') {
                # Only a proven different owner can remove this ambiguous candidate.
                # Missing/failed owner observations continue to block replacement.
                try {
                    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
                    if ($owner.ReturnValue -eq 0 -and $owner.Sid -and $authority.policy.operator_sid -and
                        [string]$owner.Sid -cne [string]$authority.policy.operator_sid) { continue }
                } catch { }
                $rows += @{pid=[int]$process.ProcessId;observable=$false;bootstrap=$false}
            }
            continue
        }
        $insideManaged = Test-BootstrapProcessRootPrefix $image $managed
        $bundle = Split-Path -Parent (Split-Path -Parent $image)
        $command = [string]$process.CommandLine
        if (-not $insideManaged) {
            if ([string]$process.Name -ceq 'Container_Audit.exe' -or $command -match 'Container_Audit\.py(?:"|\s|$)') {
                $rows += @{pid=[int]$process.ProcessId;observable=$false;bootstrap=$false}
                continue
            }
            if ([string]$process.Name -notmatch '^pythonw?\.exe$' -or (Split-Path -Leaf (Split-Path -Parent $image)) -ine 'runtime') { continue }
            $outsideManifest = Join-Path $bundle 'portable-manifest.json'
            if (-not (Test-Path -LiteralPath $outsideManifest -PathType Leaf)) { continue }
            try {
                Assert-BootstrapNoReparsePoint $outsideManifest 'possible prior packet manifest'
                if ((Get-Item -LiteralPath $outsideManifest).Length -gt 65536) { throw 'prior packet manifest oversized' }
                $outside = Get-Content -LiteralPath $outsideManifest -Raw -Encoding UTF8 | ConvertFrom-Json
                if ([string]$outside.schema -cne 'container-audit-portable-tree-v1') { continue }
            } catch {
                $rows += @{pid=[int]$process.ProcessId;observable=$false;bootstrap=$false}
                continue
            }
        }
        $bootstrapPattern = '^\s*"?' + [regex]::Escape((Join-Path $Root 'runtime\pythonw.exe')) + '"?\s+-I\s+-B\s+"?' + [regex]::Escape((Join-Path $Root 'app\auto_update.py')) + '"?\s+--bootstrap(?:\s|$)'
        $bootstrap = $insideManaged -and ($command -match $bootstrapPattern)
        if ($bootstrap) { continue }
        try {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
            if ($owner.ReturnValue -ne 0 -or -not $owner.Sid) { throw 'owner is unobservable' }
            $manifest = Get-Content -LiteralPath (Join-Path $bundle 'portable-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $role = 'writer'
            if ($command -match '--container-audit-user-relay(?:\s|$)') { $role='relay' }
            elseif ($command -match ([regex]::Escape((Join-Path $bundle 'app\main.py')) + '"?(?:\s|$)') -and $command -notmatch '--[a-z-]+') { $role='gui' }
            # A GUI's original data-root/geometry options are also supported.
            elseif ($command -match ([regex]::Escape((Join-Path $bundle 'app\main.py')) + '"?(?:\s|$)') -and $command -notmatch '--container-audit-|--onboard-|--remove-|--restore-') { $role='gui' }
            $rows += @{
                pid=[int]$process.ProcessId;observable=$true;bootstrap=[bool]$bootstrap
                sha=[string]$manifest.source_commit;sid=[string]$owner.Sid;role=$role
                ordinary_user=[KMTechStartupUpdateToken]::Ordinary([uint32]$process.ProcessId)
                created_at=([datetime]$process.CreationDate).ToUniversalTime().ToString('o')
            }
        } catch { $rows += @{pid=[int]$process.ProcessId;observable=$false;bootstrap=$false} }
    }
    return ,$rows
}

function Assert-StartupUpdateVersion([string]$Root, [string]$Candidate) {
    $managed = Split-Path -Parent $Root
    $full = Get-StrictFullPath $Candidate 'startup update version'
    Assert-Protected $full -Recursive
    Assert-BootstrapNoReparsePoint $full 'startup update version'
    $versionPrefix = Join-Path $managed 'versions'
    $packetPrefix = Join-Path $managed 'update-control'
    if (-not $full.StartsWith($versionPrefix + '\',[StringComparison]::OrdinalIgnoreCase) -and
        -not $full.StartsWith($packetPrefix + '\packet-',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'STARTUP_UPDATE_VERSION_OUTSIDE_PROTECTED_ROOT'
    }
    Assert-KmtechPortableTree $full @('portable-manifest.json','runtime\python.exe','runtime\pythonw.exe','app\main.py')
    $manifest = Read-KmtechPortableManifest $full
    # New Container Audit screen (same pins as Inspection_worker 402d3b1a): an older zero-PE release lists no
    # unsigned PE; otherwise exactly these app-relative files, each byte-identical to the builder pin.
    $unsignedPe = @{
        'site-packages/_cffi_backend.cp312-win_amd64.pyd' = '9af5e4f68a41f26b726f2e9424f9d58a4f5666189f6a48be95f406b257102aec'
        'site-packages/clr_loader/ffi/dlls/amd64/ClrLoader.dll' = '07f62bcb1b70320f221ffb2cfc5ce6133815195f3e7cdb8d833222506188c2ac'
        'site-packages/pythonnet/runtime/Python.Runtime.dll' = '2ebd4492e28442ef1f1af587afe5b3a090c2ebfa220758ded4f1450f2a27f13a'
    }
    $listedPe = @(@($manifest.allowed_unsigned_app_pe) | ForEach-Object { [string]$_ })
    $unsignedPeOk = $listedPe.Count -eq 0 -or (
        $listedPe.Count -eq $unsignedPe.Count -and
        @($listedPe | Sort-Object -Unique -CaseSensitive).Count -eq $unsignedPe.Count -and
        @($listedPe | Where-Object {
            $_ -cin @($unsignedPe.Keys) -and
            (Test-Path -LiteralPath (Join-Path (Join-Path $full 'app') $_.Replace('/', '\')) -PathType Leaf) -and
            (Get-FileSha256 (Join-Path (Join-Path $full 'app') $_.Replace('/', '\'))) -ceq $unsignedPe[$_]
        }).Count -eq $unsignedPe.Count
    )
    if ([string]$manifest.schema -cne 'container-audit-portable-tree-v1' -or
        $manifest.startup_update_protocol -ne 1 -or
        [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.entrypoint -cne 'runtime/pythonw.exe app/main.py' -or
        (Get-FileSha256 (Join-Path $full 'runtime\pythonw.exe')) -cne [string]$manifest.runtime_pythonw_sha256 -or
        -not $unsignedPeOk -or @($manifest.forbidden_dependency_paths).Count -ne 0) {
        throw 'STARTUP_UPDATE_PORTABLE_MANIFEST_DIFFERS'
    }
    $pins = @{
        'launch-container-audit.cmd'='launcher_sha256'
        'INSTALL_CANONICAL_PORTABLE.ps1'='installer_sha256'
        'INSTALL_THIS_PC.ps1'='helper_sha256'
        'tools\bootstrap_integrity.ps1'='integrity_helper_sha256'
        'tools\container_writer_fence.ps1'='writer_fence_helper_sha256'
        'tools\container_writer_session.ps1'='writer_session_adapter_sha256'
        'tools\container_writer_session_contract.json'='writer_session_contract_sha256'
        'tools\container_writer_sink_inventory.json'='writer_sink_inventory_sha256'
        'tools\apply_prepared_update.ps1'='startup_update_helper_sha256'
        'app\update-manifest-key-config.json'='update_key_config_sha256'
    }
    foreach ($path in $pins.Keys) {
        if ((Get-FileSha256 (Join-Path $full $path)) -cne [string]$manifest.($pins[$path])) { throw 'STARTUP_UPDATE_FILE_PIN_DIFFERS' }
    }
    $inventory = Get-Content -LiteralPath (Join-Path $full 'tools\container_writer_sink_inventory.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$inventory.inventory_sha256 -cne [string]$manifest.writer_sink_inventory_contract_sha256 -or
        @($inventory.uncovered_direct_mutation_functions).Count -ne 0 -or
        @($inventory.caller_fence_reference_failures).Count -ne 0 -or
        @($inventory.powershell_guard_failures).Count -ne 0 -or
        @($inventory.known_route_coverage | Where-Object { $_.pass -isnot [bool] -or -not $_.pass }).Count -ne 0) {
        throw 'STARTUP_UPDATE_WRITER_INVENTORY_DIFFERS'
    }
    Assert-KmtechCPythonSignature $full $false
    if ($full.StartsWith($packetPrefix + '\packet-',[StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath (Join-Path $full 'bootstrap-integrity.json')) { throw 'STARTUP_UPDATE_PACKET_HAS_INSTALL_RECORD' }
        $finalIdentity = Join-Path $versionPrefix ([string]$manifest.source_commit)
        [void](Write-BootstrapIntegrityRecord -Root $full -CodeRootIdentity $finalIdentity)
    } elseif ((Split-Path -Leaf $full) -cne [string]$manifest.source_commit) {
        throw 'STARTUP_UPDATE_VERSION_DIRECTORY_DIFFERS'
    } elseif (Test-Path -LiteralPath (Join-Path $full 'bootstrap-integrity.json') -PathType Leaf) {
        [void](Assert-BootstrapIntegrityRecord $full)
    } else { throw 'STARTUP_UPDATE_PREVIOUS_RECORD_MISSING' }
}

function Get-StartupUpdatePublicFailure($Failure,[int]$ExitCode=1) {
    $exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    $fields=[ordered]@{status='FAILED';stage='startup_update';reason_code='STARTUP_UPDATE_FAILURE';
        exit_code=$ExitCode;exception_type=$exception.GetType().FullName;
        report_status='REPORT_UNAVAILABLE';guidance='기존 설치 상태와 예약 작업을 확인하고 관리자 지원 복구를 요청하세요.'}
    if($Failure -is [Management.Automation.ErrorRecord]){$fields.location_line=[int]$Failure.InvocationInfo.ScriptLineNumber}
    return ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes @('FAILED','startup_update','STARTUP_UPDATE_FAILURE','REPORT_UNAVAILABLE') -SafeMessages @('기존 설치 상태와 예약 작업을 확인하고 관리자 지원 복구를 요청하세요.')
}

try {
$authority = Enter-ContainerStartupUpdateAuthority
if ($Mode -ceq 'Authority') { exit 0 }
if ($Mode -ceq 'Observe') {
    $rows = Get-StartupUpdateProcesses $authority.root
    ConvertTo-Json -InputObject @($rows) -Depth 8 -Compress
    exit 0
}
if ($Mode -ceq 'Verify') {
    Assert-StartupUpdateVersion $authority.root $CodeRoot
    exit 0
}
if ($CodeRoot) { throw 'STARTUP_UPDATE_APPLY_HAS_NO_USER_CODE_ARGUMENT' }
$runtime = Join-Path $authority.root 'runtime\python.exe'
$implementation = Join-Path $authority.root 'app\auto_update.py'
$childOutput=@(& $runtime -I -B $implementation --apply-prepared --control-root (Join-Path (Split-Path -Parent $authority.root) 'update-control') 2>&1)
$childExitCode=$LASTEXITCODE
# Apply has no machine-output protocol. Native streams are diagnostic inputs;
# there is no proven private writer in this invocation, so discard originals.
if($childExitCode -ne 0){
    $failure=[InvalidOperationException]::new('STARTUP_UPDATE_FAILURE')
    $public=Get-StartupUpdatePublicFailure $failure $childExitCode
    [Console]::Out.WriteLine('CONTAINER_AUDIT_UPDATE='+([regex]::Replace(($public|ConvertTo-Json -Depth 4 -Compress), '[^\x00-\x7f]', {param($unit) '\u{0:x4}' -f [int][char]$unit.Value})))
}
exit $childExitCode
} catch {
    if($script:StartupUpdateBootstrapLoaded){
        $public=Get-StartupUpdatePublicFailure $_ 1
        [Console]::Out.WriteLine('CONTAINER_AUDIT_UPDATE='+([regex]::Replace(($public|ConvertTo-Json -Depth 4 -Compress), '[^\x00-\x7f]', {param($unit) '\u{0:x4}' -f [int][char]$unit.Value})))
    } else {
        # Before the pinned policy can be loaded, only a fully fixed record is
        # emitted; this is not a second validation/redaction implementation.
        [Console]::Out.WriteLine('CONTAINER_AUDIT_UPDATE={"status":"FAILED","stage":"startup_update","reason_code":"STARTUP_UPDATE_FAILURE","exit_code":1,"report_status":"REPORT_UNAVAILABLE","guidance":"\uae30\uc874 \uc124\uce58 \uc0c1\ud0dc\uc640 \uc608\uc57d \uc791\uc5c5\uc744 \ud655\uc778\ud558\uace0 \uad00\ub9ac\uc790 \uc9c0\uc6d0 \ubcf5\uad6c\ub97c \uc694\uccad\ud558\uc138\uc694."}')
    }
    exit 1
}
