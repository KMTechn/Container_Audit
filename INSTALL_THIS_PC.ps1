[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [switch]$RemoveUncommittedPlacement,
    [string]$TransactionHandoverPath = '',
    [string]$TransactionHandoverSha256 = '',
    [string]$TransactionStartupPreimagePath = '',
    [string]$TransactionStartupPreimageSha256 = '',
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\KMTech\Apps\Container_Audit\current",
    [string]$TlsCaBundlePath = "",
    [string]$OperatorLocalAppDataRoot = "",
    [string]$OperatorSid = "",
    [string]$OperatorDataRoot = "",
    [string]$MachineControlRoot = "",
    [string]$ElevationLogPath = "",
    [switch]$ReplaceExistingVerifiedPortable,
    [switch]$SupportedActiveVersionPlacement,
    [string]$SupportedFromCommit = "",
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
    [int]$RemovalControllerProcessId = 0,
    [string]$RemovalControllerStartedAtUtc = "",
    [string]$RemovalControllerCanonicalPath = "",
    [string]$UninstallAuditPath = "",
    [string]$UninstallAuditSha256 = "",
    [string]$RestoreUninstallRecordPath = "",
    [string]$ExpectedUninstallRecordSha256 = "",
    [string]$WriterFenceHelperPath = "",
    [string]$ExpectedWriterFenceHelperSha256 = "",
    [string]$WriterFencePreparedReceiptPath = "",
    [string]$WriterFencePreparedReceiptSha256 = "",
    [string]$WriterFenceSessionId = "",
    [string]$WriterFenceAttemptId = "",
    [string]$WriterFenceReplacementTransactionId = "",
    [string]$WriterFenceDelegationToken = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$ApplyHardenedAclForTest,
    [switch]$InjectRestoreFailureAfterDisplaceForTest,
    [switch]$RepairAbandonedInstallationParent,
    [switch]$RepairOwnedInstallationParent,
    [switch]$RecordRollbackContinuation,
    [switch]$RecordRollbackContinuationAuthority,
    [int]$ContinuationOwnerProcessId=0,
    [string]$ContinuationOwnerStartedAtUtc="",
    [switch]$CompleteRollbackContinuation,
    [string]$ContinuationReleaseAuthorizationPath="",
    [string]$ContinuationReleaseAuthorizationSha256="",
    [string]$RollbackAuditPath = '',
    [string]$RollbackAuditSha256 = '',
    [string]$RollbackContinuationPath = '',
    [string]$RollbackContinuationSha256 = '',
    [string]$AbandonedRecoverySourceManifestSha256 = '',
    [int]$AbandonedRecoveryParentProcessId = 0
)
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop

$ErrorActionPreference = "Stop"
function Write-InstallationHelperPublicRecord([Collections.IDictionary]$Fields) {
    $permitted=@('status','code','reason_code','error_code','exit_code','exception_type','location_module','location_function','location_line')
    $publicFields=[ordered]@{}
    foreach($name in $permitted){if($Fields.Contains($name)){$publicFields[$name]=$Fields[$name]}}
    $Fields=$publicFields
    $Fields.stage='installer_helper'
    $Fields.report_status='REPORT_UNAVAILABLE'
    $messages=@('설정 파일과 설치 경로를 확인하고 다시 실행하세요.',
        '빠른 시작이 켜져 있습니다. 설치 후 Windows를 다시 시작하세요.',
        '빠른 시작이 꺼져 있습니다. 설치 절차를 계속하세요.',
        '빠른 시작 설정을 확인하지 못했습니다. 관리자 권한으로 설정을 확인하고 다시 실행하세요.')
    $reasonCode=if($Fields.Contains('reason_code')){[string]$Fields.reason_code}else{''}
    $Fields.guidance=switch($reasonCode){
        'HIBERBOOT_ENABLED'{$messages[1]}
        'HIBERBOOT_DISABLED'{$messages[2]}
        'HIBERBOOT_UNKNOWN'{$messages[3]}
        default{$messages[0]}
    }
    $public=ConvertTo-KmtechPublicRecord -Fields $Fields -AllowedCodes @('PASS','FAILED','installer_helper','REPORT_UNAVAILABLE','HIBERBOOT_ENABLED','HIBERBOOT_DISABLED','HIBERBOOT_UNKNOWN') -SafeMessages $messages
    Write-Output ('CONTAINER_AUDIT_INSTALL_HELPER='+($public|ConvertTo-Json -Depth 4 -Compress))
}
function Get-InstallationHelperPublicFailure($Failure, [int]$ExitCode) {
    $exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    $fields=[ordered]@{status='FAILED';stage='installer_helper';reason_code='INSTALLER_HELPER_FAILURE';
        exit_code=$ExitCode;exception_type=$exception.GetType().FullName;
        guidance='자료를 보존하고 관리자 지원 복구를 요청하세요.';report_status='REPORT_UNAVAILABLE'}
    $contextCodes=@('lifecycle_operation_invalid','lifecycle_owned_namespace_collision','lifecycle_namespace_parent_unavailable',
        'lifecycle_data_namespace_collision','lifecycle_removed_control_remains','lifecycle_register_requires_installed_code',
        'lifecycle_removed_tasks_remain_or_unknown','lifecycle_stock_protection_invalid','lifecycle_stock_layout_invalid',
        'lifecycle_stock_manifest_invalid','lifecycle_control_incomplete','lifecycle_transition_requires_recovery',
        'lifecycle_confirmed_pointer_mismatch','lifecycle_rolled_back_pointer_mismatch','lifecycle_pointer_mismatch',
        'lifecycle_active_manifest_mismatch','lifecycle_active_trust_key_mismatch','lifecycle_task_absence_or_unknown',
        'lifecycle_state_changed_during_verification','lifecycle_from_commit_mismatch',
        'WRITER_GATE_TIMEOUT','ACTIVE_WRITER_FENCE','FENCE_REPARSE_REJECTED','FENCE_PATH_UNOBSERVABLE')
    $context=Get-Variable -Name ContainerLifecycleContextFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($context){
        foreach($detail in @($context.failure_details)){
            if([string]$detail.message -cin $contextCodes){
                $fields.reason_code=[string]$detail.message
                $fields.guidance='기존 설치 상태와 예약 작업을 확인하고 관리자 지원 복구를 요청하세요.'
                break
            }
        }
    }
    $startupCodes=@('STARTUP_UPDATE_INITIAL_VERSION_INVALID','STARTUP_UPDATE_INITIAL_VERSION_READBACK_FAILED',
        'STARTUP_UPDATE_VERSION_ALREADY_HAS_DIFFERENT_BYTES','STARTUP_UPDATE_DURING_WORK_FORBIDDEN',
        'STARTUP_UPDATE_OPERATOR_BINDING_DIFFERS','STARTUP_UPDATE_OPERATOR_DIFFERS','STARTUP_UPDATE_DURABLE_RECORD_FAILED',
        'STARTUP_UPDATE_PREIMAGE_PATH_INVALID','STARTUP_UPDATE_PREIMAGE_READBACK_FAILED','STARTUP_UPDATE_WRITER_HELPER_PIN_DIFFERS',
        'STARTUP_UPDATE_TASK_SPEC_FAILED','STARTUP_UPDATE_TASK_SPEC_INVALID','STARTUP_UPDATE_OWNED_TASK_DIFFERS',
        'STARTUP_UPDATE_TASK_IS_RUNNING','STARTUP_UPDATE_TASK_READBACK_FAILED')
    if($fields.reason_code -ceq 'INSTALLER_HELPER_FAILURE'){
        # Exact startup-update throw codes only; other exception text stays private.
        $cause=$exception
        for($depth=0;$null -ne $cause -and $depth -lt 8;$depth++){
            if([string]$cause.Message -cin $startupCodes){$fields.reason_code=[string]$cause.Message;break}
            $cause=$cause.InnerException
        }
    }
    if($Failure -is [Management.Automation.ErrorRecord]){$fields.location_line=[int]$Failure.InvocationInfo.ScriptLineNumber}
    # The original is retained by the existing installation evidence writer.
    # A reference is published only by its verified atomic publication contract.
    $reference=$exception.Data['installation_original_failure_reference']
    $published=Get-Variable -Name InstallationMostRecentOriginalFailureReference -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($root -and $reference -and [object]::ReferenceEquals($reference,$published) -and $reference.Contains('atomic_published') -and $reference.atomic_published -eq $true){
        try {
            Assert-InstallationEvidenceWriteRoot $root
            $path=[IO.Path]::GetFullPath([string]$reference.path)
            if(-not [IO.Path]::GetDirectoryName($path).Equals([IO.Path]::GetFullPath($root),[StringComparison]::OrdinalIgnoreCase)){throw 'Report attempt differs.'}
            if(Test-InstallationEvidencePrivileged){Assert-InstallationEvidenceProtectedPath $path}
            $digest=Get-FileSha256 $path
            if($digest -cne [string]$reference.sha256){throw 'Report readback differs.'}
            $fields.Remove('report_status');$fields.report_path=$path;$fields.report_sha256=$digest
        } catch { }
    }
    return ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes (@('FAILED','installer_helper','INSTALLER_HELPER_FAILURE','REPORT_UNAVAILABLE')+$contextCodes+$startupCodes) -SafeMessages @('자료를 보존하고 관리자 지원 복구를 요청하세요.','기존 설치 상태와 예약 작업을 확인하고 관리자 지원 복구를 요청하세요.')
}
$ExpectedInstallRoot = "C:\KMTech\Apps\Container_Audit\current"
$BootstrapIntegrityFunctions = Join-Path $PSScriptRoot "tools\bootstrap_integrity.ps1"
if (-not (Test-Path -LiteralPath $BootstrapIntegrityFunctions -PathType Leaf)) {
    throw "Bootstrap integrity producer is unavailable."
}
$pinnedLibrary=Get-Variable -Name InstallationPinnedBootstrapLibrary -Scope Script -ValueOnly -ErrorAction SilentlyContinue
if($pinnedLibrary){
    if(-not $pinnedLibrary.File.Equals($BootstrapIntegrityFunctions,[StringComparison]::OrdinalIgnoreCase)){throw 'Pinned bootstrap library identity differs.'}
    $bootstrapIntegrityPath = $BootstrapIntegrityFunctions
    $BootstrapIntegrityFunctions = $pinnedLibrary
    try { . $BootstrapIntegrityFunctions }
    finally { $BootstrapIntegrityFunctions = $bootstrapIntegrityPath }
}elseif(([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    # A direct administrator invocation also evaluates the bytes it checked.
    # The canonical elevation path supplies the already verified block above.
    $libraryManifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'portable-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $libraryStream=[IO.FileStream]::new($BootstrapIntegrityFunctions,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try{
        if($libraryStream.Length -le 0 -or $libraryStream.Length -gt 4194304){throw 'Bootstrap integrity producer size is invalid.'}
        $libraryBytes=[byte[]]::new([int]$libraryStream.Length);$libraryOffset=0
        while($libraryOffset -lt $libraryBytes.Length){
            $libraryRead=$libraryStream.Read($libraryBytes,$libraryOffset,$libraryBytes.Length-$libraryOffset)
            if($libraryRead -eq 0){throw 'Bootstrap integrity producer read is incomplete.'};$libraryOffset+=$libraryRead
        }
        if($libraryStream.ReadByte() -ne -1){throw 'Bootstrap integrity producer size changed.'}
    }finally{$libraryStream.Dispose()}
    $libraryAlgorithm=[Security.Cryptography.SHA256]::Create()
    try{$librarySha=([BitConverter]::ToString($libraryAlgorithm.ComputeHash($libraryBytes))).Replace('-','').ToLowerInvariant()}finally{$libraryAlgorithm.Dispose()}
    if($librarySha -cne [string]$libraryManifest.integrity_helper_sha256){throw 'Bootstrap integrity producer byte pin differs.'}
    $libraryTokens=$null;$libraryErrors=$null
    $libraryAst=[Management.Automation.Language.Parser]::ParseInput([Text.UTF8Encoding]::new($false,$true).GetString($libraryBytes).TrimStart([char]0xfeff),$BootstrapIntegrityFunctions,[ref]$libraryTokens,[ref]$libraryErrors)
    if($libraryErrors.Count){throw 'Bootstrap integrity producer parse failed.'}
    $bootstrapIntegrityPath = $BootstrapIntegrityFunctions
    $BootstrapIntegrityFunctions = $libraryAst.GetScriptBlock()
    try { . $BootstrapIntegrityFunctions }
    finally { $BootstrapIntegrityFunctions = $bootstrapIntegrityPath }
}else{. $BootstrapIntegrityFunctions}
$IntegrityFileName = $BootstrapIntegrityFileName
if($RepairAbandonedInstallationParent -or $RepairOwnedInstallationParent){
    if(-not(Test-InstallationEvidencePrivileged) -or $InstallRoot -ine $ExpectedInstallRoot -or
        $AbandonedRecoveryParentProcessId -le 0 -or
        (Get-FileSha256 (Join-Path $PSScriptRoot 'portable-manifest.json')) -cne $AbandonedRecoverySourceManifestSha256){throw 'Abandoned parent repair binding differs.'}
    if(-not(Get-Variable -Name InstallationAbandonedRepairAdmitted -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){throw 'Abandoned repair requires the admitted pinned wrapper.'}
    Assert-InstallationEvidenceProtectedPath (Split-Path -Parent $InstallRoot)
    'abandoned_app_protection=PROVEN'
    exit 0
}
$LegacyRelayTaskName = "direct-sync-relay-container-audit"
$LegacyQualificationTaskName = "container-audit-isolated-qualification-authority"
$PlacementWriterSource = "canonical_code_placement"
$BootstrapScriptPath = $PSCommandPath
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
    Write-InstallationCaughtFailure $_

        return $false
    }
}

function Assert-NoReparsePoint([string]$Path, [string]$Purpose, [switch]$PathOnly) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Assert-BootstrapNoReparsePoint $Path $Purpose -PathOnly:$PathOnly
}

function Install-CurrentUserTlsCaBootstrap([string]$SourcePath, [string]$LocalAppDataRoot) {
    if ([string]::IsNullOrWhiteSpace($SourcePath)) { return $null }
    $source = Get-StrictFullPath $SourcePath "TLS CA bundle source"; Assert-NoReparsePoint $source "TLS CA bundle source"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "TLS CA bundle source is unavailable." }
    $sourceLength = (Get-Item -LiteralPath $source -Force).Length
    if ($sourceLength -le 0 -or $sourceLength -gt 131072) { throw "TLS CA bundle source size is invalid." }
    $userRoot = Get-StrictFullPath $LocalAppDataRoot "operator LOCALAPPDATA root"; $target = Join-Path $userRoot "KMTech\Bootstrap\Container_Audit\ca-bundle.pem"
    $targetParent = Split-Path -Parent $target
    $existingParent=$targetParent
    while(-not(Test-Path -LiteralPath $existingParent)){$existingParent=Split-Path -Parent $existingParent}
    Assert-NoReparsePoint $existingParent "TLS CA bootstrap ancestor" -PathOnly
    New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
    Assert-NoReparsePoint $targetParent "TLS CA bootstrap directory"
    Assert-NoReparsePoint $target "TLS CA bootstrap target" -PathOnly
    Copy-Item -LiteralPath $source -Destination $target -Force; Assert-NoReparsePoint $target "TLS CA bootstrap target"
    if ((Get-FileSha256 $target) -cne (Get-FileSha256 $source)) { throw "TLS CA bootstrap exact readback failed." }
    return $target
}
function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('\', '\').Replace('"', '\"') + '"'
}

function Get-CodePlacementPreflightFailureCode($Failure) {
    $candidate=$Failure.Exception
    for($depth=0;$null -ne $candidate -and $depth -lt 8;$depth++) {
        if($candidate.Data.Contains('canonical_code') -and [string]$candidate.Data['canonical_code'] -cmatch '^CONTAINER_PLACEMENT_[A-Z_]+$'){return [string]$candidate.Data['canonical_code']}
        $candidate=$candidate.InnerException
    }
    $message = [string]$Failure.Exception.Message
    if ($message -cmatch '^CONTAINER_(?:OPERATOR|WRITER|PLACEMENT)_[A-Z_]+$') { return $message }
    $exception = $Failure.Exception
    while ($exception -is [Management.Automation.RuntimeException] -and $null -ne $exception.InnerException) {
        $exception = $exception.InnerException
    }
    if ($exception -is [UnauthorizedAccessException] -or $exception -is [Security.SecurityException]) {
        return 'CONTAINER_PLACEMENT_ACCESS_DENIED'
    }
    if ($exception -is [IO.FileNotFoundException] -or $exception -is [IO.DirectoryNotFoundException] -or
        $exception -is [Management.Automation.ItemNotFoundException] -or
        $exception -is [Management.Automation.DriveNotFoundException]) {
        return 'CONTAINER_PLACEMENT_PATH_UNAVAILABLE'
    }
    if ($exception -is [IO.IOException]) { return 'CONTAINER_PLACEMENT_FILE_IO_FAILED' }
    return 'CONTAINER_PLACEMENT_UNCLASSIFIED'
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
    try {
        $process=Invoke-InstallationElevationCapture $BootstrapScriptPath $arguments $ElevationLogPath $OperatorSid
        if($process.HelperStageEvidenceRoot){Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('installation_stage_evidence_root='+$process.HelperStageEvidenceRoot))))}
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('installation_elevation_result_path='+$process.ResultPath))))
    } catch {
    Write-InstallationCaughtFailure $_

        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('code_placement_preflight_failure=CONTAINER_PLACEMENT_ELEVATION_FAILED')))
        Complete-InstallationEvidenceStage 'forward' $_
        $summary=Complete-InstallationEvidence
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('installation_evidence_status='+[string]$summary.status))))
        Write-InstallationHelperPublicRecord @{status='FAILED';summary_path=$summary.summary_path}
        exit 1
    }
    if ($process.ExitCode -ne 0) {
        $failureCode = 'CONTAINER_PLACEMENT_CHILD_FAILED'
        if ($process.ExitCode -eq 42) {
            # The child could not write its classified preflight result.
            $failureCode = 'CONTAINER_PLACEMENT_LOG_WRITE_FAILED'
        } elseif (-not [string]::IsNullOrWhiteSpace($ElevationLogPath)) {
            try {
                $logFull = Get-StrictFullPath $ElevationLogPath 'ElevationLogPath'
                Assert-NoReparsePoint $logFull 'elevation log'
                if ((Test-Path -LiteralPath $logFull -PathType Leaf) -and
                    (Get-Item -LiteralPath $logFull).Length -le 65536) {
                    $lastEntry = Get-Content -LiteralPath $logFull -Encoding UTF8 -Tail 1 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ([int]$lastEntry.process_id -eq [int]$process.Id -and
                        [string]$lastEntry.status -ceq 'PREFLIGHT_FAILED' -and
                        [string]$lastEntry.message -cmatch '^CONTAINER_(?:OPERATOR|WRITER|PLACEMENT)_[A-Z_]+$') {
                        $failureCode = [string]$lastEntry.message
                    }
                } elseif (Test-Path -LiteralPath $logFull -PathType Leaf) {
                    $failureCode = 'CONTAINER_PLACEMENT_LOG_UNREADABLE'
                }
            } catch {
    Write-InstallationCaughtFailure $_
 $failureCode = 'CONTAINER_PLACEMENT_LOG_UNREADABLE' }
        }
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("code_placement_preflight_failure=$failureCode")))
    }
    $childFailure=if($process.ExitCode -ne 0){[Exception]::new('CONTAINER_PLACEMENT_CHILD_FAILED')}else{$null}
    Complete-InstallationEvidenceStage 'forward' $childFailure
    $summary=Complete-InstallationEvidence
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('installation_evidence_status='+[string]$summary.status))))
    Write-InstallationHelperPublicRecord @{status='FAILED';summary_path=$summary.summary_path}
    exit $process.ExitCode
}

function Write-ContainerSupportedRemovalJournal([int[]]$ControllerProcessIds) {
    # Called only by the already authenticated, delegated removal helper, before
    # deleting tasks or moving owned content. A user-writable audit is input,
    # never the authority used to reclaim an abandoned controller's fence.
    if (-not (Test-InstallationEvidencePrivileged)) { throw 'REMOVAL_JOURNAL_PROTECTED_AUTHORITY_REQUIRED' }
    Assert-NoReparsePoint $UninstallAuditPath 'supported removal audit'
    if ($UninstallAuditSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-Item -LiteralPath $UninstallAuditPath).Length -gt 131072 -or
        (Get-FileSha256 $UninstallAuditPath) -cne $UninstallAuditSha256) { throw 'REMOVAL_JOURNAL_AUDIT_CHANGED' }
    $origin=Get-Content -LiteralPath $UninstallAuditPath -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    $active=Read-ContainerWriterFence
    if ([IO.Path]::GetFileName([string]$origin.stage_evidence_root) -cnotmatch '\.evidence\.([1-9][0-9]{0,9})$') { throw 'REMOVAL_JOURNAL_OWNER_INVALID' }
    $ownerPid=[int]$Matches[1]
    if ($ownerPid -notin $ControllerProcessIds) { throw 'REMOVAL_JOURNAL_OWNER_NOT_CONTROLLER_ANCESTOR' }
    $ownerStarted=(Get-Process -Id $ownerPid -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')
    $manifestSha=Get-FileSha256 (Join-Path $uninstallSource 'portable-manifest.json')
    if ([string]$origin.schema -cne 'container-audit-canonical-portable-install-v2' -or
        [string]$origin.operation -cne 'UNINSTALL' -or [string]$origin.status -cne 'PREIMAGE_SAVED' -or
        -not (Test-SamePath ([string]$origin.install_root) $installRootFull) -or
        [string]$origin.source_manifest_sha256 -cne $manifestSha -or
        [string]$origin.code_replacement.transaction_id -cne [string]$active.replacement_transaction_id -or
        [string]$active.status -cne 'INSTALLING' -or [string]$active.owner_kind -cne 'canonical_installer' -or
        [string]$active.orchestrator_sha256 -cne (Get-FileSha256 (Join-Path $uninstallSource 'INSTALL_CANONICAL_PORTABLE.ps1')) -or
        -not (Test-SamePath ([string]$active.prepared_receipt_path) $WriterFencePreparedReceiptPath) -or
        [string]$active.prepared_receipt_sha256 -cne $WriterFencePreparedReceiptSha256) { throw 'REMOVAL_JOURNAL_ORIGIN_BINDING_DIFFERS' }
    $store=Join-Path (Get-InstallationEvidenceControlRoot) 'supported-removals'
    New-InstallationProtectedDirectory $store $OperatorSid
    $directory=Join-Path $store ([string]$active.replacement_transaction_id)
    New-InstallationProtectedDirectory $directory $OperatorSid
    $path=Join-Path $directory 'removal-journal.json'
    if (Test-Path -LiteralPath $path) {
        Assert-InstallationEvidenceProtectedPath $path
        [void](Read-BootstrapReplacementReceipt $path (Get-FileSha256 $path))
        $existing=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
        foreach ($name in @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc',
            'orchestrator_sha256','writer_contract_sha256','writer_inventory_sha256','prepared_receipt_sha256')) {
            if ([string]$existing.$name -cne [string]$active.$name) { throw 'REMOVAL_JOURNAL_EXISTING_TUPLE_DIFFERS' }
        }
        if ([string]$existing.schema -cne 'container-audit-supported-removal-journal-v1' -or
            [string]$existing.source_manifest_sha256 -cne $manifestSha -or
            [string]$existing.operator_sid -cne $OperatorSid -or
            -not (Test-SamePath ([string]$existing.install_root) $installRootFull) -or
            -not (Test-SamePath ([string]$existing.audit_copy_path) (Join-Path $directory 'original-audit.json')) -or
            (Get-FileSha256 ([string]$existing.audit_copy_path)) -cne [string]$existing.original_audit_sha256) { throw 'REMOVAL_JOURNAL_EXISTING_ORIGIN_DIFFERS' }
        return
    }
    $copy=Join-Path $directory 'original-audit.json'
    Assert-BootstrapNoReparsePoint $directory 'removal audit copy parent' -PathOnly
    if (Test-Path -LiteralPath $copy) { Assert-BootstrapNoReparsePoint $copy 'removal audit copy' -PathOnly }
    $bytes=[IO.File]::ReadAllBytes($UninstallAuditPath)
    $stream=[IO.FileStream]::new($copy,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    Set-InstallationEvidenceAcl $copy $OperatorSid
    if ((Get-FileSha256 $copy) -cne $UninstallAuditSha256) { throw 'REMOVAL_JOURNAL_COPY_CHANGED' }
    $record=[ordered]@{schema='container-audit-supported-removal-journal-v1';install_root=$installRootFull;
        operator_sid=$OperatorSid;operator_local_appdata_root=$OperatorLocalAppDataRoot;
        owner_process_id=$ownerPid;owner_started_at_utc=$ownerStarted;authority_mutex_name=$active.session_authority_mutex_name;
        original_audit_path=$UninstallAuditPath;original_audit_sha256=$UninstallAuditSha256;audit_copy_path=$copy;
        source_manifest_sha256=$manifestSha;prepared_receipt_path=$active.prepared_receipt_path;secret_values_recorded=$false}
    foreach ($name in @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc',
        'orchestrator_sha256','writer_contract_sha256','writer_inventory_sha256','prepared_receipt_sha256')) { $record[$name]=[string]$active.$name }
    Write-ContainerStartupUpdateRecord $path $record
    Set-InstallationEvidenceAcl $path $OperatorSid
    Assert-InstallationEvidenceProtectedPath $path
    Write-InstallationEvidenceEvent ([ordered]@{event='SUPPORTED_REMOVAL_JOURNAL';path=$path;sha256=Get-FileSha256 $path;secret_values_recorded=$false})
}

function Write-ContainerRollbackContinuation([string]$AuditPath,[string]$AuditSha256) {
    Assert-InstallationEvidenceWriteRoot $Script:InstallationEvidenceRoot
    Assert-InstallationEvidenceProtectedPath $Script:InstallationEvidenceRoot
    Assert-BootstrapNoReparsePoint $AuditPath 'rollback origin audit' -PathOnly
    if ($AuditSha256 -cnotmatch '^[0-9a-f]{64}$' -or (Get-Item -LiteralPath $AuditPath).Length -gt 1048576 -or
        (Get-FileSha256 $AuditPath) -cne $AuditSha256) {throw 'Rollback origin audit hash/size differs.'}
    $origin=Get-Content -LiteralPath $AuditPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    $active=Read-ContainerWriterFence
    if ([IO.Path]::GetFileName([string]$origin.stage_evidence_root) -cnotmatch '\.evidence\.([1-9][0-9]{0,9})$') {
        throw 'Rollback origin controller PID binding differs.'
    }
    $ownerPid=[int]$Matches[1]
    $ownerStarted=(Get-Process -Id $ownerPid -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')
    $manifestSha=Get-FileSha256 (Join-Path $PSScriptRoot 'portable-manifest.json')
    if ([string]$origin.schema -cne 'container-audit-canonical-portable-install-v2' -or
        [string]$origin.operation -cne 'INSTALL' -or -not $origin.failure -or
        -not (Test-SamePath ([string]$origin.install_root) $installRootFull) -or
        [string]$origin.source_manifest_sha256 -cne $manifestSha -or
        [string]$origin.code_replacement.transaction_id -cne [string]$active.replacement_transaction_id -or
        [string]$active.orchestrator_sha256 -cne (Get-FileSha256 (Join-Path $PSScriptRoot 'INSTALL_CANONICAL_PORTABLE.ps1')) -or
        [string]$origin.runtime_preimage_binding.status -cne 'PASS' -or
        $origin.runtime_preimage_binding.relay_count -notin @(0,1) -or
        [bool]$origin.scheduled_writer.preimage.present) {throw 'Rollback origin audit binding differs.'}
    $path=[string]$origin.code_replacement.receipt_path
    Assert-InstallationEvidenceProtectedPath $path
    $receipt=Read-BootstrapReplacementReceipt $path ([string]$origin.code_replacement.receipt_sha256)
    if ([string]$receipt.new.manifest_sha256 -cne $manifestSha -or
        [string]$receipt.transaction_id -cne [string]$active.replacement_transaction_id) {throw 'Rollback continuation successor or transaction differs.'}
    $state=Get-BootstrapVerifiedReplacementRestoreState $receipt $path $installRootFull 'container_audit' ([string]$receipt.transaction_id) (Get-FileSha256 $BootstrapScriptPath)
    if ([string]$state.status -cne 'PENDING') {throw 'Rollback continuation requires verified pending replacement.'}
    $store=Join-Path (Get-InstallationEvidenceControlRoot) 'rollback-continuations'
    New-InstallationProtectedDirectory $store $OperatorSid
    $directory=Join-Path $store ([string]$receipt.transaction_id)
    if (Test-Path -LiteralPath $directory) {throw 'Rollback continuation path already exists.'}
    New-InstallationProtectedDirectory $directory $OperatorSid
    $copy=Join-Path $directory 'replacement-receipt.json'
    $bytes=[IO.File]::ReadAllBytes($path)
    $stream=[IO.FileStream]::new($copy,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    Set-InstallationEvidenceAcl $copy $OperatorSid
    if ((Get-FileSha256 $copy) -cne [string]$origin.code_replacement.receipt_sha256) {throw 'Rollback continuation receipt copy differs.'}
    # The immutable original's self-path is preserved. This explicit recovery
    # journal authenticates the durable byte copy outside rotating evidence runs.
    $record=[ordered]@{schema='container-audit-rollback-continuation-v1';event='ROLLBACK_CONTINUATION';install_root=$installRootFull;
        operator_sid=$OperatorSid;operator_local_appdata_root=$OperatorLocalAppDataRoot;
        owner_process_id=$ownerPid;owner_started_at_utc=$ownerStarted;
        session_id=[string]$active.session_id;attempt_id=[string]$active.attempt_id;
        orchestrator_sha256=[string]$active.orchestrator_sha256;writer_contract_sha256=[string]$active.writer_contract_sha256;
        source_manifest_sha256=$manifestSha;receipt_path=$copy;receipt_binding_path=$path;receipt_sha256=[string]$origin.code_replacement.receipt_sha256;
        old_manifest_sha256=[string]$receipt.old.manifest_sha256;new_manifest_sha256=[string]$receipt.new.manifest_sha256;
        transaction_id=[string]$receipt.transaction_id;preimage=$origin.preimage;relay_count=[int]$origin.runtime_preimage_binding.relay_count;
        original_relays=@($origin.rollback.original_relays);
        runtime_preimage_binding=$origin.runtime_preimage_binding;
        original_audit_sha256=$AuditSha256;secret_values_recorded=$false}
    $saved=Write-BootstrapReplacementReceipt (Join-Path $directory 'continuation-journal.json') $record
    Write-InstallationEvidenceEvent ([ordered]@{event='ROLLBACK_CONTINUATION';path=$saved.path;sha256=$saved.sha256;
        receipt_path=$path;receipt_sha256=$record.receipt_sha256;old_manifest_sha256=$record.old_manifest_sha256;new_manifest_sha256=$record.new_manifest_sha256})
    if($Script:InstallationEvidenceFailed){throw 'Rollback continuation journal was not durably recorded.'}
    return $saved
}

function Read-ContainerRollbackContinuation([string]$Path,[string]$ExpectedSha256) {
    Assert-InstallationEvidenceProtectedPath $Path
    $record=Read-BootstrapReplacementReceipt $Path $ExpectedSha256
    $directory=Join-Path (Join-Path (Get-InstallationEvidenceControlRoot) 'rollback-continuations') ([string]$record.transaction_id)
    if ([string]$record.schema -cne 'container-audit-rollback-continuation-v1' -or
        [string]$record.event -cne 'ROLLBACK_CONTINUATION' -or [string]$record.transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-SamePath $Path (Join-Path $directory 'continuation-journal.json')) -or
        -not (Test-SamePath ([string]$record.receipt_path) (Join-Path $directory 'replacement-receipt.json')) -or
        -not (Test-SamePath ([string]$record.install_root) $installRootFull) -or
        [string]$record.operator_sid -cne $OperatorSid -or
        -not (Test-SamePath ([string]$record.operator_local_appdata_root) $OperatorLocalAppDataRoot) -or
        [string]$record.source_manifest_sha256 -cne (Get-FileSha256 (Join-Path $PSScriptRoot 'portable-manifest.json')) -or
        [string]$record.orchestrator_sha256 -cne (Get-FileSha256 (Join-Path $PSScriptRoot 'INSTALL_CANONICAL_PORTABLE.ps1'))) {
        throw 'Rollback continuation protected journal binding differs.'
    }
    Assert-InstallationEvidenceProtectedPath $directory
    Assert-InstallationEvidenceProtectedPath ([string]$record.receipt_path)
    $receipt=Read-BootstrapReplacementReceipt ([string]$record.receipt_path) ([string]$record.receipt_sha256)
    if (-not (Test-SamePath ([string]$receipt.receipt_path) ([string]$record.receipt_binding_path)) -or
        [string]$record.old_manifest_sha256 -cne [string]$receipt.old.manifest_sha256 -or
        [string]$record.new_manifest_sha256 -cne [string]$receipt.new.manifest_sha256 -or
        [string]$record.new_manifest_sha256 -cne [string]$record.source_manifest_sha256 -or
        [string]$record.transaction_id -cne [string]$receipt.transaction_id) {throw 'Rollback continuation receipt/manifests differ.'}
    [void](Get-BootstrapVerifiedReplacementRestoreState $receipt ([string]$record.receipt_binding_path) $installRootFull 'container_audit' ([string]$record.transaction_id) (Get-FileSha256 $BootstrapScriptPath))
    return $record
}


function Write-ContainerRollbackContinuationAuthority {
    if(-not(Test-InstallationEvidencePrivileged)){throw 'Rollback authority linkage requires protected evidence authority.'}
    $record=Read-ContainerRollbackContinuation $RollbackContinuationPath $RollbackContinuationSha256
    $prior=Read-ContainerWriterFence -AllowAbsent
    if($null -eq $prior){$prior=[pscustomobject]@{session_id=$record.session_id;attempt_id=$record.attempt_id;orchestrator_sha256=$record.orchestrator_sha256;writer_contract_sha256=$record.writer_contract_sha256;replacement_transaction_id=$record.transaction_id}}
    $previous=Read-BootstrapRollbackContinuationAuthority $record $RollbackContinuationPath $RollbackContinuationSha256 $prior
    if(@(Get-Process -Id ([int]$record.owner_process_id) -ErrorAction SilentlyContinue).Count){throw 'Rollback original owner is alive or reused.'}
    Assert-BootstrapNoReparsePoint $WriterFencePreparedReceiptPath 'rollback renewed preparation' -PathOnly
    if((Get-Item -LiteralPath $WriterFencePreparedReceiptPath).Length -gt 65536 -or
        (Get-FileSha256 $WriterFencePreparedReceiptPath) -cne $WriterFencePreparedReceiptSha256){throw 'Rollback renewed preparation bytes differ.'}
    $prepared=Get-Content -LiteralPath $WriterFencePreparedReceiptPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if((Get-FileSha256 $WriterFencePreparedReceiptPath) -cne $WriterFencePreparedReceiptSha256 -or $prepared.secret_values_recorded -ne $false){throw 'Rollback renewed preparation changed or records secrets.'}
    if([string]$prepared.schema -cne 'container-audit-canonical-writer-prepared-v1' -or [string]$prepared.status -cne 'PREPARED' -or
        [string]$prepared.operator_sid -cne $OperatorSid -or -not(Test-SamePath ([string]$prepared.operator_local_appdata_root) $OperatorLocalAppDataRoot) -or
        [string]$prepared.source_manifest_sha256 -cne [string]$record.source_manifest_sha256 -or
        [string]$prepared.orchestrator_sha256 -cne [string]$record.orchestrator_sha256 -or
        [string]$prepared.writer_contract_sha256 -cne [string]$record.writer_contract_sha256){throw 'Rollback renewed preparation binding differs.'}
    foreach($name in @('session_id','attempt_id','replacement_transaction_id')) {
        $expected=switch($name){'session_id'{$WriterFenceSessionId};'attempt_id'{$WriterFenceAttemptId};'replacement_transaction_id'{$WriterFenceReplacementTransactionId}}
        if([string]$prepared.$name -cnotmatch '^[0-9a-f]{32}$' -or [string]$prepared.$name -cne [string]$expected){throw 'Rollback renewed authority tuple differs.'}
    }
    $owner=Get-Process -Id $ContinuationOwnerProcessId -ErrorAction Stop
    if($owner.StartTime.ToUniversalTime().ToString('o') -cne $ContinuationOwnerStartedAtUtc){throw 'Rollback renewed owner identity differs.'}
    $mutex=$null;$acquired=$false
    try {
        $name=Get-ContainerWriterSessionAuthorityMutexName ([string]$prepared.session_id) ([string]$prepared.attempt_id) ([string]$prepared.orchestrator_sha256) ([string]$prepared.replacement_transaction_id) ([string]$prepared.writer_contract_sha256)
        $mutex=[Threading.Mutex]::OpenExisting($name)
        try{$acquired=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$acquired=$true}
        if($acquired){throw 'Rollback renewed authority is not held by its controller.'}
    }finally{if($acquired){$mutex.ReleaseMutex()};if($null -ne $mutex){$mutex.Dispose()}}
    $tuple=[ordered]@{};foreach($name in @('session_id','attempt_id','orchestrator_sha256','writer_contract_sha256','replacement_transaction_id')){$tuple[$name]=[string]$prepared.$name}
    $link=[ordered]@{schema='container-audit-rollback-authority-link-v1';transaction_id=[string]$record.transaction_id;journal_sha256=$RollbackContinuationSha256;receipt_sha256=[string]$record.receipt_sha256;
        previous=$previous.tuple;authority=$tuple;owner_process_id=$ContinuationOwnerProcessId;owner_started_at_utc=$ContinuationOwnerStartedAtUtc;
        prepared_receipt_path=$WriterFencePreparedReceiptPath;prepared_receipt_sha256=$WriterFencePreparedReceiptSha256;previous_link_sha256=[string]$previous.link_sha256;secret_values_recorded=$false}
    [void](Write-BootstrapReplacementReceipt (Join-Path (Split-Path -Parent $RollbackContinuationPath) ('authority-'+$WriterFenceAttemptId+'.json')) $link)
}

function Read-ContainerRollbackRunPreimage {
    $key=[Microsoft.Win32.Registry]::Users.OpenSubKey(($OperatorSid+'\Software\Microsoft\Windows\CurrentVersion\Run'))
    try {
        $exists=$null -ne $key -and @($key.GetValueNames()) -ccontains 'KMTech.ContainerAudit.Relay'
        if (-not $exists) {return [pscustomobject]@{exists=$false;kind='';data=''}}
        return [pscustomobject]@{exists=$true;kind=[string]$key.GetValueKind('KMTech.ContainerAudit.Relay');
            data=[string]$key.GetValue('KMTech.ContainerAudit.Relay',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
    } finally {if($null -ne $key){$key.Dispose()}}
}

function Complete-ContainerRollbackContinuation {
    # Close evidence under the same live controller and protected evidence authority. Code,
    # startup state, and the user's runtime are read back without mutation.
    if (-not (Test-InstallationEvidencePrivileged)) {throw 'Rollback completion requires protected evidence authority.'}
    $record=Read-ContainerRollbackContinuation $RollbackContinuationPath $RollbackContinuationSha256
    $receipt=Read-BootstrapReplacementReceipt ([string]$record.receipt_path) ([string]$record.receipt_sha256)
    $state=Get-BootstrapVerifiedReplacementRestoreState $receipt ([string]$record.receipt_binding_path) $installRootFull 'container_audit' ([string]$record.transaction_id) (Get-FileSha256 $BootstrapScriptPath)
    if ([string]$state.status -cne 'RESTORED') {throw 'Rollback completion requires exact restored code.'}
    Assert-BootstrapNoReparsePoint $RollbackAuditPath 'rollback completion audit' -PathOnly
    if ((Get-Item -LiteralPath $RollbackAuditPath).Length -gt 1048576 -or (Get-FileSha256 $RollbackAuditPath) -cne $RollbackAuditSha256) {throw 'Rollback completion audit differs.'}
    $audit=Get-Content -LiteralPath $RollbackAuditPath -Raw -Encoding UTF8|ConvertFrom-Json
    if ([string]$audit.status -cnotin @('PASS_RESTORED_VERIFIED_DATA_PRESERVED','FAILED_ROLLED_BACK') -or
        $audit.rollback.code_exact -isnot [bool] -or -not $audit.rollback.code_exact -or
        $audit.rollback.runtime_restored -isnot [bool] -or -not $audit.rollback.runtime_restored -or
        [string]$audit.code_replacement.receipt_sha256 -cne [string]$record.receipt_sha256 -or
        -not (Test-SamePath ([string]$audit.install_root) $installRootFull)) {throw 'Rollback completion state is unproven.'}
    $run=Read-ContainerRollbackRunPreimage
    if ([bool]$record.preimage.exists -ne [bool]$run.exists -or [string]$record.preimage.kind -cne [string]$run.kind -or
        [string]$record.preimage.data -cne [string]$run.data) {throw 'Rollback completion Run differs.'}
    $control=Join-Path $OperatorLocalAppDataRoot 'KMTech\DirectSync\container_audit\control\writer-session'
    $relayRoot=Join-Path $OperatorLocalAppDataRoot 'KMTech\DirectSync\container_audit'
    if ($env:CONTAINER_AUDIT_DATA_ROOT) {$relayRoot=Join-Path (Get-StrictFullPath $env:CONTAINER_AUDIT_DATA_ROOT 'completion data root') 'direct_sync'}
    $stop=Join-Path $relayRoot 'control\container_audit_user_relay.stop.json'
    # Protected completion is read-only with respect to ordinary writers.
    # Require the actual completed release, the same live controller authority,
    # and exact code/runtime evidence; never open another installation fence.
    $active=Read-ContainerWriterFence -ControlRoot $control -AllowAbsent
    if($active -or (Test-Path -LiteralPath $stop)){throw 'Rollback completion requires released ordinary writers.'}
    $releasePath=Join-Path $control ('release-'+$WriterFenceReplacementTransactionId+'-'+$ContinuationReleaseAuthorizationSha256+'.json')
    $release=Read-ContainerWriterFenceReleaseReceipt $releasePath
    if([string]$release.session_id -cne $WriterFenceSessionId -or [string]$release.attempt_id -cne $WriterFenceAttemptId -or
        [string]$release.replacement_transaction_id -cne $WriterFenceReplacementTransactionId -or
        -not(Test-SamePath ([string]$release.release_authorization_path) $ContinuationReleaseAuthorizationPath) -or
        [string]$release.release_authorization_sha256 -cne $ContinuationReleaseAuthorizationSha256){throw 'Rollback completion release binding differs.'}
    $authorization=Read-BootstrapReplacementReceipt $ContinuationReleaseAuthorizationPath $ContinuationReleaseAuthorizationSha256
    if([string]$authorization.schema -cne 'container-audit-writer-release-authorization-v1' -or
        [string]$authorization.phase -cnotin @('PRODUCT_COMPLETE','ROLLBACK_COMPLETE') -or
        [string]$authorization.session_id -cne $WriterFenceSessionId -or [string]$authorization.attempt_id -cne $WriterFenceAttemptId -or
        [string]$authorization.replacement_transaction_id -cne $WriterFenceReplacementTransactionId -or
        -not(Test-SamePath ([string]$authorization.install_audit_path) $RollbackAuditPath)){throw 'Rollback completion authorization differs.'}
    $owner=Get-Process -Id $ContinuationOwnerProcessId -ErrorAction Stop
    if($owner.StartTime.ToUniversalTime().ToString('o') -cne $ContinuationOwnerStartedAtUtc){throw 'Rollback completion controller differs.'}
    $mutex=$null;$acquired=$false
    try{
        $name=Get-ContainerWriterSessionAuthorityMutexName $WriterFenceSessionId $WriterFenceAttemptId ([string]$record.orchestrator_sha256) $WriterFenceReplacementTransactionId ([string]$record.writer_contract_sha256)
        $mutex=[Threading.Mutex]::OpenExisting($name)
        try{$acquired=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$acquired=$true}
        if($acquired){throw 'Rollback completion controller authority is no longer held.'}
    }finally{if($acquired){$mutex.ReleaseMutex()};if($null -ne $mutex){$mutex.Dispose()}}
    $completionIdentity=Get-BootstrapRelayExpectedIdentity $installRootFull ([string]$record.preimage.data)
    $processes=@(Get-CimInstance Win32_Process|Where-Object {[string]$_.ExecutablePath -ieq [string]$completionIdentity.executable -and [string]$_.CommandLine -match '--container-audit-user-relay'})
    if ($processes.Count -ne [int]$record.relay_count) {throw 'Rollback completion relay count differs.'}
    if ([int]$record.relay_count -eq 1) {
        $proof=$audit.exact_launch
        $identity=Get-BootstrapRelayExpectedIdentity $installRootFull ([string]$record.preimage.data)
        $statusPath=Join-Path $relayRoot 'status\container_audit_user_relay.json'
        $status=Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8|ConvertFrom-Json
        $security=Get-BootstrapRelaySecurity ([int]$processes[0].ProcessId)
        $caller=[pscustomobject]@{sid=$OperatorSid;session_id=[int]$proof.session_id}
        if ([string]$proof.status -cne 'PROVEN' -or [int]$proof.process_id -ne [int]$processes[0].ProcessId -or
            -not (Test-BootstrapRelayReadback $identity $processes[0] $security $caller $status ([DateTime]$processes[0].CreationDate) '' (Get-FileSha256 $statusPath))) {throw 'Rollback completion resident READY is unproven.'}
    }
    if ($receipt.PSObject.Properties['startup_update_preimage']) {
        $saved=Get-Content -LiteralPath (Join-Path ([string]$receipt.startup_update_preimage) 'preimage.json') -Raw -Encoding UTF8|ConvertFrom-Json
        $startupControl=Join-Path (Split-Path -Parent $installRootFull) 'update-control'
        foreach($item in @($saved.files)) {
            $target=Join-Path $startupControl ([string]$item.name)
            if ([bool]$item.exists -ne (Test-Path -LiteralPath $target -PathType Leaf) -or
                ($item.exists -and (Get-FileSha256 $target) -cne [string]$item.sha256)) {throw 'Rollback completion startup pointer differs.'}
        }
        if($receipt.PSObject.Properties['active_version']) {
            $actual=Get-ContainerStartupUpdateTaskPreimage $installRootFull
            if([bool]$actual.exists -ne [bool]$saved.task.exists -or [string]$actual.xml -cne [string]$saved.task.xml -or
                (Get-BootstrapAclComparisonKey ([string]$actual.sddl)) -cne (Get-BootstrapAclComparisonKey ([string]$saved.task.sddl))){throw 'Rollback completion startup task differs.'}
        } elseif ($saved.task.exists -or $null -ne (Get-ScheduledTask -TaskName ([string]$saved.task.name) -ErrorAction SilentlyContinue)) {throw 'Rollback completion startup task remains.'}
    }
    $completed=[ordered]@{schema='container-audit-rollback-completed-v1';status='COMPLETE';
        journal_sha256=$RollbackContinuationSha256;receipt_sha256=[string]$record.receipt_sha256;
        old_manifest_sha256=[string]$record.old_manifest_sha256;new_manifest_sha256=[string]$record.new_manifest_sha256;
        audit_sha256=$RollbackAuditSha256;completed_at_utc=[DateTime]::UtcNow.ToString('o');secret_values_recorded=$false}
    [void](Write-BootstrapReplacementReceipt (Join-Path (Split-Path -Parent $RollbackContinuationPath) 'continuation-completed.json') $completed)
}

function Enter-ContainerPlacementWriterFence {
    if (
        [string]::IsNullOrWhiteSpace($WriterFenceHelperPath) -or
        [string]::IsNullOrWhiteSpace($OperatorLocalAppDataRoot) -or
        [string]::IsNullOrWhiteSpace($OperatorSid) -or
        [string]::IsNullOrWhiteSpace($WriterFencePreparedReceiptPath) -or
        [string]$WriterFencePreparedReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$ExpectedWriterFenceHelperSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$WriterFenceSessionId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$WriterFenceAttemptId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$WriterFenceReplacementTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$WriterFenceDelegationToken -cnotmatch '^[0-9a-f]{64}$'
    ) {
        throw 'CONTAINER_WRITER_FENCE_PARAMETERS_INVALID'
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
    . (Get-InstallationVerifiedScript $writerFenceHelperFull $ExpectedWriterFenceHelperSha256 'Production placement writer fence helper byte pin differs.')
    if ($MachineControlRoot -and -not $testOverride -and -not (Test-InstallationEvidencePrivileged)) {
        throw 'Machine placement requires an already privileged token.'
    }
    $operatorBinding = Assert-ContainerWriterFenceOperatorRoot `
        -PreparedReceiptPath $WriterFencePreparedReceiptPath `
        -PreparedReceiptSha256 $WriterFencePreparedReceiptSha256 `
        -OperatorLocalAppDataRoot $OperatorLocalAppDataRoot `
        -OperatorSid $OperatorSid `
        -ProfileLocalAppDataRootForTest $(if ($testOverride) { $OperatorLocalAppDataRoot } else { '' }) `
        -MachineControlRoot $MachineControlRoot `
        -SessionId $WriterFenceSessionId `
        -AttemptId $WriterFenceAttemptId `
        -ReplacementTransactionId $WriterFenceReplacementTransactionId
    $controlRoot = [string]$operatorBinding.control_root
    $Script:ContainerWriterFenceAdmissionProductionRoot = $controlRoot
    if ($MachineControlRoot) { $Script:ContainerMachineInstallControlRoot=$controlRoot }
    $preflightLease = Enter-ContainerWriterDelegatedOperation `
        -ControlRoot $controlRoot `
        -SessionId $WriterFenceSessionId `
        -AttemptId $WriterFenceAttemptId `
        -ReplacementTransactionId $WriterFenceReplacementTransactionId `
        -DelegationToken $WriterFenceDelegationToken `
        -Source $PlacementWriterSource `
        -TimeoutMilliseconds 15000
    try {
        $active = Read-ContainerWriterFence -ControlRoot $controlRoot
        $preparedMatches = (
            (Test-SamePath ([string]$active.prepared_receipt_path) ([string]$operatorBinding.receipt_path)) -and
            [string]$active.prepared_receipt_sha256 -ceq [string]$operatorBinding.receipt_sha256
        )
        if(-not $preparedMatches -and $RollbackContinuationPath) {
            $record=Read-ContainerRollbackContinuation $RollbackContinuationPath $RollbackContinuationSha256
            [void](Read-BootstrapRollbackContinuationAuthority $record $RollbackContinuationPath $RollbackContinuationSha256 $active -AllowLiveOwner)
            $link=Read-BootstrapReplacementReceipt ([string]$active.prepared_receipt_path) ([string]$active.prepared_receipt_sha256)
            $preparedMatches=(Test-SamePath ([string]$link.prepared_receipt_path) ([string]$operatorBinding.receipt_path)) -and
                [string]$link.prepared_receipt_sha256 -ceq [string]$operatorBinding.receipt_sha256
        }
        $uninstallRecovery = (
            -not [string]::IsNullOrWhiteSpace($RestoreUninstallRecordPath) -and
            [string]$ExpectedUninstallRecordSha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$active.status -ceq 'RESTORING'
        )
        if (
            [string]$active.owner_kind -cne 'canonical_installer' -or
            -not ($preparedMatches -or $uninstallRecovery)
        ) { throw 'CONTAINER_OPERATOR_PREPARED_BINDING_MISMATCH' }
    }
    finally { Exit-ContainerWriterAdmission $preflightLease }
    if (-not $testOverride) { Invoke-SelfElevated }
    return Enter-ContainerWriterDelegatedOperation `
        -ControlRoot $controlRoot `
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
    Write-InstallationCaughtFailure $_

        throw "Portable release manifest is invalid."
    }
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
            (Test-Path -LiteralPath (Join-Path (Join-Path $Root 'app') $_.Replace('/', '\')) -PathType Leaf) -and
            (Get-FileSha256 (Join-Path (Join-Path $Root 'app') $_.Replace('/', '\'))) -ceq $unsignedPe[$_]
        }).Count -eq $unsignedPe.Count
    )
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
        -not $unsignedPeOk -or
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
    catch {
    Write-InstallationCaughtFailure $_
 throw "Writer sink inventory is invalid." }
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
                throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Portable CPython signature is not valid: $relativePath")) -UserLine)
            }
        }
    }
    return 'PORTABLE_CPYTHON'
}

function Write-ElevationLog([string]$Status, [string]$Message) {
    if ([string]::IsNullOrWhiteSpace($ElevationLogPath)) { return }
    $path = Get-StrictFullPath $ElevationLogPath "ElevationLogPath"
    Assert-InstallationEvidenceWriteRoot (Split-Path -Parent $path)
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
        (ConvertTo-KmtechRedactedSinkText -Text (($entry | ConvertTo-Json -Compress) + [Environment]::NewLine)),
        (New-Object Text.UTF8Encoding($false))
    )
}

function ConvertTo-NormalizedAclRights([int64]$Rights) {
    $synchronize = [int64][System.Security.AccessControl.FileSystemRights]::Synchronize
    return $Rights -band (-bnot $synchronize)
}

function Assert-HardenedCodeAcl([string]$Path, [switch]$Recursive) {
    Assert-NoReparsePoint $Path "Hardened code ACL readback" -PathOnly:(-not $Recursive)
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
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code ACL owner is not BUILTIN\Administrators: $($target.FullName)")) -UserLine)
        }
        if ($isRoot -and -not $acl.AreAccessRulesProtected) {
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code root still inherits access rules: $($target.FullName)")) -UserLine)
        }
        if (-not $isRoot -and $acl.AreAccessRulesProtected) {
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code descendant does not inherit the root DACL: $($target.FullName)")) -UserLine)
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
                throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code DACL contains an unexpected ACE for $sid on $($target.FullName)")) -UserLine)
            }
            if (
                $isRoot -and (
                    [int]$rule.InheritanceFlags -ne $expectedRootInheritance -or
                    [string]$rule.PropagationFlags -cne 'None'
                )
            ) {
                throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code root inheritance flags differ for $sid.")) -UserLine)
            }
            if (-not $actual.ContainsKey($sid)) { $actual[$sid] = [int64]0 }
            $actual[$sid] = [int64]$actual[$sid] -bor [int64]$rule.FileSystemRights
        }
        if ($actual.Count -ne $expected.Count) {
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code DACL principal count differs: $($target.FullName)")) -UserLine)
        }
        foreach ($sid in $expected.Keys) {
            if (
                -not $actual.ContainsKey($sid) -or
                (ConvertTo-NormalizedAclRights ([int64]$actual[$sid])) -ne
                (ConvertTo-NormalizedAclRights ([int64]$expected[$sid]))
            ) {
                throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code DACL rights differ for $sid on $($target.FullName)")) -UserLine)
            }
        }
    }
}

function Assert-ProtectedCodeAncestors([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $leaf = $true
    while ($full) {
        if (Test-Path -LiteralPath $full) {
            $entry = Get-Item -Force -LiteralPath $full -ErrorAction Stop
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe update path component.' }
            $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
            if (-not (Test-BootstrapPrivilegedOwnerSid $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)) {
                throw 'Update path component owner is not privileged.'
            }
            if($full -in @('C:\KMTech','C:\KMTech\Apps')){
                try{Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit' -AdmissionOnly -ProtectedAncestor $full}
                catch{
                    $code=[int]$_.Exception.Data['installation_preparation_exit_code']
                    if($code -notin @(61,62,63)){throw}
                    $message=switch($code){62{'Unsafe update path component.'}63{'Update path component owner is not privileged.'}61{'Update path component is user mutable.'}}
                    throw [InvalidOperationException]::new($message,$_.Exception)
                }
                $full=[IO.Path]::GetDirectoryName($full);$leaf=$false;continue
            }
            $mask = if ($leaf) { 0x500D0156 } else { 0x500D0150 }
            foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and
                    -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                    $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and
                    ([int64]$rule.FileSystemRights -band $mask)) { throw 'Update path component is user mutable.' }
            }
        }
        if ($full -eq [IO.Path]::GetPathRoot($full)) { break }
        $full = [IO.Path]::GetDirectoryName($full)
        $leaf = $false
    }
}

function Assert-ContainerStartupUpdateTrust([string]$Root,[switch]$RestorePreimage) {
    Assert-ProtectedCodeAncestors (Split-Path -Parent $Root)
    if($RestorePreimage){Assert-NoReparsePoint $Root 'startup restore namespace' -PathOnly}
    else{Assert-HardenedCodeAcl $Root -Recursive}
}

function Set-HardenedCodeAcl([string]$Path, [switch]$Recursive) {
    try {
        Assert-NoReparsePoint $Path "Hardened code ACL target" -PathOnly:(-not $Recursive)
        $icacls = Join-Path ([Environment]::SystemDirectory) 'icacls.exe'
        $ownerArgs = @($Path, '/setowner', '*S-1-5-32-544', '/L')
        $resetArgs = @($Path, '/reset', '/L')
        if ($Recursive.IsPresent) {
            $ownerArgs += '/T'
            $resetArgs += '/T'
        }
        $ownerResult = Invoke-InstallationEvidenceChild 'acl-owner' $icacls $ownerArgs
        if ($ownerResult.ExitCode -ne 0) { throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code owner assignment failed: $Path")) -UserLine) }
        $resetResult = Invoke-InstallationEvidenceChild 'acl-reset' $icacls $resetArgs
        if ($resetResult.ExitCode -ne 0) { throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code DACL reset failed: $Path")) -UserLine) }
        $grantResult = Invoke-InstallationEvidenceChild 'acl-grant' $icacls @(
            $Path,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX','/L')
        if ($grantResult.ExitCode -ne 0) { throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Hardened code DACL installation failed: $Path")) -UserLine) }
        Assert-HardenedCodeAcl $Path -Recursive:$Recursive.IsPresent
    }
    catch {
    Write-InstallationCaughtFailure $_

        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("acl_readback_status=UNKNOWN")))
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
    Write-InstallationCaughtFailure $_

        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Legacy scheduled task observation failed: $Name/$($_.Exception.GetType().Name)")) -UserLine)
    }
    if ($taskMatches.Count -gt 1) {
        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Legacy scheduled task observation is non-unique: $Name")) -UserLine)
    }
    return $taskMatches
}

function Remove-OwnedLegacyTask([string]$Name, [string]$ExpectedRoot) {
    $taskMatches = @(Get-LegacyTaskByNameFailClosed $Name)
    if ($taskMatches.Count -eq 0) { return }
    $task = $taskMatches[0]
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Refusing to remove a legacy task with an ambiguous action: $Name")) -UserLine)
    }
    $actionText = "$([string]$actions[0].Execute) $([string]$actions[0].Arguments)"
    $ownedFieldLauncher = 'C:\ProgramData\KMTech\DirectSync\container_audit\bin\direct-sync-relay-container-audit.cmd'
    $owned = (
        $actionText.IndexOf($ExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $actionText.IndexOf($ownedFieldLauncher, [StringComparison]::OrdinalIgnoreCase) -ge 0
    )
    if (-not $owned) {
        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Refusing to remove a scheduled task not owned by this application: $Name")) -UserLine)
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
    catch {
    Write-InstallationCaughtFailure $_
 throw 'Legacy task removal manifest is invalid.' }
    if (
        [string]$installedManifest.writer_fence_helper_sha256 -cnotmatch '^[0-9a-f]{64}$'
    ) { throw 'Legacy task removal writer-fence helper pin differs.' }
    $writerFenceHelperFull = Get-InstallationVerifiedScript $writerFenceHelperPath ([string]$installedManifest.writer_fence_helper_sha256) 'Legacy task removal writer-fence helper pin differs.'
    . $writerFenceHelperFull
    [void](Remove-ContainerScheduledTaskUnderWriterFence `
        -SessionId ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID) `
        -AttemptId ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID) `
        -ReplacementTransactionId ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID) `
        -DelegationToken ([string]$env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN) `
        -TaskName ([string]$task.TaskName) `
        -TaskPath $taskPath)
    if (@(Get-LegacyTaskByNameFailClosed $Name).Count -ne 0) {
        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Legacy scheduled task removal readback failed: $Name")) -UserLine)
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
    [switch]$SkipOwnedTaskCheckForGuardedTest,
    [switch]$ClassifyOtherSessionPreflight
) {
    $processRoot = Get-StrictFullPath $CurrentRoot 'restore process root'
    if (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $processRoot) 'update-control\policy.json')) {
        $processRoot = Split-Path -Parent $processRoot
    }
    $rootPrefix = $processRoot + '\'
    try { $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop) }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'Replacement restore could not prove process quiescence.' }
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
    if ($matches.Count -ne 0) {
        if ($ClassifyOtherSessionPreflight.IsPresent) {
            $currentSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
            $otherSessionMatches = @($matches | Where-Object {
                $_.PSObject.Properties['SessionId'] -and $null -ne $_.SessionId -and
                [int]$_.SessionId -ne $currentSessionId
            })
            if ($otherSessionMatches.Count -ne 0) { throw 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING' }
        }
        throw 'Replacement restore requires zero Container product processes.'
    }
    if (-not $SkipOwnedTaskCheckForGuardedTest.IsPresent) {
        $policyPath = Join-Path (Split-Path -Parent $CurrentRoot) 'update-control\policy.json'
        if (Test-Path -LiteralPath $policyPath -PathType Leaf) {
            $policy = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ([string]$policy.operator_sid -cne $OperatorSid) { throw 'STARTUP_UPDATE_OPERATOR_DIFFERS' }
            $transitionPath = Join-Path (Split-Path -Parent $CurrentRoot) 'update-control\transition.json'
            if (Test-Path -LiteralPath $transitionPath) {
                $transition = Get-Content -LiteralPath $transitionPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ([string]$transition.phase -cnotin @('CONFIRMED','ROLLED_BACK','DEFERRED')) { throw 'STARTUP_UPDATE_TRANSITION_UNRESOLVED' }
            }
            [void](Get-ContainerStartupUpdateTaskPreimage $CurrentRoot)
        }
        try { $task = Get-ScheduledTask -TaskName $LegacyRelayTaskName -ErrorAction SilentlyContinue }
        catch {
    Write-InstallationCaughtFailure $_
 throw 'Replacement restore could not prove scheduled-task quiescence.' }
        if ($null -ne $task -and [string]$task.State -cne 'Disabled') {
            throw 'Replacement restore requires the owned scheduled writer to be disabled or absent.'
        }
    }
}

function Get-ContainerStartupUpdateTaskSpec([string]$Root, [string]$Sid) {
    Assert-ContainerStartupUpdateTrust $Root
    $runtime = Join-Path $Root 'runtime\python.exe'
    $implementation = Join-Path $Root 'app\auto_update.py'
    $child = Invoke-InstallationEvidenceChild 'startup-task-spec' $runtime @('-I','-B',$implementation,'--print-logon-task','--install-root',$Root,'--operator-sid',$Sid)
    $output = @($child.Stdout)
    if ($child.ExitCode -ne 0) { throw 'STARTUP_UPDATE_TASK_SPEC_FAILED' }
    $spec = ($output -join "`n") | ConvertFrom-Json
    if ([string]$spec.name -cnotmatch '^KMTech\.ContainerAudit\.StartupUpdate\.[0-9a-f]{24}$' -or
        $spec.xml -isnot [string]) { throw 'STARTUP_UPDATE_TASK_SPEC_INVALID' }
    return $spec
}

function Invoke-ContainerStartupUpdateTaskMutation([scriptblock]$Action) {
    Assert-ProtectedCodeAncestors (Split-Path -Parent $installRootFull)
    Invoke-ContainerWriterFenceMutation -ControlRoot $Script:ContainerWriterFenceAdmissionProductionRoot `
        -SessionId $WriterFenceSessionId -AttemptId $WriterFenceAttemptId `
        -ReplacementTransactionId $WriterFenceReplacementTransactionId -DelegationToken $WriterFenceDelegationToken -Action $Action
}

function Test-ContainerStartupUpdateTaskIdentity([xml]$Actual, [xml]$Expected, [string]$Sid) {
    $previousArguments = ([string]$Expected.Task.Actions.Exec.Arguments) -creplace '^(-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden) -ExecutionPolicy Bypass(?= -File ")','$1'
    return ($Actual.Task.Actions.Exec.Command -ceq $Expected.Task.Actions.Exec.Command -and
        ($Actual.Task.Actions.Exec.Arguments -ceq $Expected.Task.Actions.Exec.Arguments -or
            $Actual.Task.Actions.Exec.Arguments -ceq $previousArguments) -and
        (ConvertTo-BootstrapPrincipalSid ([string]$Actual.Task.Principals.Principal.UserId)) -ceq 'S-1-5-18' -and
        (ConvertTo-BootstrapPrincipalSid ([string]$Actual.Task.Triggers.LogonTrigger.UserId)) -ceq
            ([Security.Principal.SecurityIdentifier]::new($Sid).Value))
}

function Get-ContainerStartupUpdateTaskPreimage([string]$Root) {
    $spec = Get-ContainerStartupUpdateTaskSpec $Root $OperatorSid
    $existing = Get-ScheduledTask -TaskName $spec.name -ErrorAction SilentlyContinue
    $result = [ordered]@{name=[string]$spec.name;exists=($null -ne $existing);xml='';sddl=''}
    if ($null -ne $existing) {
        if ([string]$existing.State -ceq 'Running') { throw 'STARTUP_UPDATE_TASK_IS_RUNNING' }
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $registered = $service.GetFolder('\').GetTask($spec.name)
        if ([int]$registered.GetInstances(0).Count -ne 0) { throw 'STARTUP_UPDATE_TASK_IS_RUNNING' }
        $actual = [xml]$registered.Xml
        $expected = [xml]$spec.xml
        if (-not (Test-ContainerStartupUpdateTaskIdentity $actual $expected $OperatorSid)) { throw 'STARTUP_UPDATE_OWNED_TASK_DIFFERS' }
        $result.xml = [string]$registered.Xml
        $result.sddl = [string]$registered.GetSecurityDescriptor(7)
    }
    return $result
}

function Write-ContainerStartupUpdateRecord([string]$Path, $Payload) {
    Assert-NoReparsePoint $Path 'startup update record'
    $temporary = $Path + '.tmp.' + [guid]::NewGuid().ToString('N')
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Payload | ConvertTo-Json -Depth 12) + "`n")
    $stream = New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Invoke-ContainerAtomicReplace $temporary $Path -Mode WriteThrough
}

function Save-ContainerStartupUpdatePreimage([string]$Root, [string]$Purpose) {
    Assert-ContainerStartupUpdateTrust $Root
    $managed = Get-StrictFullPath (Split-Path -Parent $Root) 'startup update managed parent'
    $directory = Join-Path $managed ('.startup-update-' + $Purpose + '.' + $WriterFenceAttemptId)
    if (-not (Test-PathWithin $directory $managed) -or (Test-Path -LiteralPath $directory)) { throw 'STARTUP_UPDATE_PREIMAGE_PATH_INVALID' }
    New-Item -ItemType Directory -Path $directory | Out-Null
    Set-HardenedCodeAcl $directory -Recursive
    $files = @()
    foreach ($name in @('policy.json','active.json','transition.json')) {
        $path = Join-Path $managed ('update-control\' + $name)
        Assert-NoReparsePoint $path 'startup update control preimage'
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $hash = ''
        if ($exists) {
            Copy-Item -LiteralPath $path -Destination (Join-Path $directory $name)
            $hash = Get-FileSha256 $path
            if ((Get-FileSha256 (Join-Path $directory $name)) -cne $hash) { throw 'STARTUP_UPDATE_PREIMAGE_READBACK_FAILED' }
        }
        $files += [ordered]@{name=$name;exists=[bool]$exists;sha256=$hash}
    }
    $task = Get-ContainerStartupUpdateTaskPreimage $Root
    $payload = [ordered]@{schema='container-audit-startup-update-install-preimage-v1';root=$Root;operator_sid=$OperatorSid;attempt_id=$WriterFenceAttemptId;files=$files;task=$task}
    Write-ContainerStartupUpdateRecord (Join-Path $directory 'preimage.json') $payload
    return [pscustomobject]@{path=$directory;sha256=(Get-FileSha256 (Join-Path $directory 'preimage.json'))}
}

function Restore-ContainerStartupUpdatePreimage([string]$Root, [string]$Directory, [string]$ExpectedSha256) {
    # Restoration uses the protected parent and exact pinned preimage, not
    # executable bytes that an earlier rollback step may already have removed.
    Assert-ContainerStartupUpdateTrust $Root -RestorePreimage
    $managed = Get-StrictFullPath (Split-Path -Parent $Root) 'startup update restore parent'
    $full = Get-StrictFullPath $Directory 'startup update preimage'
    if (-not (Test-PathWithin $full $managed) -or (Split-Path -Leaf $full) -cnotmatch '^\.startup-update-(install|uninstall)\.[0-9a-f]{32}$') { throw 'STARTUP_UPDATE_RESTORE_PATH_INVALID' }
    Assert-NoReparsePoint $full 'startup update preimage'
    $path = Join-Path $full 'preimage.json'
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$' -or (Get-FileSha256 $path) -cne $ExpectedSha256) { throw 'STARTUP_UPDATE_RESTORE_PREIMAGE_PIN_DIFFERS' }
    $saved = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$saved.schema -cne 'container-audit-startup-update-install-preimage-v1' -or
        -not (Test-SamePath ([string]$saved.root) $Root) -or [string]$saved.operator_sid -cne $OperatorSid -or
        (@($saved.files | ForEach-Object { [string]$_.name }) -join ',') -cne 'policy.json,active.json,transition.json') { throw 'STARTUP_UPDATE_RESTORE_BINDING_DIFFERS' }
    $currentTask = Get-ScheduledTask -TaskName ([string]$saved.task.name) -ErrorAction SilentlyContinue
    if ($null -ne $currentTask -and [string]$currentTask.State -ceq 'Running') { throw 'STARTUP_UPDATE_TASK_IS_RUNNING' }
    $control = Join-Path $managed 'update-control'
    foreach ($item in @($saved.files)) {
        $target = Join-Path $control ([string]$item.name)
        Assert-NoReparsePoint $target 'startup update restore target'
        if ($item.exists -isnot [bool]) { throw 'STARTUP_UPDATE_RESTORE_EXISTENCE_INVALID' }
        if (($item.exists -and (Test-Path -LiteralPath $target -PathType Leaf) -and
            (Get-FileSha256 $target) -ceq [string]$item.sha256) -or
            (-not $item.exists -and -not (Test-Path -LiteralPath $target))) {continue}
        if (Test-Path -LiteralPath $target) {
            Move-Item -LiteralPath $target -Destination (Join-Path $full ('failed-' + [guid]::NewGuid().ToString('N') + '-' + $item.name))
        }
        if ($item.exists) {
            $original = Join-Path $full ([string]$item.name)
            if ((Get-FileSha256 $original) -cne [string]$item.sha256) { throw 'STARTUP_UPDATE_RESTORE_BYTES_DIFFER' }
            Copy-Item -LiteralPath $original -Destination $target
            if ((Get-FileSha256 $target) -cne [string]$item.sha256) { throw 'STARTUP_UPDATE_RESTORE_READBACK_FAILED' }
        }
    }
    Invoke-ContainerStartupUpdateTaskMutation {
        $name = [string]$saved.task.name
        if ($name -cnotmatch '^KMTech\.ContainerAudit\.StartupUpdate\.[0-9a-f]{24}$') { throw 'STARTUP_UPDATE_RESTORE_TASK_NAME_INVALID' }
        $existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($null -ne $existing -and [string]$existing.State -ceq 'Running') { throw 'STARTUP_UPDATE_TASK_IS_RUNNING' }
        if ($saved.task.exists -isnot [bool]) { throw 'STARTUP_UPDATE_RESTORE_TASK_EXISTENCE_INVALID' }
        if ($saved.task.exists) {
            Register-ScheduledTask -TaskName $name -Xml ([string]$saved.task.xml) -Force | Out-Null
            $service = New-Object -ComObject 'Schedule.Service'; $service.Connect()
            $registered = $service.GetFolder('\').GetTask($name)
            $registered.SetSecurityDescriptor([string]$saved.task.sddl,0)
            if ((Get-BootstrapAclComparisonKey ([string]$registered.GetSecurityDescriptor(7))) -cne (Get-BootstrapAclComparisonKey ([string]$saved.task.sddl)) -or [string]$registered.Xml -cne [string]$saved.task.xml) { throw 'STARTUP_UPDATE_RESTORE_TASK_READBACK_FAILED' }
        } elseif ($null -ne $existing) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            if ($null -ne (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) { throw 'STARTUP_UPDATE_RESTORE_TASK_REMOVAL_FAILED' }
        }
    } | Out-Null
}

function Get-ContainerStartupRepairObservation([string]$Root) {
    $control=Join-Path (Split-Path -Parent $Root) 'update-control'
    $files=@()
    foreach($name in @('policy.json','active.json','transition.json')){
        $path=Join-Path $control $name
        Assert-NoReparsePoint $path 'startup repair observation' -PathOnly
        $exists=Test-Path -LiteralPath $path -PathType Leaf
        $files+=@([pscustomobject]@{name=$name;exists=[bool]$exists;sha256=$(if($exists){Get-FileSha256 $path}else{''})})
    }
    $task=Get-ContainerStartupUpdateTaskPreimage $Root
    $specSha=''
    if($task.exists){$specSha=Get-BootstrapStringSha256 (([xml]$task.xml).OuterXml)}
    return [pscustomobject]@{control_files=$files;task_exists=[bool]$task.exists;
        task_spec_sha256=$specSha;task_security_sha256=$(if($task.exists){Get-BootstrapStringSha256 ([string]$task.sddl)}else{''})}
}

function Write-ContainerStartupRepairResult([string]$Root,$Before,[string]$Status) {
    $after=Get-ContainerStartupRepairObservation $Root
    $comparison=if($Before.task_exists -eq $after.task_exists -and $Before.task_spec_sha256 -ceq $after.task_spec_sha256){'UNCHANGED'}else{'CHANGED'}
    Write-InstallationEvidenceEvent ([ordered]@{event='STARTUP_REPAIR_AFTER';status=$Status;
        code_placement='UNCHANGED';before=$Before;after=$after;task_spec_disposition=$comparison})
}

function Initialize-ContainerStartupUpdate([string]$Root) {
    $settingsPath = Join-Path $Root 'app\auto-update-settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) { return }
    if ($testOverride) { Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('startup_update_status=NOT_TESTED_HOST'))); return }
    Set-InstallationEvidenceStage 'startup.trust' 'startup'
    Assert-ContainerStartupUpdateTrust $Root
    $repairBefore=$null
    if((Get-Variable -Name bootstrapStatus -ValueOnly -ErrorAction SilentlyContinue) -ceq 'REUSED'){
        $repairBefore=Get-ContainerStartupRepairObservation $Root
        Write-InstallationEvidenceEvent ([ordered]@{event='STARTUP_REPAIR_BEFORE';status='IN_PROGRESS';code_placement='UNCHANGED';before=$repairBefore})
    }
    try {
    Set-InstallationEvidenceStage 'startup.save_preimage' 'startup'
    if ($null -eq $Script:StartupUpdatePreimage) {
        $Script:StartupUpdatePreimage = Save-ContainerStartupUpdatePreimage $Root 'install'
    }
    $managed = Get-StrictFullPath (Split-Path -Parent $Root) 'startup update managed root'
    Assert-NoReparsePoint $managed 'startup update managed root'
    Set-InstallationEvidenceStage 'startup.prepare_directories' 'startup'
    $control = Join-Path $managed 'update-control'
    $versions = Join-Path $managed 'versions'
    foreach ($directory in @($control,$versions)) {
        Assert-NoReparsePoint $directory 'startup update protected directory'
        New-InstallationProtectedDirectory $directory $OperatorSid
    }
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifest = Get-Content -LiteralPath (Join-Path $Root 'portable-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or $manifest.startup_update_protocol -ne 1) {
        throw 'STARTUP_UPDATE_INITIAL_VERSION_INVALID'
    }
    Set-InstallationEvidenceStage 'startup.initial_version' 'startup'
    $version = Join-Path $versions ([string]$manifest.source_commit)
    if (-not (Test-Path -LiteralPath $version)) {
        Copy-Item -LiteralPath $Root -Destination $version -Recurse
        if ((Get-InventoryAggregate @(Get-CodeInventory $version)) -cne (Get-InventoryAggregate @(Get-CodeInventory $Root))) {
            throw 'STARTUP_UPDATE_INITIAL_VERSION_READBACK_FAILED'
        }
        [void](Write-BootstrapIntegrityRecord -Root $version -CodeRootIdentity $version)
        Set-HardenedCodeAcl $version -Recursive
    } else {
        [void](Assert-BootstrapIntegrityRecord $version)
        if ((Get-InventoryAggregate @(Get-CodeInventory $version)) -cne (Get-InventoryAggregate @(Get-CodeInventory $Root))) {
            throw 'STARTUP_UPDATE_VERSION_ALREADY_HAS_DIFFERENT_BYTES'
        }
    }
    Set-InstallationEvidenceStage 'startup.policy_prerequisites' 'startup'
    $hiberboot = $null
    $hiberbootReadStatus = 'UNPROVEN'
    try {
        $hiberboot = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled
        $hiberbootReadStatus = 'READ'
    } catch {
    Write-InstallationCaughtFailure $_
 $hiberbootReadStatus = 'UNREADABLE' }
    $policy = [ordered]@{
        schema='container-audit-startup-update-policy-v1'
        feed_url=[string]$settings.feed_url;channel=[string]$settings.channel
        profile_auth=[bool]$settings.profile_auth
        approved_transitions=@($settings.approved_transitions);apply_during_work=$false
        operator_sid=$OperatorSid;operator_local_app_data=$OperatorLocalAppDataRoot
        staging_root=(Join-Path $OperatorLocalAppDataRoot 'KMTech\ContainerAudit\updates')
        hiberboot_enabled=$hiberboot;hiberboot_read_status=$hiberbootReadStatus
    }
    if ($settings.apply_during_work -isnot [bool] -or $settings.apply_during_work) { throw 'STARTUP_UPDATE_DURING_WORK_FORBIDDEN' }
    $policyPath = Join-Path $control 'policy.json'
    if (Test-Path -LiteralPath $policyPath) {
        $old = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$old.operator_sid -cne $OperatorSid -or -not (Test-SamePath ([string]$old.operator_local_app_data) $OperatorLocalAppDataRoot)) {
            throw 'STARTUP_UPDATE_OPERATOR_BINDING_DIFFERS'
        }
        Copy-Item -LiteralPath $policyPath -Destination (Join-Path $control ('policy-before-' + $WriterFenceAttemptId + '.json'))
    }
    $failedShas = @()
    $oldTransitionPath = Join-Path $Script:StartupUpdatePreimage.path 'transition.json'
    if (Test-Path -LiteralPath $oldTransitionPath) {
        $oldTransition = Get-Content -LiteralPath $oldTransitionPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $failedShas = @($oldTransition.failed_shas)
    }
    Set-InstallationEvidenceStage 'startup.control_records' 'startup'
    Write-ContainerStartupUpdateRecord (Join-Path $control 'transition.json') ([ordered]@{schema='container-audit-startup-update-v1';phase='DEFERRED';deferred_at=(Get-Date).ToUniversalTime().ToString('o');reason='canonical installation';failed_shas=$failedShas})
    Write-ContainerStartupUpdateRecord $policyPath $policy
    Write-ContainerStartupUpdateRecord (Join-Path $control 'active.json') ([ordered]@{schema='container-audit-startup-update-v1';sha=[string]$manifest.source_commit;transition_id='CANONICAL_INSTALL'})
    Set-InstallationEvidenceStage 'startup.task_spec' 'startup'
    $spec = Get-ContainerStartupUpdateTaskSpec $Root $OperatorSid
    $writerFenceHelperFull = Get-StrictFullPath $WriterFenceHelperPath 'startup update writer fence helper'
    . (Get-InstallationVerifiedScript $writerFenceHelperFull $ExpectedWriterFenceHelperSha256 'STARTUP_UPDATE_WRITER_HELPER_PIN_DIFFERS')
    Set-InstallationEvidenceStage 'startup.register_task_sddl' 'startup'
    Invoke-ContainerWriterFenceMutation -ControlRoot $Script:ContainerWriterFenceAdmissionProductionRoot `
        -SessionId $WriterFenceSessionId -AttemptId $WriterFenceAttemptId `
        -ReplacementTransactionId $WriterFenceReplacementTransactionId -DelegationToken $WriterFenceDelegationToken -Action {
            $existing = Get-ScheduledTask -TaskName $spec.name -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                $oldXml = [xml](Export-ScheduledTask -TaskName $spec.name)
                $newXml = [xml]$spec.xml
                if (-not (Test-ContainerStartupUpdateTaskIdentity $oldXml $newXml $OperatorSid)) { throw 'STARTUP_UPDATE_OWNED_TASK_DIFFERS' }
                if ([string]$existing.State -ceq 'Running') { throw 'STARTUP_UPDATE_TASK_IS_RUNNING' }
            }
            Register-ScheduledTask -TaskName $spec.name -Xml $spec.xml -Force | Out-Null
            $service = New-Object -ComObject 'Schedule.Service'
            $service.Connect()
            $registered = $service.GetFolder('\').GetTask($spec.name)
            $registered.SetSecurityDescriptor(('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;' + $OperatorSid + ')'),0)
            $actual = [xml]$registered.Xml
            $expected = [xml]$spec.xml
            if (-not (Test-ContainerStartupUpdateTaskIdentity $actual $expected $OperatorSid)) { throw 'STARTUP_UPDATE_TASK_READBACK_FAILED' }
        } | Out-Null
    Complete-InstallationEvidenceStage 'startup'
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('startup_update_status=REGISTERED_LOGON_SYSTEM_CODE_ONLY')))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('startup_update_task=' + $spec.name))))
    $hiberbootCode=if($hiberboot -eq 1){'HIBERBOOT_ENABLED'}elseif($hiberboot -eq 0){'HIBERBOOT_DISABLED'}else{'HIBERBOOT_UNKNOWN'}
    Write-InstallationHelperPublicRecord @{status='PASS';reason_code=$hiberbootCode}
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('hiberboot_read_status=' + $hiberbootReadStatus))))
    if($null -ne $repairBefore){Write-ContainerStartupRepairResult $Root $repairBefore 'PASS'}
    } catch {
        $repairFailure=$_
        if($null -ne $repairBefore){
            try { Write-ContainerStartupRepairResult $Root $repairBefore 'FAILED' }
            catch { $repairFailure.Exception.Data['startup_repair_audit_failure_type']=$_.Exception.GetType().FullName }
        }
        throw $repairFailure
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
if (-not $OperatorSid) {
    $OperatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $BootstrapBoundParameters['OperatorSid'] = $OperatorSid
}
if (-not $OperatorDataRoot -and $env:CONTAINER_AUDIT_DATA_ROOT) {
    $OperatorDataRoot = Get-StrictFullPath $env:CONTAINER_AUDIT_DATA_ROOT 'operator data root'
    $BootstrapBoundParameters['OperatorDataRoot'] = $OperatorDataRoot
}
if ($ApplyHardenedAclForTest.IsPresent -and -not $testOverride) {
    throw "ApplyHardenedAclForTest requires the guarded noncanonical test layout."
}
if ($InjectRestoreFailureAfterDisplaceForTest.IsPresent -and -not $testOverride) {
    throw 'InjectRestoreFailureAfterDisplaceForTest requires the guarded noncanonical test layout.'
}
if($RemoveUncommittedPlacement.IsPresent -and -not $Uninstall.IsPresent){
    throw 'RemoveUncommittedPlacement requires Uninstall and the protected transaction handover.'
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
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('replacement_restore_status=DRY_RUN')))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('replacement_restore_schema=container-audit-verified-replacement-v1')))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('replacement_restore_receipt_required_at_apply=true')))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('identity_profile_created=false')))
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
# External input admission precedes placement ownership and elevation logs.
$containerExternalInputs = @('ReplacementReceiptPath', 'RestoreUninstallRecordPath')
if (-not $DryRun.IsPresent) { $containerExternalInputs += 'TlsCaBundlePath' }
foreach ($inputName in $containerExternalInputs) {
    $inputValue = [string](Get-Variable -Name $inputName -ValueOnly)
    if ([string]::IsNullOrWhiteSpace($inputValue)) { continue }
    try {
        $inputFull = Get-StrictFullPath `
            ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($inputValue)) $inputName
    } catch {
        throw '이 PC의 자료 판을 확인할 수 없어 옛 판으로 되돌릴 수 없습니다. 자료와 확인 기록을 보존하고 관리자 지원 복구를 요청하세요.'
    }
    Set-Variable -Name $inputName -Value $inputFull
    $BootstrapBoundParameters[$inputName] = $inputFull
    Assert-ContainerDataGenerationTarget -CandidateRoot $PSScriptRoot -TargetSid $OperatorSid `
        -LocalAppDataRoot $OperatorLocalAppDataRoot -DataRoot (Split-Path -Parent $inputFull) -HelperRoot $PSScriptRoot
}
# End external input admission.
$helperInstallationEvidenceRoot=''
if (-not $DryRun.IsPresent -and ($ElevationLogPath -or (Test-InstallationEvidencePrivileged))) {
    if(-not $ElevationLogPath){$ElevationLogPath='helper-audit'}
    try{
        # Prepare shared ancestors and the protected app/control/run before
        # evidence creation or delegated writer-fence acquisition.
        $helperInstallationEvidenceRoot=Initialize-InstallationEvidence $ElevationLogPath $OperatorSid @($WriterFenceDelegationToken)
    }catch{
        if(Test-InstallationEvidencePrivileged){exit (Get-InstallationPreparationExitCode $_)}
        throw
    }
    if(Test-InstallationEvidencePrivileged){
        $ElevationLogPath=Join-Path $helperInstallationEvidenceRoot 'placement-result.jsonl'
        if($ReplaceExistingVerifiedPortable -and $ReplacementReceiptPath){$ReplacementReceiptPath=Join-Path $helperInstallationEvidenceRoot 'replacement-receipt.json'}
        if($RestoreEvidencePath){$RestoreEvidencePath=Join-Path $helperInstallationEvidenceRoot 'restore-evidence.json'}
    }
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("installation_stage_evidence_root=$helperInstallationEvidenceRoot")))
    Set-InstallationEvidenceStage 'placement.writer_fence_preflight'
}
$placementWriterFenceLease = $null
$Script:StartupUpdatePreimage = $null
if (-not $CompleteRollbackContinuation -and -not $RecordRollbackContinuationAuthority -and -not $DryRun.IsPresent -and (-not $testOverride -or $Uninstall.IsPresent -or $RestoreUninstallRecordPath)) {
    try {
        $placementWriterFenceLease = Enter-ContainerPlacementWriterFence
        . (Get-InstallationVerifiedScript $WriterFenceHelperPath $ExpectedWriterFenceHelperSha256)
        $Script:ContainerWriterFenceAdmissionProductionRoot = if($MachineControlRoot){$MachineControlRoot}else{Join-Path $OperatorLocalAppDataRoot 'KMTech\DirectSync\container_audit\control\writer-session'}
        if(-not $testOverride -and -not $Uninstall.IsPresent) {
            Set-InstallationEvidenceStage 'placement.protect_shared_ancestors'
            [void](Protect-KmtechCodeAncestors (Split-Path -Parent $installRootFull))
        }
    }
    catch {
    Write-InstallationCaughtFailure $_

        $failureCode = Get-CodePlacementPreflightFailureCode $_
        Fail-InstallationEvidenceStages $_
        if($failureCode -ceq 'CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED') {
            $candidate=$_.Exception
            for($depth=0;$null -ne $candidate -and $depth -lt 8;$depth++) {
                if($candidate.Data.Contains('ancestor_trust_failure')){Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('ancestor_trust_failure='+[string]$candidate.Data['ancestor_trust_failure']))));break}
                $candidate=$candidate.InnerException
            }
        }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            try {
                Write-ElevationLog 'PREFLIGHT_FAILED' $failureCode
            } catch {
    Write-InstallationCaughtFailure $_

                Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('code_placement_preflight_failure=CONTAINER_PLACEMENT_LOG_WRITE_FAILED')))
                exit 42
            }
        }
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("code_placement_preflight_failure=$failureCode")))
        throw
    }
}
try {
if($RecordRollbackContinuationAuthority) {
    if($DryRun -or $Uninstall -or $ReplaceExistingVerifiedPortable -or $RestoreVerifiedReplacement -or $CompleteRollbackContinuation -or $RecordRollbackContinuation){throw 'Rollback authority linkage accepts only protected evidence inputs.'}
    . ( Get-InstallationVerifiedScript $WriterFenceHelperPath $ExpectedWriterFenceHelperSha256)
    Write-ContainerRollbackContinuationAuthority
    'rollback_continuation_authority=RECORDED'
    exit 0
}
if ($CompleteRollbackContinuation) {
    if ($DryRun -or $Uninstall -or $RecordRollbackContinuation -or $ReplaceExistingVerifiedPortable -or $RestoreVerifiedReplacement -or $testOverride) {throw 'Rollback completion accepts only protected evidence inputs.'}
    . ( Get-InstallationVerifiedScript $WriterFenceHelperPath $ExpectedWriterFenceHelperSha256)
    Complete-ContainerRollbackContinuation
    'rollback_continuation_status=COMPLETE'
    exit 0
}
if ($RecordRollbackContinuation) {
    if ($DryRun -or $Uninstall -or $ReplaceExistingVerifiedPortable -or $RestoreVerifiedReplacement -or
        -not $WriterFencePreparedReceiptPath -or -not $WriterFenceDelegationToken -or $testOverride) {
        throw 'Rollback continuation recording requires the live canonical placement authority.'
    }
    [void](Write-ContainerRollbackContinuation $RollbackAuditPath $RollbackAuditSha256)
    'rollback_continuation_status=RECORDED'
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
        Assert-ContainerDataGenerationTarget -CandidateRoot ([string]$receipt.rollback_root) `
            -TargetSid $OperatorSid -LocalAppDataRoot $OperatorLocalAppDataRoot `
            -DataRoot $OperatorDataRoot -HelperRoot $PSScriptRoot
        $receiptBindingPath=$ReplacementReceiptPath
        if ($RollbackContinuationPath) {
            $continuation=Read-ContainerRollbackContinuation $RollbackContinuationPath $RollbackContinuationSha256
            if (-not (Test-SamePath $ReplacementReceiptPath ([string]$continuation.receipt_path)) -or
                $ReplacementReceiptSha256 -cne [string]$continuation.receipt_sha256) {throw 'Rollback continuation restore input differs.'}
            $receiptBindingPath=[string]$continuation.receipt_binding_path
        }
        $result = Invoke-BootstrapVerifiedReplacementRestore `
            -Receipt $receipt `
            -ReceiptPath $receiptBindingPath `
            -InstallRoot $installRootFull `
            -ExpectedAppId 'container_audit' `
            -ExpectedTransactionId $ReplacementTransactionId `
            -ExpectedHelperSha256 (Get-FileSha256 $BootstrapScriptPath) `
            -InjectFailureAfterDisplace:$InjectRestoreFailureAfterDisplaceForTest.IsPresent
        if ($receipt.PSObject.Properties['startup_update_preimage']) {
            Restore-ContainerStartupUpdatePreimage $installRootFull ([string]$receipt.startup_update_preimage) ([string]$receipt.startup_update_preimage_sha256)
        }
        if (
            $result.prior_code_exact -isnot [bool] -or
            -not $result.prior_code_exact -or
            $result.failed_new_preserved -isnot [bool] -or
            -not $result.failed_new_preserved
        ) { throw 'Replacement restore result Boolean evidence is invalid.' }
        $shortcutRecord=Get-BootstrapWorkerShortcutCommonRecordPath $installRootFull
        [void](Restore-BootstrapWorkerShortcuts $installRootFull $shortcutRecord 'Common')
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
        Write-InstallationEvidenceEvent ([ordered]@{event='RESTORE_EVIDENCE_READY';path=$restoreEvidenceFull;sha256=Get-FileSha256 $restoreEvidenceFull})
        if (-not $testOverride) { Write-ElevationLog 'PASS' 'Elevated Container verified replacement restore completed.' }
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_restore_status=$($result.status)")))
        Write-InstallationHelperPublicRecord @{restore_evidence_path=$restoreEvidenceFull}
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_restore_evidence_sha256=$(Get-FileSha256 $restoreEvidenceFull)")))
        exit 0
    }
    catch {
    Write-InstallationCaughtFailure $_

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
        try { Write-BootstrapReplacementReceipt -Path $restoreEvidenceFull -Payload $failure | Out-Null } catch {
    Write-InstallationCaughtFailure $_
}
        if (-not $testOverride) { Write-ElevationLog 'FAILED' 'Elevated Container verified replacement restore failed.' }
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('replacement_restore_status=ROLLBACK_FAILED')))
        Write-InstallationHelperPublicRecord @{restore_evidence_path=$restoreEvidenceFull}
        throw
    }
}
if (-not $DryRun.IsPresent -and -not $testOverride) {
    Set-InstallationEvidenceStage 'placement.source_validation'
    Write-ElevationLog 'STARTED' 'Elevated Container code placement started.'
}

function Get-ContainerRemovalIoPath([string]$Path) {
    if ($Path.Length -lt 240 -or $Path.StartsWith('\\?\')) { return $Path }
    $native = $Path.Replace('/','\')
    if ($native.StartsWith('\\')) { return '\\?\UNC\' + $native.Substring(2) }
    return '\\?\' + $native
}

function Assert-ContainerRemovalBoundary([string]$Path) {
    # Inspect ancestors, never enumerate opaque control/code children.
    $component = [IO.Path]::GetFullPath((Get-ContainerRemovalIoPath $Path))
    while ($component) {
        if (Test-Path -LiteralPath (Get-ContainerRemovalIoPath $component) -ErrorAction Stop) {
            $item = Get-Item -LiteralPath (Get-ContainerRemovalIoPath $component) -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REMOVAL_BOUNDARY_REDIRECTED' }
        }
        $component = [IO.Path]::GetDirectoryName($component)
    }
}

function Get-ContainerTransactionRemovalControllerProcessId([object[]]$ProcessRows) {
    if($null -eq $placementWriterFenceLease){throw 'TRANSACTION_REMOVAL_ADMISSION_REQUIRED'}
    if(-not $testOverride){Assert-InstallationEvidenceProtectedPath $TransactionHandoverPath}
    $handover=(Read-InstallationTransactionFile $TransactionHandoverPath $TransactionHandoverSha256).Record
    $active=Read-ContainerWriterFence -ControlRoot $Script:ContainerWriterFenceAdmissionProductionRoot
    Assert-ContainerWriterSessionAuthority $active
    if([string]$handover.session_id -cne $WriterFenceSessionId -or [string]$handover.attempt_id -cne $WriterFenceAttemptId -or
        [string]$handover.transaction_id -cne $WriterFenceReplacementTransactionId -or
        [string]$active.session_id -cne $WriterFenceSessionId -or [string]$active.attempt_id -cne $WriterFenceAttemptId -or
        [string]$active.replacement_transaction_id -cne $WriterFenceReplacementTransactionId -or
        [string]$active.prepared_receipt_path -cne $WriterFencePreparedReceiptPath -or
        [string]$active.prepared_receipt_sha256 -cne $WriterFencePreparedReceiptSha256 -or
        [string]$handover.prepared_path -cne $WriterFencePreparedReceiptPath -or
        [string]$handover.prepared_sha256 -cne $WriterFencePreparedReceiptSha256 -or
        (Get-ContainerWriterFenceFileSha256 $WriterFencePreparedReceiptPath 65536) -cne $WriterFencePreparedReceiptSha256){
        throw 'TRANSACTION_REMOVAL_AUTHORITY_BINDING_DIFFERS'
    }
    $own=@($ProcessRows|Where-Object {[int]$_.ProcessId -eq $PID})
    $owner=@($ProcessRows|Where-Object {[int]$_.ProcessId -eq [int]$handover.helper_process_id})
    if($own.Count -ne 1 -or $owner.Count -ne 1 -or [int]$own[0].ParentProcessId -ne [int]$handover.helper_process_id -or
        -not(Test-SamePath ([string]$owner[0].ExecutablePath) (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')) -or
        [string]$handover.helper_command_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-BootstrapStringSha256 ([string]$owner[0].CommandLine)) -cne [string]$handover.helper_command_sha256 -or
        (Get-Process -Id ([int]$handover.helper_process_id)).StartTime.ToUniversalTime().ToString('o') -cne [string]$handover.helper_started_at_utc){
        throw 'TRANSACTION_REMOVAL_DIRECT_PARENT_DIFFERS'
    }
    $ids=@([int]$handover.helper_process_id)
    # The bound ordinary controller can mention InstallRoot in its command line.
    # Parent loss is allowed; a surviving PID must retain its creation identity.
    $parent=Get-Process -Id ([int]$handover.parent_process_id) -ErrorAction SilentlyContinue
    if($null -ne $parent){
        if($parent.StartTime.ToUniversalTime().ToString('o') -cne [string]$handover.parent_started_at_utc){throw 'TRANSACTION_REMOVAL_PARENT_IDENTITY_DIFFERS'}
        $ids += [int]$handover.parent_process_id
    }
    return $ids
}

function Get-ContainerRemovalControllerProcessId([object[]]$ProcessRows) {
    if($RemoveUncommittedPlacement){return Get-ContainerTransactionRemovalControllerProcessId $ProcessRows}
    # A delegated helper may exclude only its verified canonical controller.
    # The caller already holds the placement admission; retain that admission
    # and recheck the existing session authority before reading its binding.
    if ($null -eq $placementWriterFenceLease -or $RemovalControllerProcessId -le 0 -or
        [string]::IsNullOrWhiteSpace($RemovalControllerStartedAtUtc) -or
        [string]::IsNullOrWhiteSpace($RemovalControllerCanonicalPath)) {
        throw 'REMOVAL_CONTROLLER_BINDING_REQUIRED'
    }
    $active = Read-ContainerWriterFence -ControlRoot $Script:ContainerWriterFenceAdmissionProductionRoot
    Assert-ContainerWriterSessionAuthority $active
    if ([string]$active.owner_kind -cne 'canonical_installer' -or
        [string]$active.session_id -cne $WriterFenceSessionId -or
        [string]$active.attempt_id -cne $WriterFenceAttemptId -or
        [string]$active.replacement_transaction_id -cne $WriterFenceReplacementTransactionId -or
        -not (Test-SamePath ([string]$active.prepared_receipt_path) $WriterFencePreparedReceiptPath) -or
        [string]$active.prepared_receipt_sha256 -cne $WriterFencePreparedReceiptSha256 -or
        (Get-ContainerWriterFenceFileSha256 $WriterFencePreparedReceiptPath 65536) -cne $WriterFencePreparedReceiptSha256) {
        throw 'REMOVAL_CONTROLLER_AUTHORITY_BINDING_INVALID'
    }
    $prepared = Get-Content -LiteralPath $WriterFencePreparedReceiptPath -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    if ([string]$prepared.session_id -cne [string]$active.session_id -or
        [string]$prepared.attempt_id -cne [string]$active.attempt_id -or
        [string]$prepared.replacement_transaction_id -cne [string]$active.replacement_transaction_id -or
        [string]$prepared.orchestrator_sha256 -cne [string]$active.orchestrator_sha256 -or
        [string]$prepared.writer_contract_sha256 -cne [string]$active.writer_contract_sha256) {
        throw 'REMOVAL_CONTROLLER_PREPARED_BINDING_INVALID'
    }
    $canonical = Get-StrictFullPath $RemovalControllerCanonicalPath 'removal controller canonical'
    $managerRoot = Split-Path -Parent $canonical
    $applicationRoot = Split-Path -Parent $installRootFull
    if (-not (Test-SamePath $canonical (Join-Path $managerRoot 'INSTALL_CANONICAL_PORTABLE.ps1')) -or
        (Test-SamePath $managerRoot $applicationRoot) -or (Test-PathWithin $managerRoot $applicationRoot) -or
        (Test-PathWithin $applicationRoot $managerRoot)) {
        throw 'REMOVAL_CONTROLLER_EXTERNAL_CANONICAL_REQUIRED'
    }
    Assert-NoReparsePoint $canonical 'removal controller canonical'
    $managerManifest = Join-Path $managerRoot 'portable-manifest.json'
    Assert-NoReparsePoint $managerManifest 'removal controller manifest'
    if ((Get-FileSha256 $canonical) -cne [string]$active.orchestrator_sha256 -or
        (Get-ContainerWriterFenceFileSha256 $managerManifest 1048576) -cne [string]$prepared.source_manifest_sha256) {
        throw 'REMOVAL_CONTROLLER_SOURCE_BINDING_INVALID'
    }
    $ownRows = @($ProcessRows | Where-Object { [int]$_.ProcessId -eq $PID })
    if ($ownRows.Count -ne 1) { throw 'REMOVAL_CONTROLLER_ANCESTRY_INVALID' }
    $parentPid = [int]$ownRows[0].ParentProcessId
    $seen = @{}
    $controller = $null
    for ($depth = 0; $parentPid -gt 0 -and $depth -lt 8; $depth++) {
        if ($seen.ContainsKey($parentPid)) { throw 'REMOVAL_CONTROLLER_ANCESTRY_INVALID' }
        $seen[$parentPid] = $true
        $ancestors = @($ProcessRows | Where-Object { [int]$_.ProcessId -eq $parentPid })
        if ($ancestors.Count -ne 1) { throw 'REMOVAL_CONTROLLER_ANCESTRY_INVALID' }
        if ($parentPid -eq $RemovalControllerProcessId) { $controller = $ancestors[0]; break }
        $parentPid = [int]$ancestors[0].ParentProcessId
    }
    $controllerEngineVerified=$null -ne $controller -and
        (Test-SamePath ([string]$controller.ExecutablePath) (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'))
    if (-not $controllerEngineVerified -and $null -ne $controller -and $MachineControlRoot) {
        $pwsh=Get-StrictFullPath ([string]$controller.ExecutablePath) 'machine removal controller engine'
        $programFiles=(Get-StrictFullPath $env:ProgramFiles 'ProgramFiles').TrimEnd('\')+'\'
        if ([IO.Path]::GetFileName($pwsh) -ieq 'pwsh.exe' -and
            $pwsh.StartsWith($programFiles,[StringComparison]::OrdinalIgnoreCase)) {
            # Store package ancestors have additional package ACL principals.
            # Authenticate the actual Microsoft engine while retaining the
            # canonical source, authority tuple and live ancestry bindings.
            Assert-NoReparsePoint $pwsh 'machine removal controller engine'
            $signature=Get-AuthenticodeSignature -LiteralPath $pwsh
            $controllerEngineVerified=[string]$signature.Status -ceq 'Valid' -and
                [string]$signature.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)'
        }
    }
    if ($null -eq $controller -or -not $controllerEngineVerified -or
        ([string]$controller.CommandLine).IndexOf($canonical,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw 'REMOVAL_CONTROLLER_NOT_VERIFIED_ANCESTOR'
    }
    $started = ConvertTo-ContainerWriterFenceUtc $RemovalControllerStartedAtUtc
    $process = Get-Process -Id $RemovalControllerProcessId -ErrorAction Stop
    if ($started.ToString('o') -cne $RemovalControllerStartedAtUtc -or
        $process.StartTime.ToUniversalTime().ToString('o') -cne $RemovalControllerStartedAtUtc) {
        throw 'REMOVAL_CONTROLLER_PROCESS_IDENTITY_CHANGED'
    }
    return [int]$RemovalControllerProcessId
}

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

function Get-ContainerRemovalTaskNames($Folder, [string]$CurrentRoot) {
    $names = @('direct-sync-relay-container-audit','container-audit-isolated-qualification-authority')
    foreach ($task in @($Folder.GetTasks(1))) {
        if ([string]$task.Name -cnotmatch '^KMTech\.ContainerAudit\.StartupUpdate\.[0-9a-f]{24}$') { continue }
        $xml = [xml]$task.Xml
        $sid = [string]$xml.Task.Triggers.LogonTrigger.UserId
        if ($sid -cnotmatch '^S-1-(?:[0-9]+-)+[0-9]+$') { throw 'REMOVAL_TASK_IDENTITY_UNKNOWN' }
        $raw = [Text.Encoding]::UTF8.GetBytes($CurrentRoot.ToLowerInvariant().Replace('/','\') + "`n" + $sid)
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $suffix = ([BitConverter]::ToString($hash.ComputeHash($raw))).Replace('-','').ToLowerInvariant().Substring(0,24) }
        finally { $hash.Dispose() }
        if ([string]$task.Name -cne ('KMTech.ContainerAudit.StartupUpdate.' + $suffix)) { continue }
        $expected = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $CurrentRoot 'tools\apply_prepared_update.ps1') + '" -InstallRoot "' + $CurrentRoot + '"'
        $previous = $expected -creplace '^(-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden) -ExecutionPolicy Bypass(?= -File ")','$1'
        $command = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        if (([string]$xml.Task.Actions.Exec.Arguments -cne $expected -and [string]$xml.Task.Actions.Exec.Arguments -cne $previous) -or
            -not (Test-SamePath ([string]$xml.Task.Actions.Exec.Command) $command) -or
            [string]$xml.Task.Principals.Principal.UserId -cne 'S-1-5-18' -or
            @($xml.Task.Actions.Exec).Count -ne 1) { throw 'REMOVAL_TASK_IDENTITY_UNKNOWN' }
        $names += [string]$task.Name
    }
    return $names
}

function Remove-ContainerScheduledTasks($Folder, [string]$EvidenceRoot, [string]$CurrentRoot) {
    foreach ($name in @(Get-ContainerRemovalTaskNames $Folder $CurrentRoot)) {
        $task = $null
        try { $task = $Folder.GetTask($name) }
        catch { $failure=$_.Exception; while ($null -ne $failure.InnerException) { $failure=$failure.InnerException }; if ($failure.HResult -ne -2147024894) { throw } }
        if ($null -ne $task) {
            Write-ContainerStartupUpdateRecord -Path (Join-Path $EvidenceRoot ($name + '.json')) -Payload @{
                name=$name; xml=$task.Xml; sddl=$task.GetSecurityDescriptor(7)
            }
            if($name -ieq 'direct-sync-relay-container-audit'){
                $identity=Get-BootstrapOfficialLegacyRelayIdentity ([pscustomobject]@{TaskName=$name;TaskPath='\'}) ([string]$task.Xml)
                if(-not $identity.matched){throw 'REMOVAL_TASK_IDENTITY_UNKNOWN'}
                # Preserve credential material and the sealed XML preimage.
                $task.Enabled=$false
                $task.Stop(0)
                $retained=$Folder.GetTask($name)
                if($retained.Enabled -or -not(Get-BootstrapOfficialLegacyRelayIdentity ([pscustomobject]@{TaskName=$name;TaskPath='\'}) ([string]$retained.Xml)).matched){throw 'REMOVAL_TASK_DISABLE_NOT_PROVEN'}
                continue
            }
            $task.Stop(0)
            $Folder.DeleteTask($name, 0)
        }
        try { [void]$Folder.GetTask($name); throw 'REMOVAL_TASK_ABSENCE_NOT_PROVEN' }
        catch { $failure=$_.Exception; while ($null -ne $failure.InnerException) { $failure=$failure.InnerException }; if ($failure.HResult -ne -2147024894) { throw } }
    }
}

function Test-ContainerRemovalFile([string]$Path, [string]$Sha256) {
    try {
        Assert-ContainerRemovalBoundary $Path
        if (-not (Test-Path -LiteralPath (Get-ContainerRemovalIoPath $Path) -ErrorAction Stop)) { return $false }
        $file = Get-Item -LiteralPath (Get-ContainerRemovalIoPath $Path) -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
        $sha = [Security.Cryptography.SHA256]::Create()
        $reader = $null
        try {
            $reader = [IO.File]::OpenRead((Get-ContainerRemovalIoPath $Path))
            return ([BitConverter]::ToString($sha.ComputeHash($reader))).Replace('-','').ToLowerInvariant() -ceq $Sha256
        } finally { if ($null -ne $reader) { $reader.Dispose() }; $sha.Dispose() }
    } catch {
        if ($_.Exception.Message -ceq 'REMOVAL_BOUNDARY_REDIRECTED') { return $false }
        # Unknown content cannot retire the inventory needed for the next try.
        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("제거 미완 — 사용 중인 파일: $Path [REMOVAL_FILE_OBSERVATION_UNKNOWN]")) -UserLine)
    }
}

function Get-ContainerArtifactFilePlan([string]$Path, [switch]$Incoming) {
    # No registration census can prove that an opaque tree contains only code.
    # Read only the manifest and its declared files, never unknown subtrees.
    $empty = @{artifacts=@();hashes=@{};metadata_roots=@{};directories=@();retained_paths=@($Path);
        decisions=@(@{path=$Path;disposition='UNREADABLE_INVENTORY_RETAINED'})}
    try {
        Assert-ContainerRemovalBoundary $Path
        $folder = Get-Item -LiteralPath (Get-ContainerRemovalIoPath $Path) -Force -ErrorAction Stop
        if (-not $folder.PSIsContainer) { return $empty }
        $inventoryName = if ($Incoming) { 'manifest.json' } else { 'bootstrap-integrity.json' }
        $inventoryPath = Join-Path $Path $inventoryName
        Assert-ContainerRemovalBoundary $inventoryPath
        $inventoryFile = Get-Item -LiteralPath (Get-ContainerRemovalIoPath $inventoryPath) -Force -ErrorAction Stop
        $inventoryLimit = if ($Incoming) { 1048576 } else { 4194304 }
        if ($inventoryFile.PSIsContainer -or $inventoryFile.Length -gt $inventoryLimit) { return $empty }
        $raw = if ($Incoming) { [IO.File]::ReadAllBytes((Get-ContainerRemovalIoPath $inventoryPath)) }
               else { [IO.File]::ReadAllBytes((Get-ContainerRemovalIoPath $inventoryPath)) }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $inventoryHash = ([BitConverter]::ToString($sha.ComputeHash($raw))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $inventory = [Text.Encoding]::UTF8.GetString($raw).TrimStart([char]0xfeff) | ConvertFrom-Json -ErrorAction Stop
        if ($Incoming) {
            if ([string]$inventory.app_id -cne 'Container_Audit') { return $empty }
            $packetHash = [string]$inventory.artifact.sha256
            if (-not $packetHash) { $packetHash = [string]$inventory.packet_sha256 }
            $rows = @(@{path='packet.zip';sha256=$packetHash})
        } elseif ([string]$inventory.schema_version -ceq 'container-audit-bootstrap-integrity-v1' -and
            [string]$inventory.status -ceq 'PASS' -and $inventory.files -is [Array] -and $inventory.files.Count) {
            $rows = @($inventory.files)
        } else { return $empty }
        $hashes = @{}; $directories = @{}
        foreach ($row in $rows) {
            $relative = [string]$row.path; $hash = [string]$row.sha256
            if ($relative -cnotmatch '^[^:/\\]+(?:/[^:/\\]+)*$' -or
                @($relative.Split('/') | Where-Object { $_ -in @('.','..') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count -or
                $hash -cnotmatch '^[0-9a-f]{64}$') { return $empty }
            $filePath = Join-Path $Path $relative
            if ($hashes.ContainsKey($filePath)) { return $empty }
            $hashes[$filePath] = $hash
            $parent = [IO.Path]::GetDirectoryName($filePath)
            while (-not (Test-SamePath $parent $Path)) {
                $directories[$parent] = $true
                $parent = [IO.Path]::GetDirectoryName($parent)
            }
        }
    } catch { return $empty }
    $owned = @($hashes.Keys | Sort-Object | Where-Object { Test-ContainerRemovalFile $_ $hashes[$_] })
    # Explicit metadata exception: the readable list itself is retired last,
    # only while its bytes still match the exact snapshot used for this plan.
    # Unlisted signatures have no such authority and stay in place.
    $ordered = @($owned | Sort-Object { if ((Split-Path -Leaf $_) -cin @('portable-manifest.json','bootstrap-integrity.json','manifest.json')) { 1 } else { 0 } })
    $hashes[$inventoryPath] = $inventoryHash
    $ordered = @($ordered | Where-Object { -not (Test-SamePath $_ $inventoryPath) }) + @($inventoryPath)
    return @{artifacts=$ordered;hashes=$hashes;metadata_roots=@{$inventoryPath=$Path};directories=(@($directories.Keys) + @($Path));
        retained_paths=@($Path);decisions=@(@{path=$Path;disposition='HASH_MATCHED_FILES_AND_LAST_METADATA'})}
}

function Get-ContainerRemovalArtifacts([string]$ApplicationRoot, [string[]]$RetainedArtifactRoots = @()) {
    $artifacts = @(); $hashes = @{}; $metadataRoots = @{}; $directories = @(); $retained = @(); $decisions = @()
    foreach ($name in @('current', 'versions', 'update-control')) {
        $parent = Join-Path $ApplicationRoot $name
        if (-not (Test-Path -LiteralPath $parent -ErrorAction Stop)) { continue }
        try {
            Assert-ContainerRemovalBoundary $parent
            $container = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        } catch { $retained += $parent; continue }
        if (-not $container.PSIsContainer) { $retained += $parent; continue }
        if ($name -ceq 'current') {
            if ($parent -in $RetainedArtifactRoots) { $retained += $parent; continue }
            $plan = Get-ContainerArtifactFilePlan $parent
            $artifacts += $plan.artifacts; $retained += $plan.retained_paths; $directories += $plan.directories
            $decisions += $plan.decisions
            foreach ($path in $plan.hashes.Keys) { $hashes[$path] = $plan.hashes[$path] }
            foreach ($path in $plan.metadata_roots.Keys) { $metadataRoots[$path] = $plan.metadata_roots[$path] }
            continue
        }
        foreach ($child in @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop)) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { $retained += $child.FullName; continue }
            if ($name -ceq 'versions') {
                if ($child.Name -cmatch '^[0-9a-f]{40}$' -and $child.PSIsContainer) {
                    if ($child.FullName -in $RetainedArtifactRoots) { $retained += $child.FullName; continue }
                    $plan = Get-ContainerArtifactFilePlan $child.FullName
                    $artifacts += $plan.artifacts; $retained += $plan.retained_paths; $directories += $plan.directories
                    $decisions += $plan.decisions
                    foreach ($path in $plan.hashes.Keys) { $hashes[$path] = $plan.hashes[$path] }
                    foreach ($path in $plan.metadata_roots.Keys) { $metadataRoots[$path] = $plan.metadata_roots[$path] }
                } else { $retained += $child.FullName }
            } elseif (-not $child.PSIsContainer) {
                if ($child.Name -cin @('policy.json','active.json','transition.json','installation-observation.json',
                    'reinstall-intent.json','uninstall-task-preimage.json') -or
                    $child.Name -cmatch '^(?:task-preimage|support-placement|policy-before|failure)-[0-9a-f]{32}\.json$' -or
                    $child.Name -cmatch '^failed-[0-9a-f]{32}-(?:policy|active)\.json$') {
                    $artifacts += $child.FullName
                } else { $retained += $child.FullName }
            } elseif ($child.Name -cmatch '^packet-[0-9a-f]{32}$') {
                $plan = Get-ContainerArtifactFilePlan $child.FullName -Incoming
                $artifacts += $plan.artifacts; $retained += $plan.retained_paths; $directories += $plan.directories
                $decisions += $plan.decisions
                foreach ($path in $plan.hashes.Keys) { $hashes[$path] = $plan.hashes[$path] }
                foreach ($path in $plan.metadata_roots.Keys) { $metadataRoots[$path] = $plan.metadata_roots[$path] }
            } elseif ($child.Name -cin @('incoming','failures')) {
                foreach ($entry in @(Get-ChildItem -LiteralPath $child.FullName -Force -ErrorAction Stop)) {
                    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $retained += $entry.FullName; continue }
                    if ($child.Name -ceq 'incoming' -and $entry.PSIsContainer -and $entry.Name -cmatch '^[0-9a-f]{32}$') {
                        if ($entry.FullName -in $RetainedArtifactRoots) { $retained += $entry.FullName; continue }
                        $plan = Get-ContainerArtifactFilePlan $entry.FullName -Incoming
                        $artifacts += $plan.artifacts; $retained += $plan.retained_paths; $directories += $plan.directories
                        $decisions += $plan.decisions
                        foreach ($path in $plan.hashes.Keys) { $hashes[$path] = $plan.hashes[$path] }
                        foreach ($path in $plan.metadata_roots.Keys) { $metadataRoots[$path] = $plan.metadata_roots[$path] }
                    } elseif ($child.Name -ceq 'failures' -and -not $entry.PSIsContainer -and $entry.Name -cmatch '^[0-9a-f]{32}\.json$') {
                        $artifacts += $entry.FullName
                    } else { $retained += $entry.FullName }
                }
            } else { $retained += $child.FullName }
        }
    }
    return @{artifacts=@($artifacts);hashes=$hashes;metadata_roots=$metadataRoots;directories=$directories;retained_paths=@($retained);decisions=@($decisions)}
}

function Remove-ContainerEmptiedParents([string]$Path, [string[]]$Directories) {
    $parent = [IO.Path]::GetDirectoryName($Path)
    while ($parent -in $Directories) {
        try {
            Assert-ContainerRemovalBoundary $parent
            $io = Get-ContainerRemovalIoPath $parent
            if (-not (Test-Path -LiteralPath $io -ErrorAction Stop)) {
                $parent = [IO.Path]::GetDirectoryName($parent); continue
            }
            $folder = Get-Item -LiteralPath $io -Force -ErrorAction Stop
            if (-not $folder.PSIsContainer -or @(Get-ChildItem -LiteralPath $io -Force -ErrorAction Stop).Count) { return }
            # Only a proven file move authorizes this now-empty parent.
            # Never change attributes of a preexisting or nonempty directory.
            if ($folder.Attributes -band [IO.FileAttributes]::ReadOnly) {
                $folder.Attributes = $folder.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
            }
            Remove-Item -LiteralPath $io -ErrorAction Stop
        } catch {
            # Empty-directory cleanup is best effort; report a surviving path.
            return $parent
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
}

function Invoke-ContainerConvergentRemoval([string]$InstallRoot, $TaskFolder, [int[]]$ExcludeProcessIds = @(),[switch]$OnlyUncommittedCurrent) {
    if($OnlyUncommittedCurrent -and $null -ne $TaskFolder){throw 'TRANSACTION_REMOVAL_TASK_CENSUS_FORBIDDEN'}
    $current = Get-StrictFullPath $InstallRoot 'removal current'
    if ((Split-Path -Leaf $current) -cne 'current') { throw 'REMOVAL_CURRENT_PATH_INVALID' }
    $application = Get-StrictFullPath (Split-Path -Parent $current) 'removal application'
    Assert-ContainerRemovalBoundary $application
    Assert-ContainerRemovalQuiescent $application $ExcludeProcessIds
    $markerPath = Join-Path $application 'removed.json'
    if (Test-Path -LiteralPath $markerPath -ErrorAction Stop) {
        Assert-ContainerRemovalBoundary $markerPath
        $markerFile = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
        if ($markerFile.PSIsContainer) {
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("제거 표식을 만드는 경로와 자료가 겹칩니다. 자료를 보존하고 경로를 확인하세요: $markerPath")) -UserLine)
        }
    }
    $evidenceParent = Join-Path $application 'removal-evidence'
    Assert-ContainerRemovalBoundary $evidenceParent
    if (-not (Test-Path -LiteralPath $evidenceParent)) {
        New-Item -ItemType Directory -Path $evidenceParent | Out-Null
        if (-not $testOverride) { Set-HardenedCodeAcl $evidenceParent }
    } elseif (-not $testOverride) { Assert-HardenedCodeAcl $evidenceParent }
    $evidence = Join-Path $evidenceParent ([Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $evidence | Out-Null
    if (-not $testOverride) { Set-HardenedCodeAcl $evidence }
    if ($null -eq $TaskFolder -and -not $testOverride -and -not $OnlyUncommittedCurrent) { throw 'REMOVAL_TASK_OBSERVATION_UNKNOWN' }
    if ($null -ne $TaskFolder) { Remove-ContainerScheduledTasks $TaskFolder $evidence $current }
    Assert-ContainerRemovalQuiescent $application $ExcludeProcessIds
    $plan = if($OnlyUncommittedCurrent){Get-ContainerArtifactFilePlan $current}else{Get-ContainerRemovalArtifacts $application}
    if (-not $OnlyUncommittedCurrent -and (Test-Path -LiteralPath $markerPath)) { $plan.artifacts += $markerPath }
    $changedMetadataRoots = @(); $cleanupRetained = @()
    foreach ($path in $plan.artifacts) {
        $prefix = $application.TrimEnd('\') + '\'
        if (-not $path.StartsWith($prefix, 'OrdinalIgnoreCase')) { throw 'REMOVAL_PATH_ESCAPED' }
        if ($plan.hashes.ContainsKey($path) -and -not (Test-ContainerRemovalFile $path $plan.hashes[$path])) {
            if ($plan.metadata_roots.ContainsKey($path)) {
                $changedMetadataRoots += $plan.metadata_roots[$path]
                $plan.decisions += @{path=$plan.metadata_roots[$path];disposition='METADATA_CHANGED_RETAINED'}
            }
            continue
        }
        Assert-ContainerRemovalBoundary $path
        if ((Get-Item -LiteralPath (Get-ContainerRemovalIoPath $path) -Force -ErrorAction Stop).PSIsContainer) { throw 'REMOVAL_DIRECTORY_MOVE_FORBIDDEN' }
        $destination = Join-Path $evidence $path.Substring($prefix.Length)
        # Evidence adds a UUID segment; normal source paths can cross MAX_PATH
        # at the destination. The literal extended path stays inside evidence.
        $destinationIo = Get-ContainerRemovalIoPath $destination
        New-Item -ItemType Directory -Path (Split-Path -Parent $destinationIo) -Force | Out-Null
        try {
            Move-Item -LiteralPath (Get-ContainerRemovalIoPath $path) -Destination $destinationIo -ErrorAction Stop
            if (Test-Path -LiteralPath (Get-ContainerRemovalIoPath $path) -ErrorAction Stop) { throw 'REMOVAL_PATH_ABSENCE_NOT_PROVEN' }
        } finally {
            # A rename may succeed before the caller receives its exception.
            # Clean only parents of that proven move, including on retry cuts.
            if ($plan.hashes.ContainsKey($path) -and
                -not (Test-Path -LiteralPath (Get-ContainerRemovalIoPath $path) -ErrorAction Stop) -and
                (Test-ContainerRemovalFile $destination $plan.hashes[$path])) {
                $cleanupRetained += @(Remove-ContainerEmptiedParents $path $plan.directories)
            }
        }
    }
    $remaining = if($OnlyUncommittedCurrent){
        if(Test-Path -LiteralPath $current){Get-ContainerArtifactFilePlan $current}else{@{artifacts=@();retained_paths=@()}}
    }else{Get-ContainerRemovalArtifacts $application -RetainedArtifactRoots $changedMetadataRoots}
    if ($remaining.artifacts.Count) { throw 'REMOVAL_MACHINE_ARTIFACT_REMAINS' }
    foreach ($path in @($cleanupRetained | Sort-Object -Unique)) {
        if (Test-Path -LiteralPath (Get-ContainerRemovalIoPath $path) -ErrorAction Stop) {
            $remaining.retained_paths += $path
            $plan.decisions += @{path=$path;disposition='EMPTY_OWNED_PARENT_RETAINED'}
        }
    }
    if($OnlyUncommittedCurrent){
        if(Test-Path -LiteralPath $current){throw 'TRANSACTION_REMOVAL_CODE_PREIMAGE_NOT_ABSENT'}
        return @{status='PASS';lifecycle_state='UNCOMMITTED_PLACEMENT_REMOVED';evidence_root=$evidence;retained_paths=@($remaining.retained_paths)}
    }
    Write-ContainerStartupUpdateRecord -Path $markerPath -Payload @{
        schema='container-audit-supported-removal-v1'; lifecycle_state='REMOVED';
        evidence_root=$evidence; business_data_and_registration_preserved=$true
        retained_paths=@($remaining.retained_paths)+@($(if(Test-Path -LiteralPath (Get-BootstrapEmergencyShortcutPath $current)){Get-BootstrapEmergencyShortcutPath $current})); artifact_dispositions=@($plan.decisions)
        emergency_shortcut=(Get-BootstrapEmergencyRemovalState $current)
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$marker.lifecycle_state -cne 'REMOVED') { throw 'REMOVAL_MARKER_READBACK_FAILED' }
    return @{status='PASS';lifecycle_state='REMOVED';evidence_root=$evidence;retained_paths=@($remaining.retained_paths)}
}


if ($Uninstall.IsPresent) {
    if ($DryRun.IsPresent) { 'uninstall_status=DRY_RUN_CODE_ONLY'; 'user_state_preserved=true'; exit 0 }
    if($RemoveUncommittedPlacement){
        if($null -eq $placementWriterFenceLease){throw 'Uncommitted placement removal requires delegated writer admission.'}
        if(-not $testOverride){Assert-InstallationEvidenceProtectedPath $TransactionHandoverPath}
        $handover=(Read-InstallationTransactionFile $TransactionHandoverPath $TransactionHandoverSha256).Record
        if([string]$handover.schema -cne 'container-audit-installation-transaction-handover-v1' -or
            [string]$handover.session_id -cne $WriterFenceSessionId -or [string]$handover.attempt_id -cne $WriterFenceAttemptId -or
            [string]$handover.transaction_id -cne $WriterFenceReplacementTransactionId -or
            [string]$handover.operator_sid -cne $OperatorSid -or
            -not(Test-SamePath ([string]$handover.install_root) $installRootFull) -or
            $handover.context.currentAbsentBeforePlacement -isnot [bool] -or -not $handover.context.currentAbsentBeforePlacement){
            throw 'Uncommitted placement removal handover differs.'
        }
        # This read is inside the same admission lease as the actual removal.
        # An onboarding writer cannot publish G between the check and mutation.
        if((Get-BootstrapInstallationCommitPoint $handover.source_manifest $OperatorSid $OperatorLocalAppDataRoot $OperatorDataRoot $PSScriptRoot) -cne 'NOT_REACHED'){
            throw 'Uncommitted placement removal commit point is unproven.'
        }
    }
    $uninstallSource = Get-StrictFullPath $SourceRoot 'supported removal source'
    $application = Split-Path -Parent $installRootFull
    if ((Test-SamePath $uninstallSource $application) -or (Test-PathWithin $uninstallSource $application) -or
        (Test-PathWithin $application $uninstallSource)) { throw 'REMOVAL_EXTERNAL_VERIFIED_SOURCE_REQUIRED' }
    Assert-NoReparsePoint $uninstallSource 'supported removal source'
    [void](Assert-RequiredRelease $uninstallSource $testOverride)
    if (-not (Test-SamePath $BootstrapScriptPath (Join-Path $uninstallSource 'INSTALL_THIS_PC.ps1'))) {
        throw 'Removal helper must execute from the admitted external SourceRoot.'
    }
    if (-not $testOverride) { Assert-ProtectedCodeAncestors $application }
    if($RemoveUncommittedPlacement){
        $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $excluded = @(Get-ContainerRemovalControllerProcessId $rows)
    }
    if (-not $MachineControlRoot) {
    $quiesceFull = Get-StrictFullPath $QuiesceReceiptPath 'current-user removal receipt'
    Assert-NoReparsePoint $quiesceFull 'current-user removal receipt'
    if ($ExpectedQuiesceReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 $quiesceFull) -cne $ExpectedQuiesceReceiptSha256 -or
        (Get-Item -LiteralPath $quiesceFull).Length -gt 65536) { throw 'Removal current-user receipt binding differs.' }
    $quiesce = Get-Content -LiteralPath $quiesceFull -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$quiesce.status -cne 'PASS_DATA_PRESERVED' -or [string]$quiesce.state_scope -cne 'current_user' -or
        $quiesce.data_preserved -isnot [bool] -or -not $quiesce.data_preserved -or
        [string]$quiesce.relay_autostart.status -cne 'ABSENT' -or [string]$quiesce.relay_process.status -cne 'ABSENT' -or
        -not (Test-SamePath ([string]$quiesce.machine_code_root) (Join-Path $installRootFull 'app'))) {
        throw 'Removal current-user quiescence was not proven.'
    }
    }
    # A machine removal never claims to have changed or observed worker HKCU.
    # The existing convergent removal still rejects any live installed writer.
    # Only actual ancestors running the admitted external canonical source can
    # be excluded. Installed code and unrelated processes cannot claim this.
    if(-not $RemoveUncommittedPlacement){
        $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $excluded = @(Get-ContainerRemovalControllerProcessId $rows)
    }
    $folder=$null
    if($RemoveUncommittedPlacement){
        $expectedStartup=Join-Path $application ('.startup-update-install.'+$WriterFenceAttemptId)
        $savedStartup=Join-Path $expectedStartup 'preimage.json'
        if(Test-Path -LiteralPath $savedStartup){
            if(-not(Test-SamePath $TransactionStartupPreimagePath $expectedStartup) -or
                $TransactionStartupPreimageSha256 -cnotmatch '^[0-9a-f]{64}$' -or
                (Get-FileSha256 $savedStartup) -cne $TransactionStartupPreimageSha256){throw 'TRANSACTION_REMOVAL_STARTUP_PREIMAGE_PIN_DIFFERS'}
            Restore-ContainerStartupUpdatePreimage $installRootFull $expectedStartup $TransactionStartupPreimageSha256
            $saved=(Read-InstallationTransactionFile $savedStartup $TransactionStartupPreimageSha256).Record
            foreach($item in @($saved.files)){
                $target=Join-Path (Join-Path $application 'update-control') ([string]$item.name)
                if([bool]$item.exists -ne (Test-Path -LiteralPath $target) -or
                    ($item.exists -and (Get-FileSha256 $target) -cne [string]$item.sha256)){throw 'TRANSACTION_REMOVAL_STARTUP_FILE_READBACK_DIFFERS'}
            }
            $task=Get-ContainerStartupUpdateTaskPreimage $installRootFull
            if([bool]$task.exists -ne [bool]$saved.task.exists -or [string]$task.xml -cne [string]$saved.task.xml -or
                [string]$task.sddl -cne [string]$saved.task.sddl){throw 'TRANSACTION_REMOVAL_STARTUP_TASK_READBACK_DIFFERS'}
        }elseif($TransactionStartupPreimagePath -or $TransactionStartupPreimageSha256){throw 'TRANSACTION_REMOVAL_STARTUP_PREIMAGE_ABSENT'}
    }else{
        $scheduler = New-Object -ComObject 'Schedule.Service'; $scheduler.Connect(); $folder = $scheduler.GetFolder('\')
    }
    $control = Join-Path $application 'update-control'
    $identity = Get-ContainerWriterFenceStringSha256 $control.ToLowerInvariant()
    $gate = New-Object Threading.Mutex($false,('Global\KMTech.ContainerAudit.Update.'+$identity.Substring(0,24)))
    $gateHeld=$false
    try {
        try { $gateHeld=$gate.WaitOne(5000) } catch [Threading.AbandonedMutexException] { $gateHeld=$true; throw 'REMOVAL_UPDATE_GATE_ABANDONED' }
        if (-not $gateHeld) { throw 'REMOVAL_UPDATE_GATE_BUSY' }
        if ($UninstallAuditPath) { Write-ContainerSupportedRemovalJournal $excluded }
        $removed = Invoke-ContainerConvergentRemoval -InstallRoot $installRootFull -TaskFolder $folder -ExcludeProcessIds $excluded -OnlyUncommittedCurrent:$RemoveUncommittedPlacement
        $shortcutRecord=Get-BootstrapWorkerShortcutCommonRecordPath $installRootFull
        # Only the already verified machine controller owns the independent emergency stage.
        $deferEmergencyCleanup=([bool]$MachineControlRoot -and -not $RemoveUncommittedPlacement -and
            [bool]$UninstallAuditPath -and $excluded -contains $RemovalControllerProcessId)
        [void](Restore-BootstrapWorkerShortcuts $installRootFull $shortcutRecord 'Common' -DeferEmergencyCleanup:$deferEmergencyCleanup)
        'uninstall_status=PASS_KNOWN_FILES_REMOVED_STATE_PRESERVED'
        'lifecycle_state=REMOVED'
        ConvertTo-KmtechRedactedSinkText -Text ('removal_evidence_root='+[string]$removed.evidence_root)
        'retained_path_count='+@($removed.retained_paths).Count
        'user_state_preserved=true'
    } finally { if ($gateHeld) { $gate.ReleaseMutex() }; $gate.Dispose() }
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
Assert-ContainerDataGenerationTarget -CandidateRoot $sourceRootFull -TargetSid $OperatorSid `
    -LocalAppDataRoot $OperatorLocalAppDataRoot -DataRoot $OperatorDataRoot -HelperRoot $PSScriptRoot
if ($releaseLayout -ceq 'PORTABLE_CPYTHON') {
    if (-not (Test-SamePath $BootstrapScriptPath (Join-Path $sourceRootFull 'INSTALL_THIS_PC.ps1'))) {
        throw 'Code helper must execute from the admitted SourceRoot.'
    }
    if (-not (Test-SamePath $BootstrapIntegrityFunctions (Join-Path $sourceRootFull 'tools\bootstrap_integrity.ps1'))) {
        throw 'Integrity helper must load from the admitted SourceRoot.'
    }
}
function Set-ContainerLifecycleContextFailure($ContextText) {
    # Python exception text can contain paths or child streams. Retain only
    # known classifications, never the original message/stream or extra keys.
    $safe=[ordered]@{status='UNKNOWN';error_type='UNKNOWN';failure_details=@();output_classification='CONTEXT_OUTPUT_UNKNOWN'}
    $types=@('ValueError','OSError','FileNotFoundError','PermissionError','NotADirectoryError','RuntimeError','WriterFenceError','WriterFencedError',
        'InvalidOperationException','RuntimeException','IOException','UnauthorizedAccessException','COMException')
    $reasons=@('lifecycle_operation_invalid','lifecycle_owned_namespace_collision','lifecycle_namespace_parent_unavailable',
        'lifecycle_data_namespace_collision','lifecycle_removed_control_remains','lifecycle_register_requires_installed_code',
        'lifecycle_removed_tasks_remain_or_unknown','lifecycle_stock_protection_invalid','lifecycle_stock_layout_invalid',
        'lifecycle_stock_manifest_invalid','lifecycle_control_incomplete','lifecycle_transition_requires_recovery',
        'lifecycle_confirmed_pointer_mismatch','lifecycle_rolled_back_pointer_mismatch','lifecycle_pointer_mismatch',
        'lifecycle_active_manifest_mismatch','lifecycle_active_trust_key_mismatch','lifecycle_task_absence_or_unknown',
        'lifecycle_state_changed_during_verification','lifecycle_from_commit_mismatch')
    $writerReasons=@{
        'writer admission mutex is held by a deployment operation'='WRITER_GATE_TIMEOUT'
        'writer denied by the active deployment fence'='ACTIVE_WRITER_FENCE'
        'nested writer source denied by the active deployment fence'='ACTIVE_WRITER_FENCE'
        'writer fence path contains a reparse point'='FENCE_REPARSE_REJECTED'
        'writer fence path cannot be observed'='FENCE_PATH_UNOBSERVABLE'
    }
    try {
        $builder=[Text.StringBuilder]::new()
        foreach($line in @($ContextText)){
            $value=[string]$line
            if($builder.Length+$value.Length+2 -gt 65536){throw 'context output oversized'}
            [void]$builder.AppendLine($value)
        }
        $text=$builder.ToString()
        if([Text.Encoding]::UTF8.GetByteCount($text) -gt 65536){throw 'context output oversized'}
        $payload=$text|ConvertFrom-Json -ErrorAction Stop
        if([string]$payload.status -cne 'FAILED'){throw 'context failure shape differs'}
        $safe.status='FAILED';$safe.output_classification='CLASSIFIED'
        $kind=([string]$payload.error_type).Split('.')[-1]
        if($kind -cin $types){$safe.error_type=$kind}
        foreach($detail in @($payload.failure_details)|Select-Object -First 16){
            $kind=([string]$detail.type).Split('.')[-1]
            if($kind -cnotin $types){$kind='UNKNOWN'}
            $reason='UNCLASSIFIED';$message=[string]$detail.message
            if($message -cin $reasons){$reason=$message}
            elseif($writerReasons.ContainsKey($message)){$reason=$writerReasons[$message]}
            $safe.failure_details+=,[ordered]@{type=$kind;message=$reason}
        }
    }catch{
        $safe=[ordered]@{status='UNKNOWN';error_type='UNKNOWN';failure_details=@();output_classification='CONTEXT_OUTPUT_UNKNOWN'}
    }
    $Script:ContainerLifecycleContextFailure=$safe
    Write-InstallationEvidenceEvent ([ordered]@{event='LIFECYCLE_CONTEXT_FAILED';diagnostic=$safe})
}

function Get-ContainerSupportedInstallContext([string]$Source,[string]$Fixed,[string]$RecoveryMessage='Supported lifecycle context is unhealthy.') {
    $lease=Get-Variable -Name placementWriterFenceLease -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $lease -and $lease.acquired -is [bool] -and $lease.acquired){
        # The helper already owns admission. A Python child cannot reacquire
        # that mutex; use the existing pinned classifier in this same thread.
        try{return Get-BootstrapSupportedLifecycleContext (Split-Path -Parent $Fixed) 'install'}
        catch{
            Write-InstallationCaughtFailure $_
            $details=@();$contextException=$_.Exception
            for($depth=0;$null -ne $contextException -and $depth -lt 16;$depth++){
                $details+=,@{type=$contextException.GetType().Name;message=$contextException.Message}
                $contextException=$contextException.InnerException
            }
            $text=@{status='FAILED';error_type=$_.Exception.GetType().Name;failure_details=$details}|ConvertTo-Json -Depth 5 -Compress
            Set-ContainerLifecycleContextFailure @($text)
            throw $RecoveryMessage
        }
    }
    $child=Invoke-InstallationEvidenceChild 'lifecycle-context-install' (Join-Path $Source 'runtime\python.exe') @((Join-Path $Source 'app\auto_update.py'),'--lifecycle-context','--operation','install','--install-root',$Fixed)
    $contextText=@($child.Stdout -split '\r?\n')
    if($child.ExitCode -ne 0){Set-ContainerLifecycleContextFailure $contextText;throw $RecoveryMessage}
    return $contextText|ConvertFrom-Json
}

function Invoke-ContainerPlacementRollbackStep([string]$Name,[scriptblock]$Action) {
    $failure=$null
    try{Set-InstallationEvidenceStage ('rollback.'+$Name) 'rollback'; & $Action}
    catch{$failure=Get-InstallationFailureDetails $_;Write-InstallationCaughtFailure $_}
    $record=[ordered]@{step=$Name;status=if($null -eq $failure){'PROVEN'}else{'FAILED'};failure=$failure}
    Write-InstallationEvidenceEvent ([ordered]@{event='ROLLBACK_STEP';detail=$record})
    return $record
}

if(-not $testOverride -and -not $RestoreUninstallRecordPath -and -not $SupportedActiveVersionPlacement) {
    $context=Get-ContainerSupportedInstallContext $sourceRootFull $installRootFull '자료와 등록 및 전송 대기를 보존하고 지원 제거를 먼저 실행한 뒤 다시 설치하세요.'
    if([string]$context.lifecycle_state -ceq 'HEALTHY' -and [bool]$context.managed -and [string]$context.bootstrap_commit -cne [string]$context.from_commit){throw '자동 적용 뒤 지원 설치는 INSTALL_CANONICAL_PORTABLE.ps1 로 실행하세요.'}
}
$sourceInventory = @(Get-CodeInventory $sourceRootFull)
if ($sourceInventory.Count -eq 0) {
    throw "Frozen release code inventory is empty."
}
$sourceAggregate = Get-InventoryAggregate $sourceInventory
function Assert-ContainerUninstallRecoveryRemainder {
    # A failed convergent removal may retain only unchanged pinned code. Never
    # replace an unknown/changed file or erase the remnant to make recovery pass.
    Assert-NoReparsePoint $installRootFull 'uninstall recovery remainder'
    $expected = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($item in $sourceInventory) { $expected.Add([string]$item.path, $item) }
    foreach ($item in @(Get-CodeInventory $installRootFull)) {
        if (-not $expected.ContainsKey([string]$item.path) -or
            [int64]$item.size -ne [int64]$expected[[string]$item.path].size -or
            [string]$item.sha256 -cne [string]$expected[[string]$item.path].sha256) {
            throw 'UNINSTALL_RECOVERY_REMAINDER_DIFFERS'
        }
    }
    $record = Join-Path $installRootFull $IntegrityFileName
    if ((Test-Path -LiteralPath $record) -and
        (Get-FileSha256 $record) -cne $ExpectedUninstallRecordSha256) {
        throw 'UNINSTALL_RECOVERY_RECORD_CHANGED'
    }
}
if ($RestoreUninstallRecordPath) {
    if ($DryRun -or
        $ExpectedUninstallRecordSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $sourceAggregate -cne $ExpectedInstalledAggregateSha256 -or
        (Get-FileSha256 (Join-Path $sourceRootFull 'portable-manifest.json')) -cne $ExpectedInstalledManifestSha256) {
        throw 'UNINSTALL_RECOVERY_IDENTITY_INVALID: exact source required.'
    }
    $RestoreUninstallRecordPath = Get-StrictFullPath $RestoreUninstallRecordPath 'uninstall integrity preimage'
    Assert-NoReparsePoint $RestoreUninstallRecordPath 'uninstall integrity preimage'
    if ((Get-FileSha256 $RestoreUninstallRecordPath) -cne $ExpectedUninstallRecordSha256) {
        throw 'UNINSTALL_RECOVERY_RECORD_CHANGED'
    }
    Assert-ContainerReplacementRestoreQuiescent -CurrentRoot $installRootFull -SkipOwnedTaskCheckForGuardedTest:$testOverride
    if (Test-Path -LiteralPath $installRootFull) { Assert-ContainerUninstallRecoveryRemainder }
}
if ($DryRun.IsPresent) {
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("bootstrap_status=DRY_RUN")))
    Write-InstallationHelperPublicRecord @{code_root=$installRootFull}
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("release_layout=$releaseLayout")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("file_count=$($sourceInventory.Count)")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("aggregate_sha256=$sourceAggregate")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("identity_profile_created=false")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("tls_ca_bootstrap_configured=$(-not [string]::IsNullOrWhiteSpace($TlsCaBundlePath))")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("elevation_points=1:code_placement")))
    exit 0
}

function Invoke-ContainerSupportedActiveVersionPlacement {
    if($testOverride -or -not $ReplaceExistingVerifiedPortable -or $SupportedFromCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $ReplacementTransactionId -cnotmatch '^[0-9a-f]{32}$' -or -not $WriterFencePreparedReceiptPath){throw 'Supported placement requires the live canonical receipt authority.'}
    $applicationParent=Split-Path -Parent $installRootFull
    Assert-InstallationEvidenceProtectedPath $applicationParent
    $control=Join-Path $applicationParent 'update-control'
    $gate=New-Object Threading.Mutex($false,('Global\KMTech.ContainerAudit.Update.'+(Get-ContainerWriterFenceStringSha256 $control.ToLowerInvariant()).Substring(0,24)))
    $held=$false
    try {
        try{$held=$gate.WaitOne(5000)}catch [Threading.AbandonedMutexException]{$held=$true;throw 'Supported update gate was abandoned.'}
        if(-not $held){throw 'Supported update gate is busy.'}
        # Verify the old stock through the admitted source, never by running B.
        $context=Get-ContainerSupportedInstallContext $sourceRootFull $installRootFull
        if([string]$context.lifecycle_state -cne 'HEALTHY' -or [string]$context.from_commit -cne $SupportedFromCommit -or
            [string]$context.bootstrap_commit -ceq $SupportedFromCommit){throw 'Supported active from binding differs.'}
        Assert-ContainerReplacementRestoreQuiescent -CurrentRoot $installRootFull
        if((Get-FileSha256 (Join-Path $sourceRootFull 'app\update-manifest-key-config.json')) -cne (Get-FileSha256 (Join-Path $installRootFull 'app\update-manifest-key-config.json'))){throw 'Supported stock trust key differs.'}
        $from=Join-Path $applicationParent ('versions\'+$SupportedFromCommit)
        $manifest=Get-Content -LiteralPath (Join-Path $sourceRootFull 'portable-manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
        $to=Join-Path $applicationParent ('versions\'+[string]$manifest.source_commit)
        if([string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or (Test-Path -LiteralPath $to)){throw 'Supported candidate destination already exists or differs.'}
        Assert-NoReparsePoint (Split-Path -Parent $to) 'supported version parent'
        $owner=Get-BootstrapReplacementTreeIdentity $installRootFull $installRootFull
        $active=Get-BootstrapReplacementTreeIdentity $from $from
        $preimage=Save-ContainerStartupUpdatePreimage $installRootFull 'install'
        # Before publishing any pointer, preserve the complete protected C tree
        # and the same immutable receipt consumed by ordinary rollback/resume.
        Copy-Item -LiteralPath $sourceRootFull -Destination $to -Recurse -ErrorAction Stop
        if((Get-InventoryAggregate @(Get-CodeInventory $to)) -cne $sourceAggregate){throw 'Supported candidate copy differs.'}
        [void](Write-BootstrapIntegrityRecord -Root $to -CodeRootIdentity $to)
        Set-HardenedCodeAcl $to -Recursive
        $new=Get-BootstrapReplacementTreeIdentity $to $to
        $planned=Join-Path $preimage.path 'planned'
        New-InstallationProtectedDirectory $planned $OperatorSid
        $oldState=Get-Content -LiteralPath (Join-Path $control 'transition.json') -Raw -Encoding UTF8|ConvertFrom-Json
        $policy=Get-Content -LiteralPath (Join-Path $control 'policy.json') -Raw -Encoding UTF8|ConvertFrom-Json
        $settings=Get-Content -LiteralPath (Join-Path $sourceRootFull 'app\auto-update-settings.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if($settings.apply_during_work -isnot [bool] -or $settings.apply_during_work){throw 'Supported policy permits work-time application.'}
        $policy.feed_url=[string]$settings.feed_url;$policy.channel=[string]$settings.channel
        $policy.profile_auth=[bool]$settings.profile_auth;$policy.approved_transitions=@($settings.approved_transitions)
        Write-ContainerStartupUpdateRecord (Join-Path $planned 'policy.json') $policy
        Write-ContainerStartupUpdateRecord (Join-Path $planned 'active.json') ([ordered]@{schema='container-audit-startup-update-v1';sha=[string]$manifest.source_commit;transition_id=$ReplacementTransactionId})
        Write-ContainerStartupUpdateRecord (Join-Path $planned 'transition.json') ([ordered]@{schema='container-audit-startup-update-v1';phase='DEFERRED';deferred_at=[DateTime]::UtcNow.ToString('o');reason='supported canonical active-version placement';failed_shas=@($oldState.failed_shas)})
        $after=@('policy.json','active.json','transition.json'|ForEach-Object {[ordered]@{name=$_;sha256=Get-FileSha256 (Join-Path $planned $_)}})
        $receiptFull=Join-Path $Script:InstallationEvidenceRoot 'replacement-receipt.json'
        $payload=[ordered]@{schema_version='container-audit-verified-replacement-v1';status='OLD_PRESERVED_NEW_VERIFIED';app_id='container_audit';transaction_id=$ReplacementTransactionId;
            created_at=[DateTime]::UtcNow.ToString('o');helper_sha256=Get-FileSha256 $BootstrapScriptPath;integrity_helper_sha256=Get-FileSha256 $BootstrapIntegrityFunctions;
            receipt_path=$receiptFull;install_root=$installRootFull;install_parent=$applicationParent;rollback_root=$from;failed_root=Join-Path $applicationParent ('.version.failed.'+$ReplacementTransactionId);
            parent_acl=Get-BootstrapAclIdentity $applicationParent;old=$owner;new=$new;identity_or_credential_copied=$false;
            startup_update_preimage=$preimage.path;startup_update_preimage_sha256=$preimage.sha256;
            active_version=[ordered]@{kind='SUPPORTED_ACTIVE_VERSION';from_sha=$SupportedFromCommit;to_sha=[string]$manifest.source_commit;from_root=$from;to_root=$to;from=$active;control_after=$after}}
        $saved=Write-BootstrapReplacementReceipt $receiptFull $payload
        Write-InstallationEvidenceEvent ([ordered]@{event='REPLACEMENT_RECEIPT_READY';path=$saved.path;sha256=$saved.sha256;old_manifest_sha256=$owner.manifest_sha256;new_manifest_sha256=$new.manifest_sha256;transaction_id=$ReplacementTransactionId})
        if($Script:InstallationEvidenceFailed){throw 'Supported receipt was not durably recorded.'}
        foreach($name in @('transition.json','policy.json','active.json')) {
            $bytes=Get-Content -LiteralPath (Join-Path $planned $name) -Raw -Encoding UTF8|ConvertFrom-Json
            Write-ContainerStartupUpdateRecord (Join-Path $control $name) $bytes
            if((Get-FileSha256 (Join-Path $control $name)) -cne (Get-FileSha256 (Join-Path $planned $name))){throw 'Supported control publication differs.'}
        }
        $verifiedReceipt=Read-BootstrapReplacementReceipt $saved.path $saved.sha256
        [void](Get-BootstrapSupportedVersionRestoreState $verifiedReceipt $receiptFull $installRootFull 'container_audit' $ReplacementTransactionId (Get-FileSha256 $BootstrapScriptPath))
        'replacement_receipt_path='+$saved.path
        'replacement_receipt_sha256='+$saved.sha256
        'supported_placement_status=OLD_OWNER_AND_ACTIVE_PRESERVED_NEW_VERIFIED'
        return
    } finally {if($held){$gate.ReleaseMutex()};$gate.Dispose()}
}

if($SupportedActiveVersionPlacement){Invoke-ContainerSupportedActiveVersionPlacement;exit 0}

$applicationParent = Split-Path -Parent $installRootFull
$stagingRoot = Join-Path $applicationParent ('.current.bootstrap.' + [Guid]::NewGuid().ToString('N'))
$replacementApplied = $false
$uninstallPartialRoot = ''
$replacementRollbackRoot = ''
$replacementReceiptFull = ''
$replacementReceiptWritten = $false
$previousReplacementIdentity = $null
New-Item -ItemType Directory -Path $applicationParent -Force | Out-Null
if ($applyHardenedAcl) {
    # Preparation already protected this parent. Never reset control, evidence,
    # user data or unknown siblings, even temporarily, during code placement.
    Assert-InstallationEvidenceProtectedPath $applicationParent
}
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
    Set-InstallationEvidenceStage 'placement.staging_copy'
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
    Set-InstallationEvidenceStage 'placement.staging_acl'
    if ($applyHardenedAcl) {
        Set-HardenedCodeAcl $stagingRoot -Recursive
    }
    Set-InstallationEvidenceStage 'placement.old_tree_and_swap'
    if ($RestoreUninstallRecordPath -and (Test-Path -LiteralPath $installRootFull)) {
        if ($WriterFenceAttemptId -cnotmatch '^[0-9a-f]{32}$') { throw 'UNINSTALL_RECOVERY_ATTEMPT_INVALID' }
        $uninstallPartialRoot = Join-Path $applicationParent ('.current.uninstall.' + $WriterFenceAttemptId)
        if (Test-Path -LiteralPath $uninstallPartialRoot) { throw 'UNINSTALL_RECOVERY_CUSTODY_EXISTS' }
        Assert-NoReparsePoint $uninstallPartialRoot 'uninstall recovery custody' -PathOnly
        Assert-ContainerReplacementRestoreQuiescent -CurrentRoot $installRootFull -SkipOwnedTaskCheckForGuardedTest:$testOverride
        Assert-ContainerUninstallRecoveryRemainder
        Move-Item -LiteralPath $installRootFull -Destination $uninstallPartialRoot
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
    Write-InstallationCaughtFailure $_

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
                ((Test-PathWithin $replacementReceiptFull $applicationParent) -and
                    (-not $helperInstallationEvidenceRoot -or -not(Test-PathWithin $replacementReceiptFull $helperInstallationEvidenceRoot))) -or
                (Test-Path -LiteralPath $replacementReceiptFull)
            ) { throw 'Replacement receipt must be a new path outside the code parent.' }
            Assert-ContainerReplacementRestoreQuiescent `
                -CurrentRoot $installRootFull `
                -SkipOwnedTaskCheckForGuardedTest:$testOverride `
                -ClassifyOtherSessionPreflight
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
    Write-InstallationCaughtFailure $_

                if (
                    -not (Test-Path -LiteralPath $installRootFull) -and
                    (Test-Path -LiteralPath $replacementRollbackRoot -PathType Container)
                ) {
                    Assert-ContainerDataGenerationTarget -CandidateRoot $replacementRollbackRoot -TargetSid $OperatorSid `
                        -LocalAppDataRoot $OperatorLocalAppDataRoot -DataRoot $OperatorDataRoot -HelperRoot $PSScriptRoot
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
        try { Move-Item -LiteralPath $stagingRoot -Destination $installRootFull }
        catch {
            if ($uninstallPartialRoot -and -not (Test-Path -LiteralPath $installRootFull)) {
                Assert-NoReparsePoint $uninstallPartialRoot 'uninstall recovery custody'
                Move-Item -LiteralPath $uninstallPartialRoot -Destination $installRootFull
            }
            throw
        }
        $bootstrapStatus = 'PASS'
    }
    Set-InstallationEvidenceStage 'placement.installed_acl'
    if ($applyHardenedAcl) {
        Set-HardenedCodeAcl $installRootFull -Recursive
        $aclReadbackStatus = 'PASS'
    }
    Set-InstallationEvidenceStage 'placement.installed_aggregate'
    $installedAggregate = Get-InventoryAggregate @(Get-CodeInventory $installRootFull)
    if ($installedAggregate -cne $sourceAggregate) {
        throw "Installed code integrity readback failed."
    }
    Set-InstallationEvidenceStage 'placement.replacement_identity_receipt'
    $replacementReceipt = $null
    if ($replacementApplied) {
        $newIdentity = Get-BootstrapReplacementTreeIdentity $installRootFull $installRootFull
        $oldIdentity = Get-BootstrapReplacementTreeIdentity $replacementRollbackRoot $installRootFull
        if (
            -not (Test-BootstrapReplacementTreeIdentity $previousReplacementIdentity $oldIdentity) -or
            [string]$newIdentity.aggregate_sha256 -cne $sourceAggregate
        ) { throw 'Verified replacement tree identity readback failed.' }
        $parentAcl = Get-BootstrapAclIdentity $applicationParent
        if ($helperInstallationEvidenceRoot -and $WriterFencePreparedReceiptPath) {
            # Canonical callers consume the authenticated protected original.
            # Standalone callers retain their existing caller/export contract.
            $BootstrapBoundParameters['ReplacementReceiptPath']=$replacementReceiptFull
        }
        $receiptPayload = [ordered]@{
            schema_version = 'container-audit-verified-replacement-v1'
            status = 'OLD_PRESERVED_NEW_VERIFIED'
            app_id = 'container_audit'
            transaction_id = $ReplacementTransactionId
            created_at = (Get-Date).ToUniversalTime().ToString('o')
            helper_sha256 = Get-FileSha256 $BootstrapScriptPath
            integrity_helper_sha256 = Get-FileSha256 $BootstrapIntegrityFunctions
            receipt_path = Get-StrictFullPath $BootstrapBoundParameters['ReplacementReceiptPath'] 'replacement receipt binding path'
            install_root = $installRootFull
            install_parent = $applicationParent
            rollback_root = $replacementRollbackRoot
            failed_root = Join-Path $applicationParent ('.current.failed.' + $ReplacementTransactionId)
            parent_acl = $parentAcl
            old = $oldIdentity
            new = $newIdentity
            identity_or_credential_copied = $false
        }
        # Bind the original startup state before any startup mutation. The
        # immutable receipt is created once. Keep its caller/export path binding.
        if (-not $testOverride -and
            (Test-Path -LiteralPath (Join-Path $installRootFull 'app\auto-update-settings.json') -PathType Leaf)) {
            Set-InstallationEvidenceStage 'placement.startup_preimage'
            $Script:StartupUpdatePreimage = Save-ContainerStartupUpdatePreimage $installRootFull 'install'
            $receiptPayload['startup_update_preimage'] = [string]$Script:StartupUpdatePreimage.path
            $receiptPayload['startup_update_preimage_sha256'] = [string]$Script:StartupUpdatePreimage.sha256
        }
        $replacementReceipt = Write-BootstrapReplacementReceipt `
            -Path $replacementReceiptFull `
            -Payload $receiptPayload
        $replacementReceiptWritten = $true
        Write-InstallationEvidenceEvent ([ordered]@{event='REPLACEMENT_RECEIPT_READY';path=$replacementReceipt.path;
            sha256=$replacementReceipt.sha256;old_manifest_sha256=$oldIdentity.manifest_sha256;
            new_manifest_sha256=$newIdentity.manifest_sha256;transaction_id=$ReplacementTransactionId})
    }
    elseif($bootstrapStatus -ceq 'REUSED' -and $ReplaceExistingVerifiedPortable -and $WriterFencePreparedReceiptPath){
        [void](Write-BootstrapReusedPlacementEvidence $sourceRootFull $installRootFull $ReplacementTransactionId $OperatorSid $BootstrapScriptPath)
    }
    if ($RestoreUninstallRecordPath -and
        (Get-FileSha256 (Join-Path $installRootFull $IntegrityFileName)) -cne $ExpectedUninstallRecordSha256) {
        throw 'Uninstall recovery installed record readback failed.'
    }
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("bootstrap_status=$bootstrapStatus")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("acl_readback_status=$aclReadbackStatus")))
    if ($aclReadbackStatus -ceq 'PASS') {
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("acl_owner_sid=S-1-5-32-544")))
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("dacl_normalized=true")))
    }
    Write-InstallationHelperPublicRecord @{code_root=$installRootFull}
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("release_layout=$releaseLayout")))
    Write-InstallationHelperPublicRecord @{integrity_record_path=(Join-Path $installRootFull $IntegrityFileName)}
    Set-InstallationEvidenceStage 'placement.startup_update'
    Initialize-ContainerStartupUpdate $installRootFull
    Set-InstallationEvidenceStage 'placement.tls_bootstrap'
    $tlsCaBootstrap = Install-CurrentUserTlsCaBootstrap $TlsCaBundlePath $OperatorLocalAppDataRoot
    if ($null -eq $tlsCaBootstrap) { Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("tls_ca_bootstrap_status=ABSENT"))) }
    else { Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("tls_ca_bootstrap_status=PASS"))); Write-InstallationHelperPublicRecord @{tls_ca_bootstrap_path=$tlsCaBootstrap} }
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("file_count=$($sourceInventory.Count)")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("aggregate_sha256=$sourceAggregate")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("identity_profile_created=false")))
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("elevation_points=1:code_placement")))
    if ($replacementApplied) {
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('replacement_rollback_status=PRESERVED')))
        Write-InstallationHelperPublicRecord @{replacement_rollback_root=$replacementRollbackRoot}
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('replacement_receipt_status=OLD_PRESERVED_NEW_VERIFIED')))
        Write-InstallationHelperPublicRecord @{replacement_receipt_path=$replacementReceipt.path}
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_receipt_sha256=$($replacementReceipt.sha256)")))
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_transaction_id=$ReplacementTransactionId")))
    }
    if (-not $testOverride) {
        Write-ElevationLog 'PASS' "Elevated Container code placement completed: $bootstrapStatus."
        Complete-InstallationEvidenceStage 'forward'
    }
}
catch {
    Write-InstallationCaughtFailure $_

    $originalPlacementFailure = $_
    Fail-InstallationEvidenceStages $originalPlacementFailure
    $Script:PlacementRollbackSteps=@()
    $Script:PlacementRollbackSteps+=,(Invoke-ContainerPlacementRollbackStep 'startup_preimage' {
        if($null -ne $Script:StartupUpdatePreimage){Restore-ContainerStartupUpdatePreimage $installRootFull $Script:StartupUpdatePreimage.path $Script:StartupUpdatePreimage.sha256}
    })
    $otherSessionPreflightFailure = (
        -not $replacementApplied -and
        $originalPlacementFailure.Exception.Message -ceq 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING'
    )
    if ($otherSessionPreflightFailure) {
        $failureCode = 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING'
        if (-not $testOverride) {
            try { Write-ElevationLog 'PREFLIGHT_FAILED' $failureCode }
            catch {
    Write-InstallationCaughtFailure $_

                Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('code_placement_preflight_failure=CONTAINER_PLACEMENT_LOG_WRITE_FAILED')))
                exit 42
            }
        }
        Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]("code_placement_preflight_failure=$failureCode")))
    } elseif (-not $testOverride) {
        try{Write-ElevationLog 'FAILED' ($originalPlacementFailure.Exception.GetType().Name)}catch{Write-InstallationCaughtFailure $_}
    }
    $Script:PlacementRollbackSteps+=,(Invoke-ContainerPlacementRollbackStep 'staging_cleanup' {
    if (Test-Path -LiteralPath $stagingRoot) {
        $stagingFull = Get-StrictFullPath $stagingRoot "bootstrap staging root"
        $parentFull = (Get-StrictFullPath $applicationParent "application parent") + '\'
        if (-not $stagingFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Bootstrap failed and staging cleanup target escaped its parent."
        }
        Remove-Item -LiteralPath $stagingFull -Recurse -ErrorAction Stop
        if(Test-Path -LiteralPath $stagingFull){throw 'Staging cleanup readback failed.'}
    }
    })
    $recoveryState=@{tree_restored=$false}
    $Script:PlacementRollbackSteps+=,(Invoke-ContainerPlacementRollbackStep 'contain_and_restore_tree' {
    if ($replacementApplied) {
        Assert-ContainerDataGenerationTarget -CandidateRoot $replacementRollbackRoot -TargetSid $OperatorSid `
            -LocalAppDataRoot $OperatorLocalAppDataRoot -DataRoot $OperatorDataRoot -HelperRoot $PSScriptRoot
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
    Set-InstallationEvidenceStage 'rollback.old_tree_readback' 'rollback'
        $restoredIdentity = Get-BootstrapReplacementTreeIdentity $installRootFull $installRootFull
        if (-not (Test-BootstrapReplacementTreeIdentity $previousReplacementIdentity $restoredIdentity)) {
            throw 'Verified replacement prior tree restore readback failed.'
        }
        $recoveryState.tree_restored=$true
    }
    })
    $Script:PlacementRollbackSteps+=,(Invoke-ContainerPlacementRollbackStep 'receipt_cleanup' {
      if($recoveryState.tree_restored){
        if ($replacementReceiptWritten -and (Test-Path -LiteralPath $replacementReceiptFull -PathType Leaf)) {
            Remove-Item -LiteralPath $replacementReceiptFull -ErrorAction Stop
            if(Test-Path -LiteralPath $replacementReceiptFull){throw 'Replacement receipt cleanup readback failed.'}
        }
      }
    })
    Complete-InstallationEvidenceStage 'rollback'
    # Failed recovery steps remain recorded independently; never replace the
    # first placement exception or delete a receipt for an unverified tree.
    throw $originalPlacementFailure
}
}
catch {
    $originalHelperFailure=$_
    Fail-InstallationEvidenceStages $originalHelperFailure
    $diagnostic=Get-InstallationFallbackDiagnostic $originalHelperFailure
    $contextFailure=Get-Variable -Name ContainerLifecycleContextFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $contextFailure){$diagnostic.lifecycle_context_failure=$contextFailure}
    $rollbackSteps=Get-Variable -Name PlacementRollbackSteps -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $rollbackSteps){$diagnostic.rollback_steps=@($rollbackSteps|ForEach-Object {@{step=$_.step;status=$_.status}})}
    $publicFailure=Get-InstallationHelperPublicFailure $originalHelperFailure $diagnostic.exit_code
    [Console]::Out.WriteLine('installation_failure_summary='+($publicFailure | ConvertTo-Json -Depth 4 -Compress))
    exit $diagnostic.exit_code
}
finally {
    if ($null -ne $placementWriterFenceLease) {
        Exit-ContainerWriterAdmission $placementWriterFenceLease
    }
    Complete-InstallationEvidenceStage 'forward'
    Complete-InstallationEvidenceStage 'rollback'
    $helperEvidenceSummary=Complete-InstallationEvidence
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('installation_evidence_status='+[string]$helperEvidenceSummary.status))))
    Write-InstallationHelperPublicRecord @{summary_path=$helperEvidenceSummary.summary_path}
}
