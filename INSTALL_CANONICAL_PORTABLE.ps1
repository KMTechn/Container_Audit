[CmdletBinding()]
param(
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\KMTech\Apps\Container_Audit\current",
    [string]$EvidencePath = "",
    [string]$ServerBaseUrl = "",
    [string]$WorkerAccount = "",
    [string]$WorkerSurveyInventory = "",
    [switch]$PlanOnly,
    [switch]$RecoverMachineInstallation,
    [string]$MachineRecoveryAuditPath = "",
    [string]$MachineRecoveryAuditSha256 = "",
    [switch]$Uninstall,
    [switch]$CompleteRetiredRemoval,
    [string]$OldSourceRoot = "",
    [string]$RetiredRemovalReceiptSha256 = "",
    [string]$RetiredStopMarkerSha256 = "",
    [string]$ResumeRetirementReceiptPath = "",
    [string]$ResumeRetirementReceiptSha256 = "",
    [switch]$RestoreVerifiedReplacement,
    [string]$RestoreReceiptPath = "",
    [string]$RestoreReceiptSha256 = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$SkipSignatureValidationForTest
)
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop

$ErrorActionPreference = 'Stop'
$CanonicalRoot = 'C:\KMTech\Apps\Container_Audit\current'
$RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$RunName = 'KMTech.ContainerAudit.Relay'
$CanonicalWriterTaskName = 'direct-sync-relay-container-audit'
$NoncanonicalQualificationTaskName = 'container-audit-isolated-qualification-authority'
$Script:CanonicalWriterFenceSessionId = ''
$Script:CanonicalWriterFenceAttemptId = ''
$Script:CanonicalWriterFenceTransactionId = ''
$Script:CanonicalWriterFenceDelegationToken = ''
$retirementAuditSealed = $false
$audit = $null
$outputFailure = $null
$canonicalInstallationCommitPoint = 'NOT_REACHED'
$canonicalTransactionJob = $null
$enteredPlacementTry = $false
$currentAbsentBeforePlacement = $false
$Script:CanonicalPreparationAdmissionFailed = $false
$Script:CanonicalInstallerSourceInventorySha256 = ''
$testMode = $AllowNoncanonicalLayoutForTest -and
    [string]$env:KMTECH_FACTORY_INSTALL_TEST_MODE -ceq '1'
if ($SkipSignatureValidationForTest -and -not $testMode) {
    throw 'Signature bypass is test-only.'
}
$onboardingServerBaseUrl = ''
$onboardingServerBaseUri = $null
if (-not [string]::IsNullOrEmpty($ServerBaseUrl)) {
    if (
        $ServerBaseUrl -match '[\s"\\]' -or
        -not [Uri]::TryCreate($ServerBaseUrl, [UriKind]::Absolute, [ref]$onboardingServerBaseUri) -or
        $onboardingServerBaseUri.Scheme -cne 'https' -or
        [string]::IsNullOrEmpty($onboardingServerBaseUri.Host) -or
        $onboardingServerBaseUri.IsLoopback -or
        $onboardingServerBaseUri.Port -lt 1 -or
        $onboardingServerBaseUri.UserInfo -cne '' -or
        $onboardingServerBaseUri.Query -cne '' -or
        $onboardingServerBaseUri.Fragment -cne '' -or
        $onboardingServerBaseUri.AbsolutePath -cnotin @('', '/')
    ) { throw 'ServerBaseUrl must be a credential-free HTTPS origin without path, query, or fragment.' }
    $onboardingServerBaseUrl = $ServerBaseUrl.TrimEnd('/')
}
$onboardingServerBaseUrlLabel = if ($onboardingServerBaseUrl) { $onboardingServerBaseUrl } else { 'PRODUCT_DEFAULT' }

$BootstrapIntegrityFunctions = Join-Path $PSScriptRoot 'tools\bootstrap_integrity.ps1'
# Generated with the writer inventory: authenticate this earlier bootstrap load.
$ExpectedBootstrapIntegritySha256 = '43b67845c82983e01ab5b412ce9947bc3f1b240595d590099f4e507e8110c86e'
if ((Get-FileHash -LiteralPath $BootstrapIntegrityFunctions -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedBootstrapIntegritySha256) {
    throw 'Bootstrap integrity helper pin mismatch.'
}
. $BootstrapIntegrityFunctions
$sharedLeaf = Get-BootstrapSharedPortableLeaf $PSScriptRoot
. $sharedLeaf

function Full([string]$Value, [string]$Purpose) {
    return ConvertTo-KmtechFullPath $Value $Purpose
}
function Same([string]$Left, [string]$Right) {
    return (Full $Left 'left path').Equals((Full $Right 'right path'), 'OrdinalIgnoreCase')
}
function Test-ExactPropertySet($Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) { return $false }
    }
    return $true
}
function Test-ExactStringProperties($Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    foreach ($name in $Names) {
        $property = $Value.PSObject.Properties[$name]
        if ($null -eq $property -or -not ($property.Value -is [string])) { return $false }
    }
    return $true
}
function Test-JsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}
function Test-JsonTrue($Value) {
    return ($Value -is [bool] -and $Value)
}
function Test-JsonPositiveInt32($Value) {
    if (-not (Test-JsonInteger $Value)) { return $false }
    return ([int64]$Value -gt 0 -and [int64]$Value -le [int]::MaxValue)
}
function Get-CanonicalInstallationCommitPoint {
    param($Manifest,[string]$TargetSid,[string]$LocalAppDataRoot,[string]$DataRoot,[string]$HelperRoot)
    try {
        . (Get-BootstrapSharedPortableLeaf $HelperRoot 'data_generation.ps1')
        Assert-KmtechDataIdentity 'container_audit' $TargetSid
        $local=Get-StrictFullPath $LocalAppDataRoot 'operator LOCALAPPDATA'
        if(-not $DataRoot){$DataRoot=Join-Path $local 'KMTech\ContainerAudit'}
        $data=Get-StrictFullPath $DataRoot 'operator data root'
        $markers=@((Join-Path $data 'data-generation.json'),
            (Join-Path $local ('KMTech\DirectSync\container_audit\control\writer-session\data-generation\'+$TargetSid+'.json')))
        $records=@()
        foreach($marker in $markers){
            $record=Read-KmtechDataGeneration $marker 'container_audit' $TargetSid
            if($null -ne $record){$records+=,$record}
        }
        if($records.Count -eq 0){return 'NOT_REACHED'}
        $version=ConvertTo-KmtechDataVersion ([string]$Manifest.version)
        $build=[string]$Manifest.source_commit
        Assert-KmtechDataBuildIdentity $build
        $reached=$false
        foreach($record in $records){
            $comparison=(ConvertTo-KmtechDataVersion ([string]$record.version)).CompareTo($version)
            if($comparison -gt 0){return 'UNKNOWN'}
            if($comparison -eq 0 -and [string]$record.build_id -ceq $build){$reached=$true}
        }
        if($reached){return 'REACHED'}
        return 'NOT_REACHED'
    }catch{return 'UNKNOWN'}
}

function Get-CanonicalRollbackSuccessStatus {
    param([bool]$Restore,[string]$CommitPoint)
    if($Restore){return 'FAILED_RESTORE_RUNTIME_RECOVERED'}
    if($CommitPoint -ceq 'REACHED'){return 'FAILED_RUNTIME_RESTORED_CODE_RETAINED'}
    if($CommitPoint -ceq 'NOT_REACHED'){return 'FAILED_ROLLED_BACK'}
    return 'CODE_ROLLBACK_FAILED'
}

function Get-CanonicalTransactionBaseArguments {
    return @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
        '-SourceRoot',$source,'-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,
        '-OperatorDataRoot',$activeDataRoot,'-ElevationLogPath',$elevationLogPath,
        '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
        '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
        '-WriterFenceHelperPath',(Join-Path $source 'tools\container_writer_fence.ps1'),
        '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
        '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,'-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
        '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
        '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken)
}

function Get-CanonicalGlobalRelayPreimage {
    $records=@()
    foreach($relay in @(Relays)){
        $process=[Diagnostics.Process]::GetProcessById([int]$relay.ProcessId)
        try{$started=$process.StartTime.ToUniversalTime().ToString('o')}finally{$process.Dispose()}
        $security=Get-CanonicalRelaySecurity ([int]$relay.ProcessId)
        $records+=,[ordered]@{process_id=[int]$relay.ProcessId;started_at_utc=$started;
            executable_path=[string]$relay.ExecutablePath;command_line=[string]$relay.CommandLine;
            sid=[string]$security.sid;session_id=[int]$security.session_id}
    }
    return $records
}

function Get-CanonicalTransactionManagedRelays($Configuration,[object[]]$Actual) {
    $baseline=@($Configuration.relay_preimage)
    $quiesced=@($Configuration.quiesce_relays)
    $managed=@($quiesced|ForEach-Object {[int]$_.process_id})
    $foreign=@($baseline|Where-Object {[int]$_.process_id -cnotin $managed})
    foreach($expected in $foreign){
        $matching=@($actual|Where-Object {[int]$_.process_id -eq [int]$expected.process_id -and
            [string]$_.started_at_utc -ceq [string]$expected.started_at_utc -and
            (Same ([string]$_.executable_path) ([string]$expected.executable_path)) -and
            [string]$_.command_line -ceq [string]$expected.command_line -and
            [string]$_.sid -ceq [string]$expected.sid -and [int]$_.session_id -eq [int]$expected.session_id})
        if($matching.Count -ne 1){throw 'Transaction outside relay preimage differs.'}
    }
    $foreignIds=@($foreign|ForEach-Object {[int]$_.process_id})
    $remaining=@($actual|Where-Object {[int]$_.process_id -cnotin $foreignIds})
    return $remaining
}

function Assert-CanonicalTransactionRelayPreimage($Configuration,[switch]$AfterRestore) {
    $actual=@(Get-CanonicalGlobalRelayPreimage)
    $quiesced=@($Configuration.quiesce_relays)
    $remaining=@(Get-CanonicalTransactionManagedRelays $Configuration $actual)
    if(-not $AfterRestore){
        if($remaining.Count){throw 'Transaction-created or unquiesced relay remains.'}
    }else{
        if($remaining.Count -ne $quiesced.Count){throw 'Transaction restored relay count differs.'}
        foreach($expected in $quiesced){
            $matching=@($remaining|Where-Object {(Same ([string]$_.executable_path) ([string]$expected.executable_path)) -and
                (Get-CanonicalRelayCommandIdentity ([string]$_.command_line) ([string]$_.executable_path)) -ceq
                (Get-CanonicalRelayCommandIdentity ([string]$expected.command_line) ([string]$expected.executable_path)) -and
                [string]$_.sid -ceq [string]$expected.sid -and [int]$_.session_id -eq [int]$expected.session_id -and
                [int]$_.process_id -ne [int]$expected.process_id -and [string]$_.started_at_utc -cne [string]$expected.started_at_utc})
            if($matching.Count -ne 1 -or [string]$Script:CanonicalRelayProof.status -cne 'PROVEN' -or
                [int]$Script:CanonicalRelayProof.process_id -ne [int]$matching[0].process_id){throw 'Transaction restored relay identity/READY is unproven.'}
        }
    }
    return ,$actual
}

function New-CanonicalTransactionConfiguration {
    $context=[ordered]@{}
    foreach($name in @('RunKey','RunName','CanonicalWriterTaskName','NoncanonicalQualificationTaskName','source','install','installedCodeRoot',
        'operatorSid','lad','activeDataRoot','stop','removalPath','relayPath','auditRoot','auditPath','runId','sourceManifest','sourceManifestSha256',
        'sourceHelperSha256','sourceIntegrityHelperSha256','installedInventorySha256','currentAbsentBeforePlacement','before','old',
        'writerBefore','legacyRelayPreimage','supportedPlacement','SkipSignatureValidationForTest','testMode','wanted','candidate',
        'canonicalWriterFenceStartedAtUtc','canonicalWriterFenceOrchestratorSha256','canonicalWriterFenceContractSha256',
        'canonicalWriterFencePreparedReceipt','canonicalWriterFenceDelegatedSources','elevationLogPath')){
        $value=Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue
        $context[$name]=$value
    }
    $context.old=@($old)
    $context.SkipSignatureValidationForTest=[bool]$SkipSignatureValidationForTest
    $base=@(Get-CanonicalTransactionBaseArguments)
    if($testMode){$base+='-AllowNoncanonicalLayoutForTest'}
    $placementArguments=@($base)
    if($placement -ceq 'INSTALL_REQUIRED' -and -not $currentAbsentBeforePlacement){
        $placementArguments+=@('-ReplaceExistingVerifiedPortable','-ReplacementTransactionId',$replacementTransactionId,
            '-ReplacementReceiptPath',$replacementReceiptPath)
    }
    if($supportedPlacement){$placementArguments+=@('-SupportedActiveVersionPlacement','-SupportedFromCommit',([string]$supportedContext.from_commit))}
    $environment=[ordered]@{}
    foreach($name in @('LOCALAPPDATA','APPDATA','CONTAINER_AUDIT_DATA_ROOT','CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',
        'CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID','CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID','CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID')){
        $environment[$name]=[Environment]::GetEnvironmentVariable($name,'Process')
    }
    $savedRelayPreimage=Get-Variable -Name CanonicalInstallerRelayPreimage -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $relayPreimage=if($null -ne $savedRelayPreimage){@($savedRelayPreimage)}else{@(Get-CanonicalGlobalRelayPreimage)}
    $oldIds=@($old|ForEach-Object {[int]$_.ProcessId})
    $quiesceRelays=@($relayPreimage|Where-Object {[int]$_.process_id -cin $oldIds})
    if($quiesceRelays.Count -ne $oldIds.Count){throw 'Canonical relay quiesce preimage is unproven.'}
    return [ordered]@{source_root=$source;install_root=$install;operator_sid=$operatorSid;local_appdata_root=$lad;data_root=$activeDataRoot;
        relay_preimage=$relayPreimage;quiesce_relays=$quiesceRelays;
        source_manifest=$sourceManifest;context=$context;base_arguments=$base;placement_arguments=$placementArguments;
        operator_security=(Get-CanonicalRelaySecurity $PID);child_environment=$environment;test_mode=[bool]$testMode;timeout_seconds=900;
        session_id=$Script:CanonicalWriterFenceSessionId;attempt_id=$Script:CanonicalWriterFenceAttemptId;
        transaction_id=$Script:CanonicalWriterFenceTransactionId;orchestrator_sha256=$canonicalWriterFenceOrchestratorSha256;
        writer_contract_sha256=$canonicalWriterFenceContractSha256;helper_sha256=$sourceHelperSha256;library_sha256=$sourceIntegrityHelperSha256;
        fence_helper_sha256=[string]$sourceManifest.writer_fence_helper_sha256;installed_inventory_sha256=$installedInventorySha256;
        prepared_path=[string]$canonicalWriterFencePreparedReceipt.path;prepared_sha256=[string]$canonicalWriterFencePreparedReceipt.sha256;
        delegation=$Script:CanonicalWriterFenceDelegationToken;release_paths=@{product_complete=$productCompleteAuthorizationPath;product_natural=$productNaturalTriggerAuthorizationPath}}
}

function Assert-CanonicalTransactionInstalledCandidate($Configuration) {
    $context=$Configuration.context
    [void](Assert-BootstrapIntegrityRecord ([string]$context.installedCodeRoot))
    $actual=InstalledManifest ([string]$context.installedCodeRoot) ([bool]$context.SkipSignatureValidationForTest)
    if([string]$actual.source_commit -cne [string]$Configuration.source_manifest.source_commit -or
        [string]$actual.source_tree -cne [string]$Configuration.source_manifest.source_tree -or
        (Sha (Join-Path ([string]$context.installedCodeRoot) 'portable-manifest.json')) -cne [string]$context.sourceManifestSha256){
        throw 'Installation transaction installed candidate identity differs.'
    }
}

function Assert-CanonicalTransactionCommit($Configuration) {
    foreach($property in $Configuration.context.PSObject.Properties){Set-Variable -Name $property.Name -Value $property.Value}
    Assert-CanonicalTransactionInstalledCandidate $Configuration
    Assert-BootstrapNoReparsePoint $auditPath 'installation transaction final audit' -PathOnly
    $stream=[IO.File]::Open($auditPath,'Open','Read','Read')
    try{
        if($stream.Length -lt 1 -or $stream.Length -gt 1048576){throw 'Installation transaction final audit size differs.'}
        [byte[]]$bytes=([IO.BinaryReader]::new($stream)).ReadBytes([int]$stream.Length)
        if($bytes.Length -ne $stream.Length -or $stream.ReadByte() -ne -1){throw 'Installation transaction final audit read differs.'}
    }finally{$stream.Dispose()}
    $record=ConvertFrom-InstallationTransactionJson ([Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff))
    if([string]$record.schema -cne 'container-audit-canonical-portable-install-v2' -or
        [string]$record.operation -cne 'INSTALL' -or [string]$record.status -cne (Get-CanonicalInstallSuccessStatus $testMode) -or
        [string]$record.run_id -cne $runId -or -not(Same ([string]$record.install_root) $install) -or
        [string]$record.source_commit -cne [string]$sourceManifest.source_commit -or
        [string]$record.source_manifest_sha256 -cne $sourceManifestSha256 -or
        [string]$record.code_replacement.transaction_id -cne [string]$Configuration.transaction_id -or
        [string]$record.exact_launch.status -cne 'PROVEN' -or [int]$record.exact_launch.process_id -le 0){
        throw 'Installation transaction final audit identity/status differs.'
    }
    $run=Snapshot
    if(-not $run.exists -or [string]$run.kind -cne 'String' -or [string]$run.data -cne $wanted -or
        (Test-Path -LiteralPath $stop)){throw 'Installation transaction committed runtime persistence differs.'}
    $identity=Get-BootstrapRelayExpectedIdentity $install $wanted
    $snapshot=Get-BootstrapRelayReadinessSnapshot $identity
    $process=Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$record.exact_launch.process_id)" -ErrorAction Stop
    $security=Get-CanonicalRelaySecurity ([int]$record.exact_launch.process_id)
    $status=(Read-InstallationTransactionFile $relayPath).Record
    if(-not $snapshot.settled -or -not(Test-BootstrapRelayReadback $snapshot.identity $process $security $Configuration.operator_security `
        $status ([DateTime]::Parse($canonicalWriterFenceStartedAtUtc).ToUniversalTime()) '' (Sha $relayPath))){
        throw 'Installation transaction committed resident relay READY is unproven.'
    }
}

function Get-CanonicalInstallSuccessStatus([bool]$IsTestMode) {
    if ($IsTestMode) { return 'TEST_ONLY_PARTIAL' }
    return 'PASS'
}
function Write-CanonicalPreparationAdmissionFailure([string]$AuditPathValue, [string]$EvidencePathValue,
    [string]$SourceRootValue = '', [string]$SourceInventorySha256 = '', $Failure = $null) {
    $typedFailure = [ordered]@{code='FAILED_PREPARATION_ADMISSION';exception_types=@();script_line=0}
    if ($null -ne $Failure) {
        $detail = Get-CanonicalFailureDetails $Failure 'PREPARATION'
        $typedFailure.exception_types = @($detail.exception_types)
        $typedFailure.script_line = [int]$detail.script_line
    }
    $record = [ordered]@{
        schema='container-audit-canonical-portable-install-v2';operation='INSTALL'
        run_id=([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N'));captured_at=[DateTime]::UtcNow.ToString('o')
        status='FAILED';preparation_status='FAILED_PREPARATION_ADMISSION';code_placement='NOT_STARTED'
        source_root=$(if($SourceRootValue){$SourceRootValue}else{$null})
        source_inventory_sha256=$(if($SourceInventorySha256 -cmatch '^[0-9a-f]{64}$'){$SourceInventorySha256}else{$null})
        preparation_failure=$typedFailure
        rollback=[ordered]@{status='NOT_REQUIRED';available=$false;applied=$false;runtime_restored=$false}
    }
    $relayRecovery=Get-Variable -Name CanonicalInstallerEarlyRecovery -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $relayRecovery){
        $record.installer_relay_recovery=$relayRecovery
        $record.rollback.status=[string]$relayRecovery.status
        $record.rollback.available=$true
        $record.rollback.applied=[bool]$relayRecovery.stop_preimage_restored
        $record.rollback.runtime_restored=[bool]$relayRecovery.ready_proven
        if([string]$relayRecovery.status -ceq 'RECOVERY_REQUIRED'){$record.preparation_failure.code='RECOVERY_REQUIRED'}
    }
    try {
        if (-not $AuditPathValue) {
            $root = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
            $AuditPathValue = Join-Path $root ('KMTech\ContainerAudit\install-audit\canonical-portable-'+$record.run_id+'.json')
        }
        # Reuse the existing diagnostic preparation and machine-metadata writer.
        # Generic transaction Save remains confined to its writer authority.
        foreach ($path in @($AuditPathValue, $EvidencePathValue)) {
            if (-not $path) { continue }
            $path = Full $path 'preparation audit'
            $parent = Split-Path -Parent $path
            if (-not (Test-Path -LiteralPath $parent)) {
                [void](Initialize-InstallationEvidence $path ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
            }
            Assert-BootstrapNoReparsePoint $parent 'preparation audit parent' -PathOnly
            if (Test-Path -LiteralPath $path) { Assert-BootstrapNoReparsePoint $path 'preparation audit' -PathOnly }
            if (Test-Path -LiteralPath "$path.tmp.$PID") { throw 'PREPARATION_AUDIT_TEMP_PREEXISTS' }
            Write-Utf8Json $path $record
        }
        'audit_path='+$AuditPathValue
    } catch { 'preparation_audit_status=UNAVAILABLE' }
    'install_status=FAILED'
}
function Invoke-ContainerSourceDataAdmission([string]$Source, [string]$InventorySha256,
    [string]$AuditPathValue, [string]$ExternalEvidencePath) {
    try {
        $Script:canonicalOnboardingInputBinding = Get-CanonicalOnboardingInputBinding $Source `
            -InstallerSourceInventorySha256 $InventorySha256
    } catch {
        $admissionFailure = $_
        $Script:CanonicalPreparationAdmissionFailed = $true
        if(@(Relays).Count -eq 0){Write-CanonicalInstallerRelayGuidance}
        Write-CanonicalPreparationAdmissionFailure $AuditPathValue $ExternalEvidencePath $Source $InventorySha256 $admissionFailure
        throw $admissionFailure
    }
}
function Sha([string]$Path) {
    return Get-KmtechFileSha $Path
}
function Get-WriterContractSessionMutexName(
    [string]$SessionId,
    [string]$AttemptId,
    [string]$OrchestratorSha256,
    [string]$ReplacementTransactionId,
    [string]$WriterContractSha256
) {
    $tuple = (@(
        'container-audit-deployment-session-authority-v1',
        $SessionId,
        $AttemptId,
        $OrchestratorSha256,
        $ReplacementTransactionId,
        $WriterContractSha256
    ) | ForEach-Object { ([string]$_).Normalize([Text.NormalizationForm]::FormC) }) -join "`n"
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($tuple)
        $digest = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
    return 'Local\KMTech.ContainerAudit.DeploymentSession.' + $digest
}
function Write-CanonicalInstallationPublicRecord($Failure=$null,[int]$ExitCode=0) {
    $guidance='자료를 보존하고 관리자 지원 복구를 요청하세요.'
    $elevationRecovered=($ExitCode -ne 0 -and $null -ne $audit -and
        [string]$audit.status -ceq 'FAILED_ROLLED_BACK' -and [bool]$audit.rollback.runtime_restored -and
        -not $canonicalWriterFenceActive -and
        [string]$audit.code_replacement.failure_code -ceq 'CONTAINER_PLACEMENT_ELEVATION_FAILED')
    if($elevationRecovered){$guidance='관리자 권한 요청을 완료하지 못했습니다. 이번 설치의 변경을 되돌렸습니다. 관리자 실행을 다시 확인하세요.'}
    $fields=[ordered]@{status=if($ExitCode){'FAILED'}else{'PASS'};stage='canonical_install';
        reason_code=if($ExitCode){'INSTALLER_CANONICAL_FAILURE'}else{'INSTALLER_CHILD_RESULT'};
        exit_code=$ExitCode;guidance=$guidance;report_status='REPORT_UNAVAILABLE'}
    if($elevationRecovered){
        $fields.reason_code='CONTAINER_PLACEMENT_ELEVATION_FAILED'
        $fields.install_status='FAILED_ROLLED_BACK'
        $fields.runtime_restored=$true
    }
    $relayRecovery=Get-Variable -Name CanonicalInstallerEarlyRecovery -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($ExitCode -ne 0 -and $null -ne $relayRecovery -and [string]$relayRecovery.status -ceq 'RECOVERY_REQUIRED'){
        $fields.reason_code='RECOVERY_REQUIRED';$fields.recovery_status='RECOVERY_REQUIRED'
    }
    if($Failure){
        $exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
        $fields.exception_type=$exception.GetType().FullName
        if($Failure -is [Management.Automation.ErrorRecord]){$fields.location_line=[int]$Failure.InvocationInfo.ScriptLineNumber}
        $reference=$exception.Data['installation_original_failure_reference']
        $published=Get-Variable -Name InstallationMostRecentOriginalFailureReference -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($root -and $reference -and [object]::ReferenceEquals($reference,$published) -and $reference.Contains('atomic_published') -and $reference.atomic_published -eq $true){
            try{
                Assert-InstallationEvidenceWriteRoot $root
                $path=[IO.Path]::GetFullPath([string]$reference.path)
                if(-not [IO.Path]::GetDirectoryName($path).Equals([IO.Path]::GetFullPath($root),[StringComparison]::OrdinalIgnoreCase)){throw 'Report attempt differs.'}
                if(Test-InstallationEvidencePrivileged){Assert-InstallationEvidenceProtectedPath $path}
                $digest=Get-FileSha256 $path
                if($digest -cne [string]$reference.sha256){throw 'Report readback differs.'}
                $fields.Remove('report_status');$fields.report_path=$path;$fields.report_sha256=$digest
            }catch{}
        }
    }
    if(Get-Command ConvertTo-KmtechPublicRecord -ErrorAction SilentlyContinue){
        $fields=ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes @('RECOVERY_REQUIRED','PASS','FAILED','canonical_install','INSTALLER_CANONICAL_FAILURE','INSTALLER_CHILD_RESULT','REPORT_UNAVAILABLE','CONTAINER_PLACEMENT_ELEVATION_FAILED','FAILED_ROLLED_BACK') -SafeMessages @($guidance)
    }
    Write-Output ('CONTAINER_AUDIT_INSTALL_CANONICAL='+($fields|ConvertTo-Json -Depth 4 -Compress))
}
function Assert-WriterSessionPublicContract(
    [string]$Path,
    [string]$ExpectedSha256,
    [string]$ExpectedWriterInventorySha256
) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 65536) { throw 'Writer session public contract is oversized.' }
    if ((Sha $Path) -cne $ExpectedSha256) { throw 'Writer session public contract hash differs.' }
    try { $contract = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'Writer session public contract JSON is invalid.' }
    $vectors = @($contract.all_writer_fence.verification_vectors)
    $vectorsExact = ($vectors.Count -eq 2)
    foreach ($vector in $vectors) {
        if (
            $vector.session_id -isnot [string] -or
            $vector.attempt_id -isnot [string] -or
            $vector.orchestrator_sha256 -isnot [string] -or
            $vector.replacement_transaction_id -isnot [string] -or
            $vector.writer_contract_sha256 -isnot [string] -or
            $vector.expected_mutex_name -isnot [string] -or
            [string]$vector.expected_mutex_name -cne (Get-WriterContractSessionMutexName `
                ([string]$vector.session_id) `
                ([string]$vector.attempt_id) `
                ([string]$vector.orchestrator_sha256) `
                ([string]$vector.replacement_transaction_id) `
                ([string]$vector.writer_contract_sha256))
        ) { $vectorsExact = $false }
    }
    if (
        [string]$contract.schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$contract.app_id -cne 'container_audit' -or
        [string]$contract.cli.relative_path -cne 'tools/container_writer_session.ps1' -or
        (@($contract.cli.public_writer_modes) -join ',') -cne 'Contract,Prepare,ValidatePrepared,RestoreWriter' -or
        [string]$contract.identifiers.session_authority_mutex_derivation -cne 'Local\KMTech.ContainerAudit.DeploymentSession.<sha256(v1 canonical session tuple)>' -or
        [string]$contract.all_writer_fence.active_schema -cne 'container-audit-all-writer-fence-active-v1' -or
        [string]$contract.all_writer_fence.release_schema -cne 'container-audit-all-writer-fence-release-v1' -or
        [string]$contract.all_writer_fence.control_root -cne '%LOCALAPPDATA%\KMTech\DirectSync\container_audit\control\writer-session' -or
        [string]$contract.all_writer_fence.active_filename -cne 'active.json' -or
        [string]$contract.all_writer_fence.release_filename_pattern -cne 'release-{replacement_transaction_id}-{release_authorization_sha256}.json' -or
        [string]$contract.all_writer_fence.admission_mutex_name -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1' -or
        [string]$contract.all_writer_fence.noncanonical_mutex_derivation -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1.<first 16 lowercase hex characters of SHA-256 over the absolute control root after slash-to-backslash conversion, trailing-backslash removal, Unicode NFC, and ASCII A-Z to a-z mapping with every other code point unchanged, encoded as UTF-8 without BOM>' -or
        [string]$contract.all_writer_fence.session_mutex_prefix -cne 'Local\KMTech.ContainerAudit.DeploymentSession.' -or
        [string]$contract.all_writer_fence.session_tuple_version -cne 'container-audit-deployment-session-authority-v1' -or
        (@($contract.all_writer_fence.session_tuple_fields) -join ',') -cne 'session_tuple_version,session_id,attempt_id,orchestrator_sha256,replacement_transaction_id,writer_contract_sha256' -or
        [string]$contract.all_writer_fence.tuple_separator -cne 'LF (U+000A) between ordered fields; no trailing LF' -or
        [string]$contract.all_writer_fence.tuple_encoding -cne 'UTF-8 without BOM' -or
        [string]$contract.all_writer_fence.tuple_normalization -cne 'Unicode NFC applied to each field before joining' -or
        [string]$contract.all_writer_fence.writer_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$contract.all_writer_fence.canonical_installer_delegation_source -cne 'writer_sink_sources from the exact pinned code-derived inventory' -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.scheduled_task_mutation_rule) -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.natural_trigger_phase_rule) -or
        $ExpectedWriterInventorySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$contract.all_writer_fence.writer_inventory_sha256 -cne $ExpectedWriterInventorySha256 -or
        (@($contract.all_writer_fence.active_statuses) -join ',') -cne 'PREPARING,PREPARED,RESTORING,RESTORE_FAILED,INSTALLING' -or
        -not $vectorsExact -or
        -not (Test-JsonTrue $contract.all_writer_fence.writer_admission_fail_closed) -or
        -not (Test-JsonTrue $contract.all_writer_fence.unknown_or_unobservable_is_denied) -or
        $contract.all_writer_fence.denial_mutates_state -isnot [bool] -or [bool]$contract.all_writer_fence.denial_mutates_state -or
        [string]$contract.receipts.prepared_schema -cne 'container-audit-writer-session-prepared-v3' -or
        [string]$contract.receipts.restored_schema -cne 'container-audit-writer-session-restored-v2' -or
        [string]$contract.receipts.lifecycle_restore_schema -cne 'container-audit-replacement-lifecycle-restore-v1' -or
        (@($contract.receipts.prepared_required_bindings) -join ',') -cne 'session_id,attempt_id,replacement_transaction_id,session_started_at_utc,orchestrator_sha256,session_authority_mutex_name,adapter_sha256,contract_sha256,evidence_path,historical_capability.receipt_sha256,historical_capability.capability_binding_sha256' -or
        [string]$contract.lifecycle_restore.product_mode -cne '--restore-current-user-lifecycle-after-replacement' -or
        -not (Test-JsonTrue $contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore) -or
        -not (Test-JsonTrue $contract.security.active_session_authority_mutex_required) -or
        -not (Test-JsonTrue $contract.security.all_writer_fence_required) -or
        -not (Test-JsonTrue $contract.security.all_writer_sinks_require_admission) -or
        -not (Test-JsonTrue $contract.security.evidence_paths_outside_install_parent_required)
    ) { throw 'Writer session public contract semantics differ.' }
}
function Assert-WriterSinkInventory(
    [string]$Path,
    [string]$ExpectedFileSha256,
    [string]$ExpectedContractSha256
) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 1048576) { throw 'Writer sink inventory is oversized.' }
    if ((Sha $Path) -cne $ExpectedFileSha256) { throw 'Writer sink inventory file hash differs.' }
    try { $inventory = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'Writer sink inventory JSON is invalid.' }
    if (
        [string]$inventory.schema_version -cne 'container-audit-writer-sink-inventory-v8' -or
        [string]$inventory.inventory_sha256 -cne $ExpectedContractSha256 -or
        $inventory.writer_sink_sources -isnot [Object[]] -or
        @($inventory.writer_sink_sources).Count -le 0 -or
        @($inventory.writer_sink_sources | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0 -or
        (@($inventory.writer_sink_sources | Sort-Object -Unique) -join "`n") -cne (@($inventory.writer_sink_sources) -join "`n") -or
        @($inventory.uncovered_direct_mutation_functions).Count -ne 0 -or
        @($inventory.caller_fence_reference_failures).Count -ne 0 -or
        @($inventory.powershell_guard_failures).Count -ne 0 -or
        @($inventory.known_route_coverage).Count -le 0 -or
        @($inventory.known_route_coverage | Where-Object { -not (Test-JsonTrue $_.pass) }).Count -ne 0
    ) { throw 'Writer sink inventory contract is not release-admissible.' }
    return $inventory
}
function Arg([string]$Value) {
    if ($Value.Contains('"')) { throw 'A command path contains a quote.' }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}
function Command([string]$Root, [switch]$Installed, [string]$InstalledPacket = '') {
    $command = ('{0} -I -B {1} --container-audit-user-relay' -f
        (Arg (Join-Path $Root 'runtime\pythonw.exe')),
        (Arg (Join-Path $Root 'app\main.py')))
    if ((Test-Path -LiteralPath (Join-Path $Root 'app\auto-update-settings.json')) -or
        (-not $Installed -and (Test-Path -LiteralPath (Join-Path $SourceRoot 'app\auto-update-settings.json'))) -or
        ($Installed -and $InstalledPacket -and (Test-Path -LiteralPath (Join-Path $InstalledPacket 'app\auto-update-settings.json')))) {
        $command = ('{0} -I -B {1} --bootstrap --role relay -- --container-audit-user-relay' -f
            (Arg (Join-Path $Root 'runtime\pythonw.exe')),
            (Arg (Join-Path $Root 'app\auto_update.py')))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_DATA_ROOT)) {
        $dataRoot = Full $env:CONTAINER_AUDIT_DATA_ROOT 'data root'
        $codeRoot = Full $Root 'code root'
        if (
            $dataRoot.Equals($codeRoot, 'OrdinalIgnoreCase') -or
            $dataRoot.StartsWith($codeRoot + '\', 'OrdinalIgnoreCase') -or
            $codeRoot.StartsWith($dataRoot + '\', 'OrdinalIgnoreCase') -or
            $dataRoot.Equals('C:\Sync', 'OrdinalIgnoreCase') -or
            $dataRoot.StartsWith('C:\Sync\', 'OrdinalIgnoreCase')
        ) { throw 'Custom data root must be outside application code and legacy Syncthing paths.' }
        if (-not (Test-Path -LiteralPath $dataRoot -PathType Container)) {
            throw 'Custom data root is unavailable; restore the existing dataset before installation.'
        }
        $command += ' --data-root ' + (Arg $dataRoot)
    }
    return $command
}
function Manifest([string]$Root, [bool]$UnsignedOk) {
    Assert-KmtechPortableTree $Root @(
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
    $path = Join-Path $Root 'portable-manifest.json'
    $value = Read-KmtechPortableManifest $Root
    # New Container Audit screen (same pins as Inspection_worker 402d3b1a): an older zero-PE release lists no
    # unsigned PE; otherwise exactly these app-relative files, each byte-identical to the builder pin.
    $unsignedPe = @{
        'site-packages/_cffi_backend.cp312-win_amd64.pyd' = '9af5e4f68a41f26b726f2e9424f9d58a4f5666189f6a48be95f406b257102aec'
        'site-packages/clr_loader/ffi/dlls/amd64/ClrLoader.dll' = '07f62bcb1b70320f221ffb2cfc5ce6133815195f3e7cdb8d833222506188c2ac'
        'site-packages/pythonnet/runtime/Python.Runtime.dll' = '2ebd4492e28442ef1f1af587afe5b3a090c2ebfa220758ded4f1450f2a27f13a'
    }
    $listedPe = @(@($value.allowed_unsigned_app_pe) | ForEach-Object { [string]$_ })
    $unsignedPeOk = $listedPe.Count -eq 0 -or (
        $listedPe.Count -eq $unsignedPe.Count -and
        @($listedPe | Sort-Object -Unique -CaseSensitive).Count -eq $unsignedPe.Count -and
        @($listedPe | Where-Object {
            $_ -cin @($unsignedPe.Keys) -and
            (Test-Path -LiteralPath (Join-Path (Join-Path $Root 'app') $_.Replace('/', '\')) -PathType Leaf) -and
            (Sha (Join-Path (Join-Path $Root 'app') $_.Replace('/', '\'))) -ceq $unsignedPe[$_]
        }).Count -eq $unsignedPe.Count
    )
    if ([string]$value.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$value.entrypoint -cne 'runtime/pythonw.exe app/main.py' -or
        [string]$value.launcher -cne 'launch-container-audit.cmd' -or
        [string]$value.writer_fence_helper_path -cne 'tools/container_writer_fence.ps1' -or
        [string]$value.writer_session_adapter_path -cne 'tools/container_writer_session.ps1' -or
        [string]$value.writer_session_contract_path -cne 'tools/container_writer_session_contract.json' -or
        [string]$value.writer_sink_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$value.writer_session_contract_schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$value.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$value.source_tree -cnotmatch '^[0-9a-f]{40}$' -or
        -not $unsignedPeOk -or
        @($value.forbidden_dependency_paths).Count -ne 0 -or
        (Sha (Join-Path $Root 'runtime\pythonw.exe')) -cne ([string]$value.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'launch-container-audit.cmd')) -cne ([string]$value.launcher_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'INSTALL_CANONICAL_PORTABLE.ps1')) -cne ([string]$value.installer_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'INSTALL_THIS_PC.ps1')) -cne ([string]$value.helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\bootstrap_integrity.ps1')) -cne ([string]$value.integrity_helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_fence.ps1')) -cne ([string]$value.writer_fence_helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session.ps1')) -cne ([string]$value.writer_session_adapter_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session_contract.json')) -cne ([string]$value.writer_session_contract_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_sink_inventory.json')) -cne ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant()) {
        throw 'Portable manifest readback failed.'
    }
    $filesBeforeManifest = @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Where-Object {
                -not (Same $_.FullName $path) -and
                [string]$_.Name -cne 'bootstrap-integrity.json'
            }
    )
    $bytesBeforeManifest = [int64](
        ($filesBeforeManifest | Measure-Object -Property Length -Sum).Sum
    )
    if (
        -not (Test-JsonInteger $value.file_count_before_manifest) -or
        -not (Test-JsonInteger $value.byte_count_before_manifest) -or
        [int64]$value.file_count_before_manifest -lt 0 -or
        [int64]$value.byte_count_before_manifest -lt 0 -or
        [int64]$value.file_count_before_manifest -ne $filesBeforeManifest.Count -or
        [int64]$value.byte_count_before_manifest -ne $bytesBeforeManifest
    ) { throw 'Portable tree metrics differ from the manifest.' }
    Assert-WriterSessionPublicContract `
        (Join-Path $Root 'tools\container_writer_session_contract.json') `
        ([string]$value.writer_session_contract_sha256).ToLowerInvariant() `
        ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant()
    [void](Assert-WriterSinkInventory (Join-Path $Root 'tools\container_writer_sink_inventory.json') ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant() ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant())
    Assert-KmtechCPythonSignature $Root $UnsignedOk
    return $value
}
function InstalledManifest([string]$Root, [bool]$UnsignedOk) {
    foreach ($relative in @(
        'portable-manifest.json',
        'runtime\python.exe',
        'runtime\pythonw.exe',
        'app\main.py',
        'launch-container-audit.cmd',
        'tools\container_writer_fence.ps1',
        'tools\container_writer_session.ps1',
        'tools\container_writer_session_contract.json',
        'tools\container_writer_sink_inventory.json'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $relative) -PathType Leaf)) {
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Installed portable tree is missing $relative.")) -UserLine)
        }
    }
    foreach ($item in @((Get-Item $Root -Force)) + @(Get-ChildItem $Root -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Installed portable tree contains a reparse point: $($item.FullName)")) -UserLine)
        }
    }
    $path = Join-Path $Root 'portable-manifest.json'
    if ((Get-Item $path).Length -gt 65536) { throw 'Installed portable manifest is oversized.' }
    $value = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    # New Container Audit screen (same pins as Inspection_worker 402d3b1a): an older zero-PE release lists no
    # unsigned PE; otherwise exactly these app-relative files, each byte-identical to the builder pin.
    $unsignedPe = @{
        'site-packages/_cffi_backend.cp312-win_amd64.pyd' = '9af5e4f68a41f26b726f2e9424f9d58a4f5666189f6a48be95f406b257102aec'
        'site-packages/clr_loader/ffi/dlls/amd64/ClrLoader.dll' = '07f62bcb1b70320f221ffb2cfc5ce6133815195f3e7cdb8d833222506188c2ac'
        'site-packages/pythonnet/runtime/Python.Runtime.dll' = '2ebd4492e28442ef1f1af587afe5b3a090c2ebfa220758ded4f1450f2a27f13a'
    }
    $listedPe = @(@($value.allowed_unsigned_app_pe) | ForEach-Object { [string]$_ })
    $unsignedPeOk = $listedPe.Count -eq 0 -or (
        $listedPe.Count -eq $unsignedPe.Count -and
        @($listedPe | Sort-Object -Unique -CaseSensitive).Count -eq $unsignedPe.Count -and
        @($listedPe | Where-Object {
            $_ -cin @($unsignedPe.Keys) -and
            (Test-Path -LiteralPath (Join-Path (Join-Path $Root 'app') $_.Replace('/', '\')) -PathType Leaf) -and
            (Sha (Join-Path (Join-Path $Root 'app') $_.Replace('/', '\'))) -ceq $unsignedPe[$_]
        }).Count -eq $unsignedPe.Count
    )
    if ([string]$value.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$value.entrypoint -cne 'runtime/pythonw.exe app/main.py' -or
        [string]$value.launcher -cne 'launch-container-audit.cmd' -or
        [string]$value.writer_fence_helper_path -cne 'tools/container_writer_fence.ps1' -or
        [string]$value.writer_session_adapter_path -cne 'tools/container_writer_session.ps1' -or
        [string]$value.writer_session_contract_path -cne 'tools/container_writer_session_contract.json' -or
        [string]$value.writer_sink_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$value.writer_session_contract_schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$value.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$value.source_tree -cnotmatch '^[0-9a-f]{40}$' -or
        -not $unsignedPeOk -or
        @($value.forbidden_dependency_paths).Count -ne 0 -or
        (Sha (Join-Path $Root 'runtime\pythonw.exe')) -cne ([string]$value.runtime_pythonw_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'launch-container-audit.cmd')) -cne ([string]$value.launcher_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_fence.ps1')) -cne ([string]$value.writer_fence_helper_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session.ps1')) -cne ([string]$value.writer_session_adapter_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_session_contract.json')) -cne ([string]$value.writer_session_contract_sha256).ToLowerInvariant() -or
        (Sha (Join-Path $Root 'tools\container_writer_sink_inventory.json')) -cne ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant()) {
        throw 'Installed portable manifest readback failed.'
    }
    $filesBeforeManifest = @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Where-Object {
                -not (Same $_.FullName $path) -and
                -not (Same $_.FullName (Join-Path $Root 'bootstrap-integrity.json'))
            }
    )
    $bytesBeforeManifest = [int64](
        ($filesBeforeManifest | Measure-Object -Property Length -Sum).Sum
    )
    if (
        -not (Test-JsonInteger $value.file_count_before_manifest) -or
        -not (Test-JsonInteger $value.byte_count_before_manifest) -or
        [int64]$value.file_count_before_manifest -lt 0 -or
        [int64]$value.byte_count_before_manifest -lt 0 -or
        [int64]$value.file_count_before_manifest -ne $filesBeforeManifest.Count -or
        [int64]$value.byte_count_before_manifest -ne $bytesBeforeManifest
    ) { throw 'Installed portable tree metrics differ from the manifest.' }
    Assert-WriterSessionPublicContract `
        (Join-Path $Root 'tools\container_writer_session_contract.json') `
        ([string]$value.writer_session_contract_sha256).ToLowerInvariant() `
        ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant()
    [void](Assert-WriterSinkInventory (Join-Path $Root 'tools\container_writer_sink_inventory.json') ([string]$value.writer_sink_inventory_sha256).ToLowerInvariant() ([string]$value.writer_sink_inventory_contract_sha256).ToLowerInvariant())
    if (-not $UnsignedOk) {
        foreach ($relative in @('runtime\python.exe','runtime\pythonw.exe')) {
            if ([string](Get-AuthenticodeSignature (Join-Path $Root $relative)).Status -cne 'Valid') {
                throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Installed signed CPython readback failed: $relative")) -UserLine)
            }
        }
    }
    return $value
}
function Get-WriterInventorySemantics($Inventory) {
    # Compare the actual writers and guards. Caller counts and positions are
    # generator evidence, not a new delegated writer or wire contract.
    $membership = [ordered]@{
        schema_version=$Inventory.schema_version
        writer_sink_sources=$Inventory.writer_sink_sources
        writer_sinks=$Inventory.writer_sinks
        powershell_writer_sinks=$Inventory.powershell_writer_sinks
        known_route_coverage=$Inventory.known_route_coverage
    }
    $copy = $membership | ConvertTo-Json -Depth 40 | ConvertFrom-Json
    function Remove-WriterInventoryPositions($Value) {
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            foreach ($property in @($Value.PSObject.Properties)) {
                if ($property.Name -cin @('inventory_sha256','writer_site_count') -or $property.Name -cmatch '(^|_)line$') {
                    $Value.PSObject.Properties.Remove($property.Name)
                } else { Remove-WriterInventoryPositions $property.Value }
            }
        } elseif ($Value -is [array]) {
            foreach ($item in $Value) { Remove-WriterInventoryPositions $item }
        }
    }
    Remove-WriterInventoryPositions $copy
    return ($copy | ConvertTo-Json -Depth 40 -Compress)
}
function Test-InstalledReleasePreimages($Old,$New,[string]$BeforeRoot,[string]$AfterRoot) {
    # The exact release-pair route additionally binds ONE complete installed
    # release. A file cannot borrow another release's preimage or absence.
    try {
        if (-not $BeforeRoot -or -not $AfterRoot) { return $false }
        $path=Join-Path $AfterRoot 'tools\container_data_generation_transition.json'
        if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 2MB) { return $false }
        $declaration=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$declaration.schema_version -cne 'container-audit-g-forward-transition-v1' -or
            [string]$declaration.direction -cne 'forward' -or
            [string]$declaration.after_inventory_sha256 -cne [string]$New.writer_sink_inventory_contract_sha256) { return $false }
        $rows=@($declaration.installed_release_preimages)
        if ($rows.Count -ne 4) { return $false }
        $releases=@{}
        foreach($row in $rows) {
            if (-not (Test-ExactPropertySet $row @('source_commit','writer_inventory_sha256','files')) -or
                $row.source_commit -isnot [string] -or $row.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
                $row.writer_inventory_sha256 -isnot [string] -or $row.writer_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $releases.ContainsKey($row.source_commit)) { return $false }
            $releases[$row.source_commit]=$row
        }
        if (-not $releases.ContainsKey([string]$Old.source_commit)) { return $false }
        $selected=$releases[[string]$Old.source_commit]
        if ([string]$selected.writer_inventory_sha256 -cne [string]$Old.writer_sink_inventory_contract_sha256) { return $false }
        $expected=@{}
        $nonDeployed=@('tools/active_work_probe.py','tools/build_operator_review_case_report.py',
            'tools/build_portable_release_candidate.py','tools/check_logistics_runtime_profile.py',
            'tools/direct_sync_relay_install_pack.py','tools/install_protected_admin.py',
            'tools/check_update_archive.py','tools/provision_protected_admin_acl.ps1')
        $sourceSeen=@{}
        if (@($declaration.source_replacements).Count -ne 33) { return $false }
        foreach($entry in @($declaration.source_replacements)) {
            $sourcePath=[string]$entry.path
            if (-not (Test-ExactPropertySet $entry @('path','before','after')) -or $sourceSeen.ContainsKey($sourcePath)) { return $false }
            $sourceSeen[$sourcePath]=$true
            $packetPath=if($sourcePath -ceq 'portable/main.py'){'app/main.py'}else{'app/'+$sourcePath}
            $packetRows=@($declaration.files|Where-Object {[string]$_.path -ceq $sourcePath -or [string]$_.path -ceq $packetPath})
            if ($sourcePath -cin $nonDeployed) {
                # These developer tools are deliberately outside the stock.
                if ($packetRows.Count -ne 0) { return $false }
                continue
            }
            if ($packetRows.Count -ne 1) { return $false }
            $relative=[string]$packetRows[0].path
            if ($relative -cnotmatch '^[A-Za-z0-9_./-]+$' -or $relative.StartsWith('/') -or
                '..' -cin @($relative.Split('/')) -or $expected.ContainsKey($relative) -or
                [string]$entry.after -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$packetRows[0].after -cne [string]$entry.after) { return $false }
            $expected[$relative]=[string]$entry.after
        }
        if ($expected.Count -ne 25 -or @($selected.files).Count -ne $expected.Count) { return $false }
        $seen=@{}
        foreach($entry in @($selected.files)) {
            $relative=[string]$entry.path
            if (-not $expected.ContainsKey($relative) -or $seen.ContainsKey($relative)) { return $false }
            $seen[$relative]=$true
            $beforePath=Join-Path $BeforeRoot $relative
            $afterPath=Join-Path $AfterRoot $relative
            Assert-BootstrapNoReparsePoint $afterPath 'assembly exact after' -PathOnly
            if ($null -ne $entry.PSObject.Properties['absent']) {
                if (-not (Test-ExactPropertySet $entry @('path','absent')) -or
                    $entry.absent -isnot [bool] -or -not $entry.absent -or (Test-Path -LiteralPath $beforePath)) { return $false }
                # An exact absence is admitted only below a verified existing
                # parent, and only a literal ItemNotFound result proves it.
                Assert-BootstrapNoReparsePoint (Split-Path -Parent $beforePath) 'installed absent preimage parent' -PathOnly
                try { [void](Get-Item -LiteralPath $beforePath -Force -ErrorAction Stop); return $false }
                catch [Management.Automation.ItemNotFoundException] { }
            } else {
                Assert-BootstrapNoReparsePoint $beforePath 'installed exact preimage' -PathOnly
                if (-not (Test-ExactPropertySet $entry @('path','sha256')) -or
                    $entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    -not (Test-Path -LiteralPath $beforePath -PathType Leaf) -or (Sha $beforePath) -cne $entry.sha256) { return $false }
            }
            if (-not (Test-Path -LiteralPath $afterPath -PathType Leaf) -or (Sha $afterPath) -cne $expected[$relative]) { return $false }
        }
        return $true
    } catch { return $false }
}
function Test-ExactApprovedWriterTransition($Old, $New, [string]$SourceRoot) {
    $settingsPath = Join-Path $SourceRoot 'app\auto-update-settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) { return $false }
    if ((Get-Item -LiteralPath $settingsPath).Length -gt 65536) { throw 'WRITER_TRANSITION_PIN_INVALID' }
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($settings.approved_transitions -isnot [array]) { throw 'WRITER_TRANSITION_PIN_INVALID' }
    $found = $false
    $seen = @{}
    foreach ($pin in @($settings.approved_transitions)) {
        if (-not (Test-ExactPropertySet $pin @('from_commit','to_commit','from_contract_sha256','to_contract_sha256')) -or
            $pin.from_commit -isnot [string] -or $pin.to_commit -isnot [string] -or
            $pin.from_contract_sha256 -isnot [string] -or $pin.to_contract_sha256 -isnot [string] -or
            $pin.from_commit -cnotmatch '^[0-9a-f]{40}$' -or $pin.to_commit -cnotmatch '^[0-9a-f]{40}$' -or
            $pin.from_contract_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $pin.to_contract_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'WRITER_TRANSITION_PIN_INVALID'
        }
        $identity = @($pin.from_commit,$pin.to_commit,$pin.from_contract_sha256,$pin.to_contract_sha256) -join ':'
        if ($seen.ContainsKey($identity)) { throw 'WRITER_TRANSITION_PIN_DUPLICATE' }
        $seen[$identity] = $true
        if ($pin.from_commit -ceq $Old.source_commit -and $pin.to_commit -ceq $New.source_commit -and
            $pin.from_contract_sha256 -ceq $Old.writer_sink_inventory_contract_sha256 -and
            $pin.to_contract_sha256 -ceq $New.writer_sink_inventory_contract_sha256) { $found = $true }
    }
    return $found
}
function Test-ExactApprovedInstalledWriterTransition($Old,$New,[string]$SourceRoot,[string]$BeforeRoot=$install) {
    # Admission is forward-only; verified replacement restoration keeps its
    # separately authenticated receipt and exact reverse policy unchanged.
    return ((Test-ExactApprovedWriterTransition $Old $New $SourceRoot) -and
        (Test-InstalledReleasePreimages $Old $New $BeforeRoot $SourceRoot))
}
# App-only, forward-only admission for the exact sub-233 G source transition.
# The existing writer-semantic predicate and common helpers remain unchanged.
function Get-ContainerTransitionCodeFiles([string]$Root) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($rootFull)
    $files = @{}
    while ($pending.Count) {
        $directory = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'G_TRANSITION_REPARSE_POINT' }
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName); continue }
            $relative = $item.FullName.Substring($rootFull.Length + 1).Replace('\','/')
            if ($item.Extension -in @('.py','.ps1','.sql') -or
                $relative -cin @('tools/container_writer_sink_inventory.json','tools/container_writer_session_contract.json')) {
                if ($files.ContainsKey($relative)) { throw 'G_TRANSITION_PATH_COLLISION' }
                $files[$relative] = $item.FullName
            }
        }
    }
    return $files
}

function Test-ContainerDataGenerationForwardTransition {
    param([string]$BeforeRoot, [string]$AfterRoot, $BeforeInventory, $AfterInventory)
    try {
        $declarationPath = Join-Path $AfterRoot 'tools\container_data_generation_transition.json'
        $declarationFile = Get-Item -LiteralPath $declarationPath -ErrorAction Stop
        if ($declarationFile.Length -gt 2MB -or $declarationFile.Length -lt 1) { return $false }
        $declaration = Get-Content -LiteralPath $declarationPath -Raw | ConvertFrom-Json
        if ([string]$declaration.schema_version -cne 'container-audit-g-forward-transition-v1' -or
            [string]$declaration.direction -cne 'forward' -or
            [string]$declaration.before_source_commit -cne 'ea566d131f37db3ee74468e1645c6b57ac45b6fa' -or
            [string]$declaration.before_inventory_sha256 -cne [string]$BeforeInventory.inventory_sha256 -or
            [string]$declaration.after_inventory_sha256 -cne [string]$AfterInventory.inventory_sha256 -or
            [string]$BeforeInventory.inventory_sha256 -ceq [string]$AfterInventory.inventory_sha256) { return $false }
        $beforeManifest = Get-Content -LiteralPath (Join-Path $BeforeRoot 'portable-manifest.json') -Raw | ConvertFrom-Json
        if ([string]$beforeManifest.source_commit -cne [string]$declaration.before_source_commit) { return $false }

        # Only the two named routes may change, and only these exact G edges.
        if (@($declaration.route_replacements).Count -ne 2) { return $false }
        $adjusted = $BeforeInventory | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $seenRoutes = @{}
        foreach ($replacement in @($declaration.route_replacements)) {
            $id = [string]$replacement.route_id
            if ($id -cnotin @('persistent_relay','raw_runner') -or $seenRoutes.ContainsKey($id)) { return $false }
            $seenRoutes[$id] = $true
            $old = @($adjusted.known_route_coverage | Where-Object {$_.route_id -ceq $id})
            $new = @($AfterInventory.known_route_coverage | Where-Object {$_.route_id -ceq $id})
            if ($old.Count -ne 1 -or $new.Count -ne 1) { return $false }
            foreach ($field in @('reachable_sources','reachable_direct_mutation_functions')) {
                $before = @($replacement.before.$field)
                $after = @($replacement.after.$field)
                if (($old[0].$field | ConvertTo-Json -Compress) -cne ($before | ConvertTo-Json -Compress) -or
                    ($new[0].$field | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)) { return $false }
                if ($id -ceq 'persistent_relay') {
                    $added = if ($field -ceq 'reachable_sources') { @('data_generation_marker') }
                        else { @('data_generation_guard._runtime_release','kmtech_shared.data_generation.record_generation') }
                    $expected = @(@($before) + @($added) | Sort-Object -Unique)
                } else {
                    $removed = if ($field -ceq 'reachable_sources') { @('hosted_relay_failure','hosted_relay_json','hosted_relay_jsonl') }
                        else { @('container_audit_product_host._append_jsonl','container_audit_product_host._write_json_atomic') }
                    $expected = @($before | Where-Object {$_ -cnotin $removed})
                    if (@($before | Where-Object {$_ -cin $removed}).Count -ne $removed.Count) { return $false }
                }
                if (($expected | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)) { return $false }
                $old[0].$field = $after
            }
        }
        if ((Get-WriterInventorySemantics $adjusted) -cne (Get-WriterInventorySemantics $AfterInventory)) { return $false }

        # Every code file is bound, including unchanged files and added files.
        # Generated release metadata keeps its existing integrity validation.
        $beforeFiles = Get-ContainerTransitionCodeFiles $BeforeRoot
        $afterFiles = Get-ContainerTransitionCodeFiles $AfterRoot
        $expectedPaths = @(@($beforeFiles.Keys) + @($afterFiles.Keys) | Sort-Object -Unique)
        $entries = @($declaration.files)
        if ($entries.Count -ne $expectedPaths.Count) { return $false }
        $seenFiles = @{}
        foreach ($entry in $entries) {
            $relative = [string]$entry.path
            if ($relative -cnotmatch '^[A-Za-z0-9_./-]+$' -or $relative.StartsWith('/') -or
                '..' -cin @($relative.Split('/')) -or $seenFiles.ContainsKey($relative) -or
                $relative -cnotin $expectedPaths) { return $false }
            $seenFiles[$relative] = $true
            foreach ($side in @('before','after')) {
                $files = if ($side -ceq 'before') { $beforeFiles } else { $afterFiles }
                $expectedHash = $entry.$side
                if (-not $files.ContainsKey($relative)) {
                    return $false
                } else {
                    if ([string]$expectedHash -cnotmatch '^[0-9a-f]{64}$' -or
                        (Get-FileHash -LiteralPath $files[$relative] -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$expectedHash) { return $false }
                }
            }
        }
        return $true
    } catch { return $false }
}

function Sync-CanonicalWriterFenceInventory([string]$InventorySha256) {
    $active = Read-ContainerWriterFence
    if ([string]$active.writer_inventory_sha256 -ceq $InventorySha256) { return }
    [void](Set-ContainerWriterFenceInventory `
        -SessionId $Script:CanonicalWriterFenceSessionId `
        -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
        -WriterInventorySha256 $InventorySha256 `
        -AuthorityLease $canonicalWriterFenceAuthority)
    $audit.code_replacement.writer_inventory_transitions += $InventorySha256
}

function Get-CanonicalOperatorSecurity {
    $operator=Get-Variable -Name InstallationTransactionOperator -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $operator){return $operator}
    return Get-CanonicalRelaySecurity $PID
}
function Open-CanonicalRunKey([bool]$Write) {
    $operator=Get-Variable -Name InstallationTransactionOperator -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $operator -and [string]$operator.sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){
        if(-not(Test-InstallationEvidencePrivileged)){throw 'Canonical operator registry requires the privileged coordinator.'}
        $path=[string]$operator.sid+'\'+$RunKey
        if($Write){return [Microsoft.Win32.Registry]::Users.CreateSubKey($path,$true)}
        return [Microsoft.Win32.Registry]::Users.OpenSubKey($path,$false)
    }
    if($Write){return [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunKey,$true)}
    return [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RunKey,$false)
}
function Snapshot {
    $key = Open-CanonicalRunKey $false
    if ($null -eq $key) { return [ordered]@{exists=$false;kind='';data=''} }
    try {
        try { $kind = [string]$key.GetValueKind($RunName) }
        catch [IO.IOException] { return [ordered]@{exists=$false;kind='';data=''} }
        if ($kind -notin @('String','ExpandString')) { throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Unsupported Run type: $kind")) -UserLine) }
        $data = [string]$key.GetValue($RunName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return [ordered]@{exists=$true;kind=$kind;data=$data}
    } finally { $key.Dispose() }
}
function Restore-CanonicalApplicationProtection {
    $parent=Split-Path -Parent $install
    # A cancelled fresh placement may not have created either directory. There
    # is no application DACL to repair; do not start another elevation request.
    if ($currentAbsentBeforePlacement -and -not (Test-Path -LiteralPath $install -ErrorAction Stop) -and
        -not (Test-Path -LiteralPath $parent -ErrorAction Stop)) { return }
    if(Test-InstallationEvidencePrivileged){New-InstallationProtectedDirectory $parent $operatorSid -RecoverAbandoned;return}
    try{Assert-InstallationEvidenceProtectedPath $parent;return}catch{Write-InstallationCaughtFailure $_}
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
        '-RepairOwnedInstallationParent','-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,
        '-AbandonedRecoverySourceManifestSha256',$sourceManifestSha256,'-AbandonedRecoveryParentProcessId',[string]$PID)
    $result=Invoke-InstallationElevationCapture (Join-Path $source 'INSTALL_THIS_PC.ps1') $arguments (Join-Path $auditRoot ('parent-repair-'+$runId)) $operatorSid -AuthorityLease $canonicalWriterFenceAuthority
    if($result.ExitCode -ne 0){throw 'Owned application protection repair failed.'}
    Assert-InstallationEvidenceProtectedPath $parent
}
function Invoke-CanonicalRollbackRuntimePreimage($Before,[switch]$RemovalAlreadyProven) {
    $steps=[Collections.Generic.List[object]]::new()
    foreach($name in @('app_protection','product_removal','run_preimage','stop_marker')){
        $failure=$null
        try{
            Set-InstallationEvidenceStage ('rollback.'+$name) 'rollback'
            switch($name){
                'app_protection' {
                    if(-not $testMode){
                        Restore-CanonicalApplicationProtection
                    }
                }
                'product_removal' {
                    if(-not $RemovalAlreadyProven -and (Test-Path -LiteralPath $install -ErrorAction Stop)){Product $install '--remove-current-user-setup' -Rollback}
                    [void](Assert-RollbackRelayPreimage -ExpectedRelays @())
                }
                'run_preimage' {
                    Assert-CanonicalRollbackStopCleanup
                    Restore $Before
                    $check=Snapshot
                    if([bool]$check.exists -ne [bool]$Before.exists -or [string]$check.kind -cne [string]$Before.kind -or [string]$check.data -cne [string]$Before.data){throw 'registry restore failed'}
                }
                'stop_marker' {Assert-CanonicalRollbackStopCleanup;if(Test-Path -LiteralPath $stop){Remove-Item -LiteralPath $stop -ErrorAction Stop};if(Test-Path -LiteralPath $stop){throw 'stop marker remains'}}
            }
        }catch{$failure=Get-InstallationFailureDetails $_;Write-InstallationCaughtFailure $_}
        $record=[ordered]@{step=$name;status=if($null -eq $failure){'PROVEN'}else{'FAILED'};reused_completed_removal=($name -ceq 'product_removal' -and $RemovalAlreadyProven.IsPresent);failure=$failure}
        $steps.Add($record)
        Write-InstallationEvidenceEvent ([ordered]@{event='ROLLBACK_STEP';detail=$record})
    }
    return ,$steps.ToArray()
}

function Read-CanonicalSupportedRemovalResume {
    $active=Read-ContainerWriterFence -AllowAbsent
    if ($null -eq $active) { return $null }
    # A retirement attempt has a canonical journal, not a protected supported
    # removal journal. Reject its bound existing stop before native preparation.
    $preparedLeaf=[IO.Path]::GetFileName([string]$active.prepared_receipt_path)
    if ($preparedLeaf -cmatch '^canonical-portable-(\d{8}T\d{9}Z-[0-9a-f]{32})-writer-prepared\.json$') {
        $originPath=Join-Path (Split-Path -Parent ([string]$active.prepared_receipt_path)) ('canonical-portable-'+$Matches[1]+'.json')
        [void](Get-ContainerWriterFenceFileSha256 $originPath 1048576)
        $origin=Get-Content -LiteralPath $originPath -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
        if ($null -ne $origin.PSObject.Properties['retirement'] -and
            [string]$origin.schema -ceq 'container-audit-canonical-portable-install-v2' -and
            [string]$origin.operation -ceq 'COMPLETE_RETIRED_REMOVAL' -and
            [string]$origin.retirement.session_id -ceq [string]$active.session_id -and
            [string]$origin.retirement.attempt_id -ceq [string]$active.attempt_id -and
            [string]$origin.code_replacement.transaction_id -ceq [string]$active.replacement_transaction_id -and
            $env:CONTAINER_AUDIT_DATA_ROOT -and (Test-Path -LiteralPath (Join-Path $env:CONTAINER_AUDIT_DATA_ROOT 'direct_sync\control\container_audit_user_relay.stop.json'))) {
            throw 'CANONICAL_STOP_MARKER_PREEXISTS'
        }
    }
    $directory=Join-Path (Join-Path (Get-InstallationEvidenceControlRoot) 'supported-removals') ([string]$active.replacement_transaction_id)
    $path=Join-Path $directory 'removal-journal.json'
    Assert-InstallationEvidenceProtectedPath $directory
    Assert-InstallationEvidenceProtectedPath $path
    $recordSha=Get-FileSha256 $path
    [void](Read-BootstrapReplacementReceipt $path $recordSha)
    $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    if ([string]$record.schema -cne 'container-audit-supported-removal-journal-v1' -or
        [string]$active.status -cne 'INSTALLING' -or [string]$active.owner_kind -cne 'canonical_installer' -or
        -not (Same ([string]$record.install_root) $install) -or [string]$record.operator_sid -cne $operatorSid -or
        -not (Same ([string]$record.operator_local_appdata_root) $lad) -or
        [string]$record.source_manifest_sha256 -cne $sourceManifestSha256 -or
        [string]$record.orchestrator_sha256 -cne $sourceManifest.installer_sha256 -or
        [string]$record.writer_contract_sha256 -cne $sourceManifest.writer_session_contract_sha256 -or
        -not (Same ([string]$record.prepared_receipt_path) ([string]$active.prepared_receipt_path)) -or
        [string]$record.authority_mutex_name -cne [string]$active.session_authority_mutex_name -or
        $record.secret_values_recorded -isnot [bool] -or $record.secret_values_recorded) { throw 'REMOVAL_RESUME_PROTECTED_BINDING_DIFFERS' }
    foreach ($name in @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc',
        'orchestrator_sha256','writer_contract_sha256','writer_inventory_sha256','prepared_receipt_sha256')) {
        if ([string]$record.$name -cne [string]$active.$name) { throw 'REMOVAL_RESUME_FENCE_TUPLE_DIFFERS' }
    }
    $copy=Join-Path $directory 'original-audit.json'
    if (-not (Same ([string]$record.audit_copy_path) $copy)) { throw 'REMOVAL_RESUME_AUDIT_PATH_DIFFERS' }
    Assert-InstallationEvidenceProtectedPath $copy
    [void](Read-BootstrapReplacementReceipt $copy ([string]$record.original_audit_sha256))
    $origin=Get-Content -LiteralPath $copy -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    if ([string]$origin.schema -cne 'container-audit-canonical-portable-install-v2' -or
        [string]$origin.operation -cne 'UNINSTALL' -or [string]$origin.status -cne 'PREIMAGE_SAVED' -or
        -not (Same ([string]$origin.install_root) $install) -or
        [string]$origin.source_manifest_sha256 -cne $sourceManifestSha256 -or
        [string]$origin.code_replacement.transaction_id -cne [string]$active.replacement_transaction_id -or
        [IO.Path]::GetFileName([string]$origin.stage_evidence_root) -cnotmatch ('\.evidence\.'+[string]$record.owner_process_id+'$')) {
        throw 'REMOVAL_RESUME_ORIGINAL_AUDIT_DIFFERS'
    }
    Assert-RetirementOwnerExited $record
    if ((Get-FileSha256 $path) -cne $recordSha) { throw 'REMOVAL_RESUME_JOURNAL_CHANGED' }
    return [pscustomobject]@{record=$record;record_sha256=$recordSha;active=$active;
        active_sha256=Get-ContainerWriterFenceFileSha256 (Get-ContainerWriterFenceActivePath)}
}

function Resume-CanonicalSupportedRemovalFence($Prior) {
    $admission=Enter-ContainerWriterAdmission
    try {
        $fresh=Read-CanonicalSupportedRemovalResume
        if ($null -eq $fresh -or $fresh.record_sha256 -cne $Prior.record_sha256 -or
            $fresh.active_sha256 -cne $Prior.active_sha256) { throw 'REMOVAL_RESUME_INPUT_CHANGED' }
        Assert-ContainerWriterSessionAuthority $fresh.active $canonicalWriterFenceAuthority
        # Retain the authenticated original tuple and prepared bytes. The
        # create-only session authority rejects every live/reused claimant;
        # another interruption can reclaim this same immutable journal.
        $payload=New-ContainerWriterFencePayload -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
            -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
            -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 -WriterContractSha256 $canonicalWriterFenceContractSha256 `
            -PreparedReceiptPath ([string]$canonicalWriterFencePreparedReceipt.path) -PreparedReceiptSha256 ([string]$canonicalWriterFencePreparedReceipt.sha256) `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken -DelegatedSources $canonicalWriterFenceDelegatedSources `
            -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o'))
        Assert-ContainerWriterSessionAuthority $payload $canonicalWriterFenceAuthority
        [void](Write-ContainerWriterFenceAtomic '' $payload)
    } finally { Exit-ContainerWriterAdmission $admission }
}

function Write-CanonicalInstallReentryRecord([string]$Phase) {
    if($null -eq $audit -or $audit.operation -cne 'INSTALL' -or -not $before.exists -or
        [bool]$writerBefore.present){return}
    $path=Join-Path $Script:InstallationEvidenceRoot 'reentry-record.json'
    if($Phase -ceq 'PREIMAGE_SAVED'){
        $active=Read-ContainerWriterFence
        $record=[ordered]@{schema='container-audit-install-reentry-v1';phase=$Phase;run_id=$runId;install_root=$install;
            operator_sid=$operatorSid;operator_local_appdata_root=$lad;owner_process_id=$PID;
            owner_started_at_utc=(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o');
            session_id=$active.session_id;attempt_id=$active.attempt_id;replacement_transaction_id=$active.replacement_transaction_id;
            session_started_at_utc=$active.session_started_at_utc;orchestrator_sha256=$active.orchestrator_sha256;
            writer_contract_sha256=$active.writer_contract_sha256;writer_inventory_sha256=$active.writer_inventory_sha256;
            delegation_sha256=$active.delegation_sha256;prepared_receipt_sha256=$active.prepared_receipt_sha256;prepared_writer_inventory_sha256=$Script:ContainerWriterFenceInventorySha256;
            source_manifest_sha256=$sourceManifestSha256;old_manifest_sha256=Sha (Join-Path $install 'portable-manifest.json');
            old_integrity_sha256=Sha (Join-Path $install 'bootstrap-integrity.json');preimage=$before;
            removal_completed=$false;removal_receipt_sha256='';stop_marker_sha256='';secret_values_recorded=$false}
    }else{
        $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
        $record.phase=$Phase
        if($Phase -ceq 'RUNTIME_QUIESCED_UNPLACED'){
            $record.removal_completed=$true;$record.removal_receipt_sha256=Sha $removalPath;$record.stop_marker_sha256=Sha $stop
        }
        # Inventory changes are explicit fenced transitions. Keep the recovery
        # tuple equal to the actual active record, including its accepted pin.
        $record.writer_inventory_sha256=(Read-ContainerWriterFence).writer_inventory_sha256
    }
    Assert-InstallationEvidenceWriteRoot $Script:InstallationEvidenceRoot
    Assert-BootstrapNoReparsePoint (Split-Path -Parent $path) 'reentry record parent' -PathOnly
    if(Test-Path -LiteralPath $path){Assert-BootstrapNoReparsePoint $path 'reentry record' -PathOnly}
    $temporary=Join-Path $Script:InstallationEvidenceRoot ('r-'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'.tmp')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 10)+"`n")
    $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Set-InstallationEvidenceAcl $temporary $operatorSid
    Invoke-ContainerAtomicReplace $temporary $path -Mode WriteThrough
    $readback=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if([string]$readback.phase -cne $Phase -or [string]$readback.run_id -cne $runId){throw 'Reentry record readback differs.'}
    Write-InstallationEvidenceEvent ([ordered]@{event='REENTRY_RECORD';phase=$Phase;path=$path;sha256=Sha $path;secret_values_recorded=$false})
}
function Resume-CanonicalAbandonedRollback {
    try{$prior=Read-InstallationAbandonedRollback $install $lad $operatorSid}
    catch{throw [InvalidOperationException]::new('이전 설치 복구 상태를 확인할 수 없습니다. 지원 담당자에게 문의하세요.',$_.Exception)}
    if($null -eq $prior){return $null}
    if($Uninstall -or $RestoreVerifiedReplacement -or $CompleteRetiredRemoval){throw '이전 설치 복구 상태를 확인할 수 없습니다. 지원 담당자에게 문의하세요.'}
    $claim=$null;$admission=$null;$savedInventory=$Script:ContainerWriterFenceAcceptedInstalledInventorySha256
    $recoveryPath=Join-Path $auditRoot ('abandoned-recovery-'+[Guid]::NewGuid().ToString('N')+'.json')
    try{
        $admission=Enter-ContainerWriterAdmission
        # Reuse the existing tuple-derived authority. Its create-only claim
        # rejects every surviving mutex, including inaccessible/live ownership.
        $claim=Enter-ContainerWriterSessionAuthority -SessionId ([string]$prior.active.session_id) `
            -AttemptId ([string]$prior.active.attempt_id) -OrchestratorSha256 ([string]$prior.active.orchestrator_sha256) `
            -ReplacementTransactionId ([string]$prior.active.replacement_transaction_id) `
            -WriterContractSha256 ([string]$prior.active.writer_contract_sha256)
        $fresh=Read-InstallationAbandonedRollback $install $lad $operatorSid
        if($fresh.active_sha256 -cne $prior.active_sha256 -or $fresh.audit_sha256 -cne $prior.audit_sha256 -or $fresh.stop_sha256 -cne $prior.stop_sha256 -or $fresh.record_sha256 -cne $prior.record_sha256){throw 'Abandoned recovery inputs changed.'}
        if((Snapshot).exists -or @(Relays).Count -ne 0){throw 'Abandoned recovery runtime differs.'}
        $Script:ContainerWriterFenceAcceptedInstalledInventorySha256=[string]$prior.active.writer_inventory_sha256
        # The old exclusive authority remains held. Do not hold the admission
        # mutex across a child or UAC wait: ordinary product writers need it.
        Exit-ContainerWriterAdmission $admission;$admission=$null
        if(Test-InstallationEvidencePrivileged){
            New-InstallationProtectedDirectory (Split-Path -Parent $install) $operatorSid -RecoverAbandoned
            [void](Initialize-InstallationEvidence $recoveryPath $operatorSid)
        }else{
            [void](Initialize-InstallationEvidence $recoveryPath $operatorSid)
            $repairArgs=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
                '-RepairAbandonedInstallationParent','-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,
                '-AbandonedRecoverySourceManifestSha256',$sourceManifestSha256,'-AbandonedRecoveryParentProcessId',[string]$PID)
            $repair=Invoke-InstallationElevationCapture (Join-Path $source 'INSTALL_THIS_PC.ps1') $repairArgs ($recoveryPath+'.repair') $operatorSid -AuthorityLease $claim
            if($repair.ExitCode -ne 0){throw 'Abandoned app protection failed.'}
        }
        $recoveryPath=Join-Path $Script:InstallationEvidenceRoot 'abandoned-recovery.json'
        Write-InstallationEvidenceEvent ([ordered]@{event='ABANDONED_RECOVERY_START';original_owner_pid=$prior.owner_pid;original_audit_path=$prior.audit_path;original_audit_sha256=$prior.audit_sha256})
        # All prior bytes were admitted before changing the parent. Repeat the
        # installed trust/readback after protection and before registry recovery.
        Assert-BootstrapProtectedRelayPath $install
        [void](Assert-BootstrapIntegrityRecord $install)
        $steps=Invoke-CanonicalRollbackRuntimePreimage $prior.audit.preimage -RemovalAlreadyProven
        $recovery=[ordered]@{status='RECOVERY_PENDING';original_audit_path=$prior.audit_path;original_audit_sha256=$prior.audit_sha256;steps=$steps;fence_released=$false;old_relay_ready=$false}
        Save $recoveryPath $recovery
        # Continue fence recovery after an earlier removal error if the old
        # code, exact Run and absence of writers/stop marker are proven safe.
        $check=Snapshot
        if(-not $check.exists -or $check.kind -cne $prior.audit.preimage.kind -or $check.data -cne $prior.audit.preimage.data -or
            (Test-Path -LiteralPath $stop) -or @(Relays).Count -ne 0){throw 'Abandoned runtime restore readback failed.'}
        [void](Abort-ContainerWriterFence -SessionId ([string]$prior.active.session_id) -AttemptId ([string]$prior.active.attempt_id) `
            -ReplacementTransactionId ([string]$prior.active.replacement_transaction_id) -AuthorityLease $claim)
        $recovery.fence_released=$true
        Save $recoveryPath $recovery
        [void](Start-CanonicalRelayAfterFenceRelease -Root $install -RunCommand ([string]$prior.audit.preimage.data))
        $recovery.old_relay_ready=$true;$recovery.status='PROVEN_OLD_RUNTIME_RESTORED'
        Save $recoveryPath $recovery
        Write-InstallationEvidenceEvent ([ordered]@{event='ABANDONED_RECOVERY_COMPLETE';recovery_path=$recoveryPath;old_relay_ready=$true})
        return [ordered]@{status=$recovery.status;path=$recoveryPath;sha256=Sha $recoveryPath;stage_evidence_root=$Script:InstallationEvidenceRoot}
    }catch{
        Write-InstallationCaughtFailure $_
        throw [InvalidOperationException]::new('이전 설치 복구 상태를 확인할 수 없습니다. 지원 담당자에게 문의하세요.',$_.Exception)
    }finally{
        if($null -ne $admission){Exit-ContainerWriterAdmission $admission}
        if($null -ne $claim){Exit-ContainerWriterSessionAuthority $claim}
        $Script:ContainerWriterFenceAcceptedInstalledInventorySha256=$savedInventory
    }
}
function Restore($Before) {
    $key = Open-CanonicalRunKey $true
    try {
        if ([bool]$Before.exists) {
            $key.SetValue($RunName,[string]$Before.data,[Microsoft.Win32.RegistryValueKind]::$($Before.kind))
        } else { $key.DeleteValue($RunName,$false) }
    } finally { $key.Dispose() }
}
function ConvertTo-CanonicalSafeDiagnostic([string]$Text) {
    return (ConvertTo-KmtechRedactedSinkText -Text $Text)
}
function ConvertTo-CanonicalAuditJson($Value,[switch]$PrivateDiagnostics) {
    if(-not $PrivateDiagnostics){
        # Caller-selected audit files have no reader-ACL proof. Preserve the
        # machine schema and replace only free diagnostic leaves before Save.
        $copy=($Value|ConvertTo-Json -Depth 40)|ConvertFrom-Json
        $diagnostics=[Collections.Generic.List[object]]::new()
        function Limit-CanonicalPublicDiagnostics($Node,[bool]$InsideDiagnostic=$false){
            if($Node -is [Management.Automation.PSCustomObject]){
                foreach($property in $Node.PSObject.Properties){
                    $name=$property.Name
                    if(-not $InsideDiagnostic -and $name -cin @('identity','source_identity','credential','profile','manifest','metadata','receipt','server_receipt','preimage')){continue}
                    # These fields are assigned literal codes or calculated
                    # type/location/hash values by the canonical producers.
                    if($name -match '(?i)(?:^type$|exception_type$|failure_type$|_code$|_status$|_path$|_sha256$|_sha256s$|_bytes$|_count$|_hresult$|_win32_error$|^hresult$|^win32_error$|^script_line$|^script_file$)'){continue}
                    $diagnostic=$InsideDiagnostic -or $name -match '(?i)failure|message|stdout|stderr|traceback|blocked_reason|command_line|^argv$'
                    if($diagnostic -and $property.Value -is [string]){
                        if($property.Value -and $property.Value -cne 'SUPPORT_FAILURE'){
                            $diagnostics.Add(@{field=$name;diagnostic=$property.Value})
                            $property.Value='SUPPORT_FAILURE'
                        }
                    }else{Limit-CanonicalPublicDiagnostics $property.Value $diagnostic}
                }
            }elseif($Node -is [Array]){
                for($i=0;$i -lt $Node.Count;$i++){
                    if($InsideDiagnostic -and $Node[$i] -is [string]){
                        if($Node[$i] -and $Node[$i] -cne 'SUPPORT_FAILURE'){
                            $diagnostics.Add(@{field='array';diagnostic=$Node[$i]})
                            $Node[$i]='SUPPORT_FAILURE'
                        }
                    }else{Limit-CanonicalPublicDiagnostics $Node[$i] $InsideDiagnostic}
                }
            }
        }
        Limit-CanonicalPublicDiagnostics $copy
        if($diagnostics.Count -and (Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){
            # This existing writer checks the current attempt's admitted root.
            # A failed private write never promotes caller-selected audit files.
            try{Write-InstallationEvidenceEvent @{event='CANONICAL_DIAGNOSTIC_REPORT';diagnostics=$diagnostics.ToArray()}}catch{}
        }
        $json=($copy|ConvertTo-Json -Depth 40 -Compress)+"`n"
        Assert-InstallationMachineMetadataNoSecrets $json
        return $json
    }
    # Redact a valid in-memory envelope first. Budget diagnostic strings before
    # serializing, so authenticated tuple/path fields and JSON syntax survive.
    $safe=Protect-InstallationText ($Value|ConvertTo-Json -Depth 40) -1 -NoTruncate
    $copy=$safe|ConvertFrom-Json
    $diagnostics=[Collections.Generic.List[object]]::new()
    function Find-CanonicalAuditDiagnosticStrings($Node,[bool]$InsideDiagnostic=$false) {
        if($Node -is [Management.Automation.PSCustomObject]){
            foreach($property in $Node.PSObject.Properties){
                $diagnostic=$InsideDiagnostic -or $property.Name -match '(?i)failure|message|stdout|stderr|traceback'
                if($diagnostic -and $property.Value -is [string]){$diagnostics.Add($property)}
                else{Find-CanonicalAuditDiagnosticStrings $property.Value $diagnostic}
            }
        }elseif($Node -is [Collections.IEnumerable] -and $Node -isnot [string]){
            foreach($item in $Node){Find-CanonicalAuditDiagnosticStrings $item $InsideDiagnostic}
        }
    }
    Find-CanonicalAuditDiagnosticStrings $copy
    foreach($property in $diagnostics){$property.Value=ConvertTo-KmtechRedactedSinkText -Text ([string]$property.Value)}
    do {
        $json=($copy|ConvertTo-Json -Depth 40 -Compress)+"`n"
        if([Text.Encoding]::UTF8.GetByteCount($json) -le 65536){return $json}
        $largest=@($diagnostics|Sort-Object @{Expression={[Text.Encoding]::UTF8.GetByteCount([string]$_.Value)};Descending=$true}|Select-Object -First 1)
        if($largest.Count -ne 1 -or [Text.Encoding]::UTF8.GetByteCount([string]$largest[0].Value) -le 256){throw 'CANONICAL_AUDIT_METADATA_EXCEEDS_BOUND'}
        $budget=[Math]::Max(256,[int]([Text.Encoding]::UTF8.GetByteCount([string]$largest[0].Value)/2))
        $largest[0].Value=Protect-InstallationText ([string]$largest[0].Value) $budget
    }while($true)
}
function Save([string]$Path, $Value, [bool]$SanitizeDiagnostics=$false) {
    $privateDiagnostics=$false
    $evidenceRoot=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($evidenceRoot -and [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path)).Equals([IO.Path]::GetFullPath($evidenceRoot),[StringComparison]::OrdinalIgnoreCase)){
        Assert-InstallationEvidenceWriteRoot $evidenceRoot
        $privateDiagnostics=$true
    }
    $json = ConvertTo-CanonicalAuditJson $Value -PrivateDiagnostics:$privateDiagnostics
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $temp = "$Path.tmp.$PID"
    if (Get-Variable -Name CompleteRetiredRemoval -ValueOnly -ErrorAction SilentlyContinue) {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream = New-Object IO.FileStream($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    else { [IO.File]::WriteAllText($temp,$json,(New-Object Text.UTF8Encoding($false))) }
    Invoke-ContainerAtomicReplace $temp $Path -Mode WriteThrough
}
function New-CanonicalWriterFencePreparedReceipt(
    [string]$Path,
    [string]$SessionId,
    [string]$AttemptId,
    [string]$ReplacementTransactionId,
    [string]$SessionStartedAtUtc,
    [string]$OrchestratorSha256,
    [string]$WriterContractSha256,
    [string]$SourceManifestSha256,
    [string]$OperatorSid,
    [string]$OperatorLocalAppDataRoot
) {
    if (Test-Path -LiteralPath $Path) {
        throw 'CANONICAL_WRITER_PREPARED_RECEIPT_ALREADY_EXISTS'
    }
    $payload = [ordered]@{
        schema='container-audit-canonical-writer-prepared-v1'
        status='PREPARED'
        app_id='container_audit'
        session_id=$SessionId
        attempt_id=$AttemptId
        replacement_transaction_id=$ReplacementTransactionId
        session_started_at_utc=$SessionStartedAtUtc
        orchestrator_sha256=$OrchestratorSha256
        writer_contract_sha256=$WriterContractSha256
        writer_inventory_sha256=$Script:ContainerWriterFenceInventorySha256
        source_manifest_sha256=$SourceManifestSha256
        operator_sid=$OperatorSid
        operator_local_appdata_root=$OperatorLocalAppDataRoot
        created_at_utc=[DateTime]::UtcNow.ToString('o')
        secret_values_recorded=$false
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $json = ($payload | ConvertTo-Json -Depth 8) + "`n"
    Assert-InstallationMachineMetadataNoSecrets $json
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    try { $actual = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'CANONICAL_WRITER_PREPARED_RECEIPT_JSON_INVALID' }
    if (
        -not (Test-ExactPropertySet $actual @(
            'schema','status','app_id','session_id','attempt_id',
            'replacement_transaction_id','session_started_at_utc','orchestrator_sha256',
            'writer_contract_sha256','writer_inventory_sha256','source_manifest_sha256',
            'operator_sid','operator_local_appdata_root','created_at_utc','secret_values_recorded'
        )) -or
        [string]$actual.schema -cne 'container-audit-canonical-writer-prepared-v1' -or
        [string]$actual.status -cne 'PREPARED' -or
        [string]$actual.app_id -cne 'container_audit' -or
        [string]$actual.session_id -cne $SessionId -or
        [string]$actual.attempt_id -cne $AttemptId -or
        [string]$actual.replacement_transaction_id -cne $ReplacementTransactionId -or
        [string]$actual.session_started_at_utc -cne $SessionStartedAtUtc -or
        [string]$actual.orchestrator_sha256 -cne $OrchestratorSha256 -or
        [string]$actual.writer_contract_sha256 -cne $WriterContractSha256 -or
        [string]$actual.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        [string]$actual.source_manifest_sha256 -cne $SourceManifestSha256 -or
        [string]$actual.operator_sid -cne $OperatorSid -or
        [string]$actual.operator_local_appdata_root -cne $OperatorLocalAppDataRoot -or
        $actual.secret_values_recorded -isnot [bool] -or [bool]$actual.secret_values_recorded
    ) { throw 'CANONICAL_WRITER_PREPARED_RECEIPT_READBACK_FAILED' }
    return [pscustomobject][ordered]@{
        path=[IO.Path]::GetFullPath($Path)
        sha256=Sha $Path
    }
}
function New-CanonicalWriterFenceReleaseAuthorization(
    [string]$Path,
    [string]$Phase,
    [string]$AuditPath,
    $EnabledBaseline = $null
) {
    if ($Phase -cnotin @('PRODUCT_NATURAL_TRIGGER','PRODUCT_COMPLETE','ROLLBACK_NATURAL_TRIGGER','ROLLBACK_COMPLETE')) {
        throw 'CANONICAL_WRITER_RELEASE_PHASE_INVALID'
    }
    if (Test-Path -LiteralPath $Path) { throw 'CANONICAL_WRITER_RELEASE_AUTHORIZATION_ALREADY_EXISTS' }
    $auditFull = [IO.Path]::GetFullPath($AuditPath)
    if (-not (Test-Path -LiteralPath $auditFull -PathType Leaf)) {
        throw 'CANONICAL_WRITER_RELEASE_AUDIT_ABSENT'
    }
    $naturalTrigger = $Phase -cin @('PRODUCT_NATURAL_TRIGGER','ROLLBACK_NATURAL_TRIGGER')
    if ($naturalTrigger -and $null -eq $EnabledBaseline) {
        throw 'CANONICAL_WRITER_RELEASE_BASELINE_ABSENT'
    }
    $readback = if ($naturalTrigger) { $EnabledBaseline.readback } else { $null }
    $payload = [ordered]@{
        schema = 'container-audit-writer-release-authorization-v1'
        status = 'AUTHORIZED'
        phase = $Phase
        app_id = 'container_audit'
        session_id = $Script:CanonicalWriterFenceSessionId
        attempt_id = $Script:CanonicalWriterFenceAttemptId
        replacement_transaction_id = $Script:CanonicalWriterFenceTransactionId
        writer_inventory_sha256 = $Script:ContainerWriterFenceInventorySha256
        task_name = if ($naturalTrigger) { [string]$readback.task_name } else { '' }
        task_path = if ($naturalTrigger) { [string]$readback.task_path } else { '' }
        binding_sha256 = if ($naturalTrigger) { [string]$readback.binding_sha256 } else { '' }
        future_natural_trigger_utc = if ($naturalTrigger) { [string]$EnabledBaseline.future_natural_trigger_utc } else { '' }
        install_audit_path = $auditFull
        install_audit_sha256 = Sha $auditFull
        created_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_values_recorded = $false
    }
    if ($naturalTrigger -and (
        [string]::IsNullOrWhiteSpace([string]$payload.task_name) -or
        [string]::IsNullOrWhiteSpace([string]$payload.task_path) -or
        [string]$payload.binding_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$payload.future_natural_trigger_utc)
    )) { throw 'CANONICAL_WRITER_RELEASE_BASELINE_INVALID' }
    Write-Utf8Json $Path $payload
    $expectedFields = @(
        'schema','status','phase','app_id','session_id','attempt_id',
        'replacement_transaction_id','writer_inventory_sha256','task_name','task_path',
        'binding_sha256','future_natural_trigger_utc','install_audit_path',
        'install_audit_sha256','created_at_utc','secret_values_recorded'
    )
    try { $actual = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'CANONICAL_WRITER_RELEASE_AUTHORIZATION_JSON_INVALID' }
    if (
        -not (Test-ExactPropertySet $actual $expectedFields) -or
        -not (Test-ExactStringProperties $actual @($expectedFields | Where-Object { $_ -cne 'secret_values_recorded' })) -or
        $actual.secret_values_recorded -isnot [bool] -or [bool]$actual.secret_values_recorded -or
        [string]$actual.schema -cne 'container-audit-writer-release-authorization-v1' -or
        [string]$actual.status -cne 'AUTHORIZED' -or
        [string]$actual.phase -cne $Phase -or
        [string]$actual.app_id -cne 'container_audit' -or
        [string]$actual.session_id -cne $Script:CanonicalWriterFenceSessionId -or
        [string]$actual.attempt_id -cne $Script:CanonicalWriterFenceAttemptId -or
        [string]$actual.replacement_transaction_id -cne $Script:CanonicalWriterFenceTransactionId -or
        [string]$actual.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        [string]$actual.install_audit_path -cne $auditFull -or
        [string]$actual.install_audit_sha256 -cne (Sha $auditFull)
    ) { throw 'CANONICAL_WRITER_RELEASE_AUTHORIZATION_READBACK_FAILED' }
    return [ordered]@{ path=[IO.Path]::GetFullPath($Path); sha256=Sha $Path }
}
function Set-CanonicalWriterFenceReleaseAuthorization($Authorization) {
    Invoke-CanonicalWriterFenceReleaseStep {
        [void](Set-ContainerWriterFencePrepared `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -PreparedReceiptPath ([string]$Authorization.path) `
            -PreparedReceiptSha256 ([string]$Authorization.sha256) `
            -Status 'PREPARED' `
            -AuthorityLease $canonicalWriterFenceAuthority)
    }
}
function Invoke-CanonicalWriterFenceReleaseStep([scriptblock]$Action) {
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try { return & $Action }
        catch {
    Write-InstallationCaughtFailure $_

            if (
                $_.Exception.Message -cnotin @(
                    'CONTAINER_WRITER_ADMISSION_MUTEX_TIMEOUT',
                    'CONTAINER_WRITER_ADMISSION_MUTEX_ABANDONED'
                ) -or $attempt -ge 6
            ) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}
function Clear-CanonicalWriterFenceReleaseDelegation {
    Invoke-CanonicalWriterFenceReleaseStep {
        [void](Clear-ContainerWriterFenceDelegation `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
            -AuthorityLease $canonicalWriterFenceAuthority)
    }
}
function Stop-CanonicalWriterFenceRelease($Authorization) {
    $job=Get-Variable -Name canonicalTransactionJob -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $job){Stop-InstallationTransactionFence $job $Authorization;return}
    Invoke-CanonicalWriterFenceReleaseStep {
        [void](Stop-ContainerWriterFence `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -ReleaseAuthorizationPath ([string]$Authorization.path) `
            -ReleaseAuthorizationSha256 ([string]$Authorization.sha256) `
            -AuthorityLease $canonicalWriterFenceAuthority)
    }
}
function Relays {
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        [string]$_.CommandLine -like '*--container-audit-user-relay*' -and
        [string]$_.ExecutablePath -match '(?i)(pythonw?\.exe|Container_Audit\.exe)$'
    })
}
function Write-CanonicalInstallerRelayGuidance {
    'relay_recovery_guidance=같은 작업자 일반 세션에서 작업자 설정 제거 → 작업자 첫 설정 순서로 준비를 마치세요. 관리자 기계 설치는 다른 세션의 relay를 실행하지 않습니다.'
}
function Get-CanonicalInstallerProductWriters([string]$Root) {
    $scope=Full $Root 'installer writer root'
    if(Test-Path -LiteralPath (Join-Path (Split-Path -Parent $scope) 'update-control\policy.json')){$scope=Split-Path -Parent $scope}
    $prefix=$scope.TrimEnd('\')+'\'
    return @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {
        [int]$_.ProcessId -ne $PID -and (
            (([string]$_.ExecutablePath).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and
             [IO.Path]::GetFileName([string]$_.ExecutablePath) -in @('python.exe','pythonw.exe','Container_Audit.exe')) -or
            (([string]$_.CommandLine).IndexOf($prefix,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and
             ([string]$_.CommandLine).IndexOf('app\main.py',[StringComparison]::OrdinalIgnoreCase) -ge 0))
    })
}
function Test-CanonicalOrdinaryRelaySecurity($Security,[string]$SubjectSid) {
    if($null -eq $Security){return $false}
    foreach($name in @('sid','session_id','integrity_level','elevated')){
        if($null -eq $Security.PSObject.Properties[$name]){return $false}
    }
    return ($Security.sid -is [string] -and [string]$Security.sid -ceq $SubjectSid -and
        (Test-BootstrapJsonInteger $Security.session_id) -and [int]$Security.session_id -gt 0 -and
        (Test-BootstrapJsonInteger $Security.integrity_level) -and [int]$Security.integrity_level -eq 8192 -and
        $Security.elevated -is [bool] -and -not $Security.elevated)
}

function Assert-CanonicalInstallerStopPath([string]$Path) {
    $full=Full $Path 'installer stop marker'
    $cursor=$full
    while($cursor){
        $item=$null
        try{$item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop}
        catch [Management.Automation.ItemNotFoundException] {}
        if($null -ne $item){
            Assert-BootstrapNoReparsePoint $cursor 'installer stop marker' -PathOnly
            if(-not(Same $cursor $full) -and -not $item.PSIsContainer){throw 'INSTALLER_RELAY_STOP_PATH_INVALID'}
            return
        }
        $parent=Split-Path -Parent $cursor
        if($parent -ceq $cursor){break}
        $cursor=$parent
    }
    throw 'INSTALLER_RELAY_STOP_PATH_INVALID'
}

function Read-CanonicalInstallerOwnedStopMarker($Proof,[switch]$BindHash,[switch]$AllowAbsent) {
    $transaction=[string](Get-Variable -Name CanonicalWriterFenceTransactionId -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
    if($null -eq $Proof -or [string]$Proof.schema -cne 'container-audit-installer-stop-preimage-v1' -or
        $transaction -cnotmatch '^[0-9a-f]{32}$' -or [string]$Proof.transaction_id -cne $transaction -or
        $Proof.preimage_absent -isnot [bool] -or -not $Proof.preimage_absent -or
        [string]$Proof.request_id -cnotmatch '^[0-9a-f]{32}$'){
        throw 'INSTALLER_RELAY_STOP_OWNERSHIP_UNPROVEN'
    }
    $path=Full ([string]$Proof.path) 'installer stop marker'
    if(-not(Same $path (Join-Path ([string]$Proof.state_root) 'control\container_audit_user_relay.stop.json'))){
        throw 'INSTALLER_RELAY_STOP_OWNERSHIP_UNPROVEN'
    }
    Assert-CanonicalInstallerStopPath $path
    if(-not(Test-Path -LiteralPath $path)){
        if($AllowAbsent){return 'ABSENT'}
        throw 'INSTALLER_RELAY_STOP_OWNERSHIP_UNPROVEN'
    }
    $item=Get-Item -LiteralPath $path -ErrorAction Stop
    if($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 4096){throw 'INSTALLER_RELAY_STOP_OWNERSHIP_UNPROVEN'}
    $sha=Sha $path
    $marker=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    if([string]$marker.schema_version -cne 'container-audit-user-relay-stop-v1' -or
        [string]$marker.request_id -cne [string]$Proof.request_id -or (Sha $path) -cne $sha -or
        ([string]$Proof.sha256 -and [string]$Proof.sha256 -cne $sha)){
        throw 'INSTALLER_RELAY_STOP_OWNERSHIP_UNPROVEN'
    }
    if($BindHash){$Proof.sha256=$sha}
    return $sha
}

function Restore-CanonicalInstallerStopPreimage {
    $proof=Get-Variable -Name CanonicalInstallerRelayStopOwnership -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $sha=Read-CanonicalInstallerOwnedStopMarker $proof -AllowAbsent
    if($sha -cne 'ABSENT'){
        $path=Full ([string]$proof.path) 'installer stop marker'
        Assert-CanonicalInstallerStopPath $path
        if((Read-CanonicalInstallerOwnedStopMarker $proof) -cne $sha){throw 'INSTALLER_RELAY_STOP_OWNERSHIP_UNPROVEN'}
        Remove-Item -LiteralPath $path -ErrorAction Stop
        if(Test-Path -LiteralPath $path){throw 'INSTALLER_RELAY_STOP_PREIMAGE_RESTORE_UNPROVEN'}
    }
    return [ordered]@{status='ABSENT';preimage_absent=$true;owned_request_restored=$true}
}

function Restore-CanonicalInstallerEarlyRuntime($Before,[object[]]$Old,[string]$Root) {
    if($null -eq (Get-Variable -Name CanonicalInstallerEarlyRecovery -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){
        $Script:CanonicalInstallerEarlyRecovery=[ordered]@{status='RECOVERY_REQUIRED';stop_preimage_restored=$false;run_preimage_proven=$false;ready_proven=$false}
    }
    try {
        $current=Snapshot
        if($Old.Count -ne 1 -or [bool]$current.exists -ne [bool]$Before.exists -or
            [string]$current.kind -cne [string]$Before.kind -or [string]$current.data -cne [string]$Before.data -or
            @(Relays).Count -ne 0){throw 'INSTALLER_EARLY_RUNTIME_PREIMAGE_UNPROVEN'}
        $Script:CanonicalInstallerEarlyRecovery.run_preimage_proven=$true
        [void](Restore-CanonicalInstallerStopPreimage)
        $Script:CanonicalInstallerEarlyRecovery.stop_preimage_restored=$true
        $proof=Start-CanonicalRelayAfterFenceRelease -Root $Root -RunCommand ([string]$Before.data)
        $ready=Get-Variable -Name CanonicalRelayProof -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if(-not(Test-BootstrapJsonInteger $proof) -or [int]$proof -le 0 -or
            $null -eq $ready -or [string]$ready.status -cne 'PROVEN' -or [int]$ready.process_id -ne [int]$proof){
            throw 'INSTALLER_EARLY_RELAY_READY_UNPROVEN'
        }
        [void](Assert-RollbackRelayPreimage -ExpectedRelays $Old)
        $Script:CanonicalInstallerEarlyRecovery.ready_proven=$true
        $Script:CanonicalInstallerEarlyRecovery.status='RESTORED'
        Write-InstallationEvidenceEvent ([ordered]@{event='INSTALLER_EARLY_RELAY_RESTORED';ready_proven=$true;stop_preimage_restored=$true})
        return $Script:CanonicalInstallerEarlyRecovery
    }catch{
        $Script:CanonicalInstallerEarlyRecovery.status='RECOVERY_REQUIRED'
        Write-InstallationCaughtFailure $_
        throw 'RECOVERY_REQUIRED'
    }
}

function Stop-CanonicalInstallerRelayPreimage([object[]]$Expected,[string]$StateRoot,[string]$CodeRoot,[string]$InstalledRoot,[string]$SubjectSid,$RunPreimage) {
    # Other product writers must exit themselves. Only one admitted ordinary
    # resident in this caller's session is eligible for the normal stop request.
    foreach($writer in @(Get-CanonicalInstallerProductWriters $InstalledRoot)){
        if(@($Expected|Where-Object {$_.ProcessId -eq $writer.ProcessId -and $_.CreationDate -eq $writer.CreationDate}).Count -ne 1){
            throw 'INSTALLER_UNRELATED_PRODUCT_WRITER_ACTIVE'
        }
    }
    if($Expected.Count -eq 0){return [ordered]@{status='ABSENT';preimage_count=0}}
    if($Expected.Count -ne 1){throw 'INSTALLER_RELAY_PREIMAGE_INVALID'}
    $caller=Get-CanonicalOperatorSecurity
    if(-not(Test-CanonicalOrdinaryRelaySecurity $caller $SubjectSid)){throw 'INSTALLER_RELAY_ORDINARY_SESSION_REQUIRED'}
    $live=@(Assert-RollbackRelayPreimage $Expected)
    $security=Get-CanonicalRelaySecurity ([int]$live[0].ProcessId)
    if($live[0].ProcessId -ne $Expected[0].ProcessId -or
        ([DateTime]$live[0].CreationDate).ToUniversalTime() -ne ([DateTime]$Expected[0].CreationDate).ToUniversalTime() -or
        -not(Test-CanonicalOrdinaryRelaySecurity $security $SubjectSid) -or
        [int]$security.session_id -ne [int]$caller.session_id){throw 'INSTALLER_RELAY_NATIVE_PREIMAGE_DIFFERS'}
    $Script:CanonicalInstallerRelayPreimage=@(Get-CanonicalGlobalRelayPreimage)
    Write-InstallationEvidenceEvent ([ordered]@{event='INSTALLER_RELAY_PREIMAGE';relays=$Script:CanonicalInstallerRelayPreimage;run_preimage=$RunPreimage})
    $markerPath=Full (Join-Path $StateRoot 'control\container_audit_user_relay.stop.json') 'installer stop marker'
    Assert-CanonicalInstallerStopPath $markerPath
    if(Test-Path -LiteralPath $markerPath){throw 'INSTALLER_RELAY_STOP_PREIMAGE_PRESENT'}
    $transaction=[string](Get-Variable -Name CanonicalWriterFenceTransactionId -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
    if($transaction -cnotmatch '^[0-9a-f]{32}$'){throw 'INSTALLER_RELAY_STOP_ROUND_INVALID'}
    $Script:CanonicalInstallerRelayStopOwnership=[ordered]@{schema='container-audit-installer-stop-preimage-v1';
        transaction_id=$transaction;state_root=(Full $StateRoot 'installer relay state');path=$markerPath;
        preimage_absent=$true;request_id=[Guid]::NewGuid().ToString('N');sha256=''}
    $probe=@'
import pathlib, sys
root, state = map(pathlib.Path, sys.argv[1:3])
sys.path[:0] = [str(root / 'app'), str(root / 'app/site-packages')]
from user_relay import request_user_relay_stop
proof = request_user_relay_stop(state, timeout_seconds=15.0, request_id=sys.argv[3])
if proof['status'] != 'ABSENT':
    raise RuntimeError('installer relay stop unproven')
print('installer_relay_stop=ABSENT')
'@
    $probe=$probe.Replace("`r`n","`n").TrimEnd("`n")+"`n"
    if((Get-BootstrapStringSha256 $probe) -cne 'fa22b7d085661a5833406f690613775fa6b2c29adf35d7454548cb50b14af709'){
        throw 'INSTALLER_RELAY_STOP_PROBE_DIFFERS'
    }
    $Script:CanonicalInstallerRelayStopAttempted=$true
    $result=Invoke-InstallationEvidenceChild 'installer-normal-relay-stop' (Join-Path $CodeRoot 'runtime\python.exe') @('-I','-B','-c',$probe,$CodeRoot,$StateRoot,[string]$Script:CanonicalInstallerRelayStopOwnership.request_id)
    if($result.ExitCode -ne 0 -or $null -ne $result.EvidenceFailure -or $result.Stdout.Trim() -cne 'installer_relay_stop=ABSENT'){
        throw 'INSTALLER_RELAY_NORMAL_STOP_UNPROVEN'
    }
    [void](Read-CanonicalInstallerOwnedStopMarker $Script:CanonicalInstallerRelayStopOwnership -BindHash)
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    do {
        if(@(Relays).Count -eq 0){
            Write-InstallationEvidenceEvent ([ordered]@{event='INSTALLER_RELAY_STOPPED';status='ABSENT';preimage_count=$Expected.Count})
            return [ordered]@{status='ABSENT';preimage_count=$Expected.Count;normal_stop=$true}
        }
        Start-Sleep -Milliseconds 100
    }while([DateTime]::UtcNow -lt $deadline)
    throw 'INSTALLER_RELAY_PROCESS_EXIT_UNPROVEN'
}
function Confirm-CanonicalRuntimeQuiescence($Removal, [object[]]$ExpectedRelays, [string]$StopRequestPath) {
    if (
        [string]$Removal.status -cne 'PASS_DATA_PRESERVED' -or
        -not (Test-JsonTrue $Removal.data_preserved) -or
        [string]$Removal.relay_autostart.status -cne 'ABSENT' -or
        [string]$Removal.relay_process.status -cne 'ABSENT' -or
        [string]$Removal.relay_process.request_id -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Same ([string]$Removal.relay_process.stop_request_path) $StopRequestPath)
    ) { throw 'Verified replacement runtime quiescence failed: removal receipt.' }
    $deadline = (Get-Date).AddSeconds(15)
    $observations = 0
    do {
        $marker = Get-Content -LiteralPath $StopRequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$marker.schema_version -cne 'container-audit-user-relay-stop-v1' -or
            [string]$marker.request_id -cne [string]$Removal.relay_process.request_id -or (Snapshot).exists) {
            throw 'Verified replacement runtime quiescence failed: stop/Run binding.'
        }
        $remaining = @(Relays)
        $observations++
        foreach ($process in $remaining) {
            $matching = @($ExpectedRelays | Where-Object {
                (Same ([string]$process.ExecutablePath) ([string]$_.ExecutablePath)) -and
                (Get-CanonicalRelayCommandIdentity ([string]$process.CommandLine) ([string]$_.ExecutablePath)) -ceq
                (Get-CanonicalRelayCommandIdentity ([string]$_.CommandLine) ([string]$_.ExecutablePath))
            })
            if ($matching.Count -ne 1 -or $remaining.Count -gt @($ExpectedRelays).Count) {
                throw 'Verified replacement runtime quiescence failed: foreign relay.'
            }
        }
        if ($remaining.Count -eq 0) {
            return [ordered]@{status='ABSENT'; request_id=[string]$Removal.relay_process.request_id; process_observations=$observations}
        }
        # The old product releases its runtime lease before interpreter teardown.
        # Its ABSENT receipt is necessary; actual process absence is a separate proof.
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw 'Verified replacement runtime quiescence failed: process exit timed out.'
}
# G's first recorded READY was 275.561 seconds after the request. The shared
# install/rollback budget adds 84.439 seconds; it remains a failure if unproven.
function Wait-CanonicalRelayReady($Identity,[DateTime]$StartedAt,[string]$PreviousStatusSha256,[int[]]$PreviousProcessIds,[int]$TimeoutSeconds=360) {
    if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 600){throw 'Canonical relay readiness timeout is invalid.'}
    $caller=Get-CanonicalOperatorSecurity
    $watch=[Diagnostics.Stopwatch]::StartNew();$lastStatusSha='';$lastStatus=$null
    do {
        $snapshot=Get-BootstrapRelayReadinessSnapshot $Identity
        $Identity=$snapshot.identity
        $processes=@(Relays)
        $transactionConfiguration=Get-Variable -Name InstallationTransactionConfiguration -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $transactionConfiguration){
            $globalPreimage=@(Get-CanonicalGlobalRelayPreimage)
            $processes=@(Get-CanonicalTransactionManagedRelays $transactionConfiguration $globalPreimage |
                ForEach-Object {Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$_.process_id) -ErrorAction Stop})
        }
        $status=$null;$statusSha=''
        if(Test-Path -LiteralPath $relayPath -PathType Leaf) {
            Assert-BootstrapNoReparsePoint $relayPath 'relay status' -PathOnly
            if((Get-Item -LiteralPath $relayPath).Length -gt 65536){throw 'Relay status is oversized.'}
            $bytes=[IO.File]::ReadAllBytes($relayPath)
            $hash=[Security.Cryptography.SHA256]::Create()
            try{$statusSha=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
            $status=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff) | ConvertFrom-Json
            $lastStatus=$status;$lastStatusSha=$statusSha
        }
        if($processes.Count -eq 1 -and $PreviousProcessIds -cnotcontains [int]$processes[0].ProcessId) {
            $process=Get-CimInstance Win32_Process -Filter "ProcessId = $($processes[0].ProcessId)" -ErrorAction SilentlyContinue
            if($null -ne $process) {
                $security=Get-CanonicalRelaySecurity ([int]$process.ProcessId)
                $candidateTransaction=[string](Get-Variable -Name CanonicalWriterFenceTransactionId -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
                if($candidateTransaction -cmatch '^[0-9a-f]{32}$' -and $snapshot.settled -and
                    $null -ne $process.PSObject.Properties['CreationDate'] -and $process.CreationDate -is [DateTime] -and
                    ([DateTime]$process.CreationDate).ToUniversalTime() -ge $StartedAt.ToUniversalTime() -and
                    (Test-BootstrapRelayReadback $Identity $process $security $caller)){
                    Save-CanonicalRollbackRelayCandidate $process $security $caller $StartedAt
                }
                if($snapshot.settled -and (Test-BootstrapRelayReadback $Identity $process $security $caller $status $StartedAt $PreviousStatusSha256 $statusSha)) {
                    $confirmed=Get-BootstrapRelayReadinessSnapshot $Identity
                    if(-not $confirmed.settled -or [string]$confirmed.identity.source_commit -cne [string]$Identity.source_commit){continue}
                    if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds){break}
                    $Script:CanonicalRelayProof=[ordered]@{status='PROVEN';process_id=[int]$process.ProcessId;executable=[string]$process.ExecutablePath;
                        source_commit=[string]$Identity.source_commit;manifest_sha256=[string]$Identity.manifest_sha256;aggregate_sha256=[string]$Identity.aggregate_sha256;
                        sid=[string]$security.sid;session_id=[int]$security.session_id;elevated=[bool]$security.elevated;
                        relay_status=[string]$status.status;persistent_retry=[bool]$status.persistent_retry;runtime_status_sha256=$statusSha;
                        update_phase=[string]$confirmed.phase;
                        runtime_status_identity_fields=@($status.PSObject.Properties.Name | Where-Object {$_ -cin @('process_id','source_commit','ordinary_user')})}
                    Write-InstallationEvidenceEvent ([ordered]@{event='RESIDENT_RELAY_READY';proof=$Script:CanonicalRelayProof;launcher_pid_is_not_resident_proof=$true})
                    return [int]$process.ProcessId
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }while($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    Write-InstallationEvidenceEvent ([ordered]@{event='RESIDENT_RELAY_READY_TIMEOUT';status_path=$relayPath;status_sha256=$lastStatusSha;
        status_present=($null -ne $lastStatus);candidate_count=$processes.Count;expected_source_commit=$Identity.source_commit;started_at=$StartedAt.ToUniversalTime().ToString('o')})
    throw 'CANONICAL_RELAY_READY_TIMEOUT'
}
function Start-CanonicalRelayAfterFenceRelease([string]$Root=$install,[string]$RunCommand=$wanted) {
    $startedAt=[DateTime]::UtcNow
    $identity=Get-BootstrapRelayExpectedIdentity $Root $RunCommand
    $previousSha=if(Test-Path -LiteralPath $relayPath -PathType Leaf){Get-FileSha256 $relayPath}else{''}
    $previousIds=@(Relays | ForEach-Object {[int]$_.ProcessId})
    [void](StartRaw $RunCommand)
    $remaining=[Math]::Floor(360-([DateTime]::UtcNow-$startedAt).TotalSeconds)
    if($remaining -lt 1){throw 'CANONICAL_RELAY_READY_TIMEOUT'}
    return Wait-CanonicalRelayReady $identity $startedAt $previousSha $previousIds ([int]$remaining)
}
function Assert-RollbackRelayPreimage([object[]]$ExpectedRelays) {
    $actualRelays = @(Relays)
    if ($actualRelays.Count -ne $ExpectedRelays.Count) {
        throw 'rollback relay process-count readback failed'
    }
    foreach ($expected in $ExpectedRelays) {
        $matching = @($actualRelays | Where-Object {
            (Same ([string]$_.ExecutablePath) ([string]$expected.ExecutablePath)) -and
            [string]$_.CommandLine -ceq [string]$expected.CommandLine
        })
        if ($matching.Count -ne 1) {
            throw 'rollback relay executable/command readback failed'
        }
    }
    return $actualRelays
}
function Get-CanonicalRelayCommandIdentity([string]$CommandLine, [string]$ExecutablePath) {
    # Windows Run autostart can quote argv[0]; preserve every argument byte and case.
    $quotedExecutable = '"' + $ExecutablePath + '"'
    if ($CommandLine.StartsWith($quotedExecutable + ' ', [StringComparison]::Ordinal)) {
        return $ExecutablePath + $CommandLine.Substring($quotedExecutable.Length)
    }
    return $CommandLine
}
function Assert-CanonicalRuntimePreimage(
    $Before,
    [object[]]$Processes,
    [string]$ExpectedCommand,
    [string]$ExpectedRoot,
    [bool]$StopMarkerExists
) {
    $items = @($Processes)
    if ([bool]$Before.exists) {
        if (
            [string]$Before.kind -cne 'String' -or
            [string]$Before.data -cne $ExpectedCommand
        ) { throw 'CANONICAL_HKCU_RUN_BINDING_MISMATCH' }
    }
    elseif (
        -not [string]::IsNullOrEmpty([string]$Before.kind) -or
        -not [string]::IsNullOrEmpty([string]$Before.data)
    ) { throw 'CANONICAL_HKCU_RUN_ABSENCE_CONTRACT_INVALID' }
    if ($items.Count -gt 1) { throw 'CANONICAL_RELAY_CARDINALITY_INVALID' }
    $identity = if($items.Count){Get-BootstrapRelayExpectedIdentity $ExpectedRoot $ExpectedCommand}else{$null}
    $expectedExecutable = if($null -ne $identity){[string]$identity.executable}else{Join-Path $ExpectedRoot 'runtime\pythonw.exe'}
    $expectedIdentity = if($null -ne $identity){Get-CanonicalRelayCommandIdentity ([string]$identity.command) $expectedExecutable}else{''}
    foreach ($item in $items) {
        $commandIdentity = Get-CanonicalRelayCommandIdentity ([string]$item.CommandLine) $expectedExecutable
        if (
            -not [bool]$Before.exists -or
            -not (Same ([string]$item.ExecutablePath) $expectedExecutable) -or
            $commandIdentity -cne $expectedIdentity
        ) { throw 'CANONICAL_RELAY_BINDING_MISMATCH' }
    }
    if ($StopMarkerExists) { throw 'CANONICAL_STOP_MARKER_PREEXISTS' }
    return [ordered]@{
        status='PASS'
        hkcu_run_state=if ([bool]$Before.exists) { 'EXACT_CANONICAL' } else { 'ABSENT' }
        relay_count=$items.Count
        relay_binding_exact=$true
        stop_marker_absent=$true
    }
}
function Save-CanonicalRollbackRelayCandidate($Process,$Security,$Caller,[DateTime]$StartedAt) {
    $transaction=[string](Get-Variable -Name CanonicalWriterFenceTransactionId -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
    if($Process.CreationDate -isnot [DateTime] -or
        -not(Test-CanonicalOrdinaryRelaySecurity $Caller ([string]$Caller.sid)) -or
        -not(Test-CanonicalOrdinaryRelaySecurity $Security ([string]$Caller.sid)) -or
        [int]$Security.session_id -ne [int]$Caller.session_id -or
        [string]$Security.sid -cne [string]$Caller.sid -or
        ([DateTime]$Process.CreationDate).ToUniversalTime() -lt $StartedAt.ToUniversalTime()){throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'}
    if($transaction -cnotmatch '^[0-9a-f]{32}$'){throw 'ROLLBACK_RELAY_CANDIDATE_ROUND_INVALID'}
    $candidate=[ordered]@{schema='container-audit-installer-relay-candidate-v1';transaction_id=$transaction;
        round_started_at_utc=$StartedAt.ToUniversalTime().ToString('o');process_id=[int]$Process.ProcessId;
        created_at_utc=([DateTime]$Process.CreationDate).ToUniversalTime().ToString('o');
        executable_path=[string]$Process.ExecutablePath;command_line=[string]$Process.CommandLine;
        sid=[string]$Security.sid;session_id=[int]$Security.session_id}
    $previous=Get-Variable -Name CanonicalRollbackRelayCandidate -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $previous -and ($previous|ConvertTo-Json -Compress) -ceq ($candidate|ConvertTo-Json -Compress)){return}
    $Script:CanonicalRollbackRelayCandidate=$candidate
    $currentAudit=Get-Variable -Name audit -ValueOnly -ErrorAction SilentlyContinue
    $currentPath=[string](Get-Variable -Name auditPath -ValueOnly -ErrorAction SilentlyContinue)
    if($null -ne $currentAudit -and $currentPath){
        $currentAudit['rollback_relay_candidate']=$candidate
        Save $currentPath $currentAudit $true
    }
}

function Assert-CanonicalRollbackRelayCandidate {
    # Refusal remains sticky for marker cleanup later in the same compensation.
    $Script:CanonicalRollbackRelayStopRefused=$true
    $actual=@(Relays)
    if($actual.Count -eq 0){$Script:CanonicalRollbackRelayStopRefused=$false;return}
    if($actual.Count -ne 1){throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'}
    $candidate=Get-Variable -Name CanonicalRollbackRelayCandidate -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -eq $candidate){
        $configuration=Get-Variable -Name InstallationTransactionConfiguration -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $configuration){
            $parentPath=[string]$configuration.context.auditPath
            Assert-BootstrapNoReparsePoint $parentPath 'rollback candidate audit' -PathOnly
            if((Get-Item -LiteralPath $parentPath).Length -gt 1048576){throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'}
            $parent=Get-Content -LiteralPath $parentPath -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
            if([string]$parent.schema -cne 'container-audit-canonical-portable-install-v2' -or
                [string]$parent.run_id -cne [string]$configuration.context.runId){throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'}
            if($null -ne $parent.PSObject.Properties['rollback_relay_candidate']){$candidate=$parent.rollback_relay_candidate}
        }
    }
    $transaction=[string](Get-Variable -Name CanonicalWriterFenceTransactionId -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
    $caller=Get-CanonicalOperatorSecurity
    if($null -eq $candidate -or [string]$candidate.schema -cne 'container-audit-installer-relay-candidate-v1' -or
        $transaction -cnotmatch '^[0-9a-f]{32}$' -or [string]$candidate.transaction_id -cne $transaction -or
        -not(Test-CanonicalOrdinaryRelaySecurity $caller ([string]$caller.sid)) -or [string]$candidate.sid -cne [string]$caller.sid -or
        [int]$candidate.session_id -ne [int]$caller.session_id -or
        [int]$actual[0].ProcessId -ne [int]$candidate.process_id){throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'}
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$candidate.process_id) -ErrorAction Stop
    if($null -eq $process -or $process.CreationDate -isnot [DateTime] -or
        ([DateTime]$process.CreationDate).ToUniversalTime().ToString('o') -cne [string]$candidate.created_at_utc -or
        ([DateTime]$process.CreationDate).ToUniversalTime() -lt ([DateTime]$candidate.round_started_at_utc).ToUniversalTime() -or
        [string]$process.CommandLine -cne [string]$candidate.command_line -or
        -not(Same ([string]$process.ExecutablePath) ([string]$candidate.executable_path))){throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'}
    $security=Get-CanonicalRelaySecurity ([int]$process.ProcessId)
    $identity=[pscustomobject]@{executable=[string]$candidate.executable_path;command=[string]$candidate.command_line;operator_sid=[string]$caller.sid}
    if(-not(Test-CanonicalOrdinaryRelaySecurity $security ([string]$caller.sid)) -or -not(Test-BootstrapRelayReadback $identity $process $security $caller)){
        throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'
    }
    $Script:CanonicalRollbackRelayStopRefused=$false
}

function Assert-CanonicalRollbackStopCleanup {
    if([bool](Get-Variable -Name CanonicalRollbackRelayStopRefused -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){
        throw 'ROLLBACK_RELAY_CANDIDATE_UNPROVEN'
    }
}

function Product([string]$Root,[string]$Mode,[string]$AppRoot='',[switch]$Rollback) {
    if($Rollback -and $Mode -ceq '--remove-current-user-setup'){Assert-CanonicalRollbackRelayCandidate}
    if ($Mode -ceq '--onboard-current-user' -and [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) {
        throw '작업자 첫 설정은 대화형 사용자 세션에서 실행하세요.'
    }
    if (-not $AppRoot) { $AppRoot=Join-Path $Root 'app' }
    $args = @('-I','-B',(Join-Path $Root 'app\main.py'),$Mode,'--app-root',$AppRoot)
    if ($Mode -ceq '--onboard-current-user' -and $onboardingServerBaseUrl) {
        $args += @('--server-base-url',$onboardingServerBaseUrl)
    }
    if ($Mode -ceq '--onboard-current-user' -and $canonicalOnboardingInputBinding) {
        $args += @('--expected-input-binding',$canonicalOnboardingInputBinding)
    }
    # The capture waits for the host only, never its persistent relay descendant.
    $transactionOperator=Get-Variable -Name InstallationTransactionOperator -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $transactionOperator -and (Test-InstallationEvidencePrivileged)){
        $process=Invoke-BootstrapNormalFiniteProducer $source (Join-Path $Root 'runtime\pythonw.exe') $args (Join-Path $auditRoot ('transaction-product-'+[Guid]::NewGuid().ToString('N')))
    }else{$process = Invoke-InstallationEvidenceChild ('product'+$Mode.TrimStart('-')) (Join-Path $Root 'runtime\pythonw.exe') $args}
    if ($process.ExitCode -ne 0) {
        # Keep the child's protected-report pointer intact in the private failure
        # chain. The outer canonical boundary emits its fixed public record.
        $line=ConvertTo-KmtechRedactedSinkText -Text $(if($process.Stderr){$process.Stderr}else{$process.Stdout})
        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Product mode failed: $Mode/$($process.ExitCode): $line")))
    }
}
function Get-CanonicalRetirementChildFailure($Child, [Collections.IDictionary]$Environment=$null) {
    # App-owned redaction/capture is supplied by lifecycle assembly (sub-273).
    # Preserve the first child's full diagnostic up to the common sink limit.
    $detail=[ordered]@{process_id=$Child.ProcessId;exit_code=$Child.ExitCode;streams=$Child.Streams}
    foreach ($stream in @('Stdout','Stderr')) {
        $redaction=@{Text=[string]$Child.$stream}
        if ($null -ne $Environment) { $redaction.Environment=$Environment }
        $detail[$stream.ToLowerInvariant()]=ConvertTo-KmtechRedactedSinkText @redaction
    }
    return $detail
}
function Remove-CanonicalSupportedRemovalAttemptStop([string]$RemovalPath,[string]$StopPath,
    [DateTime]$StartedAt,[string]$ExpectedAppRoot,[string]$ExpectedStopSha256='') {
    if (-not (Test-Path -LiteralPath $StopPath)) { return 'ABSENT' }
    Assert-ContainerWriterFenceNoReparse $StopPath
    Assert-ContainerWriterFenceNoReparse $RemovalPath
    $receiptSha=Sha $RemovalPath
    $receipt=Get-Content -LiteralPath $RemovalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $stopSha=Sha $StopPath
    $marker=Get-Content -LiteralPath $StopPath -Raw -Encoding UTF8 | ConvertFrom-Json
    # PS7 parses ISO JSON dates eagerly; preserve their UTC kind and precision.
    $captured=if($receipt.captured_at -is [DateTime]){$receipt.captured_at.ToUniversalTime()}
        else{[DateTime]::Parse([string]$receipt.captured_at,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()}
    $requested=if($marker.requested_at -is [DateTime]){$marker.requested_at.ToUniversalTime()}
        else{[DateTime]::Parse([string]$marker.requested_at,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()}
    # Product timestamps have whole-second precision; compare the same format.
    $earliest=$StartedAt.ToUniversalTime()
    $earliest=$earliest.AddTicks(-($earliest.Ticks % [TimeSpan]::TicksPerSecond))
    if ([string]$receipt.report_version -cne 'container-audit-current-user-removal-v1' -or
        [string]$receipt.state_scope -cne 'current_user' -or $receipt.data_preserved -isnot [bool] -or -not $receipt.data_preserved -or
        -not (Same ([string]$receipt.machine_code_root) $ExpectedAppRoot) -or
        [string]$receipt.relay_autostart.status -cne 'ABSENT' -or
        [string]$receipt.relay_process.status -cnotin @('ABSENT','UNKNOWN') -or
        -not (Same ([string]$receipt.relay_process.stop_request_path) $StopPath) -or
        -not (Test-ExactPropertySet $marker @('schema_version','request_id','requested_at')) -or
        [string]$marker.schema_version -cne 'container-audit-user-relay-stop-v1' -or
        [string]$marker.request_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$marker.request_id -cne [string]$receipt.relay_process.request_id -or
        $captured -lt $earliest -or $requested -lt $captured -or $requested -gt [DateTime]::UtcNow -or
        (Snapshot).exists -or ($ExpectedStopSha256 -and $stopSha -cne $ExpectedStopSha256)) {
        throw 'REMOVAL_ATTEMPT_STOP_OWNERSHIP_UNPROVEN'
    }
    if ((Sha $RemovalPath) -cne $receiptSha -or (Sha $StopPath) -cne $stopSha) { throw 'REMOVAL_ATTEMPT_STOP_CHANGED' }
    Remove-Item -LiteralPath $StopPath -ErrorAction Stop
    return 'REMOVED_EXACT_CURRENT_ATTEMPT'
}
function Get-CanonicalOnboardingInputBinding([string]$Root,[string]$TargetReleaseRoot = '',[string]$InstallerSourceInventorySha256 = '') {
    # The existing product reader owns locator/nested resolution. This call
    # performs only admission/readback and runs before any installer mutation.
    $preflightArguments=@('-I','-B',(Join-Path $Root 'app\main.py'),
        '--onboard-current-user','--app-root',(Join-Path $Root 'app'),'--preflight-only')
    if ($TargetReleaseRoot) { $preflightArguments+=@('--target-release-root',$TargetReleaseRoot) }
    if ($InstallerSourceInventorySha256) {
        if ($TargetReleaseRoot -or $InstallerSourceInventorySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'CANONICAL_SOURCE_INVENTORY_PIN_INVALID' }
        $preflightArguments+=@('--installer-source-inventory-sha256',$InstallerSourceInventorySha256)
    }
    $pendingContinuation=Get-Variable -Name rollbackContinuation -ValueOnly -ErrorAction SilentlyContinue
    $fenceAlreadyActive=Get-Variable -Name canonicalWriterFenceActive -ValueOnly -ErrorAction SilentlyContinue
    if ($TargetReleaseRoot -and $pendingContinuation -and -not $fenceAlreadyActive) {
        $pendingFence=Read-ContainerWriterFence -AllowAbsent
        # After a verified release, use the unchanged ordinary preflight.
        # The read-only continuation scope applies only to a present fence.
        if ($null -ne $pendingFence) {
            $pendingRecheck=Read-CanonicalRollbackContinuation $install $lad $operatorSid
            if ($null -eq $pendingRecheck -or [string]$pendingRecheck.record_sha256 -cne [string]$pendingContinuation.record_sha256) {
                throw 'Rollback continuation changed before read-only preflight.'
            }
            [void](Read-BootstrapRollbackContinuationAuthority $pendingRecheck ([string]$pendingRecheck.record_path) ([string]$pendingRecheck.record_sha256) $pendingFence)
            $preflightArguments+=@('--rollback-preflight-journal-path',[string]$pendingRecheck.record_path,
                '--rollback-preflight-journal-sha256',[string]$pendingRecheck.record_sha256,
                '--rollback-preflight-fence-sha256',(Get-ContainerWriterFenceFileSha256 (Get-ContainerWriterFenceActivePath)))
        }
    }
    $preflightErrorPreference=$ErrorActionPreference
    try {
        # PS5.1 represents stderr as NativeCommandError. Capture it in memory
        # before validation; Stop would replay an unvalidated child record.
        $ErrorActionPreference='Continue'
        $PSNativeCommandUseErrorActionPreference=$false
        $output=@(& (Join-Path $Root 'runtime\python.exe') @preflightArguments 2>&1)
        $preflightExitCode=$LASTEXITCODE
    } finally { $ErrorActionPreference=$preflightErrorPreference }
    if ($preflightExitCode -ne 0) {
        $prefix='CONTAINER_AUDIT_INSTALLER_FAILURE='
        if($output.Count -ne 1 -or -not ([string]$output[0]).StartsWith($prefix,[StringComparison]::Ordinal)){
            throw 'INSTALLER_PUBLIC_FAILURE_RECORD_INVALID'
        }
        try{$payload=([string]$output[0]).Substring($prefix.Length)|ConvertFrom-ContainerWriterFenceJson}
        catch{throw 'INSTALLER_PUBLIC_FAILURE_RECORD_INVALID'}
        if($payload -isnot [pscustomobject]){throw 'PUBLIC_FIELD_NONCONFORMING'}
        $fields=[ordered]@{}
        foreach($property in $payload.PSObject.Properties){$fields[$property.Name]=$property.Value}
        $writerFailureCodes=@(
            'ACTIVE_WRITER_FENCE','FENCE_AUTHORITY_NAME_INVALID','FENCE_BINDING_INVALID',
            'FENCE_DELEGATION_INVALID','FENCE_JSON_INVALID','FENCE_PATH_UNOBSERVABLE',
            'FENCE_PREPARED_BINDING_INVALID','FENCE_PREPARED_RECEIPT_INVALID','FENCE_PREPARED_RECEIPT_MISMATCH',
            'FENCE_PREPARED_RECEIPT_UNOBSERVABLE','FENCE_REPARSE_REJECTED','FENCE_SHAPE_INVALID',
            'FENCE_SIZE_INVALID','FENCE_STATE_CHANGED','FENCE_STATE_UNOBSERVABLE',
            'FENCE_STATE_UNREADABLE','LOCALAPPDATA_UNAVAILABLE','NETWORK_WRITER_ADMISSION_HELD',
            'WRITER_ADMISSION_DEPTH_UNDERFLOW','WRITER_FENCE_FAILED','WRITER_GATE_ABANDONED',
            'WRITER_GATE_TIMEOUT','WRITER_MUTEX_CREATE_FAILED','WRITER_MUTEX_WAIT_FAILED',
            'WRITER_PROBE_ONLY_SINK_NOT_ALLOWED','WRITER_SOURCE_MISSING'
        )
        $record=ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes (@(
            'FAILED','onboarding_preflight','INSTALLER_CHILD_FAILURE','REPORT_UNAVAILABLE',
            'DATA_GENERATION_REFUSED','DATA_GENERATION_UNKNOWN') + $writerFailureCodes) `
            -SafeMessages @('자료를 보존하고 관리자 지원 복구를 요청하세요.','이 PC의 자료가 새 판으로 이미 열려 옛 판으로 되돌릴 수 없습니다. 같은 새 판을 다시 시작하거나 고친 판으로 지원 업데이트하세요. 관리자 지원 복구는 설치 전 백업과 옛 판을 함께 복원해야 합니다.','이 PC의 자료 판을 확인할 수 없어 옛 판으로 되돌릴 수 없습니다. 자료와 확인 기록을 보존하고 관리자 지원 복구를 요청하세요.')
        if($record.Contains('public_record_code')){throw 'PUBLIC_FIELD_NONCONFORMING'}
        $expectedFailureExit=if($record.reason_code -cin $writerFailureCodes){23}else{4}
        if($record.status -cne 'FAILED' -or $record.stage -cne 'onboarding_preflight' -or
            ($record.reason_code -cnotin @('INSTALLER_CHILD_FAILURE','DATA_GENERATION_REFUSED','DATA_GENERATION_UNKNOWN') -and
             $record.reason_code -cnotin $writerFailureCodes) -or
            $record.exit_code -ne $expectedFailureExit -or $record.exit_code -ne $preflightExitCode){
            throw 'INSTALLER_PUBLIC_FAILURE_RECORD_INVALID'
        }
        # The parent aborts with a fixed code; no child message is replayed.
        throw 'ONBOARDING_PREFLIGHT_FAILED'
    }
    $bindingPattern=if ($TargetReleaseRoot) { '^onboarding_input_binding=([0-9a-f]{64}:[0-9a-f]{64})$' }
        else { '^onboarding_input_binding=([0-9a-f]{64})$' }
    if ($output.Count -ne 1 -or [string]$output[0] -cnotmatch $bindingPattern) {
        throw '설치 전 자격 설정 경로 확인 결과가 올바르지 않습니다. 자료를 보존하고 설치를 다시 확인하세요.'
    }
    return $Matches[1]
}
function Assert-CanonicalRestoreCodeBinding([string]$Binding,$VerifiedRestore) {
    $oldIdentity = $VerifiedRestore.receipt.old
    $expected = Get-ContainerWriterFenceStringSha256 (
        [string]$oldIdentity.source_commit + '|' + [string]$oldIdentity.aggregate_sha256 + '|' + [string]$oldIdentity.manifest_sha256)
    if ($Binding -cnotmatch '^[0-9a-f]{64}:([0-9a-f]{64})$' -or $Matches[1] -cne $expected) {
        throw '복원 코드와 자격 설정 확인 결과가 검증한 옛 코드와 다릅니다. 자료를 보존하고 복원을 다시 확인하세요.'
    }
}
function Read-CanonicalRetiredRemoval {
    # These are observations, never authority. The caller still acquires the
    # live all-writer fence and the exact old helper rechecks code/quiescence.
    $retiredData = Join-Path $lad 'KMTech\ContainerAudit'
    $retiredRelay = Join-Path $lad 'KMTech\DirectSync\container_audit'
    if ([string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_DATA_ROOT) -or
        (Same $activeDataRoot $retiredData) -or
        (Same $activeRelayRoot $retiredRelay)) {
        throw 'RETIREMENT_DISTINCT_ADOPTED_ROOT_REQUIRED'
    }
    foreach ($root in @($retiredData, $retiredRelay, $activeDataRoot)) {
        Assert-ContainerWriterFenceNoReparse $root
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            throw 'RETIREMENT_EXISTING_ROOT_REQUIRED'
        }
    }
    foreach ($retired in @($retiredData, $retiredRelay)) {
        if ($activeDataRoot.StartsWith($retired + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $retired.StartsWith($activeDataRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'RETIREMENT_ROOTS_OVERLAP'
        }
    }
    foreach ($data in @($retiredData, $retiredRelay, $activeDataRoot)) {
        foreach ($code in @($source, $lifecycleSource, $install)) {
            if ((Same $data $code) -or $data.StartsWith($code + '\', [StringComparison]::OrdinalIgnoreCase) -or
                $code.StartsWith($data + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'RETIREMENT_SOURCE_DATA_OVERLAP'
            }
        }
    }
    foreach ($path in @($activeRelayRoot, (Join-Path $activeRelayRoot 'status'),
        (Join-Path $activeRelayRoot 'control'), (Join-Path $activeDataRoot 'install-audit'))) {
        Assert-ContainerWriterFenceNoReparse $path
    }
    if ($EvidencePath) {
        $output = Full $EvidencePath 'EvidencePath'
        Assert-ContainerWriterFenceNoReparse $output
        foreach ($protected in @($retiredData, $retiredRelay, $activeDataRoot, $source, $lifecycleSource, $install)) {
            if ((Same $output $protected) -or $output.StartsWith($protected + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'RETIREMENT_EVIDENCE_OVERLAPS_PRESERVED_INPUT'
            }
        }
    }
    $receiptPath = Join-Path $retiredRelay 'status\current_user_removal.json'
    $markerPath = Join-Path $retiredRelay 'control\container_audit_user_relay.stop.json'
    if ((Get-ContainerWriterFenceFileSha256 $receiptPath 65536) -cne $RetiredRemovalReceiptSha256 -or
        (Get-ContainerWriterFenceFileSha256 $markerPath 4096) -cne $RetiredStopMarkerSha256) {
        throw 'RETIREMENT_OBSERVATION_HASH_MISMATCH'
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $marker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Test-ExactPropertySet $marker @('schema_version','request_id','requested_at')) -or
        [string]$marker.schema_version -cne 'container-audit-user-relay-stop-v1' -or
        [string]$marker.request_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$receipt.status -cne 'PASS_DATA_PRESERVED' -or
        [string]$receipt.state_scope -cne 'current_user' -or
        -not (Test-JsonTrue $receipt.data_preserved) -or
        [string]$receipt.relay_autostart.status -cne 'ABSENT' -or
        [string]$receipt.relay_process.status -cne 'ABSENT' -or
        [string]$receipt.relay_process.request_id -cne [string]$marker.request_id -or
        -not (Same ([string]$receipt.relay_process.stop_request_path) $markerPath) -or
        -not (Same ([string]$receipt.machine_code_root) (Join-Path $install 'app')) -or
        @($receipt.preserved_paths).Count -ne 3 -or
        -not (Same ([string]$receipt.preserved_paths[0]) $retiredData) -or
        -not (Same ([string]$receipt.preserved_paths[1]) $retiredRelay)) {
        throw 'RETIREMENT_REQUEST_BINDING_MISMATCH'
    }
    [void](ConvertTo-ContainerWriterFenceUtc ([string]$marker.requested_at))
    if ((Get-ContainerWriterFenceFileSha256 $receiptPath 65536) -cne $RetiredRemovalReceiptSha256 -or
        (Get-ContainerWriterFenceFileSha256 $markerPath 4096) -cne $RetiredStopMarkerSha256) {
        throw 'RETIREMENT_OBSERVATION_CHANGED_DURING_READBACK'
    }
    return [ordered]@{
        status='BOUND_OBSERVATION_NOT_QUIESCENCE'
        current_user_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        retired_data_root=$retiredData
        retired_relay_root=$retiredRelay
        adopted_data_root=$activeDataRoot
        removal_receipt_path=$receiptPath
        removal_receipt_sha256=$RetiredRemovalReceiptSha256
        stop_marker_path=$markerPath
        stop_marker_sha256=$RetiredStopMarkerSha256
        request_id=[string]$marker.request_id
        old_source_root=$lifecycleSource
        old_manifest_sha256=$lifecycleManifestSha256
        old_aggregate_sha256=$uninstallAggregate
        stop_marker_preserved=$true
    }
}
function Assert-RetirementOwnerExited($Retirement) {
    if (-not (Test-JsonPositiveInt32 $Retirement.owner_process_id)) {
        throw 'RETIREMENT_OWNER_IDENTITY_INVALID'
    }
    [void](ConvertTo-ContainerWriterFenceUtc ([string]$Retirement.owner_started_at_utc))
    $owners = @(Get-Process -ErrorAction Stop | Where-Object { $_.Id -eq [int]$Retirement.owner_process_id })
    foreach ($owner in $owners) {
        if ($owner.StartTime.ToUniversalTime().ToString('o') -ceq [string]$Retirement.owner_started_at_utc) {
            throw 'RETIREMENT_ORIGINAL_OWNER_STILL_LIVE'
        }
        throw 'RETIREMENT_ORIGINAL_PID_REUSED'
    }
    # Process exit is observed independently of mutex absence. An inaccessible
    # or live authority is not permission to take over its journal.
    $mutex = $null
    try {
        try { $mutex = [Threading.Mutex]::OpenExisting([string]$Retirement.authority_mutex_name) }
        catch [Threading.WaitHandleCannotBeOpenedException] { return }
        try { $acquired = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'RETIREMENT_ORIGINAL_AUTHORITY_STILL_LIVE' }
        $mutex.ReleaseMutex()
    }
    finally { if ($null -ne $mutex) { $mutex.Dispose() } }
}
function Enter-RetirementResumeClaim($Prior) {
    $identity = (Get-ContainerWriterFenceControlRoot).ToLowerInvariant() + '|' + [string]$Prior.code_replacement.transaction_id
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $digest = ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity)))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
    $created = $false
    $mutex = New-Object Threading.Mutex($true, ('Local\KMTech.ContainerAudit.RetirementResume.' + $digest), [ref]$created)
    if (-not $created) {
        $mutex.Dispose()
        throw 'RETIREMENT_RESUME_AUTHORITY_ALREADY_EXISTS'
    }
    return $mutex
}
function Exit-RetirementResumeClaim($Claim) {
    if ($null -ne $Claim) {
        try { $Claim.ReleaseMutex() }
        finally { $Claim.Dispose() }
    }
}
function Assert-RetirementWriterQuiescence {
    # A stop marker covers the persistent relay only. Include GUI, hosted
    # children, and tools launched from either admitted packet or the install.
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        if ([int]$process.ProcessId -eq $PID) { continue }
        $executable = [string]$process.ExecutablePath
        if ([IO.Path]::GetFileName($executable) -notmatch '^(?i:python(?:w|[0-9.]*)?|py|Container_Audit)\.exe$') { continue }
        $command = ([string]$process.CommandLine).Replace('/', '\')
        $bound = $false
        foreach ($root in @($source, $lifecycleSource, $install)) {
            $prefix = $root.TrimEnd('\') + '\'
            if ($executable.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
                $command.IndexOf($prefix, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $bound = $true }
        }
        foreach ($data in @($activeDataRoot, (Join-Path $lad 'KMTech\ContainerAudit'),
            (Join-Path $lad 'KMTech\DirectSync\container_audit'))) {
            if ($command -match ('(?i)(?:^|\s|")' + [regex]::Escape($data) + '(?:[\\"]|\s|$)')) { $bound = $true }
        }
        if ($bound) { throw 'RETIREMENT_CODE_WRITER_STILL_ACTIVE' }
    }
}
function Read-CanonicalRetirementResume {
    $path = Full $ResumeRetirementReceiptPath 'retirement resume receipt'
    if ((Get-ContainerWriterFenceFileSha256 $path 65536) -cne $ResumeRetirementReceiptSha256) {
        throw 'RETIREMENT_RESUME_RECEIPT_HASH_MISMATCH'
    }
    $prior = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $r = $prior.retirement
    $expectedData = Full $env:CONTAINER_AUDIT_DATA_ROOT 'adopted data root'
    $expectedAudit = Join-Path (Join-Path $expectedData 'install-audit') ('canonical-portable-' + [string]$prior.run_id + '.json')
    if ([string]$prior.schema -cne 'container-audit-canonical-portable-install-v2' -or
        [string]$prior.operation -cne 'COMPLETE_RETIRED_REMOVAL' -or
        [string]$prior.status -cnotin @('PREIMAGE_SAVED','UNINSTALL_RUNTIME_QUIESCED','UNINSTALL_AWAITING_FENCE_RELEASE','PASS_RETIRED_REMOVAL_DATA_PRESERVED') -or
        [string]$prior.run_id -cnotmatch '^\d{8}T\d{9}Z-[0-9a-f]{32}$' -or
        -not (Same $path $expectedAudit) -or
        -not (Same ([string]$prior.install_root) $install) -or
        [string]$prior.source_manifest_sha256 -cne $sourceManifestSha256 -or
        [string]$r.current_user_sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
        -not (Same ([string]$r.adopted_data_root) $expectedData) -or
        -not (Same ([string]$r.old_source_root) $lifecycleSource) -or
        [string]$r.old_manifest_sha256 -cne $lifecycleManifestSha256 -or
        [string]$r.old_aggregate_sha256 -cne (Get-InventoryAggregate @(Get-CodeInventory $lifecycleSource)) -or
        [string]$r.removal_receipt_sha256 -cne $RetiredRemovalReceiptSha256 -or
        [string]$r.stop_marker_sha256 -cne $RetiredStopMarkerSha256 -or
        [string]$r.orchestrator_sha256 -cne (Sha $PSCommandPath) -or
        [string]$r.session_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$r.attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$prior.code_replacement.transaction_id -cnotmatch '^[0-9a-f]{32}$') {
        throw 'RETIREMENT_RESUME_BINDING_MISMATCH'
    }
    $expectedAuthority = Get-ContainerWriterSessionAuthorityMutexName `
        ([string]$r.session_id) ([string]$r.attempt_id) ([string]$r.orchestrator_sha256) `
        ([string]$prior.code_replacement.transaction_id) ([string]$lifecycleManifest.writer_session_contract_sha256)
    if ([string]$r.authority_mutex_name -cne $expectedAuthority) { throw 'RETIREMENT_RESUME_AUTHORITY_BINDING_MISMATCH' }
    Assert-RetirementOwnerExited $r
    $preparedPath = Join-Path (Split-Path -Parent $path) ('canonical-portable-' + [string]$prior.run_id + '-writer-prepared.json')
    if (-not (Same ([string]$r.prepared_receipt_path) $preparedPath) -or
        (Get-ContainerWriterFenceFileSha256 $preparedPath 65536) -cne [string]$r.prepared_receipt_sha256) {
        throw 'RETIREMENT_RESUME_PREPARED_RECEIPT_MISMATCH'
    }
    $prepared = Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$prepared.session_id -cne [string]$r.session_id -or
        [string]$prepared.attempt_id -cne [string]$r.attempt_id -or
        [string]$prepared.replacement_transaction_id -cne [string]$prior.code_replacement.transaction_id -or
        [string]$prepared.orchestrator_sha256 -cne [string]$r.orchestrator_sha256 -or
        [string]$prepared.source_manifest_sha256 -cne $sourceManifestSha256 -or
        [string]$prepared.writer_contract_sha256 -cne [string]$lifecycleManifest.writer_session_contract_sha256) {
        throw 'RETIREMENT_RESUME_PREPARED_OWNER_MISMATCH'
    }
    if ([string]$prior.status -ceq 'PREIMAGE_SAVED') {
        if ((Get-ContainerWriterFenceFileSha256 (Join-Path $install 'bootstrap-integrity.json')) -cne [string]$r.old_record_sha256) {
            throw 'RETIREMENT_RESUME_CODE_PREIMAGE_MISMATCH'
        }
    }
    else {
        $recordPath = Join-Path (Split-Path -Parent $path) ('canonical-portable-' + [string]$prior.run_id + '-integrity-preimage.json')
        if (-not (Same ([string]$prior.code_integrity_preimage_path) $recordPath) -or
            (Get-ContainerWriterFenceFileSha256 $recordPath) -cne [string]$prior.code_integrity_preimage_sha256 -or
            [string]$prior.code_integrity_preimage_sha256 -cne [string]$r.old_record_sha256) {
            throw 'RETIREMENT_RESUME_CODE_PREIMAGE_MISMATCH'
        }
    }
    if ((Get-ContainerWriterFenceFileSha256 $path 65536) -cne $ResumeRetirementReceiptSha256) {
        throw 'RETIREMENT_RESUME_RECEIPT_CHANGED'
    }
    return $prior
}
function Get-CanonicalFailureDetails($Failure, [string]$Phase) {
    # Preserve bounded original messages through the shared credential redactor.
    # Invocation text and arguments remain excluded.
    $detail = [ordered]@{
        phase=$Phase; code='CANONICAL_UNCLASSIFIED_FAILURE'; api=''; win32_error=$null
        exception_types=@(); script_line=0
    }
    if ($Failure -is [Exception]) { $exception=$Failure }
    else {
        $exception=$Failure.Exception
        if ($null -ne $Failure.InvocationInfo) { $detail.script_line=[int]$Failure.InvocationInfo.ScriptLineNumber }
    }
    for ($depth=0; $null -ne $exception -and $depth -lt 8; $depth++) {
        $detail.exception_types += $exception.GetType().FullName
        if ($exception -is [ComponentModel.Win32Exception]) {
            $detail.win32_error=[int]$exception.NativeErrorCode
            $detail.code='CANONICAL_NATIVE_FAILURE'
        }
        if ($exception.Data.Contains('canonical_api') -and
            [string]$exception.Data['canonical_api'] -cmatch '^[A-Za-z0-9_.:]{1,80}$') {
            $detail.api=[string]$exception.Data['canonical_api']
        }
        if($exception.Data.Contains('canonical_code') -and [string]$exception.Data['canonical_code'] -cmatch '^(?:CONTAINER|CANONICAL|CODE)_[A-Z_]{1,100}$'){$detail.code=[string]$exception.Data['canonical_code']}
        $message=[string]$exception.Message
        if ($message -cmatch '^(?:CONTAINER|CANONICAL|CODE)_[A-Z_]{1,100}$') { $detail.code=$message }
        elseif ($message -cmatch '\((CONTAINER_(?:OPERATOR|WRITER|PLACEMENT)_[A-Z_]{1,80})\)') { $detail.code=$Matches[1] }
        $exception=$exception.InnerException
    }
    if (Get-Command -Name Get-InstallationFailureDetails -ErrorAction SilentlyContinue) {
        $preserved = Get-InstallationFailureDetails $Failure
        $detail['exception_chain']=$preserved.exception_chain
        $detail['script_file']=$preserved.script_file
    }
    return $detail
}
function Initialize-CanonicalUserProcessApi {
    if ('ContainerAuditCanonicalUserProcess' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public static class ContainerAuditCanonicalUserProcess {
    public sealed class Security { public string sid; public int session_id; public bool elevated; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct Startup {
        public int cb; public string reserved, desktop, title;
        public int x,y,cx,cy,xChars,yChars,fill,flags; public short show,reservedBytes;
        public IntPtr reserved2,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr process,thread; public int pid,tid; }
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr info,int length,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token,uint access,IntPtr attributes,int level,int type,out IntPtr copy);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool CreateProcessWithTokenW(IntPtr token,uint logon,string application,StringBuilder command,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo process);
    [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr environment,IntPtr token,bool inherit);
    [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out int pid);
    static void Check(bool success,string call) {
        if (success) return;
        int error=Marshal.GetLastWin32Error();
        Win32Exception failure=new Win32Exception(error,call);
        failure.Data["canonical_api"]=call;
        throw failure;
    }
    static int Integer(IntPtr token,int kind) {
        IntPtr data=Marshal.AllocHGlobal(4);
        try { int needed; Check(GetTokenInformation(token,kind,data,4,out needed),"GetTokenInformation:"+kind); return Marshal.ReadInt32(data); }
        finally { Marshal.FreeHGlobal(data); }
    }
    static Security Inspect(IntPtr token) {
        using (WindowsIdentity identity=new WindowsIdentity(token)) {
            return new Security {sid=identity.User.Value,session_id=Integer(token,12),elevated=Integer(token,20)!=0};
        }
    }
    public static Security Read(int pid) {
        using (Process process=Process.GetProcessById(pid)) {
            IntPtr token; Check(OpenProcessToken(process.Handle,8,out token),"OpenProcessToken:read");
            try { return Inspect(token); } finally { CloseHandle(token); }
        }
    }
    static IntPtr OverrideEnvironment(IntPtr source,string[] names,string[] values) {
        if(names==null||values==null||names.Length!=values.Length) throw new InvalidOperationException("Normal-user environment override shape differs.");
        string[] allowed={"CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN","CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID","CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID","CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID","CONTAINER_AUDIT_DATA_ROOT"};
        var selected=new System.Collections.Generic.Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        for(int n=0;n<names.Length;n++) {
            if(Array.IndexOf(allowed,names[n])<0||values[n]==null||values[n].IndexOf('\0')>=0||selected.ContainsKey(names[n])) throw new InvalidOperationException("Normal-user environment override is unsupported.");
            selected.Add(names[n],values[n]);
        }
        var entries=new System.Collections.Generic.List<string>();int offset=0;
        while(true) {
            string entry=Marshal.PtrToStringUni(IntPtr.Add(source,offset*2));if(entry.Length==0)break;
            offset+=entry.Length+1;if(offset>1048576)throw new InvalidOperationException("Normal-user environment block is oversized.");
            int separator=entry.IndexOf('=',entry.StartsWith("=")?1:0);
            if(separator<1)throw new InvalidOperationException("Normal-user environment block is malformed.");
            if(!selected.ContainsKey(entry.Substring(0,separator)))entries.Add(entry);
        }
        foreach(var pair in selected)if(pair.Value.Length>0)entries.Add(pair.Key+"="+pair.Value);
        entries.Sort(StringComparer.OrdinalIgnoreCase);
        return Marshal.StringToHGlobalUni(String.Join("\0",entries.ToArray())+"\0\0");
    }
    public static int StartLimited(string command,string sid,int session) {
        return StartLimitedWithOverrides(command,sid,session,new string[0],new string[0]);
    }
    public static int StartLimitedWithOverrides(string command,string sid,int session,string[] names,string[] values) {
        IntPtr shell=GetShellWindow(); int shellPid;
        if (shell==IntPtr.Zero || GetWindowThreadProcessId(shell,out shellPid)==0)
            throw new InvalidOperationException("Canonical interactive shell is unavailable.");
        using (Process shellProcess=Process.GetProcessById(shellPid)) {
            IntPtr token; Check(OpenProcessToken(shellProcess.Handle,10,out token),"OpenProcessToken:shell");
            IntPtr primary=IntPtr.Zero,environment=IntPtr.Zero,overridden=IntPtr.Zero;
            try {
                Security security=Inspect(token);
                if (security.elevated || security.sid!=sid || security.session_id!=session || session<=0)
                    throw new InvalidOperationException("Canonical interactive shell security differs.");
                // Explicit primary-token rights proven by the lab launch (0x18B).
                Check(DuplicateTokenEx(token,0x18B,IntPtr.Zero,2,1,out primary),"DuplicateTokenEx:primary");
                security=Inspect(primary);
                if (security.elevated || security.sid!=sid || security.session_id!=session)
                    throw new InvalidOperationException("Canonical normal-user token differs.");
                Check(CreateEnvironmentBlock(out environment,primary,false),"CreateEnvironmentBlock");
                if(names.Length>0)overridden=OverrideEnvironment(environment,names,values);
                Startup startup=new Startup(); startup.cb=Marshal.SizeOf(typeof(Startup)); startup.desktop="winsta0\\default";
                ProcessInfo child;
                Check(CreateProcessWithTokenW(primary,0,null,new StringBuilder(command),0x08000400,overridden!=IntPtr.Zero?overridden:environment,null,ref startup,out child),"CreateProcessWithTokenW");
                try { return child.pid; } finally { CloseHandle(child.thread); CloseHandle(child.process); }
            } finally {
                if (environment!=IntPtr.Zero) DestroyEnvironmentBlock(environment);
                if (overridden!=IntPtr.Zero) Marshal.FreeHGlobal(overridden);
                if (primary!=IntPtr.Zero) CloseHandle(primary);
                CloseHandle(token);
            }
        }
    }
}
'@
}
function Get-CanonicalRelaySecurity([int]$ProcessId) {
    return Get-BootstrapRelaySecurity $ProcessId
}
function Start-CanonicalLimitedRelay([string]$Line, [string]$UserSid, [int]$SessionId) {
    Initialize-CanonicalUserProcessApi
    return [ContainerAuditCanonicalUserProcess]::StartLimited($Line, $UserSid, $SessionId)
}
function StartRaw([string]$Line) {
    $caller = Get-CanonicalOperatorSecurity
    if ([int]$caller.session_id -le 0) { throw 'Canonical relay requires an interactive user session.' }
    if ([bool]$caller.elevated) {
        # Reuse the same user's existing desktop token. Never fall back to the
        # installer token, another account, credentials, or a scheduled task.
        $newPid = Start-CanonicalLimitedRelay $Line ([string]$caller.sid) ([int]$caller.session_id)
    }
    else {
        $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$Line}
        if ([uint32]$created.ReturnValue -ne 0) { throw 'Rollback process start failed.' }
        $newPid = [int]$created.ProcessId
    }
    $bootstrapLaunch=$Line -cmatch ' --bootstrap --role relay -- --container-audit-user-relay(?: --data-root .+)?$'
    if(-not $bootstrapLaunch) {
        $security = Get-CanonicalRelaySecurity $newPid
        if ([bool]$security.elevated -or [string]$security.sid -cne [string]$caller.sid -or
            [int]$security.session_id -ne [int]$caller.session_id) {
            throw 'Canonical relay normal-user security readback failed.'
        }
        Write-InstallationEvidenceEvent ([ordered]@{event='DETACHED_RELAY_LAUNCH';pid=$newPid;sid=$security.sid;session=$security.session_id;elevated=$security.elevated;stream_disposition='NOT_ATTACHED_PYTHONW';installer_pipe=$false;runtime_status_path=$relayPath})
    }else{
        # The admitted primary token is checked in StartLimited. A bootstrap
        # may already have exited; only the resident child is post-start proof.
        Write-InstallationEvidenceEvent ([ordered]@{event='DETACHED_BOOTSTRAP_REQUEST';launcher_pid=$newPid;resident_security_readback='PENDING';stream_disposition='NOT_ATTACHED_PYTHONW';installer_pipe=$false;runtime_status_path=$relayPath})
    }
    return [int]$newPid
}
function Read-CanonicalHelperArtifact($Binding,[string]$Leaf,[string]$Event) {
    if ([string]$Binding.status -cnotin @('BOUND_DIRECT_CHILD','BOUND_ELEVATED_CHILD') -or
        [string]$Leaf -cnotin @('replacement-receipt.json','restore-evidence.json','reused-evidence.json')) {
        throw 'Canonical helper artifact binding is absent.'
    }
    $root=Full ([string]$Binding.stage_evidence_root) 'bound helper evidence root'
    $run=Split-Path -Parent $root
    if (-not (Same (Split-Path -Parent $run) (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence')) -or
        [IO.Path]::GetFileName($run) -cnotmatch '^run-[0-9a-f]{32}$') {
        throw 'Canonical helper artifact protected run differs.'
    }
    Assert-InstallationEvidenceProtectedPath $run
    Assert-InstallationEvidenceProtectedPath $root
    $path=Join-Path $root $Leaf
    $journal=Join-Path $root 'stages.jsonl'
    foreach($file in @($path,$journal)) {
        Assert-BootstrapNoReparsePoint $file 'bound helper artifact' -PathOnly
        Assert-InstallationEvidenceProtectedPath $file
        if ((Get-Item -LiteralPath $file).Length -gt 1048576) {throw 'Canonical helper artifact is oversized.'}
    }
    $records=@(Get-Content -LiteralPath $journal -Encoding UTF8 | ForEach-Object {$_|ConvertFrom-Json} |
        Where-Object {[string]$_.event -ceq $Event})
    if ($records.Count -ne 1 -or -not (Same ([string]$records[0].path) $path) -or
        [string]$records[0].sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Sha $path) -cne [string]$records[0].sha256) {
        throw 'Canonical helper artifact journal/hash differs.'
    }
    return $path
}

function Read-CanonicalReusedPlacementEvidence($Binding,[string]$Source,[string]$Root,$Manifest,[string]$TransactionId) {
    $path=Read-CanonicalHelperArtifact $Binding 'reused-evidence.json' 'REUSED_EVIDENCE_READY'
    $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    $fields=@('schema','status','app_id','run_id','transaction_id','evidence_run_id','helper_process_id','evidence_root',
        'source_root','install_root','source_commit','helper_sha256','source_manifest_sha256','installed_manifest_sha256',
        'source_inventory_sha256','installed_inventory_sha256','writer_inventory_sha256','writer_inventory_contract_sha256',
        'source_aggregate_sha256','installed_aggregate_sha256','code_replaced','identity_or_credential_copied')
    if(-not(Test-WriterSessionContractExactPropertySet $record $fields) -or
        -not(Test-WriterSessionContractExactStringProperties $record @($fields|Where-Object {$_ -cnotin @('helper_process_id','code_replaced','identity_or_credential_copied')})) -or
        -not(Test-BootstrapJsonInteger $record.helper_process_id) -or $record.helper_process_id -le 0 -or
        $record.helper_process_id -ne $Binding.helper_process_id -or $TransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$record.schema -cne 'container-audit-reused-placement-v1' -or [string]$record.status -cne 'REUSED_VERIFIED' -or
        [string]$record.app_id -cne 'container_audit' -or [string]$record.run_id -cne $TransactionId -or
        [string]$record.transaction_id -cne $TransactionId -or
        [string]$record.evidence_run_id -cne [IO.Path]::GetFileName((Split-Path -Parent ([string]$Binding.stage_evidence_root))) -or
        -not(Same ([string]$record.evidence_root) ([string]$Binding.stage_evidence_root)) -or
        -not(Same ([string]$record.source_root) $Source) -or -not(Same ([string]$record.install_root) $Root) -or
        [string]$record.source_commit -cne [string]$Manifest.source_commit -or
        [string]$record.helper_sha256 -cne [string]$Manifest.helper_sha256 -or
        [string]$record.writer_inventory_sha256 -cne [string]$Manifest.writer_sink_inventory_sha256 -or
        [string]$record.writer_inventory_contract_sha256 -cne [string]$Manifest.writer_sink_inventory_contract_sha256 -or
        $record.code_replaced -isnot [bool] -or $record.code_replaced -or
        $record.identity_or_credential_copied -isnot [bool] -or $record.identity_or_credential_copied){throw 'REUSED evidence binding differs.'}
    $expected=@{source_manifest_sha256=Sha (Join-Path $Source 'portable-manifest.json');installed_manifest_sha256=Sha (Join-Path $Root 'portable-manifest.json');
        source_inventory_sha256=Sha (Join-Path $Source 'tools\container_writer_sink_inventory.json');
        installed_inventory_sha256=Sha (Join-Path $Root 'tools\container_writer_sink_inventory.json');
        source_aggregate_sha256=Get-InventoryAggregate @(Get-CodeInventory $Source);
        installed_aggregate_sha256=Get-InventoryAggregate @(Get-CodeInventory $Root)}
    foreach($field in $expected.Keys){
        if($record.$field -isnot [string] -or $record.$field -cnotmatch '^[0-9a-f]{64}$' -or $record.$field -cne $expected[$field]){throw 'REUSED evidence identity differs.'}
    }
    if($record.source_manifest_sha256 -cne $record.installed_manifest_sha256 -or
        $record.source_inventory_sha256 -cne $record.installed_inventory_sha256 -or
        $record.source_aggregate_sha256 -cne $record.installed_aggregate_sha256 -or
        (Test-Path -LiteralPath (Join-Path ([string]$Binding.stage_evidence_root) 'replacement-receipt.json'))){throw 'REUSED evidence is not a no-op.'}
    return [pscustomobject]@{path=$path;sha256=Sha $path;record=$record}
}

function Read-CanonicalRollbackContinuation([string]$InstallRoot,[string]$LocalAppDataRoot,[string]$Sid) {
    $store=Join-Path (Get-InstallationEvidenceControlRoot) 'rollback-continuations'
    if (-not (Test-Path -LiteralPath $store -PathType Container)) {return $null}
    Assert-BootstrapNoReparsePoint $store 'rollback continuation store' -PathOnly
    Assert-InstallationEvidenceProtectedPath $store
    $directories=@(Get-ChildItem -Force -LiteralPath $store -Directory)
    $found=@()
    foreach($directory in $directories) {
        if ($directory.Name -cnotmatch '^[0-9a-f]{32}$') {throw 'Rollback continuation directory differs.'}
        Assert-BootstrapNoReparsePoint $directory.FullName 'rollback continuation directory' -PathOnly
        Assert-InstallationEvidenceProtectedPath $directory.FullName
        $path=Join-Path $directory.FullName 'continuation-journal.json'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'Rollback continuation journal is absent.'}
        Assert-BootstrapNoReparsePoint $path 'rollback continuation journal' -PathOnly
        Assert-InstallationEvidenceProtectedPath $path
        if ((Get-Item -LiteralPath $path).Length -gt 131072) {throw 'Rollback continuation journal is oversized.'}
        $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
        $fields=@('schema','event','install_root','operator_sid','operator_local_appdata_root','owner_process_id','owner_started_at_utc',
            'session_id','attempt_id','orchestrator_sha256','writer_contract_sha256','source_manifest_sha256','receipt_path','receipt_binding_path',
            'receipt_sha256','old_manifest_sha256','new_manifest_sha256','transaction_id','preimage','relay_count','original_relays','runtime_preimage_binding','original_audit_sha256','secret_values_recorded')
        if (-not (Test-ExactPropertySet $record $fields) -or
            [string]$record.schema -cne 'container-audit-rollback-continuation-v1' -or [string]$record.event -cne 'ROLLBACK_CONTINUATION' -or
            [string]$record.transaction_id -cne $directory.Name -or
            -not (Same ([string]$record.install_root) $InstallRoot) -or -not (Same ([string]$record.operator_local_appdata_root) $LocalAppDataRoot) -or
            [string]$record.operator_sid -cne $Sid -or $record.secret_values_recorded -isnot [bool] -or $record.secret_values_recorded -or
            -not (Test-JsonPositiveInt32 $record.owner_process_id) -or -not (Test-JsonInteger $record.relay_count) -or $record.relay_count -notin @(0,1) -or
            @( $record.original_relays ).Count -ne [int]$record.relay_count -or
            [string]$record.runtime_preimage_binding.status -cne 'PASS' -or
            [int]$record.runtime_preimage_binding.relay_count -ne [int]$record.relay_count -or
            -not (Test-ExactPropertySet $record.preimage @('exists','kind','data')) -or $record.preimage.exists -isnot [bool] -or
            $record.preimage.kind -isnot [string] -or $record.preimage.data -isnot [string]) {throw 'Rollback continuation journal binding differs.'}
        foreach($name in @('orchestrator_sha256','writer_contract_sha256','source_manifest_sha256','receipt_sha256','old_manifest_sha256','new_manifest_sha256','original_audit_sha256')) {
            if ($record.$name -isnot [string] -or [string]$record.$name -cnotmatch '^[0-9a-f]{64}$') {throw 'Rollback continuation hash is invalid.'}
        }
        foreach($name in @('session_id','attempt_id')) {if ([string]$record.$name -cnotmatch '^[0-9a-f]{32}$') {throw 'Rollback continuation authority tuple is invalid.'}}
        [void](ConvertTo-ContainerWriterFenceUtc ([string]$record.owner_started_at_utc))
        $physical=Join-Path $directory.FullName 'replacement-receipt.json'
        if (-not (Same ([string]$record.receipt_path) $physical)) {throw 'Rollback continuation receipt path differs.'}
        Assert-InstallationEvidenceProtectedPath $physical
        $receipt=Read-BootstrapReplacementReceipt $physical ([string]$record.receipt_sha256)
        $originalRoot=Split-Path -Parent ([string]$record.receipt_binding_path)
        $originalRun=Split-Path -Parent $originalRoot
        if (-not (Same ([string]$receipt.receipt_path) ([string]$record.receipt_binding_path)) -or
            [IO.Path]::GetFileName([string]$record.receipt_binding_path) -cne 'replacement-receipt.json' -or
            [IO.Path]::GetFileName($originalRun) -cnotmatch '^run-[0-9a-f]{32}$' -or
            -not (Same (Split-Path -Parent $originalRun) (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence')) -or
            [string]$record.old_manifest_sha256 -cne [string]$receipt.old.manifest_sha256 -or
            [string]$record.new_manifest_sha256 -cne [string]$receipt.new.manifest_sha256 -or
            [string]$record.transaction_id -cne [string]$receipt.transaction_id) {throw 'Rollback continuation manifests or original path differ.'}
        $completedPath=Join-Path $directory.FullName 'continuation-completed.json'
        if (Test-Path -LiteralPath $completedPath) {
            Assert-BootstrapNoReparsePoint $completedPath 'rollback completion journal' -PathOnly
            Assert-InstallationEvidenceProtectedPath $completedPath
            if ((Get-Item -LiteralPath $completedPath).Length -gt 131072) {throw 'Rollback completion journal is oversized.'}
            $completed=Get-Content -LiteralPath $completedPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
            if (-not (Test-ExactPropertySet $completed @('schema','status','journal_sha256','receipt_sha256','old_manifest_sha256','new_manifest_sha256','audit_sha256','completed_at_utc','secret_values_recorded')) -or
                [string]$completed.schema -cne 'container-audit-rollback-completed-v1' -or [string]$completed.status -cne 'COMPLETE' -or
                [string]$completed.journal_sha256 -cne (Sha $path) -or [string]$completed.receipt_sha256 -cne [string]$record.receipt_sha256 -or
                [string]$completed.old_manifest_sha256 -cne [string]$record.old_manifest_sha256 -or [string]$completed.new_manifest_sha256 -cne [string]$record.new_manifest_sha256 -or
                [string]$completed.audit_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $completed.secret_values_recorded -isnot [bool] -or $completed.secret_values_recorded) {throw 'Rollback completion journal differs.'}
            [void](ConvertTo-ContainerWriterFenceUtc ([string]$completed.completed_at_utc))
            continue
        }
        $currentManifest=Sha (Join-Path $InstallRoot 'portable-manifest.json')
        if ($currentManifest -cnotin @([string]$record.old_manifest_sha256,[string]$record.new_manifest_sha256)) {throw 'Rollback continuation current manifest differs.'}
        if ([string]$record.source_manifest_sha256 -cne $sourceManifestSha256 -or [string]$record.new_manifest_sha256 -cne $sourceManifestSha256 -or
            [string]$record.orchestrator_sha256 -cne (Sha (Join-Path $source 'INSTALL_CANONICAL_PORTABLE.ps1'))) {throw 'Rollback continuation requires its exact successor packet.'}
        Assert-BootstrapRollbackOwnerExited ([int]$record.owner_process_id) ([string]$record.owner_started_at_utc)
        $receipt=ReadReplacementReceipt $physical ([string]$record.transaction_id) $InstallRoot $sourceManifest $sourceManifestSha256 $sourceHelperSha256 $sourceIntegrityHelperSha256 ([string]$record.receipt_binding_path)
        if ($receipt.PSObject.Properties['startup_update_preimage']) {
            $preimageDirectory=[string]$receipt.startup_update_preimage
            Assert-BootstrapNoReparsePoint $preimageDirectory 'rollback startup preimage'
            Assert-InstallationEvidenceProtectedPath $preimageDirectory
            $saved=Get-Content -LiteralPath (Join-Path $preimageDirectory 'preimage.json') -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
            if ([string]$saved.schema -cne 'container-audit-startup-update-install-preimage-v1' -or
                -not (Same ([string]$saved.root) $InstallRoot) -or [string]$saved.operator_sid -cne $Sid -or
                (@($saved.files|ForEach-Object {[string]$_.name}) -join ',') -cne 'policy.json,active.json,transition.json' -or
                $saved.task.exists -isnot [bool] -or ($saved.task.exists -and -not $receipt.PSObject.Properties['active_version'])) {throw 'Rollback continuation startup preimage differs.'}
            foreach($item in @($saved.files)) {
                if ($item.exists -isnot [bool] -or ($item.exists -and
                    ([string]$item.sha256 -cnotmatch '^[0-9a-f]{64}$' -or (Sha (Join-Path $preimageDirectory ([string]$item.name))) -cne [string]$item.sha256))) {throw 'Rollback continuation startup bytes differ.'}
            }
        }
        $state=Get-BootstrapVerifiedReplacementRestoreState $receipt ([string]$record.receipt_binding_path) $InstallRoot 'container_audit' ([string]$record.transaction_id) $sourceHelperSha256
        if ([string]$state.status -cnotin @('PENDING','RESTORED')) {throw 'Rollback continuation current tree is not verified.'}
        $record|Add-Member -NotePropertyName record_path -NotePropertyValue $path
        $record|Add-Member -NotePropertyName record_sha256 -NotePropertyValue (Sha $path)
        $record|Add-Member -NotePropertyName state -NotePropertyValue ([string]$state.status)
        $found+=@($record)
    }
    if ($found.Count -gt 1) {throw 'Rollback continuation selection is ambiguous.'}
    if ($found.Count) {return $found[0]}
    return $null
}

function Write-CanonicalRollbackContinuation {
    $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
        '-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,
        '-ElevationLogPath',($elevationLogPath+'.continuation'),'-RecordRollbackContinuation',
        '-RollbackAuditPath',$auditPath,'-RollbackAuditSha256',(Sha $auditPath),
        '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
        '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
        '-WriterFenceHelperPath',$writerFenceHelperPath,'-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
        '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,'-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
        '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,'-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken)
    $child=Invoke-InstallationEvidenceChild 'record-rollback-continuation' $winps $args
    if ($child.ExitCode -ne 0) {throw 'Protected rollback continuation was not recorded.'}
    $path=Join-Path (Join-Path (Join-Path (Get-InstallationEvidenceControlRoot) 'rollback-continuations') $replacementTransactionId) 'continuation-journal.json'
    Assert-InstallationEvidenceProtectedPath $path
    $Script:CanonicalRollbackContinuationCreated=[pscustomobject]@{record_path=$path;record_sha256=(Sha $path)}
}

function Complete-CanonicalRollbackContinuation($Record) {
    $residentsBefore=@(Relays)
    $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
        '-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,
        '-ElevationLogPath',($elevationLogPath+'.continuation-complete'),'-CompleteRollbackContinuation',
        '-ContinuationReleaseAuthorizationPath',$canonicalWriterFenceLastReleaseAuthorizationPath,'-ContinuationReleaseAuthorizationSha256',$canonicalWriterFenceLastReleaseAuthorizationSha256,
        '-ContinuationOwnerProcessId',$PID,'-ContinuationOwnerStartedAtUtc',((Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')),
        '-RollbackAuditPath',$auditPath,'-RollbackAuditSha256',(Sha $auditPath),
        '-RollbackContinuationPath',([string]$Record.record_path),'-RollbackContinuationSha256',([string]$Record.record_sha256),
        '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),'-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
        '-WriterFenceHelperPath',$writerFenceHelperPath,'-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
        '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,'-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
        '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,'-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken)
    if($testMode){$args+='-AllowNoncanonicalLayoutForTest'}
    $child=Invoke-InstallationEvidenceChild 'complete-rollback-continuation' $winps $args
    if ($child.ExitCode -ne 0) {throw 'Protected rollback completion was not recorded.'}
    $residentsAfter=@(Assert-RollbackRelayPreimage -ExpectedRelays $old)
    if($residentsBefore.Count -ne $residentsAfter.Count){throw 'Rollback completion changed the resident count.'}
    if($residentsBefore.Count -eq 1 -and [int]$residentsBefore[0].ProcessId -ne [int]$residentsAfter[0].ProcessId){throw 'Rollback completion changed the resident process.'}
}

function Enter-CanonicalRollbackContinuationClaim($Record) {
    $tuple=if($continuationPriorFence){(Read-BootstrapRollbackContinuationAuthority $Record ([string]$Record.record_path) ([string]$Record.record_sha256) $continuationPriorFence).tuple}else{[pscustomobject]@{session_id=$Record.session_id;attempt_id=$Record.attempt_id;orchestrator_sha256=$Record.orchestrator_sha256;replacement_transaction_id=$Record.transaction_id;writer_contract_sha256=$Record.writer_contract_sha256}}
    return Enter-ContainerWriterSessionAuthority -SessionId ([string]$tuple.session_id) -AttemptId ([string]$tuple.attempt_id) `
        -OrchestratorSha256 ([string]$tuple.orchestrator_sha256) -ReplacementTransactionId ([string]$tuple.replacement_transaction_id) -WriterContractSha256 ([string]$tuple.writer_contract_sha256)
}
function Write-CanonicalRollbackContinuationAuthority($Record) {
    $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
        '-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,'-ElevationLogPath',($elevationLogPath+'.authority-link'),
        '-RecordRollbackContinuationAuthority','-ContinuationOwnerProcessId',$PID,'-ContinuationOwnerStartedAtUtc',((Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')),
        '-RollbackContinuationPath',([string]$Record.record_path),'-RollbackContinuationSha256',([string]$Record.record_sha256),
        '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),'-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
        '-WriterFenceHelperPath',$writerFenceHelperPath,'-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
        '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,'-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
        '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId)
    if($testMode){$args+='-AllowNoncanonicalLayoutForTest'}
    $child=Invoke-InstallationEvidenceChild 'record-rollback-authority-link' $winps $args
    if($child.ExitCode -ne 0){throw 'Protected rollback authority linkage was not recorded.'}
    $path=Join-Path (Split-Path -Parent ([string]$Record.record_path)) ('authority-'+$Script:CanonicalWriterFenceAttemptId+'.json')
    Assert-InstallationEvidenceProtectedPath $path
    return [pscustomobject]@{path=$path;sha256=Sha $path}
}

function Exit-CanonicalRollbackContinuationClaim($Claim) {Exit-ContainerWriterSessionAuthority $Claim}

function ReadReplacementReceipt(
    [string]$Path,
    [string]$ExpectedTransactionId,
    [string]$ExpectedInstallRoot,
    $ExpectedSourceManifest,
    [string]$ExpectedManifestSha256,
    [string]$ExpectedHelperSha256,
    [string]$ExpectedIntegrityHelperSha256,
    [string]$ExpectedReceiptBindingPath=''
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Verified replacement receipt is absent.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt 131072) {
        throw 'Verified replacement receipt size is invalid.'
    }
    try { $receipt = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'Verified replacement receipt JSON is invalid.' }
    $top = @(
        'schema_version','status','app_id','transaction_id','created_at','helper_sha256',
        'integrity_helper_sha256','receipt_path','install_root','install_parent',
        'rollback_root','failed_root','parent_acl','old','new','identity_or_credential_copied'
    )
    $topStrings = @(
        'schema_version','status','app_id','transaction_id','created_at','helper_sha256',
        'integrity_helper_sha256','receipt_path','install_root','install_parent',
        'rollback_root','failed_root'
    )
    if ($receipt.PSObject.Properties['startup_update_preimage'] -or
        $receipt.PSObject.Properties['startup_update_preimage_sha256']) {
        $top += @('startup_update_preimage','startup_update_preimage_sha256')
        $topStrings += @('startup_update_preimage','startup_update_preimage_sha256')
        if ([string]$receipt.startup_update_preimage_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            (Sha (Join-Path ([string]$receipt.startup_update_preimage) 'preimage.json')) -cne [string]$receipt.startup_update_preimage_sha256) {
            throw 'Verified replacement startup preimage differs.'
        }
    }
    if($receipt.PSObject.Properties['active_version']) {
        $top+='active_version'
        if(-not(Test-ExactPropertySet $receipt.active_version @('kind','from_sha','to_sha','from_root','to_root','from','control_after'))){throw 'Supported receipt selection fields differ.'}
        [void](Get-BootstrapSupportedVersionRestoreState $receipt $(if($ExpectedReceiptBindingPath){$ExpectedReceiptBindingPath}else{$Path}) $ExpectedInstallRoot 'container_audit' $ExpectedTransactionId $ExpectedHelperSha256)
    }
    $acl = @('owner_sid','access_rules_protected','sddl_sha256')
    $tree = @(
        'file_count','aggregate_sha256','integrity_sha256','manifest_sha256',
        'source_commit','source_tree','owner_sid','access_rules_protected',
        'acl_sddl_sha256','reparse_count'
    )
    $treeStrings = @(
        'aggregate_sha256','integrity_sha256','manifest_sha256','source_commit',
        'source_tree','owner_sid','acl_sddl_sha256'
    )
    if (
        -not (Test-ExactPropertySet $receipt $top) -or
        -not (Test-ExactStringProperties $receipt $topStrings) -or
        -not (Test-BootstrapAclPropertySet $receipt.parent_acl $acl) -or
        -not (Test-ExactStringProperties $receipt.parent_acl @('owner_sid','sddl_sha256')) -or
        -not ($receipt.parent_acl.access_rules_protected -is [bool]) -or
        -not (Test-BootstrapAclPropertySet $receipt.old $tree 'acl_sddl' 'acl_sddl_sha256') -or
        -not (Test-BootstrapAclPropertySet $receipt.new $tree 'acl_sddl' 'acl_sddl_sha256') -or
        -not (Test-ExactStringProperties $receipt.old $treeStrings) -or
        -not (Test-ExactStringProperties $receipt.new $treeStrings) -or
        -not ($receipt.old.access_rules_protected -is [bool]) -or
        -not ($receipt.new.access_rules_protected -is [bool]) -or
        -not (Test-JsonInteger $receipt.old.file_count) -or
        -not (Test-JsonInteger $receipt.new.file_count) -or
        [int64]$receipt.old.file_count -lt 0 -or
        [int64]$receipt.new.file_count -lt 0 -or
        -not (Test-JsonInteger $receipt.old.reparse_count) -or
        -not (Test-JsonInteger $receipt.new.reparse_count) -or
        [int64]$receipt.old.reparse_count -ne 0 -or
        [int64]$receipt.new.reparse_count -ne 0 -or
        -not ($receipt.identity_or_credential_copied -is [bool]) -or
        [string]$receipt.schema_version -cne 'container-audit-verified-replacement-v1' -or
        [string]$receipt.status -cne 'OLD_PRESERVED_NEW_VERIFIED' -or
        [string]$receipt.app_id -cne 'container_audit' -or
        [string]$receipt.transaction_id -cne $ExpectedTransactionId -or
        -not (Same ([string]$receipt.receipt_path) $(if($ExpectedReceiptBindingPath){$ExpectedReceiptBindingPath}else{$Path})) -or
        -not (Same ([string]$receipt.install_root) $ExpectedInstallRoot) -or
        [string]$receipt.helper_sha256 -cne $ExpectedHelperSha256 -or
        [string]$receipt.integrity_helper_sha256 -cne $ExpectedIntegrityHelperSha256 -or
        [string]$receipt.new.source_commit -cne [string]$ExpectedSourceManifest.source_commit -or
        [string]$receipt.new.source_tree -cne [string]$ExpectedSourceManifest.source_tree -or
        [string]$receipt.new.manifest_sha256 -cne $ExpectedManifestSha256 -or
        $receipt.identity_or_credential_copied
    ) { throw 'Verified replacement receipt contract readback failed.' }
    return $receipt
}
function ReadReplacementRestoreEvidence(
    [string]$Path,
    [string]$ExpectedTransactionId,
    [string]$ExpectedReceiptPath,
    [string]$ExpectedReceiptSha256,
    [string]$ExpectedInstallRoot
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Verified replacement restore evidence is absent.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt 131072) {
        throw 'Verified replacement restore evidence size is invalid.'
    }
    try { $evidence = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson }
    catch {
    Write-InstallationCaughtFailure $_
 throw 'Verified replacement restore evidence JSON is invalid.' }
    $top = @(
        'schema_version','status','action','app_id','transaction_id','receipt_path',
        'receipt_sha256','install_root','failed_new_root','prior_code_exact',
        'failed_new_preserved','identity_or_credential_copied','completed_at'
    )
    $strings = @(
        'schema_version','status','action','app_id','transaction_id','receipt_path',
        'receipt_sha256','install_root','failed_new_root','completed_at'
    )
    if (
        -not (Test-ExactPropertySet $evidence $top) -or
        -not (Test-ExactStringProperties $evidence $strings) -or
        -not ($evidence.prior_code_exact -is [bool]) -or
        -not ($evidence.failed_new_preserved -is [bool]) -or
        -not ($evidence.identity_or_credential_copied -is [bool]) -or
        [string]$evidence.schema_version -cne 'container-audit-verified-replacement-code-restore-v1' -or
        [string]$evidence.status -cne 'PASS' -or
        [string]$evidence.action -notin @('RESTORED','ALREADY_RESTORED') -or
        [string]$evidence.app_id -cne 'container_audit' -or
        [string]$evidence.transaction_id -cne $ExpectedTransactionId -or
        -not (Same ([string]$evidence.receipt_path) $ExpectedReceiptPath) -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        -not (Same ([string]$evidence.install_root) $ExpectedInstallRoot) -or
        -not $evidence.prior_code_exact -or
        -not $evidence.failed_new_preserved -or
        $evidence.identity_or_credential_copied
    ) { throw 'Verified replacement restore evidence contract readback failed.' }
    return $evidence
}

function UtcText([datetime]$Value) {
    if ($Value.Year -lt 2000) { return '' }
    return $Value.ToUniversalTime().ToString('o')
}
function ShaText([string]$Value) {
    $encoding = New-Object Text.UTF8Encoding($false)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash($encoding.GetBytes($Value)))).Replace('-', '').ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}
function Read-CanonicalReplacementRestore {
    $receipt = Read-BootstrapReplacementReceipt $restoreReceiptFull $RestoreReceiptSha256
    $receipt = ReadReplacementReceipt `
        -Path $restoreReceiptFull -ExpectedTransactionId ([string]$receipt.transaction_id) `
        -ExpectedInstallRoot $install -ExpectedSourceManifest $sourceManifest `
        -ExpectedManifestSha256 $sourceManifestSha256 -ExpectedHelperSha256 $sourceHelperSha256 `
        -ExpectedIntegrityHelperSha256 $sourceIntegrityHelperSha256 `
        -ExpectedReceiptBindingPath $(if($rollbackContinuation){[string]$rollbackContinuation.receipt_binding_path}else{''})
    if ((Sha $restoreReceiptFull) -cne $RestoreReceiptSha256) {
        throw 'Replacement receipt changed during canonical readback.'
    }
    $state = Get-BootstrapVerifiedReplacementRestoreState `
        -Receipt $receipt -ReceiptPath $(if($rollbackContinuation){[string]$rollbackContinuation.receipt_binding_path}else{$restoreReceiptFull}) -InstallRoot $install `
        -ExpectedAppId 'container_audit' -ExpectedTransactionId ([string]$receipt.transaction_id) `
        -ExpectedHelperSha256 $sourceHelperSha256
    if ([string]$state.status -cnotin @('PENDING','RESTORED')) {
        throw 'Canonical restore requires a verified current tree for normal runtime quiescence.'
    }
    if($receipt.PSObject.Properties['active_version']){$Script:supportedPlacement=$true;$Script:installedCodeRoot=[string]$receipt.active_version.to_root;$Script:supportedRestoreFromRoot=[string]$receipt.active_version.from_root}
    $oldRoot = if($receipt.PSObject.Properties['active_version']){[string]$receipt.active_version.from_root}elseif ([string]$state.status -ceq 'PENDING') { [string]$state.rollback_root } else { $install }
    $oldManifest = InstalledManifest $oldRoot $SkipSignatureValidationForTest
    $oldInventory = Assert-WriterSinkInventory `
        (Join-Path $oldRoot 'tools\container_writer_sink_inventory.json') `
        ([string]$oldManifest.writer_sink_inventory_sha256) `
        ([string]$oldManifest.writer_sink_inventory_contract_sha256)
    if ((Get-WriterInventorySemantics $oldInventory) -cne (Get-WriterInventorySemantics $sourceWriterInventory) -and
        -not (Test-ExactApprovedWriterTransition $sourceManifest $oldManifest $source)) {
        throw 'CODE_RESTORE_WRITER_SEMANTICS_DIFFER'
    }
    return [pscustomobject]@{
        receipt=$receipt
        state=[string]$state.status
        old_inventory_sha256=[string]$oldManifest.writer_sink_inventory_contract_sha256
    }
}
function FileObservation([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ exists=$false; path=$Path; bytes=0; mtime_utc=''; sha256='' }
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [ordered]@{
        exists=$true
        path=$Path
        bytes=[int64]$item.Length
        mtime_utc=$item.LastWriteTimeUtc.ToString('o')
        sha256=Sha $Path
    }
}
function SameFileObservation($Left, $Right) {
    return (
        [bool]$Left.exists -eq [bool]$Right.exists -and
        [string]$Left.path -ceq [string]$Right.path -and
        [int64]$Left.bytes -eq [int64]$Right.bytes -and
        [string]$Left.mtime_utc -ceq [string]$Right.mtime_utc -and
        [string]$Left.sha256 -ceq [string]$Right.sha256
    )
}
function Get-CanonicalWriterProcesses([string]$InstallRootValue) {
    $expected = Join-Path $InstallRootValue 'runtime\python.exe'
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $execute = [string]$_.ExecutablePath
        $command = [string]$_.CommandLine
        [IO.Path]::IsPathRooted($execute) -and
        (Same $execute $expected) -and
        $command.IndexOf('--container-audit-direct-sync-relay', [StringComparison]::Ordinal) -ge 0
    } | Select-Object ProcessId, ParentProcessId, ExecutablePath)
}
function Get-PrincipalSid([string]$UserId) {
    if ([string]::IsNullOrWhiteSpace($UserId)) { return '' }
    try {
        return ConvertTo-BootstrapPrincipalSid $UserId
    }
    catch {
    Write-InstallationCaughtFailure $_
 return '' }
}
function Get-CanonicalTaskProperty($Value, [string]$Name, $Default = $null) {
    if ($null -eq $Value) { return $Default }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}
function Get-CanonicalWriterBinding($Task) {
    $actions = @($Task.Actions)
    $triggers = @(Get-CanonicalTaskProperty $Task 'Triggers')
    $normalized = [ordered]@{
        task_name=[string]$Task.TaskName
        task_path=[string]$Task.TaskPath
        actions=@($actions | ForEach-Object {
            [ordered]@{
                execute=[string](Get-CanonicalTaskProperty $_ 'Execute' '')
                arguments=[string](Get-CanonicalTaskProperty $_ 'Arguments' '')
                working_directory=[string](Get-CanonicalTaskProperty $_ 'WorkingDirectory' '')
            }
        })
        principal=[ordered]@{
            user_id=[string]$Task.Principal.UserId
            logon_type=[string]$Task.Principal.LogonType
            run_level=[string]$Task.Principal.RunLevel
        }
        triggers=@($triggers | ForEach-Object {
            $class = Get-CanonicalTaskProperty $_ 'CimClass'
            $repetition = Get-CanonicalTaskProperty $_ 'Repetition'
            [ordered]@{
                type=[string](Get-CanonicalTaskProperty $class 'CimClassName' '')
                enabled=[bool](Get-CanonicalTaskProperty $_ 'Enabled' $false)
                start_boundary=[string](Get-CanonicalTaskProperty $_ 'StartBoundary' '')
                repetition_interval=[string](Get-CanonicalTaskProperty $repetition 'Interval' '')
                repetition_duration=[string](Get-CanonicalTaskProperty $repetition 'Duration' '')
                stop_at_duration_end=[bool](Get-CanonicalTaskProperty $repetition 'StopAtDurationEnd' $false)
            }
        })
        settings=[ordered]@{
            start_when_available=[bool]$Task.Settings.StartWhenAvailable
            multiple_instances=[string]$Task.Settings.MultipleInstances
            execution_time_limit=[string]$Task.Settings.ExecutionTimeLimit
            disallow_start_if_on_batteries=[bool]$Task.Settings.DisallowStartIfOnBatteries
            stop_if_going_on_batteries=[bool]$Task.Settings.StopIfGoingOnBatteries
        }
    }
    $json = $normalized | ConvertTo-Json -Depth 8 -Compress
    return [ordered]@{ value=$normalized; sha256=ShaText $json }
}
function Get-CanonicalOfficialLegacyRelayPreimage {
    $tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object {[string]$_.TaskName -ieq 'direct-sync-relay-container-audit'})
    if($tasks.Count -gt 1){throw 'NONCANONICAL_WRITER_ENABLED'}
    if($tasks.Count -eq 0){return $null}
    $task=$tasks[0]
    $actions=@($task.Actions)
    if($actions.Count -ne 1 -or [IO.Path]::GetFileName(([string]$actions[0].Execute).Trim('"')) -inotin @('wscript.exe','cmd.exe')){throw 'NONCANONICAL_WRITER_ENABLED'}
    $xml=Export-ScheduledTask -TaskName ([string]$task.TaskName) -TaskPath ([string]$task.TaskPath) -ErrorAction Stop
    $identity=Get-BootstrapOfficialLegacyRelayIdentity $task $xml
    if(-not $identity.matched){throw 'NONCANONICAL_WRITER_ENABLED'}
    $oldRoot='';$files=@()
    foreach($leaf in @('cmd','vbs')){
        $actionArguments=[string]$actions[0].Arguments
        $launcher=[regex]::Match($actionArguments,'(?:"(?<path>[^"\r\n]+\.(?:vbs|cmd))"|(?<path>\S+\.(?:vbs|cmd)))\s*$',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if(-not $launcher.Success){throw 'NONCANONICAL_WRITER_ENABLED'}
        $launcherPath=[Environment]::ExpandEnvironmentVariables($launcher.Groups['path'].Value)
        $path=[IO.Path]::ChangeExtension($launcherPath,$leaf)
        Assert-BootstrapNoReparsePoint $path 'official legacy launcher' -PathOnly
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'OFFICIAL_LEGACY_LAUNCHER_UNPROVEN'}
        $observation=FileObservation $path;$files+=,@{name=$leaf;exists=$observation.exists;bytes=$observation.bytes;sha256=$observation.sha256}
        if($leaf -ceq 'cmd' -and $observation.exists -and $observation.bytes -le 65536){
            $content=Get-Content -LiteralPath $path -Raw -Encoding UTF8
            $command=@($content -split '\r?\n'|Where-Object {$_ -match 'Container_Audit_DirectSync_Relay\.exe'})
            if($command.Count -eq 1){
                $match=[regex]::Match($command[0],'^\s*(?:"(?<exe>[^"]+Container_Audit_DirectSync_Relay\.exe)"|(?<exe>\S+Container_Audit_DirectSync_Relay\.exe))(?:\s|$)',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if($match.Success){$exe=[IO.Path]::GetFullPath($match.Groups['exe'].Value);$oldRoot=Split-Path -Parent $exe;$exeObservation=FileObservation $exe;$files+=,@{name='relay_exe';exists=$exeObservation.exists;bytes=$exeObservation.bytes;sha256=$exeObservation.sha256}}
            }
        }
    }
    return [pscustomobject]@{xml=[string]$xml;xml_sha256=(ShaText $xml);identity=$identity;enabled=[bool]$task.Settings.Enabled;task_name=[string]$task.TaskName;task_path=[string]$task.TaskPath;old_code_root=$oldRoot;files=$files}
}
function Get-CanonicalOfficialLegacyRelayAdmission([string]$ReportPath='') {
    # Read-only admission precedes protected-base preparation. An absent task
    # has no launcher requirement; a present task retains the exact identity
    # and existing launcher leaf/reparse/old-code-root observations.
    try { return (Get-CanonicalOfficialLegacyRelayPreimage) }
    catch {
        $originalFailure=$_
        $message=ConvertTo-KmtechRedactedSinkText -Text '옛 전송 예약 작업의 실행 연결을 확인하지 못해 설치를 변경하지 않았습니다. 작업과 실행 파일을 보존하고 관리자에게 지원 복구를 요청하세요.' -UserLine
        $failure=[InvalidOperationException]::new($message,$originalFailure.Exception)
        $failure.Data['original_error_record']=$originalFailure
        if($originalFailure.Exception.Message -ceq 'NONCANONICAL_WRITER_ENABLED') {
            $failure.Data['canonical_code']='NONCANONICAL_WRITER_ENABLED'
        } else {
            $failure.Data['canonical_code']='OFFICIAL_LEGACY_LAUNCHER_UNPROVEN'
        }
        if($ReportPath) {
            try {
                $reportFull=Full $ReportPath 'legacy admission report'
                Assert-BootstrapNoReparsePoint (Split-Path -Parent $reportFull) 'legacy admission report parent' -PathOnly
                if(Test-Path -LiteralPath $reportFull){
                    Assert-BootstrapNoReparsePoint $reportFull 'legacy admission report' -PathOnly
                    if(-not(Test-Path -LiteralPath $reportFull -PathType Leaf)){throw 'LEGACY_ADMISSION_REPORT_NOT_A_FILE'}
                }
                if(Test-Path -LiteralPath ($reportFull+'.tmp.'+$PID)){throw 'LEGACY_ADMISSION_REPORT_TEMP_PREEXISTS'}
                $reportPayload=ConvertTo-CanonicalAuditJson ([ordered]@{status='REJECTED_BEFORE_PREPARATION';code=[string]$failure.Data['canonical_code'];message=$message}) | ConvertFrom-Json
                Write-Utf8Json $reportFull $reportPayload
            } catch {
                $failure.Data['report_failure']=ConvertTo-KmtechRedactedSinkText -Text $_.Exception.Message -UserLine
            }
        }
        throw $failure
    }
}
function Save-CanonicalOfficialLegacyRelayPreimage($Before,[string]$Root) {
    Assert-InstallationEvidenceWriteRoot $Root
    # A task preimage may contain author/SID for restoration, never an env secret.
    Assert-InstallationMachineMetadataNoSecrets $Before.xml
    $path=Join-Path $Root 'official-v2.0.33-relay-preimage.xml'
    if(Test-Path -LiteralPath $path){throw 'OFFICIAL_LEGACY_PREIMAGE_ALREADY_EXISTS'}
    [IO.File]::WriteAllText($path,$Before.xml,[Text.UTF8Encoding]::new($false))
    Set-InstallationEvidenceAcl $path $operatorSid
    $record=[ordered]@{schema='container-audit-official-legacy-relay-preimage-v1';xml_path=$path;xml_sha256=(Sha $path);identity_sha256=[string]$Before.identity.sha256;enabled=[bool]$Before.enabled;task_name=[string]$Before.task_name;task_path=[string]$Before.task_path;old_code_root=[string]$Before.old_code_root;files=$Before.files}
    $recordPath=Join-Path $Root 'official-v2.0.33-relay-preimage.json'
    if(Test-Path -LiteralPath $recordPath){throw 'OFFICIAL_LEGACY_PREIMAGE_ALREADY_EXISTS'}
    $recordJson=$record|ConvertTo-Json -Depth 8 -Compress
    Assert-InstallationMachineMetadataNoSecrets $recordJson
    [IO.File]::WriteAllText($recordPath,$recordJson,[Text.UTF8Encoding]::new($false))
    Set-InstallationEvidenceAcl $recordPath $operatorSid
    return [pscustomobject]@{path=$recordPath;sha256=(Sha $recordPath);identity=$Before.identity;xml_sha256=[string]$record.xml_sha256}
}
function Get-CanonicalOfficialLegacyRelayRunningCount {
    # Observation only. Never signal a PID or an unrelated GUI.
    $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {
        [IO.Path]::GetFileName([string]$_.ExecutablePath) -ieq 'Container_Audit_DirectSync_Relay.exe' -and
        [string]$_.CommandLine -match '(?:^|\s)--worker-id\s+"?direct-sync-relay-container-audit"?(?:\s|$)'
    })
    $tasks=@(Get-ScheduledTask -TaskName 'direct-sync-relay-container-audit' -TaskPath '\' -ErrorAction Stop)
    if($tasks.Count -ne 1){throw 'OFFICIAL_LEGACY_RELAY_TASK_QUERY_UNKNOWN'}
    return $processes.Count+[int]([string]$tasks[0].State -ceq 'Running')
}
function Disable-CanonicalOfficialLegacyRelay($Before) {
    $live=Get-CanonicalOfficialLegacyRelayPreimage
    if($null -eq $live -or [string]$live.identity.sha256 -cne [string]$Before.identity.sha256){throw 'NONCANONICAL_WRITER_ENABLED'}
    [void](DisableAndStop-ContainerScheduledTaskUnderWriterFence -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -DelegationToken $Script:CanonicalWriterFenceDelegationToken -AuthorityLease $canonicalWriterFenceAuthority -TaskName $Before.task_name -TaskPath $Before.task_path)
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    do{$running=Get-CanonicalOfficialLegacyRelayRunningCount;if($running){Start-Sleep -Milliseconds 250}}while($running -and [DateTime]::UtcNow -lt $deadline)
    $after=Get-CanonicalOfficialLegacyRelayPreimage
    if($running -or $null -eq $after -or $after.enabled -or [string]$after.identity.sha256 -cne [string]$Before.identity.sha256){throw 'OFFICIAL_LEGACY_RELAY_QUIESCENCE_UNPROVEN'}
    return @{status='PROVEN_DISABLED_QUIESCENT';identity_sha256=[string]$after.identity.sha256;process_count=0}
}
function Restore-CanonicalOfficialLegacyRelay($Binding) {
    Assert-InstallationEvidenceProtectedPath $Binding.path
    if((Sha $Binding.path) -cne [string]$Binding.sha256 -or (Get-Item -LiteralPath $Binding.path).Length -gt 65536){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
    $record=Get-Content -LiteralPath $Binding.path -Raw -Encoding UTF8|ConvertFrom-Json
    if([string]$record.schema -cne 'container-audit-official-legacy-relay-preimage-v1' -or $record.enabled -isnot [bool] -or [string]$record.task_name -cne 'direct-sync-relay-container-audit' -or [string]$record.task_path -cne '\'){throw 'OFFICIAL_LEGACY_PREIMAGE_DIFFERS'}
    Assert-InstallationEvidenceProtectedPath $record.xml_path
    if((Sha $record.xml_path) -cne [string]$record.xml_sha256 -or (Get-Item -LiteralPath $record.xml_path).Length -gt 65536){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
    $xml=Get-Content -LiteralPath $record.xml_path -Raw -Encoding UTF8
    $task=[pscustomobject]@{TaskName=[string]$record.task_name;TaskPath=[string]$record.task_path}
    $identity=Get-BootstrapOfficialLegacyRelayIdentity $task $xml
    if(-not $identity.matched -or [string]$identity.sha256 -cne [string]$record.identity_sha256){throw 'NONCANONICAL_WRITER_ENABLED'}
    # G remains the original shared gate; no current-tree dependency.
    if([string]::IsNullOrWhiteSpace([string]$record.old_code_root) -or -not[IO.Path]::IsPathRooted([string]$record.old_code_root)){throw 'OFFICIAL_LEGACY_OLD_CODE_ROOT_UNPROVEN'}
    try{Assert-ContainerDataGenerationTarget -CandidateRoot ([string]$record.old_code_root) -TargetSid $operatorSid -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source}
    catch{Write-InstallationCaughtFailure $_;Write-Warning (ConvertTo-KmtechRedactedSinkText -Text ([string]('자료 판이 옛 판의 실행을 허용하지 않아 옛 전송 예약 작업을 되살리지 않았습니다. 자료와 복구 기록을 보존하고 관리자 지원 복구를 요청하세요.')) -UserLine);throw 'OFFICIAL_LEGACY_RELAY_G_BLOCKED'}
    if(@(Relays).Count -ne 0){throw 'OFFICIAL_LEGACY_RELAY_NEW_RUNTIME_NOT_QUIESCENT'}
    $live=Get-CanonicalOfficialLegacyRelayPreimage
    if($null -eq $live -or [string]$live.identity.sha256 -cne [string]$identity.sha256){throw 'NONCANONICAL_WRITER_ENABLED'}
    [void](Invoke-ContainerWriterFenceMutation -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -DelegationToken $Script:CanonicalWriterFenceDelegationToken -AuthorityLease $canonicalWriterFenceAuthority -Action {
        # Retained task + unchanged identity: toggle the existing credential-bearing
        # object without re-registering XML or reading/re-entering a password.
        if([bool]$record.enabled){Enable-ScheduledTask -TaskName ([string]$record.task_name) -TaskPath ([string]$record.task_path) -ErrorAction Stop|Out-Null}
        else{Disable-ScheduledTask -TaskName ([string]$record.task_name) -TaskPath ([string]$record.task_path) -ErrorAction Stop|Out-Null}
    })
    $after=Get-CanonicalOfficialLegacyRelayPreimage
    if($null -eq $after -or [bool]$after.enabled -ne [bool]$record.enabled -or [string]$after.identity.sha256 -cne [string]$identity.sha256){throw 'OFFICIAL_LEGACY_RELAY_RESTORE_READBACK_FAILED'}
    return @{status='PROVEN_PREIMAGE_RESTORED';identity_sha256=[string]$after.identity.sha256;xml_sha256=[string]$after.xml_sha256}
}

function Get-CanonicalOfficialLegacyRelayExpectedSet {
    return (Get-BootstrapOfficialLegacyRelayExpectedIdentitySet)
}
function Read-CanonicalOfficialLegacyRelayTransitionBinding($Binding,[string]$ExpectedIdentitySha256) {
    if($null -eq $Binding -or [string]$Binding.sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
    $path=[IO.Path]::GetFullPath([string]$Binding.path)
    Assert-InstallationEvidenceProtectedPath $path
    if((Get-Item -LiteralPath $path).Length -gt 65536 -or (Sha $path) -cne [string]$Binding.sha256){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
    $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if([string]$record.schema -cne 'container-audit-official-legacy-relay-preimage-v1' -or $record.enabled -isnot [bool] -or
        [string]$record.task_name -cne 'direct-sync-relay-container-audit' -or [string]$record.task_path -cne '\' -or
        [string]$record.xml_sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'OFFICIAL_LEGACY_PREIMAGE_DIFFERS'}
    Assert-InstallationEvidenceProtectedPath ([string]$record.xml_path)
    if((Get-Item -LiteralPath $record.xml_path).Length -gt 65536 -or (Sha $record.xml_path) -cne [string]$record.xml_sha256){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
    $xml=Get-Content -LiteralPath $record.xml_path -Raw -Encoding UTF8
    $identity=Get-BootstrapOfficialLegacyRelayIdentity ([pscustomobject]@{TaskName=$record.task_name;TaskPath=$record.task_path}) $xml
    if(-not $identity.matched -or [string]$identity.sha256 -cne [string]$record.identity_sha256 -or
        ($ExpectedIdentitySha256 -and [string]$identity.sha256 -cne $ExpectedIdentitySha256)){throw 'OFFICIAL_LEGACY_PREIMAGE_IDENTITY_DIFFERS'}
    if((Sha $path) -cne [string]$Binding.sha256 -or (Sha $record.xml_path) -cne [string]$record.xml_sha256){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
    return [pscustomobject]@{path=$path;sha256=[string]$Binding.sha256;identity_sha256=[string]$identity.sha256;durable=$true}
}
function Save-CanonicalOfficialLegacyRelayTransitionPointer($Binding,[switch]$Required) {
    # Extend the existing per-user installation result, never create a locator
    # store or scan installation evidence directories for a plausible preimage.
    if(-not $onboardingPath -or -not(Test-Path -LiteralPath $onboardingPath -PathType Leaf)){
        if($Required){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_REQUIRED'};return
    }
    Assert-BootstrapNoReparsePoint $onboardingPath 'official relay installation record' -PathOnly
    if((Get-Item -LiteralPath $onboardingPath).Length -gt 1048576){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_DIFFERS'}
    $priorSha=Sha $onboardingPath
    $report=Get-Content -LiteralPath $onboardingPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if([string]$report.status -cne 'READY' -or [string]$report.state_scope -cne 'current_user'){
        if($Required){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_DIFFERS'};return
    }
    $proof=Read-CanonicalOfficialLegacyRelayTransitionBinding $Binding ''
    $pointer=[ordered]@{schema='container-audit-official-legacy-relay-transition-pointer-v1';path=$proof.path;sha256=$proof.sha256;
        identity_sha256=$proof.identity_sha256;install_root=$install;operator_sid=$operatorSid}
    $report|Add-Member -MemberType NoteProperty -Name official_legacy_relay_transition -Value $pointer -Force
    $text=$report|ConvertTo-Json -Depth 20 -Compress
    Assert-InstallationMachineMetadataNoSecrets $text
    [void]($text|ConvertFrom-ContainerWriterFenceJson)
    $temporary=$onboardingPath+'.tmp.'+[Guid]::NewGuid().ToString('N')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text+"`n")
    [void](Invoke-ContainerWriterFenceMutation -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
        -AuthorityLease $canonicalWriterFenceAuthority -Action {
            if((Sha $onboardingPath) -cne $priorSha){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_CHANGED'}
            $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
            try{Invoke-ContainerAtomicReplace $temporary $onboardingPath -Mode WriteThrough}
            finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}}
        })
    $readback=Read-CanonicalOfficialLegacyRelayTransitionPointer
    if($null -eq $readback -or $readback.path -cne $proof.path -or $readback.sha256 -cne $proof.sha256){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_READBACK_DIFFERS'}
}
function Read-CanonicalOfficialLegacyRelayTransitionPointer {
    if(-not $onboardingPath -or -not(Test-Path -LiteralPath $onboardingPath -PathType Leaf)){return $null}
    Assert-BootstrapNoReparsePoint $onboardingPath 'official relay installation record' -PathOnly
    if((Get-Item -LiteralPath $onboardingPath).Length -gt 1048576){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_DIFFERS'}
    $priorSha=Sha $onboardingPath
    $report=Get-Content -LiteralPath $onboardingPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    $pointer=$report.official_legacy_relay_transition
    if($null -eq $pointer){return $null}
    if([string]$report.status -cne 'READY' -or [string]$report.state_scope -cne 'current_user' -or
        [string]$pointer.schema -cne 'container-audit-official-legacy-relay-transition-pointer-v1' -or
        [string]$pointer.operator_sid -cne $operatorSid -or -not(Same ([string]$pointer.install_root) $install) -or
        [string]$pointer.identity_sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_DIFFERS'}
    $proof=Read-CanonicalOfficialLegacyRelayTransitionBinding $pointer ([string]$pointer.identity_sha256)
    if((Sha $onboardingPath) -cne $priorSha){throw 'OFFICIAL_LEGACY_INSTALL_RECORD_CHANGED'}
    return $proof
}
function Get-CanonicalOfficialLegacyRelayWriters {
    param([string]$ComputerName,[string]$ProgramDataRoot,[string]$CurrentUser)
    # Local inspection only; callers cannot select another PC or principal.
    if($ComputerName -and $ComputerName -ine [Environment]::MachineName){throw 'OFFICIAL_LEGACY_REMOTE_CONTEXT_UNSUPPORTED'}
    if($ProgramDataRoot -and -not(Same $ProgramDataRoot ([Environment]::GetFolderPath('CommonApplicationData')))){throw 'OFFICIAL_LEGACY_PROGRAM_DATA_CONTEXT_DIFFERS'}
    if($CurrentUser){
        $currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if($CurrentUser -cne $currentSid){throw 'OFFICIAL_LEGACY_CURRENT_USER_CONTEXT_DIFFERS'}
    }
    $writers=@()
    $tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object {[string]$_.TaskName -ieq 'direct-sync-relay-container-audit'})
    if($tasks.Count -gt 1){throw 'OFFICIAL_LEGACY_NAME_CARDINALITY_UNKNOWN'}
    foreach($task in $tasks){
        $xml=Export-ScheduledTask -TaskName ([string]$task.TaskName) -TaskPath ([string]$task.TaskPath) -ErrorAction Stop
        $binding=if($onboardingPath){Read-CanonicalOfficialLegacyRelayTransitionPointer}else{$null}
        $writers+=,[pscustomobject]@{mechanism='scheduled_task';task_path=[string]$task.TaskPath;task_name=[string]$task.TaskName;xml=[string]$xml;observed_enabled=$task.Settings.Enabled;transition_record=$binding}
    }
    # No official public release creates HKCU Run relay persistence.
    # Existing canonical Run belongs to the canonical lifecycle, outside this set.
    return $writers
}
function Get-CanonicalOfficialLegacyRelayState {
    param($Writer,[object[]]$ExpectedIdentitySet,[string]$EvidenceRoot)
    if([string]$Writer.mechanism -ceq 'scheduled_task'){
        $task=[pscustomobject]@{TaskName=[string]$Writer.task_name;TaskPath=[string]$Writer.task_path}
        $identity=Get-BootstrapOfficialLegacyRelayIdentity $task $Writer.xml $ExpectedIdentitySet
        # Identity parser prohibits DTDs before this read-only settings extraction.
        $definition=[xml]$Writer.xml
        $enabledNode=$definition.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']")
        $observedProperty=$Writer.PSObject.Properties['observed_enabled']
        $hasObservation=($null -ne $observedProperty -and $observedProperty.Value -is [bool])
        $enabled=$null
        if($null -ne $enabledNode){
            $enabledValue=[string]$enabledNode.InnerText
            if($enabledValue -cin @('true','false')){
                $enabled=($enabledValue -ceq 'true')
                if($hasObservation -and $enabled -ne [bool]$observedProperty.Value){$identity.matched=$false;$identity.reason_code='TASK_ENABLED_OBSERVATION_DIFFERS'}
            }else{$identity.matched=$false;$identity.reason_code='TASK_ENABLED_STATE_UNKNOWN'}
        }elseif($hasObservation){
            # Guest exports omit Enabled. Use the separately observed scheduler
            # bool, never an XML default or a cast from null/unknown.
            $enabled=[bool]$observedProperty.Value
        }else{$identity.matched=$false;$identity.reason_code='TASK_ENABLED_STATE_UNKNOWN'}
        if(-not $hasObservation){$identity.matched=$false;$identity.reason_code='TASK_ENABLED_STATE_UNKNOWN';$enabled=$null}
    }elseif([string]$Writer.mechanism -ceq 'hkcu_run'){
        $identity=[pscustomobject]@{matched=$false;sha256='';entry_tag='';reason_code='PUBLIC_HISTORY_HAS_NO_HKCU_RUN_RELAY'}
        $enabled=[bool]$Writer.run.exists
    }else{throw 'OFFICIAL_LEGACY_MECHANISM_UNKNOWN'}
    $binding=if($null -ne $Writer.PSObject.Properties['transition_record']){$Writer.transition_record}else{$null}
    if($null -ne $binding){
        Assert-InstallationEvidenceProtectedPath $binding.path
        $durable=$null -ne $binding.PSObject.Properties['durable'] -and $binding.durable -is [bool] -and $binding.durable
        if($durable -and [string]$binding.identity_sha256 -cne [string]$identity.sha256){throw 'OFFICIAL_LEGACY_PREIMAGE_IDENTITY_DIFFERS'}
        if(-not $durable -and $EvidenceRoot -and -not ([IO.Path]::GetFullPath([string]$binding.path)).StartsWith(([IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'OFFICIAL_LEGACY_PREIMAGE_OUTSIDE_EVIDENCE'}
        if((Sha $binding.path) -cne [string]$binding.sha256){throw 'OFFICIAL_LEGACY_PREIMAGE_PIN_DIFFERS'}
        $binding=@{path=[string]$binding.path;sha256=[string]$binding.sha256}
    }
    return [pscustomobject]@{recognized=[bool]$identity.matched;entry_tag=[string]$identity.entry_tag;mechanism=[string]$Writer.mechanism;enabled=$enabled;full_fingerprint=[string]$identity.sha256;transition_record=$binding;reason_code=[string]$identity.reason_code}
}
function Invoke-CanonicalOfficialLegacyRelayTransition {
    param([object[]]$Writers,[object[]]$ExpectedIdentitySet,[ValidateSet('install','rollback')][string]$Mode,[bool]$GenerationAllowed)
    $audit=@();$states=@()
    if(@($Writers).Count -gt 1){throw 'OFFICIAL_LEGACY_NAME_CARDINALITY_UNKNOWN'}
    # Validate the whole input before changing even one writer.
    foreach($writer in $Writers){$state=Get-CanonicalOfficialLegacyRelayState $writer $ExpectedIdentitySet $installationEvidenceRoot;if(-not $state.recognized){throw 'NONCANONICAL_WRITER_ENABLED'}}
    foreach($writer in $Writers){
        $failure=$null
        try{
            if($Mode -ceq 'rollback' -and -not $GenerationAllowed){throw 'OFFICIAL_LEGACY_RELAY_G_BLOCKED'}
            if($writer.mechanism -ceq 'scheduled_task'){
                if($Mode -ceq 'install'){
                    $before=Get-CanonicalOfficialLegacyRelayPreimage
                    if($null -eq $writer.transition_record){$writer.transition_record=Save-CanonicalOfficialLegacyRelayPreimage $before $installationEvidenceRoot}
                    [void](Disable-CanonicalOfficialLegacyRelay $before)
                }else{if($null -eq $writer.transition_record){throw 'OFFICIAL_LEGACY_PREIMAGE_REQUIRED'};[void](Restore-CanonicalOfficialLegacyRelay $writer.transition_record)}
            }else{
                throw 'PUBLIC_HISTORY_HAS_NO_HKCU_RUN_RELAY'
            }
        }catch{Write-InstallationCaughtFailure $_;$failure=Get-InstallationFailureDetails $_}
        try{
            if($writer.mechanism -ceq 'scheduled_task'){
                $writer.xml=[string](Export-ScheduledTask -TaskName ([string]$writer.task_name) -TaskPath ([string]$writer.task_path) -ErrorAction Stop)
                if($null -ne $writer.PSObject.Properties['observed_enabled']){
                    $live=@(Get-ScheduledTask -TaskName ([string]$writer.task_name) -TaskPath ([string]$writer.task_path) -ErrorAction Stop)
                    if($live.Count -ne 1 -or $live[0].Settings.Enabled -isnot [bool]){throw 'TASK_ENABLED_STATE_UNKNOWN'}
                    $writer.observed_enabled=$live[0].Settings.Enabled
                }
            }
            $state=Get-CanonicalOfficialLegacyRelayState $writer $ExpectedIdentitySet $installationEvidenceRoot
            if($Mode -ceq 'install' -and $null -eq $failure -and $state.recognized -and $state.enabled -is [bool] -and -not $state.enabled -and $onboardingPath){
                Save-CanonicalOfficialLegacyRelayTransitionPointer $writer.transition_record
            }
        }catch{Write-InstallationCaughtFailure $_;$failure=Get-InstallationFailureDetails $_;$state=[pscustomobject]@{recognized=$false;entry_tag='';mechanism=[string]$writer.mechanism;enabled=$null;full_fingerprint='';transition_record=$null;reason_code='POST_TRANSITION_QUERY_UNKNOWN'}}
        $audit+=,@{mechanism=[string]$writer.mechanism;mode=$Mode;status=if($null -eq $failure){'PROVEN'}else{'FAILED'};failure=$failure}
        $states+=,$state
    }
    return [pscustomobject]@{audit=$audit;state=$states}
}

function Get-CanonicalWriterSnapshot([string]$InstallRootValue) {
    $expectedExecute = Join-Path $InstallRootValue 'runtime\python.exe'
    $expectedMain = Join-Path $InstallRootValue 'app\main.py'
    $local = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
    $logPath = Join-Path $local 'KMTech\DirectSync\container_audit\logs\scheduled_direct_sync_relay.jsonl'
    $statusPath = Join-Path $local 'KMTech\DirectSync\container_audit\status\scheduled_direct_sync_relay_status.json'
    $currentSid = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $canonical = @()
    $noncanonicalDisabled = @()
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($candidate in $allTasks) {
        $actions = @($candidate.Actions)
        $arguments = if (
            $actions.Count -eq 1 -and $null -ne $actions[0] -and
            $null -ne $actions[0].PSObject.Properties['Arguments']
        ) { [string]$actions[0].Arguments } else { '' }
        $execute = if (
            $actions.Count -eq 1 -and $null -ne $actions[0] -and
            $null -ne $actions[0].PSObject.Properties['Execute']
        ) { [string]$actions[0].Execute } else { '' }
        # A display/capture command can mention the app without running a writer.
        # Retain all named writers and relay actions, including malformed ones.
        $owned = (
            [string]$candidate.TaskName -ieq $CanonicalWriterTaskName -or
            [string]$candidate.TaskName -ieq $NoncanonicalQualificationTaskName -or
            @($actions | Where-Object {
                $actionArguments = [string](Get-CanonicalTaskProperty $_ 'Arguments' '')
                if ($actionArguments -match '(?:^|\s)["'']?--container-audit-(?:direct-sync-relay|user-relay)["'']?(?:\s|$)') {
                    return $true
                }
                # Execute is a path, not a shell command. Only Python consumes a
                # script from Arguments; a direct script Execute remains owned.
                $actionExecute = ([string](Get-CanonicalTaskProperty $_ 'Execute' '')).Trim().Trim('"')
                $python = [IO.Path]::GetFileName($actionExecute) -imatch '^(?:python[^\\/]*|py)\.exe$'
                $scriptPath = $actionExecute
                if ($python) {
                    # Windows argv quoting: whitespace splits outside quotes;
                    # backslashes are escapes only immediately before a quote.
                    $words = @()
                    $word = ''; $quoted = $false; $started = $false; $slashes = 0
                    for ($i = 0; $i -lt $actionArguments.Length; $i++) {
                        $ch = $actionArguments[$i]
                        if ($ch -ceq '\') { $slashes++; $started = $true; continue }
                        if ($ch -ceq '"') {
                            $word += '\' * [int][Math]::Floor($slashes / 2)
                            if ($slashes % 2) { $word += '"' }
                            elseif ($quoted -and $i + 1 -lt $actionArguments.Length -and $actionArguments[$i + 1] -ceq '"') {
                                $word += '"'; $i++
                            }
                            else { $quoted = -not $quoted }
                            $started = $true
                        }
                        else {
                            $word += '\' * $slashes
                            if (-not $quoted -and [char]::IsWhiteSpace($ch)) {
                                if ($started) { $words += $word; $word = ''; $started = $false }
                            }
                            else { $word += $ch; $started = $true }
                        }
                        $slashes = 0
                    }
                    $word += '\' * $slashes
                    if ($started) { $words += $word }
                    $index = 0
                    while ($index -lt $words.Count -and $words[$index].StartsWith('-')) {
                        $option = $words[$index]
                        $index++
                        if ($option -ceq '--') { break }
                        if ($option -cmatch '^-[bBdEiIOPqRsSuvx]+$') { continue }
                        if ($option -cmatch '^-[bBdEiIOPqRsSuvx]*[WX](.*)$') {
                            if ($Matches[1] -ceq '') { $index++ }
                            continue
                        }
                        if ($option -ceq '--check-hash-based-pycs') { $index++; continue }
                        if ([IO.Path]::GetFileName($actionExecute) -ieq 'py.exe' -and
                            $option -cmatch '^-(?:[23](?:\.\d+)?(?:-(?:32|64))?|V:.+)$') { continue }
                        # -c/-m/stdin, help/version and invalid options do not
                        # execute a following token as a source script.
                        return $false
                    }
                    if ($index -ge $words.Count) { return $false }
                    $scriptPath = $words[$index]
                }
                if ([string]::IsNullOrWhiteSpace($scriptPath) -or [IO.Path]::GetExtension($scriptPath) -ine '.py') {
                    return $false
                }
                try {
                    $workingDirectory = [string](Get-CanonicalTaskProperty $_ 'WorkingDirectory' '')
                    if (-not [IO.Path]::IsPathRooted($scriptPath) -and $workingDirectory) {
                        $scriptPath = Join-Path $workingDirectory $scriptPath
                    }
                    $scriptPath = [IO.Path]::GetFullPath($scriptPath).Replace('/', '\')
                }
                catch {
    Write-InstallationCaughtFailure $_
 return $false }
                # Reuse the authenticated inventory's executable Python routes;
                # method-level routes are not standalone script entrypoints.
                foreach ($route in $sourceWriterInventory.known_route_coverage) {
                    if ($route.kind -ceq 'python' -and $route.start -cmatch '^([^.]+(?:\.[^.]+)*)\.main$') {
                        $relativeScript = $Matches[1].Replace('.', '\') + '.py'
                        if ($scriptPath.EndsWith(('\' + $relativeScript), [StringComparison]::OrdinalIgnoreCase)) {
                            return $true
                        }
                    }
                }
                return $false
            }).Count -gt 0
        )
        if (-not $owned) { continue }
        if([string]$candidate.TaskName -ieq 'direct-sync-relay-container-audit' -and [IO.Path]::GetFileName($execute.Trim('"')) -iin @('wscript.exe','cmd.exe')){
            if((Get-BootstrapOfficialLegacyRelayIdentity $candidate).matched){continue}
        }
        $binding = Get-CanonicalWriterBinding $candidate
        $triggers = @($binding.value.triggers)
        $executeExact = (
            $execute.IndexOfAny([IO.Path]::GetInvalidPathChars()) -lt 0 -and
            [IO.Path]::IsPathRooted($execute) -and
            (Same $execute $expectedExecute)
        )
        $actionExact = (
            [string]$candidate.TaskName -ieq $CanonicalWriterTaskName -and
            [string]$candidate.TaskPath -ceq '\' -and
            $actions.Count -eq 1 -and $executeExact -and
            $arguments.IndexOf($expectedMain, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $arguments.IndexOf('--container-audit-direct-sync-relay', [StringComparison]::Ordinal) -ge 0 -and
            $arguments.IndexOf($logPath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $arguments.IndexOf($statusPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
        )
        $principalSid = Get-PrincipalSid ([string]$candidate.Principal.UserId)
        $principalExact = (
            -not [string]::IsNullOrWhiteSpace($principalSid) -and
            $principalSid -ceq $currentSid -and
            [string]$candidate.Principal.LogonType -ceq 'Interactive' -and
            [string]$candidate.Principal.RunLevel -ceq 'Limited'
        )
        $triggerExact = (
            $triggers.Count -eq 1 -and
            [string]$triggers[0].type -ceq 'MSFT_TaskTimeTrigger' -and
            [bool]$triggers[0].enabled -and
            [string]$triggers[0].repetition_interval -ceq 'PT1M' -and
            [bool]$candidate.Settings.StartWhenAvailable -and
            [string]$candidate.Settings.MultipleInstances -ceq 'IgnoreNew' -and
            [string]$candidate.Settings.ExecutionTimeLimit -ceq 'PT2M'
        )
        if ($actionExact -and $principalExact -and $triggerExact) {
            $canonical += $candidate
            continue
        }
        if ([bool]$candidate.Settings.Enabled) { throw 'NONCANONICAL_WRITER_ENABLED' }
        $noncanonicalDisabled += [ordered]@{
            task_name=[string]$candidate.TaskName
            task_path=[string]$candidate.TaskPath
            binding_sha256=[string]$binding.sha256
        }
    }
    if ($canonical.Count -eq 0) {
        return [ordered]@{
            present=$false
            classification='CANONICAL_ABSENT_NONCANONICAL_DISABLED'
            restore_required=$false
            noncanonical_disabled=$noncanonicalDisabled
        }
    }
    if ($canonical.Count -ne 1) { throw 'CANONICAL_WRITER_COUNT_NOT_EXACT' }
    $task = $canonical[0]
    $info = Get-ScheduledTaskInfo -TaskName ([string]$task.TaskName) -TaskPath ([string]$task.TaskPath) -ErrorAction Stop
    $binding = Get-CanonicalWriterBinding $task
    $actions = @($task.Actions)
    $triggers = @($binding.value.triggers)
    $enabled = [bool]$task.Settings.Enabled
    $processes = @(Get-CanonicalWriterProcesses $InstallRootValue)
    return [ordered]@{
        present=$true
        classification='CANONICAL_QUIESCE_RESTORE'
        restore_required=$enabled
        task_name=[string]$task.TaskName
        task_path=[string]$task.TaskPath
        binding_sha256=[string]$binding.sha256
        action_execute=if ($actions.Count -eq 1) { [string]$actions[0].Execute } else { '' }
        action_mode='--container-audit-direct-sync-relay'
        principal_user=[string]$task.Principal.UserId
        principal_sid=Get-PrincipalSid ([string]$task.Principal.UserId)
        logon_type=[string]$task.Principal.LogonType
        run_level=[string]$task.Principal.RunLevel
        trigger_type=if ($triggers.Count -eq 1) { [string]$triggers[0].type } else { '' }
        trigger_interval=if ($triggers.Count -eq 1) { [string]$triggers[0].repetition_interval } else { '' }
        start_when_available=[bool]$task.Settings.StartWhenAvailable
        multiple_instances=[string]$task.Settings.MultipleInstances
        enabled=$enabled
        state=[string]$task.State
        process_count=$processes.Count
        process_ids=@($processes | ForEach-Object { [int]$_.ProcessId })
        last_task_result=[int64]$info.LastTaskResult
        last_run_time_utc=UtcText ([datetime]$info.LastRunTime)
        next_run_time_utc=UtcText ([datetime]$info.NextRunTime)
        log=FileObservation $logPath
        runtime_status=FileObservation $statusPath
        noncanonical_disabled=$noncanonicalDisabled
    }
}
function Assert-CanonicalWriterRestoreReadback($Before, $After) {
    if (-not [bool]$After.present -or
        [string]$After.classification -cne 'CANONICAL_QUIESCE_RESTORE' -or
        -not [bool]$After.enabled -or
        [string]$After.binding_sha256 -cne [string]$Before.binding_sha256) {
        throw 'CANONICAL_WRITER_RESTORE_BINDING_MISMATCH'
    }
}
function Assert-CanonicalRetiredLegacyWriterAdmission($Snapshot,[string]$EvidenceRoot) {
    $failureMessage='Uninstall/restore requires the current-user layout without legacy scheduled writers.'
    $candidates=[Collections.Generic.List[object]]::new()
    if ([bool]$Snapshot.present) { $candidates.Add($Snapshot) }
    if ($Snapshot -is [Collections.IDictionary]) {
        $hasDisabled=$Snapshot.Contains('noncanonical_disabled')
    } else { $hasDisabled=$null -ne $Snapshot.PSObject.Properties['noncanonical_disabled'] }
    if ($hasDisabled) {
        foreach ($entry in @($Snapshot.noncanonical_disabled)) {
            if ($null -ne $entry) { $candidates.Add($entry) }
        }
    }
    if ($candidates.Count -eq 0) { return @() }
    if ([bool]$Snapshot.present -and [bool]$Snapshot.enabled) { throw $failureMessage }
    try {
        # Discovery/identity constants are app-owned lifecycle assembly inputs.
        # Match full discovered writer objects, never infer identity from a name.
        $expected=Get-CanonicalOfficialLegacyRelayExpectedSet
        $writers=@(Get-CanonicalOfficialLegacyRelayWriters `
            -ComputerName ([Environment]::MachineName) `
            -ProgramDataRoot ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) `
            -CurrentUser ([string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
        $proofs=[Collections.Generic.List[object]]::new()
        foreach ($candidate in $candidates) {
            $matches=@($writers | Where-Object {
                [string]$_.mechanism -ceq 'scheduled_task' -and
                [string]::Equals([string]$_.task_path,[string]$candidate.task_path,[StringComparison]::OrdinalIgnoreCase) -and
                [string]::Equals([string]$_.task_name,[string]$candidate.task_name,[StringComparison]::OrdinalIgnoreCase)
            })
            if ($matches.Count -ne 1) { throw $failureMessage }
            $state=Get-CanonicalOfficialLegacyRelayState -Writer $matches[0] -ExpectedIdentitySet $expected -EvidenceRoot $EvidenceRoot
            if ($state.recognized -isnot [bool] -or -not $state.recognized -or
                $state.enabled -isnot [bool] -or $state.enabled -or
                $null -eq $state.transition_record -or
                [string]::IsNullOrWhiteSpace([string]$state.transition_record.path) -or
                [string]$state.transition_record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$state.full_fingerprint -cnotmatch '^[0-9a-f]{64}$') { throw $failureMessage }
            if ((Get-ContainerWriterFenceFileSha256 ([string]$state.transition_record.path) 1048576) -cne
                [string]$state.transition_record.sha256) { throw $failureMessage }
            $proofs.Add([ordered]@{mechanism='scheduled_task';entry_tag=[string]$state.entry_tag;
                full_fingerprint=[string]$state.full_fingerprint;transition_record=$state.transition_record})
        }
        return $proofs.ToArray()
    } catch {
        # Fail closed when assembly inputs/discovery/transition evidence differ.
        throw [InvalidOperationException]::new($failureMessage,$_.Exception)
    }
}
function Get-CanonicalWriterPreimageForQuiesce([string]$InstallRootValue) {
    $deadline = (Get-Date).ToUniversalTime().AddSeconds(90)
    do {
        $snapshot = Get-CanonicalWriterSnapshot $InstallRootValue
        if (-not [bool]$snapshot.restore_required) { return $snapshot }
        if ([int64]$snapshot.last_task_result -ne 0) {
            throw 'CANONICAL_WRITER_PRESTATE_LAST_RESULT_NONZERO'
        }
        $next = if ([string]::IsNullOrWhiteSpace([string]$snapshot.next_run_time_utc)) {
            [datetime]::MinValue
        }
        else { [datetime]::Parse([string]$snapshot.next_run_time_utc).ToUniversalTime() }
        $safe = (
            [string]$snapshot.state -cne 'Running' -and
            $next -gt (Get-Date).ToUniversalTime().AddSeconds(10) -and
            $next -le (Get-Date).ToUniversalTime().AddSeconds(120)
        )
        if (-not $safe) { Start-Sleep -Milliseconds 500 }
    } while (-not $safe -and (Get-Date).ToUniversalTime() -lt $deadline)
    if (-not $safe) { throw 'CANONICAL_WRITER_PRESTATE_SAFE_BOUNDARY_NOT_FOUND' }
    return $snapshot
}
function Disable-CanonicalWriter([string]$InstallRootValue, $Before) {
    $task = DisableAndStop-ContainerScheduledTaskUnderWriterFence `
        -SessionId $Script:CanonicalWriterFenceSessionId `
        -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
        -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
        -AuthorityLease $canonicalWriterFenceAuthority `
        -TaskName ([string]$Before.task_name) `
        -TaskPath ([string]$Before.task_path)
    $deadline = (Get-Date).ToUniversalTime().AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 250
        $task = Get-ScheduledTask -TaskName ([string]$Before.task_name) -TaskPath ([string]$Before.task_path) -ErrorAction Stop
    } while ([string]$task.State -ceq 'Running' -and (Get-Date).ToUniversalTime() -lt $deadline)
    $processDeadline = (Get-Date).ToUniversalTime().AddSeconds(30)
    do {
        $processes = @(Get-CanonicalWriterProcesses $InstallRootValue)
        if ($processes.Count -gt 0) { Start-Sleep -Milliseconds 250 }
    } while ($processes.Count -gt 0 -and (Get-Date).ToUniversalTime() -lt $processDeadline)
    if ([string]$task.State -ceq 'Running' -or [bool]$task.Settings.Enabled -or $processes.Count -gt 0) {
        throw 'CANONICAL_WRITER_QUIESCE_READBACK_FAILED'
    }
    Start-Sleep -Seconds 2
    $after = Get-CanonicalWriterSnapshot $InstallRootValue
    if ([string]$after.binding_sha256 -cne [string]$Before.binding_sha256 -or [bool]$after.enabled) {
        throw 'CANONICAL_WRITER_QUIESCE_BINDING_MISMATCH'
    }
    return $after
}
function Confirm-CanonicalWriterStopped([string]$InstallRootValue, $Before, $DisabledBaseline) {
    if ([string]::IsNullOrWhiteSpace([string]$Before.next_run_time_utc)) {
        throw 'CANONICAL_WRITER_NEXT_TRIGGER_UNKNOWN'
    }
    $boundary = [datetime]::Parse([string]$Before.next_run_time_utc).ToUniversalTime()
    $now = (Get-Date).ToUniversalTime()
    if ($boundary -le $now.AddSeconds(-5) -or $boundary -gt $now.AddSeconds(120)) {
        throw 'CANONICAL_WRITER_NEXT_TRIGGER_NOT_BOUNDED'
    }
    while ((Get-Date).ToUniversalTime() -lt $boundary.AddSeconds(5)) { Start-Sleep -Milliseconds 500 }
    $after = Get-CanonicalWriterSnapshot $InstallRootValue
    $unchanged = (
        -not [bool]$after.enabled -and
        [int]$after.process_count -eq 0 -and
        [string]$after.binding_sha256 -ceq [string]$DisabledBaseline.binding_sha256 -and
        [string]$after.last_run_time_utc -ceq [string]$DisabledBaseline.last_run_time_utc -and
        (SameFileObservation $after.log $DisabledBaseline.log) -and
        (SameFileObservation $after.runtime_status $DisabledBaseline.runtime_status)
    )
    if (-not $unchanged) { throw 'CANONICAL_WRITER_STOP_PROOF_FAILED' }
    return [ordered]@{
        status='PASS'
        crossed_trigger_utc=$boundary.ToString('o')
        last_run_time_unchanged=$true
        log_size_mtime_sha256_unchanged=$true
        runtime_status_unchanged=$true
        readback=$after
    }
}
function Enable-CanonicalWriter([string]$InstallRootValue, $Before) {
    [void](Enable-ContainerScheduledTaskUnderWriterFence `
        -SessionId $Script:CanonicalWriterFenceSessionId `
        -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
        -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
        -AuthorityLease $canonicalWriterFenceAuthority `
        -TaskName ([string]$Before.task_name) `
        -TaskPath ([string]$Before.task_path))
    $deadline = (Get-Date).ToUniversalTime().AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $after = Get-CanonicalWriterSnapshot $InstallRootValue
        if ([bool]$after.enabled) { Assert-CanonicalWriterRestoreReadback $Before $after }
        $next = if ([string]::IsNullOrWhiteSpace([string]$after.next_run_time_utc)) {
            [datetime]::MinValue
        }
        else { [datetime]::Parse([string]$after.next_run_time_utc).ToUniversalTime() }
    } while ((-not [bool]$after.enabled -or $next -le (Get-Date).ToUniversalTime().AddSeconds(2)) -and (Get-Date).ToUniversalTime() -lt $deadline)
    Assert-CanonicalWriterRestoreReadback $Before $after
    if ($next -le (Get-Date).ToUniversalTime().AddSeconds(2) -or $next -gt (Get-Date).ToUniversalTime().AddSeconds(120)) {
        throw 'CANONICAL_WRITER_RESTORE_NEXT_TRIGGER_NOT_FUTURE'
    }
    return [ordered]@{
        status='PASS'
        binding_sha256_exact=$true
        future_natural_trigger_utc=$next.ToString('o')
        readback=$after
    }
}
function Confirm-CanonicalWriterRunning([string]$InstallRootValue, $EnabledBaseline) {
    $baseline = $EnabledBaseline.readback
    $boundary = [datetime]::Parse([string]$EnabledBaseline.future_natural_trigger_utc).ToUniversalTime()
    while ((Get-Date).ToUniversalTime() -lt $boundary.AddSeconds(5)) { Start-Sleep -Milliseconds 500 }
    $deadline = $boundary.AddSeconds(45)
    do {
        $after = Get-CanonicalWriterSnapshot $InstallRootValue
        $last = if ([string]::IsNullOrWhiteSpace([string]$after.last_run_time_utc)) {
            [datetime]::MinValue
        }
        else { [datetime]::Parse([string]$after.last_run_time_utc).ToUniversalTime() }
        $logChanged = (
            [bool]$after.log.exists -and
            [int64]$after.log.bytes -gt [int64]$baseline.log.bytes -and
            [string]$after.log.mtime_utc -cne [string]$baseline.log.mtime_utc -and
            [string]$after.log.sha256 -cne [string]$baseline.log.sha256
        )
        $statusChanged = (
            [bool]$after.runtime_status.exists -and
            [string]$after.runtime_status.mtime_utc -cne [string]$baseline.runtime_status.mtime_utc -and
            [string]$after.runtime_status.sha256 -cne [string]$baseline.runtime_status.sha256
        )
        $passed = (
            [bool]$after.enabled -and
            [string]$after.binding_sha256 -ceq [string]$baseline.binding_sha256 -and
            $last -ge $boundary.AddSeconds(-5) -and
            [int64]$after.last_task_result -eq 0 -and
            $logChanged -and $statusChanged
        )
        if (-not $passed) { Start-Sleep -Milliseconds 500 }
    } while (-not $passed -and (Get-Date).ToUniversalTime() -lt $deadline)
    if (-not $passed) { throw 'CANONICAL_WRITER_NATURAL_TRIGGER_PROOF_FAILED' }
    return [ordered]@{
        status='PASS'
        natural_trigger_utc=$boundary.ToString('o')
        last_run_time_advanced=$true
        last_task_result=[int64]$after.last_task_result
        log_actual_write=$true
        runtime_status_actual_write=$true
        readback=$after
    }
}

# Public boundary covers preflight, transaction and finally failures.
function Get-CanonicalInstallationCallerSecurity {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    return [pscustomobject]@{sid=$identity.User.Value;
        session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;
        elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
}
function Resolve-CanonicalWorkerSid([string]$Account) {
    if ($Account -cmatch '^S-1-') {
        return ([Security.Principal.SecurityIdentifier]::new($Account)).Value
    }
    return ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Get-CanonicalWorkerProfileRoot([string]$Sid) {
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$Sid,$false)
    if ($null -eq $key) { throw 'PENDING_TARGET_AMBIGUOUS' }
    try { $value=[string]$key.GetValue('ProfileImagePath') } finally { $key.Dispose() }
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'PENDING_TARGET_AMBIGUOUS' }
    return Full ([Environment]::ExpandEnvironmentVariables($value)) 'worker profile'
}
function Get-CanonicalConsoleWorkerSecurity {
    # WMI's computer-system principal identifies the console user. Resolve its
    # one live Explorer session using read-only process owner observations.
    $console=@(Get-CimInstance Win32_ComputerSystem -Property UserName -ErrorAction Stop)
    if ($console.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$console[0].UserName)) { throw 'PENDING_TARGET_AMBIGUOUS' }
    $sid=Resolve-CanonicalWorkerSid ([string]$console[0].UserName)
    if ($sid -cnotmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw 'PENDING_TARGET_AMBIGUOUS' }
    $owners=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | ForEach-Object {
        $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
        if ([uint32]$owner.ReturnValue -ne 0 -or [string]$owner.Sid -cnotmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw 'PENDING_TARGET_AMBIGUOUS' }
        [pscustomobject]@{sid=[string]$owner.Sid;session_id=[int]$_.SessionId}
    })
    $sessions=@($owners | Where-Object {$_.sid -ceq $sid -and $_.session_id -gt 0} | ForEach-Object {$_.session_id} | Select-Object -Unique)
    if ($sessions.Count -ne 1) { throw 'PENDING_TARGET_AMBIGUOUS' }
    $sids=@($owners | Where-Object {$_.session_id -eq $sessions[0]} | ForEach-Object {$_.sid} | Select-Object -Unique)
    if ($sids.Count -ne 1 -or $sids[0] -cne $sid) { throw 'PENDING_TARGET_AMBIGUOUS' }
    return [pscustomobject]@{sid=$sid;session_id=[int]$sessions[0]}
}
function Resolve-CanonicalMachineWorker([string]$Account,[string]$InventoryPath,$Caller) {
    $privileged=[bool]$Caller.elevated -or [int]$Caller.session_id -le 0
    if (-not $privileged) {
        if ($Account -or $InventoryPath) { throw 'MACHINE_WORKER_ARGUMENTS_REQUIRE_ADMINISTRATOR' }
        return $null
    }
    if ([string]::IsNullOrWhiteSpace($Account) -and [string]::IsNullOrWhiteSpace($InventoryPath)) {
        $console=Get-CanonicalConsoleWorkerSecurity
        $sid=[string]$console.sid
        $profile=Get-CanonicalWorkerProfileRoot $sid
        if ($sid -ceq [string]$Caller.sid -and [int]$console.session_id -eq [int]$Caller.session_id -and -not $RecoverMachineInstallation) {
            # Keep the established elevated console path (normal-user coordinator).
            return $null
        }
        # Session 0/another administrator can bind one current console worker
        # read-only. Interactive completion remains deferred to that worker.
        $sha=Get-BootstrapStringSha256 ($sid+"`n"+$profile+"`n"+[string]$console.session_id)
        return [pscustomobject]@{sid=$sid;profile_root=$profile;survey_sha256=$sha;survey_path='';
            same_caller=($sid -ceq [string]$Caller.sid);target_source='CURRENT_CONSOLE'}
    }
    if ([string]::IsNullOrWhiteSpace($Account) -or [string]::IsNullOrWhiteSpace($InventoryPath)) {
        throw 'PENDING_TARGET_AMBIGUOUS'
    }
    $sid=Resolve-CanonicalWorkerSid $Account
    $profile=Get-CanonicalWorkerProfileRoot $sid
    $path=Full $InventoryPath 'worker survey inventory'
    Assert-BootstrapNoReparsePoint $path 'worker survey inventory' -PathOnly
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 16777216) {
        throw 'PENDING_TARGET_AMBIGUOUS'
    }
    $bytes=[IO.File]::ReadAllBytes($path)
    try { $inventory=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff) | ConvertFrom-Json }
    catch { throw 'PENDING_TARGET_AMBIGUOUS' }
    if ($null -eq $inventory -or $inventory.status -isnot [string] -or [string]$inventory.status -cne 'READY' -or
        $inventory.target_sid -isnot [string] -or [string]$inventory.target_sid -cne $sid -or
        $inventory.target_profile_root -isnot [string] -or -not (Same ([string]$inventory.target_profile_root) $profile)) {
        throw 'PENDING_TARGET_AMBIGUOUS'
    }
    $digest=[Security.Cryptography.SHA256]::Create()
    try { $sha=([BitConverter]::ToString($digest.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $digest.Dispose() }
    return [pscustomobject]@{sid=$sid;profile_root=$profile;survey_sha256=$sha;survey_path=$path;same_caller=($sid -ceq [string]$Caller.sid)}
}
function Get-CanonicalMachineHelperReason([string]$Stdout,[string]$Code='') {
    # Only the pinned helper's fixed reason codes cross this edge. Any other
    # child text, including a malformed or unknown reason, stays private.
    $allowed=@('lifecycle_operation_invalid','lifecycle_owned_namespace_collision','lifecycle_namespace_parent_unavailable',
        'lifecycle_data_namespace_collision','lifecycle_removed_control_remains','lifecycle_register_requires_installed_code',
        'lifecycle_removed_tasks_remain_or_unknown','lifecycle_stock_protection_invalid','lifecycle_stock_layout_invalid',
        'lifecycle_stock_manifest_invalid','lifecycle_control_incomplete','lifecycle_transition_requires_recovery',
        'lifecycle_confirmed_pointer_mismatch','lifecycle_rolled_back_pointer_mismatch','lifecycle_pointer_mismatch',
        'lifecycle_active_manifest_mismatch','lifecycle_active_trust_key_mismatch','lifecycle_task_absence_or_unknown',
        'lifecycle_state_changed_during_verification','lifecycle_from_commit_mismatch',
        'WRITER_GATE_TIMEOUT','ACTIVE_WRITER_FENCE','FENCE_REPARSE_REJECTED','FENCE_PATH_UNOBSERVABLE',
        'STARTUP_UPDATE_INITIAL_VERSION_INVALID','STARTUP_UPDATE_INITIAL_VERSION_READBACK_FAILED',
        'STARTUP_UPDATE_VERSION_ALREADY_HAS_DIFFERENT_BYTES','STARTUP_UPDATE_DURING_WORK_FORBIDDEN',
        'STARTUP_UPDATE_OPERATOR_BINDING_DIFFERS','STARTUP_UPDATE_OPERATOR_DIFFERS','STARTUP_UPDATE_DURABLE_RECORD_FAILED',
        'STARTUP_UPDATE_PREIMAGE_PATH_INVALID','STARTUP_UPDATE_PREIMAGE_READBACK_FAILED','STARTUP_UPDATE_WRITER_HELPER_PIN_DIFFERS',
        'STARTUP_UPDATE_TASK_SPEC_FAILED','STARTUP_UPDATE_TASK_SPEC_INVALID','STARTUP_UPDATE_OWNED_TASK_DIFFERS',
        'STARTUP_UPDATE_TASK_IS_RUNNING','STARTUP_UPDATE_TASK_READBACK_FAILED',
        'EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED')
    if (-not $Code) {
        $lines=@(([string]$Stdout) -split '\r?\n' | Where-Object { $_ -clike 'installation_failure_summary=*' })
        if ($lines.Count) {
            try { $Code=[string](($lines[-1].Substring('installation_failure_summary='.Length) | ConvertFrom-Json).reason_code) } catch { $Code='' }
        }
    }
    if ($Code -cin $allowed) { return $Code }
    return 'PLACEMENT_HELPER_FAILED'
}
function Get-CanonicalMachineFailureReason($Failure) {
    # Exact pre-transaction refusals only; everything else is UNCLASSIFIED.
    $known=@(@('CONTAINER_WRITER_FENCE_ALREADY_ACTIVE','PRIOR_INSTALL_UNFINISHED'),
        @('Existing worker deployment requires recovery.','WORKER_INSTALL_UNFINISHED'),
        @('Machine installation requires an already privileged token.','ADMINISTRATOR_REQUIRED'),
        @('CODE_PRESTATE_WRITER_SEMANTICS_DIFFER','INSTALLED_WRITER_SEMANTICS_DIFFER'),
        @('EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED','EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED'))
    $exception=if($Failure -is [Exception]){$Failure}elseif($null -ne $Failure){$Failure.Exception}else{$null}
    for ($depth=0; $null -ne $exception -and $depth -lt 8; $depth++) {
        if ($exception.Data.Contains('canonical_machine_helper_reason')) {
            return (Get-CanonicalMachineHelperReason '' ([string]$exception.Data['canonical_machine_helper_reason']))
        }
        foreach ($pair in $known) { if ([string]$exception.Message -ceq $pair[0]) { return $pair[1] } }
        $exception=$exception.InnerException
    }
    return 'UNCLASSIFIED'
}
function Write-CanonicalMachinePublicRecord([string]$Code,[string]$Status='FAILED',$Failure=(Get-Variable -Name outputFailure -ValueOnly -ErrorAction SilentlyContinue)) {
    $message='작업자 계정과 살펴보기 기록을 확인하고 관리자 설치 키트로 다시 실행하세요.'
    $reason=''
    if ($Code -ceq 'MACHINE_INSTALL_FAILED') {
        $reason=Get-CanonicalMachineFailureReason $Failure
        if ($reason -cin @('PRIOR_INSTALL_UNFINISHED','WORKER_INSTALL_UNFINISHED')) {
            $message='이전 설치가 끝나지 않았습니다. 자료와 설치 기록을 보존하고 관리자 지원 복구를 요청하세요.'
        } elseif ($reason -ceq 'ADMINISTRATOR_REQUIRED') {
            $message='관리자 권한으로 연 창에서 관리자 설치 키트를 다시 실행하세요.'
        } elseif ($reason -ceq 'INSTALLED_WRITER_SEMANTICS_DIFFER') {
            $message='설치된 판과 이 설치 묶음의 기록 방식이 달라 바꾸지 않았습니다. 지원 담당자에게 문의하세요.'
        } elseif ($reason -clike 'lifecycle_*') {
            $message='기존 설치 상태와 예약 작업을 확인하고 관리자 지원 복구를 요청하세요.'
        } elseif ($reason -clike 'STARTUP_UPDATE_*') {
            $message='자동 업데이트 등록 단계에서 멈췄습니다. 자료와 설치 기록을 보존하고 관리자 지원 복구를 요청하세요.'
        }
    }
    if ($Code -ceq 'PASS_MACHINE_WORKER_PENDING') {
        $message='프로그램 배치가 끝났습니다. 지정 작업자 계정으로 처음 실행해야 설치가 끝납니다.'
    } elseif ($Code -ceq 'PASS_UNINSTALLED_DATA_PRESERVED') {
        $message='프로그램 제거가 끝났습니다. 작업자 자료는 보존했습니다.'
    } elseif ($Code -ceq 'PASS_RESTORED_VERIFIED') {
        $message='프로그램 코드 복원이 끝났습니다. 작업자 설정은 변경하지 않았습니다.'
    } elseif ($Code -ceq 'MACHINE_RECOVERY_CHILD_ACTIVE') {
        $message='설치가 아직 진행 중입니다 — 끝난 뒤 같은 명령을 다시 실행하세요'
    } elseif ($Code -clike 'MACHINE_RECOVERY_CHILD_*') {
        $message='설치 자식의 종료를 확인하지 못했습니다. 자료와 설치 기록을 보존하고 관리자 지원 복구를 요청하세요.'
    }
    $fields=[ordered]@{status=$Status;code=$Code;stage='machine_install';guidance=$message;report_status='REPORT_UNAVAILABLE'}
    $summary=''
    if ($reason) { $summary=$Code+' reason='+$reason; $fields.reason_code=$reason; $fields.summary_message=$summary }
    $public=ConvertTo-KmtechPublicRecord -Fields $fields -AllowedCodes @('FAILED','PASS','machine_install',
        'PENDING_TARGET_AMBIGUOUS','MACHINE_WORKER_ARGUMENTS_REQUIRE_ADMINISTRATOR','MACHINE_INSTALL_FAILED',
        'PASS_MACHINE_WORKER_PENDING','PASS_UNINSTALLED_DATA_PRESERVED','PASS_RESTORED_VERIFIED','REPORT_UNAVAILABLE',
        'MACHINE_RECOVERY_CHILD_UNRECORDED','MACHINE_RECOVERY_CHILD_IDENTITY_INVALID','MACHINE_RECOVERY_CHILD_ACTIVE','MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN',$reason) -SafeMessages @($message,$summary)
    Write-Output ('CONTAINER_AUDIT_INSTALL_CANONICAL='+($public|ConvertTo-Json -Depth 4 -Compress))
}

function Get-CanonicalMachineArtifactPaths([string]$State,[string]$Root='') {
    $directory=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)
    if (-not $directory) { throw 'Machine start menu is unavailable.' }
    $shortcutPath=if($Root){(Get-CanonicalMachineShortcutPlacement $Root $directory).path}else{Join-Path $directory 'KMTech 이적 검사.lnk'}
    $paths=@((Join-Path $State 'pending-onboarding.json'),$shortcutPath)
    if($Root){
        $emergency=Get-BootstrapEmergencyShortcutPath $Root
        $owned=Test-BootstrapEmergencyShortcutDirectory $emergency
        if($owned -and (Test-Path -LiteralPath $emergency)){
            $shell=New-Object -ComObject WScript.Shell
            try{
                try{$owned=Test-BootstrapEmergencyShortcutOwner ($shell.CreateShortcut($emergency)) (Join-Path $Root 'launch-container-audit.cmd')}
                catch{$owned=$false}
            }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
        }
        # Foreign data is neither changed nor copied into our recovery journal.
        if($owned){$paths+=@($emergency)}
    }
    return $paths
}
function Get-CanonicalMachineShortcutArguments([string]$Root) {
    $entry=Join-Path $Root 'app\main.py'
    if ($entry.Contains('"')) { throw 'Machine shortcut path contains a quote.' }
    return '-I -B "'+$entry+'"'
}
function Get-CanonicalMachineArtifactPreimage([string[]]$Paths) {
    return @($Paths | ForEach-Object {
        $path=Full $_ 'machine artifact'
        $ancestor=$path
        while (-not (Test-Path -LiteralPath $ancestor)) { $ancestor=Split-Path -Parent $ancestor }
        Assert-BootstrapNoReparsePoint $ancestor 'machine artifact ancestor' -PathOnly
        $exists=Test-Path -LiteralPath $path
        if ($exists -and -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Machine artifact prestate is unknown.' }
        [pscustomobject]@{path=$path;exists=$exists;bytes=if($exists){[IO.File]::ReadAllBytes($path)}else{$null};
            sha256=if($exists){Sha $path}else{''};
            acl=if($exists){Get-Acl -LiteralPath $path}else{$null}}
    })
}
function Restore-CanonicalMachineArtifacts($Before) {
    $failed=$false
    foreach ($item in $Before) {
        try {
            if (-not [bool]$item.exists -and -not (Test-Path -LiteralPath ([string]$item.path))) { continue }
            $present=Test-Path -LiteralPath ([string]$item.path)
            if ($present) {
                Assert-BootstrapNoReparsePoint ([string]$item.path) 'machine artifact restore' -PathOnly
            } else {
                # Restore a withheld old intent without following a replacement leaf.
                if ($null -ne (Get-Item -LiteralPath ([string]$item.path) -Force -ErrorAction SilentlyContinue)) { throw 'Machine artifact restore boundary differs.' }
                $ancestor=Split-Path -Parent ([string]$item.path)
                Assert-BootstrapNoReparsePoint $ancestor 'machine artifact restore parent' -PathOnly
            }
            if ([bool]$item.exists) {
                if ($present) { [IO.File]::WriteAllBytes([string]$item.path,[byte[]]$item.bytes) }
                else {
                    $stream=[IO.File]::Open([string]$item.path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                    try { $stream.Write([byte[]]$item.bytes,0,([byte[]]$item.bytes).Length) } finally { $stream.Dispose() }
                }
                Set-Acl -LiteralPath ([string]$item.path) -AclObject $item.acl
                if ((Sha ([string]$item.path)) -cne [string]$item.sha256 -or
                    (Get-BootstrapAclComparisonKey ([string](Get-Acl -LiteralPath ([string]$item.path)).Sddl)) -cne
                    (Get-BootstrapAclComparisonKey ([string]$item.acl.Sddl))) { throw 'Machine artifact restore readback failed.' }
            } elseif (Test-Path -LiteralPath ([string]$item.path)) {
                if (-not (Test-Path -LiteralPath ([string]$item.path) -PathType Leaf)) { throw 'Machine artifact restore boundary differs.' }
                Remove-Item -LiteralPath ([string]$item.path) -ErrorAction Stop
            }
        } catch { $failed=$true }
    }
    if ($failed) { throw 'Machine artifact restore failed.' }
}
function Test-CanonicalMachineCodePrestate([string]$Root,[string]$ManifestSha256,$StartupBefore) {
    try {
        if (-not $ManifestSha256) {
            if (Test-Path -LiteralPath $Root) { return $false }
        } else {
            if ((Sha (Join-Path $Root 'portable-manifest.json')) -cne $ManifestSha256) { return $false }
            [void](Assert-BootstrapIntegrityRecord $Root)
        }
        foreach ($item in $StartupBefore) {
            $exists=Test-Path -LiteralPath ([string]$item.path) -PathType Leaf
            if ($exists -ne [bool]$item.exists) { return $false }
            if ($exists -and (Sha ([string]$item.path)) -cne [string]$item.sha256) { return $false }
        }
        return $true
    } catch { return $false }
}
function Remove-CanonicalMachineArtifacts([string]$Root,$Worker,[string[]]$Paths) {
    $pending=$Paths[0];$shortcut=$Paths[1]
    $emergencyFailure=$null
    if(-not [IO.File]::Exists((Join-Path $Root 'launch-container-audit.cmd'))){
        try{Remove-BootstrapEmergencyShortcut $Root}
        catch [IO.IOException]{$emergencyFailure=$_}
        catch [UnauthorizedAccessException]{$emergencyFailure=$_}
    }
    if($null -ne $emergencyFailure){
        try {Update-BootstrapEmergencyRemovalMarker $Root $emergencyFailure}
        catch {$emergencyFailure.Exception.Data['emergency_marker_failure_type']=$_.Exception.GetType().FullName}
    }
    $followingFailure=$null
    try {
    if (Test-Path -LiteralPath $pending) {
        Assert-BootstrapNoReparsePoint $pending 'machine pending removal' -PathOnly
        $marker=Get-Content -LiteralPath $pending -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$marker.schema -cne 'container-audit-machine-pending-v1' -or
            [string]$marker.target_sid -cne [string]$Worker.sid -or -not (Same ([string]$marker.install_root) $Root)) {
            throw 'Machine pending removal binding differs.'
        }
    }
    if (Test-Path -LiteralPath $shortcut) {
        Assert-BootstrapNoReparsePoint $shortcut 'machine shortcut removal' -PathOnly
        $shell=New-Object -ComObject WScript.Shell
        try {
            $link=$shell.CreateShortcut($shortcut)
            if ((Same ([string]$link.TargetPath) (Join-Path $Root 'runtime\pythonw.exe')) -and
                [string]$link.Arguments -ceq (Get-CanonicalMachineShortcutArguments $Root) -and
                (Same ([string]$link.WorkingDirectory) (Join-Path $Root 'app'))) {
                Remove-Item -LiteralPath $shortcut -ErrorAction Stop
            }
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
    }
    if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -ErrorAction Stop }
    } catch { $followingFailure=$_ }
    Complete-BootstrapEmergencyCleanup $Root $emergencyFailure $followingFailure
}
function Get-CanonicalMachineShortcutPlacement([string]$Root,[string]$Directory='') {
    if(-not $Directory){$Directory=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)}
    $path=Join-Path $Directory 'KMTech 이적 검사.lnk'
    $target=Join-Path $Root 'runtime\pythonw.exe'
    $arguments=Get-CanonicalMachineShortcutArguments $Root
    $working=Join-Path $Root 'app'
    $preserved=@();$suffix=0
    $shell=New-Object -ComObject WScript.Shell
    try{
        while(Test-Path -LiteralPath $path){
            Assert-BootstrapWorkerShortcutPath $path
            $owned=$false
            try{
                $existing=Get-BootstrapPublishedShortcut $shell $path 'start_menu'
                $owned=([string]$existing.target_path -ieq $target -and $existing.arguments -ceq $arguments -and
                    [string]$existing.working_directory -ieq $working)
            }catch{}
            if($owned){return [pscustomobject]@{path=$path;owned=$true;preserved=@($preserved)+@([pscustomobject]@{shortcut_path=$path;status='OWNED_LINK_RETAINED'})}}
            $preserved+=@([pscustomobject]@{shortcut_path=$path;status='UNRELATED_LINK_PRESERVED'})
            $suffix++;$path=Join-Path $Directory ('KMTech 이적 검사 (새 프로그램 '+$suffix+').lnk')
        }
        return [pscustomobject]@{path=$path;owned=$false;preserved=@($preserved)}
    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
}
function New-CanonicalMachineShortcut([string]$Root,[string]$Directory='',[string]$ExpectedPath='') {
    if(-not $Directory){$Directory=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)}
    $placement=Get-CanonicalMachineShortcutPlacement $Root $Directory
    $path=[string]$placement.path
    if($ExpectedPath -and -not(Same $ExpectedPath $path)){throw 'MACHINE_SHORTCUT_PLACEMENT_CHANGED'}
    Assert-BootstrapWorkerShortcutPath $path
    [void][IO.Directory]::CreateDirectory($Directory)
    $target=Join-Path $Root 'runtime\pythonw.exe'
    $arguments=Get-CanonicalMachineShortcutArguments $Root
    $working=Join-Path $Root 'app'
    $location='start_menu'
    foreach($folder in @(Get-BootstrapWorkerShortcutFolders)){
        if(Same $Directory ([string]$folder.path)){$location=[string]$folder.location}
    }
    $published=@()
    if(-not $placement.owned){$published=@(Write-BootstrapShortcut $path $target $arguments $working '이적 검사' '' $location -CreateNew)}
    $emergency=Install-BootstrapEmergencyShortcut $Root
    return [pscustomobject]@{status='PASS';published=@($published)+@($emergency.published);preserved=@($placement.preserved)+@($emergency.preserved)}
}

function Set-CanonicalPublishedShortcuts($Audit,[object[]]$Results) {
    $published=@();$seen=@{}
    $shell=New-Object -ComObject WScript.Shell
    try{
        foreach($result in $Results){
            if($null -eq $result -or $null -eq $result.published){throw 'SHORTCUT_PUBLICATION_READBACK_REQUIRED'}
            foreach($entry in @($result.published)){
                if(-not (Test-ExactPropertySet $entry @('location','shortcut_path','target_path','arguments','working_directory'))){throw 'SHORTCUT_PUBLICATION_FIELDS_DIFFER'}
                $readback=Get-BootstrapPublishedShortcut $shell ([string]$entry.shortcut_path) ([string]$entry.location)
                if($readback.target_path -ine [string]$entry.target_path -or $readback.arguments -cne [string]$entry.arguments -or
                    $readback.working_directory -ine [string]$entry.working_directory){throw 'SHORTCUT_PUBLICATION_READBACK_DIFFERS'}
                $path=[string]$entry.shortcut_path
                if($seen.ContainsKey($path)){
                    if([string]$seen[$path].location -cne [string]$entry.location){throw 'SHORTCUT_PUBLICATION_LOCATION_DIFFERS'}
                    continue
                }
                $seen[$path]=$readback;$published+=@($readback)
            }
        }
    }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
    if($published.Count -eq 0){
        $preserved=@($Results|Where-Object {
            $null -ne $_.PSObject.Properties['status'] -and [string]$_.status -cin @('PASS','RETAINED','PRESERVED_FOREIGN') -and
            $null -ne $_.PSObject.Properties['preserved']
        }|ForEach-Object {$_.preserved})
        if($preserved.Count -eq 0){throw 'SHORTCUT_PUBLICATION_READBACK_REQUIRED'}
    }
    if(-not $Audit.Contains('shortcuts')){$Audit['shortcuts']=[ordered]@{published=@()}}
    if($Audit.shortcuts -is [Collections.IDictionary]){$Audit.shortcuts['published']=@($published)}
    else{$Audit.shortcuts|Add-Member -NotePropertyName published -NotePropertyValue @($published) -Force}
}

function Get-CanonicalWorkerPreparationPaths($Worker) {
    $local=Join-Path ([string]$Worker.profile_root) 'AppData\Local'
    if (-not (Same (Full $env:LOCALAPPDATA 'caller local application data') $local)) { throw 'Worker profile differs from caller local application data.' }
    $data=Join-Path $local 'KMTech\ContainerAudit'
    $direct=Join-Path $local 'KMTech\DirectSync\container_audit'
    $directories=@($data,(Join-Path $data 'events'),$direct)
    foreach ($name in @('queue','spool','status','logs')) { $directories+=Join-Path $direct $name }
    $shortcuts=@()
    foreach ($folder in @('Programs','DesktopDirectory')) {
        $directory=[Environment]::GetFolderPath([Environment+SpecialFolder]::$folder,[Environment+SpecialFolderOption]::DoNotVerify)
        if (-not $directory -or -not (Full $directory 'worker shortcut directory').StartsWith(([string]$Worker.profile_root).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Worker shortcut directory differs from the admitted profile.'
        }
        $directories+=$directory
        $shortcuts+=Join-Path $directory 'KMTech 이적 검사.lnk'
    }
    $created=@()
    foreach ($directory in $directories) {
        $ancestor=$directory
        while (-not (Test-Path -LiteralPath $ancestor)) {
            if ($created -cnotcontains $ancestor) { $created+=$ancestor }
            $ancestor=Split-Path -Parent $ancestor
        }
        Assert-BootstrapNoReparsePoint $ancestor 'worker preparation ancestor' -PathOnly
    }
    return [pscustomobject]@{directories=$directories;shortcuts=$shortcuts;created_directories=$created}
}
function Initialize-CanonicalSameWorkerScope([string]$Root,$Paths) {
    foreach ($directory in $Paths.directories) { [void][IO.Directory]::CreateDirectory([string]$directory) }
    $command=Command $Root -Installed -InstalledPacket $Root
    Restore @{exists=$true;kind='String';data=$command}
    $run=Snapshot
    if (-not [bool]$run.exists -or [string]$run.kind -cne 'String' -or [string]$run.data -cne $command) { throw 'Worker Run preparation readback failed.' }
    foreach ($shortcut in $Paths.shortcuts) { New-CanonicalMachineShortcut $Root (Split-Path -Parent $shortcut) }
    # Registration, limited relay and GUI belong to PENDING consumption at logon/first start.
}
function Restore-CanonicalWorkerPreparationDirectories($Paths) {
    foreach ($directory in @($Paths.created_directories | Sort-Object Length -Descending)) {
        if (Test-Path -LiteralPath $directory) {
            Assert-BootstrapNoReparsePoint $directory 'worker preparation cleanup' -PathOnly
            if ([IO.Directory]::GetFileSystemEntries($directory).Length -eq 0) { [IO.Directory]::Delete($directory,$false) }
        }
    }
}
function Get-CanonicalMachinePlacementArguments($Worker,[string]$Source,[string]$Root,$Manifest,$Prepared,[string]$Control,[string]$Run) {
    $local=Join-Path ([string]$Worker.profile_root) 'AppData\Local'
    $state=Get-ContainerMachineInstallStateRoot
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $Source 'INSTALL_THIS_PC.ps1'),
        '-InstallRoot',$Root,'-OperatorSid',([string]$Worker.sid),'-OperatorLocalAppDataRoot',$local,'-OperatorDataRoot',(Join-Path $local 'KMTech\ContainerAudit'),
        '-MachineControlRoot',$Control,'-ElevationLogPath',(Join-Path $state ('install-audit\placement-'+$Run+'.jsonl')),
        '-WriterFenceHelperPath',(Join-Path $Source 'tools\container_writer_fence.ps1'),
        '-ExpectedWriterFenceHelperSha256',([string]$Manifest.writer_fence_helper_sha256),
        '-WriterFencePreparedReceiptPath',$Prepared.path,'-WriterFencePreparedReceiptSha256',$Prepared.sha256,
        '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,'-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
        '-WriterFenceReplacementTransactionId',$Run,'-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken)
    if ($testMode) { $arguments+='-AllowNoncanonicalLayoutForTest' }
    return $arguments
}
function ConvertTo-CanonicalMachineArtifactJournal($Before) {
    if ($null -eq $Before) { return @() }
    return @($Before | ForEach-Object {
        [ordered]@{path=$_.path;exists=[bool]$_.exists;bytes=$_.bytes;sha256=$_.sha256;
            acl_sddl=if([bool]$_.exists){[string]$_.acl.Sddl}else{''}}
    })
}
function ConvertFrom-CanonicalMachineArtifactJournal($Before) {
    if ($null -eq $Before) { return @() }
    return @($Before | ForEach-Object {
        $acl=$null
        if ([bool]$_.exists) {
            $acl=New-Object Security.AccessControl.FileSecurity
            $acl.SetSecurityDescriptorSddlForm([string]$_.acl_sddl)
        }
        [pscustomobject]@{path=$_.path;exists=[bool]$_.exists;bytes=$_.bytes;sha256=$_.sha256;acl=$acl}
    })
}
function Save-CanonicalMachineFailureAudit([string]$Path,$Audit) {
    # A reporting hook/failure must not hide a completed compensation proof.
    try { Save $Path $Audit }
    catch { Write-Utf8Json $Path $Audit }
}
function Restore-CanonicalMachineInstallationPrestate($Worker,[string]$Source,[string]$Root,$Manifest,$Prestate,
    [string[]]$PlacementArguments,[string]$Receipt,[string]$AuditPath,$Audit,$AuthorityLease) {
    $state=Get-ContainerMachineInstallStateRoot
    $control=Join-Path $state 'control\writer-session'
    $run=[string]$Prestate.run_id
    $engine=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $startup=ConvertFrom-CanonicalMachineArtifactJournal $Prestate.startup_before
    $artifacts=ConvertFrom-CanonicalMachineArtifactJournal $Prestate.artifact_before
    $proof=[ordered]@{child_exit='UNPROVEN';code_restore='UNPROVEN';artifact_restore='UNPROVEN';worker_run_restore='NOT_CHANGED';worker_directory_restore='NOT_CHANGED'}
    if ($null -eq $Audit.compensation_child) { $Audit.compensation_child=@{status='NOT_STARTED'} }
    if ([string]$Audit.placement_child.status -cin @('NOT_STARTED','EXITED') -and
        [string]$Audit.compensation_child.status -cin @('NOT_STARTED','EXITED')) { $proof.child_exit='PASS' }
    if ($proof.child_exit -ceq 'PASS') {
        try {
            if (-not (Test-CanonicalMachineCodePrestate $Root ([string]$Prestate.before_manifest_sha256) @())) {
                if ([string]$Prestate.before_manifest_sha256 -and (Test-Path -LiteralPath $Receipt -PathType Leaf)) {
                    $original=Read-BootstrapReplacementReceipt $Receipt (Sha $Receipt)
                    if ([string]$original.transaction_id -cne $run -or -not (Same ([string]$original.install_root) $Root) -or
                        [string]$original.old.manifest_sha256 -cne [string]$Prestate.before_manifest_sha256) { throw 'MACHINE_RECOVERY_REPLACEMENT_BINDING_DIFFERS' }
                    $arguments=@($PlacementArguments)+@('-RestoreVerifiedReplacement','-ReplacementTransactionId',$run,
                        '-ReplacementReceiptPath',$Receipt,'-ReplacementReceiptSha256',(Sha $Receipt),
                        '-RestoreEvidencePath',(Join-Path $state ('install-audit\failed-restore-'+$run+'-'+[Guid]::NewGuid().ToString('N')+'.json')))
                    $Audit.compensation_child=@{status='EXIT_UNPROVEN'}
                    Save-CanonicalMachineFailureAudit $AuditPath $Audit
                    $child=Invoke-InstallationEvidenceChild 'machine-failure-code-restore' $engine $arguments -OnStarted {
                        param($ChildProcessId,$StartedAtUtc)
                        $Audit.compensation_child.process_id=$ChildProcessId;$Audit.compensation_child.started_at_utc=$StartedAtUtc
                        Save-CanonicalMachineFailureAudit $AuditPath $Audit
                    }
                    $Audit.compensation_child.status='EXITED';$Audit.compensation_child.exit_code=[int]$child.ExitCode
                    if ($child.ExitCode -ne 0) { throw 'MACHINE_FAILURE_CODE_RESTORE_FAILED' }
                    $Audit.code_replacement.status='RESTORED_AFTER_FAILURE'
                } elseif (-not [string]$Prestate.before_manifest_sha256 -and (Test-Path -LiteralPath $Root -PathType Container)) {
                    if ((Sha (Join-Path $Root 'portable-manifest.json')) -cne [string]$Prestate.source_manifest_sha256) { throw 'MACHINE_RECOVERY_NEW_CODE_BINDING_DIFFERS' }
                    [void](Assert-BootstrapIntegrityRecord $Root)
                    $arguments=@($PlacementArguments)+@('-SourceRoot',$Source,'-Uninstall','-RemovalControllerProcessId',[string]$PID,
                        '-RemovalControllerStartedAtUtc',(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o'),
                        '-RemovalControllerCanonicalPath',$PSCommandPath)
                    $Audit.compensation_child=@{status='EXIT_UNPROVEN'}
                    Save-CanonicalMachineFailureAudit $AuditPath $Audit
                    $child=Invoke-InstallationEvidenceChild 'machine-failure-new-code-remove' $engine $arguments -OnStarted {
                        param($ChildProcessId,$StartedAtUtc)
                        $Audit.compensation_child.process_id=$ChildProcessId;$Audit.compensation_child.started_at_utc=$StartedAtUtc
                        Save-CanonicalMachineFailureAudit $AuditPath $Audit
                    }
                    $Audit.compensation_child.status='EXITED';$Audit.compensation_child.exit_code=[int]$child.ExitCode
                    if ($child.ExitCode -ne 0) { throw 'MACHINE_FAILURE_NEW_CODE_REMOVE_FAILED' }
                    $Audit.code_replacement.status='NEW_CODE_REMOVED_AFTER_FAILURE'
                }
            }
            if (Test-CanonicalMachineCodePrestate $Root ([string]$Prestate.before_manifest_sha256) @()) {
                Restore-CanonicalMachineArtifacts $startup
                if (Test-CanonicalMachineCodePrestate $Root ([string]$Prestate.before_manifest_sha256) $startup) { $proof.code_restore='PASS' }
            }
        } catch { $Audit.code_replacement.status='RESTORE_FAILED' }
    }
    if ([string]$Audit.compensation_child.status -cnotin @('NOT_STARTED','EXITED')) { $proof.child_exit='UNPROVEN' }
    if ($proof.code_restore -cne 'PASS') {
        # The immutable journal retains the old intent for a later proved restore.
        $pending=Join-Path $state 'pending-onboarding.json'
        $artifacts=@($artifacts | ForEach-Object {
            if (Same ([string]$_.path) $pending) { [pscustomobject]@{path=$_.path;exists=$false;bytes=$null;sha256='';acl=$null} } else { $_ }
        })
        $Audit.pending_restore='WITHHELD_CODE_PRESTATE_DIFFERS'
    } else { $Audit.pending_restore='CODE_AND_CONTROL_PRESTATE_VERIFIED' }
    try { Restore-CanonicalMachineArtifacts $artifacts; $proof.artifact_restore='PASS' } catch { $proof.artifact_restore='FAILED' }
    if ($null -ne $Prestate.worker_preparation) {
        $proof.worker_run_restore='FAILED';$proof.worker_directory_restore='FAILED'
        if ([bool]$Worker.same_caller) {
            try {
                Restore $Prestate.worker_run_before
                if ((Snapshot | ConvertTo-Json -Compress) -cne ($Prestate.worker_run_before | ConvertTo-Json -Compress)) { throw 'MACHINE_RECOVERY_WORKER_RUN_READBACK_FAILED' }
                $proof.worker_run_restore='PASS'
            } catch {}
            try {
                Restore-CanonicalWorkerPreparationDirectories $Prestate.worker_preparation
                foreach ($directory in $Prestate.worker_preparation.created_directories) {
                    if (Test-Path -LiteralPath $directory) { throw 'MACHINE_RECOVERY_WORKER_DIRECTORY_READBACK_FAILED' }
                }
                $proof.worker_directory_restore='PASS'
            } catch {}
        }
    }
    $Audit.compensation=$proof
    $Audit.artifact_restore=$proof.artifact_restore
    $Audit.worker_run_restore=$proof.worker_run_restore
    $Audit.worker_directory_restore=$proof.worker_directory_restore
    $Audit.fence_retained=$true
    $Audit.support_recovery='RecoverMachineInstallation: exact machine audit path/SHA256 and original admitted packet/worker required'
    try { Save-CanonicalMachineFailureAudit $AuditPath $Audit } catch {}
    $proven=($proof.child_exit -ceq 'PASS' -and $proof.code_restore -ceq 'PASS' -and $proof.artifact_restore -ceq 'PASS' -and
        $proof.worker_run_restore -cin @('PASS','NOT_CHANGED') -and $proof.worker_directory_restore -cin @('PASS','NOT_CHANGED'))
    if (-not $proven) { return $false }
    try {
        $proofPath=Join-Path $state ('install-audit\compensated-'+$run+'-'+[Guid]::NewGuid().ToString('N')+'.json')
        Write-Utf8Json $proofPath ([ordered]@{schema='container-audit-machine-compensation-v1';status='COMPENSATED_FAILURE';
            run_id=$run;install_root=$Root;worker_sid=[string]$Worker.sid;session_id=$Script:CanonicalWriterFenceSessionId;
            attempt_id=$Script:CanonicalWriterFenceAttemptId;prestate_path=$Audit.machine_prestate.path;
            prestate_sha256=$Audit.machine_prestate.sha256;compensation=$proof;secret_values_recorded=$false})
        $authorization=New-CanonicalWriterFenceReleaseAuthorization (Join-Path $state ('install-audit\failure-release-'+[Guid]::NewGuid().ToString('N')+'.json')) 'ROLLBACK_COMPLETE' $proofPath
        [void](Set-ContainerWriterFencePrepared -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $run -PreparedReceiptPath $authorization.path -PreparedReceiptSha256 $authorization.sha256 -Status 'PREPARED' -AuthorityLease $AuthorityLease)
        [void](Clear-ContainerWriterFenceDelegation -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $run -DelegationToken $Script:CanonicalWriterFenceDelegationToken -AuthorityLease $AuthorityLease)
        [void](Stop-ContainerWriterFence -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $run -ReleaseAuthorizationPath $authorization.path -ReleaseAuthorizationSha256 $authorization.sha256 -AuthorityLease $AuthorityLease)
        $Audit.fence_retained=$false
        $Audit.fence_release='PROVEN_FAILURE_COMPENSATION'
        try { Save-CanonicalMachineFailureAudit $AuditPath $Audit } catch {}
        return $true
    } catch {
        $Audit.fence_release_failure_type=$_.Exception.GetType().FullName
        $Audit.fence_release_failure_line=$_.InvocationInfo.ScriptLineNumber
        if ($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{4,127}$') { $Audit.fence_release_failure_code=$_.Exception.Message }
        try { Save-CanonicalMachineFailureAudit $AuditPath $Audit } catch {}
        return $false
    }
}
function Read-CanonicalMachineInstallationRecovery($Worker,[string]$Source,[string]$Root,$Manifest,[string]$AuditPath,[string]$AuditSha256) {
    if (-not $testMode -and -not (Test-InstallationEvidencePrivileged)) { throw 'MACHINE_RECOVERY_ADMINISTRATOR_REQUIRED' }
    $state=Get-ContainerMachineInstallStateRoot
    $control=Join-Path $state 'control\writer-session'
    $auditFull=Full $AuditPath 'machine recovery audit'
    Assert-BootstrapNoReparsePoint $auditFull 'machine recovery audit' -PathOnly
    Assert-InstallationEvidenceProtectedPath $auditFull
    if ($AuditSha256 -cnotmatch '^[0-9a-f]{64}$' -or (Get-Item -LiteralPath $auditFull).Length -gt 131072 -or (Sha $auditFull) -cne $AuditSha256) { throw 'MACHINE_RECOVERY_AUDIT_CHANGED' }
    $recordPayload=Get-Content -LiteralPath $auditFull -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    # Recovery extends the persisted audit with the current compensation result.
    # Keep its existing fields while giving PS 5.1 and PS 7 the same mutable record.
    $record=[ordered]@{}
    foreach ($property in $recordPayload.PSObject.Properties) { $record[$property.Name]=$property.Value }
    $replacement=[ordered]@{}
    foreach ($property in $record.code_replacement.PSObject.Properties) { $replacement[$property.Name]=$property.Value }
    $record.code_replacement=$replacement
    $run=[string]$record.run_id
    if ($run -cnotmatch '^[0-9a-f]{32}$' -or -not (Same $auditFull (Join-Path $state ('install-audit\canonical-portable-'+$run+'.json'))) -or
        [string]$record.schema -cne 'container-audit-canonical-portable-install-v2' -or [string]$record.operation -cne 'INSTALL' -or
        [string]$record.status -cnotin @('MACHINE_PREPARING','MACHINE_INSTALL_FAILED') -or -not (Same ([string]$record.install_root) $Root) -or
        [string]$record.worker_sid -cne [string]$Worker.sid -or [string]$record.placement_child.status -cnotin @('NOT_STARTED','EXITED','EXIT_UNPROVEN') -or
        [string]$record.compensation_child.status -cnotin @('NOT_STARTED','EXITED','EXIT_UNPROVEN') -or
        [string]$record.source_manifest_sha256 -cne (Sha (Join-Path $Source 'portable-manifest.json'))) { throw 'MACHINE_RECOVERY_AUDIT_BINDING_DIFFERS' }
    $journal=Join-Path $state ('install-audit\machine-prestate-'+$run+'\prestate.json')
    Assert-BootstrapNoReparsePoint $journal 'machine recovery prestate' -PathOnly
    Assert-InstallationEvidenceProtectedPath $journal
    if (-not (Same ([string]$record.machine_prestate.path) $journal) -or (Get-Item -LiteralPath $journal).Length -gt 1048576 -or
        (Sha $journal) -cne [string]$record.machine_prestate.sha256) { throw 'MACHINE_RECOVERY_PRESTATE_CHANGED' }
    $prestate=Get-Content -LiteralPath $journal -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    $fence=Read-ContainerWriterFence $control
    if ([string]$prestate.schema -cne 'container-audit-machine-install-prestate-v1' -or [string]$prestate.run_id -cne $run -or
        -not (Same ([string]$prestate.install_root) $Root) -or [string]$prestate.worker_sid -cne [string]$Worker.sid -or
        -not (Same ([string]$prestate.profile_root) ([string]$Worker.profile_root)) -or
        [string]$prestate.source_manifest_sha256 -cne [string]$record.source_manifest_sha256 -or
        [string]$fence.owner_kind -cne 'canonical_installer' -or [string]$fence.replacement_transaction_id -cne $run -or
        [string]$fence.session_id -cne [string]$prestate.session_id -or [string]$fence.attempt_id -cne [string]$prestate.attempt_id -or
        [string]$fence.orchestrator_sha256 -cne (Sha $PSCommandPath) -or [string]$fence.orchestrator_sha256 -cne [string]$prestate.orchestrator_sha256 -or
        [string]$fence.writer_contract_sha256 -cne [string]$Manifest.writer_session_contract_sha256 -or
        [string]$fence.writer_inventory_sha256 -cne $Script:ContainerWriterFenceInventorySha256 -or
        ($null -ne $prestate.worker_preparation -and -not [bool]$Worker.same_caller)) { throw 'MACHINE_RECOVERY_AUTHORITY_BINDING_DIFFERS' }
    $prepared=$prestate.prepared_receipt
    if ((Sha ([string]$prepared.path)) -cne [string]$prepared.sha256) { throw 'MACHINE_RECOVERY_PREPARED_RECEIPT_CHANGED' }
    return [pscustomobject]@{state=$state;control=$control;run_id=$run;prepared=$prepared;prestate=$prestate;fence=$fence;audit=$record;audit_path=$auditFull}
}
function Confirm-CanonicalMachineRecoveryChildExit($Audit) {
    if ([string]$Audit.status -cne 'MACHINE_PREPARING' -and
        [string]$Audit.placement_child.status -cne 'EXIT_UNPROVEN' -and [string]$Audit.compensation_child.status -cne 'EXIT_UNPROVEN') { return }
    try { $processSnapshot=@(Get-CimInstance -ClassName Win32_Process -Property ProcessId,CommandLine -OperationTimeoutSec 5 -ErrorAction Stop) }
    catch { throw 'MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN' }
    # Command lines may contain delegation credentials; compare only in memory.
    $runPattern='(?i)(?:^|\s)"?-WriterFenceReplacementTransactionId"?(?:\s+|:)\s*"?'+[regex]::Escape([string]$Audit.run_id)+'"?(?=\s|$)'
    $runActive=@($processSnapshot | Where-Object { $_.CommandLine -and [regex]::IsMatch($_.CommandLine,$runPattern) }).Count -gt 0
    $processSnapshot=$null
    foreach ($child in @($Audit.placement_child,$Audit.compensation_child)) {
        if ([string]$child.status -ceq 'NOT_STARTED') { continue }
        $fields=if($child -is [Collections.IDictionary]){@($child.Keys)}else{@($child.PSObject.Properties.Name)}
        if ('process_id' -cnotin $fields) {
            if($runActive){throw 'MACHINE_RECOVERY_CHILD_UNRECORDED'}
            continue
        }
        if ('started_at_utc' -cnotin $fields) { throw 'MACHINE_RECOVERY_CHILD_IDENTITY_INVALID' }
        $started=[DateTime]::MinValue
        if (($child.process_id -isnot [int] -and $child.process_id -isnot [long]) -or
            $child.process_id -le 0 -or $child.process_id -gt [int]::MaxValue -or $child.started_at_utc -isnot [string] -or
            -not [DateTime]::TryParseExact($child.started_at_utc,[string[]]@('o','yyyy-MM-ddTHH:mm:ss.FFFFFFFK'),[Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,[ref]$started) -or $started.Kind -ne [DateTimeKind]::Utc) { throw 'MACHINE_RECOVERY_CHILD_IDENTITY_INVALID' }
        try { Initialize-InstallationChildCapture;$currentStart=[KMTechInstallationChildCapture]::ReadProcessStartTimeUtc([int]$child.process_id) }
        catch { throw 'MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN' }
        if ($currentStart -and ([DateTime]::ParseExact($currentStart,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)).Ticks -eq $started.Ticks) { throw 'MACHINE_RECOVERY_CHILD_ACTIVE' }
    }
    if($runActive){throw 'MACHINE_RECOVERY_CHILD_ACTIVE'}
    # Only termination is proved; no child exit code or placement success is inferred.
    foreach ($child in @($Audit.placement_child,$Audit.compensation_child)) {
        if ([string]$child.status -ceq 'EXIT_UNPROVEN') { $child.status='EXITED' }
    }
    $Audit.recovery_child_exit='PASS'
}
function Invoke-CanonicalMachineInstallationRecovery($Worker,[string]$Source,[string]$Root,$Manifest,$Context,$AuthorityLease) {
    $state=$Context.state;$control=$Context.control;$run=$Context.run_id;$prepared=$Context.prepared
    $prestate=$Context.prestate;$fence=$Context.fence;$record=$Context.audit;$auditFull=$Context.audit_path
    $authority=$AuthorityLease
    $Script:ContainerMachineInstallControlRoot=$control
    $Script:ContainerWriterFenceAdmissionProductionRoot=$control
    $Script:CanonicalWriterFenceSessionId=[string]$fence.session_id
    $Script:CanonicalWriterFenceAttemptId=[string]$fence.attempt_id
    $Script:CanonicalWriterFenceTransactionId=$run
    try {
        [void](Assert-ContainerWriterFenceOwner -ControlRoot $control -SessionId $fence.session_id -AttemptId $fence.attempt_id -ReplacementTransactionId $run -AuthorityLease $authority)
        Confirm-CanonicalMachineRecoveryChildExit $record
        Save-CanonicalMachineFailureAudit $auditFull $record
        [void](Initialize-InstallationEvidence (Join-Path $state ('install-audit\recovery-'+$run+'-'+[Guid]::NewGuid().ToString('N')+'.json')) ([string]$Worker.sid) @())
        [void](Set-ContainerWriterFencePrepared -ControlRoot $control -SessionId $fence.session_id -AttemptId $fence.attempt_id -ReplacementTransactionId $run `
            -PreparedReceiptPath $prepared.path -PreparedReceiptSha256 $prepared.sha256 -Status 'INSTALLING' -AuthorityLease $authority)
        $Script:CanonicalWriterFenceDelegationToken=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
        [void](Set-ContainerWriterFenceDelegation -ControlRoot $control -SessionId $fence.session_id -AttemptId $fence.attempt_id -ReplacementTransactionId $run `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken -DelegatedSources @('canonical_code_placement') -LifetimeSeconds 300 -AuthorityLease $authority)
        $arguments=Get-CanonicalMachinePlacementArguments $Worker $Source $Root $Manifest $prepared $control $run
        if (-not (Restore-CanonicalMachineInstallationPrestate $Worker $Source $Root $Manifest $prestate $arguments ([string]$record.code_replacement.receipt_path) $auditFull $record $authority)) {
            throw 'MACHINE_RECOVERY_COMPENSATION_UNPROVEN'
        }
        if ($EvidencePath) { Save (Full $EvidencePath 'EvidencePath') $record }
        Write-Output 'install_status=PASS_MACHINE_RECOVERED'
        Write-CanonicalMachinePublicRecord 'PASS_MACHINE_RECOVERED' 'PASS'
    } finally {
        # The public entry's finally owns and releases the original authority.
        $Script:ContainerMachineInstallControlRoot=''
        $Script:ContainerWriterFenceAdmissionProductionRoot=''
    }
}

function Read-CanonicalPlacementStatus([string]$Stdout,[bool]$Replacing) {
    if(-not $Replacing){return ''}
    $lines=@($Stdout -split '\r?\n'|Where-Object {$_ -cmatch '^bootstrap_status='})
    if($lines.Count -ne 1 -or $lines[0] -cnotin @('bootstrap_status=REUSED','bootstrap_status=REPLACED_VERIFIED')){
        throw 'MACHINE_PLACEMENT_STATUS_INVALID'
    }
    return $lines[0].Substring('bootstrap_status='.Length)
}

function Invoke-CanonicalMachineInstallation($Worker,[string]$Source,[string]$Root,$Manifest,$AuthorityLease) {
    if (-not $testMode -and -not (Test-InstallationEvidencePrivileged)) {
        throw 'Machine installation requires an already privileged token.'
    }
    if ($CompleteRetiredRemoval) { throw 'Machine installation does not accept retired removal.' }
    $state=Get-ContainerMachineInstallStateRoot
    $control=Join-Path $state 'control\writer-session'
    $existingState=$state
    while (-not (Test-Path -LiteralPath $existingState)) { $existingState=Split-Path -Parent $existingState }
    Assert-BootstrapNoReparsePoint $existingState 'machine installation state ancestor' -PathOnly
    $local=Join-Path ([string]$Worker.profile_root) 'AppData\Local'
    $data=Join-Path $local 'KMTech\ContainerAudit'
    $workerFence=Join-Path $local 'KMTech\DirectSync\container_audit\control\writer-session\active.json'
    if (Test-Path -LiteralPath $workerFence) { throw 'Existing worker deployment requires recovery.' }
    # Admission is read-only; another user's profile remains untouched.
    Assert-ContainerDataGenerationTarget -CandidateRoot $Source -TargetSid ([string]$Worker.sid) `
        -LocalAppDataRoot $local -DataRoot $data -HelperRoot $Source
    if (Test-Path -LiteralPath $Root -PathType Container) {
        $beforeManifest=InstalledManifest $Root $SkipSignatureValidationForTest
        [void](Assert-BootstrapIntegrityRecord $Root)
        $beforeInventory=Assert-WriterSinkInventory (Join-Path $Root 'tools\container_writer_sink_inventory.json') `
            ([string]$beforeManifest.writer_sink_inventory_sha256) ([string]$beforeManifest.writer_sink_inventory_contract_sha256)
        if ((Get-WriterInventorySemantics $beforeInventory) -cne (Get-WriterInventorySemantics $sourceWriterInventory) -and
            -not (Test-ExactApprovedInstalledWriterTransition $beforeManifest $Manifest $Source) -and
            ($Uninstall -or $RestoreVerifiedReplacement -or
             -not (Test-ContainerDataGenerationForwardTransition -BeforeRoot $Root -AfterRoot $Source -BeforeInventory $beforeInventory -AfterInventory $sourceWriterInventory))) {
            throw 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
        }
    }
    $workerPreparation=$null
    # User paths and HKCU are prepared by the ordinary interactive worker first run.
    if ($PlanOnly) { Write-Output 'install_status=PLAN_ONLY'; return }
    $Script:ContainerMachineInstallControlRoot=$control
    $Script:ContainerWriterFenceAdmissionProductionRoot=$control
    $Script:CanonicalWriterFenceDelegationToken=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
    $started=[DateTime]::UtcNow.ToString('o')
    $authority=$AuthorityLease;$active=$false;$machineStateReady=$false
    $run=$Script:CanonicalWriterFenceTransactionId
    $path=Join-Path $state ('install-audit\canonical-portable-'+$run+'.json')
    $receipt=Join-Path $state ('install-audit\canonical-portable-'+$run+'-replacement.json')
    $pending=Join-Path $state 'pending-onboarding.json'
    $audit=[ordered]@{schema='container-audit-canonical-portable-install-v2';status='MACHINE_PREPARING';
        operation=if($Uninstall){'UNINSTALL'}elseif($RestoreVerifiedReplacement){'RESTORE_VERIFIED_REPLACEMENT'}else{'INSTALL'};
        run_id=$run;install_root=$Root;source_commit=[string]$Manifest.source_commit;source_manifest_sha256=Sha (Join-Path $Source 'portable-manifest.json');
        worker_sid=[string]$Worker.sid;worker_setup='PENDING';survey_sha256=[string]$Worker.survey_sha256;
        preimage=@{scope='MACHINE_CODE_ONLY';observation_status='NOT_OBSERVED'};
        after=@{scope='WORKER_HKCU';observation_status='NOT_CHANGED'};
        code_replacement=@{transaction_id=$run;receipt_path=$receipt};created_at=$started;secret_values_recorded=$false;
        relay_readiness=@{status='DEFERRED_WORKER_INTERACTIVE_SESSION';other_session_launches=0;ready_proven=$false}}
    $artifactPaths=Get-CanonicalMachineArtifactPaths $state $Root
    $workerRunBefore=$null
    if ($null -ne $workerPreparation) {
        $artifactPaths+=@($workerPreparation.shortcuts)
        $workerRunBefore=Snapshot
    }
    $artifactBefore=Get-CanonicalMachineArtifactPreimage $artifactPaths
    $beforeManifestSha256=if(Test-Path -LiteralPath (Join-Path $Root 'portable-manifest.json') -PathType Leaf){Sha (Join-Path $Root 'portable-manifest.json')}else{''}
    $startupBefore=@()
    if (-not $Uninstall -and -not $RestoreVerifiedReplacement) {
        $startupControl=Join-Path (Split-Path -Parent $Root) 'update-control'
        $startupBefore=Get-CanonicalMachineArtifactPreimage (@('policy.json','active.json','transition.json' | ForEach-Object {Join-Path $startupControl $_})+@(Join-Path (Split-Path -Parent $Root) 'removed.json'))
    }
    $complete=$false;$placementBaseArguments=$null;$prestate=$null;$helperReason=''
    $audit.placement_child=@{status='NOT_STARTED'}
    $audit.compensation_child=@{status='NOT_STARTED'}
    $audit.machine_prestate=@{path='';sha256=''}
    try {
        [void](Initialize-InstallationEvidence $path ([string]$Worker.sid) @($Script:CanonicalWriterFenceDelegationToken))
        $audit.stage_evidence_root=$Script:InstallationEvidenceRoot
        # Intent/fence metadata contains no secrets. All users may read it;
        # only administrators/SYSTEM can write, including after first startup.
        $stateParent=[IO.Path]::GetFullPath($env:PROGRAMDATA)
        foreach ($segment in @('KMTech','ContainerAudit','machine-install')) {
            $stateParent=Join-Path $stateParent $segment
            New-InstallationProtectedDirectory $stateParent 'S-1-5-32-545'
        }
        $machineStateReady=$true
        $prepared=New-CanonicalWriterFencePreparedReceipt (Join-Path $state ('install-audit\prepared-'+$run+'.json')) `
            $Script:CanonicalWriterFenceSessionId $Script:CanonicalWriterFenceAttemptId $run $started (Sha $PSCommandPath) `
            ([string]$Manifest.writer_session_contract_sha256) (Sha (Join-Path $Source 'portable-manifest.json')) ([string]$Worker.sid) $local
        # Persist the bound recovery prestate before publishing a machine fence.
        $prestate=[ordered]@{schema='container-audit-machine-install-prestate-v1';run_id=$run;install_root=$Root;
            worker_sid=[string]$Worker.sid;profile_root=[string]$Worker.profile_root;source_manifest_sha256=$audit.source_manifest_sha256;
            before_manifest_sha256=$beforeManifestSha256;artifact_before=@(ConvertTo-CanonicalMachineArtifactJournal $artifactBefore);
            startup_before=@(ConvertTo-CanonicalMachineArtifactJournal $startupBefore);worker_preparation=$workerPreparation;worker_run_before=$workerRunBefore;
            session_id=$Script:CanonicalWriterFenceSessionId;attempt_id=$Script:CanonicalWriterFenceAttemptId;orchestrator_sha256=Sha $PSCommandPath;
            prepared_receipt=$prepared;secret_values_recorded=$false}
        $privatePrestate=Join-Path $state ('install-audit\machine-prestate-'+$run)
        New-InstallationProtectedDirectory $privatePrestate 'S-1-5-32-544'
        $journal=Join-Path $privatePrestate 'prestate.json'
        Write-Utf8Json $journal $prestate
        if ((Get-Item -LiteralPath $journal).Length -gt 1048576) { throw 'MACHINE_PRESTATE_TOO_LARGE' }
        $audit.machine_prestate=@{path=$journal;sha256=Sha $journal}
        if ($Uninstall) { $audit.status='PREIMAGE_SAVED' }
        Save $path $audit
        [void](Start-ContainerWriterFence -ControlRoot $control -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
            -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $run -SessionStartedAtUtc $started -OrchestratorSha256 (Sha $PSCommandPath) `
            -WriterContractSha256 ([string]$Manifest.writer_session_contract_sha256) -PreparedReceiptPath $prepared.path `
            -PreparedReceiptSha256 $prepared.sha256 -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
            -DelegatedSources @('canonical_code_placement') -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(15).ToString('o')) `
            -AuthorityLease $authority)
        $active=$true
        $arguments=Get-CanonicalMachinePlacementArguments $Worker $Source $Root $Manifest $prepared $control $run
        $placementBaseArguments=@($arguments)
        if ($RestoreVerifiedReplacement) {
            $original=Read-BootstrapReplacementReceipt $RestoreReceiptPath $RestoreReceiptSha256
            $arguments+=@('-RestoreVerifiedReplacement','-ReplacementTransactionId',([string]$original.transaction_id),
                '-ReplacementReceiptPath',$RestoreReceiptPath,'-ReplacementReceiptSha256',$RestoreReceiptSha256,
                '-RestoreEvidencePath',(Join-Path $state ('install-audit\restore-'+$run+'.json')))
        } else {
            $arguments+=@('-SourceRoot',$Source)
            if ($Uninstall) {
                $arguments+=@('-Uninstall','-RemovalControllerProcessId',[string]$PID,
                    '-RemovalControllerStartedAtUtc',(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o'),
                    '-RemovalControllerCanonicalPath',$PSCommandPath,'-UninstallAuditPath',$path,'-UninstallAuditSha256',(Sha $path))
            }
            elseif (Test-Path -LiteralPath $Root -PathType Container) {
                $arguments+=@('-ReplaceExistingVerifiedPortable','-ReplacementTransactionId',$run,'-ReplacementReceiptPath',$receipt)
            }
        }
        # INSTALL_THIS_PC reuses its existing already-elevated placement path.
        $engine=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $audit.placement_child.status='EXIT_UNPROVEN'
        Save $path $audit
        if ($Uninstall) {
            # Bind the exact checkpoint handed to the already-elevated remover.
            $hashArgument=[Array]::IndexOf([string[]]$arguments,'-UninstallAuditSha256')
            if ($hashArgument -lt 0) { throw 'MACHINE_UNINSTALL_AUDIT_BINDING_ABSENT' }
            $arguments[$hashArgument+1]=Sha $path
        }
        $placementStarted=if (-not $Uninstall) { {
            param($ChildProcessId,$StartedAtUtc)
            $audit.placement_child.process_id=$ChildProcessId;$audit.placement_child.started_at_utc=$StartedAtUtc
            Save $path $audit
        } } else { $null }
        $child=Invoke-InstallationEvidenceChild 'machine-placement-helper' $engine $arguments -OnStarted $placementStarted
        $audit.placement_child.status='EXITED';$audit.placement_child.exit_code=[int]$child.ExitCode
        if ($child.ExitCode -ne 0) { $helperReason=Get-CanonicalMachineHelperReason ([string]$child.Stdout) }
        $placementKind=if($child.ExitCode -eq 0){Read-CanonicalPlacementStatus ([string]$child.Stdout) ($arguments -ccontains '-ReplaceExistingVerifiedPortable')}else{''}
        $reusedPlacement=($placementKind -ceq 'REUSED')
        # REUSED proves unchanged code placement; startup repair is audited separately.
        if (-not $testMode -or $reusedPlacement) {
            $binding=Read-InstallationHelperEvidenceBinding @($child.Stdout -split "`r?`n") `
                (Join-Path $state ('install-audit\placement-'+$run+'.jsonl')) $child.ProcessId ([string]$Manifest.helper_sha256)
            Register-InstallationChildEvidenceSummary $binding.child_stage_evidence_summary
            if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and (Test-Path -LiteralPath $receipt)) {
                throw 'Unbound caller replacement receipt was published.'
            }
            if ($arguments -ccontains '-ReplaceExistingVerifiedPortable') {
                $placementStatus=@($child.Stdout -split '\r?\n'|Where-Object {$_ -cmatch '^bootstrap_status='})
                if($placementStatus.Count -eq 1 -and $placementStatus[0] -ceq 'bootstrap_status=REUSED'){
                    $reused=Read-CanonicalReusedPlacementEvidence $binding $Source $Root $Manifest $run
                    $audit.code_replacement.disposition='REUSED_VERIFIED'
                    $audit.code_replacement.scope='CODE_PLACEMENT_ONLY'
                    $audit.startup_repair=@{status='RECORDED_IN_CHILD_EVIDENCE';code_placement='UNCHANGED'}
                    $audit.code_replacement.receipt_path=''
                    $audit.code_replacement.reused_evidence_path=$reused.path
                    $audit.code_replacement.reused_evidence_sha256=$reused.sha256
                }else{
                    $receipt=Read-CanonicalHelperArtifact $binding 'replacement-receipt.json' 'REPLACEMENT_RECEIPT_READY'
                    $audit.code_replacement.receipt_path=$receipt
                    $audit.code_replacement.receipt_sha256=Sha $receipt
                }
            }
        }
        if ($child.ExitCode -ne 0) { throw 'MACHINE_INSTALL_FAILED' }
        if ($Uninstall) {
            $removed=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path (Split-Path -Parent $Root) 'removed.json') | ConvertFrom-Json
            if ([string]$removed.lifecycle_state -cne 'REMOVED') { throw 'Machine removal readback failed.' }
            Remove-CanonicalMachineArtifacts $Root $Worker $artifactPaths
            $audit.status='PASS_UNINSTALLED_DATA_PRESERVED'
        } elseif ($RestoreVerifiedReplacement) {
            [void](Assert-BootstrapIntegrityRecord $Root)
            Remove-CanonicalMachineArtifacts $Root $Worker $artifactPaths
            $audit.status='PASS_RESTORED_VERIFIED'
        } else {
            $installed=InstalledManifest $Root $SkipSignatureValidationForTest
            [void](Assert-BootstrapIntegrityRecord $Root)
            if ([string]$installed.source_commit -cne [string]$Manifest.source_commit -or
                (Sha (Join-Path $Root 'portable-manifest.json')) -cne (Sha (Join-Path $Source 'portable-manifest.json'))) {
                throw 'Machine installed identity differs.'
            }
            # Machine placement leaves relay and GUI preparation pending.
            $marker=[ordered]@{schema='container-audit-machine-pending-v1';status='PENDING';install_id=$run;
                target_sid=[string]$Worker.sid;version=[string]$Manifest.version;source_commit=[string]$Manifest.source_commit;
                install_root=$Root;survey_sha256=[string]$Worker.survey_sha256;installed_at_utc=$started;
                server_base_url=$onboardingServerBaseUrl;secret_values_recorded=$false}
            Save $pending $marker
            Set-InstallationEvidenceAcl $pending 'S-1-5-32-545'
            $shortcutPublication=New-CanonicalMachineShortcut $Root -ExpectedPath ([string]$artifactPaths[1])
            $audit['shortcut_preservation']=@($shortcutPublication.preserved)
            Set-CanonicalPublishedShortcuts $audit @($shortcutPublication)
            $audit.status='PASS_MACHINE_WORKER_PENDING'
        }
        Save $path $audit
        if ($EvidencePath) { Save (Full $EvidencePath 'EvidencePath') $audit }
        $authorization=New-CanonicalWriterFenceReleaseAuthorization (Join-Path $state ('install-audit\release-'+$run+'.json')) 'PRODUCT_COMPLETE' $path
        [void](Set-ContainerWriterFencePrepared -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId -ReplacementTransactionId $run -PreparedReceiptPath $authorization.path `
            -PreparedReceiptSha256 $authorization.sha256 -Status 'PREPARED' -AuthorityLease $authority)
        [void](Clear-ContainerWriterFenceDelegation -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId -ReplacementTransactionId $run `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken -AuthorityLease $authority)
        [void](Stop-ContainerWriterFence -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId -ReplacementTransactionId $run -ReleaseAuthorizationPath $authorization.path `
            -ReleaseAuthorizationSha256 $authorization.sha256 -AuthorityLease $authority)
        $active=$false
        $complete=$true
        Write-CanonicalInstallerRelayGuidance
        Write-Output ('install_status='+[string]$audit.status)
        Write-CanonicalMachinePublicRecord ([string]$audit.status) 'PASS'
    } catch {
        $audit.status='MACHINE_INSTALL_FAILED';$audit.fence_retained=$active
        # A failed placement child is the cause; publish only its allowlisted code.
        if ($helperReason) { $_.Exception.Data['canonical_machine_helper_reason']=$helperReason }
        if ($machineStateReady) { try { Save $path $audit } catch {} }
        throw
    } finally {
        if (-not $complete) {
            # Independent compensation and its protected proof survive audit errors.
            # Publication can succeed before its readback throws. Only reclaim our tuple.
            if (-not $active -and $null -ne $prestate -and $audit.machine_prestate.sha256) {
                try {
                    [void](Assert-ContainerWriterFenceOwner -ControlRoot $control -SessionId $Script:CanonicalWriterFenceSessionId `
                        -AttemptId $Script:CanonicalWriterFenceAttemptId -ReplacementTransactionId $run -AuthorityLease $authority)
                    $active=$true
                } catch {}
            }
            if ($active -and $null -ne $prestate) {
                try {
                    if (Restore-CanonicalMachineInstallationPrestate $Worker $Source $Root $Manifest $prestate $placementBaseArguments $receipt $path $audit $authority) { $active=$false }
                } catch {
                    $audit.fence_retained=$true
                    $audit.compensation_failure_type=$_.Exception.GetType().FullName
                    $audit.compensation_failure_line=$_.InvocationInfo.ScriptLineNumber
                }
            }
            if ($machineStateReady) { try { Save-CanonicalMachineFailureAudit $path $audit } catch {} }
        }
        $Script:ContainerMachineInstallControlRoot=''
        $Script:ContainerWriterFenceAdmissionProductionRoot=''
    }
}

function Assert-CanonicalOperatingWorkerAccount([string]$Operation,[bool]$Continuation=$false) {
    if ($Operation -ceq 'INSTALL' -and -not $Continuation -and -not $testMode -and -not $PlanOnly -and
        [string]::IsNullOrWhiteSpace($WorkerAccount)) {
        throw '설치 인수 WorkerAccount에 실제 로컬 작업자 계정 하나를 명시하세요.'
    }
}

try {
if (-not $SourceRoot) { $SourceRoot = $PSScriptRoot }
if ($CompleteRetiredRemoval) {
    if ($Uninstall -or $RestoreVerifiedReplacement -or $ServerBaseUrl -or -not $OldSourceRoot -or
        $RetiredRemovalReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $RetiredStopMarkerSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'RETIREMENT_EXACT_OLD_SOURCE_AND_OBSERVATION_PINS_REQUIRED'
    }
    $Uninstall = $true
    if (($ResumeRetirementReceiptPath -and $ResumeRetirementReceiptSha256 -cnotmatch '^[0-9a-f]{64}$') -or
        ($ResumeRetirementReceiptSha256 -and -not $ResumeRetirementReceiptPath)) {
        throw 'RETIREMENT_RESUME_EXACT_RECEIPT_REQUIRED'
    }
}
elseif ($OldSourceRoot -or $RetiredRemovalReceiptSha256 -or $RetiredStopMarkerSha256 -or
    $ResumeRetirementReceiptPath -or $ResumeRetirementReceiptSha256) {
    throw 'RETIREMENT_ARGUMENTS_REQUIRE_COMPLETE_RETIRED_REMOVAL'
}
if ($RestoreVerifiedReplacement) {
    if ($Uninstall -or $ServerBaseUrl -or -not $RestoreReceiptPath -or
        $RestoreReceiptSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Canonical restore requires an exact receipt path/hash and cannot combine install or uninstall options.'
    }
}
elseif ($RestoreReceiptPath -or $RestoreReceiptSha256) {
    throw 'Restore receipt arguments require -RestoreVerifiedReplacement.'
}
# Classify the requested operation before applying the new-install requirement.
$canonicalOperation=if($CompleteRetiredRemoval){'COMPLETE_RETIRED_REMOVAL'}elseif($Uninstall){'UNINSTALL'}elseif($RestoreVerifiedReplacement){'RESTORE'}elseif($RecoverMachineInstallation){'MACHINE_RECOVERY'}else{'INSTALL'}
try { $machineWorker=Resolve-CanonicalMachineWorker $WorkerAccount $WorkerSurveyInventory (Get-CanonicalInstallationCallerSecurity) }
catch {
    $code=if($_.Exception.Message -ceq 'MACHINE_WORKER_ARGUMENTS_REQUIRE_ADMINISTRATOR'){$_.Exception.Message}else{'PENDING_TARGET_AMBIGUOUS'}
    Write-CanonicalMachinePublicRecord $code
    exit 4
}
if ($null -ne $machineWorker) { Assert-CanonicalOperatingWorkerAccount $canonicalOperation }
$source = Full $SourceRoot 'SourceRoot'; $install = Full $InstallRoot 'InstallRoot'
$SourceRoot = $source
if (-not $testMode -and -not (Same $install $CanonicalRoot)) { throw 'InstallRoot is not canonical.' }
if (-not (Same $PSCommandPath (Join-Path $source 'INSTALL_CANONICAL_PORTABLE.ps1'))) {
    throw 'Top-level installer must execute from the admitted SourceRoot.'
}
$sourceManifest = Manifest $source $SkipSignatureValidationForTest
$sourceWriterInventory = Assert-WriterSinkInventory `
    (Join-Path $source 'tools\container_writer_sink_inventory.json') `
    ([string]$sourceManifest.writer_sink_inventory_sha256).ToLowerInvariant() `
    ([string]$sourceManifest.writer_sink_inventory_contract_sha256).ToLowerInvariant()
$lifecycleSource = $source
$lifecycleManifest = $sourceManifest
$lifecycleWriterInventory = $sourceWriterInventory
if ($CompleteRetiredRemoval) {
    # Admit management and the immutable old packet independently. This mode
    # deploys no management code; installed semantics must match the old packet.
    $lifecycleSource = Full $OldSourceRoot 'OldSourceRoot'
    if ((Same $lifecycleSource $source) -or
        $lifecycleSource.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $source.StartsWith($lifecycleSource + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'RETIREMENT_SEPARATE_MANAGEMENT_SOURCE_REQUIRED'
    }
    $lifecycleManifest = Manifest $lifecycleSource $SkipSignatureValidationForTest
    $lifecycleWriterInventory = Assert-WriterSinkInventory `
        (Join-Path $lifecycleSource 'tools\container_writer_sink_inventory.json') `
        ([string]$lifecycleManifest.writer_sink_inventory_sha256) `
        ([string]$lifecycleManifest.writer_sink_inventory_contract_sha256)
}
$lifecycleManifestSha256 = Sha (Join-Path $lifecycleSource 'portable-manifest.json')
if ($CompleteRetiredRemoval) {
    # Keep the admitted management parser available when the exact historical
    # guard predates it. The old guard still supplies every old fence function.
    $writerFenceHelperPath = Join-Path $source 'tools\container_writer_fence.ps1'
    . $writerFenceHelperPath
}
$writerFenceHelperPath = Join-Path $lifecycleSource 'tools\container_writer_fence.ps1'
if (-not (Test-Path -LiteralPath $writerFenceHelperPath -PathType Leaf)) {
    throw 'Portable tree is missing the all-writer fence helper.'
}
. $writerFenceHelperPath
if ($RecoverMachineInstallation) {
    if ($null -eq $machineWorker -or $PlanOnly -or $Uninstall -or $RestoreVerifiedReplacement -or $CompleteRetiredRemoval -or $ServerBaseUrl -or
        -not $MachineRecoveryAuditPath -or $MachineRecoveryAuditSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'MACHINE_RECOVERY_ARGUMENTS_INVALID' }
} elseif ($MachineRecoveryAuditPath -or $MachineRecoveryAuditSha256) { throw 'Machine recovery audit arguments require -RecoverMachineInstallation.' }
$sourceManifestSha256 = Sha (Join-Path $source 'portable-manifest.json')
$sourceHelperSha256 = Sha (Join-Path $source 'INSTALL_THIS_PC.ps1')
$sourceIntegrityHelperSha256 = Sha (Join-Path $source 'tools\bootstrap_integrity.ps1')
if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval) {
    $Script:CanonicalInstallerSourceInventorySha256 = Get-InventoryAggregate @(Get-CodeInventory $source)
}
if ($null -eq $machineWorker) {
$wanted = Command $install
$lad = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
$operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$supportedRemovalResume=if ($Uninstall -and -not $CompleteRetiredRemoval) { Read-CanonicalSupportedRemovalResume } else { $null }
$Script:CanonicalRollbackContinuationCreated=$null
$rollbackContinuation=$null
$continuationAuthorityBinding=$null
$continuationPriorFence=$null
$continuationPriorFenceSha=''
if (-not $testMode -and -not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval) {
    try {$rollbackContinuation=Read-CanonicalRollbackContinuation $install $lad $operatorSid}
    catch {throw [InvalidOperationException]::new('끝나지 않은 되돌리기의 기록이 맞지 않아 변경하지 않았습니다. 지원 담당자에게 문의하세요.',$_.Exception)}
}
if ($rollbackContinuation) {
    $continuationPriorFence=Read-ContainerWriterFence -AllowAbsent
    if ($continuationPriorFence) {
        [void](Read-BootstrapRollbackContinuationAuthority $rollbackContinuation ([string]$rollbackContinuation.record_path) ([string]$rollbackContinuation.record_sha256) $continuationPriorFence)
        $continuationPriorFenceSha=Get-ContainerWriterFenceFileSha256 (Get-ContainerWriterFenceActivePath)
    }
}
Assert-CanonicalOperatingWorkerAccount $canonicalOperation ([bool]$rollbackContinuation)
$supportedContext=$null
$supportedPlacement=$false
$installedCodeRoot=$install
if(-not $testMode -and -not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $rollbackContinuation) {
    $supportedContext = Get-BootstrapSupportedLifecycleContext -Root (Split-Path -Parent $install) -Operation 'install'
    if([string]$supportedContext.lifecycle_state -ceq 'HEALTHY' -and [bool]$supportedContext.managed -and
        [string]$supportedContext.bootstrap_commit -cne [string]$supportedContext.from_commit) {
        $supportedPlacement=$true
        $installedCodeRoot=Join-Path (Split-Path -Parent $install) ('versions\'+[string]$sourceManifest.source_commit)
    }
}
if ($PlanOnly) {
    'rollback_resume_status='+$(if($rollbackContinuation){'VERIFIED_PENDING'}else{'NOT_FOUND'})
    "install_status=PLAN_ONLY"
    if ($CompleteRetiredRemoval) { 'operation=COMPLETE_RETIRED_REMOVAL'; 'retirement_identity_status=NOT_CHECKED_PLAN_ONLY' }
    elseif ($Uninstall) { 'operation=UNINSTALL'; 'uninstall_identity_status=NOT_CHECKED_PLAN_ONLY' }
    if ($RestoreVerifiedReplacement) { 'operation=RESTORE_VERIFIED_REPLACEMENT'; 'restore_identity_status=NOT_CHECKED_PLAN_ONLY' }
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("install_root=$install")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("autostart_command=$wanted")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("onboarding_server_base_url=$onboardingServerBaseUrlLabel")))
    'replacement_prestate_required=VERIFIED_REPLACE'
    'replacement_restore_status=AVAILABLE_RECEIPT_BOUND'
    'registry_changed=false'
    exit 0
}
if ($rollbackContinuation) {
    $RestoreVerifiedReplacement=[Management.Automation.SwitchParameter]::new($true)
    $RestoreReceiptPath=[string]$rollbackContinuation.receipt_path
    $RestoreReceiptSha256=[string]$rollbackContinuation.receipt_sha256
}

$winps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
# Preserve the original lifecycle validator binding after source admission.
$BootstrapIntegrityFunctions = Join-Path $source 'tools\bootstrap_integrity.ps1'
. $BootstrapIntegrityFunctions
# Installation and exact restoration require a verified installed prestate.
# Ordinary supported removal instead inventories owned content under its fence;
# damaged or unknown files must reach that preserving, convergent removal path.
if (-not ($Uninstall -and -not $CompleteRetiredRemoval) -and
    -not $supportedRemovalResume -and (Test-Path -LiteralPath $install -PathType Container)) {
    $preflightCandidate = InstalledManifest $install $SkipSignatureValidationForTest
    [void](Assert-BootstrapIntegrityRecord $install)
    $preflightInventory = Assert-WriterSinkInventory `
        (Join-Path $install 'tools\container_writer_sink_inventory.json') `
        ([string]$preflightCandidate.writer_sink_inventory_sha256) `
        ([string]$preflightCandidate.writer_sink_inventory_contract_sha256)
    if ((Get-WriterInventorySemantics $preflightInventory) -cne (Get-WriterInventorySemantics $lifecycleWriterInventory) -and
        -not (Test-ExactApprovedInstalledWriterTransition $preflightCandidate $lifecycleManifest $lifecycleSource) -and
        ($Uninstall -or $RestoreVerifiedReplacement -or $CompleteRetiredRemoval -or
         -not (Test-ContainerDataGenerationForwardTransition -BeforeRoot $install -AfterRoot $source -BeforeInventory $preflightInventory -AfterInventory $lifecycleWriterInventory))) {
        throw 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
    }
}
$lad = Full $env:LOCALAPPDATA 'LOCALAPPDATA'
$operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# External input admission precedes receipt reads, reports and INSTALLING.
$containerExternalInputs = @('ResumeRetirementReceiptPath', 'RestoreReceiptPath')
foreach ($inputName in $containerExternalInputs) {
    $inputValue = [string](Get-Variable -Name $inputName -ValueOnly)
    if ([string]::IsNullOrWhiteSpace($inputValue)) { continue }
    try {
        $inputFull = Full ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($inputValue)) $inputName
    } catch {
        throw '이 PC의 자료 판을 확인할 수 없어 옛 판으로 되돌릴 수 없습니다. 자료와 확인 기록을 보존하고 관리자 지원 복구를 요청하세요.'
    }
    Set-Variable -Name $inputName -Value $inputFull
    Assert-ContainerDataGenerationTarget -CandidateRoot $source -TargetSid $operatorSid `
        -LocalAppDataRoot $lad -DataRoot (Split-Path -Parent $inputFull) -HelperRoot $source
}
if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval) {
    $containerEnvironmentInputs = @{
        CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH = $env:CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH
        CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE = $env:CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE
    }
    if ([string]::IsNullOrWhiteSpace([string]$containerEnvironmentInputs.CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE)) {
        $programData = if (-not [string]::IsNullOrWhiteSpace($env:PROGRAMDATA)) { $env:PROGRAMDATA.Trim() } else { 'C:\ProgramData' }
        $containerEnvironmentInputs.CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE = Join-Path $programData 'KMTech\ContainerAudit\protected\protected_admin.json'
    }
    foreach ($inputName in $containerEnvironmentInputs.Keys) {
        $inputValue = [string]$containerEnvironmentInputs[$inputName]
        if ([string]::IsNullOrWhiteSpace($inputValue)) { continue }
        try {
            $inputFull = Full ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($inputValue)) $inputName
        } catch {
            throw '이 PC의 자료 판을 확인할 수 없어 옛 판으로 되돌릴 수 없습니다. 자료와 확인 기록을 보존하고 관리자 지원 복구를 요청하세요.'
        }
        Assert-ContainerDataGenerationTarget -CandidateRoot $source -TargetSid $operatorSid `
            -LocalAppDataRoot $lad -DataRoot (Split-Path -Parent $inputFull) -HelperRoot $source
        [Environment]::SetEnvironmentVariable($inputName, $inputFull, 'Process')
    }
}
# End external input admission.
$retirementResume = if ($ResumeRetirementReceiptPath) { Read-CanonicalRetirementResume } else { $null }
$retirementResumeBeforeRemoval = $retirementResume -and [string]$retirementResume.status -ceq 'PREIMAGE_SAVED'
if ($RestoreVerifiedReplacement) {
    $codeParent = Split-Path -Parent $install
    $restoreReceiptFull = Full $RestoreReceiptPath 'RestoreReceiptPath'
    foreach ($external in @($source, $lad)) {
        if ((Same $external $codeParent) -or
            $external.StartsWith($codeParent + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Canonical restore requires source, receipt and user data outside the code parent.'
        }
    }
    if ((Same $restoreReceiptFull $codeParent) -or $restoreReceiptFull.StartsWith($codeParent+'\',[StringComparison]::OrdinalIgnoreCase)) {
        if ($rollbackContinuation) {
            if (-not (Same $restoreReceiptFull ([string]$rollbackContinuation.receipt_path))) {throw 'Rollback continuation receipt differs.'}
        } else {
            $protectedBinding=@{status='BOUND_DIRECT_CHILD';stage_evidence_root=(Split-Path -Parent $restoreReceiptFull)}
            if (-not (Same $restoreReceiptFull (Read-CanonicalHelperArtifact $protectedBinding 'replacement-receipt.json' 'REPLACEMENT_RECEIPT_READY'))) {
                throw 'Canonical protected receipt binding differs.'
            }
        }
    }
    # This preflight is read-only and is repeated under fresh ownership before
    # quiescence. No prepared receipt or authority from the old install is reused.
    $publicRestore = Read-CanonicalReplacementRestore
}
if ($Uninstall -and $CompleteRetiredRemoval) {
    foreach ($pair in @(@($source, $install), @($lad, $install), @($source, $lad),
        @($lifecycleSource, $install), @($lifecycleSource, $lad))) {
        if ((Same $pair[0] $pair[1]) -or
            $pair[0].StartsWith($pair[1] + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $pair[1].StartsWith($pair[0] + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Uninstall requires separate source, code and current-user data roots.'
        }
    }
    if (-not $retirementResume -and -not (Test-Path -LiteralPath $install -PathType Container)) {
        throw 'Uninstall requires the exact installed tree and its integrity record.'
    }
    $uninstallAggregate = Get-InventoryAggregate @(Get-CodeInventory $lifecycleSource)
    if (Test-Path -LiteralPath $install -PathType Container) {
        $uninstallIntegrity = Assert-BootstrapIntegrityRecord $install
        $uninstallRecordSha256 = Sha (Join-Path $install 'bootstrap-integrity.json')
        if ((Sha (Join-Path $install 'portable-manifest.json')) -cne $lifecycleManifestSha256 -or
            [string]$uninstallIntegrity.aggregate_sha256 -cne $uninstallAggregate) {
            throw 'Uninstall installed/source identity differs; use the exact installed packet.'
        }
        if ($retirementResume -and $uninstallRecordSha256 -cne [string]$retirementResume.retirement.old_record_sha256) {
            throw 'RETIREMENT_RESUME_INSTALLED_RECORD_CHANGED'
        }
    }
    else {
        $uninstallRecordSha256 = [string]$retirementResume.code_integrity_preimage_sha256
    }
}
$activeDataRoot = Join-Path $lad 'KMTech\ContainerAudit'
$activeRelayRoot = Join-Path $lad 'KMTech\DirectSync\container_audit'
if (-not [string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_DATA_ROOT)) {
    $activeDataRoot = Full $env:CONTAINER_AUDIT_DATA_ROOT 'data root'
    $activeRelayRoot = Join-Path $activeDataRoot 'direct_sync'
}
if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval -and
    [string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH)) {
    $bootstrapCaInput = if ([string]::IsNullOrWhiteSpace($env:CONTAINER_AUDIT_DATA_ROOT)) {
        Join-Path $lad 'KMTech\Bootstrap\Container_Audit\ca-bundle.pem'
    } else { Join-Path $activeDataRoot 'bootstrap\ca-bundle.pem' }
    if (Test-Path -LiteralPath $bootstrapCaInput -PathType Leaf) {
        $bootstrapCaInput = Full $bootstrapCaInput 'bootstrap TLS CA source'
        Assert-ContainerDataGenerationTarget -CandidateRoot $source -TargetSid $operatorSid `
            -LocalAppDataRoot $lad -DataRoot (Split-Path -Parent $bootstrapCaInput) -HelperRoot $source
        $env:CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH = $bootstrapCaInput
    }
}
$statusRoot = Join-Path $activeRelayRoot 'status'
$canonicalOnboardingInputBinding = ''
$canonicalRestoreInputBinding = ''
if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval) {
    Assert-ContainerDataGenerationTarget -CandidateRoot $source -TargetSid $operatorSid `
        -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source
}
$stop = Join-Path $activeRelayRoot 'control\container_audit_user_relay.stop.json'
if ($Uninstall -and -not $CompleteRetiredRemoval -and -not $supportedRemovalResume -and
    (Test-Path -LiteralPath $stop)) {
    # Reject a retirement-owned stop before evidence preparation has effects.
    throw 'CANONICAL_STOP_MARKER_PREEXISTS'
}
$onboardingPath = Join-Path $statusRoot 'current_user_onboarding.json'
$removalPath = Join-Path $statusRoot 'current_user_removal.json'
$relayPath = Join-Path $statusRoot 'container_audit_user_relay.json'
$retirement = if ($CompleteRetiredRemoval) { Read-CanonicalRetiredRemoval } else { $null }
$retirementAuditSealed=$false
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N')
$auditRoot = Join-Path $activeDataRoot 'install-audit'
$workerShortcutRecordPath=Get-BootstrapWorkerShortcutRecordPath $install $auditRoot
$abandonedRecovery=$null
try{$abandonedPending=if($rollbackContinuation -or $Uninstall){$null}else{Read-InstallationAbandonedRollback $install $lad $operatorSid}}
catch{throw [InvalidOperationException]::new('이전 설치 복구 상태를 확인할 수 없습니다. 지원 담당자에게 문의하세요.',$_.Exception)}
$auditPath = Join-Path $auditRoot "canonical-portable-$runId.json"
$canonicalWriterFencePreparedPath = Join-Path $auditRoot "canonical-portable-$runId-writer-prepared.json"
$elevationLogPath = Join-Path $auditRoot "canonical-portable-$runId-elevated.jsonl"
$replacementTransactionId = [Guid]::NewGuid().ToString('N')
$replacementReceiptPath = Join-Path $auditRoot "canonical-portable-$runId-replacement.json"
$replacementRestoreEvidencePath = Join-Path $auditRoot "canonical-portable-$runId-code-restore.json"
$productNaturalTriggerAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-product-natural-trigger-release.json"
$productCompleteAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-product-complete-release.json"
$rollbackNaturalTriggerAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-rollback-natural-trigger-release.json"
$rollbackCompleteAuthorizationPath = Join-Path $auditRoot "canonical-portable-$runId-rollback-complete-release.json"
$evidenceFull = if ($EvidencePath) { Full $EvidencePath 'EvidencePath' } else { '' }
$Script:CanonicalWriterFenceSessionId = [Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceAttemptId = [Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceTransactionId = $replacementTransactionId
$canonicalWriterFenceStartedAtUtc = [DateTime]::UtcNow.ToString('o')
$canonicalWriterFenceOrchestratorSha256 = Sha $PSCommandPath
$canonicalWriterFenceContractSha256 = ([string]$lifecycleManifest.writer_session_contract_sha256).ToLowerInvariant()
if ($supportedRemovalResume) {
    $Script:CanonicalWriterFenceSessionId=[string]$supportedRemovalResume.active.session_id
    $Script:CanonicalWriterFenceAttemptId=[string]$supportedRemovalResume.active.attempt_id
    $Script:CanonicalWriterFenceTransactionId=[string]$supportedRemovalResume.active.replacement_transaction_id
    $replacementTransactionId=$Script:CanonicalWriterFenceTransactionId
    $canonicalWriterFenceStartedAtUtc=[string]$supportedRemovalResume.active.session_started_at_utc
}
$Script:CanonicalWriterFenceDelegationToken = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
$canonicalWriterFenceEnvironmentNames = @(
    'CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',
    'CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID',
    'CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID',
    'CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID'
)
$canonicalWriterFenceEnvironmentBefore = @{}
foreach ($name in $canonicalWriterFenceEnvironmentNames) {
    $canonicalWriterFenceEnvironmentBefore[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$canonicalWriterFenceAuthority = $null
$Script:CanonicalInstallerRelayStopAttempted=$false
$Script:CanonicalInstallerRelayStopOwnership=$null
$Script:CanonicalInstallerEarlyRecovery=$null
$Script:CanonicalInstallerRelayPreimage=$null
$legacyRelayBefore=if($testMode -or $Uninstall -or $RestoreVerifiedReplacement){$null}else{Get-CanonicalOfficialLegacyRelayAdmission -ReportPath $EvidencePath}
$installationEvidenceRoot=if($null -eq $abandonedPending){Initialize-InstallationEvidence $auditPath $operatorSid @($Script:CanonicalWriterFenceDelegationToken)}else{''}
Set-InstallationEvidenceStage 'canonical.writer_fence_preflight'
$canonicalWriterFenceActive = $false
$canonicalWriterFenceLastReleaseAuthorizationPath = ''
$canonicalWriterFenceLastReleaseAuthorizationSha256 = ''
$canonicalWriterFencePreparedReceipt = $null
$enteredPlacementTry = $false
$canonicalWriterFenceDelegatedSources = [Object[]]@($sourceWriterInventory.writer_sink_sources)
if ($CompleteRetiredRemoval) {
    $canonicalWriterFenceDelegatedSources = [Object[]]@($lifecycleWriterInventory.writer_sink_sources)
}
$before = Snapshot
$old = @(Relays)
if ($rollbackContinuation) {
    if ($before.exists -and ([bool]$before.exists -ne [bool]$rollbackContinuation.preimage.exists -or
        [string]$before.kind -cne [string]$rollbackContinuation.preimage.kind -or [string]$before.data -cne [string]$rollbackContinuation.preimage.data)) {
        throw '끝나지 않은 되돌리기의 자동 시작 값이 달라 변경하지 않았습니다.'
    }
    $before=$rollbackContinuation.preimage
    $old=@($rollbackContinuation.original_relays)
}
$installedCommand = if ($CompleteRetiredRemoval) {
    # The exact admitted old packet remains available after code removal.
    Command $install -Installed -InstalledPacket $lifecycleSource
} elseif ($Uninstall) { '' } else { Command $install -Installed }
if ($retirementResume) {
    if ($retirementResumeBeforeRemoval) {
        if ([bool]$before.exists -ne [bool]$retirementResume.preimage.exists -or
            [string]$before.kind -cne [string]$retirementResume.preimage.kind -or
            [string]$before.data -cne [string]$retirementResume.preimage.data -or
            (Test-Path -LiteralPath $stop)) {
            throw 'RETIREMENT_RESUME_PREMUTATION_STATE_UNKNOWN'
        }
        [void](Assert-CanonicalRuntimePreimage -Before $before -Processes $old -ExpectedCommand $installedCommand `
            -ExpectedRoot $install -StopMarkerExists (Test-Path -LiteralPath $stop))
    }
    elseif ([bool]$before.exists -or $old.Count -ne 0 -or [string]$before.kind -cne '' -or [string]$before.data -cne '') {
        throw 'RETIREMENT_RESUME_RUNTIME_NOT_QUIESCENT'
    }
    $resumeMarkerExists = Test-Path -LiteralPath $stop
    if (-not $retirementResumeBeforeRemoval -and
        (Get-ContainerWriterFenceFileSha256 $removalPath 65536) -cne [string]$retirementResume.retirement.active_removal_receipt_sha256) {
        throw 'RETIREMENT_RESUME_ACTIVE_REQUEST_CHANGED'
    }
    if ($resumeMarkerExists) {
        if ((Get-ContainerWriterFenceFileSha256 $stop 4096) -cne [string]$retirementResume.retirement.active_stop_sha256 -or
            (Get-ContainerWriterFenceFileSha256 $removalPath 65536) -cne [string]$retirementResume.retirement.active_removal_receipt_sha256) {
            throw 'RETIREMENT_RESUME_ACTIVE_REQUEST_CHANGED'
        }
    }
    elseif ([string]$retirementResume.status -ceq 'UNINSTALL_RUNTIME_QUIESCED') {
        throw 'RETIREMENT_RESUME_STOP_REQUEST_UNKNOWN'
    }
    if (-not $retirementResumeBeforeRemoval -and -not $resumeMarkerExists -and (Test-Path -LiteralPath $install)) {
        throw 'RETIREMENT_RESUME_CODE_ABSENCE_NOT_PROVEN'
    }
    $priorFence = Read-ContainerWriterFence -AllowAbsent
    if ($null -eq $priorFence) {
        $releasePath = Join-Path (Split-Path -Parent $ResumeRetirementReceiptPath) ('canonical-portable-' + [string]$retirementResume.run_id + '-product-complete-release.json')
        $releaseSha = Get-ContainerWriterFenceFileSha256 $releasePath
        $releaseReceipt = Join-Path (Get-ContainerWriterFenceControlRoot) ('release-' + [string]$retirementResume.code_replacement.transaction_id + '-' + $releaseSha + '.json')
        [void](Assert-ContainerWriterFenceReleaseReceiptMatches `
            -Receipt (Read-ContainerWriterFenceReleaseReceipt $releaseReceipt) `
            -SessionId ([string]$retirementResume.retirement.session_id) `
            -AttemptId ([string]$retirementResume.retirement.attempt_id) `
            -ReplacementTransactionId ([string]$retirementResume.code_replacement.transaction_id) `
            -ReleaseAuthorizationPath $releasePath -ReleaseAuthorizationSha256 $releaseSha)
        if ((Test-Path -LiteralPath $install) -or $resumeMarkerExists) { throw 'RETIREMENT_RESUME_RELEASE_STATE_DIFFERS' }
        'uninstall_status=PASS_RETIRED_REMOVAL_DATA_PRESERVED'
        'retirement_resume_status=ALREADY_COMPLETED_VERIFIED'
        return
    }
    if ([string]$priorFence.session_id -cne [string]$retirementResume.retirement.session_id -or
        [string]$priorFence.attempt_id -cne [string]$retirementResume.retirement.attempt_id -or
        [string]$priorFence.orchestrator_sha256 -cne [string]$retirementResume.retirement.orchestrator_sha256 -or
        [string]$priorFence.writer_contract_sha256 -cne [string]$lifecycleManifest.writer_session_contract_sha256 -or
        [string]$priorFence.replacement_transaction_id -cne [string]$retirementResume.code_replacement.transaction_id) {
        throw 'RETIREMENT_RESUME_FOREIGN_FENCE'
    }
    if (Same ([string]$priorFence.prepared_receipt_path) ([string]$retirementResume.retirement.prepared_receipt_path)) {
        if ([string]$priorFence.prepared_receipt_sha256 -cne [string]$retirementResume.retirement.prepared_receipt_sha256) {
            throw 'RETIREMENT_RESUME_FENCE_PREPARED_BINDING_DIFFERS'
        }
    }
    else {
        $releasePath = Join-Path (Split-Path -Parent $ResumeRetirementReceiptPath) ('canonical-portable-' + [string]$retirementResume.run_id + '-product-complete-release.json')
        if ([string]$retirementResume.status -cne 'UNINSTALL_AWAITING_FENCE_RELEASE' -or
            -not (Same ([string]$priorFence.prepared_receipt_path) $releasePath) -or
            (Get-ContainerWriterFenceFileSha256 $releasePath 65536) -cne [string]$priorFence.prepared_receipt_sha256) {
            throw 'RETIREMENT_RESUME_FENCE_RELEASE_BINDING_DIFFERS'
        }
        $release = Get-Content -LiteralPath $releasePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$release.install_audit_sha256 -cne $ResumeRetirementReceiptSha256 -or
            -not (Same ([string]$release.install_audit_path) $ResumeRetirementReceiptPath)) {
            throw 'RETIREMENT_RESUME_FENCE_RELEASE_AUDIT_DIFFERS'
        }
    }
    $priorFenceSha256 = Get-ContainerWriterFenceFileSha256 (Get-ContainerWriterFenceActivePath)
    $before = $retirementResume.preimage
    $old = @($retirementResume.retirement.original_relays)
}
if ($retirementResume) {
    # Validate the recorded original runtime separately from the current,
    # receipt-bound stop request checked above. Normal admission is unchanged.
    $runtimePreimageBinding = Assert-CanonicalRuntimePreimage -Before $before -Processes $old `
        -ExpectedCommand $installedCommand -ExpectedRoot $install -StopMarkerExists $false
}
elseif($rollbackContinuation) {
    $runtimePreimageBinding=$rollbackContinuation.runtime_preimage_binding
}
elseif($Uninstall -and -not $CompleteRetiredRemoval) {
    $runtimePreimageBinding=@{status='CURRENT_USER_REMOVAL_SCOPE';machine_control_authority=$false}
}
elseif($null -eq $abandonedPending) {
    $runtimePreimageBinding = Assert-CanonicalRuntimePreimage `
        -Before $before `
        -Processes $old `
        -ExpectedCommand $installedCommand `
        -ExpectedRoot $install `
        -StopMarkerExists (Test-Path -LiteralPath $stop)
}
$legacyRelayPreimage=$null;$legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$false
$writerBefore = if ($testMode -or ($Uninstall -and -not $CompleteRetiredRemoval)) {
    [ordered]@{ present=$false; classification='TEST_BYPASS'; restore_required=$false }
}
else { Get-CanonicalWriterPreimageForQuiesce $install }
$retirementLegacyWriterAdmission=@()
if ($CompleteRetiredRemoval) {
    $retirementLegacyWriterAdmission=Assert-CanonicalRetiredLegacyWriterAdmission $writerBefore $installationEvidenceRoot
} elseif (($Uninstall -or $RestoreVerifiedReplacement) -and [bool]$writerBefore.present) {
    throw 'Uninstall/restore requires the current-user layout without legacy scheduled writers.'
}
$uninstallCodeStarted = $false
$uninstallStopSha256 = ''
$supportedRemovalProductStartedAt=$null
$uninstallRecordPreimagePath = Join-Path $auditRoot "canonical-portable-$runId-integrity-preimage.json"
$retirementResumeClaim = $null
$continuationOldClaim = $null
$original=$null
$audit=$null
} else {
    $retirementResume=$null;$rollbackContinuation=$null;$original=$null;$audit=$null
    $legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$false
    $canonicalWriterFenceAuthority=$null
    $Script:CanonicalWriterFenceSessionId=[Guid]::NewGuid().ToString('N')
    $Script:CanonicalWriterFenceAttemptId=[Guid]::NewGuid().ToString('N')
    $Script:CanonicalWriterFenceTransactionId=[Guid]::NewGuid().ToString('N')
    $canonicalWriterFenceOrchestratorSha256=Sha $PSCommandPath
    $canonicalWriterFenceContractSha256=[string]$sourceManifest.writer_session_contract_sha256
    $machineRecovery=$null
    if ($RecoverMachineInstallation) {
        try { $machineRecovery=Read-CanonicalMachineInstallationRecovery $machineWorker $source $install $sourceManifest $MachineRecoveryAuditPath $MachineRecoveryAuditSha256 }
        catch { $outputFailure=$_;Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED';exit 4 }
        $Script:CanonicalWriterFenceSessionId=[string]$machineRecovery.fence.session_id
        $Script:CanonicalWriterFenceAttemptId=[string]$machineRecovery.fence.attempt_id
        $Script:CanonicalWriterFenceTransactionId=[string]$machineRecovery.fence.replacement_transaction_id
        $canonicalWriterFenceOrchestratorSha256=[string]$machineRecovery.fence.orchestrator_sha256
        $canonicalWriterFenceContractSha256=[string]$machineRecovery.fence.writer_contract_sha256
    }
}
try {
if ($retirementResume) { $retirementResumeClaim = Enter-RetirementResumeClaim $retirementResume }
if ($rollbackContinuation) {
    $continuationOldClaim=Enter-CanonicalRollbackContinuationClaim $rollbackContinuation
}
$canonicalWriterFenceAuthority = Enter-ContainerWriterSessionAuthority `
    -SessionId $Script:CanonicalWriterFenceSessionId `
    -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -WriterContractSha256 $canonicalWriterFenceContractSha256 `
    -RecoverExisting:$RecoverMachineInstallation
if ($null -ne $machineWorker) {
    try {
        if ($RecoverMachineInstallation) { Invoke-CanonicalMachineInstallationRecovery $machineWorker $source $install $sourceManifest $machineRecovery $canonicalWriterFenceAuthority }
        else { Invoke-CanonicalMachineInstallation $machineWorker $source $install $sourceManifest $canonicalWriterFenceAuthority }
    }
    catch {
        $outputFailure=$_
        Write-CanonicalInstallerRelayGuidance
        $code=if($RecoverMachineInstallation -and $_.Exception.Message -cin @('MACHINE_RECOVERY_CHILD_UNRECORDED','MACHINE_RECOVERY_CHILD_IDENTITY_INVALID','MACHINE_RECOVERY_CHILD_ACTIVE','MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN')){$_.Exception.Message}else{'MACHINE_INSTALL_FAILED'}
        Write-CanonicalMachinePublicRecord $code;exit 4
    }
    exit 0
}
if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval) {
    Invoke-ContainerSourceDataAdmission $source $Script:CanonicalInstallerSourceInventorySha256 $auditPath $evidenceFull
    # Persist the native preimage and stop before publishing a fence: the old
    # relay must retain admission for its final STOPPED write and lease release.
    $installerRelayStop=Stop-CanonicalInstallerRelayPreimage $old $activeRelayRoot $source $install $operatorSid $before
}
elseif ($RestoreVerifiedReplacement) {
    $restoreTargetRoot = if ([string]$publicRestore.state -ceq 'RESTORED') { $install } else { [string]$publicRestore.receipt.rollback_root }
    $canonicalRestoreInputBinding = Get-CanonicalOnboardingInputBinding $source $restoreTargetRoot
    Assert-CanonicalRestoreCodeBinding $canonicalRestoreInputBinding $publicRestore
}
if($null -ne $abandonedPending){
    # Recovery mutations run under this install's existing authority boundary;
    # Resume separately claims the exact abandoned tuple before touching it.
    $abandonedRecovery=Resume-CanonicalAbandonedRollback
    $installationEvidenceRoot=Initialize-InstallationEvidence $auditPath $operatorSid @($Script:CanonicalWriterFenceDelegationToken)
    $before=Snapshot;$old=@(Relays)
    $runtimePreimageBinding=Assert-CanonicalRuntimePreimage -Before $before -Processes $old `
        -ExpectedCommand $installedCommand -ExpectedRoot $install -StopMarkerExists (Test-Path -LiteralPath $stop)
}
$canonicalWriterFencePreparedReceipt = if ($supportedRemovalResume) {
    [pscustomobject]@{path=[string]$supportedRemovalResume.active.prepared_receipt_path;sha256=[string]$supportedRemovalResume.active.prepared_receipt_sha256}
} else { New-CanonicalWriterFencePreparedReceipt `
    -Path $canonicalWriterFencePreparedPath `
    -SessionId $Script:CanonicalWriterFenceSessionId `
    -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
    -WriterContractSha256 $canonicalWriterFenceContractSha256 `
    -SourceManifestSha256 $sourceManifestSha256 `
    -OperatorSid $operatorSid `
    -OperatorLocalAppDataRoot $lad }
if ($continuationPriorFence) {
    $continuationAdmission=Enter-ContainerWriterAdmission
    try {
        $freshContinuation=Read-CanonicalRollbackContinuation $install $lad $operatorSid
        if ($null -eq $freshContinuation -or [string]$freshContinuation.record_sha256 -cne [string]$rollbackContinuation.record_sha256) {throw '끝나지 않은 되돌리기의 journal이 달라 변경하지 않았습니다.'}
        if ((Get-ContainerWriterFenceFileSha256 (Get-ContainerWriterFenceActivePath)) -cne $continuationPriorFenceSha) {throw '끝나지 않은 되돌리기의 fence가 달라 변경하지 않았습니다.'}
        Assert-ContainerWriterSessionAuthority $continuationPriorFence $continuationOldClaim
        $resumedFence=New-ContainerWriterFencePayload -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
            -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
            -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 -WriterContractSha256 $canonicalWriterFenceContractSha256 `
            -PreparedReceiptPath ([string]$canonicalWriterFencePreparedReceipt.path) -PreparedReceiptSha256 ([string]$canonicalWriterFencePreparedReceipt.sha256) `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken -DelegatedSources $canonicalWriterFenceDelegatedSources `
            -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o'))
        Assert-ContainerWriterSessionAuthority $resumedFence $canonicalWriterFenceAuthority
        $continuationAuthorityBinding=Write-CanonicalRollbackContinuationAuthority $rollbackContinuation
        $resumedFence.prepared_receipt_path=[string]$continuationAuthorityBinding.path
        $resumedFence.prepared_receipt_sha256=[string]$continuationAuthorityBinding.sha256
        [void](Write-ContainerWriterFenceAtomic '' $resumedFence)
    } finally {Exit-ContainerWriterAdmission $continuationAdmission}
}
elseif ($supportedRemovalResume) {
    Resume-CanonicalSupportedRemovalFence $supportedRemovalResume
}
elseif ($retirementResume) {
    $resumeAdmission = Enter-ContainerWriterAdmission
    try {
        Assert-RetirementOwnerExited $retirementResume.retirement
        [void](Read-CanonicalRetirementResume)
        [void](Read-CanonicalRetiredRemoval)
        if (-not $retirementResumeBeforeRemoval -and
            (Get-ContainerWriterFenceFileSha256 $removalPath 65536) -cne [string]$retirementResume.retirement.active_removal_receipt_sha256) {
            throw 'RETIREMENT_RESUME_ACTIVE_REQUEST_CHANGED'
        }
        if ((Test-Path -LiteralPath $stop) -ne $resumeMarkerExists -or
            ($resumeMarkerExists -and (
                (Get-ContainerWriterFenceFileSha256 $stop 4096) -cne [string]$retirementResume.retirement.active_stop_sha256 -or
                (Get-ContainerWriterFenceFileSha256 $removalPath 65536) -cne [string]$retirementResume.retirement.active_removal_receipt_sha256))) {
            throw 'RETIREMENT_RESUME_ACTIVE_REQUEST_CHANGED'
        }
        if ((Get-ContainerWriterFenceFileSha256 (Get-ContainerWriterFenceActivePath)) -cne $priorFenceSha256) {
            throw 'RETIREMENT_RESUME_FENCE_CHANGED'
        }
        $resumedFence = New-ContainerWriterFencePayload `
            -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
            -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
            -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
            -WriterContractSha256 $canonicalWriterFenceContractSha256 `
            -PreparedReceiptPath ([string]$canonicalWriterFencePreparedReceipt.path) `
            -PreparedReceiptSha256 ([string]$canonicalWriterFencePreparedReceipt.sha256) `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
            -DelegatedSources $canonicalWriterFenceDelegatedSources `
            -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o'))
        Assert-ContainerWriterSessionAuthority $resumedFence $canonicalWriterFenceAuthority
        [void](Write-ContainerWriterFenceAtomic '' $resumedFence)
    }
    finally { Exit-ContainerWriterAdmission $resumeAdmission }
}
else {
$fencePreparedBinding=$canonicalWriterFencePreparedReceipt
if($rollbackContinuation){$continuationAuthorityBinding=Write-CanonicalRollbackContinuationAuthority $rollbackContinuation;$fencePreparedBinding=$continuationAuthorityBinding}
[void](Start-ContainerWriterFence `
    -Status 'INSTALLING' `
    -OwnerKind 'canonical_installer' `
    -SessionId $Script:CanonicalWriterFenceSessionId `
    -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
    -WriterContractSha256 $canonicalWriterFenceContractSha256 `
    -PreparedReceiptPath ([string]$fencePreparedBinding.path) `
    -PreparedReceiptSha256 ([string]$fencePreparedBinding.sha256) `
    -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
    -DelegatedSources $canonicalWriterFenceDelegatedSources `
    -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) `
    -AuthorityLease $canonicalWriterFenceAuthority)
}
$canonicalWriterFenceActive = $true
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN', $Script:CanonicalWriterFenceDelegationToken, 'Process')
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID', $Script:CanonicalWriterFenceSessionId, 'Process')
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID', $Script:CanonicalWriterFenceAttemptId, 'Process')
[Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID', $Script:CanonicalWriterFenceTransactionId, 'Process')
$audit = [ordered]@{
    schema='container-audit-canonical-portable-install-v2'
    operation=if ($CompleteRetiredRemoval) { 'COMPLETE_RETIRED_REMOVAL' } elseif ($Uninstall) { 'UNINSTALL' } elseif ($RestoreVerifiedReplacement) { 'RESTORE_VERIFIED_REPLACEMENT' } else { 'INSTALL' }
    status='PREIMAGE_SAVED'
    run_id=$runId
    captured_at=(Get-Date).ToUniversalTime().ToString('o')
    install_root=$install
    code_placement='NOT_STARTED'
    source_commit=[string]$sourceManifest.source_commit
    source_manifest_sha256=$sourceManifestSha256
    runtime_pythonw_sha256=''
    runtime_pythonw_signature=''
    registry_value=$RunName
    preimage=$before
    runtime_preimage_binding=$runtimePreimageBinding
    after=[ordered]@{exists=$true;kind='String';data=$wanted}
    stop_marker_path=$stop
    scheduled_writer=[ordered]@{
        classification=[string]$writerBefore.classification
        preimage=$writerBefore
        disable_readback=$null
        stop_proof=$null
        restore_readback=$null
        natural_trigger_proof=$null
        restore_failure_code=''
    }
    code_replacement=[ordered]@{
        continuation_authority_link=$continuationAuthorityBinding
        status='NOT_REQUIRED'
        prestate='NOT_EVALUATED'
        transaction_id=$replacementTransactionId
        receipt_path=''
        receipt_sha256=''
        rollback_root=''
        restore_evidence_path=''
        restore_evidence_sha256=''
        later_restore_surface='NOT_REQUIRED'
        identity_or_credential_copied=$false
    }
    rollback=[ordered]@{
        available=$true
        applied=$false
        runtime_restored=$false
        scheduled_writer_restored=(-not [bool]$writerBefore.restore_required)
        original_relays=@($old|ForEach-Object {[ordered]@{ProcessId=[int]$_.ProcessId;ExecutablePath=[string]$_.ExecutablePath;CommandLine=[string]$_.CommandLine}})
    }
}
if(Get-Variable -Name installerRelayStop -ErrorAction SilentlyContinue){$audit['installer_relay_stop']=$installerRelayStop}
if ($CompleteRetiredRemoval) {
    $audit.retirement=$retirement
    $retirement.legacy_writer_admission=[Object[]]@($retirementLegacyWriterAdmission)
    $retirement.owner_process_id=$PID
    $retirement.owner_started_at_utc=(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')
    $retirement.session_id=$Script:CanonicalWriterFenceSessionId
    $retirement.attempt_id=$Script:CanonicalWriterFenceAttemptId
    $retirement.orchestrator_sha256=$canonicalWriterFenceOrchestratorSha256
    $retirement.authority_mutex_name=[string]$canonicalWriterFenceAuthority.name
    $retirement.prepared_receipt_path=[string]$canonicalWriterFencePreparedReceipt.path
    $retirement.prepared_receipt_sha256=[string]$canonicalWriterFencePreparedReceipt.sha256
    $retirement.old_record_sha256=$uninstallRecordSha256
    $retirement.original_relays=[Object[]]@($old | ForEach-Object {
        [ordered]@{ ProcessId=[int]$_.ProcessId; ExecutablePath=[string]$_.ExecutablePath; CommandLine=[string]$_.CommandLine }
    })
    $retirement.resume_receipt_path=$ResumeRetirementReceiptPath
    $retirement.resume_receipt_sha256=$ResumeRetirementReceiptSha256
}
if($null -ne $legacyRelayBefore){
    $legacyRelayPreimage=Save-CanonicalOfficialLegacyRelayPreimage $legacyRelayBefore $installationEvidenceRoot
    $audit.scheduled_writer['official_legacy']=@{preimage_path=$legacyRelayPreimage.path;preimage_sha256=$legacyRelayPreimage.sha256;xml_sha256=$legacyRelayPreimage.xml_sha256;identity_sha256=$legacyRelayPreimage.identity.sha256;fields=$legacyRelayPreimage.identity.fields;record_fields=$legacyRelayPreimage.identity.records;status='PREIMAGE_SAVED'}
}
$audit['stage_evidence_root']=$installationEvidenceRoot
$audit['abandoned_recovery']=$abandonedRecovery
Set-InstallationEvidenceStage 'canonical.prestate_verification'
Save $auditPath $audit $true
if ($evidenceFull) { Save $evidenceFull $audit $true }
Write-CanonicalInstallReentryRecord 'PREIMAGE_SAVED'

$mutated = ($old.Count -gt 0)
$writerRestoreNeeded = [bool]$writerBefore.restore_required
$runtimeQuiescedForReplacement = $false
$codeRestoreNeeded = $false
$replacementReceipt = $null
$replacementReceiptSha256 = ''
$installedInventorySha256 = $Script:ContainerWriterFenceInventorySha256
$currentTreeInventorySha256 = $Script:ContainerWriterFenceInventorySha256
$audit.code_replacement.writer_inventory_transitions = @()
$audit.code_replacement.candidate_writer_inventory_sha256 = $Script:ContainerWriterFenceInventorySha256
$currentAbsentBeforePlacement = -not (Test-Path -LiteralPath $install -ErrorAction Stop)
$audit.code_replacement['current_absent_before_placement'] = $currentAbsentBeforePlacement
$enteredPlacementTry = $true
    $placement = 'INSTALL_REQUIRED'
    $existingVerified = $false
    if ((-not $Uninstall -or $CompleteRetiredRemoval) -and (Test-Path $install -PathType Container)) {
        try {
            $candidateRoot=if($supportedContext -and $supportedPlacement){[string]$supportedContext.active_code_root}elseif($supportedPlacement){if(Test-Path -LiteralPath $installedCodeRoot){$installedCodeRoot}else{$supportedRestoreFromRoot}}else{$install}
            $candidate = InstalledManifest $candidateRoot $SkipSignatureValidationForTest
            $helper = (Join-Path $source 'tools\bootstrap_integrity.ps1').Replace("'","''")
            $escapedRoot = $candidateRoot.Replace("'","''")
            $capturedChild=Invoke-InstallationEvidenceChild 'verify-existing-code' $winps @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',". '$helper'; [void](Assert-BootstrapIntegrityRecord '$escapedRoot')")
            $global:LASTEXITCODE=$capturedChild.ExitCode
            if ($LASTEXITCODE -ne 0) { throw 'integrity differs' }
            $installedInventory = Assert-WriterSinkInventory `
                (Join-Path $candidateRoot 'tools\container_writer_sink_inventory.json') `
                ([string]$candidate.writer_sink_inventory_sha256) `
                ([string]$candidate.writer_sink_inventory_contract_sha256)
            $writerSemanticsIdentical = (Get-WriterInventorySemantics $installedInventory) -ceq (Get-WriterInventorySemantics $lifecycleWriterInventory)
            $declaredGenerationTransition = -not $writerSemanticsIdentical -and
                -not ($Uninstall -or $RestoreVerifiedReplacement -or $CompleteRetiredRemoval) -and
                (Test-ContainerDataGenerationForwardTransition -BeforeRoot $install -AfterRoot $source -BeforeInventory $installedInventory -AfterInventory $lifecycleWriterInventory)
            if (-not $writerSemanticsIdentical -and -not $declaredGenerationTransition -and
                -not (Test-ExactApprovedInstalledWriterTransition $candidate $lifecycleManifest $lifecycleSource)) {
                throw 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
            }
            $installedInventorySha256 = [string]$candidate.writer_sink_inventory_contract_sha256
            $currentTreeInventorySha256 = $installedInventorySha256
            $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $installedInventorySha256
            $audit.code_replacement.installed_writer_inventory_sha256 = $installedInventorySha256
            $audit.code_replacement.writer_semantics_identical = $writerSemanticsIdentical
            $audit.code_replacement.data_generation_transition_declared = $declaredGenerationTransition
            $existingVerified = $true
            $audit.code_replacement.prestate='VERIFIED_REPLACE'
            if (
                [string]$candidate.source_commit -ceq [string]$lifecycleManifest.source_commit -and
                [string]$candidate.source_tree -ceq [string]$lifecycleManifest.source_tree -and
                (Sha (Join-Path $install 'runtime\pythonw.exe')) -ceq (Sha (Join-Path $lifecycleSource 'runtime\pythonw.exe'))
            ) { if(-not $supportedPlacement){$placement = 'REUSED_VERIFIED'} }
        }
        catch {
    Write-InstallationCaughtFailure $_

            $audit.code_replacement.prestate='UNKNOWN_OR_DAMAGED'
            $audit.code_replacement.prestate_failure_type=$_.Exception.GetType().Name
            if ($_.Exception.Message -ceq 'CODE_PRESTATE_WRITER_SEMANTICS_DIFFER') {
                $audit.code_replacement.prestate_failure_code='CODE_PRESTATE_WRITER_SEMANTICS_DIFFER'
            }
            Save $auditPath $audit $true
            if ($evidenceFull) { Save $evidenceFull $audit $true }
        }
        if (-not $existingVerified) {
            throw 'CODE_PRESTATE_NOT_VERIFIED_REPLACE'
        }
    }
    if(-not ($RestoreVerifiedReplacement -or $Uninstall -or $CompleteRetiredRemoval)){
        $transactionLaunchForTest=Get-Variable -Name InstallationTransactionLaunchForTest -ValueOnly -ErrorAction SilentlyContinue
        if(-not $testMode -or $null -ne $transactionLaunchForTest){
            $configuration=New-CanonicalTransactionConfiguration
            $enteredPlacementTry=$false;$mutated=$false
            $canonicalTransactionJob=Start-InstallationTransaction $configuration $canonicalWriterFenceAuthority $transactionLaunchForTest
            $canonicalWriterFenceAuthority=$null
            $enteredPlacementTry=$true
            $audit['persistent_helper']=[ordered]@{status='AUTHORITY_READY';process_id=[int]$canonicalTransactionJob.Process.Id;
                parent_process_id=$PID;protected_run_root=[string]$configuration.protected_root;single_consent=$true}
        }
    }
    Set-InstallationEvidenceStage 'canonical.public_restore'
    if ($RestoreVerifiedReplacement) {
        if (-not $existingVerified) { throw 'Canonical restore current tree is not verified.' }
        $publicRestore = Read-CanonicalReplacementRestore
        $selectedReceipt = $publicRestore.receipt
        Assert-ContainerDataGenerationTarget -CandidateRoot ([string]$selectedReceipt.rollback_root) `
            -TargetSid $operatorSid -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source
        $selectedTransactionId = [string]$selectedReceipt.transaction_id
        $audit.code_replacement.transaction_id = $selectedTransactionId
        $audit.code_replacement.controller_transaction_id = $Script:CanonicalWriterFenceTransactionId
        $audit.code_replacement.receipt_path = $restoreReceiptFull
        $audit.code_replacement.receipt_sha256 = $RestoreReceiptSha256
        $audit.code_replacement.rollback_root = [string]$selectedReceipt.rollback_root
        $audit.code_replacement.prestate = [string]$publicRestore.state
        if ($rollbackContinuation) {
            $freshContinuation=Read-CanonicalRollbackContinuation $install $lad $operatorSid
            if ($null -eq $freshContinuation -or [string]$freshContinuation.record_sha256 -cne [string]$rollbackContinuation.record_sha256) {throw 'Rollback continuation changed before mutation.'}
        }
        Sync-CanonicalWriterFenceInventory $currentTreeInventorySha256
        $restoreTargetRoot = if ([string]$publicRestore.state -ceq 'RESTORED') { $install } else { [string]$selectedReceipt.rollback_root }
        $restoreRecheck = Get-CanonicalOnboardingInputBinding $source $restoreTargetRoot
        Assert-CanonicalRestoreCodeBinding $restoreRecheck $publicRestore
        if ($restoreRecheck -cne $canonicalRestoreInputBinding) {
            throw '복원 전 확인한 자격 설정 경로가 바뀌었습니다. 자료를 보존하고 복원을 다시 확인하세요.'
        }
        $mutated = $true
        Product $install '--remove-current-user-setup'
        $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Snapshot).exists -or [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
            [string]$removal.relay_process.status -cne 'ABSENT' -or @(Relays).Count -ne 0) {
            throw 'Canonical restore current-user quiescence readback failed.'
        }
        $restoreStopSha256 = Sha $stop
        $audit.status = 'RESTORE_RUNTIME_QUIESCED'
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
        Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256
        $publicRestoreArguments = @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
            '-InstallRoot',$install, '-ElevationLogPath',$elevationLogPath,
            '-OperatorLocalAppDataRoot',$lad, '-OperatorSid',$operatorSid,
            '-OperatorDataRoot',$activeDataRoot,
            '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
            '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
            '-RestoreVerifiedReplacement', '-ReplacementTransactionId',$selectedTransactionId,
            '-ReplacementReceiptPath',$restoreReceiptFull, '-ReplacementReceiptSha256',$RestoreReceiptSha256,
            '-RestoreEvidencePath',$replacementRestoreEvidencePath,
            '-WriterFenceHelperPath',$writerFenceHelperPath,
            '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
            '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
            '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
        )
        if ($testMode) { $publicRestoreArguments += '-AllowNoncanonicalLayoutForTest' }
        if ($rollbackContinuation) {
            $publicRestoreArguments+=@('-RollbackContinuationPath',([string]$rollbackContinuation.record_path),'-RollbackContinuationSha256',([string]$rollbackContinuation.record_sha256))
        }
        $capturedChild = Invoke-InstallationEvidenceChild 'public-code-restore' $winps $publicRestoreArguments
            $global:LASTEXITCODE=$capturedChild.ExitCode
            Write-CanonicalInstallationPublicRecord -ExitCode $capturedChild.ExitCode
        if ($LASTEXITCODE -ne 0) { throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Canonical code restore failed: $LASTEXITCODE")) -UserLine) }
        if (-not $testMode) {
            $restoreBinding=Read-InstallationHelperEvidenceBinding @($capturedChild.Stdout -split "`r?`n") $elevationLogPath $capturedChild.ProcessId $sourceHelperSha256
            $replacementRestoreEvidencePath=Read-CanonicalHelperArtifact $restoreBinding 'restore-evidence.json' 'RESTORE_EVIDENCE_READY'
        }
        $currentTreeInventorySha256 = [string]$publicRestore.old_inventory_sha256
        $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $currentTreeInventorySha256
        $restoreEvidence = ReadReplacementRestoreEvidence `
            -Path $replacementRestoreEvidencePath -ExpectedTransactionId $selectedTransactionId `
            -ExpectedReceiptPath $restoreReceiptFull -ExpectedReceiptSha256 $RestoreReceiptSha256 `
            -ExpectedInstallRoot $install
        $verifiedRestore = Read-CanonicalReplacementRestore
        if ([string]$verifiedRestore.state -cne 'RESTORED') { throw 'Canonical exact restore readback failed.' }
        $placement = 'RESTORED_VERIFIED'
        $audit.code_placement = $placement
        $audit.code_replacement.status = [string]$restoreEvidence.action
        $audit.code_replacement.restore_evidence_path = $replacementRestoreEvidencePath
        $audit.code_replacement.restore_evidence_sha256 = Sha $replacementRestoreEvidencePath
        $audit.code_replacement.later_restore_surface = 'CONSUMED'
        if ((Sha $stop) -cne $restoreStopSha256) { throw 'Canonical restore stop marker changed.' }
        Restore $before
        Remove-Item -LiteralPath $stop -Force
        $check = Snapshot
        if ([bool]$check.exists -ne [bool]$before.exists -or
            [string]$check.kind -cne [string]$before.kind -or
            [string]$check.data -cne [string]$before.data -or (Test-Path -LiteralPath $stop)) {
            throw 'Canonical restore runtime preimage readback failed.'
        }
        $audit.after = $check
        $audit.status = 'RESTORE_AWAITING_FENCE_RELEASE'
        Save $auditPath $audit $true
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productCompleteAuthorizationPath -Phase 'PRODUCT_COMPLETE' -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        $restoreRecheck = Get-CanonicalOnboardingInputBinding $source $install
        Assert-CanonicalRestoreCodeBinding $restoreRecheck $verifiedRestore
        if ($restoreRecheck -cne $canonicalRestoreInputBinding) {
            throw '복원 전 확인한 자격 설정 경로가 바뀌었습니다. 자료를 보존하고 복원을 다시 확인하세요.'
        }
        if($old.Count -gt 0){[void](Start-CanonicalRelayAfterFenceRelease -Root $install -RunCommand ([string]$before.data))}
        [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
        $audit.status = 'PASS_RESTORED_VERIFIED_DATA_PRESERVED'
        $audit['worker_shortcuts']=Restore-BootstrapWorkerShortcuts $install $workerShortcutRecordPath 'User'
        $audit.rollback.applied = $true
        $audit.rollback.runtime_restored = $true
        $audit.rollback.code_exact = $true
        if($old.Count -gt 0){$audit.exact_launch=$Script:CanonicalRelayProof}
        $audit.completed_at = [DateTime]::UtcNow.ToString('o')
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
        if ($rollbackContinuation) {
            Complete-CanonicalRollbackContinuation $rollbackContinuation
            $relayState=if($old.Count){'relay READY'}else{'relay 원 부재'}
            (ConvertTo-KmtechRedactedSinkText -Text ([string]("끝나지 않은 되돌리기를 마쳤습니다. 옛 판·Run·시작 작업·pointer·$relayState 확인했습니다.")))
            'rollback_resume_status=COMPLETE'
        }
        'restore_status=PASS_RESTORED_VERIFIED_DATA_PRESERVED'
        'prior_code_exact=true'
        'failed_new_preserved=true'
        'current_user_runtime_preimage_restored=true'
        (ConvertTo-KmtechRedactedSinkText -Text ([string]("audit_path=$auditPath")))
        return
    }
    Set-InstallationEvidenceStage 'canonical.uninstall'
    if ($Uninstall -and -not $CompleteRetiredRemoval) {
        # Execute only the externally verified support host. Damaged installed
        # code and update-control records are not prerequisites or authorities.
        $mutated=$true
        $supportedRemovalProductStartedAt=[DateTime]::UtcNow
        Product $source '--remove-current-user-setup' (Join-Path $install 'app')
        $removal=Get-Content -LiteralPath $removalPath -Raw -Encoding UTF8|ConvertFrom-Json
        [void](Confirm-CanonicalRuntimeQuiescence -Removal $removal -ExpectedRelays $old -StopRequestPath $stop)
        $uninstallStopSha256=Sha $stop
        $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
            '-Uninstall','-SourceRoot',$source,'-InstallRoot',$install,'-OperatorLocalAppDataRoot',$lad,'-OperatorSid',$operatorSid,
            '-QuiesceReceiptPath',$removalPath,'-ExpectedQuiesceReceiptSha256',(Sha $removalPath),
            '-RemovalControllerProcessId',[string]$PID,
            '-RemovalControllerStartedAtUtc',(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o'),
            '-RemovalControllerCanonicalPath',$PSCommandPath,
            '-UninstallAuditPath',$auditPath,'-UninstallAuditSha256',(Sha $auditPath),
            '-WriterFenceHelperPath',(Join-Path $source 'tools\container_writer_fence.ps1'),
            '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
            '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
            '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,'-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,'-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken,
            '-ElevationLogPath',$elevationLogPath)
        if($testMode){$args+='-AllowNoncanonicalLayoutForTest'}
        $child=Invoke-InstallationEvidenceChild 'supported-content-removal' $winps $args
        if($child.ExitCode -ne 0){
            $audit['removal_child_failure']=Get-CanonicalRetirementChildFailure $child
            Write-CanonicalInstallationPublicRecord -ExitCode $child.ExitCode
            throw '지원 제거를 마치지 못했습니다. 자료를 보존하고 같은 제거를 다시 실행하세요.'
        }
        $removed=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $install) 'removed.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if([string]$removed.schema -cne 'container-audit-supported-removal-v1' -or [string]$removed.lifecycle_state -cne 'REMOVED' -or
            (Snapshot).exists -or @(Relays).Count){throw 'REMOVAL_END_STATE_NOT_PROVEN'}
        if((Sha $stop) -cne $uninstallStopSha256){throw 'REMOVAL_STOP_MARKER_CHANGED'}
        Remove-Item -LiteralPath $stop -ErrorAction Stop
        $audit.status='UNINSTALL_AWAITING_FENCE_RELEASE';$audit.code_placement='REMOVED';$audit.after=Snapshot
        $audit['retained_paths']=@($removed.retained_paths);$audit['removal_evidence_root']=[string]$removed.evidence_root
        Save $auditPath $audit
        $releaseAuthorization=New-CanonicalWriterFenceReleaseAuthorization -Path $productCompleteAuthorizationPath -Phase 'PRODUCT_COMPLETE' -AuditPath $auditPath
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive=$false
        $audit['worker_shortcuts']=Restore-BootstrapWorkerShortcuts $install $workerShortcutRecordPath 'User'
        $audit.status='PASS_UNINSTALLED_DATA_PRESERVED';$audit.completed_at=[DateTime]::UtcNow.ToString('o')
        Save $auditPath $audit
        if($evidenceFull){Save $evidenceFull $audit}
        'uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED';'lifecycle_state=REMOVED';'user_state_preserved=true'
        'retained_path_count='+@($removed.retained_paths).Count
        return
    }
    if ($Uninstall) {
        $resumeCodeAbsent = $retirementResume -and -not (Test-Path -LiteralPath $install)
        if (-not $resumeCodeAbsent -and (-not $existingVerified -or $placement -cne 'REUSED_VERIFIED' -or
            (Sha (Join-Path $install 'portable-manifest.json')) -cne $lifecycleManifestSha256 -or
            (Sha (Join-Path $install 'bootstrap-integrity.json')) -cne $uninstallRecordSha256 -or
            (Get-InventoryAggregate @(Get-CodeInventory $install)) -cne $uninstallAggregate)) {
            throw 'Uninstall installed/source identity changed before mutation.'
        }
        $integrityPreimageSource = if ($retirementResume -and -not $retirementResumeBeforeRemoval) { [string]$retirementResume.code_integrity_preimage_path } else { Join-Path $install 'bootstrap-integrity.json' }
        Copy-Item -LiteralPath $integrityPreimageSource -Destination $uninstallRecordPreimagePath
        if ((Sha $uninstallRecordPreimagePath) -cne $uninstallRecordSha256) {
            throw 'Uninstall integrity preimage copy readback failed.'
        }
        $audit.code_integrity_preimage_path = $uninstallRecordPreimagePath
        $audit.code_integrity_preimage_sha256 = $uninstallRecordSha256
        $audit.code_recovery_path = Join-Path (Split-Path -Parent $install) ('.current.uninstall.' + $Script:CanonicalWriterFenceAttemptId)
        $mutated = $true
        if ($CompleteRetiredRemoval) { [void](Read-CanonicalRetiredRemoval) }
        if (-not $retirementResume -or $retirementResumeBeforeRemoval) { Product $install '--remove-current-user-setup' }
        $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Snapshot).exists -or [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
            [string]$removal.relay_process.status -cne 'ABSENT' -or @(Relays).Count -ne 0) {
            throw 'Uninstall current-user removal readback failed.'
        }
        $uninstallStopSha256 = if ($retirementResume -and -not $retirementResumeBeforeRemoval -and -not $resumeMarkerExists) { '' } else { Sha $stop }
        $quiescePath = $removalPath
        if ($CompleteRetiredRemoval) {
            [void](Read-CanonicalRetiredRemoval)
            Assert-RetirementWriterQuiescence
            $quiescePath = [string]$retirement.removal_receipt_path
            $retirement.active_stop_sha256=$uninstallStopSha256
            $retirement.active_removal_receipt_sha256=Sha $removalPath
        }
        $audit.status = 'UNINSTALL_RUNTIME_QUIESCED'
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
        $uninstallArguments = @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $lifecycleSource 'INSTALL_THIS_PC.ps1'), '-Uninstall',
            '-SourceRoot',$lifecycleSource, '-InstallRoot',$install,
            '-OperatorLocalAppDataRoot',$lad, '-ElevationLogPath',$elevationLogPath,
            '-ExpectedInstalledManifestSha256',$lifecycleManifestSha256,
            '-ExpectedInstalledAggregateSha256',$uninstallAggregate,
            '-QuiesceReceiptPath',$quiescePath, '-ExpectedQuiesceReceiptSha256',(Sha $quiescePath),
            '-WriterFenceHelperPath',$writerFenceHelperPath,
            '-ExpectedWriterFenceHelperSha256',([string]$lifecycleManifest.writer_fence_helper_sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
            '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
            '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
        )
        $retiredHelperSupportsOperatorBinding = $true
        $retiredHelperSupportsControllerBinding = $true
        if ($CompleteRetiredRemoval) {
            $helperTokens = $null; $helperErrors = $null
            $helperAst = [Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $lifecycleSource 'INSTALL_THIS_PC.ps1'), [ref]$helperTokens, [ref]$helperErrors)
            if ($helperErrors.Count -ne 0) { throw 'Retired helper syntax is invalid.' }
            $helperParameterNames = @($helperAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
            $operatorParameterNames = @('OperatorSid','WriterFencePreparedReceiptPath','WriterFencePreparedReceiptSha256')
            $supportedCount = @($operatorParameterNames | Where-Object { $_ -in $helperParameterNames }).Count
            if ($supportedCount -notin @(0,3)) { throw 'Retired helper operator binding is incomplete.' }
            $retiredHelperSupportsOperatorBinding = ($supportedCount -eq 3)
            $controllerParameterNames = @('RemovalControllerProcessId','RemovalControllerStartedAtUtc','RemovalControllerCanonicalPath')
            $controllerCount = @($controllerParameterNames | Where-Object { $_ -in $helperParameterNames }).Count
            if ($controllerCount -notin @(0,3)) { throw 'RETIREMENT_CONTROLLER_BINDING_INTERFACE_PARTIAL' }
            $retiredHelperSupportsControllerBinding = ($controllerCount -eq 3)
        }
        if ($retiredHelperSupportsOperatorBinding) {
            $uninstallArguments += @(
                '-OperatorSid',$operatorSid,
                '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
                '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256)
            )
        }
        if ($retiredHelperSupportsControllerBinding) {
            $uninstallArguments += @(
                '-RemovalControllerProcessId',[string]$PID,
                '-RemovalControllerStartedAtUtc',(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o'),
                '-RemovalControllerCanonicalPath',$PSCommandPath
            )
        }
        if ($testMode) { $uninstallArguments += '-AllowNoncanonicalLayoutForTest' }
        $uninstallCodeStarted = $true
        if (-not $resumeCodeAbsent) {
            $capturedChild = Invoke-InstallationEvidenceChild 'uninstall-helper' $winps $uninstallArguments
            $global:LASTEXITCODE=$capturedChild.ExitCode
            Write-CanonicalInstallationPublicRecord -ExitCode $capturedChild.ExitCode
            if ($LASTEXITCODE -ne 0) {
                if ($CompleteRetiredRemoval) {
                    $audit['retirement_child_failure']=Get-CanonicalRetirementChildFailure $capturedChild
                    Write-CanonicalInstallationPublicRecord -ExitCode $capturedChild.ExitCode
                }
                throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Code removal failed: $LASTEXITCODE")) -UserLine)
            }
        }
        if ((Test-Path -LiteralPath $install) -or (Snapshot).exists -or @(Relays).Count -ne 0) {
            throw 'Uninstall independent code/runtime absence readback failed.'
        }
        if ($uninstallStopSha256 -and (Sha $stop) -cne $uninstallStopSha256) { throw 'Uninstall stop marker changed.' }
        if ($CompleteRetiredRemoval) {
            [void](Read-CanonicalRetiredRemoval)
            Assert-RetirementWriterQuiescence
        }
        if ($uninstallStopSha256) { Remove-Item -LiteralPath $stop -Force }
        if (Test-Path -LiteralPath $stop) { throw 'Uninstall stop-marker cleanup failed.' }
        $audit.status = 'UNINSTALL_AWAITING_FENCE_RELEASE'
        $audit.code_placement = 'REMOVED'
        $audit.after = Snapshot
        Save $auditPath $audit $true
        if ($CompleteRetiredRemoval) {
            Set-InstallationEvidenceStage 'retirement.release_authorization'
            $retirementAuditSealed=$true
        }
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productCompleteAuthorizationPath -Phase 'PRODUCT_COMPLETE' -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        if ($CompleteRetiredRemoval) { Set-InstallationEvidenceStage 'retirement.release_authorized' }
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        $retirementAuditSealed=$false
        $audit.status = if ($CompleteRetiredRemoval) { 'PASS_RETIRED_REMOVAL_DATA_PRESERVED' } else { 'PASS_UNINSTALLED_DATA_PRESERVED' }
        $audit['worker_shortcuts']=Restore-BootstrapWorkerShortcuts $install $workerShortcutRecordPath 'User'
        $audit.completed_at = [DateTime]::UtcNow.ToString('o')
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
        (ConvertTo-KmtechRedactedSinkText -Text ([string]("uninstall_status=$($audit.status)")))
        'application_root_status=ABSENT'
        'current_user_relay_status=ABSENT'
        'user_state_preserved=true'
        'server_identity_retired=false'
        (ConvertTo-KmtechRedactedSinkText -Text ([string]("audit_path=$auditPath")))
        return
    }
    if($null -ne $legacyRelayPreimage){
        Set-InstallationEvidenceStage 'canonical.official_legacy_relay_quiesce'
        $legacyRelayRestoreNeeded=$true;$mutated=$true
        $audit.scheduled_writer.official_legacy.status='DISABLING'
        Save $auditPath $audit
        $legacyTransitionWriter=[pscustomobject]@{mechanism='scheduled_task';task_path=$legacyRelayBefore.task_path;task_name=$legacyRelayBefore.task_name;
            xml=$legacyRelayBefore.xml;observed_enabled=[bool]$legacyRelayBefore.enabled;transition_record=$legacyRelayPreimage}
        $legacyTransition=Invoke-CanonicalOfficialLegacyRelayTransition @($legacyTransitionWriter) (Get-CanonicalOfficialLegacyRelayExpectedSet) install $true
        $audit.scheduled_writer.official_legacy['transition']=$legacyTransition.audit
        if($legacyTransition.audit[0].status -cne 'PROVEN' -or $legacyTransition.state[0].enabled){throw 'OFFICIAL_LEGACY_RELAY_QUIESCENCE_UNPROVEN'}
        $audit.scheduled_writer.official_legacy.status='PROVEN_DISABLED_QUIESCENT'
        Save $auditPath $audit
    }
    if ($writerRestoreNeeded) {
        $writerDisabled = Disable-CanonicalWriter $install $writerBefore
        $audit.scheduled_writer.disable_readback = $writerDisabled
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
        $writerStopped = Confirm-CanonicalWriterStopped $install $writerBefore $writerDisabled
        $audit.scheduled_writer.stop_proof = $writerStopped
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
    }
    if ($placement -eq 'INSTALL_REQUIRED') {
        $replaceExisting = Test-Path -LiteralPath $install -PathType Container
        if ($replaceExisting) {
            Sync-CanonicalWriterFenceInventory $installedInventorySha256
            $mutated = $true
            if($supportedPlacement){Product ([string]$supportedContext.active_code_root) '--remove-current-user-setup' (Join-Path $install 'app')}else{Product $install '--remove-current-user-setup'}
            $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
            # Rollback invokes removal again; preserve this first result before
            # that supported recovery overwrites the product's status file.
            $audit.code_replacement.runtime_removal_receipt = $removal
            Save $auditPath $audit
            if ($evidenceFull) { Save $evidenceFull $audit }
            $audit.code_replacement.runtime_quiescence_readback = Confirm-CanonicalRuntimeQuiescence `
                -Removal $removal -ExpectedRelays $old -StopRequestPath $stop
            $runtimeQuiescedForReplacement = $true
            Write-CanonicalInstallReentryRecord 'RUNTIME_QUIESCED_UNPLACED'
            $audit.code_replacement.status='PRESTATE_VERIFIED_RUNTIME_QUIESCED'
            Save $auditPath $audit $true
            if ($evidenceFull) { Save $evidenceFull $audit $true }
        }
        Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256
        if($replaceExisting){Write-CanonicalInstallReentryRecord 'PLACEMENT_ATTEMPTED'}
        $bootstrap = @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $source 'INSTALL_THIS_PC.ps1'),
            '-SourceRoot',$source,
            '-InstallRoot',$install,
            '-OperatorLocalAppDataRoot',$lad,
            '-OperatorSid',$operatorSid,
            '-OperatorDataRoot',$activeDataRoot,
            '-ElevationLogPath',$elevationLogPath,
            '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
            '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
            '-WriterFenceHelperPath',(Join-Path $source 'tools\container_writer_fence.ps1'),
            '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
            '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
            '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
            '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
            '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
        )
        if ($replaceExisting) {
            $bootstrap += @(
                '-ReplaceExistingVerifiedPortable',
                '-ReplacementTransactionId',$replacementTransactionId,
                '-ReplacementReceiptPath',$replacementReceiptPath
            )
        }
        if($supportedPlacement){$bootstrap+=@('-SupportedActiveVersionPlacement','-SupportedFromCommit',([string]$supportedContext.from_commit))}
        if ($testMode) { $bootstrap += '-AllowNoncanonicalLayoutForTest' }
    Set-InstallationEvidenceStage 'canonical.placement_child'
        $previousErrorActionPreference = $ErrorActionPreference
        $bootstrapChild=$null
        try {
            # Keep the elevated helper's raw stderr out of operator-facing
            # output; only a bounded classification line may cross this edge.
            $ErrorActionPreference = 'Continue'
            $audit.code_placement='STARTED_CHILD'
            if($null -ne $canonicalTransactionJob){
                $bootstrapChild = Invoke-InstallationTransactionPlacement $canonicalTransactionJob
            }else{
                $bootstrapChild = Invoke-InstallationEvidenceChild 'placement-helper' $winps $bootstrap
            }
            $bootstrapOutput = @($bootstrapChild.Stdout -split "`r?`n")
            $bootstrapExitCode = $bootstrapChild.ExitCode
            $audit.code_replacement['child_streams']=$bootstrapChild.Streams
            $audit.code_replacement['child_failure_summary']=$bootstrapChild.FailureDiagnostic
            $binding=if($null -ne $canonicalTransactionJob){
                $canonicalTransactionJob.Placement.binding
            }else{Read-InstallationHelperEvidenceBinding $bootstrapOutput $elevationLogPath $bootstrapChild.ProcessId ([string]$sourceManifest.helper_sha256)}
            if($null -ne $canonicalTransactionJob){
                Register-InstallationChildEvidenceSummary $canonicalTransactionJob.Placement.evidence_summary
                Register-InstallationChildEvidenceSummary $binding.child_stage_evidence_summary
            }
            $audit.code_replacement['child_evidence_binding']=$binding
            $audit.code_replacement['child_stage_evidence_root']=[string]$binding.stage_evidence_root
        } catch {
    Write-InstallationCaughtFailure $_

            if($null -eq $bootstrapChild){
                $bootstrapOutput = @('code_placement_preflight_failure=CONTAINER_PLACEMENT_CHILD_FAILED')
                $bootstrapExitCode = 1
            }else{
                $bindingFailure=Get-InstallationFailureDetails $_
                $audit.code_replacement['child_evidence_binding_failure']=$bindingFailure
                Write-InstallationEvidenceEvent ([ordered]@{event='CHILD_EVIDENCE_BINDING_FAILED';child_exit_code=[int]$bootstrapChild.ExitCode;failure=$bindingFailure})
                Register-InstallationChildEvidenceSummary @{status='INCOMPLETE';recording_failed=$true}
                # Keep a failed child's native code and first one-line summary.
                # A successful child still fails closed when evidence is unbound.
                if($bootstrapExitCode -eq 0){$bootstrapExitCode=1}
            }
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if($supportedPlacement -and $null -ne $binding) {
            # A failed child may have published only part of the authenticated
            # control cut. Bind its protected receipt before entering rollback.
            $protectedReceiptPath=Join-Path ([string]$binding.stage_evidence_root) 'replacement-receipt.json'
            if(Test-Path -LiteralPath $protectedReceiptPath -PathType Leaf) {
                $replacementReceiptPath=Read-CanonicalHelperArtifact $binding 'replacement-receipt.json' 'REPLACEMENT_RECEIPT_READY'
                $replacementReceiptSha256=Sha $replacementReceiptPath
                $replacementReceipt=ReadReplacementReceipt $replacementReceiptPath $replacementTransactionId $install $sourceManifest $sourceManifestSha256 $sourceHelperSha256 $sourceIntegrityHelperSha256
                $codeRestoreNeeded=$true
                $audit.code_replacement.receipt_path=$replacementReceiptPath
                $audit.code_replacement.receipt_sha256=$replacementReceiptSha256
                $audit.code_replacement.rollback_root=[string]$replacementReceipt.rollback_root
            }
        }
        if ($bootstrapExitCode -ne 0) {
            $audit.code_placement='FAILED_CHILD'
            $preflightFailure = @($bootstrapOutput | Where-Object {
                [string]$_ -cmatch '^code_placement_preflight_failure=CONTAINER_[A-Z_]+$'
            } | Select-Object -Last 1)
            $failureCode = if ($preflightFailure.Count -eq 1) {
                ([string]$preflightFailure[0]).Split('=')[1]
            } else { 'CONTAINER_PLACEMENT_CHILD_FAILED' }
            $audit.code_replacement.failure_code=$failureCode
            $audit.code_replacement.child_exit_code=[int]$bootstrapExitCode
            if($failureCode -ceq 'CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED') {
                $audit.code_placement='PREPLACEMENT_REJECTED_ANCESTORS'
                $lines=@($bootstrapOutput | Where-Object {
                    [string]$_ -cmatch '^ancestor_trust_failure=설치 폴더 권한을 확인하세요: C:\\KMTech(?:\\Apps(?:\\Container_Audit)?)? \([^\r\n()]{1,120}\)\. 지원 담당자에게 문의하세요\.$'
                } | Select-Object -Last 1)
                $text=if($lines.Count -eq 1){([string]$lines[0]).Substring('ancestor_trust_failure='.Length)}else{'설치 폴더 권한을 확인하세요: C:\KMTech 또는 C:\KMTech\Apps (지원하지 않는 권한 상태입니다). 지원 담당자에게 문의하세요.'}
                $failure=[InvalidOperationException]::new($text)
                $failure.Data['canonical_code']=$failureCode
                throw $failure
            }
            $reason = if ($failureCode -cmatch 'MUTEX_TIMEOUT$') {
                '다른 설치 또는 기록 작업이 진행 중입니다.'
            } elseif ($failureCode -cmatch 'DELEGATED_OPERATION_MISMATCH$') {
                '이번 설치 준비가 만료되었거나 다른 시도와 섞였습니다.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_ACCESS_DENIED') {
                '준비 폴더에 접근할 권한이 없습니다. 작업자 계정과 폴더 권한을 확인하세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_PATH_UNAVAILABLE') {
                '준비 파일 경로를 찾을 수 없습니다. 원래 설치 묶음과 폴더를 확인하세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_LOG_UNREADABLE') {
                '권한 상승 작업의 결과 기록을 읽지 못했습니다. 기록 폴더 권한을 확인하세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_LOG_WRITE_FAILED') {
                '권한 상승 작업의 결과 기록을 남기지 못했습니다. 기록 폴더의 쓰기 권한과 저장 공간을 확인하세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING') {
                '같은 PC 의 다른 Windows 사용자 세션에서 이적 검사 프로그램이 실행 중입니다. 그 사용자를 로그아웃한 뒤 다시 설치하세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_CHILD_FAILED') {
                '권한 상승 작업이 결과 기록 없이 비정상 종료됐습니다. 담당자에게 문의 코드를 알려 주세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_ELEVATION_FAILED') {
                '관리자 권한 요청을 완료하지 못했습니다. 관리자 실행을 다시 확인하세요.'
            } elseif ($failureCode -ceq 'CONTAINER_PLACEMENT_UNCLASSIFIED') {
                '분류 안 된 오류가 발생했습니다. 아래 문의 코드를 담당자에게 알려 주세요.'
            } elseif ($failureCode -cmatch '^CONTAINER_PLACEMENT_') {
                '준비 파일을 읽거나 쓰지 못했습니다. 저장 공간과 폴더 상태를 확인하세요.'
            } else {
                '작업자 계정의 준비 폴더와 권한 상승 요청이 일치하지 않습니다.'
            }
            $inquiryCode = 'CA-' + (Get-ContainerWriterFenceStringSha256 ($operatorSid + '|' + $env:COMPUTERNAME + '|' + $Script:CanonicalWriterFenceAttemptId)).Substring(0, 12).ToUpperInvariant()
            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("설치 코드 배치 전 중단: $reason 문의 코드 $inquiryCode ($failureCode). 준비 상태를 다시 확인하고 설치를 재시도하세요. 기존 설치본과 기록은 그대로 보존되며, 이 시도는 보류하고 다른 업무를 계속할 수 있습니다.")) -UserLine)
        }
        if($replaceExisting){Write-CanonicalInstallReentryRecord 'PLACEMENT_COMPLETED'}
        $audit.code_placement='PLACED_PENDING_VERIFICATION'
        $currentTreeInventorySha256 = $Script:ContainerWriterFenceInventorySha256
        if ($replaceExisting) {
            if (-not $testMode) {
                $replacementReceiptPath=Read-CanonicalHelperArtifact $binding 'replacement-receipt.json' 'REPLACEMENT_RECEIPT_READY'
            }
            $replacementReceiptSha256 = Sha $replacementReceiptPath
            $replacementReceipt = ReadReplacementReceipt `
                -Path $replacementReceiptPath `
                -ExpectedTransactionId $replacementTransactionId `
                -ExpectedInstallRoot $install `
                -ExpectedSourceManifest $sourceManifest `
                -ExpectedManifestSha256 $sourceManifestSha256 `
                -ExpectedHelperSha256 $sourceHelperSha256 `
                -ExpectedIntegrityHelperSha256 $sourceIntegrityHelperSha256
            if (
                -not (Test-Path -LiteralPath ([string]$replacementReceipt.rollback_root) -PathType Container) -or
                -not (Test-Path -LiteralPath $install -PathType Container)
            ) { throw 'Verified replacement preserved-tree readback failed.' }
            $codeRestoreNeeded = $true
            $placement = 'REPLACED_VERIFIED'
            $audit.code_replacement.status='OLD_PRESERVED_NEW_VERIFIED'
            $audit.code_replacement.receipt_path=$replacementReceiptPath
            $audit.code_replacement.receipt_sha256=$replacementReceiptSha256
            $audit.code_replacement.rollback_root=[string]$replacementReceipt.rollback_root
            $audit.code_replacement.later_restore_surface='READY_PUBLIC_CANONICAL_RESTORE'
        }
        else { $placement = 'PASS_NEW_VERIFIED' }
    }
    Set-InstallationEvidenceStage 'canonical.installed_verification'
    $installedManifest = InstalledManifest $installedCodeRoot $SkipSignatureValidationForTest
    if (
        [string]$installedManifest.source_commit -cne [string]$sourceManifest.source_commit -or
        [string]$installedManifest.source_tree -cne [string]$sourceManifest.source_tree -or
        (Sha (Join-Path $installedCodeRoot 'portable-manifest.json')) -cne $sourceManifestSha256
    ) { throw 'Installed identity differs.' }
    $installedHelper = (Join-Path $source 'tools\bootstrap_integrity.ps1').Replace("'","''")
    $escapedInstalledRoot = $installedCodeRoot.Replace("'","''")
    $capturedChild=Invoke-InstallationEvidenceChild 'verify-installed-code' $winps @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',". '$installedHelper'; [void](Assert-BootstrapIntegrityRecord '$escapedInstalledRoot')")
    $global:LASTEXITCODE=$capturedChild.ExitCode
    if ($LASTEXITCODE -ne 0) { throw 'Installed aggregate integrity differs.' }
    $audit.code_placement=$placement
    $audit.source_commit=[string]$installedManifest.source_commit
    $audit.runtime_pythonw_sha256=Sha (Join-Path $install 'runtime\pythonw.exe')
    $audit.runtime_pythonw_signature=[string](Get-AuthenticodeSignature (Join-Path $install 'runtime\pythonw.exe')).Status
    Save $auditPath $audit $true
    if ($evidenceFull) { Save $evidenceFull $audit $true }

    $mutated = $true
    if($supportedPlacement){Product $source '--remove-current-user-setup' (Join-Path $install 'app')}else{Product $install '--remove-current-user-setup'}
    $removal = Get-Content $removalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((Snapshot).exists -or [string]$removal.status -cne 'PASS_DATA_PRESERVED' -or
        [string]$removal.relay_process.status -cne 'ABSENT' -or @(Relays).Count -ne 0) { throw 'Removal readback failed.' }
    $started = (Get-Date).ToUniversalTime()
    Set-InstallationEvidenceStage 'canonical.onboarding'
    if($null -ne $canonicalTransactionJob){Assert-InstallationTransactionAlive $canonicalTransactionJob}
    if($supportedPlacement){Product $source '--onboard-current-user' (Join-Path $installedCodeRoot 'app')}else{Product $install '--onboard-current-user'}
    $onboarding = Get-Content $onboardingPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Set-InstallationEvidenceStage 'canonical.onboarding_run_readback'
    $after = Snapshot
    if ([string]$onboarding.status -cne 'READY' -or [string]$onboarding.relay_autostart.command -cne $wanted -or
        -not $after.exists -or [string]$after.data -cne $wanted) { throw 'Onboarding Run readback failed.' }
    if ($onboardingServerBaseUrl) {
        $boundServerBaseUri = $null
        if (
            -not [Uri]::TryCreate([string]$onboarding.state_readback.base_url, [UriKind]::Absolute, [ref]$boundServerBaseUri) -or
            $boundServerBaseUri.Scheme -cne 'https' -or
            $boundServerBaseUri.Host -ine $onboardingServerBaseUri.Host -or
            $boundServerBaseUri.Port -ne $onboardingServerBaseUri.Port
        ) { throw 'Onboarding server endpoint readback failed.' }
    }
    if([string]$onboarding.relay_start.status -cne 'DEFERRED_CANONICAL_RELEASE' -or
        -not(Test-BootstrapJsonInteger $onboarding.relay_start.process_id) -or
        [int64]$onboarding.relay_start.process_id -ne 0 -or -not $canonicalWriterFenceActive){
        throw 'Onboarding relay release deferral readback failed.'
    }
    Set-InstallationEvidenceStage 'canonical.relay_identity_and_status'
    # Persist the READY installation result while this install session still
    # holds admission, before any natural-trigger or resident-relay release.
    if($null -ne $legacyRelayPreimage){Save-CanonicalOfficialLegacyRelayTransitionPointer $legacyRelayPreimage -Required}
    $pidValue=0
    $audit.status=if ($testMode) { 'TEST_ONLY_PARTIAL' } else { 'PRODUCT_PHASE_PASS' }
    $audit.stop_marker_absent=-not(Test-Path $stop)
    $audit.onboarding=[ordered]@{status=[string]$onboarding.status;action=[string]$onboarding.action;autostart_writer='product_onboarding';server_base_url=$onboardingServerBaseUrlLabel;bound_server_base_url=[string]$onboarding.state_readback.base_url}
    $audit.exact_launch=[ordered]@{status='PENDING_FENCE_RELEASE';process_id=0;launcher_pid_is_not_resident_proof=$true}
    Save $auditPath $audit $true
    if ($evidenceFull) { Save $evidenceFull $audit $true }

    if ($writerRestoreNeeded) {
        Set-InstallationEvidenceStage 'canonical.scheduled_writer_restore'
        $writerEnabled = Enable-CanonicalWriter $install $writerBefore
        $audit.scheduled_writer.restore_readback = $writerEnabled
        $audit.status='WRITER_ENABLED_AWAITING_NATURAL_TRIGGER'
        Save $auditPath $audit $true
        if ($evidenceFull) { Save $evidenceFull $audit $true }
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productNaturalTriggerAuthorizationPath `
            -Phase 'PRODUCT_NATURAL_TRIGGER' `
            -AuditPath $auditPath `
            -EnabledBaseline $writerEnabled
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        Set-InstallationEvidenceStage 'canonical.normal_relay_after_release'
        $pidValue = Start-CanonicalRelayAfterFenceRelease
        $audit.exact_launch=$Script:CanonicalRelayProof
        $writerRunning = Confirm-CanonicalWriterRunning $install $writerEnabled
        $audit.scheduled_writer.natural_trigger_proof = $writerRunning
        $audit.rollback.scheduled_writer_restored=$true
        $writerRestoreNeeded=$false
    }
    if($null -ne $legacyRelayPreimage){
        $legacyAfter=Get-CanonicalOfficialLegacyRelayPreimage
        if($null -eq $legacyAfter -or $legacyAfter.enabled -or $legacyAfter.identity.sha256 -cne $legacyRelayBefore.identity.sha256){throw 'OFFICIAL_LEGACY_RELAY_SUCCESS_NOT_DISABLED'}
        $audit.scheduled_writer.official_legacy.status='REPLACED_BY_CANONICAL_DISABLED_RETAINED'
    }
    $terminalStatus=Get-CanonicalInstallSuccessStatus $testMode
    $audit.status='PRODUCT_AWAITING_RESIDENT_RELAY'
    Save $auditPath $audit $true
    if ($evidenceFull) { Save $evidenceFull $audit $true }
    if ($canonicalWriterFenceActive) {
        Set-InstallationEvidenceStage 'canonical.complete_fence_release'
        $releaseAuthorization = New-CanonicalWriterFenceReleaseAuthorization `
            -Path $productCompleteAuthorizationPath `
            -Phase 'PRODUCT_COMPLETE' `
            -AuditPath $auditPath
        $canonicalWriterFenceLastReleaseAuthorizationPath = [string]$releaseAuthorization.path
        $canonicalWriterFenceLastReleaseAuthorizationSha256 = [string]$releaseAuthorization.sha256
        Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
        Clear-CanonicalWriterFenceReleaseDelegation
        Stop-CanonicalWriterFenceRelease $releaseAuthorization
        $canonicalWriterFenceActive = $false
        Set-InstallationEvidenceStage 'canonical.normal_relay_after_release'
        $pidValue = Start-CanonicalRelayAfterFenceRelease
        $audit.exact_launch=$Script:CanonicalRelayProof
    }
    if($pidValue -le 0 -or [string]$audit.exact_launch.status -cne 'PROVEN'){throw 'Resident relay acceptance is absent.'}
    Set-InstallationEvidenceStage 'canonical.worker_shortcuts'
    $audit['worker_shortcuts']=Install-BootstrapWorkerShortcuts $install $workerShortcutRecordPath 'User'
    if($testMode -and $null -eq $canonicalTransactionJob){
        $commonRecord=Get-BootstrapWorkerShortcutCommonRecordPath $install
        $audit['common_worker_shortcuts']=Install-BootstrapWorkerShortcuts $install $commonRecord 'Common'
    }
    $shortcutResults=@($audit.worker_shortcuts)
    if($audit.Contains('common_worker_shortcuts')){$shortcutResults+=@($audit.common_worker_shortcuts)}
    Set-CanonicalPublishedShortcuts $audit $shortcutResults
    $audit.status=$terminalStatus
    $audit.completed_at=(Get-Date).ToUniversalTime().ToString('o')
    Save $auditPath $audit
    if ($evidenceFull) { Save $evidenceFull $audit }
    if($null -ne $canonicalTransactionJob){
        $transactionOutcome=Complete-InstallationTransaction $canonicalTransactionJob 'COMMIT'
        if([string]$transactionOutcome.status -cne 'COMMITTED'){throw 'Canonical transaction commit acknowledgement differs.'}
        $audit['common_worker_shortcuts']=$transactionOutcome.worker_shortcuts
        Set-CanonicalPublishedShortcuts $audit @($audit.worker_shortcuts,$audit.common_worker_shortcuts)
        $audit.persistent_helper.status='COMMITTED'
        Save $auditPath $audit
        if($evidenceFull){Save $evidenceFull $audit}
    }
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("install_status=$terminalStatus")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("install_root=$install")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("code_placement_status=$placement")))
    'autostart_status=PROVEN_NON_REBOOT_APPROXIMATION'
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("autostart_command=$wanted")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("onboarding_server_base_url=$onboardingServerBaseUrlLabel")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("autostart_process_id=$pidValue")))
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("stop_marker_absent=$($audit.stop_marker_absent.ToString().ToLowerInvariant())")))
    if ($codeRestoreNeeded) {
        (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_receipt_path=$replacementReceiptPath")))
        (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_receipt_sha256=$replacementReceiptSha256")))
        (ConvertTo-KmtechRedactedSinkText -Text ([string]("replacement_transaction_id=$replacementTransactionId")))
        'later_phase_replacement_restore_status=READY_PUBLIC_CANONICAL_RESTORE'
    }
    'cold_boot_status=UNPROVEN'
    (ConvertTo-KmtechRedactedSinkText -Text ([string]("audit_path=$auditPath")))
}
catch {
    Write-InstallationCaughtFailure $_

    $original=$_
    $canonicalTransactionJob=Get-Variable -Name canonicalTransactionJob -ValueOnly -ErrorAction SilentlyContinue
    if($null -eq $canonicalTransactionJob -and $original.Exception.Data.Contains('installation_transaction_job')){
        $canonicalTransactionJob=$original.Exception.Data['installation_transaction_job']
        $canonicalWriterFenceAuthority=$null
    }
    if ($null -ne $audit -and -not $audit.Contains('diagnostic_write_failures')) {
        $audit['diagnostic_write_failures']=@()
    }
    # Diagnostics cannot prevent independent recovery. The sealed retirement
    # audit remains immutable; a separate evidence path records write failures.
    function Save-CanonicalRecoveryDiagnostics {
        param([string]$Phase)
        try {
            if (-not $retirementAuditSealed) { Save $auditPath $audit $true }
        }
        catch {
            Write-InstallationCaughtFailure $_
            $audit['diagnostic_write_failures']=@($audit.diagnostic_write_failures)+@(
                [ordered]@{phase=$Phase;target='audit';failure_type=$_.Exception.GetType().Name})
            Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('rollback_audit_status=UNAVAILABLE')))
        }
        if ($evidenceFull) {
            try { Save $evidenceFull $audit $true }
            catch {
                Write-InstallationCaughtFailure $_
                $audit['diagnostic_write_failures']=@($audit.diagnostic_write_failures)+@(
                    [ordered]@{phase=$Phase;target='evidence';failure_type=$_.Exception.GetType().Name})
                Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('rollback_evidence_status=UNAVAILABLE')))
                try { Save $evidenceFull $audit $true }
                catch {
            Write-InstallationCaughtFailure $_
 Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string]('rollback_evidence_failure_record_status=UNAVAILABLE'))) }
            }
        }
    }
    Fail-InstallationEvidenceStages $original
    Set-InstallationEvidenceStage 'rollback.entry' 'rollback'
    if ($enteredPlacementTry) {
        if(-not $RestoreVerifiedReplacement -and -not $Uninstall -and -not $CompleteRetiredRemoval){
            $canonicalInstallationCommitPoint=Get-CanonicalInstallationCommitPoint -Manifest $sourceManifest `
                -TargetSid $operatorSid -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source
            $audit.rollback['commit_point_status']=$canonicalInstallationCommitPoint
            if($canonicalInstallationCommitPoint -cne 'NOT_REACHED'){$codeRestoreNeeded=$false}
        }
        $audit.failure_type=$original.Exception.GetType().Name
        $audit.failure=Get-CanonicalFailureDetails $original 'INSTALL'
        Save-CanonicalRecoveryDiagnostics 'catch.entry'
        if($null -ne $canonicalTransactionJob){
            try{
                $transactionOutcome=Complete-InstallationTransaction $canonicalTransactionJob 'ROLLBACK'
                $proof=$transactionOutcome.compensation
                $audit.rollback['persistent_helper_result']=$transactionOutcome
                $audit.rollback.code_exact=[bool]$proof.code_exact
                $audit.rollback.runtime_restored=[bool]$proof.runtime_restored
                $audit.rollback.scheduled_writer_restored=[bool]$proof.scheduled_writer_restored
                $canonicalWriterFenceActive=-not [bool]$proof.fence_released
                $audit.status=[string]$proof.status
                $legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$true
                if([string]$proof.status -cnotin @('FAILED_ROLLED_BACK','FAILED_RUNTIME_RESTORED_CODE_RETAINED')){throw 'Persistent helper recovery is unproven; fence retained.'}
                $audit['worker_shortcuts']=Restore-BootstrapWorkerShortcuts $install $workerShortcutRecordPath 'User'
                Save-CanonicalRecoveryDiagnostics 'rollback.persistent_helper_complete'
            }catch{
                Write-InstallationCaughtFailure $_
                $audit.status='CODE_ROLLBACK_FAILED'
                $audit.rollback['persistent_helper_failure']=Get-CanonicalFailureDetails $_ 'PERSISTENT_HELPER'
                $legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$true
                Save-CanonicalRecoveryDiagnostics 'rollback.persistent_helper_unknown'
            }
            $publicFailure=[InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text $original.Exception.Message -UserLine),$original.Exception)
            $publicFailure.Data['original_type']=$original.Exception.GetType().FullName
            throw [Management.Automation.ErrorRecord]::new($publicFailure,'CanonicalInstallationFailed',[Management.Automation.ErrorCategory]::InvalidOperation,$null)
        }
        if (-not $testMode -and $codeRestoreNeeded -and -not $RestoreVerifiedReplacement) {
            if (-not $canonicalWriterFenceActive) {
                [void](Start-ContainerWriterFence -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
                    -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
                    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
                    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 -WriterContractSha256 $canonicalWriterFenceContractSha256 `
                    -PreparedReceiptPath ([string]$canonicalWriterFencePreparedReceipt.path) -PreparedReceiptSha256 ([string]$canonicalWriterFencePreparedReceipt.sha256) `
                    -DelegationToken $Script:CanonicalWriterFenceDelegationToken -DelegatedSources $canonicalWriterFenceDelegatedSources `
                    -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) -AuthorityLease $canonicalWriterFenceAuthority)
                $canonicalWriterFenceActive=$true
                [Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',$Script:CanonicalWriterFenceDelegationToken,'Process')
                [Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID',$Script:CanonicalWriterFenceSessionId,'Process')
                [Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID',$Script:CanonicalWriterFenceAttemptId,'Process')
                [Environment]::SetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID',$Script:CanonicalWriterFenceTransactionId,'Process')
            }
            try {Write-CanonicalRollbackContinuation}
            catch {Write-InstallationCaughtFailure $_;$audit.rollback['continuation_failure']=Get-CanonicalFailureDetails $_ 'ROLLBACK_CONTINUATION';Save-CanonicalRecoveryDiagnostics 'rollback.continuation'}
        }
    }
    if (-not $enteredPlacementTry) {
        if($Script:CanonicalInstallerRelayStopAttempted){
            $Script:CanonicalInstallerEarlyRecovery=[ordered]@{status='RECOVERY_REQUIRED';stop_preimage_restored=$false;run_preimage_proven=$false;ready_proven=$false}
        }
        if ($retirementResume -and $canonicalWriterFenceActive) {
            throw 'RETIREMENT_RESUME_JOURNAL_UNKNOWN_FENCE_RETAINED'
        }
        try {
            $earlyFenceMatches = $false
            try {
                $earlyFence = Read-ContainerWriterFence -AllowAbsent
                $earlyFenceMatches = (
                    $null -ne $earlyFence -and
                    [string]$earlyFence.session_id -ceq $Script:CanonicalWriterFenceSessionId -and
                    [string]$earlyFence.attempt_id -ceq $Script:CanonicalWriterFenceAttemptId -and
                    [string]$earlyFence.replacement_transaction_id -ceq $Script:CanonicalWriterFenceTransactionId
                )
            }
            catch {
        Write-InstallationCaughtFailure $_
     $earlyFenceMatches = $canonicalWriterFenceActive }
            if ($earlyFenceMatches) {
                try {
                    [void](Abort-ContainerWriterFence `
                        -SessionId $Script:CanonicalWriterFenceSessionId `
                        -AttemptId $Script:CanonicalWriterFenceAttemptId `
                        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                        -AuthorityLease $canonicalWriterFenceAuthority)
                    $canonicalWriterFenceActive = $false
                }
                catch {
        Write-InstallationCaughtFailure $_
     throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("CANONICAL_WRITER_FENCE_EARLY_ABORT_FAILED: $($_.Exception.GetType().Name)")) -UserLine) }
            }
            if (Test-Path -LiteralPath $canonicalWriterFencePreparedPath) {
                Remove-Item -LiteralPath $canonicalWriterFencePreparedPath -ErrorAction Stop
                if (Test-Path -LiteralPath $canonicalWriterFencePreparedPath) {
                    throw 'CANONICAL_WRITER_FENCE_EARLY_RECEIPT_CLEANUP_FAILED'
                }
            }
            if($Script:CanonicalInstallerRelayStopAttempted){
                [void](Restore-CanonicalInstallerEarlyRuntime -Before $before -Old $old -Root $install)
            }
            elseif ($earlyFenceMatches -and $old.Count -gt 0) {
                if (@(Relays).Count -eq 0) {
                    [void](Start-CanonicalRelayAfterFenceRelease -Root $install -RunCommand ([string]$before.data))
                }
                [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
            }
        } catch {
            if($Script:CanonicalInstallerRelayStopAttempted){
                $Script:CanonicalInstallerEarlyRecovery.status='RECOVERY_REQUIRED'
                Write-InstallationCaughtFailure $_
                $recoveryFailure=[InvalidOperationException]::new('RECOVERY_REQUIRED',$original.Exception)
                $recoveryFailure.Data['original_type']=$original.Exception.GetType().FullName
                throw $recoveryFailure
            }
            throw
        }
        Write-CanonicalInstallerRelayGuidance
        $publicFailure=[InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text $original.Exception.Message -UserLine),$original.Exception);$publicFailure.Data['original_type']=$original.Exception.GetType().FullName;$publicRecord=[Management.Automation.ErrorRecord]::new($publicFailure,'CanonicalInstallationFailed',[Management.Automation.ErrorCategory]::InvalidOperation,$null);throw $publicRecord
    }
    if (-not $canonicalWriterFenceActive) {
        try {
            $refenceStatus = 'INSTALLING'
            $refencePreparedPath = [string]$canonicalWriterFencePreparedReceipt.path
            $refencePreparedSha256 = [string]$canonicalWriterFencePreparedReceipt.sha256
            if (-not [string]::IsNullOrWhiteSpace($canonicalWriterFenceLastReleaseAuthorizationPath)) {
                $refenceStatus = 'RESTORE_FAILED'
                $refencePreparedPath = $canonicalWriterFenceLastReleaseAuthorizationPath
                $refencePreparedSha256 = $canonicalWriterFenceLastReleaseAuthorizationSha256
            }
            [void](Start-ContainerWriterFence `
                -Status $refenceStatus `
                -OwnerKind 'canonical_installer' `
                -SessionId $Script:CanonicalWriterFenceSessionId `
                -AttemptId $Script:CanonicalWriterFenceAttemptId `
                -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
                -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
                -WriterContractSha256 $canonicalWriterFenceContractSha256 `
                -PreparedReceiptPath $refencePreparedPath `
                -PreparedReceiptSha256 $refencePreparedSha256 `
                -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
                -DelegatedSources $canonicalWriterFenceDelegatedSources `
                -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) `
                -AuthorityLease $canonicalWriterFenceAuthority)
            $canonicalWriterFenceActive = $true
        }
        catch {
    Write-InstallationCaughtFailure $_

            throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("CANONICAL_WRITER_REFENCE_FAILED: $($_.Exception.GetType().Name)")) -UserLine)
        }
    }
    if ($Uninstall -and -not $CompleteRetiredRemoval) {
        # Removal converges on removal; never resurrect moved code, tasks or Run.
        if ($null -ne $supportedRemovalProductStartedAt) {
            try {
                $audit['removal_attempt_stop_cleanup']=Remove-CanonicalSupportedRemovalAttemptStop `
                    -RemovalPath $removalPath -StopPath $stop -StartedAt $supportedRemovalProductStartedAt `
                    -ExpectedAppRoot (Join-Path $install 'app') -ExpectedStopSha256 $uninstallStopSha256
            } catch {
                Write-InstallationCaughtFailure $_
                $audit['removal_attempt_stop_cleanup']='FAILED_OWNERSHIP_UNPROVEN'
                $audit['removal_attempt_stop_cleanup_failure']=Get-CanonicalFailureDetails $_
            }
        }
        if($canonicalWriterFenceActive){
            [void](Abort-ContainerWriterFence -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
                -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -AuthorityLease $canonicalWriterFenceAuthority)
            $canonicalWriterFenceActive=$false
        }
        $audit.status='FAILED_REMOVAL_INCOMPLETE';$audit.rollback.applied=$false;$audit.rollback.runtime_restored=$false
        try{Save $auditPath $audit;if($evidenceFull){Save $evidenceFull $audit}}catch{Write-InstallationCaughtFailure $_}
        $publicFailure=[InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text $original.Exception.Message -UserLine),$original.Exception);$publicFailure.Data['original_type']=$original.Exception.GetType().FullName;$publicRecord=[Management.Automation.ErrorRecord]::new($publicFailure,'CanonicalInstallationFailed',[Management.Automation.ErrorCategory]::InvalidOperation,$null);throw $publicRecord
    }
    if ($Uninstall) {
        $retirementAuditSealed=$false
        # Retirement recovery attempts each independent preimage even when an
        # earlier step fails. Writers reopen only after every exact proof passes.
        $retirementRollbackSteps = [Collections.Generic.List[object]]::new()
        $retirementCodeExact=$false; $retirementRunExact=$false
        $retirementStopExact=$false; $retirementPairExact=$false
        $retirementRelaysBound=$false; $retirementRelaysExact=$false
        $retirementFenceReleased=$false
        $retirementActions = @(
            @{name='delegation'; action={
        $uninstallActiveFence = Read-ContainerWriterFence
        [void](Set-ContainerWriterFencePrepared `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -PreparedReceiptPath ([string]$uninstallActiveFence.prepared_receipt_path) `
            -PreparedReceiptSha256 ([string]$uninstallActiveFence.prepared_receipt_sha256) `
            -Status 'RESTORING' -AuthorityLease $canonicalWriterFenceAuthority)
        [void](Set-ContainerWriterFenceDelegation `
            -SessionId $Script:CanonicalWriterFenceSessionId `
            -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
            -DelegationToken $Script:CanonicalWriterFenceDelegationToken `
            -DelegatedSources $canonicalWriterFenceDelegatedSources `
            -LifetimeSeconds 300 `
            -AuthorityLease $canonicalWriterFenceAuthority)
            }},
            @{name='code'; action={
                $codeAlreadyExact=$false
                if (Test-Path -LiteralPath $install) {
                    try {
                        [void](Assert-BootstrapIntegrityRecord $install)
                        $codeAlreadyExact=((Get-InventoryAggregate @(Get-CodeInventory $install)) -ceq $uninstallAggregate -and
                            (Sha (Join-Path $install 'bootstrap-integrity.json')) -ceq $uninstallRecordSha256)
                    } catch {
            Write-InstallationCaughtFailure $_
 $codeAlreadyExact=$false }
                }
                if ($uninstallCodeStarted -and -not $codeAlreadyExact) {
                    $recoverCodeArguments = @($uninstallArguments | Where-Object { $_ -cne '-Uninstall' })
                    $recoverCodeArguments += @('-RestoreUninstallRecordPath',$uninstallRecordPreimagePath,
                        '-ExpectedUninstallRecordSha256',$uninstallRecordSha256)
                    $capturedChild = Invoke-InstallationEvidenceChild 'uninstall-code-recovery' $winps $recoverCodeArguments
                    $global:LASTEXITCODE=$capturedChild.ExitCode
                    Write-CanonicalInstallationPublicRecord -ExitCode $capturedChild.ExitCode
                    if ($LASTEXITCODE -ne 0) {
                        $audit['retirement_recovery_child_failure']=Get-CanonicalRetirementChildFailure $capturedChild
                        Write-CanonicalInstallationPublicRecord -ExitCode $capturedChild.ExitCode
                        throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Uninstall exact code recovery failed: $LASTEXITCODE")) -UserLine)
                    }
                }
                [void](Assert-BootstrapIntegrityRecord $install)
                if ((Get-InventoryAggregate @(Get-CodeInventory $install)) -cne $uninstallAggregate -or
                    (Sha (Join-Path $install 'bootstrap-integrity.json')) -cne $uninstallRecordSha256) {
                    throw 'Uninstall exact code recovery not proven; runtime remains fenced.'
                }
                $retirementCodeExact=$true
                if ($uninstallCodeStarted) { $audit.code_placement='RESTORED_EXACT_PREIMAGE' }
            }},
            @{name='retired_pair'; action={
                [void](Read-CanonicalRetiredRemoval)
                $retirementPairExact=$true
            }},
            @{name='relay_identity'; action={
                foreach ($item in @(Relays)) {
                    if (@($old | Where-Object { [int]$_.ProcessId -eq [int]$item.ProcessId -and
                        [string]$_.CommandLine -ceq [string]$item.CommandLine -and
                        (Same ([string]$_.ExecutablePath) ([string]$item.ExecutablePath)) }).Count -ne 1) {
                        throw 'Uninstall recovery relay identity changed.'
                    }
                }
                $retirementRelaysBound=$true
            }},
            @{name='run_preimage'; action={
                Restore $before
                $check=Snapshot
                if ([bool]$check.exists -ne [bool]$before.exists -or [string]$check.kind -cne [string]$before.kind -or
                    [string]$check.data -cne [string]$before.data) { throw 'Uninstall Run preimage restore failed.' }
                $retirementRunExact=$true
            }},
            @{name='stop_preimage'; action={
                if (Test-Path -LiteralPath $stop) {
                    if (-not $uninstallStopSha256 -or (Sha $stop) -cne $uninstallStopSha256) {
                        throw 'RETIREMENT_ACTIVE_STOP_OWNERSHIP_UNKNOWN_RUNTIME_REMAINS_FENCED'
                    }
                    Assert-CanonicalRollbackStopCleanup
                    Remove-Item -LiteralPath $stop -Force
                }
                if (Test-Path -LiteralPath $stop) { throw 'Uninstall stop preimage restore failed.' }
                $retirementStopExact=$true
            }},
            @{name='fence_release'; action={
                if (-not ($retirementCodeExact -and $retirementPairExact -and $retirementRelaysBound -and
                    $retirementRunExact -and $retirementStopExact)) { throw 'RETIREMENT_EXACT_PREIMAGE_UNPROVEN_FENCE_RETAINED' }
                [void](Abort-ContainerWriterFence -SessionId $Script:CanonicalWriterFenceSessionId `
                    -AttemptId $Script:CanonicalWriterFenceAttemptId `
                    -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                    -AuthorityLease $canonicalWriterFenceAuthority)
                $canonicalWriterFenceActive=$false
                $retirementFenceReleased=$true
            }},
            @{name='old_relay'; action={
                if (-not $retirementFenceReleased) { throw 'RETIREMENT_OLD_RELAY_BLOCKED_BY_UNPROVEN_PREIMAGE' }
                if (@(Relays).Count -eq 0 -and $old.Count -gt 0) {
                    [void](Start-CanonicalRelayAfterFenceRelease -Root $install -RunCommand ([string]$before.data))
                }
                [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
                $retirementRelaysExact=$true
            }}
        )
        foreach ($step in $retirementActions) {
            Set-InstallationEvidenceStage ('rollback.retirement.'+$step.name) 'rollback'
            try {
                . $step.action
                $retirementRollbackSteps.Add([ordered]@{step=$step.name;status='PROVEN'})
            } catch {
                Write-InstallationCaughtFailure $_
                Complete-InstallationEvidenceStage 'rollback' $_
                $retirementRollbackSteps.Add([ordered]@{step=$step.name;status='FAILED';failure=Get-CanonicalFailureDetails $_ 'RETIREMENT_ROLLBACK'})
            }
        }
        $audit.rollback['steps']=$retirementRollbackSteps.ToArray()
        $audit.rollback.applied=$mutated
        $audit.rollback.code_exact=$retirementCodeExact
        $audit.rollback.runtime_restored=($retirementRunExact -and $retirementStopExact -and $retirementRelaysExact)
        $audit.status=if ($retirementFenceReleased -and $audit.rollback.runtime_restored) { 'FAILED_ROLLED_BACK' } else { 'RETIREMENT_ROLLBACK_INCOMPLETE_FENCED' }
        Save-CanonicalRecoveryDiagnostics 'uninstall.recovered'
        if ($retirementFenceReleased -and $audit.rollback.runtime_restored) {
            'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY'
        }
        $publicFailure=[InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text $original.Exception.Message -UserLine),$original.Exception);$publicFailure.Data['original_type']=$original.Exception.GetType().FullName;$publicRecord=[Management.Automation.ErrorRecord]::new($publicFailure,'CanonicalInstallationFailed',[Management.Automation.ErrorCategory]::InvalidOperation,$null);throw $publicRecord
    }
    if ($RestoreVerifiedReplacement) {
        # A child can restore the code and then fail while writing its evidence.
        # Select the exact surviving tree before invoking any product recovery.
        try {
            $survivingRestore = Read-CanonicalReplacementRestore
            if ([string]$survivingRestore.state -ceq 'RESTORED') {
                $currentTreeInventorySha256 = [string]$survivingRestore.old_inventory_sha256
                $placement = 'RESTORED_VERIFIED'
                $audit.code_placement = $placement
            }
            $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $currentTreeInventorySha256
            $audit.code_replacement.status = [string]$survivingRestore.state
        }
        catch {
    Write-InstallationCaughtFailure $_

            $audit.status = 'RESTORE_FAILED_CODE_STATE_UNVERIFIED'
            $audit.failure_type = $original.Exception.GetType().Name
            Save-CanonicalRecoveryDiagnostics 'restore.code_state_unverified'
            throw 'Canonical restore failed; code state is unverified and writers remain fenced.'
        }
    }
    $autostartRollbackFailure=''
    $codeRollbackFailure=''
    # Restore parent protection before any code/runtime trust check in rollback.
    # This uses the same non-recursive protected creator as initial preparation.
    if(-not $testMode){
        try{
            Restore-CanonicalApplicationProtection
        }catch{Write-InstallationCaughtFailure $_;$audit.rollback['app_protection_failure']=Get-InstallationFailureDetails $_}
    }
    $writerRollbackFailure=''
    $fenceReleaseFailure=''
    $codeRestoredExact=(-not $codeRestoreNeeded)
    $rollbackRecoveryVerified=$false
    $audit.failure_type=$original.Exception.GetType().Name
    $audit.rollback.applied=$mutated
    $audit.rollback.runtime_restored=(-not $mutated)
    $audit.rollback.steps=[ordered]@{}
    # Recording is best effort: unavailable audit storage must not skip recovery.
    function Record-CanonicalRollbackStep {
        param([string]$Step, [string]$Status, [string]$FailureType)
        $audit.rollback.steps[$Step]=[ordered]@{status=$Status;failure_type=$FailureType}
        Save-CanonicalRecoveryDiagnostics ('rollback.'+$Step)
    }
    if($canonicalInstallationCommitPoint -ceq 'UNKNOWN'){
        $codeRestoredExact=$false
        $codeRollbackFailure='COMMIT_POINT_UNKNOWN'
        Record-CanonicalRollbackStep 'commit_point_readback' 'UNPROVEN_FENCE_RETAINED' $codeRollbackFailure
    }elseif($canonicalInstallationCommitPoint -ceq 'NOT_REACHED' -and $currentAbsentBeforePlacement -and
        $placement -ceq 'PASS_NEW_VERIFIED' -and (Test-Path -LiteralPath $install)){
        # The privileged compensation must prove absence before this can be an
        # exact restoration of the absent code preimage.
        $codeRestoredExact=$false
        $codeRollbackFailure='ROLLBACK_NEW_CODE_REMOVAL_UNPROVEN'
        Record-CanonicalRollbackStep 'code_restore' 'UNPROVEN_FENCE_RETAINED' $codeRollbackFailure
    }
    try {
    if ($codeRestoreNeeded) {
        try {
            $generationRestoreReceipt = Read-BootstrapReplacementReceipt -Path $replacementReceiptPath `
                -ExpectedSha256 $replacementReceiptSha256
            Assert-ContainerDataGenerationTarget -CandidateRoot ([string]$generationRestoreReceipt.rollback_root) `
                -TargetSid $operatorSid -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source
            Set-InstallationEvidenceStage 'rollback.code_replacement' 'rollback'
            Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256
            if($supportedPlacement){Product $source '--remove-current-user-setup' (Join-Path $install 'app') -Rollback}else{Product $install '--remove-current-user-setup' -Rollback}
            if ((Snapshot).exists -or @(Relays).Count -ne 0) {
                throw 'Replacement rollback runtime quiescence failed.'
            }
            Record-CanonicalRollbackStep 'code_quiescence' 'PASS' ''
        }
        catch {
            Write-InstallationCaughtFailure $_
            $codeRollbackFailure=$_.Exception.GetType().Name
            $audit.code_replacement.restore_failure_type=$codeRollbackFailure
            Record-CanonicalRollbackStep 'code_quiescence' 'FAILED' $codeRollbackFailure
        }
        # A failed removal call does not prove that the runtime is still live.
        # Recheck G and actual quiescence before the independent restore attempt.
        try {
            $generationRestoreReceipt = Read-BootstrapReplacementReceipt -Path $replacementReceiptPath `
                -ExpectedSha256 $replacementReceiptSha256
            Assert-ContainerDataGenerationTarget -CandidateRoot ([string]$generationRestoreReceipt.rollback_root) `
                -TargetSid $operatorSid -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source
            if ((Snapshot).exists -or @(Relays).Count -ne 0) {
                throw 'Replacement rollback runtime quiescence failed.'
            }
            $restoreBootstrap = @(
                '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',(Join-Path $(if($supportedPlacement){$source}else{$install}) 'INSTALL_THIS_PC.ps1'),
                '-InstallRoot',$install,
                '-OperatorLocalAppDataRoot',$lad,
                '-OperatorSid',$operatorSid,
                '-OperatorDataRoot',$activeDataRoot,
                '-ElevationLogPath',$elevationLogPath,
                '-WriterFencePreparedReceiptPath',([string]$canonicalWriterFencePreparedReceipt.path),
                '-WriterFencePreparedReceiptSha256',([string]$canonicalWriterFencePreparedReceipt.sha256),
                '-RestoreVerifiedReplacement',
                '-ReplacementTransactionId',$replacementTransactionId,
                '-ReplacementReceiptPath',$replacementReceiptPath,
                '-ReplacementReceiptSha256',$replacementReceiptSha256,
                '-RestoreEvidencePath',$replacementRestoreEvidencePath,
                '-WriterFenceHelperPath',(Join-Path $(if($supportedPlacement){$source}else{$install}) 'tools\container_writer_fence.ps1'),
                '-ExpectedWriterFenceHelperSha256',([string]$sourceManifest.writer_fence_helper_sha256),
                '-WriterFenceSessionId',$Script:CanonicalWriterFenceSessionId,
                '-WriterFenceAttemptId',$Script:CanonicalWriterFenceAttemptId,
                '-WriterFenceReplacementTransactionId',$Script:CanonicalWriterFenceTransactionId,
                '-WriterFenceDelegationToken',$Script:CanonicalWriterFenceDelegationToken
            )
            if ($testMode) { $restoreBootstrap += '-AllowNoncanonicalLayoutForTest' }
            $capturedChild=Invoke-InstallationEvidenceChild 'rollback-code-restore' $winps $restoreBootstrap
            $restoreOutput=@($capturedChild.Stdout)
            $restoreExitCode=$capturedChild.ExitCode
            if ($restoreExitCode -ne 0) { throw (ConvertTo-KmtechRedactedSinkText -Text ([string]("Code restore failed: $restoreExitCode")) -UserLine) }
            if (-not $testMode) {
                $restoreBinding=Read-InstallationHelperEvidenceBinding @($capturedChild.Stdout -split "`r?`n") $elevationLogPath $capturedChild.ProcessId $sourceHelperSha256
                $replacementRestoreEvidencePath=Read-CanonicalHelperArtifact $restoreBinding 'restore-evidence.json' 'RESTORE_EVIDENCE_READY'
            }
            $currentTreeInventorySha256 = $installedInventorySha256
            $restoreEvidence = ReadReplacementRestoreEvidence `
                -Path $replacementRestoreEvidencePath `
                -ExpectedTransactionId $replacementTransactionId `
                -ExpectedReceiptPath $replacementReceiptPath `
                -ExpectedReceiptSha256 $replacementReceiptSha256 `
                -ExpectedInstallRoot $install
            $audit.code_replacement.status='RESTORED_LATER_PHASE_FAILURE'
            $audit.code_replacement.restore_evidence_path=$replacementRestoreEvidencePath
            $audit.code_replacement.restore_evidence_sha256=Sha $replacementRestoreEvidencePath
            $audit.code_replacement.later_restore_surface='CONSUMED'
            $audit.rollback.code_exact=$true
            $codeRestoreNeeded=$false
            $codeRestoredExact=$true
            Record-CanonicalRollbackStep 'code_restore' 'PASS' ''
        }
        catch {
    Write-InstallationCaughtFailure $_

            $codeRollbackFailure=$_.Exception.GetType().Name
            $audit.status='CODE_ROLLBACK_FAILED'
            $audit.code_replacement.status='ROLLBACK_FAILED_CONTAINED_OR_STOPPED'
            $audit.code_replacement.restore_failure_type=$codeRollbackFailure
            Record-CanonicalRollbackStep 'code_restore' 'FAILED' $codeRollbackFailure
        }
    }
    if ($mutated) {
        # Removal, persistence, and the scheduled writer are independent recovery
        # attempts. A refused code restore must not suppress the latter stages.
        try {
            Sync-CanonicalWriterFenceInventory $currentTreeInventorySha256
            if (Test-Path -LiteralPath $install) { Product $install '--remove-current-user-setup' -Rollback }
            [void](Assert-RollbackRelayPreimage -ExpectedRelays @())
            Record-CanonicalRollbackStep 'runtime_quiescence' 'PASS' ''
        }
        catch {
            Write-InstallationCaughtFailure $_
            $autostartRollbackFailure=$_.Exception.GetType().Name
            Record-CanonicalRollbackStep 'runtime_quiescence' 'FAILED' $autostartRollbackFailure
        }
        try {
            Restore $before
            Record-CanonicalRollbackStep 'run_restore_attempt' 'PASS' ''
        }
        catch {
            Write-InstallationCaughtFailure $_
            $autostartRollbackFailure=$_.Exception.GetType().Name
            Record-CanonicalRollbackStep 'run_restore_attempt' 'FAILED' $autostartRollbackFailure
        }
        try {
            Assert-CanonicalRollbackStopCleanup
            if (Test-Path -LiteralPath $stop) { Remove-Item -LiteralPath $stop -Force }
            Record-CanonicalRollbackStep 'stop_marker_restore' 'PASS' ''
        }
        catch {
            Write-InstallationCaughtFailure $_
            $autostartRollbackFailure=$_.Exception.GetType().Name
            Record-CanonicalRollbackStep 'stop_marker_restore' 'FAILED' $autostartRollbackFailure
        }
        try {
            $check=Snapshot
            if ([bool]$check.exists -ne [bool]$before.exists -or
                [string]$check.kind -cne [string]$before.kind -or
                [string]$check.data -cne [string]$before.data -or
                (Test-Path -LiteralPath $stop)) { throw 'registry/stop restore readback failed' }
            Record-CanonicalRollbackStep 'run_restore' 'PASS' ''
        }
        catch {
            Write-InstallationCaughtFailure $_
            $autostartRollbackFailure=$_.Exception.GetType().Name
            Record-CanonicalRollbackStep 'run_restore' 'FAILED' $autostartRollbackFailure
        }
    }
    if($legacyRelayRestoreNeeded){
        try{
            $legacyRelayRestoreAttempted=$true
            Set-InstallationEvidenceStage 'rollback.official_legacy_relay_preimage' 'rollback'
            $legacyRestored=Restore-CanonicalOfficialLegacyRelay $legacyRelayPreimage
            $legacyRelayRestoreNeeded=$false
            $audit.scheduled_writer.official_legacy.status=$legacyRestored.status
            $audit.rollback['official_legacy_relay_restored']=$true
        }catch{Write-InstallationCaughtFailure $_;$autostartRollbackFailure='OFFICIAL_LEGACY_RELAY_RESTORE_FAILED';$audit.rollback['official_legacy_relay_restored']=$false;$audit.scheduled_writer.official_legacy.status='FAILED_RESTORE';Save-CanonicalRecoveryDiagnostics 'rollback.official_legacy'}
    }
    # G is rechecked against the surviving code, independently of removal or
    # restore failures. An unproven/denied reader never reopens writers.
    $rollbackGenerationVerified=$false
    try {
        if (-not $codeRestoredExact) { throw 'ROLLBACK_CODE_IDENTITY_UNPROVEN' }
        $rollbackCurrentAbsent = $currentAbsentBeforePlacement -and -not $RestoreVerifiedReplacement -and
            -not $codeRestoreNeeded -and -not $before.exists -and $old.Count -eq 0 -and
            -not (Test-Path -LiteralPath $install -ErrorAction Stop)
        if ($rollbackCurrentAbsent) {
            # The preimage and the surviving tree are both absent. No current
            # product can read data, and no current manifest/reader exists.
            $rollbackGenerationVerified=$true
            Record-CanonicalRollbackStep 'generation_readback' 'NOT_APPLICABLE_NO_CURRENT' ''
        } else {
            Assert-ContainerDataGenerationTarget -CandidateRoot $install `
                -TargetSid $operatorSid -LocalAppDataRoot $lad -DataRoot $activeDataRoot -HelperRoot $source
            # The saved relay's first reader includes credential locator/nested
            # owners. Preserve its readonly admission for every surviving tree.
            # A freshly placed current has an authenticated installation record;
            # the transport stock has none. Its ordinary G reader cannot prove
            # runtime identity. Use this exact installed reader for fresh rollback.
            $rollbackReaderRoot=if($currentAbsentBeforePlacement -and -not $RestoreVerifiedReplacement -and
                -not $codeRestoreNeeded -and $placement -ceq 'PASS_NEW_VERIFIED'){$install}else{$source}
            $rollbackTargetBinding=Get-CanonicalOnboardingInputBinding $rollbackReaderRoot $install
            if ($RestoreVerifiedReplacement) {
                Assert-CanonicalRestoreCodeBinding $rollbackTargetBinding (Read-CanonicalReplacementRestore)
            }
            $rollbackGenerationVerified=$true
            Record-CanonicalRollbackStep 'generation_readback' 'PASS' ''
        }
    }
    catch {
        Write-InstallationCaughtFailure $_
        $autostartRollbackFailure=$_.Exception.GetType().Name
        Record-CanonicalRollbackStep 'generation_readback' 'FAILED' $autostartRollbackFailure
    }
    # Validate the remaining runtime against the saved relay identities before
    # reopening writers. This gate never treats a failed code proof as success.
    try {
        $remainingRelays=@(Relays)
        if ($remainingRelays.Count -gt 0) {
            [void](Assert-RollbackRelayPreimage -ExpectedRelays $old)
        }
        $runRestored=(-not $mutated -or ([string]$audit.rollback.steps.run_restore_attempt.status -ceq 'PASS' -and
            [string]$audit.rollback.steps.run_restore.status -ceq 'PASS'))
        # A failed earlier quiescence remains in the audit. Final exact code,
        # G, Run and live-process proofs determine whether restoration succeeded.
        $rollbackRuntimeIdentityVerified=($codeRestoredExact -and $rollbackGenerationVerified -and $runRestored -and
            -not $legacyRelayRestoreNeeded)
        $rollbackScheduledWriterVerified=(-not $writerRestoreNeeded)
        $rollbackRecoveryVerified=($rollbackRuntimeIdentityVerified -and $rollbackScheduledWriterVerified)
        Record-CanonicalRollbackStep 'recovery_identity' $(if ($rollbackRecoveryVerified) { 'PASS' } else { 'UNPROVEN' }) ''
    }
    catch {
        Write-InstallationCaughtFailure $_
        $autostartRollbackFailure=$_.Exception.GetType().Name
        Record-CanonicalRollbackStep 'recovery_identity' 'FAILED' $autostartRollbackFailure
    }
    if ($writerRestoreNeeded) {
        try {
            $writerEnabled=Enable-CanonicalWriter $install $writerBefore
            Assert-CanonicalWriterRestoreReadback $writerBefore $writerEnabled.readback
            $audit.scheduled_writer.restore_readback=$writerEnabled
            $audit.status='ROLLBACK_WRITER_ENABLED_AWAITING_NATURAL_TRIGGER'
            Record-CanonicalRollbackStep 'scheduled_writer_enable' 'PASS' ''
            $rollbackScheduledWriterVerified=$true
            $rollbackRecoveryVerified=($rollbackRuntimeIdentityVerified -and $rollbackScheduledWriterVerified)
            Record-CanonicalRollbackStep 'recovery_identity' $(if ($rollbackRecoveryVerified) { 'PASS' } else { 'UNPROVEN' }) ''
            if (-not $rollbackRecoveryVerified) { throw 'ROLLBACK_RECOVERY_IDENTITY_UNPROVEN_FENCE_RETAINED' }
            $releaseAuthorization=New-CanonicalWriterFenceReleaseAuthorization `
                -Path $rollbackNaturalTriggerAuthorizationPath `
                -Phase 'ROLLBACK_NATURAL_TRIGGER' -AuditPath $auditPath -EnabledBaseline $writerEnabled
            $canonicalWriterFenceLastReleaseAuthorizationPath=[string]$releaseAuthorization.path
            $canonicalWriterFenceLastReleaseAuthorizationSha256=[string]$releaseAuthorization.sha256
            Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
            Clear-CanonicalWriterFenceReleaseDelegation
            Stop-CanonicalWriterFenceRelease $releaseAuthorization
            $canonicalWriterFenceActive=$false
            Record-CanonicalRollbackStep 'fence_release' 'PASS' ''
            $writerRunning=Confirm-CanonicalWriterRunning $install $writerEnabled
            $audit.scheduled_writer.natural_trigger_proof=$writerRunning
            $audit.rollback.scheduled_writer_restored=$true
            $writerRestoreNeeded=$false
            Record-CanonicalRollbackStep 'scheduled_writer_restore' 'PASS' ''
        }
        catch {
            Write-InstallationCaughtFailure $_
            $writerRollbackFailure=$_.Exception.GetType().Name
            $rollbackScheduledWriterVerified=$false
            $rollbackRecoveryVerified=$false
            $audit.scheduled_writer.restore_failure_code='CANONICAL_WRITER_RESTORE_FAILED'
            Record-CanonicalRollbackStep 'scheduled_writer_restore' 'FAILED' $writerRollbackFailure
            Record-CanonicalRollbackStep 'recovery_identity' 'FAILED' $writerRollbackFailure
            if (-not $canonicalWriterFenceActive) {
                try {
                    [void](Start-ContainerWriterFence -Status 'RESTORE_FAILED' -OwnerKind 'canonical_installer' `
                        -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
                        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                        -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
                        -WriterContractSha256 $canonicalWriterFenceContractSha256 `
                        -PreparedReceiptPath $canonicalWriterFenceLastReleaseAuthorizationPath `
                        -PreparedReceiptSha256 $canonicalWriterFenceLastReleaseAuthorizationSha256 `
                        -DelegationToken $Script:CanonicalWriterFenceDelegationToken -DelegatedSources $canonicalWriterFenceDelegatedSources `
                        -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) -AuthorityLease $canonicalWriterFenceAuthority)
                    $canonicalWriterFenceActive=$true
                    Record-CanonicalRollbackStep 'writer_failure_refence' 'PASS' ''
                } catch {
            Write-InstallationCaughtFailure $_
 Record-CanonicalRollbackStep 'writer_failure_refence' 'FAILED' $_.Exception.GetType().Name }
            }
        }
    }
    }
    finally {
        # Only proven code/G/Run/task recovery may reopen writers. Independent
        # recovery attempts preserve every failure while an unproven task stays fenced.
        try {
            if ($canonicalWriterFenceActive -and $rollbackRecoveryVerified) {
                $audit.status='ROLLBACK_AWAITING_FENCE_RELEASE'
                Record-CanonicalRollbackStep 'fence_release' 'ATTEMPTING' ''
                try {
                    $releaseAuthorization=New-CanonicalWriterFenceReleaseAuthorization `
                        -Path $rollbackCompleteAuthorizationPath -Phase 'ROLLBACK_COMPLETE' -AuditPath $auditPath
                    $canonicalWriterFenceLastReleaseAuthorizationPath=[string]$releaseAuthorization.path
                    $canonicalWriterFenceLastReleaseAuthorizationSha256=[string]$releaseAuthorization.sha256
                    Set-CanonicalWriterFenceReleaseAuthorization $releaseAuthorization
                    Clear-CanonicalWriterFenceReleaseDelegation
                    Stop-CanonicalWriterFenceRelease $releaseAuthorization
                    $canonicalWriterFenceActive=$false
                    Record-CanonicalRollbackStep 'fence_release' 'PASS' ''
                }
                catch {
                    Write-InstallationCaughtFailure $_
                    $fenceReleaseFailure=$_.Exception.GetType().Name
                    Record-CanonicalRollbackStep 'fence_release' 'FAILED' $fenceReleaseFailure
                    # Existing abort verifies session authority and the exact
                    # tuple; no unbound or foreign fence can be removed here.
                    try {
                        [void](Abort-ContainerWriterFence `
                            -SessionId $Script:CanonicalWriterFenceSessionId `
                            -AttemptId $Script:CanonicalWriterFenceAttemptId `
                            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
                            -AuthorityLease $canonicalWriterFenceAuthority)
                        $canonicalWriterFenceActive=$false
                        Record-CanonicalRollbackStep 'fence_abort' 'PASS' ''
                    }
                    catch {
            Write-InstallationCaughtFailure $_
 Record-CanonicalRollbackStep 'fence_abort' 'FAILED' $_.Exception.GetType().Name }
                }
            }
        }
        finally {
            if ($mutated -and $rollbackRecoveryVerified -and -not $canonicalWriterFenceActive) {
                $relayRollbackFailed=$false
                $relayAttempt=0
                foreach ($item in $old) {
                    $relayAttempt++
                    $relayStep="relay_restart_$relayAttempt"
                    try {
                        $remaining=@(Relays)
                        $matching=@($remaining | Where-Object {
                            (Same ([string]$_.ExecutablePath) ([string]$item.ExecutablePath)) -and
                            [string]$_.CommandLine -ceq [string]$item.CommandLine
                        })
                        if ($matching.Count -gt 1) { throw 'rollback relay duplicate preimage' }
                        if ($matching.Count -eq 0) {
                            if ($RestoreVerifiedReplacement) {
                                $relayRestore=Read-CanonicalReplacementRestore
                                $relayBinding=Get-CanonicalOnboardingInputBinding $source $install
                                Assert-CanonicalRestoreCodeBinding $relayBinding $relayRestore
                            }
                            $newPid=Start-CanonicalRelayAfterFenceRelease -Root $install -RunCommand ([string]$before.data)
                            $p=Get-CimInstance Win32_Process -Filter "ProcessId = $newPid" -ErrorAction SilentlyContinue
                            if ($null -eq $p -or -not (Same ([string]$p.ExecutablePath) ([string]$item.ExecutablePath))) {
                                throw 'runtime restore failed'
                            }
                        }
                        Record-CanonicalRollbackStep $relayStep 'PASS' ''
                    }
                    catch {
                        Write-InstallationCaughtFailure $_
                        $relayRollbackFailed=$true
                        $autostartRollbackFailure=$_.Exception.GetType().Name
                        Record-CanonicalRollbackStep $relayStep 'FAILED' $autostartRollbackFailure
                    }
                }
                try { [void](Assert-RollbackRelayPreimage -ExpectedRelays $old) }
                catch {
                    Write-InstallationCaughtFailure $_
                    $relayRollbackFailed=$true
                    $autostartRollbackFailure=$_.Exception.GetType().Name
                }
                Record-CanonicalRollbackStep 'relay_restart' $(if ($relayRollbackFailed) { 'FAILED' } else { 'PASS' }) $autostartRollbackFailure
                $audit.rollback.runtime_restored=(-not $relayRollbackFailed -and $rollbackRecoveryVerified)
            }
            elseif ($canonicalWriterFenceActive) {
                Record-CanonicalRollbackStep 'fence_release' 'UNPROVEN_FENCE_RETAINED' ''
                Record-CanonicalRollbackStep 'relay_restart' 'UNPROVEN_FENCE_RETAINED' ''
                $audit.rollback.operator_message='이 PC의 코드, 자료 호환 여부 또는 실행 상태를 확인하지 못해 작업을 안전하게 멈췄습니다. 자료와 설치 기록을 보존하고 관리자 지원 복구를 요청하세요. 확인 없이 중지 표시를 지우거나 앱을 다시 실행하지 마세요.'
                $audit.rollback.support_recovery_procedure='docs/spec/operations.md#canonical-rollback-support-recovery'
                Write-Warning (ConvertTo-KmtechRedactedSinkText -Text ([string]($audit.rollback.operator_message)) -UserLine)
                Record-CanonicalRollbackStep 'support_recovery' 'REQUIRED_FENCE_RETAINED' ''
            }
        }
    }
    # Keep the earlier failure code and every failed stage after later attempts.
    if (-not [string]::IsNullOrWhiteSpace($codeRollbackFailure)) {
        $audit.status='CODE_ROLLBACK_FAILED'
        Record-CanonicalRollbackStep 'completion' 'FAILED' $codeRollbackFailure
        throw [InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text "CODE_ROLLBACK_FAILED: $codeRollbackFailure" -UserLine),$original.Exception)
    }
    if (-not [string]::IsNullOrWhiteSpace($writerRollbackFailure)) {
        $audit.status='CANONICAL_WRITER_RESTORE_FAILED'
        Record-CanonicalRollbackStep 'completion' 'FAILED' $writerRollbackFailure
        throw [InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text "CANONICAL_WRITER_RESTORE_FAILED: $writerRollbackFailure" -UserLine),$original.Exception)
    }
    if (-not [string]::IsNullOrWhiteSpace($autostartRollbackFailure)) {
        $audit.status='AUTOSTART_ROLLBACK_FAILED'
        Record-CanonicalRollbackStep 'completion' 'FAILED' $autostartRollbackFailure
        throw [InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text "AUTOSTART_ROLLBACK_FAILED: $autostartRollbackFailure" -UserLine),$original.Exception)
    }
    if (-not [string]::IsNullOrWhiteSpace($fenceReleaseFailure)) {
        $audit.status='CANONICAL_WRITER_FENCE_RELEASE_FAILED'
        Record-CanonicalRollbackStep 'completion' 'FAILED' $fenceReleaseFailure
        throw [InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text "CANONICAL_WRITER_FENCE_RELEASE_FAILED: $fenceReleaseFailure" -UserLine),$original.Exception)
    }
    if($codeRestoredExact){$audit['worker_shortcuts']=Restore-BootstrapWorkerShortcuts $install $workerShortcutRecordPath 'User'}
    $audit.status=Get-CanonicalRollbackSuccessStatus -Restore ([bool]$RestoreVerifiedReplacement) -CommitPoint $canonicalInstallationCommitPoint
    Record-CanonicalRollbackStep 'completion' 'PASS' ''
    if ($Script:CanonicalRollbackContinuationCreated -and [bool]$audit.rollback.code_exact -and [bool]$audit.rollback.runtime_restored) {
        if($old.Count -gt 0){$audit.exact_launch=$Script:CanonicalRelayProof;Save-CanonicalRecoveryDiagnostics 'rollback.continuation_completion'}
        try {Complete-CanonicalRollbackContinuation $Script:CanonicalRollbackContinuationCreated}
        catch {Write-InstallationCaughtFailure $_;$audit.rollback['continuation_completion_failure']=Get-CanonicalFailureDetails $_ 'ROLLBACK_COMPLETION';Save-CanonicalRecoveryDiagnostics 'rollback.continuation_completion'}
    }
    if ($placement -ceq 'PASS_NEW_VERIFIED') {
        Write-CanonicalInstallationPublicRecord
    }
    $publicFailure=[InvalidOperationException]::new((ConvertTo-KmtechRedactedSinkText -Text $original.Exception.Message -UserLine),$original.Exception);$publicFailure.Data['original_type']=$original.Exception.GetType().FullName;$publicRecord=[Management.Automation.ErrorRecord]::new($publicFailure,'CanonicalInstallationFailed',[Management.Automation.ErrorCategory]::InvalidOperation,$null);throw $publicRecord
}
finally {
    # Even an early code/runtime rollback throw reaches this independent attempt.
    if($legacyRelayRestoreNeeded -and -not $legacyRelayRestoreAttempted -and $null -ne $original){
        $legacyRelayRestoreAttempted=$true
        try{
            [void](Restore-CanonicalOfficialLegacyRelay $legacyRelayPreimage)
            $legacyRelayRestoreNeeded=$false
            $audit.rollback['official_legacy_relay_restored']=$true
            $audit.scheduled_writer.official_legacy.status='PROVEN_PREIMAGE_RESTORED_FINALLY'
        }catch{Write-InstallationCaughtFailure $_;$audit.rollback['official_legacy_relay_restored']=$false;$audit.scheduled_writer.official_legacy.status='FAILED_RESTORE_FINALLY'}
        try{Save $auditPath $audit}catch{Write-InstallationCaughtFailure $_}
    }

}

} catch {
    $outputFailure=$_
    if ($null -ne $machineWorker) { Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED'; exit 4 }
    if (-not $enteredPlacementTry -and -not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval) {
        if (-not $Script:CanonicalPreparationAdmissionFailed) {
            Write-CanonicalPreparationAdmissionFailure ([string](Get-Variable auditPath -ValueOnly -ErrorAction SilentlyContinue)) `
                ([string](Get-Variable evidenceFull -ValueOnly -ErrorAction SilentlyContinue)) `
                ([string](Get-Variable source -ValueOnly -ErrorAction SilentlyContinue)) $Script:CanonicalInstallerSourceInventorySha256 $outputFailure
        }
        $publicMessage='FAILED_PREPARATION_ADMISSION'
    } else {
        $publicMessage=ConvertTo-KmtechRedactedSinkText -Text $outputFailure.Exception.Message -UserLine
    }
    if(Get-Command Write-InstallationCaughtFailure -ErrorAction SilentlyContinue){Write-InstallationCaughtFailure $outputFailure}
    Write-CanonicalInstallationPublicRecord -Failure $outputFailure -ExitCode 1
    exit 1
} finally {
    try {
    # Record the outer failure and caller-selected audit diagnostics before the
    # single journal seal. Keep the deployment authority through audit publication.
    if(Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue){
    $finalAudit=$null
    if($null -ne $audit){
        $finalAudit=(ConvertTo-CanonicalAuditJson $audit)|ConvertFrom-Json
    }
    Complete-InstallationEvidenceStage 'forward'
    $evidenceRollbackFailure=$null
    $finalOriginal=Get-Variable -Name original -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $finalOriginal -and ($null -eq $audit -or -not $audit.rollback.runtime_restored)){$evidenceRollbackFailure=$finalOriginal}
    Complete-InstallationEvidenceStage 'rollback' $evidenceRollbackFailure
    $finalEvidence=Complete-InstallationEvidence
    if($null -ne $finalAudit){
        $finalAudit|Add-Member -NotePropertyName installation_evidence -NotePropertyValue $finalEvidence -Force
        # These diagnostic leaves already have their protected journal records.
        # Saving their public forms cannot append another event after the seal.
        try {
            if (-not $retirementAuditSealed) { Save $auditPath $finalAudit $true }
        }catch{Write-Warning (ConvertTo-KmtechRedactedSinkText -Text ([string]('INSTALLATION_EVIDENCE_FINAL_AUDIT_SAVE_FAILED')) -UserLine)}
        if($evidenceFull){
            try {Save $evidenceFull $finalAudit $true}
            catch{Write-Warning (ConvertTo-KmtechRedactedSinkText -Text ([string]('INSTALLATION_EVIDENCE_FINAL_EVIDENCE_SAVE_FAILED')) -UserLine)}
        }
    }
    Write-Output (ConvertTo-KmtechRedactedSinkText -Text ([string](('installation_evidence_status='+[string]$finalEvidence.status))))
    }
    } finally {
    $finalTransactionJob=Get-Variable -Name canonicalTransactionJob -ValueOnly -ErrorAction SilentlyContinue
    $finalCloseFailure=$null
    if($null -ne $finalTransactionJob){
        try{Close-InstallationTransaction $finalTransactionJob}
        catch{$finalCloseFailure=$_}
    }
    $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = ''
    $finalEnvironmentNames=Get-Variable -Name canonicalWriterFenceEnvironmentNames -ValueOnly -ErrorAction SilentlyContinue
    foreach ($name in $finalEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $canonicalWriterFenceEnvironmentBefore[$name], 'Process')
    }
    $finalAuthority=Get-Variable -Name canonicalWriterFenceAuthority -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $finalAuthority) {
        Exit-ContainerWriterSessionAuthority $finalAuthority
    }
    Exit-RetirementResumeClaim (Get-Variable -Name retirementResumeClaim -ValueOnly -ErrorAction SilentlyContinue)
    $finalContinuationClaim=Get-Variable -Name continuationOldClaim -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $finalContinuationClaim) {Exit-CanonicalRollbackContinuationClaim $finalContinuationClaim}
    if($null -ne $finalCloseFailure){Write-CanonicalInstallationPublicRecord -Failure $finalCloseFailure -ExitCode 1;exit 1}
    $finalOutputFailure=Get-Variable -Name outputFailure -ValueOnly -ErrorAction SilentlyContinue
    if($null -eq $machineWorker -and $null -eq $finalOutputFailure -and (Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){
        Write-CanonicalInstallationPublicRecord
    }
    }
}
