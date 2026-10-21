# Native-free boundary reproduction: actual producer statements and fence/readers.
$ErrorActionPreference='Stop'
$base=$env:CA_CONTRACT_ROOT
trap{
    $site=@{exception_type=$_.Exception.GetType().FullName;script_line=$_.InvocationInfo.ScriptLineNumber;
        script_file=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName)}
    [IO.File]::WriteAllText((Join-Path $base 'native-failure.json'),($site|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    exit 71
}
$repo=Split-Path -Parent $env:CA_CONTRACT_SOURCE
$lad=Join-Path $base 'profile'
$env:LOCALAPPDATA=$lad
$env:PROGRAMDATA=Join-Path $base 'program-data'
. (Join-Path $repo 'tools/container_writer_fence.ps1')
function Save([string]$Path,$Value,[bool]$SanitizeDiagnostics=$false){
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 40)+[char]10,[Text.UTF8Encoding]::new($false))
}
function Write-Utf8Json([string]$Path,$Value){Save $Path $Value}
function Sha([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
function Full([string]$Path,[string]$Label){[IO.Path]::GetFullPath($Path)}
function Same([string]$Left,[string]$Right){[IO.Path]::GetFullPath($Left).Equals([IO.Path]::GetFullPath($Right),[StringComparison]::OrdinalIgnoreCase)}
function Get-FileSha256([string]$Path){Sha $Path}
function Get-ContainerWriterFenceProfileLocalAppDataRoot($Sid){$lad}
function Assert-BootstrapNoReparsePoint{param($Path,$Label,[switch]$PathOnly)}
function Assert-InstallationEvidenceProtectedPath{param($Path)}
function Get-InstallationEvidenceControlRoot{Join-Path $base 'protected'}
function Write-InstallationCaughtFailure{param($Record)}
function Get-InstallationFailureDetails{param($Record);@{code='FIXTURE_INTERRUPTED';
    script_file=[IO.Path]::GetFileName($Record.InvocationInfo.ScriptName);script_line=$Record.InvocationInfo.ScriptLineNumber}}
function Set-InstallationEvidenceStage{param($Stage,$Operation)}
function Write-InstallationEvidenceEvent{param($Record)}
function Get-CanonicalInstallationCommitPoint{ 'NOT_REACHED' }
function Snapshot{[pscustomobject]@{exists=$false;kind='';data=''}}
function Restore{param($Preimage)}
function Assert-CanonicalRollbackStopCleanup{}
function Assert-CanonicalTransactionRelayPreimage{param($Configuration,[switch]$AfterRestore)}
function Sync-CanonicalWriterFenceInventory{param($Expected)}
function Assert-ContainerDataGenerationTarget{param($Root,$Sid,$Local,$Data,$Helper)}
function Start-CanonicalRelayAfterFenceRelease{throw 'UNEXPECTED_RELAY'}
function Get-BootstrapWorkerShortcutCommonRecordPath{param($Root);Join-Path $base 'shortcut-preimage.json'}
function Restore-BootstrapWorkerShortcuts{param($Root,$Record,$Scope);@{status='FIXTURE_PREIMAGE_RESTORED'}}
function Test-InstallationTransactionParent{param($Configuration);$true}
$testMode=$true
$install=Join-Path $base 'current'
$source=$repo
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$activeDataRoot=Join-Path $base 'data'
$stop=Join-Path $base 'stop.json'
$before=[pscustomobject]@{exists=$false;kind='';data=''}
$old=@();$legacyRelayPreimage=$null
$writerBefore=[pscustomobject]@{restore_required=$false}
$currentAbsentBeforePlacement=$true
$sourceManifest=@{source_commit=('c'*40)}
$sourceManifestSha256='a'*64
$auditRoot=Join-Path $lad 'KMTech/ContainerAudit/install-audit'
$kind=$env:CA_GENERAL_BOUNDARY
if($env:CA_GENERAL_STAGE -ceq 'setup'){
$runId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceSessionId=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceAttemptId=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceTransactionId=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceDelegationToken=[Guid]::NewGuid().ToString('N')
$canonicalWriterFenceStartedAtUtc=[DateTime]::UtcNow.ToString('o')
$canonicalWriterFenceOrchestratorSha256=Sha $env:CA_CONTRACT_SOURCE
$canonicalWriterFenceContractSha256=Sha (Join-Path $repo 'tools/container_writer_session_contract.json')
$canonicalWriterFenceDelegatedSources=@((Get-Content -LiteralPath (Join-Path $repo 'tools/container_writer_sink_inventory.json') -Raw|ConvertFrom-Json).writer_sink_sources)
$preparedPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'-writer-prepared.json')
$prepared=[ordered]@{schema='container-audit-canonical-writer-prepared-v1';status='PREPARED';app_id='container_audit';
    session_id=$Script:CanonicalWriterFenceSessionId;attempt_id=$Script:CanonicalWriterFenceAttemptId;
    replacement_transaction_id=$Script:CanonicalWriterFenceTransactionId;session_started_at_utc=$canonicalWriterFenceStartedAtUtc;
    orchestrator_sha256=$canonicalWriterFenceOrchestratorSha256;writer_contract_sha256=$canonicalWriterFenceContractSha256;
    writer_inventory_sha256=$Script:ContainerWriterFenceInventorySha256;source_manifest_sha256=$sourceManifestSha256;
    operator_sid=$operatorSid;operator_local_appdata_root=$lad;secret_values_recorded=$false}
Save $preparedPath $prepared
$canonicalWriterFencePreparedReceipt=@{path=$preparedPath;sha256=Sha $preparedPath}
$canonicalTransactionJob=$null
$initial=if($kind -like 'B_RESTORING*'){'RESTORING'}else{'INSTALLING'}
$lease=Enter-ContainerWriterSessionAuthority -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
    -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId `
    -WriterContractSha256 $canonicalWriterFenceContractSha256
$canonicalWriterFenceAuthority=$lease
try{
    if($initial -cne 'RESTORING'){
    [void](Start-ContainerWriterFence -Status $initial -OwnerKind 'canonical_installer' `
        -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc `
        -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 -WriterContractSha256 $canonicalWriterFenceContractSha256 `
        -PreparedReceiptPath $preparedPath -PreparedReceiptSha256 (Sha $preparedPath) -AuthorityLease $lease)
    }
    $auditPath=if($kind -like 'A_*'){Join-Path $auditRoot ('canonical-portable-'+$runId+'.json')}else{Join-Path $base 'protected/run-owned/transaction-rollback-audit.json'}
    Save (Join-Path $base 'boundary-context.json') @{audit_path=$auditPath;prepared_path=$preparedPath;
        owner_process_id=$PID;owner_started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')}
    $originalSet=(Get-Command Set-CanonicalWriterFenceReleaseAuthorization).Definition
    function Set-CanonicalWriterFenceReleaseAuthorization($Authorization){
        if($kind -like '*_BEFORE_SET'){exit 73}
        & ([scriptblock]::Create($originalSet)) $Authorization
        exit 73
    }
    if($kind -like 'A_*'){
        $auditPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'.json')
        $audit=[ordered]@{schema='container-audit-canonical-portable-install-v2';operation='RESTORE_VERIFIED_REPLACEMENT';run_id=$runId;
            install_root=$install;source_manifest_sha256=$sourceManifestSha256;preimage=$before;code_placement='RESTORED_VERIFIED';
            code_replacement=@{transaction_id=$Script:CanonicalWriterFenceTransactionId;later_restore_surface='CONSUMED'}}
        $check=Snapshot
        $productCompleteAuthorizationPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'-product-complete-release.json')
        # Execute the unchanged producer tail; interruption is immediately at Set.
        $text=[IO.File]::ReadAllText($env:CA_CONTRACT_SOURCE)
        $start=$text.IndexOf('        $audit.after = $check'+[char]10+'        $audit.status = ''RESTORE_AWAITING_FENCE_RELEASE''')
        if($start -lt 0){throw 'ACTUAL_RESTORE_TAIL_MISSING'}
        $end=$text.IndexOf('        Clear-CanonicalWriterFenceReleaseDelegation',$start)
        try{. ([scriptblock]::Create($text.Substring($start,$end-$start)))}catch{if($_.Exception.Message -cne 'BOUNDARY_STOP'){throw}}
    }else{
        $protectedRoot=Join-Path $base 'protected/run-owned'
        [void][IO.Directory]::CreateDirectory($protectedRoot)
        $configuration=[pscustomobject]@{context=[pscustomobject]@{};protected_root=$protectedRoot;transaction_id=$Script:CanonicalWriterFenceTransactionId}
        # Real compensator verifies every step before saving its waiting audit.
        Invoke-CanonicalTransactionCompensation $configuration $null $lease | Out-Null
        $auditPath=Join-Path $protectedRoot 'transaction-rollback-audit.json'
    }
}finally{Exit-ContainerWriterSessionAuthority $lease}
throw 'PRODUCER_DID_NOT_REACH_BOUNDARY'
}
$context=Get-Content -LiteralPath (Join-Path $base 'boundary-context.json') -Raw|ConvertFrom-Json
$auditPath=[string]$context.audit_path
$preparedPath=[string]$context.prepared_path
$activePath=Get-ContainerWriterFenceActivePath
$active=Read-ContainerWriterFence
$fenceBefore=Sha $activePath
$auditBefore=Sha $auditPath
$auditRaw=[IO.File]::ReadAllText($auditPath)
$saved=$auditRaw|ConvertFrom-ContainerWriterFenceJson
$expected=if($kind -like 'A_*'){'RESTORE_AWAITING_FENCE_RELEASE'}else{'ROLLBACK_AWAITING_FENCE_RELEASE'}
if([string]$saved.status -cne $expected){throw 'ACTUAL_WAITING_AUDIT_MISSING'}
if($kind -like 'B_*' -and @($saved.rollback.steps|Where-Object {$_.status -cne 'PROVEN'}).Count){throw 'COMPENSATION_NOT_PROVEN'}
$refusals=[ordered]@{}
foreach($entry in @('reinstall','explicit_restore','uninstall','machine_recovery')){
    try{
        switch($entry){
            'reinstall'{Read-InstallationAbandonedRollback $install $lad $operatorSid|Out-Null}
            # Both installer modes consume this same actual gate after receipt preflight.
            'explicit_restore'{Read-InstallationAbandonedRollback $install $lad $operatorSid|Out-Null}
            'uninstall'{Read-CanonicalSupportedRemovalResume|Out-Null}
            'machine_recovery'{Read-CanonicalMachineInstallationRecovery ([pscustomobject]@{sid=$operatorSid}) $source $install $sourceManifest $auditPath (Sha $auditPath)|Out-Null}
        }
        $refusals[$entry]=$false
    }catch{$refusals[$entry]=$true}
}
# Execute the actual coordinator authority gate with a continuation's link.
$text=[IO.File]::ReadAllText((Join-Path $repo 'tools/bootstrap_integrity.ps1'))
$start=$text.IndexOf('        if([string]$active.session_id -cne [string]$Configuration.session_id')
$end=$text.IndexOf('        $lease=Enter-ContainerWriterSessionAuthority',$start)
if($start -lt 0 -or $end -lt $start){throw 'ACTUAL_CONTINUATION_GATE_MISSING'}
$configuration=[pscustomobject]@{session_id=$active.session_id;attempt_id=$active.attempt_id;transaction_id=$active.replacement_transaction_id;
    prepared_path=$preparedPath;prepared_sha256=Sha $preparedPath}
$continuationActive=$active.PSObject.Copy()
$continuationActive.prepared_receipt_path=Join-Path $base 'authority-link.json'
$continuationActive.prepared_receipt_sha256='b'*64
$active=$continuationActive
$continuationRefused=$false
try{. ([scriptblock]::Create($text.Substring($start,$end-$start)))}catch{$continuationRefused=$_.Exception.Message -ceq 'Installation transaction active/prepared/parent binding differs.'}
Save (Join-Path $base 'general-observed.json') @{
    boundary=$kind;status=$saved.status;fence_status=(Read-ContainerWriterFence).status;refusals=$refusals;
    indented_audit=($auditRaw -match '"status"\s*:\s+"');continuation_refused=$continuationRefused;
    fence_preserved=((Sha $activePath) -ceq $fenceBefore);audit_preserved=((Sha $auditPath) -ceq $auditBefore);
    control_root=(Get-ContainerWriterFenceControlRoot);local_appdata=$lad;operator_sid=$operatorSid;fence_present=(Test-Path -LiteralPath $activePath)}
