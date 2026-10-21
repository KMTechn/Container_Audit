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
$lad=Join-Path $base 'profile/AppData/Local'
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
function Get-CanonicalInstallationCommitPoint{if($env:CA_GENERAL_PREIMAGE -ceq 'commit_reached'){'REACHED'}else{'NOT_REACHED'}}
function Snapshot{$script:GeneralRunState}
function Restore{param($Preimage);$script:GeneralRunState=$Preimage}
function Product{param($Root,$Mode,$AppRoot,[switch]$Rollback);$script:GeneralRunState=[pscustomobject]@{exists=$false;kind='';data=''}}
function Assert-CanonicalRollbackStopCleanup{}
function Assert-CanonicalTransactionRelayPreimage{param($Configuration,[switch]$AfterRestore)}
function Sync-CanonicalWriterFenceInventory{param($Expected)}
function Assert-ContainerDataGenerationTarget{param($Root,$Sid,$Local,$Data,$Helper)}
function Start-CanonicalRelayAfterFenceRelease{throw 'UNEXPECTED_RELAY'}
function Get-BootstrapWorkerShortcutCommonRecordPath{param($Root);Join-Path $base 'shortcut-preimage.json'}
function Restore-BootstrapWorkerShortcuts{param($Root,$Record,$Scope);@{status='FIXTURE_PREIMAGE_RESTORED'}}
function InstalledManifest($Root,$Unsigned){Get-Content -LiteralPath (Join-Path $Root 'portable-manifest.json') -Raw|ConvertFrom-Json}
function Assert-BootstrapIntegrityRecord($Root){[void](Assert-BootstrapRelocatedIntegrityRecord $Root $Root)}
function Get-CanonicalWriterSnapshot($Root){$script:GeneralWriterState}
function Enable-CanonicalWriter($Root,$Before){$script:GeneralWriterState=$Before;[pscustomobject]@{readback=$Before}}
function Restore-CanonicalOfficialLegacyRelay{param($Binding);@{status='PROVEN_PREIMAGE_RESTORED'}}
function Get-CanonicalOfficialLegacyRelayPreimage{[pscustomobject]@{identity=@{sha256=('d'*64)};enabled=$true}}
# Packet/signature checking is a fixture seam; the receipt, path/tree identity,
# manifest hashes, ACL identities, restore-state and canonical readers are real.
function Assert-BootstrapRelocatedIntegrityRecord{
    param($Root,$ExpectedCodeRoot)
    $manifest=Join-Path $Root 'portable-manifest.json'
    @{file_count=1;aggregate_sha256=Sha $manifest;integrity_sha256=Sha (Join-Path $Root 'bootstrap-integrity.json')}
}
function Test-InstallationTransactionParent{param($Configuration);$true}
$testMode=$true
$SkipSignatureValidationForTest=$true
$install=Join-Path $base 'current'
$source=Join-Path $base 'packet'
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$activeDataRoot=Join-Path $base 'data'
$stop=Join-Path $base 'data/direct_sync/control/container_audit_user_relay.stop.json'
$before=[pscustomobject]@{exists=$false;kind='';data=''}
if($env:CA_GENERAL_PREIMAGE -ceq 'run_present'){$before=[pscustomobject]@{exists=$true;kind='String';data='original fixture relay command'}}
$script:GeneralRunState=if($env:CA_GENERAL_STAGE -ceq 'setup' -and $env:CA_GENERAL_BOUNDARY -like 'B_*'){
    [pscustomobject]@{exists=$false;kind='';data=''}
}else{$before}
$old=@();$legacyRelayPreimage=$null
$writerBefore=[pscustomobject]@{present=$false;classification='TEST_BYPASS';restore_required=$false}
if($env:CA_GENERAL_PREIMAGE -ceq 'scheduled_writer'){$writerBefore=[pscustomobject]@{present=$true;enabled=$true;
    classification='CANONICAL_QUIESCE_RESTORE';restore_required=$true;binding_sha256=('a'*64)}}
$script:GeneralWriterState=$writerBefore
$currentAbsentBeforePlacement=$true
if($env:CA_GENERAL_STAGE -ceq 'setup'){
    [void][IO.Directory]::CreateDirectory((Join-Path $source 'tools'))
    foreach($relative in @('INSTALL_CANONICAL_PORTABLE.ps1','INSTALL_THIS_PC.ps1','tools/bootstrap_integrity.ps1',
        'tools/container_writer_sink_inventory.json','tools/container_writer_session_contract.json','tools/container_writer_fence.ps1')){
        [IO.File]::Copy((Join-Path $repo $relative),(Join-Path $source $relative))
    }
    $inventory=Get-Content -LiteralPath (Join-Path $repo 'tools/container_writer_sink_inventory.json') -Raw|ConvertFrom-Json
    $sourceManifest=@{schema='container-audit-portable-tree-v1';source_commit=('c'*40);source_tree=('d'*40);
        installer_sha256=Sha $env:CA_CONTRACT_SOURCE;writer_session_contract_sha256=Sha (Join-Path $repo 'tools/container_writer_session_contract.json');
        writer_sink_inventory_sha256=Sha (Join-Path $repo 'tools/container_writer_sink_inventory.json');writer_sink_inventory_contract_sha256=$inventory.inventory_sha256}
    Save (Join-Path $source 'portable-manifest.json') $sourceManifest
}
$sourceManifest=Get-Content -LiteralPath (Join-Path $source 'portable-manifest.json') -Raw|ConvertFrom-Json
$sourceManifestSha256=Sha (Join-Path $source 'portable-manifest.json')
$sourceHelperSha256=Sha (Join-Path $source 'INSTALL_THIS_PC.ps1')
$sourceIntegrityHelperSha256=Sha (Join-Path $source 'tools/bootstrap_integrity.ps1')
$RunName='KMTech.ContainerAudit.Relay'
$env:CONTAINER_AUDIT_DATA_ROOT=$activeDataRoot
if($env:CA_GENERAL_PREIMAGE -ceq 'different_inventory'){$Script:ContainerWriterFenceAcceptedInstalledInventorySha256='b'*64}
if($env:CA_GENERAL_STAGE -ceq 'setup'){
    [void][IO.Directory]::CreateDirectory($activeDataRoot)
    [IO.File]::WriteAllText((Join-Path $activeDataRoot 'preserve.bin'),'original data fixture')
}
$auditRoot=Join-Path $lad 'KMTech/ContainerAudit/install-audit'
$kind=$env:CA_GENERAL_BOUNDARY
if($env:CA_GENERAL_PREIMAGE -ceq 'legacy_writer'){
    $legacyPath=Join-Path $base 'legacy-preimage.json'
    if($env:CA_GENERAL_STAGE -ceq 'setup'){Save $legacyPath @{schema='container-audit-official-legacy-relay-preimage-v1';identity_sha256=('d'*64);enabled=$true}}
    $legacyRelayPreimage=[pscustomobject]@{path=$legacyPath;sha256=Sha $legacyPath}
}
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
if($kind -like 'A_*'){
    $transaction=$Script:CanonicalWriterFenceTransactionId
    $failed=Join-Path $base ('.current.failed.'+$transaction)
    foreach($directory in @($install,$failed)){[void][IO.Directory]::CreateDirectory($directory)}
    $inventoryPath=Join-Path $repo 'tools/container_writer_sink_inventory.json'
    $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
    $oldManifest=@{schema='container-audit-portable-tree-v1';source_commit=('b'*40);source_tree=('e'*40);
        writer_sink_inventory_sha256=Sha $inventoryPath;writer_sink_inventory_contract_sha256=$inventory.inventory_sha256}
    Save (Join-Path $install 'portable-manifest.json') $oldManifest
    Save (Join-Path $failed 'portable-manifest.json') $sourceManifest
    foreach($directory in @($install,$failed)){Save (Join-Path $directory 'bootstrap-integrity.json') @{fixture='unsigned packet seam'}}
    [void][IO.Directory]::CreateDirectory((Join-Path $install 'tools'))
    [IO.File]::Copy($inventoryPath,(Join-Path $install 'tools/container_writer_sink_inventory.json'))
    if($env:CA_GENERAL_PREIMAGE -ceq 'different_inventory'){
        $oldInventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
        $oldInventory.inventory_sha256='b'*64
        [IO.File]::WriteAllText((Join-Path $install 'tools/container_writer_sink_inventory.json'),($oldInventory|ConvertTo-Json -Depth 40 -Compress),[Text.UTF8Encoding]::new($false))
        $oldManifest.writer_sink_inventory_sha256=Sha (Join-Path $install 'tools/container_writer_sink_inventory.json')
        $oldManifest.writer_sink_inventory_contract_sha256='b'*64
        Save (Join-Path $install 'portable-manifest.json') $oldManifest
        $Script:ContainerWriterFenceAcceptedInstalledInventorySha256='b'*64
    }
    $sourceManifestSha256=Sha (Join-Path $failed 'portable-manifest.json')
    $restoreReceiptFull=Join-Path $base 'replacement-receipt.json'
    $parentAcl=Get-BootstrapAclIdentity $base
    Save $restoreReceiptFull @{
        schema_version='container-audit-verified-replacement-v1';status='OLD_PRESERVED_NEW_VERIFIED';app_id='container_audit';
        transaction_id=$transaction;created_at=[DateTime]::UtcNow.ToString('o');helper_sha256=$sourceHelperSha256;
        integrity_helper_sha256=$sourceIntegrityHelperSha256;receipt_path=$restoreReceiptFull;install_root=$install;install_parent=$base;
        rollback_root=(Join-Path $base ('.current.rollback.'+$transaction));failed_root=$failed;parent_acl=$parentAcl;
        old=(Get-BootstrapReplacementTreeIdentity $install $install);new=(Get-BootstrapReplacementTreeIdentity $failed $install);
        identity_or_credential_copied=$false}
}
$prepared=[ordered]@{schema='container-audit-canonical-writer-prepared-v1';status='PREPARED';app_id='container_audit';
    session_id=$Script:CanonicalWriterFenceSessionId;attempt_id=$Script:CanonicalWriterFenceAttemptId;
    replacement_transaction_id=$Script:CanonicalWriterFenceTransactionId;session_started_at_utc=$canonicalWriterFenceStartedAtUtc;
    orchestrator_sha256=$canonicalWriterFenceOrchestratorSha256;writer_contract_sha256=$canonicalWriterFenceContractSha256;
    writer_inventory_sha256=$Script:ContainerWriterFenceInventorySha256;source_manifest_sha256=$sourceManifestSha256;
    operator_sid=$operatorSid;operator_local_appdata_root=$lad;created_at_utc=[DateTime]::UtcNow.ToString('o');secret_values_recorded=$false}
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
    if($env:CA_GENERAL_PREIMAGE -ceq 'different_inventory'){
        [void](Set-ContainerWriterFenceInventory -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId `
            -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -WriterInventorySha256 ('b'*64) -AuthorityLease $lease)
    }
    $protectedRoot=Join-Path (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence') ('run-'+[Guid]::NewGuid().ToString('N'))
    $auditPath=if($kind -like 'A_*'){Join-Path $auditRoot ('canonical-portable-'+$runId+'.json')}else{Join-Path $protectedRoot 'transaction-rollback-audit.json'}
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
            code_replacement=@{transaction_id=$Script:CanonicalWriterFenceTransactionId;controller_transaction_id=$Script:CanonicalWriterFenceTransactionId;
                receipt_path=$restoreReceiptFull;receipt_sha256=Sha $restoreReceiptFull;later_restore_surface='CONSUMED'}}
        $stage=$auditPath+'.evidence.'+$PID
        [void][IO.Directory]::CreateDirectory($stage)
        $stageAcl=Get-Acl -LiteralPath $stage
        $stageAcl.SetAccessRuleProtection($true,$false)
        foreach($trustee in @($operatorSid,'S-1-5-18','S-1-5-32-544')){
            $stageAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($trustee),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $stage -AclObject $stageAcl
        $audit['stage_evidence_root']=$stage
        $restoreProof=Join-Path $stage 'restore-evidence.json'
        Save $restoreProof @{schema_version='container-audit-verified-replacement-code-restore-v1';status='PASS';action='RESTORED';app_id='container_audit';
            transaction_id=$Script:CanonicalWriterFenceTransactionId;receipt_path=$restoreReceiptFull;receipt_sha256=Sha $restoreReceiptFull;
            install_root=$install;failed_new_root=$failed;prior_code_exact=$true;failed_new_preserved=$true;identity_or_credential_copied=$false;
            completed_at=[DateTime]::UtcNow.ToString('o')}
        $audit.code_replacement['restore_evidence_path']=$restoreProof
        $audit.code_replacement['restore_evidence_sha256']=Sha $restoreProof
        $check=Snapshot
        $productCompleteAuthorizationPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'-product-complete-release.json')
        # Execute the unchanged producer tail; interruption is immediately at Set.
        $text=[IO.File]::ReadAllText($env:CA_CONTRACT_SOURCE)
        $start=$text.IndexOf('        $audit.after = $check'+[char]10+'        $audit.status = ''RESTORE_AWAITING_FENCE_RELEASE''')
        if($start -lt 0){throw 'ACTUAL_RESTORE_TAIL_MISSING'}
        $end=$text.IndexOf('        Clear-CanonicalWriterFenceReleaseDelegation',$start)
        try{. ([scriptblock]::Create($text.Substring($start,$end-$start)))}catch{if($_.Exception.Message -cne 'BOUNDARY_STOP'){throw}}
    }else{
        [void][IO.Directory]::CreateDirectory($protectedRoot)
        $candidate=$null
        if($env:CA_GENERAL_PREIMAGE -in @('prior_code','commit_reached')){
            [void][IO.Directory]::CreateDirectory($install)
            $candidate=if($env:CA_GENERAL_PREIMAGE -ceq 'commit_reached'){$sourceManifest}else{
                [pscustomobject]@{schema='container-audit-portable-tree-v1';source_commit=('b'*40);source_tree=('e'*40);
                    writer_sink_inventory_contract_sha256=$sourceManifest.writer_sink_inventory_contract_sha256}}
            Save (Join-Path $install 'portable-manifest.json') $candidate
            Save (Join-Path $install 'bootstrap-integrity.json') @{fixture='unsigned packet seam'}
        }
        $priorAbsent=$env:CA_GENERAL_PREIMAGE -cne 'prior_code'
        $configuration=[pscustomobject]@{context=[pscustomobject]@{source=$source;install=$install;operatorSid=$operatorSid;lad=$lad;activeDataRoot=$activeDataRoot;
            stop=$stop;before=$before;writerBefore=$writerBefore;legacyRelayPreimage=$legacyRelayPreimage;old=@();currentAbsentBeforePlacement=$priorAbsent;
            sourceManifestSha256=$sourceManifestSha256;sourceManifest=$sourceManifest;candidate=$candidate;installedCodeRoot=$install;supportedPlacement=$false;SkipSignatureValidationForTest=$true};
            protected_root=$protectedRoot;transaction_id=$Script:CanonicalWriterFenceTransactionId;source_root=$source;install_root=$install;
            operator_sid=$operatorSid;local_appdata_root=$lad;data_root=$activeDataRoot;session_id=$Script:CanonicalWriterFenceSessionId;
            attempt_id=$Script:CanonicalWriterFenceAttemptId;orchestrator_sha256=$canonicalWriterFenceOrchestratorSha256;
            writer_contract_sha256=$canonicalWriterFenceContractSha256;prepared_path=$preparedPath;prepared_sha256=Sha $preparedPath;
            source_manifest=$sourceManifest;parent_process_id=$PID;parent_started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o');
            helper_process_id=$PID;helper_started_at_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')}
        Save (Join-Path $protectedRoot 'handover.json') $configuration
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
$rollbackContinuation=$null
$restoreReceiptFull=Join-Path $base 'replacement-receipt.json'
$RestoreReceiptSha256=if(Test-Path -LiteralPath $restoreReceiptFull){Sha $restoreReceiptFull}else{'a'*64}
$sourceWriterInventory=Get-Content -LiteralPath (Join-Path $repo 'tools/container_writer_sink_inventory.json') -Raw|ConvertFrom-Json
if($kind -like 'A_*'){
    $inputReceipt=Read-BootstrapReplacementReceipt $restoreReceiptFull $RestoreReceiptSha256
    $sourceManifestSha256=[string]$inputReceipt.new.manifest_sha256
}
if($env:CA_GENERAL_STAGE -ceq 'public'){
    foreach($name in @('RecoverMachineInstallation','Uninstall','RestoreVerifiedReplacement','CompleteRetiredRemoval','PlanOnly')){Set-Variable $name $false}
    foreach($name in @('MachineRecoveryAuditPath','MachineRecoveryAuditSha256','RestoreReceiptPath','RestoreReceiptSha256','OldSourceRoot',
        'RetiredRemovalReceiptSha256','RetiredStopMarkerSha256','ResumeRetirementReceiptPath','ResumeRetirementReceiptSha256',
        'WorkerAccount','WorkerSurveyInventory','ServerBaseUrl','EvidencePath')){Set-Variable $name ''}
    $RecoverCompletedWriterFence=$true;$SourceRoot=$source;$InstallRoot=$install
    $CompletedFenceAuditPath=if($env:CA_CROSS_AUDIT_PATH){$env:CA_CROSS_AUDIT_PATH}else{$auditPath}
    $CompletedFenceAuditSha256=Sha $CompletedFenceAuditPath
    switch($env:CA_PUBLIC_CASE){
        'mixed_machine'{$RecoverMachineInstallation=$true}
        'mixed_uninstall'{$Uninstall=$true}
        'mixed_restore'{$RestoreVerifiedReplacement=$true}
        'no_switch'{$RecoverCompletedWriterFence=$false}
        'bad_hash'{$CompletedFenceAuditSha256='a'*64}
        'missing_hash'{$CompletedFenceAuditSha256=''}
        'wrong_source'{$SourceRoot=Join-Path $base 'other-source'}
        'wrong_root'{$InstallRoot=Join-Path $base 'other-root'}
        'plan'{$PlanOnly=$true}
        'worker'{$WorkerAccount='not-a-general-mode-argument'}
    }
    function Manifest($Path,$Unsigned){Get-Content -LiteralPath (Join-Path $Path 'portable-manifest.json') -Raw|ConvertFrom-Json}
    function Get-ItemProperty{
        param($LiteralPath,$Name,$ErrorAction)
        $expected='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$operatorSid
        if($LiteralPath -cne $expected -or $Name -cne 'ProfileImagePath'){throw 'UNEXPECTED_NATIVE_REGISTRY_READ'}
        [pscustomobject]@{ProfileImagePath=(Join-Path $base 'profile')}
    }
    $publicAst=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
    $entry=@($publicAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and
        $_.Clauses[0].Item1.Extent.Text -ceq '$RecoverCompletedWriterFence -or $CompletedFenceAuditPath -or $CompletedFenceAuditSha256'})
    if($entry.Count -ne 1){throw 'ACTUAL_PUBLIC_COMPLETION_ENTRY_MISSING'}
    $fixturePublicScriptPath=Join-Path $source 'INSTALL_CANONICAL_PORTABLE.ps1'
    # Extracted entry retains the original admitted script's PSCommandPath.
    $entryBody=$entry[0].Extent.Text.Replace('$PSCommandPath','$fixturePublicScriptPath')
    $publicObservation=@'
Save (Join-Path $base 'public-failure-sites.json') @($Error|Select-Object -First 16|ForEach-Object {@{
 type=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber;
 file=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName);function=($_.ScriptStackTrace -split '[\r\n]')[0] -replace ', .+',''}})
'@
    $entryBody=$entryBody.Replace("Write-Output 'CANONICAL_COMPLETED_RELEASE_PROOF_DIFFERS';exit 1",$publicObservation+";Write-Output 'CANONICAL_COMPLETED_RELEASE_PROOF_DIFFERS';exit 1")
    . ([scriptblock]::Create($entryBody))
    throw 'PUBLIC_ENTRY_DID_NOT_RETURN'
}
if($env:CA_GENERAL_STAGE -ceq 'recover'){
    $activePath=Get-ContainerWriterFenceActivePath
    $auditBefore=Sha $auditPath
    $recoveryCode='';$recovered=$null
    $Error.Clear()
    try{$recovered=Invoke-CanonicalCompletedWriterFenceRecovery $source $install $sourceManifest $auditPath (Sha $auditPath) $operatorSid $lad}
    catch{
        $recoveryCode=if($_.Exception.Message -cmatch '^[A-Z_]+$'){$_.Exception.Message}else{'RECOVERY_UNAVAILABLE'}
        $sites=@($Error|Select-Object -First 16|ForEach-Object {@{type=$_.Exception.GetType().FullName;
            line=$_.InvocationInfo.ScriptLineNumber;file=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName);
            function=($_.ScriptStackTrace -split '[\r\n]')[0] -replace ', .+',''}})
        Save (Join-Path $base 'recovery-failure-sites.json') $sites
    }
    Save (Join-Path $base 'general-recovery-result.json') @{code=$recoveryCode;result=$recovered;
        fence_present=(Test-Path -LiteralPath $activePath);audit_preserved=((Sha $auditPath) -ceq $auditBefore)}
    return
}

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
$refusalSites=[ordered]@{}
$restoreState='NOT_ACCEPTED'
foreach($entry in @('reinstall','explicit_restore','uninstall','machine_recovery')){
    try{
        switch($entry){
            'reinstall'{Read-InstallationAbandonedRollback $install $lad $operatorSid|Out-Null}
            'explicit_restore'{
                $restored=Read-CanonicalReplacementRestore
                $restoreState=[string]$restored.state
                Read-InstallationAbandonedRollback $install $lad $operatorSid|Out-Null
            }
            'uninstall'{Read-CanonicalSupportedRemovalResume|Out-Null}
            'machine_recovery'{Read-CanonicalMachineInstallationRecovery ([pscustomobject]@{sid=$operatorSid}) $source $install $sourceManifest $auditPath (Sha $auditPath)|Out-Null}
        }
        $refusals[$entry]=$false
    }catch{
        $refusals[$entry]=$true
        $refusalSites[$entry]=@{script_file=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName);
            script_line=$_.InvocationInfo.ScriptLineNumber;exception_type=$_.Exception.GetType().FullName}
    }
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
    boundary=$kind;status=$saved.status;restore_state=$restoreState;fence_status=(Read-ContainerWriterFence).status;refusals=$refusals;refusal_sites=$refusalSites;
    indented_audit=($auditRaw -match '"status"\s*:\s+"');continuation_refused=$continuationRefused;
    fence_preserved=((Sha $activePath) -ceq $fenceBefore);audit_preserved=((Sha $auditPath) -ceq $auditBefore);
    control_root=(Get-ContainerWriterFenceControlRoot);local_appdata=$lad;operator_sid=$operatorSid;fence_present=(Test-Path -LiteralPath $activePath)}
