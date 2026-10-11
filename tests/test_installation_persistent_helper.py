"""Exercise the real transaction coordinator in fresh, ordinary Windows processes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("rollback", "timeout", "tamper", "different-id", "oversize", "parent-gone", "helper-gone", "new-relay-remains", "close-tamper"))
def test_persistent_helper_owns_authority_and_compensates(tmp_path, engine, case):
    executable = shutil.which(engine)
    assert executable, engine
    driver = tmp_path / "transaction.ps1"
    driver.write_text(r'''
param([string]$Source,[string]$Root,[string]$Case,[string]$Python)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$env:PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $Root 'known-folders'
$env:LOCALAPPDATA=Join-Path $Root 'L';$env:APPDATA=Join-Path $Root 'A'
$env:CONTAINER_AUDIT_DATA_ROOT=Join-Path $Root 'data'
[void][IO.Directory]::CreateDirectory($env:LOCALAPPDATA)
[void][IO.Directory]::CreateDirectory($env:CONTAINER_AUDIT_DATA_ROOT)
. (Join-Path $Source 'tools\bootstrap_integrity.ps1')
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT 'control')}
. (Get-BootstrapSharedPortableLeaf $Source)
. (Join-Path $Source 'tools\container_writer_fence.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Source 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$null,[ref]$null)
foreach($definition in @($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){
    Invoke-Expression $definition.Extent.Text
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# Preserve the actual production profile while the fixture selects its own root.
# All three actors must derive the same case-scoped admission mutex.
$productionLocalAppData=Get-ContainerWriterFenceProfileLocalAppDataRoot $sid
$Script:ContainerWriterFenceAdmissionProductionRoot=Join-Path $productionLocalAppData 'KMTech\DirectSync\container_audit\control\writer-session'
$fixtureControlRoot=Get-ContainerWriterFenceControlRoot
$fixtureAdmissionName=Get-ContainerWriterAdmissionMutexName
if($fixtureAdmissionName -ceq $Script:ContainerWriterFenceAdmissionMutexName){throw 'Fixture did not isolate its admission mutex.'}
$script:actualTransactionWrapperSource=${function:Get-InstallationTransactionWrapperSource}
function Get-InstallationTransactionWrapperSource {
    $wrapper=& $script:actualTransactionWrapperSource
    $entry='Invoke-InstallationTransactionCoordinator $configuration'
    $adapter=@'
# The pinned product is loaded unchanged; initialize only fixture profile scope
# after its fence definitions initialize their production-root default.
$actualCoordinator=${function:Invoke-InstallationTransactionCoordinator}.ToString()
$anchor='. (Get-InstallationVerifiedScript (Join-Path $source ''tools\container_writer_fence.ps1'') ([string]$Configuration.fence_helper_sha256))'
if($actualCoordinator.Split(@($anchor),[StringSplitOptions]::None).Count -ne 2){throw 'Fixture coordinator anchor differs.'}
$initialization='$Script:ContainerWriterFenceAdmissionProductionRoot=[string]$Configuration.context.fixture_production_control_root'+"`n"+
    'if((Get-ContainerWriterAdmissionMutexName) -cne [string]$Configuration.context.fixture_admission_mutex_name){throw ''Fixture helper admission mutex differs.''}'+"`n"+
    'function Get-InstallationEvidenceControlRoot {return (Join-Path $env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT ''control'')}'
$actualCoordinator=$actualCoordinator.Replace($anchor,($anchor+"`n"+$initialization))
. ([scriptblock]::Create('function Invoke-InstallationTransactionCoordinator {'+$actualCoordinator+'}'))
Invoke-InstallationTransactionCoordinator $configuration
'@
    if($wrapper.Split(@($entry),[StringSplitOptions]::None).Count -ne 2){throw 'Fixture wrapper entry differs.'}
    return $wrapper.Replace($entry,$adapter)
}
$session=[Guid]::NewGuid().ToString('N');$attempt=[Guid]::NewGuid().ToString('N');$transaction=[Guid]::NewGuid().ToString('N')
$orchestrator=Get-FileSha256 (Join-Path $Source 'INSTALL_CANONICAL_PORTABLE.ps1')
$contract=Get-FileSha256 (Join-Path $Source 'tools\container_writer_session_contract.json')
$prepared=New-CanonicalWriterFencePreparedReceipt (Join-Path $Root 'prepared.json') $session $attempt $transaction `
    ([DateTime]::UtcNow.ToString('o')) $orchestrator $contract ('a'*64) $sid $env:LOCALAPPDATA
$lease=Enter-ContainerWriterSessionAuthority $session $attempt $orchestrator $transaction $contract
$delegation=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
[void](Start-ContainerWriterFence -Status INSTALLING -OwnerKind canonical_installer -SessionId $session -AttemptId $attempt `
    -ReplacementTransactionId $transaction -SessionStartedAtUtc ([DateTime]::UtcNow.ToString('o')) `
    -OrchestratorSha256 $orchestrator -WriterContractSha256 $contract -PreparedReceiptPath $prepared.path `
    -PreparedReceiptSha256 $prepared.sha256 -DelegationToken $delegation -DelegatedSources @('current_user_onboarding') `
    -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(20).ToString('o')) -AuthorityLease $lease)
[void](Initialize-InstallationEvidence (Join-Path $Root 'parent') $sid)
$manifest=[pscustomobject]@{version='v2.0.99';source_commit=('a'*40)}
$runName='KMTech.ContainerAudit.SUB451.'+$transaction
$context=@{RunKey='Software\Microsoft\Windows\CurrentVersion\Run';RunName=$runName;source=$Source;install=(Join-Path $Root 'apps\current');
    installedCodeRoot=(Join-Path $Root 'apps\current');operatorSid=$sid;lad=$env:LOCALAPPDATA;activeDataRoot=$env:CONTAINER_AUDIT_DATA_ROOT;
    stop=(Join-Path $Root 'stop.json');removalPath=(Join-Path $Root 'removal.json');relayPath=(Join-Path $Root 'relay.json');auditRoot=$Root;
    sourceManifest=$manifest;sourceManifestSha256=('a'*64);sourceHelperSha256=(Get-FileSha256 (Join-Path $Source 'INSTALL_THIS_PC.ps1'));
    sourceIntegrityHelperSha256=(Get-FileSha256 (Join-Path $Source 'tools\bootstrap_integrity.ps1'));installedInventorySha256=$Script:ContainerWriterFenceInventorySha256;
    currentAbsentBeforePlacement=$true;before=@{exists=$false;kind='';data=''};old=@();writerBefore=@{restore_required=$false};
    legacyRelayPreimage=$null;supportedPlacement=$false;SkipSignatureValidationForTest=$false;testMode=$true;wanted='';candidate=$null;
    canonicalWriterFenceStartedAtUtc=([DateTime]::UtcNow.ToString('o'));canonicalWriterFenceOrchestratorSha256=$orchestrator;
    canonicalWriterFenceContractSha256=$contract;canonicalWriterFencePreparedReceipt=$prepared;canonicalWriterFenceDelegatedSources=@('current_user_onboarding');
    fixture_production_control_root=$Script:ContainerWriterFenceAdmissionProductionRoot;fixture_admission_mutex_name=$fixtureAdmissionName}
$configuration=[ordered]@{source_root=$Source;install_root=$context.install;operator_sid=$sid;local_appdata_root=$env:LOCALAPPDATA;
    data_root=$env:CONTAINER_AUDIT_DATA_ROOT;source_manifest=$manifest;context=$context;operator_security=(Get-BootstrapRelaySecurity $PID);
    child_environment=@{LOCALAPPDATA=$env:LOCALAPPDATA;APPDATA=$env:APPDATA;CONTAINER_AUDIT_DATA_ROOT=$env:CONTAINER_AUDIT_DATA_ROOT};
    test_mode=$true;timeout_seconds=if($Case -ceq 'timeout'){2}else{30};session_id=$session;attempt_id=$attempt;transaction_id=$transaction;
    orchestrator_sha256=$orchestrator;writer_contract_sha256=$contract;helper_sha256=$context.sourceHelperSha256;
    library_sha256=$context.sourceIntegrityHelperSha256;fence_helper_sha256=(Get-FileSha256 (Join-Path $Source 'tools\container_writer_fence.ps1'));
    installed_inventory_sha256=$Script:ContainerWriterFenceInventorySha256;prepared_path=$prepared.path;prepared_sha256=$prepared.sha256;
    delegation=$delegation;release_paths=@{product_complete=(Join-Path $Root 'product-release.json');product_natural=(Join-Path $Root 'natural-release.json')}}
$configuration.relay_preimage=@(Get-CanonicalGlobalRelayPreimage)
$configuration.quiesce_relays=@()
$env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=$delegation
$env:CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID=$session
$env:CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID=$attempt
$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID=$transaction
$Script:launchCount=0;$Script:consentRequests=0;$Script:gapDenied=$false
$launch={param($request)
    $Script:launchCount++;if($request.RequiresConsent){$Script:consentRequests++}
    $probe=Join-Path $Root 'gap.py'
    $Script:gapProbePath=$probe
    [IO.File]::WriteAllText($probe,@'
import json,os,sys
sys.path.insert(0,sys.argv[1])
import writer_session_fence as fence
values=dict(os.environ,LOCALAPPDATA=sys.argv[2])
control_root=sys.argv[3]
admission_name=fence.writer_admission_mutex_name(control_root,environ=values)
denied_code=''
try:
    with fence.writer_admission('current_user_onboarding',control_root=control_root,environ=values):
        denied=False
except fence.WriterFenceError as failure:
    denied=True
    denied_code=failure.code
active=fence.active_fence(control_root=control_root)
print(json.dumps({'denied':denied,'denied_code':denied_code,'admission_name':admission_name,'primary_held':fence._named_mutex_held_by_other(active['session_authority_mutex_name'])}))
'@,[Text.UTF8Encoding]::new($false))
    $gap=& $Python -I -B $probe $Source $productionLocalAppData $fixtureControlRoot
    $gapProof=$gap|ConvertFrom-Json
    $Script:gapDenied=[bool]$gapProof.denied
    if($gapProof.primary_held){throw 'The probe did not run inside the actual primary ownership gap.'}
    if(-not $Script:gapDenied){throw 'Actual writer admitted during authority handover gap.'}
    if($gapProof.admission_name -cne $fixtureAdmissionName -or $gapProof.denied_code -cne 'ACTIVE_WRITER_FENCE'){throw 'Gap denial did not exercise the same fixture fence mutex.'}
    Start-Process -FilePath $request.FilePath -ArgumentList $request.ArgumentList -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Root 'helper.stdout.log') -RedirectStandardError (Join-Path $Root 'helper.stderr.log')
}
$job=Start-InstallationTransaction $configuration $lease $launch
$readyAdmission=(& $Python -I -B $Script:gapProbePath $Source $productionLocalAppData $fixtureControlRoot)|ConvertFrom-Json
if($readyAdmission.denied -or -not $readyAdmission.primary_held){throw 'Valid delegated writer did not admit under the helper primary owner.'}
if($readyAdmission.admission_name -cne $fixtureAdmissionName){throw 'READY writer admission mutex differs.'}
$info=@{protected_root=$configuration.protected_root;request_root=$configuration.request_root;helper_pid=$job.Process.Id;
    launch_count=$Script:launchCount;consent_requests=$Script:consentRequests;writer_admitted_after_ready=(-not $readyAdmission.denied);gap_denied=$Script:gapDenied;fence_path=(Get-ContainerWriterFenceActivePath);case=$Case;
    expected_consent_requests=[int](-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator));
    foreign_relay_count=@(Relays).Count}
[IO.File]::WriteAllText((Join-Path $Root 'job-info.json'),($info|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
if($Case -ceq 'parent-gone'){exit 0}
if($Case -ceq 'helper-gone'){
    $job.Process.Kill();$job.Process.WaitForExit()
    $denied=$false
    try{Assert-InstallationTransactionAlive $job}catch{$denied=$true}
    $info.helper_gone_denied=$denied;$info.fence_retained=Test-Path -LiteralPath (Get-ContainerWriterFenceActivePath)
    $info.g_marker_count=@(Get-ChildItem -LiteralPath $env:CONTAINER_AUDIT_DATA_ROOT -Filter data-generation.json -Recurse).Count
    [IO.File]::WriteAllText((Join-Path $Root 'job-info.json'),($info|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    Remove-InstallationMemoryTransport $job.Transport
    exit 0
}
if($Case -ceq 'new-relay-remains'){
    $extraRelay=Start-Process -FilePath $Python -ArgumentList '-I -B -c "import time; time.sleep(45)" --container-audit-user-relay' -WindowStyle Hidden -PassThru
}
if($Case -cin @('rollback','new-relay-remains','close-tamper')){Send-InstallationTransactionDecision $job 'ROLLBACK'}
elseif($Case -cne 'timeout'){
    [byte[]]$bytes=Get-InstallationTransactionBytes $configuration 'ROLLBACK'
    if($Case -ceq 'tamper'){$bytes[0]=32}
    elseif($Case -ceq 'different-id'){
        $record=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json;$record.transaction_id='b'*32
        $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Compress))
    }elseif($Case -ceq 'oversize'){$bytes=[Text.Encoding]::UTF8.GetBytes(' '*65537)}
    [IO.File]::WriteAllBytes((Join-Path $configuration.request_root 'rollback.request'),$bytes)
}
$response=Wait-InstallationTransactionResponse $job 'outcome-ready' 30
[IO.File]::WriteAllText((Join-Path $Root 'response.json'),($response|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
if($Case -ceq 'close-tamper'){
    [IO.File]::WriteAllBytes((Join-Path $configuration.request_root 'close.request'),[Text.Encoding]::UTF8.GetBytes('{}'))
    if(-not $job.Process.WaitForExit(15000)){throw 'Owned helper did not reject CLOSE within its bounded wait.'}
    Remove-InstallationMemoryTransport $job.Transport -AfterSeal
}else{Close-InstallationTransaction $job}
if($Case -ceq 'new-relay-remains'){$extraRelay.Kill();$extraRelay.WaitForExit()}
''', encoding="utf-8-sig")
    import sys
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver),
         "-Source", str(ROOT), "-Root", str(tmp_path), "-Case", case, "-Python", sys.executable],
        env=dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path)),
        capture_output=True, creationflags=0x08000000,
    )
    (tmp_path / "stdout.log").write_bytes(result.stdout)
    (tmp_path / "stderr.log").write_bytes(result.stderr)
    assert result.returncode == 0, f"driver failure; see {tmp_path / 'stderr.log'}"
    info = json.loads((tmp_path / "job-info.json").read_bytes())
    assert info["launch_count"] == 1
    assert info["gap_denied"] is True
    assert info["writer_admitted_after_ready"] is True
    assert info["consent_requests"] == info["expected_consent_requests"]
    if case == "helper-gone":
        assert info["helper_gone_denied"] is True
        assert info["fence_retained"] is True
        assert info["g_marker_count"] == 0
        return
    response_path = Path(info["protected_root"]) / "outcome-ready.json"
    deadline = time.monotonic() + 35
    while not response_path.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert response_path.exists(), f"helper result missing; see {tmp_path / 'helper.stderr.log'}"
    response = json.loads(response_path.read_bytes())
    expected_status = "CODE_ROLLBACK_FAILED" if case == "new-relay-remains" else "FAILED_ROLLED_BACK"
    assert response["status"] == expected_status
    assert response["compensation"]["code_exact"] is True
    assert response["compensation"]["runtime_restored"] is (case != "new-relay-remains")
    assert response["compensation"]["fence_released"] is (case != "new-relay-remains")
    assert Path(info["fence_path"]).exists() is (case == "new-relay-remains")
    expected_reason = {"rollback": "ROLLBACK_REQUESTED", "close-tamper": "ROLLBACK_REQUESTED", "new-relay-remains": "ROLLBACK_REQUESTED", "timeout": "OUTCOME_TIMEOUT", "parent-gone": "PARENT_GONE"}
    assert response["reason"] == expected_reason.get(case, "OUTCOME_RECORD_REJECTED")
    summary_path = Path(response["evidence_summary"]["summary_path"])
    summary = json.loads(summary_path.read_bytes())
    for part in summary["journal_parts"]:
        assert hashlib.sha256(Path(part["path"]).read_bytes()).hexdigest() == part["sha256"]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_transaction_mutex_grants_only_bound_operator_observer_rights(tmp_path, engine):
    driver = tmp_path / "mutex.ps1"
    driver.write_text(r'''
param([string]$Source)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $Source 'tools\container_writer_fence.ps1')
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class TransactionSidAccess {
 [StructLayout(LayoutKind.Sequential)] public struct Luid {public uint low;public int high;}
 [StructLayout(LayoutKind.Sequential)] public struct Request {public uint desired;public IntPtr self,list;public uint count;public IntPtr optional;}
 [StructLayout(LayoutKind.Sequential)] public struct Reply {public uint count;public IntPtr granted,sacl,error;}
 [DllImport("authz.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool AuthzInitializeResourceManager(uint flags,IntPtr a,IntPtr b,IntPtr c,string name,out IntPtr manager);
 [DllImport("authz.dll",SetLastError=true)] static extern bool AuthzInitializeContextFromSid(uint flags,byte[] sid,IntPtr manager,IntPtr expiry,Luid id,IntPtr args,out IntPtr context);
 [DllImport("authz.dll",SetLastError=true)] static extern bool AuthzAccessCheck(uint flags,IntPtr context,ref Request request,IntPtr audit,byte[] descriptor,IntPtr extra,uint count,ref Reply reply,IntPtr cache);
 [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr context);
 [DllImport("authz.dll")] static extern bool AuthzFreeResourceManager(IntPtr manager);
 public static uint Granted(byte[] descriptor,string value,uint desired) {
  IntPtr manager=IntPtr.Zero,context=IntPtr.Zero,granted=Marshal.AllocHGlobal(4),sacl=Marshal.AllocHGlobal(4),error=Marshal.AllocHGlobal(4);
  try {
   SecurityIdentifier sid=new SecurityIdentifier(value);byte[] bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
   if(!AuthzInitializeResourceManager(1,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,"sub451-owned-mutex",out manager))throw new Win32Exception();
   // SID-only context: no logon, network lookup, token/elevation or GUI.
   if(!AuthzInitializeContextFromSid(2,bytes,manager,IntPtr.Zero,new Luid(),IntPtr.Zero,out context))throw new Win32Exception();
   Request request=new Request {desired=desired};Reply reply=new Reply {count=1,granted=granted,sacl=sacl,error=error};
   if(!AuthzAccessCheck(0,context,ref request,IntPtr.Zero,descriptor,IntPtr.Zero,0,ref reply,IntPtr.Zero))throw new Win32Exception();
   return unchecked((uint)Marshal.ReadInt32(granted));
  } finally {if(context!=IntPtr.Zero)AuthzFreeContext(context);if(manager!=IntPtr.Zero)AuthzFreeResourceManager(manager);Marshal.FreeHGlobal(granted);Marshal.FreeHGlobal(sacl);Marshal.FreeHGlobal(error);}
 }
}
'@
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$session=[Guid]::NewGuid().ToString('N');$attempt=[Guid]::NewGuid().ToString('N');$transaction=[Guid]::NewGuid().ToString('N')
$lease=Enter-ContainerWriterSessionAuthority $session $attempt ('a'*64) $transaction ('b'*64) -ObserverSid $sid
try{
 $security=if($PSVersionTable.PSEdition -ceq 'Desktop'){$lease.mutex.GetAccessControl()}else{[Threading.ThreadingAclExtensions]::GetAccessControl($lease.mutex)}
 $rules=@($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if(@($rules|Where-Object {$_.IdentityReference.Value -cnotin @($sid,'S-1-5-18','S-1-5-32-544')}).Count){throw 'Unexpected mutex reader SID.'}
 $observer=@($rules|Where-Object {$_.IdentityReference.Value -ceq $sid})
 $rights=[Security.AccessControl.MutexRights]::Synchronize -bor [Security.AccessControl.MutexRights]::Modify
 if($observer.Count -ne 1 -or $observer[0].MutexRights -ne $rights){throw 'Operator observer rights differ.'}
 $descriptor=$security.GetSecurityDescriptorBinaryForm()
 $foreign='S-1-5-21-1234-5678-9012-3456'
 if([TransactionSidAccess]::Granted($descriptor,$foreign,[uint32]$rights) -ne 0){throw 'Other SID access was granted.'}
 if([TransactionSidAccess]::Granted($descriptor,$sid,[uint32]$rights) -ne [uint32]$rights){throw 'Bound operator cannot observe authority.'}
 $duplicateDenied=$false
 try{$duplicate=Enter-ContainerWriterSessionAuthority $session $attempt ('a'*64) $transaction ('b'*64) -ObserverSid $sid}catch{$duplicateDenied=$true}
 if(-not $duplicateDenied){Exit-ContainerWriterSessionAuthority $duplicate;throw 'Created-only ownership was weakened.'}
 [Console]::WriteLine('mutex_observer=PASS_BOUND_OPERATOR_ONLY')
}finally{Exit-ContainerWriterSessionAuthority $lease}
''', encoding="utf-8-sig")
    result = subprocess.run([shutil.which(engine), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver),
                             "-Source", str(ROOT)], capture_output=True, creationflags=0x08000000, timeout=60)
    (tmp_path / "stdout.log").write_bytes(result.stdout)
    (tmp_path / "stderr.log").write_bytes(result.stderr)
    assert result.returncode == 0, f"mutex native access proof failed; see {tmp_path / 'stderr.log'}"
    assert b"PASS_BOUND_OPERATOR_ONLY" in result.stdout
