"""Keep the forward failure and native recovery failure distinct and bounded."""
import os
import json
from pathlib import Path
import re
import sys

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('CA_RUNTIME_INSTALLER_SOURCE', ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'))


def test_limited_launch_requests_explicit_primary_token_rights_proven_in_guest():
    """Win32 error 5 was reproduced with 11 and resolved with these explicit rights."""
    calls = re.findall(r'DuplicateTokenEx\(token,\s*(0x[0-9a-fA-F]+|\d+),', SOURCE.read_text(encoding='utf-8-sig'))
    assert [int(value, 0) for value in calls] == [0x18B]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('scenario', ('native_access_denied', 'native_privilege_missing', 'placement', 'unclassified'))
def test_failure_details_survive_method_wrapper_without_credentials(tmp_path, engine, scenario):
    result = run_functions(tmp_path, SOURCE, ['Get-CanonicalFailureDetails'], r'''
$Script:InstallationEvidenceSensitiveValues=@('sensitive-sentinel-do-not-store')
Add-Type -TypeDefinition @'
using System; using System.ComponentModel;
public static class InjectedLaunchFailure {
 public static void Fail(int error) {
  Win32Exception failure=new Win32Exception(error,"sensitive-sentinel-do-not-store");
  failure.Data["canonical_api"]="CreateProcessWithTokenW";
  throw failure;
 }
}
'@
try {
 if ($env:CA_FAILURE_SCENARIO -ceq 'native_access_denied') { [InjectedLaunchFailure]::Fail(5) }
 elseif ($env:CA_FAILURE_SCENARIO -ceq 'native_privilege_missing') { [InjectedLaunchFailure]::Fail(1314) }
 elseif ($env:CA_FAILURE_SCENARIO -ceq 'placement') { throw '설치 코드 배치 전 중단 (CONTAINER_PLACEMENT_ACCESS_DENIED). sensitive-sentinel-do-not-store' }
 else { throw 'sensitive-sentinel-do-not-store' }
} catch { $failure=$_ }
$details=Get-CanonicalFailureDetails $failure 'INSTALL'
$json=$details | ConvertTo-Json -Depth 6
if ($json.Contains('sensitive-sentinel')) { throw 'raw failure message leaked' }
if ($details.phase -cne 'INSTALL' -or $details.exception_types.Count -lt 1) { throw 'failure identity lost' }
if ($env:CA_FAILURE_SCENARIO -clike 'native_*') {
 $expectedError=if ($env:CA_FAILURE_SCENARIO -ceq 'native_access_denied') {5} else {1314}
 if ($details.api -cne 'CreateProcessWithTokenW' -or $details.win32_error -ne $expectedError) { throw 'native cause lost in MethodInvocationException' }
 if ($details.exception_types -cnotcontains 'System.Management.Automation.MethodInvocationException') { throw 'outer failure not preserved' }
} elseif ($env:CA_FAILURE_SCENARIO -ceq 'placement') {
 if ($details.code -cne 'CONTAINER_PLACEMENT_ACCESS_DENIED') { throw 'forward placement failure lost' }
} elseif ($details.code -cne 'CANONICAL_UNCLASSIFIED_FAILURE') { throw 'unclassified failure invented' }
'PASS'
''', values={'CA_FAILURE_SCENARIO': scenario}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('scenario', ('native_access_denied', 'native_privilege_missing', 'ready_missing', 'ready_changed', 'identity_changed'))
def test_real_transaction_relay_failure_refences_and_preserves_forward_cause(tmp_path, engine, scenario):
    probe = tmp_path / 'writer_probe.py'
    probe.write_text('''import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import writer_session_fence as fence
try:
    with fence.writer_admission('current_user_onboarding'):
        if sys.argv[3] == 'mutate':
            Path(sys.argv[2]).write_bytes(b'unexpected writer')
    denied=False
except fence.WriterFenceError:
    denied=True
active=fence.active_fence()
print(json.dumps({'denied':denied,'primary_held':fence._named_mutex_held_by_other(active['session_authority_mutex_name'])}))
''', encoding='utf-8')
    result = run_functions(tmp_path, SOURCE, ['Get-CanonicalFailureDetails'], r'''
$source=Split-Path -Parent $env:CA_CONTRACT_SOURCE
$root=$env:CA_CONTRACT_ROOT
$env:KMTECH_FACTORY_INSTALL_TEST_MODE='1'
$env:CONTAINER_AUDIT_WRITER_TEST_MODE='1'
$env:CONTAINER_AUDIT_WRITER_CONTROL_ROOT=Join-Path $root 'control'
$env:LOCALAPPDATA=Join-Path $root 'local';$env:APPDATA=Join-Path $root 'roaming'
$env:CONTAINER_AUDIT_DATA_ROOT=Join-Path $root 'data'
[void][IO.Directory]::CreateDirectory($env:LOCALAPPDATA)
[void][IO.Directory]::CreateDirectory($env:CONTAINER_AUDIT_DATA_ROOT)
. (Join-Path $source 'tools\container_writer_fence.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
foreach($definition in @($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){
    Invoke-Expression $definition.Extent.Text
}
$library=[Management.Automation.Language.Parser]::ParseFile((Join-Path $source 'tools\bootstrap_integrity.ps1'),[ref]$null,[ref]$null)
$compensation=@($library.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Invoke-CanonicalTransactionCompensation'})
$blocks=@($compensation[0].FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and
    $n.Body.Extent.Text.Contains('Assert-CanonicalTransactionRelayPreimage') -and
    $n.CatchClauses.Count -eq 1 -and $n.CatchClauses[0].Body.Extent.Text.Contains("'RESTORE_FAILED'")},$true))
$statuses=@($compensation[0].FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -ceq '$audit.status' -and $n.Extent.Text.Contains('Get-CanonicalRollbackSuccessStatus')},$true))
if($blocks.Count -ne 1 -or $statuses.Count -ne 1){throw 'actual transaction post-release recovery missing'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
[void](Initialize-InstallationEvidence (Join-Path $root 'private') $sid)
try{throw [IO.InvalidDataException]::new('ISOLATED_ORIGINAL_FORWARD_FAILURE')}catch{$forward=$_}
Write-InstallationCaughtFailure $forward
$original=$forward.Exception.Data['installation_original_failure_reference']
$originalSha=Get-FileSha256 $original.path
$session=[Guid]::NewGuid().ToString('N');$attempt=[Guid]::NewGuid().ToString('N');$transaction=[Guid]::NewGuid().ToString('N')
$Script:CanonicalWriterFenceSessionId=$session;$Script:CanonicalWriterFenceAttemptId=$attempt;$Script:CanonicalWriterFenceTransactionId=$transaction
$canonicalWriterFenceStartedAtUtc=[DateTime]::UtcNow.ToString('o')
$canonicalWriterFenceOrchestratorSha256=Get-FileSha256 $env:CA_CONTRACT_SOURCE
$canonicalWriterFenceContractSha256=Get-FileSha256 (Join-Path $source 'tools\container_writer_session_contract.json')
$canonicalWriterFencePreparedReceipt=New-CanonicalWriterFencePreparedReceipt (Join-Path $root 'prepared.json') $session $attempt $transaction `
    $canonicalWriterFenceStartedAtUtc $canonicalWriterFenceOrchestratorSha256 $canonicalWriterFenceContractSha256 ('a'*64) $sid $env:LOCALAPPDATA
$Lease=Enter-ContainerWriterSessionAuthority $session $attempt $canonicalWriterFenceOrchestratorSha256 $transaction $canonicalWriterFenceContractSha256
$delegation=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
$env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=$delegation
$env:CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID=$session;$env:CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID=$attempt
$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID=$transaction
$bindings=@{SessionId=$session;AttemptId=$attempt;ReplacementTransactionId=$transaction;AuthorityLease=$Lease}
$business=Join-Path $root 'business.csv';[IO.File]::WriteAllText($business,'preserved business rows')
$businessSha=Get-FileSha256 $business
$ownedRelay=$null
try{
    [void](Start-ContainerWriterFence @bindings -Status RESTORING -OwnerKind canonical_installer `
        -SessionStartedAtUtc $canonicalWriterFenceStartedAtUtc -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 `
        -WriterContractSha256 $canonicalWriterFenceContractSha256 -PreparedReceiptPath $canonicalWriterFencePreparedReceipt.path `
        -PreparedReceiptSha256 $canonicalWriterFencePreparedReceipt.sha256 -DelegationToken $delegation `
        -DelegatedSources @('current_user_onboarding') -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(5).ToString('o')))
    $admitted=(& $env:CA_TEST_PYTHON -I -B $env:CA_WRITER_PROBE $source $business 'read')|ConvertFrom-Json
    if($admitted.denied -or -not $admitted.primary_held){throw 'fixture valid writer admission unproven'}
    [void](Stop-ContainerWriterFence @bindings -ReleaseAuthorizationPath $canonicalWriterFencePreparedReceipt.path `
        -ReleaseAuthorizationSha256 $canonicalWriterFencePreparedReceipt.sha256)
    $released=$true;$proven=$true;$point='REACHED'
    $audit=[ordered]@{failure=@{code='CONTAINER_PLACEMENT_CHILD_FAILED';report_sha256=$originalSha};rollback=@{}}
    $auditPath=Join-Path $Script:InstallationEvidenceRoot 'audit.json'
    $configuration=@{relay_preimage=@(Get-CanonicalGlobalRelayPreimage);quiesce_relays=@()}
    if($env:CA_FAILURE_SCENARIO -cnotlike 'native_*'){
        $ownedRelay=Start-Process -FilePath $env:CA_TEST_PYTHON -ArgumentList '-I -B -c "import time; time.sleep(60)" --container-audit-user-relay' -WindowStyle Hidden -PassThru
        $ownedCreated=$ownedRelay.StartTime.ToFileTimeUtc()
        $actual=@(Get-CanonicalGlobalRelayPreimage|Where-Object {$_.process_id -eq $ownedRelay.Id})
        if($actual.Count -ne 1){throw 'owned relay observation absent'}
        $expected=[ordered]@{};foreach($key in $actual[0].Keys){$expected[$key]=$actual[0][$key]}
        $expected.process_id=2147483646;$expected.started_at_utc='2000-01-01T00:00:00.0000000Z'
        $configuration.quiesce_relays=@($expected)
        $Script:CanonicalRelayProof=@{status='UNPROVEN';process_id=$ownedRelay.Id}
        if($env:CA_FAILURE_SCENARIO -ceq 'ready_changed'){$Script:CanonicalRelayProof=@{status='PROVEN';process_id=2147483646}}
        if($env:CA_FAILURE_SCENARIO -ceq 'identity_changed'){$expected.command_line='changed old relay command'}
    }
    $injected=if($env:CA_FAILURE_SCENARIO -ceq 'native_access_denied'){"throw [ComponentModel.Win32Exception]::new(5)"}
        elseif($env:CA_FAILURE_SCENARIO -ceq 'native_privilege_missing'){"throw [ComponentModel.Win32Exception]::new(1314)"}
        else{'[void](Assert-CanonicalTransactionRelayPreimage $configuration -AfterRestore)'}
    . ([ScriptBlock]::Create('try {'+$injected+'} catch '+$blocks[0].CatchClauses[0].Body.Extent.Text))
    Invoke-Expression $statuses[0].Extent.Text
    Save $auditPath $audit
    $active=Read-ContainerWriterFence
    Assert-ContainerWriterSessionAuthority $active $Lease
    $denied=(& $env:CA_TEST_PYTHON -I -B $env:CA_WRITER_PROBE $source $business 'mutate')|ConvertFrom-Json
    if($proven -or $released -or $active.status -cne 'RESTORE_FAILED' -or
        $active.session_id -cne $session -or $active.attempt_id -cne $attempt -or
        $active.replacement_transaction_id -cne $transaction -or
        $active.prepared_receipt_sha256 -cne $canonicalWriterFencePreparedReceipt.sha256){throw 'failed recovery not refenced exactly'}
    if(-not $denied.denied -or -not $denied.primary_held -or (Get-FileSha256 $business) -cne $businessSha){throw 'actual writer not denied'}
    $saved=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-Json
    if($saved.status -cne 'CODE_ROLLBACK_FAILED' -or $saved.failure.code -cne 'CONTAINER_PLACEMENT_CHILD_FAILED' -or
        $saved.failure.report_sha256 -cne $originalSha -or (Get-FileSha256 $original.path) -cne $originalSha -or
        -not [object]::ReferenceEquals($original,$forward.Exception.Data['installation_original_failure_reference'])){throw 'forward failure overwritten'}
    if(@(Get-ChildItem -LiteralPath $Script:InstallationEvidenceRoot -Filter 'original-failure-*.json').Count -lt 2){throw 'recovery failure report absent'}
    [ordered]@{status=$saved.status;writer_denied=$denied.denied;primary_held=$denied.primary_held;forward_preserved=$true}|ConvertTo-Json -Compress
}finally{
    if($null -ne $ownedRelay -and -not $ownedRelay.HasExited -and $ownedRelay.StartTime.ToFileTimeUtc() -eq $ownedCreated){$ownedRelay.Kill();$ownedRelay.WaitForExit()}
    if($null -ne (Read-ContainerWriterFence -AllowAbsent)){[void](Abort-ContainerWriterFence @bindings)}
    Exit-ContainerWriterSessionAuthority $Lease
}
''', values={'CA_FAILURE_SCENARIO': scenario, 'CA_TEST_PYTHON': sys.executable,
             'CA_WRITER_PROBE': str(probe)}, engine=engine)
    (tmp_path / 'stdout.txt').write_text(result.stdout, encoding='utf-8')
    (tmp_path / 'stderr.txt').write_text(result.stderr, encoding='utf-8')
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout.splitlines()[-1])
    assert observed == {'status': 'CODE_ROLLBACK_FAILED', 'writer_denied': True,
                        'primary_held': True, 'forward_preserved': True}
