"""Exercise real failure sinks with synthetic secrets and bounded JSON."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions
from tests.test_installation_stage_evidence import FUNCTIONS
from tests.test_official_legacy_relay_identity import XML_SETUP
ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
def test_escaped_first_failure_and_rotated_journal_remain_valid_and_bounded(tmp_path, engine):
    result=run_functions(tmp_path,ROOT/'tools/bootstrap_integrity.ps1',[*FUNCTIONS,'Complete-InstallationEvidence'],r'''
function Set-InstallationEvidenceAcl {param($Path,$Sid)}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'bounded') ''
$message=('가"\'*50000)+' ValueError: final synthetic exception'
Write-InstallationCaughtFailure ([InvalidOperationException]::new($message))
$ref=$Script:InstallationOriginalFailure
if(-not $ref.path -or $ref.complete){throw 'Large escaped failure was not explicitly bounded.'}
$body=Get-Content -LiteralPath $ref.path -Raw -Encoding UTF8|ConvertFrom-Json
if(-not $body.failure.exception_chain[0].message.EndsWith('ValueError: final synthetic exception')){throw 'Final exception was lost.'}
foreach($i in 0..40){Write-InstallationEvidenceEvent @{event='ROTATE_FIXTURE';detail=('v'*2000);sequence=$i}}
$summary=Complete-InstallationEvidence
if($summary.journal_parts.Count -lt 2 -or $summary.recording_failed){throw 'Journal rotation lost evidence.'}
foreach($file in @(Get-ChildItem -LiteralPath $root -File)){
 if($file.Length -gt 65536){throw 'Sink exceeded total UTF8 byte cap.'}
 if($file.Extension -ceq '.json'){[void](Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8|ConvertFrom-Json)}
 if($file.Extension -ceq '.jsonl'){foreach($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8){[void]($line|ConvertFrom-Json)}}
}
'PASS'
''',engine=engine)
    assert result.returncode==0,result.stderr

@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
def test_official_helper_keeps_registered_task_and_shared_state_accepts_writer_shape(tmp_path, engine):
    canonical=ROOT/'INSTALL_CANONICAL_PORTABLE.ps1'
    result=run_functions(tmp_path,canonical,['Get-CanonicalOfficialLegacyRelayExpectedSet','Get-CanonicalOfficialLegacyRelayState'],XML_SETUP+r'''
$writer=[pscustomobject]@{mechanism='scheduled_task';task_path='\';task_name=$name;xml=$xml}
$state=Get-CanonicalOfficialLegacyRelayState $writer (Get-CanonicalOfficialLegacyRelayExpectedSet) ''
if(-not $state.recognized -or -not $state.enabled -or $state.transition_record -ne $null){throw 'Specified writer shape was not accepted.'}
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'INSTALL_THIS_PC.ps1'),[ref]$null,[ref]$null)
$function=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Remove-ContainerScheduledTasks'},$true))
Invoke-Expression $function[0].Extent.Text
function Get-ContainerRemovalTaskNames {param($Folder,$CurrentRoot);return 'direct-sync-relay-container-audit'}
function Write-ContainerStartupUpdateRecord {param($Path,$Payload)}
$script:stops=0
$registered=[pscustomobject]@{Enabled=$true;Xml=$xml}
$registered|Add-Member ScriptMethod Stop {param($Flags);$script:stops++}
$registered|Add-Member ScriptMethod GetSecurityDescriptor {param($Flags);return 'fixture'}
$folder=[pscustomobject]@{}
$folder|Add-Member ScriptMethod GetTask {param($Name);return $registered}
$folder|Add-Member ScriptMethod DeleteTask {param($Name,$Flags);throw 'Recognized task was deleted.'}
Remove-ContainerScheduledTasks $folder $env:CA_CONTRACT_ROOT 'absent-current'
if($registered.Enabled -or $script:stops -ne 1){throw 'Legacy task disable/stop was not read back.'}
'PASS'
''',engine=engine)
    assert result.returncode==0,result.stderr

def test_updater_failure_full_record_has_no_opaque_authority_bytes(tmp_path,monkeypatch):
    import auto_update as update
    secret='synthetic-authority-boundary-only-273'
    monkeypatch.setenv('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',secret)
    error=RuntimeError(('가"'*50000)+secret+' ValueError: update final exception')
    refs=update._write_failure_evidence(tmp_path,error)
    assert refs and refs[0]['streams']['message']['complete'] is False
    for path in tmp_path.glob('failure-text-*.json'):
        raw=path.read_bytes()
        assert len(raw)<=65536
        assert secret.encode() not in raw
        assert b'update final exception' in raw

def test_fixed_helper_failure_retains_child_cause_and_bootstrap_keeps_first_and_last(monkeypatch,tmp_path):
    import auto_update as update
    import direct_sync_auto_bootstrap as bootstrap
    import subprocess
    secret='synthetic-helper-authority-273'
    monkeypatch.setenv('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',secret)
    result=subprocess.CompletedProcess(['synthetic-helper'],73,'FIRST-CONTEXT '+('x'*100000),'ValueError: last cause '+secret)
    monkeypatch.setattr(subprocess,'run',lambda *a,**kw:result)
    with pytest.raises(RuntimeError) as failure:
        update.fixed_helper.__wrapped__(tmp_path/'update-control','inspect')
    details=update._failure_details(failure.value)
    assert details[0]['exit_code']==73
    assert 'last cause' in details[0]['stderr']
    assert secret not in str(details)
    report=bootstrap._run_command(['synthetic-helper'],10)
    assert report['stdout_tail'].startswith('FIRST-CONTEXT')
    assert 'last cause' in report['stderr_tail']
    assert secret not in str(report)

@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
def test_large_child_is_redacted_before_cap_and_last_exception_survives(tmp_path,engine):
    result=run_functions(tmp_path,ROOT/'tools/bootstrap_integrity.ps1',FUNCTIONS,r'''
function Set-InstallationEvidenceAcl {param($Path,$Sid)}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'capture') ''
$path=Join-Path $env:CA_CONTRACT_ROOT 'output.ps1'
$code='[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::Out.Write("FIRST-CONTEXT"+(''x''*2097152)+"`nValueError: last cause "+[Environment]::GetEnvironmentVariable(''CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN''));exit 73'
[IO.File]::WriteAllText($path,$code,[Text.UTF8Encoding]::new($true))
$child=Invoke-InstallationEvidenceChild 'bounded-child' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile','-NonInteractive','-File',$path)
if($child.ExitCode -ne 73 -or -not $child.Stdout.StartsWith('FIRST-CONTEXT') -or -not $child.Stdout.Contains('ValueError: last cause') -or [Text.Encoding]::UTF8.GetByteCount($child.Stdout) -gt 65536){throw 'Redacted child first/last context or byte budget differs.'}
$secret=[Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN')
foreach($file in @(Get-ChildItem -LiteralPath $root -File)){if([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName)).Contains($secret)){throw 'Child secret bytes survived a sink.'}}
$ui=ConvertTo-KmtechRedactedSinkText $child.Stdout -UserLine
if($ui.Length -gt 300 -or -not $ui.StartsWith('ValueError: last cause') -or $ui.Contains($secret)){throw 'Last exception user guidance differs.'}
'PASS'
''',engine=engine,values={'CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN':'synthetic-child-authority-273'})
    assert result.returncode==0,result.stderr
