"""Exercise real failure sinks with synthetic secrets and bounded JSON."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions
from tests.test_installation_stage_evidence import FUNCTIONS
from tests.test_official_legacy_relay_identity import XML_SETUP
ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
def test_escaped_first_failure_and_rotated_journal_remain_valid_and_bounded(tmp_path, engine):
    result=run_functions(tmp_path,ROOT/'tools/bootstrap_integrity.ps1',[*FUNCTIONS,'Complete-InstallationEvidence', "Invoke-ContainerAtomicReplaceOnce", "Invoke-ContainerAtomicReplace"],r'''
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
$writer=[pscustomobject]@{mechanism='scheduled_task';task_path='\';task_name=$name;xml=$xml;observed_enabled=$true}
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
    # No existing reader ACL is proven for update-control diagnostics.
    assert refs == []
    assert not list(tmp_path.glob('failure-text-*.json'))

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


from pathlib import Path
import importlib
import json
import hashlib
import pytest


def _owned_snapshot(root):
    return {str(path.relative_to(root)): None if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob('*')}


@pytest.mark.parametrize('module_name,function_name', (
    ('direct_sync_auto_bootstrap', '_write_json'),
    ('current_user_onboarding', '_write_json_atomic'),
    ('current_user_onboarding', '_write_json_atomic_create_new'),
))
def test_related_report_sink_redacts_before_temporary_file(tmp_path, monkeypatch, module_name, function_name):
    module = importlib.import_module(module_name)
    secret = 'synthetic-final-report-sink-273'
    monkeypatch.setenv('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN', secret)
    destination = tmp_path / 'failure-report.json'
    publish_name = 'link' if function_name.endswith('create_new') else 'replace'
    publish = getattr(module.os, publish_name)
    observed = []
    def checked_publish(source, target):
        raw = Path(source).read_bytes()
        observed.append(raw)
        assert secret.encode() not in raw, 'Known authority bytes reached temporary report sink'
        return publish(source, target)
    monkeypatch.setattr(module.os, publish_name, checked_publish)
    payload = {
        'status': 'FAILED', 'failure': 'first cause ' + secret,
        'credential': {'opaque': 'synthetic-unknown-field-secret'},
        'token_elevated': False, 'writer_contract_sha256': 'a' * 64,
    }
    if module_name == 'current_user_onboarding':
        # Contract 1a: these generic writers publish authentication metadata.
        # Diagnostic redaction belongs to _persist_failure_report instead.
        before = _owned_snapshot(tmp_path)
        with pytest.raises(ValueError, match='^MACHINE_METADATA_SECRET_DETECTED$'):
            getattr(module, function_name).__wrapped__(destination, payload)
        if observed or _owned_snapshot(tmp_path) != before:
            pytest.fail('Rejected machine metadata reached a temporary file', pytrace=False)
        return
    getattr(module, function_name).__wrapped__(destination, payload)
    assert observed and secret.encode() not in destination.read_bytes()
    original_credential = payload['credential']
    payload = json.loads(destination.read_bytes())
    # Contract 1a preserves authenticated containers; only diagnostics change.
    assert payload['credential'] == original_credential
    assert payload['token_elevated'] is False
    assert payload['writer_contract_sha256'] == 'a' * 64

@pytest.mark.parametrize('field_name', ('authorization', 'registration_value', 'registration_code'))
def test_existing_json_credential_protection_is_retained(field_name):
    import auto_update
    value = {'status': 'FAILED', field_name: 'synthetic-outside-env-secret'}
    assert auto_update.redact_json_for_sink(value)[field_name] == '[REDACTED:field]'

@pytest.mark.parametrize('module_name,function_name', (
    ('direct_sync_auto_bootstrap', '_write_json'),
    ('current_user_onboarding', '_write_json_atomic'),
    ('current_user_onboarding', '_write_json_atomic_create_new'),
))
def test_related_report_sink_bounds_valid_json_after_redaction(tmp_path, monkeypatch, module_name, function_name):
    module = importlib.import_module(module_name)
    secret = 'synthetic-utf8-report-secret-273'
    monkeypatch.setenv('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN', secret)
    path = tmp_path / 'failure-report.json'
    payload = {
        'status': 'FAILED', 'failure': 'FIRST ' + ('가"' * 50000) + secret + ' ValueError: LAST',
    }
    if module_name == 'current_user_onboarding':
        # Contract 1a keeps admitted metadata bytes, including >64 KiB, exact.
        before = _owned_snapshot(tmp_path)
        with pytest.raises(ValueError, match='^MACHINE_METADATA_SECRET_DETECTED$'):
            getattr(module, function_name).__wrapped__(path, payload)
        if _owned_snapshot(tmp_path) != before:
            pytest.fail('Rejected large machine metadata reached a file', pytrace=False)
        payload['failure'] = payload['failure'].replace(secret, '')
        getattr(module, function_name).__wrapped__(path, payload)
        expected = (json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
        if len(expected) <= 65536 or path.read_bytes() != expected:
            pytest.fail('Machine metadata byte preservation differs', pytrace=False)
        return
    getattr(module, function_name).__wrapped__(path, payload)
    raw = path.read_bytes()
    assert len(raw) <= 65536 and secret.encode() not in raw
    payload = json.loads(raw)
    assert payload['failure'] == 'SUPPORT_FAILURE'


def test_onboarding_failure_report_retains_full_stream_refs_and_temporary_bytes_are_safe(tmp_path, monkeypatch):
    import auto_update as update
    import current_user_onboarding as onboarding
    import hashlib
    import json
    secret = 'synthetic-onboarding-child-273'
    monkeypatch.setenv('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN', secret)
    monkeypatch.setattr(onboarding, '_write_json_atomic', onboarding._write_json_atomic.__wrapped__)
    monkeypatch.setattr(update, 'write_json_durable', update.write_json_durable.__wrapped__)
    error = OSError('fixed child failure')
    error.stderr = 'FIRST CHILD CONTEXT ' + ('x' * 100000) + secret + ' ValueError: LAST CHILD CAUSE'
    error.exit_code = 73
    report = {'status': 'FAILED'}
    path = tmp_path / 'onboarding.json'
    onboarding._persist_failure_report(path, report, error)
    body = json.loads(path.read_bytes())
    assert body['failure_evidence_status'] == 'REPORT_UNAVAILABLE'
    assert body['failure_evidence_refs'] == []
    assert body['failure_details'][0]['stderr'] == 'SUPPORT_FAILURE'
    assert body['failure_details'][0]['exit_code'] == 73
    assert list(tmp_path.glob('*.json')) == [path]
    for saved in tmp_path.glob('*.json'):
        raw = saved.read_bytes()
        assert len(raw) <= 65536 and secret.encode() not in raw


def test_onboarding_machine_metadata_preserves_private_comparison_fields(tmp_path):
    import current_user_onboarding as onboarding
    import json
    original = {'status': 'READY', 'owner_artifact_paths': {'credential': 'isolated/credential.json'},
                'owner_artifact_fingerprints_before': {'credential': 'b' * 64}}
    path = tmp_path / 'metadata.json'
    onboarding._write_json_atomic.__wrapped__(path, original)
    body = json.loads(path.read_bytes())
    # Contract 1a forbids renaming authentication metadata during serialization.
    assert body == original
    assert original['owner_artifact_paths'] == {'credential': 'isolated/credential.json'}
    assert original['owner_artifact_fingerprints_before'] == {'credential': 'b' * 64}


def test_onboarding_user_error_keeps_full_redacted_cause_and_last_line_only(monkeypatch):
    import current_user_onboarding as onboarding
    secret = 'synthetic-onboarding-ui-273'
    monkeypatch.setenv('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN', secret)
    failure = onboarding.CurrentUserOnboardingError('FIRST\n' + ('x' * 100000) + '\nValueError: LAST ' + secret,
                                                   report_path=Path('isolated/failure.json'))
    assert len(str(failure)) <= 300 and str(failure).startswith('ValueError: LAST')
    assert secret not in str(failure) and secret not in failure.original_failure_text
    assert failure.original_failure_text.startswith('FIRST')
    assert '[TRUNCATED:' in failure.original_failure_text


def test_report_create_new_preserves_existing_preimage(tmp_path):
    import current_user_onboarding as onboarding
    path = tmp_path / 'existing.json'
    original = b'{"status":"ORIGINAL"}'
    path.write_bytes(original)
    with pytest.raises(FileExistsError):
        onboarding._write_json_atomic_create_new.__wrapped__(path, {'status': 'FAILED'})
    assert path.read_bytes() == original
    assert not list(tmp_path.glob('*.tmp'))
