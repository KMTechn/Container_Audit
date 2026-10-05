"""Official source identities and recovery, with isolated scheduler/CIM seams."""
import json
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'

XML_SETUP = r'''
$name='direct-sync-relay-container-audit'
$task=[pscustomobject]@{TaskName=$name;TaskPath='\';Settings=[pscustomobject]@{Enabled=$true}}
$exe=[Security.SecurityElement]::Escape((Join-Path ([Environment]::SystemDirectory) 'wscript.exe'))
$path=[Security.SecurityElement]::Escape((Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'KMTech\DirectSync\container_audit\bin\direct-sync-relay-container-audit.vbs'))
$sid=@('S','1','5','18') -join '-'
$xml='<Task version="1.2"><RegistrationInfo><Author>AUTHOR_PLACEHOLDER</Author><Date>2020-01-01</Date></RegistrationInfo><Triggers><TimeTrigger><StartBoundary>2020-01-01T00:00:00</StartBoundary><Repetition><Interval>PT1M</Interval><Duration>PT24H</Duration></Repetition></TimeTrigger></Triggers><Principals><Principal><UserId>'+$sid+'</UserId><LogonType>ServiceAccount</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings><Actions><Exec><Command>'+$exe+'</Command><Arguments>//B //NoLogo '+$path+'</Arguments></Exec></Actions></Task>'
'''


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_every_identity_field_is_closed_and_record_only_fields_are_not_identity(tmp_path, engine):
    result = run_functions(tmp_path, CANONICAL, ['Get-CanonicalOfficialLegacyRelayExpectedSet'], XML_SETUP + r'''
$expected=Get-CanonicalOfficialLegacyRelayExpectedSet
$identity=Get-BootstrapOfficialLegacyRelayIdentity $task $xml $expected
if(-not $identity.matched -or $identity.fields.Count -ne 13){throw 'Official SYSTEM identity did not match.'}
if($identity|ConvertTo-Json -Depth 8|Select-String -SimpleMatch 'AUTHOR_PLACEHOLDER'){throw 'Record-only raw author leaked.'}
$variants=@($xml.Replace('PT1M','PT2M'),$xml.Replace('LeastPrivilege','HighestAvailable'),$xml.Replace('ServiceAccount','InteractiveToken'),$xml.Replace('TimeTrigger','LogonTrigger'),$xml.Replace('//B','//b'),$xml.Replace('wscript.exe','cscript.exe'),$xml.Replace('container_audit\bin','other\bin'),$xml.Replace('</Exec>','<WorkingDirectory>C:\Other</WorkingDirectory></Exec>'),$xml.Replace('</Actions>','<Exec><Command>cmd.exe</Command></Exec></Actions>'))
foreach($variant in $variants){if((Get-BootstrapOfficialLegacyRelayIdentity $task $variant $expected).matched){throw 'Changed identity field admitted.'}}
$otherTask=[pscustomobject]@{TaskName=$name;TaskPath='\Other\'}
if((Get-BootstrapOfficialLegacyRelayIdentity $otherTask $xml $expected).matched){throw 'Changed task path admitted.'}
$otherTask=[pscustomobject]@{TaskName='other-task';TaskPath='\'}
if((Get-BootstrapOfficialLegacyRelayIdentity $otherTask $xml $expected).matched){throw 'Changed name admitted.'}
$recordVariant=$xml.Replace('AUTHOR_PLACEHOLDER','OTHER_AUTHOR_PLACEHOLDER').Replace('2020-01-01','2024-02-02').Replace('PT24H','P3650D').Replace('<Hidden>true</Hidden>','<Hidden>false</Hidden>').Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')
if(-not(Get-BootstrapOfficialLegacyRelayIdentity $task $recordVariant $expected).matched){throw 'OS-filled record incorrectly became identity.'}
if(-not(Get-BootstrapOfficialLegacyRelayIdentity $task ($xml.Replace('PT1M','PT60S')) $expected).matched){throw 'Equivalent ISO duration normalization differs.'}
if(@($expected|Where-Object {$_.branch -cin @('stored_password_current_user','interactive_current_user') -and -not $_.allowed}).Count){throw 'Coordinator candidate credential admission was not enabled.'}
if(@($expected|Where-Object {$_.allowed -and $_.branch -cnotin @('system_vbs','stored_password_current_user','interactive_current_user')}).Count){throw 'Unpublished identity opened.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_xml_logon_absence_is_distinct_from_unknown_and_same_user_credential_modes(tmp_path, engine):
    result = run_functions(tmp_path, CANONICAL, ['Get-CanonicalOfficialLegacyRelayExpectedSet'], XML_SETUP + r'''
$expected=Get-CanonicalOfficialLegacyRelayExpectedSet
$absent=$xml.Replace('<LogonType>ServiceAccount</LogonType>','')
$explicit=Get-BootstrapOfficialLegacyRelayIdentity $task $xml $expected
foreach($variant in @($absent,$xml.Replace('<RunLevel>LeastPrivilege</RunLevel>',''),$absent.Replace('<RunLevel>LeastPrivilege</RunLevel>',''))){
 $missing=Get-BootstrapOfficialLegacyRelayIdentity $task $variant $expected
 if(-not $missing.matched -or $missing.sha256 -cne $explicit.sha256){throw 'Guest-proven SYSTEM omitted/explicit defaults have different identities.'}
}
foreach($value in @('UNRECOGNIZED','ABSENT','')){
 $unknown=Get-BootstrapOfficialLegacyRelayIdentity $task ($xml.Replace('ServiceAccount',$value)) $expected
 if($unknown.matched -or $unknown.reason_code -cne 'LOGON_TYPE_UNKNOWN'){throw 'Unknown XML value was guessed or conflated.'}
}
# The real SID stays only in this RAM XML and is never copied to a fixture.
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach($mode in @('Password','InteractiveToken')){
 $currentXml=$xml.Replace($sid,$current).Replace('ServiceAccount',$mode)
 if(-not(Get-BootstrapOfficialLegacyRelayIdentity $task $currentXml $expected).matched){throw 'Exact same-user official credential mode rejected.'}
 $currentIdentity=Get-BootstrapOfficialLegacyRelayIdentity $task $currentXml $expected
 $omittedLevel=Get-BootstrapOfficialLegacyRelayIdentity $task ($currentXml.Replace('<RunLevel>LeastPrivilege</RunLevel>','')) $expected
 if(-not $omittedLevel.matched -or $omittedLevel.sha256 -cne $currentIdentity.sha256){throw 'Guest-proven user omitted/explicit RunLevel differs.'}
 $absentUser=Get-BootstrapOfficialLegacyRelayIdentity $task ($currentXml.Replace('<LogonType>'+$mode+'</LogonType>','')) $expected
 if($absentUser.matched -or $absentUser.reason_code -cne 'LOGON_TYPE_ABSENT_UNMATCHED'){throw 'User LogonType absence was guessed or conflated.'}
 if((Get-BootstrapOfficialLegacyRelayIdentity $task ($xml.Replace('ServiceAccount',$mode)) $expected).matched){throw 'Credential principal of another user was admitted.'}
}
foreach($value in @('UNRECOGNIZED','Limited','Highest','')){
 $unknown=Get-BootstrapOfficialLegacyRelayIdentity $task ($xml.Replace('LeastPrivilege',$value)) $expected
 if($unknown.matched -or $unknown.reason_code -cne 'RUN_LEVEL_UNKNOWN'){throw 'Unknown XML RunLevel was admitted.'}
}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('generation_allowed', (True, False))
def test_task_preimage_restore_is_independent_of_current_and_respects_g(tmp_path, engine, generation_allowed):
    result = run_functions(tmp_path, CANONICAL, ['Save-CanonicalOfficialLegacyRelayPreimage','Restore-CanonicalOfficialLegacyRelay'], XML_SETUP + r'''
$root=$env:CA_CONTRACT_ROOT;$operatorSid='';$lad='unused';$activeDataRoot='unused';$source='unused';$install=Join-Path $root 'current-absent'
function Assert-InstallationEvidenceWriteRoot {param($Path)}
function Assert-InstallationEvidenceProtectedPath {param($Path)}
function Set-InstallationEvidenceAcl {param($Path,$Sid)}
function Sha {param($Path);return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function ShaText {param($Text);$a=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($a.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant())}finally{$a.Dispose()}}
function Write-InstallationCaughtFailure {param($Failure)}
function Assert-ContainerDataGenerationTarget {param($CandidateRoot,$TargetSid,$LocalAppDataRoot,$DataRoot,$HelperRoot);if($env:CA_GENERATION_ALLOWED -cne '1'){throw 'GENERATION_GATE_REJECTED'}}
function Relays {return @()}
function Invoke-ContainerWriterFenceMutation {param($SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken,$AuthorityLease,$Action);& $Action}
$script:enabled=$true;$script:enableCalls=0
$Script:CanonicalWriterFenceSessionId='fixture';$Script:CanonicalWriterFenceAttemptId='fixture';$Script:CanonicalWriterFenceTransactionId='fixture';$Script:CanonicalWriterFenceDelegationToken='';$canonicalWriterFenceAuthority=$null
function Enable-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);$script:enabled=$true;$script:enableCalls++}
function Disable-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);$script:enabled=$false}
function Get-CanonicalOfficialLegacyRelayPreimage {
    $liveXml=if($script:enabled){$xml}else{$xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')}
    return [pscustomobject]@{xml=$liveXml;xml_sha256=(ShaText $liveXml);identity=(Get-BootstrapOfficialLegacyRelayIdentity $task $liveXml);enabled=$script:enabled;task_name=$name;task_path='\';old_code_root=(Join-Path $root 'old-code');files=@()}
}
$before=Get-CanonicalOfficialLegacyRelayPreimage
$binding=Save-CanonicalOfficialLegacyRelayPreimage $before $root
$script:enabled=$false
if(Test-Path -LiteralPath $install){throw 'Fixture current unexpectedly exists.'}
$failed=$false;try{$restored=Restore-CanonicalOfficialLegacyRelay $binding}catch{$failed=$true}
if($env:CA_GENERATION_ALLOWED -ceq '1'){
 if($failed -or -not $script:enabled -or $script:enableCalls -ne 1){throw 'Independent exact preimage restore was not attempted.'}
}else{if(-not $failed -or $script:enabled -or $script:enableCalls){throw 'G denial reactivated legacy writer.'}}
'PASS'
''', engine=engine, values={'CA_GENERATION_ALLOWED': '1' if generation_allowed else '0'})
    assert result.returncode == 0, result.stderr


def test_product_expected_set_has_only_official_public_source_templates():
    # Committed fixtures are source metadata, with no host account or raw XML.
    fixture = json.loads((ROOT/'tests/fixtures/official_legacy_relay_source_templates.json').read_text())
    assert not any(entry['branch'] == 'system_cmd' for entry in fixture['entries'])
    assert fixture['hkcu_run_public_writers'] == []
    text=(ROOT/'tools/bootstrap_integrity.ps1').read_text(encoding='utf-8-sig')
    catalog=text.split("$entries=@((@'\n",1)[1].split("\n'@",1)[0]
    assert json.loads(catalog) == fixture['entries']

@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
def test_shared_transition_reports_post_mutation_state_and_g_denial(tmp_path,engine):
    result=run_functions(tmp_path,CANONICAL,['Get-CanonicalOfficialLegacyRelayState','Get-CanonicalOfficialLegacyRelayExpectedSet','Invoke-CanonicalOfficialLegacyRelayTransition'],XML_SETUP+r'''
$installationEvidenceRoot=$env:CA_CONTRACT_ROOT;$script:enabled=$true
$writer=[pscustomobject]@{mechanism='scheduled_task';task_path='\';task_name=$name;xml=$xml;observed_enabled=$true;transition_record=$null}
function Get-CanonicalOfficialLegacyRelayPreimage {return @{identity='fixture'}}
function Save-CanonicalOfficialLegacyRelayPreimage {param($Before,$Root);return @{path=(Join-Path $Root 'fixture');sha256=('a'*64)}}
function Disable-CanonicalOfficialLegacyRelay {param($Before);$script:enabled=$false}
function Restore-CanonicalOfficialLegacyRelay {param($Binding);$script:enabled=$true}
function Assert-InstallationEvidenceProtectedPath {param($Path)}
function Sha {param($Path);return ('a'*64)}
function Write-InstallationCaughtFailure {param($Failure)}
function Get-InstallationFailureDetails {param($Failure);return @{type='fixture'}}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);if($script:enabled){return $xml};return $xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')}
function Get-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return [pscustomobject]@{Settings=[pscustomobject]@{Enabled=$script:enabled}}}
$set=Get-CanonicalOfficialLegacyRelayExpectedSet
$result=Invoke-CanonicalOfficialLegacyRelayTransition @($writer) $set install $true
if($result.audit[0].status -cne 'PROVEN' -or $result.state[0].enabled -or $null -eq $result.state[0].transition_record){throw 'Post-install state was stale.'}
$result=Invoke-CanonicalOfficialLegacyRelayTransition @($writer) $set rollback $false
if($result.audit[0].status -cne 'FAILED' -or $result.state[0].enabled){throw 'G denial state differs.'}
$result=Invoke-CanonicalOfficialLegacyRelayTransition @($writer) $set rollback $true
if($result.audit[0].status -cne 'PROVEN' -or -not $result.state[0].enabled){throw 'Post-rollback state differs.'}
'PASS'
''',engine=engine)
    assert result.returncode==0,result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_guest_export_and_explicit_defaults_match_measured_fingerprint(tmp_path, engine):
    fixture = ROOT / 'tests/fixtures/official_legacy_relay_guest_v2_0_33.xml'
    provenance = json.loads(fixture.with_suffix('.provenance.json').read_bytes())
    import hashlib
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == provenance['fixture_sha256']
    assert provenance['kind'] == 'guest_export_with_record_only_placeholders'
    result = run_functions(tmp_path, CANONICAL, ['Get-CanonicalOfficialLegacyRelayExpectedSet', 'Get-CanonicalOfficialLegacyRelayState'], r"""
$xml=[IO.File]::ReadAllText($env:CA_GUEST_FIXTURE)
[xml]$doc=$xml
$principal=$doc.SelectSingleNode("//*[local-name()='Principal']")
if($null -eq $principal -or $null -ne $principal.SelectSingleNode("*[local-name()='RunLevel' or local-name()='LogonType']")){throw 'Guest fixture default omissions were changed.'}
$task=[pscustomobject]@{TaskName='direct-sync-relay-container-audit';TaskPath='\'}
$expected=Get-CanonicalOfficialLegacyRelayExpectedSet
$identity=Get-BootstrapOfficialLegacyRelayIdentity $task $xml $expected
if(-not $identity.matched -or $identity.fields.Count -ne 13 -or $identity.sha256 -cne $env:CA_GUEST_FINGERPRINT){throw 'Guest XML differs from measured normalized expected set.'}
foreach($name in @('RunLevel','LogonType')){
 $node=$doc.CreateElement($name,$principal.NamespaceURI)
 $node.InnerText=if($name -ceq 'RunLevel'){'LeastPrivilege'}else{'ServiceAccount'}
 [void]$principal.AppendChild($node)
}
$explicit=Get-BootstrapOfficialLegacyRelayIdentity $task $doc.OuterXml $expected
if(-not $explicit.matched -or $explicit.sha256 -cne $identity.sha256){throw 'Guest omitted and explicit XML defaults differ.'}
$writer=[pscustomobject]@{mechanism='scheduled_task';task_path='\';task_name=$task.TaskName;xml=$xml;observed_enabled=$true;transition_record=$null}
$state=Get-CanonicalOfficialLegacyRelayState $writer $expected $env:CA_CONTRACT_ROOT
if(-not $state.recognized -or $state.full_fingerprint -cne $identity.sha256){throw 'Shared guest state interface differs.'}
if(-not $state.enabled){throw 'Observed guest enabled state lost.'}
$writer.observed_enabled=$false
$disabled=Get-CanonicalOfficialLegacyRelayState $writer $expected $env:CA_CONTRACT_ROOT
if(-not $disabled.recognized -or $disabled.enabled){throw 'Observed disabled state was guessed.'}
$writer.observed_enabled=$null
$unknown=Get-CanonicalOfficialLegacyRelayState $writer $expected $env:CA_CONTRACT_ROOT
if($unknown.recognized -or $unknown.reason_code -cne 'TASK_ENABLED_STATE_UNKNOWN'){throw 'Unobserved XML enabled default was guessed.'}
$writer.observed_enabled=$false
$writer.xml=$doc.OuterXml.Replace('</Settings>','<Enabled>true</Enabled></Settings>')
$changed=Get-CanonicalOfficialLegacyRelayState $writer $expected $env:CA_CONTRACT_ROOT
if($changed.recognized -or $changed.reason_code -cne 'TASK_ENABLED_OBSERVATION_DIFFERS'){throw 'Contradicting scheduler and XML states admitted.'}
$writer.observed_enabled=$null
$unknown=Get-CanonicalOfficialLegacyRelayState $writer $expected $env:CA_CONTRACT_ROOT
if($unknown.recognized -or $unknown.reason_code -cne 'TASK_ENABLED_STATE_UNKNOWN'){throw 'Explicit XML allowed an unobserved scheduler state.'}


'PASS'
""", engine=engine, values={'CA_GUEST_FIXTURE': str(fixture), 'CA_GUEST_FINGERPRINT': provenance['expected_full_fingerprint']})
    assert result.returncode == 0, result.stderr
