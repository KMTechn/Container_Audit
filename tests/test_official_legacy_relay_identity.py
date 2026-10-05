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
if(@($expected|Where-Object {$_.allowed -and $_.branch -ne 'system_vbs'}).Count){throw 'Unproven credential branch or unpublished identity opened.'}
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
$writer=[pscustomobject]@{mechanism='scheduled_task';task_path='\';task_name=$name;xml=$xml;transition_record=$null}
function Get-CanonicalOfficialLegacyRelayPreimage {return @{identity='fixture'}}
function Save-CanonicalOfficialLegacyRelayPreimage {param($Before,$Root);return @{path=(Join-Path $Root 'fixture');sha256=('a'*64)}}
function Disable-CanonicalOfficialLegacyRelay {param($Before);$script:enabled=$false}
function Restore-CanonicalOfficialLegacyRelay {param($Binding);$script:enabled=$true}
function Assert-InstallationEvidenceProtectedPath {param($Path)}
function Sha {param($Path);return ('a'*64)}
function Write-InstallationCaughtFailure {param($Failure)}
function Get-InstallationFailureDetails {param($Failure);return @{type='fixture'}}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);if($script:enabled){return $xml};return $xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')}
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
