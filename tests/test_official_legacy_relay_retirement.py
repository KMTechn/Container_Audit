"""Official relay discovery and retirement evidence, using isolated scheduler seams."""
import pytest
from tests.powershell_contracts import run_functions
from tests.test_official_legacy_relay_identity import CANONICAL, XML_SETUP


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('count', (0, 1, 2))
def test_writer_discovery_returns_flat_objects_and_rejects_ambiguous_names(tmp_path, engine, count):
    result = run_functions(tmp_path, CANONICAL, ['Get-CanonicalOfficialLegacyRelayWriters'], XML_SETUP + r'''
function Get-ScheduledTask {
    param($ErrorAction)
    foreach($i in 1..([int]$env:CA_TASK_COUNT)){
        if([int]$env:CA_TASK_COUNT -gt 0){$task}
    }
}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return $xml}
$rejected=$false
try{$writers=@(Get-CanonicalOfficialLegacyRelayWriters)}catch{$rejected=$_.Exception.Message -ceq 'OFFICIAL_LEGACY_NAME_CARDINALITY_UNKNOWN'}
if([int]$env:CA_TASK_COUNT -gt 1){if(-not $rejected){throw 'Ambiguous official writers admitted.'}}
else{
 if($rejected -or $writers.Count -ne [int]$env:CA_TASK_COUNT){throw 'Discovery count differs.'}
 if($writers.Count -and ($writers[0] -is [array] -or $writers[0].observed_enabled -isnot [bool])){throw 'Scheduler object was nested or its bool was lost.'}
}
'PASS'
''', engine=engine, values={'CA_TASK_COUNT': str(count)})
    assert result.returncode == 0, result.stderr


POINTER_SETUP = r'''
$root=$env:CA_CONTRACT_ROOT
$install=Join-Path $root 'current'
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$onboardingPath=Join-Path $root 'current_user_onboarding.json'
function Sha {param($Path);return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Get-ContainerWriterFenceFileSha256 {param($Path,$MaxBytes);if((Get-Item -LiteralPath $Path).Length -gt $MaxBytes){throw 'Fixture size differs.'};return (Sha $Path)}
function Same {param($Left,$Right);return [IO.Path]::GetFullPath($Left).Equals([IO.Path]::GetFullPath($Right),[StringComparison]::OrdinalIgnoreCase)}
function Assert-InstallationEvidenceProtectedPath {param($Path);Assert-BootstrapNoReparsePoint $Path 'isolated evidence' -PathOnly}
function Assert-InstallationEvidenceWriteRoot {param($Root)}
function Set-InstallationEvidenceAcl {param($Path,$Sid)}
function Write-InstallationCaughtFailure {param($Failure)}
function Get-InstallationFailureDetails {param($Failure);return @{type=$Failure.Exception.GetType().Name;message=$Failure.Exception.Message}}
foreach($pointerFunctionName in @('Read-CanonicalOfficialLegacyRelayTransitionBinding','Save-CanonicalOfficialLegacyRelayTransitionPointer','Read-CanonicalOfficialLegacyRelayTransitionPointer')){
 $f=@($definition_nodes|Where-Object {$_.Name -ceq $pointerFunctionName});if($f.Count -eq 1){Invoke-Expression $f[0].Extent.Text}
}
'''


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('fault', ('none', 'pointer_sha', 'pointer_path', 'preimage', 'enabled', 'absent'))
def test_separate_install_and_retirement_runs_use_durable_pointer(tmp_path, engine, fault):
    # Two native processes share only the existing installation report and its
    # explicitly pinned evidence; the retirement process gets a new evidence root.
    install = run_functions(tmp_path, CANONICAL, [
        'Save-CanonicalOfficialLegacyRelayPreimage', 'Get-CanonicalOfficialLegacyRelayState',
        'Get-CanonicalOfficialLegacyRelayExpectedSet', 'Invoke-CanonicalOfficialLegacyRelayTransition',
    ], XML_SETUP + POINTER_SETUP + r'''
$installationEvidenceRoot=Join-Path $root 'install.evidence.1'
[void][IO.Directory]::CreateDirectory($installationEvidenceRoot)
[IO.File]::WriteAllText($onboardingPath,'{"status":"READY","state_scope":"current_user"}')
$script:enabled=$true
function Get-CanonicalOfficialLegacyRelayPreimage {
 return [pscustomobject]@{xml=$xml;identity=(Get-BootstrapOfficialLegacyRelayIdentity $task $xml);enabled=$true;task_name=$name;task_path='\';old_code_root='';files=@()}
}
function Disable-CanonicalOfficialLegacyRelay {param($Before);$script:enabled=$false}
function Get-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return [pscustomobject]@{Settings=[pscustomobject]@{Enabled=$script:enabled}}}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return $xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')}
$writer=[pscustomobject]@{mechanism='scheduled_task';task_path='\';task_name=$name;xml=$xml;observed_enabled=$true;transition_record=$null}
$result=Invoke-CanonicalOfficialLegacyRelayTransition @($writer) (Get-CanonicalOfficialLegacyRelayExpectedSet) install $true
if($result.audit[0].status -cne 'PROVEN' -or $result.state[0].enabled){throw ('Installation transition failed: '+[string]$result.audit[0].failure.message)}
'PASS'
''', engine=engine)
    assert install.returncode == 0, install.stderr
    retire = run_functions(tmp_path, CANONICAL, [
        'Get-CanonicalOfficialLegacyRelayWriters', 'Get-CanonicalOfficialLegacyRelayState',
        'Get-CanonicalOfficialLegacyRelayExpectedSet', 'Assert-CanonicalRetiredLegacyWriterAdmission',
    ], XML_SETUP + POINTER_SETUP + r'''
$installationEvidenceRoot=Join-Path $root 'retire.evidence.2'
[void][IO.Directory]::CreateDirectory($installationEvidenceRoot)
$report=Get-Content -LiteralPath $onboardingPath -Raw|ConvertFrom-Json
$pointer=$report.official_legacy_relay_transition
switch($env:CA_POINTER_FAULT){
 'pointer_sha' {$pointer.sha256='0'*64}
 'pointer_path' {$pointer.path=Join-Path $root 'other.json'}
 'preimage' {[IO.File]::AppendAllText($pointer.path,' ')}
 'absent' {$report.PSObject.Properties.Remove('official_legacy_relay_transition')}
}
if($env:CA_POINTER_FAULT -cin @('pointer_sha','pointer_path','absent')){[IO.File]::WriteAllText($onboardingPath,($report|ConvertTo-Json -Depth 10))}
$script:liveEnabled=$env:CA_POINTER_FAULT -ceq 'enabled'
function Get-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return [pscustomobject]@{TaskName=$name;TaskPath='\';Settings=[pscustomobject]@{Enabled=$script:liveEnabled}}}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);if($script:liveEnabled){return $xml};return $xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')}
$snapshot=@{present=$false;noncanonical_disabled=@(@{task_path='\';task_name=$name;enabled=$false})}
$rejected=$false;$rejectionCode=''
try{$proofs=@(Assert-CanonicalRetiredLegacyWriterAdmission $snapshot $installationEvidenceRoot)}catch{$rejected=$true;$rejectionCode=[string]$_.Exception.InnerException.Message}
if($env:CA_POINTER_FAULT -ceq 'none'){
 if($rejected -or $proofs.Count -ne 1){throw ('Separate retirement run could not resolve installation evidence: '+$rejectionCode)}
 if([string]$proofs[0].transition_record.path -notlike '*install.evidence.1*'){throw 'Admission substituted the fresh evidence root.'}
}elseif(-not $rejected){throw 'Changed/missing pointer, preimage or enabled writer was admitted.'}
'PASS'
''', engine=engine, values={'CA_POINTER_FAULT': fault})
    assert retire.returncode == 0, retire.stderr
