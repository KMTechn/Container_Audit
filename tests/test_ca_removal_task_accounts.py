"""Read-only task XML identity admission on uninstall and machine recovery."""
from pathlib import Path

import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("case", ("sid", "account", "foreign_trigger", "foreign_principal", "unresolved"))
def test_removal_task_identity_forms(tmp_path, engine, case):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1", [
        "Resolve-ContainerRemovalTaskSid", "Get-ContainerRemovalTaskNames",
    ], r'''
Set-StrictMode -Version Latest
function Test-SamePath($a,$b){return $a -ieq $b}
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User.Value
$bytes=[Text.Encoding]::UTF8.GetBytes($root.ToLowerInvariant().Replace('/','\')+"`n"+$sid)
$hash=[Security.Cryptography.SHA256]::Create()
try{$suffix=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant().Substring(0,24)}finally{$hash.Dispose()}
$name='KMTech.ContainerAudit.StartupUpdate.'+$suffix
$trigger=$sid;$principal='S-1-5-18'
switch($env:CA_ACCOUNT_CASE){
 'account' {$trigger=$identity.Name;$principal=([Security.Principal.SecurityIdentifier]::new('S-1-5-18')).Translate([Security.Principal.NTAccount]).Value}
 'foreign_trigger' {$trigger='S-1-5-18'}
 'foreign_principal' {$principal=$sid}
 'unresolved' {$trigger='S-1-invalid'}
}
$command=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $root 'tools\apply_prepared_update.ps1')+'" -InstallRoot "'+$root+'"'
$xml='<Task><Triggers><LogonTrigger><UserId>'+[Security.SecurityElement]::Escape($trigger)+'</UserId></LogonTrigger></Triggers><Principals><Principal><UserId>'+[Security.SecurityElement]::Escape($principal)+'</UserId></Principal></Principals><Actions><Exec><Command>'+[Security.SecurityElement]::Escape($command)+'</Command><Arguments>'+[Security.SecurityElement]::Escape($arguments)+'</Arguments></Exec></Actions></Task>'
$folder=[pscustomobject]@{task=[pscustomobject]@{Name=$name;Xml=$xml}}
$folder|Add-Member ScriptMethod GetTasks {param($flags) return @($this.task)}
$refused=$false;$selected=@()
try{$selected=@(Get-ContainerRemovalTaskNames $folder $root)}catch{
 if($_.Exception.Message -cne 'REMOVAL_TASK_IDENTITY_UNKNOWN'){throw};$refused=$true
}
if($env:CA_ACCOUNT_CASE -in @('foreign_principal','unresolved')){
 if(-not $refused){throw 'refusal missing'}
}elseif($env:CA_ACCOUNT_CASE -eq 'foreign_trigger'){
 if($refused -or $name -cin $selected){throw 'foreign task selected'}
}elseif($refused -or $name -cnotin $selected){throw 'own task not selected'}
'PASS'
''', engine=engine, values={"CA_ACCOUNT_CASE": case})
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"


def test_machine_recovery_new_code_removal_uses_shared_task_identity_guard(tmp_path):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", [], r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$tokens,[ref]$errors)
$functions=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)
$recovery=($functions|Where-Object Name -eq 'Invoke-CanonicalMachineInstallationRecovery').Body.Extent.Text
$restore=($functions|Where-Object Name -eq 'Restore-CanonicalMachineInstallationPrestate').Body.Extent.Text
if($recovery -notmatch 'Restore-CanonicalMachineInstallationPrestate' -or $restore -notmatch "'-Uninstall'"){throw 'recovery route differs'}
$source=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'INSTALL_THIS_PC.ps1') -Raw
if($source -notmatch 'Remove-ContainerScheduledTasks \$TaskFolder' -or $source -notmatch 'Get-ContainerRemovalTaskNames \$Folder'){throw 'removal route differs'}
'PASS'
''', engine="powershell")
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
def test_missing_schema_child_diagnostic_preserves_original_exit(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", [
        "Initialize-InstallationChildCapture", "ConvertTo-SafeInstallationOutput",
        "Invoke-InstallationEvidenceChild",
    ], r'''
Set-StrictMode -Version Latest
function Protect-InstallationText($Text,$Limit,[switch]$Configuration){if($Configuration){return @{full_byte_cap=65536}};return $Text}
function ConvertTo-KmtechRedactedSinkText($Text){return $Text}
$script:events=[Collections.Generic.List[object]]::new()
function Write-InstallationEvidenceEvent($Event){$script:events.Add($Event)}
$script:InstallationOriginalFailure=[pscustomobject]@{unchanged=$true}
$original=$script:InstallationOriginalFailure
$engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$result=Invoke-InstallationEvidenceChild 'missing-schema' $engine @('-NoLogo','-NoProfile','-NonInteractive','-Command','Write-Output ''installation_failure_summary={"exit_code":73}''; exit 73')
if($result.ExitCode -ne 73 -or $null -ne $result.FailureDiagnostic){throw 'original exit changed'}
if(@($script:events|Where-Object event -eq 'CHILD_FAILURE_DIAGNOSTIC_UNKNOWN').Count -ne 1){throw 'unknown diagnostic not recorded'}
if(-not [object]::ReferenceEquals($original,$script:InstallationOriginalFailure)){throw 'original failure replaced'}
'PASS'
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"
