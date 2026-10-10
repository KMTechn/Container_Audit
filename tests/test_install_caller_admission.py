"""Admitted fresh public entry with fake caller tokens and inert native IO."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _run_entry(tmp_path, security, *, placement=False, query_failure=False, invalid_input=False):
    source = (ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').read_text(encoding='utf-8-sig')
    start = source.index('$wanted = Command $install')
    stop = source.index("Set-InstallationEvidenceStage 'canonical.writer_fence_preflight'", start)
    entry = source[start:stop].replace(
        '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value', '$caller.sid').replace(
        '. $BootstrapIntegrityFunctions', '# Authenticated native library supplied by the fixture').replace(
        "[Environment]::GetEnvironmentVariable($name, 'Process')", '$null')
    library = str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''")
    if invalid_input:
        entry = "throw 'synthetic invalid input'"
    script = r'''
$ErrorActionPreference='Stop'
$script:callerReads=0; $script:privateReports=0
function Get-CanonicalRelaySecurity([int]$ProcessId) {
    if($ProcessId -ne $PID){throw 'Original caller PID differs'}
    $script:callerReads++
    if($script:queryFailure){throw 'PRIVATE_NATIVE_FAILURE_E_SYNTHETIC_PATH'}
    return $caller
}
function Write-KmtechProtectedFailureSidecar { $script:privateReports++; $script:writes++; throw 'synthetic private writer' }
function ConvertTo-KmtechPublicRecord($Fields) { return $Fields }

$script:writes=0; $script:consents=0; $script:refused=$false; $script:evidenceStarted=$false
function Full($Value,$Purpose) { return $Value }
function Command($Root) { return 'synthetic command' }
function Read-CanonicalRollbackContinuation { return $null }
function Get-BootstrapSupportedLifecycleContext { return @{lifecycle_state='FRESH';managed=$false} }
function Read-InstallationAbandonedRollback { return $null }
function Get-CanonicalOfficialLegacyRelayAdmission { return $null }
function Assert-ContainerDataGenerationTarget { }
function Sha { return ('a'*64) }
function Test-Path {
    param($LiteralPath,$Path,$PathType)
    if(-not $script:evidenceStarted){return $false}
    return -not (([string]$LiteralPath).EndsWith('.evidence.'+$PID) -or
        [IO.Path]::GetExtension([string]$LiteralPath) -cin @('.json','.jsonl'))
}
function Test-InstallationEvidencePrivileged { return [bool]$caller.elevated }
function New-InstallationProtectedEvidenceRun { return $env:LOCALAPPDATA }
function Get-StrictFullPath($Value,$Purpose) { $script:evidenceStarted=$true; return $Value }
function Assert-BootstrapNoReparsePoint { }
function Set-InstallationEvidenceAcl { }
function Assert-InstallationEvidenceWriteRoot { }
function Write-InstallationEvidenceEvent { }
function Protect-InstallationText { return @{full_byte_cap=1024} }
function Get-InstallationEvidenceControlRoot { return $env:LOCALAPPDATA }
function Assert-InstallationEvidenceProtectedPath { }
function Get-FileSha256 { return ('a'*64) }
function Get-InstallationElevationWrapperSource { return 'synthetic wrapper' }
function New-InstallationMemoryTransport { return @{Encoded='synthetic transport'} }
function ConvertTo-BootstrapRelayArgument($Value) { return $Value }
function Remove-InstallationMemoryTransport { }
function Start-Process {
    param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
    if($Verb -cne 'RunAs' -or $WindowStyle -cne 'Hidden' -or -not $Wait){throw 'UAC boundary differs'}
    $script:consents++; return @{ExitCode=0;Id=456}
}
function Get-InstallationPreparationDiagnostic { return $null }
function Get-Item { param($LiteralPath); return @{Length=1} }
function Get-Content {
    param($LiteralPath,[switch]$Raw,$Encoding)
    return (@{schema='container-audit-installation-elevation-capture-v1';parent_process_id=$PID;wrapper_process_id=456;helper_process_id=789;helper_exit_code=0;helper_sha256=('a'*64);protected_run_root=(Split-Path -Parent $LiteralPath)}|ConvertTo-Json -Compress)
}
function Test-BootstrapJsonInteger { return $true }
function Test-BootstrapSamePath($Left,$Right) { return $Left -ceq $Right }
function ConvertTo-KmtechRedactedSinkText($Value) { return $Value }
$testMode=$false; $PlanOnly=$false; $Uninstall=$false; $RestoreVerifiedReplacement=$false; $CompleteRetiredRemoval=$false
$ResumeRetirementReceiptPath=''; $RestoreReceiptPath=''
$source='E:\synthetic-packet'; $install='E:\synthetic-current'
$lifecycleManifest=@{writer_session_contract_sha256=('a'*64)}
''' + ('$script:queryFailure=' + ('$true' if query_failure else '$false') + '\n') + '$env:LOCALAPPDATA=\'' + str(tmp_path).replace("'", "''") + "'\n" + \
        '$caller=' + '@{elevated=' + ('$true' if security[0] else '$false') + \
        ';integrity_rid=' + str(security[1]) + ';session_id=' + str(security[2]) + \
        ";sid='synthetic-worker'}\n$caller.integrity_level=$caller.integrity_rid\n" + r'''
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('@@library@@',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Product parser failed'}
foreach($name in @('Initialize-InstallationEvidence','Invoke-InstallationElevationCapture')){
    $definition=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
    $text=$definition[0].Extent.Text
    $text=$text.Replace('[void][IO.Directory]::CreateDirectory($root)','$script:writes++; [void][IO.Directory]::CreateDirectory($root)')
    Invoke-Expression $text
}
$ast=[Management.Automation.Language.Parser]::ParseFile('@@canonical@@',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Product parser failed'}
$definition=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-CanonicalInstallationPublicRecord'},$true)
Invoke-Expression $definition[0].Extent.Text
try {
''' + entry + '\n'
    if placement:
        script += r'''
if(-not $script:refused){[void](Invoke-InstallationElevationCapture 'E:\synthetic-packet\INSTALL_THIS_PC.ps1' @() (Join-Path $env:LOCALAPPDATA 'audit.jsonl') 'synthetic-worker')}
'''
    script += "\n} finally { @{writes=$script:writes;consents=$script:consents;caller_reads=$script:callerReads;private_reports=$script:privateReports}|ConvertTo-Json -Compress }\n"
    path = tmp_path / 'caller.ps1'
    path.write_text(script.replace('@@library@@', library).replace('@@canonical@@', str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').replace("'", "''")), encoding='utf-8-sig')
    executable = shutil.which('powershell.exe')
    assert executable, 'Windows PowerShell required'
    result = subprocess.run([executable,'-NoLogo','-NoProfile','-NonInteractive','-File',str(path)],
                            capture_output=True,text=True,check=False,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode in (0, 1), 'Synthetic public entry harness failed'
    lines = result.stdout.strip().splitlines()
    observed = json.loads(lines[-1])
    observed['refused'] = result.returncode == 1
    observed['exit_code'] = result.returncode
    public = [line for line in (*lines[:-1], *result.stderr.splitlines()) if line.strip()]
    if result.returncode:
        assert len(public) == 1, 'Refusal must emit exactly one public failure'
        prefix = 'CONTAINER_AUDIT_INSTALL_CANONICAL=' if (ROOT / 'Container_Audit.py').is_file() else 'LABEL_MATCH_INSTALLER_FAILURE='
        assert public[0].startswith(prefix)
        failure = json.loads(public[0][len(prefix):])
        assert failure['status'] == 'FAILED' and failure['report_status'] == 'REPORT_UNAVAILABLE'
        assert failure['reason_code'] == ('INSTALLER_CANONICAL_FAILURE' if (ROOT / 'Container_Audit.py').is_file() else 'INSTALLER_FAILED')
        assert 'report_path' not in failure
        assert 'PRIVATE_NATIVE_FAILURE' not in public[0] and 'synthetic-worker' not in public[0]
    else:
        assert public == []
    return observed


@pytest.mark.parametrize('security', [(True,12288,7),(False,12288,7),(True,16384,7),(False,8192,0)],
                         ids=['elevated','high','system','session-zero'])
def test_public_caller_refuses_before_evidence_state(tmp_path, security):
    observed = _run_entry(tmp_path, security)
    assert observed['refused'] and observed['writes'] == 0, 'Unsafe public caller reached the evidence writer'
    assert observed['exit_code'] == 1 and observed['consents'] == 0 and observed['caller_reads'] == 1 and observed['private_reports'] == 0


def test_normal_caller_keeps_existing_uac_child(tmp_path):
    observed = _run_entry(tmp_path, (False,8192,7), placement=True)
    assert not observed['refused'] and observed['writes'] == 1 and observed['consents'] == 1, observed
    assert observed['exit_code'] == 0 and observed['caller_reads'] == 1 and observed['private_reports'] == 0

def test_caller_security_query_failure_has_no_private_report(tmp_path):
    observed = _run_entry(tmp_path, (False,8192,7), query_failure=True)
    assert observed['refused'] and observed['writes'] == 0 and observed['consents'] == 0
    assert observed['caller_reads'] == 1 and observed['private_reports'] == 0


@pytest.mark.parametrize('security', [(False,4096,7),(False,8192,-1)], ids=['low','negative-session'])
def test_other_non_normal_callers_refuse_without_writes(tmp_path, security):
    observed = _run_entry(tmp_path, security)
    assert observed['refused'] and observed['writes'] == 0 and observed['private_reports'] == 0
