"""Execute evidence collection without installer, GUI, relay or token APIs."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/bootstrap_integrity.ps1'
FUNCTIONS = [
    'Get-StrictFullPath', 'Get-FileSha256', 'Assert-BootstrapNoReparsePoint',
    'Protect-InstallationText', 'ConvertTo-KmtechRedactedSinkText', 'Get-InstallationFailureDetails',
    'Set-InstallationEvidenceAcl', 'Initialize-InstallationEvidence',
    'Test-InstallationEvidencePrivileged', 'Assert-InstallationEvidenceWriteRoot',
    'Write-InstallationEvidenceEvent', 'Set-InstallationEvidenceStage',
    'Complete-InstallationEvidenceStage', 'Write-InstallationCaughtFailure',
    'Fail-InstallationEvidenceStages', 'Initialize-InstallationChildCapture',
    'ConvertTo-SafeInstallationOutput', 'Invoke-InstallationEvidenceChild',
]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('exit_code', (0, 7))
def test_finite_child_streams_survive_success_and_failure_with_private_acl(tmp_path, engine, exit_code):
    result = run_functions(tmp_path, SOURCE, FUNCTIONS, r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'own') $sid @('passed-credential-sentinel')
$childScript=Join-Path $env:CA_CONTRACT_ROOT 'child.ps1'
$code=@'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::Out.Write("stdout 한국어; space `"quote`" trailing\`n")
[Console]::Error.Write("ACL readback denied C:\fixture\path; token=passed-credential-sentinel`n")
exit CHILD_EXIT
'@
$code=$code.Replace('CHILD_EXIT',$env:CA_CHILD_EXIT)
[IO.File]::WriteAllText($childScript,$code,[Text.UTF8Encoding]::new($true))
Set-InstallationEvidenceStage 'fixture.child'
$child=Invoke-InstallationEvidenceChild 'fixture' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',$childScript)
Complete-InstallationEvidenceStage 'forward'
if($child.ExitCode -ne [int]$env:CA_CHILD_EXIT){throw 'Native child exit was lost.'}
$expected="stdout 한국어; space `"quote`" trailing\`n"
if($child.Stdout -cne $expected){throw 'Child stdout bytes or quoted arguments changed.'}
if($child.Stderr.Contains('passed-credential-sentinel') -or -not $child.Stderr.Contains('C:\fixture\path')){throw 'Failure context/redaction incorrect.'}
foreach($name in @('stdout','stderr')){
 $stream=$child.Streams[$name]
 if(-not $stream.complete -or $stream.truncated -or (Get-FileSha256 $stream.path) -cne $stream.sha256){throw 'Child stream evidence incomplete.'}
 $acl=Get-Acl -LiteralPath $stream.path
 if(-not $acl.AreAccessRulesProtected){throw 'Evidence DACL inherited.'}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'Evidence readable by an unrelated SID.'}
 }
}
if($child.Streams.stdout.redacted -or -not $child.Streams.stderr.redacted){throw 'Redaction metadata incorrect.'}
$events=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
if(@($events | Where-Object {$_.event -ceq 'CHILD_EXIT' -and $_.exit_code -eq [int]$env:CA_CHILD_EXIT}).Count -ne 1){throw 'Child exit record missing.'}
if($Script:InstallationEvidenceFailed){throw 'Evidence writer failed.'}
'PASS'
''', engine=engine, values={'CA_CHILD_EXIT': str(exit_code)})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_large_child_output_is_drained_bounded_and_partial_secret_removed(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, FUNCTIONS, r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
[void](Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'large') $sid @('edge-secret-sentinel'))
$command='[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); for($i=0;$i -lt 4096;$i++){[Console]::Out.Write(("x"*511)+"`n")}; exit 0'
$child=Invoke-InstallationEvidenceChild 'large' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe') @('-NoLogo','-NoProfile','-NonInteractive','-Command',$command)
if($child.ExitCode -ne 0 -or $child.Streams.stdout.observed_bytes -ne 2097152 -or $child.Streams.stdout.saved_bytes -gt 1048576 -or -not $child.Streams.stdout.truncated -or -not $child.Streams.stdout.complete){throw 'Large output cap/drain failed.'}
$partial=[Text.Encoding]::UTF8.GetBytes("safe`nedge-secret-")
$safe=ConvertTo-SafeInstallationOutput ([pscustomobject]@{bytes=$partial;observed=($partial.Length+100);complete=$true})
if([Text.Encoding]::UTF8.GetString($safe.bytes).Contains('edge-secret')){throw 'Partial credential escaped at cap.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_original_chain_and_stage_survive_recovery_before_generic_throw(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, FUNCTIONS, r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'failure') $sid @('bound-value-sentinel')
Set-InstallationEvidenceStage 'placement.startup.trust'
try {
 $inner=[ComponentModel.Win32Exception]::new(5,'ancestor C:\fixture denied; bound-value-sentinel')
 throw [InvalidOperationException]::new('original startup failure; password=fixture-password',$inner)
} catch {$original=$_;Fail-InstallationEvidenceStages $original}
Set-InstallationEvidenceStage 'rollback.tree' 'rollback'
Complete-InstallationEvidenceStage 'rollback'
$events=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
$failure=@($events | Where-Object {$_.event -ceq 'END' -and $_.result -ceq 'FAILED'})
if($failure.Count -ne 1 -or $failure[0].stage -cne 'placement.startup.trust' -or $failure[0].failure.script_line -le 0){throw 'Original stage/line missing.'}
$chain=$failure[0].failure.exception_chain
if(@($chain | Where-Object {$_.win32_error -eq 5 -and $_.message.Contains('C:\fixture')}).Count -ne 1){throw 'Original inner native cause missing.'}
$json=$events | ConvertTo-Json -Depth 12
foreach($secret in @('bound-value-sentinel','fixture-password')){if($json.Contains($secret)){throw 'Passed secret leaked.'}}
if(-not $json.Contains('original startup failure')){throw 'Useful original message lost.'}
if(@($events | Where-Object {$_.stage -ceq 'rollback.tree' -and $_.result -ceq 'PROVEN'}).Count -ne 1){throw 'Recovery obscured original outcome.'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
