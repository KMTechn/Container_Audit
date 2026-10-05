"""Lifecycle classification stays inside the helper's existing admission lease."""
from pathlib import Path
import json
import os
import sys

import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "INSTALL_THIS_PC.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("state", ("removed", "control", "task", "derived_task", "foreign_task", "legacy_task", "unknown"))
@pytest.mark.parametrize("invocation", ("script", "block"))
def test_helper_classifies_under_held_admission_without_child(tmp_path, engine, state, invocation):
    result = run_functions(tmp_path, HELPER, ["Get-ContainerSupportedInstallContext", "Set-ContainerLifecycleContextFailure"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
function Write-InstallationEvidenceEvent {param($Event)}
function Get-ScheduledTask {
    if($env:CA_CONTEXT_STATE -ceq 'unknown'){throw 'task observation unavailable'}
    if($env:CA_CONTEXT_STATE -ceq 'task'){return [pscustomobject]@{TaskName='direct-sync-relay-container-audit'}}
    if($env:CA_CONTEXT_STATE -cin @('derived_task','foreign_task')){
        return [pscustomobject]@{TaskName=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24));TaskPath='\'}
    }
    if($env:CA_CONTEXT_STATE -ceq 'legacy_task'){return [pscustomobject]@{TaskName='unrelated-legacy-task'}}
    return @()
}
function Export-ScheduledTask {
    param($TaskName,$TaskPath)
    $fixed=Join-Path $env:CA_CONTRACT_ROOT 'managed/current'
    if($env:CA_CONTEXT_STATE -ceq 'foreign_task'){$fixed=Join-Path $env:CA_CONTRACT_ROOT 'other/current'}
    return '<Task><Actions><Exec><Arguments>'+[Security.SecurityElement]::Escape($fixed)+'</Arguments></Exec></Actions></Task>'
}
$application=Join-Path $env:CA_CONTRACT_ROOT 'managed'
if($env:CA_CONTEXT_STATE -ceq 'control'){
    [void][IO.Directory]::CreateDirectory((Join-Path $application 'update-control'))
    [IO.File]::WriteAllText((Join-Path $application 'update-control/policy.json'),'{}')
}
# Noncanonical test root gives the real product mutex a task-specific suffix.
$Script:placementWriterFenceLease=$null
$operation={
$placementWriterFenceLease=Enter-ContainerWriterAdmission (Join-Path $env:CA_CONTRACT_ROOT 'isolated-fence')
try{
    $failed=$false
    try{$context=Get-ContainerSupportedInstallContext 'unused-source' (Join-Path $application 'current')}catch{$failed=$true;$original=$_}
    if($env:CA_CONTEXT_STATE -cin @('removed','foreign_task','legacy_task')){
        if($failed){throw $original}
        if($context.status -cne 'PASS' -or $context.lifecycle_state -cne 'REMOVED'){throw 'First-install decision differs.'}
    }else{
        if(-not $failed){throw 'Residual or unknown task state admitted.'}
        if($original.Exception.Message -cne 'Supported lifecycle context is unhealthy.'){throw 'Public rejection changed.'}
        if($Script:ContainerLifecycleContextFailure.status -cne 'FAILED'){throw 'Failure classification missing.'}
        $wanted=if($env:CA_CONTEXT_STATE -ceq 'control'){'lifecycle_removed_control_remains'}else{'lifecycle_removed_tasks_remain_or_unknown'}
        if($env:CA_CONTEXT_STATE -cne 'unknown' -and $wanted -cnotin @($Script:ContainerLifecycleContextFailure.failure_details|ForEach-Object {$_.message})){throw 'Original rejection classification missing.'}
    }
    # Context inspection must neither release nor replace the caller lease.
    if(-not $placementWriterFenceLease.acquired){throw 'Caller admission lease changed.'}
    'PASS'
}finally{Exit-ContainerWriterAdmission $placementWriterFenceLease}
}
if($env:CA_CONTEXT_INVOCATION -ceq 'block'){& $operation}else{. $operation}
''', engine=engine, values={"CA_CONTEXT_STATE": state, "CA_CONTEXT_INVOCATION": invocation})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_original_guarded_python_query_refuses_parent_owned_mutex(tmp_path, engine):
    probe = tmp_path / "context_probe.py"
    probe.write_text('''import sys
from pathlib import Path
import auto_update as update
import writer_session_fence as fence
assert getattr(fence, '__kmtech_test_ca_writer_isolated__', False), 'child isolation hook missing'
fixture=Path(sys.argv[1])
import subprocess
subprocess.run=lambda *a, **kw: subprocess.CompletedProcess(a[0],0,b'',b'')
try:
    result=update.resolve_lifecycle_context(fixture/'managed', operation='install')
    print(result['lifecycle_state'])
except ValueError as error:
    print(getattr(error.__cause__, 'code', 'UNCLASSIFIED_'+type(error.__cause__).__name__))
''', encoding="utf-8")
    result = run_functions(tmp_path, HELPER, ["Get-ContainerSupportedInstallContext"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
$placementWriterFenceLease=Enter-ContainerWriterAdmission (Join-Path $env:CA_CONTRACT_ROOT 'isolated-fence')
$env:KMTECH_TEST_CA_WRITER_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'isolated-fence'
$env:KMTECH_TEST_CA_WRITER_MUTEX=$placementWriterFenceLease.name
function Invoke-ContractContextProbe {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$env:CA_CONTEXT_PYTHON
    $info.Arguments='"'+$env:CA_CONTEXT_PROBE+'" "'+$env:CA_CONTRACT_ROOT+'"'
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$info
    try {
        [void]$process.Start()
        $output=$process.StandardOutput.ReadToEnd().Trim()
        $errorText=$process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if($process.ExitCode -ne 0 -or $errorText.Length -ne 0){throw 'Isolated context probe failed.'}
        return $output
    } finally {$process.Dispose()}
}
try{
    $observed=Invoke-ContractContextProbe
    if($observed -cne 'WRITER_GATE_TIMEOUT'){throw ('Original nested child classification: '+$(if($observed -cmatch '^[A-Z_]+$'){$observed}else{'UNCLASSIFIED'}))}
}finally{Exit-ContainerWriterAdmission $placementWriterFenceLease}
$observed=Invoke-ContractContextProbe
if($observed -cne 'REMOVED'){throw 'Same isolated query did not pass after lease release.'}
'PASS'
''', engine=engine, values={"CA_CONTEXT_PYTHON": sys.executable, "CA_CONTEXT_PROBE": str(probe),
                           "PYTHONPATH": os.pathsep.join(filter(None, (
                               os.environ.get('PYTHONPATH', ''), str(ROOT / 'tests'), str(ROOT))))})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("shape", ("classified", "sensitive", "malformed", "oversized"))
def test_context_failure_summary_keeps_only_bounded_classifications(tmp_path, engine, shape):
    payload = {"status": "FAILED", "error_type": "ValueError", "failure_details": [
        {"type": "builtins.ValueError", "message": "lifecycle_removed_control_remains"}]}
    if shape == "sensitive":
        payload["error_type"] = "private-type-value"
        payload["failure_details"][0] = {"type": "private-type-value", "message": "C:/private/location auth=canary", "stdout": "canary"}
    text = json.dumps(payload) if shape != "malformed" else "{"
    if shape == "oversized":
        text = "x" * 65537
    path = tmp_path / "context.txt"
    path.write_text(text, encoding="utf-8")
    result = run_functions(tmp_path, HELPER, ["Set-ContainerLifecycleContextFailure"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
$Script:events=@()
function Write-InstallationEvidenceEvent {param($Event) $Script:events+=,$Event}
Set-ContainerLifecycleContextFailure @(Get-Content -LiteralPath $env:CA_CONTEXT_INPUT -Raw -Encoding UTF8)
$text=$Script:ContainerLifecycleContextFailure|ConvertTo-Json -Depth 6 -Compress
if($text.Contains('canary') -or $text.Contains('private') -or $text.Contains('stdout')){throw 'Context diagnostics exposed an unclassified value.'}
if($env:CA_CONTEXT_SHAPE -ceq 'classified'){
    if($Script:ContainerLifecycleContextFailure.failure_details[0].message -cne 'lifecycle_removed_control_remains'){throw 'Original reason missing.'}
}elseif($env:CA_CONTEXT_SHAPE -cin @('malformed','oversized')){
    if($Script:ContainerLifecycleContextFailure.status -cne 'UNKNOWN'){throw 'Unknown output claimed a classified failure.'}
}
if($Script:events.Count -ne 1 -or $Script:events[0].event -cne 'LIFECYCLE_CONTEXT_FAILED'){throw 'Existing audit did not retain reason.'}
'PASS'
''', engine=engine, values={"CA_CONTEXT_INPUT": str(path), "CA_CONTEXT_SHAPE": shape})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_helper_final_summary_retains_context_reason(tmp_path, engine):
    result = run_functions(tmp_path, HELPER, ["Set-ContainerLifecycleContextFailure", "Get-InstallationHelperPublicFailure"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
function Write-InstallationEvidenceEvent {param($Event)}
function Fail-InstallationEvidenceStages {param($Failure)}
$details=@(1..16|ForEach-Object {@{type='builtins.ValueError';message='lifecycle_removed_tasks_remain_or_unknown'}})
Set-ContainerLifecycleContextFailure @((@{status='FAILED';error_type='ValueError';failure_details=$details}|ConvertTo-Json -Depth 5 -Compress))
$blocks=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CatchClauseAst] -and
    $node.Body.Extent.Text.Contains('installation_failure_summary=')
},$true))
if($blocks.Count -ne 1){throw 'Expected actual final helper catch.'}
$body=$blocks[0].Body.Extent.Text
if(-not $body.StartsWith('{') -or -not $body.EndsWith('}')){throw 'Expected actual catch-body extent.'}
try{throw 'Supported lifecycle context is unhealthy.'}catch{Invoke-Expression $body.Substring(1,$body.Length-2)}
''', engine=engine)
    assert result.returncode == 73, result.stderr
    prefix = "installation_failure_summary="
    lines = [line[len(prefix):] for line in result.stdout.splitlines() if line.startswith(prefix)]
    assert len(lines) == 1
    assert len((prefix + lines[0]).encode("utf-8")) <= 4096
    diagnostic = json.loads(lines[0])
    # Coordinator 04:0x: public diagnostics are flat codes; the protected event
    # retains the bounded classifications (verified by the preceding test).
    assert diagnostic["reason_code"] == "lifecycle_removed_tasks_remain_or_unknown"
    assert diagnostic["report_status"] == "REPORT_UNAVAILABLE"
    assert "lifecycle_context_failure" not in diagnostic
