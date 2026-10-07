"""Run canonical failure/finalization blocks with their real evidence writers."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("success", "failure", "rotated-failure"))
def test_canonical_journal_is_sealed_after_last_diagnostic(tmp_path, engine, case):
    executable = shutil.which(engine)
    assert executable, f"required PowerShell engine unavailable: {engine}"
    driver = tmp_path / "journal.ps1"
    driver.write_text(r'''
param([string]$Source,[string]$Root,[string]$Case)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
. (Join-Path $Source 'tools/bootstrap_integrity.ps1')
. (Get-BootstrapSharedPortableLeaf $Source)
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Source 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$null,[ref]$null)
Set-StrictMode -Version Latest
foreach($initialization in @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$outputFailure'
})){
    Invoke-Expression $initialization.Extent.Text
}
foreach($definition in @($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){
    Invoke-Expression $definition.Extent.Text
}
$outer=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Body.Extent.Text.Contains('$enteredPlacementTry')})
if($outer.Count -ne 1){throw 'Actual canonical outer failure boundary missing.'}
$transaction=@($outer[0].Body.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$legacyRelayRestoreNeeded -and')},$true))
if($transaction.Count -ne 1){throw 'Actual canonical transaction finalization missing.'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
[void](Initialize-InstallationEvidence (Join-Path $Root 'journal') $sid)
Set-InstallationEvidenceStage 'canonical.onboarding'
if($Case -ceq 'rotated-failure'){
    foreach($i in 1..15){Write-InstallationEvidenceEvent @{event='FIXTURE';diagnostic=('x'*5000);sequence=$i}}
}
$auditPath=Join-Path $Root 'audit.json';$evidenceFull=Join-Path $Root 'evidence.json'
$audit=[ordered]@{status='FAILED_ROLLED_BACK';rollback=@{runtime_restored=$false};code_replacement=@{};failure_message='isolated diagnostic before seal'}
$original=$null;$retirementAuditSealed=$false;$legacyRelayRestoreNeeded=$false
$canonicalWriterFenceEnvironmentNames=@();$canonicalWriterFenceAuthority=$null
$retirementResumeClaim=$null;$continuationOldClaim=$null;$enteredPlacementTry=$true
$canonicalWriterFenceActive=$false
$body=if($Case -ceq 'success'){'try {}'}else{
    'try {throw [InvalidOperationException]::new("isolated onboarding failure")} catch {$original=$_;Write-InstallationCaughtFailure $_;throw}'
}
$code='try {'+$body+' finally '+$transaction[0].Finally.Extent.Text+'} '+($outer[0].CatchClauses.Extent.Text -join ' ')
if($null -ne $outer[0].Finally){$code+=' finally '+$outer[0].Finally.Extent.Text}
Invoke-Expression $code
''', encoding="utf-8-sig")
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver),
         "-Source", str(ROOT), "-Root", str(tmp_path), "-Case", case],
        env=dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path)),
        capture_output=True, creationflags=0x08000000,
    )
    (tmp_path / "stdout.log").write_bytes(result.stdout)
    (tmp_path / "stderr.log").write_bytes(result.stderr)
    assert result.returncode == (0 if case == "success" else 1)
    evidence = next(tmp_path.glob("journal.evidence.*"))
    summary = json.loads((evidence / "evidence-status.json").read_text(encoding="utf-8-sig"))
    audit = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8-sig"))
    import hashlib
    events = []
    for part in summary["journal_parts"]:
        raw = Path(part["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == part["sha256"]
        events.extend(json.loads(line) for line in raw.splitlines())
    assert audit["installation_evidence"]["journal_parts"] == summary["journal_parts"]
    assert any(event["event"] == "CANONICAL_DIAGNOSTIC_REPORT" for event in events)
    if case != "success":
        assert sum(event["event"] == "CAUGHT_FAILURE" for event in events) == 2
    if case == "rotated-failure":
        assert len(summary["journal_parts"]) > 1


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_canonical_final_cleanup_accepts_preflight_without_acquired_resources(tmp_path, engine):
    executable = shutil.which(engine)
    assert executable
    driver = tmp_path / 'preflight-cleanup.ps1'
    driver.write_text(r'''
param([string]$Source)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Source 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$null,[ref]$null)
foreach($definition in @($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){
    Invoke-Expression $definition.Extent.Text
}
$outer=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Body.Extent.Text.Contains('$enteredPlacementTry')})
$cleanup=@($outer[0].Finally.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[0].Finally
& (Invoke-Expression $cleanup.Extent.Text)
''', encoding='utf-8-sig')
    result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(driver),
                             '-Source', str(ROOT)], capture_output=True, creationflags=0x08000000)
    (tmp_path / 'stdout.log').write_bytes(result.stdout)
    (tmp_path / 'stderr.log').write_bytes(result.stderr)
    assert result.returncode == 0
    assert result.stderr == b''
