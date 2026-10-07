"""Actual G marker readback decides the canonical rollback result."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', ('absent', 'previous', 'committed', 'partial', 'malformed', 'foreign', 'future', 'mixed', 'oversize'))
def test_canonical_commit_point_reads_actual_generation(tmp_path, engine, case):
    executable = shutil.which(engine)
    assert executable
    driver = tmp_path / 'commit-point.ps1'
    driver.write_text(r'''
param([string]$Source,[string]$Root,[string]$Case)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $Source 'tools/bootstrap_integrity.ps1')
. (Get-BootstrapSharedPortableLeaf $Source)
. (Get-BootstrapSharedPortableLeaf $Source 'data_generation.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Source 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$null,[ref]$null)
foreach($definition in @($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){
    Invoke-Expression $definition.Extent.Text
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$data=Join-Path $Root 'data';$local=Join-Path $Root 'local'
$control=Join-Path $local 'KMTech/DirectSync/container_audit/control/writer-session/data-generation'
[void][IO.Directory]::CreateDirectory($data);[void][IO.Directory]::CreateDirectory($control)
$candidate=[pscustomobject]@{version='v2.0.5';source_commit=('a'*40)}
$marker=Join-Path $data 'data-generation.json'
if($Case -ceq 'previous'){
    [void](Write-KmtechDataGeneration $marker 'v2.0.4' 'container_audit' $sid -BuildId ('b'*40))
}elseif($Case -cin @('committed','partial','foreign','future','mixed')){
    $version=if($Case -ceq 'future'){'v2.0.6'}else{'v2.0.5'}
    $owner=if($Case -ceq 'foreign'){'S-1-5-21-1-2-3-9999'}else{$sid}
    if($Case -cin @('partial','mixed')){$marker=Join-Path $control ($sid+'.json')}
    [void](Write-KmtechDataGeneration $marker $version 'container_audit' $owner -BuildId ('a'*40))
    if($Case -ceq 'mixed'){
        [IO.File]::WriteAllText((Join-Path $data 'data-generation.json'),'{"schema":"broken"}',[Text.UTF8Encoding]::new($false))
    }
}elseif($Case -ceq 'malformed'){
    [IO.File]::WriteAllText($marker,'{"schema":"broken"}',[Text.UTF8Encoding]::new($false))
}elseif($Case -ceq 'oversize'){
    [IO.File]::WriteAllText($marker,('x'*4097),[Text.UTF8Encoding]::new($false))
}
$placement='PASS_NEW_VERIFIED';$RestoreVerifiedReplacement=$false;$audit=[ordered]@{}
if(Get-Command Get-CanonicalInstallationCommitPoint -ErrorAction SilentlyContinue){
    $sourceManifest=$candidate;$operatorSid=$sid;$lad=$local;$activeDataRoot=$data
    $query=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq '$canonicalInstallationCommitPoint' -and $n.Extent.Text.Contains('Get-CanonicalInstallationCommitPoint')},$true))
    $selection=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq '$audit.status' -and $n.Extent.Text.Contains('Get-CanonicalRollbackSuccessStatus')},$true))
    if($query.Count -ne 1 -or $selection.Count -ne 1){throw 'Canonical commit-point/result binding missing.'}
    Invoke-Expression $query[0].Extent.Text
    Invoke-Expression $selection[0].Extent.Text
    $commitPoint=$canonicalInstallationCommitPoint
}else{
    # Execute the existing production selector, rather than mirroring its bug.
    $selection=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq '$audit.status' -and $n.Extent.Text.Contains('FAILED_RUNTIME_RESTORED_CODE_RETAINED')},$true))
    if($selection.Count -ne 1){throw 'Canonical rollback selector missing.'}
    Invoke-Expression $selection[0].Extent.Text
    $commitPoint='LEGACY_PLACEMENT_ONLY'
}
[IO.File]::WriteAllText((Join-Path $Root 'result.json'),(@{status=$audit.status;commit_point_status=$commitPoint}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
''', encoding='utf-8-sig')
    result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(driver),
                             '-Source', str(ROOT), '-Root', str(tmp_path), '-Case', case],
                            capture_output=True, creationflags=0x08000000)
    (tmp_path / 'stdout.log').write_bytes(result.stdout)
    (tmp_path / 'stderr.log').write_bytes(result.stderr)
    assert result.returncode == 0
    observed = json.loads((tmp_path / 'result.json').read_bytes())
    expected_point = ('NOT_REACHED' if case in ('absent', 'previous') else
                      'REACHED' if case in ('committed', 'partial') else 'UNKNOWN')
    expected_status = ('FAILED_ROLLED_BACK' if expected_point == 'NOT_REACHED' else
                       'FAILED_RUNTIME_RESTORED_CODE_RETAINED' if expected_point == 'REACHED' else
                       'CODE_ROLLBACK_FAILED')
    assert observed == {'status': expected_status, 'commit_point_status': expected_point}
