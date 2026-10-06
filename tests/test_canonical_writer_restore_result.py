"""Keep real scheduler proof objects through the canonical rollback caller."""
import os
from pathlib import Path
import re
import subprocess

import pytest

from tests.canonical_scheduler_fixture import SCHEDULER_OS


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('present', (False, True))
def test_rollback_consumes_actual_optional_writer_proof(tmp_path, engine, present):
    source = ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'
    controller = source.read_text(encoding='utf-8-sig')
    caller = re.search(r'\$writerEnabled=Enable-CanonicalWriter[^\n]*\n\s*'
                       r'Assert-CanonicalWriterRestoreReadback[^\n]*', controller)
    assert caller is not None
    root = str(ROOT).replace("'", "''")
    driver = tmp_path / 'writer-proof.ps1'
    driver.write_text(r"""
param([string]$Root,[string]$Present)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$env:LOCALAPPDATA=Join-Path $Root 'local'
$env:APPDATA=Join-Path $Root 'roaming'
$env:CA_UNINSTALL_ROOT=$Root
$env:CONTAINER_AUDIT_WRITER_TEST_MODE='1'
$env:CONTAINER_AUDIT_WRITER_CONTROL_ROOT=Join-Path $Root 'control'
""" + f"""
. '{root}/tools/bootstrap_integrity.ps1'
. (Get-BootstrapSharedPortableLeaf '{root}')
. '{root}/tools/container_writer_fence.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile('{root}/INSTALL_CANONICAL_PORTABLE.ps1',[ref]$null,[ref]$null)
foreach($definition in $ast.EndBlock.Statements){{
    if($definition -is [Management.Automation.Language.FunctionDefinitionAst]){{
        Invoke-Expression $definition.Extent.Text
    }}
}}
""" + r"""
$CanonicalWriterTaskName='direct-sync-relay-container-audit'
$NoncanonicalQualificationTaskName='container-audit-isolated-qualification-authority'
$install=Join-Path $Root 'current'
$script:CanonicalWriterFenceSessionId=[Guid]::NewGuid().ToString('N')
$script:CanonicalWriterFenceAttemptId=[Guid]::NewGuid().ToString('N')
$script:CanonicalWriterFenceTransactionId=[Guid]::NewGuid().ToString('N')
$script:CanonicalWriterFenceDelegationToken=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
$orchestrator=Sha '""" + str(source).replace("'", "''") + r"""'
$contract=Sha '""" + str(ROOT / 'tools/container_writer_session_contract.json').replace("'", "''") + r"""'
$canonicalWriterFenceAuthority=Enter-ContainerWriterSessionAuthority $script:CanonicalWriterFenceSessionId $script:CanonicalWriterFenceAttemptId $orchestrator $script:CanonicalWriterFenceTransactionId $contract
try {
    $receipt=Join-Path $Root 'prepared.json'
    [IO.File]::WriteAllText($receipt,'{"status":"PREPARED"}')
    [void](Start-ContainerWriterFence -Status 'INSTALLING' -OwnerKind 'canonical_installer' `
        -SessionId $script:CanonicalWriterFenceSessionId -AttemptId $script:CanonicalWriterFenceAttemptId `
        -ReplacementTransactionId $script:CanonicalWriterFenceTransactionId `
        -SessionStartedAtUtc ([DateTime]::UtcNow.ToString('o')) `
        -OrchestratorSha256 $orchestrator -WriterContractSha256 $contract `
        -PreparedReceiptPath $receipt -PreparedReceiptSha256 (Sha $receipt) `
        -DelegationToken $script:CanonicalWriterFenceDelegationToken `
        -DelegatedSources @('canonical_scheduler_probe') `
        -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(2).ToString('o')) `
        -AuthorityLease $canonicalWriterFenceAuthority)
""" + SCHEDULER_OS + r"""
    if($Present -ceq 'false') {
        function Get-ScheduledTask { [CmdletBinding()]param([string]$TaskName,[string]$TaskPath) return @() }
    }
    $writerBefore=Get-CanonicalWriterPreimageForQuiesce $install
    $writerRestoreNeeded=[bool]$writerBefore.restore_required
    if($writerRestoreNeeded) {
""" + caller.group() + r"""
        if($writerEnabled.status -cne 'PASS' -or -not $writerEnabled.readback.enabled){throw 'actual writer proof missing'}
        # A damaged actual readback must still be rejected.
        $writerEnabled.readback.binding_sha256='0'*64
        try { Assert-CanonicalWriterRestoreReadback $writerBefore $writerEnabled.readback; throw 'damaged proof accepted' }
        catch { if($_.Exception.Message -cne 'CANONICAL_WRITER_RESTORE_BINDING_MISMATCH'){throw} }
    } elseif($writerBefore.present) { throw 'absent scheduler preimage differs' }
    'WRITER_OPTIONAL_PROOF_PASS'
} finally {
    Exit-ContainerWriterSessionAuthority $canonicalWriterFenceAuthority
}
""", encoding='utf-8-sig')
    result = subprocess.run([engine, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        str(driver), '-Root', str(tmp_path), '-Present', str(present).lower()],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        creationflags=subprocess.CREATE_NO_WINDOW,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    (tmp_path / 'writer-proof.stdout.log').write_text(result.stdout, encoding='utf-8')
    (tmp_path / 'writer-proof.stderr.log').write_text(result.stderr, encoding='utf-8')
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert 'WRITER_OPTIONAL_PROOF_PASS' in result.stdout
