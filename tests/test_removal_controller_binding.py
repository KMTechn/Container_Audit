"""Verify the actual controller identity under the existing delegated authority."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest
import writer_session_fence as fence
from tests.powershell_contracts import run_powershell
from tests.test_writer_session_fence import _active_payload, _write_active
from tests import test_canonical_portable_uninstall as portable
from tests import test_retired_portable_removal as retired

ROOT = Path(__file__).resolve().parents[1]


HELPER = r'''
$ErrorActionPreference='Stop'
$lease=$null
try {
    . (Join-Path $env:CA_BINDING_REPO 'tools\bootstrap_integrity.ps1')
    . (Join-Path $env:CA_BINDING_REPO 'tools\container_writer_fence.ps1')
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:CA_BINDING_REPO 'INSTALL_THIS_PC.ps1'),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'controller source parse failed' }
    $definitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true))
    foreach($name in @('Test-SamePath','Test-PathWithin','Assert-NoReparsePoint','Get-ContainerRemovalControllerProcessId')) {
        $definition=@($definitions|Where-Object {$_.Name -ceq $name})
        if($definition.Count -ne 1){throw 'controller function not unique'}
        Invoke-Expression $definition[0].Extent.Text
    }
    $active=Get-Content -LiteralPath $env:CA_BINDING_PAYLOAD -Raw -Encoding UTF8|ConvertFrom-Json
    $WriterFenceSessionId=[string]$active.session_id
    $WriterFenceAttemptId=[string]$active.attempt_id
    $WriterFenceReplacementTransactionId=[string]$active.replacement_transaction_id
    $WriterFencePreparedReceiptPath=[string]$active.prepared_receipt_path
    $WriterFencePreparedReceiptSha256=[string]$active.prepared_receipt_sha256
    $Script:ContainerWriterFenceAdmissionProductionRoot=$env:CA_BINDING_CONTROL_ROOT
    $types=@{};foreach($field in $Script:ContainerWriterFenceActiveFields){$item=$active.PSObject.Properties[[string]$field];$types[[string]$field]=if($null -eq $item -or $null -eq $item.Value){'missing'}else{$item.Value.GetType().FullName}}
    [IO.File]::WriteAllText((Join-Path $env:CA_BINDING_ROOT 'controller-field-types-public.json'),($types|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $lease=Enter-ContainerWriterDelegatedOperation -ControlRoot $env:CA_BINDING_CONTROL_ROOT -SessionId $WriterFenceSessionId -AttemptId $WriterFenceAttemptId -ReplacementTransactionId $WriterFenceReplacementTransactionId -DelegationToken $env:CA_BINDING_TOKEN -Source 'canonical_code_placement'
    $placementWriterFenceLease=$lease
    $RemovalControllerProcessId=[int]$env:CA_BINDING_CONTROLLER_PID
    $RemovalControllerStartedAtUtc=$env:CA_BINDING_CONTROLLER_STARTED
    $RemovalControllerCanonicalPath=$env:CA_BINDING_CANONICAL
    $installRootFull=Join-Path $env:CA_BINDING_ROOT 'application\current'
    if($env:CA_BINDING_CASE -ceq 'wrong_pid'){$RemovalControllerProcessId=[int]$env:CA_BINDING_SPOOF_PID}
    if($env:CA_BINDING_CASE -ceq 'wrong_start'){$RemovalControllerStartedAtUtc=[DateTime]::Parse($RemovalControllerStartedAtUtc).ToUniversalTime().AddSeconds(-1).ToString('o')}
    if($env:CA_BINDING_CASE -ceq 'partial'){$RemovalControllerCanonicalPath=''}
    $rows=@(Get-CimInstance Win32_Process -ErrorAction Stop)
    $controller=Get-ContainerRemovalControllerProcessId $rows
    if($controller -ne [int]$env:CA_BINDING_CONTROLLER_PID){throw 'controller selection changed'}
    'verified_controller_selected'
} catch {
    [IO.File]::WriteAllText((Join-Path $env:CA_BINDING_ROOT 'controller-error-private.json'),((@{error_id=$_.FullyQualifiedErrorId;script_stack_trace=$_.ScriptStackTrace})|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    [Console]::Out.WriteLine($_.Exception.Message)
    exit 1
} finally {if($null -ne $lease){Exit-ContainerWriterAdmission $lease}}
'''


MANAGER = r'''
$ErrorActionPreference='Stop'
$authority=$null
try {
    . (Join-Path $env:CA_BINDING_REPO 'tools\container_writer_fence.ps1')
    $payload=Get-Content -LiteralPath $env:CA_BINDING_PAYLOAD -Raw -Encoding UTF8|ConvertFrom-Json
    if($env:CA_BINDING_CASE -cne 'no_authority') {
        $authority=Enter-ContainerWriterSessionAuthority -SessionId ([string]$payload.session_id) -AttemptId ([string]$payload.attempt_id) -OrchestratorSha256 ([string]$payload.orchestrator_sha256) -ReplacementTransactionId ([string]$payload.replacement_transaction_id) -WriterContractSha256 ([string]$payload.writer_contract_sha256)
    }
    $env:CA_BINDING_CONTROLLER_PID=[string]$PID
    $env:CA_BINDING_CONTROLLER_STARTED=(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')
    if($env:CA_BINDING_CASE -ceq 'changed_manifest'){[IO.File]::AppendAllText((Join-Path $PSScriptRoot 'portable-manifest.json'),' ')}
    if($env:CA_BINDING_CASE -ceq 'changed_canonical'){[IO.File]::AppendAllText($PSCommandPath,"`n# changed fixture bytes`n")}
    $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    & $winps -NoLogo -NoProfile -NonInteractive -File (Join-Path $env:CA_BINDING_ROOT 'helper.ps1')
    $code=$LASTEXITCODE
} finally {if($null -ne $authority){Exit-ContainerWriterSessionAuthority $authority}}
exit $code
'''


@pytest.mark.parametrize('case,expected', [
    ('valid', None),
    ('wrong_pid', 'REMOVAL_CONTROLLER_NOT_VERIFIED_ANCESTOR'),
    ('wrong_start', 'REMOVAL_CONTROLLER_PROCESS_IDENTITY_CHANGED'),
    ('partial', 'REMOVAL_CONTROLLER_BINDING_REQUIRED'),
    ('changed_manifest', 'REMOVAL_CONTROLLER_SOURCE_BINDING_INVALID'),
    ('changed_canonical', 'REMOVAL_CONTROLLER_SOURCE_BINDING_INVALID'),
    ('no_authority', 'CONTAINER_WRITER_FENCE_SESSION_AUTHORITY_NOT_HELD'),
])
def test_controller_requires_actual_ancestry_start_bytes_and_authority(tmp_path, case, expected):
    engine = shutil.which('powershell.exe')
    assert engine
    manager_root = tmp_path / 'manager'
    manager_root.mkdir()
    canonical = manager_root / 'INSTALL_CANONICAL_PORTABLE.ps1'
    canonical.write_text(MANAGER, encoding='utf-8-sig')
    manifest = manager_root / 'portable-manifest.json'
    manifest.write_text(json.dumps({'fixture': True}), encoding='utf-8')
    (tmp_path / 'helper.ps1').write_text(HELPER, encoding='utf-8-sig')
    token = uuid.uuid4().hex + uuid.uuid4().hex
    payload = _active_payload(token=token, sources=['canonical_code_placement'])
    payload['status'] = 'PREPARED'
    payload['owner_kind'] = 'canonical_installer'
    payload['orchestrator_sha256'] = hashlib.sha256(canonical.read_bytes()).hexdigest()
    payload['session_authority_mutex_name'] = fence.session_authority_mutex_name(
        payload['session_id'], payload['attempt_id'], payload['orchestrator_sha256'],
        payload['replacement_transaction_id'], payload['writer_contract_sha256'])
    prepared = tmp_path / 'prepared.json'
    prepared.write_text(json.dumps({key: payload[key] for key in (
        'session_id', 'attempt_id', 'replacement_transaction_id', 'orchestrator_sha256', 'writer_contract_sha256')} |
        {'source_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}), encoding='utf-8')
    payload['prepared_receipt_path'] = str(prepared)
    payload['prepared_receipt_sha256'] = hashlib.sha256(prepared.read_bytes()).hexdigest()
    control = fence.canonical_control_root()
    active = _write_active(control, payload)
    payload_file = tmp_path / 'payload.json'
    payload_file.write_text(json.dumps(payload), encoding='utf-8')
    environment = dict(os.environ, CA_BINDING_REPO=str(ROOT), CA_BINDING_ROOT=str(tmp_path),
        CA_BINDING_CONTROL_ROOT=str(control), CA_BINDING_PAYLOAD=str(payload_file),
        CA_BINDING_TOKEN=token, CA_BINDING_CANONICAL=str(canonical), CA_BINDING_CASE=case)
    # This actual unrelated process mentions the same canonical path. It is
    # never the manager's ancestor and must not become an exclusion by text.
    spoof = subprocess.Popen([engine, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        f"# {canonical}\n$stop = Join-Path $env:CA_BINDING_ROOT 'spoof.stop'; $deadline = [DateTime]::UtcNow.AddSeconds(30); while(-not(Test-Path -LiteralPath $stop) -and [DateTime]::UtcNow -lt $deadline){{Start-Sleep -Milliseconds 100}}"], creationflags=subprocess.CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)
    environment['CA_BINDING_SPOOF_PID'] = str(spoof.pid)
    try:
        result = run_powershell([engine, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(canonical)],
            env=environment, timeout=30)
        (tmp_path / 'controller-stdout-private.txt').write_text(result.stdout, encoding='utf-8')
        (tmp_path / 'controller-stderr-private.txt').write_text(result.stderr, encoding='utf-8')
        if expected is None:
            assert result.returncode == 0, result.stdout + result.stderr
            assert 'verified_controller_selected' in result.stdout
        else:
            assert result.returncode != 0
            assert expected in result.stdout, result.stdout + result.stderr
    finally:
        (tmp_path / 'spoof.stop').write_text('done', encoding='ascii')
        spoof.wait(timeout=10)
        active.unlink(missing_ok=True)


def test_current_packet_uninstall_uses_the_verified_controller(tmp_path):
    # Existing disposable relay-shaped fixture, OS boundaries and assertions.
    original_run = portable._run
    def capture(*args, **kwargs):
        result = original_run(*args, **kwargs)
        (tmp_path / 'normal-parent-stdout-private.txt').write_text(result.stdout, encoding='utf-8')
        (tmp_path / 'normal-parent-stderr-private.txt').write_text(result.stderr, encoding='utf-8')
        return result
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(portable, '_run', capture)
        portable.test_normal_uninstall_real_removal_and_exact_recovery(tmp_path, 'success')


def test_retired_manager_uninstall_uses_its_own_canonical_identity(tmp_path):
    retired.test_retired_exact_old_code_removal_preserves_retirement_and_data(tmp_path, False)


@pytest.mark.parametrize('case', ['outside_scope', 'unprotected_journal'])
def test_protected_journal_os_seam_is_confined_to_the_fixture_root(tmp_path, case):
    engine = shutil.which('powershell.exe')
    assert engine
    # Only definitions are loaded; no host paths, journals or controller run.
    seam = portable.HELPER_OS
    driver = tmp_path / 'journal-boundary.ps1'
    source = r"""
$ErrorActionPreference='Stop'
. (Join-Path $env:CA_BINDING_REPO 'tools\bootstrap_integrity.ps1')
$UninstallAuditPath=Join-Path $env:CA_UNINSTALL_ROOT 'audit.json'
""" + seam + r"""
$native=& $Script:CAUninstallOriginalProtectionFunctions['Test-InstallationEvidencePrivileged']
if($native){throw 'fixture requires its existing nonprivileged host'}
if(-not(Test-InstallationEvidencePrivileged)){throw 'owned seam did not apply'}
$UninstallAuditPath=Join-Path (Split-Path -Parent $env:CA_UNINSTALL_ROOT) 'unprotected-journal-audit.json'
if((Test-InstallationEvidencePrivileged) -ne $native){throw 'seam escaped its root'}
if($env:CA_BINDING_CASE -ceq 'unprotected_journal') {
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:CA_BINDING_REPO 'INSTALL_THIS_PC.ps1'),[ref]$null,[ref]$null)
    $fn=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Write-ContainerSupportedRemovalJournal'},$true))
    if($fn.Count -ne 1){throw 'journal function not unique'}
    Invoke-Expression $fn[0].Extent.Text
    try {Write-ContainerSupportedRemovalJournal @();throw 'unprotected journal was accepted'}
    catch {if($_.Exception.Message -cne 'REMOVAL_JOURNAL_PROTECTED_AUTHORITY_REQUIRED'){throw}}
}
'journal_boundary_preserved'
"""
    driver.write_text(source, encoding='utf-8-sig')
    env = dict(os.environ, CA_BINDING_REPO=str(ROOT), CA_UNINSTALL_ROOT=str(tmp_path), CA_BINDING_CASE=case)
    result = run_powershell([engine, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(driver)], env=env, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'journal_boundary_preserved' in result.stdout
