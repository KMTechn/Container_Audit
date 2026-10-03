"""A corrected installer produces recovery evidence and consumes it on rerun.

Code placement, hashes, receipts, journal writes, NTFS moves, product removal,
writer authority, and the persistent fixture relay are real. Registry, task,
token and protected-ACL observations are isolated operating-system boundaries.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from tests.powershell_contracts import run_powershell
from tests.test_canonical_installation_callers import _bind_packet, _distinct_replacement
from tests.test_canonical_portable_uninstall import (
    _assert_one_live_relay, _launch_relay, _live_preimage, _ps, _setup, _sha, _tree,
)


PROTECTED_OS = r'''
function Get-InstallationEvidenceControlRoot { return Join-Path $env:CA_UNINSTALL_ROOT 'protected-control' }
function Assert-InstallationEvidenceProtectedPath([string]$Path) {
    $owned=[IO.Path]::GetFullPath($env:CA_UNINSTALL_ROOT).TrimEnd('\')+'\'
    if (-not [IO.Path]::GetFullPath($Path).StartsWith($owned,[StringComparison]::OrdinalIgnoreCase)) {throw 'fixture escaped its owned NTFS root'}
    if (-not (Test-Path -LiteralPath $Path)) {throw 'fixture protected path absent'}
}
function Set-InstallationEvidenceAcl([string]$Path,[string]$Sid) { Assert-InstallationEvidenceProtectedPath $Path }
function New-InstallationProtectedDirectory([string]$Path,[string]$Sid) {
    [void](New-Item -ItemType Directory -Path $Path -Force)
    Assert-InstallationEvidenceProtectedPath $Path
}
function Get-BootstrapRelaySecurity([int]$ProcessId) {
    return [pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session_id=1;elevated=$false;integrity_level=8192}
}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter)
    if ($ClassName -ceq 'Win32_Process' -and (Test-Path (Join-Path $env:CA_UNINSTALL_ROOT 'relay.ready'))) {
        $observation=Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'relay-observation.json') -Raw|ConvertFrom-Json
        $observed=Get-Process -Id ([int]$observation.ProcessId) -ErrorAction SilentlyContinue
        if ($observed -and (-not $Filter -or $Filter -ceq ('ProcessId = '+$observed.Id))) {
            $observation|Add-Member -NotePropertyName CreationDate -NotePropertyValue $observed.StartTime
            return $observation
        }
    }
    return @()
}
'''


class _PrivateEnvironment(dict):
    def __repr__(self):
        return '<isolated process environment; values suppressed>'


def _fixture(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    old_profile=Path(env['LOCALAPPDATA'])
    short_profile=tmp_path/'L'
    assert old_profile.resolve().is_relative_to(tmp_path.resolve())
    assert short_profile.resolve().is_relative_to(tmp_path.resolve()) and not short_profile.exists()
    old_profile.rename(short_profile)
    protected=[short_profile/p.relative_to(old_profile) if p.is_relative_to(old_profile) else p for p in protected]
    env['LOCALAPPDATA']=str(short_profile)
    env['CA_UNINSTALL_CONTROL']=str(short_profile/'c')
    task_root = os.environ.get('KMTECH_TEST_CA_TASK_ROOT')
    preview = Path(task_root) / 'evidence/inventory-preview-rehearsal-producer.json' if task_root else None
    inventory = json.loads((preview if preview and preview.is_file() else source / 'tools/container_writer_sink_inventory.json').read_text())
    if any(inventory[key] for key in ('uncovered_direct_mutation_functions', 'caller_fence_reference_failures', 'powershell_guard_failures')):
        pytest.skip('requires a verified packet declaration; formal declarations are deliberately frozen')
    assert not any(inventory[key] for key in ('uncovered_direct_mutation_functions', 'caller_fence_reference_failures', 'powershell_guard_failures'))
    digest = inventory['inventory_sha256']
    (source / 'tools/container_writer_sink_inventory.json').write_text(json.dumps(inventory), encoding='utf-8')
    contract_path = source / 'tools/container_writer_session_contract.json'
    contract = json.loads(contract_path.read_text())
    contract['all_writer_fence']['writer_inventory_sha256'] = digest
    contract_path.write_text(json.dumps(contract), encoding='utf-8')
    fence_path = source / 'tools/container_writer_fence.ps1'
    text = fence_path.read_text(encoding='utf-8-sig')
    text = text.replace(r'KMTech\DirectSync\container_audit\control\writer-session', 'c')
    text = re.sub(r"(\$Script:ContainerWriterFenceInventorySha256 = ')[0-9a-f]{64}(')", lambda m: m[1] + digest + m[2], text)
    fence_path.write_text(text, encoding='utf-8-sig')
    manifest_path = source / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['writer_sink_inventory_sha256'] = _sha(source / 'tools/container_writer_sink_inventory.json')
    manifest['writer_sink_inventory_contract_sha256'] = digest
    manifest['writer_session_contract_sha256'] = _sha(contract_path)
    manifest['writer_fence_helper_sha256'] = _sha(fence_path)
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    _bind_packet(source)
    for file in source.rglob('*'):
        if file.is_file():
            shutil.copyfile(file, install / file.relative_to(source))
    proof = _ps(tmp_path / 'record.ps1', env)
    assert proof.returncode == 0, proof.stderr
    host = Path(env['CA_UNINSTALL_HOST'])
    text = host.read_text().replace('import writer_session_fence as fence', 'import writer_session_fence as fence\nfence.WRITER_INVENTORY_SHA256 = ' + repr(digest) + "\nfence.control_root = lambda *args, **kwargs: Path(os.environ['CA_UNINSTALL_CONTROL'])")
    text = text.replace("(direct / 'control/writer-session/active.json')", "(Path(os.environ['CA_UNINSTALL_CONTROL']) / 'active.json')")
    host.write_text(text, encoding='utf-8')
    old_tree = _tree(install)
    _distinct_replacement(source)
    evidence = tmp_path / 'protected-control/installation-evidence' / ('run-' + '1' * 32) / 'helper'
    evidence.mkdir(parents=True)
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    text=text.replace(' -WindowStyle Hidden -PassThru'," -WindowStyle Hidden -RedirectStandardOutput (Join-Path $env:CA_UNINSTALL_ROOT 'resumed-relay.stdout') -RedirectStandardError (Join-Path $env:CA_UNINSTALL_ROOT 'resumed-relay.stderr') -PassThru")
    text = text.replace("Join-Path $env:LOCALAPPDATA 'KMTech\\DirectSync\\container_audit\\control\\writer-session'", "Join-Path $env:LOCALAPPDATA 'c'")
    text = text.replace('. $BootstrapIntegrityFunctions\n', '. $BootstrapIntegrityFunctions\n' + PROTECTED_OS + '\n')
    text = text.replace('[int]$TimeoutSeconds=360', '[int]$TimeoutSeconds=5')
    # WinPS's evidence producer uses bounded ordinary NTFS paths. Keep fixture
    # evidence basenames short beneath the assigned D: test root.
    text = re.sub(r'^\$runId = .+$', "$runId = [Guid]::NewGuid().ToString('N').Substring(0,8)", text, flags=re.MULTILINE)
    text = text.replace("$auditRoot = Join-Path $activeDataRoot 'install-audit'", "$auditRoot = Join-Path $env:CA_UNINSTALL_ROOT 'a'")
    # Formal declarations stay frozen; this isolated packet needs its actual
    # unchanged bootstrap bytes bound before exercising the native entrypoint.
    text, count = re.subn(r"(\$ExpectedBootstrapIntegritySha256\s*=\s*')[0-9a-f]{64}(')",
                         lambda match: match[1] + _sha(source / 'tools/bootstrap_integrity.ps1') + match[2], text)
    assert count == 1
    # Only this owned fixture admits the native recovery reader in test layout.
    text = text.replace('if (-not $testMode -and -not $Uninstall -and -not $RestoreVerifiedReplacement',
                        'if (-not $Uninstall -and -not $RestoreVerifiedReplacement')
    text = text.replace('$wanted = Command $install', PROTECTED_OS + '\n$wanted = Command $install')
    receipt_assignment = '$replacementReceiptPath = Join-Path $auditRoot "canonical-portable-$runId-replacement.json"'
    assert text.count(receipt_assignment) == 1
    text = text.replace(receipt_assignment, receipt_assignment + '\n$replacementReceiptPath=Join-Path $env:CA_RESUME_EVIDENCE "replacement-receipt.json"')
    text = text.replace('if (-not $testMode -and $codeRestoreNeeded -and -not $RestoreVerifiedReplacement)',
                        'if ($codeRestoreNeeded -and -not $RestoreVerifiedReplacement)')
    text = text.replace("    $child=Invoke-InstallationEvidenceChild 'record-rollback-continuation'",
                        "    if($testMode){$args+='-AllowNoncanonicalLayoutForTest'}\n    $child=Invoke-InstallationEvidenceChild 'record-rollback-continuation'")
    # An external product failure occurs after real replacement. The first
    # restore child is interrupted before any restore move; rerun is unchanged.
    text = text.replace("        '--onboard-current-user' { 'onboard' }", "        '--onboard-current-user' { if(Test-Path (Join-Path $env:CA_UNINSTALL_ROOT 'fail-forward')) {throw 'FIXTURE_AFTER_REPLACEMENT'}; 'onboard' }")
    canonical.write_text(text, encoding='utf-8-sig')
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig')
    text = text.replace(r'KMTech\DirectSync\container_audit\control\writer-session', 'c')
    text = text.replace('$testOverride = (', PROTECTED_OS + r'''
function Test-InstallationEvidencePrivileged {return @((Get-PSCallStack)|Where-Object {$_.FunctionName -ceq 'Complete-ContainerRollbackContinuation'}).Count -gt 0}
function Read-ContainerRollbackRunPreimage {return Get-Content (Join-Path $env:CA_UNINSTALL_ROOT 'registry.json') -Raw|ConvertFrom-Json}
function Assert-ContainerStartupUpdateTrust([string]$Root) {Assert-InstallationEvidenceProtectedPath $Root}
function Set-HardenedCodeAcl([string]$Path,[switch]$Recursive) {Assert-InstallationEvidenceProtectedPath $Path}
function Assert-HardenedCodeAcl([string]$Path) {Assert-InstallationEvidenceProtectedPath $Path}
function Assert-ProtectedCodeAncestors([string]$Path) {Assert-InstallationEvidenceProtectedPath $Path}
function Get-ContainerStartupUpdateTaskSpec([string]$Root,[string]$Sid) {
    return [pscustomobject]@{name=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24))}
}
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName)
    $path=Join-Path $env:CA_UNINSTALL_ROOT 'startup-task.json'
    if(Test-Path -LiteralPath $path){return Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}
    return $null
}
function Unregister-ScheduledTask {
    param([string]$TaskName,[switch]$Confirm)
    if($TaskName -cne ('KMTech.ContainerAudit.StartupUpdate.'+('a'*24))){throw 'fixture task name differs'}
    Remove-Item -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'startup-task.json')
}
function Initialize-ContainerStartupUpdate([string]$Root) {
    $control=Join-Path (Split-Path -Parent $Root) 'update-control'
    foreach($name in @('policy.json','active.json','transition.json')){
        [IO.File]::WriteAllText((Join-Path $control $name),('{"sha":"'+('c'*40)+'"}'))
    }
    [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'startup-task.json'),'{"State":"Ready"}')
}
$Script:InstallationEvidenceRoot=$env:CA_RESUME_EVIDENCE
''' + '\n$testOverride = (')
    text = text.replace('-not $WriterFenceDelegationToken -or $testOverride)', '-not $WriterFenceDelegationToken)')
    text = text.replace('-or $RestoreVerifiedReplacement -or $testOverride) {throw \'Rollback completion',
                        '-or $RestoreVerifiedReplacement) {throw \'Rollback completion')
    text = text.replace('if ($RestoreVerifiedReplacement.IsPresent) {', "if ($RestoreVerifiedReplacement.IsPresent) {\n    if(Test-Path (Join-Path $env:CA_UNINSTALL_ROOT 'fail-restore')) {throw 'FIXTURE_INTERRUPTED_ROLLBACK'}")
    condition = "if (-not $testOverride -and\n            (Test-Path -LiteralPath (Join-Path $installRootFull 'app\\auto-update-settings.json') -PathType Leaf))"
    assert text.count(condition) == 1
    text = text.replace(condition, 'if ($true)')
    helper.write_text(text, encoding='utf-8-sig')
    env['CA_RESUME_EVIDENCE'] = str(evidence)
    control=install.parent/'update-control'
    control.mkdir()
    for name in ('policy.json', 'active.json', 'transition.json'):
        (control/name).write_text(json.dumps({'sha': 'a'*40}), encoding='utf-8')
    _bind_packet(source)
    return _PrivateEnvironment(env), source, install, protected, old_tree


def _invoke(tmp_path, env, source, install, engine, label, *extra):
    binary = shutil.which(engine)
    if not binary:
        pytest.skip(engine + ' unavailable')
    arguments=['-SourceRoot',str(source),'-InstallRoot',str(install),'-EvidencePath',str(tmp_path/(label+'.json')),
               '-AllowNoncanonicalLayoutForTest','-SkipSignatureValidationForTest',*extra]
    def literal(value): return "'"+str(value).replace("'","''")+"'"
    parameters=' '.join(value if re.fullmatch(r'-[A-Za-z][A-Za-z0-9]*',value) else literal(value) for value in arguments)
    command="[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;& "+literal(source/'INSTALL_CANONICAL_PORTABLE.ps1')+' '+parameters+';if(-not $?){exit 1};exit 0'
    stdout_path=tmp_path/(label+'-stdout.log');stderr_path=tmp_path/(label+'-stderr.log')
    # Real resident descendants can retain inherited handles. File capture lets
    # this finite controller finish independently of its persistent relay.
    with stdout_path.open('wb') as stdout,stderr_path.open('wb') as stderr:
        child=subprocess.Popen([binary,'-NoLogo','-NoProfile','-NonInteractive','-Command',command],env=env,
                               stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW)
        code=child.wait(timeout=90)
    result=subprocess.CompletedProcess(child.args,code,stdout_path.read_text(encoding='utf-8'),stderr_path.read_text(encoding='utf-8'))
    return result


def _produce_pending(tmp_path, env, source, install, engine):
    for name in ('fail-forward', 'fail-restore'):
        (tmp_path / name).touch()
    failed = _invoke(tmp_path, env, source, install, engine, 'interrupted')
    assert failed.returncode != 0
    assert (tmp_path / 'interrupted.json').exists(), failed.stdout + failed.stderr
    audit = json.loads((tmp_path / 'interrupted.json').read_text(encoding='utf-8-sig'))
    assert 'FIXTURE_AFTER_REPLACEMENT' in json.dumps(audit['failure'])
    assert audit['code_replacement']['prestate'] == 'VERIFIED_REPLACE'
    records = list((tmp_path / 'protected-control/rollback-continuations').glob('*/continuation-journal.json'))
    assert len(records) == 1, failed.stdout + failed.stderr
    record = json.loads(records[0].read_text(encoding='utf-8-sig'))
    assert record['new_manifest_sha256'] == _sha(install / 'portable-manifest.json')
    receipt = Path(record['receipt_path'])
    assert _sha(receipt) == record['receipt_sha256']
    assert receipt.read_bytes() == Path(record['receipt_binding_path']).read_bytes()
    for name in ('fail-forward', 'fail-restore'):
        (tmp_path / name).unlink()
    return records[0], record


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_corrected_installer_resumes_its_pending_ntfs_rollback_on_rerun(tmp_path, engine):
    env, source, install, protected, old_tree = _fixture(tmp_path)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        journal, record = _produce_pending(tmp_path, env, source, install, engine)
        journal_bytes = journal.read_bytes()
        receipt_bytes = Path(record['receipt_path']).read_bytes()
        new_tree = _tree(install)
        baseline = os.environ.get('CA_RESUME_BASELINE_CANONICAL')
        if baseline:
            text=Path(baseline).read_text(encoding='utf-8-sig')
            from tests.test_canonical_portable_uninstall import OS_BOUNDARIES
            text=text.replace('$wanted = Command $install',OS_BOUNDARIES+'\n'+PROTECTED_OS+'\n$wanted = Command $install')
            text=text.replace("Join-Path $env:LOCALAPPDATA 'KMTech\\DirectSync\\container_audit\\control\\writer-session'","Join-Path $env:LOCALAPPDATA 'c'")
            text=re.sub(r"(\$ExpectedBootstrapIntegritySha256\s*=\s*')[0-9a-f]{64}(')",lambda m:m[1]+_sha(source/'tools/bootstrap_integrity.ps1')+m[2],text)
            (source/'INSTALL_CANONICAL_PORTABLE.ps1').write_text(text,encoding='utf-8-sig')
            _bind_packet(source)
        planned = _invoke(tmp_path, env, source, install, engine, 'plan', '-PlanOnly')
        assert planned.returncode == 0 and 'rollback_resume_status=VERIFIED_PENDING' in planned.stdout, planned.stderr
        assert _tree(install) == new_tree
        resumed = _invoke(tmp_path, env, source, install, engine, 'resumed')
        assert resumed.returncode == 0 and 'rollback_resume_status=COMPLETE' in resumed.stdout, resumed.stdout + resumed.stderr
        assert _tree(install) == old_tree
        assert _tree(install.parent / ('.current.failed.' + record['transaction_id'])) == new_tree
        assert json.loads((tmp_path / 'registry.json').read_text()) == json.loads(before['registry'])
        assert journal.read_bytes() == journal_bytes and Path(record['receipt_path']).read_bytes() == receipt_bytes
        assert (journal.parent / 'continuation-completed.json').exists()
        assert not (tmp_path/'startup-task.json').exists()
        for name in ('policy.json','active.json','transition.json'):
            assert json.loads((install.parent/'update-control'/name).read_text()) == {'sha':'a'*40}
        assert all(p.read_bytes() == b'protected-fixture-must-be-preserved' for p in protected)
        _assert_one_live_relay(tmp_path, env)
        settled = _invoke(tmp_path, env, source, install, engine, 'settled-plan', '-PlanOnly')
        assert settled.returncode == 0 and 'rollback_resume_status=NOT_FOUND' in settled.stdout, settled.stderr


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('tamper', ['receipt', 'journal_manifest', 'old_tree', 'new_tree', 'startup_preimage'])
def test_resume_mismatch_refuses_before_any_mutation(tmp_path, engine, tamper):
    env, source, install, protected, _ = _fixture(tmp_path)
    with _launch_relay(tmp_path, env) as child:
        _live_preimage(tmp_path, env, source, install, child)
        journal, record = _produce_pending(tmp_path, env, source, install, engine)
        if tamper == 'receipt':
            with Path(record['receipt_path']).open('ab') as stream:
                stream.write(b' ')
        elif tamper == 'journal_manifest':
            value = dict(record, old_manifest_sha256='0' * 64)
            journal.write_text(json.dumps(value), encoding='utf-8')
        elif tamper == 'startup_preimage':
            receipt=json.loads(Path(record['receipt_path']).read_text(encoding='utf-8-sig'))
            (Path(receipt['startup_update_preimage'])/'active.json').write_text('{"sha":"tampered"}', encoding='utf-8')
        else:
            selected = install if tamper == 'new_tree' else Path(json.loads(Path(record['receipt_path']).read_text(encoding='utf-8-sig'))['rollback_root'])
            (selected / 'app/main.py').write_text('# tampered tree\n', encoding='utf-8')
        state = _tree(tmp_path)
        refused = _invoke(tmp_path, env, source, install, engine, 'refused')
        assert refused.returncode != 0 and '변경하지 않았습니다' in refused.stderr, refused.stdout + refused.stderr
        after = _tree(tmp_path)
        # Captured process output is test evidence; product state must be exact.
        for name in ('refused-stdout.log', 'refused-stderr.log'):
            after.pop(name, None)
        assert after == state
        assert not (tmp_path / 'refused.json').exists()
        assert all(p.read_bytes() == b'protected-fixture-must-be-preserved' for p in protected)
