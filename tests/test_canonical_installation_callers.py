"""Exercise canonical installer callers with real placement and recovery.

The existing owned relay/registry fixture supplies OS boundaries. These cases
run the canonical entrypoint and its child bootstrap, receipt validation,
integrity checks, and writer session authorization without replacing callers.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from tests.canonical_scheduler_fixture import (
    DURABLE_AUDIT_OBSERVER, PREPLACEMENT_OBSERVER, SCHEDULER_OS,
)
from tests.test_canonical_portable_uninstall import (
    _assert_one_live_relay, _assert_preserved_and_released, _install,
    _launch_relay, _live_preimage, _ps, _quote_fixture_executable, _setup, _sha, _tree,
)


def _bind_packet(source):
    """Rebind only a temporary packet after adapting its OS boundaries."""
    path = source / 'portable-manifest.json'
    manifest = json.loads(path.read_text())
    manifest['installer_sha256'] = _sha(source / 'INSTALL_CANONICAL_PORTABLE.ps1')
    manifest['helper_sha256'] = _sha(source / 'INSTALL_THIS_PC.ps1')
    files = [p for p in source.rglob('*') if p.is_file() and p != path]
    manifest['file_count_before_manifest'] = len(files)
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
    path.write_text(json.dumps(manifest), encoding='utf-8')


def _distinct_replacement(source):
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig')
    bypass = 'if (-not $DryRun.IsPresent -and (-not $testOverride -or $Uninstall.IsPresent -or $RestoreUninstallRecordPath)) {'
    assert text.count(bypass) == 1
    # The layout override also bypasses placement/restore admission in the
    # generic bootstrap fixture. Re-enable that production admission path for
    # this owned canonical session, preserving the real validator and arguments.
    # Elevation and ACL changes remain disabled by the original layout switch.
    text = text.replace(bypass, 'if (-not $DryRun.IsPresent) {')
    entered = '    $placementWriterFenceLease = Enter-ContainerPlacementWriterFence'
    assert text.count(entered) == 1
    text = text.replace(entered, entered + r'''
    $admission = @{ restore=$RestoreVerifiedReplacement.IsPresent; transaction_id=$WriterFenceReplacementTransactionId }
    [IO.File]::AppendAllText((Join-Path $env:CA_UNINSTALL_ROOT 'placement-admissions.jsonl'), (($admission | ConvertTo-Json -Compress) + [Environment]::NewLine))
''')
    helper.write_text(text, encoding='utf-8-sig')
    path = source / 'portable-manifest.json'
    manifest = json.loads(path.read_text())
    manifest['source_commit'] = 'c' * 40
    path.write_text(json.dumps(manifest), encoding='utf-8')
    (source / 'app/main.py').write_text('# distinct replacement code\n', encoding='utf-8')
    _bind_packet(source)


def _public_restore(tmp_path, env, source, install, receipt, digest, label='restore'):
    (tmp_path / 'expected-registry-preimage.json').write_bytes((tmp_path / 'registry.json').read_bytes())
    result = _ps(source / 'INSTALL_CANONICAL_PORTABLE.ps1', env,
                 '-SourceRoot', str(source), '-InstallRoot', str(install),
                 '-RestoreVerifiedReplacement', '-RestoreReceiptPath', str(receipt),
                 '-RestoreReceiptSha256', digest,
                 '-EvidencePath', str(tmp_path / f'{label}-audit.json'),
                 '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest')
    (tmp_path / f'{label}-stdout.log').write_text(result.stdout, encoding='utf-8')
    (tmp_path / f'{label}-stderr.log').write_text(result.stderr, encoding='utf-8')
    return result


def test_public_late_restore_uses_fresh_owner_preserves_history_and_is_repeatable(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    _distinct_replacement(source)
    history = install.parent / ('.current.rollback.' + 'd' * 32)
    history.mkdir()
    (history / 'preserved.txt').write_text('unrelated historical custody', encoding='utf-8')
    history_before = _tree(history)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        replaced = _install(tmp_path, env, source, install)
        assert replaced.returncode == 0, replaced.stderr
        original_audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        replacement = original_audit['code_replacement']
        receipt = Path(replacement['receipt_path'])
        receipt_before = receipt.read_bytes()
        new_code = _tree(install)
        product_calls = (tmp_path / 'product-calls.log').read_text().splitlines()
        _, original_runtime = _assert_one_live_relay(tmp_path, env)

        # Each invocation is a new native controller process, after the original
        # installer owner and its fence have ended. Its prepared proof is fresh.
        restored = _public_restore(tmp_path, env, source, install, receipt, replacement['receipt_sha256'])
        assert restored.returncode == 0, restored.stderr
        audit = json.loads((tmp_path / 'restore-audit.json').read_text(encoding='utf-8-sig'))
        assert audit['operation'] == 'RESTORE_VERIFIED_REPLACEMENT'
        assert audit['status'] == 'PASS_RESTORED_VERIFIED_DATA_PRESERVED'
        assert audit['code_replacement']['status'] == 'RESTORED'
        assert audit['code_replacement']['transaction_id'] == replacement['transaction_id']
        assert audit['code_replacement']['controller_transaction_id'] != replacement['transaction_id']
        evidence = json.loads(Path(audit['code_replacement']['restore_evidence_path']).read_text())
        assert evidence['status'] == 'PASS' and evidence['prior_code_exact'] is True
        assert evidence['failed_new_preserved'] is True
        assert _tree(install) == before['code']
        assert _tree(Path(evidence['failed_new_root'])) == new_code
        assert _tree(history) == history_before
        assert receipt.read_bytes() == receipt_before
        assert _tree(source) == before['source']
        assert (tmp_path / 'product-calls.log').read_text().splitlines()[len(product_calls):] == ['--remove-current-user-setup']
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert current['ProcessId'] != original_runtime['ProcessId']
        assert current['CommandLine'] == original_runtime['CommandLine']
        assert launches[-1]['fence_active'] is False
        prepared = list((Path(env['LOCALAPPDATA']) / 'KMTech/ContainerAudit/install-audit').glob('*-writer-prepared.json'))
        proofs = [json.loads(path.read_text(encoding='utf-8-sig')) for path in prepared]
        assert len(proofs) == 2
        assert len({p['session_id'] for p in proofs}) == len({p['attempt_id'] for p in proofs}) == 2
        _assert_preserved_and_released(env, protected)

        repeated = _public_restore(tmp_path, env, source, install, receipt, replacement['receipt_sha256'], 'repeat')
        assert repeated.returncode == 0, repeated.stderr
        repeat_audit = json.loads((tmp_path / 'repeat-audit.json').read_text(encoding='utf-8-sig'))
        assert repeat_audit['code_replacement']['status'] == 'ALREADY_RESTORED'
        assert repeat_audit['status'] == 'PASS_RESTORED_VERIFIED_DATA_PRESERVED'
        assert _tree(install) == before['code']
        assert _tree(history) == history_before and receipt.read_bytes() == receipt_before
        _assert_preserved_and_released(env, protected)
        _assert_one_live_relay(tmp_path, env)


@pytest.mark.parametrize('failure', ['receipt_hash', 'integrity_record', 'elevation_cancel', 'after_displace', 'after_restore'])
def test_public_late_restore_failure_preserves_exact_code_and_runtime(tmp_path, failure):
    env, source, install, protected = _setup(tmp_path)
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    call = '        & $winps @publicRestoreArguments'
    assert text.count(call) == 1
    if failure == 'elevation_cancel':
        # Cancellation at the external child-launch boundary, before code work.
        text = text.replace(call, "        throw (New-Object ComponentModel.Win32Exception 1223)")
    elif failure == 'after_displace':
        text = text.replace(call, "        $publicRestoreArguments += '-InjectRestoreFailureAfterDisplaceForTest'\n" + call)
    canonical.write_text(text, encoding='utf-8-sig')
    if failure == 'after_restore':
        helper = source / 'INSTALL_THIS_PC.ps1'
        body = helper.read_text(encoding='utf-8-sig')
        boundary = '        Write-BootstrapReplacementReceipt -Path $restoreEvidenceFull -Payload $evidence | Out-Null'
        assert body.count(boundary) == 1
        helper.write_text(body.replace(boundary, "        throw 'RESTORE_EVIDENCE_WRITE_FAILURE'"), encoding='utf-8-sig')
    _distinct_replacement(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        replaced = _install(tmp_path, env, source, install)
        assert replaced.returncode == 0, replaced.stderr
        original = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))['code_replacement']
        receipt = Path(original['receipt_path'])
        digest = original['receipt_sha256']
        if failure == 'receipt_hash':
            digest = '0' * 64
        if failure == 'integrity_record':
            # A legitimate reinstall can change this record without changing any
            # code bytes. An older receipt must still reject that exact drift.
            record = install / 'bootstrap-integrity.json'
            record.write_bytes(record.read_bytes() + b'\n')
        code_before = _tree(install)
        registry_before = json.loads((tmp_path / 'registry.json').read_text(encoding='utf-8-sig'))
        calls_before = (tmp_path / 'product-calls.log').read_bytes()
        _, runtime_before = _assert_one_live_relay(tmp_path, env)

        result = _public_restore(tmp_path, env, source, install, receipt, digest)

        assert result.returncode != 0
        assert _tree(install) == (before['code'] if failure == 'after_restore' else code_before)
        assert _sha(receipt) == original['receipt_sha256']
        assert _tree(source) == before['source']
        assert json.loads((tmp_path / 'registry.json').read_text(encoding='utf-8-sig')) == registry_before
        _assert_preserved_and_released(env, protected)
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert current['CommandLine'] == runtime_before['CommandLine']
        assert launches[-1]['fence_active'] is False
        if failure in {'receipt_hash', 'integrity_record'}:
            assert current['ProcessId'] == runtime_before['ProcessId']
            assert (tmp_path / 'product-calls.log').read_bytes() == calls_before
            assert not (tmp_path / 'restore-audit.json').exists()
        else:
            audit = json.loads((tmp_path / 'restore-audit.json').read_text(encoding='utf-8-sig'))
            assert audit['status'] == 'FAILED_RESTORE_RUNTIME_RECOVERED', result.stderr
            assert audit['rollback']['runtime_restored'] is True
            assert current['ProcessId'] != runtime_before['ProcessId']
            assert audit['code_replacement']['status'] == ('RESTORED' if failure == 'after_restore' else 'PENDING')


def test_canonical_fresh_onboarding_failure_reports_retained_verified_code(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    assert install.resolve().is_relative_to(tmp_path.resolve())
    shutil.rmtree(install)
    registry = tmp_path / 'registry.json'
    absent = {'exists': False, 'kind': '', 'data': ''}
    registry.write_text(json.dumps(absent), encoding='utf-8')
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    boundary = "function Product([string]$Root, [string]$Mode) {"
    assert text.count(boundary) == 1
    text = text.replace(boundary, boundary + "\n    if ($Mode -ceq '--onboard-current-user') { throw 'ENROLLMENT_IDENTITY_CONFLICT' }")
    canonical.write_text(text, encoding='utf-8-sig')
    _bind_packet(source)
    source_before = _tree(source)

    result = _install(tmp_path, env, source, install)

    assert result.returncode != 0
    audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
    assert audit['status'] == 'FAILED_RUNTIME_RESTORED_CODE_RETAINED'
    assert audit['code_placement'] == 'PASS_NEW_VERIFIED'
    assert audit['rollback']['runtime_restored'] is True
    assert 'ENROLLMENT_IDENTITY_CONFLICT' in result.stderr
    assert 'New verified code remains at ' + str(install) in ' '.join(result.stdout.split())
    assert {k: v for k, v in _tree(install).items() if k != 'bootstrap-integrity.json'} == source_before
    assert _tree(source) == source_before
    assert json.loads(registry.read_text(encoding='utf-8-sig')) == absent
    assert not (tmp_path / 'relay.ready').exists()
    _assert_preserved_and_released(env, protected)


def test_canonical_later_failure_restores_verified_old_tree_through_bound_child(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    quoted = _quote_fixture_executable(env)
    # The registry's canonical spelling and the live child's quoted spelling
    # are separate preimages; recovery must preserve each exactly.
    registry = tmp_path / 'registry.json'
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    boundary = "function Product([string]$Root, [string]$Mode) {"
    assert text.count(boundary) == 1
    # Fail an external product-mode boundary only after replacement committed.
    # The recovery caller and its arguments remain the actual product text.
    text = text.replace(boundary, boundary + "\n    if ($Mode -ceq '--onboard-current-user') { throw 'LATER_PRODUCT_BOUNDARY_FAILURE' }")
    canonical.write_text(text, encoding='utf-8-sig')
    _distinct_replacement(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        assert before['code']['app\\main.py'] != before['source']['app\\main.py']
        result = _install(tmp_path, env, source, install)
        assert result.returncode != 0
        assert (tmp_path / 'reinstall-audit.json').exists(), result.stderr
        audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        # Assert the recovery result before the injected-error text: an incorrect
        # caller digest/token must fail here as a contained rollback failure.
        assert audit['status'] == 'FAILED_ROLLED_BACK', audit['status']
        assert 'LATER_PRODUCT_BOUNDARY_FAILURE' in result.stderr
        assert audit['code_placement'] == 'REPLACED_VERIFIED'
        replacement = audit['code_replacement']
        assert replacement['status'] == 'RESTORED_LATER_PHASE_FAILURE'
        assert replacement['later_restore_surface'] == 'CONSUMED'
        receipt_path = Path(replacement['receipt_path'])
        receipt = json.loads(receipt_path.read_text(encoding='utf-8-sig'))
        restore_path = Path(replacement['restore_evidence_path'])
        restore = json.loads(restore_path.read_text(encoding='utf-8-sig'))
        assert _sha(receipt_path) == replacement['receipt_sha256']
        assert _sha(restore_path) == replacement['restore_evidence_sha256']
        assert restore['transaction_id'] == receipt['transaction_id']
        assert restore['receipt_sha256'] == replacement['receipt_sha256']
        assert restore['status'] == 'PASS'
        assert restore['prior_code_exact'] is True
        assert restore['failed_new_preserved'] is True
        admissions = [json.loads(line) for line in (tmp_path / 'placement-admissions.jsonl').read_text().splitlines()]
        assert [entry['restore'] for entry in admissions] == [False, True]
        assert all(entry['transaction_id'] == receipt['transaction_id'] for entry in admissions)
        assert _tree(install) == before['code']
        failed = install.parent / ('.current.failed.' + receipt['transaction_id'])
        assert {k: v for k, v in _tree(failed).items() if k != 'bootstrap-integrity.json'} == before['source']
        assert not Path(receipt['rollback_root']).exists()
        assert json.loads(registry.read_text(encoding='utf-8-sig')) == json.loads(before['registry'])
        assert _tree(source) == before['source']
        assert audit['rollback']['runtime_restored'] is True
        _assert_preserved_and_released(env, protected)
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert len(launches) == 2
        assert all(row['fence_active'] is False for row in launches)
        assert current['CommandLine'] == quoted
        assert child.poll() is not None


def test_canonical_replacement_crosses_stopped_and_restarted_writer_boundaries(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    _quote_fixture_executable(env)
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    bypass = """$writerBefore = if ($testMode) {
    [ordered]@{ present=$false; classification='TEST_BYPASS'; restore_required=$false }
}
else { Get-CanonicalWriterPreimageForQuiesce $install }"""
    assert text.count(bypass) == 1
    # Test layout normally bypasses the host scheduler. Supply an owned OS
    # scheduler instead, then use the real preimage function and caller branch.
    text = text.replace(bypass, SCHEDULER_OS + '\n$writerBefore = Get-CanonicalWriterPreimageForQuiesce $install')
    boundary = "function Product([string]$Root, [string]$Mode) {"
    assert text.count(boundary) == 1
    text = text.replace(boundary, boundary + PREPLACEMENT_OBSERVER)
    save = '    Move-Item $temp $Path -Force\n}'
    assert text.count(save) == 1
    text = text.replace(save, '    Move-Item $temp $Path -Force\n' + DURABLE_AUDIT_OBSERVER + '\n}')
    canonical.write_text(text, encoding='utf-8-sig')
    _distinct_replacement(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _install(tmp_path, env, source, install)
        assert result.returncode == 0, result.stderr
        audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        assert audit['status'] == 'TEST_ONLY_PARTIAL'
        assert audit['code_placement'] == 'REPLACED_VERIFIED'
        writer = audit['scheduled_writer']
        assert writer['preimage']['present'] is True
        assert writer['preimage']['enabled'] is True
        assert writer['preimage']['restore_required'] is True
        assert writer['disable_readback']['enabled'] is False
        stopped = writer['stop_proof']
        assert stopped['status'] == 'PASS'
        assert stopped['last_run_time_unchanged'] is True
        assert stopped['log_size_mtime_sha256_unchanged'] is True
        assert stopped['runtime_status_unchanged'] is True
        assert stopped['readback']['process_count'] == 0
        assert stopped['readback']['enabled'] is False
        resumed = writer['natural_trigger_proof']
        assert resumed['status'] == 'PASS'
        assert resumed['readback']['enabled'] is True
        assert resumed['readback']['binding_sha256'] == writer['preimage']['binding_sha256']
        assert resumed['readback']['log']['sha256'] != stopped['readback']['log']['sha256']
        assert resumed['readback']['runtime_status']['sha256'] != stopped['readback']['runtime_status']['sha256']
        events = [json.loads(line) for line in (tmp_path / 'scheduler-events.jsonl').read_text().splitlines()]
        disable = next(i for i, event in enumerate(events) if event['event'] == 'disable')
        first_mutation = next(i for i, event in enumerate(events) if event['event'] == 'product_mode')
        enable = next(i for i, event in enumerate(events) if event['event'] == 'enable')
        trigger = next(i for i, event in enumerate(events) if event['event'] == 'natural_trigger')
        terminals = [i for i, event in enumerate(events) if event['event'] == 'audit_saved' and event['detail']['completed']]
        assert terminals
        assert disable < first_mutation < enable < trigger < min(terminals)
        assert events[trigger]['detail']['fence_active'] is False
        assert events[first_mutation]['detail']['code_sha256'] == before['code']['app\\main.py']
        saves_before = [e['detail'] for e in events[:first_mutation] if e['event'] == 'audit_saved']
        assert saves_before[-1]['scheduled_writer']['stop_proof'] == stopped
        for i in terminals:
            assert events[i]['detail']['scheduled_writer']['natural_trigger_proof'] == resumed
        receipt = json.loads(Path(audit['code_replacement']['receipt_path']).read_text(encoding='utf-8-sig'))
        assert _tree(Path(receipt['rollback_root'])) == before['code']
        assert {k: v for k, v in _tree(install).items() if k != 'bootstrap-integrity.json'} == before['source']
        _assert_preserved_and_released(env, protected)
        launches, current = _assert_one_live_relay(tmp_path, env)
        assert len(launches) == 3
        assert [row['fence_active'] for row in launches] == [False, True, False]
        assert current['CommandLine'] == json.loads(before['registry'])['data']
        assert child.poll() is not None
