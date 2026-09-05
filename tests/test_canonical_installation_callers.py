"""Exercise canonical installer callers with real placement and recovery.

The existing owned relay/registry fixture supplies OS boundaries. These cases
run the canonical entrypoint and its child bootstrap, receipt validation,
integrity checks, and writer session authorization without replacing callers.
"""
from __future__ import annotations

import json
from pathlib import Path

from tests.canonical_scheduler_fixture import (
    DURABLE_AUDIT_OBSERVER, PREPLACEMENT_OBSERVER, SCHEDULER_OS,
)
from tests.test_canonical_portable_uninstall import (
    _assert_one_live_relay, _assert_preserved_and_released, _finish, _install,
    _launch_relay, _live_preimage, _quote_fixture_executable, _setup, _sha, _tree,
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
    child = _launch_relay(tmp_path, env)
    before = _live_preimage(tmp_path, env, source, install, child)
    assert before['code']['app\\main.py'] != before['source']['app\\main.py']
    try:
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
    finally:
        _finish(tmp_path, child)


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
    child = _launch_relay(tmp_path, env)
    before = _live_preimage(tmp_path, env, source, install, child)
    try:
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
    finally:
        _finish(tmp_path, child)
