"""A naturally exited controller may be resumed only from its exact journal."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import time

import pytest

from tests.test_retired_portable_removal import _complete, _retired_fixture, _expected_evidence_tree
from tests.test_canonical_portable_uninstall import _ps, _sha, _tree


@pytest.fixture(autouse=True)
def _retain_crashed_controller_handles(monkeypatch):
    if os.name != 'nt':
        yield
        return
    import _winapi

    handles = []
    original_init = subprocess.Popen.__init__

    def retain_controller(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        if (kwargs.get('env') or {}).get('CA_RETIREMENT_CRASH') == '1':
            # Keep the exited fixture's process object alive so its PID cannot be
            # reused before resume checks. The controller and its mutex still exit.
            current = _winapi.GetCurrentProcess()
            handles.append(_winapi.DuplicateHandle(
                current, self._handle, current, 0, False, _winapi.DUPLICATE_SAME_ACCESS,
            ))

    monkeypatch.setattr(subprocess.Popen, '__init__', retain_controller)
    try:
        yield
    finally:
        for handle in handles:
            _winapi.CloseHandle(handle)


def _crash_fixture(tmp_path, phase, *, historical=False, pause_claim=False):
    fixture = _retired_fixture(tmp_path, historical=historical)
    env, old_source, manager, install, protected, receipt, marker = fixture
    script = manager / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = script.read_text(encoding='utf-8-sig')
    if pause_claim:
        claim = 'if ($retirementResume) { $retirementResumeClaim = Enter-RetirementResumeClaim $retirementResume }'
        assert text.count(claim) == 1
        text = text.replace(claim, claim + "\nif ($env:CA_RESUME_CLAIM_READY) {\n"
                            "    [IO.File]::WriteAllText($env:CA_RESUME_CLAIM_READY, 'claimed')\n"
                            "    $claimDeadline = [DateTime]::UtcNow.AddSeconds(60)\n"
                            "    while (-not (Test-Path -LiteralPath $env:CA_RESUME_CLAIM_RELEASE)) {\n"
                            "        if ([DateTime]::UtcNow -gt $claimDeadline) { throw 'FIXTURE_CLAIM_TIMEOUT' }\n"
                            "        Start-Sleep -Milliseconds 50\n    }\n}")
    before = False
    if phase in {'preimage', 'quiesced', 'release'}:
        status = {'preimage': 'PREIMAGE_SAVED', 'quiesced': 'UNINSTALL_RUNTIME_QUIESCED',
                  'release': 'UNINSTALL_AWAITING_FENCE_RELEASE'}[phase]
        needle = '    Move-Item $temp $Path -Force'
        injected = "\n    if ($env:CA_RETIREMENT_CRASH -ceq '1' -and $Path -ceq $auditPath -and $Value.status -ceq '" + status + "') { exit 97 }"
    elif phase == 'removed':
        needle = 'if ($LASTEXITCODE -ne 0) { throw "Code removal failed: $LASTEXITCODE" }'
        injected = "\n            if ($env:CA_RETIREMENT_CRASH -ceq '1') { exit 97 }"
    elif phase == 'release_authorized':
        needle = "        Stop-CanonicalWriterFenceRelease $releaseAuthorization\n        $canonicalWriterFenceActive = $false\n        $audit.status = if ($CompleteRetiredRemoval) { 'PASS_RETIRED_REMOVAL_DATA_PRESERVED' } else { 'PASS_UNINSTALLED_DATA_PRESERVED' }"
        injected = "        if ($env:CA_RETIREMENT_CRASH -ceq '1') { exit 97 }\n"
        before = True
    else:
        assert phase == 'released'
        needle = "        $audit.status = if ($CompleteRetiredRemoval) { 'PASS_RETIRED_REMOVAL_DATA_PRESERVED' } else { 'PASS_UNINSTALLED_DATA_PRESERVED' }"
        injected = "\n        if ($env:CA_RETIREMENT_CRASH -ceq '1') { exit 97 }"
    assert text.count(needle) == 1
    script.write_text(text.replace(needle, injected + needle if before else needle + injected), encoding='utf-8-sig')
    manifest_path = manager / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['installer_sha256'] = _sha(script)
    files = [p for p in manager.rglob('*') if p.is_file() and p != manifest_path]
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
    manifest_path.write_text(json.dumps(manifest))
    env['CA_RETIREMENT_CRASH'] = '1'
    crashed = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    assert crashed.returncode == 97, crashed.stdout + crashed.stderr
    env.pop('CA_RETIREMENT_CRASH')
    journals = []
    for path in (Path(env['CONTAINER_AUDIT_DATA_ROOT']) / 'install-audit').glob('canonical-portable-*.json'):
        if json.loads(path.read_text()).get('schema') == 'container-audit-canonical-portable-install-v2':
            journals.append(path)
    assert len(journals) == 1
    return fixture, journals[0]


@pytest.mark.parametrize('phase', ['preimage', 'quiesced', 'removed', 'release', 'release_authorized', 'released'])
def test_resume_after_controller_exit_and_duplicate_completion_preserve_retirement(tmp_path, phase):
    fixture, journal = _crash_fixture(tmp_path, phase)
    env, old_source, manager, install, protected, receipt, marker = fixture
    original = {p: p.read_bytes() for p in [*protected, receipt, marker, journal]}
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker, resume_path=journal)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not install.exists()
    assert all(p.read_bytes() == content for p, content in original.items())
    if phase == 'released':
        assert 'retirement_resume_status=ALREADY_COMPLETED_VERIFIED' in result.stdout
        completed_journal = journal
    else:
        report = json.loads((tmp_path / 'retirement-audit.json').read_text(encoding='utf-8-sig'))
        assert report['status'] == 'PASS_RETIRED_REMOVAL_DATA_PRESERVED'
        prior = json.loads(journal.read_text())
        assert report['retirement']['session_id'] != prior['retirement']['session_id']
        assert report['retirement']['attempt_id'] != prior['retirement']['attempt_id']
        assert report['retirement']['resume_receipt_sha256'] == _sha(journal)
        completed_journal = journal.parent / ('canonical-portable-' + report['run_id'] + '.json')
    before = _tree(Path(env['CONTAINER_AUDIT_DATA_ROOT']))
    replayed = _complete(tmp_path, env, old_source, manager, install, receipt, marker,
                         resume_path=completed_journal)
    assert replayed.returncode == 0, replayed.stdout + replayed.stderr
    assert 'retirement_resume_status=ALREADY_COMPLETED_VERIFIED' in replayed.stdout
    root = Path(env['CONTAINER_AUDIT_DATA_ROOT'])
    assert _tree(root) == _expected_evidence_tree(root, before, replayed)


@pytest.mark.parametrize('difference', ['journal_hash', 'active_request', 'active_receipt', 'retired_pair', 'live_owner', 'pid_reused', 'foreign_attempt'])
def test_resume_rejects_valid_but_foreign_or_live_evidence_without_mutation(tmp_path, difference):
    fixture, journal = _crash_fixture(tmp_path, 'quiesced')
    env, old_source, manager, install, protected, receipt, marker = fixture
    active = Path(env['CONTAINER_AUDIT_DATA_ROOT']) / 'direct_sync/control/container_audit_user_relay.stop.json'
    pins = {'resume_path': journal}
    if difference == 'journal_hash':
        pins['resume_pin'] = 'a' * 64
    elif difference == 'active_request':
        value = json.loads(active.read_text())
        value['request_id'] = 'a' * 32
        active.write_text(json.dumps(value))
    elif difference == 'active_receipt':
        path = active.parent.parent / 'status/current_user_removal.json'
        value = json.loads(path.read_text())
        value['relay_process']['request_id'] = 'a' * 32
        path.write_text(json.dumps(value))
    elif difference == 'retired_pair':
        value = json.loads(marker.read_text())
        value['request_id'] = 'a' * 32
        marker.write_text(json.dumps(value))
        value = json.loads(receipt.read_text())
        value['relay_process']['request_id'] = 'a' * 32
        receipt.write_text(json.dumps(value))
    elif difference in {'live_owner', 'pid_reused'}:
        probe = tmp_path / 'owner.ps1'
        probe.write_text("(Get-Process -Id " + str(os.getpid()) + ").StartTime.ToUniversalTime().ToString('o')", encoding='utf-8-sig')
        observed = _ps(probe, env)
        assert observed.returncode == 0, observed.stderr
        value = json.loads(journal.read_text())
        value['retirement']['owner_process_id'] = os.getpid()
        value['retirement']['owner_started_at_utc'] = (observed.stdout.strip() if difference == 'live_owner'
                                                       else '2000-01-01T00:00:00.0000000Z')
        journal.write_text(json.dumps(value))
    else:
        control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control/writer-session/active.json'
        probe = tmp_path / 'foreign.ps1'
        quote = lambda path: "'" + str(path).replace("'", "''") + "'"
        probe.write_text(
            '. ' + quote(old_source / 'tools/container_writer_fence.ps1') + '\n'
            + '$path = ' + quote(control) + '\n'
            + '$value = Get-Content $path -Raw | ConvertFrom-Json\n'
            + "$value.attempt_id = '" + 'a' * 32 + "'\n"
            + '$value.session_authority_mutex_name = Get-ContainerWriterSessionAuthorityMutexName '
            + '$value.session_id $value.attempt_id $value.orchestrator_sha256 $value.replacement_transaction_id $value.writer_contract_sha256\n'
            + '[IO.File]::WriteAllText($path, ($value | ConvertTo-Json -Depth 20))\n',
            encoding='utf-8-sig',
        )
        forged = _ps(probe, env)
        assert forged.returncode == 0, forged.stderr
    original = _tree(tmp_path)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker, **pins)
    assert result.returncode != 0
    assert 'RETIREMENT_' in result.stderr
    if difference == 'pid_reused':
        assert 'RETIREMENT_ORIGINAL_PID_REUSED' in result.stderr
    expected = (_expected_evidence_tree(tmp_path, original, result)
                if difference in {'active_receipt', 'active_request', 'foreign_attempt'} else original)
    assert _tree(tmp_path) == expected


def test_historical_d69_helper_can_resume_after_code_removal(tmp_path):
    fixture, journal = _crash_fixture(tmp_path, 'removed', historical=True)
    env, old_source, manager, install, protected, receipt, marker = fixture
    original = {p: p.read_bytes() for p in [*protected, receipt, marker, journal]}
    packet = _tree(old_source)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker, resume_path=journal)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not install.exists()
    assert _tree(old_source) == packet
    assert all(p.read_bytes() == content for p, content in original.items())


@pytest.mark.parametrize('phase', ['release', 'released'])
def test_resume_rejects_changed_receipt_even_after_owned_marker_was_removed(tmp_path, phase):
    fixture, journal = _crash_fixture(tmp_path, phase)
    env, old_source, manager, install, protected, receipt, marker = fixture
    path = Path(env['CONTAINER_AUDIT_DATA_ROOT']) / 'direct_sync/status/current_user_removal.json'
    value = json.loads(path.read_text())
    value['relay_process']['request_id'] = 'a' * 32
    path.write_text(json.dumps(value))
    original = _tree(tmp_path)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker, resume_path=journal)
    assert result.returncode != 0
    assert 'RETIREMENT_RESUME_ACTIVE_REQUEST_CHANGED' in result.stderr
    assert _tree(tmp_path) == _expected_evidence_tree(tmp_path, original, result)


@pytest.mark.parametrize('resume_arguments', [False, True])
def test_ordinary_uninstall_cannot_enter_retirement_resume(tmp_path, resume_arguments):
    fixture, journal = _crash_fixture(tmp_path, 'quiesced')
    env, old_source, manager, install, protected, receipt, marker = fixture
    args = ['-SourceRoot', str(old_source), '-InstallRoot', str(install), '-Uninstall',
            '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest']
    if resume_arguments:
        args += ['-ResumeRetirementReceiptPath', str(journal), '-ResumeRetirementReceiptSha256', _sha(journal)]
    original = _tree(tmp_path)
    result = _ps(old_source / 'INSTALL_CANONICAL_PORTABLE.ps1', env, *args)
    assert result.returncode != 0
    assert ('RETIREMENT_ARGUMENTS_REQUIRE_COMPLETE_RETIRED_REMOVAL' if resume_arguments
            else 'CANONICAL_STOP_MARKER_PREEXISTS') in result.stderr
    assert _tree(tmp_path) == original


def test_two_simultaneous_resumers_have_one_atomic_authority_winner(tmp_path):
    fixture, journal = _crash_fixture(tmp_path, 'quiesced', pause_claim=True)
    env, old_source, manager, install, protected, receipt, marker = fixture
    ready, release = tmp_path / 'claim.ready', tmp_path / 'claim.release'
    first_env = dict(env, CA_RESUME_CLAIM_READY=str(ready), CA_RESUME_CLAIM_RELEASE=str(release))
    original = {p: p.read_bytes() for p in [*protected, receipt, marker, journal]}
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(_complete, tmp_path, first_env, old_source, manager, install,
                                receipt, marker, resume_path=journal)
        try:
            deadline = time.monotonic() + 30
            while not ready.exists():
                if first.done():
                    failed = first.result()
                    pytest.fail(failed.stdout + failed.stderr)
                assert time.monotonic() < deadline, 'First resumer did not acquire the claim'
                time.sleep(0.05)
            claimed = _tree(tmp_path)
            second = _complete(tmp_path, env, old_source, manager, install, receipt, marker,
                               resume_path=journal)
            assert second.returncode != 0
            assert 'RETIREMENT_RESUME_AUTHORITY_ALREADY_EXISTS' in second.stderr
            assert _tree(tmp_path) == _expected_evidence_tree(tmp_path, claimed, second, claimant=True)
        finally:
            release.write_text('continue')
        result = first.result(timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not install.exists()
    assert all(p.read_bytes() == content for p, content in original.items())
