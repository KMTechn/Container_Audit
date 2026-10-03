"""Exercise canonical installer callers with real placement and recovery.

The existing owned relay/registry fixture supplies OS boundaries. These cases
run the canonical entrypoint and its child bootstrap, receipt validation,
integrity checks, and writer session authorization without replacing callers.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import ctypes

import pytest
from tests.powershell_contracts import run_functions

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
    if '-not $RecordRollbackContinuationAuthority -and -not $DryRun.IsPresent' in text:
        bypass = bypass.replace('if (-not $DryRun.IsPresent','if (-not $RecordRollbackContinuationAuthority -and -not $DryRun.IsPresent')
    assert text.count(bypass) == 1
    # The layout override also bypasses placement/restore admission in the
    # generic bootstrap fixture. Re-enable that production admission path for
    # this owned canonical session, preserving the real validator and arguments.
    # Elevation and ACL changes remain disabled by the original layout switch.
    text = text.replace(bypass, 'if (-not $RecordRollbackContinuationAuthority -and -not $DryRun.IsPresent) {')
    entered = '    . (Get-InstallationVerifiedScript $WriterFenceHelperPath $ExpectedWriterFenceHelperSha256)'
    assert text.count(entered) == 1
    helper_loaded = "    . (Get-InstallationVerifiedScript $writerFenceHelperFull $ExpectedWriterFenceHelperSha256 'Production placement writer fence helper byte pin differs.')"
    assert text.count(helper_loaded) == 1
    text = text.replace(helper_loaded, helper_loaded + r'''
    if ($testOverride) {
        function Get-ContainerWriterFenceProfileLocalAppDataRoot {
            param([string]$OperatorSid)
            return $env:LOCALAPPDATA
        }
        $Script:ContainerWriterFenceAdmissionMutexName = $env:KMTECH_TEST_CA_WRITER_MUTEX
    }
''')
    text = text.replace(entered, r'''
    $admission = @{ restore=$RestoreVerifiedReplacement.IsPresent; transaction_id=$WriterFenceReplacementTransactionId }
    [IO.File]::AppendAllText((Join-Path $env:CA_UNINSTALL_ROOT 'placement-admissions.jsonl'), (($admission | ConvertTo-Json -Compress) + [Environment]::NewLine))
''' + entered + '\n    $Script:ContainerWriterFenceAdmissionMutexName = $env:KMTECH_TEST_CA_WRITER_MUTEX')
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


def test_operator_profile_mismatch_stops_before_code_and_explains_retry(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    _distinct_replacement(source)
    installer = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = installer.read_text(encoding='utf-8-sig')
    original = "'-OperatorLocalAppDataRoot',$lad,\n            '-OperatorSid',$operatorSid,"
    assert text.count(original) == 1
    installer.write_text(text.replace(original, "'-OperatorLocalAppDataRoot',(Join-Path $lad 'wrong-profile'),\n            '-OperatorSid',$operatorSid,"), encoding='utf-8-sig')
    _bind_packet(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _install(tmp_path, env, source, install)
        assert result.returncode != 0
        assert '설치 코드 배치 전 중단' in result.stderr
        assert 'CONTAINER_OPERATOR_PROFILE_ROOT_MISMATCH' in result.stderr
        assert '문의 코드 CA-' in result.stderr
        assert '다시 확인' in result.stderr and '기존 설치본과 기록' in result.stderr
        audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        assert audit['code_placement'] == 'NOT_STARTED'
        assert _tree(install) == before['code']


@pytest.mark.parametrize('code', [
    'CONTAINER_OPERATOR_PROFILE_ROOT_MISMATCH',
    'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING',
])
def test_elevation_failure_readback_reaches_canonical_parent_without_real_uac(tmp_path, code):
    if ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('parent forwarding path requires a non-elevated token')
    log = tmp_path / 'elevated.jsonl'
    log.write_text(json.dumps({
        'captured_at': '2026-09-23T00:00:00Z', 'process_id': 4242,
        'elevated': True, 'status': 'PREFLIGHT_FAILED', 'message': code,
    }) + '\n', encoding='utf-8')
    result = run_functions(tmp_path, Path(__file__).resolve().parents[1] / 'INSTALL_THIS_PC.ps1',
                           ['ConvertTo-ProcessArgument', 'Invoke-SelfElevated'], r'''
$BootstrapScriptPath='C:\packet\INSTALL_THIS_PC.ps1'
$BootstrapBoundParameters=@{}
$ElevationLogPath=$env:CA_FAKE_ELEVATION_LOG
function Get-StrictFullPath([string]$Value,[string]$Purpose) { return [IO.Path]::GetFullPath($Value) }
function Assert-NoReparsePoint([string]$Value,[string]$Purpose) { }
function Start-Process {
    param($FilePath,$Verb,$ArgumentList,[switch]$Wait,[switch]$PassThru)
    if ($Verb -cne 'RunAs') { throw 'elevation invocation changed' }
    return [pscustomobject]@{ Id=4242; ExitCode=1 }
}
Invoke-SelfElevated
''', values={'CA_FAKE_ELEVATION_LOG': str(log)})
    assert result.returncode == 1
    assert f'code_placement_preflight_failure={code}' in result.stdout


@pytest.mark.parametrize(('session_offset', 'code', 'message', 'after_placement'), [
    (1, 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING',
     '같은 PC 의 다른 Windows 사용자 세션에서 이적 검사 프로그램이 실행 중입니다. 그 사용자를 로그아웃한 뒤 다시 설치하세요.', False),
    (0, 'CONTAINER_PLACEMENT_CHILD_FAILED', '권한 상승 작업이 결과 기록 없이 비정상 종료됐습니다.', False),
    (None, 'CONTAINER_PLACEMENT_CHILD_FAILED', '권한 상승 작업이 결과 기록 없이 비정상 종료됐습니다.', True),
], ids=['other_session', 'same_session', 'after_placement'])
def test_replacement_process_session_failure_reaches_operator_and_preserves_code(
        tmp_path, session_offset, code, message, after_placement):
    env, source, install, protected = _setup(tmp_path)
    _distinct_replacement(source)
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig')
    marker = '$testOverride = ('
    assert text.count(marker) == 1
    injected = r'''
function Get-CimInstance {
    return [pscustomobject]@{
        ProcessId=($PID + 100000)
        ExecutablePath=(Join-Path $InstallRoot 'runtime\pythonw.exe')
        CommandLine='fixture product process'
        SessionId=([Diagnostics.Process]::GetCurrentProcess().SessionId + SESSION_OFFSET)
    }
}
'''.replace('SESSION_OFFSET', str(session_offset))
    if after_placement:
        injected = 'function Get-CimInstance { return @() }\n'
        placed = "                $bootstrapStatus = 'REPLACED_VERIFIED'"
        assert text.count(placed) == 1
        text = text.replace(placed, placed + "\n                throw 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING'")
    # Exercise the real classified-log branch inside the owned test packet;
    # the layout override still prevents elevation and machine ACL changes.
    log_branch = "        if (-not $testOverride) {\n            try { Write-ElevationLog 'PREFLIGHT_FAILED' $failureCode }"
    has_classified_log_branch = log_branch in text
    if has_classified_log_branch:
        assert text.count(log_branch) == 1
        text = text.replace(log_branch, log_branch.replace('if (-not $testOverride)', 'if ($true)'))
        failed_log = "    } elseif (-not $testOverride) {\n        Write-ElevationLog 'FAILED' ($_.Exception.GetType().Name)"
        assert text.count(failed_log) == 1
        text = text.replace(failed_log, failed_log.replace('elseif (-not $testOverride)', 'elseif ($true)'))
    helper.write_text(text.replace(marker, injected + marker), encoding='utf-8-sig')
    _bind_packet(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _install(tmp_path, env, source, install)
        assert result.returncode != 0
        assert code in result.stderr, result.stderr
        assert message in result.stderr, result.stderr
        assert '문의 코드 CA-' in result.stderr
        assert '기존 설치본과 기록' in result.stderr and '다른 업무를 계속' in result.stderr
        audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        assert audit['code_placement'] == 'NOT_STARTED'
        assert _tree(install) == before['code']
        _assert_preserved_and_released(env, protected)
        if session_offset:
            logs = list((Path(env['LOCALAPPDATA']) / 'KMTech').rglob('*-elevated.jsonl'))
            assert len(logs) == 1
            last = json.loads(logs[0].read_text(encoding='utf-8').splitlines()[-1])
            assert last['status'] == 'PREFLIGHT_FAILED' and last['message'] == code
        if after_placement:
            failed = list(install.parent.glob('.current.failed.*'))
            assert len(failed) == 1
            assert (failed[0] / 'app/main.py').read_bytes() == (source / 'app/main.py').read_bytes()
            logs = list((Path(env['LOCALAPPDATA']) / 'KMTech').rglob('*-elevated.jsonl'))
            if has_classified_log_branch:
                assert len(logs) == 1
                assert json.loads(logs[0].read_text(encoding='utf-8').splitlines()[-1])['status'] == 'FAILED'


@pytest.mark.parametrize(('session_offset', 'classify', 'self_process', 'expected'), [
    (1, True, False, 'CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING'),
    (0, True, False, 'Replacement restore requires zero Container product processes.'),
    (1, False, False, 'Replacement restore requires zero Container product processes.'),
    (None, True, False, 'Replacement restore requires zero Container product processes.'),
    (1, True, True, 'QUIESCENT'),
])
def test_quiescence_classifies_only_other_session_preflight(
        tmp_path, session_offset, classify, self_process, expected):
    session = '' if session_offset is None else (
        f'SessionId=([Diagnostics.Process]::GetCurrentProcess().SessionId + {session_offset});')
    process_id = '$PID' if self_process else '($PID + 100000)'
    switch = '-ClassifyOtherSessionPreflight' if classify else ''
    result = run_functions(
        tmp_path, Path(__file__).resolve().parents[1] / 'INSTALL_THIS_PC.ps1',
        ['Assert-ContainerReplacementRestoreQuiescent'], r'''
function Get-StrictFullPath([string]$Value,[string]$Purpose) { return [IO.Path]::GetFullPath($Value) }
function Get-CimInstance {
    return [pscustomobject]@{ ProcessId=PROCESS_ID; ExecutablePath='C:\fixture\current\runtime\pythonw.exe'; CommandLine='fixture'; SESSION }
}
try {
    Assert-ContainerReplacementRestoreQuiescent -CurrentRoot 'C:\fixture\current' -SkipOwnedTaskCheckForGuardedTest CLASSIFY
    Write-Output 'QUIESCENT'
} catch { Write-Output $_.Exception.Message }
'''.replace('PROCESS_ID', process_id).replace('SESSION', session).replace('CLASSIFY', switch),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(('exception', 'code'), [
    ('[UnauthorizedAccessException]::new("denied")', 'CONTAINER_PLACEMENT_ACCESS_DENIED'),
    ('[IO.DirectoryNotFoundException]::new("missing")', 'CONTAINER_PLACEMENT_PATH_UNAVAILABLE'),
    ('[IO.IOException]::new("io")', 'CONTAINER_PLACEMENT_FILE_IO_FAILED'),
    ('[InvalidOperationException]::new("odd")', 'CONTAINER_PLACEMENT_UNCLASSIFIED'),
])
def test_code_placement_preflight_classifies_nonstandard_errors(tmp_path, exception, code):
    result = run_functions(
        tmp_path, Path(__file__).resolve().parents[1] / 'INSTALL_THIS_PC.ps1',
        ['Get-CodePlacementPreflightFailureCode'],
        f'try {{ throw {exception} }} catch {{ Get-CodePlacementPreflightFailureCode $_ }}',
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == code


def test_code_placement_preflight_classifies_powershell_missing_path(tmp_path):
    result = run_functions(
        tmp_path, Path(__file__).resolve().parents[1] / 'INSTALL_THIS_PC.ps1',
        ['Get-CodePlacementPreflightFailureCode'], r'''
try {
    Get-Item -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'missing-path') -ErrorAction Stop
} catch {
    Get-CodePlacementPreflightFailureCode $_
}
''',
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'CONTAINER_PLACEMENT_PATH_UNAVAILABLE'


@pytest.mark.parametrize(('log_contents', 'child_exit', 'expected'), [
    ('{invalid json', 1, 'CONTAINER_PLACEMENT_LOG_UNREADABLE'),
    (None, 1, 'CONTAINER_PLACEMENT_CHILD_FAILED'),
    (None, 42, 'CONTAINER_PLACEMENT_LOG_WRITE_FAILED'),
])
def test_elevation_log_failure_and_abnormal_child_have_safe_code(tmp_path, log_contents, child_exit, expected):
    if ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('parent forwarding path requires a non-elevated token')
    log = tmp_path / 'elevated.jsonl'
    if log_contents is not None:
        log.write_text(log_contents, encoding='utf-8')
    result = run_functions(
        tmp_path, Path(__file__).resolve().parents[1] / 'INSTALL_THIS_PC.ps1',
        ['ConvertTo-ProcessArgument', 'Invoke-SelfElevated'], r'''
$BootstrapScriptPath='C:\packet\INSTALL_THIS_PC.ps1'
$BootstrapBoundParameters=@{}
$ElevationLogPath=$env:CA_FAKE_ELEVATION_LOG
function Get-StrictFullPath([string]$Value,[string]$Purpose) { return [IO.Path]::GetFullPath($Value) }
function Assert-NoReparsePoint([string]$Value,[string]$Purpose) { }
function Start-Process {
    param($FilePath,$Verb,$ArgumentList,[switch]$Wait,[switch]$PassThru)
    return [pscustomobject]@{ Id=4242; ExitCode=[int]$env:CA_FAKE_CHILD_EXIT }
}
Invoke-SelfElevated
''', values={'CA_FAKE_ELEVATION_LOG': str(log), 'CA_FAKE_CHILD_EXIT': str(child_exit)},
    )
    assert result.returncode == child_exit
    assert f'code_placement_preflight_failure={expected}' in result.stdout


def test_unclassified_child_preflight_error_reaches_canonical_parent(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    _distinct_replacement(source)
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig')
    anchor = '        $placementWriterFenceLease = Enter-ContainerPlacementWriterFence'
    assert text.count(anchor) == 1
    helper.write_text(text.replace(anchor, "        throw 'unusual preflight fault'\n" + anchor), encoding='utf-8-sig')
    _bind_packet(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _install(tmp_path, env, source, install)
        assert result.returncode != 0
        assert 'CONTAINER_PLACEMENT_UNCLASSIFIED' in result.stderr
        assert '분류 안 된 오류' in result.stderr
        assert '문의 코드 CA-' in result.stderr
        assert 'unusual preflight fault' not in result.stderr
        audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        assert audit['code_placement'] == 'NOT_STARTED'
        assert _tree(install) == before['code']


def test_preflight_log_write_failure_has_own_operator_guidance(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    _distinct_replacement(source)
    helper = source / 'INSTALL_THIS_PC.ps1'
    text = helper.read_text(encoding='utf-8-sig')
    admission = '        $placementWriterFenceLease = Enter-ContainerPlacementWriterFence'
    admin_check = (
        'if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n'
        "            try {\n                Write-ElevationLog 'PREFLIGHT_FAILED' $failureCode"
    )
    log_target = '$path = Get-StrictFullPath $ElevationLogPath "ElevationLogPath"'
    assert text.count(admission) == text.count(admin_check) == text.count(log_target) == 1
    text = text.replace(admission, "        throw [IO.IOException]::new('preflight fault')\n" + admission)
    text = text.replace(admin_check, admin_check.replace('if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))', 'if ($true)'))
    text = text.replace(log_target, '$path = [IO.Path]::GetFullPath($OperatorLocalAppDataRoot)')
    helper.write_text(text, encoding='utf-8-sig')
    _bind_packet(source)

    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        result = _install(tmp_path, env, source, install)
        assert result.returncode != 0
        assert 'CONTAINER_PLACEMENT_LOG_WRITE_FAILED' in result.stderr
        assert '결과 기록을 남기지 못했습니다' in result.stderr
        assert '기록 폴더의 쓰기 권한과 저장 공간' in result.stderr
        assert 'CONTAINER_PLACEMENT_CHILD_FAILED' not in result.stderr
        assert '문의 코드 CA-' in result.stderr
        audit = json.loads((tmp_path / 'reinstall-audit.json').read_text(encoding='utf-8-sig'))
        assert audit['code_placement'] == 'NOT_STARTED'
        assert _tree(install) == before['code']


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
