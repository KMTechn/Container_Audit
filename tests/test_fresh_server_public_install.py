"""Public fresh installer with real archive, registration and release consumers.

Only OS registry/process/signature observations, HTTP and the shared KSP are
synthetic. The installer, elevated placement leaf, writer authority, Python
host dispatch, journal, response validation, onboarding and restore are real.
"""
import json
from pathlib import Path

import pytest

from tests.test_canonical_portable_uninstall import (
    PY_HOST, _setup, _ps, _sha, _launch_relay, _assert_one_live_relay,
)


FRESH_HOST = r'''
from urllib.parse import urlsplit
from urllib.request import url2pathname
def restrict_fixture_writes(event, args):
    paths=[]
    if event == 'open':
        path, mode, flags=args
        if (mode and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            paths=[path]
    elif event in {'os.mkdir','os.rmdir','os.remove','os.chmod','os.utime'}:
        paths=[args[0]]
    elif event in {'os.rename','os.link','os.symlink'}:
        paths=list(args[:2])
    elif event == 'sqlite3.connect':
        if str(args[0]).startswith('file:'):
            paths=[url2pathname(urlsplit(str(args[0])).path)]
        elif args[0] != ':memory:':
            paths=[args[0]]
    for path in paths:
        if isinstance(path, (str, bytes, os.PathLike)) and str(path).lower() != os.devnull:
            assert Path(path).resolve().is_relative_to(root.resolve()), 'fixture attempted a write outside its isolated root'
assert Path(os.environ['LOCALAPPDATA']).resolve().is_relative_to(root.resolve())
assert Path(os.environ['PROGRAMDATA']).resolve().is_relative_to(root.resolve())
sys.addaudithook(restrict_fixture_writes)
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
import hashlib, sqlite3
import requests
import logistics_runtime_profile
import current_user_server_transition as transition
from tools import register_container_audit_worker_pc as registration
from tests.test_worker_pc_registration import _FakePossessionKey, TEST_MACHINE_GUID
from tests.test_fresh_server_registration import _enrollment_response
class FixtureKey(_FakePossessionKey):
    def descriptor(self):
        result=super().descriptor()
        result.created=False
        result.provider_name='Microsoft Software Key Storage Provider'
        result.key_name='KMTech.DirectSync.Possession.v1'
        return result
    def close(self): pass
registration.PersistentPossessionKey.open_existing=classmethod(lambda *a, **k: FixtureKey())
def forbidden(*a, **k): raise AssertionError('new KSP provisioning is forbidden')
registration.PersistentPossessionKey.provision_initial=classmethod(forbidden)
registration._current_machine_guid=lambda: TEST_MACHINE_GUID
logistics_runtime_profile._machine_environment_value=lambda name: ''
class HttpSession:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def get(self, url, **kwargs):
        assert url == 'https://new.example.invalid/health/ready' and kwargs['verify']
        return SimpleNamespace(status_code=200, headers={'X-KMTech-Source-Commit':'b'*40})
requests.Session=HttpSession
def post(url, **kwargs):
    assert url.startswith('https://new.example.invalid/') and kwargs['verify']
    if url.endswith('/challenge'):
        return SimpleNamespace(status_code=404, json=lambda: {'error':{'code':'producer_identity_not_found'}})
    assert url.endswith('/enroll')
    return SimpleNamespace(status_code=200, json=lambda: _enrollment_response(transition.current_transition()))
registration._post_enrollment_request=post
def install_run(app, **kwargs):
    return user_relay.install_user_relay_autostart(app, **kwargs,
        setter=lambda command: registry.write_text(json.dumps({'exists':True,'kind':'String','data':command})),
        getter=lambda: json.loads(registry.read_text())['data'])
onboarding.install_user_relay_autostart=install_run
if sys.argv[1] == 'seed':
    from tests.test_current_user_onboarding import _ready_state
    _ready_state(onboarding.resolve_current_user_onboarding_paths(root / 'owned/current/app'))
    private=root/'private'
    transition._private_directory(private, transition._sid())
    record=private/'accepted.json'
    record.write_text(json.dumps({'phase':'ACCEPTED','ready':True,'client_writes_blocked':False,
        'snapshot_rollback_allowed':False,'source_commit':'b'*40}))
    target={'schema':transition.INPUT_SCHEMA,'origin':'https://new.example.invalid','scope':'fresh-scope',
        'deployment_id':'/srv/fresh-test','packet':hashlib.sha256((root/'packet/portable-manifest.json').read_bytes()).hexdigest(),
        'pc':os.environ['COMPUTERNAME'],'sid':transition._sid(),
        'acceptance':{'record_path':str(record),'record_sha256':hashlib.sha256(record.read_bytes()).hexdigest(),
            'source_commit':'b'*40,'accepted_by':'fixture-admin'}}
    (private/'input.json').write_text(json.dumps(target))
    raise SystemExit(0)
if sys.argv[1] == 'fresh':
    sys.executable=str(Path(sys.argv[sys.argv.index('--app-root')+1]).parent/'runtime/pythonw.exe')
    if os.environ.get('CA_FRESH_CUT') == 'detach_child':
        save=transition._save
        def stop_after_first_rename(plan):
            if plan['phase'] == 'ARCHIVE_VERIFIED' and any(Path(entry['inactive']).exists()
                    for entry in plan['entries'] if not entry.get('shared_read_only')):
                os._exit(83)
            return save(plan)
        transition._save=stop_after_first_rename
    from container_audit_product_host import dispatch_product_mode
    raise SystemExit(dispatch_product_mode(['--fresh-server-registration', *sys.argv[2:]]))
'''

FRESH_PRODUCT = r'''
function FixturePublicationCut([string]$Stage) {
    $prefix=if ($freshResume) { 'resume-' } else { 'initial-' }
    if ($env:CA_FRESH_CUT -ceq ($prefix+$Stage)) { [Environment]::Exit(81) }
}
function Product([string]$Root,[string]$Mode,[string]$FreshAction = '') {
    if ($Mode -cne '--fresh-server-registration') { FixtureProduct $Root $Mode; return }
    Add-Content -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT 'fresh-calls.log') -Value $FreshAction
    if ($FreshAction -ceq 'register' -and $env:CA_FRESH_CUT -ceq 'before_register') { throw 'FRESH_FIXTURE_BEFORE_REGISTER' }
    $arguments=@('fresh','--app-root',(Join-Path $Root 'app'),'--action',$FreshAction,
        '--input',$FreshTransitionInput,'--archive-root',$FreshArchiveRoot,'--transition-id',$FreshTransitionId)
    $receipt=Get-Variable -Name auditPath -ValueOnly -ErrorAction SilentlyContinue
    if (-not $receipt -and $FreshAction -ceq 'preflight') { $receipt=$ResumeFreshTransitionReceiptPath }
    if ($receipt) { $arguments+=@('--lifecycle-receipt',$receipt) }
    if ($ConfirmFreshServerRegistration) { $arguments+=@('--confirm',$ConfirmFreshServerRegistration) }
    if ($ConfirmArchivePending) { $arguments+='--confirm-pending' }
    if ($FreshAction -ceq 'plan') { $arguments+=@('--report-path',(Join-Path $FreshArchiveRoot 'transition-plan.json')) }
    if ($FreshAction -ceq 'complete') {
        $arguments+=@('--release-authorization-path',[string]$releaseAuthorization.path,
            '--release-authorization-sha256',[string]$releaseAuthorization.sha256)
    }
    $output=@(& $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST @arguments 2>&1)
    $code=$LASTEXITCODE
    $output | Out-File -LiteralPath (Join-Path $env:CA_UNINSTALL_ROOT ('fresh-'+$FreshAction+'.log')) -Append -Encoding UTF8
    if ($FreshAction -ceq 'preflight') { return [int]$code }
    if ($code -ne 0) { throw "Real fresh consumer failed: $FreshAction/$code" }
}
'''


def _fresh_setup(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    for name in ('CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH', 'KM_LOGISTICS_PROFILE_PATH'):
        env.pop(name, None)
    host = PY_HOST.replace("if sys.argv[1] == 'relay':", FRESH_HOST + "\nif sys.argv[1] == 'relay':", 1)
    host = host.replace("        lease.release()\n        (root / 'relay.ready').unlink(missing_ok=True)",
                        "        try: lease.release()\n        finally: (root / 'relay.ready').unlink(missing_ok=True)")
    # The fresh branch must consume its newly registered state, never seed a
    # fabricated READY result at the onboarding boundary.
    host = host.replace("lambda cls, *args, **kwargs: _FakeExistingPossessionKey()",
                        "lambda cls, *args, **kwargs: FixtureKey()")
    host = host.replace('        _ready_state(paths)',
                        "        raise AssertionError('fresh onboarding tried another enrollment')")
    host = host.replace('profile_loader=_profile_loader,\n        credential_loader=_credential_loader,',
                        'profile_loader=onboarding._default_profile_loader,\n        credential_loader=onboarding.load_credentials_from_json,')
    host = host.replace("['--onboard-current-user', '--app-root', str(app)]",
                        "['--onboard-current-user', '--app-root', str(app), '--fresh-transition-journal', str(root/'archive/transition-journal.json')]")
    # This is the server/relay lease boundary; the actual activation consumer
    # still validates lease identity, expiry, fence and the empty SQLite queue.
    host = host.replace("    (root / 'relay.pid').write_text(str(os.getpid()))", r'''
    plan=transition.current_transition()
    if plan and plan['phase'] in {'REGISTERED','ACTIVATION_PENDING_RELEASE','ACTIVATED'}:
        paths=onboarding.resolve_current_user_onboarding_paths(plan['app_root'])
        paths.queue_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(paths.queue_dir/'direct_sync_relay.sqlite3') as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS direct_sync_relay_batches (status TEXT)')
        lease={'contract_version':'producer-runtime-lease.v1','status':'ACTIVE','server_grant_accepted':True,
            'expires_at':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
            'runtime_instance_id':'fixture-runtime','lease_id':'fixture-lease','fence':1,
            'producer_install_id':plan['candidate']['identity']['producer_install_id']}
        status=direct/'status/direct_sync_relay_status.json'
        status.parent.mkdir(parents=True, exist_ok=True)
        status.write_text(json.dumps({'runtime_lease':lease}))
    (root / 'relay.pid').write_text(str(os.getpid()))''')
    Path(env['CA_UNINSTALL_HOST']).write_text(host, encoding='utf-8')
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    old = 'function Product([string]$Root, [string]$Mode) {'
    assert text.count(old) == 1
    text = text.replace(old, 'function FixtureProduct([string]$Root, [string]$Mode) {')
    text = text.replace('$wanted = Command $install', FRESH_PRODUCT + '\n$wanted = Command $install')
    text = text.replace('$original=$_',
        "$original=$_\n    [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'controller-error.txt'), $original.Exception.Message)")
    # Kill the real controller at publication boundaries, bypassing catch and
    # finally exactly as process loss does. No writer check is replaced.
    boundaries = {
        '$canonicalWriterFencePreparedReceipt = New-CanonicalWriterFencePreparedReceipt':
            "FixturePublicationCut 'record'\n$canonicalWriterFencePreparedReceipt = New-CanonicalWriterFencePreparedReceipt",
        '    $audit.fresh_transition.prepared_receipt_path = [string]$canonicalWriterFencePreparedReceipt.path':
            "    FixturePublicationCut 'prepared'\n    $audit.fresh_transition.prepared_receipt_path = [string]$canonicalWriterFencePreparedReceipt.path",
        '    Save $auditPath $audit\n}\nif ($retirementResume) {':
            "    Save $auditPath $audit\n    FixturePublicationCut 'audit'\n}\nif ($retirementResume) {",
        '\n$canonicalWriterFenceActive = $true\n':
            "\n$canonicalWriterFenceActive = $true\nFixturePublicationCut 'fence'\n",
    }
    for old, new in boundaries.items():
        assert text.count(old) == 1
        text = text.replace(old, new)
    canonical.write_text(text, encoding='utf-8-sig')
    manifest_path = source / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['source_commit'] = 'd' * 40
    manifest['installer_sha256'] = _sha(canonical)
    files = [p for p in source.rglob('*') if p.is_file() and p != manifest_path]
    manifest['file_count_before_manifest'] = len(files)
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    seed = tmp_path / 'seed.ps1'
    seed.write_text('& $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST seed\nexit $LASTEXITCODE', encoding='utf-8-sig')
    result = _ps(seed, env)
    assert result.returncode == 0, result.stderr
    return env, source, install, protected


def _fresh_run(tmp_path, env, source, install, *extra):
    result = _ps(source / 'INSTALL_CANONICAL_PORTABLE.ps1', env,
        '-SourceRoot', str(source), '-InstallRoot', str(install),
        '-PrepareFreshServerRegistration', '-FreshTransitionInput', str(tmp_path / 'private/input.json'),
        '-FreshArchiveRoot', str(tmp_path / 'archive'), '-FreshTransitionId', 'b' * 32,
        '-ConfirmFreshServerRegistration', '이 PC의 옛 자료를 보관하고 https://new.example.invalid / fresh-scope / /srv/fresh-test에 새로 등록합니다',
        '-ConfirmArchivePending', '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest', *extra)
    (tmp_path / ('public-' + str(len(list(tmp_path.glob('public-*.log')))) + '.log')).write_text(
        result.stdout + '\n' + result.stderr, encoding='utf-8')
    return result


@pytest.mark.parametrize('finish', ['activate', 'restore'])
def test_public_fresh_install_advances_and_restores_before_registration(tmp_path, finish):
    env, source, install, protected = _fresh_setup(tmp_path)
    # Take the read-only plan against a quiescent fixture. Live relay status
    # replacement would intentionally make an unsynchronised file inventory
    # UNKNOWN; it is not the mutation path exercised here.
    before = {str(p): p.read_bytes() for p in protected}
    planned = _fresh_run(tmp_path, env, source, install, '-PlanOnly')
    assert planned.returncode == 0, planned.stderr
    assert not (tmp_path / 'archive/transition-journal.json').exists()
    assert all(Path(p).read_bytes() == value for p, value in before.items())
    with _launch_relay(tmp_path, env):
        if finish == 'restore':
            env['CA_FRESH_CUT'] = 'before_register'
        result = _fresh_run(tmp_path, env, source, install)
        journal_path = tmp_path / 'archive/transition-journal.json'
        if finish == 'restore':
            assert result.returncode != 0
            journal = json.loads(journal_path.read_text())
            assert journal['phase'] == 'DETACHED'
            # Receipt is read from the real failed public attempt, not invented.
            audit_path = Path(journal['lifecycle_receipt'])
            del env['CA_FRESH_CUT']
            preparation = next(audit_path.parent.glob('fa-*.json'))
            audit_sha = _sha(audit_path)
            stale = _fresh_run(tmp_path, env, source, install, '-FreshTransitionAction', 'Resume',
                '-ResumeFreshTransitionReceiptPath', str(preparation), '-ResumeFreshTransitionReceiptSha256', _sha(preparation))
            assert stale.returncode != 0
            assert 'fresh_transition_receipt=' + str(audit_path) in stale.stdout
            assert 'fresh_transition_receipt_sha256=' + audit_sha in stale.stdout
            assert _sha(audit_path) == audit_sha
            result = _fresh_run(tmp_path, env, source, install, '-FreshTransitionAction', 'Restore',
                '-ResumeFreshTransitionReceiptPath', str(audit_path), '-ResumeFreshTransitionReceiptSha256', _sha(audit_path))
            assert result.returncode == 0, result.stderr
            assert json.loads(journal_path.read_text())['phase'] == 'RESTORED'
            assert all(Path(p).read_bytes() == value for p, value in before.items())
        else:
            assert result.returncode == 0, result.stderr
            journal = json.loads(journal_path.read_text())
            assert journal['phase'] == 'ACTIVATED'
            assert journal['identity_absent'] and journal['first_lease'] == 'VERIFIED'
            assert journal['new_queue_rows'] == 0
            proof = journal['completion_release']
            assert _sha(Path(proof['receipt_path'])) == proof['receipt_sha256']
            assert json.loads(Path(proof['receipt_path']).read_text())['status'] == 'RELEASED'
            calls = (tmp_path / 'fresh-calls.log').read_text().splitlines()
            assert calls == ['plan', 'preflight', 'prepare', 'register', 'activate', 'complete']
            # A current receipt remains a supported input after the first
            # attempt released its fence and replaced the old code preimage.
            audit_path = Path(journal['lifecycle_receipt'])
            repeated = _fresh_run(tmp_path, env, source, install, '-FreshTransitionAction', 'Resume',
                '-ResumeFreshTransitionReceiptPath', str(audit_path), '-ResumeFreshTransitionReceiptSha256', _sha(audit_path))
            assert repeated.returncode == 0, repeated.stderr
            after = json.loads(journal_path.read_text())
            assert after['candidate'] == journal['candidate'] and after['entries'] == journal['entries']
            assert after['phase'] == 'ACTIVATED' and after['completion_release'] == proof
            assert (tmp_path / 'fresh-calls.log').read_text().splitlines() == calls + ['preflight', 'complete']
        assert _sha(install / 'portable-manifest.json') == _sha(source / 'portable-manifest.json')
        assert not (Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control/writer-session/active.json').exists()
        _assert_one_live_relay(tmp_path, env)


@pytest.mark.parametrize('stage', ['record', 'prepared', 'audit', 'fence'])
@pytest.mark.parametrize('handoff', [False, True])
def test_public_resume_survives_preparation_publication_loss(tmp_path, stage, handoff):
    env, source, install, _ = _fresh_setup(tmp_path)
    with _launch_relay(tmp_path, env):
        env['CA_FRESH_CUT'] = 'initial-fence' if handoff else 'initial-' + stage
        interrupted = _fresh_run(tmp_path, env, source, install)
        assert interrupted.returncode == 81, interrupted.stderr
        audit_root = Path(env['LOCALAPPDATA']) / 'KMTech/ContainerAudit/install-audit'
        records = list(audit_root.glob('fa-*.json'))
        assert len(records) == 1
        original = records[0]
        resume = ('-FreshTransitionAction', 'Resume', '-ResumeFreshTransitionReceiptPath', str(original),
                  '-ResumeFreshTransitionReceiptSha256', _sha(original))
        if handoff:
            env['CA_FRESH_CUT'] = 'resume-' + stage
            interrupted = _fresh_run(tmp_path, env, source, install, *resume)
            assert interrupted.returncode == 81, interrupted.stderr
            assert len(list(audit_root.glob('fa-*.json'))) == 2
        del env['CA_FRESH_CUT']
        completed = _fresh_run(tmp_path, env, source, install, *resume)
        assert completed.returncode == 0, completed.stderr
        journal = json.loads((tmp_path / 'archive/transition-journal.json').read_text())
        assert journal['phase'] == 'ACTIVATED' and journal['new_queue_rows'] == 0
        assert not (Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control/writer-session/active.json').exists()
        _assert_one_live_relay(tmp_path, env)


def test_public_partial_detach_resume_tolerates_only_its_owned_removal_report(tmp_path):
    env, source, install, _ = _fresh_setup(tmp_path)
    with _launch_relay(tmp_path, env):
        env['CA_FRESH_CUT'] = 'detach_child'
        interrupted = _fresh_run(tmp_path, env, source, install)
        assert interrupted.returncode != 0
        journal_path = tmp_path / 'archive/transition-journal.json'
        before = json.loads(journal_path.read_text())
        assert before['phase'] == 'ARCHIVE_VERIFIED'
        assert any(Path(entry['inactive']).exists() and not entry['detached']
                   for entry in before['entries'] if not entry.get('shared_read_only'))
        removal = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/status/current_user_removal.json'
        assert not any(removal.is_relative_to(Path(entry['source'])) for entry in before['entries'])
        old_removal_sha = _sha(removal)
        audit_path = Path(before['lifecycle_receipt'])
        assert json.loads(audit_path.read_text())['status'] == 'FRESH_TRANSITION_UNKNOWN_RESUME_REQUIRED'
        del env['CA_FRESH_CUT']
        result = _fresh_run(tmp_path, env, source, install, '-FreshTransitionAction', 'Resume',
            '-ResumeFreshTransitionReceiptPath', str(audit_path), '-ResumeFreshTransitionReceiptSha256', _sha(audit_path))
        assert result.returncode == 0, result.stderr
        after = json.loads(journal_path.read_text())
        assert after['phase'] == 'ACTIVATED' and after['candidate'] == before['candidate']
        assert _sha(removal) != old_removal_sha  # The public resume did refresh its own report.
        assert after['entries'] == [dict(entry, detached=True) for entry in before['entries']]
        _assert_one_live_relay(tmp_path, env)
